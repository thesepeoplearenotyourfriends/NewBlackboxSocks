#include "NetworkHook.h"

#include "Dobby/dobby.h"
#include "Log.h"
#include "xdl.h"

#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <algorithm>
#include <mutex>
#include <string>
#include <sys/socket.h>
#include <time.h>
#include <unordered_map>
#include <unistd.h>

namespace {
constexpr int kTimeoutMs = 10000;
using ConnectFn = int (*)(int, const sockaddr *, socklen_t);
ConnectFn originalConnect;
using GetAddrInfoFn = int (*)(const char *, const char *, const addrinfo *, addrinfo **);
using AndroidGetAddrInfoForNetFn = int (*)(const char *, const char *, const addrinfo *,
                                           unsigned, unsigned, addrinfo **);
GetAddrInfoFn originalGetAddrInfo;
AndroidGetAddrInfoForNetFn originalAndroidGetAddrInfoForNet;

constexpr uint32_t kFakeNetwork = 0xc6120000U; // 198.18.0.0, in host byte order.
constexpr uint32_t kFakeMask = 0xfffe0000U;
constexpr uint32_t kFakeCapacity = 1U << 17;
std::mutex mappingsMutex;
std::unordered_map<std::string, uint32_t> hostnameToAddress;
std::unordered_map<uint32_t, std::string> addressToHostname;
uint32_t nextFakeOffset;

struct Config {
    // requested deliberately remains true when validation fails.  That distinction is
    // what prevents a bad setting from accidentally restoring direct networking.
    bool requested = false;
    bool valid = false;
    sockaddr_in proxy{};
    std::string user;
    std::string password;
} config;

int64_t nowMs() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<int64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

bool waitFd(int fd, short events, int64_t deadline) {
    for (;;) {
        int64_t remaining = deadline - nowMs();
        if (remaining <= 0) { errno = ETIMEDOUT; return false; }
        pollfd pfd{fd, events, 0};
        int result = poll(&pfd, 1, static_cast<int>(remaining > INT_MAX ? INT_MAX : remaining));
        if (result > 0) {
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) { errno = ECONNRESET; return false; }
            if (pfd.revents & events) return true;
        } else if (result == 0) { errno = ETIMEDOUT; return false; }
        else if (errno != EINTR) return false;
    }
}

bool writeAll(int fd, const uint8_t *data, size_t size, int64_t deadline) {
    while (size) {
        ssize_t n = send(fd, data, size, MSG_NOSIGNAL);
        if (n > 0) { data += n; size -= static_cast<size_t>(n); continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && waitFd(fd, POLLOUT, deadline)) continue;
        if (n == 0) errno = ECONNRESET;
        return false;
    }
    return true;
}

bool readAll(int fd, uint8_t *data, size_t size, int64_t deadline) {
    while (size) {
        ssize_t n = recv(fd, data, size, 0);
        if (n > 0) { data += n; size -= static_cast<size_t>(n); continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && waitFd(fd, POLLIN, deadline)) continue;
        if (n == 0) errno = ECONNRESET;
        return false;
    }
    return true;
}

int replyErrno(uint8_t reply) {
    switch (reply) {
        case 2: return EACCES;
        case 3: return ENETUNREACH;
        case 4: return EHOSTUNREACH;
        case 5: return ECONNREFUSED;
        case 6: return ETIMEDOUT;
        case 7: return EOPNOTSUPP;
        case 8: return EAFNOSUPPORT;
        default: return EPROTO;
    }
}

bool negotiate(int fd, const sockaddr_in &destination, const std::string *hostname, int64_t deadline) {
    const bool auth = !config.user.empty() || !config.password.empty();
    // Do not offer no-auth when credentials were requested: accepting it would allow
    // a proxy (or an on-path endpoint) to silently downgrade authentication.
    uint8_t greeting[3] = {5, 1, static_cast<uint8_t>(auth ? 2 : 0)};
    if (!writeAll(fd, greeting, sizeof(greeting), deadline)) return false;
    uint8_t selection[2];
    if (!readAll(fd, selection, sizeof(selection), deadline)) return false;
    if (selection[0] != 5 || selection[1] == 0xff) { errno = EACCES; return false; }
    if (auth && selection[1] == 2) {
        std::string request;
        request.push_back(1);
        request.push_back(static_cast<char>(config.user.size()));
        request += config.user;
        request.push_back(static_cast<char>(config.password.size()));
        request += config.password;
        if (!writeAll(fd, reinterpret_cast<const uint8_t *>(request.data()), request.size(), deadline)) return false;
        uint8_t response[2];
        if (!readAll(fd, response, sizeof(response), deadline)) return false;
        if (response[0] != 1 || response[1] != 0) { errno = EACCES; return false; }
    } else if ((!auth && selection[1] != 0) || (auth && selection[1] != 2)) {
        errno = EACCES;
        return false;
    }

    if (hostname) {
        if (hostname->empty() || hostname->size() > 255) { errno = EINVAL; return false; }
        std::string request;
        request.reserve(hostname->size() + 7);
        request.append("\x05\x01\x00\x03", 4);
        request.push_back(static_cast<char>(hostname->size()));
        request += *hostname;
        request.append(reinterpret_cast<const char *>(&destination.sin_port), 2);
        if (!writeAll(fd, reinterpret_cast<const uint8_t *>(request.data()), request.size(), deadline)) return false;
    } else {
        uint8_t request[10] = {5, 1, 0, 1};
        memcpy(request + 4, &destination.sin_addr.s_addr, 4);
        memcpy(request + 8, &destination.sin_port, 2);
        if (!writeAll(fd, request, sizeof(request), deadline)) return false;
    }
    uint8_t header[4];
    if (!readAll(fd, header, sizeof(header), deadline)) return false;
    if (header[0] != 5 || header[2] != 0) { errno = EPROTO; return false; }
    if (header[1] != 0) { errno = replyErrno(header[1]); return false; }
    size_t tail = 0;
    if (header[3] == 1) tail = 6;
    else if (header[3] == 4) tail = 18;
    else if (header[3] == 3) {
        uint8_t length;
        if (!readAll(fd, &length, 1, deadline)) return false;
        tail = static_cast<size_t>(length) + 2;
    } else { errno = EPROTO; return false; }
    uint8_t discard[257];
    return readAll(fd, discard, tail, deadline);
}

bool isFakeAddress(uint32_t networkAddress) {
    return (ntohl(networkAddress) & kFakeMask) == kFakeNetwork;
}

bool mappedHostname(uint32_t networkAddress, std::string *hostname) {
    std::lock_guard<std::mutex> lock(mappingsMutex);
    auto found = addressToHostname.find(networkAddress);
    if (found == addressToHostname.end()) return false;
    *hostname = found->second;
    return true;
}

bool shouldSynthesize(const char *node, const addrinfo *hints) {
    if (!node || !*node) return false;
    if (hints && (hints->ai_flags & AI_NUMERICHOST)) return false;
    in_addr ipv4{};
    in6_addr ipv6{};
    if (inet_pton(AF_INET, node, &ipv4) == 1 || inet_pton(AF_INET6, node, &ipv6) == 1) return false;
    std::string hostname(node);
    std::transform(hostname.begin(), hostname.end(), hostname.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    while (hostname.size() > 1 && hostname.back() == '.') hostname.pop_back();
    if (hostname == "localhost" ||
        (hostname.size() > 10 && hostname.compare(hostname.size() - 10, 10, ".localhost") == 0)) return false;
    return !hints || hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET;
}

bool isOrdinaryHostname(const char *node) {
    if (!node || !*node) return false;
    in_addr ipv4{};
    in6_addr ipv6{};
    if (inet_pton(AF_INET, node, &ipv4) == 1 || inet_pton(AF_INET6, node, &ipv6) == 1) return false;
    std::string hostname(node);
    std::transform(hostname.begin(), hostname.end(), hostname.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    while (hostname.size() > 1 && hostname.back() == '.') hostname.pop_back();
    return hostname != "localhost" &&
           !(hostname.size() > 10 && hostname.compare(hostname.size() - 10, 10, ".localhost") == 0);
}

int syntheticAddress(const char *node, uint32_t *address) {
    std::string hostname(node);
    if (hostname.size() > 255) return EAI_NONAME;
    std::transform(hostname.begin(), hostname.end(), hostname.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    while (hostname.size() > 1 && hostname.back() == '.') hostname.pop_back();
    std::lock_guard<std::mutex> lock(mappingsMutex);
    auto existing = hostnameToAddress.find(hostname);
    if (existing != hostnameToAddress.end()) {
        *address = existing->second;
        ALOGD("NetworkHook: synthetic domain mapping reused");
        return 0;
    }
    while (nextFakeOffset < kFakeCapacity) {
        uint32_t candidate = htonl(kFakeNetwork + nextFakeOffset++);
        if (candidate == config.proxy.sin_addr.s_addr || addressToHostname.count(candidate)) continue;
        hostnameToAddress.emplace(hostname, candidate);
        addressToHostname.emplace(candidate, hostname);
        *address = candidate;
        ALOGD("NetworkHook: synthetic domain mapping allocated (total=%zu)", hostnameToAddress.size());
        return 0;
    }
    return EAI_MEMORY;
}

template<typename Resolver>
int resolveSynthetic(Resolver original, const char *node, const char *service,
                     const addrinfo *hints, addrinfo **result) {
    if (!shouldSynthesize(node, hints)) return original(node, service, hints, result);
    uint32_t address;
    int error = syntheticAddress(node, &address);
    if (error != 0) { ALOGE("NetworkHook: resolver synthesis failed (EAI=%d)", error); return error; }
    char numeric[INET_ADDRSTRLEN];
    in_addr value{address};
    if (!inet_ntop(AF_INET, &value, numeric, sizeof(numeric))) return EAI_SYSTEM;
    addrinfo numericHints{};
    if (hints) numericHints = *hints;
    numericHints.ai_family = AF_INET;
    numericHints.ai_flags |= AI_NUMERICHOST;
    numericHints.ai_flags &= ~AI_ADDRCONFIG;
    error = original(numeric, service, &numericHints, result);
    if (error != 0) ALOGE("NetworkHook: numeric synthetic resolver failed (EAI=%d)", error);
    return error;
}

int hookedGetAddrInfo(const char *node, const char *service, const addrinfo *hints, addrinfo **result) {
    if (hints && hints->ai_family == AF_INET6 && isOrdinaryHostname(node)) return EAI_FAMILY;
    return resolveSynthetic(originalGetAddrInfo, node, service, hints, result);
}

int hookedAndroidGetAddrInfoForNet(const char *node, const char *service, const addrinfo *hints,
                                   unsigned netId, unsigned mark, addrinfo **result) {
    if (hints && hints->ai_family == AF_INET6 && isOrdinaryHostname(node)) return EAI_FAMILY;
    auto original = [netId, mark](const char *n, const char *s, const addrinfo *h, addrinfo **r) {
        return originalAndroidGetAddrInfoForNet(n, s, h, netId, mark, r);
    };
    return resolveSynthetic(original, node, service, hints, result);
}

int hookedConnect(int fd, const sockaddr *address, socklen_t length) {
    if (!config.requested) return originalConnect(fd, address, length);
    if (!address || length < sizeof(sa_family_t)) { errno = EINVAL; return -1; }
    if (address->sa_family == AF_UNIX) return originalConnect(fd, address, length);
    if (address->sa_family == AF_INET6) { errno = EAFNOSUPPORT; return -1; }
    if (address->sa_family != AF_INET || length < sizeof(sockaddr_in)) { errno = EAFNOSUPPORT; return -1; }
    int type = 0; socklen_t typeLength = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &typeLength) != 0) return -1;
    if (type != SOCK_STREAM) { errno = EPROTONOSUPPORT; return -1; }
    if (!config.valid) { errno = EINVAL; return -1; }

    const auto &destination = *reinterpret_cast<const sockaddr_in *>(address);
    std::string hostname;
    const bool synthetic = mappedHostname(destination.sin_addr.s_addr, &hostname);
    if (isFakeAddress(destination.sin_addr.s_addr) && !synthetic) {
        errno = EHOSTUNREACH;
        ALOGE("NetworkHook: unmapped synthetic-range connect blocked");
        return -1;
    }
    if (synthetic) ALOGD("NetworkHook: synthetic domain connect recognized");

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (!(flags & O_NONBLOCK) && fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return -1;
    const int64_t deadline = nowMs() + kTimeoutMs;
    int result = originalConnect(fd, reinterpret_cast<const sockaddr *>(&config.proxy), sizeof(config.proxy));
    if (result != 0 && errno == EINPROGRESS && waitFd(fd, POLLOUT, deadline)) {
        int error = 0; socklen_t errorLength = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errorLength) == 0 && error == 0) result = 0;
        else { errno = error ? error : errno; result = -1; }
    }
    if (result == 0 && !negotiate(fd, destination, synthetic ? &hostname : nullptr, deadline)) {
        // This descriptor is connected to the proxy, not the requested peer.  Poison it
        // before returning so callers cannot accidentally use or retry this partial path.
        int negotiationErrno = errno;
        shutdown(fd, SHUT_RDWR);
        errno = negotiationErrno;
        result = -1;
    }
    if (synthetic) {
        if (result == 0) ALOGD("NetworkHook: SOCKS DOMAIN connect succeeded");
        else ALOGE("NetworkHook: SOCKS DOMAIN connect failed (errno=%d)", errno);
    }
    int savedErrno = errno;
    if (!(flags & O_NONBLOCK) && fcntl(fd, F_SETFL, flags) != 0 && result == 0) { savedErrno = errno; result = -1; }
    errno = savedErrno;
    return result;
}
} // namespace

void NetworkHook::configure(JNIEnv *env, bool enabled, jstring host, int port,
                            jstring user, jstring password) {
    config = Config{};
    config.requested = enabled;
    if (!enabled) return;
    const char *hostChars = host ? env->GetStringUTFChars(host, nullptr) : nullptr;
    config.proxy.sin_family = AF_INET;
    config.proxy.sin_port = htons(static_cast<uint16_t>(port));
    bool valid = hostChars && inet_pton(AF_INET, hostChars, &config.proxy.sin_addr) == 1;
    if (hostChars) env->ReleaseStringUTFChars(host, hostChars);
    auto copy = [env](jstring value) {
        if (!value) return std::string();
        const char *chars = env->GetStringUTFChars(value, nullptr);
        std::string result = chars ? chars : "";
        if (chars) env->ReleaseStringUTFChars(value, chars);
        return result;
    };
    config.user = copy(user); config.password = copy(password);
    config.valid = valid && port >= 1 && port <= 65535 &&
                   config.user.size() <= 255 && config.password.size() <= 255;
    if (!config.valid) ALOGE("NetworkHook: invalid configuration; guest networking will fail closed");
}

void NetworkHook::init() {
    if (!config.requested || originalConnect) return;
    void *handle = xdl_open("libc.so", XDL_DEFAULT);
    void *symbol = handle ? xdl_sym(handle, "connect", nullptr) : nullptr;
    if (symbol && DobbyHook(symbol, reinterpret_cast<void *>(hookedConnect),
                            reinterpret_cast<void **>(&originalConnect)) == 0 && originalConnect)
        ALOGD("NetworkHook: guest SOCKS5 connect hook installed");
    else {
        ALOGE("NetworkHook: requested guest connect hook could not be installed; terminating guest");
        if (handle) xdl_close(handle);
        abort();
    }
    void *getaddrinfoSymbol = xdl_sym(handle, "getaddrinfo", nullptr);
    // libcore's InetAddress JNI calls this private Bionic entry point so that its
    // selected Android netId/mark survive resolution.  Hooking getaddrinfo alone
    // therefore does not cover ordinary Java hostname lookups.
    void *networkSymbol = xdl_sym(handle, "android_getaddrinfofornet", nullptr);
    bool resolverHooked = getaddrinfoSymbol &&
            DobbyHook(getaddrinfoSymbol, reinterpret_cast<void *>(hookedGetAddrInfo),
                      reinterpret_cast<void **>(&originalGetAddrInfo)) == 0 && originalGetAddrInfo;
    bool networkHooked = networkSymbol &&
            DobbyHook(networkSymbol, reinterpret_cast<void *>(hookedAndroidGetAddrInfoForNet),
                      reinterpret_cast<void **>(&originalAndroidGetAddrInfoForNet)) == 0 &&
            originalAndroidGetAddrInfoForNet;
    if (!resolverHooked || !networkHooked) {
        ALOGE("NetworkHook: requested guest resolver hooks could not be installed; terminating guest");
        xdl_close(handle);
        abort();
    }
    ALOGD("NetworkHook: guest resolver hooks installed (getaddrinfo + network-aware)");
    xdl_close(handle);
}
