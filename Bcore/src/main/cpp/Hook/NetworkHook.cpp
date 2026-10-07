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
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <time.h>
#include <unordered_map>
#include <vector>
#include <unistd.h>

namespace {
constexpr int kTimeoutMs = 10000;
constexpr int kProbeTimeoutMs = 2000;
using ConnectFn = int (*)(int, const sockaddr *, socklen_t);
ConnectFn originalConnect;
using SocketFn = int (*)(int, int, int);
using SendToFn = ssize_t (*)(int, const void *, size_t, int, const sockaddr *, socklen_t);
using RecvFromFn = ssize_t (*)(int, void *, size_t, int, sockaddr *, socklen_t *);
using SendMsgFn = ssize_t (*)(int, const msghdr *, int);
using RecvMsgFn = ssize_t (*)(int, msghdr *, int);
using SendFn = ssize_t (*)(int, const void *, size_t, int);
using RecvFn = ssize_t (*)(int, void *, size_t, int);
using ReadFn = ssize_t (*)(int, void *, size_t);
using WriteFn = ssize_t (*)(int, const void *, size_t);
using ReadVFn = ssize_t (*)(int, const iovec *, int);
using WriteVFn = ssize_t (*)(int, const iovec *, int);
using CloseFn = int (*)(int);
using DupFn = int (*)(int);
using Dup2Fn = int (*)(int, int);
using Dup3Fn = int (*)(int, int, int);
using SendMMsgFn = int (*)(int, mmsghdr *, unsigned, int);
using RecvMMsgFn = int (*)(int, mmsghdr *, unsigned, int, timespec *);
SocketFn originalSocket;
SendToFn originalSendTo;
RecvFromFn originalRecvFrom;
SendMsgFn originalSendMsg;
RecvMsgFn originalRecvMsg;
SendFn originalSend;
RecvFn originalRecv;
ReadFn originalRead;
WriteFn originalWrite;
ReadVFn originalReadV;
WriteVFn originalWriteV;
CloseFn originalClose;
DupFn originalDup;
Dup2Fn originalDup2;
Dup3Fn originalDup3;
SendMMsgFn originalSendMMsg;
RecvMMsgFn originalRecvMMsg;
using NetHandle = uint64_t; // android.net.Network#getNetworkHandle / net_handle_t.
using SetNetworkFn = int (*)(NetHandle, int);
using SetProcessNetworkFn = int (*)(NetHandle);
SetNetworkFn originalSetNetwork;
SetProcessNetworkFn originalSetProcessNetwork;
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
std::atomic<bool> proxyProbeAttempted{false};
std::atomic<bool> loggedUnix{false};

// Per-socket capability channels live only as long as the intercepted socket (and
// its dup aliases). Closing the last channel revokes every tuple registered on it.
// Raw syscalls here avoid re-entering guest send/close hooks for private AF_UNIX IPC.
std::string flowSocketPath;
struct FlowLease {
    int channel = -1;
    std::mutex mutex;
    ~FlowLease() { if (channel >= 0) syscall(SYS_close, channel); }
};
std::mutex flowLeasesMutex;
std::unordered_map<int, std::shared_ptr<FlowLease>> flowLeases;
void releaseFlow(int fd) {
    std::lock_guard<std::mutex> lock(flowLeasesMutex);
    flowLeases.erase(fd);
}

bool authorizeTransportImpl(int fd, const sockaddr *peer, socklen_t length,
                            const uint8_t *udpHeader, size_t headerSize, int controlFd) {
    if (flowSocketPath.empty()) return true; // Existing non-VPN SOCKS mode.
    sockaddr_in destination{};
    if (peer && peer->sa_family == AF_INET && length >= sizeof(sockaddr_in)) {
        destination = *reinterpret_cast<const sockaddr_in *>(peer);
    } else if (peer && peer->sa_family == AF_INET6 && length >= sizeof(sockaddr_in6) &&
               IN6_IS_ADDR_V4MAPPED(&reinterpret_cast<const sockaddr_in6 *>(peer)->sin6_addr)) {
        const auto *v6 = reinterpret_cast<const sockaddr_in6 *>(peer);
        destination.sin_family = AF_INET;
        destination.sin_port = v6->sin6_port;
        memcpy(&destination.sin_addr, &v6->sin6_addr.s6_addr[12], 4);
    } else { errno = EAFNOSUPPORT; return false; }
    std::shared_ptr<FlowLease> lease;
    {
        std::lock_guard<std::mutex> lock(flowLeasesMutex);
        if (!flowLeases.count(fd) && flowLeases.size() >= 256) { errno = ENOBUFS; return false; }
        auto &entry = flowLeases[fd];
        if (!entry) entry = std::make_shared<FlowLease>();
        lease = entry;
    }
    std::lock_guard<std::mutex> lock(lease->mutex);
    bool first = lease->channel < 0;
    if (first) {
        sockaddr_storage local{}; socklen_t localSize = sizeof(local);
        if (getsockname(fd, reinterpret_cast<sockaddr *>(&local), &localSize) != 0) return false;
        uint16_t port = local.ss_family == AF_INET ? reinterpret_cast<sockaddr_in *>(&local)->sin_port
                         : reinterpret_cast<sockaddr_in6 *>(&local)->sin6_port;
        if (port == 0) {
            // Bind before registration/connect: the VPN must see the exact source
            // port, including the very first SYN/datagram. Never register a wildcard.
            if (local.ss_family == AF_INET) {
                auto *v4 = reinterpret_cast<sockaddr_in *>(&local);
                inet_pton(AF_INET, "10.0.0.2", &v4->sin_addr);
            } else if (local.ss_family == AF_INET6) {
                auto *v6 = reinterpret_cast<sockaddr_in6 *>(&local);
                memset(&v6->sin6_addr, 0, sizeof(v6->sin6_addr));
                v6->sin6_addr.s6_addr[10] = v6->sin6_addr.s6_addr[11] = 0xff;
                inet_pton(AF_INET, "10.0.0.2", &v6->sin6_addr.s6_addr[12]);
            } else { errno = EAFNOSUPPORT; return false; }
            if (syscall(SYS_bind, fd, &local, localSize) != 0) return false;
        }
        if (flowSocketPath.size() >= sizeof(sockaddr_un::sun_path)) { errno = ENAMETOOLONG; return false; }
        int channel = static_cast<int>(syscall(SYS_socket, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
        if (channel < 0) return false;
        sockaddr_un address{}; address.sun_family = AF_UNIX;
        memcpy(address.sun_path, flowSocketPath.c_str(), flowSocketPath.size() + 1);
        timeval timeout{2, 0};
        setsockopt(channel, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(channel, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        if (syscall(SYS_connect, channel, &address, sizeof(address)) != 0) {
            int error = errno; syscall(SYS_close, channel); errno = error; return false;
        }
        ucred peerCredentials{}; socklen_t credentialSize = sizeof(peerCredentials);
        if (getsockopt(channel, SOL_SOCKET, SO_PEERCRED, &peerCredentials, &credentialSize) != 0 ||
            peerCredentials.uid != geteuid()) {
            syscall(SYS_close, channel); errno = EACCES; return false;
        }
        lease->channel = channel;
    }
    // Version, protocol, outer destination, then exact SOCKS UDP destination header.
    // Credentials, hostnames and payloads are never sent to diagnostics.
    uint8_t request[11] = {'N', 'B', 'S', 1, static_cast<uint8_t>(udpHeader ? 17 : 6)};
    memcpy(request + 5, &destination.sin_addr, 4);
    memcpy(request + 9, &destination.sin_port, 2);
    if (headerSize > 262) { errno = EMSGSIZE; return false; }
    std::vector<uint8_t> message(request, request + 11);
    message.push_back(static_cast<uint8_t>(headerSize >> 8));
    message.push_back(static_cast<uint8_t>(headerSize));
    if (headerSize) message.insert(message.end(), udpHeader, udpHeader + headerSize);
    iovec data{message.data(), message.size()};
    char ancillary[CMSG_SPACE(2 * sizeof(int))]{};
    msghdr msg{}; msg.msg_iov = &data; msg.msg_iovlen = 1;
    if (first) {
        const int descriptors[2] = {fd, controlFd};
        const size_t descriptorSize = udpHeader ? sizeof(descriptors) : sizeof(int);
        if (udpHeader && controlFd < 0) { errno = EACCES; return false; }
        msg.msg_control = ancillary; msg.msg_controllen = CMSG_SPACE(descriptorSize);
        cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET; cmsg->cmsg_type = SCM_RIGHTS; cmsg->cmsg_len = CMSG_LEN(descriptorSize);
        memcpy(CMSG_DATA(cmsg), descriptors, descriptorSize);
    }
    ssize_t sent = syscall(SYS_sendmsg, lease->channel, &msg, MSG_NOSIGNAL);
    uint8_t accepted = 0;
    bool ok = sent == static_cast<ssize_t>(message.size()) &&
              syscall(SYS_recvfrom, lease->channel, &accepted, 1, 0, nullptr, nullptr) == 1 && accepted == 1;
    if (!ok) {
        syscall(SYS_close, lease->channel); lease->channel = -1;
        errno = EACCES;
    }
    return ok;
}

bool authorizeTransport(int fd, const sockaddr *peer, socklen_t length,
                        const uint8_t *udpHeader = nullptr, size_t headerSize = 0, int controlFd = -1) {
    if (authorizeTransportImpl(fd, peer, length, udpHeader, headerSize, controlFd)) return true;
    int error = errno;
    static std::atomic<unsigned> failures{0};
    unsigned count = ++failures;
    if (count <= 4 || (count & (count - 1)) == 0)
        ALOGE("NetworkPolicy: flow registration failed protocol=%s errno=%d count=%u", udpHeader ? "UDP" : "TCP", error, count);
    errno = error;
    return false;
}

void closeTransport(int fd) { releaseFlow(fd); originalClose(fd); }

struct UdpState {
    std::mutex mutex;
    int control = -1;
    sockaddr_storage relay{};
    socklen_t relayLength = 0;
    sockaddr_storage peer{};
    socklen_t peerLength = 0;
    bool associated = false;
    ~UdpState() { if (control >= 0 && originalClose) closeTransport(control); }
};
std::mutex udpStatesMutex;
std::unordered_map<int, std::shared_ptr<UdpState>> udpStates;

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

bool socksFailure(const char *stage, int error) {
    errno = error;
    // Stages are fixed internal literals, so this table remains bounded and each
    // failure stage is visible even if another stage has already been noisy.
    static std::mutex mutex;
    static std::unordered_map<std::string, unsigned> failures;
    unsigned count;
    { std::lock_guard<std::mutex> lock(mutex); count = ++failures[stage]; }
    if (count <= 8 || (count & (count - 1)) == 0)
        ALOGE("NetworkHook: SOCKS failure stage=%s errno=%d count=%u", stage, error, count);
    errno = error;
    return false;
}

bool socksReplyFailure(uint8_t reply, int error) {
    errno = error;
    static std::atomic<unsigned> failures{0};
    unsigned count = ++failures;
    if (count <= 8 || (count & (count - 1)) == 0)
        ALOGE("NetworkHook: SOCKS failure stage=connect-reply reply=%u errno=%d count=%u", reply, error, count);
    errno = error;
    return false;
}

bool negotiate(int fd, const sockaddr_in &destination, const std::string *hostname, int64_t deadline) {
    const bool auth = !config.user.empty() || !config.password.empty();
    // Do not offer no-auth when credentials were requested: accepting it would allow
    // a proxy (or an on-path endpoint) to silently downgrade authentication.
    uint8_t greeting[3] = {5, 1, static_cast<uint8_t>(auth ? 2 : 0)};
    if (!writeAll(fd, greeting, sizeof(greeting), deadline)) return socksFailure("greeting-write", errno);
    uint8_t selection[2];
    if (!readAll(fd, selection, sizeof(selection), deadline)) return socksFailure("method-read", errno);
    if (selection[0] != 5 || selection[1] == 0xff) return socksFailure("method-read", EACCES);
    if (auth && selection[1] == 2) {
        std::string request;
        request.push_back(1);
        request.push_back(static_cast<char>(config.user.size()));
        request += config.user;
        request.push_back(static_cast<char>(config.password.size()));
        request += config.password;
        if (!writeAll(fd, reinterpret_cast<const uint8_t *>(request.data()), request.size(), deadline))
            return socksFailure("auth-write", errno);
        uint8_t response[2];
        if (!readAll(fd, response, sizeof(response), deadline)) return socksFailure("auth-read", errno);
        if (response[0] != 1 || response[1] != 0) return socksFailure("auth-read", EACCES);
    } else if ((!auth && selection[1] != 0) || (auth && selection[1] != 2)) {
        return socksFailure("method-read", EACCES);
    }

    if (hostname) {
        if (hostname->empty() || hostname->size() > 255) return socksFailure("connect-write", EINVAL);
        std::string request;
        request.reserve(hostname->size() + 7);
        request.append("\x05\x01\x00\x03", 4);
        request.push_back(static_cast<char>(hostname->size()));
        request += *hostname;
        request.append(reinterpret_cast<const char *>(&destination.sin_port), 2);
        if (!writeAll(fd, reinterpret_cast<const uint8_t *>(request.data()), request.size(), deadline))
            return socksFailure("connect-write", errno);
    } else {
        uint8_t request[10] = {5, 1, 0, 1};
        memcpy(request + 4, &destination.sin_addr.s_addr, 4);
        memcpy(request + 8, &destination.sin_port, 2);
        if (!writeAll(fd, request, sizeof(request), deadline)) return socksFailure("connect-write", errno);
    }
    uint8_t header[4];
    if (!readAll(fd, header, sizeof(header), deadline)) return socksFailure("reply-header-read", errno);
    if (header[0] != 5 || header[2] != 0) return socksFailure("reply-header-read", EPROTO);
    if (header[1] != 0) return socksReplyFailure(header[1], replyErrno(header[1]));
    size_t tail = 0;
    if (header[3] == 1) tail = 6;
    else if (header[3] == 4) tail = 18;
    else if (header[3] == 3) {
        uint8_t length;
        if (!readAll(fd, &length, 1, deadline)) return socksFailure("reply-tail-read", errno);
        tail = static_cast<size_t>(length) + 2;
    } else { return socksFailure("reply-header-read", EPROTO); }
    uint8_t discard[257];
    if (!readAll(fd, discard, tail, deadline)) return socksFailure("reply-tail-read", errno);
    return true;
}

bool waitForProxyConnect(int fd, int64_t deadline) {
    for (;;) {
        int64_t remaining = deadline - nowMs();
        if (remaining <= 0) { errno = ETIMEDOUT; return false; }
        pollfd pfd{fd, POLLOUT, 0};
        int pollResult = poll(&pfd, 1, static_cast<int>(remaining > INT_MAX ? INT_MAX : remaining));
        int pollErrno = pollResult < 0 ? errno : 0;
        ALOGD("NetworkHook: proxy TCP poll result=%d revents=%d errno=%d",
              pollResult, static_cast<int>(pfd.revents), pollErrno);
        errno = pollErrno;
        if (pollResult > 0) return true;
        if (pollResult == 0) { errno = ETIMEDOUT; return false; }
        if (pollErrno != EINTR) return false;
    }
}

bool connectWithDeadline(int fd, const sockaddr *address, socklen_t length, int64_t deadline) {
    if (!authorizeTransport(fd, address, length)) return false;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return false;
    int result = originalConnect(fd, address, length);
    int error = result == 0 ? 0 : errno;
    if (result != 0 && error == EINPROGRESS) {
        if (waitForProxyConnect(fd, deadline)) {
            socklen_t errorLength = sizeof(error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errorLength) != 0) error = errno;
        } else {
            error = errno;
        }
    }
    if (fcntl(fd, F_SETFL, flags) != 0 && error == 0) error = errno;
    if (error != 0) { errno = error; return false; }
    return true;
}

void probeProxyOnce(int originalError) {
    if (!flowSocketPath.empty()) return; // No unregistered diagnostic network traffic.
    if (originalError != EINVAL && originalError != EAFNOSUPPORT) return;
    bool expected = false;
    if (!proxyProbeAttempted.compare_exchange_strong(expected, true)) return;

    int probeError = 0;
    bool connected = false;
    int probeFd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (probeFd < 0) {
        probeError = errno;
    } else {
        int flags = fcntl(probeFd, F_GETFL, 0);
        if (flags < 0 || fcntl(probeFd, F_SETFL, flags | O_NONBLOCK) != 0) {
            probeError = errno;
        } else {
            int result = originalConnect(probeFd, reinterpret_cast<const sockaddr *>(&config.proxy),
                                         sizeof(config.proxy));
            probeError = result == 0 ? 0 : errno;
            if (result == 0) {
                connected = true;
            } else if (probeError == EINPROGRESS) {
                pollfd pfd{probeFd, POLLOUT, 0};
                int pollResult;
                do {
                    pollResult = poll(&pfd, 1, kProbeTimeoutMs);
                } while (pollResult < 0 && errno == EINTR);
                if (pollResult > 0) {
                    int socketError = 0;
                    socklen_t errorLength = sizeof(socketError);
                    if (getsockopt(probeFd, SOL_SOCKET, SO_ERROR, &socketError, &errorLength) == 0) {
                        probeError = socketError;
                        connected = socketError == 0;
                    } else {
                        probeError = errno;
                    }
                } else {
                    probeError = pollResult == 0 ? ETIMEDOUT : errno;
                }
            }
        }
        close(probeFd);
    }
    ALOGD("NetworkHook: one-shot clean-socket proxy probe success=%d errno=%d",
          connected ? 1 : 0, probeError);
    errno = originalError;
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

bool socksAuthenticate(int fd, int64_t deadline) {
    const bool auth = !config.user.empty() || !config.password.empty();
    uint8_t greeting[3] = {5, 1, static_cast<uint8_t>(auth ? 2 : 0)};
    if (!writeAll(fd, greeting, sizeof(greeting), deadline)) return socksFailure("udp-greeting-write", errno);
    uint8_t selection[2];
    if (!readAll(fd, selection, sizeof(selection), deadline) || selection[0] != 5 || selection[1] == 0xff)
        return socksFailure("udp-method-read", EACCES);
    if ((!auth && selection[1] != 0) || (auth && selection[1] != 2))
        return socksFailure("udp-method-read", EACCES);
    if (auth) {
        std::string request(1, 1);
        request.push_back(static_cast<char>(config.user.size())); request += config.user;
        request.push_back(static_cast<char>(config.password.size())); request += config.password;
        if (!writeAll(fd, reinterpret_cast<const uint8_t *>(request.data()), request.size(), deadline))
            return socksFailure("udp-auth-write", errno);
        uint8_t response[2];
        if (!readAll(fd, response, 2, deadline) || response[0] != 1 || response[1] != 0)
            return socksFailure("udp-auth-read", EACCES);
    }
    return true;
}

bool ensureUdpAssociation(const std::shared_ptr<UdpState> &state) {
    if (state->associated) return true;
    if (!config.valid) return socksFailure("udp-configuration", EINVAL);
    const int64_t deadline = nowMs() + kTimeoutMs;
    int control = originalSocket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (control < 0) return socksFailure("udp-control-socket", errno);
    if (!connectWithDeadline(control, reinterpret_cast<const sockaddr *>(&config.proxy), sizeof(config.proxy), deadline) ||
        !socksAuthenticate(control, deadline)) {
        int error = errno; closeTransport(control); return socksFailure("udp-connect-or-auth", error);
    }
    // RFC 1928: 0.0.0.0:0 asks the server to choose the relay and source binding.
    uint8_t request[10] = {5, 3, 0, 1, 0, 0, 0, 0, 0, 0};
    if (!writeAll(control, request, sizeof(request), deadline)) {
        int error = errno; closeTransport(control); return socksFailure("udp-associate-write", error);
    }
    uint8_t header[4];
    if (!readAll(control, header, 4, deadline)) {
        int error = errno; closeTransport(control); return socksFailure("udp-associate-header", error);
    }
    if (header[0] != 5 || header[2] != 0) {
        closeTransport(control); return socksFailure("udp-associate-header", EPROTO);
    }
    if (header[1] != 0) {
        int error = replyErrno(header[1]); closeTransport(control);
        return socksFailure("udp-associate-reply", error);
    }
    sockaddr_storage relay{};
    if (header[3] == 1) {
        auto *v4 = reinterpret_cast<sockaddr_in *>(&relay); v4->sin_family = AF_INET;
        if (!readAll(control, reinterpret_cast<uint8_t *>(&v4->sin_addr), 4, deadline) ||
            !readAll(control, reinterpret_cast<uint8_t *>(&v4->sin_port), 2, deadline)) {
            int error = errno; closeTransport(control); return socksFailure("udp-associate-tail", error);
        }
        // Servers commonly return INADDR_ANY to mean the TCP peer address.
        if (v4->sin_addr.s_addr == INADDR_ANY) v4->sin_addr = config.proxy.sin_addr;
        state->relayLength = sizeof(sockaddr_in);
    } else if (header[3] == 4) {
        auto *v6 = reinterpret_cast<sockaddr_in6 *>(&relay); v6->sin6_family = AF_INET6;
        if (!readAll(control, reinterpret_cast<uint8_t *>(&v6->sin6_addr), 16, deadline) ||
            !readAll(control, reinterpret_cast<uint8_t *>(&v6->sin6_port), 2, deadline)) {
            int error = errno; closeTransport(control); return socksFailure("udp-associate-tail", error);
        }
        state->relayLength = sizeof(sockaddr_in6);
    } else if (header[3] == 3) {
        uint8_t nameLength = 0;
        if (!readAll(control, &nameLength, 1, deadline) || nameLength == 0) {
            int error = errno ? errno : EPROTO; closeTransport(control); return socksFailure("udp-associate-tail", error);
        }
        std::string relayName(nameLength, '\0'); uint16_t relayPort;
        if (!readAll(control, reinterpret_cast<uint8_t *>(&relayName[0]), nameLength, deadline) ||
            !readAll(control, reinterpret_cast<uint8_t *>(&relayPort), 2, deadline)) {
            int error = errno; closeTransport(control); return socksFailure("udp-associate-tail", error);
        }
        // A DOMAIN relay is valid RFC1928. Resolve only this proxy-supplied control
        // endpoint; guest hostnames never enter this path and remain SOCKS DOMAIN.
        addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM;
        addrinfo *answers = nullptr;
        int resolveError = originalGetAddrInfo(relayName.c_str(), nullptr, &hints, &answers);
        if (resolveError != 0 || !answers || answers->ai_addrlen > sizeof(relay)) {
            if (answers) freeaddrinfo(answers); closeTransport(control); return socksFailure("udp-relay-resolution", EHOSTUNREACH);
        }
        memcpy(&relay, answers->ai_addr, answers->ai_addrlen); state->relayLength = answers->ai_addrlen;
        if (relay.ss_family == AF_INET) reinterpret_cast<sockaddr_in *>(&relay)->sin_port = relayPort;
        else if (relay.ss_family == AF_INET6) reinterpret_cast<sockaddr_in6 *>(&relay)->sin6_port = relayPort;
        else { freeaddrinfo(answers); closeTransport(control); return socksFailure("udp-relay-family", EAFNOSUPPORT); }
        freeaddrinfo(answers);
    } else {
        closeTransport(control); return socksFailure("udp-associate-type", EAFNOSUPPORT);
    }
    state->control = control; state->relay = relay; state->associated = true;
    return true;
}

std::shared_ptr<UdpState> udpState(int fd, bool create) {
    std::lock_guard<std::mutex> lock(udpStatesMutex);
    auto found = udpStates.find(fd);
    if (found != udpStates.end()) return found->second;
    if (!create) return nullptr;
    int type = 0, domain = AF_UNSPEC; socklen_t length = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) || type != SOCK_DGRAM) return nullptr;
    length = sizeof(domain);
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &length) || (domain != AF_INET && domain != AF_INET6)) return nullptr;
    auto state = std::make_shared<UdpState>(); udpStates.emplace(fd, state); return state;
}

bool normalizeDestination(const sockaddr *address, socklen_t length, sockaddr_in *destination) {
    if (!address || length < sizeof(sa_family_t)) { errno = EDESTADDRREQ; return false; }
    if (address->sa_family == AF_INET && length >= sizeof(sockaddr_in)) {
        *destination = *reinterpret_cast<const sockaddr_in *>(address); return true;
    }
    if (address->sa_family == AF_INET6 && length >= sizeof(sockaddr_in6)) {
        const auto *v6 = reinterpret_cast<const sockaddr_in6 *>(address);
        if (!IN6_IS_ADDR_V4MAPPED(&v6->sin6_addr)) { errno = EAFNOSUPPORT; return false; }
        destination->sin_family = AF_INET; destination->sin_port = v6->sin6_port;
        memcpy(&destination->sin_addr, &v6->sin6_addr.s6_addr[12], 4); return true;
    }
    errno = EAFNOSUPPORT; return false;
}

ssize_t udpSend(int fd, const void *buffer, size_t size, int flags,
                const sockaddr *address, socklen_t length) {
    auto state = udpState(fd, true);
    if (!state) { ALOGE("NetworkPolicy: unhandled Internet path=sendto-non-INET-datagram"); errno = EPROTONOSUPPORT; return -1; }
    std::lock_guard<std::mutex> lock(state->mutex);
    if (!address && state->peerLength) { address = reinterpret_cast<const sockaddr *>(&state->peer); length = state->peerLength; }
    sockaddr_in destination{};
    if (!normalizeDestination(address, length, &destination) || !ensureUdpAssociation(state)) return -1;
    std::string hostname; bool synthetic = mappedHostname(destination.sin_addr.s_addr, &hostname);
    if (isFakeAddress(destination.sin_addr.s_addr) && !synthetic) { errno = EHOSTUNREACH; return -1; }
    std::vector<uint8_t> packet; packet.reserve(size + 262);
    packet.insert(packet.end(), {0, 0, 0, static_cast<uint8_t>(synthetic ? 3 : 1)});
    if (synthetic) { packet.push_back(static_cast<uint8_t>(hostname.size())); packet.insert(packet.end(), hostname.begin(), hostname.end()); }
    else { const uint8_t *ip = reinterpret_cast<const uint8_t *>(&destination.sin_addr); packet.insert(packet.end(), ip, ip + 4); }
    const uint8_t *port = reinterpret_cast<const uint8_t *>(&destination.sin_port); packet.insert(packet.end(), port, port + 2);
    const size_t headerSize = packet.size();
    const uint8_t *data = reinterpret_cast<const uint8_t *>(buffer); packet.insert(packet.end(), data, data + size);
    sockaddr_storage relay = state->relay; socklen_t relayLength = state->relayLength;
    int domain = AF_INET; socklen_t dl = sizeof(domain); getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &dl);
    if (domain == AF_INET6 && relay.ss_family == AF_INET) {
        auto *mapped = reinterpret_cast<sockaddr_in6 *>(&relay); auto v4 = *reinterpret_cast<sockaddr_in *>(&state->relay);
        memset(mapped, 0, sizeof(*mapped)); mapped->sin6_family = AF_INET6; mapped->sin6_port = v4.sin_port;
        mapped->sin6_addr.s6_addr[10] = mapped->sin6_addr.s6_addr[11] = 0xff;
        memcpy(&mapped->sin6_addr.s6_addr[12], &v4.sin_addr, 4); relayLength = sizeof(*mapped);
    }
    if (!authorizeTransport(fd, reinterpret_cast<sockaddr *>(&relay), relayLength, packet.data(), headerSize, state->control)) return -1;
    ssize_t result = originalSendTo(fd, packet.data(), packet.size(), flags,
                                    reinterpret_cast<sockaddr *>(&relay), relayLength);
    if (result >= 0) {
        static std::atomic<unsigned> forwarded{0};
        unsigned count = ++forwarded;
        if (count <= 4 || (count & (count - 1)) == 0)
            ALOGD("NetworkPolicy: UDP SOCKS forwarded count=%u", count);
        return static_cast<ssize_t>(size);
    }
    return -1;
}

int hookedConnect(int fd, const sockaddr *address, socklen_t length) {
    if (!config.requested) return originalConnect(fd, address, length);
    if (!address || length < sizeof(sa_family_t)) { errno = EINVAL; return -1; }
    if (address->sa_family == AF_UNIX) {
        if (!loggedUnix.exchange(true)) ALOGD("NetworkPolicy: AF_UNIX passthrough");
        return originalConnect(fd, address, length);
    }
    int type = 0; socklen_t typeLength = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &typeLength) != 0) return -1;
    if (!config.valid) { errno = EINVAL; return -1; }

    if (type == SOCK_DGRAM) {
        sockaddr_in ignored{};
        if (!normalizeDestination(address, length, &ignored)) return -1;
        auto state = udpState(fd, true);
        if (!state) { errno = EPROTONOSUPPORT; return -1; }
        std::lock_guard<std::mutex> lock(state->mutex);
        memcpy(&state->peer, address, length); state->peerLength = length;
        return ensureUdpAssociation(state) ? 0 : -1;
    }
    if (type != SOCK_STREAM) {
        ALOGE("NetworkPolicy: unhandled Internet path=connect socket-type=%d", type);
        errno = EPROTONOSUPPORT; return -1;
    }

    sockaddr_in normalized{};
    if (!normalizeDestination(address, length, &normalized)) return -1;

    const auto &destination = normalized;
    std::string hostname;
    const bool synthetic = mappedHostname(destination.sin_addr.s_addr, &hostname);
    if (isFakeAddress(destination.sin_addr.s_addr) && !synthetic) {
        ALOGE("NetworkHook: unmapped synthetic-range connect blocked");
        errno = EHOSTUNREACH;
        return -1;
    }
    if (synthetic) ALOGD("NetworkHook: synthetic domain connect recognized");

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    int domain = AF_UNSPEC;
    socklen_t domainLength = sizeof(domain);
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &domainLength) != 0) {
        int error = errno;
        ALOGE("NetworkHook: proxy handoff SO_DOMAIN failed fd=%d errno=%d", fd, error);
        errno = error;
        return -1;
    }
    sockaddr_storage local{};
    socklen_t localLength = sizeof(local);
    int localResult = getsockname(fd, reinterpret_cast<sockaddr *>(&local), &localLength);
    int localError = localResult == 0 ? 0 : errno;
    int localFamily = localResult == 0 ? local.ss_family : AF_UNSPEC;
    int v6Only = -1;
    int v6OnlyError = 0;
    if (domain == AF_INET6) {
        socklen_t v6OnlyLength = sizeof(v6Only);
        if (getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6Only, &v6OnlyLength) != 0) {
            v6OnlyError = errno;
        }
    }
    ALOGD("NetworkHook: proxy handoff fd=%d domain=%d type=%d nonblock=%d "
          "local_result=%d local_family=%d local_errno=%d synthetic=%d v6only=%d v6only_errno=%d",
          fd, domain, type, (flags & O_NONBLOCK) ? 1 : 0, localResult, localFamily, localError,
          synthetic ? 1 : 0, v6Only, v6OnlyError);

    sockaddr_in6 mappedProxy{};
    const sockaddr *proxyAddress = nullptr;
    socklen_t proxyLength = 0;
    if (domain == AF_INET) {
        proxyAddress = reinterpret_cast<const sockaddr *>(&config.proxy);
        proxyLength = sizeof(config.proxy);
    } else if (domain == AF_INET6) {
        if (v6OnlyError != 0) {
            ALOGE("NetworkHook: proxy handoff IPV6_V6ONLY inspection failed errno=%d", v6OnlyError);
            errno = v6OnlyError;
            return -1;
        }
        if (v6Only != 0) {
            ALOGE("NetworkHook: proxy handoff blocked: AF_INET6 socket is IPV6_V6ONLY");
            errno = EAFNOSUPPORT;
            return -1;
        }
        mappedProxy.sin6_family = AF_INET6;
        mappedProxy.sin6_port = config.proxy.sin_port;
        mappedProxy.sin6_addr.s6_addr[10] = 0xff;
        mappedProxy.sin6_addr.s6_addr[11] = 0xff;
        memcpy(&mappedProxy.sin6_addr.s6_addr[12], &config.proxy.sin_addr.s_addr, 4);
        proxyAddress = reinterpret_cast<const sockaddr *>(&mappedProxy);
        proxyLength = sizeof(mappedProxy);
    } else {
        ALOGE("NetworkHook: proxy handoff blocked: unsupported socket domain=%d", domain);
        errno = EAFNOSUPPORT;
        return -1;
    }

    if (!authorizeTransport(fd, proxyAddress, proxyLength)) return -1;
    if (!(flags & O_NONBLOCK) && fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return -1;
    const int64_t deadline = nowMs() + kTimeoutMs;
    ALOGD("NetworkHook: proxy TCP connect start fd=%d socket_domain=%d proxy_family=%d",
          fd, domain, proxyAddress->sa_family);
    int result = originalConnect(fd, proxyAddress, proxyLength);
    int connectError = result == 0 ? 0 : errno;
    ALOGD("NetworkHook: proxy TCP connect immediate result=%d errno=%d", result, connectError);
    errno = connectError;
    if (result != 0 && connectError == EINPROGRESS) {
        ALOGD("NetworkHook: proxy TCP connect EINPROGRESS path entered");
        if (waitForProxyConnect(fd, deadline)) {
            int socketError = 0;
            socklen_t errorLength = sizeof(socketError);
            int optionResult = getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &errorLength);
            int optionError = optionResult == 0 ? 0 : errno;
            ALOGD("NetworkHook: proxy TCP SO_ERROR result=%d value=%d errno=%d",
                  optionResult, socketError, optionError);
            if (optionResult == 0 && socketError == 0) {
                result = 0;
                errno = 0;
            } else {
                errno = optionResult == 0 ? socketError : optionError;
                result = -1;
            }
        } else {
            result = -1;
        }
    } else if (result != 0) {
        probeProxyOnce(connectError);
        errno = connectError;
    }
    if (result == 0) ALOGD("NetworkHook: proxy TCP connection established");
    if (result == 0 && !negotiate(fd, destination, synthetic ? &hostname : nullptr, deadline)) {
        // This descriptor is connected to the proxy, not the requested peer.  Poison it
        // before returning so callers cannot accidentally use or retry this partial path.
        int negotiationErrno = errno;
        shutdown(fd, SHUT_RDWR);
        errno = negotiationErrno;
        result = -1;
    }
    if (synthetic) {
        int operationError = errno;
        if (result == 0) ALOGD("NetworkHook: SOCKS DOMAIN connect succeeded");
        else ALOGE("NetworkHook: SOCKS DOMAIN connect failed (errno=%d)", operationError);
        errno = operationError;
    }
    // A nonblocking caller must observe the conventional EINPROGRESS -> writable ->
    // SO_ERROR=0 sequence.  Negotiation is completed before exposure, so epoll cannot
    // wake the guest while the descriptor still points at an unauthenticated proxy.
    bool reportInProgress = result == 0 && (flags & O_NONBLOCK);
    int savedErrno = reportInProgress ? EINPROGRESS : errno;
    if (!(flags & O_NONBLOCK) && fcntl(fd, F_SETFL, flags) != 0 && result == 0) { savedErrno = errno; result = -1; }
    if (result != 0) releaseFlow(fd);
    errno = savedErrno;
    return reportInProgress ? -1 : result;
}

ssize_t hookedSendTo(int fd, const void *buffer, size_t size, int flags,
                     const sockaddr *address, socklen_t length) {
    if (!config.requested) return originalSendTo(fd, buffer, size, flags, address, length);
    if (address && address->sa_family == AF_UNIX)
        return originalSendTo(fd, buffer, size, flags, address, length);
    int type = 0, domain = AF_UNSPEC; socklen_t tl = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &tl) || type != SOCK_DGRAM)
        return originalSendTo(fd, buffer, size, flags, address, length);
    tl = sizeof(domain);
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &tl) || (domain != AF_INET && domain != AF_INET6))
        return originalSendTo(fd, buffer, size, flags, address, length);
    return udpSend(fd, buffer, size, flags, address, length);
}

bool sameEndpoint(const sockaddr_storage &expected, socklen_t, const sockaddr_storage &actual, socklen_t) {
    if (expected.ss_family == AF_INET && actual.ss_family == AF_INET6) {
        const auto *a = reinterpret_cast<const sockaddr_in *>(&expected);
        const auto *b = reinterpret_cast<const sockaddr_in6 *>(&actual);
        return IN6_IS_ADDR_V4MAPPED(&b->sin6_addr) && a->sin_port == b->sin6_port &&
               memcmp(&a->sin_addr, &b->sin6_addr.s6_addr[12], 4) == 0;
    }
    if (expected.ss_family != actual.ss_family) return false;
    if (expected.ss_family == AF_INET) {
        const auto *a = reinterpret_cast<const sockaddr_in *>(&expected);
        const auto *b = reinterpret_cast<const sockaddr_in *>(&actual);
        return a->sin_port == b->sin_port && a->sin_addr.s_addr == b->sin_addr.s_addr;
    }
    if (expected.ss_family == AF_INET6) {
        const auto *a = reinterpret_cast<const sockaddr_in6 *>(&expected);
        const auto *b = reinterpret_cast<const sockaddr_in6 *>(&actual);
        return a->sin6_port == b->sin6_port && a->sin6_scope_id == b->sin6_scope_id &&
               memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(in6_addr)) == 0;
    }
    return false;
}

ssize_t udpReceive(int fd, void *buffer, size_t size, int flags, sockaddr *source,
                   socklen_t *sourceLength, bool *truncated) {
    auto state = udpState(fd, false);
    if (!state) { errno = ENOTCONN; return -1; }
    std::vector<uint8_t> packet(65535 + 262);
    sockaddr_storage relay{}; socklen_t relayLength = sizeof(relay);
    ssize_t count = originalRecvFrom(fd, packet.data(), packet.size(), flags,
                                     reinterpret_cast<sockaddr *>(&relay), &relayLength);
    if (count < 0) return count;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (!sameEndpoint(state->relay, state->relayLength, relay, relayLength)) {
            ALOGE("NetworkPolicy: UDP packet rejected path=unexpected-relay");
            errno = EHOSTUNREACH; return -1;
        }
    }
    if (count < 7 || packet[0] || packet[1] || packet[2]) { errno = EPROTO; return -1; }
    size_t offset = 4; sockaddr_in decoded{}; decoded.sin_family = AF_INET;
    if (packet[3] == 1) {
        if (static_cast<size_t>(count) < offset + 6) { errno = EPROTO; return -1; }
        memcpy(&decoded.sin_addr, packet.data() + offset, 4); offset += 4;
    } else if (packet[3] == 3) {
        if (static_cast<size_t>(count) <= offset) { errno = EPROTO; return -1; }
        size_t hostLength = packet[offset++];
        if (static_cast<size_t>(count) < offset + hostLength + 2) { errno = EPROTO; return -1; }
        std::string hostname(reinterpret_cast<char *>(packet.data() + offset), hostLength); offset += hostLength;
        uint32_t fake; if (syntheticAddress(hostname.c_str(), &fake) != 0) { errno = EHOSTUNREACH; return -1; }
        decoded.sin_addr.s_addr = fake;
    } else { errno = EAFNOSUPPORT; return -1; }
    memcpy(&decoded.sin_port, packet.data() + offset, 2); offset += 2;
    size_t payload = static_cast<size_t>(count) - offset, copied = std::min(size, payload);
    memcpy(buffer, packet.data() + offset, copied);
    if (source && sourceLength) {
        int domain = AF_INET; socklen_t dl = sizeof(domain); getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &dl);
        if (domain == AF_INET6) {
            sockaddr_in6 mapped{}; mapped.sin6_family = AF_INET6; mapped.sin6_port = decoded.sin_port;
            mapped.sin6_addr.s6_addr[10] = mapped.sin6_addr.s6_addr[11] = 0xff;
            memcpy(&mapped.sin6_addr.s6_addr[12], &decoded.sin_addr, 4);
            socklen_t n = std::min(*sourceLength, static_cast<socklen_t>(sizeof(mapped))); memcpy(source, &mapped, n); *sourceLength = sizeof(mapped);
        } else {
            socklen_t n = std::min(*sourceLength, static_cast<socklen_t>(sizeof(decoded))); memcpy(source, &decoded, n); *sourceLength = sizeof(decoded);
        }
    }
    if (truncated) *truncated = payload > size;
    return ((flags & MSG_TRUNC) && payload > size) ? static_cast<ssize_t>(payload) : static_cast<ssize_t>(copied);
}

ssize_t hookedRecvFrom(int fd, void *buffer, size_t size, int flags, sockaddr *source, socklen_t *length) {
    if (!config.requested || !udpState(fd, false)) return originalRecvFrom(fd, buffer, size, flags, source, length);
    return udpReceive(fd, buffer, size, flags, source, length, nullptr);
}

ssize_t hookedSendMsg(int fd, const msghdr *message, int flags) {
    if (!config.requested) return originalSendMsg(fd, message, flags);
    if (message->msg_name && reinterpret_cast<const sockaddr *>(message->msg_name)->sa_family == AF_UNIX)
        return originalSendMsg(fd, message, flags);
    int type = 0, domain = AF_UNSPEC; socklen_t tl = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &tl) || type != SOCK_DGRAM)
        return originalSendMsg(fd, message, flags);
    tl = sizeof(domain);
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &tl) || (domain != AF_INET && domain != AF_INET6))
        return originalSendMsg(fd, message, flags);
    if (message->msg_controllen != 0) {
        ALOGE("NetworkPolicy: unhandled Internet path=sendmsg-ancillary");
        errno = EOPNOTSUPP; return -1;
    }
    size_t total = 0; for (size_t i = 0; i < message->msg_iovlen; ++i) total += message->msg_iov[i].iov_len;
    std::vector<uint8_t> data(total); size_t at = 0;
    for (size_t i = 0; i < message->msg_iovlen; ++i) { memcpy(data.data() + at, message->msg_iov[i].iov_base, message->msg_iov[i].iov_len); at += message->msg_iov[i].iov_len; }
    return udpSend(fd, data.data(), data.size(), flags, reinterpret_cast<const sockaddr *>(message->msg_name), message->msg_namelen);
}

ssize_t hookedRecvMsg(int fd, msghdr *message, int flags) {
    if (!config.requested || !udpState(fd, false)) return originalRecvMsg(fd, message, flags);
    size_t total = 0; for (size_t i = 0; i < message->msg_iovlen; ++i) total += message->msg_iov[i].iov_len;
    std::vector<uint8_t> data(total); sockaddr_storage source{}; socklen_t sourceLength = sizeof(source);
    bool truncated = false;
    ssize_t count = udpReceive(fd, data.data(), data.size(), flags, reinterpret_cast<sockaddr *>(&source), &sourceLength, &truncated);
    if (count < 0) return count;
    size_t remaining = std::min(static_cast<size_t>(count), data.size()), at = 0;
    for (size_t i = 0; i < message->msg_iovlen && remaining; ++i) { size_t n = std::min(remaining, message->msg_iov[i].iov_len); memcpy(message->msg_iov[i].iov_base, data.data() + at, n); at += n; remaining -= n; }
    if (message->msg_name) { size_t n = std::min(static_cast<size_t>(message->msg_namelen), static_cast<size_t>(sourceLength)); memcpy(message->msg_name, &source, n); message->msg_namelen = sourceLength; }
    message->msg_controllen = 0;
    message->msg_flags = truncated ? MSG_TRUNC : 0;
    return count;
}

ssize_t hookedSend(int fd, const void *buffer, size_t size, int flags) {
    if (!config.requested || !udpState(fd, false)) return originalSend(fd, buffer, size, flags);
    return udpSend(fd, buffer, size, flags, nullptr, 0);
}
ssize_t hookedRecv(int fd, void *buffer, size_t size, int flags) {
    if (!config.requested || !udpState(fd, false)) return originalRecv(fd, buffer, size, flags);
    return udpReceive(fd, buffer, size, flags, nullptr, nullptr, nullptr);
}
ssize_t hookedWrite(int fd, const void *buffer, size_t size) {
    if (!config.requested || !udpState(fd, false)) return originalWrite(fd, buffer, size);
    return udpSend(fd, buffer, size, 0, nullptr, 0);
}
ssize_t hookedRead(int fd, void *buffer, size_t size) {
    if (!config.requested || !udpState(fd, false)) return originalRead(fd, buffer, size);
    return udpReceive(fd, buffer, size, 0, nullptr, nullptr, nullptr);
}
ssize_t hookedWriteV(int fd, const iovec *vectors, int count) {
    if (!config.requested || !udpState(fd, false)) return originalWriteV(fd, vectors, count);
    size_t total = 0; for (int i = 0; i < count; ++i) total += vectors[i].iov_len;
    std::vector<uint8_t> data(total); size_t at = 0;
    for (int i = 0; i < count; ++i) { memcpy(data.data() + at, vectors[i].iov_base, vectors[i].iov_len); at += vectors[i].iov_len; }
    return udpSend(fd, data.data(), data.size(), 0, nullptr, 0);
}
ssize_t hookedReadV(int fd, const iovec *vectors, int count) {
    if (!config.requested || !udpState(fd, false)) return originalReadV(fd, vectors, count);
    size_t total = 0; for (int i = 0; i < count; ++i) total += vectors[i].iov_len;
    std::vector<uint8_t> data(total);
    ssize_t result = udpReceive(fd, data.data(), data.size(), 0, nullptr, nullptr, nullptr);
    if (result < 0) return result;
    size_t remaining = static_cast<size_t>(result), at = 0;
    for (int i = 0; i < count && remaining; ++i) { size_t n = std::min(remaining, vectors[i].iov_len); memcpy(vectors[i].iov_base, data.data() + at, n); at += n; remaining -= n; }
    return result;
}

int hookedSocket(int domain, int type, int protocol) {
    int fd = originalSocket(domain, type, protocol);
    if (config.requested && fd >= 0 && (domain == AF_INET || domain == AF_INET6) &&
        ((type & 0xf) != SOCK_STREAM && (type & 0xf) != SOCK_DGRAM))
        ALOGE("NetworkPolicy: unhandled Internet path=socket type=%d protocol=%d", type & 0xf, protocol);
    return fd;
}
int hookedClose(int fd) { releaseFlow(fd); { std::lock_guard<std::mutex> lock(udpStatesMutex); udpStates.erase(fd); } return originalClose(fd); }
void duplicateState(int from, int to) {
    { std::lock_guard<std::mutex> lock(flowLeasesMutex); auto it = flowLeases.find(from); if (it != flowLeases.end()) flowLeases[to] = it->second; else flowLeases.erase(to); }
    { std::lock_guard<std::mutex> lock(udpStatesMutex); auto it = udpStates.find(from); if (it != udpStates.end()) udpStates[to] = it->second; else udpStates.erase(to); }
}
int hookedDup(int fd) { int result = originalDup(fd); if (result >= 0) duplicateState(fd, result); return result; }
int hookedDup2(int fd, int target) { int result = originalDup2(fd, target); if (result >= 0) duplicateState(fd, result); return result; }
int hookedDup3(int fd, int target, int flags) { int result = originalDup3(fd, target, flags); if (result >= 0) duplicateState(fd, result); return result; }
int hookedSendMMsg(int fd, mmsghdr *messages, unsigned count, int flags) {
    int type = 0; socklen_t length = sizeof(type);
    if (!config.requested || getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) || type != SOCK_DGRAM)
        return originalSendMMsg(fd, messages, count, flags);
    unsigned done = 0;
    for (; done < count; ++done) { ssize_t n = hookedSendMsg(fd, &messages[done].msg_hdr, flags); if (n < 0) return done ? static_cast<int>(done) : -1; messages[done].msg_len = static_cast<unsigned>(n); }
    return static_cast<int>(done);
}
int hookedRecvMMsg(int fd, mmsghdr *messages, unsigned count, int flags, timespec *timeout) {
    int type = 0; socklen_t length = sizeof(type);
    if (!config.requested || getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) || type != SOCK_DGRAM)
        return originalRecvMMsg(fd, messages, count, flags, timeout);
    unsigned done = 0;
    for (; done < count; ++done) { ssize_t n = hookedRecvMsg(fd, &messages[done].msg_hdr, flags | (done ? MSG_DONTWAIT : 0)); if (n < 0) return done ? static_cast<int>(done) : -1; messages[done].msg_len = static_cast<unsigned>(n); }
    return static_cast<int>(done);
}
int hookedSetNetwork(NetHandle network, int fd) {
    int domain = AF_UNSPEC; socklen_t length = sizeof(domain);
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &length) == 0 &&
        (domain == AF_INET || domain == AF_INET6)) {
        ALOGD("NetworkPolicy: Network.bindSocket retained on SOCKS virtual network");
        return 0;
    }
    return originalSetNetwork(network, fd);
}
int hookedSetProcessNetwork(NetHandle) {
    ALOGD("NetworkPolicy: process network selection retained on SOCKS virtual network");
    return 0;
}

void runSelfTestIfRequested(bool networkBinding, bool mmsg) {
    const char *requested = getenv("BLACKBOX_SOCKS_SELF_TEST");
    if (!requested || strcmp(requested, "1") != 0) return;
    ALOGD("NetworkSelfTest: BEGIN (one-shot; no direct DNS)");
    uint32_t fake = 0; int synthesis = syntheticAddress("self-test.invalid", &fake);
    std::string restored;
    ALOGD("NetworkSelfTest: fake-IP hostname resolution %s",
          synthesis == 0 && mappedHostname(fake, &restored) ? "PASS" : "FAIL stage=fake-ip");
    auto state = std::make_shared<UdpState>();
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        bool associated = ensureUdpAssociation(state);
        ALOGD("NetworkSelfTest: UDP ASSOCIATE %s",
              associated ? "PASS" : "FAIL stage=UDP-ASSOCIATE");
    }
    ALOGD("NetworkSelfTest: UDP numeric destination SKIP stage=no-diagnostic-peer");
    ALOGD("NetworkSelfTest: UDP hostname destination SKIP stage=no-diagnostic-peer");
    ALOGD("NetworkSelfTest: native blocking TCP SKIP stage=no-diagnostic-destination");
    ALOGD("NetworkSelfTest: native nonblocking TCP SKIP stage=no-diagnostic-destination");
    ALOGD("NetworkSelfTest: Java InetAddress/Socket SKIP stage=native-only-runner");
    ALOGD("NetworkSelfTest: libcore Os SKIP stage=native-only-runner");
    ALOGD("NetworkSelfTest: Android network binding SKIP stage=%s",
          networkBinding ? "installed-not-exercised" : "symbol-unavailable");
    ALOGD("NetworkSelfTest: sendmmsg/recvmmsg SKIP stage=%s",
          mmsg ? "installed-not-exercised" : "symbol-unavailable");
    ALOGD("NetworkSelfTest: WebView SKIP stage=requires-WebView-originated-request");
    ALOGD("NetworkSelfTest: END");
}
} // namespace

void NetworkHook::configure(JNIEnv *env, bool enabled, jstring host, int port,
                            jstring user, jstring password, jstring socketPath) {
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
    flowSocketPath = copy(socketPath);
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
    auto requiredHook = [handle](const char *name, void *replacement, void **original) {
        void *target = xdl_sym(handle, name, nullptr);
        if (!target || DobbyHook(target, replacement, original) != 0 || !*original) {
            ALOGE("NetworkPolicy: required native hook missing path=%s; terminating guest", name);
            abort();
        }
    };
    requiredHook("socket", reinterpret_cast<void *>(hookedSocket), reinterpret_cast<void **>(&originalSocket));
    requiredHook("sendto", reinterpret_cast<void *>(hookedSendTo), reinterpret_cast<void **>(&originalSendTo));
    requiredHook("recvfrom", reinterpret_cast<void *>(hookedRecvFrom), reinterpret_cast<void **>(&originalRecvFrom));
    requiredHook("sendmsg", reinterpret_cast<void *>(hookedSendMsg), reinterpret_cast<void **>(&originalSendMsg));
    requiredHook("recvmsg", reinterpret_cast<void *>(hookedRecvMsg), reinterpret_cast<void **>(&originalRecvMsg));
    requiredHook("send", reinterpret_cast<void *>(hookedSend), reinterpret_cast<void **>(&originalSend));
    requiredHook("recv", reinterpret_cast<void *>(hookedRecv), reinterpret_cast<void **>(&originalRecv));
    requiredHook("read", reinterpret_cast<void *>(hookedRead), reinterpret_cast<void **>(&originalRead));
    requiredHook("write", reinterpret_cast<void *>(hookedWrite), reinterpret_cast<void **>(&originalWrite));
    requiredHook("readv", reinterpret_cast<void *>(hookedReadV), reinterpret_cast<void **>(&originalReadV));
    requiredHook("writev", reinterpret_cast<void *>(hookedWriteV), reinterpret_cast<void **>(&originalWriteV));
    requiredHook("close", reinterpret_cast<void *>(hookedClose), reinterpret_cast<void **>(&originalClose));
    requiredHook("dup", reinterpret_cast<void *>(hookedDup), reinterpret_cast<void **>(&originalDup));
    requiredHook("dup2", reinterpret_cast<void *>(hookedDup2), reinterpret_cast<void **>(&originalDup2));
    requiredHook("dup3", reinterpret_cast<void *>(hookedDup3), reinterpret_cast<void **>(&originalDup3));
    void *sendMMsg = xdl_sym(handle, "sendmmsg", nullptr);
    void *recvMMsg = xdl_sym(handle, "recvmmsg", nullptr);
    bool mmsg = sendMMsg && recvMMsg &&
        DobbyHook(sendMMsg, reinterpret_cast<void *>(hookedSendMMsg), reinterpret_cast<void **>(&originalSendMMsg)) == 0 &&
        DobbyHook(recvMMsg, reinterpret_cast<void *>(hookedRecvMMsg), reinterpret_cast<void **>(&originalRecvMMsg)) == 0;
    bool networkBinding = false;
    void *netd = xdl_open("libnetd_client.so", XDL_DEFAULT);
    if (netd) {
        void *setNetwork = xdl_sym(netd, "android_setsocknetwork", nullptr);
        void *setProcessNetwork = xdl_sym(netd, "android_setprocnetwork", nullptr);
        networkBinding = setNetwork && setProcessNetwork &&
            DobbyHook(setNetwork, reinterpret_cast<void *>(hookedSetNetwork), reinterpret_cast<void **>(&originalSetNetwork)) == 0 &&
            DobbyHook(setProcessNetwork, reinterpret_cast<void *>(hookedSetProcessNetwork), reinterpret_cast<void **>(&originalSetProcessNetwork)) == 0;
        xdl_close(netd);
    }
    ALOGD("NetworkPolicy: coverage native=socket,connect,getaddrinfo,android_getaddrinfofornet,"
          "send,recv,read,write,readv,writev,sendto,sendmsg,recvfrom,recvmsg,close,dup* "
          "sendmmsg/recvmmsg=%s libcore=Os-native-entrypoints "
          "Binder=virtual-view/no-DNS bindSocket=%s WebView=libc",
          mmsg ? "installed" : "unavailable", networkBinding ? "virtualized" : "unavailable");
    runSelfTestIfRequested(networkBinding, mmsg);
    xdl_close(handle);
}
