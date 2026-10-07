#!/usr/bin/env python3
"""Compile and exercise the production allocator IPC functions on host AF_UNIX.
Android hook installation and Android credential APIs are not simulated here.
"""
from pathlib import Path
import subprocess
import tempfile
root = Path(__file__).resolve().parents[1]
source = (root / 'Bcore/src/main/cpp/Hook/NetworkHook.cpp').read_text()
def function(signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        if source[end] == '{': depth += 1
        elif source[end] == '}': depth -= 1
        end += 1
    return source[start:end]
# Use the definition rather than its forward declaration.
central = function('bool centralSyntheticAddress(const std::string &hostname, uint32_t *result) {')
code = r'''
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <poll.h>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <cerrno>
#include <netdb.h>
#include <vector>
#include <string>
#include <mutex>
#include <unordered_map>
#include <thread>
#include <cassert>
#include <cstdio>
#define ALOGD(...) ((void)0)
constexpr uint32_t kFakeNetwork=0xc6120000U, kFakeMask=0xfffe0000U, kFakeCapacity=1U<<17;
std::unordered_map<std::string,uint32_t> hostnameToAddress;
std::unordered_map<uint32_t,std::string> addressToHostname;
std::mutex mappingsMutex;
uint32_t nextFakeOffset=0;
std::string flowSocketPath;
struct { sockaddr_in proxy{}; } config;
'''
code += function('bool isFakeAddress(') + '\n' + central + '\n'
code += function('bool mappedHostname(') + '\n' + function('int syntheticAddress(') + '\n'
code += r'''
int main() {
    uint32_t a,b; std::string restored;
    assert(syntheticAddress("Local.Example.",&a)==0);
    assert(syntheticAddress("other.example",&b)==0 && a!=b);
    assert(mappedHostname(a,&restored) && restored=="local.example");
    char directory[]="/tmp/nbs-mapping-host.XXXXXX";
    assert(mkdtemp(directory));
    flowSocketPath=std::string(directory)+"/nbs-flow.sock";
    assert(syntheticAddress("local.example",&a)==EAI_AGAIN); // cached native entry cannot bypass missing broker
    assert(syntheticAddress("new.example",&a)==EAI_AGAIN);
    assert(!mappedHostname(b,&restored));
    std::string path=std::string(directory)+"/nbs-mapping.sock";
    int server=socket(AF_UNIX,SOCK_STREAM,0); assert(server>=0);
    sockaddr_un endpoint{}; endpoint.sun_family=AF_UNIX; strcpy(endpoint.sun_path,path.c_str());
    assert(bind(server,reinterpret_cast<sockaddr*>(&endpoint),sizeof(endpoint))==0);
    assert(listen(server,4)==0);
    std::thread broker([&] {
        for(int i=0;i<3;i++) {
            int fd=accept(server,nullptr,nullptr); assert(fd>=0);
            uint8_t header[6]; assert(recv(fd,header,6,MSG_WAITALL)==6);
            assert(memcmp(header,"NBM\1",4)==0);
            int size=(header[4]<<8)|header[5]; assert(size>0 && size<=253);
            std::vector<char> hostname(size); assert(recv(fd,hostname.data(),size,MSG_WAITALL)==size);
            assert(std::string(hostname.data(),size)=="central.example");
            uint32_t reply[2]={htonl(0x4e424d01),htonl(kFakeNetwork+500)};
            assert(send(fd,reply,8,MSG_NOSIGNAL)==8); close(fd);
        }
    });
    assert(syntheticAddress("Central.Example.",&a)==0 && ntohl(a)==kFakeNetwork+500);
    assert(syntheticAddress("central.example",&b)==0 && a==b);
    assert(mappedHostname(a,&restored) && restored=="central.example");
    assert(!mappedHostname(htonl(kFakeNetwork+501),&restored));
    broker.join(); close(server); unlink(path.c_str()); rmdir(directory);
    assert(syntheticAddress("central.example",&b)==EAI_AGAIN);
    flowSocketPath.clear(); assert(syntheticAddress("native-only.example",&b)==0);
    puts("Native production mapping checks passed: filesystem IPC, central reuse, unknown synthetic rejection, broker-unavailable failure including cached state, native-only allocation.");
}
'''
with tempfile.TemporaryDirectory(prefix='nbs-native-mapping-') as directory:
    test = Path(directory) / 'test.cpp'; test.write_text(code)
    executable = Path(directory) / 'test'
    subprocess.run(['g++', '-std=c++17', '-pthread', '-Wall', '-Wextra', '-Werror', str(test), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=15)
