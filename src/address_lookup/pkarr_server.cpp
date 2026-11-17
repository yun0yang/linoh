// linoh/address_lookup/pkarr_server.cpp — 自建 Pkarr DNS Server 实现
//
// 原生 UDP 服务端：单线程 select 循环，进程内内存表存储 publisher 预签的包。
// 收到 DNS 查询 -> 提取 NodeId -> 命中回传 SignedPacket，未命中回 NXDOMAIN。

#include "linoh/address_lookup/pkarr_server.hpp"

#include "linoh/util/logging.hpp"

#include <chrono>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define PKARR_SOCKET SOCKET
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#define PKARR_SOCKET int
#endif

namespace linoh::address_lookup {

namespace {
/// 构造 NXDOMAIN 响应（仅 header，RCODE=3），供未命中时回送。
/// 长度 < 64+12，客户端 deserialize 会失败 -> 视为未找到。
std::vector<uint8_t> build_nxdomain(uint16_t id) {
    // flags: QR=1, RCODE=3
    return pkarr::encode_dns_header(id, 0x8003, 0, 0);
}
}  // namespace

PkarrDnsServer::~PkarrDnsServer() { stop(); }

util::ResultVoid PkarrDnsServer::start(std::string listen_host, uint16_t port) {
    if (running_.load()) return util::ResultVoid{};  // 已在运行，视为成功
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return util::ResultVoid(util::ConnectionError::InternalError, "WSAStartup failed");
    }
#endif
    std::intptr_t s = static_cast<std::intptr_t>(
        ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
#ifdef _WIN32
    if (s == static_cast<std::intptr_t>(INVALID_SOCKET)) {
        WSACleanup();
        return util::ResultVoid(util::ConnectionError::InternalError, "socket() failed");
    }
#else
    if (s < 0) {
        return util::ResultVoid(util::ConnectionError::InternalError, "socket() failed");
    }
#endif
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
#ifdef _WIN32
    addr.sin_addr.s_addr = inet_addr(listen_host.c_str());
#else
    inet_pton(AF_INET, listen_host.c_str(), &addr.sin_addr);
#endif
    if (::bind(static_cast<PKARR_SOCKET>(s), reinterpret_cast<sockaddr *>(&addr),
               sizeof(addr)) != 0) {
#ifdef _WIN32
        ::closesocket(static_cast<PKARR_SOCKET>(s));
        WSACleanup();
#else
        ::close(static_cast<int>(s));
#endif
        return util::ResultVoid(util::ConnectionError::InternalError,
                                "bind() failed (port in use?)");
    }
    sock_ = s;
    bind_ = listen_host;
    port_ = port;
    running_.store(true);
    thread_ = std::thread(&PkarrDnsServer::run_loop, this);
    return util::ResultVoid{};
}

void PkarrDnsServer::stop() {
    if (!running_.exchange(false)) return;  // 幂等
    // 先关 socket 以解除 run_loop 的 select 阻塞，再 join 线程（单一权威统一 join）
    if (sock_ != -1) {
#ifdef _WIN32
        if (static_cast<PKARR_SOCKET>(sock_) != INVALID_SOCKET) {
            ::closesocket(static_cast<PKARR_SOCKET>(sock_));
        }
#else
        ::close(static_cast<int>(sock_));
#endif
        sock_ = -1;
    }
    if (thread_.joinable()) thread_.join();
#ifdef _WIN32
    WSACleanup();
#endif
}

void PkarrDnsServer::publish(const base::EndpointId &id,
                             const pkarr::SignedPacket &sp) {
    std::lock_guard<std::mutex> lk(mu_);
    records_[id] = sp;
}

size_t PkarrDnsServer::record_count() const {
    std::lock_guard<std::mutex> lk(mu_);
    return records_.size();
}

void PkarrDnsServer::run_loop() {
    std::uint8_t buf[8192];
    sockaddr_in from{};
#ifdef _WIN32
    int fromlen = static_cast<int>(sizeof(from));
#else
    socklen_t fromlen = sizeof(from);
#endif
    while (running_.load()) {
        fd_set fds;
        FD_ZERO(&fds);
#ifdef _WIN32
        FD_SET(static_cast<PKARR_SOCKET>(sock_), &fds);
#else
        FD_SET(static_cast<int>(sock_), &fds);
#endif
        timeval tv{0, 200000};  // 200ms 切片轮询 running_
        int r = ::select(static_cast<int>(sock_) + 1, &fds, nullptr, nullptr, &tv);
        if (r <= 0) continue;
        int n = static_cast<int>(::recvfrom(static_cast<PKARR_SOCKET>(sock_),
                                             reinterpret_cast<char *>(buf), sizeof(buf), 0,
                                             reinterpret_cast<sockaddr *>(&from), &fromlen));
        if (n <= 0) continue;
        auto pkt = std::span<const std::uint8_t>(buf, static_cast<std::size_t>(n));
        auto q = pkarr::parse_dns_query(pkt);
        if (!q) {
            LINOH_WARN("PkarrDnsServer: dropped malformed query");
            continue;
        }
        pkarr::SignedPacket sp;
        bool found = false;
        {
            std::lock_guard<std::mutex> lk(mu_);
            auto it = records_.find(q->node_id);
            if (it != records_.end()) {
                sp = it->second;
                found = true;
            }
        }
        std::vector<std::uint8_t> resp =
            found ? pkarr::serialize_signed_packet(sp) : build_nxdomain(q->id);
        ::sendto(static_cast<PKARR_SOCKET>(sock_),
                 reinterpret_cast<const char *>(resp.data()),
                 static_cast<int>(resp.size()), 0,
                 reinterpret_cast<sockaddr *>(&from), fromlen);
    }
}

}  // namespace linoh::address_lookup
