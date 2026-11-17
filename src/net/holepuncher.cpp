// holepuncher.cpp — NAT 打洞器实现（P4-C-3）

#include "linoh/net/holepuncher.hpp"

// P5-D-4: attempt_symmetric_adaptive 需要完整 PortPredictor 类型
#include "linoh/nat/port_predictor.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <random>
#include <thread>
#include <vector>

// ============================================================================
// S6（v5.3）打洞静默期提前收敛参数
// ============================================================================
namespace {
/// 循环收包周期（SO_RCVTIMEO）——静默判定的轮询粒度
constexpr int kPunchPollMs = 200;
/// 静默判死阈值：连续此时长无任何回包即提前失败（对称 NAT 对端回包
/// 通常 <500ms；800ms 静默基本可判对端不可达）
constexpr int kPunchQuiesceMs = 800;
/// 最小等待：静默判死前至少等待的时长（避免极快误判，预留对端首包 RTT）
constexpr int kPunchMinWaitMs = 300;
}  // namespace

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
// POSIX 平台 SOCKET 类型补丁（与 linoh_c.cpp 做法一致）
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
#endif

namespace linoh::net {

// ============================================================================
// HolepunchResult::to_string
// ============================================================================

std::string HolepunchResult::to_string() const {
    std::string s = "HolepunchResult{success=";
    s += (success ? "true" : "false");
    s += ", strategy=";
    s += std::string(Holepuncher::strategy_name(strategy_used));
    s += ", duration_ms=";
    s += std::to_string(duration.count());
    if (udp_probed) {
        s += ", udp_probe=";
        s += std::string(to_string_view(udp_probe.availability));
        s += "(loss=";
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%.0f%%", udp_probe.loss_rate * 100.0);
        s += buf;
        s += ")";
    }
    if (!error_msg.empty()) {
        s += ", error='";
        s += error_msg;
        s += "'";
    }
    s += "}";
    return s;
}

// ============================================================================
// 对称 NAT 端口预测算法
// ============================================================================

std::vector<std::uint16_t> predict_symmetric_nat_ports(
    std::uint16_t observed_port_1,
    std::uint16_t observed_port_2,
    std::size_t predictions_count) {

    std::vector<std::uint16_t> result;
    if (predictions_count == 0) return result;

    // 计算端口差值（处理 uint16 溢出）
    int delta = static_cast<int>(observed_port_2) - static_cast<int>(observed_port_1);

    // 防止重复端口
    std::vector<bool> seen(65536, false);
    seen[observed_port_1] = true;
    seen[observed_port_2] = true;

    auto try_add = [&](int port) {
        if (port < 1 || port > 65535) return;
        if (seen[port]) return;
        seen[port] = true;
        result.push_back(static_cast<std::uint16_t>(port));
    };

    if (delta != 0) {
        // 按差值外推：p2 + delta, p2 + 2*delta, ...
        for (std::size_t k = 1; k <= predictions_count; ++k) {
            int predicted = static_cast<int>(observed_port_2) + static_cast<int>(delta) * static_cast<int>(k);
            try_add(predicted);
            if (result.size() >= predictions_count) break;
        }
    }

    // 如果差值外推不够，补充简单增量（+1, +2, -1, -2）
    if (result.size() < predictions_count) {
        for (int offset : {1, 2, 3, -1, -2, -3, 4, 5, -4, -5}) {
            try_add(static_cast<int>(observed_port_2) + offset);
            if (result.size() >= predictions_count) break;
        }
    }

    // 还不够，补充 +k 的连续增量
    if (result.size() < predictions_count) {
        for (int k = 6; k < 1000 && result.size() < predictions_count; ++k) {
            try_add(static_cast<int>(observed_port_2) + k);
            try_add(static_cast<int>(observed_port_2) - k);
        }
    }

    return result;
}

// ============================================================================
// Holepuncher 公开接口
// ============================================================================

std::string_view Holepuncher::strategy_name(HolepunchStrategy s) {
    switch (s) {
        case HolepunchStrategy::None:            return "none";
        case HolepunchStrategy::StandardRfc5389: return "standard-rfc5389";
        case HolepunchStrategy::SymmetricNat:    return "symmetric-nat";
        case HolepunchStrategy::RelayFallback:   return "relay-fallback";
    }
    return "unknown";
}

HolepunchResult Holepuncher::attempt(
    const base::TransportAddr &local_addr,
    const base::TransportAddr &remote_addr,
    HolepunchStrategy strategy,
    std::chrono::milliseconds timeout) {

    return attempt(local_addr.host, local_addr.port,
                   remote_addr.host, remote_addr.port,
                   strategy, timeout);
}

HolepunchResult Holepuncher::attempt(
    const std::string &local_ip, std::uint16_t local_port,
    const std::string &remote_ip, std::uint16_t remote_port,
    HolepunchStrategy strategy,
    std::chrono::milliseconds timeout) {

    auto start = std::chrono::steady_clock::now();
    HolepunchResult result;
    result.strategy_used = strategy;

    if (strategy == HolepunchStrategy::None) {
        result.success = true;
        result.established_tuple.local_addr.kind = base::TransportKind::Ip;
        result.established_tuple.local_addr.host = local_ip;
        result.established_tuple.local_addr.port = local_port;
        result.established_tuple.remote_addr.kind = base::TransportKind::Ip;
        result.established_tuple.remote_addr.host = remote_ip;
        result.established_tuple.remote_addr.port = remote_port;
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }

    if (strategy == HolepunchStrategy::StandardRfc5389) {
        return attempt_standard(local_ip, local_port, remote_ip, remote_port, timeout);
    }

    if (strategy == HolepunchStrategy::SymmetricNat) {
        // nn-M1 (v3.6.0): 根因 — 对称 NAT 端口预测必须基于对端两次 STUN 探测
        // 观测到的外部映射端口（observed_port_1/2），而本重载仅有 remote_port
        // （对端 contact 端口，与其 NAT 外部映射端口无关）。原实现用 remote_port
        // 和 remote_port+2 作为伪观测值喂给 predict_symmetric_nat_ports，预测结果
        // 与对端真实 NAT 端口序列无关，必然打洞失败。
        //
        // 修复（P5-D-3）：本重载收到 SymmetricNat 时降级为 StandardRfc5389 +
        // 警告日志，而非走猜测模式。生产场景必须使用接受 remote_observed_port_1/2
        // 的专用重载（见下方 8 参数重载）。
        LINOH_WARN("Holepuncher: SymmetricNat strategy requires observed ports,",
                   "falling back to StandardRfc5389.",
                   "Use the overload with remote_observed_port_1/2 for accurate prediction.",
                   "local=", local_ip, ":", local_port,
                   "remote=", remote_ip, ":", remote_port);
        return attempt_standard(local_ip, local_port, remote_ip, remote_port, timeout);
    }

    if (strategy == HolepunchStrategy::RelayFallback) {
        result.error_msg = "relay fallback not directly supported in holepuncher";
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }

    result.error_msg = "unknown strategy";
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    return result;
}

// nn-M1 (v3.6.0): SymmetricNat 专用重载，接受对端两次 STUN 观测端口。
// 根因：predict_symmetric_nat_ports 算法要求输入对端 NAT 两次观测的外部端口，
// 据此外推下一次可能的端口。原 6 参数重载用 remote_port 当观测端口，
// 与对端真实 NAT 映射序列无关，预测必然失败。本重载由调用方（Endpoint）
// 在打洞前先通过 STUN 探测对端获得 observed_port_1/2，再传入做精确预测。
HolepunchResult Holepuncher::attempt(
    const std::string &local_ip, std::uint16_t local_port,
    const std::string &remote_ip, std::uint16_t remote_port,
    std::uint16_t remote_observed_port_1,
    std::uint16_t remote_observed_port_2,
    HolepunchStrategy strategy,
    std::chrono::milliseconds timeout) {

    // 非 SymmetricNat 策略：observed_ports 无意义，直接委托 6 参数重载。
    if (strategy != HolepunchStrategy::SymmetricNat) {
        return attempt(local_ip, local_port, remote_ip, remote_port,
                       strategy, timeout);
    }

    // SymmetricNat：用真实 STUN 观测端口做预测。
    auto predicted = predict_symmetric_nat_ports(
        remote_observed_port_1, remote_observed_port_2, 10);
    return attempt_symmetric(local_ip, local_port, remote_ip, predicted, timeout);
}

// ============================================================================
// P5-D-4: 自适应候选数的 SymmetricNat 打洞
// ============================================================================

std::vector<std::uint16_t> Holepuncher::build_adaptive_candidates(
    std::uint16_t remote_observed_port_1,
    std::uint16_t remote_observed_port_2,
    const nat::PortPredictor *predictor,
    const base::EndpointId &peer,
    bool &used_predictor_out,
    nat::PortPredictModel &model_used_out,
    double &confidence_out,
    std::size_t fanout_hint) {

    used_predictor_out = false;
    model_used_out = nat::PortPredictModel::TwoPoint;
    confidence_out = 0.0;

    std::vector<std::uint16_t> candidates;

    // 1. 优先使用 PortPredictor（自适应候选数 + 多模型融合）
    if (predictor != nullptr) {
        auto pred = predictor->predict(peer);  // count=0 自适应
        if (!pred.candidates.empty() && pred.confidence > 0.0) {
            candidates = pred.candidates;
            model_used_out = pred.model_used;
            confidence_out = pred.confidence;
            used_predictor_out = true;
            LINOH_INFO("Holepuncher: using PortPredictor,",
                       "confidence=", confidence_out,
                       "candidates=", candidates.size(),
                       "model=", static_cast<int>(model_used_out));
        } else {
            LINOH_INFO("Holepuncher: PortPredictor cold start, fallback to fixed 10");
        }
    }

    // 2. 回退：固定候选（PortPredictor 不可用 / 冷启动）——
    //    S6-②（v5.3）：fanout_hint>0 时按 nat_stats 自适应扇出（低成功率
    //    类型加大并发端口对），默认 10（v3.6.0 原值）
    if (candidates.empty()) {
        const std::size_t count = (fanout_hint > 0) ? fanout_hint : 10;
        candidates = predict_symmetric_nat_ports(
            remote_observed_port_1, remote_observed_port_2, count);
    }

    // 3. 追加两个 STUN 观测端口作为兜底（确保候选列表包含已知端口）
    auto append_if_missing = [&](std::uint16_t port) {
        if (std::find(candidates.begin(), candidates.end(), port) == candidates.end()) {
            candidates.push_back(port);
        }
    };
    append_if_missing(remote_observed_port_1);
    append_if_missing(remote_observed_port_2);

    return candidates;
}

HolepunchResult Holepuncher::attempt_symmetric_adaptive(
    const std::string &local_ip, std::uint16_t local_port,
    const std::string &remote_ip, std::uint16_t remote_port,
    std::uint16_t remote_observed_port_1,
    std::uint16_t remote_observed_port_2,
    nat::PortPredictor *predictor,
    const base::EndpointId &peer,
    std::chrono::milliseconds timeout,
    std::size_t fanout_hint) {

    // 1. 构建自适应候选端口列表
    bool used_predictor = false;
    nat::PortPredictModel model_used = nat::PortPredictModel::TwoPoint;
    double confidence = 0.0;
    auto candidates = build_adaptive_candidates(
        remote_observed_port_1, remote_observed_port_2,
        predictor, peer,
        used_predictor, model_used, confidence,
        fanout_hint);

    // 2. 执行打洞（P0-G4: 高置信度走单一目的模式，避免多端口触发多 NAT 映射）
    SingleDestConfig sdc;
    HolepunchResult result;
    if (should_use_single_dest(confidence, candidates.size(), sdc)) {
        LINOH_INFO("Holepuncher: high confidence (", confidence,
                   "), using single-dest mode for peer");
        result = attempt_symmetric_single_dest(
            local_ip, local_port, remote_ip, candidates, timeout, sdc);
    } else {
        LINOH_DEBUG("Holepuncher: low confidence (", confidence,
                    "), fallback to multi-port concurrent");
        result = attempt_symmetric(local_ip, local_port, remote_ip,
                                   candidates, timeout);
    }

    // 3. 成功后反馈给 PortPredictor（修正 Hybrid 模型权重）
    if (result.success && predictor != nullptr && used_predictor) {
        std::uint16_t actual_port = result.established_tuple.remote_addr.port;
        // 检查 actual 是否在候选列表中
        bool hit = (std::find(candidates.begin(), candidates.end(), actual_port)
                    != candidates.end());
        // predicted: 命中时用 actual，未命中时用第一个预测候选
        std::uint16_t predicted = hit ? actual_port :
                                  (candidates.empty() ? 0 : candidates[0]);
        predictor->feedback(peer, predicted, actual_port, hit, model_used);
        LINOH_INFO("Holepuncher: feedback recorded,",
                   "hit=", hit,
                   "predicted=", predicted,
                   "actual=", actual_port);
    }

    return result;
}

// ============================================================================
// 标准 STUN 打洞
// ============================================================================

HolepunchResult Holepuncher::attempt_standard(
    const std::string &local_ip, std::uint16_t local_port,
    const std::string &remote_ip, std::uint16_t remote_port,
    std::chrono::milliseconds timeout) {

    auto start = std::chrono::steady_clock::now();
    HolepunchResult result;
    result.strategy_used = HolepunchStrategy::StandardRfc5389;

    // 创建 UDP socket
    SOCKET sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#ifdef _WIN32
    if (sock == INVALID_SOCKET) {
        result.error_msg = "socket() failed: " + std::to_string(WSAGetLastError());
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }
#else
    if (sock < 0) {
        result.error_msg = "socket() failed";
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }
#endif

    // 绑定到指定本地地址
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(local_port);
    if (inet_pton(AF_INET, local_ip.c_str(), &local.sin_addr) != 1) {
        local.sin_addr.s_addr = htonl(INADDR_ANY);  // 回退到任意地址
    }
    if (::bind(sock, reinterpret_cast<sockaddr *>(&local), sizeof(local)) != 0) {
        result.error_msg = "bind() failed";
#ifdef _WIN32
        closesocket(sock);
#else
        ::close(sock);
#endif
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }

    // 设置非阻塞 + 接收超时
#ifdef _WIN32
    DWORD ms = static_cast<DWORD>((std::min<std::int64_t>)(timeout.count(), 5000));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&ms), sizeof(ms));
#else
    struct timeval tv;
    tv.tv_sec = timeout.count() / 1000;
    tv.tv_usec = (timeout.count() % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    // 远端地址
    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(remote_port);
    if (inet_pton(AF_INET, remote_ip.c_str(), &remote.sin_addr) != 1) {
        result.error_msg = "invalid remote ip";
#ifdef _WIN32
        closesocket(sock);
#else
        ::close(sock);
#endif
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }

    // 打洞：向远端发送多个 UDP 包（保持 NAT 映射）
    LINOH_INFO("Holepuncher: sending probe packets to ", remote_ip, ":", remote_port);
    std::vector<std::uint8_t> probe_data = {0x4c, 0x49, 0x4e, 0x4f, 0x48};  // "LINOH"
    for (int i = 0; i < 3; ++i) {
        auto sent = ::sendto(sock, reinterpret_cast<const char *>(probe_data.data()),
                              static_cast<int>(probe_data.size()), 0,
                              reinterpret_cast<sockaddr *>(&remote), sizeof(remote));
        if (sent < 0) {
            LINOH_WARN("Holepuncher: sendto failed on attempt ", i);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // 等待远端响应（实际打洞成功标志）
    std::array<std::uint8_t, 2048> recv_buf{};
    sockaddr_storage from{};
    socklen_t from_len = sizeof(from);
    auto n = ::recvfrom(sock, reinterpret_cast<char *>(recv_buf.data()),
                        static_cast<int>(recv_buf.size()), 0,
                        reinterpret_cast<sockaddr *>(&from), &from_len);

#ifdef _WIN32
    closesocket(sock);
#else
    ::close(sock);
#endif

    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);

    if (n > 0) {
        result.success = true;
        result.established_tuple.local_addr.kind = base::TransportKind::Ip;
        result.established_tuple.local_addr.host = local_ip;
        result.established_tuple.local_addr.port = local_port;
        result.established_tuple.remote_addr.kind = base::TransportKind::Ip;
        result.established_tuple.remote_addr.host = remote_ip;
        result.established_tuple.remote_addr.port = remote_port;
        LINOH_INFO("Holepuncher: success, received ", n, " bytes from ", remote_ip);
    } else {
        result.error_msg = "no response from remote";
        LINOH_INFO("Holepuncher: failed, no response");
    }

    return result;
}

// ============================================================================
// 对称 NAT 端口预测打洞
// ============================================================================

HolepunchResult Holepuncher::attempt_symmetric(
    const std::string &local_ip, std::uint16_t local_port,
    const std::string &remote_ip,
    const std::vector<std::uint16_t> &predicted_ports,
    std::chrono::milliseconds timeout) {

    auto start = std::chrono::steady_clock::now();
    HolepunchResult result;
    result.strategy_used = HolepunchStrategy::SymmetricNat;

    if (predicted_ports.empty()) {
        result.error_msg = "no predicted ports";
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }

    // 为每个预测端口尝试发送探测包（并行发包）
    SOCKET sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#ifdef _WIN32
    if (sock == INVALID_SOCKET) {
        result.error_msg = "socket() failed";
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }
#else
    if (sock < 0) {
        result.error_msg = "socket() failed";
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }
#endif

    // 绑定本地
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(local_port);
    if (inet_pton(AF_INET, local_ip.c_str(), &local.sin_addr) != 1) {
        local.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    if (::bind(sock, reinterpret_cast<sockaddr *>(&local), sizeof(local)) != 0) {
        result.error_msg = "bind() failed";
#ifdef _WIN32
        closesocket(sock);
#else
        ::close(sock);
#endif
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }

#ifdef _WIN32
    // S6（v5.3）静默期提前收敛：SO_RCVTIMEO 用短周期（kPunchPollMs），配合下方
    // 循环 recvfrom 的静默判据——对称 NAT 打洞对端回包通常 <500ms，
    // 连续 kPunchQuiesceMs 无任何回包即可判死，避免吃满 timeout
    //（patchbay S5 场景 34.9s 的主要成分即多轮 × 5s 硬等）。
    DWORD ms = static_cast<DWORD>(kPunchPollMs);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&ms), sizeof(ms));
#else
    struct timeval tv;
    tv.tv_sec = kPunchPollMs / 1000;
    tv.tv_usec = (kPunchPollMs % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv);
#endif

    // 向所有预测端口发包
    std::vector<std::uint8_t> probe_data = {0x4c, 0x49, 0x4e, 0x4f, 0x48};
    for (std::uint16_t port : predicted_ports) {
        sockaddr_in remote{};
        remote.sin_family = AF_INET;
        remote.sin_port = htons(port);
        if (inet_pton(AF_INET, remote_ip.c_str(), &remote.sin_addr) != 1) continue;
        ::sendto(sock, reinterpret_cast<const char *>(probe_data.data()),
                 static_cast<int>(probe_data.size()), 0,
                 reinterpret_cast<sockaddr *>(&remote), sizeof(remote));
    }

    LINOH_INFO("Holepuncher: sent probes to ", predicted_ports.size(),
               " predicted ports on ", remote_ip);

    // S6（v5.3）循环收包 + 静默提前收敛：
    //   - 收到目标主机任一候选端口回包 → 成功（原语义）
    //   - 杂包（非目标）→ 忽略继续等（原单次 recvfrom 会把杂包误当响应）
    //   - 持续 kPunchQuiesceMs 无任何包且已过 kPunchMinWaitMs → 提前失败
    //   - 总等待仍受 timeout 封顶
    std::array<std::uint8_t, 2048> recv_buf{};
    sockaddr_storage from{};
    socklen_t from_len = sizeof(from);
    auto punch_start = std::chrono::steady_clock::now();
    auto last_activity = punch_start;
    std::int64_t n = -1;
    std::uint16_t from_port = 0;
    while (true) {
        from_len = sizeof(from);
        n = ::recvfrom(sock, reinterpret_cast<char *>(recv_buf.data()),
                       static_cast<int>(recv_buf.size()), 0,
                       reinterpret_cast<sockaddr *>(&from), &from_len);
        auto now = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                              now - punch_start).count();
        if (n > 0) {
            std::uint16_t fp = 0;
            char from_ip[64] = {0};
            if (from.ss_family == AF_INET) {
                auto *sin = reinterpret_cast<sockaddr_in *>(&from);
                fp = ntohs(sin->sin_port);
                inet_ntop(AF_INET, &sin->sin_addr, from_ip, sizeof(from_ip));
            }
            bool from_target =
                (std::string(from_ip) == remote_ip) &&
                std::find(predicted_ports.begin(), predicted_ports.end(), fp) !=
                    predicted_ports.end();
            if (from_target) {
                from_port = fp;
                break;  // 成功
            }
            last_activity = now;  // 杂包：继续等
            continue;
        }
        auto silent_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                             now - last_activity).count();
        if (elapsed_ms >= timeout.count()) break;  // 总超时（原语义）
        if (silent_ms >= kPunchQuiesceMs && elapsed_ms >= kPunchMinWaitMs) {
            LINOH_INFO("Holepuncher: quiesce early-exit (silent=", silent_ms,
                       "ms, elapsed=", elapsed_ms, "ms)");
            break;  // 静默判死
        }
    }

#ifdef _WIN32
    closesocket(sock);
#else
    ::close(sock);
#endif

    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);

    if (n > 0 && from_port > 0) {
        result.success = true;
        result.established_tuple.local_addr.kind = base::TransportKind::Ip;
        result.established_tuple.local_addr.host = local_ip;
        result.established_tuple.local_addr.port = local_port;
        result.established_tuple.remote_addr.kind = base::TransportKind::Ip;
        result.established_tuple.remote_addr.host = remote_ip;
        result.established_tuple.remote_addr.port = from_port;
        LINOH_INFO("Holepuncher: symmetric NAT holepunched on port ", from_port);
    } else {
        result.error_msg = "no response from predicted ports";
    }

    return result;
}

// ============================================================================
// P0-G4: 单一目的地址外发（对称 NAT 端口预测模式）
// ============================================================================

std::size_t Holepuncher::single_dest_max_attempts(
    std::size_t candidates_size, const SingleDestConfig &config) {
    if (candidates_size == 0) return 0;
    std::size_t want = static_cast<std::size_t>(config.fallback_retries) + 1;
    return (std::min)(want, candidates_size);
}

bool Holepuncher::should_use_single_dest(
    double confidence, std::size_t candidates_size,
    const SingleDestConfig &config) {
    if (!config.enabled) return false;
    if (candidates_size == 0) return false;
    return confidence >= config.confidence_threshold;
}

HolepunchResult Holepuncher::attempt_symmetric_single_dest(
    const std::string &local_ip, std::uint16_t local_port,
    const std::string &remote_ip,
    const std::vector<std::uint16_t> &predicted_ports,
    std::chrono::milliseconds timeout,
    const SingleDestConfig &config) {

    auto start = std::chrono::steady_clock::now();
    HolepunchResult result;
    result.strategy_used = HolepunchStrategy::SymmetricNat;

    if (predicted_ports.empty()) {
        result.error_msg = "no predicted ports";
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }

    // config.enabled=false 回退多端口并发（兼容旧行为）
    if (!config.enabled) {
        return attempt_symmetric(local_ip, local_port, remote_ip,
                                 predicted_ports, timeout);
    }

    std::size_t max_attempts = single_dest_max_attempts(predicted_ports.size(), config);
    result.single_dest_used = true;

    // 创建 UDP socket（复用 attempt_symmetric 的跨平台模式）
    SOCKET sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#ifdef _WIN32
    if (sock == INVALID_SOCKET) {
        result.error_msg = "socket() failed: " + std::to_string(WSAGetLastError());
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }
#else
    if (sock < 0) {
        result.error_msg = "socket() failed";
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }
#endif

    // 绑定本地地址
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(local_port);
    if (inet_pton(AF_INET, local_ip.c_str(), &local.sin_addr) != 1) {
        local.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    if (::bind(sock, reinterpret_cast<sockaddr *>(&local), sizeof(local)) != 0) {
        result.error_msg = "bind() failed";
#ifdef _WIN32
        closesocket(sock);
#else
        ::close(sock);
#endif
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }

    // 单次 recvfrom 超时 = min(response_timeout, 总预算 timeout)
    std::chrono::milliseconds per_recv = (std::min)(
        config.response_timeout, timeout);

#ifdef _WIN32
    DWORD ms = static_cast<DWORD>((std::min<std::int64_t>)(per_recv.count(), 5000));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&ms), sizeof(ms));
#else
    struct timeval tv;
    tv.tv_sec = per_recv.count() / 1000;
    tv.tv_usec = (per_recv.count() % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    // 探测载荷（"LINOH"，与 attempt_symmetric 一致）
    std::vector<std::uint8_t> probe_data = {0x4c, 0x49, 0x4e, 0x4f, 0x48};

    // 按顺序向单一目的发包，失败回退到下一个候选
    for (std::size_t i = 0; i < max_attempts; ++i) {
        std::uint16_t port = predicted_ports[i];
        result.single_dest_attempts = static_cast<std::uint16_t>(i + 1);

        sockaddr_in remote{};
        remote.sin_family = AF_INET;
        remote.sin_port = htons(port);
        if (inet_pton(AF_INET, remote_ip.c_str(), &remote.sin_addr) != 1) {
            LINOH_WARN("Holepuncher: single-dest inet_pton failed for ",
                       remote_ip, ", skip port ", port);
            continue;
        }
        ::sendto(sock, reinterpret_cast<const char *>(probe_data.data()),
                 static_cast<int>(probe_data.size()), 0,
                 reinterpret_cast<sockaddr *>(&remote), sizeof(remote));

        LINOH_INFO("Holepuncher: single-dest attempt ", i + 1, "/", max_attempts,
                   " to ", remote_ip, ":", port);

        // 等待该端口的响应
        std::array<std::uint8_t, 2048> recv_buf{};
        sockaddr_storage from{};
        socklen_t from_len = sizeof(from);
        auto n = ::recvfrom(sock, reinterpret_cast<char *>(recv_buf.data()),
                            static_cast<int>(recv_buf.size()), 0,
                            reinterpret_cast<sockaddr *>(&from), &from_len);

        if (n > 0) {
            std::uint16_t from_port = 0;
            char from_ip[64] = {0};
            if (from.ss_family == AF_INET) {
                auto *sin = reinterpret_cast<sockaddr_in *>(&from);
                from_port = ntohs(sin->sin_port);
                inet_ntop(AF_INET, &sin->sin_addr, from_ip, sizeof(from_ip));
            }
            // S6（v5.3）源校验：仅目标主机的回包算成功（原实现任意杂包
            // 都会误判成功并建立错误 tuple）；端口不限定（对端 NAT 重映射）
            if (from_port > 0 && std::string(from_ip) == remote_ip) {
                result.success = true;
                result.single_dest_port = port;
                result.established_tuple.local_addr.kind = base::TransportKind::Ip;
                result.established_tuple.local_addr.host = local_ip;
                result.established_tuple.local_addr.port = local_port;
                result.established_tuple.remote_addr.kind = base::TransportKind::Ip;
                result.established_tuple.remote_addr.host = remote_ip;
                result.established_tuple.remote_addr.port = from_port;
                LINOH_INFO("Holepuncher: single-dest holepunched on port ",
                           port, " (attempt ", i + 1, "/", max_attempts, ")");
                break;
            }
        }
        // 超时或失败，回退到下一个候选
        LINOH_DEBUG("Holepuncher: single-dest attempt ", i + 1,
                    " no response, fallback to next candidate");
    }

#ifdef _WIN32
    closesocket(sock);
#else
    ::close(sock);
#endif

    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);

    if (!result.success) {
        result.error_msg = "no response from single-dest attempts (" +
                           std::to_string(result.single_dest_attempts) + " tried)";
    }

    return result;
}

// ============================================================================
// P0-G1: 带 UDP 可用性探测的打洞（NAT 穿透优化）
// ============================================================================

HolepunchResult Holepuncher::attempt_with_probe(
    const std::string &local_ip, std::uint16_t local_port,
    const std::string &remote_ip, std::uint16_t remote_port,
    HolepunchStrategy strategy,
    std::chrono::milliseconds timeout,
    const UdpProbeConfig &probe_config) {

    auto start = std::chrono::steady_clock::now();
    HolepunchResult result;
    result.strategy_used = strategy;

    // 步骤 1：UDP 可用性探测
    LINOH_INFO("Holepuncher: attempt_with_probe, probing UDP to ",
               remote_ip, ":", remote_port);
    result.udp_probe = UdpProber::probe(
        local_ip, local_port, remote_ip, remote_port, probe_config);
    result.udp_probed = true;

    // 步骤 2：根据探测结果决策
    if (result.udp_probe.availability == UdpAvailability::NotAvailable) {
        // UDP 不可用，直接返回失败，由上层 TcpFallback 降级
        result.success = false;
        result.error_msg = "UDP not available (loss_rate=" +
                           std::to_string(result.udp_probe.loss_rate) +
                           "), fallback to TCP/Relay required";
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        LINOH_WARN("Holepuncher: UDP not available, skip holepunch, ",
                   "loss_rate=", result.udp_probe.loss_rate,
                   ", fallback required");
        return result;
    }

    if (result.udp_probe.availability == UdpAvailability::Bad) {
        // UDP 质量差，仍尝试打洞但记录警告（上层可启用 FEC 增强）
        LINOH_WARN("Holepuncher: UDP bad quality (loss_rate=",
                   result.udp_probe.loss_rate,
                   "), proceeding with holepunch (FEC recommended)");
    } else {
        LINOH_INFO("Holepuncher: UDP available (loss_rate=",
                   result.udp_probe.loss_rate, "), proceeding with holepunch");
    }

    // 步骤 3：执行实际打洞（委托原 attempt 逻辑）
    // 保留 UDP 探测结果，避免重复探测
    auto probe_snapshot = result.udp_probe;
    result = attempt(local_ip, local_port, remote_ip, remote_port,
                     strategy, timeout);
    result.udp_probed = true;
    result.udp_probe = probe_snapshot;

    return result;
}

} // namespace linoh::net
