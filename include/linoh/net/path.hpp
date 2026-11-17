#pragma once

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/util/bytes.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>

namespace linoh::net {

/// 路径状态：探测中、活跃、空闲、关闭。
enum class PathState { Probing, Active, Idle, Closed };

/// 四元组路径标识（P4-A-1，借鉴 iroh PR #4273/#4281）。
///
/// 用 (local_addr, remote_addr) 明确标识一条路径，便于：
///   - 路径迁移时准确判断"哪条路径变了"
///   - 日志输出明确的本端/对端地址对
///   - 与 PATH_CHALLENGE/RESPONSE 帧对应更清晰
///
/// 使用 base::TransportAddr（已含 TransportKind + host + port + custom_payload），
/// 覆盖 IP / Relay / Custom 三种传输类型。
struct FourTuple {
    base::TransportAddr local_addr;
    base::TransportAddr remote_addr;

    bool operator==(const FourTuple &) const = default;
    bool operator!=(const FourTuple &) const = default;

    /// "local_host:port -> remote_host:port" 格式（用于日志）。
    std::string to_string() const {
        std::ostringstream oss;
        oss << format_addr(local_addr) << " -> " << format_addr(remote_addr);
        return oss.str();
    }

    /// 序列化为字节流（local + remote 顺序拼接，每段为 host_len(1B)+host+port(2B BE)）。
    /// 用于持久化或哈希，不涉及 custom_payload（避免长度可变带来的歧义）。
    std::vector<std::uint8_t> to_bytes() const {
        std::vector<std::uint8_t> out;
        encode_one_addr(local_addr, out);
        encode_one_addr(remote_addr, out);
        return out;
    }

    /// 从字节流解析（与 to_bytes 对应）。
    static std::optional<FourTuple> from_bytes(std::span<const std::uint8_t> data) {
        FourTuple t;
        std::size_t pos = 0;
        if (!decode_one_addr(data, pos, t.local_addr)) return std::nullopt;
        if (!decode_one_addr(data, pos, t.remote_addr)) return std::nullopt;
        return t;
    }

    /// 用于 std::unordered_map<FourTuple, ...> 的哈希
    struct Hash {
        std::size_t operator()(const FourTuple &t) const noexcept {
            std::size_t h = 1469598103934665603ULL;
            auto mix = [&](const base::TransportAddr &a) {
                for (char c : a.host) { h ^= static_cast<std::size_t>(c); h *= 1099511628211ULL; }
                h ^= a.port; h *= 1099511628211ULL;
                h ^= static_cast<std::size_t>(a.kind); h *= 1099511628211ULL;
            };
            mix(t.local_addr);
            mix(t.remote_addr);
            return h;
        }
    };

private:
    static std::string format_addr(const base::TransportAddr &a) {
        std::ostringstream oss;
        switch (a.kind) {
            case base::TransportKind::Ip:    oss << "ip";    break;
            case base::TransportKind::Relay: oss << "relay"; break;
            case base::TransportKind::Custom:oss << "custom";break;
        }
        oss << ":" << a.host << ":" << a.port;
        return oss.str();
    }

    static void encode_one_addr(const base::TransportAddr &a, std::vector<std::uint8_t> &out) {
        // host_len(1B) + host + port(2B BE) + kind(1B)
        if (a.host.size() > 255) {
            // 超长 host 截断（不应发生在实际场景）
            out.push_back(255);
            out.insert(out.end(), a.host.begin(), a.host.begin() + 255);
        } else {
            out.push_back(static_cast<std::uint8_t>(a.host.size()));
            out.insert(out.end(), a.host.begin(), a.host.end());
        }
        out.push_back(static_cast<std::uint8_t>((a.port >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(a.port & 0xFF));
        out.push_back(static_cast<std::uint8_t>(a.kind));
    }

    static bool decode_one_addr(std::span<const std::uint8_t> data, std::size_t &pos, base::TransportAddr &a) {
        if (pos + 1 > data.size()) return false;
        std::uint8_t host_len = data[pos++];
        if (pos + host_len + 3 > data.size()) return false;
        a.host.assign(reinterpret_cast<const char *>(data.data() + pos), host_len);
        pos += host_len;
        a.port = (static_cast<std::uint16_t>(data[pos]) << 8) | static_cast<std::uint16_t>(data[pos + 1]);
        pos += 2;
        a.kind = static_cast<base::TransportKind>(data[pos++]);
        return true;
    }
};

/// 一条到达对端的路径：通过某个 Transport，去往特定地址。
///
/// 设计为只在单线程（executor 线程）内读写；唯一被跨线程访问的字段是
/// `rtt_ms_` 和 `packets_`——它们用 `std::atomic` 保护。
class Path {
public:
    Path(std::string transport_name, base::TransportAddr addr)
        : transport_name_{std::move(transport_name)}, addr_{std::move(addr)} {
        // P4-A-1: 同步初始化 four_tuple_ 的 remote_addr（local_addr 在 set_local_addr 时填入）
        four_tuple_.remote_addr = addr_;
    }

    const std::string &transport_name() const { return transport_name_; }
    const base::TransportAddr &addr() const { return addr_; }

    /// P4-A-1: 获取完整四元组（local_addr 可能未设置，host 为空）。
    const FourTuple &four_tuple() const { return four_tuple_; }

    /// P4-A-1: 设置本端地址（在 socket 收到包时由 connection 回填）。
    void set_local_addr(base::TransportAddr local) {
        four_tuple_.local_addr = std::move(local);
    }

    PathState state() const { return state_; }
    void set_state(PathState s) { state_ = s; }

    /// 当前 RTT 估计（毫秒），EMA。
    double rtt_ema_ms() const { return rtt_ms_.load(std::memory_order_relaxed); }

    /// 观测到一个新 RTT，更新 EMA（alpha = 0.125，与 QUIC 一致）。
    void observe_rtt(double rtt_ms) {
        double cur = rtt_ms_.load(std::memory_order_relaxed);
        double next = (cur == 0.0) ? rtt_ms : (cur * (1.0 - kAlpha) + rtt_ms * kAlpha);
        rtt_ms_.store(next, std::memory_order_relaxed);
        packets_.fetch_add(1, std::memory_order_relaxed);
        last_seen_ms_ = now_ms();
    }

    std::uint64_t last_seen_ms() const { return last_seen_ms_.load(std::memory_order_relaxed); }
    std::uint64_t packets() const { return packets_.load(std::memory_order_relaxed); }

    /// "优先级"：数值越小越好。默认：按 RTT 排序，Relay 路径被加惩罚（50ms）。
    double score(bool is_relay) const {
        double rtt = rtt_ms_.load(std::memory_order_relaxed);
        if (rtt == 0.0) rtt = 9999.0; // 未探测过的路径兜底
        return rtt + (is_relay ? kRelayPenaltyMs : 0.0);
    }

private:
    static constexpr double kAlpha = 0.125;
    static constexpr double kRelayPenaltyMs = 50.0;

    static std::uint64_t now_ms() {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count());
    }

    std::string transport_name_;
    base::TransportAddr addr_;
    /// P4-A-1: 完整四元组路径标识（local_addr + remote_addr）
    FourTuple four_tuple_;
    PathState state_{PathState::Probing};
    std::atomic<double> rtt_ms_{0.0};
    std::atomic<std::uint64_t> packets_{0};
    std::atomic<std::uint64_t> last_seen_ms_{0};
};

/// 路径选择器：从一组候选 path 中挑选"当前最佳"。
///
/// 默认实现为 `BiasedRttPathSelector`，按 Path::score() 排序并加少量滞回（hysteresis），
/// 避免每收到一个包都切换路径。
class PathSelector {
public:
    virtual ~PathSelector() = default;
    /// 返回当前最佳路径索引；paths 非空。
    virtual std::size_t select(const std::vector<std::shared_ptr<Path>> &paths) const = 0;
};

class BiasedRttPathSelector : public PathSelector {
public:
    std::size_t select(const std::vector<std::shared_ptr<Path>> &paths) const override {
        if (paths.empty()) return 0;
        std::size_t best = 0;
        double best_score = paths[0]->score(/*is_relay=*/paths[0]->transport_name().find("relay") != std::string::npos);
        for (std::size_t i = 1; i < paths.size(); ++i) {
            double score = paths[i]->score(/*is_relay=*/paths[i]->transport_name().find("relay") != std::string::npos);
            if (score + kHysteresisMs < best_score) {
                best_score = score;
                best = i;
            }
        }
        return best;
    }

private:
    static constexpr double kHysteresisMs = 25.0;
};

} // namespace linoh::net
