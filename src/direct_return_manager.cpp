// direct_return_manager.cpp — Direct Return Path 管理器实现（v3.2.0）
//
// PP 链末节点 RESULT 直连回传 MASTER 的核心管理类实现。
// 详见 direct_return_manager.hpp 设计说明。

#include "linoh/direct_return_manager.hpp"

#include "linoh/endpoint/endpoint.hpp"
#include "linoh/endpoint/connection.hpp"
#include "linoh/protocol/application_message.hpp"
#include "linoh/protocol/return_address.hpp"
#include "linoh/base/key.hpp"
#include "linoh/address_lookup/lookup.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <thread>

namespace linoh {

// ============================================================================
// 构造 / 析构
// ============================================================================

DirectReturnManager::DirectReturnManager(endpoint::Endpoint *endpoint)
    : endpoint_(endpoint) {}

DirectReturnManager::~DirectReturnManager() {
    cleanup_idle_connections();
    // 清理所有 return slot，设置异常以唤醒等待的 future
    std::lock_guard<std::mutex> lk(slots_mu_);
    for (auto &kv : return_slots_) {
        try {
            kv.second->promise.set_exception(
                std::make_exception_ptr(std::runtime_error("DirectReturnManager destroyed")));
        } catch (...) {}
    }
    return_slots_.clear();
    req_id_to_token_.clear();
}

// ============================================================================
// MASTER 端 API
// ============================================================================

void DirectReturnManager::register_inbound_handler() {
    if (!endpoint_) return;
    // 覆盖式注册 accept handler；pp-llm/1 由本管理器接管，其他 ALPN 走 fallback
    endpoint_->set_accept_handler([this](endpoint::Incoming inc) {
        if (inc.alpn == "pp-llm/1") {
            // 捕获 conn 共享所有权，保证 on_stream 回调期间 conn 存活
            auto conn = inc.conn;
            conn->on_stream([this, conn](std::shared_ptr<endpoint::Stream> s) {
                this->handle_inbound_stream_(s, conn);
            });
        } else if (fallback_accept_handler_) {
            fallback_accept_handler_(std::move(inc));
        }
        // else: 忽略其他 ALPN
    });
}

std::uint32_t DirectReturnManager::register_return_slot(std::uint64_t req_id) {
    auto now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    std::uint32_t token = compute_stream_token_(req_id, now_ms);

    auto slot = std::make_unique<ReturnSlot>();
    slot->req_id = req_id;
    slot->created_at = std::chrono::steady_clock::now();

    {
        std::lock_guard<std::mutex> lk(slots_mu_);
        // 冲突时重试（极低概率）：递增 timestamp 部分
        while (return_slots_.count(token) != 0) {
            now_ms++;
            token = compute_stream_token_(req_id, now_ms);
        }
        slot->token = token;
        // P1: 防御性处理——同一 req_id 重复注册时，先唤醒旧 slot 的 future
        auto rit = req_id_to_token_.find(req_id);
        if (rit != req_id_to_token_.end()) {
            auto old_it = return_slots_.find(rit->second);
            if (old_it != return_slots_.end()) {
                try {
                    old_it->second->promise.set_exception(std::make_exception_ptr(
                        std::runtime_error("return slot superseded by re-register")));
                } catch (...) {}
                return_slots_.erase(old_it);
            }
        }
        return_slots_[token] = std::move(slot);
        req_id_to_token_[req_id] = token;  // P1: 建立反向映射
    }

    {
        std::lock_guard<std::mutex> lk(stats_mu_);
        stats_.return_slots_registered++;
    }
    return token;
}

std::future<std::vector<std::uint8_t>> DirectReturnManager::await_return_result(
    std::uint32_t stream_token,
    std::chrono::milliseconds timeout) {
    std::promise<std::vector<std::uint8_t>> *prom = nullptr;
    {
        std::lock_guard<std::mutex> lk(slots_mu_);
        auto it = return_slots_.find(stream_token);
        if (it == return_slots_.end()) {
            // slot 不存在：返回一个已就绪的异常 future
            std::promise<std::vector<std::uint8_t>> p;
            p.set_exception(std::make_exception_ptr(
                std::runtime_error("return slot not found")));
            return p.get_future();
        }
        prom = &it->second->promise;
    }
    // 注意：调用方需自行处理超时（future::wait_for），此处仅返回 future
    return prom->get_future();
}

void DirectReturnManager::cancel_return_slot(std::uint32_t stream_token) {
    auto slot = take_slot_(stream_token);  // P1: 统一取走入口（同步清理反向映射）
    if (!slot) return;
    try {
        slot->promise.set_exception(
            std::make_exception_ptr(std::runtime_error("return slot cancelled")));
    } catch (...) {}
    std::lock_guard<std::mutex> slk(stats_mu_);
    stats_.return_slots_cancelled++;
}

bool DirectReturnManager::inject_hop_by_hop_result(
    std::uint64_t req_id,
    std::span<const std::uint8_t> result_payload) {
    std::uint32_t token = 0;
    bool found = false;
    {
        std::lock_guard<std::mutex> lk(slots_mu_);
        auto it = req_id_to_token_.find(req_id);
        if (it != req_id_to_token_.end()) {
            token = it->second;
            found = true;
        }
    }
    {
        std::lock_guard<std::mutex> lk(stats_mu_);
        stats_.fallback_invoked++;
    }
    if (!found) return false;  // 无对应 slot（已被直连取走或未注册）

    auto slot = take_slot_(token);
    if (!slot) return false;  // 直连已先到达取走 slot

    std::vector<std::uint8_t> result(result_payload.begin(), result_payload.end());
    try {
        slot->promise.set_value(std::move(result));
    } catch (...) {}
    std::lock_guard<std::mutex> lk(stats_mu_);
    stats_.hop_by_hop_won++;
    stats_.results_received++;
    return true;
}

std::array<std::uint8_t, 32> DirectReturnManager::local_endpoint_id() const {
    std::array<std::uint8_t, 32> out{};
    if (endpoint_) {
        auto id = endpoint_->id();
        std::memcpy(out.data(), id.as_span().data(), 32);
    }
    return out;
}

// ============================================================================
// 末节点端 API
// ============================================================================

std::shared_ptr<endpoint::Stream> DirectReturnManager::open_return_stream(
    const std::array<std::uint8_t, 32> &master_endpoint,
    std::uint32_t stream_token,
    std::chrono::milliseconds timeout) {
    (void)stream_token;  // stream_token 在 send_result_direct 时写入 payload
    (void)timeout;       // P0：connect 同步返回，超时由 Endpoint 内部控制

    auto conn = get_or_dial_connection_(master_endpoint, timeout);
    if (!conn) {
        std::lock_guard<std::mutex> lk(stats_mu_);
        stats_.return_streams_failed++;
        return nullptr;
    }

    auto stream = conn->open_stream();
    if (!stream) {
        std::lock_guard<std::mutex> lk(stats_mu_);
        stats_.return_streams_failed++;
        return nullptr;
    }

    std::lock_guard<std::mutex> lk(stats_mu_);
    stats_.return_streams_opened++;
    return stream;
}

bool DirectReturnManager::send_result_direct(
    std::shared_ptr<endpoint::Stream> return_stream,
    std::uint32_t stream_token,
    std::span<const std::uint8_t> result_payload,
    bool combined) {
    if (!return_stream || return_stream->is_closed()) return false;

    // 构造 payload: [stream_token(4B LE)][result_payload]
    std::vector<std::uint8_t> payload;
    payload.reserve(4 + result_payload.size());
    payload.push_back(static_cast<std::uint8_t>(stream_token & 0xFF));
    payload.push_back(static_cast<std::uint8_t>((stream_token >> 8) & 0xFF));
    payload.push_back(static_cast<std::uint8_t>((stream_token >> 16) & 0xFF));
    payload.push_back(static_cast<std::uint8_t>((stream_token >> 24) & 0xFF));
    payload.insert(payload.end(), result_payload.begin(), result_payload.end());

    // 构造 ApplicationMessage（Notification 语义，id=0）
    protocol::ApplicationMessage msg = protocol::ApplicationMessage::notification(
        protocol::MethodId::ResultPP,
        std::span<const std::uint8_t>(payload.data(), payload.size()));
    msg.flags = static_cast<std::uint16_t>(protocol::MessageFlags::DirectReturn);
    if (combined) {
        msg.flags |= static_cast<std::uint16_t>(protocol::MessageFlags::EndOfStream);
    }

    auto wire = msg.serialize();

    // 流写入需持 stream_mutex（与 build_1rtt_packet 共享）
    auto conn = return_stream;  // stream 本身无 mutex，写锁在 Connection
    (void)conn;
    return_stream->write(std::span<const std::uint8_t>(wire.data(), wire.size()));
    return_stream->finish_send();  // 发送 FIN，标记本 stream 结束

    std::lock_guard<std::mutex> lk(stats_mu_);
    stats_.results_sent_direct++;
    return true;
}

bool DirectReturnManager::send_result_direct_sharded(
    std::shared_ptr<endpoint::Stream> return_stream,
    std::uint32_t stream_token,
    std::span<const std::uint8_t> result_payload,
    bool combined,
    std::size_t shard_size) {
    if (!return_stream || return_stream->is_closed()) return false;
    if (shard_size == 0) shard_size = 1024;
    // shard_size 是 result_chunk 的最大字节数（不含 8B shard header）
    // 实际 wire = ApplicationMessage header(16B) + stream_token(4B) + shard_header(4B) + chunk
    // 确保 wire < MTU(1280)：shard_size <= 1024 → wire <= 16+4+4+1024 = 1048 < 1280 ✓

    std::size_t total = result_payload.size();
    if (total == 0) {
        // 空结果：发送单条非分片 DirectReturn（退化为 send_result_direct）
        return send_result_direct(return_stream, stream_token, result_payload, combined);
    }

    std::uint16_t num_shards = static_cast<std::uint16_t>((total + shard_size - 1) / shard_size);
    if (num_shards == 0) num_shards = 1;

    for (std::uint16_t idx = 0; idx < num_shards; ++idx) {
        std::size_t offset = static_cast<std::size_t>(idx) * shard_size;
        std::size_t end = (std::min)(offset + shard_size, total);
        std::size_t chunk_len = end - offset;

        // payload = [stream_token(4B,LE)][shard_idx(2B,LE)][total_shards(2B,LE)][chunk]
        std::vector<std::uint8_t> payload;
        payload.reserve(8 + chunk_len);
        payload.push_back(static_cast<std::uint8_t>(stream_token & 0xFF));
        payload.push_back(static_cast<std::uint8_t>((stream_token >> 8) & 0xFF));
        payload.push_back(static_cast<std::uint8_t>((stream_token >> 16) & 0xFF));
        payload.push_back(static_cast<std::uint8_t>((stream_token >> 24) & 0xFF));
        payload.push_back(static_cast<std::uint8_t>(idx & 0xFF));
        payload.push_back(static_cast<std::uint8_t>((idx >> 8) & 0xFF));
        payload.push_back(static_cast<std::uint8_t>(num_shards & 0xFF));
        payload.push_back(static_cast<std::uint8_t>((num_shards >> 8) & 0xFF));
        payload.insert(payload.end(),
                        result_payload.begin() + offset,
                        result_payload.begin() + end);

        protocol::ApplicationMessage msg = protocol::ApplicationMessage::notification(
            protocol::MethodId::ResultPP,
            std::span<const std::uint8_t>(payload.data(), payload.size()));
        msg.flags = static_cast<std::uint16_t>(protocol::MessageFlags::DirectReturn) |
                    static_cast<std::uint16_t>(protocol::MessageFlags::ResultShard);
        // 最后一个 shard 附加 EndOfStream（如果 combined）
        if (combined && idx == num_shards - 1) {
            msg.flags |= static_cast<std::uint16_t>(protocol::MessageFlags::EndOfStream);
        }

        auto wire = msg.serialize();
        return_stream->write(std::span<const std::uint8_t>(wire.data(), wire.size()));
    }

    return_stream->finish_send();  // FIN

    std::lock_guard<std::mutex> lk(stats_mu_);
    stats_.results_sent_direct += num_shards;
    return true;
}

void DirectReturnManager::cleanup_idle_connections() {
    std::lock_guard<std::mutex> lk(pool_mu_);
    auto now = std::chrono::steady_clock::now();
    for (auto it = connection_pool_.begin(); it != connection_pool_.end(); ) {
        if (now - it->second.last_used > kIdleTimeout || !it->second.conn ||
            it->second.conn->is_closed()) {
            it = connection_pool_.erase(it);
            std::lock_guard<std::mutex> slk(stats_mu_);
            stats_.idle_connections_cleaned++;
        } else {
            ++it;
        }
    }
}

// ============================================================================
// 统计
// ============================================================================

DirectReturnManager::Stats DirectReturnManager::stats() const {
    std::lock_guard<std::mutex> lk(stats_mu_);
    return stats_;
}

std::string DirectReturnManager::stats_json() const {
    auto s = stats();  // 已加锁拷贝
    char buf[768];
    std::snprintf(buf, sizeof(buf),
        "{"
        "\"return_streams_opened\":%llu,"
        "\"return_streams_failed\":%llu,"
        "\"results_sent_direct\":%llu,"
        "\"results_received\":%llu,"
        "\"direct_return_won\":%llu,"
        "\"hop_by_hop_won\":%llu,"
        "\"fallback_invoked\":%llu,"
        "\"return_slots_registered\":%llu,"
        "\"return_slots_cancelled\":%llu,"
        "\"pool_hits\":%llu,"
        "\"pool_misses\":%llu,"
        "\"idle_connections_cleaned\":%llu"
        "}",
        static_cast<unsigned long long>(s.return_streams_opened),
        static_cast<unsigned long long>(s.return_streams_failed),
        static_cast<unsigned long long>(s.results_sent_direct),
        static_cast<unsigned long long>(s.results_received),
        static_cast<unsigned long long>(s.direct_return_won),
        static_cast<unsigned long long>(s.hop_by_hop_won),
        static_cast<unsigned long long>(s.fallback_invoked),
        static_cast<unsigned long long>(s.return_slots_registered),
        static_cast<unsigned long long>(s.return_slots_cancelled),
        static_cast<unsigned long long>(s.pool_hits),
        static_cast<unsigned long long>(s.pool_misses),
        static_cast<unsigned long long>(s.idle_connections_cleaned));
    return std::string(buf);
}

// ============================================================================
// private
// ============================================================================

std::shared_ptr<endpoint::Connection> DirectReturnManager::get_or_dial_connection_(
    const std::array<std::uint8_t, 32> &master_endpoint,
    std::chrono::milliseconds timeout) {
    (void)timeout;
    base::EndpointId ep_id(master_endpoint);
    {
        std::lock_guard<std::mutex> lk(pool_mu_);
        auto it = connection_pool_.find(ep_id);
        if (it != connection_pool_.end() && it->second.conn &&
            !it->second.conn->is_closed()) {
            it->second.last_used = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> slk(stats_mu_);
            stats_.pool_hits++;
            return it->second.conn;
        }
        std::lock_guard<std::mutex> slk(stats_mu_);
        stats_.pool_misses++;
    }

    if (!endpoint_) return nullptr;

    // 通过 AddressLookup 解析 EndpointAddr
    auto &lookup = endpoint_->config().lookup;
    if (!lookup) return nullptr;
    auto addr_opt = lookup->lookup(ep_id);
    if (!addr_opt) return nullptr;

    // dial pp-llm/1 连接
    auto conn = endpoint_->connect(*addr_opt, "pp-llm/1");
    if (!conn) return nullptr;

    std::lock_guard<std::mutex> lk(pool_mu_);
    connection_pool_[ep_id] = {conn, std::chrono::steady_clock::now()};
    return conn;
}

void DirectReturnManager::handle_inbound_stream_(
    std::shared_ptr<endpoint::Stream> stream,
    std::shared_ptr<endpoint::Connection> conn) {
    if (!stream || !conn) return;

    // P1-2 改进：on_stream 仅在 stream 新建时触发一次（linoh 通知机制，见
    // Connection::handle_packet: is_new_stream 才 push 到 streams_to_notify）。
    // 但 st->recv() 在 notify 之前调用，故 on_stream 触发时已到达的数据均在 recv_ 中。
    //
    // 策略：
    //   1. 一次性读取全部可读数据（read(0) 返回整个可读 span）
    //   2. 循环 parse：支持单 stream 内多条 ApplicationMessage 拼接
    //   3. parse 失败时检查 fin_received：FIN 已到则数据不完整，丢弃
    //   4. 跨 UDP 包的大消息（wire > MTU）：linoh 分多个 STREAM 帧发送，后续帧到达
    //      不触发 on_stream_（非 RPC 模式）。此场景由 P3 TensorStream 分片机制处理，
    //      每片 < MTU 独立完整，避免跨包重组。
    std::vector<std::uint8_t> acc;
    for (;;) {
        auto chunk = stream->read(0);
        if (!chunk.empty()) {
            acc.insert(acc.end(), chunk.begin(), chunk.end());
            stream->consume(chunk.size());
        }

        if (acc.empty()) {
            // 无数据可读：on_stream 触发但首帧未携带 payload（罕见），直接返回
            return;
        }

        // 循环 parse：消费 acc 中所有完整消息
        std::size_t consumed = 0;
        for (;;) {
            protocol::ApplicationMessage msg;
            auto remaining = acc.size() - consumed;
            if (remaining == 0) break;
            auto n = protocol::ApplicationMessage::parse(
                std::span<const std::uint8_t>(acc.data() + consumed, remaining), msg);
            if (n == 0) break;  // 数据不足，等待更多（但本帧已读完）
            if (n > 0) {
                if (msg.method_id == protocol::MethodId::ResultPP &&
                    protocol::has_flag(msg.flags, protocol::MessageFlags::DirectReturn)) {
                    bool is_shard = protocol::has_flag(
                        msg.flags, protocol::MessageFlags::ResultShard);
                    if (is_shard && msg.payload.size() >= 8) {
                        // P3-1 分片：[stream_token(4B)][shard_idx(2B)][total_shards(2B)][chunk]
                        std::uint32_t token =
                            static_cast<std::uint32_t>(msg.payload[0]) |
                            (static_cast<std::uint32_t>(msg.payload[1]) << 8) |
                            (static_cast<std::uint32_t>(msg.payload[2]) << 16) |
                            (static_cast<std::uint32_t>(msg.payload[3]) << 24);
                        std::uint16_t shard_idx =
                            static_cast<std::uint16_t>(msg.payload[4]) |
                            (static_cast<std::uint16_t>(msg.payload[5]) << 8);
                        std::uint16_t total_shards =
                            static_cast<std::uint16_t>(msg.payload[6]) |
                            (static_cast<std::uint16_t>(msg.payload[7]) << 8);
                        route_result_(token,
                                      std::span<const std::uint8_t>(
                                          msg.payload.data() + 8, msg.payload.size() - 8),
                                      true, shard_idx, total_shards);
                    } else if (msg.payload.size() >= 4) {
                        // 非分片：[stream_token(4B)][result_payload]
                        std::uint32_t token =
                            static_cast<std::uint32_t>(msg.payload[0]) |
                            (static_cast<std::uint32_t>(msg.payload[1]) << 8) |
                            (static_cast<std::uint32_t>(msg.payload[2]) << 16) |
                            (static_cast<std::uint32_t>(msg.payload[3]) << 24);
                        route_result_(token,
                                      std::span<const std::uint8_t>(
                                          msg.payload.data() + 4, msg.payload.size() - 4));
                    }
                }
                // 非 DirectReturn 消息：忽略（MASTER 端 pp-llm/1 应只收 ResultPP[DirectReturn]）
                consumed += static_cast<std::size_t>(n);
            }
        }

        // 已消费前 consumed 字节，保留未完成尾部
        if (consumed > 0) {
            acc.erase(acc.begin(), acc.begin() + consumed);
        }

        // 判断是否还需继续读
        if (stream->fin_received()) {
            // FIN 已到：若 acc 仍有未 parse 数据，视为不完整，丢弃
            return;
        }
        // 未 fin 且 acc 非空（半条消息）：本帧数据已读完，后续帧不触发 on_stream_
        // → 跨包场景，留给 P3 TensorStream 分片机制处理（每片独立完整）
        return;
    }
}

void DirectReturnManager::route_result_(
    std::uint32_t stream_token,
    std::span<const std::uint8_t> result_payload,
    bool is_shard,
    std::uint16_t shard_idx,
    std::uint16_t total_shards) {
    if (!is_shard) {
        // 非分片：直接取走 slot 并 set_value（P1 竞速入口）
        auto slot = take_slot_(stream_token);
        if (!slot) return;
        std::vector<std::uint8_t> result(result_payload.begin(), result_payload.end());
        try {
            slot->promise.set_value(std::move(result));
        } catch (...) {}
        std::lock_guard<std::mutex> lk(stats_mu_);
        stats_.direct_return_won++;
        stats_.results_received++;
        return;
    }

    // P3-1 分片：累积 shard，到齐后 set_value
    // 注意：分片场景下 slot 不立即取走，直到所有 shard 到齐
    std::unique_ptr<ReturnSlot> completed_slot;
    {
        std::lock_guard<std::mutex> lk(slots_mu_);
        auto it = return_slots_.find(stream_token);
        if (it == return_slots_.end() || !it->second) return;  // slot 已取走/取消
        auto &slot = it->second;
        if (slot->total_shards == 0) {
            // 首个 shard 到达：初始化 shard_chunks
            slot->total_shards = total_shards;
            slot->shard_chunks.resize(total_shards);
        }
        // 容错：total_shards 不一致时以首个为准（发送方保证一致）
        if (shard_idx < slot->total_shards && slot->shard_chunks[shard_idx].empty()) {
            slot->shard_chunks[shard_idx].assign(
                result_payload.begin(), result_payload.end());
            slot->received_shards++;
        }
        // 所有 shard 到齐：拼接并取走 slot
        if (slot->received_shards == slot->total_shards) {
            completed_slot = take_slot_(stream_token);
        }
    }

    if (completed_slot) {
        // 拼接所有 shard
        std::vector<std::uint8_t> full_result;
        for (auto &chunk : completed_slot->shard_chunks) {
            full_result.insert(full_result.end(), chunk.begin(), chunk.end());
        }
        try {
            completed_slot->promise.set_value(std::move(full_result));
        } catch (...) {}
        std::lock_guard<std::mutex> lk(stats_mu_);
        stats_.direct_return_won++;
        stats_.results_received++;
    }
}

std::unique_ptr<DirectReturnManager::ReturnSlot>
DirectReturnManager::take_slot_(std::uint32_t stream_token) {
    std::lock_guard<std::mutex> lk(slots_mu_);
    auto it = return_slots_.find(stream_token);
    if (it == return_slots_.end()) return nullptr;
    auto slot = std::move(it->second);
    return_slots_.erase(it);
    // P1: 同步清理 req_id → token 反向映射
    req_id_to_token_.erase(slot->req_id);
    return slot;
}

std::uint32_t DirectReturnManager::compute_stream_token(
    std::uint64_t req_id,
    std::uint64_t timestamp_ms) {
    // FNV-1a 64-bit over (req_id || timestamp_ms)，取低 32 位
    // 输入：8B req_id (LE) + 8B timestamp_ms (LE)
    std::uint64_t h = 0xcbf29ce484222325ULL;
    auto mix = [&](std::uint8_t b) {
        h ^= b;
        h *= 0x100000001b3ULL;
    };
    for (int i = 0; i < 8; ++i) mix(static_cast<std::uint8_t>((req_id >> (i * 8)) & 0xFF));
    for (int i = 0; i < 8; ++i) mix(static_cast<std::uint8_t>((timestamp_ms >> (i * 8)) & 0xFF));
    return static_cast<std::uint32_t>(h & 0xFFFFFFFFULL);
}

}  // namespace linoh
