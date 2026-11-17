// fec_group.cpp — FEC Group 实现（P5-B-1 Step 2）
//
// 把任意大小数据切片 + FEC 编码为 K+M 个网络包，接收端按 group_id 分组 + 乱序重组 +
// 自动 FEC 解码恢复（丢失 ≤ M 时）。封装在 fec.hpp 之上，不侵入 Connection/STREAM。

#include "linoh/fec/fec_group.hpp"

#include <algorithm>
#include <cstring>

#include "linoh/util/logging.hpp"

namespace linoh::fec {

// ============================================================================
// 序列化 / 反序列化
// 包格式：| group_id (4B) | block_idx (1B) | block_size (2B) | block_data (BS B) |
// ============================================================================

std::vector<std::uint8_t> serialize_packet(const FecPacket &p) {
    std::vector<std::uint8_t> out;
    out.reserve(4 + 1 + 2 + p.data.size());
    // group_id (4B, little endian)
    out.push_back(static_cast<std::uint8_t>(p.group_id & 0xFF));
    out.push_back(static_cast<std::uint8_t>((p.group_id >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((p.group_id >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((p.group_id >> 24) & 0xFF));
    // block_idx (1B)
    out.push_back(p.block_idx);
    // block_size (2B, little endian)
    auto bs = static_cast<std::uint16_t>(p.data.size());
    out.push_back(static_cast<std::uint8_t>(bs & 0xFF));
    out.push_back(static_cast<std::uint8_t>((bs >> 8) & 0xFF));
    // block_data
    out.insert(out.end(), p.data.begin(), p.data.end());
    return out;
}

std::optional<FecPacket> deserialize_packet(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 4 + 1 + 2) {
        return std::nullopt;
    }
    FecPacket p;
    p.group_id = static_cast<std::uint32_t>(bytes[0]) |
                 (static_cast<std::uint32_t>(bytes[1]) << 8) |
                 (static_cast<std::uint32_t>(bytes[2]) << 16) |
                 (static_cast<std::uint32_t>(bytes[3]) << 24);
    p.block_idx = bytes[4];
    std::uint16_t bs = static_cast<std::uint16_t>(bytes[5]) |
                       (static_cast<std::uint16_t>(bytes[6]) << 8);
    p.block_size = bs;
    if (bytes.size() < static_cast<std::size_t>(7 + bs)) {
        return std::nullopt;
    }
    p.data.assign(bytes.begin() + 7, bytes.begin() + 7 + bs);
    return p;
}

// ============================================================================
// FecGroup（发送端）
// ============================================================================

FecGroup::FecGroup(FecConfig cfg) : cfg_(std::move(cfg)) {
    encoder_ = create_encoder(cfg_);
    if (!encoder_) {
        LINOH_ERROR("FecGroup: create_encoder failed (type=%s K=%zu M=%zu bs=%zu)",
                    fec_type_name(cfg_.type), cfg_.data_blocks,
                    cfg_.recovery_blocks, cfg_.block_size);
    }
}

std::vector<FecPacket> FecGroup::pack(std::uint32_t group_id,
                                       std::span<const std::uint8_t> data) {
    std::vector<FecPacket> result;
    if (!encoder_) return result;

    std::size_t K = cfg_.data_blocks;
    std::size_t M = cfg_.recovery_blocks;
    std::size_t bs = cfg_.block_size;

    // 1. 把 data 切分为 K 个数据块（最后一块可能 < bs）
    std::vector<std::vector<std::uint8_t>> data_blocks(K);
    for (std::size_t i = 0; i < K; ++i) {
        std::size_t offset = i * bs;
        std::size_t copy_size = (std::min)(bs, data.size() > offset ? data.size() - offset : 0);
        data_blocks[i].resize(bs, 0);  // 填 0（最后一块可 < bs）
        if (copy_size > 0) {
            std::memcpy(data_blocks[i].data(), data.data() + offset, copy_size);
        }
    }

    // 2. 构造 span 输入给 encoder
    std::vector<std::span<const std::uint8_t>> data_spans;
    data_spans.reserve(K);
    for (auto &b : data_blocks) {
        data_spans.emplace_back(b.data(), b.size());
    }

    // 3. 编码 → K+M 个块
    auto encoded = encoder_->encode(data_spans);
    if (encoded.size() != K + M) {
        LINOH_ERROR("FecGroup::pack: encoder returned %zu blocks (expected %zu)",
                    encoded.size(), K + M);
        return result;
    }

    // 4. 构造 FecPacket 列表
    result.reserve(encoded.size());
    for (std::size_t i = 0; i < encoded.size(); ++i) {
        FecPacket pkt;
        pkt.group_id = group_id;
        pkt.block_idx = static_cast<std::uint8_t>(i);
        pkt.block_size = static_cast<std::uint16_t>(encoded[i].size());
        pkt.data = std::move(encoded[i]);
        result.push_back(std::move(pkt));
    }
    return result;
}

// ============================================================================
// FecGroupReceiver（接收端）
// ============================================================================

// [GCC 11.4 compat] 委托构造函数，默认 Options{}
FecGroupReceiver::FecGroupReceiver(FecConfig cfg) : FecGroupReceiver(cfg, Options{}) {}

FecGroupReceiver::FecGroupReceiver(FecConfig cfg, Options opts)
    : cfg_(std::move(cfg)), opts_(opts) {
    decoder_ = create_decoder(cfg_);
    if (!decoder_) {
        LINOH_ERROR("FecGroupReceiver: create_decoder failed (type=%s K=%zu M=%zu bs=%zu)",
                    fec_type_name(cfg_.type), cfg_.data_blocks,
                    cfg_.recovery_blocks, cfg_.block_size);
    }
}

void FecGroupReceiver::feed(FecPacket packet) {
    std::unique_lock<std::mutex> lk(mu_);

    std::size_t K = cfg_.data_blocks;
    std::size_t M = cfg_.recovery_blocks;
    std::size_t total = K + M;

    if (packet.block_idx >= total) {
        LINOH_ERROR("FecGroupReceiver::feed: block_idx=%u >= total=%zu",
                    packet.block_idx, total);
        return;
    }

    // 已完成的 group_id 直接丢弃重复包
    if (completed_ids_.count(packet.group_id)) {
        return;
    }

    auto it = groups_.find(packet.group_id);
    if (it == groups_.end()) {
        // 新 group
        if (groups_.size() >= opts_.max_inflight_groups) {
            LINOH_ERROR("FecGroupReceiver::feed: too many in-flight groups (%zu)",
                        groups_.size());
            return;  // 丢弃
        }
        GroupState st;
        st.group_id = packet.group_id;
        st.data_blocks = K;
        st.recovery_blocks = M;
        st.block_size = cfg_.block_size;
        st.total_size = 0;  // 延迟到 complete 时计算
        st.received.assign(total, std::nullopt);
        st.created_at = std::chrono::steady_clock::now();
        auto [ins, _] = groups_.emplace(packet.group_id, std::move(st));
        it = ins;
    }

    GroupState &st = it->second;
    if (st.completed) return;  // 已完成，忽略重复包

    // mp-P11 (v1.7.0.8): 用 received_count 维护已收块数，避免每次 O(K+M) 扫描
    //   仅当槽位从 nullopt → 有值时才递增（防重复包导致计数虚高）
    if (!st.received[packet.block_idx].has_value()) {
        ++st.received_count;
    }
    st.received[packet.block_idx] = std::move(packet.data);

    // 检查是否完成：missing = total - received_count
    std::size_t missing = total - st.received_count;

    if (missing == 0 || missing <= M) {
        // 全部到齐或丢失数 ≤ M：尝试解码
        if (!decoder_) return;
        auto decoded_opt = decoder_->decode(std::span<const std::optional<std::vector<std::uint8_t>>>(
            st.received.data(), st.received.size()));
        if (!decoded_opt.has_value()) {
            // 仍在等待更多包（missing > M 的情况不会到这里，因为 missing == 0 或 ≤ M）
            return;
        }
        // 解码成功
        auto &decoded = *decoded_opt;
        std::vector<std::uint8_t> recovered;
        recovered.reserve(K * cfg_.block_size);
        for (std::size_t i = 0; i < K; ++i) {
            recovered.insert(recovered.end(), decoded[i].begin(), decoded[i].end());
        }
        std::size_t missing_blocks = missing;
        std::uint32_t gid = packet.group_id;

        // 标记完成 + 清理（锁内）
        st.completed = true;
        groups_.erase(it);
        completed_ids_.insert(gid);
        completed_order_.push_back(gid);
        // mp-M4 (v1.7.0.8): FIFO 有界淘汰，防止 completed_ids_ 无限增长
        //   completed_order_ 队首为最旧 group_id，超上限时弹出并从 set erase。
        //   被淘汰的 group_id 若重复到达会被当作新 group 处理（decoder 重新解码），
        //   这是可接受的：group_id 空间 32 位，4096 的窗口下碰撞概率极低且重解码幂等。
        while (completed_order_.size() > kMaxCompletedIds) {
            std::uint32_t old = completed_order_.front();
            completed_order_.pop_front();
            completed_ids_.erase(old);
        }

        // v1.7.0.6: 回调移出锁外触发，避免回调内调用 feed() 导致死锁
        // （之前在 mu_ 持有时触发 on_complete_，若回调内调 feed 会自死锁）
        lk.unlock();
        if (on_complete_) {
            on_complete_(gid, std::move(recovered), missing_blocks);
        }
    }
}

std::size_t FecGroupReceiver::cleanup_expired() {
    std::lock_guard<std::mutex> lk(mu_);
    auto now = std::chrono::steady_clock::now();
    std::size_t n = 0;
    for (auto it = groups_.begin(); it != groups_.end(); ) {
        if (now - it->second.created_at > opts_.ttl) {
            it = groups_.erase(it);
            ++n;
        } else {
            ++it;
        }
    }
    return n;
}

std::size_t FecGroupReceiver::inflight_count() const {
    std::lock_guard<std::mutex> lk(mu_);
    return groups_.size();
}

}  // namespace linoh::fec
