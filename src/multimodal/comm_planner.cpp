// comm_planner.cpp - EP 在线通信规划器实现（v1.6.0.4 / P3）

#include "linoh/multimodal/comm_planner.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

#include "linoh/multimodal/expert_balancer.hpp"
#include "linoh/multimodal/static_shape.hpp"

namespace linoh::multimodal::ep {

// ============================================================================
// 序列化字节序：固定 little-endian（linoh 内部统一）
// ============================================================================
namespace {

inline void write_u8(std::vector<std::uint8_t>& buf, std::uint8_t v) {
    buf.push_back(v);
}

inline void write_u16(std::vector<std::uint8_t>& buf, std::uint16_t v) {
    buf.push_back(static_cast<std::uint8_t>(v & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
}

inline void write_u32(std::vector<std::uint8_t>& buf, std::uint32_t v) {
    buf.push_back(static_cast<std::uint8_t>(v & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
}

inline void write_u64(std::vector<std::uint8_t>& buf, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
    }
}

inline void write_double(std::vector<std::uint8_t>& buf, double v) {
    std::uint64_t bits;
    std::memcpy(&bits, &v, sizeof(double));
    write_u64(buf, bits);
}

inline bool read_u8(std::span<const std::uint8_t> data, std::size_t& pos, std::uint8_t& out) {
    if (pos + 1 > data.size()) return false;
    out = data[pos++];
    return true;
}

inline bool read_u16(std::span<const std::uint8_t> data, std::size_t& pos, std::uint16_t& out) {
    if (pos + 2 > data.size()) return false;
    out = static_cast<std::uint16_t>(data[pos])
        | (static_cast<std::uint16_t>(data[pos + 1]) << 8);
    pos += 2;
    return true;
}

inline bool read_u32(std::span<const std::uint8_t> data, std::size_t& pos, std::uint32_t& out) {
    if (pos + 4 > data.size()) return false;
    out = static_cast<std::uint32_t>(data[pos])
        | (static_cast<std::uint32_t>(data[pos + 1]) << 8)
        | (static_cast<std::uint32_t>(data[pos + 2]) << 16)
        | (static_cast<std::uint32_t>(data[pos + 3]) << 24);
    pos += 4;
    return true;
}

inline bool read_u64(std::span<const std::uint8_t> data, std::size_t& pos, std::uint64_t& out) {
    if (pos + 8 > data.size()) return false;
    out = 0;
    for (int i = 0; i < 8; ++i) {
        out |= static_cast<std::uint64_t>(data[pos + i]) << (8 * i);
    }
    pos += 8;
    return true;
}

inline bool read_double(std::span<const std::uint8_t> data, std::size_t& pos, double& out) {
    std::uint64_t bits;
    if (!read_u64(data, pos, bits)) return false;
    std::memcpy(&out, &bits, sizeof(double));
    return true;
}

inline bool read_vec_u32(std::span<const std::uint8_t> data, std::size_t& pos, std::vector<std::uint32_t>& out) {
    std::uint32_t n;
    if (!read_u32(data, pos, n)) return false;
    // v1.7.0.7 H8 DoS 防护：校验 n 不超过剩余数据能容纳的元素数（每元素 4 字节）
    //   根因：原实现直接 reserve(n)，恶意对端发送 n=0xFFFFFFFF 会触发 bad_alloc 或内存耗尽
    constexpr std::size_t kElemSize = 4;
    if (n > (data.size() - pos) / kElemSize) return false;
    out.clear();
    out.reserve(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        std::uint32_t v;
        if (!read_u32(data, pos, v)) return false;
        out.push_back(v);
    }
    return true;
}

inline bool read_vec_u64(std::span<const std::uint8_t> data, std::size_t& pos, std::vector<NodeId>& out) {
    std::uint32_t n;
    if (!read_u32(data, pos, n)) return false;
    // v1.7.0.7 H8 DoS 防护：每元素 8 字节
    constexpr std::size_t kElemSize = 8;
    if (n > (data.size() - pos) / kElemSize) return false;
    out.clear();
    out.reserve(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        std::uint64_t v;
        if (!read_u64(data, pos, v)) return false;
        out.push_back(v);
    }
    return true;
}

inline bool read_vec_buffer_slice(std::span<const std::uint8_t> data, std::size_t& pos, std::vector<BufferSlice>& out) {
    std::uint32_t n;
    if (!read_u32(data, pos, n)) return false;
    // v1.7.0.7 H8 DoS 防护：每元素 25 字节（buffer_offset 8 + length 8 + padded_length 8 + zero_fill 1）
    constexpr std::size_t kElemSize = 25;
    if (n > (data.size() - pos) / kElemSize) return false;
    out.clear();
    out.reserve(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        BufferSlice s;
        if (!read_u64(data, pos, s.buffer_offset)) return false;
        if (!read_u64(data, pos, s.length)) return false;
        if (!read_u64(data, pos, s.padded_length)) return false;
        std::uint8_t zf;
        if (!read_u8(data, pos, zf)) return false;
        s.zero_fill = (zf != 0);
        out.push_back(s);
    }
    return true;
}

inline bool read_vec_range(std::span<const std::uint8_t> data, std::size_t& pos, std::vector<Range>& out) {
    std::uint32_t n;
    if (!read_u32(data, pos, n)) return false;
    // v1.7.0.7 H8 DoS 防护：每元素 16 字节（offset 8 + length 8）
    constexpr std::size_t kElemSize = 16;
    if (n > (data.size() - pos) / kElemSize) return false;
    out.clear();
    out.reserve(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        Range r;
        if (!read_u64(data, pos, r.offset)) return false;
        if (!read_u64(data, pos, r.length)) return false;
        out.push_back(r);
    }
    return true;
}

inline void write_shape(std::vector<std::uint8_t>& buf, const ShapeDescriptor& s) {
    write_u8(buf, static_cast<std::uint8_t>(s.dtype));
    write_u32(buf, s.max_tokens);
    write_u32(buf, s.hidden_dim);
    write_u32(buf, s.expert_count);
}

inline bool read_shape(std::span<const std::uint8_t> data, std::size_t& pos, ShapeDescriptor& s) {
    std::uint8_t dt;
    if (!read_u8(data, pos, dt)) return false;
    s.dtype = static_cast<TensorDType>(dt);
    if (!read_u32(data, pos, s.max_tokens)) return false;
    if (!read_u32(data, pos, s.hidden_dim)) return false;
    if (!read_u32(data, pos, s.expert_count)) return false;
    return true;
}

inline void write_slice(std::vector<std::uint8_t>& buf, const BufferSlice& s) {
    write_u64(buf, s.buffer_offset);
    write_u64(buf, s.length);
    write_u64(buf, s.padded_length);
    write_u8(buf, s.zero_fill ? 1 : 0);
}

inline void write_range(std::vector<std::uint8_t>& buf, const Range& r) {
    write_u64(buf, r.offset);
    write_u64(buf, r.length);
}

inline void write_vec_buffer_slice(std::vector<std::uint8_t>& buf, const std::vector<BufferSlice>& v) {
    write_u32(buf, static_cast<std::uint32_t>(v.size()));
    for (const auto& s : v) write_slice(buf, s);
}

inline void write_vec_range(std::vector<std::uint8_t>& buf, const std::vector<Range>& v) {
    write_u32(buf, static_cast<std::uint32_t>(v.size()));
    for (const auto& r : v) write_range(buf, r);
}

}  // anonymous namespace

// ============================================================================
// LRUHashCache
// ============================================================================

LRUHashCache::LRUHashCache(std::size_t capacity)
    : capacity_(capacity == 0 ? 1 : capacity) {}

std::optional<EpCommPlan> LRUHashCache::lookup(std::uint64_t routing_hash) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = map_.find(routing_hash);
    if (it == map_.end()) {
        misses_.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
    }
    // 命中：移到链表头部
    list_.splice(list_.begin(), list_, it->second);
    hits_.fetch_add(1, std::memory_order_relaxed);
    return it->second->second;
}

void LRUHashCache::insert(std::uint64_t routing_hash, EpCommPlan plan) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = map_.find(routing_hash);
    if (it != map_.end()) {
        // 已存在：更新值并移到头部
        it->second->second = std::move(plan);
        list_.splice(list_.begin(), list_, it->second);
        return;
    }
    // 不存在：插入到头部
    list_.emplace_front(routing_hash, std::move(plan));
    map_[routing_hash] = list_.begin();
    // 容量满：淘汰尾部
    if (list_.size() > capacity_) {
        auto last = std::prev(list_.end());
        map_.erase(last->first);
        list_.erase(last);
    }
}

void LRUHashCache::clear() noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    list_.clear();
    map_.clear();
}

std::size_t LRUHashCache::size() const noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    return list_.size();
}

double LRUHashCache::hit_rate() const noexcept {
    const std::uint64_t h = hits_.load();
    const std::uint64_t m = misses_.load();
    const std::uint64_t total = h + m;
    if (total == 0) return 0.0;
    return static_cast<double>(h) / static_cast<double>(total);
}

// ============================================================================
// CommPlanner
// ============================================================================

CommPlanner::CommPlanner() : cache_(16) {}
CommPlanner::CommPlanner(std::size_t cache_capacity) : cache_(cache_capacity) {}

std::uint64_t CommPlanner::next_plan_id_() {
    static std::atomic<std::uint64_t> counter{0};
    return counter.fetch_add(1, std::memory_order_relaxed);
}

std::uint64_t CommPlanner::derive_sync_id_(std::uint64_t plan_id) noexcept {
    // 偏移常量避免与 P0 sync_id 冲突
    constexpr std::uint64_t OFFSET = 0xA1CC000000000000ULL;
    return OFFSET | (plan_id & 0x00FFFFFFFFFFFFFFULL);
}

std::uint64_t CommPlanner::compute_routing_hash(
    const std::vector<std::vector<std::uint32_t>>& routing) {
    // FNV-1a 64bit
    constexpr std::uint64_t FNV_OFFSET = 0xcbf29ce484222325ULL;
    constexpr std::uint64_t FNV_PRIME  = 0x100000001b3ULL;
    std::uint64_t hash = FNV_OFFSET;
    for (const auto& experts : routing) {
        for (const auto e : experts) {
            hash ^= static_cast<std::uint64_t>(e);
            hash *= FNV_PRIME;
        }
        hash ^= 0x2F;  // 分隔符
        hash *= FNV_PRIME;
    }
    return hash;
}

std::unordered_map<std::uint32_t, NodeId> CommPlanner::build_expert_to_node_map(
    const EpGroupConfig& config) {
    std::unordered_map<std::uint32_t, NodeId> m;
    m.reserve(config.num_experts > 0 ? config.num_experts : 16);
    for (std::size_t w = 0; w < config.ep_workers.size(); ++w) {
        for (const auto expert : config.expert_placement[w]) {
            // 冲突检测：同一 expert 不应被分配到多个节点
            // P3 阶段静默覆盖（最后一个生效），P5 阶段改为抛异常
            m[expert] = config.ep_workers[w];
        }
    }
    return m;
}

std::vector<NodeId> CommPlanner::map_tokens_to_nodes_(
    const std::vector<std::vector<std::uint32_t>>& routing,
    const std::unordered_map<std::uint32_t, NodeId>& expert_to_node) {
    std::vector<NodeId> dst_nodes;
    dst_nodes.reserve(routing.size());
    for (std::size_t t = 0; t < routing.size(); ++t) {
        if (routing[t].empty()) {
            throw std::invalid_argument("routing[t] must not be empty");
        }
        // P3 简化策略：取第一个专家所在节点
        const std::uint32_t expert = routing[t][0];
        auto it = expert_to_node.find(expert);
        if (it == expert_to_node.end()) {
            throw std::invalid_argument("expert not in expert_to_node map");
        }
        dst_nodes.push_back(it->second);
    }
    return dst_nodes;
}

CommPlanner::GroupedTokens CommPlanner::group_tokens_by_dst_(
    const std::vector<NodeId>& dst_nodes,
    const EpGroupConfig& config) {
    // v1.7.0.6 性能优化：先建 NodeId → worker_idx 的 hash map（O(W)），
    // 之后两遍扫描都是 O(N)，总复杂度 O(N + W) 替代原 O(N × W)
    std::unordered_map<NodeId, std::size_t> dst_to_worker_idx;
    dst_to_worker_idx.reserve(config.ep_workers.size());
    for (std::size_t w = 0; w < config.ep_workers.size(); ++w) {
        dst_to_worker_idx[config.ep_workers[w]] = w;
    }

    GroupedTokens g;
    g.group_offsets.assign(config.ep_workers.size(), 0);
    g.group_sizes.assign(config.ep_workers.size(), 0);

    // 第一遍：统计每 dst 组大小
    for (const auto dst : dst_nodes) {
        auto it = dst_to_worker_idx.find(dst);
        if (it != dst_to_worker_idx.end()) {
            ++g.group_sizes[it->second];
        }
    }

    // 计算 offsets（前缀和）
    std::uint32_t cum = 0;
    for (std::size_t w = 0; w < g.group_offsets.size(); ++w) {
        g.group_offsets[w] = cum;
        cum += g.group_sizes[w];
    }

    // 第二遍：按 dst 分组填充 token_indices
    g.token_indices.assign(dst_nodes.size(), 0);
    std::vector<std::uint32_t> cursor(g.group_offsets);  // 每组写入游标
    for (std::size_t t = 0; t < dst_nodes.size(); ++t) {
        auto it = dst_to_worker_idx.find(dst_nodes[t]);
        if (it != dst_to_worker_idx.end()) {
            g.token_indices[cursor[it->second]++] = static_cast<std::uint32_t>(t);
        }
    }

    return g;
}

std::vector<BufferSlice> CommPlanner::compute_dispatch_bufs_(
    const GroupedTokens& grouped,
    const ShapeDescriptor& shape) {
    std::vector<BufferSlice> bufs;
    bufs.reserve(grouped.group_sizes.size());
    const std::uint64_t token_bytes = static_cast<std::uint64_t>(shape.hidden_dim)
                                    * static_cast<std::uint64_t>(dtype_size(shape.dtype));
    const std::uint64_t padded_token_bytes = static_cast<std::uint64_t>(shape.max_tokens)
                                           * token_bytes;

    std::uint64_t offset = 0;
    for (std::size_t w = 0; w < grouped.group_sizes.size(); ++w) {
        const std::uint32_t sz = grouped.group_sizes[w];
        const std::uint64_t actual = static_cast<std::uint64_t>(sz) * token_bytes;
        BufferSlice s;
        s.buffer_offset = offset;
        s.length = actual;
        s.padded_length = (sz <= shape.max_tokens) ? padded_token_bytes : actual;
        s.zero_fill = (sz < shape.max_tokens);
        bufs.push_back(s);
        offset += s.padded_length;
    }
    return bufs;
}

CommPlanner::CombinePlan CommPlanner::compute_combine_plan_(
    const GroupedTokens& grouped,
    const ShapeDescriptor& shape) {
    CombinePlan cp;
    cp.combine_bufs.reserve(grouped.group_sizes.size());
    const std::uint64_t token_bytes = static_cast<std::uint64_t>(shape.hidden_dim)
                                    * static_cast<std::uint64_t>(dtype_size(shape.dtype));
    const std::uint64_t padded_token_bytes = static_cast<std::uint64_t>(shape.max_tokens)
                                           * token_bytes;

    std::uint64_t offset = 0;
    for (std::size_t w = 0; w < grouped.group_sizes.size(); ++w) {
        const std::uint32_t sz = grouped.group_sizes[w];
        const std::uint64_t actual = static_cast<std::uint64_t>(sz) * token_bytes;
        BufferSlice s;
        s.buffer_offset = offset;
        s.length = actual;
        s.padded_length = (sz <= shape.max_tokens) ? padded_token_bytes : actual;
        s.zero_fill = (sz < shape.max_tokens);
        cp.combine_bufs.push_back(s);

        // zero_fill_range：padding 区域
        if (s.zero_fill) {
            Range r;
            r.offset = offset + actual;
            r.length = s.padded_length - actual;
            cp.zero_fill_ranges.push_back(r);
        }
        offset += s.padded_length;
    }
    return cp;
}

CommPlanner::LoadStats CommPlanner::compute_load_stats_(
    const std::vector<std::vector<std::uint32_t>>& routing,
    const std::uint32_t num_experts) {
    LoadStats st;
    st.total_tokens = static_cast<std::uint32_t>(routing.size());
    if (st.total_tokens == 0 || num_experts == 0) {
        st.balanced = true;
        st.imbalance_ratio = 1.0;
        return st;
    }

    // 统计每个专家的 token 数（P3 取每个 token 的 top-1 计入）
    std::vector<std::uint32_t> tokens_per_expert(num_experts, 0);
    for (const auto& t : routing) {
        if (!t.empty()) {
            const std::uint32_t e = t[0];
            if (e < num_experts) {
                ++tokens_per_expert[e];
            }
        }
    }

    std::uint32_t mn = UINT32_MAX, mx = 0;
    for (const auto n : tokens_per_expert) {
        if (n < mn) mn = n;
        if (n > mx) mx = n;
    }
    st.min_tokens_per_expert = mn;
    st.max_tokens_per_expert = mx;
    st.imbalance_ratio = (mn == 0)
        ? (mx == 0 ? 1.0 : static_cast<double>(mx))
        : static_cast<double>(mx) / static_cast<double>(mn);
    st.balanced = (st.imbalance_ratio <= 1.2);  // 阈值 1.2
    return st;
}

std::vector<NodeId> CommPlanner::collect_sync_participants_(
    const std::vector<NodeId>& dst_nodes) {
    std::unordered_set<NodeId> seen;
    std::vector<NodeId> participants;
    participants.reserve(dst_nodes.size());
    for (const auto n : dst_nodes) {
        if (seen.insert(n).second) {
            participants.push_back(n);
        }
    }
    return participants;
}

EpCommPlan CommPlanner::launch_planning(
    const std::vector<std::vector<std::uint32_t>>& routing,
    const EpGroupConfig& config) {
    if (!config.valid()) {
        throw std::invalid_argument("EpGroupConfig is invalid");
    }
    // v1.7.0.7 H8 DoS 防护：routing 规模上限检查
    //   根因：无上限时恶意调用方传入超大 routing 导致内存耗尽 / 规划耗时过长
    //   上限 1M tokens 与 static_shape.hpp kMaxTokensLimit 对齐
    constexpr std::size_t kMaxRoutingTokens = 1u << 20;  // 1M tokens
    if (routing.size() > kMaxRoutingTokens) {
        throw std::invalid_argument("routing size exceeds 1M tokens limit (DoS protection)");
    }
    // v1.7.0.7 H8 DoS 防护：单个 token 的专家列表长度上限（典型 MoE top-k <= 16，上限 256 留余量）
    constexpr std::size_t kMaxExpertsPerToken = 256;
    for (std::size_t t = 0; t < routing.size(); ++t) {
        if (routing[t].empty()) {
            throw std::invalid_argument("routing[t] must not be empty");
        }
        if (routing[t].size() > kMaxExpertsPerToken) {
            throw std::invalid_argument("routing[t] expert count exceeds 256 limit (DoS protection)");
        }
        for (const auto e : routing[t]) {
            if (e >= config.num_experts) {
                throw std::invalid_argument("expert_id out of range");
            }
        }
    }

    EpCommPlan plan;
    plan.shape = config.shape;

    // 阶段 0：routing_hash + plan_id
    plan.routing_hash = compute_routing_hash(routing);
    plan.plan_id = next_plan_id_();
    plan.sync_id = derive_sync_id_(plan.plan_id);

    // 阶段 1：expert->node 映射
    const auto expert_to_node = build_expert_to_node_map(config);

    // 阶段 2：token->node
    plan.dst_nodes = map_tokens_to_nodes_(routing, expert_to_node);
    plan.expert_ids.reserve(plan.dst_nodes.size());
    for (std::size_t t = 0; t < routing.size(); ++t) {
        plan.expert_ids.push_back(routing[t][0]);
    }

    // 阶段 3：按 dst 分组
    const auto grouped = group_tokens_by_dst_(plan.dst_nodes, config);

    // 阶段 4：dispatch_bufs + tokens_per_dst
    plan.dispatch_bufs = compute_dispatch_bufs_(grouped, config.shape);
    plan.tokens_per_dst = grouped.group_sizes;

    // 阶段 5：combine_bufs + zero_fill_ranges
    const auto cp = compute_combine_plan_(grouped, config.shape);
    plan.combine_bufs = cp.combine_bufs;
    plan.zero_fill_ranges = cp.zero_fill_ranges;

    // 阶段 6：负载统计
    const auto st = compute_load_stats_(routing, config.num_experts);
    plan.total_tokens = st.total_tokens;
    plan.max_tokens_per_expert = st.max_tokens_per_expert;
    plan.min_tokens_per_expert = st.min_tokens_per_expert;
    plan.load_imbalance_ratio = st.imbalance_ratio;
    plan.load_balanced = st.balanced;

    // 阶段 6.5（P5）：冗余专家负载均衡
    if (config.num_redundant_experts > 0) {
        // 构建 base_assignment[E]：expert_id -> node_id（worker_idx）
        std::vector<NodeId> base_assignment(config.num_experts, 0);
        bool placement_valid = true;
        for (std::size_t w = 0; w < config.expert_placement.size(); ++w) {
            for (const auto expert : config.expert_placement[w]) {
                if (expert < config.num_experts) {
                    base_assignment[expert] = static_cast<NodeId>(w);
                } else {
                    placement_valid = false;
                }
            }
        }
        if (placement_valid) {
            // 构建 tokens_per_expert[E]：从 routing 统计每专家被选中的 token 数
            std::vector<std::uint32_t> tokens_per_expert(config.num_experts, 0);
            for (const auto& token_experts : routing) {
                for (const auto e : token_experts) {
                    if (e < config.num_experts) {
                        ++tokens_per_expert[e];
                    }
                }
            }

            ExpertBalancer balancer;
            auto assignment = balancer.balance(
                tokens_per_expert,
                base_assignment,
                static_cast<std::uint32_t>(config.ep_workers.size()),
                config.num_redundant_experts,
                static_cast<BalanceStrategy>(config.balance_strategy));

            plan.redundant_experts = std::move(assignment.redundant_experts);
            plan.num_redundant = config.num_redundant_experts;
            plan.load_imbalance_ratio = assignment.imbalance_ratio;
            plan.load_balanced = assignment.balanced;
        }
    }

    // 阶段 7：sync 参与者
    plan.sync_participants = collect_sync_participants_(plan.dst_nodes);

    // 阶段 8：写入缓存
    cache_.insert(plan.routing_hash, plan);

    return plan;
}

std::optional<EpCommPlan> CommPlanner::try_cache(std::uint64_t routing_hash) {
    return cache_.lookup(routing_hash);
}

std::size_t CommPlanner::cache_size() const noexcept {
    return cache_.size();
}

void CommPlanner::clear_cache() noexcept {
    cache_.clear();
}

std::uint64_t CommPlanner::cache_hits() const noexcept {
    return cache_.hits();
}

std::uint64_t CommPlanner::cache_misses() const noexcept {
    return cache_.misses();
}

double CommPlanner::cache_hit_rate() const noexcept {
    return cache_.hit_rate();
}

// ============================================================================
// 序列化
// ============================================================================

std::vector<std::uint8_t> CommPlanner::serialize(const EpCommPlan& plan) {
    std::vector<std::uint8_t> buf;
    // magic header
    write_u32(buf, 0x45434D50);  // 'ECMP' EpCommPlan
    write_u32(buf, 0x00010000);  // version 1.0
    write_u64(buf, plan.plan_id);
    write_u64(buf, plan.routing_hash);
    write_u64(buf, plan.sync_id);
    write_u32(buf, plan.total_tokens);
    write_u32(buf, plan.max_tokens_per_expert);
    write_u32(buf, plan.min_tokens_per_expert);
    write_double(buf, plan.load_imbalance_ratio);
    write_u8(buf, plan.load_balanced ? 1 : 0);
    write_shape(buf, plan.shape);
    write_u32(buf, static_cast<std::uint32_t>(plan.dst_nodes.size()));
    for (const auto& v : plan.dst_nodes) write_u64(buf, v);
    write_u32(buf, static_cast<std::uint32_t>(plan.expert_ids.size()));
    for (const auto& v : plan.expert_ids) write_u32(buf, v);
    write_vec_buffer_slice(buf, plan.dispatch_bufs);
    write_u32(buf, static_cast<std::uint32_t>(plan.tokens_per_dst.size()));
    for (const auto& v : plan.tokens_per_dst) write_u32(buf, v);
    write_vec_buffer_slice(buf, plan.combine_bufs);
    write_vec_range(buf, plan.zero_fill_ranges);
    write_u32(buf, static_cast<std::uint32_t>(plan.sync_participants.size()));
    for (const auto& v : plan.sync_participants) write_u64(buf, v);
    write_u8(buf, static_cast<std::uint8_t>(plan.transport_hint));
    // === P5 字段 ===
    write_u32(buf, plan.num_redundant);
    write_u32(buf, static_cast<std::uint32_t>(plan.redundant_experts.size()));
    for (const auto e : plan.redundant_experts) write_u32(buf, e);
    return buf;
}

bool CommPlanner::deserialize(std::span<const std::uint8_t> data, EpCommPlan& out) {
    std::size_t pos = 0;
    std::uint32_t magic, ver;
    if (!read_u32(data, pos, magic)) return false;
    if (magic != 0x45434D50) return false;
    if (!read_u32(data, pos, ver)) return false;
    if (ver != 0x00010000) return false;
    if (!read_u64(data, pos, out.plan_id)) return false;
    if (!read_u64(data, pos, out.routing_hash)) return false;
    if (!read_u64(data, pos, out.sync_id)) return false;
    if (!read_u32(data, pos, out.total_tokens)) return false;
    if (!read_u32(data, pos, out.max_tokens_per_expert)) return false;
    if (!read_u32(data, pos, out.min_tokens_per_expert)) return false;
    if (!read_double(data, pos, out.load_imbalance_ratio)) return false;
    std::uint8_t bal;
    if (!read_u8(data, pos, bal)) return false;
    out.load_balanced = (bal != 0);
    if (!read_shape(data, pos, out.shape)) return false;
    if (!read_vec_u64(data, pos, out.dst_nodes)) return false;
    if (!read_vec_u32(data, pos, out.expert_ids)) return false;
    if (!read_vec_buffer_slice(data, pos, out.dispatch_bufs)) return false;
    if (!read_vec_u32(data, pos, out.tokens_per_dst)) return false;
    if (!read_vec_buffer_slice(data, pos, out.combine_bufs)) return false;
    if (!read_vec_range(data, pos, out.zero_fill_ranges)) return false;
    if (!read_vec_u64(data, pos, out.sync_participants)) return false;
    std::uint8_t thint;
    if (!read_u8(data, pos, thint)) return false;
    out.transport_hint = static_cast<EpCommPlan::TransportHint>(thint);
    // === P5 字段（向后兼容：数据不足时保留默认值） ===
    if (!read_u32(data, pos, out.num_redundant)) return true;  // 旧版数据结束，P5 字段保持默认
    std::uint32_t redundant_cnt = 0;
    if (!read_u32(data, pos, redundant_cnt)) return true;
    // v1.7.0.7 H8 DoS 防护：redundant_cnt 上限检查（每元素 4 字节）
    //   根因：原实现直接 reserve(redundant_cnt)，恶意对端发送 redundant_cnt=0xFFFFFFFF 触发 bad_alloc
    constexpr std::size_t kRedundantElemSize = 4;
    if (redundant_cnt > (data.size() - pos) / kRedundantElemSize) return true;  // 视为旧版兼容
    out.redundant_experts.clear();
    out.redundant_experts.reserve(redundant_cnt);
    for (std::uint32_t i = 0; i < redundant_cnt; ++i) {
        std::uint32_t e;
        if (!read_u32(data, pos, e)) return true;  // 部分读取也视为兼容
        out.redundant_experts.push_back(e);
    }
    return true;
}

}  // namespace linoh::multimodal::ep
