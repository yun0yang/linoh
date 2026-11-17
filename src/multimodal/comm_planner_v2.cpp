// comm_planner_v2.cpp — 拓扑感知集合通信规划器实现（v2.1 Phase 2 M3/M4）
//
// 实现 CommPlannerV2 的核心规划逻辑：
//   - select_algo: 基于 (op, num_nodes, msg_size) 选择最优算法
//   - sort_nodes_by_score: 按 overall_score 降序排列节点
//   - build_route: 贪心最近邻生成通信顺序（RTT 优化）
//   - split_chunks_by_compute: 异构 chunk 切分（compute 加权 + 舍入修正）
//   - plan: 编排上述步骤 + LRU 缓存
//   - serialize/deserialize: TopologyPlan 二进制序列化（ctrl/1 下发用）

#include "linoh/multimodal/comm_planner_v2.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <list>
#include <unordered_map>

namespace linoh::multimodal::ep {

// ============================================================================
// TopologyPlan::brief
// ============================================================================

std::string TopologyPlan::brief() const {
    std::string s = "TopologyPlan{op=";
    s += collective_op_name(op);
    s += ", algo=";
    s += collective_algo_name(algo);
    s += ", nodes=";
    s += std::to_string(num_nodes);
    s += ", msg=";
    s += std::to_string(msg_size);
    s += ", min_chunk=";
    s += std::to_string(min_chunk);
    s += ", max_chunk=";
    s += std::to_string(max_chunk);
    s += ", imbalance=";
    // 截断到 2 位小数
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%.2f", chunk_imbalance_ratio);
    s += buf;
    s += "}";
    return s;
}

// ============================================================================
// CommPlannerV2::PlanCache — 内部 LRU 缓存（plan_hash -> TopologyPlan）
// ============================================================================

struct CommPlannerV2::PlanCache {
    std::size_t capacity;
    // list: 头=最近使用，尾=最久未使用
    std::list<std::pair<std::uint64_t, TopologyPlan>> list_;
    std::unordered_map<std::uint64_t,
        std::list<std::pair<std::uint64_t, TopologyPlan>>::iterator> map_;
    mutable std::mutex mu_;
    std::atomic<std::uint64_t> hits_{0};
    std::atomic<std::uint64_t> misses_{0};

    explicit PlanCache(std::size_t cap) : capacity(cap) {}

    std::optional<TopologyPlan> lookup(std::uint64_t key) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = map_.find(key);
        if (it == map_.end()) {
            ++misses_;
            return std::nullopt;
        }
        // 移到链表头部
        list_.splice(list_.begin(), list_, it->second);
        ++hits_;
        return it->second->second;
    }

    void insert(std::uint64_t key, TopologyPlan plan) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = map_.find(key);
        if (it != map_.end()) {
            // 已存在：更新并移到头部
            it->second->second = std::move(plan);
            list_.splice(list_.begin(), list_, it->second);
            return;
        }
        // 容量满时淘汰尾部
        if (list_.size() >= capacity && !list_.empty()) {
            auto last = list_.back();
            map_.erase(last.first);
            list_.pop_back();
        }
        list_.emplace_front(key, std::move(plan));
        map_[key] = list_.begin();
    }

    void clear() noexcept {
        std::lock_guard<std::mutex> lk(mu_);
        list_.clear();
        map_.clear();
    }

    std::size_t size() const noexcept {
        std::lock_guard<std::mutex> lk(mu_);
        return list_.size();
    }
};

// ============================================================================
// 构造/析构
// ============================================================================

CommPlannerV2::CommPlannerV2()
    : cache_(std::make_unique<PlanCache>(16)) {}

CommPlannerV2::CommPlannerV2(std::size_t cache_capacity)
    : cache_(std::make_unique<PlanCache>(cache_capacity == 0 ? 1 : cache_capacity)) {}

// 析构函数定义在此处（PlanCache 已完整定义，unique_ptr 可正确销毁）
CommPlannerV2::~CommPlannerV2() = default;

// ====================================================================
// 核心规划 API
// ====================================================================

TopologyPlan CommPlannerV2::plan(CollectiveOp op,
                                  const std::vector<NodeProfile>& nodes,
                                  std::size_t msg_size) {
    if (nodes.empty()) {
        throw std::invalid_argument("CommPlannerV2::plan: nodes is empty");
    }
    if (msg_size == 0) {
        throw std::invalid_argument("CommPlannerV2::plan: msg_size is 0");
    }

    // 1. 计算 plan_hash，查缓存
    std::uint64_t hash = compute_plan_hash(op, nodes, msg_size);
    {
        auto cached = cache_->lookup(hash);
        if (cached.has_value()) {
            // 缓存命中：返回副本（plan_id 重新分配以区分本次调用）
            TopologyPlan result = std::move(*cached);
            result.plan_id = next_plan_id_();
            return result;
        }
    }

    // 2. 选算法
    CollectiveAlgo algo = select_algo(op, nodes.size(), msg_size);

    // 3. 节点排序（按 overall_score 降序）
    std::vector<std::uint32_t> participants = sort_nodes_by_score(nodes);

    // 4. 路由表（RTT 贪心最近邻）
    std::vector<std::uint32_t> route = build_route(nodes, participants);

    // 5. 异构 chunk 切分（compute 加权）
    std::vector<std::size_t> chunk_sizes = split_chunks_by_compute(
        nodes, participants, msg_size);

    // 6. 组装 TopologyPlan
    TopologyPlan plan;
    plan.op = op;
    plan.algo = algo;
    plan.participants = std::move(participants);
    plan.route = std::move(route);
    plan.chunk_sizes = std::move(chunk_sizes);
    plan.plan_id = next_plan_id_();
    plan.plan_hash = hash;
    plan.msg_size = msg_size;
    plan.num_nodes = nodes.size();

    // 统计 min/max/imbalance
    auto [min_it, max_it] = std::minmax_element(plan.chunk_sizes.begin(),
                                                 plan.chunk_sizes.end());
    plan.min_chunk = (min_it != plan.chunk_sizes.end()) ? *min_it : 0;
    plan.max_chunk = (max_it != plan.chunk_sizes.end()) ? *max_it : 0;
    if (plan.min_chunk > 0) {
        plan.chunk_imbalance_ratio = static_cast<double>(plan.max_chunk) /
                                      static_cast<double>(plan.min_chunk);
    } else {
        plan.chunk_imbalance_ratio = 1.0;
    }

    // 7. 写入缓存
    cache_->insert(hash, plan);

    return plan;
}

std::optional<TopologyPlan> CommPlannerV2::try_cache(std::uint64_t plan_hash) {
    return cache_->lookup(plan_hash);
}

// ====================================================================
// 规划策略 API
// ====================================================================

CollectiveAlgo CommPlannerV2::select_algo(CollectiveOp op,
                                           std::size_t num_nodes,
                                           std::size_t msg_size) noexcept {
    // 算法选择矩阵（docs §4.3.1）：
    //   - 小消息 + 少节点 → Ring（简单低延迟）
    //   - 大消息 + 多节点 → RecursiveHalving/Tree（减少步数）
    switch (op) {
        case CollectiveOp::Barrier:
            return CollectiveAlgo::Ring;  // 屏障始终 ring

        case CollectiveOp::AllReduce:
            // 小消息(<=64KB) 且 少节点(<=8) → Ring
            // 否则 → RecursiveHalving（大消息更高效）
            if (msg_size <= 64 * 1024 && num_nodes <= 8) {
                return CollectiveAlgo::Ring;
            }
            return CollectiveAlgo::RecursiveHalving;

        case CollectiveOp::AllGather:
            // 少节点(<=16) → Ring；多节点 → Tree（减少步数）
            if (num_nodes <= 16) {
                return CollectiveAlgo::Ring;
            }
            return CollectiveAlgo::Tree;

        case CollectiveOp::Broadcast:
            // 少节点(<=8) → Tree（binomial tree 高效）；多节点 → Ring
            if (num_nodes <= 8) {
                return CollectiveAlgo::Tree;
            }
            return CollectiveAlgo::Ring;

        case CollectiveOp::ReduceScatter:
            // RecursiveHalving 始终最优（减半步数 logN）
            return CollectiveAlgo::RecursiveHalving;

        case CollectiveOp::AllToAll:
            // PairwiseExchange 始终（每步配对交换）
            return CollectiveAlgo::PairwiseExchange;

        default:
            return CollectiveAlgo::Ring;  // 未知 op 默认 ring
    }
}

std::vector<std::uint32_t> CommPlannerV2::sort_nodes_by_score(
    const std::vector<NodeProfile>& nodes) {
    // 生成索引序列 [0, 1, ..., N-1]
    std::vector<std::uint32_t> indices(nodes.size());
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        indices[i] = static_cast<std::uint32_t>(i);
    }

    // 按 overall_score 降序稳定排序
    // 同分时：vram_mb 降序（显存大优先），再按 node_id 字典序（稳定确定性）
    std::stable_sort(indices.begin(), indices.end(),
        [&nodes](std::uint32_t a, std::uint32_t b) {
            const auto &na = nodes[a];
            const auto &nb = nodes[b];
            float sa = na.overall_score();
            float sb = nb.overall_score();
            if (sa != sb) return sa > sb;  // 降序
            // 同分：vram 降序
            if (na.compute.vram_mb != nb.compute.vram_mb) {
                return na.compute.vram_mb > nb.compute.vram_mb;
            }
            // 再同：node_id 字典序（保证确定性，避免随机顺序）
            return na.node_id < nb.node_id;
        });

    return indices;
}

std::vector<std::uint32_t> CommPlannerV2::build_route(
    const std::vector<NodeProfile>& nodes,
    const std::vector<std::uint32_t>& participants) {
    // 贪心最近邻：从 participants[0]（最强节点）出发，
    // 每步从未访问节点中选择 rtt_ms_avg 最小的。
    //
    // 注：NodeProfile.network.rtt_ms_avg 是该节点到 orchestrator/基准点的 RTT，
    //     近似反映节点间 RTT（无全 pairwise RTT 矩阵时的合理近似）。
    if (participants.empty()) return {};

    std::vector<std::uint32_t> route;
    route.reserve(participants.size());

    std::vector<bool> visited(participants.size(), false);
    // 起点：participants[0]（最强节点）
    std::uint32_t cur = 0;
    visited[cur] = true;
    route.push_back(cur);

    // 贪心选择下一个：未访问中 rtt 最小
    for (std::size_t step = 1; step < participants.size(); ++step) {
        std::uint32_t best = 0;
        std::uint32_t best_rtt = UINT32_MAX;
        bool found = false;
        for (std::size_t j = 0; j < participants.size(); ++j) {
            if (visited[j]) continue;
            std::uint32_t rtt = nodes[participants[j]].network.rtt_ms_avg;
            // rtt=0 视为未测量，给一个大值避免优先选未测量节点
            if (rtt == 0) rtt = 1000;
            if (!found || rtt < best_rtt) {
                best = static_cast<std::uint32_t>(j);
                best_rtt = rtt;
                found = true;
            }
        }
        if (!found) break;  // 全部访问完
        visited[best] = true;
        route.push_back(best);
    }

    return route;
}

std::vector<std::size_t> CommPlannerV2::split_chunks_by_compute(
    const std::vector<NodeProfile>& nodes,
    const std::vector<std::uint32_t>& participants,
    std::size_t msg_size) {
    if (participants.empty() || msg_size == 0) {
        return {};
    }

    std::size_t n = participants.size();
    std::vector<std::size_t> chunks(n, 0);

    // 1. 计算各节点 compute 权重
    std::vector<float> weights(n);
    float sum_w = 0.0f;
    for (std::size_t i = 0; i < n; ++i) {
        float w = nodes[participants[i]].compute.normalized_score();
        // 权重为 0 时给极小值，避免完全不分（节点无算力信息时仍参与）
        if (w <= 0.0f) w = 0.01f;
        weights[i] = w;
        sum_w += w;
    }

    // 2. 最小 chunk 保护：min_chunk = msg_size / (N * 64)
    //    当 msg 充足时确保每节点至少分到一定量；当 msg < N 时允许 0（物理约束）
    std::size_t min_chunk = (msg_size >= n) ? (msg_size / (n * 64)) : 0;
    if (min_chunk < 1 && msg_size >= n) min_chunk = 1;

    // 3. 检查是否同构（所有权重近似相等）
    bool homogeneous = true;
    if (sum_w > 0.0f && n > 1) {
        float avg_w = sum_w / static_cast<float>(n);
        for (std::size_t i = 0; i < n; ++i) {
            if (std::abs(weights[i] - avg_w) > 0.01f) {
                homogeneous = false;
                break;
            }
        }
    }

    if (homogeneous) {
        // 同构：等分
        std::size_t base = msg_size / n;
        std::size_t remainder = msg_size % n;
        for (std::size_t i = 0; i < n; ++i) {
            chunks[i] = base + (i < remainder ? 1 : 0);
        }
        return chunks;
    }

    // 4. 异构：加权分配
    //    chunk_i = round(msg_size * w_i / sum_w)
    //    使用浮点计算后四舍五入，再修正差额
    std::size_t allocated = 0;
    for (std::size_t i = 0; i < n; ++i) {
        double exact = static_cast<double>(msg_size) *
                       static_cast<double>(weights[i]) /
                       static_cast<double>(sum_w);
        std::size_t c = static_cast<std::size_t>(exact + 0.5);
        // 最小 chunk 保护
        if (c < min_chunk) c = min_chunk;
        chunks[i] = c;
        allocated += c;
    }

    // 5. 舍入修正：保证 sum(chunks) == msg_size
    //    找权重最大的节点索引（用于补差时加到最强节点）
    std::size_t max_w_idx = 0;
    float max_w = weights[0];
    for (std::size_t i = 1; i < n; ++i) {
        if (weights[i] > max_w) {
            max_w = weights[i];
            max_w_idx = i;
        }
    }

    if (allocated < msg_size) {
        // 不足：差额加到最强节点
        chunks[max_w_idx] += (msg_size - allocated);
    } else if (allocated > msg_size) {
        // 超出：从弱节点开始扣除，保护强节点分到更多 chunk
        // 排序策略：权重升序（弱节点先扣），同权重时索引降序（后入队=弱节点先扣）
        std::size_t excess = allocated - msg_size;
        std::vector<std::size_t> order(n);
        for (std::size_t i = 0; i < n; ++i) order[i] = i;
        std::sort(order.begin(), order.end(),
            [&](std::size_t a, std::size_t b) {
                // 权重升序（弱节点先扣）
                if (std::abs(weights[a] - weights[b]) > 1e-6f)
                    return weights[a] < weights[b];
                // 同权重：索引大的（participants 中靠后 = 弱节点）先扣
                return a > b;
            });
        // Phase 1: 尊重 min_chunk 下限，尽量不扣破最小保护
        for (std::size_t idx : order) {
            if (excess == 0) break;
            std::size_t avail = (chunks[idx] > min_chunk)
                                ? (chunks[idx] - min_chunk) : 0;
            std::size_t can_take = (avail < excess) ? avail : excess;
            chunks[idx] -= can_take;
            excess -= can_take;
        }
        // Phase 2: 极端情况（msg 极小，min_chunk 总和已超 msg）允许扣到 0
        // 此场景仅在 msg < n 时物理上不可避免
        for (std::size_t idx : order) {
            if (excess == 0) break;
            std::size_t can_take = (chunks[idx] < excess) ? chunks[idx] : excess;
            chunks[idx] -= can_take;
            excess -= can_take;
        }
    }

    return chunks;
}

std::uint64_t CommPlannerV2::compute_plan_hash(
    CollectiveOp op,
    const std::vector<NodeProfile>& nodes,
    std::size_t msg_size) noexcept {
    // FNV-1a 64bit hash
    // 输入：op + 各节点 endpoint_id 字节 + msg_size
    std::uint64_t hash = 0xcbf29ce484222325ULL;  // FNV offset basis
    auto fnv_mix = [&hash](const void *data, std::size_t len) {
        const auto *bytes = static_cast<const std::uint8_t *>(data);
        for (std::size_t i = 0; i < len; ++i) {
            hash ^= bytes[i];
            hash *= 0x100000001b3ULL;  // FNV prime
        }
    };

    // op
    std::uint8_t op_byte = static_cast<std::uint8_t>(op);
    fnv_mix(&op_byte, 1);

    // 节点数（确保不同数量区分）
    std::uint32_t n = static_cast<std::uint32_t>(nodes.size());
    fnv_mix(&n, sizeof(n));

    // 各节点 endpoint_id 字节（按输入顺序，保证节点集合一致即 hash 一致）
    for (const auto &node : nodes) {
        auto span = node.endpoint_id.as_span();
        fnv_mix(span.data(), span.size());
    }

    // msg_size
    fnv_mix(&msg_size, sizeof(msg_size));

    return hash;
}

// ====================================================================
// 序列化（二进制格式，用于 ctrl/1 下发）
// ====================================================================
//
// 格式（小端序）：
//   magic:       4 bytes "TPN1"
//   version:     1 byte  = 1
//   op:          1 byte
//   algo:        1 byte
//   reserved:    1 byte  = 0
//   plan_id:     8 bytes
//   plan_hash:   8 bytes
//   msg_size:    8 bytes
//   num_nodes:   4 bytes
//   min_chunk:   8 bytes
//   max_chunk:   8 bytes
//   imbalance:   8 bytes (double)
//   participants: 4 bytes count + count*4 bytes
//   route:        4 bytes count + count*4 bytes
//   chunk_sizes:  4 bytes count + count*8 bytes

namespace {
constexpr char kMagic[4] = {'T', 'P', 'N', '1'};
constexpr std::uint8_t kVersion = 1;

// 小端序写入辅助
void write_u16(std::vector<std::uint8_t> &out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
}
void write_u32(std::vector<std::uint8_t> &out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
}
void write_u64(std::vector<std::uint8_t> &out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
    }
}
void write_f64(std::vector<std::uint8_t> &out, double v) {
    std::uint64_t bits;
    std::memcpy(&bits, &v, 8);
    write_u64(out, bits);
}

// 小端序读取辅助（返回 false 表示数据不足）
bool read_u32(const std::uint8_t *&p, const std::uint8_t *end, std::uint32_t &out) {
    if (p + 4 > end) return false;
    out = static_cast<std::uint32_t>(p[0]) |
          (static_cast<std::uint32_t>(p[1]) << 8) |
          (static_cast<std::uint32_t>(p[2]) << 16) |
          (static_cast<std::uint32_t>(p[3]) << 24);
    p += 4;
    return true;
}
bool read_u64(const std::uint8_t *&p, const std::uint8_t *end, std::uint64_t &out) {
    if (p + 8 > end) return false;
    out = 0;
    for (int i = 0; i < 8; ++i) {
        out |= static_cast<std::uint64_t>(p[i]) << (i * 8);
    }
    p += 8;
    return true;
}
bool read_f64(const std::uint8_t *&p, const std::uint8_t *end, double &out) {
    std::uint64_t bits;
    if (!read_u64(p, end, bits)) return false;
    std::memcpy(&out, &bits, 8);
    return true;
}
}  // namespace

std::vector<std::uint8_t> CommPlannerV2::serialize(const TopologyPlan &plan) {
    std::vector<std::uint8_t> out;
    // 预估大小
    out.reserve(64 + plan.participants.size() * 4 +
                plan.route.size() * 4 +
                plan.chunk_sizes.size() * 8);

    // magic + version
    out.insert(out.end(), kMagic, kMagic + 4);
    out.push_back(kVersion);
    // op + algo + reserved
    out.push_back(static_cast<std::uint8_t>(plan.op));
    out.push_back(static_cast<std::uint8_t>(plan.algo));
    out.push_back(0);  // reserved

    // 元信息
    write_u64(out, plan.plan_id);
    write_u64(out, plan.plan_hash);
    write_u64(out, static_cast<std::uint64_t>(plan.msg_size));
    write_u32(out, static_cast<std::uint32_t>(plan.num_nodes));
    write_u64(out, static_cast<std::uint64_t>(plan.min_chunk));
    write_u64(out, static_cast<std::uint64_t>(plan.max_chunk));
    write_f64(out, plan.chunk_imbalance_ratio);

    // participants
    write_u32(out, static_cast<std::uint32_t>(plan.participants.size()));
    for (auto p : plan.participants) write_u32(out, p);

    // route
    write_u32(out, static_cast<std::uint32_t>(plan.route.size()));
    for (auto r : plan.route) write_u32(out, r);

    // chunk_sizes
    write_u32(out, static_cast<std::uint32_t>(plan.chunk_sizes.size()));
    for (auto c : plan.chunk_sizes) write_u64(out, static_cast<std::uint64_t>(c));

    return out;
}

bool CommPlannerV2::deserialize(std::span<const std::uint8_t> data, TopologyPlan &out) {
    const std::uint8_t *p = data.data();
    const std::uint8_t *end = p + data.size();

    // magic
    if (p + 4 > end) return false;
    if (std::memcmp(p, kMagic, 4) != 0) return false;
    p += 4;

    // version
    if (p + 1 > end) return false;
    std::uint8_t version = *p++;
    if (version != kVersion) return false;

    // op + algo + reserved
    if (p + 3 > end) return false;
    out.op = static_cast<CollectiveOp>(*p++);
    out.algo = static_cast<CollectiveAlgo>(*p++);
    ++p;  // reserved

    // 元信息
    if (!read_u64(p, end, out.plan_id)) return false;
    if (!read_u64(p, end, out.plan_hash)) return false;
    std::uint64_t msg;
    if (!read_u64(p, end, msg)) return false;
    out.msg_size = static_cast<std::size_t>(msg);
    std::uint32_t nn;
    if (!read_u32(p, end, nn)) return false;
    out.num_nodes = static_cast<std::size_t>(nn);
    std::uint64_t mc;
    if (!read_u64(p, end, mc)) return false;
    out.min_chunk = static_cast<std::size_t>(mc);
    std::uint64_t xc;
    if (!read_u64(p, end, xc)) return false;
    out.max_chunk = static_cast<std::size_t>(xc);
    if (!read_f64(p, end, out.chunk_imbalance_ratio)) return false;

    // participants
    std::uint32_t pc;
    if (!read_u32(p, end, pc)) return false;
    out.participants.resize(pc);
    for (std::uint32_t i = 0; i < pc; ++i) {
        if (!read_u32(p, end, out.participants[i])) return false;
    }

    // route
    std::uint32_t rc;
    if (!read_u32(p, end, rc)) return false;
    out.route.resize(rc);
    for (std::uint32_t i = 0; i < rc; ++i) {
        if (!read_u32(p, end, out.route[i])) return false;
    }

    // chunk_sizes
    std::uint32_t cc;
    if (!read_u32(p, end, cc)) return false;
    out.chunk_sizes.resize(cc);
    for (std::uint32_t i = 0; i < cc; ++i) {
        std::uint64_t c;
        if (!read_u64(p, end, c)) return false;
        out.chunk_sizes[i] = static_cast<std::size_t>(c);
    }

    return true;
}

// ====================================================================
// 缓存管理
// ====================================================================

std::size_t CommPlannerV2::cache_size() const noexcept {
    return cache_->size();
}
void CommPlannerV2::clear_cache() noexcept {
    cache_->clear();
}
std::uint64_t CommPlannerV2::cache_hits() const noexcept {
    return cache_->hits_.load();
}
std::uint64_t CommPlannerV2::cache_misses() const noexcept {
    return cache_->misses_.load();
}
double CommPlannerV2::cache_hit_rate() const noexcept {
    std::uint64_t h = cache_->hits_.load();
    std::uint64_t m = cache_->misses_.load();
    std::uint64_t total = h + m;
    if (total == 0) return 0.0;
    return static_cast<double>(h) / static_cast<double>(total);
}

// ====================================================================
// plan_id 原子递增
// ====================================================================

std::uint64_t CommPlannerV2::next_plan_id_() noexcept {
    static std::atomic<std::uint64_t> counter{1};
    return counter.fetch_add(1);
}

}  // namespace linoh::multimodal::ep
