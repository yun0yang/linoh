// test_protocol_dict_compression.cpp — O1 协议字典压缩测试
//（cluster 优化总体方案 v1.0 / linoh 编码层方案 O1）
//
// 测试覆盖：
//   1. 字典注册表：load / has / clear
//   2. compress_dict → serialize → parse → decompress 往返无损（结构化分镜样本）
//   3. compress_dict 置/清 ZstdDictCompressed flag；与 ZstdCompressed 互斥
//   4. 收益门禁：字典压缩后 ≤ 原始 40%（实测约 7%，门禁 ≥60% 节省）
//   5. 字典缺失 → decompress false（丢弃路径依据）
//   6. maybe_auto_compress：开关 off/on、字典优先、无字典回退普通 zstd
//   7. recommend_compression v2 规则表
//   8. 旧格式消息（无压缩 flag）parse + maybe_auto_decompress no-op 兼容

#include "linoh/protocol/application_message.hpp"
#include "linoh/protocol/compression.hpp"
#include "linoh/protocol/capabilities.hpp"

#include <zstd.h>
#define ZDICT_STATIC_LINKING_ONLY
#include <zdict.h>

#include <cstdio>
#include <cstring>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace linoh::protocol;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 构造结构化分镜任务消息（跨消息先验丰富：schema/字段名/URL 前缀/场景描述）
// ============================================================================

static std::string make_segment_task(int variant, int segs) {
    std::mt19937_64 rng(1000 + variant);
    std::ostringstream oss;
    oss << "{\"task_id\":\"task_" << std::hex << rng() << std::dec
        << "\",\"model\":\"h3-v1-12g\",\"task_type\":\"segment_video\""
        << ",\"output_oss_url\":\"https://mpm-oss.oss-cn-beijing.aliyuncs.com/video/"
        << std::hex << rng() << std::dec
        << "/output.mp4?OSSAccessKeyId=LTAI5tExample&Expires=1756000000&Signature="
        << std::hex << rng() << rng() << std::dec << "%3D\",\"segments\":[";
    static const char *scenes[] = {
        "夜晚城市街道，年轻女子身穿米色风衣快步行走，霓虹灯映照湿漉漉的路面，镜头缓慢跟拍",
        "清晨的厨房，阳光透过百叶窗，男主角穿着白衬衫煮咖啡，中景固定机位",
        "黄昏的天台，两人并肩而坐远眺城市轮廓，逆光剪影，缓慢推进",
        "雨天咖啡馆内，玻璃窗上雨滴滑落，女子低头搅拌咖啡，特写浅景深",
    };
    for (int i = 0; i < segs; ++i) {
        if (i) oss << ",";
        oss << "{\"id\":" << i
            << ",\"start_ms\":" << (i * 3000 + static_cast<int>(rng() % 500))
            << ",\"duration_ms\":3000"
            << ",\"prompt\":\"" << scenes[i % 4] << "\""
            << ",\"negative_prompt\":\"模糊,变形,低清,多余手指,水印\""
            << ",\"ref_image\":\"https://mpm-oss.oss-cn-beijing.aliyuncs.com/refs/ref_"
            << std::hex << (rng() & 0xffffff) << std::dec << ".png\""
            << ",\"params\":{\"steps\":20,\"cfg\":7.5,\"width\":768,\"height\":432,"
               "\"use_refs\":true,\"seed\":" << static_cast<int>(rng() % 100000) << "}}";
    }
    oss << "],\"callback\":\"https://orchestrator.internal:8080/api/v1/callback\"}";
    return oss.str();
}

static std::vector<std::uint8_t> to_bytes(const std::string &s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

// 训练 4KB 字典：64 条结构化变体 + 2 条小消息
static std::vector<std::uint8_t> train_dict() {
    std::vector<std::string> samples;
    for (int v = 100; v < 164; ++v) {
        samples.push_back(make_segment_task(v, 10));
        samples.push_back(make_segment_task(v, 30));
    }
    std::string buf;
    std::vector<size_t> sizes;
    for (auto &s : samples) { buf += s; sizes.push_back(s.size()); }
    std::vector<std::uint8_t> dict(4096);
    size_t r = ZDICT_trainFromBuffer(dict.data(), dict.size(),
                                     buf.data(), sizes.data(),
                                     static_cast<unsigned>(sizes.size()));
    if (ZDICT_isError(r)) {
        std::printf("dict train failed: %s\n", ZDICT_getErrorName(r));
        return {};
    }
    dict.resize(r);
    return dict;
}

int main() {
    std::printf("=== O1 protocol dict compression tests ===\n");

    // ------------------------------------------------------------------
    // T1: 字典注册表
    // ------------------------------------------------------------------
    auto dict = train_dict();
    CHECK(!dict.empty());
    CHECK(load_protocol_dict(1, dict));
    CHECK(has_protocol_dict(1));
    CHECK(!has_protocol_dict(2));
    CHECK(has_any_protocol_dict());
    CHECK(default_dict_id() == 1);
    // O1.3: info 查询（一致性校验字段）
    auto info = protocol_dict_info(1);
    CHECK(info.loaded && info.dict_id == 1 && info.size == dict.size() && info.xxh64 != 0);
    auto info_miss = protocol_dict_info(9);
    CHECK(!info_miss.loaded);
    std::printf("[T1] dict registry: PASS-load %zuB (xxh64=%016llx)\n",
                dict.size(), (unsigned long long)info.xxh64);

    // ------------------------------------------------------------------
    // T2+T3+T4: compress_dict 往返 + flag + 收益门禁
    // ------------------------------------------------------------------
    {
        auto sample = make_segment_task(7, 10);  // 未参与训练的变体
        auto payload = to_bytes(sample);
        auto msg = ApplicationMessage::notification(
            MethodId::AddrInfoAnnounce, payload);
        size_t before = msg.payload.size();

        CHECK(msg.compress_dict(1));
        CHECK(msg.is_zstd_dict_compressed());
        CHECK(!msg.is_zstd_compressed());
        CHECK(msg.payload.size() < before);
        // 收益门禁：压缩后 ≤ 40%（门禁 ≥60% 节省；实测预期 ~7%）
        CHECK(msg.payload.size() <= before * 40 / 100);
        std::printf("[T4] ratio: %zu -> %zu B (%.1f%%)\n",
                    before, msg.payload.size(),
                    100.0 * msg.payload.size() / before);

        // serialize → parse → decompress 往返
        auto wire = msg.serialize();
        ApplicationMessage parsed;
        auto consumed = ApplicationMessage::parse(
            std::span<const std::uint8_t>(wire.data(), wire.size()), parsed);
        CHECK(consumed == wire.size());
        CHECK(parsed.is_zstd_dict_compressed());
        CHECK(parsed.maybe_auto_decompress());
        CHECK(!parsed.is_zstd_dict_compressed());
        CHECK(parsed.payload == payload);
        std::printf("[T2] roundtrip lossless: PASS\n");
    }

    // ------------------------------------------------------------------
    // T3b: flag 互斥
    // ------------------------------------------------------------------
    {
        auto payload = to_bytes(make_segment_task(8, 10));
        auto msg = ApplicationMessage::notification(MethodId::ProgressReport, payload);
        CHECK(msg.compress(CompressionAlgo::Zstd));
        CHECK(!msg.compress_dict(1));  // 已 ZstdCompressed → 互斥拒绝
        // 手工构造三 flag 同置 → decompress false
        msg.set_flag(MessageFlags::PayloadCompressed);
        CHECK(!msg.decompress());
        std::printf("[T3] flag mutex: PASS\n");
    }

    // ------------------------------------------------------------------
    // T5: 字典缺失路径
    // ------------------------------------------------------------------
    {
        auto payload = to_bytes(make_segment_task(9, 10));
        auto msg = ApplicationMessage::notification(MethodId::ProgressReport, payload);
        CHECK(!msg.compress_dict(2));  // 字典 2 未注册 → 拒绝压缩
        std::printf("[T5] missing dict compress rejected: PASS\n");
    }

    // ------------------------------------------------------------------
    // T6: maybe_auto_compress 开关行为
    // ------------------------------------------------------------------
    {
        set_auto_compress(false);  // 默认 off
        CHECK(!auto_compress_enabled());
        auto payload = to_bytes(make_segment_task(10, 10));
        auto msg = ApplicationMessage::notification(MethodId::AddrInfoAnnounce, payload);
        CHECK(!msg.maybe_auto_compress());
        CHECK(msg.payload.size() == payload.size());  // 未动

        set_auto_compress(true);
        CHECK(msg.maybe_auto_compress());
        CHECK(msg.is_zstd_dict_compressed());  // 字典优先
        CHECK(msg.maybe_auto_decompress());
        CHECK(msg.payload == payload);

        // Heartbeat 不压
        auto hb = ApplicationMessage::notification(MethodId::Heartbeat,
                                                   to_bytes(std::string(2000, 'a')));
        CHECK(!hb.maybe_auto_compress());
        // <300B 不压
        auto tiny = ApplicationMessage::notification(MethodId::AddrInfoAnnounce,
                                                     to_bytes(std::string(100, 'x')));
        CHECK(!tiny.maybe_auto_compress());
        // TensorShard 不压（与分片语义解耦）
        auto shard = ApplicationMessage::notification(MethodId::TensorShard,
                                                      to_bytes(make_segment_task(11, 10)));
        CHECK(!shard.maybe_auto_compress());
        std::printf("[T6] auto-compress gating: PASS\n");
    }

    // ------------------------------------------------------------------
    // T7: 无字典回退普通 zstd
    // ------------------------------------------------------------------
    {
        clear_protocol_dicts();
        CHECK(!has_any_protocol_dict());
        set_auto_compress(true);
        auto payload = to_bytes(make_segment_task(12, 10));
        auto msg = ApplicationMessage::notification(MethodId::ProgressReport, payload);
        CHECK(msg.maybe_auto_compress());
        CHECK(msg.is_zstd_compressed());  // 回退路径
        CHECK(msg.maybe_auto_decompress());
        CHECK(msg.payload == payload);
        std::printf("[T7] fallback to plain zstd: PASS\n");
    }

    // ------------------------------------------------------------------
    // T8: recommend_compression v2 规则表
    // ------------------------------------------------------------------
    {
        CHECK(recommend_compression(2000, MethodId::Heartbeat) == CompressionAlgo::None);
        CHECK(recommend_compression(200, MethodId::AddrInfoAnnounce) == CompressionAlgo::None);
        CHECK(recommend_compression(500, MethodId::AddrInfoAnnounce) == CompressionAlgo::Zstd);
        CHECK(recommend_compression(500, MethodId::ProgressReport) == CompressionAlgo::Zstd);
        CHECK(recommend_compression(2048, MethodId::ForwardPP) == CompressionAlgo::Zstd);
        CHECK(recommend_compression(512, MethodId::ForwardPP) == CompressionAlgo::None);
        CHECK(recommend_compression(8192, MethodId::TensorShard) == CompressionAlgo::None);
        CHECK(recommend_compression(8192, MethodId::Observe) == CompressionAlgo::None);
        CHECK(recommend_compression(32 * 1024, MethodId::StateChange) == CompressionAlgo::Zstd);
        // 未知方法默认 16KB 阈值（与旧规则一致）
        CHECK(recommend_compression(8 * 1024, static_cast<MethodId>(0x0F00)) == CompressionAlgo::None);
        CHECK(recommend_compression(32 * 1024, static_cast<MethodId>(0x0F00)) == CompressionAlgo::Zstd);
        std::printf("[T8] recommend v2 rules: PASS\n");
    }

    // ------------------------------------------------------------------
    // T9: 旧格式消息兼容（无压缩 flag）+ 能力位常量
    // ------------------------------------------------------------------
    {
        auto payload = to_bytes(make_segment_task(13, 2));
        auto msg = ApplicationMessage::notification(MethodId::Join, payload);
        auto wire = msg.serialize();
        ApplicationMessage parsed;
        CHECK(ApplicationMessage::parse(
                  std::span<const std::uint8_t>(wire.data(), wire.size()),
                  parsed) == wire.size());
        CHECK(parsed.maybe_auto_decompress());  // no-op true
        CHECK(parsed.payload == payload);
        CHECK(has_capability(kCapZstdDict, kCapZstdDict));
        CHECK(!has_capability(0, kCapZstdDict));
        std::printf("[T9] legacy message + cap bit: PASS\n");
    }

    set_auto_compress(false);  // 恢复默认，避免影响同进程其他测试
    // ------------------------------------------------------------------
    // T10: O1.2 能力降级矩阵（独立项目方案 W1.1）
    // ------------------------------------------------------------------
    {
        set_auto_compress(true);
        CHECK(load_protocol_dict(1, dict));  // T7 清空后重载

        // caps=0（未探测/旧对端）→ 不压
        auto p0 = to_bytes(make_segment_task(20, 10));
        auto m0 = ApplicationMessage::notification(MethodId::AddrInfoAnnounce, p0);
        CHECK(!m0.maybe_auto_compress(0));
        CHECK(m0.payload.size() == p0.size());

        // caps=0x0010（仅普通 zstd）→ 普通压缩，不用字典
        auto m1 = ApplicationMessage::notification(MethodId::AddrInfoAnnounce, p0);
        CHECK(m1.maybe_auto_compress(0x0010));
        CHECK(m1.is_zstd_compressed());
        CHECK(!m1.is_zstd_dict_compressed());
        CHECK(m1.maybe_auto_decompress() && m1.payload == p0);

        // caps=0x0110（含 kCapZstdDict）→ 字典优先
        auto m2 = ApplicationMessage::notification(MethodId::AddrInfoAnnounce, p0);
        CHECK(m2.maybe_auto_compress(0x0110));
        CHECK(m2.is_zstd_dict_compressed());
        CHECK(m2.maybe_auto_decompress() && m2.payload == p0);

        // 无参版本（默认全支持）→ 字典路径（兼容旧行为）
        auto m3 = ApplicationMessage::notification(MethodId::AddrInfoAnnounce, p0);
        CHECK(m3.maybe_auto_compress());
        CHECK(m3.is_zstd_dict_compressed());
        std::printf("[T10] capability downgrade matrix: none/zstd/dict\n");
        set_auto_compress(false);
    }

    std::printf("=== %d PASS / %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
