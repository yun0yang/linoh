// test_fec_adaptive.cpp — O3 FEC 自适应控制器测试
//（cluster 优化总体方案 v1.0 / linoh 编码层方案 O3）
//
// 测试覆盖：
//   1. 冷启动默认中档 M=2，current_config() 为合法 RS 配置
//   2. 恒定 p=1% → 收敛 M=2 零切换
//   3. 恒定 p=0.2% → 迟滞 4 窗口后降档 M=1（保守降档）
//   4. 恒定 p=5% → 2 窗口后升档 M=4（快速加保护）
//   5. 迟滞：短暂越界 1 窗口不升档；连续 2 窗口才升
//   6. 计数器回退 → 基线重置（无下溢/无误判）
//   7. 样本不足窗口 → update 返回 false 不评估
//   8. 极端 p=50% → 正常钳制 M=4
//   9. EMA 平滑数值断言
//  10. 分档边界对照编码层方案 §5.2 触发率表

#include "linoh/fec/fec_adaptive.hpp"

#include <cmath>
#include <cstdio>

using namespace linoh::fec;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// 建立差分基线（首次 update 只记基线不评估；(0,0) 打底使后续 feed 全额计入）
static void prime(FecAdaptiveController &c) { c.update(0, 0); }

// 喂 n_pkts、丢包率 p（确定性：lost = floor(n*p)）
static void feed(FecAdaptiveController &c, std::uint64_t n_pkts, double p,
                 std::uint64_t &sent, std::uint64_t &lost) {
    std::uint64_t d_lost = static_cast<std::uint64_t>(n_pkts * p);
    sent += n_pkts;
    lost += d_lost;
    c.update(sent, lost);
}

int main() {
    std::printf("=== O3 FEC adaptive controller tests ===\n");

    // ------------------------------------------------------------------
    // T1: 冷启动
    // ------------------------------------------------------------------
    {
        FecAdaptiveController c;
        CHECK(c.current_recovery_blocks() == 2);
        CHECK(c.loss_rate_ema() < 0.0);  // 无样本
        auto cfg = c.current_config();
        CHECK(cfg.type == FecType::ReedSolomon);
        CHECK(cfg.data_blocks == 16);
        CHECK(cfg.block_size == 1024);
        CHECK(cfg.valid());
        std::printf("[T1] cold start: M=%d\n", c.current_recovery_blocks());
    }

    // ------------------------------------------------------------------
    // T2: 恒定 p=1% → M=2 零切换
    // ------------------------------------------------------------------
    {
        FecAdaptiveController c;
        std::uint64_t sent = 0, lost = 0;
        prime(c);
        for (int i = 0; i < 20; ++i) feed(c, 500, 0.01, sent, lost);
        CHECK(c.current_recovery_blocks() == 2);
        CHECK(c.switch_count() == 0);
        CHECK(c.windows_evaluated() == 20);
        // EMA 收敛到 ~1%
        CHECK(c.loss_rate_ema() > 0.008 && c.loss_rate_ema() < 0.012);
        std::printf("[T2] p=1%% steady: M=%d, ema=%.4f, switches=%u\n",
                    c.current_recovery_blocks(), c.loss_rate_ema(),
                    c.switch_count());
    }

    // ------------------------------------------------------------------
    // T3: 恒定 p=0.2% → 4 窗口后降档 M=1
    // ------------------------------------------------------------------
    {
        FecAdaptiveController c;
        std::uint64_t sent = 0, lost = 0;
        // 先在 1% 下稳定 M=2
        for (int i = 0; i < 10; ++i) feed(c, 500, 0.01, sent, lost);
        // 降到 0.2%：EMA 需数窗拉低，随后 down_streak 累计
        for (int i = 0; i < 10; ++i) feed(c, 500, 0.002, sent, lost);
        CHECK(c.current_recovery_blocks() == 1);
        CHECK(c.switch_count() == 1);
        std::printf("[T3] p=0.2%% downshift: M=%d, switches=%u\n",
                    c.current_recovery_blocks(), c.switch_count());
    }

    // ------------------------------------------------------------------
    // T4: 恒定 p=5% → 2 窗口升档 M=4
    // ------------------------------------------------------------------
    {
        FecAdaptiveController c;
        std::uint64_t sent = 0, lost = 0;
        prime(c);
        for (int i = 0; i < 3; ++i) feed(c, 500, 0.05, sent, lost);
        CHECK(c.current_recovery_blocks() == 4);
        std::printf("[T4] p=5%% upshift: M=%d after %u windows\n",
                    c.current_recovery_blocks(), c.windows_evaluated());
    }

    // ------------------------------------------------------------------
    // T5: 迟滞 —— 短暂越界不升档
    // ------------------------------------------------------------------
    {
        FecAdaptiveController c;
        std::uint64_t sent = 0, lost = 0;
        prime(c);
        // 1% 稳定（EMA=0.010）
        for (int i = 0; i < 10; ++i) feed(c, 500, 0.01, sent, lost);
        CHECK(c.current_recovery_blocks() == 2);
        // 小冲高 4%：EMA = 0.3*0.04+0.7*0.01 = 0.019 未越界
        feed(c, 500, 0.04, sent, lost);
        // 大冲高 10% 单窗：EMA = 0.037 越界，up_streak=1 < 2 不升档
        feed(c, 500, 0.10, sent, lost);
        CHECK(c.current_recovery_blocks() == 2);  // 单窗越界不足以升档
        // 回落 1%（EMA 回落慢是平滑语义的一部分）+ 持续高丢包
        for (int i = 0; i < 5; ++i) feed(c, 500, 0.01, sent, lost);
        for (int i = 0; i < 4; ++i) feed(c, 500, 0.05, sent, lost);
        CHECK(c.current_recovery_blocks() == 4);
        std::printf("[T5] hysteresis: single-window burst not enough, sustained upshift ok\n");
    }

    // ------------------------------------------------------------------
    // T6: 计数器回退 → 基线重置
    // ------------------------------------------------------------------
    {
        FecAdaptiveController c;
        std::uint64_t sent = 0, lost = 0;
        prime(c);
        for (int i = 0; i < 5; ++i) feed(c, 500, 0.05, sent, lost);
        const int m_before = c.current_recovery_blocks();
        // 连接重置：计数器变小
        sent = 100; lost = 2;
        CHECK(!c.update(sent, lost));  // 重置不评估
        // 重新喂低丢包，控制器应正常工作且不崩
        for (int i = 0; i < 6; ++i) feed(c, 500, 0.001, sent, lost);
        CHECK(c.current_recovery_blocks() >= 1);
        CHECK(c.current_recovery_blocks() <= m_before);
        std::printf("[T6] counter rollback: rebase ok, M=%d\n",
                    c.current_recovery_blocks());
    }

    // ------------------------------------------------------------------
    // T7: 样本不足不评估
    // ------------------------------------------------------------------
    {
        FecAdaptiveController c;
        std::uint64_t sent = 0, lost = 0;
        prime(c);
        feed(c, 499, 0.5, sent, lost);
        CHECK(!c.update(sent, lost));
        CHECK(c.windows_evaluated() == 0);
        CHECK(c.loss_rate_ema() < 0.0);
        feed(c, 1, 0.0, sent, lost);  // 凑满 500
        CHECK(c.windows_evaluated() == 1);
        std::printf("[T7] window threshold respected\n");
    }

    // ------------------------------------------------------------------
    // T8: 极端 p=50% 钳制
    // ------------------------------------------------------------------
    {
        FecAdaptiveController c;
        std::uint64_t sent = 0, lost = 0;
        prime(c);
        for (int i = 0; i < 5; ++i) feed(c, 500, 0.5, sent, lost);
        CHECK(c.current_recovery_blocks() == 4);
        CHECK(c.loss_rate_ema() <= 1.0);
        std::printf("[T8] extreme clamp: M=%d, ema=%.3f\n",
                    c.current_recovery_blocks(), c.loss_rate_ema());
    }

    // ------------------------------------------------------------------
    // T9: EMA 平滑（alpha=1 直通 / alpha 小更平滑）
    // ------------------------------------------------------------------
    {
        FecAdaptiveController::Options o;
        o.ema_alpha = 1.0;  // 无平滑
        FecAdaptiveController c(o);
        std::uint64_t sent = 0, lost = 0;
        prime(c);
        feed(c, 500, 0.10, sent, lost);
        CHECK(std::fabs(c.loss_rate_ema() - 0.10) < 1e-9);

        FecAdaptiveController::Options o2;
        o2.ema_alpha = 0.5;
        FecAdaptiveController c2(o2);
        std::uint64_t s2 = 0, l2 = 0;
        prime(c2);
        feed(c2, 500, 0.10, s2, l2);  // ema = 0.10（首窗）
        feed(c2, 500, 0.00, s2, l2);  // ema = 0.5*0 + 0.5*0.10 = 0.05
        CHECK(std::fabs(c2.loss_rate_ema() - 0.05) < 1e-9);
        std::printf("[T9] EMA arithmetic\n");
    }

    // ------------------------------------------------------------------
    // T10: 分档对照编码层方案 §5.2（p=3% 越上界 2% → M=4）
    // ------------------------------------------------------------------
    {
        FecAdaptiveController c;
        std::uint64_t sent = 0, lost = 0;
        prime(c);
        for (int i = 0; i < 8; ++i) feed(c, 500, 0.03, sent, lost);
        CHECK(c.current_recovery_blocks() == 4);  // 3% > 2% 上界 → M=4
        std::printf("[T10] p=3%% tier: M=%d (方案 §5.2 表：M=4 档触发率 0.04%%)\n",
                    c.current_recovery_blocks());
    }

    std::printf("=== %d PASS / %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
