// test_single_dest_holepunch.cpp — P0-G4 单一目的地址外发测试
//
// 验证：
//   1. SingleDestConfig 默认构造（enabled=true, threshold=0.6, retries=2, timeout=2s）
//   2. HolepunchResult 新字段默认值（single_dest_used=false, port=0, attempts=0）
//   3. single_dest_max_attempts: candidates_size=0 → 0
//   4. single_dest_max_attempts: candidates_size < fallback_retries+1 → candidates_size
//   5. single_dest_max_attempts: candidates_size > fallback_retries+1 → fallback_retries+1
//   6. single_dest_max_attempts: candidates_size == fallback_retries+1 → 等值
//   7. single_dest_max_attempts: fallback_retries=0 → 1
//   8. should_use_single_dest: enabled=false → false
//   9. should_use_single_dest: candidates_size=0 → false
//  10. should_use_single_dest: confidence < threshold → false
//  11. should_use_single_dest: confidence == threshold → true（>= 语义）
//  12. should_use_single_dest: confidence > threshold → true
//  13. should_use_single_dest: 全满足 → true
//  14. attempt_symmetric_single_dest: predicted_ports 空 → 失败，single_dest_used=false
//  15. attempt_symmetric_single_dest: 空输入 error_msg 非空
//  16. SingleDestConfig 自定义值生效
//  17. HolepunchResult strategy_used 在 single_dest 失败时仍为 SymmetricNat

#include "linoh/net/holepuncher.hpp"

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::printf("FAIL line %d: %s\n", __LINE__, #cond); \
        ++fail_count; \
    } else { ++pass_count; } \
} while (0)

using namespace linoh;
using namespace linoh::net;

static int pass_count = 0;
static int fail_count = 0;

// ============================================================================
// 测试用例
// ============================================================================

static void test_single_dest_config_default() {
    SingleDestConfig cfg;
    CHECK(cfg.enabled == true);
    CHECK(cfg.confidence_threshold == 0.6);
    CHECK(cfg.response_timeout == std::chrono::seconds(2));
    CHECK(cfg.fallback_retries == 2);
}

static void test_single_dest_config_custom() {
    SingleDestConfig cfg;
    cfg.enabled = false;
    cfg.confidence_threshold = 0.8;
    cfg.response_timeout = std::chrono::milliseconds(1500);
    cfg.fallback_retries = 5;
    CHECK(cfg.enabled == false);
    CHECK(cfg.confidence_threshold == 0.8);
    CHECK(cfg.response_timeout == std::chrono::milliseconds(1500));
    CHECK(cfg.fallback_retries == 5);
}

static void test_holepunch_result_default_fields() {
    HolepunchResult r;
    CHECK(r.single_dest_used == false);
    CHECK(r.single_dest_port == 0);
    CHECK(r.single_dest_attempts == 0);
    CHECK(r.udp_probed == false);
    CHECK(r.success == false);
    CHECK(r.strategy_used == HolepunchStrategy::None);
}

static void test_single_dest_max_attempts() {
    SingleDestConfig cfg;  // fallback_retries=2 → want=3

    // candidates_size=0 → 0
    CHECK(Holepuncher::single_dest_max_attempts(0, cfg) == 0);

    // candidates_size < want(3) → candidates_size
    CHECK(Holepuncher::single_dest_max_attempts(1, cfg) == 1);
    CHECK(Holepuncher::single_dest_max_attempts(2, cfg) == 2);

    // candidates_size == want(3) → 3
    CHECK(Holepuncher::single_dest_max_attempts(3, cfg) == 3);

    // candidates_size > want(3) → 3（截断）
    CHECK(Holepuncher::single_dest_max_attempts(10, cfg) == 3);
    CHECK(Holepuncher::single_dest_max_attempts(100, cfg) == 3);

    // fallback_retries=0 → want=1
    SingleDestConfig cfg0;
    cfg0.fallback_retries = 0;
    CHECK(Holepuncher::single_dest_max_attempts(5, cfg0) == 1);
    CHECK(Holepuncher::single_dest_max_attempts(1, cfg0) == 1);
    CHECK(Holepuncher::single_dest_max_attempts(0, cfg0) == 0);

    // fallback_retries=10 → want=11
    SingleDestConfig cfg10;
    cfg10.fallback_retries = 10;
    CHECK(Holepuncher::single_dest_max_attempts(5, cfg10) == 5);
    CHECK(Holepuncher::single_dest_max_attempts(11, cfg10) == 11);
    CHECK(Holepuncher::single_dest_max_attempts(20, cfg10) == 11);
}

static void test_should_use_single_dest() {
    SingleDestConfig cfg;  // enabled=true, threshold=0.6

    // enabled=false → false
    SingleDestConfig disabled;
    disabled.enabled = false;
    CHECK(Holepuncher::should_use_single_dest(0.9, 10, disabled) == false);

    // candidates_size=0 → false
    CHECK(Holepuncher::should_use_single_dest(0.9, 0, cfg) == false);

    // confidence < threshold → false
    CHECK(Holepuncher::should_use_single_dest(0.59, 10, cfg) == false);
    CHECK(Holepuncher::should_use_single_dest(0.0, 10, cfg) == false);

    // confidence == threshold → true（>= 语义）
    CHECK(Holepuncher::should_use_single_dest(0.6, 10, cfg) == true);

    // confidence > threshold → true
    CHECK(Holepuncher::should_use_single_dest(0.61, 10, cfg) == true);
    CHECK(Holepuncher::should_use_single_dest(1.0, 1, cfg) == true);

    // 全满足 → true
    CHECK(Holepuncher::should_use_single_dest(0.8, 5, cfg) == true);
}

static void test_attempt_single_dest_empty_ports() {
    // predicted_ports 空 → 失败，不创建 socket，single_dest_used=false
    SingleDestConfig cfg;
    auto result = Holepuncher::attempt_symmetric_single_dest(
        "127.0.0.1", 0, "127.0.0.1", {}, std::chrono::seconds(1), cfg);

    CHECK(result.success == false);
    CHECK(result.single_dest_used == false);
    CHECK(result.single_dest_port == 0);
    CHECK(result.single_dest_attempts == 0);
    CHECK(!result.error_msg.empty());
    CHECK(result.strategy_used == HolepunchStrategy::SymmetricNat);
}

static void test_strategy_name() {
    // 验证枚举值未因新增字段偏移（string_view 用 empty() 检查，!= nullptr 是 UB）
    CHECK(!Holepuncher::strategy_name(HolepunchStrategy::None).empty());
    CHECK(!Holepuncher::strategy_name(HolepunchStrategy::SymmetricNat).empty());
    CHECK(!Holepuncher::strategy_name(HolepunchStrategy::StandardRfc5389).empty());
}

int main() {
    test_single_dest_config_default();
    test_single_dest_config_custom();
    test_holepunch_result_default_fields();
    test_single_dest_max_attempts();
    test_should_use_single_dest();
    test_attempt_single_dest_empty_ports();
    test_strategy_name();

    std::printf("test_single_dest_holepunch: %d passed, %d failed\n",
                pass_count, fail_count);
    return fail_count == 0 ? 0 : 1;
}
