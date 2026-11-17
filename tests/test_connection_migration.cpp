// test_connection_migration.cpp — v4.0.4 M22 连接迁移协调器单元测试
//
// 测试覆盖：
//   1. MigrationConfig 默认值 + 常量校验
//   2. MigrationConfig 工厂方法（default_for_worker / default_for_master / disabled）
//   3. MigrationState 枚举值 + to_string
//   4. is_active_state 辅助函数
//   5. should_migrate 决策（地址变化 / 相同 / 禁用 / 迁移中）
//   6. initiate_migration 成功（返回 PATH_CHALLENGE + 状态 Validating + 统计）
//   7. initiate_migration 失败（禁用 / 迁移中）
//   8. on_challenge_sent（记录发送时间 + 统计）
//   9. on_response_received 正确匹配（→ Migrating）
//  10. on_response_received 不匹配（数据不同）
//  11. on_response_received 非 Validating 状态拒绝
//  12. complete_migration（→ Completed + 统计 + 耗时记录）
//  13. fail_migration（→ Failed + 统计）
//  14. should_cleanup_old_path（Completed + 超过 grace / 未超过 / 非 Completed）
//  15. cleanup_completed（Completed → Idle + old_paths_cleaned 统计）
//  16. needs_retry（超时 + 未耗尽 / 未超时 / 耗尽）
//  17. is_validation_expired（超时 / 未超时 / 非 Validating）
//  18. retry（生成新挑战 + retry_count 递增 + 统计）
//  19. retry 耗尽返回 nullopt
//  20. reset（任意状态 → Idle）
//  21. stats 累积（多次迁移统计）
//  22. events 记录 + 最新在前 + 容量上限
//  23. current_context（Idle nullopt / 迁移中返回上下文）
//  24. set_config（Idle 允许 / 活跃状态拒绝）
//  25. 完整迁移 e2e（should_migrate → initiate → challenge_sent → response → complete → cleanup）

#include "linoh/endpoint/connection_migration.hpp"

#include <cstdio>
#include <cstring>
#include <string>

using namespace linoh;
using namespace linoh::endpoint;
using Coordinator = ConnectionMigrationCoordinator;
using Clock = ConnectionMigrationCoordinator::Clock;
using TimePoint = ConnectionMigrationCoordinator::TimePoint;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    if ((a) == (b)) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s != %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ========== 测试用例 ==========

// 1. MigrationConfig 默认值 + 常量
static void test_config_defaults() {
    std::printf("[test] MigrationConfig defaults...\n");
    MigrationConfig cfg;
    CHECK(cfg.enable_migration == true);
    CHECK(cfg.path_validation_timeout == std::chrono::seconds(3));
    CHECK(cfg.old_path_cleanup_grace == std::chrono::seconds(2));
    CHECK_EQ(cfg.max_path_id, 4);
    CHECK(cfg.fec_fallback_during_migration == true);

    // 常量
    CHECK(kDefaultPathValidationTimeout == std::chrono::seconds(3));
    CHECK(kDefaultOldPathCleanupGrace == std::chrono::seconds(2));
    CHECK_EQ(kMaxMigrationRetries, 3);
    CHECK_EQ(kMaxMigrationEvents, 64u);
}

// 2. 工厂方法
static void test_config_factories() {
    std::printf("[test] MigrationConfig factories...\n");

    auto worker_cfg = MigrationConfig::default_for_worker();
    CHECK(worker_cfg.enable_migration == true);
    CHECK(worker_cfg.path_validation_timeout == std::chrono::seconds(3));

    auto master_cfg = MigrationConfig::default_for_master();
    CHECK(master_cfg.enable_migration == true);
    CHECK(master_cfg.path_validation_timeout == std::chrono::seconds(5));
    CHECK(master_cfg.old_path_cleanup_grace == std::chrono::seconds(3));

    auto disabled_cfg = MigrationConfig::disabled();
    CHECK(disabled_cfg.enable_migration == false);
}

// 3. MigrationState 枚举 + to_string
static void test_state_enum() {
    std::printf("[test] MigrationState enum + to_string...\n");
    CHECK_EQ(static_cast<int>(MigrationState::Idle), 0);
    CHECK_EQ(static_cast<int>(MigrationState::Validating), 1);
    CHECK_EQ(static_cast<int>(MigrationState::Migrating), 2);
    CHECK_EQ(static_cast<int>(MigrationState::Completed), 3);
    CHECK_EQ(static_cast<int>(MigrationState::Failed), 4);

    CHECK(to_string(MigrationState::Idle) == "Idle");
    CHECK(to_string(MigrationState::Validating) == "Validating");
    CHECK(to_string(MigrationState::Migrating) == "Migrating");
    CHECK(to_string(MigrationState::Completed) == "Completed");
    CHECK(to_string(MigrationState::Failed) == "Failed");
}

// 4. is_active_state
static void test_is_active_state() {
    std::printf("[test] is_active_state...\n");
    CHECK(is_active_state(MigrationState::Validating) == true);
    CHECK(is_active_state(MigrationState::Migrating) == true);
    CHECK(is_active_state(MigrationState::Idle) == false);
    CHECK(is_active_state(MigrationState::Completed) == false);
    CHECK(is_active_state(MigrationState::Failed) == false);
}

// 5. should_migrate 决策
static void test_should_migrate() {
    std::printf("[test] should_migrate decision...\n");
    Coordinator coord;

    // 地址变化 + 启用 → true
    CHECK(coord.should_migrate("192.168.1.1:9001", "10.0.0.1:9001") == true);
    // 地址相同 → false
    CHECK(coord.should_migrate("192.168.1.1:9001", "192.168.1.1:9001") == false);
    // 禁用迁移 → false
    Coordinator disabled_coord(MigrationConfig::disabled());
    CHECK(disabled_coord.should_migrate("192.168.1.1:9001", "10.0.0.1:9001") == false);

    // 迁移中 → false
    auto base = Clock::now();
    coord.initiate_migration("old", "new", "test", base);
    CHECK(coord.should_migrate("old2", "new2") == false);
}

// 6. initiate_migration 成功
static void test_initiate_migration_success() {
    std::printf("[test] initiate_migration success...\n");
    Coordinator coord;
    auto base = Clock::now();

    auto frame = coord.initiate_migration("192.168.1.1:9001", "10.0.0.1:9001", "WiFi→LTE", base);
    CHECK(frame.has_value());
    CHECK(frame->data.size() == 8);  // 8 字节随机数据

    // 验证状态
    CHECK_EQ(coord.state(), MigrationState::Validating);
    CHECK(coord.is_migrating() == true);

    // 验证统计
    auto s = coord.stats();
    CHECK_EQ(s.total_migrations, 1u);
}

// 7. initiate_migration 失败
static void test_initiate_migration_failure() {
    std::printf("[test] initiate_migration failure...\n");

    // 禁用迁移
    Coordinator disabled_coord(MigrationConfig::disabled());
    auto frame1 = disabled_coord.initiate_migration("old", "new", "test");
    CHECK(!frame1.has_value());

    // 迁移中再次发起
    Coordinator coord;
    auto base = Clock::now();
    coord.initiate_migration("old", "new", "test", base);
    auto frame2 = coord.initiate_migration("old2", "new2", "test2", base);
    CHECK(!frame2.has_value());
}

// 8. on_challenge_sent
static void test_on_challenge_sent() {
    std::printf("[test] on_challenge_sent...\n");
    Coordinator coord;
    auto base = Clock::now();

    auto frame = coord.initiate_migration("old", "new", "test", base);
    CHECK(frame.has_value());

    // on_challenge_sent 默认会加 path_validations_sent
    // 注意：initiate_migration 不直接加，on_challenge_sent 才加
    auto s1 = coord.stats();
    CHECK_EQ(s1.path_validations_sent, 0u);

    coord.on_challenge_sent(*frame, base);
    auto s2 = coord.stats();
    CHECK_EQ(s2.path_validations_sent, 1u);
}

// 9. on_response_received 正确匹配
static void test_on_response_match() {
    std::printf("[test] on_response_received match...\n");
    Coordinator coord;
    auto base = Clock::now();

    auto frame = coord.initiate_migration("old", "new", "test", base);
    CHECK(frame.has_value());
    coord.on_challenge_sent(*frame, base);

    // 构造匹配的响应
    protocol::PathResponseFrame response;
    response.data = frame->data;

    bool ok = coord.on_response_received(response, base);
    CHECK(ok);
    CHECK_EQ(coord.state(), MigrationState::Migrating);

    auto s = coord.stats();
    CHECK_EQ(s.path_validations_received, 1u);
}

// 10. on_response_received 不匹配
static void test_on_response_mismatch() {
    std::printf("[test] on_response_received mismatch...\n");
    Coordinator coord;
    auto base = Clock::now();

    auto frame = coord.initiate_migration("old", "new", "test", base);
    CHECK(frame.has_value());

    // 构造不匹配的响应
    protocol::PathResponseFrame response;
    response.data = frame->data;
    response.data[0] ^= 0xFF;  // 篡改第一个字节

    bool ok = coord.on_response_received(response, base);
    CHECK(!ok);
    CHECK_EQ(coord.state(), MigrationState::Validating);  // 仍处于 Validating

    auto s = coord.stats();
    CHECK_EQ(s.path_validations_received, 1u);  // 仍计入 received
}

// 11. on_response_received 非 Validating 状态
static void test_on_response_wrong_state() {
    std::printf("[test] on_response_received wrong state...\n");
    Coordinator coord;

    // Idle 状态收到响应 → false
    protocol::PathResponseFrame response{};
    bool ok = coord.on_response_received(response);
    CHECK(!ok);
}

// 12. complete_migration
static void test_complete_migration() {
    std::printf("[test] complete_migration...\n");
    Coordinator coord;
    auto base = Clock::now();

    auto frame = coord.initiate_migration("old", "new", "test", base);
    coord.on_challenge_sent(*frame, base);

    protocol::PathResponseFrame response;
    response.data = frame->data;
    coord.on_response_received(response, base);

    // 完成迁移
    auto complete_time = base + std::chrono::milliseconds(100);
    coord.complete_migration(complete_time);

    CHECK_EQ(coord.state(), MigrationState::Completed);

    auto s = coord.stats();
    CHECK_EQ(s.successful_migrations, 1u);
    CHECK(s.last_migration_duration > std::chrono::microseconds(0));
    CHECK(s.last_migration_duration >= std::chrono::milliseconds(100));
}

// 13. fail_migration
static void test_fail_migration() {
    std::printf("[test] fail_migration...\n");
    Coordinator coord;
    auto base = Clock::now();

    coord.initiate_migration("old", "new", "test", base);

    coord.fail_migration("validation timeout");

    CHECK_EQ(coord.state(), MigrationState::Failed);
    auto s = coord.stats();
    CHECK_EQ(s.failed_migrations, 1u);

    // 非 active 状态 fail 无效
    coord.fail_migration("should not count");
    CHECK_EQ(coord.stats().failed_migrations, 1u);
}

// 14. should_cleanup_old_path
static void test_should_cleanup_old_path() {
    std::printf("[test] should_cleanup_old_path...\n");
    Coordinator coord;
    auto base = Clock::now();

    // 非 Completed 状态 → false
    CHECK(coord.should_cleanup_old_path(base) == false);

    // 完成迁移
    auto frame = coord.initiate_migration("old", "new", "test", base);
    coord.on_challenge_sent(*frame, base);
    protocol::PathResponseFrame response;
    response.data = frame->data;
    coord.on_response_received(response, base);

    auto complete_time = base + std::chrono::milliseconds(100);
    coord.complete_migration(complete_time);

    // 刚完成（未超过 grace=2s）→ false
    CHECK(coord.should_cleanup_old_path(complete_time + std::chrono::seconds(1)) == false);

    // 超过 grace → true
    CHECK(coord.should_cleanup_old_path(complete_time + std::chrono::seconds(3)) == true);
}

// 15. cleanup_completed
static void test_cleanup_completed() {
    std::printf("[test] cleanup_completed...\n");
    Coordinator coord;
    auto base = Clock::now();

    // 完成迁移
    auto frame = coord.initiate_migration("old", "new", "test", base);
    coord.on_challenge_sent(*frame, base);
    protocol::PathResponseFrame response;
    response.data = frame->data;
    coord.on_response_received(response, base);
    coord.complete_migration(base + std::chrono::milliseconds(50));

    // 清理
    coord.cleanup_completed();
    CHECK_EQ(coord.state(), MigrationState::Idle);

    auto s = coord.stats();
    CHECK_EQ(s.old_paths_cleaned, 1u);

    // Failed 状态也允许清理
    coord.initiate_migration("old2", "new2", "test2", base);
    coord.fail_migration("fail");
    CHECK_EQ(coord.state(), MigrationState::Failed);
    coord.cleanup_completed();
    CHECK_EQ(coord.state(), MigrationState::Idle);
    // Failed 清理不计入 old_paths_cleaned
    CHECK_EQ(coord.stats().old_paths_cleaned, 1u);
}

// 16. needs_retry
static void test_needs_retry() {
    std::printf("[test] needs_retry...\n");
    Coordinator coord;
    auto base = Clock::now();

    auto frame = coord.initiate_migration("old", "new", "test", base);
    coord.on_challenge_sent(*frame, base);

    // 未超时 → false
    CHECK(coord.needs_retry(base + std::chrono::seconds(1)) == false);

    // 超时（3s）→ true
    CHECK(coord.needs_retry(base + std::chrono::seconds(4)) == true);

    // 非 Validating 状态 → false
    coord.fail_migration("test");
    CHECK(coord.needs_retry(base + std::chrono::seconds(10)) == false);
}

// 17. is_validation_expired
static void test_is_validation_expired() {
    std::printf("[test] is_validation_expired...\n");
    Coordinator coord;
    auto base = Clock::now();

    coord.initiate_migration("old", "new", "test", base);

    // 未超时 → false
    CHECK(coord.is_validation_expired(base + std::chrono::seconds(2)) == false);

    // 超时 → true
    CHECK(coord.is_validation_expired(base + std::chrono::seconds(4)) == true);

    // 非 Validating 状态 → false
    coord.reset();
    CHECK(coord.is_validation_expired(base + std::chrono::seconds(100)) == false);
}

// 18. retry
static void test_retry() {
    std::printf("[test] retry...\n");
    Coordinator coord;
    auto base = Clock::now();

    auto frame = coord.initiate_migration("old", "new", "test", base);
    coord.on_challenge_sent(*frame, base);

    // 未超时 retry → nullopt
    auto r1 = coord.retry(base + std::chrono::seconds(1));
    CHECK(!r1.has_value());

    // 超时 retry → 新挑战
    auto r2 = coord.retry(base + std::chrono::seconds(4));
    CHECK(r2.has_value());
    CHECK(r2->data.size() == 8);

    // retry_count 递增
    CHECK_EQ(coord.retry_count(), 1u);

    // 新挑战与旧挑战不同（概率上，随机数据）
    bool different = false;
    for (int i = 0; i < 8; ++i) {
        if (r2->data[i] != frame->data[i]) { different = true; break; }
    }
    CHECK(different);

    // 统计 path_validations_sent 递增
    auto s = coord.stats();
    CHECK_EQ(s.path_validations_sent, 1u);  // retry 内部 ++path_validations_sent

    // 非 Validating 状态 retry → nullopt
    coord.fail_migration("test");
    auto r3 = coord.retry(base + std::chrono::seconds(100));
    CHECK(!r3.has_value());
}

// 19. retry 耗尽
static void test_retry_exhausted() {
    std::printf("[test] retry exhausted...\n");
    Coordinator coord;
    auto base = Clock::now();

    coord.initiate_migration("old", "new", "test", base);

    // 重试 3 次（kMaxMigrationRetries=3）
    for (int i = 0; i < kMaxMigrationRetries; ++i) {
        auto t = base + std::chrono::seconds(4 + i * 4);
        auto r = coord.retry(t);
        CHECK(r.has_value());
    }
    CHECK_EQ(coord.retry_count(), kMaxMigrationRetries);

    // 第 4 次 retry → nullopt（耗尽）
    auto r = coord.retry(base + std::chrono::seconds(100));
    CHECK(!r.has_value());

    // needs_retry 也返回 false（重试耗尽）
    CHECK(coord.needs_retry(base + std::chrono::seconds(100)) == false);
}

// 20. reset
static void test_reset() {
    std::printf("[test] reset...\n");
    Coordinator coord;
    auto base = Clock::now();

    coord.initiate_migration("old", "new", "test", base);
    CHECK_EQ(coord.state(), MigrationState::Validating);

    coord.reset();
    CHECK_EQ(coord.state(), MigrationState::Idle);

    // reset 后可以重新发起迁移
    auto frame = coord.initiate_migration("old2", "new2", "test2", base);
    CHECK(frame.has_value());
    CHECK_EQ(coord.state(), MigrationState::Validating);

    // 统计保留（total_migrations 不因 reset 清零）
    auto s = coord.stats();
    CHECK_EQ(s.total_migrations, 2u);
}

// 21. stats 累积
static void test_stats_accumulation() {
    std::printf("[test] stats accumulation...\n");
    Coordinator coord;
    auto base = Clock::now();

    // 第一次迁移（成功）
    auto f1 = coord.initiate_migration("a", "b", "r1", base);
    coord.on_challenge_sent(*f1, base);
    protocol::PathResponseFrame resp1;
    resp1.data = f1->data;
    coord.on_response_received(resp1, base);
    coord.complete_migration(base + std::chrono::milliseconds(50));
    coord.cleanup_completed();

    // 第二次迁移（失败）
    auto f2 = coord.initiate_migration("c", "d", "r2", base + std::chrono::seconds(1));
    coord.on_challenge_sent(*f2, base + std::chrono::seconds(1));
    coord.fail_migration("timeout");

    auto s = coord.stats();
    CHECK_EQ(s.total_migrations, 2u);
    CHECK_EQ(s.successful_migrations, 1u);
    CHECK_EQ(s.failed_migrations, 1u);
    CHECK_EQ(s.path_validations_sent, 2u);
    CHECK_EQ(s.path_validations_received, 1u);
    CHECK_EQ(s.old_paths_cleaned, 1u);
}

// 22. events 记录 + 最新在前 + 容量上限
static void test_events() {
    std::printf("[test] events...\n");
    Coordinator coord;
    auto base = Clock::now();

    coord.initiate_migration("a", "b", "r1", base);

    auto events = coord.events();
    CHECK(!events.empty());
    CHECK_EQ(events[0].state, MigrationState::Validating);  // 最新在前
    CHECK(events[0].old_address == "a");
    CHECK(events[0].new_address == "b");
    CHECK(events[0].reason == "r1");

    // 容量上限测试（创建超过 kMaxMigrationEvents 次迁移）
    Coordinator coord2;
    for (std::size_t i = 0; i < kMaxMigrationEvents + 10; ++i) {
        std::string old_addr = "old" + std::to_string(i);
        std::string new_addr = "new" + std::to_string(i);
        coord2.initiate_migration(old_addr, new_addr, "bulk", base + std::chrono::seconds(i));
        coord2.fail_migration("bulk test");
        coord2.cleanup_completed();
    }
    auto events2 = coord2.events();
    CHECK(events2.size() <= kMaxMigrationEvents);
}

// 23. current_context
static void test_current_context() {
    std::printf("[test] current_context...\n");
    Coordinator coord;
    auto base = Clock::now();

    // Idle → nullopt
    CHECK(!coord.current_context().has_value());

    // 迁移中 → 返回上下文
    coord.initiate_migration("old", "new", "test", base);
    auto ctx = coord.current_context();
    CHECK(ctx.has_value());
    CHECK(ctx->old_address == "old");
    CHECK(ctx->new_address == "new");
    CHECK(ctx->reason == "test");
    CHECK_EQ(ctx->retry_count, 0u);

    // reset 后 → nullopt
    coord.reset();
    CHECK(!coord.current_context().has_value());
}

// 24. set_config
static void test_set_config() {
    std::printf("[test] set_config...\n");
    Coordinator coord;

    // Idle 状态允许更新
    MigrationConfig new_cfg;
    new_cfg.path_validation_timeout = std::chrono::seconds(10);
    CHECK(coord.set_config(new_cfg) == true);
    CHECK(coord.config().path_validation_timeout == std::chrono::seconds(10));

    // 活跃状态拒绝更新
    coord.initiate_migration("old", "new", "test");
    CHECK(coord.set_config(MigrationConfig{}) == false);
    CHECK(coord.config().path_validation_timeout == std::chrono::seconds(10));
}

// 25. 完整 e2e 迁移流程
static void test_e2e_migration_flow() {
    std::printf("[test] e2e migration flow...\n");
    Coordinator coord;
    auto base = Clock::now();

    // Step 1: 决策
    CHECK(coord.should_migrate("192.168.1.1:9001", "10.0.0.1:9001") == true);

    // Step 2: 发起迁移
    auto frame = coord.initiate_migration("192.168.1.1:9001", "10.0.0.1:9001", "WiFi→LTE", base);
    CHECK(frame.has_value());
    CHECK_EQ(coord.state(), MigrationState::Validating);

    // Step 3: 记录挑战发送
    coord.on_challenge_sent(*frame, base);

    // Step 4: 模拟对端回复（稍后收到）
    auto response_time = base + std::chrono::milliseconds(50);
    protocol::PathResponseFrame response;
    response.data = frame->data;
    bool ok = coord.on_response_received(response, response_time);
    CHECK(ok);
    CHECK_EQ(coord.state(), MigrationState::Migrating);

    // Step 5: 完成迁移
    auto complete_time = base + std::chrono::milliseconds(100);
    coord.complete_migration(complete_time);
    CHECK_EQ(coord.state(), MigrationState::Completed);

    // Step 6: 检查旧路径清理（未超过 grace）
    CHECK(coord.should_cleanup_old_path(complete_time + std::chrono::seconds(1)) == false);

    // Step 7: 超过 grace，清理旧路径
    CHECK(coord.should_cleanup_old_path(complete_time + std::chrono::seconds(3)) == true);
    coord.cleanup_completed();
    CHECK_EQ(coord.state(), MigrationState::Idle);

    // 最终统计
    auto s = coord.stats();
    CHECK_EQ(s.total_migrations, 1u);
    CHECK_EQ(s.successful_migrations, 1u);
    CHECK_EQ(s.failed_migrations, 0u);
    CHECK_EQ(s.path_validations_sent, 1u);
    CHECK_EQ(s.path_validations_received, 1u);
    CHECK_EQ(s.old_paths_cleaned, 1u);
    CHECK(s.last_migration_duration >= std::chrono::milliseconds(100));
}

// 26. e2e 迁移失败+重试流程
static void test_e2e_retry_then_fail() {
    std::printf("[test] e2e retry then fail...\n");
    Coordinator coord;
    auto base = Clock::now();

    // 发起迁移
    auto frame = coord.initiate_migration("old", "new", "NAT rebinding", base);
    coord.on_challenge_sent(*frame, base);

    // 超时重试 3 次
    for (int i = 0; i < kMaxMigrationRetries; ++i) {
        auto retry_time = base + std::chrono::seconds(4 + i * 4);
        CHECK(coord.needs_retry(retry_time) == true);
        auto r = coord.retry(retry_time);
        CHECK(r.has_value());
        coord.on_challenge_sent(*r, retry_time);
    }

    // 重试耗尽
    auto exhaust_time = base + std::chrono::seconds(4 + kMaxMigrationRetries * 4);
    CHECK(coord.needs_retry(exhaust_time) == false);
    CHECK(coord.is_validation_expired(exhaust_time) == true);

    // 迁移失败
    coord.fail_migration("max retries exhausted");
    CHECK_EQ(coord.state(), MigrationState::Failed);

    auto s = coord.stats();
    CHECK_EQ(s.failed_migrations, 1u);
    CHECK_EQ(s.path_validations_sent, 1u + kMaxMigrationRetries);  // 初始1 + 重试3
}

// ========== main ==========

int main() {
    std::printf("=== v4.0.4 M22 Connection Migration Coordinator Tests ===\n\n");

    test_config_defaults();
    test_config_factories();
    test_state_enum();
    test_is_active_state();
    test_should_migrate();
    test_initiate_migration_success();
    test_initiate_migration_failure();
    test_on_challenge_sent();
    test_on_response_match();
    test_on_response_mismatch();
    test_on_response_wrong_state();
    test_complete_migration();
    test_fail_migration();
    test_should_cleanup_old_path();
    test_cleanup_completed();
    test_needs_retry();
    test_is_validation_expired();
    test_retry();
    test_retry_exhausted();
    test_reset();
    test_stats_accumulation();
    test_events();
    test_current_context();
    test_set_config();
    test_e2e_migration_flow();
    test_e2e_retry_then_fail();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
