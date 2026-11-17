// e2e_multimodal.cpp — v4.3.0 M21 多模态通道端到端测试
//
// 验证点：
//   1. 图片特征 pp-img/1 通道数据传输
//   2. 视频特征 pp-video/1 通道数据传输
//   3. 音频特征 pp-audio/1 通道数据传输
//   4. LLM hidden_state pp-llm/1 通道数据传输
//   5. 多模态通道共存（3 条不同 ALPN 连接到同一 master）
//   6. 各通道数据完整性验证
//   7. 不同大小数据（图片 4KB / 视频 16KB / 音频 1KB / LLM 256B）

#include "e2e/e2e_harness.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 测试 1: 图片特征通道 (pp-img/1)
// ============================================================================
static void test_img_channel() {
    std::printf("[e2e] multimodal: img channel (pp-img/1)...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 47);
    auto *worker = h.start_node("worker", 0, 47);
    CHECK(master != nullptr);
    CHECK(worker != nullptr);

    master->role = e2e::NodeContext::RoleEcho;

    auto *conn = h.connect_alpn(worker, master, "pp-img/1");
    CHECK(conn != nullptr);

    // 4KB 图片特征数据
    std::vector<uint8_t> img_data(4096);
    for (size_t i = 0; i < img_data.size(); ++i) {
        img_data[i] = static_cast<uint8_t>((i * 7 + 13) & 0xFF);
    }

    bool ok = h.send_and_wait_echo(conn, master, "pp-img/1",
                                   img_data.data(), img_data.size(),
                                   std::chrono::seconds(10));
    CHECK(ok);

    auto received = master->get_received("pp-img/1");
    CHECK(received.has_value());
    if (received) {
        CHECK(received->size() == img_data.size());
        CHECK(std::memcmp(received->data(), img_data.data(), img_data.size()) == 0);
    }
}

// ============================================================================
// 测试 2: 视频特征通道 (pp-video/1)
// ============================================================================
static void test_video_channel() {
    std::printf("[e2e] multimodal: video channel (pp-video/1)...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 47);
    auto *worker = h.start_node("worker", 0, 47);

    master->role = e2e::NodeContext::RoleEcho;

    auto *conn = h.connect_alpn(worker, master, "pp-video/1");
    CHECK(conn != nullptr);

    // 16KB 视频特征数据
    std::vector<uint8_t> video_data(16384);
    for (size_t i = 0; i < video_data.size(); ++i) {
        video_data[i] = static_cast<uint8_t>((i * 3 + 1) & 0xFF);
    }

    bool ok = h.send_and_wait_echo(conn, master, "pp-video/1",
                                   video_data.data(), video_data.size(),
                                   std::chrono::seconds(10));
    CHECK(ok);

    auto received = master->get_received("pp-video/1");
    CHECK(received.has_value());
    if (received) {
        CHECK(received->size() == video_data.size());
        CHECK(std::memcmp(received->data(), video_data.data(), video_data.size()) == 0);
    }
}

// ============================================================================
// 测试 3: 音频特征通道 (pp-audio/1)
// ============================================================================
static void test_audio_channel() {
    std::printf("[e2e] multimodal: audio channel (pp-audio/1)...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 47);
    auto *worker = h.start_node("worker", 0, 47);

    master->role = e2e::NodeContext::RoleEcho;

    auto *conn = h.connect_alpn(worker, master, "pp-audio/1");
    CHECK(conn != nullptr);

    // 1KB 音频特征数据
    std::vector<uint8_t> audio_data(1024);
    for (size_t i = 0; i < audio_data.size(); ++i) {
        audio_data[i] = static_cast<uint8_t>((i * 5 + 9) & 0xFF);
    }

    bool ok = h.send_and_wait_echo(conn, master, "pp-audio/1",
                                   audio_data.data(), audio_data.size(),
                                   std::chrono::seconds(10));
    CHECK(ok);

    auto received = master->get_received("pp-audio/1");
    CHECK(received.has_value());
    if (received) {
        CHECK(received->size() == audio_data.size());
        CHECK(std::memcmp(received->data(), audio_data.data(), audio_data.size()) == 0);
    }
}

// ============================================================================
// 测试 4: LLM hidden_state 通道 (pp-llm/1) 单连接模式
// ============================================================================
static void test_llm_channel() {
    std::printf("[e2e] multimodal: LLM channel (pp-llm/1)...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 47);
    auto *worker = h.start_node("worker", 0, 47);

    master->role = e2e::NodeContext::RoleEcho;

    auto *conn = h.connect_alpn(worker, master, "pp-llm/1");
    CHECK(conn != nullptr);

    // 256B hidden_state
    std::vector<uint8_t> llm_data(256);
    for (size_t i = 0; i < llm_data.size(); ++i) {
        llm_data[i] = static_cast<uint8_t>(0x55 ^ (i & 0xFF));
    }

    bool ok = h.send_and_wait_echo(conn, master, "pp-llm/1",
                                   llm_data.data(), llm_data.size(),
                                   std::chrono::seconds(10));
    CHECK(ok);

    auto received = master->get_received("pp-llm/1");
    CHECK(received.has_value());
    if (received) {
        CHECK(received->size() == llm_data.size());
        CHECK(std::memcmp(received->data(), llm_data.data(), llm_data.size()) == 0);
    }
}

// ============================================================================
// 测试 5: 多模态通道共存（3 条不同 ALPN 连接到同一 master）
// ============================================================================
static void test_multimodal_coexist() {
    std::printf("[e2e] multimodal: 3 channels coexist (img + video + audio)...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 47);
    auto *w_img = h.start_node("w_img", 0, 47);
    auto *w_video = h.start_node("w_video", 0, 47);
    auto *w_audio = h.start_node("w_audio", 0, 47);

    master->role = e2e::NodeContext::RoleEcho;

    auto *c_img = h.connect_alpn(w_img, master, "pp-img/1");
    auto *c_video = h.connect_alpn(w_video, master, "pp-video/1");
    auto *c_audio = h.connect_alpn(w_audio, master, "pp-audio/1");
    CHECK(c_img != nullptr);
    CHECK(c_video != nullptr);
    CHECK(c_audio != nullptr);

    // 依次发送各模态数据并立即验证（send_and_wait_echo 会 reset_echo 清空之前数据）
    std::vector<uint8_t> img_data(2048, 0x11);
    std::vector<uint8_t> video_data(4096, 0x22);
    std::vector<uint8_t> audio_data(512, 0x33);

    // img 通道
    CHECK(h.send_and_wait_echo(c_img, master, "pp-img/1",
                               img_data.data(), img_data.size(),
                               std::chrono::seconds(10)));
    {
        auto recv = master->get_received("pp-img/1");
        CHECK(recv.has_value());
        if (recv) {
            CHECK(recv->size() == 2048);
            CHECK((*recv)[0] == 0x11);
        }
    }

    // video 通道
    CHECK(h.send_and_wait_echo(c_video, master, "pp-video/1",
                               video_data.data(), video_data.size(),
                               std::chrono::seconds(10)));
    {
        auto recv = master->get_received("pp-video/1");
        CHECK(recv.has_value());
        if (recv) {
            CHECK(recv->size() == 4096);
            CHECK((*recv)[0] == 0x22);
        }
    }

    // audio 通道
    CHECK(h.send_and_wait_echo(c_audio, master, "pp-audio/1",
                               audio_data.data(), audio_data.size(),
                               std::chrono::seconds(10)));
    {
        auto recv = master->get_received("pp-audio/1");
        CHECK(recv.has_value());
        if (recv) {
            CHECK(recv->size() == 512);
            CHECK((*recv)[0] == 0x33);
        }
    }
}

// ============================================================================
// 测试 6: 向后兼容 pp-hidden/1 旧 ALPN
// ============================================================================
static void test_backward_compat_pp_hidden() {
    std::printf("[e2e] multimodal: backward compat pp-hidden/1...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 47);
    auto *worker = h.start_node("worker", 0, 47);

    master->role = e2e::NodeContext::RoleEcho;

    auto *conn = h.connect_alpn(worker, master, "pp-hidden/1");
    CHECK(conn != nullptr);

    std::vector<uint8_t> data(128, 0x77);

    bool ok = h.send_and_wait_echo(conn, master, "pp-hidden/1",
                                   data.data(), data.size(),
                                   std::chrono::seconds(10));
    CHECK(ok);

    auto received = master->get_received("pp-hidden/1");
    CHECK(received.has_value());
    if (received) {
        CHECK(received->size() == 128);
    }
}

int main() {
    std::printf("=== e2e_multimodal (v4.3.0 M21) ===\n");

    test_img_channel();
    test_video_channel();
    test_audio_channel();
    test_llm_channel();
    test_multimodal_coexist();
    test_backward_compat_pp_hidden();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
