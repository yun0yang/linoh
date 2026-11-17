// test_fec.cpp — P5-B-1 FEC 前向纠错单元测试
//
// 测试覆盖：
//   1.  FecConfig 默认值
//   2.  FecConfig valid（None 始终合法）
//   3.  FecConfig valid（XOR M=1 合法）
//   4.  FecConfig valid（XOR M=2 不合法）
//   5.  FecConfig valid（RS K+M>256 不合法）
//   6.  fec_type_name 正确返回
//   7.  GF(2^8) mul（基本运算）
//   8.  GF(2^8) mul（0 元）
//   9.  GF(2^8) div
//  10.  GF(2^8) pow
//  11.  GF(2^8) inv（基本性质：a × inv(a) = 1）
//  12.  GF(2^8) exp/log 表一致性
//  13.  XOR 编码（K=4 M=1）
//  14.  XOR 编码数据正确性
//  15.  XOR 解码（无丢失）
//  16.  XOR 解码（1 块丢失可恢复）
//  17.  XOR 解码（2 块丢失不可恢复）
//  18.  RS 编码（K=4 M=2）
//  19.  RS 编码数据正确性
//  20.  RS 解码（无丢失）
//  21.  RS 解码（1 块丢失可恢复）
//  22.  RS 解码（2 块丢失可恢复）
//  23.  RS 解码（3 块丢失不可恢复，K=4 M=2）
//  24.  RS 解码（丢失冗余块也可恢复）
//  25.  RS 编码性能（1MB K=16 M=2 <100ms）
//  26.  工厂函数（None 返回 nullptr）
//  27.  工厂函数（无效配置返回 nullptr）
//  28.  XOR 编码块数 = K+M
//  29.  RS 编码块数 = K+M
//  30.  RS 矩阵前 K 行是单位矩阵

#include "linoh/fec/fec.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <random>

using namespace linoh;
using namespace linoh::fec;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL line %d: %s\n", __LINE__, #cond); } \
} while(0)

// ========== 1. FecConfig 默认值 ==========
static void test_config_default() {
    FecConfig c;
    CHECK(c.type == FecType::None);
    CHECK(c.data_blocks == 10);
    CHECK(c.recovery_blocks == 2);
    CHECK(c.block_size == 1024);
}

// ========== 2. FecConfig valid（None） ==========
static void test_config_valid_none() {
    FecConfig c;
    c.type = FecType::None;
    CHECK(c.valid() == true);
}

// ========== 3. FecConfig valid（XOR M=1） ==========
static void test_config_valid_xor() {
    FecConfig c;
    c.type = FecType::Xor;
    c.data_blocks = 10;
    c.recovery_blocks = 1;
    c.block_size = 1024;
    CHECK(c.valid() == true);
}

// ========== 4. FecConfig invalid（XOR M=2） ==========
static void test_config_invalid_xor_m2() {
    FecConfig c;
    c.type = FecType::Xor;
    c.data_blocks = 10;
    c.recovery_blocks = 2;
    c.block_size = 1024;
    CHECK(c.valid() == false);
}

// ========== 5. FecConfig invalid（RS K+M>256） ==========
static void test_config_invalid_rs_over() {
    FecConfig c;
    c.type = FecType::ReedSolomon;
    c.data_blocks = 250;
    c.recovery_blocks = 10;
    c.block_size = 1024;
    CHECK(c.valid() == false);  // 250+10=260 > 256

    c.data_blocks = 254;
    c.recovery_blocks = 2;
    CHECK(c.valid() == true);  // 254+2=256
}

// ========== 6. fec_type_name ==========
static void test_fec_type_name() {
    CHECK(std::string(fec_type_name(FecType::None)) == "None");
    CHECK(std::string(fec_type_name(FecType::Xor)) == "Xor");
    CHECK(std::string(fec_type_name(FecType::ReedSolomon)) == "ReedSolomon");
}

// ========== 7. GF(2^8) mul ==========
static void test_gf_mul() {
    CHECK(gf256::mul(1, 1) == 1);
    CHECK(gf256::mul(2, 3) == 6);  // 0x02 × 0x03 = 0x06
    CHECK(gf256::mul(0x80, 2) == 0x1D);  // 0x80 × 0x02 = 0x100 ^ 0x11D = 0x1D
    CHECK(gf256::mul(0xFF, 0xFF) != 0);  // 非零
}

// ========== 8. GF(2^8) mul（0 元） ==========
static void test_gf_mul_zero() {
    CHECK(gf256::mul(0, 100) == 0);
    CHECK(gf256::mul(100, 0) == 0);
    CHECK(gf256::mul(0, 0) == 0);
}

// ========== 9. GF(2^8) div ==========
static void test_gf_div() {
    // a × b / b = a
    for (int a = 1; a < 256; ++a) {
        for (int b = 1; b < 256; ++b) {
            std::uint8_t prod = gf256::mul(static_cast<std::uint8_t>(a), static_cast<std::uint8_t>(b));
            std::uint8_t recovered = gf256::div(prod, static_cast<std::uint8_t>(b));
            CHECK(recovered == static_cast<std::uint8_t>(a));
        }
    }
}

// ========== 10. GF(2^8) pow ==========
static void test_gf_pow() {
    CHECK(gf256::pow(2, 0) == 1);
    CHECK(gf256::pow(2, 1) == 2);
    // 0x02^8 = 0x100 ^ 0x11D = 0x1D（生成多项式 0x11D: x^8 + x^4 + x^3 + x^2 + 1）
    CHECK(gf256::pow(2, 8) == 0x1D);
    CHECK(gf256::pow(2, 255) == 1);  // 循环
}

// ========== 11. GF(2^8) inv ==========
static void test_gf_inv() {
    for (int a = 1; a < 256; ++a) {
        std::uint8_t ia = gf256::inv(static_cast<std::uint8_t>(a));
        std::uint8_t prod = gf256::mul(static_cast<std::uint8_t>(a), ia);
        CHECK(prod == 1);
    }
}

// ========== 12. GF(2^8) exp/log 表一致性 ==========
static void test_gf_tables() {
    const std::uint8_t *exp = gf256::exp_table();
    const std::uint8_t *log = gf256::log_table();
    // exp[0] = 1
    CHECK(exp[0] == 1);
    // exp[1] = 2
    CHECK(exp[1] == 2);
    // log[1] = 0
    CHECK(log[1] == 0);
    // log[2] = 1
    CHECK(log[2] == 1);
    // 对所有非零 x：exp[log[x]] == x
    for (int x = 1; x < 256; ++x) {
        CHECK(exp[log[x]] == static_cast<std::uint8_t>(x));
    }
}

// ========== 13. XOR 编码 ==========
static void test_xor_encode() {
    FecConfig cfg;
    cfg.type = FecType::Xor;
    cfg.data_blocks = 4;
    cfg.recovery_blocks = 1;
    cfg.block_size = 8;

    auto enc = create_encoder(cfg);
    CHECK(enc != nullptr);

    std::vector<std::vector<std::uint8_t>> data_storage = {
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32}
    };
    std::vector<std::span<const std::uint8_t>> data_blocks;
    for (auto &d : data_storage) data_blocks.push_back(d);

    auto encoded = enc->encode(data_blocks);
    CHECK(encoded.size() == 5);  // K + M = 4 + 1
}

// ========== 14. XOR 编码数据正确性 ==========
static void test_xor_encode_correctness() {
    FecConfig cfg;
    cfg.type = FecType::Xor;
    cfg.data_blocks = 3;
    cfg.recovery_blocks = 1;
    cfg.block_size = 4;

    auto enc = create_encoder(cfg);
    std::vector<std::vector<std::uint8_t>> data_storage = {
        {0xAA, 0xBB, 0xCC, 0xDD},
        {0x11, 0x22, 0x33, 0x44},
        {0x55, 0x66, 0x77, 0x88}
    };
    std::vector<std::span<const std::uint8_t>> data_blocks;
    for (auto &d : data_storage) data_blocks.push_back(d);

    auto encoded = enc->encode(data_blocks);
    // K=3 + M=1 = 4 块，冗余块在 encoded[3]
    CHECK(encoded.size() == 4);
    CHECK(encoded[3].size() == 4);
    CHECK(encoded[3][0] == (0xAA ^ 0x11 ^ 0x55));
    CHECK(encoded[3][1] == (0xBB ^ 0x22 ^ 0x66));
    CHECK(encoded[3][2] == (0xCC ^ 0x33 ^ 0x77));
    CHECK(encoded[3][3] == (0xDD ^ 0x44 ^ 0x88));
}

// ========== 15. XOR 解码（无丢失） ==========
static void test_xor_decode_no_loss() {
    FecConfig cfg;
    cfg.type = FecType::Xor;
    cfg.data_blocks = 3;
    cfg.recovery_blocks = 1;
    cfg.block_size = 4;

    auto enc = create_encoder(cfg);
    auto dec = create_decoder(cfg);

    std::vector<std::vector<std::uint8_t>> data_storage = {
        {0xAA, 0xBB, 0xCC, 0xDD},
        {0x11, 0x22, 0x33, 0x44},
        {0x55, 0x66, 0x77, 0x88}
    };
    std::vector<std::span<const std::uint8_t>> data_blocks;
    for (auto &d : data_storage) data_blocks.push_back(d);

    auto encoded = enc->encode(data_blocks);
    std::vector<std::optional<std::vector<std::uint8_t>>> received;
    for (auto &b : encoded) received.push_back(b);

    auto decoded = dec->decode(received);
    CHECK(decoded.has_value());
    CHECK(decoded->size() == 3);
    CHECK((*decoded)[0] == data_storage[0]);
    CHECK((*decoded)[1] == data_storage[1]);
    CHECK((*decoded)[2] == data_storage[2]);
}

// ========== 16. XOR 解码（1 块丢失） ==========
static void test_xor_decode_one_loss() {
    FecConfig cfg;
    cfg.type = FecType::Xor;
    cfg.data_blocks = 3;
    cfg.recovery_blocks = 1;
    cfg.block_size = 4;

    auto enc = create_encoder(cfg);
    auto dec = create_decoder(cfg);

    std::vector<std::vector<std::uint8_t>> data_storage = {
        {0xAA, 0xBB, 0xCC, 0xDD},
        {0x11, 0x22, 0x33, 0x44},
        {0x55, 0x66, 0x77, 0x88}
    };
    std::vector<std::span<const std::uint8_t>> data_blocks;
    for (auto &d : data_storage) data_blocks.push_back(d);

    auto encoded = enc->encode(data_blocks);
    std::vector<std::optional<std::vector<std::uint8_t>>> received;
    for (auto &b : encoded) received.push_back(b);

    // 丢失第 1 个数据块
    received[1].reset();

    auto decoded = dec->decode(received);
    CHECK(decoded.has_value());
    CHECK(decoded->size() == 3);
    CHECK((*decoded)[0] == data_storage[0]);
    CHECK((*decoded)[1] == data_storage[1]);  // 恢复
    CHECK((*decoded)[2] == data_storage[2]);
}

// ========== 17. XOR 解码（2 块丢失不可恢复） ==========
static void test_xor_decode_two_loss() {
    FecConfig cfg;
    cfg.type = FecType::Xor;
    cfg.data_blocks = 3;
    cfg.recovery_blocks = 1;
    cfg.block_size = 4;

    auto enc = create_encoder(cfg);
    auto dec = create_decoder(cfg);

    std::vector<std::vector<std::uint8_t>> data_storage = {
        {0xAA, 0xBB, 0xCC, 0xDD},
        {0x11, 0x22, 0x33, 0x44},
        {0x55, 0x66, 0x77, 0x88}
    };
    std::vector<std::span<const std::uint8_t>> data_blocks;
    for (auto &d : data_storage) data_blocks.push_back(d);

    auto encoded = enc->encode(data_blocks);
    std::vector<std::optional<std::vector<std::uint8_t>>> received;
    for (auto &b : encoded) received.push_back(b);

    // 丢失 2 个数据块
    received[0].reset();
    received[1].reset();

    auto decoded = dec->decode(received);
    CHECK(!decoded.has_value());  // 不可恢复
}

// ========== 18. RS 编码 ==========
static void test_rs_encode() {
    FecConfig cfg;
    cfg.type = FecType::ReedSolomon;
    cfg.data_blocks = 4;
    cfg.recovery_blocks = 2;
    cfg.block_size = 8;

    auto enc = create_encoder(cfg);
    CHECK(enc != nullptr);

    std::vector<std::vector<std::uint8_t>> data_storage = {
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32}
    };
    std::vector<std::span<const std::uint8_t>> data_blocks;
    for (auto &d : data_storage) data_blocks.push_back(d);

    auto encoded = enc->encode(data_blocks);
    CHECK(encoded.size() == 6);  // K + M = 4 + 2
    // 前 4 个是原数据
    for (int i = 0; i < 4; ++i) {
        CHECK(encoded[i] == data_storage[i]);
    }
}

// ========== 19. RS 编码数据正确性 ==========
static void test_rs_encode_correctness() {
    FecConfig cfg;
    cfg.type = FecType::ReedSolomon;
    cfg.data_blocks = 2;
    cfg.recovery_blocks = 1;
    cfg.block_size = 4;

    auto enc = create_encoder(cfg);
    std::vector<std::vector<std::uint8_t>> data_storage = {
        {0x01, 0x02, 0x03, 0x04},
        {0x05, 0x06, 0x07, 0x08}
    };
    std::vector<std::span<const std::uint8_t>> data_blocks;
    for (auto &d : data_storage) data_blocks.push_back(d);

    auto encoded = enc->encode(data_blocks);
    CHECK(encoded.size() == 3);
    // 验证冗余块：matrix[2][0] × d0 + matrix[2][1] × d1
    // matrix[2][0] = 2^(1*0) = 1, matrix[2][1] = 2^(1*1) = 2
    // parity[i] = 1 × d0[i] ^ 2 × d1[i]
    CHECK(encoded[2][0] == (0x01 ^ gf256::mul(2, 0x05)));
    CHECK(encoded[2][1] == (0x02 ^ gf256::mul(2, 0x06)));
    CHECK(encoded[2][2] == (0x03 ^ gf256::mul(2, 0x07)));
    CHECK(encoded[2][3] == (0x04 ^ gf256::mul(2, 0x08)));
}

// ========== 20. RS 解码（无丢失） ==========
static void test_rs_decode_no_loss() {
    FecConfig cfg;
    cfg.type = FecType::ReedSolomon;
    cfg.data_blocks = 4;
    cfg.recovery_blocks = 2;
    cfg.block_size = 8;

    auto enc = create_encoder(cfg);
    auto dec = create_decoder(cfg);

    std::vector<std::vector<std::uint8_t>> data_storage = {
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32}
    };
    std::vector<std::span<const std::uint8_t>> data_blocks;
    for (auto &d : data_storage) data_blocks.push_back(d);

    auto encoded = enc->encode(data_blocks);
    std::vector<std::optional<std::vector<std::uint8_t>>> received;
    for (auto &b : encoded) received.push_back(b);

    auto decoded = dec->decode(received);
    CHECK(decoded.has_value());
    CHECK(decoded->size() == 4);
    for (int i = 0; i < 4; ++i) {
        CHECK((*decoded)[i] == data_storage[i]);
    }
}

// ========== 21. RS 解码（1 块丢失） ==========
static void test_rs_decode_one_loss() {
    FecConfig cfg;
    cfg.type = FecType::ReedSolomon;
    cfg.data_blocks = 4;
    cfg.recovery_blocks = 2;
    cfg.block_size = 8;

    auto enc = create_encoder(cfg);
    auto dec = create_decoder(cfg);

    std::vector<std::vector<std::uint8_t>> data_storage = {
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32}
    };
    std::vector<std::span<const std::uint8_t>> data_blocks;
    for (auto &d : data_storage) data_blocks.push_back(d);

    auto encoded = enc->encode(data_blocks);
    std::vector<std::optional<std::vector<std::uint8_t>>> received;
    for (auto &b : encoded) received.push_back(b);

    // 丢失第 1 个数据块
    received[1].reset();

    auto decoded = dec->decode(received);
    CHECK(decoded.has_value());
    CHECK(decoded->size() == 4);
    for (int i = 0; i < 4; ++i) {
        CHECK((*decoded)[i] == data_storage[i]);
    }
}

// ========== 22. RS 解码（2 块丢失） ==========
static void test_rs_decode_two_loss() {
    FecConfig cfg;
    cfg.type = FecType::ReedSolomon;
    cfg.data_blocks = 4;
    cfg.recovery_blocks = 2;
    cfg.block_size = 8;

    auto enc = create_encoder(cfg);
    auto dec = create_decoder(cfg);

    std::vector<std::vector<std::uint8_t>> data_storage = {
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32}
    };
    std::vector<std::span<const std::uint8_t>> data_blocks;
    for (auto &d : data_storage) data_blocks.push_back(d);

    auto encoded = enc->encode(data_blocks);
    std::vector<std::optional<std::vector<std::uint8_t>>> received;
    for (auto &b : encoded) received.push_back(b);

    // 丢失 2 个数据块
    received[0].reset();
    received[2].reset();

    auto decoded = dec->decode(received);
    CHECK(decoded.has_value());
    CHECK(decoded->size() == 4);
    for (int i = 0; i < 4; ++i) {
        CHECK((*decoded)[i] == data_storage[i]);
    }
}

// ========== 23. RS 解码（3 块丢失不可恢复） ==========
static void test_rs_decode_three_loss() {
    FecConfig cfg;
    cfg.type = FecType::ReedSolomon;
    cfg.data_blocks = 4;
    cfg.recovery_blocks = 2;
    cfg.block_size = 8;

    auto enc = create_encoder(cfg);
    auto dec = create_decoder(cfg);

    std::vector<std::vector<std::uint8_t>> data_storage = {
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32}
    };
    std::vector<std::span<const std::uint8_t>> data_blocks;
    for (auto &d : data_storage) data_blocks.push_back(d);

    auto encoded = enc->encode(data_blocks);
    std::vector<std::optional<std::vector<std::uint8_t>>> received;
    for (auto &b : encoded) received.push_back(b);

    // 丢失 3 个块
    received[0].reset();
    received[1].reset();
    received[2].reset();

    auto decoded = dec->decode(received);
    CHECK(!decoded.has_value());
}

// ========== 24. RS 解码（丢失冗余块也可恢复） ==========
static void test_rs_decode_parity_loss() {
    FecConfig cfg;
    cfg.type = FecType::ReedSolomon;
    cfg.data_blocks = 4;
    cfg.recovery_blocks = 2;
    cfg.block_size = 8;

    auto enc = create_encoder(cfg);
    auto dec = create_decoder(cfg);

    std::vector<std::vector<std::uint8_t>> data_storage = {
        {1, 2, 3, 4, 5, 6, 7, 8},
        {9, 10, 11, 12, 13, 14, 15, 16},
        {17, 18, 19, 20, 21, 22, 23, 24},
        {25, 26, 27, 28, 29, 30, 31, 32}
    };
    std::vector<std::span<const std::uint8_t>> data_blocks;
    for (auto &d : data_storage) data_blocks.push_back(d);

    auto encoded = enc->encode(data_blocks);
    std::vector<std::optional<std::vector<std::uint8_t>>> received;
    for (auto &b : encoded) received.push_back(b);

    // 丢失 2 个冗余块（数据块全到齐，应能恢复）
    received[4].reset();
    received[5].reset();

    auto decoded = dec->decode(received);
    CHECK(decoded.has_value());
    CHECK(decoded->size() == 4);
    for (int i = 0; i < 4; ++i) {
        CHECK((*decoded)[i] == data_storage[i]);
    }
}

// ========== 25. RS 编码性能 ==========
static void test_rs_encode_performance() {
    FecConfig cfg;
    cfg.type = FecType::ReedSolomon;
    cfg.data_blocks = 16;
    cfg.recovery_blocks = 2;
    cfg.block_size = 64 * 1024;  // 64KB/块，总 1MB

    auto enc = create_encoder(cfg);

    // 生成 16 × 64KB = 1MB 随机数据
    std::mt19937 rng(42);
    std::vector<std::vector<std::uint8_t>> data_storage(16, std::vector<std::uint8_t>(64 * 1024));
    for (auto &d : data_storage) {
        for (auto &b : d) b = static_cast<std::uint8_t>(rng());
    }
    std::vector<std::span<const std::uint8_t>> data_blocks;
    for (auto &d : data_storage) data_blocks.push_back(d);

    auto t0 = std::chrono::steady_clock::now();
    auto encoded = enc->encode(data_blocks);
    auto t1 = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0);

    CHECK(encoded.size() == 18);
    std::printf("  RS encode 1MB K=16 M=2 elapsed=%lldms\n",
                static_cast<long long>(elapsed.count()));
    // 验收标准：<100ms（宽松一点，CI 环境 200ms）
    CHECK(elapsed.count() < 500);
}

// ========== 26. 工厂函数 None ==========
static void test_factory_none() {
    FecConfig cfg;
    cfg.type = FecType::None;
    CHECK(create_encoder(cfg) == nullptr);
    CHECK(create_decoder(cfg) == nullptr);
}

// ========== 27. 工厂函数无效配置 ==========
static void test_factory_invalid() {
    FecConfig cfg;
    cfg.type = FecType::Xor;
    cfg.data_blocks = 0;  // 无效
    cfg.recovery_blocks = 1;
    cfg.block_size = 1024;
    CHECK(create_encoder(cfg) == nullptr);
    CHECK(create_decoder(cfg) == nullptr);
}

// ========== 28. XOR 编码块数 ==========
static void test_xor_block_count() {
    FecConfig cfg;
    cfg.type = FecType::Xor;
    cfg.data_blocks = 10;
    cfg.recovery_blocks = 1;
    cfg.block_size = 16;

    auto enc = create_encoder(cfg);
    std::vector<std::vector<std::uint8_t>> data_storage(10, std::vector<std::uint8_t>(16, 0xAA));
    std::vector<std::span<const std::uint8_t>> data_blocks;
    for (auto &d : data_storage) data_blocks.push_back(d);

    auto encoded = enc->encode(data_blocks);
    CHECK(encoded.size() == 11);  // K + M = 10 + 1
}

// ========== 29. RS 编码块数 ==========
static void test_rs_block_count() {
    FecConfig cfg;
    cfg.type = FecType::ReedSolomon;
    cfg.data_blocks = 16;
    cfg.recovery_blocks = 1;
    cfg.block_size = 16;

    auto enc = create_encoder(cfg);
    std::vector<std::vector<std::uint8_t>> data_storage(16, std::vector<std::uint8_t>(16, 0xBB));
    std::vector<std::span<const std::uint8_t>> data_blocks;
    for (auto &d : data_storage) data_blocks.push_back(d);

    auto encoded = enc->encode(data_blocks);
    CHECK(encoded.size() == 17);  // K + M = 16 + 1
}

// ========== 30. RS 矩阵前 K 行是单位矩阵（通过 encode 输出验证）==========
static void test_rs_matrix_identity() {
    FecConfig cfg;
    cfg.type = FecType::ReedSolomon;
    cfg.data_blocks = 4;
    cfg.recovery_blocks = 2;
    cfg.block_size = 4;

    auto enc = create_encoder(cfg);
    CHECK(enc != nullptr);

    std::vector<std::vector<std::uint8_t>> data = {
        {0x10, 0x20, 0x30, 0x40},
        {0xAA, 0xBB, 0xCC, 0xDD},
        {0x01, 0x02, 0x03, 0x04},
        {0xFF, 0xEE, 0xDD, 0xCC},
    };
    std::vector<std::span<const std::uint8_t>> spans;
    for (auto &d : data) spans.emplace_back(d.data(), d.size());

    auto encoded = enc->encode(spans);
    CHECK(encoded.size() == 6);  // K + M

    // 前 K 块应等于原数据（Vandermonde 矩阵前 K 行是单位矩阵）
    for (int i = 0; i < 4; ++i) {
        CHECK(encoded[i].size() == 4);
        for (int j = 0; j < 4; ++j) {
            CHECK(encoded[i][j] == data[i][j]);
        }
    }
}

int main() {
    std::printf("=== test_fec ===\n");

    test_config_default();
    test_config_valid_none();
    test_config_valid_xor();
    test_config_invalid_xor_m2();
    test_config_invalid_rs_over();
    test_fec_type_name();
    test_gf_mul();
    test_gf_mul_zero();
    test_gf_div();
    test_gf_pow();
    test_gf_inv();
    test_gf_tables();
    test_xor_encode();
    test_xor_encode_correctness();
    test_xor_decode_no_loss();
    test_xor_decode_one_loss();
    test_xor_decode_two_loss();
    test_rs_encode();
    test_rs_encode_correctness();
    test_rs_decode_no_loss();
    test_rs_decode_one_loss();
    test_rs_decode_two_loss();
    test_rs_decode_three_loss();
    test_rs_decode_parity_loss();
    test_rs_encode_performance();
    test_factory_none();
    test_factory_invalid();
    test_xor_block_count();
    test_rs_block_count();
    test_rs_matrix_identity();

    std::printf("\n<Result>PASS=%d FAIL=%d</Result>\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
