// X25519 (Curve25519 ECDH) — RFC 7748.
// Direct port of TweetNaCl.c crypto_scalarmult / crypto_scalarmult_base.
// Public domain reference; validated against RFC 7748 test vectors.

#include "linoh/crypto/x25519.hpp"
#include "linoh/util/crypto.hpp"  // crypto_random_bytes

#include <cstring>

namespace linoh::crypto::x25519 {

namespace {

using i64 = int64_t;
using u8  = uint8_t;
using gf  = i64[16];

const u8 kBasePoint[32] = {9};
const gf k121665 = {0xDB41, 1};

void car25519(gf o) {
    for (int i = 0; i < 16; ++i) {
        o[i] += (1LL << 16);
        i64 c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

void sel25519(gf p, gf q, int b) {
    i64 c = ~(static_cast<i64>(b) - 1);
    for (int i = 0; i < 16; ++i) {
        i64 t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

void pack25519(u8 *o, const gf n) {
    gf m, t;
    for (int i = 0; i < 16; ++i) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; ++i) {
        o[2 * i]     = t[i] & 0xff;
        o[2 * i + 1] = t[i] >> 8;
    }
}

void unpack25519(gf o, const u8 *n) {
    for (int i = 0; i < 16; ++i) o[i] = n[2 * i] + (static_cast<i64>(n[2 * i + 1]) << 8);
    o[15] &= 0x7fff;
}

void A(gf o, const gf a, const gf b) { for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i]; }
void Z(gf o, const gf a, const gf b) { for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i]; }

void M(gf o, const gf a, const gf b) {
    i64 t[31];
    for (int i = 0; i < 31; ++i) t[i] = 0;
    for (int i = 0; i < 16; ++i)
        for (int j = 0; j < 16; ++j) t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; ++i) o[i] = t[i];
    car25519(o);
    car25519(o);
}

void S(gf o, const gf a) { M(o, a, a); }

void inv25519(gf o, const gf i) {
    gf c;
    for (int a = 0; a < 16; ++a) c[a] = i[a];
    for (int a = 253; a >= 0; --a) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    for (int a = 0; a < 16; ++a) o[a] = c[a];
}

int crypto_scalarmult(u8 *q, const u8 *n, const u8 *p) {
    u8 z[32];
    i64 x[80], r;
    gf a, b, c, d, e, f;
    for (int i = 0; i < 31; ++i) z[i] = n[i];
    z[31] = (n[31] & 127) | 64;  // clamp high bits
    z[0] &= 248;                  // clamp low bits
    unpack25519(x, p);
    for (int i = 0; i < 16; ++i) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (int i = 254; i >= 0; --i) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, static_cast<int>(r));
        sel25519(c, d, static_cast<int>(r));
        A(e, a, c);
        Z(a, a, c);
        A(c, b, d);
        Z(b, b, d);
        S(d, e);
        S(f, a);
        M(a, c, a);
        M(c, b, e);
        A(e, a, c);
        Z(a, a, c);
        S(b, a);
        Z(c, d, f);
        M(a, c, k121665);
        A(a, a, d);
        M(c, c, a);
        M(a, d, f);
        M(d, b, x);
        S(b, e);
        sel25519(a, b, static_cast<int>(r));
        sel25519(c, d, static_cast<int>(r));
    }
    for (int i = 0; i < 16; ++i) {
        x[i + 16] = a[i];
        x[i + 32] = c[i];
        x[i + 48] = b[i];
        x[i + 64] = d[i];
    }
    inv25519(x + 32, x + 32);
    M(x + 16, x + 16, x + 32);
    pack25519(q, x + 16);
    return 0;
}

} // namespace

bool scalarmult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    crypto_scalarmult(out, scalar, point);
    // RFC 7748 §6: 检查全零输出（抵挡小阶子群攻击）
    // 攻击者可构造特殊公钥使 ECDH 输出全零，从而预测会话密钥，破坏前向保密
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (out[i] != 0) { all_zero = false; break; }
    }
    if (all_zero) {
        // 全零输出视为协议失败，调用方必须中止握手
        return false;
    }
    return true;
}

void scalarmult_base(uint8_t out[32], const uint8_t scalar[32]) {
    crypto_scalarmult(out, scalar, kBasePoint);
}

bool keygen(uint8_t pk[32], uint8_t sk[32]) {
    // tc-M1 (v1.7.0.8): 检查 CSPRNG 返回值。
    //   crypto_random_bytes 失败时 sk 内容未定义（可能全零），直接 scalarmult_base
    //   会生成可预测的公钥（9*0=0），攻击者可解密所有后续流量，破坏前向保密。
    //   失败时返回 false，调用方必须中止握手。
    if (!crypto::crypto_random_bytes(std::span<uint8_t>(sk, 32))) {
        return false;
    }
    scalarmult_base(pk, sk);
    return true;
}

} // namespace linoh::crypto::x25519
