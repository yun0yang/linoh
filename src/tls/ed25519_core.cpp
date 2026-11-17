// Ed25519 implementation (RFC 8032)
// Direct port of TweetNaCl.c — public domain, well-tested reference
// Only depends on SHA-512 from linoh::crypto

#include "linoh/tls/ed25519_core.hpp"
#include "linoh/util/crypto.hpp"

#include <cstring>
#include <cstdint>
#include <vector>

namespace linoh::crypto::ed25519 {

// ============================================================================
// Types and macros
// ============================================================================

using i64 = int64_t;
using u8 = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;
using gf = i64[16];

#define FOR(i, n) for (int i = 0; i < (n); ++i)

// ============================================================================
// Constants (from TweetNaCl.c)
// ============================================================================

static const u8 _9[32] = {9};

static const gf gf0 = {};
static const gf gf1 = {1};
static const gf _121665 = {0xDB41, 1};

// D = -d = 121665/121666 mod p (precomputed field element)
static const gf D = {
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203
};

// D2 = 2*D
static const gf D2 = {
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406
};

// Base point X coordinate
static const gf X = {
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169
};

// Base point Y coordinate
static const gf Y = {
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666
};

// I = sqrt(-1) mod p
static const gf I = {
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83
};

// Group order L (for scalar reduction)
static const u64 L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x10
};

// ============================================================================
// Helper: SHA-512 wrapper (matches TweetNaCl's crypto_hash)
// ============================================================================

static void crypto_hash(u8 *out, const u8 *msg, size_t len) {
    auto h = linoh::crypto::SHA512::hash(
        std::span<const uint8_t>(msg, len));
    std::memcpy(out, h.data(), 64);
}

// ============================================================================
// Helper: constant-time comparison (from TweetNaCl's vn)
// ============================================================================

static int vn(const u8 *x, const u8 *y, int n) {
    u32 i, d = 0;
    FOR(i, n) d |= x[i] ^ y[i];
    return (1 & ((d - 1) >> 8)) - 1;
}

static int crypto_verify_32(const u8 *x, const u8 *y) {
    return vn(x, y, 32);
}

// ============================================================================
// Field arithmetic (exact port from TweetNaCl.c)
// ============================================================================

static void set25519(gf r, const gf a) {
    FOR(i, 16) r[i] = a[i];
}

static void car25519(gf o) {
    i64 c;
    FOR(i, 16) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel25519(gf p, gf q, int b) {
    i64 t, c = ~(b - 1);
    FOR(i, 16) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(u8 *o, const gf n) {
    int i, j, b;
    gf m, t;
    FOR(i, 16) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    FOR(j, 2) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    FOR(i, 16) {
        o[2 * i] = (u8)(t[i] & 0xff);
        o[2 * i + 1] = (u8)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const u8 *n) {
    int i;
    FOR(i, 16) o[i] = n[2 * i] + ((i64)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static int neq25519(const gf a, const gf b) {
    u8 c[32], d[32];
    pack25519(c, a);
    pack25519(d, b);
    return crypto_verify_32(c, d);
}

static u8 par25519(const gf a) {
    u8 d[32];
    pack25519(d, a);
    return d[0] & 1;
}

static void A(gf o, const gf a, const gf b) {
    FOR(i, 16) o[i] = a[i] + b[i];
}

static void Z(gf o, const gf a, const gf b) {
    FOR(i, 16) o[i] = a[i] - b[i];
}

static void M(gf o, const gf a, const gf b) {
    i64 i, j, t[31];
    FOR(i, 31) t[i] = 0;
    FOR(i, 16) FOR(j, 16) t[i + j] += a[i] * b[j];
    FOR(i, 15) t[i] += 38 * t[i + 16];
    FOR(i, 16) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void S(gf o, const gf a) {
    M(o, a, a);
}

static void inv25519(gf o, const gf i) {
    gf c;
    int a;
    FOR(a, 16) c[a] = i[a];
    for (a = 253; a >= 0; --a) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    FOR(a, 16) o[a] = c[a];
}

static void pow2523(gf o, const gf i) {
    gf c;
    int a;
    FOR(a, 16) c[a] = i[a];
    for (a = 250; a >= 0; --a) {
        S(c, c);
        if (a != 1) M(c, c, i);
    }
    FOR(a, 16) o[a] = c[a];
}

// ============================================================================
// Point operations (exact port from TweetNaCl.c)
// ============================================================================

// Point: p[0]=X, p[1]=Y, p[2]=Z, p[3]=T (extended twisted Edwards)

static void add(gf p[4], gf q[4]) {
    gf a, b, c, d, t, e, f, g, h;

    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, D2);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);

    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
}

static void cswap(gf p[4], gf q[4], u8 b) {
    FOR(i, 4) sel25519(p[i], q[i], b);
}

static void pack(u8 *r, gf p[4]) {
    gf tx, ty, zi;
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= par25519(tx) << 7;
}

static void scalarmult(gf p[4], gf q[4], const u8 *s) {
    int i;
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);
    for (i = 255; i >= 0; --i) {
        u8 b = (s[i / 8] >> (i & 7)) & 1;
        cswap(p, q, b);
        add(q, p);
        add(p, p);
        cswap(p, q, b);
    }
}

static void scalarbase(gf p[4], const u8 *s) {
    gf q[4];
    set25519(q[0], X);
    set25519(q[1], Y);
    set25519(q[2], gf1);
    M(q[3], X, Y);
    scalarmult(p, q, s);
}

// ============================================================================
// Scalar reduction mod L (exact port from TweetNaCl.c)
// ============================================================================

static void modL(u8 *r, i64 x[64]) {
    i64 carry, i, j;
    for (i = 63; i >= 32; --i) {
        carry = 0;
        for (j = i - 32; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    FOR(j, 32) {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    FOR(j, 32) x[j] -= carry * L[j];
    FOR(i, 32) {
        x[i + 1] += x[i] >> 8;
        r[i] = (u8)(x[i] & 255);
    }
}

static void reduce(u8 *r) {
    i64 x[64], i;
    FOR(i, 64) x[i] = (u64)r[i];
    FOR(i, 64) r[i] = 0;
    modL(r, x);
}

// ============================================================================
// Point decompression (for verification)
// ============================================================================

static int unpackneg(gf r[4], const u8 p[32]) {
    gf t, chk, num, den, den2, den4, den6;
    set25519(r[2], gf1);
    unpack25519(r[1], p);
    S(num, r[1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);

    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);

    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) M(r[0], r[0], I);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) return -1;

    if (par25519(r[0]) == (p[31] >> 7)) Z(r[0], gf0, r[0]);

    M(r[3], r[0], r[1]);
    return 0;
}

// ============================================================================
// Public API (adapted from TweetNaCl to detached signature format)
// ============================================================================

void keypair_from_seed(u8 pub[32], const u8 seed[32]) {
    u8 d[64];
    gf p[4];

    crypto_hash(d, seed, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    scalarbase(p, d);
    pack(pub, p);
}

void sign(u8 sig[64], const u8 seed[32], const u8 *message, size_t len) {
    u8 d[64], h[64], r[64], pk[32];
    i64 i, j, x[64];
    gf p[4];

    // Step 1: derive scalar from seed
    crypto_hash(d, seed, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    // Step 2: derive public key (needed for hash)
    scalarbase(p, d);
    pack(pk, p);

    // Step 3: r = reduce(SHA512(prefix || message))
    // prefix = d[32..63]
    // v1.7.0.6 (H6-1 fix): 用 std::vector 替代裸 new[]/delete[]，异常安全
    {
        std::vector<u8> buf(32 + len);
        std::memcpy(buf.data(), d + 32, 32);
        std::memcpy(buf.data() + 32, message, len);
        crypto_hash(r, buf.data(), 32 + len);
    }
    reduce(r);

    // Step 4: R = r * B
    scalarbase(p, r);
    pack(sig, p);  // sig[0..31] = R

    // Step 5: h = reduce(SHA512(R || pk || message))
    {
        std::vector<u8> buf(32 + 32 + len);
        std::memcpy(buf.data(), sig, 32);
        std::memcpy(buf.data() + 32, pk, 32);
        std::memcpy(buf.data() + 64, message, len);
        crypto_hash(h, buf.data(), 32 + 32 + len);
    }
    reduce(h);

    // Step 6: S = (r + h * a) mod L
    FOR(i, 64) x[i] = 0;
    FOR(i, 32) x[i] = (u64)r[i];
    FOR(i, 32) FOR(j, 32) x[i + j] += h[i] * (u64)d[j];
    modL(sig + 32, x);
}

bool verify(const u8 sig[64], const u8 pub[32], const u8 *message, size_t len) {
    u8 t[32], h[64];
    gf p[4], q[4];

    // tc-M2 (v1.7.0.8): RFC 8032 §8.2.3 — 验签前检查 S < L（群阶），防止签名可塑性。
    // S = sig[32..63] (little-endian), L = 群阶 (little-endian, 见 L[32])。
    // 若 S >= L，攻击者可从合法签名 (R, S) 构造 (R, S mod L + L) 同样通过验证，
    // 破坏"唯一签名"属性，影响依赖签名唯一性的上层协议。比较从最高字节开始。
    bool s_ge_l = false;
    for (int i = 31; i >= 0; --i) {
        if (sig[32 + i] != static_cast<u8>(L[i])) {
            s_ge_l = (sig[32 + i] > static_cast<u8>(L[i]));
            break;
        }
    }
    if (s_ge_l) return false;

    // Decompress public key point A
    if (unpackneg(q, pub)) return false;

    // h = reduce(SHA512(R || pub || message))
    // v1.7.0.6 (H6-1 fix): 用 std::vector 替代裸 new[]/delete[]，异常安全
    {
        std::vector<u8> buf(32 + 32 + len);
        std::memcpy(buf.data(), sig, 32);      // R
        std::memcpy(buf.data() + 32, pub, 32); // A
        std::memcpy(buf.data() + 64, message, len);
        crypto_hash(h, buf.data(), 32 + 32 + len);
    }
    reduce(h);

    // p = h * A
    scalarmult(p, q, h);

    // q = S * B
    scalarbase(q, sig + 32);

    // p = h*A + S*B
    add(p, q);

    // Check: encode(p) == R
    pack(t, p);

    // If t == sig[0..31], the signature is valid
    return crypto_verify_32(sig, t) == 0;
}

} // namespace linoh::crypto::ed25519
