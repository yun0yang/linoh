// 自定义加密实现 - SHA-256, HMAC-SHA256, ChaCha20, AEAD
// 不依赖 OpenSSL
#include "linoh/util/crypto.hpp"

#include <algorithm>
#include <cstring>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
extern "C" {
    typedef long NTSTATUS;
    NTSTATUS WINAPI BCryptGenRandom(void*, unsigned char*, unsigned long, unsigned long);
}
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#else
#include <random>
#endif

namespace linoh::crypto {

// ============================================================================
// Helpers
// ============================================================================
inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

inline uint32_t load32_le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline void store32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF); p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF); p[3] = (uint8_t)((v >> 24) & 0xFF);
}
inline void store64_le(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) { p[i] = (uint8_t)(v & 0xFF); v >>= 8; }
}

// ============================================================================
// SHA-256
// ============================================================================
SHA256::SHA256() {
    state_[0] = 0x6a09e667; state_[1] = 0xbb67ae85; state_[2] = 0x3c6ef372;
    state_[3] = 0xa54ff53a; state_[4] = 0x510e527f; state_[5] = 0x9b05688c;
    state_[6] = 0x1f83d9ab; state_[7] = 0x5be0cd19;
    buffer_.fill(0); buffer_len_ = 0; bit_count_ = 0;
}

void SHA256::update(std::span<const uint8_t> data) {
    for (auto byte : data) {
        buffer_[buffer_len_++] = byte;
        if (buffer_len_ == 64) {
            transform(buffer_.data());
            bit_count_ += 512;
            buffer_len_ = 0;
        }
    }
}

void SHA256::transform(const uint8_t* block) {
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    for (int i = 0; i < 16; ++i) {
        m[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(m[i-15], 7) ^ rotr32(m[i-15], 18) ^ (m[i-15] >> 3);
        uint32_t s1 = rotr32(m[i-2], 17) ^ rotr32(m[i-2], 19) ^ (m[i-2] >> 10);
        m[i] = m[i-16] + s0 + m[i-7] + s1;
    }
    a = state_[0]; b = state_[1]; c = state_[2]; d = state_[3];
    e = state_[4]; f = state_[5]; g = state_[6]; h = state_[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + k[i] + m[i];
        uint32_t S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
}

std::array<uint8_t, SHA256::kDigestSize> SHA256::finalize() {
    uint64_t total_bits = bit_count_ + (uint64_t)buffer_len_ * 8;
    buffer_[buffer_len_++] = 0x80;
    if (buffer_len_ > 56) {
        while (buffer_len_ < 64) buffer_[buffer_len_++] = 0;
        transform(buffer_.data());
        buffer_len_ = 0;
    }
    while (buffer_len_ < 56) buffer_[buffer_len_++] = 0;
    for (int i = 7; i >= 0; --i) {
        buffer_[buffer_len_++] = (uint8_t)((total_bits >> (i * 8)) & 0xFF);
    }
    transform(buffer_.data());
    std::array<uint8_t, kDigestSize> out;
    for (int i = 0; i < 8; ++i) {
        out[i*4+0] = (uint8_t)((state_[i] >> 24) & 0xFF);
        out[i*4+1] = (uint8_t)((state_[i] >> 16) & 0xFF);
        out[i*4+2] = (uint8_t)((state_[i] >> 8) & 0xFF);
        out[i*4+3] = (uint8_t)(state_[i] & 0xFF);
    }
    return out;
}

std::array<uint8_t, SHA256::kDigestSize> SHA256::hash(std::span<const uint8_t> data) {
    SHA256 h; h.update(data); return h.finalize();
}

// ============================================================================
// SHA-512
// ============================================================================
inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

SHA512::SHA512() {
    state_[0] = 0x6a09e667f3bcc908ULL; state_[1] = 0xbb67ae8584caa73bULL;
    state_[2] = 0x3c6ef372fe94f82bULL; state_[3] = 0xa54ff53a5f1d36f1ULL;
    state_[4] = 0x510e527fade682d1ULL; state_[5] = 0x9b05688c2b3e6c1fULL;
    state_[6] = 0x1f83d9abfb41bd6bULL; state_[7] = 0x5be0cd19137e2179ULL;
    buffer_.fill(0); buffer_len_ = 0; bit_count_lo_ = 0; bit_count_hi_ = 0;
}

void SHA512::update(std::span<const uint8_t> data) {
    for (auto byte : data) {
        buffer_[buffer_len_++] = byte;
        if (buffer_len_ == kBlockSize) {
            transform(buffer_.data());
            // increment 128-bit counter
            bit_count_lo_ += 1024;
            if (bit_count_lo_ < 1024) bit_count_hi_++;
            buffer_len_ = 0;
        }
    }
}

void SHA512::transform(const uint8_t *block) {
    static const uint64_t k[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };
    uint64_t a, b, c, d, e, f, g, h, t1, t2;
    uint64_t w[80];

    // Load first 16 words (big-endian)
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint64_t)block[i*8]   << 56) | ((uint64_t)block[i*8+1] << 48) |
               ((uint64_t)block[i*8+2] << 40) | ((uint64_t)block[i*8+3] << 32) |
               ((uint64_t)block[i*8+4] << 24) | ((uint64_t)block[i*8+5] << 16) |
               ((uint64_t)block[i*8+6] << 8)  |  (uint64_t)block[i*8+7];
    }
    // Extend to 80 words
    for (int i = 16; i < 80; ++i) {
        uint64_t s0 = rotr64(w[i-15], 1) ^ rotr64(w[i-15], 8) ^ (w[i-15] >> 7);
        uint64_t s1 = rotr64(w[i-2], 19) ^ rotr64(w[i-2], 61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    a = state_[0]; b = state_[1]; c = state_[2]; d = state_[3];
    e = state_[4]; f = state_[5]; g = state_[6]; h = state_[7];

    for (int i = 0; i < 80; ++i) {
        uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + k[i] + w[i];
        uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }

    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
}

std::array<uint8_t, SHA512::kDigestSize> SHA512::finalize() {
    // total bits = bit_count + buffer_len * 8
    uint64_t total_lo = bit_count_lo_ + (uint64_t)buffer_len_ * 8;
    uint64_t total_hi = bit_count_hi_;
    if (total_lo < bit_count_lo_) total_hi++;

    // Append 0x80
    buffer_[buffer_len_++] = 0x80;
    // Pad to 112 mod 128 (then 16 bytes for length)
    if (buffer_len_ > 112) {
        while (buffer_len_ < 128) buffer_[buffer_len_++] = 0;
        transform(buffer_.data());
        buffer_len_ = 0;
    }
    while (buffer_len_ < 112) buffer_[buffer_len_++] = 0;

    // Append 128-bit length (big-endian)
    for (int i = 7; i >= 0; --i)
        buffer_[buffer_len_++] = (uint8_t)((total_hi >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i)
        buffer_[buffer_len_++] = (uint8_t)((total_lo >> (i * 8)) & 0xFF);

    transform(buffer_.data());

    std::array<uint8_t, kDigestSize> out;
    for (int i = 0; i < 8; ++i) {
        out[i*8+0] = (uint8_t)((state_[i] >> 56) & 0xFF);
        out[i*8+1] = (uint8_t)((state_[i] >> 48) & 0xFF);
        out[i*8+2] = (uint8_t)((state_[i] >> 40) & 0xFF);
        out[i*8+3] = (uint8_t)((state_[i] >> 32) & 0xFF);
        out[i*8+4] = (uint8_t)((state_[i] >> 24) & 0xFF);
        out[i*8+5] = (uint8_t)((state_[i] >> 16) & 0xFF);
        out[i*8+6] = (uint8_t)((state_[i] >> 8) & 0xFF);
        out[i*8+7] = (uint8_t)(state_[i] & 0xFF);
    }
    return out;
}

std::array<uint8_t, SHA512::kDigestSize> SHA512::hash(std::span<const uint8_t> data) {
    SHA512 h; h.update(data); return h.finalize();
}

// ============================================================================
// HMAC-SHA256
// ============================================================================
std::array<uint8_t, HMAC_SHA256::kDigestSize> HMAC_SHA256::compute(
    std::span<const uint8_t> key, std::span<const uint8_t> msg)
{
    std::array<uint8_t, 64> key_pad;
    key_pad.fill(0);
    if (key.size() > 64) {
        auto khash = SHA256::hash(key);
        std::memcpy(key_pad.data(), khash.data(), 32);
    } else {
        std::memcpy(key_pad.data(), key.data(), key.size());
    }
    std::array<uint8_t, 64> ipad, opad;
    for (int i = 0; i < 64; ++i) {
        ipad[i] = key_pad[i] ^ 0x36;
        opad[i] = key_pad[i] ^ 0x5c;
    }
    SHA256 inner;
    inner.update(std::span<const uint8_t>(ipad.data(), 64));
    inner.update(msg);
    auto ih = inner.finalize();

    SHA256 outer;
    outer.update(std::span<const uint8_t>(opad.data(), 64));
    outer.update(std::span<const uint8_t>(ih.data(), ih.size()));
    return outer.finalize();
}

// ============================================================================
// ChaCha20
// ============================================================================
void ChaCha20::block(std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                       uint32_t counter, std::span<uint8_t> out_block) {
    const char* const_k = "expand 32-byte k";
    uint32_t state[16];
    state[0] = (uint32_t)const_k[0] | ((uint32_t)const_k[1] << 8) | ((uint32_t)const_k[2] << 16) | ((uint32_t)const_k[3] << 24);
    state[1] = (uint32_t)const_k[4] | ((uint32_t)const_k[5] << 8) | ((uint32_t)const_k[6] << 16) | ((uint32_t)const_k[7] << 24);
    state[2] = (uint32_t)const_k[8] | ((uint32_t)const_k[9] << 8) | ((uint32_t)const_k[10] << 16) | ((uint32_t)const_k[11] << 24);
    state[3] = (uint32_t)const_k[12] | ((uint32_t)const_k[13] << 8) | ((uint32_t)const_k[14] << 16) | ((uint32_t)const_k[15] << 24);
    state[4]  = load32_le(key.data());
    state[5]  = load32_le(key.data() + 4);
    state[6]  = load32_le(key.data() + 8);
    state[7]  = load32_le(key.data() + 12);
    state[8]  = load32_le(key.data() + 16);
    state[9]  = load32_le(key.data() + 20);
    state[10] = load32_le(key.data() + 24);
    state[11] = load32_le(key.data() + 28);
    state[12] = counter;
    state[13] = load32_le(nonce.data());
    state[14] = load32_le(nonce.data() + 4);
    state[15] = load32_le(nonce.data() + 8);

    uint32_t work[16];
    std::memcpy(work, state, sizeof(work));

    for (int round = 0; round < 10; ++round) {
#define QR(a, b, c, d) \
        work[a] += work[b]; work[d] ^= work[a]; work[d] = rotl32(work[d], 16); \
        work[c] += work[d]; work[b] ^= work[c]; work[b] = rotl32(work[b], 12); \
        work[a] += work[b]; work[d] ^= work[a]; work[d] = rotl32(work[d], 8); \
        work[c] += work[d]; work[b] ^= work[c]; work[b] = rotl32(work[b], 7);
        QR(0, 4, 8, 12); QR(1, 5, 9, 13); QR(2, 6, 10, 14); QR(3, 7, 11, 15);
        QR(0, 5, 10, 15); QR(1, 6, 11, 12); QR(2, 7, 8, 13); QR(3, 4, 9, 14);
#undef QR
    }
    for (int i = 0; i < 16; ++i) {
        store32_le(out_block.data() + i * 4, work[i] + state[i]);
    }
}

void ChaCha20::process(std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                        std::span<uint8_t> data, uint32_t counter) {
    uint8_t block_buf[64];
    std::size_t offset = 0;
    while (offset < data.size()) {
        ChaCha20::block(key, nonce, counter++,
                         std::span<uint8_t>(block_buf, 64));
        std::size_t to_xor = data.size() - offset;
        if (to_xor > 64) to_xor = 64;
        for (std::size_t j = 0; j < to_xor; ++j) {
            data[offset + j] ^= block_buf[j];
        }
        offset += to_xor;
    }
}

void ChaCha20::process(std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                        std::span<const uint8_t> input, std::span<uint8_t> output,
                        uint32_t counter) {
    std::copy(input.begin(), input.end(), output.begin());
    ChaCha20::process(key, nonce, output, counter);
}

// ============================================================================
// Poly1305 - RFC 7539 (real implementation, 5x26-bit limbs)
// ============================================================================
namespace {

// Load 16 bytes as little-endian limbs: h0(26) h1(26) h2(26) h3(26) h4(22)
inline void poly_load_block(uint32_t h[5], const uint8_t *block, size_t len) {
    // Read up to 17 bytes (16 data + 1 high bit) as little-endian
    uint64_t t0 = 0, t1 = 0, t2 = 0;
    for (size_t i = 0; i < 8 && i < len; ++i) t0 |= (uint64_t)block[i] << (8*i);
    for (size_t i = 8; i < 16 && i < len; ++i) t1 |= (uint64_t)block[i] << (8*(i-8));
    // Add 2^(8*len) for the high bit
    if (len < 8) {
        t0 |= (uint64_t)1 << (8*len);
    } else if (len < 16) {
        t1 |= (uint64_t)1 << (8*(len-8));
    } else {
        t2 = 1;
    }

    h[0] = (uint32_t)(t0 & 0x3ffffff);
    h[1] = (uint32_t)((t0 >> 26) & 0x3ffffff);
    h[2] = (uint32_t)((t0 >> 52) | (t1 << 12) & 0x3ffffff);
    h[3] = (uint32_t)((t1 >> 14) & 0x3ffffff);
    h[4] = (uint32_t)((t1 >> 40) | (t2 << 24));
}

// Schoolbook multiply h = h * r (mod 2^130-5)
// Uses the identity: 2^130 = 5 (mod p), so carries from bit 130 wrap to bit 0 * 5
void poly_mult_mod(uint32_t h[5], const uint32_t r[5]) {
    uint64_t d[5];
    // Schoolbook: d[i] = sum(h[j] * r[i-j]) for j=0..4
    d[0] = (uint64_t)h[0]*r[0] + (uint64_t)h[1]*r[4]*5 + (uint64_t)h[2]*r[3]*5 +
           (uint64_t)h[3]*r[2]*5 + (uint64_t)h[4]*r[1]*5;
    d[1] = (uint64_t)h[0]*r[1] + (uint64_t)h[1]*r[0] + (uint64_t)h[2]*r[4]*5 +
           (uint64_t)h[3]*r[3]*5 + (uint64_t)h[4]*r[2]*5;
    d[2] = (uint64_t)h[0]*r[2] + (uint64_t)h[1]*r[1] + (uint64_t)h[2]*r[0] +
           (uint64_t)h[3]*r[4]*5 + (uint64_t)h[4]*r[3]*5;
    d[3] = (uint64_t)h[0]*r[3] + (uint64_t)h[1]*r[2] + (uint64_t)h[2]*r[1] +
           (uint64_t)h[3]*r[0] + (uint64_t)h[4]*r[4]*5;
    d[4] = (uint64_t)h[0]*r[4] + (uint64_t)h[1]*r[3] + (uint64_t)h[2]*r[2] +
           (uint64_t)h[3]*r[1] + (uint64_t)h[4]*r[0];

    // Propagate carries (must start from d[0], matching poly1305-donna-32)
    uint64_t c;
    c = d[0] >> 26; d[0] &= 0x3ffffff;
    d[1] += c; c = d[1] >> 26; d[1] &= 0x3ffffff;
    d[2] += c; c = d[2] >> 26; d[2] &= 0x3ffffff;
    d[3] += c; c = d[3] >> 26; d[3] &= 0x3ffffff;
    d[4] += c; c = d[4] >> 26; d[4] &= 0x3ffffff;
    d[0] += c * 5; c = d[0] >> 26; d[0] &= 0x3ffffff;
    d[1] += c;

    h[0] = (uint32_t)d[0];
    h[1] = (uint32_t)d[1];
    h[2] = (uint32_t)d[2];
    h[3] = (uint32_t)d[3];
    h[4] = (uint32_t)d[4];
}

} // namespace

std::array<uint8_t, Poly1305::kTagSize> Poly1305::compute(
    std::span<const uint8_t> key, std::span<const uint8_t> msg)
{
    // r = key[0..15] with clamping, s = key[16..31]
    uint32_t r[5], h[5] = {0,0,0,0,0};

    // Load and clamp r using poly1305-donna-32 approach:
    // Read 4 bytes as LE uint32, shift, and mask (clamping is in the mask)
    r[0] = load32_le(key.data()) & 0x3ffffff;
    r[1] = (load32_le(key.data() + 3) >> 2) & 0x3ffff03;
    r[2] = (load32_le(key.data() + 6) >> 4) & 0x3ffc0ff;
    r[3] = (load32_le(key.data() + 9) >> 6) & 0x3f03fff;
    r[4] = (load32_le(key.data() + 12) >> 8) & 0x00fffff;

    // Process full 16-byte blocks
    const uint8_t *p = msg.data();
    size_t remaining = msg.size();

    while (remaining >= 16) {
        uint32_t block[5];
        poly_load_block(block, p, 16);
        // h += block
        for (int i = 0; i < 5; ++i) h[i] += block[i];
        // Reduce h after addition (propagate carries, start from h[0])
        uint64_t c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += (uint32_t)c;
        c = h[1] >> 26; h[1] &= 0x3ffffff; h[2] += (uint32_t)c;
        c = h[2] >> 26; h[2] &= 0x3ffffff; h[3] += (uint32_t)c;
        c = h[3] >> 26; h[3] &= 0x3ffffff; h[4] += (uint32_t)c;
        c = h[4] >> 26; h[4] &= 0x3ffffff; h[0] += (uint32_t)(c * 5);
        c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += (uint32_t)c;

        // h = h * r mod p
        poly_mult_mod(h, r);

        p += 16;
        remaining -= 16;
    }

    // Process partial block
    if (remaining > 0) {
        uint32_t block[5];
        poly_load_block(block, p, remaining);
        for (int i = 0; i < 5; ++i) h[i] += block[i];
        uint64_t c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += (uint32_t)c;
        c = h[1] >> 26; h[1] &= 0x3ffffff; h[2] += (uint32_t)c;
        c = h[2] >> 26; h[2] &= 0x3ffffff; h[3] += (uint32_t)c;
        c = h[3] >> 26; h[3] &= 0x3ffffff; h[4] += (uint32_t)c;
        c = h[4] >> 26; h[4] &= 0x3ffffff; h[0] += (uint32_t)(c * 5);
        c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += (uint32_t)c;

        poly_mult_mod(h, r);
    }

    // Final reduction: h = h mod (2^130-5)
    // Full carry propagation
    uint64_t g = h[1] >> 26; h[1] &= 0x3ffffff; h[2] += (uint32_t)g;
    g = h[2] >> 26; h[2] &= 0x3ffffff; h[3] += (uint32_t)g;
    g = h[3] >> 26; h[3] &= 0x3ffffff; h[4] += (uint32_t)g;
    g = h[4] >> 26; h[4] &= 0x3ffffff; h[0] += (uint32_t)(g * 5);
    g = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += (uint32_t)g;

    // h + 5 (for conditional subtraction)
    uint32_t h0_cb = h[0] + 5;
    uint32_t carry = h0_cb >> 26;
    h0_cb &= 0x3ffffff;
    uint32_t h1_cb = h[1] + carry;
    carry = h1_cb >> 26; h1_cb &= 0x3ffffff;
    uint32_t h2_cb = h[2] + carry;
    carry = h2_cb >> 26; h2_cb &= 0x3ffffff;
    uint32_t h3_cb = h[3] + carry;
    carry = h3_cb >> 26; h3_cb &= 0x3ffffff;
    uint32_t h4_cb = h[4] + carry;

    // h4_cb is 26-bit limb (bits 104-129). If h+5 >= 2^130, bit 26 of h4_cb is set.
    // mask = 0xFFFFFFFF if h4_cb >= 2^26 (h >= p, use h_cb = h+5-2^130 = h-p)
    // mask = 0x00000000 if h4_cb < 2^26 (h < p, keep original h)
    uint32_t mask = (uint32_t)(0 - (h4_cb >> 26));
    // Select: h = (h >= p) ? h_cb : h
    h[0] = (h[0] & ~mask) | (h0_cb & mask);
    h[1] = (h[1] & ~mask) | (h1_cb & mask);
    h[2] = (h[2] & ~mask) | (h2_cb & mask);
    h[3] = (h[3] & ~mask) | (h3_cb & mask);
    h[4] = (h[4] & ~mask) | ((h4_cb & 0x3ffffff) & mask);

    // Add s = key[16..31] (as 128-bit little-endian)
    uint8_t s_bytes[16];
    std::memcpy(s_bytes, key.data() + 16, 16);
    uint64_t s_lo = 0, s_hi = 0;
    for (int i = 0; i < 8; ++i) s_lo |= (uint64_t)s_bytes[i] << (8*i);
    for (int i = 0; i < 8; ++i) s_hi |= (uint64_t)s_bytes[i+8] << (8*i);

    // Reconstruct h as 128-bit from 5x26-bit limbs:
    // h = h[0] + h[1]*2^26 + h[2]*2^52 + h[3]*2^78 + h[4]*2^104
    // Low 64 bits:  h[0] | (h[1] << 26) | ((h[2] & 0xFFF) << 52)
    // High 64 bits: (h[2] >> 12) | (h[3] << 14) | (h[4] << 40)
    uint64_t h_val_lo = (uint64_t)h[0] | ((uint64_t)h[1] << 26) | (((uint64_t)h[2] & 0xFFF) << 52);
    uint64_t h_val_hi = ((uint64_t)h[2] >> 12) | ((uint64_t)h[3] << 14) | ((uint64_t)h[4] << 40);

    // Add s (mod 2^128)
    uint64_t out_lo = h_val_lo + s_lo;
    uint64_t carry_add = (out_lo < h_val_lo) ? 1 : 0;
    uint64_t out_hi = h_val_hi + s_hi + carry_add;

    // Output as 16 bytes little-endian
    std::array<uint8_t, kTagSize> tag;
    for (int i = 0; i < 8; ++i) tag[i] = (uint8_t)(out_lo >> (8*i));
    for (int i = 0; i < 8; ++i) tag[i+8] = (uint8_t)(out_hi >> (8*i));
    return tag;
}

// ============================================================================
// ChaCha20-Poly1305 AEAD (RFC 8439 - real Poly1305, not HMAC)
// ============================================================================
std::size_t ChaCha20Poly1305::seal(std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                                     std::span<const uint8_t> ad, std::span<const uint8_t> plaintext,
                                     std::span<uint8_t> out)
{
    if (key.size() != kKeySize || nonce.size() != kNonceSize) return 0;
    if (out.size() < plaintext.size() + kTagSize) return 0;

    // Step 1: Derive Poly1305 key from ChaCha20 block 0 (counter=0)
    uint8_t poly_key[32] = {};
    {
        uint8_t zero_buf[64] = {};
        ChaCha20::process(key, nonce, std::span<uint8_t>(zero_buf, 64), 0);
        std::memcpy(poly_key, zero_buf, 32);
    }

    // Step 2: Encrypt plaintext with ChaCha20 starting at counter=1
    std::memcpy(out.data(), plaintext.data(), plaintext.size());
    ChaCha20::process(key, nonce, std::span<uint8_t>(out.data(), plaintext.size()), 1);

    // Step 3: Build Poly1305 MAC input per RFC 8439 Section 2.8:
    //   pad16(ad) || pad16(ciphertext) || le64(ad_len) || le64(ct_len)
    std::vector<uint8_t> mac_input;
    mac_input.reserve(((ad.size() + 15) & ~(size_t)15) + ((plaintext.size() + 15) & ~(size_t)15) + 16);

    // AD + padding to 16-byte boundary
    mac_input.insert(mac_input.end(), ad.begin(), ad.end());
    for (size_t i = ad.size(); i < ((ad.size() + 15) & ~(size_t)15); ++i) mac_input.push_back(0);

    // Ciphertext + padding to 16-byte boundary
    mac_input.insert(mac_input.end(), out.data(), out.data() + plaintext.size());
    for (size_t i = plaintext.size(); i < ((plaintext.size() + 15) & ~(size_t)15); ++i) mac_input.push_back(0);

    // Lengths as little-endian 64-bit
    uint8_t len_buf[8];
    store64_le(len_buf, ad.size());
    mac_input.insert(mac_input.end(), len_buf, len_buf + 8);
    store64_le(len_buf, plaintext.size());
    mac_input.insert(mac_input.end(), len_buf, len_buf + 8);

    // Step 4: Compute Poly1305 tag
    auto tag = Poly1305::compute(
        std::span<const uint8_t>(poly_key, 32),
        std::span<const uint8_t>(mac_input.data(), mac_input.size()));
    std::memcpy(out.data() + plaintext.size(), tag.data(), kTagSize);

    return plaintext.size() + kTagSize;
}

std::size_t ChaCha20Poly1305::open(std::span<const uint8_t> key, std::span<const uint8_t> nonce,
                                     std::span<const uint8_t> ad,
                                     std::span<const uint8_t> ciphertext_with_tag,
                                     std::span<uint8_t> out)
{
    if (key.size() != kKeySize || nonce.size() != kNonceSize) return 0;
    if (ciphertext_with_tag.size() < kTagSize) return 0;
    std::size_t ct_size = ciphertext_with_tag.size() - kTagSize;
    if (out.size() < ct_size) return 0;

    // Step 1: Derive Poly1305 key from ChaCha20 block 0 (counter=0)
    uint8_t poly_key[32] = {};
    {
        uint8_t zero_buf[64] = {};
        ChaCha20::process(key, nonce, std::span<uint8_t>(zero_buf, 64), 0);
        std::memcpy(poly_key, zero_buf, 32);
    }

    // Step 2: Build Poly1305 MAC input
    std::vector<uint8_t> mac_input;
    mac_input.reserve(((ad.size() + 15) & ~(size_t)15) + ((ct_size + 15) & ~(size_t)15) + 16);

    mac_input.insert(mac_input.end(), ad.begin(), ad.end());
    for (size_t i = ad.size(); i < ((ad.size() + 15) & ~(size_t)15); ++i) mac_input.push_back(0);

    mac_input.insert(mac_input.end(), ciphertext_with_tag.begin(),
                      ciphertext_with_tag.begin() + ct_size);
    for (size_t i = ct_size; i < ((ct_size + 15) & ~(size_t)15); ++i) mac_input.push_back(0);

    uint8_t len_buf[8];
    store64_le(len_buf, ad.size());
    mac_input.insert(mac_input.end(), len_buf, len_buf + 8);
    store64_le(len_buf, ct_size);
    mac_input.insert(mac_input.end(), len_buf, len_buf + 8);

    // Step 3: Compute expected tag and verify (constant-time)
    auto expected = Poly1305::compute(
        std::span<const uint8_t>(poly_key, 32),
        std::span<const uint8_t>(mac_input.data(), mac_input.size()));

    uint8_t diff = 0;
    const uint8_t *received = ciphertext_with_tag.data() + ct_size;
    for (std::size_t i = 0; i < kTagSize; ++i) diff |= expected[i] ^ received[i];
    if (diff != 0) return 0;

    // Step 4: Decrypt with ChaCha20 (counter=1)
    std::memcpy(out.data(), ciphertext_with_tag.data(), ct_size);
    ChaCha20::process(key, nonce, std::span<uint8_t>(out.data(), ct_size), 1);
    return ct_size;
}

// ============================================================================
// Crypto random - Windows BCrypt
// ============================================================================
bool crypto_random_bytes(std::span<uint8_t> out) {
#ifdef _WIN32
    // 使用 Windows BCryptGenRandom - 需要链接 bcrypt.lib
    HMODULE hMod = LoadLibraryA("bcrypt.dll");
    if (hMod) {
        typedef NTSTATUS (WINAPI* PFN_BCryptGenRandom)(void*, PUCHAR, ULONG, ULONG);
        PFN_BCryptGenRandom pFn = (PFN_BCryptGenRandom)GetProcAddress(hMod, "BCryptGenRandom");
        if (pFn) {
            NTSTATUS status = pFn(nullptr, out.data(), (ULONG)out.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            FreeLibrary(hMod);
            if (status == 0) return true;
        }
        FreeLibrary(hMod);
    }
    // BCryptGenRandom failed — refuse to return insecure random bytes
    return false;
#else
    std::random_device rd;
    auto it = out.begin();
    while (it != out.end()) {
        uint32_t v = rd();
        std::size_t remaining = out.end() - it;
        if (remaining > 4) remaining = 4;
        std::memcpy(&*it, &v, remaining);
        it += remaining;
    }
    return true;
#endif
}

// ============================================================================
// P1-7: 常量时间比较
// ============================================================================

bool verify_equal_32(const uint8_t *a, const uint8_t *b) noexcept {
    if (!a || !b) return false;
    uint32_t diff = 0;
    for (int i = 0; i < 32; ++i) {
        diff |= static_cast<uint32_t>(a[i] ^ b[i]);
    }
    // 返回 1 表示相等（diff == 0），0 表示不等
    // 使用位运算而非分支，避免 timing leak
    return (diff == 0);
}

} // namespace linoh::crypto
