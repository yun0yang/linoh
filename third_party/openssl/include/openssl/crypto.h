// OpenSSL crypto.h stub
#pragma once

#include <cstddef>
#include <cstdint>

// OpenSSL type declarations
typedef struct openssl_slh_ctxt OPENSSL_INIT_ONCE;

int RAND_bytes(unsigned char* buf, int num);

inline int CRYPTO_memcmp(const void* a, const void* b, size_t len) {
    const unsigned char* pa = static_cast<const unsigned char*>(a);
    const unsigned char* pb = static_cast<const unsigned char*>(b);
    unsigned char diff = 0;
    for (size_t i = 0; i < len; ++i) diff |= pa[i] ^ pb[i];
    return diff;
}
