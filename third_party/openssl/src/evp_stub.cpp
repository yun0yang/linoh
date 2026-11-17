// OpenSSL stub implementation - stub functions that do nothing
// This allows compilation without installing OpenSSL

#include <openssl/evp.h>

// RAND_bytes stub
int RAND_bytes(unsigned char* buf, int num) {
    if (buf && num > 0) {
        // Simple pseudo-random fill for testing
        for (int i = 0; i < num; ++i) {
            buf[i] = static_cast<unsigned char>(i * 17 + 42);
        }
    }
    return 1;
}

// EVP_CIPHER_CTX functions stub
EVP_CIPHER_CTX* EVP_CIPHER_CTX_new(void) { return nullptr; }
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX*) {}
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX*, int, int, void*) { return 1; }

// PKEY functions stub
void EVP_PKEY_free(EVP_PKEY*) {}
EVP_MD_CTX* EVP_MD_CTX_new(void) { return nullptr; }
void EVP_MD_CTX_free(EVP_MD_CTX*) {}

EVP_PKEY* EVP_PKEY_new_raw_private_key(int, void*, const unsigned char*, size_t) { return nullptr; }
EVP_PKEY* EVP_PKEY_new_raw_public_key(int, void*, const unsigned char*, size_t) { return nullptr; }
int EVP_PKEY_get_raw_public_key(const EVP_PKEY*, unsigned char*, size_t*) { return 0; }

// Digest functions stub
int EVP_DigestSignInit(EVP_MD_CTX*, void*, const void*, void*, const EVP_PKEY*) { return 0; }
int EVP_DigestSign(EVP_MD_CTX*, unsigned char*, size_t*, const unsigned char*, size_t) { return 0; }
int EVP_DigestVerifyInit(EVP_MD_CTX*, void*, const void*, void*, const EVP_PKEY*) { return 0; }
int EVP_DigestVerify(EVP_MD_CTX*, const unsigned char*, size_t, const unsigned char*, size_t) { return 0; }

// Encrypt/Decrypt functions stub
int EVP_EncryptInit_ex(EVP_CIPHER_CTX*, const struct evp_cipher_st*, void*, const unsigned char*, const unsigned char*) { return 1; }
int EVP_EncryptUpdate(EVP_CIPHER_CTX*, unsigned char*, int*, const unsigned char*, int) { return 1; }
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX*, unsigned char*, int*) { return 1; }

int EVP_DecryptInit_ex(EVP_CIPHER_CTX*, const struct evp_cipher_st*, void*, const unsigned char*, const unsigned char*) { return 1; }
int EVP_DecryptUpdate(EVP_CIPHER_CTX*, unsigned char*, int*, const unsigned char*, int) { return 1; }
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX*, unsigned char*, int*) { return 0; }
