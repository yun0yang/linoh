// OpenSSL stub for compilation without full OpenSSL installation
#pragma once

#include <cstddef>
#include <cstdint>

// Forward declarations
struct evp_pkey_st;
struct evp_md_ctx_st;
struct evp_md_st;

// Cipher types
#define EVP_PKEY_ED25519 949

typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_md_ctx_st EVP_MD_CTX;

// Opaque types - define as incomplete structs
struct evp_cipher_st;
struct evp_cipher_ctx_st;

typedef const struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

// Cipher functions
inline int EVP_CIPHER_key_length(const struct evp_cipher_st*) { return 32; }
inline int EVP_CIPHER_iv_length(const struct evp_cipher_st*) { return 12; }

EVP_CIPHER_CTX* EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX*);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX*, int, int, void*);

// AEAD control commands
#define EVP_CTRL_AEAD_SET_IVLEN 0x9
#define EVP_CTRL_AEAD_GET_TAG 0x10
#define EVP_CTRL_AEAD_SET_TAG 0x11

// Cipher constructors (stub implementations - return nullptr for now)
inline const struct evp_cipher_st* EVP_chacha20_poly1305() { return nullptr; }
inline const struct evp_cipher_st* EVP_aes_128_gcm() { return nullptr; }

// Encrypt/Decrypt functions
int EVP_EncryptInit_ex(EVP_CIPHER_CTX*, const struct evp_cipher_st*, void*, const unsigned char*, const unsigned char*);
int EVP_EncryptUpdate(EVP_CIPHER_CTX*, unsigned char*, int*, const unsigned char*, int);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX*, unsigned char*, int*);

int EVP_DecryptInit_ex(EVP_CIPHER_CTX*, const struct evp_cipher_st*, void*, const unsigned char*, const unsigned char*);
int EVP_DecryptUpdate(EVP_CIPHER_CTX*, unsigned char*, int*, const unsigned char*, int);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX*, unsigned char*, int*);

// PKEY functions
void EVP_PKEY_free(EVP_PKEY*);
EVP_MD_CTX* EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX*);

EVP_PKEY* EVP_PKEY_new_raw_private_key(int type, void* engine,
    const unsigned char* priv, size_t len);

EVP_PKEY* EVP_PKEY_new_raw_public_key(int type, void* engine,
    const unsigned char* pub, size_t len);

int EVP_PKEY_get_raw_public_key(const EVP_PKEY* pkey,
    unsigned char* pub, size_t* len);

int EVP_DigestSignInit(EVP_MD_CTX* ctx, void* engine, const void* type,
    void* impl, const EVP_PKEY* pkey);

int EVP_DigestSign(EVP_MD_CTX* ctx, unsigned char* sigret, size_t* siglen,
    const unsigned char* tbs, size_t tbslen);

int EVP_DigestVerifyInit(EVP_MD_CTX* ctx, void* engine, const void* type,
    void* impl, const EVP_PKEY* pkey);

int EVP_DigestVerify(EVP_MD_CTX* ctx, const unsigned char* sigret, size_t siglen,
    const unsigned char* tbs, size_t tbslen);
