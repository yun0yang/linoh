// linoh/relay/tls_channel.cpp — Optional TLS transport channel.
//
// Real OpenSSL backend when LINOH_RELAY_TLS is defined; transparent
// recv/send passthrough otherwise. See tls_channel.hpp for the ownership
// model and the relationship to the P2P TLS 1.3 AKE.

#include "linoh/relay/tls_channel.hpp"

#include <climits>
#include <cstring>
#include <memory>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifdef LINOH_RELAY_TLS
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>  // SSL_set_tls_ext_host_name
#include <openssl/x509.h>
#endif

namespace linoh::relay {

namespace {

#ifdef _WIN32
bool set_socket_timeout(socket_t s, int ms) {
    DWORD t = static_cast<DWORD>(ms < 0 ? 0 : ms);
    return ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                        reinterpret_cast<const char *>(&t),
                        sizeof(t)) == 0;
}
#else
bool set_socket_timeout(socket_t s, int ms) {
    struct timeval tv { ms / 1000, (ms % 1000) * 1000 };
    return ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
}
#endif

}  // namespace

struct TlsChannel::Impl {
#ifdef LINOH_RELAY_TLS
    SSL_CTX *ctx = nullptr;
    SSL *ssl = nullptr;
#else
    int dummy = 0;
#endif
};

TlsChannel::TlsChannel() : impl_(std::make_unique<Impl>()) {}
TlsChannel::~TlsChannel() { close(); }

void TlsChannel::close() {
#ifdef LINOH_RELAY_TLS
    if (impl_) {
        if (impl_->ssl) {
            SSL_free(impl_->ssl);
            impl_->ssl = nullptr;
        }
        if (impl_->ctx) {
            SSL_CTX_free(impl_->ctx);
            impl_->ctx = nullptr;
        }
    }
    // NOTE: the underlying socket is owned by the caller (RelayServer) and is
    // deliberately NOT closed here, to avoid a double-close race.
#endif
}

// ─── Server accept ───

std::shared_ptr<TlsChannel> TlsChannel::accept(socket_t s, const TlsConfig &cfg,
                                               std::string *err) {
#ifdef LINOH_RELAY_TLS
    OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT, nullptr);

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        if (err) *err = "SSL_CTX_new failed";
        return nullptr;
    }
    // rl-L1 (v1.7.0.8): 强制 TLS 1.3，移除 TLS 1.2 攻击面。
    //   linoh relay 是内部组件，客户端均为 linoh 自有实现（支持 TLS 1.3），
    //   无需兼容旧版 TLS 1.2 客户端。TLS 1.2 存在 BEAST/CRIME/Lucky13 等
    //   已知攻击面（虽然 OpenSSL 已修复，但禁用可消除剩余风险）。
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    // Load certificate + private key from in-memory PEM (no temp files).
    {
        BIO *cbio = BIO_new_mem_buf(cfg.cert_pem.data(),
                                    static_cast<int>(cfg.cert_pem.size()));
        X509 *cert = nullptr;
        if (!cbio || !PEM_read_bio_X509(cbio, &cert, nullptr, nullptr) ||
            !cert) {
            if (err) *err = "failed to parse server certificate PEM";
            if (cbio) BIO_free(cbio);
            SSL_CTX_free(ctx);
            return nullptr;
        }
        bool ok = SSL_CTX_use_certificate(ctx, cert) == 1;
        X509_free(cert);
        BIO_free(cbio);
        if (!ok) {
            if (err) *err = "SSL_CTX_use_certificate failed";
            SSL_CTX_free(ctx);
            return nullptr;
        }
    }
    {
        BIO *kbio = BIO_new_mem_buf(cfg.key_pem.data(),
                                    static_cast<int>(cfg.key_pem.size()));
        EVP_PKEY *pkey = nullptr;
        if (!kbio || !PEM_read_bio_PrivateKey(kbio, &pkey, nullptr, nullptr) ||
            !pkey) {
            if (err) *err = "failed to parse server private key PEM";
            if (kbio) BIO_free(kbio);
            SSL_CTX_free(ctx);
            return nullptr;
        }
        bool ok = SSL_CTX_use_PrivateKey(ctx, pkey) == 1;
        EVP_PKEY_free(pkey);
        BIO_free(kbio);
        if (!ok) {
            if (err) *err = "SSL_CTX_use_PrivateKey failed";
            SSL_CTX_free(ctx);
            return nullptr;
        }
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        if (err) *err = "certificate/key mismatch";
        SSL_CTX_free(ctx);
        return nullptr;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        if (err) *err = "SSL_new failed";
        SSL_CTX_free(ctx);
        return nullptr;
    }
    SSL_set_fd(ssl, static_cast<int>(s));
    SSL_set_accept_state(ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    // Bound the handshake so a stalled client cannot hang the accept thread.
    set_socket_timeout(s, 5000);
    int r = SSL_accept(ssl);
    set_socket_timeout(s, 0);  // data phase uses select-based timeouts
    if (r != 1) {
        if (err) {
            unsigned long e = ERR_get_error();
            *err = "SSL_accept failed (0x" + std::to_string(e) + ")";
        }
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    auto ch = std::shared_ptr<TlsChannel>(new TlsChannel());
    ch->sock_ = s;
    ch->impl_ = std::make_unique<Impl>();
    ch->impl_->ctx = ctx;
    ch->impl_->ssl = ssl;
    return ch;
#else
    (void)s;
    (void)cfg;
    if (err) *err = "TLS not enabled in this build (LINOH_RELAY_TLS undefined)";
    return nullptr;
#endif
}

// ─── Client connect ───

std::shared_ptr<TlsChannel> TlsChannel::connect(socket_t s, std::string_view sni,
                                                bool insecure_skip_verify,
                                                std::string *err) {
#ifdef LINOH_RELAY_TLS
    OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT, nullptr);

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        if (err) *err = "SSL_CTX_new failed";
        return nullptr;
    }
    // rl-L1 (v1.7.0.8): 客户端同样强制 TLS 1.3，与 server 端对齐
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    if (insecure_skip_verify) {
        // Test-only: accept any server certificate (self-signed, etc.).
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_default_verify_paths(ctx);
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        if (err) *err = "SSL_new failed";
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (!sni.empty()) {
        std::string h(sni);
        SSL_set_tlsext_host_name(ssl, h.c_str());
    }
    SSL_set_fd(ssl, static_cast<int>(s));
    SSL_set_connect_state(ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    set_socket_timeout(s, 5000);
    int r = SSL_connect(ssl);
    set_socket_timeout(s, 0);
    if (r != 1) {
        if (err) {
            unsigned long e = ERR_get_error();
            *err = "SSL_connect failed (0x" + std::to_string(e) + ")";
        }
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    auto ch = std::shared_ptr<TlsChannel>(new TlsChannel());
    ch->sock_ = s;
    ch->impl_ = std::make_unique<Impl>();
    ch->impl_->ctx = ctx;
    ch->impl_->ssl = ssl;
    return ch;
#else
    (void)s;
    (void)sni;
    (void)insecure_skip_verify;
    if (err) *err = "TLS not enabled in this build (LINOH_RELAY_TLS undefined)";
    return nullptr;
#endif
}

// ─── Read / Write ───

int TlsChannel::read(uint8_t *buf, std::size_t len, int timeout_ms) {
#ifdef LINOH_RELAY_TLS
    if (!impl_ || !impl_->ssl) return -1;

    // rl-M4 (v1.7.0.8): 先检查 SSL 内部缓冲是否有未消费数据。
    // TLS 记录可能一次解密多字节应用数据，若仅依赖 select(sock) 会因 socket
    // 无新数据而超时返回 -2，导致 SSL 缓冲数据卡住（SSL+select 经典陷阱）。
    if (SSL_pending(impl_->ssl) > 0) {
        int want = static_cast<int>(len > static_cast<std::size_t>(INT_MAX)
                                        ? INT_MAX
                                        : len);
        int n = SSL_read(impl_->ssl, buf, want);
        if (n > 0) return n;
        int e = SSL_get_error(impl_->ssl, n);
        if (e == SSL_ERROR_ZERO_RETURN) return 0;  // graceful close
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return -2;
        return -1;
    }

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock_, &fds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int r = ::select(static_cast<int>(sock_) + 1, &fds, nullptr, nullptr, &tv);
    if (r < 0) return -1;
    if (r == 0) return -2;  // timeout, keep waiting

    int want = static_cast<int>(len > static_cast<std::size_t>(INT_MAX)
                                    ? INT_MAX
                                    : len);
    int n = SSL_read(impl_->ssl, buf, want);
    if (n > 0) return n;
    int e = SSL_get_error(impl_->ssl, n);
    if (e == SSL_ERROR_ZERO_RETURN) return 0;  // graceful close
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return -2;
    return -1;
#else
    (void)impl_;
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock_, &fds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int r = ::select(static_cast<int>(sock_) + 1, &fds, nullptr, nullptr, &tv);
    if (r < 0) return -1;
    if (r == 0) return -2;
    int want = static_cast<int>(len > static_cast<std::size_t>(INT_MAX)
                                    ? INT_MAX
                                    : len);
    int n = ::recv(sock_, reinterpret_cast<char *>(buf), want, 0);
    if (n < 0) return -1;
    return n;  // 0 = close, >0 = data
#endif
}

bool TlsChannel::write(const uint8_t *buf, std::size_t len) {
#ifdef LINOH_RELAY_TLS
    if (!impl_ || !impl_->ssl) return false;
    std::size_t off = 0;
    while (off < len) {
        std::size_t rem = len - off;
        int chunk = static_cast<int>(rem > static_cast<std::size_t>(INT_MAX)
                                         ? INT_MAX
                                         : rem);
        int n = SSL_write(impl_->ssl, buf + off, chunk);
        if (n <= 0) {
            int e = SSL_get_error(impl_->ssl, n);
            if (e == SSL_ERROR_WANT_WRITE) continue;  // retry
            return false;
        }
        off += static_cast<std::size_t>(n);
    }
    return true;
#else
    (void)impl_;
    std::size_t off = 0;
    while (off < len) {
        std::size_t rem = len - off;
        int chunk = static_cast<int>(rem > static_cast<std::size_t>(INT_MAX)
                                         ? INT_MAX
                                         : rem);
        int n = ::send(sock_, reinterpret_cast<const char *>(buf + off), chunk, 0);
        if (n <= 0) return false;
        off += static_cast<std::size_t>(n);
    }
    return true;
#endif
}

}  // namespace linoh::relay
