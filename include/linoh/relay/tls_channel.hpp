// linoh/relay/tls_channel.hpp — Optional TLS transport channel for the relay.
//
// Provides a small, OpenSSL-backed wrapper that performs a TLS handshake over
// an already-accepted (server) or already-connected (client) TCP socket and
// then exposes stream read/write. The relay server routes its byte I/O through
// this channel when TLS is enabled; otherwise it is a transparent passthrough.
//
// This is the relay *transport-layer* TLS (wss://). It is completely separate
// from the P2P *application-layer* TLS 1.3 AKE (X25519 + Ed25519 + ChaCha20),
// which lives in linoh::tls and is never invoked here.
//
// Build gating:
//   - LINOH_RELAY_TLS defined  -> real OpenSSL backend (accept/connect work).
//   - LINOH_RELAY_TLS undefined -> passthrough: read/write forward to recv/send;
//                                   accept/connect return null ("TLS not enabled").
// The header itself never includes OpenSSL, so it is safe to include in either
// build. The OpenSSL types live behind the PIMPL `Impl` (defined in the .cpp).

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace linoh::relay {

#ifndef LINOH_RELAY_SOCKET_T
#define LINOH_RELAY_SOCKET_T
#ifdef _WIN32
using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;
#else
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;
#endif
#endif

/// In-memory TLS material for the server side (PEM text).
struct TlsConfig {
    std::string cert_pem;
    std::string key_pem;
};

/// A TLS-wrapped stream over an existing TCP socket.
///
/// Ownership model: TlsChannel owns the SSL/SSL_CTX objects but does NOT own
/// the underlying socket. The caller (RelayServer) is responsible for closing
/// the socket. This avoids double-close races with the server's connection
/// lifecycle.
class TlsChannel {
public:
    ~TlsChannel();

    /// Server side: perform a blocking TLS accept on an already-accepted
    /// socket `s` using the given certificate/key. Returns nullptr on failure
    /// (and fills `err` when provided). On success, all subsequent read/write
    /// calls on the returned channel are decrypted/encrypted transparently.
    static std::shared_ptr<TlsChannel> accept(socket_t s, const TlsConfig &cfg,
                                              std::string *err = nullptr);

    /// Client side: perform a TLS connect (client hello) on an already-connected
    /// socket `s`. `sni` is the Server Name Indication (host). When
    /// `insecure_skip_verify` is true the server certificate chain is NOT
    /// validated (test-only; never use in production). Returns nullptr on
    /// failure.
    static std::shared_ptr<TlsChannel> connect(socket_t s, std::string_view sni,
                                               bool insecure_skip_verify,
                                               std::string *err = nullptr);

    /// Read decrypted application data. Mirrors the server's `sock_recv`
    /// contract:
    ///   > 0  : bytes read
    ///     0  : graceful close (peer closed)
    ///    -1  : error
    ///    -2  : timeout, no data within timeout_ms (caller should keep polling)
    int read(uint8_t *buf, std::size_t len, int timeout_ms);

    /// Write all `len` bytes. Returns true on success, false on error.
    bool write(const uint8_t *buf, std::size_t len);

    /// Release SSL resources. Does NOT close the underlying socket.
    void close();

private:
    TlsChannel();
    struct Impl;
    std::unique_ptr<Impl> impl_;
    socket_t sock_{kInvalidSocket};
};

}  // namespace linoh::relay
