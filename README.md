# linoh

**Li**ghtweight **N**etwork for **O**n-device **H**igh-throughput — a C++20 P2P QUIC
framework engineered as the communication backbone for multimodal distributed
inference (LLM pipeline parallelism, image / video / audio feature streaming).

linoh gives every node an Ed25519 public-key identity, builds multipath QUIC
transports between peers, routes application traffic by ALPN, and falls back to
relay automatically when direct connection is impossible — zero configuration.

## Highlights

- **Key-based identity** — 32-byte Ed25519 public key (`EndpointId`); no IP or
  DNS dependency. Pkarr-style DNS server for endpoint discovery.
- **Multipath QUIC transport** — `MultipathSelector` with round-robin and
  coordinated (weighted) modes; UDP multi-port striping.
- **Custom TLS 1.3 AKE** — X25519 + Ed25519 + ChaCha20-Poly1305, 1-RTT
  handshake, 0-RTT session resumption, pluggable crypto interface.
- **ALPN multimodal routing** — independent data channels per modality
  (`pp-hidden/1`, `pp-img`, `pp-video`, `pp-audio`, `ctrl`, ...).
- **5-tier NAT traversal** — ICE → CGN detection → dual-stack → bidirectional
  hole punching → relay pool. Automatic failover, address discovery without
  STUN (QAD).
- **Reliability & performance** — retransmission / loss recovery with OOS
  handling, BBR + NewReno congestion control, pacing, FEC (Reed-Solomon,
  adaptive), optional zstd dictionary compression on the wire.
- **Flow & path control** — credit-based reservation flow control, connection-level
  path override with fast failover, async send primitives.
- **C API + Android SDK** — stable C ABI (`linoh_c.h`) for engine integration;
  Android library module with Kotlin bindings.

## Repository Layout

```
include/linoh/   Public headers (endpoint, net, protocol, crypto, fec, nat, ...)
src/             Framework implementation
examples/        Relay/DNS server mains, echo & chat samples
tests/           250+ unit/integration test files + patchbay NAT testbed
tools/           Relay bridge helper
android/         Android library module (JNI + Kotlin)
third_party/     Vendored zstd 1.5.6
```

## Building

| Platform | Toolchain | Command |
|---|---|---|
| Windows 10/11 | Visual Studio 2022 (MSVC) | `build_all.bat` |
| Linux | GCC 11+ | `./build_all.sh` |
| Android | NDK + AGP 8.5 | `cd android && ./gradlew :linoh:assembleRelease` |

CMake is also supported (`CMakeLists.txt` at the root). The build produces four
static libraries — `linoh-base`, `linoh`, `linoh-relay`, `linoh-dns-server` —
plus standalone executables `linoh-relay-server` and `linoh-dns-server`.

## Testing

The full suite (unit + integration + e2e) is built and run by `build_all.bat` /
`build_all.sh`. `tests/patchbay/` contains a scriptable NAT-condition testbed
for hole-punching scenarios.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
