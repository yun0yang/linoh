#!/bin/bash
set -e
cd "$(dirname "$0")"
mkdir -p build

CXX=${CXX:-g++}
CXXFLAGS="-std=c++20 -O2 -pthread -DLINOH_USE_STUB_ASIO \
    -I. -Iinclude -Ithird_party/asio/include -Ithird_party/openssl/include"

# Minimal linoh objects needed for Ed25519 key/sign/verify and SHA-512
# v4.5.0: 新增 key_file/crc32/file_permission/atomic_write（统一密钥持久化）
SRCS=(
    tools/linoh_relay_bridge.cpp
    src/base/key.cpp
    src/util/crypto.cpp
    src/util/crc32.cpp
    src/util/file_permission.cpp
    src/util/key_file.cpp
    src/util/atomic_write.cpp
    src/tls/ed25519_core.cpp
)

echo "Building linoh_relay_bridge (Linux)..."
$CXX $CXXFLAGS "${SRCS[@]}" -o build/linoh_relay_bridge
chmod +x build/linoh_relay_bridge
echo "SUCCESS: build/linoh_relay_bridge"
