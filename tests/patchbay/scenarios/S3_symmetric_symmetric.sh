#!/bin/bash
# S3: Symmetric ↔ Symmetric（双向 Hard-NAT）— K-LP-001 修复版
# T-LP2-003 NAT 穿透自动化测试矩阵
#
# 描述：双方均为 Symmetric NAT（Hard-NAT），直连不可能，必须 relay 兜底。
# 预期：通过 relay 中转连接 + 数据传输成功。
#
# K-LP-001 修复：echo_node 新增 relay 模式（原生 socket + linoh relay 协议），
#               双向 Symmetric NAT 场景下通过 relay 服务器中转数据。
set -euo pipefail

echo "============================================"
echo "  S3: Symmetric ↔ Symmetric（双向 Hard-NAT）"
echo "  描述：双方 Symmetric NAT，直连不可能"
echo "  预期：通过 relay 中转连接成功"
echo "============================================"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../lib/netns_setup.sh"
source "${SCRIPT_DIR}/../lib/linoh_node.sh"

trap 'patchbay_cleanup; linoh_node_cleanup' EXIT

# ---------- 前置检查 ----------
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] 需要 root 权限（ip netns / iptables / tc）"
    echo "[RESULT] S3 FAILED"
    exit 1
fi

if [[ ! -f "$LINOH_ECHO_NODE" ]] || [[ ! -f "$LINOH_RELAY" ]]; then
    echo "[SKIP] 测试二进制不存在（echo=$LINOH_ECHO_NODE, relay=$LINOH_RELAY）"
    echo "[RESULT] S3 SKIPPED"
    exit 0
fi

# ---------- 1. 创建命名空间 ----------
echo "[step] 创建网络命名空间..."
ns_create "node_a" 1
ns_create "node_b" 2
ns_create "node_relay" 3

# ---------- 2. 配置 NAT（双方 Symmetric） ----------
echo "[step] 配置 Symmetric NAT（双向 Hard-NAT）..."
nat_symmetric "node_a"
nat_symmetric "node_b"

# ---------- 3. 启动 relay（必需，兜底） ----------
RELAY_ADDR="10.99.0.3:9100"
echo "[step] 启动 relay (node_relay, $RELAY_ADDR)..."
node_start_relay "node_relay" 9100
if ! node_wait_ready "node_relay" "LISTENING\|READY\|relay" 20; then
    echo "[WARN] relay 未在 20s 内就绪，尝试继续"
fi

# ---------- 4. 启动 echo server（relay 模式） ----------
echo "[step] 启动 echo server (node_b, relay 模式)..."
node_start_relay_echo "node_b" "server" "$RELAY_ADDR"
if ! node_wait_ready "node_b" "LISTENING" 30; then
    echo "[ERROR] relay server 未在 30s 内就绪"
    echo "[RESULT] S3 FAILED"
    exit 1
fi

# ---------- 5. 获取 server 的 endpoint_id ----------
echo "[step] 获取 server endpoint_id..."
SERVER_EID=""
for _i in $(seq 1 10); do
    SERVER_EID=$(node_get_endpoint_id "node_b")
    if [[ -n "$SERVER_EID" ]]; then break; fi
    sleep 1
done
if [[ -z "$SERVER_EID" ]]; then
    echo "[ERROR] 无法获取 server endpoint_id"
    echo "[RESULT] S3 FAILED"
    exit 1
fi
echo "[info] server endpoint_id = ${SERVER_EID:0:16}..."

# ---------- 6. 启动 echo client（relay 模式） ----------
echo "[step] 启动 echo client (node_a, relay 模式)..."
node_start_relay_echo "node_a" "client" "$RELAY_ADDR" "$SERVER_EID"

# ---------- 7. 验证 relay 中转连接 + 数据传输 ----------
if verify_connection "node_a" "node_b" 60; then
    echo "[info] 连接已建立（经 relay 中转）"
    if verify_data_transfer "node_a" 30; then
        echo "[RESULT] S3 PASSED"
        exit 0
    else
        echo "[RESULT] S3 FAILED（数据传输失败）"
        exit 1
    fi
else
    echo "[RESULT] S3 FAILED（relay 中转连接失败）"
    exit 1
fi
