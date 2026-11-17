#!/bin/bash
# S2: Symmetric ↔ FullCone（端口预测）
# T-LP2-003 NAT 穿透自动化测试矩阵
#
# 描述：node_a 为 Symmetric NAT（Hard-NAT），node_b 为 FullCone NAT。
#       Symmetric 一侧端口随机，需端口预测或 relay 兜底。
# 预期：应直连或 relay 连接成功 + 数据传输成功。
set -euo pipefail

echo "============================================"
echo "  S2: Symmetric ↔ FullCone（端口预测）"
echo "  描述：node_a Symmetric, node_b FullCone"
echo "  预期：应直连或 relay 连接成功"
echo "============================================"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../lib/netns_setup.sh"
source "${SCRIPT_DIR}/../lib/linoh_node.sh"

trap 'patchbay_cleanup; linoh_node_cleanup' EXIT

# ---------- 前置检查 ----------
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] 需要 root 权限（ip netns / iptables / tc）"
    echo "[RESULT] S2 FAILED"
    exit 1
fi

if [[ ! -f "$LINOH_ECHO_NODE" ]] || [[ ! -f "$LINOH_RELAY" ]]; then
    echo "[SKIP] 测试二进制不存在（echo=$LINOH_ECHO_NODE, relay=$LINOH_RELAY）"
    echo "[RESULT] S2 SKIPPED"
    exit 0
fi

# ---------- 辅助函数 ----------
_count_marker() {
    local ns_name="$1"
    local marker="$2"
    local log_file="${LOG_DIR}/${ns_name}.log"
    local n
    n=$(grep -Fc -- "$marker" "$log_file" 2>/dev/null) || n=0
    echo "${n:-0}"
}

# ---------- 1. 创建命名空间 ----------
echo "[step] 创建网络命名空间..."
ns_create "node_a" 1
ns_create "node_b" 2
ns_create "node_relay" 3

# ---------- 2. 配置 NAT ----------
echo "[step] 配置 NAT（node_a=Symmetric, node_b=FullCone）..."
nat_symmetric "node_a"
nat_fullcone "node_b"

# ---------- 3. 启动 relay（兜底） ----------
# 注意：echo 节点需通过 RELAY_ADDR 环境变量发现 relay 地址
export RELAY_ADDR="10.99.0.3:9100"
echo "[step] 启动 relay (node_relay, RELAY_ADDR=$RELAY_ADDR)..."
node_start_relay "node_relay" 9100
if ! node_wait_ready "node_relay" "LISTENING\|READY\|relay" 20; then
    echo "[WARN] relay 未在 20s 内就绪，尝试继续"
fi

# ---------- 4. 启动 linoh 节点 ----------
echo "[step] 启动 echo server (node_b)..."
node_start_echo "node_b" 9100 "server"
if ! node_wait_ready "node_b" "LISTENING" 30; then
    echo "[WARN] server 未在 30s 内输出就绪标记"
fi

echo "[step] 启动 echo client (node_a, Symmetric NAT)..."
node_start_echo "node_a" 9100 "client" "node_b"

# ---------- 5. 验证（直连或 relay 均算成功） ----------
# 客户端日志出现 CONNECTED 即表示连接建立（无论直连还是 relay）
if verify_connection "node_a" "node_b" 60; then
    # 顺便记录是否走了 relay（信息性，不影响判定）
    if node_log_contains "node_a" "relay"; then
        echo "[info] 连接路径：relay"
    else
        echo "[info] 连接路径：直连（端口预测成功）"
    fi
    if verify_data_transfer "node_a" 30; then
        echo "[RESULT] S2 PASSED"
        exit 0
    else
        echo "[RESULT] S2 FAILED（数据传输失败）"
        exit 1
    fi
else
    echo "[RESULT] S2 FAILED（连接失败）"
    exit 1
fi
