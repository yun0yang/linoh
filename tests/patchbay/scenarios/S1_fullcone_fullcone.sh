#!/bin/bash
# S1: FullCone ↔ FullCone（基线直连）
# T-LP2-003 NAT 穿透自动化测试矩阵
#
# 描述：双方均为 FullCone NAT，最简单的直连场景，作为穿透基线。
# 预期：应直连成功 + 数据传输成功。
set -euo pipefail

echo "============================================"
echo "  S1: FullCone ↔ FullCone（基线直连）"
echo "  描述：双方 FullCone NAT，最简单直连"
echo "  预期：应直连成功 + 数据传输成功"
echo "============================================"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../lib/netns_setup.sh"
source "${SCRIPT_DIR}/../lib/linoh_node.sh"

trap 'patchbay_cleanup; linoh_node_cleanup' EXIT

# ---------- 前置检查 ----------
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] 需要 root 权限（ip netns / iptables / tc）"
    echo "[RESULT] S1 FAILED"
    exit 1
fi

# 二进制缺失则 SKIP（不阻塞 CI）
if [[ ! -f "$LINOH_ECHO_NODE" ]]; then
    echo "[SKIP] echo 节点二进制不存在: $LINOH_ECHO_NODE"
    echo "[HINT]  请编译 linoh 测试二进制，或通过 LINOH_BIN 环境变量指定路径"
    echo "[RESULT] S1 SKIPPED"
    exit 0
fi

# ---------- 辅助函数 ----------
# 统计日志中某标记出现次数（用于恢复场景判断是否有新数据）
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

# ---------- 2. 配置 NAT ----------
echo "[step] 配置 FullCone NAT..."
nat_fullcone "node_a"
nat_fullcone "node_b"

# ---------- 3. 启动 linoh 节点 ----------
echo "[step] 启动 echo server (node_b)..."
node_start_echo "node_b" 9100 "server"

# 等待 server 就绪（输出 LISTENING 即视为就绪）
if ! node_wait_ready "node_b" "LISTENING" 30; then
    echo "[WARN] server 未在 30s 内输出就绪标记，尝试继续"
fi

echo "[step] 启动 echo client (node_a)..."
node_start_echo "node_a" 9100 "client" "node_b"

# ---------- 4. 验证 ----------
if verify_connection "node_a" "node_b" 60; then
    if verify_data_transfer "node_a" 30; then
        echo "[RESULT] S1 PASSED"
        exit 0
    else
        echo "[RESULT] S1 FAILED（数据传输失败）"
        exit 1
    fi
else
    echo "[RESULT] S1 FAILED（连接失败）"
    exit 1
fi
