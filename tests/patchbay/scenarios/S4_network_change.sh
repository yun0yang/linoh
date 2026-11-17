#!/bin/bash
# S4: 网络切换（IP 变化）
# T-LP2-003 NAT 穿透自动化测试矩阵
#
# 描述：先建立 FullCone↔FullCone 连接，然后改变 node_a 的 IP，
#       验证 linoh 触发 on_network_change 回调并重连成功。
# 预期：应触发 on_network_change + 重连后数据传输恢复。
set -euo pipefail

echo "============================================"
echo "  S4: 网络切换（IP 变化）"
echo "  描述：建立连接后改变 node_a IP"
echo "  预期：触发 on_network_change + 重连成功"
echo "============================================"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../lib/netns_setup.sh"
source "${SCRIPT_DIR}/../lib/linoh_node.sh"

trap 'patchbay_cleanup; linoh_node_cleanup' EXIT

# ---------- 前置检查 ----------
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] 需要 root 权限（ip netns / iptables / tc）"
    echo "[RESULT] S4 FAILED"
    exit 1
fi

if [[ ! -f "$LINOH_ECHO_NODE" ]]; then
    echo "[SKIP] echo 节点二进制不存在: $LINOH_ECHO_NODE"
    echo "[RESULT] S4 SKIPPED"
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

# ---------- 2. 配置 NAT ----------
echo "[step] 配置 FullCone NAT..."
nat_fullcone "node_a"
nat_fullcone "node_b"

# ---------- 3. 启动 linoh 节点 ----------
echo "[step] 启动 echo server (node_b)..."
node_start_echo "node_b" 9100 "server"
if ! node_wait_ready "node_b" "LISTENING" 30; then
    echo "[WARN] server 未在 30s 内输出就绪标记"
fi

echo "[step] 启动 echo client (node_a, continuous 模式)..."
# 使用 continuous 模式持续发送 echo，便于检测网络切换后的数据传输恢复
node_start_echo "node_a" 9100 "client" "node_b" "--mode" "continuous" "--interval" "1"

# ---------- 4. 建立初始连接 ----------
if ! verify_connection "node_a" "node_b" 60; then
    echo "[RESULT] S4 FAILED（初始连接失败）"
    exit 1
fi
# continuous 模式下等待首个 ECHO_OK 即可（数据传输已恢复的标志）
if ! wait_for "node_a 首个 ECHO_OK" 30 node_log_contains "node_a" "ECHO_OK"; then
    echo "[RESULT] S4 FAILED（初始数据传输失败）"
    exit 1
fi
echo "[step] 初始连接已建立，准备触发网络切换"

# 记录切换前的 ECHO_OK 计数（用于判断切换后是否有新数据）
_before=$(_count_marker "node_a" "ECHO_OK")
echo "[info] 切换前 ECHO_OK 计数 = $_before"

# ---------- 5. 触发网络切换（IP 变化） ----------
# node_a: 10.99.0.1 → 10.99.0.11
simulate_network_change "node_a" 11

# ---------- 6. 验证 on_network_change 回调 ----------
# 注意：实际日志标记待 linoh 实现确认，此处匹配 "network_change" 子串（覆盖 on_network_change）
if ! wait_for "node_a on_network_change 回调" 30 node_log_contains "node_a" "network_change"; then
    echo "[RESULT] S4 FAILED（未在 30s 内触发 on_network_change）"
    exit 1
fi
echo "[step] 已检测到 on_network_change 回调"

# ---------- 7. 验证重连后数据传输恢复 ----------
# 等待新的 ECHO_OK 出现（计数增加 = 数据流恢复）
_recovered=0
for _i in $(seq 1 30); do
    _after=$(_count_marker "node_a" "ECHO_OK")
    if [[ "${_after:-0}" -gt "${_before:-0}" ]]; then
        _recovered=1
        break
    fi
    sleep 1
done

if [[ $_recovered -eq 1 ]]; then
    echo "[step] 重连成功，ECHO_OK 计数 ${_before} → ${_after}"
    echo "[RESULT] S4 PASSED"
    exit 0
else
    echo "[RESULT] S4 FAILED（重连后 30s 内无新数据传输）"
    exit 1
fi
