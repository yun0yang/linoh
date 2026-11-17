#!/bin/bash
# S7: PTO 超时恢复（注入 5s 丢包）
# T-LP2-003 NAT 穿透自动化测试矩阵
#
# 描述：FullCone↔FullCone 建立连接后，对 node_a 注入 100% 丢包持续 5s，
#       然后清除丢包，验证 linoh 在 10s 内 PTO 探测恢复连接与数据传输。
# 预期：应在 10s 内恢复连接 + 数据传输。
set -euo pipefail

echo "============================================"
echo "  S7: PTO 超时恢复（注入 5s 丢包）"
echo "  描述：注入 5s 100% 丢包，验证 PTO 恢复"
echo "  预期：应在 10s 内恢复"
echo "============================================"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../lib/netns_setup.sh"
source "${SCRIPT_DIR}/../lib/linoh_node.sh"

trap 'patchbay_cleanup; linoh_node_cleanup' EXIT

# ---------- 前置检查 ----------
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] 需要 root 权限（ip netns / iptables / tc）"
    echo "[RESULT] S7 FAILED"
    exit 1
fi

if [[ ! -f "$LINOH_ECHO_NODE" ]]; then
    echo "[SKIP] echo 节点二进制不存在: $LINOH_ECHO_NODE"
    echo "[RESULT] S7 SKIPPED"
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
# 使用 continuous 模式持续发送 echo，便于检测 PTO 恢复后的数据传输状态
node_start_echo "node_a" 9100 "client" "node_b" "--mode" "continuous" "--interval" "1"

# ---------- 4. 建立初始连接 ----------
if ! verify_connection "node_a" "node_b" 60; then
    echo "[RESULT] S7 FAILED（初始连接失败）"
    exit 1
fi
if ! wait_for "node_a 首个 ECHO_OK" 30 node_log_contains "node_a" "ECHO_OK"; then
    echo "[RESULT] S7 FAILED（初始数据传输失败）"
    exit 1
fi
echo "[step] 初始连接已建立，准备注入 PTO 丢包"

# 等待 continuous 模式稳定运行（积累若干 ECHO_OK 作为基线）
sleep 3

_before=$(_count_marker "node_a" "ECHO_OK")
echo "[info] 注入前 ECHO_OK 计数 = $_before"

# ---------- 5. 注入 5s 100% 丢包 ----------
echo "[step] 对 node_a 注入 100% 丢包，持续 5s..."
inject_loss "node_a" 100
sleep 5
echo "[step] 清除丢包，开始计时恢复窗口（10s）"
inject_clear "node_a"

# ---------- 6. 验证 10s 内恢复 ----------
# 判定标准：10s 内出现新的 ECHO_OK（PTO 探测成功，数据流恢复）
_recovered=0
for _i in $(seq 1 10); do
    _after=$(_count_marker "node_a" "ECHO_OK")
    if [[ "${_after:-0}" -gt "${_before:-0}" ]]; then
        _recovered=1
        break
    fi
    sleep 1
done

if [[ $_recovered -eq 1 ]]; then
    echo "[step] PTO 恢复成功，ECHO_OK 计数 ${_before} → ${_after}"
    # 信息性：检查是否有 PTO 恢复标记
    if node_log_contains "node_a" "pto\|recover"; then
        echo "[info] 检测到 PTO 恢复相关日志标记"
    fi
    echo "[RESULT] S7 PASSED"
    exit 0
else
    echo "[RESULT] S7 FAILED（10s 内 PTO 未恢复，无新数据传输）"
    exit 1
fi
