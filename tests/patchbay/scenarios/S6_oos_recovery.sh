#!/bin/bash
# S6: OOS 空洞恢复（注入乱序）
# T-LP2-003 NAT 穿透自动化测试矩阵
#
# 描述：FullCone↔FullCone 建立连接后，对 node_b 注入 30% 乱序（OOS），
#       验证 linoh 在 30s 内填补乱序空洞或触发恢复回调，数据传输不中断。
# 预期：应 30s 内 OOS 空洞填补或回调，数据传输恢复。
set -euo pipefail

echo "============================================"
echo "  S6: OOS 空洞恢复（注入乱序）"
echo "  描述：注入 30% 乱序，验证 OOS 恢复"
echo "  预期：应 30s 内填补空洞或回调"
echo "============================================"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../lib/netns_setup.sh"
source "${SCRIPT_DIR}/../lib/linoh_node.sh"

trap 'patchbay_cleanup; linoh_node_cleanup' EXIT

# ---------- 前置检查 ----------
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] 需要 root 权限（ip netns / iptables / tc）"
    echo "[RESULT] S6 FAILED"
    exit 1
fi

if [[ ! -f "$LINOH_ECHO_NODE" ]]; then
    echo "[SKIP] echo 节点二进制不存在: $LINOH_ECHO_NODE"
    echo "[RESULT] S6 SKIPPED"
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
# 使用 continuous 模式持续发送 echo，便于检测 OOS 注入期间/恢复后的数据传输状态
node_start_echo "node_a" 9100 "client" "node_b" "--mode" "continuous" "--interval" "1"

# ---------- 4. 建立初始连接 ----------
if ! verify_connection "node_a" "node_b" 60; then
    echo "[RESULT] S6 FAILED（初始连接失败）"
    exit 1
fi
if ! wait_for "node_a 首个 ECHO_OK" 30 node_log_contains "node_a" "ECHO_OK"; then
    echo "[RESULT] S6 FAILED（初始数据传输失败）"
    exit 1
fi
echo "[step] 初始连接已建立，准备注入 OOS"

# 等待 continuous 模式稳定运行（积累若干 ECHO_OK 作为基线）
sleep 3

_before=$(_count_marker "node_a" "ECHO_OK")
echo "[info] 注入前 ECHO_OK 计数 = $_before"

# ---------- 5. 注入乱序（OOS） ----------
# 对 node_b（server 侧）注入 100ms 延迟 + 30% 乱序
inject_reorder "node_b" 100 30

# ---------- 6. 验证 30s 内 OOS 恢复 ----------
# 判定标准：30s 内出现新的 ECHO_OK（数据流未中断 = 空洞已填补）
# 也可检测 OOS 恢复标记（信息性，不阻塞）
_recovered=0
for _i in $(seq 1 30); do
    _after=$(_count_marker "node_a" "ECHO_OK")
    if [[ "${_after:-0}" -gt "${_before:-0}" ]]; then
        _recovered=1
        break
    fi
    sleep 1
done

# 清除网络损伤
inject_clear "node_b"

if [[ $_recovered -eq 1 ]]; then
    echo "[step] OOS 期间数据持续传输，ECHO_OK 计数 ${_before} → ${_after}"
    # 信息性：检查是否有 OOS 恢复标记
    if node_log_contains "node_a" "oos\|reorder\|recover"; then
        echo "[info] 检测到 OOS 相关日志标记"
    fi
    echo "[RESULT] S6 PASSED"
    exit 0
else
    echo "[RESULT] S6 FAILED（30s 内 OOS 空洞未恢复，无新数据传输）"
    exit 1
fi
