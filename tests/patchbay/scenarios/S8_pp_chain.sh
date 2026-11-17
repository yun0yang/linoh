#!/bin/bash
# S8: 5 节点 PP 菊花链端到端
# T-LP2-003 NAT 穿透自动化测试矩阵
#
# 描述：创建 5 个 FullCone 命名空间（node1-node5），模拟 5 节点 PP 推理链。
#       验证菊花链相邻链路（node1↔node2↔node3↔node4↔node5）端到端可连通。
# 预期：4 条相邻链路全部直连成功 + 数据传输成功。
#
# 注意：完整 PP 菊花链（多跳中继推理）需与 LLMPP 联合测试；
#       本脚本验证 5 节点的相邻可达性矩阵（linoh echo 节点不支持多跳时的简化方案）。
set -euo pipefail

echo "============================================"
echo "  S8: 5 节点 PP 菊花链端到端"
echo "  描述：5 节点 FullCone，验证菊花链相邻链路"
echo "  预期：4 条相邻链路全部直连 + 数据传输成功"
echo "============================================"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../lib/netns_setup.sh"
source "${SCRIPT_DIR}/../lib/linoh_node.sh"

trap 'patchbay_cleanup; linoh_node_cleanup' EXIT

# ---------- 前置检查 ----------
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] 需要 root 权限（ip netns / iptables / tc）"
    echo "[RESULT] S8 FAILED"
    exit 1
fi

if [[ ! -f "$LINOH_ECHO_NODE" ]]; then
    echo "[SKIP] echo 节点二进制不存在: $LINOH_ECHO_NODE"
    echo "[RESULT] S8 SKIPPED"
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

# ---------- 1. 创建 5 个命名空间（FullCone） ----------
echo "[step] 创建 5 个网络命名空间（FullCone）..."
_nodes=("node1" "node2" "node3" "node4" "node5")
_suffix=1
for _n in "${_nodes[@]}"; do
    ns_create "$_n" "$_suffix"
    nat_fullcone "$_n"
    _suffix=$((_suffix + 1))
done

# ---------- 2. 菊花链相邻链路验证 ----------
# 链路：node1 → node2 → node3 → node4 → node5
# 每条链路：后一节点为 server，前一节点为 client，验证直连 + 数据传输
_pairs=("node1:node2" "node2:node3" "node3:node4" "node4:node5")
_ok=0
_total=${#_pairs[@]}

for _pair in "${_pairs[@]}"; do
    _client="${_pair%%:*}"
    _server="${_pair##*:}"
    echo "------ 链路: ${_client} → ${_server} ------"

    # 清理上一轮日志（节点复用，避免旧标记干扰）
    rm -f "${LOG_DIR}/${_client}.log" "${LOG_DIR}/${_server}.log" 2>/dev/null || true

    # 启动 server
    if ! node_start_echo "$_server" 9100 "server"; then
        echo "[ERROR] 启动 server ${_server} 失败"
        echo "[RESULT] S8 FAILED"
        exit 1
    fi
    if ! node_wait_ready "$_server" "LISTENING" 30; then
        echo "[ERROR] ${_server} 未在 30s 内就绪"
        echo "[RESULT] S8 FAILED"
        exit 1
    fi

    # 启动 client（通过 server 命名空间名推导 IP 连接）
    if ! node_start_echo "$_client" 9100 "client" "$_server"; then
        echo "[ERROR] 启动 client ${_client} 失败"
        echo "[RESULT] S8 FAILED"
        exit 1
    fi

    # 验证连接 + 数据传输
    if ! verify_connection "$_client" "$_server" 30; then
        echo "[ERROR] 链路 ${_client} → ${_server} 连接失败"
        echo "[RESULT] S8 FAILED"
        exit 1
    fi
    if ! verify_data_transfer "$_client" 15; then
        echo "[ERROR] 链路 ${_client} → ${_server} 数据传输失败"
        echo "[RESULT] S8 FAILED"
        exit 1
    fi

    echo "[step] 链路 ${_client} → ${_server} OK"
    _ok=$((_ok + 1))

    # 停止本轮节点（保留命名空间，下一轮复用）
    node_stop "$_client"
    node_stop "$_server"
done

# ---------- 3. 汇总 ----------
echo "[step] 菊花链验证完成：${_ok}/${_total} 条链路成功"
if [[ $_ok -eq $_total ]]; then
    echo "[info] 5 节点 PP 菊花链相邻可达性全部通过"
    echo "[NOTE] 完整多跳 PP 推理链需与 LLMPP 联合测试"
    echo "[RESULT] S8 PASSED"
    exit 0
else
    echo "[RESULT] S8 FAILED（${_ok}/${_total} 链路成功）"
    exit 1
fi
