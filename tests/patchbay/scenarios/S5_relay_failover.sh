#!/bin/bash
# S5: relay 故障切换（主 relay 宕机）— K-LP-001 修复版
# T-LP2-003 NAT 穿透自动化测试矩阵
#
# 描述：双向 Symmetric NAT，启动主备两个 relay。先经主 relay 连接，
#       然后 kill 主 relay，验证自动切换到备 relay 且数据不中断。
# 预期：应切换备 relay + 数据传输恢复。
#
# K-LP-001 修复：echo_node relay 模式支持 --relay-backup 参数，
#               主 relay 断开后自动重连到备用 relay。
set -euo pipefail

echo "============================================"
echo "  S5: relay 故障切换（主 relay 宕机）"
echo "  描述：主 relay 宕机后切换备 relay"
echo "  预期：应切换备 relay + 数据传输恢复"
echo "============================================"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../lib/netns_setup.sh"
source "${SCRIPT_DIR}/../lib/linoh_node.sh"

trap 'patchbay_cleanup; linoh_node_cleanup' EXIT

# ---------- 前置检查 ----------
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] 需要 root 权限（ip netns / iptables / tc）"
    echo "[RESULT] S5 FAILED"
    exit 1
fi

if [[ ! -f "$LINOH_ECHO_NODE" ]] || [[ ! -f "$LINOH_RELAY" ]]; then
    echo "[SKIP] 测试二进制不存在（echo=$LINOH_ECHO_NODE, relay=$LINOH_RELAY）"
    echo "[RESULT] S5 SKIPPED"
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
ns_create "relay_primary" 3
ns_create "relay_backup" 4

# ---------- 2. 配置 NAT ----------
echo "[step] 配置 Symmetric NAT（双向 Hard-NAT，强制走 relay）..."
nat_symmetric "node_a"
nat_symmetric "node_b"

# ---------- 3. 启动主备 relay ----------
RELAY_PRIMARY="10.99.0.3:9100"
RELAY_BACKUP="10.99.0.4:9100"

echo "[step] 启动主 relay (relay_primary, $RELAY_PRIMARY)..."
node_start_relay "relay_primary" 9100
if ! node_wait_ready "relay_primary" "LISTENING\|READY\|relay" 20; then
    echo "[WARN] 主 relay 未在 20s 内就绪"
fi

echo "[step] 启动备 relay (relay_backup, $RELAY_BACKUP)..."
node_start_relay "relay_backup" 9100
if ! node_wait_ready "relay_backup" "LISTENING\|READY\|relay" 20; then
    echo "[WARN] 备 relay 未在 20s 内就绪"
fi

# ---------- 4. 启动 echo server（relay 模式，主 relay） ----------
echo "[step] 启动 echo server (node_b, relay 模式, 主 relay)..."
node_start_relay_echo "node_b" "server" "$RELAY_PRIMARY"
if ! node_wait_ready "node_b" "LISTENING" 30; then
    echo "[ERROR] relay server 未在 30s 内就绪"
    echo "[RESULT] S5 FAILED"
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
    echo "[RESULT] S5 FAILED"
    exit 1
fi
echo "[info] server endpoint_id = ${SERVER_EID:0:16}..."

# ---------- 6. 启动 echo client（relay 模式，主 relay + 备 relay） ----------
echo "[step] 启动 echo client (node_a, continuous 模式, 主+备 relay)..."
node_start_relay_echo "node_a" "client" "$RELAY_PRIMARY" "$SERVER_EID" \
    "--relay-backup" "$RELAY_BACKUP" \
    "--mode" "continuous" "--interval" "1"

# ---------- 7. 建立初始连接（经主 relay） ----------
if ! verify_connection "node_a" "node_b" 60; then
    echo "[RESULT] S5 FAILED（初始连接失败）"
    exit 1
fi
if ! wait_for "node_a 首个 ECHO_OK" 30 node_log_contains "node_a" "ECHO_OK"; then
    echo "[RESULT] S5 FAILED（初始数据传输失败）"
    exit 1
fi
echo "[step] 初始连接已建立（经主 relay）"

_before=$(_count_marker "node_a" "ECHO_OK")
echo "[info] 故障切换前 ECHO_OK 计数 = $_before"

# ---------- 8. 故障注入：停止主 relay ----------
echo "[step] 停止主 relay，触发故障切换..."
node_stop "relay_primary"

# 等待故障切换标记（client 日志中应出现 RECONNECT + 备用 relay）
wait_for "relay 故障切换标记" 30 node_log_contains "node_a" "RECONNECT\|backup\|备用" || true

# ---------- 9. 验证切换备 relay + 数据恢复 ----------
# 等待新的 ECHO_OK 出现（计数增加 = 已切换到备 relay 且数据恢复）
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
    echo "[step] 已切换备 relay，ECHO_OK 计数 ${_before} → ${_after}"
    if node_is_alive "relay_backup"; then
        echo "[info] 备 relay 存活"
    fi
    echo "[RESULT] S5 PASSED"
    exit 0
else
    echo "[RESULT] S5 FAILED（切换备 relay 后 30s 内无新数据传输）"
    exit 1
fi
