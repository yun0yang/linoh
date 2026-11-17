#!/bin/bash
# manual_s6_debug.sh — 手动执行 S6 场景，保留日志用于排查 continuous 模式问题
# 不触发 trap cleanup，手动控制清理时机
set -uo pipefail

export LINOH_BIN=/root/linoh/build
source /root/linoh/tests/patchbay/lib/netns_setup.sh
source /root/linoh/tests/patchbay/lib/linoh_node.sh

echo "========== 手动 S6 调试（continuous 模式 + OOS 注入） =========="

# 清理残留
ns_delete_all 2>/dev/null || true
rm -rf /tmp/patchbay_pids /tmp/patchbay_logs /tmp/patchbay_ip_map
mkdir -p /tmp/patchbay_pids /tmp/patchbay_logs

# 创建 netns
echo "[step] 创建 netns..."
ns_create "node_a" 1
ns_create "node_b" 2

# 配置 FullCone NAT
echo "[step] 配置 FullCone NAT..."
nat_fullcone "node_a"
nat_fullcone "node_b"

# 启动 server
echo "[step] 启动 server..."
node_start_echo "node_b" 9100 "server"
node_wait_ready "node_b" "LISTENING" 30 && echo "[ok] server LISTENING"

# 启动 client（continuous 模式，1 秒间隔）
echo "[step] 启动 client (continuous 模式, interval=1s)..."
node_start_echo "node_a" 9100 "client" "node_b" "--mode" "continuous" "--interval" "1"

# 等待连接建立 + 首个 ECHO_OK
echo "[step] 等待连接建立（20s）..."
sleep 20

# 检查连接状态
echo ""
echo "========== 连接建立后状态（注入前） =========="
echo "--- CLIENT LOG (ECHO_OK/ECHO_FAIL/CONN_STATE) ---"
grep -E 'ECHO_OK|ECHO_FAIL|CONN_STATE|CONNECTED|CLOSED|ERROR|WARN' /tmp/patchbay_logs/node_a.log 2>/dev/null | tail -20

_before=$(grep -Fc "ECHO_OK" /tmp/patchbay_logs/node_a.log 2>/dev/null || echo 0)
echo ""
echo "[info] 注入前 ECHO_OK 计数 = $_before"

# 注入 OOS（30% 乱序 + 100ms 延迟）
echo "[step] 对 node_b 注入 30% 乱序 + 100ms 延迟..."
inject_reorder "node_b" 100 30

# 等待 30s，观察 continuous 模式行为
echo "[step] 等待 30s 观察 continuous 模式行为..."
sleep 30

_after=$(grep -Fc "ECHO_OK" /tmp/patchbay_logs/node_a.log 2>/dev/null || echo 0)
echo ""
echo "========== OOS 注入期间状态 =========="
echo "[info] 注入后 ECHO_OK 计数 = $_after"
echo "--- CLIENT LOG (ECHO_OK/ECHO_FAIL/CONN_STATE, last 40) ---"
grep -E 'ECHO_OK|ECHO_FAIL|CONN_STATE|CONNECTED|CLOSED|ERROR|WARN' /tmp/patchbay_logs/node_a.log 2>/dev/null | tail -40

# 清除网络损伤
echo ""
echo "[step] 清除网络损伤..."
inject_clear "node_b"

# 等待恢复
echo "[step] 等待 15s 观察恢复..."
sleep 15

_recovered=$(grep -Fc "ECHO_OK" /tmp/patchbay_logs/node_a.log 2>/dev/null || echo 0)
echo ""
echo "========== 清除损伤后状态 =========="
echo "[info] 恢复后 ECHO_OK 计数 = $_recovered"
echo "--- CLIENT LOG (last 30) ---"
grep -E 'ECHO_OK|ECHO_FAIL|CONN_STATE|CONNECTED|CLOSED|ERROR|WARN|DONE' /tmp/patchbay_logs/node_a.log 2>/dev/null | tail -30

echo ""
echo "========== CLIENT LOG (CONN_STATE 完整) =========="
grep -E 'CONN_STATE' /tmp/patchbay_logs/node_a.log 2>/dev/null | head -20

echo ""
echo "========== CLIENT LOG (tail 30 全量) =========="
tail -30 /tmp/patchbay_logs/node_a.log 2>/dev/null

# 清理
echo ""
echo "[cleanup] 停止节点..."
node_stop_all 2>/dev/null || true
echo "[cleanup] 删除 netns..."
ns_delete_all 2>/dev/null || true
rm -rf /tmp/patchbay_pids /tmp/patchbay_ip_map 2>/dev/null || true
echo "[done] 日志保留在 /tmp/patchbay_logs/"
