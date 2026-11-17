#!/bin/bash
# manual_s1_debug.sh — 手动执行 S1 场景，保留日志用于排查
# 不触发 trap cleanup，手动控制清理时机
set -uo pipefail

export LINOH_BIN=/root/linoh/build
source /root/linoh/tests/patchbay/lib/netns_setup.sh
source /root/linoh/tests/patchbay/lib/linoh_node.sh

echo "========== 手动 S1 调试 =========="

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

# 等待就绪
if node_wait_ready "node_b" "LISTENING" 30; then
    echo "[ok] server LISTENING"
else
    echo "[FAIL] server 未就绪"
fi

# 启动 client
echo "[step] 启动 client..."
node_start_echo "node_a" 9100 "client" "node_b"

# 等待结果（最多 20s）
echo "[step] 等待 echo 结果（20s）..."
sleep 20

# 检查日志
echo ""
echo "========== SERVER LOG (filtered) =========="
grep -E 'BOOT|LISTENING|ACCEPT|STREAM|ECHO|on_conn|on_stream|WARN|ERROR|callback|stream|recv|RECV|send|SEND' /tmp/patchbay_logs/node_b.log 2>/dev/null | head -40

echo ""
echo "========== CLIENT LOG (filtered) =========="
grep -E 'BOOT|CONNECTED|SEND|RECV|ECHO|WARN|ERROR|stream|recv' /tmp/patchbay_logs/node_a.log 2>/dev/null | head -40

echo ""
echo "========== SERVER LOG (tail 20) =========="
tail -20 /tmp/patchbay_logs/node_b.log 2>/dev/null

echo ""
echo "========== CLIENT LOG (tail 20) =========="
tail -20 /tmp/patchbay_logs/node_a.log 2>/dev/null

# 清理
echo ""
echo "[cleanup] 停止节点..."
node_stop_all 2>/dev/null || true
echo "[cleanup] 删除 netns..."
ns_delete_all 2>/dev/null || true
rm -rf /tmp/patchbay_pids /tmp/patchbay_ip_map 2>/dev/null || true
# 保留日志目录供检查
echo "[done] 日志保留在 /tmp/patchbay_logs/"
