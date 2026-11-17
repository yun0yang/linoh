#!/bin/bash
# manual_s3_debug.sh — 手动执行 S3 场景，保留日志用于排查双向 Symmetric NAT 数据传输问题
set -uo pipefail

export LINOH_BIN=/root/linoh/build
source /root/linoh/tests/patchbay/lib/netns_setup.sh
source /root/linoh/tests/patchbay/lib/linoh_node.sh

echo "========== 手动 S3 调试（双向 Symmetric NAT） =========="

# 清理残留
ns_delete_all 2>/dev/null || true
rm -rf /tmp/patchbay_pids /tmp/patchbay_logs /tmp/patchbay_ip_map
mkdir -p /tmp/patchbay_pids /tmp/patchbay_logs

# 创建 netns
echo "[step] 创建 netns..."
ns_create "node_a" 1
ns_create "node_b" 2

# 配置 Symmetric NAT
echo "[step] 配置 Symmetric NAT（双向）..."
nat_symmetric "node_a"
nat_symmetric "node_b"

# 启动 server
echo "[step] 启动 server..."
node_start_echo "node_b" 9100 "server"
node_wait_ready "node_b" "LISTENING" 30 && echo "[ok] server LISTENING"

# 启动 client（continuous 模式）
echo "[step] 启动 client (continuous 模式)..."
node_start_echo "node_a" 9100 "client" "node_b" "--mode" "continuous" "--interval" "1"

# 等待连接建立
echo "[step] 等待连接建立（15s）..."
sleep 15

# 检查连接状态
echo ""
echo "========== CLIENT 状态 =========="
echo "--- ECHO_OK/ECHO_FAIL/CONN_STATE ---"
grep -E 'ECHO_OK|ECHO_FAIL|CONN_STATE|CONNECTED|CLOSED' /tmp/patchbay_logs/node_a.log 2>/dev/null | head -20

echo ""
echo "--- CLIENT RECV 统计（是否收到回包）---"
grep -c 'RECV' /tmp/patchbay_logs/node_a.log 2>/dev/null || echo "0"
echo "--- CLIENT SEND 统计 ---"
grep -c 'SEND' /tmp/patchbay_logs/node_a.log 2>/dev/null || echo "0"

echo ""
echo "--- SERVER 状态（是否收到 client 数据）---"
grep -E 'ACCEPT|STREAM|ECHO|RECV' /tmp/patchbay_logs/node_b.log 2>/dev/null | head -20

echo ""
echo "--- 检查 conntrack 表 ---"
echo "node_a conntrack:"
ip netns exec pb-node_a conntrack -L 2>/dev/null | head -10 || echo "(conntrack 不可用或无表项)"
echo "node_b conntrack:"
ip netns exec pb-node_b conntrack -L 2>/dev/null | head -10 || echo "(conntrack 不可用或无表项)"

echo ""
echo "--- 检查 iptables 计数器 ---"
echo "node_a INPUT 链:"
ip netns exec pb-node_a iptables -L INPUT -v -n 2>/dev/null | head -10
echo "node_b INPUT 链:"
ip netns exec pb-node_b iptables -L INPUT -v -n 2>/dev/null | head -10

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
echo "[done] 日志保留在 /tmp/patchbay_logs/"
