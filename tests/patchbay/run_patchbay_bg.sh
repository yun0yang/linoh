#!/bin/bash
# run_patchbay_bg.sh — 后台运行 patchbay 全量测试
# 用法: bash run_patchbay_bg.sh
set -uo pipefail

LOG_FILE="/tmp/patchbay_run.log"
JSON_FILE="/tmp/patchbay_run.json"

# 清理残留
pkill -f 'linoh_patchbay.py' 2>/dev/null || true
sleep 1

cd /root/linoh/tests/patchbay

# 启动 patchbay 测试（后台运行，无缓冲输出）
nohup env PYTHONUNBUFFERED=1 python3 -u linoh_patchbay.py \
    --linoh-bin /root/linoh/build \
    --timeout 300 \
    --output text \
    > "$LOG_FILE" 2>&1 &

PATCHBAY_PID=$!
echo "$PATCHBAY_PID" > /tmp/patchbay.pid
echo "[INFO] patchbay 测试已启动 PID=$PATCHBAY_PID"
echo "[INFO] 日志文件: $LOG_FILE"
echo "[INFO] 监控: tail -f $LOG_FILE"
