#!/usr/bin/env bash
# ============================================================================
#  run_patchbay_ci.sh — patchbay 测试矩阵 CI 入口（T-LP2-004）
#
#  作用：
#    1. 检测当前运行环境是否支持 patchbay（需要 root + ip netns + iptables + tc）
#    2. 如支持，调用 linoh_patchbay.py 执行全部 S1-S8 场景
#    3. 如不支持（典型 CI 容器无 NET_ADMIN 能力），输出跳过原因并以 exit 0 退出
#       —— 避免 CI 因环境受限而红，同时保留本地/orchestrator 上的强制执行能力
#    4. 收集 JUnit XML 与文本报告，作为 CI artifact 上传
#
#  退出码：
#    0  全部场景通过 / 环境不支持已跳过
#    1  有场景失败或超时
#    2  环境检查失败（非容器受限情形）
#
#  用法：
#    bash tests/patchbay/ci/run_patchbay_ci.sh
#    LINOH_BIN=/opt/linoh/build bash tests/patchbay/ci/run_patchbay_ci.sh
#    FORCE_RUN=1 bash tests/patchbay/ci/run_patchbay_ci.sh   # 强制运行（不跳过）
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PATCHBAY_PY="${SCRIPT_DIR}/linoh_patchbay.py"
LINOH_BIN="${LINOH_BIN:-/opt/linoh/build}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/ci/output}"
JUNIT_XML="${OUTPUT_DIR}/patchbay_junit.xml"
TEXT_REPORT="${OUTPUT_DIR}/patchbay_report.txt"
JSON_REPORT="${OUTPUT_DIR}/patchbay_report.json"
SCENARIO_TIMEOUT="${SCENARIO_TIMEOUT:-300}"
FORCE_RUN="${FORCE_RUN:-0}"

mkdir -p "$OUTPUT_DIR"

echo "============================================================"
echo "  linoh patchbay CI 入口"
echo "  脚本目录:   ${SCRIPT_DIR}"
echo "  linoh 目录: ${LINOH_BIN}"
echo "  输出目录:   ${OUTPUT_DIR}"
echo "============================================================"

# ----------------------------------------------------------------------------
# 1. 依赖检查（Python / ip / iptables / tc / root）
# ----------------------------------------------------------------------------
PYTHON_BIN=""
for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1; then
        PYTHON_BIN="$c"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "[FATAL] 未找到 python3/python，patchbay 无法运行"
    exit 2
fi

echo "[ci] 使用 Python: $PYTHON_BIN ($($PYTHON_BIN --version 2>&1))"

# 检查 patchbay 主控脚本
if [ ! -f "$PATCHBAY_PY" ]; then
    echo "[FATAL] 主控脚本不存在: $PATCHBAY_PY"
    exit 2
fi

# ----------------------------------------------------------------------------
# 2. 环境能力检查（root + NET_ADMIN）
# ----------------------------------------------------------------------------
is_root=0
has_netns=0
has_iptables=0
has_tc=0

if [ "$(id -u)" -eq 0 ]; then
    is_root=1
fi
if command -v ip >/dev/null 2>&1 && ip netns list >/dev/null 2>&1; then
    has_netns=1
fi
if command -v iptables >/dev/null 2>&1 && iptables -L >/dev/null 2>&1; then
    has_iptables=1
fi
if command -v tc >/dev/null 2>&1; then
    has_tc=1
fi

echo "[ci] 环境能力: root=${is_root} netns=${has_netns} iptables=${has_iptables} tc=${has_tc}"

if [ "$FORCE_RUN" != "1" ]; then
    if [ "$is_root" -ne 1 ] || [ "$has_netns" -ne 1 ] || [ "$has_iptables" -ne 1 ] || [ "$has_tc" -ne 1 ]; then
        echo "------------------------------------------------------------"
        echo "[SKIP] 当前环境不支持 patchbay 全套场景（需要 root + ip netns + iptables + tc）"
        echo "[SKIP] 这在受限于 NET_ADMIN 的 CI 容器中属于预期行为"
        echo "[SKIP] 完整测试请在 orchestrator 上手动执行："
        echo "[SKIP]   sudo python3 ${PATCHBAY_PY} --linoh-bin ${LINOH_BIN}"
        echo "------------------------------------------------------------"

        # 生成一个最小化的 JUnit XML 以便 CI 解析
        cat > "$JUNIT_XML" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="linoh-patchbay" tests="1" failures="0" errors="0" skipped="1" time="0.0">
  <testsuite name="patchbay-environment" tests="1" failures="0" errors="0" skipped="1" time="0.0">
    <testcase name="environment-check" classname="patchbay" time="0.0">
      <skipped message="CI 容器无 NET_ADMIN 能力，patchbay 跳过" />
    </testcase>
  </testsuite>
</testsuites>
EOF
        echo "[ci] JUnit XML: $JUNIT_XML"
        echo "[ci] 跳过完成（exit 0）"
        exit 0
    fi
fi

# ----------------------------------------------------------------------------
# 3. 检查 linoh 测试二进制
# ----------------------------------------------------------------------------
linoh_test_binary=""
for name in test_tensor_stream test_tensor_stream.exe; do
    if [ -x "${LINOH_BIN}/${name}" ] || [ -f "${LINOH_BIN}/${name}" ]; then
        linoh_test_binary="${LINOH_BIN}/${name}"
        break
    fi
done

if [ -z "$linoh_test_binary" ]; then
    echo "[FATAL] 未找到 linoh 测试二进制（test_tensor_stream）于 ${LINOH_BIN}"
    echo "[FATAL] 请先在 orchestrator 上运行 build_all.sh"
    exit 2
fi
echo "[ci] linoh 测试二进制: $linoh_test_binary"

# ----------------------------------------------------------------------------
# 4. 运行 patchbay 主控脚本
# ----------------------------------------------------------------------------
echo "[ci] 启动 patchbay 全量场景（超时 ${SCENARIO_TIMEOUT}s/场景）..."

set +e
$PYTHON_BIN "$PATCHBAY_PY" \
    --linoh-bin "$LINOH_BIN" \
    --timeout "$SCENARIO_TIMEOUT" \
    --output text > "$TEXT_REPORT" 2>&1
EXIT_CODE=$?
set -e

echo "[ci] patchbay 退出码: $EXIT_CODE"
echo "------------------------------------------------------------"
cat "$TEXT_REPORT"
echo "------------------------------------------------------------"

# 生成 JSON 报告（便于 CI 解析）
set +e
$PYTHON_BIN "$PATCHBAY_PY" \
    --linoh-bin "$LINOH_BIN" \
    --timeout "$SCENARIO_TIMEOUT" \
    --output json > "$JSON_REPORT" 2>/dev/null
set -e

# ----------------------------------------------------------------------------
# 5. 转换为 JUnit XML（轻量实现，不依赖外部库）
# ----------------------------------------------------------------------------
$PYTHON_BIN - "$JSON_REPORT" "$JUNIT_XML" <<'PYEOF'
import json
import sys
import xml.etree.ElementTree as ET
from xml.dom import minidom

json_path, xml_path = sys.argv[1], sys.argv[2]

try:
    with open(json_path, "r", encoding="utf-8") as f:
        report = json.load(f)
except Exception as e:
    # JSON 不可用时，输出最小化 JUnit
    root = ET.Element("testsuites", {
        "name": "linoh-patchbay",
        "tests": "1", "failures": "1", "errors": "0", "skipped": "0", "time": "0.0",
    })
    suite = ET.SubElement(root, "testsuite", {
        "name": "patchbay-parse",
        "tests": "1", "failures": "1", "errors": "0", "skipped": "0", "time": "0.0",
    })
    tc = ET.SubElement(suite, "testcase", {
        "name": "report-parse", "classname": "patchbay", "time": "0.0",
    })
    ET.SubElement(tc, "failure", {"message": f"解析 JSON 报告失败: {e}"})
    tree = ET.ElementTree(root)
    tree.write(xml_path, encoding="utf-8", xml_declaration=True)
    sys.exit(0)

results = report.get("results", [])
total = report.get("total", len(results))
passed = report.get("passed", 0)
failed = report.get("failed", 0) + report.get("timeout", 0)
skipped = report.get("skipped", 0)
total_time = report.get("total_duration_sec", 0.0)

root = ET.Element("testsuites", {
    "name": "linoh-patchbay",
    "tests": str(total),
    "failures": str(failed),
    "errors": "0",
    "skipped": str(skipped),
    "time": f"{total_time:.2f}",
})

suite = ET.SubElement(root, "testsuite", {
    "name": "patchbay-scenarios",
    "tests": str(total),
    "failures": str(failed),
    "errors": "0",
    "skipped": str(skipped),
    "time": f"{total_time:.2f}",
    "timestamp": report.get("timestamp", ""),
})

for r in results:
    sid = r.get("scenario_id", "unknown")
    name = r.get("name", sid)
    status = r.get("status", "failed")
    dur = r.get("duration_sec", 0.0)

    tc = ET.SubElement(suite, "testcase", {
        "name": f"{sid}-{name}",
        "classname": "patchbay",
        "time": f"{dur:.2f}",
    })

    if status in ("failed", "timeout"):
        err = r.get("error", "")
        ET.SubElement(tc, "failure", {
            "message": err,
            "type": "timeout" if status == "timeout" else "assertion",
        })
        # 附加日志（截断前 2KB）
        log = r.get("log", "")
        if log:
            ET.SubElement(tc, "system-err").text = log[:2048]
    elif status == "skipped":
        err = r.get("error", "")
        ET.SubElement(tc, "skipped", {"message": err})
    elif status == "passed":
        log = r.get("log", "")
        if log:
            ET.SubElement(tc, "system-out").text = log[:2048]

rough = ET.tostring(root, encoding="utf-8")
pretty = minidom.parseString(rough).toprettyxml(indent="  ")
with open(xml_path, "w", encoding="utf-8") as f:
    f.write(pretty)
PYEOF

echo "[ci] JUnit XML:  $JUNIT_XML"
echo "[ci] 文本报告:   $TEXT_REPORT"
echo "[ci] JSON 报告:  $JSON_REPORT"

exit $EXIT_CODE
