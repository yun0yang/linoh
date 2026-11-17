#!/usr/bin/env python3
"""
linoh_patchbay.py — linoh NAT 穿透自动化测试矩阵主控脚本（T-LP2-002）

借鉴 iroh patchbay 测试床，使用 Linux 网络命名空间（ip netns）+ iptables + tc netem
模拟 8 种 NAT/网络场景，验证 linoh NAT 穿透、relay 故障切换、OOS 恢复等能力。

部署位置：orchestrator（203.0.113.10），需 root 权限 + linoh Linux 编译版本

用法：
    sudo python3 linoh_patchbay.py                      # 运行全部场景
    sudo python3 linoh_patchbay.py --scenario S1        # 运行指定场景
    sudo python3 linoh_patchbay.py --list               # 列出所有场景
    sudo python3 linoh_patchbay.py --timeout 300        # 设置全局超时（秒）
    sudo python3 linoh_patchbay.py --output json        # JSON 输出
    sudo python3 linoh_patchbay.py --linoh-bin /opt/linoh/build  # 指定 linoh 构建目录

场景定义（S1-S8）：
    S1  FullCone ↔ FullCone（基线直连）
    S2  Symmetric ↔ FullCone（端口预测）
    S3  Symmetric ↔ Symmetric（双向 Hard-NAT，relay 兜底）
    S4  网络切换（IP 变化，触发 on_network_change + 重连）
    S5  relay 故障切换（主 relay 宕机，切换备 relay）
    S6  OOS 空洞恢复（注入乱序，30s 内填补或回调）
    S7  PTO 超时恢复（注入 5s 丢包，10s 内恢复）
    S8  5 节点 PP 菊花链端到端（与 LLMPP 联合测试）

依赖：
    - Linux 内核 ≥ 4.18（ip netns / iptables / tc netem）
    - Python ≥ 3.8
    - linoh Linux 编译版本（build_all.sh 产物）
    - root 权限（网络命名空间操作）

退出码：
    0  全部场景通过
    1  有场景失败
    2  环境检查失败
    3  参数错误
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Dict, Tuple

# ============================================================================
# 常量定义
# ============================================================================

SCRIPT_DIR = Path(__file__).parent.resolve()
SCENARIOS_DIR = SCRIPT_DIR / "scenarios"
LIB_DIR = SCRIPT_DIR / "lib"
DEFAULT_LINOH_BIN = Path("/opt/linoh/build")
DEFAULT_TIMEOUT = 300  # 单场景默认超时 5 分钟
CLEANUP_TIMEOUT = 30   # 清理超时

# 场景定义：ID → (名称, 描述, 脚本文件名)
SCENARIOS = [
    ("S1", "FullCone ↔ FullCone（基线直连）",
     "应直连成功", "S1_fullcone_fullcone.sh"),
    ("S2", "Symmetric ↔ FullCone（端口预测）",
     "应直连或 relay", "S2_symmetric_fullcone.sh"),
    ("S3", "Symmetric ↔ Symmetric（双向 Hard-NAT）",
     "应 relay 兜底", "S3_symmetric_symmetric.sh"),
    ("S4", "网络切换（IP 变化）",
     "应触发 on_network_change + 重连", "S4_network_change.sh"),
    ("S5", "relay 故障切换（主 relay 宕机）",
     "应切换备 relay", "S5_relay_failover.sh"),
    ("S6", "OOS 空洞恢复（注入乱序）",
     "应 30s 内填补或回调", "S6_oos_recovery.sh"),
    ("S7", "PTO 超时恢复（注入 5s 丢包）",
     "应在 10s 内恢复", "S7_pto_recovery.sh"),
    ("S8", "5 节点 PP 菊花链端到端",
     "与 LLMPP 联合测试", "S8_pp_chain.sh"),
]


# ============================================================================
# 数据结构
# ============================================================================

@dataclass
class ScenarioResult:
    """单个场景的测试结果"""
    scenario_id: str
    name: str
    description: str
    expected: str
    status: str = "pending"  # pending / running / passed / failed / skipped / timeout
    duration_sec: float = 0.0
    log: str = ""
    error: str = ""
    timestamp: str = ""


@dataclass
class TestReport:
    """完整测试报告"""
    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    timeout: int = 0
    total_duration_sec: float = 0.0
    results: List[ScenarioResult] = field(default_factory=list)
    timestamp: str = ""


# ============================================================================
# 环境检查
# ============================================================================

def check_root() -> bool:
    """检查是否以 root 运行"""
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def check_command(cmd: str) -> bool:
    """检查命令是否存在"""
    return shutil.which(cmd) is not None


def check_environment(linoh_bin: Path) -> Tuple[bool, List[str]]:
    """环境检查，返回 (是否通过, 错误列表)"""
    errors = []

    if not check_root():
        errors.append("需要 root 权限（网络命名空间操作）")

    required_commands = ["ip", "iptables", "tc", "bash"]
    for cmd in required_commands:
        if not check_command(cmd):
            errors.append(f"缺少命令: {cmd}")

    # 检查 linoh 二进制
    linoh_test = linoh_bin / "test_tensor_stream.exe"
    if not linoh_test.exists():
        # Linux 上可能是无扩展名
        linoh_test = linoh_bin / "test_tensor_stream"
    if not linoh_test.exists():
        errors.append(f"linoh 测试二进制不存在: {linoh_test}")

    return len(errors) == 0, errors


# ============================================================================
# 网络命名空间管理
# ============================================================================

def cleanup_all_netns() -> int:
    """清理所有 linoh_patchbay 相关的网络命名空间"""
    cleaned = 0
    try:
        result = subprocess.run(
            ["ip", "netns", "list"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            ns_name = line.split()[0]
            if ns_name.startswith("pb-"):  # patchbay 命名空间前缀
                subprocess.run(
                    ["ip", "netns", "del", ns_name],
                    capture_output=True, timeout=10
                )
                cleaned += 1
    except Exception as e:
        print(f"  [WARN] 清理网络命名空间时出错: {e}", file=sys.stderr)
    return cleaned


def cleanup_iptables() -> int:
    """清理 patchbay 相关的 iptables 规则"""
    cleaned = 0
    try:
        # 清理 nat 表中带 pb- 标记的规则
        for table in ["nat", "mangle", "filter"]:
            result = subprocess.run(
                ["iptables", "-t", table, "-S"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.strip().split("\n"):
                if "pb-" in line and line.startswith("-A"):
                    # 删除规则
                    del_rule = line.replace("-A", "-D", 1)
                    subprocess.run(
                        ["iptables", "-t", table] + del_rule.split()[1:],
                        capture_output=True, timeout=10
                    )
                    cleaned += 1
    except Exception as e:
        print(f"  [WARN] 清理 iptables 规则时出错: {e}", file=sys.stderr)
    return cleaned


# ============================================================================
# 场景执行
# ============================================================================

def find_scenario_script(scenario_id: str) -> Optional[Path]:
    """查找场景脚本"""
    for sid, _, _, script_name in SCENARIOS:
        if sid == scenario_id:
            script_path = SCENARIOS_DIR / script_name
            return script_path if script_path.exists() else None
    return None


def run_scenario(
    scenario_id: str,
    name: str,
    description: str,
    expected: str,
    script_path: Path,
    linoh_bin: Path,
    timeout: int,
) -> ScenarioResult:
    """执行单个场景"""
    result = ScenarioResult(
        scenario_id=scenario_id,
        name=name,
        description=description,
        expected=expected,
        status="running",
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
    )

    print(f"\n{'='*60}")
    print(f"  场景 {scenario_id}: {name}")
    print(f"  预期: {expected}")
    print(f"{'='*60}")

    start_time = time.time()

    try:
        # 执行场景脚本
        env = os.environ.copy()
        env["LINOH_BIN"] = str(linoh_bin)
        env["PATCHBAY_DIR"] = str(SCRIPT_DIR)
        env["SCENARIO_ID"] = scenario_id

        proc = subprocess.run(
            ["bash", str(script_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )

        result.duration_sec = time.time() - start_time
        result.log = proc.stdout + proc.stderr

        if proc.returncode == 0:
            result.status = "passed"
            print(f"  [PASS] {scenario_id} ({result.duration_sec:.1f}s)")
        else:
            result.status = "failed"
            result.error = f"脚本退出码: {proc.returncode}"
            print(f"  [FAIL] {scenario_id} ({result.duration_sec:.1f}s)")
            # 输出最后 20 行日志
            log_lines = result.log.strip().split("\n")
            for line in log_lines[-20:]:
                print(f"    {line}")

    except subprocess.TimeoutExpired:
        result.duration_sec = time.time() - start_time
        result.status = "timeout"
        result.error = f"场景超时（{timeout}s）"
        print(f"  [TIMEOUT] {scenario_id} ({timeout}s)")
    except Exception as e:
        result.duration_sec = time.time() - start_time
        result.status = "failed"
        result.error = str(e)
        print(f"  [ERROR] {scenario_id}: {e}")
    finally:
        # 每个场景后清理资源
        cleanup_all_netns()
        cleanup_iptables()

    return result


# ============================================================================
# 报告生成
# ============================================================================

def generate_report(results: List[ScenarioResult], output_format: str) -> str:
    """生成测试报告"""
    report = TestReport(
        total=len(results),
        passed=sum(1 for r in results if r.status == "passed"),
        failed=sum(1 for r in results if r.status == "failed"),
        skipped=sum(1 for r in results if r.status == "skipped"),
        timeout=sum(1 for r in results if r.status == "timeout"),
        total_duration_sec=sum(r.duration_sec for r in results),
        results=results,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
    )

    if output_format == "json":
        return json.dumps(asdict(report), indent=2, ensure_ascii=False)
    else:
        # 文本格式
        lines = [
            "=" * 60,
            "  linoh patchbay 测试报告",
            f"  时间: {report.timestamp}",
            f"  总场景: {report.total}",
            f"  通过: {report.passed}",
            f"  失败: {report.failed}",
            f"  超时: {report.timeout}",
            f"  跳过: {report.skipped}",
            f"  总耗时: {report.total_duration_sec:.1f}s",
            "=" * 60,
            "",
        ]
        for r in results:
            status_icon = {
                "passed": "✅",
                "failed": "❌",
                "timeout": "⏰",
                "skipped": "⏭️",
            }.get(r.status, "❓")
            lines.append(f"  {status_icon} {r.scenario_id}: {r.name} ({r.duration_sec:.1f}s)")
            if r.status in ("failed", "timeout") and r.error:
                lines.append(f"      错误: {r.error}")
        lines.append("")
        lines.append("=" * 60)
        return "\n".join(lines)


# ============================================================================
# 主函数
# ============================================================================

def list_scenarios():
    """列出所有场景"""
    print(f"\nlinoh patchbay 场景列表（共 {len(SCENARIOS)} 个）\n")
    print(f"{'ID':<6} {'名称':<40} {'预期行为':<30}")
    print("-" * 80)
    for sid, name, expected, _ in SCENARIOS:
        print(f"{sid:<6} {name:<40} {expected:<30}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="linoh patchbay NAT 穿透自动化测试矩阵",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scenario", "-s",
        help="指定场景 ID（如 S1），不指定则运行全部",
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="列出所有场景",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"单场景超时秒数（默认 {DEFAULT_TIMEOUT}）",
    )
    parser.add_argument(
        "--output", "-o",
        choices=["text", "json"],
        default="text",
        help="输出格式（默认 text）",
    )
    parser.add_argument(
        "--linoh-bin",
        type=Path,
        default=DEFAULT_LINOH_BIN,
        help=f"linoh 构建目录（默认 {DEFAULT_LINOH_BIN}）",
    )
    parser.add_argument(
        "--skip-cleanup",
        action="store_true",
        help="跳过测试后清理（调试用）",
    )
    parser.add_argument(
        "--no-env-check",
        action="store_true",
        help="跳过环境检查（调试用）",
    )

    args = parser.parse_args()

    # --list
    if args.list:
        list_scenarios()
        return 0

    # 环境检查
    if not args.no_env_check:
        print("环境检查...")
        ok, errors = check_environment(args.linoh_bin)
        if not ok:
            print("环境检查失败:")
            for e in errors:
                print(f"  - {e}")
            return 2
        print("环境检查通过\n")

    # 运行前清理
    if not args.skip_cleanup:
        print("运行前清理资源...")
        ns_cleaned = cleanup_all_netns()
        ipt_cleaned = cleanup_iptables()
        if ns_cleaned or ipt_cleaned:
            print(f"  清理了 {ns_cleaned} 个命名空间, {ipt_cleaned} 条 iptables 规则")
        print()

    # 选择场景
    if args.scenario:
        scenarios_to_run = [(s[0], s[1], s[2], s[3]) for s in SCENARIOS if s[0] == args.scenario]
        if not scenarios_to_run:
            print(f"错误: 未知场景 ID '{args.scenario}'")
            print(f"可用场景: {', '.join(s[0] for s in SCENARIOS)}")
            return 3
    else:
        scenarios_to_run = SCENARIOS

    # 执行场景
    results: List[ScenarioResult] = []
    total_start = time.time()

    for sid, name, expected, script_name in scenarios_to_run:
        script_path = SCENARIOS_DIR / script_name
        if not script_path.exists():
            result = ScenarioResult(
                scenario_id=sid,
                name=name,
                description=expected,
                expected=expected,
                status="skipped",
                error=f"脚本不存在: {script_path}",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
            )
            results.append(result)
            print(f"  [SKIP] {sid}: 脚本不存在")
            continue

        result = run_scenario(
            sid, name, expected, expected, script_path,
            args.linoh_bin, args.timeout,
        )
        results.append(result)

    total_duration = time.time() - total_start

    # 运行后清理
    if not args.skip_cleanup:
        print("\n运行后清理资源...")
        cleanup_all_netns()
        cleanup_iptables()

    # 生成报告
    print()
    report = generate_report(results, args.output)
    print(report)

    # 返回码
    failed_count = sum(1 for r in results if r.status in ("failed", "timeout"))
    return 0 if failed_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
