#!/usr/bin/env python3
# train_dict.py — O1.3 协议压缩字典训练脚本（linoh 独立项目方案 W1.3）
#
# 用法（stdin/stdout 模式，脚本自身不接触任何文件路径——路径由 shell 重定向控制）：
#   python train_dict.py < 语料.jsonl > 字典.bin [--size 4096] [--min-sample 100] 2>训练报告.txt
#   语料：每行一条消息样本（JSON 文本；空行与 # 注释跳过）
#   字典二进制写 stdout（勿重定向到终端）；人读报告写 stderr
#
# 产出：zstd dictionary 二进制（fastcover 训练），经 linoh_load_protocol_dict_file()
# 加载后供两端协议字典压缩使用（两端同文件加载 → linoh_protocol_dict_info()
# 的 size/xxh64 一致性校验）。
#
# 依赖：pip install zstandard
import argparse
import sys


def main():
    ap = argparse.ArgumentParser(
        description="协议压缩字典训练（stdin 语料 → stdout 字典）")
    ap.add_argument("--size", type=int, default=4096)
    ap.add_argument("--min-sample", type=int, default=100)
    args = ap.parse_args()

    try:
        import zstandard as zstd
    except ImportError:
        sys.exit("需要 zstandard 库：pip install zstandard")

    samples = []
    for raw in sys.stdin.buffer.read().splitlines():
        line = raw.decode("utf-8", errors="replace").strip()
        if not line or line.startswith("#"):
            continue
        samples.append(line.encode("utf-8"))
    if len(samples) < args.min_sample:
        sys.exit(f"样本不足：{len(samples)} < {args.min_sample}"
                 "（fastcover 建议 ≥100 条结构化变体）")

    try:
        trainer = zstd.train_dictionary(args.size, samples, level=3)
    except Exception:  # zstandard 版本差异
        try:
            trainer = zstd.train_dictionary(args.size, samples)
        except Exception as e2:
            sys.exit(f"训练失败: {e2}")

    data = trainer.as_bytes()
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    print(f"OK: {len(data)} 字节字典已写 stdout（样本 {len(samples)} 条）",
          file=sys.stderr)
    try:
        import xxhash  # 可选：与 linoh_protocol_dict_info 的 XXH64 对齐
        print(f"XXH64={xxhash.xxh64(data).intdigest():016x}", file=sys.stderr)
        print("两端部署校验：linoh_protocol_dict_info() 的 size/xxh64 须一致",
              file=sys.stderr)
    except ImportError:
        print("（未装 xxhash：跳过 XXH64 校验值输出）", file=sys.stderr)


if __name__ == "__main__":
    main()
