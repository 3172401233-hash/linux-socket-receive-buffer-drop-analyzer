"""CLI entry: python -m rcvbuf_analyzer input.json"""

import argparse
import json
import sys

from .analyzer import analyze
from .model import AnalyzerInput
from .report import render_report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="rcvbuf_analyzer",
        description="离线分析 socket 接收缓冲与丢包归因（只读取离线指标文件）",
    )
    parser.add_argument("input", help="包含 config 与 slices 的 JSON 指标文件")
    parser.add_argument("-o", "--output", help="报告输出路径（默认 stdout）")
    args = parser.parse_args(argv)

    with open(args.input, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    data = AnalyzerInput.from_dict(payload)
    if not data.slices:
        print("输入文件不包含任何时间片", file=sys.stderr)
        return 2
    result = analyze(data.slices, data.config)
    report = render_report(result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
    else:
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
