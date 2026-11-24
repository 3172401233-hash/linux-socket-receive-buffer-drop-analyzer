"""Text report rendering: buffer curve, attribution, suggestions."""

from typing import List

from .analyzer import AnalysisResult, Cause

_BAR_WIDTH = 40
_CAUSE_LABELS = {
    Cause.SLOW_APP_READ: "应用读取慢",
    Cause.AUTOTUNING_INEFFECTIVE: "autotuning 未生效",
    Cause.CGROUP_MEMORY: "cgroup 内存不足",
    Cause.BURST: "短时突发",
    Cause.AMBIGUOUS: "待人工判断",
}


def _bar(ratio: float, width: int = _BAR_WIDTH) -> str:
    filled = int(round(max(0.0, min(1.0, ratio)) * width))
    return "#" * filled + "-" * (width - filled)


def render_curve(result: AnalysisResult) -> List[str]:
    lines = ["== 缓冲曲线（占用/有效缓冲） =="]
    header = "timestamp      occupancy   effective  ratio  bar"
    lines.append(header)
    for s in result.slices:
        m = s.metrics
        flags = []
        if s.cgroup_limited:
            flags.append("C")
        if s.app_stalled:
            flags.append("S")
        if s.autotuning_ineffective:
            flags.append("A")
        if s.burst:
            flags.append("B")
        if m.drops > 0:
            flags.append("D%d" % m.drops)
        lines.append(
            "%12.1f  %10d  %10d  %5.1f%%  |%s| %s"
            % (
                m.timestamp,
                s.occupancy_bytes,
                s.effective_buffer,
                s.occupancy_ratio * 100.0,
                _bar(s.occupancy_ratio),
                " ".join(flags),
            )
        )
    lines.append("标记: C=cgroup 受限 S=应用停顿 A=autotuning 未生效 B=突发 D=丢包数")
    return lines


def render_attribution(result: AnalysisResult) -> List[str]:
    lines = ["== 丢包归因 =="]
    total = sum(result.attribution.values())
    if total == 0:
        lines.append("总丢包: 0")
        return lines
    lines.append("总丢包: %d" % total)
    for cause in (
        Cause.SLOW_APP_READ,
        Cause.AUTOTUNING_INEFFECTIVE,
        Cause.CGROUP_MEMORY,
        Cause.BURST,
        Cause.AMBIGUOUS,
    ):
        count = result.attribution.get(cause, 0)
        pct = (count * 100.0 / total) if total else 0.0
        lines.append("  %-22s %8d  (%5.1f%%)" % (_CAUSE_LABELS[cause], count, pct))
    return lines


def render_stalls(result: AnalysisResult) -> List[str]:
    lines = ["== 应用读取停顿区间 =="]
    if not result.stall_runs:
        lines.append("无")
    for start, end in result.stall_runs:
        lines.append("  %.1f - %.1f" % (start, end))
    if result.app_stall_dominant:
        lines.append("警告: 应用停顿是主要矛盾，扩大缓冲配置不能掩盖该问题。")
    return lines


def render_manual(result: AnalysisResult) -> List[str]:
    lines = ["== 仍需人工判断的区间 =="]
    if not result.manual_intervals:
        lines.append("无")
    for start, end in result.manual_intervals:
        lines.append("  %.1f - %.1f" % (start, end))
    return lines


def render_suggestions(result: AnalysisResult) -> List[str]:
    lines = ["== 修复建议 =="]
    for i, suggestion in enumerate(result.suggestions, 1):
        lines.append("  %d. %s" % (i, suggestion))
    return lines


def render_report(result: AnalysisResult) -> str:
    sections = [
        render_curve(result),
        render_attribution(result),
        render_stalls(result),
        render_manual(result),
        render_suggestions(result),
    ]
    out: List[str] = []
    for section in sections:
        out.extend(section)
        out.append("")
    return "\n".join(out).rstrip() + "\n"
