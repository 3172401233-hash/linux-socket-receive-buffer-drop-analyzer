"""Per-slice effective-buffer computation and drop attribution."""

import enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .model import AnalyzerConfig, SliceMetrics


class Cause(enum.Enum):
    SLOW_APP_READ = "slow_app_read"
    AUTOTUNING_INEFFECTIVE = "autotuning_ineffective"
    CGROUP_MEMORY = "cgroup_memory"
    BURST = "burst"
    AMBIGUOUS = "ambiguous"


@dataclass
class SliceAnalysis:
    metrics: SliceMetrics
    occupancy_bytes: int
    sysctl_buffer: int
    effective_buffer: int
    cgroup_limited: bool
    autotuning_ineffective: bool
    app_stalled: bool
    burst: bool
    cause: Optional[Cause]
    competing_causes: List[Cause] = field(default_factory=list)

    @property
    def occupancy_ratio(self) -> float:
        if self.effective_buffer <= 0:
            return 1.0 if self.occupancy_bytes > 0 else 0.0
        return min(1.0, self.occupancy_bytes / float(self.effective_buffer))


@dataclass
class AnalysisResult:
    slices: List[SliceAnalysis]
    attribution: Dict[Cause, int]
    stall_runs: List[Tuple[float, float]]
    manual_intervals: List[Tuple[float, float]]
    suggestions: List[str]
    app_stall_dominant: bool


def _sysctl_buffer(m: SliceMetrics) -> int:
    return min(m.sk_rcvbuf, m.rmem_max)


def _cgroup_limited(m: SliceMetrics, cfg: AnalyzerConfig) -> bool:
    if m.cgroup_limit <= 0:
        return False
    usage_ratio = m.cgroup_usage / float(m.cgroup_limit)
    return (
        usage_ratio >= cfg.cgroup_usage_ratio
        or m.cgroup_stall_ms >= cfg.cgroup_stall_ms_threshold
    )


def _effective_buffer(m: SliceMetrics, cfg: AnalyzerConfig) -> Tuple[int, bool]:
    buf = _sysctl_buffer(m)
    limited = _cgroup_limited(m, cfg)
    if limited:
        headroom = max(0, m.cgroup_limit - m.cgroup_usage)
        buf = min(buf, headroom)
    return buf, limited


def _autotuning_ineffective(
    m: SliceMetrics, cfg: AnalyzerConfig, occupancy: int, sysctl_buf: int
) -> bool:
    saturated = sysctl_buf > 0 and occupancy >= cfg.saturation_ratio * sysctl_buf
    if not saturated:
        return False
    stuck_at_default = m.sk_rcvbuf <= m.rmem_default
    headroom_available = m.rmem_max > m.sk_rcvbuf
    if not m.autotuning_enabled:
        return headroom_available
    return stuck_at_default and headroom_available


def _app_stalled(m: SliceMetrics, cfg: AnalyzerConfig, occupancy: int, eff: int) -> bool:
    if m.bytes_arrived <= 0:
        return False
    reads_lagging = m.bytes_read < cfg.slow_read_ratio * m.bytes_arrived
    buffer_full = eff <= 0 or occupancy >= cfg.saturation_ratio * eff
    return reads_lagging and buffer_full


def _is_burst(
    index: int,
    slices: List[SliceMetrics],
    cfg: AnalyzerConfig,
    baseline: List[float],
) -> bool:
    m = slices[index]
    start = max(0, index - cfg.burst_window)
    history = baseline[start:index]
    if not history:
        return False
    mean = sum(history) / len(history)
    if mean <= 0:
        return False
    return m.bytes_arrived > cfg.burst_factor * mean


def _classify(
    m: SliceMetrics,
    cfg: AnalyzerConfig,
    occupancy: int,
    eff: int,
    cgroup_limited: bool,
    autotuning_bad: bool,
    stalled: bool,
    burst: bool,
) -> Tuple[Optional[Cause], List[Cause]]:
    if m.drops <= 0:
        return None, []
    candidates: List[Cause] = []
    if cgroup_limited:
        candidates.append(Cause.CGROUP_MEMORY)
    if stalled:
        candidates.append(Cause.SLOW_APP_READ)
    if autotuning_bad:
        candidates.append(Cause.AUTOTUNING_INEFFECTIVE)
    if burst:
        candidates.append(Cause.BURST)
    if not candidates:
        return Cause.AMBIGUOUS, []
    if len(candidates) > 1:
        return Cause.AMBIGUOUS, candidates
    return candidates[0], []


def _stall_runs(slices: List[SliceAnalysis], cfg: AnalyzerConfig) -> List[Tuple[float, float]]:
    runs: List[Tuple[float, float]] = []
    run_start: Optional[float] = None
    last_ts: Optional[float] = None
    run_len = 0
    for s in slices:
        if s.app_stalled:
            if run_start is None:
                run_start = s.metrics.timestamp
                run_len = 0
            run_len += 1
            last_ts = s.metrics.timestamp
        else:
            if run_start is not None and run_len >= cfg.min_stall_slices:
                runs.append((run_start, last_ts if last_ts is not None else run_start))
            run_start = None
            run_len = 0
    if run_start is not None and run_len >= cfg.min_stall_slices:
        runs.append((run_start, last_ts if last_ts is not None else run_start))
    return runs


def _build_suggestions(
    result_slices: List[SliceAnalysis],
    attribution: Dict[Cause, int],
    stall_runs: List[Tuple[float, float]],
) -> Tuple[List[str], bool]:
    suggestions: List[str] = []
    total_drops = sum(attribution.values())
    app_stall_dominant = bool(stall_runs) and (
        total_drops == 0
        or attribution.get(Cause.SLOW_APP_READ, 0) >= total_drops * 0.5
        or attribution.get(Cause.AMBIGUOUS, 0) > 0
    )

    if stall_runs:
        suggestions.append(
            "检测到应用读取停顿（连续时间片读取速率远低于到达速率且缓冲饱和）。"
            "优先排查应用线程调度、GC 暂停或锁竞争；仅扩大 rmem/sk_rcvbuf 只会推迟丢包，"
            "不能掩盖应用停顿，相关扩容建议已降级为辅助手段。"
        )
    if attribution.get(Cause.CGROUP_MEMORY, 0) > 0:
        suggestions.append(
            "cgroup 内存接近上限或存在 memory stall：提高 cgroup memory.limit、"
            "检查是否有内存泄漏，或降低单 socket 缓冲以适配限额。"
        )
    if attribution.get(Cause.AUTOTUNING_INEFFECTIVE, 0) > 0:
        suggestions.append(
            "autotuning 未生效：确认 net.ipv4.tcp_moderate_rcvbuf=1，"
            "且应用未通过 SO_RCVBUF 固定缓冲（固定值会禁用 autotuning）；"
            "必要时提高 net.core.rmem_max / net.ipv4.tcp_rmem 上限。"
        )
    if attribution.get(Cause.BURST, 0) > 0:
        suggestions.append(
            "短时突发导致丢包：评估 GRO/中断合并与 skb 合并效率，"
            "必要时平滑发送端或临时增大缓冲吸收尖峰。"
        )
    if attribution.get(Cause.AMBIGUOUS, 0) > 0:
        suggestions.append(
            "存在多种因素同时成立或证据不足的时间片，已列入人工判断区间，"
            "建议结合 perf/ss -ti 与 cgroup memory.stat 进一步确认。"
        )
    if not suggestions:
        suggestions.append("未检测到丢包或明确的缓冲瓶颈，当前配置与读取速率匹配。")
    return suggestions, app_stall_dominant


def analyze(slices: List[SliceMetrics], cfg: Optional[AnalyzerConfig] = None) -> AnalysisResult:
    cfg = cfg or AnalyzerConfig()
    results: List[SliceAnalysis] = []
    attribution: Dict[Cause, int] = {c: 0 for c in Cause}
    occupancy = 0
    baseline: List[float] = []

    for index, m in enumerate(slices):
        occupancy = max(0, occupancy + m.bytes_arrived - m.bytes_read)
        eff, cgroup_limited = _effective_buffer(m, cfg)
        sysctl_buf = _sysctl_buffer(m)
        autotuning_bad = _autotuning_ineffective(m, cfg, occupancy, sysctl_buf)
        stalled = _app_stalled(m, cfg, occupancy, eff)
        burst = _is_burst(index, slices, cfg, baseline)
        cause, competing = _classify(
            m, cfg, occupancy, eff, cgroup_limited, autotuning_bad, stalled, burst
        )
        if cause is not None:
            attribution[cause] += m.drops
        results.append(
            SliceAnalysis(
                metrics=m,
                occupancy_bytes=occupancy,
                sysctl_buffer=sysctl_buf,
                effective_buffer=eff,
                cgroup_limited=cgroup_limited,
                autotuning_ineffective=autotuning_bad,
                app_stalled=stalled,
                burst=burst,
                cause=cause,
                competing_causes=competing,
            )
        )
        baseline.append(float(m.bytes_arrived))

    stall_runs = _stall_runs(results, cfg)
    manual_intervals = [
        (s.metrics.timestamp, s.metrics.timestamp)
        for s in results
        if s.cause == Cause.AMBIGUOUS
    ]
    suggestions, app_stall_dominant = _build_suggestions(results, attribution, stall_runs)
    return AnalysisResult(
        slices=results,
        attribution=attribution,
        stall_runs=stall_runs,
        manual_intervals=manual_intervals,
        suggestions=suggestions,
        app_stall_dominant=app_stall_dominant,
    )
