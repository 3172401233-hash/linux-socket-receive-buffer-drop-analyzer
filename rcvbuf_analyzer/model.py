"""Data model for offline receive-buffer analysis (Python 3.8.2)."""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class SliceMetrics:
    """Metrics exported for one time slice."""

    timestamp: float
    bytes_arrived: int
    bytes_read: int
    sk_rcvbuf: int
    rmem_max: int
    rmem_default: int
    autotuning_enabled: bool
    cgroup_usage: int
    cgroup_limit: int
    cgroup_stall_ms: float
    skb_total: int
    skb_merged: int
    drops: int

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "SliceMetrics":
        return cls(
            timestamp=float(raw["timestamp"]),
            bytes_arrived=int(raw["bytes_arrived"]),
            bytes_read=int(raw["bytes_read"]),
            sk_rcvbuf=int(raw["sk_rcvbuf"]),
            rmem_max=int(raw["rmem_max"]),
            rmem_default=int(raw["rmem_default"]),
            autotuning_enabled=bool(raw["autotuning_enabled"]),
            cgroup_usage=int(raw["cgroup_usage"]),
            cgroup_limit=int(raw["cgroup_limit"]),
            cgroup_stall_ms=float(raw.get("cgroup_stall_ms", 0.0)),
            skb_total=int(raw.get("skb_total", 0)),
            skb_merged=int(raw.get("skb_merged", 0)),
            drops=int(raw.get("drops", 0)),
        )


@dataclass
class AnalyzerConfig:
    """Tunable thresholds for the heuristic classifier."""

    slice_duration_s: float = 1.0
    saturation_ratio: float = 0.9
    slow_read_ratio: float = 0.5
    cgroup_usage_ratio: float = 0.9
    cgroup_stall_ms_threshold: float = 1.0
    burst_factor: float = 3.0
    burst_window: int = 5
    min_stall_slices: int = 3

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "AnalyzerConfig":
        cfg = cls()
        for key in (
            "slice_duration_s",
            "saturation_ratio",
            "slow_read_ratio",
            "cgroup_usage_ratio",
            "cgroup_stall_ms_threshold",
            "burst_factor",
            "burst_window",
            "min_stall_slices",
        ):
            if key in raw:
                setattr(cfg, key, type(getattr(cfg, key))(raw[key]))
        return cfg


@dataclass
class AnalyzerInput:
    slices: List[SliceMetrics] = field(default_factory=list)
    config: AnalyzerConfig = field(default_factory=AnalyzerConfig)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "AnalyzerInput":
        slices = [SliceMetrics.from_dict(s) for s in raw.get("slices", [])]
        slices.sort(key=lambda s: s.timestamp)
        config = AnalyzerConfig.from_dict(raw.get("config", {}))
        return cls(slices=slices, config=config)
