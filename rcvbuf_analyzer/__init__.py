"""Offline analyzer for socket receive-buffer drops.

Consumes exported metrics (sk_rcvbuf, rmem, autotuning state, cgroup
memory pressure, application read rate, skb coalescing and drop
counters) and attributes drops per time slice. It never touches a live
system; all inputs come from files.
"""

from .model import SliceMetrics, AnalyzerConfig
from .analyzer import analyze, AnalysisResult, SliceAnalysis, Cause

__all__ = [
    "SliceMetrics",
    "AnalyzerConfig",
    "analyze",
    "AnalysisResult",
    "SliceAnalysis",
    "Cause",
]

__version__ = "0.1.0"
