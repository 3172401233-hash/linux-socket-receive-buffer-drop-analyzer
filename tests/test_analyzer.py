import unittest

from rcvbuf_analyzer import AnalyzerConfig, Cause, SliceMetrics, analyze
from rcvbuf_analyzer.report import render_report


def make_slice(ts, arrived, read, drops=0, **overrides):
    params = dict(
        timestamp=float(ts),
        bytes_arrived=arrived,
        bytes_read=read,
        sk_rcvbuf=1 << 20,
        rmem_max=4 << 20,
        rmem_default=212992,
        autotuning_enabled=True,
        cgroup_usage=100 << 20,
        cgroup_limit=512 << 20,
        cgroup_stall_ms=0.0,
        skb_total=1000,
        skb_merged=600,
        drops=drops,
    )
    params.update(overrides)
    return SliceMetrics(**params)


class SlowReadTest(unittest.TestCase):
    def test_slow_app_read_attribution(self):
        slices = [
            make_slice(i, arrived=200000, read=20000, drops=50) for i in range(8)
        ]
        result = analyze(slices)
        self.assertGreater(result.attribution[Cause.SLOW_APP_READ], 0)
        self.assertEqual(result.attribution[Cause.CGROUP_MEMORY], 0)
        self.assertTrue(result.stall_runs)
        self.assertTrue(result.app_stall_dominant)
        joined = "\n".join(result.suggestions)
        self.assertIn("应用", joined)
        self.assertIn("不能掩盖", joined)

    def test_healthy_reader_no_drops(self):
        slices = [make_slice(i, arrived=100000, read=100000) for i in range(5)]
        result = analyze(slices)
        self.assertEqual(sum(result.attribution.values()), 0)
        self.assertFalse(result.stall_runs)
        for s in result.slices:
            self.assertIsNone(s.cause)


class CgroupThrottleTest(unittest.TestCase):
    def test_cgroup_memory_attribution(self):
        limit = 100 << 20
        slices = [
            make_slice(
                i,
                arrived=80000,
                read=80000,
                drops=30,
                cgroup_usage=limit - (512 << 10),
                cgroup_limit=limit,
                cgroup_stall_ms=5.0,
            )
            for i in range(4)
        ]
        result = analyze(slices)
        self.assertGreater(result.attribution[Cause.CGROUP_MEMORY], 0)
        for s in result.slices:
            self.assertTrue(s.cgroup_limited)
            self.assertLess(s.effective_buffer, s.sysctl_buffer)

    def test_effective_buffer_capped_by_cgroup_headroom(self):
        limit = 100 << 20
        m = make_slice(
            0,
            arrived=1000,
            read=1000,
            cgroup_usage=limit - 1024,
            cgroup_limit=limit,
        )
        result = analyze([m])
        self.assertEqual(result.slices[0].effective_buffer, 1024)


class BurstTrafficTest(unittest.TestCase):
    def test_burst_attribution(self):
        slices = [make_slice(i, arrived=10000, read=10000) for i in range(6)]
        slices.append(make_slice(6, arrived=200000, read=10000, drops=80))
        result = analyze(slices)
        self.assertGreater(result.attribution[Cause.BURST], 0)
        self.assertTrue(result.slices[-1].burst)

    def test_steady_traffic_not_burst(self):
        slices = [make_slice(i, arrived=10000, read=10000) for i in range(8)]
        result = analyze(slices)
        self.assertFalse(any(s.burst for s in result.slices))


class AutotuningTest(unittest.TestCase):
    def test_autotuning_disabled_attribution(self):
        slices = [
            make_slice(
                i,
                arrived=250000,
                read=130000,
                drops=20,
                autotuning_enabled=False,
                sk_rcvbuf=212992,
            )
            for i in range(6)
        ]
        result = analyze(slices)
        self.assertGreater(result.attribution[Cause.AUTOTUNING_INEFFECTIVE], 0)

    def test_autotuning_stuck_at_default(self):
        slices = [
            make_slice(i, arrived=250000, read=130000, drops=20, sk_rcvbuf=212992)
            for i in range(6)
        ]
        result = analyze(slices)
        self.assertTrue(any(s.autotuning_ineffective for s in result.slices))


class AmbiguousTest(unittest.TestCase):
    def test_competing_causes_go_to_manual(self):
        limit = 100 << 20
        slices = [
            make_slice(
                i,
                arrived=200000,
                read=20000,
                drops=40,
                cgroup_usage=int(limit * 0.99),
                cgroup_limit=limit,
                cgroup_stall_ms=3.0,
            )
            for i in range(8)
        ]
        result = analyze(slices)
        self.assertGreater(result.attribution[Cause.AMBIGUOUS], 0)
        self.assertTrue(result.manual_intervals)
        ambiguous = [s for s in result.slices if s.cause == Cause.AMBIGUOUS]
        competing = ambiguous[0].competing_causes
        self.assertIn(Cause.CGROUP_MEMORY, competing)
        self.assertIn(Cause.SLOW_APP_READ, competing)

    def test_unexplained_drops_go_to_manual(self):
        slices = [make_slice(i, arrived=1000, read=1000, drops=10) for i in range(3)]
        result = analyze(slices)
        self.assertEqual(result.attribution[Cause.AMBIGUOUS], 30)
        self.assertEqual(len(result.manual_intervals), 3)


class ReportTest(unittest.TestCase):
    def test_report_sections(self):
        slices = [
            make_slice(i, arrived=200000, read=20000, drops=50) for i in range(6)
        ]
        text = render_report(analyze(slices))
        for section in ("缓冲曲线", "丢包归因", "修复建议", "人工判断", "停顿"):
            self.assertIn(section, text)


if __name__ == "__main__":
    unittest.main()
