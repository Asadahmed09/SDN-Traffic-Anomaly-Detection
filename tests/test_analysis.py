import unittest

from analysis.detector import AnomalyDetector, DetectorConfig
from analysis.features import FeatureExtractor
from analysis.records import FlowStatSample, PORT_SCAN, SYN_HEAVY

SYN_FLAGS = (0x002, 0x012)
H1, H2 = "10.0.1.11", "10.0.1.66"
H3 = "10.0.2.10"
POLL = 0.25


def syn_sample(ts, dpid, src, dst, dport, packets, duration=1.0):
    """A table-0 SYN monitor flow as the switch would report it."""
    return FlowStatSample(
        timestamp=ts, dpid=dpid, table_id=0, priority=10, duration_s=duration,
        idle_timeout=15, packet_count=packets, byte_count=packets * 60,
        match={"eth_type": 0x0800, "ip_proto": 6, "ipv4_src": src,
               "ipv4_dst": dst, "tcp_dst": dport, "tcp_flags": SYN_FLAGS})


def l2_sample(ts, dpid, packets, duration=5.0):
    """A table-1 forwarding flow (no IP/TCP fields)."""
    return FlowStatSample(
        timestamp=ts, dpid=dpid, table_id=1, priority=1, duration_s=duration,
        idle_timeout=0, packet_count=packets, byte_count=packets * 1000,
        match={"in_port": 1, "eth_src": "00:00:00:00:00:01",
               "eth_dst": "00:00:00:00:00:02"})


class FeatureTests(unittest.TestCase):

    def test_first_sample_and_deltas(self):
        fx = FeatureExtractor(default_interval_s=0.25)
        f1 = fx.update(1, 100.0, [syn_sample(100.0, 1, H1, H3, 80, 3)])[0]
        self.assertEqual(f1.delta_packets, 3)          # first sight = whole counter
        self.assertAlmostEqual(f1.interval_s, 0.25)    # default interval
        self.assertAlmostEqual(f1.packet_rate_pps, 12.0)

        f2 = fx.update(1, 100.5, [syn_sample(100.5, 1, H1, H3, 80, 13, 1.5)])[0]
        self.assertEqual(f2.delta_packets, 10)
        self.assertAlmostEqual(f2.interval_s, 0.5)
        self.assertAlmostEqual(f2.packet_rate_pps, 20.0)
        self.assertAlmostEqual(f2.byte_rate_Bps, 10 * 60 / 0.5)
        self.assertTrue(f2.is_syn_flow)
        self.assertEqual(f2.tcp_dst, 80)

    def test_counter_reset_when_flow_recreated(self):
        fx = FeatureExtractor()
        fx.update(1, 10.0, [syn_sample(10.0, 1, H2, H3, 80, 600, duration=12.0)])
        f = fx.update(1, 10.25, [syn_sample(10.25, 1, H2, H3, 80, 4, duration=0.1)])[0]
        self.assertEqual(f.delta_packets, 4)           # not negative

    def test_zero_interval_does_not_divide_by_zero(self):
        fx = FeatureExtractor(default_interval_s=0.0)
        f = fx.update(1, 5.0, [syn_sample(5.0, 1, H1, H3, 80, 7)])[0]
        self.assertEqual(f.packet_rate_pps, 0.0)
        self.assertEqual(f.byte_rate_Bps, 0.0)

    def test_switches_tracked_independently(self):
        fx = FeatureExtractor()
        fx.update(1, 1.0, [l2_sample(1.0, 1, 100)])
        f = fx.update(2, 1.1, [l2_sample(1.1, 2, 100)])[0]
        self.assertEqual(f.delta_packets, 100)         # s2's first sample

    def test_l2_flow_is_not_a_syn_flow(self):
        fx = FeatureExtractor()
        f = fx.update(1, 1.0, [l2_sample(1.0, 1, 10)])[0]
        self.assertFalse(f.is_syn_flow)
        self.assertIsNone(f.tcp_dst)
        self.assertEqual(f.in_port, 1)

    def test_vanished_flow_forgotten(self):
        fx = FeatureExtractor()
        fx.update(1, 1.0, [syn_sample(1.0, 1, H1, H3, 80, 50)])
        fx.update(1, 1.25, [])                         # flow expired
        f = fx.update(1, 1.5, [syn_sample(1.5, 1, H1, H3, 80, 50)])[0]
        self.assertEqual(f.delta_packets, 50)          # treated as new


class Sim:
    """Drives the extractor + detector with simulated switch counters."""

    def __init__(self, config=None, dpid=1):
        self.fx = FeatureExtractor(default_interval_s=POLL)
        self.det = AnomalyDetector(config)
        self.dpid = dpid
        self.counts = {}          # (src, dst, dport) -> cumulative SYNs
        self.t0 = 1000.0
        self.alerts = []

    def poll(self, t, new_syns):
        """new_syns: {(src, dst, dport): syn_packets_since_last_poll}"""
        for k, n in new_syns.items():
            self.counts[k] = self.counts.get(k, 0) + n
        ts = self.t0 + t
        samples = [syn_sample(ts, self.dpid, s, d, p, c, duration=t + 1)
                   for (s, d, p), c in self.counts.items()]
        alerts = self.det.process(self.fx.update(self.dpid, ts, samples))
        self.alerts.extend(alerts)
        return alerts

    def run_idle(self, start, end):
        t = start
        while t < end:
            self.poll(t, {})
            t += POLL


class DetectorTests(unittest.TestCase):

    def test_normal_http_no_alert(self):
        sim = Sim()
        sim.poll(0.25, {(H1, H3, 80): 1})              # one curl = one SYN
        sim.run_idle(0.5, 5)
        self.assertEqual(sim.alerts, [])

    def test_iperf_no_alert(self):
        sim = Sim()
        sim.poll(0.25, {(H1, H3, 5201): 2})            # control + data connection
        sim.run_idle(0.5, 12)
        self.assertEqual(sim.alerts, [])

    def test_nmap_port_scan_detected(self):
        """nmap -sS -p 1-100: one SYN to each of 100 ports within ~1 s."""
        sim = Sim()
        t = 0.25
        for chunk in range(4):                          # 25 ports per poll
            ports = range(1 + chunk * 25, 26 + chunk * 25)
            sim.poll(t, {(H2, H3, p): 1 for p in ports})
            t += POLL
        scans = [a for a in sim.alerts if a.anomaly_type == PORT_SCAN]
        self.assertEqual(len(scans), 1)
        a = scans[0]
        self.assertEqual((a.src_ip, a.dst_ip, a.dst_port), (H2, H3, None))
        self.assertGreater(a.measured_value, 20)
        self.assertEqual(a.threshold, 20)
        self.assertEqual(a.metric, "distinct_dst_ports")
        # 100 SYNs spread over 100 different ports is NOT a SYN-heavy event
        self.assertEqual([x for x in sim.alerts if x.anomaly_type == SYN_HEAVY], [])

    def test_scan_threshold_is_strict(self):
        sim = Sim()
        sim.poll(0.25, {(H2, H3, p): 1 for p in range(1, 21)})   # exactly 20
        self.assertEqual(sim.alerts, [])
        sim.poll(0.5, {(H2, H3, 21): 1})                         # 21st port
        self.assertEqual(len(sim.alerts), 1)
        self.assertEqual(sim.alerts[0].measured_value, 21)

    def test_scan_ports_expire_after_window(self):
        sim = Sim()
        sim.poll(0.25, {(H2, H3, p): 1 for p in range(1, 16)})   # 15 ports
        sim.run_idle(0.5, 11)                                    # > 10 s later
        sim.poll(11.0, {(H2, H3, p): 1 for p in range(100, 110)})  # 10 more
        self.assertEqual(sim.alerts, [])                         # not 25 in window

    def test_hping3_syn_burst_detected(self):
        """hping3 -S -p 80 -c 600 -i u1000: 600 SYNs in ~0.6 s to one port."""
        sim = Sim()
        sim.poll(0.25, {})
        for i, t in enumerate((0.5, 0.75, 1.0)):                # 250,250,100
            sim.poll(t, {(H2, H3, 80): (250, 250, 100)[i]})
        syn = [a for a in sim.alerts if a.anomaly_type == SYN_HEAVY]
        self.assertEqual(len(syn), 1)
        a = syn[0]
        self.assertEqual((a.src_ip, a.dst_ip, a.dst_port), (H2, H3, 80))
        self.assertGreater(a.measured_value, 500)
        self.assertEqual(a.metric, "syn_per_second")
        self.assertEqual(a.window_s, 1.0)

    def test_burst_detected_at_any_alignment(self):
        """The 600-SYN burst must be caught however it lines up with polls."""
        for offset in (0.0, 0.05, 0.10, 0.15, 0.20):
            sim = Sim()
            sim.poll(0.25, {})
            # 1000 SYN/s for 0.6 s starting `offset` after a poll boundary
            sent_until = lambda t: max(0.0, min(0.6, t - 0.25 - offset)) * 1000
            prev = 0
            t = 0.5
            while t < 3:
                cum = round(sent_until(t))
                sim.poll(t, {(H2, H3, 80): cum - prev} if cum > prev else {})
                prev = cum
                t += POLL
            self.assertEqual(
                len([a for a in sim.alerts if a.anomaly_type == SYN_HEAVY]), 1,
                "missed burst at offset %.2f" % offset)

    def test_slow_syn_rate_no_alert(self):
        sim = Sim()
        t = 0.25
        while t < 5:
            sim.poll(t, {(H2, H3, 80): 100})            # 400 SYN/s
            t += POLL
        self.assertEqual(sim.alerts, [])

    def test_syn_threshold_is_strict(self):
        sim = Sim()
        sim.poll(0.25, {(H2, H3, 80): 500})             # 500 in 1 s window
        self.assertEqual(sim.alerts, [])
        sim.poll(0.5, {(H2, H3, 80): 1})                # 501
        self.assertEqual(len(sim.alerts), 1)

    def test_cooldown_suppresses_duplicates_then_realerts(self):
        cfg = DetectorConfig(alert_cooldown_s=2.0)
        sim = Sim(cfg)
        t = 0.25
        while t < 1.9:                                   # sustained flood
            sim.poll(t, {(H2, H3, 80): 200})            # 800 SYN/s
            t += POLL
        self.assertEqual(len(sim.alerts), 1)
        while t < 3.0:
            sim.poll(t, {(H2, H3, 80): 200})
            t += POLL
        self.assertEqual(len(sim.alerts), 2)             # re-alert after cooldown

    def test_same_traffic_on_two_switches_gives_one_alert(self):
        det = AnomalyDetector()
        fx = FeatureExtractor()
        alerts = []
        for dpid in (1, 2):                              # s1 and s2 both see it
            s = [syn_sample(50.0, dpid, H2, H3, 80, 600)]
            alerts += det.process(fx.update(dpid, 50.0, s))
        self.assertEqual(len(alerts), 1)

    def test_non_syn_flows_ignored(self):
        det = AnomalyDetector()
        fx = FeatureExtractor()
        alerts = det.process(fx.update(1, 1.0, [l2_sample(1.0, 1, 10 ** 6)]))
        self.assertEqual(alerts, [])

    def test_alert_to_dict_has_contract_fields(self):
        sim = Sim()
        sim.poll(0.25, {(H2, H3, 80): 700})
        d = sim.alerts[0].to_dict()
        for key in ("timestamp", "anomaly_type", "dpid", "src_ip", "dst_ip",
                    "dst_port", "metric", "measured_value", "threshold",
                    "window_s"):
            self.assertIn(key, d)


if __name__ == "__main__":
    unittest.main()
