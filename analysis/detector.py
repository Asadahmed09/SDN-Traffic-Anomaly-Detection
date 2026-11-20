from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Tuple

from analysis.records import Alert, FlowFeature, PORT_SCAN, SYN_HEAVY


@dataclass
class DetectorConfig:
    scan_port_threshold: int = 20        # distinct dst ports (alert if >)
    scan_window_s: float = 10.0
    syn_rate_threshold: float = 500.0    # SYN packets per second (alert if >)
    syn_window_s: float = 1.0
    alert_cooldown_s: float = 10.0


class AnomalyDetector:

    def __init__(self, config: DetectorConfig = None):
        self.config = config or DetectorConfig()
        # (dpid, src, dst, dport) -> deque[(timestamp, syn_packets)]
        self._syn_hist: Dict[Tuple, Deque[Tuple[float, int]]] = {}
        # (dpid, src, dst) -> {dport: last timestamp a SYN was seen}
        self._scan_ports: Dict[Tuple, Dict[int, float]] = {}
        # (type, src, dst, dport) -> time of last alert
        self._last_alert: Dict[Tuple, float] = {}
        self._last_gc = 0.0

    def process(self, features: List[FlowFeature]) -> List[Alert]:
        """Feed one batch of features (one switch, one poll). Returns alerts."""
        cfg = self.config
        syn_touched: Dict[Tuple, float] = {}
        scan_touched: Dict[Tuple, float] = {}
        newest = None

        for f in features:
            newest = f.timestamp if newest is None else max(newest, f.timestamp)
            if (not f.is_syn_flow or f.delta_packets <= 0 or f.tcp_dst is None
                    or f.ipv4_src is None or f.ipv4_dst is None):
                continue

            syn_key = (f.dpid, f.ipv4_src, f.ipv4_dst, f.tcp_dst)
            self._syn_hist.setdefault(syn_key, deque()).append(
                (f.timestamp, f.delta_packets))
            syn_touched[syn_key] = f.timestamp

            scan_key = (f.dpid, f.ipv4_src, f.ipv4_dst)
            self._scan_ports.setdefault(scan_key, {})[f.tcp_dst] = f.timestamp
            scan_touched[scan_key] = f.timestamp

        alerts: List[Alert] = []

        for key, now in syn_touched.items():
            dpid, src, dst, dport = key
            hist = self._syn_hist[key]
            while hist and hist[0][0] <= now - cfg.syn_window_s:
                hist.popleft()
            rate = sum(n for _, n in hist) / cfg.syn_window_s
            if rate > cfg.syn_rate_threshold and self._cooldown_ok(
                    (SYN_HEAVY, src, dst, dport), now):
                alerts.append(Alert(
                    timestamp=now, anomaly_type=SYN_HEAVY, dpid=dpid,
                    src_ip=src, dst_ip=dst, dst_port=dport,
                    metric="syn_per_second", measured_value=rate,
                    threshold=cfg.syn_rate_threshold,
                    window_s=cfg.syn_window_s))

        for key, now in scan_touched.items():
            dpid, src, dst = key
            ports = self._scan_ports[key]
            for p in [p for p, t in ports.items() if t <= now - cfg.scan_window_s]:
                del ports[p]
            count = len(ports)
            if count > cfg.scan_port_threshold and self._cooldown_ok(
                    (PORT_SCAN, src, dst, None), now):
                alerts.append(Alert(
                    timestamp=now, anomaly_type=PORT_SCAN, dpid=dpid,
                    src_ip=src, dst_ip=dst, dst_port=None,
                    metric="distinct_dst_ports", measured_value=float(count),
                    threshold=cfg.scan_port_threshold,
                    window_s=cfg.scan_window_s))

        if newest is not None:
            self._gc(newest)
        return alerts

    # ------------------------------------------------------------------
    def _cooldown_ok(self, key: Tuple, now: float) -> bool:
        last = self._last_alert.get(key)
        if last is not None and now - last < self.config.alert_cooldown_s:
            return False
        self._last_alert[key] = now
        return True

    def _gc(self, now: float) -> None:
        """Drop state for traffic that has gone quiet (runs every ~5 s)."""
        if now - self._last_gc < 5.0:
            return
        self._last_gc = now
        cfg = self.config
        for k in [k for k, h in self._syn_hist.items()
                  if not h or h[-1][0] <= now - cfg.syn_window_s]:
            del self._syn_hist[k]
        for k in [k for k, ports in self._scan_ports.items()
                  if all(t <= now - cfg.scan_window_s for t in ports.values())]:
            del self._scan_ports[k]
        for k in [k for k, t in self._last_alert.items()
                  if now - t >= cfg.alert_cooldown_s]:
            del self._last_alert[k]
