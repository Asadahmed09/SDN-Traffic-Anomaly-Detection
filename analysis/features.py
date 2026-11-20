from typing import Dict, List, Tuple

from analysis.records import FlowFeature, FlowStatSample


class FeatureExtractor:

    def __init__(self, default_interval_s: float = 0.25):
        self.default_interval_s = default_interval_s
        # dpid -> {flow_id: (packet_count, byte_count, duration_s)}
        self._prev_flows: Dict[int, Dict[Tuple, Tuple[int, int, float]]] = {}
        # dpid -> timestamp of previous poll
        self._prev_ts: Dict[int, float] = {}

    def forget_datapath(self, dpid: int) -> None:
        """Call when a switch disconnects so stale counters are not reused."""
        self._prev_flows.pop(dpid, None)
        self._prev_ts.pop(dpid, None)

    def update(self, dpid: int, timestamp: float,
               samples: List[FlowStatSample]) -> List[FlowFeature]:
        """Process one complete stats reply from one switch."""
        prev_ts = self._prev_ts.get(dpid)
        if prev_ts is not None and timestamp > prev_ts:
            interval_s = timestamp - prev_ts
        else:
            interval_s = self.default_interval_s

        prev_flows = self._prev_flows.get(dpid, {})
        new_flows: Dict[Tuple, Tuple[int, int, float]] = {}
        features: List[FlowFeature] = []

        for s in samples:
            fid = s.flow_id
            new_flows[fid] = (s.packet_count, s.byte_count, s.duration_s)
            delta_p, delta_b = self._delta(s, prev_flows.get(fid))

            if interval_s > 0:
                pps = delta_p / interval_s
                bps = delta_b / interval_s
            else:
                pps = bps = 0.0

            m = s.match
            features.append(FlowFeature(
                timestamp=timestamp,
                dpid=dpid,
                table_id=s.table_id,
                priority=s.priority,
                in_port=m.get("in_port"),
                eth_src=m.get("eth_src"),
                eth_dst=m.get("eth_dst"),
                ipv4_src=m.get("ipv4_src"),
                ipv4_dst=m.get("ipv4_dst"),
                ip_proto=m.get("ip_proto"),
                tcp_dst=m.get("tcp_dst"),
                is_syn_flow=("tcp_flags" in m),
                duration_s=s.duration_s,
                packet_count=s.packet_count,
                byte_count=s.byte_count,
                delta_packets=delta_p,
                delta_bytes=delta_b,
                interval_s=interval_s,
                packet_rate_pps=pps,
                byte_rate_Bps=bps,
            ))

        # Replacing the whole dict also drops flows that no longer exist.
        self._prev_flows[dpid] = new_flows
        self._prev_ts[dpid] = timestamp
        return features

    @staticmethod
    def _delta(s: FlowStatSample, prev) -> Tuple[int, int]:
        if prev is None:
            return s.packet_count, s.byte_count
        prev_p, prev_b, prev_dur = prev
        reset = (s.packet_count < prev_p or
                 s.byte_count < prev_b or
                 s.duration_s + 1e-6 < prev_dur)
        if reset:
            return s.packet_count, s.byte_count
        return s.packet_count - prev_p, s.byte_count - prev_b
