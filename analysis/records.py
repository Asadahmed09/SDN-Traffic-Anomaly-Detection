from dataclasses import dataclass, field, fields, asdict
from typing import Any, Dict, Optional, Tuple


@dataclass
class FlowStatSample:
    """F3 output: one flow entry as reported by a switch in one stats reply."""

    timestamp: float          # time the full stats reply was received (epoch s)
    dpid: int                 # datapath id (s1 = 1, s2 = 2 in Mininet)
    table_id: int             # 0 = monitor table, 1 = forwarding table
    priority: int
    duration_s: float         # seconds the flow has existed on the switch
    idle_timeout: int         # seconds (0 = none)
    packet_count: int         # cumulative since the flow was installed
    byte_count: int           # cumulative since the flow was installed
    match: Dict[str, Any] = field(default_factory=dict)
    # match keys used: in_port, eth_src, eth_dst, eth_type, ip_proto,
    #                  ipv4_src, ipv4_dst, tcp_src, tcp_dst, tcp_flags

    @property
    def flow_id(self) -> Tuple:
        """Hashable identity of a flow on one switch."""
        return (self.table_id, self.priority, tuple(sorted(self.match.items())))


@dataclass
class FlowFeature:
    """F4 output: derived values for one flow over one polling interval."""

    timestamp: float
    dpid: int
    table_id: int
    priority: int

    # identity fields (None when the flow does not match on them)
    in_port: Optional[int]
    eth_src: Optional[str]
    eth_dst: Optional[str]
    ipv4_src: Optional[str]
    ipv4_dst: Optional[str]
    ip_proto: Optional[int]
    tcp_dst: Optional[int]
    is_syn_flow: bool         # True for monitor flows that count SYN-only packets

    # raw cumulative counters
    duration_s: float
    packet_count: int
    byte_count: int

    # derived values
    delta_packets: int        # packets seen since the previous poll
    delta_bytes: int          # bytes seen since the previous poll
    interval_s: float         # seconds covered by the delta
    packet_rate_pps: float    # delta_packets / interval_s
    byte_rate_Bps: float      # delta_bytes / interval_s  (bytes per second)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def field_names(cls):
        return tuple(f.name for f in fields(cls))


# anomaly_type values used by F5
PORT_SCAN = "port_scan"
SYN_HEAVY = "syn_heavy"


@dataclass
class Alert:
    """F5 output: one detected anomaly. F6 and F8 consume this."""

    timestamp: float
    anomaly_type: str             # PORT_SCAN or SYN_HEAVY
    dpid: int                     # switch where the threshold was crossed
    src_ip: str
    dst_ip: str
    dst_port: Optional[int]       # None for port scans (many ports)
    metric: str                   # "distinct_dst_ports" or "syn_per_second"
    measured_value: float
    threshold: float
    window_s: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def field_names(cls):
        return tuple(f.name for f in fields(cls))

    def summary(self) -> str:
        port = "-" if self.dst_port is None else self.dst_port
        return ("%s src=%s dst=%s dst_port=%s %s=%.1f (threshold >%g in %.1fs window) dpid=%s"
                % (self.anomaly_type, self.src_ip, self.dst_ip, port,
                   self.metric, self.measured_value, self.threshold,
                   self.window_s, self.dpid))
