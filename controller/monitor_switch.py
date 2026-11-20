import time
from collections import deque

from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, DEAD_DISPATCHER,
                                    MAIN_DISPATCHER, set_ev_cls)
from ryu.lib import hub
from ryu.lib.packet import ipv4, packet, tcp
from ryu.ofproto import ofproto_v1_3

from analysis.detector import AnomalyDetector, DetectorConfig
from analysis.features import FeatureExtractor
from analysis.records import FlowStatSample
from controller.learning_switch import LearningSwitch13

MONITOR_TABLE = 0
FORWARD_TABLE = 1

ETH_TYPE_IP = 0x0800
IP_PROTO_TCP = 6
TCP_SYN = 0x002
TCP_SYN_ACK_MASK = 0x012      # look at the SYN and ACK bits only

# Ryu 4.34 exposes the OpenFlow 1.3 TCP-flags match as "tcp_flags" (ONF
# extension). Newer Ryu versions also have "tcp_flags_nxm".
_OXM_NAMES = set(t.name for t in ofproto_v1_3.oxm_types)
TCP_FLAGS_FIELD = "tcp_flags" if "tcp_flags" in _OXM_NAMES else "tcp_flags_nxm"

# Match keys copied from a switch's flow entry into FlowStatSample.match
_MATCH_KEYS = ("in_port", "eth_src", "eth_dst", "eth_type", "ip_proto",
               "ipv4_src", "ipv4_dst", "tcp_src", "tcp_dst", "tcp_flags")


class MonitorSwitch13(LearningSwitch13):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    POLL_INTERVAL_S = 0.25          # how often stats are requested
    LOG_EVERY_N_POLLS = 20          # INFO summary per switch (every ~5 s)
    PRIO_SENTINEL = 5
    PRIO_SYN_MONITOR = 10
    MONITOR_IDLE_TIMEOUT_S = 15     # monitor flows vanish when traffic stops
    REINSTALL_GUARD_S = 1.0         # don't re-install the same key twice quickly

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}                 # dpid -> datapath
        self._reply_parts = {}              # dpid -> accumulated stats bodies
        self._monitored = {}                # (dpid, src, dst, dport) -> install time
        self._poll_count = {}               # dpid -> number of completed polls
        self.alerts = deque(maxlen=1000)    # recent alerts, newest last

        self.extractor = FeatureExtractor(default_interval_s=self.POLL_INTERVAL_S)
        self.detector = AnomalyDetector(DetectorConfig())

        self.sample_listeners = []
        self.feature_listeners = []
        self.alert_listeners = []

        self.poll_thread = hub.spawn(self._poll_loop)

    # ------------------------------------------------------------------
    # Hooks for F6 / F8
    # ------------------------------------------------------------------
    def add_sample_listener(self, fn):
        self.sample_listeners.append(fn)

    def add_feature_listener(self, fn):
        self.feature_listeners.append(fn)

    def add_alert_listener(self, fn):
        self.alert_listeners.append(fn)

    def _notify(self, listeners, arg):
        # A bug in a teammate's listener must not stop the polling loop.
        for fn in list(listeners):
            try:
                fn(arg)
            except Exception:
                self.logger.exception("listener %r raised", fn)

    # ------------------------------------------------------------------
    # Flow-table helpers
    # ------------------------------------------------------------------
    def _send_flow(self, datapath, table_id, priority, match, instructions,
                   idle_timeout=0):
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=table_id, priority=priority,
            match=match, instructions=instructions,
            idle_timeout=idle_timeout))

    def add_flow(self, datapath, priority, match, actions,
                 table_id=FORWARD_TABLE, idle_timeout=0):
        """Same as LearningSwitch13.add_flow but installs into table 1.

        The parent's code calls self.add_flow(...) for its table-miss and its
        learned flows, so overriding this moves the whole learning switch to
        the forwarding table without editing learning_switch.py.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self._send_flow(datapath, table_id, priority, match, instructions,
                        idle_timeout)

    @staticmethod
    def _syn_match(parser, ipv4_src=None, ipv4_dst=None, tcp_dst=None):
        fields = {"eth_type": ETH_TYPE_IP,
                  "ip_proto": IP_PROTO_TCP,
                  TCP_FLAGS_FIELD: (TCP_SYN, TCP_SYN_ACK_MASK)}
        if ipv4_src is not None:
            fields["ipv4_src"] = ipv4_src
            fields["ipv4_dst"] = ipv4_dst
            fields["tcp_dst"] = tcp_dst
        return parser.OFPMatch(**fields)

    # ------------------------------------------------------------------
    # Switch connects: install the monitor table
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def monitor_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # p0: everything continues to the forwarding table
        self._send_flow(datapath, MONITOR_TABLE, 0, parser.OFPMatch(),
                        [parser.OFPInstructionGotoTable(FORWARD_TABLE)])

        # p5: SYN-only TCP with no monitor flow yet -> ask the controller
        to_controller = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._send_flow(
            datapath, MONITOR_TABLE, self.PRIO_SENTINEL,
            self._syn_match(parser),
            [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, to_controller)])

    # ------------------------------------------------------------------
    # Packet-In: SYN sentinel (table 0) or normal learning switch (table 1)
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        if msg.table_id == MONITOR_TABLE:
            self._handle_syn_sentinel(msg)
            return
        # Table-1 miss: unchanged learning-switch behaviour.
        super().packet_in_handler(ev)

    def _handle_syn_sentinel(self, msg):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        ip4 = pkt.get_protocol(ipv4.ipv4)
        seg = pkt.get_protocol(tcp.tcp)

        if ip4 is not None and seg is not None:
            key = (datapath.id, ip4.src, ip4.dst, seg.dst_port)
            now = time.time()
            last = self._monitored.get(key)
            if last is None or now - last >= self.REINSTALL_GUARD_S:
                self._install_syn_monitor(datapath, ip4.src, ip4.dst,
                                          seg.dst_port)
                if len(self._monitored) > 5000:
                    self._monitored.clear()
                self._monitored[key] = now

        # Send the packet through the pipeline again; it now matches the
        # monitor flow (so this SYN is counted) and continues to table 1.
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=[parser.OFPActionOutput(datapath.ofproto.OFPP_TABLE)],
            data=msg.data))

    def _install_syn_monitor(self, datapath, src, dst, dport):
        parser = datapath.ofproto_parser
        self._send_flow(
            datapath, MONITOR_TABLE, self.PRIO_SYN_MONITOR,
            self._syn_match(parser, src, dst, dport),
            [parser.OFPInstructionGotoTable(FORWARD_TABLE)],
            idle_timeout=self.MONITOR_IDLE_TIMEOUT_S)

    # ------------------------------------------------------------------
    # Switch registry and polling loop (runs in its own green thread, so
    # nothing here blocks the OpenFlow event handlers)
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info("switch %s connected for monitoring", datapath.id)
        elif datapath.id in self.datapaths:
            del self.datapaths[datapath.id]
            self._reply_parts.pop(datapath.id, None)
            self.extractor.forget_datapath(datapath.id)
            self.logger.info("switch %s disconnected", datapath.id)

    def _poll_loop(self):
        while True:
            for datapath in list(self.datapaths.values()):
                self._request_flow_stats(datapath)
            hub.sleep(self.POLL_INTERVAL_S)

    def _request_flow_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowStatsRequest(
            datapath, 0, ofproto.OFPTT_ALL, ofproto.OFPP_ANY,
            ofproto.OFPG_ANY, 0, 0, parser.OFPMatch()))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parts = self._reply_parts.setdefault(datapath.id, [])
        parts.extend(msg.body)
        if msg.flags & datapath.ofproto.OFPMPF_REPLY_MORE:
            return                      # more parts of this reply to come
        body = self._reply_parts.pop(datapath.id)
        self._process_reply(datapath.id, time.time(), body)

    @staticmethod
    def _match_to_dict(match):
        out = {}
        for key, value in match.items():
            if key.endswith("_nxm"):
                key = key[:-4]
            if key in _MATCH_KEYS:
                out[key] = tuple(value) if isinstance(value, list) else value
        return out

    def _process_reply(self, dpid, timestamp, body):
        # F3: raw samples
        samples = [FlowStatSample(
            timestamp=timestamp, dpid=dpid, table_id=st.table_id,
            priority=st.priority,
            duration_s=st.duration_sec + st.duration_nsec / 1e9,
            idle_timeout=st.idle_timeout,
            packet_count=st.packet_count, byte_count=st.byte_count,
            match=self._match_to_dict(st.match)) for st in body]
        self._notify(self.sample_listeners, samples)

        # F4: features
        features = self.extractor.update(dpid, timestamp, samples)
        self._notify(self.feature_listeners, features)

        # F5: detection
        for alert in self.detector.process(features):
            self.alerts.append(alert)
            self.logger.warning("ANOMALY %s", alert.summary())
            self._notify(self.alert_listeners, alert)

        count = self._poll_count.get(dpid, 0) + 1
        self._poll_count[dpid] = count
        if count == 1 or count % self.LOG_EVERY_N_POLLS == 0:
            monitor = sum(1 for s in samples if "tcp_flags" in s.match)
            self.logger.info(
                "stats dpid=%s t=%.3f flows=%d syn_monitor_flows=%d",
                dpid, timestamp, len(samples), monitor)

    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_handler(self, ev):
        msg = ev.msg
        self.logger.error(
            "OpenFlow error from switch %s: type=%s code=%s "
            "(if this appears right after connect, the switch may not "
            "support the TCP-flags match field)",
            msg.datapath.id, msg.type, msg.code)
