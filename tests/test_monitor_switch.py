import unittest

try:
    from ryu.controller import ofp_event
    from ryu.lib.packet import arp, ethernet, ipv4, packet, tcp
    from ryu.ofproto import ofproto_parser, ofproto_v1_3, ofproto_v1_3_parser
    from controller.monitor_switch import (MonitorSwitch13, FORWARD_TABLE,
                                           MONITOR_TABLE)
    HAVE_RYU = True
except ImportError:          # pragma: no cover
    HAVE_RYU = False

H2, H3 = "10.0.1.66", "10.0.2.10"


class FakeDatapath:
    def __init__(self, dpid=1):
        self.id = dpid
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_v1_3_parser
        self.sent = []

    def set_xid(self, msg):
        msg.set_xid(1)

    def send_msg(self, msg):
        msg.serialize()                      # fails loudly on bad encoding
        self.sent.append(msg)

    def reparsed(self):
        """FlowMods are re-parsed from their bytes. Ryu has no parser for the
        other controller-to-switch messages (PacketOut, stats requests), so
        those are returned as built; they were already serialised in send_msg.
        """
        out = []
        for m in self.sent:
            if m.__class__.__name__ != "OFPFlowMod":
                out.append(m)
                continue
            buf = bytes(m.buf)
            version, msg_type, msg_len, xid = ofproto_parser.header(buf)
            out.append(ofproto_parser.msg(self, version, msg_type, msg_len,
                                          xid, buf))
        return out


def tcp_packet(src_ip, dst_ip, dport, flags=None, sport=40000):
    if flags is None:
        flags = tcp.TCP_SYN
    p = packet.Packet()
    p.add_protocol(ethernet.ethernet(dst="00:00:00:00:00:aa",
                                     src="00:00:00:00:00:02", ethertype=0x0800))
    p.add_protocol(ipv4.ipv4(src=src_ip, dst=dst_ip, proto=6))
    p.add_protocol(tcp.tcp(src_port=sport, dst_port=dport, bits=flags))
    p.serialize()
    return bytes(p.data)


def arp_packet():
    p = packet.Packet()
    p.add_protocol(ethernet.ethernet(dst="ff:ff:ff:ff:ff:ff",
                                     src="00:00:00:00:00:01", ethertype=0x0806))
    p.add_protocol(arp.arp_ip(arp.ARP_REQUEST, "00:00:00:00:00:01", "10.0.1.11",
                              "00:00:00:00:00:00", "10.0.1.1"))
    p.serialize()
    return bytes(p.data)


def packet_in(dp, data, table_id, in_port=1):
    msg = ofproto_v1_3_parser.OFPPacketIn(
        dp, buffer_id=dp.ofproto.OFP_NO_BUFFER, total_len=len(data),
        reason=dp.ofproto.OFPR_ACTION, table_id=table_id, cookie=0,
        match=ofproto_v1_3_parser.OFPMatch(in_port=in_port), data=data)
    return ofp_event.EventOFPPacketIn(msg)


@unittest.skipUnless(HAVE_RYU, "Ryu is not installed")
class MonitorSwitchTests(unittest.TestCase):

    def setUp(self):
        self.app = MonitorSwitch13()
        self.dp = FakeDatapath(1)

    def features_event(self):
        msg = ofproto_v1_3_parser.OFPSwitchFeatures(self.dp)
        msg.datapath = self.dp
        return ofp_event.EventOFPSwitchFeatures(msg)

    # --- switch connects ---------------------------------------------
    def test_monitor_table_installed(self):
        self.app.monitor_features_handler(self.features_event())
        flows = self.dp.reparsed()
        self.assertEqual(len(flows), 2)
        by_prio = {f.priority: f for f in flows}
        self.assertEqual(set(by_prio), {0, 5})
        for f in flows:
            self.assertEqual(f.table_id, MONITOR_TABLE)
        # p0: goto forwarding table
        goto = by_prio[0].instructions[0]
        self.assertEqual(goto.table_id, FORWARD_TABLE)
        # p5: SYN-only TCP -> controller
        m = dict(by_prio[5].match.items())
        self.assertEqual(m["ip_proto"], 6)
        self.assertEqual(tuple(m["tcp_flags"]), (0x002, 0x012))

    def test_learning_switch_moved_to_forwarding_table(self):
        """Parent's table-miss must land in table 1 without editing the parent."""
        self.app.switch_features_handler(self.features_event())
        (miss,) = self.dp.reparsed()
        self.assertEqual(miss.table_id, FORWARD_TABLE)
        self.assertEqual(miss.priority, 0)
        out = miss.instructions[0].actions[0]
        self.assertEqual(out.port, self.dp.ofproto.OFPP_CONTROLLER)

    # --- SYN sentinel -------------------------------------------------
    def test_syn_packet_in_installs_monitor_flow_and_resubmits(self):
        ev = packet_in(self.dp, tcp_packet(H2, H3, 80), table_id=MONITOR_TABLE)
        self.app.packet_in_handler(ev)
        flow, out = self.dp.reparsed()
        self.assertEqual(flow.table_id, MONITOR_TABLE)
        self.assertEqual(flow.priority, 10)
        self.assertEqual(flow.idle_timeout, 15)
        m = dict(flow.match.items())
        self.assertEqual((m["ipv4_src"], m["ipv4_dst"], m["tcp_dst"]),
                         (H2, H3, 80))
        self.assertEqual(tuple(m["tcp_flags"]), (0x002, 0x012))
        self.assertEqual(flow.instructions[0].table_id, FORWARD_TABLE)
        # the packet is re-sent through the pipeline, not dropped
        self.assertEqual(out.actions[0].port, self.dp.ofproto.OFPP_TABLE)
        self.assertEqual(out.in_port, 1)
        self.assertTrue(len(out.data) > 0)

    def test_duplicate_sentinel_does_not_reinstall(self):
        data = tcp_packet(H2, H3, 80)
        self.app.packet_in_handler(packet_in(self.dp, data, MONITOR_TABLE))
        self.app.packet_in_handler(packet_in(self.dp, data, MONITOR_TABLE))
        kinds = [type(m).__name__ for m in self.dp.sent]
        self.assertEqual(kinds.count("OFPFlowMod"), 1)       # no counter reset
        self.assertEqual(kinds.count("OFPPacketOut"), 2)     # both still forwarded

    def test_different_ports_get_separate_flows(self):
        for port in (22, 80, 443):
            self.app.packet_in_handler(
                packet_in(self.dp, tcp_packet(H2, H3, port), MONITOR_TABLE))
        flows = [m for m in self.dp.reparsed() if m.__class__.__name__ == "OFPFlowMod"]
        self.assertEqual(sorted(dict(f.match.items())["tcp_dst"] for f in flows),
                         [22, 80, 443])

    # --- table-1 miss goes to the unchanged learning switch ----------
    def test_table1_packet_in_uses_learning_switch(self):
        ev = packet_in(self.dp, arp_packet(), table_id=FORWARD_TABLE, in_port=3)
        self.app.packet_in_handler(ev)
        self.assertEqual(self.app.mac_to_port[1]["00:00:00:00:00:01"], 3)
        (out,) = self.dp.reparsed()
        self.assertEqual(out.__class__.__name__, "OFPPacketOut")
        self.assertEqual(out.actions[0].port, self.dp.ofproto.OFPP_FLOOD)

    # --- polling --------------------------------------------------------
    def test_stats_request_is_valid(self):
        self.app._request_flow_stats(self.dp)
        (req,) = self.dp.reparsed()
        self.assertEqual(req.__class__.__name__, "OFPFlowStatsRequest")
        self.assertEqual(req.table_id, self.dp.ofproto.OFPTT_ALL)

    def _flow_stats(self, table_id, priority, match, packets, duration=1):
        return ofproto_v1_3_parser.OFPFlowStats(
            table_id=table_id, duration_sec=duration, duration_nsec=0,
            priority=priority, idle_timeout=15, hard_timeout=0, flags=0,
            cookie=0, packet_count=packets, byte_count=packets * 60,
            match=match, instructions=[])

    def syn_stat(self, dport, packets, duration=1):
        P = ofproto_v1_3_parser
        m = P.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=H2, ipv4_dst=H3,
                       tcp_dst=dport, tcp_flags=(0x002, 0x012))
        return self._flow_stats(0, 10, m, packets, duration)

    def test_stats_reply_to_samples(self):
        got = []
        self.app.add_sample_listener(got.append)
        l2 = self._flow_stats(1, 1, ofproto_v1_3_parser.OFPMatch(
            in_port=1, eth_src="00:00:00:00:00:01", eth_dst="00:00:00:00:00:02"), 40)
        self.app._process_reply(1, 500.0, [self.syn_stat(80, 3), l2])
        (samples,) = got
        syn = [s for s in samples if s.table_id == 0][0]
        self.assertEqual(syn.dpid, 1)
        self.assertEqual(syn.packet_count, 3)
        self.assertEqual(syn.match["tcp_dst"], 80)
        self.assertEqual(syn.match["ipv4_src"], H2)
        self.assertIn("tcp_flags", syn.match)
        l2s = [s for s in samples if s.table_id == 1][0]
        self.assertEqual(l2s.match["in_port"], 1)

    def test_multipart_reply_is_assembled(self):
        got = []
        self.app.add_sample_listener(got.append)
        P = ofproto_v1_3_parser
        more = P.OFPFlowStatsReply(self.dp, body=[self.syn_stat(80, 1)],
                                   flags=self.dp.ofproto.OFPMPF_REPLY_MORE)
        last = P.OFPFlowStatsReply(self.dp, body=[self.syn_stat(81, 1)], flags=0)
        more.datapath = last.datapath = self.dp
        self.app.flow_stats_reply_handler(ofp_event.EventOFPFlowStatsReply(more))
        self.assertEqual(got, [])                            # waits for the rest
        self.app.flow_stats_reply_handler(ofp_event.EventOFPFlowStatsReply(last))
        self.assertEqual(len(got), 1)
        self.assertEqual(len(got[0]), 2)

    def test_full_chain_nmap_then_hping3(self):
        """stats reply -> F3 samples -> F4 features -> F5 alerts -> listeners."""
        alerts, features = [], []
        self.app.add_alert_listener(alerts.append)
        self.app.add_feature_listener(features.append)

        # normal traffic first: nothing should fire
        self.app._process_reply(1, 100.00, [self.syn_stat(80, 1)])
        self.app._process_reply(1, 100.25, [self.syn_stat(80, 1)])
        self.assertEqual(alerts, [])

        # nmap -sS -p 1-100
        scan = [self.syn_stat(p, 1) for p in range(1, 101)]
        self.app._process_reply(1, 101.00, scan)
        self.assertEqual([a.anomaly_type for a in alerts], ["port_scan"])
        self.assertEqual(alerts[0].measured_value, 100)
        self.assertEqual(len(self.app.alerts), 1)

        # hping3 burst to one port, 600 SYNs over three polls
        for t, total in ((102.0, 250), (102.25, 500), (102.5, 600)):
            self.app._process_reply(1, t, [self.syn_stat(80, total, duration=5)])
        self.assertEqual([a.anomaly_type for a in alerts], ["port_scan", "syn_heavy"])
        self.assertEqual(alerts[1].dst_port, 80)
        self.assertGreater(alerts[1].measured_value, 500)
        self.assertTrue(features)

    def test_broken_listener_does_not_break_pipeline(self):
        def boom(_):
            raise RuntimeError("teammate bug")
        self.app.add_feature_listener(boom)
        good = []
        self.app.add_alert_listener(good.append)
        self.app._process_reply(1, 1.0, [self.syn_stat(80, 900)])
        self.assertEqual(len(good), 1)                      # still reached F5


if __name__ == "__main__":
    unittest.main()
