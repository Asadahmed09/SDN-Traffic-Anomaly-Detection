import csv
import ipaddress
import os
import time

from ryu.lib import hub

from analysis.records import Alert, FlowFeature
from controller.monitor_switch import MONITOR_TABLE, MonitorSwitch13


LOG_DIR = os.path.expanduser(os.environ.get("SDN_LOG_DIR", "~/sdn_logs"))

BLOCK_PRIORITY = 20
BLOCK_SECONDS = 60
ETH_TYPE_IP = 0x0800

WHITELIST = {
    "10.0.1.1",
    "10.0.12.1",
    "10.0.12.2",
    "10.0.2.1",
    "10.0.2.10",
}


class CsvLog:

    def __init__(self, name, columns):
        os.makedirs(LOG_DIR, exist_ok=True)
        self.path = os.path.join(LOG_DIR, name)

        new_file = (
            not os.path.exists(self.path)
            or os.path.getsize(self.path) == 0
        )

        self.file = open(self.path, "a", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(
            self.file,
            fieldnames=columns,
            extrasaction="ignore",
        )

        if new_file:
            self.writer.writeheader()
            self.file.flush()

    def write(self, row):
        self.writer.writerow(row)
        self.file.flush()

    def close(self):
        if not self.file.closed:
            self.file.close()


class MitigationSwitch13(MonitorSwitch13):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.blocked = {}

        self.feature_csv = CsvLog(
            "features.csv",
            list(FlowFeature.field_names()),
        )
        self.alert_csv = CsvLog(
            "alerts.csv",
            list(Alert.field_names()) + ["action"],
        )

        self.add_feature_listener(self._log_features)
        self.add_alert_listener(self._on_alert)

        self.logger.info(
            "Mitigation module active: F6 Auto-Mitigation + F8 CSV Logging"
        )
        self.logger.info("CSV logs directory: %s", LOG_DIR)

    def _log_features(self, features):
        for feature in features:
            if feature.delta_packets > 0:
                self.feature_csv.write(feature.to_dict())

    def _on_alert(self, alert):
        action = self.block_source(alert.src_ip)

        row = alert.to_dict()
        row["action"] = action
        self.alert_csv.write(row)

        self.logger.warning(
            "Alert received: source=%s action=%s",
            alert.src_ip,
            action,
        )

    def block_source(self, src_ip):
        try:
            src_ip = str(ipaddress.IPv4Address(src_ip))
        except ipaddress.AddressValueError:
            self.logger.error("Invalid source IP received: %s", src_ip)
            return "invalid_ip"

        if src_ip in WHITELIST:
            return "skipped_whitelist"

        if src_ip in self.blocked:
            return "already_blocked"

        datapaths = list(self.datapaths.values())

        if not datapaths:
            self.logger.warning(
                "No connected switches available for mitigation"
            )
            return "no_switches_available"

        installed = 0

        for dp in datapaths:
            parser = dp.ofproto_parser

            match = parser.OFPMatch(
                eth_type=ETH_TYPE_IP,
                ipv4_src=src_ip,
            )

            flow_mod = parser.OFPFlowMod(
                datapath=dp,
                table_id=MONITOR_TABLE,
                priority=BLOCK_PRIORITY,
                match=match,
                instructions=[],
                hard_timeout=BLOCK_SECONDS,
            )

            dp.send_msg(flow_mod)
            installed += 1

        if installed == 0:
            return "no_switches_available"

        self.blocked[src_ip] = time.time()

        self.logger.warning(
            "BLOCKED source IP %s for %s seconds",
            src_ip,
            BLOCK_SECONDS,
        )

        hub.spawn_after(BLOCK_SECONDS, self.blocked.pop, src_ip, None)

        return "blocked_%ds" % BLOCK_SECONDS

    def close(self):
        self.feature_csv.close()
        self.alert_csv.close()
        super().close()
