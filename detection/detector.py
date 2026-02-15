from typing import List

from alerts.alert import Alert
from flow.flow_record import FlowRecord
from . import rules


class Detector:
    """
    Detection engine that runs all rules and aggregates alerts.
    """

    def __init__(self, config: dict):
        self.config = config
        self.state: dict = {}  # shared state for rules (history, counters, etc.)

    def analyze(self, packet_meta: dict, flow: FlowRecord) -> List[Alert]:
        alerts: List[Alert] = []

        # Run all detection rules
        alerts.extend(rules.port_scan_detection(packet_meta, self.state, self.config))
        alerts.extend(rules.high_connection_rate_detection(packet_meta, self.state, self.config))
        alerts.extend(rules.suspicious_port_detection(packet_meta, flow, self.config))

        return alerts
