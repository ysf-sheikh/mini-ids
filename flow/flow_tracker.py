from typing import Dict, Tuple

from .flow_record import FlowRecord


FlowKey = Tuple[str, str, str, int | None, int | None]


class FlowTracker:
    """
    Maintains active flows and updates them as packets arrive.
    """

    def __init__(self):
        self.flows: Dict[FlowKey, FlowRecord] = {}

    def _make_key(self, packet_meta: dict) -> FlowKey:
        return (
            packet_meta["src_ip"],
            packet_meta["dst_ip"],
            packet_meta["protocol"],
            packet_meta["src_port"],
            packet_meta["dst_port"],
        )

    def update_with_packet(self, packet_meta: dict) -> FlowRecord:
        key = self._make_key(packet_meta)

        if key not in self.flows:
            # Initialize flow directly from first packet
            flow = FlowRecord(
                src_ip=packet_meta["src_ip"],
                dst_ip=packet_meta["dst_ip"],
                protocol=packet_meta["protocol"],
                src_port=packet_meta["src_port"],
                dst_port=packet_meta["dst_port"],
                packet_count=1,
                byte_count=packet_meta["size"],
                first_seen=packet_meta["timestamp"],
                last_seen=packet_meta["timestamp"],
            )
            self.flows[key] = flow
            return flow

        # Existing flow
        flow = self.flows[key]
        flow.update(packet_meta["size"], packet_meta["timestamp"])
        return flow
