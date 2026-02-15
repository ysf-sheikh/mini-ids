from typing import Callable, Optional
from threading import Event

from scapy.all import sniff, IP, TCP, UDP


class PacketSniffer:
    """
    Captures packets from a network interface and extracts metadata.
    """

    def __init__(
        self,
        interface: Optional[str],
        packet_handler: Callable[[dict], None],
        stop_event: Optional[Event] = None,
    ):
        self.interface = interface
        self.packet_handler = packet_handler
        self.stop_event = stop_event

    def _process_packet(self, packet):
        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        src_port = None
        dst_port = None

        if packet.haslayer(TCP):
            l4 = packet[TCP]
            src_port = l4.sport
            dst_port = l4.dport
            protocol_name = "TCP"

        elif packet.haslayer(UDP):
            l4 = packet[UDP]
            src_port = l4.sport
            dst_port = l4.dport
            protocol_name = "UDP"

        else:
            protocol_name = str(proto)

        meta = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol_name,
            "src_port": src_port,
            "dst_port": dst_port,
            "size": len(packet),
            "timestamp": float(packet.time),  # More accurate than datetime.utcnow()
        }

        self.packet_handler(meta)

    def start(self):
        sniff(
            iface=self.interface,
            prn=self._process_packet,
            store=False,
            filter="ip",  # Capture only IP traffic
            stop_filter=lambda x: self.stop_event.is_set() if self.stop_event else False,
        )
