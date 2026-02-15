from dataclasses import dataclass


@dataclass
class FlowRecord:
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int | None
    dst_port: int | None

    packet_count: int
    byte_count: int
    first_seen: float
    last_seen: float

    def update(self, packet_size: int, timestamp: float) -> None:
        self.packet_count += 1
        self.byte_count += packet_size
        self.last_seen = timestamp
