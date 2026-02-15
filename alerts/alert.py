from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Alert:
    timestamp: float = field(default_factory=lambda: datetime.utcnow().timestamp())
    alert_type: str = ""
    src_ip: str = ""
    description: str = ""

    def to_log_line(self) -> str:
        iso_time = datetime.utcfromtimestamp(self.timestamp).isoformat()
        return f"{iso_time} | {self.alert_type} | {self.src_ip} | {self.description}"

    def __str__(self) -> str:
        return self.to_log_line()
