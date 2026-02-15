from pathlib import Path
from threading import Lock

from .alert import Alert


class AlertManager:
    """
    Handles alert output: console + log file (thread-safe).
    """

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()  # ensure thread-safe file writes

    def handle_alert(self, alert: Alert):
        line = f"[ALERT] {alert}"

        # Console output
        print(line)

        # Thread-safe file write
        with self._lock:
            with self.log_path.open("a") as f:
                f.write(line + "\n")
