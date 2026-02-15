import json
import threading
from pathlib import Path
from queue import Queue, Empty
from datetime import datetime

from sniffer.packet_sniffer import PacketSniffer
from flow.flow_tracker import FlowTracker
from detection.detector import Detector
from alerts.alert_manager import AlertManager


CONFIG_PATH = Path("config/settings.json")
LOG_PATH = Path("logs/alerts.log")


def load_config(path: Path) -> dict:
    with path.open("r") as f:
        return json.load(f)


def packet_worker(
    packet_queue: Queue,
    flow_tracker: FlowTracker,
    detector: Detector,
    alert_manager: AlertManager,
    stop_event: threading.Event,
):
    while not stop_event.is_set():
        try:
            packet_meta = packet_queue.get(timeout=1)
        except Empty:
            continue

        try:
            flow = flow_tracker.update_with_packet(packet_meta)
            alerts = detector.analyze(packet_meta, flow)

            for alert in alerts:
                alert_manager.handle_alert(alert)

        finally:
            packet_queue.task_done()


def main():
    config = load_config(CONFIG_PATH)

    packet_queue: Queue = Queue()
    stop_event = threading.Event()

    flow_tracker = FlowTracker()
    detector = Detector(config)
    alert_manager = AlertManager(LOG_PATH)

    # Start worker thread
    worker_thread = threading.Thread(
        target=packet_worker,
        args=(packet_queue, flow_tracker, detector, alert_manager, stop_event),
        daemon=True,  # ensures thread won't block exit
    )
    worker_thread.start()

    # Start packet sniffer (blocking)
    sniffer = PacketSniffer(
        interface=None,
        packet_handler=lambda meta: packet_queue.put(meta),
        stop_event=stop_event,
    )

    print(f"[{datetime.utcnow().isoformat()}] Mini-IDS starting...")
    print("Press Ctrl+C to stop.\n")

    try:
        sniffer.start()
    except KeyboardInterrupt:
        print("\nStopping Mini-IDS...")
    finally:
        stop_event.set()
        worker_thread.join()
        print("Goodbye.")


if __name__ == "__main__":
    main()