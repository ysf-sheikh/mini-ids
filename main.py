import json
import threading
from pathlib import Path
from queue import Queue, Empty
from datetime import datetime

from sniffer.packet_sniffer import PacketSniffer
from flow.flow_tracker import FlowTracker
from detection.detector import Detector
from alerts.alert_manager import AlertManager


# Configuration and log file paths
CONFIG_PATH = Path("config/settings.json")
LOG_PATH = Path("logs/alerts.log")


def load_config(path: Path) -> dict:
    """
    Load JSON configuration from file.

    Args:
        path: Path to configuration file.

    Returns:
        Parsed configuration dictionary.
    """
    with path.open("r") as f:
        return json.load(f)


def packet_worker(
    packet_queue: Queue,
    flow_tracker: FlowTracker,
    detector: Detector,
    alert_manager: AlertManager,
    stop_event: threading.Event,
):
    """
    Worker thread responsible for processing incoming packets.

    Pipeline per packet:
        1. Retrieve packet from queue
        2. Update flow state
        3. Run detection logic
        4. Dispatch alerts if any are triggered

    Runs continuously until stop_event is set.
    """
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
    """
    Entry point for the Mini IDS system.

    Responsibilities:
        - Load configuration
        - Initialize core components (sniffer, detector, tracker)
        - Start background processing thread
        - Capture packets in real time
        - Gracefully shutdown on interruption
    """
    config = load_config(CONFIG_PATH)

    # Thread-safe queue for packet processing pipeline
    packet_queue: Queue = Queue()
    stop_event = threading.Event()

    # Core IDS components
    flow_tracker = FlowTracker()
    detector = Detector(config)
    alert_manager = AlertManager(LOG_PATH)

    # Background worker for analysis pipeline
    worker_thread = threading.Thread(
        target=packet_worker,
        args=(packet_queue, flow_tracker, detector, alert_manager, stop_event),
        daemon=True,  # allows clean exit if main thread stops
    )
    worker_thread.start()

    # Packet capture engine (pushes packets into queue)
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
        # Signal shutdown and wait for worker cleanup
        stop_event.set()
        worker_thread.join()
        print("Goodbye.")


if __name__ == "__main__":
    main()
