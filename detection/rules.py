from collections import defaultdict
from typing import List, Dict

from alerts.alert import Alert
from flow.flow_record import FlowRecord


def port_scan_detection(
    packet_meta: dict,
    state: dict,
    config: dict,
) -> List[Alert]:
    """
    Detects if a single source IP is hitting many different destination ports
    on the same target within a time window.
    """
    alerts: List[Alert] = []

    src_ip = packet_meta["src_ip"]
    dst_ip = packet_meta["dst_ip"]
    dst_port = packet_meta["dst_port"]
    ts = packet_meta["timestamp"]

    if dst_port is None:
        return alerts

    window = config.get("scan_time_window", 10)
    threshold = config.get("port_scan_threshold", 20)

    history: Dict[str, Dict[str, list]] = state.setdefault(
        "port_scan_history",
        defaultdict(lambda: defaultdict(list))
    )

    ports_list = history[src_ip][dst_ip]
    ports_list.append((dst_port, ts))

    # Keep only events within window
    ports_list[:] = [(p, t) for (p, t) in ports_list if ts - t <= window]

    unique_ports = {p for (p, _) in ports_list}

    if len(unique_ports) >= threshold:
        alert = Alert(
            alert_type="Port Scan Detected",
            src_ip=src_ip,
            description=(
                f"Source {src_ip} connected to {len(unique_ports)} ports "
                f"on {dst_ip} within {window} seconds."
            ),
        )
        alerts.append(alert)

        # Reset to avoid repeated alerts
        history[src_ip][dst_ip].clear()

    return alerts


def high_connection_rate_detection(
    packet_meta: dict,
    state: dict,
    config: dict,
) -> List[Alert]:
    """
    Detects high connection rate from a single source IP.
    """
    alerts: List[Alert] = []

    src_ip = packet_meta["src_ip"]
    ts = packet_meta["timestamp"]

    window = config.get("connection_time_window", 10)
    threshold = config.get("high_connection_threshold", 50)

    history = state.setdefault("conn_rate_history", defaultdict(list))
    events = history[src_ip]

    events.append(ts)

    # Keep only events within window
    events[:] = [t for t in events if ts - t <= window]

    if len(events) >= threshold:
        alert = Alert(
            alert_type="High Connection Rate",
            src_ip=src_ip,
            description=(
                f"Source {src_ip} initiated {len(events)} connections "
                f"within {window} seconds."
            ),
        )
        alerts.append(alert)

        history[src_ip].clear()

    return alerts


def suspicious_port_detection(
    packet_meta: dict,
    flow: FlowRecord,
    config: dict,
) -> List[Alert]:
    """
    Flags connections to suspicious ports.
    """
    alerts: List[Alert] = []

    suspicious_ports = set(config.get("suspicious_ports", []))
    dst_port = packet_meta["dst_port"]

    if dst_port is None:
        return alerts

    if dst_port in suspicious_ports:
        alert = Alert(
            alert_type="Suspicious Port Access",
            src_ip=packet_meta["src_ip"],
            description=(
                f"Connection from {packet_meta['src_ip']} "
                f"to {packet_meta['dst_ip']} "
                f"on suspicious port {dst_port} ({flow.protocol})."
            ),
        )
        alerts.append(alert)

    return alerts
