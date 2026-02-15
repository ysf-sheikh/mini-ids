# Mini-IDS – Real-Time Network Intrusion Detection System

A lightweight, modular Intrusion Detection System (IDS) built in Python.

Mini-IDS captures live network traffic, tracks flows, and detects suspicious behavior such as port scans, high connection rates, and access to risky ports.

This project was built to demonstrate practical knowledge of networking, packet inspection, and rule-based intrusion detection.

---

## 🚀 Features

- Real-time packet capture using Scapy
- Flow tracking (source/destination IPs, ports, protocol)
- Rule-based detection engine
- Multithreaded architecture (sniffer + processing thread)
- Console and file-based alert logging
- Configurable detection thresholds via JSON
- Modular and extensible design

---

## 🏗 Project Structure

mini-ids/
│
├── main.py
│
├── sniffer/
│ └── packet_sniffer.py
│
├── flow/
│ ├── flow_record.py
│ └── flow_tracker.py
│
├── detection/
│ ├── detector.py
│ └── rules.py
│
├── alerts/
│ ├── alert.py
│ └── alert_manager.py
│
└── config/
└── settings.json

---

## 🧠 Detection Capabilities

### 1. Port Scan Detection
Detects when a source IP connects to multiple different destination ports within a short time window.

Configurable parameters:
- `port_scan_threshold`
- `scan_time_window`

---

### 2. High Connection Rate Detection
Triggers an alert when a single source IP initiates too many connections within a defined time window.

Configurable parameters:
- `high_connection_threshold`
- `connection_time_window`

---

### 3. Suspicious Port Access
Alerts when traffic targets predefined high-risk ports (e.g., Telnet, SMB, RDP).

Configurable parameter:
- `suspicious_ports`

---

## ⚙ Configuration

All detection thresholds can be adjusted in:
config/settings.json

Example:

```json
{
  "port_scan_threshold": 20,
  "scan_time_window": 10,
  "high_connection_threshold": 50,
  "connection_time_window": 10,
  "suspicious_ports": [23, 445, 3389]
}

