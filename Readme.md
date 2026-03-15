# IDS Engine

> Network LAN detection engine that sniffs packets, identifies connected hosts via multi-protocol analysis, tracks device lifecycle (joined/idle/left), and streams structured events to a backend service.

## Quick Start

```bash
# 1. Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1      # Windows
# source venv/bin/activate       # Linux/macOS

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure and run
python start_detection.py
```

> **Note:** Packet sniffing requires administrator/root privileges.

---

## Project Description

### Problem Statement

In modern LAN environments, monitoring connected devices is critical for network management, security, and incident response. Manually tracking devices or relying on limited tools leads to incomplete network visibility, delayed threat detection, and poor operational awareness.

### Objectives

- Passively detect all devices active on a LAN without injecting disruptive traffic.
- Identify devices using nine protocol-based detection methods: ARP, DHCP, DNS, ICMP, IP, TCP-IP, SMB, TLS, and UDP.
- Fingerprint devices by matching MAC OUI prefixes to known vendors.
- Track device lifecycle transitions: joined → idle → left.
- Stream structured, sequenced events to a backend service in real time.
- Provide periodic topology and metric snapshots for dashboards and audits.

### Target Users

- **Network administrators** managing small to medium LANs who need continuous visibility.
- **Security professionals** conducting network audits or monitoring for unauthorised devices.
- **Researchers** analysing device connectivity, protocol behaviour, or network topology in lab environments.

### Overview

IDS Engine runs as a background Python process on a host with access to the LAN. It uses Scapy to capture raw packets and passes each packet through a detection pipeline that classifies protocol types, extracts device metadata, and maintains a stateful map of known devices. Events are emitted over WebSocket to a backend in real time. When the backend is unreachable, events are written to a local log file for later ingestion.

---

## System Architecture / Design

### Workflow

```
Packet Capture (Scapy)
       |
       v
 DetectionEngine          <-- classifies protocol types per packet (non-exclusive)
       |
       v
 Protocol Detectors       <-- extracts src/dst IP, MAC, hostname, ports, flags
       |
       v
  DataHandler             <-- updates known-device state & aggregated metrics
       |
       v
 EventTypeHandler         <-- shapes typed, sequenced event payloads
       |
       v
    Logger
   /       \
WebSocket  logs.txt       <-- primary stream to backend / offline fallback
```

### Components

| Component | Location | Responsibility |
|---|---|---|
| `DetectionEngine` | `engine/core.py` | Classifies protocol layer(s) present in each packet |
| `ARPDetector` … `UDPDetector` | `detector/` | Extracts device metadata per protocol |
| `DataHandler` | `handler/data_handler.py` | Maintains `known_devices` map, drives periodic tasks |
| `EventTypeHandler` | `handler/event_handler.py` | Produces typed JSON event payloads |
| `ConnectivityJoinAnalyzer` | `packet_analyzer/device_connectivity_analyzer.py` | Detects first-seen and re-join events |
| `MetricAnalyzer` | `packet_analyzer/metric_analyzer.py` | Aggregates packet-level counters |
| `DeviceStatAnalyzer` | `packet_analyzer/device_stat_analyzer.py` | Tracks per-device byte/packet statistics |
| `Logger` | `logger/logger.py` | WebSocket client with auto-reconnect; falls back to file |
| `FingerprintEngine` | `device_fingerprint_analyzer/fingerprint_engine.py` | Resolves vendor name from MAC OUI |
| `OUILoader` | `device_fingerprint_analyzer/oui_loader.py` | Loads and caches `data/oui.csv` |

### Periodic Tasks

| Task | Default interval | Event subtype emitted |
|---|---|---|
| Device timeout / offline check | 15 s (3× base) | `DEVICE_LEFT` |
| Device idle mark | 30 s idle threshold | `DEVICE_IDLE` |
| Metrics snapshot | 5 s (base) | `PERIODIC_METRIC_STATE` |
| Topology snapshot | 10 s (2× base) | `PERIODIC_TOPOLOGY_STATE` |

---

## Technologies Used

| Category | Technology | Version / Notes |
|---|---|---|
| Language | Python | 3.10+ |
| Packet capture | [Scapy](https://scapy.net/) | 2.7.0 |
| WebSocket client | [websocket-client](https://github.com/websocket-client/websocket-client) | 1.9.0 |
| Environment config | [python-dotenv](https://github.com/theskumar/python-dotenv) | 1.2.2 |
| HTTP | requests | 2.32.5 |
| Async I/O (optional) | gevent | 25.9.1 (installed in venv) |
| OUI data | IEEE OUI CSV | `data/oui.csv` |
| Version control | Git | — |
| Runtime isolation | Python venv | — |

---

## Installation Instructions

### System Requirements

- Python 3.10 or above
- `pip`
- Administrator / root privileges (required for raw packet capture)
- A network interface accessible to Scapy on the monitoring host

### Step-by-step Installation

#### Windows

```powershell
git clone https://github.com/NaveenDanj/nuam-detection-engine-python
cd IDS-engine
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

#### Linux / macOS

```bash
git clone https://github.com/NaveenDanj/nuam-detection-engine-python
cd IDS-engine
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configuration

Create a `.env` file in the project root (or edit the existing one):

```env
DETECTION_ENGINE_PATH="./start_detection.py"
BACKEND_WS_URL="ws://192.168.56.1:8000/ws/device"
LOG_PATH="./logs.txt"
```

| Variable | Description | Default |
|---|---|---|
| `DETECTION_ENGINE_PATH` | Script spawned by `main.py` | `./start_detection.py` |
| `BACKEND_WS_URL` | WebSocket endpoint for event streaming | `ws://192.168.56.1:8000/ws/device` |
| `LOG_PATH` | Local fallback log file path | `./logs.txt` |

### How to Run

**Option 1 — Direct (recommended for development)**

```bash
python start_detection.py
```

Starts the detection engine, WebSocket logger, and all periodic tasks in-process.

**Option 2 — Via launcher**

```bash
python main.py
```

Spawns `start_detection.py` as a subprocess and streams its `stdout`/`stderr` to the console — useful for diagnosing subprocess-level errors.

---

## Usage Instructions

### Basic Usage

1. Ensure the `.env` file is configured and your backend WebSocket server is running.
2. Run the engine with elevated privileges:

```bash
# Windows (run PowerShell as Administrator)
python start_detection.py

# Linux / macOS
sudo python3 start_detection.py
```

3. The engine starts sniffing all packets on the default interface and prints detected activity:

```
[Packet] Detected ARP packet
[Packet] Detected DHCP packet
Packet Data :  192.168.1.42
[Packet] Detected DNS packet
...
Running periodic check for device leave...
```

### Example Event Output

When a new device is detected, an event like the following is sent to the WebSocket backend (and written to `logs.txt` if offline):

```json
{
  "meta": {
    "timestamp": "2026-03-16T10:05:23.412Z",
    "sequence": 1
  },
  "type": "TOPOLOGY",
  "subtype": "DEVICE_JOINED",
  "payload": {
    "event_type": "device_connected",
    "timestamp": "2026-03-16T10:05:23.412Z",
    "device": {
      "device_id": "aa:bb:cc:dd:ee:ff",
      "hostname": "mydevice.local",
      "ip_address": "192.168.1.42",
      "device_type": "unknown",
      "os": "unknown",
      "vendor": "Raspberry Pi Trading Ltd",
      "first_seen": "2026-03-16T10:05:23.412Z",
      "last_seen": "2026-03-16T10:05:23.412Z"
    }
  }
}
```

### Periodic Metric Snapshot (example)

```json
{
  "meta": { "timestamp": "2026-03-16T10:05:28.000Z", "sequence": 5 },
  "type": "METRIC",
  "subtype": "PERIODIC_METRIC_STATE",
  "payload": {
    "event_type": "metric_snapshot",
    "metrics": {
      "total_devices": 4,
      "active_devices": 3,
      "total_packets": 1240,
      "arp_requests": 18,
      "arp_replies": 17,
      "dns_queries": 95,
      "tcp_packets": 830,
      "udp_packets": 210
    }
  }
}
```

### Log File

When the backend is unreachable, events are appended as newline-delimited JSON to `logs.txt`:

```
{"meta": {"timestamp": "...", "sequence": 0}, "type": "TOPOLOGY", "subtype": "DEVICE_JOINED", "payload": {...}}
{"meta": {"timestamp": "...", "sequence": 1}, "type": "METRIC", "subtype": "PERIODIC_METRIC_STATE", "payload": {...}}
```

---

## Dataset

### OUI Vendor Data

| Field | Detail |
|---|---|
| File | `data/oui.csv` |
| Description | IEEE Organizationally Unique Identifier (OUI) assignments mapping 24-bit MAC address prefixes to registered vendor names |
| Source | [IEEE Registration Authority](https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries) |
| Format | CSV — columns: `Assignment`, `Organization Name`, `Organization Address` |
| Licence | Public domain (IEEE public registry) |
| Usage | Loaded by `device_fingerprint_analyzer/oui_loader.py` at startup and cached to `data/oui_cache.pkl` for fast lookups |

No other external datasets are required. All network data is captured live from the local interface at runtime.

---

## Project Structure

```
IDS-engine/
├── .env                              # Runtime configuration (not committed)
├── start_detection.py                # Main entry point
├── main.py                           # Subprocess launcher (reads .env)
├── requirements.txt                  # Python dependencies
├── LICENSE                           # MIT Licence
├── Readme.md                         # This file
│
├── engine/
│   ├── core.py                       # DetectionEngine: protocol classification
│   └── config.py                     # Detector registry & env config
│
├── detector/
│   ├── base.py                       # Abstract base detector
│   ├── ARPDetector.py
│   ├── DHCPDetector.py
│   ├── DNSDetector.py
│   ├── ICMPDetector.py
│   ├── IPDetector.py
│   ├── SMBDetector.py
│   ├── TCPIPDetector.py
│   ├── TLSDetector.py
│   └── UDPDetector.py
│
├── handler/
│   ├── data_handler.py               # Device state, metrics, periodic tasks
│   ├── event_handler.py              # Event payload shaping
│   └── periodic_checker_handler.py
│
├── packet_analyzer/
│   ├── base.py
│   ├── device_connectivity_analyzer.py
│   ├── device_stat_analyzer.py
│   └── metric_analyzer.py
│
├── device_fingerprint_analyzer/
│   ├── fingerprint_engine.py
│   ├── host_profile.py
│   └── oui_loader.py
│
├── logger/
│   └── logger.py                     # WebSocket + file logger
│
├── utils/
│   └── packet_source.py              # Scapy sniff wrapper
│
├── network/
│   ├── topology.py                   # Lab network topology (Mininet)
│   └── runner.py                     # Test traffic generator (Mininet)
│
├── data/
│   ├── oui.csv                       # IEEE OUI vendor data
│   └── oui_cache.pkl                 # Cached OUI lookups (auto-generated)
│
├── scripts/                          # Utility / helper scripts
└── logs.txt                          # Event log (fallback output)
```

---

## Screenshots / Demo

> _Screenshots and demo recordings will be added here._  
> In the meantime, see the [Usage Instructions](#usage-instructions) section for example console output and event payloads.

<!-- Add screenshots like this:
![Console output](docs/screenshots/console_output.png)
![Dashboard topology view](docs/screenshots/topology_dashboard.png)
-->

<!-- Add a demo video link like this:
[![Demo Video](https://img.youtube.com/vi/VIDEO_ID/0.jpg)](https://www.youtube.com/watch?v=VIDEO_ID)
-->

---

## Contributors

| Name | Role |
|---|---|
| _Naveen Hettiwaththa_ | Lead Developer |
| _Ravindu Peshan_ | Developer |

> To contribute, open a pull request or raise an issue on the repository.

---

## Contact Information

| Field | Detail |
|---|---|
| Name | _Naveen Hettiwaththa_ |
| Email | _naveenhettiwaththa@gmail.com_ |
| Institution / Organisation | _University Of Jaffna_ |
| Repository | _https://github.com/naveendanj/nuam-detection-engine-python_ |

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| Permission error on sniff | Insufficient privileges | Run as Administrator (Windows) or `sudo` (Linux) |
| No packets captured | Wrong/no interface | Check Scapy interface selection; verify traffic on the interface |
| WebSocket keeps failing | Backend unreachable | Events fall back to `logs.txt`; confirm `BACKEND_WS_URL` is correct |
| `ModuleNotFoundError` | Missing packages | Run `pip install python-dotenv websocket-client` inside the venv |
| `KeyError: src_ip` | Unsupported packet type | The detector for that type may not populate `src_ip`; check the relevant detector |

---

## Current Limitations

- Scapy uses its default interface selection; no explicit interface configuration is exposed yet.
- `requirements.txt` does not pin `python-dotenv` or `websocket-client` (installed separately in the venv).
- Log file has no rotation — it grows indefinitely by default.

---

## License

This project is licensed under the [MIT License](LICENSE).