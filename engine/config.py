from detector.ARPDetector import ARPDetector
from detector.IPDetector import IPDetector

ENABLED_DETECTORS = {
    "ARP": ARPDetector(),
    "IP": IPDetector(),
}

# MUST be reachable from VM
BACKEND_WS_URL = "ws://192.168.56.1:8000/ws/device"

LOG_PATH = "/media/sf_shared/logs.txt"
