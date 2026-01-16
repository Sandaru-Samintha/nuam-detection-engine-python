from detector import ARPDetector

ENABLED_DETECTORS = [
    ARPDetector(name = "ARPDetector" , detector_type="ARP"),
]

BACKEND_BASE_URL = "http://192.168.56.1"
BACKEND_PORT = 5000