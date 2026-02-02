import random
import time
from engine.config import ENABLED_DETECTORS
from engine.core import DetectionEngine
from engine.config import BACKEND_WS_URL
from utils.packet_source import start_sniffing
from logger.logger import Logger
from handler.event_handler import EventTypeHandler
from handler.data_handler import DataHandler

def generate_test_traffic(net):
    hosts = [net.get(h) for h in ("h1", "h2", "h3", "h4")]

    while True:
        src = random.choice(hosts)
        dst = random.choice([h for h in hosts if h != src])
        # print(f"[TRAFFIC] {src.name} {dst.IP()}", flush=True)
        src.cmd(f"ping -c 1 {dst.IP()} > /dev/null 2>&1")
        time.sleep(random.uniform(1, 3))


def start_detection_engine():
    engine = DetectionEngine(ENABLED_DETECTORS)
    logger = Logger(BACKEND_WS_URL)
    logger.init_socket_connection()
    event_type_handler = EventTypeHandler()
    data_handler = DataHandler(logger , event_type_handler)

    def on_packet(pkt):
        packet_type = engine.observe_type(pkt)
        
        if packet_type not in ENABLED_DETECTORS:
            return
        
        observed_details = engine.extract_device_info(pkt, packet_type)
        data_handler.handle_observed_data(observed_details, packet_type)
                
    start_sniffing(on_packet)