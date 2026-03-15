from engine.core import DetectionEngine
from engine.config import ENABLED_DETECTORS, BACKEND_WS_URL
from logger.logger import Logger
from handler.event_handler import EventTypeHandler
from handler.data_handler import DataHandler
from utils.packet_source import start_sniffing

def start_detection_engine():
    engine = DetectionEngine(ENABLED_DETECTORS)
    INTERVAL = 5  # seconds

    logger = Logger(BACKEND_WS_URL)
    logger.init_socket_connection()

    event_type_handler = EventTypeHandler()
    data_handler = DataHandler(logger, event_type_handler)

    data_handler.start_periodic_check(INTERVAL * 3)
    data_handler.send_periodic_metrics(INTERVAL)
    data_handler.send_periodic_topology(INTERVAL * 2)

    def on_packet(pkt):
        packet_types = engine.observe_types(pkt)
        
        for packet_type in packet_types: 
        
            if packet_type not in ENABLED_DETECTORS:
                continue
        
            print(f"[Packet] Detected {packet_type} packet")
            
            observed_details, observed_type = engine.extract_device_info(pkt, packet_type)
            print("Packet Data : " , observed_details['src_ip'])
            data_handler.handle_observed_data(pkt, observed_details, observed_type)

    start_sniffing(on_packet)


if __name__ == "__main__":
    start_detection_engine()
