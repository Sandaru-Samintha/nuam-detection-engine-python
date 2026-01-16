# from engine.core import DetectionEngine
# from utils.packet_source import start_sniffing
# from engine.config import ENABLED_DETECTORS , BACKEND_BASE_URL , BACKEND_PORT
# from logger.logger import Logger

# engine = DetectionEngine(ENABLED_DETECTORS)

# # logger = Logger()
# # logger.init_socket_connection(BACKEND_BASE_URL, BACKEND_PORT)

# def on_packet(pkt):
#     packet_type = engine.observe_type(pkt)
#     observed_details = engine.extract_device_info(pkt , packet_type)
#     is_new = engine.is_new_device_joined(observed_details)
    
#     if is_new:
#         event = engine.generate_event(observed_details , detector_name=packet_type + " Detector")
#         # logger.send_event(event)
#         print("New device joined:", event)

# start_sniffing(on_packet)

from multiprocessing import Process
from network.runner import generate_test_traffic, start_detection_engine

if __name__ == "__main__":
    detector_process = Process(target=start_detection_engine)
    traffic_process = Process(target=generate_test_traffic)

    detector_process.start()
    traffic_process.start()

    detector_process.join()
    traffic_process.join()