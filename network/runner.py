
import os
import time

from engine.config import ENABLED_DETECTORS
from engine.core import DetectionEngine
from utils.packet_source import start_sniffing


def generate_test_traffic():
    
    TARGET_IP = "10.0.0.2"

    while True:
        os.system(f"ping -c 1 {TARGET_IP} > /dev/null 2>&1")
        os.system(f"arping -c 1 {TARGET_IP} > /dev/null 2>&1")
        time.sleep(2)



def start_detection_engine():
    engine = DetectionEngine(ENABLED_DETECTORS)

    def on_packet(pkt):
        packet_type = engine.observe_type(pkt)
        
        if packet_type not in ENABLED_DETECTORS:
            print("Unsupported packet type:", packet_type)
            return
        
        observed_details = engine.extract_device_info(pkt, packet_type)
        is_new = engine.is_new_device_joined(observed_details)

        if is_new:
            event = engine.generate_event(
                observed_details,
                detector_name=f"{packet_type} Detector"
            )
            print("New device joined:", event)

    start_sniffing(on_packet)
