
import os
import random
import time
from engine.config import ENABLED_DETECTORS
from engine.core import DetectionEngine
from utils.packet_source import start_sniffing


def generate_test_traffic():
    
    HOSTS = {
        "h1": "10.0.0.1",
        "h2": "10.0.0.2",
        "h3": "10.0.0.3",
        "h4": "10.0.0.4",
    }

    while True:
        sender, receiver = random.sample(list(HOSTS.items()), 2)
        sender_host, sender_ip = sender
        receiver_host, receiver_ip = receiver

        print(f"[TRAFFIC] {sender_host} ({sender_ip}) {receiver_host} ({receiver_ip})")

        os.system(
            f"mnexec -a $(pgrep -f 'mininet:{sender_host}') "
            f"arping -c 1 {receiver_ip} > /dev/null 2>&1"
        )

        time.sleep(random.uniform(1, 3))



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
