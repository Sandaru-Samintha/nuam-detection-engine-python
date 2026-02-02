import subprocess
from threading import Thread
from network.topology import create_lab_network
from network.runner import generate_test_traffic
from mininet.cli import CLI
import time
import sys
import os


if __name__ == "__main__":
    from mininet.log import setLogLevel
    setLogLevel("info")

    net = create_lab_network()

    traffic_thread = Thread(
        target=generate_test_traffic,
        args=(net,),
        daemon=True
    )
    traffic_thread.start()

    hIDS = net.get('hIDS')
    print("*** Starting detection engine on hIDS")
    
    det_engine_proc = subprocess.Popen(
        ["sudo", "-E", "python3", "/media/sf_shared/nuam-detection-engine-python/start_detection.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    while True:
        line = det_engine_proc.stdout.readline()
        if line:
            print("[DetectionEngine]", line.decode().strip())
        elif det_engine_proc.poll() is not None:
            print("Detection engine stopped!")
            break
                
    CLI(net)

    net.stop()
