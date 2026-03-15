import subprocess
from threading import Thread
# from network.topology import create_lab_network
# from network.runner import generate_test_traffic
# from mininet.cli import CLI
import os
from dotenv import load_dotenv

load_dotenv()

if __name__ == "__main__":
    # from mininet.log import setLogLevel
    # setLogLevel("info")

    # net = create_lab_network()

    # traffic_thread = Thread(
    #     target=generate_test_traffic,
    #     args=(net,),
    #     daemon=True
    # )
    # traffic_thread.start()

    # hIDS = net.get('hIDS')
    # print("*** Starting detection engine on hIDS")
    
    det_engine_proc = subprocess.Popen(
        # ["sudo", "-E", "python3", os.getenv("DETECTION_ENGINE_PATH")],
        ["python", os.getenv("DETECTION_ENGINE_PATH")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # while True:
    #     line = det_engine_proc.stdout.readline()
    #     if line:
    #         print("[DetectionEngine]", line.decode().strip())
    #     elif det_engine_proc.poll() is not None:
    #         print("Detection engine stopped!")
    #         break
        
        
    # enable when detection engine stopped error occured to see the actual error
    while True:
        stdout_line = det_engine_proc.stdout.readline()
        stderr_line = det_engine_proc.stderr.readline()

        if stdout_line:
            print("[DetectionEngine]", stdout_line.decode().strip())

        if stderr_line:
            print("[DetectionEngine][ERROR]", stderr_line.decode().strip())

        if det_engine_proc.poll() is not None:
            print(f"[DetectionEngine] exited with code {det_engine_proc.returncode}")

            # Drain remaining stderr (very important)
            remaining_err = det_engine_proc.stderr.read()
            if remaining_err:
                print("[DetectionEngine][FATAL]")
                print(remaining_err.decode())

            break
                
    # CLI(net)

    # net.stop()
