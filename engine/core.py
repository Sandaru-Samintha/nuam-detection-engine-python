import datetime
import subprocess
from scapy.all import ARP, IP

class DetectionEngine:
    def __init__(self , detectors):
        
        self.known_devices = {}
        self.detectors = detectors
        
    def observe_type(self, packet):
        
        if ARP in packet:
            return "ARP"
        elif IP in packet:
            return "IP"
        elif packet.haslayer('TCP'):
            return "TCP"
        elif packet.haslayer('UDP'):
            return "UDP"
        elif packet.haslayer('ICMP'):
            return "ICMP"
        elif packet.haslayer('DNS'):
            return "DNS"
        elif packet.haslayer('HTTP'):
            return "HTTP"
        elif packet.haslayer('TLS'):
            return "TLS"
        return None
    
    
    def extract_device_info(self , packet , observed_type):
        details = self.detectors[observed_type].extract_details(packet)
        return details
    
    
    def is_new_device_joined(self , details):
        mac_address = details["src_mac"]
        if mac_address not in self.known_devices:
            self.known_devices[mac_address] = True
            return True
        return False
    
    
    def handle_device_left_event(self , packet , observed_type):
        pass
    
    
    def is_device_left(self , mac_address):
        
        if mac_address in self.known_devices:
            del self.known_devices[mac_address]
            return True
        return False
    
    
    def generate_event(self, details , detector_name):
        
        event = {
            "detector": detector_name,
            "details": details,
            "detected_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
        }
           
        return event
    
    def get_known_devices(self):
        return list(self.known_devices.keys())
    
    # def ping_device(self , mac_address):
    #     if mac_address in self.known_devices:
    #         subprocess.run(["ping" , "-c" , "1" , self.known_devices[mac_address]])
    #         return True
    #     return False
    