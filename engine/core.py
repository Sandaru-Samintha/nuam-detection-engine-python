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
        return details , observed_type
    
    
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
    
    def get_known_devices(self):
        return list(self.known_devices.keys())
    