from detector.base import Detector
from scapy.all import ARP , Ether

class ARPDetector(Detector):
    def __init__(self):
        super().__init__(name="ARPDetector", detector_type="ARP")
        
    def extract_details(self, packet):
        arp_layer = packet.getlayer(ARP)
        eth = packet.getlayer(Ether)
        
        details = {
            "eth_src": eth.src,
            "eth_dst": eth.dst,
            "eth_type": eth.type,
            "is_broadcast": eth.dst == "ff:ff:ff:ff:ff:ff",
            
            "src_mac": arp_layer.hwsrc,
            "dst_mac": arp_layer.hwdst,
            "src_ip": arp_layer.psrc,
            "dst_ip": arp_layer.pdst,
            "operation": arp_layer.op
        }
        return details