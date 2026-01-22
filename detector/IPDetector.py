from detector.base import Detector
from scapy.all import Ether

class IPDetector(Detector):
    def __init__(self):
        super().__init__(name="IPDetector", detector_type="IP")
        
    def extract_details(self, packet):
        ip_layer = packet.getlayer("IP")
        eth = packet.getlayer(Ether)
        
        details = {
            "eth_src": eth.src,
            "eth_dst": eth.dst,
            "eth_type": eth.type,
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "version": ip_layer.version,
            "ihl": ip_layer.ihl,
            "tos": ip_layer.tos,
            "len": ip_layer.len,
            "id": ip_layer.id,
            "flags": ip_layer.flags,
            "frag": ip_layer.frag,
            "ttl": ip_layer.ttl,
            "proto": ip_layer.proto,
            "chksum": ip_layer.chksum,
        }
        
        return details
    