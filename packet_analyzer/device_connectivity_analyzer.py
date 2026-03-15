from datetime import datetime, timezone
import ipaddress

from handler.event_handler import EventTypeHandler
from packet_analyzer.base import BaseAnalyzer
from device_fingerprint_analyzer.fingerprint_engine import FingerprintEngine
from device_fingerprint_analyzer.oui_loader import OUILoader

class ConnectivityJoinAnalyzer(BaseAnalyzer):
    
    def __init__(self, event_type_handler: EventTypeHandler, local_network="192.168.56.0/24"):
        super().__init__(event_type_handler)
        self.oui_loader = OUILoader(csv_path="./data/oui.csv", cache_file="./data/oui_cache.pkl")
        self.oui_loader.load()
        self.analyzer = FingerprintEngine(self.oui_loader)
        
        self.filter_hosts_ips = {
            "0.0.0.0",
            "255.255.255.255",
        }
        try:
            self.local_network = ipaddress.ip_network(local_network, strict=False)
        except:
            self.local_network = ipaddress.ip_network("192.168.56.0/24", strict=False)

    
    def analyze(self, pkt, details, known_devices , metric_data , generate_event):
        self.handle_device_join_event(pkt, details , known_devices , metric_data , generate_event)
    
    
    def parse_details(self, details):
        out = {}
        
        if "src_mac" in details:
            out['mac'] =  details['src_mac']
        elif "eth_src" in details:
            out['mac'] = details['eth_src']
        else:
            out['mac'] = 'Unknown'
            
        
        if "src_ip" in details:
            out['ip_address'] = details['src_ip']
        elif "psrc" in details:
            out['ip_address'] = details['psrc']
        else:
            out['ip_address'] = 'Unknown'
            
        out['hostname'] = 'Unknown'
        out['first_seen'] = None
        out['last_seen'] = None
        out['online'] = True
        out['device_type'] = 'Unknown'
        out['vendor'] = 'Unknown'
        out['os'] = 'Unknown'
        out['data_sent'] = 0
        out['data_received'] = 0
        out['packet_count'] = 0
        out['status'] = 'active'
        out['access_logs'] = []
        out['access_services'] = []
        return out
    
    def should_filter_ip(self, ip_address):
        """Check if IP should be filtered (localhost, non-local network, or invalid)"""
        if ip_address == 'Unknown' or ip_address in self.filter_hosts_ips:
            return True
        
        try:
            ip_obj = ipaddress.ip_address(ip_address)
                        
            # Filter localhost addresses (127.0.0.0/8)
            if ip_obj.is_loopback:
                return True
            
            # Filter link-local addresses (169.254.0.0/16)
            if ip_obj.is_link_local:
                return True
            
            # Filter multicast addresses
            if ip_obj.is_multicast:
                return True
            
            # Check if IP is in local network
            if not ip_obj in self.local_network:
                return True
            
            return False
        except ValueError:
            # Invalid IP address
            return True
    
    def add_known_device(self, mac_address, details, known_devices, metric_data):
        details['first_seen'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        details['last_seen'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        known_devices[mac_address] = details
        metric_data['total_devices'] += 1
        
    def handle_device_join_event(self, pkt, details , known_devices , metric_data , generate_event):
        mac_address = ""
        if "src_mac" in details:
            mac_address = details['src_mac']
        elif "eth_src" in details:
            mac_address = details['eth_src']
        else:
            mac_address = 'Unknown'
            
        if mac_address == 'Unknown':
            return
                
        parsed_details = self.parse_details(details)
        
        # Filter out devices with invalid or non-local IPs
        if self.should_filter_ip(parsed_details.get('ip_address', 'Unknown')):
            return
        
        if mac_address in known_devices:
            if known_devices[mac_address]['mac'] == "Unknown":
                known_devices[mac_address].update(parsed_details)
        
            known_devices[mac_address]['last_seen'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            known_devices[mac_address]['online'] = True
            known_devices[mac_address]['status'] = 'active'
            
                    
        if mac_address not in known_devices:
            
            analyzer_result = self.analyzer.analyze_packet(pkt)
            parsed_details['vendor'] = analyzer_result['manufacturer']
            parsed_details['device_type'] = analyzer_result['device_type']
            parsed_details['os'] = analyzer_result['os']
            parsed_details['status'] = 'active'
            
            self.add_known_device(mac_address, parsed_details, known_devices, metric_data)
            generate_event(parsed_details, "DEVICE_JOINED")
        

# class ConnectivityLeaveAnalyzer(BaseAnalyzer):
    
#     def __init__(self, event_type_handler: EventTypeHandler):
#         super().__init__(event_type_handler)
    
#     def analyze(self, details, known_devices , metric_data , generate_event):
#         mac_address = ""
#         if "src_mac" in details:
#             mac_address = details['src_mac']
#         elif "eth_src" in details:
#             mac_address = details['eth_src']
#         else:
#             mac_address = 'Unknown'
            
#         if mac_address == 'Unknown':
#             return
                
#         if mac_address in known_devices:
#             known_devices[mac_address]['online'] = False
#             known_devices[mac_address]['status'] = 'inactive'
#             generate_event(known_devices[mac_address], "DEVICE_LEFT")