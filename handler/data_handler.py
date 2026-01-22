from datetime import datetime, time, timezone
from logger.logger import Logger

class DataHandler:
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.known_devices = {}
        self.batch = []
        self.metric_data = {
            "messure_time": time.time(),
            "total_devices": 0,
            "active_devices": 0,
            "data_sent": 0,
            "data_received": 0,
            "total_broadcast_packets": 0,
            "total_unicast_packets": 0,
            "arp_requests": 0,
            "arp_replies": 0,
            "ip_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "dns_queries": 0,
            "http_requests": 0,
            "tls_handshakes": 0
        }
        self.sequence_number = 0

    def add_known_device(self, mac_address, details):
        device_data = self.parse_details(details)
        device_data['first_seen'] = time.time()
        device_data['last_seen'] = time.time()
        self.known_devices[mac_address] = device_data
        self.metric_data['total_devices'] += 1
        self.metric_data['active_devices'] += 1
        
    def remove_from_known_devices(self, mac_address):
        if mac_address in self.known_devices:
            del self.known_devices[mac_address]
            return True
        return False
    
    def handle_device_join_event(self, details):
        mac_address = details.get("src_mac")
        if mac_address not in self.known_devices:
            parsed_details = self.parse_details(details)
            self.add_known_device(mac_address, parsed_details)
            self.generate_event(parsed_details)
    
    def handle_device_left_event(self, mac_address):
        return self.remove_from_known_devices(mac_address)
    
    def parse_details(self, details):
        out = {}
        out['mac'] = details.get('src_mac')
        out['ip_address'] = details.get('src_ip')
        out['hostname'] = 'Unknown'
        out['first_seen'] = None
        out['last_seen'] = None
        out['online'] = False
        out['device_type'] = 'Unknown'
        out['vendor'] = 'Unknown'
        out['os'] = 'Unknown'
        out['data_sent'] = 0
        out['data_received'] = 0
        out['status'] = 'active'
        out['access_logs'] = []
        out['access_services'] = []
        return out
    
    
    def handle_observed_data(self, details , observed_type):
        self.handle_device_join_event(details)
            
        
    def send_batch_data(self):
        if len(self.batch) > 0:
            batch_to_send = self.batch.copy()
            self.batch.clear()
            return batch_to_send
        
    def add_to_batch(self, event):
        self.batch.append(event)
        
    
    def send_immediate_event(self , event):
        self.logger.send_event(event)

    
    def generate_event(self, details):
        event = {
            "meta": {
                "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                "sequence": self.sequence_number,
            },
            "type": "", # STATE | METRIC | TOPOLOGY | HEALTH
            "payload": details
        }
        self.sequence_number += 1
        self.logger.send_event(event)
