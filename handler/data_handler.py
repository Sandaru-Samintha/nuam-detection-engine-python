from datetime import datetime, timezone
from logger.logger import Logger
from handler.event_handler import EventTypeHandler
from threading import Thread, Event
import time

class DataHandler:
    
    def __init__(self, logger: Logger , event_type_handler: EventTypeHandler):
        self.logger = logger
        self.event_type_handler = event_type_handler
        self.known_devices = {}
        self.batch = []
        self.metric_data = {
            "messure_time": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
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
        self._stop_event = Event()
        self._check_thread = None
        self.timeout_seconds = 300
        self.idle_seconds = 180

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
        
    def add_to_batch(self, event,):
        self.batch.append(event)
        
    def send_immediate_event(self , event):
        self.logger.send_event(event)

    def generate_event(self, details, event_type):
        event = self.event_type_handler.handle_event_type(event_type, details, self.sequence_number)
        print(f"[EVENT GENERATED] Type: {event_type} | Sequence: {self.sequence_number} | Details: {details}", flush=True)
        self.sequence_number += 1
        self.logger.send_event(event)
        
    def add_known_device(self, mac_address, details):
        details['first_seen'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        details['last_seen'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        self.known_devices[mac_address] = details
        self.metric_data['total_devices'] += 1
        self.metric_data['active_devices'] += 1
        print(self.known_devices)
        
    def remove_from_known_devices(self, mac_address):
        if mac_address in self.known_devices:
            del self.known_devices[mac_address]
            return True
        return False

    def handle_device_join_event(self, details):
        mac_address = ""
        if "src_mac" in details:
            mac_address = details['src_mac']
        elif "eth_src" in details:
            mac_address = details['eth_src']
        else:
            mac_address = 'Unknown'
            
        if mac_address == 'Unknown':
            return
                
        if mac_address in self.known_devices:
            if self.known_devices[mac_address]['mac'] == "Unknown":
                parsed_details = self.parse_details(details)
                self.known_devices[mac_address].update(parsed_details)
        
            self.known_devices[mac_address]['last_seen'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            self.known_devices[mac_address]['online'] = True
            self.known_devices[mac_address]['status'] = 'active'
            self.generate_event(parsed_details, "DEVICE_ONLINE")
            
        
        if mac_address not in self.known_devices:
            parsed_details = self.parse_details(details)
            self.add_known_device(mac_address, parsed_details)
            self.generate_event(parsed_details, "DEVICE_JOINED")
            
    def handle_device_left_event(self, mac_address):
        return self.remove_from_known_devices(mac_address)
    
    def start_periodic_check(self, interval=60):
        def _periodic_check():
            while not self._stop_event.is_set():
                self.periodic_check_for_device_leave()
                time.sleep(interval)
        
        self._check_thread = Thread(target=_periodic_check, daemon=True)
        self._check_thread.start()
    
    def stop_periodic_check(self):
        if self._check_thread:
            self._stop_event.set()
            self._check_thread.join(timeout=5)
            print("[DATA HANDLER] Periodic device check stopped", flush=True)
    
    def periodic_check_for_device_leave(self):
        current_time = datetime.now(timezone.utc)
        
        if len(self.known_devices.keys()) == 0:
            return
        
        for mac, details in self.known_devices.items():
            last_seen_str = details.get('last_seen')
            if last_seen_str:
                last_seen = datetime.strptime(
                    details['last_seen'],
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ).replace(tzinfo=timezone.utc)

                elapsed = (current_time - last_seen).total_seconds()
                
                if elapsed > self.timeout_seconds:
                    details['online'] = False
                    self.metric_data['active_devices'] -= 1
                    self.handle_device_left_event(mac)
                    self.generate_event(details, "DEVICE_LEFT")
                    
                elif elapsed > self.idle_seconds:
                    details['status'] = 'idle'
                    self.metric_data['active_devices'] -= 1
                    self.generate_event(details, "DEVICE_IDLE")
                    
            print(f"[PERIODIC CHECK] Device: {mac} | Last Seen: {last_seen_str} | Elapsed: {elapsed} seconds", flush=True)
        print(f"[PERIODIC CHECK] Known devices after check: {list(self.known_devices.keys())}", flush=True)
        print("[DATA HANDLER] Periodic device check completed", flush=True)
