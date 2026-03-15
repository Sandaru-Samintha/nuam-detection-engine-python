from datetime import datetime, timezone
from logger.logger import Logger
from handler.event_handler import EventTypeHandler
from threading import Thread, Event
import time
from packet_analyzer.device_connectivity_analyzer import ConnectivityJoinAnalyzer
from packet_analyzer.device_stat_analyzer import DeviceStatAnalyzer
from packet_analyzer.metric_analyzer import MetricAnalyzer
from handler.periodic_checker_handler import PeriodicCheckerHandler

class DataHandler:
    
    def __init__(self, logger: Logger , event_type_handler: EventTypeHandler):
        self.logger = logger
        self.event_type_handler = event_type_handler
        self.known_devices = {}
        self.batch = []
        self.metric_data = {
            "measure_time": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
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
            "dhcp_packets": 0,
            "http_requests": 0,
            "tls_handshakes": 0,
            "total_packets": 0
        }
        
        self.sequence_number = 0
        self._stop_event = Event()
        self._check_thread = None
        self.timeout_seconds = 60
        self.idle_seconds = 30
        self.mectric_analyzer = MetricAnalyzer(event_type_handler)
        self.device_connectivity_analyzer = ConnectivityJoinAnalyzer(event_type_handler , "10.0.0.0/8")
        self.periodic_checker = PeriodicCheckerHandler()
        self.deviceStatAnalyzer = DeviceStatAnalyzer(event_type_handler)

    def handle_observed_data(self, pkt, details, observed_type):
        self.mectric_analyzer.analyze(details, self.known_devices , self.metric_data)
        self.device_connectivity_analyzer.analyze(pkt, details, self.known_devices , self.metric_data , self.generate_event)
        self.deviceStatAnalyzer.analyze(details, self.known_devices)
        
    def send_batch_data(self):
        if len(self.batch) > 0:
            batch_to_send = self.batch.copy()
            self.batch.clear()
            return batch_to_send
        
    def add_to_batch(self, event):
        self.batch.append(event)
        
    def generate_event(self, details, event_type):
        event = self.event_type_handler.handle_event_type(event_type, details, self.sequence_number)
        self.sequence_number += 1
        self.logger.send_event(event)
        

    def remove_from_known_devices(self, mac_address):
        if mac_address in self.known_devices:
            self.known_devices[mac_address]['online'] = False
            self.known_devices[mac_address]['status'] = 'offline'
            return True
        return False

            
    def handle_device_left_event(self, mac_address):
        return self.remove_from_known_devices(mac_address)
    
    def start_periodic_check(self, interval):
        # self.periodic_checker.start_periodic_check(interval, self.known_devices, self.metric_data, self.generate_event, idle_seconds=interval)
        def _periodic_check():
            while not self._stop_event.is_set():
                self.periodic_check_for_device_leave()
                time.sleep(interval)
        
        self._check_thread = Thread(target=_periodic_check, daemon=True)
        self._check_thread.start()
        
    def send_periodic_metrics(self , interval=10):
        def _metric_check():
            while not self._stop_event.is_set():
                event = self.event_type_handler.handle_event_type("PERIODIC_METRIC_STATE", self.metric_data, self.sequence_number)
                self.sequence_number += 1
                self.logger.send_event(event)
                time.sleep(interval)
        
        metric_thread = Thread(target=_metric_check, daemon=True)
        metric_thread.start()
        
        
    def send_periodic_topology(self , interval=15):
        def _topology_check():
            while not self._stop_event.is_set():
                topology_event = self.event_type_handler.handle_event_type("PERIODIC_TOPOLOGY_STATE", self.known_devices, self.sequence_number)
                self.sequence_number += 1
                self.logger.send_event(topology_event)
                time.sleep(interval)
        
        topology_thread = Thread(target=_topology_check, daemon=True)
        topology_thread.start()
    
    def stop_periodic_check(self):
        if self._check_thread:
            self._stop_event.set()
            self._check_thread.join(timeout=5)
    
    def periodic_check_for_device_leave(self):
        print("Running periodic check for device leave...")
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
                
                if elapsed > self.timeout_seconds and details['online'] == True :
                    details['online'] = False
                    details['status'] = 'offline'  
                    self.handle_device_left_event(mac)
                    self.generate_event(details, "DEVICE_LEFT")
                    
                elif elapsed > self.idle_seconds and details['status'] != 'idle' and details['online'] == True:
                    details['status'] = 'idle'
                    self.generate_event(details, "DEVICE_IDLE")