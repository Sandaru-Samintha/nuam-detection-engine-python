import socket

class Logger:
    
    def __init__(self, backend_base_url , backend_port , log_path = "logs.txt"):
        self.backend_base_url = backend_base_url
        self.backend_port  = backend_port
        self.backend_url = f"{self.backend_base_url}:{self.backend_port}"
        self.log_path = log_path
        self.socket = None
        
    def init_socket_connection(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.backend_base_url, int(self.backend_port)))
            print(f"Socket connection established to {self.backend_url}")
        except Exception as e:
            print(f"[WARNING] Logging over socket is disabled, {self.backend_url} is unreachable. {e}")
            self.socket = None
    
    def log_event(self, event):
        print(f"[{event['detected_timestamp']}] Detector: {event['detector']}, Details: {event['details']}")
        
    def send_event(self , event):
        if self.socket:
            try:
                message = f"[{event['detected_timestamp']}] Detector: {event['detector']}, Details: {event['details']}\n"
                self.socket.sendall(message.encode())
            except Exception as e:
                print(f"[ERROR] Failed to send log over socket: {e}")
        else:
            self.log_event(event)
            
    def write_to_file(self , event , file_path="logs.txt"):
        try:
            with open(file_path, 'a') as f:
                f.write(f"[{event['detected_timestamp']}] Detector: {event['detector']}, Details: {event['details']}\n")
        except Exception as e:
            print(f"[ERROR] Failed to write log to file: {e}")
