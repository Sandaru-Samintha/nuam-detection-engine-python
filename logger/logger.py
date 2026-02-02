import websocket
import json
import logging
import time

class Logger:

    def __init__(self, backend_ws_url, log_path="/media/sf_shared/logs.txt"):
        self.backend_ws_url = backend_ws_url
        self.log_path = log_path
        self.ws = None

    def init_socket_connection(self):
        try:
            self.ws = websocket.WebSocket()
            self.ws.connect(self.backend_ws_url)
            print(f"[Logger] WebSocket connected {self.backend_ws_url}")
        except Exception as e:
            print(f"[ERROR] WebSocket connection failed: {e}")
            self.ws = None

    def send_event(self, event):
        if self.ws:
            try:
                self.ws.send(json.dumps(event))
            except Exception as e:
                print(f"[ERROR] Failed to send event: {e}")
                self.ws = None
                self.log_event(event)
        else:
            self.log_event(event)

    def log_event(self, event):
        print(
            f"[{event['detected_timestamp']}] "
            f"Detector: {event['detector']}, Details: {event['details']}"
        )

    def write_to_file(self, event, file_path="/media/sf_shared/logs.txt"):
        try:
            with open(file_path, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            print(f"[ERROR] Failed to write log to file: {e}")

    def debug_log(self, message):
        logging.basicConfig(filename=self.log_path, level=logging.DEBUG)
        logging.debug(message)
