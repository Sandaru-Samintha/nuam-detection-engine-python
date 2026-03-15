import websocket
import json
import logging
import threading
import time

class Logger:
    def __init__(self, backend_ws_url, log_path="./logs.txt"):
        self.backend_ws_url = backend_ws_url
        self.log_path = log_path
        self.ws_app = None
        self.ws_thread = None
        self.ws_connected = False
        

    def init_socket_connection(self):
        """Initialize WebSocketApp with callbacks and start in a separate thread"""
        def on_open(ws):
            self.ws_connected = True
            print(f"[Logger] WebSocket opened: {self.backend_ws_url}")

        def on_message(ws, message):
            print(f"[Message] {message}")

        def on_close(ws, close_status_code, close_msg):
            self.ws_connected = False
            print(f"[Logger] WebSocket closed: {close_status_code}, {close_msg}")
            # reconnect automatically
            while not self.ws_connected:
                try:
                    ws.run_forever()
                except Exception as e:
                    print(f"[ERROR] WebSocket reconnect failed: {e}")
                    time.sleep(5)

        def on_error(ws, error):
            print(f"[ERROR] WebSocket error: {error}")

        self.ws_app = websocket.WebSocketApp(
            self.backend_ws_url,
            on_open=on_open,
            on_message=on_message,
            on_close=on_close,
            on_error=on_error
        )

        self.ws_thread = threading.Thread(target=self.ws_app.run_forever, kwargs={
            "ping_interval": 30,
            "ping_timeout": 10
        })
        self.ws_thread.daemon = True
        self.ws_thread.start()

    def send_event(self, event):
        if self.ws_connected:
            try:
                self.ws_app.send(json.dumps(event))
            except Exception as e:
                print(f"[ERROR] Failed to send event: {e}")
                self.log_event(event)
        else:
            self.log_event(event)

    def log_event(self, event):
        print(
            f"[{event.get('detected_timestamp', 'N/A')}] "
            f"Detector: {event.get('detector', 'N/A')}, Details: {event.get('details', {})}"
        )
        self.write_to_file(event)

    def write_to_file(self, event, file_path=None):
        path = file_path or self.log_path
        try:
            with open(path, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            print(f"[ERROR] Failed to write log to file: {e}")

    def debug_log(self, message):
        logging.basicConfig(filename=self.log_path, level=logging.DEBUG)
        logging.debug(message)
