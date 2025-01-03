import tkinter as tk
from tkinter import ttk, filedialog
import socket
import threading
import time
import os
import platform
import csv
from getmac import get_mac_address  # For MAC address retrieval

class NetworkScanner(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Network Scanner")
        self.geometry("1200x600")

        # Control panel frame
        self.control_panel_frame = tk.Frame(self)
        self.control_panel_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        # IP Address label and entry
        self.local_ip_label = tk.Label(self.control_panel_frame, text="Main System IP:")
        self.local_ip_label.pack(side=tk.LEFT, padx=(0, 5))
        self.local_ip_entry = tk.Entry(self.control_panel_frame, state='readonly', fg='black', width=15)
        self.local_ip_entry.pack(side=tk.LEFT, padx=(0, 15))

        # Network prefix and ending IP range
        self.network_prefix_label = tk.Label(self.control_panel_frame, text="Network Prefix:")
        self.network_prefix_label.pack(side=tk.LEFT, padx=(0, 5))
        self.network_prefix_entry = tk.Entry(self.control_panel_frame, width=12)
        self.network_prefix_entry.pack(side=tk.LEFT, padx=(0, 15))
        self.network_prefix_entry.insert(0, "192.168.1")

        self.end_ip_label = tk.Label(self.control_panel_frame, text="Ending IP Range:")
        self.end_ip_label.pack(side=tk.LEFT, padx=(0, 5))
        self.end_ip_entry = tk.Entry(self.control_panel_frame, width=5)
        self.end_ip_entry.pack(side=tk.LEFT, padx=(0, 15))
        self.end_ip_entry.insert(0, "254")

        # Control buttons
        self.scan_button = tk.Button(self.control_panel_frame, text="Start Network Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.stop_scan_button = tk.Button(self.control_panel_frame, text="Stop Scan", command=self.stop_scan)
        self.stop_scan_button.pack(side=tk.LEFT, padx=5)

        self.clear_screen_button = tk.Button(self.control_panel_frame, text="Clear Screen", command=self.clear_screen)
        self.clear_screen_button.pack(side=tk.LEFT, padx=5)

        # Export Results Button
        self.export_button = tk.Button(self.control_panel_frame, text="Export Results", command=self.export_results)
        self.export_button.pack(side=tk.LEFT, padx=5)

        # Output area
        self.output_area = tk.Text(self, wrap=tk.WORD, state='disabled', bg="black", fg="green", font=("Monospaced", 14))
        self.output_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))

        # Device list
        self.device_list_label = tk.Label(self, text="Active Devices:")
        self.device_list_label.pack(pady=5)

        self.device_listbox = tk.Listbox(self, height=15, width=80)
        self.device_listbox.pack(fill=tk.BOTH, padx=5, pady=(0, 5))

        # Flags and thread setup
        self.scanning = False
        self.devices = []  # To store scan results
        self.fetch_main_ip()

    def fetch_main_ip(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                main_ip = s.getsockname()[0]
                self.local_ip_entry.config(state='normal')
                self.local_ip_entry.delete(0, tk.END)
                self.local_ip_entry.insert(0, main_ip)
                self.local_ip_entry.config(state='readonly')
        except Exception:
            self.local_ip_entry.config(state='normal')
            self.local_ip_entry.delete(0, tk.END)
            self.local_ip_entry.insert(0, "Error fetching IP")
            self.local_ip_entry.config(state='readonly')

    def start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.devices.clear()
        network_prefix = self.network_prefix_entry.get()
        end_ip = self.end_ip_entry.get()
        self.append_output(f"Starting network scan on {network_prefix}.0-{network_prefix}.{end_ip}...\n")
        threading.Thread(target=self.simulate_scan, args=(network_prefix, int(end_ip))).start()

    def simulate_scan(self, network_prefix, end_ip):
        try:
            for ip in range(1, end_ip + 1):
                if not self.scanning:
                    break
                test_ip = f"{network_prefix}.{ip}"
                if self.ping_device(test_ip):
                    mac_address = get_mac_address(ip=test_ip) or "Unknown"
                    hostname = self.get_hostname(test_ip)
                    device_info = {"IP": test_ip, "MAC": mac_address, "Hostname": hostname, "Ports": []}
                    self.append_output(f"{test_ip} ({hostname}, MAC: {mac_address}) is active.\n")
                    self.devices.append(device_info)
                    threading.Thread(target=self.scan_ports, args=(test_ip, device_info)).start()
                else:
                    self.append_output(f"{test_ip} is inactive.\n")
                time.sleep(0.1)
        finally:
            self.scanning = False

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return "Unknown Host"

    def ping_device(self, ip):
        param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
        command = f"ping {param} {ip}"
        return os.system(command) == 0

    def scan_ports(self, ip, device_info):
        open_ports = []
        for port in range(20, 1025):
            if not self.scanning:
                break
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
            except Exception:
                pass
        device_info["Ports"] = open_ports
        if open_ports:
            self.append_output(f"{ip}: Open Ports: {', '.join(map(str, open_ports))}\n")
        else:
            self.append_output(f"{ip}: No open ports found.\n")

    def stop_scan(self):
        self.scanning = False
        self.append_output("Stopping the scan...\n")

    def export_results(self):
        if not self.devices:
            self.append_output("No results to export.\n")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not file_path:
            return

        with open(file_path, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["IP Address", "MAC Address", "Hostname", "Open Ports"])
            for device in self.devices:
                writer.writerow([device["IP"], device["MAC"], device["Hostname"], ", ".join(map(str, device["Ports"]))])

        self.append_output(f"Results exported to {file_path}\n")

    def append_output(self, text):
        self.output_area.config(state='normal')
        self.output_area.insert(tk.END, text)
        self.output_area.see(tk.END)
        self.output_area.config(state='disabled')

    def clear_screen(self):
        self.output_area.config(state='normal')
        self.output_area.delete(1.0, tk.END)
        self.output_area.config(state='disabled')

if __name__ == "__main__":
    app = NetworkScanner()
    app.mainloop()
