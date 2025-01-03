import tkinter as tk
from tkinter import ttk
import socket
import threading
import time
import os
import platform


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

        # Auto Scan Controls
        self.auto_scan_var = tk.BooleanVar(value=False)
        self.auto_scan_checkbox = tk.Checkbutton(
            self.control_panel_frame, text="Enable Auto Scan", variable=self.auto_scan_var, command=self.toggle_auto_scan
        )
        self.auto_scan_checkbox.pack(side=tk.LEFT, padx=5)

        self.scan_interval_label = tk.Label(self.control_panel_frame, text="Interval (s):")
        self.scan_interval_label.pack(side=tk.LEFT, padx=(5, 0))
        self.scan_interval_spinner = ttk.Spinbox(self.control_panel_frame, from_=5, to=3600, width=5)
        self.scan_interval_spinner.set(30)
        self.scan_interval_spinner.pack(side=tk.LEFT, padx=5)

        # Output area
        self.output_area = tk.Text(self, wrap=tk.WORD, state='disabled', bg="black", fg="green", font=("Monospaced", 14))
        self.output_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))

        # Flags and thread setup
        self.scanning = False
        self.auto_scanning = False
        self.auto_scan_thread = None
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
                    self.append_output(f"{test_ip} is active.\n")
                    threading.Thread(target=self.scan_ports, args=(test_ip,)).start()
                else:
                    self.append_output(f"{test_ip} is inactive.\n")
                time.sleep(0.1)
        finally:
            self.scanning = False

    def ping_device(self, ip):
        """
        Ping the device to check if it is active.
        """
        param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
        command = f"ping {param} {ip}"
        return os.system(command) == 0

    def scan_ports(self, ip):
        open_ports = []
        hostname = None

        # Attempt to resolve the DNS hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]  # Perform reverse DNS lookup
        except socket.herror:
            hostname = "Unknown Host"  # No reverse DNS record found
        except Exception as e:
            hostname = f"DNS Error: {str(e)}"  # Other errors

        for port in range(20, 1025):  # Common range of ports to scan
            if not self.scanning:
                break
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
            except Exception:
                pass

        # Display results
        if open_ports:
            self.append_output(
                f"{ip} ({hostname}): Open Ports: {', '.join(map(str, open_ports))}\n"
            )
        elif hostname != "Unknown Host":
            self.append_output(f"{ip} ({hostname}): No open ports found\n")
        else:
            self.append_output(f"{ip}: DNS resolution failed, no open ports found\n")

    def stop_scan(self):
        self.scanning = False
        self.auto_scanning = False
        self.auto_scan_var.set(False)
        self.append_output("Stopping the scan...\n")

    def toggle_auto_scan(self):
        if self.auto_scan_var.get():
            self.auto_scanning = True
            self.start_auto_scan()
        else:
            self.auto_scanning = False

    def start_auto_scan(self):
        def auto_scan_loop():
            while self.auto_scanning:
                self.start_scan()
                interval = int(self.scan_interval_spinner.get())
                time.sleep(interval)

        self.auto_scan_thread = threading.Thread(target=auto_scan_loop, daemon=True)
        self.auto_scan_thread.start()

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
