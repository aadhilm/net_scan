import tkinter as tk
from tkinter import ttk
import socket
import threading
import time
import os
import platform
import networkx as nx
import matplotlib.pyplot as plt
from scapy.all import traceroute


class NetworkScanner(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Network Scanner")
        self.geometry("1200x700")

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

        # Visualization and advanced features
        self.visualize_button = tk.Button(self.control_panel_frame, text="Visualize Network Topology", command=self.visualize_network)
        self.visualize_button.pack(side=tk.LEFT, padx=5)

        self.traceroute_button = tk.Button(self.control_panel_frame, text="Traceroute", command=self.run_traceroute)
        self.traceroute_button.pack(side=tk.LEFT, padx=5)

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
        self.device_graph = nx.Graph()  # Graph for network topology
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
                    self.device_graph.add_node(test_ip)  # Add node for device
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

        # Display results in the listbox
        if open_ports:
            device_info = f"{ip} ({hostname}): Open Ports: {', '.join(map(str, open_ports))}"
            self.append_output(device_info + "\n")
            self.device_listbox.insert(tk.END, device_info)
            self.device_graph.add_edge(self.local_ip_entry.get(), ip)  # Add edge between devices
        elif hostname != "Unknown Host":
            device_info = f"{ip} ({hostname}): No open ports found"
            self.append_output(device_info + "\n")
            self.device_listbox.insert(tk.END, device_info)
        else:
            device_info = f"{ip}: DNS resolution failed, no open ports found"
            self.append_output(device_info + "\n")
            self.device_listbox.insert(tk.END, device_info)

    def stop_scan(self):
        self.scanning = False
        self.append_output("Stopping the scan...\n")

    def visualize_network(self):
        """
        Visualize the network topology using matplotlib and networkx.
        """
        nx.draw(self.device_graph, with_labels=True, node_size=500, node_color='skyblue', font_size=10)
        plt.title("Network Topology")
        plt.show()

    def run_traceroute(self):
        """
        Run a traceroute to a specified IP address or hostname.
        """
        target = self.local_ip_entry.get()
        self.append_output(f"Running traceroute to {target}...\n")
        try:
            ans, _ = traceroute(target, timeout=2, verbose=0)
            for s, rtt in ans:
                self.append_output(f"{s} with RTT: {rtt}ms\n")
        except Exception as e:
            self.append_output(f"Error in traceroute: {e}\n")

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
