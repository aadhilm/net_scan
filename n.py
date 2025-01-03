import tkinter as tk
from tkinter import ttk
import socket
import subprocess
import threading


class NetworkScanner(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Network Scanner")
        self.geometry("1200x600")

        # Control panel frame (top row, single row layout)
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
        self.network_prefix_entry.insert(0, "192.168.1")  # Default prefix

        self.end_ip_label = tk.Label(self.control_panel_frame, text="Ending IP Range:")
        self.end_ip_label.pack(side=tk.LEFT, padx=(0, 5))
        self.end_ip_entry = tk.Entry(self.control_panel_frame, width=5)
        self.end_ip_entry.pack(side=tk.LEFT, padx=(0, 15))
        self.end_ip_entry.insert(0, "254")  # Default range

        # Control buttons
        self.scan_button = tk.Button(self.control_panel_frame, text="Start Network Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.stop_scan_button = tk.Button(self.control_panel_frame, text="Stop Scan", command=self.stop_scan)
        self.stop_scan_button.pack(side=tk.LEFT, padx=5)

        self.list_wifi_button = tk.Button(self.control_panel_frame, text="List Available Wi-Fi", command=self.list_wifi)
        self.list_wifi_button.pack(side=tk.LEFT, padx=5)

        self.clear_screen_button = tk.Button(self.control_panel_frame, text="Clear Screen", command=self.clear_screen)
        self.clear_screen_button.pack(side=tk.LEFT, padx=5)

        # UFW Controls
        self.ufw_enable_button = tk.Button(self.control_panel_frame, text="Enable UFW", command=self.enable_ufw)
        self.ufw_enable_button.pack(side=tk.LEFT, padx=5)

        self.ufw_disable_button = tk.Button(self.control_panel_frame, text="Disable UFW", command=self.disable_ufw)
        self.ufw_disable_button.pack(side=tk.LEFT, padx=5)

        self.ufw_allow_label = tk.Label(self.control_panel_frame, text="Allow Port:")
        self.ufw_allow_label.pack(side=tk.LEFT, padx=(10, 5))
        self.ufw_allow_entry = tk.Entry(self.control_panel_frame, width=8)
        self.ufw_allow_entry.pack(side=tk.LEFT, padx=(0, 5))
        self.ufw_allow_button = tk.Button(self.control_panel_frame, text="Allow", command=self.allow_port)
        self.ufw_allow_button.pack(side=tk.LEFT, padx=5)

        self.ufw_block_label = tk.Label(self.control_panel_frame, text="Block Port:")
        self.ufw_block_label.pack(side=tk.LEFT, padx=(10, 5))
        self.ufw_block_entry = tk.Entry(self.control_panel_frame, width=8)
        self.ufw_block_entry.pack(side=tk.LEFT, padx=(0, 5))
        self.ufw_block_button = tk.Button(self.control_panel_frame, text="Block", command=self.block_port)
        self.ufw_block_button.pack(side=tk.LEFT, padx=5)

        self.ufw_list_button = tk.Button(self.control_panel_frame, text="List UFW Rules", command=self.list_ufw_rules)
        self.ufw_list_button.pack(side=tk.LEFT, padx=5)

        # Font size spinner
        self.font_size_label = tk.Label(self.control_panel_frame, text="Font Size:")
        self.font_size_label.pack(side=tk.LEFT, padx=(10, 5))
        self.font_size_spinner = ttk.Spinbox(self.control_panel_frame, from_=8, to=30, command=self.update_font_size, width=3)
        self.font_size_spinner.set(14)
        self.font_size_spinner.pack(side=tk.LEFT, padx=5)

        # Output area
        self.output_area = tk.Text(self, wrap=tk.WORD, state='disabled', bg="black", fg="green", font=("Monospaced", 14))
        self.output_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))

        # Flags and initial display setup
        self.scanning = False
        self.display_main_ip()

    def display_main_ip(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))  # Connecting to an external IP (Google DNS) to get local IP
                main_ip = s.getsockname()[0]
                self.local_ip_entry.config(state='normal')
                self.local_ip_entry.delete(0, tk.END)
                self.local_ip_entry.insert(0, main_ip)
                self.local_ip_entry.config(state='readonly')
        except Exception as e:
            self.local_ip_entry.config(state='normal')
            self.local_ip_entry.delete(0, tk.END)
            self.local_ip_entry.insert(0, "Error fetching IP")
            self.local_ip_entry.config(state='readonly')

    def update_font_size(self):
        font_size = int(self.font_size_spinner.get())
        self.output_area.config(font=("Monospaced", font_size))

    def start_scan(self):
        network_prefix = self.network_prefix_entry.get()
        end_ip = self.end_ip_entry.get()
        self.append_output(f"Starting network scan on {network_prefix}.0-{network_prefix}.{end_ip}...\n")
        # Add scanning logic here

    def stop_scan(self):
        self.append_output("Stopping the scan...\n")
        # Add stop logic here

    def list_wifi(self):
        try:
            self.append_output("Listing available Wi-Fi networks...\n")
            # Add Wi-Fi listing logic here
        except Exception as e:
            self.append_output(f"Error listing Wi-Fi networks: {e}\n")

    def enable_ufw(self):
        self.execute_command("sudo ufw enable", "UFW enabled successfully.\n")

    def disable_ufw(self):
        self.execute_command("sudo ufw disable", "UFW disabled successfully.\n")

    def allow_port(self):
        port = self.ufw_allow_entry.get()
        if port.isdigit():
            self.execute_command(f"sudo ufw allow {port}", f"Port {port} allowed.\n")
        else:
            self.append_output("Invalid port specified for allowing.\n")

    def block_port(self):
        port = self.ufw_block_entry.get()
        if port.isdigit():
            self.execute_command(f"sudo ufw deny {port}", f"Port {port} blocked.\n")
        else:
            self.append_output("Invalid port specified for blocking.\n")

    def list_ufw_rules(self):
        self.execute_command("sudo ufw status numbered", "UFW rules listed below:\n")

    def execute_command(self, command, success_message):
        try:
            subprocess.run(command, shell=True, check=True)
            self.append_output(success_message)
        except subprocess.CalledProcessError as e:
            self.append_output(f"Error executing command: {e}\n")

    def append_output(self, text):
        self.output_area.config(state='normal')
        self.output_area.insert(tk.END, text)
        self.output_area.config(state='disabled')

    def clear_screen(self):
        self.output_area.config(state='normal')
        self.output_area.delete(1.0, tk.END)
        self.output_area.config(state='disabled')


if __name__ == "__main__":
    app = NetworkScanner()
    app.mainloop()
