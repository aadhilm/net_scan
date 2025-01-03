import tkinter as tk
from tkinter import ttk
import socket
import threading
import time
import os
import platform
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR


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

        # Scheduled Scan Controls
        self.schedule_scan_var = tk.BooleanVar(value=False)
        self.schedule_scan_checkbox = tk.Checkbutton(
            self.control_panel_frame, text="Enable Scheduled Scan", variable=self.schedule_scan_var, command=self.toggle_schedule_scan
        )
        self.schedule_scan_checkbox.pack(side=tk.LEFT, padx=5)

        self.schedule_time_label = tk.Label(self.control_panel_frame, text="Schedule Time (HH:MM):")
        self.schedule_time_label.pack(side=tk.LEFT, padx=(5, 0))
        self.schedule_time_entry = tk.Entry(self.control_panel_frame, width=10)
        self.schedule_time_entry.pack(side=tk.LEFT, padx=5)

        # Email notification controls
        self.email_notification_var = tk.BooleanVar(value=False)
        self.email_notification_checkbox = tk.Checkbutton(
            self.control_panel_frame, text="Send Email Notification", variable=self.email_notification_var
        )
        self.email_notification_checkbox.pack(side=tk.LEFT, padx=5)

        self.email_entry_label = tk.Label(self.control_panel_frame, text="Email Address:")
        self.email_entry_label.pack(side=tk.LEFT, padx=5)
        self.email_entry = tk.Entry(self.control_panel_frame, width=30)
        self.email_entry.pack(side=tk.LEFT, padx=5)

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
        self.scheduler = BackgroundScheduler()
        self.scheduler.add_listener(self.job_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)

    def job_listener(self, event):
        if event.exception:
            self.append_output(f"Job {event.job_id} failed!\n")
        else:
            self.append_output(f"Job {event.job_id} completed successfully.\n")

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

        # Display results in the listbox
        if open_ports:
            device_info = f"{ip} ({hostname}): Open Ports: {', '.join(map(str, open_ports))}"
            self.append_output(device_info + "\n")
            self.device_listbox.insert(tk.END, device_info)
            self.save_log(device_info)
        elif hostname != "Unknown Host":
            device_info = f"{ip} ({hostname}): No open ports found"
            self.append_output(device_info + "\n")
            self.device_listbox.insert(tk.END, device_info)
            self.save_log(device_info)
        else:
            device_info = f"{ip}: DNS resolution failed, no open ports found"
            self.append_output(device_info + "\n")
            self.device_listbox.insert(tk.END, device_info)
            self.save_log(device_info)

    def stop_scan(self):
        self.scanning = False
        self.append_output("Stopping the scan...\n")

    def toggle_schedule_scan(self):
        if self.schedule_scan_var.get():
            self.schedule_scan_time = self.schedule_time_entry.get()
            self.schedule_scan()
        else:
            self.scheduler.remove_all_jobs()

    def schedule_scan(self):
        def scheduled_scan():
            self.start_scan()
        
        schedule_time = self.schedule_scan_time
        hours, minutes = map(int, schedule_time.split(":"))
        self.scheduler.add_job(scheduled_scan, 'interval', hours=hours, minutes=minutes, id="auto_scan_job")
        self.scheduler.start()

    def append_output(self, text):
        self.output_area.config(state='normal')
        self.output_area.insert(tk.END, text)
        self.output_area.see(tk.END)
        self.output_area.config(state='disabled')

    def save_log(self, log_text):
        with open("scan_log.txt", "a") as log_file:
            log_file.write(f"{datetime.now()}: {log_text}\n")

    def clear_screen(self):
        self.output_area.config(state='normal')
        self.output_area.delete(1.0, tk.END)
        self.output_area.config(state='disabled')


if __name__ == "__main__":
    app = NetworkScanner()
    app.mainloop()
