import tkinter as tk
from tkinter import messagebox, scrolledtext
from PIL import Image, ImageTk
from scapy.all import sniff, IP, TCP, UDP
import datetime
import threading

# Global variables
seen_alerts = set()
detected_attacks = []
sniffing_active = threading.Event()

def detect_attack(attack_type, dst_ip, attack_details_dict):
    alert_key = (attack_type, dst_ip)
    if alert_key in seen_alerts:
        return

    attack_details = {
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "dst_ip": dst_ip,
        "attack_type": attack_type,
        "cvss_score": attack_details_dict.get(attack_type, {}).get("cvss_score", "unknown"),
        "owasp_category": attack_details_dict.get(attack_type, {}).get("owasp_category", "unknown")
    }

    detected_attacks.append(attack_details)
    seen_alerts.add(alert_key)

    alert_message = (
        f"Suspicious traffic detected:\n"
        f"Type: {attack_details['attack_type']}\n"
        f"Destination IP: {dst_ip}\n"
        f"CVSS Score: {attack_details['cvss_score']}"
    )

    messagebox.showwarning("Alert", alert_message)
    log_attack(attack_details)

def log_attack(attack_details):
    attack_log = (
        f"Time: {attack_details['time']}\n"
        f"Type: {attack_details['attack_type']}\n"
        f"Destination IP: {attack_details['dst_ip']}\n"
        f"CVSS Score: {attack_details['cvss_score']}\n"
        f"OWASP Category: {attack_details['owasp_category']}\n\n"
    )
    # Update text widget safely using Tkinter's thread-safe method
    attack_text.after(0, lambda: attack_text.insert(tk.END, attack_log))
    attack_text.after(0, lambda: attack_text.see(tk.END))

def analyze_packet(packet):
    if IP in packet:
        dst_ip = packet[IP].dst
        if TCP in packet:
            dst_port = packet[TCP].dport
            if dst_port == 22:
                detect_attack("SSH Brute Force Attack", dst_ip, attack_details_dict)
            elif dst_port in (80, 443):
                detect_attack("HTTP DoS Attack", dst_ip, attack_details_dict)
        elif UDP in packet:
            dst_port = packet[UDP].dport
            if dst_port == 53:
                detect_attack("UDP-based Attack (DNS Amplification)", dst_ip, attack_details_dict)

def start_sniffing():
    sniffing_active.set()  # Set the event to signal sniffing should continue
    sniff(filter="(tcp or udp)", prn=analyze_packet, store=0, stop_filter=lambda x: not sniffing_active.is_set())

def stop_sniffing():
    sniffing_active.clear()  # Clear the event to stop sniffing

def start_sniffing_thread():
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

def generate_report():
    report = "Detected Attacks Report:\n\n"
    for attack in detected_attacks:
        report += (
            f"Time: {attack['time']}\n"
            f"Type: {attack['attack_type']}\n"
            f"Destination IP: {attack['dst_ip']}\n"
            f"CVSS Score: {attack['cvss_score']}\n"
            f"OWASP Category: {attack['owasp_category']}\n\n"
        )
    messagebox.showinfo("Report", report)


# Example usage
attack_details_dict = {
    'SSH Brute Force Attack': {'cvss_score': 'High', 'owasp_category': 'A'},
    'HTTP DoS Attack': {'cvss_score': 'Medium', 'owasp_category': 'B'},
    'UDP-based Attack (DNS Amplification)': {'cvss_score': 'Low', 'owasp_category': 'C'}
}

# Create the main window
root = tk.Tk()
root.title("Intrusion Detection System")

# Create a frame for project info
project_info_frame = tk.Frame(root)
project_info_frame.pack(pady=10)

# Add a label for project info
project_info_label = tk.Label(project_info_frame, text="Project Info", font=("Arial", 14))
project_info_label.pack()

# Add an image for project info (replace 'logo.png' with your image file)
try:
    logo_image = Image.open("logoids.jpg")
    logo_photo = ImageTk.PhotoImage(logo_image)
    logo_label = tk.Label(project_info_frame, image=logo_photo)
    logo_label.image = logo_photo  # Keep a reference to avoid garbage collection
    logo_label.pack()
except FileNotFoundError:
    print("Image file not found. Please check the path.")

# Create a text widget to display detected attacks
attack_text = scrolledtext.ScrolledText(root, width=80, height=20)
attack_text.pack(padx=10, pady=10)

# Create start, stop, and generate report buttons
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

start_button = tk.Button(button_frame, text="Start IDS", command=start_sniffing_thread)
start_button.pack(side=tk.LEFT, padx=10)

stop_button = tk.Button(button_frame, text="Stop IDS", command=stop_sniffing)
stop_button.pack(side=tk.LEFT, padx=10)

report_button = tk.Button(button_frame, text="Generate Report", command=generate_report)
report_button.pack(side=tk.LEFT, padx=10)

# Run the Tkinter event loop
root.mainloop()
