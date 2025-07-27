import socket
import threading
import subprocess
import platform
import concurrent.futures
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Menu
import ssl
import json
import csv
import time
from unittest import result
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit
from datetime import datetime
import requests
import nmap
import shutil


# Globals
SCAN_RUNNING_EVENT = threading.Event()
COMMON_PORTS = {
    20: "FTP (Data Transfer)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3389: "RDP"
}
scan_results = []  # Global variable to store results

def nmap_vulnerability_scan(target):
    if not shutil.which("nmap"):
        return "Nmap is not installed or not found in PATH."
    try:
        command = ["nmap", "--script", "vuln", target]
        result = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True, timeout=60)
        # Truncate output for messagebox
        if len(result) > 2000:
            return result[:2000] + "\n\n[Output truncated. See terminal for full results.]"
        return result
    except subprocess.TimeoutExpired:
        return "Nmap scan timed out."
    except subprocess.CalledProcessError as e:
        return f"Error during Nmap execution: {e.output}"
    except Exception as e:
        return f"General error: {e}"

# Function to trigger vulnerability scanning from the GUI
def display_vulnerabilities():
    target = ip_entry.get()
    if not target:
        messagebox.showerror("Error", "Enter a valid IP or URL for vulnerabilities.")
        return

    def run_scan():
        try:
            vulnerabilities = nmap_vulnerability_scan(target)
            print(vulnerabilities)  # Print full output to terminal
            root.after(0, lambda: messagebox.showinfo(
                "Vulnerability Info",
                f"Target: {target}\n\n{vulnerabilities}\n\n[See terminal for full output.]"
            ))
        except Exception as e:
            root.after(0, lambda: messagebox.showerror("Error", f"Failed to fetch vulnerabilities: {e}"))

    threading.Thread(target=run_scan, daemon=True).start()


# Function to fetch geolocation data
def get_geolocation(ip_or_url):
    try:
        ip = socket.gethostbyname(ip_or_url)  # Resolve URL to IP if necessary
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            return f"IP: {ip}\nLocation: {data.get('city', 'Unknown')}, {data.get('region', 'Unknown')}, {data.get('country', 'Unknown')}\nOrganization: {data.get('org', 'Unknown')}"
        else:
            return f"Failed to retrieve geolocation data: {response.status_code}"
    except Exception as e:
        return f"Error fetching geolocation data: {e}"

# Display Geolocation Function
def display_geolocation():
    target = ip_entry.get()
    if not target:
        messagebox.showerror("Error", "Enter a valid IP or URL for geolocation.")
        return
    try:
        geo_info = get_geolocation(target)
        messagebox.showinfo("Geolocation Info", geo_info)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to fetch geolocation info: {e}")

# Get TTL from ping
def get_ttl(target):
    try:
        cmd = f"ping -n 1 {target}" if platform.system().lower() == "windows" else f"ping -c 1 {target}"
        output = subprocess.check_output(cmd, shell=True, universal_newlines=True, timeout=5, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            if "ttl=" in line.lower():
                return int(line.lower().split("ttl=")[1].split()[0])
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    except Exception:
        return None

def detect_os(ttl):
    if not ttl:
        return "Unknown OS"
    if ttl >= 128 and ttl <= 255:
        return "Windows (Default TTL: 128/255)"
    elif ttl >= 64 and ttl < 128:
        return "Linux/Unix-based OS (Default TTL: 64)"
    else:
        return "Custom/Unknown TTL"

# Stop Scan
def stop_scan():
    SCAN_RUNNING_EVENT.clear()

# Port Scanner with Banner
def scan_port(ip, port, results):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                banner = ""
                try:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode(errors="ignore").strip()
                except Exception:
                    banner = "No Banner Detected"
                results.append((port, "OPEN", f"{COMMON_PORTS.get(port, 'Unknown')} | {banner}"))
            else:
                results.append((port, "CLOSED", COMMON_PORTS.get(port, 'Unknown')))
    except Exception as e:
        results.append((port, "ERROR", f"{e}"))

# Save Results to File
def save_results():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("JSON Files", "*.json"), ("CSV Files", "*.csv")])
    if file_path:
        data = result_text.get(1.0, tk.END).strip().split("\n")
        if file_path.endswith(".json"):
            with open(file_path, "w") as file:
                json.dump(data, file, indent=4)
        elif file_path.endswith(".csv"):
            with open(file_path, "w", newline="") as file:
                writer = csv.writer(file)
                for line in data:
                    writer.writerow([line])
        else:
            with open(file_path, "w") as file:
                file.write("\n".join(data))
        messagebox.showinfo("Success", "Results saved successfully!")

# Function to generate PDF report
def generate_pdf_report(scan_results):
    file_path = filedialog.asksaveasfilename(
        defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")]
    )
    if not file_path:
        return

    try:
        c = canvas.Canvas(file_path, pagesize=letter)
        width, height = letter

        # Header Section
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, height - 50, "Advanced Port Scanner Report")
        c.setFont("Helvetica", 12)
        c.drawString(50, height - 70, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(50, height - 90, f"Target: {ip_entry.get()}")
        c.drawString(50, height - 110, f"Port Range: {port_entry.get()}")
        c.drawString(50, height - 130, f"Threads Used: {thread_count.get()}")
        c.drawString(50, height - 150, "-" * 70)

        y_position = height - 170
        line_spacing = 15  # Space between lines

        for result in scan_results:
            # Wrap text if too long
            wrapped_text = simpleSplit(result, "Helvetica", 10, width - 100)
            for line in wrapped_text:
                if y_position < 50:  # Check for page overflow
                    c.showPage()
                    y_position = height - 50
                    c.setFont("Helvetica", 12)
                c.drawString(50, y_position, line)
                y_position -= line_spacing

        c.save()
        messagebox.showinfo("Success", f"Report saved to {file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate report: {e}")

# Clear Results
def clear_results():
    result_text.delete(1.0, tk.END)

# OS Detection Function
def os_detection():
    target = ip_entry.get()
    if not target:
        messagebox.showerror("Error", "Enter a valid IP or URL for OS detection.")
        return
    try:
        ip = socket.gethostbyname(target)
        ttl = get_ttl(ip)
        os = detect_os(ttl)
        messagebox.showinfo("OS Detection Result", f"Target: {ip}\nTTL: {ttl}\nDetected OS: {os}")
    except Exception:
        messagebox.showerror("Error", "Unable to detect OS.")

# Show Host IP
def show_host_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as temp_socket:
            temp_socket.connect(("8.8.8.8", 80))
            host_ip = temp_socket.getsockname()[0]
        messagebox.showinfo("Host IP", f"Your Host IP Address: {host_ip}")
    except Exception as e:
        messagebox.showerror("Error", f"Unable to fetch Host IP: {e}")

# Project Info
def show_project_info():
    messagebox.showinfo("Project Info", "PortXplorer\nDesigned and developed by: Manoj Kumar S")

# Main Scan
def start_scan():
    global scan_results
    SCAN_RUNNING_EVENT.set()
    scan_results = []  # Clear previous results
    target = ip_entry.get()
    port_input = port_entry.get()
    threads = int(thread_count.get())

    if not target:
        messagebox.showerror("Error", "Enter target IP/URL")
        return

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        messagebox.showerror("Error", "Invalid hostname or IP address")
        return

    try:
        if "-" in port_input:
            start, end = map(int, port_input.split('-'))
            ports = range(start, end + 1)
        else:
            ports = list(map(int, port_input.split(',')))
    except ValueError:
        messagebox.showerror("Error", "Invalid port input. Use '80-100' or '22,80,443'.")
        return

    result_text.delete(1.0, tk.END)
    progress_bar["value"] = 0
    progress_bar["maximum"] = len(ports)
    results = []

    def scan():
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(scan_port, target_ip, port, results) for port in ports]
            for i, _ in enumerate(concurrent.futures.as_completed(futures)):
                if not SCAN_RUNNING_EVENT.is_set():
                    break
                progress_bar["value"] = i + 1
                root.update_idletasks()

        for port, status, info in results:
            tag = "open" if status == "OPEN" else "closed"
            result_text.insert(tk.END, f"{port} ({info}): {status}\n", tag)
            scan_results.append(f"{port} ({info}): {status}")

    threading.Thread(target=scan).start()

# GUI Setup
root = tk.Tk()
root.title("PortXplorerr")
root.geometry("900x700")
root.configure(bg="#1c1c1c")
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)
root.grid_rowconfigure(4, weight=1)

menu_bar = Menu(root)
root.config(menu=menu_bar)

header_frame = tk.Frame(root, bg="#262626", padx=10, pady=10)
header_frame.grid(row=0, column=0, columnspan=2, sticky="ew")
header_label = tk.Label(
    header_frame, text="PortXplorer", font=("Arial", 18, "bold"), fg="#FFD700", bg="#262626"
)
header_label.pack()

input_frame = tk.Frame(root, bg="#1c1c1c")
input_frame.grid(row=1, column=0, columnspan=2, pady=10, sticky="ew")
input_frame.grid_columnconfigure(1, weight=1)

tk.Label(input_frame, text="Target IP/URL:", bg="#1c1c1c", fg="#00FF00", font=("Arial", 12)).grid(row=0, column=0, padx=10, pady=5, sticky="e")
ip_entry = tk.Entry(input_frame, width=40, bg="#333333", fg="#00FF00", insertbackground="#00FF00", font=("Arial", 12))
ip_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

port_label = tk.Label(input_frame, text="Port Range/List:", bg="#1c1c1c", fg="#00FF00", font=("Arial", 12))
port_label.grid(row=1, column=0, padx=10, pady=5, sticky="e")
port_entry = tk.Entry(input_frame, width=40, bg="#333333", fg="#00FF00", insertbackground="#00FF00", font=("Arial", 12))
port_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

thread_label = tk.Label(input_frame, text="Threads:", bg="#1c1c1c", fg="#00FF00", font=("Arial", 12))
thread_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")
thread_count = tk.StringVar(value="10")
ttk.Spinbox(input_frame, from_=1, to=50, textvariable=thread_count, width=10).grid(row=2, column=1, padx=10, pady=5, sticky="w")

button_frame = tk.Frame(root, bg="#262626", padx=10, pady=10)
button_frame.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")

buttons = [
    ("Start Scan", start_scan, "#32CD32"),
    ("Stop Scan", stop_scan, "#FF6347"),
    ("Save Results", save_results, "#FFD700"),
    ("Clear Results", clear_results, "#FF4500"),
    ("Show Host IP", show_host_ip, "#1E90FF"),
    ("OS Detection", os_detection, "#9370DB"),
    ("IP Geolocation", display_geolocation, "#4682B4"),
    ("Vulnerability Scan", display_vulnerabilities, "#FFA07A"),
]

for i, (text, command, color) in enumerate(buttons):
    tk.Button(
        button_frame,
        text=text,
        command=command,
        bg="#333333",
        fg=color,
        font=("Arial", 12),
        relief="flat",
        width=18,
    ).grid(row=0, column=i, padx=10, pady=5)

progress_frame = tk.Frame(root, bg="#1c1c1c")
progress_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
progress_bar = ttk.Progressbar(
    progress_frame, orient="horizontal", mode="determinate", style="green.Horizontal.TProgressbar"
)
style = ttk.Style(root)
style.configure("green.Horizontal.TProgressbar", troughcolor="#333333", background="#00FF00")
progress_bar.pack(fill="x")

result_frame = tk.Frame(root, bg="#1c1c1c")
result_frame.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

result_text = tk.Text(result_frame, wrap="word", bg="#333333", fg="#00FF00", font=("Consolas", 10), height=20)
result_text.pack(fill="both", expand=True)
result_text.tag_configure("open", foreground="green")
result_text.tag_configure("closed", foreground="red")

footer_frame = tk.Frame(root, bg="#262626", padx=10, pady=10)
footer_frame.grid(row=5, column=0, columnspan=2, sticky="ew")

tk.Button(
    footer_frame,
    text="Project Info",
    command=show_project_info,
    bg="#333333",
    fg="#FFD700",
    font=("Arial", 12),
    relief="flat",
    width=18,
).pack(side="left", padx=10)

tk.Button(
    footer_frame,
    text="Generate PDF Report",
    command=lambda: generate_pdf_report(scan_results),
    bg="#333333",
    fg="#FFD700",
    font=("Arial", 12),
    relief="flat",
    width=20,
).pack(side="right", padx=10)

# Check for Nmap installation
if not shutil.which("nmap"):
    messagebox.showerror("Error", "Nmap is not installed or not found in PATH.")

root.mainloop()
