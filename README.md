# PortXplorer
An advanced, GUI-based port scanner built from scratch by me to explore and analyze networks efficiently.


PortXplorer is an advanced, multi-threaded port scanning and reconnaissance tool with a rich graphical interface. It enables fast port scans, OS fingerprinting, IP geolocation, and experimental vulnerability checks. Built in Python with tkinter, nmap, and other libraries.


📋 Features

    🔍 Port Scanning

        Scan specific ports or ranges.

        Detect open/closed ports with service banners.

        Multi-threaded scanning for speed.

    🌐 IP Geolocation

        Fetch geographic location & organization of a target IP.

    🖥️ OS Detection

        Estimate the target’s operating system based on TTL.

    🧪 Vulnerability Scan (experimental)

        Run an Nmap vulnerability scan on the target.
        ⚠️ This feature is under development/testing.

    🗂️ Report Generation

        Save scan results as .txt, .csv, .json, or a professional PDF report.

    📈 Host Info

        Display your own host IP address.

        Project information built into the UI.

 
🖼️ GUI

The application features a clean tkinter-based interface:

✅ Input fields for target, ports, and thread count

✅ Real-time progress bar

✅ Color-coded result display

✅ Quick action buttons for all features

🚀 Installation
Requirements

    Python 3.8+

    Install dependencies:

    pip install requests python-nmap reportlab

    Run: python PortXplorer.py

🎉 The PortXplorer GUI will open — enter your target and start exploring!

👨‍💻 Author
Manoj Kumar S

📜 License

⚠️ This project is currently proprietary — all rights reserved, but you are welcome to use the tool for personal or educational purposes.
If you wish to contribute or use it in any other way, please contact the author.

