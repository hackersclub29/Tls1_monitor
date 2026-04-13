🛰️ TLS Traffic Monitor (CLI)
A real-time TLS/SSL traffic monitor for Windows with a terminal dashboard.
✨ Features
🔎 Live packet capture with WinDivert / `pydivert`
🧩 TLS handshake parsing
🌐 SNI, ALPN, and TLS version extraction
👤 Process and PID resolution with `psutil`
📈 Throughput sparklines and flow tables
⌨️ Keyboard navigation inside the dashboard
> ⚠️ This tool is passive only. It does **not** decrypt TLS payloads.
---
🛠️ Requirements
Windows 10/11
Python 3.10+
Administrator privileges
WinDivert driver installed
Dependencies from `requirements.txt`
---
📦 Installation
```powershell
git clone https://github.com/hackersclub29/Tls1_monitor.git
cd Tls1_monitor
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```
WinDivert
`pydivert` needs the WinDivert driver to sniff packets. Install WinDivert separately before running the monitor.
---
🚀 Usage
Run from an elevated PowerShell:
```powershell
python Tls1_monitor.py
```
Common options
```powershell
python Tls1_monitor.py --ports 443 8443 853
python Tls1_monitor.py --rows 24
python Tls1_monitor.py --events 300
python Tls1_monitor.py --resolver-refresh 1.5
```
---
⌨️ Controls
Arrow keys / `W` `A` `S` `D`-style aliases for navigation
`Tab` to switch between panels
`Q` to quit
---
🧠 What it shows
Active TLS sessions
Process name and PID
Remote endpoint
SNI and ALPN
TLS version hints
Upload/download rates
Event stream for TLS handshakes and alerts
---
📁 File
`Tls1_monitor.py` — CLI TLS monitor
---
🤝 Notes
Best used with administrative access
Windows-only because it depends on WinDivert and `msvcrt`
Designed for security monitoring, troubleshooting, and traffic visibility
