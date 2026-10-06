# 🛡️ NetTrace — Unknown Network Traffic Detector
A production-ready Network Security Monitoring (NSM) system that captures
live traffic metadata, learns a statistical baseline, detects unknown /
suspicious traffic, and produces professional HTML + PDF security reports.
> **Educational use only.** Capture only networks you own or are authorised
> to monitor.
---
## 1. Objective
- Capture **metadata only** (no payloads) via Scapy.
- Learn per-port / per-protocol baselines (mean + stddev + hit count).
- Flag **UNKNOWN** (new / still learning) and **SUSPICIOUS** (risky port,
  spike, statistical outlier) traffic.
- Persist everything in SQLite.
- Show a live dashboard in **Flet**.
- Export **HTML** and **PDF** reports.
---
## 2. Technologies & Packages
| Package     | Purpose                                     |
|-------------|---------------------------------------------|
| Python 3.10+| Language                                    |
| flet        | Cross-platform desktop GUI (Flutter-based)  |
| scapy       | Packet capture (TCP/UDP/ICMP metadata)      |
| reportlab   | PDF generation                              |
| sqlite3     | Standard-library embedded DB                |
---
## 3. Folder Structure
```
NetTrace/
├── main.py
├── scanner.py
├── analyzer.py
├── baseline.py
├── reputation.py
├── database.py
├── models.py
├── report_html.py
├── report_pdf.py
├── utils.py
├── config.py
├── requirements.txt
├── README.md
├── data/            ← auto-created, holds nettrace.db
├── reports/
│   ├── html/
│   └── pdf/
└── tests/
    └── test_baseline.py
```
---
## 4. Setup (Windows / Linux / macOS)
```bash
# 1. Clone / create the folder
mkdir NetTrace && cd NetTrace
# 2. Create & activate a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate
# 3. Install dependencies
python.exe -m pip install --upgrade pip
pip install -r requirements.txt
pip install --upgrade flet
```
### Windows — Npcap
Scapy needs a packet capture driver on Windows:
1. Download **Npcap**: https://npcap.com/#download
2. Install with **"WinPcap API-compatible Mode"** enabled.
3. Reboot if prompted.
### Linux
```bash
sudo apt install libpcap-dev python3-tk
# Run as root, or:
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```
### macOS
```bash
brew install libpcap
```
---
## 5. Run
```bash
# Windows (as Administrator) / Linux / macOS (sudo)
python main.py
```
The Flet window opens. Click **▶ Start Monitoring**.
---
## 6. Dashboard Buttons
| Button               | Action                                             |
|----------------------|----------------------------------------------------|
| ▶ Start Monitoring   | Launches the Scapy sniffer thread                  |
| ⏹ Stop               | Stops the sniffer                                  |
| 🔄 Refresh           | Reloads DB data into the UI                        |
| 📄 Generate PDF      | Builds & opens a PDF report                        |
| 🌐 Generate HTML     | Builds & opens an HTML report                      |
| 📂 Open Reports      | Opens `reports/` in the OS file manager            |
| 🗑 Reset DB          | Deletes all packets, alerts and baseline rows      |
---
## 7. Testing Walkthrough
1. Start the app, click **▶ Start Monitoring**.
2. Open a browser → normal HTTPS (443) traffic is captured as `KNOWN`.
3. Use `nmap -p 23 <some-host>` → risky-port hits appear as `SUSPICIOUS`.
4. Use `ping <host>` → ICMP rows appear (port 0).
5. Wait 30–60s, then click **📄 Generate PDF** and **🌐 Generate HTML**.
6. Verify outputs in `reports/pdf/` and `reports/html/`.
---
## 8. Baseline Behaviour Example
| Step | Observation                          | Result                     |
|------|--------------------------------------|----------------------------|
| 1    | First packet to port 9999            | UNKNOWN (First-seen)       |
| 2    | 2nd–4th packets to 9999              | UNKNOWN (Learning 2/5 …)   |
| 3    | 5th packet, normal size              | KNOWN (Baseline established)|
| 4    | 6th packet, 10× normal size          | UNKNOWN (Byte-size anomaly) |
| 5    | 50 packets in 1 minute               | SUSPICIOUS (Traffic spike) |
| 6    | Any packet to port 23 / 445 / 3389   | SUSPICIOUS (Risky port)    |
---
## 9. Report Explanation
Both HTML and PDF reports contain:
1. Header + timestamp
2. Risk banner (LOW / MEDIUM / HIGH) with numeric score
3. Summary cards — Total / Known / Unknown / Suspicious
4. Protocol Statistics table
5. Top Unknown / Suspicious Sources
6. Security Alerts table
7. Recent Traffic table
8. Learned Baseline table
9. Recommendations list
Risk score weights: `SUSPICIOUS×10 + UNKNOWN×3 + HIGH_alerts×8 + MEDIUM_alerts×3`.
---
## 10. Troubleshooting
| Symptom                                | Fix                                                |
|----------------------------------------|----------------------------------------------------|
| `ModuleNotFoundError: scapy`           | `pip install -r requirements.txt`                  |
| `PermissionError` on capture           | Run as Administrator / sudo, or setcap on Linux    |
| No packets appear                      | Confirm network activity; try `ping 8.8.8.8`       |
| Empty PDF/HTML tables                  | Capture for a minute before generating a report    |
| Flet window blank                      | `pip install --upgrade flet`                       |
| Scapy warns about missing Npcap        | Install Npcap with WinPcap compatibility           |
---
## 11. Security & Legal Notice
NetTrace captures **network metadata** on the machine where it runs.
You must only use it on networks you own or have **explicit written
permission** to monitor. Unauthorised packet capture is illegal in most
jurisdictions. The authors accept no liability.
---
## 12. Future Improvements
- GeoIP enrichment
- ML-based anomaly detection (Isolation Forest / autoencoder)
- PCAP export
- Multi-user web dashboard (FastAPI + React)
- Real-time threat-intel feeds
- Email / Slack alerting
---
## 13. Quick Start TL;DR
```bash
mkdir NetTrace && cd NetTrace
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```
