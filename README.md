# Antivirus-Tool
# 🛡️ Python Antivirus

A signature-based antivirus tool built using Python. It features a GUI powered by Tkinter, real-time file monitoring, automatic threat detection, quarantine management, and more.

## 📦 Features

- **Signature-based Malware Detection**  
  Uses SHA-256 hash matching with a malware signature database.

- **Real-Time File Monitoring**  
  Automatically detects and scans new or modified files using the `watchdog` module.

- **Scanning Options**  
  - Quick Scan (targets common infection paths like `/tmp`, `~/.config/autostart`)
  - Full System Scan
  - Custom Scan with directory browser
  - Individual File Scan

- **Quarantine Manager**  
  Automatically quarantines infected files and allows:
  - Viewing quarantined items
  - Manual restoration or permanent deletion

- **GUI Interface (Tkinter)**  
  User-friendly interface with:
  - Scan control buttons
  - Tabs for different scan types
  - Real-time log display
  - Quarantine viewer

- **Log Management**  
  View, clear, and save logs of all scans and real-time detections.

## 🛠️ Technologies Used

- Python 3
- Tkinter (GUI)
- `watchdog` (File monitoring)
- `hashlib`, `json`, `threading`, etc.
## 📁 Folder Structure
project/
├── signatures/
│ ├── sha256_pack1.txt
│ ├── sha256_pack2.txt
│ └── sha256_pack3.txt
├── quarantine/
├── quarantine_db.json
├── antivirus_logs.txt
└── antivirus.py
> Note: Ensure the `signatures/` directory contains valid signature files in the format:  
> `sha256_hash;MalwareName`

## 🧪 How to Run

1. Clone this repository:
   git clone https://github.com/yourusername/python-antivirus.git
   cd python-antivirus
2. Install dependencies:
   pip install watchdog
3. Run the antivirus:
   python AVS.py
