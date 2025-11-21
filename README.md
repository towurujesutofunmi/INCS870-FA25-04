# Lightweight IoT Intrusion Detection System

A lightweight Intrusion Detection System (IDS) optimized for real-time operation on Raspberry Pi devices. Uses an XGBoost-based multiclass model trained on the ToN-IoT network dataset with a Flask-based monitoring dashboard for visualizing live alerts from Zeek network logs.

## Repository Structure

```
├── app.py                     # Flask dashboard serving live alerts
├── realtime_inference.py      # Real-time inference engine for Zeek logs
├── xgb_multiclass.json        # Trained XGBoost model (10-class IDS)
├── label_encoders.json        # Fitted label encoders for categorical features
└── requirements.txt           # Python dependencies
```

## Features

- **Real-time inference:** Continuously monitors multiple Zeek logs (conn.log, http.log, dns.log, etc.)
- **UID-based merging:** Joins related events across log types using connection UIDs
- **Lightweight dashboard:** Flask server displaying live alerts from alerts.csv
- **Edge optimized:** Efficiently runs on Raspberry Pi 4 (4GB) with low latency
  
## Requirements

### Hardware
- Raspberry Pi 4 (recommended) 
- Minimum 2 GB RAM
- Raspbian Bullseye or later

### Software
- Python 3.8 or later
- Zeek Network Security Monitor
- Dependencies from requirements.txt

## Installation

### 1. System Setup

```bash
sudo apt update
sudo apt install python3-pip python3-venv -y
```

### 2. Create Virtual Environment

```bash
python3 -m venv ids_env
source ids_env/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## Usage

### 1. Start Zeek

Start Zeek with JSON logging enabled:

```bash
sudo su
source /etc/profile.d/zeek.sh
zeek -i wlan0 LogAscii::use_json=T local
```

This will generate logs in the current directory or Zeek's default log location.

### 2. Run Real-Time Inference

**For processing existing logs (without live monitoring):**

```bash
python3 realtime_inference.py \
  --model xgb_multiclass.json \
  --encoders label_encoders.json \
  --logs ~/zeekrun/http.log ~/zeekrun/conn.log ~/zeekrun/weird.log ~/zeekrun/dns.log ~/zeekrun/ssl.log \
  --batch-size 20 \
  --max-wait 0.5 \
  --emit all \
  --alert-csv alerts.csv
```

**For live monitoring of new log entries:**

```bash
python3 realtime_inference.py \
  --model xgb_multiclass.json \
  --encoders label_encoders.json \
  --logs ~/zeekrun/http.log ~/zeekrun/conn.log ~/zeekrun/weird.log ~/zeekrun/dns.log ~/zeekrun/ssl.log \
  --batch-size 20 \
  --max-wait 0.5 \
  --emit all \
  --follow \
  --alert-csv alerts.csv
```

**Key Options:**

| Flag | Description |
|------|-------------|
| `--model` | Path to trained model |
| `--encoders` | Fitted label encoders |
| `--logs` | One or more Zeek log files to process |
| `--follow` | Continuously monitor and process new log entries (omit for batch processing) |
| `--batch-size` | Number of entries per prediction batch |
| `--max-wait` | Max seconds before a batch is processed |
| `--emit` | Event filter: `all` (all events), `normal` (only normal traffic), `abnormal` (only attacks) |
| `--alert-csv` | Path to output alert file (CSV) |

### 3. Start the Dashboard

```bash
python3 app.py --csv alerts.csv --host 0.0.0.0 --port 8000
```

Access at: `http://localhost:8000`

## Testing the IDS

To generate network traffic and test the IDS detection capabilities, you can run network scanning tools against the Raspberry Pi from another machine on the network.

### Using Nmap

Run a comprehensive scan to generate various log entries:

```bash
nmap -sS -sV -O -A -p- <raspberrypi_ip>
```

This command performs:
- `-sS`: TCP SYN scan (stealth scan)
- `-sV`: Service version detection
- `-O`: OS detection
- `-A`: Aggressive scan (enables OS detection, version detection, script scanning, and traceroute)
- `-p-`: Scan all 65535 ports

### Using Nessus

Run a vulnerability scan using Nessus by:
1. Adding the Raspberry Pi IP address as a target
2. Running a basic or advanced network scan
3. Monitor the IDS dashboard for detected scanning activity

Both tools will generate significant network traffic that Zeek will capture and the IDS will classify, allowing you to observe detection of scanning, potential vulnerabilities, and other network anomalies in real-time.

## Model Details

The system uses an XGBoost multiclass model trained on 35 key features from the ToN-IoT dataset.

### Attack Classes

| Class | Label | Description |
|-------|-------|-------------|
| 0 | mitm | Man-in-the-middle attacks |
| 1 | ransomware | Ransomware activity |
| 2 | injection | Code or command injection |
| 3 | backdoor | Unauthorized backdoor access |
| 4 | normal | Legitimate traffic |
| 5 | password | Password brute-force attempts |
| 6 | xss | Cross-site scripting |
| 7 | dos | Denial-of-Service |
| 8 | ddos | Distributed Denial-of-Service |
| 9 | scanning | Network or port scanning |


## Troubleshooting

| Issue | Solution |
|-------|----------|
| `num_feature mismatch` error | Ensure same `label_encoders.json` used during training |
| Dashboard blank | Wait for first predictions or check Zeek log paths |
| CPU spikes | Increase `--batch-size` (e.g., 2048) |
| Permission denied | Run with `sudo` or adjust file permissions |


