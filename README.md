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
- **Offline operation:** Works without internet connectivity once setup is complete

## Requirements

### Hardware
- Raspberry Pi 4 (recommended) or Pi 3B+
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
