# CT-Logs Monitor & Phishing Detection

This project monitors Certificate Transparency (CT) logs in real time using a local `certstream-server` instance and performs analysis on suspicious domains. It is intended for advanced network and cybersecurity students or researchers.

## Project Overview

The system:
- connects to a locally running CertStream server
- extracts domain names from certificates
- identifies potential phishing domains using heuristics (Levenshtein distance, keyword matching, TLD and entropy)
- stores flagged domains for analysis
- provides a script to generate statistics and plots

---

## Requirements

- Python 3.8+
- Docker
- `pip install -r requirements.txt`

Recommended packages:
```bash
pip install websocket-client pandas matplotlib python-Levenshtein
```

---

## How to Run

### 1. Clone the repository

```bash
git clone https://github.com/your-org/ct-logs-monitor.git
cd ct-logs-monitor
```

### 2. Start CertStream locally via Docker

```bash
docker pull 0rickyy0/certstream-server-go
docker run -d -p 8080:8080 0rickyy0/certstream-server-go
```

> This spins up a local WebSocket server compatible with the CertStream protocol on `ws://127.0.0.1:8080`.

### 3. Start monitoring CT logs

```bash
python certstream/listener.py
```

Suspicious domains will be saved to:

```
data/suspected_phishing.csv
```

---

### 4. Analyze the collected data

```bash
python analysis/stats.py
```

This generates:
- top TLDs
- top certificate authorities (issuers)
- keyword-based detections
- entropy histogram

---

## Project Structure

```
CT-Logs/
├── analysis/
│   ├── phishing_detect.py
│   ├── stats.py
├── certstream/
│   └── listener.py
├── dashboard/
│   └── streamlit_app.py (future update)
├── data/
│   └── websites.txt
├── output/
│   ├── suspected_phishing.csv
├── requirements.txt
├── README.md
```

---

## Notes

- The list of monitored brands is stored in `data/websites.txt`
- Detection logic is based on heuristic signals, not ML (yet)
- Accuracy depends on tuning thresholds and keyword/TLD lists

---

 Developed for academic purposes.