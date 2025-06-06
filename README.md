# CT-Logs Monitoring and Phishing Detection

This project monitors live Certificate Transparency logs using a local CertStream server and analyzes newly issued TLS certificates to identify potentially suspicious or phishing-related domains. Detected threats are logged to a CSV file for further analysis.

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

## How to Run

### 1. Clone the repository

```bash
git clone https://github.com/olivblvck/CT-Logs.git
cd CT-Logs
```

### 2. Start CertStream locally via Docker

```bash
docker pull 0rickyy0/certstream-server-go
docker run -d -p 8080:8080 0rickyy0/certstream-server-go
```

> This spins up a local WebSocket server compatible with the CertStream protocol on `ws://127.0.0.1:8080`.

### 3. Set up the Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 4. Start monitoring CT logs

```bash
python certstream/listener.py
```

Suspicious domains will be saved to:

```
data/suspected_phishing.csv
```
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

## Features Extracted per Domain

For each domain found in new TLS certificates, the following features are extracted:

- **TLD**: Top-Level Domain (e.g., `.com`, `.xyz`)
- **TLD Suspicious**: Whether the TLD is from a list of commonly abused TLDs
- **Keyword Match**: Checks if the domain contains suspicious keywords like `login`, `secure`, `verify`
- **Entropy**: Shannon entropy of the domain name – higher values may indicate algorithmically generated domains
- **WHOIS Age**: Number of days since domain registration (if data available)

---

## Phishing Score Calculation

Each domain is assigned a `score` between `0.0` and `1.0` indicating its phishing likelihood.

The score is based on:

| Feature                | Condition                                          | Points |
|------------------------|---------------------------------------------------|--------|
| **Entropy**            | > 3.5                                             | +0.25  |
| **Suspicious Keyword** | Yes                                               | +0.25  |
| **TLD Suspicious**     | `.xyz`, `.top`, `.buzz`, `.shop`                  | +0.2   |
| **WHOIS Age**          | Registered within last 14 days                    | +0.2   |
| **Brand Match**        | Similarity to known brands (e.g. `goog1e.com`)    | up to +0.1 |

The final score is normalized to max `1.0`.

> Domains with a score above a chosen threshold (e.g., 0.6) can be flagged as potential phishing.

---

## Output

The script saves results to `data/suspected_phishing.csv`, with the following columns:

- `timestamp`
- `domain`
- `brand_match`
- `similarity_score`
- `issuer`
- `tld`
- `tld_suspicious`
- `has_keyword`
- `entropy`
- `registration_days`
- `score`

---

## Statistical Analysis

To analyze the output data:

```bash
python analysis/stats.py
```

This script provides:

- Distribution of TLDs and issuers
- Entropy statistics
- Domains containing phishing-like keywords
- Most common matched brands
- Distribution of phishing scores

---

##  False Positives & Limitations

- Domains like `*.amazonaws.com` or `*.cloudfront.net` often appear similar to brand names but are legitimate infrastructure domains.
- WHOIS data may be unavailable or rate-limited.
- CT logs include a large number of benign domains; filtering is heuristic-based and not perfect.

---

## Todo / Future Work

- DNS / ASN checks (e.g., identify free hosting providers or bulletproof infrastructure)
- Passive DNS / domain reputation integrations
- Historical enrichment: attach certificate metadata, hosting history, etc.
- Integration with threat intel feeds

---
