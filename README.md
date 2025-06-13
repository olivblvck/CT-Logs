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
`output/suspected_phishing.csv`
---

## Project Structure

```
CT-Logs/
├── analysis/
│   ├── phishing_detect.py
│   └── stats.py
├── certstream/
│   └── listener.py
├── utils/
│   ├── dns_twister.py
│   └── who_is.py
├── data/
│   └── websites.txt
├── output/
│   ├──suspected_phishing.csv
│   └──plots/ (...)
├── requirements.txt
├── README.md
```

---

## Notes

- The list of monitored brands is stored in `data/websites.txt`
- Detection logic is based on heuristic signals, not ML (yet)
- Accuracy depends on tuning thresholds and keyword/TLD lists
- DNS permutations are limited to 30 per domain
- WHOIS queries are cached and only executed for suspicious domains
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

Each domain is assigned a `score` between 0 and 10, reflecting the likelihood of phishing. The higher the score, the more suspicious the domain.

The score is calculated based on the following features:

| Feature              | Condition                                               | Points   |
|----------------------|---------------------------------------------------------|----------|
| **Entropy**          | ≥ 3.1 → +1, ≥ 3.4 → +2, ≥ 3.7 → +3                      | +1–3     |
| **Suspicious Keyword** | Presence of phishing-related words  (e.g. `login`, `auth`, `verify`)  | +2       |
| **Suspicious TLD**   | Known shady TLDs (e.g. `.xyz`, `.top`, `.buzz`, `.shop`) | +1 |
| **Issuer**           | Free/automated issuers (e.g. Let's Encrypt, ZeroSSL)    | +1 |
| **WHOIS Age**        | <14 days → +3, <60 → +2, <180 → +1                      | +1–3     |
 |**Similarity to Brand**| Levenshtein ratio ≥ 0.80 and ≠ brand → scaled: 0.80 → +0.5, 0.85 → +0.75, ≥ 0.90 → +1.0 | +0–1|

> Domains exceeding a chosen threshold (e.g. **score ≥ 4**) can be flagged as **medium** or **high-risk**.

---

## Output

The script saves results to `output/suspected_phishing.csv`, with the following columns:

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
- `cn_mismatch`
- `ocsp_missing`
- `short_lived`
- `brand_in_subdomain`
- `score`

> Duplicate detections with identical features (except timestamp) are automatically deduplicated before analysis.
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
- Score vs entropy and domain age
- Score vs issuer and brand match
- Score by presence of suspicious keyword
- Age distribution (log scale)
- Frequency heatmap: TLD vs Issuer

---
## Performance Optimizations
- WHOIS rewritten to use native system `whois` command via `subprocess`, massively improving speed
- stdout/stderr from WHOIS are suppressed using `contextlib.redirect_stdout` and `subprocess.DEVNULL`
- Permutation checks are limited (max 30), and WHOIS is only called for domains flagged as suspicious
- Uses in-memory caches (`TTLCache` and `lru_cache`) to prevent redundant DNS and WHOIS queries
- Debug prints show which permutations were generated and checked (e.g. `[DEBUG]` Permutation: `xxx.com` (`base: yyy.com`))
- Domains with missing WHOIS creation date are marked with `-1` and excluded from age-based scoring
- Analysis script deduplicates rows to avoid skewing results from repeated entries
---

##  False Positives & Limitations

- Domains like `*.amazonaws.com` or `*.cloudfront.net` often appear similar to brand names but are legitimate infrastructure domains.
- WHOIS data may be unavailable or rate-limited.
- CT logs include a large number of benign domains; filtering is heuristic-based and not perfect.

---

## Todo / Future Work
- Add machine learning-based phishing classifier
- Build web dashboard for real-time alerts
- Support for other log sources beyond CertStream
- Crosscheck with Google Safe Browsing, Virus Total and other blacklists if the domains have been detected as malicious.
---
