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
python certstream/listener.py # or python -m certstream.listener
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
├── data/
│   └── websites.txt
├── output/
│   ├── suspected_phishing.csv
│   └── plots/ 
│       ├── domain_length.png
│       ├── registration_age_log.png
│       ├── score_distribution.png
│       ├── score_vs_age.png
│       ├── score_vs_brand_match.png
│       ├── score_vs_entropy.png
│       ├── score_vs_issuer.png
│       ├── score_vs_keyword.png
│       ├── tld_vs_issuer.png
│       └── top_tlds.png
├── utils/
│   ├── dns_twister.py
│   └── who_is.py
├── requirements.txt
└── README.md
```

---

## Notes

- The list of monitored brands is stored in `data/websites.txt`
- Detection logic is based on heuristic signals
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
- **WHOIS Age**: Number of days since domain registration (if data available, returns -1 days if unavailable)

---

## Phishing Score Calculation

Each domain is assigned a `score` between 0 and 10 (final scores are capped at a maximum of 10 points), reflecting the likelihood of phishing. The higher the score, the more suspicious the domain.

The score is calculated based on the following features:

| Feature              | Condition                                                                          | Points   |
|----------------------|------------------------------------------------------------------------------------|----------|
| **Entropy**          | ≥ 2.8 → +0.5, ≥ 3.2 → +1, ≥ 3.6 → +1.5                                             | +0.5-1.5 |
| **Suspicious Keyword** | Presence of phishing-related words  (e.g. `login`, `bank`, `verify`)               | +1       |
| **Suspicious TLD**       | `.xyz`, `.icu`, `.top`, `.buzz`, `.shop` etc.                                      | +1       | 
| **Issuer Risk**          | Let's Encrypt/ZeroSSL/Actalis **AND** (`age<14d` OR `suspicious_tld` OR `keyword`) | +1       | 
| **CN Mismatch**          | Certificate Common Name ≠ domain                                                   | +1       | 
| **OCSP Missing**         | No Online Certificate Status Protocol                                              | +1       |
| **Short-Lived Cert**     | Certificate validity ≤ 14 days                                                     | +1       |
| **Brand in Subdomain**   | Legitimate brand name in subdomain (e.g. `paypal.host.com`)                        | +1       | 
| **Domain Age**           | `0-30 days → +3`, `<90 days → +2`, `<360 days → +1`                                | 1-3      | 
| **Brand Similarity**     | `ratio ≥ 0.8 → +1`, `≥0.85 → +1.5`, `≥0.9 → +2.0`                                  | 1-2      |
> Domains exceeding a chosen threshold (**score ≥ 2**) can be flagged as **medium** or (**score ≥ 4**) **high-risk**.

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
- Permutation checks are limited (max 30), and WHOIS is only called for domains flagged as suspicious
- Uses in-memory caches (`TTLCache` and `lru_cache`) to prevent redundant DNS and WHOIS queries
- Semaphore Limits: 30 concurrent DNS Twister API calls, 10 parallel processing workers
- Domains with missing WHOIS creation date are marked with `-1` and excluded from age-based scoring
- Analysis script deduplicates rows to avoid skewing results from repeated entries
---

##  False Positives & Limitations

- Domains like `s3-eu-west-1.amazonaws.com` often appear similar to brand names but are legitimate infrastructure domains.
- WHOIS lookups may occasionally fail due to connection resets or missing domain records (`Domain not found`, `No match for ...`, `[Errno 54] Connection reset by peer`).
- CT logs include a large number of benign domains; filtering is heuristic-based and not perfect.
- 
---

## Todo / Future Work
- Add machine learning-based phishing classifier
- Support for other log sources beyond CertStream
- Crosscheck with Google Safe Browsing, Virus Total and other blacklists if the domains have been detected as malicious.
---
