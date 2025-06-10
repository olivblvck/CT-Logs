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
│   └── stats.py
├── certstream/
│   └── listener.py
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

A. FUNKCJONALNOŚĆ

1. Strumieniowe przetwarzanie danych
	-	Zaimplementuj pełnoprawny mechanizm kolejkowania i buforowania danych z certstream.
	-	Obsłuż rozłączenia, timeouty, błędy sieciowe — z backoffem i reconnectem.
	-	Dodaj możliwość asynchronicznego przetwarzania certyfikatów (np. przez asyncio, threading, multiprocessing).

2. System reguł heurystycznych

Dodaj zaawansowane reguły wykrywania phishingu:
	-	detekcja homografów (np. g00gle.com, arnazon.com)
	-	słowa kluczowe w domenach (np. secure, login, verify)
	-	anomalie w strukturze certyfikatu (CN ≠ SAN, brak OCSP, zbyt krótki czas życia)
	-	analizuj organizację, lokalizację, wystawcę certyfikatu

3. Integracja z zewnętrznymi źródłami
	-	Sprawdzenie reputacji domeny: phishtank, virustotal, abuse.ch, URLScan.io
	-	Generowanie podobnych domen z dnstwister i porównanie z CT Logs

4. Wprowadzenie klasyfikatora ML
	-	Zbieranie danych: podejrzane i nieszkodliwe domeny
	-	Feature engineering (długość domeny, entropia, zawartość certyfikatu, itp.)
	-	Trening klasyfikatora: nawet prostego drzewa decyzyjnego (sklearn) z ewaluacją metryk

B. JAKOŚĆ KODU

5. Refaktoryzacja struktury projektu
	-	Podział na moduły: core/, detection/, data/, utils/, api/
	-	Dokumentacja każdej funkcji: docstringi, typowanie (Python 3 type hints)
	-	Jednolity styl kodu (PEP8), automatyzacja przez black lub flake8

6. Testy jednostkowe
	-	Napisz testy dla każdego komponentu: pobieranie danych, detekcja, analiza certyfikatów
	-	Użyj pytest, mock, unittest

7. Logowanie i monitoring
	-	Zaimplementuj logging z poziomami (INFO, ERROR, DEBUG)
	-	Zapisuj błędy z whois, dns, API do osobnych logów

C. ANALIZA I RAPORT

8. System ewaluacji
	-	Metryki: precision, recall, F1-score, confusion matrix dla klasyfikatora
	-	Porównanie skuteczności heurystyk vs ML
	-	Przykłady wykrytych domen, błędy fałszywie pozytywne i negatywne

9. Wizualizacje
	-	Statystyki rejestrowanych domen (wykresy: typy certyfikatów, długość nazw, popularność TLD)
	-	Heatmapy, słowa kluczowe, trend phishingowych nazw w czasie

10. Raport końcowy
	-	Schemat architektury systemu
	-	Opis metod i uzasadnienie ich wyboru
	-	Opis wyników z tabelami, wykresami, metrykami
	-	Omówienie ograniczeń i możliwości dalszego rozwoju


---
