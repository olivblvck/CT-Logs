# certstream/listener.py
import websocket
import json
import csv
import os
from analysis.phishing_detect import is_similar, extract_features

CERTSTREAM_URL = "ws://127.0.0.1:8080"

# Ścieżka do folderu głównego projektu
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUTPUT_FILE = os.path.join(PROJECT_ROOT, "output", "suspected_phishing.csv")

# Tworzenie katalogu jeśli nie istnieje
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

# Inicjalizacja pliku CSV z nagłówkiem
if not os.path.exists(OUTPUT_FILE) or os.stat(OUTPUT_FILE).st_size == 0:
    with open(OUTPUT_FILE, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "timestamp", "domain", "brand_match", "similarity_score",
            "issuer", "tld", "tld_suspicious", "has_keyword", "entropy"
        ])

def on_message(ws, message):
    try:
        data = json.loads(message)
        if data.get("message_type") == "certificate_update":
            cert_data = data.get("data", {})
            all_domains = cert_data.get("leaf_cert", {}).get("all_domains", [])
            timestamp = cert_data.get("seen", None)
            issuer = cert_data.get("leaf_cert", {}).get("issuer", {}).get("O", "Unknown")

            print(f"[{timestamp}] Domains: {all_domains}")
            print(f"  ↳ Issuer: {issuer}")

            with open(OUTPUT_FILE, "a", newline="") as csvfile:
                writer = csv.writer(csvfile)
                for domain in all_domains:
                    suspicious, brand, score = is_similar(domain)
                    if suspicious:
                        print(f"[ALERT] Possible phishing domain: {domain} ~ {brand} (score={score:.2f})")
                        tld, tld_suspicious, has_keyword, entropy = extract_features(domain)
                        writer.writerow([
                            timestamp, domain, brand, f"{score:.2f}", issuer,
                            tld, tld_suspicious, has_keyword, entropy
                        ])
    except Exception as e:
        print(f"[ERROR] Failed to parse message: {e}")

def on_error(ws, error):
    print(f"[ERROR] WebSocket error: {error}")

def on_close(ws, close_status_code, close_msg):
    print(f"[INFO] WebSocket closed: {close_status_code}, {close_msg}")

def on_open(ws):
    print("[INFO] Connected to local certstream server...")

if __name__ == "__main__":
    print("[INFO] Starting CertStream client...")
    ws = websocket.WebSocketApp(
        CERTSTREAM_URL,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        on_open=on_open
    )
    ws.run_forever()