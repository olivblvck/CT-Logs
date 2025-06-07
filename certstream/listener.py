# analysis/listener.py
import websocket
import json
import csv
import os
from analysis.phishing_detect import is_similar, extract_features, domain_registration_age
import time

# Address of the local CertStream-compatible WebSocket server
CERTSTREAM_URL = "ws://127.0.0.1:8080"

# Define paths for project root and output file
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUTPUT_FILE = os.path.join(PROJECT_ROOT, "output", "suspected_phishing.csv")

# Ensure output directory exists
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

# Initialize CSV file with headers if it does not exist or is empty
if not os.path.exists(OUTPUT_FILE) or os.stat(OUTPUT_FILE).st_size == 0:
    with open(OUTPUT_FILE, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        # Headers
        writer.writerow([
            "timestamp", "domain", "brand_match", "similarity_score",
            "issuer", "tld", "tld_suspicious", "has_keyword",
            "entropy", "registration_days", "score"
        ])

# Handler for each incoming WebSocket message
def on_message(ws, message):
    try:
        data = json.loads(message)
        # Process only certificate update messages
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
                    # Check similarity to known brands
                    suspicious, brand, score_match = is_similar(domain)
                    if suspicious:
                        print(f"[ALERT] Possible phishing domain: {domain} ~ {brand} (score={score_match:.2f})")

                        # Get WHOIS registration age
                        reg_days = domain_registration_age(domain)
                        tld, tld_suspicious, has_keyword, entropy, score = extract_features(domain, issuer, reg_days,score_match)

                        # Extract domain features and compute final phishing score
                        print(f"        → Features: TLD={tld}, Suspicious={tld_suspicious}, Keyword={has_keyword}, Entropy={entropy}, Days={reg_days}, Score={score:.2f}")

                        # Append to CSV file
                        writer.writerow([
                            timestamp, domain, brand, f"{score_match:.2f}", issuer,
                            tld, tld_suspicious, has_keyword, entropy, reg_days, score
                        ])
    except Exception as e:
        print(f"[ERROR] Failed to parse message: {e}")

# WebSocket error handler
def on_error(ws, error):
    print(f"[ERROR] WebSocket error: {error}")

# WebSocket closure handler
def on_close(ws, close_status_code, close_msg):
    print(f"[INFO] WebSocket closed: {close_status_code}, {close_msg}")

# WebSocket open handler
def on_open(ws):
    print("[INFO] Connected to local certstream server...")

# Persistent client loop with reconnection on failure
def run_client():
    while True:
        print("[INFO] Starting CertStream client...")
        try:
            ws = websocket.WebSocketApp(
                CERTSTREAM_URL,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close,
                on_open=on_open
            )
            ws.run_forever()
        except Exception as e:
            print(f"[ERROR] WebSocket client crashed: {e}")
        print("[INFO] Reconnecting in 5 seconds...")
        time.sleep(5)

# Main entry point
if __name__ == "__main__":
    run_client()




