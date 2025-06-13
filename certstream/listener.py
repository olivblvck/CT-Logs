# analysis/listener.py
import websockets
import json
import csv
import os
import time
import asyncio
import traceback
from analysis.phishing_detect import is_similar, extract_features, domain_registration_age
from utils.dns_twister import get_permutations
from cachetools import TTLCache

# Przechowujemy maks. 50k alertów przez 24h
seen_alerts = TTLCache(maxsize=50000, ttl=86400)

semaphore = asyncio.Semaphore(50)  # max 10 równoległych zapytań do dnstwister

# Address of the local CertStream-compatible WebSocket server
CERTSTREAM_URL = "ws://127.0.0.1:8080"

# Define paths for project root and output file
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUTPUT_FILE = os.path.join(PROJECT_ROOT, "output", "suspected_phishing.csv")

queue = asyncio.Queue()

# Ensure output directory exists
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

# Initialize CSV file with headers if it does not exist or is empty
if not os.path.exists(OUTPUT_FILE) or os.stat(OUTPUT_FILE).st_size == 0:
    with open(OUTPUT_FILE, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        # Headers
        writer.writerow([
            "timestamp", "domain", "brand_match", "similarity_score", "issuer",
            "tld", "tld_suspicious", "has_keyword", "entropy", "registration_days",
            "cn_mismatch", "ocsp_missing", "short_lived", "brand_in_subdomain", "score"
        ])


async def process_worker():
    while True:
        try:
            message = await queue.get()
        except asyncio.CancelledError:
            break  # Nie rób nic więcej, kończ pętlę

        try:
            await process_message(message)
        except Exception:
            print("[ERROR] Processing failed:")
            traceback.print_exc()
        finally:
            queue.task_done()

async def process_domain(domain, issuer, timestamp, cert_data, writer):
    async with semaphore:
        try:
            domain = domain.lstrip("*.")  # usuń prefix '*.' jeśli jest
            permutations = await get_permutations(domain)
            to_check = {domain}


            for entry in permutations:
                if isinstance(entry, dict) and entry.get("dns-a"):
                    to_check.add(entry["domain"])
                elif isinstance(entry, str):
                    to_check.add(entry)

            processed = set()
            for fuzzed_domain in to_check:
                if fuzzed_domain in processed:
                    continue
                processed.add(fuzzed_domain)

                suspicious, brand, score_match = is_similar(fuzzed_domain)
                if not suspicious:
                    continue

                reg_days = domain_registration_age(domain)
                tld, tld_suspicious, has_keyword, entropy, cn_mismatch, ocsp_missing, short_lived, brand_in_subdomain, score = extract_features(
                    domain, issuer, reg_days, score_match, cert_data.get("leaf_cert", {})
                )

                key = (fuzzed_domain, brand)
                if key not in seen_alerts:
                    seen_alerts[key] = True
                    print(f"[{timestamp}] ALERT: {fuzzed_domain} ~ {brand} (score={score:.2f})")
                    writer.writerow([
                        timestamp, domain, brand, f"{score_match:.2f}", issuer,
                        tld, tld_suspicious, has_keyword, entropy, reg_days,
                        cn_mismatch, ocsp_missing, short_lived, brand_in_subdomain, score
                    ])

        except Exception as e:
            print(f"[ERROR] Failed domain processing: {domain}")
            import traceback; traceback.print_exc()

async def process_message(message):
    data = json.loads(message)
    if data.get("message_type") != "certificate_update":
        return

    cert_data = data.get("data", {})
    domains = cert_data.get("leaf_cert", {}).get("all_domains", [])
    timestamp = cert_data.get("seen")
    issuer = cert_data.get("leaf_cert", {}).get("issuer", {}).get("O", "Unknown")

    with open(OUTPUT_FILE, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        tasks = []

        for domain in domains:
            tasks.append(process_domain(domain, issuer, timestamp,cert_data, writer))

        await asyncio.gather(*tasks)


# Persistent client loop with reconnection on failure
async def certstream_client():
    backoff = 1
    while True:
        try:
            print("[INFO] Connecting to CertStream...")
            async with websockets.connect(CERTSTREAM_URL) as ws:
                backoff = 1
                print("[INFO] Connected.")
                async for message in ws:
                    await queue.put(message)
        except Exception as e:
            print(f"[WARN] Connection failed: {e}")
            print(f"[INFO] Reconnecting in {backoff} seconds...")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60)  # exponential backoff

async def main():
    consumer = asyncio.create_task(process_worker())
    producer = asyncio.create_task(certstream_client())
    await asyncio.gather(producer, consumer)

# Main entry point
if __name__ == "__main__":
    asyncio.run(main())