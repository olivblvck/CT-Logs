# analysis/listener.py
import websockets
import json
import csv
import os
import re
import gc
import time
import asyncio
import traceback
import ipaddress
import functools
from analysis.phishing_detect import is_similar, extract_features, domain_registration_age
from utils.dns_twister import get_permutations
from utils.who_is import domain_registration_age
from cachetools import TTLCache
from collections import deque

# you can lower value
seen_alerts = deque(maxlen=10000)

# Address of the local CertStream-compatible WebSocket server
CERTSTREAM_URL = "ws://127.0.0.1:8080"

# Define paths for project root and output file
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUTPUT_FILE = os.path.join(PROJECT_ROOT, "output", "suspected_phishing.csv")

# IMPORTANT: for 8GB RAM I recommend use max 20 here
semaphore = asyncio.Semaphore(50)  # max równoległych zapytań do dnstwister

domain_queue = asyncio.Queue()
log_queue = asyncio.Queue()
log_lock = asyncio.Lock()

ALLOWED_LABEL_RE = re.compile(r"^[a-zA-Z0-9-]+$")

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
            item = await domain_queue.get()
            if item is None:
                break
            await process_domain(*item)
        except Exception:
            print("[ERROR] Processing failed:")
            traceback.print_exc()
        finally:
            domain_queue.task_done()

async def csv_writer_worker():
    while True:
        entry = await log_queue.get()
        await asyncio.to_thread(write_csv_row, entry)
        log_queue.task_done()

def write_csv_row(entry):
    try:
        with open(OUTPUT_FILE, "a", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(entry)
    except Exception as e:
        print(f"[ERROR] Failed to write CSV row: {e}")


async def get_valid_permutations(domain: str, limit: int = 30) -> set[str]:
    try:
        ipaddress.ip_address(domain)
        # Jest to IP – nie generujemy permutacji
        return {domain}
    except ValueError:
        # Domena wygląda na złą? Pomijamy
        if not "." in domain or len(domain) > 253 or any(len(label) > 63 for label in domain.split(".")):
            print(f"[SKIP] Ignoring invalid domain: {domain}")
            return set()

    try:
        permutations = await get_permutations(domain)
    except Exception as e:
        print(f"[SKIP] Permutation fetch failed for {domain}: {e}")
        return set()

    to_check = {domain}
    for entry in permutations:
        if isinstance(entry, dict):
            domain_candidate = entry.get("domain")
            if domain_candidate and ALLOWED_LABEL_RE.match(domain_candidate.replace(".", "")):
                to_check.add(domain_candidate)
        elif isinstance(entry, str) and "." in entry:
            to_check.add(entry)

    return set(list(to_check)[:limit])

async def process_domain(domain, issuer, timestamp, cert_data):
    async with semaphore:
        try:
            domain = domain.lstrip("*.")  # usuń prefix '*.' jeśli jest

            try:
                ipaddress.ip_address(domain)
                # To jest IP → pomiń permutacje
                to_check = {domain}
            except ValueError:
                # To jest nazwa domeny → OK
                labels = domain.split(".")
                if len(labels) > 10 or len(domain) > 120 or any(len(label) > 63 for label in labels):
                    print(f"[SKIP] Domain too complex for dnstwister: {domain}")
                    return
                # tylko litery, cyfry i myślniki w każdej etykiecie (dozwolone wg RFC)
                if any(not ALLOWED_LABEL_RE.match(label) for label in labels):
                    print(f"[SKIP] Domain has invalid label characters for dnstwister: {domain}")
                    return
                try:
                    permutations = await get_permutations(domain)
                except Exception as e:
                    print(f"[SKIP] Dnstwister failed for {domain}: {e}")
                    return
                to_check = {domain}

                for entry in permutations:
                    if isinstance(entry, dict) and entry.get("dns-a"):
                        to_check.add(entry["domain"])
                    elif isinstance(entry, str):
                        to_check.add(entry)

                #LIMITUJ liczbę domen do analizy:
                to_check = list(to_check)[:30]

            processed = set()
            for fuzzed_domain in to_check:
                if len(processed) >= 20:
                    break
                #if len(seen_alerts) % 200 == 0:
                    #gc.collect()
                if fuzzed_domain in processed:
                    continue
                processed.add(fuzzed_domain)

                #debug
                #if fuzzed_domain != domain:
                 #   print(f"[DEBUG] Permutation: {fuzzed_domain} (base: {domain})")

                suspicious, brand, score_match = is_similar(fuzzed_domain)
                if not suspicious:
                    continue

                #wywołuj WHOIS tylko dla podejrzanych domen
                if suspicious:
                    # time debug - is whois slowing down the process?
                    # start = time.time()
                    reg_days = await domain_registration_age(fuzzed_domain)
                    # elapsed = time.time() - start
                    # print(f"[WHOIS] {fuzzed_domain} → {reg_days} days old (took {elapsed:.2f}s)")
                else:
                    continue


                tld, tld_suspicious, has_keyword, entropy, cn_mismatch, ocsp_missing, short_lived, brand_in_subdomain, score = extract_features(
                    fuzzed_domain, issuer, reg_days, score_match, cert_data.get("leaf_cert", {})
                )

                key = (fuzzed_domain, brand)
                if key not in seen_alerts:
                    seen_alerts.append(key)
                    print(f"[{timestamp}] ALERT: {fuzzed_domain} ~ {brand} (score={score:.2f})")
                    await log_queue.put([
                        timestamp, fuzzed_domain, brand, f"{score_match:.2f}", issuer,
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

    for domain in domains:
        domain = domain.lstrip("*.")
        await domain_queue.put((domain, issuer, timestamp, cert_data))


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
                    await process_message(message)
        except Exception as e:
            print(f"[WARN] Connection failed: {e}")
            print(f"[INFO] Reconnecting in {backoff} seconds...")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60)  # exponential backoff

async def main():
    consumers = [asyncio.create_task(process_worker()) for _ in range(10)]  # np. 10 równoległych workerów
    producer = asyncio.create_task(certstream_client())
    csv_writer = asyncio.create_task(csv_writer_worker())
    await asyncio.gather(producer, csv_writer, *consumers)

# Main entry point
if __name__ == "__main__":
    asyncio.run(main())


