# utils/who_is.py
import asyncio
from datetime import datetime
from whois import whois
from cachetools import TTLCache
from functools import lru_cache
import os
import subprocess
import tempfile
import contextlib
import sys

whois_semaphore = asyncio.Semaphore(10)  # max 10 równoczesnych WHOIS


os.environ["TERM"] = "dumb"
os.environ["PAGER"] = "cat"

# Mały cache w pamięci na 1 godzinę
whois_cache = TTLCache(maxsize=3000, ttl=3600)

@contextlib.contextmanager
def suppress_stdout_stderr():
    with open(os.devnull, 'w') as devnull:
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        try:
            sys.stdout = devnull
            sys.stderr = devnull
            yield
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

@lru_cache(maxsize=10000)
def _sync_whois(domain):
    try:
        with suppress_stdout_stderr():
            output = subprocess.check_output(
                ['whois', domain],
                stderr=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                text=True,
                timeout=5  # opcjonalnie dodaj timeout
            )
    except Exception:
        return -1

    for line in output.splitlines():
        if "Creation Date:" in line or "created:" in line.lower():
            try:
                date_str = line.split(":")[1].strip()
                creation_date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
                return (datetime.now() - creation_date).days
            except Exception:
                continue
    return -1

# Asynchroniczny wrapper
async def domain_registration_age(domain):
    if domain in whois_cache:
        return whois_cache[domain]
    async with whois_semaphore:
        try:
            age = await asyncio.to_thread(_sync_whois, domain)
        except Exception as e:
            print(f"[WARN] WHOIS lookup failed for {domain}: {e}")
            age = -1
        whois_cache[domain] = age
        return age



