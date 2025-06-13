# utils/who_is.py
# This module performs WHOIS lookups to determine domain registration age.
# It uses system-level `whois` for speed and caches results to optimize performance in large-scale scans.

import asyncio, os, subprocess, tempfile, contextlib, sys
from datetime import datetime
from whois import whois # Not used in main logic but may be fallback
from cachetools import TTLCache # In-memory cache with time-to-live
from functools import lru_cache # Least-recently-used cache for function-level memoization

# Semaphore to limit concurrency and avoid WHOIS rate limits
whois_semaphore = asyncio.Semaphore(10)  # Allow up to 10 concurrent WHOIS lookups

# Ensure terminal behavior is simple to avoid `whois` asking for input or using pagers
os.environ["TERM"] = "dumb"
os.environ["PAGER"] = "cat"

# In-memory cache storing results for 1 hour (TTL = 3600 seconds)
whois_cache = TTLCache(maxsize=3000, ttl=3600)

# Context manager to suppress output during subprocess execution
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

# Synchronous WHOIS lookup using system `whois` tool
# Caches up to 10,000 results for repeated calls
@lru_cache(maxsize=10000)
def _sync_whois(domain):
    try:
        with suppress_stdout_stderr():
            output = subprocess.check_output(
                ['whois', domain],         # Call system whois
                stderr=subprocess.DEVNULL,      # Suppress stderr
                stdout=subprocess.PIPE,         # Capture stdout
                text=True,                      # Decode to text
                timeout=5                       # Avoid hanging on unresponsive WHOIS
            )
    except Exception:
        return -1 # WHOIS failed or timed out

    # Try to parse the creation date from the WHOIS response
    for line in output.splitlines():
        if "Creation Date:" in line or "created:" in line.lower():
            try:
                date_str = line.split(":")[1].strip()
                creation_date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
                return (datetime.now() - creation_date).days # Return domain age in days
            except Exception:
                continue # Malformed date, skip
    return -1

# Async wrapper around the synchronous WHOIS function
# Includes concurrency limit and result caching
async def domain_registration_age(domain):
    # Check in TTL cache first
    if domain in whois_cache:
        return whois_cache[domain]

    # Use semaphore to control parallel WHOIS executions
    async with whois_semaphore:
        try:
            # Offload blocking function to thread pool
            age = await asyncio.to_thread(_sync_whois, domain)
        except Exception as e:
            print(f"[WARN] WHOIS lookup failed for {domain}: {e}")
            age = -1

        # Cache result for future use
        whois_cache[domain] = age
        return age



