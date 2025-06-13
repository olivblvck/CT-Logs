#utils/dns_twister.py
# This module interacts with the DNS Twister API to fetch domain name permutations for typo-squatting detection.
# It uses asynchronous HTTP requests and includes retry logic with exponential backoff for robustness.

import time
import json
import aiohttp
import asyncio

# Local in-memory cache to avoid redundant API calls for the same domain
_permutations_cache = {}

# Base API URL for DNS Twister
BASE_URL = "https://dnstwister.report/api"

# Main function to retrieve typo permutations of a given domain
async def get_permutations(domain, retries=3, backoff=2):
    # Check cache first
    if domain in _permutations_cache:
        return _permutations_cache[domain]
    try:
        async with aiohttp.ClientSession() as session:
            # Step 1: Convert domain to hexadecimal representation required by API
            for attempt in range(retries):
                try:
                    url1 = f"{BASE_URL}/to_hex/{domain}"
                    async with session.get(url1, timeout=10) as response1:
                        response1.raise_for_status()   # Raise exception on HTTP error
                        data = await response1.json()
                        break # Success, exit retry loop
                except Exception as e:
                    # Retry if not the final attempt
                    if attempt == retries - 1:
                        raise e
                    await asyncio.sleep(backoff ** attempt)  # Exponential backoff

            domain_hex = data['domain_as_hexadecimal']

            # Step 2: Query the fuzzing endpoint with the hex domain to get permutations
            for attempt in range(retries):
                try:
                    url2 = f"{BASE_URL}/fuzz/{domain_hex}"
                    async with session.get(url2, timeout=10) as response2:
                        response2.raise_for_status()
                        result = await response2.json()
                        fuzzy_list = result.get("fuzzy_domains", [])
                        # Extract domain names from the response
                        filtered = [entry.get("domain") for entry in fuzzy_list if entry.get("domain")]
                        _permutations_cache[domain] = filtered # Save in cache
                        return filtered[:30]  # Limit to 30 permutations
                except Exception as e:
                    if attempt == retries - 1:
                        raise e
                    await asyncio.sleep(backoff ** attempt)
    except Exception as e:
        print(f"[ERROR] aiohttp dnstwister failed for {domain}: {e}")
        raise # Raise exception to the caller for visibility


# Demo/test usage for manual run
if __name__ == "__main__":
    async def main():
        permutations = await get_permutations("facebook.com")
        print(permutations)
    asyncio.run(main())
