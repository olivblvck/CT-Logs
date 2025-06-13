#utils/dns_twister.py
import time
import json
import aiohttp
import asyncio

_permutations_cache = {}
BASE_URL = "https://dnstwister.report/api"


async def get_permutations(domain, retries=3, backoff=2):
    if domain in _permutations_cache:
        return _permutations_cache[domain]
    try:
        async with aiohttp.ClientSession() as session:
            # Step 1: Get hex version of domain
            for attempt in range(retries):
                try:
                    url1 = f"{BASE_URL}/to_hex/{domain}"
                    async with session.get(url1, timeout=10) as response1:
                        response1.raise_for_status()
                        data = await response1.json()
                        break
                except Exception as e:
                    if attempt == retries - 1:
                        raise e
                    await asyncio.sleep(backoff ** attempt)

            domain_hex = data['domain_as_hexadecimal']

            # Step 2: Get fuzzed permutations
            for attempt in range(retries):
                try:
                    url2 = f"{BASE_URL}/fuzz/{domain_hex}"
                    async with session.get(url2, timeout=10) as response2:
                        response2.raise_for_status()
                        result = await response2.json()
                        fuzzy_list = result.get("fuzzy_domains", [])
                        filtered = [entry.get("domain") for entry in fuzzy_list if entry.get("domain")]
                        _permutations_cache[domain] = filtered
                        return filtered[:30]  # ogranicz do 30
                except Exception as e:
                    if attempt == retries - 1:
                        raise e
                    await asyncio.sleep(backoff ** attempt)
    except Exception as e:
        print(f"[ERROR] aiohttp dnstwister failed for {domain}: {e}")
        raise



if __name__ == "__main__":
    async def main():
        permutations = await get_permutations("facebook.com")
        print(permutations)
    asyncio.run(main())
