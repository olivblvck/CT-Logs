import time
import json
import aiohttp
import asyncio

_permutations_cache = {}
BASE_URL = "https://dnstwister.report/api"


BASE_URL = "https://dnstwister.report/api"

async def get_permutations(domain, retries=3, backoff=2):
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
                        return await response2.json()
                except Exception as e:
                    if attempt == retries - 1:
                        raise e
                    await asyncio.sleep(backoff ** attempt)
    except Exception as e:
        print(f"[ERROR] aiohttp dnstwister failed for {domain}: {e}")
        raise

if __name__ == "__main__":
    try:
        permutations = get_permutations("facebook.com")
        print(permutations)
    except Exception as e:
        print(f"Failed to fetch permutations: {e}")
