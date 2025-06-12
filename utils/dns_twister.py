import requests
import time
import json

BASE_URL = "https://dnstwister.report/api"


def get_permutations(domain, retries=3, backoff=2):
    url = f"{BASE_URL}/to_hex/{domain}"
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = json.loads(response.content.decode('utf-8'))
            domain_hex = data['domain_as_hexadecimal']
            url = f"{BASE_URL}/fuzz/{domain_hex}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if 500 <= response.status_code < 600 and attempt < retries - 1:
                time.sleep(backoff ** attempt)  # Exponential backoff
                continue
            raise
        except requests.exceptions.RequestException as e:
            print(f"Network error: {e}")
            raise


if __name__ == "__main__":
    try:
        permutations = get_permutations("facebook.com")
        print(permutations)
    except Exception as e:
        print(f"Failed to fetch permutations: {e}")
