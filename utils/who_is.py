#utils/who_is.py
import asyncio
from whois import whois
from datetime import datetime
from cachetools import TTLCache

whois_cache = TTLCache(maxsize=1000, ttl=86400)



# Estimate domain age in days using WHOIS creation date
async def domain_registration_age(domain):
    if domain in whois_cache:
        return whois_cache[domain]
    try:
        w = await asyncio.to_thread(whois, domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            age = -1
        else:
            age = (datetime.now() - creation_date).days
    except Exception as e:
        print(f"[WARN] WHOIS lookup failed for {domain}: {e}")
        age = -1

    whois_cache[domain] = age
    return age


#print(asyncio.run(domain_registration_age("google.com")))
#print(asyncio.run(domain_registration_age("witkowska-oliwia.pl")))
#print(asyncio.run(domain_registration_age("ochnik.com")))
#print(asyncio.run(domain_registration_age("nonexistent-domain-qwerty.zzz")))