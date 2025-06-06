
import Levenshtein
import math
from collections import Counter
import os

def load_brand_domains(filepath=None):
    if filepath is None:
        base_dir = os.path.dirname(os.path.dirname(__file__))  # CT-Logs/
        filepath = os.path.join(base_dir, "data", "websites.txt")

    with open(filepath, "r") as f:
        return [line.strip() for line in f if line.strip()]

BRAND_DOMAINS = load_brand_domains()

def is_similar(domain, threshold=0.8):
    for brand in BRAND_DOMAINS:
        dist = Levenshtein.ratio(domain.lower(), brand.lower())
        if dist >= threshold and domain.lower() != brand.lower():
            # Filtracja znanych false positives (np. CDN, API, chmura)
            if is_known_false_positive(domain):
                return False, None, None
            return True, brand, dist
    return False, None, None

def contains_suspicious_word(domain):
    suspicious_words = {
        "login", "verify", "secure", "update", "account", "signin",
        "password", "auth", "bank", "pay", "confirm", "reset", "validate",
        "webmail", "support", "unlock", "user", "invoice"
    }
    return any(word in domain.lower() for word in suspicious_words)

def calculate_entropy(s):
    p, lns = Counter(s), float(len(s))
    return -sum(count / lns * math.log2(count / lns) for count in p.values())

TLD_SUSPICIOUS = {
    "xyz", "top", "buzz", "shop", "online", "click", "link", "support",
    "help", "fit", "club", "live", "life", "host", "press", "work", "today",
    "site", "website", "space", "rest", "fail", "gdn", "uno", "trade"
}

# False positive patterns: chmura, dev toolsy, legalne CDN
FALSE_POSITIVE_PATTERNS = [
    "s3.amazonaws.com", "cloudfront.net", "github.io", "gitlab.io",
    "firebaseapp.com", "azurewebsites.net", "fastly.net",
    "herokuapp.com", "vercel.app", "netlify.app", "pages.dev",
    "wordpress.com", "blogspot.com", "automattic.com"
]

def is_known_false_positive(domain):
    return any(pattern in domain.lower() for pattern in FALSE_POSITIVE_PATTERNS)

def extract_features(domain: str):
    tld = domain.split(".")[-1]
    tld_suspicious = tld in TLD_SUSPICIOUS
    has_keyword = contains_suspicious_word(domain)
    entropy = calculate_entropy(domain)
    return tld, tld_suspicious, has_keyword, round(entropy, 2)
