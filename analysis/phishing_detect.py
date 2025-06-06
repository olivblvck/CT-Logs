import Levenshtein
import math
from collections import Counter
import os
import whois
import dns.resolver
import datetime

def load_brand_domains(filepath=None):
    if filepath is None:
        base_dir = os.path.dirname(os.path.dirname(__file__))
        filepath = os.path.join(base_dir, "data", "websites.txt")

    with open(filepath, "r") as f:
        return [line.strip() for line in f if line.strip()]

BRAND_DOMAINS = load_brand_domains()

def is_similar(domain, threshold=0.8):
    for brand in BRAND_DOMAINS:
        dist = Levenshtein.ratio(domain.lower(), brand.lower())
        if dist >= threshold and domain.lower() != brand.lower():
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

FALSE_POSITIVE_PATTERNS = [
    "s3.amazonaws.com", "cloudfront.net", "github.io", "gitlab.io",
    "firebaseapp.com", "azurewebsites.net", "fastly.net",
    "herokuapp.com", "vercel.app", "netlify.app", "pages.dev",
    "wordpress.com", "blogspot.com", "automattic.com"
]

def is_known_false_positive(domain):
    return any(pattern in domain.lower() for pattern in FALSE_POSITIVE_PATTERNS)

def domain_registration_age(domain):
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not creation_date:
            return None
        age_days = (datetime.datetime.now() - creation_date).days
        return age_days
    except:
        return None

def has_valid_dns(domain):
    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except:
        return False

def phishing_score(domain, brand_match, entropy, has_keyword, tld_suspicious, issuer, registration_days):
    score = 0
    if brand_match:
        score += 2
    if has_keyword:
        score += 2
    if entropy >= 3.6:
        score += 1
    if tld_suspicious:
        score += 1
    if issuer.lower() == "let's encrypt":
        score += 1
    if registration_days is not None and registration_days < 30:
        score += 2
    if not has_valid_dns(domain):
        score += 1
    return score

def extract_features(domain: str, brand_match, issuer: str):
    tld = domain.split(".")[-1]
    tld_suspicious = tld in TLD_SUSPICIOUS
    has_keyword = contains_suspicious_word(domain)
    entropy = calculate_entropy(domain)
    age_days = domain_registration_age(domain)
    score = phishing_score(domain, brand_match, entropy, has_keyword, tld_suspicious, issuer, age_days)
    return tld, tld_suspicious, has_keyword, round(entropy, 2), age_days, score
