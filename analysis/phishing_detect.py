#certstream/phishing_detect.py
import Levenshtein
import math
from collections import Counter
import os
import whois
import dns.resolver
from datetime import datetime

# Load a list of known brand domains from a text file
def load_brand_domains(filepath=None):
    if filepath is None:
        base_dir = os.path.dirname(os.path.dirname(__file__))
        filepath = os.path.join(base_dir, "data", "websites.txt")

    with open(filepath, "r") as f:
        return [line.strip() for line in f if line.strip()]

BRAND_DOMAINS = load_brand_domains()

def has_brand_in_subdomain(domain: str) -> (bool, str):
    """
    Sprawdza, czy subdomena zawiera znany brand (np. paypal.security.com)
    """
    parts = domain.lower().split(".")
    if len(parts) < 3:
        return False, None  # Brak subdomeny

    subdomain_parts = parts[:-2]  # Wszystko przed główną domeną i TLD
    subdomain = ".".join(subdomain_parts)

    for brand in BRAND_DOMAINS:
        if brand.lower() in subdomain:
            return True, brand
    return False, None

# Check if a domain is similar to any known brand using Levenshtein similarity
def is_similar(domain, threshold=0.8):
    for brand in BRAND_DOMAINS:
        dist = Levenshtein.ratio(domain.lower(), brand.lower())
        if dist >= threshold and domain.lower() != brand.lower():
            if is_known_false_positive(domain):
                return False, None, None
            return True, brand, dist
    return False, None, None

# Check if the domain contains known phishing-related keywords
def contains_suspicious_word(domain):
    suspicious_words = {
        "login", "verify", "secure", "update", "account", "signin",
        "password", "auth", "bank", "pay", "confirm", "reset", "validate",
        "webmail", "support", "unlock", "user", "invoice"
    }
    return any(word in domain.lower() for word in suspicious_words)

# Calculate Shannon entropy of a domain string to detect randomness
def calculate_entropy(s):
    p, lns = Counter(s), float(len(s))
    return -sum(count / lns * math.log2(count / lns) for count in p.values())

# Suspicious TLDs commonly associated with phishing, scams, and low-cost registrations.
TLD_SUSPICIOUS = {
    # Freenom-based and free/cheap TLDs
    "tk", "ml", "ga", "cf", "gq", "icu", "cyou", "vip", "cam", "men", "xyz", "me", "info", "sbs", "icu", "cfd"

    # Marketing and misleading content themes
    "click", "link", "press", "review", "trade", "stream", "party", "download", "racing", "loan", "win", "date",

    # Technical / hosting / generic usage – often abused for disposable websites
    "host", "website", "space", "site", "online", "webcam", "cloud",

    # Lifestyle and trendy TLDs – often used in social engineering or deceptive branding
    "buzz", "shop", "top", "club", "life", "live", "fun", "fit", "mom", "today", "beauty", "pics", "fashion", "boats", "autos",

    # Geographic or sovereign TLDs with known history of lax policies or cheap registration
    "zw", "cm", "vu", "cd", "cc", "la", "su", "tv", "to",

    # Frequently reported in phishing/malware campaigns or underground markets
    "uno", "xin", "lol", "gdn", "faith", "science", "work", "run", "pro", "asia", "ws", "pw", "yt", "bd", "cam",
}
# Common AWS S3 and related service official endpoints to avoid false positives
AWS_DOMAINS = [
    "s3-website.us-east-2.amazonaws.com",
    "s3-website-us-east-1.amazonaws.com",
    "s3-website-us-west-1.amazonaws.com",
    "s3-website-us-west-2.amazonaws.com",
    "s3-website.af-south-1.amazonaws.com",
    "s3-website.ap-east-1.amazonaws.com",
    "s3-website.ap-south-2.amazonaws.com",
    "s3-website.ap-southeast-3.amazonaws.com",
    "s3-website.ap-southeast-5.amazonaws.com",
    "s3-website.ap-southeast-4.amazonaws.com",
    "s3-website.ap-south-1.amazonaws.com",
    "s3-website.ap-northeast-3.amazonaws.com",
    "s3-website.ap-northeast-2.amazonaws.com",
    "s3-website-ap-southeast-1.amazonaws.com",
    "s3-website-ap-southeast-2.amazonaws.com",
    "s3-website.ap-east-2.amazonaws.com",
    "s3-website.ap-southeast-7.amazonaws.com",
    "s3-website-ap-northeast-1.amazonaws.com",
    "s3-website.ca-central-1.amazonaws.com",
    "s3-website.ca-west-1.amazonaws.com",
    "s3-website.eu-central-1.amazonaws.com",
    "s3-website-eu-west-1.amazonaws.com",
    "s3-website.eu-west-2.amazonaws.com",
    "s3-website.eu-south-1.amazonaws.com",
    "s3-website.eu-west-3.amazonaws.com",
    "s3-website.eu-south-2.amazonaws.com",
    "s3-website.eu-north-1.amazonaws.com",
    "s3-website.eu-central-2.amazonaws.com",
    "s3-website.il-central-1.amazonaws.com",
    "s3-website.mx-central-1.amazonaws.com",
    "s3-website.me-south-1.amazonaws.com",
    "s3-website.me-central-1.amazonaws.com",
    "s3-website-sa-east-1.amazonaws.com",
    "s3-website.us-gov-east-1.amazonaws.com",
    "s3-website-us-gov-west-1.amazonaws.com",
    "s3-control.us-east-2.amazonaws.com",
    "s3-control.dualstack.us-east-2.amazonaws.com",
    "s3-control-fips.dualstack.us-east-2.amazonaws.com",
    "s3-control-fips.us-east-2.amazonaws.com",
    "s3-control.us-east-1.amazonaws.com",
    "s3-control-fips.us-east-1.amazonaws.com",
    "s3-control.dualstack.us-east-1.amazonaws.com",
    "s3-control-fips.dualstack.us-east-1.amazonaws.com",
    "s3-control.us-west-1.amazonaws.com",
    "s3-control.dualstack.us-west-1.amazonaws.com",
    "s3-control-fips.dualstack.us-west-1.amazonaws.com",
    "s3-control-fips.us-west-1.amazonaws.com",
    "s3-control.us-west-2.amazonaws.com",
    "s3-control-fips.us-west-2.amazonaws.com",
    "s3-control.dualstack.us-west-2.amazonaws.com",
    "s3-control-fips.dualstack.us-west-2.amazonaws.com",
    "s3-control.af-south-1.amazonaws.com",
    "s3-control.dualstack.af-south-1.amazonaws.com",
    "s3-control.ap-east-1.amazonaws.com",
    "s3-control.dualstack.ap-east-1.amazonaws.com",
    "s3-control.ap-south-2.amazonaws.com",
    "s3-control.dualstack.ap-south-2.amazonaws.com",
    "s3-control.ap-southeast-3.amazonaws.com",
    "s3-control.dualstack.ap-southeast-3.amazonaws.com",
    "s3-control.ap-southeast-4.amazonaws.com",
    "s3-control.dualstack.ap-southeast-4.amazonaws.com",
    "s3-control.ap-south-1.amazonaws.com",
    "s3-control.dualstack.ap-south-1.amazonaws.com",
    "s3-control.ap-northeast-3.amazonaws.com",
    "s3-control.dualstack.ap-northeast-3.amazonaws.com",
    "s3-control.ap-northeast-2.amazonaws.com",
    "s3-control.dualstack.ap-northeast-2.amazonaws.com",
    "s3-control.ap-southeast-1.amazonaws.com",
    "s3-control.dualstack.ap-southeast-1.amazonaws.com",
    "s3-control.ap-southeast-2.amazonaws.com",
    "s3-control.dualstack.ap-southeast-2.amazonaws.com",
    "s3-control.ap-northeast-1.amazonaws.com",
    "s3-control.dualstack.ap-northeast-1.amazonaws.com",
    "s3-control.ca-central-1.amazonaws.com",
    "s3-control.dualstack.ca-central-1.amazonaws.com",
    "s3-control-fips.ca-central-1.amazonaws.com",
    "s3-control-fips.dualstack.ca-central-1.amazonaws.com",
    "s3-control.ca-west-1.amazonaws.com",
    "s3-control-fips.ca-west-1.amazonaws.com",
    "s3-control.dualstack.ca-west-1.amazonaws.com",
    "s3-control-fips.dualstack.ca-west-1.amazonaws.com",
    "s3-control.eu-central-1.amazonaws.com",
    "s3-control.dualstack.eu-central-1.amazonaws.com",
    "s3-control.eu-west-1.amazonaws.com",
    "s3-control.dualstack.eu-west-1.amazonaws.com",
    "s3-control.eu-west-2.amazonaws.com",
    "s3-control.dualstack.eu-west-2.amazonaws.com",
    "s3-control.eu-south-1.amazonaws.com",
    "s3-control.dualstack.eu-south-1.amazonaws.com",
    "s3-control.eu-west-3.amazonaws.com",
    "s3-control.dualstack.eu-west-3.amazonaws.com",
    "s3-control.eu-south-2.amazonaws.com",
    "s3-control.dualstack.eu-south-2.amazonaws.com",
    "s3-control.eu-north-1.amazonaws.com",
    "s3-control.dualstack.eu-north-1.amazonaws.com",
    "s3-control.eu-central-2.amazonaws.com",
    "s3-control.dualstack.eu-central-2.amazonaws.com",
    "s3-control.il-central-1.amazonaws.com",
    "s3-control.dualstack.il-central-1.amazonaws.com",
    "s3-control.me-south-1.amazonaws.com",
    "s3-control.dualstack.me-south-1.amazonaws.com",
    "s3-control.me-central-1.amazonaws.com",
    "s3-control.dualstack.me-central-1.amazonaws.com",
    "s3-control.sa-east-1.amazonaws.com",
    "s3-control.dualstack.sa-east-1.amazonaws.com",
    "s3-control.us-gov-east-1.amazonaws.com",
    "s3-control-fips.us-gov-east-1.amazonaws.com",
    "s3-control.dualstack.us-gov-east-1.amazonaws.com",
    "s3-control-fips.dualstack.us-gov-east-1.amazonaws.com",
    "s3-control.us-gov-west-1.amazonaws.com",
    "s3-control-fips.dualstack.us-gov-west-1.amazonaws.com",
    "s3-control.dualstack.us-gov-west-1.amazonaws.com",
    "s3-control-fips.us-gov-west-1.amazonaws.com",
    "s3-accesspoint.us-east-2.amazonaws.com",
    "s3-accesspoint-fips.dualstack.us-east-2.amazonaws.com",
    "s3-accesspoint-fips.us-east-2.amazonaws.com",
    "s3-accesspoint.dualstack.us-east-2.amazonaws.com",
    "s3-accesspoint.us-east-1.amazonaws.com",
    "s3-accesspoint-fips.dualstack.us-east-1.amazonaws.com",
    "s3-accesspoint-fips.us-east-1.amazonaws.com",
    "s3-accesspoint.dualstack.us-east-1.amazonaws.com",
    "s3-accesspoint.us-west-1.amazonaws.com",
    "s3-accesspoint-fips.dualstack.us-west-1.amazonaws.com",
    "s3-accesspoint-fips.us-west-1.amazonaws.com",
    "s3-accesspoint.dualstack.us-west-1.amazonaws.com",
    "s3-accesspoint.us-west-2.amazonaws.com",
    "s3-accesspoint-fips.dualstack.us-west-2.amazonaws.com",
    "s3-accesspoint-fips.us-west-2.amazonaws.com",
    "s3-accesspoint.dualstack.us-west-2.amazonaws.com",
    "s3-accesspoint.af-south-1.amazonaws.com",
    "s3-accesspoint.dualstack.af-south-1.amazonaws.com",
    "s3-accesspoint.ap-east-1.amazonaws.com",
    "s3-accesspoint.dualstack.ap-east-1.amazonaws.com",
    "s3-accesspoint.ap-south-2.amazonaws.com",
    "s3-accesspoint.dualstack.ap-south-2.amazonaws.com",
    "s3-accesspoint.ap-southeast-3.amazonaws.com",
    "s3-accesspoint.dualstack.ap-southeast-3.amazonaws.com",
    "s3-accesspoint.ap-southeast-5.amazonaws.com",
    "s3-accesspoint.dualstack.ap-southeast-5.amazonaws.com",
    "s3-accesspoint.ap-southeast-4.amazonaws.com",
    "s3-accesspoint.dualstack.ap-southeast-4.amazonaws.com",
    "s3-accesspoint.ap-south-1.amazonaws.com",
    "s3-accesspoint.dualstack.ap-south-1.amazonaws.com",
    "s3-accesspoint.ap-northeast-3.amazonaws.com",
    "s3-accesspoint.dualstack.ap-northeast-3.amazonaws.com",
    "s3-accesspoint.ap-northeast-2.amazonaws.com",
    "s3-accesspoint.dualstack.ap-northeast-2.amazonaws.com",
    "s3-accesspoint.ap-southeast-1.amazonaws.com",
    "s3-accesspoint.dualstack.ap-southeast-1.amazonaws.com",
    "s3-accesspoint.ap-southeast-2.amazonaws.com",
    "s3-accesspoint.dualstack.ap-southeast-2.amazonaws.com",
    "s3-accesspoint.ap-east-2.amazonaws.com",
    "s3-accesspoint.dualstack.ap-east-2.amazonaws.com",
    "s3-accesspoint.ap-southeast-7.amazonaws.com",
    "s3-accesspoint.dualstack.ap-southeast-7.amazonaws.com",
    "s3-accesspoint.ap-northeast-1.amazonaws.com",
    "s3-accesspoint.dualstack.ap-northeast-1.amazonaws.com",
    "s3-accesspoint.ca-central-1.amazonaws.com",
    "s3-accesspoint-fips.dualstack.ca-central-1.amazonaws.com",
    "s3-accesspoint-fips.ca-central-1.amazonaws.com",
    "s3-accesspoint.dualstack.ca-central-1.amazonaws.com",
    "s3-accesspoint.ca-west-1.amazonaws.com",
    "s3-accesspoint-fips.dualstack.ca-west-1.amazonaws.com",
    "s3-accesspoint-fips.ca-west-1.amazonaws.com",
    "s3-accesspoint.dualstack.ca-west-1.amazonaws.com",
    "s3-accesspoint.eu-central-1.amazonaws.com",
    "s3-accesspoint.dualstack.eu-central-1.amazonaws.com",
    "s3-accesspoint.eu-west-1.amazonaws.com",
    "s3-accesspoint.dualstack.eu-west-1.amazonaws.com",
    "s3-accesspoint.eu-west-2.amazonaws.com",
    "s3-accesspoint.dualstack.eu-west-2.amazonaws.com",
    "s3-accesspoint.eu-south-1.amazonaws.com",
    "s3-accesspoint.dualstack.eu-south-1.amazonaws.com",
    "s3-accesspoint.eu-west-3.amazonaws.com",
    "s3-accesspoint.dualstack.eu-west-3.amazonaws.com",
    "s3-accesspoint.eu-south-2.amazonaws.com",
    "s3-accesspoint.dualstack.eu-south-2.amazonaws.com",
    "s3-accesspoint.eu-north-1.amazonaws.com",
    "s3-accesspoint.dualstack.eu-north-1.amazonaws.com",
    "s3-accesspoint.eu-central-2.amazonaws.com",
    "s3-accesspoint.dualstack.eu-central-2.amazonaws.com",
    "s3-accesspoint.il-central-1.amazonaws.com",
    "s3-accesspoint.dualstack.il-central-1.amazonaws.com",
    "s3-accesspoint.mx-central-1.amazonaws.com",
    "s3-accesspoint.dualstack.mx-central-1.amazonaws.com",
    "s3-accesspoint.me-south-1.amazonaws.com",
    "s3-accesspoint.dualstack.me-south-1.amazonaws.com",
    "s3-accesspoint.me-central-1.amazonaws.com",
    "s3-accesspoint.dualstack.me-central-1.amazonaws.com",
    "s3-accesspoint.sa-east-1.amazonaws.com",
    "s3-accesspoint.dualstack.sa-east-1.amazonaws.com",
    "s3-accesspoint.us-gov-east-1.amazonaws.com",
    "s3-accesspoint-fips.dualstack.us-gov-east-1.amazonaws.com",
    "s3-accesspoint-fips.us-gov-east-1.amazonaws.com",
    "s3-accesspoint.dualstack.us-gov-east-1.amazonaws.com",
    "s3-accesspoint.us-gov-west-1.amazonaws.com",
    "s3-accesspoint-fips.dualstack.us-gov-west-1.amazonaws.com",
    "s3-accesspoint-fips.us-gov-west-1.amazonaws.com",
    "s3-accesspoint.dualstack.us-gov-west-1.amazonaws.com",
    "s3.us-east-2.amazonaws.com",
    "s3.dualstack.us-east-2.amazonaws.com",
    "s3-fips.dualstack.us-east-2.amazonaws.com",
    "s3-fips.us-east-2.amazonaws.com",
    "s3.us-east-1.amazonaws.com",
    "s3.dualstack.us-east-1.amazonaws.com",
    "s3-fips.us-east-1.amazonaws.com",
    "s3-fips.dualstack.us-east-1.amazonaws.com",
    "s3.us-west-1.amazonaws.com",
    "s3.dualstack.us-west-1.amazonaws.com",
    "s3-fips.dualstack.us-west-1.amazonaws.com",
    "s3-fips.us-west-1.amazonaws.com",
    "s3.us-west-2.amazonaws.com",
    "s3.dualstack.us-west-2.amazonaws.com",
    "s3-fips.dualstack.us-west-2.amazonaws.com",
    "s3-fips.us-west-2.amazonaws.com",
    "s3.af-south-1.amazonaws.com",
    "s3.dualstack.af-south-1.amazonaws.com",
    "s3.ap-east-1.amazonaws.com",
    "s3.dualstack.ap-east-1.amazonaws.com",
    "s3.ap-south-2.amazonaws.com",
    "s3.dualstack.ap-south-2.amazonaws.com",
    "s3.ap-southeast-3.amazonaws.com",
    "s3.dualstack.ap-southeast-3.amazonaws.com",
    "s3.ap-southeast-5.amazonaws.com",
    "s3.dualstack.ap-southeast-5.amazonaws.com",
    "s3.ap-southeast-4.amazonaws.com",
    "s3.dualstack.ap-southeast-4.amazonaws.com",
    "s3.ap-south-1.amazonaws.com",
    "s3.dualstack.ap-south-1.amazonaws.com",
    "s3.ap-northeast-3.amazonaws.com",
    "s3.dualstack.ap-northeast-3.amazonaws.com",
    "s3.ap-northeast-2.amazonaws.com",
    "s3.dualstack.ap-northeast-2.amazonaws.com",
    "s3.ap-southeast-1.amazonaws.com",
    "s3.dualstack.ap-southeast-1.amazonaws.com",
    "s3.ap-southeast-2.amazonaws.com",
    "s3.dualstack.ap-southeast-2.amazonaws.com",
    "s3.ap-east-2.amazonaws.com",
    "s3.dualstack.ap-east-2.amazonaws.com",
    "s3.ap-southeast-7.amazonaws.com",
    "s3.dualstack.ap-southeast-7.amazonaws.com",
    "s3.ap-northeast-1.amazonaws.com",
    "s3.dualstack.ap-northeast-1.amazonaws.com",
    "s3.ca-central-1.amazonaws.com",
    "s3.dualstack.ca-central-1.amazonaws.com",
    "s3-fips.dualstack.ca-central-1.amazonaws.com",
    "s3-fips.ca-central-1.amazonaws.com",
    "s3.ca-west-1.amazonaws.com",
    "s3.dualstack.ca-west-1.amazonaws.com",
    "s3-fips.dualstack.ca-west-1.amazonaws.com",
    "s3-fips.ca-west-1.amazonaws.com",
    "s3.eu-central-1.amazonaws.com",
    "s3.dualstack.eu-central-1.amazonaws.com",
    "s3.eu-west-1.amazonaws.com",
    "s3.dualstack.eu-west-1.amazonaws.com",
    "s3.eu-west-2.amazonaws.com",
    "s3.dualstack.eu-west-2.amazonaws.com",
    "s3.eu-south-1.amazonaws.com",
    "s3.dualstack.eu-south-1.amazonaws.com",
    "s3.eu-west-3.amazonaws.com",
    "s3.dualstack.eu-west-3.amazonaws.com",
    "s3.eu-south-2.amazonaws.com",
    "s3.dualstack.eu-south-2.amazonaws.com",
    "s3.eu-north-1.amazonaws.com",
    "s3.dualstack.eu-north-1.amazonaws.com",
    "s3.eu-central-2.amazonaws.com",
    "s3.dualstack.eu-central-2.amazonaws.com",
    "s3.il-central-1.amazonaws.com",
    "s3.dualstack.il-central-1.amazonaws.com",
    "s3.mx-central-1.amazonaws.com",
    "s3.dualstack.mx-central-1.amazonaws.com",
    "s3.me-south-1.amazonaws.com",
    "s3.dualstack.me-south-1.amazonaws.com",
    "s3.me-central-1.amazonaws.com",
    "s3.dualstack.me-central-1.amazonaws.com",
    "s3.sa-east-1.amazonaws.com",
    "s3.dualstack.sa-east-1.amazonaws.com",
    "s3.us-gov-east-1.amazonaws.com",
    "s3-fips.dualstack.us-gov-east-1.amazonaws.com",
    "s3.dualstack.us-gov-east-1.amazonaws.com",
    "s3-fips.us-gov-east-1.amazonaws.com",
    "s3.us-gov-west-1.amazonaws.com",
    "s3-fips.dualstack.us-gov-west-1.amazonaws.com",
    "s3.dualstack.us-gov-west-1.amazonaws.com",
    "s3-fips.us-gov-west-1.amazonaws.com",
    "s3-eu-west-1.amazonaws.com"
]
# Known hosting/CDN domains that might lead to false positives
FALSE_POSITIVE_PATTERNS = [
     *AWS_DOMAINS, "s3.amazonaws.com", "cloudfront.net", "github.io", "gitlab.io",
    "firebaseapp.com", "azurewebsites.net", "fastly.net",
    "herokuapp.com", "vercel.app", "netlify.app", "pages.dev",
    "wordpress.com", "blogspot.com", "automattic.com"
]

# Assign a small score based on domain-brand similarity
def score_similarity(similarity_score: float) -> float:
    if similarity_score >= 0.90:
        return 1.0
    elif similarity_score >= 0.85:
        return 0.75
    elif similarity_score >= 0.80:
        return 0.5
    return 0.0

# Check if the domain matches known benign hosting/CDN services
def is_known_false_positive(domain):
    return any(pattern in domain.lower() for pattern in FALSE_POSITIVE_PATTERNS)

# Estimate domain age in days using WHOIS creation date
def domain_registration_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return -1
        return (datetime.now() - creation_date).days
    except Exception as e:
        print(f"[WARN] WHOIS lookup failed for {domain}: {e}")
        return -1

# Check if a domain has valid DNS A records (currently unused)
def has_valid_dns(domain):
    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except:
        return False

# Main scoring function to calculate phishing likelihood
def phishing_score(
    entropy: float,
    has_keyword: bool,
    tld_suspicious: bool,
    issuer: str,
    registration_days: int,
    similarity_score: float,
    cn_mismatch: bool,
    ocsp_missing: bool,
    short_lived: bool,
    brand_in_subdomain: bool
) -> float:
    score = 0.0

    # Add points based on entropy thresholds
    if entropy >= 3.7:
        score += 3
    elif entropy >= 3.4:
        score += 2
    elif entropy >= 3.1:
        score += 1

    # Keyword, TLD, and issuer-based adjustments
    if has_keyword:
        score += 2
    if tld_suspicious:
        score += 1
    if issuer in {"ZeroSSL", "Let's Encrypt", "Actalis S.p.A."}:
        score += 1
    if cn_mismatch:
        score += 1.5
    if ocsp_missing:
        score += 1.5
    if short_lived:
        score += 1.5
    if brand_in_subdomain:
        score += 1.0

    # Adjust score based on domain age
    if registration_days is not None:
        if registration_days < 14:
            score += 3
        elif registration_days < 60:
            score += 2
        elif registration_days < 180:
            score += 1

    # Add similarity bonus
    score += score_similarity(similarity_score)

    # Cap score at 10 and round
    return round(min(score, 10), 2)


def parse_time(ts: str) -> datetime | None:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
    except:
        return None


# Wrapper function to extract all features needed for scoring
def extract_features(domain: str, issuer: str, registration_days: int, similarity_score: float, cert: dict):
    tld = domain.split(".")[-1]
    tld_suspicious = tld in TLD_SUSPICIOUS
    has_keyword = contains_suspicious_word(domain)
    entropy = round(calculate_entropy(domain), 2)

    # --- CN mismatch detection ---
    subject = cert.get("subject", {})
    common_name = subject.get("CN")
    san = cert.get("all_domains", [])

    # Jeśli CN istnieje i nie ma go w SAN → potencjalna anomalia
    cn_mismatch = common_name not in san if common_name and san else False

    # --- OCSP / CRL presence check ---
    ocsp_urls = cert.get("ocsp_urls", [])
    crl_urls = cert.get("crl_distribution_points", [])
    ocsp_missing = not ocsp_urls and not crl_urls

    # --- Short-lived cert detection ---
    not_before = cert.get("not_before")
    not_after = cert.get("not_after")
    short_lived = False
    try:
        if not_before and not_after:
            # Zamiana na datetime i różnica
            not_before_dt = datetime.datetime.utcfromtimestamp(not_before)
            not_after_dt = datetime.datetime.utcfromtimestamp(not_after)
            lifetime_days = (not_after_dt - not_before_dt).days
            short_lived = lifetime_days <= 14
    except Exception:
        pass  # Jeśli coś poszło nie tak, nie traktujemy jako short-lived

    brand_in_subdomain, subdomain_brand = has_brand_in_subdomain(domain)

    score = phishing_score(
        entropy, has_keyword, tld_suspicious, issuer, registration_days,
        similarity_score, cn_mismatch, ocsp_missing, short_lived, brand_in_subdomain
    )

    return (
        tld, tld_suspicious, has_keyword, entropy,
        cn_mismatch, ocsp_missing, short_lived,
        brand_in_subdomain, score
    )