#certstream/phishing_detect.py

from rapidfuzz.fuzz import ratio # Faster alternative to Levenshtein for string similarity
from collections import Counter
import os, dns.resolver, math
from datetime import datetime
from utils.who_is import domain_registration_age

# Loads brand domain names from a file for use in similarity and impersonation checks
def load_brand_domains(filepath=None):
    if filepath is None:
        base_dir = os.path.dirname(os.path.dirname(__file__)) # go to root
        filepath = os.path.join(base_dir, "data", "websites.txt")

    with open(filepath, "r") as f:
        return [line.strip() for line in f if line.strip()]

# List of top brands (e.g., google.com, paypal.com)
BRAND_DOMAINS = load_brand_domains()

# Checks if a known brand name appears in the subdomain part (e.g., paypal.security-login.com)
def has_brand_in_subdomain(domain: str) -> (bool, str):
    parts = domain.lower().split(".")
    if len(parts) < 3:
        return False, None  # No subdomain present

    subdomain_parts = parts[:-2]  # Drop root domain and TLD
    subdomain = ".".join(subdomain_parts)

    for brand in BRAND_DOMAINS:
        if brand.lower() in subdomain:
            return True, brand
    return False, None

# Checks for similarity to known brands using string similarity (e.g., gooogle.com vs google.com)
def is_similar(domain, threshold=0.8):
    for brand in BRAND_DOMAINS:
        dist = ratio(domain.lower(), brand.lower()) / 100.0
        if dist >= threshold and domain.lower() != brand.lower():
            if is_known_false_positive(domain):
                return False, None, None # Legitimate but similar domain (e.g., AWS)
            return True, brand, dist
    return False, None, None

# Looks for keywords commonly found in phishing (e.g., 'login', 'account', 'verify')
def contains_suspicious_word(domain):
    suspicious_words = {
        "login", "verify", "secure", "update", "account", "signin",
        "password", "auth", "bank", "pay", "confirm", "reset", "validate",
        "webmail", "support", "unlock", "user", "invoice"
    }
    return any(word in domain.lower() for word in suspicious_words)

# Measures randomness in domain name using Shannon entropy — useful for detecting DGA
def calculate_entropy(s):
    p, lns = Counter(s), float(len(s))
    return -sum(count / lns * math.log2(count / lns) for count in p.values())

# Set of TLDs known to be frequently abused in phishing (e.g., .xyz, .buzz, .icu)
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

# List of known AWS S3 endpoints to suppress false alerts
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

# Additional benign patterns used by CDNs, blogs, static sites etc.
FALSE_POSITIVE_PATTERNS = [
     *AWS_DOMAINS, "s3.amazonaws.com", "cloudfront.net", "github.io", "gitlab.io",
    "firebaseapp.com", "azurewebsites.net", "fastly.net",
    "herokuapp.com", "vercel.app", "netlify.app", "pages.dev",
    "wordpress.com", "blogspot.com", "automattic.com"
]

# Converts similarity score to phishing points
def score_similarity(similarity_score: float) -> float:
    if similarity_score >= 0.90:
        return 2.0
    elif similarity_score >= 0.85:
        return 1.5
    elif similarity_score >= 0.80:
        return 1
    return 0.0

# Checks if a domain is a known benign false positive
def is_known_false_positive(domain):
    return any(pattern in domain.lower() for pattern in FALSE_POSITIVE_PATTERNS)

# Verifies if DNS A records are resolvable (not used but useful for future DNS integrity checks)
def has_valid_dns(domain):
    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except:
        return False

# Core phishing score function — accumulates heuristic points based on domain features
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

    # Higher entropy = higher suspicion
    if entropy >= 3.6:
        score += 1.5
    elif entropy >= 3.2:
        score += 1
    elif entropy >= 2.8:
        score += 0.5

    if has_keyword:
        score += 1

    if tld_suspicious:
        score += 1

    # Free CAs are common in phishing due to ease of issuance,
    # but we only penalize them when combined with other red flags.
    if issuer in {"ZeroSSL", "Let's Encrypt", "Actalis S.p.A."} :
        score += 1

    if cn_mismatch:
        score += 1

    if ocsp_missing:
        score += 1

    if short_lived:
        score += 1

    if brand_in_subdomain:
        score += 1

    # Recent domains are riskier
    if registration_days is not None and registration_days >= 0:
        if registration_days < 30:
            score += 3
        elif registration_days < 90:
            score += 2
        elif registration_days < 360:
            score += 1

    # Add similarity bonus
    score += score_similarity(similarity_score)

    return min(score, 10) #max 10 points

# Converts timestamp string to datetime object; returns None if malformed
def parse_time(ts: str) -> datetime | None:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
    except:
        return None


# Extracts all features needed for phishing score calculation for a given domain
def extract_features(domain: str, issuer: str, registration_days: int, similarity_score: float, cert: dict):
    tld = domain.split(".")[-1]
    tld_suspicious = tld in TLD_SUSPICIOUS
    has_keyword = contains_suspicious_word(domain)
    entropy = round(calculate_entropy(domain), 2)

    # -- CN mismatch detection --
    def normalize_domain(d):
        return d.lower().replace("*.", "")

    subject = cert.get("subject", {})
    if isinstance(subject, list):
        subject = subject[0] if subject else {}

    common_name = subject.get("CN", "")

    # Pobierz SAN
    san = []
    extensions = cert.get("extensions", {})
    if "subjectAltName" in extensions:
        san_raw = extensions["subjectAltName"]
        if isinstance(san_raw, str):
            san = [d.strip() for d in san_raw.split(",") if "DNS:" in d]
            san = [d.replace("DNS:", "").strip() for d in san]
        elif isinstance(san_raw, list):
            san = [d.replace("DNS:", "").strip() for d in san_raw if "DNS:" in str(d)]

    # Sprawdź czy CN pasuje do którejkolwiek z domen SAN (uwzględniając wildcardy)
    cn_mismatch = True
    if common_name:
        cn_normalized = normalize_domain(common_name)
        for d in san:
            if normalize_domain(d) == cn_normalized:
                cn_mismatch = False
                break
            if d.startswith("*.") and cn_normalized.endswith(normalize_domain(d)):
                cn_mismatch = False
                break
    else:
        cn_mismatch = False

    # --- OCSP / CRL presence check ---
    extensions = cert.get("extensions", {})
    ocsp_urls = [extensions.get("authorityInfoAccess")] if "authorityInfoAccess" in extensions else []
    crl_urls = [extensions.get("crlDistributionPoints")] if "crlDistributionPoints" in extensions else []
    ocsp_missing = not any("ocsp" in str(url).lower() for url in ocsp_urls) and not crl_urls

    # -- Check certificate validity period --
    not_before = cert.get("not_before")
    not_after = cert.get("not_after")
    short_lived = False

    try:
        if not_before and not_after:
             # Konwersja na timestamp jeśli to string
             if isinstance(not_before, str):
                 not_before_dt = datetime.strptime(not_before, "%Y-%m-%dT%H:%M:%S")
             else:
                 not_before_dt = datetime.fromtimestamp(not_before)

             if isinstance(not_after, str):
                 not_after_dt = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%S")
             else:
                 not_after_dt = datetime.fromtimestamp(not_after)

             # Oblicz pozostałe dni do wygaśnięcia
             remaining_days = (not_after_dt - datetime.now()).days
             short_lived = remaining_days <= 30  # Ustawienie progu na 30 dni
    except Exception as e:
        pass  # If dates are malformed, skip this feature

    brand_in_subdomain, subdomain_brand = has_brand_in_subdomain(domain)

    # Final phishing score aggregation
    score = phishing_score(
        entropy, has_keyword, tld_suspicious, issuer, registration_days,
        similarity_score, cn_mismatch, ocsp_missing, short_lived, brand_in_subdomain
    )

    return (
        tld, tld_suspicious, has_keyword, entropy,
        cn_mismatch, ocsp_missing, short_lived,
        brand_in_subdomain, score
    )


# def test_certificate_features():
#     """Test only certificate features detection (no scoring)"""
#     test_cases = [
#         {
#             "name": "Perfectly valid cert",
#             "cert": {
#                 "subject": {"CN": "example.com"},
#                 "extensions": {
#                     "subjectAltName": "DNS:example.com, DNS:*.example.com",
#                     "authorityInfoAccess": "OCSP - URI:http://ocsp.example.com",
#                     "crlDistributionPoints": "http://crl.example.com"
#                 },
#                 "not_before": "2023-01-01T00:00:00",
#                 "not_after": "2024-01-01T00:00:00"  # 1 year validity
#             },
#             "expected": {
#                 "cn_mismatch": False,
#                 "ocsp_missing": False,
#                 "short_lived": False
#             }
#         },
#         {
#             "name": "CN mismatch",
#             "cert": {
#                 "subject": {"CN": "real.com"},
#                 "extensions": {
#                     "subjectAltName": "DNS:fake.com",
#                     "authorityInfoAccess": "OCSP - URI:http://ocsp.example.com"
#                 },
#                 "not_before": "2023-01-01T00:00:00",
#                 "not_after": "2023-01-15T00:00:00"  # 14 days validity
#             },
#             "expected": {
#                 "cn_mismatch": True,
#                 "ocsp_missing": False,
#                 "short_lived": True
#             }
#         },
#         {
#             "name": "Missing OCSP/CRL",
#             "cert": {
#                 "subject": {"CN": "insecure.org"},
#                 "extensions": {
#                     "subjectAltName": "DNS:insecure.org"
#                 },  # Brak OCSP/CRL
#                 "not_before": 1672531200,  # Unix timestamp
#                 "not_after": 1675209600  # 30 days validity
#             },
#             "expected": {
#                 "cn_mismatch": False,
#                 "ocsp_missing": True,
#                 "short_lived": False
#             }
#         }
#     ]
#
#     print("\nTesting certificate features detection:")
#     for case in test_cases:
#         print(f"\nTest: {case['name']}")
#         print(f"Cert data: {case['cert']}")
#
#         # Używamy pustej domeny i domyślnych wartości, skupiamy się tylko na certyfikacie
#         _, _, _, _, cn_mismatch, ocsp_missing, short_lived, _, _ = extract_features(
#             domain="test.com",
#             issuer="Test CA",
#             registration_days=100,
#             similarity_score=0,
#             cert=case["cert"]
#         )
#
#         print(f"Results: cn_mismatch={cn_mismatch}, ocsp_missing={ocsp_missing}, short_lived={short_lived}")
#
#         assert cn_mismatch == case["expected"]["cn_mismatch"], f"CN mismatch failed for {case['name']}"
#         assert ocsp_missing == case["expected"]["ocsp_missing"], f"OCSP check failed for {case['name']}"
#         assert short_lived == case["expected"]["short_lived"], f"Certificate lifetime check failed for {case['name']}"
#         print("✓ Passed")
#
#

#
# def test_cn_mismatch_detection():
#     """Test różnych przypadków CN mismatch"""
#     test_cases = [
#         {
#             "name": "Wildcard match 1",
#             "cert": {
#                 "subject": {"CN": "sub.example.com"},
#                 "extensions": {"subjectAltName": "DNS:*.example.com"}
#             },
#             "expected": False
#         },
#         {
#             "name": "Wildcard match 2",
#             "cert": {
#                 "subject": {"CN": "example.com"},
#                 "extensions": {"subjectAltName": "DNS:*.example.com"}
#             },
#             "expected": False
#         },
#         {
#             "name": "Wildcard mismatch",
#             "cert": {
#                 "subject": {"CN": "evil.com"},
#                 "extensions": {"subjectAltName": "DNS:*.example.com"}
#             },
#             "expected": True
#         }
#     ]
#
#     print("\nTesting CN mismatch with wildcards:")
#     for case in test_cases:
#         _, _, _, _, cn_mismatch, _, _, _, _ = extract_features(
#             domain="test.com",
#             issuer="Test CA",
#             registration_days=100,
#             similarity_score=0,
#             cert=case["cert"]
#         )
#         result = "MISMATCH" if cn_mismatch else "MATCH"
#         print(f"{case['name']}: {result} (expected: {'MISMATCH' if case['expected'] else 'MATCH'})")
#         assert cn_mismatch == case["expected"], f"Failed: {case['name']}"
# if __name__ == "__main__":
#     test_cn_mismatch_detection()
    #     test_certificate_features()

