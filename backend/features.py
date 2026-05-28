"""
Feature Extraction Module for Malicious URL Detection
Implements Contextual Brand Impersonation Detection, Typosquatting, Homoglyphs and Structural Analysis.
"""

import re
import math
from urllib.parse import urlparse
from collections import Counter
import tldextract

try:
    from Levenshtein import distance as levenshtein_distance
except ImportError:
    def levenshtein_distance(s1, s2):
        if len(s1) < len(s2): return levenshtein_distance(s2, s1)
        if len(s2) == 0: return len(s1)
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(prev[j] if c1 == c2 else min(prev[j], prev[j + 1], curr[-1]) + 1)
            prev = curr
        return prev[-1]

TRUSTED_BRANDS = [
    "google", "paypal", "microsoft", "amazon", "facebook", "apple", "github", "openai",
    "kaggle", "youtube", "twitter", "linkedin", "netflix", "instagram", "reddit",
    "stackoverflow", "wikipedia", "python", "tensorflow", "pytorch"
]

OFFICIAL_DOMAINS = {
    "google":        ["google.com", "google.co.uk", "google.ca", "google.com.eg"],
    "paypal":        ["paypal.com", "paypal.co.uk"],
    "microsoft":     ["microsoft.com", "live.com", "office.com", "azure.com", "outlook.com"],
    "amazon":        ["amazon.com", "amazon.co.uk", "amazon.com.eg", "aws.amazon.com"],
    "facebook":      ["facebook.com", "fb.com", "instagram.com"],
    "apple":         ["apple.com", "icloud.com"],
    "github":        ["github.com", "github.io"],
    "openai":        ["openai.com", "chatgpt.com"],
    "kaggle":        ["kaggle.com"],
    "youtube":       ["youtube.com", "youtu.be"],
    "twitter":       ["twitter.com", "x.com", "t.co"],
    "linkedin":      ["linkedin.com"],
    "netflix":       ["netflix.com"],
    "reddit":        ["reddit.com", "redd.it"],
    "stackoverflow": ["stackoverflow.com", "stackexchange.com"],
    "wikipedia":     ["wikipedia.org", "wikimedia.org"],
    "python":        ["python.org", "pypi.org"],
    "tensorflow":    ["tensorflow.org"],
    "pytorch":       ["pytorch.org"],
}

# Flat set of ALL official root domains for fast lookup
OFFICIAL_WHITELIST = {
    domain
    for domains in OFFICIAL_DOMAINS.values()
    for domain in domains
}

# Class-Specific Indicators

# --- Malware Features ---
MALWARE_EXTENSIONS = [
    '.exe', '.apk', '.scr', '.bat', '.dll', '.bin', '.zip', '.rar', '.msi'
]

PAYLOAD_KEYWORDS = [
    'download', 'setup', 'install', 'update', 'patch', 'crack'
]

CMD_PATTERNS = [
    'cmd=', 'exec=', 'system=', 'shell=', 'wget', 'curl'
]

# --- Phishing Features ---
BRAND_NAMES = [
    'paypal', 'facebook', 'google', 'apple', 'microsoft', 'amazon', 'netflix', 'github'
]

PHISHING_PATHS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update', 'billing', 'auth', 'recover'
]

# --- Defacement Features ---
HACK_KEYWORDS = [
    'hacked', 'defaced', 'owned', 'pwned', 'anonymous', 'team', 'hacker'
]

SQLI_PATTERNS = [
    'union select', 'or 1=1', "'--", 'index.php?id='
]

# Shorteners & TLDs
SHORTENING_SERVICES = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'cli.gs', 'yfrog.com', 
    'migre.me', 'ff.im', 'url4.eu', 'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com',
    'short.to', 'BudURL.com', 'ping.fm', 'post.ly', 'Just.as', 'bkite.com',
    'snipr.com', 'fic.kr', 'loopt.us', 'doiop.com', 'short.ie', 'kl.am', 'wp.me',
    'rubyurl.com', 'om.ly', 'to.ly', 'bit.do', 't2m.io', 'lnkd.in', 'db.tt', 
    'qr.ae', 'adf.ly', 'bitly.com', 'cur.lv', 'ow.ly', 'ity.im', 'q.gs'
]

SUSPICIOUS_TLDS = [
    'xyz', 'top', 'pw', 'cc', 'tk', 'ml', 'ga', 'cf', 'gq', 'info', 'site', 
    'click', 'link', 'icu', 'vip', 'buzz', 'work', 'wang', 'fit', 'fun', 'cam', 'online'
]

FEATURE_NAMES = [
    'has_malware_extension',
    'has_payload_keyword',
    'has_command_pattern',
    'has_brand_impersonation',
    'has_auth_path',
    'has_defacement_signature',
    'has_sqli_pattern',
    'url_entropy',
    
    # Keeping strong structural baselines to support the tree model
    'url_length',
    'num_dots',
    'num_digits',
    'num_hyphens',
    'num_slashes',
    'num_subdomains',
    'has_ip_address',
    'num_special_chars',
    'path_length',
    'domain_length',
    'num_uppercase',
    'digit_to_length_ratio',
    'tld_length',
    'num_query_params',
    'has_port',
    'subdomain_depth',
    'domain_entropy',
    'subdomain_entropy',
    'is_shortened',
    'has_suspicious_tld',
    'vowel_consonant_ratio',
    'dash_ratio',
    'is_typosquatted',
    'homoglyph_detected'
]


def _compute_entropy(text):
    if not text: return 0.0
    freq = Counter(text)
    total = len(text)
    return round(-sum((c / total) * math.log2(c / total) for c in freq.values()), 4)

def _detect_homoglyphs(text):
    return int(any(ord(c) > 127 for c in text))

def _has_ip_address(url):
    ip_pattern = re.compile(r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)')
    return int(bool(ip_pattern.search(url)))

def extract_features(url):
    # Strip protocol for unbiased feature extraction
    clean_url = re.sub(r'^https?://', '', url)
    url_to_parse = 'http://' + clean_url

    try:
        parsed = urlparse(url_to_parse)
    except Exception:
        parsed = urlparse('http://invalid.url')

    # Advanced Extraction via tldextract
    ext = tldextract.extract(clean_url)
    subdomain = ext.subdomain.lower()
    domain = ext.domain.lower()
    suffix = ext.suffix.lower()
    root_domain = f"{domain}.{suffix}" if suffix else domain
    hostname = parsed.hostname or root_domain

    path = parsed.path.lower() or ''
    query = parsed.query.lower() or ''
    url_lower = clean_url.lower()

    # --- Class-Specific Feature Extraction ---
    # 1. Malware
    has_malware_extension = int(any(ext in url_lower for ext in MALWARE_EXTENSIONS))
    has_payload_keyword = int(any(word in url_lower for word in PAYLOAD_KEYWORDS))
    has_command_pattern = int(any(p in url_lower for p in CMD_PATTERNS))
    
    # 2. Phishing
    has_brand_impersonation = int(any(b in url_lower for b in BRAND_NAMES))
    has_auth_path = int(any(p in url_lower for p in PHISHING_PATHS))
    
    # 3. Defacement
    has_defacement_signature = int(any(k in url_lower for k in HACK_KEYWORDS))
    has_sqli_pattern = int(any(p in url_lower for p in SQLI_PATTERNS))

    # 4. Anti-overlap Entropy
    entropy = _compute_entropy(clean_url)
    domain_entropy = _compute_entropy(hostname)
    subdomain_entropy = _compute_entropy(subdomain)

    # 5. Structural Baselines (keeping for robustness)
    url_length = len(clean_url)
    num_dots = clean_url.count('.')
    num_digits = sum(c.isdigit() for c in clean_url)
    num_hyphens = clean_url.count('-')
    num_slashes = clean_url.count('/')
    has_ip = _has_ip_address(clean_url)

    num_subdomains = len(subdomain.split('.')) if subdomain else 0
    subdomain_depth = max(0, num_subdomains)

    special_chars = set('@?=&%!#$^*()[]{}|\\<>')
    num_special = sum(c in special_chars for c in clean_url)
    
    path_length = len(path)
    domain_length = len(hostname)

    num_uppercase = sum(c.isupper() for c in clean_url)
    digit_ratio = num_digits / url_length if url_length > 0 else 0
    tld_length = len(suffix)
    num_query_params = len(query.split('&')) if query else 0
    
    try:
        has_port = int(bool(parsed.port))
    except ValueError:
        has_port = 0

    dash_ratio = round(num_hyphens / url_length, 4) if url_length > 0 else 0
    is_shortened = int(any(short in hostname for short in SHORTENING_SERVICES))
    has_suspicious_tld = int(suffix in SUSPICIOUS_TLDS)

    vowels = sum(1 for c in url_lower if c in 'aeiou')
    consonants = sum(1 for c in url_lower if c.isalpha() and c not in 'aeiou')
    vowel_consonant_ratio = round(vowels / consonants, 4) if consonants > 0 else 0
    
    homoglyph_detected = _detect_homoglyphs(domain)
    
    # Simplified Typosquatting (retained from old code but refactored to fit)
    is_typosquatted = 0
    if root_domain not in OFFICIAL_WHITELIST:
        typo_distance = 100
        for brand in BRAND_NAMES:
            dist = levenshtein_distance(domain, brand)
            if dist < typo_distance:
                typo_distance = dist
        is_typosquatted = 1 if (0 < typo_distance <= 2) else 0

    feature_vector = [
        has_malware_extension,
        has_payload_keyword,
        has_command_pattern,
        has_brand_impersonation,
        has_auth_path,
        has_defacement_signature,
        has_sqli_pattern,
        entropy,
        url_length,
        num_dots,
        num_digits,
        num_hyphens,
        num_slashes,
        num_subdomains,
        has_ip,
        num_special,
        path_length,
        domain_length,
        num_uppercase,
        round(digit_ratio, 4),
        tld_length,
        num_query_params,
        has_port,
        subdomain_depth,
        domain_entropy,
        subdomain_entropy,
        is_shortened,
        has_suspicious_tld,
        vowel_consonant_ratio,
        dash_ratio,
        is_typosquatted,
        homoglyph_detected
    ]

    return feature_vector, dict(zip(FEATURE_NAMES, feature_vector))

def get_feature_names():
    return FEATURE_NAMES.copy()
