import math
import re
from typing import Dict, List, Tuple

# High-risk TLDs often abused in phishing and malware distribution campaigns
HIGH_RISK_TLDS = {
    "xyz", "top", "buzz", "club", "work", "loan", "tk", "ml", "ga", "cf", "gq",
    "country", "stream", "gdn", "mom", "bid", "racing", "win", "icu", "cam", "fit"
}

# Targeted financial, tech and identity brands
TARGET_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook", "netflix",
    "instagram", "chase", "bankofamerica", "wellsfargo", "binance", "coinbase",
    "metamask", "github", "linkedin", "dropbox", "adobe", "whatsapp", "twitter"
]

# Sensitive credentials & security action keywords
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security", "account",
    "update", "banking", "wallet", "checkpoint", "confirm", "recovery", "password",
    "credential", "suspend", "reactivate", "support", "billing", "invoice", "authorize"
]

IPV4_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for a given string."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate minimum edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


LEET_MAP = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "$": "s"
})

def normalize_leet(text: str) -> str:
    """Normalize common leet-speak characters back to standard Latin."""
    return text.translate(LEET_MAP)

def check_typosquatting(domain: str) -> Tuple[bool, List[str]]:
    """Detect if a domain mimics a well-known brand via edit distance, leet-speak, or token similarity."""
    clean_domain = domain.lower().split(":")[0]
    labels = clean_domain.split(".")
    domain_body = labels[-2] if len(labels) >= 2 else labels[0]
    tokens = domain_body.split("-")

    # If domain_body is exactly the brand name (e.g., google.com, paypal.com), it's the official brand domain
    if domain_body in TARGET_BRANDS:
        return (False, [])

    detected_targets = set()
    for token in tokens:
        if not token or len(token) < 3:
            continue
        norm_token = normalize_leet(token)
        for brand in TARGET_BRANDS:
            # Exact brand token embedded in a hyphenated composite (e.g., paypal-update, security-google)
            if token == brand or norm_token == brand:
                detected_targets.add(brand)
                continue
            dist_raw = levenshtein_distance(token, brand)
            dist_norm = levenshtein_distance(norm_token, brand)
            if (1 <= dist_raw <= 1 or 1 <= dist_norm <= 1) and len(token) >= 4:
                detected_targets.add(brand)

    return (len(detected_targets) > 0, sorted(list(detected_targets)))




def detect_punycode_homograph(hostname: str) -> bool:
    """Check if the hostname uses punycode or mixed cyrillic/greek script."""
    if "xn--" in hostname.lower():
        return True
    try:
        hostname.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True


def defang_url(url: str) -> str:
    """Defang a malicious URL to prevent accidental clicks."""
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    defanged = defanged.replace(".", "[.]")
    return defanged
