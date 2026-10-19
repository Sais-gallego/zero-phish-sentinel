import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
from .heuristics import (
    HIGH_RISK_TLDS,
    IPV4_PATTERN,
    SUSPICIOUS_KEYWORDS,
    calculate_entropy,
    check_typosquatting,
    defang_url,
    detect_punycode_homograph,
)


class ThreatLevel(str, Enum):
    SAFE = "SAFE"
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    PHISHING = "PHISHING"


@dataclass
class URLAnalysisResult:
    url: str
    defanged_url: str
    hostname: str
    domain_entropy: float
    total_entropy: float
    threat_score: int
    threat_level: ThreatLevel
    indicators: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "defanged_url": self.defanged_url,
            "hostname": self.hostname,
            "domain_entropy": self.domain_entropy,
            "total_entropy": self.total_entropy,
            "threat_score": self.threat_score,
            "threat_level": self.threat_level.value,
            "indicators": self.indicators,
            "mitre_techniques": self.mitre_techniques,
        }


class PhishDetector:
    """
    Advanced heuristic and lexical anti-phishing detection engine.
    """

    def __init__(self, risk_threshold: int = 50):
        self.risk_threshold = risk_threshold

    def analyze(self, raw_url: str) -> URLAnalysisResult:
        normalized_url = raw_url.strip()
        if not normalized_url.startswith(("http://", "https://")):
            normalized_url = "http://" + normalized_url

        parsed = urllib.parse.urlparse(normalized_url)
        hostname = (parsed.hostname or "").lower()
        path_and_query = f"{parsed.path}?{parsed.query}".lower()

        score = 0
        indicators: List[str] = []
        mitre_techniques: List[str] = []

        domain_entropy = calculate_entropy(hostname)
        total_entropy = calculate_entropy(normalized_url)

        # 1. IP Address as Hostname
        if IPV4_PATTERN.match(hostname):
            score += 35
            indicators.append("Direct IP address used as hostname (no verified domain name)")
            mitre_techniques.append("T1566.002 - Spearphishing Link")

        # 2. Punycode / Homograph Attack
        if detect_punycode_homograph(hostname):
            score += 40
            indicators.append("Punycode (IDN) or non-ASCII characters detected; potential homograph spoofing")
            mitre_techniques.append("T1036.007 - Masquerading: Double File Extension or Homoglyph")

        # 3. High-Risk TLD
        tld = hostname.split(".")[-1] if "." in hostname else ""
        if tld in HIGH_RISK_TLDS:
            score += 25
            indicators.append(f"Domain uses high-abuse top-level domain (.{tld})")

        # 4. Brand Typosquatting
        is_typo, brands = check_typosquatting(hostname)
        if is_typo:
            score += 40
            indicators.append(f"Typosquatting/brand impersonation detected against: {', '.join(brands)}")
            mitre_techniques.append("T1036 - Masquerading")

        # 5. Excessive Subdomains (Domain shadowing / DGA proxy)
        subdomains = [s for s in hostname.split(".") if s and s != "www"]
        if len(subdomains) > 3:
            score += 20
            indicators.append(f"Excessive subdomain depth ({len(subdomains)} levels)")

        # 6. Domain Entropy
        if domain_entropy > 4.1:
            score += 25
            indicators.append(f"High domain character entropy ({domain_entropy:.2f} bits); possible DGA")
            mitre_techniques.append("T1568.002 - Dynamic Resolution: Domain Generation Algorithms")
        elif domain_entropy > 3.7:
            score += 10
            indicators.append(f"Elevated domain entropy ({domain_entropy:.2f} bits)")

        # 7. URL Credential Trick (@ symbol)
        if "@" in parsed.netloc:
            score += 45
            indicators.append("Embedded credentials (@ symbol in authority) detected")

        # 8. Suspicious Hyphens in Domain
        if hostname.count("-") >= 2:
            score += 15
            indicators.append(f"Multiple hyphens ({hostname.count('-')}) in domain name")

        # 9. Suspicious Security/Auth Keywords
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path_and_query or kw in hostname]
        if found_keywords:
            weight = min(len(found_keywords) * 10, 30)
            score += weight
            indicators.append(f"Phishing lure keywords identified: {', '.join(found_keywords[:5])}")

        # 10. Excessive Length
        if len(normalized_url) > 130:
            score += 15
            indicators.append(f"Excessive URL length ({len(normalized_url)} characters)")

        # Normalize score capped at 100
        threat_score = min(score, 100)

        # Categorize threat level
        if threat_score >= 70:
            threat_level = ThreatLevel.PHISHING
        elif threat_score >= 45:
            threat_level = ThreatLevel.HIGH_RISK
        elif threat_score >= 25:
            threat_level = ThreatLevel.SUSPICIOUS
        elif threat_score >= 10:
            threat_level = ThreatLevel.LOW_RISK
        else:
            threat_level = ThreatLevel.SAFE

        return URLAnalysisResult(
            url=raw_url,
            defanged_url=defang_url(raw_url),
            hostname=hostname,
            domain_entropy=domain_entropy,
            total_entropy=total_entropy,
            threat_score=threat_score,
            threat_level=threat_level,
            indicators=indicators,
            mitre_techniques=list(set(mitre_techniques)),
        )
