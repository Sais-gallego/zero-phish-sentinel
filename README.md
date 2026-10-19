# 🛡️ ZeroPhish-Sentinel

[![CI Pipeline](https://github.com/Sais-gallego/zero-phish-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Sais-gallego/zero-phish-sentinel/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Security: MITRE ATT&CK](https://img.shields.io/badge/Security-MITRE%20ATT%26CK%20Aligned-red.svg)](https://attack.mitre.org/)

> **High-Performance Heuristic, Lexical & Entropy-Based Anti-Phishing Analysis Engine.**  
> Detects credential harvesting, homograph spoofing, domain generation algorithms (DGA), typosquatting, and brand impersonation in real time without external telemetry delays.

---

## ⚡ Key Capabilities

- **Shannon Entropy Analysis**: Measures character distribution entropy across domain levels and URL paths to identify algorithmic domain generation (DGA) and obfuscated redirectors.
- **Punycode & Homograph Detection**: Identifies internationalized domain names (IDN) and mixed Cyrillic/Greek script attacks masquerading as Latin characters (e.g. `xn--pple-43d.com`).
- **Targeted Typosquatting Engine**: Detects visual character substitutions (leet-speak like `0` for `o`, `1` for `l`) and Levenshtein edit distances targeting 20+ major financial and tech brands.
- **Lexical Lure Extraction**: Discovers suspicious authentication lures, token verification paths, and embedded credential tricks (`user:pass@host`).
- **Defanged Evidence Output**: Automatically formats malicious indicators as defanged strings (`hxxps://target[.]xyz`) to safeguard security teams during triage.
- **MITRE ATT&CK Mapping**: Every threat signal is mapped directly to standard threat techniques (`T1566.002`, `T1036.007`, `T1568.002`).

---

## 📐 Architecture Overview

```
             ┌─────────────────────────┐
             │       Target URL        │
             └────────────┬────────────┘
                          │
         ┌────────────────┴────────────────┐
         ▼                                 ▼
┌──────────────────┐             ┌──────────────────┐
│ Lexical & Host   │             │ Shannon Entropy  │
│  - IP Hostname   │             │  - Domain Depth  │
│  - Punycode/IDN  │             │  - Subdomain DGA │
│  - Brand Typos   │             │  - Path & Query  │
└────────┬─────────┘             └─────────┬────────┘
         │                                 │
         └────────────────┬────────────────┘
                          ▼
            ┌───────────────────────────┐
            │   Heuristic Score Engine  │
            │     (Weights 0 to 100)    │
            └─────────────┬─────────────┘
                          │
         ┌────────────────┼────────────────┐
         ▼                ▼                ▼
    🟢 [SAFE]      🟡 [SUSPICIOUS]   🚨 [PHISHING]
   Score: 0-24       Score: 25-44      Score: 70-100
```

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/Sais-gallego/zero-phish-sentinel.git
cd zero-phish-sentinel
pip install -r requirements.txt
pip install .
```

### CLI Usage

**Single URL Scan:**
```bash
zerophish "https://paypa1-security-verification.xyz/update-account"
```

**Output:**
```
============================================================
  ZeroPhish-Sentinel: Malicious URL Analysis Report
============================================================
 Target URL     : hxxps://paypa1-security-verification[.]xyz/update-account
 Hostname       : paypa1-security-verification.xyz
 Threat Score   : 85/100
 Classification : 🚨 [PHISHING MALICIOUS]
 Domain Entropy : 4.1287 bits
 Total Entropy  : 4.4921 bits

 Detected Threat Indicators:
   [!] Domain uses high-abuse top-level domain (.xyz)
   [!] Typosquatting/brand impersonation detected against: paypal
   [!] Multiple hyphens (2) in domain name
   [!] Phishing lure keywords identified: update, account

 MITRE ATT&CK Mapping:
   [-] T1036 - Masquerading
============================================================
```

**JSON Output:**
```bash
zerophish "https://suspicious-site.top/login" --json
```

**Batch Processing:**
```bash
zerophish --file targets.txt --json > results.json
```

---

## 🐍 Python SDK Integration

```python
from zerophish import PhishDetector, ThreatLevel

detector = PhishDetector()
result = detector.analyze("http://192.168.1.100/banking-login")

print(f"Risk Score : {result.threat_score}/100")
print(f"Level      : {result.threat_level.value}")
print(f"Indicators : {result.indicators}")
```

---

## 🧪 Testing

```bash
python -m unittest discover tests -v
```

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for details.
