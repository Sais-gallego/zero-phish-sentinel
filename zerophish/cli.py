import argparse
import json
import sys
from .detector import PhishDetector, ThreatLevel


def format_cli_output(result) -> str:
    level_icons = {
        ThreatLevel.SAFE: "🟢 [SAFE]",
        ThreatLevel.LOW_RISK: "🟡 [LOW RISK]",
        ThreatLevel.SUSPICIOUS: "🟠 [SUSPICIOUS]",
        ThreatLevel.HIGH_RISK: "🔴 [HIGH RISK]",
        ThreatLevel.PHISHING: "🚨 [PHISHING MALICIOUS]",
    }
    lines = [
        "=" * 60,
        "  ZeroPhish-Sentinel: Malicious URL Analysis Report",
        "=" * 60,
        f" Target URL     : {result.defanged_url}",
        f" Hostname       : {result.hostname}",
        f" Threat Score   : {result.threat_score}/100",
        f" Classification : {level_icons.get(result.threat_level, str(result.threat_level))}",
        f" Domain Entropy : {result.domain_entropy:.4f} bits",
        f" Total Entropy  : {result.total_entropy:.4f} bits",
    ]
    if result.indicators:
        lines.append("\n Detected Threat Indicators:")
        for ind in result.indicators:
            lines.append(f"   [!] {ind}")
    if result.mitre_techniques:
        lines.append("\n MITRE ATT&CK Mapping:")
        for m in result.mitre_techniques:
            lines.append(f"   [-] {m}")
    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="ZeroPhish-Sentinel CLI")
    parser.add_argument("url", nargs="?", help="URL to analyze for phishing/malware indicators")
    parser.add_argument("--json", action="store_true", help="Output raw JSON data")
    parser.add_argument("--file", "-f", help="Scan URLs from a text file (one URL per line)")
    args = parser.parse_args()

    detector = PhishDetector()

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading file {args.file}: {e}", file=sys.stderr)
            sys.exit(1)

        results = [detector.analyze(u).to_dict() for u in urls]
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            for u in urls:
                res = detector.analyze(u)
                print(format_cli_output(res))
                print()
        sys.exit(0)

    if not args.url:
        parser.print_help()
        sys.exit(1)

    result = detector.analyze(args.url)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(format_cli_output(result))

    if result.threat_score >= 50:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
