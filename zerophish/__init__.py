"""
ZeroPhish-Sentinel: Advanced Anti-Phishing & Malicious URL Analysis Engine.
"""

__version__ = "1.0.0"
__author__ = "Sais-gallego"

from .detector import PhishDetector, URLAnalysisResult, ThreatLevel

__all__ = ["PhishDetector", "URLAnalysisResult", "ThreatLevel"]
