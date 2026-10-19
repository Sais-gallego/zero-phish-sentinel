import unittest
from zerophish.detector import PhishDetector, ThreatLevel
from zerophish.heuristics import calculate_entropy, levenshtein_distance, defang_url


class TestZeroPhishSentinel(unittest.TestCase):
    def setUp(self):
        self.detector = PhishDetector()

    def test_benign_urls(self):
        benign_samples = [
            "https://www.google.com",
            "https://github.com/Sais-gallego",
            "https://en.wikipedia.org/wiki/Computer_security",
        ]
        for url in benign_samples:
            res = self.detector.analyze(url)
            self.assertIn(res.threat_level, [ThreatLevel.SAFE, ThreatLevel.LOW_RISK])
            self.assertLess(res.threat_score, 30)

    def test_direct_ip_detection(self):
        url = "http://192.168.1.100/login/verify-account"
        res = self.detector.analyze(url)
        self.assertGreaterEqual(res.threat_score, 45)
        self.assertTrue(any("Direct IP address" in ind for ind in res.indicators))

    def test_typosquatting_detection(self):
        url = "https://paypa1-security-verification.xyz/update"
        res = self.detector.analyze(url)
        self.assertIn(res.threat_level, [ThreatLevel.HIGH_RISK, ThreatLevel.PHISHING])
        self.assertTrue(any("Typosquatting" in ind for ind in res.indicators))
        self.assertTrue(any("high-abuse" in ind for ind in res.indicators))

    def test_punycode_homograph_detection(self):
        url = "https://xn--pple-43d.com/login"
        res = self.detector.analyze(url)
        self.assertTrue(any("Punycode" in ind for ind in res.indicators))

    def test_entropy_and_defang(self):
        entropy = calculate_entropy("aquickbrownfox")
        self.assertGreater(entropy, 2.0)
        defanged = defang_url("https://malicious.example.com/payload")
        self.assertIn("hxxps://", defanged)
        self.assertIn("[.]", defanged)

    def test_to_dict_structure(self):
        res = self.detector.analyze("https://github.com")
        d = res.to_dict()
        self.assertEqual(d["hostname"], "github.com")
        self.assertIn("threat_score", d)
        self.assertIn("threat_level", d)


if __name__ == "__main__":
    unittest.main()
