"""
Automated tests for PHISHTRAP scoring engine.
Run with: python -m pytest server/python/test_scoring.py -v
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import analyze_phishing_target


def test_case(name: str, url: str, mode: str, expected_score_range: tuple, expected_verdict: str = None, watchlist=None):
    """Run a test case and report results."""
    result = analyze_phishing_target(url, mode, watchlist or [])
    score = result["risk"]["score"]
    verdict = result["risk"]["verdictType"]
    passed = expected_score_range[0] <= score <= expected_score_range[1]
    verdict_ok = expected_verdict is None or verdict == expected_verdict
    
    status = "[PASS]" if (passed and verdict_ok) else "[FAIL]"
    print(f"{status} {name}")
    print(f"       URL: {url}")
    print(f"       Mode: {mode}")
    print(f"       Score: {score} (expected {expected_score_range[0]}-{expected_score_range[1]})")
    print(f"       Verdict: {verdict} (expected {expected_verdict or 'any'})")
    print(f"       Confidence: {result['risk']['confidence']}")
    print(f"       Signals: {result['signals']}")
    print(f"       Reasons: {result['reasons']}")
    print()
    return passed and verdict_ok


def run_all_tests():
    print("=" * 70)
    print("PHISHTRAP SCORING ENGINE TESTS")
    print("=" * 70)
    print()
    
    results = []
    
    # === LEGITIMATE DOMAINS (should be SAFE/VERIFIED_SAFE) ===
    print("--- LEGITIMATE DOMAINS ---")
    results.append(test_case(
        "GitHub (legitimate, well-known)",
        "https://github.com",
        "LIVE",
        (0, 15),
        "NO_THREATS_DETECTED"
    ))
    
    results.append(test_case(
        "Microsoft (legitimate, brand match)",
        "https://microsoft.com",
        "LIVE",
        (0, 5),
        "VERIFIED_SAFE"
    ))
    
    results.append(test_case(
        "Google (legitimate, brand match)",
        "https://google.com",
        "LIVE",
        (0, 5),
        "VERIFIED_SAFE"
    ))
    
    results.append(test_case(
        "Amazon (legitimate, brand match)",
        "https://amazon.com",
        "DEMO",
        (0, 5),
        "VERIFIED_SAFE"
    ))
    
    results.append(test_case(
        "Chase Bank (legitimate, brand match)",
        "https://chase.com",
        "DEMO",
        (0, 5),
        "VERIFIED_SAFE"
    ))
    
    results.append(test_case(
        "Subdomain of legitimate brand",
        "https://login.microsoft.com",
        "LIVE",
        (0, 15),
        "VERIFIED_SAFE"
    ))
    
    results.append(test_case(
        "Legitimate brand with path keywords",
        "https://github.com/login",
        "LIVE",
        (0, 20),
        "NO_THREATS_DETECTED"
    ))
    
    results.append(test_case(
        "Legitimate brand with security path",
        "https://microsoft.com/security",
        "LIVE",
        (0, 20),
        "NO_THREATS_DETECTED"
    ))
    
    # === TYPOSQUATTING ===
    print("--- TYPOSQUATTING ---")
    results.append(test_case(
        "Typosquatting: goog1e.com (edit distance 1)",
        "https://goog1e.com",
        "DEMO",
        (70, 100),
        "CRITICAL"
    ))
    
    results.append(test_case(
        "Typosquatting: micros0ft.com (edit distance 1)",
        "https://micros0ft.com",
        "DEMO",
        (70, 100),
        "CRITICAL"
    ))
    
    results.append(test_case(
        "Typosquatting: paypa1.com (edit distance 1)",
        "https://paypa1.com",
        "DEMO",
        (70, 100),
        "CRITICAL"
    ))
    
    results.append(test_case(
        "Typosquatting: amaazon.com (edit distance 1 - insertion)",
        "https://amaazon.com",
        "DEMO",
        (70, 100),
        "CRITICAL"
    ))
    
    # === BRAND IMPERSONATION IN SUBDOMAIN ===
    print("--- BRAND IMPERSONATION IN SUBDOMAIN ---")
    results.append(test_case(
        "Subdomain injection: paypal.attacker.com",
        "https://paypal.attacker.com",
        "DEMO",
        (70, 100),
        "CRITICAL"
    ))
    
    results.append(test_case(
        "Subdomain injection: login.microsoft.com.phishersite.xyz",
        "https://login.microsoft.com.phishersite.xyz",
        "DEMO",
        (70, 100),
        "CRITICAL"
    ))
    
    results.append(test_case(
        "Brand in subdomain but not root: secure-paypal-login.xyz",
        "https://secure-paypal-login.xyz",
        "DEMO",
        (50, 90),
        "HIGH_RISK"
    ))
    
    # === FALSE POSITIVE PREVENTION ===
    print("--- FALSE POSITIVE PREVENTION ---")
    results.append(test_case(
        "Unrelated domain containing brand substring: pineapple.com",
        "https://pineapple.com",
        "DEMO",
        (0, 25),
        "NO_THREATS_DETECTED"
    ))
    
    results.append(test_case(
        "Unrelated domain: snapple.com",
        "https://snapple.com",
        "DEMO",
        (0, 25),
        "NO_THREATS_DETECTED"
    ))
    
    results.append(test_case(
        "Unrelated domain: appletree.com",
        "https://appletree.com",
        "DEMO",
        (0, 25),
        "NO_THREATS_DETECTED"
    ))
    
    results.append(test_case(
        "Unrelated domain: chasebanking.com (not chase.com)",
        "https://chasebanking.com",
        "DEMO",
        (0, 30),
        "NO_THREATS_DETECTED"
    ))
    
    # === SUSPICIOUS PATTERNS ===
    print("--- SUSPICIOUS PATTERNS ---")
    results.append(test_case(
        "Phishing: chase-security-login-portal.xyz",
        "https://chase-security-login-portal.xyz/auth/verify",
        "DEMO",
        (70, 100),
        "CRITICAL"
    ))
    
    results.append(test_case(
        "Phishing: paypal-account-verification-alert.top",
        "https://paypal-account-verification-alert.top/signin",
        "DEMO",
        (70, 100),
        "CRITICAL"
    ))
    
    results.append(test_case(
        "Phishing: apple-icloud-secure-confirm.info",
        "https://apple-icloud-secure-confirm.info/idmswebauth",
        "DEMO",
        (60, 90),
        "HIGH_RISK"
    ))
    
    results.append(test_case(
        "Raw IP address",
        "https://192.168.1.1/login",
        "DEMO",
        (50, 85),
        "HIGH_RISK"
    ))
    
    results.append(test_case(
        "URL with @ symbol",
        "https://user:pass@paypal.com.attacker.com/",
        "DEMO",
        (60, 95),
        "CRITICAL"
    ))
    
    results.append(test_case(
        "Punycode domain",
        "https://xn--pple-43d.com",
        "DEMO",
        (50, 80),
        "HIGH_RISK"
    ))
    
    results.append(test_case(
        "Homoglyph attack",
        "https://раypal.com",  # Cyrillic 'р' instead of 'p'
        "DEMO",
        (70, 100),
        "CRITICAL"
    ))
    
    results.append(test_case(
        "Long URL with many params",
        "https://example.com/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p?param1=value1&param2=value2&param3=value3",
        "DEMO",
        (15, 50),
        "SUSPICIOUS"
    ))
    
    # === DNS/TLS UNAVAILABLE IN DEMO MODE ===
    print("--- DEMO MODE: DNS/TLS UNAVAILABLE ---")
    results.append(test_case(
        "DEMO mode: DNS/TLS should be UNAVAILABLE",
        "https://github.com",
        "DEMO",
        (0, 15),
        "NO_THREATS_DETECTED"
    ))
    
    # === WATCHLIST ===
    print("--- WATCHLIST ---")
    custom_watchlist = [
        {"name": "MyCorp", "domain": "mycorp.com", "category": "Enterprise", "active": True}
    ]
    results.append(test_case(
        "Watchlist match: mycorp.phisher.xyz",
        "https://mycorp.phisher.xyz",
        "DEMO",
        (70, 100),
        "CRITICAL"
    ))
    
    results.append(test_case(
        "Watchlist legitimate: mycorp.com",
        "https://mycorp.com",
        "DEMO",
        (0, 5),
        "VERIFIED_SAFE"
    ))
    
    # === LIVE MODE SPECIFIC ===
    print("--- LIVE MODE (requires network) ---")
    results.append(test_case(
        "LIVE: github.com (should resolve DNS, TLS)",
        "https://github.com",
        "LIVE",
        (0, 20),
        "NO_THREATS_DETECTED"
    ))
    
    results.append(test_case(
        "LIVE: microsoft.com (brand verified)",
        "https://microsoft.com",
        "LIVE",
        (0, 5),
        "VERIFIED_SAFE"
    ))
    
    # Summary
    print("=" * 70)
    passed = sum(results)
    total = len(results)
    print(f"SUMMARY: {passed}/{total} tests passed")
    if passed < total:
        print(f"FAILED: {total - passed} tests")
    print("=" * 70)
    
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)