from scanner.detector import scan_text


def test_detects_password():
    findings = scan_text('password = "DemoPassword123!"', "config.py")
    assert any(f["type"] == "Password Assignment" for f in findings)


def test_detects_private_key():
    findings = scan_text(
        "-----BEGIN PRIVATE KEY-----",
        "key.txt"
    )
    assert any(f["type"] == "Private Key" for f in findings)


def test_masks_detected_value():
    findings = scan_text('api_key = "sk_test_1234567890abcdef"', "demo.env")
    assert findings
    assert "1234567890abcdef" not in str(findings)
