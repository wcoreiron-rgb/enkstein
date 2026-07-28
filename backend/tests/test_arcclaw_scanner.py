from app.claws.arcclaw.scanner import scan_text


def test_large_alphanumeric_source_is_not_misclassified_as_base64():
    result = scan_text("x" * 100_001, redact=False)

    assert not any(finding["pattern"] == "Base64 payload" for finding in result.findings)


def test_base64_payload_with_symbol_is_detected_and_redacted():
    payload = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo+/0123456789="
    result = scan_text(f"payload={payload}", redact=True)

    assert any(finding["pattern"] == "Base64 payload" for finding in result.findings)
    assert payload not in result.redacted


def test_json_escaped_framework_decorator_is_not_treated_as_email():
    payload = r'{"content":"from flask import Blueprint\n\n@routes.route(\"/health\")\ndef health(): pass\n"}'
    result = scan_text(payload, redact=True)

    assert "@routes.route" in result.redacted
    assert not any(item["pattern"] == "Email Address" for item in result.findings)


def test_real_email_is_still_redacted_after_code_boundary_hardening():
    result = scan_text("Contact owner@example.com", redact=True)

    assert "owner@example.com" not in result.redacted
    assert any(item["pattern"] == "Email Address" for item in result.findings)
