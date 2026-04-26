from sniffer import mask_ip, redact_sensitive_text


def test_mask_ip():
    assert mask_ip("192.168.1.55") == "192.168.1.xxx"


def test_redact_email():
    text = "Contact admin@example.com for help"
    assert "[REDACTED_EMAIL]" in redact_sensitive_text(text)


def test_redact_authorization():
    text = "Authorization: Bearer secret123"
    assert "Authorization: [REDACTED_AUTH]" in redact_sensitive_text(text)


def test_redact_cookie():
    text = "Cookie: sessionid=abc123"
    assert "Cookie: [REDACTED_COOKIE]" in redact_sensitive_text(text)


def test_redact_query_token():
    text = "GET /login?token=abc123 HTTP/1.1"
    redacted = redact_sensitive_text(text)
    assert "token=[REDACTED_SECRET]" in redacted
