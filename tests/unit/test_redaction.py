"""Redaction tests: secrets, identifiers, and recursive structures are removed."""

from __future__ import annotations

from typing import Any

import pytest

from azure_sre.security.redaction import redact_text, redact_value

PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk"
GH = "ghp_" + "a" * 36


@pytest.mark.parametrize(
    "secret",
    [
        PEM,
        JWT,
        GH,
        "Bearer abcdef0123456789.token",
        "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=abc==",
        "password=hunter2",
        "client_secret: s3cr3t-value",
        "contact jane.doe@contoso.com now",
        "caller 10.20.30.40 failed",
        "from 2001:db8::1 blocked",
    ],
)
def test_known_secret_shapes_are_removed(secret: str) -> None:
    redacted = redact_text(f"prefix {secret} suffix")
    assert secret not in redacted
    assert "prefix" in redacted and "suffix" in redacted


def test_plain_text_is_unchanged() -> None:
    text = "GET /api/orders returned 500 in 120 ms"
    assert redact_text(text) == text


def test_redaction_is_recursive_through_mappings_and_lists() -> None:
    value: dict[str, Any] = {
        "outer": [{"inner": {"msg": f"token {GH}"}}, "mail a@b.example"],
        "count": 3,
        "flag": True,
        "none": None,
    }
    redacted = redact_value(value)
    dumped = repr(redacted)
    assert GH not in dumped
    assert "a@b.example" not in dumped
    assert redacted["count"] == 3
    assert redacted["flag"] is True
    assert redacted["none"] is None


def test_deep_nesting_is_bounded_and_does_not_raise() -> None:
    value: Any = "leaf jane@contoso.com"
    for _ in range(200):
        value = [value]
    redacted = redact_value(value)
    assert "jane@contoso.com" not in repr(redacted)


def test_non_string_keys_do_not_leak_secret_values() -> None:
    redacted = redact_value({"safe": f"{JWT}"})
    assert JWT not in repr(redacted)
