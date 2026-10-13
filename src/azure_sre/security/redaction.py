"""Recursive secret and PII redaction for evidence text before it reaches model context."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Final

_MAX_DEPTH: Final = 32

_PATTERNS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
            r"[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)"
        ),
        "[REDACTED:pem]",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),
        "[REDACTED:jwt]",
    ),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), "[REDACTED:github_token]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), "[REDACTED:github_token]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer [REDACTED:token]"),
    (
        re.compile(
            r"(?i)\b(AccountKey|SharedAccessKey|SharedAccessSignature|Password|Pwd|"
            r"InstrumentationKey|sig|client_secret|secret|token|api[_-]?key)"
            r"(\s*[=:]\s*)[^;\s,'\"&]+"
        ),
        r"\1\2[REDACTED:secret]",
    ),
    (
        re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        "[REDACTED:email]",
    ),
    (
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "[REDACTED:ip]",
    ),
    (
        re.compile(
            r"(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{0,4}:){2,7}:[0-9a-f]{0,4}\b"
        ),
        "[REDACTED:ip]",
    ),
)


def redact_text(text: str) -> str:
    """Replace secret-looking and personal substrings; order matters (PEM before generic keys)."""
    result = text
    for pattern, replacement in _PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_value(value: Any, *, _depth: int = 0) -> Any:
    """Redact strings inside arbitrarily nested dicts, lists, and tuples without mutating input."""
    if _depth > _MAX_DEPTH:
        return "[REDACTED:depth]"
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {
            redact_text(str(key)): redact_value(item, _depth=_depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return tuple(redact_value(item, _depth=_depth + 1) for item in value)
    return value
