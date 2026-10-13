"""Typed service configuration.

Configuration is a reviewed JSON document. It holds identifiers and Key Vault
*references* only; secret material is never stored inline. Loading rejects
credential-looking content, and placeholder values (``REPLACE`` markers and nil
GUIDs) unless ``allow_placeholders=True`` is passed explicitly, which is meant
for the checked-in example and tests only.

Budget values can never exceed the hard maxima defined in ``contracts``.
"""

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any, Final, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from azure_sre.contracts import (
    HARD_MAX_CLI_CALL_SECONDS,
    HARD_MAX_CONCURRENCY_PER_REPLICA,
    HARD_MAX_DIAGNOSTIC_CALLS,
    HARD_MAX_EVIDENCE_BYTES,
    HARD_MAX_INVESTIGATION_SECONDS,
    HARD_MAX_ISSUE_BODY_BYTES,
    HARD_MAX_ROWS_PER_QUERY,
    HARD_MAX_WINDOW_AFTER_MINUTES,
    HARD_MAX_WINDOW_BEFORE_MINUTES,
    MAX_METRIC_NAMES,
    MAX_TARGETS_PER_ALERT,
    ApplicationRegistry,
    ContractError,
    Sink,
)

__all__ = [
    "DEFAULT_CLI_CALL_SECONDS",
    "DEFAULT_CONCURRENCY_PER_REPLICA",
    "DEFAULT_DIAGNOSTIC_CALLS",
    "DEFAULT_EVIDENCE_BYTES",
    "DEFAULT_INVESTIGATION_SECONDS",
    "DEFAULT_ISSUE_BODY_BYTES",
    "DEFAULT_MAX_METRIC_NAMES",
    "DEFAULT_MAX_TARGETS",
    "DEFAULT_ROWS_PER_QUERY",
    "DEFAULT_WINDOW_AFTER_MINUTES",
    "DEFAULT_WINDOW_BEFORE_MINUTES",
    "MAX_CONFIG_BYTES",
    "AppConfig",
    "BudgetPolicy",
    "ConfigError",
    "PublisherConfig",
    "WebhookCaller",
    "load_config",
    "parse_config",
]

MAX_CONFIG_BYTES: Final = 256 * 1024

DEFAULT_INVESTIGATION_SECONDS: Final = 300
DEFAULT_CLI_CALL_SECONDS: Final = 30
DEFAULT_DIAGNOSTIC_CALLS: Final = 12
DEFAULT_CONCURRENCY_PER_REPLICA: Final = 2
DEFAULT_ROWS_PER_QUERY: Final = 100
DEFAULT_EVIDENCE_BYTES: Final = 64 * 1024
DEFAULT_ISSUE_BODY_BYTES: Final = 24 * 1024
DEFAULT_WINDOW_BEFORE_MINUTES: Final = 15
DEFAULT_WINDOW_AFTER_MINUTES: Final = 5
DEFAULT_MAX_TARGETS: Final = 8
DEFAULT_MAX_METRIC_NAMES: Final = 5

_NIL_GUID: Final = "00000000-0000-0000-0000-000000000000"
_PLACEHOLDER_MARKER: Final = "REPLACE"
_PEM_MARKER: Final = "-----BEGIN"

_GUID_RE: Final = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_KEY_VAULT_URI_RE: Final = re.compile(
    r"^https://[A-Za-z0-9-]{3,24}\.vault\.(?:azure\.net|usgovcloudapi\.net|azure\.cn)/?$"
)
_VAULT_NAME_PATTERN: Final = r"^[A-Za-z0-9-]{1,127}$"
_VERSION_RE: Final = r"^[A-Za-z0-9._+-]{1,64}$"
_TOKEN_RE: Final = re.compile(
    r"(?<![A-Za-z0-9])(?:ghp_|ghs_|gho_|ghu_|ghr_|github_pat_)[A-Za-z0-9_]{8,}"
)
_SAFE_PATH_RE: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_SECRET_KEYS: Final = frozenset(
    {
        "clientsecret",
        "password",
        "secretvalue",
        "secret",
        "apikey",
        "privatekey",
        "accesstoken",
        "token",
    }
)

_MODEL_CONFIG: Final = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ConfigError(ValueError):
    """The configuration is unreadable, oversized, unsafe or invalid."""


class BudgetPolicy(BaseModel):
    """Per-investigation limits. Every value is bounded by a hard maximum."""

    model_config = _MODEL_CONFIG

    investigation_seconds: Annotated[
        int, Field(strict=True, ge=1, le=HARD_MAX_INVESTIGATION_SECONDS)
    ] = DEFAULT_INVESTIGATION_SECONDS
    cli_call_seconds: Annotated[int, Field(strict=True, ge=1, le=HARD_MAX_CLI_CALL_SECONDS)] = (
        DEFAULT_CLI_CALL_SECONDS
    )
    diagnostic_calls: Annotated[int, Field(strict=True, ge=1, le=HARD_MAX_DIAGNOSTIC_CALLS)] = (
        DEFAULT_DIAGNOSTIC_CALLS
    )
    concurrency_per_replica: Annotated[
        int, Field(strict=True, ge=1, le=HARD_MAX_CONCURRENCY_PER_REPLICA)
    ] = DEFAULT_CONCURRENCY_PER_REPLICA
    rows_per_query: Annotated[int, Field(strict=True, ge=1, le=HARD_MAX_ROWS_PER_QUERY)] = (
        DEFAULT_ROWS_PER_QUERY
    )
    evidence_bytes: Annotated[int, Field(strict=True, ge=1, le=HARD_MAX_EVIDENCE_BYTES)] = (
        DEFAULT_EVIDENCE_BYTES
    )
    issue_body_bytes: Annotated[int, Field(strict=True, ge=1, le=HARD_MAX_ISSUE_BODY_BYTES)] = (
        DEFAULT_ISSUE_BODY_BYTES
    )
    window_before_minutes: Annotated[
        int, Field(strict=True, ge=1, le=HARD_MAX_WINDOW_BEFORE_MINUTES)
    ] = DEFAULT_WINDOW_BEFORE_MINUTES
    window_after_minutes: Annotated[
        int, Field(strict=True, ge=1, le=HARD_MAX_WINDOW_AFTER_MINUTES)
    ] = DEFAULT_WINDOW_AFTER_MINUTES
    max_targets: Annotated[int, Field(strict=True, ge=1, le=MAX_TARGETS_PER_ALERT)] = (
        DEFAULT_MAX_TARGETS
    )
    max_metric_names: Annotated[int, Field(strict=True, ge=1, le=MAX_METRIC_NAMES)] = (
        DEFAULT_MAX_METRIC_NAMES
    )


class WebhookCaller(BaseModel):
    """An Entra object id allowed to call the webhook, mapped to the sink it may use."""

    model_config = _MODEL_CONFIG

    object_id: str
    sink: Sink

    @field_validator("object_id")
    @classmethod
    def _object_id(cls, value: str) -> str:
        if not _GUID_RE.match(value):
            raise ValueError("webhook caller object_id must be a GUID")
        return value.lower()


class PublisherConfig(BaseModel):
    """Key Vault reference for the publisher credential. Never the secret itself."""

    model_config = _MODEL_CONFIG

    key_vault_uri: Annotated[str, StringConstraints(pattern=_KEY_VAULT_URI_RE.pattern)]
    secret_name: Annotated[str, StringConstraints(pattern=_VAULT_NAME_PATTERN)]


class AppConfig(BaseModel):
    """Root configuration document (schema version 1)."""

    model_config = _MODEL_CONFIG

    schema_version: Literal[1]
    deployed_version: Annotated[str, StringConstraints(pattern=_VERSION_RE)]
    budget: BudgetPolicy = Field(default_factory=BudgetPolicy)
    registry: ApplicationRegistry
    webhook_callers: Annotated[tuple[WebhookCaller, ...], Field(min_length=1)]
    publisher: PublisherConfig | None = None

    @model_validator(mode="after")
    def _unique_callers(self) -> Self:
        ids = [caller.object_id for caller in self.webhook_callers]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate webhook caller object_id")
        return self

    def sink_for_caller(self, object_id: str) -> Sink | None:
        """Return the sink for an authenticated caller object id, or ``None`` if unknown."""
        key = object_id.strip().lower()
        for caller in self.webhook_callers:
            if caller.object_id == key:
                return caller.sink
        return None


def _location(parts: tuple[str | int, ...]) -> str:
    out = ""
    for part in parts:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            # Keys are echoed only when they look like schema names, never raw content.
            safe = part if _SAFE_PATH_RE.match(part) else "<key>"
            out = f"{out}.{safe}" if out else safe
    return out or "<root>"


def _check_credentials(text: str, parts: tuple[str | int, ...]) -> None:
    if _PEM_MARKER in text or _TOKEN_RE.search(text):
        raise ConfigError(
            f"{_location(parts)}: credential material is not allowed in configuration; "
            "reference secrets through Key Vault"
        )


def _check_placeholder(text: str, parts: tuple[str | int, ...]) -> None:
    if _PLACEHOLDER_MARKER in text or text.strip().lower() == _NIL_GUID:
        raise ConfigError(
            f"{_location(parts)}: placeholder value; replace it before deployment "
            "(or pass allow_placeholders=True for examples and tests)"
        )


def _scan(node: Any, parts: tuple[str | int, ...], allow_placeholders: bool) -> None:
    """Reject credential material and, unless allowed, placeholder values anywhere in the tree."""
    if isinstance(node, Mapping):
        for key, value in node.items():
            key_text = str(key)
            child = (*parts, key_text)
            _check_credentials(key_text, child)
            if re.sub(r"[^a-z]", "", key_text.lower()) in _SECRET_KEYS:
                raise ConfigError(
                    f"{_location(child)}: inline secret values are not allowed; "
                    "use key_vault_uri and secret_name references"
                )
            _scan(value, child, allow_placeholders)
    elif isinstance(node, list | tuple):
        for index, item in enumerate(node):
            _scan(item, (*parts, index), allow_placeholders)
    elif isinstance(node, str):
        _check_credentials(node, parts)
        if not allow_placeholders:
            _check_placeholder(node, parts)


def parse_config(data: Mapping[str, Any], *, allow_placeholders: bool = False) -> AppConfig:
    """Validate an already-decoded configuration mapping.

    Raises ``ConfigError`` with a message that names locations but never echoes values.
    """
    if not isinstance(data, Mapping):
        raise ConfigError("configuration must be a JSON object")
    _scan(data, (), allow_placeholders)
    try:
        return AppConfig.model_validate(data)
    except ValidationError as exc:
        problems = [f"{_location(tuple(e['loc']))}: {e['msg']}" for e in exc.errors()[:20]]
        raise ConfigError("invalid configuration: " + "; ".join(problems)) from exc
    except ContractError as exc:
        # Raised from nested contract models outside pydantic's error sanitisation; report the
        # stable code only so no raw values leak.
        raise ConfigError(f"invalid configuration: contract violation ({exc.code})") from None


def load_config(path: Path | str, *, allow_placeholders: bool = False) -> AppConfig:
    """Read, size-check and validate a JSON configuration file."""
    target = Path(path)
    try:
        with target.open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise ConfigError(f"cannot read configuration file {target.name}") from exc
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(f"configuration file exceeds {MAX_CONFIG_BYTES} bytes")
    try:
        data: Any = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ConfigError("configuration file is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"configuration file is not valid JSON: {exc.msg}") from exc
    return parse_config(data, allow_placeholders=allow_placeholders)
