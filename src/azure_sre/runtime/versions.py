"""Pinned integration versions verified by the offline integration gate.

Change these only together with ``pyproject.toml``/``uv.lock`` and a re-run of
``python -m azure_sre.runtime.smoke offline`` plus the live gates in
``docs/integration-gates.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import version

PYTHON_SERIES = "3.13"
COPILOT_SDK_VERSION = "1.0.20"
# Copilot runtime pinned by the SDK wheel (``copilot._cli_version.CLI_VERSION``).
COPILOT_RUNTIME_VERSION = "1.0.96"
COPILOT_SDK_PROTOCOL_VERSION = 3
MCP_PYTHON_VERSION = "2.3.0"
PYDANTIC_VERSION = "2.14.1"

# Official GitHub MCP server stdio binary (release asset digests from the GitHub release API).
GITHUB_MCP_SERVER_VERSION = "v2.0.2"
GITHUB_MCP_SERVER_SHA256 = {
    "github-mcp-server_Linux_x86_64.tar.gz": (
        "815e27d931c796af0c97f24fd211e14f8a4607d4528377719a5ad2352086b0b0"
    ),
    "github-mcp-server_Darwin_arm64.tar.gz": (
        "5d9b38511bffc84d2272eb6189129eb721c8900e45784d8ea7eaf25f8d3dd835"
    ),
}


@dataclass(frozen=True)
class InstalledVersions:
    copilot_sdk: str
    copilot_runtime: str | None
    mcp: str
    pydantic: str


def installed_versions() -> InstalledVersions:
    from copilot._cli_version import CLI_VERSION

    return InstalledVersions(
        copilot_sdk=version("github-copilot-sdk"),
        copilot_runtime=CLI_VERSION,
        mcp=version("mcp"),
        pydantic=version("pydantic"),
    )


def pin_mismatches() -> list[str]:
    """Return human-readable drift between installed packages and the pins above."""
    got = installed_versions()
    expected = {
        "github-copilot-sdk": (COPILOT_SDK_VERSION, got.copilot_sdk),
        "copilot runtime": (COPILOT_RUNTIME_VERSION, got.copilot_runtime),
        "mcp": (MCP_PYTHON_VERSION, got.mcp),
        "pydantic": (PYDANTIC_VERSION, got.pydantic),
    }
    return [
        f"{k}: pinned {want}, installed {have}"
        for k, (want, have) in expected.items()
        if want != have
    ]
