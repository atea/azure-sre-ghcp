"""Server process lifecycle: private dir/key, env isolation, schema discovery checks."""

from __future__ import annotations

import json
import os
import shutil
import stat
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from mcp.client.stdio import get_default_environment

from azure_sre.github.mcp_client import (
    McpSetupError,
    open_publisher_session,
    safe_child_environment,
    stdio_session_factory,
)
from azure_sre.github.tool_schemas import (
    EXPECTED_TOOLS,
    SchemaMismatchError,
    check_advertised_tools,
)
from azure_sre.runtime.mcp_policy import PUBLISHER_TOOLS, McpPolicyError, RepositoryTarget
from tests.unit.test_publisher_support import (
    FIXTURE_PATH,
    TEST_PEM,
    FakeGitHub,
    entries,
    factory_for,
    real_tools,
    resolve_installation,
)

TARGET = RepositoryTarget(owner="contoso", repo="shop")


def schemas() -> dict[str, Any]:
    return {t.name: t.input_schema for t in real_tools()}


async def load_pem() -> str:
    return TEST_PEM


def session_kwargs(gh: FakeGitHub, root: Path, **overrides: Any) -> dict[str, Any]:
    return {
        "binary": Path("/opt/gms/github-mcp-server"),
        "app_id": "123456",
        "installation_id": 42,
        "load_private_key": load_pem,
        "target": TARGET,
        "factory": factory_for(gh),
        "private_root": root,
        "installation_resolver": resolve_installation,
        **overrides,
    }


def test_captured_fixture_matches_expectations() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text())
    assert fixture["server"] == {"name": "github-mcp-server", "version": "2.0.2"}
    assert fixture["next_cursor"] is None
    assert {t["name"] for t in fixture["tools"]} == set(PUBLISHER_TOOLS) == set(EXPECTED_TOOLS)
    check_advertised_tools(schemas())


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s["issue_write"]["required"].append("title"),
        lambda s: s["issue_read"]["properties"]["method"].update(enum=["get"]),
        lambda s: s["list_issues"]["properties"]["perPage"].update(type="string"),
        lambda s: s["add_issue_comment"]["properties"].pop("body"),
        lambda s: s.update(delete_issue={"type": "object", "properties": {}}),
        lambda s: s.pop("search_issues"),
    ],
)
def test_schema_drift_detected(mutate: Any) -> None:
    advertised = json.loads(json.dumps(schemas()))
    mutate(advertised)
    with pytest.raises(SchemaMismatchError):
        check_advertised_tools(advertised)


def test_safe_env_overrides_every_sdk_default_and_hides_user_home(tmp_path: Path) -> None:
    env = safe_child_environment(tmp_path)
    assert set(get_default_environment()) <= set(env)
    assert env["HOME"].startswith(str(tmp_path))
    assert env["HOME"] != os.path.expanduser("~")
    assert not any(k.startswith(("GITHUB", "GH_", "AZURE")) for k in env)


async def test_session_launch_parameters_key_and_cleanup(tmp_path: Path) -> None:
    gh = FakeGitHub()
    async with open_publisher_session(**session_kwargs(gh, tmp_path)) as session:
        (private,) = entries(tmp_path)
        assert stat.S_IMODE(private.stat().st_mode) == 0o700
        (params,) = gh.params
        assert params.env is not None and params.env["HOME"] == str(private / "home")
        assert not any("GITHUB" in k for k in params.env)
        assert "--app-installation-id=42" in params.args
        assert f"--tools={','.join(PUBLISHER_TOOLS)}" in params.args
        assert TEST_PEM not in " ".join(params.args)
        assert gh.sessions[0].key_snapshot == (True, 0o600)
        with pytest.raises(McpPolicyError):
            await session.call("issue_write", {"owner": "evil", "repo": "x", "method": "create"})
        with pytest.raises(McpPolicyError):
            await session.call("delete_issue", {"owner": "contoso", "repo": "shop"})
        assert gh.calls == []
    assert entries(tmp_path) == []


async def test_body_exception_propagates_and_cleans(tmp_path: Path) -> None:
    gh = FakeGitHub()
    with pytest.raises(LookupError):
        async with open_publisher_session(**session_kwargs(gh, tmp_path)):
            raise LookupError
    assert entries(tmp_path) == []


@pytest.mark.parametrize(
    ("loader_result", "code", "retryable"),
    [(RuntimeError("vault"), "private_key_unavailable", True), ("not a pem", None, False)],
)
async def test_key_loader_failures(
    tmp_path: Path, loader_result: Any, code: str | None, retryable: bool
) -> None:
    async def loader() -> str:
        if isinstance(loader_result, Exception):
            raise loader_result
        return str(loader_result)

    gh = FakeGitHub()
    with pytest.raises(McpSetupError) as info:
        async with open_publisher_session(**session_kwargs(gh, tmp_path, load_private_key=loader)):
            pass
    assert info.value.retryable is retryable
    if code:
        assert info.value.code == code
    assert gh.sessions == [] and entries(tmp_path) == []


async def test_factory_failure_is_retryable_unavailable(tmp_path: Path) -> None:
    @asynccontextmanager
    async def broken(params: Any, errlog: Any) -> Any:
        raise FileNotFoundError("binary missing")
        yield

    with pytest.raises(McpSetupError) as info:
        async with open_publisher_session(**session_kwargs(FakeGitHub(), tmp_path, factory=broken)):
            pass
    assert info.value.code == "mcp_unavailable" and info.value.retryable
    assert entries(tmp_path) == []


async def test_relative_binary_rejected(tmp_path: Path) -> None:
    with pytest.raises((ValueError, McpSetupError)):
        async with open_publisher_session(
            **session_kwargs(FakeGitHub(), tmp_path, binary=Path("github-mcp-server"))
        ):
            pass


GMS = os.environ.get("GITHUB_MCP_SERVER_PATH")
GMS_PATH = Path(GMS).resolve() if GMS else Path("/nonexistent")


@pytest.mark.skipif(not GMS or not shutil.which(GMS or ""), reason="GITHUB_MCP_SERVER_PATH unset")
async def test_real_server_discovery_matches_fixture(tmp_path: Path) -> None:
    """Offline: real gms v2.0.2 starts with a throwaway key and advertises the fixture schemas."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()

    async def loader() -> str:
        return pem

    async def offline_resolver(app_id: str, pem: str, target: RepositoryTarget) -> int:
        return 1

    async with open_publisher_session(
        binary=GMS_PATH,
        app_id="1",
        installation_id=1,
        load_private_key=loader,
        target=TARGET,
        factory=stdio_session_factory,
        startup_timeout_seconds=20,
        private_root=tmp_path,
        installation_resolver=offline_resolver,
    ):
        pass  # initialize + version + schema checks all ran
    assert entries(tmp_path) == []
