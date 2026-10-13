"""Offline integration gates: real pinned runtime/binary, no credentials, no Azure."""

import os
from pathlib import Path

import pytest
from copilot._cli_download import get_cached_cli_path

from azure_sre.runtime import smoke


@pytest.mark.offline_runtime
@pytest.mark.skipif(
    get_cached_cli_path() is None, reason="run: uv run python -m copilot download-runtime"
)
async def test_sdk_runtime_offline_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SRE_SMOKE_WORKDIR", str(tmp_path))
    results = await smoke.run_offline()
    assert results and all(results.values()), results


@pytest.mark.offline_runtime
@pytest.mark.skipif(
    not os.environ.get("GITHUB_MCP_SERVER_PATH"), reason="set GITHUB_MCP_SERVER_PATH"
)
async def test_github_mcp_advertises_only_publisher_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SRE_SMOKE_WORKDIR", str(tmp_path))
    results = await smoke.run_mcp_tools(Path(os.environ["GITHUB_MCP_SERVER_PATH"]))
    assert all(results.values()), results


@pytest.mark.live
@pytest.mark.skipif(os.environ.get("SRE_LIVE_GATES") != "1", reason="live gates are opt-in")
async def test_live_inference_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SRE_SMOKE_WORKDIR", str(tmp_path))
    results = await smoke.run_live(os.environ["SRE_LIVE_MODEL"], turn_timeout_s=120)
    assert all(results.values()), results
