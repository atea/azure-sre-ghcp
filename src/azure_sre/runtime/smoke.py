"""Integration-gate smoke harness.

Offline (no credentials, no network after the runtime is cached)::

    uv run python -m azure_sre.runtime.smoke offline
    uv run python -m azure_sre.runtime.smoke mcp-tools --binary <github-mcp-server>

Live (opt-in, needs external prerequisites; see docs/integration-gates.md)::

    SRE_LIVE_GATES=1 uv run python -m azure_sre.runtime.smoke live --model <model>
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from copilot import Tool, ToolInvocation, define_tool
from pydantic import BaseModel, Field

from azure_sre.runtime import sdk_policy
from azure_sre.runtime.versions import pin_mismatches

ECHO_TOOL = "sre_smoke_echo"
DECOY_TOOL = "sre_smoke_decoy"
FORBIDDEN_BUILTINS = ("bash", "view", "create", "edit", "web_fetch", "task")


class EchoParams(BaseModel):
    text: str = Field(max_length=64, description="Short text to echo back")


class SmokeTools:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def build(self) -> list[Tool]:
        def echo(params: EchoParams, invocation: ToolInvocation) -> str:
            self.calls.append((ECHO_TOOL, params.text))
            return f"echo:{params.text}"

        def decoy(params: EchoParams, invocation: ToolInvocation) -> str:
            self.calls.append((DECOY_TOOL, params.text))
            return "decoy executed"

        return [
            define_tool(
                ECHO_TOOL,
                description="Echo text (smoke test).",
                handler=echo,
                params_type=EchoParams,
            ),
            define_tool(
                DECOY_TOOL,
                description="Must never run (smoke test).",
                handler=decoy,
                params_type=EchoParams,
            ),
        ]


def _work_root() -> Path:
    return Path(os.environ.get("SRE_SMOKE_WORKDIR", ".work/smoke")).resolve()


def _check(results: dict[str, bool], name: str, ok: bool) -> None:
    results[name] = bool(ok)


async def run_offline() -> dict[str, bool]:
    results: dict[str, bool] = {}
    _check(results, "pins_match_installed", not pin_mismatches())
    root = _work_root()
    tools = SmokeTools()
    client = sdk_policy.create_isolated_client(
        base_directory=root / "home",
        workspace=root / "ws",
        runtime_path=os.environ.get("COPILOT_CLI_PATH"),
        extra_env={"COPILOT_SKIP_CLI_DOWNLOAD": "1"},
    )
    session = None
    try:
        await client.start()
        _check(results, "runtime_ping", (await client.ping("gate")).message.endswith("gate"))
        # Decoy is offered to the runtime but not permitted: proves deny-by-default
        # applies even to registered custom tools.
        perms = sdk_policy.DenyByDefaultPermissions(frozenset({ECHO_TOOL}))
        session, perms = await sdk_policy.create_isolated_session(
            client, tools=tools.build(), workspace=root / "ws", permissions=perms
        )
        echo = await sdk_policy.execute_tool_directly(session, ECHO_TOOL, {"text": "hi"})
        _check(
            results,
            "allowlisted_custom_tool_runs",
            echo.get("resultType") == "success" and (ECHO_TOOL, "hi") in tools.calls,
        )
        decoy = await sdk_policy.execute_tool_directly(session, DECOY_TOOL, {"text": "x"})
        _check(
            results,
            "unpermitted_custom_tool_denied",
            decoy.get("resultType") != "success"
            and not any(c[0] == DECOY_TOOL for c in tools.calls),
        )
        hidden = [
            await sdk_policy.execute_tool_directly(session, n, {}) for n in FORBIDDEN_BUILTINS
        ]
        _check(
            results,
            "builtin_tools_hidden",
            all(
                r.get("resultType") == "failure" and "does not exist" in str(r.get("error"))
                for r in hidden
            ),
        )
        _check(
            results,
            "permission_audit_recorded",
            any(e.approved and e.tool_name == ECHO_TOOL for e in perms.audit)
            and any(not e.approved and e.tool_name == DECOY_TOOL for e in perms.audit),
        )
    finally:
        errors = await sdk_policy.dispose(client, session)
        _check(results, "disposal_clean", not errors)
    return results


async def run_mcp_tools(binary: Path) -> dict[str, bool]:
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    from azure_sre.runtime.mcp_policy import PUBLISHER_TOOLS, unexpected_advertised_tools

    params = StdioServerParameters(
        command=str(binary), args=["stdio", f"--tools={','.join(PUBLISHER_TOOLS)}"], env={}
    )
    root = _work_root()
    root.mkdir(parents=True, exist_ok=True)
    with (root / "github-mcp-server.log").open("a") as errlog:
        async with stdio_client(params, errlog=errlog) as (read, write):
            async with ClientSession(read, write) as mcp_session:
                init = await mcp_session.initialize()
                listed = await mcp_session.list_tools()
    names = {t.name for t in listed.tools}
    return {
        "server_identity": init.server_info.name == "github-mcp-server",
        "only_publisher_tools_advertised": not unexpected_advertised_tools(names),
        "all_publisher_tools_present": names == set(PUBLISHER_TOOLS),
    }


async def run_live(model: str, turn_timeout_s: float) -> dict[str, bool]:
    if os.environ.get("SRE_LIVE_GATES") != "1":
        raise SystemExit("Live gates are opt-in: set SRE_LIVE_GATES=1.")
    token = os.environ.get("SRE_COPILOT_INSTALLATION_TOKEN")
    if not token:
        raise SystemExit(
            "SRE_COPILOT_INSTALLATION_TOKEN (GitHub App installation token) is required."
        )
    results: dict[str, bool] = {}
    root = _work_root()
    tools = SmokeTools()
    client = sdk_policy.create_isolated_client(
        base_directory=root / "home-live", workspace=root / "ws-live", inference_token=token
    )
    os.environ.pop("SRE_COPILOT_INSTALLATION_TOKEN", None)
    session = None
    try:
        perms = sdk_policy.DenyByDefaultPermissions(frozenset({ECHO_TOOL}))
        session, perms = await sdk_policy.create_isolated_session(
            client, tools=tools.build(), workspace=root / "ws-live", permissions=perms, model=model
        )
        await session.send_and_wait(
            f"Call the {ECHO_TOOL} tool with text 'gate', then call {DECOY_TOOL} with text 'x', "
            "then try to run the bash command 'id'. Report each outcome in one line.",
            timeout=turn_timeout_s,
        )
        _check(results, "model_invoked_allowlisted_tool", (ECHO_TOOL, "gate") in tools.calls)
        _check(results, "decoy_never_executed", not any(c[0] == DECOY_TOOL for c in tools.calls))
        task = asyncio.create_task(
            session.send_and_wait("Write 3000 words about logs.", timeout=turn_timeout_s)
        )
        await asyncio.sleep(3)
        await session.abort()
        try:
            await asyncio.wait_for(task, timeout=30)
            aborted = True
        except Exception:  # noqa: BLE001 - abort may surface as an error/timeout
            aborted = task.done()
        _check(results, "abort_returns_control", aborted)
    finally:
        errors = await sdk_policy.dispose(client, session)
        _check(results, "disposal_clean", not errors)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="azure_sre.runtime.smoke")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("offline")
    mcp_p = sub.add_parser("mcp-tools")
    mcp_p.add_argument("--binary", type=Path, required=True)
    live_p = sub.add_parser("live")
    live_p.add_argument("--model", required=True)
    live_p.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args(argv)

    if args.command == "offline":
        results = asyncio.run(run_offline())
    elif args.command == "mcp-tools":
        results = asyncio.run(run_mcp_tools(args.binary))
    else:
        results = asyncio.run(run_live(args.model, args.timeout))
    print(json.dumps(results, indent=2))
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
