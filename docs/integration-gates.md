# Integration gates

Status: **offline baseline verified; live gates unverified (blocked on absent inputs).**

This page records the pinned versions, the API surface actually verified against the
installed releases, how to run each gate, and which acceptance criteria from work
package 1 (`integration-gates`) are still open.

## Pinned versions

| Component | Pin | Source / verification |
|---|---|---|
| Python | 3.13 (`requires-python = ">=3.13,<3.14"`) | `.python-version` |
| `github-copilot-sdk` | `==1.0.20` | PyPI latest at pin time; wheel inspected |
| Copilot runtime (CLI) | `1.0.96` | Pinned by the SDK in `copilot/_cli_version.py`; downloaded from `github/copilot-cli` `v1.0.96` and verified against `SHA256SUMS.txt` |
| SDK ↔ runtime protocol | `3` | Confirmed by `client.ping()` |
| `mcp` (Python client) | `==2.3.0` | PyPI latest at pin time |
| `pydantic` | `==2.14.1` | PyPI |
| `github-mcp-server` | `v2.0.2` (commit `eb47a99`) | GitHub release; sha256 below |
| Dev: pytest / pytest-asyncio / ruff / mypy | 9.1.1 / 1.4.0 / 0.17.0 / 2.4.0 | `uv.lock` |
| Dependency tool | uv 0.11.x | `uv.lock` is authoritative |

`github-mcp-server` v2.0.2 sha256:

- `Linux_x86_64`: `815e27d931c796af0c97f24fd211e14f8a4607d4528377719a5ad2352086b0b0`
- `Darwin_arm64`: `5d9b38511bffc84d2272eb6189129eb721c8900e45784d8ea7eaf25f8d3dd835`

Pins live in code in `src/azure_sre/runtime/versions.py`. `pin_mismatches()` fails the
smoke if the installed versions drift from the pins.

Azure CLI 2.91.0 and checksum-pinned `log-analytics` 1.0.0b3 are preinstalled in the
built non-root image. The actual SDK runtime/tool-denial smoke passed inside the
image without downloads. CLI command availability is checked with `--help`; this
does not prove managed-identity authentication or live telemetry access.

## Verified API notes (from installed `github-copilot-sdk` 1.0.20)

Older examples drift from this release. Read these against the installed package, not
blog posts.

- `CopilotClient(mode="empty", base_directory=..., use_logged_in_user=False, env={...}, connection=RuntimeConnection.for_stdio(...), github_token=...)`.
  - `env=None` inherits **all** of `os.environ`, so always pass an explicit env.
  - `use_logged_in_user` defaults to True unless `github_token` is given. Set it to False explicitly (this adds `--no-auto-login`), so there is no user-credential fallback.
  - `mode="empty"` needs `base_directory` (it becomes `COPILOT_HOME`) and `available_tools` on every session. It disables keytar, custom instructions, plugins and builtin skills.
  - `github_token` reaches the child via env `COPILOT_SDK_AUTH_TOKEN` (`--auth-token-env`). It is not passed in argv.
- `client.create_session(...)` is keyword-only. Hardening options used here:
  - `available_tools=ToolSet().add_custom(name)`. Entries are `custom:<name>`. The allowlist covers built-in, MCP and custom tools, and unlisted tools do not exist for the session.
  - `on_permission_request=handler(PermissionRequest, PermissionInvocation)`. It returns `PermissionDecisionApproveOnce()` or `PermissionDecisionReject(feedback=...)` from `copilot.generated.rpc`.
  - `enable_config_discovery=False`, `skip_custom_instructions=True`, `enable_skills=False`, `enable_file_hooks=False`, `enable_host_git_operations=False`, `enable_session_store=False`.
  - Also available but not exercised: `mcp_servers`, `hooks`, `session_limits` (experimental), `provider` (BYOK).
  - `github_token_provider` is a per-session callback returning `{"kind": "token", "accessToken", "expiresIn"}`. It is the candidate mechanism for installation-token refresh. **Live unverified.**
- `define_tool(name, description=, handler=fn(params, invocation), params_type=<pydantic model>)`. Handler exceptions are not shown to the model.
- Permission request variants (`copilot.generated.session_events`) carry a `kind`: `PermissionRequestCustomTool`, `PermissionRequestMcp` and `PermissionRequestShell`. Policy must check `kind` as well as `tool_name`, because an MCP tool can share a name with a custom tool. **Never use `PermissionHandler.approve_all`.**
- `session.rpc.tools.execute(ToolsExecuteRequest(name=, arguments=))` (experimental) is annotated as returning `ToolResultExpanded` but actually returns a raw dict (`textResultForLlm`, `resultType`, `error`). `sdk_policy.execute_tool_directly` normalizes it. Calling a hidden built-in returns `resultType="failure"` with `Tool '<name>' does not exist.`
- Lifecycle: `session.abort()`, `session.disconnect()`, `client.delete_session(id)`, `client.stop()` (returns None and raises `ExceptionGroup` on errors), and `client.force_stop()`.
- Preinstall the runtime with `python -m copilot download-runtime`. Run with `COPILOT_SKIP_CLI_DOWNLOAD=1` and, optionally, `COPILOT_CLI_PATH`.

### MCP (`mcp` 2.3.0 + `github-mcp-server` v2.0.2)

- Client: `stdio_client(StdioServerParameters(command, args, env, cwd))` together with `ClientSession(read, write)` and its `initialize()`, `list_tools()` and `call_tool()` methods. The child env is the dict you pass, merged over safe defaults (HOME, PATH, ...).
- Server flags used: `stdio --app-id --app-installation-id --app-private-key-path --tools=... --lockdown-mode`. With `--tools=issue_write,issue_read,list_issues,search_issues,add_issue_comment` the server advertises exactly those 5 tools. `--toolsets=issues` advertises 10.
- `issue_write` supports `method` values `create|update` and `state` values `open|closed`, and `add_issue_comment` supports reactions. The server alone cannot enforce create-only, no-close or single-repo rules, so the host enforces them in `mcp_policy.validate_call`.

## Offline gates — verified

Prerequisites: `uv sync`, then `uv run python -m copilot download-runtime` (a one-time
public download with checksum verification), then `scripts/fetch_github_mcp_server.sh`.
No credentials are used.

| Command | Result |
|---|---|
| `uv run python -m azure_sre.runtime.smoke offline` | ✅ every check passed: `pins_match_installed`, `runtime_ping`, `allowlisted_custom_tool_runs`, `unpermitted_custom_tool_denied`, `builtin_tools_hidden` (bash/view/edit/... do not exist), `permission_audit_recorded`, `disposal_clean` |
| `uv run python -m azure_sre.runtime.smoke mcp-tools --binary .work/gms/github-mcp-server` | ✅ `server_identity`, `only_publisher_tools_advertised`, `all_publisher_tools_present` |
| `GITHUB_MCP_SERVER_PATH=$PWD/.work/gms/github-mcp-server uv run pytest -q` | ✅ 13 passed, 1 skipped (the live gate is opt-in) |
| `uv run ruff check . && uv run ruff format --check .` | ✅ clean |
| `uv run mypy` (strict) | ✅ no issues in 13 files |
| `uv lock --check` | ✅ lockfile consistent |

The offline smoke drives tools through `session.rpc.tools.execute`, so it needs no model
and no authentication. It does **not** prove that a model chooses tools correctly.

## Live gates — unverified (opt-in)

None of these ran. They need tenant, GitHub App and deployment inputs that do not exist
in this environment. Never point them at production. Use a dedicated test org, test repo
and non-production subscription.

| # | Gate (WP1 acceptance) | Prerequisites | Opt-in command / procedure |
|---|---|---|---|
| L1 | SDK session with a real model: the model calls an allowlisted tool, a decoy is never executed, abort works, disposal is clean | Copilot Requests GitHub App installed on the org; Copilot org enablement and billing; a **`ghs_` installation token** minted by a token supplier (never a user/PAT token); model name | `SRE_LIVE_GATES=1 SRE_COPILOT_INSTALLATION_TOKEN=<ghs_…> uv run python -m azure_sre.runtime.smoke live --model <model>` or `SRE_LIVE_GATES=1 SRE_LIVE_MODEL=<model> SRE_COPILOT_INSTALLATION_TOKEN=… uv run pytest -m live` |
| L2 | Installation-token routing and refresh (expiry under `github_token_provider`) | As L1, plus a Key Vault-backed App private key | Provider implemented with offline cache/refresh tests. Run a real session past expiry and assert refreshed credentials, with no stored-user fallback. |
| L3 | Managed-identity Azure CLI inside Container Apps | Tenant, subscription, pilot environment, explicit UAMI with diagnostic Reader + Log Analytics Reader | Image and CLI adapter implemented. Verify `az login --identity --client-id`, historical template reads, MI profile refresh, and denied mutations on throwaway resources. |
| L4 | MCP App auth: create/read/reconcile/comment in the test repo | Separate publisher App ID/install/bot login, selected test repo, Key Vault PEM | Publisher implemented. Pilot real writes and deliberately lost responses against a mapped test repository; verify bot author/marker and no blind retries. |
| L5 | Real Monitor secure-webhook validation | Entra audience/app role/caller IDs and secure action group | Ingress implemented. Validate real JWT issuer/audience/role/caller and measured durable acceptance latency. |
| L6 | Deployed non-root image, preinstalled runtime/CLI/MCP and app readiness | Container Apps environment/registry | Local image build and actual non-root SDK smoke passed. Deploy and verify both roles, probes, permissions and no first-incident downloads. |

## Recommended stable interfaces for other implementers

Import these and do not re-wire the SDK or MCP directly.

- `azure_sre.runtime.sdk_policy`
  - `create_isolated_client(base_directory, workspace, inference_token, runtime_path=None, extra_env=None, log_level=...)` builds an empty-mode client with an explicit env, no auto-login, and only `ghs_` tokens.
  - `create_isolated_session(client, tools, workspace, permissions=None, model=None, **opts) -> (session, permissions)` sets the allowlist to exactly the given custom tools and denies everything else by default.
  - `DenyByDefaultPermissions(allowed_custom_tools)` keeps a `.audit` list of `PermissionAuditEntry`. `custom_tool_allowlist(names)`.
  - `build_runtime_env(home, extra=None)` rejects `GITHUB_*`, `GH_*`, `AZURE_*`, `IDENTITY_*`, `MSI_*` and secret-like names. `validate_inference_token(token)`.
  - `execute_tool_directly(session, name, args)` is for tests and gates only. `dispose(client, session) -> list[str]` returns errors and never raises.
  - `PolicyError`.
- `azure_sre.runtime.mcp_policy`
  - `PUBLISHER_TOOLS` and `RepositoryTarget(owner, repo)`.
  - `github_mcp_stdio_parameters(binary, app_id, installation_id, private_key_path, workdir)`. The env is empty and the key is passed as a file path.
  - `unexpected_advertised_tools(names)`.
  - `validate_call(name, args, target)` raises `McpPolicyError` for a foreign repo, close/update, reactions or unknown args.
- `azure_sre.runtime.versions`: pin constants, `installed_versions()` and `pin_mismatches()`.
- Service packages are implemented. Their public interfaces and offline checks are
  documented in the package-specific docs; see [implementation status](implementation-status.md).
- Tests use pytest markers `offline_runtime` and `live` (strict markers). Keep live tests behind `SRE_LIVE_GATES=1`.

## Remaining blockers

1. No Copilot Requests GitHub App, installation, org enablement or billing, and no `ghs_` token supplier, so L1 and L2 cannot run.
2. No Azure tenant, subscription, managed identity or Container Apps environment, so L3 cannot run.
3. No publisher GitHub App, Key Vault PEM or test repository, so L4 cannot run.
4. No Entra app registration or action group for secure webhooks, so L5 cannot run.
5. Local image build and runtime smoke are verified; the Container Apps portion of L6 is not.
6. `session.rpc.tools.execute` and `session_limits` are marked experimental in SDK 1.0.20. Re-verify both on every SDK bump.
