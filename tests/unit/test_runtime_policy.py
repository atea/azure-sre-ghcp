from pathlib import Path

import pytest
from copilot.generated.rpc import PermissionDecisionApproveOnce, PermissionDecisionReject
from copilot.generated.session_events import (
    PermissionRequestCustomTool,
    PermissionRequestMcp,
    PermissionRequestShell,
)

from azure_sre.runtime import mcp_policy, sdk_policy
from azure_sre.runtime.versions import pin_mismatches

INV = {"session_id": "s"}


def test_installed_versions_match_pins() -> None:
    assert pin_mismatches() == []


def test_permissions_approve_only_allowlisted_custom_tool() -> None:
    perms = sdk_policy.DenyByDefaultPermissions(frozenset({"ok_tool"}))
    ok = PermissionRequestCustomTool(tool_description="d", tool_name="ok_tool")
    other = PermissionRequestCustomTool(tool_description="d", tool_name="other")
    managed = PermissionRequestCustomTool(
        tool_description="d", tool_name="ok_tool", managed_approval_required=True
    )
    mcp_same_name = PermissionRequestMcp(
        read_only=True, server_name="x", tool_name="ok_tool", tool_title="t"
    )
    shell = PermissionRequestShell(
        can_offer_session_approval=False,
        commands=[],
        full_command_text="id",
        has_write_file_redirection=False,
        intention="i",
        possible_paths=[],
        possible_urls=[],
    )
    assert isinstance(perms(ok, INV), PermissionDecisionApproveOnce)
    for req in (other, managed, mcp_same_name, shell):
        assert isinstance(perms(req, INV), PermissionDecisionReject)
    assert [e.approved for e in perms.audit] == [True, False, False, False, False]


def test_allowlist_only_contains_custom_entries() -> None:
    assert sdk_policy.custom_tool_allowlist(["b", "a", "a"]).to_list() == ["custom:a", "custom:b"]
    with pytest.raises(sdk_policy.PolicyError):
        sdk_policy.custom_tool_allowlist([])


def test_runtime_env_is_minimal_and_rejects_credentials(tmp_path: Path) -> None:
    source = {"PATH": "/bin", "GITHUB_TOKEN": "x", "AZURE_CLIENT_SECRET": "y", "LANG": "C"}
    env = sdk_policy.build_runtime_env(home=tmp_path, source=source)
    assert env == {"PATH": "/bin", "LANG": "C", "HOME": str(tmp_path)}
    for bad in ("GH_TOKEN", "MY_SECRET", "APP_PRIVATE_KEY", "AZURE_CONFIG_DIR", "IDENTITY_HEADER"):
        with pytest.raises(sdk_policy.PolicyError):
            sdk_policy.build_runtime_env(home=tmp_path, extra={bad: "v"}, source={})


@pytest.mark.parametrize("token", ["ghp_x", "gho_x", "ghu_x", "github_pat_x", "random"])
def test_inference_token_rejects_non_installation_tokens(token: str) -> None:
    with pytest.raises(sdk_policy.PolicyError):
        sdk_policy.validate_inference_token(token)
    assert sdk_policy.validate_inference_token(" ghs_abc ") == "ghs_abc"


TARGET = mcp_policy.RepositoryTarget("org", "repo")


def test_mcp_policy_allows_create_read_comment_on_target_only() -> None:
    mcp_policy.validate_call(
        "issue_write", {"method": "create", "owner": "org", "repo": "repo", "title": "t"}, TARGET
    )
    mcp_policy.validate_call("search_issues", {"query": "repo:org/repo marker"}, TARGET)
    bad_calls = [
        ("issue_write", {"method": "update", "owner": "org", "repo": "repo", "issue_number": 1}),
        ("issue_write", {"method": "create", "owner": "org", "repo": "repo", "state": "closed"}),
        ("issue_write", {"method": "create", "owner": "evil", "repo": "repo"}),
        ("add_issue_comment", {"owner": "org", "repo": "repo", "issue_number": 1, "comment_id": 2}),
        ("search_issues", {"query": "marker"}),
        ("search_issues", {"query": "repo:org/repository marker"}),
        ("search_issues", {"query": "repo:org/repo marker OR repo:evil/repo"}),
        ("search_issues", {"query": "repo:org/repo repo:evil/repo marker"}),
        ("search_issues", {"query": "repo:org/repo NOT marker"}),
        ("delete_repository", {"owner": "org", "repo": "repo"}),
    ]
    for name, args in bad_calls:
        with pytest.raises(mcp_policy.McpPolicyError):
            mcp_policy.validate_call(name, args, TARGET)


def test_github_mcp_parameters_keep_key_out_of_env(tmp_path: Path) -> None:
    params = mcp_policy.github_mcp_stdio_parameters(
        binary=tmp_path / "gms",
        app_id="1",
        installation_id="2",
        private_key_path=tmp_path / "k.pem",
        workdir=tmp_path,
    )
    assert params.env == {}
    assert f"--tools={','.join(mcp_policy.PUBLISHER_TOOLS)}" in params.args
    assert not any("PRIVATE_KEY" in a for a in params.args)
