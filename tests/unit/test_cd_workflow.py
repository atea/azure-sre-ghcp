import os
import re
import shutil
import subprocess
from pathlib import Path
from textwrap import dedent

import pytest

WORKFLOW = (Path(__file__).parents[2] / ".github/workflows/cd.yml").read_text()
BASH = shutil.which("bash")
assert BASH is not None


def workflow_step(name: str) -> str:
    match = re.search(
        rf"^      - name: {re.escape(name)}\n.*?(?=^      - |\Z)",
        WORKFLOW,
        re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"Missing workflow step: {name}"
    return match.group()


def run_block(name: str) -> str:
    _, separator, script = workflow_step(name).partition("        run: |\n")
    assert separator, f"Missing shell script: {name}"
    return dedent(script)


def run_shell(script: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    assert BASH is not None
    return subprocess.run(  # noqa: S603 -- executes reviewed repository workflow blocks with mocks
        [BASH, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
        env={"PATH": os.defpath, **env},
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def settings() -> dict[str, str]:
    return {
        "CLIENT_ID": "application-client",
        "TENANT_ID": "tenant",
        "SUBSCRIPTION_ID": "subscription",
        "RESOURCE_GROUP": "rg-dev",
        "ACR_NAME": "devregistry",
        "DEPLOY": "false",
    }


@pytest.mark.parametrize(
    ("deploy", "apps", "error"),
    [
        ("false", {}, None),
        ("false", {"RECEIVER_APP": "", "WORKER_APP": ""}, None),
        ("false", {"RECEIVER_APP": "same", "WORKER_APP": "same"}, None),
        ("true", {}, "Missing environment variable RECEIVER_APP"),
        (
            "true",
            {"RECEIVER_APP": "", "WORKER_APP": "worker"},
            "Missing environment variable RECEIVER_APP",
        ),
        ("true", {"RECEIVER_APP": "receiver"}, "Missing environment variable WORKER_APP"),
        (
            "true",
            {"RECEIVER_APP": "receiver", "WORKER_APP": ""},
            "Missing environment variable WORKER_APP",
        ),
        (
            "true",
            {"RECEIVER_APP": "same", "WORKER_APP": "same"},
            "Receiver and worker must be different Container Apps",
        ),
        ("true", {"RECEIVER_APP": "receiver", "WORKER_APP": "worker"}, None),
    ],
)
def test_preflight_app_requirements(
    settings: dict[str, str], deploy: str, apps: dict[str, str], error: str | None
) -> None:
    result = run_shell(
        run_block("Check deployment settings"), {**settings, "DEPLOY": deploy, **apps}
    )
    if error is None:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0
        assert f"::error::{error}" in result.stdout


@pytest.mark.parametrize(
    "setting", ["CLIENT_ID", "TENANT_ID", "SUBSCRIPTION_ID", "RESOURCE_GROUP", "ACR_NAME"]
)
@pytest.mark.parametrize("unset", [False, True])
def test_bootstrap_requires_shared_settings(
    settings: dict[str, str], setting: str, unset: bool
) -> None:
    if unset:
        del settings[setting]
    else:
        settings[setting] = ""
    result = run_shell(run_block("Check deployment settings"), settings)
    assert result.returncode != 0
    assert f"::error::Missing environment variable {setting}" in result.stdout


@pytest.mark.parametrize("deploy", ["false", "true"])
def test_registry_setup_only_checks_apps_when_deploying(
    settings: dict[str, str], tmp_path: Path, deploy: str
) -> None:
    calls = tmp_path / "azure-calls"
    output = tmp_path / "github-output"
    mock = """
    az() {
      printf '%s\\n' "$*" >> "$AZ_CALLS"
      if [[ "$1 $2" == "acr show" ]]; then
        printf '%s\\n' "devregistry.azurecr.io"
      fi
    }
    """
    apps = {"RECEIVER_APP": "receiver", "WORKER_APP": "worker"} if deploy == "true" else {}
    result = run_shell(
        dedent(mock) + run_block("Verify infrastructure and sign in to ACR"),
        {
            **settings,
            **apps,
            "DEPLOY": deploy,
            "AZ_CALLS": str(calls),
            "GITHUB_OUTPUT": str(output),
        },
    )
    assert result.returncode == 0, result.stderr
    expected = []
    if deploy == "true":
        expected = [
            "extension add --name containerapp --upgrade --yes",
            "containerapp show --resource-group rg-dev --name receiver --output none",
            "containerapp show --resource-group rg-dev --name worker --output none",
        ]
    assert calls.read_text().splitlines() == [
        *expected,
        "acr show --name devregistry --query loginServer --output tsv",
        "acr login --name devregistry",
    ]
    assert output.read_text() == "server=devregistry.azurecr.io\n"


def test_login_and_rollout_contract() -> None:
    client_id = "${{ secrets.AZURE_APP_CLIENT_ID }}"
    assert f"CLIENT_ID: {client_id}" in workflow_step("Check deployment settings")
    assert f"client-id: {client_id}" in workflow_step("Sign in to Azure with OIDC")
    assert "DEPLOY: ${{ github.event_name != 'workflow_dispatch' || inputs.deploy }}" in WORKFLOW
    for name in ("Deploy image to receiver and worker", "Check receiver readiness over HTTPS"):
        assert "if: env.DEPLOY == 'true'" in workflow_step(name)
    smoke = workflow_step("Verify offline gates in the built image")
    assert "if:" not in smoke
    assert "Published shared image" in smoke
    assert "/azure-sre-copilot@${{ steps.build.outputs.digest }}" in smoke


def test_workflow_shell_syntax() -> None:
    scripts = re.findall(r"^        run: \|\n((?:          .*\n|\n)+)", WORKFLOW, re.MULTILINE)
    assert scripts
    for script in scripts:
        assert BASH is not None
        result = subprocess.run(  # noqa: S603 -- syntax-checks repository shell blocks only
            [BASH, "-n"], input=dedent(script), capture_output=True, text=True, check=False
        )
        assert result.returncode == 0, result.stderr
