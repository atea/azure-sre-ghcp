"""Host wiring for the investigator; credentials remain outside model tools."""

from __future__ import annotations

import os
import threading
import uuid
from pathlib import Path

import httpx

from azure_sre.config import AppConfig
from azure_sre.contracts import NormalizedAlert
from azure_sre.diagnostics.cli_session import AzureCliSession
from azure_sre.diagnostics.collector import DiagnosticsCollector
from azure_sre.diagnostics.executor import SubprocessRunner
from azure_sre.investigation.backend import SdkModelBackend, TokenSupplier
from azure_sre.investigation.investigator import CopilotInvestigator
from azure_sre.runtime.sdk_policy import validate_inference_auth_mode
from azure_sre.security.github_app import InstallationTokenProvider
from azure_sre.security.key_vault import PatLoader, PrivateKeyLoader
from azure_sre.security.pat_provider import PatTokenProvider


def build_inference_supplier(
    *,
    auth_mode: str,
    http: httpx.AsyncClient,
    client_id: str,
    vault_url: str,
    secret_name: str,
    app_id: str | None = None,
    installation_id: str | None = None,
) -> TokenSupplier:
    """Return the host-side SDK token supplier for the configured inference auth mode."""
    mode = validate_inference_auth_mode(auth_mode)
    if mode == "pat":
        return PatTokenProvider(
            load_pat=PatLoader(vault_url=vault_url, secret_name=secret_name, client_id=client_id)
        ).for_sdk
    if not app_id or not installation_id:
        raise ValueError("App inference mode requires an App ID and installation ID.")
    return InstallationTokenProvider(
        app_id=app_id,
        installation_id=installation_id,
        load_private_key=PrivateKeyLoader(
            vault_url=vault_url, secret_name=secret_name, client_id=client_id
        ),
        client=http,
    ).for_sdk


def build_investigator(
    config: AppConfig,
    *,
    cli: AzureCliSession,
    root: Path,
    http: httpx.AsyncClient,
    client_id: str,
    inference_auth_mode: str,
    inference_vault_url: str,
    inference_secret_name: str,
    runtime_path: str,
    model: str,
    inference_app_id: str | None = None,
    inference_installation_id: str | None = None,
) -> CopilotInvestigator:
    supplier = build_inference_supplier(
        auth_mode=inference_auth_mode,
        http=http,
        client_id=client_id,
        vault_url=inference_vault_url,
        secret_name=inference_secret_name,
        app_id=inference_app_id,
        installation_id=inference_installation_id,
    )
    backend = SdkModelBackend(
        runtime_path=runtime_path,
        extra_env={"COPILOT_SKIP_CLI_DOWNLOAD": "1"},
        initial_token_supplier=supplier,
        refresh_token_supplier=supplier,
        model=model,
    )

    def collector_factory(alert: NormalizedAlert, cancel: threading.Event) -> DiagnosticsCollector:
        return DiagnosticsCollector(
            registry=config.registry,
            runner=SubprocessRunner(),
            env=cli.worker_env(uuid.uuid4().hex),
            budget=config.budget,
            cancel=cancel,
        )

    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    return CopilotInvestigator(
        registry=config.registry,
        collector_factory=collector_factory,
        backend=backend,
        scratch_root=root,
        budget=config.budget,
    )
