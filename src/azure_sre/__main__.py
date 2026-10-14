"""Role entrypoint for the shared Container Apps image."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import httpx
import uvicorn
from azure.identity.aio import ManagedIdentityCredential

from azure_sre.bootstrap import load_service_config
from azure_sre.diagnostics.cli_session import AzureCliSession
from azure_sre.diagnostics.executor import SubprocessRunner
from azure_sre.github.publisher import McpPublisher
from azure_sre.ingress.app import create_app
from azure_sre.ingress.servicebus import ServiceBusAlertSender
from azure_sre.ingress.settings import IngressSettings
from azure_sre.pipeline import build_investigator
from azure_sre.runtime.sdk_policy import DEFAULT_INFERENCE_AUTH_MODE, validate_inference_auth_mode
from azure_sre.security.key_vault import PrivateKeyLoader
from azure_sre.worker.service import AzureWorkerEndpoints, run_worker

logger = logging.getLogger(__name__)


def required_setting(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"Required deployment setting is missing: {name}")
    return value


async def serve_receiver() -> None:
    config = await load_service_config(os.environ)
    settings = IngressSettings(
        tenant_id=config.registry.tenant_id,
        audience=required_setting("SRE_WEBHOOK_AUDIENCE"),
        expected_caller_app_id=required_setting("SRE_MONITOR_APP_ID"),
        expected_role=required_setting("SRE_WEBHOOK_ROLE"),
    )
    port = int(os.environ.get("SRE_PORT", "8080"))
    if not 1 <= port <= 65535:
        raise ValueError("SRE_PORT must be between 1 and 65535.")
    credential = ManagedIdentityCredential(client_id=required_setting("AZURE_CLIENT_ID"))
    sender = ServiceBusAlertSender(
        required_setting("AZURE_SERVICEBUS_NAMESPACE"),
        required_setting("AZURE_SERVICEBUS_QUEUE_NAME"),
        credential=credential,
    )
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(config, sender, settings=settings),
            host="0.0.0.0",  # noqa: S104 - Container Apps ingress proxy terminates TLS
            port=port,
            access_log=False,
            log_level="info",
        )
    )
    await server.serve()


async def run_role(role: str) -> None:
    if role == "receiver":
        await serve_receiver()
        return
    await serve_worker()


@dataclass(frozen=True)
class InferenceSettings:
    auth_mode: str
    vault_url: str
    secret_name: str
    app_id: str | None = None
    installation_id: str | None = None


def resolve_inference_settings(
    env: Mapping[str, str], *, publisher_app_id: str, publisher_secret_name: str
) -> InferenceSettings:
    """Resolve inference credentials for ``SRE_INFERENCE_AUTH_MODE`` (``pat`` default, or ``app``).

    Inference and publisher credentials must always reference separate secrets.
    """

    def required(name: str) -> str:
        value = env.get(name, "").strip()
        if not value:
            raise ValueError(f"Required deployment setting is missing: {name}")
        return value

    mode = validate_inference_auth_mode(
        env.get("SRE_INFERENCE_AUTH_MODE", "").strip() or DEFAULT_INFERENCE_AUTH_MODE
    )
    app_id: str | None = None
    installation_id: str | None = None
    if mode == "pat":
        secret = required("SRE_INFERENCE_PAT_SECRET")
    else:
        secret = required("SRE_INFERENCE_KEY_SECRET")
        app_id = required("SRE_INFERENCE_APP_ID")
        installation_id = required("SRE_INFERENCE_INSTALLATION_ID")
        if app_id == publisher_app_id:
            raise ValueError("Inference and publisher GitHub Apps must be separate.")
    if secret == publisher_secret_name:
        raise ValueError("Inference and publisher credentials must use separate vault secrets.")
    return InferenceSettings(
        auth_mode=mode,
        vault_url=required("SRE_INFERENCE_VAULT_URL"),
        secret_name=secret,
        app_id=app_id,
        installation_id=installation_id,
    )


async def serve_worker() -> None:
    config = await load_service_config(os.environ)
    if config.publisher is None:
        raise ValueError("Worker requires the separate publisher Key Vault reference.")
    client_id = required_setting("AZURE_CLIENT_ID")
    publisher_app_id = required_setting("SRE_PUBLISHER_APP_ID")
    inference = resolve_inference_settings(
        os.environ,
        publisher_app_id=publisher_app_id,
        publisher_secret_name=config.publisher.secret_name,
    )
    endpoints = AzureWorkerEndpoints(
        managed_identity_client_id=client_id,
        service_bus_namespace=required_setting("AZURE_SERVICEBUS_NAMESPACE"),
        queue_name=required_setting("AZURE_SERVICEBUS_QUEUE_NAME"),
        table_endpoint=required_setting("AZURE_STORAGE_TABLE_URL"),
        table_name=required_setting("SRE_STATE_TABLE_NAME"),
        blob_endpoint=required_setting("AZURE_STORAGE_BLOB_URL"),
        report_container=required_setting("SRE_EVIDENCE_CONTAINER_NAME"),
    )
    scratch = Path(os.environ.get("SRE_SCRATCH_ROOT", "/var/lib/sre/work"))
    await asyncio.to_thread(scratch.mkdir, parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="worker-", dir=scratch) as temporary:
        root = Path(temporary)
        cli = AzureCliSession(
            root=root / "azure",
            client_id=client_id,
            extension_dir=Path(os.environ.get("AZURE_EXTENSION_DIR", "/opt/az-ext")),
            runner=SubprocessRunner(),
            identity_env=os.environ,
        )
        await asyncio.to_thread(cli.initialize)
        async with httpx.AsyncClient() as http:
            investigator = build_investigator(
                config,
                cli=cli,
                root=root / "investigations",
                http=http,
                client_id=client_id,
                runtime_path=required_setting("COPILOT_CLI_PATH"),
                model=required_setting("SRE_MODEL"),
                inference_auth_mode=inference.auth_mode,
                inference_vault_url=inference.vault_url,
                inference_secret_name=inference.secret_name,
                inference_app_id=inference.app_id,
                inference_installation_id=inference.installation_id,
            )
            publisher = McpPublisher(
                registry=config.registry,
                budget=config.budget,
                binary=Path(os.environ.get("GITHUB_MCP_SERVER_PATH", "/opt/gms/github-mcp-server")),
                app_id=publisher_app_id,
                author_login=required_setting("SRE_PUBLISHER_BOT_LOGIN"),
                load_private_key=PrivateKeyLoader(
                    vault_url=config.publisher.key_vault_uri,
                    secret_name=config.publisher.secret_name,
                    client_id=client_id,
                ),
                private_root=root,
            )
            await run_worker(config, endpoints, investigator, publisher)


def main() -> None:
    parser = argparse.ArgumentParser(description="Azure SRE Copilot container role")
    parser.add_argument("role", choices=("receiver", "worker"))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    try:
        asyncio.run(run_role(args.role))
    except Exception as exc:  # noqa: BLE001 - fatal process boundary, safe category and nonzero exit
        logger.error("service failed category=%s", type(exc).__name__)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
