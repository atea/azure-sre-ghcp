"""Azure wiring for the worker: managed identity only, no secrets, no fallback credential."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final

from azure.identity.aio import ManagedIdentityCredential

from azure_sre.config import AppConfig
from azure_sre.state.reports import AzureBlobReportStore
from azure_sre.state.repository import IncidentRepository
from azure_sre.state.table_store import AzureTableEntityStore
from azure_sre.worker.host import WorkerHost, install_stop_signals
from azure_sre.worker.processor import IncidentProcessor
from azure_sre.worker.protocols import Investigator, Publisher
from azure_sre.worker.queue import ServiceBusMessageSource
from azure_sre.worker.settings import WorkerSettings

__all__ = ["AzureWorkerEndpoints", "run_worker"]

_GUID_RE: Final = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_NAMESPACE_RE: Final = re.compile(r"^[a-z][a-z0-9-]{4,48}[a-z0-9]\.servicebus\.windows\.net$")
_QUEUE_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,259}$")
_SECRET_HINT: Final = re.compile(r"(?i)(sharedaccess|accountkey|sig=|endpoint=|;)")


@dataclass(frozen=True)
class AzureWorkerEndpoints:
    """Reviewed resource coordinates. Connection strings and keys are rejected."""

    managed_identity_client_id: str
    service_bus_namespace: str
    queue_name: str
    table_endpoint: str
    table_name: str
    blob_endpoint: str
    report_container: str = field(default="sre-evidence")

    def __post_init__(self) -> None:
        values = (
            self.managed_identity_client_id,
            self.service_bus_namespace,
            self.queue_name,
            self.table_endpoint,
            self.table_name,
            self.blob_endpoint,
            self.report_container,
        )
        if any(_SECRET_HINT.search(v) for v in values):
            raise ValueError("endpoints must not contain connection strings or keys")
        if not _GUID_RE.match(self.managed_identity_client_id):
            raise ValueError("managed_identity_client_id must be a GUID")
        if not _NAMESPACE_RE.match(self.service_bus_namespace):
            raise ValueError("service_bus_namespace must be a *.servicebus.windows.net FQDN")
        if not _QUEUE_RE.match(self.queue_name):
            raise ValueError("invalid queue name")


async def run_worker(
    config: AppConfig,
    endpoints: AzureWorkerEndpoints,
    investigator: Investigator,
    publisher: Publisher,
    *,
    settings: WorkerSettings | None = None,
    handle_signals: bool = True,
) -> None:
    """Run the durable worker until SIGTERM/SIGINT; raises ``WorkerFatalError`` on failure.

    Only ``ManagedIdentityCredential(client_id=...)`` is used - there is no
    developer/CLI/environment fallback. ``Sink.TEST`` alerts are investigated and
    persisted but never reach ``publisher``.
    """
    worker_settings = settings or WorkerSettings.from_config(config)
    if worker_settings.concurrency > config.budget.concurrency_per_replica:
        raise ValueError("concurrency exceeds the configured budget")
    credential = ManagedIdentityCredential(client_id=endpoints.managed_identity_client_id)
    entities = AzureTableEntityStore(
        endpoint=endpoints.table_endpoint, table_name=endpoints.table_name, credential=credential
    )
    reports = AzureBlobReportStore(
        account_url=endpoints.blob_endpoint,
        container_name=endpoints.report_container,
        credential=credential,
    )
    source = ServiceBusMessageSource(
        fully_qualified_namespace=endpoints.service_bus_namespace,
        queue_name=endpoints.queue_name,
        credential=credential,
        lock_renewal_max_seconds=worker_settings.lock_renewal_max_seconds,
    )
    try:
        repository = IncidentRepository(entities)
        processor = IncidentProcessor(
            repository=repository,
            reports=reports,
            investigator=investigator,
            publisher=publisher,
            registry=config.registry,
            settings=worker_settings,
        )
        host = WorkerHost(
            source=source,
            processor=processor,
            repository=repository,
            registry=config.registry,
            settings=worker_settings,
        )
        if handle_signals:
            install_stop_signals(host)
        await host.run()
    finally:
        errors: list[Exception] = []
        for close in (source.close, reports.close, entities.close, credential.close):
            try:
                await close()
            except Exception as exc:  # noqa: BLE001 - all cleanup failures are re-raised
                errors.append(exc)
        if errors:
            raise ExceptionGroup("Worker resource cleanup failed.", errors)
