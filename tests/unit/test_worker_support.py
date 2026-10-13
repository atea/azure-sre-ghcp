"""Shared fakes for the worker/state tests (no test functions here)."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from azure_sre import contracts as c
from azure_sre.state import IncidentRepository, InMemoryEntityStore, InMemoryReportStore
from azure_sre.worker import (
    IncidentProcessor,
    PublicationStatus,
    PublishRequest,
    PublishResult,
    RecoveryRequest,
    RecoveryResult,
    WorkerSettings,
)
from azure_sre.worker.messages import PoisonReason

SUB = "11111111-2222-3333-4444-555555555555"
WS = "66666666-7777-8888-9999-aaaaaaaaaaaa"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
RG = "rg-shop"


def arm(provider: str, rtype: str, name: str) -> str:
    return f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/{provider}/{rtype}/{name}"


APP = arm("Microsoft.App", "containerApps", "shop-api")
AI = arm("Microsoft.Insights", "components", "shop-ai")
ALERT_ID = f"/subscriptions/{SUB}/providers/Microsoft.AlertsManagement/alerts/abc-123"
T0 = datetime(2026, 10, 13, 6, 0, tzinfo=UTC)


def make_registry(repository: str = "contoso/shop") -> c.ApplicationRegistry:
    return c.ApplicationRegistry(
        schema_version=1,
        tenant_id=TENANT,
        applications=(  # type: ignore[arg-type]
            {
                "app_id": "shop",
                "environment": "prod",
                "subscription_id": SUB,
                "container_app_id": APP,
                "app_insights_component_id": AI,
                "log_analytics_workspace_id": WS,
                "repository": repository,
                "installation_id": 42,
            },
        ),
    )


REGISTRY = make_registry()


def make_alert(
    condition: str = "Fired",
    *,
    sink: c.Sink = c.Sink.PRODUCTION,
    alert_id: str = ALERT_ID,
    registry: c.ApplicationRegistry = REGISTRY,
) -> c.NormalizedAlert:
    essentials: dict[str, Any] = {
        "alertId": alert_id,
        "alertRule": "shop-5xx",
        "severity": "Sev2",
        "signalType": "Metric",
        "monitoringService": "Platform",
        "monitorCondition": condition,
        "alertTargetIDs": [APP],
        "firedDateTime": "2026-10-13T06:00:00Z",
    }
    if condition == "Resolved":
        essentials["resolvedDateTime"] = "2026-10-13T06:20:00Z"
    payload = {
        "schemaId": c.ALERT_SCHEMA_ID,
        "data": {"essentials": essentials, "alertContext": None, "customProperties": None},
    }
    return c.normalize_alert(payload, registry, sink=sink)


def complete_report(alert: c.NormalizedAlert, summary: str = "5xx spike") -> c.InvestigationReport:
    window = c.DiagnosticWindow(start=T0 - timedelta(minutes=30), end=T0 + timedelta(minutes=5))
    item = c.EvidenceItem(
        evidence_id="E1",
        provenance=c.EvidenceProvenance(
            source=c.EvidenceSource.CONTAINER_APP_HEALTH,
            template_id="health",
            scope_ref="container_app",
            window=window,
            collected_at=T0,
        ),
        status=c.EvidenceStatus.OK,
        summary="Replica restarts observed",
        row_count=0,
    )
    return c.InvestigationReport(
        schema_version=1,
        incident_key=alert.incident_key,
        alert_id=alert.alert_id,
        app_id=alert.app_id,
        severity=alert.severity,
        sink=alert.sink,
        generated_at=T0,
        status="complete",
        evidence=c.EvidenceBundle(incident_key=alert.incident_key, items=(item,)),
        draft=c.ModelReportDraft(
            status="complete",
            summary=summary,
            observations=(c.Observation(text="Restarts", evidence_refs=("E1",)),),
        ),
    )


class FakeClock:
    def __init__(self, now: datetime = T0) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class FixedRng:
    def uniform(self, a: float, b: float, /) -> float:
        return b


class FakeInvestigator:
    def __init__(self) -> None:
        self.calls = 0
        self.started = asyncio.Event()
        self.cancelled = 0
        self.behavior: Callable[[c.NormalizedAlert], Awaitable[c.InvestigationReport]] | None = None

    async def run(self, alert: c.NormalizedAlert) -> c.InvestigationReport:
        self.calls += 1
        self.started.set()
        try:
            if self.behavior is not None:
                return await self.behavior(alert)
            await asyncio.sleep(0)
            return complete_report(alert)
        except asyncio.CancelledError:
            self.cancelled += 1
            raise


def published_record(request: PublishRequest, number: int = 7) -> c.PublicationRecord:
    return c.PublicationRecord(
        repository=request.repository,
        issue_number=number,
        issue_url=f"https://github.com/{request.repository}/issues/{number}",
        incident_key=request.report.incident_key,
        marker=request.marker,
    )


class FakePublisher:
    """Records calls. ``publish_results``/``reconcile_results`` are consumed in order."""

    def __init__(self) -> None:
        self.publish_calls: list[PublishRequest] = []
        self.reconcile_calls: list[PublishRequest] = []
        self.recover_calls: list[RecoveryRequest] = []
        self.reconcile_recovery_calls: list[RecoveryRequest] = []
        self.publish_results: list[PublishResult | BaseException] = []
        self.reconcile_results: list[PublishResult | BaseException] = []
        self.recover_results: list[RecoveryResult | BaseException] = []
        self.reconcile_recovery_results: list[RecoveryResult | BaseException] = []
        self.issues: dict[str, c.PublicationRecord] = {}
        self.comments: dict[str, int] = {}
        self.publish_gate: asyncio.Event | None = None

    async def publish(self, request: PublishRequest) -> PublishResult:
        self.publish_calls.append(request)
        if self.publish_gate is not None:
            await self.publish_gate.wait()
        if self.publish_results:
            result = self.publish_results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        record = published_record(request)
        self.issues[request.marker] = record
        return PublishResult(status=PublicationStatus.PUBLISHED, record=record)

    async def reconcile(self, request: PublishRequest) -> PublishResult:
        self.reconcile_calls.append(request)
        if self.reconcile_results:
            result = self.reconcile_results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        found = self.issues.get(request.marker)
        if found is None:
            return PublishResult(status=PublicationStatus.ABSENT)
        return PublishResult(status=PublicationStatus.PUBLISHED, record=found)

    async def recover(self, request: RecoveryRequest) -> RecoveryResult:
        self.recover_calls.append(request)
        if self.recover_results:
            result = self.recover_results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        self.comments[request.marker] = 99
        return RecoveryResult(status=PublicationStatus.PUBLISHED, comment_id=99)

    async def reconcile_recovery(self, request: RecoveryRequest) -> RecoveryResult:
        self.reconcile_recovery_calls.append(request)
        if self.reconcile_recovery_results:
            result = self.reconcile_recovery_results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        found = self.comments.get(request.marker)
        if found is None:
            return RecoveryResult(status=PublicationStatus.ABSENT)
        return RecoveryResult(status=PublicationStatus.PUBLISHED, comment_id=found)


def make_settings(**overrides: Any) -> WorkerSettings:
    values: dict[str, Any] = {
        "owner_id": "worker-a",
        "concurrency": 2,
        "investigation_timeout_seconds": 30.0,
        "renew_interval_seconds": 0.01,
        "publish_timeout_seconds": 5.0,
        "lock_renewal_max_seconds": 300.0,
        "shutdown_grace_seconds": 1.0,
        "receive_wait_seconds": 0.01,
        "reconcile_interval_seconds": 0.01,
        "store_backoff_base_seconds": 0.001,
        "store_backoff_max_seconds": 0.002,
    }
    values.update(overrides)
    return WorkerSettings.model_validate(values)


class Harness:
    def __init__(self, **settings: Any) -> None:
        self.clock = FakeClock()
        self.store = InMemoryEntityStore()
        self.reports = InMemoryReportStore()
        self.repo = IncidentRepository(self.store, clock=self.clock)
        self.investigator = FakeInvestigator()
        self.publisher = FakePublisher()
        self.settings = make_settings(**settings)
        self.processor = self.make_processor(self.settings)

    def make_processor(
        self, settings: WorkerSettings, registry: c.ApplicationRegistry = REGISTRY
    ) -> IncidentProcessor:
        return IncidentProcessor(
            repository=self.repo,
            reports=self.reports,
            investigator=self.investigator,
            publisher=self.publisher,
            registry=registry,
            settings=settings,
            rng=FixedRng(),
        )


class FakeMessage:
    def __init__(self, body: bytes | None, message_id: str | None, delivery_count: int = 1) -> None:
        self._body = body
        self._id = message_id
        self._count = delivery_count
        self._lock_lost = asyncio.Event()
        self.settled: list[str] = []
        self.dead_letter_reason: PoisonReason | None = None

    @classmethod
    def of(cls, alert: c.NormalizedAlert, delivery_count: int = 1) -> FakeMessage:
        return cls(alert.model_dump_json().encode(), alert.delivery_id, delivery_count)

    @property
    def message_id(self) -> str | None:
        return self._id

    @property
    def body(self) -> bytes | None:
        return self._body

    @property
    def delivery_count(self) -> int:
        return self._count

    @property
    def lock_lost(self) -> asyncio.Event:
        return self._lock_lost

    async def complete(self) -> None:
        self.settled.append("complete")

    async def abandon(self) -> None:
        self.settled.append("abandon")

    async def dead_letter(self, reason: PoisonReason) -> None:
        self.dead_letter_reason = reason
        self.settled.append("dead_letter")


class FakeSource:
    def __init__(self, messages: list[FakeMessage] | None = None) -> None:
        self.queue: list[FakeMessage] = list(messages or [])
        self.received = 0
        self.closed = False
        self.drained = asyncio.Event()

    async def receive(self, max_messages: int, max_wait_seconds: float) -> list[FakeMessage]:
        if not self.queue:
            self.drained.set()
            await asyncio.sleep(max_wait_seconds)
            return []
        out = self.queue[:max_messages]
        del self.queue[:max_messages]
        self.received += len(out)
        return out

    async def close(self) -> None:
        self.closed = True


async def eventually(predicate: Callable[[], bool], *, attempts: int = 1000) -> None:
    """Poll a condition owned by code under test (bounded; fails rather than hanging)."""
    for _ in range(attempts):
        if predicate():
            return
        await asyncio.sleep(0.005)
    raise AssertionError("condition not reached")
