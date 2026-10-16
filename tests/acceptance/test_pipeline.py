"""Offline full-pipeline acceptance.

Path under test, with no network, auth, or writes outside ``tmp_path``:

ingress ``create_app`` -> normalized queue fake -> ``decode_message`` -> real
``IncidentProcessor`` on ``IncidentRepository`` (in-memory stores) -> real
``CopilotInvestigator`` (fake model backend and collector) -> real ``McpPublisher``
(fake GitHub MCP session factory answering with the real tool schemas).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from azure_sre import contracts as c
from azure_sre.config import AppConfig, BudgetPolicy
from azure_sre.diagnostics.collector import DiagnosticsCollector
from azure_sre.diagnostics.templates import DiagnosticKind
from azure_sre.investigation.investigator import CollectorFactory, CopilotInvestigator
from azure_sre.state.entity_store import InMemoryEntityStore
from azure_sre.state.records import IncidentPhase, issue_marker, recovery_marker
from azure_sre.state.reports import InMemoryReportStore
from azure_sre.state.repository import IncidentRepository
from azure_sre.worker.messages import decode_message
from azure_sre.worker.processor import DriveOutcome, IncidentProcessor

from ..unit.test_contracts import RESOLVED, arm, payload
from ..unit.test_ingress import (
    TEST_OID,
    FakeSender,
    _auth,
    _claims,
    _client,
    _registry_config,
    _token,
)
from ..unit.test_investigation import TOKEN, FakeBackend, FakeCollector, call_tool, draft_json
from ..unit.test_publisher_support import BOT, FakeGitHub, make_publisher
from ..unit.test_worker_support import FakeClock, FixedRng, make_settings

KIND = DiagnosticKind.CONTAINER_APP_HEALTH
OTHER_SUB = "99999999-2222-3333-4444-555555555555"
MAX_BODY_BYTES = 64 * 1024


async def model(tools: Any, prompt: str) -> str:
    """Fake model: calls the diagnostics tool, then cites evidence and echoes a secret."""
    await call_tool(tools, KIND)
    return draft_json(
        summary=f"Health probes failed. Leaked {TOKEN} in logs.",
        observations=[{"text": f"Probe errors, token {TOKEN}", "evidence_refs": ["E1"]}],
    )


class Pipeline:
    """Wires every real component together over fakes at the true external edges."""

    def __init__(
        self,
        tmp_path: Path,
        *,
        config: AppConfig | None = None,
        collector_factory: CollectorFactory | None = None,
    ) -> None:
        self.config = config or _registry_config()
        self.reg = self.config.registry
        self.clock = FakeClock()
        scratch = tmp_path / "scratch"
        private = tmp_path / "private"
        scratch.mkdir()
        private.mkdir()
        self.backend = FakeBackend(script=model)
        self.github = FakeGitHub()
        self.repo = IncidentRepository(InMemoryEntityStore(), clock=self.clock)
        self.processor = IncidentProcessor(
            repository=self.repo,
            reports=InMemoryReportStore(),
            investigator=CopilotInvestigator(
                registry=self.reg,
                collector_factory=collector_factory or (lambda alert, cancel: FakeCollector()),
                backend=self.backend,
                scratch_root=scratch,
                clock=self.clock,
            ),
            publisher=make_publisher(self.github, private, registry=self.reg),
            registry=self.reg,
            settings=make_settings(),
            rng=FixedRng(),
        )
        self.sender = FakeSender()

    async def open(self) -> httpx.AsyncClient:
        client, _, _ = await _client(self.config, self.sender)
        return client

    async def process(self) -> None:
        """Deliver queued messages the way the worker does: serialize, decode, handle."""
        for alert in list(self.sender.sent):
            body = alert.model_dump_json().encode()
            decoded = decode_message(body, alert.delivery_id, self.reg, max_bytes=MAX_BODY_BYTES)
            await self.processor.handle_alert(decoded)
        self.sender.sent.clear()

    async def settle(self, key: str) -> DriveOutcome:
        """Drive an incident until terminal, moving the clock past any retry deadline."""
        for _ in range(20):
            outcome = await self.processor.drive(key)
            if outcome in (DriveOutcome.COMPLETED, DriveOutcome.ABSENT):
                return outcome
            self.clock.advance(7200)
        raise AssertionError("incident did not settle")


def body_for(condition: str, *, targets: list[str] | None = None) -> bytes:
    if condition == "Resolved":
        data = payload(targets, condition="Resolved", resolved=RESOLVED)
    else:
        data = payload(targets)
    return json.dumps(data).encode()


def incident_key(condition: str = "Fired") -> str:
    return c.normalize_alert(payload(condition=condition), _registry_config().registry).incident_key


def calls(p: Pipeline, name: str) -> list[dict[str, Any]]:
    return [args for n, args in p.github.calls if n == name]


async def test_fired_and_resolved_with_lost_responses_stay_one_issue_and_one_comment(
    tmp_path: Path,
) -> None:
    p = Pipeline(tmp_path)
    key = incident_key()
    lost = {"create": False, "comment": False}

    def lose_create(name: str, args: dict[str, Any]) -> None:
        if args["method"] == "create" and not lost["create"]:
            lost["create"] = True
            raise ConnectionError("create response lost")

    def lose_comment(name: str, args: dict[str, Any]) -> None:
        if not lost["comment"]:
            lost["comment"] = True
            raise ConnectionError("comment response lost")

    p.github.after_hooks["issue_write"] = lose_create
    p.github.after_hooks["add_issue_comment"] = lose_comment

    client = await p.open()
    async with client:
        assert (await post_alert(client, "Fired")).status_code == 202
        await p.process()
        assert await p.settle(key) is DriveOutcome.COMPLETED
        assert lost["create"], "create response was lost and reconciled"

        resp = await post_alert(client, "Resolved")
        assert resp.status_code == 202
        await p.process()
        assert await p.settle(key) is DriveOutcome.COMPLETED
        assert lost["comment"], "comment response was lost and reconciled"

        # Redelivery of the same bodies must not reinvestigate or write again.
        writes_before = len(p.github.writes())
        for condition in ("Fired", "Resolved"):
            resp = await client.post(
                "/alerts", content=body_for(condition), headers=_auth(_token(_claims()))
            )
            assert resp.status_code == 202
            await p.process()
        assert await p.settle(key) is DriveOutcome.COMPLETED
        assert len(p.github.writes()) == writes_before

    assert len(p.backend.prompts) == 1, "one investigation per incident"
    creates = [a for a in calls(p, "issue_write") if a["method"] == "create"]
    assert len(creates) == 1, "lost create reconciled, never re-created"
    assert len(p.github.issues) == 1
    ((number, issue),) = p.github.issues.items()
    assert issue["state"] == "open", "Resolved never closes the issue"

    comments = p.github.comments[number]
    assert len(comments) == 1, "lost comment reconciled, redelivery adds nothing"
    assert recovery_marker(key) in comments[0]["body"]

    title, body = issue["title"], issue["body"]
    assert "Sev2" in title
    assert f"<!-- {issue_marker(key)} -->" == body.splitlines()[0]
    assert "E1" in body, "evidence marker from the investigation report"
    assert TOKEN not in title and TOKEN not in body, "secret is redacted"
    assert len(body.encode("utf-8")) <= BudgetPolicy().issue_body_bytes
    assert issue["user"]["login"] == BOT
    for args in calls(p, "issue_write") + calls(p, "add_issue_comment"):
        assert "assignees" not in args, "trusted severity: no model-assigned assignees"

    tools = {t.name: t for t in p.github.tools}
    for name, args in p.github.calls:
        assert name in tools, f"{name} is not a real GitHub MCP tool"
        assert set(args) <= set(tools[name].input_schema["properties"]), f"{name} args off-schema"


async def test_resolved_before_fired_is_held_then_handled_as_one_incident(tmp_path: Path) -> None:
    p = Pipeline(tmp_path)
    key = incident_key()

    client = await p.open()
    async with client:
        resp = await post_alert(client, "Resolved")
        assert resp.status_code == 202
        await p.process()
        assert p.github.calls == [], "nothing published while Fired is missing"
        assert p.backend.prompts == []

        resp = await post_alert(client, "Fired")
        assert resp.status_code == 202
        await p.process()
        assert await p.settle(key) is DriveOutcome.COMPLETED

    assert len(p.backend.prompts) == 1
    assert len(p.github.issues) == 1
    ((number, _),) = p.github.issues.items()
    assert len(p.github.comments[number]) == 1


async def test_dns_failure_survives_sdk_error_and_publishes_separate_probe_suggestion(
    tmp_path: Path,
) -> None:
    from azure_sre.state.records import ImprovementState, improvement_marker
    from tests.unit.test_diagnostics_collector import FakeRunner, ok

    config = _registry_config()
    app = config.registry.applications[0]
    storage_id = (
        f"/subscriptions/{app.subscription_id}/resourceGroups/rg-shop"
        "/providers/Microsoft.Storage/storageAccounts/shopdata"
    )
    app = c.ApplicationMapping.model_validate(app.model_dump() | {"storage_account_id": storage_id})
    reg = c.ApplicationRegistry.model_validate(
        config.registry.model_dump() | {"applications": [app]}
    )
    config = AppConfig.model_validate(config.model_dump() | {"registry": reg})
    runner = FakeRunner(
        ok(
            {
                "name": "shop-api",
                "properties": {
                    "runningStatus": "Running",
                    "template": {
                        "containers": [
                            {
                                "env": [{"name": "AZURE_STORAGE_ACCOUNT_NAME", "value": "shopdat"}],
                                "probes": [{"type": "Readiness", "tcpSocket": {"port": 8000}}],
                            }
                        ]
                    },
                },
            }
        ),
        ok(
            [
                {
                    "ErrorKind": "dependency_dns",
                    "Occurrences": 3,
                    "Log_s": f"Failed to resolve shopdat.table.core.windows.net {TOKEN}",
                }
            ]
        ),
        ok({"properties": {"WorkspaceResourceId": app.log_analytics_workspace_resource_id}}),
        ok([]),
        ok({"id": storage_id, "name": "shopdata", "provisioningState": "Succeeded"}),
    )
    p = Pipeline(
        tmp_path,
        config=config,
        collector_factory=lambda alert, cancel: DiagnosticsCollector(
            registry=reg,
            runner=runner,
            env={},
            cancel=cancel,
        ),
    )

    def sdk_error(tools: Any, prompt: str) -> str:
        raise RuntimeError("model unavailable")

    p.backend.script = sdk_error
    lost = False

    def lose_recommendation(name: str, args: dict[str, Any]) -> None:
        nonlocal lost
        if args["title"].startswith("[suggested improvement]") and not lost:
            lost = True
            raise ConnectionResetError("accepted, response lost")

    p.github.after_hooks["issue_write"] = lose_recommendation
    key = c.normalize_alert(payload(), reg).incident_key
    async with await p.open() as client:
        assert (await post_alert(client, "Fired")).status_code == 202
        await p.process()
        assert await p.settle(key) is DriveOutcome.COMPLETED
        assert (await post_alert(client, "Fired")).status_code == 202
        await p.process()
        assert (await post_alert(client, "Resolved")).status_code == 202
        await p.process()
        assert await p.settle(key) is DriveOutcome.COMPLETED
    loaded = await p.repo.load(key)
    assert loaded and loaded[0].phase is IncidentPhase.PARTIAL_PUBLISHED
    assert loaded[0].improvement_state is ImprovementState.PUBLISHED
    assert loaded[0].recovery_done
    assert len(p.github.issues) == 2
    incident = next(i for i in p.github.issues.values() if issue_marker(key) in i["body"])
    suggestion = next(i for i in p.github.issues.values() if improvement_marker(key) in i["body"])
    assert "sdk_error" in incident["body"]
    assert "Failed to resolve shopdat.table.core.windows.net" in incident["body"]
    assert "shopdata" in incident["body"] and "shopdat" in incident["body"]
    assert "storage.account\\_matches\\_registry" in incident["body"]
    assert "false" in incident["body"]
    assert TOKEN not in incident["body"]
    assert suggestion["title"].startswith("[suggested improvement]")
    assert "not a verified incident root cause" in suggestion["body"]
    assert lost and len(calls(p, "issue_write")) == 2
    assert len(p.github.comments[incident["number"]]) == 1
    assert p.github.comments[suggestion["number"]] == []
    assert len(runner.calls) == 5
    query = next(arg for arg in runner.calls[1][0] if arg.startswith("--analytics-query="))
    assert "isempty(_ResourceId) and ContainerAppName_s" in query


async def test_test_sink_investigates_but_never_touches_github(tmp_path: Path) -> None:
    p = Pipeline(tmp_path)
    key = incident_key()

    client = await p.open()
    async with client:
        resp = await client.post(
            "/alerts", content=body_for("Fired"), headers=_auth(_token(_claims(oid=TEST_OID)))
        )
        assert resp.status_code == 202
        await p.process()
        assert await p.settle(key) is DriveOutcome.COMPLETED

    loaded = await p.repo.load(key)
    assert loaded is not None
    assert loaded[0].phase is IncidentPhase.TEST_SINK_SUPPRESSED
    assert p.github.calls == []
    assert p.github.sessions == []


async def test_receiver_enqueue_failure_returns_503_and_leaves_no_state(tmp_path: Path) -> None:
    p = Pipeline(tmp_path)
    key = incident_key()
    p.sender.fail = True

    client = await p.open()
    async with client:
        resp = await post_alert(client, "Fired")
        assert resp.status_code == 503

    assert p.sender.sent == []
    assert await p.repo.load(key) is None
    assert p.backend.prompts == []


async def test_unknown_scope_is_rejected_before_queue(tmp_path: Path) -> None:
    p = Pipeline(tmp_path)
    unknown = arm("Microsoft.App", "containerApps", "ghost", sub=OTHER_SUB)

    client = await p.open()
    async with client:
        resp = await client.post(
            "/alerts",
            content=body_for("Fired", targets=[unknown]),
            headers=_auth(_token(_claims())),
        )
        assert resp.status_code == 400

    assert p.sender.sent == []
    assert p.backend.prompts == []
    assert p.github.calls == []


async def post_alert(client: httpx.AsyncClient, state: str) -> httpx.Response:
    return await client.post("/alerts", content=body_for(state), headers=_auth(_token(_claims())))
