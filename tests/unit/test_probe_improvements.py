"""Probe assessment and independently durable, verified recommendation issues."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from azure_sre import contracts as c
from azure_sre.diagnostics.templates import project_probe_assessment
from azure_sre.github.recommendations import probe_recommendation_refs
from azure_sre.github.render import RenderError, render_probe_improvement
from azure_sre.state.records import (
    ImprovementState,
    IncidentPhase,
    decode_incident,
    encode_incident,
    improvement_marker,
)
from azure_sre.worker import DriveOutcome, PublicationStatus, PublishRequest, PublishResult
from tests.unit.test_publisher_support import FakeGitHub, make_publisher, publish_request
from tests.unit.test_worker_support import (
    Harness,
    complete_report,
    make_alert,
    published_record,
)


def probe_report(alert: c.NormalizedAlert) -> c.InvestigationReport:
    base = complete_report(alert)
    assessment = project_probe_assessment(
        {
            "properties": {
                "template": {
                    "containers": [
                        {
                            "probes": [
                                {"type": "Readiness", "tcpSocket": {"port": 8000}},
                                {"type": "Liveness", "tcpSocket": {"port": 8000}},
                            ],
                        }
                    ]
                }
            },
        }
    )
    item = c.EvidenceItem.model_validate(
        {
            **base.evidence.items[0].model_dump(),
            "rows": [assessment],
            "row_count": 1,
        }
    )
    return c.InvestigationReport.model_validate(
        {
            **base.model_dump(),
            "evidence": c.EvidenceBundle(incident_key=alert.incident_key, items=(item,)),
        }
    )


def improvement_request() -> PublishRequest:
    base = publish_request()
    return PublishRequest.model_validate(
        {
            **base.model_dump(),
            "report": probe_report(base.alert),
            "purpose": "probe_improvement",
            "marker": improvement_marker(base.alert.incident_key),
        }
    )


@pytest.mark.parametrize(
    ("probes", "suggest"),
    [
        ([{"type": "Readiness", "tcpSocket": {"port": 8000}}], True),
        ([{"type": "Liveness", "tcpSocket": {"port": 8000}}], True),
        ([], True),
        ([{"type": "Readiness", "httpGet": {"path": "/health", "port": 8000}}], False),
    ],
)
def test_probe_assessment_distinguishes_readiness_from_liveness(
    probes: list[dict[str, Any]],
    suggest: bool,
) -> None:
    result = project_probe_assessment(
        {
            "properties": {"template": {"containers": [{"probes": probes}]}},
        }
    )
    assert result["probes.suggest_dependency_readiness"] is suggest


@pytest.mark.parametrize(
    "containers", [None, [], ["bad"], [{"probes": "bad"}], [{"probes": [{"type": "Readiness"}]}]]
)
def test_malformed_probe_data_is_unknown_not_a_recommendation(containers: Any) -> None:
    result = project_probe_assessment({"properties": {"template": {"containers": containers}}})
    assert result == {"probes.assessment": "unknown"}


def test_improvement_renderer_explains_limits_without_claiming_a_root_cause() -> None:
    request = improvement_request()
    title, body = render_probe_improvement(
        request.alert,
        request.report,
        marker=request.marker,
        max_bytes=24576,
    )
    assert title.startswith("[suggested improvement]")
    assert body.startswith(f"<!-- {request.marker} -->")
    assert "not a verified incident root cause" in body
    assert "HTTP probes alone do not prove dependency coverage" in body
    assert "E1" in body
    assert "restart loops" in body
    with pytest.raises(RenderError):
        render_probe_improvement(
            request.alert, request.report, marker=request.marker, max_bytes=100
        )


async def test_improvement_publisher_creates_and_verifies_separate_issue(tmp_path: Path) -> None:
    github = FakeGitHub()
    publisher = make_publisher(github, tmp_path)
    incident = await publisher.publish(publish_request())
    result = await publisher.publish(improvement_request())
    assert result.status is PublicationStatus.PUBLISHED
    assert result.record and incident.record
    assert result.record.issue_number != incident.record.issue_number
    assert result.record.marker != incident.record.marker
    assert github.issues[result.record.issue_number]["title"].startswith("[suggested improvement]")
    reconciled = await publisher.reconcile(improvement_request())
    assert reconciled.record == result.record
    assert github.writes() == ["issue_write", "issue_write"]


async def test_improvement_publisher_rejects_missing_evidence_and_wrong_marker(
    tmp_path: Path,
) -> None:
    github = FakeGitHub()
    publisher = make_publisher(github, tmp_path)
    req = improvement_request()
    for updates in [
        {"report": complete_report(req.alert)},
        {"marker": publish_request().marker},
        {"sink": c.Sink.TEST, "alert": make_alert(sink=c.Sink.TEST)},
    ]:
        result = await publisher.publish(req.model_copy(update=updates))
        assert result.status is PublicationStatus.ABSENT
    assert github.calls == []


async def configure_probe_report(h: Harness) -> None:
    async def investigate(alert: c.NormalizedAlert) -> c.InvestigationReport:
        return probe_report(alert)

    h.investigator.behavior = investigate


async def test_recommendation_state_roundtrips_and_redelivery_never_duplicates() -> None:
    h = Harness()
    await configure_probe_report(h)
    alert = make_alert()
    assert await h.processor.handle_alert(alert) is DriveOutcome.COMPLETED
    loaded = await h.repo.load(alert.incident_key)
    assert loaded is not None
    record = loaded[0]
    assert record.phase is IncidentPhase.PUBLISHED
    assert record.improvement_state is ImprovementState.PUBLISHED
    assert record.improvement_publication and record.publication
    assert record.improvement_publication.issue_number != record.publication.issue_number
    assert decode_incident(alert.incident_key, encode_incident(record)) == record
    assert not record.is_active
    await h.make_processor(h.settings).handle_alert(alert)
    assert [r.purpose for r in h.publisher.publish_calls] == ["incident", "probe_improvement"]
    assert h.investigator.calls == 1


async def test_accepted_recommendation_with_lost_response_reconciles_after_restart() -> None:
    h = Harness()
    await configure_probe_report(h)
    alert = make_alert()
    real_publish = h.publisher.publish

    async def lose_response(request: PublishRequest) -> PublishResult:
        if request.purpose == "probe_improvement":
            loaded = await h.repo.load(alert.incident_key)
            assert loaded and loaded[0].improvement_state is ImprovementState.WRITING
            assert loaded[0].improvement_intent_at is not None
            await real_publish(request)
            raise ConnectionResetError("accepted remotely")
        return await real_publish(request)

    h.publisher.publish = lose_response  # type: ignore[method-assign]
    assert await h.processor.handle_alert(alert) is DriveOutcome.DEFERRED
    loaded = await h.repo.load(alert.incident_key)
    assert loaded and loaded[0].improvement_state is ImprovementState.UNCERTAIN
    assert loaded[0].is_active
    h.clock.advance(1000)
    assert await h.make_processor(h.settings).drive(alert.incident_key) is DriveOutcome.COMPLETED
    loaded = await h.repo.load(alert.incident_key)
    assert loaded and loaded[0].improvement_state is ImprovementState.PUBLISHED
    assert len(h.publisher.publish_calls) == 2
    assert len(h.publisher.reconcile_calls) == 1
    assert h.publisher.reconcile_calls[0].purpose == "probe_improvement"


async def test_cancelled_recommendation_resumes_with_read_not_create() -> None:
    h = Harness()
    await configure_probe_report(h)
    alert = make_alert()
    real_publish = h.publisher.publish
    started = asyncio.Event()

    async def hang(request: PublishRequest) -> PublishResult:
        if request.purpose == "probe_improvement":
            h.publisher.issues[request.marker] = published_record(request, 8)
            started.set()
            await asyncio.Event().wait()
        return await real_publish(request)

    h.publisher.publish = hang  # type: ignore[method-assign]
    task = asyncio.create_task(h.processor.handle_alert(alert))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    loaded = await h.repo.load(alert.incident_key)
    assert loaded and loaded[0].improvement_state is ImprovementState.WRITING
    h.clock.advance(1000)
    assert await h.make_processor(h.settings).drive(alert.incident_key) is DriveOutcome.COMPLETED
    assert len(h.publisher.reconcile_calls) == 1
    assert len(h.publisher.publish_calls) == 1  # the incident only; no second recommendation write


async def test_recommendation_exhaustion_does_not_block_incident_recovery() -> None:
    h = Harness(max_reconcile_attempts=1)
    await configure_probe_report(h)
    alert = make_alert()
    real_publish = h.publisher.publish

    async def fail(request: PublishRequest) -> PublishResult:
        if request.purpose == "probe_improvement":
            raise ConnectionError("ambiguous")
        return await real_publish(request)

    h.publisher.publish = fail  # type: ignore[method-assign]
    h.publisher.reconcile_results = [PublishResult(status=PublicationStatus.UNCERTAIN)]
    await h.processor.handle_alert(alert)
    h.clock.advance(1000)
    await h.processor.drive(alert.incident_key)
    h.clock.advance(1000)
    await h.processor.drive(alert.incident_key)
    loaded = await h.repo.load(alert.incident_key)
    assert loaded and loaded[0].phase is IncidentPhase.PUBLISHED
    assert loaded[0].improvement_state is ImprovementState.OPERATOR_REQUIRED
    assert loaded[0].improvement_reason == "improvement_uncertain"
    await h.processor.handle_alert(make_alert("Resolved"))
    assert len(h.publisher.recover_calls) == 1


async def test_uncertain_recommendation_is_not_recreated_before_absence_settles() -> None:
    h = Harness()
    await configure_probe_report(h)
    alert = make_alert()
    real_publish = h.publisher.publish
    writes = 0

    async def uncertain_first(request: PublishRequest) -> PublishResult:
        nonlocal writes
        if request.purpose == "probe_improvement":
            writes += 1
            if writes == 1:
                return PublishResult(status=PublicationStatus.UNCERTAIN)
        return await real_publish(request)

    h.publisher.publish = uncertain_first  # type: ignore[method-assign]
    assert await h.processor.handle_alert(alert) is DriveOutcome.DEFERRED
    h.clock.advance(20)
    assert await h.processor.drive(alert.incident_key) is DriveOutcome.DEFERRED
    loaded = await h.repo.load(alert.incident_key)
    assert loaded and loaded[0].improvement_state is ImprovementState.UNCERTAIN
    assert writes == 1
    h.clock.advance(h.settings.not_found_settle_seconds)
    assert await h.processor.drive(alert.incident_key) is DriveOutcome.DEFERRED
    loaded = await h.repo.load(alert.incident_key)
    assert loaded and loaded[0].improvement_state is ImprovementState.PENDING
    assert writes == 1
    h.clock.advance(1000)
    assert await h.processor.drive(alert.incident_key) is DriveOutcome.COMPLETED
    assert writes == 2


async def test_probe_recommendations_never_publish_for_test_sink() -> None:
    h = Harness()
    await configure_probe_report(h)
    await h.processor.handle_alert(make_alert(sink=c.Sink.TEST))
    assert h.publisher.publish_calls == []
    assert h.publisher.reconcile_calls == []


def test_no_recommendation_without_positive_host_evidence() -> None:
    assert probe_recommendation_refs(complete_report(make_alert())) == ()
