from datetime import UTC, datetime
from typing import Any

import pytest

from azure_sre import contracts as c
from azure_sre.contracts import EvidenceSource, EvidenceStatus, HostFindingCode
from azure_sre.github.render import render_issue_body
from azure_sre.investigation.findings import MAX_DNS_HOSTS, derive_host_findings

from .test_worker_support import complete_report, make_alert

T = datetime(2026, 10, 16, 11, 30, tzinfo=UTC)
WINDOW = c.DiagnosticWindow(start=T, end=T.replace(minute=45))
DNS_LOG = (
    "2026-10-16 11:33:08,502 [ERROR] aca_demo: Error creating entity: HTTPSConnection("
    "host='stdemoapp1v2ho7.table.core.windows.net', port=443): Failed to resolve "
    "'stdemoapp1v2ho7.table.core.windows.net' ([Errno -2] Name or service not known)"
)
REVISION = "ca-demoapp1-v2ho77--0000002"


def item(
    evidence_id: str,
    source: EvidenceSource,
    rows: tuple[dict[str, Any], ...],
    status: EvidenceStatus = EvidenceStatus.OK,
) -> c.EvidenceItem:
    return c.EvidenceItem(
        evidence_id=evidence_id,
        provenance=c.EvidenceProvenance(
            source=source,
            template_id="t",
            scope_ref="app:demo/env:dev",
            window=WINDOW,
            collected_at=T,
        ),
        status=status,
        summary="s",
        rows=rows if status is EvidenceStatus.OK else (),
        row_count=len(rows) if status is EvidenceStatus.OK else 0,
        error=None
        if status is EvidenceStatus.OK
        else c.EvidenceError(category=status, message="failed"),
    )


def health(**facts: Any) -> c.EvidenceItem:
    row = {"name": "ca-demo", "storage.setting_status": "configured", **facts}
    return item("E1", EvidenceSource.CONTAINER_APP_HEALTH, (row,))


def errors(*rows: dict[str, Any], status: EvidenceStatus = EvidenceStatus.OK) -> c.EvidenceItem:
    return item("E2", EvidenceSource.CONTAINER_APP_CONSOLE_ERRORS, rows, status)


def dns_row(log: str = DNS_LOG, occurrences: object = "3") -> dict[str, Any]:
    return {
        "ErrorKind": "dependency_dns",
        "RevisionName_s": REVISION,
        "Occurrences": occurrences,
        "Log_s": log,
    }


def http_row(occurrences: object = "4") -> dict[str, Any]:
    return {"ErrorKind": "http_5xx", "RevisionName_s": REVISION, "Occurrences": occurrences}


def bundle(*items: c.EvidenceItem) -> c.EvidenceBundle:
    return c.EvidenceBundle(incident_key="a" * 64, items=items)


def test_dns_failure_for_configured_storage_account_is_a_storage_finding() -> None:
    findings = derive_host_findings(
        bundle(
            health(**{"storage.configured_account": "stdemoapp1v2ho7"}),
            errors(dns_row(), http_row()),
        )
    )
    assert [f.code for f in findings] == [
        HostFindingCode.STORAGE_ACCOUNT_DNS_FAILURE,
        HostFindingCode.HTTP_5XX_WITH_DEPENDENCY_FAILURE,
    ]
    storage, http = findings
    assert '"stdemoapp1v2ho7"' in storage.text
    assert '"stdemoapp1v2ho7.table.core.windows.net"' in storage.text
    assert "3 occurrences" in storage.text
    assert "most likely does not exist" in storage.text
    assert storage.evidence_refs == ("E1", "E2")
    assert REVISION in http.text and "4 occurrences" in http.text
    assert http.evidence_refs == ("E2",)


def test_registry_mismatch_is_reported_when_expected_account_differs() -> None:
    findings = derive_host_findings(
        bundle(
            health(
                **{
                    "storage.configured_account": "stdemoapp1v2ho7",
                    "storage.expected_account": "stdemoapp1v2ho77",
                    "storage.account_matches_registry": False,
                }
            )
        )
    )
    assert [f.code for f in findings] == [HostFindingCode.STORAGE_ACCOUNT_REGISTRY_MISMATCH]
    assert '"stdemoapp1v2ho7"' in findings[0].text
    assert '"stdemoapp1v2ho77"' in findings[0].text


def test_matching_registry_account_produces_no_mismatch() -> None:
    facts = {
        "storage.configured_account": "stdemo",
        "storage.expected_account": "stdemo",
        "storage.account_matches_registry": True,
    }
    assert derive_host_findings(bundle(health(**facts))) == ()


def test_unrelated_dns_host_is_a_generic_dependency_finding() -> None:
    log = "Failed to resolve 'db.internal.example.com' ([Errno -2] Name or service not known)"
    findings = derive_host_findings(
        bundle(health(**{"storage.configured_account": "stdemo"}), errors(dns_row(log, 1)))
    )
    assert [f.code for f in findings] == [HostFindingCode.DEPENDENCY_DNS_FAILURE]
    assert '"db.internal.example.com"' in findings[0].text
    assert "1 occurrence)" in findings[0].text
    assert findings[0].evidence_refs == ("E2",)


def test_generic_dns_findings_are_capped() -> None:
    rows = tuple(dns_row(f"Failed to resolve 'h{i}.example.com'") for i in range(6))
    findings = derive_host_findings(bundle(errors(*rows)))
    assert len(findings) == MAX_DNS_HOSTS


@pytest.mark.parametrize(
    "log",
    [
        "Failed to resolve '<script>.example.com'",
        "Failed to resolve 'not a host'",
        "Failed to resolve '[REDACTED:ip]'",
        "connection refused to db.example.com",
    ],
)
def test_unvalidated_or_non_dns_hosts_are_not_reported(log: str) -> None:
    assert derive_host_findings(bundle(errors(dns_row(log)))) == ()


@pytest.mark.parametrize("account", ["ST_UPPER", "[REDACTED:secret]", "ab", 7, None])
def test_invalid_configured_account_never_reaches_a_finding(account: object) -> None:
    findings = derive_host_findings(
        bundle(health(**{"storage.configured_account": account}), errors(dns_row()))
    )
    assert [f.code for f in findings] == [HostFindingCode.DEPENDENCY_DNS_FAILURE]
    assert "configured storage account" not in findings[0].text


def test_failed_evidence_is_never_used() -> None:
    failed_health = item(
        "E1", EvidenceSource.CONTAINER_APP_HEALTH, ({"n": 1},), EvidenceStatus.ERROR
    )
    assert (
        derive_host_findings(bundle(failed_health, errors(dns_row(), status=EvidenceStatus.ERROR)))
        == ()
    )


def test_http_5xx_without_dns_failure_is_not_correlated() -> None:
    assert derive_host_findings(bundle(errors(http_row()))) == ()


def test_report_rejects_findings_citing_non_ok_evidence() -> None:
    alert = make_alert()
    base = complete_report(alert)
    failed = item("E1", EvidenceSource.CONTAINER_APP_HEALTH, (), EvidenceStatus.ERROR)
    finding = c.HostFinding(
        code=HostFindingCode.DEPENDENCY_DNS_FAILURE, text="x", evidence_refs=("E1",)
    )
    with pytest.raises(ValueError, match="host_findings"):
        c.InvestigationReport.model_validate(
            {
                **base.model_dump(),
                "status": "partial",
                "partial_category": "evidence_missing",
                "draft": None,
                "evidence": bundle(failed).model_copy(update={"incident_key": alert.incident_key}),
                "host_findings": (finding,),
            }
        )


def test_partial_issue_without_draft_leads_with_host_findings() -> None:
    alert = make_alert()
    evidence = bundle(
        health(**{"storage.configured_account": "stdemoapp1v2ho7"}), errors(dns_row())
    ).model_copy(update={"incident_key": alert.incident_key})
    report = c.InvestigationReport(
        schema_version=1,
        incident_key=alert.incident_key,
        alert_id=alert.alert_id,
        app_id=alert.app_id,
        severity=alert.severity,
        sink=alert.sink,
        generated_at=T,
        status="partial",
        partial_category=c.PartialCategory.SDK_ERROR,
        evidence=evidence,
        host_gaps=(
            c.ReportGap(
                description="model session failed during session_open: authentication",
                category=c.PartialCategory.SDK_ERROR,
            ),
        ),
        host_findings=derive_host_findings(evidence),
    )
    body = render_issue_body(
        alert,
        report,
        marker=f"azure-sre:incident:{alert.incident_key}",
        max_bytes=60_000,
        window_before_minutes=15,
        window_after_minutes=5,
    )
    assert "see the host-verified findings below" in body
    findings_at = body.index("## Host-verified findings")
    assert findings_at < body.index("## Alert")
    assert 'configured storage account "stdemoapp1v2ho7" failed DNS' in body
