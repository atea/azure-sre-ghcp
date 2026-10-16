"""Host-owned recommendations; telemetry and model text never choose issue actions."""

from azure_sre.contracts import EvidenceSource, EvidenceStatus, InvestigationReport


def probe_recommendation_refs(report: InvestigationReport) -> tuple[str, ...]:
    return tuple(
        item.evidence_id
        for item in report.evidence.items
        if item.provenance.source is EvidenceSource.CONTAINER_APP_HEALTH
        and item.status is EvidenceStatus.OK
        and any(row.get("probes.suggest_dependency_readiness") is True for row in item.rows)
    )
