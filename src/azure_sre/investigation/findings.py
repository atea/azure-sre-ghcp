"""Deterministic host findings: fixed-template correlations of OK evidence.

Findings never depend on the model, so they survive SDK failures. Every value interpolated
into a finding is re-validated against a strict pattern; anything else is skipped.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any, Final

from azure_sre.contracts import (
    EvidenceBundle,
    EvidenceItem,
    EvidenceSource,
    EvidenceStatus,
    HostFinding,
    HostFindingCode,
)

MAX_DNS_HOSTS: Final = 3
_STORAGE_ACCOUNT = re.compile(r"[a-z0-9]{3,24}")
_STORAGE_HOST = re.compile(
    r"(?<![a-z0-9.-])([a-z0-9]{3,24})\.(blob|table|queue|file|dfs)\.core\.windows\.net(?![a-z0-9-])"
)
_RESOLVE_HOST = re.compile(r"[Ff]ailed to resolve '?([A-Za-z0-9.-]{1,253})'?")
_HOSTNAME = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
_REVISION = re.compile(r"[a-z0-9][a-z0-9-]{0,99}")


def derive_host_findings(bundle: EvidenceBundle) -> tuple[HostFinding, ...]:
    health = _first_row(bundle, EvidenceSource.CONTAINER_APP_HEALTH)
    errors = _ok_items(bundle, EvidenceSource.CONTAINER_APP_CONSOLE_ERRORS)
    findings: list[HostFinding] = []

    configured = _account(health[1].get("storage.configured_account")) if health else None
    expected = _account(health[1].get("storage.expected_account")) if health else None
    if (
        health
        and configured
        and expected
        and health[1].get("storage.account_matches_registry") is False
    ):
        findings.append(
            HostFinding(
                code=HostFindingCode.STORAGE_ACCOUNT_REGISTRY_MISMATCH,
                text=(
                    f'The app is configured for storage account "{configured}", but the '
                    f'registered dependency is "{expected}".'
                ),
                evidence_refs=(health[0].evidence_id,),
            )
        )

    dns: dict[str, tuple[int, set[str]]] = {}
    for item in errors:
        for row in item.rows:
            if row.get("ErrorKind") != "dependency_dns":
                continue
            log = row.get("Log_s")
            if not isinstance(log, str):
                continue
            count = _count(row.get("Occurrences"))
            for host in _dns_hosts(log):
                total, refs = dns.get(host, (0, set()))
                dns[host] = (total + count, refs | {item.evidence_id})

    covered: set[str] = set()
    if health and configured:
        for host, (count, refs) in sorted(dns.items()):
            match = _STORAGE_HOST.fullmatch(host)
            if match is None or match.group(1) != configured:
                continue
            covered.add(host)
            findings.append(
                HostFinding(
                    code=HostFindingCode.STORAGE_ACCOUNT_DNS_FAILURE,
                    text=(
                        f'The app\'s configured storage account "{configured}" failed DNS '
                        f'resolution for "{host}" ({_times(count)}). Public Azure Storage '
                        "endpoints resolve for every existing account, so the configured "
                        "name most likely does not exist (for example a typo or a deleted "
                        "account), unless private DNS overrides this endpoint."
                    ),
                    evidence_refs=_refs(health[0], refs),
                )
            )

    uncovered = [(host, value) for host, value in sorted(dns.items()) if host not in covered]
    for host, (count, refs) in uncovered[:MAX_DNS_HOSTS]:
        findings.append(
            HostFinding(
                code=HostFindingCode.DEPENDENCY_DNS_FAILURE,
                text=f'Dependency host "{host}" failed DNS resolution ({_times(count)}).',
                evidence_refs=tuple(sorted(refs, key=_ref_order)),
            )
        )

    if dns:
        findings.extend(_http_5xx_with_dns(errors))
    return tuple(findings)


def _http_5xx_with_dns(errors: Iterable[EvidenceItem]) -> list[HostFinding]:
    dns_revisions: set[str] = set()
    http: dict[str, tuple[int, set[str]]] = {}
    for item in errors:
        for row in item.rows:
            revision = row.get("RevisionName_s")
            if not isinstance(revision, str) or not _REVISION.fullmatch(revision):
                continue
            if row.get("ErrorKind") == "dependency_dns":
                dns_revisions.add(revision)
            elif row.get("ErrorKind") == "http_5xx":
                total, refs = http.get(revision, (0, set()))
                http[revision] = (total + _count(row.get("Occurrences")), refs | {item.evidence_id})
    return [
        HostFinding(
            code=HostFindingCode.HTTP_5XX_WITH_DEPENDENCY_FAILURE,
            text=(
                f'Revision "{revision}" logged HTTP 5xx responses ({_times(count)}) in the '
                "same window as dependency DNS failures."
            ),
            evidence_refs=tuple(sorted(refs, key=_ref_order)),
        )
        for revision, (count, refs) in sorted(http.items())
        if revision in dns_revisions
    ]


def _ok_items(bundle: EvidenceBundle, source: EvidenceSource) -> list[EvidenceItem]:
    return [
        item
        for item in bundle.items
        if item.provenance.source is source and item.status is EvidenceStatus.OK
    ]


def _first_row(
    bundle: EvidenceBundle, source: EvidenceSource
) -> tuple[EvidenceItem, Mapping[str, Any]] | None:
    for item in _ok_items(bundle, source):
        if item.rows:
            return item, item.rows[0]
    return None


def _dns_hosts(log: str) -> set[str]:
    hosts = {m.group(0) for m in _STORAGE_HOST.finditer(log.lower())}
    for match in _RESOLVE_HOST.finditer(log):
        host = match.group(1).lower().rstrip(".")
        if _HOSTNAME.fullmatch(host):
            hosts.add(host)
    return hosts


def _account(value: object) -> str | None:
    return value if isinstance(value, str) and _STORAGE_ACCOUNT.fullmatch(value) else None


def _count(value: object) -> int:
    if isinstance(value, bool):
        return 1
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and value.isdigit() and 0 < len(value) <= 9:
        return int(value)
    return 1


def _times(count: int) -> str:
    return f"{count} occurrence" + ("" if count == 1 else "s")


def _ref_order(ref: str) -> int:
    return int(ref[1:])


def _refs(health: EvidenceItem, refs: set[str]) -> tuple[str, ...]:
    return tuple(sorted({health.evidence_id, *refs}, key=_ref_order))
