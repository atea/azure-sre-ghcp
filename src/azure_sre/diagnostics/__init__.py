"""Bounded, read-only Azure diagnostics collection (fixed templates, no shell, budgeted)."""

from azure_sre.diagnostics.budget import EvidenceBudgetExhausted
from azure_sre.diagnostics.cli_session import AzureCliSession, CliSessionError
from azure_sre.diagnostics.collector import (
    CorrelationSelector,
    DiagnosticsCollector,
    DiagnosticsError,
)
from azure_sre.diagnostics.executor import (
    CommandCleanupError,
    CommandResult,
    CommandRunner,
    SubprocessRunner,
)
from azure_sre.diagnostics.templates import TEMPLATES, DiagnosticKind

__all__ = [
    "TEMPLATES",
    "AzureCliSession",
    "CliSessionError",
    "CommandCleanupError",
    "CommandResult",
    "CommandRunner",
    "CorrelationSelector",
    "DiagnosticKind",
    "DiagnosticsCollector",
    "DiagnosticsError",
    "EvidenceBudgetExhausted",
    "SubprocessRunner",
]
