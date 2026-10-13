"""Worker runtime settings. Concurrency and investigation time come from ``AppConfig.budget``."""

from __future__ import annotations

import os
import re
import socket
import uuid
from typing import Annotated, Any, Final, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from azure_sre.config import AppConfig
from azure_sre.contracts import (
    HARD_MAX_CONCURRENCY_PER_REPLICA,
    HARD_MAX_INVESTIGATION_SECONDS,
)

__all__ = ["WorkerSettings", "default_owner_id"]

_OWNER_RE: Final = re.compile(r"[^A-Za-z0-9_.:-]")

Seconds = Annotated[float, Field(gt=0, le=86_400)]
Attempts = Annotated[int, Field(strict=True, ge=1, le=50)]


def default_owner_id() -> str:
    host = _OWNER_RE.sub("-", socket.gethostname())[:64] or "worker"
    return f"{host}:{os.getpid()}:{uuid.uuid4().hex[:8]}"


class WorkerSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    owner_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")] = Field(
        default_factory=default_owner_id
    )
    concurrency: Annotated[int, Field(strict=True, ge=1, le=HARD_MAX_CONCURRENCY_PER_REPLICA)] = 1
    investigation_timeout_seconds: Annotated[
        float, Field(gt=0, le=HARD_MAX_INVESTIGATION_SECONDS + 60)
    ] = HARD_MAX_INVESTIGATION_SECONDS + 15
    lease_seconds: Seconds = 60.0
    renew_interval_seconds: Seconds = 15.0
    lease_safety_margin_seconds: Seconds = 5.0
    publish_timeout_seconds: Seconds = 30.0
    lock_renewal_max_seconds: Seconds = 1200.0
    max_investigation_attempts: Attempts = 3
    max_publish_attempts: Attempts = 5
    max_reconcile_attempts: Attempts = 12
    max_store_attempts: Attempts = 4
    not_found_settle_seconds: Seconds = 600.0
    fired_grace_seconds: Seconds = 3600.0
    backoff_base_seconds: Seconds = 5.0
    backoff_max_seconds: Seconds = 900.0
    store_backoff_base_seconds: Seconds = 0.2
    store_backoff_max_seconds: Seconds = 5.0
    reconcile_interval_seconds: Seconds = 30.0
    reconcile_batch: Annotated[int, Field(strict=True, ge=1, le=100)] = 10
    reconcile_scan_limit: Annotated[int, Field(strict=True, ge=1, le=1000)] = 200
    shutdown_grace_seconds: Seconds = 25.0
    receive_wait_seconds: Seconds = 5.0
    max_message_bytes: Annotated[int, Field(strict=True, ge=1024, le=256 * 1024)] = 64 * 1024
    max_delivery_attempts: Annotated[int, Field(strict=True, ge=1, le=100)] = 8
    max_consecutive_failures: Annotated[int, Field(strict=True, ge=1, le=1000)] = 20

    @model_validator(mode="after")
    def _coherent(self) -> Self:
        if self.renew_interval_seconds * 2 >= self.lease_seconds:
            raise ValueError("renew_interval_seconds must be under half of lease_seconds")
        if self.lease_safety_margin_seconds >= self.lease_seconds / 2:
            raise ValueError("lease_safety_margin_seconds is too large for lease_seconds")
        if self.publish_timeout_seconds + self.lease_safety_margin_seconds >= self.lease_seconds:
            raise ValueError("publish_timeout_seconds must fit inside one lease")
        if self.lock_renewal_max_seconds < (
            self.investigation_timeout_seconds + 2 * self.publish_timeout_seconds
        ):
            raise ValueError("lock_renewal_max_seconds must cover investigation and publication")
        if self.backoff_base_seconds > self.backoff_max_seconds:
            raise ValueError("backoff_base_seconds exceeds backoff_max_seconds")
        return self

    @classmethod
    def from_config(cls, config: AppConfig, **overrides: Any) -> WorkerSettings:
        """Bind concurrency and investigation timeout to the reviewed budget policy."""
        values: dict[str, Any] = {
            "concurrency": config.budget.concurrency_per_replica,
            "investigation_timeout_seconds": float(config.budget.investigation_seconds) + 15.0,
        }
        for key in ("concurrency", "investigation_timeout_seconds"):
            if key in overrides:
                raise ValueError(f"{key} is bound to AppConfig.budget")
        values.update(overrides)
        return cls.model_validate(values)
