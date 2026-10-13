"""FastAPI receiver for Azure Monitor secure-webhook alerts.

Request flow for ``POST /alerts``: bearer token verified first (no body read for unauthenticated
callers), then the body is streamed with a hard byte cap, normalized against the reviewed registry
with the sink taken from the authenticated caller, and durably enqueued. Only after the broker
accepts the message does the client receive 202. Nothing is queued for a rejected request.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from azure_sre.config import AppConfig
from azure_sre.contracts import MAX_ALERT_PAYLOAD_BYTES, ContractError, normalize_alert
from azure_sre.ingress.auth import EntraTokenVerifier
from azure_sre.ingress.protocols import (
    AlertSender,
    AuthenticationError,
    AuthorizationError,
    IngressError,
    JwksUnavailableError,
    PayloadError,
    SendError,
    TokenVerifier,
)
from azure_sre.ingress.settings import IngressSettings

logger = logging.getLogger(__name__)

_BEARER_PREFIX = "bearer "
_READ_CHUNK_BYTES = 16 * 1024


def _error(status: int, code: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": code})


def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith(_BEARER_PREFIX):
        return None
    token = header[len(_BEARER_PREFIX) :].strip()
    return token or None


async def _read_capped(request: Request, limit: int) -> bytes:
    """Read the body incrementally and stop as soon as it exceeds ``limit``."""
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > limit:
                raise PayloadError("payload_too_large")
        except ValueError:
            raise PayloadError("invalid_content_length") from None
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise PayloadError("payload_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


def create_app(
    config: AppConfig,
    sender: AlertSender | None = None,
    *,
    settings: IngressSettings | None = None,
    verifier: TokenVerifier | None = None,
    http: httpx.AsyncClient | None = None,
) -> FastAPI:
    """Build the receiver.

    ``sender`` is the durable enqueue seam. ``verifier`` is the bearer-token seam; when omitted
    and ``settings`` is provided, the Entra verifier is used. With neither, the app fails closed:
    ``/alerts`` returns 503 and ``/readyz`` reports not ready.
    """
    if settings is not None and settings.tenant_id != config.registry.tenant_id.lower():
        raise ValueError("ingress tenant_id must match registry tenant_id")
    if verifier is None and settings is not None:
        verifier = EntraTokenVerifier(config, settings, http=http)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        if sender is not None:
            try:
                await sender.open()
            except SendError as exc:
                logger.error("sender not ready at startup category=%s", exc.code)
        if isinstance(verifier, EntraTokenVerifier):
            try:
                await verifier.refresh()
            except IngressError as exc:
                logger.warning("jwks initial load failed code=%s", exc.code)
        try:
            yield
        finally:
            if sender is not None:
                await sender.close()

    app = FastAPI(
        title="azure-sre-ingress",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.config = config
    app.state.sender = sender
    app.state.verifier = verifier

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness only. Never touches the broker or the key set."""
        return {"status": "ok"}

    @app.get("/readyz", response_model=None)
    async def readyz() -> JSONResponse | dict[str, str]:
        sender_ready = sender is not None and await sender.ready()
        verifier_ready = verifier is not None and await verifier.ready()
        if sender_ready and verifier_ready:
            return {"status": "ready"}
        return _error(503, "not_ready")

    @app.post("/alerts", status_code=202, response_model=None)
    async def receive_alert(request: Request) -> JSONResponse:
        if verifier is None or sender is None:
            logger.error("ingress not configured; rejecting alert")
            return _error(503, "not_configured")

        token = _bearer_token(request)
        if token is None:
            return _error(401, "unauthenticated")
        try:
            caller = await verifier.verify(token)
        except AuthenticationError as exc:
            logger.info("alert rejected category=%s", exc.code)
            return _error(401, "unauthenticated")
        except AuthorizationError as exc:
            logger.info("alert rejected category=%s", exc.code)
            return _error(403, "forbidden")
        except JwksUnavailableError as exc:
            logger.error("alert rejected category=%s", exc.code)
            return _error(503, "unavailable")

        try:
            body = await _read_capped(request, MAX_ALERT_PAYLOAD_BYTES)
        except PayloadError as exc:
            logger.info("alert rejected category=%s", exc.code)
            return _error(413, "payload_too_large")

        try:
            alert = normalize_alert(body, config.registry, sink=caller.sink)
        except ContractError as exc:
            logger.info("alert rejected category=%s", exc.code)
            return _error(400, "invalid_payload")

        try:
            accepted = await sender.send(alert)
        except SendError as exc:
            logger.error("alert not accepted category=%s", exc.code)
            return _error(503, "unavailable")

        logger.info("alert accepted sink=%s message_id=%s", caller.sink.value, accepted.message_id)
        return JSONResponse(status_code=202, content={"status": "accepted"})

    return app


__all__ = ["create_app"]
