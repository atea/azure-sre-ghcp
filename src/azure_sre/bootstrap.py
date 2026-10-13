"""Load reviewed configuration without account keys or developer-login fallback."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

from azure.identity.aio import ManagedIdentityCredential
from azure.storage.blob.aio import BlobClient

from azure_sre.config import MAX_CONFIG_BYTES, AppConfig, ConfigError, load_config, parse_config

_BLOB_HOST = re.compile(r"^[a-z0-9]{3,24}\.blob\.core\.windows\.net$")
_GUID = re.compile(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")


def validate_config_blob_url(url: str) -> str:
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or not _BLOB_HOST.fullmatch(parts.netloc)
        or parts.query
        or parts.fragment
        or not re.fullmatch(r"/[a-z0-9-]{3,63}/[A-Za-z0-9_.-]{1,128}\.json", parts.path)
    ):
        raise ConfigError(
            "Configuration URL must identify a fixed Azure Blob JSON file, without SAS."
        )
    return url


async def load_service_config(env: Mapping[str, str]) -> AppConfig:
    local = env.get("SRE_CONFIG_PATH")
    remote = env.get("SRE_SOURCE_CONFIG_URL")
    if bool(local) == bool(remote):
        raise ConfigError("Set exactly one of SRE_CONFIG_PATH or SRE_SOURCE_CONFIG_URL.")
    if local:
        return load_config(Path(local))
    if remote is None:
        raise ConfigError("Missing reviewed configuration blob URL.")
    validate_config_blob_url(remote)
    client_id = env.get("AZURE_CLIENT_ID", "")
    if not _GUID.fullmatch(client_id):
        raise ConfigError(
            "Azure configuration loading requires an explicit managed identity client ID."
        )
    async with ManagedIdentityCredential(client_id=client_id) as credential:
        async with BlobClient.from_blob_url(remote, credential=credential) as blob:
            stream = await blob.download_blob(max_concurrency=1)
            raw = bytearray()
            async for chunk in stream.chunks():
                raw.extend(chunk)
                if len(raw) > MAX_CONFIG_BYTES:
                    raise ConfigError("Configuration blob exceeds the permitted byte limit.")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigError("Configuration blob is not valid UTF-8 JSON.") from exc
    return parse_config(document)
