"""Load only named host credentials using an explicit managed identity."""

from __future__ import annotations

import re

from azure.identity.aio import ManagedIdentityCredential
from azure.keyvault.secrets.aio import SecretClient

from azure_sre.security.github_app import AppAuthenticationError

_VAULT = re.compile(r"^https://[a-zA-Z0-9-]{3,24}\.vault\.azure\.net/?$")
_SECRET_NAME = re.compile(r"^[a-zA-Z0-9-]{1,127}$")


class VaultSecretLoader:
    """Read one named secret from an approved vault with an explicit managed identity."""

    def __init__(self, *, vault_url: str, secret_name: str, client_id: str) -> None:
        if not _VAULT.fullmatch(vault_url) or not _SECRET_NAME.fullmatch(secret_name):
            raise ValueError("Credential must reference a named secret in an approved Azure vault.")
        if not client_id:
            raise ValueError("Credential loading requires an explicit managed identity.")
        self.vault_url = vault_url
        self.secret_name = secret_name
        self.client_id = client_id

    async def _read(self) -> str:
        async with ManagedIdentityCredential(client_id=self.client_id) as credential:
            async with SecretClient(vault_url=self.vault_url, credential=credential) as client:
                secret = await client.get_secret(self.secret_name)
        return secret.value or ""


class PrivateKeyLoader(VaultSecretLoader):
    async def __call__(self) -> str:
        value = await self._read()
        if not value.startswith(("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----")):
            raise AppAuthenticationError("Named vault secret is not a PEM private key.")
        return value


class PatLoader(VaultSecretLoader):
    """Return the raw secret; ``PatTokenProvider`` validates the ``github_pat_`` prefix."""

    async def __call__(self) -> str:
        return (await self._read()).strip()
