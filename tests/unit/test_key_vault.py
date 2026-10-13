import pytest

from azure_sre.security.key_vault import PrivateKeyLoader


@pytest.mark.parametrize(
    ("vault", "secret", "client_id"),
    [
        ("https://evil.example", "key", "identity"),
        ("https://myvault.vault.azure.net/?sig=secret", "key", "identity"),
        ("https://myvault.vault.azure.net", "../key", "identity"),
        ("https://myvault.vault.azure.net", "key", ""),
    ],
)
def test_private_key_loader_rejects_unapproved_reference(
    vault: str, secret: str, client_id: str
) -> None:
    with pytest.raises(ValueError):
        PrivateKeyLoader(vault_url=vault, secret_name=secret, client_id=client_id)
