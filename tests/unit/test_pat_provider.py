import httpx
import pytest
from copilot import GitHubTokenProviderArgs
from copilot.generated.rpc import GitHubTokenAcquireReason

from azure_sre.__main__ import resolve_inference_settings
from azure_sre.pipeline import build_inference_supplier
from azure_sre.security.github_app import InstallationTokenProvider
from azure_sre.security.key_vault import PatLoader
from azure_sre.security.pat_provider import PatAuthenticationError, PatTokenProvider

PAT = "github_pat_secretvalue"
VAULT = "https://myvault.vault.azure.net/"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _args(
    host: str = "github.com",
    reason: GitHubTokenAcquireReason = GitHubTokenAcquireReason.INITIAL,
) -> GitHubTokenProviderArgs:
    return {"host": host, "session_id": "s", "reason": reason}


async def test_pat_is_cached_refreshed_and_reloaded_after_expiry() -> None:
    loads: list[int] = []
    clock = Clock()

    async def load() -> str:
        loads.append(1)
        return f" {PAT}{len(loads)} "

    provider = PatTokenProvider(load_pat=load, cache_seconds=600, clock=clock)
    first = await provider.for_sdk(_args())
    assert first == {"kind": "token", "accessToken": f"{PAT}1", "expiresIn": 600}
    clock.now += 100
    second = await provider.for_sdk(_args())
    assert second["accessToken"] == f"{PAT}1"
    assert second["expiresIn"] == 500
    assert len(loads) == 1

    refreshed = await provider.for_sdk(_args(reason=GitHubTokenAcquireReason.REFRESH))
    assert refreshed["accessToken"] == f"{PAT}2"

    clock.now += 601
    assert (await provider.for_sdk(_args()))["accessToken"] == f"{PAT}3"
    assert PAT not in repr(await provider.get_token())


async def test_pat_provider_rejects_unapproved_host_without_loading() -> None:
    async def load() -> str:
        raise AssertionError("must not load")

    provider = PatTokenProvider(load_pat=load)
    with pytest.raises(PatAuthenticationError, match="unapproved"):
        await provider.for_sdk(_args(host="evil.example"))


async def test_pat_provider_accepts_sdk_https_origin_host() -> None:
    async def load() -> str:
        return PAT

    provider = PatTokenProvider(load_pat=load)
    result = await provider.for_sdk(_args(host="https://github.com"))
    assert result["accessToken"] == PAT


@pytest.mark.parametrize("value", ["ghs_install", "ghp_classic", "gho_oauth", "", "garbage"])
async def test_pat_provider_rejects_non_fine_grained_secret(value: str) -> None:
    async def load() -> str:
        return value

    provider = PatTokenProvider(load_pat=load)
    with pytest.raises(PatAuthenticationError, match="not a fine-grained PAT") as error:
        await provider.get_token()
    if value:
        assert value not in str(error.value)
    assert error.value.__cause__ is None


async def test_pat_loader_failure_does_not_surface_details() -> None:
    async def load() -> str:
        raise RuntimeError(f"vault said {PAT}")

    provider = PatTokenProvider(load_pat=load)
    with pytest.raises(PatAuthenticationError, match="RuntimeError") as error:
        await provider.get_token()
    assert PAT not in str(error.value)
    assert error.value.__cause__ is None


def test_pat_loader_requires_approved_vault_reference() -> None:
    with pytest.raises(ValueError):
        PatLoader(vault_url="https://evil.example", secret_name="pat", client_id="id")
    with pytest.raises(ValueError):
        PatLoader(vault_url=VAULT, secret_name="pat", client_id="")


def _env(**extra: str) -> dict[str, str]:
    return {"SRE_INFERENCE_VAULT_URL": VAULT, **extra}


def test_settings_default_to_pat_mode() -> None:
    settings = resolve_inference_settings(
        _env(SRE_INFERENCE_PAT_SECRET="inference-pat"),
        publisher_app_id="9",
        publisher_secret_name="publisher-pem",
    )
    assert settings.auth_mode == "pat"
    assert settings.secret_name == "inference-pat"
    assert settings.app_id is None and settings.installation_id is None


def test_pat_mode_does_not_require_app_settings_but_requires_pat_secret() -> None:
    with pytest.raises(ValueError, match="SRE_INFERENCE_PAT_SECRET"):
        resolve_inference_settings(
            _env(SRE_INFERENCE_KEY_SECRET="pem"), publisher_app_id="9", publisher_secret_name="p"
        )


def test_inference_secret_must_differ_from_publisher_secret() -> None:
    with pytest.raises(ValueError, match="separate"):
        resolve_inference_settings(
            _env(SRE_INFERENCE_PAT_SECRET="shared"),
            publisher_app_id="9",
            publisher_secret_name="shared",
        )


def test_app_mode_requires_separate_app_settings() -> None:
    app_env = _env(
        SRE_INFERENCE_AUTH_MODE="app",
        SRE_INFERENCE_KEY_SECRET="inference-pem",
        SRE_INFERENCE_APP_ID="1",
        SRE_INFERENCE_INSTALLATION_ID="2",
    )
    settings = resolve_inference_settings(
        app_env, publisher_app_id="9", publisher_secret_name="publisher-pem"
    )
    assert (settings.auth_mode, settings.app_id, settings.installation_id) == ("app", "1", "2")
    with pytest.raises(ValueError, match="separate"):
        resolve_inference_settings(
            app_env, publisher_app_id="1", publisher_secret_name="publisher-pem"
        )
    with pytest.raises(ValueError, match="SRE_INFERENCE_APP_ID"):
        resolve_inference_settings(
            _env(SRE_INFERENCE_AUTH_MODE="app", SRE_INFERENCE_KEY_SECRET="k"),
            publisher_app_id="9",
            publisher_secret_name="p",
        )


def test_unknown_auth_mode_is_rejected() -> None:
    with pytest.raises(ValueError):
        resolve_inference_settings(
            _env(SRE_INFERENCE_AUTH_MODE="oauth", SRE_INFERENCE_PAT_SECRET="x"),
            publisher_app_id="9",
            publisher_secret_name="p",
        )


async def test_build_inference_supplier_selects_provider_by_mode() -> None:
    async with httpx.AsyncClient() as http:
        pat = build_inference_supplier(
            auth_mode="pat", http=http, client_id="id", vault_url=VAULT, secret_name="pat"
        )
        app = build_inference_supplier(
            auth_mode="app",
            http=http,
            client_id="id",
            vault_url=VAULT,
            secret_name="pem",
            app_id="1",
            installation_id="2",
        )
        assert isinstance(pat.__self__, PatTokenProvider)  # type: ignore[attr-defined]
        assert isinstance(app.__self__, InstallationTokenProvider)  # type: ignore[attr-defined]
        with pytest.raises(ValueError, match="App ID"):
            build_inference_supplier(
                auth_mode="app", http=http, client_id="id", vault_url=VAULT, secret_name="pem"
            )
