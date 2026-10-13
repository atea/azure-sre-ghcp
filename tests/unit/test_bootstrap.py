import pytest

from azure_sre.bootstrap import load_service_config, validate_config_blob_url
from azure_sre.config import ConfigError


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/sre-config/config.json",
        "http://stexample.blob.core.windows.net/sre-config/config.json",
        "https://stexample.blob.core.windows.net/sre-config/config.json?sig=secret",
        "https://stexample.blob.core.windows.net/sre-config/../config.json",
        "https://stexample.blob.core.windows.net:443/sre-config/config.json",
        "https://stexample.blob.core.windows.net/sre-config/config.json#fragment",
    ],
)
def test_config_url_rejects_unapproved_destination(url: str) -> None:
    with pytest.raises(ConfigError):
        validate_config_blob_url(url)


def test_config_url_allows_fixed_blob() -> None:
    url = "https://stexample.blob.core.windows.net/sre-config/sources.json"
    assert validate_config_blob_url(url) == url


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"SRE_CONFIG_PATH": "/file", "SRE_SOURCE_CONFIG_URL": "https://example.com"},
        {
            "SRE_SOURCE_CONFIG_URL": "https://stexample.blob.core.windows.net/sre-config/sources.json"
        },
    ],
)
async def test_configuration_fails_before_attempting_unconfigured_identity(
    env: dict[str, str],
) -> None:
    with pytest.raises(ConfigError):
        await load_service_config(env)
