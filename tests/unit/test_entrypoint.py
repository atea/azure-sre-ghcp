import pytest

from azure_sre.__main__ import required_setting, run_role


def test_required_settings_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SRE_WEBHOOK_AUDIENCE", raising=False)
    with pytest.raises(ValueError, match="SRE_WEBHOOK_AUDIENCE"):
        required_setting("SRE_WEBHOOK_AUDIENCE")


async def test_worker_rejects_missing_reviewed_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SRE_CONFIG_PATH", raising=False)
    monkeypatch.delenv("SRE_SOURCE_CONFIG_URL", raising=False)
    with pytest.raises(ValueError, match="Set exactly one"):
        await run_role("worker")
