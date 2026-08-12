import asyncio

import pytest

from corsproxy import collectors
from corsproxy.config import Settings
from corsproxy.store import Store


def test_sync_risk_marks_total_failure(tmp_path, monkeypatch):
    async def fail(_url):
        raise OSError("fixture network failure")

    monkeypatch.setattr(collectors, "fetch_text", fail)
    store = Store(tmp_path / "service.db")
    store.initialize()
    with pytest.raises(RuntimeError, match="all risk"):
        asyncio.run(collectors.sync_risk(Settings(db_path=tmp_path / "service.db"), store))
    assert {item["last_status"] for item in store.sources()} == {"error"}


def test_parse_ip_lines_filters_invalid_values():
    assert collectors.parse_ip_lines("1.1.1.1\ninvalid\n1.1.1.0/24 # note\n") == ["1.1.1.1", "1.1.1.0/24"]
