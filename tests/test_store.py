from corsproxy.store import Store


def test_risk_and_key_quota(tmp_path):
    store = Store(tmp_path / "service.db")
    store.initialize()
    store.ensure_key("test-key-0123456789", 1, 1, 10)
    key = store.get_key("test-key-0123456789")
    assert key is not None
    assert store.allow_usage(key)
    store.record_usage(key, 10)
    assert not store.allow_usage(key)
    store.add_risk([("1.1.1.0/24", "fixture", "blocklist", "test")])
    result = store.risk("1.1.1.1")
    assert result["risk_score"] == 25
    assert result["observations"][0]["source"] == "fixture"
