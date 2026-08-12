import socket

from fastapi.testclient import TestClient

from corsproxy.app import create_app
from corsproxy.config import Settings


def make_client(tmp_path, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, ("1.1.1.1", 443))])
    settings = Settings(db_path=tmp_path / "test.db", admin_key="admin-secret", api_keys=("client-key-0123456789",), allowed_targets=("api.example.com",))
    return TestClient(create_app(settings))


def test_api_requires_key(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    assert client.get("/v1/sources").status_code == 401
    assert client.get("/v1/sources", headers={"X-API-Key": "client-key-0123456789"}).status_code == 200


def test_forward_rejects_bad_target(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    response = client.get("/v1/forward?url=https://not-allowed.example", headers={"X-API-Key": "client-key-0123456789"})
    assert response.status_code == 403


def test_admin_auth(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    assert client.get("/v1/admin/jobs").status_code == 403
    assert client.get("/v1/admin/jobs", headers={"X-Admin-Key": "admin-secret"}).status_code == 200


def test_cors_preflight(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    response = client.options("/v1/forward?url=https://api.example.com", headers={"Origin": "https://app.example", "Access-Control-Request-Method": "GET"})
    assert response.status_code == 200
