import socket

import pytest

from corsproxy.security import TargetError, is_public_ip, validate_target


def test_public_ip_classification():
    assert is_public_ip("1.1.1.1")
    assert not is_public_ip("127.0.0.1")
    assert not is_public_ip("10.0.0.1")


def test_target_rejects_local_dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, ("127.0.0.1", 443))])
    with pytest.raises(TargetError, match="non-public"):
        validate_target("https://api.example.com/x", ("api.example.com",))


def test_target_accepts_allowlisted_public_dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, ("1.1.1.1", 443))])
    assert validate_target("https://api.example.com/x", ("api.example.com",)) == ("api.example.com", 443)

