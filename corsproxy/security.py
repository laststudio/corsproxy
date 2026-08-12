from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class TargetError(ValueError):
    pass


def is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return ip.is_global and not ip.is_multicast and not ip.is_unspecified


def validate_target(url: str, allowed_hosts: tuple[str, ...]) -> tuple[str, int]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TargetError("target must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise TargetError("target URL credentials are not supported")
    host = parsed.hostname.rstrip(".").lower()
    if not allowed_hosts:
        raise TargetError("no forwarding targets are configured")
    if not any(host == rule or (rule.startswith(".") and host.endswith(rule)) for rule in allowed_hosts):
        raise TargetError("target host is not allowed")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise TargetError("target DNS resolution failed") from exc
    if not addresses or any(not is_public_ip(address) for address in addresses):
        raise TargetError("target resolves to a non-public address")
    return host, parsed.port or (443 if parsed.scheme == "https" else 80)


HOP_BY_HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
})

# httpx transparently decodes compressed response bodies. These framing headers
# must not be forwarded with the decoded bytes, or clients will decode again.
RESPONSE_REWRITE_HEADERS = frozenset({"content-encoding", "content-length"})


def filtered_headers(headers: dict[str, str], *, response: bool = False) -> dict[str, str]:
    excluded = HOP_BY_HOP_HEADERS | (RESPONSE_REWRITE_HEADERS if response else frozenset())
    return {key: value for key, value in headers.items() if key.lower() not in excluded}
