from __future__ import annotations

import asyncio
import csv
import ipaddress
import re
import socket
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .config import Settings
from .store import Store

RISK_SOURCES = {
    "ustc_mailblackip": "https://blackip.ustc.edu.cn/mailblackip.php?txt",
    "ustc_blackip": "https://blackip.ustc.edu.cn/list.php?txt",
    "firehol": "https://iplists.firehol.org/files/firehol_level1.netset",
    "abuseipdb": "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/master/abuseipdb-s100-0d.ipv4",
    "littlejake": "https://raw.githubusercontent.com/LittleJake/ip-blacklist/master/blacklist.txt",
}

PROXY_SOURCES = {
    "proxy-list_download": "https://www.proxy-list.download/api/v1/get?type=http",
    "geonode": "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc",
    "proxifly": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",
}


def parse_ip_lines(text: str) -> list[str]:
    result = []
    for line in text.splitlines():
        value = line.strip().split("#", 1)[0].strip()
        if not value:
            continue
        match = re.search(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?)(?![\w.])", value)
        if match:
            try:
                ipaddress.ip_network(match.group(1), strict=False)
                result.append(match.group(1))
            except ValueError:
                pass
    return list(dict.fromkeys(result))


async def fetch_text(url: str) -> str:
    async with httpx.AsyncClient(follow_redirects=True, timeout=20) as client:
        response = await client.get(url, headers={"User-Agent": "corsproxy-service/0.1"})
        response.raise_for_status()
        return response.text


async def sync_risk(settings: Settings, store: Store) -> dict:
    total = 0
    succeeded = 0
    for name, url in RISK_SOURCES.items():
        try:
            values = [(item, name, "blocklist", url) for item in parse_ip_lines(await fetch_text(url))]
            total += store.add_risk(values)
            succeeded += 1
            store.source_status(name, "risk", url, "ok", f"{len(values)} entries")
        except Exception as exc:
            store.source_status(name, "risk", url, "error", str(exc)[:300])
    if settings.reference_dir:
        path = settings.reference_dir / "ipdbs" / "proxy_blocks.csv"
        if path.exists():
            values = []
            with path.open(encoding="utf-8", errors="ignore", newline="") as handle:
                for row in csv.DictReader(handle):
                    item = row.get("ip") or row.get("cidr") or row.get("network")
                    if item:
                        values.append((item, "lastudio_proxy_blocks", "proxy", str(path)))
            total += store.add_risk(values)
            succeeded += 1
            store.source_status("lastudio_proxy_blocks", "risk", str(path), "ok", f"{len(values)} entries")
    if not succeeded:
        raise RuntimeError("all risk sources failed")
    return {"sources": succeeded, "observations": total}


def parse_proxy_text(text: str, source: str) -> list[dict]:
    output = []
    for line in text.splitlines():
        value = line.strip()
        match = re.search(r"((?:\d{1,3}\.){3}\d{1,3})\s*[: ]\s*(\d{2,5})", value)
        if match:
            try:
                ipaddress.ip_address(match.group(1))
                output.append({"ip": match.group(1), "port": int(match.group(2)), "protocol": "http", "source": source})
            except ValueError:
                pass
    return list({(x["ip"], x["port"], x["protocol"], x["source"]): x for x in output}.values())


async def collect_proxies(store: Store) -> dict:
    count = 0
    succeeded = 0
    for name, url in PROXY_SOURCES.items():
        try:
            rows = parse_proxy_text(await fetch_text(url), name)
            now = time.time()
            with store.connect() as conn:
                conn.executemany("INSERT OR REPLACE INTO proxies(ip,port,protocol,source,collected_at) VALUES (?,?,?,?,?)", [(x["ip"], x["port"], x["protocol"], x["source"], now) for x in rows])
            count += len(rows)
            succeeded += 1
            store.source_status(name, "proxy", url, "ok", f"{len(rows)} entries")
        except Exception as exc:
            store.source_status(name, "proxy", url, "error", str(exc)[:300])
    if not succeeded:
        raise RuntimeError("all proxy sources failed")
    return {"proxies": count}


async def validate_proxies(store: Store, limit: int = 500) -> dict:
    checked = working = 0
    with store.connect() as conn:
        rows = conn.execute("SELECT ip,port,protocol,source FROM proxies LIMIT ?", (limit,)).fetchall()
    async def check(row):
        started = time.perf_counter()
        try:
            proxy = f"http://{row['ip']}:{row['port']}"
            async with httpx.AsyncClient(proxy=proxy, timeout=5) as client:
                response = await client.get("http://httpbin.org/ip")
                response.raise_for_status()
            return True, (time.perf_counter() - started) * 1000
        except Exception:
            return False, None
    results = await asyncio.gather(*(check(row) for row in rows))
    now = time.time()
    with store.connect() as conn:
        for row, (ok, latency) in zip(rows, results):
            checked += 1
            if ok: working += 1
            conn.execute("UPDATE proxies SET is_working=?,latency_ms=?,last_checked=? WHERE ip=? AND port=? AND protocol=? AND source=?", (int(ok), latency, now, row["ip"], row["port"], row["protocol"], row["source"]))
    return {"checked": checked, "working": working}


async def probe_cf(settings: Settings, store: Store) -> dict:
    candidates = []
    cloudflare_ok = False
    try:
        text = await fetch_text("https://www.cloudflare.com/ips-v4")
        for network in parse_ip_lines(text):
            net = ipaddress.ip_network(network, strict=False)
            candidates.append(str(net.network_address))
        cloudflare_ok = True
    except Exception:
        candidates = []
    for host in settings.cf_test_hosts:
        try:
            addresses = {x[4][0] for x in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
            candidates.extend(addresses)
        except socket.gaierror:
            continue
    rows = [(ip, "cloudflare", "public" if not settings.cf_test_hosts else "custom", "", 0.0, None, None, None, time.time()) for ip in dict.fromkeys(candidates)]
    if rows:
        with store.connect() as conn:
            conn.executemany("INSERT OR REPLACE INTO cf_candidates(ip,source,mode,region,success_rate,latency_ms,ttfb_ms,speed_kbps,last_checked) VALUES (?,?,?,?,?,?,?,?,?)", rows)
    if not cloudflare_ok and not settings.cf_test_hosts:
        raise RuntimeError("Cloudflare candidate source failed and CF_TEST_HOSTS is empty")
    return {"candidates": len(rows)}
