from __future__ import annotations

import hashlib
import ipaddress
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
  key_hash TEXT PRIMARY KEY, key_id TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
  rpm INTEGER NOT NULL, concurrent_limit INTEGER NOT NULL, daily_bytes INTEGER NOT NULL,
  features TEXT NOT NULL, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS usage_events (
  id INTEGER PRIMARY KEY, key_hash TEXT NOT NULL, created_at REAL NOT NULL, bytes INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS usage_key_time ON usage_events(key_hash, created_at);
CREATE TABLE IF NOT EXISTS risk_observations (
  ip_or_cidr TEXT NOT NULL, source TEXT NOT NULL, category TEXT NOT NULL, observed_at REAL NOT NULL,
  evidence TEXT NOT NULL DEFAULT '', PRIMARY KEY(ip_or_cidr, source, category)
);
CREATE TABLE IF NOT EXISTS sources (
  name TEXT PRIMARY KEY, kind TEXT NOT NULL, url TEXT NOT NULL, last_status TEXT NOT NULL,
  last_run REAL, detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS proxies (
  ip TEXT NOT NULL, port INTEGER NOT NULL, protocol TEXT NOT NULL DEFAULT 'http', source TEXT NOT NULL,
  country TEXT NOT NULL DEFAULT '', asn TEXT NOT NULL DEFAULT '', latency_ms REAL, speed_kbps REAL,
  is_working INTEGER NOT NULL DEFAULT 0, last_checked REAL, collected_at REAL NOT NULL,
  PRIMARY KEY(ip, port, protocol, source)
);
CREATE TABLE IF NOT EXISTS cf_candidates (
  ip TEXT NOT NULL, source TEXT NOT NULL, mode TEXT NOT NULL, region TEXT NOT NULL DEFAULT '',
  success_rate REAL NOT NULL DEFAULT 0, latency_ms REAL, ttfb_ms REAL, speed_kbps REAL,
  last_checked REAL, PRIMARY KEY(ip, source, mode, region)
);
CREATE TABLE IF NOT EXISTS job_runs (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL, started_at REAL NOT NULL,
  completed_at REAL, detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY, key_id TEXT NOT NULL, target_host TEXT NOT NULL, status INTEGER NOT NULL,
  bytes INTEGER NOT NULL, elapsed_ms REAL NOT NULL, upstream TEXT NOT NULL, created_at REAL NOT NULL
);
"""


@dataclass(frozen=True)
class ApiKey:
    key_hash: str
    key_id: str
    rpm: int
    concurrent_limit: int
    daily_bytes: int
    features: frozenset[str]


class Store:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    @contextmanager
    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @staticmethod
    def hash_key(raw: str) -> str:
        return hashlib.sha256(raw.encode()).hexdigest()

    def ensure_key(self, raw: str, rpm: int, concurrent_limit: int, daily_bytes: int, features: str = "query,forward") -> None:
        digest = self.hash_key(raw)
        with self.connect() as conn:
            conn.execute("INSERT OR IGNORE INTO api_keys VALUES (?,?,?,?,?,?,?,?)", (digest, digest[:12], 1, rpm, concurrent_limit, daily_bytes, features, time.time()))

    def get_key(self, raw: str) -> ApiKey | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM api_keys WHERE key_hash=? AND enabled=1", (self.hash_key(raw),)).fetchone()
        if not row:
            return None
        return ApiKey(row["key_hash"], row["key_id"], row["rpm"], row["concurrent_limit"], row["daily_bytes"], frozenset(row["features"].split(",")))

    def allow_usage(self, key: ApiKey) -> bool:
        now = time.time()
        with self._lock, self.connect() as conn:
            rpm = conn.execute("SELECT COUNT(*) FROM usage_events WHERE key_hash=? AND created_at>=?", (key.key_hash, now - 60)).fetchone()[0]
            used = conn.execute("SELECT COALESCE(SUM(bytes), 0) FROM usage_events WHERE key_hash=? AND created_at>=?", (key.key_hash, now - 86400)).fetchone()[0]
            return rpm < key.rpm and used < key.daily_bytes

    def record_usage(self, key: ApiKey, bytes_sent: int) -> None:
        with self.connect() as conn:
            conn.execute("INSERT INTO usage_events(key_hash,created_at,bytes) VALUES (?,?,?)", (key.key_hash, time.time(), bytes_sent))

    def audit(self, key: ApiKey, host: str, status: int, byte_count: int, elapsed_ms: float, upstream: str) -> None:
        with self.connect() as conn:
            conn.execute("INSERT INTO audit_log(key_id,target_host,status,bytes,elapsed_ms,upstream,created_at) VALUES (?,?,?,?,?,?,?)", (key.key_id, host, status, byte_count, elapsed_ms, upstream, time.time()))

    def add_risk(self, values: Iterable[tuple[str, str, str, str]]) -> int:
        now = time.time()
        rows = [(ip, source, category, now, evidence) for ip, source, category, evidence in values]
        with self.connect() as conn:
            conn.executemany("INSERT OR REPLACE INTO risk_observations VALUES (?,?,?,?,?)", rows)
        return len(rows)

    def risk(self, ip: str) -> dict:
        parsed = ipaddress.ip_address(ip)
        matches = []
        with self.connect() as conn:
            for row in conn.execute("SELECT * FROM risk_observations"):
                try:
                    network = ipaddress.ip_network(row["ip_or_cidr"], strict=False)
                    if parsed in network:
                        matches.append(dict(row))
                except ValueError:
                    continue
        return {"ip": ip, "risk_score": min(100, len(matches) * 25), "observations": matches}

    def sources(self) -> list[dict]:
        with self.connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM sources ORDER BY name")]

    def source_status(self, name: str, kind: str, url: str, status: str, detail: str = "") -> None:
        with self.connect() as conn:
            conn.execute("INSERT INTO sources(name,kind,url,last_status,last_run,detail) VALUES (?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET last_status=excluded.last_status,last_run=excluded.last_run,detail=excluded.detail", (name, kind, url, status, time.time(), detail))

    def list_proxies(self, max_risk: int, freshness_seconds: int = 3600, limit: int = 100) -> list[dict]:
        cutoff = time.time() - freshness_seconds
        with self.connect() as conn:
            rows = [dict(row) for row in conn.execute("SELECT * FROM proxies WHERE is_working=1 AND last_checked>=? ORDER BY speed_kbps DESC LIMIT ?", (cutoff, limit))]
        return [row for row in rows if self.risk(row["ip"])["risk_score"] <= max_risk]

    def list_cf(self, mode: str | None, limit: int) -> list[dict]:
        query = "SELECT * FROM cf_candidates"
        params: tuple = ()
        if mode:
            query += " WHERE mode=?"
            params = (mode,)
        query += " ORDER BY success_rate DESC, ttfb_ms ASC, speed_kbps DESC LIMIT ?"
        with self.connect() as conn:
            return [dict(row) for row in conn.execute(query, (*params, limit))]

    def job_start(self, name: str) -> int:
        with self.connect() as conn:
            cur = conn.execute("INSERT INTO job_runs(name,status,started_at) VALUES (?,?,?)", (name, "running", time.time()))
            return int(cur.lastrowid)

    def job_finish(self, job_id: int, status: str, detail: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE job_runs SET status=?,completed_at=?,detail=? WHERE id=?", (status, time.time(), detail, job_id))

    def jobs(self) -> list[dict]:
        with self.connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM job_runs ORDER BY id DESC LIMIT 100")]
