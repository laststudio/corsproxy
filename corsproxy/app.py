from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from .collectors import collect_proxies, probe_cf, sync_risk, validate_proxies
from .config import Settings, load_settings
from .security import TargetError, filtered_headers, validate_target
from .store import ApiKey, Store


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    store = Store(settings.db_path)
    store.initialize()
    for raw in settings.api_keys:
        store.ensure_key(raw, settings.request_limit_per_minute, settings.concurrent_limit, settings.daily_byte_limit)
    semaphore = asyncio.Semaphore(settings.concurrent_limit)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        task: asyncio.Task | None = None
        if settings.scheduler == "internal":
            async def scheduled_jobs() -> None:
                while True:
                    for name, fn, needs_settings in (
                        ("sync-risk", sync_risk, True),
                        ("collect", collect_proxies, False),
                        ("probe-cf", probe_cf, True),
                    ):
                        job_id = store.job_start(name)
                        try:
                            result = await fn(settings, store) if needs_settings else await fn(store)
                            store.job_finish(job_id, "ok", str(result))
                        except Exception as exc:
                            store.job_finish(job_id, "error", str(exc)[:500])
                    await asyncio.sleep(15 * 60)
            task = asyncio.create_task(scheduled_jobs())
        try:
            yield
        finally:
            if task:
                task.cancel()

    app = FastAPI(title="corsproxy-service", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.store = store
    origins = list(settings.allowed_origins) or ["*"]
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

    def require_key(x_api_key: str | None = Header(default=None)) -> ApiKey:
        key = store.get_key(x_api_key or "")
        if not key or not store.allow_usage(key):
            raise HTTPException(401 if not key else 429, "invalid API key or quota exceeded")
        return key

    def require_admin(x_admin_key: str | None = Header(default=None)) -> None:
        if not settings.admin_key or x_admin_key != settings.admin_key:
            raise HTTPException(403, "admin authentication required")

    @app.get("/health")
    async def health():
        return {"status": "ok", "database": str(settings.db_path), "scheduler": settings.scheduler}

    @app.get("/v1/sources")
    async def sources(_: ApiKey = Depends(require_key)):
        return {"items": store.sources()}

    @app.get("/v1/risk/{ip}")
    async def risk(ip: str, _: ApiKey = Depends(require_key)):
        try:
            return store.risk(ip)
        except ValueError:
            raise HTTPException(400, "invalid IP address")

    @app.get("/v1/proxies")
    async def proxies(limit: int = 100, max_risk: int = 25, _: ApiKey = Depends(require_key)):
        return {"items": store.list_proxies(max(0, max_risk), limit=min(max(1, limit), 500))}

    @app.get("/v1/cf/ips")
    async def cf_ips(mode: str | None = None, limit: int = 100, _: ApiKey = Depends(require_key)):
        return {"items": store.list_cf(mode, min(max(1, limit), 500))}

    @app.api_route("/v1/forward", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    async def forward(request: Request, url: str, key: ApiKey = Depends(require_key)):
        try:
            host, _ = validate_target(url, settings.allowed_targets)
        except TargetError as exc:
            raise HTTPException(403, str(exc))
        if request.method == "OPTIONS":
            return {"status": "ok"}
        body = await request.body()
        if len(body) > settings.max_request_bytes:
            raise HTTPException(413, "request body too large")
        headers = filtered_headers(dict(request.headers))
        started = time.perf_counter()
        async with semaphore:
            try:
                async with httpx.AsyncClient(follow_redirects=False, timeout=settings.request_timeout) as client:
                    upstream = await client.request(request.method, url, headers=headers, content=body)
            except httpx.HTTPError as exc:
                store.audit(key, host, 502, 0, (time.perf_counter() - started) * 1000, "direct")
                raise HTTPException(502, f"upstream request failed: {exc}")
        data = upstream.content
        if len(data) > settings.max_response_bytes:
            raise HTTPException(502, "upstream response too large")
        store.record_usage(key, len(body) + len(data))
        store.audit(key, host, upstream.status_code, len(data), (time.perf_counter() - started) * 1000, "direct")
        response_headers = filtered_headers(dict(upstream.headers), response=True)
        return StreamingResponse(iter([data]), status_code=upstream.status_code, headers=response_headers)

    @app.post("/v1/admin/jobs/{name}")
    async def run_job(name: str, _: None = Depends(require_admin)):
        jobs = {"collect": collect_proxies, "sync-risk": sync_risk, "validate-proxies": validate_proxies, "probe-cf": probe_cf}
        if name not in jobs:
            raise HTTPException(404, "unknown job")
        job_id = store.job_start(name)
        try:
            result = await jobs[name](settings, store) if name in {"sync-risk", "probe-cf"} else await jobs[name](store)
            store.job_finish(job_id, "ok", str(result))
            return {"job_id": job_id, "status": "ok", "result": result}
        except Exception as exc:
            store.job_finish(job_id, "error", str(exc)[:500])
            raise HTTPException(500, "job failed")

    @app.get("/v1/admin/jobs")
    async def jobs(_: None = Depends(require_admin)):
        return {"items": store.jobs()}

    @app.post("/v1/admin/keys")
    async def create_key(payload: dict, _: None = Depends(require_admin)):
        raw = str(payload.get("key", "")).strip()
        if len(raw) < 16:
            raise HTTPException(400, "key must be at least 16 characters")
        store.ensure_key(raw, int(payload.get("rpm", settings.request_limit_per_minute)), int(payload.get("concurrent_limit", settings.concurrent_limit)), int(payload.get("daily_bytes", settings.daily_byte_limit)), str(payload.get("features", "query,forward")))
        return {"key_id": store.hash_key(raw)[:12]}

    return app


app = create_app()
