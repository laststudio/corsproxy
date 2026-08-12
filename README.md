# corsproxy-service

Managed CORS and HTTP(S) forward proxy with API-key quotas, IP-risk intelligence,
validated public-proxy observations, and Cloudflare candidate measurements.

## Quick start

```powershell
python -m pip install -r requirements.txt
$env:CORS_PROXY_ADMIN_KEY = "replace-with-a-long-secret"
$env:CORS_PROXY_API_KEYS = "client-key"
$env:CORS_PROXY_ALLOWED_TARGETS = "api.example.com"
python -m corsproxy.cli serve
```

The service defaults to `127.0.0.1:9800`. Use `/docs` for the OpenAPI UI.

完整的中文接口、认证、配置、任务和转发安全说明见
[`docs/API.md`](docs/API.md)。

## Jobs

External scheduler mode:

```powershell
python -m corsproxy.cli collect
python -m corsproxy.cli sync-risk
python -m corsproxy.cli validate-proxies
python -m corsproxy.cli probe-cf
```

Alternatively use `python -m corsproxy.cli serve --scheduler internal`. Do not
run external cron jobs for the same database while the internal scheduler is active.

`CORS_PROXY_REFERENCE_DIR` may point at the read-only `lastudio_backend` directory
to import `ipdbs/proxy_blocks.csv`; no reference-project file is changed.
