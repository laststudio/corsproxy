from __future__ import annotations

import argparse
import asyncio

import uvicorn

from .app import create_app
from .collectors import collect_proxies, probe_cf, sync_risk, validate_proxies
from .config import load_settings
from .store import Store


def main() -> None:
    parser = argparse.ArgumentParser(prog="corsproxy")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--scheduler", choices=["off", "internal"], default=None)
    for name in ("collect", "probe-cf", "validate-proxies", "sync-risk"):
        sub.add_parser(name)
    args = parser.parse_args()
    settings = load_settings()
    store = Store(settings.db_path)
    store.initialize()
    if args.command == "serve":
        scheduler = args.scheduler or settings.scheduler
        if scheduler not in {"off", "internal"}:
            raise SystemExit("scheduler must be off or internal")
        if scheduler != settings.scheduler:
            settings = settings.__class__(**{**settings.__dict__, "scheduler": scheduler})
        uvicorn.run(create_app(settings), host=settings.host, port=settings.port)
        return
    jobs = {"collect": collect_proxies, "probe-cf": probe_cf, "validate-proxies": validate_proxies, "sync-risk": sync_risk}
    coroutine = jobs[args.command](settings, store) if args.command in {"probe-cf", "sync-risk"} else jobs[args.command](store)
    result = asyncio.run(coroutine)
    print(result)


if __name__ == "__main__":
    main()
