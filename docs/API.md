# corsproxy-service API 文档

版本：`0.1.0`  
默认地址：`http://127.0.0.1:9800`  
在线 OpenAPI：`GET /docs`，JSON 描述：`GET /openapi.json`

## 1. 快速启动

```powershell
python -m pip install -r requirements.txt
$env:CORS_PROXY_ADMIN_KEY = "change-this-admin-secret"
$env:CORS_PROXY_API_KEYS = "client-key-0123456789"
$env:CORS_PROXY_ALLOWED_TARGETS = "api.example.com,.example.com"
$env:CORS_PROXY_ALLOWED_ORIGINS = "https://app.example.com"
python -m corsproxy.cli serve
```

API Key 通过 `X-API-Key` 请求头传递，管理接口通过 `X-Admin-Key` 传递。API
Key 区分大小写；目标主机匹配不区分大小写。生产环境必须设置非默认的长随机密钥，
并在反向代理层启用 HTTPS。

## 2. 认证和配额

| 请求类型 | 请求头 | 未认证 | 配额超限 |
|---|---|---:|---:|
| 健康检查 | 无 | 允许 | 不适用 |
| `/v1/*` 数据和转发 | `X-API-Key` | `401` | `429` |
| `/v1/admin/*` | `X-Admin-Key` | `403` | 不适用 |

启动时 `CORS_PROXY_API_KEYS` 中的每个 Key 会自动注册，默认配额由
`CORS_PROXY_RPM`、`CORS_PROXY_CONCURRENCY`、`CORS_PROXY_DAILY_BYTES` 决定。
用量按请求体加响应体字节数统计。数据库只保存 Key 的 SHA-256 哈希，不保存原文。

## 3. 公共接口

### `GET /health`

无需认证，用于存活检查。

响应：

```json
{"status":"ok","database":"data\\corsproxy.db","scheduler":"off"}
```

### `GET /v1/sources`

返回风险库、代理源及其最近一次运行状态。

```powershell
curl.exe -H "X-API-Key: client-key-0123456789" http://127.0.0.1:9800/v1/sources
```

响应中的 `last_status` 为 `ok` 或 `error`，`detail` 保存条数或截断后的错误信息。

### `GET /v1/risk/{ip}`

查询单个 IPv4/IPv6 地址是否命中风险观察。支持风险源写入的 CIDR 网段匹配。

```json
{
  "ip":"1.2.3.4",
  "risk_score":25,
  "observations":[
    {"ip_or_cidr":"1.2.3.0/24","source":"firehol","category":"blocklist",
     "observed_at":1720000000,"evidence":"https://..."}
  ]
}
```

`risk_score` 当前按命中观察数计算，每个命中 25 分，最高 100；它是筛选信号，
不是第三方服务的官方信誉分。

### `GET /v1/proxies`

返回近期验证成功且风险分不超过阈值的公开代理。

查询参数：

- `limit`：返回数量，范围 1-500，默认 100。
- `max_risk`：风险分上限，默认 25。

返回字段包括 `ip`、`port`、`protocol`、`source`、`country`、`asn`、
`latency_ms`、`speed_kbps`、`last_checked` 和 `collected_at`。

### `GET /v1/cf/ips`

返回 Cloudflare 候选地址。候选来自 Cloudflare IPv4 网段首地址和
`CF_TEST_HOSTS` 配置主机的 DNS 地址；探测结果写入后会补充延迟、TTFB、吞吐和成功率。

查询参数：

- `mode=public`：公共候选。
- `mode=custom`：自有 Cloudflare 域名解析候选。
- `limit`：范围 1-500，默认 100。

### `ANY /v1/forward?url=...`

受控 HTTP(S) CORS 转发。支持 `GET`、`POST`、`PUT`、`PATCH`、`DELETE`、
`HEAD`、`OPTIONS`。

```powershell
curl.exe -i `
  -H "X-API-Key: client-key-0123456789" `
  -H "Accept: application/json" `
  "http://127.0.0.1:9800/v1/forward?url=https://api.example.com/data"
```

安全规则：

1. `url` 必须是绝对 `http://` 或 `https://` URL，禁止 URL 用户名和密码。
2. 主机必须匹配 `CORS_PROXY_ALLOWED_TARGETS`；空列表时所有转发均拒绝。
3. 解析出的全部地址必须是公网地址，阻止回环、私网、链路本地、保留和组播地址。
4. 不跟随上游重定向，防止跳转绕过主机允许列表。
5. 默认请求体上限 2 MiB、响应体上限 8 MiB、超时 20 秒、并发 4。
6. 请求和响应会移除 `Host`、`Connection`、`Transfer-Encoding` 等逐跳头。

错误状态：`400` 参数错误，`401` Key 无效，`403` 目标不允许，`413` 请求过大，
`429` 配额超限，`502` 上游失败或响应过大。

## 4. 管理接口

### `POST /v1/admin/jobs/{name}`

触发任务：`collect`、`sync-risk`、`validate-proxies`、`probe-cf`。

```powershell
curl.exe -X POST -H "X-Admin-Key: change-this-admin-secret" `
  http://127.0.0.1:9800/v1/admin/jobs/sync-risk
```

返回 `job_id`、状态和任务结果。任务失败详情会写入任务表，并以 `500` 返回。

### `GET /v1/admin/jobs`

返回最近 100 次任务，包括名称、状态、开始/完成时间和详情。

### `POST /v1/admin/keys`

创建或登记 API Key。请求体：

```json
{
  "key":"client-key-0123456789",
  "rpm":60,
  "concurrent_limit":4,
  "daily_bytes":104857600,
  "features":"query,forward"
}
```

Key 至少 16 个字符；响应只返回不可逆的 `key_id`，原始 Key 不会再次显示。

## 5. 数据采集任务

```powershell
python -m corsproxy.cli collect
python -m corsproxy.cli sync-risk
python -m corsproxy.cli validate-proxies
python -m corsproxy.cli probe-cf
```

风险源包括 USTC、FireHOL、AbuseIPDB 公开列表和 LittleJake 列表；代理源包括
Proxy-List、GeoNode、Proxifly。网络源失败会单独记录，不影响其他源。设置
`CORS_PROXY_REFERENCE_DIR=G:\\ets_crack\\backend\\lastudio_backend` 后，风险同步会只读导入
`ipdbs/proxy_blocks.csv`。

Cloudflare 自定义探测主机通过 `CF_TEST_HOSTS` 配置。当前探测任务负责生成候选，
并保留 `public`/`custom` 模式；部署环境可继续扩展 TCP/TLS/HTTP 测量适配器。

## 6. 调度和部署

默认 `CORS_PROXY_SCHEDULER=off`，使用外部 Cron/任务计划程序执行上述 CLI 命令。
设置 `CORS_PROXY_SCHEDULER=internal` 时，服务启动后每 15 分钟依次执行风险同步、
代理采集和 CF 探测。两种模式不要同时运行同一数据库。

关键环境变量详见 [`.env.example`](../.env.example)：监听地址/端口、数据库路径、
允许目标、CORS 来源、配额、请求限制、超时、CF 主机和参考目录均可配置。

