# AuthShield (week-2)

Python + FastAPI + SQLite. Ingest a combined web access log, detect short-window path scans **and** sensitive-path probes, then inspect alerts over HTTP.

`access.log` → parse → SQLite → `web_path_scan` + `web_sensitive_path` → `/alerts`

No SSH rules and no frontend yet. See `week2.md` for the week-2 task list.

## Setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Run

```bash
python -m authshield
```

Open http://127.0.0.1:8000/docs

```bash
curl -X POST http://127.0.0.1:8000/ingest/web \
  -H 'content-type: application/json' \
  -d '{"path":"access.log"}'

curl -X POST http://127.0.0.1:8000/detect
curl http://127.0.0.1:8000/alerts
curl 'http://127.0.0.1:8000/alerts?rule=web_sensitive_path'
curl http://127.0.0.1:8000/issues
```

`POST /transport` heartbeats from your own Node workers should not become alerts. Scanner IPs with many distinct 4xx paths in 120 seconds should fire `web_path_scan`. A single `/.env` (or similar) should fire `web_sensitive_path`.

## Tests

```bash
pytest
```

## Rules

`web_path_scan` fires when one source IP, inside 120 seconds, has:

- at least 20 distinct normalized paths
- at least 20 counted requests
- at least 30% of those requests with status >= 400

Static `.js` / `.css` / images / fonts / source maps are ignored. Severity is `high` when distinct paths reach 50 or the error ratio reaches 0.8.

`web_sensitive_path` fires on a point probe:

- `/.env`、`/.git/config`、`/etc/passwd` and similar: one hit, `critical`
- decoded path still contains `..`: directory traversal, `high`
- `/admin` or `/wp-admin`: three hits inside 300 seconds, `medium`
- `/transport` and `/data/wechat` prefixes are allowlisted
