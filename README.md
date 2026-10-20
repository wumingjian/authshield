# AuthShield (week-1 MVP)

Python + FastAPI + SQLite. Ingest a combined web access log, detect short-window path scans, and inspect alerts over HTTP.

This is the first vertical slice:

`access.log` → parse → SQLite → `web_path_scan` → `/alerts`

No SSH rules, no frontend, no extra detectors yet.

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
```

`POST /transport` heartbeats from your own Node workers should not become alerts. Scanner IPs with many distinct 4xx paths in 120 seconds should.

## Tests

```bash
pytest
```

## Rule

`web_path_scan` fires when one source IP, inside 120 seconds, has:

- at least 20 distinct normalized paths
- at least 20 counted requests
- at least 30% of those requests with status >= 400

Static `.js` / `.css` / images / fonts / source maps are ignored. Severity is `high` when distinct paths reach 50 or the error ratio reaches 0.8.
