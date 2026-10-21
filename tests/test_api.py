from __future__ import annotations

from pathlib import Path


def _write_scan_log(path: Path) -> None:
    lines = []
    for i in range(25):
        lines.append(
            f'203.0.113.77 - - [13/Oct/2026:00:07:{i:02d} +0800] '
            f'"GET /probe/{i} HTTP/1.1" 404 12 "-" "curl/7.68.0"'
        )
    lines.append(
        '47.99.206.210 - - [13/Oct/2026:00:07:00 +0800] '
        '"POST /transport HTTP/1.1" 200 7 "-" "node-urllib"'
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_ingest_detect_and_dedup(client) -> None:
    log = Path.cwd() / "web-access.log"
    _write_scan_log(log)

    first = client.post("/ingest/web", json={"path": "web-access.log"})
    assert first.status_code == 200
    body = first.json()
    assert body["events_inserted"] == 26
    assert body["events_ignored"] == 0

    second = client.post("/ingest/web", json={"path": "web-access.log"})
    assert second.json()["events_inserted"] == 0
    assert second.json()["events_ignored"] == 26

    detected = client.post("/detect")
    assert detected.status_code == 200
    assert detected.json()["created"] == 1

    again = client.post("/detect")
    assert again.json()["created"] == 0
    assert again.json()["skipped"] == 1

    listing = client.get("/alerts")
    assert listing.status_code == 200
    assert listing.json()["count"] == 1
    alert = listing.json()["alerts"][0]
    assert alert["src_ip"] == "203.0.113.77"
    assert alert["rule_id"] == "web_path_scan"

    detail = client.get(f"/alerts/{alert['alert_id']}")
    assert detail.status_code == 200
    assert detail.json()["trigger"]["distinct_paths"] == 25
    assert detail.json()["evidence"]


def test_ingest_rejects_outside_path(client) -> None:
    response = client.post("/ingest/web", json={"path": "/etc/hosts"})
    assert response.status_code == 400


def _write_sensitive_log(path: Path) -> None:
    lines = [
        '203.0.113.88 - - [13/Oct/2026:00:08:00 +0800] '
        '"GET /.env HTTP/1.1" 404 12 "-" "curl/7.68.0"',
        '203.0.113.88 - - [13/Oct/2026:00:08:01 +0800] '
        '"GET /admin HTTP/1.1" 404 12 "-" "curl/7.68.0"',
        '47.99.206.210 - - [13/Oct/2026:00:08:02 +0800] '
        '"POST /transport HTTP/1.1" 200 7 "-" "node-urllib"',
        '203.0.113.88 - - [13/Oct/2026:00:08:01 +0800] '
        '"t3 1" 400 0 "-" "-"',
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_sensitive_rule_filter_issues_and_dedup(client) -> None:
    log = Path.cwd() / "sensitive.log"
    _write_sensitive_log(log)

    ingested = client.post("/ingest/web", json={"path": "sensitive.log"})
    assert ingested.status_code == 200
    assert ingested.json()["events_inserted"] == 3
    assert ingested.json()["issues_inserted"] == 1

    first = client.post("/detect")
    assert first.status_code == 200
    assert first.json()["created"] == 1
    assert first.json()["candidates"] == 1

    again = client.post("/detect")
    assert again.json()["created"] == 0
    assert again.json()["skipped"] == 1

    listing = client.get("/alerts?rule=web_sensitive_path")
    assert listing.json()["count"] == 1
    assert listing.json()["alerts"][0]["entity"] == "/.env"

    scan_only = client.get("/alerts?rule=web_path_scan")
    assert scan_only.json()["count"] == 0

    issues = client.get("/issues")
    assert issues.status_code == 200
    assert issues.json()["count"] == 1
    assert issues.json()["issues"][0]["code"] == "non_http"
