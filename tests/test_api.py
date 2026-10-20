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
