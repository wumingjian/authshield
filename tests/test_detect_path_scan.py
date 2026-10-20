from __future__ import annotations

from datetime import datetime, timedelta, timezone

from authshield.detect_path_scan import detect
from authshield.models import Event


def _event(ip: str, path: str, status: int, second: int, line_no: int) -> Event:
    ts = datetime(2026, 10, 13, 0, 7, 0, tzinfo=timezone.utc) + timedelta(seconds=second)
    return Event(
        event_id=f"{ip}-{line_no}",
        ts=ts,
        source="web",
        event_type="http_access",
        src_ip=ip,
        method="GET",
        path=path,
        path_norm=path,
        status=status,
        user_agent="curl",
        raw="",
        source_file="web.log",
        line_no=line_no,
        parser="combined",
    )


def test_below_path_threshold_no_alert() -> None:
    events = [_event("203.0.113.77", f"/p{i}", 404, i, i) for i in range(19)]
    assert detect(events) == []


def test_scan_triggers_high() -> None:
    events = [_event("203.0.113.77", f"/p{i}", 404, i, i) for i in range(20)]
    alerts = detect(events)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "web_path_scan"
    assert alert.severity == "high"
    assert alert.trigger["distinct_paths"] == 20
    assert alert.trigger["error_ratio"] == 1.0
    assert alert.false_positive


def test_mostly_200_browsing_no_alert() -> None:
    events = [_event("198.51.100.20", f"/page{i}", 200, i, i) for i in range(25)]
    assert detect(events) == []


def test_static_assets_are_ignored() -> None:
    events = [_event("198.51.100.60", f"/app{i}.js", 404, i, i) for i in range(25)]
    assert detect(events) == []


def test_same_path_heartbeat_no_alert() -> None:
    events = [_event("47.99.206.210", "/transport", 200, i, i) for i in range(40)]
    assert detect(events) == []
