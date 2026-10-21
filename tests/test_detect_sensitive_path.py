from __future__ import annotations

from datetime import datetime, timedelta, timezone

from authshield.detect_sensitive_path import classify, detect
from authshield.models import Event
from authshield.parse_web import normalize_path


def _event(ip: str, path: str, second: int, line_no: int) -> Event:
    ts = datetime(2026, 10, 13, 0, 7, 0, tzinfo=timezone.utc) + timedelta(seconds=second)
    return Event(
        event_id=f"{ip}-{line_no}",
        ts=ts,
        source="web",
        event_type="http_access",
        src_ip=ip,
        method="GET",
        path=path,
        path_norm=normalize_path(path),
        status=404,
        user_agent="curl",
        raw="",
        source_file="web.log",
        line_no=line_no,
        parser="combined",
    )


def test_single_env_hit_alerts() -> None:
    alerts = detect([_event("203.0.113.10", "/.env", 0, 1)])
    assert len(alerts) == 1
    assert alerts[0].rule_id == "web_sensitive_path"
    assert alerts[0].severity == "critical"
    assert alerts[0].entity == "/.env"
    assert alerts[0].trigger["hits"] == 1


def test_admin_once_no_alert_three_times_alerts() -> None:
    once = detect([_event("198.51.100.9", "/admin", 0, 1)])
    assert once == []

    events = [_event("198.51.100.9", "/admin/login", i, i + 1) for i in range(3)]
    alerts = detect(events)
    assert len(alerts) == 1
    assert alerts[0].entity == "/admin"
    assert alerts[0].severity == "medium"
    assert alerts[0].trigger["hits"] == 3


def test_transport_heartbeat_not_sensitive() -> None:
    events = [_event("47.99.206.210", "/transport", i, i) for i in range(5)]
    events.append(_event("47.99.206.210", "/data/wechat/component_access_token", 10, 99))
    assert detect(events) == []
    assert classify(events[0]) is None


def test_traversal_is_high() -> None:
    alerts = detect([_event("203.0.113.11", "/foo/../secret", 0, 1)])
    assert len(alerts) == 1
    assert alerts[0].entity == "path_traversal"
    assert alerts[0].severity == "high"


def test_nested_env_is_critical() -> None:
    alerts = detect([_event("203.0.113.12", "/app/.env", 0, 1)])
    assert len(alerts) == 1
    assert alerts[0].entity == "/.env"
    assert alerts[0].severity == "critical"
