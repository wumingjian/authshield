from __future__ import annotations

from datetime import timezone

from authshield.models import Event, ParseIssue
from authshield.parse_web import normalize_path, parse_file, parse_line


def test_parse_combined_and_utc() -> None:
    line = (
        '203.0.113.77 - - [13/Oct/2026:00:07:07 +0800] '
        '"GET /.env HTTP/1.1" 404 125 "-" "curl/7.68.0"'
    )
    parsed = parse_line(line, "access.log", 1)
    assert isinstance(parsed, Event)
    assert parsed.src_ip == "203.0.113.77"
    assert parsed.method == "GET"
    assert parsed.path == "/.env"
    assert parsed.status == 404
    assert parsed.ts.tzinfo == timezone.utc
    assert parsed.ts.isoformat() == "2026-10-12T16:07:07+00:00"


def test_normalize_dotdot_and_query() -> None:
    assert normalize_path(" /foo/../.env?x=1 ") == "/.env"


def test_non_http_is_issue() -> None:
    line = '165.154.6.82 - - [13/Oct/2026:00:02:38 +0800] "t3 12.1.2" 400 157 "-" "-"'
    parsed = parse_line(line, "access.log", 27)
    assert isinstance(parsed, ParseIssue)
    assert parsed.code == "non_http"


def test_blank_line_skipped() -> None:
    assert parse_line("   ", "access.log", 3) is None


def test_parse_file_continues_after_bad_line(tmp_path) -> None:
    log = tmp_path / "web.log"
    log.write_text(
        "\n".join(
            [
                '198.51.100.20 - - [13/Oct/2026:00:00:06 +0800] "POST /transport HTTP/1.1" 200 7 "-" "node-urllib"',
                "this is not a combined line",
                '198.51.100.20 - - [13/Oct/2026:00:00:07 +0800] "POST /transport HTTP/1.1" 200 7 "-" "node-urllib"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    events, issues = parse_file(log)
    assert len(events) == 2
    assert len(issues) == 1
    assert issues[0].code == "unreadable_line"
