# 仓库管理员：把事件、问题、告警写入 SQLite，再按接口需要取出来。不判断算不算扫描。

# 类型标签先当文字存着。不写也能跑。
from __future__ import annotations

# json 用来把 trigger 字典收成一段文字存进库，取出来再 loads 还原。
import json
# datetime / timezone 用来把库里的时间字符串还原成带 UTC 标签的时间。
from datetime import datetime, timezone

# session = with 一下就能借到连接、结束时提交或撤回。
from authshield.db import session
# 三种表格纸，加上 Event 变字典的帮手。
from authshield.models import Alert, Event, ParseIssue, event_to_row

# 库里时间统一存成这种样子：2026-10-12T16:07:07Z。
ISO = "%Y-%m-%dT%H:%M:%SZ"


# 把库里的时间字符串还原成 datetime，并标成 UTC。
def _parse_ts(raw: str) -> datetime:
    return datetime.strptime(raw, ISO).replace(tzinfo=timezone.utc)


# 把一批事件写入 events 表。返回（新插入条数, 因重复跳过条数）。
def insert_events(events: list[Event]) -> tuple[int, int]:
    inserted = 0
    ignored = 0
    # with 结束会 commit；中途出错会 rollback。
    with session() as conn:
        for event in events:
            # 对象变成字典，键名和 SQL 里 :event_id 这种占位符对得上。
            row = event_to_row(event)
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO events (
                    event_id, ts, source, event_type, src_ip, method, path,
                    path_norm, status, user_agent, raw, source_file, line_no, parser
                ) VALUES (
                    :event_id, :ts, :source, :event_type, :src_ip, :method, :path,
                    :path_norm, :status, :user_agent, :raw, :source_file, :line_no, :parser
                )
                """,
                row,
            )
            # rowcount 有值表示真的插入了一行；0 表示主键已存在，被 IGNORE 掉了。
            if cur.rowcount:
                inserted += 1
            else:
                ignored += 1
    return inserted, ignored


# 把看不懂的行写入问题表。返回这次新插入多少条。
def insert_issues(issues: list[ParseIssue]) -> int:
    inserted = 0
    with session() as conn:
        for issue in issues:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO parse_issues (source_file, line_no, code, raw)
                VALUES (?, ?, ?, ?)
                """,
                (issue.source_file, issue.line_no, issue.code, issue.raw),
            )
            if cur.rowcount:
                inserted += 1
    return inserted


# 列出解析问题，证明看不懂的行没有悄悄丢掉。
def list_issues(limit: int = 200) -> list[dict]:
    if limit < 1:
        limit = 1
    if limit > 1000:
        limit = 1000
    with session() as conn:
        rows = conn.execute(
            """
            SELECT source_file, line_no, code, raw
            FROM parse_issues
            ORDER BY source_file, line_no
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(item) for item in rows]


# 检测前把库存的网页访问事件全部取出，按时间、行号排好。
def load_events() -> list[Event]:
    with session() as conn:
        rows = conn.execute(
            "SELECT * FROM events WHERE event_type = 'http_access' ORDER BY ts, line_no"
        ).fetchall()
    # 下面这个列表推导：每一行数据库记录还原成一个 Event 对象。
    return [
        Event(
            event_id=row["event_id"],
            ts=_parse_ts(row["ts"]),
            source=row["source"],
            event_type=row["event_type"],
            src_ip=row["src_ip"],
            method=row["method"],
            path=row["path"],
            path_norm=row["path_norm"],
            status=row["status"],
            user_agent=row["user_agent"],
            raw=row["raw"],
            source_file=row["source_file"],
            line_no=row["line_no"],
            parser=row["parser"],
        )
        for row in rows
    ]


# 严重级别谁更大。更新告警时：只升不降，避免 high 被后来的 medium 盖掉。
def _severity_rank(value: str) -> int:
    order = {"medium": 1, "high": 2, "critical": 3}
    # 不认识的级别当 0。
    return order.get(value, 0)


# 有告警就看要不要更新，没有就新建。返回 created / updated / skipped 三个计数。
def upsert_alerts(alerts: list[Alert]) -> dict[str, int]:
    created = 0
    updated = 0
    skipped = 0
    with session() as conn:
        for alert in alerts:
            # 按指纹找：同一拨扫描应该对上同一条旧告警。
            existing = conn.execute(
                "SELECT * FROM alerts WHERE fingerprint = ?",
                (alert.fingerprint,),
            ).fetchone()
            if existing is None:
                # 库里没有这条指纹，全新插入。
                conn.execute(
                    """
                    INSERT INTO alerts (
                        alert_id, fingerprint, rule_id, rule_name, src_ip, entity,
                        severity, status, summary, trigger_json, false_positive,
                        window_start, window_end, hit_count, evidence_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.alert_id,
                        alert.fingerprint,
                        alert.rule_id,
                        alert.rule_name,
                        alert.src_ip,
                        alert.entity,
                        alert.severity,
                        alert.status,
                        alert.summary,
                        json.dumps(alert.trigger, ensure_ascii=False),
                        alert.false_positive,
                        alert.window_start.strftime(ISO),
                        alert.window_end.strftime(ISO),
                        1,
                        alert.evidence_hash,
                    ),
                )
                # 把证据 ID 挂到告警上。OR IGNORE 避免同一对重复插。
                conn.executemany(
                    "INSERT OR IGNORE INTO alert_evidence (alert_id, event_id) VALUES (?, ?)",
                    [(alert.alert_id, event_id) for event_id in alert.evidence_ids],
                )
                created += 1
                continue
            # 指纹已在，但证据哈希一样：内容没变，跳过。
            if existing["evidence_hash"] == alert.evidence_hash:
                skipped += 1
                continue
            # 证据变了：准备更新。先把严重级别定下来。
            severity = alert.severity
            # 旧的更严重就保留旧的，只升不降。
            if _severity_rank(existing["severity"]) > _severity_rank(severity):
                severity = existing["severity"]
            conn.execute(
                """
                UPDATE alerts SET
                    summary = ?, trigger_json = ?, window_start = ?, window_end = ?,
                    severity = ?, hit_count = hit_count + 1, evidence_hash = ?
                WHERE fingerprint = ?
                """,
                (
                    alert.summary,
                    json.dumps(alert.trigger, ensure_ascii=False),
                    alert.window_start.strftime(ISO),
                    alert.window_end.strftime(ISO),
                    severity,
                    alert.evidence_hash,
                    alert.fingerprint,
                ),
            )
            # 新证据挂到原来的 alert_id 上（不要换编号，详情链接才稳定）。
            conn.executemany(
                "INSERT OR IGNORE INTO alert_evidence (alert_id, event_id) VALUES (?, ?)",
                [(existing["alert_id"], event_id) for event_id in alert.evidence_ids],
            )
            updated += 1
    return {"created": created, "updated": updated, "skipped": skipped}


# 列出告警。ip、severity、rule_id 都可以不传；传了就当过滤条件。
def list_alerts(
    src_ip: str | None = None,
    severity: str | None = None,
    rule_id: str | None = None,
) -> list[dict]:
    # 1=1 是占位条件，后面追加 AND 时不用判断「WHERE 已经有没有」。
    sql = "SELECT * FROM alerts WHERE 1=1"
    params: list[str] = []
    if src_ip:
        sql += " AND src_ip = ?"
        params.append(src_ip)
    if severity:
        sql += " AND severity = ?"
        params.append(severity)
    if rule_id:
        sql += " AND rule_id = ?"
        params.append(rule_id)
    sql += " ORDER BY window_start DESC"
    with session() as conn:
        rows = conn.execute(sql, params).fetchall()
        # 列表不要证据细节，详情接口才带。
        return [_alert_dict(conn, row, include_evidence=False) for row in rows]


# 按 ID 取一条告警详情。找不到返回 None，由 api.py 去变 404。
def get_alert(alert_id: str) -> dict | None:
    with session() as conn:
        row = conn.execute(
            "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        if row is None:
            return None
        return _alert_dict(conn, row, include_evidence=True)


# 把数据库的一行变成接口要的字典。详情才把证据列表附上。
def _alert_dict(conn, row, include_evidence: bool) -> dict:
    payload = {
        "alert_id": row["alert_id"],
        "fingerprint": row["fingerprint"],
        "rule_id": row["rule_id"],
        "rule_name": row["rule_name"],
        "src_ip": row["src_ip"],
        "entity": row["entity"],
        "severity": row["severity"],
        "status": row["status"],
        "summary": row["summary"],
        "trigger": json.loads(row["trigger_json"]),
        "false_positive": row["false_positive"],
        "window_start": row["window_start"],
        "window_end": row["window_end"],
        "hit_count": row["hit_count"],
    }
    if include_evidence:
        evidence_rows = conn.execute(
            """
            SELECT e.event_id, e.ts, e.method, e.path, e.path_norm, e.status
            FROM alert_evidence ae
            JOIN events e ON e.event_id = ae.event_id
            WHERE ae.alert_id = ?
            ORDER BY e.ts, e.line_no
            LIMIT 50
            """,
            (row["alert_id"],),
        ).fetchall()
        # sqlite3.Row 转成普通 dict，FastAPI 才能顺利变成 JSON。
        payload["evidence"] = [dict(item) for item in evidence_rows]
    return payload
