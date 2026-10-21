# 安检规则：有没有人在点射敏感文件或目录穿越。只出告警，不写库。

# 类型标签先当文字存着。不写也能跑。
from __future__ import annotations

# hashlib 用来把指纹、证据列表收成固定长度的编号。
import hashlib
# defaultdict：按 (IP, 实体) 分篮子时，第一次碰到会自动给一个空列表。
from collections import defaultdict
# datetime 是窗口起止时间的类型。
from datetime import datetime
# unquote 把 %2e 还原成 .；urlsplit 把完整网址拆出路径。
from urllib.parse import unquote, urlsplit

# 从说明书借第二周的签名和阈值。
from authshield.config import (
    CRITICAL_EXACT,
    CRITICAL_SINGLE_HIT,
    CRITICAL_SUFFIXES,
    EVIDENCE_LIMIT,
    REPEAT_PREFIXES,
    SENSITIVE_ALLOWLIST,
    SENSITIVE_FALSE_POSITIVE,
    SENSITIVE_MIN_HITS,
    SENSITIVE_RULE_ID,
    SENSITIVE_RULE_NAME,
    SENSITIVE_SUPPRESSION_SECONDS,
    SENSITIVE_WINDOW_SECONDS,
)
# Event 是一条访问；Alert 是一条告警。
from authshield.models import Alert, Event


# 这条路径是不是业务心跳，要直接放过。
def is_allowlisted(path_norm: str) -> bool:
    for prefix in SENSITIVE_ALLOWLIST:
        # 正好等于前缀，或后面跟 /，才算白名单。/transportX 不算。
        if path_norm == prefix or path_norm.startswith(prefix + "/"):
            return True
    return False


# 解码后（还没折叠 ..）是不是带着「回上一层」。那是目录穿越的长相。
def looks_like_traversal(path: str) -> bool:
    raw = path.strip()
    # 最多解 3 次 %xx，和 normalize_path 同一规矩。
    for _ in range(3):
        nxt = unquote(raw)
        if nxt == raw:
            break
        raw = nxt
    if "://" in raw and not raw.startswith("/"):
        raw = urlsplit(raw).path or "/"
    else:
        raw = raw.split("?", 1)[0].split("#", 1)[0]
    # 任一段叫 ..，就是穿越形态。折叠之后 .. 可能已经看不见了。
    return any(part == ".." for part in raw.split("/"))


# 规范化路径是不是对上某个 critical 签名。
def _critical_entity(path_norm: str) -> str | None:
    lowered = path_norm.lower()
    if lowered in CRITICAL_EXACT:
        return lowered
    for suffix in CRITICAL_SUFFIXES:
        if lowered == suffix or lowered.endswith(suffix):
            return suffix
    return None


# 规范化路径是不是对上某个累计前缀，例如 /admin。
def _repeat_match(path_norm: str) -> tuple[str, str] | None:
    lowered = path_norm.lower()
    for prefix, severity in REPEAT_PREFIXES:
        if lowered == prefix or lowered.startswith(prefix + "/"):
            return prefix, severity
    return None


# 给一条事件贴标签：实体、严重级别、至少打几次才报。对不上返回 None。
def classify(event: Event) -> tuple[str, str, int] | None:
    if is_allowlisted(event.path_norm):
        return None
    critical = _critical_entity(event.path_norm)
    if critical is not None:
        # critical 默认打 1 次就报；开关关掉时改走累计次数。
        min_hits = 1 if CRITICAL_SINGLE_HIT else SENSITIVE_MIN_HITS
        return critical, "critical", min_hits
    if looks_like_traversal(event.path):
        return "path_traversal", "high", 1
    repeat = _repeat_match(event.path_norm)
    if repeat is not None:
        entity, severity = repeat
        return entity, severity, SENSITIVE_MIN_HITS
    return None


# 做去重指纹：同一规则、同一 IP、同一敏感实体、同一时间桶。
def _fingerprint(src_ip: str, entity: str, window_start: datetime) -> str:
    bucket = int(window_start.timestamp()) // SENSITIVE_SUPPRESSION_SECONDS
    return f"{SENSITIVE_RULE_ID}|{src_ip}|{entity}|{bucket}"


def _alert_id(fingerprint: str) -> str:
    return hashlib.sha256(fingerprint.encode()).hexdigest()[:32]


def _evidence_hash(event_ids: list[str]) -> str:
    joined = ",".join(sorted(event_ids))
    return hashlib.sha256(joined.encode()).hexdigest()


# 在累计型签名里，找出 300 秒内命中最多的那一段。不够次数返回 None。
def best_repeat_window(events: list[Event]) -> list[Event] | None:
    ordered = sorted(events, key=lambda item: (item.ts, item.line_no))
    if len(ordered) < SENSITIVE_MIN_HITS:
        return None
    best: list[Event] | None = None
    left = 0
    for right, item in enumerate(ordered):
        while (item.ts - ordered[left].ts).total_seconds() > SENSITIVE_WINDOW_SECONDS:
            left += 1
        window = ordered[left : right + 1]
        if len(window) < SENSITIVE_MIN_HITS:
            continue
        if best is None or len(window) > len(best):
            best = window
    return best


def _summary(src_ip: str, entity: str, hits: int, min_hits: int, severity: str) -> str:
    return (
        f"来源 {src_ip} 访问敏感路径 {entity} 共 {hits} 次"
        f"（阈值 {min_hits}），级别 {severity}。"
    )


# 对外入口：按 IP 和实体分组，每组最多出一条敏感路径告警。
def detect(events: list[Event]) -> list[Alert]:
    # 篮子的钥匙是 (来源 IP, 实体)。同一 IP 打 .env 和 /admin 会进两个篮子。
    groups: dict[tuple[str, str, str, int], list[Event]] = defaultdict(list)
    for event in events:
        found = classify(event)
        if found is None:
            continue
        entity, severity, min_hits = found
        groups[(event.src_ip, entity, severity, min_hits)].append(event)

    alerts: list[Alert] = []
    for (src_ip, entity, severity, min_hits), group in groups.items():
        if min_hits <= 1:
            window = sorted(group, key=lambda item: (item.ts, item.line_no))
        else:
            found_window = best_repeat_window(group)
            if found_window is None:
                continue
            window = found_window
        evidence_ids = [item.event_id for item in window]
        start = window[0].ts
        fingerprint = _fingerprint(src_ip, entity, start)
        trigger = {
            "window_seconds": SENSITIVE_WINDOW_SECONDS if min_hits > 1 else 0,
            "min_hits": min_hits,
            "hits": len(window),
            "entity": entity,
            "traversal": entity == "path_traversal",
        }
        alerts.append(
            Alert(
                alert_id=_alert_id(fingerprint),
                fingerprint=fingerprint,
                rule_id=SENSITIVE_RULE_ID,
                rule_name=SENSITIVE_RULE_NAME,
                src_ip=src_ip,
                entity=entity,
                severity=severity,
                status="open",
                summary=_summary(src_ip, entity, len(window), min_hits, severity),
                trigger=trigger,
                false_positive=SENSITIVE_FALSE_POSITIVE,
                window_start=start,
                window_end=window[-1].ts,
                hit_count=1,
                evidence_hash=_evidence_hash(evidence_ids),
                evidence_ids=evidence_ids[:EVIDENCE_LIMIT],
            )
        )
    return alerts
