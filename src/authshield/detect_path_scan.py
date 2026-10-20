# 安检规则：看每个 IP 是不是在短时间里乱扫很多不同路径。只出告警，不写库。

# 类型标签先当文字存着。不写也能跑。
from __future__ import annotations

# hashlib 用来把指纹、证据列表收成固定长度的编号。
import hashlib
# defaultdict：按 IP 分篮子时，第一次碰到这个 IP 会自动给一个空列表。
from collections import defaultdict
# datetime 是窗口起止时间的类型。
from datetime import datetime
# Path 在这里只用来取路径的后缀名，例如 .css。
from pathlib import Path

# 从说明书一次借齐阈值、规则名、静态后缀这些数字和文字。
from authshield.config import (
    EVIDENCE_LIMIT,
    FALSE_POSITIVE_NOTE,
    HIGH_ERROR_RATIO,
    HIGH_PATHS,
    MIN_DISTINCT_PATHS,
    MIN_ERROR_RATIO,
    MIN_REQUESTS,
    RULE_ID,
    RULE_NAME,
    STATIC_SUFFIXES,
    SUPPRESSION_SECONDS,
    WINDOW_SECONDS,
)
# Event 是一条访问；Alert 是一条告警。
from authshield.models import Alert, Event


# 这条路径是不是静态资源（js/css/图片）。静态的不拿来当「扫目录」。
def is_static(path_norm: str) -> bool:
    # Path(...).suffix 取出最后的 .xxx；lower() 让 .CSS 和 .css 一样算。
    suffix = Path(path_norm).suffix.lower()
    # in 问：这个后缀在说明书那组静态后缀里吗？
    return suffix in STATIC_SUFFIXES


# 这条事件要不要计入扫描统计。静态路径返回 False，不当扫描。
def countable(event: Event) -> bool:
    # not 把「是静态」翻成「不要计」。
    return not is_static(event.path_norm)


# 根据不同路径数和错误占比，决定 medium 还是 high。
def _severity(distinct_paths: int, error_ratio: float) -> str:
    # 路径很多，或者绝大多数都是 4xx/5xx，升为 high。
    if distinct_paths >= HIGH_PATHS or error_ratio >= HIGH_ERROR_RATIO:
        return "high"
    return "medium"


# 数一个窗口里：请求次数、不同路径数、错误次数、错误占比。
def _stats(window: list[Event]) -> tuple[int, int, int, float]:
    # 窗口里有几条请求。
    requests = len(window)
    # 花括号是集合：同样的 path_norm 只算一次。再 len 就是不同路径数。
    paths = len({item.path_norm for item in window})
    # 状态码 >= 400 的条数。sum(1 for ...) 是「满足条件的有几条」。
    errors = sum(1 for item in window if item.status >= 400)
    # 有请求才除；没有请求就当 0，避免除以 0。
    ratio = (errors / requests) if requests else 0.0
    return requests, paths, errors, ratio


# 这三个数字是不是都过了门槛。差一项都不算扫描。
def _qualifies(requests: int, paths: int, ratio: float) -> bool:
    return (
        requests >= MIN_REQUESTS
        and paths >= MIN_DISTINCT_PATHS
        and ratio >= MIN_ERROR_RATIO
    )


# 做去重指纹：同一规则、同一 IP、同一时间桶，只保留一条告警。
def _fingerprint(src_ip: str, window_start: datetime) -> str:
    # timestamp() 是秒数；// 是整除。把时间切成 1800 秒一块的桶。
    bucket = int(window_start.timestamp()) // SUPPRESSION_SECONDS
    # entity 当前用 "-"，以后做敏感路径可以换成具体路径。
    return f"{RULE_ID}|{src_ip}|-|{bucket}"


# 把指纹再哈希成 32 位 alert_id，给详情网址用。
def _alert_id(fingerprint: str) -> str:
    return hashlib.sha256(fingerprint.encode()).hexdigest()[:32]


# 把证据 ID 列表收成哈希。下次检测时用来判断「证据有没有变」。
def _evidence_hash(event_ids: list[str]) -> str:
    # 先排序再拼接，避免同样几条只因为顺序不同就算成两份。
    joined = ",".join(sorted(event_ids))
    return hashlib.sha256(joined.encode()).hexdigest()


# 拼一句人能读的摘要。f"..." 把数字嵌进句子里。
def _summary(src_ip: str, requests: int, paths: int, errors: int, ratio: float) -> str:
    return (
        f"来源 {src_ip} 在 {WINDOW_SECONDS} 秒内访问了 {paths} 个不同路径"
        f"（阈值 {MIN_DISTINCT_PATHS}），请求 {requests} 次（阈值 {MIN_REQUESTS}），"
        f"状态码 >= 400 的占比 {ratio:.2f}（阈值 {MIN_ERROR_RATIO}），其中错误 {errors} 次。"
    )


# 在一个 IP 的事件里，找出「最像扫描」的那一个 120 秒窗口。找不到返回 None。
def best_window(events: list[Event]) -> tuple[list[Event], tuple[int, int, int, float]] | None:
    # 先丢掉静态请求，再按时间、行号排好。这样窗口是顺着时间滑的。
    ordered = sorted(
        (item for item in events if countable(item)),
        key=lambda item: (item.ts, item.line_no),
    )
    # 连最低请求次数都不够，不可能达标，直接放弃。
    if len(ordered) < MIN_REQUESTS:
        return None
    # best 先空着。后面每发现一个达标窗口，再跟当前最佳比一比。
    best: tuple[list[Event], tuple[int, int, int, float]] | None = None
    # left 是窗口左边界下标。右边界 right 往前走时，左边界会被追上。
    left = 0
    for right, item in enumerate(ordered):
        # 右端这条和左端差得超过 120 秒，就把左端往右挪，直到窗口重新缩进 120 秒。
        while (item.ts - ordered[left].ts).total_seconds() > WINDOW_SECONDS:
            left += 1
        # 左闭右闭：从 left 到 right 这一段就是当前窗口。
        window = ordered[left : right + 1]
        stats = _stats(window)
        # stats[0]=请求数、[1]=路径数、[3]=错误占比。不达标就看下一个。
        if not _qualifies(stats[0], stats[1], stats[3]):
            continue
        # 还没有最佳，或者这条在「路径数、错误占比、请求数」上更大，就换掉最佳。
        if best is None or (stats[1], stats[3], stats[0]) > (
            best[1][1],
            best[1][3],
            best[1][0],
        ):
            best = (window, stats)
    # 可能整圈都没有达标窗口，那时 best 仍是 None。
    return best


# 对外的入口：给一堆事件，按 IP 分组，每组最多出一条路径扫描告警。
def detect(events: list[Event]) -> list[Alert]:
    # 按来源 IP 分篮子。defaultdict(list) = 新 IP 自动得到 []。
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        by_ip[event.src_ip].append(event)

    alerts: list[Alert] = []
    # group 是这个 IP 的全部事件。
    for src_ip, group in by_ip.items():
        found = best_window(group)
        if found is None:
            # 这个 IP 没有达标窗口。
            continue
        # 把窗口和四个统计数字拆开。这行是拆包：左边几个名字一次接住。
        window, (requests, paths, errors, ratio) = found
        # 证据就是窗口里每条事件的 ID。
        evidence_ids = [item.event_id for item in window]
        # 机器能核对的数字：阈值是多少、实际扫到多少。
        trigger = {
            "window_seconds": WINDOW_SECONDS,
            "min_distinct_paths": MIN_DISTINCT_PATHS,
            "min_requests": MIN_REQUESTS,
            "min_error_ratio": MIN_ERROR_RATIO,
            "distinct_paths": paths,
            "requests": requests,
            "error_count": errors,
            "error_ratio": round(ratio, 4),
        }
        # 窗口里最早那条的时间，当窗口开始，也用来切抑制桶。
        start = window[0].ts
        fingerprint = _fingerprint(src_ip, start)
        alerts.append(
            Alert(
                alert_id=_alert_id(fingerprint),
                fingerprint=fingerprint,
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                src_ip=src_ip,
                entity="-",
                severity=_severity(paths, ratio),
                status="open",
                summary=_summary(src_ip, requests, paths, errors, ratio),
                trigger=trigger,
                false_positive=FALSE_POSITIVE_NOTE,
                window_start=start,
                window_end=window[-1].ts,  # 窗口里最晚那条。
                hit_count=1,
                evidence_hash=_evidence_hash(evidence_ids),
                evidence_ids=evidence_ids[:EVIDENCE_LIMIT],  # 展示最多留 200 个。
            )
        )
    return alerts
