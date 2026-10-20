# 三种「表格纸」：事件、解析问题、告警。解析、检测、存储都按这几张纸来填。

# 类型标签先当文字存着。不写也能跑。
from __future__ import annotations

# dataclass = 给 class 盖章自动生成常用能力；asdict = 对象变字典好写入数据库；field = 给某个字段加额外说明。
from dataclasses import asdict, dataclass, field
# 事件上的 ts（什么时候发生）要用日期时间类型，不是随手写的字符串。
from datetime import datetime
# Any = 类型标签「值是什么都行」。trigger 字典里既有整数也有小数。
from typing import Any


# 盖章：按数据表来用；frozen=冻住造好后不能改；slots=只给列出的字段留位子，更省内存。
@dataclass(frozen=True, slots=True)
# 一张「正常网页访问」的表。一行日志看懂了，就填成一个 Event。
class Event:
    event_id: str  # 这一行的编号，由文件名+行号+原文算出来，重复导入还是同一个。
    ts: datetime  # 发生时间（UTC）。
    source: str  # 日志来源，MVP 里是 "web"。
    event_type: str  # 事件类型，MVP 里是 "http_access"。
    src_ip: str  # 来源 IP。
    method: str  # HTTP 方法，如 GET、POST。
    path: str  # 原始路径，查询串也保留在这里。
    path_norm: str  # 规范化路径：去掉 ?、折叠 . 和 ..，检测时用这个去重。
    status: int  # 状态码，如 200、404。
    user_agent: str  # 客户端自称是谁。
    raw: str  # 日志原文，方便以后核对。
    source_file: str  # 来自哪个文件名。
    line_no: int  # 文件里第几行。
    parser: str  # 谁解析的，MVP 里是 "combined"。


# 同样冻住：看不懂的行也一旦记下就不改。
@dataclass(frozen=True, slots=True)
# 一张「这行日志没看懂」的表。不让整份文件失败。
class ParseIssue:
    source_file: str  # 哪个文件。
    line_no: int  # 第几行。
    code: str  # 错误代号，如 non_http、bad_ip。
    raw: str  # 原文。


# 告警允许后面补证据列表，所以这里不 frozen，只用 slots 省内存。
@dataclass(slots=True)
# 一张「值得看的告警」的表。
class Alert:
    alert_id: str  # 告警编号，给详情接口用。
    fingerprint: str  # 去重指纹：同一拨扫描不要反复新建。
    rule_id: str  # 规则英文 ID，如 web_path_scan。
    rule_name: str  # 规则中文名称。
    src_ip: str  # 哪个来源 IP。
    entity: str  # 实体；路径扫描当前用 "-"。
    severity: str  # 严重级别 medium / high。
    status: str  # 调查状态，新建时是 open。
    summary: str  # 人能读的摘要。
    trigger: dict[str, Any]  # 机器能核对的数字：窗口、阈值、实际计数。
    false_positive: str  # 误报说明，写进告警本身，避免以后改文案对不上旧报告。
    window_start: datetime  # 窗口开始（UTC）。
    window_end: datetime  # 窗口结束（UTC）。
    hit_count: int  # 同一指纹被合并了几次。
    evidence_hash: str  # 证据集合的哈希，用来判断「再检测一次要不要更新」。
    # default_factory=list：每个告警自己有一份新空列表，不要大家共用一个列表。
    evidence_ids: list[str] = field(default_factory=list)

    # 把 trigger 复制成普通字典，方便后面 json.dumps。
    def trigger_json_ready(self) -> dict[str, Any]:
        return dict(self.trigger)


# 把一个 Event 对象变成字典，好插入 SQLite。时间要写成统一的字符串格式。
def event_to_row(event: Event) -> dict[str, Any]:
    # asdict 把表格纸上每个格子变成字典的键值。
    row = asdict(event)
    # 数据库里时间存成 2026-10-12T16:07:07Z 这种文本。
    row["ts"] = event.ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    return row
