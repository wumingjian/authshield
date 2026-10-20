# 翻译官：把 Nginx combined 日志一行行拆开。看懂的变成 Event，看不懂的变成 ParseIssue。

# 类型标签先当文字存着。不写也能跑。
from __future__ import annotations

# hashlib 用来算哈希：同一行日志重复导入还是同一个 event_id。
import hashlib
# ipaddress 用来核对 IP 写得对不对，并把 IPv6 收成标准短写法。
import ipaddress
# re = 正则：按固定格式从一行字里抠出 IP、时间、请求这些格子。
import re
# datetime 是时间类型；timezone.utc 表示按世界标准时间存。
from datetime import datetime, timezone
# Path 用来处理要读的日志文件路径。
from pathlib import Path
# unquote 把 %2e 这种编码还原；urlsplit 把完整网址拆成路径。
from urllib.parse import unquote, urlsplit

# HTTP_METHODS = 认哪些动词；SKIP_BLANK = 空行要不要直接跳过。
from authshield.config import HTTP_METHODS, SKIP_BLANK
# Event = 看懂的访问；ParseIssue = 看不懂的行。
from authshield.models import Event, ParseIssue

# 编译好 combined 格式的尺子。r"..." 是原始字符串，里面的 \ 不用写两遍。
# (?P<名字>...) 给抠出来的那一块起名，后面可以用 match.group("ip") 取出。
COMBINED = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    r'"(?P<req>[^"]*)" (?P<status>\S+) (?P<size>\S+)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)

# strptime 用的时间格式：13/Oct/2026:16:07:07 +0000 这种 Apache 写法。
APACHE_TIME = "%d/%b/%Y:%H:%M:%S %z"


# 给这一行算一个稳定编号。同一文件同一行同一原文，永远得到同一个 32 位十六进制。
def event_id(source_file: str, line_no: int, raw: str) -> str:
    # \0 当分隔符，避免「文件名和行号粘在一起」碰巧撞号。encode() 变成字节才能哈希。
    payload = f"{source_file}\0{line_no}\0{raw}".encode()
    # sha256 算出一长串，[:32] 只取前 32 个字符当 ID，够用也短一点。
    return hashlib.sha256(payload).hexdigest()[:32]


# 把 IP 收成标准写法。不对就返回 None，让上层记成 bad_ip。
def compress_ip(raw: str) -> str | None:
    try:
        # ip_address 能认 IPv4/IPv6；compressed 是收短后的标准字符串。
        return ipaddress.ip_address(raw).compressed
    except ValueError:
        # 不是合法 IP，例如 "-" 或乱码。
        return None


# 把 Apache 时间字符串变成 datetime。不对就返回 None。
def parse_apache_time(raw: str) -> datetime | None:
    try:
        # 按 APACHE_TIME 那把尺子去读。对不上就进 except。
        ts = datetime.strptime(raw, APACHE_TIME)
    except ValueError:
        return None
    # 先转到 UTC，再把时区标签明确标成 UTC，后面比较时间才不会乱。
    return ts.astimezone(timezone.utc).replace(tzinfo=timezone.utc)


# 把路径收成检测时用的「标准长相」：解码、去掉查询串、折叠 . 和 ..。
def normalize_path(path: str) -> str:
    # 先去掉首尾空格。
    raw = path.strip()
    # 最多解 3 次 %xx。有人会把 / 编两次来绕过简单过滤。
    for _ in range(3):
        nxt = unquote(raw)
        # 再解一次没变化，说明解完了，跳出循环。
        if nxt == raw:
            break
        raw = nxt
    # 有人把完整网址写进请求里。不是 / 开头且带 ://，就只留下路径部分。
    if "://" in raw and not raw.startswith("/"):
        parsed = urlsplit(raw)
        raw = parsed.path or "/"
    else:
        # 普通路径：问号后面的查询、井号后面的锚点都丢掉。
        raw = raw.split("?", 1)[0].split("#", 1)[0]
    # 检测时路径都从 / 开头，少了就补上。
    if not raw.startswith("/"):
        raw = "/" + raw
    # 下面把 /a/./b/../c 收成 /a/c。segments 是一路走过来还留着的目录名。
    segments: list[str] = []
    for part in raw.split("/"):
        # 空段（//）和当前目录 . 都跳过。
        if part in ("", "."):
            continue
        # .. 表示回上一层：有上一层就弹出。
        if part == "..":
            if segments:
                segments.pop()
            continue
        # 普通目录名，留下来。
        segments.append(part)
    # 再拼回 /a/c 这种字符串。空列表会得到 "/"。
    return "/" + "/".join(segments)


# 把引号里的 "GET /foo HTTP/1.1" 拆成方法和路径。拆不开就返回 None。
def _split_request(req: str) -> tuple[str, str] | None:
    # 按空格切开。正常会得到方法、路径、协议三截。
    parts = req.split()
    # 至少两截：第 0 个当方法，第 1 个当路径。协议有没有都行。
    if len(parts) >= 2:
        return parts[0], parts[1]
    # 只有一截且不是空：当方法，路径默认成 /。
    if len(parts) == 1 and parts[0]:
        return parts[0], "/"
    # 完全空的请求串。
    return None


# 解析一行。看懂返回 Event；看不懂返回 ParseIssue；空行且允许跳过则返回 None。
def parse_line(raw: str, source_file: str, line_no: int) -> Event | ParseIssue | None:
    # 去掉 NUL 字符，避免后面哈希或入库时出怪问题。
    text = raw.replace("\x00", "")
    # 去掉空白后什么都没有 = 空行。
    if not text.strip():
        if SKIP_BLANK:
            # 空行直接当没看见，不进问题表。
            return None
        return ParseIssue(source_file, line_no, "empty_line", raw)

    # 用 combined 尺子去量这一行。量不上 match 就是 None。
    match = COMBINED.match(text)
    if not match:
        return ParseIssue(source_file, line_no, "unreadable_line", raw)

    # 取出 IP 并收成标准写法。
    src_ip = compress_ip(match.group("ip"))
    if src_ip is None:
        return ParseIssue(source_file, line_no, "bad_ip", raw)

    # 取出时间。
    ts = parse_apache_time(match.group("time"))
    if ts is None:
        return ParseIssue(source_file, line_no, "bad_time", raw)

    # 取出引号里的请求，拆成方法和路径。
    split = _split_request(match.group("req"))
    if split is None:
        return ParseIssue(source_file, line_no, "bad_request", raw)
    method, path = split
    # t3、TLS 握手这些不是 GET/POST，进问题表，不当扫描。
    if method not in HTTP_METHODS:
        return ParseIssue(source_file, line_no, "non_http", raw)

    try:
        # 状态码必须是整数。有时日志里会写 "-"。
        status = int(match.group("status"))
    except ValueError:
        return ParseIssue(source_file, line_no, "bad_status", raw)

    # User-Agent 可能没有（尺子最后那段是可选的）。没有就当空字符串。
    ua = match.group("ua") or ""
    # 格子都填齐了，做成一张冻住的 Event 交出去。
    return Event(
        event_id=event_id(source_file, line_no, raw),
        ts=ts,
        source="web",
        event_type="http_access",
        src_ip=src_ip,
        method=method,
        path=path,
        path_norm=normalize_path(path),
        status=status,
        user_agent=ua,
        raw=raw,
        source_file=source_file,
        line_no=line_no,
        parser="combined",
    )


# 读整个文件。返回两摞：看懂的事件、看不懂的问题。
def parse_file(path: Path) -> tuple[list[Event], list[ParseIssue]]:
    # 先准备两个空篮子。冒号后面是类型标签：里面都是 Event / ParseIssue。
    events: list[Event] = []
    issues: list[ParseIssue] = []
    # 入库时只记文件名，不记一长串目录。
    source = path.name
    # 打开文件。errors="replace" = 碰到坏编码用替换符，不要整份读失败。
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        # enumerate 从 1 开始数行号。raw 还带着换行。
        for line_no, raw in enumerate(handle, start=1):
            # 去掉行尾的 \n 或 \r，原文其余部分原样保留。
            line = raw.rstrip("\n\r")
            parsed = parse_line(line, source, line_no)
            if parsed is None:
                # 被跳过的空行。
                continue
            if isinstance(parsed, Event):
                # 看懂了，放进事件篮。
                events.append(parsed)
            else:
                # 看不懂，放进问题篮。
                issues.append(parsed)
    # 两个篮子一起交回去。api.py 用逗号一次接住。
    return events, issues
