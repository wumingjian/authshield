# 前台：接待请求，把活分给解析/检测/存储，再用 JSON 送回去。自己不算扫描规则、不写 SQL。

# 类型标签先当文字存着。不写也能跑。
from __future__ import annotations

# 从标准库拿出 Path，专门处理文件路径（拼目录、判断是不是文件）。
from pathlib import Path

# APIRouter = 接口登记本；HTTPException = 出错时给浏览器的正式拒客条。
from fastapi import APIRouter, HTTPException
# BaseModel / Field = 规定请求 JSON 必须长什么样，并在 /docs 里显示说明。
from pydantic import BaseModel, Field

# 真正做路径扫描判断的函数。
from authshield.detect_path_scan import detect
# 读整个 Web 日志文件、拆成事件和问题行的函数。
from authshield.parse_web import parse_file
# 下面这一对括号是「从 store.py 一次借多个函数」，10～17 行是同一句。
from authshield.store import (
    get_alert,  # 按 ID 取一条告警详情。
    insert_events,  # 把看懂的事件写入数据库。
    insert_issues,  # 把看不懂的行写入问题表。
    list_alerts,  # 按可选条件列出告警。
    load_events,  # 检测前把库存事件取出来。
    upsert_alerts,  # 有告警就更新，没有就新建。
)

# 新建一本空的接口登记本。后面的 @router.get / @router.post 都写在这本上。
router = APIRouter()


# 定义导入接口收到的 JSON 表格。括号里的 BaseModel 让 FastAPI 自动验字段。
class IngestBody(BaseModel):
    # path 必填（... 表示必填），必须是字符串；description 会出现在 /docs。
    path: str = Field(..., description="Web access log path relative to the project root")


# 内部安检函数。名字前面的 _ 表示给本文件自己用，不是一个网址。
def _safe_path(raw: str) -> Path:
    # 先搞清程序现在在哪个文件夹运行，并变成完整真实地址。这是「院子大门」。
    cwd = Path.cwd().resolve()
    # 把客人写的那串字（例如 access.log）变成路径对象，先不检查。
    target = Path(raw)
    # 已经是 / 开头的绝对路径就保持；否则拼到院子后面。这里的 / 是拼接路径，不是除法。
    target = target if target.is_absolute() else cwd / target
    try:
        # 把 ..、快捷方式展开，得到电脑真正会去读的地址。
        resolved = target.resolve()
        # 问：这个真实地址能不能看成院子里面的相对位置？不能就抛错。
        resolved.relative_to(cwd)
    except (OSError, ValueError) as exc:
        # 路径非法或跑到院子外：回 400，不要让程序崩溃。from exc 把原错误链在后面。
        raise HTTPException(status_code=400, detail="path is outside the project") from exc
    # 路径在项目里，但不是普通文件（不存在或是文件夹）。
    if not resolved.is_file():
        # f"..." 把你原来填的路径嵌进句子里。
        raise HTTPException(status_code=400, detail=f"file not found: {raw}")
    # 两道检查都过了，把真实 Path 交给导入函数去读。
    return resolved


# 盖章：有人用 GET 访问 /health，就跑下面这个函数。浏览器直接打开网址就是 GET。
@router.get("/health")
# 不需要额外参数。返回的字典键和值都是字符串。
def health() -> dict[str, str]:
    # 交回一本小对照表，表示服务还活着。不查库、不读日志。
    return {"status": "ok"}


# 盖章：有人用 POST 访问 /ingest/web，就跑导入。POST = 来办事、提交 JSON。
@router.post("/ingest/web")
# body 是核对过的请求体。返回的字典里值有的是文字、有的是数字。
def ingest_web(body: IngestBody) -> dict[str, int | str]:
    # 从 JSON 取出 path 那串字，先安检；通过后左边的 path 是完整、安全的文件地址。
    path = _safe_path(body.path)
    # 读整个日志：看懂的进 events，看不懂的进 issues。逗号表示一次接两个结果。
    events, issues = parse_file(path)
    # 把事件存进库。新写入多少、因重复跳过多少，分别接住。
    inserted, ignored = insert_events(events)
    # 把问题行存进问题表，得到这次新写入多少条。
    issue_count = insert_issues(issues)
    # 把刚才的计数打包成字典，FastAPI 会变成 /docs 里那段 JSON。
    return {
        "file": path.name,  # 只取文件名，不要一长串目录。
        "lines_parsed": len(events) + len(issues),  # 看懂的条数 + 看不懂的条数。
        "events_inserted": inserted,  # 新写入事件表。
        "events_ignored": ignored,  # 已经存在而跳过。
        "issues_inserted": issue_count,  # 新写入问题表。
    }


# 盖章：POST /detect 开始检测。不再读日志文件，只看数据库里已有事件。
@router.post("/detect")
# 括号是空的：/docs 里不用填 JSON。交回的字典值都是整数。
def run_detect() -> dict[str, int]:
    # 从库里取出已导入的访问记录。没导入过就是空的。
    events = load_events()
    # 交给路径扫描规则，找出短时间乱扫很多路径的 IP。
    alerts = detect(events)
    # 写入告警表：没有就新建，有了且证据没变就跳过。
    result = upsert_alerts(alerts)
    # 往结果字典里再加一项：这次一共找出多少条候选告警。
    result["candidates"] = len(alerts)
    # 把 created / updated / skipped / candidates 交回去。
    return result


# 盖章：GET /alerts 列出告警。只看、不强制改库。浏览器直接打开也能看到 JSON。
@router.get("/alerts")
# ip、severity 都可以不传（默认 None）。FastAPI 会把它们变成 ?ip= 这种查询参数。
def alerts(ip: str | None = None, severity: str | None = None) -> dict:
    # 按名字把接口上的 ip 传给存储层的 src_ip（两边名字不一样，要对准）。
    rows = list_alerts(src_ip=ip, severity=severity)
    # count 一眼知道几条；alerts 是列表，里面每条告警是一本小字典。
    return {"count": len(rows), "alerts": rows}


# 盖章：路径里 {alert_id} 是占位符，必须带编号。和 ?ip= 那种可选查询参数不是一类。
@router.get("/alerts/{alert_id}")
# alert_id 来自网址那一段，必须是字符串。找到就交回详情字典。
def alert_detail(alert_id: str) -> dict:
    # 按 ID 去库里找。找不到时 row 是 None。
    row = get_alert(alert_id)
    # is None 表示就是空。找不到就走下一行。
    if row is None:
        # 404 = 要的东西不存在。raise 之后不会执行 return。
        raise HTTPException(status_code=404, detail="alert not found")
    # 找到了，把详情（含最多 50 条证据）原样交出去。
    return row
