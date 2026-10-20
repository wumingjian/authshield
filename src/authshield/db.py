# 仓库大门：连上 SQLite、建表、借出一次会话。真正往表里填数据的是 store.py。

# 类型标签先当文字存着。不写也能跑。
from __future__ import annotations

# sqlite3 是 Python 自带的小数据库工具，数据存在一个文件里，不必另开服务器。
import sqlite3
# Iterator 是类型标签：「这是一个能一次交出一件东西的东西」，给 session 的返回值用。
from collections.abc import Iterator
# contextmanager 把普通函数改装成 with ... as ... 能用的会话。
from contextlib import contextmanager
# Path 用来处理数据库文件放在哪。
from pathlib import Path

# 从说明书里借「数据库文件默认路径」那个函数。
from authshield.config import db_path

# 三引号包起来的是一整段建表 SQL。IF NOT EXISTS = 表已经有了就别再建，重复启动不会炸。
SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    path_norm TEXT NOT NULL,
    status INTEGER NOT NULL,
    user_agent TEXT NOT NULL,
    raw TEXT NOT NULL,
    source_file TEXT NOT NULL,
    line_no INTEGER NOT NULL,
    parser TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS parse_issues (
    source_file TEXT NOT NULL,
    line_no INTEGER NOT NULL,
    code TEXT NOT NULL,
    raw TEXT NOT NULL,
    PRIMARY KEY (source_file, line_no, code, raw)
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    entity TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    summary TEXT NOT NULL,
    trigger_json TEXT NOT NULL,
    false_positive TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    hit_count INTEGER NOT NULL,
    evidence_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_evidence (
    alert_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    PRIMARY KEY (alert_id, event_id),
    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
);
"""


# 打开（或新建）数据库文件，并打开几个开关。path 可以不传，不传就用说明书上的默认路径。
def connect(path: Path | None = None) -> sqlite3.Connection:
    # 传了就用传来的；没传就问 config.db_path()。or 在左边为空时才用右边。
    target = path or db_path()
    # 确保 data/ 这类父目录存在。exist_ok=True 表示目录已有也不报错。
    target.parent.mkdir(parents=True, exist_ok=True)
    # 真正连上那个 .db 文件。没有文件会自动建一个空的。
    conn = sqlite3.connect(target)
    # 查出来的每一行像字典一样能用 row["src_ip"]，不必记第几列。
    conn.row_factory = sqlite3.Row
    # 打开外键检查：告警证据必须指向真实存在的告警，乱写会被拒绝。
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL = 边写边读更稳，多人同时查库时不容易卡住。
    conn.execute("PRAGMA journal_mode = WAL")
    # 把这根已经打开的连接交出去。谁借谁负责用完关掉。
    return conn


# 建好所有表。网站开门时 main.py 会调用一次。-> None 表示只做事、不返回有用的值。
def init_db(path: Path | None = None) -> None:
    # 先连上库。
    conn = connect(path)
    try:
        # 把上面那一大段 SCHEMA 一次跑完，该建的表都建好。
        conn.executescript(SCHEMA)
        # 记下当前结构版本是 1。OR IGNORE = 已经有这条就跳过，重复启动不会重复插。
        conn.execute("INSERT OR IGNORE INTO schema_meta(version) VALUES (1)")
        # 把刚才的改动真正写进磁盘。不 commit，一关连接就丢了。
        conn.commit()
    finally:
        # 不管上面成功还是失败，都把连接关掉，不要占着文件。
        conn.close()


# 盖章：把下面的函数变成 with session() as conn: 这种用法。
@contextmanager
# 借出一次会话：用的时候自动提交，出错就撤回，最后一定关掉。
def session(path: Path | None = None) -> Iterator[sqlite3.Connection]:
    # 先连上。
    conn = connect(path)
    try:
        # yield 把连接交给 with 里面的代码。里面的活干完，才会继续往下走。
        yield conn
        # with 里面没出错，就把改动提交。
        conn.commit()
    except Exception:
        # 任何错误：先撤回这次改动，库回到进入 with 之前的样子。
        conn.rollback()
        # 再把错误原样抛出去，让调用方知道失败了。
        raise
    finally:
        # 成功或失败都关掉连接。
        conn.close()
