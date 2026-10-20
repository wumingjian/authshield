# 说明书上的数字。测试和接口不传额外配置时，都用这里。避免被目录里的示例文件带跑。

"""代码里的默认阈值。除非环境变量 AUTHSHIELD_DB 另有指定，数据库也按这里的路径。"""

# 类型标签先当文字存着。
from __future__ import annotations

# 读环境变量（电脑里额外设置的小纸条）。
import os
# 处理数据库文件路径。
from pathlib import Path

# 规则英文 ID，告警指纹和接口都会用到。
RULE_ID = "web_path_scan"
# 规则中文名称，给人看的。
RULE_NAME = "短时间访问大量不同路径"

# 时间窗口：120 秒内看是不是在扫。
WINDOW_SECONDS = 120
# 窗口里至少多少个不同路径才算扫。
MIN_DISTINCT_PATHS = 20
# 窗口里至少多少次请求才算扫。
MIN_REQUESTS = 20
# 状态码 >= 400 的占比至少多少（挡住大多是 200 的正常浏览）。
MIN_ERROR_RATIO = 0.3
# 不同路径达到 50 就升为 high。
HIGH_PATHS = 50
# 错误占比达到 0.8 也升为 high。
HIGH_ERROR_RATIO = 0.8
# 同一指纹的抑制桶长度（秒）。用来避免短时间重复报。
SUPPRESSION_SECONDS = 1800
# 告警上最多挂多少个证据 ID（展示用截断，哈希仍按完整集合算）。
EVIDENCE_LIMIT = 200

# 空行默认跳过，不当解析问题。
SKIP_BLANK = True

# 只有这些方法才当正常 HTTP。t3、TLS 握手会进问题表。frozenset 表示这组名字不能改。
HTTP_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"})

# 这些后缀默认不参与路径扫描统计，避免把打开网页加载的 js/css/图片当成扫描。
STATIC_SUFFIXES = frozenset(
    {
        ".css",  # 样式表
        ".js",  # 脚本
        ".mjs",  # 另一种 JS 模块
        ".map",  # source map
        ".png",  # 图片
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".webp",
        ".ico",  # 网站图标
        ".bmp",
        ".woff",  # 字体
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
    }
)

# 写进每条告警里的误报说明。以后改文案不会让旧报告对不上（因为已经存在库里）。
FALSE_POSITIVE_NOTE = (
    "爬虫和监控会访问很多路径，错误占比用来挡住大多是 200 的浏览。"
    "前端路由全部返回 404 时仍可能误报。首版没有来源 IP 白名单。"
    "只请求静态扩展名的探测会被漏掉。"
)


# 算出 SQLite 文件放哪。
def db_path() -> Path:
    # 优先读环境变量；没有就用项目下的 data/authshield.db。
    raw = os.environ.get("AUTHSHIELD_DB", "data/authshield.db")
    # 把字符串变成路径对象。
    path = Path(raw)
    # 如果不是 / 开头的绝对路径，就拼到当前工作目录后面。
    if not path.is_absolute():
        path = Path.cwd() / path
    return path
