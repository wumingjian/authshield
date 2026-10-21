# 发动机：创建网站、启动前建好数据库、最后开始听 8000 端口。

# 类型标签先当文字存着，定义函数时先不急着核对。不写也能跑。
from __future__ import annotations

# 把 Python 自带的日志工具箱拿进来，后面才能 logging.getLogger。
import logging
# 从标准库拿出「启动时做 A、关闭时做 B」这种成对生命周期的工具。
from contextlib import asynccontextmanager

# 从 pip 装的 fastapi 里拿出建网站的模具 FastAPI。
from fastapi import FastAPI

# 从咱们的 api.py 把五个接口的登记本借过来。
from authshield.api import router
# 从咱们的 db.py 把「建数据库表」的函数借过来。
from authshield.db import init_db


# 定义函数：把日志怎么打印配好。-> None 表示只做事、不返回有用的值。
def setup_logging() -> None:
    # 按名字领取（或创建）叫 authshield 的记录员，不是造一台新打印机。
    logger = logging.getLogger("authshield")
    # 如果已经接过出口，说明配过了，直接结束，避免同一句话打两遍。
    if logger.handlers:
        return
    # 新建一个通道：把日志打到终端屏幕。
    handler = logging.StreamHandler()
    # 规定每一行长什么样：等级、名字、内容。例如 INFO authshield 某某事。
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    # 把这个出口接到记录员身上，不接的话字出不去。
    logger.addHandler(handler)
    # 最低显示 INFO。更碎的 DEBUG 先不显示。
    logger.setLevel(logging.INFO)
    # 不要再传给上级记录器，避免重复打印。
    logger.propagate = False


# 装饰器：把下面的函数改装成「开门做前半段、yield 后营业、打烊做后半段」。
@asynccontextmanager
# async 是给 FastAPI 用的启动函数。_app 是传来的网站对象，下划线表示暂时不用。
async def lifespan(_app: FastAPI):
    # 开门第一件事：配好日志通道。
    setup_logging()
    # 开门第二件事：建好 SQLite 表，后面才有地方存数据。
    init_db()
    # 分界牌：上面是启动时做的；跑到这里开始对外服务；关掉时才走后面（现在是空的）。
    yield


# 工厂函数：调用它就得到一个组装好的 FastAPI 应用。
def create_app() -> FastAPI:
    # 用模具盖房子。括号跨好几行，到下面的 ) 才结束。
    app = FastAPI(
        title="AuthShield",  # /docs 页面顶上的标题。
        version="0.1.0",  # 版本号，也会显示在 /docs。
        description="Week-2: ingest combined web logs, detect path scans and sensitive paths.",
        lifespan=lifespan,  # 把开门/打烊说明书交给 FastAPI。
    )
    # 把 api.py 里的接口清单钉到这个网站上。没有这行就没有 /health、/alerts。
    app.include_router(router)
    # 把装好的应用交还调用者。
    return app


# 加载本文件时立刻盖房子。uvicorn 找的就是这个名叫 app 的对象。
app = create_app()


# __main__.py 调用的就是这个函数：把网站真正跑起来。
def run() -> None:
    # 用到再导入：只跑测试、不启动网站时，不必立刻加载 uvicorn。
    import uvicorn

    # 请 uvicorn 去 main.py 里找 app，只在本机 8000 端口听；改代码不自动重启。
    uvicorn.run("authshield.main:app", host="127.0.0.1", port=8000, reload=False)
