# 这个文件是开关：你敲 python -m authshield 时，Python 会进到这里。
# 从 main.py 里把名叫 run 的函数借过来。run 会启动网站。
from authshield.main import run

# __name__ 是 Python 自动贴的标签。用 python -m 启动时，标签是 "__main__"，条件成立。
# 如果只是被别人 import，就不会自动开店。
if __name__ == "__main__":
    # 真正按开关：后面的工作都交给 main.py 里的 run()。
    run()
