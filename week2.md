# AuthShield 第二周任务

继续只做 Web。不上 SSH，不做页面。用已经入库的访问事件，把检测从「乱扫很多路径」补上「专打敏感文件」。

代码大约从 1000 行加到 1800～2200 行。课余一周够用。

## 第一周已经有什么

- 导入 combined 访问日志 → SQLite
- 一条规则：`web_path_scan`
- 五个接口：`/health`、`/ingest/web`、`/detect`、`/alerts`、`/alerts/{id}`

`access.log` 里还没被规则吃到的，是 `/.env`、云凭证、`/../.env` 这类点射。

## 为什么不先做 SSH / 页面

第二周如果同时加 SSH 解析、两条 SSH 规则和前端，等于新开一条产品线。概念和行数都会爆。

第三周再接 `ssh-auth.log`。第四周再做薄前端。

## 核心：敏感路径规则 `web_sensitive_path`

和现有规则分工：

| 规则 | 抓什么 |
| --- | --- |
| 已有 `web_path_scan` | 短时间乱扫很多路径（面） |
| 新增 `web_sensitive_path` | 专门打 `.env`、`.git/config`、云凭证、目录穿越（点） |

阈值按 `PRD.md` 的 B4：

- 路径最多连续百分号解码 3 次，去掉查询串，再折叠 `.` 和 `..`。第一周的 `normalize_path` 已经做了大半。
- 解码后仍包含 `..`：记为目录穿越，级别 high。
- `/.env`、`/.git/config`、`/etc/passwd`：打 1 次就报，级别 critical。
- `/admin` 这类：300 秒内满 3 次才报，避免管理员点一次后台就响。
- `/transport`、微信 token 路径不要进签名，否则业务心跳会误报。

`163.7.11.19` 这类扫描源，两条规则可能都会中。面试可以讲：一条看面，一条看点。

建议新文件：`src/authshield/detect_sensitive_path.py`。签名名单写进 `config.py`。

## 配套接口

都挂在现有门上，少开新入口。

1. `POST /detect` 一次跑两条规则：先 `web_path_scan`，再 `web_sensitive_path`。告警用 `rule_id` 区分，不要再做一个 `/detect/sensitive`。
2. `GET /alerts` 增加 `?rule=`，演示时能只看敏感路径，或只看扫描。
3. `GET /issues`：列出导入时写入的 `parse_issues`（T3、TLS 等），证明看不懂的行没有悄悄丢掉。
4. 调查状态（可选，做不完就留第三周开头）：`PATCH /alerts/{id}`，在 `open`、`acknowledged`、`resolved` 之间更新，可写一句备注。

## 测试和说明

至少覆盖：

- 打一次 `/.env` 要报
- `/admin` 一次不报，三次才报
- `/transport` 不报
- 再检测一次，告警不翻倍

`README.md` 补上第二周怎么演示。`api.md` 补上新接口和 `?rule=`。

## 按天排

| 天 | 做什么 |
| --- | --- |
| 周一 | 签名名单写进 `config.py`：critical / high / admin 三类，外加不参与的前缀 |
| 周二 | 写 `detect_sensitive_path.py`：规范化后的路径怎么对上签名 |
| 周三 | 接进 `detect` 和 `store`，`GET /alerts?rule=` |
| 周四 | `GET /issues`；用 `access.log` 看敏感路径告警长什么样 |
| 周五 | 测试：单次 critical、累计 `/admin`、心跳不误报、去重 |
| 周六 | 补 README / api.md；triage 有余力再做 |
| 周日 | 只修 bug，不加 SSH，不加页面 |

## 验收

周五晚上能讲清楚这些，第二周就算成立：

- `/docs` 里点一次检测，告警里能同时看到 `web_path_scan` 和 `web_sensitive_path`
- 能用 `?rule=web_sensitive_path` 只列出敏感路径
- `GET /issues` 能看到第一周那 30 条左右 T3/TLS
- 阿里云 `POST /transport` 两条规则都不中
- 同一文件再导入、再检测，告警条数不涨

## 明确不做

- 不解析 `ssh-auth.log`
- 不做前端
- 不加第三条 Web 规则
- 不写利用，不写怎么绕过检测；签名只说明这个路径为什么值得看
