# AuthShield 产品需求说明

英文仓库名：`authshield-security-monitor`

版本：0.1.0

## 1. 背景

安全工程实习需要一个能拿出来讲清楚的小系统，而不是一个只打印几行结果的脚本。AuthShield 读取合成的 Linux SSH 登录日志和 Web 访问日志，把原始行整理成统一事件，用可解释的规则生成告警，把事件和告警放进 SQLite，并输出能够复核的调查报告。

它服务的场景是：给定一批日志，回答「有哪些来源值得看、为什么告警、哪些情况可能是误报、同一件事有没有被重复报出来」。

## 2. 目标

- 把不完整、时间格式不统一的日志行变成同一种事件结构。坏行进入隔离区，不让整份文件失败。
- 首版实现 4 条检测规则。每条规则同时给出人能读的说明和机器能核对的触发字段。
- 用 SQLite 保存事件、解析问题和告警，并按时间、来源 IP、严重级别、规则查询。
- 同一抑制时间桶里的重复告警合并成一条，重复导入同一批日志不会把计数越加越大。
- 命令行可以输出摘要、JSON、CSV 和 Markdown 调查报告。
- 用 pytest 覆盖正常路径、坏输入和误报形态，并用 GitHub Actions 在 push 和 pull request 上跑测试与覆盖率。

## 3. 不做的事

- 不接真实生产日志采集器，不解析私有或未授权系统上的日志。
- 不做攻击利用、漏洞复现或绕过检测的说明。签名库只描述「这个路径为什么值得看」。
- 不上 Kubernetes，不拆微服务，不做机器学习模型。
- 首版没有来源 IP 白名单。敏感路径有路径前缀白名单。
- 不把断开连接单独算成一次登录失败。OpenSSH 经常在失败口令之外再打一行断开记录，重复计数会造成误报。

## 4. 使用者

| 角色 | 要完成的事 |
| --- | --- |
| 实习演示者 | 生成合成日志，跑通导入、检测和报告，讲清楚四条规则 |
| 复核的人 | 按告警里的触发字段和时间线核对原始事件，并记下调查状态 |
| 后续维护者 | 改阈值、加路径签名或加一种日志格式，而不必改存储表的主流程 |

## 5. 模块需求

### 模块 A：日志采集与解析

系统接受 SSH 和 Web 两类文件，可以重复传入多个文件。

SSH 支持：

- OpenSSH syslog，例如 `Failed password`、`Accepted password`、`Accepted publickey`、`Invalid user`、断开连接。
- JSONL。时间字段可以是 `timestamp`、`ts`、`time`，来源可以是 `ip`、`src_ip`、`source_ip`，结果可以是 `result` 或 `event`。

Web 支持：

- combined 访问日志。
- JSONL。
- 带表头的 CSV，至少要有 `timestamp`、`ip`、`method`、`path`、`status`。

时间至少要识别：

- ISO 8601，包括带 `Z` 的写法，以及 `YYYY-MM-DD HH:MM:SS`。
- Apache 时间，例如 `11/Oct/2026:03:00:00 -0700`，要换算成 UTC。
- 没有年份的 syslog 时间。年份用配置里的 `reference_year`。如果这个日期比当前时间超前超过 30 天，则回退一年，用来处理跨年日志。
- Unix 秒和毫秒。

无效记录：

- 空行默认跳过。配置 `skip_blank = false` 时记为解析问题。
- JSON 损坏、不是对象、缺时间、缺 IP、时间非法、IP 非法、请求行拆不开、CSV 缺列，都记为解析问题。
- 无法识别的行记为解析问题，不中断同文件的后续行。
- 非法 UTF-8 用替换字符继续读，不让进程崩溃。

标准事件至少包含：事件 ID、UTC 时间、日志来源、事件类型、来源 IP、结果、用户名、目的主机和端口、HTTP 方法、路径、状态码、User-Agent、原始行、源文件、行号、解析器名称和附加属性。

事件 ID 由源文件、行号和原始行算出。同一行重复导入得到同一个 ID。

验收：

- 一条非法用户的失败口令不会把单词 `invalid` 当成用户名。
- `Invalid user` 和紧挨着的 `Failed password for invalid user` 在检测时只计一次。检测层处理这件事，因为两行都要先被保存下来。
- 路径 ` /foo/../.env?x=1 ` 保留原始路径，同时给出规范化结果 `/.env`。
- IPv6 地址写成压缩形式。

### 模块 B：安全检测规则

四条规则都可以单独关闭。检测器只看已经规范化的事件。

#### B1 `ssh_bruteforce` 短时间多次登录失败

触发条件：

- 只统计登录失败：失败口令、失败公钥，以及没有对应口令失败行的非法用户记录。
- 断开连接和 preauth 关闭不计数。
- 同一来源、同一用户、2 秒内的 `Invalid user` 与失败口令只留口令那一行。
- 同一来源 IP 在 `window_seconds`（默认 300）内失败次数达到 `min_failures`（默认 5）。
- 时间差正好等于窗口长度时仍然算在窗口内。

严重级别：达到 5 次为 medium，达到 `high_at`（默认 10）为 high，达到 `critical_at`（默认 30）为 critical。

可能的误报：

- NAT、堡垒机后面多个真人同时输错密码。
- 密码管理器或配错的自动化任务。
- 公钥轮换时的 publickey 失败。
- 同一次会话先失败公钥再失败口令会记成两次。这是已知的偏严行为。

#### B2 `ssh_failure_then_success` 连续失败后登录成功

触发条件：

- 按来源 IP 观察，不要求失败用户和成功用户是同一个人。
- 成功时刻往前 `window_seconds`（默认 600）内的失败次数达到 `min_failures`（默认 3）。
- 一次成功结束当前失败串。下一次成功必须重新积累失败。
- 告警实体是成功登录的用户名。

严重级别：默认 high。失败次数达到 15，或失败用户名达到 5 个时为 critical。

可能的误报：

- 同一个人打错几次后自己登录成功。
- 共享出口上一个人失败、另一个人成功。
- 密码重置后，旧脚本仍在失败，同时管理员登录成功。

这条规则故意按来源而不是按用户关联，所以不能单靠它区分「撞库成功」和「真人输错后登录」。

#### B3 `web_path_scan` 短时间访问大量不同路径

触发条件，三者同时满足：

- 窗口默认 120 秒。
- 去掉查询串并折叠 `.` 和 `..` 之后，不同路径数达到 20。
- 参与统计的请求数达到 20。
- 状态码大于等于 400 的占比达到 0.3。

`.css`、`.js`、图片、字体和 source map 默认不参与统计，避免把一次正常页面加载当成扫描。这个列表可以在配置里清空。

严重级别：默认 medium。不同路径达到 50，或错误占比达到 0.8 时为 high。

可能的误报和漏报：

- 爬虫和监控会访问很多路径。错误占比用来挡住大多是 200 的浏览。
- 前端路由全部返回 404 时仍可能误报。首版没有来源白名单。
- 只请求静态扩展名的探测会漏掉。这是用漏报换误报，可以关扩展名过滤。
- 刚好被时间窗切开的扫描，每一侧都可能达不到阈值。

#### B4 `web_sensitive_path` 重复访问异常或敏感路径

触发条件：

- 路径最多连续百分号解码 3 次，去掉查询串，再折叠点段。
- 解码后仍包含 `..` 的，记为目录穿越形态，级别 high。
- 签名库里的 critical 路径，在 `critical_single_hit` 打开时出现 1 次就告警。默认打开。`/.env`、`/.git/config`、`/etc/passwd` 属于这一类。
- 其他签名要在 300 秒内累计 3 次。`/admin` 属于这一类，避免管理员打开一次后台就告警。
- `allowlist` 里的路径前缀不参与命中。不能把 `/` 放进白名单。

严重级别取本窗口里命中签名的最高级别。

可能的误报：

- 站点真的把后台放在 `/admin` 或 `/wp-admin`。
- 文档或数据包使用 `.sql`、`.bak` 后缀。
- 自己的扫描器会稳定打中 critical 签名，应该排除来源，而不是关掉规则。

每条告警都要带：

- 规则 ID 和中文名称。
- 一段直接说明观察到了什么、阈值是多少的摘要。
- `trigger` 对象，里面是窗口、阈值和实际计数值。
- 这段规则的误报说明，写进告警本身，避免以后改文案导致旧报告对不上。

### 模块 C：事件存储与查询

使用 SQLite，单文件数据库。表包括：

- `events`：标准事件。主键是事件 ID，重复插入被忽略。
- `parse_issues`：解析问题。同一文件、行号、错误码和原始行只保留一条。
- `alerts`：告警。`fingerprint` 唯一。
- `alert_evidence`：告警和证据事件 ID 的关系。
- `triage_history`：调查状态变化。
- `schema_meta`：当前只接受版本 1。

告警指纹由规则 ID、来源 IP、实体和抑制时间桶组成。抑制桶是 `窗口起点的 Unix 秒 / suppression_seconds`。默认 SSH 规则 3600 秒，路径扫描 1800 秒。

去重行为：

- 第一次见到指纹就新建告警，`hit_count` 为 1，状态为 `open`。
- 证据哈希没变时，再次检测不更新，`hit_count` 不变。因此把同一批日志再跑一遍是安全的。
- 证据哈希变了，才合并证据、延长时间窗、取更高严重级别，并把 `hit_count` 加 1。已经确认或关闭的状态保持不变。
- 展示用的证据 ID 最多保留 200 个。哈希按截断前的完整 ID 集合计算，避免截断本身造成重复计数。

查询：

- 告警可按来源 IP、严重级别、规则 ID、状态过滤。
- 时间过滤看窗口是否与查询区间重叠：`window_end >= since` 且 `window_start <= until`。
- 事件可按来源 IP、事件类型、日志来源和时间过滤。
- `limit` 最大 1000，`offset` 不能为负。过滤值全部使用参数绑定。

调查状态可以在 `open`、`acknowledged`、`resolved` 之间更新。状态没变且备注为空时报错。每次成功更新都写历史。

重新检测时，除了本批新事件，还会回看启用规则里最大的那个抑制窗口，避免一批日志刚好把同一次行为切开。

### 模块 D：报告和可视化

命令行可以输出：

- `summary`：计数、严重级别、规则、来源和每条告警一行。
- `json`：告警、触发字段、证据、误报说明、复核问题和解析问题。
- `csv`：适合用表格软件打开的告警扁平行。
- `md`：调查报告。每条告警包含触发条件、误报说明、建议复核的问题和证据时间线。

报告里的日志字段会去掉换行并转义表格竖线，避免一条恶意或损坏的日志破坏 Markdown 表格。

Streamlit 面板是可选的。它读取同一份 SQLite，展示事件数、解析问题数、告警数、严重级别、按天趋势和告警表。没安装 Streamlit 时，检测和命令行仍然可用。

复核问题只帮助判断是不是误报，例如「这个 IP 是不是已知 NAT」。不提供攻击步骤。

### 模块 E：工程质量

- pytest 覆盖解析、四条规则的触发和误报、去重、查询、合成场景和命令行。
- `data` 可以由 `authshield synth` 反复生成。场景包括只含正常与低噪声的 `benign`，以及四种行为都出现的 `mixed`。
- `benign` 不得产生告警。`mixed` 必须正好产生四条告警，且正常来源 IP 不在告警里。
- GitHub Actions 在 push 和 pull request 上安装依赖、跑 ruff、跑 pytest，并上传 coverage.xml。
- ruff 检查导入、语法和常见升级问题。行宽检查对中文句子关闭，格式化仍使用 100 列。
- Docker 镜像只提供 `authshield` 命令，不包含面板依赖。

## 6. 默认阈值

| 规则 | 窗口 | 触发 | 抑制桶 | 升级 |
| --- | --- | --- | --- | --- |
| ssh_bruteforce | 300 秒 | 5 次失败 | 3600 秒 | 10 次 high，30 次 critical |
| ssh_failure_then_success | 600 秒 | 3 次失败后成功 | 3600 秒 | 15 次失败或 5 个用户名 critical |
| web_path_scan | 120 秒 | 20 个路径、20 次请求、错误占比 0.3 | 1800 秒 | 50 个路径或错误占比 0.8 为 high |
| web_sensitive_path | 300 秒 | critical 1 次，其他 3 次 | 3600 秒 | 取签名最高级别 |

这些数字都在 `config/authshield.toml`，也是代码里的默认值。不传 `--config` 时用代码默认值，避免测试因为当前目录里的示例文件而改变行为。

## 7. 命令行

```text
authshield synth --scenario mixed --out data/samples
authshield pipeline --ssh data/samples/ssh-auth.log --web data/samples/web-access.log \
  --db data/authshield.db --report reports/investigation.md --format md
authshield query alerts --db data/authshield.db --severity high
authshield query events --db data/authshield.db --ip 203.0.113.10
authshield query issues --db data/authshield.db
authshield report --db data/authshield.db --format json --output reports/alerts.json
authshield triage --db data/authshield.db --alert-id <id> --status acknowledged --note "已查看"
authshield rules
authshield stats --db data/authshield.db
```

预期错误，例如找不到文件、配置不合法、未知场景，打印到标准错误并以状态码 2 退出。

## 8. 合成场景

`mixed` 固定在 2026-10-11，便于演示和测试。

| 来源 | 行为 | 期望 |
| --- | --- | --- |
| 198.51.100.10 | 一次成功登录 | 不告警 |
| 198.51.100.50 | 两次失败后成功 | 不告警，低于 3 次 |
| 198.51.100.80 | 四次失败，间隔一分钟 | 不告警，低于 5 次 |
| 198.51.100.20 | 八个正常页面，状态 200 | 不告警 |
| 198.51.100.60 | 十二个静态脚本 | 不告警 |
| 198.51.100.70 | 一次 `/admin` | 不告警，未到 3 次 |
| 203.0.113.10 | 八次不同用户名的失败 | `ssh_bruteforce`，medium |
| 203.0.113.44 | 四次失败后 `deploy` 成功 | `ssh_failure_then_success`，high |
| 203.0.113.77 | 二十五条 404 探测 | `web_path_scan`，high |
| 203.0.113.88 | `/.env`、`/.git/config` 等 | `web_sensitive_path`，critical |

`mixed` 另外写出 `ssh-dirty.log` 和 `web-dirty.log`，里面有空行、坏时间、坏 IP 和无法识别的行。

## 9. 非功能需求

- Python 3.12 或兼容版本。核心依赖只有标准库：`argparse`、`sqlite3`、`logging`、`tomllib`。
- 面板依赖 Streamlit，放在可选安装里。
- 日志使用标准库 `logging`。重复初始化不会叠加 handler。
- 数据库打开时启用外键和 WAL。
- 单机、单进程。一次演示的日志量在几千行以内，检测窗口使用直接扫描即可。

## 10. 已知限制

- syslog 没有年份。跨年启发式只处理「比现在超前 30 天以上」的情况，不会猜测任意历史年份。
- 百分号解码最多 3 次。更深层的编码不保证命中。
- 公钥失败和口令失败如果属于同一次会话，仍然各算一次。
- 路径扫描没有来源白名单。
- 证据展示超过 200 条时会截断 ID，但条数和哈希仍按完整集合计算。
- 调查报告最多展开 30 条证据时间线和 50 条解析问题，避免一份报告无限变长。

## 11. 验收清单

- [ ] `authshield synth --scenario benign` 再跑 pipeline，告警数为 0。
- [ ] `mixed` 场景产生且只产生四条规则告警，来源 IP 与第 8 节一致。
- [ ] 同一数据库再跑一次，新写入事件为 0，新建和更新告警都为 0。
- [ ] 坏日志进入 `query issues`，其余行仍然成为事件。
- [ ] `authshield rules` 能看到每条规则的触发条件和误报说明。
- [ ] Markdown 或 JSON 报告里能看到 `trigger` 和误报说明。
- [ ] `pytest` 通过，GitHub Actions 能跑 ruff 和覆盖率。
