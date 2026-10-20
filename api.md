# AuthShield 接口文档（第一周 MVP）

基础地址：`http://127.0.0.1:8000`

交互式文档（可点按钮试）：http://127.0.0.1:8000/docs

当前版本没有登录鉴权。启动后即可调用。

```bash
python -m authshield
```

工作目录必须是项目根目录（`access.log` 所在的位置），否则导入会提示找不到文件。

## 推荐调用顺序

1. `GET /health` — 确认服务已启动  
2. `POST /ingest/web` — 导入 `access.log`  
3. `POST /detect` — 对库中事件跑路径扫描规则  
4. `GET /alerts` — 查看告警列表  
5. `GET /alerts/{alert_id}` — 查看某一条详情和证据  

导入不会自动检测。检测不会再读日志文件，只读取 SQLite 里已有事件。

---

## GET `/health`

健康检查。不读写数据库。

**请求：** 无参数、无请求体。

**成功（200）：**

```json
{"status": "ok"}
```

```bash
curl http://127.0.0.1:8000/health
```

---

## POST `/ingest/web`

导入一份 Nginx combined 格式的 Web 访问日志。

能解析的行写入 `events` 表；非 HTTP 或格式错误的行写入 `parse_issues`。同一行重复导入会被忽略，计数不会翻倍。空行默认跳过，不计入 `lines_parsed`。

**请求体（JSON，必填）：**

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `path` | string | 相对项目根目录的日志路径，例如 `access.log`。也会接受项目内的绝对路径。 |

路径必须落在当前工作目录内，且必须是普通文件。不允许用 `..` 指到项目外（例如 `/etc/passwd`）。

```json
{"path": "access.log"}
```

**成功（200）：**

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `file` | string | 文件名（不含目录） |
| `lines_parsed` | int | 被解析的行数：事件 + 问题行 |
| `events_inserted` | int | 新写入事件表的条数 |
| `events_ignored` | int | 因已存在而跳过的事件条数 |
| `issues_inserted` | int | 新写入问题表的条数 |

示例（第一次导入仓库里的 `access.log`）：

```json
{
  "file": "access.log",
  "lines_parsed": 8643,
  "events_inserted": 8613,
  "events_ignored": 0,
  "issues_inserted": 30
}
```

再导一次同一文件时，`events_inserted` 和 `issues_inserted` 应为 0，`events_ignored` 约为 8613。

**失败：**

| HTTP | `detail` | 原因 |
| --- | --- | --- |
| 400 | `path is outside the project` | 路径解析后不在项目目录内 |
| 400 | `file not found: ...` | 路径合法但文件不存在，或不是普通文件 |
| 422 | FastAPI 校验错误 | 缺少 `path`，或类型不是字符串 |

```bash
curl -X POST http://127.0.0.1:8000/ingest/web \
  -H 'content-type: application/json' \
  -d '{"path":"access.log"}'
```

---

## POST `/detect`

对数据库中全部 `http_access` 事件运行规则 `web_path_scan`，并把告警写入 `alerts` 表。

不读日志文件。若从未导入过，结果计数全为 0。

同一指纹且证据哈希未变时，不会增加 `hit_count`，`created` 为 0、`skipped` 为候选条数。

**请求：** 无参数、无请求体。

**成功（200）：**

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `created` | int | 新建告警条数 |
| `updated` | int | 证据变化后合并更新的条数 |
| `skipped` | int | 指纹已存在且证据未变，跳过的条数 |
| `candidates` | int | 本次规则产出的告警候选数 |

示例（对 `access.log` 第一次检测）：

```json
{
  "created": 5,
  "updated": 0,
  "skipped": 0,
  "candidates": 5
}
```

```bash
curl -X POST http://127.0.0.1:8000/detect
```

### 规则说明（`web_path_scan`）

同一来源 IP 在 120 秒内同时满足：

- 规范化后的不同路径数 ≥ 20  
- 参与统计的请求数 ≥ 20  
- 状态码 ≥ 400 的占比 ≥ 0.3  

静态资源（`.js` / `.css` / 图片 / 字体 / source map）不参与统计。  
默认严重级别为 `medium`；不同路径 ≥ 50 或错误占比 ≥ 0.8 时为 `high`。

业务心跳 `POST /transport` 因路径单一、状态多为 200，不应产生告警。

---

## GET `/alerts`

列出告警，按 `window_start` 从新到旧。列表**不含**证据数组，证据只在详情接口返回。

**查询参数（均可选）：**

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `ip` | string | 精确匹配来源 IP |
| `severity` | string | 精确匹配严重级别，当前可能为 `medium` 或 `high` |

不传则返回全部告警。

**成功（200）：**

```json
{
  "count": 5,
  "alerts": [
    {
      "alert_id": "…",
      "fingerprint": "web_path_scan|163.7.11.19|-|…",
      "rule_id": "web_path_scan",
      "rule_name": "短时间访问大量不同路径",
      "src_ip": "163.7.11.19",
      "entity": "-",
      "severity": "high",
      "status": "open",
      "summary": "来源 163.7.11.19 在 120 秒内访问了 …",
      "trigger": {
        "window_seconds": 120,
        "min_distinct_paths": 20,
        "min_requests": 20,
        "min_error_ratio": 0.3,
        "distinct_paths": 422,
        "requests": 432,
        "error_count": 432,
        "error_ratio": 1.0
      },
      "false_positive": "爬虫和监控会访问很多路径…",
      "window_start": "2026-10-12T16:07:07Z",
      "window_end": "2026-10-12T16:09:07Z",
      "hit_count": 1
    }
  ]
}
```

告警对象字段：

| 字段 | 说明 |
| --- | --- |
| `alert_id` | 告警 ID，用于详情接口 |
| `fingerprint` | 去重指纹：规则 + IP + 抑制时间桶 |
| `rule_id` / `rule_name` | 规则英文 ID 与中文名称 |
| `src_ip` | 来源 IP |
| `entity` | 实体；路径扫描当前固定为 `-` |
| `severity` | `medium` 或 `high` |
| `status` | 调查状态，MVP 新建时为 `open` |
| `summary` | 可读摘要（含阈值和实际计数） |
| `trigger` | 机器可核对的触发字段 |
| `false_positive` | 写入告警时的误报说明 |
| `window_start` / `window_end` | 触发窗口（UTC，`YYYY-MM-DDTHH:MM:SSZ`） |
| `hit_count` | 同一指纹被合并的次数 |

```bash
curl http://127.0.0.1:8000/alerts
curl 'http://127.0.0.1:8000/alerts?ip=163.7.11.19'
curl 'http://127.0.0.1:8000/alerts?severity=high'
```

---

## GET `/alerts/{alert_id}`

按 ID 取单条告警。字段与列表相同，并额外包含 `evidence`（最多 50 条）。

**路径参数：**

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `alert_id` | string | 列表接口返回的 `alert_id` |

**成功（200）：** 告警对象，另含：

| 字段 | 说明 |
| --- | --- |
| `evidence` | 窗口内证据事件，按时间排序，最多 50 条 |

`evidence` 中每条：

| 字段 | 说明 |
| --- | --- |
| `event_id` | 事件 ID |
| `ts` | UTC 时间 |
| `method` | HTTP 方法 |
| `path` | 原始路径 |
| `path_norm` | 规范化路径（去 query、折叠 `.` / `..`） |
| `status` | 状态码 |

**失败：**

| HTTP | `detail` | 原因 |
| --- | --- | --- |
| 404 | `alert not found` | ID 不存在 |

```bash
curl http://127.0.0.1:8000/alerts/<alert_id>
```

---

## 尚未提供的接口

第一周 MVP 没有：

- 文件上传（multipart）；只接受项目内路径  
- SSH 日志导入  
- 解析问题列表（问题已写入数据库，但无查询接口）  
- 修改调查状态（triage）  
- 敏感路径规则、报告导出  

这些计划在后续周次加入。
