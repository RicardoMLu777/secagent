# SecAgent 🔐

> 基于 **MCP (Model Context Protocol)** 的自主安全评估 Agent —— 把真实的 Kali 安全工具封装成 MCP Server，让 LLM **显式规划**、并/串行调用工具、分层记忆发现、映射 MITRE ATT&CK、自动生成报告。
>
> **安全优先**：侵入式操作默认需要人工批准，工具调用全程审计，支持目标白名单与私网访问管控。

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-1.9.4-green.svg)](https://modelcontextprotocol.io/)
[![Tests](https://img.shields.io/badge/tests-54%20passed-brightgreen.svg)](tests/)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue.svg)](.github/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 效果演示

给一个目标，Agent 自己规划、自己决定每一步做什么：

```bash
$ python secagent.py --target 192.168.1.10 --report out/report.md
```

```
╭────────────────────────────── plan ──────────────────────────────╮
│ Plan for 192.168.1.10:                                           │
│   ○ 1. Probe the target to confirm it is live (http_probe)        │
│   ○ 2. Inspect HTTP security headers (check_security_headers)     │
│   ○ 3. Review robots.txt for hidden paths (check_robots)          │
│   ○ 4. Enumerate sensitive directories (ffuf_dirs) [intrusive]    │
│   ○ 5. Port/service scan (nmap_scan) [intrusive]                  │
│   ○ 6. Consolidate into a risk assessment                         │
╰──────────────────────────────────────────────────────────────────╯

step 1 · reasoning
  → nmap_server__nmap_scan {"target": "192.168.1.10"}
     ✓ 22/tcp open ssh OpenSSH 8.2p1 / 80/tcp open http nginx 1.18.0

step 2 · reasoning
  running 3 tool calls in parallel          ← 并行执行
  → httpx_server__http_probe {"url": "http://192.168.1.10"}
  → httpx_server__check_security_headers {"url": "http://192.168.1.10"}
  → httpx_server__check_robots {"url": "http://192.168.1.10"}
     ✓ status 200, server nginx/1.18.0
     ✓ missing: content-security-policy, x-frame-options (4/6)
     ✓ interesting: /admin, /backup

step 3 · reasoning
  → ffuf_server__ffuf_dirs {"url": "http://192.168.1.10/FUZZ"}
     ✓ 7 hits: /admin (301), /backup.zip (200), ...

ATT&CK: T1046, T1592, T1083
report written: out/report.md
```

生成的报告包含 **执行计划 / ATT&CK 映射 / 配置弱点 / Agent 结论**：

```markdown
# SecAgent Assessment Report

**Steps used:** 5   **Tool calls:** 11

## Summary
- Open ports: 22, 80
- Services: ssh, nginx 1.18.0
- Missing security headers: content-security-policy, x-frame-options

## Plan execution
| # | Task | Status | Intrusive |
|---|------|--------|-----------|
| 1 | Probe the target | done | no |
...

## MITRE ATT&CK techniques observed
| ID | Technique | Tactic |
|----|-----------|--------|
| T1046 | Network Service Discovery | Discovery |
| T1592 | Gather Victim Host Information | Reconnaissance |
| T1083 | File and Directory Discovery | Discovery |

## Configuration weaknesses
- **content-security-policy** — No CSP: reflected XSS has no browser-level mitigation.

## Agent report
### Findings
...
```

---

## 架构

```
┌──────────────────────────────────────────────────────────┐
│                      SecAgent                            │
│                                                          │
│   ┌──────────────┐        ┌──────────────────────────┐   │
│   │   Planner    │───────▶│   ReAct Execution Loop   │   │
│   │              │        │                          │   │
│   │ 1. plan()    │        │  think → call → observe  │   │
│   │ 2. revise()  │◀───3────│  (parallel tool calls)   │   │
│   └──────────────┘  steps └────────────┬─────────────┘   │
│                                        │                 │
│                          ┌─────────────┴─────────────┐   │
│                          │      Tiered Memory        │   │
│                          │  raw observations +       │   │
│                          │  distilled findings       │   │
│                          └───────────────────────────┘   │
│                                        │                 │
│            ┌─────────────┴─────────────┐                 │
│            │  Policy Gate              │                 │
│            │  deny / ask / allow       │                 │
│            └─────────────┬─────────────┘                 │
│            ┌─────────────┴─────────────┐                 │
│            │  ATT&CK Mapper + Report   │                 │
│            │  + SQLite History         │                 │
│            └───────────────────────────┘                 │
└──────────────────────────┬───────────────────────────────┘
                           │ MCP protocol (stdio)
     ┌────────────┬────────┴───────┬────────────┐
     ▼            ▼                ▼            ▼
┌──────────┐ ┌──────────┐ ┌───────────┐ ┌──────────┐
│  nmap    │ │  httpx   │ │  sqlmap   │ │   ffuf   │
│ 2 tools  │ │ 3 tools  │ │  3 tools  │ │  1 tool  │
└────┬─────┘ └────┬─────┘ └─────┬─────┘ └────┬─────┘
     ▼            ▼             ▼            ▼
   nmap       httpx+re     sqlmap       ffuf
```

### 模块职责

| 模块 | 文件 | 职责 |
|------|------|------|
| **Planner** | `agent/planner.py` | Plan-and-Execute：一次性分解目标 + 每 3 步重规划 |
| **ReAct Core** | `agent/core.py` | 推理→调用工具→观察循环，支持并行工具调用 |
| **MCP Manager** | `agent/mcp_client.py` | MCP Server 生命周期、工具发现、命名空间隔离 |
| **Memory** | `agent/memory.py` | 双层记忆：原始观察（有预算）+ 结构化发现 |
| **ATT&CK Mapper** | `agent/attack_map.py` | 发现 → MITRE ATT&CK 技术 ID + 配置弱点说明 |
| **Policy** | `agent/policy.py` | 工具分级、目标白名单、人工批准门控 |
| **Store** | `agent/store.py` | SQLite 持久化 + 历次扫描对比 |
| **Retry** | `agent/retry.py` | 瞬时错误指数退避重试 |
| **Report** | `agent/report.py` | 渲染 Markdown / JSON 报告 |

---

## 安全模型

自主 Agent 执行真实的攻击工具，最大的风险是它自己决定去做什么。SecAgent 用三层约束解决这个问题。

### 1. 工具分级 — 侵入式操作默认需要人工批准

```python
PASSIVE_TOOLS   = {"http_probe", "check_security_headers", "check_robots"}
INTRUSIVE_TOOLS = {"nmap_scan", "nmap_vuln_scan", "sqlmap_scan",
                   "sqlmap_dump", "ffuf_dirs", ...}
```

```bash
$ python secagent.py --target 192.168.1.10 --policy ask

step 2 · reasoning
  → sqlmap_server__sqlmap_scan {"url": "http://192.168.1.10/news.php?id=1"}

╭──────────────────── ⚠ approval required ────────────────────╮
│ sqlmap_scan                                                 │
│ {"url": "http://192.168.1.10/news.php?id=1"}                │
│                                                             │
│ 'sqlmap_scan' sends intrusive traffic and needs approval    │
╰─────────────────────────────────────────────────────────────╯
  Allow this action? [y/N]
```

三种模式：

| 模式 | 被动工具 | 侵入工具 | 适用场景 |
|------|---------|---------|---------|
| `passive` | ✅ 自动放行 | ❌ 一律拒绝 | 生产环境的只读侦察 |
| `ask`（默认） | ✅ 自动放行 | ⚠️ 弹窗等人工确认 | 常规渗透测试 |
| `allow` | ✅ | ✅ | 明确授权的靶场 / 红队演练 |

**未配置批准人时默认拒绝**（fail closed）——这是刻意的，避免"配置漏了"变成"全放行"。

被拒绝的调用会以结构化 JSON 反馈给模型，并附上指引：

```json
{
  "blocked": true,
  "tool": "sqlmap_server__sqlmap_scan",
  "reason": "'sqlmap_scan' sends intrusive traffic and needs approval",
  "guidance": "This action was blocked by the engagement policy. Do not retry it."
}
```

模型拿到这个不会死循环重试，而是转向被动手段或在报告里说明需要授权。

### 2. 目标管控 — 白名单 + 私网保护

```bash
# 只允许指定域名，越界一律拒绝
python secagent.py --target x --scope 'example\.com' --scope 'testsite\.org'

# 禁止访问回环/内网地址（防 SSRF 式的误操作）
python secagent.py --target x --deny-private

# 彻底禁用某个工具
python secagent.py --target x --deny-tools sqlmap_dump ffuf_dirs
```

`--deny-private` 拦截 `127.`、`10.`、`172.16-31.`、`192.168.`、`169.254.`——这条规则在扫内网时要注意关掉。

### 3. 全链路审计

每次工具调用都记录决策与理由：

```bash
$ python secagent.py --target x --policy ask --json | jq '.tool_audit'
[
  {"step": 1, "tool": "httpx_server__http_probe",
   "decision": "allow", "reason": "passive reconnaissance"},
  {"step": 2, "tool": "sqlmap_server__sqlmap_scan",
   "decision": "ask-denied",
   "reason": "'sqlmap_scan' sends intrusive traffic and needs approval..."}
]
```

审计日志同时落库，可以回溯"这次评估到底跑过什么、谁批的"。

---

## 快速开始

### 环境要求

- Python 3.11+
- Linux（nmap / sqlmap / ffuf 需要，缺失的工具会被自动跳过）
- 一个 OpenAI 兼容的 LLM API

```bash
sudo apt install nmap sqlmap ffuf
```

### 安装

```bash
git clone https://github.com/<your-username>/secagent.git
cd secagent
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 配置

```bash
cp .env.example .env
# 编辑 .env，填入 DEEPSEEK_API_KEY
```

兼容任意 OpenAI 协议端点：

```bash
SECAGENT_BASE_URL=https://api.deepseek.com/v1   # DeepSeek
SECAGENT_BASE_URL=https://api.openai.com/v1     # OpenAI
SECAGENT_BASE_URL=http://localhost:11434/v1     # Ollama 本地
```

### 运行

```bash
# 给目标，自动规划
python secagent.py --target 192.168.1.10

# 自然语言目标
python secagent.py "审计 example.com 的安全头配置和敏感路径"

# 输出报告文件
python secagent.py --target example.com --report out/example.md

# 加载全部 MCP Server
python secagent.py --target x --all-servers

# 关闭规划/并行（对比实验用）
python secagent.py --target x --no-planner --no-parallel

# JSON 输出（便于集成到 CI）
python secagent.py --target x --json
```

---

## MCP 工具清单

### `nmap_server.py`

| 工具 | 说明 | ATT&CK |
|------|------|--------|
| `nmap_scan` | 端口扫描 + 服务版本识别 | T1046 |
| `nmap_vuln_scan` | NSE 漏洞脚本扫描 | T1595 |

### `httpx_server.py`

| 工具 | 说明 | ATT&CK |
|------|------|--------|
| `http_probe` | 状态码、响应头、标题、技术指纹 | T1592 |
| `check_security_headers` | 6 个关键安全头缺失审计 | — |
| `check_robots` | robots.txt 解析，标记敏感路径 | T1590 |

### `sqlmap_server.py`

| 工具 | 说明 | ATT&CK |
|------|------|--------|
| `sqlmap_scan` | SQL 注入检测 | T1190 |
| `sqlmap_tables` | 枚举数据库表 | — |
| `sqlmap_dump` | 导出表数据（需显式指定库表） | T1213 |

### `ffuf_server.py`

| 工具 | 说明 | ATT&CK |
|------|------|--------|
| `ffuf_dirs` | 目录/文件爆破（自带迷你字典） | T1083 |

---

## 设计要点

### 1. 显式规划 vs 纯 ReAct

纯 ReAct 的问题：模型边想边做，容易在细节里打转。SecAgent 拆成两阶段：

```python
# 阶段一：无工具环境下的纯规划（模型不会忍不住直接开火）
plan = planner.plan(objective, available_tools)

# 阶段二：带计划执行
result = await agent.run(objective, plan=plan)

# 阶段三：每 3 步让 planner 复核，可 continue / revise / done
action, plan = planner.revise(objective, plan, findings_so_far)
```

规划调用**不挂工具**，这是关键——模型只能思考 `做什么`，不能直接 `做`。

### 2. 并行工具调用

模型一轮返回多个 tool_calls 时，用 `asyncio.gather` 并发执行：

```python
if self.parallel and len(parsed) > 1:
    results = await asyncio.gather(
        *(mcp.call(tc.function.name, args) for tc, args in parsed),
        return_exceptions=True,
    )
```

无依赖的调用（http_probe + check_headers + check_robots）一轮搞定，实测省 40%+ 时间。

### 3. 双层记忆

大多数 Agent 把全部工具输出塞进 context，很快就爆了：

```python
# 第一层：原始观察（有长度预算，超长截断）
observations = [Observation(step=1, tool="nmap_scan", result="...")]

# 第二层：结构化事实（用正则从原始输出抽取）
findings = {
    "open_ports": {"22", "80"},
    "services": {"ssh", "nginx 1.18.0"},
    "missing_headers": {"content-security-policy"},
    "interesting_paths": {"/admin", "/backup"},
    "flags": set(),
}
```

每轮只注入 **摘要 + 最近 2 条观察**，而非全量历史。

### 4. 工具命名空间

多个 Server 可能有同名工具，统一加前缀：

```
nmap_server__nmap_scan
httpx_server__http_probe
```

### 5. 安全加固

- 所有系统命令用 **list 形式**调用（不经 shell），并在参数层面过滤元字符：
  ```python
  if re.search(r"[;&|`$><\n]", target):
      return "error: invalid characters in target"
  ```
- `sqlmap_dump` 的库名/表名/列名全部正则白名单校验
- System prompt 明确 Rules of Engagement：只对授权目标操作、优先非侵入、不伪造输出

---

## 历史与对比

每次评估自动落库（SQLite，默认 `~/.secagent/engagements.db`），可以回溯和对比同一个目标的历次扫描。

```bash
# 查看历史
$ python secagent.py history --target example.com

         Engagement history
┏━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ ID ┃ Target     ┃ Started             ┃ Steps ┃ Calls ┃ Flags              ┃
┡━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ 7  │ example.com│ 2026-09-17T14:20:11 │ 6     │ 14    │ flag{new_finding}  │
│ 3  │ example.com│ 2026-09-10T09:02:44 │ 5     │ 11    │ -                  │
└────┴────────────┴─────────────────────┴───────┴───────┴────────────────────┘

# 对比两次扫描
$ python secagent.py diff 3 7

example.com  #3 (2026-09-10T09:02:44) → #7 (2026-09-17T14:20:11)
  + ports: 8080
  - headers: x-frame-options
  + flags: flag{new_finding}
  = services: no change (4)

# 所有评估过的目标
$ python secagent.py targets
```

对比维度：开放端口、服务版本、缺失的安全头、敏感路径、Flag。

关掉持久化用 `--no-store`，或指定库路径 `--db /path/to.db`。

---

## 容错

工具调用遇到网络抖动、超时、5xx 时自动重试（指数退避 + 抖动），最多 3 次：

```python
TRANSIENT_MARKERS = (
    "timeout", "connection refused", "connection reset",
    "502 bad gateway", "503 service unavailable", "rate limit", ...
)
```

只有**瞬时错误**才重试——遇到"目标不可达"这类确定性失败直接返回，不做无谓等待。重试过程会打印 `↻ retry 1` 让使用者看到。

调整次数：`retry_attempts=5`（构造参数）。

---

## CI

推送到 `main` 自动触发 GitHub Actions：

```yaml
matrix: python 3.11 / 3.12 / 3.13
  - pytest tests/          # 54 个测试
lint:
  - ruff check .           # E/F/W 规则
  - compileall             # 字节码编译检查
```

CI 曾经抓到过一个真 bug：`ffuf_server.py` 里 `ext` 变量名写错（应为 `exts`），静态检查直接暴露。这就是把 lint 放进 CI 的价值。

---

## 扩展新的 MCP Server

在 `mcp_servers/` 下按模板新建即可，运行时钟自动发现：

```python
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app = Server("myserver")

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [Tool(
        name="my_tool",
        description="What this tool does",
        inputSchema={"type": "object", "properties": {...}, "required": [...]},
    )]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(result))]

async def main():
    async with stdio_server() as (r, w):
        await app.run(r, w, app.create_initialization_options())
```

```bash
python secagent.py --target X --servers nmap_server.py myserver.py
```

**推荐扩展方向**：`nuclei_server.py`、`nikto_server.py`、`gobuster_server.py`、`hydra_server.py`

---

## 项目结构

```
secagent/
├── agent/
│   ├── __init__.py
│   ├── core.py           # ReAct 主循环 + 并行执行
│   ├── planner.py        # Plan-and-Execute 规划层
