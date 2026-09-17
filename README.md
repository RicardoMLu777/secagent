# SecAgent 🔐

> 基于 **MCP (Model Context Protocol)** 的自主安全评估 Agent —— 把真实的 Kali 安全工具封装成 MCP Server，让 LLM **显式规划**、并/串行调用工具、分层记忆发现、映射 MITRE ATT&CK、自动生成报告。

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-1.9.4-green.svg)](https://modelcontextprotocol.io/)
[![Tests](https://img.shields.io/badge/tests-20%20passed-brightgreen.svg)](tests/)
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
│                          ┌─────────────┴─────────────┐   │
│                          │   ATT&CK Mapper + Report  │   │
│                          └───────────────────────────┘   │
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
| **Report** | `agent/report.py` | 渲染 Markdown / JSON 报告 |

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
│   ├── mcp_client.py     # MCP Server 生命周期 + 工具发现
│   ├── memory.py         # 双层记忆
│   ├── attack_map.py     # MITRE ATT&CK 映射
│   └── report.py         # Markdown / JSON 报告
├── mcp_servers/
│   ├── nmap_server.py    # 2 tools
│   ├── httpx_server.py   # 3 tools
│   ├── sqlmap_server.py  # 3 tools
│   └── ffuf_server.py    # 1 tool
├── tests/                # 20 个单元测试
├── secagent.py           # CLI 入口
├── requirements.txt
├── .env.example
└── LICENSE
```

---

## 测试

```bash
pytest tests/ -v
# 20 passed
```

覆盖：记忆蒸馏、ATT&CK 映射、报告渲染、规划器 JSON 解析、计划状态机。

---

## 已知限制

- **无跨会话持久记忆**：每次运行是一次性任务，不累积历史
- **规划质量依赖模型**：小模型可能产出模糊的计划
- **无主动确认机制**：标记为 `[intrusive]` 的任务不会真的停下来等人工确认（目前只在 prompt 里提示）
- **单目标**：一次运行针对一个目标，无多目标编排

这些都是有意的 MVP 取舍。

---

## Roadmap

- [ ] 向量库长期记忆（跨会话积累目标画像）
- [ ] `[intrusive]` 任务的人工确认门控
- [ ] 更多 MCP Server（nuclei / nikto / gobuster）
- [ ] Web UI（可视化计划执行过程）
- [ ] 多目标批量编排
- [ ] 报告导出 PDF

---

## 法律声明

**本项目仅供授权的安全测试、研究和教育用途。**

使用前必须获得目标系统的**明确书面授权**。未经授权对他人系统进行扫描或攻击是违法的。使用者需自行承担全部法律责任。

---

## License

MIT
