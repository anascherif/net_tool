# ERREETOOL

> **Autonomous AI Penetration Testing Toolkit** — A free, cross-platform CLI agent with skill-driven workflows, persistent memory, safety gates, MITRE ATT&CK mapping, attack path analysis, compliance reporting, REST API, and plugin architecture.

---

## ✨ Features

### 🤖 Autonomous AI Agent (`assess`)
- **LLM-driven or skill-driven modes** — Free models via OpenRouter, Groq, Together.ai, NVIDIA NIM
- **Evidence-based reasoning** — Every claim backed by tool output; anti-hallucination gate
- **Persistent memory** — Learns across sessions: finding patterns, CVE knowledge, credential patterns, tool effectiveness
- **Safety gates** — Risk classification (SAFE→CRITICAL), human-in-the-loop approvals, CI/CD non-interactive mode
- **Exploitation verification** — Controlled exploit execution with `--allow-exploitation`

### 🎯 Skill Engine (18 Built-in Skills)
| Category | Skills |
|----------|--------|
| **Recon** | `quick-triage`, `nmap-recon`, `full-port-scan`, `web-tech-fingerprint`, `web-enumeration`, `directory-bruteforce` |
| **Vuln** | `nuclei-vuln-scan`, `sqli-detection`, `crypto-analysis` |
| **AD/Identity** | `ad-enumeration`, `ldap-enumeration`, `kerberos-enumeration`, `smb-enumeration`, `privilege-escalation` |
| **Cloud/Container** | `cloud-aws-recon`, `docker-enumeration`, `subdomain-enumeration`, `api-testing` |

### 🧠 Advanced Analysis (Phase 6)
- **Attack Path Planning** — Graph-based paths from host → service → vuln/cred with risk scoring
- **MITRE ATT&CK Mapping** — 40+ techniques, heatmap, technique tables in reports
- **Compliance Reporting** — NIST CSF, ISO 27001, PCI-DSS v4.0, CIS Controls v8

### 🌐 Enterprise Features (Phase 7)
- **REST API** — FastAPI server with JWT auth, RBAC (admin/analyst/viewer)
- **Plugin Architecture** — Custom tools, skills, providers, lifecycle hooks
- **Campaign Management** — Multi-target scheduled assessments
- **CI/CD Integration** — GitHub Actions + GitLab CI pipelines

---

## 🚀 Quick Start

### Requirements
- Python 3.11+
- Windows / Linux / macOS

### Installation

```bash
# Clone
git clone https://github.com/anascherif/net_tool.git
cd net_tool

# Create venv & install
python -m venv .venv
# Windows:
.venv\Scripts\activate && pip install -r requirements.txt
# Linux/macOS:
source .venv/bin/activate && pip install -r requirements.txt

# Install security tools (nmap, nuclei, whatweb, gobuster, sqlmap, SecLists)
# Windows:
.\scripts\install-tools.ps1
# Linux/macOS:
chmod +x scripts/install-tools.sh && ./scripts/install-tools.sh

# Configure API keys (at least one required for LLM mode)
cp .env.example .env
# Edit .env with your keys: OPENROUTER_API_KEY, GROQ_API_KEY, TOGETHER_API_KEY, NVIDIA_NIM_API_KEY
```

### Run the CLI

```bash
# Interactive menu
.venv\Scripts\python.exe ict_tool.py

# Direct commands
.venv\Scripts\python.exe -m erreetool.cli assess 192.168.1.100 --skill quick-triage
.venv\Scripts\python.exe -m erreetool.cli assess 10.10.10.27 --full
.venv\Scripts\python.exe -m erreetool.cli scan 192.168.1.0/24
.venv\Scripts\python.exe -m erreetool.cli ports 192.168.1.1 --full
.venv\Scripts\python.exe -m erreetool.cli doctor --json
.venv\Scripts\python.exe -m erreetool.cli skill list
.venv\Scripts\python.exe -m erreetool.cli memory sessions
```

---

## 📖 Commands Reference

### Core Networking
| Command | Description |
|---------|-------------|
| `scan <cidr>` | ARP network scan |
| `ports <target> [--full]` | Port scan with service detection |
| `dns <domain>` | DNS record lookup (A/AAAA/MX/TXT/NS) |
| `ping <host>` | ICMP echo with statistics |
| `trace <host>` | Traceroute |
| `wifi` | Wi-Fi/interface info |
| `speedtest` | Internet bandwidth test |
| `doctor [--json]` | Diagnostic health check (tools, keys, wordlists) |

### AI Assessment (`assess`)
```bash
# Quick skill-driven triage (default)
erreetool assess 192.168.1.100

# Full assessment with all tools
erreetool assess 192.168.1.100 --full

# Specific skill(s)
erreetool assess 192.168.1.100 --skill ad-enumeration,kerberos-enumeration

# Offline demo mode (no LLM)
erreetool assess 192.168.1.100 --offline

# With custom goal
erreetool assess 192.168.1.100 --goal "Find path to domain admin"

# Safety gate config
erreetool assess 192.168.1.100 --non-interactive  # CI/CD mode
```

**Assess Options:**
- `--full` / `--quick` — Depth control
- `--skill <name>` — Comma-separated skill names
- `--skill-mode auto|quick|full` — Skill selection mode
- `--offline` — No LLM calls
- `--max-steps <n>` — Step limit (default 30)
- `--goal <text>` — Specific objective
- `--interactive / -i` — REPL mode
- `--explain` — Show AI reasoning

### Skill Management
```bash
erreetool skill list              # List all skills
erreetool skill list --tag web    # Filter by tag
erreetool skill show --name quick-triage  # Show skill details
erreetool skill validate --file my-skill.yml  # Validate YAML
```

### Memory
```bash
erreetool memory sessions         # List past sessions
erreetool memory patterns         # List finding patterns
erreetool memory export --format json  # Export memory
erreetool memory clear            # Clear all memory
```

### REST API Server
```bash
erreetool api --host 0.0.0.0 --port 8000 --reload
```
- **Docs:** http://localhost:8000/docs
- **Auth:** JWT Bearer tokens (`/api/v1/auth/login`)
- **Endpoints:** Assessments, Campaigns, Skills, Memory, Reports

---

## 🔌 Plugin System

Extend ERREETOOL without modifying core code.

### Plugin Types
| Type | Interface | Example |
|------|-----------|---------|
| **Tool** | `ToolPlugin` → `ToolWrapper` | Custom scanner |
| **Skill** | `SkillPlugin` → YAML definition | Custom workflow |
| **Provider** | `ProviderPlugin` → `LLMProvider` | Custom LLM |
| **Hooks** | `HookPlugin` → lifecycle callbacks | Notifications |

### Installation
```bash
# User directory (auto-discovered)
# Windows: %APPDATA%\erreetool\plugins\
# Linux: ~/.local/share/erreetool/plugins/

# Or project directory
mkdir -p erreetool/plugins/my-plugin
```

### Example: Custom Tool Plugin
```python
# erreetool/plugins/mytool/__init__.py
from erreetool.plugins import ToolPlugin, PluginMetadata
from erreetool.agent.tools.base import ToolWrapper, ToolResult

class MyTool(ToolWrapper):
    name = "mytool"
    windows_binary = "mytool.exe"
    linux_binary = "mytool"
    def build_args(self, **kwargs): return [kwargs.get("target", "")]
    def run(self, **kwargs): ...

class MyToolPlugin(ToolPlugin):
    @property
    def metadata(self): return PluginMetadata(name="my-tool", version="1.0.0", description="...")
    def get_tool_class(self): return MyTool
    def get_tool_name(self): return "mytool"

def get_plugin(): return MyToolPlugin()
```

---

## 📊 Report Output

Reports include:
- **Executive Summary** — Target, duration, scope
- **Summary Statistics** — Steps, evidence, facts, MITRE techniques, attack paths
- **Compliance Summary** — Per-framework control coverage
- **MITRE ATT&CK Heatmap** — Tactic coverage visualization
- **Top Techniques Table** — Technique ID, name, count, tactics
- **Attack Paths** — Risk-scored paths with MITRE techniques
- **Verified Facts** — High-signal findings with evidence IDs
- **Tool Usage** — Success/failure per tool
- **Evidence Log** — Raw tool outputs

**Formats:** Markdown (default), HTML, JSON

---

## ⚙️ Configuration

### Environment Variables (`.env`)
```bash
# LLM Providers (at least one required)
OPENROUTER_API_KEY=sk-or-...
GROQ_API_KEY=gsk_...
TOGETHER_API_KEY=...
NVIDIA_NIM_API_KEY=...

# Optional overrides
OPENROUTER_MODEL=anthropic/claude-3-haiku
GROQ_MODEL=llama3-70b-8192
TOGETHER_MODEL=meta-llama/Llama-3-70b-chat-hf

# Paths
ERREETOOL_MEMORY_DIR=/custom/memory/path
ERREETOOL_OUTPUT_DIR=/custom/output/path
ERREETOOL_WORDLIST_DIR=/custom/wordlists

# API Server
ERREETOOL_API_SECRET=your-secret-key
ERREETOOL_API_ADMIN_USER=admin
ERREETOOL_API_ADMIN_PASS=secure-password
ERREETOOL_API_CORS_ORIGINS=https://yourdomain.com
```

### Agent Config (Programmatic)
```python
from erreetool.agent.loop import AgentLoop, AgentConfig
from erreetool.agent.safety import RiskLevel

config = AgentConfig(
    max_steps=50,
    max_duration=3600,
    skill_mode=True,
    skill_names="quick-triage,nuclei-vuln-scan",
    skill_mode_type="auto",
    use_memory=True,
    use_safety_gate=True,
    non_interactive=True,           # CI/CD: auto-deny dangerous
    auto_approve_below=RiskLevel.MODERATE,
    allow_exploitation=False,       # Master exploit switch
    human_in_loop=False,
)
```

---

## 🛡️ Safety & Ethics

- **Authorization required** — Only scan systems you own or have explicit permission to test
- **Safety gates** — Dangerous actions (exploitation, data exfiltration, destructive commands) require approval
- **Non-interactive mode** — CI/CD pipelines auto-deny risky actions
- **Audit trail** — All tool executions, approvals, and findings logged with evidence IDs

---

## 🏗️ Architecture

```
erreetool/
├── agent/
│   ├── loop.py           # Autonomous agent loop
│   ├── state.py          # Session state & evidence
│   ├── providers.py      # LLM providers (4 free tiers)
│   ├── safety.py         # Risk classification & approvals
│   ├── attack_path.py    # Graph-based attack planning
│   ├── mitre.py          # MITRE ATT&CK mapping
│   ├── memory/           # Persistent memory (store, retriever, schema)
│   ├── skills/           # Skill engine (loader, executor, registry, schema)
│   └── tools/            # Tool wrappers (nmap, nuclei, whatweb, gobuster, sqlmap, crypto, shell)
├── api/                  # FastAPI REST server
├── plugins/              # Plugin system + examples
├── compliance/           # NIST, ISO, PCI-DSS, CIS mapping
├── reporting/            # Report generator (MD/HTML/JSON)
├── commands/             # CLI commands (Typer)
├── config/               # Stable cross-platform paths
└── skills/*.yml          # 18 built-in YAML skills
```

---

## 🧪 Testing

```bash
# Run all tests
.venv\Scripts\python.exe -m pytest tests/ -v

# Run specific test file
.venv\Scripts\python.exe -m pytest tests/test_skills.py -v
```

---

## 📦 CI/CD

- **GitHub Actions** (`.github/workflows/ci.yml`) — Lint, type-check, test, security, build, publish
- **GitLab CI** (`.gitlab-ci.yml`) — Parallel stages, coverage, Docker, deploy

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

## 🙋 Contact

- **Issues:** [GitHub Issues](https://github.com/anascherif/net_tool/issues)
- **Author:** [anas abd elmalek cherif](https://github.com/anascherif)

---

> **⚠️ Legal Notice:** This tool is for authorized security testing only. Unauthorized scanning of systems you do not own or have explicit permission to test is illegal in most jurisdictions. The authors assume no liability for misuse.