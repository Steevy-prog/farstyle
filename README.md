# FARSTYLE — Authentication Security Auditor

> A desktop security auditing platform with an AI workspace, proxy, intruder, repeater, module engine, and knowledge base — all in one native binary.

---

## Table of Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Building & Running](#building--running)
4. [First Launch](#first-launch)
5. [AI Configuration](#ai-configuration)
6. [Module System](#module-system)
7. [User Modules](#user-modules)
8. [Workspace & AI Commands](#workspace--ai-commands)
9. [System Tools](#system-tools)
10. [Directory Structure](#directory-structure)
11. [Troubleshooting](#troubleshooting)

---

## Requirements

### Mandatory

| Dependency | Minimum Version | Purpose |
|---|---|---|
| **Rust + Cargo** | 1.80+ | Build the application |
| **Python 3** | 3.10+ | Run user Python modules |

### Optional (enhances AI tool selection)

| Tool | Install | Purpose |
|---|---|---|
| `nmap` | `brew install nmap` | Port & service scanning |
| `httpx` | `brew install httpx` | Fast HTTP probing |
| `ffuf` | `brew install ffuf` | Directory & parameter fuzzing |
| `sqlmap` | `brew install sqlmap` | Deep SQL injection exploitation |
| `nikto` | `brew install nikto` | Web server misconfiguration scan |
| `nuclei` | `brew install nuclei` | Template-based vulnerability scan |
| `gobuster` | `brew install gobuster` | Directory brute-forcing |
| `whatweb` | `brew install whatweb` | Web technology fingerprinting |
| `subfinder` | `brew install subfinder` | Subdomain enumeration |

> The AI checks which tools are installed at runtime and prefers them over fallbacks. None are required to run the app.

### System

- **OS**: macOS 12+ (primary), Linux (supported), Windows (untested)
- **RAM**: 256 MB minimum
- **Network**: Required for AI features and scanning targets
- **OpenGL**: Required for the GUI (any modern GPU driver)

---

## Installation

### 1. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### 2. Install Python 3 (if not present)

```bash
# macOS
brew install python3

# Debian/Ubuntu
sudo apt install python3
```

### 3. Clone or place the project

```bash
# If you received the source as a folder, navigate into it:
cd /path/to/nullforge
```

---

## Building & Running

### Development build (faster compile)

```bash
cargo build
cargo run
```

### Release build (faster runtime, recommended for daily use)

```bash
cargo build --release
./target/release/farstyle
```

> The binary is self-contained. Copy `target/release/farstyle` anywhere and run it — as long as the `modules/` directory is in the same folder.

---

## First Launch

1. **Set a target** — go to **Target** page, enter a URL (e.g. `http://localhost:3000`)
2. **Configure AI** — go to **Settings**, enter your API key (see [AI Configuration](#ai-configuration))
3. **Enable modules** — go to **Scan Modules**, toggle on the modules you want
4. **Open Workspace** — type a goal in natural language and hit **Send**

---

## AI Configuration

Go to **Settings** and fill in:

| Field | Description |
|---|---|
| **Provider** | `OpenRouter`, `OpenAI`, or `Ollama` (local) |
| **Endpoint** | API base URL (auto-filled for OpenAI/OpenRouter) |
| **Model** | e.g. `openai/gpt-4o`, `meta-llama/llama-3.1-8b-instruct:free` |
| **API Key** | Your provider API key |

### Recommended free models (OpenRouter)

```
meta-llama/llama-3.1-8b-instruct:free     # Fast, good for tool selection
mistralai/mistral-7b-instruct:free         # Balanced
nousresearch/hermes-3-llama-3.1-405b:free  # Best reasoning, slower
```

### Local (Ollama)

```bash
brew install ollama
ollama pull llama3
# In Settings: Provider=Ollama, Endpoint=http://localhost:11434, Model=llama3
```

> **Rate limits**: Free OpenRouter models have daily request limits. If you hit `429 Rate limit exceeded`, wait or switch to a paid model.

---

## Module System

FARSTYLE has two module types:

### Built-in Modules (always available)

| Name | ID | Language | Purpose |
|---|---|---|---|
| HTTP Probe | `recon.http_probe` | Rust | Fast HTTP reachability & header analysis |
| Directory Fuzzer | `fuzz.dir_fuzz` | Rust | Common path enumeration |
| SQL Injection Exploit | `exploit.sqli` | Python | Multi-technique SQLi detection |

These are compiled into the binary. They run automatically during **Scan** and can be enabled/disabled per scan.

### User Modules

Python scripts placed in `modules/python/`. Loaded and auto-validated on startup.

---

## User Modules

### Included

| File | Purpose |
|---|---|
| `modules/python/sqli_exploit.py` | SQL Injection detection (error, boolean, UNION, ORDER BY, time, reflection) |
| `modules/python/web_scrapper.py` | Recursive web crawler — discovers links, forms, endpoints |

### Adding your own module

1. Create a Python file in `modules/python/yourmodule.py`
2. It must follow the IPC protocol:

```python
import json, sys

# Read one JSON line from stdin
ctx = json.loads(sys.stdin.readline())
target = ctx["target"]
run_id = ctx["run_id"]

# Emit progress/log/finding/done to stdout
def emit(msg): print(json.dumps(msg), flush=True)
def log(level, msg): emit({"type":"log","level":level,"message":msg})
def progress(pct, msg=""): emit({"type":"progress","percent":pct,"message":msg})
def finding(title, desc, severity, evidence=None):
    emit({"type":"finding","title":title,"description":desc,
          "severity":severity,"evidence":evidence,"tags":[]})
def done(summary=""): emit({"type":"done","summary":summary})

# Your logic here
log("info", f"Running against {target}")
progress(50, "Working...")
# finding("Something found", "Details", "high", "Evidence string")
done("Finished")
```

3. **Restart the app** — the module auto-validates and enables itself if the IPC protocol is detected
4. The AI will see it listed as `[RUNNABLE]` and use it when appropriate

### IPC Input Format (stdin)

```json
{
  "run_id": "ws-yourmodule",
  "target": "http://example.com",
  "config": {},
  "timeout_secs": 120
}
```

### IPC Output Format (stdout — one JSON per line)

```json
{"type": "log",      "level": "info",  "message": "..."}
{"type": "progress", "percent": 50,    "message": "..."}
{"type": "finding",  "title": "...",   "description": "...", "severity": "high", "evidence": "..."}
{"type": "error",    "message": "..."}
{"type": "done",     "summary": "..."}
```

---

## Workspace & AI Commands

The AI understands natural language. Examples:

The Workspace maps plain English straight to the right tool workflow — no need
to name a tool or emit an `ACTION:` line. The intent router (`deduce_action`)
recognises, among others:

| You say | What happens |
|---|---|
| `test connectivity` / `is it up?` | `ping -c 4 <host>` |
| `check for a login page` | Crawls (spider) **and** directory-busts for login/admin paths |
| `brute force the login` | Captures the login POST into the Repeater (body `email=…&password=FUZZ`), then runs the calibrated `ffuf` attack |
| `capture the request` | Turns the proxy on and primes the Repeater with the target |
| `dirbust` / `find hidden paths` | `ffuf` content discovery |
| `hunt the .env` / `find the flag` | `ffuf` sensitive-file sweep (.env, .git, config, backups) |
| `find hidden parameters` | `arjun` parameter discovery |
| `enumerate subdomains` | `subfinder` |
| `what tech is it running?` | `whatweb` fingerprint |
| `check the response headers` | `curl -sI` + header/cookie/CORS/CSP analysis |
| `scan ports` | `nmap` service scan |
| `vuln scan` | `nuclei` |
| `test for SQL injection` | `sqlmap` |
| `test for XSS` | `dalfox` |
| `whois` / `dns records` | `whois` / `dig` |
| `decode the JWT` / `cve lookup` / `osint` | Opens the matching analyser |
| `use the web scrapper module on http://localhost:3000` | Runs `web_scrapper` module |
| `run it on the other links` | Re-runs last module on each URL found in conversation context |
| `what is SSRF?` | Answers directly — no action taken |

Anything the router doesn't recognise falls through to the model, which can
still emit an `ACTION:` line itself.

### Decision logic

```
User says "use [module]"     → run_module <module>
User names a CLI tool        → smart_run_tool <tool> <goal>
Generic task, tool installed → smart_run_tool <tool> <goal>
Generic task, no tool        → run_module <matching_module>
Neither                      → curl fallback
```

> If a module exists but is **disabled**, the AI will tell you instead of silently falling back to curl.

---

## System Tools

Tools are detected at startup. The AI only uses tools marked **installed**.

```
Settings → (auto-detected on launch)
```

To check manually:

```bash
which nmap httpx ffuf sqlmap nikto nuclei gobuster
```

---

## Directory Structure

```
nullforge/
├── src/                    # Rust source
│   ├── gui.rs              # Main UI + AI action handler
│   ├── ai/                 # AI provider, action parser, executor
│   └── modules/            # Built-in module logic
├── modules/
│   ├── python/             # User Python modules (auto-loaded)
│   │   ├── sqli_exploit.py
│   │   └── web_scrapper.py
│   └── rust/               # User Rust modules (future)
├── Cargo.toml
└── README.md
```

---

## Troubleshooting

### App won't start — OpenGL error
```bash
# macOS: ensure display drivers are up to date
# Try running with software rendering:
LIBGL_ALWAYS_SOFTWARE=1 ./target/release/farstyle
```

### Module shows "Not validated"
- The module's IPC protocol check failed
- Open the module file, ensure it reads from `sys.stdin` and emits `{"type":"done",...}` to stdout
- Click **Quick Check** in the Modules tab to re-validate

### AI uses curl instead of my module
- Check the module is **enabled** (toggle on) in Scan Modules
- Check it passed validation (no "Not validated" badge)
- Restart the app — modules are loaded once at startup

### API error 429 — Rate limit
- Switch to a different free model in Settings
- Or wait for the daily quota to reset (midnight UTC)
- Or use a paid API key

### Module runs but finds nothing
- Ensure the target URL **contains query parameters** (e.g. `?q=test&sort=1`)
- For login/POST forms, the current `sqli_exploit` only tests GET params — use `sqlmap` for POST
- Confirm the target is reachable: `curl -s http://your-target/path?param=test`

---

## License

Private / internal use. Not for redistribution.
