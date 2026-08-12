# FARSTYLE — Architecture

FARSTYLE is a single native Rust binary: an AI-driven web-application security
auditing platform (proxy, intruder, repeater, scanner/module engine, knowledge
base) built around an autonomous penetration-testing agent.

- **Language / edition:** Rust 2024
- **UI:** `eframe` / `egui` (immediate-mode GUI, single glow/OpenGL window)
- **HTTP:** `ureq` · **TLS MITM:** `rustls` + `rcgen` · **Secrets:** `keyring`
- **Persistence:** JSON under `~/.config/farstyle/` (API keys in the OS keychain)

---

## Top-level layout

```
src/
├── main.rs            App entry point + module declarations
│
├── gui/               ── PRESENTATION LAYER (egui) ──────────────────
│   ├── mod.rs         NullForgeApp state, Default, the eframe update loop,
│   │                  page dispatch, sidebar/top-bar, and the agent/async
│   │                  logic (send_workspace, poll_*, drive_autopilot, …)
│   ├── theme.rs       Colour palette + shared widget builders (cards, buttons)
│   ├── types.rs       GUI data model (Finding, WsMessage, IntruderResult, …)
│   │                  + the static MODULES / TOOLS catalogues
│   └── page_*.rs      One file per cohesive group of pages (see below)
│
├── ai/                ── AI LAYER ───────────────────────────────────
│   ├── mod.rs         Provider abstraction (Ollama / OpenAI / OpenRouter),
│   │                  chat_with_history, and the ACTION: protocol parser
│   └── executor.rs    Turns parsed AiActions into tool/module invocations
│
├── scanners/          ── EXTERNAL TOOL WRAPPERS (22 files) ──────────
│   └── nmap.rs, sqlmap.rs, nuclei.rs, ffuf.rs, gobuster.rs, httpx.rs,
│       subfinder.rs, katana.rs, dalfox.rs, … wordlists.rs
│
├── modules/           ── PLUGGABLE MODULE ENGINE ─────────────────────
│   ├── mod_trait.rs, registry.rs, manager.rs, event_bus.rs,
│   │   python_bridge.rs, types.rs, output.rs
│   └── builtin/       http_probe.rs, dir_fuzz.rs, sqli_exploit.rs
│
└── ── DOMAIN / SERVICES ─────────────────────────────────────────────
    proxy.rs            Intercepting HTTP proxy + capture store
    tls_mitm.rs         On-the-fly certificate generation for HTTPS MITM
    spider.rs           Crawler
    passive_scan.rs     Passive traffic analyser (runs on every capture)
    scripting.rs        Native match/action rule-engine DSL
    crypto.rs           Encoder/decoder + hashing primitives
    httpx.rs            Raw-request HTTP send (Repeater / Intruder)
    knowledge.rs        Knowledge-base documents (KbDoc / DocKind)
    config.rs           Persisted AppConfig (+ keychain helpers)
    engagement.rs       Per-engagement findings, scope, targets, reports
    vulnstore.rs        Global reusable vulnerability / PoC store
    utils.rs            Small shared helpers
```

---

## The GUI layer (how the monolith was broken up)

`NullForgeApp` is the central egui application state. egui is immediate-mode, so
every frame `update()` runs: it polls async receivers, drives the Auto-pilot loop,
draws the sidebar/top-bar, and dispatches to exactly one `page_*` renderer based
on `self.selected_nav`.

The page renderers were extracted out of the original single file into cohesive
modules. Rust lets an `impl` block be split across files, so each page module is
simply:

```rust
// src/gui/page_<group>.rs
use super::*;                       // inherits the egui prelude + crate types
                                    // re-exported as `pub(crate) use` in mod.rs
impl NullForgeApp {
    pub(crate) fn page_x(&mut self, ui: &mut Ui) { … }   // dispatched → pub(crate)
    fn helper(&mut self, …) { … }                        // page-local → private
}
```

`mod.rs` declares each with `mod page_<group>;`. Methods called from the dispatch
or the update loop are `pub(crate)`; helpers used only within a page stay private.
Shared state, theme constants and helper methods that live in `mod.rs`/`theme.rs`
remain reachable from every page module via `self.` and `use super::*;`.

### Page modules

| File | Pages |
|------|-------|
| `page_recon.rs` | Overview, Target, Scan Modules, Results, Encoder, Logs, History, AI Assistant |
| `page_http_tools.rs` | Proxy, Repeater, Intruder |
| `page_workspace.rs` | Workspace (AI agent console + Auto-pilot controls) |
| `page_analysis.rs` | JWT, Mind Base, Hypotheses, OSINT, Diff Viewer, command palette |
| `page_tools_misc.rs` | Timeline, Spider, Passive Scan, Scripting, WebSocket |
| `page_payloads.rs` | Payload Library, Wordlist Bank |
| `page_vuln_store.rs` | Vulnerability / PoC store (library, match, editor) |
| `page_engagements.rs` | Engagements + per-tab renderers |
| `page_admin.rs` | Modules manager, Settings, Knowledge Base, About |

`mod.rs` retains the cross-cutting concerns that don't belong to a single page:
the `NullForgeApp` struct + `Default`, the `eframe::App::update` loop, sidebar /
top-bar / status-bar chrome, page dispatch, config load/save, and the agent async
machinery (`send_workspace`, `poll_workspace`, `drive_autopilot`, `poll_scan`,
`poll_proxy_ai`, `poll_cve`, …).

---

## Request / data flow

```
User ──▶ Workspace ──▶ ai::chat_with_history ──▶ provider (Ollama/OpenRouter/OpenAI)
                                                        │
                          ai::extract_actions ◀─────────┘   (parses ACTION: lines)
                                  │
                  apply_ws_actions / apply_ai_actions
                          │            │            │
                    scanners::*   modules engine   proxy / repeater / intruder
                          │            │            │
                  Mind Base · Hypotheses · Knowledge Base · Vuln Store · Engagement
```

The **Auto-pilot** loop in `mod.rs` (`drive_autopilot`) runs this cycle
autonomously toward a goal — observe → note → hypothesise → test → conclude →
exploit — firing one tool action per step, gated on the previous step's async
work completing, with a step budget and live operator "Guide" steering.

---

## Build & conventions

- `cargo build` / `cargo run` — single binary, no codegen steps.
- **Zero compiler warnings.** Intentionally-unused API surface (e.g. the scanner
  wrappers the AI dispatches dynamically) is marked with `#[allow(dead_code)]`
  plus a one-line reason; everything else is wired or removed.
- External CLI tools (nmap, sqlmap, ffuf, …) are optional and detected at runtime;
  the AI prefers installed tools and falls back gracefully when absent.
