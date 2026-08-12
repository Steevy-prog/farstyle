// Core data model for the GUI layer: findings, chat/workspace messages, the Mind
// Base entry, Intruder payload/result types, module descriptors and the static
// catalogues of built-in modules and system tools. Pure data — no rendering.

use eframe::egui::Color32;

// ============ DATA STRUCTURES ============
#[derive(Clone)]
pub struct Finding { pub severity: String, pub module: String, pub title: String }

#[derive(Clone)]
pub struct ChatMessage { pub role: String, pub content: String }

/// One entry in the ephemeral Mind Base — a session scratch cache of facts that
/// help continue the pentest (endpoints, creds, tokens, observations). Not persisted:
/// it lives only in memory and can be cleared at any moment.
#[derive(Clone)]
pub struct MindEntry { pub text: String, pub kind: String, pub ts: String }

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AttackMode { Sniper, BatteringRam, Pitchfork, ClusterBomb }

impl AttackMode {
    pub fn label(&self) -> &'static str {
        match self {
            AttackMode::Sniper => "Sniper",
            AttackMode::BatteringRam => "Battering Ram",
            AttackMode::Pitchfork => "Pitchfork",
            AttackMode::ClusterBomb => "Cluster Bomb",
        }
    }
}

#[derive(Clone)]
pub struct PayloadPosition { pub id: usize, pub name: String, pub payloads: Vec<String>, pub payload_type: PayloadType }

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PayloadType { Wordlist, Numbers, Nulls, Dates, Characters }

impl PayloadType {
    pub fn label(&self) -> &'static str {
        match self { PayloadType::Wordlist => "Wordlist", PayloadType::Numbers => "Numbers", PayloadType::Nulls => "Nulls", PayloadType::Dates => "Dates", PayloadType::Characters => "Chars" }
    }
    pub fn all() -> &'static [PayloadType] { &[PayloadType::Wordlist, PayloadType::Numbers, PayloadType::Nulls, PayloadType::Dates, PayloadType::Characters] }
}

#[derive(Clone)]
pub struct IntruderResult { pub payload_set: Vec<String>, pub status: u16, pub length: usize, pub elapsed_ms: u128, pub error: Option<String> }

#[derive(Clone, PartialEq)]
#[allow(dead_code)] // direction tags for captured WS frames; UI shows a subset
pub enum WsDirection { ClientToServer, ServerToClient }

#[derive(Clone)]
pub struct WsCapture {
    pub id: u64,
    pub host: String,
    pub direction: WsDirection,
    pub opcode: u8,     // 1 = text, 2 = binary, 8 = close, 9 = ping, 10 = pong
    pub payload: Vec<u8>,
    #[allow(dead_code)] // capture time; not surfaced in the WS frame list yet
    pub timestamp_ms: u128,
    pub note: String,
}

/// Coded modules (Rust or Python — written by the user or built-in).
/// Format: (id, display name, category, runtime label)
pub(crate) const MODULES: [(&str, &str, &str, &str); 3] = [
    ("recon.http_probe",  "HTTP Probe",            "Recon",   "Rust"),
    ("fuzz.dir_fuzz",     "Directory Fuzzer",      "Fuzzing", "Rust"),
    ("exploit.sqli",      "SQL Injection Exploit", "Exploit", "Python"),
];

/// System-installed CLI tools available to the AI and workspace.
/// Format: (bin name, display name, category, description)
pub(crate) const TOOLS: [(&str, &str, &str, &str); 13] = [
    ("nmap",       "Nmap",       "Recon",   "Port & service scanner"),
    ("whatweb",    "WhatWeb",    "Recon",   "Web tech fingerprinting"),
    ("subfinder",  "Subfinder",  "Recon",   "Subdomain enumeration"),
    ("httpx",      "HTTPX",      "Recon",   "Fast HTTP prober"),
    ("katana",     "Katana",     "Recon",   "Web crawler"),
    ("nuclei",     "Nuclei",     "Scan",    "Template-based vuln scanner"),
    ("nikto",      "Nikto",      "Scan",    "Web server scanner"),
    ("gobuster",   "Gobuster",   "Fuzzing", "Dir/DNS brute forcer"),
    ("ffuf",       "Ffuf",       "Fuzzing", "Fast web fuzzer"),
    ("sqlmap",     "SQLMap",     "Exploit", "SQL injection tool"),
    ("xssstrike",  "XSStrike",   "Exploit", "XSS detection suite"),
    ("dalfox",     "Dalfox",     "Exploit", "XSS scanner & exploiter"),
    ("arjun",      "Arjun",      "Recon",   "HTTP parameter finder"),
];

// ============ KB INTENT ============

/// Detected intent from user message — drives auto-save of AI response to KB.
#[derive(Clone, PartialEq, Eq)]
pub enum KbIntent {
    /// User wants the AI to remember something → save as Manual Note
    Remember { title: String },
    /// User wants the AI to learn something → save as Competence
    Learn { title: String },
}

// ============ USER MODULE TYPES ============

#[derive(Clone, PartialEq, Eq)]
pub enum ModuleRuntime { Rust, Python }

impl ModuleRuntime {
    pub fn label(&self) -> &str { match self { Self::Rust => "Rust", Self::Python => "Python" } }
    pub fn color(&self) -> Color32 { match self { Self::Rust => Color32::from_rgb(255, 100, 60), Self::Python => Color32::from_rgb(80, 180, 100) } }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ModuleStatus { Ready, Error(String), Testing }

impl ModuleStatus {
    pub fn label(&self) -> &str { match self { Self::Ready => "Ready", Self::Error(_) => "Error", Self::Testing => "Testing..." } }
    pub fn color(&self) -> Color32 { match self { Self::Ready => Color32::from_rgb(50, 200, 100), Self::Error(_) => Color32::from_rgb(220, 60, 60), Self::Testing => Color32::from_rgb(200, 160, 30) } }
}

#[derive(Clone)]
pub struct UserModule {
    pub name: String,
    #[allow(dead_code)] // shown via summary(); kept for module metadata
    pub description: String,
    pub category: String,
    pub runtime: ModuleRuntime,
    pub source: String,          // full file content
    pub file_name: String,
    pub status: ModuleStatus,
    pub last_output: String,
    pub enabled: bool,
    pub ai_validated: bool,
}

impl UserModule {
    #[allow(dead_code)] // one-line module descriptor for logs/tooltips
    pub fn summary(&self) -> String {
        format!("[{}] {} — {} ({})", self.runtime.label(), self.name, self.category, self.status.label())
    }
}

// ============ WORKSPACE TYPES ============
#[derive(Clone, PartialEq, Eq)]
pub enum WsRole { User, Agent, Tool, Info }

#[derive(Clone)]
pub struct WsMessage {
    pub id: usize,
    pub role: WsRole,
    pub content: String,
    pub artifact: Option<String>,
}

fn next_ws_id() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static CTR: AtomicUsize = AtomicUsize::new(0);
    CTR.fetch_add(1, Ordering::Relaxed)
}

impl WsMessage {
    pub fn user(content: impl Into<String>) -> Self { Self { id: next_ws_id(), role: WsRole::User, content: content.into(), artifact: None } }
    pub fn agent(content: impl Into<String>) -> Self { Self { id: next_ws_id(), role: WsRole::Agent, content: content.into(), artifact: None } }
    pub fn tool(label: impl Into<String>, artifact: impl Into<String>) -> Self { Self { id: next_ws_id(), role: WsRole::Tool, content: label.into(), artifact: Some(artifact.into()) } }
    pub fn info(content: impl Into<String>) -> Self { Self { id: next_ws_id(), role: WsRole::Info, content: content.into(), artifact: None } }
}
