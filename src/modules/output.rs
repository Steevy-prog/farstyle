/// Unified output model for all modules.
/// Every module — Rust native or Python IPC — produces a ModuleOutput.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Severity ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Info     => "info",
            Self::Low      => "low",
            Self::Medium   => "medium",
            Self::High     => "high",
            Self::Critical => "critical",
        };
        write!(f, "{}", s)
    }
}

// ── Finding ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub target: String,
    pub evidence: Vec<Evidence>,
    pub tags: Vec<String>,
    pub remediation: Option<String>,
    pub cvss: Option<f32>,
    pub cve: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub extra: HashMap<String, serde_json::Value>,
}

impl Finding {
    pub fn new(title: impl Into<String>, severity: Severity, target: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            title: title.into(),
            description: String::new(),
            severity,
            target: target.into(),
            evidence: Vec::new(),
            tags: Vec::new(),
            remediation: None,
            cvss: None,
            cve: None,
            timestamp: Utc::now(),
            extra: HashMap::new(),
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_evidence(mut self, ev: Evidence) -> Self {
        self.evidence.push(ev);
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

// ── Evidence ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub data: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    HttpRequest,
    HttpResponse,
    Screenshot,
    RawOutput,
    Payload,
    Log,
}

impl Evidence {
    pub fn raw(data: impl Into<String>) -> Self {
        Self { kind: EvidenceKind::RawOutput, data: data.into(), note: None }
    }

    pub fn request(data: impl Into<String>) -> Self {
        Self { kind: EvidenceKind::HttpRequest, data: data.into(), note: None }
    }

    pub fn response(data: impl Into<String>) -> Self {
        Self { kind: EvidenceKind::HttpResponse, data: data.into(), note: None }
    }
}

// ── Log entry ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub level: LogLevel,
    pub message: String,
    pub module: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogEntry {
    pub fn info(module: impl Into<String>, msg: impl Into<String>) -> Self {
        Self { level: LogLevel::Info, message: msg.into(), module: module.into(), timestamp: Utc::now() }
    }
    pub fn warn(module: impl Into<String>, msg: impl Into<String>) -> Self {
        Self { level: LogLevel::Warn, message: msg.into(), module: module.into(), timestamp: Utc::now() }
    }
    pub fn error(module: impl Into<String>, msg: impl Into<String>) -> Self {
        Self { level: LogLevel::Error, message: msg.into(), module: module.into(), timestamp: Utc::now() }
    }
}

// ── Unified module output ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleOutput {
    pub run_id: String,
    pub module_id: String,
    pub module_name: String,
    pub target: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub status: ExecutionStatus,
    pub findings: Vec<Finding>,
    pub logs: Vec<LogEntry>,
    pub errors: Vec<String>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub raw_output: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Success,
    PartialSuccess,
    Failed,
    Cancelled,
    TimedOut,
}

impl ModuleOutput {
    pub fn success(module_id: impl Into<String>, module_name: impl Into<String>, target: impl Into<String>, started_at: DateTime<Utc>) -> Self {
        Self {
            run_id: String::new(),
            module_id: module_id.into(),
            module_name: module_name.into(),
            target: target.into(),
            started_at,
            finished_at: Utc::now(),
            status: ExecutionStatus::Success,
            findings: Vec::new(),
            logs: Vec::new(),
            errors: Vec::new(),
            metadata: HashMap::new(),
            raw_output: None,
        }
    }

    pub fn failed(module_id: impl Into<String>, module_name: impl Into<String>, target: impl Into<String>, started_at: DateTime<Utc>, error: impl Into<String>) -> Self {
        let mut out = Self::success(module_id, module_name, target, started_at);
        out.status = ExecutionStatus::Failed;
        out.errors.push(error.into());
        out
    }

    pub fn add_finding(&mut self, f: Finding) { self.findings.push(f); }
    pub fn add_log(&mut self, l: LogEntry) { self.logs.push(l); }
    pub fn add_error(&mut self, e: impl Into<String>) { self.errors.push(e.into()); }
    pub fn set_meta(&mut self, key: impl Into<String>, val: serde_json::Value) { self.metadata.insert(key.into(), val); }

    pub fn finding_count_by_severity(&self, sev: &Severity) -> usize {
        self.findings.iter().filter(|f| &f.severity == sev).count()
    }

    pub fn has_critical(&self) -> bool { self.finding_count_by_severity(&Severity::Critical) > 0 }
    pub fn has_high(&self) -> bool { self.finding_count_by_severity(&Severity::High) > 0 }
}
