/// Python IPC bridge — executes Python exploit modules as subprocesses.
/// Communication protocol: newline-delimited JSON on stdin/stdout.
///
/// Protocol flow:
///   1. Manager serializes ExecutionContext to JSON and writes to Python stdin.
///   2. Python module reads the context, executes, streams IpcMessage lines to stdout.
///   3. Bridge collects IpcMessage lines and assembles a ModuleOutput.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use super::output::{Evidence, ExecutionStatus, Finding, LogEntry, LogLevel, ModuleOutput, Severity};
use super::types::ExecutionContext;

// ── IPC message schema ────────────────────────────────────────────────────────

/// Every line written by the Python module must be a serialized IpcMessage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcMessage {
    /// A finding discovered during execution.
    Finding {
        title: String,
        description: String,
        severity: String,     // "info" | "low" | "medium" | "high" | "critical"
        evidence: Option<String>,
        tags: Option<Vec<String>>,
        remediation: Option<String>,
        cve: Option<String>,
    },

    /// A log entry.
    Log {
        level: String,        // "debug" | "info" | "warn" | "error"
        message: String,
    },

    /// A progress update (0–100).
    Progress { percent: u8, message: Option<String> },

    /// An error that occurred (non-fatal).
    Error { message: String },

    /// The module signals it finished successfully.
    Done { summary: Option<String> },
}

// ── Python IPC runner ─────────────────────────────────────────────────────────

pub struct PythonBridge;

impl PythonBridge {
    /// Execute a Python exploit module at `script_path` with the given context.
    /// Returns a normalized ModuleOutput.
    pub fn execute(
        module_id: &str,
        module_name: &str,
        script_path: &PathBuf,
        ctx: &ExecutionContext,
    ) -> ModuleOutput {
        let started_at = Utc::now();

        if !script_path.exists() {
            return ModuleOutput::failed(
                module_id,
                module_name,
                &ctx.target,
                started_at,
                format!("Script not found: {}", script_path.display()),
            );
        }

        let ctx_json = match serde_json::to_string(ctx) {
            Ok(j) => j,
            Err(e) => {
                return ModuleOutput::failed(module_id, module_name, &ctx.target, started_at,
                    format!("Failed to serialize context: {}", e));
            }
        };

        let mut child = match Command::new("python3")
            .arg(script_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                return ModuleOutput::failed(module_id, module_name, &ctx.target, started_at,
                    format!("Failed to spawn python3: {}", e));
            }
        };

        // Write context JSON to stdin
        if let Some(mut stdin) = child.stdin.take() {
            let _ = writeln!(stdin, "{}", ctx_json);
        }

        let mut output = ModuleOutput::success(module_id, module_name, &ctx.target, started_at);

        // Read IPC messages from stdout line by line
        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let line = match line {
                    Ok(l) if !l.trim().is_empty() => l,
                    _ => continue,
                };

                match serde_json::from_str::<IpcMessage>(&line) {
                    Ok(msg) => Self::apply_ipc_message(&mut output, msg, module_id, &ctx.target),
                    Err(e) => {
                        output.add_log(LogEntry::warn(
                            module_id,
                            format!("Malformed IPC line ({}): {}", e, &line[..line.len().min(120)]),
                        ));
                    }
                }
            }
        }

        // Capture stderr as log errors
        if let Some(stderr) = child.stderr.take() {
            let reader = BufReader::new(stderr);
            for line in reader.lines().flatten() {
                if !line.trim().is_empty() {
                    output.add_log(LogEntry::error(module_id, format!("[stderr] {}", line)));
                }
            }
        }

        let exit_status = child.wait();
        match exit_status {
            Ok(s) if !s.success() => {
                output.status = ExecutionStatus::PartialSuccess;
                output.add_error(format!("Process exited with non-zero status: {:?}", s.code()));
            }
            Err(e) => {
                output.status = ExecutionStatus::Failed;
                output.add_error(format!("Failed to wait on child process: {}", e));
            }
            _ => {}
        }

        output.finished_at = Utc::now();
        output
    }

    fn apply_ipc_message(output: &mut ModuleOutput, msg: IpcMessage, module_id: &str, target: &str) {
        match msg {
            IpcMessage::Finding { title, description, severity, evidence, tags, remediation, cve } => {
                let sev = match severity.as_str() {
                    "critical" => Severity::Critical,
                    "high"     => Severity::High,
                    "medium"   => Severity::Medium,
                    "low"      => Severity::Low,
                    _          => Severity::Info,
                };
                let mut f = Finding::new(&title, sev, target)
                    .with_description(&description);
                if let Some(ev) = evidence { f = f.with_evidence(Evidence::raw(ev)); }
                if let Some(tags) = tags { for t in tags { f = f.with_tag(t); } }
                if let Some(r) = remediation { f.remediation = Some(r); }
                if let Some(c) = cve { f.cve = Some(c); }
                output.add_finding(f);
            }
            IpcMessage::Log { level, message } => {
                let entry = match level.as_str() {
                    "warn"  | "warning" => LogEntry::warn(module_id, message),
                    "error"             => LogEntry::error(module_id, message),
                    _                   => LogEntry::info(module_id, message),
                };
                output.add_log(entry);
            }
            IpcMessage::Progress { percent, message } => {
                output.add_log(LogEntry {
                    level: LogLevel::Info,
                    message: format!("[{}%] {}", percent, message.unwrap_or_default()),
                    module: module_id.to_string(),
                    timestamp: Utc::now(),
                });
            }
            IpcMessage::Error { message } => {
                output.add_error(message.clone());
                output.add_log(LogEntry::error(module_id, message));
            }
            IpcMessage::Done { summary } => {
                if let Some(s) = summary {
                    output.add_log(LogEntry::info(module_id, format!("Done: {}", s)));
                }
            }
        }
    }
}
