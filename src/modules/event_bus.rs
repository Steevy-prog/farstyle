/// Event bus — broadcast/subscribe model for inter-module communication.
/// Modules emit events; the manager and other subscribers react to them.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;

use super::output::{Finding, LogEntry};

// ── Event types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ModuleEvent {
    /// A finding was discovered during a run.
    FindingDiscovered {
        run_id: String,
        module_id: String,
        finding: Finding,
    },

    /// A log entry was emitted during a run.
    Log {
        run_id: String,
        entry: LogEntry,
    },

    /// A module started executing.
    ModuleStarted {
        run_id: String,
        module_id: String,
        target: String,
    },

    /// A module finished executing.
    ModuleFinished {
        run_id: String,
        module_id: String,
        success: bool,
        finding_count: usize,
    },

    /// A module emitted a progress update (0.0 – 1.0).
    Progress {
        run_id: String,
        module_id: String,
        percent: f32,
        message: Option<String>,
    },

    /// A module was loaded into the manager.
    ModuleLoaded { module_id: String },

    /// A module was unloaded from the manager.
    ModuleUnloaded { module_id: String },

    /// Generic custom payload for extensibility.
    Custom {
        kind: String,
        payload: serde_json::Value,
    },
}

// ── EventBus ─────────────────────────────────────────────────────────────────

pub const BUS_CAPACITY: usize = 512;

#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<ModuleEvent>,
}

impl EventBus {
    pub fn new() -> Arc<Self> {
        let (tx, _) = broadcast::channel(BUS_CAPACITY);
        Arc::new(Self { tx })
    }

    /// Publish an event to all current subscribers.
    pub fn emit(&self, event: ModuleEvent) {
        let _ = self.tx.send(event);
    }

    /// Subscribe to receive all future events.
    pub fn subscribe(&self) -> broadcast::Receiver<ModuleEvent> {
        self.tx.subscribe()
    }

    /// Convenience: emit a finding discovered event.
    pub fn finding(&self, run_id: &str, module_id: &str, finding: Finding) {
        self.emit(ModuleEvent::FindingDiscovered {
            run_id: run_id.to_string(),
            module_id: module_id.to_string(),
            finding,
        });
    }

    /// Convenience: emit a log event.
    pub fn log(&self, run_id: &str, entry: LogEntry) {
        self.emit(ModuleEvent::Log { run_id: run_id.to_string(), entry });
    }

    /// Convenience: emit a progress event.
    pub fn progress(&self, run_id: &str, module_id: &str, percent: f32, msg: Option<String>) {
        self.emit(ModuleEvent::Progress {
            run_id: run_id.to_string(),
            module_id: module_id.to_string(),
            percent,
            message: msg,
        });
    }
}

impl Default for EventBus {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(BUS_CAPACITY);
        Self { tx }
    }
}
