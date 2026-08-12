/// Built-in example: Reconnaissance module — HTTP probe.
/// Probes a URL and reports its status code, title, and server header as a finding.

use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;

use crate::modules::{
    event_bus::EventBus,
    mod_trait::Module,
    output::{Evidence, Finding, LogEntry, ModuleOutput, Severity},
    types::{
        Capability, ConfigSchema, ExecutionContext, FieldKind,
        ModuleCategory, ModuleMetadata, ModuleState, RuntimeKind, TargetType,
    },
};

// ── HttpProbeModule ───────────────────────────────────────────────────────────

pub struct HttpProbeModule {
    state: ModuleState,
}

impl Default for HttpProbeModule {
    fn default() -> Self { Self { state: ModuleState::Registered } }
}

impl HttpProbeModule {
    /// Expose static metadata for use in the registry macro.
    pub fn static_metadata() -> ModuleMetadata {
        ModuleMetadata::new(
            "recon.http_probe",
            "HTTP Probe",
            "Probes a URL: checks status code, response headers, and server banner.",
            "1.0.0",
            "FarStyle",
            ModuleCategory::Reconnaissance,
            RuntimeKind::NativeRust,
        )
        .with_targets(vec![TargetType::Url, TargetType::Domain])
        .with_capability(Capability::NetworkAccess)
        .with_tag("http")
        .with_tag("recon")
        .with_tag("passive")
    }
}

#[async_trait]
impl Module for HttpProbeModule {
    fn metadata(&self) -> &ModuleMetadata {
        // Safe: static metadata is embedded per-instance via lazy_static or inline.
        // In a real SDK the metadata would be stored as a struct field.
        // For simplicity we return a leaked reference here.
        Box::leak(Box::new(Self::static_metadata()))
    }

    fn config_schema(&self) -> ConfigSchema {
        ConfigSchema::empty()
            .optional_field(
                "timeout_secs",
                FieldKind::Integer,
                "HTTP request timeout in seconds",
                serde_json::json!(10),
            )
            .optional_field(
                "follow_redirects",
                FieldKind::Boolean,
                "Follow HTTP redirects",
                serde_json::json!(true),
            )
    }

    fn state(&self) -> ModuleState { self.state.clone() }
    fn set_state(&mut self, state: ModuleState) { self.state = state; }

    async fn run(&self, ctx: ExecutionContext, bus: Arc<EventBus>) -> ModuleOutput {
        let started = Utc::now();
        let mut output = ModuleOutput::success("recon.http_probe", "HTTP Probe", &ctx.target, started);

        bus.log(&ctx.run_id, LogEntry::info("recon.http_probe", format!("Probing {}", ctx.target)));

        // Run httpx tool via subprocess
        let raw = crate::scanners::httpx::run_httpx(&ctx.target, &[]);

        output.raw_output = Some(raw.clone());

        if raw.contains("[!]") || raw.trim().is_empty() {
            output.add_log(LogEntry::warn("recon.http_probe", "No response or tool not available"));
            return output;
        }

        // Parse simple httpx output: "https://target.com [200] [Title] [nginx]"
        let finding = Finding::new(
            format!("HTTP probe result for {}", ctx.target),
            Severity::Info,
            &ctx.target,
        )
        .with_description(raw.trim())
        .with_evidence(Evidence::raw(raw.trim()))
        .with_tag("http-probe");

        bus.finding(&ctx.run_id, "recon.http_probe", finding.clone());
        output.add_finding(finding);

        bus.progress(&ctx.run_id, "recon.http_probe", 1.0, Some("Done".into()));
        output
    }
}
