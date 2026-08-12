/// Built-in example: Fuzzing module — directory fuzzer (wraps ffuf).

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

pub struct DirFuzzModule {
    state: ModuleState,
}

impl Default for DirFuzzModule {
    fn default() -> Self { Self { state: ModuleState::Registered } }
}

impl DirFuzzModule {
    pub fn static_metadata() -> ModuleMetadata {
        ModuleMetadata::new(
            "fuzz.dir_fuzz",
            "Directory Fuzzer",
            "Fuzzes web paths using ffuf with SecLists wordlists.",
            "1.0.0",
            "FarStyle",
            ModuleCategory::Fuzzing,
            RuntimeKind::NativeRust,
        )
        .with_targets(vec![TargetType::Url])
        .with_capability(Capability::NetworkAccess)
        .with_capability(Capability::SubprocessSpawn)
        .with_tag("fuzzing")
        .with_tag("ffuf")
        .with_tag("directories")
    }
}

#[async_trait]
impl Module for DirFuzzModule {
    fn metadata(&self) -> &ModuleMetadata {
        Box::leak(Box::new(Self::static_metadata()))
    }

    fn config_schema(&self) -> ConfigSchema {
        ConfigSchema::empty()
            .optional_field("wordlist", FieldKind::FilePath, "Custom wordlist path", serde_json::json!(""))
            .optional_field("extensions", FieldKind::String, "Extensions to append e.g. php,html", serde_json::json!(""))
            .optional_field("threads", FieldKind::Integer, "Concurrent threads", serde_json::json!(40))
    }

    fn state(&self) -> ModuleState { self.state.clone() }
    fn set_state(&mut self, state: ModuleState) { self.state = state; }

    async fn run(&self, ctx: ExecutionContext, bus: Arc<EventBus>) -> ModuleOutput {
        let started = Utc::now();
        let mut output = ModuleOutput::success("fuzz.dir_fuzz", "Directory Fuzzer", &ctx.target, started);

        bus.log(&ctx.run_id, LogEntry::info("fuzz.dir_fuzz", format!("Starting directory fuzz on {}", ctx.target)));

        let raw = crate::scanners::ffuf::run_ffuf(&ctx.target, &[]);
        output.raw_output = Some(raw.clone());

        // Parse each hit line as a finding
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('[') { continue; }

            let finding = Finding::new(
                format!("Directory found: {}", line),
                Severity::Low,
                &ctx.target,
            )
            .with_evidence(Evidence::raw(line))
            .with_tag("directory")
            .with_tag("fuzzing");

            bus.finding(&ctx.run_id, "fuzz.dir_fuzz", finding.clone());
            output.add_finding(finding);
        }

        bus.progress(&ctx.run_id, "fuzz.dir_fuzz", 1.0, Some(format!("{} paths found", output.findings.len())));
        output
    }
}
