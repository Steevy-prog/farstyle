/// NullForge Module Architecture
///
/// Folder structure:
///   src/modules/
///     mod.rs            — this file, public API surface
///     types.rs          — ModuleMetadata, ModuleCategory, TargetType, ConfigSchema, ExecutionContext, ModuleState
///     output.rs         — ModuleOutput, Finding, Evidence, LogEntry, Severity
///     mod_trait.rs      — Module trait (async_trait), BoxedModule
///     event_bus.rs      — EventBus, ModuleEvent (broadcast channel)
///     registry.rs       — ModuleRegistry (factory store), register_module! macro
///     manager.rs        — ModuleManager (load/unload/run/cancel/collect)
///     python_bridge.rs  — PythonBridge (stdin/stdout JSON IPC)
///     builtin/
///       mod.rs
///       http_probe.rs   — Recon: HTTP probe (NativeRust)
///       dir_fuzz.rs     — Fuzzing: directory fuzzer (NativeRust)
///       sqli_exploit.rs — Exploit: SQL injection (PythonIpc)
///
///   modules/python/
///     sqli_exploit.py   — Example Python exploit module

pub mod types;
pub mod output;
pub mod mod_trait;
pub mod event_bus;
pub mod registry;
pub mod manager;
pub mod python_bridge;
pub mod builtin;

// ── Re-exports for convenient usage ──────────────────────────────────────────

pub use types::{
    ModuleCategory, ModuleMetadata, ModuleState, TargetType, RuntimeKind,
    Capability, ConfigSchema, ConfigField, FieldKind, ExecutionContext, ModuleConfig,
};
pub use output::{
    ModuleOutput, Finding, Evidence, EvidenceKind, LogEntry, LogLevel, Severity, ExecutionStatus,
};
pub use mod_trait::{Module, BoxedModule};
pub use event_bus::{EventBus, ModuleEvent};
pub use registry::ModuleRegistry;
pub use manager::ModuleManager;
pub use python_bridge::PythonBridge;

// ── Default module system bootstrap ──────────────────────────────────────────

use std::sync::Arc;

/// Bootstrap the full module system: create registry, bus, manager,
/// and register all built-in modules.
/// Returns (manager, bus) ready to use.
pub fn bootstrap() -> (Arc<ModuleManager>, Arc<EventBus>) {
    let registry = ModuleRegistry::new();
    let bus = EventBus::new();

    // Register built-in Rust modules
    let _ = registry.register(
        builtin::http_probe::HttpProbeModule::static_metadata(),
        Arc::new(|| Box::new(builtin::http_probe::HttpProbeModule::default())),
    );
    let _ = registry.register(
        builtin::dir_fuzz::DirFuzzModule::static_metadata(),
        Arc::new(|| Box::new(builtin::dir_fuzz::DirFuzzModule::default())),
    );

    // Register Python IPC modules
    let _ = registry.register(
        builtin::sqli_exploit::SqliExploitModule::static_metadata(),
        Arc::new(|| Box::new(builtin::sqli_exploit::SqliExploitModule::default())),
    );

    let manager = ModuleManager::new(Arc::clone(&registry), Arc::clone(&bus));

    (manager, bus)
}
