/// The core Module trait every plugin must implement.
/// Supports both native Rust modules and Python IPC modules.

use async_trait::async_trait;
use std::sync::Arc;

use super::event_bus::EventBus;
use super::output::ModuleOutput;
use super::types::{ConfigSchema, ExecutionContext, ModuleMetadata, ModuleState};

// ── Core module trait ─────────────────────────────────────────────────────────

#[async_trait]
pub trait Module: Send + Sync + 'static {
    // ── Identity ──────────────────────────────────────────────────────────────

    fn metadata(&self) -> &ModuleMetadata;

    fn id(&self) -> &str { &self.metadata().id }
    fn name(&self) -> &str { &self.metadata().name }
    fn version(&self) -> &str { &self.metadata().version }

    // ── Configuration schema ──────────────────────────────────────────────────

    fn config_schema(&self) -> ConfigSchema;

    /// Validate a concrete config against the schema.
    /// Default implementation checks required fields are present.
    fn validate_config(&self, ctx: &ExecutionContext) -> Result<(), String> {
        for field in self.config_schema().fields.iter().filter(|f| f.required) {
            if !ctx.config.contains_key(&field.key) {
                return Err(format!("Missing required config field: '{}'", field.key));
            }
        }
        Ok(())
    }

    // ── Lifecycle hooks ───────────────────────────────────────────────────────

    /// Called once after the module is loaded into the manager.
    async fn on_load(&mut self) -> Result<(), String> { Ok(()) }

    /// Called before each execution run.
    async fn on_before_run(&mut self, _ctx: &ExecutionContext) -> Result<(), String> { Ok(()) }

    /// Called after each execution run (success or failure).
    async fn on_after_run(&mut self, _output: &ModuleOutput) {}

    /// Called before the module is unloaded/removed from the manager.
    async fn on_unload(&mut self) {}

    // ── Main execution entrypoint ─────────────────────────────────────────────

    async fn run(
        &self,
        ctx: ExecutionContext,
        bus: Arc<EventBus>,
    ) -> ModuleOutput;

    // ── Runtime state ─────────────────────────────────────────────────────────

    fn state(&self) -> ModuleState;
    fn set_state(&mut self, state: ModuleState);
}

// ── Boxed module alias ────────────────────────────────────────────────────────

pub type BoxedModule = Box<dyn Module>;

// ── Blanket impl so manager can call Module methods on BoxedModule ────────────

#[async_trait]
impl Module for Box<dyn Module> {
    fn metadata(&self) -> &ModuleMetadata { (**self).metadata() }
    fn config_schema(&self) -> super::types::ConfigSchema { (**self).config_schema() }
    fn state(&self) -> super::types::ModuleState { (**self).state() }
    fn set_state(&mut self, state: super::types::ModuleState) { (**self).set_state(state) }

    async fn on_load(&mut self) -> Result<(), String> { (**self).on_load().await }
    async fn on_before_run(&mut self, ctx: &super::types::ExecutionContext) -> Result<(), String> { (**self).on_before_run(ctx).await }
    async fn on_after_run(&mut self, output: &super::output::ModuleOutput) { (**self).on_after_run(output).await }
    async fn on_unload(&mut self) { (**self).on_unload().await }

    async fn run(
        &self,
        ctx: super::types::ExecutionContext,
        bus: Arc<super::event_bus::EventBus>,
    ) -> super::output::ModuleOutput {
        (**self).run(ctx, bus).await
    }
}
