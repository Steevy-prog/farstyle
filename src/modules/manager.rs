/// ModuleManager — central orchestrator.
///
/// Responsibilities:
/// - Load/unload modules from the registry
/// - Validate compatibility and dependencies
/// - Execute modules with timeout, concurrency, cancellation
/// - Track per-run state
/// - Broadcast events on the shared event bus
/// - Collect and expose outputs

use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};

use super::event_bus::{EventBus, ModuleEvent};
use super::mod_trait::{BoxedModule, Module};
use super::output::{ExecutionStatus, ModuleOutput};
use super::registry::ModuleRegistry;
use super::types::{ExecutionContext, ModuleState};

// ── Run record ────────────────────────────────────────────────────────────────

pub struct RunRecord {
    pub run_id: String,
    pub module_id: String,
    pub state: ModuleState,
    pub output: Option<ModuleOutput>,
}

// ── ModuleManager ─────────────────────────────────────────────────────────────

pub struct ModuleManager {
    registry: Arc<ModuleRegistry>,
    bus: Arc<EventBus>,

    /// Currently loaded module instances (id → locked BoxedModule)
    loaded: RwLock<HashMap<String, Arc<Mutex<BoxedModule>>>>,

    /// Execution history keyed by run_id
    runs: RwLock<HashMap<String, RunRecord>>,

    /// Active background task handles keyed by run_id
    handles: Mutex<HashMap<String, JoinHandle<()>>>,
}

impl ModuleManager {
    pub fn new(registry: Arc<ModuleRegistry>, bus: Arc<EventBus>) -> Arc<Self> {
        Arc::new(Self {
            registry,
            bus,
            loaded: RwLock::new(HashMap::new()),
            runs: RwLock::new(HashMap::new()),
            handles: Mutex::new(HashMap::new()),
        })
    }

    // ── Loading ───────────────────────────────────────────────────────────────

    /// Load a module by ID from the registry, call on_load, mark as Idle.
    pub async fn load(&self, module_id: &str) -> Result<(), String> {
        if self.is_loaded(module_id).await {
            return Err(format!("Module '{}' is already loaded", module_id));
        }

        let mut module = self.registry.instantiate(module_id)?;

        // Validate dependencies
        for dep in module.metadata().requires.clone() {
            if !self.is_loaded(&dep).await {
                return Err(format!(
                    "Module '{}' requires '{}' to be loaded first",
                    module_id, dep
                ));
            }
        }

        module.on_load().await?;
        module.set_state(ModuleState::Idle);

        let arc: Arc<Mutex<BoxedModule>> = Arc::new(Mutex::new(module));
        self.loaded.write().await.insert(module_id.to_string(), arc);

        self.bus.emit(ModuleEvent::ModuleLoaded { module_id: module_id.to_string() });
        Ok(())
    }

    /// Unload a module (calls on_unload, removes from loaded map).
    pub async fn unload(&self, module_id: &str) -> Result<(), String> {
        let arc = {
            let mut map = self.loaded.write().await;
            map.remove(module_id).ok_or_else(|| format!("Module '{}' is not loaded", module_id))?
        };

        arc.lock().await.on_unload().await;
        self.bus.emit(ModuleEvent::ModuleUnloaded { module_id: module_id.to_string() });
        Ok(())
    }

    pub async fn is_loaded(&self, id: &str) -> bool {
        self.loaded.read().await.contains_key(id)
    }

    // ── Execution ─────────────────────────────────────────────────────────────

    /// Execute a module synchronously (blocks until done or timeout).
    pub async fn run_sync(&self, module_id: &str, ctx: ExecutionContext) -> Result<ModuleOutput, String> {
        let arc = {
            let map = self.loaded.read().await;
            map.get(module_id).cloned().ok_or_else(|| format!("Module '{}' not loaded", module_id))?
        };

        let run_id = ctx.run_id.clone();
        let timeout_secs = ctx.timeout_secs.unwrap_or(300);
        let bus = Arc::clone(&self.bus);

        // Validate config
        {
            let m = arc.lock().await;
            m.validate_config(&ctx)?;
        }

        // Record start
        self.record_start(&run_id, module_id, ModuleState::Running).await;
        bus.emit(ModuleEvent::ModuleStarted {
            run_id: run_id.clone(),
            module_id: module_id.to_string(),
            target: ctx.target.clone(),
        });

        // Set state to Running
        arc.lock().await.set_state(ModuleState::Running);

        // Call on_before_run
        arc.lock().await.on_before_run(&ctx).await?;

        // Execute with timeout
        let module_ref = Arc::clone(&arc);
        let bus_ref = Arc::clone(&bus);
        let ctx_clone = ctx.clone();

        let result = timeout(
            Duration::from_secs(timeout_secs),
            async move {
                module_ref.lock().await.run(ctx_clone, bus_ref).await
            },
        )
        .await;

        let mut output = match result {
            Ok(out) => out,
            Err(_) => {
                let mut o = ModuleOutput::failed(
                    module_id, module_id, &ctx.target, Utc::now(),
                    format!("Timed out after {}s", timeout_secs),
                );
                o.status = ExecutionStatus::TimedOut;
                o
            }
        };

        output.module_id = module_id.to_string();
        output.run_id = run_id.clone();

        // Call on_after_run
        arc.lock().await.on_after_run(&output).await;

        // Update state
        let new_state = if output.status == ExecutionStatus::Success { ModuleState::Completed } else { ModuleState::Failed };
        arc.lock().await.set_state(new_state);

        // Broadcast finish
        bus.emit(ModuleEvent::ModuleFinished {
            run_id: run_id.clone(),
            module_id: module_id.to_string(),
            success: output.status == ExecutionStatus::Success,
            finding_count: output.findings.len(),
        });

        // Store in run history
        self.record_output(&run_id, output.clone()).await;

        Ok(output)
    }

    /// Execute a module in the background. Returns the run_id.
    pub async fn run_async(self: &Arc<Self>, module_id: &str, ctx: ExecutionContext) -> Result<String, String> {
        let run_id = ctx.run_id.clone();
        let mid = module_id.to_string();
        let mgr = Arc::clone(self);

        let handle = tokio::spawn(async move {
            let _ = mgr.run_sync(&mid, ctx).await;
        });

        self.handles.lock().await.insert(run_id.clone(), handle);
        Ok(run_id)
    }

    /// Cancel a background run by run_id.
    pub async fn cancel(&self, run_id: &str) -> Result<(), String> {
        let mut handles = self.handles.lock().await;
        if let Some(handle) = handles.remove(run_id) {
            handle.abort();
            // Mark run as cancelled
            let mut runs = self.runs.write().await;
            if let Some(rec) = runs.get_mut(run_id) {
                rec.state = ModuleState::Failed;
                if let Some(out) = &mut rec.output {
                    out.status = ExecutionStatus::Cancelled;
                }
            }
            Ok(())
        } else {
            Err(format!("No active run with id '{}'", run_id))
        }
    }

    // ── Output access ─────────────────────────────────────────────────────────

    pub async fn get_output(&self, run_id: &str) -> Option<ModuleOutput> {
        self.runs.read().await.get(run_id)?.output.clone()
    }

    pub async fn all_outputs(&self) -> Vec<ModuleOutput> {
        self.runs.read().await.values().filter_map(|r| r.output.clone()).collect()
    }

    pub async fn all_findings(&self) -> Vec<super::output::Finding> {
        self.all_outputs().await.into_iter().flat_map(|o| o.findings).collect()
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    async fn record_start(&self, run_id: &str, module_id: &str, state: ModuleState) {
        self.runs.write().await.insert(run_id.to_string(), RunRecord {
            run_id: run_id.to_string(),
            module_id: module_id.to_string(),
            state,
            output: None,
        });
    }

    async fn record_output(&self, run_id: &str, output: ModuleOutput) {
        let mut runs = self.runs.write().await;
        if let Some(rec) = runs.get_mut(run_id) {
            rec.state = if output.status == ExecutionStatus::Success { ModuleState::Completed } else { ModuleState::Failed };
            rec.output = Some(output);
        }
    }

    // ── Info ──────────────────────────────────────────────────────────────────

    pub async fn loaded_module_ids(&self) -> Vec<String> {
        self.loaded.read().await.keys().cloned().collect()
    }

    pub fn registry(&self) -> &Arc<ModuleRegistry> { &self.registry }
    pub fn bus(&self) -> &Arc<EventBus> { &self.bus }
}
