/// Module registry — central store of all registered module factories.
/// Supports dynamic registration, discovery by category/tag/capability.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::mod_trait::BoxedModule;
use super::types::{Capability, ModuleCategory, ModuleMetadata, TargetType};

// ── Module factory ────────────────────────────────────────────────────────────

/// A factory function that produces a fresh module instance.
/// Using Box<dyn Fn> allows both closure and fn pointer registration.
pub type ModuleFactory = Arc<dyn Fn() -> BoxedModule + Send + Sync + 'static>;

// ── Registry entry ────────────────────────────────────────────────────────────

pub struct RegistryEntry {
    pub metadata: ModuleMetadata,
    pub factory:  ModuleFactory,
}

// ── ModuleRegistry ────────────────────────────────────────────────────────────

pub struct ModuleRegistry {
    entries: RwLock<HashMap<String, RegistryEntry>>,
}

impl ModuleRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { entries: RwLock::new(HashMap::new()) })
    }

    /// Register a module factory under its metadata ID.
    pub fn register(&self, metadata: ModuleMetadata, factory: ModuleFactory) -> Result<(), String> {
        let id = metadata.id.clone();
        let mut entries = self.entries.write().map_err(|e| e.to_string())?;
        if entries.contains_key(&id) {
            return Err(format!("Module '{}' is already registered", id));
        }
        entries.insert(id, RegistryEntry { metadata, factory });
        Ok(())
    }

    /// Unregister a module by ID.
    pub fn unregister(&self, id: &str) -> Result<(), String> {
        let mut entries = self.entries.write().map_err(|e| e.to_string())?;
        entries.remove(id).map(|_| ()).ok_or_else(|| format!("Module '{}' not found", id))
    }

    /// Instantiate a fresh module by ID.
    pub fn instantiate(&self, id: &str) -> Result<BoxedModule, String> {
        let entries = self.entries.read().map_err(|e| e.to_string())?;
        let entry = entries.get(id).ok_or_else(|| format!("Module '{}' not registered", id))?;
        Ok((entry.factory)())
    }

    /// List all registered module metadata.
    pub fn list_all(&self) -> Vec<ModuleMetadata> {
        self.entries.read().unwrap().values().map(|e| e.metadata.clone()).collect()
    }

    /// Filter by category.
    pub fn by_category(&self, cat: &ModuleCategory) -> Vec<ModuleMetadata> {
        self.list_all().into_iter().filter(|m| &m.category == cat).collect()
    }

    /// Filter by target type support.
    pub fn by_target(&self, t: &TargetType) -> Vec<ModuleMetadata> {
        self.list_all()
            .into_iter()
            .filter(|m| m.supported_targets.contains(t) || m.supported_targets.contains(&TargetType::Any))
            .collect()
    }

    /// Filter by capability.
    pub fn by_capability(&self, cap: &Capability) -> Vec<ModuleMetadata> {
        self.list_all().into_iter().filter(|m| m.capabilities.contains(cap)).collect()
    }

    /// Filter by tag.
    pub fn by_tag(&self, tag: &str) -> Vec<ModuleMetadata> {
        self.list_all().into_iter().filter(|m| m.tags.iter().any(|t| t == tag)).collect()
    }

    /// Check if a module ID is registered.
    pub fn contains(&self, id: &str) -> bool {
        self.entries.read().unwrap().contains_key(id)
    }

    pub fn count(&self) -> usize {
        self.entries.read().unwrap().len()
    }
}

// ── Helper macro for registration ─────────────────────────────────────────────

/// register_module!(registry, MyModuleStruct)
/// Requires MyModuleStruct to implement Module + Default.
#[macro_export]
macro_rules! register_module {
    ($registry:expr, $ty:ty) => {{
        let meta = <$ty>::static_metadata();
        let factory: $crate::modules::registry::ModuleFactory =
            std::sync::Arc::new(|| Box::new(<$ty>::default()));
        $registry.register(meta, factory)
    }};
}
