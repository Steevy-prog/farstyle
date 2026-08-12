/// Core types: module metadata, categories, target types, config schema, lifecycle state.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Module category ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleCategory {
    Reconnaissance,
    Fuzzing,
    Crawling,
    VulnerabilityScanning,
    Exploit,
    Utility,
}

impl std::fmt::Display for ModuleCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Reconnaissance      => "reconnaissance",
            Self::Fuzzing             => "fuzzing",
            Self::Crawling            => "crawling",
            Self::VulnerabilityScanning => "vulnerability_scanning",
            Self::Exploit             => "exploit",
            Self::Utility             => "utility",
        };
        write!(f, "{}", s)
    }
}

// ── Target type ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetType {
    Url,
    IpAddress,
    Domain,
    Network,       // CIDR range
    File,
    GitRepo,
    ApiEndpoint,
    Any,
}

// ── Module runtime kind ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    NativeRust,
    PythonIpc,
    // Reserved for future: Wasm, RemoteRpc, AiGenerated
}

// ── Capability tags ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    PassiveOnly,
    RequiresAuth,
    NetworkAccess,
    FileSystemAccess,
    SubprocessSpawn,
    InternetRequired,
    // Extend freely
}

// ── Module metadata ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMetadata {
    pub id: String,             // unique slug e.g. "recon.subdomain_enum"
    pub name: String,
    pub description: String,
    pub version: String,        // semver e.g. "1.0.0"
    pub author: String,
    pub category: ModuleCategory,
    pub runtime: RuntimeKind,
    pub supported_targets: Vec<TargetType>,
    pub capabilities: Vec<Capability>,
    pub tags: Vec<String>,
    pub requires: Vec<String>,  // dependency module IDs
}

impl ModuleMetadata {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        version: impl Into<String>,
        author: impl Into<String>,
        category: ModuleCategory,
        runtime: RuntimeKind,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            version: version.into(),
            author: author.into(),
            category,
            runtime,
            supported_targets: vec![TargetType::Any],
            capabilities: Vec::new(),
            tags: Vec::new(),
            requires: Vec::new(),
        }
    }

    pub fn with_targets(mut self, targets: Vec<TargetType>) -> Self {
        self.supported_targets = targets;
        self
    }

    pub fn with_capability(mut self, cap: Capability) -> Self {
        self.capabilities.push(cap);
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn requires(mut self, dep: impl Into<String>) -> Self {
        self.requires.push(dep.into());
        self
    }
}

// ── Configuration schema ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSchema {
    pub fields: Vec<ConfigField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigField {
    pub key: String,
    pub kind: FieldKind,
    pub description: String,
    pub required: bool,
    pub default: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    String,
    Integer,
    Float,
    Boolean,
    StringList,
    FilePath,
}

impl ConfigSchema {
    pub fn empty() -> Self { Self { fields: Vec::new() } }

    pub fn field(mut self, key: impl Into<String>, kind: FieldKind, desc: impl Into<String>, required: bool) -> Self {
        self.fields.push(ConfigField { key: key.into(), kind, description: desc.into(), required, default: None });
        self
    }

    pub fn optional_field(mut self, key: impl Into<String>, kind: FieldKind, desc: impl Into<String>, default: serde_json::Value) -> Self {
        self.fields.push(ConfigField { key: key.into(), kind, description: desc.into(), required: false, default: Some(default) });
        self
    }
}

pub type ModuleConfig = HashMap<String, serde_json::Value>;

// ── Execution context ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub run_id: String,
    pub target: String,
    pub config: ModuleConfig,
    pub timeout_secs: Option<u64>,
}

impl ExecutionContext {
    pub fn new(target: impl Into<String>, config: ModuleConfig) -> Self {
        Self {
            run_id: uuid::Uuid::new_v4().to_string(),
            target: target.into(),
            config,
            timeout_secs: Some(300),
        }
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = Some(secs);
        self
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.config.get(key)?.as_str()
    }

    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.config.get(key)?.as_u64()
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.config.get(key)?.as_bool()
    }
}

// ── Module lifecycle state ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleState {
    Registered,
    Idle,
    Running,
    Paused,
    Completed,
    Failed,
    Unloaded,
}
