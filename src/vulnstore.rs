/// Vulnerability / PoC store — a global, reusable library of vulnerabilities found
/// across systems, each with its discovery context, a proof-of-concept to reproduce
/// it, and an exploitation-complexity rating.
///
/// Persisted to ~/.config/farstyle/vulnstore.json
///
/// The store is GLOBAL (not per-engagement): when you point the tool at a new system
/// you can rank every stored PoC by how well its tags match the current target, then
/// choose which ones to test. Engagements reference entries by id (see Engagement.poc_refs).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ── Storage path ────────────────────────────────────────────────────────────────

fn store_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config").join("farstyle").join("vulnstore.json")
}

// ── Exploitation complexity ───────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Complexity {
    Trivial,
    Low,
    Medium,
    High,
}

impl Complexity {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Trivial => "Trivial",
            Self::Low     => "Low",
            Self::Medium  => "Medium",
            Self::High    => "High",
        }
    }

    /// One-line hint shown beside the rating.
    pub fn hint(&self) -> &'static str {
        match self {
            Self::Trivial => "single request / copy-paste payload",
            Self::Low     => "a couple of manual steps",
            Self::Medium  => "chained steps or specific conditions",
            Self::High    => "advanced — tooling, timing, or deep prerequisites",
        }
    }

    /// RGB for the GUI to colour the badge (green → red as it gets harder).
    pub fn color_rgb(&self) -> (u8, u8, u8) {
        match self {
            Self::Trivial => (0, 230, 118),   // green — easiest
            Self::Low     => (150, 220, 90),
            Self::Medium  => (255, 180, 60),  // amber
            Self::High    => (255, 95, 95),   // red — hardest
        }
    }

    pub fn all() -> &'static [Complexity] {
        &[Self::Trivial, Self::Low, Self::Medium, Self::High]
    }
}

impl Default for Complexity {
    fn default() -> Self { Self::Medium }
}

// ── A single stored vulnerability + PoC ─────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PocEntry {
    pub id: usize,
    pub title: String,
    pub vuln_type: String,        // SQLi, XSS, IDOR, SSRF, Auth bypass…
    pub severity: String,         // "critical" | "high" | "medium" | "low" | "info"
    pub complexity: Complexity,
    pub system: String,           // where it was originally found (host / URL / app name)
    pub discovered_at: String,    // when found (auto-stamped at creation)
    pub how_found: String,        // how it was discovered (method / tool / observation)
    pub poc: String,              // proof-of-concept — steps / request to reproduce & exploit
    pub payload: String,          // the key payload/string (optional — feeds Repeater/Intruder)
    pub tags: Vec<String>,        // tech/stack/vuln tags used for per-system matching
    pub references: String,       // CVE / CWE / links (optional)
    pub notes: String,            // free-form notes
}

impl PocEntry {
    pub fn severity_rank(&self) -> u8 {
        match self.severity.to_lowercase().as_str() {
            "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4,
        }
    }
}

// ── The store ──────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VulnStore {
    pub entries: Vec<PocEntry>,
    pub next_id: usize,
}

impl VulnStore {
    /// Load from disk, or return an empty store seeded with one illustrative example
    /// the first time (so the page isn't blank and the matching demo makes sense).
    pub fn load() -> Self {
        let path = store_path();
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(store) = serde_json::from_str::<VulnStore>(&raw) {
                return store;
            }
        }
        Self::seeded()
    }

    fn seeded() -> Self {
        let mut s = VulnStore::default();
        s.next_id = 1;
        s.add(PocEntry {
            id: 0,
            title: "Reflected XSS in search parameter".into(),
            vuln_type: "XSS".into(),
            severity: "medium".into(),
            complexity: Complexity::Trivial,
            system: "http://localhost:3000".into(),
            discovered_at: now_str(),
            how_found: "Injected a marker into ?q= and saw it reflected unencoded in the HTML body.".into(),
            poc: "GET /search?q=<script>alert(document.domain)</script>\nThe payload executes in the victim's browser when the link is opened.".into(),
            payload: "<script>alert(document.domain)</script>".into(),
            tags: vec!["xss".into(), "reflected".into(), "web".into(), "search".into()],
            references: "CWE-79".into(),
            notes: "Example entry — edit or delete it. Tag your own PoCs to make per-system matching useful.".into(),
        });
        s
    }

    pub fn save(&self) {
        let path = store_path();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, json);
        }
    }

    /// Add an entry, assigning it the next id. Returns the assigned id.
    pub fn add(&mut self, mut entry: PocEntry) -> usize {
        if self.next_id == 0 { self.next_id = 1; }
        let id = self.next_id;
        self.next_id += 1;
        entry.id = id;
        self.entries.push(entry);
        id
    }

    pub fn remove(&mut self, id: usize) {
        self.entries.retain(|e| e.id != id);
    }

    pub fn get(&self, id: usize) -> Option<&PocEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Distinct vuln types present, for filter dropdowns.
    pub fn vuln_types(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for e in &self.entries {
            if !e.vuln_type.trim().is_empty() && !v.iter().any(|x| x.eq_ignore_ascii_case(&e.vuln_type)) {
                v.push(e.vuln_type.clone());
            }
        }
        v.sort();
        v
    }

    /// Rank every entry by how well it matches the current system.
    ///
    /// Signal (tag-based ranking):
    ///   +3  the entry was originally found on a host that matches the current target
    ///   +2  per tag that overlaps the supplied `want_tags`
    ///   +1  the entry's vuln_type appears among the wanted tags
    ///
    /// Returns (entry_id, score) sorted by score desc, then severity, then recency of id.
    pub fn ranked_for(&self, target: &str, want_tags: &[String]) -> Vec<(usize, u32)> {
        let host = host_token(target);
        let want: Vec<String> = want_tags.iter()
            .map(|t| t.trim().to_lowercase())
            .filter(|t| !t.is_empty())
            .collect();

        let mut scored: Vec<(usize, u32, u8, usize)> = self.entries.iter().map(|e| {
            let mut score: u32 = 0;

            // Host / system overlap — same registrable host scores high.
            if !host.is_empty() {
                let entry_host = host_token(&e.system);
                if !entry_host.is_empty() && (entry_host == host || e.system.to_lowercase().contains(&host)) {
                    score += 3;
                }
            }

            // Tag overlap (fuzzy contains both ways so "mysql" ~ "sql", "wp" ~ "wordpress" etc.)
            for tag in &e.tags {
                let t = tag.trim().to_lowercase();
                if t.is_empty() { continue; }
                if want.iter().any(|w| w == &t || w.contains(&t) || t.contains(w)) {
                    score += 2;
                }
            }

            // Vuln type named explicitly in wanted tags
            let vt = e.vuln_type.trim().to_lowercase();
            if !vt.is_empty() && want.iter().any(|w| w == &vt || w.contains(&vt) || vt.contains(w)) {
                score += 1;
            }

            (e.id, score, e.severity_rank(), e.id)
        }).collect();

        // Highest score first; tie-break by severity (lower rank = worse = first), then newest id.
        scored.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then(a.2.cmp(&b.2))
                .then(b.3.cmp(&a.3))
        });

        scored.into_iter().map(|(id, score, _, _)| (id, score)).collect()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract a comparable host token from a URL/target string:
/// "http://localhost:3000/x" -> "localhost", "https://app.example.com" -> "example.com".
fn host_token(target: &str) -> String {
    let t = target.trim().to_lowercase();
    if t.is_empty() { return String::new(); }
    let no_scheme = t.split("://").last().unwrap_or(&t);
    let host = no_scheme.split('/').next().unwrap_or(no_scheme);
    let host = host.split('?').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host); // strip port
    // Collapse to registrable-ish domain: keep last two labels for FQDNs.
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() >= 2 && !host.eq_ignore_ascii_case("localhost") {
        labels[labels.len() - 2..].join(".")
    } else {
        host.to_string()
    }
}

/// Parse a comma/space separated tag string into a clean tag vector.
pub fn parse_tags(s: &str) -> Vec<String> {
    s.split([',', ' ', '\n', '\t'])
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty())
        .collect::<Vec<_>>()
}

fn now_str() -> String {
    // Mirror engagement.rs: derive a rough YYYY-MM-DD HH:MM from epoch without chrono.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mins  = (secs / 60) % 60;
    let hours = (secs / 3600) % 24;
    let days  = secs / 86400;
    let year = 1970 + days / 365;
    let day_of_year = days % 365;
    let month = (day_of_year / 30) + 1;
    let day   = (day_of_year % 30) + 1;
    format!("{:04}-{:02}-{:02} {:02}:{:02}", year, month.min(12), day.min(31), hours, mins)
}

/// Public timestamp helper so the GUI stamps new entries consistently.
pub fn timestamp() -> String { now_str() }
