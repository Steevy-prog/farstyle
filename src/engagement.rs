/// Engagement — named pentest project with scope, notes, findings, and session memory.
///
/// Persisted to ~/.config/farstyle/engagements/<slug>.json
/// Each engagement carries its own target list, scope rules, AI conversation history,
/// and all findings produced during the engagement.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ── Storage path ──────────────────────────────────────────────────────────────

pub fn engagements_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config").join("farstyle").join("engagements")
}

fn engagement_path(slug: &str) -> PathBuf {
    engagements_dir().join(format!("{}.json", slug))
}

// ── Data model ────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum EngagementStatus {
    Active,
    Paused,
    Completed,
}

impl EngagementStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Active    => "Active",
            Self::Paused    => "Paused",
            Self::Completed => "Completed",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScopeRule {
    /// Allowed pattern — supports wildcards: "*.example.com", "10.0.0.*", exact URL
    pub pattern: String,
    pub note: String,
}

impl ScopeRule {
    pub fn matches(&self, url: &str) -> bool {
        let pat = self.pattern.trim().to_lowercase();
        let url_lc = url.to_lowercase();
        if pat.starts_with("*.") {
            let suffix = &pat[2..];
            return url_lc.contains(suffix);
        }
        if pat.ends_with(".*") {
            let prefix = &pat[..pat.len() - 2];
            return url_lc.starts_with(prefix);
        }
        url_lc.contains(&pat)
    }
}

/// Single AI conversation turn, stored per-engagement for full session memory.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EngagementMessage {
    pub role: String,   // "user" | "assistant"
    pub content: String,
    pub timestamp: String,
}

/// A finding produced during this engagement.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EngagementFinding {
    pub id: usize,
    pub title: String,
    pub description: String,
    pub severity: String,           // "critical" | "high" | "medium" | "low" | "info"
    pub category: String,           // e.g. "Authentication / Security Misconfiguration"
    pub finding_status: String,     // "Open" | "Verified" | "Closed" | "False Positive"
    pub evidence: String,
    pub target: String,
    pub module: String,
    pub tags: Vec<String>,
    pub remediation: String,
    pub cve: Option<String>,
    pub timestamp: String,
    pub confirmed: bool,
}

impl EngagementFinding {
    #[allow(dead_code)] // used by HTML export styling paths; kept for report theming
    pub fn severity_color_hex(&self) -> &'static str {
        match self.severity.to_lowercase().as_str() {
            "critical" => "#ff4444",
            "high"     => "#ff8c00",
            "medium"   => "#ffb400",
            "low"      => "#4caf50",
            _          => "#607d8b",
        }
    }
}

/// A target URL/host within this engagement.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EngagementTarget {
    pub url: String,
    pub note: String,
    pub tested: bool,
}

/// Full engagement record.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Engagement {
    pub id: String,             // slug / filename key
    pub name: String,
    pub description: String,
    pub client: String,
    pub status: EngagementStatus,
    pub created_at: String,
    pub updated_at: String,
    pub targets: Vec<EngagementTarget>,
    pub scope: Vec<ScopeRule>,
    pub out_of_scope: Vec<ScopeRule>,
    pub findings: Vec<EngagementFinding>,
    pub notes: String,          // free-form markdown notes
    pub ai_history: Vec<EngagementMessage>, // full AI conversation memory
    pub tags: Vec<String>,
    pub next_finding_id: usize,
    /// IDs of PoC entries (from the global vuln store) referenced by this engagement.
    #[serde(default)]
    pub poc_refs: Vec<usize>,
}

impl Engagement {
    pub fn new(name: impl Into<String>, client: impl Into<String>) -> Self {
        let name = name.into();
        let id = slugify(&name);
        let now = now_str();
        Self {
            id,
            name,
            description: String::new(),
            client: client.into(),
            status: EngagementStatus::Active,
            created_at: now.clone(),
            updated_at: now,
            targets: Vec::new(),
            scope: Vec::new(),
            out_of_scope: Vec::new(),
            findings: Vec::new(),
            notes: String::new(),
            ai_history: Vec::new(),
            tags: Vec::new(),
            next_finding_id: 1,
            poc_refs: Vec::new(),
        }
    }

    /// Add a finding. Returns the assigned ID.
    pub fn add_finding(&mut self, f: EngagementFinding) -> usize {
        let id = self.next_finding_id;
        self.next_finding_id += 1;
        let mut f = f;
        f.id = id;
        self.findings.push(f);
        self.updated_at = now_str();
        id
    }

    /// Record an AI message turn.
    pub fn push_message(&mut self, role: impl Into<String>, content: impl Into<String>) {
        self.ai_history.push(EngagementMessage {
            role: role.into(),
            content: content.into(),
            timestamp: now_str(),
        });
        self.updated_at = now_str();
    }

    /// Check if a URL is in scope. Returns (in_scope, reason).
    pub fn check_scope(&self, url: &str) -> (bool, String) {
        // Explicit out-of-scope takes priority
        for rule in &self.out_of_scope {
            if rule.matches(url) {
                return (false, format!("OUT OF SCOPE: matches exclusion rule '{}'", rule.pattern));
            }
        }
        // If scope rules defined, must match at least one
        if !self.scope.is_empty() {
            for rule in &self.scope {
                if rule.matches(url) {
                    return (true, format!("In scope: matches '{}'", rule.pattern));
                }
            }
            return (false, format!("OUT OF SCOPE: '{}' does not match any allowed scope rule", url));
        }
        // No scope defined — everything allowed
        (true, "No scope restrictions defined".into())
    }

    /// Count findings by severity.
    pub fn severity_counts(&self) -> [usize; 5] {
        let mut counts = [0usize; 5]; // [critical, high, medium, low, info]
        for f in &self.findings {
            match f.severity.to_lowercase().as_str() {
                "critical" => counts[0] += 1,
                "high"     => counts[1] += 1,
                "medium"   => counts[2] += 1,
                "low"      => counts[3] += 1,
                _          => counts[4] += 1,
            }
        }
        counts
    }

    /// Save to disk.
    pub fn save(&self) {
        let dir = engagements_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = engagement_path(&self.id);
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, json);
        }
    }

    /// Load from disk.
    #[allow(dead_code)] // single-engagement loader; app loads via load_all()
    pub fn load(slug: &str) -> Option<Self> {
        let path = engagement_path(slug);
        let raw = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&raw).ok()
    }

    /// Load all engagements from disk, sorted by updated_at desc.
    pub fn load_all() -> Vec<Self> {
        let dir = engagements_dir();
        let Ok(entries) = std::fs::read_dir(&dir) else { return vec![] };
        let mut list: Vec<Self> = entries
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) == Some("json") {
                    let raw = std::fs::read_to_string(&p).ok()?;
                    serde_json::from_str(&raw).ok()
                } else {
                    None
                }
            })
            .collect();
        list.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        list
    }

    /// Delete from disk.
    pub fn delete(&self) {
        let path = engagement_path(&self.id);
        let _ = std::fs::remove_file(path);
    }

    /// Export as a markdown pentest report.
    pub fn export_markdown(&self) -> String {
        let counts = self.severity_counts();
        let mut md = format!(
"# Pentest Report — {}

**Client:** {}  
**Status:** {}  
**Created:** {}  
**Updated:** {}  

---

## Executive Summary

{}

**Findings Summary:**

| Severity | Count | Risk Weight |
|---|---|---|
| 🔴 Critical | {} | {} pts |
| 🟠 High     | {} | {} pts |
| 🟡 Medium   | {} | {} pts |
| 🟢 Low      | {} | {} pts |
| ℹ️  Info     | {} | — |

**Risk Score: {}**

---

## Scope

### In Scope
{}

### Out of Scope
{}

---

## Targets

{}

---

## Findings

",
            self.name,
            self.client,
            self.status.label(),
            self.created_at,
            self.updated_at,
            if self.description.is_empty() { "No executive summary recorded. Add one in the Engagements → Notes tab." } else { &self.description },
            counts[0], counts[0] * 40,
            counts[1], counts[1] * 15,
            counts[2], counts[2] * 5,
            counts[3], counts[3] * 1,
            counts[4],
            counts[0]*40 + counts[1]*15 + counts[2]*5 + counts[3],
            if self.scope.is_empty() { "No scope restrictions defined.".into() }
            else { self.scope.iter().map(|r| format!("- `{}` — {}", r.pattern, r.note)).collect::<Vec<_>>().join("\n") },
            if self.out_of_scope.is_empty() { "None.".into() }
            else { self.out_of_scope.iter().map(|r| format!("- `{}` — {}", r.pattern, r.note)).collect::<Vec<_>>().join("\n") },
            if self.targets.is_empty() { "No targets defined.".into() }
            else { self.targets.iter().map(|t| format!("- {} {}{}", t.url, if t.tested { "✅" } else { "⬜" }, if t.note.is_empty() { String::new() } else { format!(" — {}", t.note) })).collect::<Vec<_>>().join("\n") },
        );

        // Sort findings: critical first
        let severity_order = |s: &str| match s.to_lowercase().as_str() {
            "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4
        };
        let mut sorted = self.findings.clone();
        sorted.sort_by_key(|f| severity_order(&f.severity));

        for (i, f) in sorted.iter().enumerate() {
            md.push_str(&format!(
"### [{severity}] {title}

**ID:** F-{id}  
**Category:** {category}  
**Status:** {finding_status}  
**Target:** `{target}`  
**Module:** {module}  
**Tags:** {tags}  
**CVSS Score:** {cvss}  
{cve}
#### Description
{description}

#### Evidence
```
{evidence}
```

#### Remediation
{remediation}

---

",
                severity = f.severity.to_uppercase(),
                title = f.title,
                id = f.id,
                category = if f.category.is_empty() { "—".into() } else { f.category.clone() },
                finding_status = if f.finding_status.is_empty() { "Open".into() } else { f.finding_status.clone() },
                target = f.target,
                module = f.module,
                tags = if f.tags.is_empty() { "—".into() } else { f.tags.join(", ") },
                cvss = match f.severity.to_lowercase().as_str() {
                    "critical" => "9.0–10.0 (Critical)",
                    "high"     => "7.0–8.9 (High)",
                    "medium"   => "4.0–6.9 (Medium)",
                    "low"      => "0.1–3.9 (Low)",
                    _          => "0.0 (Info/None)",
                },
                cve = if let Some(c) = &f.cve { format!("**CVE/CWE:** {}  \n", c) } else { String::new() },
                description = f.description,
                evidence = f.evidence,
                remediation = f.remediation,
            ));
            let _ = i; // suppress unused warning
        }

        if !self.notes.is_empty() {
            md.push_str("## Notes\n\n");
            md.push_str(&self.notes);
            md.push_str("\n\n---\n\n");
        }

        md.push_str(&format!("*Report generated by FARSTYLE v0.1.0 — {}*\n", now_str()));
        md
    }

    /// Export findings as JSON (importable into other tools).
    pub fn export_json(&self) -> String {
        serde_json::to_string_pretty(&self.findings).unwrap_or_default()
    }

    /// Export a fully styled HTML pentest report with severity chart and colour coding.
    pub fn export_html(&self) -> String {
        let counts = self.severity_counts();
        let total  = self.findings.len();
        let now    = now_str();

        // Severity colour map
        fn sev_color(s: &str) -> &'static str {
            match s.to_lowercase().as_str() {
                "critical" => "#e53935",
                "high"     => "#fb8c00",
                "medium"   => "#fdd835",
                "low"      => "#43a047",
                _          => "#78909c",
            }
        }
        fn sev_badge(s: &str) -> String {
            format!(
                r#"<span style="background:{};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.5px">{}</span>"#,
                sev_color(s), s.to_uppercase()
            )
        }

        // Build chart bars (simple CSS bar chart)
        let chart_bars = [("Critical", counts[0], "#e53935"), ("High", counts[1], "#fb8c00"),
                          ("Medium",   counts[2], "#fdd835"), ("Low",  counts[3], "#43a047"),
                          ("Info",     counts[4], "#78909c")]
            .iter().map(|(label, count, color)| {
                let pct = if total == 0 { 0.0 } else { (*count as f64 / total as f64) * 100.0 };
                format!(
                    r#"<div style="display:flex;align-items:center;gap:8px;margin:4px 0">
                      <div style="width:70px;font-size:12px;color:#ccc">{label}</div>
                      <div style="flex:1;background:#1e2733;border-radius:3px;height:16px">
                        <div style="width:{pct:.1}%;background:{color};height:16px;border-radius:3px;transition:width .3s"></div>
                      </div>
                      <div style="width:24px;text-align:right;font-size:12px;color:#ccc">{count}</div>
                    </div>"#,
                    label = label, pct = pct, color = color, count = count
                )
            }).collect::<Vec<_>>().join("\n");

        // Sort: critical first
        let severity_order = |s: &str| match s.to_lowercase().as_str() {
            "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4
        };
        let mut sorted = self.findings.clone();
        sorted.sort_by_key(|f| severity_order(&f.severity));

        let findings_html = sorted.iter().map(|f| {
            let cve_row = if let Some(c) = &f.cve {
                format!(r#"<tr><td class="label">CVE/CWE</td><td><span style="color:#fb8c00">{}</span></td></tr>"#, c)
            } else { String::new() };
            let tags_html = if f.tags.is_empty() { "—".into() }
                else { f.tags.iter().map(|t| format!(r#"<span style="background:#1e2733;border:1px solid #2a3547;border-radius:3px;padding:1px 6px;font-size:11px;color:#aaa">{}</span>"#, t)).collect::<Vec<_>>().join(" ") };
            format!(r#"
            <div class="finding" style="border-left:4px solid {color};background:#131c29;border-radius:6px;margin:12px 0;padding:16px">
              <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
                {badge}
                <span style="font-size:15px;font-weight:600;color:#e8eaf0">F-{id} &nbsp;{title}</span>
              </div>
              <table style="width:100%;border-collapse:collapse;font-size:12px;color:#9aa3b0;margin-bottom:10px">
                <tr><td class="label">Target</td><td><code>{target}</code></td></tr>
                <tr><td class="label">Module</td><td>{module}</td></tr>
                <tr><td class="label">Category</td><td>{category}</td></tr>
                <tr><td class="label">Status</td><td>{status_badge}</td></tr>
                <tr><td class="label">Tags</td><td>{tags}</td></tr>
                <tr><td class="label">CVSS Range</td><td><span style="color:{cvss_col};font-weight:600">{cvss_range}</span></td></tr>
                {cve_row}
                <tr><td class="label">Confirmed</td><td>{confirmed}</td></tr>
              </table>
              <div class="section-label">Description</div>
              <p style="color:#c5cad4;font-size:13px;margin:4px 0 10px">{description}</p>
              {evidence_block}
              {remediation_block}
            </div>"#,
                color       = sev_color(&f.severity),
                badge       = sev_badge(&f.severity),
                id          = f.id,
                title       = html_escape(&f.title),
                target      = html_escape(&f.target),
                module      = html_escape(&f.module),
                category    = if f.category.is_empty() { "—".into() } else { html_escape(&f.category) },
                status_badge = {
                    let st = if f.finding_status.is_empty() { "Open" } else { f.finding_status.as_str() };
                    let col = match st { "Verified" => "#43a047", "Closed" => "#5c6b7a", "False Positive" => "#7b1fa2", _ => "#1565c0" };
                    format!(r#"<span style="background:{};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">{}</span>"#, col, st)
                },
                tags        = tags_html,
                cvss_col    = sev_color(&f.severity),
                cvss_range  = match f.severity.to_lowercase().as_str() {
                    "critical" => "9.0 – 10.0", "high" => "7.0 – 8.9",
                    "medium"   => "4.0 – 6.9",  "low"  => "0.1 – 3.9",
                    _          => "0.0 (Info)",
                },
                cve_row     = cve_row,
                confirmed   = if f.confirmed { "✅ Yes" } else { "⬜ Unconfirmed" },
                description = html_escape(&f.description),
                evidence_block = if f.evidence.is_empty() { String::new() } else {
                    format!(r#"<div class="section-label">Evidence</div>
              <pre style="background:#0d1117;color:#7ee787;border-radius:4px;padding:10px;font-size:11px;overflow-x:auto;margin:4px 0 10px">{}</pre>"#,
                        html_escape(&f.evidence))
                },
                remediation_block = if f.remediation.is_empty() { String::new() } else {
                    format!(r#"<div class="section-label">Remediation</div>
              <p style="color:#81c995;font-size:12px;margin:4px 0">{}</p>"#,
                        html_escape(&f.remediation))
                },
            )
        }).collect::<Vec<_>>().join("\n");

        let scope_rows = self.scope.iter().map(|r| {
            format!(r#"<li><code style="color:#43a047">{}</code>{}</li>"#, html_escape(&r.pattern),
                if r.note.is_empty() { String::new() } else { format!(" — {}", html_escape(&r.note)) })
        }).collect::<Vec<_>>().join("\n");

        let oos_rows = self.out_of_scope.iter().map(|r| {
            format!(r#"<li><code style="color:#e53935">{}</code>{}</li>"#, html_escape(&r.pattern),
                if r.note.is_empty() { String::new() } else { format!(" — {}", html_escape(&r.note)) })
        }).collect::<Vec<_>>().join("\n");

        format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Pentest Report — {name}</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0b1018;color:#c5cad4;line-height:1.6;padding:0}}
    .page{{max-width:960px;margin:0 auto;padding:40px 24px}}
    h1{{font-size:28px;color:#fff;font-weight:700;letter-spacing:-.5px}}
    h2{{font-size:18px;color:#43e07a;border-bottom:1px solid #1e2733;padding-bottom:6px;margin:32px 0 16px}}
    h3{{font-size:14px;color:#9aa3b0;font-weight:600;text-transform:uppercase;letter-spacing:.8px;margin:20px 0 8px}}
    .label{{width:100px;color:#5c6b7a;font-weight:600;padding:3px 0;vertical-align:top}}
    .section-label{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:#5c6b7a;margin:8px 0 4px}}
    code{{background:#1a2233;padding:1px 5px;border-radius:3px;font-family:monospace;color:#7ee787;font-size:12px}}
    pre{{white-space:pre-wrap;word-break:break-all}}
    .hero{{background:linear-gradient(135deg,#0d1b2a 0%,#0f2318 100%);border:1px solid #1e3a28;border-radius:10px;padding:32px;margin-bottom:32px}}
    .meta-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-top:20px}}
    .meta-card{{background:#131c29;border:1px solid #1e2733;border-radius:6px;padding:12px}}
    .meta-card .value{{font-size:22px;font-weight:700;color:#43e07a}}
    .meta-card .sub{{font-size:11px;color:#5c6b7a;margin-top:2px}}
    .stat-critical .value{{color:#e53935}}
    .stat-high    .value{{color:#fb8c00}}
    .stat-medium  .value{{color:#fdd835}}
    .stat-low     .value{{color:#43a047}}
    footer{{margin-top:48px;padding-top:16px;border-top:1px solid #1e2733;font-size:11px;color:#3d4d5c;text-align:center}}
    ul{{padding-left:18px;color:#9aa3b0;font-size:13px}}
    li{{margin:3px 0}}
  </style>
</head>
<body>
<div class="page">

  <!-- Hero header -->
  <div class="hero">
    <div style="display:flex;align-items:center;gap:14px;margin-bottom:8px">
      <span style="font-size:36px">🛡</span>
      <div>
        <h1>Pentest Report</h1>
        <div style="color:#43e07a;font-size:14px;margin-top:4px">{name}</div>
      </div>
    </div>
    <div style="color:#5c6b7a;font-size:13px">
      Client: <strong style="color:#9aa3b0">{client}</strong> &nbsp;|&nbsp;
      Status: <strong style="color:#43e07a">{status}</strong> &nbsp;|&nbsp;
      Generated: <strong style="color:#9aa3b0">{now}</strong>
    </div>
    <div class="meta-grid" style="margin-top:20px">
      <div class="meta-card stat-critical"><div class="value">{c_crit}</div><div class="sub">Critical</div></div>
      <div class="meta-card stat-high">   <div class="value">{c_high}</div><div class="sub">High</div></div>
      <div class="meta-card stat-medium"> <div class="value">{c_med}</div> <div class="sub">Medium</div></div>
      <div class="meta-card stat-low">    <div class="value">{c_low}</div> <div class="sub">Low</div></div>
      <div class="meta-card">             <div class="value">{total}</div> <div class="sub">Total findings</div></div>
    </div>
  </div>

  <!-- Severity chart -->
  <h2>📊 Severity Distribution</h2>
  <div style="background:#131c29;border:1px solid #1e2733;border-radius:6px;padding:16px">
    {chart_bars}
  </div>

  <!-- Description -->
  {desc_block}

  <!-- Scope -->
  <h2>🎯 Scope</h2>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
    <div><h3>In Scope</h3><ul>{scope_rows}</ul></div>
    <div><h3>Out of Scope</h3><ul>{oos_rows}</ul></div>
  </div>

  <!-- Findings -->
  <h2>🔍 Findings ({total})</h2>
  {findings_html}

  <!-- Notes -->
  {notes_block}

  <footer>Generated by FARSTYLE v0.1.0 &nbsp;·&nbsp; {now}</footer>
</div>
</body>
</html>"#,
            name          = html_escape(&self.name),
            client        = html_escape(if self.client.is_empty() { "—" } else { &self.client }),
            status        = self.status.label(),
            now           = now,
            c_crit        = counts[0],
            c_high        = counts[1],
            c_med         = counts[2],
            c_low         = counts[3],
            total         = total,
            chart_bars    = chart_bars,
            desc_block    = if self.description.is_empty() { String::new() } else {
                format!("<h2>📋 Description</h2><p style='color:#9aa3b0'>{}</p>", html_escape(&self.description))
            },
            scope_rows    = if scope_rows.is_empty() { "<li style='color:#5c6b7a'>No restrictions — all targets in scope</li>".into() } else { scope_rows },
            oos_rows      = if oos_rows.is_empty() { "<li style='color:#5c6b7a'>None defined</li>".into() } else { oos_rows },
            findings_html = if findings_html.is_empty() {
                "<p style='color:#5c6b7a;font-style:italic'>No findings recorded.</p>".into()
            } else { findings_html },
            notes_block   = if self.notes.is_empty() { String::new() } else {
                format!("<h2>📝 Notes</h2><pre style='background:#131c29;border:1px solid #1e2733;border-radius:6px;padding:16px;color:#9aa3b0;font-size:13px;white-space:pre-wrap'>{}</pre>",
                    html_escape(&self.notes))
            },
        )
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn slugify(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn now_str() -> String {
    // Use file modification time as a proxy since we can't import chrono
    // Format: seconds since epoch as ISO-like string
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Convert to rough date string: YYYY-MM-DD HH:MM
    let s = secs;
    let mins  = (s / 60) % 60;
    let hours = (s / 3600) % 24;
    let days  = s / 86400;
    // Days since epoch to year/month/day (Gregorian approximation)
    let year = 1970 + days / 365;
    let day_of_year = days % 365;
    let month = (day_of_year / 30) + 1;
    let day   = (day_of_year % 30) + 1;
    format!("{:04}-{:02}-{:02} {:02}:{:02}", year, month.min(12), day.min(31), hours, mins)
}
