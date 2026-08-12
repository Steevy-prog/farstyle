// Rule-engine DSL: the evaluator, context/output types and JSON (de)serialisers
// form a complete API. The GUI exercises a subset, so the rest is intentional
// surface rather than oversight.
#![allow(dead_code)]

/// Native scripting / rule engine for FARSTYLE.
///
/// Rules are defined as simple TOML-like structs with:
///   Match conditions (AND'd together):
///     - url_contains
///     - method_is
///     - request_header_contains
///     - request_body_contains
///     - response_status_is
///     - response_body_contains
///     - response_header_contains
///
///   Actions (all applied):
///     - log_message       → pushed to audit log
///     - set_request_header(name, value)
///     - remove_request_header(name)
///     - set_response_header(name, value)
///     - highlight         → marks the capture with a colour tag
///     - flag_as_interesting → adds to "Flagged" list
///     - send_to_repeater  → queues URL for Repeater auto-fill
///     - alert(title, description) → passive finding

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MatchField {
    UrlContains(String),
    MethodIs(String),
    RequestHeaderContains(String, String),   // (header-name, value)
    RequestBodyContains(String),
    ResponseStatusIs(u16),
    ResponseBodyContains(String),
    ResponseHeaderContains(String, String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuleAction {
    LogMessage(String),
    SetRequestHeader(String, String),
    RemoveRequestHeader(String),
    SetResponseHeader(String, String),
    Highlight(String),           // colour name: "red" | "green" | "blue" | "yellow"
    FlagAsInteresting,
    SendToRepeater,
    Alert(String, String),       // (title, description)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id:      String,
    pub name:    String,
    pub enabled: bool,
    pub matches: Vec<MatchField>,
    pub actions: Vec<RuleAction>,
}

impl Rule {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id:      id.into(),
            name:    name.into(),
            enabled: true,
            matches: Vec::new(),
            actions: Vec::new(),
        }
    }
}

/// Context provided when evaluating rules against a traffic item.
pub struct RuleContext<'a> {
    pub method:           &'a str,
    pub url:              &'a str,
    pub req_headers:      &'a [(String, String)],
    pub req_body:         &'a [u8],
    pub status:           u16,
    pub resp_headers:     &'a [(String, String)],
    pub resp_body:        &'a [u8],
}

/// Result of applying matched rules.
#[derive(Debug, Default)]
pub struct RuleOutput {
    pub log_messages:       Vec<String>,
    pub extra_req_headers:  Vec<(String, String)>,
    pub remove_req_headers: Vec<String>,
    pub extra_resp_headers: Vec<(String, String)>,
    pub highlight:          Option<String>,
    pub flagged:            bool,
    pub send_to_repeater:   bool,
    pub alerts:             Vec<(String, String)>,   // (title, description)
}

/// Evaluate all enabled rules against a traffic context.
pub fn evaluate(rules: &[Rule], ctx: &RuleContext) -> RuleOutput {
    let mut out = RuleOutput::default();

    for rule in rules {
        if !rule.enabled { continue; }
        if rule.matches.is_empty() { continue; }
        if !all_match(&rule.matches, ctx) { continue; }

        // Rule matched — apply actions
        for action in &rule.actions {
            match action {
                RuleAction::LogMessage(msg) =>
                    out.log_messages.push(format!("[Rule: {}] {}", rule.name, msg)),
                RuleAction::SetRequestHeader(k, v) =>
                    out.extra_req_headers.push((k.clone(), v.clone())),
                RuleAction::RemoveRequestHeader(k) =>
                    out.remove_req_headers.push(k.to_lowercase()),
                RuleAction::SetResponseHeader(k, v) =>
                    out.extra_resp_headers.push((k.clone(), v.clone())),
                RuleAction::Highlight(colour) =>
                    out.highlight = Some(colour.clone()),
                RuleAction::FlagAsInteresting =>
                    out.flagged = true,
                RuleAction::SendToRepeater =>
                    out.send_to_repeater = true,
                RuleAction::Alert(title, desc) =>
                    out.alerts.push((title.clone(), desc.clone())),
            }
        }
    }

    out
}

fn all_match(conditions: &[MatchField], ctx: &RuleContext) -> bool {
    let resp_text = std::str::from_utf8(ctx.resp_body).unwrap_or("");
    let req_text  = std::str::from_utf8(ctx.req_body).unwrap_or("");

    let req_hdrs: std::collections::HashMap<String, String> = ctx.req_headers.iter()
        .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
        .collect();
    let resp_hdrs: std::collections::HashMap<String, String> = ctx.resp_headers.iter()
        .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
        .collect();

    for cond in conditions {
        let matched = match cond {
            MatchField::UrlContains(s)               => ctx.url.contains(s.as_str()),
            MatchField::MethodIs(m)                  => ctx.method.eq_ignore_ascii_case(m),
            MatchField::RequestBodyContains(s)       => req_text.contains(s.as_str()),
            MatchField::ResponseBodyContains(s)      => resp_text.contains(s.as_str()),
            MatchField::ResponseStatusIs(code)       => ctx.status == *code,
            MatchField::RequestHeaderContains(k, v)  =>
                req_hdrs.get(&k.to_lowercase()).map(|hv| hv.contains(v.as_str())).unwrap_or(false),
            MatchField::ResponseHeaderContains(k, v) =>
                resp_hdrs.get(&k.to_lowercase()).map(|hv| hv.contains(v.as_str())).unwrap_or(false),
        };
        if !matched { return false; }
    }
    true
}

// ── Built-in starter rules ────────────────────────────────────────────────────

pub fn default_rules() -> Vec<Rule> {
    vec![
        {
            let mut r = Rule::new("builtin-admin", "Flag admin endpoints");
            r.matches = vec![MatchField::UrlContains("/admin".into())];
            r.actions = vec![
                RuleAction::FlagAsInteresting,
                RuleAction::Highlight("red".into()),
                RuleAction::Alert("Admin endpoint detected".into(),
                    "A request was made to an /admin path. Verify access controls.".into()),
            ];
            r
        },
        {
            let mut r = Rule::new("builtin-jwt", "Flag JWT responses");
            r.matches = vec![MatchField::ResponseBodyContains("eyJ".into())];
            r.actions = vec![
                RuleAction::FlagAsInteresting,
                RuleAction::Highlight("blue".into()),
                RuleAction::LogMessage("JWT token found in response body".into()),
            ];
            r
        },
        {
            let mut r = Rule::new("builtin-sqlerr", "Flag SQL errors");
            r.matches = vec![MatchField::ResponseBodyContains("SQL syntax".into())];
            r.actions = vec![
                RuleAction::Highlight("red".into()),
                RuleAction::Alert("SQL error in response".into(),
                    "A SQL error message was reflected — possible injection point.".into()),
            ];
            r
        },
        {
            let mut r = Rule::new("builtin-500", "Flag 500 errors");
            r.matches = vec![MatchField::ResponseStatusIs(500)];
            r.actions = vec![
                RuleAction::FlagAsInteresting,
                RuleAction::Highlight("yellow".into()),
                RuleAction::LogMessage("HTTP 500 — possible unhandled exception".into()),
            ];
            r
        },
        {
            let mut r = Rule::new("builtin-api", "Flag API endpoints");
            r.matches = vec![MatchField::UrlContains("/api/".into())];
            r.actions = vec![
                RuleAction::FlagAsInteresting,
                RuleAction::Highlight("green".into()),
            ];
            r
        },
    ]
}

// ── Serialization helpers ─────────────────────────────────────────────────────

pub fn rules_to_json(rules: &[Rule]) -> String {
    serde_json::to_string_pretty(rules).unwrap_or_default()
}

pub fn rules_from_json(json: &str) -> Vec<Rule> {
    serde_json::from_str(json).unwrap_or_default()
}
