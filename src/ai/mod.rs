pub mod executor;

// AI module: supports a local LLM via Ollama or a remote OpenAI-compatible endpoint.
// Also exposes a tiny task automation parser so the AI can trigger app actions.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Ollama,
    OpenAI,
    OpenRouter,
}

impl Provider {
    pub fn label(&self) -> &'static str {
        match self {
            Provider::Ollama => "Ollama (local)",
            Provider::OpenAI => "OpenAI-compatible",
            Provider::OpenRouter => "OpenRouter",
        }
    }
    
    pub fn all() -> &'static [Provider] {
        &[Provider::Ollama, Provider::OpenAI, Provider::OpenRouter]
    }
}

#[derive(Serialize)]
struct OllamaOptions {
    // Hard ceiling on generated tokens — at ~8 tok/s a runaway response can
    // stall for minutes, which is fatal in a live demo. 400 is generous for
    // a FOUND/KEEPING report or a paragraph answer, but kills true runaways.
    num_predict: i32,
}

#[derive(Serialize)]
struct OllamaRequest<'a> {
    model: &'a str,
    prompt: &'a str,
    stream: bool,
    // Keep the model resident between requests so there's no multi-second
    // cold reload after a pause (default is only 5 minutes).
    keep_alive: &'static str,
    options: OllamaOptions,
}

#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}

#[derive(Serialize)]
struct OpenAIMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct OpenAIRequest<'a> {
    model: &'a str,
    messages: Vec<OpenAIMessage<'a>>,
    stream: bool,
}

#[derive(Deserialize)]
struct OpenAIChoice {
    message: OpenAIMessageOwned,
}

#[derive(Deserialize)]
struct OpenAIMessageOwned {
    content: String,
}

#[derive(Deserialize)]
struct OpenAIResponse {
    choices: Vec<OpenAIChoice>,
}

#[allow(dead_code)] // one-shot completion API; the app uses chat_with_history
pub fn complete(
    provider: Provider,
    endpoint: &str,
    model: &str,
    api_key: &str,
    prompt: &str,
) -> Result<String, String> {
    match provider {
        Provider::Ollama => {
            let url = if endpoint.is_empty() {
                "http://localhost:11434/api/generate".to_string()
            } else {
                format!("{}/api/generate", endpoint.trim_end_matches('/'))
            };
            let body = OllamaRequest { model, prompt, stream: false, keep_alive: "30m", options: OllamaOptions { num_predict: 400 } };
            let resp = ureq::post(&url).timeout(std::time::Duration::from_secs(120))
                .set("Content-Type", "application/json")
                .send_json(serde_json::to_value(&body).map_err(|e| e.to_string())?)
                .map_err(|e| format!("Ollama request failed: {}", e))?;
            let parsed: OllamaResponse = resp.into_json().map_err(|e| e.to_string())?;
            Ok(parsed.response)
        }
        Provider::OpenAI => {
            let url = if endpoint.is_empty() {
                "https://api.openai.com/v1/chat/completions".to_string()
            } else {
                format!("{}/chat/completions", endpoint.trim_end_matches('/'))
            };
            let body = OpenAIRequest {
                model,
                messages: vec![OpenAIMessage { role: "user", content: prompt }],
                stream: false,
            };
            let mut req = ureq::post(&url).timeout(std::time::Duration::from_secs(120)).set("Content-Type", "application/json");
            if !api_key.is_empty() {
                req = req.set("Authorization", &format!("Bearer {}", api_key));
            }
            let resp = req
                .send_json(serde_json::to_value(&body).map_err(|e| e.to_string())?)
                .map_err(|e| format!("OpenAI request failed: {}", e))?;
            let parsed: OpenAIResponse = resp.into_json().map_err(|e| e.to_string())?;
            parsed
                .choices
                .into_iter()
                .next()
                .map(|c| c.message.content)
                .ok_or_else(|| "no choices returned".to_string())
        }
        Provider::OpenRouter => {
            let url = "https://openrouter.ai/api/v1/chat/completions".to_string();
            let body = OpenAIRequest {
                model,
                messages: vec![OpenAIMessage { role: "user", content: prompt }],
                stream: false,
            };
            let mut req = ureq::post(&url).timeout(std::time::Duration::from_secs(120))
                .set("Content-Type", "application/json")
                .set("HTTP-Referer", "https://farstyle.app")
                .set("X-Title", "FarStyle Security Auditor");
            if !api_key.is_empty() {
                req = req.set("Authorization", &format!("Bearer {}", api_key));
            }
            let resp = req
                .send_json(serde_json::to_value(&body).map_err(|e| e.to_string())?)
                .map_err(|e| format!("OpenRouter request failed: {}", e))?;
            let parsed: OpenAIResponse = resp.into_json().map_err(|e| e.to_string())?;
            parsed
                .choices
                .into_iter()
                .next()
                .map(|c| c.message.content)
                .ok_or_else(|| "no choices returned".to_string())
        }
    }
}

/// Cheap, instant TASK vs DISCUSSION classifier — pure keyword matching, no
/// LLM call. Mirrors the same split the Workspace system prompt teaches the
/// model to make, but doing it here for free lets us route plain questions
/// to a small/fast model without spending a slow round-trip just to decide
/// which model to use.
pub fn classify_is_task(prompt: &str) -> bool {
    // A knowledge question ("do you know how to fuzz?") is NEVER a task, even
    // though it contains an action keyword. Route it to discussion so the agent
    // explains instead of executing.
    if is_discussion_question(prompt) { return false; }
    let p = prompt.to_lowercase();
    const TASK_KEYWORDS: &[&str] = &[
        "check", "scan", "fetch", "test", "find", "run", "probe", "analyse", "analyze",
        "enumerate", "fuzz", "look at", "try", "attack", "send", "use", "curl",
        "exploit", "decode", "brute", "crawl", "set target", "go to",
        // slang commands
        "dirbust", "dirb", "recon", "spider", "pwn", "enum ",
    ];
    TASK_KEYWORDS.iter().any(|k| p.contains(k))
}

/// Is the message a QUESTION asking to explain/teach, versus a COMMAND to do
/// something? "do you know how to fuzz?", "how do I dirbust?", "what is SQLi?"
/// are discussion; "fuzz the target", "can you scan it" are actions. Note that
/// "can you X" / "could you X" are polite COMMANDS, not questions, so they are
/// deliberately excluded here.
pub fn is_discussion_question(prompt: &str) -> bool {
    let p = prompt.trim().to_lowercase();
    const OPENERS: &[&str] = &[
        "do you know", "do you understand", "have you heard", "are you able",
        "how do", "how does", "how to", "how can i", "how would", "how should", "how are",
        "what is", "what's", "whats", "what are", "what does", "what do you", "what would",
        "why ", "when should", "when do", "should i", "should we", "which is",
        "explain", "tell me about", "describe", "define", "teach me",
        "is it possible", "is there a way", "can it", "does it", "difference between",
    ];
    if OPENERS.iter().any(|o| p.starts_with(o)) { return true; }
    // Same knowledge-question phrasings when they appear mid-sentence.
    p.contains("do you know how") || p.contains("how do i") || p.contains("how do you")
        || p.contains("how to ") || p.contains("what is ")
}

/// Detect an unambiguous, direct tool command ("curl the target",
/// "nmap example.com", "fetch the site") so the Workspace can skip the slow
/// "decide which tool" LLM round-trip entirely and run the smart-tool
/// pipeline directly. Returns (tool, goal) or None for requests that
/// genuinely need the model to reason about intent ("look at the proxy and
/// tell me what's interesting").
pub fn parse_direct_command(prompt: &str) -> Option<(String, String)> {
    let first = prompt.split_whitespace().next()?.to_lowercase();
    // First word IS a known CLI tool → run it directly.
    const TOOLS: &[&str] = &[
        "curl", "nmap", "whatweb", "nikto", "sqlmap", "nuclei", "ffuf", "gobuster",
        "subfinder", "dig", "whois", "httpx", "katana", "dalfox", "arjun", "ping", "wafw00f",
    ];
    let tool = if TOOLS.contains(&first.as_str()) {
        first
    } else {
        // Or a plain verb that maps to one obvious tool.
        match first.as_str() {
            "fetch" | "get" | "download" => "curl".into(),
            "scan" | "portscan"          => "nmap".into(),
            "fuzz"                        => "ffuf".into(),
            _ => return None,
        }
    };
    Some((tool, prompt.to_string()))
}

/// Detect a command that explicitly names a tool AND an action, even mid-
/// sentence ("can u brute force /login ... using ffuf"). Routes straight to
/// that tool's pipeline, skipping the open-ended "decide" LLM call — which is
/// exactly what trips the model's safety training into refusing an action the
/// app has already authorised via its own confirmation gate. Returns
/// (tool, goal) or None.
pub fn parse_tool_command(prompt: &str) -> Option<(String, String)> {
    // "do you know how to use ffuf?" names a tool but is a question — don't run it.
    if is_discussion_question(prompt) { return None; }
    let p = prompt.to_lowercase();
    const TOOLS: &[&str] = &[
        "ffuf", "gobuster", "sqlmap", "nmap", "nuclei", "nikto", "hydra", "dalfox",
        "arjun", "katana", "httpx", "subfinder", "whatweb", "wfuzz", "feroxbuster",
    ];
    // An action verb signals "do it" (vs. "what is ffuf?").
    let has_action = ["brute", "fuzz", "scan", "run", "attack", "exploit", "test",
        "crack", "enumerate", "probe", "force", "find"].iter().any(|v| p.contains(v));
    if !has_action { return None; }
    // The tool must appear as a whole word, not a substring.
    let tool = TOOLS.iter().find(|t|
        p.split(|c: char| !c.is_alphanumeric()).any(|w| w == **t))?;
    Some((tool.to_string(), prompt.to_string()))
}

/// Decide whether a non-task message is genuine small-talk safe for the tiny
/// fast model, versus a substantive question that needs the capable model's
/// real knowledge. The fast model is great at "yo"/"who are you?" but
/// fabricates dangerous nonsense on security questions (e.g. WAF evasion
/// payloads), so anything with technical/security substance — or any real
/// request to explain/show/write something — must go to the capable model.
///
/// Conservative by design: when in doubt, returns false so the capable model
/// handles it. Only obvious chit-chat takes the fast path.
pub fn is_trivial_chat(prompt: &str) -> bool {
    let p = prompt.trim().to_lowercase();
    if p.is_empty() { return false; }

    // Any security/technical substance → never the fast model.
    const TECH: &[&str] = &[
        "payload", "exploit", "waf", "bypass", "evade", "inject", "sqli", "xss", "csrf",
        "ssrf", "xxe", "rce", "lfi", "rfi", "shell", "obfuscat", "encode", "decode", "vuln",
        "cve", "token", "jwt", "hash", "crack", "firewall", "privilege", "escalat", "recon",
        "header", "cookie", "auth", "cipher", "tls", "ssl", "subdomain", "endpoint", "request",
        "response", "http", "dns", "port", "sql", "script", "command", "reverse", "backdoor",
        "malware", "ransom", "phish", "burp", "nmap", "curl", "proxy", "intercept",
    ];
    if TECH.iter().any(|t| p.contains(t)) { return false; }

    // Questions that refer back to prior results need the capable model AND the
    // tool-output context — the fast model has neither.
    const REFERENTIAL: &[&str] = &[
        "which", "that one", "the one", "result", "earlier", "previous", "last one",
        "status", "size", "differ", "different", "above", "before",
    ];
    if REFERENTIAL.iter().any(|r| p.contains(r)) { return false; }
    // A bare 3-digit token is almost always an HTTP status / port reference.
    if p.split(|c: char| !c.is_ascii_digit()).any(|n| n.len() == 3) { return false; }

    // Substantive "teach me / make me X" requests need the capable model even
    // when no security keyword is present.
    const SUBSTANTIVE_OPENERS: &[&str] = &[
        "show", "give", "write", "generate", "create", "build", "make", "explain",
        "how do", "how to", "how can", "how does", "what's the best", "steps to", "guide",
    ];
    if SUBSTANTIVE_OPENERS.iter().any(|o| p.starts_with(o)) { return false; }

    // Otherwise: only short, plain conversational turns qualify as trivial.
    let words = p.split_whitespace().count();
    words <= 8
}

#[derive(Debug, Clone)]
pub enum AiAction {
    // Target
    SetTarget(String),
    // Proxy
    StartProxy,
    StopProxy,
    // Repeater
    RepeaterSetMethod(String),
    RepeaterSetUrl(String),
    RepeaterSetBody(String),
    RepeaterSetHeader(String),
    RepeaterSend,
    // Intruder
    IntruderSetUrl(String),
    IntruderSetMethod(String),
    IntruderSetBody(String),
    IntruderAddPosition { name: String },
    IntruderSetWordlist { position: usize, path: String },
    IntruderSetAttackMode(String),
    IntruderStartAttack,
    // Scan modules toggle
    EnableModule(usize),
    DisableModule(usize),
    // Generic tool execution: tool name + full args list
    RunTool { tool: String, args: Vec<String> },
    // Smart tool execution: AI reads -h, builds precise command, synthesizes output
    SmartRunTool { tool: String, goal: String },
    // Encoder
    Encode { op: String, input: String },
    // JWT analysis — decode/inspect a token
    DecodeJwt(String),
    // CVE lookup for a service + version string
    CveLookup(String),
    // OSINT query on a domain (subdomains / IP / tech stack)
    OsintQuery(String),
    // OSINT AI investigation of a person / company (dork + scrape + synthesise)
    OsintInvestigate(String),
    // Run the enabled built-in scan modules against the target
    StartScan,
    // Crawl/spider the target to map its surface
    StartSpider,
    // Navigation
    NavigateTo(String),
    // Run a user-uploaded module by name, optionally against a specific URL
    RunModule { name: String, target_url: Option<String> },
    // ── Memory / knowledge integration ─────────────────────────────────────
    // Let the agent record its thinking so it surfaces across the app.
    AddHypothesis(String),                                  // → Hypotheses Lounge
    AddMindNote { kind: String, text: String },            // → Mind Base (ephemeral)
    AddKnowledge { title: String, content: String },       // → Knowledge Base (persisted)
    // Store a CONFIRMED vulnerability + PoC in the Vuln Store (and pin to Mind Base)
    StoreVuln { vuln_type: String, title: String, poc: String },
    // Full form-attack pipeline: curl page → parse inputs → fill & send → analyse
    FormAttack(String), // target URL
    // Load a specific proxy capture (by ID) into the Repeater
    LoadCaptureToRepeater(u64),
    // Take the current Repeater request, mark <field> as FUZZ, push to Intruder
    SetupIntruderFromRepeater(String), // field name to fuzz (e.g. "password")
}

/// Send a full message history (role, content) pairs and return the assistant reply.
/// Used by the Workspace for multi-turn, stateful conversations.
pub fn chat_with_history(
    provider: &Provider,
    endpoint: &str,
    model: &str,
    api_key: &str,
    messages: Vec<(String, String)>,
) -> Result<String, String> {
    match provider {
        Provider::Ollama => {
            // Ollama doesn't natively support multi-turn via /api/generate —
            // flatten to a single prompt with role prefixes.
            let prompt = messages.iter()
                .map(|(role, content)| format!("[{}]: {}", role, content))
                .collect::<Vec<_>>()
                .join("\n\n");
            let url = if endpoint.is_empty() {
                "http://localhost:11434/api/generate".to_string()
            } else {
                format!("{}/api/generate", endpoint.trim_end_matches('/'))
            };
            let body = OllamaRequest { model, prompt: &prompt, stream: false, keep_alive: "30m", options: OllamaOptions { num_predict: 400 } };
            let resp = ureq::post(&url).timeout(std::time::Duration::from_secs(120))
                .set("Content-Type", "application/json")
                .send_json(serde_json::to_value(&body).map_err(|e| e.to_string())?)
                .map_err(|e| format!("Ollama request failed: {}", e))?;
            let parsed: OllamaResponse = resp.into_json().map_err(|e| e.to_string())?;
            Ok(parsed.response)
        }
        Provider::OpenAI | Provider::OpenRouter => {
            let url = match provider {
                Provider::OpenAI => {
                    if endpoint.is_empty() {
                        "https://api.openai.com/v1/chat/completions".to_string()
                    } else {
                        format!("{}/chat/completions", endpoint.trim_end_matches('/'))
                    }
                }
                _ => "https://openrouter.ai/api/v1/chat/completions".to_string(),
            };

            // Extract system content and merge into the first user message.
            // Many free/small models (e.g. baidu/cobuddy) honour the user role
            // but silently ignore the system role for identity/context. By
            // prepending the system block directly into the first user turn we
            // guarantee it is always read.
            let system_content: String = messages.iter()
                .filter(|(r, _)| r == "system")
                .map(|(_, c)| c.as_str())
                .collect::<Vec<_>>()
                .join("\n");

            let mut owned: Vec<(String, String)> = messages.into_iter()
                .filter(|(r, _)| r != "system")
                .collect();

            if !system_content.is_empty() {
                if let Some(first_user) = owned.iter_mut().find(|(r, _)| r == "user") {
                    first_user.1 = format!(
                        "--- CONTEXT (read this carefully before answering) ---\n{}\n--- END CONTEXT ---\n\n{}",
                        system_content, first_user.1
                    );
                } else {
                    owned.insert(0, ("user".to_string(), format!(
                        "--- CONTEXT ---\n{}\n--- END CONTEXT ---",
                        system_content
                    )));
                }
            }

            let msgs: Vec<OpenAIMessage> = owned.iter()
                .map(|(role, content)| OpenAIMessage { role: role.as_str(), content: content.as_str() })
                .collect();

            let body = OpenAIRequest { model, messages: msgs, stream: false };
            let mut req = ureq::post(&url).timeout(std::time::Duration::from_secs(120)).set("Content-Type", "application/json");
            if matches!(provider, Provider::OpenRouter) {
                req = req
                    .set("HTTP-Referer", "https://farstyle.app")
                    .set("X-Title", "FarStyle Security Auditor");
            }
            if !api_key.is_empty() { req = req.set("Authorization", &format!("Bearer {}", api_key)); }
            let resp = req.send_json(serde_json::to_value(&body).map_err(|e| e.to_string())?)
                .map_err(|e| {
                    // ureq wraps HTTP error responses — try to extract body for detail
                    match e {
                        ureq::Error::Status(code, response) => {
                            let body = response.into_string().unwrap_or_default();
                            // Try to pull OpenRouter error message
                            let detail = serde_json::from_str::<serde_json::Value>(&body)
                                .ok()
                                .and_then(|v| {
                                    v.pointer("/error/message")
                                        .or_else(|| v.pointer("/error"))
                                        .map(|m| m.to_string())
                                })
                                .unwrap_or(body);
                            format!("API error {}: {}", code, detail)
                        }
                        other => format!("request failed: {}", other),
                    }
                })?;
            let parsed: OpenAIResponse = resp.into_json().map_err(|e| e.to_string())?;
            parsed.choices.into_iter().next().map(|c| c.message.content)
                .ok_or_else(|| "no choices returned".to_string())
        }
    }
}

/// Parse ACTION: lines from an AI response.
///
/// Syntax:
///   ACTION: run_tool <tool> [arg1 arg2 ...]
///   e.g.
///   ACTION: run_tool nmap -sV -p 80,443 --script vuln example.com
///   ACTION: run_tool sqlmap -u https://example.com/login --data "u=a&p=b" --batch --dbs
///   ACTION: run_tool ffuf -u https://example.com/FUZZ -mc 200   (omit -w; a wordlist is injected automatically)
///   ACTION: run_tool nuclei -u https://example.com -t cves/ -severity critical
pub fn extract_actions(text: &str) -> Vec<AiAction> {
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        let body = match l.strip_prefix("ACTION:") {
            Some(b) => b.trim(),
            None => continue,
        };
        if body.is_empty() { continue; }

        // Split on whitespace but don't limit — we need all args
        let parts: Vec<&str> = body.split_whitespace().collect();

        match parts.as_slice() {
            // Target
            ["set_target", url, ..] =>
                out.push(AiAction::SetTarget(url.to_string())),

            // Proxy
            ["proxy_start"] => out.push(AiAction::StartProxy),
            ["proxy_stop"]  => out.push(AiAction::StopProxy),

            // Repeater
            ["repeater_method", m, ..] =>
                out.push(AiAction::RepeaterSetMethod(m.to_string())),
            ["repeater_url", url, ..] =>
                out.push(AiAction::RepeaterSetUrl(url.to_string())),
            ["repeater_body", rest @ ..] =>
                out.push(AiAction::RepeaterSetBody(rest.join(" "))),
            ["repeater_header", rest @ ..] =>
                out.push(AiAction::RepeaterSetHeader(rest.join(" "))),
            ["repeater_send"] =>
                out.push(AiAction::RepeaterSend),

            // Intruder
            ["intruder_url", url, ..] =>
                out.push(AiAction::IntruderSetUrl(url.to_string())),
            ["intruder_method", m, ..] =>
                out.push(AiAction::IntruderSetMethod(m.to_string())),
            ["intruder_body", rest @ ..] =>
                out.push(AiAction::IntruderSetBody(rest.join(" "))),
            ["intruder_add_position", name, ..] =>
                out.push(AiAction::IntruderAddPosition { name: name.to_string() }),
            ["intruder_wordlist", pos, path, ..] => {
                if let Ok(i) = pos.parse() {
                    out.push(AiAction::IntruderSetWordlist { position: i, path: path.to_string() });
                }
            }
            ["intruder_mode", mode, ..] =>
                out.push(AiAction::IntruderSetAttackMode(mode.to_string())),
            ["intruder_attack"] =>
                out.push(AiAction::IntruderStartAttack),

            // Scan module toggles
            ["enable_module", n, ..] => {
                if let Ok(i) = n.parse() { out.push(AiAction::EnableModule(i)); }
            }
            ["disable_module", n, ..] => {
                if let Ok(i) = n.parse() { out.push(AiAction::DisableModule(i)); }
            }

            // Generic tool runner — all remaining tokens are the args
            // ACTION: run_tool nmap -sV -p 80,443 target.com
            ["run_tool", tool, args @ ..] =>
                out.push(AiAction::RunTool {
                    tool: tool.to_string(),
                    args: args.iter().map(|s| s.to_string()).collect(),
                }),

            // Smart tool runner: reads -h, picks flags, synthesizes output
            // ACTION: smart_run_tool curl get the status code of https://mozastore.net
            ["smart_run_tool", tool, goal @ ..] if !goal.is_empty() =>
                out.push(AiAction::SmartRunTool {
                    tool: tool.to_string(),
                    goal: goal.join(" "),
                }),

            // Legacy shorthands kept for backwards compat
            ["nmap_scan", target, ..] =>
                out.push(AiAction::RunTool {
                    tool: "nmap".into(),
                    args: vec![target.to_string()],
                }),

            // Encoder
            ["encode", op, rest @ ..] =>
                out.push(AiAction::Encode { op: op.to_string(), input: rest.join(" ") }),

            // JWT / CVE / OSINT / scan / spider
            ["decode_jwt", rest @ ..] =>
                out.push(AiAction::DecodeJwt(rest.join(" "))),
            ["jwt", rest @ ..] =>
                out.push(AiAction::DecodeJwt(rest.join(" "))),
            ["cve_lookup", rest @ ..] | ["cve", rest @ ..] =>
                out.push(AiAction::CveLookup(rest.join(" "))),
            // Person/company investigation must be matched before the generic
            // osint domain query so "osint investigate <name>" routes correctly.
            ["osint", "investigate", rest @ ..] | ["osint_investigate", rest @ ..]
            | ["investigate", rest @ ..] if !rest.is_empty() =>
                out.push(AiAction::OsintInvestigate(rest.join(" "))),
            ["osint", rest @ ..] =>
                out.push(AiAction::OsintQuery(rest.join(" "))),
            ["start_scan"] | ["scan"] =>
                out.push(AiAction::StartScan),
            ["spider"] | ["crawl"] =>
                out.push(AiAction::StartSpider),

            // Navigation
            ["navigate", rest @ ..] =>
                out.push(AiAction::NavigateTo(rest.join(" "))),

            // User module runner
            // ACTION: run_module web_scrapper
            // ACTION: run_module sqli_exploit http://localhost:3000/search?q=test
            ["run_module", name, url, ..] if url.starts_with("http") =>
                out.push(AiAction::RunModule { name: name.to_string(), target_url: Some(url.to_string()) }),
            ["run_module", name, ..] =>
                out.push(AiAction::RunModule { name: name.to_string(), target_url: None }),

            // Memory integration — record the agent's thinking into the app's stores.
            // ACTION: hypothesis <a specific, testable theory>
            ["hypothesis", rest @ ..] if !rest.is_empty() =>
                out.push(AiAction::AddHypothesis(rest.join(" "))),
            // ACTION: remember <a key fact / endpoint / token / observation>
            ["remember", rest @ ..] if !rest.is_empty() =>
                out.push(AiAction::AddMindNote { kind: "Note".into(), text: rest.join(" ") }),
            // ACTION: learn <title> :: <durable knowledge to keep>
            ["learn", rest @ ..] if !rest.is_empty() => {
                let joined = rest.join(" ");
                let (title, content) = match joined.split_once("::") {
                    Some((t, c)) => (t.trim().to_string(), c.trim().to_string()),
                    None => {
                        let title: String = joined.split_whitespace().take(6).collect::<Vec<_>>().join(" ");
                        (title, joined.clone())
                    }
                };
                if !content.is_empty() {
                    out.push(AiAction::AddKnowledge { title, content });
                }
            }
            // ACTION: store_vuln <type> :: <title> :: <poc / how to reproduce>
            ["store_vuln", rest @ ..] | ["vuln", rest @ ..] if !rest.is_empty() => {
                let joined = rest.join(" ");
                let parts: Vec<&str> = joined.splitn(3, "::").map(|s| s.trim()).collect();
                let (vuln_type, title, poc) = match parts.as_slice() {
                    [t, ti, p] => (t.to_string(), ti.to_string(), p.to_string()),
                    [t, ti] => (t.to_string(), ti.to_string(), String::new()),
                    [t] => ("Vulnerability".to_string(), t.to_string(), String::new()),
                    _ => (String::new(), joined.clone(), String::new()),
                };
                if !title.is_empty() {
                    out.push(AiAction::StoreVuln { vuln_type, title, poc });
                }
            }

            // ACTION: form_attack <url>
            ["form_attack", url, ..] =>
                out.push(AiAction::FormAttack(url.to_string())),
            // ACTION: repeater_load_capture <id>
            ["repeater_load_capture", id, ..] => {
                if let Ok(n) = id.parse::<u64>() {
                    out.push(AiAction::LoadCaptureToRepeater(n));
                }
            }
            // ACTION: intruder_from_repeater <field_name>
            ["intruder_from_repeater", field, ..] =>
                out.push(AiAction::SetupIntruderFromRepeater(field.to_string())),

            _ => {}
        }
    }
    out
}
