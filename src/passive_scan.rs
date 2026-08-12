// The Severity scale and the standalone `analyse` entry point are the analyser's
// public API; the live path uses a subset, the rest is intentional surface.
#![allow(dead_code)]

/// Passive traffic analyser for FARSTYLE.
///
/// Runs after every captured HTTP(S) request+response pair and emits
/// PassiveAlert items for potential vulnerabilities detected purely from
/// the traffic — no active probing involved.

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info     => "INFO",
            Severity::Low      => "LOW",
            Severity::Medium   => "MEDIUM",
            Severity::High     => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
    pub fn color_rgb(&self) -> (u8, u8, u8) {
        match self {
            Severity::Info     => (100, 160, 220),
            Severity::Low      => (80,  200, 120),
            Severity::Medium   => (220, 180,  40),
            Severity::High     => (220, 100,  40),
            Severity::Critical => (220,  50,  50),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PassiveAlert {
    pub id:          u64,
    pub url:         String,
    pub title:       String,
    pub description: String,
    pub severity:    Severity,
    pub evidence:    String,
}

/// Analyse a single captured request/response pair.
/// Returns any alerts triggered (may be empty).
pub fn analyse(
    alert_counter: &mut u64,
    method: &str,
    url: &str,
    req_headers: &[(String, String)],
    req_body: &[u8],
    status: u16,
    resp_headers: &[(String, String)],
    resp_body: &[u8],
) -> Vec<PassiveAlert> {
    let mut alerts = Vec::new();
    let resp_text  = std::str::from_utf8(resp_body).unwrap_or("");
    let req_text   = std::str::from_utf8(req_body).unwrap_or("");

    let resp_hdr_map: std::collections::HashMap<String, String> = resp_headers.iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();
    let req_hdr_map: std::collections::HashMap<String, String> = req_headers.iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    macro_rules! alert {
        ($sev:expr, $title:expr, $desc:expr, $evidence:expr) => {{
            *alert_counter += 1;
            alerts.push(PassiveAlert {
                id: *alert_counter,
                url: url.to_string(),
                title: $title.to_string(),
                description: $desc.to_string(),
                severity: $sev,
                evidence: $evidence.to_string(),
            });
        }};
    }

    // ── 1. Missing security headers ───────────────────────────────────────────
    let security_headers = [
        ("x-content-type-options", "X-Content-Type-Options missing",
         "Without this header, browsers may MIME-sniff responses, enabling XSS in some cases.",
         Severity::Low),
        ("x-frame-options", "X-Frame-Options missing",
         "The page may be embeddable in an iframe, enabling clickjacking attacks.",
         Severity::Medium),
        ("strict-transport-security", "HSTS missing",
         "Without HSTS, connections could be downgraded from HTTPS to HTTP.",
         Severity::Medium),
        ("content-security-policy", "Content-Security-Policy missing",
         "No CSP header found. XSS payloads can execute without restriction.",
         Severity::Medium),
        ("x-xss-protection", "X-XSS-Protection missing",
         "Legacy header absent (note: CSP is the modern replacement).",
         Severity::Info),
        ("referrer-policy", "Referrer-Policy missing",
         "Sensitive URL parameters may be leaked via the Referer header.",
         Severity::Low),
        ("permissions-policy", "Permissions-Policy missing",
         "Browser features (camera, geolocation…) are not restricted by policy.",
         Severity::Info),
    ];
    for (hdr, title, desc, sev) in &security_headers {
        if !resp_hdr_map.contains_key(*hdr) {
            alert!(sev.clone(), title, desc, format!("Header '{}' not present in response", hdr));
        }
    }

    // ── 2. Sensitive data in response ─────────────────────────────────────────
    let sensitive_patterns: &[(&str, &str, Severity)] = &[
        (r"-----BEGIN",          "Private key exposed",                        Severity::Critical),
        (r"api_key",             "Possible API key in response body",           Severity::High),
        (r"apikey",              "Possible API key in response body",           Severity::High),
        (r"secret",              "Word 'secret' found in response",             Severity::Medium),
        (r"password",            "Word 'password' found in response body",      Severity::High),
        (r"Authorization: Bearer", "Bearer token echoed in response",           Severity::High),
        (r"aws_access_key_id",   "AWS access key ID in response",              Severity::Critical),
        (r"eyJ",                 "Possible JWT in response body",               Severity::Medium),
        (r"<script>document.cookie", "Cookie access via inline script",        Severity::High),
        (r"X-Powered-By",        "Technology fingerprint exposed",              Severity::Info),
    ];
    for (pattern, title, sev) in sensitive_patterns {
        if resp_text.contains(pattern) {
            let evidence = resp_text.lines()
                .find(|l| l.contains(pattern))
                .unwrap_or("")
                .trim()
                .chars()
                .take(120)
                .collect::<String>();
            alert!(sev.clone(), title,
                format!("Pattern '{}' detected in response body.", pattern),
                evidence);
        }
    }

    // ── 3. Cookie issues ──────────────────────────────────────────────────────
    if let Some(set_cookie) = resp_hdr_map.get("set-cookie") {
        let lower = set_cookie.to_lowercase();
        if !lower.contains("httponly") {
            alert!(Severity::Medium, "Cookie missing HttpOnly flag",
                "The cookie is accessible via JavaScript, enabling theft via XSS.",
                set_cookie.chars().take(100).collect::<String>());
        }
        if !lower.contains("secure") && url.starts_with("https") {
            alert!(Severity::Medium, "Cookie missing Secure flag",
                "The cookie may be transmitted over plain HTTP.",
                set_cookie.chars().take(100).collect::<String>());
        }
        if !lower.contains("samesite") {
            alert!(Severity::Low, "Cookie missing SameSite attribute",
                "Without SameSite, the cookie may be sent in cross-site requests (CSRF).",
                set_cookie.chars().take(100).collect::<String>());
        }
    }

    // ── 4. Interesting status codes ───────────────────────────────────────────
    match status {
        500..=599 => alert!(Severity::Medium, "Server error response",
            "A 5xx response may indicate an unhandled exception leaking internal details.",
            format!("HTTP {}", status)),
        403 => alert!(Severity::Info, "403 Forbidden — possible hidden resource",
            "A 403 may indicate a resource that exists but is access-controlled.",
            format!("HTTP 403 on {} {}", method, url)),
        _ => {}
    }

    // ── 5. SQL error patterns in response ────────────────────────────────────
    let sql_errors = [
        "You have an error in your SQL syntax",
        "ORA-01756", "ORA-00907", "Microsoft OLE DB Provider for SQL Server",
        "Unclosed quotation mark", "pg_query()", "mysql_fetch_array()",
        "SQLiteException", "syntax error at or near",
    ];
    for pat in &sql_errors {
        if resp_text.contains(pat) {
            alert!(Severity::High, "SQL error in response — possible SQLi",
                "A SQL error message was returned. The endpoint may be vulnerable to SQL injection.",
                pat.to_string());
        }
    }

    // ── 6. XSS reflection ─────────────────────────────────────────────────────
    let xss_probes = ["<script>", "onerror=", "onload=", "javascript:", "alert(", "confirm("];
    for probe in &xss_probes {
        if req_text.contains(probe) && resp_text.contains(probe) {
            alert!(Severity::High, "Possible reflected XSS",
                "An XSS probe sent in the request was reflected unencoded in the response.",
                probe.to_string());
        }
    }

    // ── 7. Directory listing ──────────────────────────────────────────────────
    if resp_text.contains("Index of /") || resp_text.contains("Directory listing for") {
        alert!(Severity::Medium, "Directory listing enabled",
            "The server is exposing a directory index. Sensitive files may be accessible.",
            url.to_string());
    }

    // ── 8. Credentials in URL ─────────────────────────────────────────────────
    let lower_url = url.to_lowercase();
    for kw in &["password=", "passwd=", "token=", "api_key=", "secret=", "apikey="] {
        if lower_url.contains(kw) {
            alert!(Severity::High, "Sensitive parameter in URL",
                "Credentials or tokens in URLs are logged by proxies, browsers, and servers.",
                format!("URL contains '{}'", kw));
        }
    }

    // ── 9. CORS misconfiguration ──────────────────────────────────────────────
    if let Some(acao) = resp_hdr_map.get("access-control-allow-origin") {
        if acao == "*" {
            alert!(Severity::Medium, "CORS wildcard origin",
                "Access-Control-Allow-Origin: * allows any site to read responses.",
                acao.clone());
        }
        if let Some(origin) = req_hdr_map.get("origin") {
            if acao == origin {
                alert!(Severity::High, "CORS reflects arbitrary origin",
                    "The server mirrors the request Origin header, enabling cross-origin data theft.",
                    format!("Origin: {} → ACAO: {}", origin, acao));
            }
        }
    }

    // ── 10. Clickjacking via CSP frame-ancestors ──────────────────────────────
    if let Some(csp) = resp_hdr_map.get("content-security-policy") {
        if !csp.contains("frame-ancestors") {
            alert!(Severity::Low, "CSP missing frame-ancestors directive",
                "Without frame-ancestors in CSP, X-Frame-Options is the only clickjacking protection.",
                csp.chars().take(120).collect::<String>());
        }
    }

    alerts
}
