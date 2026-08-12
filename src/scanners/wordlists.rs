/// Resolve the best available wordlist path for a given category.
/// Checks SecLists first (common install paths), then falls back to built-in minimal lists.
pub fn resolve(category: WordlistCategory) -> String {
    let candidates = category.candidates();
    for path in &candidates {
        if std::path::Path::new(path).exists() {
            return path.to_string();
        }
    }
    // Fallback: write a minimal inline wordlist to /tmp
    let fallback = category.fallback_content();
    let path = format!("/tmp/farstyle_{}.txt", category.name());
    let _ = std::fs::write(&path, fallback);
    path
}

/// Repair an AI-built fuzzing command so its wordlist argument points at a file
/// that actually exists on THIS machine. The model routinely emits Kali/Linux
/// paths like `/usr/share/wordlists/dirb/big.txt` which don't exist on macOS,
/// so ffuf/gobuster/etc. die with "wordlist not found". We detect the wordlist
/// flag and, if its path is missing (or there's no `-w` at all), substitute a
/// `resolve()`d path — which falls back to a generated minimal list in /tmp.
/// Non-fuzzing commands are returned unchanged.
pub fn fixup_wordlist(cmd: &str) -> String {
    let first = cmd.split_whitespace().next().unwrap_or("");
    let needs = matches!(first,
        "ffuf" | "gobuster" | "feroxbuster" | "wfuzz" | "dirb" | "dirsearch" | "arjun");
    if !needs { return cmd.to_string(); }

    let lc = cmd.to_lowercase();
    // Passwords ONLY for a real credential attack: FUZZ inside a POST body
    // (-d ...FUZZ). Merely mentioning "login" in a directory-fuzz goal must NOT
    // switch to the password list — that's a path scan and needs path words.
    let is_credential = lc.contains("-d ") && lc.contains("fuzz");
    let category = if is_credential || lc.contains("passwd") {
        WordlistCategory::Passwords
    } else if first == "arjun" || lc.contains("param") {
        WordlistCategory::Parameters
    } else if lc.contains(" dns") || lc.contains("vhost") || lc.contains("subdomain") {
        WordlistCategory::Subdomains
    } else {
        WordlistCategory::CommonPaths
    };
    // resolve() may write a /tmp fallback, so compute it once and reuse.
    let resolved = resolve(category);

    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    let mut out: Vec<String> = Vec::with_capacity(tokens.len() + 2);
    let mut had_wordlist = false;
    let mut i = 0;
    while i < tokens.len() {
        let t = tokens[i];
        if t == "-w" || t == "--wordlist" {
            had_wordlist = true;
            out.push(t.to_string());
            if let Some(path) = tokens.get(i + 1) {
                if std::path::Path::new(path).exists() {
                    out.push(path.to_string());      // already valid — keep it
                } else {
                    out.push(resolved.clone());      // broken path — repair it
                }
                i += 2;
                continue;
            }
        }
        out.push(t.to_string());
        i += 1;
    }
    if !had_wordlist {
        // dirb takes a positional wordlist; the rest use a -w flag.
        if first == "dirb" {
            out.push(resolved.clone());
        } else {
            out.push("-w".to_string());
            out.push(resolved.clone());
        }
    }
    out.join(" ")
}

/// Tune an ffuf credential brute-force so a real hit is actually detectable.
/// The model loves to bolt on contradictory match flags (`-mc 200,302 -mc
/// 401,403`) against a login that returns the SAME response for every wrong
/// password — so either everything matches or nothing does, and a valid
/// credential never stands out. We strip those guesses and add `-ac`
/// (auto-calibration): ffuf sends a few junk passwords, learns what a FAILED
/// attempt looks like, and filters it — leaving only anomalies = candidate
/// valid creds. This is how you "know what success looks like" without manually
/// inspecting the response in the Repeater first.
pub fn tune_bruteforce(cmd: &str) -> String {
    if cmd.split_whitespace().next().unwrap_or("") != "ffuf" { return cmd.to_string(); }
    let lc = cmd.to_lowercase();
    // Only credential fuzzing (FUZZ inside a POST body), not directory fuzzing.
    let is_cred = lc.contains("-d ") && lc.contains("fuzz")
        && (lc.contains("password") || lc.contains("passwd") || lc.contains("pass="));
    if !is_cred { return cmd.to_string(); }

    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    let mut out: Vec<String> = Vec::with_capacity(tokens.len() + 1);
    let mut i = 0;
    while i < tokens.len() {
        match tokens[i] {
            // Drop the model's match/filter guesses (and their value) — -ac replaces them.
            "-mc" | "-fc" | "-fs" | "-fw" | "-fl" | "-ml" | "-mw" | "-ms" => { i += 2; continue; }
            "-ac" => { i += 1; continue; } // re-added once below
            t => { out.push(t.to_string()); i += 1; }
        }
    }
    out.push("-ac".to_string());
    out.join(" ")
}

/// Repair the malformed ffuf flags the model loves to invent:
///   • duplicate `-mc 200 -mc 302` → merged `-mc 200,204,301,302,307,401,403`
///     (a single match set; for path fuzzing we use the full useful set).
///   • bogus `-x FUZZ` / `-x <non-url>` → dropped (-x is the PROXY flag; a value
///     that isn't a URL is wrong and breaks the run).
///   • `-c` (colorize) → dropped, because ANSI codes pollute the captured output.
///   • duplicate `-w` → only the first kept.
/// Leaves an auto-calibrated (`-ac`) credential brute-force untouched re: match
/// codes. Non-ffuf commands pass through unchanged.
pub fn sanitize_ffuf(cmd: &str) -> String {
    if cmd.split_whitespace().next().unwrap_or("") != "ffuf" { return cmd.to_string(); }
    let toks: Vec<&str> = cmd.split_whitespace().collect();
    let mut out: Vec<String> = Vec::new();
    let mut mc: Vec<String> = Vec::new();
    let mut seen_w = false;
    let mut i = 0;
    while i < toks.len() {
        match toks[i] {
            "-mc" => {
                if let Some(v) = toks.get(i + 1) {
                    for c in v.split(',') {
                        let c = c.trim();
                        if !c.is_empty() && !mc.iter().any(|x| x == c) { mc.push(c.to_string()); }
                    }
                }
                i += 2; continue;
            }
            "-x" => {
                // Proxy flag: keep only if the value is a real proxy URL.
                if let Some(v) = toks.get(i + 1) {
                    if v.starts_with("http://") || v.starts_with("https://") || v.starts_with("socks") {
                        out.push("-x".into()); out.push((*v).to_string());
                    }
                    i += 2; continue;
                }
                i += 1; continue;
            }
            "-c" => { i += 1; continue; }
            "-w" | "--wordlist" => {
                if seen_w { i += 2; continue; } // drop duplicate wordlist
                seen_w = true;
                out.push(toks[i].to_string());
                if let Some(v) = toks.get(i + 1) { out.push((*v).to_string()); }
                i += 2; continue;
            }
            t => { out.push(t.to_string()); i += 1; }
        }
    }
    // Re-emit a single, well-formed match set (unless auto-calibrated).
    let has_ac = out.iter().any(|s| s == "-ac");
    if !has_ac {
        let is_path = cmd.contains("FUZZ") && !cmd.to_lowercase().contains("-d ");
        if is_path {
            for c in ["200", "204", "301", "302", "307", "401", "403"] {
                if !mc.iter().any(|x| x == c) { mc.push(c.to_string()); }
            }
        } else if mc.is_empty() {
            mc = ["200", "302"].iter().map(|s| s.to_string()).collect();
        }
        out.push("-mc".into());
        out.push(mc.join(","));
    }
    out.join(" ")
}

/// Narrow a directory/path fuzzing wordlist to the entries relevant to the
/// stated goal, instead of blasting the whole list. E.g. "check for a login
/// directory" → only login/signin/auth/admin/account/portal-type words. Writes
/// the focused subset to /tmp and rewrites `-w` to point at it. Falls back to
/// the full list when the goal has no clear intent or too few words match.
/// Only applies to path fuzzing (FUZZ in the URL), never credential brute-force.
pub fn focus_wordlist(cmd: &str, goal: &str) -> String {
    // Path fuzzing only: FUZZ present and NOT a POST-body credential attack.
    let lc = cmd.to_lowercase();
    if !cmd.contains("FUZZ") || lc.contains("-d ") { return cmd.to_string(); }

    let toks: Vec<&str> = cmd.split_whitespace().collect();
    let wi = match toks.iter().position(|t| *t == "-w" || *t == "--wordlist") {
        Some(i) if i + 1 < toks.len() => i + 1,
        _ => return cmd.to_string(),
    };
    let path = toks[wi];

    let terms = intent_terms(goal);
    if terms.is_empty() { return cmd.to_string(); }

    let content = match std::fs::read_to_string(path) { Ok(c) => c, Err(_) => return cmd.to_string() };
    let mut scored: Vec<(i32, String)> = Vec::new();
    for line in content.lines() {
        let w = line.trim();
        if w.is_empty() { continue; }
        let wl = w.to_lowercase();
        let mut best = 0;
        for t in &terms {
            if wl == *t { best = best.max(3); }
            else if wl.starts_with(t.as_str()) || t.starts_with(wl.as_str()) { best = best.max(2); }
            else if wl.contains(t.as_str()) || t.contains(wl.as_str()) { best = best.max(1); }
        }
        if best > 0 { scored.push((best, w.to_string())); }
    }
    // Not enough signal → keep the full list rather than over-narrowing.
    if scored.len() < 2 { return cmd.to_string(); }
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    let subset: Vec<String> = scored.into_iter().map(|(_, w)| w).collect();

    let outpath = "/tmp/farstyle_focused.txt";
    if std::fs::write(outpath, subset.join("\n")).is_err() { return cmd.to_string(); }
    let mut out: Vec<String> = toks.iter().map(|s| s.to_string()).collect();
    out[wi] = outpath.to_string();
    out.join(" ")
}

/// Map a free-text goal to the wordlist terms worth trying. Each group fires if
/// the goal mentions any of its triggers, contributing related path words.
fn intent_terms(goal: &str) -> Vec<String> {
    let g = goal.to_lowercase();
    let groups: &[(&[&str], &[&str])] = &[
        (&["login", "signin", "sign in", "log in", "logon", "auth", "authentication"],
         &["login", "log-in", "signin", "sign-in", "sign_in", "logon", "auth", "authenticate",
           "authentication", "account", "session", "sso", "oauth", "user", "users", "admin",
           "portal", "dashboard", "panel", "member", "members"]),
        (&["admin", "administrator", "backend", "panel", "dashboard", "manage"],
         &["admin", "administrator", "admin-panel", "adminpanel", "wp-admin", "manage",
           "manager", "management", "console", "panel", "backend", "cpanel", "dashboard"]),
        (&["upload", "attachment", "file upload"],
         &["upload", "uploads", "file", "files", "attachment", "attachments", "media", "import", "filemanager"]),
        (&["api", "endpoint", "rest", "graphql"],
         &["api", "v1", "v2", "v3", "rest", "graphql", "swagger", "openapi", "api-docs", "endpoint", "endpoints"]),
        (&["config", "configuration", "setting", "settings", "setup"],
         &["config", "configuration", "configs", "settings", "setting", "setup", "conf", "ini", "yaml", "yml"]),
        (&["env", ".env", "environment", "secret", "dotenv", "flag", "credential"],
         &[".env", "env", ".env.local", ".env.bak", "environment", "dotenv", "secret", "secrets",
           "config", ".git", "credentials", "creds", "flag"]),
        (&["backup", "old", "archive", "dump"],
         &["backup", "backups", "bak", ".bak", "old", "archive", "archives", "dump", ".sql", ".zip", ".tar"]),
        (&["user", "account", "profile", "member"],
         &["user", "users", "account", "accounts", "profile", "profiles", "member", "members"]),
        (&["debug", "dev", "test", "staging"],
         &["debug", "dev", "test", "testing", "staging", "stage", "sandbox", "beta"]),
    ];
    let mut terms: Vec<String> = Vec::new();
    for (triggers, expanded) in groups {
        if triggers.iter().any(|t| g.contains(t)) {
            for e in *expanded {
                if !terms.iter().any(|x| x == e) { terms.push((*e).to_string()); }
            }
        }
    }
    terms
}

pub enum WordlistCategory {
    CommonPaths,
    BigPaths,
    Subdomains,
    Parameters,
    Passwords,
    Usernames,
    Extensions,
    FuzzingPayloads,
}

impl WordlistCategory {
    pub fn name(&self) -> &'static str {
        match self {
            Self::CommonPaths     => "common_paths",
            Self::BigPaths        => "big_paths",
            Self::Subdomains      => "subdomains",
            Self::Parameters      => "parameters",
            Self::Passwords       => "passwords",
            Self::Usernames       => "usernames",
            Self::Extensions      => "extensions",
            Self::FuzzingPayloads => "fuzzing",
        }
    }

    fn candidates(&self) -> Vec<&'static str> {
        match self {
            Self::CommonPaths => vec![
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            ],
            Self::BigPaths => vec![
                "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
                "/opt/homebrew/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                "/usr/share/wordlists/dirb/big.txt",
            ],
            Self::Subdomains => vec![
                "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                "/opt/homebrew/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                "/usr/share/wordlists/subdomains.txt",
                "/usr/share/seclists/Discovery/DNS/namelist.txt",
            ],
            Self::Parameters => vec![
                "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
                "/opt/homebrew/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
                "/usr/share/seclists/Discovery/Web-Content/common-parameters.txt",
            ],
            Self::Passwords => vec![
                "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
                "/opt/homebrew/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
                "/usr/share/wordlists/rockyou.txt",
            ],
            Self::Usernames => vec![
                "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
                "/opt/homebrew/share/seclists/Usernames/top-usernames-shortlist.txt",
                "/usr/share/seclists/Usernames/Names/names.txt",
            ],
            Self::Extensions => vec![
                "/usr/share/seclists/Discovery/Web-Content/web-extensions.txt",
                "/opt/homebrew/share/seclists/Discovery/Web-Content/web-extensions.txt",
            ],
            Self::FuzzingPayloads => vec![
                "/usr/share/seclists/Fuzzing/special-chars.txt",
                "/opt/homebrew/share/seclists/Fuzzing/special-chars.txt",
                "/usr/share/seclists/Fuzzing/alphanum-case.txt",
            ],
        }
    }

    fn fallback_content(&self) -> &'static str {
        match self {
            Self::CommonPaths => "admin\nlogin\nbackup\napi\ntest\nconfig\nuploads\nstatic\nassets\njs\ncss\nphpinfo.php\nrobots.txt\n.env\nwp-admin\nwp-login.php",
            Self::BigPaths    => "admin\nlogin\napi\nv1\nv2\nbackup\nold\ndev\ntest\nstaging\ndashboard\npanel\nmanager\nconsole\nuploads\nfiles\ndownloads\ndata",
            Self::Subdomains  => "www\nmail\napi\ndev\nstaging\ntest\nadmin\nvpn\nftp\ncdn\nblog\nshop\napp\nm\nmobile\nportal\ndocs",
            Self::Parameters  => "id\npage\nq\nquery\nsearch\nurl\nfile\npath\ntoken\nkey\nname\ntype\naction\nview\nmode\nformat\nlang\nuser",
            Self::Passwords   => "123456\npassword\nadmin\n12345678\nqwerty\nletmein\nwelcome\nmonkey\ndragon\nmaster\npassword1\n1234567890",
            Self::Usernames   => "admin\nroot\nuser\ntest\nguest\ninfo\nweb\nsupport\nmaster\noperator\nservice",
            Self::Extensions  => ".php\n.asp\n.aspx\n.jsp\n.html\n.htm\n.txt\n.json\n.xml\n.bak\n.old\n.conf\n.config\n.log\n.sql\n.env",
            Self::FuzzingPayloads => "'\"\n<script>\n{{7*7}}\n${7*7}\n;ls\n|id\n&&id\n../\n../../\n%00\n%0a\nnull\nundefined",
        }
    }
}
