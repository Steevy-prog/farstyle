/// Authenticated BFS web spider for FARSTYLE.
///
/// Crawls a target origin following href/src/action/form links.
/// Auth headers (Bearer + Cookie) are injected on every request.
/// Scope is enforced: only URLs whose host matches the seed host are crawled.
/// Results are streamed to the caller via an mpsc channel.

use std::collections::{HashSet, VecDeque};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct SpiderResult {
    pub url:         String,
    pub status:      u16,
    pub content_type: String,
    pub length:      usize,
    pub depth:       usize,
    pub links_found: usize,
    #[allow(dead_code)] // timing captured for reporting; not shown in the UI yet
    pub elapsed_ms:  u128,
    pub note:        String,
}

#[derive(Debug, Clone)]
pub struct SpiderConfig {
    pub seed_url:    String,
    pub max_depth:   usize,
    pub max_pages:   usize,
    pub delay_ms:    u64,
    pub bearer:      String,
    pub cookie:      String,
    pub user_agent:  String,
    pub follow_ext:  bool,   // follow links to .js/.css/.png etc.
    pub scope_strict: bool,  // only crawl same host
}

impl Default for SpiderConfig {
    fn default() -> Self {
        Self {
            seed_url:    String::new(),
            max_depth:   5,
            max_pages:   200,
            delay_ms:    100,
            bearer:      String::new(),
            cookie:      String::new(),
            user_agent:  "FarStyle-Spider/1.0".into(),
            follow_ext:  false,
            scope_strict: true,
        }
    }
}

/// Start spider in a background thread.  Returns a Receiver for results.
/// Send `true` on the returned stop channel to abort.
pub fn start(config: SpiderConfig) -> (Receiver<SpiderResult>, Sender<bool>) {
    let (result_tx, result_rx) = channel::<SpiderResult>();
    let (stop_tx, stop_rx)     = channel::<bool>();

    thread::spawn(move || run(config, result_tx, stop_rx));

    (result_rx, stop_tx)
}

fn run(cfg: SpiderConfig, tx: Sender<SpiderResult>, stop: Receiver<bool>) {
    let seed = match normalise_url(&cfg.seed_url) {
        Some(u) => u,
        None    => return,
    };
    let host = extract_host(&seed);

    let mut visited: HashSet<String> = HashSet::new();
    // (url, depth)
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    queue.push_back((seed, 0));

    let client = build_client(&cfg);
    let mut pages = 0usize;

    while let Some((url, depth)) = queue.pop_front() {
        // Check stop signal
        if stop.try_recv().is_ok() { break; }
        if visited.contains(&url) { continue; }
        if pages >= cfg.max_pages  { break; }
        if depth  > cfg.max_depth  { continue; }

        visited.insert(url.clone());
        pages += 1;

        if cfg.delay_ms > 0 {
            thread::sleep(Duration::from_millis(cfg.delay_ms));
        }

        let t0 = Instant::now();
        let (status, ct, body, note) = fetch(&client, &url, &cfg);
        let elapsed = t0.elapsed().as_millis();

        // Extract links
        let links = extract_links(&body, &url);
        let new_links: Vec<String> = links.iter()
            .filter(|l| {
                let l_host = extract_host(l);
                if cfg.scope_strict && l_host != host { return false; }
                if !cfg.follow_ext && is_static_ext(l) { return false; }
                !visited.contains(*l)
            })
            .cloned()
            .collect();

        let found = new_links.len();
        for link in new_links {
            if !visited.contains(&link) {
                queue.push_back((link, depth + 1));
            }
        }

        let result = SpiderResult {
            url: url.clone(),
            status,
            content_type: ct,
            length: body.len(),
            depth,
            links_found: found,
            elapsed_ms: elapsed,
            note,
        };

        if tx.send(result).is_err() { break; }
    }
}

// ── HTTP fetch ────────────────────────────────────────────────────────────────

struct SimpleClient {
    bearer:     String,
    cookie:     String,
    user_agent: String,
}

fn build_client(cfg: &SpiderConfig) -> SimpleClient {
    SimpleClient {
        bearer:     cfg.bearer.clone(),
        cookie:     cfg.cookie.clone(),
        user_agent: cfg.user_agent.clone(),
    }
}

fn fetch(client: &SimpleClient, url: &str, _cfg: &SpiderConfig) -> (u16, String, String, String) {
    let mut req = ureq::get(url)
        .set("User-Agent", &client.user_agent)
        .set("Accept", "text/html,application/xhtml+xml,*/*");

    if !client.bearer.is_empty() {
        req = req.set("Authorization", &format!("Bearer {}", client.bearer.trim()));
    }
    if !client.cookie.is_empty() {
        req = req.set("Cookie", client.cookie.trim());
    }

    match req.call() {
        Ok(resp) => {
            let status = resp.status();
            let ct = resp.content_type().to_string();
            let body = resp.into_string().unwrap_or_default();
            (status, ct, body, String::new())
        }
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            (code, String::new(), body, String::new())
        }
        Err(e) => (0, String::new(), String::new(), e.to_string()),
    }
}

// ── Link extraction ───────────────────────────────────────────────────────────

fn extract_links(html: &str, base: &str) -> Vec<String> {
    let mut links = Vec::new();
    let base_origin = extract_origin(base);

    // Scan for href="..." src="..." action="..."
    for attr in &["href", "src", "action"] {
        let needle = format!("{}=\"", attr);
        let mut pos = 0;
        while let Some(start) = html[pos..].find(&needle) {
            let abs = pos + start + needle.len();
            if abs >= html.len() { break; }
            if let Some(end) = html[abs..].find('"') {
                let raw = &html[abs..abs + end];
                if let Some(resolved) = resolve_url(raw, base, &base_origin) {
                    if !links.contains(&resolved) {
                        links.push(resolved);
                    }
                }
                pos = abs + end + 1;
            } else { break; }
        }
    }
    links
}

fn resolve_url(raw: &str, base: &str, base_origin: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.starts_with('#') || raw.starts_with("javascript:") || raw.starts_with("mailto:") {
        return None;
    }
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return Some(raw.to_string());
    }
    if raw.starts_with("//") {
        let scheme = if base.starts_with("https") { "https:" } else { "http:" };
        return Some(format!("{}{}", scheme, raw));
    }
    if raw.starts_with('/') {
        return Some(format!("{}{}", base_origin, raw));
    }
    // Relative
    let base_dir = base.rfind('/').map(|i| &base[..i]).unwrap_or(base);
    Some(format!("{}/{}", base_dir, raw))
}

// ── URL helpers ───────────────────────────────────────────────────────────────

fn normalise_url(url: &str) -> Option<String> {
    let u = url.trim();
    if u.starts_with("http://") || u.starts_with("https://") {
        Some(u.to_string())
    } else if !u.is_empty() {
        Some(format!("http://{}", u))
    } else {
        None
    }
}

fn extract_host(url: &str) -> String {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    rest.split('/').next().unwrap_or("").split('?').next().unwrap_or("").to_string()
}

fn extract_origin(url: &str) -> String {
    let scheme = if url.starts_with("https") { "https://" } else { "http://" };
    format!("{}{}", scheme, extract_host(url))
}

fn is_static_ext(url: &str) -> bool {
    let path = url.split('?').next().unwrap_or(url).to_lowercase();
    matches!(
        path.rsplit('.').next().unwrap_or(""),
        "png" | "jpg" | "jpeg" | "gif" | "svg" | "ico" | "webp" |
        "css" | "woff" | "woff2" | "ttf" | "eot" | "otf" |
        "mp4" | "mp3" | "avi" | "mov" | "pdf" | "zip" | "gz"
    )
}
