// HTTP proxy with real intercept hold-and-release.
// - HTTP requests are captured; when intercept=true the handler thread blocks
//   until the UI calls forward_pending() or drop_pending().
// - HTTPS CONNECT is now fully MITM'd via tls_mitm: requests are decrypted,
//   intercepted, captured, and forwarded like plain HTTP.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;
use crate::tls_mitm;

/// Verdict set by the UI for a held request.
#[derive(Clone, PartialEq, Debug)]
pub enum Verdict {
    Pending,
    Forward,
    Drop,
}

#[derive(Clone, Debug)]
pub struct CapturedRequest {
    pub id: u64,
    pub method: String,
    pub url: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body: Vec<u8>,
    pub note: String,
}

pub struct ProxyState {
    pub running: bool,
    pub port: u16,
    pub captures: Vec<CapturedRequest>,
    pub intercept: bool,
    pub next_id: u64,
    pub last_error: Option<String>,
    /// Queue of requests held for intercept, each with a verdict.
    pub pending: Vec<(CapturedRequest, Verdict)>,
}

impl Default for ProxyState {
    fn default() -> Self {
        Self {
            running: false,
            port: 8000,
            captures: Vec::new(),
            intercept: false,
            next_id: 1,
            last_error: None,
            pending: Vec::new(),
        }
    }
}

/// `Arc<(Mutex<ProxyState>, Condvar)>` — the condvar is notified whenever the
/// UI sets a verdict so blocked handler threads wake up.
pub type SharedState = Arc<(Mutex<ProxyState>, Condvar)>;

pub fn new_state() -> SharedState {
    Arc::new((Mutex::new(ProxyState::default()), Condvar::new()))
}

/// Start the listener.  No-op if already running.
pub fn start(state: SharedState, port: u16) {
    {
        let (lock, _) = &*state;
        let mut s = lock.lock().unwrap();
        if s.running { return; }
        s.port = port;
        s.running = true;
        s.last_error = None;
    }
    let st = state.clone();
    thread::spawn(move || run_listener(st, port));
}

pub fn stop(state: &SharedState) {
    let (lock, cvar) = &**state;
    let mut s = lock.lock().unwrap();
    s.running = false;
    // Wake any blocked handler threads so they can exit
    cvar.notify_all();
}

// ─────────────────────────────────────────────────────────────────────────────
// macOS system proxy — point the OS HTTP/HTTPS proxy at our listener so the
// browser/system routes traffic through us, the same as ticking the boxes in
// System Settings → Network → Proxies. Returns the network service name on
// success (e.g. "Wi-Fi") so the UI can report exactly what was changed.
// ─────────────────────────────────────────────────────────────────────────────

/// Enable the macOS HTTP + HTTPS system proxy pointing at host:port.
#[cfg(target_os = "macos")]
pub fn set_system_proxy(host: &str, port: u16) -> Result<String, String> {
    let service = active_network_service()?;
    let p = port.to_string();
    run_networksetup(&["-setwebproxy", &service, host, &p])?;
    run_networksetup(&["-setsecurewebproxy", &service, host, &p])?;
    run_networksetup(&["-setwebproxystate", &service, "on"])?;
    run_networksetup(&["-setsecurewebproxystate", &service, "on"])?;
    Ok(service)
}

/// Disable the macOS HTTP + HTTPS system proxy.
#[cfg(target_os = "macos")]
pub fn clear_system_proxy() -> Result<String, String> {
    let service = active_network_service()?;
    run_networksetup(&["-setwebproxystate", &service, "off"])?;
    run_networksetup(&["-setsecurewebproxystate", &service, "off"])?;
    Ok(service)
}

#[cfg(target_os = "macos")]
fn run_networksetup(args: &[&str]) -> Result<(), String> {
    let out = std::process::Command::new("networksetup")
        .args(args)
        .output()
        .map_err(|e| format!("networksetup not available: {}", e))?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = if err.trim().is_empty() { String::from_utf8_lossy(&out.stdout).trim().to_string() }
                  else { err.trim().to_string() };
        Err(err)
    }
}

/// Resolve the network service (e.g. "Wi-Fi") backing the default route's
/// device (e.g. "en0"), so we configure the interface actually in use.
#[cfg(target_os = "macos")]
fn active_network_service() -> Result<String, String> {
    let route = std::process::Command::new("sh")
        .args(["-c", "route get default 2>/dev/null | awk '/interface:/{print $2}'"])
        .output().map_err(|e| e.to_string())?;
    let device = String::from_utf8_lossy(&route.stdout).trim().to_string();
    if device.is_empty() { return Err("no active network connection".into()); }

    // Map device → service name via the service-order listing. Blocks look like:
    //   (1) Wi-Fi
    //   (Hardware Port: Wi-Fi, Device: en0)
    let order = std::process::Command::new("networksetup")
        .arg("-listnetworkserviceorder")
        .output().map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&order.stdout);
    let mut last_service = String::new();
    for line in text.lines() {
        let l = line.trim();
        if l.contains("Hardware Port") {
            if l.contains(&format!("Device: {})", device)) && !last_service.is_empty() {
                return Ok(last_service.clone());
            }
        } else if let Some(rest) = l.strip_prefix('(') {
            if let Some(idx) = rest.find(')') {
                last_service = rest[idx + 1..].trim().to_string();
            }
        }
    }
    Err(format!("could not map device {} to a network service", device))
}

#[cfg(not(target_os = "macos"))]
pub fn set_system_proxy(_host: &str, _port: u16) -> Result<String, String> {
    Err("automatic system-proxy configuration is only supported on macOS".into())
}

#[cfg(not(target_os = "macos"))]
pub fn clear_system_proxy() -> Result<String, String> {
    Err("automatic system-proxy configuration is only supported on macOS".into())
}

/// UI calls this to forward the currently-held pending request (by id).
pub fn forward_pending(state: &SharedState, id: u64) {
    let (lock, cvar) = &**state;
    let mut s = lock.lock().unwrap();
    if let Some(entry) = s.pending.iter_mut().find(|(r, _)| r.id == id) {
        entry.1 = Verdict::Forward;
    }
    cvar.notify_all();
}

/// UI calls this to drop the currently-held pending request (by id).
pub fn drop_pending(state: &SharedState, id: u64) {
    let (lock, cvar) = &**state;
    let mut s = lock.lock().unwrap();
    if let Some(entry) = s.pending.iter_mut().find(|(r, _)| r.id == id) {
        entry.1 = Verdict::Drop;
    }
    cvar.notify_all();
}

/// UI calls this to forward ALL pending requests at once (intercept off).
pub fn forward_all_pending(state: &SharedState) {
    let (lock, cvar) = &**state;
    let mut s = lock.lock().unwrap();
    for (_, v) in s.pending.iter_mut() {
        if *v == Verdict::Pending { *v = Verdict::Forward; }
    }
    cvar.notify_all();
}

// ─── Listener loop ────────────────────────────────────────────────────────────

fn run_listener(state: SharedState, port: u16) {
    let addr = format!("127.0.0.1:{}", port);
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            let (lock, _) = &*state;
            let mut s = lock.lock().unwrap();
            s.running = false;
            s.last_error = Some(format!("bind {} failed: {}", addr, e));
            return;
        }
    };
    listener.set_nonblocking(true).ok();
    loop {
        {
            let (lock, _) = &*state;
            if !lock.lock().unwrap().running { break; }
        }
        match listener.accept() {
            Ok((client, _)) => {
                let st2 = state.clone();
                thread::spawn(move || handle_client(client, st2));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(30));
            }
            Err(e) => {
                let (lock, _) = &*state;
                lock.lock().unwrap().last_error = Some(format!("accept: {}", e));
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

// ─── Per-connection handler ────────────────────────────────────────────────────

fn read_until_double_crlf(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 1024];
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 { break; }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
        if buf.len() > 1024 * 1024 { break; }
    }
    Ok(buf)
}

fn parse_raw_headers(raw: &[u8]) -> Option<(Vec<String>, Vec<(String, String)>, usize)> {
    let pos = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let text = std::str::from_utf8(&raw[..pos]).ok()?;
    let mut lines = text.split("\r\n");
    let req_line: Vec<String> = lines.next()?.split_whitespace().map(|s| s.to_string()).collect();
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Some((req_line, headers, pos + 4))
}

fn handle_client(mut client: TcpStream, state: SharedState) {
    let raw = match read_until_double_crlf(&mut client) {
        Ok(b) => b,
        Err(_) => return,
    };
    let (req_line, headers, body_start) = match parse_raw_headers(&raw) {
        Some(v) => v,
        None => return,
    };
    if req_line.len() < 3 { return; }
    let method = req_line[0].clone();
    let target = req_line[1].clone();

    if method == "CONNECT" {
        handle_connect(client, target, headers, state);
        return;
    }

    // ── HTTP plain text ───────────────────────────────────────────────────────
    let (scheme, host, path) = match parse_absolute_url(&target) {
        Some(v) => v,
        None => return,
    };
    let port_num: u16 = if scheme == "https" { 443 } else { 80 };
    let upstream_addr = if host.contains(':') { host.clone() }
                        else { format!("{}:{}", host, port_num) };
    let body = if body_start < raw.len() { raw[body_start..].to_vec() } else { Vec::new() };
    let url = format!("{}://{}{}", scheme, host, path);

    // ── Intercept: hold in pending queue until UI makes a decision ────────────
    let should_intercept = {
        let (lock, _) = &*state;
        lock.lock().unwrap().intercept
    };

    // intercept_cap holds the original cap id if we went through intercept
    let mut intercept_cap: Option<CapturedRequest> = None;

    if should_intercept {
        let cap = {
            let (lock, _) = &*state;
            let mut s = lock.lock().unwrap();
            let id = s.next_id;
            s.next_id += 1;
            let c = CapturedRequest {
                id, method: method.clone(), url: url.clone(), host: host.clone(),
                headers: headers.clone(), body: body.clone(),
                status: 0, response_headers: Vec::new(), response_body: Vec::new(),
                note: "Intercepted — awaiting Forward/Drop".into(),
            };
            // Add to captures immediately so it shows in HTTP History tab right away
            s.captures.insert(0, c.clone());
            if s.captures.len() > 500 { s.captures.pop(); }
            s.pending.push((c.clone(), Verdict::Pending));
            c
        };

        // Block this thread until the UI sets a non-Pending verdict
        let verdict = {
            let (lock, cvar) = &*state;
            let mut s = lock.lock().unwrap();
            loop {
                if !s.running { return; }
                let entry = s.pending.iter().find(|(r, _)| r.id == cap.id);
                match entry.map(|(_, v)| v.clone()) {
                    Some(Verdict::Forward) | Some(Verdict::Drop) => {
                        let v = entry.map(|(_, v)| v.clone()).unwrap();
                        s.pending.retain(|(r, _)| r.id != cap.id);
                        break v;
                    }
                    _ => {}
                }
                s = cvar.wait(s).unwrap();
            }
        };

        if verdict == Verdict::Drop {
            let _ = client.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            // Update the existing captures entry to reflect the drop
            let (lock, _) = &*state;
            let mut s = lock.lock().unwrap();
            if let Some(entry) = s.captures.iter_mut().find(|c| c.id == cap.id) {
                entry.note = "Dropped by intercept".into();
            }
            return;
        }
        // Forwarding — remember cap so we reuse its id when saving the response
        intercept_cap = Some(cap);
    }

    // ── Forward request upstream ───────────────────────────────────────────────
    let mut fwd: Vec<u8> = Vec::new();
    fwd.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method, path).as_bytes());
    let mut have_host = false;
    for (k, v) in &headers {
        let lk = k.to_lowercase();
        if lk == "proxy-connection" || lk == "proxy-authorization" { continue; }
        if lk == "host" { have_host = true; }
        fwd.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
    }
    if !have_host { fwd.extend_from_slice(format!("Host: {}\r\n", host).as_bytes()); }
    fwd.extend_from_slice(b"Connection: close\r\n\r\n");
    fwd.extend_from_slice(&body);

    let mut upstream = match TcpStream::connect(&upstream_addr) {
        Ok(s) => s,
        Err(e) => {
            let _ = client.write_all(
                format!("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n{}", e).as_bytes(),
            );
            return;
        }
    };
    upstream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    if upstream.write_all(&fwd).is_err() { return; }

    let mut response = Vec::new();
    let _ = upstream.read_to_end(&mut response);
    let _ = client.write_all(&response);

    let (status, resp_headers, resp_body) = parse_response(&response);
    let (lock, _) = &*state;
    let mut s = lock.lock().unwrap();

    if let Some(ref cap) = intercept_cap {
        // Update the existing intercepted capture entry with the real response
        if let Some(entry) = s.captures.iter_mut().find(|c| c.id == cap.id) {
            entry.status = status;
            entry.response_headers = resp_headers;
            entry.response_body = resp_body;
            entry.note = String::new();
        }
    } else {
        // Non-intercepted path — insert a fresh capture entry
        let id = s.next_id;
        s.next_id += 1;
        s.captures.insert(0, CapturedRequest {
            id, method, url, host, headers, body, status,
            response_headers: resp_headers, response_body: resp_body, note: String::new(),
        });
        if s.captures.len() > 500 { s.captures.pop(); }
    }
}

fn handle_connect(client: TcpStream, target: String,
                  _headers: Vec<(String, String)>, state: SharedState) {
    // Parse host:port from CONNECT target
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(443)),
        None         => (target.clone(), 443),
    };

    // Attempt full TLS MITM
    let session = match tls_mitm::mitm_connect(client, &host, port) {
        Ok(s)  => s,
        Err(e) => {
            let (lock, _) = &*state;
            let mut s = lock.lock().unwrap();
            let id = s.next_id; s.next_id += 1;
            s.captures.insert(0, CapturedRequest {
                id, method: "CONNECT".into(),
                url: format!("https://{}", target), host: target.clone(),
                headers: Vec::new(), body: Vec::new(), status: 0,
                response_headers: Vec::new(),
                response_body: format!("TLS MITM failed: {}", e).into_bytes(),
                note: "MITM error".into(),
            });
            if s.captures.len() > 500 { s.captures.pop(); }
            return;
        }
    };

    // Now we have a decrypted request — run through normal HTTP intercept path
    let tls_mitm::MitmSession { request_bytes, mut client_tls, mut upstream_tls } = session;

    let (req_line, req_headers, body_start) = match parse_raw_headers(&request_bytes) {
        Some(v) => v,
        None => return,
    };
    if req_line.len() < 2 { return; }

    let method = req_line[0].clone();
    let path   = req_line[1].clone();
    let url    = format!("https://{}{}", host, path);
    let body   = if body_start < request_bytes.len() {
        request_bytes[body_start..].to_vec()
    } else { Vec::new() };

    // ── Intercept hold (same logic as plain HTTP) ─────────────────────────────
    let should_intercept = {
        let (lock, _) = &*state;
        lock.lock().unwrap().intercept
    };
    let mut intercept_cap: Option<CapturedRequest> = None;

    if should_intercept {
        let cap = {
            let (lock, _) = &*state;
            let mut s = lock.lock().unwrap();
            let id = s.next_id; s.next_id += 1;
            let c = CapturedRequest {
                id, method: method.clone(), url: url.clone(), host: host.clone(),
                headers: req_headers.clone(), body: body.clone(),
                status: 0, response_headers: Vec::new(), response_body: Vec::new(),
                note: "Intercepted HTTPS — awaiting Forward/Drop".into(),
            };
            s.captures.insert(0, c.clone());
            if s.captures.len() > 500 { s.captures.pop(); }
            s.pending.push((c.clone(), Verdict::Pending));
            c
        };
        let verdict = {
            let (lock, cvar) = &*state;
            let mut s = lock.lock().unwrap();
            loop {
                if !s.running { return; }
                let entry = s.pending.iter().find(|(r, _)| r.id == cap.id);
                match entry.map(|(_, v)| v.clone()) {
                    Some(Verdict::Forward) | Some(Verdict::Drop) => {
                        let v = entry.map(|(_, v)| v.clone()).unwrap();
                        s.pending.retain(|(r, _)| r.id != cap.id);
                        break v;
                    }
                    _ => {}
                }
                s = cvar.wait(s).unwrap();
            }
        };
        if verdict == Verdict::Drop {
            let _ = client_tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            let (lock, _) = &*state;
            let mut s = lock.lock().unwrap();
            if let Some(entry) = s.captures.iter_mut().find(|c| c.id == cap.id) {
                entry.note = "Dropped by intercept".into();
            }
            return;
        }
        intercept_cap = Some(cap);
    }

    // ── Forward request to upstream TLS ───────────────────────────────────────
    let mut fwd: Vec<u8> = Vec::new();
    fwd.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method, path).as_bytes());
    let mut have_host = false;
    for (k, v) in &req_headers {
        let lk = k.to_lowercase();
        if lk == "proxy-connection" || lk == "proxy-authorization" { continue; }
        if lk == "host" { have_host = true; }
        fwd.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
    }
    if !have_host { fwd.extend_from_slice(format!("Host: {}\r\n", host).as_bytes()); }
    fwd.extend_from_slice(b"Connection: close\r\n\r\n");
    fwd.extend_from_slice(&body);

    if upstream_tls.write_all(&fwd).is_err() { return; }

    // ── Read response from upstream, relay to client ──────────────────────────
    let mut response = Vec::new();
    let _ = upstream_tls.read_to_end(&mut response);
    let _ = client_tls.write_all(&response);

    let (status, resp_headers, resp_body) = parse_response(&response);
    let (lock, _) = &*state;
    let mut s = lock.lock().unwrap();

    if let Some(ref cap) = intercept_cap {
        if let Some(entry) = s.captures.iter_mut().find(|c| c.id == cap.id) {
            entry.status = status;
            entry.response_headers = resp_headers;
            entry.response_body = resp_body;
            entry.note = String::new();
        }
    } else {
        let id = s.next_id; s.next_id += 1;
        s.captures.insert(0, CapturedRequest {
            id, method, url, host, headers: req_headers, body, status,
            response_headers: resp_headers, response_body: resp_body, note: String::new(),
        });
        if s.captures.len() > 500 { s.captures.pop(); }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn parse_absolute_url(url: &str) -> Option<(String, String, String)> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("http://") { ("http", r) }
        else if let Some(r) = url.strip_prefix("https://") { ("https", r) }
        else { return None; };
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None     => (rest, "/"),
    };
    Some((scheme.to_string(), host.to_string(), path.to_string()))
}

fn parse_response(raw: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let pos = match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(p) => p,
        None => return (0, Vec::new(), raw.to_vec()),
    };
    let head = std::str::from_utf8(&raw[..pos]).unwrap_or("");
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next().unwrap_or("").split_whitespace()
        .nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let headers = lines.filter_map(|l| l.split_once(':')
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))).collect();
    (status, headers, raw[pos + 4..].to_vec())
}

#[allow(dead_code)] // header-normalisation helper kept for rule/script use
pub fn header_map(headers: &[(String, String)]) -> HashMap<String, String> {
    headers.iter().map(|(k, v)| (k.to_lowercase(), v.clone())).collect()
}
