// Raw-style HTTP send used by Repeater and Intruder.
// Uses ureq for simplicity and ergonomic synchronous sends.
// Raw-request parse/build helpers are part of this module's API surface and are
// not all wired into a caller yet.
#![allow(dead_code)]

use std::time::Instant;

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub elapsed_ms: u128,
    pub length: usize,
}

pub fn send(method: &str, url: &str, headers: &[(String, String)], body: &str) -> Result<HttpResponse, String> {
    let start = Instant::now();
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .build();

    let mut req = agent.request(method, url);
    for (k, v) in headers {
        let lk = k.to_lowercase();
        if lk == "content-length" || lk == "host" {
            continue; // ureq sets these
        }
        req = req.set(k, v);
    }

    let resp = if body.is_empty() {
        req.call()
    } else {
        req.send_string(body)
    };

    match resp {
        Ok(r) => {
            let status = r.status();
            let status_text = r.status_text().to_string();
            let headers: Vec<(String, String)> = r
                .headers_names()
                .iter()
                .map(|n| (n.clone(), r.header(n).unwrap_or("").to_string()))
                .collect();
            let body = r.into_string().unwrap_or_default();
            let length = body.len();
            Ok(HttpResponse {
                status,
                status_text,
                headers,
                body,
                elapsed_ms: start.elapsed().as_millis(),
                length,
            })
        }
        Err(ureq::Error::Status(code, r)) => {
            let status_text = r.status_text().to_string();
            let headers: Vec<(String, String)> = r
                .headers_names()
                .iter()
                .map(|n| (n.clone(), r.header(n).unwrap_or("").to_string()))
                .collect();
            let body = r.into_string().unwrap_or_default();
            let length = body.len();
            Ok(HttpResponse {
                status: code,
                status_text,
                headers,
                body,
                elapsed_ms: start.elapsed().as_millis(),
                length,
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

// Parse a raw HTTP request text (Burp-style) into method/url/headers/body
pub fn parse_raw_request(raw: &str, scheme_hint: &str) -> Result<(String, String, Vec<(String, String)>, String), String> {
    let mut parts = raw.split("\r\n\r\n");
    let head = parts.next().ok_or("empty request")?;
    let body = parts.next().unwrap_or("").to_string();

    let mut lines = head.split("\r\n");
    let first = lines.next().ok_or("missing request line")?;
    let mut iter = first.split_whitespace();
    let method = iter.next().ok_or("missing method")?.to_string();
    let path = iter.next().ok_or("missing path")?.to_string();

    let mut headers = Vec::new();
    let mut host = String::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_string();
            let v = v.trim().to_string();
            if k.eq_ignore_ascii_case("host") {
                host = v.clone();
            }
            headers.push((k, v));
        }
    }
    if host.is_empty() {
        return Err("missing Host header".into());
    }
    let scheme = if scheme_hint.is_empty() { "http" } else { scheme_hint };
    let url = if path.starts_with("http://") || path.starts_with("https://") {
        path
    } else {
        format!("{}://{}{}", scheme, host, path)
    };
    Ok((method, url, headers, body))
}

pub fn build_raw_request(method: &str, url: &str, headers: &[(String, String)], body: &str) -> String {
    let (path, host) = url_to_path_host(url);
    let mut s = format!("{} {} HTTP/1.1\r\n", method, path);
    let mut have_host = false;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("host") {
            have_host = true;
        }
        s.push_str(&format!("{}: {}\r\n", k, v));
    }
    if !have_host {
        s.push_str(&format!("Host: {}\r\n", host));
    }
    s.push_str("\r\n");
    s.push_str(body);
    s
}

fn url_to_path_host(url: &str) -> (String, String) {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    match rest.find('/') {
        Some(i) => (rest[i..].to_string(), rest[..i].to_string()),
        None => ("/".to_string(), rest.to_string()),
    }
}
