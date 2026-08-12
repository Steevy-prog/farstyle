use crate::scanners::{
    nmap::run_nmap_args,
    curl::{run_curl, run_curl_get},
    whois::run_whois,
    ping::run_ping,
    dig::run_dig,
    whatweb::run_whatweb,
    subfinder::run_subfinder,
    dalfox::run_dalfox,
    xssstrike::run_xssstrike,
    gobuster::run_gobuster,
    ffuf::run_ffuf,
    nuclei::run_nuclei,
    sqlmap::run_sqlmap,
    nikto::run_nikto,
    katana::run_katana,
    httpx::run_httpx,
    linkfinder::run_linkfinder,
    arjun::run_arjun,
    tplmap::run_tplmap,
};
use std::process::Command;

/// Execute any tool by name with a full args list.
/// `target` is the primary target (host/URL).
/// `args` overrides the default flags — pass empty slice for sensible defaults.
///
/// Tool names:
///   nmap, curl, curl_get, curl_status, whois, ping, dig,
///   whatweb, subfinder, dalfox, xssstrike,
///   gobuster, ffuf, nuclei, sqlmap, nikto, katana
pub fn execute_tool(name: &str, target: &str, args: &[&str]) -> String {
    if !tool_available(bin_for(name)) {
        return format!("[!] '{}' is not installed on this system.", bin_for(name));
    }
    match name {
        "nmap"        => run_nmap_args(target, args),
        "curl"        => run_curl(target, args),
        "curl_get"    => run_curl_get(target, args),
        "curl_status" => crate::scanners::curl::run_curl_status(target),
        "whois"       => run_whois(target, args),
        "ping"        => run_ping(target, args),
        "dig"         => run_dig(target, args),
        "whatweb"     => run_whatweb(target, args),
        "subfinder"   => run_subfinder(target, args),
        "dalfox"      => run_dalfox(target, args),
        "xssstrike"   => run_xssstrike(target, args),
        "gobuster"    => run_gobuster(target, args),
        "ffuf"        => run_ffuf(target, args),
        "nuclei"      => run_nuclei(target, args),
        "sqlmap"      => run_sqlmap(target, args),
        "nikto"       => run_nikto(target, args),
        "katana"      => run_katana(target, args),
        "httpx"       => run_httpx(target, args),
        "linkfinder"  => run_linkfinder(target, args),
        "arjun"       => run_arjun(target, args),
        "tplmap"      => run_tplmap(target, args),
        _ => format!(
            "Unknown tool '{}'. Available: nmap, curl, curl_get, curl_status, whois, ping, dig, \
             whatweb, subfinder, dalfox, xssstrike, gobuster, ffuf, nuclei, sqlmap, nikto, katana, \
             httpx, linkfinder, arjun, tplmap",
            name
        ),
    }
}

/// Map tool alias → binary name for availability check
fn bin_for(name: &str) -> &str {
    match name {
        "nmap"                          => "nmap",
        "curl" | "curl_get" | "curl_status" => "curl",
        "whois"                         => "whois",
        "ping"                          => "ping",
        "dig"                           => "dig",
        "whatweb"                       => "whatweb",
        "subfinder"                     => "subfinder",
        "dalfox"                        => "dalfox",
        "xssstrike"                     => "xssstrike",
        "gobuster"                      => "gobuster",
        "ffuf"                          => "ffuf",
        "nuclei"                        => "nuclei",
        "sqlmap"                        => "sqlmap",
        "nikto"                         => "nikto",
        "katana"                        => "katana",
        "httpx"                         => "httpx",
        "linkfinder"                    => "linkfinder",
        "arjun"                         => "arjun",
        "tplmap"                        => "tplmap",
        other                           => other,
    }
}

/// Run `tool -h` (or `--help`) and return its help text, capped at 2000 chars.
/// Tries `-h` first, then `--help` if that fails or produces nothing.
pub fn tool_help(name: &str) -> String {
    let bin = bin_for(name);
    if !tool_available(bin) {
        return format!("[!] '{}' is not installed.", bin);
    }
    for flag in &["-h", "--help"] {
        let out = Command::new(bin)
            .arg(flag)
            .output();
        if let Ok(o) = out {
            // Many tools print help to stderr
            let text = if o.stdout.is_empty() {
                String::from_utf8_lossy(&o.stderr).to_string()
            } else {
                String::from_utf8_lossy(&o.stdout).to_string()
            };
            let text = text.trim().to_string();
            if !text.is_empty() {
                return if text.len() > 2000 {
                    format!("{}[...truncated]", &text[..2000])
                } else {
                    text
                };
            }
        }
    }
    format!("No help text available for '{}'.", bin)
}

/// Patch commands that classically run forever so they self-terminate:
/// `ping` with no count pings until killed; `curl` against an unresponsive
/// host can hang indefinitely. This makes "test connectivity" actually return.
fn guard_hang(cmd: &str) -> String {
    let first = cmd.split_whitespace().next().unwrap_or("");
    match first {
        "ping" if !cmd.contains(" -c") =>
            cmd.replacen("ping", "ping -c 4", 1),
        "curl" if !cmd.contains("--max-time") && !cmd.contains(" -m ") =>
            format!("{} --max-time 20", cmd),
        _ => cmd.to_string(),
    }
}

/// Execute a raw command string via sh -c so quoted args and pipes work
/// correctly. Hardened with a hard timeout: a hung command (e.g. ping with no
/// count, or an unresponsive host) is killed instead of blocking the agent
/// forever. The child runs in its own process group so we can kill any
/// sub-processes it spawned too.
pub fn run_raw(cmd_line: &str) -> String {
    let cmd_line = cmd_line.trim();
    if cmd_line.is_empty() { return "Empty command.".to_string(); }
    let cmd_line = guard_hang(cmd_line);

    // Scanners legitimately take a while; quick tools should never linger.
    let first = cmd_line.split_whitespace().next().unwrap_or("");
    let timeout = match first {
        "ffuf" | "gobuster" | "nmap" | "nuclei" | "sqlmap" | "nikto"
        | "hydra" | "feroxbuster" | "wfuzz" | "katana" | "subfinder"
            => std::time::Duration::from_secs(180),
        _   => std::time::Duration::from_secs(30),
    };

    let mut command = Command::new("sh");
    command.args(["-c", cmd_line.as_str()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // Own process group → killing -pid reaps the whole tree, not just sh.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);

    let child = match command.spawn() {
        Ok(c) => c,
        Err(e) => return format!("Failed to run '{}': {}", cmd_line, e),
    };
    let pid = child.id();

    // Read on a thread so a full pipe buffer can't deadlock the wait.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || { let _ = tx.send(child.wait_with_output()); });

    match rx.recv_timeout(timeout) {
        Ok(Ok(o)) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            let combined = if stdout.trim().is_empty() { stderr } else { stdout };
            let combined = combined.trim().to_string();
            if combined.is_empty() {
                format!("(no output — command exited cleanly: {})", cmd_line)
            } else if combined.len() > 3000 {
                format!("{}[...truncated]", &combined[..3000])
            } else {
                combined
            }
        }
        Ok(Err(e)) => format!("Failed to run '{}': {}", cmd_line, e),
        Err(_) => {
            // Timed out — kill the whole process group (TERM then KILL).
            #[cfg(unix)]
            {
                let _ = Command::new("kill").arg("-TERM").arg(format!("-{}", pid)).status();
                std::thread::sleep(std::time::Duration::from_millis(200));
                let _ = Command::new("kill").arg("-KILL").arg(format!("-{}", pid)).status();
            }
            format!("⏱ Timed out after {}s and was killed — the command hung (unresponsive host, or a tool with no built-in limit). Command: {}",
                timeout.as_secs(), cmd_line)
        }
    }
}

/// Check if a binary exists on PATH
pub fn tool_available(name: &str) -> bool {
    Command::new("which").arg(name).output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// List all tools with availability status
#[allow(dead_code)] // tool-availability probe retained for prompt building / future use
pub fn available_tools() -> Vec<(&'static str, bool)> {
    vec![
        ("nmap",      tool_available("nmap")),
        ("curl",      tool_available("curl")),
        ("whois",     tool_available("whois")),
        ("ping",      tool_available("ping")),
        ("dig",       tool_available("dig")),
        ("whatweb",   tool_available("whatweb")),
        ("subfinder", tool_available("subfinder")),
        ("dalfox",    tool_available("dalfox")),
        ("xssstrike", tool_available("xssstrike")),
        ("gobuster",  tool_available("gobuster")),
        ("ffuf",      tool_available("ffuf")),
        ("nuclei",    tool_available("nuclei")),
        ("sqlmap",    tool_available("sqlmap")),
        ("nikto",     tool_available("nikto")),
        ("katana",      tool_available("katana")),
        ("httpx",       tool_available("httpx")),
        ("linkfinder",  tool_available("linkfinder")),
        ("arjun",       tool_available("arjun")),
        ("tplmap",      tool_available("tplmap")),
    ]
}