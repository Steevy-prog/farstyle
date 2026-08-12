use super::nmap::run_tool;
use super::wordlists::{resolve, WordlistCategory};

/// gobuster — directory/file and subdomain brute-force
/// Default (dir mode): gobuster dir -u <target> -w <best_wordlist> -q
pub fn run_gobuster(target: &str, extra_args: &[&str]) -> String {
    if !extra_args.is_empty() {
        return run_tool("gobuster", extra_args);
    }
    let wordlist = resolve(WordlistCategory::CommonPaths);
    run_tool("gobuster", &["dir", "-u", target, "-w", wordlist.as_str(), "-q"])
}

/// gobuster DNS — subdomain enumeration
pub fn run_gobuster_dns(target: &str, wordlist: &str) -> String {
    let host = target
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(target);
    let wl = if wordlist.is_empty() {
        resolve(WordlistCategory::Subdomains)
    } else {
        wordlist.to_string()
    };
    run_tool("gobuster", &["dns", "-d", host, "-w", wl.as_str(), "-q"])
}
