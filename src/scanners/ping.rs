use super::nmap::run_tool;

/// ping — ICMP reachability and latency
/// Default: ping -c 4 <target>
pub fn run_ping(target: &str, extra_args: &[&str]) -> String {
    let host = target
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(target);
    let default = ["-c", "4", host];
    run_tool("ping", if extra_args.is_empty() { &default } else { extra_args })
}
