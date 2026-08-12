use super::nmap::run_tool;

/// dig — DNS lookup (A, MX, NS, TXT records, etc.)
/// Default: dig <target> ANY +noall +answer
pub fn run_dig(target: &str, extra_args: &[&str]) -> String {
    let host = target
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(target);
    let default = [host, "ANY", "+noall", "+answer"];
    run_tool("dig", if extra_args.is_empty() { &default } else { extra_args })
}

/// dig — specific record type (A, MX, NS, TXT, CNAME…)
pub fn run_dig_record(target: &str, record_type: &str) -> String {
    let host = target
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(target);
    run_tool("dig", &[host, record_type, "+short"])
}
