use super::nmap::run_tool;

/// whois — domain registration info, registrar, contacts, nameservers
/// Default: whois <target>
pub fn run_whois(target: &str, extra_args: &[&str]) -> String {
    let domain = target
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(target);
    let default = [domain];
    run_tool("whois", if extra_args.is_empty() { &default } else { extra_args })
}
