use super::nmap::run_tool;

/// httpx — fast HTTP probing: status codes, titles, tech stack, redirects
/// Default: httpx -u <target> -status-code -title -tech-detect -silent
pub fn run_httpx(target: &str, extra_args: &[&str]) -> String {
    let args: Vec<&str> = if extra_args.is_empty() {
        vec!["-u", target, "-status-code", "-title", "-tech-detect", "-silent"]
    } else {
        extra_args.to_vec()
    };
    run_tool("httpx", &args)
}

/// httpx — probe a list of hosts from a file
pub fn run_httpx_list(list_path: &str) -> String {
    run_tool("httpx", &["-l", list_path, "-status-code", "-title", "-tech-detect", "-silent"])
}

/// httpx — probe with response body for content analysis
pub fn run_httpx_body(target: &str) -> String {
    run_tool("httpx", &["-u", target, "-status-code", "-title", "-tech-detect", "-response-body", "-silent"])
}
