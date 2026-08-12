use super::nmap::run_tool;

/// curl — HTTP client for headers, status codes, body, etc.
/// Default (HEAD): curl -sI --max-time 15 <target>
pub fn run_curl(target: &str, extra_args: &[&str]) -> String {
    let default = ["-sI", "--max-time", "15", target];
    run_tool("curl", if extra_args.is_empty() { &default } else { extra_args })
}

/// curl GET — fetch full response body
/// Default: curl -s --max-time 15 <target>
pub fn run_curl_get(target: &str, extra_args: &[&str]) -> String {
    let default = ["-s", "--max-time", "15", target];
    run_tool("curl", if extra_args.is_empty() { &default } else { extra_args })
}

/// curl — just status code
/// curl -s -o /dev/null -w "%{http_code}" <target>
pub fn run_curl_status(target: &str) -> String {
    run_tool("curl", &["-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15", target])
}
