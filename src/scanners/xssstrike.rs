use super::nmap::run_tool;

/// XSStrike XSS scanner. Default: xssstrike -u <target>
/// Extra args: ["-u", "https://example.com/page?q=test", "--crawl", "--blind"]
pub fn run_xssstrike(target: &str, extra_args: &[&str]) -> String {
    let args: Vec<&str> = if extra_args.is_empty() {
        vec!["-u", target]
    } else {
        extra_args.to_vec()
    };
    run_tool("xssstrike", &args)
}