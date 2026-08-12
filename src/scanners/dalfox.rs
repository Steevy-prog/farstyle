use super::nmap::run_tool;

/// XSS scanner. Default: dalfox url <target>
/// Extra args example: ["url", "https://example.com/search?q=test", "--blind", "https://yourcollab.net"]
pub fn run_dalfox(target: &str, extra_args: &[&str]) -> String {
    let args: Vec<&str> = if extra_args.is_empty() {
        vec!["url", target]
    } else {
        extra_args.to_vec()
    };
    run_tool("dalfox", &args)
}