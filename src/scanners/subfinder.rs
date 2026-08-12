use super::nmap::run_tool;

/// Subdomain enumeration. Default: subfinder -d <target> -silent
/// Extra args example: ["-d", "example.com", "-o", "/tmp/subs.txt", "-all"]
pub fn run_subfinder(target: &str, extra_args: &[&str]) -> String {
    let args: Vec<&str> = if extra_args.is_empty() {
        vec!["-d", target, "-silent"]
    } else {
        extra_args.to_vec()
    };
    run_tool("subfinder", &args)
}