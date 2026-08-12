use super::nmap::run_tool;

/// linkfinder — extract endpoints/URLs hidden inside JavaScript files
/// Default: linkfinder -i <target> -o cli
pub fn run_linkfinder(target: &str, extra_args: &[&str]) -> String {
    let args: Vec<&str> = if extra_args.is_empty() {
        vec!["-i", target, "-o", "cli"]
    } else {
        extra_args.to_vec()
    };
    run_tool("linkfinder", &args)
}

/// linkfinder — crawl a domain and extract endpoints from all JS files
pub fn run_linkfinder_domain(target: &str) -> String {
    run_tool("linkfinder", &["-i", target, "-d", "-o", "cli"])
}
