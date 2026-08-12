use super::nmap::run_tool;

/// katana — fast web crawler by ProjectDiscovery
/// Default: katana -u <target> -depth 2 -silent
pub fn run_katana(target: &str, extra_args: &[&str]) -> String {
    let args: Vec<&str> = if extra_args.is_empty() {
        vec!["-u", target, "-depth", "2", "-silent"]
    } else {
        extra_args.to_vec()
    };
    run_tool("katana", &args)
}
