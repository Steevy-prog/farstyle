use super::nmap::run_tool;

/// tplmap — Server-Side Template Injection (SSTI) detection and exploitation
/// Default: tplmap -u <target>
pub fn run_tplmap(target: &str, extra_args: &[&str]) -> String {
    let args: Vec<&str> = if extra_args.is_empty() {
        vec!["-u", target]
    } else {
        extra_args.to_vec()
    };
    run_tool("tplmap", &args)
}

/// tplmap — test POST data for SSTI
pub fn run_tplmap_post(target: &str, data: &str) -> String {
    run_tool("tplmap", &["-u", target, "-d", data])
}
