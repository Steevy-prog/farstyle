use super::nmap::run_tool;

/// Identify web technologies. Default: whatweb -a 3 <target>
/// Extra args example: ["-a", "4", "--log-json", "/tmp/out.json"]
pub fn run_whatweb(target: &str, extra_args: &[&str]) -> String {
    let args: Vec<&str> = if extra_args.is_empty() {
        vec!["-a", "3", target]
    } else {
        let mut v = extra_args.to_vec();
        if !v.contains(&target) { v.push(target); }
        v
    };
    run_tool("whatweb", &args)
}