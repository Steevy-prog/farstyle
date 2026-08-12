use super::nmap::run_tool;

/// nikto — web server vulnerability scanner
/// Default: nikto -h <target> -maxtime 60
pub fn run_nikto(target: &str, extra_args: &[&str]) -> String {
    let args: Vec<&str> = if extra_args.is_empty() {
        vec!["-h", target, "-maxtime", "60"]
    } else {
        extra_args.to_vec()
    };
    run_tool("nikto", &args)
}
