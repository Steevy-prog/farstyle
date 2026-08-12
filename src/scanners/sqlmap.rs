use super::nmap::run_tool;

/// sqlmap — automatic SQL injection detection and exploitation
/// Default: sqlmap -u <target> --batch --level 3 --risk 2
pub fn run_sqlmap(target: &str, extra_args: &[&str]) -> String {
    let args: Vec<&str> = if extra_args.is_empty() {
        vec!["-u", target, "--batch", "--level", "3", "--risk", "2"]
    } else {
        extra_args.to_vec()
    };
    run_tool("sqlmap", &args)
}
