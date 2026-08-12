use super::nmap::run_tool;

/// gobuster — directory/subdomain brute-force
/// Default: gobuster dir -u <target> -w /usr/share/wordlists/dirb/common.txt
pub fn run_gobuster(target: &str, extra_args: &[&str]) -> String {
    let args: Vec<&str> = if extra_args.is_empty() {
        vec!["dir", "-u", target, "-w", "/usr/share/wordlists/dirb/common.txt", "-q"]
    } else {
        extra_args.to_vec()
    };
    run_tool("gobuster", &args)
}

/// ffuf — fast web fuzzer
/// Default: ffuf -u <target>/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302
pub fn run_ffuf(target: &str, extra_args: &[&str]) -> String {
    if !extra_args.is_empty() {
        return run_tool("ffuf", extra_args);
    }
    let fuzz_url = format!("{}/FUZZ", target);
    let args = ["-u", &fuzz_url, "-w", "/usr/share/wordlists/dirb/common.txt", "-mc", "200,301,302", "-s"];
    run_tool("ffuf", &args)
}

/// nuclei — vulnerability scanner with templates
/// Default: nuclei -u <target> -severity medium,high,critical
pub fn run_nuclei(target: &str, extra_args: &[&str]) -> String {
    let args: Vec<&str> = if extra_args.is_empty() {
        vec!["-u", target, "-severity", "medium,high,critical", "-silent"]
    } else {
        extra_args.to_vec()
    };
    run_tool("nuclei", &args)
}

/// sqlmap — SQL injection scanner
/// Default: sqlmap -u <target> --batch --level 3
pub fn run_sqlmap(target: &str, extra_args: &[&str]) -> String {
    let args: Vec<&str> = if extra_args.is_empty() {
        vec!["-u", target, "--batch", "--level", "3"]
    } else {
        extra_args.to_vec()
    };
    run_tool("sqlmap", &args)
}

/// nikto — web server vulnerability scanner
/// Default: nikto -h <target>
pub fn run_nikto(target: &str, extra_args: &[&str]) -> String {
    let args: Vec<&str> = if extra_args.is_empty() {
        vec!["-h", target]
    } else {
        extra_args.to_vec()
    };
    run_tool("nikto", &args)
}