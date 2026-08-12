use std::process::Command;

/// Run nmap with a custom args list. If args is empty, defaults to ["-sV", target].
/// Example args: ["-sV", "-p", "80,443", "--script", "vuln", "target.com"]
pub fn run_nmap(target: &str) -> String {
    run_nmap_args(target, &[])
}

pub fn run_nmap_args(target: &str, extra_args: &[&str]) -> String {
    let args: Vec<&str> = if extra_args.is_empty() {
        vec!["-sV", target]
    } else {
        let mut v: Vec<&str> = extra_args.to_vec();
        if !v.contains(&target) { v.push(target); }
        v
    };
    run_tool("nmap", &args)
}

pub fn run_tool(bin: &str, args: &[&str]) -> String {
    match Command::new(bin).args(args).output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            if stdout.is_empty() && !stderr.is_empty() { stderr } else { stdout }
        }
        Err(e) => format!("[!] Failed to run '{}': {}", bin, e),
    }
}