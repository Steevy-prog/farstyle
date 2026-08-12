use super::nmap::run_tool;

/// nuclei — fast vulnerability scanner using templates
/// Default: nuclei -u <target> -severity medium,high,critical -silent
pub fn run_nuclei(target: &str, extra_args: &[&str]) -> String {
    let args: Vec<&str> = if extra_args.is_empty() {
        vec!["-u", target, "-severity", "medium,high,critical", "-silent"]
    } else {
        extra_args.to_vec()
    };
    run_tool("nuclei", &args)
}

/// nuclei — specific template category (cves, exposures, misconfiguration…)
pub fn run_nuclei_tags(target: &str, tags: &str) -> String {
    run_tool("nuclei", &["-u", target, "-tags", tags, "-silent"])
}
