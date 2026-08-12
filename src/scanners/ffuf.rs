use super::nmap::run_tool;
use super::wordlists::{resolve, WordlistCategory};

/// ffuf — fast web fuzzer
/// Default: ffuf -u <target>/FUZZ -w <best_wordlist> -mc 200,301,302 -s
pub fn run_ffuf(target: &str, extra_args: &[&str]) -> String {
    if !extra_args.is_empty() {
        return run_tool("ffuf", extra_args);
    }
    let wordlist = resolve(WordlistCategory::CommonPaths);
    let fuzz_url = format!("{}/FUZZ", target.trim_end_matches('/'));
    let args = ["-u", fuzz_url.as_str(), "-w", wordlist.as_str(), "-mc", "200,301,302", "-s"];
    run_tool("ffuf", &args)
}
