use super::nmap::run_tool;
use super::wordlists::{resolve, WordlistCategory};

/// arjun — hidden GET/POST parameter discovery
/// Default: arjun -u <target> -w <best_parameter_wordlist>
pub fn run_arjun(target: &str, extra_args: &[&str]) -> String {
    if !extra_args.is_empty() {
        return run_tool("arjun", extra_args);
    }
    let wordlist = resolve(WordlistCategory::Parameters);
    run_tool("arjun", &["-u", target, "-w", wordlist.as_str()])
}

/// arjun — POST parameter discovery
pub fn run_arjun_post(target: &str) -> String {
    let wordlist = resolve(WordlistCategory::Parameters);
    run_tool("arjun", &["-u", target, "-m", "POST", "-w", wordlist.as_str()])
}

/// arjun — with a custom wordlist
pub fn run_arjun_wordlist(target: &str, wordlist: &str) -> String {
    run_tool("arjun", &["-u", target, "-w", wordlist])
}
