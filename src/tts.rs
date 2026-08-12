// Text-to-speech output — reads agent responses aloud via the OS speech
// synthesizer (macOS `say`). Optional, off by default. When on, the
// Workspace surfaces an explicit "🔊 Speaking…" status while a reply is
// being read so it's never ambiguous whether voice output actually fired.

use std::process::{Child, Command};

/// Default male English voice shipped with macOS.
pub const DEFAULT_VOICE: &str = "Daniel";

/// Spawn the OS TTS process to speak `text` with `voice`. Returns the child
/// handle so the caller can poll `try_wait()` to know when speech finishes,
/// or kill it to interrupt/replace with a newer reply.
pub fn speak(text: &str, voice: &str) -> Result<Child, String> {
    if text.trim().is_empty() {
        return Err("nothing to speak".into());
    }
    Command::new("say")
        .arg("-v")
        .arg(voice)
        .arg(text)
        .spawn()
        .map_err(|e| format!("failed to start `say` — voice output needs macOS: {e}"))
}

/// Strip markdown noise (code fences, headers, bullets, emphasis markers)
/// that reads badly aloud — e.g. "asterisk asterisk found colon" — so the
/// synthesizer gets clean prose instead of raw markdown. Also drops the
/// agent's internal monologue (REASON: lines, shell command echoes) so only
/// the actual answer gets read, not the scaffolding around it.
pub fn clean_for_speech(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_code_block = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_code_block = !in_code_block;
            continue;
        }
        let upper = trimmed.to_uppercase();
        if in_code_block
            || trimmed.starts_with("ACTION:")
            || upper.starts_with("REASON:")
            || trimmed.starts_with('$')
        {
            continue;
        }
        let cleaned = trimmed
            .trim_start_matches(['#', '-', '*', '>', '•'])
            .replace(['`', '*', '_'], "")
            .trim()
            .to_string();
        if !cleaned.is_empty() {
            out.push_str(&cleaned);
            out.push_str(". ");
        }
    }
    out
}
