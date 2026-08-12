mod gui;
// External-tool wrappers (nmap, sqlmap, nuclei, ffuf, gobuster, …). The AI
// executor dispatches a dynamic subset of these by name at runtime, so not every
// wrapper is statically referenced — the unused ones are the integration surface.
#[allow(dead_code)]
mod scanners;
mod utils;
mod proxy;
mod tls_mitm;
mod spider;
// Passive traffic analyser — retired from the UI; kept as a library for the
// proxy capture hook to re-enable later without re-implementing the ruleset.
#[allow(dead_code)]
mod passive_scan;
mod scripting;
mod crypto;
mod httpx;
mod ai;
mod knowledge;
mod config;
mod engagement;
mod vulnstore;
mod report_pdf;
mod voice;
mod tts;
pub mod modules;

fn main() -> Result<(), eframe::Error> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls ring crypto provider");
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("FarStyle"),
        ..Default::default()
    };

    eframe::run_native(
        "FarStyle",
        options,
        Box::new(|_cc| {
            Ok(Box::new(gui::NullForgeApp::new()))
        }),
    )
}
