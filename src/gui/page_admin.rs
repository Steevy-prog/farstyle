// Admin pages: Modules manager, Settings, Knowledge Base and About.
// Split out of the GUI monolith; see gui/mod.rs.

use super::*;

impl NullForgeApp {
    pub(crate) fn page_modules(&mut self, ui: &mut Ui) {
        use egui::{Frame, Margin, RichText, Color32, Layout, Align};

        // ── header ───────────────────────────────────────────────────────────
        ui.horizontal(|ui| {
            ui.label(RichText::new("🧩 MODULES").size(18.0).strong().color(ACCENT));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                // Upload Python module
                if ui.add(
                    egui::Button::new(RichText::new("⬆ Upload Python").size(11.0).color(Color32::from_rgb(80, 200, 100)))
                        .fill(Color32::from_rgb(10, 28, 14))
                        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(30, 120, 50)))
                        .corner_radius(4.0)
                ).clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Python module", &["py"])
                        .pick_file()
                    {
                        if let Ok(src) = std::fs::read_to_string(&path) {
                            let fname = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                            let name = fname.trim_end_matches(".py").to_string();
                            // Copy to modules/python/ for persistence
                            let dest_dir = std::path::PathBuf::from("modules/python");
                            let _ = std::fs::create_dir_all(&dest_dir);
                            let dest = dest_dir.join(&fname);
                            let _ = std::fs::copy(&path, &dest);
                            if self.user_modules.iter().any(|m| m.file_name == fname) {
                                // update existing
                                if let Some(m) = self.user_modules.iter_mut().find(|m| m.file_name == fname) {
                                    m.source = src.clone();
                                    m.status = ModuleStatus::Ready;
                                }
                            } else {
                                self.user_modules.push(UserModule {
                                    name: name.clone(),
                                    description: "Uploaded Python module".into(),
                                    category: "Custom".into(),
                                    runtime: ModuleRuntime::Python,
                                    source: src,
                                    file_name: fname,
                                    status: ModuleStatus::Ready,
                                    last_output: String::new(),
                                    enabled: false,
                                    ai_validated: false,
                                });
                                self.module_selected = Some(self.user_modules.len() - 1);
                            }
                            self.push_toast(format!("Module '{}' saved — run Analyse Module to validate", name), Color32::from_rgb(200, 160, 30));
                        }
                    }
                }
                ui.add_space(6.0);
                // Upload Rust module
                if ui.add(
                    egui::Button::new(RichText::new("⬆ Upload Rust").size(11.0).color(Color32::from_rgb(255, 130, 80)))
                        .fill(Color32::from_rgb(28, 14, 10))
                        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(120, 50, 30)))
                        .corner_radius(4.0)
                ).clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Rust module", &["rs"])
                        .pick_file()
                    {
                        if let Ok(src) = std::fs::read_to_string(&path) {
                            let fname = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                            let name = fname.trim_end_matches(".rs").to_string();
                            // Copy to modules/rust/ for persistence
                            let dest_dir = std::path::PathBuf::from("modules/rust");
                            let _ = std::fs::create_dir_all(&dest_dir);
                            let dest = dest_dir.join(&fname);
                            let _ = std::fs::copy(&path, &dest);
                            if self.user_modules.iter().any(|m| m.file_name == fname) {
                                if let Some(m) = self.user_modules.iter_mut().find(|m| m.file_name == fname) {
                                    m.source = src.clone();
                                    m.status = ModuleStatus::Ready;
                                }
                            } else {
                                self.user_modules.push(UserModule {
                                    name: name.clone(),
                                    description: "Uploaded Rust module".into(),
                                    category: "Custom".into(),
                                    runtime: ModuleRuntime::Rust,
                                    source: src,
                                    file_name: fname,
                                    status: ModuleStatus::Ready,
                                    last_output: String::new(),
                                    enabled: false,
                                    ai_validated: false,
                                });
                                self.module_selected = Some(self.user_modules.len() - 1);
                            }
                            self.push_toast(format!("Module '{}' saved — run Analyse Module to validate", name), Color32::from_rgb(200, 160, 30));
                        }
                    }
                }
            });
        });

        ui.add_space(10.0);

        ScrollArea::vertical().id_salt("modules_page").auto_shrink([false, false]).show(ui, |ui| {

        // ── Built-in modules from architecture ───────────────────────────────
        let builtin = [
            ("recon.http_probe",  "HTTP Probe",           "Reconnaissance", "Rust",   "Probes URLs: status, headers, server banner"),
            ("fuzz.dir_fuzz",     "Directory Fuzzer",     "Fuzzing",        "Rust",   "Fuzzes web paths using ffuf"),
            ("exploit.sqli",      "SQL Injection Exploit","Exploit",        "Python", "SQLi detection via sqlmap IPC"),
        ];

        ui.label(RichText::new("Built-in Modules").size(12.0).strong().color(TEXT_MUTED));
        ui.add_space(4.0);

        for (id, name, cat, runtime, desc) in &builtin {
            let rt_color = if *runtime == "Rust" { Color32::from_rgb(255, 100, 60) } else { Color32::from_rgb(80, 180, 100) };
            Frame::NONE
                .fill(Color32::from_rgb(14, 20, 30))
                .stroke(egui::Stroke::new(1.0, Color32::from_rgb(35, 50, 70)))
                .corner_radius(6.0)
                .inner_margin(Margin::same(10))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(*name).size(13.0).strong().color(TEXT_PRIMARY));
                        ui.label(RichText::new(format!("[{}]", runtime)).size(10.0).color(rt_color));
                        ui.label(RichText::new(format!("— {}", cat)).size(10.0).color(TEXT_MUTED));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(RichText::new("● Ready").size(10.0).color(Color32::from_rgb(50, 200, 100)));
                        });
                    });
                    ui.label(RichText::new(format!("ID: {}  •  {}", id, desc)).size(10.0).color(TEXT_MUTED));
                });
            ui.add_space(4.0);
        }

        // ── User-uploaded modules ─────────────────────────────────────────────
        if !self.user_modules.is_empty() {
            ui.add_space(8.0);
            ui.label(RichText::new("Uploaded Modules").size(12.0).strong().color(TEXT_MUTED));
            ui.add_space(4.0);

            let count = self.user_modules.len();
            for i in 0..count {
                let is_sel = self.module_selected == Some(i);
                let (name, cat, rt_label, rt_color, status_label, status_color) = {
                    let m = &self.user_modules[i];
                    (m.name.clone(), m.category.clone(), m.runtime.label().to_string(),
                     m.runtime.color(), m.status.label().to_string(), m.status.color())
                };

                let border = if is_sel { ACCENT } else { Color32::from_rgb(35, 50, 70) };
                let bg = if is_sel { Color32::from_rgb(10, 28, 20) } else { Color32::from_rgb(14, 20, 30) };

                let resp = Frame::NONE
                    .fill(bg)
                    .stroke(egui::Stroke::new(1.0, border))
                    .corner_radius(6.0)
                    .inner_margin(Margin::same(10))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&name).size(13.0).strong().color(TEXT_PRIMARY));
                            ui.label(RichText::new(format!("[{}]", rt_label)).size(10.0).color(rt_color));
                            ui.label(RichText::new(format!("— {}", cat)).size(10.0).color(TEXT_MUTED));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.add(
                                    egui::Button::new(RichText::new("🗑").size(11.0))
                                        .fill(Color32::TRANSPARENT)
                                ).on_hover_text("Remove module").clicked() {
                                    // mark for removal
                                    self.user_modules[i].status = ModuleStatus::Error("__REMOVE__".into());
                                }
                                ui.label(RichText::new(format!("● {}", status_label)).size(10.0).color(status_color));
                            });
                        });
                    });

                if resp.response.clicked() {
                    self.module_selected = Some(i);
                }
                ui.add_space(4.0);
            }

            // remove marked modules
            self.user_modules.retain(|m| !matches!(&m.status, ModuleStatus::Error(e) if e == "__REMOVE__"));
            // fix selected index after removal
            if let Some(sel) = self.module_selected {
                if sel >= self.user_modules.len() {
                    self.module_selected = if self.user_modules.is_empty() { None } else { Some(self.user_modules.len() - 1) };
                }
            }
        }

        // ── Module detail + tester ────────────────────────────────────────────
        if let Some(idx) = self.module_selected {
            if idx < self.user_modules.len() {
                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);

                let (name, runtime, source, file_name) = {
                    let m = &self.user_modules[idx];
                    let dir = match m.runtime { ModuleRuntime::Python => "modules/python", ModuleRuntime::Rust => "modules/rust" };
                    // Always read from disk so we use the latest saved version
                    let disk_src = std::fs::read_to_string(std::path::PathBuf::from(dir).join(&m.file_name)).unwrap_or_else(|_| m.source.clone());
                    (m.name.clone(), m.runtime.clone(), disk_src, m.file_name.clone())
                };

                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("Module: {}", name)).size(14.0).strong().color(ACCENT));
                    ui.label(RichText::new(&file_name).size(10.0).color(TEXT_MUTED));
                });
                ui.add_space(6.0);

                // Source preview
                ui.label(RichText::new("Source").size(11.0).color(TEXT_MUTED));
                ScrollArea::vertical().id_salt("mod_source_preview").max_height(180.0).show(ui, |ui| {
                    Frame::NONE
                        .fill(Color32::from_rgb(10, 14, 22))
                        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(30, 45, 65)))
                        .corner_radius(4.0)
                        .inner_margin(Margin::same(8))
                        .show(ui, |ui| {
                            ui.label(RichText::new(&source).size(10.0).color(Color32::from_rgb(160, 220, 160)).monospace());
                        });
                });

                ui.add_space(8.0);
                ui.label(RichText::new("Module Tester").size(11.0).color(TEXT_MUTED));
                ui.label(RichText::new("Send a JSON payload (ExecutionContext) to test the module:").size(10.0).color(TEXT_MUTED));

                let test_hint = r#"{"run_id":"test-001","target":"https://example.com","config":{},"timeout_secs":30}"#;
                let mut input_buf = self.module_test_input.clone();
                if ui.add(
                    egui::TextEdit::multiline(&mut input_buf)
                        .hint_text(test_hint)
                        .desired_rows(3)
                        .font(egui::FontId::monospace(11.0))
                        .desired_width(f32::INFINITY)
                        .text_color(TEXT_PRIMARY)
                ).changed() {
                    self.module_test_input = input_buf;
                }

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let busy = self.module_test_busy;
                    if !busy {
                        if ui.add(
                            egui::Button::new(RichText::new("▶ Run Test").size(11.0).color(Color32::WHITE))
                                .fill(Color32::from_rgb(30, 100, 50))
                                .corner_radius(4.0)
                        ).clicked() {
                            let input = if self.module_test_input.trim().is_empty() {
                                format!(r#"{{"run_id":"test-001","target":"{}","config":{{}},"timeout_secs":30}}"#, self.target)
                            } else {
                                self.module_test_input.clone()
                            };

                            let source_c = source.clone();
                            let runtime_c = runtime.clone();
                            let file_name_c = file_name.clone();
                            let (tx, rx) = std::sync::mpsc::channel();
                            self.module_test_receiver = Some(rx);
                            self.module_test_busy = true;
                            self.module_test_output = "Running...".into();
                            self.user_modules[idx].status = ModuleStatus::Testing;

                            std::thread::spawn(move || {
                                let result = match runtime_c {
                                    ModuleRuntime::Python => {
                                        // Write source to temp file and execute with context via stdin
                                        let tmp = std::env::temp_dir().join(&file_name_c);
                                        if std::fs::write(&tmp, &source_c).is_err() {
                                            let _ = tx.send("[ERROR] Failed to write temp file".into());
                                            return;
                                        }
                                        use std::io::Write;
                                        use std::process::{Command, Stdio};
                                        match Command::new("python3").arg(&tmp)
                                            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
                                            .spawn()
                                        {
                                            Ok(mut child) => {
                                                if let Some(mut sin) = child.stdin.take() {
                                                    let _ = writeln!(sin, "{}", input);
                                                }
                                                let out = child.wait_with_output().unwrap_or_else(|_| std::process::Output { status: std::process::ExitStatus::default(), stdout: vec![], stderr: b"[ERROR] wait failed".to_vec() });
                                                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                                                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                                                if stdout.is_empty() && !stderr.is_empty() {
                                                    format!("[ERROR]\n{}", stderr)
                                                } else {
                                                    stdout
                                                }
                                            }
                                            Err(e) => format!("[ERROR] python3 not found or failed: {}", e),
                                        }
                                    }
                                    ModuleRuntime::Rust => {
                                        // Syntax check: write to temp, try rustfmt --check or rustc --edition 2021 --emit=metadata
                                        let tmp = std::env::temp_dir().join(&file_name_c);
                                        if std::fs::write(&tmp, &source_c).is_err() {
                                            let _ = tx.send("[ERROR] Failed to write temp file".into());
                                            return;
                                        }
                                        use std::process::Command;
                                        let out = Command::new("rustc")
                                            .args(["--edition", "2021", "--crate-type", "lib", "--emit", "metadata", "-o", "/dev/null"])
                                            .arg(&tmp)
                                            .output();
                                        match out {
                                            Ok(o) => {
                                                let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                                                if o.status.success() {
                                                    "✓ Rust syntax OK — module compiles cleanly.".into()
                                                } else {
                                                    format!("[ERROR] Compile check failed:\n{}", stderr)
                                                }
                                            }
                                            Err(e) => format!("[ERROR] rustc not found: {}", e),
                                        }
                                    }
                                };
                                let _ = tx.send(result);
                            });
                        }
                    } else {
                        ui.add(egui::Label::new(RichText::new("⏳ Testing...").size(11.0).color(Color32::from_rgb(200, 160, 30))));
                    }
                });

                // Test output
                if !self.module_test_output.is_empty() {
                    ui.add_space(6.0);
                    ui.label(RichText::new("Test Output").size(11.0).color(TEXT_MUTED));
                    let out_color = if self.module_test_output.contains("[ERROR]") {
                        Color32::from_rgb(255, 100, 80)
                    } else {
                        Color32::from_rgb(100, 220, 130)
                    };
                    ScrollArea::vertical().id_salt("mod_test_out").max_height(200.0).show(ui, |ui| {
                        Frame::NONE
                            .fill(Color32::from_rgb(8, 12, 18))
                            .stroke(egui::Stroke::new(1.0, Color32::from_rgb(30, 45, 65)))
                            .corner_radius(4.0)
                            .inner_margin(Margin::same(8))
                            .show(ui, |ui| {
                                ui.label(RichText::new(&self.module_test_output).size(10.0).color(out_color).monospace());
                            });
                    });

                }

                // ── Analyse Module button — always visible ────────────────
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("AI Validation").size(11.0).color(TEXT_MUTED));
                    ui.add_space(8.0);
                    let validated = self.user_modules[idx].ai_validated;
                    if validated {
                        ui.label(RichText::new("✔ COMPATIBLE").size(11.0).color(Color32::from_rgb(50, 200, 100)));
                    } else {
                        ui.label(RichText::new("⚠ Not validated").size(11.0).color(Color32::from_rgb(220, 160, 30)));
                    }
                });
                ui.add_space(4.0);
                // Quick local static check — instant, no AI
                if ui.add(
                    egui::Button::new(RichText::new("⚡ Quick Check").size(11.0).color(Color32::WHITE))
                        .fill(Color32::from_rgb(20, 60, 20))
                        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(50, 180, 80)))
                        .corner_radius(4.0)
                ).on_hover_text("Instantly check IPC compliance rules without AI").clicked() {
                    match Self::validate_module_locally(&source) {
                        Ok(()) => {
                            self.user_modules[idx].ai_validated = true;
                            self.push_toast(format!("Module '{}' passed all checks — COMPATIBLE", name), Color32::from_rgb(50, 200, 100));
                        }
                        Err(fails) => {
                            self.user_modules[idx].ai_validated = false;
                            self.push_toast(format!("INCOMPATIBLE: {}", fails.join("; ")), Color32::from_rgb(220, 60, 60));
                        }
                    }
                }
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if ui.add(
                        egui::Button::new(RichText::new("🔍 Analyse Module").size(11.0).color(Color32::WHITE))
                            .fill(Color32::from_rgb(30, 60, 120))
                            .stroke(egui::Stroke::new(1.0, Color32::from_rgb(60, 120, 220)))
                            .corner_radius(4.0)
                    ).on_hover_text("Ask the AI to verify this module is compatible with the system").clicked() {
                        let src_preview = if source.len() > 6000 {
                            format!("{}\n... [truncated, {} total chars]", &source[..6000], source.len())
                        } else {
                            source.clone()
                        };
                        let prompt = format!(
                            "Check if module '{}' is compatible with this system. \
                             Reply in exactly 3 lines, no more:\n\
                             Line 1: COMPATIBLE or INCOMPATIBLE\n\
                             Line 2: Why (max 15 words)\n\
                             Line 3: pip install <deps> or 'No external deps'\n\n\
                             System requirements — all must be true for COMPATIBLE:\n\
                             1. Reads one JSON line from stdin (keys: target, run_id, config, timeout_secs)\n\
                             2. Writes JSON lines to stdout with 'type' field — valid types: log, progress, finding, error, done\n\
                             3. Ends with a 'done' message in all code paths\n\
                             4. Does not crash on empty or malformed stdin\n\
                             5. opts = ctx.get('config', ctx.get('options', {{}})) — config key used\n\
                             6. timeout = ctx.get('timeout_secs', ...) — timeout_secs key used\n\
                             NOTE: 'data' output type is NOT required and its absence is fine.\n\n\
                             ```python\n{}\n```",
                            name, src_preview
                        );
                        self.pending_ai_validation = Some(idx);
                        self.ai_input = prompt;
                        self.selected_nav = "AI Assistant".to_string();
                        self.send_ai();
                    }

                    // Fix Module button — only when not validated
                    if !self.user_modules[idx].ai_validated {
                        ui.add_space(6.0);
                        if ui.add(
                            egui::Button::new(RichText::new("🔧 Fix Module").size(11.0).color(Color32::WHITE))
                                .fill(Color32::from_rgb(80, 40, 0))
                                .stroke(egui::Stroke::new(1.0, Color32::from_rgb(200, 120, 30)))
                                .corner_radius(4.0)
                        ).on_hover_text("Ask the AI to rewrite the module to fix all compatibility issues, then save to disk automatically").clicked() {
                            let src_preview = if source.len() > 6000 {
                                format!("{}\n... [truncated, {} total chars]", &source[..6000], source.len())
                            } else {
                                source.clone()
                            };
                            let prompt = format!(
                                "Fix the Python module '{}' so it is fully compatible with this system.\n\
                                 IMPORTANT: reply with ONLY the complete corrected Python file inside a single ```python ... ``` block. No explanations before or after.\n\n\
                                 Requirements to fix:\n\
                                 - from_context must read opts from ctx.get(\"config\", ctx.get(\"options\", {{}}))\n\
                                 - timeout must come from ctx.get(\"timeout_secs\", opts.get(\"timeout\", 15))\n\
                                 - reads one JSON line from stdin with keys: target, run_id, config, timeout_secs\n\
                                 - writes JSON lines to stdout, types: log, progress, finding, error, done\n\
                                 - must not crash on empty or malformed stdin\n\
                                 - emit each discovered link as a finding with type='finding'\n\n\
                                 Current source:\n```python\n{}\n```",
                                name, src_preview
                            );
                            self.pending_ai_fix = Some(idx);
                            self.ai_input = prompt;
                            self.selected_nav = "AI Assistant".to_string();
                            self.send_ai();
                        }
                    }
                });
            }
        }

        // ── AI/Workspace context summary ─────────────────────────────────────
        ui.add_space(12.0);
        ui.separator();
        ui.add_space(6.0);
        ui.label(RichText::new("Modules visible to AI & Workspace").size(11.0).color(TEXT_MUTED));
        let builtin_summary = builtin.iter().map(|(id, n, c, r, d)| format!("  [{r}] {n} ({c}) — {d}  [id: {id}]")).collect::<Vec<_>>().join("\n");
        let user_summary = if self.user_modules.is_empty() {
            "  (none uploaded)".into()
        } else {
            self.user_modules.iter().map(|m| format!("  [{}] {} ({}) — {}", m.runtime.label(), m.name, m.category, m.status.label())).collect::<Vec<_>>().join("\n")
        };
        Frame::NONE
            .fill(Color32::from_rgb(10, 14, 22))
            .stroke(egui::Stroke::new(1.0, Color32::from_rgb(30, 45, 65)))
            .corner_radius(4.0)
            .inner_margin(Margin::same(8))
            .show(ui, |ui| {
                ui.label(RichText::new(format!("Built-in:\n{}\n\nUploaded:\n{}", builtin_summary, user_summary)).size(10.0).color(TEXT_MUTED).monospace());
            });

        }); // end ScrollArea::vertical modules_page
    }

    pub(crate) fn page_settings(&mut self, ui: &mut Ui) {
        ScrollArea::vertical().show(ui, |ui| {
            card_frame().show(ui, |ui| {
                section_title(ui, "SECURITY");
                ui.label(RichText::new("Exploit confirmation phrase").size(11.0).color(TEXT_MUTED));
                ui.label(RichText::new("AI will refuse to run exploit-level tools (sqlmap, ffuf, nuclei, etc.) unless this exact phrase is present in your message. Leave blank to disable.").size(10.0).color(TEXT_DIM));
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add(TextEdit::singleline(&mut self.confirm_phrase)
                        .hint_text("e.g. runit")
                        .desired_width(200.0)
                        .background_color(INPUT_BG));
                    ui.label(RichText::new(
                        if self.confirm_phrase.trim().is_empty() {
                            "⚠ disabled — any message can trigger exploits".to_string()
                        } else {
                            format!("✓ exploits require: \"{}\"", self.confirm_phrase.trim())
                        }
                    ).size(10.0).color(if self.confirm_phrase.trim().is_empty() { WARN } else { ACCENT }));
                });
                ui.add_space(4.0);
                ui.label(RichText::new("Covered tools: sqlmap, ffuf, gobuster, nikto, nuclei, xssstrike, dalfox, wfuzz, hydra, medusa, commix, arjun, paramspider").size(10.0).color(TEXT_DIM));
            });
            ui.add_space(8.0);
            card_frame().show(ui, |ui| {
                section_title(ui, "AUTH AUTO — SESSION INJECTION");
                ui.label(RichText::new("When enabled, the Bearer token and/or Cookie are automatically injected into every Repeater, Intruder, and Proxy request.").size(10.0).color(TEXT_DIM));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.auth_enabled, "");
                    ui.label(RichText::new(if self.auth_enabled { "Auth injection ON 🔐" } else { "Auth injection OFF" })
                        .size(11.0).color(if self.auth_enabled { ACCENT } else { TEXT_MUTED }));
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Bearer Token:").size(11.0).color(TEXT_MUTED));
                    ui.add_space(4.0);
                    ui.add(TextEdit::singleline(&mut self.auth_bearer)
                        .password(true).desired_width(f32::INFINITY)
                        .background_color(INPUT_BG)
                        .hint_text("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…"));
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Cookie:       ").size(11.0).color(TEXT_MUTED));
                    ui.add_space(4.0);
                    ui.add(TextEdit::singleline(&mut self.auth_cookie)
                        .password(true).desired_width(f32::INFINITY)
                        .background_color(INPUT_BG)
                        .hint_text("session=abc123; csrf=xyz…"));
                });
                ui.add_space(4.0);
                if ui.add(subtle_button("Clear credentials")).clicked() {
                    self.auth_bearer.clear();
                    self.auth_cookie.clear();
                    self.auth_enabled = false;
                }
            });
            ui.add_space(8.0);
            card_frame().show(ui, |ui| {
                section_title(ui, "TLS MITM PROXY — CA CERTIFICATE");
                ui.label(RichText::new("Import this CA into your browser/OS to decrypt HTTPS traffic through the proxy.").size(10.0).color(TEXT_DIM));
                ui.add_space(6.0);
                let ca_path = crate::tls_mitm::ca_cert_path();
                let ca_str  = ca_path.to_string_lossy().to_string();
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&ca_str).size(10.0).monospace().color(ACCENT));
                    if ui.add(subtle_button("Copy path")).clicked() {
                        ui.ctx().copy_text(ca_str.clone());
                    }
                });
                ui.add_space(4.0);
                if ui.add(accent_button("Export CA to Desktop")).clicked() {
                    let dest = std::path::PathBuf::from(
                        std::env::var("HOME").unwrap_or_else(|_| ".".into())
                    ).join("Desktop").join("FarstyleCA.pem");
                    match std::fs::copy(&ca_path, &dest) {
                        Ok(_)  => self.push_toast(format!("CA saved → {}", dest.display()), ACCENT),
                        Err(e) => self.push_toast(format!("Export failed: {}", e), DANGER),
                    }
                }
            });
            ui.add_space(8.0);
            card_frame().show(ui, |ui| {
                section_title(ui, "AI MODEL SETTINGS");
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Provider:").size(11.0).color(TEXT_MUTED));
                    egui::ComboBox::from_id_salt("ai_prov").selected_text(self.ai_provider.label()).show_ui(ui, |ui| {
                        for prov in Provider::all() {
                            ui.selectable_value(&mut self.ai_provider, *prov, prov.label());
                        }
                    });
                });
                ui.label(RichText::new("Model").size(11.0).color(TEXT_MUTED));
                ui.add(TextEdit::singleline(&mut self.ai_model).desired_width(f32::INFINITY).background_color(INPUT_BG));
                ui.label(RichText::new("Endpoint URL").size(11.0).color(TEXT_MUTED));
                let hint = match self.ai_provider {
                    Provider::Ollama => "http://localhost:11434",
                    Provider::OpenAI => "https://api.openai.com/v1",
                    Provider::OpenRouter => "Auto: https://openrouter.ai/api/v1",
                };
                ui.add(TextEdit::singleline(&mut self.ai_endpoint).hint_text(hint).desired_width(f32::INFINITY).background_color(INPUT_BG));
                if self.ai_provider != Provider::Ollama {
                    ui.label(RichText::new("API Key").size(11.0).color(TEXT_MUTED));
                    ui.add(TextEdit::singleline(&mut self.ai_api_key).password(true).desired_width(f32::INFINITY).background_color(INPUT_BG));
                    if self.ai_provider == Provider::OpenRouter {
                        ui.label(RichText::new("Get key from: https://openrouter.ai/keys").size(10.0).color(ACCENT_DIM));
                    }
                }
            });
            ui.add_space(8.0);
            card_frame().show(ui, |ui| {
                section_title(ui, "VOICE INPUT — SPEECH-TO-TEXT");
                ui.label(RichText::new("Powers the 🎙 record button in the Workspace. Independent of the chat provider above — pick OpenAI Whisper, a local OpenAI-compatible server, or an audio-capable model via OpenRouter.").size(10.0).color(TEXT_DIM));
                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    ui.label(RichText::new("Provider:").size(11.0).color(TEXT_MUTED));
                    let mut chosen = self.ws_stt_provider;
                    egui::ComboBox::from_id_salt("stt_prov").selected_text(chosen.label()).show_ui(ui, |ui| {
                        for prov in SttProvider::all() {
                            ui.selectable_value(&mut chosen, *prov, prov.label());
                        }
                    });
                    if chosen != self.ws_stt_provider {
                        self.switch_stt_provider(chosen);
                    }
                });

                ui.label(RichText::new("Model").size(11.0).color(TEXT_MUTED));
                let model_hint = self.ws_stt_provider.default_model();
                ui.add(TextEdit::singleline(&mut self.ws_stt_model).hint_text(model_hint).desired_width(f32::INFINITY).background_color(INPUT_BG));

                if self.ws_stt_provider == SttProvider::Local {
                    ui.label(RichText::new("Endpoint URL").size(11.0).color(TEXT_MUTED));
                    ui.add(TextEdit::singleline(&mut self.ws_stt_endpoint).hint_text("http://localhost:8000/v1").desired_width(f32::INFINITY).background_color(INPUT_BG));
                    ui.label(RichText::new("Any OpenAI-compatible /audio/transcriptions server — whisper.cpp server, faster-whisper-server, etc. No API key needed unless your server requires one.").size(10.0).color(ACCENT_DIM));
                }

                if self.ws_stt_provider != SttProvider::Local {
                    ui.label(RichText::new("API Key").size(11.0).color(TEXT_MUTED));
                }
                if self.ws_stt_provider == SttProvider::Local {
                    ui.label(RichText::new("API Key (optional)").size(11.0).color(TEXT_MUTED));
                }
                ui.add(TextEdit::singleline(&mut self.ws_whisper_key).password(true).desired_width(f32::INFINITY).background_color(INPUT_BG));
                match self.ws_stt_provider {
                    SttProvider::OpenAI => ui.label(RichText::new("Get key from: https://platform.openai.com/api-keys").size(10.0).color(ACCENT_DIM)),
                    SttProvider::OpenRouter => ui.label(RichText::new("Get key from: https://openrouter.ai/keys — model must support audio input (e.g. openai/gpt-4o-audio-preview).").size(10.0).color(ACCENT_DIM)),
                    SttProvider::Local => ui.label(RichText::new("Leave blank unless your local server enforces a bearer token.").size(10.0).color(ACCENT_DIM)),
                };
            });
            ui.add_space(8.0);
            card_frame().show(ui, |ui| {
                section_title(ui, "VOICE OUTPUT — TEXT-TO-SPEECH");
                ui.label(RichText::new("Reads agent replies aloud using the OS speech synthesizer (free, fully local, no API key). Same toggle is available as a quick switch in the Workspace toolbar, which also shows \"Speaking…\" while it's actually talking.").size(10.0).color(TEXT_DIM));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let label = if self.tts_enabled { "🔊 Enabled" } else { "🔇 Disabled" };
                    let color = if self.tts_enabled { ACCENT } else { TEXT_MUTED };
                    if ui.add(egui::Button::new(RichText::new(label).size(11.0).color(color))
                        .fill(Color32::TRANSPARENT).stroke(Stroke::new(1.0, if self.tts_enabled { ACCENT } else { BORDER }))
                        .corner_radius(4.0).min_size(Vec2::new(100.0, 24.0)))
                        .clicked() {
                        self.tts_enabled = !self.tts_enabled;
                        if !self.tts_enabled {
                            if let Some(mut child) = self.tts_child.take() {
                                let _ = child.kill();
                            }
                            self.tts_speaking = false;
                        }
                    }
                    if self.tts_speaking {
                        ui.add_space(8.0);
                        ui.label(RichText::new("🔊 Speaking now…").size(10.0).color(ACCENT));
                    }
                });
                ui.add_space(4.0);
                ui.label(RichText::new("Voice (macOS male voices: Daniel, Alex, Fred, Bruce)").size(11.0).color(TEXT_MUTED));
                ui.add(TextEdit::singleline(&mut self.tts_voice).hint_text(crate::tts::DEFAULT_VOICE).desired_width(220.0).background_color(INPUT_BG));
            });
            ui.add_space(8.0);
            card_frame().show(ui, |ui| {
                section_title(ui, "FAST Q&A — DUAL-MODEL ROUTING");
                ui.label(RichText::new("Plain questions (\"what is XSS?\", \"who are you?\") skip the slower model above entirely and get answered by a small fast model with a minimal prompt — no ACTION syntax, no tool-state dump. Anything that needs a tool/scan still routes to the model in AI Model Settings. Routing itself is a free keyword check, never an extra LLM call.").size(10.0).color(TEXT_DIM));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let label = if self.ws_fast_enabled { "⚡ Enabled" } else { "⚡ Disabled" };
                    let color = if self.ws_fast_enabled { ACCENT } else { TEXT_MUTED };
                    if ui.add(egui::Button::new(RichText::new(label).size(11.0).color(color))
                        .fill(Color32::TRANSPARENT).stroke(Stroke::new(1.0, if self.ws_fast_enabled { ACCENT } else { BORDER }))
                        .corner_radius(4.0).min_size(Vec2::new(100.0, 24.0)))
                        .clicked() {
                        self.ws_fast_enabled = !self.ws_fast_enabled;
                    }
                });
                ui.add_space(4.0);
                ui.label(RichText::new("Fast model (must be pulled in Ollama already)").size(11.0).color(TEXT_MUTED));
                ui.add(TextEdit::singleline(&mut self.ws_fast_model).hint_text("qwen2.5:1.5b").desired_width(220.0).background_color(INPUT_BG));
            });
        });
    }

    pub(crate) fn page_knowledge(&mut self, ui: &mut Ui) {
        // Tab bar
        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                section_title(ui, "KNOWLEDGE BASE");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let active_count = self.kb_docs.iter().filter(|d| d.enabled).count();
                    ui.label(RichText::new(format!("{}/{} active in AI context", active_count, self.kb_docs.len())).size(11.0).color(TEXT_MUTED));
                });
            });
            ui.horizontal(|ui| {
                for tab in ["Documents", "Add Note", "Add Competence", "Upload File"] {
                    let sel = self.kb_tab == tab;
                    if ui.add(
                        egui::Button::new(RichText::new(tab).size(12.0).color(if sel { ACCENT } else { TEXT_SECONDARY }))
                            .fill(if sel { Color32::from_rgb(12, 35, 22) } else { Color32::TRANSPARENT })
                            .stroke(if sel { Stroke::new(1.0, ACCENT) } else { Stroke::NONE })
                            .corner_radius(6.0)
                    ).clicked() {
                        self.kb_tab = tab.into();
                    }
                    ui.add_space(4.0);
                }
            });
        });

        let tab = self.kb_tab.clone();
        match tab.as_str() {
            "Documents" => {
                ui.columns(2, |cols| {
                    // Left: doc list
                    card_frame().show(&mut cols[0], |ui| {
                        section_title(ui, "DOCUMENTS");
                        ScrollArea::vertical().id_salt("kb_doc_list").max_height(480.0).show(ui, |ui| {
                            let doc_ids: Vec<usize> = self.kb_docs.iter().map(|d| d.id).collect();
                            let mut to_delete: Option<usize> = None;
                            for id in doc_ids {
                                let idx = self.kb_docs.iter().position(|d| d.id == id).unwrap();
                                let selected = self.kb_selected == Some(id);
                                let (title, kind_label, enabled, preview) = {
                                    let d = &self.kb_docs[idx];
                                    (d.title.clone(), d.kind.label(), d.enabled, d.preview())
                                };
                                let kind_color = match kind_label {
                                    "Competence" => ACCENT,
                                    "File" => Color32::from_rgb(100, 160, 255),
                                    _ => TEXT_MUTED,
                                };
                                Frame::NONE
                                    .fill(if selected { Color32::from_rgb(12, 35, 22) } else { INPUT_BG })
                                    .stroke(Stroke::new(1.0, if selected { ACCENT } else { BORDER }))
                                    .corner_radius(6.0)
                                    .inner_margin(Margin::same(8))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            let mut en = enabled;
                                            if ui.checkbox(&mut en, "").changed() {
                                                self.kb_docs[idx].enabled = en;
                                            }
                                            ui.label(RichText::new(&title).size(12.0).strong().color(TEXT_PRIMARY));
                                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                                if ui.add(egui::Button::new(RichText::new("✕").size(10.0).color(DANGER)).fill(Color32::TRANSPARENT)).clicked() {
                                                    to_delete = Some(id);
                                                }
                                                ui.label(RichText::new(kind_label).size(10.0).color(kind_color));
                                            });
                                        });
                                        ui.label(RichText::new(&preview).size(10.0).color(TEXT_DIM).monospace());
                                        if ui.add(egui::Button::new(RichText::new("View / Edit").size(10.0).color(ACCENT)).fill(Color32::TRANSPARENT)).clicked() {
                                            self.kb_selected = Some(id);
                                        }
                                    });
                                ui.add_space(4.0);
                            }
                            if let Some(del_id) = to_delete {
                                self.kb_docs.retain(|d| d.id != del_id);
                                if self.kb_selected == Some(del_id) { self.kb_selected = None; }
                            }
                        });
                    });

                    // Right: doc viewer/editor
                    card_frame().show(&mut cols[1], |ui| {
                        if let Some(sel_id) = self.kb_selected {
                            if let Some(idx) = self.kb_docs.iter().position(|d| d.id == sel_id) {
                                section_title(ui, &self.kb_docs[idx].title.clone());
                                ui.label(RichText::new(format!("Kind: {}  |  Status: {}", self.kb_docs[idx].kind.label(), if self.kb_docs[idx].enabled { "Active in AI" } else { "Disabled" })).size(11.0).color(TEXT_MUTED));
                                ui.add_space(6.0);
                                ScrollArea::vertical().id_salt("kb_doc_view").max_height(420.0).show(ui, |ui| {
                                    ui.add(TextEdit::multiline(&mut self.kb_docs[idx].content)
                                        .font(egui::TextStyle::Monospace)
                                        .desired_rows(18)
                                        .desired_width(f32::INFINITY)
                                        .background_color(INPUT_BG));
                                });
                            }
                        } else {
                            ui.vertical_centered(|ui| {
                                ui.add_space(80.0);
                                ui.label(RichText::new("📚").size(48.0));
                                ui.label(RichText::new("Select a document to view or edit").size(13.0).color(TEXT_MUTED));
                            });
                        }
                    });
                });
            }

            "Add Note" => {
                card_frame().show(ui, |ui| {
                    section_title(ui, "NEW NOTE");
                    ui.label(RichText::new("Title").size(11.0).color(TEXT_MUTED));
                    ui.add(TextEdit::singleline(&mut self.kb_new_title).desired_width(f32::INFINITY).background_color(INPUT_BG).hint_text("e.g. OWASP Top 10 notes"));
                    ui.add_space(6.0);
                    ui.label(RichText::new("Content").size(11.0).color(TEXT_MUTED));
                    ScrollArea::vertical().id_salt("kb_note_body").max_height(320.0).show(ui, |ui| {
                        ui.add(TextEdit::multiline(&mut self.kb_new_body)
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(14)
                            .desired_width(f32::INFINITY)
                            .background_color(INPUT_BG)
                            .hint_text("Write your notes here — they will be injected into every AI prompt when enabled..."));
                    });
                    ui.add_space(8.0);
                    if ui.add(egui::Button::new(RichText::new("Save Note").size(13.0).color(Color32::BLACK)).fill(ACCENT).min_size(Vec2::new(120.0, 32.0))).clicked() {
                        if !self.kb_new_title.is_empty() && !self.kb_new_body.is_empty() {
                            let id = self.kb_next_id;
                            self.kb_next_id += 1;
                            self.kb_docs.push(KbDoc::new_note(id, self.kb_new_title.clone(), self.kb_new_body.clone()));
                            self.kb_new_title.clear();
                            self.kb_new_body.clear();
                            self.kb_tab = "Documents".into();
                        }
                    }
                });
            }

            "Add Competence" => {
                card_frame().show(ui, |ui| {
                    section_title(ui, "NEW COMPETENCE / TECHNIQUE");
                    ui.label(RichText::new("Describe a technique, attack pattern, or methodology that the AI should know about and apply during audits.").size(11.0).color(TEXT_MUTED));
                    ui.add_space(6.0);
                    ui.label(RichText::new("Title").size(11.0).color(TEXT_MUTED));
                    ui.add(TextEdit::singleline(&mut self.kb_new_title).desired_width(f32::INFINITY).background_color(INPUT_BG).hint_text("e.g. IDOR Testing Methodology"));
                    ui.add_space(6.0);
                    ui.label(RichText::new("Technique / Competence").size(11.0).color(TEXT_MUTED));
                    ScrollArea::vertical().id_salt("kb_comp_body").max_height(300.0).show(ui, |ui| {
                        ui.add(TextEdit::multiline(&mut self.kb_new_body)
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(12)
                            .desired_width(f32::INFINITY)
                            .background_color(INPUT_BG)
                            .hint_text("e.g.\nWhen testing for IDOR:\n1. Find object references in requests (id=123)\n2. Change to id=124 while authenticated as different user\n3. Check if access is granted\n..."));
                    });
                    ui.add_space(8.0);
                    if ui.add(egui::Button::new(RichText::new("Save Competence").size(13.0).color(Color32::BLACK)).fill(ACCENT).min_size(Vec2::new(150.0, 32.0))).clicked() {
                        if !self.kb_new_title.is_empty() && !self.kb_new_body.is_empty() {
                            let id = self.kb_next_id;
                            self.kb_next_id += 1;
                            self.kb_docs.push(KbDoc::new_competence(id, self.kb_new_title.clone(), self.kb_new_body.clone()));
                            self.kb_new_title.clear();
                            self.kb_new_body.clear();
                            self.kb_tab = "Documents".into();
                        }
                    }
                });
            }

            "Upload File" => {
                card_frame().show(ui, |ui| {
                    section_title(ui, "UPLOAD FILE");
                    ui.label(RichText::new("Load a .txt, .md, or .pdf (text) file from disk. The content will be added to the AI context.").size(11.0).color(TEXT_MUTED));
                    ui.add_space(10.0);
                    if ui.add(egui::Button::new(RichText::new("📂  Choose File...").size(13.0).color(Color32::BLACK)).fill(ACCENT).min_size(Vec2::new(160.0, 36.0))).clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("Text files", &["txt", "md", "csv", "json", "yaml", "toml"])
                            .pick_file()
                        {
                            let id = self.kb_next_id;
                            self.kb_next_id += 1;
                            match KbDoc::from_file(id, path) {
                                Ok(doc) => {
                                    self.kb_docs.push(doc);
                                    self.kb_tab = "Documents".into();
                                }
                                Err(e) => {
                                    self.kb_docs.push(KbDoc::new_note(id, "Load Error".into(), e));
                                    self.kb_tab = "Documents".into();
                                }
                            }
                        }
                    }
                    ui.add_space(16.0);
                    ui.label(RichText::new("Supported: .txt  .md  .csv  .json  .yaml  .toml").size(11.0).color(TEXT_DIM));
                    ui.label(RichText::new("Tip: You can paste course PDFs converted to .txt, OWASP guides, custom checklists, etc.").size(11.0).color(TEXT_DIM));
                });
            }

            _ => {}
        }
    }


    pub(crate) fn page_about(&mut self, ui: &mut Ui) {
        card_frame().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(30.0);
                ui.label(RichText::new("🛡").size(64.0).color(ACCENT));
                ui.add_space(16.0);
                ui.label(RichText::new("FARSTYLE").size(24.0).strong().color(ACCENT));
                ui.label(RichText::new("Authentication Security Auditor by TONGOUE STEEVY").size(13.0).color(TEXT_SECONDARY));
                ui.add_space(20.0);
                ui.label(RichText::new("v0.1.0 | Built with Rust + egui").size(11.0).color(TEXT_MUTED));
                ui.add_space(10.0);
                ui.label(RichText::new("Features: Scanner • Proxy • Repeater • Intruder • Encoder • AI • Engagements").size(11.0).color(TEXT_SECONDARY));
            });
        });
    }
}
