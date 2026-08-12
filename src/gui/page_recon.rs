// Recon & core pages: Overview, Target, Scan Modules, Results, Encoder, Logs,
// History and the AI Assistant. Split out of the GUI monolith; see gui/mod.rs.

use super::*;

impl NullForgeApp {
    pub(crate) fn page_overview(&mut self, ui: &mut Ui) {
        let avail = ui.available_size();
        let left_w = (avail.x * 0.30).min(300.0).max(200.0);
        // Reserve the explicit gap (12) + egui's auto item_spacing between the two
        // columns so the right column never overflows the panel's right edge.
        let right_w = (avail.x - left_w - 12.0 - 24.0).max(0.0);

        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(Vec2::new(left_w, avail.y), Layout::top_down(Align::LEFT), |ui| {
                // Dashboard Overview Card — compact hero (was 58% tall with lots of
                // dead space); trimmed so it balances better with Recent Activity below.
                let top_h = (avail.y * 0.46).max(240.0);
                Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(12.0)
                    .inner_margin(Margin::same(16)).show(ui, |ui| {
                    ui.set_min_height(top_h);
                    section_title(ui, "DASHBOARD OVERVIEW");
                    ui.add_space(top_h * 0.08);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("🛡").size(64.0).color(ACCENT_DIM));
                        ui.add_space(14.0);
                        ui.label(RichText::new("Ready to secure").size(20.0).strong().color(TEXT_PRIMARY));
                        ui.add_space(6.0);
                        ui.label(RichText::new("Configure your target and start a scan to").size(11.0).color(TEXT_MUTED));
                        ui.label(RichText::new("analyze authentication security.").size(11.0).color(TEXT_MUTED));
                        ui.add_space(18.0);
                        if ui.add(accent_button("  ▶  START SCAN  ")).clicked() { self.start_scan(); }
                    });
                });
                
                ui.add_space(12.0);
                
                // Recent Activity Card
                card_frame().show(ui, |ui| {
                    section_title(ui, "RECENT ACTIVITY");
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Time").size(10.0).color(TEXT_DIM).strong());
                        ui.add_space(60.0);
                        ui.label(RichText::new("Activity").size(10.0).color(TEXT_DIM).strong());
                        ui.add_space(60.0);
                        ui.label(RichText::new("Status").size(10.0).color(TEXT_DIM).strong());
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(RichText::new("Details").size(10.0).color(TEXT_DIM).strong());
                        });
                    });
                    ui.separator();
                    if self.scan_history.is_empty() {
                        ui.vertical_centered(|ui| {
                            ui.add_space(30.0);
                            ui.label(RichText::new("📥").size(32.0).color(TEXT_DIM));
                            ui.label(RichText::new("No recent activity").size(13.0).color(TEXT_PRIMARY));
                            ui.label(RichText::new("Your scan activities will appear here.").size(10.0).color(TEXT_MUTED));
                        });
                    } else {
                        for (time, target, findings) in &self.scan_history {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(time).size(11.0).color(TEXT_MUTED));
                                ui.add_space(40.0);
                                ui.label(RichText::new(format!("Scan: {}", target.chars().take(20).collect::<String>())).size(11.0).color(TEXT_PRIMARY));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(RichText::new(format!("{} findings", findings)).size(11.0).color(if *findings > 0 { WARN } else { ACCENT }));
                                });
                            });
                            ui.add_space(4.0);
                        }
                    }
                });
            });
            
            ui.add_space(12.0);
            
            ui.allocate_ui_with_layout(Vec2::new(right_w, avail.y), Layout::top_down(Align::LEFT), |ui| {
            ScrollArea::vertical().id_salt("overview_right").auto_shrink([false, false]).show(ui, |ui| {
                // Two balanced columns: each stacks its cards so they fill the height
                // and leave no dead space beside the taller Risk Dashboard.
                ui.horizontal_top(|ui| {
                    let half = ((ui.available_width() - 12.0 - 24.0) / 2.0).max(80.0);

                    // ── Left column: Target Configuration + Scan Modules ──────
                    ui.allocate_ui_with_layout(Vec2::new(half, 0.0), Layout::top_down(Align::LEFT), |ui| {
                        card_frame().show(ui, |ui| {
                            section_title(ui, "TARGET CONFIGURATION");
                            ui.label(RichText::new("Target URL").size(11.0).color(TEXT_MUTED));
                            ui.add_space(4.0);
                            ui.add(TextEdit::singleline(&mut self.target).desired_width(f32::INFINITY).background_color(INPUT_BG));
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut false, RichText::new("Use Proxy").size(11.0).color(TEXT_SECONDARY));
                                ui.label(RichText::new("HTTP/HTTPS").size(10.0).color(TEXT_DIM));
                            });
                            ui.add_space(12.0);
                            if ui.add_sized(Vec2::new(ui.available_width(), 40.0), accent_button("▶  START SCAN")).clicked() { self.start_scan(); }
                        });

                        ui.add_space(12.0);

                        // Scan Modules (stacked under Target Config to fill the column)
                        card_frame().show(ui, |ui| {
                            section_title(ui, "SCAN MODULES");
                            for i in 0..MODULES.len() {
                                let (_id, name, category, runtime) = MODULES[i];
                                ui.horizontal(|ui| {
                                    let mut enabled = self.modules_enabled[i];
                                    if ui.checkbox(&mut enabled, "").changed() { self.modules_enabled[i] = enabled; }
                                    let rt_color = match runtime {
                                        "Rust"   => Color32::from_rgb(255, 100, 60),
                                        "Python" => Color32::from_rgb(80, 180, 100),
                                        _        => Color32::from_rgb(100, 160, 220),
                                    };
                                    ui.label(RichText::new(format!("[{}]", runtime)).size(10.0).color(rt_color).monospace());
                                    ui.label(RichText::new(name).size(12.0).color(TEXT_PRIMARY));
                                    ui.label(RichText::new(category).size(10.0).color(TEXT_MUTED));
                                });
                                ui.add_space(4.0);
                            }
                            for i in 0..self.user_modules.len() {
                                let (name, category, rt_label, rt_color) = {
                                    let m = &self.user_modules[i];
                                    (m.name.clone(), m.category.clone(), m.runtime.label().to_string(), m.runtime.color())
                                };
                                ui.horizontal(|ui| {
                                    let mut enabled = self.user_modules[i].enabled;
                                    if ui.checkbox(&mut enabled, "").changed() { self.user_modules[i].enabled = enabled; }
                                    ui.label(RichText::new(format!("[{}]", rt_label)).size(10.0).color(rt_color).monospace());
                                    ui.label(RichText::new(&name).size(12.0).color(TEXT_PRIMARY));
                                    ui.label(RichText::new(&category).size(10.0).color(TEXT_MUTED));
                                });
                                ui.add_space(4.0);
                            }
                            ui.separator();
                            ui.horizontal(|ui| {
                                let builtin_enabled = self.modules_enabled.iter().filter(|&&e| e).count();
                                let user_enabled = self.user_modules.iter().filter(|m| m.enabled).count();
                                let total = MODULES.len() + self.user_modules.len();
                                ui.label(RichText::new(format!("{} / {} modules enabled  •  {} system tools", builtin_enabled + user_enabled, total, TOOLS.len())).size(11.0).color(TEXT_MUTED));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(RichText::new("›").size(14.0).color(TEXT_MUTED));
                                });
                            });
                        });
                    });

                    ui.add_space(12.0);

                    // ── Right column: Risk Dashboard + Live Logs ──────────────
                    ui.allocate_ui_with_layout(Vec2::new(half, 0.0), Layout::top_down(Align::LEFT), |ui| {
                        card_frame().show(ui, |ui| {
                            section_title(ui, "RISK DASHBOARD");
                            ui.add_space(4.0);

                            // ── Pull live counts from active engagement ────────
                            let (eng_crit, eng_high, eng_med, eng_low, eng_info, eng_total) = {
                                if let Some(idx) = self.active_engagement_idx {
                                    if let Some(eng) = self.engagements.get(idx) {
                                        let c = eng.severity_counts(); // [crit, high, med, low, info]
                                        (c[0], c[1], c[2], c[3], c[4], c.iter().sum::<usize>())
                                    } else { (0,0,0,0,0,0) }
                                } else { (0,0,0,0,0,0) }
                            };
                            // Also count from local scan findings
                            let scan_total = self.findings.len();
                            let total_findings = eng_total + scan_total;

                            // ── Risk score ────────────────────────────────────
                            let risk_score: u32 = (eng_crit * 40 + eng_high * 15 + eng_med * 5 + eng_low * 1) as u32;
                            let (risk_label, risk_color) = if risk_score == 0 {
                                ("None", TEXT_MUTED)
                            } else if risk_score < 20 {
                                ("Low", Color32::from_rgb(80, 220, 120))
                            } else if risk_score < 60 {
                                ("Medium", WARN)
                            } else if risk_score < 120 {
                                ("High", Color32::from_rgb(255, 120, 40))
                            } else {
                                ("Critical", DANGER)
                            };

                            // ── Score headline ────────────────────────────────
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(RichText::new(format!("{}", risk_score)).size(32.0).strong().color(risk_color));
                                    ui.label(RichText::new("risk score").size(9.0).color(TEXT_DIM));
                                });
                                ui.add_space(16.0);
                                ui.vertical(|ui| {
                                    ui.label(RichText::new(format!("{}", total_findings)).size(32.0).strong().color(if total_findings > 0 { WARN } else { TEXT_MUTED }));
                                    ui.label(RichText::new("total findings").size(9.0).color(TEXT_DIM));
                                });
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    Frame::NONE
                                        .fill(risk_color.linear_multiply(0.2))
                                        .stroke(Stroke::new(1.0, risk_color.linear_multiply(0.6)))
                                        .corner_radius(8.0)
                                        .inner_margin(Margin::symmetric(10, 6))
                                        .show(ui, |ui| {
                                        ui.label(RichText::new(risk_label).size(13.0).strong().color(risk_color));
                                    });
                                });
                            });
                            ui.add_space(10.0);
                            ui.separator();
                            ui.add_space(8.0);

                            // ── Per-severity bar chart ─────────────────────────
                            let sev_data: &[(&str, usize, Color32)] = &[
                                ("CRIT",  eng_crit, DANGER),
                                ("HIGH",  eng_high, Color32::from_rgb(255, 100, 40)),
                                ("MED",   eng_med,  WARN),
                                ("LOW",   eng_low,  Color32::from_rgb(80, 200, 120)),
                                ("INFO",  eng_info, Color32::from_rgb(100, 160, 220)),
                            ];
                            let max_count = sev_data.iter().map(|(_, n, _)| *n).max().unwrap_or(1).max(1);
                            let bar_area_w = ui.available_width();
                            for (label, count, color) in sev_data {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(*label).size(9.0).monospace().strong().color(*color)
                                        .text_style(egui::TextStyle::Monospace));
                                    ui.add_space(4.0);
                                    let bar_max_w = (bar_area_w - 80.0).max(40.0);
                                    let bar_w = if *count == 0 { 2.0 } else {
                                        ((*count as f32 / max_count as f32) * bar_max_w).max(2.0)
                                    };
                                    let (bar_rect, _) = ui.allocate_exact_size(
                                        Vec2::new(bar_w, 12.0), egui::Sense::hover()
                                    );
                                    let fill = if *count == 0 { color.linear_multiply(0.1) } else { color.linear_multiply(0.7) };
                                    ui.painter().rect_filled(bar_rect, 3.0, fill);
                                    ui.add_space(4.0);
                                    ui.label(RichText::new(format!("{}", count)).size(10.0).color(if *count > 0 { *color } else { TEXT_DIM }));
                                });
                                ui.add_space(3.0);
                            }

                            ui.add_space(6.0);
                            let enabled = self.modules_enabled.iter().filter(|&&e| e).count();
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("🔍 {} modules active", enabled)).size(10.0).color(TEXT_MUTED));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    let status_color = if self.scanning { ACCENT } else { TEXT_DIM };
                                    ui.label(RichText::new(if self.scanning { "● Scanning" } else { "○ Idle" }).size(10.0).color(status_color));
                                });
                            });
                            if self.active_engagement_idx.is_some() {
                                ui.add_space(4.0);
                                if ui.add(subtle_button("→ View in Engagements")).clicked() {
                                    self.selected_nav = "Engagements".into();
                                }
                            }
                        });

                        ui.add_space(12.0);

                        // Live Logs (stacked under Risk Dashboard to fill the column)
                        card_frame().show(ui, |ui| {
                            ui.horizontal(|ui| {
                                section_title(ui, "LIVE LOGS");
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui.add(subtle_button("Clear")).clicked() { self.logs.clear(); }
                                });
                            });
                            Frame::NONE.fill(TERMINAL_BG).corner_radius(8.0).inner_margin(Margin::same(10)).show(ui, |ui| {
                                ScrollArea::vertical().id_salt("overview_logs").max_height(160.0).stick_to_bottom(true).show(ui, |ui| {
                                    for log in &self.logs {
                                        let color = if log.contains("ERROR") { DANGER } else if log.contains("DONE") { ACCENT } else { TEXT_PRIMARY };
                                        ui.label(RichText::new(log).size(11.0).monospace().color(color));
                                    }
                                    ui.label(RichText::new("▶").size(11.0).monospace().color(ACCENT));
                                });
                            });
                        });
                    });
                });
            }); // ScrollArea right
            }); // allocate_ui right
        });
    }

    pub(crate) fn page_target(&mut self, ui: &mut Ui) {
        card_frame().show(ui, |ui| {
            section_title(ui, "TARGET CONFIGURATION");
            ui.label(RichText::new("Target URL").size(11.0).color(TEXT_MUTED));
            ui.add(TextEdit::singleline(&mut self.target).desired_width(f32::INFINITY).background_color(INPUT_BG));
            ui.add_space(16.0);
            if ui.add(accent_button("▶  START SCAN")).clicked() { self.start_scan(); }
        });
    }

    pub(crate) fn page_scan_modules(&mut self, ui: &mut Ui) {
        // ── Coded Modules ──────────────────────────────────────────────────
        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                section_title(ui, "MODULES");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add(subtle_button("Disable All")).clicked() { for e in &mut self.modules_enabled { *e = false; } }
                    if ui.add(subtle_button("Enable All")).clicked() { for e in &mut self.modules_enabled { *e = true; } }
                });
            });
            ui.label(RichText::new("Coded modules — Rust or Python, run directly by the engine.").size(10.0).color(TEXT_DIM));
            ui.add_space(6.0);
            for (i, (id, name, category, runtime)) in MODULES.iter().enumerate() {
                ui.horizontal(|ui| {
                    let mut enabled = self.modules_enabled[i];
                    if ui.checkbox(&mut enabled, "").changed() { self.modules_enabled[i] = enabled; }
                    let rt_color = match *runtime {
                        "Rust"   => Color32::from_rgb(255, 100, 60),
                        "Python" => Color32::from_rgb(80, 180, 100),
                        _        => Color32::from_rgb(100, 160, 220),
                    };
                    ui.label(RichText::new(format!("[{}]", runtime)).size(10.0).color(rt_color).monospace());
                    ui.label(RichText::new(*name).size(13.0).color(TEXT_PRIMARY));
                    ui.add_space(4.0);
                    ui.label(RichText::new(*category).size(10.0).color(TEXT_MUTED));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let color = if self.modules_enabled[i] { ACCENT } else { TEXT_DIM };
                        ui.label(RichText::new(if self.modules_enabled[i] { "Enabled" } else { "Disabled" }).size(11.0).color(color));
                        ui.add_space(8.0);
                        ui.label(RichText::new(*id).size(9.0).color(TEXT_DIM).monospace());
                    });
                });
                ui.separator();
            }
            // ── Uploaded user modules ─────────────────────────────────────
            let count = self.user_modules.len();
            for i in 0..count {
                let (name, category, rt_label, rt_color, status_label, status_color, validated) = {
                    let m = &self.user_modules[i];
                    (m.name.clone(), m.category.clone(), m.runtime.label().to_string(),
                     m.runtime.color(), m.status.label().to_string(), m.status.color(), m.ai_validated)
                };
                ui.horizontal(|ui| {
                    if validated {
                        let mut enabled = self.user_modules[i].enabled;
                        if ui.checkbox(&mut enabled, "").changed() {
                            self.user_modules[i].enabled = enabled;
                        }
                    } else {
                        // locked — render a disabled-looking checkbox
                        let mut dummy = false;
                        ui.add_enabled(false, egui::Checkbox::new(&mut dummy, ""))
                            .on_hover_text("Run 'Analyse Module' first — AI must confirm COMPATIBLE");
                    }
                    ui.label(RichText::new(format!("[{}]", rt_label)).size(10.0).color(rt_color).monospace());
                    let name_color = if validated { TEXT_PRIMARY } else { TEXT_DIM };
                    ui.label(RichText::new(&name).size(13.0).color(name_color));
                    ui.add_space(4.0);
                    ui.label(RichText::new(&category).size(10.0).color(TEXT_MUTED));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if !validated {
                            ui.label(RichText::new("⚠ Not validated").size(10.0).color(Color32::from_rgb(220, 160, 30)));
                        } else {
                            let col = if self.user_modules[i].enabled { ACCENT } else { TEXT_DIM };
                            ui.label(RichText::new(
                                if self.user_modules[i].enabled { "Enabled" } else { "Disabled" }
                            ).size(11.0).color(col));
                        }
                        ui.add_space(8.0);
                        ui.label(RichText::new(&status_label).size(10.0).color(status_color));
                    });
                });
                ui.separator();
            }
        });

        ui.add_space(8.0);

        // ── System-installed Tools ─────────────────────────────────────────
        card_frame().show(ui, |ui| {
            section_title(ui, "SYSTEM TOOLS");
            ui.label(RichText::new("CLI tools installed on your system — invoked by the AI and workspace.").size(10.0).color(TEXT_DIM));
            ui.add_space(6.0);
            ScrollArea::vertical().id_salt("tools_list").max_height(280.0).show(ui, |ui| {
                for (bin, name, category, desc) in TOOLS.iter() {
                    let installed = std::process::Command::new("which")
                        .arg(bin).output()
                        .map(|o| o.status.success()).unwrap_or(false);
                    ui.horizontal(|ui| {
                        let (dot, dot_color) = if installed { ("●", ACCENT) } else { ("○", TEXT_DIM) };
                        ui.label(RichText::new(dot).size(10.0).color(dot_color));
                        ui.label(RichText::new(*name).size(13.0).color(if installed { TEXT_PRIMARY } else { TEXT_DIM }));
                        ui.add_space(4.0);
                        ui.label(RichText::new(*category).size(10.0).color(TEXT_MUTED));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(RichText::new(if installed { "installed" } else { "not found" }).size(10.0).color(if installed { ACCENT } else { TEXT_DIM }));
                            ui.add_space(8.0);
                            ui.label(RichText::new(*desc).size(10.0).color(TEXT_DIM));
                        });
                    });
                    ui.separator();
                }
            });
        });

        // Nmap Scanner Card
        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                section_title(ui, "NMAP PORT SCANNER");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let btn_label = if self.nmap_running { "Scanning..." } else { "Run Scan" };
                    let btn_color = if self.nmap_running { TEXT_DIM } else { ACCENT };
                    if ui.add(
                        egui::Button::new(RichText::new(btn_label).size(13.0).color(Color32::BLACK))
                            .fill(btn_color)
                            .min_size(Vec2::new(90.0, 28.0))
                    ).clicked() && !self.nmap_running {
                        self.run_nmap_scan();
                    }
                });
            });
            ui.label(RichText::new(format!("Target: {}", self.target)).size(11.0).color(TEXT_MUTED));
            ui.add_space(6.0);
            ScrollArea::vertical().id_salt("nmap_output").max_height(240.0).show(ui, |ui| {
                ui.add(
                    TextEdit::multiline(&mut self.nmap_output)
                        .font(egui::TextStyle::Monospace)
                        .desired_rows(12)
                        .desired_width(f32::INFINITY)
                        .background_color(INPUT_BG)
                );
            });
        });
    }

    pub(crate) fn page_results(&mut self, ui: &mut Ui) {
        card_frame().show(ui, |ui| {
            section_title(ui, "SCAN RESULTS");
            if self.findings.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(60.0);
                    ui.label(RichText::new("✓").size(48.0).color(ACCENT));
                    ui.label(RichText::new("No vulnerabilities found").size(14.0).color(TEXT_PRIMARY));
                });
            } else {
                for f in &self.findings {
                    let color = match f.severity.as_str() { "HIGH" => DANGER, "MEDIUM" => WARN, _ => ACCENT };
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&f.severity).size(11.0).strong().color(color));
                        ui.add_space(20.0);
                        ui.label(RichText::new(&f.module).size(11.0).color(TEXT_PRIMARY));
                        ui.add_space(20.0);
                        ui.label(RichText::new(&f.title).size(11.0).color(TEXT_MUTED));
                    });
                    ui.separator();
                }
            }
            ui.add_space(8.0);
            ui.separator();
            let busy = self.page_ai_busy.contains("results");
            ui.horizontal(|ui| {
                ui.label(RichText::new("AI INTERPRETATION").size(10.0).color(TEXT_DIM));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if busy {
                        ui.spinner();
                        ui.label(RichText::new("Analysing...").size(10.0).color(TEXT_MUTED));
                    } else if ui.add(subtle_button("Analyse")).clicked() && !self.findings.is_empty() {
                        let ctx_str = self.findings.iter().map(|f|
                            format!("[{}] {} — {}", f.severity, f.title, f.module)
                        ).collect::<Vec<_>>().join("\n");
                        let context = format!("Target: {}\nFindings:\n{}", self.target, ctx_str);
                        self.trigger_page_ai("results", context);
                    }
                });
            });
            if let Some(result) = self.page_ai_results.get("results").cloned() {
                ui.add_space(6.0);
                Frame::NONE.fill(Color32::from_rgb(8, 25, 15)).corner_radius(6.0).inner_margin(Margin::same(10)).show(ui, |ui| {
                    ScrollArea::vertical().id_salt("results_ai_scroll").max_height(200.0).show(ui, |ui| {
                        ui.label(RichText::new(&result).size(11.0).color(TEXT_PRIMARY));
                    });
                });
            }
        });
    }


    pub(crate) fn page_encoder(&mut self, ui: &mut Ui) {
        card_frame().show(ui, |ui| {
            section_title(ui, "ENCODER / DECODER / HASH");
            ui.horizontal_wrapped(|ui| {
                for op in Op::all() {
                    let sel = self.enc_op == *op;
                    let btn = egui::Button::new(RichText::new(op.label()).size(10.0).color(if sel { ACCENT } else { TEXT_SECONDARY }))
                        .min_size(Vec2::new(100.0, 26.0))
                        .fill(if sel { Color32::from_rgb(12, 35, 22) } else { INPUT_BG })
                        .stroke(Stroke::new(1.0, if sel { ACCENT } else { BORDER }))
                        .corner_radius(4.0);
                    if ui.add(btn).clicked() { self.enc_op = *op; }
                }
            });
            ui.add_space(12.0);
            
            ui.label(RichText::new("Input").size(11.0).color(TEXT_MUTED));
            ui.add(TextEdit::multiline(&mut self.enc_input).desired_rows(5).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY).background_color(INPUT_BG));
            ui.horizontal(|ui| {
                if ui.add(accent_button("▶ Apply")).clicked() {
                    match crypto::apply(self.enc_op, &self.enc_input) {
                        Ok(o) => self.enc_output = o,
                        Err(e) => self.enc_output = format!("Error: {}", e),
                    }
                }
                if ui.add(subtle_button("Swap")).clicked() { std::mem::swap(&mut self.enc_input, &mut self.enc_output); }
                if ui.add(subtle_button("Copy")).clicked() { ui.ctx().copy_text(self.enc_output.clone()); }
            });
            ui.add_space(8.0);
            
            ui.label(RichText::new("Output").size(11.0).color(TEXT_MUTED));
            ui.add(TextEdit::multiline(&mut self.enc_output).desired_rows(5).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY).background_color(INPUT_BG));
            if !self.enc_output.is_empty() {
                ui.add_space(8.0);
                ui.separator();
                let busy = self.page_ai_busy.contains("encoder");
                ui.horizontal(|ui| {
                    ui.label(RichText::new("AI INTERPRETATION").size(10.0).color(TEXT_DIM));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if busy {
                            ui.spinner();
                            ui.label(RichText::new("Analysing...").size(10.0).color(TEXT_MUTED));
                        } else if ui.add(subtle_button("Analyse")).clicked() {
                            let context = format!(
                                "Operation: {}\nInput: {}\nOutput: {}",
                                self.enc_op.label(), self.enc_input, self.enc_output
                            );
                            self.trigger_page_ai("encoder", context);
                        }
                    });
                });
                if let Some(result) = self.page_ai_results.get("encoder").cloned() {
                    ui.add_space(6.0);
                    Frame::NONE.fill(Color32::from_rgb(8, 25, 15)).corner_radius(6.0).inner_margin(Margin::same(10)).show(ui, |ui| {
                        ScrollArea::vertical().id_salt("encoder_ai_scroll").max_height(160.0).show(ui, |ui| {
                            ui.label(RichText::new(&result).size(11.0).color(TEXT_PRIMARY));
                        });
                    });
                }
            }
        });
    }

    pub(crate) fn page_logs(&mut self, ui: &mut Ui) {
        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                section_title(ui, "APPLICATION LOGS");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add(subtle_button("Clear")).clicked() { self.logs.clear(); }
                });
            });
            Frame::NONE.fill(TERMINAL_BG).corner_radius(8.0).inner_margin(Margin::same(10)).show(ui, |ui| {
                ScrollArea::vertical().id_salt("logs_page").stick_to_bottom(true).show(ui, |ui| {
                    for log in &self.logs {
                        let color = if log.contains("ERROR") { DANGER } else if log.contains("[SCAN]") || log.contains("[DONE]") { ACCENT } else { TEXT_PRIMARY };
                        ui.label(RichText::new(log).size(11.0).monospace().color(color));
                    }
                });
            });
        });
    }

    pub(crate) fn page_history(&mut self, ui: &mut Ui) {
        card_frame().show(ui, |ui| {
            section_title(ui, "SCAN HISTORY");
            if self.scan_history.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(40.0);
                    ui.label(RichText::new("No scan history yet").size(13.0).color(TEXT_MUTED));
                });
            } else {
                for (time, target, findings) in &self.scan_history {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(time).size(11.0).color(TEXT_MUTED));
                        ui.add_space(20.0);
                        ui.label(RichText::new(target).size(12.0).color(TEXT_PRIMARY));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(RichText::new(format!("{} findings", findings)).size(11.0).color(if *findings > 0 { WARN } else { ACCENT }));
                        });
                    });
                    ui.separator();
                }
            }
        });
    }

    pub(crate) fn page_ai(&mut self, ui: &mut Ui) {
        let avail = ui.available_size();
        let pending_extra = if self.pending_nav.is_some() { 44.0 } else { 0.0 };
        // header(52) + provider_label(18) + gap(8) + thinking(36+4) + pending(44) + input_bar(52) + frame_margins(32) = ~210
        let chat_h = (avail.y - 210.0 - pending_extra).max(160.0);

        Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(12.0)
            .inner_margin(Margin::same(16))
            .show(ui, |ui| {
                ui.set_max_width(ui.available_width());
                ui.set_min_height(avail.y - 32.0);

                // ── Header ──────────────────────────────────────────────
                ui.horizontal(|ui| {
                    section_title(ui, "AI SECURITY ASSISTANT");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        // Voice toggle — off by default so the assistant doesn't
                        // read its replies aloud unless the user opts in.
                        let voice_label = if self.tts_enabled { "🔊 Voice on" } else { "🔇 Voice off" };
                        let voice_col = if self.tts_enabled { ACCENT } else { TEXT_DIM };
                        if ui.add(egui::Button::new(RichText::new(voice_label).size(11.0).color(voice_col))
                            .fill(Color32::TRANSPARENT).stroke(Stroke::new(1.0, voice_col)).corner_radius(6.0)).clicked() {
                            self.tts_enabled = !self.tts_enabled;
                            if !self.tts_enabled { self.stop_tts(); }
                        }
                        ui.add_space(8.0);
                        if ui.add(subtle_button("Clear")).clicked() { self.ai_messages.clear(); }
                        ui.add_space(8.0);
                        if !self.ai_queue.is_empty() {
                            if ui.add(
                                egui::Button::new(RichText::new(format!("⏱ {} queued", self.ai_queue.len())).size(10.0).color(Color32::WHITE))
                                    .fill(Color32::from_rgb(80, 60, 0)).corner_radius(4.0)
                            ).on_hover_text("Click to clear the queue").clicked() {
                                self.ai_queue.clear();
                            }
                            ui.add_space(4.0);
                        }
                        if self.ai_busy {
                            if ui.add(
                                egui::Button::new(RichText::new("■ Stop").size(10.0).color(Color32::WHITE))
                                    .fill(Color32::from_rgb(180, 40, 40)).corner_radius(4.0)
                            ).clicked() {
                                self.ai_receiver = None; self.ai_busy = false; self.ai_pending = false; self.ai_queue.clear();
                                self.ai_messages.push(ChatMessage { role: "ai".into(), content: "[Cancelled]".into() });
                            }
                        }
                    });
                });
                let asst_model = if self.ws_fast_model.trim().is_empty() { self.ai_model.clone() } else { self.ws_fast_model.clone() };
                ui.label(RichText::new(format!("{} | {} · knowledge-only librarian (run tasks in Workspace)", self.ai_provider.label(), asst_model)).size(10.0).color(TEXT_MUTED));
                ui.add_space(8.0);

                // ── Chat area ────────────────────────────────────────────
                Frame::NONE.fill(TERMINAL_BG).corner_radius(8.0).inner_margin(Margin::same(12)).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ScrollArea::vertical()
                        .id_salt("ai_chat")
                        .min_scrolled_height(chat_h)
                        .max_height(chat_h)
                        .stick_to_bottom(true)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            let bubble_w = (ui.available_width() * 0.78).max(160.0);
                            for msg in &self.ai_messages.clone() {
                                let is_user = msg.role == "user";
                                // User bubbles hug the right, assistant bubbles the left.
                                let layout = if is_user {
                                    Layout::top_down(Align::Max)
                                } else {
                                    Layout::top_down(Align::Min)
                                };
                                ui.with_layout(layout, |ui| {
                                    let (label, lc, bg, brd, tc) = if is_user {
                                        ("You", ACCENT, Color32::from_rgb(12, 35, 22), Color32::from_rgb(0, 80, 40), TEXT_PRIMARY)
                                    } else {
                                        ("AI", Color32::from_rgb(100, 200, 255), Color32::from_rgb(14, 22, 36), Color32::from_rgb(0, 70, 120), TEXT_SECONDARY)
                                    };
                                    ui.label(RichText::new(label).size(10.0).strong().color(lc));
                                    // Bubble sizes to content (capped at bubble_w); the
                                    // parent Align (Max for user / Min for AI) pins it to
                                    // the correct edge so user text hugs the far right.
                                    Frame::NONE.fill(bg).stroke(Stroke::new(1.0, brd)).corner_radius(8.0)
                                        .inner_margin(Margin::same(8)).show(ui, |ui| {
                                        ui.set_max_width(bubble_w);
                                        ui.label(RichText::new(&msg.content).size(12.0).color(tc));
                                    });
                                });
                                ui.add_space(10.0);
                            }
                        });
                });

                // ── Thinking bubble ──────────────────────────────────────
                if self.ai_busy {
                    let t = ui.input(|i| i.time);
                    let dots = match ((t * 2.0) as usize) % 4 { 0 => ".", 1 => "..", 2 => "...", _ => "" };
                    ui.add_space(4.0);
                    Frame::NONE.fill(Color32::from_rgb(14, 22, 36))
                        .stroke(Stroke::new(1.0, Color32::from_rgb(0, 100, 180)))
                        .corner_radius(6.0).inner_margin(Margin::same(8))
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.label(RichText::new(format!("⏳ Working{}", dots)).size(11.0).color(Color32::from_rgb(100, 180, 255)));
                        });
                    ui.add_space(4.0);
                }

                // ── Pending nav ──────────────────────────────────────────
                if let Some(nav) = self.pending_nav.clone() {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("📍 AI suggests: {}", nav)).size(11.0).color(WARN));
                        if ui.add(accent_button("Go →")).clicked() { self.selected_nav = nav; self.pending_nav = None; }
                        if ui.add(subtle_button("Dismiss")).clicked() { self.pending_nav = None; }
                    });
                    ui.add_space(4.0);
                }

                // ── Input bar ────────────────────────────────────────────
                ui.add_space(8.0);
                let send_w = 90.0;
                let input_w = (ui.available_width() - send_w - 10.0 - 14.0).max(80.0);
                ui.horizontal_top(|ui| {
                    let resp = ui.add(
                        TextEdit::singleline(&mut self.ai_input)
                            .hint_text("Ask me about security, payloads, or request analysis...")
                            .desired_width(input_w)
                            .min_size(Vec2::new(input_w, 40.0))
                            .background_color(INPUT_BG)
                    );
                    let can_send = !self.ai_busy && !self.ai_pending;
                    if can_send {
                        if (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                            || ui.add_sized(
                                Vec2::new(send_w, 40.0),
                                egui::Button::new(RichText::new("Send").size(12.0).color(Color32::BLACK))
                                    .fill(ACCENT).corner_radius(8.0)
                            ).clicked()
                        {
                            self.send_ai();
                        }
                    } else {
                        ui.add_sized(Vec2::new(send_w, 40.0),
                            egui::Button::new(RichText::new("Send").size(12.0).color(TEXT_DIM))
                                .fill(Color32::from_rgb(30, 36, 48))
                        );
                    }
                });
                ui.label(RichText::new("Enter to send").size(9.0).color(TEXT_MUTED));
            });
}
}
