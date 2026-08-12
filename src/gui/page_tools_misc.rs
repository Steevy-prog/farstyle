// Timeline, Spider, Passive Scan, Scripting and WebSocket pages.
// Split out of the GUI monolith; see gui/mod.rs.

use super::*;

impl NullForgeApp {

    // ═══════════════════════════════════════════════════════════════════════
    // TIMELINE / AUDIT LOG PAGE
    // ═══════════════════════════════════════════════════════════════════════
    pub(crate) fn page_timeline(&mut self, ui: &mut Ui) {
        let avail = ui.available_size();

        // ── Header row ────────────────────────────────────────────────────
        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                section_title(ui, "TIMELINE & AUDIT LOG");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add(subtle_button("Clear Log")).clicked() {
                        self.audit_log.clear();
                    }
                    if ui.add(subtle_button("Export CSV")).clicked() {
                        let mut csv = String::from("Timestamp,Category,Message\n");
                        for (ts, cat, msg) in &self.audit_log {
                            csv.push_str(&format!("{},{},\"{}\"\n", ts, cat, msg.replace('"', "\"\"")));
                        }
                        let path = format!("{}/farstyle_audit_{}.csv",
                            std::env::var("HOME").unwrap_or_else(|_| ".".into()),
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs()).unwrap_or(0));
                        if std::fs::write(&path, csv).is_ok() {
                            self.push_toast(format!("Exported to {}", path), ACCENT);
                        } else {
                            self.push_toast("Export failed".to_string(), DANGER);
                        }
                    }
                });
            });
            ui.add_space(4.0);
            ui.label(RichText::new(format!("{} events recorded  ·  auto-captures findings, scope violations, AI actions, OSINT queries",
                self.audit_log.len())).size(10.0).color(TEXT_MUTED));
        });

        ui.add_space(8.0);

        // ── Category filter pills ─────────────────────────────────────────
        let categories = ["ALL", "FINDING", "SCOPE", "AI", "OSINT", "SYSTEM"];
        // Use a simple string in a local we can compare
        let filter_key = "timeline_filter";
        let mut filter_val = ui.data(|d| d.get_temp::<String>(egui::Id::new(filter_key)))
            .unwrap_or_else(|| "ALL".into());
        ui.horizontal_wrapped(|ui| {
            for cat in &categories {
                let sel = filter_val == *cat;
                let count = if *cat == "ALL" { self.audit_log.len() } else {
                    self.audit_log.iter().filter(|(_, c, _)| c == *cat).count()
                };
                if ui.add(
                    egui::Button::new(
                        RichText::new(format!("{}  ({})", cat, count)).size(11.0)
                            .color(if sel { Color32::BLACK } else { TEXT_SECONDARY })
                    )
                    .fill(if sel { ACCENT } else { Color32::from_rgb(22, 30, 44) })
                    .stroke(Stroke::new(1.0, if sel { ACCENT } else { BORDER }))
                    .corner_radius(12.0)
                ).clicked() {
                    filter_val = cat.to_string();
                }
                ui.add_space(2.0);
            }
        });
        ui.data_mut(|d| d.insert_temp(egui::Id::new(filter_key), filter_val.clone()));
        ui.add_space(8.0);

        // ── Table ─────────────────────────────────────────────────────────
        let table_h = (avail.y - 120.0).max(200.0);
        Frame::NONE.fill(TERMINAL_BG).corner_radius(8.0).inner_margin(Margin::same(0)).show(ui, |ui| {
            // Header
            Frame::NONE.fill(Color32::from_rgb(20, 28, 40)).inner_margin(Margin::symmetric(12, 8)).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("TIME").size(10.0).strong().color(TEXT_DIM));
                    ui.add_space(50.0);
                    ui.label(RichText::new("CATEGORY").size(10.0).strong().color(TEXT_DIM));
                    ui.add_space(60.0);
                    ui.label(RichText::new("EVENT").size(10.0).strong().color(TEXT_DIM));
                });
            });
            ui.separator();

            ScrollArea::vertical()
                .id_salt("timeline_scroll")
                .max_height(table_h)
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                let log = self.audit_log.clone();
                let filtered: Vec<&(String, String, String)> = log.iter()
                    .filter(|(_, cat, _)| filter_val == "ALL" || cat == &filter_val)
                    .collect();

                if filtered.is_empty() {
                    ui.add_space(60.0);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("📋").size(36.0).color(TEXT_DIM));
                        ui.label(RichText::new("No events recorded yet").size(13.0).color(TEXT_PRIMARY));
                        ui.label(RichText::new("Events are captured automatically as you use the tool").size(10.0).color(TEXT_MUTED));
                    });
                    return;
                }

                for (ts, cat, msg) in filtered.iter().rev() {
                    let cat_color = match cat.as_str() {
                        "FINDING" => DANGER,
                        "SCOPE"   => WARN,
                        "AI"      => Color32::from_rgb(100, 200, 255),
                        "OSINT"   => Color32::from_rgb(140, 255, 140),
                        _         => TEXT_MUTED,
                    };
                    let cat_bg = match cat.as_str() {
                        "FINDING" => Color32::from_rgba_unmultiplied(255, 60, 60, 18),
                        "SCOPE"   => Color32::from_rgba_unmultiplied(255, 160, 0, 18),
                        "AI"      => Color32::from_rgba_unmultiplied(60, 160, 255, 12),
                        "OSINT"   => Color32::from_rgba_unmultiplied(60, 200, 60, 12),
                        _         => Color32::TRANSPARENT,
                    };
                    Frame::NONE.fill(cat_bg).inner_margin(Margin::symmetric(12, 5)).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(ts.as_str()).size(10.5).monospace().color(TEXT_DIM));
                            ui.add_space(8.0);
                            Frame::NONE
                                .fill(cat_color.linear_multiply(0.18))
                                .stroke(Stroke::new(1.0, cat_color.linear_multiply(0.5)))
                                .corner_radius(4.0)
                                .inner_margin(Margin::symmetric(6, 2))
                                .show(ui, |ui| {
                                ui.label(RichText::new(cat.as_str()).size(9.0).strong().color(cat_color));
                            });
                            ui.add_space(8.0);
                            ui.label(RichText::new(msg.as_str()).size(11.0).color(TEXT_SECONDARY));
                        });
                    });
                    ui.separator();
                }
            });
        });
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SPIDER PAGE
    // ═══════════════════════════════════════════════════════════════════════
    pub(crate) fn page_spider(&mut self, ui: &mut egui::Ui) {
        card_frame().show(ui, |ui| {
            section_title(ui, "SPIDER / CRAWLER");
            ui.horizontal(|ui| {
                for tab in ["Config", "Results"] {
                    let sel = self.spider_tab == tab;
                    if ui.add(egui::Button::new(RichText::new(tab).size(12.0).color(if sel { ACCENT } else { TEXT_SECONDARY }))
                        .fill(Color32::TRANSPARENT).stroke(Stroke::NONE).min_size(Vec2::new(0.0, 24.0))).clicked() {
                        self.spider_tab = tab.into();
                    }
                    ui.add_space(12.0);
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new(format!("{} pages crawled", self.spider_results.len())).size(10.0).color(TEXT_DIM));
                });
            });
        });
        ui.add_space(6.0);

        if self.spider_tab == "Config" {
            card_frame().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Seed URL").size(11.0).color(TEXT_MUTED));
                    ui.add_space(8.0);
                    ui.add(TextEdit::singleline(&mut self.spider_config.seed_url)
                        .desired_width(f32::INFINITY).background_color(INPUT_BG)
                        .hint_text("https://target.com"));
                });
                ui.add_space(6.0);
                ui.columns(3, |cols| {
                    cols[0].horizontal(|ui| {
                        ui.label(RichText::new("Max depth").size(11.0).color(TEXT_MUTED));
                        ui.add(egui::DragValue::new(&mut self.spider_config.max_depth).range(1..=20));
                    });
                    cols[1].horizontal(|ui| {
                        ui.label(RichText::new("Max pages").size(11.0).color(TEXT_MUTED));
                        ui.add(egui::DragValue::new(&mut self.spider_config.max_pages).range(1..=2000));
                    });
                    cols[2].horizontal(|ui| {
                        ui.label(RichText::new("Delay (ms)").size(11.0).color(TEXT_MUTED));
                        ui.add(egui::DragValue::new(&mut self.spider_config.delay_ms).range(0..=5000));
                    });
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.spider_config.scope_strict, "Strict scope (same host only)");
                    ui.add_space(16.0);
                    ui.checkbox(&mut self.spider_config.follow_ext, "Follow static assets (.js/.css/…)");
                });
                ui.add_space(6.0);
                // Use auth from Settings if enabled
                if self.auth_enabled {
                    self.spider_config.bearer = self.auth_bearer.clone();
                    self.spider_config.cookie = self.auth_cookie.clone();
                    ui.label(RichText::new("🔐 Auth injection ON — using credentials from Settings").size(10.0).color(ACCENT));
                } else {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Bearer").size(11.0).color(TEXT_MUTED));
                        ui.add(TextEdit::singleline(&mut self.spider_config.bearer).password(true).desired_width(240.0).background_color(INPUT_BG));
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Cookie ").size(11.0).color(TEXT_MUTED));
                        ui.add(TextEdit::singleline(&mut self.spider_config.cookie).password(true).desired_width(240.0).background_color(INPUT_BG));
                    });
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if !self.spider_running {
                        if ui.add(accent_button("▶  Start crawl")).clicked() {
                            self.spider_results.clear();
                            let cfg = self.spider_config.clone();
                            let (rx, stop_tx) = crate::spider::start(cfg);
                            self.spider_receiver = Some(rx);
                            self.spider_stop_tx  = Some(stop_tx);
                            self.spider_running  = true;
                            self.spider_tab      = "Results".into();
                        }
                    } else {
                        if ui.add(egui::Button::new(RichText::new("■  Stop").size(12.0).color(TEXT_PRIMARY))
                            .fill(Color32::from_rgb(160, 50, 50)).corner_radius(6.0).min_size(Vec2::new(90.0, 28.0))).clicked() {
                            if let Some(ref tx) = self.spider_stop_tx { let _ = tx.send(true); }
                            self.spider_running = false;
                        }
                        ui.add_space(8.0);
                        ui.label(RichText::new(format!("Crawling… {} pages", self.spider_results.len())).size(11.0).color(ACCENT));
                    }
                });
            });
        } else {
            // Results tab
            card_frame().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Filter URL:").size(11.0).color(TEXT_MUTED));
                    ui.add_space(4.0);
                    ui.add(TextEdit::singleline(&mut self.spider_filter).desired_width(300.0).background_color(INPUT_BG).hint_text("api, admin, login…"));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.add(subtle_button("Clear")).clicked() { self.spider_results.clear(); }
                        if ui.add(subtle_button("Export CSV")).clicked() {
                            let csv: String = "URL,Status,Content-Type,Length,Depth\n".to_string()
                                + &self.spider_results.iter().map(|r| format!("{},{},{},{},{}", r.url, r.status, r.content_type, r.length, r.depth)).collect::<Vec<_>>().join("\n");
                            if let Some(path) = rfd::FileDialog::new().add_filter("CSV", &["csv"]).save_file() {
                                let _ = std::fs::write(path, csv);
                            }
                        }
                    });
                });
                ui.add_space(6.0);
                // Header row
                Frame::NONE.fill(Color32::from_rgb(14, 20, 30)).inner_margin(Margin::symmetric(10, 6)).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Status").size(10.0).strong().color(TEXT_DIM));
                        ui.add_space(10.0);
                        ui.label(RichText::new("URL").size(10.0).strong().color(TEXT_DIM));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(RichText::new("Depth").size(10.0).strong().color(TEXT_DIM));
                            ui.add_space(16.0);
                            ui.label(RichText::new("Length").size(10.0).strong().color(TEXT_DIM));
                            ui.add_space(16.0);
                            ui.label(RichText::new("Links").size(10.0).strong().color(TEXT_DIM));
                        });
                    });
                });
                let filter = self.spider_filter.to_lowercase();
                let results_snap: Vec<crate::spider::SpiderResult> = self.spider_results.iter()
                    .filter(|r| filter.is_empty() || r.url.to_lowercase().contains(&filter))
                    .cloned()
                    .collect();
                ScrollArea::vertical().id_salt("spider_results").show(ui, |ui| {
                    for r in &results_snap {
                        let bg = if r.status >= 200 && r.status < 300 { Color32::TRANSPARENT }
                                 else if r.status >= 400 { Color32::from_rgb(30, 10, 10) }
                                 else { Color32::TRANSPARENT };
                        Frame::NONE.fill(bg).inner_margin(Margin::symmetric(10, 4)).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let sc = status_color(r.status);
                                ui.label(RichText::new(format!("{}", r.status)).size(11.0).strong().color(sc));
                                ui.add_space(8.0);
                                ui.label(RichText::new(&r.url).size(11.0).monospace().color(TEXT_PRIMARY));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(RichText::new(format!("d{}", r.depth)).size(10.0).color(TEXT_DIM));
                                    ui.add_space(10.0);
                                    ui.label(RichText::new(format!("{}", r.length)).size(10.0).color(TEXT_MUTED));
                                    ui.add_space(10.0);
                                    ui.label(RichText::new(format!("{} lnk", r.links_found)).size(10.0).color(TEXT_MUTED));
                                });
                            });
                            if !r.note.is_empty() {
                                ui.label(RichText::new(&r.note).size(10.0).color(DANGER));
                            }
                        });
                        ui.separator();
                    }
                });
                if !results_snap.is_empty() {
                    ui.add_space(8.0);
                    ui.separator();
                    let busy = self.page_ai_busy.contains("spider");
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("AI INTERPRETATION").size(10.0).color(TEXT_DIM));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if busy {
                                ui.spinner();
                            } else if ui.add(subtle_button("Analyse crawl")).clicked() {
                                let ctx_str = results_snap.iter().map(|r|
                                    format!("{} {} ({} bytes, {} links) {}", r.status, r.url, r.length, r.links_found, r.note)
                                ).collect::<Vec<_>>().join("\n");
                                let context = format!("Spider crawl of {}:\n{}", self.target, ctx_str);
                                self.trigger_page_ai("spider", context);
                            }
                        });
                    });
                    if let Some(result) = self.page_ai_results.get("spider").cloned() {
                        ui.add_space(6.0);
                        egui::Frame::NONE.fill(Color32::from_rgb(8, 20, 14)).corner_radius(6.0).inner_margin(egui::Margin::same(8)).show(ui, |ui| {
                            egui::ScrollArea::vertical().id_salt("spider_ai_scroll").max_height(140.0).show(ui, |ui| {
                                ui.label(RichText::new(&result).size(11.0).color(TEXT_PRIMARY));
                            });
                        });
                    }
                }
            });
        }
    }

    pub(crate) fn poll_spider(&mut self) {
        if !self.spider_running { return; }
        let mut done = false;
        if let Some(ref rx) = self.spider_receiver {
            loop {
                match rx.try_recv() {
                    Ok(r)  => { self.spider_results.push(r); }
                    Err(std::sync::mpsc::TryRecvError::Empty)        => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => { done = true; break; }
                }
            }
        }
        if done { self.spider_running = false; self.spider_receiver = None; }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SCRIPTING PAGE
    // ═══════════════════════════════════════════════════════════════════════
    pub(crate) fn page_scripting(&mut self, ui: &mut egui::Ui) {
        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                section_title(ui, "RULE ENGINE / SCRIPTING");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    for tab in ["Rules", "Log"] {
                        let sel = self.script_tab == tab;
                        if ui.add(egui::Button::new(RichText::new(tab).size(11.0).color(if sel { ACCENT } else { TEXT_SECONDARY }))
                            .fill(Color32::TRANSPARENT).stroke(Stroke::NONE)).clicked() {
                            self.script_tab = tab.into();
                        }
                        ui.add_space(4.0);
                    }
                });
            });
        });
        ui.add_space(6.0);

        if self.script_tab == "Rules" {
            let avail = ui.available_size();
            let list_w = (avail.x * 0.38).max(160.0);
            let edit_w = (avail.x - list_w - 8.0 - 24.0).max(120.0);
            let h = (avail.y - 10.0).max(200.0);
            let selected_idx = self.script_editor_idx;

            ui.horizontal_top(|ui| {
                // Rule list
                ui.allocate_ui_with_layout(Vec2::new(list_w, h), Layout::top_down(Align::LEFT), |ui| {
                    card_frame().show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Rules").size(11.0).strong().color(TEXT_PRIMARY));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.add(subtle_button("+ New")).clicked() {
                                    let name = if self.script_new_name.trim().is_empty() {
                                        format!("Rule {}", self.script_rules.len() + 1)
                                    } else {
                                        self.script_new_name.trim().to_string()
                                    };
                                    let id = format!("user-{}", self.script_rules.len());
                                    self.script_rules.push(crate::scripting::Rule::new(id, name));
                                    self.script_editor_idx = Some(self.script_rules.len() - 1);
                                    self.script_new_name.clear();
                                }
                            });
                        });
                        ui.add(TextEdit::singleline(&mut self.script_new_name)
                            .desired_width(f32::INFINITY).background_color(INPUT_BG).hint_text("New rule name…"));
                        ui.add_space(6.0);
                        ScrollArea::vertical().id_salt("rule_list").show(ui, |ui| {
                            let mut to_del: Option<usize> = None;
                            for (i, rule) in self.script_rules.iter_mut().enumerate() {
                                let sel = selected_idx == Some(i);
                                Frame::NONE
                                    .fill(if sel { Color32::from_rgb(0, 40, 25) } else { INPUT_BG })
                                    .stroke(Stroke::new(1.0, if sel { ACCENT } else { BORDER }))
                                    .corner_radius(6.0).inner_margin(Margin::symmetric(8, 5))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.checkbox(&mut rule.enabled, "");
                                            let resp = ui.add(egui::Label::new(
                                                RichText::new(&rule.name).size(11.0).color(if sel { ACCENT } else { TEXT_PRIMARY })
                                            ).sense(egui::Sense::click()));
                                            if resp.clicked() { /* handled below via index */ }
                                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                                if ui.add(egui::Button::new(RichText::new("✕").size(10.0).color(DANGER))
                                                    .fill(Color32::TRANSPARENT)).clicked() { to_del = Some(i); }
                                            });
                                        });
                                        ui.label(RichText::new(format!("{} conds  {} actions", rule.matches.len(), rule.actions.len())).size(9.0).color(TEXT_DIM));
                                    }); // click handled by the ui.interact() below
                                if ui.interact(ui.min_rect(), egui::Id::new(("rl_row", i)), egui::Sense::click()).clicked() {
                                    self.script_editor_idx = Some(i);
                                }
                                ui.add_space(3.0);
                            }
                            if let Some(d) = to_del {
                                self.script_rules.remove(d);
                                self.script_editor_idx = None;
                            }
                        });
                    });
                });
                ui.add_space(8.0);
                // Rule editor
                ui.allocate_ui_with_layout(Vec2::new(edit_w, h), Layout::top_down(Align::LEFT), |ui| {
                    card_frame().show(ui, |ui| {
                        if let Some(idx) = self.script_editor_idx {
                            // Render editable name/enabled fields
                            if let Some(rule) = self.script_rules.get_mut(idx) {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("Name:").size(11.0).color(TEXT_MUTED));
                                    ui.add(TextEdit::singleline(&mut rule.name).desired_width(200.0).background_color(INPUT_BG));
                                    ui.checkbox(&mut rule.enabled, "Enabled");
                                });
                            }
                            ui.add_space(8.0);
                            ui.label(RichText::new("Match conditions (JSON array)").size(10.0).color(TEXT_MUTED));
                            ui.label(RichText::new(r#"e.g. [{"UrlContains":"/admin"}, {"ResponseStatusIs":500}]"#).size(9.0).color(TEXT_DIM));
                            ui.add(TextEdit::multiline(&mut self.script_match_input)
                                .font(egui::TextStyle::Monospace).desired_width(f32::INFINITY)
                                .background_color(INPUT_BG).desired_rows(5)
                                .hint_text(r#"[{"UrlContains": "/api/v1"}]"#));
                            ui.add_space(6.0);
                            ui.label(RichText::new("Actions (JSON array)").size(10.0).color(TEXT_MUTED));
                            ui.label(RichText::new(r#"e.g. [{"FlagAsInteresting":null}, {"Highlight":"red"}]"#).size(9.0).color(TEXT_DIM));
                            ui.add(TextEdit::multiline(&mut self.script_action_input)
                                .font(egui::TextStyle::Monospace).desired_width(f32::INFINITY)
                                .background_color(INPUT_BG).desired_rows(5)
                                .hint_text(r#"[{"LogMessage": "Hit!"}, "FlagAsInteresting"]"#));
                            ui.add_space(8.0);
                            let apply_clicked = ui.horizontal(|ui| {
                                let a = ui.add(accent_button("Apply JSON")).clicked();
                                ui.add_space(8.0);
                                let l = ui.add(subtle_button("Load into editor")).clicked();
                                (a, l)
                            }).inner;
                            // Apply JSON — deferred outside get_mut borrow
                            if apply_clicked.0 {
                                let ms   = serde_json::from_str::<Vec<crate::scripting::MatchField>>(&self.script_match_input).ok();
                                let acts = serde_json::from_str::<Vec<crate::scripting::RuleAction>>(&self.script_action_input).ok();
                                if let Some(rule) = self.script_rules.get_mut(idx) {
                                    if let Some(m) = ms   { rule.matches  = m; }
                                    if let Some(a) = acts { rule.actions  = a; }
                                }
                                self.push_toast("Rule updated".to_string(), ACCENT);
                            }
                            if apply_clicked.1 {
                                if let Some(rule) = self.script_rules.get(idx) {
                                    self.script_match_input  = serde_json::to_string_pretty(&rule.matches).unwrap_or_default();
                                    self.script_action_input = serde_json::to_string_pretty(&rule.actions).unwrap_or_default();
                                }
                            }
                        } else {
                            ui.vertical_centered(|ui| {
                                ui.add_space(40.0);
                                ui.label(RichText::new("Select a rule to edit").size(12.0).color(TEXT_DIM));
                            });
                        }
                    });
                });
            });
        } else {
            // Log tab
            card_frame().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Rule Engine Log").size(11.0).strong().color(TEXT_PRIMARY));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.add(subtle_button("Clear")).clicked() { self.script_log.clear(); }
                    });
                });
                ui.add_space(4.0);
                ScrollArea::vertical().id_salt("script_log").stick_to_bottom(true).show(ui, |ui| {
                    for msg in &self.script_log {
                        ui.label(RichText::new(msg).size(10.0).monospace().color(TEXT_SECONDARY));
                    }
                });
            });
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WEBSOCKET PAGE
    // ═══════════════════════════════════════════════════════════════════════
    pub(crate) fn page_websocket(&mut self, ui: &mut egui::Ui) {
        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                section_title(ui, "WEBSOCKET CAPTURES");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add(subtle_button("Clear")).clicked() {
                        self.ws_captures.clear();
                        self.ws_selected = None;
                    }
                    ui.label(RichText::new(format!("{} frames", self.ws_captures.len())).size(10.0).color(TEXT_DIM));
                });
            });
            ui.add_space(4.0);
            ui.label(RichText::new("WebSocket frames are captured automatically when the proxy intercepts a WS Upgrade handshake. Enable the proxy and configure your browser to route traffic through it.").size(10.0).color(TEXT_DIM));
        });
        ui.add_space(6.0);

        let avail = ui.available_size();
        let list_w = (avail.x * 0.45).max(180.0);
        let detail_w = (avail.x - list_w - 8.0 - 24.0).max(120.0);
        let h = (avail.y - 10.0).max(200.0);
        let selected = self.ws_selected;

        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(Vec2::new(list_w, h), Layout::top_down(Align::LEFT), |ui| {
                card_frame().show(ui, |ui| {
                    // Header
                    Frame::NONE.fill(Color32::from_rgb(14,20,30)).inner_margin(Margin::symmetric(8, 5)).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("#").size(9.0).strong().color(TEXT_DIM));
                            ui.add_space(8.0);
                            ui.label(RichText::new("Dir").size(9.0).strong().color(TEXT_DIM));
                            ui.add_space(8.0);
                            ui.label(RichText::new("Payload preview").size(9.0).strong().color(TEXT_DIM));
                        });
                    });
                    ScrollArea::vertical().id_salt("ws_list").show(ui, |ui| {
                        let n = self.ws_captures.len();
                        for i in 0..n {
                            let cap = &self.ws_captures[i];
                            let sel = selected == Some(i);
                            let dir_label = match cap.direction {
                                WsDirection::ClientToServer => "→ C2S",
                                WsDirection::ServerToClient => "← S2C",
                            };
                            let dir_col = match cap.direction {
                                WsDirection::ClientToServer => Color32::from_rgb(100, 200, 255),
                                WsDirection::ServerToClient => Color32::from_rgb(255, 180, 100),
                            };
                            let preview = std::str::from_utf8(&cap.payload).unwrap_or("[binary]")
                                .chars().take(60).collect::<String>();
                            let resp = Frame::NONE
                                .fill(if sel { Color32::from_rgb(0,40,25) } else { Color32::TRANSPARENT })
                                .stroke(Stroke::new(if sel { 1.0 } else { 0.0 }, ACCENT))
                                .corner_radius(5.0).inner_margin(Margin::symmetric(8, 4))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new(format!("{}", cap.id)).size(9.0).monospace().color(TEXT_DIM));
                                        ui.add_space(6.0);
                                        ui.label(RichText::new(dir_label).size(10.0).strong().color(dir_col));
                                        ui.add_space(6.0);
                                        ui.label(RichText::new(&preview).size(10.0).monospace().color(TEXT_SECONDARY));
                                    });
                                }).response;
                            if resp.interact(egui::Sense::click()).clicked() {
                                self.ws_selected = Some(i);
                            }
                            ui.add_space(1.0);
                        }
                    });
                });
            });
            ui.add_space(8.0);
            ui.allocate_ui_with_layout(Vec2::new(detail_w, h), Layout::top_down(Align::LEFT), |ui| {
                card_frame().show(ui, |ui| {
                    if let Some(idx) = selected {
                        if let Some(cap) = self.ws_captures.get(idx) {
                            let dir_label = match cap.direction {
                                WsDirection::ClientToServer => "Client → Server",
                                WsDirection::ServerToClient => "Server → Client",
                            };
                            ui.label(RichText::new(dir_label).size(11.0).strong().color(ACCENT));
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Host:").size(10.0).color(TEXT_MUTED));
                                ui.label(RichText::new(&cap.host).size(11.0).monospace().color(TEXT_PRIMARY));
                            });
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Opcode:").size(10.0).color(TEXT_MUTED));
                                let op_label = match cap.opcode {
                                    1 => "Text", 2 => "Binary", 8 => "Close", 9 => "Ping", 10 => "Pong", _ => "Unknown"
                                };
                                ui.label(RichText::new(format!("{} ({})", op_label, cap.opcode)).size(11.0).color(TEXT_PRIMARY));
                            });
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Length:").size(10.0).color(TEXT_MUTED));
                                ui.label(RichText::new(format!("{} bytes", cap.payload.len())).size(11.0).color(TEXT_PRIMARY));
                            });
                            ui.add_space(8.0);
                            ui.label(RichText::new("Payload (text)").size(10.0).color(TEXT_MUTED));
                            let text_payload = std::str::from_utf8(&cap.payload).unwrap_or("[binary data]").to_string();
                            let mut text_payload_mut = text_payload;
                            ui.add(TextEdit::multiline(&mut text_payload_mut)
                                .font(egui::TextStyle::Monospace).desired_width(f32::INFINITY)
                                .background_color(INPUT_BG).desired_rows(8));
                            ui.add_space(8.0);
                            if !cap.note.is_empty() {
                                ui.label(RichText::new(&cap.note).size(10.0).color(WARN));
                            }
                        }
                    } else {
                        ui.vertical_centered(|ui| {
                            ui.add_space(40.0);
                            ui.label(RichText::new("Select a frame to inspect").size(12.0).color(TEXT_DIM));
                            ui.add_space(8.0);
                            ui.label(RichText::new("No captures yet — route WebSocket traffic through the proxy").size(11.0).color(TEXT_DIM));
                        });
                    }
                    // ── AI interpretation ──────────────────────────────────
                    if !self.ws_captures.is_empty() {
                        ui.add_space(8.0);
                        ui.separator();
                        let busy = self.page_ai_busy.contains("websocket");
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("AI INTERPRETATION").size(10.0).color(TEXT_DIM));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if busy {
                                    ui.spinner();
                                } else if ui.add(subtle_button("Analyse traffic")).clicked() {
                                    let ctx_str = self.ws_captures.iter().rev().take(30).map(|c| {
                                        let dir = if c.direction == WsDirection::ServerToClient { "←" } else { "→" };
                                        let text = std::str::from_utf8(&c.payload).unwrap_or("[binary]");
                                        format!("{} {}", dir, text.chars().take(200).collect::<String>())
                                    }).collect::<Vec<_>>().join("\n");
                                    let context = format!("WebSocket traffic (last 30 frames):\n{}", ctx_str);
                                    self.trigger_page_ai("websocket", context);
                                }
                            });
                        });
                        if let Some(result) = self.page_ai_results.get("websocket").cloned() {
                            ui.add_space(6.0);
                            egui::Frame::NONE.fill(Color32::from_rgb(8, 20, 14)).corner_radius(6.0).inner_margin(egui::Margin::same(8)).show(ui, |ui| {
                                egui::ScrollArea::vertical().id_salt("ws_ai_scroll").max_height(120.0).show(ui, |ui| {
                                    ui.label(RichText::new(&result).size(11.0).color(TEXT_PRIMARY));
                                });
                            });
                        }
                    }
                });
            });
        });
    }
}
