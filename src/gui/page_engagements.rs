// Engagements page + its per-tab renderers (overview, findings, targets,
// scope, notes, PoCs, HTTP history, report). Split out of the GUI monolith.

use super::*;

impl NullForgeApp {
    // ENGAGEMENTS PAGE
    // ═══════════════════════════════════════════════════════════════════════
    pub(crate) fn page_engagements(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            // Left panel — engagement list
            ui.vertical(|ui| {
                ui.set_min_width(220.0);
                ui.set_max_width(220.0);

                card_frame().show(ui, |ui| {
                    section_title(ui, "ENGAGEMENTS");

                    // New engagement form
                    ui.label(RichText::new("New Engagement").size(11.0).color(TEXT_MUTED));
                    ui.add_space(4.0);
                    ui.add(TextEdit::singleline(&mut self.eng_new_name)
                        .hint_text("Name (e.g. ACME Corp Q4)")
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace));
                    ui.add_space(4.0);
                    ui.add(TextEdit::singleline(&mut self.eng_new_client)
                        .hint_text("Client name")
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace));
                    ui.add_space(6.0);
                    if ui.add(accent_button("+ Create")).clicked() && !self.eng_new_name.trim().is_empty() {
                        let e = Engagement::new(self.eng_new_name.trim(), self.eng_new_client.trim());
                        e.save();
                        self.engagements.insert(0, e);
                        self.active_engagement_idx = Some(0);
                        self.eng_new_name.clear();
                        self.eng_new_client.clear();
                        self.engagement_tab = "Overview".into();
                        self.save_config();
                    }

                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(8.0);

                    ScrollArea::vertical().id_salt("eng_list").show(ui, |ui| {
                        let count = self.engagements.len();
                        for i in 0..count {
                            let e = &self.engagements[i];
                            let active = self.active_engagement_idx == Some(i);
                            let counts = e.severity_counts();
                            let badge = if counts[0] > 0 { format!("{}C", counts[0]) }
                                else if counts[1] > 0 { format!("{}H", counts[1]) }
                                else { format!("{}F", e.findings.len()) };
                            let badge_color = if counts[0] > 0 { DANGER } else if counts[1] > 0 { WARN } else { TEXT_MUTED };

                            let resp = Frame::NONE
                                .fill(if active { Color32::from_rgb(12, 35, 22) } else { Color32::TRANSPARENT })
                                .stroke(if active { Stroke::new(1.0, ACCENT) } else { Stroke::NONE })
                                .corner_radius(6.0)
                                .inner_margin(Margin::symmetric(8, 6))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.vertical(|ui| {
                                            ui.label(RichText::new(&e.name).size(12.0)
                                                .color(if active { ACCENT } else { TEXT_PRIMARY }).strong());
                                            ui.label(RichText::new(format!("{} • {}", e.status.label(), e.updated_at.get(..10).unwrap_or("")))
                                                .size(9.0).color(TEXT_MUTED));
                                        });
                                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                            ui.label(RichText::new(&badge).size(10.0).color(badge_color));
                                        });
                                    });
                                });
                            if resp.response.interact(egui::Sense::click()).clicked() {
                                self.active_engagement_idx = Some(i);
                                self.engagement_tab = "Overview".into();
                                self.save_config();
                            }
                            ui.add_space(2.0);
                        }
                    });
                });
            });

            ui.add_space(12.0);

            // Right panel — active engagement detail
            if let Some(idx) = self.active_engagement_idx {
                if idx < self.engagements.len() {
                    ui.vertical(|ui| {
                        ui.set_min_width(200.0);

                        // Tab bar
                        card_frame().show(ui, |ui| {
                            ui.horizontal(|ui| {
                                for tab in ["Overview", "Findings", "PoCs", "Targets", "Scope", "Notes", "Report", "HTTP History"] {
                                    let sel = self.engagement_tab == tab;
                                    if ui.add(egui::Button::new(
                                        RichText::new(tab).size(11.0)
                                            .color(if sel { ACCENT } else { TEXT_MUTED })
                                    ).fill(if sel { Color32::from_rgb(12,35,22) } else { Color32::TRANSPARENT })
                                     .stroke(Stroke::new(1.0, if sel { ACCENT } else { BORDER }))
                                     .corner_radius(4.0).min_size(Vec2::new(70.0, 24.0))).clicked() {
                                        self.engagement_tab = tab.into();
                                    }
                                }

                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    // Status toggle
                                    let status = self.engagements[idx].status.clone();
                                    let next_label = match status {
                                        crate::engagement::EngagementStatus::Active    => "Pause",
                                        crate::engagement::EngagementStatus::Paused    => "Resume",
                                        crate::engagement::EngagementStatus::Completed => "Re-open",
                                    };
                                    if ui.add(subtle_button(next_label)).clicked() {
                                        self.engagements[idx].status = match self.engagements[idx].status {
                                            crate::engagement::EngagementStatus::Active    => crate::engagement::EngagementStatus::Paused,
                                            crate::engagement::EngagementStatus::Paused    => crate::engagement::EngagementStatus::Active,
                                            crate::engagement::EngagementStatus::Completed => crate::engagement::EngagementStatus::Active,
                                        };
                                        self.engagements[idx].save();
                                    }
                                    // Delete engagement
                                    if ui.add(egui::Button::new(RichText::new("Delete").size(11.0).color(DANGER))
                                        .fill(Color32::TRANSPARENT).stroke(Stroke::new(1.0, DANGER)).corner_radius(4.0).min_size(Vec2::new(60.0, 24.0))).clicked() {
                                        self.engagements[idx].delete();
                                        self.engagements.remove(idx);
                                        self.active_engagement_idx = if self.engagements.is_empty() { None } else { Some(0) };
                                        self.save_config();
                                        return;
                                    }
                                });
                            });
                        });

                        ui.add_space(8.0);

                        match self.engagement_tab.as_str() {
                            "Overview"     => self.eng_tab_overview(ui, idx),
                            "Findings"     => self.eng_tab_findings(ui, idx),
                            "PoCs"         => self.eng_tab_pocs(ui, idx),
                            "Targets"      => self.eng_tab_targets(ui, idx),
                            "Scope"        => self.eng_tab_scope(ui, idx),
                            "Notes"        => self.eng_tab_notes(ui, idx),
                            "Report"       => self.eng_tab_report(ui, idx),
                            "HTTP History" => self.eng_tab_http_history(ui),
                            _ => {}
                        }
                    });
                }
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label(RichText::new("Select or create an engagement →").size(14.0).color(TEXT_MUTED));
                });
            }
        });
    }

    fn eng_tab_pocs(&mut self, ui: &mut Ui, idx: usize) {
        let refs = self.engagements[idx].poc_refs.clone();
        let mut detach_id: Option<usize> = None;
        let mut copy_text: Option<String> = None;
        let mut test_payload: Option<(String, String)> = None;
        let mut goto_store = false;

        ui.horizontal(|ui| {
            section_title(ui, "REFERENCED PoCs");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.add(subtle_button("+ Add from Vuln Store")).clicked() { goto_store = true; }
            });
        });
        ui.label(RichText::new("PoCs from the global store linked to this engagement. Attach more from the Vuln Store with “📎 Attach”.")
            .size(10.0).color(TEXT_MUTED));
        ui.add_space(8.0);

        // Resolve referenced entries (skip ids that were deleted from the store).
        let entries: Vec<crate::vulnstore::PocEntry> = refs.iter()
            .filter_map(|id| self.vuln_store.get(*id).cloned())
            .collect();
        let missing = refs.len().saturating_sub(entries.len());

        if entries.is_empty() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("No PoCs referenced yet").size(14.0).color(TEXT_MUTED));
                ui.add_space(4.0);
                ui.label(RichText::new("Open the Vuln Store, pick a PoC, and click “📎 Attach”.").size(11.0).color(TEXT_DIM));
            });
        } else {
            ScrollArea::vertical().id_salt("eng_pocs").auto_shrink([false, false]).show(ui, |ui| {
                for e in &entries {
                    let (cr, cg, cb) = e.complexity.color_rgb();
                    let comp_color = Color32::from_rgb(cr, cg, cb);
                    let sev_color = Self::vs_severity_color(&e.severity);
                    card_frame().show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&e.title).size(13.0).strong().color(TEXT_PRIMARY));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                Frame::NONE.fill(Color32::from_rgb(20, 26, 36)).stroke(Stroke::new(1.0, comp_color))
                                    .corner_radius(6.0).inner_margin(Margin::symmetric(7, 2)).show(ui, |ui| {
                                    ui.label(RichText::new(format!("⚙ {}", e.complexity.label())).size(10.0).strong().color(comp_color));
                                });
                                ui.add_space(4.0);
                                Frame::NONE.fill(sev_color).corner_radius(6.0).inner_margin(Margin::symmetric(7, 2)).show(ui, |ui| {
                                    ui.label(RichText::new(e.severity.to_uppercase()).size(10.0).strong().color(Color32::BLACK));
                                });
                                ui.add_space(4.0);
                                Frame::NONE.fill(Color32::from_rgb(20, 30, 44)).stroke(Stroke::new(1.0, BORDER))
                                    .corner_radius(6.0).inner_margin(Margin::symmetric(7, 2)).show(ui, |ui| {
                                    ui.label(RichText::new(&e.vuln_type).size(10.0).color(TEXT_SECONDARY));
                                });
                            });
                        });
                        ui.label(RichText::new(format!("🖥 {}   •   🕐 {}",
                            if e.system.is_empty() { "—" } else { &e.system }, e.discovered_at))
                            .size(10.0).color(TEXT_MUTED));
                        if !e.poc.is_empty() {
                            ui.add_space(4.0);
                            let preview: String = e.poc.lines().take(3).collect::<Vec<_>>().join("\n");
                            Frame::NONE.fill(TERMINAL_BG).corner_radius(5.0).inner_margin(Margin::same(8)).show(ui, |ui| {
                                ui.label(RichText::new(preview).size(10.5).monospace().color(Color32::from_rgb(126, 231, 135)));
                            });
                        }
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.add(accent_button("🎯 Test")).clicked() {
                                let payload = if !e.payload.is_empty() { e.payload.clone() } else { e.poc.clone() };
                                test_payload = Some((payload, e.system.clone()));
                            }
                            if ui.add(subtle_button("📋 PoC")).clicked() {
                                copy_text = Some(if e.poc.is_empty() { e.payload.clone() } else { e.poc.clone() });
                            }
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.add(
                                    egui::Button::new(RichText::new("✕ Detach").size(10.0).color(DANGER))
                                        .fill(Color32::from_rgb(28, 18, 22)).stroke(Stroke::new(1.0, BORDER))
                                        .corner_radius(6.0).min_size(Vec2::new(72.0, 26.0))
                                ).on_hover_text("Remove this reference (keeps the PoC in the store)").clicked() {
                                    detach_id = Some(e.id);
                                }
                            });
                        });
                    });
                    ui.add_space(8.0);
                }
                if missing > 0 {
                    ui.label(RichText::new(format!("⚠ {} referenced PoC(s) no longer exist in the store", missing)).size(10.0).color(WARN));
                }
            });
        }

        // Apply staged actions
        if goto_store { self.selected_nav = "Vuln Store".into(); }
        if let Some(id) = detach_id {
            self.engagements[idx].poc_refs.retain(|x| *x != id);
            self.engagements[idx].save();
            self.push_toast("PoC detached".to_string(), WARN);
        }
        if let Some(text) = copy_text {
            ui.ctx().copy_text(text);
        }
        if let Some((payload, system)) = test_payload {
            if !system.is_empty() { self.rep_url = system; }
            else if !self.target.is_empty() { self.rep_url = self.target.clone(); }
            if self.rep_body.is_empty() { self.rep_body = payload; }
            else { self.rep_body.push_str(&format!("\n{}", payload)); }
            self.selected_nav = "Repeater".into();
            self.push_toast("Loaded PoC into Repeater".to_string(), ACCENT);
        }
    }

    fn eng_tab_overview(&mut self, ui: &mut Ui, idx: usize) {
        let counts = self.engagements[idx].severity_counts();
        let name        = self.engagements[idx].name.clone();
        let client      = self.engagements[idx].client.clone();
        let status      = self.engagements[idx].status.clone();
        let created_at  = self.engagements[idx].created_at.clone();
        let updated_at  = self.engagements[idx].updated_at.clone();
        let n_targets   = self.engagements[idx].targets.len();
        let n_findings  = self.engagements[idx].findings.len();
        let n_turns     = self.engagements[idx].ai_history.len();
        let last_turn   = self.engagements[idx].ai_history.last().map(|m| (m.role.clone(), m.content.clone()));
        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.set_min_width(300.0);
                    section_title(ui, &name.to_uppercase());
                    ui.label(RichText::new(format!("Client: {}", if client.is_empty() { "—" } else { &client })).size(12.0).color(TEXT_SECONDARY));
                    ui.label(RichText::new(format!("Status: {}", status.label())).size(12.0).color(match status {
                        crate::engagement::EngagementStatus::Active    => ACCENT,
                        crate::engagement::EngagementStatus::Paused    => WARN,
                        crate::engagement::EngagementStatus::Completed => TEXT_MUTED,
                    }));
                    ui.label(RichText::new(format!("Created: {}  |  Updated: {}", created_at, updated_at)).size(10.0).color(TEXT_MUTED));
                    ui.add_space(8.0);
                    ui.label(RichText::new(format!("{} targets  •  {} findings  •  {} AI turns",
                        n_targets, n_findings, n_turns)).size(11.0).color(TEXT_SECONDARY));
                });

                ui.add_space(20.0);

                // Severity breakdown
                ui.vertical(|ui| {
                    for (label, count, color) in [
                        ("Critical", counts[0], DANGER),
                        ("High",     counts[1], Color32::from_rgb(255,140,0)),
                        ("Medium",   counts[2], WARN),
                        ("Low",      counts[3], ACCENT),
                        ("Info",     counts[4], TEXT_MUTED),
                    ] {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(format!("{:>8}", label)).size(11.0).color(TEXT_MUTED));
                            ui.add_space(8.0);
                            let bar_w = (count as f32 * 12.0).min(120.0);
                            let (rect, _) = ui.allocate_exact_size(Vec2::new(120.0, 12.0), egui::Sense::hover());
                            ui.painter().rect_filled(rect, 2.0, Color32::from_rgb(24,32,44));
                            if bar_w > 0.0 {
                                let bar = egui::Rect::from_min_size(rect.min, Vec2::new(bar_w, 12.0));
                                ui.painter().rect_filled(bar, 2.0, color);
                            }
                            ui.label(RichText::new(count.to_string()).size(11.0).color(color));
                        });
                    }
                });
            });

            // Description edit
            ui.add_space(12.0);
            ui.separator();
            ui.add_space(8.0);
            ui.label(RichText::new("Description").size(11.0).color(TEXT_MUTED));
            let desc = &mut self.engagements[idx].description;
            let r = ui.add(TextEdit::multiline(desc)
                .desired_width(f32::INFINITY)
                .desired_rows(3)
                .hint_text("Brief engagement description..."));
            if r.changed() { self.engagements[idx].save(); }

            // AI session memory summary
            if n_turns > 0 {
                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);
                ui.label(RichText::new("AI Session Memory").size(11.0).color(TEXT_MUTED));
                ui.label(RichText::new(format!("{} conversation turns stored", n_turns))
                    .size(11.0).color(TEXT_SECONDARY));
                if let Some((role, content)) = &last_turn {
                    let preview = if content.len() > 120 {
                        format!("{}…", &content[..120])
                    } else { content.clone() };
                    ui.label(RichText::new(format!("Last [{}]: {}", role, preview))
                        .size(10.0).color(TEXT_MUTED));
                }
                if ui.add(subtle_button("Clear Memory")).clicked() {
                    self.engagements[idx].ai_history.clear();
                    self.engagements[idx].save();
                }
            }

            // ── AI Brief + client OSINT ────────────────────────────────────
            ui.add_space(12.0);
            ui.separator();
            ui.add_space(8.0);
            let busy = self.page_ai_busy.contains("engagement");
            ui.horizontal(|ui| {
                ui.label(RichText::new("AI BRIEF").size(11.0).color(TEXT_DIM));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    // Investigate the client with the OSINT engine.
                    if !client.is_empty() && ui.add(subtle_button("🕵 Investigate client (OSINT)")).clicked() {
                        self.osint_subject = client.clone();
                        self.selected_nav = "OSINT".into();
                        self.run_osint_investigation();
                    }
                    ui.add_space(6.0);
                    if busy {
                        ui.spinner();
                        ui.label(RichText::new("Thinking…").size(10.0).color(TEXT_MUTED));
                    } else if ui.add(subtle_button("Generate brief")).clicked() {
                        let findings_list = self.engagements[idx].findings.iter()
                            .map(|f| format!("- [{}] {} ({})", f.severity, f.title, f.category))
                            .collect::<Vec<_>>().join("\n");
                        let context = format!(
                            "Engagement: {} (client: {}, status: {})\nTargets: {}\nSeverity counts — Critical {}, High {}, Medium {}, Low {}, Info {}\n\nFindings:\n{}\n\nWrite a short executive brief: current risk posture, the 3 most important findings, and the recommended next steps for the tester.",
                            name, if client.is_empty() { "—" } else { &client }, status.label(),
                            n_targets, counts[0], counts[1], counts[2], counts[3], counts[4],
                            if findings_list.is_empty() { "(none recorded yet)".into() } else { findings_list }
                        );
                        self.trigger_page_ai("engagement", context);
                    }
                });
            });
            if let Some(result) = self.page_ai_results.get("engagement").cloned() {
                ui.add_space(6.0);
                Frame::NONE.fill(Color32::from_rgb(8, 20, 14)).corner_radius(6.0).inner_margin(Margin::same(10)).show(ui, |ui| {
                    ScrollArea::vertical().id_salt("engagement_ai_scroll").max_height(200.0).show(ui, |ui| {
                        ui.label(RichText::new(&result).size(11.5).color(TEXT_PRIMARY));
                    });
                });
            }
        });
    }

    fn eng_tab_findings(&mut self, ui: &mut Ui, idx: usize) {
        // ── Toolbar ──────────────────────────────────────────────────────────
        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                section_title(ui, "FINDINGS");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let add_label = if self.eng_f_show_add { "− Cancel" } else { "+ Add Finding" };
                    if ui.add(accent_button(add_label)).clicked() {
                        self.eng_f_show_add = !self.eng_f_show_add;
                    }
                });
            });

            // ── Manual add form ──────────────────────────────────────────────
            if self.eng_f_show_add {
                ui.add_space(8.0);
                Frame::NONE.fill(Color32::from_rgb(12, 20, 32))
                    .stroke(Stroke::new(1.0, ACCENT))
                    .corner_radius(8.0).inner_margin(Margin::same(12)).show(ui, |ui| {
                    ui.label(RichText::new("NEW FINDING").size(10.0).strong().color(ACCENT));
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Title").size(10.0).color(TEXT_MUTED));
                        ui.add(TextEdit::singleline(&mut self.eng_f_title)
                            .desired_width(280.0).background_color(INPUT_BG)
                            .hint_text("e.g. Auth0 OpenID Config Disclosure"));
                        ui.add_space(8.0);
                        ui.label(RichText::new("Severity").size(10.0).color(TEXT_MUTED));
                        egui::ComboBox::from_id_salt("eng_f_sev")
                            .selected_text(&self.eng_f_sev).width(90.0)
                            .show_ui(ui, |ui| {
                                for s in ["critical","high","medium","low","info"] {
                                    ui.selectable_value(&mut self.eng_f_sev, s.into(), s);
                                }
                            });
                    });
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Category").size(10.0).color(TEXT_MUTED));
                        ui.add(TextEdit::singleline(&mut self.eng_f_category)
                            .desired_width(220.0).background_color(INPUT_BG)
                            .hint_text("e.g. Authentication / Security Misconfiguration"));
                        ui.add_space(8.0);
                        ui.label(RichText::new("Target").size(10.0).color(TEXT_MUTED));
                        ui.add(TextEdit::singleline(&mut self.eng_f_target)
                            .desired_width(200.0).background_color(INPUT_BG)
                            .hint_text("`auth.example.com`"));
                    });
                    ui.add_space(4.0);
                    ui.label(RichText::new("Description").size(10.0).color(TEXT_MUTED));
                    ui.add(TextEdit::multiline(&mut self.eng_f_desc)
                        .desired_width(f32::INFINITY).desired_rows(3)
                        .background_color(INPUT_BG).hint_text("Describe the vulnerability…"));
                    ui.add_space(4.0);
                    ui.label(RichText::new("Remediation").size(10.0).color(TEXT_MUTED));
                    ui.add(TextEdit::singleline(&mut self.eng_f_remediation)
                        .desired_width(f32::INFINITY).background_color(INPUT_BG)
                        .hint_text("Recommended fix…"));
                    ui.add_space(8.0);
                    let can_save = !self.eng_f_title.trim().is_empty();
                    if ui.add_enabled(can_save, accent_button("Save Finding")).clicked() {
                        let title   = self.eng_f_title.trim().to_string();
                        let desc    = self.eng_f_desc.trim().to_string();
                        let sev     = self.eng_f_sev.clone();
                        let cat     = self.eng_f_category.trim().to_string();
                        let tgt     = if self.eng_f_target.trim().is_empty() { self.target.clone() } else { self.eng_f_target.trim().to_string() };
                        let rem     = self.eng_f_remediation.trim().to_string();
                        self.save_finding_to_engagement_full(
                            &title, &desc, &sev, &cat,
                            "", &tgt, "Manual", vec![], &rem, None,
                        );
                        self.eng_f_title.clear(); self.eng_f_desc.clear();
                        self.eng_f_category.clear(); self.eng_f_target.clear();
                        self.eng_f_remediation.clear(); self.eng_f_show_add = false;
                    }
                });
                ui.add_space(8.0);
            }

            // ── Filter bar ───────────────────────────────────────────────────
            ui.horizontal(|ui| {
                ui.label(RichText::new("🔍").size(11.0).color(TEXT_MUTED));
                ui.add(TextEdit::singleline(&mut self.eng_finding_filter)
                    .hint_text("Search title, severity, category, tag…")
                    .desired_width(220.0).background_color(INPUT_BG));
                ui.add_space(8.0);
                ui.label(RichText::new("Status:").size(10.0).color(TEXT_MUTED));
                for st in ["All", "Open", "Verified", "Closed", "False Positive"] {
                    let active = if st == "All" { self.eng_finding_status_filter.is_empty() }
                                 else { self.eng_finding_status_filter == st };
                    if ui.add(egui::Button::new(RichText::new(st).size(10.0)
                        .color(if active { ACCENT } else { TEXT_MUTED }))
                        .fill(if active { Color32::from_rgb(0,40,20) } else { Color32::TRANSPARENT })
                        .stroke(if active { Stroke::new(1.0,ACCENT) } else { Stroke::new(1.0,BORDER) })
                        .corner_radius(4.0)).clicked() {
                        self.eng_finding_status_filter = if st == "All" { String::new() } else { st.into() };
                    }
                }
            });
            ui.add_space(6.0);
        });

        let finding_count = self.engagements[idx].findings.len();
        if finding_count == 0 {
            card_frame().show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    ui.label(RichText::new("No findings yet.").size(13.0).color(TEXT_MUTED));
                    ui.label(RichText::new("Run modules or add manually above.").size(11.0).color(TEXT_DIM));
                    ui.add_space(20.0);
                });
            });
            return;
        }

        // ── Column header ────────────────────────────────────────────────────
        Frame::NONE.fill(Color32::from_rgb(10,15,24))
            .inner_margin(Margin::symmetric(12, 6)).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("ID").size(10.0).strong().color(TEXT_DIM));
                ui.add_space(28.0);
                ui.label(RichText::new("Finding").size(10.0).strong().color(TEXT_DIM));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.add_space(6.0);
                    ui.label(RichText::new("Status").size(10.0).strong().color(TEXT_DIM));
                    ui.add_space(80.0);
                    ui.label(RichText::new("Target").size(10.0).strong().color(TEXT_DIM));
                    ui.add_space(100.0);
                    ui.label(RichText::new("Category").size(10.0).strong().color(TEXT_DIM));
                    ui.add_space(120.0);
                    ui.label(RichText::new("Severity").size(10.0).strong().color(TEXT_DIM));
                });
            });
        });

        // ── Rows ─────────────────────────────────────────────────────────────
        let filter = self.eng_finding_filter.to_lowercase();
        let status_filter = self.eng_finding_status_filter.clone();

        struct FRow {
            fi: usize,
            id: usize,
            severity: String,
            title: String,
            category: String,
            finding_status: String,
            target: String,
            description: String,
            evidence: String,
            remediation: String,
            cve: Option<String>,
            confirmed: bool,
        }

        let rows: Vec<FRow> = (0..finding_count).filter_map(|fi| {
            let f = &self.engagements[idx].findings[fi];
            if !filter.is_empty() {
                let haystack = format!("{} {} {} {} {}",
                    f.severity, f.title, f.category, f.tags.join(" "), f.description).to_lowercase();
                if !haystack.contains(&filter) { return None; }
            }
            let fst = if f.finding_status.is_empty() { "Open" } else { f.finding_status.as_str() };
            if !status_filter.is_empty() && fst != status_filter { return None; }
            Some(FRow {
                fi,
                id: f.id,
                severity: f.severity.clone(),
                title: f.title.clone(),
                category: f.category.clone(),
                finding_status: fst.to_string(),
                target: f.target.clone(),
                description: f.description.clone(),
                evidence: f.evidence.clone(),
                remediation: f.remediation.clone(),
                cve: f.cve.clone(),
                confirmed: f.confirmed,
            })
        }).collect();

        ScrollArea::vertical().id_salt("eng_findings_v2").show(ui, |ui| {
            let mut toggle_status: Option<(usize, String)> = None;
            let mut toggle_confirmed: Option<(usize, bool)> = None;
            let mut delete_idx: Option<usize> = None;

            for row in &rows {
                let sev_color = match row.severity.to_lowercase().as_str() {
                    "critical" => DANGER,
                    "high"     => Color32::from_rgb(255, 140, 0),
                    "medium"   => WARN,
                    "low"      => ACCENT,
                    _          => TEXT_MUTED,
                };
                let status_color = match row.finding_status.as_str() {
                    "Verified"       => Color32::from_rgb(67, 160, 71),
                    "Closed"         => TEXT_MUTED,
                    "False Positive" => Color32::from_rgb(123, 31, 162),
                    _                => Color32::from_rgb(21, 101, 192), // Open = blue
                };
                let selected = self.eng_selected_finding == Some(row.fi);

                let resp = Frame::NONE
                    .fill(if selected { Color32::from_rgb(12,35,22) } else { Color32::from_rgb(14,20,30) })
                    .stroke(Stroke::new(1.0, if selected { ACCENT } else { BORDER }))
                    .corner_radius(6.0).inner_margin(Margin::symmetric(12, 7))
                    .show(ui, |ui| {
                        // ── Main row ─────────────────────────────────────────
                        ui.horizontal(|ui| {
                            // ID badge
                            Frame::NONE.fill(Color32::from_rgb(20,28,40))
                                .stroke(Stroke::new(1.0, BORDER)).corner_radius(3.0)
                                .inner_margin(Margin::symmetric(5, 2)).show(ui, |ui| {
                                ui.label(RichText::new(format!("V-{:03}", row.id))
                                    .size(10.0).monospace().color(TEXT_MUTED));
                            });
                            ui.add_space(6.0);
                            // Title
                            ui.label(RichText::new(&row.title).size(12.0).color(TEXT_PRIMARY));

                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                // Status pill
                                Frame::NONE.fill(status_color.linear_multiply(0.25))
                                    .stroke(Stroke::new(1.0, status_color))
                                    .corner_radius(4.0).inner_margin(Margin::symmetric(8, 2))
                                    .show(ui, |ui| {
                                    ui.label(RichText::new(&row.finding_status)
                                        .size(10.0).strong().color(status_color));
                                });
                                ui.add_space(8.0);
                                // Target
                                ui.label(RichText::new(
                                    if row.target.len() > 28 { format!("{}…", &row.target[..25]) } else { row.target.clone() }
                                ).size(10.0).monospace().color(TEXT_MUTED));
                                ui.add_space(8.0);
                                // Category
                                ui.label(RichText::new(
                                    if row.category.is_empty() { "—".into() }
                                    else if row.category.len() > 30 { format!("{}…", &row.category[..28]) }
                                    else { row.category.clone() }
                                ).size(10.0).color(TEXT_SECONDARY));
                                ui.add_space(8.0);
                                // Severity badge
                                Frame::NONE.fill(sev_color.linear_multiply(0.2))
                                    .stroke(Stroke::new(1.0, sev_color))
                                    .corner_radius(4.0).inner_margin(Margin::symmetric(7, 2))
                                    .show(ui, |ui| {
                                    ui.label(RichText::new(row.severity.to_uppercase())
                                        .size(10.0).strong().color(sev_color));
                                });
                            });
                        });

                        // ── Expanded detail ──────────────────────────────────
                        if selected {
                            ui.add_space(8.0);
                            ui.separator();
                            ui.add_space(6.0);
                            ui.label(RichText::new(&row.description).size(11.0).color(TEXT_SECONDARY));
                            if !row.evidence.is_empty() {
                                ui.add_space(4.0);
                                ui.label(RichText::new("Evidence").size(10.0).strong().color(TEXT_DIM));
                                Frame::NONE.fill(TERMINAL_BG).corner_radius(4.0)
                                    .inner_margin(Margin::same(8)).show(ui, |ui| {
                                    ui.label(RichText::new(&row.evidence).size(10.0).color(ACCENT).monospace());
                                });
                            }
                            if !row.remediation.is_empty() {
                                ui.add_space(4.0);
                                ui.label(RichText::new(format!("🔧 {}", row.remediation)).size(10.0).color(TEXT_MUTED));
                            }
                            if let Some(ref cve) = row.cve {
                                ui.label(RichText::new(format!("🔗 {}", cve)).size(10.0).color(WARN));
                            }
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Status:").size(10.0).color(TEXT_DIM));
                                for st in ["Open", "Verified", "Closed", "False Positive"] {
                                    let active = row.finding_status == st;
                                    if ui.add(egui::Button::new(RichText::new(st).size(10.0)
                                        .color(if active { Color32::WHITE } else { TEXT_MUTED }))
                                        .fill(if active { status_color } else { Color32::TRANSPARENT })
                                        .stroke(Stroke::new(1.0, if active { status_color } else { BORDER }))
                                        .corner_radius(4.0)).clicked() && !active {
                                        toggle_status = Some((row.fi, st.into()));
                                    }
                                }
                                ui.add_space(12.0);
                                let conf_label = if row.confirmed { "✅ Confirmed" } else { "⬜ Confirm" };
                                if ui.add(subtle_button(conf_label)).clicked() {
                                    toggle_confirmed = Some((row.fi, !row.confirmed));
                                }
                                ui.add_space(8.0);
                                if ui.add(egui::Button::new(RichText::new("🗑 Delete").size(10.0).color(DANGER))
                                    .fill(Color32::TRANSPARENT).stroke(Stroke::new(1.0, DANGER))
                                    .corner_radius(4.0)).clicked() {
                                    delete_idx = Some(row.fi);
                                }
                            });
                        }
                    });

                if resp.response.interact(egui::Sense::click()).clicked() {
                    self.eng_selected_finding = if selected { None } else { Some(row.fi) };
                }
                ui.add_space(3.0);
            }

            // Apply deferred mutations
            if let Some((fi, new_status)) = toggle_status {
                self.engagements[idx].findings[fi].finding_status = new_status;
                self.engagements[idx].save();
            }
            if let Some((fi, val)) = toggle_confirmed {
                self.engagements[idx].findings[fi].confirmed = val;
                self.engagements[idx].save();
            }
            if let Some(fi) = delete_idx {
                self.engagements[idx].findings.remove(fi);
                self.eng_selected_finding = None;
                self.engagements[idx].save();
            }
        });
    }

    fn eng_tab_targets(&mut self, ui: &mut Ui, idx: usize) {
        card_frame().show(ui, |ui| {
            section_title(ui, "TARGET LIST");

            ui.horizontal(|ui| {
                ui.add(TextEdit::singleline(&mut self.eng_new_target)
                    .hint_text("http://example.com/path")
                    .desired_width(320.0)
                    .font(egui::TextStyle::Monospace));
                if ui.add(accent_button("Add")).clicked() && !self.eng_new_target.trim().is_empty() {
                    self.engagements[idx].targets.push(EngagementTarget {
                        url: self.eng_new_target.trim().to_string(),
                        note: String::new(),
                        tested: false,
                    });
                    self.engagements[idx].save();
                    self.eng_new_target.clear();
                }
                if ui.add(subtle_button("Use current target")).clicked() {
                    let t = self.target.clone();
                    self.engagements[idx].targets.push(EngagementTarget {
                        url: t, note: String::new(), tested: false
                    });
                    self.engagements[idx].save();
                }
            });

            ui.add_space(12.0);
            let target_count = self.engagements[idx].targets.len();
            if target_count == 0 {
                ui.label(RichText::new("No targets. Add URLs you want to test.").size(12.0).color(TEXT_MUTED));
                return;
            }

            // Collect target display data upfront to avoid borrow conflicts
            struct TRow { ti: usize, url: String, tested: bool, in_scope: bool, scope_reason: String }
            let rows: Vec<TRow> = (0..target_count).map(|ti| {
                let t = &self.engagements[idx].targets[ti];
                let (in_scope, scope_reason) = self.engagements[idx].check_scope(&t.url);
                TRow { ti, url: t.url.clone(), tested: t.tested, in_scope, scope_reason }
            }).collect();

            ScrollArea::vertical().id_salt("eng_targets").show(ui, |ui| {
                let mut remove_idx: Option<usize> = None;
                let mut set_target: Option<String> = None;
                let mut toggle_tested: Option<(usize, bool)> = None;

                for row in &rows {
                    Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(6.0)
                        .inner_margin(Margin::symmetric(10,6)).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let mut tested = row.tested;
                            if ui.checkbox(&mut tested, "").changed() {
                                toggle_tested = Some((row.ti, tested));
                            }
                            ui.label(RichText::new(&row.url).size(12.0)
                                .color(if row.tested { TEXT_MUTED } else { TEXT_PRIMARY }).monospace());
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.add(subtle_button("✕")).clicked() { remove_idx = Some(row.ti); }
                                if ui.add(subtle_button("→ Set")).clicked() { set_target = Some(row.url.clone()); }
                                let scope_label = if row.in_scope { "✓ In scope" } else { "⚠ OOS" };
                                ui.label(RichText::new(scope_label).size(10.0)
                                    .color(if row.in_scope { ACCENT } else { DANGER }).strong())
                                    .on_hover_text(&row.scope_reason);
                            });
                        });
                    });
                    ui.add_space(4.0);
                }

                if let Some((ti, v)) = toggle_tested {
                    self.engagements[idx].targets[ti].tested = v;
                    self.engagements[idx].save();
                }
                if let Some(url) = set_target {
                    self.target = url;
                    self.save_config();
                }
                if let Some(ri) = remove_idx {
                    self.engagements[idx].targets.remove(ri);
                    self.engagements[idx].save();
                }
            });
        });
    }

    fn eng_tab_scope(&mut self, ui: &mut Ui, idx: usize) {
        card_frame().show(ui, |ui| {
            section_title(ui, "SCOPE RULES");
            ui.label(RichText::new("Define what is and isn't in scope. Wildcards: *.example.com, 10.0.0.*").size(11.0).color(TEXT_MUTED));
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.add(TextEdit::singleline(&mut self.eng_new_scope)
                    .hint_text("*.example.com or exact URL")
                    .desired_width(240.0)
                    .font(egui::TextStyle::Monospace));
                if ui.add(accent_button("+ In Scope")).clicked() && !self.eng_new_scope.trim().is_empty() {
                    self.engagements[idx].scope.push(ScopeRule {
                        pattern: self.eng_new_scope.trim().to_string(),
                        note: String::new(),
                    });
                    self.engagements[idx].save();
                    self.eng_new_scope.clear();
                }
                if ui.add(egui::Button::new(RichText::new("+ Out of Scope").size(12.0).color(DANGER))
                    .fill(Color32::TRANSPARENT).stroke(Stroke::new(1.0, DANGER))
                    .corner_radius(8.0).min_size(Vec2::new(110.0, 36.0))).clicked()
                    && !self.eng_new_scope.trim().is_empty()
                {
                    self.engagements[idx].out_of_scope.push(ScopeRule {
                        pattern: self.eng_new_scope.trim().to_string(),
                        note: String::new(),
                    });
                    self.engagements[idx].save();
                    self.eng_new_scope.clear();
                }
            });

            ui.add_space(12.0);
            ui.label(RichText::new("IN SCOPE").size(11.0).strong().color(ACCENT));
            let scope_count = self.engagements[idx].scope.len();
            let mut remove_scope: Option<usize> = None;
            for si in 0..scope_count {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("✓  {}", self.engagements[idx].scope[si].pattern))
                        .size(12.0).color(ACCENT).monospace());
                    if ui.add(subtle_button("✕")).clicked() { remove_scope = Some(si); }
                });
            }
            if let Some(ri) = remove_scope { self.engagements[idx].scope.remove(ri); self.engagements[idx].save(); }

            ui.add_space(8.0);
            ui.label(RichText::new("OUT OF SCOPE").size(11.0).strong().color(DANGER));
            let oos_count = self.engagements[idx].out_of_scope.len();
            let mut remove_oos: Option<usize> = None;
            for oi in 0..oos_count {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("✕  {}", self.engagements[idx].out_of_scope[oi].pattern))
                        .size(12.0).color(DANGER).monospace());
                    if ui.add(subtle_button("✕")).clicked() { remove_oos = Some(oi); }
                });
            }
            if let Some(ri) = remove_oos { self.engagements[idx].out_of_scope.remove(ri); self.engagements[idx].save(); }

            // Live scope test
            ui.add_space(12.0);
            ui.separator();
            ui.add_space(8.0);
            ui.label(RichText::new("Test a URL against scope").size(11.0).color(TEXT_MUTED));
            ui.horizontal(|ui| {
                ui.add(TextEdit::singleline(&mut self.target_list_input)
                    .hint_text("http://test.example.com/path")
                    .desired_width(280.0)
                    .font(egui::TextStyle::Monospace));
                if ui.add(subtle_button("Check")).clicked() && !self.target_list_input.is_empty() {
                    let (in_scope, reason) = self.engagements[idx].check_scope(&self.target_list_input.clone());
                    let msg = format!("{}: {}", if in_scope { "IN SCOPE" } else { "OUT OF SCOPE" }, reason);
                    self.push_toast(msg, if in_scope { ACCENT } else { DANGER });
                }
            });
        });
    }

    fn eng_tab_notes(&mut self, ui: &mut Ui, idx: usize) {
        card_frame().show(ui, |ui| {
            section_title(ui, "NOTES");
            ui.label(RichText::new("Free-form markdown notes. While this engagement is active, discoveries (subdomains, names, creds, endpoints, OSINT intel) are auto-appended under \"## Auto-captured intel\".").size(11.0).color(TEXT_MUTED));
            ui.add_space(8.0);
            ScrollArea::vertical().id_salt("eng_notes").show(ui, |ui| {
                let r = ui.add(TextEdit::multiline(&mut self.engagements[idx].notes)
                    .desired_width(f32::INFINITY)
                    .desired_rows(20)
                    .hint_text("# Findings\n\n- [ ] Test login for SQLi\n- [ ] Check admin panel auth..."));
                if r.changed() { self.engagements[idx].save(); }
            });
        });
    }

    fn eng_tab_http_history(&mut self, ui: &mut Ui) {
        card_frame().show(ui, |ui| {
            section_title(ui, "HTTP REQUEST / RESPONSE HISTORY");
            ui.label(RichText::new("All requests captured by the proxy, linked to findings.").size(11.0).color(TEXT_MUTED));
            ui.add_space(8.0);

            let (lock, _) = &*self.proxy_state;
            let captures: Vec<crate::proxy::CapturedRequest> = lock.lock().unwrap().captures.clone();

            if captures.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.label(RichText::new("No proxy captures yet — start the proxy and browse your target.").size(12.0).color(TEXT_MUTED));
                });
                return;
            }

            // Filter bar
            ui.horizontal(|ui| {
                ui.label(RichText::new("Filter:").size(11.0).color(TEXT_MUTED));
                ui.add(TextEdit::singleline(&mut self.eng_http_filter)
                    .hint_text("method, url, status…")
                    .desired_width(220.0)
                    .font(egui::TextStyle::Monospace));
                if ui.add(subtle_button("Clear")).clicked() { self.eng_http_filter.clear(); }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new(format!("{} requests", captures.len())).size(10.0).color(TEXT_MUTED));
                });
            });
            ui.add_space(6.0);

            let filter = self.eng_http_filter.to_lowercase();
            let selected_id = self.eng_selected_request;

            // Split: list on left, detail on right
            let available_w = ui.available_width();
            ui.horizontal_top(|ui| {
                // ── Left: request list ──────────────────────────────────
                ui.vertical(|ui| {
                    ui.set_max_width((available_w * 0.42).max(200.0));
                    ScrollArea::vertical().id_salt("http_list").max_height(480.0).show(ui, |ui| {
                        for req in captures.iter().rev() {
                            if !filter.is_empty() {
                                let haystack = format!("{} {} {}", req.method, req.url, req.status).to_lowercase();
                                if !haystack.contains(&filter) { continue; }
                            }
                            let is_sel = selected_id == Some(req.id);
                            let status_color = match req.status {
                                200..=299 => Color32::from_rgb(67,224,122),
                                300..=399 => Color32::from_rgb(100,180,255),
                                400..=499 => WARN,
                                500..=599 => DANGER,
                                _         => TEXT_MUTED,
                            };
                            let row = Frame::NONE
                                .fill(if is_sel { Color32::from_rgb(12,35,22) } else { Color32::from_rgb(18,24,34) })
                                .stroke(Stroke::new(1.0, if is_sel { ACCENT } else { BORDER }))
                                .corner_radius(5.0).inner_margin(Margin::symmetric(10, 6))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new(&req.method).size(10.0)
                                            .color(match req.method.as_str() {
                                                "POST" => Color32::from_rgb(255,160,80),
                                                "PUT"  => Color32::from_rgb(100,180,255),
                                                "DELETE" => DANGER,
                                                _ => ACCENT,
                                            }).strong().monospace());
                                        let url_display = if req.url.len() > 40 {
                                            format!("{}…", &req.url[..40])
                                        } else { req.url.clone() };
                                        ui.label(RichText::new(&url_display).size(10.0).color(TEXT_SECONDARY).monospace());
                                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                            ui.label(RichText::new(format!("{}", req.status)).size(10.0).color(status_color).strong());
                                        });
                                    });
                                });
                            if row.response.interact(egui::Sense::click()).clicked() {
                                self.eng_selected_request = if is_sel { None } else { Some(req.id) };
                            }
                            ui.add_space(2.0);
                        }
                    });
                });

                ui.add_space(10.0);

                // ── Right: request detail ───────────────────────────────
                ui.vertical(|ui| {
                    if let Some(sid) = selected_id {
                        if let Some(req) = captures.iter().find(|r| r.id == sid) {
                            let req = req.clone();
                            let body_str  = String::from_utf8_lossy(&req.body);
                            let resp_str  = String::from_utf8_lossy(&req.response_body);

                            ScrollArea::vertical().id_salt("http_detail").max_height(480.0).show(ui, |ui| {
                                // Request section
                                ui.label(RichText::new("REQUEST").size(10.0).color(TEXT_MUTED).strong());
                                Frame::NONE.fill(TERMINAL_BG).corner_radius(6.0)
                                    .inner_margin(Margin::same(10)).show(ui, |ui| {
                                    ui.label(RichText::new(format!("{} {} HTTP/1.1", req.method, req.url))
                                        .size(11.0).color(ACCENT).monospace());
                                    ui.label(RichText::new(format!("Host: {}", req.host))
                                        .size(10.0).color(TEXT_SECONDARY).monospace());
                                    for (k, v) in &req.headers {
                                        ui.label(RichText::new(format!("{}: {}", k, v))
                                            .size(10.0).color(TEXT_MUTED).monospace());
                                    }
                                    if !body_str.is_empty() {
                                        ui.add_space(4.0);
                                        ui.separator();
                                        ui.label(RichText::new(body_str.as_ref())
                                            .size(10.0).color(TEXT_SECONDARY).monospace());
                                    }
                                });

                                ui.add_space(8.0);

                                // Response section
                                let status_color = match req.status {
                                    200..=299 => Color32::from_rgb(67,224,122),
                                    300..=399 => Color32::from_rgb(100,180,255),
                                    400..=499 => WARN,
                                    500..=599 => DANGER,
                                    _         => TEXT_MUTED,
                                };
                                ui.label(RichText::new(format!("RESPONSE  {}", req.status))
                                    .size(10.0).color(status_color).strong());
                                Frame::NONE.fill(TERMINAL_BG).corner_radius(6.0)
                                    .inner_margin(Margin::same(10)).show(ui, |ui| {
                                    for (k, v) in &req.response_headers {
                                        ui.label(RichText::new(format!("{}: {}", k, v))
                                            .size(10.0).color(TEXT_MUTED).monospace());
                                    }
                                    if !resp_str.is_empty() {
                                        ui.add_space(4.0);
                                        ui.separator();
                                        let preview = if resp_str.len() > 2000 {
                                            format!("{}\n\n[… {} bytes total]", &resp_str[..2000], resp_str.len())
                                        } else { resp_str.into_owned() };
                                        ui.label(RichText::new(&preview)
                                            .size(10.0).color(TEXT_SECONDARY).monospace());
                                    }
                                });

                                ui.add_space(8.0);
                                // Action buttons
                                ui.horizontal(|ui| {
                                    if ui.add(accent_button("Send to Repeater")).clicked() {
                                        self.rep_url    = req.url.clone();
                                        self.rep_method = req.method.clone();
                                        self.rep_body   = String::from_utf8_lossy(&req.body).into_owned();
                                        self.selected_nav = "Repeater".into();
                                        self.push_toast("Request loaded in Repeater".to_string(), ACCENT);
                                    }
                                    if ui.add(subtle_button("Save as Finding")).clicked() {
                                        let title = format!("{} {} → {}", req.method, req.url, req.status);
                                        let evidence = format!("{} {} HTTP/1.1\nHost: {}\n\n{}",
                                            req.method, req.url, req.host,
                                            String::from_utf8_lossy(&req.body));
                                        let target = req.url.clone();
                                        self.save_finding_to_engagement(
                                            &title, "Captured HTTP request", "info",
                                            &evidence, &target, "HTTP History",
                                            vec!["http".into()], "", None,
                                        );
                                        self.push_toast("Saved as finding".to_string(), ACCENT);
                                    }
                                });
                            });
                        } else {
                            ui.label(RichText::new("Request not found.").size(12.0).color(TEXT_MUTED));
                        }
                    } else {
                        ui.centered_and_justified(|ui| {
                            ui.label(RichText::new("← Select a request to inspect").size(12.0).color(TEXT_MUTED));
                        });
                    }
                });
            });
        });
    }

    fn eng_tab_report(&mut self, ui: &mut Ui, idx: usize) {
        card_frame().show(ui, |ui| {
            section_title(ui, "EXPORT REPORT");

            let counts = self.engagements[idx].severity_counts();
            ui.label(RichText::new(format!(
                "{} findings — {} critical  {} high  {} medium  {} low  {} info",
                self.engagements[idx].findings.len(),
                counts[0], counts[1], counts[2], counts[3], counts[4]
            )).size(12.0).color(TEXT_SECONDARY));

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.add(accent_button("Export Markdown")).clicked() {
                    let md = self.engagements[idx].export_markdown();
                    let filename = format!("{}-report.md", self.engagements[idx].id);
                    let path = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                    let full = std::path::PathBuf::from(path).join("Desktop").join(&filename);
                    match std::fs::write(&full, &md) {
                        Ok(_) => {
                            self.eng_export_msg = format!("Saved to ~/Desktop/{}", filename);
                            self.push_toast(format!("Report saved: {}", filename), ACCENT);
                        }
                        Err(e) => {
                            self.eng_export_msg = format!("Error: {}", e);
                        }
                    }
                }
                if ui.add(accent_button("Export HTML")).clicked() {
                    let html = self.engagements[idx].export_html();
                    let filename = format!("{}-report.html", self.engagements[idx].id);
                    let path = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                    let full = std::path::PathBuf::from(path).join("Desktop").join(&filename);
                    match std::fs::write(&full, &html) {
                        Ok(_) => {
                            self.eng_export_msg = format!("Saved to ~/Desktop/{}", filename);
                            self.push_toast(format!("HTML report saved: {}", filename), ACCENT);
                            // Auto-open in browser
                            let _ = std::process::Command::new("open").arg(&full).spawn();
                        }
                        Err(e) => { self.eng_export_msg = format!("Error: {}", e); }
                    }
                }
                if ui.add(accent_button("Export PDF")).clicked() {
                    let title = format!("{} — Security Assessment Report", self.engagements[idx].name);
                    let body = self.engagements[idx].export_markdown();
                    let pdf = crate::report_pdf::render_text_pdf(&title, &body);
                    let filename = format!("{}-report.pdf", self.engagements[idx].id);
                    let path = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                    let full = std::path::PathBuf::from(path).join("Desktop").join(&filename);
                    match std::fs::write(&full, &pdf) {
                        Ok(_) => {
                            self.eng_export_msg = format!("Saved to ~/Desktop/{}", filename);
                            self.push_toast(format!("PDF report saved: {}", filename), ACCENT);
                            let _ = std::process::Command::new("open").arg(&full).spawn();
                        }
                        Err(e) => { self.eng_export_msg = format!("Error: {}", e); }
                    }
                }
                if ui.add(subtle_button("Export JSON")).clicked() {
                    let json = self.engagements[idx].export_json();
                    let filename = format!("{}-findings.json", self.engagements[idx].id);
                    let path = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                    let full = std::path::PathBuf::from(path).join("Desktop").join(&filename);
                    match std::fs::write(&full, &json) {
                        Ok(_) => {
                            self.eng_export_msg = format!("Saved to ~/Desktop/{}", filename);
                            self.push_toast(format!("JSON saved: {}", filename), ACCENT);
                        }
                        Err(e) => { self.eng_export_msg = format!("Error: {}", e); }
                    }
                }
            });

            if !self.eng_export_msg.is_empty() {
                ui.add_space(8.0);
                ui.label(RichText::new(&self.eng_export_msg.clone()).size(11.0).color(ACCENT));
            }

            // ── AI-drafted PTES report ─────────────────────────────────────
            ui.add_space(12.0);
            ui.separator();
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("🤖 AI REPORT (PTES)").size(11.0).color(TEXT_DIM));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if self.eng_report_busy {
                        ui.spinner();
                        ui.label(RichText::new("Drafting…").size(10.0).color(TEXT_MUTED));
                    } else {
                        if ui.add(accent_button("Draft with AI")).clicked() {
                            self.run_ai_report(idx);
                        }
                        if !self.eng_report_ai.is_empty() {
                            if ui.add(subtle_button("Export AI Report PDF")).clicked() {
                                let title = format!("{} — Penetration Test Report (PTES)", self.engagements[idx].name);
                                let pdf = crate::report_pdf::render_text_pdf(&title, &self.eng_report_ai);
                                let filename = format!("{}-ptes-report.pdf", self.engagements[idx].id);
                                let path = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                                let full = std::path::PathBuf::from(path).join("Desktop").join(&filename);
                                match std::fs::write(&full, &pdf) {
                                    Ok(_) => {
                                        self.eng_export_msg = format!("Saved to ~/Desktop/{}", filename);
                                        self.push_toast(format!("AI PDF report saved: {}", filename), ACCENT);
                                        let _ = std::process::Command::new("open").arg(&full).spawn();
                                    }
                                    Err(e) => { self.eng_export_msg = format!("Error: {}", e); }
                                }
                            }
                            if ui.add(subtle_button("Copy")).clicked() {
                                ui.ctx().copy_text(self.eng_report_ai.clone());
                                self.push_toast("Copied AI report".to_string(), ACCENT);
                            }
                        }
                    }
                });
            });
            ui.label(RichText::new("The model expands your recorded findings into a full PTES-structured report (executive summary + technical detail). Grounded in the engagement data; review before sending.")
                .size(10.0).color(TEXT_MUTED));
            if !self.eng_report_ai.is_empty() {
                ui.add_space(6.0);
                ScrollArea::vertical().id_salt("ai_report_preview").max_height(320.0).show(ui, |ui| {
                    Frame::NONE.fill(TERMINAL_BG).corner_radius(6.0).inner_margin(Margin::same(12)).show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.label(RichText::new(&self.eng_report_ai).size(11.0).color(TEXT_SECONDARY));
                    });
                });
            }

            // Markdown preview
            ui.add_space(12.0);
            ui.separator();
            ui.add_space(8.0);
            ui.label(RichText::new("Preview (raw markdown)").size(11.0).color(TEXT_MUTED));
            let preview = self.engagements[idx].export_markdown();
            let preview_short = if preview.len() > 2000 { format!("{}…\n\n[truncated — export to see full report]", &preview[..2000]) } else { preview };
            ScrollArea::vertical().id_salt("report_preview").max_height(300.0).show(ui, |ui| {
                Frame::NONE.fill(TERMINAL_BG).corner_radius(6.0).inner_margin(Margin::same(12)).show(ui, |ui| {
                    ui.label(RichText::new(&preview_short).size(10.0).color(TEXT_SECONDARY).monospace());
                });
            });
        });
    }

}
