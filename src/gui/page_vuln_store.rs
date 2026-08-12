// Vulnerability / PoC store pages — the reusable exploit library, its match
// view and editor. Split out of the GUI monolith; see gui/mod.rs.

use super::*;

impl NullForgeApp {
    // ═══════════════════════════════════════════════════════════════════════
    // VULNERABILITY / PoC STORE
    // ═══════════════════════════════════════════════════════════════════════
    fn vs_reset_form(&mut self) {
        self.vs_edit_id = None;
        self.vs_f_title.clear();
        self.vs_f_type = "SQLi".into();
        self.vs_f_severity = "high".into();
        self.vs_f_complexity = crate::vulnstore::Complexity::Medium;
        self.vs_f_system = self.target.clone();
        self.vs_f_how.clear();
        self.vs_f_poc.clear();
        self.vs_f_payload.clear();
        self.vs_f_tags.clear();
        self.vs_f_refs.clear();
        self.vs_f_notes.clear();
    }

    fn vs_load_form(&mut self, id: usize) {
        if let Some(e) = self.vuln_store.get(id).cloned() {
            self.vs_edit_id = Some(e.id);
            self.vs_f_title = e.title;
            self.vs_f_type = e.vuln_type;
            self.vs_f_severity = e.severity;
            self.vs_f_complexity = e.complexity;
            self.vs_f_system = e.system;
            self.vs_f_how = e.how_found;
            self.vs_f_poc = e.poc;
            self.vs_f_payload = e.payload;
            self.vs_f_tags = e.tags.join(", ");
            self.vs_f_refs = e.references;
            self.vs_f_notes = e.notes;
        }
    }

    /// Attach a PoC to the active engagement (per-engagement reference).
    /// Returns a user-facing status message.
    fn vs_attach_to_engagement(&mut self, poc_id: usize) -> String {
        match self.active_engagement_idx.and_then(|i| self.engagements.get_mut(i)) {
            Some(eng) => {
                if eng.poc_refs.contains(&poc_id) {
                    format!("Already referenced by engagement '{}'", eng.name)
                } else {
                    eng.poc_refs.push(poc_id);
                    eng.save();
                    format!("Attached to engagement '{}'", eng.name)
                }
            }
            None => "No active engagement — open one in Engagements first".into(),
        }
    }

    pub(crate) fn page_vuln_store(&mut self, ui: &mut Ui) {
        // ── Header: title + view switcher ─────────────────────────────────
        ui.horizontal(|ui| {
            ui.label(RichText::new("🗄  Vulnerability Store").size(16.0).strong().color(TEXT_PRIMARY));
            ui.add_space(6.0);
            ui.label(RichText::new(format!("{} PoCs", self.vuln_store.entries.len())).size(11.0).color(TEXT_MUTED));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let active = self.active_engagement_idx
                    .and_then(|i| self.engagements.get(i))
                    .map(|e| e.name.clone());
                match active {
                    Some(name) => ui.label(RichText::new(format!("◆ {}", name)).size(10.0).color(ACCENT)),
                    None => ui.label(RichText::new("◇ no active engagement").size(10.0).color(TEXT_DIM)),
                };
            });
        });
        ui.add_space(8.0);

        let views = [("Library", "📚 Library"), ("Match", "🎯 Match to system"), ("Add", "➕ Add PoC")];
        ui.horizontal(|ui| {
            for (key, label) in views {
                let sel = self.vs_view == key;
                if ui.add(
                    egui::Button::new(RichText::new(label).size(12.0)
                        .color(if sel { Color32::BLACK } else { TEXT_SECONDARY }))
                        .fill(if sel { ACCENT } else { Color32::from_rgb(22, 30, 44) })
                        .stroke(Stroke::new(1.0, if sel { ACCENT } else { BORDER }))
                        .corner_radius(7.0)
                        .min_size(Vec2::new(150.0, 32.0))
                ).clicked() {
                    if key == "Add" && self.vs_view != "Add" && self.vs_edit_id.is_none() {
                        self.vs_reset_form();
                    }
                    if key == "Match" && self.vs_match_tags.trim().is_empty() {
                        self.vs_match_tags = self.target.clone();
                    }
                    self.vs_view = key.to_string();
                }
                ui.add_space(4.0);
            }
        });
        ui.add_space(10.0);

        match self.vs_view.as_str() {
            "Add"   => self.vs_view_editor(ui),
            "Match" => self.vs_view_match(ui),
            _        => self.vs_view_library(ui),
        }
    }

    pub(crate) fn vs_severity_color(s: &str) -> Color32 {
        match s.to_lowercase().as_str() {
            "critical" => DANGER,
            "high"     => Color32::from_rgb(255, 140, 0),
            "medium"   => WARN,
            "low"      => ACCENT,
            _          => TEXT_MUTED,
        }
    }

    /// Render a single PoC card with action buttons; returns staged actions via the out-params.
    fn vs_card(
        ui: &mut Ui,
        e: &crate::vulnstore::PocEntry,
        score: Option<u32>,
        edit_id: &mut Option<usize>,
        delete_id: &mut Option<usize>,
        copy_text: &mut Option<String>,
        test_payload: &mut Option<(String, String)>, // (payload_or_poc, system)
        attach_id: &mut Option<usize>,
    ) {
        let (cr, cg, cb) = e.complexity.color_rgb();
        let comp_color = Color32::from_rgb(cr, cg, cb);
        let sev_color = Self::vs_severity_color(&e.severity);

        card_frame().show(ui, |ui| {
            // Title row + badges
            ui.horizontal(|ui| {
                if let Some(sc) = score {
                    let bg = if sc > 0 { Color32::from_rgb(10, 38, 24) } else { Color32::from_rgb(26, 26, 30) };
                    let fg = if sc > 0 { ACCENT } else { TEXT_DIM };
                    Frame::NONE.fill(bg).corner_radius(10.0).inner_margin(Margin::symmetric(8, 2)).show(ui, |ui| {
                        ui.label(RichText::new(format!("⊕ {}", sc)).size(10.0).strong().color(fg));
                    });
                    ui.add_space(4.0);
                }
                ui.label(RichText::new(&e.title).size(13.0).strong().color(TEXT_PRIMARY));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    // complexity badge
                    Frame::NONE.fill(Color32::from_rgb(20, 26, 36)).stroke(Stroke::new(1.0, comp_color))
                        .corner_radius(6.0).inner_margin(Margin::symmetric(7, 2)).show(ui, |ui| {
                        ui.label(RichText::new(format!("⚙ {}", e.complexity.label())).size(10.0).strong().color(comp_color));
                    });
                    ui.add_space(4.0);
                    // severity badge
                    Frame::NONE.fill(sev_color).corner_radius(6.0).inner_margin(Margin::symmetric(7, 2)).show(ui, |ui| {
                        ui.label(RichText::new(e.severity.to_uppercase()).size(10.0).strong().color(Color32::BLACK));
                    });
                    ui.add_space(4.0);
                    // type badge
                    Frame::NONE.fill(Color32::from_rgb(20, 30, 44)).stroke(Stroke::new(1.0, BORDER))
                        .corner_radius(6.0).inner_margin(Margin::symmetric(7, 2)).show(ui, |ui| {
                        ui.label(RichText::new(&e.vuln_type).size(10.0).color(TEXT_SECONDARY));
                    });
                });
            });
            ui.add_space(4.0);

            // Meta line: system • when • how
            ui.label(RichText::new(format!("🖥 {}   •   🕐 {}",
                if e.system.is_empty() { "—" } else { &e.system }, e.discovered_at))
                .size(10.0).color(TEXT_MUTED));
            if !e.how_found.is_empty() {
                ui.label(RichText::new(format!("🔍 How: {}", e.how_found)).size(10.0).color(TEXT_DIM));
            }

            // Tags
            if !e.tags.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    for t in &e.tags {
                        Frame::NONE.fill(Color32::from_rgb(18, 24, 34)).stroke(Stroke::new(1.0, BORDER))
                            .corner_radius(4.0).inner_margin(Margin::symmetric(6, 1)).show(ui, |ui| {
                            ui.label(RichText::new(t).size(9.0).color(TEXT_SECONDARY));
                        });
                        ui.add_space(2.0);
                    }
                });
            }

            // PoC preview
            if !e.poc.is_empty() {
                ui.add_space(4.0);
                let preview: String = e.poc.lines().take(4).collect::<Vec<_>>().join("\n");
                Frame::NONE.fill(TERMINAL_BG).corner_radius(5.0).inner_margin(Margin::same(8)).show(ui, |ui| {
                    ui.label(RichText::new(preview).size(10.5).monospace().color(Color32::from_rgb(126, 231, 135)));
                });
            }

            ui.add_space(6.0);
            // Action row
            ui.horizontal(|ui| {
                if ui.add(accent_button("🎯 Test")).on_hover_text("Load into Repeater against the current target").clicked() {
                    let payload = if !e.payload.is_empty() { e.payload.clone() } else { e.poc.clone() };
                    *test_payload = Some((payload, e.system.clone()));
                }
                if ui.add(subtle_button("📎 Attach")).on_hover_text("Reference from the active engagement").clicked() {
                    *attach_id = Some(e.id);
                }
                if ui.add(subtle_button("📋 PoC")).clicked() {
                    *copy_text = Some(if e.poc.is_empty() { e.payload.clone() } else { e.poc.clone() });
                }
                if ui.add(subtle_button("✎ Edit")).clicked() {
                    *edit_id = Some(e.id);
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add(
                        egui::Button::new(RichText::new("✕ Delete").size(10.0).color(DANGER))
                            .fill(Color32::from_rgb(28, 18, 22)).stroke(Stroke::new(1.0, BORDER)).corner_radius(6.0)
                            .min_size(Vec2::new(70.0, 26.0))
                    ).clicked() {
                        *delete_id = Some(e.id);
                    }
                });
            });
        });
        ui.add_space(8.0);
    }

    /// Apply the staged card actions (shared by Library + Match views).
    fn vs_apply_card_actions(
        &mut self,
        ui: &mut Ui,
        edit_id: Option<usize>,
        delete_id: Option<usize>,
        copy_text: Option<String>,
        test_payload: Option<(String, String)>,
        attach_id: Option<usize>,
    ) {
        if let Some(id) = edit_id {
            self.vs_load_form(id);
            self.vs_view = "Add".into();
        }
        if let Some(id) = delete_id {
            self.vuln_store.remove(id);
            self.vuln_store.save();
            self.push_toast("PoC deleted".to_string(), WARN);
        }
        if let Some(text) = copy_text {
            ui.ctx().copy_text(text);
            self.push_toast("Copied to clipboard".to_string(), ACCENT);
        }
        if let Some((payload, system)) = test_payload {
            // Aim the Repeater at the PoC's system (or the current target as a fallback).
            if !system.is_empty() { self.rep_url = system; }
            else if !self.target.is_empty() { self.rep_url = self.target.clone(); }
            if self.rep_body.is_empty() { self.rep_body = payload; }
            else { self.rep_body.push_str(&format!("\n{}", payload)); }
            self.selected_nav = "Repeater".into();
            self.push_toast("Loaded PoC into Repeater".to_string(), ACCENT);
        }
        if let Some(id) = attach_id {
            let msg = self.vs_attach_to_engagement(id);
            let color = if msg.starts_with("Attached") { ACCENT } else { WARN };
            self.push_toast(msg, color);
        }
    }

    fn vs_view_library(&mut self, ui: &mut Ui) {
        // Filter controls
        let types = self.vuln_store.vuln_types();
        ui.horizontal(|ui| {
            ui.add(TextEdit::singleline(&mut self.vs_search)
                .hint_text("Search title / system / tags…")
                .desired_width(260.0).background_color(INPUT_BG));
            ui.add_space(8.0);
            egui::ComboBox::from_id_salt("vs_type_filter")
                .selected_text(if self.vs_filter_type.is_empty() { "All types".to_string() } else { self.vs_filter_type.clone() })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.vs_filter_type, String::new(), "All types");
                    for t in &types {
                        ui.selectable_value(&mut self.vs_filter_type, t.clone(), t);
                    }
                });
        });
        ui.add_space(8.0);

        let q = self.vs_search.to_lowercase();
        let type_filter = self.vs_filter_type.clone();
        let entries: Vec<crate::vulnstore::PocEntry> = self.vuln_store.entries.iter()
            .filter(|e| type_filter.is_empty() || e.vuln_type.eq_ignore_ascii_case(&type_filter))
            .filter(|e| {
                q.is_empty()
                    || e.title.to_lowercase().contains(&q)
                    || e.system.to_lowercase().contains(&q)
                    || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .cloned().collect();

        let mut edit_id = None;
        let mut delete_id = None;
        let mut copy_text = None;
        let mut test_payload = None;
        let mut attach_id = None;

        if entries.is_empty() {
            ui.add_space(60.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("No PoCs yet").size(15.0).color(TEXT_MUTED));
                ui.add_space(4.0);
                ui.label(RichText::new("Add one with “➕ Add PoC”, then tag it so it surfaces on matching systems.")
                    .size(11.0).color(TEXT_DIM));
            });
        } else {
            ScrollArea::vertical().id_salt("vs_library").auto_shrink([false, false]).show(ui, |ui| {
                for e in &entries {
                    Self::vs_card(ui, e, None, &mut edit_id, &mut delete_id, &mut copy_text, &mut test_payload, &mut attach_id);
                }
            });
        }

        self.vs_apply_card_actions(ui, edit_id, delete_id, copy_text, test_payload, attach_id);
    }

    fn vs_view_match(&mut self, ui: &mut Ui) {
        Frame::NONE.fill(Color32::from_rgb(13, 22, 18)).stroke(Stroke::new(1.0, ACCENT_DIM))
            .corner_radius(8.0).inner_margin(Margin::same(12)).show(ui, |ui| {
            ui.label(RichText::new("CURRENT SYSTEM PROFILE").size(10.0).strong().color(ACCENT));
            ui.add_space(4.0);
            ui.label(RichText::new("Describe the target with tags (tech, stack, vuln types). PoCs are ranked by how well their tags overlap. The target host is always factored in.")
                .size(10.0).color(TEXT_MUTED));
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("🎯").size(13.0).color(ACCENT));
                ui.add(TextEdit::singleline(&mut self.vs_match_tags)
                    .hint_text("e.g. php, mysql, wordpress, idor, http://target:3000")
                    .desired_width(ui.available_width() - 90.0).background_color(INPUT_BG));
                if ui.add(subtle_button("Use target")).clicked() {
                    self.vs_match_tags = self.target.clone();
                }
            });
        });
        ui.add_space(10.0);

        let want = crate::vulnstore::parse_tags(&self.vs_match_tags);
        let target = self.target.clone();
        let ranked = self.vuln_store.ranked_for(&target, &want);
        let matches = ranked.iter().filter(|(_, s)| *s > 0).count();

        ui.label(RichText::new(format!("{} of {} PoCs match this system", matches, ranked.len()))
            .size(11.0).color(if matches > 0 { ACCENT } else { TEXT_MUTED }));
        ui.add_space(6.0);

        // Build an id->entry map for rendering in ranked order.
        let by_id: std::collections::HashMap<usize, crate::vulnstore::PocEntry> =
            self.vuln_store.entries.iter().map(|e| (e.id, e.clone())).collect();

        let mut edit_id = None;
        let mut delete_id = None;
        let mut copy_text = None;
        let mut test_payload = None;
        let mut attach_id = None;

        if ranked.is_empty() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("The store is empty — add some tagged PoCs first").size(13.0).color(TEXT_MUTED));
            });
        } else {
            ScrollArea::vertical().id_salt("vs_match").auto_shrink([false, false]).show(ui, |ui| {
                for (id, score) in &ranked {
                    if let Some(e) = by_id.get(id) {
                        Self::vs_card(ui, e, Some(*score), &mut edit_id, &mut delete_id, &mut copy_text, &mut test_payload, &mut attach_id);
                    }
                }
            });
        }

        self.vs_apply_card_actions(ui, edit_id, delete_id, copy_text, test_payload, attach_id);
    }

    fn vs_view_editor(&mut self, ui: &mut Ui) {
        let editing = self.vs_edit_id.is_some();
        let mut do_save = false;
        let mut do_cancel = false;

        ScrollArea::vertical().id_salt("vs_editor").auto_shrink([false, false]).show(ui, |ui| {
            card_frame().show(ui, |ui| {
                section_title(ui, if editing { "EDIT PoC" } else { "NEW PoC" });

                ui.label(RichText::new("Title").size(10.0).color(TEXT_MUTED));
                ui.add(TextEdit::singleline(&mut self.vs_f_title)
                    .hint_text("Short name, e.g. “IDOR on /api/orders/{id}”")
                    .desired_width(f32::INFINITY).background_color(INPUT_BG));
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Vuln type").size(10.0).color(TEXT_MUTED));
                        ui.add(TextEdit::singleline(&mut self.vs_f_type)
                            .hint_text("SQLi, XSS, IDOR…").desired_width(150.0).background_color(INPUT_BG));
                    });
                    ui.add_space(10.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Severity").size(10.0).color(TEXT_MUTED));
                        egui::ComboBox::from_id_salt("vs_f_sev")
                            .selected_text(self.vs_f_severity.clone()).width(120.0)
                            .show_ui(ui, |ui| {
                                for s in ["critical", "high", "medium", "low", "info"] {
                                    ui.selectable_value(&mut self.vs_f_severity, s.to_string(), s);
                                }
                            });
                    });
                    ui.add_space(10.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Exploit complexity").size(10.0).color(TEXT_MUTED));
                        egui::ComboBox::from_id_salt("vs_f_complexity")
                            .selected_text(self.vs_f_complexity.label()).width(130.0)
                            .show_ui(ui, |ui| {
                                for c in crate::vulnstore::Complexity::all() {
                                    ui.selectable_value(&mut self.vs_f_complexity, *c, c.label());
                                }
                            });
                    });
                });
                ui.label(RichText::new(format!("↳ {}", self.vs_f_complexity.hint())).size(9.0).color(TEXT_DIM));
                ui.add_space(8.0);

                ui.label(RichText::new("System where found").size(10.0).color(TEXT_MUTED));
                ui.add(TextEdit::singleline(&mut self.vs_f_system)
                    .hint_text("host / URL / app name").desired_width(f32::INFINITY).background_color(INPUT_BG));
                ui.add_space(8.0);

                ui.label(RichText::new("How it was found").size(10.0).color(TEXT_MUTED));
                ui.add(TextEdit::multiline(&mut self.vs_f_how)
                    .hint_text("Discovery method / observation / tool").desired_rows(2)
                    .desired_width(f32::INFINITY).background_color(INPUT_BG));
                ui.add_space(8.0);

                ui.label(RichText::new("Proof of Concept (steps / request to reproduce & exploit)").size(10.0).color(TEXT_MUTED));
                ui.add(TextEdit::multiline(&mut self.vs_f_poc)
                    .hint_text("GET /api/orders/1043 with another user's session →\nreturns the victim's order; increment id to enumerate.")
                    .desired_rows(6).font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY).background_color(INPUT_BG));
                ui.add_space(8.0);

                ui.label(RichText::new("Key payload (optional — feeds Repeater/Intruder when you Test)").size(10.0).color(TEXT_MUTED));
                ui.add(TextEdit::singleline(&mut self.vs_f_payload)
                    .hint_text("e.g. ' OR 1=1--").font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY).background_color(INPUT_BG));
                ui.add_space(8.0);

                ui.label(RichText::new("Tags (comma separated — used for per-system matching)").size(10.0).color(TEXT_MUTED));
                ui.add(TextEdit::singleline(&mut self.vs_f_tags)
                    .hint_text("php, mysql, wordpress, idor, api").desired_width(f32::INFINITY).background_color(INPUT_BG));
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("References (CVE / CWE / links)").size(10.0).color(TEXT_MUTED));
                        ui.add(TextEdit::singleline(&mut self.vs_f_refs)
                            .hint_text("CWE-639, CVE-2024-…").desired_width(300.0).background_color(INPUT_BG));
                    });
                });
                ui.add_space(8.0);

                ui.label(RichText::new("Notes").size(10.0).color(TEXT_MUTED));
                ui.add(TextEdit::multiline(&mut self.vs_f_notes)
                    .hint_text("Anything else worth remembering").desired_rows(2)
                    .desired_width(f32::INFINITY).background_color(INPUT_BG));
                ui.add_space(12.0);

                ui.horizontal(|ui| {
                    if ui.add(accent_button(if editing { "💾 Save changes" } else { "💾 Save PoC" })).clicked() {
                        do_save = true;
                    }
                    ui.add_space(6.0);
                    if ui.add(subtle_button("Cancel")).clicked() {
                        do_cancel = true;
                    }
                    if self.vs_f_title.trim().is_empty() {
                        ui.add_space(8.0);
                        ui.label(RichText::new("A title is required").size(10.0).color(WARN));
                    }
                });
            });
        });

        if do_save && !self.vs_f_title.trim().is_empty() {
            let entry = crate::vulnstore::PocEntry {
                id: self.vs_edit_id.unwrap_or(0),
                title: self.vs_f_title.trim().to_string(),
                vuln_type: self.vs_f_type.trim().to_string(),
                severity: self.vs_f_severity.clone(),
                complexity: self.vs_f_complexity,
                system: self.vs_f_system.trim().to_string(),
                discovered_at: crate::vulnstore::timestamp(),
                how_found: self.vs_f_how.trim().to_string(),
                poc: self.vs_f_poc.clone(),
                payload: self.vs_f_payload.clone(),
                tags: crate::vulnstore::parse_tags(&self.vs_f_tags),
                references: self.vs_f_refs.trim().to_string(),
                notes: self.vs_f_notes.clone(),
            };
            match self.vs_edit_id {
                Some(id) => {
                    if let Some(slot) = self.vuln_store.entries.iter_mut().find(|e| e.id == id) {
                        let created = slot.discovered_at.clone();
                        *slot = entry;
                        slot.discovered_at = created; // preserve original discovery time on edit
                    }
                    self.push_toast("PoC updated".to_string(), ACCENT);
                }
                None => {
                    self.vuln_store.add(entry);
                    self.push_toast("PoC saved to store".to_string(), ACCENT);
                }
            }
            self.vuln_store.save();
            self.vs_reset_form();
            self.vs_view = "Library".into();
        }
        if do_cancel {
            self.vs_reset_form();
            self.vs_view = "Library".into();
        }
    }
}
