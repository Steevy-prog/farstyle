// Payload library + Wordlist bank pages — editable catalogues that feed the
// Intruder and external fuzzers. Split out of the GUI monolith; see gui/mod.rs.

use super::*;

impl NullForgeApp {
    // ═══════════════════════════════════════════════════════════════════════
    // PAYLOAD LIBRARY PAGE
    // ═══════════════════════════════════════════════════════════════════════
    pub(crate) fn page_payloads(&mut self, ui: &mut Ui) {
        let avail = ui.available_size();

        // Keep the editable library non-empty and the selection valid.
        if self.payload_lib.is_empty() {
            self.payload_lib = crate::config::default_payload_categories();
        }
        if !self.payload_lib.iter().any(|c| c.name == self.payload_lib_category) {
            self.payload_lib_category = self.payload_lib.first().map(|c| c.name.clone()).unwrap_or_default();
        }

        // Snapshot for rendering, so the UI closures don't hold a borrow of
        // self.payload_lib while we also mutate self (toasts / navigation).
        let cat_names: Vec<String> = self.payload_lib.iter().map(|c| c.name.clone()).collect();
        let cur = self.payload_lib_category.clone();
        let search = self.payload_lib_search.to_lowercase();
        let cur_items: Vec<String> = self.payload_lib.iter()
            .find(|c| c.name == cur).map(|c| c.items.clone()).unwrap_or_default();
        let shown: Vec<String> = if search.is_empty() { cur_items.clone() }
            else { cur_items.iter().filter(|p| p.to_lowercase().contains(&search)).cloned().collect() };

        // Staged actions — applied after the UI to avoid borrow conflicts.
        let mut select_category: Option<String> = None;
        let mut delete_category: Option<String> = None;
        let mut do_add_category = false;
        let mut do_add_item = false;
        let mut remove_item: Option<String> = None;
        let mut to_repeater: Option<String> = None;
        let mut to_intruder: Option<String> = None;
        let mut copy_text: Option<String> = None;
        let mut toast: Option<String> = None;

        ui.horizontal_top(|ui| {
            // ── Left: category panel (with add / delete) ──────────────────
            ui.allocate_ui_with_layout(Vec2::new(190.0, avail.y), Layout::top_down(Align::LEFT), |ui| {
                card_frame().show(ui, |ui| {
                    section_title(ui, "CATEGORIES");
                    ScrollArea::vertical().id_salt("payload_cats").max_height((avail.y - 150.0).max(120.0)).show(ui, |ui| {
                        for name in &cat_names {
                            let sel = *name == cur;
                            ui.horizontal(|ui| {
                                if ui.add(
                                    egui::Button::new(RichText::new(name).size(12.0)
                                        .color(if sel { Color32::BLACK } else { TEXT_SECONDARY }))
                                        .fill(if sel { ACCENT } else { Color32::from_rgb(22, 30, 44) })
                                        .stroke(Stroke::new(1.0, if sel { ACCENT } else { BORDER }))
                                        .corner_radius(6.0)
                                        .min_size(Vec2::new((ui.available_width() - 40.0).max(60.0), 32.0))
                                ).clicked() {
                                    select_category = Some(name.clone());
                                }
                                if ui.add(
                                    egui::Button::new(RichText::new("✕").size(11.0).color(TEXT_MUTED))
                                        .fill(Color32::from_rgb(30, 18, 22))
                                        .stroke(Stroke::new(1.0, BORDER))
                                        .corner_radius(6.0)
                                        .min_size(Vec2::new(24.0, 32.0))
                                ).on_hover_text("Delete category").clicked() {
                                    delete_category = Some(name.clone());
                                }
                            });
                            ui.add_space(2.0);
                        }
                    });
                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.label(RichText::new("NEW CATEGORY").size(9.0).strong().color(TEXT_DIM));
                    ui.add_space(3.0);
                    ui.add(TextEdit::singleline(&mut self.payload_new_category)
                        .hint_text("e.g. NoSQLi")
                        .desired_width(f32::INFINITY)
                        .background_color(INPUT_BG));
                    ui.add_space(4.0);
                    if ui.add(accent_button("+ Add Category")).clicked() {
                        do_add_category = true;
                    }
                });
            });
            ui.add_space(10.0);

            // ── Right: editable payload list ──────────────────────────────
            ui.allocate_ui_with_layout(Vec2::new((avail.x - 200.0 - 10.0 - 24.0).max(200.0), avail.y), Layout::top_down(Align::LEFT), |ui| {
                card_frame().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("💣  {}", cur)).size(13.0).strong().color(ACCENT));
                        ui.add_space(6.0);
                        ui.label(RichText::new(format!("{} payloads", cur_items.len())).size(10.0).color(TEXT_MUTED));
                        ui.add_space(8.0);
                        ui.add(TextEdit::singleline(&mut self.payload_lib_search)
                            .hint_text("Filter…")
                            .desired_width(150.0)
                            .background_color(INPUT_BG));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.add(subtle_button("Copy All")).clicked() {
                                copy_text = Some(cur_items.join("\n"));
                                toast = Some("All payloads copied".into());
                            }
                        });
                    });
                    ui.add_space(8.0);
                    // Add-payload row
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("➕").size(13.0).color(ACCENT));
                        let r = ui.add(TextEdit::singleline(&mut self.payload_new_item)
                            .hint_text("Add a payload to this category…  (Enter)")
                            .desired_width((ui.available_width() - 124.0).max(80.0))
                            .background_color(INPUT_BG));
                        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if ui.add(accent_button("Add")).clicked() || enter {
                            do_add_item = true;
                        }
                    });
                });

                ui.add_space(6.0);

                ScrollArea::vertical().id_salt("payload_list").auto_shrink([false, false]).show(ui, |ui| {
                    for (i, payload) in shown.iter().enumerate() {
                        let row_bg = if i % 2 == 0 { Color32::from_rgb(14, 20, 30) } else { Color32::from_rgb(18, 26, 38) };
                        Frame::NONE.fill(row_bg).corner_radius(4.0).inner_margin(Margin::symmetric(10, 6)).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("{:>2}.", i + 1)).size(10.0).color(TEXT_DIM));
                                ui.add_space(6.0);
                                ui.label(RichText::new(payload).size(11.0).monospace().color(TEXT_SECONDARY));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui.add(
                                        egui::Button::new(RichText::new("✕").size(10.0).color(DANGER))
                                            .fill(Color32::from_rgb(28, 18, 22))
                                            .stroke(Stroke::new(1.0, BORDER))
                                            .corner_radius(4.0)
                                    ).on_hover_text("Remove payload").clicked() {
                                        remove_item = Some(payload.clone());
                                    }
                                    if ui.add(
                                        egui::Button::new(RichText::new("📋").size(10.0).color(TEXT_SECONDARY))
                                            .fill(Color32::from_rgb(18, 26, 38))
                                            .stroke(Stroke::new(1.0, BORDER))
                                            .corner_radius(4.0)
                                    ).on_hover_text("Copy").clicked() {
                                        copy_text = Some(payload.clone());
                                    }
                                    if ui.add(
                                        egui::Button::new(RichText::new("⚡").size(10.0).color(TEXT_SECONDARY))
                                            .fill(Color32::from_rgb(20, 25, 40))
                                            .stroke(Stroke::new(1.0, Color32::from_rgb(80, 60, 10)))
                                            .corner_radius(4.0)
                                    ).on_hover_text("Send to Intruder slot 1").clicked() {
                                        to_intruder = Some(payload.clone());
                                    }
                                    if ui.add(
                                        egui::Button::new(RichText::new("↻").size(10.0).color(TEXT_SECONDARY))
                                            .fill(Color32::from_rgb(20, 30, 44))
                                            .stroke(Stroke::new(1.0, BORDER))
                                            .corner_radius(4.0)
                                    ).on_hover_text("Send to Repeater").clicked() {
                                        to_repeater = Some(payload.clone());
                                    }
                                });
                            });
                        });
                        ui.add_space(1.0);
                    }
                    if shown.is_empty() {
                        ui.add_space(50.0);
                        ui.vertical_centered(|ui| {
                            ui.label(RichText::new(if cur_items.is_empty() { "No payloads yet — add one above" }
                                else { "No payloads match your filter" })
                                .size(13.0).color(TEXT_MUTED));
                        });
                    }
                });
            });
        });

        // ── Apply staged actions ──────────────────────────────────────────
        let mut dirty = false;
        if let Some(name) = select_category {
            self.payload_lib_category = name;
            self.payload_lib_search.clear();
        }
        if let Some(name) = delete_category {
            self.payload_lib.retain(|c| c.name != name);
            if self.payload_lib_category == name {
                self.payload_lib_category = self.payload_lib.first().map(|c| c.name.clone()).unwrap_or_default();
            }
            dirty = true;
            toast = Some("Category deleted".into());
        }
        if do_add_category {
            let name = self.payload_new_category.trim().to_string();
            if !name.is_empty() && !self.payload_lib.iter().any(|c| c.name.eq_ignore_ascii_case(&name)) {
                self.payload_lib.push(crate::config::SavedPayloadCategory { name: name.clone(), items: vec![] });
                self.payload_lib_category = name;
                self.payload_new_category.clear();
                dirty = true;
                toast = Some("Category added".into());
            }
        }
        if do_add_item {
            let item = self.payload_new_item.trim().to_string();
            if !item.is_empty() {
                if let Some(c) = self.payload_lib.iter_mut().find(|c| c.name == cur) {
                    if !c.items.contains(&item) { c.items.push(item); dirty = true; }
                }
                self.payload_new_item.clear();
            }
        }
        if let Some(val) = remove_item {
            if let Some(c) = self.payload_lib.iter_mut().find(|c| c.name == cur) {
                if let Some(pos) = c.items.iter().position(|x| x == &val) { c.items.remove(pos); dirty = true; }
            }
        }
        if let Some(text) = copy_text {
            ui.ctx().copy_text(text);
        }
        if let Some(p) = to_repeater {
            if self.rep_body.is_empty() { self.rep_body = p; } else { self.rep_body.push_str(&format!("\n{}", p)); }
            self.selected_nav = "Repeater".into();
            toast = Some("Payload sent to Repeater".into());
        }
        if let Some(p) = to_intruder {
            if let Some(pos) = self.intr_positions.get_mut(0) { pos.payloads.push(p); }
            self.selected_nav = "Intruder".into();
            toast = Some("Payload added to Intruder slot 1".into());
        }
        if let Some(t) = toast { self.push_toast(t, ACCENT); }
        if dirty { self.save_config(); }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORDLIST BANK PAGE
    // ═══════════════════════════════════════════════════════════════════════
    pub(crate) fn page_wordlists(&mut self, ui: &mut Ui) {
        let avail = ui.available_size();

        // Keep the bank non-empty and the selection valid.
        if self.wordlist_lib.is_empty() {
            self.wordlist_lib = crate::config::default_wordlist_categories();
        }
        if !self.wordlist_lib.iter().any(|c| c.name == self.wordlist_category) {
            self.wordlist_category = self.wordlist_lib.first().map(|c| c.name.clone()).unwrap_or_default();
        }

        // Snapshot for rendering so the UI closures don't borrow self.wordlist_lib
        // while we also mutate self (toasts / navigation).
        let cat_names: Vec<String> = self.wordlist_lib.iter().map(|c| c.name.clone()).collect();
        let cur = self.wordlist_category.clone();
        let search = self.wordlist_search.to_lowercase();
        let cur_items: Vec<String> = self.wordlist_lib.iter()
            .find(|c| c.name == cur).map(|c| c.items.clone()).unwrap_or_default();
        let shown: Vec<String> = if search.is_empty() { cur_items.clone() }
            else { cur_items.iter().filter(|p| p.to_lowercase().contains(&search)).cloned().collect() };

        // Staged actions — applied after the UI to avoid borrow conflicts.
        let mut select_category: Option<String> = None;
        let mut delete_category: Option<String> = None;
        let mut do_add_category = false;
        let mut do_add_item = false;
        let mut remove_item: Option<String> = None;
        let mut word_to_intruder: Option<String> = None;
        let mut list_to_intruder = false;
        let mut do_export = false;
        let mut do_import = false;
        let mut copy_text: Option<String> = None;
        let mut toast: Option<String> = None;

        ui.horizontal_top(|ui| {
            // ── Left: list panel (with add / delete) ──────────────────────
            ui.allocate_ui_with_layout(Vec2::new(190.0, avail.y), Layout::top_down(Align::LEFT), |ui| {
                card_frame().show(ui, |ui| {
                    section_title(ui, "WORDLISTS");
                    ScrollArea::vertical().id_salt("wordlist_cats").max_height((avail.y - 150.0).max(120.0)).show(ui, |ui| {
                        for name in &cat_names {
                            let sel = *name == cur;
                            ui.horizontal(|ui| {
                                if ui.add(
                                    egui::Button::new(RichText::new(name).size(12.0)
                                        .color(if sel { Color32::BLACK } else { TEXT_SECONDARY }))
                                        .fill(if sel { ACCENT } else { Color32::from_rgb(22, 30, 44) })
                                        .stroke(Stroke::new(1.0, if sel { ACCENT } else { BORDER }))
                                        .corner_radius(6.0)
                                        .min_size(Vec2::new((ui.available_width() - 40.0).max(60.0), 32.0))
                                ).clicked() {
                                    select_category = Some(name.clone());
                                }
                                if ui.add(
                                    egui::Button::new(RichText::new("✕").size(11.0).color(TEXT_MUTED))
                                        .fill(Color32::from_rgb(30, 18, 22))
                                        .stroke(Stroke::new(1.0, BORDER))
                                        .corner_radius(6.0)
                                        .min_size(Vec2::new(24.0, 32.0))
                                ).on_hover_text("Delete wordlist").clicked() {
                                    delete_category = Some(name.clone());
                                }
                            });
                            ui.add_space(2.0);
                        }
                    });
                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.label(RichText::new("NEW WORDLIST").size(9.0).strong().color(TEXT_DIM));
                    ui.add_space(3.0);
                    ui.add(TextEdit::singleline(&mut self.wordlist_new_category)
                        .hint_text("e.g. CMS paths")
                        .desired_width(f32::INFINITY)
                        .background_color(INPUT_BG));
                    ui.add_space(4.0);
                    if ui.add(accent_button("+ Add Wordlist")).clicked() {
                        do_add_category = true;
                    }
                    ui.add_space(4.0);
                    if ui.add(subtle_button("⬆ Import .txt")).on_hover_text("Append lines from a text file into this wordlist").clicked() {
                        do_import = true;
                    }
                });
            });
            ui.add_space(10.0);

            // ── Right: editable word list ─────────────────────────────────
            ui.allocate_ui_with_layout(Vec2::new((avail.x - 200.0 - 10.0 - 24.0).max(200.0), avail.y), Layout::top_down(Align::LEFT), |ui| {
                card_frame().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("📋  {}", cur)).size(13.0).strong().color(ACCENT));
                        ui.add_space(6.0);
                        ui.label(RichText::new(format!("{} words", cur_items.len())).size(10.0).color(TEXT_MUTED));
                        ui.add_space(8.0);
                        ui.add(TextEdit::singleline(&mut self.wordlist_search)
                            .hint_text("Filter…")
                            .desired_width(150.0)
                            .background_color(INPUT_BG));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.add(subtle_button("Copy All")).clicked() {
                                copy_text = Some(cur_items.join("\n"));
                                toast = Some("Wordlist copied".into());
                            }
                            if ui.add(subtle_button("⬇ Export")).on_hover_text("Save this list as a .txt for ffuf / gobuster / sqlmap").clicked() {
                                do_export = true;
                            }
                            if ui.add(subtle_button("⚡ Send to Intruder")).on_hover_text("Load the whole list into Intruder slot 1").clicked() {
                                list_to_intruder = true;
                            }
                        });
                    });
                    ui.add_space(8.0);
                    // Add-word row
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("➕").size(13.0).color(ACCENT));
                        let r = ui.add(TextEdit::singleline(&mut self.wordlist_new_item)
                            .hint_text("Add a word to this list…  (Enter)")
                            .desired_width((ui.available_width() - 124.0).max(80.0))
                            .background_color(INPUT_BG));
                        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if ui.add(accent_button("Add")).clicked() || enter {
                            do_add_item = true;
                        }
                    });
                });

                ui.add_space(6.0);

                ScrollArea::vertical().id_salt("wordlist_list").auto_shrink([false, false]).show(ui, |ui| {
                    for (i, word) in shown.iter().enumerate() {
                        let row_bg = if i % 2 == 0 { Color32::from_rgb(14, 20, 30) } else { Color32::from_rgb(18, 26, 38) };
                        Frame::NONE.fill(row_bg).corner_radius(4.0).inner_margin(Margin::symmetric(10, 6)).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("{:>3}.", i + 1)).size(10.0).color(TEXT_DIM));
                                ui.add_space(6.0);
                                ui.label(RichText::new(word).size(11.0).monospace().color(TEXT_SECONDARY));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui.add(
                                        egui::Button::new(RichText::new("✕").size(10.0).color(DANGER))
                                            .fill(Color32::from_rgb(28, 18, 22))
                                            .stroke(Stroke::new(1.0, BORDER))
                                            .corner_radius(4.0)
                                    ).on_hover_text("Remove word").clicked() {
                                        remove_item = Some(word.clone());
                                    }
                                    if ui.add(
                                        egui::Button::new(RichText::new("📋").size(10.0).color(TEXT_SECONDARY))
                                            .fill(Color32::from_rgb(18, 26, 38))
                                            .stroke(Stroke::new(1.0, BORDER))
                                            .corner_radius(4.0)
                                    ).on_hover_text("Copy").clicked() {
                                        copy_text = Some(word.clone());
                                    }
                                    if ui.add(
                                        egui::Button::new(RichText::new("⚡").size(10.0).color(TEXT_SECONDARY))
                                            .fill(Color32::from_rgb(20, 25, 40))
                                            .stroke(Stroke::new(1.0, Color32::from_rgb(80, 60, 10)))
                                            .corner_radius(4.0)
                                    ).on_hover_text("Send to Intruder slot 1").clicked() {
                                        word_to_intruder = Some(word.clone());
                                    }
                                });
                            });
                        });
                        ui.add_space(1.0);
                    }
                    if shown.is_empty() {
                        ui.add_space(50.0);
                        ui.vertical_centered(|ui| {
                            ui.label(RichText::new(if cur_items.is_empty() { "Empty wordlist — add a word above or import a .txt" }
                                else { "No words match your filter" })
                                .size(13.0).color(TEXT_MUTED));
                        });
                    }
                });
            });
        });

        // ── Apply staged actions ──────────────────────────────────────────
        let mut dirty = false;
        if let Some(name) = select_category {
            self.wordlist_category = name;
            self.wordlist_search.clear();
        }
        if let Some(name) = delete_category {
            self.wordlist_lib.retain(|c| c.name != name);
            if self.wordlist_category == name {
                self.wordlist_category = self.wordlist_lib.first().map(|c| c.name.clone()).unwrap_or_default();
            }
            dirty = true;
            toast = Some("Wordlist deleted".into());
        }
        if do_add_category {
            let name = self.wordlist_new_category.trim().to_string();
            if !name.is_empty() && !self.wordlist_lib.iter().any(|c| c.name.eq_ignore_ascii_case(&name)) {
                self.wordlist_lib.push(crate::config::SavedPayloadCategory { name: name.clone(), items: vec![] });
                self.wordlist_category = name;
                self.wordlist_new_category.clear();
                dirty = true;
                toast = Some("Wordlist added".into());
            }
        }
        if do_add_item {
            let item = self.wordlist_new_item.trim().to_string();
            if !item.is_empty() {
                if let Some(c) = self.wordlist_lib.iter_mut().find(|c| c.name == cur) {
                    if !c.items.contains(&item) { c.items.push(item); dirty = true; }
                }
                self.wordlist_new_item.clear();
            }
        }
        if let Some(val) = remove_item {
            if let Some(c) = self.wordlist_lib.iter_mut().find(|c| c.name == cur) {
                if let Some(pos) = c.items.iter().position(|x| x == &val) { c.items.remove(pos); dirty = true; }
            }
        }
        if do_import {
            if let Some(path) = rfd::FileDialog::new().add_filter("Text", &["txt", "lst", "dic"]).pick_file() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Some(c) = self.wordlist_lib.iter_mut().find(|c| c.name == cur) {
                        let before = c.items.len();
                        for line in content.lines().map(|l| l.trim()).filter(|l| !l.is_empty()) {
                            if !c.items.iter().any(|x| x == line) { c.items.push(line.to_string()); }
                        }
                        let added = c.items.len() - before;
                        dirty = true;
                        toast = Some(format!("Imported {} new words", added));
                    }
                }
            }
        }
        if do_export {
            let suggested = format!("{}.txt", cur.to_lowercase().replace(' ', "_"));
            if let Some(path) = rfd::FileDialog::new().set_file_name(&suggested).add_filter("Text", &["txt"]).save_file() {
                match std::fs::write(&path, cur_items.join("\n")) {
                    Ok(_)  => toast = Some(format!("Exported {} words", cur_items.len())),
                    Err(e) => toast = Some(format!("Export failed: {}", e)),
                }
            }
        }
        if let Some(text) = copy_text {
            ui.ctx().copy_text(text);
        }
        if let Some(w) = word_to_intruder {
            if let Some(pos) = self.intr_positions.get_mut(0) { pos.payloads.push(w); }
            self.selected_nav = "Intruder".into();
            toast = Some("Word added to Intruder slot 1".into());
        }
        if list_to_intruder {
            if let Some(pos) = self.intr_positions.get_mut(0) {
                pos.payloads = cur_items.clone();
            }
            self.selected_nav = "Intruder".into();
            toast = Some(format!("Loaded {} words into Intruder slot 1", cur_items.len()));
        }
        if let Some(t) = toast { self.push_toast(t, ACCENT); }
        if dirty { self.save_config(); }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // OBFUSCATION LAB
    // ═══════════════════════════════════════════════════════════════════════
    pub(crate) fn page_obfuscator(&mut self, ui: &mut Ui) {
        ScrollArea::vertical().id_salt("obf_page").auto_shrink([false, false]).show(ui, |ui| {
        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("🌀").size(16.0));
                section_title(ui, "OBFUSCATION LAB");
            });
            ui.label(RichText::new("Take a payload and transform it to evade naive filters/WAFs. Use the one-click transforms, or let the model generate functional evasion variants. Save anything useful straight to the Knowledge Base.")
                .size(10.0).color(TEXT_MUTED));
            ui.add_space(8.0);

            ui.label(RichText::new("Payload").size(11.0).color(TEXT_MUTED));
            ui.add(TextEdit::multiline(&mut self.obf_input)
                .desired_rows(3).font(egui::TextStyle::Monospace)
                .desired_width(f32::INFINITY).background_color(INPUT_BG)
                .hint_text("<script>alert(1)</script>  ·  ' OR 1=1--  ·  ../../etc/passwd"));

            ui.add_space(6.0);
            ui.label(RichText::new("Target / filter to evade (optional — guides the AI)").size(11.0).color(TEXT_MUTED));
            ui.add(TextEdit::singleline(&mut self.obf_context)
                .desired_width(f32::INFINITY).background_color(INPUT_BG)
                .hint_text("e.g. Cloudflare WAF blocks <script> and quotes; reflected in an HTML attribute"));

            // One-click deterministic transforms.
            ui.add_space(10.0);
            ui.label(RichText::new("QUICK TRANSFORMS").size(10.0).color(TEXT_DIM));
            ui.add_space(4.0);
            let techniques = [
                "URL encode", "Double URL encode", "Base64", "Hex", "HTML entities",
                "Unicode \\uXXXX", "HTML \\xNN escape", "HTML decimal ents", "Mixed case", "SQL comment split",
            ];
            ui.horizontal_wrapped(|ui| {
                for t in techniques {
                    if ui.add(subtle_button(t)).clicked() && !self.obf_input.trim().is_empty() {
                        self.obf_output = format!("[{}]\n{}", t, Self::obfuscate_local(t, &self.obf_input));
                    }
                }
            });

            // AI obfuscation.
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                let busy = self.obf_busy;
                if busy {
                    ui.add(egui::Button::new(RichText::new("⏳ Generating variants…").size(12.0).color(TEXT_DIM))
                        .fill(Color32::from_rgb(25, 35, 48)).corner_radius(8.0).min_size(Vec2::new(200.0, 34.0)));
                } else if ui.add(egui::Button::new(RichText::new("🤖 AI Obfuscate").size(12.0).color(Color32::BLACK))
                        .fill(ACCENT).corner_radius(8.0).min_size(Vec2::new(160.0, 34.0))).clicked()
                        && !self.obf_input.trim().is_empty() {
                    self.run_ai_obfuscation();
                }
                if ui.add(subtle_button("Clear")).clicked() { self.obf_output.clear(); }
            });
        });

        // Output + save-to-KB.
        if !self.obf_output.is_empty() {
            ui.add_space(8.0);
            card_frame().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("RESULT").size(10.0).color(TEXT_DIM));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.add(subtle_button("💾 Save to KB")).clicked() {
                            let src = self.obf_input.chars().take(60).collect::<String>();
                            let title = format!("Obfuscation: {}", src);
                            let content = format!(
                                "Original payload:\n{}\n\nContext: {}\n\nObfuscated variants:\n{}",
                                self.obf_input,
                                if self.obf_context.trim().is_empty() { "(none)".into() } else { self.obf_context.clone() },
                                self.obf_output
                            );
                            let id = self.kb_next_id;
                            self.kb_next_id += 1;
                            self.kb_docs.push(crate::knowledge::KbDoc::new_competence(id, title.clone(), content));
                            self.save_config();
                            self.push_toast(format!("Saved to Knowledge Base: {}", title), ACCENT);
                        }
                        if ui.add(subtle_button("Copy")).clicked() {
                            ui.ctx().copy_text(self.obf_output.clone());
                            self.push_toast("Copied".to_string(), ACCENT);
                        }
                    });
                });
                ui.add_space(6.0);
                Frame::NONE.fill(TERMINAL_BG).corner_radius(6.0).inner_margin(Margin::same(10)).show(ui, |ui| {
                    ScrollArea::vertical().id_salt("obf_output").max_height(360.0).auto_shrink([false, true]).show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        for line in self.obf_output.lines() {
                            let color = if line.starts_with("TECHNIQUE") || line.starts_with('[') { ACCENT }
                                else if line.starts_with("PAYLOAD") { Color32::from_rgb(120, 200, 255) }
                                else if line.starts_with("WHY") { TEXT_MUTED }
                                else { TEXT_SECONDARY };
                            ui.label(RichText::new(line).size(11.0).monospace().color(color));
                        }
                    });
                });
            });
        }
        });
    }
}
