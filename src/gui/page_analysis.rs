// Intelligence & analysis pages: JWT, Mind Base, Hypotheses, OSINT, Diff Viewer,
// plus the command palette. Split out of the GUI monolith; see gui/mod.rs.

use super::*;

impl NullForgeApp {

    // ═══════════════════════════════════════════════════════════════════════
    // JWT PAGE
    // ═══════════════════════════════════════════════════════════════════════
    pub(crate) fn page_jwt(&mut self, ui: &mut Ui) {
        let avail = ui.available_size();
        ui.horizontal_top(|ui| {
            // ── Left panel ────────────────────────────────────────────────
            ui.allocate_ui_with_layout(Vec2::new(340.0, avail.y), Layout::top_down(Align::LEFT), |ui| {
                card_frame().show(ui, |ui| {
                    section_title(ui, "JWT ANALYZER");
                    ui.add_space(6.0);
                    ui.label(RichText::new("Paste JWT token").size(11.0).color(TEXT_MUTED));
                    ui.add_space(4.0);
                    ui.add(TextEdit::multiline(&mut self.jwt_input)
                        .desired_width(f32::INFINITY)
                        .desired_rows(4)
                        .hint_text("eyJhbGciOiJIUzI1NiJ9…")
                        .background_color(TERMINAL_BG)
                        .font(egui::TextStyle::Monospace));
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.add_sized(Vec2::new((ui.available_width() - 8.0) / 2.0, 36.0),
                            egui::Button::new(RichText::new("🔍 Decode").size(12.0).color(Color32::BLACK)).fill(ACCENT).corner_radius(8.0)
                        ).clicked() {
                            self.decode_jwt();
                        }
                        if ui.add_sized(Vec2::new(ui.available_width(), 36.0),
                            subtle_button("Clear")
                        ).clicked() {
                            self.jwt_input.clear(); self.jwt_header.clear();
                            self.jwt_payload.clear(); self.jwt_signature.clear();
                            self.jwt_edit_payload.clear(); self.jwt_attack_result.clear();
                        }
                    });
                });

                ui.add_space(10.0);

                // ── Attack panel ──────────────────────────────────────────
                card_frame().show(ui, |ui| {
                    section_title(ui, "ATTACK");
                    ui.add_space(6.0);

                    // none algorithm attack
                    if ui.add_sized(Vec2::new(ui.available_width(), 34.0),
                        egui::Button::new(RichText::new("⚡ None Algorithm Attack").size(11.0).color(TEXT_PRIMARY))
                            .fill(Color32::from_rgb(60, 20, 20))
                            .stroke(Stroke::new(1.0, DANGER))
                            .corner_radius(6.0)
                    ).clicked() {
                        // Build alg:none token from current payload
                        let header = r#"{"alg":"none","typ":"JWT"}"#;
                        let encode_b64 = |s: &str| -> String {
                            crate::crypto::b64_encode_url(s.as_bytes())
                        };
                        let h = encode_b64(header);
                        let p = encode_b64(&self.jwt_edit_payload);
                        self.jwt_attack_result = format!(
                            "None-alg token:\n{}.{}.\n\nSend this to a server that fails to validate 'alg:none' to bypass signature verification.",
                            h, p
                        );
                        self.audit("AI", "JWT none-alg attack token generated".to_string());
                    }
                    ui.add_space(4.0);

                    ui.label(RichText::new("Secret (for HS256 re-sign)").size(10.0).color(TEXT_MUTED));
                    ui.add(TextEdit::singleline(&mut self.jwt_secret)
                        .desired_width(f32::INFINITY)
                        .hint_text("secret key…")
                        .background_color(INPUT_BG));
                    ui.add_space(4.0);

                    if ui.add_sized(Vec2::new(ui.available_width(), 34.0),
                        egui::Button::new(RichText::new("🔑 Re-sign with HS256").size(11.0).color(TEXT_PRIMARY))
                            .fill(Color32::from_rgb(20, 40, 20))
                            .stroke(Stroke::new(1.0, ACCENT))
                            .corner_radius(6.0)
                    ).clicked() && !self.jwt_secret.is_empty() {
                        let header_json = r#"{"alg":"HS256","typ":"JWT"}"#;
                        let encode_b64  = |s: &str| crate::crypto::b64_encode_url(s.as_bytes());
                        let h = encode_b64(header_json);
                        let p = encode_b64(&self.jwt_edit_payload);
                        let msg = format!("{}.{}", h, p);
                        let sig = crate::crypto::hmac_sha256(self.jwt_secret.as_bytes(), msg.as_bytes());
                        let sig_b64 = crate::crypto::b64_encode_url(&sig);
                        self.jwt_attack_result = format!("Re-signed HS256 token:\n{}.{}", msg, sig_b64);
                        self.audit("AI", "JWT re-signed with user secret".to_string());
                    }
                    ui.add_space(6.0);

                    // Copy result
                    if !self.jwt_attack_result.is_empty() {
                        if ui.add(subtle_button("Copy token")).clicked() {
                            // Copy the token only (first line after "…token:\n")
                            let token_line = self.jwt_attack_result.lines()
                                .find(|l| l.contains('.'))
                                .unwrap_or("")
                                .to_string();
                            ui.ctx().copy_text(token_line);
                            self.push_toast("Copied".to_string(), ACCENT);
                        }
                    }
                });

                // ── CVSS mini-panel ───────────────────────────────────────
                ui.add_space(10.0);
                card_frame().show(ui, |ui| {
                    let score = self.cvss_score();
                    let (lbl, col) = Self::cvss_label(score);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("CVSS 3.1 CALCULATOR").size(11.0).strong().color(TEXT_MUTED));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            Frame::NONE.fill(col.linear_multiply(0.2))
                                .stroke(Stroke::new(1.0, col.linear_multiply(0.6)))
                                .corner_radius(8.0).inner_margin(Margin::symmetric(10, 4))
                                .show(ui, |ui| {
                                ui.label(RichText::new(format!("{:.1}  {}", score, lbl)).size(12.0).strong().color(col));
                            });
                        });
                    });
                    ui.add_space(6.0);
                    let cvss_row = |ui: &mut Ui, label: &str, val: &mut u8, opts: &[&str]| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(label).size(10.0).color(TEXT_MUTED).monospace());
                            ui.add_space(4.0);
                            for (i, opt) in opts.iter().enumerate() {
                                let sel = *val == i as u8;
                                if ui.add(
                                    egui::Button::new(RichText::new(*opt).size(9.0)
                                        .color(if sel { Color32::BLACK } else { TEXT_SECONDARY }))
                                        .fill(if sel { ACCENT } else { Color32::from_rgb(22, 30, 44) })
                                        .corner_radius(4.0)
                                ).clicked() { *val = i as u8; }
                            }
                        });
                        ui.add_space(2.0);
                    };
                    cvss_row(ui, "AV ", &mut self.cvss_av, &["N", "A", "L", "P"]);
                    cvss_row(ui, "AC ", &mut self.cvss_ac, &["L", "H"]);
                    cvss_row(ui, "PR ", &mut self.cvss_pr, &["N", "L", "H"]);
                    cvss_row(ui, "UI ", &mut self.cvss_ui, &["N", "R"]);
                    cvss_row(ui, "S  ", &mut self.cvss_s,  &["U", "C"]);
                    cvss_row(ui, "C  ", &mut self.cvss_c,  &["N", "L", "H"]);
                    cvss_row(ui, "I  ", &mut self.cvss_i,  &["N", "L", "H"]);
                    cvss_row(ui, "A  ", &mut self.cvss_a,  &["N", "L", "H"]);
                });
            });

            ui.add_space(12.0);

            // ── Right panel — decoded view + editor ───────────────────────
            ui.allocate_ui_with_layout(Vec2::new((avail.x - 352.0 - 12.0 - 24.0).max(200.0), avail.y), Layout::top_down(Align::LEFT), |ui| {
                ScrollArea::vertical().id_salt("jwt_right").auto_shrink([false, false]).show(ui, |ui| {
                    if self.jwt_header.is_empty() && self.jwt_payload.is_empty() {
                        ui.add_space(avail.y * 0.35);
                        ui.vertical_centered(|ui| {
                            ui.label(RichText::new("🔑").size(52.0).color(TEXT_DIM));
                            ui.add_space(10.0);
                            ui.label(RichText::new("No token decoded yet").size(15.0).color(TEXT_PRIMARY));
                            ui.label(RichText::new("Paste a JWT and click Decode — or use /jwt <token> in Workspace").size(11.0).color(TEXT_MUTED));
                        });
                        return;
                    }

                    // Header
                    card_frame().show(ui, |ui| {
                        ui.label(RichText::new("HEADER").size(10.0).strong().color(Color32::from_rgb(100, 200, 255)));
                        ui.add_space(4.0);
                        Frame::NONE.fill(TERMINAL_BG).corner_radius(6.0).inner_margin(Margin::same(8)).show(ui, |ui| {
                            for line in self.jwt_header.lines() {
                                let color = if line.contains("alg") { WARN }
                                    else if line.contains("none") { DANGER }
                                    else { TEXT_SECONDARY };
                                ui.label(RichText::new(line).size(11.0).monospace().color(color));
                            }
                        });
                        if self.jwt_header.contains("\"none\"") || self.jwt_header.contains("\"None\"") {
                            ui.add_space(4.0);
                            Frame::NONE.fill(Color32::from_rgba_unmultiplied(255, 60, 60, 30))
                                .stroke(Stroke::new(1.0, DANGER)).corner_radius(6.0).inner_margin(Margin::same(8))
                                .show(ui, |ui| {
                                ui.label(RichText::new("⚠  alg:none — signature is NOT verified! This token may be exploitable.").size(11.0).color(DANGER));
                            });
                        }
                    });
                    ui.add_space(8.0);

                    // Payload — read-only decoded
                    card_frame().show(ui, |ui| {
                        ui.label(RichText::new("PAYLOAD  (decoded)").size(10.0).strong().color(Color32::from_rgb(140, 255, 140)));
                        ui.add_space(4.0);
                        Frame::NONE.fill(TERMINAL_BG).corner_radius(6.0).inner_margin(Margin::same(8)).show(ui, |ui| {
                            for line in self.jwt_payload.lines() {
                                let color = if line.contains("exp") || line.contains("nbf") { WARN }
                                    else if line.contains("admin") || line.contains("true") { Color32::from_rgb(255, 120, 40) }
                                    else { TEXT_SECONDARY };
                                ui.label(RichText::new(line).size(11.0).monospace().color(color));
                            }
                        });
                    });
                    ui.add_space(8.0);

                    // Editable payload
                    card_frame().show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("EDIT PAYLOAD").size(10.0).strong().color(WARN));
                            ui.label(RichText::new("(for re-sign attack)").size(9.0).color(TEXT_DIM));
                        });
                        ui.add_space(4.0);
                        Frame::NONE.fill(TERMINAL_BG).corner_radius(6.0).inner_margin(Margin::same(6)).show(ui, |ui| {
                            ui.add(TextEdit::multiline(&mut self.jwt_edit_payload)
                                .desired_width(f32::INFINITY)
                                .desired_rows(6)
                                .font(egui::TextStyle::Monospace)
                                .background_color(Color32::TRANSPARENT));
                        });
                    });
                    ui.add_space(8.0);

                    // Attack result
                    if !self.jwt_attack_result.is_empty() {
                        card_frame().show(ui, |ui| {
                            ui.label(RichText::new("ATTACK RESULT").size(10.0).strong().color(DANGER));
                            ui.add_space(4.0);
                            Frame::NONE.fill(TERMINAL_BG).corner_radius(6.0).inner_margin(Margin::same(8)).show(ui, |ui| {
                                for line in self.jwt_attack_result.lines() {
                                    let color = if line.starts_with("eyJ") { ACCENT } else { TEXT_SECONDARY };
                                    ui.label(RichText::new(line).size(11.0).monospace().color(color));
                                }
                            });
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                if ui.add(subtle_button("Copy token")).clicked() {
                                    let t = self.jwt_attack_result.lines()
                                        .find(|l| l.contains('.')).unwrap_or("").to_string();
                                    ui.ctx().copy_text(t);
                                    self.push_toast("Copied".to_string(), ACCENT);
                                }
                                if ui.add(subtle_button("Send to Repeater")).clicked() {
                                    let t = self.jwt_attack_result.lines()
                                        .find(|l| l.contains('.')).unwrap_or("").to_string();
                                    let auth_header = format!("Authorization: Bearer {}", t);
                                    if !self.rep_headers.contains("Authorization") {
                                        self.rep_headers.push('\n');
                                        self.rep_headers.push_str(&auth_header);
                                    }
                                    self.selected_nav = "Repeater".into();
                                    self.push_toast("Token injected into Repeater".to_string(), ACCENT);
                                }
                            });
                        });
                    }
                    // ── AI interpretation ──────────────────────────────────
                    if !self.jwt_header.is_empty() {
                        card_frame().show(ui, |ui| {
                            let busy = self.page_ai_busy.contains("jwt");
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("AI INTERPRETATION").size(10.0).color(TEXT_DIM));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if busy {
                                        ui.spinner();
                                    } else if ui.add(subtle_button("Analyse token")).clicked() {
                                        let context = format!(
                                            "JWT token analysis:\nHeader: {}\nPayload: {}\nSignature: {}\nAlgorithm used: {}\nAttack result: {}",
                                            self.jwt_header, self.jwt_payload, self.jwt_signature,
                                            if self.jwt_header.contains("\"none\"") { "NONE (critical!)" } else { "signed" },
                                            if self.jwt_attack_result.is_empty() { "no attack run" } else { &self.jwt_attack_result }
                                        );
                                        self.trigger_page_ai("jwt", context);
                                    }
                                });
                            });
                            if let Some(result) = self.page_ai_results.get("jwt").cloned() {
                                ui.add_space(6.0);
                                Frame::NONE.fill(Color32::from_rgb(8, 20, 14)).corner_radius(6.0).inner_margin(Margin::same(8)).show(ui, |ui| {
                                    ScrollArea::vertical().id_salt("jwt_ai_scroll").max_height(180.0).show(ui, |ui| {
                                        ui.label(RichText::new(&result).size(11.0).color(TEXT_PRIMARY));
                                    });
                                });
                            }
                        });
                    }
                });
            });
        });
    }



    // ═══════════════════════════════════════════════════════════════════════
    // MIND BASE  — ephemeral session scratch cache
    // ═══════════════════════════════════════════════════════════════════════
    pub(crate) fn page_mind_base(&mut self, ui: &mut Ui) {
        let mut add = false;
        let mut clear = false;
        let mut remove_idx: Option<usize> = None;
        let entries = self.mind_base.clone();

        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("🧠").size(18.0));
                ui.add_space(4.0);
                section_title(ui, "MIND BASE");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add(egui::Button::new(RichText::new("🗑 Clear All").size(11.0).color(DANGER))
                        .fill(Color32::from_rgb(30, 18, 22)).stroke(Stroke::new(1.0, BORDER))
                        .corner_radius(8.0).min_size(Vec2::new(96.0, 28.0))).clicked() { clear = true; }
                    ui.add_space(8.0);
                    ui.label(RichText::new(format!("{} items", entries.len())).size(10.0).color(TEXT_MUTED));
                });
            });
            ui.label(RichText::new("Ephemeral scratch cache for this session — pin facts that help continue the pentest (endpoints, creds, tokens, observations). Cleared on exit or with Clear All, and fed into the Workspace AI's context.")
                .size(10.0).color(TEXT_MUTED));
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_salt("mind_kind").selected_text(&self.mind_kind).width(130.0).show_ui(ui, |ui| {
                    for k in ["Note", "Endpoint", "Credential", "Token", "Observation"] {
                        ui.selectable_value(&mut self.mind_kind, k.to_string(), k);
                    }
                });
                ui.add_space(6.0);
                let r = ui.add(TextEdit::singleline(&mut self.mind_input)
                    .hint_text("Add a fact, endpoint, token, observation…  (Enter)")
                    .desired_width((ui.available_width() - 96.0).max(120.0))
                    .background_color(INPUT_BG));
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.add(accent_button("Add")).clicked() || enter { add = true; }
            });
        });
        ui.add_space(10.0);

        if entries.is_empty() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("🧠").size(40.0).color(TEXT_DIM));
                ui.label(RichText::new("Mind Base is empty").size(14.0).color(TEXT_MUTED));
                ui.label(RichText::new("Pin facts here as you discover them — they feed the AI and clear whenever you want.").size(11.0).color(TEXT_DIM));
            });
        } else {
            ScrollArea::vertical().id_salt("mind_list").auto_shrink([false, false]).show(ui, |ui| {
                for (i, e) in entries.iter().enumerate() {
                    let kc = mind_kind_color(&e.kind);
                    Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(8.0)
                        .inner_margin(Margin::same(10)).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            Frame::NONE.fill(kc.linear_multiply(0.2)).stroke(Stroke::new(1.0, kc)).corner_radius(6.0)
                                .inner_margin(Margin::symmetric(7, 2)).show(ui, |ui| {
                                ui.label(RichText::new(&e.kind).size(9.0).strong().color(kc));
                            });
                            ui.add_space(8.0);
                            ui.label(RichText::new(&e.text).size(12.0).color(TEXT_PRIMARY));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.add(egui::Button::new(RichText::new("✕").size(10.0).color(DANGER))
                                    .fill(Color32::from_rgb(28, 18, 22)).stroke(Stroke::new(1.0, BORDER)).corner_radius(6.0)).clicked() {
                                    remove_idx = Some(i);
                                }
                                ui.add_space(6.0);
                                ui.label(RichText::new(&e.ts).size(9.0).color(TEXT_DIM));
                            });
                        });
                    });
                    ui.add_space(4.0);
                }
            });
        }

        if add {
            let t = self.mind_input.trim().to_string();
            if !t.is_empty() {
                self.mind_base.push(MindEntry { text: t, kind: self.mind_kind.clone(), ts: crate::vulnstore::timestamp() });
                self.mind_input.clear();
            }
        }
        if let Some(i) = remove_idx { if i < self.mind_base.len() { self.mind_base.remove(i); } }
        if clear { self.mind_base.clear(); self.push_toast("Mind Base cleared".to_string(), WARN); }

        if !self.mind_base.is_empty() {
            ui.add_space(6.0);
            let busy = self.page_ai_busy.contains("mind_base");
            card_frame().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("AI INTERPRETATION").size(10.0).color(TEXT_DIM));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if busy {
                            ui.spinner();
                            ui.label(RichText::new("Analysing...").size(10.0).color(TEXT_MUTED));
                        } else if ui.add(subtle_button("Analyse")).clicked() {
                            let ctx_str = self.mind_base.iter().map(|e|
                                format!("[{}] {}", e.kind, e.text)
                            ).collect::<Vec<_>>().join("\n");
                            self.trigger_page_ai("mind_base", ctx_str);
                        }
                    });
                });
                if let Some(result) = self.page_ai_results.get("mind_base").cloned() {
                    ui.add_space(6.0);
                    Frame::NONE.fill(Color32::from_rgb(8, 20, 14)).corner_radius(6.0).inner_margin(Margin::same(8)).show(ui, |ui| {
                        ScrollArea::vertical().id_salt("mind_ai_scroll").max_height(160.0).show(ui, |ui| {
                            ui.label(RichText::new(&result).size(11.0).color(TEXT_PRIMARY));
                        });
                    });
                }
            });
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HYPOTHESES LOUNGE
    // ═══════════════════════════════════════════════════════════════════════
    pub(crate) fn page_hypotheses(&mut self, ui: &mut Ui) {
        let mut add_me = false;
        let mut ask_ai = false;
        let mut delete_idx: Option<usize> = None;
        let mut set_status: Option<(usize, &'static str)> = None;
        let mut dirty = false;
        let busy = self.hypo_busy;
        let count = self.hypotheses.len();

        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("🔬").size(18.0));
                ui.add_space(4.0);
                section_title(ui, "HYPOTHESES LOUNGE");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if busy {
                        ui.label(RichText::new("⏳ thinking…").size(11.0).color(WARN));
                    } else if ui.add(accent_button("💡 Ask AI")).clicked() {
                        ask_ai = true;
                    }
                    ui.add_space(8.0);
                    ui.label(RichText::new(format!("{} hypotheses", count)).size(10.0).color(TEXT_MUTED));
                });
            });
            ui.label(RichText::new("Working theories about the target. You and the agent post them; mark each Valid or Invalid as you test. Persisted across sessions.")
                .size(10.0).color(TEXT_MUTED));
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                let r = ui.add(TextEdit::singleline(&mut self.hypo_input)
                    .hint_text("State a hypothesis to test…  (Enter)")
                    .desired_width((ui.available_width() - 120.0).max(120.0))
                    .background_color(INPUT_BG));
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.add(accent_button("+ Add (Me)")).clicked() || enter { add_me = true; }
            });
        });
        ui.add_space(10.0);

        if self.hypotheses.is_empty() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("🔬").size(40.0).color(TEXT_DIM));
                ui.label(RichText::new("No hypotheses yet").size(14.0).color(TEXT_MUTED));
                ui.label(RichText::new("Add one above, or click “💡 Ask AI” to have the agent propose some.").size(11.0).color(TEXT_DIM));
            });
        } else {
            ScrollArea::vertical().id_salt("hypo_list").auto_shrink([false, false]).show(ui, |ui| {
                for i in 0..self.hypotheses.len() {
                    let (author, status, text, ts) = {
                        let h = &self.hypotheses[i];
                        (h.author.clone(), h.status.clone(), h.text.clone(), h.ts.clone())
                    };
                    let sc = hypo_status_color(&status);
                    let ac = if author == "AI" { INFO } else { ACCENT };
                    card_frame().show(ui, |ui| {
                        ui.horizontal(|ui| {
                            Frame::NONE.fill(ac.linear_multiply(0.18)).stroke(Stroke::new(1.0, ac)).corner_radius(6.0)
                                .inner_margin(Margin::symmetric(7, 2)).show(ui, |ui| {
                                ui.label(RichText::new(if author == "AI" { "🤖 AI" } else { "🧑 Me" }).size(9.0).strong().color(ac));
                            });
                            ui.add_space(6.0);
                            Frame::NONE.fill(sc.linear_multiply(0.18)).stroke(Stroke::new(1.0, sc)).corner_radius(6.0)
                                .inner_margin(Margin::symmetric(7, 2)).show(ui, |ui| {
                                ui.label(RichText::new(&status).size(9.0).strong().color(sc));
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(RichText::new(&ts).size(9.0).color(TEXT_DIM));
                            });
                        });
                        ui.add_space(4.0);
                        ui.label(RichText::new(&text).size(13.0).color(TEXT_PRIMARY));
                        ui.add_space(6.0);
                        ui.label(RichText::new("Evidence / notes").size(9.0).color(TEXT_DIM));
                        if ui.add(TextEdit::multiline(&mut self.hypotheses[i].evidence)
                            .desired_width(f32::INFINITY).desired_rows(2)
                            .hint_text("What did testing show?")
                            .background_color(INPUT_BG)).changed() { dirty = true; }
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.add(subtle_button("◷ Testing")).clicked() { set_status = Some((i, "Testing")); }
                            if ui.add(egui::Button::new(RichText::new("✓ Valid").size(10.0).strong().color(Color32::BLACK))
                                .fill(ACCENT).corner_radius(8.0).min_size(Vec2::new(72.0, 26.0))).clicked() { set_status = Some((i, "Valid")); }
                            if ui.add(egui::Button::new(RichText::new("✗ Invalid").size(10.0).strong().color(Color32::WHITE))
                                .fill(DANGER).corner_radius(8.0).min_size(Vec2::new(76.0, 26.0))).clicked() { set_status = Some((i, "Invalid")); }
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.add(egui::Button::new(RichText::new("✕ Delete").size(10.0).color(DANGER))
                                    .fill(Color32::from_rgb(28, 18, 22)).stroke(Stroke::new(1.0, BORDER)).corner_radius(8.0)).clicked() {
                                    delete_idx = Some(i);
                                }
                            });
                        });
                    });
                    ui.add_space(8.0);
                }
            });
        }

        if add_me {
            let t = self.hypo_input.trim().to_string();
            if !t.is_empty() {
                self.hypotheses.insert(0, crate::config::SavedHypothesis {
                    text: t, author: "Me".into(), status: "Open".into(), evidence: String::new(),
                    ts: crate::vulnstore::timestamp(),
                });
                self.hypo_input.clear();
                dirty = true;
            }
        }
        if let Some((i, st)) = set_status { if i < self.hypotheses.len() { self.hypotheses[i].status = st.to_string(); dirty = true; } }
        if let Some(i) = delete_idx { if i < self.hypotheses.len() { self.hypotheses.remove(i); dirty = true; } }
        if dirty { self.save_config(); }
        if ask_ai && !self.hypo_busy { self.generate_hypotheses(); }

        if !self.hypotheses.is_empty() {
            ui.add_space(6.0);
            let ai_busy = self.page_ai_busy.contains("hypotheses");
            card_frame().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("AI INTERPRETATION").size(10.0).color(TEXT_DIM));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ai_busy {
                            ui.spinner();
                            ui.label(RichText::new("Analysing...").size(10.0).color(TEXT_MUTED));
                        } else if ui.add(subtle_button("Analyse all")).clicked() {
                            let ctx_str = self.hypotheses.iter().map(|h|
                                format!("[{}][{}] {}", h.author, h.status, h.text)
                            ).collect::<Vec<_>>().join("\n");
                            let context = format!("Target: {}\nHypotheses:\n{}", self.target, ctx_str);
                            self.trigger_page_ai("hypotheses", context);
                        }
                    });
                });
                if let Some(result) = self.page_ai_results.get("hypotheses").cloned() {
                    ui.add_space(6.0);
                    Frame::NONE.fill(Color32::from_rgb(8, 20, 14)).corner_radius(6.0).inner_margin(Margin::same(8)).show(ui, |ui| {
                        ScrollArea::vertical().id_salt("hypo_ai_scroll").max_height(160.0).show(ui, |ui| {
                            ui.label(RichText::new(&result).size(11.0).color(TEXT_PRIMARY));
                        });
                    });
                }
            });
        }
    }

    /// Fire an async request asking the AI to propose new testable hypotheses
    /// based on the current target, findings, Mind Base, and existing hypotheses.
    fn generate_hypotheses(&mut self) {
        self.hypo_busy = true;
        let target   = self.target.clone();
        let provider = self.ai_provider;
        let endpoint = self.ai_endpoint.clone();
        let model    = self.ai_model.clone();
        let key      = self.ai_api_key.clone();

        let findings_ctx = if self.findings.is_empty() { "none".to_string() }
            else { self.findings.iter().take(8).map(|f| format!("[{}] {}", f.severity, f.title)).collect::<Vec<_>>().join("; ") };
        let mind_ctx = if self.mind_base.is_empty() { "none".to_string() }
            else { self.mind_base.iter().take(20).map(|m| format!("[{}] {}", m.kind, m.text)).collect::<Vec<_>>().join("; ") };
        let existing = if self.hypotheses.is_empty() { "none".to_string() }
            else { self.hypotheses.iter().take(20).map(|h| h.text.clone()).collect::<Vec<_>>().join("; ") };
        let vuln_types = self.vuln_store.vuln_types().join(", ");
        let kb_ctx = crate::knowledge::build_context(&self.kb_docs);

        let (tx, rx) = channel();
        self.hypo_receiver = Some(rx);

        std::thread::spawn(move || {
            let system = format!(
"You are a senior penetration tester proposing testable security hypotheses about a target.

Target: {target}
Known findings: {findings}
Operator scratch notes (Mind Base): {mind}
Existing hypotheses (do NOT repeat these): {existing}
Reusable PoC categories on record: {vtypes}
{kb}

Output 3 to 6 NEW, specific, testable hypotheses about likely vulnerabilities or weaknesses.
Put each on its own line, prefixed EXACTLY with 'HYPOTHESIS: '. No preamble, no numbering, no extra commentary.
Example:
HYPOTHESIS: The /debug endpoint leaks stack traces revealing framework versions.
HYPOTHESIS: The login form allows user enumeration via differing error messages.",
                target   = if target.is_empty() { "(not set)" } else { target.as_str() },
                findings = findings_ctx,
                mind     = mind_ctx,
                existing = existing,
                vtypes   = if vuln_types.is_empty() { "none".to_string() } else { vuln_types },
                kb       = if kb_ctx.is_empty() { String::new() } else { format!("Knowledge base:\n{}", kb_ctx) },
            );
            let msgs = vec![
                ("system".to_string(), system),
                ("user".to_string(), "Propose hypotheses now.".to_string()),
            ];
            let result = ai::chat_with_history(&provider, &endpoint, &model, &key, msgs);
            let _ = tx.send(result);
        });
    }

    pub(crate) fn poll_hypotheses(&mut self) {
        if let Some(ref rx) = self.hypo_receiver {
            if let Ok(result) = rx.try_recv() {
                self.hypo_busy = false;
                self.hypo_receiver = None;
                match result {
                    Ok(resp) => {
                        // Prefer correctly-prefixed lines; fall back to bullet/numbered
                        // lines only if the model ignored the format entirely.
                        let prefixed: Vec<String> = resp.lines().filter_map(|l| {
                            let l = l.trim();
                            l.strip_prefix("HYPOTHESIS:").or_else(|| l.strip_prefix("Hypothesis:"))
                                .map(|s| s.trim().to_string())
                        }).filter(|s| !s.is_empty()).collect();

                        let candidates: Vec<String> = if !prefixed.is_empty() {
                            prefixed
                        } else {
                            resp.lines().filter_map(|l| {
                                let t = l.trim().trim_start_matches(|c: char|
                                    c == '-' || c == '*' || c == '•' || c.is_ascii_digit() || c == '.' || c == ')' || c == ' '
                                ).trim().to_string();
                                if t.len() > 15 { Some(t) } else { None }
                            }).collect()
                        };

                        let mut added = 0;
                        for t in candidates {
                            if t.is_empty() || self.hypotheses.iter().any(|h| h.text.eq_ignore_ascii_case(&t)) { continue; }
                            self.hypotheses.insert(0, crate::config::SavedHypothesis {
                                text: t, author: "AI".into(), status: "Open".into(), evidence: String::new(),
                                ts: crate::vulnstore::timestamp(),
                            });
                            added += 1;
                        }
                        if added > 0 {
                            self.save_config();
                            self.push_toast(format!("AI proposed {} hypotheses", added), ACCENT);
                        } else {
                            self.push_toast("AI returned no new hypotheses".to_string(), WARN);
                        }
                    }
                    Err(e) => { self.push_toast(format!("AI error: {}", e), DANGER); }
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GLOBAL COMMAND PALETTE  (Ctrl+P)
    // ═══════════════════════════════════════════════════════════════════════
    pub(crate) fn render_palette(&mut self, ctx: &egui::Context) {
        // All searchable destinations
        let nav_items: &[(&str, &str, &str)] = &[
            // (display, nav_target, description)
            ("Overview",      "Overview",      "Dashboard with risk score"),
            ("Workspace",     "Workspace",     "AI co-pilot — talk to the agent"),
            ("Mind Base",     "Mind Base",     "Ephemeral scratch cache (clearable)"),
            ("Hypotheses",    "Hypotheses",    "Track & test pentest hypotheses"),
            ("Proxy",         "Proxy",         "HTTP intercept & history"),
            ("Repeater",      "Repeater",      "Manual HTTP request editor"),
            ("Intruder",      "Intruder",      "Automated payload attack"),
            ("Encoder",       "Encoder",       "Encode/decode/hash"),
            ("JWT",           "JWT",           "JWT decoder, editor, attack"),
            ("Payloads",      "Payloads",      "Editable payload library"),
            ("Vuln Store",    "Vuln Store",    "PoC library + per-system matching"),
            ("OSINT",         "OSINT",         "Subdomain & IP recon"),
            ("Diff Viewer",   "Diff Viewer",   "Side-by-side HTTP diff"),
            ("Timeline",      "Timeline",      "Audit log of all actions"),
            ("Engagements",   "Engagements",   "Projects & findings manager"),
            ("Scan Modules",  "Scan Modules",  "Enable/run scan modules"),
            ("Results",       "Results",       "Scan findings"),
            ("Knowledge Base","Knowledge Base","Personal notes & competences"),
            ("Modules",       "Modules",       "Custom user modules"),
            ("AI Assistant",  "AI Assistant",  "Classic AI chat"),
            ("Settings",      "Settings",      "API keys, model, proxy port"),
            ("About",         "About",         "Version & credits"),
        ];

        let screen = ctx.screen_rect();
        let w = (screen.width() * 0.55).min(640.0).max(400.0);
        let modal_rect = egui::Rect::from_center_size(
            screen.center(),
            Vec2::new(w, screen.height() * 0.7),
        );

        // Dim background
        egui::Area::new(egui::Id::new("palette_backdrop"))
            .fixed_pos(egui::Pos2::ZERO)
            .order(egui::Order::Background)
            .show(ctx, |ui| {
            let full = ctx.screen_rect();
            ui.allocate_rect(full, egui::Sense::click());
            ui.painter().rect_filled(full, 0.0, Color32::from_rgba_unmultiplied(0, 0, 0, 160));
        });

        egui::Window::new("command_palette_window")
            .fixed_rect(modal_rect)
            .title_bar(false)
            .frame(Frame::NONE
                .fill(Color32::from_rgb(14, 20, 30))
                .stroke(Stroke::new(1.5, ACCENT))
                .corner_radius(12.0)
                .inner_margin(Margin::same(16)))
            .show(ctx, |ui| {
            // Header
            ui.horizontal(|ui| {
                ui.label(RichText::new("⌘  COMMAND PALETTE").size(12.0).strong().color(TEXT_MUTED));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add(subtle_button("✕  Close")).clicked() {
                        self.palette_open = false;
                    }
                    ui.label(RichText::new("Esc to close  ·  ↵ to navigate").size(10.0).color(TEXT_DIM));
                });
            });
            ui.add_space(8.0);

            // Search box — auto-focus
            let search_id = egui::Id::new("palette_search");
            let resp = ui.add(
                TextEdit::singleline(&mut self.palette_query)
                    .id(search_id)
                    .hint_text("Search pages, tools, engagements…")
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Heading)
                    .background_color(INPUT_BG)
            );
            if !resp.has_focus() { resp.request_focus(); }
            ui.add_space(8.0);
            ui.separator();
            ui.add_space(4.0);

            // Close on Escape
            if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
                self.palette_open = false;
                self.palette_query.clear();
            }

            let q = self.palette_query.to_lowercase();

            // Nav items
            ScrollArea::vertical().id_salt("palette_scroll").max_height(modal_rect.height() - 120.0).show(ui, |ui| {
                let mut first = true;
                let mut hit_nav: Option<String> = None;

                for (label, nav, desc) in nav_items {
                    if !q.is_empty() && !label.to_lowercase().contains(&q) && !desc.to_lowercase().contains(&q) {
                        continue;
                    }
                    let is_current = self.selected_nav == *nav;
                    let row = Frame::NONE
                        .fill(if is_current { Color32::from_rgb(12, 35, 22) } else { Color32::TRANSPARENT })
                        .corner_radius(8.0)
                        .inner_margin(Margin::symmetric(10, 8))
                        .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(RichText::new(*label).size(13.0).strong()
                                    .color(if is_current { ACCENT } else { TEXT_PRIMARY }));
                                ui.label(RichText::new(*desc).size(10.0).color(TEXT_MUTED));
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if is_current {
                                    ui.label(RichText::new("● current").size(9.0).color(ACCENT));
                                }
                            });
                        });
                    });
                    if row.response.clicked() {
                        hit_nav = Some(nav.to_string());
                    }
                    // Enter key navigates to first match
                    if first && ctx.input(|i| i.key_pressed(egui::Key::Enter)) {
                        hit_nav = Some(nav.to_string());
                    }
                    first = false;
                }

                // Engagement quick-jump
                if q.is_empty() {
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.label(RichText::new("ENGAGEMENTS").size(10.0).color(TEXT_DIM));
                    ui.add_space(4.0);
                } else {
                    ui.add_space(4.0);
                }

                let engs = self.engagements.clone();
                for (i, eng) in engs.iter().enumerate() {
                    if !q.is_empty() && !eng.name.to_lowercase().contains(&q)
                        && !eng.client.to_lowercase().contains(&q) { continue; }
                    let counts = eng.severity_counts();
                    let row = Frame::NONE
                        .fill(Color32::TRANSPARENT).corner_radius(8.0).inner_margin(Margin::symmetric(10, 6))
                        .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(format!("📁  {}", eng.name)).size(12.0).color(TEXT_PRIMARY));
                            ui.label(RichText::new(&eng.client).size(10.0).color(TEXT_MUTED));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if counts[0] > 0 {
                                    ui.label(RichText::new(format!("{}C", counts[0])).size(10.0).color(DANGER));
                                }
                                if counts[1] > 0 {
                                    ui.label(RichText::new(format!("{}H", counts[1])).size(10.0).color(Color32::from_rgb(255,120,40)));
                                }
                            });
                        });
                    });
                    if row.response.clicked() {
                        self.active_engagement_idx = Some(i);
                        self.selected_nav = "Engagements".into();
                        hit_nav = Some("Engagements".into());
                    }
                }

                if let Some(nav) = hit_nav {
                    self.selected_nav = nav;
                    self.palette_open = false;
                    self.palette_query.clear();
                }
            });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Ctrl+P").size(9.0).color(TEXT_DIM).monospace());
                ui.label(RichText::new(" to toggle  ·  ").size(9.0).color(TEXT_DIM));
                ui.label(RichText::new("/help").size(9.0).color(TEXT_DIM).monospace());
                ui.label(RichText::new(" in Workspace for slash commands").size(9.0).color(TEXT_DIM));
            });
        });
    }

    // ═══════════════════════════════════════════════════════════════════════
    // OSINT PAGE
    // ═══════════════════════════════════════════════════════════════════════

    /// Full-width AI investigation card: enter a person / company / handle and
    /// get an AI dossier built from dorked, scraped public search results.
    fn osint_investigation_panel(&mut self, ui: &mut Ui) {
        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("🕵").size(16.0));
                section_title(ui, "AI INVESTIGATION — person / company");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if !self.osint_dossier.is_empty() && ui.add(subtle_button("Clear")).clicked() {
                        self.osint_dossier.clear();
                    }
                });
            });
            ui.label(RichText::new("Enter a name, handle or company (e.g. \"reiza\"). The agent runs targeted Google dorks, scrapes public results, and synthesises who they are, their role and organisation.")
                .size(10.0).color(TEXT_MUTED));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let busy = self.osint_investigating;
                let resp = ui.add(TextEdit::singleline(&mut self.osint_subject)
                    .hint_text("Subject to investigate…")
                    .desired_width((ui.available_width() - 140.0).max(120.0))
                    .background_color(INPUT_BG));
                let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                let can = !busy && !self.osint_subject.trim().is_empty();
                if busy {
                    ui.add(egui::Button::new(RichText::new("⏳ Investigating…").size(12.0).color(TEXT_DIM))
                        .fill(Color32::from_rgb(25, 35, 48)).corner_radius(8.0).min_size(Vec2::new(130.0, 32.0)));
                } else if (ui.add(egui::Button::new(RichText::new("🔎 Investigate").size(12.0).color(if can { Color32::BLACK } else { TEXT_DIM }))
                        .fill(if can { ACCENT } else { Color32::from_rgb(25, 35, 48) }).corner_radius(8.0)
                        .min_size(Vec2::new(130.0, 32.0))).clicked() || enter) && can {
                    self.run_osint_investigation();
                }
            });
            if !self.osint_dossier.is_empty() {
                ui.add_space(8.0);
                Frame::NONE.fill(TERMINAL_BG).stroke(Stroke::new(1.0, Color32::from_rgb(0, 70, 40)))
                    .corner_radius(6.0).inner_margin(Margin::same(10)).show(ui, |ui| {
                    ScrollArea::vertical().id_salt("osint_dossier").max_height(240.0).auto_shrink([false, true]).show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        for line in self.osint_dossier.lines() {
                            let color = if line.starts_with("IDENTITY") || line.starts_with("ROLE") { ACCENT }
                                else if line.starts_with("CONFIDENCE") { WARN }
                                else if line.starts_with("http") { Color32::from_rgb(120, 160, 220) }
                                else { TEXT_SECONDARY };
                            ui.label(RichText::new(line).size(11.5).color(color));
                        }
                    });
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.add(subtle_button("Copy dossier")).clicked() {
                        ui.ctx().copy_text(self.osint_dossier.clone());
                        self.push_toast("Copied".to_string(), ACCENT);
                    }
                    if ui.add(subtle_button("Pin to engagement")).clicked() {
                        let title = format!("OSINT dossier: {}", self.osint_subject);
                        let data = self.osint_dossier.clone();
                        let subj = self.osint_subject.clone();
                        self.save_finding_to_engagement(&title, &data, "info", &data, &subj, "OSINT", vec!["osint".into(), "recon".into()], "", None);
                        self.push_toast("Pinned to active engagement".to_string(), ACCENT);
                    }
                });
            }
        });
    }

    pub(crate) fn page_osint(&mut self, ui: &mut Ui) {
        ScrollArea::vertical().id_salt("osint_page").auto_shrink([false, false]).show(ui, |ui| {
        self.osint_investigation_panel(ui);
        ui.add_space(8.0);
        // Fixed height for the recon columns so, inside the scroll area, both
        // panels are fully reachable instead of clipping at the viewport edge.
        let avail = Vec2::new(ui.available_width(), 620.0);
        ui.horizontal_top(|ui| {
            // ── Left: query panel ─────────────────────────────────────────
            ui.allocate_ui_with_layout(Vec2::new(280.0, avail.y), Layout::top_down(Align::LEFT), |ui| {
                card_frame().show(ui, |ui| {
                    section_title(ui, "OSINT INTEL");
                    ui.add_space(6.0);
                    ui.label(RichText::new("Target domain / IP").size(11.0).color(TEXT_MUTED));
                    ui.add_space(4.0);
                    ui.add(TextEdit::singleline(&mut self.osint_target)
                        .hint_text("e.g. example.com or 93.184.216.34")
                        .desired_width(f32::INFINITY)
                        .background_color(INPUT_BG));
                    ui.add_space(10.0);

                    ui.label(RichText::new("Source").size(11.0).color(TEXT_MUTED));
                    ui.add_space(4.0);
                    for tab in ["Subdomains", "IP Info", "Tech Stack"] {
                        let sel = self.osint_tab == tab;
                        if ui.add(
                            egui::Button::new(RichText::new(tab).size(11.0).color(if sel { Color32::BLACK } else { TEXT_SECONDARY }))
                                .fill(if sel { ACCENT } else { Color32::from_rgb(22, 30, 44) })
                                .stroke(Stroke::new(1.0, if sel { ACCENT } else { BORDER }))
                                .corner_radius(6.0)
                                .min_size(Vec2::new(ui.available_width(), 32.0))
                        ).clicked() {
                            self.osint_tab = tab.into();
                        }
                        ui.add_space(3.0);
                    }

                    ui.add_space(10.0);
                    let busy = self.osint_receiver.is_some();
                    let can_run = !busy && !self.osint_target.trim().is_empty();
                    if ui.add_sized(
                        Vec2::new(ui.available_width(), 38.0),
                        egui::Button::new(RichText::new(if busy { "⏳  Querying…" } else { "🔍  Run Query" })
                            .size(12.0).color(if can_run { Color32::BLACK } else { TEXT_DIM }))
                            .fill(if can_run { ACCENT } else { Color32::from_rgb(25, 35, 48) })
                            .corner_radius(8.0)
                    ).clicked() && can_run {
                        self.run_osint_query();
                    }

                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(8.0);
                    if ui.add(subtle_button("Clear results")).clicked() {
                        self.osint_results.clear();
                    }
                    ui.add_space(4.0);
                    if ui.add(subtle_button("Copy all to clipboard")).clicked() {
                        let all: String = self.osint_results.iter()
                            .map(|(src, data)| format!("=== {} ===\n{}\n", src, data))
                            .collect();
                        ui.ctx().copy_text(all);
                        self.push_toast("Copied OSINT results".to_string(), ACCENT);
                    }

                    ui.add_space(10.0);
                    // API key hint for Shodan
                    if self.osint_tab == "Tech Stack" {
                        Frame::NONE.fill(Color32::from_rgb(18, 18, 10))
                            .stroke(Stroke::new(1.0, Color32::from_rgb(100, 90, 0)))
                            .corner_radius(6.0).inner_margin(Margin::same(8))
                            .show(ui, |ui| {
                            ui.label(RichText::new("ℹ Tech Stack uses WhatWeb (CLI) or Shodan if installed.").size(10.0).color(TEXT_MUTED));
                        });
                    }
                });

                // Stats box
                ui.add_space(10.0);
                card_frame().show(ui, |ui| {
                    section_title(ui, "SESSION STATS");
                    let total = self.osint_results.len();
                    let sub_count = self.osint_results.iter().filter(|(s, _)| s == "Subdomains").count();
                    let ip_count  = self.osint_results.iter().filter(|(s, _)| s == "IP Info").count();
                    let tech_count = self.osint_results.iter().filter(|(s, _)| s == "Tech Stack").count();
                    let stat = |ui: &mut Ui, label: &str, val: usize, color: Color32| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(label).size(11.0).color(TEXT_MUTED));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(RichText::new(format!("{}", val)).size(12.0).strong().color(color));
                            });
                        });
                        ui.add_space(2.0);
                    };
                    stat(ui, "Total queries:", total, ACCENT);
                    stat(ui, "Subdomain runs:", sub_count, Color32::from_rgb(100, 200, 255));
                    stat(ui, "IP info runs:",   ip_count,  Color32::from_rgb(255, 180, 60));
                    stat(ui, "Tech stack runs:", tech_count, Color32::from_rgb(140, 255, 140));
                });
            });

            ui.add_space(12.0);

            // ── Right: results ────────────────────────────────────────────
            ui.allocate_ui_with_layout(
                Vec2::new((avail.x - 292.0 - 12.0 - 24.0).max(200.0), avail.y),
                Layout::top_down(Align::LEFT),
                |ui| {
                ScrollArea::vertical().id_salt("osint_results").auto_shrink([false, false]).show(ui, |ui| {
                    if self.osint_results.is_empty() && self.osint_receiver.is_none() {
                        ui.add_space(avail.y * 0.3);
                        ui.vertical_centered(|ui| {
                            ui.label(RichText::new("🌍").size(56.0).color(TEXT_DIM));
                            ui.add_space(12.0);
                            ui.label(RichText::new("No OSINT results yet").size(15.0).color(TEXT_PRIMARY));
                            ui.add_space(6.0);
                            ui.label(RichText::new("Enter a domain or IP and select a source, then click Run Query").size(11.0).color(TEXT_MUTED));
                        });
                        return;
                    }

                    if self.osint_receiver.is_some() {
                        let t = ui.input(|i| i.time);
                        let dots = match ((t * 2.0) as usize) % 4 { 0 => ".", 1 => "..", 2 => "...", _ => "" };
                        Frame::NONE.fill(Color32::from_rgb(10, 18, 10))
                            .stroke(Stroke::new(1.0, ACCENT))
                            .corner_radius(8.0).inner_margin(Margin::same(12))
                            .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("⏳ Querying {}{}", self.osint_tab, dots)).size(12.0).color(ACCENT));
                            });
                        });
                        ui.add_space(8.0);
                    }

                    // Render each result block in reverse order (newest first)
                    let results = self.osint_results.clone();
                    for (idx, (source, data)) in results.iter().enumerate().rev() {
                        let header_color = match source.as_str() {
                            "Subdomains" => Color32::from_rgb(100, 200, 255),
                            "IP Info"    => Color32::from_rgb(255, 180, 60),
                            _            => Color32::from_rgb(140, 255, 140),
                        };
                        let icon = match source.as_str() {
                            "Subdomains" => "🔗",
                            "IP Info"    => "📍",
                            _            => "🔬",
                        };
                        card_frame().show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("{} {}", icon, source)).size(11.0).strong().color(header_color));
                                ui.label(RichText::new(format!("· {}", self.osint_target)).size(10.0).color(TEXT_DIM));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui.add(subtle_button("Copy")).clicked() {
                                        ui.ctx().copy_text(data.clone());
                                        self.push_toast("Copied".to_string(), ACCENT);
                                    }
                                    if ui.add(subtle_button("Pin")).clicked() {
                                        let title = format!("OSINT: {} – {}", source, self.osint_target);
                                        let tgt = self.osint_target.clone();
                                        let data_c = data.clone();
                                        self.save_finding_to_engagement(
                                            &title, &data_c, "info",
                                            &data_c, &tgt, "OSINT",
                                            vec!["osint".into()], "", None,
                                        );
                                        self.push_toast("Pinned to active engagement".to_string(), ACCENT);
                                    }
                                });
                            });
                            ui.add_space(4.0);
                            Frame::NONE.fill(TERMINAL_BG).corner_radius(6.0).inner_margin(Margin::same(8)).show(ui, |ui| {
                                ScrollArea::vertical()
                                    .id_salt(format!("osint_result_{}", idx))
                                    .max_height(220.0)
                                    .auto_shrink([false, true])
                                    .show(ui, |ui| {
                                    for line in data.lines() {
                                        let color = if line.starts_with("ERROR") || line.starts_with("Error") { DANGER }
                                            else if line.contains("open") || line.contains("443") || line.contains("80") { ACCENT }
                                            else if line.starts_with('[') || line.starts_with('#') { Color32::from_rgb(120, 160, 220) }
                                            else { TEXT_SECONDARY };
                                        ui.label(RichText::new(line).size(11.0).monospace().color(color));
                                    }
                                });
                            });
                        });
                        ui.add_space(8.0);
                    }
                });
            });
        });
        });
    }

    /// Spawn the OSINT query thread based on the selected tab.
    pub(crate) fn run_osint_query(&mut self) {
        if self.osint_receiver.is_some() { return; }
        let target = self.osint_target.trim().to_string();
        let tab    = self.osint_tab.clone();
        let (tx, rx) = channel();
        self.osint_receiver = Some(rx);
        self.audit("OSINT", format!("Querying {} for {}", tab, target));

        std::thread::spawn(move || {
            let result: Result<String, String> = (|| {
                match tab.as_str() {
                    "Subdomains" => {
                        // crt.sh JSON API
                        let url = format!("https://crt.sh/?q={}&output=json", target);
                        let resp = ureq::get(&url)
                            .set("Accept", "application/json")
                            .call()
                            .map_err(|e| format!("crt.sh request failed: {}", e))?;
                        let text = resp.into_string().map_err(|e| e.to_string())?;
                        let json: serde_json::Value = serde_json::from_str(&text)
                            .map_err(|e| format!("JSON parse error: {}", e))?;
                        let mut subs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
                        if let Some(arr) = json.as_array() {
                            for entry in arr {
                                if let Some(name) = entry.get("name_value").and_then(|v| v.as_str()) {
                                    for sub in name.split('\n') {
                                        let s = sub.trim().to_lowercase();
                                        if !s.starts_with('*') && !s.is_empty() {
                                            subs.insert(s);
                                        }
                                    }
                                }
                            }
                        }
                        if subs.is_empty() {
                            return Ok(format!("No subdomains found for {} via crt.sh", target));
                        }
                        let mut out = format!("# crt.sh — {} subdomains for {}\n\n", subs.len(), target);
                        for s in &subs { out.push_str(&format!("{}\n", s)); }
                        Ok(out)
                    }
                    "IP Info" => {
                        // HackerTarget IP neighbours / IP info
                        let url = if target.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                            // IP — use reverse DNS
                            format!("https://api.hackertarget.com/reversedns/?q={}", target)
                        } else {
                            // Hostname — resolve to IP first then get neighbours
                            format!("https://api.hackertarget.com/hostsearch/?q={}", target)
                        };
                        let text = ureq::get(&url)
                            .call()
                            .map_err(|e| format!("HackerTarget request failed: {}", e))?
                            .into_string()
                            .map_err(|e| e.to_string())?;
                        if text.trim().is_empty() || text.starts_with("error") {
                            return Ok(format!("No results from HackerTarget for {}\n\nRaw: {}", target, text));
                        }
                        Ok(format!("# HackerTarget — IP/Host info for {}\n\n{}", target, text))
                    }
                    _ => {
                        // Tech Stack — WhatWeb banner grab via HackerTarget API
                        let url = format!("https://api.hackertarget.com/whatweb/?q=https://{}", target);
                        let text = ureq::get(&url)
                            .call()
                            .map_err(|e| format!("WhatWeb API failed: {}", e))?
                            .into_string()
                            .map_err(|e| e.to_string())?;
                        Ok(format!("# Tech Stack — {}\n\n{}", target, text))
                    }
                }
            })();
            let _ = tx.send(result);
        });
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DIFF VIEWER PAGE
    // ═══════════════════════════════════════════════════════════════════════
    pub(crate) fn page_diff(&mut self, ui: &mut Ui) {
        let avail = ui.available_size();

        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                section_title(ui, "HTTP DIFF VIEWER");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add(subtle_button("Clear Both")).clicked() {
                        self.diff_left.clear();
                        self.diff_right.clear();
                    }
                    if ui.add(subtle_button("Swap")).clicked() {
                        std::mem::swap(&mut self.diff_left, &mut self.diff_right);
                        std::mem::swap(&mut self.diff_left_label, &mut self.diff_right_label);
                    }
                });
            });
            ui.add_space(4.0);
            ui.label(RichText::new("Paste two HTTP responses below. Lines are highlighted: green = only in A, red = only in B, yellow = modified.").size(10.0).color(TEXT_MUTED));
            ui.add_space(8.0);

            // ── Label row ─────────────────────────────────────────────────
            let half = ((avail.x - 28.0 - 12.0 - 24.0) / 2.0).max(80.0);
            ui.horizontal(|ui| {
                ui.add(TextEdit::singleline(&mut self.diff_left_label)
                    .desired_width(half)
                    .hint_text("Label A")
                    .background_color(INPUT_BG));
                ui.add_space(12.0);
                ui.add(TextEdit::singleline(&mut self.diff_right_label)
                    .desired_width(half)
                    .hint_text("Label B")
                    .background_color(INPUT_BG));
            });
            ui.add_space(6.0);

            // ── Edit panes ────────────────────────────────────────────────
            let editor_h = (avail.y * 0.28).max(120.0);
            ui.horizontal_top(|ui| {
                ui.allocate_ui_with_layout(Vec2::new(half, editor_h), Layout::top_down(Align::LEFT), |ui| {
                    Frame::NONE.fill(TERMINAL_BG).stroke(Stroke::new(1.0, Color32::from_rgb(0, 80, 40))).corner_radius(6.0).inner_margin(Margin::same(6)).show(ui, |ui| {
                        ScrollArea::vertical().id_salt("diff_edit_left").max_height(editor_h).show(ui, |ui| {
                            ui.add(TextEdit::multiline(&mut self.diff_left)
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace)
                                .hint_text("Paste Response A here…")
                                .background_color(Color32::TRANSPARENT));
                        });
                    });
                });
                ui.add_space(12.0);
                ui.allocate_ui_with_layout(Vec2::new(half, editor_h), Layout::top_down(Align::LEFT), |ui| {
                    Frame::NONE.fill(TERMINAL_BG).stroke(Stroke::new(1.0, Color32::from_rgb(80, 40, 0))).corner_radius(6.0).inner_margin(Margin::same(6)).show(ui, |ui| {
                        ScrollArea::vertical().id_salt("diff_edit_right").max_height(editor_h).show(ui, |ui| {
                            ui.add(TextEdit::multiline(&mut self.diff_right)
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace)
                                .hint_text("Paste Response B here…")
                                .background_color(Color32::TRANSPARENT));
                        });
                    });
                });
            });
            ui.add_space(8.0);

            // ── Quick-load from Proxy history ─────────────────────────────
            let (lock, _) = &*self.proxy_state;
            let captures: Vec<CapturedRequest> = {
                let s = lock.lock().unwrap();
                s.captures.iter().filter(|r| !r.response_body.is_empty()).cloned().collect()
            };
            if !captures.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Load from proxy:").size(10.0).color(TEXT_MUTED));
                    for cap in captures.iter().take(6) {
                        let label = format!("#{} {} {}", cap.id, cap.method, cap.url.chars().take(30).collect::<String>());
                        if ui.add(
                            egui::Button::new(RichText::new(&label).size(9.0).color(TEXT_SECONDARY))
                                .fill(Color32::from_rgb(20, 28, 40))
                                .stroke(Stroke::new(1.0, BORDER))
                                .corner_radius(4.0)
                        ).clicked() {
                            let body = String::from_utf8_lossy(&cap.response_body).into_owned();
                            let status = cap.status.to_string();
                            let hdrs: String = cap.response_headers.iter()
                                .map(|(k, v)| format!("{}: {}", k, v))
                                .collect::<Vec<_>>().join("\n");
                            let full = format!("HTTP/1.1 {}\n{}\n\n{}", status, hdrs, body);
                            if self.diff_left.is_empty() {
                                self.diff_left = full;
                                self.diff_left_label = format!("#{} {}", cap.id, cap.url.chars().take(40).collect::<String>());
                            } else {
                                self.diff_right = full;
                                self.diff_right_label = format!("#{} {}", cap.id, cap.url.chars().take(40).collect::<String>());
                            }
                        }
                    }
                });
                ui.add_space(8.0);
            }

            ui.separator();
            ui.add_space(8.0);

            // ── Diff output ───────────────────────────────────────────────
            let diff_h = (avail.y * 0.42).max(160.0);
            if self.diff_left.is_empty() && self.diff_right.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(diff_h * 0.25);
                    ui.label(RichText::new("Paste responses above to see the diff").size(13.0).color(TEXT_MUTED));
                });
                return;
            }

            let left_lines:  Vec<&str> = self.diff_left.lines().collect();
            let right_lines: Vec<&str> = self.diff_right.lines().collect();
            let max_lines = left_lines.len().max(right_lines.len());

            // Stat bar
            let added:   usize = right_lines.iter().filter(|l| !left_lines.contains(l)).count();
            let removed: usize = left_lines.iter().filter(|l| !right_lines.contains(l)).count();
            let same:    usize = left_lines.iter().filter(|l| right_lines.contains(l)).count();
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("  {} identical", same)).size(11.0).color(TEXT_MUTED));
                ui.label(RichText::new(format!("  +{} added", added)).size(11.0).color(Color32::from_rgb(80, 220, 100)));
                ui.label(RichText::new(format!("  -{} removed", removed)).size(11.0).color(DANGER));
                ui.label(RichText::new(format!("  {} lines total", max_lines)).size(11.0).color(TEXT_DIM));
            });
            ui.add_space(6.0);

            Frame::NONE.fill(TERMINAL_BG).corner_radius(8.0).inner_margin(Margin::same(8)).show(ui, |ui| {
                ScrollArea::vertical().id_salt("diff_output").max_height(diff_h).auto_shrink([false, false]).show(ui, |ui| {
                    ui.horizontal_top(|ui| {
                        // LEFT column
                        ui.allocate_ui_with_layout(Vec2::new(half - 6.0, 0.0), Layout::top_down(Align::LEFT), |ui| {
                            ui.label(RichText::new(&self.diff_left_label).size(10.0).strong().color(Color32::from_rgb(0, 200, 100)));
                            ui.add_space(4.0);
                            for i in 0..max_lines {
                                let line = left_lines.get(i).copied().unwrap_or("");
                                let in_right = right_lines.contains(&line);
                                let (bg, fg) = if line.is_empty() {
                                    (Color32::TRANSPARENT, TEXT_DIM)
                                } else if !in_right {
                                    (Color32::from_rgba_unmultiplied(180, 30, 30, 40), Color32::from_rgb(255, 130, 130))
                                } else {
                                    (Color32::TRANSPARENT, TEXT_SECONDARY)
                                };
                                Frame::NONE.fill(bg).corner_radius(2.0).show(ui, |ui| {
                                    ui.label(RichText::new(format!("{:>4}  {}", i + 1, line)).size(10.5).monospace().color(fg));
                                });
                            }
                        });

                        ui.add_space(12.0);
                        ui.separator();
                        ui.add_space(4.0);

                        // RIGHT column
                        ui.allocate_ui_with_layout(Vec2::new(half - 6.0, 0.0), Layout::top_down(Align::LEFT), |ui| {
                            ui.label(RichText::new(&self.diff_right_label).size(10.0).strong().color(Color32::from_rgb(255, 140, 60)));
                            ui.add_space(4.0);
                            for i in 0..max_lines {
                                let line = right_lines.get(i).copied().unwrap_or("");
                                let in_left = left_lines.contains(&line);
                                let (bg, fg) = if line.is_empty() {
                                    (Color32::TRANSPARENT, TEXT_DIM)
                                } else if !in_left {
                                    (Color32::from_rgba_unmultiplied(30, 160, 30, 40), Color32::from_rgb(130, 240, 130))
                                } else {
                                    (Color32::TRANSPARENT, TEXT_SECONDARY)
                                };
                                Frame::NONE.fill(bg).corner_radius(2.0).show(ui, |ui| {
                                    ui.label(RichText::new(format!("{:>4}  {}", i + 1, line)).size(10.5).monospace().color(fg));
                                });
                            }
                        });
                    });
                });
            });
        });

        if !self.diff_left.is_empty() && !self.diff_right.is_empty() {
            ui.add_space(6.0);
            let busy = self.page_ai_busy.contains("diff");
            card_frame().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("AI INTERPRETATION").size(10.0).color(TEXT_DIM));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if busy {
                            ui.spinner();
                            ui.label(RichText::new("Analysing...").size(10.0).color(TEXT_MUTED));
                        } else if ui.add(subtle_button("Analyse diff")).clicked() {
                            let context = format!(
                                "Diff viewer — comparing two HTTP responses:\n\nResponse A ({}):\n{}\n\nResponse B ({}):\n{}",
                                self.diff_left_label,
                                self.diff_left.chars().take(1500).collect::<String>(),
                                self.diff_right_label,
                                self.diff_right.chars().take(1500).collect::<String>()
                            );
                            self.trigger_page_ai("diff", context);
                        }
                    });
                });
                if let Some(result) = self.page_ai_results.get("diff").cloned() {
                    ui.add_space(6.0);
                    Frame::NONE.fill(Color32::from_rgb(8, 20, 14)).corner_radius(6.0).inner_margin(Margin::same(8)).show(ui, |ui| {
                        ScrollArea::vertical().id_salt("diff_ai_scroll").max_height(160.0).show(ui, |ui| {
                            ui.label(RichText::new(&result).size(11.0).color(TEXT_PRIMARY));
                        });
                    });
                }
            });
        }
    }
}
