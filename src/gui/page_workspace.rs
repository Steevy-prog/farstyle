// Workspace page — the AI agent console (chat, smart-tool pipeline, Auto-pilot
// controls). Rendering only; the agent loop (send_workspace, poll_workspace,
// drive_autopilot, …) lives in gui/mod.rs and is reached via self.

use super::*;

impl NullForgeApp {
    pub(crate) fn page_workspace(&mut self, ui: &mut Ui) {
        let avail = ui.available_size();
        // Reserve everything below the chat panel so the input bar + hint never
        // fall off-screen: header(28) + subtitle(18) + reasoning gap + chips(40)
        // + gaps(~32) + autopilot row(44) + input(48) + hint(16) + card margins(32) ≈ 300
        let pending_extra = if self.pending_nav.is_some() { 44.0 } else { 0.0 };
        let thinking_extra = if self.ws_busy { 44.0 } else { 0.0 };
        let chat_h = (avail.y - 300.0 - pending_extra - thinking_extra).max(120.0);

        Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(12.0)
            .inner_margin(Margin::same(16)).show(ui, |ui| {
                ui.set_max_width(ui.available_width());
                ui.set_min_height(avail.y - 32.0);

                // ── Header ─────────────────────────────────────────────
                ui.horizontal(|ui| {
                    ui.label(RichText::new("🧪").size(18.0));
                    ui.add_space(4.0);
                    section_title(ui, "WORKSPACE");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.add(subtle_button("Clear")).clicked() {
                            self.ws_messages.clear();
                            self.ws_messages.push(WsMessage::info("Session cleared. Ready."));
                        }
                        ui.add_space(8.0);
                        if !self.ws_queue.is_empty() {
                            if ui.add(
                                egui::Button::new(RichText::new(format!("⏱ {} queued", self.ws_queue.len())).size(10.0).color(Color32::WHITE))
                                    .fill(Color32::from_rgb(80, 60, 0))
                                    .corner_radius(4.0)
                            ).on_hover_text("Click to clear the queue").clicked() {
                                self.ws_queue.clear();
                            }
                            ui.add_space(4.0);
                        }
                        if self.ws_busy {
                            ui.label(RichText::new("⏳").size(10.0).color(WARN));
                            if ui.add(
                                egui::Button::new(RichText::new("■ Stop").size(10.0).color(Color32::WHITE))
                                    .fill(Color32::from_rgb(180, 40, 40))
                                    .corner_radius(4.0)
                            ).on_hover_text("Cancel current request").clicked() {
                                self.ws_receiver = None;
                                self.ws_smart_receiver = None;
                                self.ws_busy = false;
                                self.ws_queue.clear();
                                self.auto_running = false;
                                self.ws_messages.push(WsMessage::info("[Request cancelled — queue cleared]"));
                            }
                            ui.add_space(8.0);
                        }
                    });
                });
                // Status row: quick provider/model switcher | engagement | passive AI toggle
                ui.horizontal(|ui| {
                    let mut picked = self.ai_provider;
                    egui::ComboBox::from_id_salt("ws_provider_quick")
                        .selected_text(RichText::new(picked.label()).size(10.0))
                        .width(120.0)
                        .show_ui(ui, |ui| {
                            for prov in Provider::all() {
                                ui.selectable_value(&mut picked, *prov, prov.label());
                            }
                        });
                    if picked != self.ai_provider {
                        self.switch_ai_provider(picked);
                    }
                    ui.add_space(4.0);
                    ui.add(
                        TextEdit::singleline(&mut self.ai_model)
                            .hint_text("model name")
                            .desired_width(140.0)
                            .font(egui::FontId::proportional(10.0))
                            .background_color(INPUT_BG),
                    ).on_hover_text("Model name sent to the selected provider — e.g. llama3 (Ollama) or meta-llama/llama-3.1-8b-instruct:free (OpenRouter)");
                    if self.ai_provider != Provider::Ollama && self.ai_api_key.trim().is_empty() {
                        ui.add_space(4.0);
                        ui.label(RichText::new("⚠ no API key — set one in Settings").size(9.0).color(WARN));
                    }
                    ui.label(RichText::new("— full tool access").size(10.0).color(TEXT_MUTED));
                    ui.add_space(12.0);
                    // Active engagement badge
                    if let Some(idx) = self.active_engagement_idx {
                        if let Some(eng) = self.engagements.get(idx) {
                            ui.label(RichText::new(format!("📁 {}", eng.name)).size(10.0).color(ACCENT));
                            ui.add_space(8.0);
                        }
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        // Explicit "background action running" sign — separate from
                        // ws_fast_busy so a plain question never lights this up, and
                        // it never goes dark just because you kept chatting.
                        if self.ws_busy {
                            ui.label(RichText::new("🔧 Working in background…").size(10.0).color(ACCENT).italics());
                            ui.add_space(8.0);
                        }
                        // Passive proxy AI toggle
                        let pa_label = if self.proxy_ai_enabled { "🤖 Proxy AI: ON" } else { "🤖 Proxy AI: OFF" };
                        let pa_color = if self.proxy_ai_enabled { ACCENT } else { TEXT_MUTED };
                        if ui.add(egui::Button::new(RichText::new(pa_label).size(10.0).color(pa_color))
                            .fill(Color32::TRANSPARENT).stroke(Stroke::new(1.0, if self.proxy_ai_enabled { ACCENT } else { BORDER }))
                            .corner_radius(4.0).min_size(Vec2::new(110.0, 22.0)))
                            .on_hover_text("Auto-analyze every new proxy request for security anomalies").clicked() {
                            self.proxy_ai_enabled = !self.proxy_ai_enabled;
                        }
                        ui.add_space(6.0);
                        // Fast Q&A routing toggle — plain questions skip the slow model
                        // and bulky prompt entirely, using ws_fast_model instead.
                        let fq_label = if self.ws_fast_enabled { "⚡ Fast Q&A: ON" } else { "⚡ Fast Q&A: OFF" };
                        let fq_color = if self.ws_fast_enabled { ACCENT } else { TEXT_MUTED };
                        if ui.add(egui::Button::new(RichText::new(fq_label).size(10.0).color(fq_color))
                            .fill(Color32::TRANSPARENT).stroke(Stroke::new(1.0, if self.ws_fast_enabled { ACCENT } else { BORDER }))
                            .corner_radius(4.0).min_size(Vec2::new(110.0, 22.0)))
                            .on_hover_text(format!("Plain questions answered instantly by {} instead of the slower model above", self.ws_fast_model)).clicked() {
                            self.ws_fast_enabled = !self.ws_fast_enabled;
                        }
                        ui.add_space(6.0);
                        // Voice output toggle — explicit ON/OFF/SPEAKING states so it's
                        // never ambiguous whether replies are actually being read aloud.
                        let (vo_label, vo_color) = if !self.tts_enabled {
                            ("🔇 Voice: OFF", TEXT_MUTED)
                        } else if self.tts_speaking {
                            ("🔊 Speaking…", ACCENT)
                        } else {
                            ("🔊 Voice: ON", ACCENT)
                        };
                        if ui.add(egui::Button::new(RichText::new(vo_label).size(10.0).color(vo_color))
                            .fill(Color32::TRANSPARENT).stroke(Stroke::new(1.0, if self.tts_enabled { ACCENT } else { BORDER }))
                            .corner_radius(4.0).min_size(Vec2::new(110.0, 22.0)))
                            .on_hover_text("Read agent replies aloud with the OS speech synthesizer (male voice)").clicked() {
                            self.tts_enabled = !self.tts_enabled;
                            if !self.tts_enabled {
                                if let Some(mut child) = self.tts_child.take() {
                                    let _ = child.kill();
                                }
                                self.tts_speaking = false;
                            }
                        }
                    });
                });
                // Reasoning chain display
                if !self.last_ai_reasoning.is_empty() {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("🧠").size(10.0));
                        ui.label(RichText::new(&self.last_ai_reasoning.clone()).size(10.0)
                            .color(Color32::from_rgb(120, 180, 255)).italics());
                    });
                }
                ui.add_space(6.0);

                // ── Quick-action chips (scrollable horizontal) ─────────────
                ScrollArea::horizontal().id_salt("ws_chips").max_height(36.0).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing = Vec2::new(6.0, 4.0);
                        let chips: &[(&str, &str)] = &[
                            ("Analyse intruder results", "Look at the intruder results and highlight anomalies — requests with different status codes or response sizes from the majority."),
                            ("Check last repeater response", "Analyse the last repeater response. Decode any tokens, check for sensitive data or auth flaws."),
                            ("Summarise proxy captures", "Summarise the proxy captures. Which endpoints look interesting for further testing?"),
                            ("Brute-force login", &format!("Set up the intruder to brute-force the login endpoint at {}/login with a common password list, run the attack and tell me the anomalies.", self.target)),
                            ("Scan target", &format!("Run an nmap scan on {} then tell me what services to focus on.", self.target)),
                            ("Decode token", "Take the last repeater response, extract any JWT or base64 token, decode it and explain the structure."),
                            ("Check KB context", "What knowledge base documents do I have? Summarise what you know from them."),
                            ("Auth flow analysis", "Look at the proxy captures and repeater history. Describe the authentication flow and identify any weaknesses."),
                        ];
                        for (label, prompt) in chips {
                            if ui.add(
                                egui::Button::new(RichText::new(*label).size(10.0).color(TEXT_SECONDARY))
                                    .fill(Color32::from_rgb(22, 30, 44))
                                    .stroke(Stroke::new(1.0, BORDER))
                                    .corner_radius(10.0)
                            ).clicked() {
                                self.ws_input = prompt.to_string();
                            }
                        }
                    });
                });
                ui.add_space(6.0);

                // ── Chat area ───────────────────────────────────────────
                // Extra right padding so message text clears the floating scrollbar
                // instead of running under it / off the edge.
                Frame::NONE.fill(TERMINAL_BG).corner_radius(8.0)
                    .inner_margin(Margin { left: 14, right: 20, top: 12, bottom: 12 }).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ScrollArea::vertical().id_salt("ws_chat").min_scrolled_height(chat_h).max_height(chat_h).auto_shrink([false, false]).stick_to_bottom(true).show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        // Vertical centering when only the welcome Info message is present
                        let only_info = self.ws_messages.len() == 1
                            && matches!(self.ws_messages[0].role, WsRole::Info);
                        if only_info {
                            let pad = (chat_h / 2.0 - 40.0).max(0.0);
                            ui.add_space(pad);
                        }
                        let messages_snap = self.ws_messages.clone();
                        let conf_snap     = self.ws_confidence.clone();
                        // Count agent messages before each index so we can look up confidence
                        let mut agent_counter: usize = 0;
                        for (msg_idx, msg) in messages_snap.iter().enumerate() {
                            let is_agent = matches!(msg.role, WsRole::Agent);
                            let conf: Option<u8> = if is_agent {
                                let c = conf_snap.get(agent_counter).copied().flatten();
                                agent_counter += 1;
                                c
                            } else { None };

                            let bubble_w = (ui.available_width() * 0.78).max(180.0);
                            match msg.role {
                                WsRole::User => {
                                    // Align::Max right-aligns each child; the bubble
                                    // sizes to its content (capped at bubble_w) so it
                                    // hugs the far right edge instead of floating mid-pane.
                                    ui.with_layout(Layout::top_down(Align::Max), |ui| {
                                        ui.label(RichText::new("You").size(10.0).strong().color(ACCENT));
                                        let frame_resp = Frame::NONE.fill(Color32::from_rgb(12, 35, 22))
                                            .stroke(Stroke::new(1.0, Color32::from_rgb(0, 80, 40)))
                                            .corner_radius(8.0).inner_margin(Margin::same(8)).show(ui, |ui| {
                                            ui.set_max_width(bubble_w);
                                            ui.label(RichText::new(&msg.content).size(12.0).color(TEXT_PRIMARY));
                                        });
                                        // Quick-pin context menu
                                        frame_resp.response.context_menu(|ui| {
                                            if ui.button("📌  Pin as Finding").clicked() {
                                                self.pin_staged = Some(msg_idx);
                                                ui.close_menu();
                                            }
                                            if ui.button("📋  Copy text").clicked() {
                                                ui.ctx().copy_text(msg.content.clone());
                                                ui.close_menu();
                                            }
                                        });
                                    });
                                }
                                WsRole::Agent => {
                                    ui.with_layout(Layout::top_down(Align::Min), |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new("🤖 Agent").size(10.0).strong().color(Color32::from_rgb(100, 200, 255)));
                                            // ── Confidence badge ───────────────────────────────
                                            if self.show_confidence {
                                                if let Some(pct) = conf {
                                                    let (badge_color, badge_bg, label) = if pct >= 80 {
                                                        (Color32::from_rgb(60, 220, 100), Color32::from_rgba_unmultiplied(60, 200, 80, 30), format!("✓ {}% conf", pct))
                                                    } else if pct >= 55 {
                                                        (WARN, Color32::from_rgba_unmultiplied(200, 150, 0, 30), format!("~ {}% conf", pct))
                                                    } else {
                                                        (DANGER, Color32::from_rgba_unmultiplied(200, 40, 40, 30), format!("⚠ {}% conf", pct))
                                                    };
                                                    Frame::NONE.fill(badge_bg)
                                                        .stroke(Stroke::new(1.0, badge_color.linear_multiply(0.6)))
                                                        .corner_radius(10.0)
                                                        .inner_margin(Margin::symmetric(6, 2))
                                                        .show(ui, |ui| {
                                                        ui.label(RichText::new(label).size(9.0).color(badge_color));
                                                    });
                                                }
                                            }
                                        });
                                        let msg_resp = Frame::NONE.fill(Color32::from_rgb(14, 22, 36))
                                            .stroke(Stroke::new(1.0, Color32::from_rgb(0, 70, 120)))
                                            .corner_radius(8.0).inner_margin(Margin::same(8)).show(ui, |ui| {
                                            ui.set_max_width(bubble_w);
                                            ui.label(RichText::new(&msg.content).size(12.0).color(TEXT_SECONDARY));
                                        });
                                        // Context menu for agent messages
                                        msg_resp.response.context_menu(|ui| {
                                            if ui.button("📌  Pin as Finding").clicked() {
                                                self.pin_staged = Some(msg_idx);
                                                ui.close_menu();
                                            }
                                            if ui.button("📋  Copy text").clicked() {
                                                ui.ctx().copy_text(msg.content.clone());
                                                ui.close_menu();
                                            }
                                            if ui.button("🔍  Lookup CVE from this").clicked() {
                                                let hint = msg.content.lines()
                                                    .find(|l| l.chars().any(|c| c.is_ascii_digit()))
                                                    .unwrap_or(&msg.content)
                                                    .chars().take(60).collect::<String>();
                                                self.lookup_cve(&hint);
                                                ui.close_menu();
                                            }
                                        });
                                    });
                                }
                                WsRole::Tool => {
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new(format!("⚙ {}", msg.content)).size(10.0).strong().color(Color32::from_rgb(255,140,0)));
                                    });
                                    if let Some(artifact) = &msg.artifact {
                                        let frame_resp = Frame::NONE.fill(Color32::from_rgb(10, 16, 24))
                                            .stroke(Stroke::new(1.0, Color32::from_rgb(80, 50, 10)))
                                            .corner_radius(6.0).inner_margin(Margin::same(8)).show(ui, |ui| {
                                            ScrollArea::vertical()
                                                .id_salt(format!("tool_artifact_{}", msg.id))
                                                .max_height(180.0)
                                                .auto_shrink([false, true])
                                                .show(ui, |ui| {
                                                ui.set_min_width(ui.available_width());
                                                ui.label(RichText::new(artifact).size(11.0).monospace().color(Color32::from_rgb(220, 180, 100)));
                                            });
                                        });
                                        frame_resp.response.context_menu(|ui| {
                                            if ui.button("📌  Pin output as Finding").clicked() {
                                                self.pin_staged = Some(msg_idx);
                                                ui.close_menu();
                                            }
                                            if ui.button("📋  Copy output").clicked() {
                                                ui.ctx().copy_text(artifact.clone());
                                                ui.close_menu();
                                            }
                                            if ui.button("⬛  Load into Diff A").clicked() {
                                                self.diff_left = artifact.clone();
                                                self.diff_left_label = msg.content.clone();
                                                ui.close_menu();
                                            }
                                            if ui.button("⬛  Load into Diff B").clicked() {
                                                self.diff_right = artifact.clone();
                                                self.diff_right_label = msg.content.clone();
                                                ui.close_menu();
                                            }
                                        });
                                    }
                                }
                                WsRole::Info => {
                                    ui.vertical_centered(|ui| {
                                        ui.label(RichText::new(format!("ℹ {}", msg.content)).size(11.0).color(TEXT_MUTED));
                                    });
                                }
                            }
                            ui.add_space(8.0);
                        }

                        // ── Handle quick-pin: open dialog ──────────────────
                        if let Some(pin_idx) = self.pin_staged {
                            if let Some(pinned_msg) = messages_snap.get(pin_idx) {
                                let content = pinned_msg.content.clone();
                                let tgt = self.target.clone();
                                self.save_finding_to_engagement(
                                    "Pinned from Workspace",
                                    &content, "info",
                                    &content, &tgt, "Workspace",
                                    vec!["pinned".into()], "", None,
                                );
                                self.push_toast("📌 Pinned to active engagement".to_string(), ACCENT);
                            }
                            self.pin_staged = None;
                        }
                    });
                });

                // ── Thinking indicator ──────────────────────────────────────
                if self.ws_busy {
                    let t = ui.input(|i| i.time);
                    let dots = match ((t * 2.0) as usize) % 4 { 0 => ".", 1 => "..", 2 => "...", _ => "" };
                    ui.add_space(4.0);
                    Frame::NONE.fill(Color32::from_rgb(14, 22, 36))
                        .stroke(Stroke::new(1.0, Color32::from_rgb(0, 100, 180)))
                        .corner_radius(6.0).inner_margin(Margin::same(8))
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("⏳ Working{}", dots)).size(11.0).color(Color32::from_rgb(100, 180, 255)));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui.add(
                                        egui::Button::new(RichText::new("■ Stop").size(10.0).color(Color32::WHITE))
                                            .fill(Color32::from_rgb(160, 30, 30)).corner_radius(4.0)
                                    ).clicked() {
                                        self.ws_receiver = None; self.ws_smart_receiver = None;
                                        self.ws_busy = false; self.ws_queue.clear();
                                        self.ws_messages.push(WsMessage::info("[Cancelled]"));
                                    }
                                });
                            });
                        });
                    ui.add_space(4.0);
                }

                // ── Pending navigation suggestion ───────────────────
                if let Some(nav) = self.pending_nav.clone() {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("📍 Suggested: go to '{}'", nav)).size(11.0).color(WARN));
                        if ui.add(accent_button("Go →")).clicked() {
                            self.selected_nav = nav;
                            self.pending_nav = None;
                        }
                        if ui.add(subtle_button("Dismiss")).clicked() {
                            self.pending_nav = None;
                        }
                    });
                    ui.add_space(4.0);
                }

                // ── Passive Proxy AI anomalies panel ────────────────────
                if !self.proxy_ai_findings.is_empty() {
                    ui.add_space(6.0);
                    egui::CollapsingHeader::new(
                        RichText::new(format!("🔍 Proxy AI Anomalies  ({})", self.proxy_ai_findings.len()))
                            .size(11.0).color(WARN))
                        .id_salt("proxy_anomalies")
                        .default_open(false)
                        .show(ui, |ui| {
                            Frame::NONE.fill(Color32::from_rgb(30, 22, 10))
                                .stroke(Stroke::new(1.0, Color32::from_rgb(180, 120, 0)))
                                .corner_radius(6.0).inner_margin(Margin::same(10))
                                .show(ui, |ui| {
                                    ScrollArea::vertical().id_salt("proxy_ai_anomalies_list").max_height(120.0).show(ui, |ui| {
                                        for finding in &self.proxy_ai_findings.clone() {
                                            ui.horizontal_wrapped(|ui| {
                                                ui.label(RichText::new("⚠").size(10.0).color(WARN));
                                                ui.label(RichText::new(finding).size(10.0).color(TEXT_SECONDARY));
                                            });
                                            ui.add_space(2.0);
                                        }
                                    });
                                    ui.add_space(4.0);
                                    if ui.add(subtle_button("Clear")).clicked() {
                                        self.proxy_ai_findings.clear();
                                    }
                                });
                        });
                    ui.add_space(4.0);
                }

                // ── CVE Intelligence panel ───────────────────────────────
                if !self.cve_result.is_empty() || self.cve_receiver.is_some() {
                    ui.add_space(4.0);
                    let header_text = if self.cve_receiver.is_some() {
                        RichText::new("🛡 CVE Intelligence  [querying…]").size(11.0).color(Color32::from_rgb(255, 180, 60))
                    } else {
                        RichText::new("🛡 CVE Intelligence").size(11.0).color(Color32::from_rgb(255, 180, 60))
                    };
                    egui::CollapsingHeader::new(header_text)
                        .id_salt("cve_panel")
                        .default_open(true)
                        .show(ui, |ui| {
                            Frame::NONE.fill(Color32::from_rgb(24, 18, 10))
                                .stroke(Stroke::new(1.0, Color32::from_rgb(180, 100, 0)))
                                .corner_radius(6.0).inner_margin(Margin::same(10))
                                .show(ui, |ui| {
                                    if self.cve_receiver.is_some() {
                                        let t = ui.input(|i| i.time);
                                        let dots = match ((t * 2.0) as usize) % 4 { 0=>".", 1=>"..", 2=>"...", _=>"" };
                                        ui.label(RichText::new(format!("Querying OSV.dev + AI{}", dots))
                                            .size(10.0).color(TEXT_MUTED).italics());
                                    } else {
                                        ScrollArea::vertical().id_salt("cve_scroll").max_height(150.0).show(ui, |ui| {
                                            // Render lines with severity colour coding
                                            for line in self.cve_result.lines() {
                                                let color = if line.contains("CRITICAL") || line.contains("Critical") { DANGER }
                                                    else if line.contains("High") || line.contains("HIGH") { Color32::from_rgb(255,140,0) }
                                                    else if line.contains("Medium") || line.contains("MEDIUM") { WARN }
                                                    else if line.contains("OSV.dev") || line.contains("AI Enrichment") { Color32::from_rgb(120,160,220) }
                                                    else { TEXT_SECONDARY };
                                                ui.label(RichText::new(line).size(10.0).color(color));
                                            }
                                        });
                                        ui.add_space(4.0);
                                        ui.horizontal(|ui| {
                                            if ui.add(subtle_button("Clear")).clicked() {
                                                self.cve_result.clear();
                                            }
                                            if ui.add(subtle_button("Save to Finding")).clicked() {
                                                let cve_text = self.cve_result.clone();
                                                let title = "CVE Intelligence Report".to_string();
                                                let target = self.target.clone();
                                                self.save_finding_to_engagement(
                                                    &title, &cve_text, "info",
                                                    "", &target, "CVE Lookup",
                                                    vec!["cve".into(), "intel".into()], "", None,
                                                );
                                            }
                                        });
                                    }
                                });
                        });
                    ui.add_space(4.0);
                }

                // ── Auto-pilot controls ─────────────────────────────────
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if self.auto_running {
                        ui.label(RichText::new(format!("🤖 Auto-pilot · step {}/{}", self.auto_step, self.auto_max_steps))
                            .size(11.0).strong().color(ACCENT));
                        ui.add_space(8.0);
                        if ui.add(egui::Button::new(RichText::new("■ Stop").size(10.0).color(Color32::WHITE))
                            .fill(Color32::from_rgb(180, 40, 40)).corner_radius(8.0).min_size(Vec2::new(64.0, 26.0))).clicked() {
                            self.stop_autopilot("stopped by operator");
                        }
                        ui.add_space(6.0);
                        if ui.add(subtle_button("➤ Guide"))
                            .on_hover_text("Send the text box as a course-correction the agent applies on its next step").clicked() {
                            let g = self.ws_input.trim().to_string();
                            if !g.is_empty() {
                                self.auto_guidance = Some(g);
                                self.ws_input.clear();
                                self.ws_messages.push(WsMessage::info("📍 Guidance queued — the agent will apply it on the next step."));
                            }
                        }
                    } else {
                        if ui.add(egui::Button::new(RichText::new("🤖 Auto-pilot").size(11.0).strong().color(Color32::BLACK))
                            .fill(ACCENT).corner_radius(8.0).min_size(Vec2::new(112.0, 28.0)))
                            .on_hover_text("Run autonomously toward the goal in the text box: observe → note → hypothesize → test → conclude → exploit").clicked() {
                            let goal = self.ws_input.trim().to_string();
                            self.start_autopilot(goal);
                            self.ws_input.clear();
                        }
                        ui.add_space(8.0);
                        ui.label(RichText::new("budget").size(10.0).color(TEXT_MUTED));
                        egui::ComboBox::from_id_salt("auto_max").selected_text(format!("{} steps", self.auto_max_steps)).width(92.0).show_ui(ui, |ui| {
                            for n in [6u32, 10, 12, 20, 30, 50] {
                                ui.selectable_value(&mut self.auto_max_steps, n, format!("{} steps", n));
                            }
                        });
                        ui.label(RichText::new("— type a goal, then Auto-pilot").size(9.0).color(TEXT_DIM));
                    }
                });

                // ── Input bar ───────────────────────────────────────────
                ui.add_space(8.0);
                let send_w = 90.0;
                let mic_w = 40.0;
                let input_w = (ui.available_width() - send_w - mic_w - 18.0 - 14.0).max(80.0);
                ui.horizontal_top(|ui| {
                    let mic_hint = if self.ws_recording {
                        "Stop recording and transcribe"
                    } else if self.ws_transcribing {
                        "Transcribing…"
                    } else {
                        "Record a voice prompt"
                    };
                    let mic_label = if self.ws_recording { "⏹" } else { "🎙" };
                    let mic_fill = if self.ws_recording {
                        Color32::from_rgb(180, 40, 40)
                    } else {
                        Color32::from_rgb(30, 36, 48)
                    };
                    let mic_resp = ui.add_enabled(
                        !self.ws_transcribing,
                        egui::Button::new(RichText::new(mic_label).size(14.0)
                            .color(if self.ws_recording { Color32::WHITE } else { TEXT_SECONDARY }))
                            .fill(mic_fill)
                            .corner_radius(8.0)
                            .min_size(Vec2::new(mic_w, 40.0)),
                    ).on_hover_text(mic_hint);
                    if mic_resp.clicked() {
                        if self.ws_recording {
                            self.stop_voice_recording();
                        } else {
                            self.start_voice_recording();
                        }
                    }
                    ui.add_space(4.0);

                    let resp = ui.add(
                        TextEdit::singleline(&mut self.ws_input)
                            .hint_text(if self.ws_recording {
                                "🔴 Recording — tap ⏹ when you're done speaking…"
                            } else if self.ws_transcribing {
                                "Transcribing your voice prompt…"
                            } else {
                                "Tell me what to do — I have access to all your tools…"
                            })
                            .desired_width(input_w)
                            .min_size(Vec2::new(input_w, 40.0))
                            .background_color(INPUT_BG)
                    );
                    // egui's singleline TextEdit loses focus the instant Enter is
                    // pressed, so checking has_focus() here would always be false
                    // in that same frame — lost_focus() is the correct signal for
                    // "Enter was just pressed in this field", no Cmd modifier needed.
                    let send_shortcut = !self.ws_busy
                        && resp.lost_focus()
                        && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if self.ws_busy {
                        ui.add_sized(
                            Vec2::new(send_w, 40.0),
                            egui::Button::new(RichText::new("Send").size(12.0).color(TEXT_DIM))
                                .fill(Color32::from_rgb(30, 36, 48)),
                        );
                    } else if send_shortcut || ui.add_sized(
                        Vec2::new(send_w, 40.0),
                        egui::Button::new(RichText::new("Send").size(12.0).color(Color32::BLACK))
                            .fill(ACCENT)
                            .corner_radius(8.0)
                    ).clicked() {
                        self.send_workspace();
                        // Enter just defocused the field (egui's singleline
                        // behavior) — pull focus back so the next message can
                        // be typed and sent without an extra click.
                        resp.request_focus();
                    }
                });
                if self.ws_recording {
                    ui.label(RichText::new("🔴 Recording from your microphone — click ⏹ to stop and transcribe").size(9.0).color(DANGER));
                } else if self.ws_transcribing {
                    ui.label(RichText::new("⏳ Transcribing…").size(9.0).color(TEXT_DIM));
                } else {
                    ui.label(RichText::new("Enter to send · 🎙 to dictate").size(9.0).color(TEXT_DIM));
                }
            });
    }
}
