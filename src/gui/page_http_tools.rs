// HTTP tooling pages: intercepting Proxy, Repeater and Intruder.
// Split out of the GUI monolith; see gui/mod.rs.

use super::*;

impl NullForgeApp {
    pub(crate) fn page_proxy(&mut self, ui: &mut Ui) {
        let (running, pending_count) = {
            let (lock, _) = &*self.proxy_state;
            let s = lock.lock().unwrap();
            (s.running, s.pending.len())
        };

        // ── Top control bar ──────────────────────────────────────────────────
        Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
            .inner_margin(Margin::symmetric(16, 10)).show(ui, |ui| {
            ui.horizontal(|ui| {
                // Intercept toggle
                let int_color = if self.proxy_intercept { Color32::from_rgb(255, 140, 0) } else { Color32::from_rgb(60, 80, 60) };
                let int_label = if self.proxy_intercept { "  Intercept ON  " } else { "  Intercept OFF  " };
                if ui.add(egui::Button::new(RichText::new(int_label).size(12.0).strong()
                    .color(if self.proxy_intercept { Color32::WHITE } else { TEXT_MUTED }))
                    .fill(int_color).corner_radius(6.0).min_size(Vec2::new(130.0, 30.0))).clicked() {
                    self.proxy_intercept = !self.proxy_intercept;
                    // Sync to actual proxy state
                    let (lock, cvar) = &*self.proxy_state;
                    lock.lock().unwrap().intercept = self.proxy_intercept;
                    if !self.proxy_intercept {
                        // Turning intercept off — release all held requests
                        proxy::forward_all_pending(&self.proxy_state);
                    }
                    cvar.notify_all();
                    self.proxy_tab = if self.proxy_intercept { "Intercept".into() } else { "HTTP History".into() };
                    self.push_toast(if self.proxy_intercept { "Intercept ON — requests will be held" } else { "Intercept OFF — traffic flows freely" }, if self.proxy_intercept { Color32::from_rgb(255,140,0) } else { ACCENT });
                }
                ui.add_space(8.0);
                // Forward / Drop (only meaningful when intercepting)
                if ui.add(egui::Button::new(RichText::new("  Forward  ").size(12.0).color(Color32::BLACK))
                    .fill(ACCENT).corner_radius(6.0).min_size(Vec2::new(90.0, 30.0))).clicked() {
                    // Forward selected pending OR selected history entry
                    let id_to_fwd = self.proxy_intercept_selected
                        .or(if !self.proxy_intercept { self.proxy_selected } else { None });
                    if let Some(id) = id_to_fwd {
                        proxy::forward_pending(&self.proxy_state, id);
                        self.push_toast(format!("Forwarded #{}", id), ACCENT);
                        self.proxy_intercept_selected = None;
                    }
                }
                ui.add_space(4.0);
                if ui.add(egui::Button::new(RichText::new("  Drop  ").size(12.0).color(TEXT_PRIMARY))
                    .fill(INPUT_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(6.0).min_size(Vec2::new(70.0, 30.0))).clicked() {
                    let id_to_drop = self.proxy_intercept_selected
                        .or(if !self.proxy_intercept { self.proxy_selected } else { None });
                    if let Some(id) = id_to_drop {
                        proxy::drop_pending(&self.proxy_state, id);
                        self.push_toast(format!("Dropped #{}", id), WARN);
                        self.proxy_intercept_selected = None;
                    }
                }
                if pending_count > 0 {
                    ui.add_space(8.0);
                    ui.label(RichText::new(format!("⏸ {} held", pending_count)).size(11.0).strong().color(Color32::from_rgb(255,140,0)));
                }

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    // Start/Stop proxy
                    if running {
                        if ui.add(egui::Button::new(RichText::new("■  Stop Proxy").size(11.0).color(TEXT_PRIMARY))
                            .fill(Color32::from_rgb(120, 40, 40)).corner_radius(6.0).min_size(Vec2::new(100.0, 28.0))).clicked() {
                            proxy::stop(&self.proxy_state);
                        }
                        ui.label(RichText::new(format!("●  127.0.0.1:{}", self.proxy_port)).size(11.0).color(ACCENT));
                    } else {
                        if ui.add(egui::Button::new(RichText::new("▶  Start Proxy").size(11.0).color(Color32::BLACK))
                            .fill(ACCENT).corner_radius(6.0).min_size(Vec2::new(100.0, 28.0))).clicked() {
                            proxy::start(self.proxy_state.clone(), self.proxy_port);
                        }
                        ui.label(RichText::new("●  Stopped").size(11.0).color(TEXT_DIM));
                    }
                });
            });
        });

        ui.add_space(6.0);

        // ── Sub-tabs: Intercept | HTTP History ───────────────────────────────
        Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
            .inner_margin(Margin::symmetric(16, 8)).show(ui, |ui| {
            ui.horizontal(|ui| {
                for tab in ["Intercept", "HTTP History"] {
                    let sel = self.proxy_tab == tab;
                    if ui.add(egui::Button::new(RichText::new(tab).size(12.0)
                        .color(if sel { ACCENT } else { TEXT_SECONDARY }))
                        .fill(Color32::TRANSPARENT)
                        .stroke(if sel { Stroke::new(0.0, Color32::TRANSPARENT) } else { Stroke::NONE })
                        .corner_radius(0.0)
                        .min_size(Vec2::new(0.0, 24.0))).clicked() {
                        self.proxy_tab = tab.into();
                    }
                    if sel {
                        ui.painter().line_segment(
                            [ui.cursor().min - Vec2::new(0.0, 2.0),
                             ui.cursor().min + Vec2::new(60.0, -2.0)],
                            Stroke::new(2.0, ACCENT),
                        );
                    }
                    ui.add_space(16.0);
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add(subtle_button("Clear")).clicked() {
                        { let (lock, _) = &*self.proxy_state; lock.lock().unwrap().captures.clear(); }
                        self.proxy_selected = None;
                    }
                    ui.add(TextEdit::singleline(&mut self.proxy_filter)
                        .desired_width(180.0).background_color(INPUT_BG).hint_text("Filter URL..."));
                });
            });
        });

        ui.add_space(6.0);

        let avail = ui.available_size();
        let inspector_w = if self.proxy_show_inspector { 260.0_f32 } else { 0.0 };
        let main_w = (avail.x - inspector_w - if self.proxy_show_inspector { 8.0 } else { 0.0 } - 24.0).max(160.0);

        ui.horizontal_top(|ui| {
            // ── Main content area ──────────────────────────────────────────
            ui.allocate_ui_with_layout(Vec2::new(main_w, avail.y), Layout::top_down(Align::LEFT), |ui| {
                let tab = self.proxy_tab.clone();
                if tab == "HTTP History" {
                    // ── History table ─────────────────────────────────────
                    let captures = { let (lock, _) = &*self.proxy_state; lock.lock().unwrap().captures.clone() };
                    Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
                        .inner_margin(Margin::same(0)).show(ui, |ui| {
                        // Table header
                        Frame::NONE.fill(Color32::from_rgb(14, 20, 30)).inner_margin(Margin::symmetric(12, 8)).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Time").size(10.0).strong().color(TEXT_DIM));
                                ui.add_space(30.0);
                                ui.label(RichText::new("Type").size(10.0).strong().color(TEXT_DIM));
                                ui.add_space(10.0);
                                ui.label(RichText::new("Method").size(10.0).strong().color(TEXT_DIM));
                                ui.add_space(10.0);
                                ui.label(RichText::new("URL").size(10.0).strong().color(TEXT_DIM));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(RichText::new("Length").size(10.0).strong().color(TEXT_DIM));
                                    ui.add_space(20.0);
                                    ui.label(RichText::new("Status").size(10.0).strong().color(TEXT_DIM));
                                });
                            });
                        });
                        ui.separator();

                        let top_h = (avail.y * 0.38).max(120.0);
                        ScrollArea::vertical().id_salt("proxy_hist").max_height(top_h).show(ui, |ui| {
                            let mut to_select: Option<u64> = None;
                            for cap in captures.iter().rev() {
                                if !self.proxy_filter.is_empty() && !cap.url.to_lowercase().contains(&self.proxy_filter.to_lowercase()) { continue; }
                                let sel = self.proxy_selected == Some(cap.id);
                                let row_fill = if sel { Color32::from_rgb(0, 60, 35) } else { Color32::TRANSPARENT };
                                let row = Frame::NONE.fill(row_fill).inner_margin(Margin::symmetric(12, 5))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new(format!("{:08}", cap.id)).size(10.0).monospace().color(TEXT_DIM));
                                            ui.add_space(8.0);
                                            ui.label(RichText::new("HTTP").size(10.0).color(TEXT_MUTED));
                                            ui.add_space(8.0);
                                            let m_color = match cap.method.as_str() { "GET" => Color32::from_rgb(80, 200, 120), "POST" => Color32::from_rgb(255, 165, 0), "DELETE" => Color32::from_rgb(220, 80, 80), _ => TEXT_SECONDARY };
                                            ui.label(RichText::new(&cap.method).size(11.0).strong().color(m_color));
                                            ui.add_space(8.0);
                                            ui.label(RichText::new(cap.url.chars().take(60).collect::<String>()).size(10.0).color(TEXT_SECONDARY));
                                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                                ui.label(RichText::new(format!("{}", cap.body.len())).size(10.0).color(TEXT_MUTED));
                                                ui.add_space(20.0);
                                                ui.label(RichText::new(format!("{}", cap.status)).size(11.0).strong().color(status_color(cap.status)));
                                            });
                                        });
                                    }).response;
                                if row.interact(egui::Sense::click()).clicked() { to_select = Some(cap.id); }
                            }
                            if let Some(id) = to_select { self.proxy_selected = Some(id); }
                        });
                    });

                    ui.add_space(8.0);

                    // ── Request / Response detail below history ────────────
                    if let Some(id) = self.proxy_selected {
                        let cap = { let (lock, _) = &*self.proxy_state; lock.lock().unwrap().captures.iter().find(|c| c.id == id).cloned() };
                        if let Some(cap) = cap {
                            let detail_h = avail.y - (avail.y * 0.38).max(120.0) - 80.0;
                            let half = ((main_w - 10.0 - 24.0) / 2.0).max(80.0);
                            ui.horizontal_top(|ui| {
                                // Request pane
                                ui.allocate_ui_with_layout(Vec2::new(half, detail_h), Layout::top_down(Align::LEFT), |ui| {
                                    Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
                                        .inner_margin(Margin::same(14)).show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new("Request").size(11.0).strong().color(TEXT_PRIMARY));
                                            ui.add_space(16.0);
                                            for t in ["Pretty", "Raw"] {
                                                let s = self.proxy_req_tab == t;
                                                if ui.add(egui::Button::new(RichText::new(t).size(10.0).color(if s { ACCENT } else { TEXT_MUTED }))
                                                    .fill(Color32::TRANSPARENT).stroke(if s { Stroke::new(1.0, ACCENT) } else { Stroke::NONE }).corner_radius(4.0)).clicked() {
                                                    self.proxy_req_tab = t.into();
                                                }
                                            }
                                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                                if ui.add(subtle_button("Send to Repeater")).clicked() { self.proxy_action("repeater", &cap); }
                                                if ui.add(subtle_button("Send to Intruder")).clicked() { self.proxy_action("intruder", &cap); }
                                            });
                                        });
                                        ui.add_space(8.0);
                                        let req_text = format!("{} {} HTTP/1.1\n{}\n\n{}",
                                            cap.method, cap.url,
                                            cap.headers.iter().map(|(k,v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join("\n"),
                                            String::from_utf8_lossy(&cap.body));
                                        ScrollArea::vertical().id_salt("proxy_req_body").max_height(detail_h - 60.0).show(ui, |ui| {
                                            ui.add(TextEdit::multiline(&mut req_text.clone())
                                                .font(egui::TextStyle::Monospace).desired_width(f32::INFINITY)
                                                .background_color(INPUT_BG).desired_rows(10));
                                        });
                                    });
                                });
                                ui.add_space(10.0);
                                // Response pane
                                ui.allocate_ui_with_layout(Vec2::new(half, detail_h), Layout::top_down(Align::LEFT), |ui| {
                                    Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
                                        .inner_margin(Margin::same(14)).show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new("Response").size(11.0).strong().color(TEXT_PRIMARY));
                                            ui.add_space(8.0);
                                            ui.label(RichText::new(format!("{}", cap.status)).size(11.0).strong().color(status_color(cap.status)));
                                            ui.add_space(16.0);
                                            for t in ["Pretty", "Raw"] {
                                                let s = self.proxy_res_tab == t;
                                                if ui.add(egui::Button::new(RichText::new(t).size(10.0).color(if s { ACCENT } else { TEXT_MUTED }))
                                                    .fill(Color32::TRANSPARENT).stroke(if s { Stroke::new(1.0, ACCENT) } else { Stroke::NONE }).corner_radius(4.0)).clicked() {
                                                    self.proxy_res_tab = t.into();
                                                }
                                            }
                                        });
                                        ui.add_space(8.0);
                                        let res_text = format!("{}\n{}\n\n{}",
                                            cap.status,
                                            cap.response_headers.iter().map(|(k,v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join("\n"),
                                            String::from_utf8_lossy(&cap.response_body).chars().take(4000).collect::<String>());
                                        ScrollArea::vertical().id_salt("proxy_res_body").max_height(detail_h - 60.0).show(ui, |ui| {
                                            ui.add(TextEdit::multiline(&mut res_text.clone())
                                                .font(egui::TextStyle::Monospace).desired_width(f32::INFINITY)
                                                .background_color(INPUT_BG).desired_rows(10));
                                        });
                                    });
                                });
                            });
                        }
                    } else {
                        Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
                            .inner_margin(Margin::same(14)).show(ui, |ui| {
                            ui.vertical_centered(|ui| {
                                ui.add_space(30.0);
                                ui.label(RichText::new("Click a request above to inspect it").size(12.0).color(TEXT_MUTED));
                            });
                        });
                    }
                    // ── AI interpretation of selected capture ──────────────
                    ui.add_space(8.0);
                    let busy = self.page_ai_busy.contains("proxy_history");
                    Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
                        .inner_margin(Margin::symmetric(14, 10)).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("AI INTERPRETATION").size(10.0).color(TEXT_DIM));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if busy {
                                    ui.spinner();
                                    ui.label(RichText::new("Analysing...").size(10.0).color(TEXT_MUTED));
                                } else if ui.add(subtle_button("Analyse selected")).clicked() {
                                    let ctx_str = if let Some(id) = self.proxy_selected {
                                        let cap = { let (lock, _) = &*self.proxy_state; lock.lock().unwrap().captures.iter().find(|c| c.id == id).cloned() };
                                        if let Some(cap) = cap {
                                            format!(
                                                "{} {}\nHost: {}\nHeaders:\n{}\nBody: {}\n\nResponse status: {}\nResponse headers:\n{}\nResponse body (first 1000):\n{}",
                                                cap.method, cap.url, cap.host,
                                                cap.headers.iter().map(|(k,v)| format!("  {}: {}", k, v)).collect::<Vec<_>>().join("\n"),
                                                String::from_utf8_lossy(&cap.body),
                                                cap.status,
                                                cap.response_headers.iter().map(|(k,v)| format!("  {}: {}", k, v)).collect::<Vec<_>>().join("\n"),
                                                String::from_utf8_lossy(&cap.response_body).chars().take(1000).collect::<String>()
                                            )
                                        } else { String::new() }
                                    } else {
                                        let captures = { let (lock, _) = &*self.proxy_state; lock.lock().unwrap().captures.clone() };
                                        captures.iter().rev().take(10).map(|c|
                                            format!("[{}] {} {} → {}", c.id, c.method, c.url, c.status)
                                        ).collect::<Vec<_>>().join("\n")
                                    };
                                    if !ctx_str.is_empty() {
                                        self.trigger_page_ai("proxy_history", ctx_str);
                                    }
                                }
                            });
                        });
                        if let Some(result) = self.page_ai_results.get("proxy_history").cloned() {
                            ui.add_space(6.0);
                            egui::Frame::NONE.fill(Color32::from_rgb(8, 20, 14)).corner_radius(6.0).inner_margin(egui::Margin::same(8)).show(ui, |ui| {
                                ScrollArea::vertical().id_salt("proxy_ai_scroll").max_height(140.0).show(ui, |ui| {
                                    ui.label(RichText::new(&result).size(11.0).color(TEXT_PRIMARY));
                                });
                            });
                        }
                    });
                } else {
                    // ── Intercept tab — live queue of held requests ────────
                    let pending = {
                        let (lock, _) = &*self.proxy_state;
                        lock.lock().unwrap().pending.iter().map(|(r, v)| (r.clone(), v.clone())).collect::<Vec<_>>()
                    };
                    if !self.proxy_intercept {
                        Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
                            .inner_margin(Margin::same(16)).show(ui, |ui| {
                            ui.vertical_centered(|ui| {
                                ui.add_space(50.0);
                                ui.label(RichText::new("Intercept is OFF").size(18.0).color(TEXT_MUTED));
                                ui.add_space(8.0);
                                ui.label(RichText::new("Toggle Intercept ON in the bar above to hold requests.").size(12.0).color(TEXT_DIM));
                                ui.add_space(12.0);
                                ui.label(RichText::new(format!("Configure browser proxy → 127.0.0.1:{}", self.proxy_port)).size(11.0).color(TEXT_DIM));
                            });
                        });
                    } else if pending.is_empty() {
                        Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
                            .inner_margin(Margin::same(16)).show(ui, |ui| {
                            ui.vertical_centered(|ui| {
                                ui.add_space(50.0);
                                ui.label(RichText::new("Waiting for traffic...").size(16.0).color(Color32::from_rgb(255,140,0)));
                                ui.add_space(8.0);
                                ui.label(RichText::new(format!("Proxy listening on 127.0.0.1:{} — route your browser through it", self.proxy_port)).size(11.0).color(TEXT_DIM));
                            });
                        });
                    } else {
                        // Show the first pending request in full, with Forward/Drop/Edit/Send-to buttons
                        let held = &pending[0];
                        let held_cap = held.0.clone();
                        let held_id = held_cap.id;
                        let body_h = (avail.y - 120.0).max(200.0);
                        Frame::NONE.fill(CARD_BG).stroke(Stroke::new(2.0, Color32::from_rgb(255,140,0))).corner_radius(10.0)
                            .inner_margin(Margin::same(14)).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("⏸  HELD: {} {}", held_cap.method, held_cap.url)).size(12.0).strong().color(Color32::from_rgb(255,140,0)));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui.add(egui::Button::new(RichText::new("✕ Drop").size(11.0).color(TEXT_PRIMARY))
                                        .fill(Color32::from_rgb(100,30,30)).corner_radius(4.0).min_size(Vec2::new(70.0, 26.0))).clicked() {
                                        proxy::drop_pending(&self.proxy_state, held_id);
                                        self.push_toast(format!("Dropped #{}", held_id), WARN);
                                    }
                                    ui.add_space(4.0);
                                    if ui.add(egui::Button::new(RichText::new("→ Forward").size(11.0).color(Color32::BLACK))
                                        .fill(ACCENT).corner_radius(4.0).min_size(Vec2::new(80.0, 26.0))).clicked() {
                                        proxy::forward_pending(&self.proxy_state, held_id);
                                        self.push_toast(format!("Forwarded #{}", held_id), ACCENT);
                                    }
                                    ui.add_space(4.0);
                                    if ui.add(egui::Button::new(RichText::new("→ Repeater").size(11.0).color(TEXT_PRIMARY))
                                        .fill(INPUT_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(4.0)).clicked() {
                                        let c = held_cap.clone();
                                        self.import_to_repeater(&c);
                                        self.selected_nav = "Repeater".into();
                                        proxy::forward_pending(&self.proxy_state, held_id);
                                        self.push_toast("Sent to Repeater & forwarded", ACCENT);
                                    }
                                    ui.add_space(4.0);
                                    if ui.add(egui::Button::new(RichText::new("→ Intruder").size(11.0).color(TEXT_PRIMARY))
                                        .fill(INPUT_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(4.0)).clicked() {
                                        let c = held_cap.clone();
                                        self.import_to_intruder(&c);
                                        self.selected_nav = "Intruder".into();
                                        proxy::forward_pending(&self.proxy_state, held_id);
                                        self.push_toast("Sent to Intruder & forwarded", Color32::from_rgb(255,140,0));
                                    }
                                });
                            });
                            ui.add_space(8.0);
                            if pending.len() > 1 {
                                ui.label(RichText::new(format!("+{} more requests waiting", pending.len()-1)).size(10.0).color(TEXT_MUTED));
                                ui.add_space(4.0);
                            }
                            let req_text = format!("{} {} HTTP/1.1\n{}\n\n{}",
                                held_cap.method, held_cap.url,
                                held_cap.headers.iter().map(|(k,v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join("\n"),
                                String::from_utf8_lossy(&held_cap.body));
                            ScrollArea::vertical().id_salt("intercept_req").max_height(body_h).show(ui, |ui| {
                                ui.add(TextEdit::multiline(&mut req_text.clone())
                                    .font(egui::TextStyle::Monospace).desired_width(f32::INFINITY)
                                    .background_color(INPUT_BG).desired_rows(16));
                            });
                        });
                    }
                }
            });

            // ── Inspector panel ────────────────────────────────────────────
            if self.proxy_show_inspector {
                ui.add_space(8.0);
                ui.allocate_ui_with_layout(Vec2::new(inspector_w, avail.y), Layout::top_down(Align::LEFT), |ui| {
                    Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
                        .inner_margin(Margin::same(14)).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Inspector").size(12.0).strong().color(TEXT_PRIMARY));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.add(egui::Button::new(RichText::new("✕").size(10.0).color(TEXT_DIM)).fill(Color32::TRANSPARENT)).clicked() {
                                    self.proxy_show_inspector = false;
                                }
                            });
                        });
                        ui.add_space(10.0);
                        let cap = self.proxy_selected.and_then(|id| {
                            let (lock, _) = &*self.proxy_state;
                            lock.lock().unwrap().captures.iter().find(|c| c.id == id).cloned()
                        });
                        if let Some(cap) = cap {
                            for (label, count) in [
                                ("Request attributes", cap.headers.len()),
                                ("Request query parameters", cap.url.matches('=').count()),
                                ("Request body parameters", if cap.body.is_empty() { 0 } else { cap.body.iter().filter(|&&b| b == b'=').count() }),
                                ("Request cookies", cap.headers.iter().filter(|(k,_)| k.to_lowercase() == "cookie").count()),
                                ("Request headers", cap.headers.len()),
                            ] {
                                Frame::NONE.fill(INPUT_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(6.0)
                                    .inner_margin(Margin::symmetric(10, 8)).show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new(label).size(11.0).color(TEXT_SECONDARY));
                                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                            ui.label(RichText::new(format!("{}", count)).size(11.0).strong().color(ACCENT));
                                            ui.label(RichText::new("∨").size(10.0).color(TEXT_DIM));
                                        });
                                    });
                                });
                                ui.add_space(4.0);
                            }
                        } else {
                            ui.label(RichText::new("Select a request to inspect").size(11.0).color(TEXT_DIM));
                        }
                    });
                });
            }
        });
    }

    pub(crate) fn page_repeater(&mut self, ui: &mut Ui) {
        // ── Named tabs (Burp-style) ───────────────────────────────────────────
        Frame::NONE.fill(Color32::from_rgb(10, 16, 24)).inner_margin(Margin::symmetric(0, 4)).show(ui, |ui| {
            ui.horizontal(|ui| {
                // Ensure at least one tab exists
                if self.rep_tabs.is_empty() {
                    self.rep_tabs.push(("Tab 1".into(), self.rep_method.clone(),
                        self.rep_url.clone(), self.rep_headers.clone(), self.rep_body.clone()));
                    self.rep_tab_idx = 0;
                }
                // Clamp index
                if self.rep_tab_idx >= self.rep_tabs.len() { self.rep_tab_idx = self.rep_tabs.len() - 1; }

                let n = self.rep_tabs.len();
                for i in 0..n {
                    let selected = self.rep_tab_idx == i;
                    let tab_name = self.rep_tabs[i].0.clone();
                    let btn = ui.add(
                        egui::Button::new(RichText::new(&tab_name).size(11.0)
                            .color(if selected { ACCENT } else { TEXT_MUTED }))
                            .fill(if selected { Color32::from_rgb(12, 35, 22) } else { Color32::from_rgb(12, 18, 28) })
                            .stroke(if selected { Stroke::new(1.0, ACCENT) } else { Stroke::new(1.0, BORDER) })
                            .corner_radius(6.0)
                            .min_size(Vec2::new(80.0, 26.0))
                    );
                    if btn.clicked() {
                        // Save current tab state before switching
                        if self.rep_tab_idx < self.rep_tabs.len() {
                            let cur = self.rep_tab_idx;
                            self.rep_tabs[cur].1 = self.rep_method.clone();
                            self.rep_tabs[cur].2 = self.rep_url.clone();
                            self.rep_tabs[cur].3 = self.rep_headers.clone();
                            self.rep_tabs[cur].4 = self.rep_body.clone();
                        }
                        self.rep_tab_idx = i;
                        // Load new tab into active fields
                        self.rep_method  = self.rep_tabs[i].1.clone();
                        self.rep_url     = self.rep_tabs[i].2.clone();
                        self.rep_headers = self.rep_tabs[i].3.clone();
                        self.rep_body    = self.rep_tabs[i].4.clone();
                        self.rep_response.clear();
                        self.rep_status.clear();
                    }
                    // Right-click to rename or close
                    btn.context_menu(|ui| {
                        ui.label(RichText::new(format!("Tab {}", i + 1)).size(10.0).color(TEXT_DIM));
                        ui.separator();
                        if ui.button("Rename…").clicked() {
                            // Toggle name to next generic label
                            let new_name = format!("Tab {}", self.rep_tabs.len() + i + 1);
                            self.rep_tabs[i].0 = new_name;
                            ui.close_menu();
                        }
                        if n > 1 {
                            if ui.button("Close tab").clicked() {
                                self.rep_tabs.remove(i);
                                if self.rep_tab_idx >= self.rep_tabs.len() {
                                    self.rep_tab_idx = self.rep_tabs.len().saturating_sub(1);
                                }
                                // Load newly-active tab
                                if let Some(t) = self.rep_tabs.get(self.rep_tab_idx) {
                                    self.rep_method  = t.1.clone();
                                    self.rep_url     = t.2.clone();
                                    self.rep_headers = t.3.clone();
                                    self.rep_body    = t.4.clone();
                                    self.rep_response.clear();
                                }
                                ui.close_menu();
                            }
                        }
                    });
                }

                // + New tab button
                if ui.add(
                    egui::Button::new(RichText::new(" + ").size(12.0).color(TEXT_MUTED))
                        .fill(Color32::TRANSPARENT)
                        .stroke(Stroke::new(1.0, BORDER))
                        .corner_radius(6.0)
                        .min_size(Vec2::new(30.0, 26.0))
                ).clicked() {
                    // Save current before adding
                    if let Some(cur) = self.rep_tabs.get_mut(self.rep_tab_idx) {
                        cur.1 = self.rep_method.clone();
                        cur.2 = self.rep_url.clone();
                        cur.3 = self.rep_headers.clone();
                        cur.4 = self.rep_body.clone();
                    }
                    let idx = self.rep_tabs.len() + 1;
                    self.rep_tabs.push((
                        format!("Tab {}", idx),
                        "GET".into(),
                        "https://".into(),
                        "User-Agent: FarStyle/0.1\nAccept: application/json".into(),
                        String::new(),
                    ));
                    self.rep_tab_idx = self.rep_tabs.len() - 1;
                    self.rep_method  = "GET".into();
                    self.rep_url     = "https://".into();
                    self.rep_headers = "User-Agent: FarStyle/0.1\nAccept: application/json".into();
                    self.rep_body    .clear();
                    self.rep_response.clear();
                    self.rep_status  .clear();
                }
            });
        });
        ui.add_space(4.0);

        // ── Send bar ─────────────────────────────────────────────────────────
        Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
            .inner_margin(Margin::symmetric(10, 8)).show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui.add(egui::Button::new(RichText::new(" Send ").size(13.0).strong().color(Color32::BLACK))
                    .fill(ACCENT).corner_radius(6.0).min_size(Vec2::new(70.0, 30.0))).clicked() {
                    // Build headers + inject auth if enabled
                    let mut hdrs = parse_header_block(&self.rep_headers);
                    if self.auth_enabled {
                        if !self.auth_bearer.is_empty() {
                            hdrs.push(("Authorization".into(), format!("Bearer {}", self.auth_bearer.trim())));
                        }
                        if !self.auth_cookie.is_empty() {
                            hdrs.push(("Cookie".into(), self.auth_cookie.trim().to_string()));
                        }
                    }
                    match httpx::send(&self.rep_method, &self.rep_url, &hdrs, &self.rep_body) {
                        Ok(r) => { self.rep_response = r.body; self.rep_status = format!("{} {}", r.status, r.status_text); self.rep_time_ms = r.elapsed_ms; }
                        Err(e) => { self.rep_response = e; self.rep_status = "ERROR".into(); }
                    }
                }
                ui.add_space(6.0);
                egui::ComboBox::from_id_salt("rep_method").selected_text(&self.rep_method).width(68.0).show_ui(ui, |ui| {
                    for m in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
                        ui.selectable_value(&mut self.rep_method, m.into(), m);
                    }
                });
                ui.add_space(4.0);
                ui.add(TextEdit::singleline(&mut self.rep_url).desired_width(f32::INFINITY)
                    .background_color(INPUT_BG).hint_text("https://target.com/api/endpoint"));
                ui.add_space(6.0);
                // Diff buttons
                if !self.rep_response.is_empty() {
                    if ui.add(egui::Button::new(RichText::new("Save A").size(10.0).color(Color32::from_rgb(100,200,255)))
                        .fill(Color32::TRANSPARENT).stroke(Stroke::new(1.0, Color32::from_rgb(100,200,255))).corner_radius(4.0)).clicked() {
                        self.rep_diff_a = self.rep_response.clone();
                        self.rep_diff_label_a = format!("{} {}", self.rep_method, self.rep_status);
                        self.push_toast("Saved as Diff A".to_string(), ACCENT);
                    }
                    if ui.add(egui::Button::new(RichText::new("Save B").size(10.0).color(Color32::from_rgb(255,180,100)))
                        .fill(Color32::TRANSPARENT).stroke(Stroke::new(1.0, Color32::from_rgb(255,180,100))).corner_radius(4.0)).clicked() {
                        self.rep_diff_b = self.rep_response.clone();
                        self.rep_diff_label_b = format!("{} {}", self.rep_method, self.rep_status);
                        self.push_toast("Saved as Diff B".to_string(), WARN);
                    }
                }
                if !self.rep_diff_a.is_empty() && !self.rep_diff_b.is_empty() {
                    let diff_label = if self.rep_diff_show { "Hide Diff" } else { "⬛ Diff" };
                    if ui.add(egui::Button::new(RichText::new(diff_label).size(10.0).color(ACCENT))
                        .fill(Color32::TRANSPARENT).stroke(Stroke::new(1.0, ACCENT)).corner_radius(4.0)).clicked() {
                        self.rep_diff_show = !self.rep_diff_show;
                    }
                }
                if self.auth_enabled {
                    ui.label(RichText::new("🔐 Auth").size(9.0).color(ACCENT));
                }
            });
        });
        // ── Diff panel ────────────────────────────────────────────────────────
        if self.rep_diff_show && !self.rep_diff_a.is_empty() && !self.rep_diff_b.is_empty() {
            ui.add_space(4.0);
            Frame::NONE.fill(Color32::from_rgb(10,16,26))
                .stroke(Stroke::new(1.0, BORDER)).corner_radius(8.0)
                .inner_margin(Margin::same(10)).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("⬛ RESPONSE DIFF").size(10.0).strong().color(ACCENT));
                    ui.add_space(12.0);
                    ui.label(RichText::new(format!("A: {}  ({} bytes)", self.rep_diff_label_a, self.rep_diff_a.len())).size(10.0).color(Color32::from_rgb(100,200,255)));
                    ui.add_space(8.0);
                    ui.label(RichText::new(format!("B: {}  ({} bytes)", self.rep_diff_label_b, self.rep_diff_b.len())).size(10.0).color(Color32::from_rgb(255,180,100)));
                });
                ui.add_space(6.0);
                let diff_h = 260.0;
                let half_w = ((ui.available_width() - 24.0) / 2.0 - 6.0).max(80.0);
                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(Vec2::new(half_w, diff_h), Layout::top_down(Align::LEFT), |ui| {
                        ui.label(RichText::new(&self.rep_diff_label_a).size(10.0).strong().color(Color32::from_rgb(100,200,255)));
                        ScrollArea::vertical().id_salt("diff_a").max_height(diff_h - 20.0).show(ui, |ui| {
                            // Highlight lines present in A but not B
                            let b_lines: std::collections::HashSet<&str> = self.rep_diff_b.lines().collect();
                            for line in self.rep_diff_a.lines() {
                                let col = if !b_lines.contains(line) { Color32::from_rgb(255, 100, 100) } else { TEXT_SECONDARY };
                                ui.label(RichText::new(line).size(10.0).monospace().color(col));
                            }
                        });
                    });
                    ui.add_space(4.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.allocate_ui_with_layout(Vec2::new(half_w, diff_h), Layout::top_down(Align::LEFT), |ui| {
                        ui.label(RichText::new(&self.rep_diff_label_b).size(10.0).strong().color(Color32::from_rgb(255,180,100)));
                        ScrollArea::vertical().id_salt("diff_b").max_height(diff_h - 20.0).show(ui, |ui| {
                            let a_lines: std::collections::HashSet<&str> = self.rep_diff_a.lines().collect();
                            for line in self.rep_diff_b.lines() {
                                let col = if !a_lines.contains(line) { Color32::from_rgb(100, 220, 100) } else { TEXT_SECONDARY };
                                ui.label(RichText::new(line).size(10.0).monospace().color(col));
                            }
                        });
                    });
                });
            });
        }

        ui.add_space(6.0);

        let avail = ui.available_size();
        // Account for egui's automatic item_spacing between the columns so the three
        // panes fit avail.x exactly and the Inspector never overflows the right edge.
        let sp = ui.spacing().item_spacing.x;
        let inspector_w = if self.rep_show_inspector { (avail.x * 0.22).min(240.0).max(180.0) } else { 0.0 };
        let gaps = if self.rep_show_inspector { 2.0 * sp } else { sp };
        let pane_area_w = (avail.x - inspector_w - gaps).max(160.0);
        let pane_w = (pane_area_w / 2.0).max(80.0);
        let pane_h = (avail.y - 60.0).max(200.0);

        ui.horizontal_top(|ui| {
            // ── Request pane ─────────────────────────────────────────────
            ui.allocate_ui_with_layout(Vec2::new(pane_w, pane_h), Layout::top_down(Align::LEFT), |ui| {
                Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
                    .inner_margin(Margin::same(14)).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Request").size(12.0).strong().color(TEXT_PRIMARY));
                        ui.add_space(12.0);
                        for t in ["Pretty", "Raw", "Hex"] {
                            let s = self.rep_req_tab == t;
                            if ui.add(egui::Button::new(RichText::new(t).size(10.0).color(if s { ACCENT } else { TEXT_MUTED }))
                                .fill(if s { Color32::from_rgb(0, 40, 20) } else { Color32::TRANSPARENT })
                                .stroke(if s { Stroke::new(1.0, ACCENT) } else { Stroke::NONE })
                                .corner_radius(4.0)).clicked() {
                                self.rep_req_tab = t.into();
                            }
                        }
                    });
                    ui.add_space(8.0);
                    // Full raw request (headers + body) editable
                    let full_req_h = pane_h - 80.0;
                    ScrollArea::vertical().id_salt("rep_req").max_height(full_req_h).show(ui, |ui| {
                        ui.add(TextEdit::multiline(&mut self.rep_headers)
                            .font(egui::TextStyle::Monospace).desired_width(f32::INFINITY)
                            .background_color(INPUT_BG).desired_rows(8)
                            .hint_text("Headers: one per line, e.g.\nUser-Agent: FarStyle\nContent-Type: application/json"));
                        ui.add_space(6.0);
                        ui.add(TextEdit::multiline(&mut self.rep_body)
                            .font(egui::TextStyle::Monospace).desired_width(f32::INFINITY)
                            .background_color(INPUT_BG).desired_rows(8)
                            .hint_text("Body (leave blank for GET)"));
                    });
                    ui.add_space(6.0);
                    // Bottom status
                    ui.label(RichText::new(format!("{} bytes", self.rep_headers.len() + self.rep_body.len()))
                        .size(10.0).color(TEXT_DIM));
                });
            });

            // ── Response pane ────────────────────────────────────────────
            ui.allocate_ui_with_layout(Vec2::new(pane_w, pane_h), Layout::top_down(Align::LEFT), |ui| {
                Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
                    .inner_margin(Margin::same(14)).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Response").size(12.0).strong().color(TEXT_PRIMARY));
                        ui.add_space(12.0);
                        for t in ["Pretty", "Raw", "Hex"] {
                            let s = self.rep_res_tab == t;
                            if ui.add(egui::Button::new(RichText::new(t).size(10.0).color(if s { ACCENT } else { TEXT_MUTED }))
                                .fill(if s { Color32::from_rgb(0, 40, 20) } else { Color32::TRANSPARENT })
                                .stroke(if s { Stroke::new(1.0, ACCENT) } else { Stroke::NONE })
                                .corner_radius(4.0)).clicked() {
                                self.rep_res_tab = t.into();
                            }
                        }
                        if !self.rep_status.is_empty() {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(RichText::new(format!("{} ms", self.rep_time_ms)).size(10.0).color(TEXT_MUTED));
                                ui.add_space(8.0);
                                let sc: u16 = self.rep_status.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
                                ui.label(RichText::new(&self.rep_status).size(11.0).strong().color(status_color(sc)));
                            });
                        }
                    });
                    ui.add_space(8.0);
                    let res_h = pane_h - 80.0;
                    ScrollArea::vertical().id_salt("rep_res").max_height(res_h).show(ui, |ui| {
                        if self.rep_response.is_empty() {
                            ui.vertical_centered(|ui| {
                                ui.add_space(50.0);
                                ui.label(RichText::new("No response yet").size(12.0).color(TEXT_DIM));
                                ui.label(RichText::new("Hit Send to fire the request").size(11.0).color(TEXT_DIM));
                            });
                        } else {
                            ui.add(TextEdit::multiline(&mut self.rep_response)
                                .font(egui::TextStyle::Monospace).desired_width(f32::INFINITY)
                                .background_color(INPUT_BG).desired_rows(18));
                        }
                    });
                    ui.add_space(6.0);
                    ui.label(RichText::new(format!("{} bytes", self.rep_response.len())).size(10.0).color(TEXT_DIM));
                });
            });

            // ── Inspector panel ──────────────────────────────────────────
            if self.rep_show_inspector {
                ui.allocate_ui_with_layout(Vec2::new(inspector_w, pane_h), Layout::top_down(Align::LEFT), |ui| {
                    Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
                        .inner_margin(Margin::same(14)).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Inspector").size(12.0).strong().color(TEXT_PRIMARY));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.add(egui::Button::new(RichText::new("✕").size(10.0).color(TEXT_DIM))
                                    .fill(Color32::TRANSPARENT)).clicked() {
                                    self.rep_show_inspector = false;
                                }
                            });
                        });
                        ui.add_space(10.0);
                        let hdrs = parse_header_block(&self.rep_headers);
                        let q_params = self.rep_url.find('?').map(|i| self.rep_url[i+1..].matches('=').count()).unwrap_or(0);
                        let body_params = if self.rep_body.is_empty() { 0 } else { self.rep_body.matches('=').count() };
                        let cookies = hdrs.iter().filter(|(k,_)| k.to_lowercase() == "cookie").count();
                        for (label, count) in [
                            ("Request attributes", hdrs.len()),
                            ("Query parameters", q_params),
                            ("Body parameters", body_params),
                            ("Cookies", cookies),
                            ("Headers", hdrs.len()),
                        ] {
                            Frame::NONE.fill(INPUT_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(6.0)
                                .inner_margin(Margin::symmetric(10, 8)).show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(label).size(11.0).color(TEXT_SECONDARY));
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        ui.label(RichText::new(format!("{}", count)).size(11.0).strong().color(ACCENT));
                                        ui.label(RichText::new("∨").size(10.0).color(TEXT_DIM));
                                    });
                                });
                            });
                            ui.add_space(4.0);
                        }
                        ui.add_space(16.0);
                        ui.label(RichText::new("Quick Actions").size(11.0).strong().color(TEXT_DIM));
                        ui.add_space(6.0);
                        if ui.add(subtle_button("Send to Intruder")).clicked() {
                            self.intr_url    = self.rep_url.clone();
                            self.intr_method = self.rep_method.clone();
                            self.intr_headers= self.rep_headers.clone();
                            self.intr_body   = self.rep_body.clone();
                            self.selected_nav = "Intruder".into();
                        }
                        ui.add_space(4.0);
                        if ui.add(subtle_button("Send to AI")).clicked() {
                            let summary = format!("Analyse this request:\n{} {}\nHeaders:\n{}\nBody:\n{}", self.rep_method, self.rep_url, self.rep_headers, self.rep_body);
                            self.ai_input = summary;
                            self.selected_nav = "AI Assistant".into();
                        }
                    });
                });
            }
        });

        // ── AI interpretation of current request/response ────────────────────
        if !self.rep_response.is_empty() {
            ui.add_space(4.0);
            let busy = self.page_ai_busy.contains("repeater");
            Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
                .inner_margin(Margin::symmetric(14, 8)).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("AI INTERPRETATION").size(10.0).color(TEXT_DIM));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if busy {
                            ui.spinner();
                            ui.label(RichText::new("Analysing...").size(10.0).color(TEXT_MUTED));
                        } else if ui.add(subtle_button("Analyse")).clicked() {
                            let context = format!(
                                "Request:\n{} {}\nHeaders:\n{}\nBody:\n{}\n\nResponse (status: {}):\n{}",
                                self.rep_method, self.rep_url, self.rep_headers, self.rep_body,
                                self.rep_status,
                                self.rep_response.chars().take(2000).collect::<String>()
                            );
                            self.trigger_page_ai("repeater", context);
                        }
                    });
                });
                if let Some(result) = self.page_ai_results.get("repeater").cloned() {
                    ui.add_space(6.0);
                    Frame::NONE.fill(Color32::from_rgb(8, 20, 14)).corner_radius(6.0).inner_margin(Margin::same(8)).show(ui, |ui| {
                        ScrollArea::vertical().id_salt("rep_ai_scroll").max_height(160.0).show(ui, |ui| {
                            ui.label(RichText::new(&result).size(11.0).color(TEXT_PRIMARY));
                        });
                    });
                }
            });
        }

        // ── Bottom status bar ─────────────────────────────────────────────────
        ui.add_space(4.0);
        Frame::NONE.fill(Color32::from_rgb(10, 16, 24)).inner_margin(Margin::symmetric(14, 4)).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(if self.rep_status.is_empty() { "Ready".to_string() } else { self.rep_status.clone() }).size(10.0).color(TEXT_MUTED));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if !self.rep_show_inspector {
                        if ui.add(subtle_button("Inspector")).clicked() { self.rep_show_inspector = true; }
                    }
                });
            });
        });
    }

    pub(crate) fn page_intruder(&mut self, ui: &mut Ui) {
        // ── Top bar: attack mode + target + start ─────────────────────────────
        Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
            .inner_margin(Margin::symmetric(14, 10)).show(ui, |ui| {
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_salt("intr_attack_mode")
                    .selected_text(self.intr_attack_mode.label()).width(160.0)
                    .show_ui(ui, |ui| {
                        for mode in [AttackMode::Sniper, AttackMode::BatteringRam, AttackMode::Pitchfork, AttackMode::ClusterBomb] {
                            ui.selectable_value(&mut self.intr_attack_mode, mode, mode.label());
                        }
                    });
                ui.add_space(8.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if self.intr_running {
                        if ui.add(egui::Button::new(RichText::new("  ■  Stop  ").size(12.0).color(TEXT_PRIMARY))
                            .fill(Color32::from_rgb(160, 50, 50)).corner_radius(6.0).min_size(Vec2::new(100.0, 30.0))).clicked() {
                            self.intr_running = false;
                        }
                    } else {
                        if ui.add(egui::Button::new(RichText::new("  Start attack  ").size(12.0).strong().color(Color32::BLACK))
                            .fill(Color32::from_rgb(255, 140, 0)).corner_radius(6.0).min_size(Vec2::new(120.0, 30.0))).clicked() {
                            self.intr_results.clear();
                            self.intr_running = true;
                            self.run_intruder_attack();
                            self.intr_running = false;
                        }
                    }
                });
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Target").size(11.0).color(TEXT_MUTED));
                ui.add_space(8.0);
                ui.add(TextEdit::singleline(&mut self.intr_url).desired_width(f32::INFINITY).background_color(INPUT_BG).hint_text("https://target.com/login"));
            });
        });

        ui.add_space(6.0);

        // ── Sub tabs: Positions | Payloads | Results ──────────────────────────
        Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
            .inner_margin(Margin::symmetric(14, 8)).show(ui, |ui| {
            ui.horizontal(|ui| {
                for tab in ["Positions", "Payloads", "Results"] {
                    let sel = self.intr_tab == tab;
                    if ui.add(egui::Button::new(RichText::new(tab).size(12.0)
                        .color(if sel { ACCENT } else { TEXT_SECONDARY }))
                        .fill(Color32::TRANSPARENT).stroke(Stroke::NONE)
                        .min_size(Vec2::new(0.0, 24.0))).clicked() {
                        self.intr_tab = tab.into();
                    }
                    ui.add_space(16.0);
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new(format!("{} results", self.intr_results.len())).size(10.0).color(TEXT_DIM));
                });
            });
        });

        ui.add_space(6.0);

        let avail = ui.available_size();
        let body_h = (avail.y - 50.0).max(200.0);
        let tab = self.intr_tab.clone();

        match tab.as_str() {
            "Positions" => {
                // Left: request editor. Right: payload positions panel
                let left_w = (avail.x * 0.62).max(100.0);
                let right_w = (avail.x - left_w - 8.0 - 24.0).max(80.0);
                ui.horizontal_top(|ui| {
                    // Request editor
                    ui.allocate_ui_with_layout(Vec2::new(left_w, body_h), Layout::top_down(Align::LEFT), |ui| {
                        Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
                            .inner_margin(Margin::same(14)).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                egui::ComboBox::from_id_salt("intr_method").selected_text(&self.intr_method).width(72.0).show_ui(ui, |ui| {
                                    for m in ["GET", "POST", "PUT", "DELETE", "PATCH"] { ui.selectable_value(&mut self.intr_method, m.into(), m); }
                                });
                                ui.add_space(8.0);
                                if ui.add(subtle_button("Add §")).clicked() { self.intr_body.push_str(" §1§"); }
                                if ui.add(subtle_button("Clear §")).clicked() {
                                    self.intr_body = self.intr_body.replace("§1§","").replace("§2§","").replace("§3§","");
                                    self.intr_url  = self.intr_url.replace("§1§","").replace("§2§","").replace("§3§","");
                                }
                                ui.label(RichText::new("Use §1§ §2§ as markers").size(10.0).color(TEXT_DIM));
                            });
                            ui.add_space(8.0);
                            let h = avail.y - 80.0;
                            ScrollArea::vertical().id_salt("intr_req").max_height(h).show(ui, |ui| {
                                ui.add(TextEdit::multiline(&mut self.intr_headers)
                                    .font(egui::TextStyle::Monospace).desired_width(f32::INFINITY)
                                    .background_color(INPUT_BG).desired_rows(6)
                                    .hint_text("Headers (one per line)"));
                                ui.add_space(4.0);
                                ui.add(TextEdit::multiline(&mut self.intr_body)
                                    .font(egui::TextStyle::Monospace).desired_width(f32::INFINITY)
                                    .background_color(INPUT_BG).desired_rows(10)
                                    .hint_text("Body — place §1§ §2§ where payloads go\ne.g.  username=§1§&password=§2§"));
                            });
                            ui.add_space(6.0);
                            let pos_count = self.intr_url.matches('§').count() / 2 + self.intr_body.matches('§').count() / 2;
                            ui.label(RichText::new(format!("{} payload positions detected", pos_count)).size(10.0).color(TEXT_DIM));
                        });
                    });
                    ui.add_space(8.0);
                    // Positions list panel
                    ui.allocate_ui_with_layout(Vec2::new(right_w, body_h), Layout::top_down(Align::LEFT), |ui| {
                        Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
                            .inner_margin(Margin::same(14)).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Payload Positions").size(12.0).strong().color(TEXT_PRIMARY));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui.add(subtle_button("+ Add")).clicked() { self.add_payload_position(); }
                                });
                            });
                            ui.add_space(8.0);
                            ScrollArea::vertical().id_salt("intr_pos_list").show(ui, |ui| {
                                let count = self.intr_positions.len();
                                let mut to_remove: Option<usize> = None;
                                for idx in 0..count {
                                    let sel = self.intr_payload_pos == idx;
                                    let row = Frame::NONE
                                        .fill(if sel { Color32::from_rgb(0, 50, 30) } else { INPUT_BG })
                                        .stroke(Stroke::new(1.0, if sel { ACCENT } else { BORDER }))
                                        .corner_radius(6.0).inner_margin(Margin::symmetric(10, 8))
                                        .show(ui, |ui| {
                                            ui.horizontal(|ui| {
                                                ui.label(RichText::new(format!("§{}§  {}", self.intr_positions[idx].id, self.intr_positions[idx].name))
                                                    .size(11.0).strong().color(if sel { ACCENT } else { TEXT_PRIMARY }));
                                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                                    if ui.add(egui::Button::new(RichText::new("✕").size(10.0).color(TEXT_DIM)).fill(Color32::TRANSPARENT)).clicked() {
                                                        to_remove = Some(idx);
                                                    }
                                                    ui.label(RichText::new(format!("{}", self.intr_positions[idx].payloads.len())).size(10.0).color(TEXT_MUTED));
                                                });
                                            });
                                        }).response;
                                    if row.interact(egui::Sense::click()).clicked() { self.intr_payload_pos = idx; }
                                    ui.add_space(4.0);
                                }
                                if let Some(i) = to_remove { if i < self.intr_positions.len() { self.intr_positions.remove(i); } }
                            });
                        });
                    });
                });
            }

            "Payloads" => {
                // Left: payload list with per-item delete. Right: controls panel.
                let left_w = (avail.x * 0.55).max(100.0);
                let right_w = (avail.x - left_w - 8.0 - 24.0).max(80.0);
                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(Vec2::new(left_w, body_h), Layout::top_down(Align::LEFT), |ui| {
                        Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
                            .inner_margin(Margin::same(14)).show(ui, |ui| {
                            // Header row
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Payload set:").size(11.0).color(TEXT_MUTED));
                                ui.add_space(6.0);
                                egui::ComboBox::from_id_salt("intr_payload_pos_sel")
                                    .selected_text(self.intr_positions.get(self.intr_payload_pos).map(|p| p.name.as_str()).unwrap_or("–"))
                                    .width(140.0).show_ui(ui, |ui| {
                                        for (i, pos) in self.intr_positions.iter().enumerate() {
                                            ui.selectable_value(&mut self.intr_payload_pos, i, &pos.name);
                                        }
                                    });
                                ui.add_space(6.0);
                                ui.label(RichText::new("Type:").size(11.0).color(TEXT_MUTED));
                                ui.add_space(4.0);
                                if let Some(pos) = self.intr_positions.get_mut(self.intr_payload_pos) {
                                    egui::ComboBox::from_id_salt("intr_payload_type").selected_text(pos.payload_type.label()).width(120.0).show_ui(ui, |ui| {
                                        for pt in PayloadType::all() { ui.selectable_value(&mut pos.payload_type, *pt, pt.label()); }
                                    });
                                }
                            });
                            ui.add_space(8.0);
                            // Add-item row
                            ui.horizontal(|ui| {
                                ui.add(TextEdit::singleline(&mut self.intr_new_payload)
                                    .desired_width(f32::INFINITY).background_color(INPUT_BG)
                                    .hint_text("New payload item..."));
                                if ui.add(egui::Button::new(RichText::new("Add").size(11.0).color(Color32::BLACK))
                                    .fill(ACCENT).corner_radius(4.0).min_size(Vec2::new(48.0, 26.0))).clicked() {
                                    let v = self.intr_new_payload.trim().to_string();
                                    if !v.is_empty() {
                                        if let Some(pos) = self.intr_positions.get_mut(self.intr_payload_pos) { pos.payloads.push(v); }
                                        self.intr_new_payload.clear();
                                    }
                                }
                            });
                            ui.add_space(8.0);
                            // Scrollable per-item list with delete button
                            let list_h = (body_h - 130.0).max(80.0);
                            ScrollArea::vertical().id_salt("intr_payload_items").max_height(list_h).show(ui, |ui| {
                                let n = self.intr_positions.get(self.intr_payload_pos).map(|p| p.payloads.len()).unwrap_or(0);
                                let mut to_remove: Option<usize> = None;
                                for i in 0..n {
                                    Frame::NONE.fill(INPUT_BG).corner_radius(4.0)
                                        .inner_margin(Margin::symmetric(8, 4)).show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new(format!("{}", i + 1)).size(10.0).color(TEXT_DIM).monospace());
                                            ui.add_space(6.0);
                                            let text = self.intr_positions.get(self.intr_payload_pos)
                                                .and_then(|p| p.payloads.get(i)).cloned().unwrap_or_default();
                                            ui.label(RichText::new(&text).size(11.0).monospace().color(TEXT_PRIMARY));
                                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                                if ui.add(egui::Button::new(RichText::new("✕").size(10.0).color(DANGER))
                                                    .fill(Color32::TRANSPARENT).min_size(Vec2::new(20.0, 20.0))).clicked() {
                                                    to_remove = Some(i);
                                                }
                                            });
                                        });
                                    });
                                    ui.add_space(2.0);
                                }
                                if let Some(i) = to_remove {
                                    if let Some(pos) = self.intr_positions.get_mut(self.intr_payload_pos) {
                                        if i < pos.payloads.len() { pos.payloads.remove(i); }
                                    }
                                }
                            });
                            ui.add_space(6.0);
                            let cnt = self.intr_positions.get(self.intr_payload_pos).map(|p| p.payloads.len()).unwrap_or(0);
                            ui.label(RichText::new(format!("{} payloads", cnt)).size(10.0).color(TEXT_MUTED));
                        });
                    });
                    ui.add_space(8.0);
                    // Right config panel
                    ui.allocate_ui_with_layout(Vec2::new(right_w, body_h), Layout::top_down(Align::LEFT), |ui| {
                        Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
                            .inner_margin(Margin::same(14)).show(ui, |ui| {
                            ui.label(RichText::new("Actions").size(12.0).strong().color(TEXT_PRIMARY));
                            ui.add_space(10.0);
                            for btn in ["Load from file...", "Clear all", "Deduplicate"] {
                                if ui.add(egui::Button::new(RichText::new(btn).size(11.0).color(TEXT_PRIMARY))
                                    .fill(INPUT_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(4.0)
                                    .min_size(Vec2::new(f32::INFINITY, 28.0))).clicked() {
                                    match btn {
                                        "Clear all" => {
                                            if let Some(pos) = self.intr_positions.get_mut(self.intr_payload_pos) { pos.payloads.clear(); }
                                        }
                                        "Deduplicate" => {
                                            if let Some(pos) = self.intr_positions.get_mut(self.intr_payload_pos) { pos.payloads.dedup(); }
                                        }
                                        "Load from file..." => {
                                            if let Some(path) = rfd::FileDialog::new().add_filter("Text", &["txt"]).pick_file() {
                                                if let Ok(content) = std::fs::read_to_string(path) {
                                                    if let Some(pos) = self.intr_positions.get_mut(self.intr_payload_pos) {
                                                        pos.payloads = content.lines().filter(|l| !l.is_empty()).map(|l| l.to_string()).collect();
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                ui.add_space(4.0);
                            }
                            ui.add_space(16.0);
                            ui.label(RichText::new("Generate").size(11.0).strong().color(TEXT_DIM));
                            ui.add_space(4.0);
                            if ui.add(egui::Button::new(RichText::new("Generate from type").size(11.0).color(TEXT_PRIMARY))
                                .fill(INPUT_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(4.0)
                                .min_size(Vec2::new(f32::INFINITY, 28.0))).clicked() {
                                if let Some(pos) = self.intr_positions.get_mut(self.intr_payload_pos) {
                                    pos.payloads = match pos.payload_type {
                                        PayloadType::Numbers    => (1..=100).map(|n| n.to_string()).collect(),
                                        PayloadType::Characters => ('a'..='z').map(|c| c.to_string()).collect(),
                                        PayloadType::Dates      => (2020..=2025).flat_map(|y| (1..=12).map(move |m| format!("{:04}-{:02}", y, m))).collect(),
                                        PayloadType::Nulls      => vec!["null".into(), "None".into(), "undefined".into(), "\0".into(), "''".into()],
                                        PayloadType::Wordlist   => pos.payloads.clone(),
                                    };
                                }
                            }
                        });
                    });
                });
            }

            _ => {
                // Results tab
                Frame::NONE.fill(CARD_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(10.0)
                    .inner_margin(Margin::same(0)).show(ui, |ui| {
                    // Results header
                    Frame::NONE.fill(Color32::from_rgb(14, 20, 30)).inner_margin(Margin::symmetric(12, 8)).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("#").size(10.0).strong().color(TEXT_DIM));
                            ui.add_space(10.0);
                            ui.label(RichText::new("Payload").size(10.0).strong().color(TEXT_DIM));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(RichText::new("ms").size(10.0).strong().color(TEXT_DIM));
                                ui.add_space(20.0);
                                ui.label(RichText::new("Length").size(10.0).strong().color(TEXT_DIM));
                                ui.add_space(20.0);
                                ui.label(RichText::new("Status").size(10.0).strong().color(TEXT_DIM));
                            });
                        });
                    });
                    ui.separator();
                    if self.intr_results.is_empty() {
                        ui.vertical_centered(|ui| {
                            ui.add_space(40.0);
                            ui.label(RichText::new("No results yet — configure Positions & Payloads then Start attack").size(12.0).color(TEXT_MUTED));
                        });
                    }
                    ScrollArea::vertical().id_salt("intr_results").show(ui, |ui| {
                        for (i, result) in self.intr_results.iter().enumerate() {
                            let payload_str = result.payload_set.join(" | ");
                            let bg = if result.status >= 200 && result.status < 300 {
                                Color32::from_rgb(0, 30, 15)
                            } else if result.error.is_some() {
                                Color32::from_rgb(40, 10, 10)
                            } else {
                                Color32::TRANSPARENT
                            };
                            Frame::NONE.fill(bg).inner_margin(Margin::symmetric(12, 5)).show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(format!("{}", i + 1)).size(10.0).monospace().color(TEXT_DIM));
                                    ui.add_space(10.0);
                                    ui.label(RichText::new(&payload_str).size(11.0).monospace().color(TEXT_PRIMARY));
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        ui.label(RichText::new(format!("{}", result.elapsed_ms)).size(10.0).color(TEXT_MUTED));
                                        ui.add_space(20.0);
                                        ui.label(RichText::new(format!("{}", result.length)).size(10.0).color(TEXT_PRIMARY));
                                        ui.add_space(20.0);
                                        let sc = if result.error.is_some() { DANGER } else { status_color(result.status) };
                                        ui.label(RichText::new(format!("{}", result.status)).size(11.0).strong().color(sc));
                                    });
                                });
                                if let Some(ref err) = result.error {
                                    ui.label(RichText::new(err).size(10.0).color(DANGER));
                                }
                            });
                            ui.separator();
                        }
                    });
                });
            }
        }

        // Status bar
        ui.add_space(4.0);
        Frame::NONE.fill(Color32::from_rgb(10, 16, 24)).inner_margin(Margin::symmetric(14, 4)).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(if self.intr_running { "Attacking..." } else { "Ready" }).size(10.0).color(if self.intr_running { ACCENT } else { TEXT_MUTED }));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let total_pos: usize = self.intr_positions.iter().map(|p| p.payloads.len()).sum();
                    ui.label(RichText::new(format!("{} payload positions  |  {} total payloads  |  {} results", self.intr_positions.len(), total_pos, self.intr_results.len())).size(10.0).color(TEXT_DIM));
                });
            });
        });
    }
}
