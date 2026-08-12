// Visual theme: the palette and the shared widget builders (cards, section
// titles, buttons) that give every page a consistent look. Kept in one place so
// a colour or corner-radius tweak propagates app-wide.

use eframe::egui::{self, Color32, Frame, Margin, RichText, Stroke, Vec2, Ui};

// ============ THEME COLORS ============
pub(crate) const BG: Color32 = Color32::from_rgb(8, 12, 18);
pub(crate) const PANEL_BG: Color32 = Color32::from_rgb(13, 18, 26);
pub(crate) const CARD_BG: Color32 = Color32::from_rgb(18, 24, 34);
pub(crate) const ELEVATED: Color32 = Color32::from_rgb(26, 35, 48);
pub(crate) const INPUT_BG: Color32 = Color32::from_rgb(24, 32, 44);
pub(crate) const BORDER: Color32 = Color32::from_rgb(30, 40, 55);
pub(crate) const ACCENT: Color32 = Color32::from_rgb(0, 230, 118);
pub(crate) const ACCENT_BRIGHT: Color32 = Color32::from_rgb(70, 255, 170);
pub(crate) const ACCENT_DIM: Color32 = Color32::from_rgb(0, 180, 90);
pub(crate) const TEXT_PRIMARY: Color32 = Color32::from_rgb(235, 235, 240);
pub(crate) const TEXT_SECONDARY: Color32 = Color32::from_rgb(180, 185, 195);
pub(crate) const TEXT_MUTED: Color32 = Color32::from_rgb(120, 130, 145);
pub(crate) const TEXT_DIM: Color32 = Color32::from_rgb(80, 90, 105);
pub(crate) const INFO: Color32 = Color32::from_rgb(90, 170, 255);
pub(crate) const WARN: Color32 = Color32::from_rgb(255, 180, 60);
pub(crate) const DANGER: Color32 = Color32::from_rgb(255, 85, 85);
pub(crate) const TERMINAL_BG: Color32 = Color32::from_rgb(5, 8, 12);

// ============ UI HELPERS ============
pub(crate) fn card_frame() -> Frame {
    // Soft drop-shadow + rounder corners give cards a gentle sense of elevation
    // instead of sitting flat on the background — the main "smoothness" lever,
    // since this frame backs almost every panel in the app.
    Frame::NONE
        .fill(CARD_BG)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(14.0)
        .shadow(egui::Shadow { offset: [0, 3], blur: 16, spread: 0, color: Color32::from_black_alpha(45) })
        .inner_margin(Margin::same(20))
}

pub(crate) fn section_title(ui: &mut Ui, text: &str) {
    ui.horizontal(|ui| {
        let (tick_rect, _) = ui.allocate_exact_size(Vec2::new(3.0, 13.0), egui::Sense::hover());
        ui.painter().rect_filled(tick_rect, 1.5, ACCENT);
        ui.add_space(2.0);
        ui.label(RichText::new(text).size(12.0).strong().color(ACCENT).line_height(Some(14.0)));
    });
    ui.add_space(12.0);
}

pub(crate) fn accent_button(text: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(text).size(12.0).strong().color(Color32::WHITE))
        .fill(ACCENT).corner_radius(10.0).min_size(Vec2::new(100.0, 36.0))
}

pub(crate) fn subtle_button(text: &str) -> egui::Button<'_> {
    // No explicit `.stroke()` — lets the global widget visuals (inactive/hovered/active)
    // drive the border color, so these buttons glow with the accent ring on hover.
    egui::Button::new(RichText::new(text).size(11.0).color(TEXT_SECONDARY))
        .fill(INPUT_BG).corner_radius(8.0).min_size(Vec2::new(80.0, 28.0))
}

#[allow(dead_code)] // icon+label RichText helper kept for reuse across pages
pub(crate) fn icon_text(icon: &str, text: &str) -> RichText {
    RichText::new(format!("{} {}", icon, text)).size(13.0).color(TEXT_PRIMARY)
}

pub(crate) fn status_color(status: u16) -> Color32 {
    match status { 200..=299 => ACCENT, 300..=399 => WARN, 400..=599 => DANGER, _ => TEXT_DIM }
}

pub(crate) fn mind_kind_color(kind: &str) -> Color32 {
    match kind {
        "Endpoint"    => INFO,
        "Credential"  => DANGER,
        "Token"       => WARN,
        "Observation" => Color32::from_rgb(180, 140, 255),
        _             => TEXT_SECONDARY,
    }
}

pub(crate) fn hypo_status_color(status: &str) -> Color32 {
    match status {
        "Valid"   => ACCENT,
        "Invalid" => DANGER,
        "Testing" => WARN,
        _         => INFO, // Open
    }
}
