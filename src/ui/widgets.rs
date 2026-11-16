//! Small reusable pieces of UI.

use super::theme::{pal, pal_ctx, regular, semibold, Icon};
use eframe::egui::{
    self, pos2, text::LayoutJob, text::TextWrapping, vec2, Align2, Color32, CornerRadius, FontId,
    Frame, Margin, Rect, Response, RichText, Sense, Stroke, StrokeKind, TextureHandle, Ui, Vec2,
};

/// A rounded card.
pub fn card(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    let p = pal(ui);
    Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        });
}

fn filled_button(ui: &mut Ui, text: &str, fill: Color32, fg: Color32, enabled: bool) -> Response {
    let p = pal(ui);
    let (fill, fg) = if enabled {
        (fill, fg)
    } else {
        (p.hover, p.faint)
    };
    let button = egui::Button::new(RichText::new(text).font(semibold(14.0)).color(fg))
        .fill(fill)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(8))
        .min_size(vec2(0.0, 34.0));
    let prev = ui.spacing().button_padding;
    ui.spacing_mut().button_padding = vec2(16.0, 7.0);
    let r = ui.add_enabled(enabled, button);
    ui.spacing_mut().button_padding = prev;
    if r.hovered() && enabled {
        ui.painter()
            .rect_filled(r.rect, CornerRadius::same(8), Color32::from_white_alpha(22));
    }
    r
}

/// The main action on a screen (lime green).
pub fn primary_button(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    let p = pal(ui);
    filled_button(ui, text, p.accent, p.on_accent, enabled)
}

/// A destructive action (coral).
pub fn danger_button(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    let p = pal(ui);
    filled_button(ui, text, p.danger, Color32::WHITE, enabled)
}

/// A secondary action.
pub fn ghost_button(ui: &mut Ui, text: &str) -> Response {
    ghost_button_enabled(ui, text, true)
}

pub fn ghost_button_enabled(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    let p = pal(ui);
    let button =
        egui::Button::new(RichText::new(text).color(if enabled { p.text } else { p.faint }))
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::new(1.0_f32, p.border))
            .corner_radius(CornerRadius::same(8))
            .min_size(vec2(0.0, 34.0));
    ui.add_enabled(enabled, button)
}

/// A square icon-only button with a tooltip.
pub fn icon_button(ui: &mut Ui, icon: Icon, tooltip: &str) -> Response {
    let p = pal(ui);
    let label = if icon.glyph().is_empty() {
        tooltip.chars().take(1).collect::<String>()
    } else {
        icon.glyph().to_string()
    };
    let button = egui::Button::new(RichText::new(label).size(15.0).color(p.muted))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(8))
        .min_size(vec2(32.0, 32.0));
    ui.add(button).on_hover_text(tooltip)
}

/// A small pill label.
pub fn badge(ui: &mut Ui, text: &str, color: Color32) -> Response {
    let font = semibold(11.5);
    let galley = ui.painter().layout_no_wrap(text.to_string(), font, color);
    let size = vec2(galley.size().x + 14.0, 20.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
    paint_badge_at(ui, rect, galley, color);
    resp
}

fn paint_badge_at(ui: &Ui, rect: Rect, galley: std::sync::Arc<egui::Galley>, color: Color32) {
    ui.painter()
        .rect_filled(rect, CornerRadius::same(10), color.gamma_multiply(0.16));
    let pos = pos2(
        rect.center().x - galley.size().x / 2.0,
        rect.center().y - galley.size().y / 2.0,
    );
    ui.painter().galley(pos, galley, color);
}

/// Paints a badge right-aligned inside `rect` and returns the width it used.
pub fn paint_badge(ui: &Ui, rect: Rect, text: &str, color: Color32) -> f32 {
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_string(), semibold(11.5), color);
    let w = galley.size().x + 14.0;
    let r = Rect::from_min_size(pos2(rect.left(), rect.center().y - 10.0), vec2(w, 20.0));
    paint_badge_at(ui, r, galley, color);
    w
}

/// Paints a custom checkbox in `rect`. `state`: Some(true) checked,
/// Some(false) unchecked, None = mixed.
pub fn paint_checkbox(ui: &Ui, rect: Rect, state: Option<bool>, hovered: bool) {
    let p = pal(ui);
    let r = Rect::from_center_size(rect.center(), Vec2::splat(18.0));
    match state {
        Some(false) => {
            ui.painter().rect_stroke(
                r,
                CornerRadius::same(5),
                Stroke::new(1.5_f32, if hovered { p.accent } else { p.faint }),
                StrokeKind::Inside,
            );
        }
        Some(true) => {
            ui.painter().rect_filled(r, CornerRadius::same(5), p.accent);
            let c = r.center();
            let pts = [
                c + vec2(-4.5, 0.0),
                c + vec2(-1.5, 3.2),
                c + vec2(4.8, -3.6),
            ];
            ui.painter()
                .line_segment([pts[0], pts[1]], Stroke::new(2.0_f32, p.on_accent));
            ui.painter()
                .line_segment([pts[1], pts[2]], Stroke::new(2.0_f32, p.on_accent));
        }
        None => {
            ui.painter().rect_filled(r, CornerRadius::same(5), p.accent);
            let c = r.center();
            ui.painter().line_segment(
                [c + vec2(-4.5, 0.0), c + vec2(4.5, 0.0)],
                Stroke::new(2.0_f32, p.on_accent),
            );
        }
    }
}

/// A checkbox with a label, in the brand style.
pub fn checkbox(ui: &mut Ui, value: &mut bool, label: &str) -> Response {
    checkbox_enabled(ui, value, label, true)
}

pub fn checkbox_enabled(ui: &mut Ui, value: &mut bool, label: &str, enabled: bool) -> Response {
    let p = pal(ui);
    let galley = ui.painter().layout_no_wrap(
        label.to_string(),
        regular(14.0),
        if enabled { p.text } else { p.faint },
    );
    let size = vec2(26.0 + galley.size().x, 24.0);
    let (rect, mut resp) = ui.allocate_exact_size(
        size,
        if enabled {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    if resp.clicked() {
        *value = !*value;
        resp.mark_changed();
    }
    let box_rect = Rect::from_min_size(rect.min, vec2(20.0, rect.height()));
    if enabled {
        paint_checkbox(ui, box_rect, Some(*value), resp.hovered());
    } else {
        ui.painter().rect_stroke(
            Rect::from_center_size(box_rect.center(), Vec2::splat(18.0)),
            CornerRadius::same(5),
            Stroke::new(1.5_f32, p.border),
            StrokeKind::Inside,
        );
    }
    ui.painter().galley(
        pos2(rect.left() + 26.0, rect.center().y - galley.size().y / 2.0),
        galley,
        p.text,
    );
    resp
}

/// An on/off switch. Returns true when clicked.
pub fn toggle(ui: &mut Ui, on: bool, enabled: bool) -> Response {
    let p = pal(ui);
    let (rect, resp) = ui.allocate_exact_size(
        vec2(38.0, 22.0),
        if enabled {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    let t = ui.ctx().animate_bool_with_time(resp.id, on, 0.12);
    let track = if !enabled {
        p.border
    } else if on {
        p.accent
    } else {
        p.faint.gamma_multiply(0.6)
    };
    ui.painter()
        .rect_filled(rect, CornerRadius::same(11), track);
    let x = egui::lerp((rect.left() + 11.0)..=(rect.right() - 11.0), t);
    ui.painter().circle_filled(
        pos2(x, rect.center().y),
        8.0,
        if enabled { Color32::WHITE } else { p.faint },
    );
    resp
}

/// A row of mutually exclusive choices. Returns the newly picked index.
pub fn segmented(ui: &mut Ui, options: &[&str], current: usize) -> Option<usize> {
    let p = pal(ui);
    let mut picked = None;
    Frame::new()
        .fill(p.hover)
        .corner_radius(CornerRadius::same(9))
        .inner_margin(Margin::same(3))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                // In a right-to-left row the first widget lands on the right:
                // add the options backwards so they still read left to right.
                let mut order: Vec<usize> = (0..options.len()).collect();
                if ui.layout().prefer_right_to_left() {
                    order.reverse();
                }
                for i in order {
                    let label = &options[i];
                    let active = i == current;
                    let text = RichText::new(*label).color(if active { p.text } else { p.muted });
                    let text = if active {
                        text.font(semibold(13.5))
                    } else {
                        text.size(13.5)
                    };
                    let b = egui::Button::new(text)
                        .fill(if active { p.card } else { Color32::TRANSPARENT })
                        .stroke(if active {
                            Stroke::new(1.0_f32, p.border)
                        } else {
                            Stroke::NONE
                        })
                        .corner_radius(CornerRadius::same(7))
                        .min_size(vec2(0.0, 28.0));
                    if ui.add(b).clicked() && !active {
                        picked = Some(i);
                    }
                }
            });
        });
    picked
}

/// A filter chip.
pub fn chip(ui: &mut Ui, label: &str, count: Option<usize>, active: bool) -> Response {
    let p = pal(ui);
    let text = match count {
        Some(n) => format!("{label}  {n}"),
        None => label.to_string(),
    };
    let (fill, fg, stroke) = if active {
        (
            p.accent.gamma_multiply(0.16),
            p.accent,
            Stroke::new(1.0_f32, p.accent.gamma_multiply(0.6)),
        )
    } else {
        (
            Color32::TRANSPARENT,
            p.muted,
            Stroke::new(1.0_f32, p.border),
        )
    };
    let b = egui::Button::new(RichText::new(text).size(13.0).color(fg))
        .fill(fill)
        .stroke(stroke)
        .corner_radius(CornerRadius::same(15))
        .min_size(vec2(0.0, 30.0));
    ui.add(b)
}

/// Lays out one line of text, cut off with an ellipsis at `max_width`.
pub fn elided(
    ui: &Ui,
    text: &str,
    font: FontId,
    color: Color32,
    max_width: f32,
) -> std::sync::Arc<egui::Galley> {
    let mut job = LayoutJob::simple_singleline(text.to_string(), font, color);
    job.wrap = TextWrapping {
        max_width: max_width.max(8.0),
        max_rows: 1,
        break_anywhere: true,
        overflow_character: Some('…'),
    };
    ui.fonts(|f| f.layout_job(job))
}

/// Paints one elided line, vertically centred in `rect`. Returns whether it was cut.
pub fn text_in(ui: &Ui, rect: Rect, text: &str, font: FontId, color: Color32) -> bool {
    let galley = elided(ui, text, font, color, rect.width());
    let cut = galley.elided;
    ui.painter().galley(
        pos2(rect.left(), rect.center().y - galley.size().y / 2.0),
        galley,
        color,
    );
    cut
}

/// Like [`text_in`], right-aligned.
pub fn text_in_right(ui: &Ui, rect: Rect, text: &str, font: FontId, color: Color32) {
    let galley = elided(ui, text, font, color, rect.width());
    ui.painter().galley(
        pos2(
            rect.right() - galley.size().x,
            rect.center().y - galley.size().y / 2.0,
        ),
        galley,
        color,
    );
}

fn tile_color(name: &str) -> Color32 {
    const COLORS: [Color32; 8] = [
        Color32::from_rgb(0x10, 0xa3, 0x7f),
        Color32::from_rgb(0x08, 0x6f, 0xa8),
        Color32::from_rgb(0x7c, 0x5c, 0xd6),
        Color32::from_rgb(0xd9, 0x6a, 0x2b),
        Color32::from_rgb(0xc2, 0x48, 0x7a),
        Color32::from_rgb(0x2f, 0x86, 0xc9),
        Color32::from_rgb(0x4e, 0x9a, 0x3c),
        Color32::from_rgb(0xb8, 0x8a, 0x1f),
    ];
    let h = name
        .bytes()
        .fold(7u32, |a, b| a.wrapping_mul(31).wrapping_add(b as u32));
    COLORS[(h % COLORS.len() as u32) as usize]
}

/// Paints a program icon, or a coloured tile with the program's initial.
pub fn program_icon(ui: &Ui, rect: Rect, name: &str, texture: Option<&TextureHandle>) {
    match texture {
        Some(tex) => {
            ui.painter().image(
                tex.id(),
                rect,
                Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)),
                Color32::WHITE,
            );
        }
        None => {
            let radius = (rect.width() * 0.26) as u8;
            ui.painter()
                .rect_filled(rect, CornerRadius::same(radius), tile_color(name));
            let initial: String = name
                .chars()
                .find(|c| c.is_alphanumeric())
                .map(|c| c.to_uppercase().collect())
                .unwrap_or_default();
            ui.painter().text(
                rect.center(),
                Align2::CENTER_CENTER,
                initial,
                semibold(rect.height() * 0.5),
                Color32::WHITE,
            );
        }
    }
}

/// A designed empty / error state: icon, title, explanation.
pub fn empty_state(ui: &mut Ui, icon: Icon, color: Color32, title: &str, text: &str) {
    let p = pal(ui);
    ui.vertical_centered(|ui| {
        ui.add_space((ui.available_height() * 0.22).clamp(24.0, 140.0));
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(72.0), Sense::hover());
        ui.painter()
            .circle_filled(rect.center(), 36.0, color.gamma_multiply(0.14));
        ui.painter().text(
            rect.center(),
            Align2::CENTER_CENTER,
            icon.glyph(),
            regular(30.0),
            color,
        );
        ui.add_space(10.0);
        ui.label(RichText::new(title).font(semibold(18.0)).color(p.text));
        ui.add_space(2.0);
        ui.scope(|ui| {
            ui.set_max_width(460.0);
            ui.label(RichText::new(text).color(p.muted));
        });
        ui.add_space(8.0);
    });
}

/// A spinner with a line of text, centred.
pub fn busy_state(ui: &mut Ui, title: &str, text: &str) {
    let p = pal(ui);
    ui.vertical_centered(|ui| {
        ui.add_space((ui.available_height() * 0.25).clamp(24.0, 160.0));
        ui.add(egui::Spinner::new().size(34.0).color(p.accent));
        ui.add_space(12.0);
        ui.label(RichText::new(title).font(semibold(18.0)));
        ui.add_space(2.0);
        ui.scope(|ui| {
            ui.set_max_width(560.0);
            ui.add(egui::Label::new(RichText::new(text).color(p.muted)).truncate());
        });
    });
}

/// "Label" on the left, value below it: used in the details panel.
pub fn field(ui: &mut Ui, label: &str, value: &str) {
    let p = pal(ui);
    ui.label(RichText::new(label).size(12.0).color(p.faint));
    ui.add_space(-6.0);
    let shown = if value.trim().is_empty() {
        "Not recorded"
    } else {
        value
    };
    let color = if value.trim().is_empty() {
        p.faint
    } else {
        p.text
    };
    ui.add(
        egui::Label::new(RichText::new(shown).color(color))
            .wrap()
            .selectable(true),
    );
    ui.add_space(2.0);
}

/// Section title inside a page.
pub fn section(ui: &mut Ui, title: &str) {
    ui.label(RichText::new(title).font(semibold(15.0)));
}

/// A thin horizontal line.
pub fn divider(ui: &mut Ui) {
    let p = pal(ui);
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
    ui.painter().rect_filled(rect, 0, p.border);
}

/// The family's modal window: a card with a fixed width. Every modal needs
/// its own `id`. Returns true when the user dismissed it (Esc or click outside).
pub fn modal(ctx: &egui::Context, id: &str, width: f32, add: impl FnOnce(&mut Ui)) -> bool {
    let p = pal_ctx(ctx);
    let modal = egui::Modal::new(egui::Id::new(id))
        .frame(
            Frame::new()
                .fill(p.card)
                .stroke(Stroke::new(1.0_f32, p.border))
                .corner_radius(CornerRadius::same(16))
                .inner_margin(Margin::same(24)),
        )
        .show(ctx, |ui| {
            ui.set_width(width);
            add(ui)
        });
    modal.should_close()
}

/// The title line of a modal.
pub fn modal_title(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).font(semibold(19.0)));
    ui.add_space(2.0);
}

/// A right-aligned row of dialog buttons with a fixed height. A bare
/// right-to-left layout takes all the height the modal may use, which makes
/// the dialog as tall as the window and leaves a blank panel.
pub fn button_row(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    ui.allocate_ui_with_layout(
        vec2(ui.available_width(), 36.0),
        egui::Layout::right_to_left(egui::Align::Center),
        add,
    );
}

/// A wrapped paragraph in the muted colour.
pub fn para(ui: &mut Ui, text: &str) {
    let p = pal(ui);
    ui.add(egui::Label::new(RichText::new(text).color(p.muted)).wrap());
}

/// The standard page header: title, subtitle and right-aligned actions.
pub fn page_header(ui: &mut Ui, title: &str, subtitle: &str, actions: impl FnOnce(&mut Ui)) {
    let p = pal(ui);
    ui.allocate_ui_with_layout(
        vec2(ui.available_width(), 50.0),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.label(RichText::new(title).font(semibold(24.0)));
                ui.label(RichText::new(subtitle).color(p.muted));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), actions);
        },
    );
    ui.add_space(6.0);
}

// --------------------------------------------------------------------------------------
// Tables
// --------------------------------------------------------------------------------------

/// Height of a table row.
pub const ROW_H: f32 = 46.0;
/// Height of a table header.
pub const HEADER_H: f32 = 34.0;

/// The card that holds a table: fills the remaining height of the page.
pub fn table_card(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    let p = pal(ui);
    let height = ui.available_height();
    Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(6, 6))
        .show(ui, |ui| {
            ui.set_height((height - 14.0).max(60.0));
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 0.0;
            add(ui)
        });
}

/// Allocates the header strip of a table and draws the line under it.
pub fn table_header(ui: &mut Ui) -> Rect {
    let p = pal(ui);
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), HEADER_H), Sense::hover());
    ui.painter().hline(
        rect.x_range().shrink(6.0),
        rect.bottom() - 1.0,
        Stroke::new(1.0_f32, p.border),
    );
    rect
}

/// One column title. `sorted`: None = not the sort column, Some(ascending).
/// With `sortable` the title reacts to clicks; the caller changes the order.
pub fn header_cell(
    ui: &mut Ui,
    rect: Rect,
    label: &str,
    sorted: Option<bool>,
    sortable: bool,
    right: bool,
) -> bool {
    let p = pal(ui);
    if rect.width() <= 4.0 {
        return false;
    }
    let mut clicked = false;
    let mut hovered = false;
    if sortable {
        let resp = ui
            .interact(rect, ui.id().with(("hdr", label)), Sense::click())
            .on_hover_text(format!("Sort by {}", label.to_lowercase()));
        hovered = resp.hovered();
        clicked = resp.clicked();
    }
    let color = if sorted.is_some() {
        p.text
    } else if hovered {
        p.muted
    } else {
        p.faint
    };
    let arrow = match sorted {
        None => "",
        Some(true) => Icon::SORT_UP.glyph(),
        Some(false) => Icon::SORT_DOWN.glyph(),
    };
    if right {
        let text = format!("{arrow} {label}");
        text_in_right(ui, rect, text.trim(), semibold(12.0), color);
    } else {
        let text = format!("{label} {arrow}");
        text_in(ui, rect, text.trim(), semibold(12.0), color);
    }
    clicked
}

/// How a table row is tinted: steady, just appeared (0..1) or fading out (0..1).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RowTint {
    None,
    New(f32),
    Closed(f32),
}

/// Strength of a highlight for a phase between 0 (just happened) and 1 (over).
pub fn tint_strength(phase: f32) -> f32 {
    let t = phase.clamp(0.0, 1.0);
    // Stays strong for the first third, then eases out.
    if t < 0.33 {
        1.0
    } else {
        let u = (1.0 - t) / 0.67;
        u * u
    }
}

/// Paints the background of a table row: selection, hover and change tint.
pub fn row_background(ui: &Ui, rect: Rect, selected: bool, hovered: bool, tint: RowTint) {
    let p = pal(ui);
    let r = rect.shrink2(vec2(0.0, 1.0));
    if selected {
        ui.painter()
            .rect_filled(r, CornerRadius::same(8), p.selected);
    } else if hovered {
        ui.painter().rect_filled(r, CornerRadius::same(8), p.hover);
    }
    let (color, phase) = match tint {
        RowTint::None => return,
        RowTint::New(t) => (p.accent, t),
        RowTint::Closed(t) => (p.danger, t),
    };
    let k = tint_strength(phase);
    ui.painter().rect_filled(
        r,
        CornerRadius::same(8),
        color.gamma_multiply(if p.dark { 0.17 } else { 0.14 } * k),
    );
    let bar = Rect::from_min_size(pos2(r.left() + 1.0, r.center().y - 11.0), vec2(3.0, 22.0));
    ui.painter()
        .rect_filled(bar, CornerRadius::same(2), color.gamma_multiply(k));
}

/// A cell rectangle inside a row: `x .. x + w`, minus the column gap.
pub fn cell(row: Rect, x: f32, w: f32) -> Rect {
    Rect::from_min_max(
        pos2(x, row.top()),
        pos2((x + w - 12.0).max(x), row.bottom()),
    )
}

/// Two lines of text in one cell: a first line and a smaller second one.
pub fn two_lines(
    ui: &Ui,
    rect: Rect,
    first: (&str, FontId, Color32),
    second: (&str, Color32),
) -> bool {
    if second.0.is_empty() {
        return text_in(ui, rect, first.0, first.1, first.2);
    }
    let top = Rect::from_min_max(
        rect.min + vec2(0.0, 5.0),
        pos2(rect.right(), rect.center().y + 1.0),
    );
    let bottom = Rect::from_min_max(
        pos2(rect.left(), rect.center().y + 1.0),
        rect.max - vec2(0.0, 5.0),
    );
    let cut = text_in(ui, top, first.0, first.1, first.2);
    let cut2 = text_in(ui, bottom, second.0, regular(11.5), second.1);
    cut || cut2
}

/// A compact button for rows and side panels.
pub fn small_button(ui: &mut Ui, text: &str) -> Response {
    small_button_enabled(ui, text, true)
}

pub fn small_button_enabled(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    let p = pal(ui);
    let color = if enabled { p.text } else { p.faint };
    let button = egui::Button::new(RichText::new(text).size(13.0).color(color))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(7))
        .min_size(vec2(0.0, 28.0));
    let prev = ui.spacing().button_padding;
    ui.spacing_mut().button_padding = vec2(10.0, 4.0);
    let r = ui.add_enabled(enabled, button);
    ui.spacing_mut().button_padding = prev;
    r
}

/// A single-line text box in the brand style with a fixed width.
pub fn text_box(ui: &mut Ui, text: &mut String, width: f32, hint: &str) -> Response {
    let p = pal(ui);
    Frame::new()
        .fill(if p.dark { p.bg } else { p.card })
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(10, 5))
        .show(ui, |ui| {
            let edit = egui::TextEdit::singleline(text)
                .hint_text(RichText::new(hint).color(p.faint))
                .frame(false)
                .desired_width(width)
                .font(regular(14.5));
            ui.add(edit)
        })
        .inner
}

/// A card with an icon in front of a wrapped paragraph: notes and banners.
pub fn note_card(ui: &mut Ui, icon: Icon, color: Color32, title: &str, text: &str) {
    let p = pal(ui);
    Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 12.0;
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(30.0), Sense::hover());
                ui.painter()
                    .circle_filled(rect.center(), 15.0, color.gamma_multiply(0.15));
                ui.painter().text(
                    rect.center(),
                    Align2::CENTER_CENTER,
                    icon.glyph(),
                    regular(14.0),
                    color,
                );
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.set_width(ui.available_width());
                    if !title.is_empty() {
                        ui.label(RichText::new(title).font(semibold(14.0)));
                    }
                    if !text.is_empty() {
                        ui.add(egui::Label::new(RichText::new(text).color(p.muted)).wrap());
                    }
                });
            });
        });
}

/// A settings row: title and explanation on the left, a control on the right.
pub fn setting_row(ui: &mut Ui, title: &str, text: &str, control: impl FnOnce(&mut Ui)) {
    let p = pal(ui);
    let width = ui.available_width();
    let text_width = (width - 270.0).max(200.0);
    let galley = ui
        .painter()
        .layout(text.to_string(), regular(12.5), p.muted, text_width);
    let height = (galley.size().y + 26.0).max(42.0);
    let (rect, _) = ui.allocate_exact_size(vec2(width, height), Sense::hover());
    ui.painter().text(
        rect.left_top() + vec2(0.0, 1.0),
        Align2::LEFT_TOP,
        title,
        regular(14.5),
        p.text,
    );
    ui.painter()
        .galley(rect.left_top() + vec2(0.0, 22.0), galley, p.muted);
    let control_rect = Rect::from_min_max(pos2(rect.right() - 250.0, rect.top()), rect.max);
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(control_rect)
            .layout(egui::Layout::right_to_left(egui::Align::Center)),
    );
    control(&mut child);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tint_fades_out() {
        assert_eq!(tint_strength(0.0), 1.0);
        assert_eq!(tint_strength(0.3), 1.0);
        assert!(tint_strength(0.6) < 1.0 && tint_strength(0.6) > tint_strength(0.9));
        assert!(tint_strength(1.0).abs() < 1e-6);
        assert_eq!(tint_strength(7.0), 0.0);
        assert_eq!(tint_strength(-1.0), 1.0);
    }

    #[test]
    fn cells_never_invert() {
        let row = Rect::from_min_size(pos2(0.0, 0.0), vec2(500.0, ROW_H));
        let c = cell(row, 100.0, 80.0);
        assert_eq!((c.left(), c.right()), (100.0, 168.0));
        let c = cell(row, 100.0, 4.0);
        assert!(c.width() >= 0.0);
    }
}
