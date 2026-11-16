//! Port check: "who is using port N?" with every reason a bind can fail,
//! and the free-port finder.

use super::app::App;
use super::details::exposure_color;
use super::theme::{pal, regular, semibold, Icon, Palette};
use super::widgets::{self, ROW_H};
use crate::freeport::{self, BindTest, PortContext, PortReport, Verdict};
use crate::model::{ListenerKey, Proto, SocketSnapshot};
use eframe::egui::{
    self, pos2, vec2, Align, Align2, Color32, CornerRadius, Frame, Layout, Margin, Rect, RichText,
    Sense, Stroke, Ui,
};

/// Most free ports of a range shown as chips.
const RANGE_CHIPS: usize = 24;
/// Most ports of a list shown in the verdict table.
const LIST_ROWS: usize = 512;

pub struct LookupState {
    /// false = "Check a port", true = "Find a free port".
    pub finder: bool,
    pub port_text: String,
    pub proto: Proto,
    /// The last test bind and what it was for.
    pub bind: Option<(u16, Proto, BindTest)>,
    pub from_text: String,
    pub block_text: String,
    pub range_from: String,
    pub range_to: String,
    pub list_text: String,
    pub finder_proto: Proto,
}

impl Default for LookupState {
    fn default() -> Self {
        LookupState {
            finder: false,
            port_text: String::new(),
            proto: Proto::Tcp,
            bind: None,
            from_text: "3000".into(),
            block_text: "3".into(),
            range_from: "8000".into(),
            range_to: "8100".into(),
            list_text: String::new(),
            finder_proto: Proto::Tcp,
        }
    }
}

impl LookupState {
    pub fn set_port(&mut self, port: u16, proto: Proto) {
        self.finder = false;
        self.port_text = port.to_string();
        self.proto = proto;
        self.bind = None;
    }
}

/// Reads a port number as people type it: `3000`, ` :3000 `, `localhost:3000`.
/// `Err("")` means "nothing typed yet".
pub(super) fn parse_port(text: &str) -> Result<u16, String> {
    let t = text.trim();
    let t = t.rsplit(':').next().unwrap_or(t).trim();
    if t.is_empty() {
        return Err(String::new());
    }
    if !t.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("\"{t}\" is not a port number."));
    }
    match t.parse::<u32>() {
        Ok(n) if n <= u16::MAX as u32 => Ok(n as u16),
        _ => Err("Port numbers go from 0 to 65535.".to_string()),
    }
}

pub(super) fn verdict_label(v: Verdict) -> &'static str {
    match v {
        Verdict::Free => "Free",
        Verdict::FreeWithNotes => "Free, with notes",
        Verdict::InUse => "In use",
        Verdict::Reserved => "Reserved",
    }
}

fn verdict_color(v: Verdict, p: &Palette) -> Color32 {
    match v {
        Verdict::Free => p.accent,
        Verdict::FreeWithNotes => p.info,
        Verdict::InUse => p.warn,
        Verdict::Reserved => p.danger,
    }
}

fn verdict_icon(v: Verdict) -> Icon {
    match v {
        Verdict::Free => Icon::CHECK,
        Verdict::FreeWithNotes => Icon::INFO,
        Verdict::InUse => Icon::PLUG,
        Verdict::Reserved => Icon::LOCK,
    }
}

/// One short line about a port for the list check.
pub(super) fn verdict_detail(report: &PortReport, snap: &SocketSnapshot) -> String {
    match report.verdict {
        Verdict::InUse => {
            let mut who: Vec<String> = Vec::new();
            for &i in &report.users {
                if let Some(l) = snap.listeners.get(i) {
                    let s = format!("{} (PID {})", snap.proc_name(l.pid), l.pid);
                    if !who.contains(&s) {
                        who.push(s);
                    }
                }
            }
            if who.is_empty() {
                "Served by HTTP.sys".to_string()
            } else if !report.http_urls.is_empty() {
                format!("{} · HTTP.sys", who.join(", "))
            } else {
                who.join(", ")
            }
        }
        Verdict::Reserved => match report.excluded {
            Some(r) => format!(
                "Excluded range {}-{}: binds fail with \"access denied\"",
                r.start, r.end
            ),
            None => "Reserved by Windows".to_string(),
        },
        Verdict::FreeWithNotes => {
            if report.port == 0 {
                "Port 0 means \"any free port\"".to_string()
            } else if !report.reserved_urls.is_empty() {
                format!("URL reservation {}", report.reserved_urls.join(", "))
            } else {
                "Inside the dynamic range: may be taken at any moment".to_string()
            }
        }
        Verdict::Free => match report.well_known {
            Some(name) => format!("Usually: {name}"),
            None => String::new(),
        },
    }
}

/// How a note is illustrated: reasons a bind fails stand out.
fn note_style(note: &str, p: &Palette) -> (Icon, Color32, &'static str) {
    if note.contains("excluded range") {
        (Icon::LOCK, p.danger, "Excluded port range")
    } else if note.contains("HTTP.sys") && note.contains("serving") {
        (Icon::GLOBE, p.warn, "Served by HTTP.sys")
    } else if note.starts_with("URL reservation") {
        (Icon::LINK, p.info, "HTTP.sys URL reservation")
    } else if note.contains("dynamic (ephemeral) range") {
        (Icon::CLOCK, p.info, "Dynamic port range")
    } else if note.contains("bound to it") {
        (Icon::PLUG, p.warn, "Already bound")
    } else if note.starts_with("Commonly used by") {
        (Icon::TAG, p.muted, "Well-known port")
    } else {
        (Icon::INFO, p.muted, "Good to know")
    }
}

fn proto_index(proto: Proto) -> usize {
    match proto {
        Proto::Tcp => 0,
        Proto::Udp => 1,
    }
}

fn proto_at(i: usize) -> Proto {
    if i == 0 {
        Proto::Tcp
    } else {
        Proto::Udp
    }
}

fn copy_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

impl App {
    pub(super) fn lookup_apply_view(&mut self, view: &str) {
        match view {
            "free" => {
                self.lookup.finder = true;
                if self.lookup.list_text.is_empty() {
                    self.lookup.list_text =
                        "3000, 3001, 5432, 8080-8082, 9000, 50010, 61000".into();
                }
            }
            "lookup-reserved" => self.lookup.set_port(50010, Proto::Tcp),
            _ => {
                if self.lookup.port_text.is_empty() && self.sh.demo {
                    self.lookup.set_port(80, Proto::Tcp);
                }
            }
        }
    }

    pub(super) fn lookup_ui(&mut self, ui: &mut Ui) {
        let mut tab = None;
        widgets::page_header(
            ui,
            "Port check",
            "Find out who is using a port, why a bind fails, and which ports are free.",
            |ui| {
                tab = widgets::segmented(
                    ui,
                    &["Check a port", "Find a free port"],
                    usize::from(self.lookup.finder),
                );
            },
        );
        if let Some(i) = tab {
            self.lookup.finder = i == 1;
        }
        if !self.sys_loaded {
            let p = pal(ui);
            ui.label(
                RichText::new(
                    "Reserved ranges and URL reservations are still being read; the answers \
                     below only consider listening sockets for now.",
                )
                .color(p.warn),
            );
        }
        if self.lookup.finder {
            self.finder_ui(ui);
        } else {
            self.check_ui(ui);
        }
    }

    // ----------------------------------------------------------------------------------
    // Check a port
    // ----------------------------------------------------------------------------------

    fn check_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let parsed = parse_port(&self.lookup.port_text);
        let proto = self.lookup.proto;
        let report = parsed.as_ref().ok().map(|&port| {
            let pc = PortContext::new(&self.snap, &self.sys);
            freeport::check(port, proto, &pc)
        });

        // ---- The question -----------------------------------------------------------
        widgets::card(ui, |ui| {
            let row = Layout::left_to_right(Align::Center);
            ui.allocate_ui_with_layout(vec2(ui.available_width(), 44.0), row, |ui| {
                ui.spacing_mut().item_spacing.x = 12.0;
                ui.label(RichText::new("Who is using port").font(semibold(18.0)));
                let resp = Frame::new()
                    .fill(if p.dark { p.bg } else { p.card })
                    .stroke(Stroke::new(1.0_f32, p.border))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(Margin::symmetric(12, 6))
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.lookup.port_text)
                                .hint_text(RichText::new("3000").color(p.faint))
                                .frame(false)
                                .desired_width(92.0)
                                .char_limit(24)
                                .font(semibold(20.0)),
                        )
                    })
                    .inner;
                if resp.changed() {
                    self.lookup.bind = None;
                }
                if let Some(i) = widgets::segmented(ui, &["TCP", "UDP"], proto_index(proto)) {
                    self.lookup.proto = proto_at(i);
                    self.lookup.bind = None;
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    for port in [8080u16, 5432, 3000, 443, 80] {
                        if widgets::small_button(ui, &port.to_string()).clicked() {
                            self.lookup.set_port(port, self.lookup.proto);
                        }
                    }
                    ui.label(RichText::new("Try").color(p.faint));
                });
            });
            match (&parsed, &report) {
                (Err(e), _) if !e.is_empty() => {
                    ui.add_space(4.0);
                    ui.label(RichText::new(e).color(p.danger));
                }
                (_, Some(r)) => {
                    ui.add_space(8.0);
                    widgets::divider(ui);
                    ui.add_space(8.0);
                    let color = verdict_color(r.verdict, &p);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 14.0;
                        let (rect, _) = ui.allocate_exact_size(vec2(48.0, 48.0), Sense::hover());
                        ui.painter()
                            .circle_filled(rect.center(), 24.0, color.gamma_multiply(0.16));
                        ui.painter().text(
                            rect.center(),
                            Align2::CENTER_CENTER,
                            verdict_icon(r.verdict).glyph(),
                            regular(21.0),
                            color,
                        );
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            ui.label(RichText::new(r.headline()).font(semibold(21.0)));
                            let sub = match (r.verdict, r.well_known) {
                                (Verdict::Free, _) => {
                                    "Nothing listens on it and nothing reserves it.".to_string()
                                }
                                (Verdict::Reserved, _) => "Nothing listens on it, but Windows \
                                                           refuses every bind."
                                    .to_string(),
                                (Verdict::FreeWithNotes, _) => {
                                    "Nothing listens on it. Read the notes below.".to_string()
                                }
                                (Verdict::InUse, Some(name)) => {
                                    format!("This port usually carries: {name}.")
                                }
                                (Verdict::InUse, None) => {
                                    "A program on this PC is listening on it.".to_string()
                                }
                            };
                            ui.label(RichText::new(sub).color(p.muted));
                        });
                    });
                }
                _ => {}
            }
        });
        let Some(report) = report else {
            if parsed.as_ref().is_err_and(|e| e.is_empty()) {
                widgets::empty_state(
                    ui,
                    Icon::TARGET,
                    p.info,
                    "Type a port number",
                    "For example 3000, 5432 or 8080. You get the process that listens on it, \
                     or the reason why a free-looking port still refuses a bind.",
                );
            }
            return;
        };
        ui.add_space(4.0);

        let mut show: Option<ListenerKey> = None;
        let mut do_bind = false;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_width(ui.available_width());

                // ---- Who uses it --------------------------------------------------------
                let users: Vec<ListenerKey> = report
                    .users
                    .iter()
                    .filter_map(|&i| self.snap.listeners.get(i).map(|l| l.key()))
                    .collect();
                let http: Vec<_> = if proto == Proto::Tcp {
                    self.sys
                        .http_listeners
                        .iter()
                        .filter(|h| h.port == Some(report.port))
                        .cloned()
                        .collect()
                } else {
                    Vec::new()
                };
                if !users.is_empty() || !http.is_empty() {
                    widgets::section(ui, "Who is using it");
                    let paths: Vec<&str> = self
                        .rows
                        .iter()
                        .filter(|r| users.contains(&r.listener.key()))
                        .map(|r| r.proc.path.as_str())
                        .collect();
                    let paths: Vec<String> = paths.into_iter().map(String::from).collect();
                    let refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
                    self.ensure_icons(&ctx, &refs);
                    Frame::new()
                        .fill(p.card)
                        .stroke(Stroke::new(1.0_f32, p.border))
                        .corner_radius(CornerRadius::same(12))
                        .inner_margin(Margin::symmetric(6, 6))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.spacing_mut().item_spacing.y = 0.0;
                            let width = ui.available_width();
                            for key in &users {
                                let Some(row) = self.rows.iter().find(|r| r.listener.key() == *key)
                                else {
                                    continue;
                                };
                                let (rect, resp) =
                                    ui.allocate_exact_size(vec2(width, ROW_H), Sense::click());
                                widgets::row_background(
                                    ui,
                                    rect,
                                    false,
                                    resp.hovered(),
                                    widgets::RowTint::None,
                                );
                                let x = rect.left() + 14.0;
                                let icon = Rect::from_center_size(
                                    pos2(x + 14.0, rect.center().y),
                                    vec2(28.0, 28.0),
                                );
                                let name = row.proc.display_name();
                                widgets::program_icon(ui, icon, &name, self.icon(&row.proc.path));
                                let name_w = (width * 0.34).clamp(170.0, 330.0);
                                widgets::two_lines(
                                    ui,
                                    widgets::cell(rect, x + 40.0, name_w),
                                    (&name, semibold(14.0), p.text),
                                    (&super::listen_view::process_subline(row), p.muted),
                                );
                                let mut cx = x + 40.0 + name_w;
                                let (first, second) = super::listen_view::address_lines(row);
                                widgets::two_lines(
                                    ui,
                                    widgets::cell(rect, cx, 170.0),
                                    (&row.listener.endpoint(), regular(13.5), p.text),
                                    (
                                        if row.listener.scope() == crate::model::Scope::Specific {
                                            &second
                                        } else {
                                            &first
                                        },
                                        p.muted,
                                    ),
                                );
                                cx += 170.0;
                                let badge = widgets::cell(rect, cx, 190.0);
                                if badge.right() < rect.right() - 150.0 {
                                    widgets::paint_badge(
                                        ui,
                                        badge,
                                        &row.exposure.badge(),
                                        exposure_color(&row.exposure, &p),
                                    );
                                }
                                let link = Rect::from_min_max(
                                    pos2(rect.right() - 150.0, rect.top()),
                                    pos2(rect.right() - 14.0, rect.bottom()),
                                );
                                widgets::text_in_right(
                                    ui,
                                    link,
                                    &format!("Show details  {}", Icon::CHEVRON_RIGHT.glyph()),
                                    regular(13.0),
                                    if resp.hovered() { p.accent } else { p.muted },
                                );
                                if resp
                                    .on_hover_text("Open this socket in Listening ports")
                                    .clicked()
                                {
                                    show = Some(*key);
                                }
                            }
                            for h in &http {
                                let (rect, _) =
                                    ui.allocate_exact_size(vec2(width, ROW_H), Sense::hover());
                                let x = rect.left() + 14.0;
                                let icon = Rect::from_center_size(
                                    pos2(x + 14.0, rect.center().y),
                                    vec2(28.0, 28.0),
                                );
                                ui.painter().circle_filled(
                                    icon.center(),
                                    14.0,
                                    p.info.gamma_multiply(0.16),
                                );
                                ui.painter().text(
                                    icon.center(),
                                    Align2::CENTER_CENTER,
                                    Icon::GLOBE.glyph(),
                                    regular(14.0),
                                    p.info,
                                );
                                let who: Vec<String> = h
                                    .pids
                                    .iter()
                                    .map(|pid| format!("{} (PID {pid})", self.snap.proc_name(*pid)))
                                    .collect();
                                let first = if who.is_empty() {
                                    "HTTP.sys request queue".to_string()
                                } else {
                                    who.join(", ")
                                };
                                let mut second = format!("via HTTP.sys · {}", h.url);
                                if !h.queue.is_empty() {
                                    second.push_str(&format!(" · queue {}", h.queue));
                                }
                                widgets::two_lines(
                                    ui,
                                    widgets::cell(rect, x + 40.0, width - 68.0),
                                    (&first, semibold(14.0), p.text),
                                    (&second, p.muted),
                                );
                            }
                        });
                    ui.add_space(6.0);
                }

                // ---- Notes --------------------------------------------------------------
                if !report.notes.is_empty() {
                    widgets::section(ui, "What to know");
                    for note in &report.notes {
                        let (icon, color, title) = note_style(note, &p);
                        widgets::note_card(ui, icon, color, title, note);
                    }
                    ui.add_space(6.0);
                }

                // ---- Test bind ----------------------------------------------------------
                widgets::section(ui, "Try it");
                widgets::card(ui, |ui| {
                    ui.horizontal(|ui| {
                        if widgets::ghost_button(
                            ui,
                            &Icon::PLAY.with("Try a test bind on 127.0.0.1"),
                        )
                        .clicked()
                        {
                            do_bind = true;
                        }
                        ui.add_space(4.0);
                        match &self.lookup.bind {
                            Some((port, bproto, result))
                                if *port == report.port && *bproto == proto =>
                            {
                                let ok = *result == BindTest::Ok;
                                ui.label(
                                    RichText::new(if ok {
                                        Icon::DONE.glyph()
                                    } else {
                                        Icon::ERROR.glyph()
                                    })
                                    .color(if ok {
                                        p.accent
                                    } else {
                                        p.danger
                                    }),
                                );
                                ui.add(egui::Label::new(result.label()).wrap());
                            }
                            _ => {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(format!(
                                            "Binds {} port {} on the loopback address for an \
                                             instant and lets go. Nothing is accepted and nothing \
                                             leaves this PC.",
                                            proto.label(),
                                            report.port
                                        ))
                                        .color(p.muted),
                                    )
                                    .wrap(),
                                );
                            }
                        }
                    });
                });
                if report.is_bindable() {
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        if widgets::small_button(ui, &Icon::BELL.with("Watch this port")).clicked()
                        {
                            self.watch_port(report.port);
                        }
                        ui.label(
                            RichText::new("Get an alert when a program starts listening on it.")
                                .color(p.faint),
                        );
                    });
                }
                ui.add_space(8.0);
            });

        if do_bind && !self.demo_blocked() {
            self.lookup.bind = Some((report.port, proto, freeport::bind_test(report.port, proto)));
        }
        if let Some(key) = show {
            self.show_listener(key);
        }
    }

    // ----------------------------------------------------------------------------------
    // Find a free port
    // ----------------------------------------------------------------------------------

    fn finder_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let proto = self.lookup.finder_proto;
        let pc = PortContext::new(&self.snap, &self.sys);

        let from = parse_port(&self.lookup.from_text);
        let block_len = self
            .lookup
            .block_text
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|n| (1..=1000).contains(n));
        let next = from
            .as_ref()
            .ok()
            .and_then(|&f| freeport::next_free(f, proto, &pc));
        let block = match (&from, block_len) {
            (Ok(f), Some(len)) => freeport::next_free_block(*f, len, proto, &pc).map(|s| (s, len)),
            _ => None,
        };
        let range = match (
            parse_port(&self.lookup.range_from),
            parse_port(&self.lookup.range_to),
        ) {
            (Ok(a), Ok(b)) => Some((a.min(b), a.max(b))),
            _ => None,
        };
        let range_free: Vec<u16> = range
            .map(|(a, b)| freeport::free_in_range(a, b, proto, &pc, usize::MAX))
            .unwrap_or_default();
        let list = if self.lookup.list_text.trim().is_empty() {
            None
        } else {
            Some(freeport::parse_port_list(&self.lookup.list_text))
        };
        let reports: Vec<PortReport> = match &list {
            Some(Ok(ports)) => ports
                .iter()
                .take(LIST_ROWS)
                .map(|&port| freeport::check(port, proto, &pc))
                .collect(),
            _ => Vec::new(),
        };
        let details: Vec<String> = reports
            .iter()
            .map(|r| verdict_detail(r, &self.snap))
            .collect();

        let mut copy: Option<(String, &str)> = None;
        let mut check: Option<u16> = None;

        ui.horizontal(|ui| {
            ui.label(RichText::new("Protocol").color(p.muted));
            if let Some(i) = widgets::segmented(ui, &["TCP", "UDP"], proto_index(proto)) {
                self.lookup.finder_proto = proto_at(i);
            }
            ui.label(
                RichText::new(
                    "Free means: nobody listens, not in an excluded range, not served by HTTP.sys.",
                )
                .color(p.faint),
            );
        });
        ui.add_space(2.0);

        let result_box = |ui: &mut Ui, text: &str, ok: bool| {
            Frame::new()
                .fill(if ok {
                    p.accent.gamma_multiply(0.14)
                } else {
                    p.hover
                })
                .corner_radius(CornerRadius::same(8))
                .inner_margin(Margin::symmetric(12, 4))
                .show(ui, |ui| {
                    ui.label(RichText::new(text).font(semibold(17.0)).color(if ok {
                        p.accent
                    } else {
                        p.faint
                    }));
                });
        };

        ui.columns(2, |cols| {
            // ---- Next free / consecutive ------------------------------------------------
            widgets::card(&mut cols[0], |ui| {
                ui.set_min_height(132.0);
                widgets::section(ui, "Next free port");
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Starting at").color(p.muted));
                    widgets::text_box(ui, &mut self.lookup.from_text, 64.0, "3000");
                    ui.label(
                        RichText::new(Icon::CHEVRON_RIGHT.glyph())
                            .size(11.0)
                            .color(p.faint),
                    );
                    match next {
                        Some(port) => {
                            result_box(ui, &port.to_string(), true);
                            if widgets::small_button(ui, &Icon::COPY.with("Copy")).clicked() {
                                copy = Some((port.to_string(), "the port"));
                            }
                        }
                        None => result_box(ui, "none", false),
                    }
                });
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    widgets::text_box(ui, &mut self.lookup.block_text, 34.0, "3");
                    ui.label(RichText::new("ports in a row").color(p.muted));
                    ui.label(
                        RichText::new(Icon::CHEVRON_RIGHT.glyph())
                            .size(11.0)
                            .color(p.faint),
                    );
                    match block {
                        Some((start, len)) => {
                            let text = if len == 1 {
                                start.to_string()
                            } else {
                                format!("{}-{}", start, start as u32 + len as u32 - 1)
                            };
                            result_box(ui, &text, true);
                            if widgets::small_button(ui, &Icon::COPY.with("Copy")).clicked() {
                                copy = Some((text, "the range"));
                            }
                        }
                        None => result_box(
                            ui,
                            if block_len.is_none() {
                                "1 to 1000"
                            } else {
                                "none"
                            },
                            false,
                        ),
                    }
                });
            });

            // ---- Range ----------------------------------------------------------------
            widgets::card(&mut cols[1], |ui| {
                ui.set_min_height(132.0);
                widgets::section(ui, "Free ports in a range");
                ui.horizontal(|ui| {
                    widgets::text_box(ui, &mut self.lookup.range_from, 64.0, "8000");
                    ui.label(RichText::new("to").color(p.muted));
                    widgets::text_box(ui, &mut self.lookup.range_to, 64.0, "8100");
                    match range {
                        Some((a, b)) => {
                            let total = b as usize - a as usize + 1;
                            ui.label(
                                RichText::new(format!("{} of {} free", range_free.len(), total))
                                    .color(p.muted),
                            );
                        }
                        None => {
                            ui.label(RichText::new("Type two port numbers.").color(p.faint));
                        }
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if !range_free.is_empty()
                            && widgets::small_button(ui, &Icon::COPY.with("Copy all")).clicked()
                        {
                            copy = Some((copy_ports(&range_free), "the free ports"));
                        }
                    });
                });
                ui.add_space(2.0);
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = vec2(6.0, 6.0);
                    for port in range_free.iter().take(RANGE_CHIPS) {
                        if widgets::small_button(ui, &port.to_string())
                            .on_hover_text("Click to copy")
                            .clicked()
                        {
                            copy = Some((port.to_string(), "the port"));
                        }
                    }
                    if range_free.len() > RANGE_CHIPS {
                        ui.label(
                            RichText::new(format!("+{} more", range_free.len() - RANGE_CHIPS))
                                .color(p.faint),
                        );
                    }
                });
            });
        });
        ui.add_space(4.0);

        // ---- Check a list -----------------------------------------------------------------
        ui.horizontal(|ui| {
            widgets::section(ui, "Check a list");
            ui.add_space(6.0);
            let width = (ui.available_width() - 190.0).clamp(200.0, 520.0);
            widgets::text_box(
                ui,
                &mut self.lookup.list_text,
                width,
                "3000, 5432, 8000-8010",
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let free: Vec<u16> = reports
                    .iter()
                    .filter(|r| r.is_bindable())
                    .map(|r| r.port)
                    .collect();
                if !free.is_empty()
                    && widgets::ghost_button(ui, &Icon::COPY.with("Copy free ports")).clicked()
                {
                    copy = Some((copy_ports(&free), "the free ports"));
                }
            });
        });
        ui.add_space(2.0);
        match &list {
            None => {
                widgets::empty_state(
                    ui,
                    Icon::LIST,
                    p.info,
                    "Paste the ports your project needs",
                    "Separate them with commas or spaces; ranges such as 8000-8010 work too. \
                     Each port gets a verdict.",
                );
            }
            Some(Err(e)) => {
                widgets::empty_state(ui, Icon::WARNING, p.warn, "That list cannot be read", e);
            }
            Some(Ok(ports)) => {
                widgets::table_card(ui, |ui| {
                    let width = ui.available_width();
                    let header = widgets::table_header(ui);
                    let x0 = header.left() + 14.0;
                    let (w_port, w_verdict) = (90.0, 170.0);
                    let w_detail = (width - 14.0 - w_port - w_verdict - 150.0).max(120.0);
                    widgets::header_cell(
                        ui,
                        widgets::cell(header, x0, w_port),
                        "PORT",
                        None,
                        false,
                        false,
                    );
                    widgets::header_cell(
                        ui,
                        widgets::cell(header, x0 + w_port, w_verdict),
                        "VERDICT",
                        None,
                        false,
                        false,
                    );
                    widgets::header_cell(
                        ui,
                        widgets::cell(header, x0 + w_port + w_verdict, w_detail),
                        "WHO OR WHY",
                        None,
                        false,
                        false,
                    );
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show_rows(ui, ROW_H, reports.len(), |ui, range| {
                            for i in range {
                                let r = &reports[i];
                                let (rect, resp) =
                                    ui.allocate_exact_size(vec2(width, ROW_H), Sense::click());
                                widgets::row_background(
                                    ui,
                                    rect,
                                    false,
                                    resp.hovered(),
                                    widgets::RowTint::None,
                                );
                                let x = rect.left() + 14.0;
                                widgets::text_in(
                                    ui,
                                    widgets::cell(rect, x, w_port),
                                    &r.port.to_string(),
                                    semibold(15.0),
                                    p.text,
                                );
                                widgets::paint_badge(
                                    ui,
                                    widgets::cell(rect, x + w_port, w_verdict),
                                    verdict_label(r.verdict),
                                    verdict_color(r.verdict, &p),
                                );
                                widgets::text_in(
                                    ui,
                                    widgets::cell(rect, x + w_port + w_verdict, w_detail),
                                    &details[i],
                                    regular(13.5),
                                    p.muted,
                                );
                                let link = Rect::from_min_max(
                                    pos2(rect.right() - 140.0, rect.top()),
                                    pos2(rect.right() - 14.0, rect.bottom()),
                                );
                                widgets::text_in_right(
                                    ui,
                                    link,
                                    &format!("Check  {}", Icon::CHEVRON_RIGHT.glyph()),
                                    regular(13.0),
                                    if resp.hovered() { p.accent } else { p.muted },
                                );
                                if resp
                                    .on_hover_text("Open this port in Check a port")
                                    .clicked()
                                {
                                    check = Some(r.port);
                                }
                            }
                        });
                });
                if ports.len() > LIST_ROWS {
                    ui.label(
                        RichText::new(format!("Showing the first {LIST_ROWS} ports."))
                            .color(p.faint),
                    );
                }
            }
        }

        if let Some((text, what)) = copy {
            self.copy(&ctx, text, what);
        }
        if let Some(port) = check {
            self.lookup.set_port(port, proto);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo;

    #[test]
    fn port_input() {
        assert_eq!(parse_port("3000"), Ok(3000));
        assert_eq!(parse_port("  :8080 "), Ok(8080));
        assert_eq!(parse_port("localhost:5173"), Ok(5173));
        assert_eq!(parse_port("0"), Ok(0));
        assert_eq!(parse_port("65535"), Ok(65535));
        assert_eq!(parse_port(""), Err(String::new()));
        assert_eq!(parse_port("   "), Err(String::new()));
        assert!(parse_port("65536").unwrap_err().contains("65535"));
        assert!(parse_port("99999999999999").unwrap_err().contains("65535"));
        assert!(parse_port("http").unwrap_err().contains("not a port"));
        assert!(parse_port("-1").is_err());
        assert!(parse_port("30 00").is_err());
    }

    #[test]
    fn details_for_each_verdict() {
        let (snap, sys) = (demo::snapshot(), demo::system());
        let pc = PortContext::new(&snap, &sys);
        let detail = |port: u16| verdict_detail(&freeport::check(port, Proto::Tcp, &pc), &snap);
        assert_eq!(detail(3000), "node.exe (PID 7340)");
        assert!(detail(80).starts_with("System (PID 4)"));
        assert!(detail(80).ends_with("HTTP.sys"));
        assert!(detail(50010).contains("50000-50059"));
        assert!(detail(61000).contains("dynamic range"));
        assert!(detail(8088).contains("http://+:8088/api/"));
        assert_eq!(detail(3001), "Usually: Development web server");
        assert_eq!(detail(4711), "");
        assert!(detail(0).contains("any free port"));
    }

    #[test]
    fn every_note_gets_a_title() {
        let (snap, sys) = (demo::snapshot(), demo::system());
        let pc = PortContext::new(&snap, &sys);
        let p = crate::ui::theme::palette(true);
        let titles = |port: u16| -> Vec<&'static str> {
            freeport::check(port, Proto::Tcp, &pc)
                .notes
                .iter()
                .map(|n| note_style(n, &p).2)
                .collect()
        };
        assert_eq!(titles(50010), vec!["Excluded port range"]);
        let t80 = titles(80);
        assert!(t80.contains(&"Already bound"));
        assert!(t80.contains(&"Served by HTTP.sys"));
        assert!(t80.contains(&"HTTP.sys URL reservation"));
        assert_eq!(titles(61000), vec!["Dynamic port range"]);
        assert_eq!(titles(3001), vec!["Well-known port"]);
    }

    #[test]
    fn labels_and_copy() {
        assert_eq!(verdict_label(Verdict::InUse), "In use");
        assert_eq!(copy_ports(&[3001, 3002]), "3001, 3002");
        assert_eq!(proto_at(proto_index(Proto::Udp)), Proto::Udp);
        assert_eq!(proto_at(proto_index(Proto::Tcp)), Proto::Tcp);
    }
}
