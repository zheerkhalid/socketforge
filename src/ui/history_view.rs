//! Watch & history: the watch list with the current state of each port, the
//! alert switches and the log of listeners opening and closing.

use super::app::App;
use super::details::Dialog;
use super::lookup_view::parse_port;
use super::theme::{pal, regular, semibold, Icon};
use super::widgets::{self, ROW_H};
use crate::diff::{EventKind, HistoryEvent};
use crate::export;
use crate::model::Proto;
use crate::util::fmt_time;
use crate::view::ListenerRow;
use eframe::egui::{self, pos2, vec2, Align, Layout, Rect, RichText, Sense, Ui};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum HistFilter {
    #[default]
    All,
    Opened,
    Closed,
    Watched,
}

#[derive(Default)]
pub struct HistState {
    pub add_text: String,
    pub filter: HistFilter,
}

/// Does an event pass the chip filter and the search? A bare number matches
/// the port or the PID exactly.
pub(super) fn event_matches(e: &HistoryEvent, filter: HistFilter, search: &str) -> bool {
    let kind_ok = match filter {
        HistFilter::All => true,
        HistFilter::Opened => e.kind == EventKind::Opened,
        HistFilter::Closed => e.kind == EventKind::Closed,
        HistFilter::Watched => e.watched,
    };
    if !kind_ok {
        return false;
    }
    let needle = search.trim().to_lowercase();
    needle.split_whitespace().all(|word| {
        if let Ok(n) = word.trim_start_matches(':').parse::<u32>() {
            if e.port as u32 == n || e.pid == n {
                return true;
            }
        }
        e.process.to_lowercase().contains(word)
            || e.addr.contains(word)
            || e.proto.label().to_lowercase() == word
            || match e.kind {
                EventKind::Opened => "opened".contains(word),
                EventKind::Closed => "closed".contains(word),
            }
    })
}

/// `addr:port`, with brackets around IPv6 addresses.
pub(super) fn event_endpoint(e: &HistoryEvent) -> String {
    if e.addr.contains(':') {
        format!("[{}]:{}", e.addr, e.port)
    } else {
        format!("{}:{}", e.addr, e.port)
    }
}

/// Who holds a watched port right now: `node.exe (PID 7340) · TCP`, or None when it is free.
pub(super) fn watch_status(port: u16, rows: &[ListenerRow]) -> Option<String> {
    let mut who: Vec<String> = Vec::new();
    for r in rows.iter().filter(|r| r.listener.port == port) {
        let s = format!(
            "{} (PID {}) · {}",
            r.proc.display_name(),
            r.listener.pid,
            r.listener.proto.label()
        );
        if !who.contains(&s) {
            who.push(s);
        }
    }
    (!who.is_empty()).then(|| who.join(", "))
}

impl App {
    pub(super) fn history_count(&self) -> Option<usize> {
        let n = self.history.events.len();
        (n > 0).then_some(n)
    }

    fn add_watch_from_text(&mut self) {
        match parse_port(&self.hist.add_text) {
            Ok(0) => self.sh.toast("Port 0 cannot be watched.", true),
            Ok(port) => {
                self.watch_port(port);
                self.hist.add_text.clear();
            }
            Err(e) if e.is_empty() => {}
            Err(e) => self.sh.toast(e, true),
        }
    }

    pub(super) fn history_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let search = self.sh.search.clone();
        let filter = self.hist.filter;
        // Newest first.
        let searched: Vec<HistoryEvent> = self
            .history
            .events
            .iter()
            .rev()
            .filter(|e| event_matches(e, HistFilter::All, &search))
            .cloned()
            .collect();
        let visible: Vec<&HistoryEvent> = searched
            .iter()
            .filter(|e| event_matches(e, filter, ""))
            .collect();

        // ---- Title row --------------------------------------------------------------
        let watched = self.sh.settings.watched_ports.clone();
        let subtitle = format!(
            "{} watched port{} · {} event{} recorded",
            watched.len(),
            if watched.len() == 1 { "" } else { "s" },
            self.history.events.len(),
            if self.history.events.len() == 1 {
                ""
            } else {
                "s"
            },
        );
        let has_events = !self.history.events.is_empty();
        let mut do_export = false;
        let mut do_clear = false;
        widgets::page_header(ui, "Watch & history", &subtitle, |ui| {
            if widgets::ghost_button_enabled(ui, &Icon::DELETE.with("Clear"), has_events)
                .on_hover_text("Remove every recorded event")
                .clicked()
            {
                do_clear = true;
            }
            if widgets::ghost_button_enabled(ui, &Icon::EXPORT.with("Export"), has_events)
                .on_hover_text("Save the events shown as CSV, JSON or HTML")
                .clicked()
            {
                do_export = true;
            }
        });
        if do_clear {
            self.dialog = Dialog::ClearHistory;
        }
        if do_export {
            let events: Vec<HistoryEvent> = visible.iter().map(|e| (*e).clone()).collect();
            self.export_with("socketforge-history", move |format| {
                export::history(&events, format)
            });
        }

        // ---- Watch list and alerts ------------------------------------------------------
        const TOP_H: f32 = 178.0;
        let mut remove: Option<u16> = None;
        let mut check: Option<u16> = None;
        let mut add = false;
        ui.columns(2, |cols| {
            widgets::card(&mut cols[0], |ui| {
                ui.set_height(TOP_H);
                ui.horizontal(|ui| {
                    widgets::section(ui, "Watched ports");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if widgets::small_button(ui, &Icon::ADD.with("Watch")).clicked() {
                            add = true;
                        }
                        let resp = widgets::text_box(ui, &mut self.hist.add_text, 70.0, "Port");
                        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            add = true;
                        }
                    });
                });
                if watched.is_empty() {
                    ui.add_space(10.0);
                    ui.add(
                        egui::Label::new(
                            RichText::new(
                                "No port is watched yet. Add the ports your projects need \
                                 (3000, 5432, 8080...) and SocketForge tells you when another \
                                 program takes one.",
                            )
                            .color(p.muted),
                        )
                        .wrap(),
                    );
                    return;
                }
                ui.spacing_mut().item_spacing.y = 0.0;
                egui::ScrollArea::vertical()
                    .id_salt("watched")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let width = ui.available_width();
                        for &port in &watched {
                            let (rect, resp) =
                                ui.allocate_exact_size(vec2(width, 30.0), Sense::click());
                            if resp.hovered() {
                                ui.painter().rect_filled(rect, 6, p.hover);
                            }
                            let status = watch_status(port, &self.rows);
                            widgets::text_in(
                                ui,
                                Rect::from_min_max(
                                    rect.min + vec2(8.0, 0.0),
                                    pos2(rect.left() + 64.0, rect.bottom()),
                                ),
                                &port.to_string(),
                                semibold(14.5),
                                p.text,
                            );
                            let (label, color) = match &status {
                                Some(_) => ("In use", p.warn),
                                None => ("Free", p.accent),
                            };
                            let used = widgets::paint_badge(
                                ui,
                                Rect::from_min_max(
                                    pos2(rect.left() + 64.0, rect.top()),
                                    pos2(rect.left() + 130.0, rect.bottom()),
                                ),
                                label,
                                color,
                            );
                            widgets::text_in(
                                ui,
                                Rect::from_min_max(
                                    pos2(rect.left() + 64.0 + used + 10.0, rect.top()),
                                    pos2(rect.right() - 34.0, rect.bottom()),
                                ),
                                status.as_deref().unwrap_or("Nothing is listening on it"),
                                regular(13.0),
                                p.muted,
                            );
                            let x_rect = Rect::from_center_size(
                                pos2(rect.right() - 16.0, rect.center().y),
                                vec2(24.0, 24.0),
                            );
                            let x_resp = ui
                                .interact(x_rect, ui.id().with(("unwatch", port)), Sense::click())
                                .on_hover_text("Stop watching this port");
                            ui.painter().text(
                                x_rect.center(),
                                egui::Align2::CENTER_CENTER,
                                Icon::CLOSE.glyph(),
                                regular(11.0),
                                if x_resp.hovered() { p.danger } else { p.faint },
                            );
                            if x_resp.clicked() {
                                remove = Some(port);
                            } else if resp.on_hover_text("Open in Port check").clicked() {
                                check = Some(port);
                            }
                        }
                    });
            });
            widgets::card(&mut cols[1], |ui| {
                ui.set_height(TOP_H);
                widgets::section(ui, "Alerts and recording");
                ui.add_space(2.0);
                let s = &mut self.sh.settings;
                let mut changed = false;
                let rows: [(&str, &str, &mut bool); 3] = [
                    (
                        "A watched port is taken",
                        "Tells you which program started listening on it.",
                        &mut s.alert_watched,
                    ),
                    (
                        "Any new TCP listener",
                        "Every program that starts listening. Can be noisy.",
                        &mut s.alert_new_listeners,
                    ),
                    (
                        "Record the history",
                        "Keeps the log below, also between sessions.",
                        &mut s.record_history,
                    ),
                ];
                for (title, text, value) in rows {
                    widgets::setting_row(ui, title, text, |ui| {
                        if widgets::toggle(ui, *value, true).clicked() {
                            *value = !*value;
                            changed = true;
                        }
                    });
                }
                if changed {
                    self.sh.touch_settings();
                }
            });
        });
        if add {
            self.add_watch_from_text();
        }
        if let Some(port) = remove {
            self.sh.settings.watched_ports.retain(|x| *x != port);
            self.sh.touch_settings();
        }
        if let Some(port) = check {
            self.open_port_check(port, Proto::Tcp);
            return;
        }
        ui.add_space(4.0);

        // ---- Filter chips -----------------------------------------------------------
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            let chips = [
                (HistFilter::All, "All", "Every recorded event"),
                (HistFilter::Opened, "Opened", "A program started listening"),
                (HistFilter::Closed, "Closed", "A listener went away"),
                (
                    HistFilter::Watched,
                    "Watched only",
                    "Events on watched ports",
                ),
            ];
            for (f, label, hint) in chips {
                let n = searched.iter().filter(|e| event_matches(e, f, "")).count();
                if widgets::chip(ui, label, Some(n), filter == f)
                    .on_hover_text(hint)
                    .clicked()
                {
                    self.hist.filter = f;
                }
            }
            if !self.sh.settings.record_history {
                ui.add_space(6.0);
                widgets::badge(ui, "Recording is off", p.warn);
            }
        });
        ui.add_space(2.0);

        // ---- Log --------------------------------------------------------------------
        if visible.is_empty() {
            if !has_events {
                widgets::empty_state(
                    ui,
                    Icon::HISTORY,
                    p.info,
                    "Nothing recorded yet",
                    "While SocketForge runs it notes every listener that opens or closes. \
                     Start a server and it shows up here.",
                );
            } else if !search.trim().is_empty() && searched.is_empty() {
                let text = format!("No event matches \"{}\".", search.trim());
                widgets::empty_state(ui, Icon::SEARCH, p.muted, "No matches", &text);
            } else {
                widgets::empty_state(
                    ui,
                    Icon::FILTER,
                    p.muted,
                    "No such events",
                    "Nothing of this kind has been recorded.",
                );
            }
            return;
        }
        widgets::table_card(ui, |ui| {
            let width = ui.available_width();
            let header = widgets::table_header(ui);
            let (w_time, w_kind, w_proto, w_pid) = (176.0, 104.0, 64.0, 90.0);
            let w_end = ((width - 14.0 - w_time - w_kind - w_proto - w_pid) * 0.42).max(150.0);
            let w_proc = (width - 14.0 - w_time - w_kind - w_proto - w_pid - w_end).max(100.0);
            let mut x = header.left() + 14.0;
            for (label, w) in [
                ("TIME", w_time),
                ("EVENT", w_kind),
                ("PROTO", w_proto),
                ("ADDRESS : PORT", w_end),
                ("PROCESS", w_proc),
                ("PID", w_pid),
            ] {
                widgets::header_cell(ui, widgets::cell(header, x, w), label, None, false, false);
                x += w;
            }
            egui::ScrollArea::vertical()
                .id_salt("history")
                .auto_shrink([false, false])
                .show_rows(ui, ROW_H, visible.len(), |ui, range| {
                    for e in &visible[range] {
                        let (rect, resp) =
                            ui.allocate_exact_size(vec2(width, ROW_H), Sense::hover());
                        widgets::row_background(
                            ui,
                            rect,
                            false,
                            resp.hovered(),
                            widgets::RowTint::None,
                        );
                        let mut x = rect.left() + 14.0;
                        widgets::text_in(
                            ui,
                            widgets::cell(rect, x, w_time),
                            &fmt_time(e.time),
                            regular(13.5),
                            p.muted,
                        );
                        x += w_time;
                        let (label, color) = match e.kind {
                            EventKind::Opened => ("Opened", p.accent),
                            EventKind::Closed => ("Closed", p.danger),
                        };
                        widgets::paint_badge(ui, widgets::cell(rect, x, w_kind), label, color);
                        x += w_kind;
                        widgets::paint_badge(
                            ui,
                            widgets::cell(rect, x, w_proto),
                            e.proto.label(),
                            match e.proto {
                                Proto::Tcp => p.info,
                                Proto::Udp => p.udp,
                            },
                        );
                        x += w_proto;
                        let end_rect = widgets::cell(rect, x, w_end);
                        let galley = widgets::elided(
                            ui,
                            &event_endpoint(e),
                            semibold(14.0),
                            p.text,
                            end_rect.width() - 80.0,
                        );
                        let end_w = galley.size().x;
                        ui.painter().galley(
                            pos2(end_rect.left(), rect.center().y - galley.size().y / 2.0),
                            galley,
                            p.text,
                        );
                        if e.watched {
                            widgets::paint_badge(
                                ui,
                                Rect::from_min_max(
                                    pos2(end_rect.left() + end_w + 10.0, rect.top()),
                                    end_rect.max,
                                ),
                                "Watched",
                                p.warn,
                            );
                        }
                        x += w_end;
                        widgets::text_in(
                            ui,
                            widgets::cell(rect, x, w_proc),
                            &e.process,
                            regular(13.5),
                            p.text,
                        );
                        x += w_proc;
                        widgets::text_in(
                            ui,
                            widgets::cell(rect, x, w_pid),
                            &e.pid.to_string(),
                            regular(13.5),
                            p.muted,
                        );
                    }
                });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo;
    use crate::view;

    #[test]
    fn filters_and_search() {
        let events = demo::history();
        let n = |f, s: &str| events.iter().filter(|e| event_matches(e, f, s)).count();
        assert_eq!(n(HistFilter::All, ""), events.len());
        assert_eq!(
            n(HistFilter::Opened, "") + n(HistFilter::Closed, ""),
            events.len()
        );
        assert!(n(HistFilter::Watched, "") > 0 && n(HistFilter::Watched, "") < events.len());
        // A number is an exact port or PID, never a substring of another port.
        assert_eq!(n(HistFilter::All, "3000"), 2);
        assert_eq!(n(HistFilter::All, "300"), 0);
        assert_eq!(n(HistFilter::All, "7340"), 2);
        assert_eq!(n(HistFilter::All, "sshd"), 1);
        assert_eq!(n(HistFilter::Closed, "node"), 2);
        assert_eq!(n(HistFilter::All, "udp"), 3);
        assert!(n(HistFilter::All, "127.0.0.1 opened") > 0);
        assert_eq!(n(HistFilter::All, "no-such-thing"), 0);
    }

    #[test]
    fn endpoints() {
        let mut e = demo::history().remove(0);
        e.addr = "0.0.0.0".into();
        e.port = 80;
        assert_eq!(event_endpoint(&e), "0.0.0.0:80");
        e.addr = "::1".into();
        assert_eq!(event_endpoint(&e), "[::1]:80");
    }

    #[test]
    fn watched_port_status() {
        let rows = view::listener_rows(&demo::snapshot(), &demo::system());
        assert_eq!(
            watch_status(3000, &rows).as_deref(),
            Some("node.exe (PID 7340) · TCP")
        );
        // Bound on IPv4 and IPv6 by the same process: listed once.
        assert_eq!(
            watch_status(5432, &rows).as_deref(),
            Some("postgres.exe (PID 4188) · TCP")
        );
        assert_eq!(watch_status(443, &rows), None);
        assert!(watch_status(3389, &rows).unwrap().contains("UDP"));
    }
}
