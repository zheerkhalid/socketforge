//! Connections: active TCP connections with their processes, optional
//! reverse-DNS names, filters and the same change highlighting as the
//! Listening view.

use super::app::{cmp_text, App};
use super::listen_view::tint_of;
use super::theme::{pal, regular, semibold, Icon, Palette};
use super::widgets::{self, RowTint, ROW_H};
use crate::export;
use crate::model::TcpState;
use crate::util::{fmt_age, fmt_clock};
use crate::view::{self, ConnectionRow};
use eframe::egui::{self, pos2, vec2, Align, Color32, Layout, Rect, RichText, Sense, Ui};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnSort {
    Process,
    Local,
    Remote,
    State,
    Service,
    Age,
}

pub struct ConnState {
    pub established_only: bool,
    pub hide_loopback: bool,
    pub system: bool,
    pub user: bool,
    pub sort: (ConnSort, bool),
}

impl Default for ConnState {
    fn default() -> Self {
        ConnState {
            established_only: false,
            hide_loopback: false,
            system: true,
            user: true,
            sort: (ConnSort::Process, true),
        }
    }
}

impl ConnState {
    /// Do the filter chips let this row through? (The search is separate.)
    pub(super) fn matches(&self, row: &ConnectionRow) -> bool {
        (!self.established_only || row.conn.state == TcpState::Established)
            && (!self.hide_loopback || !row.conn.remote.ip().is_loopback())
            && if row.is_system {
                self.system
            } else {
                self.user
            }
    }
}

#[derive(Debug)]
pub(super) struct Columns {
    pub process: f32,
    pub local: f32,
    pub remote: f32,
    pub state: f32,
    pub service: f32,
    pub age: f32,
}

const LEFT_PAD: f32 = 14.0;

impl Columns {
    pub fn for_width(width: f32) -> Columns {
        let mut c = Columns {
            process: 0.0,
            local: 176.0,
            remote: 236.0,
            state: 118.0,
            service: 164.0,
            age: 72.0,
        };
        let mut rest = width - LEFT_PAD - c.local - c.remote - c.state - c.service - c.age;
        if rest < 190.0 {
            rest += c.service;
            c.service = 0.0;
        }
        if rest < 170.0 {
            rest += c.age;
            c.age = 0.0;
        }
        if rest < 130.0 {
            // Very narrow: take the missing room from the remote column.
            let take = (130.0 - rest).min(c.remote - 150.0);
            c.remote -= take;
            rest += take;
        }
        c.process = rest.max(130.0);
        c
    }

    #[cfg(test)]
    pub fn total(&self) -> f32 {
        LEFT_PAD + self.process + self.local + self.remote + self.state + self.service + self.age
    }
}

pub(super) fn compare(a: &ConnectionRow, b: &ConnectionRow, col: ConnSort) -> Ordering {
    let base = || {
        (a.conn.local.port(), a.conn.remote, a.conn.pid).cmp(&(
            b.conn.local.port(),
            b.conn.remote,
            b.conn.pid,
        ))
    };
    let ord = match col {
        ConnSort::Process => cmp_text(&a.proc_name, &b.proc_name).then(a.conn.pid.cmp(&b.conn.pid)),
        ConnSort::Local => a.conn.local.cmp(&b.conn.local),
        ConnSort::Remote => a.conn.remote.cmp(&b.conn.remote),
        ConnSort::State => a.conn.state.label().cmp(b.conn.state.label()),
        ConnSort::Service => match (a.well_known, b.well_known) {
            (Some(x), Some(y)) => cmp_text(x, y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        },
        ConnSort::Age => match (a.conn.created, b.conn.created) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        },
    };
    ord.then_with(base)
}

fn state_color(state: TcpState, p: &Palette) -> Color32 {
    match state {
        TcpState::Established => p.accent,
        TcpState::SynSent | TcpState::SynReceived | TcpState::Listen => p.info,
        TcpState::TimeWait | TcpState::Closed | TcpState::DeleteTcb | TcpState::Unknown => p.muted,
        _ => p.warn,
    }
}

impl App {
    pub(super) fn connection_count(&self) -> Option<usize> {
        self.snap_loaded.then_some(self.conn_rows.len())
    }

    pub(super) fn conn_apply_view(&mut self, _view: &str) {
        if self.sh.demo {
            // Show what the optional host names look like (invented names).
            self.sh.settings.reverse_dns = true;
        }
    }

    pub(super) fn connections_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let now = self.clock();
        let wall = self.wall_now();
        let resolve = self.sh.settings.reverse_dns;

        let all: Vec<(ConnectionRow, RowTint)> = self
            .ctrack
            .rows(now)
            .into_iter()
            .map(|(_, row, state)| (row.clone(), tint_of(state)))
            .collect();
        if resolve {
            let ips: Vec<IpAddr> = all
                .iter()
                .map(|(r, _)| r.conn.remote.ip())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            self.resolve_names(&ctx, &ips);
        }
        let no_names = HashMap::new();
        let names: &HashMap<IpAddr, String> = if resolve { &self.host_names } else { &no_names };
        let search = self.sh.search.clone();
        let searched: Vec<&(ConnectionRow, RowTint)> = all
            .iter()
            .filter(|(r, _)| {
                let host = names.get(&r.conn.remote.ip()).map(|s| s.as_str());
                view::connection_matches(r, host, &search)
            })
            .collect();
        let mut visible: Vec<(ConnectionRow, RowTint)> = searched
            .iter()
            .filter(|(r, _)| self.conn.matches(r))
            .map(|x| (*x).clone())
            .collect();
        let sort = self.conn.sort;
        visible.sort_by(|a, b| {
            let ord = compare(&a.0, &b.0, sort.0);
            if sort.1 {
                ord
            } else {
                ord.reverse()
            }
        });
        let names: HashMap<IpAddr, String> = names.clone();

        // ---- Title row --------------------------------------------------------------
        let subtitle = if !self.snap_loaded {
            "Reading the TCP table…".to_string()
        } else {
            let established = self
                .conn_rows
                .iter()
                .filter(|r| r.conn.state == TcpState::Established)
                .count();
            let remotes: HashSet<IpAddr> = self
                .conn_rows
                .iter()
                .map(|r| r.conn.remote.ip())
                .filter(|ip| !ip.is_loopback())
                .collect();
            let mut s = format!(
                "{} TCP connections · {} established · {} remote addresses",
                self.conn_rows.len(),
                established,
                remotes.len()
            );
            if self.snap.taken > 0 {
                s.push_str(&format!(" · updated {}", fmt_clock(self.snap.taken)));
            }
            s
        };
        let live = self.sh.settings.live;
        let mut do_export = false;
        let mut toggle_live = false;
        widgets::page_header(ui, "Connections", &subtitle, |ui| {
            if widgets::ghost_button(ui, &Icon::EXPORT.with("Export"))
                .on_hover_text("Save the rows shown as CSV, JSON or HTML")
                .clicked()
            {
                do_export = true;
            }
            let label = if live {
                Icon::STOP.with("Pause")
            } else {
                Icon::PLAY.with("Resume")
            };
            if widgets::ghost_button(ui, &label)
                .on_hover_text(if live {
                    "Stop refreshing automatically"
                } else {
                    "Refresh automatically again"
                })
                .clicked()
            {
                toggle_live = true;
            }
            if !live {
                widgets::badge(ui, "Paused", p.warn);
            }
        });
        if toggle_live {
            self.sh.settings.live = !live;
            self.sh.touch_settings();
        }
        if do_export {
            let rows: Vec<ConnectionRow> = visible.iter().map(|(r, _)| r.clone()).collect();
            let export_names = names.clone();
            self.export_with("socketforge-connections", move |format| {
                export::connections(
                    &rows,
                    (!export_names.is_empty()).then_some(&export_names),
                    format,
                )
            });
        }

        // ---- Filter chips -----------------------------------------------------------
        let count =
            |f: &dyn Fn(&ConnectionRow) -> bool| searched.iter().filter(|(r, _)| f(r)).count();
        let mut toggle_dns = false;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            let c = &mut self.conn;
            let chips: [(&str, usize, &mut bool, &str); 4] = [
                (
                    "Established only",
                    count(&|r| r.conn.state == TcpState::Established),
                    &mut c.established_only,
                    "Hide connections that are being opened or closed",
                ),
                (
                    "Hide loopback",
                    count(&|r| !r.conn.remote.ip().is_loopback()),
                    &mut c.hide_loopback,
                    "Hide connections between programs on this PC",
                ),
                (
                    "System",
                    count(&|r| r.is_system),
                    &mut c.system,
                    "Windows' own processes and services",
                ),
                (
                    "User",
                    count(&|r| !r.is_system),
                    &mut c.user,
                    "Everything that is not part of Windows",
                ),
            ];
            for (i, (label, n, on, hint)) in chips.into_iter().enumerate() {
                if i == 2 {
                    ui.add_space(6.0);
                }
                if widgets::chip(ui, label, Some(n), *on)
                    .on_hover_text(hint)
                    .clicked()
                {
                    *on = !*on;
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let hint = "Looks up the names of remote addresses. This sends reverse DNS \
                            queries for them to your DNS server. Off by default.";
                if widgets::toggle(ui, resolve, true)
                    .on_hover_text(hint)
                    .clicked()
                {
                    toggle_dns = true;
                }
                ui.label(RichText::new("Host names (sends DNS queries)").color(p.muted))
                    .on_hover_text(hint);
            });
        });
        if toggle_dns {
            self.sh.settings.reverse_dns = !resolve;
            self.sh.touch_settings();
        }
        ui.add_space(2.0);

        // ---- States -----------------------------------------------------------------
        if visible.is_empty() {
            if !self.snap_loaded {
                widgets::busy_state(
                    ui,
                    "Reading connections",
                    "Asking Windows for its TCP table.",
                );
            } else if all.is_empty() {
                widgets::empty_state(
                    ui,
                    Icon::SWITCH,
                    p.muted,
                    "No active connections",
                    "No program on this PC has a TCP connection open right now.",
                );
            } else if !search.trim().is_empty() && searched.is_empty() {
                let text = format!(
                    "Nothing matches \"{}\". Try an address, a port number or a program name.",
                    search.trim()
                );
                widgets::empty_state(ui, Icon::SEARCH, p.muted, "No matches", &text);
                ui.vertical_centered(|ui| {
                    if widgets::ghost_button(ui, "Clear search").clicked() {
                        self.sh.search.clear();
                    }
                });
            } else {
                widgets::empty_state(
                    ui,
                    Icon::FILTER,
                    p.muted,
                    "Everything is filtered out",
                    "The filter chips above hide every connection.",
                );
                ui.vertical_centered(|ui| {
                    if widgets::ghost_button(ui, "Reset filters").clicked() {
                        let sort = self.conn.sort;
                        self.conn = ConnState {
                            sort,
                            ..Default::default()
                        };
                    }
                });
            }
            return;
        }

        let paths: Vec<&str> = visible.iter().map(|(r, _)| r.proc_path.as_str()).collect();
        self.ensure_icons(&ctx, &paths);

        // ---- Table ------------------------------------------------------------------
        widgets::table_card(ui, |ui| {
            let width = ui.available_width();
            let cols = Columns::for_width(width);
            let header = widgets::table_header(ui);
            let mut x = header.left() + LEFT_PAD;
            let mut sort = self.conn.sort;
            let titles: [(&str, ConnSort, f32); 6] = [
                ("PROCESS", ConnSort::Process, cols.process),
                ("LOCAL", ConnSort::Local, cols.local),
                ("REMOTE", ConnSort::Remote, cols.remote),
                ("STATE", ConnSort::State, cols.state),
                ("SERVICE", ConnSort::Service, cols.service),
                ("AGE", ConnSort::Age, cols.age),
            ];
            for (label, col, w) in titles {
                if w <= 0.0 {
                    continue;
                }
                let active = (sort.0 == col).then_some(sort.1);
                if widgets::header_cell(ui, widgets::cell(header, x, w), label, active, true, false)
                {
                    sort = if sort.0 == col {
                        (col, !sort.1)
                    } else {
                        (col, col != ConnSort::Age)
                    };
                }
                x += w;
            }
            self.conn.sort = sort;

            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show_rows(ui, ROW_H, visible.len(), |ui, range| {
                    for (row, tint) in &visible[range] {
                        let (rect, resp) =
                            ui.allocate_exact_size(vec2(width, ROW_H), Sense::hover());
                        widgets::row_background(ui, rect, false, resp.hovered(), *tint);
                        let closed = matches!(tint, RowTint::Closed(_));
                        let (text, muted) = if closed {
                            (p.muted, p.faint)
                        } else {
                            (p.text, p.muted)
                        };
                        let mut x = rect.left() + LEFT_PAD;

                        let icon = Rect::from_center_size(
                            pos2(x + 14.0, rect.center().y),
                            vec2(28.0, 28.0),
                        );
                        widgets::program_icon(ui, icon, &row.proc_name, self.icon(&row.proc_path));
                        let mut sub = format!("PID {}", row.conn.pid);
                        if closed {
                            sub.push_str(" · closed");
                        } else if matches!(tint, RowTint::New(_)) {
                            sub.push_str(" · new");
                        }
                        widgets::two_lines(
                            ui,
                            widgets::cell(rect, x + 40.0, cols.process - 40.0),
                            (&row.proc_name, semibold(14.0), text),
                            (&sub, muted),
                        );
                        x += cols.process;

                        widgets::text_in(
                            ui,
                            widgets::cell(rect, x, cols.local),
                            &row.conn.local.to_string(),
                            regular(13.5),
                            muted,
                        );
                        x += cols.local;

                        let host = names
                            .get(&row.conn.remote.ip())
                            .map(|s| s.as_str())
                            .unwrap_or("");
                        widgets::two_lines(
                            ui,
                            widgets::cell(rect, x, cols.remote),
                            (&row.conn.remote.to_string(), regular(13.5), text),
                            (host, muted),
                        );
                        x += cols.remote;

                        let color = if closed {
                            p.faint
                        } else {
                            state_color(row.conn.state, &p)
                        };
                        widgets::paint_badge(
                            ui,
                            widgets::cell(rect, x, cols.state),
                            row.conn.state.label(),
                            color,
                        );
                        x += cols.state;

                        if cols.service > 0.0 {
                            widgets::text_in(
                                ui,
                                widgets::cell(rect, x, cols.service),
                                row.well_known.unwrap_or(""),
                                regular(13.0),
                                muted,
                            );
                            x += cols.service;
                        }
                        if cols.age > 0.0 {
                            let age = match row.conn.created {
                                Some(t) => fmt_age(wall - t),
                                None => "—".to_string(),
                            };
                            widgets::text_in(
                                ui,
                                widgets::cell(rect, x, cols.age),
                                &age,
                                regular(13.0),
                                muted,
                            );
                        }
                    }
                });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo;

    fn rows() -> Vec<ConnectionRow> {
        view::connection_rows(&demo::snapshot())
    }

    #[test]
    fn columns_always_fit() {
        for width in [620.0_f32, 700.0, 860.0, 1012.0, 1600.0] {
            let c = Columns::for_width(width);
            assert!(c.total() <= width + 0.5, "{width}: {c:?}");
            assert!(c.process >= 130.0);
        }
        assert!(Columns::for_width(1012.0).service > 0.0);
    }

    #[test]
    fn filters() {
        let rows = rows();
        let n = |s: &ConnState| rows.iter().filter(|r| s.matches(r)).count();
        let all = ConnState::default();
        assert_eq!(n(&all), rows.len());
        let est = ConnState {
            established_only: true,
            ..Default::default()
        };
        assert!(n(&est) < rows.len() && n(&est) > 0);
        let remote = ConnState {
            hide_loopback: true,
            ..Default::default()
        };
        assert!(rows.iter().filter(|r| remote.matches(r)).all(|r| !r
            .conn
            .remote
            .ip()
            .is_loopback()));
        let user = ConnState {
            system: false,
            ..Default::default()
        };
        let system = ConnState {
            user: false,
            ..Default::default()
        };
        assert_eq!(n(&user) + n(&system), rows.len());
        assert!(n(&system) > 0);
    }

    #[test]
    fn sorting() {
        let mut rows = rows();
        rows.sort_by(|a, b| compare(a, b, ConnSort::Remote));
        assert!(rows
            .windows(2)
            .all(|w| w[0].conn.remote <= w[1].conn.remote));
        rows.sort_by(|a, b| compare(a, b, ConnSort::Process));
        assert!(rows
            .windows(2)
            .all(|w| w[0].proc_name.to_lowercase() <= w[1].proc_name.to_lowercase()));
        rows.sort_by(|a, b| compare(a, b, ConnSort::Age).reverse());
        assert_eq!(rows[0].conn.created, Some(demo::NOW - 1), "newest first");
    }
}
