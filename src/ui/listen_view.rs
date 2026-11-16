//! Listening ports: the sortable, groupable table of everything that is
//! bound to a port, with change highlighting. The details panel for the
//! selected row lives in `details.rs`.

use super::app::{cmp_text, App};
use super::details::exposure_color;
use super::theme::{pal, regular, semibold, Icon};
use super::widgets::{self, RowTint, ROW_H};
use crate::diff::RowState;
use crate::export;
use crate::exposure::Exposure;
use crate::model::{ListenerKey, Proto, Scope};
use crate::settings::GroupBy;
use crate::util::{fmt_age, fmt_clock};
use crate::view::{self, ListenerFilter, ListenerRow};
use eframe::egui::{self, pos2, vec2, Align, Layout, Rect, Sense, Ui};
use std::cmp::Ordering;
use std::collections::HashSet;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SortCol {
    Port,
    Proto,
    Address,
    Process,
    Service,
    Exposure,
    Since,
}

pub struct ListenState {
    pub filter: ListenerFilter,
    pub sort: (SortCol, bool),
    pub selected: Option<ListenerKey>,
    /// Group headers that are folded (see [`group_key`]).
    pub collapsed: HashSet<String>,
    /// Bring the selected row into view on the next frame.
    pub scroll_to_selected: bool,
}

impl Default for ListenState {
    fn default() -> Self {
        ListenState {
            filter: ListenerFilter::default(),
            sort: (SortCol::Port, true),
            selected: None,
            collapsed: HashSet::new(),
            scroll_to_selected: false,
        }
    }
}

/// Column widths for a table of the given inner width. Columns that do not
/// fit are dropped (width 0); the process column takes what is left.
#[derive(Debug, PartialEq)]
pub(super) struct Columns {
    pub port: f32,
    pub proto: f32,
    pub address: f32,
    pub process: f32,
    pub service: f32,
    pub exposure: f32,
    pub since: f32,
}

pub(super) const LEFT_PAD: f32 = 14.0;

impl Columns {
    pub fn for_width(width: f32) -> Columns {
        let mut c = Columns {
            port: 68.0,
            proto: 58.0,
            address: 150.0,
            process: 0.0,
            service: 200.0,
            exposure: 172.0,
            since: 84.0,
        };
        let mut rest =
            width - LEFT_PAD - c.port - c.proto - c.address - c.service - c.exposure - c.since;
        if rest < 210.0 {
            rest += c.service;
            c.service = 0.0;
        }
        if rest < 200.0 {
            rest += c.since;
            c.since = 0.0;
        }
        if rest < 170.0 {
            rest += c.address - 112.0;
            c.address = 112.0;
        }
        c.process = rest.max(130.0);
        c
    }

    #[cfg(test)]
    pub fn total(&self) -> f32 {
        LEFT_PAD
            + self.port
            + self.proto
            + self.address
            + self.process
            + self.service
            + self.exposure
            + self.since
    }
}

/// Lower = more exposed, so that an ascending sort puts open ports first.
fn exposure_rank(row: &ListenerRow) -> u8 {
    match row.exposure.exposure {
        Exposure::Allowed(_) if row.exposure.reachable_now => 0,
        Exposure::Allowed(_) => 1,
        Exposure::Network => 2,
        Exposure::Blocked => 3,
        Exposure::LoopbackOnly => 4,
    }
}

/// Orders two rows by a column; ties fall back to port, protocol, address.
pub(super) fn compare(a: &ListenerRow, b: &ListenerRow, col: SortCol) -> Ordering {
    let base = || {
        (
            a.listener.port,
            a.listener.proto,
            a.listener.addr,
            a.listener.pid,
        )
            .cmp(&(
                b.listener.port,
                b.listener.proto,
                b.listener.addr,
                b.listener.pid,
            ))
    };
    let ord = match col {
        SortCol::Port => Ordering::Equal,
        SortCol::Proto => a.listener.proto.cmp(&b.listener.proto),
        SortCol::Address => a.listener.addr.cmp(&b.listener.addr),
        SortCol::Process => cmp_text(&a.proc.display_name(), &b.proc.display_name())
            .then(a.listener.pid.cmp(&b.listener.pid)),
        SortCol::Service => {
            // Rows without a well-known name go last.
            match (a.well_known, b.well_known) {
                (Some(x), Some(y)) => cmp_text(x, y),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            }
        }
        SortCol::Exposure => exposure_rank(a).cmp(&exposure_rank(b)),
        // Ascending = oldest first; unknown times last.
        SortCol::Since => match (a.listener.created, b.listener.created) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        },
    };
    ord.then_with(base)
}

pub(super) fn sort_rows<T>(rows: &mut [(ListenerRow, T)], sort: (SortCol, bool)) {
    rows.sort_by(|a, b| {
        let ord = compare(&a.0, &b.0, sort.0);
        if sort.1 {
            ord
        } else {
            ord.reverse()
        }
    });
}

/// The two lines of the address column.
pub(super) fn address_lines(row: &ListenerRow) -> (String, String) {
    let addr = row.listener.addr.to_string();
    match row.listener.scope() {
        Scope::AllInterfaces => ("All interfaces".to_string(), addr),
        Scope::Loopback => ("Loopback only".to_string(), addr),
        Scope::Specific => (addr, "This address only".to_string()),
    }
}

/// The small line under the process name: PID and hosted services.
pub(super) fn process_subline(row: &ListenerRow) -> String {
    let services = row.services_label();
    if services.is_empty() {
        format!("PID {}", row.listener.pid)
    } else {
        format!("PID {} · {}", row.listener.pid, services)
    }
}

/// How to reach a port from this PC: the URL for web-like TCP ports,
/// otherwise `host:port`.
pub(super) fn connect_line(row: &ListenerRow) -> String {
    let l = &row.listener;
    if l.proto == Proto::Tcp && crate::ports::looks_like_http(l.port) {
        row.url()
    } else {
        row.host_port()
    }
}

pub(super) fn group_key(by: GroupBy, row: &ListenerRow) -> String {
    match by {
        GroupBy::None => String::new(),
        GroupBy::Process => format!("pid:{}", row.listener.pid),
        GroupBy::Port => format!("port:{}:{}", row.listener.port, row.listener.proto.label()),
    }
}

pub(super) fn tint_of(state: RowState) -> RowTint {
    match state {
        RowState::Steady => RowTint::None,
        RowState::New(t) => RowTint::New(t),
        RowState::Closed(t) => RowTint::Closed(t),
    }
}

enum Item {
    Group {
        key: String,
        /// Index of the first row of the group (for the icon and titles).
        first: usize,
        count: usize,
    },
    Row(usize),
}

impl App {
    pub(super) fn listening_count(&self) -> Option<usize> {
        self.snap_loaded.then_some(self.rows.len())
    }

    pub(super) fn listen_apply_view(&mut self, view: &str) {
        if view.ends_with("grouped") {
            self.sh.settings.group_by = GroupBy::Process;
        }
        if view == "details" || view == "end" {
            // The demo's API server; on a real PC simply the first row.
            let row = self
                .rows
                .iter()
                .find(|r| r.listener.port == 3000)
                .or(self.rows.first())
                .cloned();
            if let Some(row) = row {
                self.listen.selected = Some(row.listener.key());
                if view == "end" {
                    self.ask_end_process(&row);
                }
            }
        }
    }

    /// Selects a listener and opens the Listening tab with it in view.
    pub(super) fn show_listener(&mut self, key: ListenerKey) {
        self.tab = super::app::Tab::Listening;
        self.sh.search.clear();
        self.listen.filter = ListenerFilter::default();
        self.listen.collapsed.clear();
        self.listen.selected = Some(key);
        self.listen.scroll_to_selected = true;
    }

    fn export_listeners(&mut self, rows: Vec<ListenerRow>) {
        self.export_with("socketforge-listening", move |format| {
            export::listeners(&rows, format)
        });
    }

    pub(super) fn listening_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let now = self.clock();
        let wall = self.wall_now();

        // Live rows plus the ones that are fading out.
        let all: Vec<(ListenerRow, RowTint)> = self
            .ltrack
            .rows(now)
            .into_iter()
            .map(|(_, row, state)| (row.clone(), tint_of(state)))
            .collect();
        let search = self.sh.search.clone();
        let searched: Vec<&(ListenerRow, RowTint)> = all
            .iter()
            .filter(|(r, _)| view::search_matches(r, &search))
            .collect();
        let mut filter = self.listen.filter.clone();
        filter.search = search.clone();
        let mut visible: Vec<(ListenerRow, RowTint)> = all
            .iter()
            .filter(|(r, _)| view::filter_matches(r, &filter))
            .cloned()
            .collect();
        sort_rows(&mut visible, self.listen.sort);

        // ---- Title row --------------------------------------------------------------
        let subtitle = if !self.snap_loaded {
            "Reading the socket tables…".to_string()
        } else {
            let processes: HashSet<u32> = self.rows.iter().map(|r| r.listener.pid).collect();
            let exposed = self.rows.iter().filter(|r| r.exposure.is_exposed()).count();
            let mut s = format!(
                "{} sockets · {} processes · {} reachable from the network",
                self.rows.len(),
                processes.len(),
                exposed
            );
            if !self.sys_loaded {
                s.push_str(" · reading the firewall…");
            } else if self.snap.taken > 0 {
                s.push_str(&format!(" · updated {}", fmt_clock(self.snap.taken)));
            }
            s
        };
        let mut do_export = false;
        let mut toggle_live = false;
        let live = self.sh.settings.live;
        widgets::page_header(ui, "Listening ports", &subtitle, |ui| {
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
            self.export_listeners(visible.iter().map(|(r, _)| r.clone()).collect());
        }

        // ---- Filter chips -----------------------------------------------------------
        let count =
            |f: &dyn Fn(&ListenerRow) -> bool| searched.iter().filter(|(r, _)| f(r)).count();
        // Next to the details panel there is no room for counts and long labels.
        let narrow = ui.available_width() < 820.0;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            let f = &mut self.listen.filter;
            let chips: [(&str, usize, &mut bool, &str); 7] = [
                (
                    "TCP",
                    count(&|r| r.listener.proto == Proto::Tcp),
                    &mut f.tcp,
                    "Listening TCP sockets",
                ),
                (
                    "UDP",
                    count(&|r| r.listener.proto == Proto::Udp),
                    &mut f.udp,
                    "Bound UDP sockets",
                ),
                (
                    "IPv4",
                    count(&|r| !r.listener.is_v6()),
                    &mut f.v4,
                    "IPv4 addresses",
                ),
                (
                    "IPv6",
                    count(&|r| r.listener.is_v6()),
                    &mut f.v6,
                    "IPv6 addresses",
                ),
                (
                    "System",
                    count(&|r| r.proc.is_system),
                    &mut f.system,
                    "Windows' own processes and services",
                ),
                (
                    "User",
                    count(&|r| !r.proc.is_system),
                    &mut f.user,
                    "Everything that is not part of Windows",
                ),
                (
                    if narrow { "Exposed" } else { "Exposed only" },
                    count(&|r| r.exposure.is_exposed()),
                    &mut f.exposed_only,
                    "Only ports that other devices could reach",
                ),
            ];
            for (i, (label, n, on, hint)) in chips.into_iter().enumerate() {
                if !narrow && (i == 2 || i == 4 || i == 6) {
                    ui.add_space(6.0);
                }
                if widgets::chip(ui, label, (!narrow).then_some(n), *on)
                    .on_hover_text(hint)
                    .clicked()
                {
                    *on = !*on;
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let current = match self.sh.settings.group_by {
                    GroupBy::None => 0,
                    GroupBy::Process => 1,
                    GroupBy::Port => 2,
                };
                let labels: [&str; 3] = if narrow {
                    ["Flat", "Process", "Port"]
                } else {
                    ["Flat", "By process", "By port"]
                };
                if let Some(i) = widgets::segmented(ui, &labels, current) {
                    self.sh.settings.group_by = [GroupBy::None, GroupBy::Process, GroupBy::Port][i];
                    self.listen.collapsed.clear();
                    self.sh.touch_settings();
                }
            });
        });
        ui.add_space(2.0);

        // ---- States -----------------------------------------------------------------
        if visible.is_empty() {
            if !self.snap_loaded {
                widgets::busy_state(
                    ui,
                    "Reading listening ports",
                    "Asking Windows for its TCP and UDP tables.",
                );
            } else if all.is_empty() {
                widgets::empty_state(
                    ui,
                    Icon::PLUG,
                    p.muted,
                    "Nothing is listening",
                    "Windows did not report any listening TCP socket or bound UDP socket.",
                );
            } else if !search.trim().is_empty() && searched.is_empty() {
                let text = format!(
                    "Nothing matches \"{}\". Try a port number, a program name or a service name.",
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
                    "The filter chips above hide every row. Switch some of them back on.",
                );
                ui.vertical_centered(|ui| {
                    if widgets::ghost_button(ui, "Reset filters").clicked() {
                        self.listen.filter = ListenerFilter::default();
                    }
                });
            }
            return;
        }

        // ---- Grouping ---------------------------------------------------------------
        let by = self.sh.settings.group_by;
        let rows_only: Vec<ListenerRow> = visible.iter().map(|(r, _)| r.clone()).collect();
        let groups: Vec<Vec<usize>> = match by {
            GroupBy::None => Vec::new(),
            GroupBy::Process => view::group_by_process(&rows_only)
                .into_iter()
                .map(|(_, v)| v)
                .collect(),
            GroupBy::Port => view::group_by_port(&rows_only)
                .into_iter()
                .map(|(_, v)| v)
                .collect(),
        };
        let mut items: Vec<Item> = Vec::new();
        if by == GroupBy::None {
            items.extend((0..visible.len()).map(Item::Row));
        } else {
            for members in groups {
                let Some(&first) = members.first() else {
                    continue;
                };
                let key = group_key(by, &rows_only[first]);
                let folded = self.listen.collapsed.contains(&key);
                items.push(Item::Group {
                    key,
                    first,
                    count: members.len(),
                });
                if !folded {
                    items.extend(members.into_iter().map(Item::Row));
                }
            }
        }

        // Icons for the rows on screen are loaded a few per frame.
        let paths: Vec<&str> = rows_only.iter().map(|r| r.proc.path.as_str()).collect();
        self.ensure_icons(&ctx, &paths);

        let scroll_target = if std::mem::take(&mut self.listen.scroll_to_selected) {
            self.listen.selected.and_then(|key| {
                items.iter().position(
                    |it| matches!(it, Item::Row(i) if rows_only[*i].listener.key() == key),
                )
            })
        } else {
            None
        };

        // ---- Table ------------------------------------------------------------------
        let mut clicked: Option<ListenerKey> = None;
        let mut toggled: Option<String> = None;
        widgets::table_card(ui, |ui| {
            let width = ui.available_width();
            let cols = Columns::for_width(width);
            self.listen_header(ui, &cols);
            let mut area = egui::ScrollArea::vertical().auto_shrink([false, false]);
            if let Some(i) = scroll_target {
                area = area.vertical_scroll_offset((i as f32 - 2.0).max(0.0) * ROW_H);
            }
            area.show_rows(ui, ROW_H, items.len(), |ui, range| {
                for item in &items[range] {
                    match item {
                        Item::Group { key, first, count } => {
                            let (rect, resp) =
                                ui.allocate_exact_size(vec2(width, ROW_H), Sense::click());
                            let row = &rows_only[*first];
                            let folded = self.listen.collapsed.contains(key);
                            let band = rect.shrink2(vec2(0.0, 4.0));
                            ui.painter().rect_filled(
                                band,
                                8,
                                if resp.hovered() { p.hover } else { p.bg },
                            );
                            let chevron = if folded {
                                Icon::CHEVRON_RIGHT
                            } else {
                                Icon::CHEVRON_DOWN
                            };
                            ui.painter().text(
                                pos2(rect.left() + 20.0, rect.center().y),
                                egui::Align2::CENTER_CENTER,
                                chevron.glyph(),
                                regular(11.0),
                                p.muted,
                            );
                            let mut x = rect.left() + 38.0;
                            let (title, sub) = match by {
                                GroupBy::Process => {
                                    let icon = Rect::from_center_size(
                                        pos2(x + 12.0, rect.center().y),
                                        vec2(24.0, 24.0),
                                    );
                                    widgets::program_icon(
                                        ui,
                                        icon,
                                        &row.proc.display_name(),
                                        self.icon(&row.proc.path),
                                    );
                                    x += 34.0;
                                    let mut sub = process_subline(row);
                                    if !row.proc.description.is_empty() {
                                        sub.push_str(&format!(" · {}", row.proc.description));
                                    }
                                    (row.proc.display_name(), sub)
                                }
                                _ => (
                                    format!("{} {}", row.listener.proto.label(), row.listener.port),
                                    row.well_known.unwrap_or("").to_string(),
                                ),
                            };
                            let count_text = if *count == 1 {
                                "1 socket".to_string()
                            } else {
                                format!("{count} sockets")
                            };
                            let right = Rect::from_min_max(
                                pos2(rect.right() - 110.0, rect.top()),
                                pos2(rect.right() - 14.0, rect.bottom()),
                            );
                            widgets::text_in_right(ui, right, &count_text, regular(12.5), p.muted);
                            let title_galley = widgets::elided(
                                ui,
                                &title,
                                semibold(14.0),
                                p.text,
                                (right.left() - x - 12.0).max(40.0),
                            );
                            let title_w = title_galley.size().x;
                            ui.painter().galley(
                                pos2(x, rect.center().y - title_galley.size().y / 2.0),
                                title_galley,
                                p.text,
                            );
                            let sub_rect = Rect::from_min_max(
                                pos2(x + title_w + 12.0, rect.top()),
                                pos2(right.left() - 12.0, rect.bottom()),
                            );
                            if sub_rect.width() > 40.0 {
                                widgets::text_in(ui, sub_rect, &sub, regular(12.5), p.muted);
                            }
                            if resp.clicked() {
                                toggled = Some(key.clone());
                            }
                        }
                        Item::Row(i) => {
                            let (row, tint) = &visible[*i];
                            let (rect, resp) =
                                ui.allocate_exact_size(vec2(width, ROW_H), Sense::click());
                            let key = row.listener.key();
                            let selected = self.listen.selected == Some(key);
                            widgets::row_background(ui, rect, selected, resp.hovered(), *tint);
                            self.listen_row(ui, rect, &cols, row, *tint, wall, by);
                            if resp.clicked() {
                                clicked = Some(key);
                            }
                        }
                    }
                }
            });
        });
        if let Some(key) = toggled {
            if !self.listen.collapsed.remove(&key) {
                self.listen.collapsed.insert(key);
            }
        }
        if let Some(key) = clicked {
            self.listen.selected = if self.listen.selected == Some(key) {
                None
            } else {
                Some(key)
            };
        }
    }

    fn listen_header(&mut self, ui: &mut Ui, cols: &Columns) {
        let rect = widgets::table_header(ui);
        let mut x = rect.left() + LEFT_PAD;
        let mut sort = self.listen.sort;
        // Under a process header the column shows how to reach the port instead.
        let process_title = if self.sh.settings.group_by == GroupBy::Process {
            "CONNECT TO"
        } else {
            "PROCESS"
        };
        let titles: [(&str, SortCol, f32); 7] = [
            ("PORT", SortCol::Port, cols.port),
            ("PROTO", SortCol::Proto, cols.proto),
            ("ADDRESS", SortCol::Address, cols.address),
            (process_title, SortCol::Process, cols.process),
            ("USUALLY", SortCol::Service, cols.service),
            ("EXPOSURE", SortCol::Exposure, cols.exposure),
            ("SINCE", SortCol::Since, cols.since),
        ];
        for (label, col, w) in titles {
            if w <= 0.0 {
                continue;
            }
            let active = (sort.0 == col).then_some(sort.1);
            if widgets::header_cell(ui, widgets::cell(rect, x, w), label, active, true, false) {
                sort = if sort.0 == col {
                    (col, !sort.1)
                } else {
                    // Newest first is the useful order for "since".
                    (col, col != SortCol::Since)
                };
            }
            x += w;
        }
        self.listen.sort = sort;
    }

    #[allow(clippy::too_many_arguments)]
    fn listen_row(
        &self,
        ui: &mut Ui,
        rect: Rect,
        cols: &Columns,
        row: &ListenerRow,
        tint: RowTint,
        wall: i64,
        by: GroupBy,
    ) {
        let p = pal(ui);
        let closed = matches!(tint, RowTint::Closed(_));
        let (text, muted) = if closed {
            (p.muted, p.faint)
        } else {
            (p.text, p.muted)
        };
        let l = &row.listener;
        let mut x = rect.left() + LEFT_PAD;

        widgets::text_in(
            ui,
            widgets::cell(rect, x, cols.port),
            &l.port.to_string(),
            semibold(15.0),
            text,
        );
        x += cols.port;

        let proto_color = match l.proto {
            _ if closed => p.faint,
            Proto::Tcp => p.info,
            Proto::Udp => p.udp,
        };
        widgets::paint_badge(
            ui,
            widgets::cell(rect, x, cols.proto),
            l.proto.label(),
            proto_color,
        );
        x += cols.proto;

        let (first, second) = address_lines(row);
        widgets::two_lines(
            ui,
            widgets::cell(rect, x, cols.address),
            (&first, regular(13.5), text),
            (&second, muted),
        );
        x += cols.address;

        // Process: icon, name, PID and services. Under a process group header
        // that would only repeat itself, so the cell shows how to reach the port.
        let change = if closed {
            " · closed"
        } else if matches!(tint, RowTint::New(_)) {
            " · new"
        } else {
            ""
        };
        if by == GroupBy::Process {
            let first = connect_line(row);
            let second = change.trim_start_matches(" · ");
            widgets::two_lines(
                ui,
                widgets::cell(rect, x, cols.process),
                (&first, regular(13.5), muted),
                (second, muted),
            );
        } else {
            let name = row.proc.display_name();
            let icon = Rect::from_center_size(pos2(x + 14.0, rect.center().y), vec2(28.0, 28.0));
            widgets::program_icon(ui, icon, &name, self.icon(&row.proc.path));
            let sub = format!("{}{change}", process_subline(row));
            widgets::two_lines(
                ui,
                widgets::cell(rect, x + 40.0, cols.process - 40.0),
                (&name, semibold(14.0), text),
                (&sub, muted),
            );
        }
        x += cols.process;

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

        let badge_rect = widgets::cell(rect, x, cols.exposure);
        let color = if closed {
            p.faint
        } else {
            exposure_color(&row.exposure, &p)
        };
        let badge = row.exposure.badge();
        let used = widgets::paint_badge(ui, badge_rect, &badge, color);
        let hit = Rect::from_min_size(
            pos2(badge_rect.left(), badge_rect.center().y - 12.0),
            vec2(used.min(badge_rect.width()), 24.0),
        );
        ui.interact(
            hit,
            ui.id().with(("exp", row.listener.key())),
            Sense::hover(),
        )
        .on_hover_text(row.exposure.explain());
        x += cols.exposure;

        if cols.since > 0.0 {
            let since = match l.created {
                Some(t) => fmt_age(wall - t),
                None => "—".to_string(),
            };
            widgets::text_in(
                ui,
                widgets::cell(rect, x, cols.since),
                &since,
                regular(13.0),
                muted,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo;

    fn rows() -> Vec<(ListenerRow, ())> {
        view::listener_rows(&demo::snapshot(), &demo::system())
            .into_iter()
            .map(|r| (r, ()))
            .collect()
    }

    #[test]
    fn columns_always_fit() {
        for width in [
            560.0_f32, 640.0, 672.0, 760.0, 900.0, 1012.0, 1400.0, 2200.0,
        ] {
            let c = Columns::for_width(width);
            assert!(c.total() <= width + 0.5, "{width}: {c:?}");
            assert!(c.process >= 130.0, "{width}: {c:?}");
            assert!(c.port > 0.0 && c.exposure > 0.0);
        }
        // The full window shows every column; next to the details panel the
        // optional ones give way.
        let wide = Columns::for_width(1012.0);
        assert!(wide.service > 0.0 && wide.since > 0.0);
        let narrow = Columns::for_width(660.0);
        assert_eq!(narrow.service, 0.0);
    }

    #[test]
    fn sorting_by_every_column() {
        let mut r = rows();
        sort_rows(&mut r, (SortCol::Port, true));
        assert!(r
            .windows(2)
            .all(|w| w[0].0.listener.port <= w[1].0.listener.port));
        sort_rows(&mut r, (SortCol::Port, false));
        assert!(r
            .windows(2)
            .all(|w| w[0].0.listener.port >= w[1].0.listener.port));

        sort_rows(&mut r, (SortCol::Process, true));
        let names: Vec<String> = r.iter().map(|x| x.0.proc.name.to_lowercase()).collect();
        assert!(names.windows(2).all(|w| w[0] <= w[1]));

        sort_rows(&mut r, (SortCol::Exposure, true));
        assert!(r[0].0.exposure.is_exposed());
        assert_eq!(
            r.last().unwrap().0.exposure.exposure,
            Exposure::LoopbackOnly
        );

        sort_rows(&mut r, (SortCol::Since, false));
        assert_eq!(r[0].0.listener.port, 22, "the newest socket comes first");

        sort_rows(&mut r, (SortCol::Service, true));
        assert!(r[0].0.well_known.is_some());
        assert!(r.last().unwrap().0.well_known.is_none());

        sort_rows(&mut r, (SortCol::Proto, true));
        assert_eq!(r[0].0.listener.proto, Proto::Tcp);
        assert_eq!(r.last().unwrap().0.listener.proto, Proto::Udp);

        sort_rows(&mut r, (SortCol::Address, true));
        assert!(r
            .windows(2)
            .all(|w| w[0].0.listener.addr <= w[1].0.listener.addr));
    }

    #[test]
    fn address_and_process_texts() {
        let r = rows();
        let find = |port: u16, addr: &str| {
            r.iter()
                .map(|x| &x.0)
                .find(|x| x.listener.port == port && x.listener.addr.to_string() == addr)
                .unwrap()
        };
        assert_eq!(
            address_lines(find(3000, "0.0.0.0")),
            ("All interfaces".to_string(), "0.0.0.0".to_string())
        );
        assert_eq!(address_lines(find(5173, "::1")).0, "Loopback only");
        assert_eq!(address_lines(find(139, demo::LAN)).0, demo::LAN);
        assert_eq!(process_subline(find(3000, "0.0.0.0")), "PID 7340");
        assert_eq!(
            process_subline(find(5353, "0.0.0.0")),
            "PID 1680 · Dnscache"
        );
        assert_eq!(connect_line(find(3000, "0.0.0.0")), "http://localhost:3000");
        assert_eq!(connect_line(find(5432, "0.0.0.0")), "localhost:5432");
        assert_eq!(
            connect_line(find(139, demo::LAN)),
            format!("{}:139", demo::LAN)
        );
    }

    #[test]
    fn group_keys_are_distinct_per_group() {
        let r = rows();
        let a = &r.iter().find(|x| x.0.listener.port == 3000).unwrap().0;
        let b = &r.iter().find(|x| x.0.listener.port == 9229).unwrap().0;
        assert_eq!(
            group_key(GroupBy::Process, a),
            group_key(GroupBy::Process, b)
        );
        assert_ne!(group_key(GroupBy::Port, a), group_key(GroupBy::Port, b));
        assert_eq!(group_key(GroupBy::None, a), "");
    }
}
