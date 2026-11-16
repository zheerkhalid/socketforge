//! Rules & forwards: read-only views of Windows Firewall rules, port
//! proxies, HTTP.sys, reserved port ranges and container / VM forwards.

use super::app::{cmp_text, App};
use super::theme::{pal, regular, semibold, Icon};
use super::widgets::{self, ROW_H};
use crate::export;
use crate::exposure::port_spec_contains;
use crate::model::{ForwardSource, FwRule, Profiles, Proto};
use crate::util::fmt_clock;
use eframe::egui::{
    self, vec2, Align2, CornerRadius, Frame, Margin, Rect, RichText, Sense, Stroke, Ui,
};
use std::cmp::Ordering;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RulesTab {
    Firewall,
    Proxies,
    Http,
    Ranges,
    Forwards,
    Collectors,
}

const TABS: [RulesTab; 6] = [
    RulesTab::Firewall,
    RulesTab::Proxies,
    RulesTab::Http,
    RulesTab::Ranges,
    RulesTab::Forwards,
    RulesTab::Collectors,
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FwSort {
    Name,
    Enabled,
    Direction,
    Action,
    Proto,
    Ports,
    Program,
    Profiles,
}

pub struct RulesState {
    pub tab: RulesTab,
    pub inbound: bool,
    pub outbound: bool,
    pub allow: bool,
    pub block: bool,
    pub enabled_only: bool,
    pub sort: (FwSort, bool),
}

impl Default for RulesState {
    fn default() -> Self {
        RulesState {
            tab: RulesTab::Firewall,
            inbound: true,
            outbound: true,
            allow: true,
            block: true,
            enabled_only: false,
            sort: (FwSort::Name, true),
        }
    }
}

impl RulesState {
    pub fn show_firewall(&mut self) {
        let sort = self.sort;
        *self = RulesState {
            sort,
            ..Default::default()
        };
    }

    /// Do the filter chips let this rule through? (The search is separate.)
    pub(super) fn matches(&self, rule: &FwRule) -> bool {
        (if rule.inbound {
            self.inbound
        } else {
            self.outbound
        }) && (if rule.allow { self.allow } else { self.block })
            && (!self.enabled_only || rule.enabled)
    }
}

/// The file name of a program path; `Any program` when the rule has none.
pub(super) fn program_label(rule: &FwRule) -> String {
    if rule.program.is_empty() {
        "Any program".to_string()
    } else {
        rule.program
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&rule.program)
            .to_string()
    }
}

/// `Any` for `*` and empty port lists, otherwise the list as stored.
pub(super) fn ports_label(spec: &str) -> String {
    let s = spec.trim();
    if s.is_empty() || s == "*" {
        "Any".to_string()
    } else {
        s.replace(',', ", ")
    }
}

fn is_specific(spec: &str) -> bool {
    let s = spec.trim();
    !s.is_empty() && s != "*"
}

/// Search over firewall rules. Every word must match. A number matches rules
/// whose port list contains that port (ranges included); text matches the
/// name, group, program, service and port keywords.
pub(super) fn rule_matches_search(rule: &FwRule, search: &str) -> bool {
    let needle = search.trim().to_lowercase();
    needle.split_whitespace().all(|word| {
        if let Ok(port) = word.trim_start_matches(':').parse::<u16>() {
            let local =
                is_specific(&rule.local_ports) && port_spec_contains(&rule.local_ports, port);
            let remote =
                is_specific(&rule.remote_ports) && port_spec_contains(&rule.remote_ports, port);
            if local || remote {
                return true;
            }
        }
        rule.name.to_lowercase().contains(word)
            || rule.group.to_lowercase().contains(word)
            || rule.program.to_lowercase().contains(word)
            || rule.service.to_lowercase().contains(word)
            || (word.parse::<u32>().is_err() && rule.local_ports.to_lowercase().contains(word))
    })
}

pub(super) fn compare_rules(a: &FwRule, b: &FwRule, col: FwSort) -> Ordering {
    let ord = match col {
        FwSort::Name => Ordering::Equal,
        // Enabled first, inbound first, allow first.
        FwSort::Enabled => b.enabled.cmp(&a.enabled),
        FwSort::Direction => b.inbound.cmp(&a.inbound),
        FwSort::Action => b.allow.cmp(&a.allow),
        FwSort::Proto => a.proto.label().cmp(&b.proto.label()),
        FwSort::Ports => first_port(&a.local_ports).cmp(&first_port(&b.local_ports)),
        FwSort::Program => cmp_text(&program_label(a), &program_label(b)),
        FwSort::Profiles => a.profiles.0.cmp(&b.profiles.0),
    };
    ord.then_with(|| cmp_text(&a.name, &b.name))
        .then_with(|| b.inbound.cmp(&a.inbound))
}

/// The first number of a port list, for sorting; "any" sorts first, keywords last.
fn first_port(spec: &str) -> u32 {
    if !is_specific(spec) {
        return 0;
    }
    let digits: String = spec
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<u32>().map(|n| n + 1).unwrap_or(u32::MAX)
}

/// Positions of table columns: a width of 0 marks the one flexible column.
pub(super) fn layout_columns(left: f32, width: f32, widths: &[f32]) -> Vec<(f32, f32)> {
    let fixed: f32 = widths.iter().sum();
    let flex = (width - fixed).max(80.0);
    let mut x = left;
    widths
        .iter()
        .map(|&w| {
            let w = if w <= 0.0 { flex } else { w };
            let at = (x, w);
            x += w;
            at
        })
        .collect()
}

/// A small table that is as tall as its rows (inside a scrolling page).
fn mini_table(
    ui: &mut Ui,
    columns: &[(&str, f32)],
    rows: usize,
    mut draw: impl FnMut(&mut Ui, Rect, &[(f32, f32)], usize),
) {
    let p = pal(ui);
    Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(6, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 0.0;
            let width = ui.available_width();
            let header = widgets::table_header(ui);
            let widths: Vec<f32> = columns.iter().map(|c| c.1).collect();
            let at = layout_columns(header.left() + 14.0, width - 28.0, &widths);
            for ((label, _), (x, w)) in columns.iter().zip(&at) {
                widgets::header_cell(ui, widgets::cell(header, *x, *w), label, None, false, false);
            }
            for i in 0..rows {
                let (rect, resp) = ui.allocate_exact_size(vec2(width, ROW_H), Sense::hover());
                widgets::row_background(ui, rect, false, resp.hovered(), widgets::RowTint::None);
                draw(ui, rect, &at, i);
            }
        });
}

fn source_color(source: ForwardSource, p: &super::theme::Palette) -> egui::Color32 {
    match source {
        ForwardSource::Docker => p.info,
        ForwardSource::Wsl => p.warn,
        ForwardSource::HyperV => p.accent,
    }
}

impl App {
    pub(super) fn rules_count(&self) -> Option<usize> {
        None
    }

    pub(super) fn rules_apply_view(&mut self, view: &str) {
        self.rules.tab = match view {
            "rules-proxy" | "rules-proxies" => RulesTab::Proxies,
            "rules-http" => RulesTab::Http,
            "rules-ranges" => RulesTab::Ranges,
            "rules-forwards" => RulesTab::Forwards,
            "rules-collectors" => RulesTab::Collectors,
            _ => RulesTab::Firewall,
        };
    }

    pub(super) fn rules_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let busy = self.system_busy() && !self.sh.screenshot;
        let subtitle = if !self.sys_loaded {
            "Reading the firewall, reserved ranges and forwards…".to_string()
        } else {
            let mut s = "Read-only: SocketForge never changes any of this.".to_string();
            if self.sys.taken > 0 {
                s.push_str(&format!(" Read at {}.", fmt_clock(self.sys.taken)));
            }
            s
        };
        let mut do_export = false;
        let mut do_reload = false;
        widgets::page_header(ui, "Rules & forwards", &subtitle, |ui| {
            if widgets::ghost_button(ui, &Icon::EXPORT.with("Export"))
                .on_hover_text("Save this list as CSV, JSON or HTML")
                .clicked()
            {
                do_export = true;
            }
            if busy {
                ui.add(egui::Spinner::new().size(18.0).color(p.accent));
            } else if widgets::ghost_button(ui, &Icon::REFRESH.with("Reload"))
                .on_hover_text("Read the firewall and the other lists again (F5)")
                .clicked()
            {
                do_reload = true;
            }
        });
        if do_reload {
            self.refresh(true);
        }

        // ---- Sub-tabs ---------------------------------------------------------------
        let sys = &self.sys;
        let labels: Vec<String> = vec![
            format!("Firewall rules  {}", sys.firewall.rules.len()),
            format!("Port proxies  {}", sys.portproxy.len()),
            format!(
                "HTTP.sys  {}",
                sys.reservations.len() + sys.http_listeners.len()
            ),
            format!("Reserved ranges  {}", sys.excluded.len()),
            format!("Forwards  {}", sys.forwards.len()),
            "Collectors".to_string(),
        ];
        let refs: Vec<&str> = labels.iter().map(|s| s.as_str()).collect();
        let current = TABS.iter().position(|t| *t == self.rules.tab).unwrap_or(0);
        ui.horizontal(|ui| {
            if let Some(i) = widgets::segmented(ui, &refs, current) {
                self.rules.tab = TABS[i];
                self.sh.search.clear();
            }
        });
        ui.add_space(4.0);

        if !self.sys_loaded {
            widgets::busy_state(
                ui,
                "Reading system rules",
                "Windows Firewall, netsh and HTTP.sys take a moment the first time.",
            );
            return;
        }

        match self.rules.tab {
            RulesTab::Firewall => self.firewall_ui(ui, do_export),
            other => {
                if do_export {
                    let sys = self.sys.clone();
                    self.export_with("socketforge-system", move |format| {
                        export::system(&sys, format)
                    });
                }
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        match other {
                            RulesTab::Proxies => self.proxies_ui(ui),
                            RulesTab::Http => self.http_ui(ui),
                            RulesTab::Ranges => self.ranges_ui(ui),
                            RulesTab::Forwards => self.forwards_ui(ui),
                            _ => self.collectors_ui(ui),
                        }
                        ui.add_space(8.0);
                    });
            }
        }
    }

    // ----------------------------------------------------------------------------------
    // Firewall
    // ----------------------------------------------------------------------------------

    fn firewall_ui(&mut self, ui: &mut Ui, do_export: bool) {
        let p = pal(ui);
        let fw = self.sys.firewall.clone();
        if !fw.available {
            widgets::empty_state(
                ui,
                Icon::SHIELD,
                p.warn,
                "Windows Firewall could not be read",
                fw.error.as_deref().unwrap_or(
                    "The firewall service did not answer. Exposure badges show \"LAN\" without \
                     saying whether the port is open.",
                ),
            );
            return;
        }

        // ---- Banner -----------------------------------------------------------------
        Frame::new()
            .fill(p.card)
            .stroke(Stroke::new(1.0_f32, p.border))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(Margin::symmetric(14, 10))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    let all_on = fw.enabled.contains(Profiles::ALL);
                    let color = if all_on { p.accent } else { p.danger };
                    let (rect, _) = ui.allocate_exact_size(vec2(30.0, 30.0), Sense::hover());
                    ui.painter()
                        .circle_filled(rect.center(), 15.0, color.gamma_multiply(0.15));
                    ui.painter().text(
                        rect.center(),
                        Align2::CENTER_CENTER,
                        Icon::SHIELD.glyph(),
                        regular(14.0),
                        color,
                    );
                    ui.label(RichText::new("Windows Firewall").font(semibold(14.5)));
                    for (profile, name) in [
                        (Profiles::DOMAIN, "Domain"),
                        (Profiles::PRIVATE, "Private"),
                        (Profiles::PUBLIC, "Public"),
                    ] {
                        let on = fw.enabled.contains(profile);
                        let active = fw.active.contains(profile);
                        let mut text = format!("{name}: {}", if on { "on" } else { "off" });
                        if active {
                            text.push_str(" · active now");
                        }
                        let color = if !on {
                            p.danger
                        } else if active {
                            p.accent
                        } else {
                            p.muted
                        };
                        widgets::badge(ui, &text, color).on_hover_text(if active {
                            "This profile applies to the network you are connected to."
                        } else {
                            "This profile is not in use on the current network."
                        });
                    }
                    let unblocked = Profiles(Profiles::ALL.0 & !fw.default_inbound_block.0);
                    let note = if unblocked.is_empty() {
                        "Inbound connections without a matching rule are blocked.".to_string()
                    } else {
                        format!(
                            "Unmatched inbound connections are ALLOWED on: {}.",
                            unblocked.label()
                        )
                    };
                    ui.add(
                        egui::Label::new(RichText::new(note).size(12.5).color(
                            if unblocked.is_empty() {
                                p.faint
                            } else {
                                p.danger
                            },
                        ))
                        .truncate(),
                    );
                });
            });
        ui.add_space(2.0);

        // ---- Chips ------------------------------------------------------------------
        let search = self.sh.search.clone();
        let searched: Vec<&FwRule> = fw
            .rules
            .iter()
            .filter(|r| rule_matches_search(r, &search))
            .collect();
        let count = |f: &dyn Fn(&FwRule) -> bool| searched.iter().filter(|r| f(r)).count();
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            let s = &mut self.rules;
            let chips: [(&str, usize, &mut bool, &str); 5] = [
                (
                    "Inbound",
                    count(&|r| r.inbound),
                    &mut s.inbound,
                    "Rules for connections coming in to this PC",
                ),
                (
                    "Outbound",
                    count(&|r| !r.inbound),
                    &mut s.outbound,
                    "Rules for connections this PC starts",
                ),
                (
                    "Allow",
                    count(&|r| r.allow),
                    &mut s.allow,
                    "Rules that let traffic through",
                ),
                (
                    "Block",
                    count(&|r| !r.allow),
                    &mut s.block,
                    "Rules that stop traffic",
                ),
                (
                    "Enabled only",
                    count(&|r| r.enabled),
                    &mut s.enabled_only,
                    "Hide rules that are switched off",
                ),
            ];
            for (i, (label, n, on, hint)) in chips.into_iter().enumerate() {
                if i == 2 || i == 4 {
                    ui.add_space(6.0);
                }
                if widgets::chip(ui, label, Some(n), *on)
                    .on_hover_text(hint)
                    .clicked()
                {
                    *on = !*on;
                }
            }
        });
        ui.add_space(2.0);

        let mut visible: Vec<&FwRule> = searched
            .iter()
            .copied()
            .filter(|r| self.rules.matches(r))
            .collect();
        let sort = self.rules.sort;
        visible.sort_by(|a, b| {
            let ord = compare_rules(a, b, sort.0);
            if sort.1 {
                ord
            } else {
                ord.reverse()
            }
        });
        if do_export {
            let rules: Vec<FwRule> = visible.iter().map(|r| (*r).clone()).collect();
            self.export_with("socketforge-firewall-rules", move |format| {
                let refs: Vec<&FwRule> = rules.iter().collect();
                export::firewall_rules(&refs, format)
            });
        }

        if visible.is_empty() {
            if fw.rules.is_empty() {
                widgets::empty_state(
                    ui,
                    Icon::SHIELD,
                    p.muted,
                    "No firewall rules",
                    "Windows Firewall reported no rules at all.",
                );
            } else if !search.trim().is_empty() && searched.is_empty() {
                let text = format!(
                    "No rule matches \"{}\". Search by port number, program or rule name.",
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
                    "The filter chips above hide every rule.",
                );
            }
            return;
        }

        // ---- Table ------------------------------------------------------------------
        widgets::table_card(ui, |ui| {
            let width = ui.available_width();
            let header = widgets::table_header(ui);
            let narrow = width < 900.0;
            let widths = [
                0.0,
                60.0,
                56.0,
                76.0,
                70.0,
                if narrow { 96.0 } else { 124.0 },
                if narrow { 130.0 } else { 186.0 },
                if narrow { 104.0 } else { 128.0 },
            ];
            let at = layout_columns(header.left() + 14.0, width - 28.0, &widths);
            let titles = [
                ("NAME", FwSort::Name),
                ("STATE", FwSort::Enabled),
                ("DIR", FwSort::Direction),
                ("ACTION", FwSort::Action),
                ("PROTO", FwSort::Proto),
                ("LOCAL PORTS", FwSort::Ports),
                ("PROGRAM", FwSort::Program),
                ("PROFILES", FwSort::Profiles),
            ];
            let mut sort = self.rules.sort;
            for ((label, col), (x, w)) in titles.iter().zip(&at) {
                let active = (sort.0 == *col).then_some(sort.1);
                if widgets::header_cell(
                    ui,
                    widgets::cell(header, *x, *w),
                    label,
                    active,
                    true,
                    false,
                ) {
                    sort = if sort.0 == *col {
                        (*col, !sort.1)
                    } else {
                        (*col, true)
                    };
                }
            }
            self.rules.sort = sort;
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show_rows(ui, ROW_H, visible.len(), |ui, range| {
                    for rule in &visible[range] {
                        let (rect, resp) =
                            ui.allocate_exact_size(vec2(width, ROW_H), Sense::hover());
                        widgets::row_background(
                            ui,
                            rect,
                            false,
                            resp.hovered(),
                            widgets::RowTint::None,
                        );
                        let (text, muted) = if rule.enabled {
                            (p.text, p.muted)
                        } else {
                            (p.muted, p.faint)
                        };
                        let c = |i: usize| widgets::cell(rect, at[i].0, at[i].1);
                        let cut = widgets::two_lines(
                            ui,
                            c(0),
                            (&rule.name, regular(14.0), text),
                            (&rule.group, muted),
                        );
                        if rule.enabled {
                            widgets::paint_badge(ui, c(1), "On", p.accent);
                        } else {
                            widgets::paint_badge(ui, c(1), "Off", p.faint);
                        }
                        widgets::text_in(
                            ui,
                            c(2),
                            if rule.inbound { "In" } else { "Out" },
                            regular(13.5),
                            text,
                        );
                        let action_color = if !rule.enabled {
                            p.faint
                        } else if rule.allow {
                            p.accent
                        } else {
                            p.danger
                        };
                        widgets::paint_badge(
                            ui,
                            c(3),
                            if rule.allow { "Allow" } else { "Block" },
                            action_color,
                        );
                        widgets::text_in(ui, c(4), &rule.proto.label(), regular(13.5), muted);
                        widgets::text_in(
                            ui,
                            c(5),
                            &ports_label(&rule.local_ports),
                            regular(13.5),
                            text,
                        );
                        let service = match rule.service.as_str() {
                            "" => String::new(),
                            "*" => "any service".to_string(),
                            name => format!("service {name}"),
                        };
                        widgets::two_lines(
                            ui,
                            c(6),
                            (
                                &program_label(rule),
                                regular(13.5),
                                if rule.program.is_empty() { muted } else { text },
                            ),
                            (&service, muted),
                        );
                        widgets::text_in(ui, c(7), &rule.profiles.label(), regular(13.0), muted);
                        if resp.hovered() && (cut || !rule.program.is_empty()) {
                            let mut tip = rule.name.clone();
                            if !rule.description.is_empty() {
                                tip.push_str(&format!("\n{}", rule.description));
                            }
                            if !rule.program.is_empty() {
                                tip.push_str(&format!("\nProgram: {}", rule.program));
                            }
                            if is_specific(&rule.remote_ports) {
                                tip.push_str(&format!("\nRemote ports: {}", rule.remote_ports));
                            }
                            resp.on_hover_text(tip);
                        }
                    }
                });
        });
    }

    // ----------------------------------------------------------------------------------
    // Port proxies
    // ----------------------------------------------------------------------------------

    fn proxies_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let search = self.sh.search.trim().to_lowercase();
        let list: Vec<_> = self
            .sys
            .portproxy
            .iter()
            .filter(|x| {
                search.is_empty()
                    || x.listen_port.to_string() == search
                    || x.connect_port.to_string() == search
                    || x.listen_addr.contains(&search)
                    || x.connect_addr.contains(&search)
                    || x.kind.contains(&search)
            })
            .cloned()
            .collect();
        widgets::note_card(
            ui,
            Icon::SWITCH,
            p.info,
            "Port proxies (netsh interface portproxy)",
            "A port proxy makes Windows accept TCP connections on one address and pass them on \
             to another, often into WSL or a virtual machine. The IP Helper service does the \
             listening, so Listening ports shows svchost.exe (iphlpsvc) for these ports.",
        );
        if self.sys.portproxy.is_empty() {
            widgets::empty_state(
                ui,
                Icon::SWITCH,
                p.muted,
                "No port proxies",
                "Nothing is forwarded with netsh interface portproxy on this PC.",
            );
            return;
        }
        if list.is_empty() {
            widgets::empty_state(
                ui,
                Icon::SEARCH,
                p.muted,
                "No matches",
                "No port proxy matches the search.",
            );
            return;
        }
        let listening: Vec<u16> = self
            .snap
            .listeners
            .iter()
            .filter(|l| l.proto == Proto::Tcp)
            .map(|l| l.port)
            .collect();
        mini_table(
            ui,
            &[
                ("LISTENS ON", 230.0),
                ("", 40.0),
                ("CONNECTS TO", 0.0),
                ("KIND", 110.0),
                ("STATE", 150.0),
            ],
            list.len(),
            |ui, rect, at, i| {
                let x = &list[i];
                let c = |i: usize| widgets::cell(rect, at[i].0, at[i].1);
                widgets::text_in(
                    ui,
                    c(0),
                    &format!("{}:{}", x.listen_addr, x.listen_port),
                    semibold(14.0),
                    p.text,
                );
                widgets::text_in(ui, c(1), "→", regular(15.0), p.faint);
                widgets::text_in(
                    ui,
                    c(2),
                    &format!("{}:{}", x.connect_addr, x.connect_port),
                    regular(14.0),
                    p.text,
                );
                widgets::text_in(ui, c(3), &x.kind, regular(13.5), p.muted);
                if listening.contains(&x.listen_port) {
                    widgets::paint_badge(ui, c(4), "Listening", p.accent);
                } else {
                    widgets::paint_badge(ui, c(4), "Not listening", p.warn);
                }
            },
        );
    }

    // ----------------------------------------------------------------------------------
    // HTTP.sys
    // ----------------------------------------------------------------------------------

    fn http_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let search = self.sh.search.trim().to_lowercase();
        let hit = |url: &str, port: Option<u16>, extra: &str| {
            search.is_empty()
                || port.map(|n| n.to_string()) == Some(search.clone())
                || url.to_lowercase().contains(&search)
                || extra.to_lowercase().contains(&search)
        };
        let listeners: Vec<_> = self
            .sys
            .http_listeners
            .iter()
            .filter(|h| hit(&h.url, h.port, &h.queue))
            .cloned()
            .collect();
        let reservations: Vec<_> = self
            .sys
            .reservations
            .iter()
            .filter(|r| hit(&r.url, r.port, &r.accounts))
            .cloned()
            .collect();
        widgets::note_card(
            ui,
            Icon::GLOBE,
            p.info,
            "HTTP.sys, the web server inside Windows",
            "IIS, WinRM, printing and many .NET programs do not open a port themselves. They \
             register URLs with HTTP.sys, which listens as the System process (PID 4) and can \
             share one port between several programs. That is why port 80 can be \"in use by \
             System\".",
        );
        if self.sys.http_listeners.is_empty() && self.sys.reservations.is_empty() {
            widgets::empty_state(
                ui,
                Icon::GLOBE,
                p.muted,
                "Nothing registered with HTTP.sys",
                "No URL is being served and no URL is reserved.",
            );
            return;
        }

        ui.add_space(2.0);
        widgets::section(ui, &format!("Served right now  ·  {}", listeners.len()));
        if listeners.is_empty() {
            widgets::para(
                ui,
                if self.sys.http_listeners.is_empty() {
                    "No program is serving a URL through HTTP.sys at the moment."
                } else {
                    "No served URL matches the search."
                },
            );
        } else {
            mini_table(
                ui,
                &[
                    ("URL", 0.0),
                    ("PORT", 80.0),
                    ("PROCESS", 240.0),
                    ("REQUEST QUEUE", 190.0),
                ],
                listeners.len(),
                |ui, rect, at, i| {
                    let h = &listeners[i];
                    let c = |i: usize| widgets::cell(rect, at[i].0, at[i].1);
                    widgets::text_in(ui, c(0), &h.url, semibold(14.0), p.text);
                    widgets::text_in(
                        ui,
                        c(1),
                        &h.port.map(|n| n.to_string()).unwrap_or_default(),
                        regular(13.5),
                        p.text,
                    );
                    let who: Vec<String> = h
                        .pids
                        .iter()
                        .map(|pid| format!("{} ({pid})", self.snap.proc_name(*pid)))
                        .collect();
                    if who.is_empty() {
                        widgets::text_in(ui, c(2), "Not known", regular(13.5), p.faint);
                    } else {
                        widgets::text_in(ui, c(2), &who.join(", "), regular(13.5), p.text);
                    }
                    widgets::text_in(ui, c(3), &h.queue, regular(13.5), p.muted);
                },
            );
        }

        ui.add_space(10.0);
        widgets::section(ui, &format!("URL reservations  ·  {}", reservations.len()));
        widgets::para(
            ui,
            "A reservation lets the named accounts listen on a URL without administrator \
             rights. It does not occupy the port.",
        );
        if reservations.is_empty() {
            widgets::para(ui, "No reservation matches.");
        } else {
            mini_table(
                ui,
                &[("URL", 0.0), ("PORT", 80.0), ("WHO MAY LISTEN", 430.0)],
                reservations.len(),
                |ui, rect, at, i| {
                    let r = &reservations[i];
                    let c = |i: usize| widgets::cell(rect, at[i].0, at[i].1);
                    widgets::text_in(ui, c(0), &r.url, regular(14.0), p.text);
                    widgets::text_in(
                        ui,
                        c(1),
                        &r.port.map(|n| n.to_string()).unwrap_or_default(),
                        regular(13.5),
                        p.text,
                    );
                    widgets::text_in(ui, c(2), &r.accounts, regular(13.5), p.muted);
                },
            );
        }
    }

    // ----------------------------------------------------------------------------------
    // Reserved ranges
    // ----------------------------------------------------------------------------------

    fn ranges_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let excluded = self.sys.excluded.clone();
        let dynamic = self.sys.dynamic.clone();
        widgets::note_card(
            ui,
            Icon::LOCK,
            p.warn,
            "Why a free port can still refuse a bind",
            "Windows sets whole ranges of ports aside. Hyper-V, WSL and Docker ask for such \
             excluded ranges when they start, and the ranges can move after a restart. Inside \
             one, every bind fails with \"access denied\" (WSAEACCES, error 10013) or \"address \
             already in use\", although no program is listening there. If your server's port \
             lands in a range, pick another port, or reserve yours first with an administered \
             exclusion.",
        );
        ui.add_space(2.0);

        widgets::section(ui, "Dynamic (ephemeral) range");
        widgets::para(
            ui,
            "Windows takes the local port of outgoing connections from this range, so a port \
             in it can be taken at any moment.",
        );
        if dynamic.is_empty() {
            widgets::para(ui, "The dynamic range could not be read.");
        } else {
            ui.horizontal_wrapped(|ui| {
                for d in &dynamic {
                    let end = (d.start as u32 + d.count).saturating_sub(1).min(65535);
                    Frame::new()
                        .fill(p.card)
                        .stroke(Stroke::new(1.0_f32, p.border))
                        .corner_radius(CornerRadius::same(12))
                        .inner_margin(Margin::symmetric(14, 10))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                widgets::badge(
                                    ui,
                                    d.proto.label(),
                                    match d.proto {
                                        Proto::Tcp => p.info,
                                        Proto::Udp => p.udp,
                                    },
                                );
                                ui.label(
                                    RichText::new(format!("{} – {}", d.start, end))
                                        .font(semibold(16.0)),
                                );
                                ui.label(
                                    RichText::new(format!("{} ports", d.count)).color(p.muted),
                                );
                            });
                        });
                }
            });
        }

        ui.add_space(10.0);
        widgets::section(ui, &format!("Excluded ranges  ·  {}", excluded.len()));
        if excluded.is_empty() {
            widgets::empty_state(
                ui,
                Icon::CHECK,
                p.accent,
                "No excluded ranges",
                "Windows has not set any port range aside. A bind can only fail because the \
                 port is really in use.",
            );
            return;
        }
        let listeners = &self.snap.listeners;
        mini_table(
            ui,
            &[
                ("PROTO", 80.0),
                ("RANGE", 190.0),
                ("PORTS", 90.0),
                ("KIND", 230.0),
                ("NOW", 0.0),
            ],
            excluded.len(),
            |ui, rect, at, i| {
                let r = &excluded[i];
                let c = |i: usize| widgets::cell(rect, at[i].0, at[i].1);
                widgets::paint_badge(
                    ui,
                    c(0),
                    &format!("{}{}", r.proto.label(), if r.v6 { " v6" } else { "" }),
                    match r.proto {
                        Proto::Tcp => p.info,
                        Proto::Udp => p.udp,
                    },
                );
                let range = if r.start == r.end {
                    r.start.to_string()
                } else {
                    format!("{} – {}", r.start, r.end)
                };
                widgets::text_in(ui, c(1), &range, semibold(14.5), p.text);
                widgets::text_in(
                    ui,
                    c(2),
                    &(r.end as u32 - r.start.min(r.end) as u32 + 1).to_string(),
                    regular(13.5),
                    p.muted,
                );
                widgets::text_in(
                    ui,
                    c(3),
                    if r.administered {
                        "Administered (stays after restart)"
                    } else {
                        "Set by a Windows component"
                    },
                    regular(13.5),
                    p.muted,
                );
                let inside = listeners
                    .iter()
                    .filter(|l| l.proto == r.proto && r.contains(l.port))
                    .count();
                let text = match inside {
                    0 => "Nothing listens inside".to_string(),
                    1 => "1 socket listens inside".to_string(),
                    n => format!("{n} sockets listen inside"),
                };
                widgets::text_in(ui, c(4), &text, regular(13.5), p.faint);
            },
        );
    }

    // ----------------------------------------------------------------------------------
    // Forwards
    // ----------------------------------------------------------------------------------

    fn forwards_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let search = self.sh.search.trim().to_lowercase();
        let list: Vec<_> = self
            .sys
            .forwards
            .iter()
            .filter(|f| {
                search.is_empty()
                    || f.host_port.to_string() == search
                    || f.target_port.to_string() == search
                    || f.target.to_lowercase().contains(&search)
                    || f.detail.to_lowercase().contains(&search)
                    || f.source.label().to_lowercase().contains(&search)
            })
            .cloned()
            .collect();
        widgets::note_card(
            ui,
            Icon::NETWORK,
            p.info,
            "Ports that lead into containers and virtual machines",
            "Docker, WSL and Hyper-V publish ports of this PC and pass the traffic inside. In \
             Listening ports they appear under a helper process (com.docker.backend.exe, \
             wslrelay.exe) or not at all; this list names the real target.",
        );
        if self.sys.forwards.is_empty() {
            widgets::empty_state(
                ui,
                Icon::NETWORK,
                p.muted,
                "No forwards found",
                "No running container, WSL distribution or Hyper-V NAT rule publishes a port \
                 of this PC.",
            );
            return;
        }
        if list.is_empty() {
            widgets::empty_state(
                ui,
                Icon::SEARCH,
                p.muted,
                "No matches",
                "No forward matches the search.",
            );
            return;
        }
        mini_table(
            ui,
            &[
                ("SOURCE", 100.0),
                ("ON THIS PC", 200.0),
                ("", 40.0),
                ("LEADS TO", 250.0),
                ("DETAILS", 0.0),
            ],
            list.len(),
            |ui, rect, at, i| {
                let f = &list[i];
                let c = |i: usize| widgets::cell(rect, at[i].0, at[i].1);
                widgets::paint_badge(ui, c(0), f.source.label(), source_color(f.source, &p));
                let host = if f.host_addr.is_empty() {
                    format!("{} port {}", f.proto.label(), f.host_port)
                } else {
                    format!("{} {}:{}", f.proto.label(), f.host_addr, f.host_port)
                };
                widgets::text_in(ui, c(1), &host, semibold(14.0), p.text);
                widgets::text_in(ui, c(2), "→", regular(15.0), p.faint);
                let target = if f.target_port == 0 {
                    f.target.clone()
                } else {
                    format!("{} : {}", f.target, f.target_port)
                };
                widgets::text_in(ui, c(3), &target, regular(14.0), p.text);
                widgets::text_in(ui, c(4), &f.detail, regular(13.5), p.muted);
            },
        );
    }

    // ----------------------------------------------------------------------------------
    // Collectors
    // ----------------------------------------------------------------------------------

    fn collectors_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let notes = self.sys.notes.clone();
        widgets::para(
            ui,
            "Where the data on this tab comes from, and whether each source could be read.",
        );
        ui.add_space(2.0);
        if notes.is_empty() {
            widgets::empty_state(
                ui,
                Icon::LIST,
                p.muted,
                "No collector reports",
                "The collectors did not leave any notes.",
            );
            return;
        }
        mini_table(
            ui,
            &[
                ("SOURCE", 280.0),
                ("STATE", 110.0),
                ("ITEMS", 80.0),
                ("NOTES", 0.0),
            ],
            notes.len(),
            |ui, rect, at, i| {
                let n = &notes[i];
                let c = |i: usize| widgets::cell(rect, at[i].0, at[i].1);
                widgets::text_in(ui, c(0), &n.name, regular(14.0), p.text);
                if n.ok {
                    widgets::paint_badge(ui, c(1), "OK", p.accent);
                } else {
                    widgets::paint_badge(ui, c(1), "Limited", p.warn);
                }
                widgets::text_in(ui, c(2), &n.count.to_string(), regular(13.5), p.muted);
                let cut = widgets::text_in(ui, c(3), &n.detail, regular(13.5), p.muted);
                if cut {
                    ui.interact(c(3), ui.id().with(("note", i)), Sense::hover())
                        .on_hover_text(&n.detail);
                }
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo;

    fn rules() -> Vec<FwRule> {
        demo::system().firewall.rules
    }

    #[test]
    fn search_by_port_program_and_name() {
        let rules = rules();
        let hits = |q: &str| -> Vec<String> {
            rules
                .iter()
                .filter(|r| rule_matches_search(r, q))
                .map(|r| r.name.clone())
                .collect()
        };
        assert_eq!(hits("5432"), vec!["PostgreSQL 17 (TCP-In)"]);
        // Inside the range 27031-27036.
        assert_eq!(hits("27033"), vec!["Nebula Games Launcher (UDP-In)"]);
        // "Any port" rules do not match every number.
        assert!(hits("12345").is_empty());
        // Remote ports count too (DNS out).
        assert_eq!(hits("53"), vec!["Core Networking - DNS (UDP-Out)"]);
        assert_eq!(hits("node.exe").len(), 2);
        assert_eq!(hits("docker").len(), 1);
        assert_eq!(hits("termservice").len(), 2);
        assert_eq!(hits("iphttps").len(), 1);
        assert_eq!(hits("file printer").len(), 4);
        assert_eq!(hits("").len(), rules.len());
        // A number never matches as a substring of another port.
        assert!(hits("543").is_empty());
    }

    #[test]
    fn chips() {
        let rules = rules();
        let n = |s: &RulesState| rules.iter().filter(|r| s.matches(r)).count();
        let all = RulesState::default();
        assert_eq!(n(&all), rules.len());
        let inbound = RulesState {
            outbound: false,
            ..Default::default()
        };
        let outbound = RulesState {
            inbound: false,
            ..Default::default()
        };
        assert_eq!(n(&inbound) + n(&outbound), rules.len());
        assert_eq!(n(&outbound), 4);
        let block = RulesState {
            allow: false,
            ..Default::default()
        };
        assert_eq!(n(&block), 3);
        let enabled = RulesState {
            enabled_only: true,
            ..Default::default()
        };
        assert_eq!(n(&enabled), rules.len() - 3);
        assert_eq!(rules.len(), 29);
    }

    #[test]
    fn labels() {
        let rules = rules();
        let by_name = |name: &str| rules.iter().find(|r| r.name == name).unwrap();
        assert_eq!(
            program_label(by_name("Docker Desktop Backend")),
            "com.docker.backend.exe"
        );
        assert_eq!(
            program_label(by_name("PostgreSQL 17 (TCP-In)")),
            "Any program"
        );
        assert_eq!(
            program_label(by_name("File and Printer Sharing (SMB-In)")),
            "System"
        );
        assert_eq!(ports_label("*"), "Any");
        assert_eq!(ports_label(""), "Any");
        assert_eq!(ports_label("80,443"), "80, 443");
        assert_eq!(ports_label("RPC"), "RPC");
    }

    #[test]
    fn sorting() {
        let mut rules = rules();
        rules.sort_by(|a, b| compare_rules(a, b, FwSort::Name));
        assert!(rules
            .windows(2)
            .all(|w| w[0].name.to_lowercase() <= w[1].name.to_lowercase()));
        rules.sort_by(|a, b| compare_rules(a, b, FwSort::Ports));
        assert_eq!(ports_label(&rules[0].local_ports), "Any");
        assert_eq!(rules.last().unwrap().local_ports, "IPHTTPS");
        rules.sort_by(|a, b| compare_rules(a, b, FwSort::Action));
        assert!(rules[0].allow && !rules.last().unwrap().allow);
        rules.sort_by(|a, b| compare_rules(a, b, FwSort::Enabled));
        assert!(rules[0].enabled && !rules.last().unwrap().enabled);
    }

    #[test]
    fn column_layout() {
        let at = layout_columns(10.0, 1000.0, &[0.0, 100.0, 200.0]);
        assert_eq!(at, vec![(10.0, 700.0), (710.0, 100.0), (810.0, 200.0)]);
        // Too narrow: the flexible column keeps a minimum.
        let at = layout_columns(0.0, 200.0, &[0.0, 100.0, 200.0]);
        assert_eq!(at[0].1, 80.0);
    }
}
