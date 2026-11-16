//! The details side panel of the Listening view, and the modal dialogs:
//! end process / stop service confirmation, the port test and "clear history".

use super::app::{App, Tab};
use super::theme::{pal, pal_ctx, regular, semibold, Icon};
use super::widgets;
use super::worker::{self, ProbeSlot};
use crate::actions;
use crate::diff::RowState;
use crate::exposure::{self, Exposure, ExposureInfo};
use crate::model::{FwRule, Proto, Scope};
use crate::util::{fmt_age, fmt_time};
use crate::view::{self, ListenerRow};
use eframe::egui::{
    self, vec2, Align, Color32, CornerRadius, Frame, Layout, Margin, RichText, Sense, Stroke, Ui,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Most "also serving" lines listed in a confirmation before summarising.
const MAX_LISTED_PORTS: usize = 8;
/// Most firewall rules listed in the details panel.
const MAX_LISTED_RULES: usize = 8;

/// The one modal dialog that can be open.
pub enum Dialog {
    None,
    EndProcess {
        pid: u32,
        name: String,
        /// Everything this process is serving.
        ports: Vec<String>,
        system: bool,
    },
    StopService {
        service: String,
        display: String,
        process: String,
        pid: u32,
        ports: Vec<String>,
    },
    Probe {
        addr: SocketAddr,
        slot: ProbeSlot,
    },
    ClearHistory,
}

impl Dialog {
    pub fn is_open(&self) -> bool {
        !matches!(self, Dialog::None)
    }
}

/// The colour of an exposure badge: loopback is calm, blocked neutral, open stands out.
pub(super) fn exposure_color(info: &ExposureInfo, p: &super::theme::Palette) -> Color32 {
    match info.exposure {
        Exposure::LoopbackOnly => p.info,
        Exposure::Blocked => p.muted,
        Exposure::Network => p.warn,
        Exposure::Allowed(_) if info.reachable_now => p.danger,
        Exposure::Allowed(_) => p.warn,
    }
}

/// Why a process cannot be ended from here, if it cannot.
pub(super) fn end_blocked_reason(pid: u32) -> Option<&'static str> {
    match pid {
        0 => Some("PID 0 is the idle process: a placeholder of Windows that cannot be ended."),
        4 => Some(
            "System (PID 4) is the Windows kernel. It cannot be ended; stop the service or \
             feature that uses the port instead.",
        ),
        _ => None,
    }
}

/// Where "Test port" connects: the loopback address for sockets bound to
/// every interface or to loopback, otherwise the bound address itself.
pub(super) fn probe_target(row: &ListenerRow) -> SocketAddr {
    let l = &row.listener;
    let ip = match l.scope() {
        Scope::Specific | Scope::Loopback => l.addr,
        Scope::AllInterfaces => {
            if l.is_v6() {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            } else {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            }
        }
    };
    SocketAddr::new(ip, l.port)
}

/// One line for a firewall rule: `Allow · In · Private` / `Block · Out · disabled`.
pub(super) fn rule_summary(rule: &FwRule) -> String {
    let mut s = format!(
        "{} · {} · {}",
        if rule.allow { "Allow" } else { "Block" },
        if rule.inbound { "In" } else { "Out" },
        rule.profiles.label()
    );
    if !rule.enabled {
        s.push_str(" · disabled");
    }
    s
}

/// `first` lines of `items`, then "and N more".
pub(super) fn listed(items: &[String], first: usize) -> Vec<String> {
    let mut out: Vec<String> = items.iter().take(first).cloned().collect();
    if items.len() > first {
        out.push(format!("and {} more", items.len() - first));
    }
    out
}

impl App {
    /// True (after telling the user) when an action must not run: the demo
    /// never touches the system.
    pub(super) fn demo_blocked(&mut self) -> bool {
        if self.sh.demo {
            self.sh.toast("Not available in the demo.", false);
        }
        self.sh.demo
    }

    pub(super) fn copy(&mut self, ctx: &egui::Context, text: String, what: &str) {
        ctx.copy_text(text);
        self.sh.toast(format!("Copied {what}."), false);
    }

    /// Opens the Port check tab for this port.
    pub(super) fn open_port_check(&mut self, port: u16, proto: Proto) {
        self.tab = Tab::Lookup;
        self.sh.search.clear();
        self.lookup.set_port(port, proto);
    }

    pub(super) fn watch_port(&mut self, port: u16) {
        if self.sh.settings.watched_ports.contains(&port) {
            self.sh
                .toast(format!("Port {port} is already on the watch list."), false);
            return;
        }
        self.sh.settings.watched_ports.push(port);
        self.sh.settings.watched_ports.sort_unstable();
        self.sh.touch_settings();
        self.sh.toast(
            format!("Watching port {port}: you get an alert when it is taken."),
            false,
        );
    }

    pub(super) fn ask_end_process(&mut self, row: &ListenerRow) {
        self.dialog = Dialog::EndProcess {
            pid: row.listener.pid,
            name: row.proc.display_name(),
            ports: view::other_ports_of(&self.rows, row.listener.pid),
            system: row.proc.is_system,
        };
    }

    fn start_probe(&mut self, ctx: &egui::Context, row: &ListenerRow) {
        if self.demo_blocked() {
            return;
        }
        let addr = probe_target(row);
        self.dialog = Dialog::Probe {
            addr,
            slot: worker::spawn_probe(ctx, addr, self.sh.settings.probe_non_local),
        };
    }

    /// The details side panel for the selected listener.
    pub(super) fn details_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let full = ui.max_rect();
        ui.painter().vline(
            full.left() - 18.0,
            full.y_range().expand(18.0),
            Stroke::new(1.0_f32, p.border),
        );
        let Some(key) = self.listen.selected else {
            return;
        };
        let now = self.clock();
        let found = self
            .ltrack
            .rows(now)
            .into_iter()
            .find(|(k, _, _)| **k == key)
            .map(|(_, row, state)| (row.clone(), state));
        let Some((row, state)) = found else {
            self.listen.selected = None;
            return;
        };
        let closed = matches!(state, RowState::Closed(_));
        let l = row.listener.clone();
        let name = row.proc.display_name();
        self.ensure_icons(&ctx, &[row.proc.path.as_str()]);

        // ---- Header -----------------------------------------------------------------
        let mut close = false;
        ui.horizontal(|ui| {
            ui.label(RichText::new("Details").font(semibold(13.0)).color(p.faint));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if widgets::icon_button(ui, Icon::CLOSE, "Close (Esc)").clicked() {
                    close = true;
                }
            });
        });
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(vec2(52.0, 52.0), Sense::hover());
            widgets::program_icon(ui, rect, &name, self.icon(&row.proc.path));
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.add(egui::Label::new(RichText::new(&name).font(semibold(17.0))).wrap());
                let sub = if !row.proc.description.is_empty() {
                    row.proc.description.clone()
                } else if !row.proc.company.is_empty() {
                    row.proc.company.clone()
                } else {
                    format!("PID {}", l.pid)
                };
                ui.add(egui::Label::new(RichText::new(sub).color(p.muted)).wrap());
            });
        });
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = vec2(6.0, 6.0);
            widgets::badge(ui, &format!("{} {}", l.proto.label(), l.port), p.accent);
            widgets::badge(ui, &row.exposure.badge(), exposure_color(&row.exposure, &p))
                .on_hover_text(row.exposure.explain());
            if row.proc.is_system {
                widgets::badge(ui, "Windows", p.muted)
                    .on_hover_text("One of Windows' own processes or services.");
            }
            if closed {
                widgets::badge(ui, "Just closed", p.danger);
            }
        });
        ui.add_space(2.0);

        // ---- Main actions -----------------------------------------------------------
        let blocked = end_blocked_reason(l.pid);
        ui.horizontal(|ui| {
            let end = widgets::danger_button(
                ui,
                &Icon::STOP.with("End process"),
                blocked.is_none() && !closed,
            )
            .on_hover_text("Ends the process after a confirmation")
            .on_disabled_hover_text(blocked.unwrap_or("The socket has already closed."));
            if end.clicked() {
                self.ask_end_process(&row);
            }
            if l.proto == Proto::Tcp
                && widgets::ghost_button(ui, &Icon::GLOBE.with("Open in browser"))
                    .on_hover_text(row.url())
                    .clicked()
                && !self.demo_blocked()
            {
                if let Err(e) = actions::open_url(&row.url()) {
                    self.sh.toast(e, true);
                }
            }
        });
        if let Some(reason) = blocked {
            ui.add(egui::Label::new(RichText::new(reason).size(12.0).color(p.faint)).wrap());
        }
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = vec2(6.0, 6.0);
            let test = widgets::small_button_enabled(
                ui,
                &Icon::PLAY.with("Test port"),
                l.proto == Proto::Tcp,
            )
            .on_hover_text(format!(
                "Connects to {} and shows what answers",
                probe_target(&row)
            ))
            .on_disabled_hover_text("Only TCP ports can be tested by connecting.");
            if test.clicked() {
                self.start_probe(&ctx, &row);
            }
            if widgets::small_button(ui, &Icon::TARGET.with("Port check"))
                .on_hover_text("Everything known about this port number")
                .clicked()
            {
                self.open_port_check(l.port, l.proto);
            }
            let watched = self.sh.settings.watched_ports.contains(&l.port);
            if widgets::small_button(
                ui,
                &Icon::BELL.with(if watched { "Watched" } else { "Watch port" }),
            )
            .on_hover_text("Alert me when this port is taken again")
            .clicked()
            {
                self.watch_port(l.port);
            }
            let has_path = !row.proc.path.is_empty();
            let folder = widgets::small_button_enabled(
                ui,
                &Icon::FOLDER_OPEN.with("File location"),
                has_path,
            )
            .on_disabled_hover_text("The program path is not known.");
            if folder.clicked() && !self.demo_blocked() {
                if let Err(e) = actions::open_file_location(&row.proc.path) {
                    self.sh.toast(e, true);
                }
            }
        });
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            ui.label(
                RichText::new(Icon::COPY.with("Copy"))
                    .size(12.5)
                    .color(p.faint),
            );
            if widgets::small_button(ui, "Line")
                .on_hover_text(row.as_text())
                .clicked()
            {
                self.copy(&ctx, row.as_text(), "the line");
            }
            if widgets::small_button(ui, "host:port")
                .on_hover_text(row.host_port())
                .clicked()
            {
                self.copy(&ctx, row.host_port(), "the address");
            }
            if l.proto == Proto::Tcp
                && widgets::small_button(ui, "curl")
                    .on_hover_text(row.curl_line())
                    .clicked()
            {
                self.copy(&ctx, row.curl_line(), "the curl command");
            }
        });
        ui.add_space(2.0);
        widgets::divider(ui);
        ui.add_space(2.0);

        // ---- Facts ------------------------------------------------------------------
        let wall = self.wall_now();
        let mut stop: Option<(String, String)> = None;
        let mut goto_rules = false;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                let mut listening = format!("{}  ({})", l.endpoint(), row.scope_label());
                if let Some(created) = l.created {
                    listening.push_str(&format!("\nsince {}", fmt_time(created)));
                }
                widgets::field(ui, "Listening on", &listening);
                widgets::field(ui, "Who can reach it", &row.exposure.explain());
                if let Some(usual) = row.well_known {
                    widgets::field(ui, "Usually on this port", usual);
                }
                let who = if row.proc.user.is_empty() {
                    format!("PID {}", l.pid)
                } else {
                    format!("PID {} · {}", l.pid, row.proc.user)
                };
                widgets::field(ui, "Process", &who);
                if row.proc.limited {
                    ui.add(
                        egui::Label::new(
                            RichText::new(
                                "Some details are hidden: this process needs administrator \
                                 rights to inspect.",
                            )
                            .size(12.0)
                            .color(p.warn),
                        )
                        .wrap(),
                    );
                }
                if l.pid != 4 && l.pid != 0 {
                    widgets::field(ui, "Path", &row.proc.path);
                    widgets::field(ui, "Command line", &row.proc.cmdline);
                }
                if let Some(started) = row.proc.started {
                    widgets::field(
                        ui,
                        "Started",
                        &format!("{}  ({} ago)", fmt_time(started), fmt_age(wall - started)),
                    );
                }
                if let Some(parent) = row.proc.parent {
                    let text = if row.proc.parent_name.is_empty() {
                        format!("PID {parent}")
                    } else {
                        format!("{} (PID {parent})", row.proc.parent_name)
                    };
                    widgets::field(ui, "Parent", &text);
                }

                if !row.proc.services.is_empty() {
                    ui.label(
                        RichText::new("Services in this process")
                            .size(12.0)
                            .color(p.faint),
                    );
                    for s in &row.proc.services {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 0.0;
                                ui.set_width(ui.available_width() - 64.0);
                                ui.add(egui::Label::new(&s.display).truncate());
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&s.name).size(12.0).color(p.muted),
                                    )
                                    .truncate(),
                                );
                            });
                            if widgets::small_button(ui, "Stop")
                                .on_hover_text(format!("Stop the service {}", s.name))
                                .clicked()
                            {
                                stop = Some((s.name.clone(), s.display.clone()));
                            }
                        });
                    }
                    ui.add_space(2.0);
                }

                // Firewall rules that mention this port or this program.
                let fw = &self.sys.firewall;
                let mut idx: Vec<usize> = row
                    .exposure
                    .allow_rules
                    .iter()
                    .chain(row.exposure.block_rules.iter())
                    .copied()
                    .collect();
                for i in exposure::rules_for_port(fw, l.proto, l.port)
                    .into_iter()
                    .chain(exposure::rules_for_program(fw, &row.proc.path))
                {
                    if !idx.contains(&i) {
                        idx.push(i);
                    }
                }
                ui.label(RichText::new("Firewall rules").size(12.0).color(p.faint));
                if !fw.available {
                    ui.label(RichText::new("Windows Firewall could not be read.").color(p.faint));
                } else if idx.is_empty() {
                    ui.add(
                        egui::Label::new(
                            RichText::new("No rule mentions this port or program.").color(p.faint),
                        )
                        .wrap(),
                    );
                } else {
                    for &i in idx.iter().take(MAX_LISTED_RULES) {
                        let Some(rule) = fw.rules.get(i) else {
                            continue;
                        };
                        Frame::new()
                            .fill(p.card)
                            .stroke(Stroke::new(1.0_f32, p.border))
                            .corner_radius(CornerRadius::same(8))
                            .inner_margin(Margin::symmetric(10, 6))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.spacing_mut().item_spacing.y = 1.0;
                                ui.add(egui::Label::new(&rule.name).truncate());
                                let color = if !rule.enabled {
                                    p.faint
                                } else if rule.allow {
                                    p.accent
                                } else {
                                    p.danger
                                };
                                ui.label(RichText::new(rule_summary(rule)).size(12.0).color(color));
                            });
                    }
                    if idx.len() > MAX_LISTED_RULES {
                        ui.label(
                            RichText::new(format!("and {} more", idx.len() - MAX_LISTED_RULES))
                                .color(p.muted),
                        );
                    }
                    if widgets::small_button(ui, "Show in Rules & forwards").clicked() {
                        goto_rules = true;
                    }
                }
                ui.add_space(2.0);

                let me = format!("{} {}", l.proto.label(), l.endpoint());
                let others: Vec<String> = view::other_ports_of(&self.rows, l.pid)
                    .into_iter()
                    .filter(|o| *o != me)
                    .collect();
                if !others.is_empty() {
                    widgets::field(
                        ui,
                        "Also listening in this process",
                        &listed(&others, 12).join("\n"),
                    );
                }
                ui.add_space(8.0);
            });

        if let Some((service, display)) = stop {
            self.dialog = Dialog::StopService {
                service,
                display,
                process: name,
                pid: l.pid,
                ports: view::other_ports_of(&self.rows, l.pid),
            };
        }
        if goto_rules {
            self.tab = Tab::Rules;
            self.rules.show_firewall();
            self.sh.search = l.port.to_string();
        }
        if close {
            self.listen.selected = None;
        }
    }

    // ----------------------------------------------------------------------------------
    // Dialogs
    // ----------------------------------------------------------------------------------

    pub(super) fn dialogs_ui(&mut self, ctx: &egui::Context) {
        let p = pal_ctx(ctx);
        let mut close = false;
        let mut confirm = false;
        let port_list = |ui: &mut Ui, ports: &[String]| {
            Frame::new()
                .fill(p.bg)
                .stroke(Stroke::new(1.0_f32, p.border))
                .corner_radius(CornerRadius::same(10))
                .inner_margin(Margin::symmetric(12, 10))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 4.0;
                    for line in listed(ports, MAX_LISTED_PORTS) {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(Icon::PLUG.glyph()).size(12.0).color(p.faint));
                            ui.label(RichText::new(line).font(regular(13.5)));
                        });
                    }
                });
        };
        match &self.dialog {
            Dialog::None => return,
            Dialog::EndProcess {
                pid,
                name,
                ports,
                system,
            } => {
                let dismissed = widgets::modal(ctx, "end-process", 460.0, |ui| {
                    widgets::modal_title(ui, &format!("End {name}?"));
                    widgets::para(
                        ui,
                        &format!(
                            "PID {pid} is ended at once, without a chance to save its work. \
                             Everything it is serving stops:"
                        ),
                    );
                    ui.add_space(4.0);
                    if ports.is_empty() {
                        widgets::para(ui, "It is not listening on any port right now.");
                    } else {
                        port_list(ui, ports);
                    }
                    if *system {
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(Icon::WARNING.glyph()).color(p.warn));
                            ui.add(
                                egui::Label::new(
                                    RichText::new(
                                        "This is one of Windows' own processes. Ending it can \
                                         log you out, break networking or restart the PC.",
                                    )
                                    .color(p.warn),
                                )
                                .wrap(),
                            );
                        });
                    }
                    ui.add_space(14.0);
                    widgets::button_row(ui, |ui| {
                        if widgets::danger_button(ui, "End process", true).clicked() {
                            confirm = true;
                        }
                        if widgets::ghost_button(ui, "Cancel").clicked() {
                            close = true;
                        }
                    });
                });
                close |= dismissed;
            }
            Dialog::StopService {
                service,
                display,
                process,
                pid,
                ports,
            } => {
                let dismissed = widgets::modal(ctx, "stop-service", 460.0, |ui| {
                    widgets::modal_title(ui, &format!("Stop the service {service}?"));
                    widgets::para(
                        ui,
                        &format!(
                            "{display} runs inside {process} (PID {pid}). Windows is asked to \
                             stop it; it may start again by itself or at the next sign-in. \
                             The process is listening on:"
                        ),
                    );
                    ui.add_space(4.0);
                    port_list(ui, ports);
                    ui.add_space(6.0);
                    ui.add(
                        egui::Label::new(
                            RichText::new(
                                "Stopping a service needs administrator rights, and services \
                                 that other services depend on may refuse.",
                            )
                            .size(12.5)
                            .color(p.faint),
                        )
                        .wrap(),
                    );
                    ui.add_space(14.0);
                    widgets::button_row(ui, |ui| {
                        if widgets::danger_button(ui, "Stop service", true).clicked() {
                            confirm = true;
                        }
                        if widgets::ghost_button(ui, "Cancel").clicked() {
                            close = true;
                        }
                    });
                });
                close |= dismissed;
            }
            Dialog::Probe { addr, slot } => {
                let result = slot.lock().ok().and_then(|r| r.clone());
                let dismissed = widgets::modal(ctx, "probe", 480.0, |ui| {
                    widgets::modal_title(ui, &format!("Test TCP {addr}"));
                    match &result {
                        None => {
                            ui.horizontal(|ui| {
                                ui.add(egui::Spinner::new().size(18.0).color(p.accent));
                                ui.label(RichText::new("Connecting…").color(p.muted));
                            });
                        }
                        Some(r) if r.connected => {
                            ui.horizontal(|ui| {
                                widgets::badge(ui, "Connected", p.accent);
                                ui.label(format!("in {} ms", r.elapsed_ms));
                                if r.http_reply {
                                    widgets::badge(ui, "Answers HTTP", p.info);
                                }
                            });
                            ui.add_space(4.0);
                            if r.banner_text.trim().is_empty() {
                                widgets::para(
                                    ui,
                                    "The port accepted the connection but sent nothing, neither \
                                     on its own nor in reply to a plain HTTP request.",
                                );
                            } else {
                                widgets::para(
                                    ui,
                                    if r.http_reply {
                                        "Reply to a minimal HTTP request:"
                                    } else {
                                        "The server greeted with:"
                                    },
                                );
                                Frame::new()
                                    .fill(p.bg)
                                    .stroke(Stroke::new(1.0_f32, p.border))
                                    .corner_radius(CornerRadius::same(10))
                                    .inner_margin(Margin::symmetric(12, 10))
                                    .show(ui, |ui| {
                                        ui.set_width(ui.available_width());
                                        egui::ScrollArea::vertical().max_height(220.0).show(
                                            ui,
                                            |ui| {
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new(r.banner_text.trim_end())
                                                            .monospace(),
                                                    )
                                                    .wrap()
                                                    .selectable(true),
                                                );
                                            },
                                        );
                                    });
                            }
                        }
                        Some(r) => {
                            ui.horizontal(|ui| {
                                widgets::badge(ui, "No connection", p.danger);
                                if r.elapsed_ms > 0 {
                                    ui.label(
                                        RichText::new(format!("after {} ms", r.elapsed_ms))
                                            .color(p.muted),
                                    );
                                }
                            });
                            ui.add_space(4.0);
                            widgets::para(
                                ui,
                                r.error
                                    .as_deref()
                                    .unwrap_or("The connection could not be made."),
                            );
                        }
                    }
                    ui.add_space(14.0);
                    widgets::button_row(ui, |ui| {
                        if widgets::primary_button(ui, "Close", true).clicked() {
                            close = true;
                        }
                        if let Some(r) = &result {
                            if !r.banner_text.trim().is_empty()
                                && widgets::ghost_button(ui, "Copy reply").clicked()
                            {
                                ui.ctx().copy_text(r.banner_text.clone());
                            }
                        }
                    });
                });
                close |= dismissed;
            }
            Dialog::ClearHistory => {
                let count = self.history.events.len();
                let dismissed = widgets::modal(ctx, "clear-history", 420.0, |ui| {
                    widgets::modal_title(ui, "Clear the history?");
                    widgets::para(
                        ui,
                        &format!(
                            "{count} recorded event{} will be removed, including the saved log \
                             file. The watch list stays.",
                            if count == 1 { "" } else { "s" }
                        ),
                    );
                    ui.add_space(14.0);
                    widgets::button_row(ui, |ui| {
                        if widgets::danger_button(ui, "Clear history", true).clicked() {
                            confirm = true;
                        }
                        if widgets::ghost_button(ui, "Cancel").clicked() {
                            close = true;
                        }
                    });
                });
                close |= dismissed;
            }
        }
        if confirm {
            match std::mem::replace(&mut self.dialog, Dialog::None) {
                Dialog::EndProcess { pid, name, .. } => {
                    if !self.demo_blocked() {
                        worker::spawn_action(ctx, &self.notices, move || {
                            actions::end_process(pid).map(|()| format!("Ended {name} (PID {pid})."))
                        });
                    }
                }
                Dialog::StopService { service, .. } => {
                    if !self.demo_blocked() {
                        worker::spawn_action(ctx, &self.notices, move || {
                            actions::stop_service(&service)
                                .map(|()| format!("Stopped the service {service}."))
                        });
                    }
                }
                Dialog::ClearHistory => {
                    self.history.clear();
                    self.sh.toast("History cleared.", false);
                }
                Dialog::Probe { .. } | Dialog::None => {}
            }
        } else if close {
            self.dialog = Dialog::None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FwProto, Listener, ProcInfo, Profiles};
    use crate::ui::theme::palette;

    fn row(addr: &str, port: u16, proto: Proto) -> ListenerRow {
        let listener = Listener {
            proto,
            addr: addr.parse().unwrap(),
            port,
            pid: 77,
            created: None,
        };
        ListenerRow {
            exposure: exposure::classify(&listener, None, &Default::default()),
            listener,
            proc: ProcInfo::default(),
            well_known: None,
        }
    }

    #[test]
    fn probe_goes_to_loopback_unless_bound_elsewhere() {
        assert_eq!(
            probe_target(&row("0.0.0.0", 3000, Proto::Tcp)).to_string(),
            "127.0.0.1:3000"
        );
        assert_eq!(
            probe_target(&row("::", 3000, Proto::Tcp)).to_string(),
            "[::1]:3000"
        );
        assert_eq!(
            probe_target(&row("127.0.0.2", 81, Proto::Tcp)).to_string(),
            "127.0.0.2:81"
        );
        assert_eq!(
            probe_target(&row("192.0.2.10", 139, Proto::Tcp)).to_string(),
            "192.0.2.10:139"
        );
    }

    #[test]
    fn system_processes_cannot_be_ended() {
        assert!(end_blocked_reason(0).is_some());
        assert!(end_blocked_reason(4).is_some());
        assert!(end_blocked_reason(5120).is_none());
    }

    #[test]
    fn long_lists_are_summarised() {
        let items: Vec<String> = (0..11).map(|i| format!("TCP 0.0.0.0:{i}")).collect();
        let out = listed(&items, 8);
        assert_eq!(out.len(), 9);
        assert_eq!(out[8], "and 3 more");
        assert_eq!(listed(&items[..3], 8).len(), 3);
    }

    #[test]
    fn rule_summaries() {
        let mut rule = FwRule {
            name: "x".into(),
            group: String::new(),
            description: String::new(),
            enabled: true,
            inbound: true,
            allow: true,
            proto: FwProto::Tcp,
            local_ports: "80".into(),
            remote_ports: "*".into(),
            local_addrs: "*".into(),
            remote_addrs: "*".into(),
            program: String::new(),
            service: String::new(),
            profiles: Profiles::PRIVATE,
        };
        assert_eq!(rule_summary(&rule), "Allow · In · Private");
        rule.enabled = false;
        rule.allow = false;
        rule.inbound = false;
        rule.profiles = Profiles::ALL;
        assert_eq!(rule_summary(&rule), "Block · Out · All profiles · disabled");
    }

    #[test]
    fn exposure_colours_differ() {
        let p = palette(true);
        let loopback = row("127.0.0.1", 1, Proto::Tcp);
        let network = row("0.0.0.0", 1, Proto::Tcp);
        assert_ne!(
            exposure_color(&loopback.exposure, &p),
            exposure_color(&network.exposure, &p)
        );
    }
}
