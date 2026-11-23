//! Tools: serve a folder over HTTP and forward a local port. Both run inside
//! SocketForge, need no administrator rights, change nothing in Windows and
//! stop when they are stopped or SocketForge exits.

use super::app::App;
use super::hosts_view::fmt_bytes;
use super::lookup_view::parse_port;
use super::theme::{pal, regular, semibold, Icon, Palette};
use super::widgets;
use crate::actions;
use crate::relay::{self, Relay, RelayStats};
use crate::serve::{FolderServer, RequestLog, Wake};
use crate::util::fmt_clock;
use eframe::egui::{
    self, vec2, Align, CornerRadius, FontFamily, FontId, Frame, Layout, Margin, RichText, Stroke,
    Ui,
};
use std::path::Path;
use std::sync::Arc;

/// Requests shown under a running folder server.
const REQUESTS_SHOWN: usize = 8;

/// What the window shows for a running folder server.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct ServeInfo {
    pub url: String,
    pub folder: String,
    /// Addresses for other devices; empty when only this PC may connect.
    pub lan_urls: Vec<String>,
    pub served: u64,
    pub requests: Vec<RequestLog>,
}

/// What the window shows for one forward.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct ForwardInfo {
    pub listen: String,
    pub target: String,
    pub lan: bool,
    pub stats: RelayStats,
}

#[derive(Default)]
pub struct ToolsState {
    folder: String,
    port: String,
    lan: bool,
    server: Option<FolderServer>,
    /// Addresses of this PC, read when a server or forward starts.
    lan_ips: Vec<String>,
    fwd_port: String,
    fwd_target: String,
    fwd_lan: bool,
    relays: Vec<Relay>,
    /// Invented state for `--demo` and the screenshots.
    demo_serve: Option<ServeInfo>,
    demo_forwards: Vec<ForwardInfo>,
    /// The saved values have been copied into the boxes.
    primed: bool,
    /// Draw the forward card first (the `forward` screenshot).
    forward_first: bool,
}

impl ToolsState {
    /// Servers and forwards that are running.
    pub fn running(&self) -> usize {
        self.server.is_some() as usize
            + self.relays.len()
            + self.demo_serve.is_some() as usize
            + self.demo_forwards.len()
    }
}

/// A path without the `\\?\` prefix that Windows adds to exact paths.
pub(super) fn display_path(path: &Path) -> String {
    let s = path.to_string_lossy();
    match s.strip_prefix("\\\\?\\UNC\\") {
        Some(rest) => format!("\\\\{rest}"),
        None => s.strip_prefix("\\\\?\\").unwrap_or(&s).to_string(),
    }
}

/// Reads the port box of a tool: a number from 1 to 65535.
pub(super) fn tool_port(text: &str) -> Result<u16, String> {
    match parse_port(text) {
        Ok(0) => Err("Port 0 cannot be used here.".into()),
        Ok(p) => Ok(p),
        Err(e) if e.is_empty() => Err("Type a port number, for example 8080.".into()),
        Err(e) => Err(e),
    }
}

/// One line about what a forward has done so far.
pub(super) fn forward_summary(stats: &RelayStats) -> String {
    let mut s = format!(
        "{} open · {} connection{} so far · {} sent · {} received",
        stats.active,
        stats.total,
        if stats.total == 1 { "" } else { "s" },
        fmt_bytes(stats.sent),
        fmt_bytes(stats.received)
    );
    if stats.failed > 0 {
        s.push_str(&format!(" · {} failed", stats.failed));
    }
    s
}

/// The colour family of an HTTP status.
fn status_color(status: u16, p: &Palette) -> egui::Color32 {
    match status {
        200..=299 => p.accent,
        300..=399 => p.info,
        400..=499 => p.warn,
        _ => p.danger,
    }
}

fn mono(size: f32) -> FontId {
    FontId::new(size, FontFamily::Monospace)
}

fn card(ui: &mut Ui, p: &Palette, add: impl FnOnce(&mut Ui)) {
    Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(18, 16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui);
        });
}

fn card_title(ui: &mut Ui, p: &Palette, icon: Icon, title: &str, text: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(icon.glyph()).size(16.0).color(p.accent));
        ui.label(RichText::new(title).font(semibold(16.5)));
    });
    ui.add(egui::Label::new(RichText::new(text).color(p.muted)).wrap());
    ui.add_space(6.0);
}

fn small_label(ui: &mut Ui, p: &Palette, text: &str) {
    ui.label(RichText::new(text).size(12.5).color(p.muted));
}

impl App {
    pub(super) fn tools_count(&self) -> Option<usize> {
        let n = self.tools.running();
        (n > 0).then_some(n)
    }

    /// Fills the page with invented servers for the screenshots.
    pub(super) fn tools_apply_view(&mut self, view: &str) {
        self.tools.forward_first = view == "forward";
        if !self.sh.demo {
            return;
        }
        let t = &mut self.tools;
        t.folder = "C:\\Projects\\storefront\\dist".into();
        t.port = "8080".into();
        t.fwd_port = "15432".into();
        t.fwd_target = "staging-db.example.test:5432".into();
        let now = crate::demo::NOW;
        let req = |ago: i64, path: &str, status: u16, bytes: u64| RequestLog {
            time: now - ago,
            method: "GET".into(),
            path: path.into(),
            status,
            bytes,
            remote: false,
        };
        t.demo_serve = Some(ServeInfo {
            url: "http://localhost:8080/".into(),
            folder: t.folder.clone(),
            lan_urls: Vec::new(),
            served: 42,
            requests: vec![
                req(2, "/assets/logo.svg", 200, 3_412),
                req(2, "/assets/app.css", 200, 18_240),
                req(2, "/assets/app.js", 200, 214_866),
                req(3, "/", 200, 1_904),
                req(41, "/favicon.ico", 404, 152),
                req(44, "/checkout/", 200, 2_310),
            ],
        });
        t.demo_forwards = vec![
            ForwardInfo {
                listen: "127.0.0.1:15432".into(),
                target: "staging-db.example.test:5432".into(),
                lan: false,
                stats: RelayStats {
                    active: 2,
                    total: 17,
                    sent: 48_211,
                    received: 1_932_774,
                    failed: 0,
                    last_error: None,
                },
            },
            ForwardInfo {
                listen: "0.0.0.0:8088".into(),
                target: "127.0.0.1:3000".into(),
                lan: true,
                stats: RelayStats {
                    active: 0,
                    total: 3,
                    sent: 2_144,
                    received: 96_480,
                    failed: 1,
                    last_error: Some("Nothing is listening on 127.0.0.1:3000.".into()),
                },
            },
        ];
    }

    fn tools_prime(&mut self) {
        if self.tools.primed {
            return;
        }
        self.tools.primed = true;
        if self.sh.demo {
            return;
        }
        let s = &self.sh.settings;
        let t = &mut self.tools;
        t.folder = s.serve_folder.clone();
        t.port = s.serve_port.to_string();
        t.fwd_port = s.forward_port.to_string();
        t.fwd_target = s.forward_target.clone();
    }

    fn lan_addresses() -> Vec<String> {
        actions::own_addresses()
            .into_iter()
            .filter(|ip| ip.is_ipv4() && !ip.is_loopback() && !ip.is_unspecified())
            .map(|ip| ip.to_string())
            .collect()
    }

    fn serve_info(&self) -> Option<ServeInfo> {
        if let Some(info) = &self.tools.demo_serve {
            return Some(info.clone());
        }
        let server = self.tools.server.as_ref()?;
        Some(ServeInfo {
            url: server.url(),
            folder: display_path(server.root()),
            lan_urls: if server.lan() {
                self.tools
                    .lan_ips
                    .iter()
                    .map(|ip| format!("http://{ip}:{}/", server.port()))
                    .collect()
            } else {
                Vec::new()
            },
            served: server.served(),
            requests: server.requests(),
        })
    }

    fn forward_infos(&self) -> Vec<ForwardInfo> {
        if !self.tools.demo_forwards.is_empty() {
            return self.tools.demo_forwards.clone();
        }
        self.tools
            .relays
            .iter()
            .map(|r| ForwardInfo {
                listen: format!(
                    "{}:{}",
                    if r.lan() { "0.0.0.0" } else { "127.0.0.1" },
                    r.port()
                ),
                target: r.target().label(),
                lan: r.lan(),
                stats: r.stats(),
            })
            .collect()
    }

    pub(super) fn tools_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        self.tools_prime();
        widgets::page_header(
            ui,
            "Tools",
            "Helpers that run inside SocketForge, for as long as it is open. Nothing in \
             Windows is changed.",
            |_| {},
        );
        // Byte counters move while connections are open.
        if self.tools.relays.iter().any(|r| r.stats().active > 0) {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if self.tools.forward_first {
                    self.forward_card(ui, &p, &ctx);
                    ui.add_space(12.0);
                    self.serve_card(ui, &p, &ctx);
                } else {
                    self.serve_card(ui, &p, &ctx);
                    ui.add_space(12.0);
                    self.forward_card(ui, &p, &ctx);
                }
                ui.add_space(8.0);
            });
    }

    // ----------------------------------------------------------------------------------
    // Serve a folder
    // ----------------------------------------------------------------------------------

    fn serve_card(&mut self, ui: &mut Ui, p: &Palette, ctx: &egui::Context) {
        let info = self.serve_info();
        let (mut start, mut stop, mut browse) = (false, false, false);
        let mut open: Option<String> = None;
        let mut copy: Option<String> = None;
        card(ui, p, |ui| {
            card_title(
                ui,
                p,
                Icon::GLOBE,
                "Serve a folder over HTTP",
                "Opens a small web server for the files in a folder: handy for trying a built \
                 site, sharing a file with your phone, or testing a page that needs http://.",
            );
            match &info {
                Some(info) => {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        widgets::badge(ui, "RUNNING", p.accent);
                        ui.label(RichText::new(&info.url).font(mono(15.0)).color(p.text));
                        if widgets::small_button(ui, &Icon::GLOBE.with("Open")).clicked() {
                            open = Some(info.url.clone());
                        }
                        if widgets::small_button(ui, &Icon::COPY.with("Copy")).clicked() {
                            copy = Some(info.url.clone());
                        }
                        if widgets::small_button(ui, &Icon::STOP.with("Stop")).clicked() {
                            stop = true;
                        }
                    });
                    ui.add_space(2.0);
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!("Folder: {}", info.folder)).color(p.muted),
                        )
                        .truncate(),
                    );
                    if info.lan_urls.is_empty() {
                        small_label(ui, p, "Only this PC can connect.");
                    } else {
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing.x = 8.0;
                            widgets::badge(ui, "ON THE NETWORK", p.warn).on_hover_text(
                                "Other devices on your network can read every file in this \
                                 folder. Windows Firewall may ask once whether to allow it.",
                            );
                            for url in &info.lan_urls {
                                if ui
                                    .add(
                                        egui::Label::new(
                                            RichText::new(url).font(mono(13.0)).color(p.muted),
                                        )
                                        .sense(egui::Sense::click()),
                                    )
                                    .on_hover_text("Click to copy")
                                    .clicked()
                                {
                                    copy = Some(url.clone());
                                }
                            }
                        });
                    }
                    ui.add_space(6.0);
                    widgets::divider(ui);
                    ui.add_space(4.0);
                    if info.requests.is_empty() {
                        small_label(ui, p, "No requests yet. Open the address in a browser.");
                    } else {
                        small_label(
                            ui,
                            p,
                            &format!(
                                "{} request{} answered. The latest:",
                                info.served,
                                if info.served == 1 { "" } else { "s" }
                            ),
                        );
                        ui.spacing_mut().item_spacing.y = 2.0;
                        for r in info.requests.iter().take(REQUESTS_SHOWN) {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 10.0;
                                ui.label(
                                    RichText::new(fmt_clock(r.time))
                                        .font(mono(12.5))
                                        .color(p.faint),
                                );
                                ui.label(
                                    RichText::new(r.status.to_string())
                                        .font(mono(12.5))
                                        .color(status_color(r.status, p)),
                                );
                                ui.label(RichText::new(&r.method).font(mono(12.5)).color(p.muted));
                                let size = fmt_bytes(r.bytes);
                                let width = (ui.available_width() - 110.0).max(80.0);
                                ui.allocate_ui_with_layout(
                                    vec2(width, 18.0),
                                    Layout::left_to_right(Align::Center),
                                    |ui| {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(&r.path)
                                                    .font(mono(12.5))
                                                    .color(p.text),
                                            )
                                            .truncate(),
                                        );
                                    },
                                );
                                ui.label(RichText::new(size).size(12.5).color(p.faint));
                                if r.remote {
                                    ui.label(
                                        RichText::new("from the network").size(12.0).color(p.warn),
                                    );
                                }
                            });
                        }
                    }
                }
                None => {
                    small_label(ui, p, "Folder");
                    ui.horizontal(|ui| {
                        let width = (ui.available_width() - 150.0).clamp(200.0, 620.0);
                        widgets::text_box(
                            ui,
                            &mut self.tools.folder,
                            width,
                            "C:\\Projects\\site\\dist",
                        );
                        if widgets::ghost_button(ui, &Icon::FOLDER_OPEN.with("Browse…")).clicked()
                        {
                            browse = true;
                        }
                    });
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 10.0;
                        small_label(ui, p, "Port");
                        widgets::text_box(ui, &mut self.tools.port, 70.0, "8080");
                        widgets::checkbox(
                            ui,
                            &mut self.tools.lan,
                            "Let other devices on the network connect",
                        )
                        .on_hover_text(
                            "Off: only this PC can open the address. On: phones and other PCs \
                             on your network can read every file in the folder.",
                        );
                    });
                    ui.add_space(8.0);
                    let problem = if self.tools.folder.trim().is_empty() {
                        Some("Choose the folder to serve.".to_string())
                    } else {
                        tool_port(&self.tools.port).err()
                    };
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 12.0;
                        if widgets::primary_button(
                            ui,
                            &Icon::PLAY.with("Start serving"),
                            problem.is_none(),
                        )
                        .clicked()
                        {
                            start = true;
                        }
                        if let Some(msg) = &problem {
                            ui.label(RichText::new(msg).size(12.5).color(p.faint));
                        }
                    });
                }
            }
        });

        if browse && !self.sh.demo && !self.sh.screenshot {
            if let Some(dir) = rfd::FileDialog::new()
                .set_title("Choose the folder to serve")
                .pick_folder()
            {
                self.tools.folder = dir.to_string_lossy().into_owned();
            }
        }
        if start {
            self.serve_start(ctx);
        }
        if stop {
            if self.sh.demo {
                self.sh.toast("The demo's server is invented.", false);
            } else if let Some(mut server) = self.tools.server.take() {
                let port = server.port();
                server.stop();
                self.sh.toast(
                    format!("Stopped serving. Port {port} is free again."),
                    false,
                );
                self.refresh(false);
            }
        }
        if let Some(url) = open {
            if !self.demo_blocked() {
                if let Err(e) = actions::open_url(&url) {
                    self.sh.toast(e, true);
                }
            }
        }
        if let Some(text) = copy {
            self.copy(ctx, text, "the address");
        }
    }

    fn serve_start(&mut self, ctx: &egui::Context) {
        if self.sh.demo {
            self.sh.toast(
                "Starting is switched off in the demo. No port was opened.",
                false,
            );
            return;
        }
        let port = match tool_port(&self.tools.port) {
            Ok(p) => p,
            Err(e) => return self.sh.toast(e, true),
        };
        let folder = self.tools.folder.trim().trim_matches('"').to_string();
        let wake: Wake = {
            let ctx = ctx.clone();
            Arc::new(move || ctx.request_repaint())
        };
        match FolderServer::start(Path::new(&folder), port, self.tools.lan, Some(wake)) {
            Ok(server) => {
                if self.tools.lan {
                    self.tools.lan_ips = Self::lan_addresses();
                }
                self.sh.toast(format!("Serving at {}", server.url()), false);
                self.sh.settings.serve_folder = display_path(server.root());
                self.sh.settings.serve_port = port;
                self.sh.touch_settings();
                self.tools.server = Some(server);
                self.refresh(false);
            }
            Err(e) => self.sh.toast(e, true),
        }
    }

    // ----------------------------------------------------------------------------------
    // Forward a port
    // ----------------------------------------------------------------------------------

    fn forward_card(&mut self, ui: &mut Ui, p: &Palette, ctx: &egui::Context) {
        let infos = self.forward_infos();
        let mut add = false;
        let mut stop: Option<usize> = None;
        card(ui, p, |ui| {
            card_title(
                ui,
                p,
                Icon::SWITCH,
                "Forward a local port",
                "Listens on a port of this PC and passes every connection on to another \
                 address: reach a database on another machine as localhost, or give a second \
                 port to a local server.",
            );
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 10.0;
                small_label(ui, p, "Listen on port");
                widgets::text_box(ui, &mut self.tools.fwd_port, 70.0, "8081");
                small_label(ui, p, "and send to");
                let width = (ui.available_width() - 20.0).clamp(160.0, 320.0);
                widgets::text_box(
                    ui,
                    &mut self.tools.fwd_target,
                    width,
                    "localhost:3000 or 192.168.1.20:5432",
                );
            });
            ui.add_space(4.0);
            widgets::checkbox(
                ui,
                &mut self.tools.fwd_lan,
                "Let other devices on the network connect",
            )
            .on_hover_text(
                "Off: only programs on this PC can use the forward. On: other devices can \
                 reach the target through this PC.",
            );
            ui.add_space(8.0);
            let problem = match tool_port(&self.tools.fwd_port) {
                Err(e) => Some(e),
                Ok(_) if self.tools.fwd_target.trim().is_empty() => {
                    Some("Type where to send the connections.".to_string())
                }
                Ok(_) => relay::parse_target(&self.tools.fwd_target).err(),
            };
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 12.0;
                if widgets::primary_button(ui, &Icon::ADD.with("Start forward"), problem.is_none())
                    .clicked()
                {
                    add = true;
                }
                if let Some(msg) = &problem {
                    ui.add(
                        egui::Label::new(RichText::new(msg).size(12.5).color(p.faint)).truncate(),
                    );
                }
            });
            if !infos.is_empty() {
                ui.add_space(8.0);
                widgets::divider(ui);
                ui.add_space(4.0);
            }
            for (i, info) in infos.iter().enumerate() {
                ui.allocate_ui_with_layout(
                    vec2(ui.available_width(), 46.0),
                    Layout::left_to_right(Align::Center),
                    |ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 1.0;
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 8.0;
                                ui.label(RichText::new(&info.listen).font(mono(14.0)));
                                ui.label(RichText::new("→").color(p.faint));
                                ui.label(RichText::new(&info.target).font(mono(14.0)));
                                if info.lan {
                                    widgets::badge(ui, "ON THE NETWORK", p.warn);
                                }
                            });
                            let line = match &info.stats.last_error {
                                Some(e) => format!("{} · {e}", forward_summary(&info.stats)),
                                None => forward_summary(&info.stats),
                            };
                            ui.label(RichText::new(line).font(regular(12.5)).color(
                                if info.stats.last_error.is_some() {
                                    p.warn
                                } else {
                                    p.muted
                                },
                            ));
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if widgets::small_button(ui, &Icon::STOP.with("Stop")).clicked() {
                                stop = Some(i);
                            }
                        });
                    },
                );
            }
        });

        if add {
            self.forward_start(ctx);
        }
        if let Some(i) = stop {
            if self.sh.demo {
                self.sh.toast("The demo's forwards are invented.", false);
            } else if i < self.tools.relays.len() {
                let mut relay = self.tools.relays.remove(i);
                let port = relay.port();
                relay.stop();
                self.sh.toast(
                    format!("Forward stopped. Port {port} is free again."),
                    false,
                );
                self.refresh(false);
            }
        }
    }

    fn forward_start(&mut self, ctx: &egui::Context) {
        if self.sh.demo {
            self.sh.toast(
                "Starting is switched off in the demo. No port was opened.",
                false,
            );
            return;
        }
        let port = match tool_port(&self.tools.fwd_port) {
            Ok(p) => p,
            Err(e) => return self.sh.toast(e, true),
        };
        let target = match relay::parse_target(&self.tools.fwd_target) {
            Ok(t) => t,
            Err(e) => return self.sh.toast(e, true),
        };
        let wake: Wake = {
            let ctx = ctx.clone();
            Arc::new(move || ctx.request_repaint())
        };
        match Relay::start(port, self.tools.fwd_lan, target.clone(), Some(wake)) {
            Ok(relay) => {
                self.sh.toast(
                    format!("Forwarding port {port} to {}.", target.label()),
                    false,
                );
                self.sh.settings.forward_port = port;
                self.sh.settings.forward_target = target.label();
                self.sh.touch_settings();
                self.tools.relays.push(relay);
                self.refresh(false);
            }
            Err(e) => self.sh.toast(e, true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_shown_without_the_exact_path_prefix() {
        assert_eq!(
            display_path(Path::new("\\\\?\\C:\\site\\dist")),
            "C:\\site\\dist"
        );
        assert_eq!(
            display_path(Path::new("\\\\?\\UNC\\nas\\share\\site")),
            "\\\\nas\\share\\site"
        );
        assert_eq!(display_path(Path::new("C:\\site")), "C:\\site");
    }

    #[test]
    fn tool_ports() {
        assert_eq!(tool_port(" 8080 "), Ok(8080));
        assert!(tool_port("").unwrap_err().contains("Type a port"));
        assert!(tool_port("0").is_err());
        assert!(tool_port("70000").is_err());
        assert!(tool_port("http").is_err());
    }

    #[test]
    fn forward_summaries() {
        let mut stats = RelayStats {
            active: 1,
            total: 1,
            sent: 100,
            received: 4096,
            ..Default::default()
        };
        assert_eq!(
            forward_summary(&stats),
            "1 open · 1 connection so far · 100 bytes sent · 4.0 KB received"
        );
        stats.total = 5;
        stats.failed = 2;
        assert!(forward_summary(&stats)
            .ends_with("5 connections so far · 100 bytes sent · 4.0 KB received · 2 failed"));
    }

    #[test]
    fn nothing_runs_until_started() {
        let state = ToolsState::default();
        assert_eq!(state.running(), 0);
    }
}
