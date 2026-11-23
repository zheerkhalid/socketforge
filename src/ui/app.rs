//! Application state and the window frame (header, navigation rail, dialogs,
//! toasts, screenshots).

use super::conn_view::ConnState;
use super::details::Dialog;
use super::history_view::HistState;
use super::hosts_view::HostsView;
use super::listen_view::ListenState;
use super::lookup_view::LookupState;
use super::rules_view::RulesState;
use super::shared::Shared;
use super::theme::{self, pal_ctx, regular, semibold, Icon};
use super::tools_view::ToolsState;
use super::widgets;
use super::worker::{Notices, Resolver, Worker, WorkerConfig};
use crate::actions;
use crate::demo;
use crate::diff::{History, Tracker};
use crate::export::{self, Format};
use crate::model::{ConnectionKey, ListenerKey, Proto, SocketSnapshot, SystemInfo};
use crate::settings::{self, Settings};
use crate::tray::{self, Tray, TrayEvent};
use crate::view::{self, ConnectionRow, ListenerRow};
use eframe::egui::{
    self, pos2, vec2, Align, Align2, Color32, CornerRadius, Frame, Key, Layout, Margin, Rect,
    RichText, Sense, Stroke, TextureHandle,
};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Instant;

/// Seconds a new row stays highlighted and a closed row lingers.
pub(super) const HIGHLIGHT_SECS: f64 = 6.0;
/// Where the highlight is frozen for screenshots (0 = just changed, 1 = over).
const SCREENSHOT_PHASE: f64 = 0.3;
/// Most program icons extracted in one frame.
const ICONS_PER_FRAME: usize = 3;

/// How the app was started.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Show invented data and never touch the system.
    pub demo: bool,
    /// Render one frame of the chosen view to this PNG, then exit.
    pub screenshot: Option<PathBuf>,
    /// Which tab / panel to open first (see `Tab::from_name` and the views' sub-views).
    pub view: Option<String>,
    /// Force the light theme (for screenshots).
    pub light: bool,
    /// Open the port lookup for this port (`--port N` hands over to the window with `--gui`).
    pub port: Option<u16>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Listening,
    Connections,
    Lookup,
    History,
    Hosts,
    Rules,
    Tools,
    Settings,
}

impl Tab {
    /// Maps a `--view` name to a tab. Sub-views use a prefix: `hosts-raw`, `rules-firewall`...
    pub fn from_name(view: &str) -> Option<Tab> {
        let head = view.split('-').next().unwrap_or(view);
        Some(match head {
            "listening" | "ports" | "details" | "end" => Tab::Listening,
            "connections" => Tab::Connections,
            "lookup" | "free" | "port" => Tab::Lookup,
            "history" | "watch" => Tab::History,
            "hosts" => Tab::Hosts,
            "rules" | "firewall" | "system" => Tab::Rules,
            "tools" | "serve" | "forward" => Tab::Tools,
            "settings" => Tab::Settings,
            _ => return None,
        })
    }
}

struct Shot {
    path: PathBuf,
    frames: u32,
    requested: bool,
}

pub struct App {
    pub(super) sh: Shared,
    pub(super) tab: Tab,
    pub(super) hosts: HostsView,
    pub(super) about_open: bool,
    pub(super) focus_search: bool,
    logo: Option<TextureHandle>,
    shot: Option<Shot>,

    // ---- Data ----
    /// The latest socket snapshot.
    pub(super) snap: SocketSnapshot,
    /// False until the first snapshot arrived.
    pub(super) snap_loaded: bool,
    pub(super) sys: SystemInfo,
    /// False until the first (slow) system collection arrived.
    pub(super) sys_loaded: bool,
    /// Listeners joined with processes and exposure, sorted by port.
    pub(super) rows: Vec<ListenerRow>,
    pub(super) conn_rows: Vec<ConnectionRow>,
    pub(super) ltrack: Tracker<ListenerKey, ListenerRow>,
    pub(super) ctrack: Tracker<ConnectionKey, ConnectionRow>,
    pub(super) history: History,
    /// Reverse-DNS names that are known so far.
    pub(super) host_names: HashMap<IpAddr, String>,
    dns_asked: HashSet<IpAddr>,
    worker: Option<Worker>,
    resolver: Option<Resolver>,
    /// Outcomes of background actions, turned into toasts.
    pub(super) notices: Notices,
    started: Instant,
    /// Program icons by executable path (None = the file has no usable icon).
    pub(super) icons: HashMap<String, Option<TextureHandle>>,

    // ---- Views ----
    pub(super) listen: ListenState,
    pub(super) conn: ConnState,
    pub(super) lookup: LookupState,
    pub(super) hist: HistState,
    pub(super) rules: RulesState,
    pub(super) tools: ToolsState,
    pub(super) dialog: Dialog,
    /// The note box of the details panel: which port it is for, and its text.
    pub(super) note_edit: (Option<(bool, u16)>, String),

    // ---- Closing with unsaved hosts edits ----
    /// The "save before closing?" dialog is open.
    close_dialog: bool,
    /// "Save and close" was chosen: close once the save went through.
    close_after_save: bool,
    /// The user decided: do not ask again.
    close_confirmed: bool,

    // ---- Notification area ----
    tray: Option<Tray>,
    tray_tx: Sender<TrayEvent>,
    tray_rx: Receiver<TrayEvent>,
    hwnd: isize,
    exiting: bool,
}

/// Starts the window.
pub fn run(options: Options, icon: egui::IconData) -> eframe::Result<()> {
    let viewport = egui::ViewportBuilder::default()
        .with_title(if options.demo {
            "SocketForge (demo)"
        } else {
            "SocketForge"
        })
        .with_inner_size([1280.0, 800.0])
        .with_min_inner_size([980.0, 620.0])
        .with_icon(icon.clone());
    let native = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "SocketForge",
        native,
        Box::new(move |cc| Ok(Box::new(App::new(cc, options, icon)))),
    )
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, options: Options, icon: egui::IconData) -> Self {
        let ctx = &cc.egui_ctx;
        theme::install(ctx);
        // Nothing is read from or written to this folder in demo mode; an
        // invented path keeps the real user name out of screenshots.
        let app_dir = if options.demo {
            PathBuf::from("C:\\Users\\Alex\\AppData\\Local\\SocketForge")
        } else {
            settings::app_dir()
        };
        let mut settings = if options.demo {
            Settings::default()
        } else {
            Settings::load(&app_dir)
        };
        if options.light {
            settings.theme = crate::settings::ThemeChoice::Light;
        }
        theme::apply_choice(ctx, settings.theme);

        let logo = (icon.width > 0).then(|| {
            let image = egui::ColorImage::from_rgba_unmultiplied(
                [icon.width as usize, icon.height as usize],
                &icon.rgba,
            );
            ctx.load_texture("logo", image, egui::TextureOptions::LINEAR)
        });
        let sh = Shared {
            demo: options.demo,
            screenshot: options.screenshot.is_some(),
            elevated: if options.demo {
                false
            } else {
                actions::is_elevated()
            },
            settings,
            settings_dirty: false,
            app_dir: app_dir.clone(),
            search: String::new(),
            toasts: Vec::new(),
        };
        let history = if options.demo {
            History::in_memory(sh.settings.history_limit)
        } else {
            History::load(&app_dir, sh.settings.history_limit)
        };
        let worker =
            (!options.demo).then(|| Worker::start(ctx, WorkerConfig::from_settings(&sh.settings)));
        let (tray_tx, tray_rx) = channel();
        let mut app = App {
            hosts: HostsView::new(options.demo, &app_dir),
            sh,
            tab: Tab::Listening,
            about_open: false,
            focus_search: false,
            logo,
            shot: options.screenshot.clone().map(|path| Shot {
                path,
                frames: 0,
                requested: false,
            }),
            snap: SocketSnapshot::default(),
            snap_loaded: false,
            sys: SystemInfo::default(),
            sys_loaded: false,
            rows: Vec::new(),
            conn_rows: Vec::new(),
            ltrack: Tracker::new(HIGHLIGHT_SECS),
            ctrack: Tracker::new(HIGHLIGHT_SECS),
            history,
            host_names: HashMap::new(),
            dns_asked: HashSet::new(),
            worker,
            resolver: None,
            notices: Notices::default(),
            started: Instant::now(),
            icons: HashMap::new(),
            listen: ListenState::default(),
            conn: ConnState::default(),
            lookup: LookupState::default(),
            hist: HistState::default(),
            rules: RulesState::default(),
            tools: ToolsState::default(),
            dialog: Dialog::None,
            note_edit: (None, String::new()),
            close_dialog: false,
            close_after_save: false,
            close_confirmed: false,
            tray: None,
            tray_tx,
            tray_rx,
            hwnd: 0,
            exiting: false,
        };
        if options.demo {
            app.load_demo();
        }
        match (options.view.as_deref(), options.port) {
            (Some(view), _) => app.apply_view(view),
            (None, Some(port)) => app.open_port_check(port, Proto::Tcp),
            (None, None) => {}
        }
        app
    }

    /// Fills every view with the invented PC of `demo.rs`.
    fn load_demo(&mut self) {
        self.sh.settings.watched_ports = demo::watched_ports();
        // A few notes and favourites, as someone who uses them would have.
        for (port, note) in [
            (22, "SSH for the deploy script"),
            (3000, "Storefront API: npm run dev"),
            (5432, "Local database for the shop"),
            (8080, "Admin panel behind the proxy"),
        ] {
            self.sh.settings.set_note(true, port, note);
            self.sh.settings.toggle_favourite(true, port);
        }
        self.sys = demo::system();
        self.sys_loaded = true;
        // Two refreshes, so that one row is new and one has just closed.
        self.snap = demo::previous_snapshot();
        self.snap_loaded = true;
        self.rebuild_rows(0.0);
        self.snap = demo::snapshot();
        self.rebuild_rows(1.0);
        self.history.push(&demo::history());
    }

    /// Opens the tab / panel named on the command line.
    fn apply_view(&mut self, view: &str) {
        if view == "about" {
            self.about_open = true;
            return;
        }
        if let Some(tab) = Tab::from_name(view) {
            self.tab = tab;
        }
        match self.tab {
            Tab::Hosts => self.hosts.apply_view(view),
            Tab::Listening => self.listen_apply_view(view),
            Tab::Connections => self.conn_apply_view(view),
            Tab::Lookup => self.lookup_apply_view(view),
            Tab::Rules => self.rules_apply_view(view),
            Tab::Tools => self.tools_apply_view(view),
            Tab::History | Tab::Settings => {}
        }
    }

    // ----------------------------------------------------------------------------------
    // Data
    // ----------------------------------------------------------------------------------

    /// A monotonic clock in seconds for the change highlighting. Frozen while
    /// a screenshot is rendered so that the picture does not depend on timing.
    pub(super) fn clock(&self) -> f64 {
        if self.sh.screenshot {
            1.0 + HIGHLIGHT_SECS * SCREENSHOT_PHASE
        } else {
            1.0 + self.started.elapsed().as_secs_f64()
        }
    }

    /// "Now" for ages and time stamps (the demo has its own fixed time).
    pub(super) fn wall_now(&self) -> i64 {
        if self.sh.demo {
            demo::NOW
        } else {
            crate::model::now_unix()
        }
    }

    /// Joins the snapshot with the system data again and feeds the trackers.
    fn rebuild_rows(&mut self, now: f64) {
        self.rows = view::listener_rows(&self.snap, &self.sys);
        self.ltrack.update(
            self.rows
                .iter()
                .map(|r| (r.listener.key(), r.clone()))
                .collect(),
            now,
        );
        self.conn_rows = view::connection_rows(&self.snap);
        self.ctrack.update(
            self.conn_rows
                .iter()
                .map(|r| (r.conn.key(), r.clone()))
                .collect(),
            now,
        );
    }

    /// Picks up what the background threads have produced.
    fn pump(&mut self, ctx: &egui::Context) {
        let now = self.clock();
        if let Some(worker) = &self.worker {
            let inbox = worker.take();
            let mut changed = false;
            if let Some(sys) = inbox.system {
                self.sys = sys;
                self.sys_loaded = true;
                changed = true;
            }
            if let Some(snap) = inbox.snapshot {
                for e in &snap.errors {
                    if !self.snap.errors.contains(e) {
                        self.sh.toast(e.clone(), true);
                    }
                }
                self.snap = snap;
                self.snap_loaded = true;
                changed = true;
            }
            if changed {
                self.rebuild_rows(now);
            }
            if self.sh.settings.record_history && !inbox.events.is_empty() {
                self.history.capacity = self.sh.settings.history_limit.max(1);
                self.history.push(&inbox.events);
            }
            for alert in inbox.alerts {
                self.sh
                    .toast(format!("{}. {}", alert.title, alert.text), false);
            }
        }
        let notices: Vec<(String, bool)> = self
            .notices
            .lock()
            .map(|mut n| std::mem::take(&mut *n))
            .unwrap_or_default();
        if !notices.is_empty() {
            for (text, error) in notices {
                self.sh.toast(text, error);
            }
            self.refresh(false);
        }
        if let Some(resolver) = &self.resolver {
            for (ip, name) in resolver.take() {
                if let Some(name) = name {
                    self.host_names.insert(ip, name);
                }
            }
        }
        if !self.sh.screenshot && (self.ltrack.is_animating(now) || self.ctrack.is_animating(now)) {
            ctx.request_repaint_after(std::time::Duration::from_millis(60));
        }
    }

    /// Asks for fresh data now (F5 / the Refresh buttons).
    pub(super) fn refresh(&mut self, by_user: bool) {
        match &self.worker {
            Some(worker) => {
                worker.refresh_sockets();
                if by_user {
                    worker.refresh_system();
                }
            }
            None => {
                if by_user {
                    self.sh.toast("The demo shows fixed, invented data.", false);
                }
            }
        }
    }

    /// True while the slow system collection is running.
    pub(super) fn system_busy(&self) -> bool {
        self.worker.as_ref().is_some_and(|w| w.system_busy())
    }

    /// Requests reverse-DNS names for addresses that have not been asked yet.
    pub(super) fn resolve_names(&mut self, ctx: &egui::Context, ips: &[IpAddr]) {
        if self.sh.demo {
            if self.host_names.is_empty() {
                self.host_names = demo::reverse_names();
            }
            return;
        }
        for ip in ips {
            if ip.is_loopback() || ip.is_unspecified() || !self.dns_asked.insert(*ip) {
                continue;
            }
            self.resolver
                .get_or_insert_with(|| Resolver::start(ctx))
                .request(*ip);
        }
    }

    /// Makes sure the icons of these executables are loaded (a few per frame).
    pub(super) fn ensure_icons(&mut self, ctx: &egui::Context, paths: &[&str]) {
        if self.sh.demo {
            return;
        }
        let mut budget = ICONS_PER_FRAME;
        for path in paths {
            if path.is_empty() || self.icons.contains_key(*path) {
                continue;
            }
            if budget == 0 {
                ctx.request_repaint();
                break;
            }
            budget -= 1;
            let texture = crate::icons::extract(path).and_then(|icon| {
                let size = [icon.width as usize, icon.height as usize];
                (icon.rgba.len() == size[0] * size[1] * 4 && size[0] > 0).then(|| {
                    ctx.load_texture(
                        format!("icon:{path}"),
                        egui::ColorImage::from_rgba_unmultiplied(size, &icon.rgba),
                        egui::TextureOptions::LINEAR,
                    )
                })
            });
            self.icons.insert(path.to_string(), texture);
        }
    }

    pub(super) fn icon(&self, path: &str) -> Option<&TextureHandle> {
        self.icons.get(path).and_then(|t| t.as_ref())
    }

    /// Asks where to save and writes an export. `make` renders the content.
    pub(super) fn export_with(&mut self, base_name: &str, make: impl Fn(Format) -> String) {
        if self.sh.screenshot {
            return;
        }
        let picked = rfd::FileDialog::new()
            .set_title("Export")
            .set_file_name(format!("{base_name}.csv"))
            .add_filter("CSV (spreadsheet)", &["csv"])
            .add_filter("JSON", &["json"])
            .add_filter("HTML report", &["html"])
            .save_file();
        let Some(path) = picked else { return };
        let format = Format::from_path(&path);
        match export::write(&path, &make(format), format) {
            Ok(()) => {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                self.sh.toast(format!("Exported to {name}."), false);
            }
            Err(e) => self.sh.toast(e, true),
        }
    }

    // ----------------------------------------------------------------------------------
    // Notification area
    // ----------------------------------------------------------------------------------

    fn handle_tray(&mut self, ctx: &egui::Context) {
        if self.sh.demo || self.sh.screenshot {
            return;
        }
        if self.tray.is_none() {
            if self.hwnd == 0 {
                self.hwnd = tray::find_thread_window();
            }
            if self.hwnd != 0 {
                let wake = ctx.clone();
                self.tray = Tray::start(
                    self.hwnd,
                    self.tray_tx.clone(),
                    Box::new(move || wake.request_repaint()),
                );
                if let Some(tray) = &self.tray {
                    tray.set_enabled(self.sh.settings.tray_icon);
                    if let Some(worker) = &self.worker {
                        worker.set_tray(Some(tray.clone()));
                    }
                }
            }
        }
        while let Ok(event) = self.tray_rx.try_recv() {
            match event {
                TrayEvent::Show => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                TrayEvent::Exit => {
                    self.exiting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
        // Closing the window keeps the program in the notification area when asked to.
        let close_requested = ctx.input(|i| i.viewport().close_requested());
        if close_requested
            && !self.exiting
            && self.sh.settings.close_to_tray
            && self.sh.settings.tray_icon
            && self.tray.is_some()
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            tray::hide_window(self.hwnd);
        }
        if let Some(tray) = &self.tray {
            tray.set_tooltip(&format!(
                "SocketForge: {} listening, {} connections",
                self.snap.listeners.len(),
                self.snap.connections.len()
            ));
        }
    }

    /// Closing the window must not silently drop hosts edits: ask first.
    fn handle_close(&mut self, ctx: &egui::Context) {
        if self.sh.demo || self.shot.is_some() || self.close_confirmed {
            return;
        }
        if !ctx.input(|i| i.viewport().close_requested()) {
            return;
        }
        if !self.hosts.has_unsaved() && !self.hosts.is_saving() {
            return;
        }
        // Closing to the notification area keeps the editor and its changes.
        let to_tray = !self.exiting
            && self.sh.settings.close_to_tray
            && self.sh.settings.tray_icon
            && self.tray.is_some();
        if to_tray {
            return;
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        if self.exiting {
            // "Exit" came from the notification area: the window may be hidden.
            self.exiting = false;
            tray::show_window(self.hwnd);
        }
        self.tab = Tab::Hosts;
        self.hosts.show_entries();
        if self.hosts.is_saving() {
            self.sh.toast(
                "The hosts file is still being saved. Close again when it is done.",
                false,
            );
        } else {
            self.close_dialog = true;
        }
    }

    fn close_dialog_ui(&mut self, ctx: &egui::Context) {
        if self.close_after_save && !self.hosts.is_saving() {
            self.close_after_save = false;
            // Still unsaved: the save failed, was cancelled at the administrator
            // prompt, or needs an answer first. Stay open.
            if !self.hosts.has_unsaved() {
                self.close_now(ctx);
            }
        }
        if !self.close_dialog {
            return;
        }
        if !self.hosts.has_unsaved() {
            self.close_dialog = false;
            return;
        }
        let (mut save, mut discard, mut cancel) = (false, false, false);
        let dismissed = widgets::modal(ctx, "close-unsaved", 470.0, |ui| {
            widgets::modal_title(ui, "Save the hosts file before closing?");
            widgets::para(
                ui,
                "The hosts editor has changes that are not saved yet. Closing without saving \
                 drops them; the hosts file itself stays as it is.",
            );
            ui.add_space(10.0);
            widgets::button_row(ui, |ui| {
                if widgets::primary_button(ui, "Save and close", true).clicked() {
                    save = true;
                }
                if widgets::danger_button(ui, "Close without saving", true).clicked() {
                    discard = true;
                }
                if widgets::ghost_button(ui, "Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if save {
            self.close_dialog = false;
            self.close_after_save = true;
            self.hosts.save_now(ctx, &mut self.sh);
        } else if discard {
            self.close_dialog = false;
            self.close_now(ctx);
        } else if cancel || dismissed {
            self.close_dialog = false;
        }
    }

    /// Really closes the window: no more questions, not into the notification area.
    fn close_now(&mut self, ctx: &egui::Context) {
        self.close_confirmed = true;
        self.exiting = true;
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    /// Passes changed settings on to the refresh threads and the tray icon.
    fn sync_settings(&mut self) {
        if let Some(worker) = &self.worker {
            worker.set_config(WorkerConfig::from_settings(&self.sh.settings));
        }
        if self.sh.settings_dirty {
            if let Some(tray) = &self.tray {
                tray.set_enabled(self.sh.settings.tray_icon);
            }
        }
    }

    fn handle_keys(&mut self, ctx: &egui::Context) {
        let (find, escape) = ctx.input(|i| {
            (
                i.modifiers.command && i.key_pressed(Key::F),
                i.key_pressed(Key::Escape),
            )
        });
        let refresh = ctx.input(|i| i.key_pressed(Key::F5));
        if find {
            self.focus_search = true;
        }
        if refresh {
            self.refresh(true);
        }
        // Dialogs close themselves on Esc; after that the search, then the side panel.
        if escape
            && !self.about_open
            && !self.close_dialog
            && !self.dialog.is_open()
            && !self.hosts.has_dialog()
        {
            if !self.sh.search.is_empty() {
                self.sh.search.clear();
            } else if self.tab == Tab::Listening {
                self.listen.selected = None;
            }
        }
    }

    fn handle_screenshot(&mut self, ctx: &egui::Context) {
        let Some(shot) = &mut self.shot else { return };
        ctx.request_repaint();
        shot.frames += 1;
        if shot.frames == 1 {
            ctx.set_pixels_per_point(1.0);
        }
        if shot.frames == 3 {
            // Now that one point is one pixel, this gives an exact 1280 x 800 image.
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(vec2(1280.0, 800.0)));
        }
        let image = ctx.input(|i| {
            i.events.iter().find_map(|e| match e {
                egui::Event::Screenshot { image, .. } => Some(image.clone()),
                _ => None,
            })
        });
        if let Some(image) = image {
            let [w, h] = image.size;
            if let Some(parent) = shot.path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let result = image::save_buffer(
                &shot.path,
                image.as_raw(),
                w as u32,
                h as u32,
                image::ColorType::Rgba8,
            );
            if let Err(e) = result {
                eprintln!("screenshot failed: {e}");
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            self.shot = None;
            return;
        }
        if !shot.requested && shot.frames > 40 {
            shot.requested = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
        }
    }

    // ----------------------------------------------------------------------------------
    // Frame: header and navigation
    // ----------------------------------------------------------------------------------

    fn header(&mut self, ctx: &egui::Context) {
        let p = pal_ctx(ctx);
        egui::TopBottomPanel::top("header")
            .exact_height(64.0)
            .frame(
                Frame::new()
                    .fill(p.rail)
                    .inner_margin(Margin::symmetric(18, 0)),
            )
            .show(ctx, |ui| {
                let full = ui.max_rect();
                ui.painter().hline(
                    full.x_range().expand(18.0),
                    full.bottom(),
                    Stroke::new(1.0_f32, p.border),
                );
                ui.horizontal_centered(|ui| {
                    // Brand
                    let (rect, _) = ui.allocate_exact_size(vec2(32.0, 32.0), Sense::hover());
                    if let Some(logo) = &self.logo {
                        ui.painter().image(
                            logo.id(),
                            rect,
                            Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                            Color32::WHITE,
                        );
                    }
                    ui.add_space(2.0);
                    ui.label(RichText::new("SocketForge").font(semibold(19.0)));
                    if self.sh.demo {
                        widgets::badge(ui, "DEMO", p.info)
                            .on_hover_text("Invented data. Nothing on this PC is read or changed.");
                    }
                    ui.add_space(214.0 - ui.min_rect().width().min(214.0));

                    // Search
                    let search_width = (ui.available_width() - 380.0).clamp(220.0, 460.0);
                    let enabled = self.tab != Tab::Settings && self.tab != Tab::Tools;
                    Frame::new()
                        .fill(if p.dark { p.card } else { p.bg })
                        .stroke(Stroke::new(1.0_f32, p.border))
                        .corner_radius(CornerRadius::same(10))
                        .inner_margin(Margin::symmetric(12, 6))
                        .show(ui, |ui| {
                            ui.set_width(search_width);
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(Icon::SEARCH.glyph())
                                        .size(14.0)
                                        .color(p.faint),
                                );
                                let hint = match self.tab {
                                    Tab::Listening => {
                                        "Search ports, programs, services: 3000, node"
                                    }
                                    Tab::Connections => {
                                        "Search connections: address, port, program"
                                    }
                                    Tab::Lookup => "Search results",
                                    Tab::History => "Search the history",
                                    Tab::Hosts => "Search host names and addresses",
                                    Tab::Rules => "Search rules: port, program, name",
                                    Tab::Tools | Tab::Settings => "Search",
                                };
                                let edit = egui::TextEdit::singleline(&mut self.sh.search)
                                    .hint_text(RichText::new(hint).color(p.faint))
                                    .frame(false)
                                    .desired_width(ui.available_width() - 30.0)
                                    .font(regular(15.0));
                                let resp = ui.add_enabled(enabled, edit);
                                if self.focus_search {
                                    resp.request_focus();
                                    self.focus_search = false;
                                }
                                if !self.sh.search.is_empty() {
                                    if widgets::icon_button(ui, Icon::CLOSE, "Clear search (Esc)")
                                        .clicked()
                                    {
                                        self.sh.search.clear();
                                    }
                                } else {
                                    ui.label(RichText::new("Ctrl+F").size(11.5).color(p.faint));
                                }
                            });
                        });

                    // Right side: rights and About
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if widgets::icon_button(ui, Icon::INFO, "About SocketForge").clicked() {
                            self.about_open = true;
                        }
                        if widgets::icon_button(ui, Icon::REFRESH, "Refresh now (F5)").clicked() {
                            self.refresh(true);
                        }
                        ui.add_space(6.0);
                        if self.sh.elevated {
                            widgets::badge(ui, &Icon::SHIELD.with("Administrator"), p.accent)
                                .on_hover_text(
                                    "SocketForge runs with administrator rights and can show \
                                     the details of every process.",
                                );
                        } else {
                            if widgets::ghost_button(ui, "Restart as administrator").clicked() {
                                if self.sh.demo {
                                    self.sh.toast("Not available in the demo.", false);
                                } else if self.hosts.has_unsaved() || self.hosts.is_saving() {
                                    // The restarted copy would open without the edits.
                                    self.tab = Tab::Hosts;
                                    self.hosts.show_entries();
                                    self.sh.toast(
                                        "Save or revert the hosts changes first; a restart \
                                         would drop them.",
                                        true,
                                    );
                                } else {
                                    match actions::restart_as_admin() {
                                        Ok(()) => {
                                            ctx.send_viewport_cmd(egui::ViewportCommand::Close)
                                        }
                                        Err(e) => self.sh.toast(e, true),
                                    }
                                }
                            }
                            widgets::badge(ui, &Icon::WARNING.with("Standard rights"), p.warn)
                                .on_hover_text(
                                    "Without administrator rights the path, command line and \
                                     user of some system processes stay hidden.",
                                );
                        }
                    });
                });
            });
    }

    fn rail(&mut self, ctx: &egui::Context) {
        let p = pal_ctx(ctx);
        egui::SidePanel::left("rail")
            .exact_width(208.0)
            .resizable(false)
            .frame(
                Frame::new()
                    .fill(p.rail)
                    .inner_margin(Margin::symmetric(10, 14)),
            )
            .show(ctx, |ui| {
                let full = ui.max_rect();
                ui.painter().vline(
                    full.right() + 10.0,
                    full.y_range().expand(14.0),
                    Stroke::new(1.0_f32, p.border),
                );
                ui.spacing_mut().item_spacing.y = 4.0;
                let items: [(Tab, Icon, &str, Option<usize>); 8] = [
                    (
                        Tab::Listening,
                        Icon::PLUG,
                        "Listening ports",
                        self.listening_count(),
                    ),
                    (
                        Tab::Connections,
                        Icon::SWITCH,
                        "Connections",
                        self.connection_count(),
                    ),
                    (Tab::Lookup, Icon::TARGET, "Port check", None),
                    (
                        Tab::History,
                        Icon::HISTORY,
                        "Watch & history",
                        self.history_count(),
                    ),
                    (Tab::Hosts, Icon::DOCUMENT, "Hosts file", self.hosts.count()),
                    (
                        Tab::Rules,
                        Icon::SHIELD,
                        "Rules & forwards",
                        self.rules_count(),
                    ),
                    (Tab::Tools, Icon::TOOLS, "Tools", self.tools_count()),
                    (Tab::Settings, Icon::SETTINGS, "Settings", None),
                ];
                for (tab, icon, label, count) in items {
                    if tab == Tab::Settings {
                        ui.add_space(8.0);
                        widgets::divider(ui);
                        ui.add_space(8.0);
                    }
                    let active = self.tab == tab;
                    let (rect, resp) =
                        ui.allocate_exact_size(vec2(ui.available_width(), 40.0), Sense::click());
                    if active {
                        ui.painter()
                            .rect_filled(rect, CornerRadius::same(9), p.selected);
                        let bar = Rect::from_min_size(
                            rect.left_center() - vec2(0.0, 9.0),
                            vec2(3.0, 18.0),
                        );
                        ui.painter()
                            .rect_filled(bar, CornerRadius::same(2), p.accent);
                    } else if resp.hovered() {
                        ui.painter()
                            .rect_filled(rect, CornerRadius::same(9), p.hover);
                    }
                    let fg = if active { p.text } else { p.muted };
                    ui.painter().text(
                        rect.left_center() + vec2(24.0, 0.0),
                        Align2::CENTER_CENTER,
                        icon.glyph(),
                        regular(16.0),
                        if active { p.accent } else { fg },
                    );
                    ui.painter().text(
                        rect.left_center() + vec2(46.0, -1.0),
                        Align2::LEFT_CENTER,
                        label,
                        if active {
                            semibold(14.5)
                        } else {
                            regular(14.5)
                        },
                        fg,
                    );
                    // A running tool shows as a green count; unsaved hosts edits as a dot.
                    let running = tab == Tab::Tools && count.is_some();
                    let mut count_right = rect.right() - 12.0;
                    if let Some(n) = count {
                        let r = ui.painter().text(
                            pos2(count_right, rect.center().y - 1.0),
                            Align2::RIGHT_CENTER,
                            super::settings_view::thousands(n),
                            regular(12.5),
                            if running { p.accent } else { p.faint },
                        );
                        count_right = r.left() - 8.0;
                    }
                    if tab == Tab::Hosts && self.hosts.has_unsaved() {
                        ui.painter().circle_filled(
                            pos2(count_right, rect.center().y),
                            3.5,
                            p.accent,
                        );
                        resp.clone().on_hover_text("Unsaved changes");
                    }
                    if resp.clicked() && self.tab != tab {
                        self.tab = tab;
                        self.sh.search.clear();
                    }
                }
                ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.add_space(12.0);
                        ui.label(
                            RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION")))
                                .size(12.0)
                                .color(p.faint),
                        );
                    });
                });
            });
    }

    // ----------------------------------------------------------------------------------
    // Dialogs and toasts
    // ----------------------------------------------------------------------------------

    fn about_dialog(&mut self, ctx: &egui::Context) {
        if !self.about_open {
            return;
        }
        let p = pal_ctx(ctx);
        let mut close = false;
        let dismissed = widgets::modal(ctx, "about", 380.0, |ui| {
            ui.vertical_centered(|ui| {
                let (rect, _) = ui.allocate_exact_size(vec2(84.0, 84.0), Sense::hover());
                if let Some(logo) = &self.logo {
                    ui.painter().image(
                        logo.id(),
                        rect,
                        Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                        Color32::WHITE,
                    );
                }
                ui.add_space(6.0);
                ui.label(RichText::new("SocketForge").font(semibold(26.0)));
                ui.label(
                    RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION"))).color(p.muted),
                );
                ui.add_space(10.0);
                ui.label("See what is listening on this PC, and edit the hosts file.");
                ui.add_space(10.0);
                ui.label(RichText::new("Developed by Zheer Khalid").font(semibold(15.0)));
                ui.add_space(2.0);
                ui.hyperlink_to(
                    RichText::new("zheer.dev").color(p.accent),
                    "https://zheer.dev",
                );
                ui.hyperlink_to(
                    RichText::new("github.com/zheerkhalid/socketforge").color(p.accent),
                    "https://github.com/zheerkhalid/socketforge",
                );
                ui.add_space(10.0);
                ui.label(
                    RichText::new("Free and open source under the MIT License.")
                        .size(12.0)
                        .color(p.faint),
                );
                ui.add_space(14.0);
                if widgets::primary_button(ui, "Close", true).clicked() {
                    close = true;
                }
            });
        });
        if close || dismissed {
            self.about_open = false;
        }
    }

    fn toasts_ui(&mut self, ctx: &egui::Context) {
        self.sh
            .toasts
            .retain(|t| t.born.elapsed().as_secs_f32() < if t.error { 8.0 } else { 3.5 });
        if self.sh.toasts.is_empty() {
            return;
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(250));
        let p = pal_ctx(ctx);
        egui::Area::new(egui::Id::new("toasts"))
            .anchor(Align2::RIGHT_BOTTOM, vec2(-18.0, -18.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                ui.with_layout(Layout::bottom_up(Align::Max), |ui| {
                    for t in self.sh.toasts.iter().rev().take(4) {
                        let color = if t.error { p.danger } else { p.accent };
                        Frame::new()
                            .fill(p.card)
                            .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.7)))
                            .corner_radius(CornerRadius::same(10))
                            .inner_margin(Margin::symmetric(14, 10))
                            .show(ui, |ui| {
                                ui.set_max_width(420.0);
                                ui.horizontal(|ui| {
                                    let icon = if t.error { Icon::ERROR } else { Icon::DONE };
                                    ui.label(RichText::new(icon.glyph()).color(color));
                                    ui.add(egui::Label::new(t.text.as_str()).wrap());
                                });
                            });
                    }
                });
            });
    }

    fn save_settings_if_dirty(&mut self) {
        if !self.sh.settings_dirty {
            return;
        }
        self.sh.settings_dirty = false;
        if self.sh.demo {
            return;
        }
        self.sh.settings.sanitize();
        if let Err(e) = self.sh.settings.save(&self.sh.app_dir) {
            self.sh.toast(e, true);
        }
    }
}

/// Case-insensitive comparison for sorting text columns.
pub(super) fn cmp_text(a: &str, b: &str) -> std::cmp::Ordering {
    a.to_lowercase().cmp(&b.to_lowercase())
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.pump(ctx);
        self.handle_tray(ctx);
        self.handle_close(ctx);
        self.handle_keys(ctx);
        self.handle_screenshot(ctx);

        self.header(ctx);
        self.rail(ctx);

        let p = pal_ctx(ctx);
        if self.tab == Tab::Listening && self.listen.selected.is_some() {
            egui::SidePanel::right("details")
                .exact_width(340.0)
                .resizable(false)
                .frame(Frame::new().fill(p.rail).inner_margin(Margin::same(18)))
                .show(ctx, |ui| self.details_ui(ui));
        }
        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(p.bg)
                    .inner_margin(Margin::symmetric(24, 18)),
            )
            .show(ctx, |ui| match self.tab {
                Tab::Listening => self.listening_ui(ui),
                Tab::Connections => self.connections_ui(ui),
                Tab::Lookup => self.lookup_ui(ui),
                Tab::History => self.history_ui(ui),
                Tab::Hosts => self.hosts.ui(ui, &mut self.sh),
                Tab::Rules => self.rules_ui(ui),
                Tab::Tools => self.tools_ui(ui),
                Tab::Settings => self.settings_ui(ui),
            });

        self.hosts.dialogs(ctx, &mut self.sh);
        self.close_dialog_ui(ctx);
        self.dialogs_ui(ctx);
        self.about_dialog(ctx);
        self.toasts_ui(ctx);
        self.sync_settings();
        self.save_settings_if_dirty();
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(worker) = &self.worker {
            worker.stop();
        }
        if let Some(tray) = &self.tray {
            tray.stop();
        }
    }

    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        // Screenshots must not depend on where the mouse happens to be:
        // no hover highlights, no tooltips.
        if self.shot.is_some() {
            raw_input.events.retain(|e| {
                !matches!(
                    e,
                    egui::Event::PointerMoved(_)
                        | egui::Event::MouseMoved(_)
                        | egui::Event::PointerButton { .. }
                        | egui::Event::MouseWheel { .. }
                )
            });
            raw_input.events.push(egui::Event::PointerGone);
        }
    }
}
