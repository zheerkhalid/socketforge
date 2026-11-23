//! The hosts file editor: entries table with switches, raw text, profiles,
//! backups and restore. Saving asks for elevation only when Windows refuses
//! the write.

use super::settings_view::thousands;
use super::shared::Shared;
use super::theme::{pal, regular, semibold, Icon, Palette};
use super::widgets;
use crate::export::{self, Format};
use crate::hosts::{
    self, BlockList, Entry, HostsDoc, Issue, IssueKind, LineKind, Profile, ProfileEntry, Row,
};
use crate::hosts_store::{
    self, Backup, DnsCacheEntry, HostsPaths, SaveError, SaveOptions, SaveOutcome,
};
use crate::model::now_unix;
use crate::util::{fmt_age, fmt_time};
use eframe::egui::{
    self, pos2, vec2, Align, Align2, CornerRadius, FontFamily, FontId, Frame, Key, Layout, Margin,
    Rect, RichText, Sense, Stroke, Ui, UiBuilder,
};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};

const ROW_H: f32 = 44.0;
/// Height of a line in the fast raw view.
const RAW_LINE_H: f32 = 20.0;
/// Height of a row in the DNS cache list.
const DNS_ROW_H: f32 = 38.0;
/// Files with more lines open in the fast, read-only raw view: a text box
/// lays out its whole content every frame, which is slow for long files.
const LARGE_LINES: usize = 2000;
/// Above this many names Windows itself gets slow with the hosts file.
const MANY_NAMES: usize = 100_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sub {
    Entries,
    Raw,
    Profiles,
    Backups,
    Dns,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Show {
    All,
    Enabled,
    Disabled,
    Problems,
}

struct EditDlg {
    /// None = a new entry.
    line: Option<usize>,
    ip: String,
    names: String,
    comment: String,
    group: String,
    enabled: bool,
    focus: bool,
}

struct ProfileDlg {
    /// None = a new profile.
    index: Option<usize>,
    name: String,
    text: String,
}

struct ImportDlg {
    file: String,
    doc: HostsDoc,
    group: String,
    /// Entries in the file when it is read as a hosts file.
    entries: usize,
    /// Lines of it with problems.
    problems: usize,
    /// The names in the file when it is read as a block list.
    block: BlockList,
    /// Import as a block list (one line per name) instead of line by line.
    as_block: bool,
    /// Index into [`SINKS`].
    sink: usize,
}

/// Where a blocked name is pointed. 0.0.0.0 fails at once; 127.0.0.1 makes
/// programs try to connect to this PC first.
const SINKS: [&str; 2] = ["0.0.0.0", "127.0.0.1"];

impl ImportDlg {
    fn new(file: &str, doc: HostsDoc) -> ImportDlg {
        let block = hosts::parse_block_list(&doc.to_text());
        let entries = doc.entry_count();
        let as_block =
            !block.names.is_empty() && (entries == 0 || hosts::looks_like_block_list(&doc));
        ImportDlg {
            group: ImportDlg::default_group(file, as_block),
            file: file.to_string(),
            entries,
            problems: doc.issues().len(),
            doc,
            block,
            as_block,
            sink: 0,
        }
    }

    fn default_group(file: &str, as_block: bool) -> String {
        if as_block {
            format!("Block list: {file}")
        } else {
            format!("Imported from {file}")
        }
    }

    /// Switches between the two ways of importing; a group name that was not
    /// edited follows the choice.
    fn set_block(&mut self, as_block: bool) {
        if self.group == ImportDlg::default_group(&self.file, self.as_block) {
            self.group = ImportDlg::default_group(&self.file, as_block);
        }
        self.as_block = as_block;
    }

    /// What the dialog says about the file.
    fn summary(&self) -> String {
        if self.as_block {
            let mut s = format!(
                "{} has {} name{} to block",
                self.file,
                thousands(self.block.names.len()),
                if self.block.names.len() == 1 { "" } else { "s" }
            );
            if self.block.repeats > 0 {
                s.push_str(&format!(
                    " ({} listed more than once)",
                    thousands(self.block.repeats)
                ));
            }
            s.push_str(
                ". Each one gets its own line pointing at the address below, so the name \
                 stops resolving on this PC. Names your hosts file already lists are left as \
                 they are.",
            );
            if self.block.skipped > 0 {
                s.push_str(&format!(
                    " {} line{} that cannot go into a hosts file (wildcards, rules with \
                     options) are skipped.",
                    thousands(self.block.skipped),
                    if self.block.skipped == 1 { "" } else { "s" }
                ));
            }
            s
        } else {
            format!(
                "{} has {} entries{}. Entries that are already in your hosts file are \
                 skipped. A name that already points to a different address is added \
                 switched off, so nothing that works now changes.",
                self.file,
                thousands(self.entries),
                if self.problems > 0 {
                    format!(" ({} with problems)", thousands(self.problems))
                } else {
                    String::new()
                }
            )
        }
    }
}

enum Dialog {
    Edit(EditDlg),
    Delete(usize),
    Restore(usize),
    /// The file is read-only: lift the mark for this save?
    ReadOnly,
    /// The file changed on disk: overwrite or reload?
    Changed,
    /// Reload and lose unsaved changes?
    Reload,
    Profile(ProfileDlg),
    ProfileDelete(usize),
    Import(ImportDlg),
}

/// What a row click asked for; applied after the table has been drawn.
enum Act {
    Toggle(usize, bool),
    Edit(usize),
    Delete(usize),
    GroupToggle(String, bool),
    Collapse(String),
    /// Text for the clipboard, and what to call it in the toast.
    Copy(String, &'static str),
}

enum Item {
    Group {
        name: String,
        total: usize,
        enabled: usize,
    },
    Entry(usize),
}

struct SaveJob {
    rx: Receiver<Result<SaveOutcome, SaveError>>,
    doc: HostsDoc,
    options: SaveOptions,
    /// "Saved" or "Restored": the word for the toast.
    done_word: &'static str,
}

pub struct HostsView {
    demo: bool,
    paths: HostsPaths,
    doc: HostsDoc,
    /// The file as it is on disk (as far as we know).
    loaded_bytes: Vec<u8>,
    read_only: bool,
    missing: bool,
    load_error: Option<String>,
    sub: Sub,
    show: Show,
    profiles: Vec<Profile>,
    backups: Vec<Backup>,
    collapsed: HashSet<String>,
    dialog: Option<Dialog>,
    saving: Option<SaveJob>,
    /// The save that a dialog (read-only, changed on disk) is asking about.
    held: Option<(HostsDoc, SaveOptions, &'static str)>,

    // Caches, rebuilt by `changed()`.
    version: u64,
    dirty: bool,
    rows: Vec<Row>,
    issues: Vec<Issue>,
    issues_by_line: HashMap<usize, Vec<usize>>,
    raw: String,
    raw_version: u64,
    visible: Vec<Item>,
    visible_key: (u64, String, Show, usize),
    enabled_count: usize,
    /// Group names without the profile blocks, in file order.
    plain_groups: Vec<String>,
    /// Names of the profile blocks in the file.
    active_profiles: Vec<String>,
    /// Names (lower case) that a switched-on entry maps.
    names_on: HashSet<String>,
    has_duplicates: bool,

    /// A long file is being edited as text although that is slow.
    raw_edit_large: bool,
    /// Lines of the fast raw view that match the search.
    raw_lines: Vec<usize>,
    raw_lines_key: (u64, String),

    /// The DNS cache as last read; None = not read yet.
    dns: Option<Vec<DnsCacheEntry>>,
    dns_error: Option<String>,
}

fn mono(size: f32) -> FontId {
    FontId::new(size, FontFamily::Monospace)
}

pub(super) fn fmt_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n} bytes")
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    }
}

/// Turns the text of the profile editor into entries (comment lines are ignored).
fn profile_entries(text: &str) -> Vec<ProfileEntry> {
    HostsDoc::parse(text)
        .rows()
        .into_iter()
        .map(|r| ProfileEntry {
            ip: r.entry.ip,
            hosts: r.entry.hosts,
            comment: r.entry.comment,
        })
        .collect()
}

fn profile_text(profile: &Profile) -> String {
    profile
        .entries
        .iter()
        .map(|e| {
            Entry {
                enabled: true,
                ip: e.ip.clone(),
                hosts: e.hosts.clone(),
                comment: e.comment.clone(),
            }
            .format()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Problems with the fields of the edit dialog; empty = can be saved.
fn edit_problems(ip: &str, names: &str) -> Vec<String> {
    let mut out = Vec::new();
    if ip.trim().is_empty() {
        out.push("Type an address, for example 127.0.0.1 or ::1.".to_string());
    } else if hosts::parse_ip(ip).is_none() {
        out.push(format!(
            "\"{}\" is not a valid IPv4 or IPv6 address.",
            ip.trim()
        ));
    }
    let list: Vec<&str> = names.split_whitespace().collect();
    if list.is_empty() {
        out.push("Type at least one host name.".to_string());
    }
    for n in list {
        if let Some(problem) = hosts::name_problem(n) {
            out.push(problem);
        }
    }
    out
}

impl HostsView {
    pub fn new(demo: bool, app_dir: &Path) -> HostsView {
        let mut view = HostsView {
            demo,
            paths: HostsPaths::system(app_dir),
            doc: HostsDoc::parse(""),
            loaded_bytes: Vec::new(),
            read_only: false,
            missing: false,
            load_error: None,
            sub: Sub::Entries,
            show: Show::All,
            profiles: Vec::new(),
            backups: Vec::new(),
            collapsed: HashSet::new(),
            dialog: None,
            saving: None,
            held: None,
            version: 0,
            dirty: false,
            rows: Vec::new(),
            issues: Vec::new(),
            issues_by_line: HashMap::new(),
            raw: String::new(),
            raw_version: u64::MAX,
            visible: Vec::new(),
            visible_key: (u64::MAX, String::new(), Show::All, 0),
            enabled_count: 0,
            plain_groups: Vec::new(),
            active_profiles: Vec::new(),
            names_on: HashSet::new(),
            has_duplicates: false,
            raw_edit_large: false,
            raw_lines: Vec::new(),
            raw_lines_key: (u64::MAX, String::new()),
            dns: None,
            dns_error: None,
        };
        if demo {
            // Invented content; the real hosts file is not even opened.
            view.paths.hosts = PathBuf::from("C:\\Windows\\System32\\drivers\\etc\\hosts");
            let text = hosts::demo_text();
            view.loaded_bytes = text.clone().into_bytes();
            view.doc = HostsDoc::parse(&text);
            view.profiles = hosts::demo_profiles();
            let now = now_unix();
            view.backups = [
                (2 * 3600 + 700, 14, 612),
                (26 * 3600, 13, 574),
                (5 * 86_400 + 4000, 9, 431),
                (19 * 86_400, 2, 824),
            ]
            .iter()
            .map(|&(ago, entries, size)| Backup {
                path: view
                    .paths
                    .backups
                    .join(format!("hosts-{}.bak", crate::util::fmt_stamp(now - ago))),
                time: now - ago,
                size,
                entries,
            })
            .collect();
            view.changed();
        } else {
            view.reload_from_disk();
        }
        view
    }

    /// Number of entries, for the navigation rail.
    pub fn count(&self) -> Option<usize> {
        Some(self.rows.len())
    }

    /// True while there are edits that have not been saved.
    pub fn has_unsaved(&self) -> bool {
        self.dirty
    }

    /// True while a save is under way (the administrator prompt may be open).
    pub fn is_saving(&self) -> bool {
        self.saving.is_some()
    }

    /// True while one of the editor's dialogs is open.
    pub fn has_dialog(&self) -> bool {
        self.dialog.is_some()
    }

    /// Saves the edits, as the Save button does.
    pub fn save_now(&mut self, ctx: &egui::Context, sh: &mut Shared) {
        if self.dirty && self.saving.is_none() {
            let doc = self.doc.clone();
            self.start_save(ctx, sh, doc, SaveOptions::default(), "Saved");
        }
    }

    /// Opens the entries table (where the unsaved changes can be seen).
    pub fn show_entries(&mut self) {
        self.sub = Sub::Entries;
    }

    /// Opens a sub-view by its `--view` name.
    pub fn apply_view(&mut self, view: &str) {
        match view {
            "hosts-raw" => self.sub = Sub::Raw,
            "hosts-profiles" => self.sub = Sub::Profiles,
            "hosts-backups" => self.sub = Sub::Backups,
            "hosts-dns" => self.sub = Sub::Dns,
            "hosts-raw-large" | "hosts-import" => {
                if self.demo {
                    // An invented block list, long enough for the fast raw view.
                    let names: Vec<String> = (1..=4200)
                        .map(|i| format!("ads-{i:04}.tracker.example.test"))
                        .collect();
                    if view == "hosts-import" {
                        let text: String =
                            names.iter().map(|n| format!("0.0.0.0 {n}\r\n")).collect();
                        self.dialog = Some(Dialog::Import(ImportDlg::new(
                            "blocklist.txt",
                            HostsDoc::parse(&text),
                        )));
                    } else {
                        self.doc
                            .add_block_list(&names, SINKS[0], "Block list: blocklist.txt");
                        self.loaded_bytes = self.doc.to_bytes();
                        self.changed();
                        self.sub = Sub::Raw;
                    }
                }
            }
            "hosts-restore" => {
                self.sub = Sub::Backups;
                if !self.backups.is_empty() {
                    self.dialog = Some(Dialog::Restore(0));
                }
            }
            "hosts-problems" => self.show = Show::Problems,
            "hosts-edit" => {
                if let Some(r) = self.rows.iter().find(|r| r.entry.enabled).cloned() {
                    self.open_edit(Some(r.line));
                }
            }
            "hosts-unsaved" => {
                if let Some(line) = self.rows.iter().find(|r| !r.entry.enabled).map(|r| r.line) {
                    self.doc.set_enabled(line, true);
                    self.changed();
                }
            }
            _ => {}
        }
    }

    fn reload_from_disk(&mut self) {
        match hosts_store::load(&self.paths) {
            Ok(loaded) => {
                self.doc = loaded.doc;
                self.loaded_bytes = loaded.bytes;
                self.read_only = loaded.read_only;
                self.missing = loaded.missing;
                self.load_error = None;
            }
            Err(e) => {
                self.doc = HostsDoc::parse("");
                self.loaded_bytes.clear();
                self.load_error = Some(e);
            }
        }
        self.profiles = hosts_store::load_profiles(&self.paths);
        self.backups = hosts_store::list_backups(&self.paths);
        self.changed();
    }

    /// Rebuilds everything derived from the document.
    fn changed(&mut self) {
        self.version = self.version.wrapping_add(1);
        self.rows = self.doc.rows();
        self.issues = self.doc.issues();
        self.issues_by_line.clear();
        for (i, issue) in self.issues.iter().enumerate() {
            self.issues_by_line.entry(issue.line).or_default().push(i);
        }
        self.dirty = self.doc.to_bytes() != self.loaded_bytes;
        // Everything the page asks for every frame is worked out once here;
        // with a long block list in the file that is the difference between
        // a smooth window and a sluggish one.
        self.enabled_count = self.rows.iter().filter(|r| r.entry.enabled).count();
        self.has_duplicates = self.issues.iter().any(|i| i.kind == IssueKind::Duplicate);
        self.active_profiles = self.doc.active_profiles();
        self.plain_groups.clear();
        self.names_on.clear();
        let mut last_group = "";
        for r in &self.rows {
            if r.group != last_group {
                last_group = r.group.as_str();
                if !r.group.is_empty()
                    && !r.group.starts_with("Profile: ")
                    && !self.plain_groups.contains(&r.group)
                {
                    self.plain_groups.push(r.group.clone());
                }
            }
            if r.entry.enabled {
                for h in &r.entry.hosts {
                    self.names_on.insert(h.to_lowercase());
                }
            }
        }
        if self.doc.lines.len() <= LARGE_LINES {
            self.raw_edit_large = false;
        }
    }

    fn profile_active(&self, name: &str) -> bool {
        self.active_profiles.iter().any(|n| n == name)
    }

    fn flush_dns(&mut self, sh: &mut Shared) {
        if self.demo {
            sh.toast("Not available in the demo.", false);
            return;
        }
        match hosts_store::flush_dns() {
            Ok(()) => {
                sh.toast("DNS cache flushed.", false);
                if self.dns.is_some() {
                    self.load_dns();
                }
            }
            Err(e) => sh.toast(e, true),
        }
    }

    fn load_dns(&mut self) {
        if self.demo {
            self.dns = Some(demo_dns_cache());
            return;
        }
        match hosts_store::dns_cache() {
            Ok(list) => {
                self.dns = Some(list);
                self.dns_error = None;
            }
            Err(e) => {
                self.dns = Some(Vec::new());
                self.dns_error = Some(e);
            }
        }
    }

    fn open_edit(&mut self, line: Option<usize>) {
        let dlg = match line.and_then(|l| self.rows.iter().find(|r| r.line == l)) {
            Some(r) => EditDlg {
                line,
                ip: r.entry.ip.clone(),
                names: r.entry.hosts.join(" "),
                comment: r.entry.comment.clone(),
                group: r.group.clone(),
                enabled: r.entry.enabled,
                focus: true,
            },
            None => EditDlg {
                line: None,
                ip: "127.0.0.1".into(),
                names: String::new(),
                comment: String::new(),
                group: String::new(),
                enabled: true,
                focus: true,
            },
        };
        self.dialog = Some(Dialog::Edit(dlg));
    }

    fn row_matches(&self, r: &Row, needle: &str) -> bool {
        let shown = match self.show {
            Show::All => true,
            Show::Enabled => r.entry.enabled,
            Show::Disabled => !r.entry.enabled,
            Show::Problems => self.issues_by_line.contains_key(&r.line),
        };
        shown
            && (needle.is_empty()
                || needle.split_whitespace().all(|w| {
                    r.entry.ip.to_lowercase().contains(w)
                        || r.entry.hosts.iter().any(|h| h.to_lowercase().contains(w))
                        || r.entry.comment.to_lowercase().contains(w)
                        || r.group.to_lowercase().contains(w)
                }))
    }

    fn rebuild_visible(&mut self, search: &str) {
        let key = (
            self.version,
            search.to_string(),
            self.show,
            self.collapsed.len(),
        );
        if key == self.visible_key {
            return;
        }
        let needle = search.trim().to_lowercase();
        let matching: Vec<usize> = (0..self.rows.len())
            .filter(|&i| self.row_matches(&self.rows[i], &needle))
            .collect();
        let mut totals: HashMap<&str, (usize, usize)> = HashMap::new();
        for &i in &matching {
            let t = totals.entry(self.rows[i].group.as_str()).or_default();
            t.0 += 1;
            t.1 += self.rows[i].entry.enabled as usize;
        }
        let any_group = matching.iter().any(|&i| !self.rows[i].group.is_empty());
        let mut items = Vec::new();
        let mut current: Option<&str> = None;
        for &i in &matching {
            let g = self.rows[i].group.as_str();
            if any_group && current != Some(g) {
                current = Some(g);
                let (total, enabled) = totals.get(g).copied().unwrap_or_default();
                items.push(Item::Group {
                    name: g.to_string(),
                    total,
                    enabled,
                });
            }
            if !self.collapsed.contains(g) {
                items.push(Item::Entry(i));
            }
        }
        self.visible = items;
        self.visible_key = key;
    }

    // ----------------------------------------------------------------------------------
    // Saving
    // ----------------------------------------------------------------------------------

    fn start_save(
        &mut self,
        ctx: &egui::Context,
        sh: &mut Shared,
        doc: HostsDoc,
        options: SaveOptions,
        done_word: &'static str,
    ) {
        if self.demo {
            sh.toast(
                "Saving is switched off in the demo. Nothing on this PC was changed.",
                false,
            );
            return;
        }
        if self.saving.is_some() {
            return;
        }
        let options = SaveOptions {
            keep_backups: sh.settings.hosts_backups_kept,
            ..options
        };
        let (tx, rx) = channel();
        let (paths, stage, ctx2, doc2) = (
            self.paths.clone(),
            sh.app_dir.clone(),
            ctx.clone(),
            doc.clone(),
        );
        // A restore replaces whatever is there; an ordinary save must not
        // silently undo another program's change.
        let expected = (!options.overwrite_changes).then(|| self.loaded_bytes.clone());
        std::thread::spawn(move || {
            let direct = hosts_store::save(&paths, &doc2, expected.as_deref(), options);
            let result = match direct {
                Err(SaveError::NeedsElevation) => hosts_store::save_elevated(
                    &paths,
                    &doc2,
                    expected.as_deref(),
                    options,
                    &stage,
                    false,
                ),
                other => other,
            };
            let _ = tx.send(result);
            ctx2.request_repaint();
        });
        self.saving = Some(SaveJob {
            rx,
            doc,
            options,
            done_word,
        });
    }

    fn poll_save(&mut self, sh: &mut Shared) {
        let Some(job) = &self.saving else { return };
        let Ok(result) = job.rx.try_recv() else {
            return;
        };
        let job = self.saving.take().expect("job");
        match result {
            Ok(outcome) => {
                self.reload_from_disk();
                let mut text = if outcome.unchanged {
                    "The hosts file already had this content.".to_string()
                } else {
                    match &outcome.backup {
                        Some(b) => format!(
                            "{}. The previous version was backed up as {}.",
                            job.done_word,
                            b.file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_default()
                        ),
                        None => format!("{}.", job.done_word),
                    }
                };
                if !outcome.unchanged && sh.settings.flush_dns_after_save {
                    match hosts_store::flush_dns() {
                        Ok(()) => text.push_str(" DNS cache flushed."),
                        Err(e) => text.push_str(&format!(" {e}")),
                    }
                }
                sh.toast(text, false);
            }
            Err(SaveError::ReadOnly) => {
                self.held = Some((job.doc, job.options, job.done_word));
                self.dialog = Some(Dialog::ReadOnly);
            }
            Err(SaveError::ChangedOnDisk) => {
                self.held = Some((job.doc, job.options, job.done_word));
                self.dialog = Some(Dialog::Changed);
            }
            Err(e) => {
                // A backup may have been made even though the write failed.
                self.backups = hosts_store::list_backups(&self.paths);
                sh.toast(e.message(), true);
            }
        }
    }

    // ----------------------------------------------------------------------------------
    // Page
    // ----------------------------------------------------------------------------------

    pub fn ui(&mut self, ui: &mut Ui, sh: &mut Shared) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let save_key = ctx.input(|i| i.modifiers.command && i.key_pressed(Key::S));
        let busy = self.saving.is_some();

        let enabled = self.enabled_count;
        let subtitle = format!(
            "{} entries, {} switched on. Names listed here win over DNS on this PC.",
            thousands(self.rows.len()),
            thousands(enabled)
        );
        let (mut do_save, mut do_revert, mut do_reload, mut do_import) =
            (save_key && self.dirty, false, false, false);
        let mut do_export: Option<Format> = None;
        let mut do_flush = false;
        let mut do_dedupe = false;
        let has_duplicates = self.has_duplicates;
        widgets::page_header(ui, "Hosts file", &subtitle, |ui| {
            let label = if busy {
                "Saving…".to_string()
            } else {
                Icon::SAVE.with("Save")
            };
            if widgets::primary_button(ui, &label, self.dirty && !busy)
                .on_hover_text(if sh.elevated {
                    "Write the changes to the hosts file (Ctrl+S). A backup is made first."
                } else {
                    "Write the changes to the hosts file (Ctrl+S). A backup is made first; \
                     Windows then asks for administrator approval."
                })
                .clicked()
            {
                do_save = true;
            }
            if widgets::ghost_button_enabled(ui, &Icon::UNDO.with("Revert"), self.dirty && !busy)
                .on_hover_text("Throw away the changes that have not been saved")
                .clicked()
            {
                do_revert = true;
            }
            ui.menu_button(RichText::new(Icon::MORE.with("More")), |ui| {
                ui.set_min_width(230.0);
                if ui
                    .button(Icon::IMPORT.with("Import a hosts file or block list…"))
                    .clicked()
                {
                    do_import = true;
                    ui.close_menu();
                }
                if ui
                    .add_enabled(
                        has_duplicates,
                        egui::Button::new(Icon::BROOM.with("Remove duplicates")),
                    )
                    .on_hover_text(
                        "Removes names that repeat an earlier line with the same address",
                    )
                    .on_disabled_hover_text("No name is listed twice with the same address.")
                    .clicked()
                {
                    do_dedupe = true;
                    ui.close_menu();
                }
                ui.separator();
                for (label, f) in [
                    ("Export as CSV…", Format::Csv),
                    ("Export as JSON…", Format::Json),
                    ("Export as web page (HTML)…", Format::Html),
                ] {
                    if ui.button(label).clicked() {
                        do_export = Some(f);
                        ui.close_menu();
                    }
                }
                ui.separator();
                if ui.button(Icon::REFRESH.with("Reload from disk")).clicked() {
                    do_reload = true;
                    ui.close_menu();
                }
                if ui.button("Flush the DNS cache now").clicked() {
                    do_flush = true;
                    ui.close_menu();
                }
            });
        });

        self.status_strip(ui, sh, &p);
        ui.add_space(4.0);

        // ---- Sub-tabs and filters ---------------------------------------------------
        let problem_lines = self.issues_by_line.len();
        let mut add_entry = false;
        ui.allocate_ui_with_layout(
            vec2(ui.available_width(), 36.0),
            Layout::left_to_right(Align::Center),
            |ui| {
                let tabs = [
                    format!("Entries  {}", thousands(self.rows.len())),
                    "Raw text".to_string(),
                    format!("Profiles  {}", self.profiles.len()),
                    format!("Backups  {}", self.backups.len()),
                    "DNS cache".to_string(),
                ];
                let labels: Vec<&str> = tabs.iter().map(String::as_str).collect();
                let current = match self.sub {
                    Sub::Entries => 0,
                    Sub::Raw => 1,
                    Sub::Profiles => 2,
                    Sub::Backups => 3,
                    Sub::Dns => 4,
                };
                if let Some(i) = widgets::segmented(ui, &labels, current) {
                    self.sub = [
                        Sub::Entries,
                        Sub::Raw,
                        Sub::Profiles,
                        Sub::Backups,
                        Sub::Dns,
                    ][i];
                }
                if self.sub == Sub::Entries {
                    ui.add_space(8.0);
                    ui.spacing_mut().item_spacing.x = 6.0;
                    let off = self.rows.len() - enabled;
                    for (show, label, count) in [
                        (Show::All, "All", self.rows.len()),
                        (Show::Enabled, "On", enabled),
                        (Show::Disabled, "Off", off),
                        (Show::Problems, "Problems", problem_lines),
                    ] {
                        if widgets::chip(ui, label, Some(count), self.show == show).clicked() {
                            self.show = show;
                        }
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if widgets::ghost_button(ui, &Icon::ADD.with("Add entry")).clicked() {
                            add_entry = true;
                        }
                    });
                }
            },
        );
        ui.add_space(2.0);

        match self.sub {
            Sub::Entries => self.entries_ui(ui, sh, &p),
            Sub::Raw => self.raw_ui(ui, sh, &p),
            Sub::Profiles => self.profiles_ui(ui, sh, &p),
            Sub::Backups => self.backups_ui(ui, sh, &p),
            Sub::Dns => self.dns_ui(ui, sh, &p),
        }

        // ---- Deferred actions -------------------------------------------------------
        if add_entry {
            self.open_edit(None);
        }
        if do_save && !busy {
            let doc = self.doc.clone();
            self.start_save(&ctx, sh, doc, SaveOptions::default(), "Saved");
        }
        if do_revert {
            self.doc = HostsDoc::from_bytes(&self.loaded_bytes);
            self.changed();
            sh.toast("Changes reverted.", false);
        }
        if do_reload {
            if self.dirty {
                self.dialog = Some(Dialog::Reload);
            } else if self.demo {
                sh.toast("The demo has no file to reload.", false);
            } else {
                self.reload_from_disk();
                sh.toast("Reloaded from disk.", false);
            }
        }
        if do_flush {
            self.flush_dns(sh);
        }
        if do_dedupe {
            let removed = self.doc.remove_duplicates();
            self.changed();
            sh.toast(
                format!(
                    "Removed {} repeated name{}. Save to apply.",
                    thousands(removed),
                    if removed == 1 { "" } else { "s" }
                ),
                false,
            );
        }
        if do_import {
            self.import(sh);
        }
        if let Some(format) = do_export {
            self.export(sh, format);
        }
    }

    /// One line under the header: where the file is and what state it is in.
    fn status_strip(&mut self, ui: &mut Ui, sh: &Shared, p: &Palette) {
        ui.allocate_ui_with_layout(
            vec2(ui.available_width(), 24.0),
            Layout::left_to_right(Align::Center),
            |ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                ui.label(
                    RichText::new(self.paths.hosts.to_string_lossy())
                        .font(mono(12.5))
                        .color(p.faint),
                );
                if let Some(e) = &self.load_error {
                    widgets::badge(ui, "Could not be read", p.danger).on_hover_text(e);
                } else if self.missing {
                    widgets::badge(ui, "File does not exist yet", p.warn).on_hover_text(
                        "Windows treats a missing hosts file as an empty one. Saving creates it.",
                    );
                }
                if self.read_only {
                    widgets::badge(ui, &Icon::LOCK.with("Read-only"), p.warn).on_hover_text(
                        "The file is marked read-only. SocketForge asks before lifting the mark \
                         for a save, and puts it back afterwards.",
                    );
                }
                if self.dirty {
                    widgets::badge(ui, "Unsaved changes", p.accent);
                }
                if !self.issues.is_empty() {
                    let n = self.issues_by_line.len();
                    let text = format!("{n} line{} with problems", if n == 1 { "" } else { "s" });
                    if widgets::badge(ui, &text, p.warn)
                        .on_hover_text("Show them")
                        .interact(Sense::click())
                        .clicked()
                    {
                        self.sub = Sub::Entries;
                        self.show = Show::Problems;
                    }
                }
                if !sh.elevated && !self.demo {
                    ui.label(
                        RichText::new("Saving asks for administrator approval.")
                            .size(12.0)
                            .color(p.faint),
                    );
                }
            },
        );
    }

    // ----------------------------------------------------------------------------------
    // Entries
    // ----------------------------------------------------------------------------------

    fn entries_ui(&mut self, ui: &mut Ui, sh: &mut Shared, p: &Palette) {
        self.rebuild_visible(&sh.search);
        if self.visible.is_empty() {
            if let Some(e) = self.load_error.clone() {
                widgets::empty_state(
                    ui,
                    Icon::ERROR,
                    p.danger,
                    "The hosts file could not be read",
                    &e,
                );
            } else if !sh.search.trim().is_empty() {
                let text = format!("No entry matches \"{}\".", sh.search.trim());
                widgets::empty_state(ui, Icon::SEARCH, p.muted, "No matches", &text);
            } else {
                let (title, text) = match self.show {
                    Show::Problems => (
                        "No problems found",
                        "Every line is a valid mapping, and no name is listed twice.",
                    ),
                    Show::Enabled => ("Nothing is switched on", "Every entry is commented out."),
                    Show::Disabled => ("Nothing is switched off", "Every entry is active."),
                    Show::All => (
                        "The hosts file has no entries",
                        "Add one to point a name such as shop.test at 127.0.0.1.",
                    ),
                };
                widgets::empty_state(ui, Icon::DOCUMENT, p.accent, title, text);
            }
            return;
        }

        let mut acts: Vec<Act> = Vec::new();
        Frame::new()
            .fill(p.card)
            .stroke(Stroke::new(1.0_f32, p.border))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(Margin::symmetric(6, 6))
            .show(ui, |ui| {
                ui.set_height(ui.available_height());
                ui.set_width(ui.available_width());
                let width = ui.available_width();
                let cols = Cols::for_width(width);
                // Header
                let (head, _) = ui.allocate_exact_size(vec2(width, 30.0), Sense::hover());
                let mut x = head.left() + cols.switch;
                for (label, w) in [
                    ("Address", cols.addr),
                    ("Names", cols.names),
                    (
                        if self.show == Show::Problems {
                            "Problem"
                        } else {
                            "Comment"
                        },
                        cols.comment,
                    ),
                ] {
                    if w > 0.0 {
                        ui.painter().text(
                            pos2(x, head.center().y),
                            Align2::LEFT_CENTER,
                            label,
                            regular(12.5),
                            p.faint,
                        );
                    }
                    x += w;
                }
                ui.painter().hline(
                    head.x_range(),
                    head.bottom(),
                    Stroke::new(1.0_f32, p.border),
                );
                ui.spacing_mut().item_spacing.y = 0.0;
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show_rows(ui, ROW_H, self.visible.len(), |ui, range| {
                        for idx in range {
                            match &self.visible[idx] {
                                Item::Group {
                                    name,
                                    total,
                                    enabled,
                                } => {
                                    self.group_row(ui, p, width, name, *total, *enabled, &mut acts)
                                }
                                Item::Entry(i) => {
                                    self.entry_row(ui, p, &cols, width, &self.rows[*i], &mut acts)
                                }
                            }
                        }
                    });
            });

        for act in acts {
            match act {
                Act::Toggle(line, on) => {
                    self.doc.set_enabled(line, on);
                    self.changed();
                }
                Act::GroupToggle(group, on) => {
                    self.doc.set_group_enabled(&group, on);
                    self.changed();
                }
                Act::Collapse(group) => {
                    if !self.collapsed.remove(&group) {
                        self.collapsed.insert(group);
                    }
                    // The cache key only knows the number of collapsed groups.
                    self.visible_key.0 = u64::MAX;
                }
                Act::Edit(line) => self.open_edit(Some(line)),
                Act::Delete(line) => self.dialog = Some(Dialog::Delete(line)),
                Act::Copy(text, what) => {
                    ui.ctx().copy_text(text);
                    sh.toast(format!("Copied {what}."), false);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn group_row(
        &self,
        ui: &mut Ui,
        p: &Palette,
        width: f32,
        name: &str,
        total: usize,
        enabled: usize,
        acts: &mut Vec<Act>,
    ) {
        let (rect, resp) = ui.allocate_exact_size(vec2(width, ROW_H), Sense::click());
        let collapsed = self.collapsed.contains(name);
        if resp.hovered() {
            ui.painter()
                .rect_filled(rect.shrink2(vec2(0.0, 1.0)), CornerRadius::same(8), p.hover);
        }
        let chevron = if collapsed {
            Icon::CHEVRON_RIGHT
        } else {
            Icon::CHEVRON_DOWN
        };
        ui.painter().text(
            pos2(rect.left() + 20.0, rect.center().y),
            Align2::CENTER_CENTER,
            chevron.glyph(),
            regular(11.0),
            p.muted,
        );
        let is_profile = name.starts_with("Profile: ");
        let title = if name.is_empty() { "No group" } else { name };
        let galley = widgets::elided(
            ui,
            title,
            semibold(14.0),
            if name.is_empty() { p.muted } else { p.text },
            (width - 330.0).max(120.0),
        );
        let title_w = galley.size().x;
        ui.painter().galley(
            pos2(rect.left() + 38.0, rect.center().y - galley.size().y / 2.0),
            galley,
            p.text,
        );
        let mut x = rect.left() + 38.0 + title_w + 10.0;
        if is_profile {
            let r = Rect::from_min_size(pos2(x, rect.top()), vec2(80.0, ROW_H));
            x += widgets::paint_badge(ui, r, "PROFILE", p.info) + 8.0;
        }
        ui.painter().text(
            pos2(x, rect.center().y),
            Align2::LEFT_CENTER,
            format!("{enabled} of {total} on"),
            regular(12.5),
            p.faint,
        );
        // All on / all off, right-aligned.
        let buttons = Rect::from_min_max(
            pos2(rect.right() - 150.0, rect.top()),
            pos2(rect.right() - 8.0, rect.bottom()),
        );
        let mut child = ui.new_child(
            UiBuilder::new()
                .max_rect(buttons)
                .layout(Layout::right_to_left(Align::Center)),
        );
        child.spacing_mut().button_padding = vec2(8.0, 3.0);
        let small = |text: &str, on: bool| {
            egui::Button::new(RichText::new(text).size(12.5).color(if on {
                p.text
            } else {
                p.faint
            }))
            .fill(egui::Color32::TRANSPARENT)
            .stroke(Stroke::new(1.0_f32, p.border))
            .corner_radius(CornerRadius::same(7))
        };
        if child
            .add_enabled(enabled > 0, small("All off", enabled > 0))
            .clicked()
        {
            acts.push(Act::GroupToggle(name.to_string(), false));
        }
        if child
            .add_enabled(enabled < total, small("All on", enabled < total))
            .clicked()
        {
            acts.push(Act::GroupToggle(name.to_string(), true));
        }
        if resp.clicked() {
            acts.push(Act::Collapse(name.to_string()));
        }
    }

    fn entry_row(
        &self,
        ui: &mut Ui,
        p: &Palette,
        cols: &Cols,
        width: f32,
        row: &Row,
        acts: &mut Vec<Act>,
    ) {
        let (rect, resp) = ui.allocate_exact_size(vec2(width, ROW_H), Sense::click());
        if resp.hovered() {
            ui.painter()
                .rect_filled(rect.shrink2(vec2(0.0, 1.0)), CornerRadius::same(8), p.hover);
        }
        let e = &row.entry;
        let issue_ids = self.issues_by_line.get(&row.line);
        let (main, dim) = if e.enabled {
            (p.text, p.muted)
        } else {
            (p.faint, p.faint)
        };

        // Switch
        let sw = Rect::from_center_size(
            pos2(rect.left() + cols.switch / 2.0 + 4.0, rect.center().y),
            vec2(38.0, 22.0),
        );
        let mut child = ui.new_child(UiBuilder::new().max_rect(sw).id_salt(("sw", row.line)));
        if widgets::toggle(&mut child, e.enabled, true)
            .on_hover_text(if e.enabled {
                "Switch off (comments the line out)"
            } else {
                "Switch on (removes the #)"
            })
            .clicked()
        {
            acts.push(Act::Toggle(row.line, !e.enabled));
        }

        let cell = |x: f32, w: f32| {
            Rect::from_min_max(pos2(x, rect.top()), pos2(x + w - 14.0, rect.bottom()))
        };
        let mut x = rect.left() + cols.switch;
        widgets::text_in(ui, cell(x, cols.addr), &e.ip, mono(13.5), main);
        x += cols.addr;
        let names = e.hosts.join("   ");
        let cut = widgets::text_in(ui, cell(x, cols.names), &names, semibold(14.0), main);
        if cut && resp.hovered() {
            resp.clone().on_hover_text(e.hosts.join("\n"));
        }
        x += cols.names;
        if cols.comment > 0.0 {
            if self.show == Show::Problems {
                let text = issue_ids
                    .map(|ids| {
                        ids.iter()
                            .map(|&i| self.issues[i].message.as_str())
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_default();
                let cut = widgets::text_in(ui, cell(x, cols.comment), &text, regular(13.0), p.warn);
                if cut && resp.hovered() {
                    resp.clone().on_hover_text(text);
                }
            } else {
                widgets::text_in(ui, cell(x, cols.comment), &e.comment, regular(13.0), dim);
            }
        }
        x += cols.comment;

        // Status badge
        let badge_rect = Rect::from_min_size(pos2(x, rect.top()), vec2(cols.status, ROW_H));
        if let Some(ids) = issue_ids {
            let first = &self.issues[ids[0]];
            let (label, color) = match first.kind {
                IssueKind::BadAddress => ("Bad address", p.danger),
                IssueKind::BadName => ("Bad name", p.danger),
                IssueKind::Duplicate => ("Duplicate", p.warn),
                IssueKind::Conflict => ("Ignored: conflict", p.warn),
                IssueKind::Invalid => ("Invalid", p.danger),
            };
            let w = widgets::paint_badge(ui, badge_rect, label, color);
            let hit = Rect::from_min_size(
                pos2(badge_rect.left(), rect.center().y - 10.0),
                vec2(w, 20.0),
            );
            let tip = ids
                .iter()
                .map(|&i| self.issues[i].message.clone())
                .collect::<Vec<_>>()
                .join("\n");
            ui.interact(hit, ui.id().with(("issue", row.line)), Sense::hover())
                .on_hover_text(tip);
        } else if !e.enabled {
            widgets::paint_badge(ui, badge_rect, "Off", p.faint);
        }

        // Row actions
        let actions = Rect::from_min_max(
            pos2(rect.right() - cols.actions, rect.top()),
            pos2(rect.right() - 4.0, rect.bottom()),
        );
        let mut child = ui.new_child(
            UiBuilder::new()
                .max_rect(actions)
                .id_salt(("act", row.line))
                .layout(Layout::right_to_left(Align::Center)),
        );
        child.spacing_mut().item_spacing.x = 0.0;
        if widgets::icon_button(&mut child, Icon::DELETE, "Delete").clicked() {
            acts.push(Act::Delete(row.line));
        }
        if widgets::icon_button(&mut child, Icon::EDIT, "Edit").clicked() {
            acts.push(Act::Edit(row.line));
        }
        if resp.double_clicked() {
            acts.push(Act::Edit(row.line));
        }
        resp.context_menu(|ui| {
            ui.set_min_width(190.0);
            let names = if e.hosts.len() == 1 {
                "Copy the name"
            } else {
                "Copy the names"
            };
            if ui.button(Icon::COPY.with(names)).clicked() {
                acts.push(Act::Copy(e.hosts.join(" "), "the names"));
                ui.close_menu();
            }
            if ui.button("Copy the address").clicked() {
                acts.push(Act::Copy(e.ip.clone(), "the address"));
                ui.close_menu();
            }
            if ui.button("Copy the line").clicked() {
                acts.push(Act::Copy(e.format(), "the line"));
                ui.close_menu();
            }
            ui.separator();
            let switch = if e.enabled { "Switch off" } else { "Switch on" };
            if ui.button(switch).clicked() {
                acts.push(Act::Toggle(row.line, !e.enabled));
                ui.close_menu();
            }
            if ui.button(Icon::EDIT.with("Edit…")).clicked() {
                acts.push(Act::Edit(row.line));
                ui.close_menu();
            }
            if ui.button(Icon::DELETE.with("Delete…")).clicked() {
                acts.push(Act::Delete(row.line));
                ui.close_menu();
            }
        });
    }

    // ----------------------------------------------------------------------------------
    // Raw text
    // ----------------------------------------------------------------------------------

    fn raw_ui(&mut self, ui: &mut Ui, sh: &Shared, p: &Palette) {
        let large = self.doc.lines.len() > LARGE_LINES;
        if large && !self.raw_edit_large {
            self.raw_fast_ui(ui, sh, p);
            return;
        }
        if large {
            ui.allocate_ui_with_layout(
                vec2(ui.available_width(), 30.0),
                Layout::left_to_right(Align::Center),
                |ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    ui.label(
                        RichText::new(format!(
                            "Editing {} lines as text. Typing is slow with a file this long.",
                            thousands(self.doc.lines.len())
                        ))
                        .color(p.warn),
                    );
                    if widgets::small_button(ui, "Back to the fast view").clicked() {
                        self.raw_edit_large = false;
                    }
                },
            );
        }
        if self.raw_version != self.version {
            self.raw = self.doc.to_text();
            self.raw_version = self.version;
        }
        let mut edited = false;
        Frame::new()
            .fill(p.card)
            .stroke(Stroke::new(1.0_f32, p.border))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(Margin::symmetric(10, 10))
            .show(ui, |ui| {
                ui.set_height(ui.available_height());
                ui.set_width(ui.available_width());
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let edit = egui::TextEdit::multiline(&mut self.raw)
                            .font(mono(13.5))
                            .frame(false)
                            .code_editor()
                            .desired_width(f32::INFINITY)
                            .desired_rows(24);
                        edited = ui.add(edit).changed();
                    });
            });
        if edited {
            self.doc.set_text(&self.raw);
            self.changed();
            self.raw_version = self.version;
        }
    }

    /// The raw text of a long file: only the lines on screen are drawn, with
    /// line numbers, and the search box filters them. Read-only.
    fn raw_fast_ui(&mut self, ui: &mut Ui, sh: &Shared, p: &Palette) {
        let needle = sh.search.trim().to_lowercase();
        if self.raw_lines_key.0 != self.version || self.raw_lines_key.1 != needle {
            self.raw_lines = if needle.is_empty() {
                Vec::new()
            } else {
                (0..self.doc.lines.len())
                    .filter(|&i| self.doc.lines[i].raw.to_lowercase().contains(&needle))
                    .collect()
            };
            self.raw_lines_key = (self.version, needle.clone());
        }
        let filtered = !needle.is_empty();
        let count = if filtered {
            self.raw_lines.len()
        } else {
            self.doc.lines.len()
        };
        ui.allocate_ui_with_layout(
            vec2(ui.available_width(), 30.0),
            Layout::left_to_right(Align::Center),
            |ui| {
                ui.spacing_mut().item_spacing.x = 10.0;
                let text = if filtered {
                    format!(
                        "{} of {} lines match the search.",
                        thousands(count),
                        thousands(self.doc.lines.len())
                    )
                } else {
                    format!(
                        "{} lines, shown read-only so that scrolling stays quick. Edit \
                         entries in the table.",
                        thousands(count)
                    )
                };
                ui.label(RichText::new(text).color(p.muted));
                if widgets::small_button(ui, &Icon::EDIT.with("Edit as text anyway"))
                    .on_hover_text("Opens the whole file in a text box. Slow with a long file.")
                    .clicked()
                {
                    self.raw_edit_large = true;
                }
            },
        );
        Frame::new()
            .fill(p.card)
            .stroke(Stroke::new(1.0_f32, p.border))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(Margin::symmetric(6, 8))
            .show(ui, |ui| {
                ui.set_height(ui.available_height());
                ui.set_width(ui.available_width());
                if count == 0 {
                    widgets::empty_state(
                        ui,
                        Icon::SEARCH,
                        p.muted,
                        "No matches",
                        "No line of the file contains the search text.",
                    );
                    return;
                }
                let width = ui.available_width();
                let digits = self.doc.lines.len().to_string().len() as f32;
                let gutter = 22.0 + digits * 8.0;
                ui.spacing_mut().item_spacing.y = 0.0;
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show_rows(ui, RAW_LINE_H, count, |ui, range| {
                        for idx in range {
                            let li = if filtered { self.raw_lines[idx] } else { idx };
                            let line = &self.doc.lines[li];
                            let (rect, _) =
                                ui.allocate_exact_size(vec2(width, RAW_LINE_H), Sense::hover());
                            ui.painter().text(
                                pos2(rect.left() + gutter - 12.0, rect.center().y),
                                Align2::RIGHT_CENTER,
                                (li + 1).to_string(),
                                mono(12.0),
                                p.faint,
                            );
                            let color = if self.issues_by_line.contains_key(&li) {
                                p.warn
                            } else {
                                match &line.kind {
                                    LineKind::Entry(e) if e.enabled => p.text,
                                    LineKind::Entry(_) => p.muted,
                                    LineKind::Invalid => p.danger,
                                    LineKind::Comment | LineKind::Blank => p.faint,
                                }
                            };
                            let cell = Rect::from_min_max(
                                pos2(rect.left() + gutter, rect.top()),
                                pos2(rect.right() - 16.0, rect.bottom()),
                            );
                            widgets::text_in(ui, cell, &line.raw, mono(13.0), color);
                        }
                    });
            });
    }

    // ----------------------------------------------------------------------------------
    // DNS cache
    // ----------------------------------------------------------------------------------

    fn dns_ui(&mut self, ui: &mut Ui, sh: &mut Shared, p: &Palette) {
        if self.dns.is_none() {
            self.load_dns();
        }
        let (mut refresh, mut flush) = (false, false);
        ui.allocate_ui_with_layout(
            vec2(ui.available_width(), 40.0),
            Layout::left_to_right(Align::Center),
            |ui| {
                ui.label(
                    RichText::new(
                        "Names Windows looked up lately and still remembers. Flush the cache \
                         to make it ask again.",
                    )
                    .color(p.muted),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if widgets::ghost_button(ui, &Icon::BROOM.with("Flush the cache"))
                        .on_hover_text(
                            "Forgets every remembered answer. Needs no administrator rights.",
                        )
                        .clicked()
                    {
                        flush = true;
                    }
                    if widgets::ghost_button(ui, &Icon::REFRESH.with("Read again")).clicked() {
                        refresh = true;
                    }
                });
            },
        );
        let needle = sh.search.trim().to_lowercase();
        let list = self.dns.as_deref().unwrap_or(&[]);
        let shown: Vec<&DnsCacheEntry> = list
            .iter()
            .filter(|e| needle.is_empty() || e.name.to_lowercase().contains(&needle))
            .collect();
        let mut copy: Option<String> = None;
        let mut add: Option<String> = None;
        if let Some(e) = &self.dns_error {
            widgets::empty_state(
                ui,
                Icon::ERROR,
                p.danger,
                "The DNS cache could not be read",
                e,
            );
        } else if list.is_empty() {
            widgets::empty_state(
                ui,
                Icon::GLOBE,
                p.accent,
                "The DNS cache is empty",
                "Windows has not looked up any name since the cache was last flushed.",
            );
        } else if shown.is_empty() {
            let text = format!("No remembered name contains \"{}\".", sh.search.trim());
            widgets::empty_state(ui, Icon::SEARCH, p.muted, "No matches", &text);
        } else {
            Frame::new()
                .fill(p.card)
                .stroke(Stroke::new(1.0_f32, p.border))
                .corner_radius(CornerRadius::same(12))
                .inner_margin(Margin::symmetric(6, 6))
                .show(ui, |ui| {
                    ui.set_height(ui.available_height());
                    ui.set_width(ui.available_width());
                    let width = ui.available_width();
                    ui.spacing_mut().item_spacing.y = 0.0;
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show_rows(ui, DNS_ROW_H, shown.len(), |ui, range| {
                            for i in range {
                                let e = shown[i];
                                let (rect, resp) =
                                    ui.allocate_exact_size(vec2(width, DNS_ROW_H), Sense::hover());
                                if resp.hovered() {
                                    ui.painter().rect_filled(
                                        rect.shrink2(vec2(0.0, 1.0)),
                                        CornerRadius::same(8),
                                        p.hover,
                                    );
                                }
                                let badge = Rect::from_min_size(
                                    pos2(rect.left() + 12.0, rect.top()),
                                    vec2(70.0, DNS_ROW_H),
                                );
                                let label = hosts_store::record_type_label(e.record_type);
                                let color = match e.record_type {
                                    1 => p.info,
                                    28 => p.udp,
                                    _ => p.muted,
                                };
                                let used = widgets::paint_badge(ui, badge, &label, color);
                                let hint = hosts_store::record_type_hint(e.record_type);
                                if !hint.is_empty() {
                                    let hit = Rect::from_min_size(
                                        pos2(badge.left(), rect.center().y - 11.0),
                                        vec2(used, 22.0),
                                    );
                                    ui.interact(hit, ui.id().with(("dns-type", i)), Sense::hover())
                                        .on_hover_text(hint);
                                }
                                let in_hosts = self.names_on.contains(&e.name.to_lowercase());
                                let name = Rect::from_min_max(
                                    pos2(rect.left() + 92.0, rect.top()),
                                    pos2(rect.right() - 250.0, rect.bottom()),
                                );
                                widgets::text_in(ui, name, &e.name, semibold(14.0), p.text);
                                if in_hosts {
                                    let r = Rect::from_min_size(
                                        pos2(rect.right() - 240.0, rect.top()),
                                        vec2(150.0, DNS_ROW_H),
                                    );
                                    widgets::paint_badge(ui, r, "IN YOUR HOSTS FILE", p.accent);
                                }
                                let actions = Rect::from_min_max(
                                    pos2(rect.right() - 80.0, rect.top()),
                                    pos2(rect.right() - 4.0, rect.bottom()),
                                );
                                let mut child = ui.new_child(
                                    UiBuilder::new()
                                        .max_rect(actions)
                                        .id_salt(("dns-act", i))
                                        .layout(Layout::right_to_left(Align::Center)),
                                );
                                child.spacing_mut().item_spacing.x = 0.0;
                                if widgets::icon_button(
                                    &mut child,
                                    Icon::ADD,
                                    "Add this name to the hosts file…",
                                )
                                .clicked()
                                {
                                    add = Some(e.name.clone());
                                }
                                if widgets::icon_button(&mut child, Icon::COPY, "Copy the name")
                                    .clicked()
                                {
                                    copy = Some(e.name.clone());
                                }
                            }
                        });
                });
        }
        if let Some(name) = copy {
            ui.ctx().copy_text(name);
            sh.toast("Copied the name.", false);
        }
        if let Some(name) = add {
            self.dialog = Some(Dialog::Edit(EditDlg {
                line: None,
                ip: "127.0.0.1".into(),
                names: name,
                comment: String::new(),
                group: String::new(),
                enabled: true,
                focus: true,
            }));
        }
        if refresh {
            self.load_dns();
            if self.dns_error.is_none() {
                let n = self.dns.as_ref().map(Vec::len).unwrap_or(0);
                sh.toast(
                    format!(
                        "{} remembered name{}.",
                        thousands(n),
                        if n == 1 { "" } else { "s" }
                    ),
                    false,
                );
            }
        }
        if flush {
            self.flush_dns(sh);
        }
    }

    // ----------------------------------------------------------------------------------
    // Profiles
    // ----------------------------------------------------------------------------------

    fn save_profiles(&mut self, sh: &mut Shared) {
        if self.demo {
            return;
        }
        if let Err(e) = hosts_store::save_profiles(&self.paths, &self.profiles) {
            sh.toast(e, true);
        }
    }

    fn profiles_ui(&mut self, ui: &mut Ui, sh: &mut Shared, p: &Palette) {
        let mut new_profile = false;
        let mut from_group: Option<String> = None;
        ui.allocate_ui_with_layout(
            vec2(ui.available_width(), 40.0),
            Layout::left_to_right(Align::Center),
            |ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(
                            "A profile is a set of entries you switch on and off together, for \
                             example \"dev\" or \"staging\". Switching one on writes its entries \
                             into a marked block at the end of the file. Save to apply.",
                        )
                        .color(p.muted),
                    )
                    .wrap(),
                );
            },
        );
        ui.horizontal(|ui| {
            if widgets::ghost_button(ui, &Icon::ADD.with("New profile")).clicked() {
                new_profile = true;
            }
            let groups: &[String] = &self.plain_groups;
            if !groups.is_empty() {
                ui.menu_button(
                    RichText::new(Icon::TAG.with("Make a profile from a group")),
                    |ui| {
                        ui.set_min_width(240.0);
                        egui::ScrollArea::vertical()
                            .max_height(320.0)
                            .show(ui, |ui| {
                                for g in groups {
                                    if ui.button(g).clicked() {
                                        from_group = Some(g.clone());
                                        ui.close_menu();
                                    }
                                }
                            });
                    },
                );
            }
        });
        ui.add_space(2.0);

        // Blocks that are in the file but not saved as a profile on this PC.
        let unsaved_blocks: Vec<String> = self
            .active_profiles
            .iter()
            .filter(|n| !self.profiles.iter().any(|p| &p.name == *n))
            .cloned()
            .collect();

        if self.profiles.is_empty() && unsaved_blocks.is_empty() {
            widgets::empty_state(
                ui,
                Icon::TAG,
                p.accent,
                "No profiles yet",
                "Create one for each environment you switch between.",
            );
        }

        let mut toggle: Option<(usize, bool)> = None;
        let mut edit: Option<usize> = None;
        let mut delete: Option<usize> = None;
        let mut adopt: Option<String> = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (i, profile) in self.profiles.iter().enumerate() {
                    let active = self.profile_active(&profile.name);
                    widgets::card(ui, |ui| {
                        ui.allocate_ui_with_layout(
                            vec2(ui.available_width(), 30.0),
                            Layout::left_to_right(Align::Center),
                            |ui| {
                                if widgets::toggle(ui, active, true)
                                    .on_hover_text(if active {
                                        "Remove this profile's block from the file"
                                    } else {
                                        "Write this profile's entries into the file"
                                    })
                                    .clicked()
                                {
                                    toggle = Some((i, !active));
                                }
                                ui.add_space(4.0);
                                ui.label(RichText::new(&profile.name).font(semibold(16.0)));
                                let n = profile.entries.len();
                                ui.label(
                                    RichText::new(format!(
                                        "{n} entr{}",
                                        if n == 1 { "y" } else { "ies" }
                                    ))
                                    .color(p.faint),
                                );
                                if active {
                                    widgets::badge(ui, "IN THE FILE", p.accent);
                                }
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if widgets::icon_button(ui, Icon::DELETE, "Delete profile")
                                        .clicked()
                                    {
                                        delete = Some(i);
                                    }
                                    if widgets::icon_button(ui, Icon::EDIT, "Edit profile")
                                        .clicked()
                                    {
                                        edit = Some(i);
                                    }
                                });
                            },
                        );
                        ui.add_space(2.0);
                        for e in profile.entries.iter().take(4) {
                            let (line, _) = ui.allocate_exact_size(
                                vec2(ui.available_width(), 20.0),
                                Sense::hover(),
                            );
                            let ip = Rect::from_min_max(
                                pos2(line.left() + 50.0, line.top()),
                                pos2(line.left() + 220.0, line.bottom()),
                            );
                            widgets::text_in(ui, ip, &e.ip, mono(13.0), p.muted);
                            let names = Rect::from_min_max(
                                pos2(line.left() + 230.0, line.top()),
                                pos2(line.right() - 8.0, line.bottom()),
                            );
                            let text = if e.comment.is_empty() {
                                e.hosts.join("   ")
                            } else {
                                format!("{}     # {}", e.hosts.join("   "), e.comment)
                            };
                            widgets::text_in(ui, names, &text, regular(13.5), p.text);
                        }
                        if profile.entries.len() > 4 {
                            ui.horizontal(|ui| {
                                ui.add_space(46.0);
                                ui.label(
                                    RichText::new(format!(
                                        "and {} more",
                                        profile.entries.len() - 4
                                    ))
                                    .size(12.5)
                                    .color(p.faint),
                                );
                            });
                        }
                    });
                    ui.add_space(2.0);
                }
                for name in &unsaved_blocks {
                    widgets::card(ui, |ui| {
                        ui.allocate_ui_with_layout(
                            vec2(ui.available_width(), 30.0),
                            Layout::left_to_right(Align::Center),
                            |ui| {
                                ui.label(RichText::new(name).font(semibold(16.0)));
                                widgets::badge(ui, "IN THE FILE ONLY", p.warn).on_hover_text(
                                    "The hosts file has a block for this profile, but the \
                                     profile is not saved on this PC.",
                                );
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if widgets::ghost_button(ui, "Keep as a profile").clicked() {
                                        adopt = Some(name.clone());
                                    }
                                });
                            },
                        );
                    });
                    ui.add_space(2.0);
                }
            });

        if let Some((i, on)) = toggle {
            if on {
                let profile = self.profiles[i].clone();
                self.doc.profile_on(&profile);
            } else {
                let name = self.profiles[i].name.clone();
                self.doc.profile_off(&name);
            }
            self.changed();
        }
        if let Some(i) = edit {
            let profile = &self.profiles[i];
            self.dialog = Some(Dialog::Profile(ProfileDlg {
                index: Some(i),
                name: profile.name.clone(),
                text: profile_text(profile),
            }));
        }
        if let Some(i) = delete {
            self.dialog = Some(Dialog::ProfileDelete(i));
        }
        if new_profile {
            self.dialog = Some(Dialog::Profile(ProfileDlg {
                index: None,
                name: String::new(),
                text: "127.0.0.1\tapp.dev.test".into(),
            }));
        }
        if let Some(group) = from_group {
            let profile = self.doc.profile_from_group(&group, &group);
            self.dialog = Some(Dialog::Profile(ProfileDlg {
                index: None,
                name: group,
                text: profile_text(&profile),
            }));
        }
        if let Some(name) = adopt {
            let profile = self
                .doc
                .profile_from_group(&format!("Profile: {name}"), &name);
            self.profiles.push(profile);
            self.save_profiles(sh);
        }
    }

    // ----------------------------------------------------------------------------------
    // Backups
    // ----------------------------------------------------------------------------------

    fn backups_ui(&mut self, ui: &mut Ui, sh: &mut Shared, p: &Palette) {
        let mut backup_now = false;
        let mut open_folder = false;
        ui.allocate_ui_with_layout(
            vec2(ui.available_width(), 40.0),
            Layout::left_to_right(Align::Center),
            |ui| {
                ui.label(
                    RichText::new(format!(
                        "A backup is made automatically before every save. The newest {} are kept.",
                        sh.settings.hosts_backups_kept
                    ))
                    .color(p.muted),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if widgets::ghost_button(ui, &Icon::FOLDER_OPEN.with("Open folder")).clicked() {
                        open_folder = true;
                    }
                    if widgets::ghost_button(ui, &Icon::SAVE.with("Back up now")).clicked() {
                        backup_now = true;
                    }
                });
            },
        );
        if self.backups.is_empty() {
            widgets::empty_state(
                ui,
                Icon::HISTORY,
                p.accent,
                "No backups yet",
                "The first one appears when you save a change, or when you choose Back up now.",
            );
        } else {
            let now = now_unix();
            let mut restore: Option<usize> = None;
            Frame::new()
                .fill(p.card)
                .stroke(Stroke::new(1.0_f32, p.border))
                .corner_radius(CornerRadius::same(12))
                .inner_margin(Margin::symmetric(6, 6))
                .show(ui, |ui| {
                    ui.set_height(ui.available_height());
                    ui.set_width(ui.available_width());
                    let width = ui.available_width();
                    ui.spacing_mut().item_spacing.y = 0.0;
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show_rows(ui, 52.0, self.backups.len(), |ui, range| {
                            for i in range {
                                let b = &self.backups[i];
                                let (rect, resp) =
                                    ui.allocate_exact_size(vec2(width, 52.0), Sense::hover());
                                if resp.hovered() {
                                    ui.painter().rect_filled(
                                        rect.shrink2(vec2(0.0, 1.0)),
                                        CornerRadius::same(8),
                                        p.hover,
                                    );
                                }
                                ui.painter().text(
                                    pos2(rect.left() + 26.0, rect.center().y),
                                    Align2::CENTER_CENTER,
                                    Icon::HISTORY.glyph(),
                                    regular(17.0),
                                    if i == 0 { p.accent } else { p.muted },
                                );
                                ui.painter().text(
                                    pos2(rect.left() + 52.0, rect.center().y - 9.0),
                                    Align2::LEFT_CENTER,
                                    fmt_time(b.time),
                                    semibold(14.0),
                                    p.text,
                                );
                                ui.painter().text(
                                    pos2(rect.left() + 52.0, rect.center().y + 10.0),
                                    Align2::LEFT_CENTER,
                                    format!(
                                        "{} ago   ·   {} entries   ·   {}   ·   {}",
                                        fmt_age(now - b.time),
                                        b.entries,
                                        fmt_bytes(b.size),
                                        b.file_name()
                                    ),
                                    regular(12.5),
                                    p.muted,
                                );
                                if i == 0 {
                                    let r = Rect::from_min_size(
                                        pos2(rect.left() + 220.0, rect.center().y - 19.0),
                                        vec2(70.0, 20.0),
                                    );
                                    widgets::paint_badge(ui, r, "NEWEST", p.accent);
                                }
                                let btn = Rect::from_min_max(
                                    pos2(rect.right() - 130.0, rect.top()),
                                    pos2(rect.right() - 8.0, rect.bottom()),
                                );
                                let mut child = ui.new_child(
                                    UiBuilder::new()
                                        .max_rect(btn)
                                        .id_salt(("restore", i))
                                        .layout(Layout::right_to_left(Align::Center)),
                                );
                                if widgets::ghost_button(&mut child, &Icon::UNDO.with("Restore"))
                                    .clicked()
                                {
                                    restore = Some(i);
                                }
                            }
                        });
                });
            if let Some(i) = restore {
                self.dialog = Some(Dialog::Restore(i));
            }
        }

        if backup_now {
            if self.demo {
                sh.toast("Not available in the demo.", false);
            } else {
                match hosts_store::backup_now(&self.paths) {
                    Ok(Some(path)) => {
                        hosts_store::prune_backups(&self.paths, sh.settings.hosts_backups_kept);
                        self.backups = hosts_store::list_backups(&self.paths);
                        sh.toast(
                            format!(
                                "Backed up as {}.",
                                path.file_name()
                                    .map(|n| n.to_string_lossy().into_owned())
                                    .unwrap_or_default()
                            ),
                            false,
                        );
                    }
                    Ok(None) => sh.toast("The newest backup already has this content.", false),
                    Err(e) => sh.toast(e, true),
                }
            }
        }
        if open_folder {
            if self.demo {
                sh.toast("Not available in the demo.", false);
            } else {
                let _ = std::fs::create_dir_all(&self.paths.backups);
                if let Err(e) = crate::actions::open_url(&self.paths.backups.to_string_lossy()) {
                    sh.toast(e, true);
                }
            }
        }
    }

    // ----------------------------------------------------------------------------------
    // Import / export
    // ----------------------------------------------------------------------------------

    fn import(&mut self, sh: &mut Shared) {
        if self.demo || sh.screenshot {
            sh.toast("Importing is switched off in the demo.", false);
            return;
        }
        let Some(path) = rfd::FileDialog::new()
            .set_title("Choose a hosts file or a block list")
            .add_filter(
                "Hosts files, lists and text",
                &["txt", "hosts", "bak", "list", "*"],
            )
            .pick_file()
        else {
            return;
        };
        match std::fs::metadata(&path) {
            Ok(m) if m.len() > hosts_store::MAX_HOSTS_BYTES => {
                sh.toast("That file is larger than 32 MB.", true);
                return;
            }
            _ => {}
        }
        match std::fs::read(&path) {
            Ok(bytes) => {
                let file = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let dlg = ImportDlg::new(&file, HostsDoc::from_bytes(&bytes));
                if dlg.entries == 0 && dlg.block.names.is_empty() {
                    sh.toast("That file has no host entries and no names to block.", true);
                    return;
                }
                self.dialog = Some(Dialog::Import(dlg));
            }
            Err(e) => sh.toast(format!("Could not read the file: {e}"), true),
        }
    }

    fn export(&mut self, sh: &mut Shared, format: Format) {
        if self.demo || sh.screenshot {
            sh.toast("Exporting is switched off in the demo.", false);
            return;
        }
        let Some(path) = rfd::FileDialog::new()
            .set_title("Export the hosts entries")
            .set_file_name(format!("hosts-entries.{}", format.extension()))
            .save_file()
        else {
            return;
        };
        match export::write(&path, &export::hosts(&self.rows, format), format) {
            Ok(()) => sh.toast(
                format!("Exported {} entries.", thousands(self.rows.len())),
                false,
            ),
            Err(e) => sh.toast(e, true),
        }
    }

    // ----------------------------------------------------------------------------------
    // Dialogs
    // ----------------------------------------------------------------------------------

    /// Modal dialogs of the hosts view; called every frame after the panels.
    pub fn dialogs(&mut self, ctx: &egui::Context, sh: &mut Shared) {
        self.poll_save(sh);
        if self.saving.is_some() {
            // The UAC prompt may be open: keep polling for the result.
            ctx.request_repaint_after(std::time::Duration::from_millis(200));
        }
        let Some(mut dialog) = self.dialog.take() else {
            return;
        };
        let keep = match &mut dialog {
            Dialog::Edit(d) => self.edit_dialog(ctx, d),
            Dialog::Delete(line) => self.delete_dialog(ctx, *line),
            Dialog::Restore(i) => self.restore_dialog(ctx, sh, *i),
            Dialog::ReadOnly => self.read_only_dialog(ctx, sh),
            Dialog::Changed => self.changed_dialog(ctx, sh),
            Dialog::Reload => self.reload_dialog(ctx, sh),
            Dialog::Profile(d) => self.profile_dialog(ctx, sh, d),
            Dialog::ProfileDelete(i) => self.profile_delete_dialog(ctx, sh, *i),
            Dialog::Import(d) => self.import_dialog(ctx, sh, d),
        };
        // A dialog may have opened another one (read-only -> ...); keep that.
        if keep && self.dialog.is_none() {
            self.dialog = Some(dialog);
        }
    }

    fn edit_dialog(&mut self, ctx: &egui::Context, d: &mut EditDlg) -> bool {
        let mut keep = true;
        let mut apply = false;
        let problems = edit_problems(&d.ip, &d.names);
        let groups: Vec<String> = self.plain_groups.clone();
        let in_profile = d.group.starts_with("Profile: ");
        let dismissed = widgets::modal(ctx, "hosts-edit", 480.0, |ui| {
            let p = pal(ui);
            widgets::modal_title(
                ui,
                if d.line.is_some() {
                    "Edit entry"
                } else {
                    "Add entry"
                },
            );
            let label = |ui: &mut Ui, text: &str| {
                ui.add_space(4.0);
                ui.label(RichText::new(text).size(12.5).color(p.muted));
            };
            label(ui, "Address (IPv4 or IPv6)");
            let r = ui.add(
                egui::TextEdit::singleline(&mut d.ip)
                    .font(mono(14.0))
                    .desired_width(f32::INFINITY)
                    .hint_text("127.0.0.1"),
            );
            label(ui, "Host names, separated by spaces");
            let names = ui.add(
                egui::TextEdit::singleline(&mut d.names)
                    .desired_width(f32::INFINITY)
                    .hint_text("shop.test api.shop.test"),
            );
            if d.focus {
                if d.line.is_some() {
                    r.request_focus();
                } else {
                    names.request_focus();
                }
                d.focus = false;
            }
            label(ui, "Comment (optional)");
            ui.add(egui::TextEdit::singleline(&mut d.comment).desired_width(f32::INFINITY));
            if d.line.is_none() {
                label(ui, "Group (optional): an existing one, or a new name");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut d.group)
                            .desired_width(ui.available_width() - 130.0)
                            .hint_text("No group"),
                    );
                    if !groups.is_empty() {
                        egui::ComboBox::from_id_salt("hosts-edit-group")
                            .selected_text("Existing")
                            .width(110.0)
                            .show_ui(ui, |ui| {
                                for g in &groups {
                                    if ui.selectable_label(&d.group == g, g).clicked() {
                                        d.group = g.clone();
                                    }
                                }
                            });
                    }
                });
            } else if in_profile {
                ui.add_space(4.0);
                widgets::para(
                    ui,
                    "This entry belongs to a profile block. Edit the profile itself to keep the \
                     change when the profile is switched off and on again.",
                );
            }
            ui.add_space(8.0);
            widgets::checkbox(ui, &mut d.enabled, "Switched on");
            ui.add_space(4.0);
            // A fixed-height area for validation messages, so the dialog does not jump.
            ui.allocate_ui_with_layout(
                vec2(ui.available_width(), 40.0),
                Layout::top_down(Align::Min),
                |ui| {
                    let untouched = d.names.trim().is_empty() && d.line.is_none();
                    for msg in problems.iter().take(2) {
                        if !untouched {
                            ui.add(
                                egui::Label::new(RichText::new(msg).size(12.5).color(p.warn))
                                    .truncate(),
                            );
                        }
                    }
                },
            );
            let enter = ui.input(|i| i.key_pressed(Key::Enter));
            widgets::button_row(ui, |ui| {
                let text = if d.line.is_some() { "Apply" } else { "Add" };
                if widgets::primary_button(ui, text, problems.is_empty()).clicked()
                    || (enter && problems.is_empty())
                {
                    apply = true;
                }
                if widgets::ghost_button(ui, "Cancel").clicked() {
                    keep = false;
                }
            });
        });
        if apply {
            let entry = Entry {
                enabled: d.enabled,
                ip: d.ip.trim().to_string(),
                hosts: d.names.split_whitespace().map(str::to_string).collect(),
                comment: d.comment.trim().to_string(),
            };
            match d.line {
                Some(line) => {
                    self.doc.update_entry(line, entry);
                }
                None => {
                    self.doc.add_entry(entry, Some(d.group.as_str()));
                }
            }
            self.changed();
            return false;
        }
        keep && !dismissed
    }

    fn delete_dialog(&mut self, ctx: &egui::Context, line: usize) -> bool {
        let Some(entry) = self.doc.entry(line).cloned() else {
            return false;
        };
        let (mut keep, mut delete) = (true, false);
        let dismissed = widgets::modal(ctx, "hosts-delete", 420.0, |ui| {
            widgets::modal_title(ui, "Delete this entry?");
            widgets::para(
                ui,
                &format!(
                    "{}  →  {}\n\nThe line is removed from the hosts file when you save. To keep \
                     it for later, switch it off instead.",
                    entry.hosts.join(", "),
                    entry.ip
                ),
            );
            ui.add_space(10.0);
            widgets::button_row(ui, |ui| {
                if widgets::danger_button(ui, "Delete", true).clicked() {
                    delete = true;
                }
                if widgets::ghost_button(ui, "Cancel").clicked() {
                    keep = false;
                }
            });
        });
        if delete {
            self.doc.delete_line(line);
            self.changed();
            return false;
        }
        keep && !dismissed
    }

    fn restore_dialog(&mut self, ctx: &egui::Context, sh: &mut Shared, index: usize) -> bool {
        let Some(backup) = self.backups.get(index).cloned() else {
            return false;
        };
        let (mut keep, mut restore) = (true, false);
        let dirty = self.dirty;
        let dismissed = widgets::modal(ctx, "hosts-restore", 460.0, |ui| {
            widgets::modal_title(ui, "Restore this backup?");
            widgets::para(
                ui,
                &format!(
                    "The hosts file is replaced by the backup from {} ({} entries). The current \
                     file is backed up first, so this can be undone.{}",
                    fmt_time(backup.time),
                    backup.entries,
                    if dirty {
                        "\n\nYour unsaved changes in the editor will be lost."
                    } else {
                        ""
                    }
                ),
            );
            ui.add_space(10.0);
            widgets::button_row(ui, |ui| {
                if widgets::primary_button(ui, "Restore", true).clicked() {
                    restore = true;
                }
                if widgets::ghost_button(ui, "Cancel").clicked() {
                    keep = false;
                }
            });
        });
        if restore {
            if self.demo {
                sh.toast(
                    "Restoring is switched off in the demo. Nothing on this PC was changed.",
                    false,
                );
                return false;
            }
            match std::fs::read(&backup.path) {
                Ok(bytes) => {
                    let doc = HostsDoc::from_bytes(&bytes);
                    let options = SaveOptions {
                        overwrite_changes: true,
                        ..Default::default()
                    };
                    self.start_save(ctx, sh, doc, options, "Restored");
                }
                Err(e) => sh.toast(format!("Could not read the backup: {e}"), true),
            }
            return false;
        }
        keep && !dismissed
    }

    fn read_only_dialog(&mut self, ctx: &egui::Context, sh: &mut Shared) -> bool {
        let (mut keep, mut go) = (true, false);
        let dismissed = widgets::modal(ctx, "hosts-readonly", 460.0, |ui| {
            widgets::modal_title(ui, "The hosts file is read-only");
            widgets::para(
                ui,
                "Someone, or a security tool, marked the file read-only to protect it. \
                 SocketForge can lift the mark for this save and put it back right after.",
            );
            ui.add_space(10.0);
            widgets::button_row(ui, |ui| {
                if widgets::primary_button(ui, "Save anyway", true).clicked() {
                    go = true;
                }
                if widgets::ghost_button(ui, "Cancel").clicked() {
                    keep = false;
                }
            });
        });
        if go {
            if let Some((doc, options, word)) = self.held.take() {
                let options = SaveOptions {
                    clear_read_only: true,
                    ..options
                };
                self.start_save(ctx, sh, doc, options, word);
            }
            return false;
        }
        if !keep || dismissed {
            self.held = None;
            return false;
        }
        true
    }

    fn changed_dialog(&mut self, ctx: &egui::Context, sh: &mut Shared) -> bool {
        let (mut keep, mut overwrite, mut reload) = (true, false, false);
        let dismissed = widgets::modal(ctx, "hosts-changed", 480.0, |ui| {
            widgets::modal_title(ui, "The hosts file changed on disk");
            widgets::para(
                ui,
                "Another program changed the hosts file after SocketForge opened it. Saving now \
                 would undo that change (a backup of it is kept). Reloading shows the new file \
                 and drops your edits.",
            );
            ui.add_space(10.0);
            widgets::button_row(ui, |ui| {
                if widgets::danger_button(ui, "Save my version", true).clicked() {
                    overwrite = true;
                }
                if widgets::ghost_button(ui, "Reload").clicked() {
                    reload = true;
                }
                if widgets::ghost_button(ui, "Cancel").clicked() {
                    keep = false;
                }
            });
        });
        if overwrite {
            if let Some((doc, options, word)) = self.held.take() {
                let options = SaveOptions {
                    overwrite_changes: true,
                    ..options
                };
                self.start_save(ctx, sh, doc, options, word);
            }
            return false;
        }
        if reload {
            self.held = None;
            self.reload_from_disk();
            return false;
        }
        if !keep || dismissed {
            self.held = None;
            return false;
        }
        true
    }

    fn reload_dialog(&mut self, ctx: &egui::Context, sh: &mut Shared) -> bool {
        let (mut keep, mut go) = (true, false);
        let dismissed = widgets::modal(ctx, "hosts-reload", 420.0, |ui| {
            widgets::modal_title(ui, "Reload and lose your changes?");
            widgets::para(
                ui,
                "The editor has changes that are not saved. Reloading reads the file from disk \
                 again and drops them.",
            );
            ui.add_space(10.0);
            widgets::button_row(ui, |ui| {
                if widgets::danger_button(ui, "Reload", true).clicked() {
                    go = true;
                }
                if widgets::ghost_button(ui, "Cancel").clicked() {
                    keep = false;
                }
            });
        });
        if go {
            if self.demo {
                self.doc = HostsDoc::from_bytes(&self.loaded_bytes);
                self.changed();
            } else {
                self.reload_from_disk();
            }
            sh.toast("Reloaded from disk.", false);
            return false;
        }
        keep && !dismissed
    }

    fn profile_dialog(&mut self, ctx: &egui::Context, sh: &mut Shared, d: &mut ProfileDlg) -> bool {
        let (mut keep, mut save) = (true, false);
        let entries = profile_entries(&d.text);
        let name = d.name.trim().to_string();
        let name_taken = self
            .profiles
            .iter()
            .enumerate()
            .any(|(i, p)| Some(i) != d.index && p.name.eq_ignore_ascii_case(&name));
        let problem = if name.is_empty() {
            Some("Give the profile a name.".to_string())
        } else if name_taken {
            Some("Another profile already has this name.".to_string())
        } else if entries.is_empty() {
            Some("Add at least one line such as \"127.0.0.1 app.dev.test\".".to_string())
        } else {
            entries
                .iter()
                .flat_map(|e| edit_problems(&e.ip, &e.hosts.join(" ")))
                .next()
        };
        let dismissed = widgets::modal(ctx, "hosts-profile", 540.0, |ui| {
            let p = pal(ui);
            widgets::modal_title(
                ui,
                if d.index.is_some() {
                    "Edit profile"
                } else {
                    "New profile"
                },
            );
            ui.label(RichText::new("Name").size(12.5).color(p.muted));
            ui.add(
                egui::TextEdit::singleline(&mut d.name)
                    .desired_width(f32::INFINITY)
                    .hint_text("dev"),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new("Entries, one per line: address, then names")
                    .size(12.5)
                    .color(p.muted),
            );
            egui::ScrollArea::vertical()
                .id_salt("hosts-profile-text")
                .max_height(220.0)
                .min_scrolled_height(220.0)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut d.text)
                            .font(mono(13.5))
                            .code_editor()
                            .desired_width(f32::INFINITY)
                            .desired_rows(10),
                    );
                });
            ui.add_space(4.0);
            ui.allocate_ui_with_layout(
                vec2(ui.available_width(), 20.0),
                Layout::left_to_right(Align::Center),
                |ui| match &problem {
                    Some(msg) => {
                        ui.add(
                            egui::Label::new(RichText::new(msg).size(12.5).color(p.warn))
                                .truncate(),
                        );
                    }
                    None => {
                        ui.label(
                            RichText::new(format!("{} entries", entries.len()))
                                .size(12.5)
                                .color(p.faint),
                        );
                    }
                },
            );
            widgets::button_row(ui, |ui| {
                if widgets::primary_button(ui, "Save profile", problem.is_none()).clicked() {
                    save = true;
                }
                if widgets::ghost_button(ui, "Cancel").clicked() {
                    keep = false;
                }
            });
        });
        if save {
            let profile = Profile {
                name: name.clone(),
                entries,
            };
            // If the profile is switched on, the block in the file follows the edit.
            let old_name = d.index.map(|i| self.profiles[i].name.clone());
            let was_active = old_name
                .as_deref()
                .map(|n| self.doc.is_profile_active(n))
                .unwrap_or(false);
            if was_active {
                if let Some(old) = &old_name {
                    self.doc.profile_off(old);
                }
                self.doc.profile_on(&profile);
                self.changed();
            }
            match d.index {
                Some(i) => self.profiles[i] = profile,
                None => self.profiles.push(profile),
            }
            self.save_profiles(sh);
            return false;
        }
        keep && !dismissed
    }

    fn profile_delete_dialog(
        &mut self,
        ctx: &egui::Context,
        sh: &mut Shared,
        index: usize,
    ) -> bool {
        let Some(profile) = self.profiles.get(index).cloned() else {
            return false;
        };
        let active = self.profile_active(&profile.name);
        let (mut keep, mut delete) = (true, false);
        let dismissed = widgets::modal(ctx, "hosts-profile-delete", 430.0, |ui| {
            widgets::modal_title(ui, &format!("Delete the profile \"{}\"?", profile.name));
            widgets::para(
                ui,
                if active {
                    "The profile is switched on: its block is also removed from the hosts file \
                     when you save."
                } else {
                    "The profile is removed from SocketForge. The hosts file is not changed."
                },
            );
            ui.add_space(10.0);
            widgets::button_row(ui, |ui| {
                if widgets::danger_button(ui, "Delete", true).clicked() {
                    delete = true;
                }
                if widgets::ghost_button(ui, "Cancel").clicked() {
                    keep = false;
                }
            });
        });
        if delete {
            if active {
                self.doc.profile_off(&profile.name);
                self.changed();
            }
            self.profiles.remove(index);
            self.save_profiles(sh);
            return false;
        }
        keep && !dismissed
    }

    fn import_dialog(&mut self, ctx: &egui::Context, sh: &mut Shared, d: &mut ImportDlg) -> bool {
        let (mut keep, mut merge) = (true, false);
        let both = d.entries > 0 && !d.block.names.is_empty();
        let dismissed = widgets::modal(ctx, "hosts-import", 500.0, |ui| {
            let p = pal(ui);
            widgets::modal_title(
                ui,
                if d.as_block {
                    "Add a block list to the hosts file"
                } else {
                    "Merge entries into the hosts file"
                },
            );
            if both {
                ui.add_space(2.0);
                if let Some(i) = widgets::segmented(
                    ui,
                    &["As a block list", "As ordinary entries"],
                    usize::from(!d.as_block),
                ) {
                    d.set_block(i == 0);
                }
                ui.add_space(6.0);
            }
            widgets::para(ui, &d.summary());
            if d.as_block {
                ui.add_space(6.0);
                ui.label(
                    RichText::new("Point the names at")
                        .size(12.5)
                        .color(p.muted),
                );
                if let Some(i) =
                    widgets::segmented(ui, &["0.0.0.0 (fails at once)", "127.0.0.1"], d.sink)
                {
                    d.sink = i;
                }
                if d.block.names.len() + self.rows.len() > MANY_NAMES {
                    ui.add_space(6.0);
                    ui.add(
                        egui::Label::new(
                            RichText::new(
                                "With this many names Windows itself becomes slow at looking \
                                 names up, because it reads the whole hosts file. A shorter \
                                 list works better.",
                            )
                            .size(12.5)
                            .color(p.warn),
                        )
                        .wrap(),
                    );
                }
            }
            ui.add_space(6.0);
            ui.label(
                RichText::new("Put them in the group")
                    .size(12.5)
                    .color(p.muted),
            );
            ui.add(egui::TextEdit::singleline(&mut d.group).desired_width(f32::INFINITY));
            ui.add_space(10.0);
            widgets::button_row(ui, |ui| {
                let label = if d.as_block { "Add the names" } else { "Merge" };
                if widgets::primary_button(ui, label, !d.group.trim().is_empty()).clicked() {
                    merge = true;
                }
                if widgets::ghost_button(ui, "Cancel").clicked() {
                    keep = false;
                }
            });
        });
        if merge {
            let text = if d.as_block {
                let report =
                    self.doc
                        .add_block_list(&d.block.names, SINKS[d.sink.min(1)], d.group.trim());
                block_report_text(&report)
            } else {
                let report = self.doc.merge(&d.doc, d.group.trim());
                format!(
                    "{} added, {} already there, {} added switched off because of a conflict. \
                     Save to apply.",
                    thousands(report.added),
                    thousands(report.already_present),
                    thousands(report.conflicts)
                )
            };
            self.changed();
            sh.toast(text, false);
            return false;
        }
        keep && !dismissed
    }
}

/// The toast after a block list was added.
fn block_report_text(report: &hosts::BlockReport) -> String {
    let mut s = format!(
        "{} name{} added",
        thousands(report.added),
        if report.added == 1 { "" } else { "s" }
    );
    if report.already_blocked > 0 {
        s.push_str(&format!(
            ", {} already blocked",
            thousands(report.already_blocked)
        ));
    }
    if report.kept_yours > 0 {
        s.push_str(&format!(
            ", {} left alone because your hosts file maps them",
            thousands(report.kept_yours)
        ));
    }
    s.push_str(if report.added > 0 {
        ". Save to apply."
    } else {
        ". Nothing to save."
    });
    s
}

/// Invented cache content for `--demo`.
fn demo_dns_cache() -> Vec<DnsCacheEntry> {
    let e = |name: &str, record_type: u16| DnsCacheEntry {
        name: name.into(),
        record_type,
    };
    hosts_store::tidy_dns_cache(vec![
        e("shop.test", 1),
        e("shop.test", 28),
        e("api.shop.test", 1),
        e("admin.shop.test", 1),
        e("staging.example.test", 1),
        e("nas.lab", 1),
        e("printer.lab", 1),
        e("updates.example.net", 1),
        e("updates.example.net", 28),
        e("cdn.example.net", 5),
        e("cdn.example.net", 65),
        e("mail.example.org", 1),
        e("_ldap._tcp.corp.example.org", 33),
        e("registry.packages.example", 1),
        e("registry.packages.example", 28),
        e("telemetry.vendor.example", 1),
        e("10.2.0.192.in-addr.arpa", 12),
        e("time.example.net", 1),
        e("fonts.example.com", 1),
        e("fonts.example.com", 65),
    ])
}

/// Column widths of the entries table.
struct Cols {
    switch: f32,
    addr: f32,
    names: f32,
    comment: f32,
    status: f32,
    actions: f32,
}

impl Cols {
    fn for_width(width: f32) -> Cols {
        let mut c = Cols {
            switch: 62.0,
            addr: 190.0,
            names: 0.0,
            comment: 250.0,
            status: 140.0,
            actions: 76.0,
        };
        let mut rest = width - c.switch - c.addr - c.comment - c.status - c.actions;
        if rest < 220.0 {
            rest += c.comment;
            c.comment = 0.0;
        }
        c.names = rest.max(140.0);
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_fit_the_width() {
        let wide = Cols::for_width(1012.0);
        let sum = wide.switch + wide.addr + wide.names + wide.comment + wide.status + wide.actions;
        assert!((sum - 1012.0).abs() < 0.5);
        assert!(wide.comment > 0.0 && wide.names >= 220.0);
        let narrow = Cols::for_width(640.0);
        assert_eq!(narrow.comment, 0.0);
        assert!(narrow.names >= 140.0);
    }

    #[test]
    fn edit_dialog_validation() {
        assert!(edit_problems("127.0.0.1", "shop.test api.shop.test").is_empty());
        assert!(edit_problems("::1", "a.test").is_empty());
        assert_eq!(edit_problems("", "").len(), 2);
        assert_eq!(edit_problems("300.1.1.1", "a.test").len(), 1);
        assert_eq!(edit_problems("10.0.0.1", "ok.test bad/name").len(), 1);
    }

    #[test]
    fn caches_follow_the_document() {
        let mut v = HostsView::new(true, Path::new("C:\\nowhere"));
        assert_eq!(v.enabled_count, 10);
        assert_eq!(
            v.plain_groups,
            vec![
                "localhost name resolution is handled within DNS itself.",
                "Local development",
                "Staging servers",
                "Lab network"
            ]
        );
        assert_eq!(v.active_profiles, vec!["dev"]);
        assert!(v.profile_active("dev") && !v.profile_active("staging"));
        assert!(v.names_on.contains("shop.test") && !v.names_on.contains("legacy.shop.test"));
        assert!(!v.has_duplicates);
        v.doc
            .add_entry(Entry::new("127.0.0.1", &["Shop.Test"]), None);
        v.changed();
        assert!(v.has_duplicates && v.has_unsaved());
        assert_eq!(v.doc.remove_duplicates(), 1);
        v.changed();
        assert!(!v.has_duplicates);
        v.doc.profile_off("dev");
        v.changed();
        assert!(v.active_profiles.is_empty());
        assert!(!v.is_saving() && !v.has_dialog());
    }

    #[test]
    fn long_files_use_the_fast_raw_view_and_small_ones_do_not() {
        let mut v = HostsView::new(true, Path::new("C:\\nowhere"));
        assert!(v.doc.lines.len() <= LARGE_LINES);
        v.apply_view("hosts-raw-large");
        assert!(v.doc.lines.len() > LARGE_LINES);
        assert!(v.sub == Sub::Raw && !v.raw_edit_large);
        assert!(!v.has_unsaved(), "the demo list counts as the file on disk");
        // Choosing to edit as text sticks until the file is short again.
        v.raw_edit_large = true;
        v.changed();
        assert!(v.raw_edit_large);
        v.doc = HostsDoc::parse("127.0.0.1 a.test\r\n");
        v.changed();
        assert!(!v.raw_edit_large);
    }

    #[test]
    fn import_dialog_recognises_block_lists() {
        // A plain list of names is not a hosts file at all: block list only.
        let d = ImportDlg::new(
            "names.txt",
            HostsDoc::parse("ads.example\ntracker.example\n"),
        );
        assert!(d.as_block);
        assert_eq!((d.entries, d.block.names.len()), (0, 2));
        assert_eq!(d.group, "Block list: names.txt");
        assert!(d.summary().contains("2 names to block"));

        // A few ordinary entries: merged line by line, as before.
        let mut d = ImportDlg::new(
            "team.hosts",
            HostsDoc::parse("10.0.0.5 intranet.example\n10.0.0.6 wiki.example\n"),
        );
        assert!(!d.as_block);
        assert_eq!(d.group, "Imported from team.hosts");
        assert!(d.summary().contains("2 entries"));
        // Switching the way of importing renames the untouched group...
        d.set_block(true);
        assert_eq!(d.group, "Block list: team.hosts");
        // ...but not one the user typed.
        d.group = "Mine".into();
        d.set_block(false);
        assert_eq!(d.group, "Mine");

        // Many names that all point nowhere: a block list in hosts format.
        let text: String = (0..50)
            .map(|i| format!("0.0.0.0 ads{i}.example\n"))
            .chain([
                "0.0.0.0 ads1.example\n".to_string(),
                "||*.x.example^\n".to_string(),
            ])
            .collect();
        let d = ImportDlg::new("list.txt", HostsDoc::parse(&text));
        assert!(d.as_block);
        let s = d.summary();
        assert!(s.contains("50 names") && s.contains("1 listed more than once"));
        assert!(s.contains("1 line that cannot"));
    }

    #[test]
    fn block_report_texts() {
        let r = |added, already_blocked, kept_yours| hosts::BlockReport {
            added,
            already_blocked,
            kept_yours,
        };
        assert_eq!(
            block_report_text(&r(1, 0, 0)),
            "1 name added. Save to apply."
        );
        assert_eq!(
            block_report_text(&r(12_000, 30, 2)),
            "12,000 names added, 30 already blocked, 2 left alone because your hosts file maps \
             them. Save to apply."
        );
        assert!(block_report_text(&r(0, 5, 0)).ends_with("Nothing to save."));
    }

    #[test]
    fn demo_dns_cache_is_sorted_and_invented() {
        let mut v = HostsView::new(true, Path::new("C:\\nowhere"));
        v.apply_view("hosts-dns");
        v.load_dns();
        let list = v.dns.clone().unwrap();
        assert!(list.len() >= 15);
        assert!(list
            .windows(2)
            .all(|w| w[0].name.to_lowercase() <= w[1].name.to_lowercase()));
        assert!(list.iter().all(|e| e.name.ends_with(".test")
            || e.name.ends_with(".lab")
            || e.name.contains("example")
            || e.name.ends_with(".arpa")));
        assert!(list.iter().any(|e| v.names_on.contains(&e.name)));
    }

    #[test]
    fn profile_text_round_trip() {
        let profile = &hosts::demo_profiles()[1];
        let text = profile_text(profile);
        assert_eq!(profile_entries(&text), profile.entries);
        // Comments and blank lines in the editor are ignored.
        let entries = profile_entries("# note\n\n127.0.0.1 a.test b.test # two\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hosts, vec!["a.test", "b.test"]);
        assert_eq!(entries[0].comment, "two");
    }

    #[test]
    fn demo_view_groups_filters_and_edits_in_memory() {
        let mut v = HostsView::new(true, Path::new("C:\\nowhere"));
        assert_eq!(v.count(), Some(14));
        assert!(!v.has_unsaved());
        v.rebuild_visible("");
        let groups = v
            .visible
            .iter()
            .filter(|i| matches!(i, Item::Group { .. }))
            .count();
        assert_eq!(groups, 5);
        v.rebuild_visible("staging");
        assert!(v.visible.iter().all(|i| match i {
            Item::Entry(i) => v.rows[*i].group == "Staging servers",
            Item::Group { name, .. } => name == "Staging servers",
        }));
        v.show = Show::Problems;
        v.rebuild_visible("");
        let entries = v
            .visible
            .iter()
            .filter(|i| matches!(i, Item::Entry(_)))
            .count();
        assert_eq!(entries, 2, "one conflict and one bad address");
        // Toggling marks the document as changed; reverting clears it.
        v.apply_view("hosts-unsaved");
        assert!(v.has_unsaved());
        v.doc = HostsDoc::from_bytes(&v.loaded_bytes);
        v.changed();
        assert!(!v.has_unsaved());
        assert_eq!(v.backups.len(), 4);
        assert_eq!(fmt_bytes(612), "612 bytes");
        assert_eq!(fmt_bytes(2048), "2.0 KB");
    }
}
