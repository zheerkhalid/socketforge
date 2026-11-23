//! User settings, stored as JSON in `%LOCALAPPDATA%\SocketForge\settings.json`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemeChoice {
    Dark,
    Light,
    System,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupBy {
    None,
    Process,
    Port,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme: ThemeChoice,
    /// Seconds between refreshes of the port and connection tables (1-60).
    pub refresh_secs: u32,
    /// Refresh automatically.
    pub live: bool,
    pub group_by: GroupBy,
    /// Look up host names for remote addresses (sends DNS queries).
    pub reverse_dns: bool,
    /// Record listeners opening and closing in the history.
    pub record_history: bool,
    /// Most history events kept.
    pub history_limit: usize,
    /// Ports to watch: an alert fires when one of them is taken.
    pub watched_ports: Vec<u16>,
    /// Alert when any new TCP listener appears.
    pub alert_new_listeners: bool,
    /// Alert when a watched port is taken.
    pub alert_watched: bool,
    /// Show the notification-area icon.
    pub tray_icon: bool,
    /// Closing the window keeps SocketForge running in the notification area.
    pub close_to_tray: bool,
    /// Flush the DNS cache after saving the hosts file.
    pub flush_dns_after_save: bool,
    /// Hosts backups to keep (oldest are removed).
    pub hosts_backups_kept: usize,
    /// Allow "test port" to connect to addresses other than this PC.
    pub probe_non_local: bool,
    /// Your own notes for ports, by [`port_key`] ("TCP 3000").
    pub port_notes: BTreeMap<String, String>,
    /// Ports marked as favourites, by [`port_key`].
    pub favourite_ports: Vec<String>,
    /// The folder last served over HTTP (Tools).
    pub serve_folder: String,
    /// The port last used for serving a folder.
    pub serve_port: u16,
    /// The listening port last used for a forward.
    pub forward_port: u16,
    /// The target last used for a forward.
    pub forward_target: String,
}

/// The key of a port in the notes and favourites: protocol and number.
pub fn port_key(tcp: bool, port: u16) -> String {
    format!("{} {port}", if tcp { "TCP" } else { "UDP" })
}

/// The longest note kept for a port.
pub const NOTE_LIMIT: usize = 200;

impl Default for Settings {
    fn default() -> Self {
        Settings {
            theme: ThemeChoice::Dark,
            refresh_secs: 2,
            live: true,
            group_by: GroupBy::None,
            reverse_dns: false,
            record_history: true,
            history_limit: 5000,
            watched_ports: Vec::new(),
            alert_new_listeners: false,
            alert_watched: true,
            tray_icon: false,
            close_to_tray: false,
            flush_dns_after_save: true,
            hosts_backups_kept: 30,
            probe_non_local: false,
            port_notes: BTreeMap::new(),
            favourite_ports: Vec::new(),
            serve_folder: String::new(),
            serve_port: 8080,
            forward_port: 8081,
            forward_target: String::new(),
        }
    }
}

/// `%LOCALAPPDATA%\SocketForge`.
pub fn app_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("SocketForge")
}

impl Settings {
    pub fn load(dir: &Path) -> Settings {
        let mut s: Settings = std::fs::read_to_string(dir.join("settings.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        s.sanitize();
        s
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("Could not save settings: {e}"))?;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(dir.join("settings.json"), json)
            .map_err(|e| format!("Could not save settings: {e}"))
    }

    /// Brings hand-edited values back into range.
    pub fn sanitize(&mut self) {
        self.refresh_secs = self.refresh_secs.clamp(1, 60);
        self.history_limit = self.history_limit.clamp(100, 100_000);
        self.hosts_backups_kept = self.hosts_backups_kept.clamp(1, 500);
        self.watched_ports.retain(|p| *p != 0);
        self.watched_ports.sort_unstable();
        self.watched_ports.dedup();
        self.port_notes.retain(|_, note| !note.trim().is_empty());
        for note in self.port_notes.values_mut() {
            if note.chars().count() > NOTE_LIMIT {
                *note = note.chars().take(NOTE_LIMIT).collect();
            }
        }
        self.favourite_ports.sort();
        self.favourite_ports.dedup();
    }

    /// Your note for a port ("" when there is none).
    pub fn note(&self, tcp: bool, port: u16) -> &str {
        self.port_notes
            .get(&port_key(tcp, port))
            .map(String::as_str)
            .unwrap_or("")
    }

    /// Sets or (with empty text) removes the note for a port.
    pub fn set_note(&mut self, tcp: bool, port: u16, text: &str) {
        let key = port_key(tcp, port);
        if text.trim().is_empty() {
            self.port_notes.remove(&key);
        } else {
            self.port_notes
                .insert(key, text.chars().take(NOTE_LIMIT).collect());
        }
    }

    pub fn is_favourite(&self, tcp: bool, port: u16) -> bool {
        self.favourite_ports.contains(&port_key(tcp, port))
    }

    /// Marks or unmarks a port as a favourite. Returns the new state.
    pub fn toggle_favourite(&mut self, tcp: bool, port: u16) -> bool {
        let key = port_key(tcp, port);
        match self.favourite_ports.iter().position(|k| *k == key) {
            Some(i) => {
                self.favourite_ports.remove(i);
                false
            }
            None => {
                self.favourite_ports.push(key);
                self.favourite_ports.sort();
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notes_and_favourites() {
        let mut s = Settings::default();
        assert_eq!(s.note(true, 3000), "");
        s.set_note(true, 3000, "storefront dev server");
        s.set_note(false, 3000, "game discovery");
        assert_eq!(s.note(true, 3000), "storefront dev server");
        assert_eq!(s.note(false, 3000), "game discovery");
        s.set_note(false, 3000, "   ");
        assert_eq!(s.note(false, 3000), "");
        assert_eq!(s.port_notes.len(), 1);
        s.set_note(true, 1, &"x".repeat(500));
        assert_eq!(s.note(true, 1).len(), NOTE_LIMIT);

        assert!(!s.is_favourite(true, 5432));
        assert!(s.toggle_favourite(true, 5432));
        assert!(s.toggle_favourite(true, 80));
        assert!(s.is_favourite(true, 5432) && !s.is_favourite(false, 5432));
        assert!(!s.toggle_favourite(true, 5432));
        assert_eq!(s.favourite_ports, vec!["TCP 80".to_string()]);

        // They survive a save and a load; hand-made mess is tidied.
        let dir = std::env::temp_dir().join(format!("socketforge-notes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        s.save(&dir).unwrap();
        assert_eq!(Settings::load(&dir), s);
        std::fs::write(
            dir.join("settings.json"),
            r#"{"port_notes":{"TCP 1":"  ","TCP 2":"ok"},"favourite_ports":["UDP 9","TCP 8","UDP 9"]}"#,
        )
        .unwrap();
        let loaded = Settings::load(&dir);
        assert_eq!(loaded.port_notes.len(), 1);
        assert_eq!(loaded.favourite_ports, vec!["TCP 8", "UDP 9"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn round_trip_and_tolerant_loading() {
        let dir = std::env::temp_dir().join(format!("socketforge-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(Settings::load(&dir), Settings::default());
        let s = Settings {
            theme: ThemeChoice::Light,
            watched_ports: vec![3000, 8080],
            group_by: GroupBy::Process,
            ..Default::default()
        };
        s.save(&dir).unwrap();
        assert_eq!(Settings::load(&dir), s);
        std::fs::write(
            dir.join("settings.json"),
            r#"{"theme":"System","refresh_secs":0,"watched_ports":[80,0,80,22],"future":1}"#,
        )
        .unwrap();
        let loaded = Settings::load(&dir);
        assert_eq!(loaded.theme, ThemeChoice::System);
        assert_eq!(loaded.refresh_secs, 1);
        assert_eq!(loaded.watched_ports, vec![22, 80]);
        assert!(loaded.record_history);
        // A settings file written by version 1.0 has none of the newer fields.
        assert!(loaded.port_notes.is_empty() && loaded.favourite_ports.is_empty());
        assert_eq!(loaded.serve_port, 8080);
        std::fs::write(dir.join("settings.json"), "{{{").unwrap();
        assert_eq!(Settings::load(&dir), Settings::default());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
