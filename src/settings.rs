//! User settings, stored as JSON in `%LOCALAPPDATA%\SocketForge\settings.json`.

use serde::{Deserialize, Serialize};
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
}

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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        std::fs::write(dir.join("settings.json"), "{{{").unwrap();
        assert_eq!(Settings::load(&dir), Settings::default());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
