//! Settings: appearance, refresh, alerts, the notification-area icon, the
//! options of the hosts editor and the port test.

use super::app::App;
use super::theme::{self, pal, semibold, Icon};
use super::widgets;
use crate::actions;
use crate::settings::ThemeChoice;
use eframe::egui::{self, RichText, Ui};

const REFRESH_CHOICES: [u32; 5] = [1, 2, 5, 10, 30];
const HISTORY_CHOICES: [usize; 4] = [1000, 5000, 20_000, 100_000];
const BACKUP_CHOICES: [usize; 4] = [10, 30, 100, 500];

/// `1000` -> `1,000`.
pub(super) fn thousands(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A segmented control over a fixed list of values. Returns the picked value.
fn choice<T: Copy + PartialEq>(
    ui: &mut Ui,
    values: &[T],
    current: T,
    label: impl Fn(T) -> String,
) -> Option<T> {
    let labels: Vec<String> = values.iter().map(|v| label(*v)).collect();
    let refs: Vec<&str> = labels.iter().map(|s| s.as_str()).collect();
    // A hand-edited value that is not offered leaves every option unselected.
    let index = values
        .iter()
        .position(|v| *v == current)
        .unwrap_or(usize::MAX);
    widgets::segmented(ui, &refs, index).map(|i| values[i])
}

fn card_title(ui: &mut Ui, icon: Icon, title: &str) {
    let p = pal(ui);
    ui.horizontal(|ui| {
        ui.label(RichText::new(icon.glyph()).size(15.0).color(p.accent));
        ui.label(RichText::new(title).font(semibold(15.5)));
    });
    ui.add_space(2.0);
}

impl App {
    pub(super) fn settings_ui(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        let mut open_about = false;
        widgets::page_header(
            ui,
            "Settings",
            "Saved automatically in the data folder.",
            |ui| {
                if widgets::ghost_button(ui, &Icon::INFO.with("About SocketForge")).clicked() {
                    open_about = true;
                }
            },
        );
        if open_about {
            self.about_open = true;
        }
        let before = self.sh.settings.clone();
        let demo = self.sh.demo;
        let mut open_folder = false;

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_width(ui.available_width().min(900.0));
                let s = &mut self.sh.settings;

                widgets::card(ui, |ui| {
                    card_title(ui, Icon::EYE, "Appearance");
                    widgets::setting_row(
                        ui,
                        "Theme",
                        "Dark, light, or whatever Windows is set to.",
                        |ui| {
                            let choices =
                                [ThemeChoice::Dark, ThemeChoice::Light, ThemeChoice::System];
                            if let Some(t) = choice(ui, &choices, s.theme, |t| {
                                match t {
                                    ThemeChoice::Dark => "Dark",
                                    ThemeChoice::Light => "Light",
                                    ThemeChoice::System => "System",
                                }
                                .to_string()
                            }) {
                                s.theme = t;
                            }
                        },
                    );
                });

                widgets::card(ui, |ui| {
                    card_title(ui, Icon::REFRESH, "Refresh");
                    widgets::setting_row(
                        ui,
                        "Refresh automatically",
                        "Keeps the port and connection tables up to date. Press F5 at any \
                         time to refresh by hand.",
                        |ui| {
                            if widgets::toggle(ui, s.live, true).clicked() {
                                s.live = !s.live;
                            }
                        },
                    );
                    widgets::setting_row(
                        ui,
                        "Every",
                        "How often the tables are read again, in seconds.",
                        |ui| {
                            if let Some(n) =
                                choice(ui, &REFRESH_CHOICES, s.refresh_secs, |n| format!("{n} s"))
                            {
                                s.refresh_secs = n;
                            }
                        },
                    );
                });

                widgets::card(ui, |ui| {
                    card_title(ui, Icon::SWITCH, "Connections");
                    widgets::setting_row(
                        ui,
                        "Look up host names",
                        "Shows names next to remote addresses. This sends a reverse DNS query \
                         for each address to your DNS server, so it is off unless you turn it on.",
                        |ui| {
                            if widgets::toggle(ui, s.reverse_dns, true).clicked() {
                                s.reverse_dns = !s.reverse_dns;
                            }
                        },
                    );
                });

                widgets::card(ui, |ui| {
                    card_title(ui, Icon::BELL, "Watch & alerts");
                    widgets::setting_row(
                        ui,
                        "Alert when a watched port is taken",
                        "The watch list is on the Watch & history page.",
                        |ui| {
                            if widgets::toggle(ui, s.alert_watched, true).clicked() {
                                s.alert_watched = !s.alert_watched;
                            }
                        },
                    );
                    widgets::setting_row(
                        ui,
                        "Alert on any new TCP listener",
                        "Every program that starts listening on a TCP port. Can be noisy.",
                        |ui| {
                            if widgets::toggle(ui, s.alert_new_listeners, true).clicked() {
                                s.alert_new_listeners = !s.alert_new_listeners;
                            }
                        },
                    );
                    widgets::setting_row(
                        ui,
                        "Record the history",
                        "Notes every listener that opens or closes while SocketForge runs.",
                        |ui| {
                            if widgets::toggle(ui, s.record_history, true).clicked() {
                                s.record_history = !s.record_history;
                            }
                        },
                    );
                    widgets::setting_row(
                        ui,
                        "Events to keep",
                        "Older events are dropped when the log is full.",
                        |ui| {
                            if let Some(n) =
                                choice(ui, &HISTORY_CHOICES, s.history_limit, thousands)
                            {
                                s.history_limit = n;
                            }
                        },
                    );
                });

                widgets::card(ui, |ui| {
                    card_title(ui, Icon::PIN, "Notification area");
                    widgets::setting_row(
                        ui,
                        "Show an icon in the notification area",
                        "Alerts then also appear as Windows notifications. SocketForge never \
                         adds itself to startup.",
                        |ui| {
                            if widgets::toggle(ui, s.tray_icon, true).clicked() {
                                s.tray_icon = !s.tray_icon;
                            }
                        },
                    );
                    widgets::setting_row(
                        ui,
                        "Keep running when the window is closed",
                        "Closing the window hides it; the icon's menu has Show and Exit. \
                         Needs the icon.",
                        |ui| {
                            let on = s.close_to_tray && s.tray_icon;
                            if widgets::toggle(ui, on, s.tray_icon).clicked() {
                                s.close_to_tray = !on;
                            }
                        },
                    );
                });

                widgets::card(ui, |ui| {
                    card_title(ui, Icon::DOCUMENT, "Hosts file");
                    widgets::setting_row(
                        ui,
                        "Flush the DNS cache after saving",
                        "Makes changed entries take effect at once.",
                        |ui| {
                            if widgets::toggle(ui, s.flush_dns_after_save, true).clicked() {
                                s.flush_dns_after_save = !s.flush_dns_after_save;
                            }
                        },
                    );
                    widgets::setting_row(
                        ui,
                        "Backups to keep",
                        "A backup is made before every save; the oldest are removed.",
                        |ui| {
                            if let Some(n) =
                                choice(ui, &BACKUP_CHOICES, s.hosts_backups_kept, |n| n.to_string())
                            {
                                s.hosts_backups_kept = n;
                            }
                        },
                    );
                });

                widgets::card(ui, |ui| {
                    card_title(ui, Icon::PLAY, "Test port");
                    widgets::setting_row(
                        ui,
                        "Allow testing addresses of other devices",
                        "\"Test port\" normally connects only to this PC. Turn this on to let \
                         it connect to an address a socket is bound to even when Windows does \
                         not list it as local.",
                        |ui| {
                            if widgets::toggle(ui, s.probe_non_local, true).clicked() {
                                s.probe_non_local = !s.probe_non_local;
                            }
                        },
                    );
                });

                widgets::card(ui, |ui| {
                    card_title(ui, Icon::FOLDER, "Data folder");
                    widgets::setting_row(
                        ui,
                        &self.sh.app_dir.to_string_lossy(),
                        "Settings, the history log and hosts-file backups live here.",
                        |ui| {
                            if widgets::ghost_button(ui, &Icon::FOLDER_OPEN.with("Open folder"))
                                .clicked()
                            {
                                open_folder = true;
                            }
                        },
                    );
                });
                ui.add_space(4.0);
                ui.label(
                    RichText::new(if demo {
                        "Demo: changes here are not saved."
                    } else {
                        "SocketForge only reads. The actions that change something (ending a \
                         process, stopping a service, saving the hosts file) always ask first."
                    })
                    .size(12.5)
                    .color(p.faint),
                );
                ui.add_space(10.0);
            });

        if self.sh.settings != before {
            if self.sh.settings.theme != before.theme {
                theme::apply_choice(ui.ctx(), self.sh.settings.theme);
            }
            self.sh.touch_settings();
        }
        if open_folder && !self.demo_blocked() {
            let dir = self.sh.app_dir.clone();
            let _ = std::fs::create_dir_all(&dir);
            if let Err(e) = actions::open_url(&dir.to_string_lossy()) {
                self.sh.toast(e, true);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Settings;

    #[test]
    fn thousands_separator() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(20_000), "20,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn defaults_are_among_the_choices() {
        let s = Settings::default();
        assert!(REFRESH_CHOICES.contains(&s.refresh_secs));
        assert!(HISTORY_CHOICES.contains(&s.history_limit));
        assert!(BACKUP_CHOICES.contains(&s.hosts_backups_kept));
        // Every offered value survives `sanitize`.
        for n in REFRESH_CHOICES {
            let mut t = Settings {
                refresh_secs: n,
                ..Default::default()
            };
            t.sanitize();
            assert_eq!(t.refresh_secs, n);
        }
        for n in HISTORY_CHOICES {
            let mut t = Settings {
                history_limit: n,
                ..Default::default()
            };
            t.sanitize();
            assert_eq!(t.history_limit, n);
        }
        for n in BACKUP_CHOICES {
            let mut t = Settings {
                hosts_backups_kept: n,
                ..Default::default()
            };
            t.sanitize();
            assert_eq!(t.hosts_backups_kept, n);
        }
    }
}
