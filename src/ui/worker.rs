//! Background threads: the periodic socket refresh, the slow system
//! collection, reverse-DNS lookups, port tests and other blocking actions.
//!
//! The refresh threads keep going while the window is hidden in the
//! notification area, so results are left in a shared "inbox" (latest snapshot
//! wins, events accumulate up to a bound) rather than queued without limit.

use crate::actions::{self, ProbeResult};
use crate::collect::{self, ProcCache};
use crate::diff::{self, Alert, HistoryEvent};
use crate::model::{SocketSnapshot, SystemInfo};
use crate::tray::Tray;
use eframe::egui;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Seconds between two system collections (firewall, ranges, forwards...).
const SYSTEM_EVERY_SECS: u64 = 60;
/// Most history events kept in the inbox while nobody picks them up.
const MAX_PENDING_EVENTS: usize = 20_000;
/// Most notifications for one refresh; the rest is summarised.
const MAX_ALERTS_PER_REFRESH: usize = 3;

/// The settings the refresh thread needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerConfig {
    pub live: bool,
    pub refresh_secs: u32,
    pub watched: Vec<u16>,
    pub alert_new_listeners: bool,
    pub alert_watched: bool,
}

impl WorkerConfig {
    pub fn from_settings(s: &crate::settings::Settings) -> WorkerConfig {
        WorkerConfig {
            live: s.live,
            refresh_secs: s.refresh_secs,
            watched: s.watched_ports.clone(),
            alert_new_listeners: s.alert_new_listeners,
            alert_watched: s.alert_watched,
        }
    }

    /// How long the refresh thread sleeps before the next automatic refresh.
    pub fn wait(&self) -> Duration {
        if self.live {
            Duration::from_secs(self.refresh_secs.clamp(1, 60) as u64)
        } else {
            // Paused: only an explicit refresh wakes the thread.
            Duration::from_secs(3600)
        }
    }
}

/// What the threads have produced since the window last looked.
#[derive(Default)]
pub struct Inbox {
    pub snapshot: Option<SocketSnapshot>,
    pub events: Vec<HistoryEvent>,
    pub alerts: Vec<Alert>,
    pub system: Option<SystemInfo>,
}

struct State {
    config: WorkerConfig,
    inbox: Inbox,
    tray: Option<Tray>,
    system_busy: bool,
}

enum Cmd {
    Refresh,
    /// The configuration changed: start waiting afresh.
    Reconfigure,
    Stop,
}

/// Events and alerts between two snapshots. The first snapshot has nothing
/// to compare with and produces neither.
pub fn changes(
    prev: Option<&SocketSnapshot>,
    new: &SocketSnapshot,
    config: &WorkerConfig,
) -> (Vec<HistoryEvent>, Vec<Alert>) {
    let Some(prev) = prev else {
        return (Vec::new(), Vec::new());
    };
    let events = diff::listener_events(prev, new, &config.watched);
    let mut alerts = diff::alerts(&events, config.alert_new_listeners, config.alert_watched);
    // Watched ports first; a burst of new listeners must not bury the screen.
    alerts.sort_by_key(|a| !a.watched);
    if alerts.len() > MAX_ALERTS_PER_REFRESH {
        let rest = alerts.len() - (MAX_ALERTS_PER_REFRESH - 1);
        let watched = alerts[MAX_ALERTS_PER_REFRESH - 1..]
            .iter()
            .any(|a| a.watched);
        alerts.truncate(MAX_ALERTS_PER_REFRESH - 1);
        alerts.push(Alert {
            title: format!("{rest} more new listeners"),
            text: "Open Watch & history to see them all.".to_string(),
            watched,
        });
    }
    (events, alerts)
}

/// Owns the two refresh threads.
pub struct Worker {
    state: Arc<Mutex<State>>,
    sockets_tx: Sender<Cmd>,
    system_tx: Sender<Cmd>,
}

impl Worker {
    pub fn start(ctx: &egui::Context, config: WorkerConfig) -> Worker {
        let state = Arc::new(Mutex::new(State {
            config,
            inbox: Inbox::default(),
            tray: None,
            system_busy: true,
        }));
        let (sockets_tx, sockets_rx) = channel::<Cmd>();
        let (system_tx, system_rx) = channel::<Cmd>();

        let (st, cx) = (state.clone(), ctx.clone());
        let _ = std::thread::Builder::new()
            .name("socketforge-sockets".into())
            .spawn(move || {
                let mut cache = ProcCache::default();
                let mut prev: Option<SocketSnapshot> = None;
                loop {
                    let snap = collect::sockets(&mut cache);
                    let wait = {
                        let Ok(mut s) = st.lock() else { break };
                        let (events, alerts) = changes(prev.as_ref(), &snap, &s.config);
                        if let Some(tray) = &s.tray {
                            for a in &alerts {
                                tray.notify(&a.title, &a.text, a.watched);
                            }
                        }
                        s.inbox.events.extend(events);
                        if s.inbox.events.len() > MAX_PENDING_EVENTS {
                            let extra = s.inbox.events.len() - MAX_PENDING_EVENTS;
                            s.inbox.events.drain(..extra);
                        }
                        s.inbox.alerts.extend(alerts);
                        if s.inbox.alerts.len() > 32 {
                            let extra = s.inbox.alerts.len() - 32;
                            s.inbox.alerts.drain(..extra);
                        }
                        s.inbox.snapshot = Some(snap.clone());
                        s.config.wait()
                    };
                    prev = Some(snap);
                    cx.request_repaint();
                    // Wait for the next tick or an explicit command.
                    let mut wait = wait;
                    loop {
                        match sockets_rx.recv_timeout(wait) {
                            Ok(Cmd::Refresh) => break,
                            Ok(Cmd::Reconfigure) => {
                                wait = st.lock().map(|s| s.config.wait()).unwrap_or(wait);
                            }
                            Ok(Cmd::Stop) | Err(RecvTimeoutError::Disconnected) => return,
                            Err(RecvTimeoutError::Timeout) => {
                                let live = st.lock().map(|s| s.config.live).unwrap_or(false);
                                if live {
                                    break;
                                }
                            }
                        }
                    }
                }
            });

        let (st, cx) = (state.clone(), ctx.clone());
        let _ = std::thread::Builder::new()
            .name("socketforge-system".into())
            .spawn(move || loop {
                if let Ok(mut s) = st.lock() {
                    s.system_busy = true;
                }
                let sys = collect::system();
                if let Ok(mut s) = st.lock() {
                    s.inbox.system = Some(sys);
                    s.system_busy = false;
                }
                cx.request_repaint();
                match system_rx.recv_timeout(Duration::from_secs(SYSTEM_EVERY_SECS)) {
                    Ok(Cmd::Refresh) | Ok(Cmd::Reconfigure) | Err(RecvTimeoutError::Timeout) => {}
                    Ok(Cmd::Stop) | Err(RecvTimeoutError::Disconnected) => return,
                }
            });

        Worker {
            state,
            sockets_tx,
            system_tx,
        }
    }

    /// Takes everything that arrived since the last call.
    pub fn take(&self) -> Inbox {
        self.state
            .lock()
            .map(|mut s| std::mem::take(&mut s.inbox))
            .unwrap_or_default()
    }

    pub fn refresh_sockets(&self) {
        let _ = self.sockets_tx.send(Cmd::Refresh);
    }

    pub fn refresh_system(&self) {
        let _ = self.system_tx.send(Cmd::Refresh);
    }

    pub fn system_busy(&self) -> bool {
        self.state.lock().map(|s| s.system_busy).unwrap_or(false)
    }

    /// Passes changed settings on. Does nothing when they are the same.
    pub fn set_config(&self, config: WorkerConfig) {
        let changed = self
            .state
            .lock()
            .map(|mut s| {
                if s.config == config {
                    false
                } else {
                    s.config = config;
                    true
                }
            })
            .unwrap_or(false);
        if changed {
            let _ = self.sockets_tx.send(Cmd::Reconfigure);
        }
    }

    /// The tray icon that shows alert notifications (None = no notifications).
    pub fn set_tray(&self, tray: Option<Tray>) {
        if let Ok(mut s) = self.state.lock() {
            s.tray = tray;
        }
    }

    pub fn stop(&self) {
        let _ = self.sockets_tx.send(Cmd::Stop);
        let _ = self.system_tx.send(Cmd::Stop);
    }
}

/// Results of background actions, shown as toasts: `(text, is_error)`.
pub type Notices = Arc<Mutex<Vec<(String, bool)>>>;

/// Runs a blocking action (ending a process, stopping a service) off the
/// user-interface thread and reports the outcome as a toast.
pub fn spawn_action(
    ctx: &egui::Context,
    notices: &Notices,
    action: impl FnOnce() -> Result<String, String> + Send + 'static,
) {
    let (ctx, notices) = (ctx.clone(), notices.clone());
    let _ = std::thread::Builder::new()
        .name("socketforge-action".into())
        .spawn(move || {
            let outcome = match action() {
                Ok(text) => (text, false),
                Err(text) => (text, true),
            };
            if let Ok(mut n) = notices.lock() {
                n.push(outcome);
            }
            ctx.request_repaint();
        });
}

/// A port test in progress; `None` until the result is in.
pub type ProbeSlot = Arc<Mutex<Option<ProbeResult>>>;

pub fn spawn_probe(ctx: &egui::Context, addr: SocketAddr, allow_non_local: bool) -> ProbeSlot {
    let slot: ProbeSlot = Arc::new(Mutex::new(None));
    let (ctx, out) = (ctx.clone(), slot.clone());
    let _ = std::thread::Builder::new()
        .name("socketforge-probe".into())
        .spawn(move || {
            let result = actions::probe_port(addr, Duration::from_secs(3), allow_non_local);
            if let Ok(mut o) = out.lock() {
                *o = Some(result);
            }
            ctx.request_repaint();
        });
    slot
}

/// Reverse-DNS lookups, one at a time on their own thread.
pub struct Resolver {
    tx: Sender<IpAddr>,
    done: Arc<Mutex<Vec<(IpAddr, Option<String>)>>>,
}

impl Resolver {
    pub fn start(ctx: &egui::Context) -> Resolver {
        let (tx, rx) = channel::<IpAddr>();
        let done: Arc<Mutex<Vec<(IpAddr, Option<String>)>>> = Arc::new(Mutex::new(Vec::new()));
        let (ctx, out) = (ctx.clone(), done.clone());
        let _ = std::thread::Builder::new()
            .name("socketforge-dns".into())
            .spawn(move || {
                for ip in rx {
                    let name = actions::reverse_dns(&ip);
                    if let Ok(mut o) = out.lock() {
                        o.push((ip, name));
                    }
                    ctx.request_repaint();
                }
            });
        Resolver { tx, done }
    }

    pub fn request(&self, ip: IpAddr) {
        let _ = self.tx.send(ip);
    }

    pub fn take(&self) -> Vec<(IpAddr, Option<String>)> {
        self.done
            .lock()
            .map(|mut d| std::mem::take(&mut *d))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Listener, ProcInfo, Proto};

    fn config() -> WorkerConfig {
        WorkerConfig {
            live: true,
            refresh_secs: 2,
            watched: vec![3000],
            alert_new_listeners: true,
            alert_watched: true,
        }
    }

    fn snap(ports: &[u16]) -> SocketSnapshot {
        let mut s = SocketSnapshot::default();
        for &port in ports {
            s.listeners.push(Listener {
                proto: Proto::Tcp,
                addr: "127.0.0.1".parse().unwrap(),
                port,
                pid: 10,
                created: None,
            });
        }
        s.procs.insert(
            10,
            ProcInfo {
                pid: 10,
                name: "app.exe".into(),
                ..Default::default()
            },
        );
        s
    }

    #[test]
    fn wait_follows_the_settings() {
        let mut c = config();
        assert_eq!(c.wait(), Duration::from_secs(2));
        c.refresh_secs = 0;
        assert_eq!(c.wait(), Duration::from_secs(1));
        c.refresh_secs = 500;
        assert_eq!(c.wait(), Duration::from_secs(60));
        c.live = false;
        assert!(c.wait() >= Duration::from_secs(600));
    }

    #[test]
    fn first_snapshot_is_silent() {
        let (events, alerts) = changes(None, &snap(&[3000, 8080]), &config());
        assert!(events.is_empty() && alerts.is_empty());
    }

    #[test]
    fn changes_become_events_and_alerts() {
        let (events, alerts) = changes(Some(&snap(&[8080])), &snap(&[3000, 9000]), &config());
        assert_eq!(events.len(), 3);
        assert_eq!(alerts.len(), 2);
        assert!(alerts[0].watched, "watched ports come first");
        let mut quiet = config();
        quiet.alert_new_listeners = false;
        quiet.alert_watched = false;
        let (events, alerts) = changes(Some(&snap(&[8080])), &snap(&[3000]), &quiet);
        assert_eq!(events.len(), 2);
        assert!(alerts.is_empty());
    }

    #[test]
    fn bursts_are_summarised() {
        let many: Vec<u16> = (4000..4010).collect();
        let (events, alerts) = changes(Some(&snap(&[])), &snap(&many), &config());
        assert_eq!(events.len(), 10);
        assert_eq!(alerts.len(), MAX_ALERTS_PER_REFRESH);
        assert!(alerts.last().unwrap().title.starts_with("8 more"));
    }
}
