//! What changed between two refreshes: table diffing, row highlighting, the
//! open/close history log and watch alerts.

use crate::model::{Listener, ListenerKey, Proto, SocketSnapshot};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::path::{Path, PathBuf};

/// Keys that appeared and keys that went away.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableDiff<K> {
    pub added: Vec<K>,
    pub removed: Vec<K>,
}

impl<K> TableDiff<K> {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// Compares two tables by key. Order follows the input order; duplicates count once.
pub fn diff_keys<K: Eq + Hash + Clone>(old: &[K], new: &[K]) -> TableDiff<K> {
    let old_set: HashSet<&K> = old.iter().collect();
    let new_set: HashSet<&K> = new.iter().collect();
    let mut seen = HashSet::new();
    let added = new
        .iter()
        .filter(|k| !old_set.contains(k) && seen.insert(*k))
        .cloned()
        .collect();
    let mut seen = HashSet::new();
    let removed = old
        .iter()
        .filter(|k| !new_set.contains(k) && seen.insert(*k))
        .cloned()
        .collect();
    TableDiff { added, removed }
}

/// How a row should be drawn.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RowState {
    Steady,
    /// Appeared recently; `0.0` = just now, `1.0` = highlight about to end.
    New(f32),
    /// Gone; kept on screen while it fades. `0.0` = just closed, `1.0` = about to vanish.
    Closed(f32),
}

/// Remembers when rows appeared and keeps closed rows around for a moment so
/// that the table can highlight changes (new = green, closed = fading red).
pub struct Tracker<K, V> {
    /// Seconds a row stays highlighted / lingers after closing.
    pub highlight_secs: f64,
    first: bool,
    born: HashMap<K, f64>,
    current: Vec<(K, V)>,
    closed: Vec<(K, V, f64)>,
}

impl<K: Eq + Hash + Clone, V: Clone> Tracker<K, V> {
    pub fn new(highlight_secs: f64) -> Self {
        Tracker {
            highlight_secs,
            first: true,
            born: HashMap::new(),
            current: Vec::new(),
            closed: Vec::new(),
        }
    }

    /// Feeds a fresh table. `now` is any monotonic clock in seconds. Rows of
    /// the very first table are not highlighted. Returns what changed.
    pub fn update(&mut self, rows: Vec<(K, V)>, now: f64) -> TableDiff<K> {
        let old_keys: Vec<K> = self.current.iter().map(|(k, _)| k.clone()).collect();
        let new_keys: Vec<K> = rows.iter().map(|(k, _)| k.clone()).collect();
        let diff = diff_keys(&old_keys, &new_keys);
        if self.first {
            self.first = false;
            self.current = rows;
            return TableDiff {
                added: Vec::new(),
                removed: Vec::new(),
            };
        }
        let removed: HashSet<&K> = diff.removed.iter().collect();
        for (k, v) in &self.current {
            if removed.contains(k) {
                self.closed.push((k.clone(), v.clone(), now));
                self.born.remove(k);
            }
        }
        for k in &diff.added {
            self.born.insert(k.clone(), now);
            // A row that comes back is no longer "closed".
            self.closed.retain(|(c, _, _)| c != k);
        }
        self.current = rows;
        self.prune(now);
        diff
    }

    fn prune(&mut self, now: f64) {
        let limit = self.highlight_secs;
        self.closed.retain(|(_, _, t)| now - *t < limit);
        self.born.retain(|_, t| now - *t < limit);
    }

    /// Live rows followed by the rows that are fading out.
    pub fn rows(&self, now: f64) -> Vec<(&K, &V, RowState)> {
        let limit = self.highlight_secs.max(0.001);
        let mut out: Vec<(&K, &V, RowState)> = self
            .current
            .iter()
            .map(|(k, v)| {
                let state = match self.born.get(k) {
                    Some(t) if now - *t < limit => RowState::New(((now - *t) / limit) as f32),
                    _ => RowState::Steady,
                };
                (k, v, state)
            })
            .collect();
        for (k, v, t) in &self.closed {
            if now - *t < limit {
                out.push((k, v, RowState::Closed(((now - *t) / limit) as f32)));
            }
        }
        out
    }

    /// True while something is highlighted or fading (keep repainting).
    pub fn is_animating(&self, now: f64) -> bool {
        let limit = self.highlight_secs;
        self.closed.iter().any(|(_, _, t)| now - *t < limit)
            || self.born.values().any(|t| now - *t < limit)
    }

    pub fn len(&self) -> usize {
        self.current.len()
    }

    pub fn is_empty(&self) -> bool {
        self.current.is_empty()
    }
}

// --------------------------------------------------------------------------------------
// History log
// --------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    Opened,
    Closed,
}

/// One line of the history: a listener appeared or went away.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEvent {
    /// Unix seconds, UTC.
    pub time: i64,
    pub kind: EventKind,
    pub proto: Proto,
    pub addr: String,
    pub port: u16,
    pub pid: u32,
    pub process: String,
    /// The port is on the watch list.
    #[serde(default)]
    pub watched: bool,
}

/// Listener events between two snapshots. Process names come from whichever
/// snapshot still knows the process.
pub fn listener_events(
    old: &SocketSnapshot,
    new: &SocketSnapshot,
    watched: &[u16],
) -> Vec<HistoryEvent> {
    let old_keys: Vec<ListenerKey> = old.listeners.iter().map(Listener::key).collect();
    let new_keys: Vec<ListenerKey> = new.listeners.iter().map(Listener::key).collect();
    let diff = diff_keys(&old_keys, &new_keys);
    let event = |key: &ListenerKey, kind: EventKind, names: &SocketSnapshot| HistoryEvent {
        time: new.taken,
        kind,
        proto: key.0,
        addr: key.1.to_string(),
        port: key.2,
        pid: key.3,
        process: names.proc_name(key.3),
        watched: watched.contains(&key.2),
    };
    let mut out: Vec<HistoryEvent> = diff
        .removed
        .iter()
        .map(|k| event(k, EventKind::Closed, old))
        .collect();
    out.extend(diff.added.iter().map(|k| event(k, EventKind::Opened, new)));
    out
}

/// A notification worth showing in the tray.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alert {
    pub title: String,
    pub text: String,
    pub watched: bool,
}

/// Turns events into alerts. Watched ports always alert when taken (if
/// `alert_watched`); other new TCP listeners alert when `alert_new_listeners`.
/// Short-lived UDP sockets are too noisy and never alert unless watched.
pub fn alerts(
    events: &[HistoryEvent],
    alert_new_listeners: bool,
    alert_watched: bool,
) -> Vec<Alert> {
    let mut out = Vec::new();
    for e in events.iter().filter(|e| e.kind == EventKind::Opened) {
        if e.watched && alert_watched {
            out.push(Alert {
                title: format!("Watched port {} was taken", e.port),
                text: format!(
                    "{} (PID {}) is now listening on {} {}:{}.",
                    e.process,
                    e.pid,
                    e.proto.label(),
                    e.addr,
                    e.port
                ),
                watched: true,
            });
        } else if alert_new_listeners && e.proto == Proto::Tcp {
            out.push(Alert {
                title: format!("New listener on port {}", e.port),
                text: format!(
                    "{} (PID {}) started listening on TCP {}:{}.",
                    e.process, e.pid, e.addr, e.port
                ),
                watched: false,
            });
        }
    }
    out
}

/// The history: newest last, bounded, stored as JSON lines.
pub struct History {
    pub events: VecDeque<HistoryEvent>,
    pub capacity: usize,
    path: Option<PathBuf>,
}

impl History {
    /// An in-memory history (demo, tests).
    pub fn in_memory(capacity: usize) -> History {
        History {
            events: VecDeque::new(),
            capacity: capacity.max(1),
            path: None,
        }
    }

    /// Loads `history.jsonl` from `dir` (missing or damaged lines are skipped).
    pub fn load(dir: &Path, capacity: usize) -> History {
        let path = dir.join("history.jsonl");
        let mut events: VecDeque<HistoryEvent> = std::fs::read_to_string(&path)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        let capacity = capacity.max(1);
        while events.len() > capacity {
            events.pop_front();
        }
        History {
            events,
            capacity,
            path: Some(path),
        }
    }

    /// Adds events and appends them to the file. Rewrites the file when it
    /// has grown to twice the capacity.
    pub fn push(&mut self, new: &[HistoryEvent]) {
        if new.is_empty() {
            return;
        }
        self.events.extend(new.iter().cloned());
        let mut trimmed = false;
        while self.events.len() > self.capacity {
            self.events.pop_front();
            trimmed = true;
        }
        let Some(path) = &self.path else { return };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let lines_on_disk = std::fs::read_to_string(path)
            .map(|t| t.lines().count())
            .unwrap_or(0);
        if trimmed && lines_on_disk + new.len() > self.capacity * 2 {
            let _ = self.rewrite();
        } else {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                for e in new {
                    if let Ok(line) = serde_json::to_string(e) {
                        let _ = writeln!(f, "{line}");
                    }
                }
            }
        }
    }

    fn rewrite(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut text = String::new();
        for e in &self.events {
            if let Ok(line) = serde_json::to_string(e) {
                text.push_str(&line);
                text.push('\n');
            }
        }
        std::fs::write(path, text)
    }

    pub fn clear(&mut self) {
        self.events.clear();
        if let Some(path) = &self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProcInfo;

    #[test]
    fn key_diff() {
        let d = diff_keys(&[1, 2, 3, 3], &[2, 3, 4, 5, 5]);
        assert_eq!(d.added, vec![4, 5]);
        assert_eq!(d.removed, vec![1]);
        assert!(diff_keys(&[1, 2], &[2, 1]).is_empty());
        let d = diff_keys::<u8>(&[], &[]);
        assert!(d.is_empty());
    }

    #[test]
    fn tracker_highlights_new_rows_and_keeps_closed_ones_for_a_while() {
        let mut t: Tracker<u16, &str> = Tracker::new(4.0);
        // The first table is the baseline: nothing is "new".
        let d = t.update(vec![(80, "a"), (443, "b")], 0.0);
        assert!(d.is_empty());
        assert!(t.rows(0.0).iter().all(|r| r.2 == RowState::Steady));
        assert!(!t.is_animating(0.0));

        let d = t.update(vec![(443, "b"), (3000, "c")], 10.0);
        assert_eq!(d.added, vec![3000]);
        assert_eq!(d.removed, vec![80]);
        let rows = t.rows(11.0);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0], (&443, &"b", RowState::Steady));
        assert_eq!(rows[1], (&3000, &"c", RowState::New(0.25)));
        assert_eq!(rows[2], (&80, &"a", RowState::Closed(0.25)));
        assert!(t.is_animating(11.0));

        // After the highlight time everything is steady and the closed row is gone.
        let rows = t.rows(14.5);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.2 == RowState::Steady));
        assert!(!t.is_animating(14.5));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn tracker_row_that_returns_is_not_shown_twice() {
        let mut t: Tracker<u16, ()> = Tracker::new(5.0);
        t.update(vec![(80, ())], 0.0);
        t.update(vec![], 1.0);
        t.update(vec![(80, ())], 2.0);
        let rows = t.rows(2.5);
        assert_eq!(rows.len(), 1);
        assert!(matches!(rows[0].2, RowState::New(_)));
    }

    fn snap(taken: i64, listeners: &[(Proto, &str, u16, u32)]) -> SocketSnapshot {
        let mut s = SocketSnapshot {
            taken,
            ..Default::default()
        };
        for (proto, addr, port, pid) in listeners {
            s.listeners.push(Listener {
                proto: *proto,
                addr: addr.parse().unwrap(),
                port: *port,
                pid: *pid,
                created: None,
            });
            s.procs.insert(
                *pid,
                ProcInfo {
                    pid: *pid,
                    name: format!("app{pid}.exe"),
                    ..Default::default()
                },
            );
        }
        s
    }

    #[test]
    fn events_and_alerts() {
        let a = snap(
            100,
            &[
                (Proto::Tcp, "0.0.0.0", 80, 1),
                (Proto::Tcp, "127.0.0.1", 5432, 2),
            ],
        );
        let b = snap(
            105,
            &[
                (Proto::Tcp, "0.0.0.0", 80, 1),
                (Proto::Tcp, "127.0.0.1", 3000, 3),
                (Proto::Udp, "0.0.0.0", 5353, 4),
                (Proto::Tcp, "::", 8080, 5),
            ],
        );
        let ev = listener_events(&a, &b, &[3000]);
        assert_eq!(ev.len(), 4);
        assert_eq!(ev[0].kind, EventKind::Closed);
        assert_eq!((ev[0].port, ev[0].process.as_str()), (5432, "app2.exe"));
        assert_eq!(ev[0].time, 105);
        assert!(ev[1].watched && ev[1].port == 3000 && ev[1].kind == EventKind::Opened);
        assert!(!ev[2].watched);

        let all = alerts(&ev, true, true);
        assert_eq!(
            all.len(),
            2,
            "watched port + new TCP listener; UDP is quiet"
        );
        assert!(all[0].watched && all[0].title.contains("3000"));
        assert!(all[1].title.contains("8080"));
        assert_eq!(alerts(&ev, false, true).len(), 1);
        assert_eq!(alerts(&ev, false, false).len(), 0);
        // A changed PID on the same port is a close plus an open.
        let c = snap(110, &[(Proto::Tcp, "0.0.0.0", 80, 9)]);
        let ev = listener_events(&snap(100, &[(Proto::Tcp, "0.0.0.0", 80, 1)]), &c, &[]);
        assert_eq!(ev.len(), 2);
    }

    #[test]
    fn history_is_bounded_and_survives_a_reload() {
        let dir = std::env::temp_dir().join(format!("socketforge-history-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let e = |port: u16| HistoryEvent {
            time: port as i64,
            kind: EventKind::Opened,
            proto: Proto::Tcp,
            addr: "127.0.0.1".into(),
            port,
            pid: 1,
            process: "x.exe".into(),
            watched: false,
        };
        let mut h = History::load(&dir, 5);
        assert!(h.events.is_empty());
        h.push(&[e(1), e(2), e(3)]);
        h.push(&[e(4), e(5), e(6), e(7)]);
        assert_eq!(h.events.len(), 5);
        assert_eq!(h.events.front().unwrap().port, 3);
        std::fs::write(
            dir.join("history.jsonl"),
            format!(
                "{}\nnot json\n{}\n",
                serde_json::to_string(&e(8)).unwrap(),
                serde_json::to_string(&e(9)).unwrap()
            ),
        )
        .unwrap();
        let mut h = History::load(&dir, 5);
        assert_eq!(h.events.len(), 2);
        // Growing far past the capacity rewrites the file instead of appending forever.
        for i in 0..30 {
            h.push(&[e(100 + i)]);
        }
        let on_disk = std::fs::read_to_string(dir.join("history.jsonl")).unwrap();
        assert!(on_disk.lines().count() <= 11);
        let reloaded = History::load(&dir, 5);
        assert_eq!(reloaded.events.back().unwrap().port, 129);
        h.clear();
        assert!(!dir.join("history.jsonl").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
