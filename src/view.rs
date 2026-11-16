//! Rows as the views, the exports and the command line show them: collector
//! data joined with process details, well-known names and exposure.

use crate::exposure::{self, ExposureInfo};
use crate::model::{Connection, Listener, ProcInfo, Proto, SocketSnapshot, SystemInfo};
use crate::ports;

/// One listening socket with everything known about it.
#[derive(Clone, Debug)]
pub struct ListenerRow {
    pub listener: Listener,
    /// Process details; a stub with only the PID when the process is unknown.
    pub proc: ProcInfo,
    /// What usually lives on this port ("PostgreSQL"), if anything.
    pub well_known: Option<&'static str>,
    pub exposure: ExposureInfo,
}

impl ListenerRow {
    /// `Dnscache, Dhcp` for service hosts; empty otherwise.
    pub fn services_label(&self) -> String {
        self.proc
            .services
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `All interfaces` / `Loopback` / the address itself.
    pub fn scope_label(&self) -> String {
        match self.listener.scope() {
            crate::model::Scope::AllInterfaces => {
                if self.listener.is_v6() {
                    "All interfaces (IPv6)".into()
                } else {
                    "All interfaces".into()
                }
            }
            crate::model::Scope::Loopback => "Loopback only".into(),
            crate::model::Scope::Specific => self.listener.addr.to_string(),
        }
    }

    /// `localhost:3000`, or the bound address when it is a specific one.
    pub fn host_port(&self) -> String {
        match self.listener.scope() {
            crate::model::Scope::Specific => self.listener.endpoint(),
            _ => format!("localhost:{}", self.listener.port),
        }
    }

    pub fn url(&self) -> String {
        format!(
            "{}://{}",
            ports::url_scheme(self.listener.port),
            self.host_port()
        )
    }

    pub fn curl_line(&self) -> String {
        format!("curl -i {}/", self.url())
    }

    /// One line of plain text for the clipboard.
    pub fn as_text(&self) -> String {
        let mut s = format!(
            "{} {}  {} (PID {})",
            self.listener.proto.label(),
            self.listener.endpoint(),
            self.proc.display_name(),
            self.listener.pid
        );
        let services = self.services_label();
        if !services.is_empty() {
            s.push_str(&format!("  services: {services}"));
        }
        if !self.proc.path.is_empty() {
            s.push_str(&format!("  {}", self.proc.path));
        }
        s.push_str(&format!("  [{}]", self.exposure.badge()));
        s
    }
}

/// Joins listeners with processes and the firewall. Sorted by port, protocol, address.
pub fn listener_rows(snap: &SocketSnapshot, sys: &SystemInfo) -> Vec<ListenerRow> {
    let mut rows: Vec<ListenerRow> = snap
        .listeners
        .iter()
        .map(|l| {
            let proc = snap.procs.get(&l.pid);
            ListenerRow {
                listener: l.clone(),
                proc: proc.cloned().unwrap_or_else(|| ProcInfo {
                    pid: l.pid,
                    limited: true,
                    ..Default::default()
                }),
                well_known: ports::service_name(l.port, l.proto),
                exposure: exposure::classify(l, proc, &sys.firewall),
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        (
            a.listener.port,
            a.listener.proto,
            a.listener.addr,
            a.listener.pid,
        )
            .cmp(&(
                b.listener.port,
                b.listener.proto,
                b.listener.addr,
                b.listener.pid,
            ))
    });
    rows
}

/// The filters of the Listening view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenerFilter {
    pub tcp: bool,
    pub udp: bool,
    pub v4: bool,
    pub v6: bool,
    /// Show Windows' own processes.
    pub system: bool,
    /// Show everything else.
    pub user: bool,
    /// Only listeners other devices could reach.
    pub exposed_only: bool,
    pub search: String,
}

impl Default for ListenerFilter {
    fn default() -> Self {
        ListenerFilter {
            tcp: true,
            udp: true,
            v4: true,
            v6: true,
            system: true,
            user: true,
            exposed_only: false,
            search: String::new(),
        }
    }
}

/// Free-text search: every word must match something. A bare number matches
/// the port exactly (or the PID); `:30` style prefixes are not needed.
pub fn search_matches(row: &ListenerRow, search: &str) -> bool {
    let needle = search.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    needle.split_whitespace().all(|word| {
        if let Ok(n) = word.trim_start_matches(':').parse::<u32>() {
            if row.listener.port as u32 == n || row.listener.pid == n {
                return true;
            }
            // Fall through: "127" should still find 127.0.0.1.
        }
        let hay = [
            row.proc.name.to_lowercase(),
            row.proc.path.to_lowercase(),
            row.proc.cmdline.to_lowercase(),
            row.proc.description.to_lowercase(),
            row.proc.user.to_lowercase(),
            row.services_label().to_lowercase(),
            row.proc
                .services
                .iter()
                .map(|s| s.display.to_lowercase())
                .collect::<Vec<_>>()
                .join(" "),
            row.well_known.unwrap_or("").to_lowercase(),
            ports::short_name(row.listener.port, row.listener.proto)
                .unwrap_or("")
                .to_string(),
            row.listener.addr.to_string(),
            row.listener.proto.label().to_lowercase(),
            row.exposure.badge().to_lowercase(),
        ];
        // A number only matches addresses and text, never "contains" in the port.
        hay.iter().any(|h| h.contains(word))
    })
}

pub fn filter_matches(row: &ListenerRow, f: &ListenerFilter) -> bool {
    let l = &row.listener;
    let proto_ok = match l.proto {
        Proto::Tcp => f.tcp,
        Proto::Udp => f.udp,
    };
    let family_ok = if l.is_v6() { f.v6 } else { f.v4 };
    let kind_ok = if row.proc.is_system { f.system } else { f.user };
    proto_ok
        && family_ok
        && kind_ok
        && (!f.exposed_only || row.exposure.is_exposed())
        && search_matches(row, &f.search)
}

/// Groups row indices by process, ordered by process name then PID.
pub fn group_by_process(rows: &[ListenerRow]) -> Vec<(u32, Vec<usize>)> {
    let mut groups: Vec<(u32, Vec<usize>)> = Vec::new();
    for (i, r) in rows.iter().enumerate() {
        match groups.iter_mut().find(|(pid, _)| *pid == r.listener.pid) {
            Some((_, v)) => v.push(i),
            None => groups.push((r.listener.pid, vec![i])),
        }
    }
    groups.sort_by_key(|(pid, v)| (rows[v[0]].proc.display_name().to_lowercase(), *pid));
    groups
}

/// Groups row indices by `(port, protocol)`, ascending.
pub fn group_by_port(rows: &[ListenerRow]) -> Vec<((u16, Proto), Vec<usize>)> {
    let mut groups: Vec<((u16, Proto), Vec<usize>)> = Vec::new();
    for (i, r) in rows.iter().enumerate() {
        let key = (r.listener.port, r.listener.proto);
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(i),
            None => groups.push((key, vec![i])),
        }
    }
    groups.sort_by_key(|(k, _)| *k);
    groups
}

/// Everything else this process is serving: shown before ending it.
pub fn other_ports_of(rows: &[ListenerRow], pid: u32) -> Vec<String> {
    let mut out: Vec<String> = rows
        .iter()
        .filter(|r| r.listener.pid == pid)
        .map(|r| format!("{} {}", r.listener.proto.label(), r.listener.endpoint()))
        .collect();
    out.dedup();
    out
}

/// One active connection with its process.
#[derive(Clone, Debug)]
pub struct ConnectionRow {
    pub conn: Connection,
    pub proc_name: String,
    pub proc_path: String,
    pub is_system: bool,
    /// Name of the service usually found on the remote (or local) port.
    pub well_known: Option<&'static str>,
}

pub fn connection_rows(snap: &SocketSnapshot) -> Vec<ConnectionRow> {
    let listening: std::collections::HashSet<u16> = snap
        .listeners
        .iter()
        .filter(|l| l.proto == Proto::Tcp)
        .map(|l| l.port)
        .collect();
    snap.connections
        .iter()
        .map(|c| {
            let proc = snap.procs.get(&c.pid);
            // An inbound connection lands on a port we listen on: name that one.
            let well_known = if listening.contains(&c.local.port()) {
                ports::service_name(c.local.port(), Proto::Tcp)
            } else {
                ports::service_name(c.remote.port(), Proto::Tcp)
            };
            ConnectionRow {
                conn: c.clone(),
                proc_name: snap.proc_name(c.pid),
                proc_path: proc.map(|p| p.path.clone()).unwrap_or_default(),
                is_system: proc.map(|p| p.is_system).unwrap_or(false),
                well_known,
            }
        })
        .collect()
}

/// Search over a connection; `host` is the reverse-DNS name when known.
pub fn connection_matches(row: &ConnectionRow, host: Option<&str>, search: &str) -> bool {
    let needle = search.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    needle.split_whitespace().all(|word| {
        if let Ok(n) = word.trim_start_matches(':').parse::<u32>() {
            if row.conn.local.port() as u32 == n
                || row.conn.remote.port() as u32 == n
                || row.conn.pid == n
            {
                return true;
            }
        }
        row.proc_name.to_lowercase().contains(word)
            || row.conn.local.ip().to_string().contains(word)
            || row.conn.remote.ip().to_string().contains(word)
            || row.conn.state.label().to_lowercase().contains(word)
            || row.well_known.unwrap_or("").to_lowercase().contains(word)
            || host
                .map(|h| h.to_lowercase().contains(word))
                .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ServiceRef, TcpState};

    fn snap() -> SocketSnapshot {
        let mut s = SocketSnapshot::default();
        let mut add = |proto, addr: &str, port, pid, name: &str, system: bool| {
            s.listeners.push(Listener {
                proto,
                addr: addr.parse().unwrap(),
                port,
                pid,
                created: None,
            });
            s.procs.entry(pid).or_insert_with(|| ProcInfo {
                pid,
                name: name.into(),
                path: format!("C:\\apps\\{name}"),
                is_system: system,
                ..Default::default()
            });
        };
        add(Proto::Tcp, "0.0.0.0", 3000, 10, "node.exe", false);
        add(Proto::Tcp, "::", 3000, 10, "node.exe", false);
        add(Proto::Tcp, "127.0.0.1", 5432, 20, "postgres.exe", false);
        add(Proto::Udp, "0.0.0.0", 5353, 30, "svchost.exe", true);
        add(Proto::Tcp, "0.0.0.0", 135, 40, "svchost.exe", true);
        s.procs.get_mut(&30).unwrap().services = vec![ServiceRef {
            name: "Dnscache".into(),
            display: "DNS Client".into(),
        }];
        s.connections.push(Connection {
            local: "192.168.1.5:50123".parse().unwrap(),
            remote: "93.184.216.34:443".parse().unwrap(),
            state: TcpState::Established,
            pid: 10,
            created: None,
        });
        s.connections.push(Connection {
            local: "127.0.0.1:5432".parse().unwrap(),
            remote: "127.0.0.1:50999".parse().unwrap(),
            state: TcpState::Established,
            pid: 20,
            created: None,
        });
        s
    }

    #[test]
    fn rows_are_sorted_and_joined() {
        let rows = listener_rows(&snap(), &SystemInfo::default());
        let ports: Vec<u16> = rows.iter().map(|r| r.listener.port).collect();
        assert_eq!(ports, vec![135, 3000, 3000, 5353, 5432]);
        assert_eq!(rows[4].well_known, Some("PostgreSQL"));
        assert_eq!(rows[4].host_port(), "localhost:5432");
        assert_eq!(rows[1].url(), "http://localhost:3000");
        assert_eq!(rows[1].curl_line(), "curl -i http://localhost:3000/");
        assert_eq!(rows[3].services_label(), "Dnscache");
        assert!(rows[3].as_text().contains("services: Dnscache"));
        assert_eq!(rows[4].scope_label(), "Loopback only");
    }

    #[test]
    fn search_finds_ports_names_and_services() {
        let rows = listener_rows(&snap(), &SystemInfo::default());
        let hits = |q: &str| -> Vec<u16> {
            rows.iter()
                .filter(|r| search_matches(r, q))
                .map(|r| r.listener.port)
                .collect()
        };
        assert_eq!(hits("3000"), vec![3000, 3000]);
        assert_eq!(hits("node"), vec![3000, 3000]);
        assert_eq!(hits("postgres"), vec![5432]);
        assert_eq!(hits("POSTGRESQL"), vec![5432]);
        assert_eq!(hits("dns client"), vec![5353]);
        assert_eq!(hits("udp"), vec![5353]);
        assert_eq!(hits("svchost tcp"), vec![135]);
        // A number is a port or PID, not a substring of another port.
        assert_eq!(hits("300"), Vec::<u16>::new());
        assert_eq!(hits("20"), vec![5432]);
        assert_eq!(hits("127.0.0.1"), vec![5432]);
        assert_eq!(hits(""), vec![135, 3000, 3000, 5353, 5432]);
    }

    #[test]
    fn filters() {
        let rows = listener_rows(&snap(), &SystemInfo::default());
        let count = |f: &ListenerFilter| rows.iter().filter(|r| filter_matches(r, f)).count();
        let all = ListenerFilter::default();
        assert_eq!(count(&all), 5);
        assert_eq!(
            count(&ListenerFilter {
                udp: false,
                ..all.clone()
            }),
            4
        );
        assert_eq!(
            count(&ListenerFilter {
                v4: false,
                ..all.clone()
            }),
            1
        );
        assert_eq!(
            count(&ListenerFilter {
                system: false,
                ..all.clone()
            }),
            3
        );
        assert_eq!(
            count(&ListenerFilter {
                user: false,
                ..all.clone()
            }),
            2
        );
        // No firewall data: everything bound to the network counts as exposed.
        assert_eq!(
            count(&ListenerFilter {
                exposed_only: true,
                ..all.clone()
            }),
            4
        );
    }

    #[test]
    fn grouping() {
        let rows = listener_rows(&snap(), &SystemInfo::default());
        let by_proc = group_by_process(&rows);
        assert_eq!(by_proc.len(), 4);
        assert_eq!(by_proc[0].0, 10, "node.exe sorts first");
        assert_eq!(by_proc[0].1.len(), 2);
        let by_port = group_by_port(&rows);
        assert_eq!(by_port.len(), 4);
        assert_eq!(by_port[1].0, (3000, Proto::Tcp));
        assert_eq!(by_port[1].1.len(), 2);
        assert_eq!(other_ports_of(&rows, 10).len(), 2);
    }

    #[test]
    fn connections() {
        let s = snap();
        let rows = connection_rows(&s);
        assert_eq!(rows[0].proc_name, "node.exe");
        assert_eq!(rows[0].well_known, Some("Web server (HTTPS)"));
        assert_eq!(rows[1].well_known, Some("PostgreSQL"));
        assert!(connection_matches(&rows[0], None, "443"));
        assert!(connection_matches(&rows[0], Some("example.org"), "example"));
        assert!(!connection_matches(&rows[0], None, "example"));
        assert!(connection_matches(&rows[1], None, "postgres established"));
        assert!(!connection_matches(&rows[1], None, "node"));
    }
}
