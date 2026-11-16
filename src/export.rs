//! Export to CSV, JSON and HTML.
//!
//! Every kind of data is first turned into a plain [`Table`]; the three
//! formats are then written from tables, so they always agree.

use crate::diff::{EventKind, HistoryEvent};
use crate::hosts;
use crate::model::{FwRule, SystemInfo};
use crate::util::{csv_line, fmt_time, html_escape};
use crate::view::{ConnectionRow, ListenerRow};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Csv,
    Json,
    Html,
}

impl Format {
    pub fn extension(self) -> &'static str {
        match self {
            Format::Csv => "csv",
            Format::Json => "json",
            Format::Html => "html",
        }
    }

    /// Picks the format from a file name; CSV when the extension is unknown.
    pub fn from_path(path: &Path) -> Format {
        match path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .as_deref()
        {
            Some("json") => Format::Json,
            Some("html") | Some("htm") => Format::Html,
            _ => Format::Csv,
        }
    }
}

/// Everything that can go into one export file. Leave a part empty to omit it.
#[derive(Default)]
pub struct Bundle<'a> {
    pub listeners: &'a [ListenerRow],
    pub connections: &'a [ConnectionRow],
    /// Reverse-DNS names for remote addresses, when looked up.
    pub host_names: Option<&'a HashMap<IpAddr, String>>,
    pub history: &'a [HistoryEvent],
    pub system: Option<&'a SystemInfo>,
    pub hosts: &'a [hosts::Row],
}

/// A titled grid of text cells.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    pub title: &'static str,
    /// JSON key of the table in a combined export.
    pub key: &'static str,
    pub headers: Vec<&'static str>,
    pub rows: Vec<Vec<String>>,
}

/// Columns written as JSON numbers / booleans rather than strings.
const NUMERIC: &[&str] = &[
    "Port",
    "PID",
    "Local port",
    "Remote port",
    "Listen port",
    "Connect port",
    "Host port",
    "Target port",
    "Start",
    "End",
    "Count",
    "Line",
];
const BOOLEAN: &[&str] = &["Enabled", "Watched", "Administered"];

fn json_key(header: &str) -> String {
    header.to_lowercase().replace([' ', '-', '/'], "_")
}

impl Table {
    pub fn to_csv(&self) -> String {
        let mut out = csv_line(&self.headers);
        out.push_str("\r\n");
        for r in &self.rows {
            out.push_str(&csv_line(&r.iter().map(String::as_str).collect::<Vec<_>>()));
            out.push_str("\r\n");
        }
        out
    }

    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.rows
                .iter()
                .map(|r| {
                    let mut obj = serde_json::Map::new();
                    for (h, v) in self.headers.iter().zip(r) {
                        let value = if NUMERIC.contains(h) {
                            v.parse::<u64>()
                                .map(serde_json::Value::from)
                                .unwrap_or(serde_json::Value::Null)
                        } else if BOOLEAN.contains(h) {
                            serde_json::Value::Bool(v == "yes")
                        } else {
                            serde_json::Value::String(v.clone())
                        };
                        obj.insert(json_key(h), value);
                    }
                    serde_json::Value::Object(obj)
                })
                .collect(),
        )
    }

    fn to_html_section(&self) -> String {
        let mut s = format!(
            "<section>\n<h2>{} <span class=\"count\">{}</span></h2>\n",
            html_escape(self.title),
            self.rows.len()
        );
        if self.rows.is_empty() {
            s.push_str("<p class=\"empty\">Nothing to show.</p>\n</section>\n");
            return s;
        }
        s.push_str("<div class=\"wrap\"><table>\n<thead><tr>");
        for h in &self.headers {
            s.push_str(&format!("<th>{}</th>", html_escape(h)));
        }
        s.push_str("</tr></thead>\n<tbody>\n");
        for r in &self.rows {
            s.push_str("<tr>");
            for v in r {
                s.push_str(&format!("<td>{}</td>", html_escape(v)));
            }
            s.push_str("</tr>\n");
        }
        s.push_str("</tbody>\n</table></div>\n</section>\n");
        s
    }
}

const HTML_STYLE: &str = "body{font-family:'Segoe UI',system-ui,sans-serif;margin:32px;background:#f3f6f8;color:#141f29}\
h1{font-size:24px;margin:0 0 4px}p.meta{color:#566572;margin:0 0 24px}\
section{background:#fff;border:1px solid #d9e1e7;border-radius:12px;padding:18px 20px;margin:0 0 20px}\
h2{font-size:16px;margin:0 0 12px}.count{color:#2f861c;background:#e3f5d3;border-radius:10px;padding:1px 9px;font-size:12px;margin-left:6px}\
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}\
th{text-align:left;color:#566572;font-weight:600;border-bottom:1px solid #d9e1e7;padding:6px 10px;white-space:nowrap}\
td{border-bottom:1px solid #edf1f4;padding:6px 10px;vertical-align:top;word-break:break-word}\
tr:last-child td{border-bottom:none}p.empty{color:#8c99a4;margin:0}\
@media(prefers-color-scheme:dark){body{background:#0f1418;color:#e8eef2}section{background:#161d23;border-color:#26313a}\
th{color:#9aa8b3;border-color:#26313a}td{border-color:#1c252d}p.meta{color:#9aa8b3}.count{color:#8fd93a;background:#1d301c}}";

fn html_document(tables: &[Table]) -> String {
    let mut s = String::from(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>SocketForge export</title>\n<style>",
    );
    s.push_str(HTML_STYLE);
    s.push_str("</style>\n</head>\n<body>\n<h1>SocketForge export</h1>\n");
    s.push_str(&format!(
        "<p class=\"meta\">Created {}</p>\n",
        html_escape(&fmt_time(crate::model::now_unix()))
    ));
    for t in tables {
        s.push_str(&t.to_html_section());
    }
    s.push_str("</body>\n</html>\n");
    s
}

/// Writes tables in one format. A single table gives a plain CSV / a JSON
/// array; several give CSV sections (`# Title` lines) / a JSON object.
pub fn render(tables: &[Table], format: Format) -> String {
    match format {
        Format::Html => html_document(tables),
        Format::Json => {
            let value = if tables.len() == 1 {
                tables[0].to_json_value()
            } else {
                let mut obj = serde_json::Map::new();
                obj.insert(
                    "created".into(),
                    serde_json::Value::String(fmt_time(crate::model::now_unix())),
                );
                for t in tables {
                    obj.insert(t.key.to_string(), t.to_json_value());
                }
                serde_json::Value::Object(obj)
            };
            serde_json::to_string_pretty(&value).unwrap_or_default()
        }
        Format::Csv => {
            if tables.len() == 1 {
                tables[0].to_csv()
            } else {
                tables
                    .iter()
                    .map(|t| format!("# {}\r\n{}", t.title, t.to_csv()))
                    .collect::<Vec<_>>()
                    .join("\r\n")
            }
        }
    }
}

fn yes_no(b: bool) -> String {
    if b { "yes" } else { "no" }.to_string()
}

fn time_or_empty(t: Option<i64>) -> String {
    t.map(fmt_time).unwrap_or_default()
}

pub fn listeners_table(rows: &[ListenerRow]) -> Table {
    Table {
        title: "Listening ports",
        key: "listening",
        headers: vec![
            "Protocol",
            "Address",
            "Port",
            "PID",
            "Process",
            "Services",
            "Path",
            "Command line",
            "User",
            "Exposure",
            "Usually",
            "Opened",
        ],
        rows: rows
            .iter()
            .map(|r| {
                vec![
                    r.listener.proto.label().to_string(),
                    r.listener.addr.to_string(),
                    r.listener.port.to_string(),
                    r.listener.pid.to_string(),
                    r.proc.display_name(),
                    r.services_label(),
                    r.proc.path.clone(),
                    r.proc.cmdline.clone(),
                    r.proc.user.clone(),
                    r.exposure.badge(),
                    r.well_known.unwrap_or("").to_string(),
                    time_or_empty(r.listener.created),
                ]
            })
            .collect(),
    }
}

pub fn connections_table(
    rows: &[ConnectionRow],
    host_names: Option<&HashMap<IpAddr, String>>,
) -> Table {
    Table {
        title: "Connections",
        key: "connections",
        headers: vec![
            "Local address",
            "Local port",
            "Remote address",
            "Remote port",
            "Remote host",
            "State",
            "PID",
            "Process",
            "Usually",
            "Opened",
        ],
        rows: rows
            .iter()
            .map(|r| {
                vec![
                    r.conn.local.ip().to_string(),
                    r.conn.local.port().to_string(),
                    r.conn.remote.ip().to_string(),
                    r.conn.remote.port().to_string(),
                    host_names
                        .and_then(|h| h.get(&r.conn.remote.ip()))
                        .cloned()
                        .unwrap_or_default(),
                    r.conn.state.label().to_string(),
                    r.conn.pid.to_string(),
                    r.proc_name.clone(),
                    r.well_known.unwrap_or("").to_string(),
                    time_or_empty(r.conn.created),
                ]
            })
            .collect(),
    }
}

pub fn history_table(events: &[HistoryEvent]) -> Table {
    Table {
        title: "History",
        key: "history",
        headers: vec![
            "Time", "Event", "Protocol", "Address", "Port", "PID", "Process", "Watched",
        ],
        rows: events
            .iter()
            .map(|e| {
                vec![
                    fmt_time(e.time),
                    match e.kind {
                        EventKind::Opened => "opened",
                        EventKind::Closed => "closed",
                    }
                    .to_string(),
                    e.proto.label().to_string(),
                    e.addr.clone(),
                    e.port.to_string(),
                    e.pid.to_string(),
                    e.process.clone(),
                    yes_no(e.watched),
                ]
            })
            .collect(),
    }
}

pub fn firewall_table(rules: &[&FwRule]) -> Table {
    Table {
        title: "Firewall rules",
        key: "firewall_rules",
        headers: vec![
            "Name",
            "Enabled",
            "Direction",
            "Action",
            "Protocol",
            "Local ports",
            "Remote ports",
            "Program",
            "Service",
            "Profiles",
            "Local addresses",
            "Remote addresses",
            "Group",
        ],
        rows: rules
            .iter()
            .map(|r| {
                vec![
                    r.name.clone(),
                    yes_no(r.enabled),
                    if r.inbound { "in" } else { "out" }.to_string(),
                    if r.allow { "allow" } else { "block" }.to_string(),
                    r.proto.label(),
                    r.local_ports.clone(),
                    r.remote_ports.clone(),
                    r.program.clone(),
                    r.service.clone(),
                    r.profiles.label(),
                    r.local_addrs.clone(),
                    r.remote_addrs.clone(),
                    r.group.clone(),
                ]
            })
            .collect(),
    }
}

fn system_tables(sys: &SystemInfo) -> Vec<Table> {
    let opt_port = |p: Option<u16>| p.map(|p| p.to_string()).unwrap_or_default();
    vec![
        firewall_table(&sys.firewall.rules.iter().collect::<Vec<_>>()),
        Table {
            title: "Port proxies",
            key: "port_proxies",
            headers: vec![
                "Kind",
                "Listen address",
                "Listen port",
                "Connect address",
                "Connect port",
            ],
            rows: sys
                .portproxy
                .iter()
                .map(|p| {
                    vec![
                        p.kind.clone(),
                        p.listen_addr.clone(),
                        p.listen_port.to_string(),
                        p.connect_addr.clone(),
                        p.connect_port.to_string(),
                    ]
                })
                .collect(),
        },
        Table {
            title: "URL reservations (HTTP.sys)",
            key: "url_reservations",
            headers: vec!["URL", "Port", "Accounts"],
            rows: sys
                .reservations
                .iter()
                .map(|r| vec![r.url.clone(), opt_port(r.port), r.accounts.clone()])
                .collect(),
        },
        Table {
            title: "HTTP.sys listeners",
            key: "http_listeners",
            headers: vec!["URL", "Port", "Processes", "Queue"],
            rows: sys
                .http_listeners
                .iter()
                .map(|h| {
                    vec![
                        h.url.clone(),
                        opt_port(h.port),
                        h.pids
                            .iter()
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(" "),
                        h.queue.clone(),
                    ]
                })
                .collect(),
        },
        Table {
            title: "Excluded port ranges",
            key: "excluded_ranges",
            headers: vec!["Protocol", "Start", "End", "Administered", "Family"],
            rows: sys
                .excluded
                .iter()
                .map(|r| {
                    vec![
                        r.proto.label().to_string(),
                        r.start.to_string(),
                        r.end.to_string(),
                        yes_no(r.administered),
                        if r.v6 { "IPv6" } else { "IPv4" }.to_string(),
                    ]
                })
                .collect(),
        },
        Table {
            title: "Dynamic port range",
            key: "dynamic_ranges",
            headers: vec!["Protocol", "Start", "Count"],
            rows: sys
                .dynamic
                .iter()
                .map(|d| {
                    vec![
                        d.proto.label().to_string(),
                        d.start.to_string(),
                        d.count.to_string(),
                    ]
                })
                .collect(),
        },
        Table {
            title: "Forwards into containers and virtual machines",
            key: "forwards",
            headers: vec![
                "Source",
                "Protocol",
                "Host address",
                "Host port",
                "Target",
                "Target port",
                "Detail",
            ],
            rows: sys
                .forwards
                .iter()
                .map(|f| {
                    vec![
                        f.source.label().to_string(),
                        f.proto.label().to_string(),
                        f.host_addr.clone(),
                        f.host_port.to_string(),
                        f.target.clone(),
                        if f.target_port == 0 {
                            String::new()
                        } else {
                            f.target_port.to_string()
                        },
                        f.detail.clone(),
                    ]
                })
                .collect(),
        },
    ]
}

pub fn hosts_table(rows: &[hosts::Row]) -> Table {
    Table {
        title: "Hosts file",
        key: "hosts",
        headers: vec!["Line", "Enabled", "Address", "Names", "Comment", "Group"],
        rows: rows
            .iter()
            .map(|r| {
                vec![
                    (r.line + 1).to_string(),
                    yes_no(r.entry.enabled),
                    r.entry.ip.clone(),
                    r.entry.hosts.join(" "),
                    r.entry.comment.clone(),
                    r.group.clone(),
                ]
            })
            .collect(),
    }
}

pub fn listeners(rows: &[ListenerRow], format: Format) -> String {
    render(&[listeners_table(rows)], format)
}

pub fn connections(
    rows: &[ConnectionRow],
    host_names: Option<&HashMap<IpAddr, String>>,
    format: Format,
) -> String {
    render(&[connections_table(rows, host_names)], format)
}

pub fn history(events: &[HistoryEvent], format: Format) -> String {
    render(&[history_table(events)], format)
}

pub fn firewall_rules(rules: &[&FwRule], format: Format) -> String {
    render(&[firewall_table(rules)], format)
}

/// Firewall rules, port proxies, URL reservations, reserved ranges, forwards.
pub fn system(sys: &SystemInfo, format: Format) -> String {
    render(&system_tables(sys), format)
}

pub fn hosts(rows: &[hosts::Row], format: Format) -> String {
    render(&[hosts_table(rows)], format)
}

/// One file with every non-empty part of the bundle.
pub fn everything(bundle: &Bundle, format: Format) -> String {
    let mut tables = Vec::new();
    if !bundle.listeners.is_empty() {
        tables.push(listeners_table(bundle.listeners));
    }
    if !bundle.connections.is_empty() {
        tables.push(connections_table(bundle.connections, bundle.host_names));
    }
    if !bundle.history.is_empty() {
        tables.push(history_table(bundle.history));
    }
    if let Some(sys) = bundle.system {
        tables.extend(system_tables(sys));
    }
    if !bundle.hosts.is_empty() {
        tables.push(hosts_table(bundle.hosts));
    }
    // Two or more tables always get the sectioned layout, even if one is alone.
    if tables.len() == 1 && format != Format::Html {
        let only = tables.remove(0);
        return match format {
            Format::Json => {
                let mut obj = serde_json::Map::new();
                obj.insert(only.key.to_string(), only.to_json_value());
                serde_json::to_string_pretty(&serde_json::Value::Object(obj)).unwrap_or_default()
            }
            _ => format!("# {}\r\n{}", only.title, only.to_csv()),
        };
    }
    render(&tables, format)
}

/// Writes an export (CSV gets a UTF-8 byte-order mark so that spreadsheets read it right).
pub fn write(path: &Path, content: &str, format: Format) -> Result<(), String> {
    let mut bytes = Vec::new();
    if format == Format::Csv {
        bytes.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    }
    bytes.extend_from_slice(content.as_bytes());
    std::fs::write(path, bytes).map_err(|e| format!("Could not write the export: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        FirewallState, FwProto, Listener, PortProxy, PortRange, ProcInfo, Profiles, Proto,
        SocketSnapshot,
    };
    use crate::view;

    fn sample_rows() -> Vec<ListenerRow> {
        let mut snap = SocketSnapshot::default();
        snap.listeners.push(Listener {
            proto: Proto::Tcp,
            addr: "0.0.0.0".parse().unwrap(),
            port: 3000,
            pid: 10,
            created: None,
        });
        snap.procs.insert(
            10,
            ProcInfo {
                pid: 10,
                name: "node.exe".into(),
                path: "C:\\Program Files\\nodejs\\node.exe".into(),
                cmdline: "node server.js --title \"a, b\" <tag>".into(),
                ..Default::default()
            },
        );
        view::listener_rows(&snap, &SystemInfo::default())
    }

    #[test]
    fn formats_from_file_names() {
        assert_eq!(Format::from_path(Path::new("a.JSON")), Format::Json);
        assert_eq!(Format::from_path(Path::new("a.htm")), Format::Html);
        assert_eq!(Format::from_path(Path::new("a.csv")), Format::Csv);
        assert_eq!(Format::from_path(Path::new("a")), Format::Csv);
        assert_eq!(Format::Html.extension(), "html");
    }

    #[test]
    fn listeners_in_three_formats() {
        let rows = sample_rows();
        let csv = listeners(&rows, Format::Csv);
        let lines: Vec<&str> = csv.split("\r\n").collect();
        assert_eq!(lines.len(), 3, "header, one row, trailing empty");
        assert!(lines[0].starts_with("Protocol,Address,Port,PID,Process,"));
        assert!(lines[1]
            .starts_with("TCP,0.0.0.0,3000,10,node.exe,,C:\\Program Files\\nodejs\\node.exe,"));
        assert!(lines[1].contains("\"node server.js --title \"\"a, b\"\" <tag>\""));

        let json: serde_json::Value =
            serde_json::from_str(&listeners(&rows, Format::Json)).unwrap();
        assert_eq!(json[0]["port"], 3000);
        assert_eq!(json[0]["pid"], 10);
        assert_eq!(json[0]["process"], "node.exe");
        assert_eq!(
            json[0]["command_line"],
            "node server.js --title \"a, b\" <tag>"
        );

        let html = listeners(&rows, Format::Html);
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("<th>Command line</th>"));
        assert!(html.contains("&lt;tag&gt;") && !html.contains("<tag>"));
        assert!(html.contains("<h2>Listening ports <span class=\"count\">1</span></h2>"));
    }

    #[test]
    fn combined_export_has_sections() {
        let rows = sample_rows();
        let sys = SystemInfo {
            firewall: FirewallState {
                available: true,
                rules: vec![FwRule {
                    name: "Dev server".into(),
                    group: String::new(),
                    description: String::new(),
                    enabled: true,
                    inbound: true,
                    allow: true,
                    proto: FwProto::Tcp,
                    local_ports: "3000-3010".into(),
                    remote_ports: "*".into(),
                    local_addrs: "*".into(),
                    remote_addrs: "*".into(),
                    program: String::new(),
                    service: String::new(),
                    profiles: Profiles::PRIVATE,
                }],
                ..Default::default()
            },
            excluded: vec![PortRange {
                proto: Proto::Tcp,
                start: 50000,
                end: 50059,
                administered: true,
                v6: false,
            }],
            portproxy: vec![PortProxy {
                kind: "v4tov4".into(),
                listen_addr: "0.0.0.0".into(),
                listen_port: 8080,
                connect_addr: "172.20.0.2".into(),
                connect_port: 80,
            }],
            ..Default::default()
        };
        let events = vec![HistoryEvent {
            time: 1_700_000_000,
            kind: EventKind::Opened,
            proto: Proto::Tcp,
            addr: "0.0.0.0".into(),
            port: 3000,
            pid: 10,
            process: "node.exe".into(),
            watched: true,
        }];
        let doc = hosts::HostsDoc::parse("# Dev\n127.0.0.1 a.test # x\n");
        let host_rows = doc.rows();
        let bundle = Bundle {
            listeners: &rows,
            history: &events,
            system: Some(&sys),
            hosts: &host_rows,
            ..Default::default()
        };
        let json: serde_json::Value =
            serde_json::from_str(&everything(&bundle, Format::Json)).unwrap();
        assert_eq!(json["listening"][0]["port"], 3000);
        assert_eq!(json["history"][0]["watched"], true);
        assert_eq!(json["history"][0]["event"], "opened");
        assert_eq!(json["firewall_rules"][0]["profiles"], "Private");
        assert_eq!(json["firewall_rules"][0]["enabled"], true);
        assert_eq!(json["excluded_ranges"][0]["end"], 50059);
        assert_eq!(json["excluded_ranges"][0]["administered"], true);
        assert_eq!(json["port_proxies"][0]["connect_port"], 80);
        assert_eq!(json["hosts"][0]["names"], "a.test");
        assert_eq!(json["hosts"][0]["line"], 2);
        assert_eq!(json["hosts"][0]["group"], "Dev");
        assert!(
            json.get("connections").is_none(),
            "empty parts are left out"
        );

        let csv = everything(&bundle, Format::Csv);
        for title in [
            "# Listening ports",
            "# History",
            "# Firewall rules",
            "# Port proxies",
            "# Hosts file",
        ] {
            assert!(csv.contains(title), "{title}");
        }
        let html = everything(&bundle, Format::Html);
        assert!(html.matches("<section>").count() >= 8);
        assert!(html.contains("Nothing to show."));

        // A bundle with one part still names it.
        let only = Bundle {
            listeners: &rows,
            ..Default::default()
        };
        let json: serde_json::Value =
            serde_json::from_str(&everything(&only, Format::Json)).unwrap();
        assert_eq!(json["listening"][0]["pid"], 10);
    }

    #[test]
    fn csv_files_get_a_byte_order_mark() {
        let dir = std::env::temp_dir().join(format!("socketforge-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let csv = dir.join("x.csv");
        let json = dir.join("x.json");
        write(&csv, "a,b\r\n", Format::Csv).unwrap();
        write(&json, "[]", Format::Json).unwrap();
        assert_eq!(std::fs::read(&csv).unwrap(), b"\xEF\xBB\xBFa,b\r\n");
        assert_eq!(std::fs::read(&json).unwrap(), b"[]");
        assert!(write(&dir.join("no\\such\\dir\\x.csv"), "", Format::Csv).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
