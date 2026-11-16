//! The command line: parsing, and the text commands that answer without opening the window.

use crate::collect::{self, ProcCache};
use crate::export::{self, Format};
use crate::freeport::{self, PortContext, PortReport};
use crate::model::{Proto, SocketSnapshot, SystemInfo};
use crate::util::fmt_age;
use crate::view::{self, ListenerFilter, ListenerRow};
use std::path::PathBuf;

pub const USAGE: &str = "SocketForge: what is listening on this PC, and a hosts-file editor

  SocketForge.exe                       open the window
  SocketForge.exe --port 3000           who is using port 3000? (adds why a bind can fail)
        [--udp] [--json] [--gui]        --gui opens the window on that port instead
  SocketForge.exe --list                every listening port with its process
        [--tcp] [--udp] [--exposed] [--user] [--json | --csv]
  SocketForge.exe --connections         active TCP connections   [--json | --csv]
  SocketForge.exe --free-from 8000      the next free port from 8000
        [--count 3] [--block] [--udp]   3 free ports; --block = 3 in a row
  SocketForge.exe --check 3000,8000-8010 5432
                                        free or taken, for a list of ports and ranges [--udp]
  SocketForge.exe --export <file>       everything, as .json, .html or .csv
  SocketForge.exe --demo                the window with invented data; nothing is read or changed
  SocketForge.exe --screenshot <png> [--view <name>] [--light]
                                        render one view to a 1280x800 PNG and exit
  SocketForge.exe --selftest            opens listeners itself and checks that they are found
  SocketForge.exe --help | --version

Exit codes of --port and --check: 0 = free, 1 = in use or reserved, 2 = error.
From cmd.exe use `start /wait SocketForge.exe --list` (or pipe the output) so that the
prompt waits for the answer.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output {
    Text,
    Json,
    Csv,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Open the window.
    Gui {
        demo: bool,
        screenshot: Option<PathBuf>,
        view: Option<String>,
        light: bool,
        port: Option<u16>,
    },
    Port {
        port: u16,
        proto: Proto,
        output: Output,
    },
    List {
        tcp: bool,
        udp: bool,
        exposed: bool,
        user_only: bool,
        output: Output,
    },
    Connections {
        output: Output,
    },
    FreeFrom {
        from: u16,
        count: u16,
        block: bool,
        proto: Proto,
    },
    Check {
        ports: Vec<u16>,
        proto: Proto,
    },
    Export {
        path: PathBuf,
    },
    Selftest,
    SelftestChild,
    /// The elevated half of saving the hosts file (internal).
    ApplyHosts {
        source: PathBuf,
        target: PathBuf,
        clear_read_only: bool,
        flush_dns: bool,
    },
    Help,
    Version,
}

const VALUE_FLAGS: &[&str] = &[
    "--port",
    "--free-from",
    "--count",
    "--check",
    "--export",
    "--screenshot",
    "--view",
];
const PLAIN_FLAGS: &[&str] = &[
    "--demo",
    "--light",
    "--udp",
    "--tcp",
    "--json",
    "--csv",
    "--gui",
    "--exposed",
    "--user",
    "--block",
    "--list",
    "--connections",
    "--selftest",
    "--selftest-child",
    "--clear-read-only",
    "--flush-dns",
    "--help",
    "-h",
    "/?",
    "--version",
    "-V",
];

fn parse_port(s: &str, what: &str) -> Result<u16, String> {
    match s.trim().trim_start_matches(':').parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        _ => Err(format!(
            "{what} needs a port number between 1 and 65535, not \"{s}\"."
        )),
    }
}

/// Parses the arguments (without the program name).
pub fn parse(args: &[String]) -> Result<Command, String> {
    let has = |flag: &str| args.iter().any(|a| a == flag);
    let value = |flag: &str| -> Result<Option<&String>, String> {
        match args.iter().position(|a| a == flag) {
            None => Ok(None),
            Some(i) => match args.get(i + 1) {
                Some(v) if !v.starts_with("--") => Ok(Some(v)),
                _ => Err(format!("{flag} needs a value.")),
            },
        }
    };

    if has("--help") || has("-h") || has("/?") {
        return Ok(Command::Help);
    }
    if has("--version") || has("-V") {
        return Ok(Command::Version);
    }
    if let Some(i) = args.iter().position(|a| a == "--apply-hosts") {
        return match (args.get(i + 1), args.get(i + 2)) {
            (Some(s), Some(t)) if !s.starts_with("--") && !t.starts_with("--") => {
                Ok(Command::ApplyHosts {
                    source: PathBuf::from(s),
                    target: PathBuf::from(t),
                    clear_read_only: has("--clear-read-only"),
                    flush_dns: has("--flush-dns"),
                })
            }
            _ => Err("--apply-hosts needs a source and a target file.".into()),
        };
    }

    // Reject unknown flags early: a typo should not silently open the window.
    let mut skip = false;
    let mut free_values = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if skip {
            skip = false;
            continue;
        }
        if VALUE_FLAGS.contains(&a.as_str()) {
            skip = true;
            // `--check` takes every following bare value.
            if a == "--check" {
                free_values = args[i + 1..]
                    .iter()
                    .take_while(|v| !v.starts_with("--"))
                    .cloned()
                    .collect();
            }
        } else if a.starts_with('-') && !PLAIN_FLAGS.contains(&a.as_str()) {
            return Err(format!("Unknown option {a}. Try --help."));
        } else if !a.starts_with('-') && !free_values.contains(a) {
            return Err(format!("Unexpected argument \"{a}\". Try --help."));
        }
    }

    let output = match (has("--json"), has("--csv")) {
        (true, true) => return Err("Choose either --json or --csv.".into()),
        (true, false) => Output::Json,
        (false, true) => Output::Csv,
        (false, false) => Output::Text,
    };
    let proto = if has("--udp") { Proto::Udp } else { Proto::Tcp };

    if has("--selftest-child") {
        return Ok(Command::SelftestChild);
    }
    if has("--selftest") {
        return Ok(Command::Selftest);
    }
    let port = value("--port")?
        .map(|v| parse_port(v, "--port"))
        .transpose()?;
    if let (Some(port), false) = (port, has("--gui")) {
        if output == Output::Csv {
            return Err("--port prints text or --json.".into());
        }
        return Ok(Command::Port {
            port,
            proto,
            output,
        });
    }
    if has("--list") {
        let (tcp, udp) = (has("--tcp"), has("--udp"));
        return Ok(Command::List {
            tcp: tcp || !udp,
            udp: udp || !tcp,
            exposed: has("--exposed"),
            user_only: has("--user"),
            output,
        });
    }
    if has("--connections") {
        return Ok(Command::Connections { output });
    }
    if let Some(v) = value("--free-from")? {
        let count = match value("--count")? {
            Some(c) => match c.parse::<u16>() {
                Ok(n) if (1..=1000).contains(&n) => n,
                _ => return Err("--count needs a number between 1 and 1000.".into()),
            },
            None => 1,
        };
        return Ok(Command::FreeFrom {
            from: parse_port(v, "--free-from")?,
            count,
            block: has("--block"),
            proto,
        });
    }
    if has("--check") {
        if free_values.is_empty() {
            return Err("--check needs ports, for example --check 3000,8000-8010.".into());
        }
        let ports = freeport::parse_port_list(&free_values.join(" "))?;
        if ports.contains(&0) {
            return Err("Port 0 cannot be checked.".into());
        }
        return Ok(Command::Check { ports, proto });
    }
    if let Some(path) = value("--export")? {
        return Ok(Command::Export {
            path: PathBuf::from(path),
        });
    }
    Ok(Command::Gui {
        demo: has("--demo"),
        screenshot: value("--screenshot")?.map(PathBuf::from),
        view: value("--view")?.cloned(),
        light: has("--light"),
        port,
    })
}

// --------------------------------------------------------------------------------------
// Rendering (pure)
// --------------------------------------------------------------------------------------

fn pad(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - len))
    }
}

/// The table printed by `--list`.
pub fn render_list(rows: &[ListenerRow], now: i64) -> String {
    if rows.is_empty() {
        return "No listening ports match.\n".to_string();
    }
    let cells: Vec<[String; 7]> = rows
        .iter()
        .map(|r| {
            let services = r.services_label();
            [
                r.listener.proto.label().to_string(),
                r.listener.endpoint(),
                r.listener.pid.to_string(),
                if services.is_empty() {
                    r.proc.display_name()
                } else {
                    format!("{} [{services}]", r.proc.display_name())
                },
                r.exposure.badge(),
                r.listener
                    .created
                    .map(|c| fmt_age(now - c))
                    .unwrap_or_default(),
                r.well_known.unwrap_or("").to_string(),
            ]
        })
        .collect();
    let head = [
        "Proto",
        "Local address",
        "PID",
        "Process",
        "Exposure",
        "Open for",
        "Usually",
    ];
    let mut widths: Vec<usize> = head.iter().map(|h| h.len()).collect();
    for c in &cells {
        for (i, v) in c.iter().enumerate() {
            widths[i] = widths[i].max(v.chars().count()).min(48);
        }
    }
    let line = |vals: &[&str]| -> String {
        vals.iter()
            .enumerate()
            .map(|(i, v)| pad(v, widths[i]))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
    };
    let mut out = line(&head);
    out.push('\n');
    for c in &cells {
        out.push_str(&line(&c.iter().map(String::as_str).collect::<Vec<_>>()));
        out.push('\n');
    }
    out.push_str(&format!(
        "{} listening socket{}\n",
        rows.len(),
        if rows.len() == 1 { "" } else { "s" }
    ));
    out
}

/// The answer printed by `--port N`.
pub fn render_port(report: &PortReport, users: &[&ListenerRow], now: i64) -> String {
    let mut out = format!("{}\n", report.headline());
    for r in users {
        out.push_str(&format!(
            "\n  {} {}  {} (PID {})  [{}]\n",
            r.listener.proto.label(),
            r.listener.endpoint(),
            r.proc.display_name(),
            r.listener.pid,
            r.exposure.badge()
        ));
        let mut detail = |label: &str, value: &str| {
            if !value.is_empty() {
                out.push_str(&format!("      {label}: {value}\n"));
            }
        };
        detail("Path", &r.proc.path);
        detail("Command line", &r.proc.cmdline);
        detail("Services", &r.services_label());
        detail("User", &r.proc.user);
        if let Some(c) = r.listener.created {
            detail("Listening for", &fmt_age(now - c));
        }
        if r.proc.limited {
            detail(
                "Note",
                "run as administrator to see this process's path and command line",
            );
        }
    }
    if !report.notes.is_empty() {
        out.push('\n');
        for n in &report.notes {
            out.push_str(&format!("  - {n}\n"));
        }
    }
    out
}

/// One line per port for `--check`.
pub fn render_check(reports: &[PortReport]) -> String {
    let mut out = String::new();
    for r in reports {
        let state = match r.verdict {
            freeport::Verdict::Free => "free".to_string(),
            freeport::Verdict::FreeWithNotes => "free (see notes with --port)".to_string(),
            freeport::Verdict::InUse => "IN USE".to_string(),
            freeport::Verdict::Reserved => match r.excluded {
                Some(x) => format!("RESERVED (excluded range {}-{})", x.start, x.end),
                None => "RESERVED".to_string(),
            },
        };
        out.push_str(&format!(
            "{:>5}/{}  {state}\n",
            r.port,
            r.proto.label().to_lowercase()
        ));
    }
    out
}

fn port_json(report: &PortReport, users: &[&ListenerRow]) -> String {
    let v = serde_json::json!({
        "port": report.port,
        "protocol": report.proto.label(),
        "verdict": format!("{:?}", report.verdict),
        "bindable": report.is_bindable(),
        "users": users.iter().map(|r| serde_json::json!({
            "address": r.listener.addr.to_string(),
            "pid": r.listener.pid,
            "process": r.proc.display_name(),
            "path": r.proc.path,
            "command_line": r.proc.cmdline,
            "services": r.proc.services.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
            "exposure": r.exposure.badge(),
        })).collect::<Vec<_>>(),
        "excluded_range": report.excluded.map(|x| vec![x.start, x.end]),
        "url_reservations": report.reserved_urls,
        "in_dynamic_range": report.in_dynamic_range,
        "usually": report.well_known,
        "notes": report.notes,
    });
    serde_json::to_string_pretty(&v).unwrap_or_default()
}

// --------------------------------------------------------------------------------------
// Running
// --------------------------------------------------------------------------------------

/// Makes `println!` reach the console a GUI-subsystem program was started from.
pub fn attach_console() {
    use windows::core::w;
    use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Console::{
        AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE,
        STD_OUTPUT_HANDLE,
    };
    unsafe {
        let missing = |which| match GetStdHandle(which) {
            Ok(h) => h.is_invalid() || h.0.is_null(),
            Err(_) => true,
        };
        // Redirected output (a pipe or a file) already works: leave it alone.
        let (need_out, need_err) = (missing(STD_OUTPUT_HANDLE), missing(STD_ERROR_HANDLE));
        if !need_out && !need_err {
            return;
        }
        if AttachConsole(ATTACH_PARENT_PROCESS).is_err() {
            return;
        }
        if let Ok(con) = CreateFileW(
            w!("CONOUT$"),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        ) {
            if need_out {
                let _ = SetStdHandle(STD_OUTPUT_HANDLE, con);
            }
            if need_err {
                let _ = SetStdHandle(STD_ERROR_HANDLE, con);
            }
        }
    }
}

fn collect_all() -> (SocketSnapshot, SystemInfo) {
    let mut cache = ProcCache::default();
    let mut snap = collect::sockets(&mut cache);
    let sys = collect::system();
    snap.errors.dedup();
    (snap, sys)
}

/// Runs a text command and returns the process exit code. `Gui` is not handled here.
pub fn run(command: &Command) -> i32 {
    match command {
        Command::Help => {
            println!("{USAGE}");
            0
        }
        Command::Version => {
            println!("SocketForge {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Command::Selftest => match crate::selftest::run() {
            Ok(log) => {
                for line in log {
                    println!("{line}");
                }
                println!("SELFTEST PASSED");
                0
            }
            Err(e) => {
                println!("{e}");
                println!("SELFTEST FAILED");
                1
            }
        },
        Command::SelftestChild => crate::selftest::child_main(),
        Command::ApplyHosts {
            source,
            target,
            clear_read_only,
            flush_dns,
        } => match crate::hosts_store::apply_hosts(source, target, *clear_read_only) {
            Ok(()) => {
                if *flush_dns {
                    let _ = crate::hosts_store::flush_dns();
                }
                0
            }
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
        Command::Port {
            port,
            proto,
            output,
        } => {
            let (snap, sys) = collect_all();
            let rows = view::listener_rows(&snap, &sys);
            let report = freeport::check(*port, *proto, &PortContext::new(&snap, &sys));
            let users: Vec<&ListenerRow> = rows
                .iter()
                .filter(|r| r.listener.port == *port && r.listener.proto == *proto)
                .collect();
            if *output == Output::Json {
                println!("{}", port_json(&report, &users));
            } else {
                print!("{}", render_port(&report, &users, snap.taken));
            }
            if report.is_bindable() {
                0
            } else {
                1
            }
        }
        Command::List {
            tcp,
            udp,
            exposed,
            user_only,
            output,
        } => {
            let (snap, sys) = collect_all();
            let filter = ListenerFilter {
                tcp: *tcp,
                udp: *udp,
                exposed_only: *exposed,
                system: !*user_only,
                ..Default::default()
            };
            let rows: Vec<ListenerRow> = view::listener_rows(&snap, &sys)
                .into_iter()
                .filter(|r| view::filter_matches(r, &filter))
                .collect();
            match output {
                Output::Text => print!("{}", render_list(&rows, snap.taken)),
                Output::Json => println!("{}", export::listeners(&rows, Format::Json)),
                Output::Csv => print!("{}", export::listeners(&rows, Format::Csv)),
            }
            for e in &snap.errors {
                eprintln!("{e}");
            }
            0
        }
        Command::Connections { output } => {
            let (snap, _) = collect_all();
            let rows = view::connection_rows(&snap);
            let format = match output {
                Output::Json => Format::Json,
                _ => Format::Csv,
            };
            let text = export::connections(&rows, None, format);
            if *output == Output::Text {
                // Plain text: the CSV with wider separators reads well enough in a console.
                print!("{}", text.replace(',', "  "));
                println!(
                    "{} connection{}",
                    rows.len(),
                    if rows.len() == 1 { "" } else { "s" }
                );
            } else {
                println!("{text}");
            }
            0
        }
        Command::FreeFrom {
            from,
            count,
            block,
            proto,
        } => {
            let (snap, sys) = collect_all();
            let ctx = PortContext::new(&snap, &sys);
            let found: Vec<u16> = if *block {
                freeport::next_free_block(*from, *count, *proto, &ctx)
                    .map(|start| (start..=start + (*count - 1)).collect())
                    .unwrap_or_default()
            } else {
                freeport::free_in_range(*from, u16::MAX, *proto, &ctx, *count as usize)
            };
            if found.is_empty() {
                eprintln!("No free port from {from} upwards.");
                return 1;
            }
            for p in found {
                println!("{p}");
            }
            0
        }
        Command::Check { ports, proto } => {
            let (snap, sys) = collect_all();
            let ctx = PortContext::new(&snap, &sys);
            let reports: Vec<PortReport> = ports
                .iter()
                .map(|p| freeport::check(*p, *proto, &ctx))
                .collect();
            print!("{}", render_check(&reports));
            if reports.iter().all(|r| r.is_bindable()) {
                0
            } else {
                1
            }
        }
        Command::Export { path } => {
            let (snap, sys) = collect_all();
            let rows = view::listener_rows(&snap, &sys);
            let conns = view::connection_rows(&snap);
            let format = Format::from_path(path);
            let bundle = export::Bundle {
                listeners: &rows,
                connections: &conns,
                system: Some(&sys),
                ..Default::default()
            };
            match export::write(path, &export::everything(&bundle, format), format) {
                Ok(()) => {
                    println!(
                        "Exported {} listening sockets and {} connections.",
                        rows.len(),
                        conns.len()
                    );
                    0
                }
                Err(e) => {
                    eprintln!("{e}");
                    2
                }
            }
        }
        Command::Gui { .. } => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Listener, ProcInfo, SocketSnapshot};

    fn p(args: &[&str]) -> Result<Command, String> {
        parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn no_arguments_opens_the_window() {
        assert_eq!(
            p(&[]).unwrap(),
            Command::Gui {
                demo: false,
                screenshot: None,
                view: None,
                light: false,
                port: None
            }
        );
        assert_eq!(
            p(&[
                "--demo",
                "--screenshot",
                "a.png",
                "--view",
                "hosts-raw",
                "--light"
            ])
            .unwrap(),
            Command::Gui {
                demo: true,
                screenshot: Some(PathBuf::from("a.png")),
                view: Some("hosts-raw".into()),
                light: true,
                port: None
            }
        );
    }

    #[test]
    fn port_queries() {
        assert_eq!(
            p(&["--port", "3000"]).unwrap(),
            Command::Port {
                port: 3000,
                proto: Proto::Tcp,
                output: Output::Text
            }
        );
        assert_eq!(
            p(&["--port", ":53", "--udp", "--json"]).unwrap(),
            Command::Port {
                port: 53,
                proto: Proto::Udp,
                output: Output::Json
            }
        );
        assert!(matches!(
            p(&["--port", "8080", "--gui"]).unwrap(),
            Command::Gui {
                port: Some(8080),
                ..
            }
        ));
        for bad in [
            &["--port"][..],
            &["--port", "0"],
            &["--port", "70000"],
            &["--port", "http"],
            &["--port", "--udp"],
            &["--port", "80", "--csv"],
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn list_free_check_export() {
        assert_eq!(
            p(&["--list"]).unwrap(),
            Command::List {
                tcp: true,
                udp: true,
                exposed: false,
                user_only: false,
                output: Output::Text
            }
        );
        assert_eq!(
            p(&["--list", "--udp", "--exposed", "--user", "--csv"]).unwrap(),
            Command::List {
                tcp: false,
                udp: true,
                exposed: true,
                user_only: true,
                output: Output::Csv
            }
        );
        assert!(p(&["--list", "--json", "--csv"]).is_err());
        assert_eq!(
            p(&["--free-from", "8000"]).unwrap(),
            Command::FreeFrom {
                from: 8000,
                count: 1,
                block: false,
                proto: Proto::Tcp
            }
        );
        assert_eq!(
            p(&["--free-from", "8000", "--count", "3", "--block", "--udp"]).unwrap(),
            Command::FreeFrom {
                from: 8000,
                count: 3,
                block: true,
                proto: Proto::Udp
            }
        );
        assert!(p(&["--free-from", "8000", "--count", "0"]).is_err());
        assert!(p(&["--free-from"]).is_err());
        assert_eq!(
            p(&["--check", "3000,8000-8002", "5432"]).unwrap(),
            Command::Check {
                ports: vec![3000, 8000, 8001, 8002, 5432],
                proto: Proto::Tcp
            }
        );
        assert!(p(&["--check"]).is_err());
        assert!(p(&["--check", "abc"]).is_err());
        assert_eq!(
            p(&["--export", "out.html"]).unwrap(),
            Command::Export {
                path: PathBuf::from("out.html")
            }
        );
        assert_eq!(
            p(&["--connections", "--json"]).unwrap(),
            Command::Connections {
                output: Output::Json
            }
        );
    }

    #[test]
    fn misc_commands_and_typos() {
        assert_eq!(p(&["--help"]).unwrap(), Command::Help);
        assert_eq!(p(&["/?"]).unwrap(), Command::Help);
        assert_eq!(p(&["--version"]).unwrap(), Command::Version);
        assert_eq!(p(&["--selftest"]).unwrap(), Command::Selftest);
        assert_eq!(p(&["--selftest-child"]).unwrap(), Command::SelftestChild);
        assert!(p(&["--prot", "3000"]).unwrap_err().contains("--prot"));
        assert!(p(&["3000"]).is_err());
        assert_eq!(
            p(&[
                "--apply-hosts",
                "C:\\t\\new.tmp",
                "C:\\t\\hosts",
                "--flush-dns"
            ])
            .unwrap(),
            Command::ApplyHosts {
                source: PathBuf::from("C:\\t\\new.tmp"),
                target: PathBuf::from("C:\\t\\hosts"),
                clear_read_only: false,
                flush_dns: true
            }
        );
        assert!(p(&["--apply-hosts", "only-one"]).is_err());
    }

    fn sample() -> (SocketSnapshot, SystemInfo) {
        let mut snap = SocketSnapshot {
            taken: 1000,
            ..Default::default()
        };
        snap.listeners.push(Listener {
            proto: Proto::Tcp,
            addr: "127.0.0.1".parse().unwrap(),
            port: 5432,
            pid: 77,
            created: Some(400),
        });
        snap.procs.insert(
            77,
            ProcInfo {
                pid: 77,
                name: "postgres.exe".into(),
                path: "C:\\pg\\bin\\postgres.exe".into(),
                cmdline: "postgres -D data".into(),
                user: "PC\\Alex".into(),
                ..Default::default()
            },
        );
        (snap, SystemInfo::default())
    }

    #[test]
    fn rendering() {
        let (snap, sys) = sample();
        let rows = view::listener_rows(&snap, &sys);
        let list = render_list(&rows, snap.taken);
        let lines: Vec<&str> = list.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("Proto  Local address"));
        assert!(lines[1].starts_with("TCP    127.0.0.1:5432  77   postgres.exe"));
        assert!(lines[1].contains("Loopback only") && lines[1].contains("10 min"));
        assert!(lines[1].ends_with("PostgreSQL"));
        assert_eq!(lines[2], "1 listening socket");
        assert_eq!(render_list(&[], 0), "No listening ports match.\n");

        let ctx = PortContext::new(&snap, &sys);
        let report = freeport::check(5432, Proto::Tcp, &ctx);
        let users: Vec<&ListenerRow> = rows.iter().collect();
        let text = render_port(&report, &users, snap.taken);
        assert!(text.starts_with("TCP port 5432 is in use\n"));
        assert!(text.contains("postgres.exe (PID 77)  [Loopback only]"));
        assert!(text.contains("Command line: postgres -D data"));
        assert!(text.contains("Listening for: 10 min"));
        let json: serde_json::Value = serde_json::from_str(&port_json(&report, &users)).unwrap();
        assert_eq!(json["bindable"], false);
        assert_eq!(json["users"][0]["pid"], 77);

        let free = freeport::check(5433, Proto::Tcp, &ctx);
        assert_eq!(render_port(&free, &[], 0), "TCP port 5433 is free\n");
        let checks = render_check(&[report, free]);
        assert_eq!(checks, " 5432/tcp  IN USE\n 5433/tcp  free\n");
    }
}
