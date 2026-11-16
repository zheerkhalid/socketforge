//! `--selftest`: opens listeners itself and checks that every layer finds them.
//!
//! The test only looks at things it started itself (its own sockets, a helper
//! copy of this program, a hosts file in a temporary folder). Its log contains
//! categories and counts only: no process names, paths, user names or remote
//! addresses of this PC other than SocketForge's own and loopback addresses.

use crate::actions;
use crate::collect::{self, ProcCache};
use crate::diff::{self, EventKind};
use crate::exposure::Exposure;
use crate::freeport::{self, BindTest, PortContext, Verdict};
use crate::hosts::Entry;
use crate::hosts_store::{self, HostsPaths, SaveOptions};
use crate::model::{Proto, SocketSnapshot, SystemInfo, TcpState};
use crate::view;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const GREETING: &[u8] = b"220 socketforge-selftest ready\r\n";
/// How long the helper process stays alive when nobody ends it.
const CHILD_LIFETIME: Duration = Duration::from_secs(60);

type Step = Result<(), String>;

fn ensure(condition: bool, what: &str) -> Step {
    if condition {
        Ok(())
    } else {
        Err(what.to_string())
    }
}

/// Runs the self-test. `Ok(log lines)` when everything passed, otherwise the
/// log up to and including the failure.
pub fn run() -> Result<Vec<String>, String> {
    run_with(&["--selftest-child".to_string()])
}

/// The self-test with a given command line for the helper process (started
/// from the current executable).
fn run_with(child_args: &[String]) -> Result<Vec<String>, String> {
    let mut log: Vec<String> = Vec::new();
    let mut cache = ProcCache::default();
    let steps: [(&str, &dyn Fn(&mut Vec<String>, &mut ProcCache) -> Step); 6] = [
        ("own sockets", &step_own_sockets),
        ("connection and port test", &step_connection),
        ("helper process", &|log, cache| {
            step_child(log, cache, child_args)
        }),
        ("hosts file in a sandbox", &|log, _| step_hosts(log)),
        ("system collectors", &|log, _| step_system(log)),
        ("actions", &|log, _| step_actions(log)),
    ];
    log.push(format!("SocketForge self-test ({} checks)", steps.len()));
    for (name, step) in steps {
        match step(&mut log, &mut cache) {
            Ok(()) => log.push(format!("PASS  {name}")),
            Err(e) => {
                log.push(format!("FAIL  {name}: {e}"));
                return Err(log.join("\n"));
            }
        }
    }
    log.push("All checks passed.".to_string());
    Ok(log)
}

fn same_file(a: &str, b: &Path) -> bool {
    let b_text = b.to_string_lossy();
    if a.eq_ignore_ascii_case(&b_text) {
        return true;
    }
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn has_listener(snap: &SocketSnapshot, proto: Proto, addr: IpAddr, port: u16, pid: u32) -> bool {
    snap.listeners
        .iter()
        .any(|l| l.proto == proto && l.addr == addr && l.port == port && l.pid == pid)
}

// --------------------------------------------------------------------------------------
// 1. Our own sockets through collect, view and freeport
// --------------------------------------------------------------------------------------

fn step_own_sockets(log: &mut Vec<String>, cache: &mut ProcCache) -> Step {
    let own = std::process::id();
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;

    let tcp4 = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind TCP 127.0.0.1: {e}"))?;
    let udp4 = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("bind UDP 127.0.0.1: {e}"))?;
    let tcp6 = TcpListener::bind("[::1]:0").ok();
    let tcp4_addr = tcp4.local_addr().map_err(|e| e.to_string())?;
    let udp4_addr = udp4.local_addr().map_err(|e| e.to_string())?;

    let snap = collect::sockets(cache);
    ensure(snap.errors.is_empty(), "a socket table could not be read")?;
    let with_path = snap.procs.values().filter(|p| !p.path.is_empty()).count();
    let limited = snap.procs.values().filter(|p| p.limited).count();
    let tcp = snap
        .listeners
        .iter()
        .filter(|l| l.proto == Proto::Tcp)
        .count();
    log.push(format!(
        "sockets: listeners={} (tcp={} udp={}) connections={} processes={} with_path={} \
         limited={}",
        snap.listeners.len(),
        tcp,
        snap.listeners.len() - tcp,
        snap.connections.len(),
        snap.procs.len(),
        with_path,
        limited
    ));

    let mut expected = vec![(Proto::Tcp, tcp4_addr), (Proto::Udp, udp4_addr)];
    match &tcp6 {
        Some(l) => expected.push((Proto::Tcp, l.local_addr().map_err(|e| e.to_string())?)),
        None => log.push("note: IPv6 loopback is not available here; [::1] check skipped".into()),
    }
    for (proto, addr) in &expected {
        ensure(
            has_listener(&snap, *proto, addr.ip(), addr.port(), own),
            &format!("own {} socket on {addr} was not found", proto.label()),
        )?;
        log.push(format!("found own {} socket on {addr}", proto.label()));
    }

    let me = snap
        .proc_of(own)
        .ok_or("no process details for SocketForge itself")?;
    ensure(
        same_file(&me.path, &exe),
        "own process path is not the current executable",
    )?;
    ensure(
        !me.limited && !me.name.is_empty(),
        "own process details are incomplete",
    )?;
    ensure(me.started.is_some(), "own start time is missing")?;
    ensure(
        !me.is_system,
        "SocketForge was classified as a Windows process",
    )?;
    log.push(format!(
        "own process: path matches, cmdline={} user={} parent={}",
        if me.cmdline.is_empty() {
            "missing"
        } else {
            "read"
        },
        if me.user.is_empty() {
            "missing"
        } else {
            "read"
        },
        if me.parent_name.is_empty() {
            "unknown"
        } else {
            "named"
        },
    ));

    // The view and the port checker must agree with what was just opened.
    let sys = SystemInfo::default();
    let rows = view::listener_rows(&snap, &sys);
    ensure(
        rows.len() == snap.listeners.len(),
        "view rows do not match the listeners",
    )?;
    for (proto, addr) in &expected {
        let row = rows
            .iter()
            .find(|r| {
                r.listener.proto == *proto
                    && r.listener.addr == addr.ip()
                    && r.listener.port == addr.port()
                    && r.listener.pid == own
            })
            .ok_or("own socket is missing from the view")?;
        ensure(
            row.exposure.exposure == Exposure::LoopbackOnly,
            "a loopback socket was not classified as loopback-only",
        )?;
        ensure(
            same_file(&row.proc.path, &exe),
            "view row has the wrong process",
        )?;
    }
    log.push(format!(
        "view: {} own rows classified loopback-only",
        expected.len()
    ));

    let ctx = PortContext::new(&snap, &sys);
    for (proto, addr) in [(Proto::Tcp, tcp4_addr), (Proto::Udp, udp4_addr)] {
        let port = addr.port();
        let report = freeport::check(port, proto, &ctx);
        ensure(
            report.verdict == Verdict::InUse,
            "freeport::check did not say in use",
        )?;
        ensure(
            !report.users.is_empty(),
            "freeport::check names no user of the port",
        )?;
        match freeport::next_free(port, proto, &ctx) {
            Some(next) => ensure(next != port, "freeport::next_free returned the used port")?,
            None => ensure(port == u16::MAX, "freeport::next_free found nothing")?,
        }
        ensure(
            freeport::bind_test(port, proto) != BindTest::Ok,
            "freeport::bind_test could bind a port that is in use",
        )?;
    }
    log.push("freeport: in use, skipped by next_free, test bind refused (TCP and UDP)".into());
    Ok(())
}

// --------------------------------------------------------------------------------------
// 2. A connection to ourselves, and the port test
// --------------------------------------------------------------------------------------

fn step_connection(log: &mut Vec<String>, cache: &mut ProcCache) -> Step {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let stop = Arc::new(AtomicBool::new(false));
    let server = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            // Greets every client and keeps the connections open until told to stop.
            let mut held = Vec::new();
            for stream in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(mut s) = stream {
                    let _ = s.write_all(GREETING);
                    held.push(s);
                }
            }
        })
    };
    let result = connection_checks(log, cache, addr);
    stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect_timeout(&addr, Duration::from_secs(2));
    let _ = server.join();
    result
}

fn connection_checks(log: &mut Vec<String>, cache: &mut ProcCache, addr: SocketAddr) -> Step {
    let own = std::process::id();
    let mut client = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|e| format!("connect to own listener: {e}"))?;
    let local = client.local_addr().map_err(|e| e.to_string())?;
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    let mut greeting = vec![0u8; GREETING.len()];
    client
        .read_exact(&mut greeting)
        .map_err(|e| format!("read greeting: {e}"))?;
    ensure(greeting == GREETING, "the greeting arrived damaged")?;

    let snap = collect::sockets(cache);
    let outgoing = snap
        .connections
        .iter()
        .find(|c| c.local == local && c.remote == addr && c.pid == own)
        .ok_or("the client side of the connection was not found")?;
    ensure(
        outgoing.state == TcpState::Established,
        "the connection is not shown as established",
    )?;
    ensure(
        snap.connections
            .iter()
            .any(|c| c.local == addr && c.remote == local && c.pid == own),
        "the accepted side of the connection was not found",
    )?;
    let rows = view::connection_rows(&snap);
    ensure(
        rows.len() == snap.connections.len(),
        "connection rows do not match",
    )?;
    log.push(format!(
        "connection {local} -> {addr} found on both sides (established)"
    ));

    let probe = actions::probe_port(addr, Duration::from_secs(3), false);
    ensure(
        probe.connected && probe.error.is_none(),
        "probe_port could not connect",
    )?;
    ensure(
        probe.banner == GREETING,
        "probe_port did not return the greeting",
    )?;
    ensure(
        !probe.http_reply,
        "probe_port mistook the greeting for an HTTP reply",
    )?;
    ensure(
        probe.banner_text == String::from_utf8_lossy(GREETING).trim_end(),
        "probe_port banner text is wrong",
    )?;
    log.push(format!(
        "probe_port: greeting read ({} bytes)",
        probe.banner.len()
    ));

    let refused = actions::probe_port(
        "203.0.113.1:9".parse().map_err(|_| "address")?,
        Duration::from_secs(1),
        false,
    );
    ensure(
        !refused.connected && refused.error.is_some(),
        "probe_port did not refuse an address outside this PC",
    )?;
    log.push("probe_port: non-local address refused without connecting".into());
    Ok(())
}

// --------------------------------------------------------------------------------------
// 3. A helper process: appears, is ended, disappears
// --------------------------------------------------------------------------------------

/// Kills the helper on every way out.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn step_child(log: &mut Vec<String>, cache: &mut ProcCache, args: &[String]) -> Step {
    let own = std::process::id();
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let before = collect::sockets(cache);

    let child = Command::new(&exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("the helper process could not be started: {e}"))?;
    let mut child = ChildGuard(child);
    let child_pid = child.0.id();

    // The helper prints its port on a line of its own.
    let stdout = child
        .0
        .stdout
        .take()
        .ok_or("the helper has no output pipe")?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if let Ok(port) = line.trim().parse::<u16>() {
                let _ = tx.send(port);
                break;
            }
        }
    });
    let port = rx
        .recv_timeout(Duration::from_secs(20))
        .map_err(|_| "the helper process did not report its port")?;
    ensure(port != 0, "the helper reported port 0")?;
    let loopback: IpAddr = [127, 0, 0, 1].into();

    let deadline = Instant::now() + Duration::from_secs(5);
    let after = loop {
        let snap = collect::sockets(cache);
        if has_listener(&snap, Proto::Tcp, loopback, port, child_pid) {
            break snap;
        }
        ensure(
            Instant::now() < deadline,
            "the helper's listener never appeared",
        )?;
        std::thread::sleep(Duration::from_millis(100));
    };
    let helper = after
        .proc_of(child_pid)
        .ok_or("no process details for the helper")?;
    ensure(
        same_file(&helper.path, &exe),
        "the helper's path is not this executable",
    )?;
    ensure(
        helper.parent == Some(own),
        "the helper's parent is not SocketForge",
    )?;
    ensure(
        !helper.parent_name.is_empty(),
        "the helper's parent has no name",
    )?;
    let opened = diff::listener_events(&before, &after, &[port]);
    ensure(
        opened.iter().any(|e| {
            e.kind == EventKind::Opened && e.port == port && e.pid == child_pid && e.watched
        }),
        "no Opened event for the helper's port",
    )?;
    log.push(format!(
        "helper: listener on 127.0.0.1:{port} found by its PID, Opened event seen"
    ));

    actions::end_process(child_pid).map_err(|e| format!("end_process failed: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let gone = loop {
        let snap = collect::sockets(cache);
        if !snap.listeners.iter().any(|l| l.pid == child_pid) {
            break snap;
        }
        ensure(
            Instant::now() < deadline,
            "the helper's listener is still there after end_process",
        )?;
        std::thread::sleep(Duration::from_millis(100));
    };
    let closed = diff::listener_events(&after, &gone, &[]);
    ensure(
        closed
            .iter()
            .any(|e| e.kind == EventKind::Closed && e.port == port && e.pid == child_pid),
        "no Closed event for the helper's port",
    )?;
    let exited = child.0.wait().map(|s| !s.success()).unwrap_or(false);
    ensure(exited, "the helper did not end through end_process")?;
    log.push("helper: ended by end_process, listener gone, Closed event seen".into());
    Ok(())
}

// --------------------------------------------------------------------------------------
// 4. The hosts flow on a copy in a temporary folder
// --------------------------------------------------------------------------------------

const SAMPLE_HOSTS: &str = "# SocketForge self-test hosts file\r\n\
127.0.0.1 localhost\r\n\
# 192.0.2.10 staging.example.test\r\n\
192.0.2.11 api.example.test www.example.test # demo\r\n";

fn step_hosts(log: &mut Vec<String>) -> Step {
    let dir = std::env::temp_dir().join(format!("socketforge-selftest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("temporary folder: {e}"))?;
    let result = hosts_checks(log, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    ensure(!dir.exists(), "the temporary folder could not be removed")?;
    log.push("hosts: temporary folder removed".into());
    Ok(())
}

fn hosts_checks(log: &mut Vec<String>, dir: &Path) -> Step {
    let paths = HostsPaths::sandbox(dir);
    ensure(
        paths.hosts.starts_with(dir),
        "the sandbox points outside its folder",
    )?;
    let original = SAMPLE_HOSTS.as_bytes().to_vec();
    std::fs::write(&paths.hosts, &original).map_err(|e| format!("write sample: {e}"))?;

    let loaded = hosts_store::load(&paths)?;
    ensure(
        !loaded.missing && loaded.bytes == original,
        "the sample was not read back",
    )?;
    let mut doc = loaded.doc.clone();
    let entries = doc.entry_count();
    let enabled = doc.enabled_count();
    ensure(
        entries == 3 && enabled == 2,
        "the sample was not parsed as 3 entries, 2 enabled",
    )?;

    let row = doc
        .rows()
        .into_iter()
        .find(|r| r.entry.hosts.iter().any(|h| h == "api.example.test"))
        .ok_or("the sample entry was not found")?;
    ensure(
        doc.set_enabled(row.line, false),
        "the entry could not be switched off",
    )?;
    doc.add_entry(
        Entry::new("127.0.0.1", &["selftest.socketforge.test"]),
        None,
    );
    ensure(
        doc.entry_count() == entries + 1 && doc.enabled_count() == enabled,
        "toggle and add did not change the counts as expected",
    )?;

    let outcome = hosts_store::save(&paths, &doc, Some(&loaded.bytes), SaveOptions::default())
        .map_err(|e| e.message())?;
    ensure(!outcome.unchanged, "the save claims nothing changed")?;
    let backup = outcome.backup.ok_or("the save made no backup")?;
    ensure(backup.is_file(), "the backup file does not exist")?;
    ensure(backup.starts_with(dir), "the backup is outside the sandbox")?;
    let backup_bytes = std::fs::read(&backup).map_err(|e| format!("read backup: {e}"))?;
    ensure(
        backup_bytes == original,
        "the backup differs from the original",
    )?;
    ensure(
        !hosts_store::list_backups(&paths).is_empty(),
        "the backup is not listed",
    )?;

    let saved = hosts_store::load(&paths)?;
    ensure(
        saved.bytes != original,
        "the hosts file was not changed by the save",
    )?;
    ensure(
        saved.doc.entry_count() == entries + 1 && saved.doc.enabled_count() == enabled,
        "the saved file does not contain the changes",
    )?;
    ensure(
        String::from_utf8_lossy(&saved.bytes).contains("selftest.socketforge.test"),
        "the new entry is not in the saved file",
    )?;
    log.push(format!(
        "hosts: loaded {entries} entries, toggled 1, added 1, saved with a backup"
    ));

    hosts_store::restore(&paths, &backup, SaveOptions::default()).map_err(|e| e.message())?;
    let restored = std::fs::read(&paths.hosts).map_err(|e| format!("read restored: {e}"))?;
    ensure(
        restored == original,
        "the restored file differs from the original",
    )?;
    log.push(format!(
        "hosts: restored from the backup, {} bytes identical to the original",
        restored.len()
    ));
    Ok(())
}

// --------------------------------------------------------------------------------------
// 5. The slow collectors, and 6. the harmless actions
// --------------------------------------------------------------------------------------

fn step_system(log: &mut Vec<String>) -> Step {
    let started = Instant::now();
    let sys = collect::system();
    ensure(!sys.notes.is_empty(), "no collector reported")?;
    for note in &sys.notes {
        log.push(format!(
            "collector {}: {}, count {}",
            note.name,
            if note.ok { "ok" } else { "failed" },
            note.count
        ));
    }
    log.push(format!(
        "firewall: available={} profiles enabled={} active={} default-block={}",
        sys.firewall.available,
        sys.firewall.enabled.label(),
        sys.firewall.active.label(),
        sys.firewall.default_inbound_block.label()
    ));
    log.push(format!(
        "system(): {} collectors in {} ms",
        sys.notes.len(),
        started.elapsed().as_millis()
    ));
    ensure(
        sys.notes.iter().any(|n| n.ok),
        "every system collector failed",
    )?;
    ensure(
        sys.firewall.rules.len() == sys.notes.first().map(|n| n.count).unwrap_or(usize::MAX),
        "the firewall note does not match the rules",
    )
}

fn step_actions(log: &mut Vec<String>) -> Step {
    ensure(
        actions::is_local_address(&[127, 0, 0, 1].into()),
        "127.0.0.1 is not seen as local",
    )?;
    ensure(
        !actions::is_local_address(&[203, 0, 113, 1].into()),
        "a documentation address is seen as local",
    )?;
    ensure(
        actions::end_process(0).is_err(),
        "end_process accepted PID 0",
    )?;
    ensure(
        actions::end_process(4).is_err(),
        "end_process accepted PID 4",
    )?;
    ensure(
        actions::end_process(std::process::id()).is_err(),
        "end_process accepted SocketForge itself",
    )?;
    let icon = std::env::current_exe()
        .ok()
        .and_then(|exe| crate::icons::extract(&exe.to_string_lossy()));
    log.push(format!(
        "actions: guards hold, elevated={}, own icon={}",
        actions::is_elevated(),
        match icon {
            Some(i) => format!("{}x{}", i.width, i.height),
            None => "none".to_string(),
        }
    ));
    Ok(())
}

// --------------------------------------------------------------------------------------
// The helper process
// --------------------------------------------------------------------------------------

/// Binds a loopback listener, prints its port and waits to be ended.
fn child_body() {
    let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
        std::process::exit(2);
    };
    let Ok(addr) = listener.local_addr() else {
        std::process::exit(2);
    };
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{}", addr.port());
    let _ = out.flush();
    std::thread::sleep(CHILD_LIFETIME);
    drop(listener);
}

/// `--selftest-child`: the helper process of the self-test. Binds a TCP
/// listener on 127.0.0.1 (port chosen by Windows), prints the port number on
/// one line to stdout, then sleeps for up to 60 seconds and exits.
pub fn child_main() -> ! {
    child_body();
    std::process::exit(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands in for `SocketForge.exe --selftest-child` when the self-test
    /// runs inside the test program.
    #[test]
    #[ignore = "helper process of full_selftest"]
    fn selftest_child_helper() {
        child_body();
    }

    /// The whole self-test, with the test program itself as the helper.
    /// Run with `cargo test --lib selftest::tests::full_selftest -- --ignored --nocapture`.
    #[test]
    #[ignore = "starts a helper process and reads the live system"]
    fn full_selftest() {
        let args: Vec<String> = [
            "--ignored",
            "--exact",
            "--nocapture",
            "selftest::tests::selftest_child_helper",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        match run_with(&args) {
            Ok(log) => println!("{}", log.join("\n")),
            Err(log) => panic!("self-test failed:\n{log}"),
        }
    }

    #[test]
    fn hosts_step_works_and_cleans_up() {
        let mut log = Vec::new();
        step_hosts(&mut log).unwrap();
        assert!(log.iter().any(|l| l.contains("restored")));
        let dir = std::env::temp_dir().join(format!("socketforge-selftest-{}", std::process::id()));
        assert!(!dir.exists());
    }

    #[test]
    fn own_sockets_step_passes() {
        let mut log = Vec::new();
        let mut cache = ProcCache::default();
        step_own_sockets(&mut log, &mut cache).unwrap();
        step_connection(&mut log, &mut cache).unwrap();
        // The log holds only our own loopback endpoints.
        let exe = std::env::current_exe().unwrap();
        let name = exe.file_stem().unwrap().to_string_lossy().to_lowercase();
        assert!(log.iter().all(|l| !l.to_lowercase().contains(&name)));
        assert!(log.iter().all(|l| !l.contains(":\\")));
    }
}
