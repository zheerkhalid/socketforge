//! Collectors: read-only enumeration of sockets, processes, services, the
//! firewall, HTTP.sys, reserved ranges, port proxies and container forwards.
//!
//! Nothing in here changes the system.

pub mod firewall;
pub mod forwards;
pub mod httpsys;
pub mod netsh;
pub mod procs;
pub mod services;
pub mod sockets;

use crate::model::{CollectorNote, SocketSnapshot, SystemInfo};
use std::collections::HashSet;
use std::io::Read;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub use procs::ProcCache;

/// The fast part: TCP/UDP tables (IPv4 + IPv6) and the processes behind them.
/// Cheap enough to call every second or two. `cache` keeps process details
/// between calls so that only new PIDs are inspected.
pub fn sockets(cache: &mut ProcCache) -> SocketSnapshot {
    let raw = sockets::read_tables();
    let mut pids: HashSet<u32> = raw.listeners.iter().map(|l| l.pid).collect();
    pids.extend(raw.connections.iter().map(|c| c.pid));
    let procs = cache.resolve(&pids);
    SocketSnapshot {
        taken: crate::model::now_unix(),
        listeners: raw.listeners,
        connections: raw.connections,
        procs,
        errors: raw.errors,
    }
}

/// The slow part: firewall rules, excluded ranges, URL reservations, HTTP.sys
/// listeners, port proxies, Docker/WSL/Hyper-V forwards. May take a second or
/// more; call it from a background thread, on demand and every minute or so.
///
/// Every collector runs on its own thread and reports through one
/// `CollectorNote`; a collector that fails (or even panics) leaves its part of
/// the result empty and does not disturb the others.
pub fn system() -> SystemInfo {
    let mut info = SystemInfo {
        taken: crate::model::now_unix(),
        ..Default::default()
    };
    let failed = |name: &str| CollectorNote {
        name: name.to_string(),
        ok: false,
        count: 0,
        detail: "The collector stopped unexpectedly.".to_string(),
    };
    std::thread::scope(|s| {
        let firewall = s.spawn(firewall::collect);
        let excluded = s.spawn(netsh::excluded_ranges);
        let dynamic = s.spawn(netsh::dynamic_ranges);
        let portproxy = s.spawn(netsh::portproxy_rules);
        let reservations = s.spawn(httpsys::reservations);
        let http = s.spawn(httpsys::listeners);
        let docker = s.spawn(forwards::docker);
        let wsl = s.spawn(forwards::wsl);

        match firewall.join() {
            Ok(state) => {
                info.notes.push(CollectorNote {
                    name: "Firewall rules".into(),
                    ok: state.available,
                    count: state.rules.len(),
                    detail: state.error.clone().unwrap_or_default(),
                });
                info.firewall = state;
            }
            Err(_) => {
                info.firewall.error = Some("The firewall collector stopped unexpectedly.".into());
                info.notes.push(failed("Firewall rules"));
            }
        }
        match excluded.join() {
            Ok((ranges, note)) => {
                info.excluded = ranges;
                info.notes.push(note);
            }
            Err(_) => info.notes.push(failed("Excluded port ranges")),
        }
        match dynamic.join() {
            Ok((ranges, note)) => {
                info.dynamic = ranges;
                info.notes.push(note);
            }
            Err(_) => info.notes.push(failed("Dynamic port range")),
        }
        match reservations.join() {
            Ok((list, note)) => {
                info.reservations = list;
                info.notes.push(note);
            }
            Err(_) => info.notes.push(failed("URL reservations")),
        }
        match http.join() {
            Ok((list, note)) => {
                info.http_listeners = list;
                info.notes.push(note);
            }
            Err(_) => info.notes.push(failed("HTTP.sys listeners")),
        }
        match portproxy.join() {
            Ok((list, note)) => {
                info.portproxy = list;
                info.notes.push(note);
            }
            Err(_) => info.notes.push(failed("Port proxies")),
        }
        match docker.join() {
            Ok((list, note)) => {
                info.forwards.extend(list);
                info.notes.push(note);
            }
            Err(_) => info.notes.push(failed("Docker forwards")),
        }
        match wsl.join() {
            Ok((list, note)) => {
                info.forwards.extend(list);
                info.notes.push(note);
            }
            Err(_) => info.notes.push(failed("WSL forwards")),
        }
    });
    info
}

// --------------------------------------------------------------------------------------
// Shared helpers for the collectors
// --------------------------------------------------------------------------------------

pub(crate) const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// How long an external command (netsh, docker) may take before it is killed.
pub(crate) const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) fn note(name: &str, ok: bool, count: usize, detail: impl Into<String>) -> CollectorNote {
    CollectorNote {
        name: name.to_string(),
        ok,
        count,
        detail: detail.into(),
    }
}

/// `%SystemRoot%\System32\<name>`: Windows' own tools are started by full path.
pub(crate) fn system32(name: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\Windows"));
    root.join("System32").join(name)
}

pub(crate) struct CommandOutput {
    /// The command ended with exit code 0.
    pub success: bool,
    pub stdout: Vec<u8>,
}

/// Runs a console program without a window, captures what it prints and kills
/// it when it takes longer than `timeout`.
pub(crate) fn run_hidden(
    program: &Path,
    args: &[&str],
    timeout: Duration,
) -> Result<CommandOutput, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("could not be started ({})", e.kind()))?;
    let (tx, rx) = std::sync::mpsc::channel();
    if let Some(mut out) = child.stdout.take() {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = out.read_to_end(&mut buf);
            let _ = tx.send(buf);
        });
    }
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "did not answer within {} s",
                        timeout.as_secs().max(1)
                    ));
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("could not be waited for ({})", e.kind()));
            }
        }
    };
    let stdout = rx.recv_timeout(Duration::from_secs(1)).unwrap_or_default();
    Ok(CommandOutput {
        success: status.success(),
        stdout,
    })
}

#[link(name = "kernel32")]
extern "system" {
    fn GetOEMCP() -> u32;
    fn MultiByteToWideChar(
        code_page: u32,
        flags: u32,
        multi_byte: *const u8,
        multi_byte_len: i32,
        wide: *mut u16,
        wide_len: i32,
    ) -> i32;
}

/// Decodes console output (OEM code page). Falls back to a lossy UTF-8 reading.
pub(crate) fn decode_oem(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    if bytes.is_ascii() {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let Ok(len) = i32::try_from(bytes.len()) else {
        return String::from_utf8_lossy(bytes).into_owned();
    };
    unsafe {
        let cp = GetOEMCP();
        let n = MultiByteToWideChar(cp, 0, bytes.as_ptr(), len, std::ptr::null_mut(), 0);
        if n <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let mut wide = vec![0u16; n as usize];
        let n = MultiByteToWideChar(cp, 0, bytes.as_ptr(), len, wide.as_mut_ptr(), n);
        if n <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        String::from_utf16_lossy(&wide[..n as usize])
    }
}

/// Runs `netsh <args>` hidden: `(exit code was 0, text)`.
pub(crate) fn netsh_output(args: &[&str], timeout: Duration) -> Result<(bool, String), String> {
    let out =
        run_hidden(&system32("netsh.exe"), args, timeout).map_err(|e| format!("netsh {e}"))?;
    Ok((out.success, decode_oem(&out.stdout)))
}

/// Runs `netsh <args>` hidden and returns its text.
pub(crate) fn netsh(args: &[&str]) -> Result<String, String> {
    netsh_output(args, COMMAND_TIMEOUT).map(|(_, text)| text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_plain_and_empty_output() {
        assert_eq!(decode_oem(b""), "");
        assert_eq!(
            decode_oem(b"Start Port : 49152\r\n"),
            "Start Port : 49152\r\n"
        );
        // Non-ASCII bytes must never panic, whatever the code page is.
        let text = decode_oem(&[b'P', 0x81, b'r', b't', b' ', b'8', b'0']);
        assert!(text.ends_with("80"));
    }

    #[test]
    fn hidden_commands_are_captured_and_time_out() {
        let cmd = system32("cmd.exe");
        let out = run_hidden(&cmd, &["/c", "echo", "forge-test"], COMMAND_TIMEOUT).unwrap();
        assert!(out.success);
        assert!(decode_oem(&out.stdout).contains("forge-test"));

        let started = Instant::now();
        let ping = system32("ping.exe");
        let r = run_hidden(
            &ping,
            &["-n", "30", "127.0.0.1"],
            Duration::from_millis(300),
        );
        assert!(r.is_err());
        assert!(started.elapsed() < Duration::from_secs(5));

        assert!(run_hidden(Path::new("Z:\\missing\\nothing.exe"), &[], COMMAND_TIMEOUT).is_err());
    }
}
