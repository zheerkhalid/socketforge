//! Collector: ports of this PC that are forwarded into containers or virtual
//! machines. Docker is asked through its command-line client (only when it is
//! installed); WSL forwards are recognised by the relay processes that own
//! the listening sockets. Read-only: nothing is started, stopped or changed.

use super::{note, procs, run_hidden, sockets, COMMAND_TIMEOUT};
use crate::model::{CollectorNote, Forward, ForwardSource, ProcInfo, Proto, SocketSnapshot};
use std::collections::HashMap;
use std::path::PathBuf;

// --------------------------------------------------------------------------------------
// Docker
// --------------------------------------------------------------------------------------

/// One published port from the `Ports` column of `docker ps`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DockerPort {
    /// `0.0.0.0`, `::`, `127.0.0.1`, ...
    pub host_addr: String,
    pub host_port: u16,
    pub container_port: u16,
    pub proto: Proto,
}

fn port_span(text: &str) -> Option<(u16, u16)> {
    let (a, b) = match text.split_once('-') {
        Some((a, b)) => (a.trim().parse::<u16>().ok()?, b.trim().parse::<u16>().ok()?),
        None => {
            let p = text.trim().parse::<u16>().ok()?;
            (p, p)
        }
    };
    (a != 0 && a <= b).then_some((a, b))
}

/// Parses the `Ports` column of `docker ps`, e.g.
/// `0.0.0.0:8080->80/tcp, [::]:8080->80/tcp, 5432/tcp`. Ports that are only
/// exposed inside Docker (no `->`) are not forwards and are left out; port
/// ranges are expanded.
pub fn parse_docker_ports(ports: &str) -> Vec<DockerPort> {
    let mut out: Vec<DockerPort> = Vec::new();
    for item in ports.split(',') {
        let item = item.trim();
        let Some((host, container)) = item.split_once("->") else {
            continue;
        };
        let (container_ports, proto) = match container.rsplit_once('/') {
            Some((p, proto)) => (p, proto.trim().to_ascii_lowercase()),
            None => (container, "tcp".to_string()),
        };
        let proto = match proto.as_str() {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            _ => continue,
        };
        // `0.0.0.0:8080`, `[::]:8080`, `:::8080` or just `8080`.
        let (addr, host_ports) = match host.rsplit_once(':') {
            Some((addr, p)) => (addr.trim(), p),
            None => ("", host),
        };
        let addr = addr.trim_start_matches('[').trim_end_matches(']');
        let (Some((h0, h1)), Some((c0, c1))) = (port_span(host_ports), port_span(container_ports))
        else {
            continue;
        };
        for (i, host_port) in (h0..=h1).enumerate() {
            // A range maps port by port; a single container port serves all.
            let container_port = if c1 - c0 == h1 - h0 {
                c0 + i as u16
            } else {
                c0
            };
            let port = DockerPort {
                host_addr: addr.to_string(),
                host_port,
                container_port,
                proto,
            };
            if !out.contains(&port) {
                out.push(port);
            }
        }
    }
    out
}

/// Parses the output of `docker ps --format "{{.Names}}\t{{.Image}}\t{{.Ports}}"`.
pub fn parse_docker_ps(text: &str) -> Vec<Forward> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut fields = line.trim_end_matches('\r').split('\t');
        let (Some(name), Some(image), Some(ports)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        for p in parse_docker_ports(ports) {
            out.push(Forward {
                source: ForwardSource::Docker,
                proto: p.proto,
                host_addr: p.host_addr,
                host_port: p.host_port,
                target: name.to_string(),
                target_port: p.container_port,
                detail: image.trim().to_string(),
            });
        }
    }
    out
}

/// `docker.exe` from the folders on PATH, if it is installed.
fn find_docker() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join("docker.exe"))
        .find(|candidate| candidate.is_file())
}

/// Does a pipe name belong to a Docker engine (`docker_engine`,
/// `dockerDesktopLinuxEngine`, ...)?
fn is_docker_pipe(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("docker")
}

/// Is a Docker engine listening on this PC? `None` when that cannot be told
/// (the pipe list is unreadable, or Docker is pointed at another place).
fn docker_engine_running() -> Option<bool> {
    if std::env::var_os("DOCKER_HOST").is_some() || std::env::var_os("DOCKER_CONTEXT").is_some() {
        return None;
    }
    let pipes = std::fs::read_dir(r"\\.\pipe\").ok()?;
    Some(
        pipes
            .flatten()
            .any(|p| is_docker_pipe(&p.file_name().to_string_lossy())),
    )
}

/// Published container ports. Without Docker (or with Docker switched off)
/// this is an empty, successful answer and nothing is started.
pub fn docker() -> (Vec<Forward>, CollectorNote) {
    const NAME: &str = "Docker forwards";
    let Some(exe) = find_docker() else {
        return (Vec::new(), note(NAME, true, 0, "Docker is not installed."));
    };
    // The client waits a long time for an engine that is not there.
    if docker_engine_running() == Some(false) {
        return (
            Vec::new(),
            note(NAME, true, 0, "Docker is installed but not running."),
        );
    }
    let args = [
        "ps",
        "--no-trunc",
        "--format",
        "{{.Names}}\t{{.Image}}\t{{.Ports}}",
    ];
    match run_hidden(&exe, &args, COMMAND_TIMEOUT) {
        Ok(out) if out.success => {
            let list = parse_docker_ps(&String::from_utf8_lossy(&out.stdout));
            let count = list.len();
            (list, note(NAME, true, count, ""))
        }
        Ok(_) => (
            Vec::new(),
            note(NAME, true, 0, "Docker is installed but not running."),
        ),
        Err(e) => (Vec::new(), note(NAME, false, 0, format!("docker {e}"))),
    }
}

// --------------------------------------------------------------------------------------
// WSL
// --------------------------------------------------------------------------------------

fn is_wsl_relay(name: &str) -> bool {
    name.eq_ignore_ascii_case("wslrelay.exe") || name.eq_ignore_ascii_case("wslhost.exe")
}

/// Listeners owned by the WSL relay processes (`wslrelay.exe`, `wslhost.exe`)
/// are ports forwarded into a WSL distribution.
pub fn wsl_forwards(snapshot: &SocketSnapshot) -> Vec<Forward> {
    let mut out: Vec<Forward> = Vec::new();
    for l in &snapshot.listeners {
        let Some(proc) = snapshot.procs.get(&l.pid) else {
            continue;
        };
        if !is_wsl_relay(&proc.name) {
            continue;
        }
        let forward = Forward {
            source: ForwardSource::Wsl,
            proto: l.proto,
            host_addr: l.addr.to_string(),
            host_port: l.port,
            target: "WSL".to_string(),
            target_port: 0,
            detail: proc.name.clone(),
        };
        if !out.contains(&forward) {
            out.push(forward);
        }
    }
    out
}

/// WSL forwards, found by taking a light look at the socket tables.
pub fn wsl() -> (Vec<Forward>, CollectorNote) {
    const NAME: &str = "WSL forwards";
    let raw = sockets::read_tables();
    let names = procs::process_table();
    let ok = !names.is_empty() && raw.errors.is_empty();
    let detail = if names.is_empty() {
        "The process list could not be read.".to_string()
    } else {
        raw.errors.join(" ")
    };
    let procs: HashMap<u32, ProcInfo> = names
        .into_iter()
        .filter(|(_, (name, _))| is_wsl_relay(name))
        .map(|(pid, (name, _))| {
            (
                pid,
                ProcInfo {
                    pid,
                    name,
                    ..Default::default()
                },
            )
        })
        .collect();
    let snapshot = SocketSnapshot {
        taken: crate::model::now_unix(),
        listeners: raw.listeners,
        connections: Vec::new(),
        procs,
        errors: Vec::new(),
    };
    let list = wsl_forwards(&snapshot);
    let count = list.len();
    (list, note(NAME, ok, count, detail))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Listener;

    fn p(addr: &str, host: u16, container: u16, proto: Proto) -> DockerPort {
        DockerPort {
            host_addr: addr.into(),
            host_port: host,
            container_port: container,
            proto,
        }
    }

    #[test]
    fn docker_ports_column() {
        assert_eq!(
            parse_docker_ports("0.0.0.0:8080->80/tcp, [::]:8080->80/tcp, 5432/tcp"),
            vec![
                p("0.0.0.0", 8080, 80, Proto::Tcp),
                p("::", 8080, 80, Proto::Tcp)
            ]
        );
        assert_eq!(
            parse_docker_ports("0.0.0.0:8080->80/tcp, :::8080->80/tcp"),
            vec![
                p("0.0.0.0", 8080, 80, Proto::Tcp),
                p("::", 8080, 80, Proto::Tcp)
            ]
        );
        assert_eq!(
            parse_docker_ports("127.0.0.1:5353->53/udp"),
            vec![p("127.0.0.1", 5353, 53, Proto::Udp)]
        );
        assert_eq!(
            parse_docker_ports("0.0.0.0:8000-8002->9000-9002/tcp"),
            vec![
                p("0.0.0.0", 8000, 9000, Proto::Tcp),
                p("0.0.0.0", 8001, 9001, Proto::Tcp),
                p("0.0.0.0", 8002, 9002, Proto::Tcp),
            ]
        );
        assert_eq!(
            parse_docker_ports("8080->80/tcp"),
            vec![p("", 8080, 80, Proto::Tcp)]
        );
        assert_eq!(
            parse_docker_ports("0.0.0.0:8080->80/tcp, 0.0.0.0:8080->80/tcp").len(),
            1
        );
    }

    #[test]
    fn docker_ports_that_are_not_forwards() {
        assert!(parse_docker_ports("").is_empty());
        assert!(parse_docker_ports("80/tcp, 443/tcp").is_empty());
        assert!(parse_docker_ports("0.0.0.0:9000->9000/sctp").is_empty());
        assert!(parse_docker_ports("0.0.0.0:abc->80/tcp").is_empty());
        assert!(parse_docker_ports("0.0.0.0:0->80/tcp").is_empty());
        assert!(parse_docker_ports("0.0.0.0:90-80->80/tcp").is_empty());
    }

    #[test]
    fn docker_ps_lines() {
        let text = "web\texample/web:1.2\t0.0.0.0:8080->80/tcp, [::]:8080->80/tcp\r\n\
                    db\texample/db:16\t5432/tcp\r\n\
                    cache\texample/cache\t127.0.0.1:6379->6379/tcp\n\
                    idle\texample/idle\t\n\
                    broken line\n";
        let list = parse_docker_ps(text);
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].source, ForwardSource::Docker);
        assert_eq!(list[0].target, "web");
        assert_eq!(list[0].detail, "example/web:1.2");
        assert_eq!(
            (list[0].host_addr.as_str(), list[0].host_port),
            ("0.0.0.0", 8080)
        );
        assert_eq!(list[0].target_port, 80);
        assert_eq!(list[1].host_addr, "::");
        assert_eq!(list[2].target, "cache");
        assert_eq!(
            (list[2].host_addr.as_str(), list[2].host_port),
            ("127.0.0.1", 6379)
        );
        assert!(parse_docker_ps("").is_empty());
    }

    #[test]
    fn wsl_relay_listeners_are_forwards() {
        let listener = |port: u16, pid: u32| Listener {
            proto: Proto::Tcp,
            addr: "127.0.0.1".parse().unwrap(),
            port,
            pid,
            created: None,
        };
        let proc = |pid: u32, name: &str| {
            (
                pid,
                ProcInfo {
                    pid,
                    name: name.into(),
                    ..Default::default()
                },
            )
        };
        let snapshot = SocketSnapshot {
            taken: 0,
            listeners: vec![
                listener(3000, 10),
                listener(3000, 10),
                listener(5173, 11),
                listener(8080, 12),
                listener(9999, 13),
            ],
            connections: Vec::new(),
            procs: [
                proc(10, "wslrelay.exe"),
                proc(11, "WSLHOST.EXE"),
                proc(12, "example.exe"),
            ]
            .into_iter()
            .collect(),
            errors: Vec::new(),
        };
        let list = wsl_forwards(&snapshot);
        assert_eq!(list.len(), 2);
        assert!(list
            .iter()
            .all(|f| f.source == ForwardSource::Wsl && f.target == "WSL"));
        assert_eq!(
            (list[0].host_port, list[0].host_addr.as_str()),
            (3000, "127.0.0.1")
        );
        assert_eq!(list[1].host_port, 5173);
        assert_eq!(list[1].detail, "WSLHOST.EXE");
    }

    #[test]
    fn docker_pipe_names() {
        assert!(is_docker_pipe("docker_engine"));
        assert!(is_docker_pipe("dockerDesktopLinuxEngine"));
        assert!(is_docker_pipe("DOCKER_CLI"));
        assert!(!is_docker_pipe("example_docker"));
        assert!(!is_docker_pipe("lsass"));
        // The pipe list of this PC is readable (unless Docker is redirected).
        if std::env::var_os("DOCKER_HOST").is_none() && std::env::var_os("DOCKER_CONTEXT").is_none()
        {
            assert!(docker_engine_running().is_some());
        }
    }

    #[test]
    fn collectors_answer_without_docker_or_wsl() {
        let (list, note) = wsl();
        assert!(note.ok);
        assert_eq!(note.count, list.len());
        let (list, note) = docker();
        assert_eq!(note.count, list.len());
    }
}
