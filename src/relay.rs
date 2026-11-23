//! A local port forward: listens on one port of this PC and passes every
//! connection on to another address, for as long as SocketForge runs.
//!
//! Unlike a `netsh portproxy` rule it needs no administrator rights, changes
//! nothing in Windows, and is gone when it is stopped.

use crate::serve::{bind_error_text, Wake};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Connections passed on at the same time; more are refused.
const MAX_ACTIVE: usize = 256;

/// Where connections are sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn label(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// True when the target is a port of this PC.
    pub fn is_local(&self) -> bool {
        self.host.eq_ignore_ascii_case("localhost")
            || self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }
}

/// Reads a target as people type it: `5432`, `localhost:5432`,
/// `192.168.1.20:80`, `db.example:5432`, `[::1]:8080`.
pub fn parse_target(text: &str) -> Result<Target, String> {
    let t = text.trim();
    let t = t
        .strip_prefix("tcp://")
        .or_else(|| t.strip_prefix("http://"))
        .unwrap_or(t)
        .trim_end_matches('/');
    if t.is_empty() {
        return Err("Type where to send the connections, for example localhost:5432.".into());
    }
    let port_of = |s: &str| -> Result<u16, String> {
        match s.parse::<u32>() {
            Ok(n) if (1..=65535).contains(&n) => Ok(n as u16),
            _ => Err(format!("\"{s}\" is not a port number (1 to 65535).")),
        }
    };
    if t.chars().all(|c| c.is_ascii_digit()) {
        return Ok(Target {
            host: "127.0.0.1".into(),
            port: port_of(t)?,
        });
    }
    let (host, port) = if let Some(rest) = t.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or("The IPv6 address is missing its closing bracket.")?;
        let port = after
            .strip_prefix(':')
            .ok_or("Add the port after the address, for example [::1]:8080.")?;
        (host, port)
    } else {
        match t.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, port),
            Some(_) => {
                return Err("Put an IPv6 address in brackets, for example [::1]:8080.".to_string())
            }
            None => return Err("Add the port, for example localhost:5432.".to_string()),
        }
    };
    let host = host.trim();
    if host.is_empty() {
        return Err("The address before the port is missing.".into());
    }
    if host.parse::<IpAddr>().is_err() {
        if let Some(problem) = crate::hosts::name_problem(host) {
            return Err(problem);
        }
    }
    Ok(Target {
        host: host.to_string(),
        port: port_of(port.trim())?,
    })
}

struct Shared {
    active: AtomicUsize,
    total: AtomicU64,
    /// Bytes from the clients to the target.
    sent: AtomicU64,
    /// Bytes from the target back to the clients.
    received: AtomicU64,
    failed: AtomicU64,
    last_error: Mutex<Option<String>>,
    /// Open sockets, so that stopping can close them.
    live: Mutex<Vec<(u64, TcpStream)>>,
    wake: Option<Wake>,
}

impl Shared {
    fn wake(&self) {
        if let Some(wake) = &self.wake {
            wake();
        }
    }
}

/// Numbers for the window.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayStats {
    pub active: usize,
    pub total: u64,
    pub sent: u64,
    pub received: u64,
    pub failed: u64,
    pub last_error: Option<String>,
}

/// A running forward. Dropping it stops it and closes its connections.
pub struct Relay {
    listen: SocketAddr,
    lan: bool,
    target: Target,
    stop: Arc<AtomicBool>,
    shared: Arc<Shared>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Relay {
    /// Starts listening on `port` (0 = any free port) and forwarding to `target`.
    pub fn start(
        port: u16,
        lan: bool,
        target: Target,
        wake: Option<Wake>,
    ) -> Result<Relay, String> {
        if target.is_local() && target.port == port {
            return Err("That would forward the port to itself. Pick two different ports.".into());
        }
        let ip = if lan {
            Ipv4Addr::UNSPECIFIED
        } else {
            Ipv4Addr::LOCALHOST
        };
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(ip), port))
            .map_err(|e| bind_error_text(port, &e))?;
        let listen = listener
            .local_addr()
            .map_err(|e| format!("Could not start the forward: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("Could not start the forward: {e}"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Shared {
            active: AtomicUsize::new(0),
            total: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            last_error: Mutex::new(None),
            live: Mutex::new(Vec::new()),
            wake,
        });
        let (stop2, shared2, target2) = (stop.clone(), shared.clone(), target.clone());
        let thread = std::thread::Builder::new()
            .name("forward".into())
            .spawn(move || accept_loop(listener, target2, stop2, shared2))
            .map_err(|e| format!("Could not start the forward: {e}"))?;
        Ok(Relay {
            listen,
            lan,
            target,
            stop,
            shared,
            thread: Some(thread),
        })
    }

    pub fn port(&self) -> u16 {
        self.listen.port()
    }

    pub fn lan(&self) -> bool {
        self.lan
    }

    pub fn target(&self) -> &Target {
        &self.target
    }

    pub fn stats(&self) -> RelayStats {
        RelayStats {
            active: self.shared.active.load(Ordering::Relaxed),
            total: self.shared.total.load(Ordering::Relaxed),
            sent: self.shared.sent.load(Ordering::Relaxed),
            received: self.shared.received.load(Ordering::Relaxed),
            failed: self.shared.failed.load(Ordering::Relaxed),
            last_error: self.shared.last_error.lock().ok().and_then(|e| e.clone()),
        }
    }

    /// Stops listening and closes the connections that are open.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if let Ok(mut live) = self.shared.live.lock() {
            for (_, s) in live.drain(..) {
                let _ = s.shutdown(Shutdown::Both);
            }
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(listener: TcpListener, target: Target, stop: Arc<AtomicBool>, shared: Arc<Shared>) {
    let mut next_id = 0u64;
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((client, _)) => {
                let _ = client.set_nonblocking(false);
                if shared.active.load(Ordering::Relaxed) >= MAX_ACTIVE {
                    shared.failed.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                next_id += 2;
                let id = next_id;
                shared.active.fetch_add(1, Ordering::Relaxed);
                shared.total.fetch_add(1, Ordering::Relaxed);
                let (shared2, target2, stop2) = (shared.clone(), target.clone(), stop.clone());
                let spawned = std::thread::Builder::new()
                    .name("forward-conn".into())
                    .spawn(move || {
                        pipe(client, &target2, id, &shared2, &stop2);
                        shared2.active.fetch_sub(1, Ordering::Relaxed);
                        shared2.wake();
                    });
                if spawned.is_err() {
                    shared.active.fetch_sub(1, Ordering::Relaxed);
                }
                shared.wake();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

/// Connects to the target, trying each address its name resolves to.
fn connect(target: &Target) -> Result<TcpStream, String> {
    let addrs: Vec<SocketAddr> = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|_| format!("The name {} could not be found.", target.host))?
        .collect();
    let mut last = format!("The name {} has no address.", target.host);
    for addr in addrs.iter().take(4) {
        match TcpStream::connect_timeout(addr, Duration::from_secs(5)) {
            Ok(s) => return Ok(s),
            Err(e) => {
                last = match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => {
                        format!("Nothing is listening on {}.", target.label())
                    }
                    std::io::ErrorKind::TimedOut => {
                        format!("{} did not answer in time.", target.label())
                    }
                    _ => format!("Could not connect to {}: {e}", target.label()),
                }
            }
        }
    }
    Err(last)
}

/// How often a quiet connection looks whether it should end.
const POLL: Duration = Duration::from_millis(250);

/// Passes bytes one way until the sender is done, an error occurs, or one of
/// the `ended` flags is set. The reads time out every [`POLL`] to look at the
/// flags: on Windows closing a socket's other handle does not wake a read
/// that is already waiting.
fn copy(from: &mut TcpStream, to: &mut TcpStream, counter: &AtomicU64, ended: [&AtomicBool; 2]) {
    let _ = from.set_read_timeout(Some(POLL));
    let _ = to.set_write_timeout(Some(Duration::from_secs(30)));
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                if ended.iter().any(|f| f.load(Ordering::Relaxed)) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

fn pipe(client: TcpStream, target: &Target, id: u64, shared: &Arc<Shared>, stop: &Arc<AtomicBool>) {
    let upstream = match connect(target) {
        Ok(s) => s,
        Err(e) => {
            shared.failed.fetch_add(1, Ordering::Relaxed);
            if let Ok(mut last) = shared.last_error.lock() {
                *last = Some(e);
            }
            return;
        }
    };
    let (Ok(mut client_r), Ok(mut up_w), Ok(c_keep), Ok(u_keep)) = (
        client.try_clone(),
        upstream.try_clone(),
        client.try_clone(),
        upstream.try_clone(),
    ) else {
        return;
    };
    if let Ok(mut live) = shared.live.lock() {
        live.push((id, c_keep));
        live.push((id + 1, u_keep));
    }
    // Stopped while the connection was being made: do not start.
    if !stop.load(Ordering::Relaxed) {
        // Set when the target has closed: the other direction then ends too.
        // (A client that has finished sending still gets the rest of the answer.)
        let target_done = Arc::new(AtomicBool::new(false));
        let (shared_up, stop_up, done_up) = (shared.clone(), stop.clone(), target_done.clone());
        let up = std::thread::Builder::new()
            .name("forward-up".into())
            .spawn(move || {
                copy(
                    &mut client_r,
                    &mut up_w,
                    &shared_up.sent,
                    [&stop_up, &done_up],
                )
            });
        let (mut up_r, mut client_w) = (upstream, client);
        copy(&mut up_r, &mut client_w, &shared.received, [stop, stop]);
        // The target is done: nothing more will be passed on.
        target_done.store(true, Ordering::Relaxed);
        let _ = client_w.shutdown(Shutdown::Both);
        let _ = up_r.shutdown(Shutdown::Both);
        if let Ok(t) = up {
            let _ = t.join();
        }
    }
    if let Ok(mut live) = shared.live.lock() {
        live.retain(|(i, _)| *i != id && *i != id + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server that answers each connection with "echo:" + what it received.
    fn echo_server() -> (u16, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let thread = std::thread::spawn(move || {
            while !stop2.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        s.set_nonblocking(false).unwrap();
                        std::thread::spawn(move || {
                            let mut data = Vec::new();
                            let _ = s.read_to_end(&mut data);
                            let _ = s.write_all(b"echo:");
                            let _ = s.write_all(&data);
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        (port, stop, thread)
    }

    fn wait_until(what: &str, f: impl Fn() -> bool) {
        let started = std::time::Instant::now();
        while !f() {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "timed out: {what}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn passes_bytes_both_ways_through_real_listeners() {
        let (echo_port, echo_stop, echo_thread) = echo_server();
        let target = parse_target(&echo_port.to_string()).unwrap();
        let mut relay = Relay::start(0, false, target.clone(), None).unwrap();
        assert_ne!(relay.port(), echo_port);
        assert_eq!(relay.target(), &target);
        assert!(!relay.lan());

        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        for _ in 0..3 {
            let mut c = TcpStream::connect(("127.0.0.1", relay.port())).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            c.write_all(&payload).unwrap();
            c.shutdown(Shutdown::Write).unwrap();
            let mut back = Vec::new();
            c.read_to_end(&mut back).unwrap();
            assert_eq!(&back[..5], b"echo:");
            assert_eq!(&back[5..], &payload[..]);
        }
        wait_until("connections closed", || relay.stats().active == 0);
        let stats = relay.stats();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.sent, 3 * payload.len() as u64);
        assert_eq!(stats.received, 3 * (payload.len() as u64 + 5));
        assert_eq!((stats.failed, stats.last_error), (0, None));

        // Stopping frees the port.
        let port = relay.port();
        relay.stop();
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
        echo_stop.store(true, Ordering::Relaxed);
        echo_thread.join().unwrap();
    }

    #[test]
    fn stopping_closes_open_connections() {
        let (echo_port, echo_stop, echo_thread) = echo_server();
        let mut relay = Relay::start(
            0,
            false,
            parse_target(&echo_port.to_string()).unwrap(),
            None,
        )
        .unwrap();
        let mut c = TcpStream::connect(("127.0.0.1", relay.port())).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(b"held open").unwrap();
        wait_until("bytes passed on", || relay.stats().sent == 9);
        assert_eq!(relay.stats().active, 1);
        relay.stop();
        // The client sees the end of the connection instead of hanging.
        let mut rest = Vec::new();
        let _ = c.read_to_end(&mut rest);
        wait_until("connection closed", || relay.stats().active == 0);
        echo_stop.store(true, Ordering::Relaxed);
        echo_thread.join().unwrap();
    }

    #[test]
    fn a_dead_target_is_reported_not_hung() {
        // A port nothing listens on: bind, note the number, close.
        let dead = {
            let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            l.local_addr().unwrap().port()
        };
        let relay = Relay::start(0, false, parse_target(&dead.to_string()).unwrap(), None).unwrap();
        let mut c = TcpStream::connect(("127.0.0.1", relay.port())).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        let mut rest = Vec::new();
        let _ = c.read_to_end(&mut rest);
        assert!(rest.is_empty());
        wait_until("failure counted", || relay.stats().failed == 1);
        let error = relay.stats().last_error.unwrap();
        assert!(error.contains("Nothing is listening") || error.contains("did not answer"));
    }

    #[test]
    fn targets_as_people_type_them() {
        let t = |s: &str| parse_target(s).map(|t| t.label());
        assert_eq!(t("5432").unwrap(), "127.0.0.1:5432");
        assert_eq!(t(" localhost:5432 ").unwrap(), "localhost:5432");
        assert_eq!(t("192.168.1.20:80").unwrap(), "192.168.1.20:80");
        assert_eq!(t("db.example:5432").unwrap(), "db.example:5432");
        assert_eq!(t("[::1]:8080").unwrap(), "[::1]:8080");
        assert_eq!(t("http://localhost:3000/").unwrap(), "localhost:3000");
        for bad in [
            "",
            "localhost",
            "localhost:",
            ":80",
            "host:0",
            "host:70000",
            "host:abc",
            "::1:80",
            "[::1]",
            "[::1:80",
            "bad name:80",
            "0",
        ] {
            assert!(parse_target(bad).is_err(), "{bad:?} should be refused");
        }
        assert!(parse_target("5432").unwrap().is_local());
        assert!(parse_target("LOCALHOST:1").unwrap().is_local());
        assert!(!parse_target("192.168.1.20:80").unwrap().is_local());
        // A port cannot be forwarded to itself.
        let own = Relay::start(47_113, false, parse_target("47113").unwrap(), None);
        assert!(own.err().unwrap().contains("to itself"));
    }
}
