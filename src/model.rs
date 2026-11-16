//! Shared data types: what the collectors produce and what the views show.
//!
//! This file is the contract between the collectors (`collect`), the pure logic
//! (`exposure`, `freeport`, `diff`, `export`, `cli`) and the user interface.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn label(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
        }
    }
}

/// Which interfaces a socket is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Scope {
    /// `0.0.0.0` or `::`: every interface.
    AllInterfaces,
    /// `127.0.0.0/8` or `::1`: this PC only.
    Loopback,
    /// One specific address of this PC.
    Specific,
}

pub fn scope_of(addr: &IpAddr) -> Scope {
    if addr.is_unspecified() {
        Scope::AllInterfaces
    } else if addr.is_loopback() {
        Scope::Loopback
    } else {
        Scope::Specific
    }
}

/// A listening TCP socket or a bound UDP socket.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Listener {
    pub proto: Proto,
    pub addr: IpAddr,
    pub port: u16,
    pub pid: u32,
    /// When the socket was created (Unix seconds, UTC), if Windows reports it.
    pub created: Option<i64>,
}

impl Listener {
    pub fn is_v6(&self) -> bool {
        self.addr.is_ipv6()
    }
    pub fn scope(&self) -> Scope {
        scope_of(&self.addr)
    }
    /// Identity of a listener across refreshes.
    pub fn key(&self) -> ListenerKey {
        (self.proto, self.addr, self.port, self.pid)
    }
    /// `127.0.0.1:3000` / `[::1]:3000`.
    pub fn endpoint(&self) -> String {
        SocketAddr::new(self.addr, self.port).to_string()
    }
}

pub type ListenerKey = (Proto, IpAddr, u16, u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown,
}

impl TcpState {
    /// From the `MIB_TCP_STATE` number (1 = closed ... 12 = delete TCB).
    pub fn from_mib(n: u32) -> TcpState {
        match n {
            1 => TcpState::Closed,
            2 => TcpState::Listen,
            3 => TcpState::SynSent,
            4 => TcpState::SynReceived,
            5 => TcpState::Established,
            6 => TcpState::FinWait1,
            7 => TcpState::FinWait2,
            8 => TcpState::CloseWait,
            9 => TcpState::Closing,
            10 => TcpState::LastAck,
            11 => TcpState::TimeWait,
            12 => TcpState::DeleteTcb,
            _ => TcpState::Unknown,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            TcpState::Closed => "Closed",
            TcpState::Listen => "Listening",
            TcpState::SynSent => "Connecting",
            TcpState::SynReceived => "Accepting",
            TcpState::Established => "Established",
            TcpState::FinWait1 => "Closing (FIN wait 1)",
            TcpState::FinWait2 => "Closing (FIN wait 2)",
            TcpState::CloseWait => "Close wait",
            TcpState::Closing => "Closing",
            TcpState::LastAck => "Last ACK",
            TcpState::TimeWait => "Time wait",
            TcpState::DeleteTcb => "Deleted",
            TcpState::Unknown => "Unknown",
        }
    }
}

/// An active TCP connection (anything in the TCP table that is not listening).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Connection {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: TcpState,
    pub pid: u32,
    pub created: Option<i64>,
}

pub type ConnectionKey = (SocketAddr, SocketAddr, u32);

impl Connection {
    pub fn key(&self) -> ConnectionKey {
        (self.local, self.remote, self.pid)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRef {
    /// Short service name, e.g. `Dnscache`.
    pub name: String,
    /// Display name, e.g. `DNS Client`.
    pub display: String,
}

/// What is known about a process that owns a socket.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcInfo {
    pub pid: u32,
    /// Image name, e.g. `node.exe`. `System` for PID 4, `System Idle Process` for 0.
    pub name: String,
    /// Full path of the executable; empty when access was denied.
    pub path: String,
    /// Full command line; empty when it could not be read.
    pub cmdline: String,
    /// `DOMAIN\user`; empty when it could not be read.
    pub user: String,
    /// Start time (Unix seconds, UTC).
    pub started: Option<i64>,
    pub parent: Option<u32>,
    pub parent_name: String,
    /// Windows services hosted by this process (svchost and friends).
    pub services: Vec<ServiceRef>,
    /// File description from the version resource, e.g. `Node.js JavaScript Runtime`.
    pub description: String,
    /// Company name from the version resource.
    pub company: String,
    /// True for Windows' own processes: PID 0/4, services running as SYSTEM /
    /// LOCAL SERVICE / NETWORK SERVICE, anything under `%SystemRoot%`.
    pub is_system: bool,
    /// Details were limited because this process needs administrator rights to inspect.
    pub limited: bool,
}

impl ProcInfo {
    /// Name shown in lists: the image name, or `PID n` when even that is unknown.
    pub fn display_name(&self) -> String {
        if self.name.is_empty() {
            format!("PID {}", self.pid)
        } else {
            self.name.clone()
        }
    }
}

/// Fast-changing data: refreshed every few seconds.
#[derive(Clone, Debug, Default)]
pub struct SocketSnapshot {
    /// When it was taken (Unix seconds, UTC).
    pub taken: i64,
    pub listeners: Vec<Listener>,
    pub connections: Vec<Connection>,
    pub procs: HashMap<u32, ProcInfo>,
    /// Problems worth showing ("TCP table unavailable: ...").
    pub errors: Vec<String>,
}

impl SocketSnapshot {
    pub fn proc_of(&self, pid: u32) -> Option<&ProcInfo> {
        self.procs.get(&pid)
    }
    pub fn proc_name(&self, pid: u32) -> String {
        self.procs
            .get(&pid)
            .map(|p| p.display_name())
            .unwrap_or_else(|| format!("PID {pid}"))
    }
}

/// Firewall profiles as a bit set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Profiles(pub u8);

impl Profiles {
    pub const NONE: Profiles = Profiles(0);
    pub const DOMAIN: Profiles = Profiles(1);
    pub const PRIVATE: Profiles = Profiles(2);
    pub const PUBLIC: Profiles = Profiles(4);
    pub const ALL: Profiles = Profiles(7);

    pub fn contains(self, other: Profiles) -> bool {
        self.0 & other.0 == other.0
    }
    pub fn intersects(self, other: Profiles) -> bool {
        self.0 & other.0 != 0
    }
    pub fn union(self, other: Profiles) -> Profiles {
        Profiles(self.0 | other.0)
    }
    pub fn is_empty(self) -> bool {
        self.0 & 7 == 0
    }
    /// `Private, Public` / `All profiles` / `None`.
    pub fn label(self) -> String {
        match self.0 & 7 {
            0 => "None".to_string(),
            7 => "All profiles".to_string(),
            n => {
                let mut parts = Vec::new();
                if n & 1 != 0 {
                    parts.push("Domain");
                }
                if n & 2 != 0 {
                    parts.push("Private");
                }
                if n & 4 != 0 {
                    parts.push("Public");
                }
                parts.join(", ")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FwProto {
    Any,
    Tcp,
    Udp,
    /// Another IP protocol number (ICMP = 1, ICMPv6 = 58, ...).
    Other(i32),
}

impl FwProto {
    /// From the IANA protocol number used by the firewall API (256 = any).
    pub fn from_number(n: i32) -> FwProto {
        match n {
            6 => FwProto::Tcp,
            17 => FwProto::Udp,
            256 => FwProto::Any,
            n => FwProto::Other(n),
        }
    }
    pub fn matches(self, proto: Proto) -> bool {
        matches!(
            (self, proto),
            (FwProto::Any, _) | (FwProto::Tcp, Proto::Tcp) | (FwProto::Udp, Proto::Udp)
        )
    }
    pub fn label(self) -> String {
        match self {
            FwProto::Any => "Any".into(),
            FwProto::Tcp => "TCP".into(),
            FwProto::Udp => "UDP".into(),
            FwProto::Other(1) => "ICMPv4".into(),
            FwProto::Other(58) => "ICMPv6".into(),
            FwProto::Other(n) => format!("Protocol {n}"),
        }
    }
}

/// One Windows Firewall rule (read-only).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FwRule {
    pub name: String,
    pub group: String,
    pub description: String,
    pub enabled: bool,
    /// true = inbound, false = outbound.
    pub inbound: bool,
    /// true = allow, false = block.
    pub allow: bool,
    pub proto: FwProto,
    /// As the firewall stores it: `*`, empty, `80,443`, `5000-5010`, or a keyword
    /// such as `RPC`, `RPC-EPMap`, `IPHTTPS`, `Teredo`, `Ply2Disc`.
    pub local_ports: String,
    pub remote_ports: String,
    /// `*` or empty = any address; otherwise a list as the firewall stores it.
    pub local_addrs: String,
    pub remote_addrs: String,
    /// Full program path with environment variables expanded; empty = any program.
    pub program: String,
    /// Service short name; `*` = any service; empty = not restricted to services.
    pub service: String,
    pub profiles: Profiles,
}

/// The state of Windows Firewall plus its rules.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FirewallState {
    /// False when the firewall API could not be read at all (see `error`).
    pub available: bool,
    pub error: Option<String>,
    /// Profiles on which the firewall is switched on.
    pub enabled: Profiles,
    /// Profiles that are active on a network right now.
    pub active: Profiles,
    /// Profiles whose default for unmatched inbound traffic is "block" (the normal case).
    pub default_inbound_block: Profiles,
    pub rules: Vec<FwRule>,
}

/// A range of ports nobody can bind (`netsh int ipv4 show excludedportrange`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub proto: Proto,
    pub start: u16,
    /// Inclusive.
    pub end: u16,
    /// Marked with `*` by Windows: an administered (persistent) exclusion.
    pub administered: bool,
    pub v6: bool,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        (self.start..=self.end).contains(&port)
    }
}

/// The range Windows hands out for outgoing connections (ephemeral ports).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicRange {
    pub proto: Proto,
    pub start: u16,
    pub count: u32,
}

impl DynamicRange {
    pub fn contains(&self, port: u16) -> bool {
        let p = port as u32;
        p >= self.start as u32 && p < self.start as u32 + self.count
    }
}

/// An HTTP.sys URL reservation (`netsh http show urlacl`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlReservation {
    /// e.g. `http://+:8080/app/`
    pub url: String,
    pub port: Option<u16>,
    /// Who may listen: account names where they resolve, else the SDDL string.
    pub accounts: String,
}

/// A URL that HTTP.sys is serving right now on behalf of a process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpSysListener {
    pub url: String,
    pub port: Option<u16>,
    /// Processes attached to the request queue.
    pub pids: Vec<u32>,
    pub queue: String,
}

/// A `netsh interface portproxy` rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortProxy {
    /// `v4tov4`, `v4tov6`, `v6tov4`, `v6tov6`.
    pub kind: String,
    pub listen_addr: String,
    pub listen_port: u16,
    pub connect_addr: String,
    pub connect_port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ForwardSource {
    Docker,
    Wsl,
    HyperV,
}

impl ForwardSource {
    pub fn label(self) -> &'static str {
        match self {
            ForwardSource::Docker => "Docker",
            ForwardSource::Wsl => "WSL",
            ForwardSource::HyperV => "Hyper-V",
        }
    }
}

/// A port on this PC that is forwarded into a container or virtual machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Forward {
    pub source: ForwardSource,
    pub proto: Proto,
    /// Address on this PC (`0.0.0.0`, `127.0.0.1`, ...). Empty when unknown.
    pub host_addr: String,
    pub host_port: u16,
    /// Container name, distribution name or VM name.
    pub target: String,
    /// Port inside the target; 0 when it is the same or unknown.
    pub target_port: u16,
    /// Anything else worth showing (image name, NAT name).
    pub detail: String,
}

/// How one collector went: shown in Settings/diagnostics and in the report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorNote {
    pub name: String,
    pub ok: bool,
    pub count: usize,
    /// Short human explanation when not ok or when partially available.
    pub detail: String,
}

/// Slow-changing data: refreshed on demand and every minute or so.
#[derive(Clone, Debug, Default)]
pub struct SystemInfo {
    pub taken: i64,
    pub firewall: FirewallState,
    pub excluded: Vec<PortRange>,
    pub dynamic: Vec<DynamicRange>,
    pub reservations: Vec<UrlReservation>,
    pub http_listeners: Vec<HttpSysListener>,
    pub portproxy: Vec<PortProxy>,
    pub forwards: Vec<Forward>,
    pub notes: Vec<CollectorNote>,
}

/// Seconds since the Unix epoch, UTC.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_and_endpoints() {
        let l = |a: &str| Listener {
            proto: Proto::Tcp,
            addr: a.parse().unwrap(),
            port: 3000,
            pid: 1,
            created: None,
        };
        assert_eq!(l("0.0.0.0").scope(), Scope::AllInterfaces);
        assert_eq!(l("::").scope(), Scope::AllInterfaces);
        assert_eq!(l("127.0.0.1").scope(), Scope::Loopback);
        assert_eq!(l("127.0.0.53").scope(), Scope::Loopback);
        assert_eq!(l("::1").scope(), Scope::Loopback);
        assert_eq!(l("192.168.1.20").scope(), Scope::Specific);
        assert_eq!(l("::1").endpoint(), "[::1]:3000");
        assert_eq!(l("127.0.0.1").endpoint(), "127.0.0.1:3000");
        assert!(l("fe80::1").is_v6());
    }

    #[test]
    fn profile_labels() {
        assert_eq!(Profiles::ALL.label(), "All profiles");
        assert_eq!(Profiles::NONE.label(), "None");
        assert_eq!(
            Profiles::PRIVATE.union(Profiles::PUBLIC).label(),
            "Private, Public"
        );
        assert!(Profiles::ALL.contains(Profiles::DOMAIN));
        assert!(!Profiles::PRIVATE.intersects(Profiles::PUBLIC));
    }

    #[test]
    fn dynamic_range_edges() {
        let d = DynamicRange {
            proto: Proto::Tcp,
            start: 49152,
            count: 16384,
        };
        assert!(d.contains(49152) && d.contains(65535) && !d.contains(49151));
    }
}
