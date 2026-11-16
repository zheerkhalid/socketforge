//! Invented data for `--demo` and the screenshots: a believable developer PC.
//! Nothing here comes from the real machine. The user is "Alex", the PC is
//! "DEVBOX", and every address is loopback, unspecified or from the ranges
//! reserved for documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
//! 2001:db8::/32).

use crate::diff::{EventKind, HistoryEvent};
use crate::model::{
    CollectorNote, Connection, DynamicRange, FirewallState, Forward, ForwardSource, FwProto,
    FwRule, HttpSysListener, Listener, PortProxy, PortRange, ProcInfo, Profiles, Proto, ServiceRef,
    SocketSnapshot, SystemInfo, TcpState, UrlReservation,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// The moment the demo pretends it is: 2026-11-16 09:41:00 UTC.
pub const NOW: i64 = 1_794_822_060;

/// This PC's invented address on the local network.
pub const LAN: &str = "192.0.2.10";

const SVCHOST: &str = "C:\\Windows\\System32\\svchost.exe";
const NODE: &str = "C:\\Program Files\\nodejs\\node.exe";
const DOCKER: &str = "C:\\Program Files\\Docker\\Docker\\resources\\com.docker.backend.exe";
const LAUNCHER: &str = "C:\\Program Files\\Nebula Games\\Launcher\\LauncherService.exe";
const USER: &str = "DEVBOX\\Alex";
const SYSTEM: &str = "NT AUTHORITY\\SYSTEM";
const NETWORK_SERVICE: &str = "NT AUTHORITY\\NETWORK SERVICE";
const LOCAL_SERVICE: &str = "NT AUTHORITY\\LOCAL SERVICE";

const MIN: i64 = 60;
const HOUR: i64 = 3600;
const DAY: i64 = 86_400;

/// The PID of the listener that has just appeared in the demo.
pub const NEW_PID: u32 = 12_644;
/// The PID of the listener that has just closed in the demo.
pub const CLOSED_PID: u32 = 11_872;

struct P {
    pid: u32,
    name: &'static str,
    path: &'static str,
    args: &'static str,
    user: &'static str,
    /// Seconds before [`NOW`].
    age: i64,
    parent: (u32, &'static str),
    services: &'static [(&'static str, &'static str)],
    description: &'static str,
    company: &'static str,
    system: bool,
}

const MS: &str = "Microsoft Corporation";
const HOST: &str = "Host Process for Windows Services";

const PROCS: &[P] = &[
    P {
        pid: 4,
        name: "System",
        path: "",
        args: "",
        user: SYSTEM,
        age: 3 * DAY + 4 * HOUR,
        parent: (0, "System Idle Process"),
        services: &[],
        description: "Windows kernel (file sharing, HTTP.sys)",
        company: MS,
        system: true,
    },
    P {
        pid: 932,
        name: "lsass.exe",
        path: "C:\\Windows\\System32\\lsass.exe",
        args: "",
        user: SYSTEM,
        age: 3 * DAY + 4 * HOUR,
        parent: (716, "wininit.exe"),
        services: &[
            ("KeyIso", "CNG Key Isolation"),
            ("SamSs", "Security Accounts Manager"),
        ],
        description: "Local Security Authority Process",
        company: MS,
        system: true,
    },
    P {
        pid: 1104,
        name: "svchost.exe",
        path: SVCHOST,
        args: "-k RPCSS -p",
        user: NETWORK_SERVICE,
        age: 3 * DAY + 4 * HOUR,
        parent: (880, "services.exe"),
        services: &[
            ("RpcEptMapper", "RPC Endpoint Mapper"),
            ("RpcSs", "Remote Procedure Call (RPC)"),
        ],
        description: HOST,
        company: MS,
        system: true,
    },
    P {
        pid: 1680,
        name: "svchost.exe",
        path: SVCHOST,
        args: "-k NetworkService -p -s Dnscache",
        user: NETWORK_SERVICE,
        age: 3 * DAY + 4 * HOUR,
        parent: (880, "services.exe"),
        services: &[("Dnscache", "DNS Client")],
        description: HOST,
        company: MS,
        system: true,
    },
    P {
        pid: 2312,
        name: "svchost.exe",
        path: SVCHOST,
        args: "-k LocalServiceAndNoImpersonation -p -s SSDPSRV",
        user: LOCAL_SERVICE,
        age: 3 * DAY + 4 * HOUR,
        parent: (880, "services.exe"),
        services: &[("SSDPSRV", "SSDP Discovery")],
        description: HOST,
        company: MS,
        system: true,
    },
    P {
        pid: 2476,
        name: "svchost.exe",
        path: SVCHOST,
        args: "-k NetworkService -s TermService",
        user: NETWORK_SERVICE,
        age: 3 * DAY + 4 * HOUR,
        parent: (880, "services.exe"),
        services: &[("TermService", "Remote Desktop Services")],
        description: HOST,
        company: MS,
        system: true,
    },
    P {
        pid: 3020,
        name: "svchost.exe",
        path: SVCHOST,
        args: "-k LocalService -p -s CDPSvc",
        user: LOCAL_SERVICE,
        age: 3 * DAY + 4 * HOUR - 2 * MIN,
        parent: (880, "services.exe"),
        services: &[("CDPSvc", "Connected Devices Platform Service")],
        description: HOST,
        company: MS,
        system: true,
    },
    P {
        pid: 3344,
        name: "svchost.exe",
        path: SVCHOST,
        args: "-k NetworkService -p -s DoSvc",
        user: NETWORK_SERVICE,
        age: 2 * DAY + 7 * HOUR,
        parent: (880, "services.exe"),
        services: &[("DoSvc", "Delivery Optimization")],
        description: HOST,
        company: MS,
        system: true,
    },
    P {
        pid: 3604,
        name: "svchost.exe",
        path: SVCHOST,
        args: "-k netsvcs -p -s IKEEXT",
        user: SYSTEM,
        age: 3 * DAY + 4 * HOUR,
        parent: (880, "services.exe"),
        services: &[
            ("IKEEXT", "IKE and AuthIP IPsec Keying Modules"),
            ("iphlpsvc", "IP Helper"),
        ],
        description: HOST,
        company: MS,
        system: true,
    },
    P {
        pid: 3888,
        name: "spoolsv.exe",
        path: "C:\\Windows\\System32\\spoolsv.exe",
        args: "",
        user: SYSTEM,
        age: 3 * DAY + 4 * HOUR,
        parent: (880, "services.exe"),
        services: &[("Spooler", "Print Spooler")],
        description: "Spooler SubSystem App",
        company: MS,
        system: true,
    },
    P {
        pid: 4188,
        name: "postgres.exe",
        path: "C:\\Program Files\\PostgreSQL\\17\\bin\\postgres.exe",
        args: "-D \"C:\\Program Files\\PostgreSQL\\17\\data\"",
        user: NETWORK_SERVICE,
        age: 3 * DAY + 4 * HOUR - 5 * MIN,
        parent: (4120, "pg_ctl.exe"),
        services: &[("postgresql-x64-17", "PostgreSQL Server 17")],
        description: "PostgreSQL Server",
        company: "PostgreSQL Global Development Group",
        system: false,
    },
    P {
        pid: 4420,
        name: "redis-server.exe",
        path: "C:\\Program Files\\Redis\\redis-server.exe",
        args: "--service-run \"C:\\Program Files\\Redis\\redis.conf\"",
        user: NETWORK_SERVICE,
        age: 3 * DAY + 4 * HOUR - 5 * MIN,
        parent: (880, "services.exe"),
        services: &[("Redis", "Redis")],
        description: "Redis in-memory data store",
        company: "Redis contributors",
        system: false,
    },
    P {
        pid: 5120,
        name: "node.exe",
        path: NODE,
        args: "C:\\Users\\Alex\\projects\\storefront\\node_modules\\vite\\bin\\vite.js --port 5173",
        user: USER,
        age: 2 * HOUR + 12 * MIN,
        parent: (9020, "pwsh.exe"),
        services: &[],
        description: "Node.js JavaScript Runtime",
        company: "Node.js",
        system: false,
    },
    P {
        pid: 5544,
        name: "nginx.exe",
        path: "C:\\tools\\nginx\\nginx.exe",
        args: "-c conf\\dev.conf",
        user: USER,
        age: 26 * HOUR,
        parent: (5508, "nginx.exe"),
        services: &[],
        description: "nginx web server",
        company: "nginx contributors",
        system: false,
    },
    P {
        pid: 6012,
        name: "com.docker.backend.exe",
        path: DOCKER,
        args: "run",
        user: USER,
        age: 5 * HOUR + 20 * MIN,
        parent: (5980, "Docker Desktop.exe"),
        services: &[],
        description: "Docker Desktop Backend",
        company: "Docker Inc.",
        system: false,
    },
    P {
        pid: 6240,
        name: "wslrelay.exe",
        path: "C:\\Program Files\\WSL\\wslrelay.exe",
        args: "--mode 2 --vm-id {7f3c0a52-0000-4000-8000-0000d0c5a11e}",
        user: USER,
        age: 5 * HOUR + 18 * MIN,
        parent: (6188, "wslservice.exe"),
        services: &[],
        description: "Windows Subsystem for Linux relay",
        company: MS,
        system: false,
    },
    P {
        pid: 7340,
        name: "node.exe",
        path: NODE,
        args: "--inspect=127.0.0.1:9229 C:\\Users\\Alex\\projects\\shop-api\\server.js",
        user: USER,
        age: 47 * MIN,
        parent: (9020, "pwsh.exe"),
        services: &[],
        description: "Node.js JavaScript Runtime",
        company: "Node.js",
        system: false,
    },
    P {
        pid: 7716,
        name: "w3wp.exe",
        path: "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
        args: "-ap \"DefaultAppPool\" -v \"v4.0\"",
        user: "IIS APPPOOL\\DefaultAppPool",
        age: 9 * HOUR,
        parent: (2960, "svchost.exe"),
        services: &[],
        description: "IIS Worker Process",
        company: MS,
        system: true,
    },
    P {
        pid: 8920,
        name: "LauncherService.exe",
        path: LAUNCHER,
        args: "--background",
        user: USER,
        age: 7 * HOUR + 3 * MIN,
        parent: (8876, "NebulaLauncher.exe"),
        services: &[],
        description: "Nebula Games Launcher",
        company: "Nebula Games",
        system: false,
    },
    P {
        pid: 9980,
        name: "firefox.exe",
        path: "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
        args: "",
        user: USER,
        age: 6 * HOUR + 40 * MIN,
        parent: (5300, "explorer.exe"),
        services: &[],
        description: "Firefox",
        company: "Mozilla Corporation",
        system: false,
    },
    P {
        pid: 10332,
        name: "Code.exe",
        path: "C:\\Users\\Alex\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
        args: "--type=utility --utility-sub-type=network.mojom.NetworkService",
        user: USER,
        age: 6 * HOUR + 31 * MIN,
        parent: (10280, "Code.exe"),
        services: &[],
        description: "Visual Studio Code",
        company: MS,
        system: false,
    },
    P {
        pid: 10904,
        name: "ssh.exe",
        path: "C:\\Windows\\System32\\OpenSSH\\ssh.exe",
        args: "git@git.example git-upload-pack 'alex/shop-api.git'",
        user: USER,
        age: 40,
        parent: (10860, "git.exe"),
        services: &[],
        description: "OpenSSH client",
        company: MS,
        system: false,
    },
    P {
        pid: CLOSED_PID,
        name: "caddy.exe",
        path: "C:\\tools\\caddy\\caddy.exe",
        args: "run --config C:\\Users\\Alex\\projects\\storefront\\Caddyfile",
        user: USER,
        age: 3 * HOUR + 2 * MIN,
        parent: (9020, "pwsh.exe"),
        services: &[],
        description: "Caddy web server",
        company: "Caddy contributors",
        system: false,
    },
    P {
        pid: NEW_PID,
        name: "sshd.exe",
        path: "C:\\Windows\\System32\\OpenSSH\\sshd.exe",
        args: "",
        user: SYSTEM,
        age: 2,
        parent: (880, "services.exe"),
        services: &[("sshd", "OpenSSH SSH Server")],
        description: "OpenSSH SSH Server",
        company: MS,
        system: true,
    },
];

fn proc_info(p: &P) -> ProcInfo {
    let cmdline = if p.path.is_empty() {
        String::new()
    } else if p.args.is_empty() {
        format!("\"{}\"", p.path)
    } else if p.path.contains(' ') {
        format!("\"{}\" {}", p.path, p.args)
    } else {
        format!("{} {}", p.path, p.args)
    };
    ProcInfo {
        pid: p.pid,
        name: p.name.to_string(),
        path: p.path.to_string(),
        cmdline,
        user: p.user.to_string(),
        started: Some(NOW - p.age),
        parent: Some(p.parent.0),
        parent_name: p.parent.1.to_string(),
        services: p
            .services
            .iter()
            .map(|(name, display)| ServiceRef {
                name: name.to_string(),
                display: display.to_string(),
            })
            .collect(),
        description: p.description.to_string(),
        company: p.company.to_string(),
        is_system: p.system,
        limited: false,
    }
}

use Proto::{Tcp, Udp};

/// `(protocol, address, port, pid, seconds since the socket was created)`.
const LISTENERS: &[(Proto, &str, u16, u32, i64)] = &[
    (Tcp, "0.0.0.0", 80, 4, 9 * HOUR),
    (Tcp, "::", 80, 4, 9 * HOUR),
    (Tcp, "0.0.0.0", 135, 1104, 3 * DAY + 4 * HOUR),
    (Tcp, "::", 135, 1104, 3 * DAY + 4 * HOUR),
    (Udp, LAN, 137, 4, 3 * DAY + 4 * HOUR),
    (Udp, LAN, 138, 4, 3 * DAY + 4 * HOUR),
    (Tcp, LAN, 139, 4, 3 * DAY + 4 * HOUR),
    (Tcp, "0.0.0.0", 445, 4, 3 * DAY + 4 * HOUR),
    (Tcp, "::", 445, 4, 3 * DAY + 4 * HOUR),
    (Udp, "0.0.0.0", 500, 3604, 3 * DAY + 4 * HOUR),
    (Udp, "0.0.0.0", 4500, 3604, 3 * DAY + 4 * HOUR),
    (Udp, LAN, 1900, 2312, 3 * DAY + 4 * HOUR),
    (Udp, "127.0.0.1", 1900, 2312, 3 * DAY + 4 * HOUR),
    (Tcp, "0.0.0.0", 2222, 3604, 4 * HOUR + 50 * MIN),
    (Tcp, "0.0.0.0", 3000, 7340, 47 * MIN),
    (Tcp, "0.0.0.0", 3389, 2476, 3 * DAY + 4 * HOUR),
    (Udp, "0.0.0.0", 3389, 2476, 3 * DAY + 4 * HOUR),
    (Tcp, "0.0.0.0", 5040, 3020, 3 * DAY + 4 * HOUR - 2 * MIN),
    (Udp, "0.0.0.0", 5050, 3020, 3 * DAY + 4 * HOUR - 2 * MIN),
    (Tcp, "127.0.0.1", 5173, 5120, 2 * HOUR + 12 * MIN),
    (Tcp, "::1", 5173, 5120, 2 * HOUR + 12 * MIN),
    (Udp, "0.0.0.0", 5353, 1680, 3 * DAY + 4 * HOUR),
    (Udp, "::", 5353, 1680, 3 * DAY + 4 * HOUR),
    (Udp, "0.0.0.0", 5355, 1680, 3 * DAY + 4 * HOUR),
    (Tcp, "0.0.0.0", 5357, 4, 3 * DAY + 4 * HOUR),
    (Tcp, "0.0.0.0", 5432, 4188, 3 * DAY + 4 * HOUR - 5 * MIN),
    (Tcp, "::", 5432, 4188, 3 * DAY + 4 * HOUR - 5 * MIN),
    (Tcp, "127.0.0.1", 5433, 6012, 5 * HOUR + 11 * MIN),
    (Tcp, "127.0.0.1", 6379, 4420, 3 * DAY + 4 * HOUR - 5 * MIN),
    (Tcp, "127.0.0.1", 6443, 6012, 5 * HOUR + 19 * MIN),
    (Tcp, "0.0.0.0", 7680, 3344, 2 * DAY + 7 * HOUR),
    (Tcp, "127.0.0.1", 8000, 6240, 3 * HOUR + 30 * MIN),
    (Tcp, "0.0.0.0", 8080, 6012, 5 * HOUR + 11 * MIN),
    (Tcp, "0.0.0.0", 8081, 5544, 26 * HOUR),
    (Tcp, "0.0.0.0", 8443, 5544, 26 * HOUR),
    (Tcp, "127.0.0.1", 9229, 7340, 47 * MIN),
    (Udp, "0.0.0.0", 27036, 8920, 7 * HOUR + 3 * MIN),
    (Tcp, "127.0.0.1", 27060, 8920, 7 * HOUR + 3 * MIN),
    (Tcp, "0.0.0.0", 49664, 932, 3 * DAY + 4 * HOUR),
    (Tcp, "0.0.0.0", 49668, 3888, 3 * DAY + 4 * HOUR),
];

/// The listener that appeared a moment ago.
const NEW_LISTENER: (Proto, &str, u16, u32, i64) = (Tcp, "0.0.0.0", 22, NEW_PID, 2);
/// The listener that closed a moment ago.
const CLOSED_LISTENER: (Proto, &str, u16, u32, i64) =
    (Tcp, "0.0.0.0", 443, CLOSED_PID, 3 * HOUR + 2 * MIN);

/// `(local, remote, state, pid, age in seconds)`.
const CONNECTIONS: &[(&str, &str, TcpState, u32, i64)] = &[
    (
        "192.0.2.10:3000",
        "192.0.2.44:61022",
        TcpState::Established,
        7340,
        95,
    ),
    (
        "192.0.2.10:3000",
        "192.0.2.44:61023",
        TcpState::Established,
        7340,
        94,
    ),
    (
        "127.0.0.1:52301",
        "127.0.0.1:5432",
        TcpState::Established,
        7340,
        46 * MIN,
    ),
    (
        "127.0.0.1:5432",
        "127.0.0.1:52301",
        TcpState::Established,
        4188,
        46 * MIN,
    ),
    (
        "127.0.0.1:52310",
        "127.0.0.1:6379",
        TcpState::Established,
        7340,
        46 * MIN,
    ),
    (
        "127.0.0.1:6379",
        "127.0.0.1:52310",
        TcpState::Established,
        4420,
        46 * MIN,
    ),
    (
        "192.0.2.10:52114",
        "203.0.113.25:443",
        TcpState::Established,
        7340,
        12,
    ),
    (
        "192.0.2.10:52440",
        "198.51.100.7:443",
        TcpState::Established,
        9980,
        9 * MIN,
    ),
    (
        "192.0.2.10:52441",
        "198.51.100.7:443",
        TcpState::Established,
        9980,
        9 * MIN,
    ),
    (
        "192.0.2.10:52467",
        "203.0.113.80:443",
        TcpState::Established,
        9980,
        3 * MIN,
    ),
    (
        "192.0.2.10:52390",
        "203.0.113.81:443",
        TcpState::TimeWait,
        9980,
        14 * MIN,
    ),
    (
        "127.0.0.1:52480",
        "127.0.0.1:5173",
        TcpState::Established,
        9980,
        2 * MIN,
    ),
    (
        "127.0.0.1:5173",
        "127.0.0.1:52480",
        TcpState::Established,
        5120,
        2 * MIN,
    ),
    (
        "[2001:db8::10]:52500",
        "[2001:db8:1::5]:443",
        TcpState::Established,
        9980,
        70,
    ),
    (
        "192.0.2.10:51877",
        "198.51.100.40:443",
        TcpState::Established,
        10332,
        2 * HOUR,
    ),
    (
        "192.0.2.10:52012",
        "203.0.113.9:443",
        TcpState::Established,
        6012,
        31 * MIN,
    ),
    (
        "192.0.2.10:51020",
        "198.51.100.77:443",
        TcpState::Established,
        8920,
        7 * HOUR,
    ),
    (
        "192.0.2.10:52510",
        "203.0.113.140:27017",
        TcpState::SynSent,
        8920,
        1,
    ),
    (
        "192.0.2.10:50844",
        "198.51.100.200:443",
        TcpState::Established,
        3020,
        26 * HOUR,
    ),
    (
        "192.0.2.10:52498",
        "203.0.113.61:22",
        TcpState::Established,
        10904,
        40,
    ),
    (
        "192.0.2.10:8080",
        "192.0.2.61:49822",
        TcpState::CloseWait,
        6012,
        6 * MIN,
    ),
    (
        "192.0.2.10:445",
        "192.0.2.31:50112",
        TcpState::Established,
        4,
        3 * HOUR,
    ),
];

/// Connections that appeared a moment ago.
const NEW_CONNECTIONS: &[(&str, &str, TcpState, u32, i64)] = &[
    (
        "192.0.2.10:22",
        "192.0.2.44:61090",
        TcpState::Established,
        NEW_PID,
        1,
    ),
    (
        "192.0.2.10:52515",
        "198.51.100.41:443",
        TcpState::Established,
        10332,
        1,
    ),
];
/// The connection that closed a moment ago.
const CLOSED_CONNECTION: (&str, &str, TcpState, u32, i64) = (
    "127.0.0.1:52433",
    "127.0.0.1:443",
    TcpState::Established,
    9980,
    11 * MIN,
);

fn listener(l: &(Proto, &str, u16, u32, i64)) -> Listener {
    Listener {
        proto: l.0,
        addr: l.1.parse().expect("demo address"),
        port: l.2,
        pid: l.3,
        created: Some(NOW - l.4),
    }
}

fn connection(c: &(&str, &str, TcpState, u32, i64)) -> Connection {
    Connection {
        local: c.0.parse::<SocketAddr>().expect("demo endpoint"),
        remote: c.1.parse::<SocketAddr>().expect("demo endpoint"),
        state: c.2,
        pid: c.3,
        created: Some(NOW - c.4),
    }
}

fn build(new: bool) -> SocketSnapshot {
    let mut snap = SocketSnapshot {
        taken: if new { NOW } else { NOW - 2 },
        ..Default::default()
    };
    snap.listeners = LISTENERS.iter().map(listener).collect();
    snap.connections = CONNECTIONS.iter().map(connection).collect();
    if new {
        snap.listeners.push(listener(&NEW_LISTENER));
        snap.connections
            .extend(NEW_CONNECTIONS.iter().map(connection));
    } else {
        snap.listeners.push(listener(&CLOSED_LISTENER));
        snap.connections.push(connection(&CLOSED_CONNECTION));
    }
    for p in PROCS {
        let gone = (new && p.pid == CLOSED_PID) || (!new && p.pid == NEW_PID);
        if !gone {
            snap.procs.insert(p.pid, proc_info(p));
        }
    }
    snap
}

/// What the demo PC is listening on right now.
pub fn snapshot() -> SocketSnapshot {
    build(true)
}

/// The refresh before [`snapshot`]: one listener and one connection that have
/// since closed, and without the ones that have just appeared. Feeding both to
/// the views makes the change highlighting visible.
pub fn previous_snapshot() -> SocketSnapshot {
    build(false)
}

/// Ports on the demo watch list.
pub fn watched_ports() -> Vec<u16> {
    vec![443, 3000, 5432, 8080, 9229]
}

#[allow(clippy::too_many_arguments)]
fn rule(
    name: &str,
    group: &str,
    enabled: bool,
    inbound: bool,
    allow: bool,
    proto: FwProto,
    local_ports: &str,
    program: &str,
    service: &str,
    profiles: Profiles,
) -> FwRule {
    FwRule {
        name: name.to_string(),
        group: group.to_string(),
        description: String::new(),
        enabled,
        inbound,
        allow,
        proto,
        local_ports: local_ports.to_string(),
        remote_ports: "*".to_string(),
        local_addrs: "*".to_string(),
        remote_addrs: "*".to_string(),
        program: program.to_string(),
        service: service.to_string(),
        profiles,
    }
}

fn firewall() -> FirewallState {
    let home = Profiles::PRIVATE.union(Profiles::DOMAIN);
    let all = Profiles::ALL;
    let fps = "File and Printer Sharing";
    let core = "Core Networking";
    let mut rules = vec![
        rule(
            "World Wide Web Services (HTTP Traffic-In)",
            "World Wide Web Services (HTTP)",
            true,
            true,
            true,
            FwProto::Tcp,
            "80",
            "System",
            "",
            all,
        ),
        rule(
            "File and Printer Sharing (SMB-In)",
            fps,
            true,
            true,
            true,
            FwProto::Tcp,
            "445",
            "System",
            "",
            home,
        ),
        rule(
            "File and Printer Sharing (NB-Session-In)",
            fps,
            true,
            true,
            true,
            FwProto::Tcp,
            "139",
            "System",
            "",
            home,
        ),
        rule(
            "File and Printer Sharing (NB-Name-In)",
            fps,
            true,
            true,
            true,
            FwProto::Udp,
            "137",
            "System",
            "",
            home,
        ),
        rule(
            "File and Printer Sharing (NB-Datagram-In)",
            fps,
            true,
            true,
            true,
            FwProto::Udp,
            "138",
            "System",
            "",
            home,
        ),
        rule(
            "Network Discovery (SSDP-In)",
            "Network Discovery",
            true,
            true,
            true,
            FwProto::Udp,
            "1900",
            SVCHOST,
            "SSDPSRV",
            Profiles::PRIVATE,
        ),
        rule(
            "Network Discovery (WSD Events-In)",
            "Network Discovery",
            true,
            true,
            true,
            FwProto::Tcp,
            "5357",
            "System",
            "",
            Profiles::PRIVATE,
        ),
        rule(
            "mDNS (UDP-In)",
            "mDNS",
            true,
            true,
            true,
            FwProto::Udp,
            "5353",
            SVCHOST,
            "Dnscache",
            all,
        ),
        rule(
            "Network Discovery (LLMNR-UDP-In)",
            "Network Discovery",
            true,
            true,
            true,
            FwProto::Udp,
            "5355",
            SVCHOST,
            "Dnscache",
            Profiles::PRIVATE,
        ),
        rule(
            "Remote Desktop - User Mode (TCP-In)",
            "Remote Desktop",
            false,
            true,
            true,
            FwProto::Tcp,
            "3389",
            SVCHOST,
            "TermService",
            all,
        ),
        rule(
            "Remote Desktop - User Mode (UDP-In)",
            "Remote Desktop",
            false,
            true,
            true,
            FwProto::Udp,
            "3389",
            SVCHOST,
            "TermService",
            all,
        ),
        rule(
            "Delivery Optimization (TCP-In)",
            "Delivery Optimization",
            true,
            true,
            true,
            FwProto::Tcp,
            "7680",
            SVCHOST,
            "DoSvc",
            all,
        ),
        rule(
            "Connected Devices Platform (TCP-In)",
            "Connected Devices Platform",
            true,
            true,
            true,
            FwProto::Tcp,
            "*",
            SVCHOST,
            "CDPSvc",
            home,
        ),
        rule(
            "Connected Devices Platform (UDP-In)",
            "Connected Devices Platform",
            true,
            true,
            true,
            FwProto::Udp,
            "*",
            SVCHOST,
            "CDPSvc",
            home,
        ),
        rule(
            "PostgreSQL 17 (TCP-In)",
            "",
            true,
            true,
            true,
            FwProto::Tcp,
            "5432",
            "",
            "",
            home,
        ),
        rule(
            "Node.js JavaScript Runtime",
            "",
            true,
            true,
            true,
            FwProto::Tcp,
            "*",
            NODE,
            "",
            Profiles::PRIVATE,
        ),
        rule(
            "Node.js JavaScript Runtime",
            "",
            true,
            true,
            false,
            FwProto::Tcp,
            "*",
            NODE,
            "",
            Profiles::PUBLIC,
        ),
        rule(
            "Docker Desktop Backend",
            "",
            true,
            true,
            true,
            FwProto::Tcp,
            "*",
            DOCKER,
            "",
            all,
        ),
        rule(
            "Nebula Games Launcher (UDP-In)",
            "",
            true,
            true,
            true,
            FwProto::Udp,
            "27031-27036",
            LAUNCHER,
            "",
            all,
        ),
        rule(
            "WSL ssh forward 2222",
            "",
            true,
            true,
            true,
            FwProto::Tcp,
            "2222",
            "",
            "",
            Profiles::PRIVATE,
        ),
        rule(
            "OpenSSH SSH Server (sshd)",
            "OpenSSH Server",
            true,
            true,
            true,
            FwProto::Tcp,
            "22",
            "C:\\Windows\\System32\\OpenSSH\\sshd.exe",
            "",
            Profiles::PRIVATE,
        ),
        rule(
            "Windows Remote Management (HTTP-In)",
            "Windows Remote Management",
            false,
            true,
            true,
            FwProto::Tcp,
            "5985",
            "System",
            "",
            home,
        ),
        rule(
            "Core Networking - IPHTTPS (TCP-In)",
            core,
            true,
            true,
            true,
            FwProto::Tcp,
            "IPHTTPS",
            "System",
            "",
            all,
        ),
        rule(
            "Core Networking - Dynamic Host Configuration Protocol (DHCP-In)",
            core,
            true,
            true,
            true,
            FwProto::Udp,
            "68",
            SVCHOST,
            "Dhcp",
            all,
        ),
        rule(
            "Block inbound Telnet",
            "",
            true,
            true,
            false,
            FwProto::Tcp,
            "23",
            "",
            "",
            all,
        ),
        rule(
            "Core Networking - DNS (UDP-Out)",
            core,
            true,
            false,
            true,
            FwProto::Udp,
            "*",
            SVCHOST,
            "Dnscache",
            all,
        ),
        rule(
            "Core Networking - Dynamic Host Configuration Protocol (DHCP-Out)",
            core,
            true,
            false,
            true,
            FwProto::Udp,
            "68",
            SVCHOST,
            "Dhcp",
            all,
        ),
        rule(
            "Firefox (C:\\Program Files\\Mozilla Firefox)",
            "",
            true,
            false,
            true,
            FwProto::Any,
            "*",
            "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
            "",
            all,
        ),
        rule(
            "Block Acme Updater telemetry",
            "",
            true,
            false,
            false,
            FwProto::Any,
            "*",
            "C:\\Program Files\\Acme Updater\\updater.exe",
            "",
            all,
        ),
    ];
    for r in rules.iter_mut().filter(|r| !r.inbound) {
        r.local_ports = "*".to_string();
    }
    rules[25].remote_ports = "53".to_string();
    rules[26].remote_ports = "67".to_string();
    rules[0].description =
        "An inbound rule to allow HTTP traffic for Internet Information Services (IIS).".into();
    FirewallState {
        available: true,
        error: None,
        enabled: Profiles::ALL,
        active: Profiles::PRIVATE,
        default_inbound_block: Profiles::ALL,
        rules,
    }
}

/// The slow-changing half of the demo PC.
pub fn system() -> SystemInfo {
    let range = |proto, start, end, administered| PortRange {
        proto,
        start,
        end,
        administered,
        v6: false,
    };
    let reservation = |url: &str, port: u16, accounts: &str| UrlReservation {
        url: url.to_string(),
        port: Some(port),
        accounts: accounts.to_string(),
    };
    let forward =
        |source, host_addr: &str, host_port, target: &str, target_port, detail: &str| Forward {
            source,
            proto: Tcp,
            host_addr: host_addr.to_string(),
            host_port,
            target: target.to_string(),
            target_port,
            detail: detail.to_string(),
        };
    let note = |name: &str, ok: bool, count: usize, detail: &str| CollectorNote {
        name: name.to_string(),
        ok,
        count,
        detail: detail.to_string(),
    };
    let firewall = firewall();
    let rule_count = firewall.rules.len();
    SystemInfo {
        taken: NOW - 20,
        firewall,
        excluded: vec![
            range(Tcp, 2869, 2869, true),
            range(Tcp, 5357, 5357, true),
            range(Tcp, 50000, 50059, false),
            range(Tcp, 50160, 50259, false),
            range(Tcp, 50360, 50459, false),
            range(Udp, 50000, 50059, false),
        ],
        dynamic: vec![
            DynamicRange {
                proto: Tcp,
                start: 49152,
                count: 16384,
            },
            DynamicRange {
                proto: Udp,
                start: 49152,
                count: 16384,
            },
        ],
        reservations: vec![
            reservation("http://+:80/Temporary_Listen_Addresses/", 80, "Everyone"),
            reservation(
                "http://+:5357/",
                5357,
                "NT AUTHORITY\\LOCAL SERVICE, NT AUTHORITY\\NETWORK SERVICE",
            ),
            reservation(
                "http://+:5985/wsman/",
                5985,
                "NT SERVICE\\WinRM, NT SERVICE\\Wecsvc",
            ),
            reservation(
                "https://+:5986/wsman/",
                5986,
                "NT SERVICE\\WinRM, NT SERVICE\\Wecsvc",
            ),
            reservation("http://+:8088/api/", 8088, "DEVBOX\\Alex"),
            reservation(
                "http://+:10246/MDEServer/",
                10246,
                "NT AUTHORITY\\Authenticated Users",
            ),
            reservation("http://*:2869/", 2869, "NT AUTHORITY\\LOCAL SERVICE"),
        ],
        http_listeners: vec![
            HttpSysListener {
                url: "http://+:80/".to_string(),
                port: Some(80),
                pids: vec![7716],
                queue: "DefaultAppPool".to_string(),
            },
            HttpSysListener {
                url: "http://+:80/docs/".to_string(),
                port: Some(80),
                pids: vec![7716],
                queue: "DefaultAppPool".to_string(),
            },
            HttpSysListener {
                url: "http://+:5357/b6c1d2e3-0000-4000-8000-00000000d0c5/".to_string(),
                port: Some(5357),
                pids: vec![2312],
                queue: "WSDAPI".to_string(),
            },
        ],
        portproxy: vec![
            PortProxy {
                kind: "v4tov4".to_string(),
                listen_addr: "0.0.0.0".to_string(),
                listen_port: 2222,
                connect_addr: "198.51.100.12".to_string(),
                connect_port: 22,
            },
            PortProxy {
                kind: "v4tov4".to_string(),
                listen_addr: "127.0.0.1".to_string(),
                listen_port: 9443,
                connect_addr: "198.51.100.12".to_string(),
                connect_port: 443,
            },
        ],
        forwards: vec![
            forward(
                ForwardSource::Docker,
                "0.0.0.0",
                8080,
                "storefront-web",
                80,
                "nginx:1.27-alpine",
            ),
            forward(
                ForwardSource::Docker,
                "127.0.0.1",
                5433,
                "storefront-db-test",
                5432,
                "postgres:17",
            ),
            forward(
                ForwardSource::Docker,
                "127.0.0.1",
                6443,
                "kubernetes",
                6443,
                "Docker Desktop Kubernetes API",
            ),
            forward(
                ForwardSource::Wsl,
                "127.0.0.1",
                8000,
                "Ubuntu-24.04",
                8000,
                "localhost forwarding (wslrelay)",
            ),
            forward(
                ForwardSource::HyperV,
                "0.0.0.0",
                3390,
                "Win11-Test",
                3389,
                "NAT static mapping on \"DevNat\"",
            ),
        ],
        notes: vec![
            note(
                "TCP and UDP tables",
                true,
                LISTENERS.len() + 1 + CONNECTIONS.len() + 2,
                "",
            ),
            note("Processes and services", true, PROCS.len() - 1, ""),
            note("Windows Firewall", true, rule_count, ""),
            note("Excluded and dynamic port ranges", true, 8, ""),
            note("HTTP.sys URL reservations", true, 7, ""),
            note(
                "HTTP.sys request queues",
                false,
                3,
                "Partly available: some request queues can only be read with administrator rights.",
            ),
            note("Port proxies", true, 2, ""),
            note("Docker", true, 3, "3 published ports from 3 containers."),
            note("WSL", true, 1, "1 distribution running."),
            note("Hyper-V NAT", true, 1, ""),
        ],
    }
}

/// The history log of the demo PC, oldest first.
pub fn history() -> Vec<HistoryEvent> {
    let ev = |ago: i64, kind, proto: Proto, addr: &str, port: u16, pid: u32, process: &str| {
        HistoryEvent {
            time: NOW - ago,
            kind,
            proto,
            addr: addr.to_string(),
            port,
            pid,
            process: process.to_string(),
            watched: watched_ports().contains(&port),
        }
    };
    use EventKind::{Closed, Opened};
    vec![
        ev(
            7 * HOUR + 3 * MIN,
            Opened,
            Udp,
            "0.0.0.0",
            27036,
            8920,
            "LauncherService.exe",
        ),
        ev(
            7 * HOUR + 3 * MIN,
            Opened,
            Tcp,
            "127.0.0.1",
            27060,
            8920,
            "LauncherService.exe",
        ),
        ev(
            5 * HOUR + 19 * MIN,
            Opened,
            Tcp,
            "127.0.0.1",
            6443,
            6012,
            "com.docker.backend.exe",
        ),
        ev(
            5 * HOUR + 11 * MIN,
            Opened,
            Tcp,
            "0.0.0.0",
            8080,
            6012,
            "com.docker.backend.exe",
        ),
        ev(
            5 * HOUR + 11 * MIN,
            Opened,
            Tcp,
            "127.0.0.1",
            5433,
            6012,
            "com.docker.backend.exe",
        ),
        ev(
            4 * HOUR + 50 * MIN,
            Opened,
            Tcp,
            "0.0.0.0",
            2222,
            3604,
            "svchost.exe",
        ),
        ev(
            3 * HOUR + 30 * MIN,
            Opened,
            Tcp,
            "127.0.0.1",
            8000,
            6240,
            "wslrelay.exe",
        ),
        ev(
            3 * HOUR + 2 * MIN,
            Opened,
            Tcp,
            "0.0.0.0",
            443,
            CLOSED_PID,
            "caddy.exe",
        ),
        ev(
            2 * HOUR + 12 * MIN,
            Opened,
            Tcp,
            "127.0.0.1",
            5173,
            5120,
            "node.exe",
        ),
        ev(
            2 * HOUR + 12 * MIN,
            Opened,
            Tcp,
            "::1",
            5173,
            5120,
            "node.exe",
        ),
        ev(58 * MIN, Closed, Tcp, "0.0.0.0", 3000, 6904, "node.exe"),
        ev(58 * MIN, Closed, Tcp, "127.0.0.1", 9229, 6904, "node.exe"),
        ev(47 * MIN, Opened, Tcp, "0.0.0.0", 3000, 7340, "node.exe"),
        ev(47 * MIN, Opened, Tcp, "127.0.0.1", 9229, 7340, "node.exe"),
        ev(21 * MIN, Opened, Udp, "0.0.0.0", 53124, 9980, "firefox.exe"),
        ev(20 * MIN, Closed, Udp, "0.0.0.0", 53124, 9980, "firefox.exe"),
        ev(2, Closed, Tcp, "0.0.0.0", 443, CLOSED_PID, "caddy.exe"),
        ev(0, Opened, Tcp, "0.0.0.0", 22, NEW_PID, "sshd.exe"),
    ]
}

/// Invented reverse-DNS names for the remote addresses of the demo.
pub fn reverse_names() -> HashMap<IpAddr, String> {
    [
        ("192.0.2.44", "alex-laptop.lan.test"),
        ("192.0.2.61", "tablet.lan.test"),
        ("192.0.2.31", "nas.lan.test"),
        ("203.0.113.25", "registry.packages.example"),
        ("198.51.100.7", "cdn.storefront.example"),
        ("203.0.113.80", "docs.framework.example"),
        ("203.0.113.81", "fonts.framework.example"),
        ("2001:db8:1::5", "api.search.example"),
        ("198.51.100.40", "marketplace.editor.example"),
        ("198.51.100.41", "update.editor.example"),
        ("203.0.113.9", "registry.containers.example"),
        ("198.51.100.77", "cdn.nebula-games.example"),
        ("198.51.100.200", "push.notify.example"),
        ("203.0.113.61", "git.example"),
    ]
    .into_iter()
    .map(|(ip, name)| (ip.parse().expect("demo address"), name.to_string()))
    .collect()
}

/// Is this one of the addresses the demo is allowed to show?
pub fn is_documentation_address(ip: &IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            matches!(
                (o[0], o[1], o[2]),
                (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
            )
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0x2001 && s[1] == 0x0db8
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exposure::Exposure;
    use crate::freeport::{self, PortContext, Verdict};
    use crate::view;
    use std::collections::HashSet;

    #[test]
    fn only_documentation_addresses() {
        for snap in [snapshot(), previous_snapshot()] {
            for l in &snap.listeners {
                assert!(is_documentation_address(&l.addr), "{}", l.addr);
            }
            for c in &snap.connections {
                assert!(is_documentation_address(&c.local.ip()), "{}", c.local);
                assert!(is_documentation_address(&c.remote.ip()), "{}", c.remote);
            }
        }
        for ip in reverse_names().keys() {
            assert!(is_documentation_address(ip));
        }
        for name in reverse_names().values() {
            assert!(
                name.ends_with(".example") || name.ends_with(".test"),
                "{name}"
            );
        }
        for e in history() {
            let ip: IpAddr = e.addr.parse().unwrap();
            assert!(is_documentation_address(&ip));
        }
        let sys = system();
        for p in &sys.portproxy {
            assert!(is_documentation_address(&p.listen_addr.parse().unwrap()));
            assert!(is_documentation_address(&p.connect_addr.parse().unwrap()));
        }
        for f in &sys.forwards {
            assert!(is_documentation_address(&f.host_addr.parse().unwrap()));
        }
    }

    #[test]
    fn no_real_user_or_machine_names() {
        let real_user = std::env::var("USERNAME").unwrap_or_default().to_lowercase();
        let real_pc = std::env::var("COMPUTERNAME")
            .unwrap_or_default()
            .to_lowercase();
        let mut text = String::new();
        for p in snapshot().procs.values() {
            text.push_str(&format!("{p:?}\n"));
            if p.path.to_lowercase().contains("\\users\\") {
                assert!(p.path.contains("\\Users\\Alex\\"), "{}", p.path);
            }
            assert!(
                p.user.starts_with("DEVBOX\\Alex")
                    || p.user.starts_with("NT AUTHORITY\\")
                    || p.user.starts_with("IIS APPPOOL\\"),
                "{}",
                p.user
            );
        }
        text.push_str(&format!("{:?}", system()));
        let text = text.to_lowercase();
        for real in [real_user, real_pc] {
            // Short or generic names would match by accident.
            if real.len() >= 4 && real != "alex" && real != "devbox" && real != "system" {
                assert!(!text.contains(&real), "demo data mentions a real name");
            }
        }
    }

    #[test]
    fn every_socket_has_a_process() {
        for snap in [snapshot(), previous_snapshot()] {
            for l in &snap.listeners {
                assert!(snap.procs.contains_key(&l.pid), "listener pid {}", l.pid);
            }
            for c in &snap.connections {
                assert!(snap.procs.contains_key(&c.pid), "connection pid {}", c.pid);
            }
            let keys: HashSet<_> = snap.listeners.iter().map(|l| l.key()).collect();
            assert_eq!(keys.len(), snap.listeners.len(), "duplicate listener");
            let keys: HashSet<_> = snap.connections.iter().map(|c| c.key()).collect();
            assert_eq!(keys.len(), snap.connections.len(), "duplicate connection");
        }
    }

    #[test]
    fn one_new_and_one_closed_row() {
        let (old, new) = (previous_snapshot(), snapshot());
        let events = crate::diff::listener_events(&old, &new, &watched_ports());
        assert_eq!(events.len(), 2);
        assert!(events
            .iter()
            .any(|e| e.kind == EventKind::Opened && e.port == 22));
        assert!(events
            .iter()
            .any(|e| e.kind == EventKind::Closed && e.port == 443 && e.watched));
    }

    #[test]
    fn exposure_badges_are_mixed() {
        let rows = view::listener_rows(&snapshot(), &system());
        let has = |f: &dyn Fn(&Exposure) -> bool| rows.iter().any(|r| f(&r.exposure.exposure));
        assert!(has(&|e| *e == Exposure::LoopbackOnly));
        assert!(has(&|e| *e == Exposure::Blocked));
        assert!(has(&|e| *e == Exposure::Allowed(Profiles::ALL)));
        assert!(has(&|e| *e == Exposure::Allowed(Profiles::PRIVATE)));
        let port = |n: u16| rows.iter().find(|r| r.listener.port == n).unwrap();
        assert_eq!(port(8443).exposure.exposure, Exposure::Blocked);
        assert_eq!(port(3389).exposure.exposure, Exposure::Blocked);
        assert_eq!(
            port(8080).exposure.exposure,
            Exposure::Allowed(Profiles::ALL)
        );
        assert_eq!(
            port(3000).exposure.exposure,
            Exposure::Allowed(Profiles::PRIVATE)
        );
        assert_eq!(port(80).exposure.exposure, Exposure::Allowed(Profiles::ALL));
    }

    #[test]
    fn port_check_examples() {
        let (snap, sys) = (snapshot(), system());
        let ctx = PortContext::new(&snap, &sys);
        let r = freeport::check(80, Tcp, &ctx);
        assert_eq!(r.verdict, Verdict::InUse);
        assert!(r.notes.len() >= 2);
        let r = freeport::check(50010, Tcp, &ctx);
        assert_eq!(r.verdict, Verdict::Reserved);
        assert_eq!(freeport::check(3001, Tcp, &ctx).verdict, Verdict::Free);
        assert_eq!(freeport::next_free(3000, Tcp, &ctx), Some(3001));
    }

    #[test]
    fn history_is_in_time_order() {
        let h = history();
        assert!(h.windows(2).all(|w| w[0].time <= w[1].time));
        assert!(h.iter().any(|e| e.watched));
    }
}
