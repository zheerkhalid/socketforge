//! "Is this port free?" and "why can't I bind it?": pure logic over a snapshot,
//! plus an optional real bind test on the loopback address.

use crate::model::{
    DynamicRange, HttpSysListener, Listener, PortRange, Proto, SocketSnapshot, SystemInfo,
    UrlReservation,
};
use crate::ports;

/// Everything that can stand in the way of binding a port.
#[derive(Clone, Copy, Default)]
pub struct PortContext<'a> {
    pub listeners: &'a [Listener],
    pub excluded: &'a [PortRange],
    pub dynamic: &'a [DynamicRange],
    pub reservations: &'a [UrlReservation],
    pub http_listeners: &'a [HttpSysListener],
}

impl<'a> PortContext<'a> {
    pub fn new(snap: &'a SocketSnapshot, sys: &'a SystemInfo) -> PortContext<'a> {
        PortContext {
            listeners: &snap.listeners,
            excluded: &sys.excluded,
            dynamic: &sys.dynamic,
            reservations: &sys.reservations,
            http_listeners: &sys.http_listeners,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing listens and nothing reserves it.
    Free,
    /// Nothing listens, but there is something to know (URL reservation, dynamic range).
    FreeWithNotes,
    /// A process is listening on it.
    InUse,
    /// Nothing listens, yet Windows will refuse the bind (excluded range).
    Reserved,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortReport {
    pub port: u16,
    pub proto: Proto,
    pub verdict: Verdict,
    /// Indices into `PortContext::listeners`.
    pub users: Vec<usize>,
    pub excluded: Option<PortRange>,
    /// URL reservations on this port (TCP only).
    pub reserved_urls: Vec<String>,
    /// URLs HTTP.sys serves on this port right now.
    pub http_urls: Vec<String>,
    pub in_dynamic_range: bool,
    /// IANA-style name of the service usually found here.
    pub well_known: Option<&'static str>,
    /// Plain-language explanation, one sentence per item.
    pub notes: Vec<String>,
}

impl PortReport {
    pub fn is_bindable(&self) -> bool {
        matches!(self.verdict, Verdict::Free | Verdict::FreeWithNotes)
    }

    pub fn headline(&self) -> String {
        let p = format!("{} port {}", self.proto.label(), self.port);
        match self.verdict {
            Verdict::Free => format!("{p} is free"),
            Verdict::FreeWithNotes => format!("{p} is free, with notes"),
            Verdict::InUse => format!("{p} is in use"),
            Verdict::Reserved => format!("{p} is reserved by Windows"),
        }
    }
}

/// Checks one port.
pub fn check(port: u16, proto: Proto, ctx: &PortContext) -> PortReport {
    let users: Vec<usize> = ctx
        .listeners
        .iter()
        .enumerate()
        .filter(|(_, l)| l.proto == proto && l.port == port)
        .map(|(i, _)| i)
        .collect();
    let excluded = ctx
        .excluded
        .iter()
        .find(|r| r.proto == proto && r.contains(port))
        .copied();
    let (reserved_urls, http_urls) = if proto == Proto::Tcp {
        (
            ctx.reservations
                .iter()
                .filter(|r| r.port == Some(port))
                .map(|r| r.url.clone())
                .collect::<Vec<_>>(),
            ctx.http_listeners
                .iter()
                .filter(|r| r.port == Some(port))
                .map(|r| r.url.clone())
                .collect::<Vec<_>>(),
        )
    } else {
        (Vec::new(), Vec::new())
    };
    let in_dynamic_range = ctx
        .dynamic
        .iter()
        .any(|d| d.proto == proto && d.contains(port));
    let well_known = ports::service_name(port, proto);

    let mut notes = Vec::new();
    if port == 0 {
        notes.push(
            "Port 0 is not a real port: binding it asks Windows to pick any free port.".to_string(),
        );
    }
    if !users.is_empty() {
        let scopes: Vec<String> = users
            .iter()
            .map(|&i| ctx.listeners[i].addr.to_string())
            .collect();
        notes.push(format!(
            "{} socket{} bound to it (on {}). A second program can only bind it on a different \
             address, and not at all if the first one bound every interface exclusively.",
            users.len(),
            if users.len() == 1 { " is" } else { "s are" },
            scopes.join(", ")
        ));
    }
    if let Some(r) = excluded {
        notes.push(format!(
            "It lies in the excluded range {}-{}{}. Windows refuses every bind in that range with \
             \"access denied\" (WSAEACCES, error 10013) even though nothing is listening. Hyper-V, \
             WSL and Docker reserve such ranges; they can change after a restart.",
            r.start,
            r.end,
            if r.administered {
                " (set by an administrator)"
            } else {
                ""
            }
        ));
    }
    if !http_urls.is_empty() {
        notes.push(format!(
            "The Windows HTTP service (HTTP.sys, shown as the System process) is serving {} here. \
             Programs that use HTTP.sys can share the port; an ordinary socket bind fails.",
            http_urls.join(", ")
        ));
    }
    if !reserved_urls.is_empty() {
        notes.push(format!(
            "URL reservation{}: {}. This matters only to programs that listen through HTTP.sys; \
             without a matching reservation they need administrator rights. Ordinary sockets are \
             not affected.",
            if reserved_urls.len() == 1 { "" } else { "s" },
            reserved_urls.join(", ")
        ));
    }
    if in_dynamic_range && users.is_empty() && excluded.is_none() {
        notes.push(
            "It is inside the dynamic (ephemeral) range that Windows hands out for outgoing \
             connections, so it can be taken at any moment. Prefer a port below that range for a \
             server."
                .to_string(),
        );
    }
    if port != 0 && port < 1024 && users.is_empty() && excluded.is_none() {
        notes.push(
            "Ports below 1024 are the classic \"well-known\" ports. Windows does not require \
             administrator rights to bind them, but other systems do."
                .to_string(),
        );
    }
    if let Some(name) = well_known {
        if users.is_empty() {
            notes.push(format!("Commonly used by: {name}."));
        }
    }

    let verdict = if !users.is_empty() || !http_urls.is_empty() {
        Verdict::InUse
    } else if excluded.is_some() {
        Verdict::Reserved
    } else if !reserved_urls.is_empty() || in_dynamic_range || port == 0 {
        Verdict::FreeWithNotes
    } else {
        Verdict::Free
    };
    PortReport {
        port,
        proto,
        verdict,
        users,
        excluded,
        reserved_urls,
        http_urls,
        in_dynamic_range,
        well_known,
        notes,
    }
}

/// Is the port clean for a server: nobody listens, not excluded, not in the dynamic range?
fn is_clean(port: u16, proto: Proto, ctx: &PortContext) -> bool {
    port != 0
        && !ctx
            .listeners
            .iter()
            .any(|l| l.proto == proto && l.port == port)
        && !ctx
            .excluded
            .iter()
            .any(|r| r.proto == proto && r.contains(port))
        && !(proto == Proto::Tcp && ctx.http_listeners.iter().any(|h| h.port == Some(port)))
}

/// The first free port at or after `from`.
pub fn next_free(from: u16, proto: Proto, ctx: &PortContext) -> Option<u16> {
    (from.max(1)..=u16::MAX).find(|&p| is_clean(p, proto, ctx))
}

/// Up to `limit` free ports in `start..=end`.
pub fn free_in_range(
    start: u16,
    end: u16,
    proto: Proto,
    ctx: &PortContext,
    limit: usize,
) -> Vec<u16> {
    let (a, b) = if start <= end {
        (start, end)
    } else {
        (end, start)
    };
    (a.max(1)..=b)
        .filter(|&p| is_clean(p, proto, ctx))
        .take(limit)
        .collect()
}

/// The first run of `len` consecutive free ports at or after `from`.
pub fn next_free_block(from: u16, len: u16, proto: Proto, ctx: &PortContext) -> Option<u16> {
    let len = len.max(1) as u32;
    let mut start = from.max(1) as u32;
    let mut run = 0u32;
    let mut p = start;
    while p <= u16::MAX as u32 {
        if is_clean(p as u16, proto, ctx) {
            if run == 0 {
                start = p;
            }
            run += 1;
            if run == len {
                return Some(start as u16);
            }
        } else {
            run = 0;
        }
        p += 1;
    }
    None
}

/// Parses `3000, 8000-8010 5432` into individual ports (order kept, duplicates
/// removed, at most 4096 ports).
pub fn parse_port_list(text: &str) -> Result<Vec<u16>, String> {
    let mut out: Vec<u16> = Vec::new();
    let push = |p: u16, out: &mut Vec<u16>| {
        if !out.contains(&p) {
            out.push(p);
        }
    };
    for part in text
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|s| !s.is_empty())
    {
        let bad = || format!("\"{part}\" is not a port (1-65535) or a range such as 8000-8010.");
        match part.split_once('-') {
            Some((a, b)) => {
                let a: u16 = a.trim().parse().map_err(|_| bad())?;
                let b: u16 = b.trim().parse().map_err(|_| bad())?;
                let (a, b) = if a <= b { (a, b) } else { (b, a) };
                if (b - a) as usize + out.len() >= 4096 {
                    return Err("That is too many ports at once (4096 at most).".to_string());
                }
                for p in a..=b {
                    push(p, &mut out);
                }
            }
            None => push(part.parse().map_err(|_| bad())?, &mut out),
        }
    }
    if out.is_empty() {
        return Err("Type one or more port numbers.".to_string());
    }
    Ok(out)
}

/// Outcome of really trying to bind `127.0.0.1:port` for a moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindTest {
    Ok,
    /// WSAEADDRINUSE (10048)
    InUse,
    /// WSAEACCES (10013): excluded range or exclusive use.
    Denied,
    Other(String),
}

impl BindTest {
    pub fn label(&self) -> String {
        match self {
            BindTest::Ok => "A test bind on 127.0.0.1 succeeded.".into(),
            BindTest::InUse => {
                "A test bind on 127.0.0.1 failed: the address is already in use (10048).".into()
            }
            BindTest::Denied => "A test bind on 127.0.0.1 failed: access denied (10013). The port \
                 is excluded or held exclusively."
                .into(),
            BindTest::Other(e) => format!("A test bind on 127.0.0.1 failed: {e}"),
        }
    }
}

/// Binds the loopback address on `port` and lets go immediately. Nothing is
/// accepted and nothing leaves the PC.
pub fn bind_test(port: u16, proto: Proto) -> BindTest {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let result = match proto {
        Proto::Tcp => std::net::TcpListener::bind(addr).map(|_| ()),
        Proto::Udp => std::net::UdpSocket::bind(addr).map(|_| ()),
    };
    match result {
        Ok(()) => BindTest::Ok,
        Err(e) => match e.raw_os_error() {
            Some(10048) => BindTest::InUse,
            Some(10013) => BindTest::Denied,
            _ => BindTest::Other(e.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l(proto: Proto, addr: &str, port: u16) -> Listener {
        Listener {
            proto,
            addr: addr.parse().unwrap(),
            port,
            pid: 10,
            created: None,
        }
    }

    fn range(start: u16, end: u16) -> PortRange {
        PortRange {
            proto: Proto::Tcp,
            start,
            end,
            administered: false,
            v6: false,
        }
    }

    struct Fixture {
        listeners: Vec<Listener>,
        excluded: Vec<PortRange>,
        dynamic: Vec<DynamicRange>,
        reservations: Vec<UrlReservation>,
        http: Vec<HttpSysListener>,
    }

    impl Fixture {
        fn new() -> Fixture {
            Fixture {
                listeners: vec![
                    l(Proto::Tcp, "0.0.0.0", 3000),
                    l(Proto::Tcp, "::", 3000),
                    l(Proto::Tcp, "127.0.0.1", 3001),
                    l(Proto::Udp, "0.0.0.0", 3002),
                ],
                excluded: vec![range(3003, 3005), range(50000, 50099)],
                dynamic: vec![DynamicRange {
                    proto: Proto::Tcp,
                    start: 49152,
                    count: 16384,
                }],
                reservations: vec![UrlReservation {
                    url: "http://+:3006/app/".into(),
                    port: Some(3006),
                    accounts: "Everyone".into(),
                }],
                http: vec![HttpSysListener {
                    url: "http://+:3007/".into(),
                    port: Some(3007),
                    pids: vec![4],
                    queue: "q".into(),
                }],
            }
        }
        fn ctx(&self) -> PortContext<'_> {
            PortContext {
                listeners: &self.listeners,
                excluded: &self.excluded,
                dynamic: &self.dynamic,
                reservations: &self.reservations,
                http_listeners: &self.http,
            }
        }
    }

    #[test]
    fn verdicts() {
        let f = Fixture::new();
        let c = f.ctx();
        let r = check(3000, Proto::Tcp, &c);
        assert_eq!(r.verdict, Verdict::InUse);
        assert_eq!(r.users, vec![0, 1]);
        assert!(!r.is_bindable());
        // UDP 3000 is a different thing from TCP 3000.
        assert_eq!(check(3000, Proto::Udp, &c).verdict, Verdict::Free);
        assert_eq!(check(3002, Proto::Udp, &c).verdict, Verdict::InUse);
        let r = check(3004, Proto::Tcp, &c);
        assert_eq!(r.verdict, Verdict::Reserved);
        assert_eq!(r.excluded.unwrap().start, 3003);
        assert!(r.notes.iter().any(|n| n.contains("10013")));
        // Exclusions are per protocol.
        assert_eq!(check(3004, Proto::Udp, &c).verdict, Verdict::Free);
        let r = check(3006, Proto::Tcp, &c);
        assert_eq!(r.verdict, Verdict::FreeWithNotes);
        assert_eq!(r.reserved_urls.len(), 1);
        assert_eq!(check(3007, Proto::Tcp, &c).verdict, Verdict::InUse);
        let r = check(49200, Proto::Tcp, &c);
        assert_eq!(r.verdict, Verdict::FreeWithNotes);
        assert!(r.in_dynamic_range);
        assert_eq!(check(3010, Proto::Tcp, &c).verdict, Verdict::Free);
        assert_eq!(
            check(3010, Proto::Tcp, &c).headline(),
            "TCP port 3010 is free"
        );
        assert_eq!(check(50050, Proto::Tcp, &c).verdict, Verdict::Reserved);
    }

    #[test]
    fn next_free_skips_listeners_and_reserved_ranges() {
        let f = Fixture::new();
        let c = f.ctx();
        // 3000, 3001 in use; 3003-3005 excluded; 3007 served by HTTP.sys.
        assert_eq!(next_free(3000, Proto::Tcp, &c), Some(3002));
        assert_eq!(next_free(3003, Proto::Tcp, &c), Some(3006));
        assert_eq!(next_free(3007, Proto::Tcp, &c), Some(3008));
        assert_eq!(next_free(3002, Proto::Udp, &c), Some(3003));
        assert_eq!(next_free(0, Proto::Tcp, &c), Some(1));
        assert_eq!(
            free_in_range(3000, 3010, Proto::Tcp, &c, 10),
            vec![3002, 3006, 3008, 3009, 3010]
        );
        assert_eq!(
            free_in_range(3010, 3000, Proto::Tcp, &c, 2),
            vec![3002, 3006]
        );
        assert_eq!(next_free_block(3000, 3, Proto::Tcp, &c), Some(3008));
        assert_eq!(next_free_block(3000, 1, Proto::Tcp, &c), Some(3002));
    }

    #[test]
    fn nothing_free_at_the_top() {
        let listeners = vec![l(Proto::Tcp, "0.0.0.0", 65535)];
        let c = PortContext {
            listeners: &listeners,
            ..Default::default()
        };
        assert_eq!(next_free(65535, Proto::Tcp, &c), None);
        assert_eq!(next_free_block(65534, 3, Proto::Tcp, &c), None);
    }

    #[test]
    fn port_lists() {
        assert_eq!(
            parse_port_list("3000, 8000-8002 5432;3000").unwrap(),
            vec![3000, 8000, 8001, 8002, 5432]
        );
        assert_eq!(
            parse_port_list("8002-8000").unwrap(),
            vec![8000, 8001, 8002]
        );
        assert!(parse_port_list("").is_err());
        assert!(parse_port_list("http").is_err());
        assert!(parse_port_list("70000").is_err());
        assert!(parse_port_list("1-65535").is_err());
    }

    #[test]
    fn real_bind_test_sees_our_own_listener() {
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();
        assert_ne!(bind_test(port, Proto::Tcp), BindTest::Ok);
        drop(held);
        assert_eq!(bind_test(port, Proto::Tcp), BindTest::Ok);
    }
}
