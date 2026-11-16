//! Collector: the TCP and UDP tables of this PC (IPv4 and IPv6) with the
//! owning process of every socket. Read-only.

use crate::model::{Connection, Listener, ListenerKey, Proto, TcpState};
use crate::util::filetime_to_unix;
use std::collections::HashSet;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_MODULE, MIB_TCP6ROW_OWNER_PID,
    MIB_TCP6TABLE_OWNER_MODULE, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_MODULE,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_MODULE, MIB_TCPTABLE_OWNER_PID,
    MIB_UDP6ROW_OWNER_MODULE, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_MODULE,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_MODULE, MIB_UDPROW_OWNER_PID,
    MIB_UDPTABLE_OWNER_MODULE, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_MODULE_ALL,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_MODULE, UDP_TABLE_OWNER_PID,
};

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const MIB_TCP_STATE_LISTEN: u32 = 2;

/// The socket tables without process details.
#[derive(Default)]
pub(crate) struct RawTables {
    pub listeners: Vec<Listener>,
    pub connections: Vec<Connection>,
    pub errors: Vec<String>,
}

/// A port as the IP helper tables store it: network byte order in the low 16 bits.
pub(crate) fn port_of(raw: u32) -> u16 {
    u16::from_be(raw as u16)
}

/// An IPv4 address as the IP helper tables store it (network byte order).
pub(crate) fn v4_of(raw: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes()))
}

fn v6_of(raw: [u8; 16]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(raw))
}

/// Collects rows and drops duplicates.
#[derive(Default)]
pub(crate) struct Tables {
    raw: RawTables,
    seen_listeners: HashSet<ListenerKey>,
    seen_connections: HashSet<(SocketAddr, SocketAddr, u32, TcpState)>,
}

impl Tables {
    /// One row of a TCP table: listening rows become listeners, the rest connections.
    pub(crate) fn push_tcp(
        &mut self,
        state: u32,
        local: SocketAddr,
        remote: SocketAddr,
        pid: u32,
        created_ticks: Option<i64>,
    ) {
        let created = created_ticks.and_then(filetime_to_unix);
        if state == MIB_TCP_STATE_LISTEN {
            self.push_listener(Proto::Tcp, local, pid, created);
        } else {
            let state = TcpState::from_mib(state);
            if self.seen_connections.insert((local, remote, pid, state)) {
                self.raw.connections.push(Connection {
                    local,
                    remote,
                    state,
                    pid,
                    created,
                });
            }
        }
    }

    /// One row of a UDP table: every bound UDP socket counts as a listener.
    pub(crate) fn push_udp(&mut self, local: SocketAddr, pid: u32, created_ticks: Option<i64>) {
        let created = created_ticks.and_then(filetime_to_unix);
        self.push_listener(Proto::Udp, local, pid, created);
    }

    fn push_listener(&mut self, proto: Proto, local: SocketAddr, pid: u32, created: Option<i64>) {
        let listener = Listener {
            proto,
            addr: local.ip(),
            port: local.port(),
            pid,
            created,
        };
        if self.seen_listeners.insert(listener.key()) {
            self.raw.listeners.push(listener);
        }
    }

    pub(crate) fn finish(mut self) -> RawTables {
        self.raw
            .listeners
            .sort_by_key(|l| (l.port, l.proto, l.addr, l.pid));
        self.raw
            .connections
            .sort_by_key(|c| (c.local.port(), c.remote, c.local.ip(), c.pid));
        self.raw
    }
}

/// Calls one of the `GetExtended*Table` functions until the buffer is large enough.
fn fetch(call: impl Fn(Option<*mut c_void>, *mut u32) -> u32) -> Result<Vec<u64>, u32> {
    let mut buf: Vec<u64> = Vec::new();
    let mut size = 0u32;
    for _ in 0..8 {
        let ptr = if buf.is_empty() {
            None
        } else {
            Some(buf.as_mut_ptr() as *mut c_void)
        };
        match call(ptr, &mut size) {
            0 => return Ok(buf),
            ERROR_INSUFFICIENT_BUFFER => {
                // Room to spare: the tables change between the two calls.
                buf = vec![0u64; (size as usize + 8192) / 8 + 1];
                size = (buf.len() * 8) as u32;
            }
            e => return Err(e),
        }
    }
    Err(ERROR_INSUFFICIENT_BUFFER)
}

fn tcp_table(
    family: u32,
    class: windows::Win32::NetworkManagement::IpHelper::TCP_TABLE_CLASS,
) -> Result<Vec<u64>, u32> {
    fetch(|ptr, size| unsafe { GetExtendedTcpTable(ptr, size, false, family, class, 0) })
}

fn udp_table(
    family: u32,
    class: windows::Win32::NetworkManagement::IpHelper::UDP_TABLE_CLASS,
) -> Result<Vec<u64>, u32> {
    fetch(|ptr, size| unsafe { GetExtendedUdpTable(ptr, size, false, family, class, 0) })
}

/// The rows of a `MIB_*TABLE_*` buffer (a count followed by that many rows).
macro_rules! rows {
    ($buf:expr, $table:ty, $row:ty) => {{
        let buf: &Vec<u64> = $buf;
        let bytes = buf.len() * 8;
        if bytes < std::mem::size_of::<$table>() {
            &[][..]
        } else {
            // SAFETY: the buffer is 8-byte aligned, at least one table header
            // long, and the row count is checked against its size.
            unsafe {
                let table = buf.as_ptr() as *const $table;
                let first = std::ptr::addr_of!((*table).table) as *const $row;
                let offset = first as usize - table as usize;
                let room = (bytes - offset) / std::mem::size_of::<$row>();
                let n = ((*table).dwNumEntries as usize).min(room);
                std::slice::from_raw_parts(first, n)
            }
        }
    }};
}

fn sock(addr: IpAddr, raw_port: u32) -> SocketAddr {
    SocketAddr::new(addr, port_of(raw_port))
}

fn read_tcp4(out: &mut Tables) -> Result<(), u32> {
    match tcp_table(AF_INET, TCP_TABLE_OWNER_MODULE_ALL) {
        Ok(buf) => {
            for r in rows!(&buf, MIB_TCPTABLE_OWNER_MODULE, MIB_TCPROW_OWNER_MODULE) {
                out.push_tcp(
                    r.dwState,
                    sock(v4_of(r.dwLocalAddr), r.dwLocalPort),
                    sock(v4_of(r.dwRemoteAddr), r.dwRemotePort),
                    r.dwOwningPid,
                    Some(r.liCreateTimestamp),
                );
            }
        }
        Err(_) => {
            let buf = tcp_table(AF_INET, TCP_TABLE_OWNER_PID_ALL)?;
            for r in rows!(&buf, MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID) {
                out.push_tcp(
                    r.dwState,
                    sock(v4_of(r.dwLocalAddr), r.dwLocalPort),
                    sock(v4_of(r.dwRemoteAddr), r.dwRemotePort),
                    r.dwOwningPid,
                    None,
                );
            }
        }
    }
    Ok(())
}

fn read_tcp6(out: &mut Tables) -> Result<(), u32> {
    match tcp_table(AF_INET6, TCP_TABLE_OWNER_MODULE_ALL) {
        Ok(buf) => {
            for r in rows!(&buf, MIB_TCP6TABLE_OWNER_MODULE, MIB_TCP6ROW_OWNER_MODULE) {
                out.push_tcp(
                    r.dwState,
                    sock(v6_of(r.ucLocalAddr), r.dwLocalPort),
                    sock(v6_of(r.ucRemoteAddr), r.dwRemotePort),
                    r.dwOwningPid,
                    Some(r.liCreateTimestamp),
                );
            }
        }
        Err(_) => {
            let buf = tcp_table(AF_INET6, TCP_TABLE_OWNER_PID_ALL)?;
            for r in rows!(&buf, MIB_TCP6TABLE_OWNER_PID, MIB_TCP6ROW_OWNER_PID) {
                out.push_tcp(
                    r.dwState,
                    sock(v6_of(r.ucLocalAddr), r.dwLocalPort),
                    sock(v6_of(r.ucRemoteAddr), r.dwRemotePort),
                    r.dwOwningPid,
                    None,
                );
            }
        }
    }
    Ok(())
}

fn read_udp4(out: &mut Tables) -> Result<(), u32> {
    match udp_table(AF_INET, UDP_TABLE_OWNER_MODULE) {
        Ok(buf) => {
            for r in rows!(&buf, MIB_UDPTABLE_OWNER_MODULE, MIB_UDPROW_OWNER_MODULE) {
                out.push_udp(
                    sock(v4_of(r.dwLocalAddr), r.dwLocalPort),
                    r.dwOwningPid,
                    Some(r.liCreateTimestamp),
                );
            }
        }
        Err(_) => {
            let buf = udp_table(AF_INET, UDP_TABLE_OWNER_PID)?;
            for r in rows!(&buf, MIB_UDPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID) {
                out.push_udp(
                    sock(v4_of(r.dwLocalAddr), r.dwLocalPort),
                    r.dwOwningPid,
                    None,
                );
            }
        }
    }
    Ok(())
}

fn read_udp6(out: &mut Tables) -> Result<(), u32> {
    match udp_table(AF_INET6, UDP_TABLE_OWNER_MODULE) {
        Ok(buf) => {
            for r in rows!(&buf, MIB_UDP6TABLE_OWNER_MODULE, MIB_UDP6ROW_OWNER_MODULE) {
                out.push_udp(
                    sock(v6_of(r.ucLocalAddr), r.dwLocalPort),
                    r.dwOwningPid,
                    Some(r.liCreateTimestamp),
                );
            }
        }
        Err(_) => {
            let buf = udp_table(AF_INET6, UDP_TABLE_OWNER_PID)?;
            for r in rows!(&buf, MIB_UDP6TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID) {
                out.push_udp(
                    sock(v6_of(r.ucLocalAddr), r.dwLocalPort),
                    r.dwOwningPid,
                    None,
                );
            }
        }
    }
    Ok(())
}

/// Reads all four tables. A table that cannot be read is reported in `errors`
/// and the others are still returned.
pub(crate) fn read_tables() -> RawTables {
    let mut out = Tables::default();
    let mut errors = Vec::new();
    let readers: [(&str, fn(&mut Tables) -> Result<(), u32>); 4] = [
        ("TCP table (IPv4)", read_tcp4),
        ("TCP table (IPv6)", read_tcp6),
        ("UDP table (IPv4)", read_udp4),
        ("UDP table (IPv6)", read_udp6),
    ];
    for (name, read) in readers {
        if let Err(code) = read(&mut out) {
            errors.push(format!("{name} unavailable: Windows error {code}."));
        }
    }
    let mut raw = out.finish();
    raw.errors = errors;
    raw
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ports_and_addresses_are_in_network_byte_order() {
        // Port 8080 = 0x1F90, stored as the bytes 1F 90.
        let raw = u32::from(u16::from_ne_bytes([0x1F, 0x90]));
        assert_eq!(port_of(raw), 8080);
        // Garbage in the upper half is ignored.
        assert_eq!(port_of(raw | 0xABCD_0000), 8080);
        assert_eq!(port_of(0), 0);
        let addr = u32::from_ne_bytes([192, 0, 2, 7]);
        assert_eq!(v4_of(addr), "192.0.2.7".parse::<IpAddr>().unwrap());
        assert_eq!(v4_of(0), "0.0.0.0".parse::<IpAddr>().unwrap());
        let mut six = [0u8; 16];
        six[15] = 1;
        assert_eq!(v6_of(six), "::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn rows_are_classified_and_deduplicated() {
        let mut t = Tables::default();
        let ticks = 116_444_736_000_000_000 + 1_700_000_000 * 10_000_000;
        t.push_tcp(2, sa("0.0.0.0:8080"), sa("0.0.0.0:0"), 100, Some(ticks));
        t.push_tcp(2, sa("0.0.0.0:8080"), sa("0.0.0.0:0"), 100, Some(ticks));
        t.push_tcp(2, sa("[::]:8080"), sa("[::]:0"), 100, None);
        t.push_tcp(
            5,
            sa("192.0.2.7:50123"),
            sa("198.51.100.9:443"),
            200,
            Some(0),
        );
        t.push_tcp(
            5,
            sa("192.0.2.7:50123"),
            sa("198.51.100.9:443"),
            200,
            Some(0),
        );
        t.push_tcp(11, sa("192.0.2.7:50124"), sa("198.51.100.9:443"), 200, None);
        t.push_udp(sa("127.0.0.1:5353"), 300, None);
        t.push_udp(sa("127.0.0.1:5353"), 300, None);
        t.push_udp(sa("127.0.0.1:5353"), 301, None);
        let raw = t.finish();

        assert_eq!(raw.listeners.len(), 4);
        assert_eq!(raw.connections.len(), 2);
        let tcp: Vec<_> = raw
            .listeners
            .iter()
            .filter(|l| l.proto == Proto::Tcp)
            .collect();
        assert_eq!(tcp.len(), 2);
        assert!(tcp.iter().all(|l| l.port == 8080 && l.pid == 100));
        let v4 = tcp.iter().find(|l| !l.is_v6()).unwrap();
        assert_eq!(v4.created, Some(1_700_000_000));
        assert_eq!(tcp.iter().find(|l| l.is_v6()).unwrap().created, None);
        assert_eq!(raw.connections[0].state, TcpState::Established);
        assert_eq!(raw.connections[0].created, None, "tick 0 is not a time");
        assert_eq!(raw.connections[1].state, TcpState::TimeWait);
        // Sorted by port.
        assert_eq!(raw.listeners[0].port, 5353);
    }

    #[test]
    fn reads_the_real_tables_without_errors() {
        let raw = read_tables();
        assert!(
            raw.errors.is_empty(),
            "{} table(s) failed",
            raw.errors.len()
        );
        // Every Windows PC has at least a few bound sockets.
        assert!(!raw.listeners.is_empty());
        let keys: HashSet<_> = raw.listeners.iter().map(Listener::key).collect();
        assert_eq!(keys.len(), raw.listeners.len());
    }
}
