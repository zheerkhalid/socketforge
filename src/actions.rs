//! Things the user can do from the window: end a process, stop a service,
//! open a folder or a URL, test a port, restart elevated.

use crate::collect::procs::Handle;
use crate::collect::services::ScHandle;
use crate::util::{from_wide, wide};
use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::os::windows::process::CommandExt;
use std::time::{Duration, Instant};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::Networking::WinSock::{
    socklen_t, GetNameInfoW, WSAStartup, NI_NAMEREQD, SOCKADDR, WSADATA,
};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Services::{
    ControlService, EnumDependentServicesW, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
    ENUM_SERVICE_STATUSW, SC_HANDLE, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_ACTIVE,
    SERVICE_CONTROL_STOP, SERVICE_ENUMERATE_DEPENDENTS, SERVICE_QUERY_STATUS, SERVICE_STATUS,
    SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOPPED,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, TerminateProcess, WaitForSingleObject,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_BUFFER_OVERFLOW: u32 = 111;
const ERROR_MORE_DATA: u32 = 234;
const ERROR_DEPENDENT_SERVICES_RUNNING: u32 = 1051;
const ERROR_INVALID_SERVICE_CONTROL: u32 = 1052;
const ERROR_SERVICE_CANNOT_ACCEPT_CTRL: u32 = 1061;
const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;
const ERROR_INVALID_NAME: u32 = 123;

/// How long `stop_service` waits for the service to report "stopped".
const SERVICE_STOP_WAIT: Duration = Duration::from_secs(10);
/// How long `probe_port` waits for a server to speak first.
const GREETING_WAIT: Duration = Duration::from_millis(400);
/// At most this many bytes of a banner are kept.
pub const BANNER_LIMIT: usize = 512;

/// The Win32 error number inside a `windows` error (0 when it is not one).
fn win32_code(e: &windows::core::Error) -> u32 {
    let hr = e.code().0 as u32;
    if hr >> 16 == 0x8007 {
        hr & 0xFFFF
    } else {
        0
    }
}

// --------------------------------------------------------------------------------------
// Elevation
// --------------------------------------------------------------------------------------

/// Is this process running with administrator rights?
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let token = Handle(token);
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token.0,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .is_ok();
        ok && elevation.TokenIsElevated != 0
    }
}

fn shell_execute(verb: &str, file: &str, params: &str) -> Result<(), usize> {
    let (v, f, p) = (wide(verb), wide(file), wide(params));
    let r = unsafe {
        ShellExecuteW(
            HWND::default(),
            PCWSTR(v.as_ptr()),
            PCWSTR(f.as_ptr()),
            if params.is_empty() {
                PCWSTR::null()
            } else {
                PCWSTR(p.as_ptr())
            },
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    let code = r.0 as usize;
    if code > 32 {
        Ok(())
    } else {
        Err(code)
    }
}

/// Starts a new elevated copy of SocketForge (UAC prompt). The caller then closes this one.
pub fn restart_as_admin() -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("SocketForge could not find its own program file: {e}"))?;
    shell_execute("runas", &exe.to_string_lossy(), "").map_err(|code| {
        if code == ERROR_ACCESS_DENIED as usize {
            "The administrator prompt was declined.".to_string()
        } else {
            format!("Windows could not restart SocketForge as administrator (code {code}).")
        }
    })
}

// --------------------------------------------------------------------------------------
// Processes and services
// --------------------------------------------------------------------------------------

/// The rules of `end_process` that need no system call: never PID 0 (idle),
/// PID 4 (the Windows kernel) or SocketForge itself. Windows ignores the two
/// lowest bits of a PID (5, 6 and 7 all mean process 4), so they are ignored
/// here too.
pub fn end_process_guard(pid: u32, own_pid: u32) -> Result<(), String> {
    match pid & !3 {
        0 => Err("The System Idle Process cannot be ended.".into()),
        4 => Err("The System process is Windows itself and cannot be ended.".into()),
        p if p == own_pid & !3 => {
            Err("SocketForge will not end itself; close the window instead.".into())
        }
        _ => Ok(()),
    }
}

/// Plain words for why a process could not be ended.
pub fn end_process_error(code: u32, pid: u32) -> String {
    match code {
        ERROR_ACCESS_DENIED => format!(
            "Ending process {pid} needs administrator rights (or Windows protects this process)."
        ),
        ERROR_INVALID_PARAMETER => format!("Process {pid} is no longer running."),
        _ => format!("Process {pid} could not be ended (Windows error {code})."),
    }
}

/// Ends a process (TerminateProcess). Refuses PID 0, PID 4 and SocketForge itself.
pub fn end_process(pid: u32) -> Result<(), String> {
    end_process_guard(pid, std::process::id())?;
    unsafe {
        let process = OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, pid)
            .map_err(|e| end_process_error(win32_code(&e), pid))?;
        let process = Handle(process);
        if let Err(e) = TerminateProcess(process.0, 1) {
            // Access denied here also happens when the process has just ended.
            if WaitForSingleObject(process.0, 0).0 == 0 {
                return Ok(());
            }
            return Err(end_process_error(win32_code(&e), pid));
        }
        // Give Windows a moment to tear it down, so that a refresh right
        // after this no longer shows its sockets.
        let _ = WaitForSingleObject(process.0, 3000);
    }
    Ok(())
}

/// Service short names: no path separators, at most 256 characters.
pub fn service_name_guard(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("No service name was given.".into());
    }
    if name.chars().count() > 256
        || name.contains(['/', '\\'])
        || name.chars().any(char::is_control)
    {
        return Err(format!("\"{name}\" is not a valid service name."));
    }
    Ok(())
}

/// Plain words for why a service could not be stopped.
pub fn stop_service_error(code: u32, name: &str) -> String {
    match code {
        ERROR_ACCESS_DENIED => {
            format!("Stopping the service \"{name}\" needs administrator rights.")
        }
        ERROR_SERVICE_DOES_NOT_EXIST | ERROR_INVALID_NAME => {
            format!("There is no service named \"{name}\".")
        }
        ERROR_DEPENDENT_SERVICES_RUNNING => format!(
            "The service \"{name}\" cannot be stopped while other running services depend on it."
        ),
        ERROR_INVALID_SERVICE_CONTROL | ERROR_SERVICE_CANNOT_ACCEPT_CTRL => {
            format!("The service \"{name}\" does not accept a stop request right now.")
        }
        _ => format!("The service \"{name}\" could not be stopped (Windows error {code})."),
    }
}

unsafe fn service_state(service: SC_HANDLE) -> Option<SERVICE_STATUS_PROCESS> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0u32;
    let bytes = std::slice::from_raw_parts_mut(
        &mut status as *mut _ as *mut u8,
        std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
    );
    QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, Some(bytes), &mut needed).ok()?;
    Some(status)
}

/// Display names of the running services that depend on `service`.
unsafe fn running_dependents(service: SC_HANDLE) -> Vec<String> {
    let mut needed = 0u32;
    let mut count = 0u32;
    let _ = EnumDependentServicesW(service, SERVICE_ACTIVE, None, 0, &mut needed, &mut count);
    if needed == 0 {
        return Vec::new();
    }
    let mut buf: Vec<u64> = vec![0; needed as usize / 8 + 1];
    if EnumDependentServicesW(
        service,
        SERVICE_ACTIVE,
        Some(buf.as_mut_ptr() as *mut ENUM_SERVICE_STATUSW),
        (buf.len() * 8) as u32,
        &mut needed,
        &mut count,
    )
    .is_err()
    {
        return Vec::new();
    }
    let entries =
        std::slice::from_raw_parts(buf.as_ptr() as *const ENUM_SERVICE_STATUSW, count as usize);
    entries
        .iter()
        .map(|e| {
            let p = if e.lpDisplayName.is_null() {
                e.lpServiceName
            } else {
                e.lpDisplayName
            };
            if p.is_null() {
                String::new()
            } else {
                String::from_utf16_lossy(p.as_wide())
            }
        })
        .filter(|n| !n.is_empty())
        .collect()
}

/// Asks the Service Control Manager to stop a service and waits a few seconds for it.
pub fn stop_service(name: &str) -> Result<(), String> {
    let name = name.trim();
    service_name_guard(name)?;
    let wide_name = wide(name);
    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)
            .map_err(|e| stop_service_error(win32_code(&e), name))?;
        let scm = ScHandle(scm);
        let service = OpenServiceW(
            scm.0,
            PCWSTR(wide_name.as_ptr()),
            SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS,
        )
        .map_err(|e| stop_service_error(win32_code(&e), name))?;
        let service = ScHandle(service);

        if service_state(service.0).is_some_and(|s| s.dwCurrentState == SERVICE_STOPPED) {
            return Ok(());
        }
        let mut status = SERVICE_STATUS::default();
        if let Err(e) = ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) {
            let code = win32_code(&e);
            return match code {
                ERROR_SERVICE_NOT_ACTIVE => Ok(()),
                ERROR_DEPENDENT_SERVICES_RUNNING => {
                    let dependents = running_dependents(service.0);
                    let mut text = stop_service_error(code, name);
                    if !dependents.is_empty() {
                        text.push_str(&format!(" Stop these first: {}.", dependents.join(", ")));
                    }
                    Err(text)
                }
                _ => Err(stop_service_error(code, name)),
            };
        }
        let deadline = Instant::now() + SERVICE_STOP_WAIT;
        loop {
            match service_state(service.0) {
                Some(s) if s.dwCurrentState == SERVICE_STOPPED => return Ok(()),
                _ if Instant::now() >= deadline => {
                    return Err(format!(
                        "The service \"{name}\" was asked to stop but is still stopping after {} \
                         seconds.",
                        SERVICE_STOP_WAIT.as_secs()
                    ))
                }
                _ => std::thread::sleep(Duration::from_millis(200)),
            }
        }
    }
}

// --------------------------------------------------------------------------------------
// Opening things
// --------------------------------------------------------------------------------------

/// Opens File Explorer with the file selected.
pub fn open_file_location(path: &str) -> Result<(), String> {
    let path = path.trim().trim_matches('"');
    if path.is_empty() {
        return Err("The location of this program is not known.".into());
    }
    if !std::path::Path::new(path).exists() {
        return Err(format!("\"{path}\" no longer exists."));
    }
    let explorer = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("C:\\Windows"))
        .join("explorer.exe");
    std::process::Command::new(explorer)
        .raw_arg(format!("/select,\"{path}\""))
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("File Explorer could not be opened: {e}"))
}

/// Opens a web address or file with its default program.
pub fn open_url(url: &str) -> Result<(), String> {
    let url = url.trim();
    if url.is_empty() {
        return Err("There is nothing to open.".into());
    }
    shell_execute("open", url, "")
        .map_err(|code| format!("Windows could not open \"{url}\" (code {code})."))
}

// --------------------------------------------------------------------------------------
// Addresses of this PC
// --------------------------------------------------------------------------------------

/// The IP address inside a Windows `SOCKADDR` (IPv4 or IPv6).
unsafe fn sockaddr_ip(addr: *const SOCKADDR, len: i32) -> Option<IpAddr> {
    if addr.is_null() || len < 16 {
        return None;
    }
    let bytes = std::slice::from_raw_parts(addr as *const u8, len as usize);
    match u16::from_ne_bytes([bytes[0], bytes[1]]) {
        2 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[4], bytes[5], bytes[6], bytes[7],
        ))),
        23 if bytes.len() >= 24 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&bytes[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => None,
    }
}

/// Every unicast address configured on this PC's network adapters.
pub fn own_addresses() -> Vec<IpAddr> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut out = Vec::new();
    // 8-byte aligned storage for the linked list Windows writes into it.
    let mut buf: Vec<u64> = vec![0; 4096];
    unsafe {
        for _ in 0..4 {
            let mut size = (buf.len() * 8) as u32;
            let r = GetAdaptersAddresses(
                0,
                flags,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            );
            if r == ERROR_BUFFER_OVERFLOW || r == ERROR_MORE_DATA {
                buf = vec![0; size as usize / 8 + 512];
                continue;
            }
            if r != 0 {
                return out;
            }
            let mut adapter = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
            while !adapter.is_null() {
                let mut unicast = (*adapter).FirstUnicastAddress;
                while !unicast.is_null() {
                    let address = &(*unicast).Address;
                    if let Some(ip) = sockaddr_ip(address.lpSockaddr, address.iSockaddrLength) {
                        if !out.contains(&ip) {
                            out.push(ip);
                        }
                    }
                    unicast = (*unicast).Next;
                }
                adapter = (*adapter).Next;
            }
            return out;
        }
    }
    out
}

/// `::ffff:192.0.2.1` -> `192.0.2.1`; everything else unchanged.
fn unmapped(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => *ip,
        },
        IpAddr::V4(_) => *ip,
    }
}

/// Is `ip` loopback, "any address" or one of `own`?
pub fn is_local_among(ip: &IpAddr, own: &[IpAddr]) -> bool {
    let ip = unmapped(ip);
    ip.is_loopback() || ip.is_unspecified() || own.iter().any(|o| unmapped(o) == ip)
}

/// Is this an address of this PC (loopback, or one of its own interface addresses)?
pub fn is_local_address(ip: &IpAddr) -> bool {
    let plain = unmapped(ip);
    if plain.is_loopback() || plain.is_unspecified() {
        return true;
    }
    is_local_among(&plain, &own_addresses())
}

// --------------------------------------------------------------------------------------
// Port test
// --------------------------------------------------------------------------------------

/// The result of connecting to a port and reading what the server says first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProbeResult {
    pub connected: bool,
    pub elapsed_ms: u64,
    /// First bytes the server sent on its own, or in reply to a minimal HTTP
    /// request (at most 512 bytes).
    pub banner: Vec<u8>,
    /// `banner` with non-printable bytes replaced by dots.
    pub banner_text: String,
    /// True when the banner is the reply to the HTTP request rather than a greeting.
    pub http_reply: bool,
    /// Why the connection failed, in plain words.
    pub error: Option<String>,
}

/// Makes a banner safe to show: printable ASCII stays, line breaks stay (as
/// `\n`), tabs become spaces, every other byte becomes a dot. Trailing blank
/// space is dropped and at most `BANNER_LIMIT` bytes are looked at.
pub fn sanitize_banner(bytes: &[u8]) -> String {
    let bytes = &bytes[..bytes.len().min(BANNER_LIMIT)];
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\r' if bytes.get(i + 1) == Some(&b'\n') => {}
            b'\n' => out.push('\n'),
            b'\t' => out.push(' '),
            b @ 0x20..=0x7E => out.push(b as char),
            _ => out.push('.'),
        }
        i += 1;
    }
    out.trim_end().to_string()
}

/// Plain words for a failed connection attempt.
pub fn connect_error_text(os_code: Option<i32>, kind: std::io::ErrorKind) -> String {
    use std::io::ErrorKind;
    match (os_code, kind) {
        (Some(10061), _) | (_, ErrorKind::ConnectionRefused) => {
            "Connection refused: nothing is accepting connections on this port.".into()
        }
        (Some(10060), _) | (_, ErrorKind::TimedOut) | (_, ErrorKind::WouldBlock) => {
            "Timed out: no answer within the time limit (the port may be filtered).".into()
        }
        (Some(10051), _) | (Some(10065), _) => "The address cannot be reached from this PC.".into(),
        (Some(10049), _) | (_, ErrorKind::AddrNotAvailable) => {
            "This address cannot be connected to.".into()
        }
        (Some(10013), _) | (_, ErrorKind::PermissionDenied) => {
            "Windows did not allow the connection (access denied).".into()
        }
        (Some(10054), _) | (_, ErrorKind::ConnectionReset) => {
            "The connection was reset by the other side.".into()
        }
        (Some(code), _) => format!("Could not connect (Windows error {code})."),
        (None, kind) => format!("Could not connect ({kind})."),
    }
}

/// Where a test connection really goes: "any address" listeners are reached
/// through the loopback address of the same family.
pub fn probe_target(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => {
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), addr.port())
        }
        IpAddr::V6(v6) if v6.is_unspecified() => {
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), addr.port())
        }
        _ => addr,
    }
}

/// Reads until `limit` bytes, the end of the stream or `wait` without data.
/// Once something has arrived only a short moment is given for the rest.
fn read_some(stream: &mut TcpStream, wait: Duration, limit: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut buf = [0u8; BANNER_LIMIT];
    let mut closed = false;
    let _ = stream.set_read_timeout(Some(wait.max(Duration::from_millis(1))));
    while out.len() < limit {
        let room = (limit - out.len()).min(buf.len());
        match stream.read(&mut buf[..room]) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                let _ = stream.set_read_timeout(Some(Duration::from_millis(60)));
            }
            Err(e) => {
                closed = !matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                );
                break;
            }
        }
    }
    (out, closed)
}

/// Connects to `addr`, waits briefly for a greeting, and if none arrives sends
/// a minimal `HEAD / HTTP/1.0` request to see whether an HTTP server answers.
/// Refuses non-local addresses unless `allow_non_local`.
pub fn probe_port(addr: SocketAddr, timeout: Duration, allow_non_local: bool) -> ProbeResult {
    let fail = |text: &str| ProbeResult {
        error: Some(text.to_string()),
        ..Default::default()
    };
    if addr.port() == 0 {
        return fail("Port 0 cannot be tested.");
    }
    let target = probe_target(addr);
    if !allow_non_local && !is_local_address(&target.ip()) {
        return fail(
            "Not allowed: only addresses of this PC are tested unless testing other computers \
             is switched on.",
        );
    }
    let timeout = timeout.clamp(Duration::from_millis(50), Duration::from_secs(30));
    let started = Instant::now();
    let mut stream = match TcpStream::connect_timeout(&target, timeout) {
        Ok(s) => s,
        Err(e) => {
            return ProbeResult {
                elapsed_ms: started.elapsed().as_millis() as u64,
                error: Some(connect_error_text(e.raw_os_error(), e.kind())),
                ..Default::default()
            }
        }
    };
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let _ = stream.set_write_timeout(Some(timeout));

    let (mut banner, closed) = read_some(&mut stream, GREETING_WAIT.min(timeout), BANNER_LIMIT);
    let mut http_reply = false;
    if banner.is_empty() && !closed && stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").is_ok() {
        let _ = stream.flush();
        (banner, _) = read_some(&mut stream, timeout, BANNER_LIMIT);
        http_reply = !banner.is_empty();
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
    ProbeResult {
        connected: true,
        elapsed_ms,
        banner_text: sanitize_banner(&banner),
        banner,
        http_reply,
        error: None,
    }
}

// --------------------------------------------------------------------------------------
// Reverse DNS
// --------------------------------------------------------------------------------------

/// A host name as DNS returns it, checked before it is shown.
fn clean_host_name(name: &str) -> Option<String> {
    let name = name.trim().trim_end_matches('.');
    let ok = !name.is_empty()
        && name.len() <= 253
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    ok.then(|| name.to_string())
}

/// Reverse DNS lookup (blocking; call from a background thread). Sends a DNS query.
pub fn reverse_dns(ip: &IpAddr) -> Option<String> {
    // A SOCKADDR_IN / SOCKADDR_IN6 by hand: family, port, (flow), address, (scope).
    let mut raw = [0u32; 7];
    let len = unsafe {
        let bytes = std::slice::from_raw_parts_mut(raw.as_mut_ptr() as *mut u8, 28);
        match ip {
            IpAddr::V4(v4) => {
                bytes[..2].copy_from_slice(&2u16.to_ne_bytes());
                bytes[4..8].copy_from_slice(&v4.octets());
                16
            }
            IpAddr::V6(v6) => {
                bytes[..2].copy_from_slice(&23u16.to_ne_bytes());
                bytes[8..24].copy_from_slice(&v6.octets());
                28
            }
        }
    };
    let mut host = [0u16; 1025];
    let r = unsafe {
        let mut data = WSADATA::default();
        if WSAStartup(0x0202, &mut data) != 0 {
            return None;
        }
        GetNameInfoW(
            raw.as_ptr() as *const SOCKADDR,
            socklen_t(len),
            Some(&mut host),
            None,
            NI_NAMEREQD as i32,
        )
    };
    if r != 0 {
        return None;
    }
    let name = clean_host_name(&from_wide(&host))?;
    // An address back is not a name.
    name.parse::<IpAddr>().is_err().then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn end_process_refuses_the_untouchables() {
        assert!(end_process_guard(0, 500).is_err());
        assert!(end_process_guard(4, 500).is_err());
        assert!(end_process_guard(500, 500).is_err());
        assert!(end_process_guard(504, 500).is_ok());
        // Windows rounds PIDs down to a multiple of four.
        for alias in [1, 2, 3, 5, 6, 7, 501, 503] {
            assert!(end_process_guard(alias, 500).is_err(), "{alias}");
        }
        // The public function applies the guard before anything else.
        assert!(end_process(0).unwrap_err().contains("Idle"));
        assert!(end_process(4).unwrap_err().contains("System"));
        assert!(end_process(std::process::id())
            .unwrap_err()
            .contains("SocketForge"));
        // A PID that cannot exist (PIDs are multiples of 4).
        assert!(end_process(0xFFFF_FFF3)
            .unwrap_err()
            .contains("no longer running"));
    }

    #[test]
    fn error_texts_say_what_to_do() {
        assert!(end_process_error(5, 77).contains("needs administrator rights"));
        assert!(end_process_error(87, 77).contains("no longer running"));
        assert!(end_process_error(1450, 77).contains("1450"));
        assert!(stop_service_error(5, "ExampleSvc").contains("needs administrator rights"));
        assert!(stop_service_error(1060, "ExampleSvc").contains("no service named"));
        assert!(stop_service_error(1051, "ExampleSvc").contains("depend on it"));
        assert!(stop_service_error(1052, "ExampleSvc").contains("does not accept"));
        assert!(stop_service_error(1061, "ExampleSvc").contains("does not accept"));
        assert!(stop_service_error(9999, "ExampleSvc").contains("9999"));
        assert!(stop_service_error(5, "ExampleSvc").contains("\"ExampleSvc\""));
    }

    #[test]
    fn service_names_are_checked_before_anything_is_asked() {
        assert!(service_name_guard("ExampleSvc").is_ok());
        assert!(service_name_guard("Example Svc_1.0").is_ok());
        assert!(service_name_guard("").is_err());
        assert!(service_name_guard("a\\b").is_err());
        assert!(service_name_guard("a/b").is_err());
        assert!(service_name_guard("a\nb").is_err());
        assert!(service_name_guard(&"x".repeat(257)).is_err());
        assert!(stop_service("   ").is_err());
        assert!(stop_service("bad/name").is_err());
        // A service that does not exist: asked, answered, nothing stopped.
        let e = stop_service("SocketForgeNoSuchService-7f3a").unwrap_err();
        assert!(e.contains("no service named"), "{e}");
    }

    #[test]
    fn banners_are_made_printable() {
        assert_eq!(
            sanitize_banner(b"220 mail.example ESMTP\r\n"),
            "220 mail.example ESMTP"
        );
        assert_eq!(
            sanitize_banner(b"HTTP/1.0 200 OK\r\nServer: x\r\n\r\n"),
            "HTTP/1.0 200 OK\nServer: x"
        );
        assert_eq!(sanitize_banner(b"a\tb\x00\x01\xffc\x7f"), "a b...c.");
        assert_eq!(sanitize_banner(b"lone\rreturn"), "lone.return");
        assert_eq!(sanitize_banner(b""), "");
        assert_eq!(sanitize_banner(&[0u8; 4]), "....");
        assert_eq!(sanitize_banner(&[b'x'; 2000]).len(), BANNER_LIMIT);
        assert_eq!(sanitize_banner("gr\u{fc}n".as_bytes()), "gr..n");
    }

    #[test]
    fn connection_errors_in_plain_words() {
        use std::io::ErrorKind;
        assert!(connect_error_text(Some(10061), ErrorKind::ConnectionRefused).contains("refused"));
        assert!(connect_error_text(None, ErrorKind::ConnectionRefused).contains("refused"));
        assert!(connect_error_text(Some(10060), ErrorKind::TimedOut).contains("Timed out"));
        assert!(connect_error_text(None, ErrorKind::TimedOut).contains("Timed out"));
        assert!(connect_error_text(Some(10051), ErrorKind::Other).contains("reached"));
        assert!(connect_error_text(Some(10013), ErrorKind::Other).contains("not allow"));
        assert!(connect_error_text(Some(12345), ErrorKind::Other).contains("12345"));
    }

    #[test]
    fn local_addresses() {
        let own: Vec<IpAddr> = vec!["192.0.2.7".parse().unwrap(), "2001:db8::7".parse().unwrap()];
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(is_local_among(&ip("127.0.0.1"), &own));
        assert!(is_local_among(&ip("127.9.9.9"), &own));
        assert!(is_local_among(&ip("::1"), &own));
        assert!(is_local_among(&ip("0.0.0.0"), &own));
        assert!(is_local_among(&ip("192.0.2.7"), &own));
        assert!(is_local_among(&ip("::ffff:192.0.2.7"), &own));
        assert!(is_local_among(&ip("2001:db8::7"), &own));
        assert!(!is_local_among(&ip("192.0.2.8"), &own));
        assert!(!is_local_among(&ip("198.51.100.1"), &[]));
        // The real thing: loopback is local, a documentation address is not,
        // and every address of this PC is.
        assert!(is_local_address(&ip("127.0.0.1")));
        assert!(is_local_address(&ip("::1")));
        assert!(!is_local_address(&ip("203.0.113.77")));
        assert!(own_addresses().iter().all(is_local_address));
        assert_eq!(
            probe_target("0.0.0.0:80".parse().unwrap()).to_string(),
            "127.0.0.1:80"
        );
        assert_eq!(
            probe_target("[::]:80".parse().unwrap()).to_string(),
            "[::1]:80"
        );
        assert_eq!(
            probe_target("192.0.2.7:80".parse().unwrap()).to_string(),
            "192.0.2.7:80"
        );
    }

    #[test]
    fn probe_reads_a_greeting() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.write_all(b"220 forge.test ready\r\n").unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });
        let r = probe_port(addr, Duration::from_secs(2), false);
        server.join().unwrap();
        assert!(r.connected && r.error.is_none());
        assert_eq!(r.banner, b"220 forge.test ready\r\n");
        assert_eq!(r.banner_text, "220 forge.test ready");
        assert!(!r.http_reply);
    }

    #[test]
    fn probe_asks_a_silent_server_over_http() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut request = [0u8; 64];
            let n = s.read(&mut request).unwrap();
            assert!(request[..n].starts_with(b"HEAD / HTTP/1.0\r\n"));
            s.write_all(b"HTTP/1.0 200 OK\r\nServer: forge-test\r\n\r\n")
                .unwrap();
        });
        let r = probe_port(addr, Duration::from_secs(2), false);
        server.join().unwrap();
        assert!(r.connected && r.http_reply);
        assert_eq!(r.banner_text, "HTTP/1.0 200 OK\nServer: forge-test");
    }

    #[test]
    fn probe_reports_refusals_and_forbidden_targets() {
        // A port that was just free: bind, note the number, let go.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let r = probe_port(
            SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_secs(8),
            false,
        );
        assert!(!r.connected);
        assert!(r.error.unwrap().contains("refused"));

        // Not this PC: refused before any packet is sent.
        let started = Instant::now();
        let r = probe_port(
            "203.0.113.77:80".parse().unwrap(),
            Duration::from_secs(5),
            false,
        );
        assert!(!r.connected);
        assert!(r.error.unwrap().contains("Not allowed"));
        assert!(started.elapsed() < Duration::from_secs(2));

        let r = probe_port(
            "127.0.0.1:0".parse().unwrap(),
            Duration::from_secs(1),
            false,
        );
        assert!(r.error.is_some());
    }

    #[test]
    fn host_names_are_checked() {
        assert_eq!(
            clean_host_name("host.example."),
            Some("host.example".into())
        );
        assert_eq!(clean_host_name(" pc-1.lan "), Some("pc-1.lan".into()));
        assert_eq!(clean_host_name(""), None);
        assert_eq!(clean_host_name("bad name"), None);
        assert_eq!(clean_host_name("evil\u{202e}.example"), None);
    }

    #[test]
    fn elevation_and_opening_guards() {
        // Whatever the answer, asking must work twice in a row.
        assert_eq!(is_elevated(), is_elevated());
        assert!(open_url("  ").is_err());
        assert!(open_file_location("").is_err());
        assert!(open_file_location("Z:\\missing\\nothing.exe").is_err());
    }
}
