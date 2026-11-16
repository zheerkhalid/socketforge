//! Collector: HTTP.sys URL reservations (through the HTTP Server API) and the
//! URLs HTTP.sys serves right now (from `netsh http show servicestate`).
//! Read-only.

use super::{netsh_output, note, procs};
use crate::model::{CollectorNote, HttpSysListener, UrlReservation};
use crate::util::wide;
use std::collections::HashMap;
use std::ffi::c_void;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
use windows::Win32::Networking::HttpServer::{
    HttpInitialize, HttpQueryServiceConfiguration, HttpServiceConfigQueryNext,
    HttpServiceConfigUrlAclInfo, HttpTerminate, HTTPAPI_VERSION, HTTP_INITIALIZE_CONFIG,
    HTTP_SERVICE_CONFIG_URLACL_QUERY, HTTP_SERVICE_CONFIG_URLACL_SET,
};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::PSID;

/// `netsh http show servicestate` walks every request queue of the HTTP
/// service and is slow by nature (2-5 s on an idle PC, more under load), so it
/// gets more time than the other commands before it is killed.
const SERVICESTATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NO_MORE_ITEMS: u32 = 259;

// --------------------------------------------------------------------------------------
// Pure helpers
// --------------------------------------------------------------------------------------

/// The port of an HTTP.sys URL prefix: `http://+:8080/app/` -> 8080,
/// `https://[::1]:8443/` -> 8443. Without a port: 80 / 443 by scheme.
pub fn url_port(url: &str) -> Option<u16> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let default = match scheme.to_ascii_lowercase().as_str() {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    let port_text = if let Some(after) = authority.strip_prefix('[') {
        // IPv6 literal: the port follows the closing bracket.
        let (_, tail) = after.split_once(']')?;
        match tail.strip_prefix(':') {
            Some(p) => p,
            None if tail.is_empty() => return default,
            None => return None,
        }
    } else {
        match authority.rsplit_once(':') {
            Some((_, p)) => p,
            None => return default,
        }
    };
    port_text.parse::<u16>().ok().filter(|p| *p != 0)
}

/// The accounts that an SDDL string grants access to: the trustee of every
/// "allow" entry (`D:(A;;GX;;;S-1-5-21-...)(A;;GX;;;WD)` -> the SID and `WD`).
pub fn sddl_trustees(sddl: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut rest = sddl;
    while let Some(open) = rest.find('(') {
        let Some(close) = rest[open..].find(')') else {
            break;
        };
        let ace = &rest[open + 1..open + close];
        rest = &rest[open + close + 1..];
        let fields: Vec<&str> = ace.split(';').collect();
        if fields.len() < 6 || !fields[0].trim().eq_ignore_ascii_case("A") {
            continue;
        }
        let trustee = fields[5].trim();
        if !trustee.is_empty() && !out.iter().any(|t| t == trustee) {
            out.push(trustee.to_string());
        }
    }
    out
}

/// Does this token look like `http://...` or `https://...`?
fn url_token(token: &str) -> Option<String> {
    let lower = token.to_ascii_lowercase();
    let scheme_len = if lower.starts_with("https://") {
        5
    } else if lower.starts_with("http://") {
        4
    } else {
        return None;
    };
    if token.len() <= scheme_len + 3 {
        return None;
    }
    // HTTP.sys prints the scheme in capitals; show it the usual way.
    Some(format!("{}{}", &lower[..scheme_len], &token[scheme_len..]))
}

/// PIDs on a line that consists of nothing but numbers (`4388` or `812, 4388`).
fn pid_line(line: &str) -> Option<Vec<u32>> {
    if line.is_empty()
        || !line
            .chars()
            .all(|c| c.is_ascii_digit() || c == ',' || c == ' ')
    {
        return None;
    }
    let pids: Vec<u32> = line
        .split([',', ' '])
        .filter(|p| !p.is_empty())
        .map(|p| p.parse::<u32>())
        .collect::<Result<_, _>>()
        .ok()?;
    (!pids.is_empty()).then_some(pids)
}

/// Parses `netsh http show servicestate view=requestq` in any display
/// language. The text is organised by indentation: every request queue starts
/// on an unindented `label: name` line; inside it, lines made of numbers are
/// the attached process IDs and URL-shaped tokens are the registered URLs.
/// Anything else is ignored, so an unexpected layout yields fewer details
/// rather than wrong ones.
pub fn parse_servicestate(text: &str) -> Vec<HttpSysListener> {
    struct Block {
        queue: String,
        pids: Vec<u32>,
        urls: Vec<String>,
    }
    let mut blocks: Vec<Block> = Vec::new();
    let new_block = |queue: String| Block {
        queue,
        pids: Vec::new(),
        urls: Vec::new(),
    };

    for raw in text.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let indent = line.len() - trimmed.len();
        let url = trimmed.split_whitespace().find_map(url_token);

        if indent == 0 && url.is_none() {
            if trimmed.chars().all(|c| matches!(c, '-' | '=' | '_')) {
                continue;
            }
            // `Request queue name: DefaultAppPool` (the title line of the
            // whole output has nothing after its colon).
            if let Some((_, value)) = trimmed.split_once([':', '\u{ff1a}']) {
                let value = value.trim();
                if !value.is_empty() {
                    // An unnamed queue is described by a sentence, in the
                    // display language; a real name is a single word.
                    let unnamed = value.contains(' ') && value.ends_with(['.', '\u{3002}']);
                    blocks.push(new_block(if unnamed {
                        String::new()
                    } else {
                        value.to_string()
                    }));
                }
            }
            continue;
        }
        if let Some(url) = url {
            if blocks.is_empty() {
                blocks.push(new_block(String::new()));
            }
            if let Some(block) = blocks.last_mut() {
                if !block.urls.contains(&url) {
                    block.urls.push(url);
                }
            }
        } else if let Some(pids) = pid_line(trimmed) {
            if blocks.is_empty() {
                blocks.push(new_block(String::new()));
            }
            if let Some(block) = blocks.last_mut() {
                for pid in pids {
                    if !block.pids.contains(&pid) {
                        block.pids.push(pid);
                    }
                }
            }
        }
    }

    let mut out: Vec<HttpSysListener> = Vec::new();
    for block in blocks {
        for url in block.urls {
            match out
                .iter_mut()
                .find(|l| l.url == url && l.queue == block.queue)
            {
                Some(existing) => {
                    for pid in &block.pids {
                        if !existing.pids.contains(pid) {
                            existing.pids.push(*pid);
                        }
                    }
                }
                None => out.push(HttpSysListener {
                    port: url_port(&url),
                    url,
                    pids: block.pids.clone(),
                    queue: block.queue.clone(),
                }),
            }
        }
    }
    out
}

// --------------------------------------------------------------------------------------
// Collectors
// --------------------------------------------------------------------------------------

/// `DOMAIN\user` for an SDDL trustee (`S-1-5-...` or an alias such as `WD`).
fn trustee_name(trustee: &str) -> Option<String> {
    let text = wide(trustee);
    unsafe {
        let mut sid = PSID::default();
        ConvertStringSidToSidW(PCWSTR(text.as_ptr()), &mut sid).ok()?;
        let name = procs::account_name(sid);
        let _ = LocalFree(HLOCAL(sid.0));
        (!name.is_empty()).then_some(name)
    }
}

/// Account names for an SDDL string where they all resolve, else the SDDL itself.
fn accounts_of(sddl: &str, cache: &mut HashMap<String, Option<String>>) -> String {
    let trustees = sddl_trustees(sddl);
    if trustees.is_empty() {
        return sddl.to_string();
    }
    let mut names = Vec::new();
    for t in trustees {
        let name = cache
            .entry(t.clone())
            .or_insert_with(|| trustee_name(&t))
            .clone();
        match name {
            Some(n) => names.push(n),
            None => return sddl.to_string(),
        }
    }
    names.join(", ")
}

unsafe fn pwstr_text(p: windows::core::PWSTR) -> String {
    if p.is_null() {
        String::new()
    } else {
        String::from_utf16_lossy(p.as_wide())
    }
}

unsafe fn query_reservations() -> Result<Vec<(String, String)>, u32> {
    let version = HTTPAPI_VERSION {
        HttpApiMajorVersion: 1,
        HttpApiMinorVersion: 0,
    };
    let r = HttpInitialize(version, HTTP_INITIALIZE_CONFIG, None);
    if r != 0 {
        return Err(r);
    }
    let mut out = Vec::new();
    let mut error = None;
    // 8-byte aligned: the answer starts with two pointers.
    let mut buf: Vec<u64> = vec![0; 512];
    let mut token = 0u32;
    while token < 100_000 {
        let query = HTTP_SERVICE_CONFIG_URLACL_QUERY {
            QueryDesc: HttpServiceConfigQueryNext,
            dwToken: token,
            ..Default::default()
        };
        let mut returned = 0u32;
        let r = HttpQueryServiceConfiguration(
            HANDLE::default(),
            HttpServiceConfigUrlAclInfo,
            Some(&query as *const _ as *const c_void),
            std::mem::size_of::<HTTP_SERVICE_CONFIG_URLACL_QUERY>() as u32,
            Some(buf.as_mut_ptr() as *mut c_void),
            (buf.len() * 8) as u32,
            Some(&mut returned),
            None,
        );
        match r {
            0 => {
                let set = &*(buf.as_ptr() as *const HTTP_SERVICE_CONFIG_URLACL_SET);
                out.push((
                    pwstr_text(set.KeyDesc.pUrlPrefix),
                    pwstr_text(set.ParamDesc.pStringSecurityDescriptor),
                ));
                token += 1;
            }
            ERROR_INSUFFICIENT_BUFFER if buf.len() < 1 << 20 => {
                let want = (returned as usize / 8 + 1).max(buf.len() * 2);
                buf = vec![0; want];
            }
            ERROR_NO_MORE_ITEMS => break,
            e => {
                error = Some(e);
                break;
            }
        }
    }
    let _ = HttpTerminate(HTTP_INITIALIZE_CONFIG, None);
    match error {
        Some(e) if out.is_empty() => Err(e),
        _ => Ok(out),
    }
}

/// URL reservations (`netsh http show urlacl`), read through the HTTP Server API.
pub fn reservations() -> (Vec<UrlReservation>, CollectorNote) {
    const NAME: &str = "URL reservations";
    match unsafe { query_reservations() } {
        Ok(raw) => {
            let mut cache = HashMap::new();
            let mut list: Vec<UrlReservation> = raw
                .into_iter()
                .filter(|(url, _)| !url.is_empty())
                .map(|(url, sddl)| UrlReservation {
                    port: url_port(&url),
                    accounts: accounts_of(&sddl, &mut cache),
                    url,
                })
                .collect();
            list.sort_by(|a, b| (a.port, &a.url).cmp(&(b.port, &b.url)));
            list.dedup();
            let count = list.len();
            (list, note(NAME, true, count, ""))
        }
        Err(code) => (
            Vec::new(),
            note(
                NAME,
                false,
                0,
                format!("The HTTP Server API answered with Windows error {code}."),
            ),
        ),
    }
}

/// URLs that HTTP.sys is serving right now, with the processes behind them.
pub fn listeners() -> (Vec<HttpSysListener>, CollectorNote) {
    const NAME: &str = "HTTP.sys listeners";
    let args = ["http", "show", "servicestate", "view=requestq"];
    match netsh_output(&args, SERVICESTATE_TIMEOUT) {
        Ok((success, text)) => {
            let mut list = parse_servicestate(&text);
            list.sort_by(|a, b| (a.port, &a.url).cmp(&(b.port, &b.url)));
            let count = list.len();
            if !success && list.is_empty() {
                (
                    list,
                    note(
                        NAME,
                        false,
                        0,
                        "netsh could not show the HTTP service state.",
                    ),
                )
            } else {
                (list, note(NAME, true, count, ""))
            }
        }
        Err(e) => (Vec::new(), note(NAME, false, 0, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_of_url_prefixes() {
        assert_eq!(url_port("http://+:8080/app/"), Some(8080));
        assert_eq!(url_port("https://*:443/"), Some(443));
        assert_eq!(url_port("HTTP://+:5357/abc/"), Some(5357));
        assert_eq!(url_port("http://localhost:5000/"), Some(5000));
        assert_eq!(url_port("https://[::1]:8443/x"), Some(8443));
        assert_eq!(url_port("http://[fe80::1]/x"), Some(80));
        assert_eq!(url_port("http://example.test/"), Some(80));
        assert_eq!(url_port("https://example.test"), Some(443));
        assert_eq!(url_port("http://+:80"), Some(80));
        assert_eq!(url_port("http://+:0/"), None);
        assert_eq!(url_port("http://+:99999/"), None);
        assert_eq!(url_port("http://+:abc/"), None);
        assert_eq!(url_port("net.tcp://host/"), None);
        assert_eq!(url_port("no url"), None);
        assert_eq!(url_port("http:///path"), None);
    }

    #[test]
    fn trustees_of_sddl_strings() {
        assert_eq!(
            sddl_trustees("D:(A;;GX;;;S-1-5-21-1-2-3-1001)(A;;GX;;;WD)"),
            vec!["S-1-5-21-1-2-3-1001", "WD"]
        );
        assert_eq!(sddl_trustees("D:(A;;GA;;;NS)"), vec!["NS"]);
        // Deny entries and duplicates are left out.
        assert_eq!(
            sddl_trustees("D:(D;;GX;;;BU)(A;;GX;;;BA)(A;;GR;;;BA)"),
            vec!["BA"]
        );
        assert!(sddl_trustees("").is_empty());
        assert!(sddl_trustees("D:").is_empty());
        assert!(sddl_trustees("D:(A;;GX").is_empty());
        assert!(sddl_trustees("D:(broken)").is_empty());
    }

    #[test]
    fn well_known_trustees_resolve() {
        // "Everyone" has a different name in every display language, but it resolves.
        assert!(trustee_name("WD").is_some());
        assert!(trustee_name("S-1-5-18").is_some());
        assert!(trustee_name("not a sid").is_none());
        let mut cache = HashMap::new();
        assert_ne!(accounts_of("D:(A;;GX;;;WD)", &mut cache), "D:(A;;GX;;;WD)");
        assert_eq!(accounts_of("D:(broken)", &mut cache), "D:(broken)");
        // An account that does not exist keeps the SDDL.
        let unknown = "D:(A;;GX;;;S-1-5-21-1-2-3-4444)(A;;GX;;;WD)";
        assert_eq!(accounts_of(unknown, &mut cache), unknown);
    }

    const STATE_EN: &str = r"
Snapshot of HTTP service state (Request Queue View):
-----------------------------------------------------

Request queue name: Request queue is unnamed.
    Version: 2.0
    State: Active
    Request queue 503 verbosity level: Basic
    Max requests: 1000
    Number of active processes attached: 1
    Process IDs:
        4388
    URL groups:
    URL group ID: FD00000040000001
        State: Active
        Request queue name: Request queue is unnamed.
        Properties:
            Max bandwidth: inherited
            Max connections: inherited
            Timeouts:
                Timeout values inherited
            Number of registered URLs: 2
            Registered URLs:
                HTTP://+:5357/5F0E3F5B-0000-4000-8000-123456789ABC/
                HTTPS://+:5358/5F0E3F5B-0000-4000-8000-123456789ABC/
        Server session ID: FE00000020000001
            Version: 2.0
            State: Active
            Properties:
                Max bandwidth: 4294967295
                Timeouts:
                    Entity body timeout (secs): 120
                    Drain entity body timeout (secs): 120
                    Request queue timeout (secs): 120
                    Idle connection timeout (secs): 120
                    Header wait timeout (secs): 120
                    Minimum send rate (bytes/sec): 150

Request queue name: ExamplePool
    Version: 2.0
    State: Active
    Request queue 503 verbosity level: Limited
    Max requests: 1000
    Number of active processes attached: 2
    Controller process ID: 900
    Process IDs:
        7120, 7124
    URL groups:
    URL group ID: FD00000040000002
        State: Active
        Request queue name: ExamplePool
        Properties:
            Number of registered URLs: 1
            Registered URLs:
                HTTP://*:8080/
";

    const STATE_DE: &str = r"
Momentaufnahme des HTTP-Dienststatus (Anforderungswarteschlangenansicht):
-----------------------------------------------------

Name der Anforderungswarteschlange: Die Anforderungswarteschlange ist unbenannt.
    Version: 2.0
    Status: Aktiv
    Ausführlichkeitsgrad für 503-Antworten: Einfach
    Max. Anforderungen: 1000
    Anzahl angefügter aktiver Prozesse: 1
    Prozess-IDs:
        5120
    URL-Gruppen:
    URL-Gruppen-ID: FB00000040000001
        Status: Aktiv
        Name der Anforderungswarteschlange: Die Anforderungswarteschlange ist unbenannt.
        Eigenschaften:
            Max. Bandbreite: geerbt
            Anzahl registrierter URLs: 1
            Registrierte URLs:
                HTTP://LOCALHOST:9090/API/
";

    const STATE_FR: &str = r"
Capture instantanée de l'état du service HTTP (vue File d'attente de demandes) :
-----------------------------------------------------

Nom de la file d'attente de demandes : ServiceExemple
    Version : 1.0
    État : Actif
    Nombre maximal de demandes : 1000
    Nombre de processus actifs attachés : 1
    ID de processus :
        2044
    Groupes d'URL :
    ID du groupe d'URL : FC00000040000001
        État : Actif
        Propriétés :
            Nombre d'URL inscrites : 1
            URL inscrites :
                HTTPS://[::1]:8443/SVC/
";

    #[test]
    fn service_state_in_english() {
        let list = parse_servicestate(STATE_EN);
        assert_eq!(list.len(), 3);
        assert_eq!(
            list[0].url,
            "http://+:5357/5F0E3F5B-0000-4000-8000-123456789ABC/"
        );
        assert_eq!(list[0].port, Some(5357));
        assert_eq!(list[0].pids, vec![4388]);
        assert_eq!(list[0].queue, "");
        assert!(list[1].url.starts_with("https://+:5358/"));
        assert_eq!(list[1].port, Some(5358));
        assert_eq!(list[1].pids, vec![4388]);
        assert_eq!(list[2].url, "http://*:8080/");
        assert_eq!(list[2].port, Some(8080));
        assert_eq!(list[2].pids, vec![7120, 7124]);
        assert_eq!(list[2].queue, "ExamplePool");
    }

    #[test]
    fn service_state_in_german_and_french() {
        let de = parse_servicestate(STATE_DE);
        assert_eq!(de.len(), 1);
        assert_eq!(de[0].url, "http://LOCALHOST:9090/API/");
        assert_eq!(
            (de[0].port, de[0].pids.as_slice()),
            (Some(9090), &[5120][..])
        );
        assert_eq!(de[0].queue, "");

        let fr = parse_servicestate(STATE_FR);
        assert_eq!(fr.len(), 1);
        assert_eq!(fr[0].url, "https://[::1]:8443/SVC/");
        assert_eq!(
            (fr[0].port, fr[0].pids.as_slice()),
            (Some(8443), &[2044][..])
        );
        assert_eq!(fr[0].queue, "ServiceExemple");
    }

    #[test]
    fn service_state_degrades_gracefully() {
        assert!(parse_servicestate("").is_empty());
        assert!(parse_servicestate("The requested operation requires elevation.\n").is_empty());
        // A queue without URLs yields nothing.
        assert!(parse_servicestate("Queue: A\n    Process IDs:\n        12\n").is_empty());
        // Unknown layout: URLs are still found, with whatever PIDs were seen.
        let odd = "  12\n  http://+:7000/\nsomething else\n\thttp://+:7001/ (extra)\n";
        let list = parse_servicestate(odd);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].port, Some(7000));
        assert_eq!(list[0].pids, vec![12]);
        assert_eq!(list[1].port, Some(7001));
        // The same URL in two groups of one queue appears once.
        let twice = "Q: Pool\n    4\n        http://+:81/\n        http://+:81/\n";
        assert_eq!(parse_servicestate(twice).len(), 1);
        // A bare scheme is not a URL.
        assert!(parse_servicestate("Q: Pool\n    http://\n").is_empty());
    }

    #[test]
    fn reads_reservations_without_elevation() {
        let (list, note) = reservations();
        assert!(note.ok, "the HTTP Server API is readable by every user");
        assert_eq!(note.count, list.len());
        assert!(list
            .iter()
            .all(|r| !r.url.is_empty() && !r.accounts.is_empty()));
    }
}
