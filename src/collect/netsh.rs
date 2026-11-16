//! Collector: excluded port ranges, the dynamic (ephemeral) port range and
//! `netsh interface portproxy` rules. Read-only.
//!
//! Port proxies are read from the registry. For the excluded ranges and the
//! dynamic range Windows offers no documented API, so `netsh` is run hidden
//! and its text is parsed by its numbers alone: the output is translated, the
//! numbers and the `*` marker are not.

use super::{netsh, note};
use crate::model::{CollectorNote, DynamicRange, PortProxy, PortRange, Proto};
use crate::util::from_wide;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
};

const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_MORE_DATA: u32 = 234;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;

// --------------------------------------------------------------------------------------
// Pure parsers
// --------------------------------------------------------------------------------------

/// Parses `netsh int ipv4 show excludedportrange protocol=tcp` in any display
/// language. A data line is two port numbers, optionally followed by `*`
/// (an administered exclusion); everything else is ignored.
pub fn parse_excluded_ranges(text: &str, proto: Proto, v6: bool) -> Vec<PortRange> {
    let mut out: Vec<PortRange> = Vec::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let administered = match tokens.len() {
            2 => false,
            3 if tokens[2] == "*" => true,
            _ => continue,
        };
        let (Ok(start), Ok(end)) = (tokens[0].parse::<u16>(), tokens[1].parse::<u16>()) else {
            continue;
        };
        if start == 0 || end < start {
            continue;
        }
        let range = PortRange {
            proto,
            start,
            end,
            administered,
            v6,
        };
        if !out.contains(&range) {
            out.push(range);
        }
    }
    out
}

/// Parses `netsh int ipv4 show dynamicport tcp` in any display language: the
/// first two lines that end in `: <number>` are the start port and the count.
pub fn parse_dynamic_range(text: &str, proto: Proto) -> Option<DynamicRange> {
    let mut numbers = text.lines().filter_map(|line| {
        let (label, value) = line.rsplit_once(':')?;
        if label.trim().is_empty() {
            return None;
        }
        // Some languages group digits (`16.384`, `16 384`).
        let digits: String = value
            .trim()
            .chars()
            .filter(|c| !matches!(c, '.' | ',' | ' ' | '\u{a0}' | '\u{202f}' | '\''))
            .collect();
        if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        digits.parse::<u32>().ok()
    });
    let start = numbers.next()?;
    let count = numbers.next()?;
    if !(1..=65_535).contains(&start) || count == 0 || start + count > 65_536 {
        return None;
    }
    Some(DynamicRange {
        proto,
        start: start as u16,
        count,
    })
}

/// Splits `address/port` (the form the port proxy keeps in the registry).
fn split_addr_port(s: &str) -> Option<(String, u16)> {
    let (addr, port) = s.trim().rsplit_once('/')?;
    let port = port.trim().parse::<u16>().ok().filter(|p| *p != 0)?;
    let addr = addr.trim();
    if addr.is_empty() {
        return None;
    }
    Some((addr.to_string(), port))
}

/// One registry value of
/// `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\<kind>\tcp`:
/// the name is `listenaddr/port`, the data `connectaddr/port`.
pub fn parse_portproxy_value(kind: &str, name: &str, data: &str) -> Option<PortProxy> {
    let (listen_addr, listen_port) = split_addr_port(name)?;
    let (connect_addr, connect_port) = split_addr_port(data)?;
    Some(PortProxy {
        kind: kind.to_string(),
        listen_addr,
        listen_port,
        connect_addr,
        connect_port,
    })
}

// --------------------------------------------------------------------------------------
// Collectors
// --------------------------------------------------------------------------------------

/// Excluded port ranges for TCP and UDP, IPv4 and IPv6.
pub fn excluded_ranges() -> (Vec<PortRange>, CollectorNote) {
    const NAME: &str = "Excluded port ranges";
    let queries = [
        ("ipv4", "tcp", Proto::Tcp, false),
        ("ipv4", "udp", Proto::Udp, false),
        ("ipv6", "tcp", Proto::Tcp, true),
        ("ipv6", "udp", Proto::Udp, true),
    ];
    let results: Vec<Result<Vec<PortRange>, String>> = std::thread::scope(|s| {
        let handles: Vec<_> = queries
            .iter()
            .map(|&(family, proto_name, proto, v6)| {
                s.spawn(move || {
                    let protocol = format!("protocol={proto_name}");
                    netsh(&["int", family, "show", "excludedportrange", &protocol])
                        .map(|text| parse_excluded_ranges(&text, proto, v6))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|_| Err("netsh failed".to_string())))
            .collect()
    });
    let mut ranges = Vec::new();
    let mut problems = Vec::new();
    for r in results {
        match r {
            Ok(list) => ranges.extend(list),
            Err(e) => problems.push(e),
        }
    }
    // The IPv4 answers are the ones that matter; IPv6 is a bonus.
    let ok = problems.len() < queries.len();
    problems.dedup();
    let detail = problems.join("; ");
    let count = ranges.len();
    (ranges, note(NAME, ok, count, detail))
}

/// The dynamic port range for TCP and UDP (IPv4).
pub fn dynamic_ranges() -> (Vec<DynamicRange>, CollectorNote) {
    const NAME: &str = "Dynamic port range";
    let mut ranges = Vec::new();
    let mut problems: Vec<String> = Vec::new();
    let results: Vec<(Proto, Result<String, String>)> = std::thread::scope(|s| {
        let handles: Vec<_> = [("tcp", Proto::Tcp), ("udp", Proto::Udp)]
            .into_iter()
            .map(|(name, proto)| {
                s.spawn(move || (proto, netsh(&["int", "ipv4", "show", "dynamicport", name])))
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    for (proto, result) in results {
        match result {
            Ok(text) => match parse_dynamic_range(&text, proto) {
                Some(range) => ranges.push(range),
                None => problems.push(format!("the {} range was not understood", proto.label())),
            },
            Err(e) => problems.push(e),
        }
    }
    problems.dedup();
    let ok = !ranges.is_empty();
    let count = ranges.len();
    (ranges, note(NAME, ok, count, problems.join("; ")))
}

/// Closes a registry key when it goes out of scope.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

/// The string values of one registry key under HKLM. `Ok(empty)` when the key
/// does not exist.
fn string_values(path: &str) -> Result<Vec<(String, String)>, u32> {
    let wide_path = crate::util::wide(path);
    let mut out = Vec::new();
    unsafe {
        let mut key = HKEY::default();
        let r = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wide_path.as_ptr()),
            0,
            KEY_READ,
            &mut key,
        );
        match r.0 {
            0 => {}
            ERROR_FILE_NOT_FOUND | 3 => return Ok(out),
            e => return Err(e),
        }
        let key = Key(key);
        let mut name = vec![0u16; 16_384];
        let mut data = vec![0u16; 4096];
        let mut index = 0u32;
        loop {
            let mut name_len = name.len() as u32;
            let mut data_bytes = (data.len() * 2) as u32;
            let mut kind = 0u32;
            let r = RegEnumValueW(
                key.0,
                index,
                PWSTR(name.as_mut_ptr()),
                &mut name_len,
                None,
                Some(&mut kind),
                Some(data.as_mut_ptr() as *mut u8),
                Some(&mut data_bytes),
            );
            match r.0 {
                0 => {
                    if kind == REG_SZ || kind == REG_EXPAND_SZ {
                        let chars = (data_bytes as usize / 2).min(data.len());
                        out.push((
                            String::from_utf16_lossy(&name[..name_len as usize]),
                            from_wide(&data[..chars]),
                        ));
                    }
                }
                ERROR_MORE_DATA => {
                    if data.len() < 65_536 {
                        data = vec![0u16; 65_536];
                        continue;
                    }
                }
                // ERROR_NO_MORE_ITEMS and anything unexpected end the listing.
                _ => break,
            }
            index += 1;
        }
    }
    Ok(out)
}

/// `netsh interface portproxy` rules, straight from the registry.
pub fn portproxy_rules() -> (Vec<PortProxy>, CollectorNote) {
    const NAME: &str = "Port proxies";
    let mut rules = Vec::new();
    let mut problems = Vec::new();
    for kind in ["v4tov4", "v4tov6", "v6tov4", "v6tov6"] {
        let path = format!("SYSTEM\\CurrentControlSet\\Services\\PortProxy\\{kind}\\tcp");
        match string_values(&path) {
            Ok(values) => rules.extend(
                values
                    .iter()
                    .filter_map(|(name, data)| parse_portproxy_value(kind, name, data)),
            ),
            Err(code) => problems.push(format!("{kind}: Windows error {code}")),
        }
    }
    rules.sort_by(|a, b| {
        (a.listen_port, &a.listen_addr, &a.kind).cmp(&(b.listen_port, &b.listen_addr, &b.kind))
    });
    let ok = problems.is_empty();
    let count = rules.len();
    (rules, note(NAME, ok, count, problems.join("; ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXCLUDED_EN: &str = "\r\n\
Protocol tcp Port Exclusion Ranges\r\n\
\r\n\
Start Port    End Port      \r\n\
----------    --------      \r\n\
      5357        5357      \r\n\
     50000       50059     *\r\n\
     61000       61099      \r\n\
\r\n\
* - Administered port exclusions.\r\n\
\r\n";

    const EXCLUDED_DE: &str = "\r\n\
Portausschlussbereiche f\u{fc}r das Protokoll \"tcp\"\r\n\
\r\n\
Startport    Endport      \r\n\
----------    --------      \r\n\
        80          80      \r\n\
      1024        1123     *\r\n\
\r\n\
* - Verwaltete Portausschl\u{fc}sse.\r\n";

    const EXCLUDED_FR: &str = "\n\
Plages d'exclusion de ports du protocole udp\n\
\n\
Port de d\u{e9}but    Port de fin      \n\
----------    --------      \n\
      2869        2869      \n\
     49670       49769     *\n\
\n\
* - Exclusions de ports administr\u{e9}es.\n";

    const EXCLUDED_EMPTY_ES: &str = "\r\n\
Intervalos de exclusi\u{f3}n de puertos del protocolo tcp\r\n\
\r\n\
Puerto de inicio    Puerto final      \r\n\
----------    --------      \r\n\
\r\n\
* - Exclusiones de puertos administradas.\r\n";

    fn r(proto: Proto, start: u16, end: u16, administered: bool) -> PortRange {
        PortRange {
            proto,
            start,
            end,
            administered,
            v6: false,
        }
    }

    #[test]
    fn excluded_ranges_in_english() {
        assert_eq!(
            parse_excluded_ranges(EXCLUDED_EN, Proto::Tcp, false),
            vec![
                r(Proto::Tcp, 5357, 5357, false),
                r(Proto::Tcp, 50000, 50059, true),
                r(Proto::Tcp, 61000, 61099, false),
            ]
        );
    }

    #[test]
    fn excluded_ranges_in_german_and_french() {
        assert_eq!(
            parse_excluded_ranges(EXCLUDED_DE, Proto::Tcp, false),
            vec![
                r(Proto::Tcp, 80, 80, false),
                r(Proto::Tcp, 1024, 1123, true)
            ]
        );
        let fr = parse_excluded_ranges(EXCLUDED_FR, Proto::Udp, true);
        assert_eq!(fr.len(), 2);
        assert!(fr.iter().all(|x| x.v6 && x.proto == Proto::Udp));
        assert_eq!(
            (fr[1].start, fr[1].end, fr[1].administered),
            (49670, 49769, true)
        );
        assert!(fr[1].contains(49700) && !fr[1].contains(49770));
    }

    #[test]
    fn excluded_ranges_empty_table_and_noise() {
        assert!(parse_excluded_ranges(EXCLUDED_EMPTY_ES, Proto::Tcp, false).is_empty());
        assert!(parse_excluded_ranges("", Proto::Tcp, false).is_empty());
        // Lines that only look similar are not ranges.
        let noise = "80 79\n0 10\n70000 70010\n10 20 x\n1 2 3\n  * - 5 6\nabc 10\n\
                     The requested operation requires elevation.\n";
        assert!(parse_excluded_ranges(noise, Proto::Tcp, false).is_empty());
        // Duplicates collapse.
        assert_eq!(
            parse_excluded_ranges("10 20\n10 20\n", Proto::Udp, false).len(),
            1
        );
    }

    const DYNAMIC_EN: &str = "\r\n\
Protocol tcp Dynamic Port Range\r\n\
---------------------------------\r\n\
Start Port      : 49152\r\n\
Number of Ports : 16384\r\n\
\r\n";

    const DYNAMIC_DE: &str = "\r\n\
Dynamischer Portbereich des Protokolls \"tcp\"\r\n\
---------------------------------\r\n\
Startport      : 1025\r\n\
Anzahl von Ports : 64511\r\n\
\r\n";

    const DYNAMIC_FR: &str = "\n\
Plage de ports dynamique du protocole udp\n\
---------------------------------\n\
Port de d\u{e9}marrage   : 49152\n\
Nombre de ports     : 16\u{a0}384\n\
\n";

    #[test]
    fn dynamic_range_in_three_languages() {
        assert_eq!(
            parse_dynamic_range(DYNAMIC_EN, Proto::Tcp),
            Some(DynamicRange {
                proto: Proto::Tcp,
                start: 49152,
                count: 16384
            })
        );
        let de = parse_dynamic_range(DYNAMIC_DE, Proto::Tcp).unwrap();
        assert_eq!((de.start, de.count), (1025, 64511));
        assert!(de.contains(65535) && !de.contains(1024));
        let fr = parse_dynamic_range(DYNAMIC_FR, Proto::Udp).unwrap();
        assert_eq!((fr.proto, fr.start, fr.count), (Proto::Udp, 49152, 16384));
    }

    #[test]
    fn dynamic_range_rejects_nonsense() {
        assert_eq!(parse_dynamic_range("", Proto::Tcp), None);
        assert_eq!(
            parse_dynamic_range("Start Port : 49152\n", Proto::Tcp),
            None
        );
        assert_eq!(
            parse_dynamic_range("Start : 60000\nCount : 10000\n", Proto::Tcp),
            None,
            "would run past port 65535"
        );
        assert_eq!(parse_dynamic_range("A : 0\nB : 100\n", Proto::Tcp), None);
        assert_eq!(parse_dynamic_range("A : x\nB : y\n", Proto::Tcp), None);
        assert_eq!(
            parse_dynamic_range("The command failed: access denied\n", Proto::Tcp),
            None
        );
    }

    #[test]
    fn portproxy_registry_values() {
        assert_eq!(
            parse_portproxy_value("v4tov4", "0.0.0.0/8080", "192.0.2.10/80"),
            Some(PortProxy {
                kind: "v4tov4".into(),
                listen_addr: "0.0.0.0".into(),
                listen_port: 8080,
                connect_addr: "192.0.2.10".into(),
                connect_port: 80,
            })
        );
        let any = parse_portproxy_value("v4tov6", "*/2222", "fd00::5/22").unwrap();
        assert_eq!((any.listen_addr.as_str(), any.listen_port), ("*", 2222));
        assert_eq!(
            (any.connect_addr.as_str(), any.connect_port),
            ("fd00::5", 22)
        );
        let named = parse_portproxy_value("v6tov4", "::/443", "backend.example/8443").unwrap();
        assert_eq!(named.connect_addr, "backend.example");
        assert_eq!(
            parse_portproxy_value("v4tov4", "0.0.0.0", "192.0.2.10/80"),
            None
        );
        assert_eq!(
            parse_portproxy_value("v4tov4", "0.0.0.0/http", "192.0.2.10/80"),
            None
        );
        assert_eq!(
            parse_portproxy_value("v4tov4", "0.0.0.0/0", "192.0.2.10/80"),
            None
        );
        assert_eq!(
            parse_portproxy_value("v4tov4", "/80", "192.0.2.10/80"),
            None
        );
        assert_eq!(parse_portproxy_value("v4tov4", "0.0.0.0/80", ""), None);
    }

    #[test]
    fn registry_listing_tolerates_a_missing_key() {
        assert_eq!(
            string_values("SOFTWARE\\SocketForge-Test\\DoesNotExist"),
            Ok(Vec::new())
        );
        let (rules, note) = portproxy_rules();
        assert!(note.ok);
        assert_eq!(note.count, rules.len());
    }
}
