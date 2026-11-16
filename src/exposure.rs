//! Who can reach a listening port: loopback only, the local network, and what
//! Windows Firewall says about it. Pure logic over [`FirewallState`].

use crate::model::{FirewallState, FwRule, Listener, ProcInfo, Profiles, Proto, Scope};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Exposure {
    /// Bound to 127.0.0.1 / ::1: only programs on this PC can connect.
    LoopbackOnly,
    /// Bound to a network address, but the firewall lets nobody in.
    Blocked,
    /// Bound to a network address and allowed in on these profiles.
    Allowed(Profiles),
    /// Bound to a network address; the firewall could not be read.
    Network,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExposureInfo {
    pub exposure: Exposure,
    /// Indices into `FirewallState::rules` of the inbound allow rules that match.
    pub allow_rules: Vec<usize>,
    /// Indices of inbound block rules that match.
    pub block_rules: Vec<usize>,
    /// Allowed on a profile that is active on a network right now.
    pub reachable_now: bool,
    /// The process path was unknown, so program-specific rules could not be checked.
    pub uncertain: bool,
}

impl ExposureInfo {
    /// Short text for the badge.
    pub fn badge(&self) -> String {
        match self.exposure {
            Exposure::LoopbackOnly => "Loopback only".into(),
            Exposure::Blocked => "LAN, firewall blocks".into(),
            Exposure::Network => "LAN".into(),
            Exposure::Allowed(p) if p.contains(Profiles::ALL) => "Open: all profiles".into(),
            Exposure::Allowed(p) => format!("Open: {}", p.label()),
        }
    }

    /// One or two sentences for tooltips and the details panel.
    pub fn explain(&self) -> String {
        let mut s = match self.exposure {
            Exposure::LoopbackOnly => {
                "Bound to the loopback address: only programs on this PC can connect.".to_string()
            }
            Exposure::Blocked => {
                "Bound to a network address, but no enabled inbound firewall rule \
                 allows it, so other devices cannot connect."
                    .to_string()
            }
            Exposure::Network => "Bound to a network address. Windows Firewall could not be read, \
                 so it is unknown whether other devices can connect."
                .to_string(),
            Exposure::Allowed(p) => format!(
                "Bound to a network address and allowed through Windows Firewall on: {}.{}",
                p.label(),
                if self.reachable_now {
                    " One of those profiles is active now, so other devices can connect."
                } else {
                    " None of those profiles is active on the current network."
                }
            ),
        };
        if self.uncertain {
            s.push_str(
                " The program path is hidden without administrator rights, so rules for a \
                 specific program were not counted.",
            );
        }
        s
    }

    pub fn is_exposed(&self) -> bool {
        matches!(self.exposure, Exposure::Allowed(_) | Exposure::Network)
    }
}

/// Does a firewall port list (`80,443,5000-5010`, `*`, empty) include `port`?
/// Keywords such as `RPC` or `Teredo` never match a specific number.
pub fn port_spec_contains(spec: &str, port: u16) -> bool {
    let spec = spec.trim();
    if spec.is_empty() || spec == "*" {
        return true;
    }
    spec.split(',').any(|part| {
        let part = part.trim();
        match part.split_once('-') {
            Some((a, b)) => match (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                (Ok(a), Ok(b)) => (a..=b).contains(&port),
                _ => false,
            },
            None => part.parse::<u16>().map(|p| p == port).unwrap_or(false),
        }
    })
}

fn same_path(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.trim().trim_matches('"').replace('/', "\\").to_lowercase();
    norm(a) == norm(b)
}

/// Does `rule` apply to inbound traffic for this port on this process?
/// `path` empty = unknown program (program-specific rules then do not match).
pub fn rule_matches(rule: &FwRule, proto: Proto, port: u16, path: &str, services: &[&str]) -> bool {
    if !rule.enabled || !rule.inbound || !rule.proto.matches(proto) {
        return false;
    }
    if !port_spec_contains(&rule.local_ports, port) {
        return false;
    }
    if !rule.program.is_empty() {
        let system_rule = rule.program.eq_ignore_ascii_case("system");
        let ok = if system_rule {
            path.is_empty() && services.is_empty() || path.eq_ignore_ascii_case("system")
        } else {
            !path.is_empty() && same_path(&rule.program, path)
        };
        if !ok {
            return false;
        }
    }
    match rule.service.trim() {
        "" => true,
        "*" => !services.is_empty(),
        name => services.iter().any(|s| s.eq_ignore_ascii_case(name)),
    }
}

/// Inbound rules (any action, enabled or not) that mention this port.
pub fn rules_for_port(fw: &FirewallState, proto: Proto, port: u16) -> Vec<usize> {
    fw.rules
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            r.inbound
                && r.proto.matches(proto)
                && !r.local_ports.trim().is_empty()
                && r.local_ports.trim() != "*"
                && port_spec_contains(&r.local_ports, port)
        })
        .map(|(i, _)| i)
        .collect()
}

/// Rules (both directions) written for this program path.
pub fn rules_for_program(fw: &FirewallState, path: &str) -> Vec<usize> {
    if path.is_empty() {
        return Vec::new();
    }
    fw.rules
        .iter()
        .enumerate()
        .filter(|(_, r)| !r.program.is_empty() && same_path(&r.program, path))
        .map(|(i, _)| i)
        .collect()
}

/// Works out the exposure of one listener.
pub fn classify(l: &Listener, proc: Option<&ProcInfo>, fw: &FirewallState) -> ExposureInfo {
    let mut info = ExposureInfo {
        exposure: Exposure::LoopbackOnly,
        allow_rules: Vec::new(),
        block_rules: Vec::new(),
        reachable_now: false,
        uncertain: false,
    };
    if l.scope() == Scope::Loopback {
        return info;
    }
    if !fw.available {
        info.exposure = Exposure::Network;
        return info;
    }
    let path = if l.pid == 4 {
        "System"
    } else {
        proc.map(|p| p.path.as_str()).unwrap_or("")
    };
    let services: Vec<&str> = proc
        .map(|p| p.services.iter().map(|s| s.name.as_str()).collect())
        .unwrap_or_default();

    let mut allowed = Profiles::NONE;
    let mut blocked = Profiles::NONE;
    for (i, rule) in fw.rules.iter().enumerate() {
        if !rule_matches(rule, l.proto, l.port, path, &services) {
            continue;
        }
        if rule.allow {
            info.allow_rules.push(i);
            allowed = allowed.union(rule.profiles);
        } else {
            info.block_rules.push(i);
            blocked = blocked.union(rule.profiles);
        }
    }
    info.uncertain = path.is_empty()
        && fw.rules.iter().any(|r| {
            r.enabled
                && r.inbound
                && r.allow
                && !r.program.is_empty()
                && !r.program.eq_ignore_ascii_case("system")
                && r.proto.matches(l.proto)
                && port_spec_contains(&r.local_ports, l.port)
        });

    // Per profile: firewall off = open; block rules win over allow rules;
    // otherwise the default action decides.
    let mut open = Profiles::NONE;
    for profile in [Profiles::DOMAIN, Profiles::PRIVATE, Profiles::PUBLIC] {
        let is_open = if !fw.enabled.contains(profile) {
            true
        } else if blocked.contains(profile) {
            false
        } else if allowed.contains(profile) {
            true
        } else {
            !fw.default_inbound_block.contains(profile)
        };
        if is_open {
            open = open.union(profile);
        }
    }
    if open.is_empty() {
        info.exposure = Exposure::Blocked;
    } else {
        info.exposure = Exposure::Allowed(open);
        info.reachable_now = open.intersects(fw.active);
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FwProto, ServiceRef};

    fn rule(name: &str, allow: bool, ports: &str, program: &str, profiles: Profiles) -> FwRule {
        FwRule {
            name: name.into(),
            group: String::new(),
            description: String::new(),
            enabled: true,
            inbound: true,
            allow,
            proto: FwProto::Tcp,
            local_ports: ports.into(),
            remote_ports: "*".into(),
            local_addrs: "*".into(),
            remote_addrs: "*".into(),
            program: program.into(),
            service: String::new(),
            profiles,
        }
    }

    fn fw(rules: Vec<FwRule>) -> FirewallState {
        FirewallState {
            available: true,
            error: None,
            enabled: Profiles::ALL,
            active: Profiles::PRIVATE,
            default_inbound_block: Profiles::ALL,
            rules,
        }
    }

    fn listener(addr: &str, port: u16) -> Listener {
        Listener {
            proto: Proto::Tcp,
            addr: addr.parse().unwrap(),
            port,
            pid: 100,
            created: None,
        }
    }

    fn proc(path: &str, services: &[&str]) -> ProcInfo {
        ProcInfo {
            pid: 100,
            name: "app.exe".into(),
            path: path.into(),
            services: services
                .iter()
                .map(|s| ServiceRef {
                    name: s.to_string(),
                    display: s.to_string(),
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn port_specs() {
        assert!(port_spec_contains("*", 1));
        assert!(port_spec_contains("", 1));
        assert!(port_spec_contains("80,443", 443));
        assert!(port_spec_contains("80, 5000-5010", 5005));
        assert!(port_spec_contains("5000-5010", 5010));
        assert!(!port_spec_contains("5000-5010", 5011));
        assert!(!port_spec_contains("RPC", 135));
        assert!(!port_spec_contains("RPC-EPMap,Teredo", 3544));
        assert!(!port_spec_contains("80", 8080));
    }

    #[test]
    fn loopback_is_never_exposed() {
        let f = fw(vec![rule("all", true, "*", "", Profiles::ALL)]);
        for a in ["127.0.0.1", "::1", "127.1.2.3"] {
            let e = classify(&listener(a, 3000), None, &f);
            assert_eq!(e.exposure, Exposure::LoopbackOnly);
            assert!(!e.is_exposed());
        }
    }

    #[test]
    fn no_rule_means_blocked() {
        let f = fw(vec![rule("other", true, "80", "", Profiles::ALL)]);
        let e = classify(
            &listener("0.0.0.0", 3000),
            Some(&proc("C:\\a.exe", &[])),
            &f,
        );
        assert_eq!(e.exposure, Exposure::Blocked);
        assert!(e.allow_rules.is_empty());
        assert!(!e.is_exposed());
    }

    #[test]
    fn port_rule_allows_on_its_profiles() {
        let f = fw(vec![rule("dev", true, "3000-3010", "", Profiles::PRIVATE)]);
        let e = classify(
            &listener("0.0.0.0", 3000),
            Some(&proc("C:\\a.exe", &[])),
            &f,
        );
        assert_eq!(e.exposure, Exposure::Allowed(Profiles::PRIVATE));
        assert!(e.reachable_now);
        assert_eq!(e.allow_rules, vec![0]);
        assert_eq!(e.badge(), "Open: Private");

        let mut f2 = f.clone();
        f2.active = Profiles::PUBLIC;
        let e = classify(&listener("::", 3000), Some(&proc("C:\\a.exe", &[])), &f2);
        assert!(!e.reachable_now);
    }

    #[test]
    fn program_rule_needs_the_same_path() {
        let f = fw(vec![rule(
            "node",
            true,
            "*",
            "C:\\Program Files\\nodejs\\node.exe",
            Profiles::ALL,
        )]);
        let hit = proc("c:\\program files\\nodejs\\NODE.EXE", &[]);
        let miss = proc("C:\\other\\node.exe", &[]);
        let l = listener("192.168.1.5", 8080);
        assert_eq!(
            classify(&l, Some(&hit), &f).exposure,
            Exposure::Allowed(Profiles::ALL)
        );
        assert_eq!(classify(&l, Some(&miss), &f).exposure, Exposure::Blocked);
        // Unknown path: not counted, but flagged as uncertain.
        let unknown = classify(&l, Some(&proc("", &[])), &f);
        assert_eq!(unknown.exposure, Exposure::Blocked);
        assert!(unknown.uncertain);
    }

    #[test]
    fn block_rules_win_and_disabled_rules_do_not_count() {
        let mut off = rule("off", true, "9000", "", Profiles::ALL);
        off.enabled = false;
        let f = fw(vec![
            rule("allow", true, "8080", "", Profiles::ALL),
            rule("block public", false, "8080", "", Profiles::PUBLIC),
            off,
        ]);
        let p = proc("C:\\a.exe", &[]);
        let e = classify(&listener("0.0.0.0", 8080), Some(&p), &f);
        assert_eq!(
            e.exposure,
            Exposure::Allowed(Profiles::DOMAIN.union(Profiles::PRIVATE))
        );
        assert_eq!(e.block_rules, vec![1]);
        let e = classify(&listener("0.0.0.0", 9000), Some(&p), &f);
        assert_eq!(e.exposure, Exposure::Blocked);
    }

    #[test]
    fn firewall_off_or_unreadable() {
        let mut f = fw(vec![]);
        f.enabled = Profiles::DOMAIN.union(Profiles::PUBLIC);
        let e = classify(&listener("0.0.0.0", 5000), None, &f);
        assert_eq!(e.exposure, Exposure::Allowed(Profiles::PRIVATE));
        let unreadable = FirewallState::default();
        let e = classify(&listener("0.0.0.0", 5000), None, &unreadable);
        assert_eq!(e.exposure, Exposure::Network);
        assert!(e.is_exposed());
    }

    #[test]
    fn service_and_direction_and_protocol() {
        let mut svc = rule("dns", true, "5353", "", Profiles::ALL);
        svc.service = "Dnscache".into();
        svc.proto = FwProto::Udp;
        let mut out = rule("out", true, "5353", "", Profiles::ALL);
        out.inbound = false;
        out.proto = FwProto::Any;
        let f = fw(vec![svc, out]);
        let mut l = listener("0.0.0.0", 5353);
        l.proto = Proto::Udp;
        let host = proc("C:\\Windows\\System32\\svchost.exe", &["dnscache"]);
        let other = proc("C:\\Windows\\System32\\svchost.exe", &["Other"]);
        assert!(classify(&l, Some(&host), &f).is_exposed());
        assert!(!classify(&l, Some(&other), &f).is_exposed());
        l.proto = Proto::Tcp;
        assert!(!classify(&l, Some(&host), &f).is_exposed());
        assert_eq!(rules_for_port(&f, Proto::Udp, 5353), vec![0]);
        assert_eq!(
            rules_for_program(
                &fw(vec![rule("p", true, "*", "C:/X/y.exe", Profiles::ALL)]),
                "c:\\x\\Y.exe"
            ),
            vec![0]
        );
    }
}
