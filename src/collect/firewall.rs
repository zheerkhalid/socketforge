//! Collector: Windows Firewall state and rules through the `INetFwPolicy2`
//! COM interface. Strictly read-only; works without administrator rights.

use crate::model::{FirewallState, FwProto, FwRule, Profiles};
use crate::util::{from_wide, wide};
use std::collections::HashMap;
use std::ffi::c_void;
use windows::core::{IUnknown, Interface, BSTR, PCWSTR, VARIANT};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NetFwPolicy2, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK,
    NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NET_FW_RULE_DIR_IN,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::UI::Shell::SHLoadIndirectString;

const RPC_E_CHANGED_MODE: i32 = 0x8001_0106_u32 as i32;
const VT_DISPATCH: u16 = 9;
const VT_UNKNOWN: u16 = 13;

/// The firewall API's profile bit mask (1 = domain, 2 = private, 4 = public,
/// 0x7FFFFFFF = all) as `Profiles`.
pub fn profiles_from_mask(mask: i32) -> Profiles {
    Profiles((mask & 7) as u8)
}

/// A rule as the COM interface hands it out, before tidying.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawRule {
    pub name: String,
    pub group: String,
    pub description: String,
    pub enabled: bool,
    /// `NET_FW_RULE_DIRECTION`: 1 = in, 2 = out.
    pub direction: i32,
    /// `NET_FW_ACTION`: 0 = block, 1 = allow.
    pub action: i32,
    /// IANA protocol number; 256 = any.
    pub protocol: i32,
    pub local_ports: String,
    pub remote_ports: String,
    pub local_addrs: String,
    pub remote_addrs: String,
    /// Environment variables already expanded.
    pub program: String,
    pub service: String,
    pub profiles: i32,
}

/// Port lists are kept as stored, minus stray spaces (`80, 443` -> `80,443`).
pub fn tidy_ports(spec: &str) -> String {
    spec.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

/// Converts the numbers of the firewall API into the model's rule.
pub fn rule_from_raw(raw: RawRule) -> FwRule {
    let proto = FwProto::from_number(raw.protocol);
    // Ports only mean something for TCP and UDP (and "any").
    let has_ports = matches!(proto, FwProto::Tcp | FwProto::Udp | FwProto::Any);
    FwRule {
        name: raw.name.trim().to_string(),
        group: raw.group.trim().to_string(),
        description: raw.description.trim().to_string(),
        enabled: raw.enabled,
        inbound: raw.direction == NET_FW_RULE_DIR_IN.0,
        allow: raw.action == NET_FW_ACTION_ALLOW.0,
        proto,
        local_ports: if has_ports {
            tidy_ports(&raw.local_ports)
        } else {
            String::new()
        },
        remote_ports: if has_ports {
            tidy_ports(&raw.remote_ports)
        } else {
            String::new()
        },
        local_addrs: raw.local_addrs.trim().to_string(),
        remote_addrs: raw.remote_addrs.trim().to_string(),
        program: raw.program.trim().trim_matches('"').to_string(),
        service: raw.service.trim().to_string(),
        profiles: profiles_from_mask(raw.profiles),
    }
}

/// Expands `%ProgramFiles%` style variables.
pub(crate) fn expand_env(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let src = wide(s);
    let mut buf = vec![0u16; 1024];
    loop {
        let n = unsafe { ExpandEnvironmentStringsW(PCWSTR(src.as_ptr()), Some(&mut buf)) } as usize;
        if n == 0 {
            return s.to_string();
        }
        if n <= buf.len() {
            return from_wide(&buf);
        }
        buf.resize(n + 1, 0);
    }
}

/// Resolves `@FirewallAPI.dll,-28502` style resource references (rule groups).
fn resolve_indirect(text: &str, cache: &mut HashMap<String, String>) -> String {
    if !text.starts_with('@') {
        return text.to_string();
    }
    if let Some(hit) = cache.get(text) {
        return hit.clone();
    }
    let src = wide(text);
    let mut buf = vec![0u16; 1024];
    let resolved = match unsafe { SHLoadIndirectString(PCWSTR(src.as_ptr()), &mut buf, None) } {
        Ok(()) => from_wide(&buf),
        Err(_) => text.to_string(),
    };
    cache.insert(text.to_string(), resolved.clone());
    resolved
}

/// Balances `CoInitializeEx` when this collector was the one to initialise COM.
struct ComGuard(bool);

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.0 {
            unsafe { CoUninitialize() };
        }
    }
}

fn text(value: windows::core::Result<BSTR>) -> String {
    value.map(|b| b.to_string()).unwrap_or_default()
}

unsafe fn read_rule(rule: &INetFwRule, groups: &mut HashMap<String, String>) -> FwRule {
    let raw = RawRule {
        name: resolve_indirect(&text(rule.Name()), groups),
        group: resolve_indirect(&text(rule.Grouping()), groups),
        description: resolve_indirect(&text(rule.Description()), groups),
        enabled: rule.Enabled().map(|b| b.as_bool()).unwrap_or(false),
        direction: rule.Direction().map(|d| d.0).unwrap_or(0),
        action: rule.Action().map(|a| a.0).unwrap_or(NET_FW_ACTION_BLOCK.0),
        protocol: rule.Protocol().unwrap_or(256),
        local_ports: text(rule.LocalPorts()),
        remote_ports: text(rule.RemotePorts()),
        local_addrs: text(rule.LocalAddresses()),
        remote_addrs: text(rule.RemoteAddresses()),
        program: expand_env(&text(rule.ApplicationName())),
        service: text(rule.ServiceName()),
        profiles: rule.Profiles().unwrap_or(0),
    };
    rule_from_raw(raw)
}

/// The COM object inside a VARIANT of type VT_DISPATCH / VT_UNKNOWN.
unsafe fn variant_object(v: &VARIANT) -> Option<IUnknown> {
    // VARIANT layout: the type tag in the first two bytes, the value at offset 8.
    let base = v as *const VARIANT as *const u8;
    let vt = *(base as *const u16);
    if vt != VT_DISPATCH && vt != VT_UNKNOWN {
        return None;
    }
    let ptr = *(base.add(8) as *const *mut c_void);
    IUnknown::from_raw_borrowed(&ptr).cloned()
}

unsafe fn read() -> Result<FirewallState, String> {
    let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
    if hr.is_err() && hr.0 != RPC_E_CHANGED_MODE {
        return Err(format!("COM could not be initialised ({hr})."));
    }
    // Declared first, so it is dropped after every COM object below.
    let _com = ComGuard(hr.is_ok());

    let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
        .map_err(|e| format!("Windows Firewall could not be opened ({}).", e.code()))?;

    let mut state = FirewallState {
        available: true,
        ..Default::default()
    };
    state.active = profiles_from_mask(policy.CurrentProfileTypes().unwrap_or(0));
    for (api, profile) in [
        (NET_FW_PROFILE2_DOMAIN, Profiles::DOMAIN),
        (NET_FW_PROFILE2_PRIVATE, Profiles::PRIVATE),
        (NET_FW_PROFILE2_PUBLIC, Profiles::PUBLIC),
    ] {
        if policy
            .get_FirewallEnabled(api)
            .map(|b| b.as_bool())
            .unwrap_or(false)
        {
            state.enabled = state.enabled.union(profile);
        }
        // Unknown counts as "block": that is the Windows default.
        let blocks = policy
            .get_DefaultInboundAction(api)
            .map(|a| a != NET_FW_ACTION_ALLOW)
            .unwrap_or(true);
        if blocks {
            state.default_inbound_block = state.default_inbound_block.union(profile);
        }
    }

    let rules = policy
        .Rules()
        .map_err(|e| format!("The firewall rules could not be read ({}).", e.code()))?;
    let enumerator: IEnumVARIANT = rules
        ._NewEnum()
        .and_then(|unknown| unknown.cast())
        .map_err(|e| format!("The firewall rules could not be listed ({}).", e.code()))?;
    let mut groups = HashMap::new();
    loop {
        let mut batch: [VARIANT; 64] = std::array::from_fn(|_| VARIANT::default());
        let mut fetched = 0u32;
        let hr = enumerator.Next(&mut batch, &mut fetched);
        for v in batch.iter().take(fetched as usize) {
            if let Some(rule) = variant_object(v).and_then(|o| o.cast::<INetFwRule>().ok()) {
                state.rules.push(read_rule(&rule, &mut groups));
            }
        }
        // S_FALSE: fewer than asked for, the list is finished.
        if hr.0 != 0 || fetched == 0 {
            break;
        }
    }
    Ok(state)
}

/// Reads the firewall. Never fails: when the firewall API is unavailable the
/// state says so (`available == false`, `error` set).
pub fn collect() -> FirewallState {
    match unsafe { read() } {
        Ok(state) => state,
        Err(error) => FirewallState {
            available: false,
            error: Some(error),
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_masks() {
        assert_eq!(profiles_from_mask(0), Profiles::NONE);
        assert_eq!(profiles_from_mask(1), Profiles::DOMAIN);
        assert_eq!(profiles_from_mask(2), Profiles::PRIVATE);
        assert_eq!(profiles_from_mask(4), Profiles::PUBLIC);
        assert_eq!(
            profiles_from_mask(6),
            Profiles::PRIVATE.union(Profiles::PUBLIC)
        );
        assert_eq!(profiles_from_mask(0x7FFF_FFFF), Profiles::ALL);
    }

    #[test]
    fn port_lists_are_tidied_but_kept() {
        assert_eq!(tidy_ports("80, 443 ,5000-5010"), "80,443,5000-5010");
        assert_eq!(tidy_ports("*"), "*");
        assert_eq!(tidy_ports(""), "");
        assert_eq!(tidy_ports(" RPC "), "RPC");
        assert_eq!(tidy_ports("RPC-EPMap"), "RPC-EPMap");
    }

    #[test]
    fn rules_are_mapped_from_the_api_numbers() {
        let rule = rule_from_raw(RawRule {
            name: " Example Web Server ".into(),
            group: "Example Group".into(),
            description: "Allows the example.".into(),
            enabled: true,
            direction: 1,
            action: 1,
            protocol: 6,
            local_ports: "8080, 8443".into(),
            remote_ports: "*".into(),
            local_addrs: "*".into(),
            remote_addrs: "LocalSubnet".into(),
            program: "\"D:\\Tools\\web.exe\"".into(),
            service: "".into(),
            profiles: 6,
        });
        assert_eq!(rule.name, "Example Web Server");
        assert!(rule.enabled && rule.inbound && rule.allow);
        assert_eq!(rule.proto, FwProto::Tcp);
        assert_eq!(rule.local_ports, "8080,8443");
        assert_eq!(rule.remote_ports, "*");
        assert_eq!(rule.remote_addrs, "LocalSubnet");
        assert_eq!(rule.program, "D:\\Tools\\web.exe");
        assert_eq!(rule.profiles.label(), "Private, Public");

        let out = rule_from_raw(RawRule {
            direction: 2,
            action: 0,
            protocol: 17,
            profiles: 0x7FFF_FFFF,
            ..Default::default()
        });
        assert!(!out.inbound && !out.allow && !out.enabled);
        assert_eq!(out.proto, FwProto::Udp);
        assert_eq!(out.profiles, Profiles::ALL);

        // ICMP rules have no ports, whatever the API returns; "any" keeps them.
        let icmp = rule_from_raw(RawRule {
            protocol: 1,
            local_ports: "*".into(),
            ..Default::default()
        });
        assert_eq!(icmp.proto, FwProto::Other(1));
        assert_eq!(icmp.local_ports, "");
        let any = rule_from_raw(RawRule {
            protocol: 256,
            local_ports: "*".into(),
            ..Default::default()
        });
        assert_eq!(any.proto, FwProto::Any);
        assert_eq!(any.local_ports, "*");
    }

    #[test]
    fn environment_variables_are_expanded() {
        let root = std::env::var("SystemRoot").unwrap();
        assert_eq!(
            expand_env("%SystemRoot%\\System32\\svchost.exe").to_lowercase(),
            format!("{root}\\System32\\svchost.exe").to_lowercase()
        );
        assert_eq!(expand_env("D:\\Tools\\app.exe"), "D:\\Tools\\app.exe");
        assert_eq!(expand_env("System"), "System");
    }

    #[test]
    fn reads_the_firewall_without_elevation() {
        let state = collect();
        assert!(
            state.available,
            "the firewall API is readable by every user"
        );
        assert!(state.error.is_none());
        assert!(!state.rules.is_empty());
        assert!(state.rules.iter().any(|r| r.inbound));
        // Twice on the same thread: COM is balanced.
        assert_eq!(collect().rules.len(), state.rules.len());
    }
}
