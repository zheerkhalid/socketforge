//! Collector: which running Windows services live in which process. Read-only;
//! needs no administrator rights.

use crate::model::ServiceRef;
use std::collections::HashMap;
use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW,
    SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE,
    SERVICE_ACTIVE, SERVICE_WIN32,
};

const ERROR_MORE_DATA: u32 = 234;

/// Closes a service handle when it goes out of scope.
pub(crate) struct ScHandle(pub SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

unsafe fn pwstr_text(p: windows::core::PWSTR) -> String {
    if p.is_null() {
        String::new()
    } else {
        String::from_utf16_lossy(p.as_wide())
    }
}

/// Running Win32 services grouped by the process that hosts them.
pub fn running_by_pid() -> Result<HashMap<u32, Vec<ServiceRef>>, String> {
    let mut map: HashMap<u32, Vec<ServiceRef>> = HashMap::new();
    unsafe {
        let scm = OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
        )
        .map_err(|e| format!("The service list could not be opened ({}).", e.code()))?;
        let scm = ScHandle(scm);

        // 8-byte aligned storage: the entries contain pointers.
        let mut buf: Vec<u64> = vec![0; 8192];
        let mut resume = 0u32;
        for _ in 0..64 {
            let mut needed = 0u32;
            let mut returned = 0u32;
            let bytes = std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, buf.len() * 8);
            let result = EnumServicesStatusExW(
                scm.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                Some(bytes),
                &mut needed,
                &mut returned,
                Some(&mut resume),
                PCWSTR::null(),
            );
            let more = match &result {
                Ok(()) => false,
                Err(e) if e.code().0 as u32 & 0xFFFF == ERROR_MORE_DATA => true,
                Err(e) => {
                    return Err(format!(
                        "The service list could not be read ({}).",
                        e.code()
                    ))
                }
            };
            let entries = std::slice::from_raw_parts(
                buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                returned as usize,
            );
            for e in entries {
                let pid = e.ServiceStatusProcess.dwProcessId;
                if pid == 0 {
                    continue;
                }
                map.entry(pid).or_default().push(ServiceRef {
                    name: pwstr_text(e.lpServiceName),
                    display: pwstr_text(e.lpDisplayName),
                });
            }
            if !more {
                break;
            }
            if returned == 0 {
                // Not even one entry fitted: grow and go on from the resume point.
                let want = (needed as usize / 8 + 1).max(buf.len() * 2);
                buf = vec![0; want];
            }
        }
    }
    for list in map.values_mut() {
        list.sort_by_key(|a| a.name.to_lowercase());
        list.dedup();
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_running_services_without_elevation() {
        let map = running_by_pid().expect("the service list is readable by every user");
        assert!(!map.is_empty());
        assert!(map.keys().all(|pid| *pid != 0));
        assert!(map
            .values()
            .all(|list| !list.is_empty() && list.iter().all(|s| !s.name.is_empty())));
    }
}
