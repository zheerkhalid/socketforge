//! Process details for the PIDs that own sockets: name, path, command line,
//! user, start time, parent, hosted services, version-resource texts.
//! Read-only; works without administrator rights (with fewer details for
//! processes of other accounts).

use super::services;
use crate::model::{ProcInfo, ServiceRef};
use crate::util::{filetime_to_unix, from_wide, wide};
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::time::{Duration, Instant};
use windows::core::{PCWSTR, PWSTR};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, FILETIME, HANDLE, HLOCAL, UNICODE_STRING,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, TokenUser, PSID, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

/// How often the service list is read again.
const SERVICES_MAX_AGE: Duration = Duration::from_secs(10);
/// `ProcessCommandLineInformation`: readable with limited rights since Windows 8.1.
const PROCESS_COMMAND_LINE_INFORMATION: i32 = 60;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;

struct Entry {
    info: ProcInfo,
    /// Creation time in FILETIME ticks: tells a reused PID from the old process.
    start_ticks: Option<i64>,
    /// The account as a SID string (`S-1-5-18`); empty when unknown.
    sid: String,
}

/// Process details kept between refreshes, keyed by PID and start time.
#[derive(Default)]
pub struct ProcCache {
    entries: HashMap<u32, Entry>,
    /// SID string -> `DOMAIN\user`.
    accounts: HashMap<String, String>,
    /// Lower-case path -> (description, company).
    versions: HashMap<String, (String, String)>,
    services: HashMap<u32, Vec<ServiceRef>>,
    services_read: Option<Instant>,
    system_root: Option<String>,
}

/// Closes a kernel handle when it goes out of scope.
pub(crate) struct Handle(pub HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Image name and parent PID of every running process. Works for all
/// processes, whatever the rights of this one.
pub(crate) fn process_table() -> HashMap<u32, (String, u32)> {
    let mut map = HashMap::new();
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return map;
        };
        let snapshot = Handle(snapshot);
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snapshot.0, &mut entry).is_ok() {
            loop {
                map.insert(
                    entry.th32ProcessID,
                    (from_wide(&entry.szExeFile), entry.th32ParentProcessID),
                );
                if Process32NextW(snapshot.0, &mut entry).is_err() {
                    break;
                }
            }
        }
    }
    map
}

/// `c:\windows\`: lower case, with a trailing backslash.
fn system_root() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    format!("{}\\", root.trim_end_matches('\\').to_lowercase())
}

/// Is `path` inside the Windows folder? `root` as `system_root()` returns it.
pub(crate) fn under_root(path: &str, root: &str) -> bool {
    let path = path.replace('/', "\\").to_lowercase();
    let path = path.strip_prefix("\\\\?\\").unwrap_or(&path);
    !root.is_empty() && path.starts_with(root)
}

/// SYSTEM, LOCAL SERVICE and NETWORK SERVICE.
pub(crate) fn is_service_account(sid: &str) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-19" | "S-1-5-20")
}

/// Windows processes that never let other processes look at them.
fn is_protected_windows_name(name: &str) -> bool {
    const NAMES: [&str; 12] = [
        "registry",
        "secure system",
        "memory compression",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "lsaiso.exe",
        "msmpeng.exe",
        "nissrv.exe",
        "sgrmbroker.exe",
    ];
    NAMES.contains(&name.to_lowercase().as_str())
}

/// What the model calls a Windows process: PID 0/4, services running as
/// SYSTEM / LOCAL SERVICE / NETWORK SERVICE, anything under `%SystemRoot%`.
/// When access was denied the account is unknown: a process that hosts
/// services, or one of the protected Windows processes, is then taken as
/// Windows' own.
pub(crate) fn is_system_process(info: &ProcInfo, sid: &str, root: &str) -> bool {
    if info.pid == 0 || info.pid == 4 {
        return true;
    }
    if !info.path.is_empty() && under_root(&info.path, root) {
        return true;
    }
    if !info.services.is_empty() && is_service_account(sid) {
        return true;
    }
    info.limited
        && info.path.is_empty()
        && (!info.services.is_empty() || is_protected_windows_name(&info.name))
}

fn ticks(ft: FILETIME) -> i64 {
    ((ft.dwHighDateTime as i64) << 32) | ft.dwLowDateTime as i64
}

fn open_limited(pid: u32) -> Option<Handle> {
    unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .ok()
        .map(Handle)
}

fn start_ticks(process: &Handle) -> Option<i64> {
    let mut created = FILETIME::default();
    let (mut exited, mut kernel, mut user) = (created, created, created);
    unsafe {
        GetProcessTimes(process.0, &mut created, &mut exited, &mut kernel, &mut user).ok()?;
    }
    Some(ticks(created)).filter(|t| *t > 0)
}

fn image_path(process: &Handle) -> String {
    let mut buf = vec![0u16; 1024];
    loop {
        let mut len = buf.len() as u32;
        let ok = unsafe {
            QueryFullProcessImageNameW(
                process.0,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
        }
        .is_ok();
        if ok {
            return String::from_utf16_lossy(&buf[..(len as usize).min(buf.len())]);
        }
        if buf.len() >= 32_768 {
            return String::new();
        }
        buf = vec![0u16; 32_768];
    }
}

fn command_line(process: &Handle) -> String {
    // 8-byte aligned: the buffer starts with a UNICODE_STRING.
    let mut buf: Vec<u64> = vec![0; 1024];
    for _ in 0..3 {
        let mut len = 0u32;
        let status = unsafe {
            NtQueryInformationProcess(
                process.0,
                PROCESSINFOCLASS(PROCESS_COMMAND_LINE_INFORMATION),
                buf.as_mut_ptr() as *mut c_void,
                (buf.len() * 8) as u32,
                &mut len,
            )
        };
        if status.0 == STATUS_INFO_LENGTH_MISMATCH {
            let want = (len as usize / 8 + 2).max(buf.len() * 2);
            if want > 16_384 {
                return String::new();
            }
            buf = vec![0; want];
            continue;
        }
        if status.0 < 0 {
            return String::new();
        }
        // SAFETY: on success the buffer holds a UNICODE_STRING whose text
        // lies inside the same buffer; that is checked before it is read.
        unsafe {
            let us = &*(buf.as_ptr() as *const UNICODE_STRING);
            let start = us.Buffer.0 as usize;
            let bytes = us.Length as usize;
            let lo = buf.as_ptr() as usize;
            let hi = lo + buf.len() * 8;
            if us.Buffer.is_null() || start < lo || start + bytes > hi || !start.is_multiple_of(2) {
                return String::new();
            }
            let text = std::slice::from_raw_parts(us.Buffer.0 as *const u16, bytes / 2);
            return String::from_utf16_lossy(text).trim().to_string();
        }
    }
    String::new()
}

/// `(SID string, DOMAIN\user)` of the account a process runs as.
fn account_of(process: &Handle, names: &mut HashMap<String, String>) -> (String, String) {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(process.0, TOKEN_QUERY, &mut token).is_err() {
            return Default::default();
        }
        let token = Handle(token);
        let mut buf: Vec<u64> = vec![0; 64];
        let mut len = 0u32;
        if GetTokenInformation(
            token.0,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            (buf.len() * 8) as u32,
            &mut len,
        )
        .is_err()
        {
            return Default::default();
        }
        let sid = (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid;
        let text = sid_text(sid);
        if text.is_empty() {
            return Default::default();
        }
        if let Some(name) = names.get(&text) {
            return (text, name.clone());
        }
        let name = account_name(sid);
        names.insert(text.clone(), name.clone());
        (text, name)
    }
}

unsafe fn sid_text(sid: PSID) -> String {
    let mut out = PWSTR::null();
    if ConvertSidToStringSidW(sid, &mut out).is_err() || out.is_null() {
        return String::new();
    }
    let text = String::from_utf16_lossy(out.as_wide());
    let _ = LocalFree(HLOCAL(out.0 as *mut c_void));
    text
}

/// `DOMAIN\user` for a SID; empty when it does not resolve.
pub(crate) unsafe fn account_name(sid: PSID) -> String {
    let mut name = [0u16; 512];
    let mut domain = [0u16; 512];
    let (mut name_len, mut domain_len) = (name.len() as u32, domain.len() as u32);
    let mut kind = SID_NAME_USE::default();
    if LookupAccountSidW(
        PCWSTR::null(),
        sid,
        PWSTR(name.as_mut_ptr()),
        &mut name_len,
        PWSTR(domain.as_mut_ptr()),
        &mut domain_len,
        &mut kind,
    )
    .is_err()
    {
        return String::new();
    }
    let (name, domain) = (from_wide(&name), from_wide(&domain));
    if domain.is_empty() {
        name
    } else {
        format!("{domain}\\{name}")
    }
}

/// `(FileDescription, CompanyName)` from the version resource of a file.
pub(crate) fn version_texts(path: &str) -> (String, String) {
    let file = wide(path);
    unsafe {
        let size = GetFileVersionInfoSizeW(PCWSTR(file.as_ptr()), None);
        if size == 0 {
            return Default::default();
        }
        let mut data = vec![0u8; size as usize];
        if GetFileVersionInfoW(
            PCWSTR(file.as_ptr()),
            0,
            size,
            data.as_mut_ptr() as *mut c_void,
        )
        .is_err()
        {
            return Default::default();
        }
        let block = data.as_ptr() as *const c_void;

        // The languages the file has texts for, then the usual suspects.
        let mut langs: Vec<(u16, u16)> = Vec::new();
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let mut len = 0u32;
        let key = wide("\\VarFileInfo\\Translation");
        if VerQueryValueW(block, PCWSTR(key.as_ptr()), &mut ptr, &mut len).as_bool()
            && !ptr.is_null()
        {
            let pairs = std::slice::from_raw_parts(ptr as *const [u16; 2], len as usize / 4);
            langs.extend(pairs.iter().map(|p| (p[0], p[1])));
        }
        langs.extend([(0x0409, 1200), (0x0409, 1252), (0x0000, 1200), (0x0409, 0)]);

        let query = |name: &str| -> String {
            for (lang, codepage) in &langs {
                let key = wide(&format!(
                    "\\StringFileInfo\\{lang:04x}{codepage:04x}\\{name}"
                ));
                let mut ptr: *mut c_void = std::ptr::null_mut();
                let mut len = 0u32;
                if VerQueryValueW(block, PCWSTR(key.as_ptr()), &mut ptr, &mut len).as_bool()
                    && !ptr.is_null()
                    && len > 0
                {
                    let text = std::slice::from_raw_parts(ptr as *const u16, len as usize);
                    let text = from_wide(text).trim().to_string();
                    if !text.is_empty() {
                        return text;
                    }
                }
            }
            String::new()
        };
        (query("FileDescription"), query("CompanyName"))
    }
}

fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or("").to_string()
}

impl ProcCache {
    fn refresh_services(&mut self) {
        let fresh = self
            .services_read
            .map(|t| t.elapsed() < SERVICES_MAX_AGE)
            .unwrap_or(false);
        if fresh {
            return;
        }
        // On failure the previous map stays in use.
        if let Ok(map) = services::running_by_pid() {
            self.services = map;
        }
        self.services_read = Some(Instant::now());
    }

    /// Reads everything about one process that does not change while it runs.
    fn inspect(
        &mut self,
        pid: u32,
        name: &str,
        parent: Option<u32>,
        process: Option<&Handle>,
        started: Option<i64>,
    ) -> Entry {
        let mut info = ProcInfo {
            pid,
            name: name.to_string(),
            parent,
            started: started.and_then(filetime_to_unix),
            limited: process.is_none(),
            ..Default::default()
        };
        let mut sid = String::new();
        if let Some(process) = process {
            info.path = image_path(process);
            info.cmdline = command_line(process);
            (sid, info.user) = account_of(process, &mut self.accounts);
            if info.name.is_empty() {
                info.name = file_name(&info.path);
            }
            if !info.path.is_empty() {
                let key = info.path.to_lowercase();
                let texts = match self.versions.get(&key) {
                    Some(t) => t.clone(),
                    None => {
                        let t = version_texts(&info.path);
                        self.versions.insert(key, t.clone());
                        t
                    }
                };
                (info.description, info.company) = texts;
            }
        }
        Entry {
            info,
            start_ticks: started,
            sid,
        }
    }

    /// Details for every PID in `pids`. Processes seen before (same PID, same
    /// start time) come from the cache; only new ones are inspected.
    pub fn resolve(&mut self, pids: &HashSet<u32>) -> HashMap<u32, ProcInfo> {
        let table = process_table();
        self.refresh_services();
        let root = self.system_root.get_or_insert_with(system_root).clone();
        if !table.is_empty() {
            self.entries.retain(|pid, _| table.contains_key(pid));
        }
        // Start times of parents, to notice a parent PID that was reused.
        let mut parent_starts: HashMap<u32, Option<i64>> = HashMap::new();

        let mut out = HashMap::with_capacity(pids.len());
        for &pid in pids {
            if pid == 0 || pid == 4 {
                out.insert(
                    pid,
                    ProcInfo {
                        pid,
                        name: if pid == 0 {
                            "System Idle Process"
                        } else {
                            "System"
                        }
                        .to_string(),
                        parent: None,
                        is_system: true,
                        ..Default::default()
                    },
                );
                continue;
            }
            let listed = table.get(&pid);
            let name = listed.map(|(n, _)| n.as_str()).unwrap_or("");
            let parent = listed.map(|(_, p)| *p).filter(|p| *p != pid);
            let process = open_limited(pid);
            let started = process.as_ref().and_then(start_ticks);

            let cached = self.entries.get(&pid).is_some_and(|e| {
                e.start_ticks == started
                    && e.info.limited == process.is_none()
                    && (started.is_some() || e.info.name.eq_ignore_ascii_case(name))
            });
            if !cached {
                if listed.is_none() && process.is_none() {
                    // Gone already (or never visible): nothing worth caching.
                    out.insert(
                        pid,
                        ProcInfo {
                            pid,
                            limited: true,
                            ..Default::default()
                        },
                    );
                    continue;
                }
                let entry = self.inspect(pid, name, parent, process.as_ref(), started);
                self.entries.insert(pid, entry);
            }
            drop(process);

            // The parts that can change while the process runs.
            let services = self.services.get(&pid).cloned().unwrap_or_default();
            let Some(entry) = self.entries.get_mut(&pid) else {
                continue;
            };
            entry.info.services = services;
            entry.info.parent = parent;
            entry.info.parent_name = String::new();
            if let Some(ppid) = parent {
                if let Some((parent_name, _)) = table.get(&ppid) {
                    let parent_start = *parent_starts
                        .entry(ppid)
                        .or_insert_with(|| open_limited(ppid).as_ref().and_then(start_ticks));
                    // A "parent" that started after its child is another
                    // process that got the old parent's PID.
                    let reused = matches!(
                        (parent_start, entry.start_ticks),
                        (Some(p), Some(c)) if p > c
                    );
                    if !reused {
                        entry.info.parent_name = match ppid {
                            0 => "System Idle Process".to_string(),
                            4 => "System".to_string(),
                            _ => parent_name.clone(),
                        };
                    }
                }
            }
            entry.info.is_system = is_system_process(&entry.info, &entry.sid, &root);
            out.insert(pid, entry.info.clone());
        }
        out
    }

    /// Number of processes currently remembered.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(pid: u32, name: &str, path: &str) -> ProcInfo {
        ProcInfo {
            pid,
            name: name.into(),
            path: path.into(),
            ..Default::default()
        }
    }

    #[test]
    fn paths_under_the_windows_folder() {
        let root = "c:\\windows\\";
        assert!(under_root("C:\\Windows\\System32\\svchost.exe", root));
        assert!(under_root("c:/windows/explorer.exe", root));
        assert!(under_root("\\\\?\\C:\\WINDOWS\\System32\\x.exe", root));
        assert!(!under_root("C:\\WindowsApps\\tool.exe", root));
        assert!(!under_root("C:\\Program Files\\App\\app.exe", root));
        assert!(!under_root("", root));
        assert!(!under_root("C:\\Windows\\x.exe", ""));
    }

    #[test]
    fn what_counts_as_a_windows_process() {
        let root = "c:\\windows\\";
        assert!(is_system_process(&info(0, "", ""), "", root));
        assert!(is_system_process(&info(4, "System", ""), "", root));
        assert!(is_system_process(
            &info(900, "svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
            "S-1-5-20",
            root
        ));
        // A user program is not, whoever runs it.
        let app = info(4100, "app.exe", "D:\\Tools\\app.exe");
        assert!(!is_system_process(&app, "S-1-5-21-1-2-3-1001", root));
        assert!(!is_system_process(&app, "S-1-5-18", root));
        // ... unless it is a service running as a service account.
        let mut service = app.clone();
        service.services = vec![ServiceRef {
            name: "ExampleSvc".into(),
            display: "Example Service".into(),
        }];
        assert!(is_system_process(&service, "S-1-5-19", root));
        assert!(!is_system_process(&service, "S-1-5-21-1-2-3-1001", root));
        // Access denied: services or a protected Windows process.
        let mut hidden = info(700, "example.exe", "");
        hidden.limited = true;
        assert!(!is_system_process(&hidden, "", root));
        hidden.services = service.services.clone();
        assert!(is_system_process(&hidden, "", root));
        let mut protected = info(600, "CSRSS.EXE", "");
        protected.limited = true;
        assert!(is_system_process(&protected, "", root));
    }

    #[test]
    fn service_accounts_and_file_names() {
        assert!(is_service_account("S-1-5-18"));
        assert!(is_service_account("S-1-5-20"));
        assert!(!is_service_account("S-1-5-21-1-2-3-500"));
        assert!(!is_service_account(""));
        assert_eq!(file_name("D:\\Tools\\app.exe"), "app.exe");
        assert_eq!(file_name("app.exe"), "app.exe");
        assert_eq!(file_name(""), "");
    }

    #[test]
    fn resolves_this_process_and_the_fixed_pids() {
        let own = std::process::id();
        let mut cache = ProcCache::default();
        let pids: HashSet<u32> = [0, 4, own].into_iter().collect();
        let procs = cache.resolve(&pids);
        assert_eq!(procs[&0].name, "System Idle Process");
        assert_eq!(procs[&4].name, "System");
        assert!(procs[&0].is_system && procs[&4].is_system);

        let me = &procs[&own];
        let exe = std::env::current_exe().unwrap();
        assert!(!me.limited);
        assert_eq!(
            std::path::Path::new(&me.path).file_name(),
            exe.file_name(),
            "the path of this process"
        );
        assert!(me.name.eq_ignore_ascii_case(&file_name(&me.path)));
        assert!(!me.cmdline.is_empty());
        assert!(me.user.contains('\\'));
        assert!(me.started.is_some());
        assert!(me.parent.is_some());
        assert!(!me.is_system);

        // The second call answers from the cache and gives the same result.
        assert_eq!(cache.len(), 1);
        let again = cache.resolve(&pids);
        assert_eq!(again[&own], procs[&own]);
        assert_eq!(cache.len(), 1);

        // A PID that does not exist gives a limited, nameless entry.
        let ghost: HashSet<u32> = [0xFFFF_FFF0].into_iter().collect();
        let g = cache.resolve(&ghost);
        assert!(g[&0xFFFF_FFF0].limited && g[&0xFFFF_FFF0].name.is_empty());
    }

    #[test]
    fn version_texts_of_a_windows_program() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let (description, company) = version_texts(&format!("{root}\\System32\\cmd.exe"));
        assert!(!description.is_empty());
        assert!(!company.is_empty());
        assert_eq!(
            version_texts("Z:\\missing\\nothing.exe"),
            (String::new(), String::new())
        );
    }
}
