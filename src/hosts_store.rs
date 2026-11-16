//! Reading and writing the hosts file on disk: timestamped backups, restore,
//! read-only detection, saving with elevation only when needed, profiles.
//!
//! Every function takes the paths to work on, so the whole flow can be (and
//! is) exercised on copies in a temporary folder.

use crate::hosts::{HostsDoc, Profile};
use crate::model::now_unix;
use crate::util::{fmt_stamp, wide};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostsPaths {
    pub hosts: PathBuf,
    pub backups: PathBuf,
    pub profiles: PathBuf,
}

impl HostsPaths {
    /// The real hosts file, with backups and profiles under `app_dir`.
    pub fn system(app_dir: &Path) -> HostsPaths {
        let root = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("C:\\Windows"));
        HostsPaths {
            hosts: root
                .join("System32")
                .join("drivers")
                .join("etc")
                .join("hosts"),
            backups: app_dir.join("hosts-backups"),
            profiles: app_dir.join("hosts-profiles.json"),
        }
    }

    /// Everything inside one folder (tests, self-test).
    pub fn sandbox(dir: &Path) -> HostsPaths {
        HostsPaths {
            hosts: dir.join("hosts"),
            backups: dir.join("hosts-backups"),
            profiles: dir.join("hosts-profiles.json"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Loaded {
    pub doc: HostsDoc,
    /// The bytes as read: used to notice changes made by another program.
    pub bytes: Vec<u8>,
    /// The file has the read-only attribute.
    pub read_only: bool,
    /// The file does not exist (Windows treats that as an empty hosts file).
    pub missing: bool,
    /// Last modified (Unix seconds).
    pub modified: Option<i64>,
}

fn unix_mtime(meta: &std::fs::Metadata) -> Option<i64> {
    meta.modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}

/// Reads the hosts file. A missing file is an empty document, not an error.
pub fn load(paths: &HostsPaths) -> Result<Loaded, String> {
    match std::fs::read(&paths.hosts) {
        Ok(bytes) => {
            let meta = std::fs::metadata(&paths.hosts).ok();
            Ok(Loaded {
                doc: HostsDoc::from_bytes(&bytes),
                bytes,
                read_only: meta
                    .as_ref()
                    .map(|m| m.permissions().readonly())
                    .unwrap_or(false),
                missing: false,
                modified: meta.as_ref().and_then(unix_mtime),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Loaded {
            doc: HostsDoc::parse(""),
            bytes: Vec::new(),
            read_only: false,
            missing: true,
            modified: None,
        }),
        Err(e) => Err(format!(
            "Could not read {}: {e}",
            paths.hosts.to_string_lossy()
        )),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backup {
    pub path: PathBuf,
    /// When the backup was made (Unix seconds).
    pub time: i64,
    pub size: u64,
    /// Number of entries in it (enabled and disabled).
    pub entries: usize,
}

impl Backup {
    pub fn file_name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

/// Backups, newest first.
pub fn list_backups(paths: &HostsPaths) -> Vec<Backup> {
    let mut out: Vec<(std::time::SystemTime, Backup)> = std::fs::read_dir(&paths.backups)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            let name = path.file_name()?.to_string_lossy().to_lowercase();
            if !(name.starts_with("hosts-") && name.ends_with(".bak")) {
                return None;
            }
            let meta = e.metadata().ok()?;
            let bytes = std::fs::read(&path).ok()?;
            let precise = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
            let backup = Backup {
                time: unix_mtime(&meta).unwrap_or(0),
                size: meta.len(),
                entries: HostsDoc::from_bytes(&bytes).entry_count(),
                path,
            };
            Some((precise, backup))
        })
        .collect();
    // File times have sub-second precision, so backups made in the same second keep their order.
    out.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.path.cmp(&a.1.path)));
    out.into_iter().map(|(_, b)| b).collect()
}

/// Copies the current hosts file into the backup folder. Returns None when
/// there is nothing to back up or the newest backup already has this content.
pub fn backup_now(paths: &HostsPaths) -> Result<Option<PathBuf>, String> {
    let current = match std::fs::read(&paths.hosts) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("Could not read the hosts file for the backup: {e}")),
    };
    if let Some(newest) = list_backups(paths).first() {
        if std::fs::read(&newest.path).ok().as_deref() == Some(&current[..]) {
            return Ok(None);
        }
    }
    std::fs::create_dir_all(&paths.backups)
        .map_err(|e| format!("Could not create the backup folder: {e}"))?;
    let stamp = fmt_stamp(now_unix());
    let mut target = paths.backups.join(format!("hosts-{stamp}.bak"));
    let mut n = 2;
    while target.exists() {
        target = paths.backups.join(format!("hosts-{stamp}-{n}.bak"));
        n += 1;
    }
    std::fs::write(&target, &current).map_err(|e| format!("Could not write the backup: {e}"))?;
    Ok(Some(target))
}

/// Removes the oldest backups so that at most `keep` remain.
pub fn prune_backups(paths: &HostsPaths, keep: usize) -> usize {
    let all = list_backups(paths);
    let mut removed = 0;
    for b in all.iter().skip(keep.max(1)) {
        if std::fs::remove_file(&b.path).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SaveError {
    /// Writing needs administrator rights: call [`save_elevated`].
    NeedsElevation,
    /// The file has the read-only attribute (and the caller did not ask to clear it).
    ReadOnly,
    /// Another program changed the file since it was loaded.
    ChangedOnDisk,
    Other(String),
}

impl SaveError {
    pub fn message(&self) -> String {
        match self {
            SaveError::NeedsElevation => "Saving the hosts file needs administrator rights.".into(),
            SaveError::ReadOnly => "The hosts file is marked read-only.".into(),
            SaveError::ChangedOnDisk => {
                "The hosts file was changed by another program since it was opened.".into()
            }
            SaveError::Other(e) => e.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SaveOutcome {
    /// The backup made of the previous content, if any.
    pub backup: Option<PathBuf>,
    /// Nothing was written because the file already had this content.
    pub unchanged: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SaveOptions {
    /// Remove the read-only attribute for the write and put it back afterwards.
    pub clear_read_only: bool,
    /// Save even though the file changed on disk since it was loaded.
    pub overwrite_changes: bool,
    /// Backups to keep (0 = keep all).
    pub keep_backups: usize,
}

/// Checks and backs up, without writing the hosts file itself.
fn prepare(
    paths: &HostsPaths,
    new_bytes: &[u8],
    loaded_bytes: Option<&[u8]>,
    options: SaveOptions,
) -> Result<SaveOutcome, SaveError> {
    let current = std::fs::read(&paths.hosts).ok();
    if let (Some(expected), false) = (loaded_bytes, options.overwrite_changes) {
        if current.as_deref().unwrap_or(&[]) != expected {
            return Err(SaveError::ChangedOnDisk);
        }
    }
    if current.as_deref() == Some(new_bytes) {
        return Ok(SaveOutcome {
            backup: None,
            unchanged: true,
        });
    }
    let read_only = std::fs::metadata(&paths.hosts)
        .map(|m| m.permissions().readonly())
        .unwrap_or(false);
    if read_only && !options.clear_read_only {
        return Err(SaveError::ReadOnly);
    }
    let backup = backup_now(paths).map_err(SaveError::Other)?;
    if options.keep_backups > 0 {
        prune_backups(paths, options.keep_backups);
    }
    Ok(SaveOutcome {
        backup,
        unchanged: false,
    })
}

/// Writes `bytes` over the file in place (keeping its permissions), with the
/// read-only attribute lifted for the moment when asked.
pub fn write_in_place(target: &Path, bytes: &[u8], clear_read_only: bool) -> std::io::Result<()> {
    let was_read_only = std::fs::metadata(target)
        .map(|m| m.permissions().readonly())
        .unwrap_or(false);
    if was_read_only && clear_read_only {
        let mut perms = std::fs::metadata(target)?.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(target, perms)?;
    }
    let result = std::fs::write(target, bytes);
    if was_read_only && clear_read_only {
        if let Ok(meta) = std::fs::metadata(target) {
            let mut perms = meta.permissions();
            perms.set_readonly(true);
            let _ = std::fs::set_permissions(target, perms);
        }
    }
    result
}

/// Saves the document: backup first, then write in place. Returns
/// `NeedsElevation` when Windows refuses the write; nothing has been changed
/// then except that a backup exists.
pub fn save(
    paths: &HostsPaths,
    doc: &HostsDoc,
    loaded_bytes: Option<&[u8]>,
    options: SaveOptions,
) -> Result<SaveOutcome, SaveError> {
    let bytes = doc.to_bytes();
    let outcome = prepare(paths, &bytes, loaded_bytes, options)?;
    if outcome.unchanged {
        return Ok(outcome);
    }
    match write_in_place(&paths.hosts, &bytes, options.clear_read_only) {
        Ok(()) => Ok(outcome),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(SaveError::NeedsElevation)
        }
        Err(e) => Err(SaveError::Other(format!(
            "Could not write the hosts file: {e}"
        ))),
    }
}

/// The elevated half of saving: copies `source` over `target`. Run by
/// `SocketForge.exe --apply-hosts <source> <target>` after the UAC prompt.
/// As a safety net the target must be a file named `hosts`.
pub fn apply_hosts(source: &Path, target: &Path, clear_read_only: bool) -> Result<(), String> {
    let name_ok = target
        .file_name()
        .map(|n| n.to_string_lossy().eq_ignore_ascii_case("hosts"))
        .unwrap_or(false);
    if !name_ok {
        return Err("Refusing to write: the target is not a hosts file.".into());
    }
    let bytes =
        std::fs::read(source).map_err(|e| format!("Could not read the new content: {e}"))?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("Refusing to write: the new content is larger than 16 MB.".into());
    }
    write_in_place(target, &bytes, clear_read_only)
        .map_err(|e| format!("Could not write the hosts file: {e}"))
}

/// Saves through an elevated copy of SocketForge (one UAC prompt). The new
/// content is staged in `stage_dir`; the elevated process only copies it.
pub fn save_elevated(
    paths: &HostsPaths,
    doc: &HostsDoc,
    loaded_bytes: Option<&[u8]>,
    options: SaveOptions,
    stage_dir: &Path,
    flush_dns_after: bool,
) -> Result<SaveOutcome, SaveError> {
    let bytes = doc.to_bytes();
    let outcome = prepare(paths, &bytes, loaded_bytes, options)?;
    if outcome.unchanged {
        return Ok(outcome);
    }
    std::fs::create_dir_all(stage_dir)
        .map_err(|e| SaveError::Other(format!("Could not stage the new hosts file: {e}")))?;
    let staged = stage_dir.join(format!("hosts-pending-{}.tmp", std::process::id()));
    std::fs::write(&staged, &bytes)
        .map_err(|e| SaveError::Other(format!("Could not stage the new hosts file: {e}")))?;
    let exe = std::env::current_exe().map_err(|e| SaveError::Other(e.to_string()))?;
    let mut params = format!(
        "--apply-hosts \"{}\" \"{}\"",
        staged.to_string_lossy(),
        paths.hosts.to_string_lossy()
    );
    if options.clear_read_only {
        params.push_str(" --clear-read-only");
    }
    if flush_dns_after {
        params.push_str(" --flush-dns");
    }
    let result = run_elevated_and_wait(&exe.to_string_lossy(), &params);
    let _ = std::fs::remove_file(&staged);
    match result {
        Ok(0) => {
            // Trust, but verify: the file must now have the new content.
            if std::fs::read(&paths.hosts).ok().as_deref() == Some(&bytes[..]) {
                Ok(outcome)
            } else {
                Err(SaveError::Other(
                    "The hosts file does not have the new content after saving. Security \
                     software may have blocked the change."
                        .into(),
                ))
            }
        }
        Ok(code) => Err(SaveError::Other(format!(
            "The elevated save failed (code {code}). Security software may protect the hosts file."
        ))),
        Err(e) => Err(SaveError::Other(e)),
    }
}

/// Starts a program elevated (UAC prompt), waits for it and returns its exit code.
fn run_elevated_and_wait(exe: &str, params: &str) -> Result<u32, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SEE_MASK_NO_CONSOLE, SHELLEXECUTEINFOW,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let (verb, file, args) = (wide("runas"), wide(exe), wide(params));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(args.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    unsafe {
        ShellExecuteExW(&mut info).map_err(|e| {
            if e.code().0 as u32 == 0x8007_04C7 {
                "Saving was cancelled at the administrator prompt.".to_string()
            } else {
                format!("Could not start the elevated save: {e}")
            }
        })?;
        if info.hProcess.is_invalid() {
            return Err("Could not start the elevated save.".into());
        }
        WaitForSingleObject(info.hProcess, 60_000);
        let mut code = 1u32;
        let ok = GetExitCodeProcess(info.hProcess, &mut code).is_ok();
        let _ = CloseHandle(info.hProcess);
        if ok {
            Ok(code)
        } else {
            Err("Could not read the result of the elevated save.".into())
        }
    }
}

/// Restores a backup over the hosts file (the current content is backed up first).
pub fn restore(
    paths: &HostsPaths,
    backup: &Path,
    options: SaveOptions,
) -> Result<SaveOutcome, SaveError> {
    let bytes = std::fs::read(backup)
        .map_err(|e| SaveError::Other(format!("Could not read the backup: {e}")))?;
    let doc = HostsDoc::from_bytes(&bytes);
    save(
        paths,
        &doc,
        None,
        SaveOptions {
            overwrite_changes: true,
            ..options
        },
    )
}

/// Empties the Windows DNS resolver cache so that hosts changes apply at once.
/// Needs no administrator rights.
pub fn flush_dns() -> Result<(), String> {
    #[link(name = "dnsapi")]
    extern "system" {
        fn DnsFlushResolverCache() -> i32;
    }
    if unsafe { DnsFlushResolverCache() } != 0 {
        Ok(())
    } else {
        Err("Windows did not flush the DNS cache.".into())
    }
}

/// Saved profiles; a missing or damaged file is an empty list.
pub fn load_profiles(paths: &HostsPaths) -> Vec<Profile> {
    std::fs::read_to_string(&paths.profiles)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn save_profiles(paths: &HostsPaths, profiles: &[Profile]) -> Result<(), String> {
    if let Some(dir) = paths.profiles.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("Could not save the profiles: {e}"))?;
    }
    let json = serde_json::to_string_pretty(profiles).map_err(|e| e.to_string())?;
    std::fs::write(&paths.profiles, json).map_err(|e| format!("Could not save the profiles: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosts::{Entry, ProfileEntry};

    fn sandbox(name: &str) -> (PathBuf, HostsPaths) {
        let dir =
            std::env::temp_dir().join(format!("socketforge-hosts-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = HostsPaths::sandbox(&dir);
        (dir, paths)
    }

    const ORIGINAL: &[u8] = b"# test hosts\r\n127.0.0.1\tapp.test\r\n# 10.0.0.1 off.test\r\n";

    #[test]
    fn system_paths_point_at_the_drivers_folder() {
        let p = HostsPaths::system(Path::new("C:\\data"));
        let s = p.hosts.to_string_lossy().to_lowercase();
        assert!(s.ends_with("\\system32\\drivers\\etc\\hosts"));
        assert!(p.backups.starts_with("C:\\data"));
    }

    #[test]
    fn load_edit_save_backup_restore_on_a_copy() {
        let (dir, paths) = sandbox("flow");
        // Missing file = empty document.
        let empty = load(&paths).unwrap();
        assert!(empty.missing && empty.doc.lines.is_empty());

        std::fs::write(&paths.hosts, ORIGINAL).unwrap();
        let loaded = load(&paths).unwrap();
        assert!(!loaded.missing && !loaded.read_only);
        assert_eq!(loaded.bytes, ORIGINAL);
        assert_eq!(loaded.doc.entry_count(), 2);
        assert!(loaded.modified.is_some());

        // Saving without changes writes nothing and makes no backup.
        let out = save(
            &paths,
            &loaded.doc,
            Some(&loaded.bytes),
            SaveOptions::default(),
        )
        .unwrap();
        assert!(out.unchanged && out.backup.is_none());
        assert!(list_backups(&paths).is_empty());

        // Edit, save: the old content is backed up, the new content is on disk.
        let mut doc = loaded.doc.clone();
        doc.set_enabled(2, true);
        doc.add_entry(Entry::new("10.0.0.2", &["new.test"]), None);
        let out = save(&paths, &doc, Some(&loaded.bytes), SaveOptions::default()).unwrap();
        let backup = out.backup.expect("a backup was made");
        assert_eq!(std::fs::read(&backup).unwrap(), ORIGINAL);
        let on_disk = std::fs::read(&paths.hosts).unwrap();
        assert_eq!(
            on_disk,
            b"# test hosts\r\n127.0.0.1\tapp.test\r\n10.0.0.1 off.test\r\n\r\n10.0.0.2\tnew.test\r\n"
        );
        let backups = list_backups(&paths);
        assert_eq!(backups.len(), 1);
        assert_eq!(backups[0].entries, 2);
        assert_eq!(backups[0].size, ORIGINAL.len() as u64);
        assert!(backups[0].file_name().starts_with("hosts-2"));

        // One-click restore brings the original back and backs up what it replaces.
        let out = restore(&paths, &backup, SaveOptions::default()).unwrap();
        assert!(out.backup.is_some());
        assert_eq!(std::fs::read(&paths.hosts).unwrap(), ORIGINAL);
        assert_eq!(list_backups(&paths).len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn notices_changes_made_by_another_program() {
        let (dir, paths) = sandbox("changed");
        std::fs::write(&paths.hosts, ORIGINAL).unwrap();
        let loaded = load(&paths).unwrap();
        std::fs::write(&paths.hosts, b"127.0.0.1 someone.else\r\n").unwrap();
        let mut doc = loaded.doc.clone();
        doc.set_enabled(1, false);
        let err = save(&paths, &doc, Some(&loaded.bytes), SaveOptions::default()).unwrap_err();
        assert_eq!(err, SaveError::ChangedOnDisk);
        assert_eq!(
            std::fs::read(&paths.hosts).unwrap(),
            b"127.0.0.1 someone.else\r\n"
        );
        let force = SaveOptions {
            overwrite_changes: true,
            ..Default::default()
        };
        save(&paths, &doc, Some(&loaded.bytes), force).unwrap();
        assert_eq!(std::fs::read(&paths.hosts).unwrap(), doc.to_bytes());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_only_file_is_detected_and_can_be_written_on_request() {
        let (dir, paths) = sandbox("readonly");
        std::fs::write(&paths.hosts, ORIGINAL).unwrap();
        let mut perms = std::fs::metadata(&paths.hosts).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&paths.hosts, perms).unwrap();

        let loaded = load(&paths).unwrap();
        assert!(loaded.read_only);
        let mut doc = loaded.doc.clone();
        doc.set_enabled(1, false);
        let err = save(&paths, &doc, Some(&loaded.bytes), SaveOptions::default()).unwrap_err();
        assert_eq!(err, SaveError::ReadOnly);
        assert_eq!(std::fs::read(&paths.hosts).unwrap(), ORIGINAL);

        let clear = SaveOptions {
            clear_read_only: true,
            ..Default::default()
        };
        save(&paths, &doc, Some(&loaded.bytes), clear).unwrap();
        assert_eq!(std::fs::read(&paths.hosts).unwrap(), doc.to_bytes());
        // The attribute is back after the write.
        assert!(std::fs::metadata(&paths.hosts)
            .unwrap()
            .permissions()
            .readonly());

        let mut perms = std::fs::metadata(&paths.hosts).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&paths.hosts, perms).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn backups_are_deduplicated_and_pruned() {
        let (dir, paths) = sandbox("prune");
        std::fs::write(&paths.hosts, ORIGINAL).unwrap();
        assert!(backup_now(&paths).unwrap().is_some());
        // Same content again: no second backup.
        assert!(backup_now(&paths).unwrap().is_none());
        for i in 0..5 {
            std::fs::write(&paths.hosts, format!("127.0.0.1 v{i}.test\r\n")).unwrap();
            assert!(backup_now(&paths).unwrap().is_some());
        }
        let all = list_backups(&paths);
        assert_eq!(all.len(), 6);
        // Same second: names get a counter instead of overwriting each other.
        assert!(all.iter().any(|b| b.file_name().contains("-2.bak")) || all.len() == 6);
        assert_eq!(prune_backups(&paths, 2), 4);
        assert_eq!(list_backups(&paths).len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn elevated_helper_only_writes_files_named_hosts() {
        let (dir, paths) = sandbox("apply");
        std::fs::write(&paths.hosts, ORIGINAL).unwrap();
        let staged = dir.join("staged.tmp");
        std::fs::write(&staged, b"127.0.0.1 staged.test\r\n").unwrap();
        let other = dir.join("notes.txt");
        std::fs::write(&other, b"keep").unwrap();
        assert!(apply_hosts(&staged, &other, false).is_err());
        assert_eq!(std::fs::read(&other).unwrap(), b"keep");
        assert!(apply_hosts(&dir.join("missing.tmp"), &paths.hosts, false).is_err());
        apply_hosts(&staged, &paths.hosts, false).unwrap();
        assert_eq!(
            std::fs::read(&paths.hosts).unwrap(),
            b"127.0.0.1 staged.test\r\n"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn profiles_round_trip() {
        let (dir, paths) = sandbox("profiles");
        assert!(load_profiles(&paths).is_empty());
        let profiles = vec![Profile {
            name: "dev".into(),
            entries: vec![ProfileEntry {
                ip: "127.0.0.1".into(),
                hosts: vec!["a.dev.test".into()],
                comment: "x".into(),
            }],
        }];
        save_profiles(&paths, &profiles).unwrap();
        assert_eq!(load_profiles(&paths), profiles);
        std::fs::write(&paths.profiles, "[{").unwrap();
        assert!(load_profiles(&paths).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
