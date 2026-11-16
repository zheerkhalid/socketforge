//! The hosts file as an editable document.
//!
//! The parser keeps every line exactly as it was read (text, line ending,
//! byte-order mark, encoding). Only lines that are edited are rewritten, so
//! saving a document that was not changed gives back the same bytes, and
//! toggling one entry changes one line.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Eol {
    Lf,
    CrLf,
}

impl Eol {
    fn as_str(self) -> &'static str {
        match self {
            Eol::Lf => "\n",
            Eol::CrLf => "\r\n",
        }
    }
}

/// How the file was stored on disk; it is written back the same way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Utf8,
    /// UTF-8 with a byte-order mark.
    Utf8Bom,
    /// Not valid UTF-8: every byte is kept as the character with the same number.
    Latin1,
    /// UTF-16 little endian with a byte-order mark (Windows cannot use such a hosts file).
    Utf16Le,
}

/// One mapping line: an address and the names that resolve to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// False when the line is commented out.
    pub enabled: bool,
    pub ip: String,
    pub hosts: Vec<String>,
    /// The comment after the names, without the `#`.
    pub comment: String,
}

impl Entry {
    pub fn new(ip: &str, hosts: &[&str]) -> Entry {
        Entry {
            enabled: true,
            ip: ip.to_string(),
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
            comment: String::new(),
        }
    }

    /// The line as SocketForge writes it.
    pub fn format(&self) -> String {
        let mut s = String::new();
        if !self.enabled {
            s.push_str("# ");
        }
        s.push_str(self.ip.trim());
        s.push('\t');
        s.push_str(&self.hosts.join(" "));
        let c = self.comment.trim();
        if !c.is_empty() {
            s.push_str(" # ");
            s.push_str(c);
        }
        s
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LineKind {
    Blank,
    /// A comment that is not a disabled entry.
    Comment,
    Entry(Entry),
    /// Not a comment and not a usable mapping (Windows ignores it).
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    /// The text without its line ending.
    pub raw: String,
    /// None for a last line without a line ending.
    pub eol: Option<Eol>,
    pub kind: LineKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueKind {
    /// The address is not a valid IPv4 or IPv6 address.
    BadAddress,
    /// A name contains characters that cannot be in a host name.
    BadName,
    /// The same address + name appears on an earlier enabled line.
    Duplicate,
    /// The same name already points to another address; Windows uses the first.
    Conflict,
    /// The line is neither a comment nor a mapping.
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    /// Index into `HostsDoc::lines`.
    pub line: usize,
    pub kind: IssueKind,
    pub message: String,
}

/// A table row: an entry with where it is and which group it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub line: usize,
    pub entry: Entry,
    /// Group header above the entry; empty when there is none.
    pub group: String,
    /// Name of the profile block the entry is in, if any.
    pub profile: Option<String>,
}

/// A named set of entries that can be switched on and off as a block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub entries: Vec<ProfileEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileEntry {
    pub ip: String,
    pub hosts: Vec<String>,
    #[serde(default)]
    pub comment: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Names added (one per address + name pair).
    pub added: usize,
    /// Pairs that were already in the file.
    pub already_present: usize,
    /// Names that already point somewhere else: added switched off.
    pub conflicts: usize,
}

const PROFILE_BEGIN: &str = "# >>> SocketForge profile: ";
const PROFILE_END: &str = "# <<< SocketForge profile: ";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostsDoc {
    pub encoding: Encoding,
    pub lines: Vec<Line>,
}

/// Parses an address as the hosts file allows it (IPv6 zone ids are tolerated).
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    let bare = s.split('%').next().unwrap_or(s);
    bare.parse().ok()
}

/// Why a name cannot be used in the hosts file, or None when it is fine.
pub fn name_problem(name: &str) -> Option<String> {
    if name.is_empty() {
        return Some("The name is empty.".into());
    }
    if name.contains('*') {
        return Some(format!(
            "\"{name}\": wildcards do not work in the hosts file; list each name."
        ));
    }
    if name.len() > 253 {
        return Some("The name is longer than 253 characters.".into());
    }
    if !name.is_ascii() {
        return Some(format!(
            "\"{name}\" has non-ASCII characters; use its punycode form (xn--...)."
        ));
    }
    if let Some(c) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_')))
    {
        return Some(format!("\"{name}\" contains the character '{c}'."));
    }
    if name.starts_with('.') || name.contains("..") {
        return Some(format!("\"{name}\" has an empty label."));
    }
    if name.split('.').any(|label| label.len() > 63) {
        return Some(format!("\"{name}\" has a label longer than 63 characters."));
    }
    None
}

fn parse_mapping(text: &str, enabled: bool) -> Option<Entry> {
    let (body, comment) = match text.find('#') {
        Some(i) => (&text[..i], text[i + 1..].trim()),
        None => (text, ""),
    };
    let mut tokens = body.split_whitespace();
    let ip = tokens.next()?;
    let hosts: Vec<String> = tokens.map(|t| t.to_string()).collect();
    if hosts.is_empty() {
        return None;
    }
    Some(Entry {
        enabled,
        ip: ip.to_string(),
        hosts,
        comment: comment.to_string(),
    })
}

fn classify(raw: &str) -> LineKind {
    let t = raw.trim();
    if t.is_empty() || t == "\u{feff}" {
        return LineKind::Blank;
    }
    if let Some(rest) = t.strip_prefix('#') {
        // A commented-out mapping must look exactly like one: a valid address
        // followed by valid names. Anything else is prose.
        if !rest.starts_with('#') {
            if let Some(e) = parse_mapping(rest, false) {
                if parse_ip(&e.ip).is_some() && e.hosts.iter().all(|h| name_problem(h).is_none()) {
                    return LineKind::Entry(e);
                }
            }
        }
        return LineKind::Comment;
    }
    match parse_mapping(t, true) {
        Some(e) => LineKind::Entry(e),
        None => LineKind::Invalid,
    }
}

/// The text of a group header comment, or None when the comment is not one.
fn header_text(raw: &str) -> Option<String> {
    let t = raw.trim();
    if let Some(name) = t.strip_prefix(PROFILE_BEGIN) {
        return Some(format!("Profile: {}", name.trim()));
    }
    let name = t.trim_matches(|c: char| {
        c.is_whitespace() || matches!(c, '#' | '-' | '=' | '*' | '[' | ']' | '<' | '>' | '~')
    });
    (!name.is_empty()).then(|| name.to_string())
}

fn profile_marker<'a>(raw: &'a str, marker: &str) -> Option<&'a str> {
    raw.trim().strip_prefix(marker).map(|n| n.trim())
}

impl HostsDoc {
    /// Parses text. The encoding is only remembered for writing.
    pub fn parse(text: &str) -> HostsDoc {
        HostsDoc::parse_as(text, Encoding::Utf8)
    }

    pub fn parse_as(text: &str, encoding: Encoding) -> HostsDoc {
        let mut lines = Vec::new();
        let mut rest = text;
        while !rest.is_empty() {
            let (raw, eol, next) = match rest.find('\n') {
                Some(i) => {
                    if i > 0 && rest.as_bytes()[i - 1] == b'\r' {
                        (&rest[..i - 1], Some(Eol::CrLf), &rest[i + 1..])
                    } else {
                        (&rest[..i], Some(Eol::Lf), &rest[i + 1..])
                    }
                }
                None => (rest, None, ""),
            };
            lines.push(Line {
                raw: raw.to_string(),
                eol,
                kind: classify(raw),
            });
            rest = next;
        }
        HostsDoc { encoding, lines }
    }

    /// Reads the bytes of a hosts file, whatever their encoding.
    pub fn from_bytes(bytes: &[u8]) -> HostsDoc {
        if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
            if let Ok(text) = std::str::from_utf8(rest) {
                return HostsDoc::parse_as(text, Encoding::Utf8Bom);
            }
        }
        if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
            if rest.len().is_multiple_of(2) {
                let units: Vec<u16> = rest
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .collect();
                if let Ok(text) = String::from_utf16(&units) {
                    return HostsDoc::parse_as(&text, Encoding::Utf16Le);
                }
            }
        }
        match std::str::from_utf8(bytes) {
            Ok(text) => HostsDoc::parse_as(text, Encoding::Utf8),
            Err(_) => {
                let text: String = bytes.iter().map(|b| *b as char).collect();
                HostsDoc::parse_as(&text, Encoding::Latin1)
            }
        }
    }

    /// The whole file as text (without a byte-order mark).
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        for l in &self.lines {
            s.push_str(&l.raw);
            if let Some(e) = l.eol {
                s.push_str(e.as_str());
            }
        }
        s
    }

    /// The bytes to write to disk, in the encoding the file came in.
    pub fn to_bytes(&self) -> Vec<u8> {
        let text = self.to_text();
        match self.encoding {
            Encoding::Utf8 => text.into_bytes(),
            Encoding::Utf8Bom => {
                let mut out = vec![0xEF, 0xBB, 0xBF];
                out.extend_from_slice(text.as_bytes());
                out
            }
            Encoding::Latin1 => {
                if text.chars().all(|c| (c as u32) < 256) {
                    text.chars().map(|c| c as u32 as u8).collect()
                } else {
                    // New text that does not fit the old encoding: fall back to UTF-8.
                    text.into_bytes()
                }
            }
            Encoding::Utf16Le => {
                let mut out = vec![0xFF, 0xFE];
                for u in text.encode_utf16() {
                    out.extend_from_slice(&u.to_le_bytes());
                }
                out
            }
        }
    }

    /// Replaces the content with edited raw text, keeping the encoding.
    pub fn set_text(&mut self, text: &str) {
        self.lines = HostsDoc::parse_as(text, self.encoding).lines;
    }

    /// The line ending most lines use (CRLF for an empty file: this is Windows).
    pub fn dominant_eol(&self) -> Eol {
        let lf = self.lines.iter().filter(|l| l.eol == Some(Eol::Lf)).count();
        let crlf = self
            .lines
            .iter()
            .filter(|l| l.eol == Some(Eol::CrLf))
            .count();
        if lf > crlf {
            Eol::Lf
        } else {
            Eol::CrLf
        }
    }

    pub fn entry(&self, line: usize) -> Option<&Entry> {
        match self.lines.get(line).map(|l| &l.kind) {
            Some(LineKind::Entry(e)) => Some(e),
            _ => None,
        }
    }

    /// Group and profile of every line (index-aligned with `lines`).
    fn memberships(&self) -> Vec<(String, Option<String>)> {
        let mut out = Vec::with_capacity(self.lines.len());
        let mut group = String::new();
        let mut profile: Option<String> = None;
        for (i, l) in self.lines.iter().enumerate() {
            match &l.kind {
                LineKind::Blank => {
                    if profile.is_none() {
                        group.clear();
                    }
                }
                LineKind::Comment => {
                    if let Some(name) = profile_marker(&l.raw, PROFILE_BEGIN) {
                        profile = Some(name.to_string());
                        group = format!("Profile: {name}");
                    } else if profile_marker(&l.raw, PROFILE_END).is_some() {
                        profile = None;
                        group.clear();
                    } else if profile.is_none() {
                        // A header is a comment directly above a mapping.
                        let next_is_entry = matches!(
                            self.lines.get(i + 1).map(|n| &n.kind),
                            Some(LineKind::Entry(_))
                        );
                        if next_is_entry {
                            if let Some(name) = header_text(&l.raw) {
                                group = name;
                            }
                        }
                    }
                }
                LineKind::Entry(_) | LineKind::Invalid => {}
            }
            out.push((group.clone(), profile.clone()));
        }
        out
    }

    /// All entries in file order.
    pub fn rows(&self) -> Vec<Row> {
        let members = self.memberships();
        self.lines
            .iter()
            .enumerate()
            .filter_map(|(i, l)| match &l.kind {
                LineKind::Entry(e) => Some(Row {
                    line: i,
                    entry: e.clone(),
                    group: members[i].0.clone(),
                    profile: members[i].1.clone(),
                }),
                _ => None,
            })
            .collect()
    }

    /// Group names in file order (without the empty "no group").
    pub fn groups(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for r in self.rows() {
            if !r.group.is_empty() && !out.contains(&r.group) {
                out.push(r.group);
            }
        }
        out
    }

    pub fn entry_count(&self) -> usize {
        self.lines
            .iter()
            .filter(|l| matches!(l.kind, LineKind::Entry(_)))
            .count()
    }

    pub fn enabled_count(&self) -> usize {
        self.lines
            .iter()
            .filter(|l| matches!(&l.kind, LineKind::Entry(e) if e.enabled))
            .count()
    }

    /// Comments an entry out or back in. Only that line changes; a line that
    /// SocketForge did not write keeps its own spacing.
    pub fn set_enabled(&mut self, line: usize, on: bool) -> bool {
        let Some(l) = self.lines.get_mut(line) else {
            return false;
        };
        let LineKind::Entry(e) = &mut l.kind else {
            return false;
        };
        if e.enabled == on {
            return false;
        }
        e.enabled = on;
        if on {
            let t = l.raw.trim_start();
            l.raw = t.strip_prefix('#').unwrap_or(t).trim_start().to_string();
        } else {
            l.raw = format!("# {}", l.raw.trim_start());
        }
        true
    }

    /// Switches every entry of a group.
    pub fn set_group_enabled(&mut self, group: &str, on: bool) -> usize {
        let lines: Vec<usize> = self
            .rows()
            .into_iter()
            .filter(|r| r.group == group)
            .map(|r| r.line)
            .collect();
        lines
            .into_iter()
            .filter(|&l| self.set_enabled(l, on))
            .count()
    }

    /// Replaces an entry; the line is rewritten in SocketForge's format.
    pub fn update_entry(&mut self, line: usize, entry: Entry) -> bool {
        match self.lines.get_mut(line) {
            Some(l) if matches!(l.kind, LineKind::Entry(_) | LineKind::Invalid) => {
                l.raw = entry.format();
                l.kind = LineKind::Entry(entry);
                true
            }
            _ => false,
        }
    }

    /// Removes a line (entry or anything else).
    pub fn delete_line(&mut self, line: usize) -> bool {
        if line >= self.lines.len() {
            return false;
        }
        let removed = self.lines.remove(line);
        // The file keeps its "ends without a newline" property.
        if removed.eol.is_none() {
            if let Some(last) = self.lines.last_mut() {
                last.eol = None;
            }
        }
        true
    }

    fn insert_line(&mut self, at: usize, raw: String) -> usize {
        let eol = self.dominant_eol();
        let at = at.min(self.lines.len());
        let kind = classify(&raw);
        if at == self.lines.len() {
            // Appending: the old last line gains a line ending, the new one
            // ends the file the way the old one did.
            let tail = match self.lines.last_mut() {
                Some(last) => {
                    let t = last.eol;
                    last.eol = Some(t.unwrap_or(eol));
                    t
                }
                None => Some(eol),
            };
            self.lines.push(Line {
                raw,
                eol: tail,
                kind,
            });
        } else {
            self.lines.insert(
                at,
                Line {
                    raw,
                    eol: Some(eol),
                    kind,
                },
            );
        }
        at
    }

    /// Adds an entry. With a group: after the last entry of that group, or in
    /// a new group at the end of the file. Returns the line index.
    pub fn add_entry(&mut self, entry: Entry, group: Option<&str>) -> usize {
        let group = group.map(str::trim).filter(|g| !g.is_empty());
        if let Some(g) = group {
            if let Some(last) = self.rows().iter().rev().find(|r| r.group == g) {
                return self.insert_line(last.line + 1, entry.format());
            }
            self.append_blank_if_needed();
            let at = self.lines.len();
            self.insert_line(at, format!("# {g}"));
            let at = self.lines.len();
            return self.insert_line(at, entry.format());
        }
        // No group: at the end, but before any profile blocks so that they stay last.
        let mut at = self.lines.len();
        if let Some(first_profile) = self
            .lines
            .iter()
            .position(|l| profile_marker(&l.raw, PROFILE_BEGIN).is_some())
        {
            at = first_profile;
            while at > 0 && self.lines[at - 1].kind == LineKind::Blank {
                at -= 1;
            }
        }
        // Directly below a group it would join that group: keep a blank line between.
        if at > 0 && !self.memberships()[at - 1].0.is_empty() {
            at = self.insert_line(at, String::new()) + 1;
        }
        self.insert_line(at, entry.format())
    }

    fn append_blank_if_needed(&mut self) {
        if matches!(self.lines.last(), Some(l) if l.kind != LineKind::Blank) {
            let at = self.lines.len();
            self.insert_line(at, String::new());
        }
    }

    /// Syntax problems, duplicates and conflicts.
    pub fn issues(&self) -> Vec<Issue> {
        let mut out = Vec::new();
        // name (lower case) -> (address family is v6, address, line) of the first enabled mapping
        let mut seen: HashMap<(String, bool), (IpAddr, usize)> = HashMap::new();
        for (i, l) in self.lines.iter().enumerate() {
            let e = match &l.kind {
                LineKind::Invalid => {
                    out.push(Issue {
                        line: i,
                        kind: IssueKind::Invalid,
                        message: "This line is neither a comment nor \"address name\"; Windows \
                                  ignores it."
                            .into(),
                    });
                    continue;
                }
                LineKind::Entry(e) => e,
                _ => continue,
            };
            let ip = parse_ip(&e.ip);
            if ip.is_none() {
                out.push(Issue {
                    line: i,
                    kind: IssueKind::BadAddress,
                    message: format!("\"{}\" is not a valid IPv4 or IPv6 address.", e.ip),
                });
            }
            for h in &e.hosts {
                if let Some(problem) = name_problem(h) {
                    out.push(Issue {
                        line: i,
                        kind: IssueKind::BadName,
                        message: problem,
                    });
                }
            }
            let (Some(ip), true) = (ip, e.enabled) else {
                continue;
            };
            for h in &e.hosts {
                let key = (h.to_lowercase(), ip.is_ipv6());
                match seen.get(&key) {
                    Some((first_ip, first_line)) if *first_ip == ip => out.push(Issue {
                        line: i,
                        kind: IssueKind::Duplicate,
                        message: format!(
                            "{h} is already mapped to {ip} on line {}.",
                            first_line + 1
                        ),
                    }),
                    Some((first_ip, first_line)) => out.push(Issue {
                        line: i,
                        kind: IssueKind::Conflict,
                        message: format!(
                            "{h} already points to {first_ip} on line {}; Windows uses the first \
                             one and ignores this line.",
                            first_line + 1
                        ),
                    }),
                    None => {
                        seen.insert(key, (ip, i));
                    }
                }
            }
        }
        out
    }

    /// Merges the entries of another hosts file into this one, under `group`.
    /// Pairs that already exist are skipped; names that already point to a
    /// different address are added switched off.
    pub fn merge(&mut self, other: &HostsDoc, group: &str) -> MergeReport {
        let mut report = MergeReport::default();
        let mut have: HashMap<String, Vec<IpAddr>> = HashMap::new();
        let note = |e: &Entry, have: &mut HashMap<String, Vec<IpAddr>>| {
            if let Some(ip) = parse_ip(&e.ip) {
                for h in &e.hosts {
                    have.entry(h.to_lowercase()).or_default().push(ip);
                }
            }
        };
        for r in self.rows() {
            note(&r.entry, &mut have);
        }
        for r in other.rows() {
            let Some(ip) = parse_ip(&r.entry.ip) else {
                continue;
            };
            let mut fresh = Vec::new();
            let mut clash = Vec::new();
            for h in &r.entry.hosts {
                match have.get(&h.to_lowercase()) {
                    Some(ips) if ips.contains(&ip) => report.already_present += 1,
                    Some(ips) if ips.iter().any(|x| x.is_ipv6() == ip.is_ipv6()) => {
                        clash.push(h.clone())
                    }
                    _ => fresh.push(h.clone()),
                }
            }
            for (hosts, conflict) in [(fresh, false), (clash, true)] {
                if hosts.is_empty() {
                    continue;
                }
                if conflict {
                    report.conflicts += hosts.len();
                } else {
                    report.added += hosts.len();
                }
                let e = Entry {
                    enabled: r.entry.enabled && !conflict,
                    ip: r.entry.ip.clone(),
                    hosts,
                    comment: r.entry.comment.clone(),
                };
                note(&e, &mut have);
                self.add_entry(e, Some(group));
            }
        }
        report
    }

    // ---- profiles -----------------------------------------------------------------

    /// Names of the profile blocks currently in the file.
    pub fn active_profiles(&self) -> Vec<String> {
        self.lines
            .iter()
            .filter_map(|l| profile_marker(&l.raw, PROFILE_BEGIN))
            .map(|n| n.to_string())
            .collect()
    }

    pub fn is_profile_active(&self, name: &str) -> bool {
        self.active_profiles().iter().any(|n| n == name)
    }

    /// Removes a profile's block (and the blank line before it). Returns whether it was there.
    pub fn profile_off(&mut self, name: &str) -> bool {
        let Some(start) = self
            .lines
            .iter()
            .position(|l| profile_marker(&l.raw, PROFILE_BEGIN) == Some(name))
        else {
            return false;
        };
        let end = self.lines[start..]
            .iter()
            .position(|l| profile_marker(&l.raw, PROFILE_END) == Some(name))
            .map(|i| start + i)
            // A block without its end marker stops at the next block or the end.
            .unwrap_or_else(|| {
                self.lines[start + 1..]
                    .iter()
                    .position(|l| profile_marker(&l.raw, PROFILE_BEGIN).is_some())
                    .map(|i| start + i)
                    .unwrap_or(self.lines.len() - 1)
            });
        let mut from = start;
        if from > 0 && self.lines[from - 1].kind == LineKind::Blank {
            from -= 1;
        }
        let at_end = end + 1 == self.lines.len();
        let tail_eol = self.lines[end].eol;
        self.lines.drain(from..=end);
        if at_end && tail_eol.is_none() {
            // The file ended without a newline before the block was added.
            if let Some(last) = self.lines.last_mut() {
                last.eol = None;
            }
        }
        true
    }

    /// Writes a profile's entries as a marked block at the end of the file
    /// (replacing its previous block).
    pub fn profile_on(&mut self, profile: &Profile) {
        self.profile_off(&profile.name);
        self.append_blank_if_needed();
        let push = |doc: &mut HostsDoc, raw: String| {
            let at = doc.lines.len();
            doc.insert_line(at, raw);
        };
        push(self, format!("{PROFILE_BEGIN}{}", profile.name));
        for e in &profile.entries {
            let entry = Entry {
                enabled: true,
                ip: e.ip.clone(),
                hosts: e.hosts.clone(),
                comment: e.comment.clone(),
            };
            push(self, entry.format());
        }
        push(self, format!("{PROFILE_END}{}", profile.name));
    }

    /// Builds a profile from the entries of a group (or of an active profile block).
    pub fn profile_from_group(&self, group: &str, name: &str) -> Profile {
        Profile {
            name: name.to_string(),
            entries: self
                .rows()
                .into_iter()
                .filter(|r| r.group == group)
                .map(|r| ProfileEntry {
                    ip: r.entry.ip,
                    hosts: r.entry.hosts,
                    comment: r.entry.comment,
                })
                .collect(),
        }
    }
}

/// A hosts file like the one Windows ships with, plus invented entries: used
/// by `--demo` and the screenshots.
pub fn demo_text() -> String {
    [
        "# Copyright (c) 1993-2009 Microsoft Corp.",
        "#",
        "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.",
        "#",
        "# localhost name resolution is handled within DNS itself.",
        "#\t127.0.0.1       localhost",
        "#\t::1             localhost",
        "",
        "# Local development",
        "127.0.0.1\tshop.test api.shop.test # storefront and its API",
        "127.0.0.1\tadmin.shop.test",
        "::1\tshop.test",
        "# 127.0.0.1\tlegacy.shop.test # old checkout, switched off",
        "",
        "# Staging servers",
        "10.20.0.15\tstaging.example.test",
        "10.20.0.16\tstaging-db.example.test",
        "10.20.0.17\tstaging.example.test # moved to the new rack",
        "",
        "# Lab network",
        "192.168.50.10\tnas.lab printer.lab",
        "192.168.50.300\tcamera.lab",
        "# 192.168.50.12\told-router.lab",
        "",
        "# >>> SocketForge profile: dev",
        "127.0.0.1\tauth.dev.test # single sign-on mock",
        "127.0.0.1\tmail.dev.test",
        "# <<< SocketForge profile: dev",
        "",
    ]
    .join("\r\n")
}

/// Invented profiles for `--demo`.
pub fn demo_profiles() -> Vec<Profile> {
    let e = |ip: &str, hosts: &[&str], comment: &str| ProfileEntry {
        ip: ip.into(),
        hosts: hosts.iter().map(|h| h.to_string()).collect(),
        comment: comment.into(),
    };
    vec![
        Profile {
            name: "dev".into(),
            entries: vec![
                e("127.0.0.1", &["auth.dev.test"], "single sign-on mock"),
                e("127.0.0.1", &["mail.dev.test"], ""),
            ],
        },
        Profile {
            name: "staging".into(),
            entries: vec![
                e("10.20.0.15", &["app.example.test", "api.example.test"], ""),
                e("10.20.0.16", &["db.example.test"], "read replica"),
                e("10.20.0.21", &["cdn.example.test"], ""),
            ],
        },
        Profile {
            name: "offline demo".into(),
            entries: vec![e("127.0.0.1", &["demo.example.test"], "")],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# Copyright (c) 1993-2009 Microsoft Corp.\r\n\
#\r\n\
# localhost name resolution is handled within DNS itself.\r\n\
#\t127.0.0.1       localhost\r\n\
#\t::1             localhost\r\n\
\r\n\
# Dev\r\n\
127.0.0.1\tapp.test api.test   # the app\r\n\
   10.0.0.5     db.test\r\n\
fe80::1%12 router.test\r\n\
#10.0.0.6 old.test\r\n\
\r\n\
0.0.0.0 ads.example\r\n";

    fn rows_of(doc: &HostsDoc) -> Vec<(bool, String, String, String)> {
        doc.rows()
            .into_iter()
            .map(|r| {
                (
                    r.entry.enabled,
                    r.entry.ip,
                    r.entry.hosts.join(" "),
                    r.group,
                )
            })
            .collect()
    }

    #[test]
    fn parses_comments_tabs_ipv6_inline_comments_and_disabled_entries() {
        let doc = HostsDoc::parse(SAMPLE);
        assert_eq!(doc.lines.len(), 13);
        assert_eq!(doc.lines[0].kind, LineKind::Comment);
        assert_eq!(doc.lines[1].kind, LineKind::Comment);
        assert_eq!(doc.lines[5].kind, LineKind::Blank);
        let rows = rows_of(&doc);
        let s = |a: &str| a.to_string();
        assert_eq!(
            rows,
            vec![
                (
                    false,
                    s("127.0.0.1"),
                    s("localhost"),
                    s("localhost name resolution is handled within DNS itself.")
                ),
                (
                    false,
                    s("::1"),
                    s("localhost"),
                    s("localhost name resolution is handled within DNS itself.")
                ),
                (true, s("127.0.0.1"), s("app.test api.test"), s("Dev")),
                (true, s("10.0.0.5"), s("db.test"), s("Dev")),
                (true, s("fe80::1%12"), s("router.test"), s("Dev")),
                (false, s("10.0.0.6"), s("old.test"), s("Dev")),
                (true, s("0.0.0.0"), s("ads.example"), s("")),
            ]
        );
        assert_eq!(doc.entry(7).unwrap().comment, "the app");
        assert_eq!(doc.entry_count(), 7);
        assert_eq!(doc.enabled_count(), 4);
        assert_eq!(
            doc.groups(),
            vec![
                "localhost name resolution is handled within DNS itself.".to_string(),
                "Dev".to_string()
            ]
        );
        assert!(doc.issues().is_empty());
    }

    #[test]
    fn prose_comments_are_not_mistaken_for_entries() {
        for text in [
            "# This file contains the mappings of IP addresses to host names.",
            "# For example:",
            "## 127.0.0.1 doubled.test",
            "# 127.0.0.1",
            "# 300.1.1.1 nope.test",
            "# 10.0.0.1 is the gateway (really)",
            "#",
        ] {
            let doc = HostsDoc::parse(text);
            assert_eq!(doc.lines[0].kind, LineKind::Comment, "{text}");
        }
        // The examples in the stock file do look like mappings, and are shown as switched off.
        let doc =
            HostsDoc::parse("#      102.54.94.97     rhino.acme.com          # source server");
        let e = doc.entry(0).unwrap();
        assert!(!e.enabled);
        assert_eq!(
            (e.ip.as_str(), e.comment.as_str()),
            ("102.54.94.97", "source server")
        );
    }

    #[test]
    fn round_trip_is_byte_exact_for_every_line_ending_and_encoding() {
        let variants: Vec<Vec<u8>> = vec![
            SAMPLE.as_bytes().to_vec(),
            SAMPLE.replace("\r\n", "\n").into_bytes(),
            // Mixed endings, no final newline, trailing spaces, odd spacing.
            b"127.0.0.1 a.test\r\n# c\n\n  ::1\t\tb.test  \r\n10.0.0.1 last.test".to_vec(),
            // UTF-8 with a byte-order mark.
            [
                &[0xEF, 0xBB, 0xBF][..],
                "# caf\u{e9}\r\n127.0.0.1 a.test\r\n".as_bytes(),
            ]
            .concat(),
            // Not UTF-8 at all (a Latin-1 comment).
            b"# caf\xe9\r\n127.0.0.1 a.test\r\n".to_vec(),
            // UTF-16 LE with a byte-order mark.
            {
                let mut v = vec![0xFF, 0xFE];
                for u in "127.0.0.1 a.test\r\n".encode_utf16() {
                    v.extend_from_slice(&u.to_le_bytes());
                }
                v
            },
            Vec::new(),
            b"\r\n\r\n".to_vec(),
            b"\n".to_vec(),
            b"127.0.0.1 only.test".to_vec(),
        ];
        for bytes in variants {
            let doc = HostsDoc::from_bytes(&bytes);
            assert_eq!(doc.to_bytes(), bytes, "round trip changed the file");
        }
        assert_eq!(
            HostsDoc::from_bytes(&[0xEF, 0xBB, 0xBF, b'#']).encoding,
            Encoding::Utf8Bom
        );
        assert_eq!(HostsDoc::from_bytes(b"# \xe9").encoding, Encoding::Latin1);
        // A BOM does not hide the first entry.
        let doc =
            HostsDoc::from_bytes(&[&[0xEF, 0xBB, 0xBF][..], b"127.0.0.1 first.test\n"].concat());
        assert_eq!(doc.entry(0).unwrap().hosts, vec!["first.test"]);
    }

    /// Lines that differ between two texts, as `(index, before, after)`.
    fn changed_lines(a: &str, b: &str) -> Vec<(usize, String, String)> {
        let (la, lb): (Vec<&str>, Vec<&str>) = (a.split('\n').collect(), b.split('\n').collect());
        assert_eq!(la.len(), lb.len(), "line count changed");
        la.iter()
            .zip(&lb)
            .enumerate()
            .filter(|(_, (x, y))| x != y)
            .map(|(i, (x, y))| (i, x.to_string(), y.to_string()))
            .collect()
    }

    #[test]
    fn toggling_changes_exactly_one_line_and_is_reversible() {
        let mut doc = HostsDoc::parse(SAMPLE);
        assert!(doc.set_enabled(8, false));
        let off = doc.to_text();
        let diff = changed_lines(SAMPLE, &off);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].0, 8);
        assert_eq!(diff[0].2, "# 10.0.0.5     db.test\r");
        assert!(!doc.entry(8).unwrap().enabled);
        // Reparsing the written text gives the same document.
        assert_eq!(HostsDoc::parse(&off), doc);

        // Enabling an entry that was commented out with a tab.
        assert!(doc.set_enabled(3, true));
        assert_eq!(doc.lines[3].raw, "127.0.0.1       localhost");
        assert!(doc.set_enabled(3, false));
        assert_eq!(doc.lines[3].raw, "# 127.0.0.1       localhost");
        // No-ops report false and change nothing.
        let before = doc.to_text();
        assert!(!doc.set_enabled(3, false));
        assert!(!doc.set_enabled(0, true), "comments cannot be toggled");
        assert!(!doc.set_enabled(999, true));
        assert_eq!(doc.to_text(), before);

        // Enable + disable of a tidy line is an exact round trip.
        let mut doc = HostsDoc::parse("# 10.0.0.6 old.test\r\n");
        doc.set_enabled(0, true);
        assert_eq!(doc.to_text(), "10.0.0.6 old.test\r\n");
        doc.set_enabled(0, false);
        assert_eq!(doc.to_text(), "# 10.0.0.6 old.test\r\n");
    }

    #[test]
    fn group_toggle() {
        let mut doc = HostsDoc::parse(SAMPLE);
        assert_eq!(doc.set_group_enabled("Dev", false), 3);
        assert_eq!(doc.enabled_count(), 1);
        assert_eq!(doc.set_group_enabled("Dev", true), 4);
        assert_eq!(doc.enabled_count(), 5);
        assert_eq!(doc.set_group_enabled("Nope", true), 0);
    }

    #[test]
    fn edit_add_delete() {
        let mut doc = HostsDoc::parse(SAMPLE);
        let mut e = doc.entry(8).unwrap().clone();
        e.hosts.push("db2.test".into());
        e.comment = "databases".into();
        assert!(doc.update_entry(8, e));
        assert_eq!(doc.lines[8].raw, "10.0.0.5\tdb.test db2.test # databases");
        assert!(!doc.update_entry(0, Entry::new("1.1.1.1", &["x.test"])));
        assert_eq!(changed_lines(SAMPLE, &doc.to_text()).len(), 1);

        // Into an existing group: right after its last entry.
        let at = doc.add_entry(Entry::new("10.0.0.9", &["new.test"]), Some("Dev"));
        assert_eq!(at, 11);
        assert_eq!(doc.lines[11].raw, "10.0.0.9\tnew.test");
        assert_eq!(doc.lines[11].eol, Some(Eol::CrLf));
        assert_eq!(doc.rows()[6].group, "Dev");

        // Into a new group: blank line, header, entry at the end.
        let at = doc.add_entry(Entry::new("10.1.1.1", &["s.test"]), Some("Staging"));
        assert_eq!(at, doc.lines.len() - 1);
        assert!(doc
            .to_text()
            .ends_with("0.0.0.0 ads.example\r\n\r\n# Staging\r\n10.1.1.1\ts.test\r\n"));
        assert_eq!(doc.rows().last().unwrap().group, "Staging");

        // Without a group: at the end, separated so that it does not join "Staging".
        doc.add_entry(Entry::new("10.2.2.2", &["free.test"]), None);
        assert!(doc
            .to_text()
            .ends_with("10.1.1.1\ts.test\r\n\r\n10.2.2.2\tfree.test\r\n"));
        assert_eq!(doc.rows().last().unwrap().group, "");

        let n = doc.lines.len();
        assert!(doc.delete_line(n - 1));
        assert!(!doc.delete_line(n + 5));
        assert_eq!(HostsDoc::parse(&doc.to_text()), doc);
    }

    #[test]
    fn appending_keeps_the_files_line_ending_style() {
        // LF file without a final newline stays that way.
        let mut doc = HostsDoc::parse("127.0.0.1 a.test\n127.0.0.1 b.test");
        doc.add_entry(Entry::new("127.0.0.1", &["c.test"]), None);
        assert_eq!(
            doc.to_text(),
            "127.0.0.1 a.test\n127.0.0.1 b.test\n127.0.0.1\tc.test"
        );
        doc.delete_line(2);
        assert_eq!(doc.to_text(), "127.0.0.1 a.test\n127.0.0.1 b.test");
        // An empty file gets Windows line endings.
        let mut doc = HostsDoc::parse("");
        doc.add_entry(Entry::new("127.0.0.1", &["a.test"]), None);
        assert_eq!(doc.to_text(), "127.0.0.1\ta.test\r\n");
    }

    #[test]
    fn duplicates_conflicts_and_syntax_problems() {
        let doc = HostsDoc::parse(
            "127.0.0.1 a.test\n\
             127.0.0.1 A.TEST b.test\n\
             10.0.0.1 a.test\n\
             ::1 a.test\n\
             # 10.0.0.2 a.test\n\
             999.1.1.1 bad.test\n\
             127.0.0.1 under_score.test *.wild.test b\u{fc}cher.test\n\
             justoneword\n\
             127.0.0.1 has/slash\n",
        );
        let issues = doc.issues();
        let kinds: Vec<(usize, IssueKind)> = issues.iter().map(|i| (i.line, i.kind)).collect();
        assert_eq!(
            kinds,
            vec![
                (1, IssueKind::Duplicate),
                (2, IssueKind::Conflict),
                // ::1 is a different address family: not a conflict with 127.0.0.1.
                // Line 4 is switched off: not counted.
                (5, IssueKind::BadAddress),
                (6, IssueKind::BadName),
                (6, IssueKind::BadName),
                (7, IssueKind::Invalid),
                (8, IssueKind::BadName),
            ]
        );
        assert!(issues[0].message.contains("line 1"));
        assert!(issues[1].message.contains("127.0.0.1"));
        assert!(issues[3].message.contains("wildcards"));
        assert!(issues[4].message.contains("punycode"));
        assert!(name_problem("ok-name_1.example").is_none());
        assert!(name_problem(&"a".repeat(64)).is_some());
        assert!(name_problem("a..b").is_some());
        assert!(parse_ip("fe80::1%eth0").is_some());
        assert!(parse_ip("1.2.3").is_none());
    }

    #[test]
    fn merge_skips_what_is_there_and_disarms_conflicts() {
        let mut doc = HostsDoc::parse("127.0.0.1 a.test\r\n10.0.0.1 b.test\r\n");
        let other = HostsDoc::parse(
            "127.0.0.1 a.test c.test\n10.0.0.2 b.test\n# 10.0.0.3 d.test\nnot-a-line\n::1 a.test\n",
        );
        let report = doc.merge(&other, "Imported");
        assert_eq!(
            report,
            MergeReport {
                added: 3,
                already_present: 1,
                conflicts: 1
            }
        );
        assert_eq!(
            doc.to_text(),
            "127.0.0.1 a.test\r\n10.0.0.1 b.test\r\n\r\n# Imported\r\n127.0.0.1\tc.test\r\n\
             # 10.0.0.2\tb.test\r\n# 10.0.0.3\td.test\r\n::1\ta.test\r\n"
        );
        // Merging the same file again adds nothing new.
        let again = doc.merge(&other, "Imported");
        assert_eq!(again.added, 0);
        assert!(doc.issues().is_empty());
    }

    #[test]
    fn profiles_switch_on_and_off_as_a_block() {
        let original = "127.0.0.1 a.test\r\n";
        let mut doc = HostsDoc::parse(original);
        let dev = Profile {
            name: "dev".into(),
            entries: vec![
                ProfileEntry {
                    ip: "127.0.0.1".into(),
                    hosts: vec!["x.dev.test".into(), "y.dev.test".into()],
                    comment: "mock".into(),
                },
                ProfileEntry {
                    ip: "::1".into(),
                    hosts: vec!["x.dev.test".into()],
                    comment: String::new(),
                },
            ],
        };
        let staging = Profile {
            name: "staging".into(),
            entries: vec![ProfileEntry {
                ip: "10.0.0.7".into(),
                hosts: vec!["s.test".into()],
                comment: String::new(),
            }],
        };
        assert!(doc.active_profiles().is_empty());
        doc.profile_on(&dev);
        assert_eq!(
            doc.to_text(),
            "127.0.0.1 a.test\r\n\r\n# >>> SocketForge profile: dev\r\n\
             127.0.0.1\tx.dev.test y.dev.test # mock\r\n::1\tx.dev.test\r\n\
             # <<< SocketForge profile: dev\r\n"
        );
        doc.profile_on(&staging);
        assert_eq!(doc.active_profiles(), vec!["dev", "staging"]);
        assert!(doc.is_profile_active("dev"));
        let rows = doc.rows();
        assert_eq!(rows[1].profile.as_deref(), Some("dev"));
        assert_eq!(rows[1].group, "Profile: dev");
        assert_eq!(rows[3].profile.as_deref(), Some("staging"));
        assert_eq!(rows[0].profile, None);

        // Switching on twice does not duplicate the block.
        doc.profile_on(&dev);
        assert_eq!(doc.active_profiles(), vec!["staging", "dev"]);
        assert_eq!(doc.entry_count(), 4);

        // New ungrouped entries go above the profile blocks.
        doc.add_entry(Entry::new("10.9.9.9", &["plain.test"]), None);
        assert!(doc
            .to_text()
            .starts_with("127.0.0.1 a.test\r\n10.9.9.9\tplain.test\r\n\r\n# >>>"));
        assert_eq!(doc.rows()[1].profile, None);
        doc.delete_line(1);

        assert!(doc.profile_off("dev"));
        assert!(doc.profile_off("staging"));
        assert!(!doc.profile_off("staging"));
        assert_eq!(
            doc.to_text(),
            original,
            "switching profiles off restores the file"
        );

        let from_group = HostsDoc::parse(SAMPLE).profile_from_group("Dev", "saved");
        assert_eq!(from_group.entries.len(), 4);
        assert_eq!(from_group.entries[0].hosts, vec!["app.test", "api.test"]);
    }

    #[test]
    fn profile_off_at_end_of_file_without_trailing_newline() {
        let mut doc = HostsDoc::parse("127.0.0.1 a.test");
        let p = Profile {
            name: "p".into(),
            entries: vec![ProfileEntry {
                ip: "127.0.0.1".into(),
                hosts: vec!["b.test".into()],
                comment: String::new(),
            }],
        };
        doc.profile_on(&p);
        assert!(doc.to_text().ends_with("# <<< SocketForge profile: p"));
        doc.profile_off("p");
        assert_eq!(doc.to_text(), "127.0.0.1 a.test");
    }

    #[test]
    fn raw_text_editing_keeps_the_encoding() {
        let mut doc =
            HostsDoc::from_bytes(&[&[0xEF, 0xBB, 0xBF][..], b"127.0.0.1 a.test\r\n"].concat());
        doc.set_text("127.0.0.1 a.test\r\n10.0.0.1 b.test\r\n");
        assert_eq!(doc.entry_count(), 2);
        assert!(doc.to_bytes().starts_with(&[0xEF, 0xBB, 0xBF]));
    }

    #[test]
    fn demo_data_parses_and_has_something_to_show() {
        let doc = HostsDoc::parse(&demo_text());
        assert!(doc.entry_count() >= 12);
        assert_eq!(doc.active_profiles(), vec!["dev"]);
        let kinds: Vec<IssueKind> = doc.issues().iter().map(|i| i.kind).collect();
        assert!(kinds.contains(&IssueKind::Conflict));
        assert!(kinds.contains(&IssueKind::BadAddress));
        assert_eq!(doc.to_text(), demo_text());
        assert!(demo_profiles().iter().any(|p| p.name == "dev"));
    }
}
