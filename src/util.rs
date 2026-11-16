//! Small helpers: local time, durations, text escaping.

use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

/// Broken-down local time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalTime {
    pub year: u16,
    pub month: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
}

/// 100-nanosecond intervals between 1601-01-01 and 1970-01-01.
const EPOCH_DIFF: i64 = 116_444_736_000_000_000;

/// Windows FILETIME ticks to Unix seconds.
pub fn filetime_to_unix(ticks: i64) -> Option<i64> {
    (ticks > EPOCH_DIFF).then(|| (ticks - EPOCH_DIFF) / 10_000_000)
}

/// Converts Unix seconds (UTC) to this PC's local time.
pub fn local_time(unix: i64) -> Option<LocalTime> {
    let ticks = unix.checked_mul(10_000_000)?.checked_add(EPOCH_DIFF)?;
    if ticks < 0 {
        return None;
    }
    let ft = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut utc = SYSTEMTIME::default();
    let mut local = SYSTEMTIME::default();
    unsafe {
        FileTimeToSystemTime(&ft, &mut utc).ok()?;
        SystemTimeToTzSpecificLocalTime(None, &utc, &mut local).ok()?;
    }
    Some(LocalTime {
        year: local.wYear,
        month: local.wMonth,
        day: local.wDay,
        hour: local.wHour,
        minute: local.wMinute,
        second: local.wSecond,
    })
}

/// `2026-03-09 14:05:07` in local time; empty for times that cannot be shown.
pub fn fmt_time(unix: i64) -> String {
    match local_time(unix) {
        Some(t) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            t.year, t.month, t.day, t.hour, t.minute, t.second
        ),
        None => String::new(),
    }
}

/// `14:05:07` in local time.
pub fn fmt_clock(unix: i64) -> String {
    match local_time(unix) {
        Some(t) => format!("{:02}:{:02}:{:02}", t.hour, t.minute, t.second),
        None => String::new(),
    }
}

/// `20260309-140507` in local time: used in backup file names.
pub fn fmt_stamp(unix: i64) -> String {
    match local_time(unix) {
        Some(t) => format!(
            "{:04}{:02}{:02}-{:02}{:02}{:02}",
            t.year, t.month, t.day, t.hour, t.minute, t.second
        ),
        None => format!("t{unix}"),
    }
}

/// A rough age: `12 s`, `5 min`, `3 h 12 min`, `4 d 2 h`.
pub fn fmt_age(seconds: i64) -> String {
    let s = seconds.max(0);
    if s < 60 {
        format!("{s} s")
    } else if s < 3600 {
        format!("{} min", s / 60)
    } else if s < 86_400 {
        let (h, m) = (s / 3600, (s % 3600) / 60);
        if m == 0 {
            format!("{h} h")
        } else {
            format!("{h} h {m} min")
        }
    } else {
        let (d, h) = (s / 86_400, (s % 86_400) / 3600);
        if h == 0 {
            format!("{d} d")
        } else {
            format!("{d} d {h} h")
        }
    }
}

/// Quotes a CSV field when needed (RFC 4180).
pub fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub fn csv_line(fields: &[&str]) -> String {
    fields
        .iter()
        .map(|f| csv_field(f))
        .collect::<Vec<_>>()
        .join(",")
}

pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// UTF-16, NUL-terminated.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// UTF-16 up to the first NUL.
pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages() {
        assert_eq!(fmt_age(-5), "0 s");
        assert_eq!(fmt_age(59), "59 s");
        assert_eq!(fmt_age(60), "1 min");
        assert_eq!(fmt_age(3600), "1 h");
        assert_eq!(fmt_age(3600 * 3 + 12 * 60), "3 h 12 min");
        assert_eq!(fmt_age(86_400 * 4 + 7200), "4 d 2 h");
    }

    #[test]
    fn time_formats_have_the_right_shape() {
        let s = fmt_time(1_700_000_000);
        assert_eq!(s.len(), 19);
        assert!(s.starts_with("2023-11-1"));
        assert_eq!(fmt_stamp(1_700_000_000).len(), 15);
        assert_eq!(fmt_clock(1_700_000_000).len(), 8);
        assert_eq!(filetime_to_unix(EPOCH_DIFF + 10_000_000), Some(1));
        assert_eq!(filetime_to_unix(0), None);
    }

    #[test]
    fn escaping() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_line(&["a", "b c", "d,e"]), "a,b c,\"d,e\"");
        assert_eq!(
            html_escape("<a href=\"x\">&</a>"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;"
        );
        assert_eq!(from_wide(&wide("héllo")), "héllo");
    }
}
