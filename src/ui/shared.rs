//! State that every view may need: settings, toasts, the search text, rights.
//!
//! Views get `&mut Shared` next to their own state. New members may be added;
//! existing ones must keep their names and meaning (the hosts view relies on them).

use crate::settings::Settings;
use std::path::PathBuf;
use std::time::Instant;

pub struct Toast {
    pub text: String,
    pub error: bool,
    pub born: Instant,
}

pub struct Shared {
    /// Invented data; nothing on this PC is read or changed.
    pub demo: bool,
    /// Rendering a screenshot: no animations that never settle, no native dialogs.
    pub screenshot: bool,
    /// Running with administrator rights.
    pub elevated: bool,
    pub settings: Settings,
    /// Set when `settings` changed; the app saves them and clears the flag.
    pub settings_dirty: bool,
    /// `%LOCALAPPDATA%\SocketForge` (an invented path in the demo).
    pub app_dir: PathBuf,
    /// The header's search box. Each view filters by it.
    pub search: String,
    pub toasts: Vec<Toast>,
}

impl Shared {
    pub fn toast(&mut self, text: impl Into<String>, error: bool) {
        self.toasts.push(Toast {
            text: text.into(),
            error,
            born: Instant::now(),
        });
    }

    /// Marks the settings as changed so that they get saved.
    pub fn touch_settings(&mut self) {
        self.settings_dirty = true;
    }
}
