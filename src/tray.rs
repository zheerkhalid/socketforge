//! The notification-area icon: a small menu (Show / Exit) and balloon
//! notifications for watch alerts.
//!
//! The icon lives on its own thread with a hidden window, so it keeps working
//! while the main window is hidden and its event loop is asleep. Nothing here
//! adds a startup entry.

use std::ffi::c_void;
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{BOOL, HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIIF_WARNING, NIM_ADD,
    NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
};
use windows::Win32::UI::WindowsAndMessaging::*;

const WM_TRAY: u32 = WM_APP + 1;
const WM_SET_ENABLED: u32 = WM_APP + 2;
const WM_UPDATE: u32 = WM_APP + 3;
const WM_NOTIFY_USER: u32 = WM_APP + 4;
const WM_QUIT_THREAD: u32 = WM_APP + 5;

const MENU_SHOW: usize = 1;
const MENU_EXIT: usize = 2;

/// Most notifications waiting to be shown; more than that are dropped.
const MAX_PENDING: usize = 8;

/// What the user did with the tray icon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayEvent {
    /// Show the main window (it has already been made visible).
    Show,
    Exit,
}

struct Pending {
    title: String,
    text: String,
    warning: bool,
}

struct State {
    tx: Sender<TrayEvent>,
    wake: Box<dyn Fn() + Send>,
    main_window: isize,
    enabled: bool,
    added: bool,
    tooltip: String,
    pending: Vec<Pending>,
    taskbar_created: u32,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> Option<R> {
    STATE.lock().ok().and_then(|mut g| g.as_mut().map(f))
}

fn emit(event: TrayEvent) {
    with_state(|s| {
        let _ = s.tx.send(event);
        (s.wake)();
    });
}

fn hwnd(raw: isize) -> HWND {
    HWND(raw as *mut c_void)
}

/// Hides a window completely (it lives on in the notification area).
pub fn hide_window(raw: isize) {
    if raw != 0 {
        // SAFETY: a window handle of this process; a stale handle just fails.
        unsafe {
            let _ = ShowWindow(hwnd(raw), SW_HIDE);
        }
    }
}

/// Shows a window again, restores it if minimised and brings it to the front.
pub fn show_window(raw: isize) {
    if raw != 0 {
        // SAFETY: as above.
        unsafe {
            if IsIconic(hwnd(raw)).as_bool() {
                let _ = ShowWindow(hwnd(raw), SW_RESTORE);
            } else {
                let _ = ShowWindow(hwnd(raw), SW_SHOW);
            }
            let _ = SetForegroundWindow(hwnd(raw));
        }
    }
}

unsafe extern "system" fn find_proc(window: HWND, lparam: LPARAM) -> BOOL {
    // Top-level, unowned, with a title: that is the application window.
    let owned = GetWindow(window, GW_OWNER)
        .map(|o| !o.is_invalid())
        .unwrap_or(false);
    if !owned && GetWindowTextLengthW(window) > 0 {
        *(lparam.0 as *mut isize) = window.0 as isize;
        return BOOL(0);
    }
    BOOL(1)
}

/// The top-level window of the calling thread (the eframe window when called
/// from the user-interface thread), or 0 when there is none yet.
pub fn find_thread_window() -> isize {
    let mut found: isize = 0;
    // SAFETY: the callback only writes to `found`, which outlives the call.
    unsafe {
        let _ = EnumThreadWindows(
            GetCurrentThreadId(),
            Some(find_proc),
            LPARAM(&mut found as *mut isize as isize),
        );
    }
    found
}

unsafe fn app_icon() -> HICON {
    let module = GetModuleHandleW(PCWSTR::null()).unwrap_or_default();
    // Icon resource 1 is the application icon embedded by the build script.
    LoadIconW(
        HINSTANCE(module.0),
        PCWSTR(std::ptr::without_provenance::<u16>(1)),
    )
    .or_else(|_| LoadIconW(HINSTANCE::default(), IDI_APPLICATION))
    .unwrap_or_default()
}

/// Copies `text` into a fixed UTF-16 buffer, truncating and NUL-terminating.
pub fn copy_wide(dst: &mut [u16], text: &str) {
    if dst.is_empty() {
        return;
    }
    let max = dst.len() - 1;
    let mut i = 0;
    for c in text.encode_utf16() {
        if i >= max {
            break;
        }
        dst[i] = c;
        i += 1;
    }
    dst[i] = 0;
}

/// Adds, updates or removes the icon so that it matches the state.
unsafe fn sync(window: HWND) {
    let Some((enabled, added, tooltip)) = with_state(|s| (s.enabled, s.added, s.tooltip.clone()))
    else {
        return;
    };
    let mut data = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: window,
        uID: 1,
        ..Default::default()
    };
    if !enabled {
        if added {
            let _ = Shell_NotifyIconW(NIM_DELETE, &data);
            with_state(|s| s.added = false);
        }
        return;
    }
    data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    data.uCallbackMessage = WM_TRAY;
    data.hIcon = app_icon();
    copy_wide(&mut data.szTip, &tooltip);
    let ok = Shell_NotifyIconW(if added { NIM_MODIFY } else { NIM_ADD }, &data).as_bool();
    if ok {
        with_state(|s| s.added = true);
    }
}

unsafe fn show_pending(window: HWND) {
    let Some((items, added)) = with_state(|s| (std::mem::take(&mut s.pending), s.added)) else {
        return;
    };
    if !added {
        return;
    }
    for item in items {
        let mut data = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: window,
            uID: 1,
            uFlags: NIF_INFO,
            dwInfoFlags: if item.warning {
                NIIF_WARNING
            } else {
                NIIF_INFO
            },
            ..Default::default()
        };
        copy_wide(&mut data.szInfoTitle, &item.title);
        copy_wide(&mut data.szInfo, &item.text);
        let _ = Shell_NotifyIconW(NIM_MODIFY, &data);
    }
}

fn main_window() -> isize {
    with_state(|s| s.main_window).unwrap_or(0)
}

/// A hidden window does not run its event loop: nudge it with a harmless message.
fn wake_main() {
    let main = main_window();
    if main != 0 {
        // SAFETY: posting to a window of this process; a stale handle just fails.
        unsafe {
            let _ = PostMessageW(hwnd(main), WM_NULL, WPARAM(0), LPARAM(0));
        }
    }
}

fn show_main() {
    show_window(main_window());
    emit(TrayEvent::Show);
}

unsafe fn tray_menu(window: HWND) {
    let Ok(menu) = CreatePopupMenu() else { return };
    let _ = AppendMenuW(menu, MF_STRING, MENU_SHOW, w!("Show SocketForge"));
    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    let _ = AppendMenuW(menu, MF_STRING, MENU_EXIT, w!("Exit"));
    let mut pt = POINT::default();
    let _ = GetCursorPos(&mut pt);
    // Needed so the menu closes when the user clicks elsewhere.
    let _ = SetForegroundWindow(window);
    let choice = TrackPopupMenu(
        menu,
        TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
        pt.x,
        pt.y,
        0,
        window,
        None,
    );
    let _ = DestroyMenu(menu);
    match choice.0 as usize {
        MENU_SHOW => show_main(),
        MENU_EXIT => {
            // The main window must be awake to process the exit.
            emit(TrayEvent::Exit);
            wake_main();
        }
        _ => {}
    }
}

unsafe extern "system" fn wnd_proc(
    window: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_TRAY => {
            match lparam.0 as u32 {
                WM_LBUTTONUP | WM_LBUTTONDBLCLK => show_main(),
                WM_RBUTTONUP | WM_CONTEXTMENU => tray_menu(window),
                _ => {}
            }
            LRESULT(0)
        }
        WM_SET_ENABLED => {
            with_state(|s| s.enabled = wparam.0 != 0);
            sync(window);
            LRESULT(0)
        }
        WM_UPDATE => {
            sync(window);
            LRESULT(0)
        }
        WM_NOTIFY_USER => {
            show_pending(window);
            LRESULT(0)
        }
        WM_QUIT_THREAD => {
            with_state(|s| s.enabled = false);
            sync(window);
            let _ = DestroyWindow(window);
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => {
            // Explorer restarted: the icon has to be added again.
            let created = with_state(|s| s.taskbar_created).unwrap_or(0);
            if created != 0 && msg == created {
                with_state(|s| s.added = false);
                sync(window);
                return LRESULT(0);
            }
            DefWindowProcW(window, msg, wparam, lparam)
        }
    }
}

/// Handle to the tray thread. Cheap to clone; all methods just post a message.
#[derive(Clone)]
pub struct Tray {
    window: isize,
}

impl Tray {
    /// Starts the tray thread (the icon itself appears with [`Tray::set_enabled`]).
    /// `wake` is called after every event so the user interface picks it up.
    pub fn start(
        main_window: isize,
        tx: Sender<TrayEvent>,
        wake: Box<dyn Fn() + Send>,
    ) -> Option<Tray> {
        if let Ok(mut g) = STATE.lock() {
            *g = Some(State {
                tx,
                wake,
                main_window,
                enabled: false,
                added: false,
                tooltip: "SocketForge".into(),
                pending: Vec::new(),
                taskbar_created: 0,
            });
        }
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<isize>();
        std::thread::Builder::new()
            .name("socketforge-tray".into())
            .spawn(move || {
                // SAFETY: a standard window class, window and message loop,
                // all owned by this thread.
                unsafe {
                    let module = GetModuleHandleW(PCWSTR::null()).unwrap_or_default();
                    let class = WNDCLASSW {
                        lpfnWndProc: Some(wnd_proc),
                        hInstance: HINSTANCE(module.0),
                        lpszClassName: w!("SocketForgeTrayWindow"),
                        ..Default::default()
                    };
                    RegisterClassW(&class);
                    let window = CreateWindowExW(
                        WS_EX_TOOLWINDOW,
                        w!("SocketForgeTrayWindow"),
                        w!("SocketForge tray"),
                        WS_POPUP,
                        0,
                        0,
                        0,
                        0,
                        HWND::default(),
                        HMENU::default(),
                        HINSTANCE(module.0),
                        None,
                    );
                    let Ok(window) = window else {
                        let _ = ready_tx.send(0);
                        return;
                    };
                    let created = RegisterWindowMessageW(w!("TaskbarCreated"));
                    with_state(|s| s.taskbar_created = created);
                    let _ = ready_tx.send(window.0 as isize);
                    let mut msg = MSG::default();
                    while GetMessageW(&mut msg, HWND::default(), 0, 0).as_bool() {
                        let _ = TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
            })
            .ok()?;
        let window = ready_rx.recv().ok().filter(|w| *w != 0)?;
        Some(Tray { window })
    }

    fn post(&self, msg: u32, wparam: usize) {
        // SAFETY: posting to our own window; a stale handle just fails.
        unsafe {
            let _ = PostMessageW(hwnd(self.window), msg, WPARAM(wparam), LPARAM(0));
        }
    }

    /// Shows or removes the icon.
    pub fn set_enabled(&self, on: bool) {
        self.post(WM_SET_ENABLED, usize::from(on));
    }

    /// Sets the tooltip. Does nothing if it is unchanged.
    pub fn set_tooltip(&self, tooltip: &str) {
        let changed = with_state(|s| {
            let tooltip: String = tooltip.chars().take(120).collect();
            if s.tooltip == tooltip {
                false
            } else {
                s.tooltip = tooltip;
                true
            }
        })
        .unwrap_or(false);
        if changed {
            self.post(WM_UPDATE, 0);
        }
    }

    /// Shows a notification bubble (only while the icon is visible).
    pub fn notify(&self, title: &str, text: &str, warning: bool) {
        with_state(|s| {
            if s.pending.len() < MAX_PENDING {
                s.pending.push(Pending {
                    title: title.to_string(),
                    text: text.to_string(),
                    warning,
                });
            }
        });
        self.post(WM_NOTIFY_USER, 0);
    }

    /// Removes the icon and ends the thread.
    pub fn stop(&self) {
        self.post(WM_QUIT_THREAD, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_copy_truncates_and_terminates() {
        let mut buf = [0xffffu16; 6];
        copy_wide(&mut buf, "SocketForge");
        assert_eq!(&buf[..5], &[83, 111, 99, 107, 101]);
        assert_eq!(buf[5], 0);
        let mut buf = [0xffffu16; 6];
        copy_wide(&mut buf, "ab");
        assert_eq!(&buf[..3], &[97, 98, 0]);
        let mut empty: [u16; 0] = [];
        copy_wide(&mut empty, "x");
    }
}
