//! "Serve this folder": a small static web server for developers.
//!
//! It answers GET and HEAD for the files under one folder, lists folders that
//! have no `index.html`, and nothing else. By default it listens on this PC
//! only. It is a development helper, not a server for the open internet.

use crate::model::now_unix;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Called when something changed that the window should show.
pub type Wake = Arc<dyn Fn() + Send + Sync>;

/// Requests kept for the list in the window.
const LOG_LIMIT: usize = 200;
/// Connections answered at the same time; more get "busy".
const MAX_ACTIVE: usize = 64;
/// The largest request head read.
const MAX_HEAD: usize = 16 * 1024;

/// One answered request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestLog {
    /// Unix seconds.
    pub time: i64,
    pub method: String,
    pub path: String,
    pub status: u16,
    /// Bytes of content sent.
    pub bytes: u64,
    /// True when the request came from another device.
    pub remote: bool,
}

struct Shared {
    log: Mutex<VecDeque<RequestLog>>,
    served: AtomicU64,
    active: AtomicUsize,
    wake: Option<Wake>,
}

/// A running folder server. Dropping it stops it and frees the port.
pub struct FolderServer {
    addr: SocketAddr,
    root: PathBuf,
    lan: bool,
    stop: Arc<AtomicBool>,
    shared: Arc<Shared>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// Why a port could not be opened, in plain words.
pub fn bind_error_text(port: u16, e: &std::io::Error) -> String {
    match (e.kind(), e.raw_os_error()) {
        (std::io::ErrorKind::AddrInUse, _) | (_, Some(10048)) => format!(
            "Port {port} is already in use. Pick another one; Port check can find a free port."
        ),
        (std::io::ErrorKind::PermissionDenied, _) | (_, Some(10013)) => format!(
            "Windows does not allow opening port {port} (it is in a reserved range or needs \
             administrator rights). Pick another one."
        ),
        _ => format!("Could not open port {port}: {e}"),
    }
}

impl FolderServer {
    /// Starts serving `root`. `port` 0 lets Windows pick a free port. With
    /// `lan` other devices on the network may connect; otherwise only this PC.
    pub fn start(
        root: &Path,
        port: u16,
        lan: bool,
        wake: Option<Wake>,
    ) -> Result<FolderServer, String> {
        let root = root
            .canonicalize()
            .map_err(|_| "That folder does not exist.".to_string())?;
        if !root.is_dir() {
            return Err("That is a file, not a folder.".into());
        }
        if lan && root.parent().is_none() {
            return Err(
                "A whole drive cannot be shared with the network. Pick a folder on it.".into(),
            );
        }
        let ip = if lan {
            Ipv4Addr::UNSPECIFIED
        } else {
            Ipv4Addr::LOCALHOST
        };
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(ip), port))
            .map_err(|e| bind_error_text(port, &e))?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("Could not start the server: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("Could not start the server: {e}"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Shared {
            log: Mutex::new(VecDeque::new()),
            served: AtomicU64::new(0),
            active: AtomicUsize::new(0),
            wake,
        });
        let (stop2, shared2, root2) = (stop.clone(), shared.clone(), root.clone());
        let thread = std::thread::Builder::new()
            .name("serve-folder".into())
            .spawn(move || accept_loop(listener, root2, stop2, shared2))
            .map_err(|e| format!("Could not start the server: {e}"))?;
        Ok(FolderServer {
            addr,
            root,
            lan,
            stop,
            shared,
            thread: Some(thread),
        })
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// True when other devices may connect.
    pub fn lan(&self) -> bool {
        self.lan
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The address to open on this PC.
    pub fn url(&self) -> String {
        format!("http://localhost:{}/", self.addr.port())
    }

    /// Requests answered since the start.
    pub fn served(&self) -> u64 {
        self.shared.served.load(Ordering::Relaxed)
    }

    /// The latest requests, newest first.
    pub fn requests(&self) -> Vec<RequestLog> {
        self.shared
            .log
            .lock()
            .map(|l| l.iter().rev().cloned().collect())
            .unwrap_or_default()
    }

    /// Stops the server and waits until the port is free again.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for FolderServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(listener: TcpListener, root: PathBuf, stop: Arc<AtomicBool>, shared: Arc<Shared>) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                // On Windows an accepted socket inherits "non-blocking".
                let _ = stream.set_nonblocking(false);
                if shared.active.load(Ordering::Relaxed) >= MAX_ACTIVE {
                    let mut s = stream;
                    let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
                    let _ = write_simple(&mut s, 503, "The server is busy. Try again.", false);
                    continue;
                }
                shared.active.fetch_add(1, Ordering::Relaxed);
                let (root, shared2) = (root.clone(), shared.clone());
                let spawned =
                    std::thread::Builder::new()
                        .name("serve-conn".into())
                        .spawn(move || {
                            handle(stream, peer, &root, &shared2);
                            shared2.active.fetch_sub(1, Ordering::Relaxed);
                        });
                if spawned.is_err() {
                    shared.active.fetch_sub(1, Ordering::Relaxed);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

/// Reads the request head: everything up to the blank line.
fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.windows(2).any(|w| w == b"\n\n") {
            break;
        }
        if buf.len() > MAX_HEAD {
            return None;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return None,
        }
    }
    (!buf.is_empty()).then(|| String::from_utf8_lossy(&buf).into_owned())
}

/// Splits the request line into method and target.
pub fn parse_request_line(head: &str) -> Option<(String, String)> {
    let line = head.lines().next()?;
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() || !version.starts_with("HTTP/1.") || method.is_empty() {
        return None;
    }
    Some((method.to_string(), target.to_string()))
}

/// Decodes `%41` style escapes. None when the text is not valid.
pub fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Encodes a file name for use in a link.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn is_device_name(segment: &str) -> bool {
    let stem = segment.split('.').next().unwrap_or("").to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || (stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.as_bytes()[3].is_ascii_digit())
}

/// Maps the path of a URL to a path under `root`. The result has not been
/// checked for existence. `Err` is the HTTP status to answer with.
pub fn resolve(root: &Path, target: &str) -> Result<PathBuf, u16> {
    let path = target.split(['?', '#']).next().unwrap_or("");
    if !path.starts_with('/') {
        return Err(400);
    }
    let decoded = percent_decode(path).ok_or(400u16)?;
    let mut out = root.to_path_buf();
    for segment in decoded.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        // Nothing that climbs out of the folder, names a drive or a file
        // stream, or that Windows would quietly rewrite to another name.
        if segment == ".."
            || segment.contains(['\\', ':', '\0', '*', '?', '"', '<', '>', '|'])
            || segment.chars().any(|c| c.is_control())
            || segment.ends_with('.')
            || segment.ends_with(' ')
        {
            return Err(403);
        }
        if is_device_name(segment) {
            return Err(404);
        }
        out.push(segment);
    }
    Ok(out)
}

/// The content type for a file name.
pub fn content_type(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "txt" | "log" | "md" => "text/plain; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        301 => "Moved Permanently",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

fn write_head(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    length: u64,
    extra: &str,
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {length}\r\n\
         Connection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\
         Server: SocketForge\r\n{extra}\r\n",
        status_text(status)
    );
    stream.write_all(head.as_bytes())
}

fn write_simple(
    stream: &mut TcpStream,
    status: u16,
    text: &str,
    head_only: bool,
) -> std::io::Result<u64> {
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>{status} {}</title>\
         <body style=\"font-family:Segoe UI,sans-serif;margin:3em\"><h2>{status} {}</h2>\
         <p>{}</p></body>",
        status_text(status),
        status_text(status),
        crate::util::html_escape(text)
    );
    let extra = if status == 405 {
        "Allow: GET, HEAD\r\n"
    } else {
        ""
    };
    write_head(
        stream,
        status,
        "text/html; charset=utf-8",
        body.len() as u64,
        extra,
    )?;
    if head_only {
        return Ok(0);
    }
    stream.write_all(body.as_bytes())?;
    Ok(body.len() as u64)
}

/// The page that lists a folder: folders first, then files, by name.
pub fn listing_html(url_path: &str, dir: &Path) -> String {
    let mut items: Vec<(bool, String, u64)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let meta = e.metadata().ok()?;
            Some((
                meta.is_dir(),
                e.file_name().to_string_lossy().into_owned(),
                meta.len(),
            ))
        })
        .collect();
    items.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.to_lowercase().cmp(&b.1.to_lowercase()))
    });
    let esc = crate::util::html_escape;
    let mut rows = String::new();
    if url_path != "/" {
        rows.push_str("<tr><td><a href=\"../\">../</a></td><td></td></tr>\n");
    }
    for (is_dir, name, size) in &items {
        let slash = if *is_dir { "/" } else { "" };
        let size = if *is_dir {
            String::new()
        } else {
            format!("{size} bytes")
        };
        rows.push_str(&format!(
            "<tr><td><a href=\"{}{slash}\">{}{slash}</a></td><td>{size}</td></tr>\n",
            percent_encode(name),
            esc(name)
        ));
    }
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{0}</title><style>\
         body{{font-family:Segoe UI,sans-serif;margin:2.5em;color:#222}}\
         table{{border-collapse:collapse}}td{{padding:.25em 1.5em .25em 0}}\
         td+td{{color:#777;text-align:right}}a{{color:#0b6e4f;text-decoration:none}}\
         a:hover{{text-decoration:underline}}</style></head><body>\
         <h2>{0}</h2><table>\n{1}</table>\
         <p style=\"color:#999;font-size:.85em\">Served by SocketForge</p></body></html>",
        esc(url_path),
        rows
    )
}

fn handle(mut stream: TcpStream, peer: SocketAddr, root: &Path, shared: &Shared) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let Some(head) = read_head(&mut stream) else {
        return;
    };
    let (method, target, status, bytes) = match parse_request_line(&head) {
        None => {
            let sent = write_simple(&mut stream, 400, "That is not an HTTP request.", false);
            ("?".to_string(), String::new(), 400, sent.unwrap_or(0))
        }
        Some((method, target)) => {
            let (status, bytes) = respond(&mut stream, root, &method, &target);
            (method, target, status, bytes)
        }
    };
    // Noted before the connection closes, so that whoever waited for the
    // answer already finds it in the list.
    if let Ok(mut log) = shared.log.lock() {
        shared.served.fetch_add(1, Ordering::Relaxed);
        if log.len() >= LOG_LIMIT {
            log.pop_front();
        }
        log.push_back(RequestLog {
            time: now_unix(),
            method,
            path: target.chars().take(300).collect(),
            status,
            bytes,
            remote: !peer.ip().is_loopback(),
        });
    }
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Write);
    if let Some(wake) = &shared.wake {
        wake();
    }
}

/// Answers one request. Returns the status and the content bytes sent.
fn respond(stream: &mut TcpStream, root: &Path, method: &str, target: &str) -> (u16, u64) {
    let head_only = method == "HEAD";
    let fail = |stream: &mut TcpStream, status: u16, text: &str| {
        let sent = write_simple(stream, status, text, head_only).unwrap_or(0);
        (status, sent)
    };
    if method != "GET" && method != "HEAD" {
        return fail(
            stream,
            405,
            "This server only hands out files (GET and HEAD).",
        );
    }
    let wanted = match resolve(root, target) {
        Ok(p) => p,
        Err(400) => return fail(stream, 400, "The address could not be read."),
        Err(403) => return fail(stream, 403, "That path is outside the served folder."),
        Err(status) => return fail(stream, status, "There is no such file here."),
    };
    // Links and junctions must not lead out of the folder either.
    let real = match wanted.canonicalize() {
        Ok(p) if p.starts_with(root) => p,
        Ok(_) => return fail(stream, 403, "That path is outside the served folder."),
        Err(_) => return fail(stream, 404, "There is no such file here."),
    };
    let url_path = target.split(['?', '#']).next().unwrap_or("/");
    if real.is_dir() {
        if !url_path.ends_with('/') {
            let extra = format!("Location: {url_path}/\r\n");
            let _ = write_head(stream, 301, "text/html; charset=utf-8", 0, &extra);
            return (301, 0);
        }
        let index = real.join("index.html");
        if index.is_file() {
            return send_file(stream, &index, head_only);
        }
        let shown = percent_decode(url_path).unwrap_or_else(|| url_path.to_string());
        let body = listing_html(&shown, &real);
        if write_head(
            stream,
            200,
            "text/html; charset=utf-8",
            body.len() as u64,
            "",
        )
        .is_err()
            || head_only
        {
            return (200, 0);
        }
        let _ = stream.write_all(body.as_bytes());
        return (200, body.len() as u64);
    }
    send_file(stream, &real, head_only)
}

fn send_file(stream: &mut TcpStream, path: &Path, head_only: bool) -> (u16, u64) {
    let (mut file, length) = match std::fs::File::open(path).and_then(|f| {
        let len = f.metadata()?.len();
        Ok((f, len))
    }) {
        Ok(x) => x,
        Err(_) => {
            let sent = write_simple(stream, 404, "The file could not be opened.", head_only);
            return (404, sent.unwrap_or(0));
        }
    };
    if write_head(stream, 200, content_type(path), length, "").is_err() || head_only {
        return (200, 0);
    }
    let sent = std::io::copy(&mut file, stream).unwrap_or(0);
    (200, sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_site(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("socketforge-serve-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("site").join("sub dir")).unwrap();
        std::fs::create_dir_all(dir.join("site").join("with-index")).unwrap();
        std::fs::write(dir.join("site").join("hello.txt"), "hello").unwrap();
        std::fs::write(dir.join("site").join("page.html"), "<p>page</p>").unwrap();
        std::fs::write(dir.join("site").join("sub dir").join("a&b.json"), "{}").unwrap();
        std::fs::write(
            dir.join("site").join("with-index").join("index.html"),
            "<h1>index</h1>",
        )
        .unwrap();
        // A file next to the served folder: must never be reachable.
        std::fs::write(dir.join("secret.txt"), "secret").unwrap();
        dir
    }

    /// Sends one raw request and returns (status, headers, body).
    fn fetch(port: u16, request: &str) -> (u16, String, Vec<u8>) {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(request.as_bytes()).unwrap();
        let mut all = Vec::new();
        let _ = s.read_to_end(&mut all);
        let split = all
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("a response head");
        let head = String::from_utf8_lossy(&all[..split]).into_owned();
        let status = head
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, head, all[split + 4..].to_vec())
    }

    fn get(port: u16, path: &str) -> (u16, String, Vec<u8>) {
        fetch(
            port,
            &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        )
    }

    #[test]
    fn serves_files_listings_and_indexes_from_a_real_listener() {
        let dir = temp_site("basic");
        let mut server = FolderServer::start(&dir.join("site"), 0, false, None).unwrap();
        let port = server.port();
        assert_ne!(port, 0);
        assert!(!server.lan());
        assert_eq!(server.url(), format!("http://localhost:{port}/"));

        let (status, head, body) = get(port, "/hello.txt");
        assert_eq!(status, 200);
        assert!(head.contains("Content-Type: text/plain; charset=utf-8"));
        assert!(head.contains("Content-Length: 5"));
        assert!(head.contains("X-Content-Type-Options: nosniff"));
        assert_eq!(body, b"hello");

        // A query string does not change which file is meant.
        assert_eq!(get(port, "/page.html?v=2").2, b"<p>page</p>");

        // The folder listing links to its entries, escaped.
        let (status, _, body) = get(port, "/");
        let page = String::from_utf8(body).unwrap();
        assert_eq!(status, 200);
        assert!(page.contains("href=\"hello.txt\""));
        assert!(page.contains("href=\"sub%20dir/\""));
        assert!(!page.contains("secret"));
        let (_, _, body) = get(port, "/sub%20dir/");
        let page = String::from_utf8(body).unwrap();
        assert!(page.contains("href=\"a%26b.json\"") && page.contains("a&amp;b.json"));
        assert!(page.contains("href=\"../\""));
        assert_eq!(get(port, "/sub%20dir/a%26b.json").2, b"{}");

        // A folder without the trailing slash redirects; one with index.html shows it.
        let (status, head, _) = get(port, "/with-index");
        assert_eq!(status, 301);
        assert!(head.contains("Location: /with-index/"));
        assert_eq!(get(port, "/with-index/").2, b"<h1>index</h1>");

        // HEAD sends the head only.
        let (status, head, body) = fetch(port, "HEAD /hello.txt HTTP/1.1\r\n\r\n");
        assert_eq!((status, body.len()), (200, 0));
        assert!(head.contains("Content-Length: 5"));

        assert_eq!(get(port, "/missing.txt").0, 404);
        let (status, head, _) = fetch(port, "POST /hello.txt HTTP/1.1\r\n\r\n");
        assert_eq!(status, 405);
        assert!(head.contains("Allow: GET, HEAD"));
        assert_eq!(fetch(port, "nonsense\r\n\r\n").0, 400);

        let log = server.requests();
        assert_eq!(server.served(), log.len() as u64);
        assert_eq!(log[0].status, 400, "newest first");
        assert!(log.iter().any(|r| r.path == "/hello.txt" && r.bytes == 5));
        assert!(log.iter().all(|r| !r.remote));

        // Stopping frees the port at once.
        server.stop();
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
        let again = TcpListener::bind(("127.0.0.1", port));
        assert!(again.is_ok(), "the port is free again");
        drop(again);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn nothing_outside_the_folder_can_be_reached() {
        let dir = temp_site("escape");
        let server = FolderServer::start(&dir.join("site"), 0, false, None).unwrap();
        let port = server.port();
        for path in [
            "/../secret.txt",
            "/%2e%2e/secret.txt",
            "/..%2fsecret.txt",
            "/..%5csecret.txt",
            "/sub%20dir/../../secret.txt",
            "/hello.txt::$DATA",
            "/hello.txt.",
            "/hello.txt%20",
            "/C:/Windows/win.ini",
            "/%00",
            "/nul",
            "/%zz",
        ] {
            let (status, _, body) = get(port, path);
            assert!(matches!(status, 400 | 403 | 404), "{path} gave {status}");
            assert!(
                !String::from_utf8_lossy(&body).contains("secret\n")
                    && body != b"secret"
                    && body != b"hello",
                "{path} leaked a file"
            );
        }
        drop(server);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn paths_are_resolved_strictly() {
        let root = Path::new("C:\\site");
        assert_eq!(resolve(root, "/"), Ok(root.to_path_buf()));
        assert_eq!(
            resolve(root, "/a/./b.txt?x=1#top"),
            Ok(root.join("a").join("b.txt"))
        );
        assert_eq!(resolve(root, "/a%20b"), Ok(root.join("a b")));
        assert_eq!(resolve(root, "//a///b"), Ok(root.join("a").join("b")));
        assert_eq!(
            resolve(root, "/.well-known/x"),
            Ok(root.join(".well-known").join("x"))
        );
        assert_eq!(resolve(root, "/.."), Err(403));
        assert_eq!(resolve(root, "/a/%2E%2E/b"), Err(403));
        assert_eq!(resolve(root, "/a\\b"), Err(403));
        assert_eq!(resolve(root, "/a:b"), Err(403));
        assert_eq!(resolve(root, "/con.txt"), Err(404));
        assert_eq!(resolve(root, "/COM1"), Err(404));
        assert_eq!(resolve(root, "/comic"), Ok(root.join("comic")));
        assert_eq!(resolve(root, "no-slash"), Err(400));
        assert_eq!(resolve(root, "/%"), Err(400));
        assert_eq!(resolve(root, "/%ff"), Err(400));
    }

    #[test]
    fn request_lines_types_and_escapes() {
        assert_eq!(
            parse_request_line("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"),
            Some(("GET".into(), "/a".into()))
        );
        assert_eq!(parse_request_line("GET /a"), None);
        assert_eq!(parse_request_line("GET /a b HTTP/1.1"), None);
        assert_eq!(parse_request_line("GET /a SPDY/3"), None);
        assert_eq!(
            content_type(Path::new("a.HTML")),
            "text/html; charset=utf-8"
        );
        assert_eq!(content_type(Path::new("a.wasm")), "application/wasm");
        assert_eq!(content_type(Path::new("a.bin")), "application/octet-stream");
        assert_eq!(content_type(Path::new("noext")), "application/octet-stream");
        assert_eq!(percent_encode("a b&c/é.txt"), "a%20b%26c%2F%C3%A9.txt");
        assert_eq!(
            percent_decode("a%20b%26c%2F%C3%A9.txt").as_deref(),
            Some("a b&c/é.txt")
        );
        assert_eq!(percent_decode("%4"), None);
    }

    #[test]
    fn start_errors_are_in_plain_words() {
        let dir = temp_site("errors");
        let missing = FolderServer::start(&dir.join("nope"), 0, false, None);
        assert!(missing.err().unwrap().contains("does not exist"));
        let file = FolderServer::start(&dir.join("secret.txt"), 0, false, None);
        assert!(file.err().unwrap().contains("not a folder"));
        // A whole drive is never handed to the network (no port is opened for the check).
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()) + "\\";
        let whole = FolderServer::start(Path::new(&drive), 0, true, None);
        assert!(whole.err().unwrap().contains("whole drive"));
        // A port that is taken (by our own listener).
        let holder = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = holder.local_addr().unwrap().port();
        let taken = FolderServer::start(&dir.join("site"), port, false, None);
        assert!(taken.err().unwrap().contains("already in use"));
        drop(holder);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
