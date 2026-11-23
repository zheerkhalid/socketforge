# Changelog

All notable changes to SocketForge are listed here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the versions follow [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-11-24

### Added

- **Tools page** with two helpers that run inside SocketForge, need no administrator rights and change nothing in Windows:
  - **Serve a folder over HTTP.** Pick a folder and a port, press Start, and open `http://localhost:port/`. Folders without an `index.html` get a file listing. A list shows the latest requests. By default only this PC can connect; one checkbox lets other devices on your network connect too (a whole drive cannot be shared this way).
  - **Forward a local port.** Listen on a port of this PC and pass every connection on to another address, for example `localhost:15432` to a database on another machine. Shows open connections, totals and the last error. Several forwards can run at once.
- **Block-list import.** "Import a hosts file or block list" now understands hosts-style lists (`0.0.0.0 ads.example`), plain lists of names and `||ads.example^` filter rules. Names that are repeated in the list are added once, names your hosts file already has are left as they are, and you choose whether they point at `0.0.0.0` or `127.0.0.1`.
- **Remove duplicates** in the hosts editor's More menu: removes names that repeat an earlier line with the same address.
- **DNS cache tab** in the hosts editor: the names Windows currently remembers, with their record type, a search, a Flush button, and a button to add a name to the hosts file.
- **Notes and favourites for ports.** In the details panel, star a port and type a note such as "storefront dev server". The note shows in the table in place of the usual use of the port, the search finds it, and a Favourites filter shows only starred ports.
- **Right-click menu on hosts entries:** copy the names, the address or the line, switch on or off, edit, delete.
- A dot next to "Hosts file" in the side bar while there are unsaved changes.

### Changed

- **Large hosts files are fast now.** Files with more than 2,000 lines open in a quick, read-only raw view with line numbers that the search box filters; "Edit as text anyway" is one click away. The profiles tab and the import dialog no longer go through the whole file many times a second.
- Importing a long list takes a moment; it used to get slower with every line.
- The backups tab opens quickly even when the backups are large.
- The size limit for a hosts file is 32 MB everywhere (importing allowed 32 MB, but saving stopped at 16 MB).
- Large numbers of entries are written with thousands separators.
- `scripts\package.ps1` builds into `CARGO_TARGET_DIR` when it is set.

### Fixed

- **Closing the window no longer drops unsaved hosts changes without a word.** SocketForge asks whether to save, close without saving, or stay. This also covers Exit from the notification area, and "Restart as administrator" asks you to save or revert first.
- A hosts file that is too large is refused before the backup is made and before the administrator prompt, with a clear message, instead of failing after you approved the prompt.
- If the administrator step takes longer than a minute, SocketForge says so instead of showing "code 259".
- Pressing Esc in a hosts dialog no longer also clears the search box.

## [1.0.0] - 2026-11-16

First release.

### Added

- Listening TCP and UDP ports (IPv4 and IPv6) with the program, service, path and command line behind each, and whether the port is reachable from the network.
- Active connections with live highlighting, a watch list and a history of ports opening and closing, with alerts.
- Port check ("who is using port N?", and why a bind can fail) and a free-port finder.
- Hosts file editor: on/off switches, groups, duplicate and syntax checks, raw text, automatic backups with restore, and profiles.
- Read-only views of firewall rules, port proxies, URL reservations, reserved ranges, and Docker and WSL forwards.
- End a process or stop a service, export to CSV, JSON and HTML, a command line, dark and light themes.

[1.1.0]: https://github.com/zheerkhalid/socketforge/releases/tag/v1.1.0
[1.0.0]: https://github.com/zheerkhalid/socketforge/releases/tag/v1.0.0
