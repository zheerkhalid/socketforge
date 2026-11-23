//! SocketForge: a local ports and listening-services viewer with a hosts-file
//! editor for Windows.
//!
//! The logic lives in this library so that it can be unit-tested; `main.rs`
//! only parses the command line and opens the window.
#![allow(clippy::type_complexity)]

pub mod actions;
pub mod cli;
pub mod collect;
pub mod demo;
pub mod diff;
pub mod export;
pub mod exposure;
pub mod freeport;
pub mod hosts;
pub mod hosts_store;
pub mod icons;
pub mod model;
pub mod ports;
pub mod relay;
pub mod selftest;
pub mod serve;
pub mod settings;
pub mod tray;
pub mod ui;
pub mod util;
pub mod view;
