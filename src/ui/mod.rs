//! The egui user interface.
mod app;
mod conn_view;
mod details;
mod history_view;
mod hosts_view;
mod listen_view;
mod lookup_view;
mod rules_view;
mod settings_view;
mod shared;
mod theme;
mod tools_view;
mod widgets;
mod worker;

pub use app::{run, Options};
