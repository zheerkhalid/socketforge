#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use socketforge::cli::{self, Command};
use socketforge::ui::{self, Options};

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match cli::parse(&args) {
        Ok(c) => c,
        Err(e) => {
            cli::attach_console();
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    match command {
        Command::Gui {
            demo,
            screenshot,
            view,
            light,
            port,
        } => ui::run(
            Options {
                demo,
                screenshot,
                view,
                light,
                port,
            },
            window_icon(),
        ),
        other => {
            cli::attach_console();
            std::process::exit(cli::run(&other));
        }
    }
}

fn window_icon() -> egui::IconData {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/icon-256.png"));
    match image::load_from_memory(bytes) {
        Ok(img) => {
            let rgba = img.into_rgba8();
            let (width, height) = rgba.dimensions();
            egui::IconData {
                rgba: rgba.into_raw(),
                width,
                height,
            }
        }
        Err(_) => egui::IconData::default(),
    }
}
