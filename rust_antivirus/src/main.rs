mod engine;
mod memory_scanner;
mod process_monitor;
mod utils;
mod gui;

use eframe::{egui, NativeOptions};
use std::sync::Arc;

use crate::engine::AntivirusEngine;
use crate::gui::AntivirusApp;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    log::info!("Starting Rust Antivirus with full functionality...");

    let engine = match AntivirusEngine::new() {
        Ok(engine) => Arc::new(engine),
        Err(e) => {
            log::error!("Failed to create antivirus engine: {:?}", e);
            return Err(format!("Engine creation failed: {:?}", e).into());
        }
    };

    let app = AntivirusApp::new(engine);

    let options = NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    match eframe::run_native(
        "SafetyWen Antivirus - Rust Edition",
        options,
        Box::new(|_cc| Ok(Box::new(app))),
    ) {
        Ok(()) => Ok(()),
        Err(e) => Err(Box::new(e)),
    }
}