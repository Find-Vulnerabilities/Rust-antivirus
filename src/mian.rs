mod engine;
mod memory_scanner;
mod process_monitor;
mod utils;
mod gui;

use eframe::{egui, NativeOptions};
use std::sync::Arc;

use crate::engine::AntivirusEngine;
use crate::gui::AntivirusApp;

fn main() -> Result<(), eframe::Error> {
    // 初始化日志
    env_logger::init();
    
    log::info!("Starting Rust Antivirus with full functionality...");

    // 创建默认配置文件
    if let Err(e) = config::create_default_configs() {
        log::error!("Failed to create config files: {}", e);
    }

    // 创建防毒引擎
    let engine = match AntivirusEngine::new() {
        Ok(engine) => Arc::new(engine),
        Err(e) => {
            log::error!("Failed to create antivirus engine: {}", e);
            return Err(eframe::Error::Other(format!("Engine creation failed: {}", e)));
        }
    };

    let app = AntivirusApp::new(engine);

    let options = NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "SafetyWen Antivirus - Rust Edition",
        options,
        Box::new(|_cc| Box::new(app)),
    )
}