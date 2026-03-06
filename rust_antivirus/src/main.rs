mod engine;
mod memory_scanner;
mod process_monitor;
mod utils;
mod gui;
mod ipc;
mod config;
mod subprocess_manager;

use eframe::{egui, NativeOptions};
use std::sync::Arc;
use crate::subprocess_manager::SubprocessManager;

use crate::engine::AntivirusEngine;
use crate::gui::AntivirusApp;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    log::info!("Starting Rust Antivirus with full functionality...");

    // 设置 Ctrl+C 处理程序以优雅关闭
    let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_clone = shutdown_flag.clone();
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        shutdown_clone.store(true, std::sync::atomic::Ordering::Relaxed);
    }).map_err(|e| format!("Failed to set Ctrl-C handler: {}", e))?;

    let engine = match AntivirusEngine::new() {
        Ok(engine) => Arc::new(engine),
        Err(e) => {
            log::error!("Failed to create antivirus engine: {:?}", e);
            return Err(format!("Engine creation failed: {:?}", e).into());
        }
    };

    // 启动监控子进程
    let mut subprocess_manager = SubprocessManager::new();
    if let Err(e) = subprocess_manager.start_all_monitors() {
        log::error!("Failed to start some monitors: {}", e);
        // 仅警告，不中断主程序启动
    }

    let app = AntivirusApp::new(engine, subprocess_manager);

    let options = NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    match eframe::run_native(
        "Wenle Antivirus - Rust Edition",
        options,
        Box::new(|_cc| Ok(Box::new(app))),
    ) {
        Ok(()) => {
            log::info!("Application exiting normally");
            Ok(())
        }
        Err(e) => {
            log::error!("Application error: {}", e);
            Err(Box::new(e))
        }
    }
}
