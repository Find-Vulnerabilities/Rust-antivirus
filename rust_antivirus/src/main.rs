mod engine;
mod memory_scanner;
mod behavior_monitor;
mod process_monitor;
mod utils;
mod gui;
mod ipc;
mod config;
mod subprocess_manager;
mod yara_sys;
mod yara_engine;
mod yara_integration;
mod yara_integration_helpers;
mod quarantine_manager;  // 隔离管理器
mod kernel_driver;  // 🔐 NEW: Kernel-mode protection driver
mod driver_bridge_enhanced; // minifilter connect

use eframe::{egui, NativeOptions};
use std::sync::Arc;
use crate::subprocess_manager::SubprocessManager;
use crate::kernel_driver::KernelDriverService;  // NEW

use crate::engine::AntivirusEngine;
use crate::gui::AntivirusApp;
use crate::behavior_monitor::BehaviorMonitor;  // NEW
use crate::memory_scanner::MemoryScanner;  // NEW

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    log::info!("🚀 Starting Wenle Antivirus - Commercial Edition with Rust Kernel Protection...");

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

    let behavior_monitor = Arc::new(BehaviorMonitor::new());
    if let Err(e) = behavior_monitor.init_default_rules() {
        log::error!("Failed to initialize default rules: {}", e);
    }
    log::info!("✓ Behavior Monitor initialized");

    let memory_scanner = Arc::new(MemoryScanner::new());
    log::info!("✓ Memory Scanner initialized");

    // ============================================================
    // 🔐 INITIALIZE KERNEL-MODE PROTECTION DRIVER (Rust Implementation)
    // ============================================================
    let kernel_driver = match KernelDriverService::new(
        engine.clone(),
        behavior_monitor.clone(),
        memory_scanner.clone()
    ) {
        Ok(driver) => {
            log::info!("✓ Kernel Driver Service initialized");
            driver
        }
        Err(e) => {
            log::warn!("⚠️ Kernel Driver initialization failed (non-fatal): {}", e);
            // Continue without kernel driver - user-mode fallback
            return Err(format!("Driver error: {}", e).into());
        }
    };

    // Start real-time protection
    if let Err(e) = kernel_driver.start() {
        log::error!("❌ Failed to start kernel protection: {}", e);
        return Err(format!("Driver startup failed: {}", e).into());
    }

    log::info!("🎯 Real-time kernel protection is ACTIVE");
    log::info!("   ✓ File monitoring enabled (executable files)");
    log::info!("   ✓ Process monitoring enabled (new process control)");
    log::info!("   ✓ DLL injection protection enabled");

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
        "Wenle Antivirus - Rust Edition (Commercial Protection)",
        options,
        Box::new(|_cc| Ok(Box::new(app))),
    ) {
        Ok(()) => {
            kernel_driver.stop();
            log::info!("Application exiting normally");
            Ok(())
        }
        Err(e) => {
            kernel_driver.stop();
            log::error!("Application error: {}", e);
            Err(Box::new(e))
        }
    }
}
