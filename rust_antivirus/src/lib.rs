// Library crate exposing modules used by binaries
// Direct native library linkage to ensure YARA and OpenSSL libraries are linked for all targets
#[link(name = "libyara", kind = "static")]
#[link(name = "libcrypto")]  // Dynamic linking to OpenSSL crypto library
#[link(name = "libssl")]     // Dynamic linking to OpenSSL SSL library
extern "C" {
    // Dummy declaration to force library linking
    // The actual YARA functions are defined in yara_sys.rs
}

pub mod yara_sys;
pub mod yara_engine;
pub mod yara_integration;
pub mod yara_integration_helpers;
pub mod memory_scanner;
pub mod process_monitor;
pub mod subprocess_manager;
pub mod utils;
pub mod engine;
pub mod gui;
pub mod quarantine_manager;
pub mod memory_scanning;
pub mod driver_bridge_enhanced;
pub mod kernel_driver;  // 🔐 NEW: Kernel-mode protection driver (Rust implementation)
pub mod ipc;
pub mod scan_optimization;
pub mod sandbox;          // 新增：輕量級沙箱引擎
pub mod behavior_monitor;  // 新增：實時行為監控和攔截
pub mod service;          // P1：Windows Service 包裝
