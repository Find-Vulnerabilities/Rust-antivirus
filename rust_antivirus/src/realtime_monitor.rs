// Add module declarations so this bin can compile standalone and reuse the library source files.
mod engine;
mod memory_scanner;
mod process_monitor;
mod utils; // <- added so `crate::utils` in engine.rs resolves

use std::collections::{HashSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::Duration;

// Use local module paths (not crate::) so the binary includes these modules directly.
use engine::AntivirusEngine;
use memory_scanner::MemoryScanner;
use process_monitor::ProcessMonitor;
use ctrlc; // <- added to allow Ctrl+C handling

pub struct RealtimeMonitor {
    engine: Arc<AntivirusEngine>,
    memory_scanner: MemoryScanner,
    process_monitor: ProcessMonitor,
    known_pids: HashSet<u32>,
    known_files: HashMap<PathBuf, String>,
    stop_signal: Arc<AtomicBool>,
}

impl RealtimeMonitor {
    pub fn new(engine: Arc<AntivirusEngine>) -> Self {
        let mut memory_scanner = MemoryScanner::new();
        memory_scanner.refresh();

        let process_monitor = ProcessMonitor::new(engine.clone());

        // 初始化已知进程
        let known_pids: HashSet<u32> = memory_scanner.get_system()
            .processes()
            .keys()
            .map(|pid| pid.as_u32())
            .collect();

        // 初始化已知文件
        let mut known_files = HashMap::new();
        let root_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        if let Ok(entries) = std::fs::read_dir(&root_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(hash) = engine.calculate_sha256(&path) {
                        known_files.insert(path, hash);
                    }
                }
            }
        }

        Self {
            engine,
            memory_scanner,
            process_monitor,
            known_pids,
            known_files,
            stop_signal: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&mut self) {
        let stop_signal = self.stop_signal.clone();
        let engine = self.engine.clone();
        let mut memory_scanner = MemoryScanner::new(); // 创建新的实例
        let mut known_pids = self.known_pids.clone();
        let mut known_files = self.known_files.clone();

        thread::spawn(move || {
            println!("🎯 开始实时监控...");

            while !stop_signal.load(Ordering::Relaxed) {
                // 1. 检查新进程
                memory_scanner.refresh();
                let current_pids: HashSet<u32> = memory_scanner.get_system()
                    .processes()
                    .keys()
                    .map(|pid| pid.as_u32())
                    .collect();

                for &pid in current_pids.difference(&known_pids) {
                    println!("🔄 新进程检测: PID {}", pid);
                    if let Some(process) = memory_scanner.get_system().process(sysinfo::Pid::from_u32(pid)) {
                        if let Some(exe_path) = process.exe() {
                            let scan_result = engine.scan_file(exe_path);
                            if scan_result.threat_detected {
                                // process.name() may be an OsStr; use to_string_lossy() for safe formatting
                                println!("🚨 恶意进程检测: {} (PID: {})", process.name().to_string_lossy(), pid);
                                engine.terminate_process(sysinfo::Pid::from_u32(pid));
                            }
                        }
                    }
                }
                known_pids = current_pids;

                // 2. 检查文件新增/修改
                let root_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                if let Ok(entries) = std::fs::read_dir(&root_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            match engine.calculate_sha256(&path) {
                                Ok(hash) => {
                                    if !known_files.contains_key(&path) {
                                        println!("📁 新文件检测: {:?}", path);
                                        let scan_result = engine.scan_file(&path);
                                        if scan_result.threat_detected {
                                            println!("🚨 恶意文件检测: {:?}", path);
                                            engine.handle_threat(&path, &scan_result.result);
                                        }
                                        known_files.insert(path.clone(), hash);
                                    } else if let Some(old_hash) = known_files.get(&path) {
                                        if &hash != old_hash {
                                            println!("✏️  文件修改: {:?}", path);
                                            let scan_result = engine.scan_file(&path);
                                            if scan_result.threat_detected {
                                                println!("🚨 恶意文件修改检测: {:?}", path);
                                                engine.handle_threat(&path, &scan_result.result);
                                            }
                                            known_files.insert(path.clone(), hash);
                                        }
                                    }
                                }
                                Err(_) => {}
                            }
                        }
                    }
                }

                thread::sleep(Duration::from_secs(5));
            }
            
            println!("🛑 监控已停止");
        });
    }

    pub fn stop(&self) {
        self.stop_signal.store(true, Ordering::Relaxed);
    }
}

// NEW: expose the stop signal so external handlers can stop the monitor.
impl RealtimeMonitor {
    pub fn get_stop_signal(&self) -> Arc<AtomicBool> {
        self.stop_signal.clone()
    }
}

// Provide a real binary entrypoint so `cargo build --bin realtime_monitor` succeeds.
// Replaced the previous short sleep main with a Ctrl+C-driven long-running main.
fn main() {
    env_logger::init();

    let engine = Arc::new(AntivirusEngine::default());
    let mut monitor = RealtimeMonitor::new(engine);

    // Clone the stop signal for the Ctrl+C handler
    let stop_signal = monitor.get_stop_signal();

    // Install Ctrl+C handler to set the stop flag
    ctrlc::set_handler(move || {
        println!("Received Ctrl+C, stopping realtime monitor...");
        stop_signal.store(true, Ordering::Relaxed);
    }).expect("Error setting Ctrl-C handler");

    monitor.start();

    println!("Realtime monitor running. Press Ctrl+C to stop.");

    // Block here until stop signal is set by Ctrl+C
    while !monitor.get_stop_signal().load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(1));
    }

    // ensure monitor stop routine runs (redundant but explicit)
    monitor.stop();
    println!("Realtime monitor stopped.");
}

// 單獨編譯測試入口點
#[cfg(test)]
fn main() {
    use crate::engine::AntivirusEngine;
    use std::sync::Arc;

    let engine = Arc::new(AntivirusEngine::default());
    let mut monitor = RealtimeMonitor::new(engine);
    monitor.start();

    // 讓監控執行一段時間
    std::thread::sleep(std::time::Duration::from_secs(10));
    monitor.stop();
}