// Add module declarations so this bin can compile standalone and reuse the library source files.
mod engine;
mod memory_scanner;
mod process_monitor;
mod utils;

use std::collections::{HashSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::Duration;

// Use local module paths (not crate::) so the binary includes these modules directly.
use engine::AntivirusEngine;
use memory_scanner::{MemoryScanner, MemoryRegion};
use process_monitor::ProcessMonitor;
use ctrlc; // <- added to allow Ctrl+C handling

// YARA is optional: provide conditional imports and a type alias so the struct's field compiles
#[cfg(feature = "with-yara")]
use yara::{Compiler, Rules};

#[cfg(feature = "with-yara")]
type YaraRules = Rules;
#[cfg(not(feature = "with-yara"))]
type YaraRules = (); // dummy type when YARA disabled

pub struct RealtimeMonitor {
    engine: Arc<AntivirusEngine>,
    memory_scanner: MemoryScanner,
    process_monitor: ProcessMonitor,
    known_pids: HashSet<u32>,
    known_files: HashMap<PathBuf, String>,
    stop_signal: Arc<AtomicBool>,
    yara_rules: Option<Arc<YaraRules>>, // compiled YARA rules (shared) or None when disabled
}

impl RealtimeMonitor {
    pub fn new(engine: Arc<AntivirusEngine>) -> Self {
        // ...existing initialization...
        let mut memory_scanner = MemoryScanner::new();
        memory_scanner.refresh();

        let process_monitor = ProcessMonitor::new(engine.clone());

        // 初始化已知進程
        let known_pids: HashSet<u32> = memory_scanner.get_system()
            .processes()
            .keys()
            .map(|pid| pid.as_u32())
            .collect();

        // 初始化已知文件 (same as before)
        let mut known_files: HashMap<PathBuf, String> = HashMap::new();
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

        // Try to compile/load YARA rules (only for .yar source files when feature enabled)
        #[cfg(feature = "with-yara")]
        let yara_rules: Option<Arc<YaraRules>> = {
            let rules_path = utils::get_yara_rules_path();
            if !rules_path.exists() {
                log::warn!("YARA rules not found at {:?}", rules_path);
                None
            } else if rules_path.extension().and_then(|s| s.to_str()).map(|e| e.eq_ignore_ascii_case("yarac")).unwrap_or(false) {
                // Compiled rules present; skip in-process compilation (cannot compile .yarac with Compiler).
                log::info!("Compiled YARA rules detected ({}). Skipping in-process compilation; realtime monitor will not load compiled rules into the yara crate.", rules_path.display());
                None
            } else {
                // rules_path is expected to be a .yar source file — attempt to compile it into Rules.
                match rules_path.to_str() {
                    Some(rules_str) => {
                        match Compiler::new() {
                            Ok(mut compiler) => {
                                match compiler.add_rules_file(rules_str) {
                                    Ok(_) => match compiler.compile() {
                                        Ok(r) => {
                                            log::info!("Loaded YARA rules from {}", rules_str);
                                            Some(Arc::new(r))
                                        }
                                        Err(e) => {
                                            log::warn!("Failed to compile YARA rules {}: {:?}", rules_str, e);
                                            None
                                        }
                                    },
                                    Err(e) => {
                                        log::warn!("Failed to add YARA rules file {}: {:?}", rules_str, e);
                                        None
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!("Failed to create YARA compiler: {:?}", e);
                                None
                            }
                        }
                    }
                    None => {
                        log::warn!("YARA rules path not valid UTF-8: {:?}", rules_path);
                        None
                    }
                }
            }
        };

        // When YARA is not enabled, set yara_rules to None
        #[cfg(not(feature = "with-yara"))]
        let yara_rules: Option<Arc<YaraRules>> = None;

        Self {
            engine,
            memory_scanner,
            process_monitor,
            known_pids,
            known_files,
            stop_signal: Arc::new(AtomicBool::new(false)),
            yara_rules,
        }
    }

    // helper: scan a file with compiled yara rules (if present)
    fn yara_scan_file_if_loaded(&self, file_path: &PathBuf) -> Option<Vec<String>> {
        #[cfg(feature = "with-yara")]
        {
            if let Some(rules) = &self.yara_rules {
                if let Ok(data) = std::fs::read(file_path) {
                    match rules.scan_mem(&data, 10) {
                        Ok(matches) => {
                            if !matches.is_empty() {
                                let names = matches.into_iter().map(|m| m.identifier).collect();
                                return Some(names);
                            }
                        }
                        Err(e) => {
                            log::warn!("YARA memory scan error for file {:?}: {:?}", file_path, e);
                        }
                    }
                }
            }
            None
        }
        #[cfg(not(feature = "with-yara"))]
        {
            // YARA not enabled in this build
            None
        }
    }

    // helper: scan memory regions of a pid with yara rules (returns true if any match)
    fn yara_scan_process_memory_if_loaded(&self, pid: sysinfo::Pid) -> Option<Vec<(usize, Vec<String>)>> {
        #[cfg(feature = "with-yara")]
        {
            if self.yara_rules.is_none() {
                return None;
            }
            let rules = self.yara_rules.as_ref().unwrap();

            // get memory map (best-effort)
            match self.memory_scanner.get_process_memory_map(pid) {
                Ok(regions) => {
                    let mut hits = Vec::new();
                    for region in regions {
                        // skip empty/large/special regions
                        if region.size == 0 || region.size > 1024 * 1024 {
                            continue;
                        }
                        if let Ok(bytes) = self.memory_scanner.read_memory_region(pid, region.base_address, region.size) {
                            match rules.scan_mem(&bytes, 10) {
                                Ok(matches) => {
                                    if !matches.is_empty() {
                                        let names = matches.into_iter().map(|m| m.identifier).collect();
                                        hits.push((region.base_address, names));
                                    }
                                }
                                Err(e) => {
                                    log::warn!("YARA scan_mem failed for PID {} region {:x}: {:?}", pid, region.base_address, e);
                                }
                            }
                        }
                    }
                    if hits.is_empty() {
                        None
                    } else {
                        Some(hits)
                    }
                }
                Err(e) => {
                    log::warn!("Failed to get memory map for PID {}: {:?}", pid, e);
                    None
                }
            }
        }
        #[cfg(not(feature = "with-yara"))]
        {
            None
        }
    }

    pub fn start(&mut self) {
        let stop_signal = self.stop_signal.clone();
        let engine = self.engine.clone();
        let mut memory_scanner = MemoryScanner::new(); // 创建新的实例
        let mut known_pids = self.known_pids.clone();
        let mut known_files = self.known_files.clone();
        let yara_rules_clone = self.yara_rules.clone();

        thread::spawn(move || {
            println!("🎯 开始实时监控...");

            // initial memory scan using memory_scanner + YARA (if loaded)
            memory_scanner.refresh();

            #[cfg(feature = "with-yara")]
            {
                if let Some(rules) = yara_rules_clone.as_ref() {
                    // run a quick memory scan on all processes
                    for (pid, process) in memory_scanner.get_system().processes() {
                        if memory_scanner.is_system_process(*pid) {
                            continue;
                        }
                        if let Ok(regions) = memory_scanner.get_process_memory_map(*pid) {
                            for region in regions {
                                if region.size == 0 || region.size > 1024 * 1024 { continue; }
                                if let Ok(bytes) = memory_scanner.read_memory_region(*pid, region.base_address, region.size) {
                                    if let Ok(matches) = rules.scan_mem(&bytes, 10) {
                                        if !matches.is_empty() {
                                            let names = matches.into_iter().map(|m| m.identifier).collect::<Vec<_>>();
                                            log::warn!("RealtimeMonitor: YARA memory hit in PID {} -> {:?}", pid, names);
                                            // terminate or handle via engine
                                            engine.terminate_process(*pid);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            while !stop_signal.load(Ordering::Relaxed) {
                // 1. 检查新進程
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
                                println!("🚨 恶意进程检测: {} (PID: {})", process.name().to_string_lossy(), pid);
                                engine.terminate_process(sysinfo::Pid::from_u32(pid));
                            } else {
                                // NEW: also scan the process's memory with YARA rules (if loaded)
                                #[cfg(feature = "with-yara")]
                                {
                                    if let Some(rules) = yara_rules_clone.as_ref() {
                                        if let Ok(regions) = memory_scanner.get_process_memory_map(sysinfo::Pid::from_u32(pid)) {
                                            let mut found = false;
                                            for region in regions {
                                                if region.size == 0 || region.size > 1024 * 1024 { continue; }
                                                if let Ok(bytes) = memory_scanner.read_memory_region(sysinfo::Pid::from_u32(pid), region.base_address, region.size) {
                                                    if let Ok(matches) = rules.scan_mem(&bytes, 10) {
                                                        if !matches.is_empty() {
                                                            let names = matches.into_iter().map(|m| m.identifier).collect::<Vec<_>>();
                                                            println!("🚨 YARA 恶意进程检测: {} (PID: {})", process.name().to_string_lossy(), pid);
                                                            println!("  - 匹配 YARA 规则: {:?}", names);
                                                            found = true;
                                                        }
                                                    }
                                                }
                                            }
                                            if found {
                                                engine.terminate_process(sysinfo::Pid::from_u32(pid));
                                            }
                                        }
                                    }
                                }
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
                                        } else {
                                            // NEW: scan new files with YARA rules (if loaded)
                                            #[cfg(feature = "with-yara")]
                                            {
                                                if let Some(rules) = yara_rules_clone.as_ref() {
                                                    if let Ok(data) = std::fs::read(&path) {
                                                        if let Ok(matches) = rules.scan_mem(&data, 10) {
                                                            if !matches.is_empty() {
                                                                let names = matches.into_iter().map(|m| m.identifier).collect::<Vec<_>>();
                                                                println!("🚨 YARA 恶意文件检测: {:?}", path);
                                                                println!("  - 匹配 YARA 规则: {:?}", names);
                                                                engine.handle_threat(&path, &scan_result.result);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        known_files.insert(path.clone(), hash);
                                    } else if let Some(old_hash) = known_files.get(&path) {
                                        if &hash != old_hash {
                                            println!("✏️  文件修改: {:?}", path);
                                            let scan_result = engine.scan_file(&path);
                                            if scan_result.threat_detected {
                                                println!("🚨 恶意文件修改检测: {:?}", path);
                                                engine.handle_threat(&path, &scan_result.result);
                                            } else {
                                                // NEW: scan modified files with YARA rules (if loaded)
                                                #[cfg(feature = "with-yara")]
                                                {
                                                    if let Some(rules) = yara_rules_clone.as_ref() {
                                                        if let Ok(data) = std::fs::read(&path) {
                                                            if let Ok(matches) = rules.scan_mem(&data, 10) {
                                                                if !matches.is_empty() {
                                                                    let names = matches.into_iter().map(|m| m.identifier).collect::<Vec<_>>();
                                                                    println!("🚨 YARA 恶意文件修改检测: {:?}", path);
                                                                    println!("  - 匹配 YARA 规则: {:?}", names);
                                                                    engine.handle_threat(&path, &scan_result.result);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
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