use std::collections::HashSet;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use crossbeam_channel::{Receiver, Sender, unbounded};
use sysinfo::{Pid, System};

use crate::engine::AntivirusEngine;
use crate::memory_scanner::MemoryScanner;

#[derive(Debug)]
pub struct ProcessEvent {
    pub pid: Pid,
    pub name: String,
    pub event_type: ProcessEventType,
}

#[derive(Debug)]
pub enum ProcessEventType {
    Started,
    Terminated,
    SuspiciousActivity(String),
}

pub struct ProcessMonitor {
    engine: Arc<AntivirusEngine>,
    memory_scanner: MemoryScanner,
    known_pids: HashSet<Pid>,
    stop_signal: Arc<std::sync::atomic::AtomicBool>,
}

impl ProcessMonitor {
    pub fn new(engine: Arc<AntivirusEngine>) -> Self {
        Self {
            engine,
            memory_scanner: MemoryScanner::new(),
            known_pids: HashSet::new(),
            stop_signal: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn start_monitoring(&mut self) -> Receiver<ProcessEvent> {
        let (tx, rx) = unbounded();
        let stop_signal = self.stop_signal.clone();
        let engine_arc = self.engine.clone();

        // 初始化已知进程
        self.memory_scanner.refresh();
        self.known_pids = self.memory_scanner.get_system().processes().keys().cloned().collect();

        let memory_scanner = self.memory_scanner.clone();
        let mut known_pids = self.known_pids.clone();

        thread::spawn(move || {
            let mut system = System::new_all();

            while !stop_signal.load(std::sync::atomic::Ordering::Relaxed) {
                system.refresh_all();
                let current_pids: HashSet<Pid> = system.processes().keys().cloned().collect();

                // 检测新进程
                for &pid in current_pids.difference(&known_pids) {
                    if let Some(process) = system.process(pid) {
                        let event = ProcessEvent {
                            pid,
                            name: process.name().to_string_lossy().to_string(),
                            event_type: ProcessEventType::Started,
                        };
                        let _ = tx.send(event);

                        // 扫描新进程 - 使用 memory_scanner
                        Self::scan_new_process(pid, process, &memory_scanner, &engine_arc, &tx);
                    }
                }

                // 定期内存扫描 - 使用 memory_scanner
                Self::perform_periodic_memory_scan(&memory_scanner, &engine_arc, &tx);

                known_pids = current_pids;
                thread::sleep(Duration::from_secs(5));
            }
        });

        rx
    }

    fn scan_new_process(
        pid: Pid,
        process: &sysinfo::Process,
        memory_scanner: &MemoryScanner,
        _engine: &AntivirusEngine,
        tx: &Sender<ProcessEvent>,
    ) {
        // 跳过系统进程 - 使用 memory_scanner
        if memory_scanner.is_system_process(pid) {
            return;
        }

        // 扫描可执行文件
        if let Some(exe_path) = process.exe() {
            let scan_result = _engine.scan_file(exe_path);
            if scan_result.threat_detected {
                let event = ProcessEvent {
                    pid,
                    name: process.name().to_string_lossy().to_string(),
                    event_type: ProcessEventType::SuspiciousActivity(
                        format!("Malicious executable: {}", scan_result.result)
                    ),
                };
                let _ = tx.send(event);

                // 终止恶意进程 - 使用 memory_scanner
                if memory_scanner.terminate_process(pid) {
                    log::warn!("Terminated malicious process: {:?} (PID: {})", process.name(), pid);
                }
            }
        }

        // 扫描进程内存 - 使用 memory_scanner
        match memory_scanner.scan_process_memory(pid) {
            Ok(memory_scan_result) => {
                if memory_scan_result.is_malicious {
                    let event = ProcessEvent {
                        pid,
                        name: process.name().to_string_lossy().to_string(),
                        event_type: ProcessEventType::SuspiciousActivity(memory_scan_result.reason),
                    };
                    let _ = tx.send(event);

                    // 终止恶意进程 - 使用 memory_scanner
                    if memory_scanner.terminate_process(pid) {
                        log::warn!("Terminated process with malicious memory: {:?} (PID: {})", process.name(), pid);
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to scan process memory for {:?} (PID: {}): {}", process.name(), pid, e);
            }
        }
    }

    fn perform_periodic_memory_scan(
        memory_scanner: &MemoryScanner,
        engine: &AntivirusEngine,
        tx: &Sender<ProcessEvent>,
    ) {
        let scan_results = memory_scanner.scan_all_processes();
        
        for result in scan_results {
            if result.is_malicious {
                let process_name = result.process_name.clone();
                let event = ProcessEvent {
                    pid: result.pid,
                    name: process_name.clone(),
                    event_type: ProcessEventType::SuspiciousActivity(result.reason.clone()),
                };
                let _ = tx.send(event);

                // 终止恶意进程 - 使用 memory_scanner
                if memory_scanner.terminate_process(result.pid) {
                    log::warn!("Terminated malicious process during periodic scan: {} (PID: {})", 
                              process_name, result.pid);
                }
            }
        }
    }

    pub fn stop(&self) {
        self.stop_signal.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

// 为 MemoryScanner 实现 Clone
impl Clone for MemoryScanner {
    fn clone(&self) -> Self {
        Self::new()
    }
}

// Add public getter for system field
impl MemoryScanner {
    pub fn get_system(&self) -> &System {
        &self.system
    }
}