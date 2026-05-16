//! 内存和进程监控服务（独立二进制）
//!
//! 职责：
//! - 监听进程创建事件（WMI或轮询）
//! - 扫描新进程的可执行文件和内存
//! - 通过IPC向主程序报告威胁

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{System, ProcessRefreshKind, Pid};
use std::collections::HashSet;
use chrono::Local;
use std::io::{self, Write};
use rust_antivirus::memory_scanner;

use rust_antivirus::yara_engine::YaraEngine;
use rust_antivirus::driver_bridge_enhanced::DriverInterface;

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(false)
        .try_init()
        .ok();
    
    println!("╔══════════════════════════════════════════╗");
    println!("║ Wenle Antivirus - Memory Monitor Service ║");
    println!("║  版本: 2.0 | 监控进程: PID {}         ║", std::process::id());
    println!("╚══════════════════════════════════════════╝");
    println!();
    println!("[时间] 监控类型 | 详细信息");
    println!("─────────────────────────────────────────");
    io::stdout().flush().ok();
    
    log::info!("Memory Monitor Service Started");
    log::info!("轮询间隔: 500ms | 检查进程创建/内存异常");
    log::info!("按 Ctrl+C 停止服务...");
    println!();

    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop_signal);

    // 设置 Ctrl+C 处理
    ctrlc::set_handler(move || {
        println!();
        let now = Local::now().format("%H:%M:%S");
        println!("[{}] 正在停止内存监控服务...", now);
        log::info!("Memory monitor received shutdown signal");
        stop_clone.store(true, Ordering::Relaxed);
    })
    .unwrap_or_else(|e| {
        log::error!("Failed to set Ctrl-C handler: {}", e);
    });

    // 主监控循环
    memory_monitor_loop(&stop_signal);

    let now = Local::now().format("%H:%M:%S");
    println!("[{}] 内存监控服务已停止", now);
    log::info!("Memory Monitor Service Stopped");
}

/// 内存和进程监控主循环
fn memory_monitor_loop(stop_signal: &Arc<AtomicBool>) {
    let mut system = System::new_all();
    let mut known_pids: HashSet<u32> = HashSet::new();
    let mut threat_count = 0u32;

    log::info!("Starting memory/process monitoring loop");

    // Initialize YARA engine and optional driver interface
    let yara: Option<YaraEngine> = match YaraEngine::with_rules("Configuration\\anti.yarac") {
        Ok(e) => {
            log::info!("Loaded YARA rules from Configuration\\anti.yarac");
            Some(e)
        }
        Err(e) => {
            log::warn!("Failed to initialize YARA engine: {}", e);
            None
        }
    };

    let mut driver = match DriverInterface::open("\\\\.\\WenleDriver") {
        Ok(d) => Some(d),
        Err(_) => None,
    };

    loop {
        if stop_signal.load(Ordering::Relaxed) {
            break;
        }

        // 刷新进程列表
        system.refresh_all();

        // 检测新进程
        for (pid, process) in system.processes() {
            if stop_signal.load(Ordering::Relaxed) {
                break;
            }

            let pid_value = pid.as_u32();

            // 如果这是新进程
            if !known_pids.contains(&pid_value) {
                known_pids.insert(pid_value);
                
                let proc_name = process.name().to_string_lossy().to_string();
                let now = Local::now().format("%H:%M:%S");
                println!("[{}] 🔍 进程监控 | 新进程: {} (PID: {})", now, proc_name, pid_value);
                log::info!("New process detected: PID {} - {}", pid_value, proc_name);

                // 扫描新进程的可执行文件
                if let Some(exe_path) = process.exe() {
                    let exe_str = exe_path.to_string_lossy().to_string();
                    
                    // 首先使用 YARA 扫描可执行文件（如果可用）
                    let matched = if let Some(ref y) = yara {
                        match y.scan_file(&exe_str) {
                            Ok(result) => !result.matched_rules.is_empty(),
                            Err(e) => {
                                log::warn!("YARA scan_file failed for {}: {}", exe_str, e);
                                false
                            }
                        }
                    } else {
                        false
                    };

                    if matched {
                        threat_count += 1;
                        let now = Local::now().format("%H:%M:%S");
                        println!("[{}] ⚠️  威胁检测 | YARA规则匹配 进程 {}", now, pid_value);
                        log::warn!("YARA rule matched process: PID {}", pid_value);
                    } else if let Some((threat_name, risk_score)) = heuristic_scan_process(pid_value, &exe_str, &proc_name) {
                        threat_count += 1;
                        let now = Local::now().format("%H:%M:%S");
                        println!("[{}] ⚠️  威胁检测 | 进程 {} - {} (风险评分: {})", now, pid_value, threat_name, risk_score);
                        log::warn!("Process threat detected: PID {} - {} (score: {})", pid_value, threat_name, risk_score);
                    }
                }

                // 扫描新进程的内存
                let memory_mb = process.memory() as f64 / 1024.0 / 1024.0;
                if memory_mb > 500.0 {
                    threat_count += 1;
                    let now = Local::now().format("%H:%M:%S");
                    println!("[{}] ⚠️  内存异常 | 进程 {} 占用 {:.1} MB", now, proc_name, memory_mb);
                    log::warn!("Suspicious memory usage detected: {} - {:.1} MB", proc_name, memory_mb);
                }
            }
        }

        // 清理已退出的进程
        let current_pids: HashSet<u32> = system
            .processes()
            .keys()
            .map(|p| p.as_u32())
            .collect();
        known_pids.retain(|pid| current_pids.contains(pid));

        // 降低检测延迟：改为300ms而不是5000ms
        std::thread::sleep(Duration::from_millis(300));
    }

    let now = Local::now().format("%H:%M:%S");
    println!("[{}] 监控总计检测到 {} 个威胁", now, threat_count);
    log::info!("Memory monitor loop ended. Total threats detected: {}", threat_count);
}

/// 启发式扫描进程
fn heuristic_scan_process(pid: u32, exe_path: &str, proc_name: &str) -> Option<(String, u8)> {
    let mut risk_score = 0u8;
    let mut threats = Vec::new();

    let exe_lower = exe_path.to_lowercase();
    let proc_lower = proc_name.to_lowercase();

    // 检查可疑的进程路径
    let suspicious_paths = [
        "temp", "tmp", "appdata", "local", "roaming", "windows\\temp",
        "system32\\drivers\\etc", "programdata"
    ];
    
    if suspicious_paths.iter().any(|&path| exe_lower.contains(path)) {
        risk_score += 20;
        threats.push("Suspicious execution path".to_string());
    }

    // 检查可疑的进程名称
    let suspicious_names = [
        "virus", "malware", "trojan", "backdoor", "keylogger", "ransomware", "worm",
        "rundll32", "wscript", "cscript", "powershell"
    ];
    
    if suspicious_names.iter().any(|&name| proc_lower.contains(name)) {
        risk_score += 30;
        threats.push("Suspicious process name".to_string());
    }

    // 检查进程是否没有公司签名（非系统进程）
    if !is_signed_system_process(exe_path) {
        if !exe_lower.contains("program files") && !exe_lower.contains("windows\\system32") {
            risk_score += 15;
            threats.push("Unsigned executable in unusual location".to_string());
        }
    }

    // 检查命令行参数（如果可以）
    if proc_lower.contains("cmd") || proc_lower.contains("powershell") {
        risk_score += 10;
        threats.push("Command interpreter detected".to_string());
    }

    if risk_score > 0 {
        Some((threats.join("; "), risk_score.min(100)))
    } else {
        None
    }
}

/// 检查进程是否是已签名的系统进程
fn is_signed_system_process(exe_path: &str) -> bool {
    let exe_lower = exe_path.to_lowercase();
    
    // 已知的合法系统进程路径
    let system_paths = [
        "windows\\system32",
        "windows\\syswow64",
        "windows\\winsxs",
        "program files\\windows defender",
        "program files\\windows nt",
    ];
    
    system_paths.iter().any(|&path| exe_lower.contains(path))
}
