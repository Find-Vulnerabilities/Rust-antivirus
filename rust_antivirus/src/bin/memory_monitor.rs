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
    .expect("Error setting Ctrl-C handler");

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

    log::info!("Starting memory/process monitoring loop");

    loop {
        if stop_signal.load(Ordering::Relaxed) {
            break;
        }

        // 刷新进程列表
        system.refresh_all();

        // 检测新进程
        for (pid, _process) in system.processes() {
            if stop_signal.load(Ordering::Relaxed) {
                break;
            }

            let pid_value = pid.as_u32();

            // 如果这是新进程
            if !known_pids.contains(&pid_value) {
                known_pids.insert(pid_value);
                log::info!("New process detected: PID {}", pid_value);

                // TODO: 扫描新进程的可执行文件
                // if let Some(exe_path) = process.exe() {
                //     let result = engine.scan_file(exe_path);
                //     if result.threat_detected {
                //         // TODO: 通过IPC发送威胁告警
                //     }
                // }

                // TODO: 扫描新进程的内存
                // let memory_result = memory_scanner.scan_process_memory(pid);
                // if memory_result.is_malicious {
                //     // TODO: 通过IPC发送威胁告警
                // }
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

    log::info!("Memory monitor loop ended");
}
