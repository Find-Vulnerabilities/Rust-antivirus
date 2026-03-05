//! 文件系统监控服务（独立二进制）
//! 
//! 职责：
//! - 监听文件系统变化（ReadDirectoryChangesW或轮询）
//! - 维护文件哈希缓存
//! - 通过IPC向主程序报告威胁

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use walkdir::WalkDir;
use chrono::Local;
use std::io::{self, Write};

fn main() {
    // Write to file to confirm execution
    let _ = std::fs::write(
        "C:\\file-monitor-started.txt",
        format!("File Monitor started at {}\n", chrono::Local::now())
    );
    
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(false)
        .try_init()
        .ok();
    
    println!("╔══════════════════════════════════════════╗");
    println!("║  Wenle Antivirus - File Monitor Service  ║");
    println!("║  版本: 2.0 | 监控进程: PID {}         ║", std::process::id());
    println!("╚══════════════════════════════════════════╝");
    println!();
    println!("[时间] 监控类型 | 详细信息");
    println!("─────────────────────────────────────────");
    io::stdout().flush().ok();
    
    log::info!("File Monitor Service Started");
    log::info!("监控路径: C:\\Windows\\System32, C:\\ProgramData, C:\\Program Files*");
    log::info!("按 Ctrl+C 停止服务...");
    println!();

    // 配置监控路径
    let monitored_paths = vec![
        PathBuf::from("C:\\Windows\\System32"),
        PathBuf::from("C:\\ProgramData"),
        PathBuf::from("C:\\Program Files"),
        PathBuf::from("C:\\Program Files (x86)"),
    ];

    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop_signal);

    // 设置 Ctrl+C 处理
    ctrlc::set_handler(move || {
        println!();
        let now = Local::now().format("%H:%M:%S");
        println!("[{}] 正在停止文件监控服务...", now);
        log::info!("File monitor received shutdown signal");
        stop_clone.store(true, Ordering::Relaxed);
    })
    .expect("Error setting Ctrl-C handler");

    // 主监控循环
    file_monitor_loop(&monitored_paths, &stop_signal);

    let now = Local::now().format("%H:%M:%S");
    println!("[{}] 文件监控服务已停止", now);
    log::info!("File Monitor Service Stopped");
}

/// 文件监控主循环
fn file_monitor_loop(monitored_paths: &[PathBuf], stop_signal: &Arc<AtomicBool>) {
    log::info!("Starting file monitoring loop for {} paths", monitored_paths.len());

    loop {
        if stop_signal.load(Ordering::Relaxed) {
            break;
        }

        for path in monitored_paths {
            if stop_signal.load(Ordering::Relaxed) {
                break;
            }

            if !path.exists() {
                log::debug!("Monitored path does not exist: {:?}", path);
                continue;
            }

            // 遍历目录（max_depth=2避免深入递归）
            for entry in WalkDir::new(path)
                .max_depth(2)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if stop_signal.load(Ordering::Relaxed) {
                    break;
                }

                if !entry.file_type().is_file() {
                    continue;
                }

                let file_path = entry.path();

                // 跳过不需要扫描的文件
                if !should_scan_file(file_path) {
                    continue;
                }

                log::trace!("Monitoring file: {:?}", file_path);

                // TODO: 集成实际的扫描引擎
                // let result = engine.scan_file(file_path);
                // if result.threat_detected {
                //     TODO: 通过IPC发送威胁告警
                // }
            }
        }

        // 降低检测延迟：改为200ms而不是5000ms
        std::thread::sleep(Duration::from_millis(200));
    }

    log::info!("File monitor loop ended");
}

/// 判断文件是否应该被扫描
fn should_scan_file(path: &Path) -> bool {
    // 检查扩展名
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_lowercase();
        // 跳过已知的非可执行文件
        let skip_extensions = ["txt", "pdf", "jpg", "png", "gif", "mp3", "mp4"];
        if skip_extensions.contains(&ext_lower.as_str()) {
            return false;
        }
    }

    true
}
