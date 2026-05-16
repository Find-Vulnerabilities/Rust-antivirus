//! 文件系统监控服务（独立二进制）
//! 
//! 职责：
//! - 监听文件系统变化（ReadDirectoryChangesW或轮询）
//! - 维护文件哈希缓存
//! - 通过IPC向主程序报告威胁

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use rust_antivirus::engine;
use std::time::Duration;
use walkdir::WalkDir;
use chrono::Local;
use std::io::{self, Write};

use rust_antivirus::yara_engine::YaraEngine;
use rust_antivirus::driver_bridge_enhanced::DriverInterface;

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
    .unwrap_or_else(|e| {
        log::error!("Failed to set Ctrl-C handler: {}", e);
    });

    // 主监控循环
    file_monitor_loop(&monitored_paths, &stop_signal);

    let now = Local::now().format("%H:%M:%S");
    println!("[{}] 文件监控服务已停止", now);
    log::info!("File Monitor Service Stopped");
}

/// 文件监控主循环
fn file_monitor_loop(monitored_paths: &[PathBuf], stop_signal: &Arc<AtomicBool>) {
    log::info!("Starting file monitoring loop for {} paths", monitored_paths.len());
    
    let mut file_hashes = std::collections::HashMap::new();
    let mut threat_count = 0u32;

    // Initialize YARA engine and driver interface (driver optional)
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

                // 检查文件是否存在异常
                let file_hash = calculate_quick_hash(file_path);
                let is_new_or_modified = if let Some(prev_hash) = file_hashes.get(&file_path.to_path_buf()) {
                    prev_hash != &file_hash
                } else {
                    true
                };

                if is_new_or_modified {
                    file_hashes.insert(file_path.to_path_buf(), file_hash.clone());
                    
                    // Prefer scanning with YARA library if available; otherwise fall back to heuristic
                    let matched = if let Some(ref y) = yara {
                        let file_path_str = file_path.to_str().unwrap_or("");
                        match y.scan_file(file_path_str) {
                            Ok(result) => !result.matched_rules.is_empty(),
                            Err(e) => {
                                log::warn!("YARA scan failed for {:?}: {}", file_path, e);
                                false
                            }
                        }
                    } else {
                        false
                    };

                    if matched {
                        threat_count += 1;
                        let now = Local::now().format("%H:%M:%S");
                        println!("[{}] ⚠️  威胁检测 | YARA规则匹配 {:?}", now, file_path);
                        log::warn!("YARA rule matched file: {:?}", file_path);
                        // TODO: 通过IPC或驱动上报并隔离文件
                    } else if let Some((threat_name, risk_score)) = heuristic_scan_file(file_path) {
                        threat_count += 1;
                        let now = Local::now().format("%H:%M:%S");
                        println!("[{}] ⚠️  威胁检测 | {} (风险评分: {})", now, threat_name, risk_score);
                        log::warn!("Threat detected: {:?} - {} (score: {})", file_path, threat_name, risk_score);
                    } else {
                        let now = Local::now().format("%H:%M:%S");
                        println!("[{}] ✓ 文件扫描 | {:?}", now, file_path.file_name().unwrap_or_default());
                    }
                }
            }
        }

        // 降低检测延迟：改为200ms而不是5000ms
        std::thread::sleep(Duration::from_millis(200));
    }

    let now = Local::now().format("%H:%M:%S");
    println!("[{}] 监控总计检测到 {} 个威胁", now, threat_count);
    log::info!("File monitor loop ended. Total threats detected: {}", threat_count);
}

/// 判断文件是否应该被扫描
fn should_scan_file(path: &Path) -> bool {
    // 检查扩展名
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_lowercase();
        // 跳过已知的非可执行文件
        let skip_extensions = ["txt", "pdf", "jpg", "png", "gif", "mp3", "mp4", "zip", "rar"];
        if skip_extensions.contains(&ext_lower.as_str()) {
            return false;
        }
    }

    true
}

/// 快速哈希计算（用于检测文件修改）
fn calculate_quick_hash(path: &Path) -> String {
    match std::fs::metadata(path) {
        Ok(metadata) => {
            // 使用修改时间 + 文件大小作为快速哈希
            format!("{:x}_{}", metadata.len(), metadata.modified()
                .map(|t| t.elapsed().map(|d| d.as_secs()).unwrap_or(0))
                .unwrap_or(0))
        }
        Err(_) => String::new()
    }
}

/// 启发式扫描文件
fn heuristic_scan_file(path: &Path) -> Option<(String, u8)> {
    let mut risk_score = 0u8;
    let mut threats = Vec::new();

    // 检查文件扩展名
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_lowercase();
        
        // 高风险可执行文件
        if matches!(ext_lower.as_str(), "exe" | "bat" | "cmd" | "vbs" | "js" | "jar" | "dll" | "sys" | "ps1") {
            risk_score += 30;
            threats.push("High risk executable".to_string());
        }
    }

    // 检查文件名可疑特征
    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
        let name_lower = file_name.to_lowercase();
        
        let suspicious_names = ["virus", "malware", "trojan", "backdoor", "keylogger", "ransomware", "worm"];
        if suspicious_names.iter().any(|&name| name_lower.contains(name)) {
            risk_score += 40;
            threats.push("Suspicious filename".to_string());
        }

        // 检查双重扩展名
        let parts: Vec<&str> = file_name.split('.').collect();
        if parts.len() > 2 {
            let last_two = &parts[parts.len()-2..];
            if matches!(last_two, ["exe", "txt"] | ["jpg", "exe"] | ["pdf", "exe"] | ["doc", "exe"]) {
                risk_score += 50;
                threats.push("Double extension detected".to_string());
            }
        }
    }

    // 检查文件大小异常
    if let Ok(metadata) = std::fs::metadata(path) {
        if metadata.len() == 0 {
            risk_score += 10;
            threats.push("Zero-byte file".to_string());
        } else if metadata.len() > 100 * 1024 * 1024 {
            risk_score += 20;
            threats.push("Suspiciously large file".to_string());
        }
    }

    if risk_score > 0 {
        Some((threats.join("; "), risk_score.min(100)))
    } else {
        None
    }
}
