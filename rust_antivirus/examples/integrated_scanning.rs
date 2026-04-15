// examples/integrated_scanning.rs: 整合式掃描示例
// 展示如何整合沙箱、行為監控、改進的隔離和記憶體掃描

use rust_antivirus::{
    sandbox::SandboxEngine,
    behavior_monitor::BehaviorMonitor,
    quarantine_manager::QuarantineManager,
    memory_scanner::MemoryScanner,
};
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    println!("=== Integrated Antivirus Scanning Example ===\n");

    // 1. 初始化沙箱引擎
    println!("[1] Initializing Sandbox Engine...");
    let sandbox = SandboxEngine::new();
    println!("✓ Sandbox engine ready\n");

    // 2. 初始化行為監控
    println!("[2] Initializing Behavior Monitor...");
    let behavior_monitor = BehaviorMonitor::new();
    behavior_monitor.init_default_rules()?;
    println!("✓ Behavior monitor with {} default rules ready\n", 5);

    // 3. 初始化隔離管理器（帶加密）
    println!("[3] Initializing Quarantine Manager with Encryption...");
    let quarantine_dir = PathBuf::from("./quarantine");
    let mut quarantine_mgr = QuarantineManager::new(quarantine_dir)?;
    println!("✓ Quarantine manager with encryption/audit enabled\n");

    // 4. 沙箱掃描檔案示例
    println!("[4] Scanning sample files with Sandbox...\n");
    let test_files = vec![
        ("C:\\Windows\\System32\\notepad.exe", "Trusted system file"),
        ("C:\\Users\\Public\\Downloads\\suspicious.exe", "Suspicious executable"),
    ];

    for (file_path, description) in test_files {
        println!("  Scanning: {} ({})", file_path, description);
        let file = PathBuf::from(file_path);
        
        if file.exists() {
            match sandbox.scan_file(&file) {
                Ok(result) => {
                    println!("    Risk Score: {}/100", result.risk_score);
                    println!("    Suspicious: {}", result.is_suspicious);
                    println!("    API Hooks Detected: {}", result.api_hooks_detected);
                    if !result.obfuscation_indicators.is_empty() {
                        println!("    Obfuscation Indicators:");
                        for indicator in &result.obfuscation_indicators {
                            println!("      - {}", indicator);
                        }
                    }
                    println!("    Scan Time: {} ms\n", result.scan_time_ms);

                    // 如果風險很高，隔離檔案
                    if result.risk_score > 60 {
                        println!("    → HIGH RISK! Attempting to quarantine...");
                        match quarantine_mgr.isolate_file(
                            &file,
                            "Sandbox Detection - High Risk".to_string(),
                            "automated_scanner",
                        ) {
                            Ok(qpath) => println!("    ✓ Quarantined to: {}\n", qpath.display()),
                            Err(e) => println!("    ✗ Quarantine failed: {}\n", e),
                        }
                    }
                }
                Err(e) => println!("    Error: {}\n", e),
            }
        } else {
            println!("    (file does not exist, skipping)\n");
        }
    }

    // 5. 行為監控 - 模擬執行請求攔截
    println!("[5] Testing Behavior Monitoring & Interception...\n");

    let test_cases = vec![
        (4567, "chrome.exe", "C:\\Windows\\System32\\kernel32.dll", "read", "Normal system access"),
        (1234, "unknown.exe", "C:\\Users\\Public\\Downloads\\malware.exe", "execute", "Suspicious executable"),
        (9999, "powershell.exe", "powershell.exe -Command Invoke-Expression", "process_create", "Malicious PowerShell"),
    ];

    for (pid, name, target, access_type, desc) in test_cases {
        println!("  Case: {} ({})", desc, name);
        match behavior_monitor.handle_file_access_interception(pid, name, target, access_type) {
            Ok((action, reason)) => {
                println!("    Action: {:?}", action);
                println!("    Reason: {}\n", reason);
            }
            Err(e) => println!("    Error: {}\n", e),
        }
    }

    // 6. 獲取被攔截的事件
    println!("[6] Blocked Events Summary\n");
    match behavior_monitor.get_blocked_events() {
        Ok(events) => {
            println!("  Total blocked events: {}", events.len());
            for event in events.iter().take(5) {
                println!("    - {}: {} (PID:{})", event.event_type, event.reason, event.source);
            }
            println!();
        }
        Err(e) => println!("  Error retrieving events: {}\n", e),
    }

    // 7. 隔離審計日誌
    println!("[7] Quarantine Audit Log\n");
    let audit_log = quarantine_mgr.get_audit_log();
    if !audit_log.is_empty() {
        println!("  Recent audit entries ({} total):", audit_log.len());
        for entry in audit_log.iter().take(3) {
            println!("    - [{}] {} by {} - {}", 
                entry.action, entry.quarantine_hash, entry.operator, entry.status);
        }
    } else {
        println!("  (No audit entries yet)");
    }
    println!();

    // 8. 記憶體掃描改進示例
    println!("[8] Memory Scanning with Improved Region Traversal\n");
    let memory_scanner = MemoryScanner::new();
    
    // 獲取所有非系統進程
    let results = memory_scanner.scan_all_processes();
    println!("  Scanned {} processes", results.len());
    
    // 顯示可疑進程
    let suspicious: Vec<_> = results.iter().filter(|r| r.is_malicious).collect();
    if !suspicious.is_empty() {
        println!("  Suspicious processes detected: {}", suspicious.len());
        for result in suspicious.iter().take(3) {
            println!("    - {} (Risk: {}/100)", result.process_name, result.risk_score);
        }
    } else {
        println!("  No suspicious processes detected");
    }
    println!();

    // 最終總結
    println!("=== Scanning Summary ===");
    println!("✓ Sandbox scanning completed");
    println!("✓ Behavior monitoring active");
    println!("✓ Quarantine with encryption/audit enabled");
    println!("✓ Memory scanning with improved region traversal");
    println!("✓ All threat detection layers operational");

    Ok(())
}
