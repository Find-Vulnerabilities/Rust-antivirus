// src/bin/yara_scan_example.rs
// YARA 掃描示例程序 - 展示如何使用新的 YARA 集成層

use std::path::PathBuf;
use std::sync::Arc;
use rust_antivirus::yara_engine;

fn main() -> Result<(), String> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    log::info!("=== YARA Enterprise Antivirus Scanner ===");
    log::info!("Version: 0.2.0 Enterprise");

    // 初始化 YARA 引擎
    log::info!("Initializing YARA engine...");
    if let Err(e) = rust_antivirus::yara_engine::YaraEngine::init() {
        return Err(e);
    }
    log::info!("✓ YARA engine initialized");

    // 加載編譯的規則
    let rules_path = "Configuration/anti.yarac";
    log::info!("Loading compiled rules from: {}", rules_path);
    
    let engine = Arc::new(
        rust_antivirus::yara_engine::YaraEngine::with_rules(rules_path)
            .map_err(|e| format!("Failed to load rules: {}", e))?
    );
    log::info!("✓ Rules loaded successfully (27.4MB compiled ruleset)");

    // 创建文件扫描器
    let file_scanner = rust_antivirus::yara_integration::FileScanner::new(engine.clone());
    
    // 创建隔离管理器
    let quarantine_dir = PathBuf::from("Quarantine");
    let quarantine = rust_antivirus::yara_integration::QuarantineManager::new(quarantine_dir)?;
    log::info!("✓ Quarantine directory ready");

    // 示例 1: 扫描单个文件
    log::info!("\n=== Example 1: Scan Single File ===");
    scan_example_file(&file_scanner)?;

    // 示例 2: 扫描目录
    log::info!("\n=== Example 2: Scan Directory ===");
    scan_example_directory(&file_scanner)?;

    // 示例 3: 内存扫描
    #[cfg(windows)]
    {
        log::info!("\n=== Example 3: Scan Process Memory ===");
        scan_example_memory(&engine)?;
    }

    // 示例 4: 隔离管理
    log::info!("\n=== Example 4: Quarantine Management ===");
    quarantine_example(&quarantine)?;

    log::info!("\n=== Scan Complete ===");
    log::info!("Summary:");
    log::info!("  - YARA engine initialized successfully");
    log::info!("  - Rules loaded: anti.yarac (compiled binary format)");
    log::info!("  - File scanning supported");
    log::info!("  - Memory scanning supported (Windows)");
    log::info!("  - Quarantine management available");

    Ok(())
}

fn scan_example_file(
    scanner: &rust_antivirus::yara_integration::FileScanner,
) -> Result<(), String> {
    // 扫描当前目录中的某个文件
    let test_file = std::env::current_exe().map_err(|e| e.to_string())?;
    log::info!("Scanning: {}", test_file.display());

    match scanner.scan_file(&test_file) {
        Ok(result) => {
            if result.is_malicious {
                log::warn!("  ⚠ THREAT DETECTED!");
                log::warn!("    Matched rules: {:?}", result.matched_rules);
                log::warn!("    Confidence: {}%", result.confidence);
            } else {
                log::info!("  ✓ File is clean");
            }
            log::info!("    Scan time: {}ms", result.scan_time_ms);
        }
        Err(e) => log::error!("  ✗ Scan error: {}", e),
    }

    Ok(())
}

fn scan_example_directory(
    scanner: &rust_antivirus::yara_integration::FileScanner,
) -> Result<(), String> {
    let scan_dir = std::env::temp_dir();
    log::info!("Scanning directory: {}", scan_dir.display());
    log::info!("(Note: Scanning temp directory - for demo purposes)");

    match scanner.scan_directory(&scan_dir) {
        Ok(results) => {
            log::info!("  Total files scanned: {}", results.len());
            
            let threats = results.iter().filter(|r| r.is_malicious).count();
            if threats > 0 {
                log::warn!("  ⚠ Threats found: {}", threats);
                for result in results.iter().filter(|r| r.is_malicious) {
                    log::warn!("    - {}", result.item_path);
                }
            } else {
                log::info!("  ✓ No threats detected");
            }
        }
        Err(e) => log::error!("  ✗ Directory scan error: {}", e),
    }

    Ok(())
}

#[cfg(windows)]
fn scan_example_memory(
    engine: &Arc<rust_antivirus::yara_engine::YaraEngine>,
) -> Result<(), String> {
    use std::process;

    let current_pid = process::id();
    let process_name = "yara_scan_example";
    
    log::info!("Scanning process memory: PID={}, Name={}", current_pid, process_name);

    let memory_scanner = rust_antivirus::yara_integration::MemoryScanner::new(engine.clone());
    
    match memory_scanner.scan_process(current_pid, process_name) {
        Ok(result) => {
            if result.is_malicious {
                log::warn!("  ⚠ THREAT DETECTED IN MEMORY!");
                log::warn!("    Matched rules: {:?}", result.matched_rules);
            } else {
                log::info!("  ✓ Process memory is clean");
            }
            log::info!("    Scan time: {}ms", result.scan_time_ms);
        }
        Err(e) => log::error!("  ✗ Memory scan error: {}", e),
    }

    Ok(())
}

fn quarantine_example(
    quarantine: &rust_antivirus::yara_integration::QuarantineManager,
) -> Result<(), String> {
    // 列出隔离文件
    match quarantine.list_quarantined() {
        Ok(files) => {
            log::info!("Quarantined files: {}", files.len());
            for file in files {
                log::info!("  - {}", file.display());
            }
        }
        Err(e) => log::error!("Error listing quarantine: {}", e),
    }

    Ok(())
}
