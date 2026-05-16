use std::path::{PathBuf};

pub fn get_quarantine_dir() -> PathBuf {
    let mut dir = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("."))
        .parent()
        .unwrap_or(&PathBuf::from("."))
        .to_path_buf();
    
    dir.push("quarantine");
    dir
}

pub fn format_file_size(size: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    
    if size == 0 {
        return "0 B".to_string();
    }

    let size_f = size as f64;
    // 正確以 1024 為底計算階層
    let unit_index = (size_f.log(1024_f64).floor() as usize).min(UNITS.len() - 1);
    let value = size_f / 1024_f64.powi(unit_index as i32);
    if unit_index >= UNITS.len() {
        format!("{:.1} {}", size_f, UNITS.last().copied().unwrap_or("B"))
    } else {
        format!("{:.1} {}", value, UNITS[unit_index])
    }
}

pub fn get_system_info() -> String {
    format!(
        "OS: {} | Arch: {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

// Add helper for YARA rules path
pub fn get_yara_rules_path() -> PathBuf {
    // Search order:
    // 1. Compiled "anti.yarac" next to executable
    // 2. Compiled "anti.yarac" in Configuration subdirectory
    // 3. Fallback to "anti.yar" next to executable
    
    let mut exe_dir = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("."))
        .parent()
        .unwrap_or(&PathBuf::from("."))
        .to_path_buf();

    log::info!("搜索 YARA 规则文件，可执行文件目录: {:?}", exe_dir);

    // Try 1: anti.yarac in exe directory
    let compiled_exe = exe_dir.join("anti.yarac");
    log::debug!("检查路径 1: {:?}", compiled_exe);
    if compiled_exe.exists() {
        log::info!("✓ 找到 YARA 规则文件: {:?}", compiled_exe);
        return compiled_exe;
    }

    // Try 2: anti.yarac in Configuration subdirectory (relative to exe)
    let compiled_config = exe_dir.join("Configuration").join("anti.yarac");
    log::debug!("检查路径 2: {:?}", compiled_config);
    if compiled_config.exists() {
        log::info!("✓ 找到 YARA 规则文件: {:?}", compiled_config);
        return compiled_config;
    }

    // Try 3: anti.yarac in ../Configuration (relative to exe, parent is rust_antivirus/)
    let compiled_parent_config = exe_dir.parent()
        .map(|p| p.join("Configuration").join("anti.yarac"))
        .filter(|p| {
            log::debug!("检查路径 3: {:?}", p);
            p.exists()
        });
    if let Some(p) = compiled_parent_config {
        log::info!("✓ 找到 YARA 规则文件: {:?}", p);
        return p;
    }

    // Fallback: anti.yar in exe directory
    log::warn!("⚠ 未找到 anti.yarac，回退到 anti.yar");
    exe_dir.push("anti.yar");
    log::warn!("回退路径: {:?}", exe_dir);
    exe_dir
}

// Add helper for deletion log path
pub fn get_deletion_log_path() -> PathBuf {
    let mut dir = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("."))
        .parent()
        .unwrap_or(&PathBuf::from("."))
        .to_path_buf();
    dir.push("deletion_log.json");
    dir
}