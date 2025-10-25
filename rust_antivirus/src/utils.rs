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
    
    let digit_groups = (size as f64).log10() / 1024_f64.log10();
    let unit_index = digit_groups as usize;
    
    if unit_index >= UNITS.len() {
        format!("{:.1} {}", size, UNITS.last().unwrap())
    } else {
        format!("{:.1} {}", size as f64 / 1024_f64.powi(unit_index as i32), UNITS[unit_index])
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
    let mut dir = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("."))
        .parent()
        .unwrap_or(&PathBuf::from("."))
        .to_path_buf();
    dir.push("anti.yar");
    dir
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