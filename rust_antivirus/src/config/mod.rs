//! Shared configuration module used by all three processes

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Global configuration for antivirus monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntvirusConfig {
    /// Directories to monitor (recursive)
    pub monitored_paths: Vec<PathBuf>,

    /// Whitelist of safe file hashes
    pub whitelist_hashes: HashSet<String>,

    /// File extensions to exclude from scanning
    pub excluded_extensions: Vec<String>,

    /// Process names to exclude (system processes)
    pub excluded_processes: Vec<String>,

    /// Enable realtime file monitoring
    pub enable_file_monitoring: bool,

    /// Enable process monitoring
    pub enable_process_monitoring: bool,

    /// Enable memory scanning
    pub enable_memory_scanning: bool,

    /// File monitoring interval in milliseconds (fallback if event API fails)
    pub file_monitor_interval_ms: u32,

    /// Process monitoring interval in milliseconds
    pub process_monitor_interval_ms: u32,

    /// Memory scan interval in milliseconds
    pub memory_scan_interval_ms: u32,

    /// Maximum size of hash cache (in number of entries)
    pub hash_cache_max_entries: usize,

    /// Hash cache TTL in seconds
    pub hash_cache_ttl_secs: u64,

    /// Quarantine directory path
    pub quarantine_dir: PathBuf,

    /// Enable automatic threat isolation
    pub auto_isolate_threats: bool,

    /// Risk score threshold for automatic action (0-100)
    pub threat_action_threshold: u8,
}

impl Default for AntvirusConfig {
    fn default() -> Self {
        let mut monitored_paths = vec![];

        // Add core system paths
        let core_paths = vec![
            "C:\\Windows",
            "C:\\Windows\\System32",
            "C:\\ProgramData",
            "C:\\Program Files",
            "C:\\Program Files (x86)",
        ];

        for path_str in core_paths {
            let path = PathBuf::from(path_str);
            if path.exists() {
                monitored_paths.push(path);
            }
        }

        // Add user paths
        if let Ok(users_dir) = std::fs::read_dir("C:\\Users") {
            for entry in users_dir.flatten() {
                let user_path = entry.path();
                if user_path.is_dir() {
                    for sub_dir in &["AppData", "Downloads", "Documents"] {
                        let sub_path = user_path.join(sub_dir);
                        if sub_path.exists() {
                            monitored_paths.push(sub_path);
                        }
                    }
                }
            }
        }

        // Add temp directory
        if let Ok(temp) = std::env::var("TEMP") {
            let temp_path = PathBuf::from(temp);
            if temp_path.exists() {
                monitored_paths.push(temp_path);
            }
        }

        let excluded_extensions = vec![
            "txt", "pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "gif", "mp3", "mp4",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect();

        let excluded_processes = vec![
            "System", "svchost.exe", "csrss.exe", "lsass.exe", "services.exe",
            "winlogon.exe", "explorer.exe", "dwm.exe",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect();

        let quarantine_dir = if let Ok(appdata) = std::env::var("APPDATA") {
            PathBuf::from(appdata).join("Wenle Antivirus\\Quarantine")
        } else {
            PathBuf::from("C:\\ProgramData\\Wenle Antivirus\\Quarantine")
        };

        Self {
            monitored_paths,
            whitelist_hashes: HashSet::new(),
            excluded_extensions,
            excluded_processes,
            enable_file_monitoring: true,
            enable_process_monitoring: true,
            enable_memory_scanning: true,
            file_monitor_interval_ms: 5000,
            process_monitor_interval_ms: 5000,
            memory_scan_interval_ms: 5000,
            hash_cache_max_entries: 100_000,
            hash_cache_ttl_secs: 3600, // 1 hour
            quarantine_dir,
            auto_isolate_threats: true,
            threat_action_threshold: 70, // Kill processes with risk score > 70
        }
    }
}

impl AntvirusConfig {
    /// Load configuration from JSON file
    pub fn load_from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config = serde_json::from_str(&contents)?;
        Ok(config)
    }

    /// Save configuration to JSON file
    pub fn save_to_file(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))?;
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Check if a file extension should be scanned
    pub fn should_scan_extension(&self, path: &Path) -> bool {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            !self.excluded_extensions.contains(&ext.to_lowercase())
        } else {
            true
        }
    }

    /// Check if a process should be monitored
    pub fn should_monitor_process(&self, process_name: &str) -> bool {
        !self
            .excluded_processes
            .iter()
            .any(|p| p.eq_ignore_ascii_case(process_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AntvirusConfig::default();
        assert!(config.enable_file_monitoring);
        assert!(config.enable_process_monitoring);
        assert!(config.enable_memory_scanning);
        assert!(!config.monitored_paths.is_empty());
    }

    #[test]
    fn test_excluded_extensions() {
        let config = AntvirusConfig::default();
        assert!(!config.should_scan_extension(Path::new("test.txt")));
        assert!(!config.should_scan_extension(Path::new("test.pdf")));
        assert!(config.should_scan_extension(Path::new("test.exe")));
    }

    #[test]
    fn test_excluded_processes() {
        let config = AntvirusConfig::default();
        assert!(!config.should_monitor_process("System"));
        assert!(!config.should_monitor_process("explorer.exe"));
        assert!(config.should_monitor_process("myapp.exe"));
    }
}
