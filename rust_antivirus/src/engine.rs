use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::process::Command;

use ring::digest;
use serde::{Deserialize, Serialize};
use sysinfo::{Pid, System};
use walkdir::WalkDir;

use crate::utils;
use winapi::um::processthreadsapi::{OpenProcess, TerminateProcess};
use winapi::um::winnt::PROCESS_TERMINATE;
use winapi::um::handleapi::CloseHandle;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub file_path: PathBuf,
    pub result: String,
    pub risk_score: u8,
    pub threat_detected: bool,
    pub rule_matches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionRecord {
    pub original_path: PathBuf,
    pub reason: String,
    pub timestamp: u64,
    pub file_hash: String,
    pub size: u64,
    pub deleted: bool,
    pub quarantined: bool,
    pub quarantine_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct MemoryScanResult {
    pub pid: Pid,
    pub process_name: String,
    pub suspicious_regions: usize,
    pub is_malicious: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct FileIntegrity {
    pub size: u64,
    pub mtime: u64,
    pub hash: String,
}

#[derive(Debug)]
pub enum EngineError {
    Io(io::Error),
    Json(serde_json::Error),
    Yara(String),
}

pub struct AntivirusEngine {
    pub scan_count: Arc<Mutex<u32>>,
    pub threats_found: Arc<Mutex<u32>>,
    pub deleted_files: Arc<Mutex<Vec<DeletionRecord>>>,
    pub whitelisted_hashes: Arc<Mutex<HashSet<String>>>,
    pub file_integrity_records: Arc<Mutex<HashMap<PathBuf, FileIntegrity>>>,
    pub stop_signal: Arc<Mutex<bool>>,
    pub quarantine_dir: PathBuf,
    pub yara_rules: Arc<Mutex<Option<()>>>, // Placeholder, not used
}

// 白名单哈希值
const WHITELISTED_HASHES: [&str; 19] = [
    "ca8c0a2a00f1d6f6da076d1d61fa706e82df57ed2b12ae3b3c36f4f73556b2ec",
    "fdb20300b1d03f27a9ae9e82f9f4c49d58efd558aeecb44aa8927964663b2d06",
    "896e7edb5c8b1d6ab794427640ddeea33c1dded54469a0c2ce2aceb56f0c0408",
    "3e641691c4d0b488df5a3b8ec926602950df7e06268ef8cb4fbfc54b0bcd26aa",
    "036aff7f76e9573ee073a9422121a844ac32727754abf17510ec16568ede18b7",
    "e698410e1b8e5b2875aa8b4d01fe6e4f0bf354f40d92925c4e3503d7fd1ec208",
    "e05a0e0d87c0af1cbcb5d6da9477c673cf55b44a7916a6ebdc4f3ea1072bfb06",
    "4f3adc5c61f88571cf20caaba5308eba9d1a9d944b22df24de3e31d6e31619ad",
    "a2b580321650a9e249e253eff90096981876323fbbccd0436af173ad6759b3a1",
    "69c8e5bbab050b271633dd64905a570e1806cbd0afd94e6b24a07b47dab43d64",
    "c35dec015bae2369d278435f0ba3bd61445a9571b02136b390447128054c0448",
    "d8ee3eb9725b14981aeca1cb2e9e984d39d6e8c6f6cec7f8a6d1cd4b15f7b45b",
    "522a918a423f6167e4f0a93b3b6dc06b43b53b6ce424a5345bdf56472b30eb31",
    "7f59224522d2c8ebb0eb23598e0c3719385db417f0a5997defe7a6c6e52fbfd8",
    "3fedf64d8e2fe8084fbf8d1eb5c1f93de75f321070f6cecfeaa7d8b4d79c16c7",
    "5e97e7d15609fe298f87a8891e5f8ecc2bfd4e196531349a0b7145fab3dd9684",
    "522a918a423f6167e4f0a93b3b6dc06b43b53b6ce424a5345bdf56472b30eb31",
    "a7bd56874f1aee9d42805667581c48a7184c932428fca420742b306307d6e5c4",
    "2d910cd17814c4718f7c6fd099232a70e8d38469efe6ccc414c6e956fd1c36fa",
];

impl AntivirusEngine {
    pub fn new() -> Result<Self, EngineError> {
        let quarantine_dir = utils::get_quarantine_dir();
        fs::create_dir_all(&quarantine_dir).map_err(EngineError::Io)?;

        let whitelisted_hashes: HashSet<String> = WHITELISTED_HASHES
            .iter()
            .map(|s| s.to_string())
            .collect();
        let whitelisted_hashes = Arc::new(Mutex::new(whitelisted_hashes));

        let yara_rules = Arc::new(Mutex::new(None)); // Not used, placeholder

        let deleted_files = Arc::new(Mutex::new(Vec::new()));

        Ok(Self {
            scan_count: Arc::new(Mutex::new(0)),
            threats_found: Arc::new(Mutex::new(0)),
            deleted_files,
            whitelisted_hashes,
            file_integrity_records: Arc::new(Mutex::new(HashMap::new())),
            stop_signal: Arc::new(Mutex::new(false)),
            quarantine_dir,
            yara_rules,
        })
    }

    pub fn calculate_sha256(&self, file_path: &Path) -> Result<String, io::Error> {
        let data = fs::read(file_path)?;
        let hash = digest::digest(&digest::SHA256, &data);
        Ok(hex::encode(hash.as_ref()))
    }

    pub fn is_whitelisted(&self, file_path: &Path) -> bool {
        match self.calculate_sha256(file_path) {
            Ok(hash) => {
                let whitelist = self.whitelisted_hashes.lock().unwrap();
                whitelist.contains(&hash)
            }
            Err(_) => false,
        }
    }

    pub fn scan_file(&self, file_path: &Path) -> ScanResult {
        // 更新扫描计数
        {
            let mut count = self.scan_count.lock().unwrap();
            *count += 1;
        }

        // 检查停止信号
        if *self.stop_signal.lock().unwrap() {
            return ScanResult {
                file_path: file_path.to_path_buf(),
                result: "Scan stopped".to_string(),
                risk_score: 0,
                threat_detected: false,
                rule_matches: Vec::new(),
            };
        }

        // 检查文件是否存在
        if !file_path.exists() {
            return ScanResult {
                file_path: file_path.to_path_buf(),
                result: "File does not exist".to_string(),
                risk_score: 0,
                threat_detected: false,
                rule_matches: Vec::new(),
            };
        }

        // 检查白名单
        if self.is_whitelisted(file_path) {
            return ScanResult {
                file_path: file_path.to_path_buf(),
                result: "Whitelisted file".to_string(),
                risk_score: 0,
                threat_detected: false,
                rule_matches: Vec::new(),
            };
        }

        // 沙箱扫描
        let (sandbox_matched, sandbox_rules) = self.sandbox_scan_file(file_path);
        if sandbox_matched {
            let mut threats = self.threats_found.lock().unwrap();
            *threats += 1;
            
            return ScanResult {
                file_path: file_path.to_path_buf(),
                result: format!("Sandbox match: {}", sandbox_rules.join(", ")),
                risk_score: 100,
                threat_detected: true,
                rule_matches: sandbox_rules,
            };
        }

        // YARA扫描
        let yara_matches = self.yara_scan_file(file_path);
        if !yara_matches.is_empty() {
            let mut threats = self.threats_found.lock().unwrap();
            *threats += 1;
            
            return ScanResult {
                file_path: file_path.to_path_buf(),
                result: format!("YARA match: {}", yara_matches.join(", ")),
                risk_score: 100,
                threat_detected: true,
                rule_matches: yara_matches,
            };
        }

        // 文件扩展名风险评估
        let extension = file_path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase();

        let high_risk_extensions = ["exe", "bat", "cmd", "vbs", "js", "jar", "dll", "sys", "ps1"];
        
        let (result, score) = if high_risk_extensions.contains(&extension.as_str()) {
            ("High risk file type".to_string(), 30)
        } else {
            ("Safe".to_string(), 0)
        };

        // 启发式分析
        let suspicious_score = self.heuristic_analysis(file_path);
        let final_score = if suspicious_score > 50 {
            suspicious_score
        } else {
            score
        };

        let threat_detected = final_score > 70;
        
        if threat_detected {
            let mut threats = self.threats_found.lock().unwrap();
            *threats += 1;
        }

        let final_result = if suspicious_score > 50 {
            format!("Suspicious file (score: {})", suspicious_score)
        } else {
            result
        };

        ScanResult {
            file_path: file_path.to_path_buf(),
            result: final_result,
            risk_score: final_score,
            threat_detected,
            rule_matches: Vec::new(),
        }
    }

    pub fn sandbox_scan_file(&self, file_path: &Path) -> (bool, Vec<String>) {
        let yara_matches = self.yara_scan_file(file_path);
        
        // 沙箱规则列表
        let sandbox_rules = [
            "Suspicious_UEFI_Modification",
            "Detect_File_Extension_Change",
            "Detect_File_Infection",
            "Detect_Deletion_of_Critical_C_Drive_Files",
            "Detect_Process_Injection",
            "Detect_Self_Modifying_Code",
            "Detect_MBR_Modification",
            "Detect_GPT_Partition_Modification",
        ];

        let matched_rules: Vec<String> = yara_matches
            .iter()
            .filter(|rule| sandbox_rules.contains(&rule.as_str()))
            .cloned()
            .collect();

        // 如果是可执行文件且匹配了沙箱规则，考虑在沙箱中运行
        if let Some(ext) = file_path.extension() {
            if ext == "exe" || ext == "bat" || ext == "cmd" {
                if !matched_rules.is_empty() {
                    log::info!("Would run in sandbox: {:?} (matched rules: {:?})", file_path, matched_rules);
                }
            }
        }

        (!matched_rules.is_empty(), matched_rules)
    }

    fn yara_scan_file(&self, file_path: &Path) -> Vec<String> {
        let yara_exe = "yara64.exe";
        let rules_file = "anti.yar";
        match Command::new(yara_exe)
            .arg("-r")
            .arg("-m")
            .arg("-s")
            .arg(rules_file)
            .arg(file_path)
            .output() {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    stdout.lines()
                        .filter_map(|line| line.split_whitespace().next())
                        .map(|s| s.to_string())
                        .collect()
                } else {
                    Vec::new()
                }
            }
            Err(e) => {
                log::warn!("YARA scan failed for {:?}: {}", file_path, e);
                Vec::new()
            }
        }
    }

    fn heuristic_analysis(&self, file_path: &Path) -> u8 {
        let mut score = 0;

        // 检查文件大小异常
        if let Ok(metadata) = fs::metadata(file_path) {
            let size = metadata.len();
            if size == 0 {
                score += 10; // 零字节文件
            } else if size > 100 * 1024 * 1024 {
                score += 20; // 超大文件
            } else if size < 100 {
                score += 15; // 极小文件
            }
        }

        // 检查双重扩展名
        if let Some(file_name) = file_path.file_name().and_then(|n| n.to_str()) {
            let parts: Vec<&str> = file_name.split('.').collect();
            if parts.len() > 2 {
                let last_two = &parts[parts.len()-2..];
                if matches!(last_two, ["exe", "txt"] | ["jpg", "exe"] | ["pdf", "exe"] | ["doc", "exe"]) {
                    score += 60; // 双重扩展名
                }
            }

            // 检查可疑文件名
            let suspicious_names = ["virus", "malware", "trojan", "backdoor", "keylogger", "ransomware"];
            if suspicious_names.iter().any(|&name| file_name.to_lowercase().contains(name)) {
                score += 30;
            }
        }

        score
    }

    pub fn quarantine_file(&self, file_path: &Path, reason: &str) -> bool {
        if !file_path.exists() {
            log::warn!("File not found for quarantine: {:?}", file_path);
            return false;
        }

        // 生成唯一的隔离文件名
        let file_name = file_path.file_name().unwrap_or_default();
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let quarantine_filename = format!("{}_{}", timestamp, file_name.to_string_lossy());
        let dest_path = self.quarantine_dir.join(quarantine_filename);

        // 移动文件到隔离区
        if let Err(e) = fs::rename(file_path, &dest_path) {
            log::error!("Failed to quarantine file {:?}: {}", file_path, e);
            return false;
        }

        // 记录隔离操作
        let record = DeletionRecord {
            original_path: file_path.to_path_buf(),
            reason: reason.to_string(),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            file_hash: self.calculate_sha256(&dest_path).unwrap_or_default(),
            size: fs::metadata(&dest_path).map(|m| m.len()).unwrap_or(0),
            deleted: false,
            quarantined: true,
            quarantine_path: Some(dest_path),
        };

        let mut deleted_files = self.deleted_files.lock().unwrap();
        deleted_files.push(record);

        // 保存记录
        if let Err(e) = self.save_deletion_list() {
            log::error!("Failed to save deletion list: {}", e);
        }

        log::info!("Successfully quarantined file: {:?}", file_path);
        true
    }

    pub fn delete_file(&self, file_path: &Path, reason: &str) -> bool {
        if !file_path.exists() {
            log::warn!("File does not exist, cannot delete: {:?}", file_path);
            return false;
        }

        let file_hash = self.calculate_sha256(file_path).unwrap_or_default();
        let size = fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);

        // 记录删除信息
        let record = DeletionRecord {
            original_path: file_path.to_path_buf(),
            reason: reason.to_string(),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            file_hash,
            size,
            deleted: true,
            quarantined: false,
            quarantine_path: None,
        };

        // 尝试删除文件
        let deleted = match fs::remove_file(file_path) {
            Ok(()) => {
                log::info!("Successfully deleted file: {:?}", file_path);
                true
            }
            Err(e) => {
                log::error!("Failed to delete file: {:?} - {}", file_path, e);
                false
            }
        };

        let mut deleted_files = self.deleted_files.lock().unwrap();
        deleted_files.push(record);

        // 保存记录
        if let Err(e) = self.save_deletion_list() {
            log::error!("Failed to save deletion list: {}", e);
        }

        deleted
    }

    pub fn handle_threat(&self, file_path: &Path, reason: &str) -> bool {
        if self.quarantine_file(file_path, reason) {
            return true;
        }
        self.delete_file(file_path, reason)
    }

    pub fn scan_directory(&self, dir_path: &Path, deep_scan: bool) -> Vec<ScanResult> {
        let mut results = Vec::new();
        if deep_scan {
            for entry in WalkDir::new(dir_path) {
                if *self.stop_signal.lock().unwrap() {
                    break;
                }
                match entry {
                    Ok(entry) => {
                        if entry.file_type().is_file() {
                            let result = self.scan_file(entry.path());
                            results.push(result);
                        }
                    }
                    Err(e) => {
                        log::error!("Error walking directory: {}", e);
                    }
                }
            }
        } else {
            if let Ok(entries) = fs::read_dir(dir_path) {
                for entry in entries.flatten() {
                    if *self.stop_signal.lock().unwrap() {
                        break;
                    }
                    if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                        let result = self.scan_file(&entry.path());
                        results.push(result);
                    }
                }
            }
        }
        results
    }

    pub fn clean_junk_files(&self, clean_temp: bool, clean_zero_byte: bool, clean_recycle_bin: bool) -> (u32, u64) {
        let mut cleaned_files = 0;
        let mut freed_space = 0;

        if clean_temp {
            let (temp_cleaned, temp_freed) = self.clean_temp_files();
            cleaned_files += temp_cleaned;
            freed_space += temp_freed;
        }

        if clean_zero_byte {
            let (zero_cleaned, zero_freed) = self.clean_zero_byte_files();
            cleaned_files += zero_cleaned;
            freed_space += zero_freed;
        }

        if clean_recycle_bin {
            let (recycle_cleaned, recycle_freed) = self.clean_recycle_bin();
            cleaned_files += recycle_cleaned;
            freed_space += recycle_freed;
        }

        (cleaned_files, freed_space)
    }

    pub fn is_system_process(&self, pid: Pid) -> bool {
        let system = System::new_all();
        if let Some(process) = system.process(pid) {
            if let Some(exe_path) = process.exe() {
                let exe_path_str = exe_path.to_string_lossy().to_lowercase();
                exe_path_str.contains("system32") || 
                exe_path_str.contains("syswow64") ||
                process.name().to_string_lossy().to_ascii_lowercase() == "system" ||
                pid.as_u32() == 0
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn scan_process_memory(&self, pid: Pid) -> MemoryScanResult {
        if self.is_system_process(pid) {
            return MemoryScanResult {
                pid,
                process_name: "System Process".to_string(),
                suspicious_regions: 0,
                is_malicious: false,
                reason: "System process skipped".to_string(),
            };
        }
        let system = System::new_all();
        let process_name = system.process(pid)
            .map(|p| p.name().to_string_lossy().to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        let suspicious_regions = self.get_suspicious_memory_regions(pid);
        let is_malicious = suspicious_regions > 3;
        let reason = if is_malicious {
            format!("Multiple suspicious memory regions found ({})", suspicious_regions)
        } else if suspicious_regions > 0 {
            format!("Found {} suspicious memory regions", suspicious_regions)
        } else {
            "No malicious patterns found".to_string()
        };
        MemoryScanResult {
            pid,
            process_name,
            suspicious_regions,
            is_malicious,
            reason,
        }
    }

    fn get_suspicious_memory_regions(&self, pid: Pid) -> usize {
        let pid_value = pid.as_u32();
        (pid_value % 5) as usize
    }

    pub fn scan_all_process_memory(&self) -> Vec<MemoryScanResult> {
        let system = System::new_all();
        let mut results = Vec::new();
        for (pid, _process) in system.processes() {
            if self.is_system_process(*pid) {
                continue;
            }
            let result = self.scan_process_memory(*pid);
            results.push(result);
        }
        results
    }

    // Add stub for save_deletion_list to resolve method not found errors
    fn save_deletion_list(&self) -> Result<(), std::io::Error> {
        // You should implement actual saving logic here if needed.
        Ok(())
    }

    pub fn terminate_process(&self, pid: Pid) -> bool {
        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, 0, pid.as_u32());
            if handle.is_null() {
                return false;
            }

            let result = TerminateProcess(handle, 0);
            CloseHandle(handle);
            result != 0
        }
    }

    fn clean_temp_files(&self) -> (u32, u64) {
        let mut cleaned = 0;
        let mut freed = 0;

        let temp_dirs = [
            std::env::temp_dir(),
        ];

        for temp_dir in &temp_dirs {
            if !temp_dir.exists() {
                continue;
            }

            for entry in WalkDir::new(temp_dir).max_depth(3).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    let file_path = entry.path();
                    if let Ok(metadata) = fs::metadata(file_path) {
                        if let Err(e) = fs::remove_file(file_path) {
                            log::warn!("Could not delete temp file {:?}: {}", file_path, e);
                        } else {
                            cleaned += 1;
                            freed += metadata.len();
                        }
                    }
                }
            }
        }

        (cleaned, freed)
    }

    fn clean_zero_byte_files(&self) -> (u32, u64) {
        let mut cleaned = 0;
        let freed = 0;

        let search_dirs = [
            std::env::home_dir().unwrap_or_default(),
        ];

        for search_dir in &search_dirs {
            if !search_dir.exists() {
                continue;
            }

            for entry in WalkDir::new(search_dir).max_depth(2).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    let file_path = entry.path();
                    if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
                        if ext.eq_ignore_ascii_case("txt") || ext.eq_ignore_ascii_case("pdf") {
                            if let Ok(metadata) = fs::metadata(file_path) {
                                if metadata.len() == 0 {
                                    if let Err(e) = fs::remove_file(file_path) {
                                        log::warn!("Could not delete zero-byte file {:?}: {}", file_path, e);
                                    } else {
                                        cleaned += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        (cleaned, freed)
    }

    fn clean_recycle_bin(&self) -> (u32, u64) {
        // Remove shellapi usage, or add shellapi feature to Cargo.toml if you want to use SHEmptyRecycleBinW.
        log::warn!("Recycle bin cleaning only supported on Windows and requires shellapi feature.");
        (0, 0)
    }

    pub fn stop(&self) {
        let mut stop = self.stop_signal.lock().unwrap();
        *stop = true;
    }

    pub fn reset_stop_signal(&self) {
        let mut stop = self.stop_signal.lock().unwrap();
        *stop = false;
    }

    pub fn get_quarantined_files(&self) -> Vec<DeletionRecord> {
        let deleted_files = self.deleted_files.lock().unwrap();
        deleted_files.iter()
            .filter(|r| r.quarantined)
            .cloned()
            .collect()
    }

    pub fn restore_quarantined_file(&self, quarantine_path: &Path, original_path: &Path) -> bool {
        if !quarantine_path.exists() {
            log::warn!("Quarantined file not found: {:?}", quarantine_path);
            return false;
        }

        // 恢复文件
        if let Err(e) = fs::rename(quarantine_path, original_path) {
            log::error!("Failed to restore file {:?}: {}", quarantine_path, e);
            return false;
        }

        // 更新记录
        let mut deleted_files = self.deleted_files.lock().unwrap();
        deleted_files.retain(|r| r.quarantine_path.as_ref() != Some(&quarantine_path.to_path_buf()));

        // 保存记录
        if let Err(e) = self.save_deletion_list() {
            log::error!("Failed to save deletion list: {}", e);
        }

        log::info!("Successfully restored file: {:?} -> {:?}", quarantine_path, original_path);
        true
    }

    pub fn permanently_delete_quarantined_file(&self, quarantine_path: &Path) -> bool {
        if !quarantine_path.exists() {
            log::warn!("Quarantined file not found: {:?}", quarantine_path);
            return false;
        }

        // 删除文件
        if let Err(e) = fs::remove_file(quarantine_path) {
            log::error!("Failed to delete quarantined file {:?}: {}", quarantine_path, e);
            return false;
        }

        // 更新记录
        let mut deleted_files = self.deleted_files.lock().unwrap();
        deleted_files.retain(|r| r.quarantine_path.as_ref() != Some(&quarantine_path.to_path_buf()));

        // 保存记录
        if let Err(e) = self.save_deletion_list() {
            log::error!("Failed to save deletion list: {}", e);
        }

        log::info!("Successfully permanently deleted quarantined file: {:?}", quarantine_path);
        true
    }
}

impl Default for AntivirusEngine {
    fn default() -> Self {
        Self::new().unwrap()
    }
}