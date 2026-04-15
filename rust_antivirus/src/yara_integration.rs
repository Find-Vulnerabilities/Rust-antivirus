// src/yara_integration.rs: 全面的 YARA 整合層
// 提供文件掃描、記憶體掃描和隔離功能

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use crate::yara_engine::YaraEngine;

#[derive(Debug, Clone)]
pub struct ScanFile {
    pub path: PathBuf,
    pub size: u64,
    pub hash: String,
}

#[derive(Debug, Clone)]
pub struct ScanMemory {
    pub pid: u32,
    pub process_name: String,
    pub region: u64,
    pub size: u64,
}

/// YARA 掃描結果
#[derive(Debug, Clone)]
pub struct YaraFullScanResult {
    pub item_path: String,
    pub item_type: String, // "file" or "memory"
    pub matched_rules: Vec<String>,
    pub is_malicious: bool,
    pub confidence: u8,
    pub scan_time_ms: u64,
    pub quarantined: bool,
}

/// 文件掃描器
pub struct FileScanner {
    engine: Arc<YaraEngine>,
}

impl FileScanner {
    pub fn new(engine: Arc<YaraEngine>) -> Self {
        FileScanner { engine }
    }

    /// 掃描單個文件
    pub fn scan_file(&self, file_path: &Path) -> Result<YaraFullScanResult, String> {
        // 先檢查文件是否存在且可讀
        if !file_path.exists() {
            return Err(format!("File not found: {:?}", file_path));
        }

        let file_size = fs::metadata(file_path)
            .map_err(|e| format!("Cannot read file metadata: {}", e))?
            .len();

        // 如果文件過大（>500MB），只掃描前面部分
        let read_size = std::cmp::min(file_size as usize, 500 * 1024 * 1024);
        
        let file_data = fs::read(file_path)
            .map_err(|e| format!("Cannot read file: {}", e))?;

        // 使用 YARA 引擎掃描
        let scan_result = self.engine.scan_mem(&file_data[..read_size.min(file_data.len())])?;

        let is_malicious = !scan_result.matched_rules.is_empty();
        let confidence = if is_malicious { 90 } else { 0 };

        Ok(YaraFullScanResult {
            item_path: file_path.to_string_lossy().to_string(),
            item_type: "file".to_string(),
            matched_rules: scan_result.matched_rules
                .iter()
                .map(|r| r.rule_name.clone())
                .collect(),
            is_malicious,
            confidence,
            scan_time_ms: scan_result.scan_time_ms,
            quarantined: false,
        })
    }

    /// 遞迴掃描目錄
    pub fn scan_directory(&self, dir_path: &Path) -> Result<Vec<YaraFullScanResult>, String> {
        let mut results = Vec::new();

        for entry in walkdir::WalkDir::new(dir_path)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.path().is_file())
        {
            let path = entry.path();
            
            // 跳過系統文件和隱藏文件
            if self.should_skip_file(path) {
                continue;
            }

            match self.scan_file(path) {
                Ok(result) => results.push(result),
                Err(e) => log::warn!("Error scanning {}: {}", path.display(), e),
            }
        }

        Ok(results)
    }

    fn should_skip_file(&self, path: &Path) -> bool {
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            // 跳過系統和非可執行文件
            matches!(ext_str.as_str(), "sys" | "dll" | "drv" | "exe" | "lnk" | "tmp" | "~")
        } else {
            false
        }
    }
}

/// 記憶體掃描器
pub struct MemoryScanner {
    engine: Arc<YaraEngine>,
}

impl MemoryScanner {
    pub fn new(engine: Arc<YaraEngine>) -> Self {
        MemoryScanner { engine }
    }

    /// 掃描進程記憶體（Windows 特定）
    #[cfg(windows)]
    pub fn scan_process(&self, pid: u32, process_name: &str) -> Result<YaraFullScanResult, String> {
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::winnt::{PROCESS_VM_READ, PROCESS_QUERY_INFORMATION, MEM_COMMIT, PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE};
        use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
        use winapi::um::handleapi::CloseHandle;
        use winapi::shared::basetsd::SIZE_T;
        use winapi::um::winnt::MEMORY_BASIC_INFORMATION;
        use winapi::ctypes::c_void;
        use std::mem::size_of;

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
            if handle.is_null() {
                return Err(format!("Cannot open process {}", pid));
            }

            let mut current_addr: *mut c_void = std::ptr::null_mut();
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let mut matched_rules = Vec::new();
            let mut is_malicious = false;
            let mut total_scan_time = 0;

            while VirtualQueryEx(
                handle,
                current_addr,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>() as SIZE_T,
            ) != 0 {
                // Check if region is committed and readable
                if mbi.State == MEM_COMMIT {
                    let protect = mbi.Protect;
                    let is_readable = (protect & PAGE_READONLY) != 0 ||
                                      (protect & PAGE_READWRITE) != 0 ||
                                      (protect & PAGE_EXECUTE_READ) != 0 ||
                                      (protect & PAGE_EXECUTE_READWRITE) != 0;

                    if is_readable {
                        let mut buffer = vec![0u8; mbi.RegionSize as usize];
                        let mut bytes_read: SIZE_T = 0;

                        let read_result = ReadProcessMemory(
                            handle,
                            mbi.BaseAddress,
                            buffer.as_mut_ptr() as *mut c_void,
                            buffer.len() as SIZE_T,
                            &mut bytes_read as *mut SIZE_T,
                        );

                        if read_result != 0 && bytes_read > 0 {
                            buffer.truncate(bytes_read as usize);
                            if let Ok(scan_result) = self.engine.scan_mem(&buffer) {
                                if !scan_result.matched_rules.is_empty() {
                                    is_malicious = true;
                                    for rule in scan_result.matched_rules {
                                        matched_rules.push(rule.rule_name.clone());
                                    }
                                }
                                total_scan_time += scan_result.scan_time_ms;
                            }
                        }
                    }
                }
                
                let next_addr = (mbi.BaseAddress as usize + mbi.RegionSize as usize) as *mut c_void;
                if next_addr <= current_addr {
                    break;
                }
                current_addr = next_addr;
            }

            CloseHandle(handle);

            // 去重複規則名稱
            matched_rules.sort();
            matched_rules.dedup();

            let confidence = if is_malicious { 85 } else { 0 };

            Ok(YaraFullScanResult {
                item_path: format!("Process:{} ({})", pid, process_name),
                item_type: "memory".to_string(),
                matched_rules,
                is_malicious,
                confidence,
                scan_time_ms: total_scan_time,
                quarantined: false,
            })
        }
    }

    #[cfg(not(windows))]
    pub fn scan_process(&self, pid: u32, process_name: &str) -> Result<YaraFullScanResult, String> {
        Err("Process memory scanning only supported on Windows".to_string())
    }
}

/// 隔離管理器
pub struct QuarantineManager {
    quarantine_dir: PathBuf,
}

impl QuarantineManager {
    pub fn new(quarantine_dir: PathBuf) -> Result<Self, String> {
        if !quarantine_dir.exists() {
            fs::create_dir_all(&quarantine_dir)
                .map_err(|e| format!("Cannot create quarantine dir: {}", e))?;
        }
        Ok(QuarantineManager { quarantine_dir })
    }

    /// 隔離被感染文件
    pub fn quarantine_file(&self, source_path: &Path, threat_name: &str) -> Result<PathBuf, String> {
        let file_name = source_path.file_name()
            .ok_or("Cannot get file name")?
            .to_string_lossy();

        let quarantine_name = format!("{}.{}.quarantine", file_name, threat_name);
        let quarantine_path = self.quarantine_dir.join(&quarantine_name);

        fs::copy(source_path, &quarantine_path)
            .map_err(|e| format!("Cannot quarantine file: {}", e))?;

        // 刪除原始文件
        fs::remove_file(source_path)
            .map_err(|e| format!("Cannot remove original file: {}", e))?;

        log::info!("File quarantined: {} -> {}", source_path.display(), quarantine_path.display());
        Ok(quarantine_path)
    }

    /// 查看隔離文件
    pub fn list_quarantined(&self) -> Result<Vec<PathBuf>, String> {
        let mut files = Vec::new();
        for entry in fs::read_dir(&self.quarantine_dir)
            .map_err(|e| format!("Cannot read quarantine dir: {}", e))?
        {
            if let Ok(entry) = entry {
                files.push(entry.path());
            }
        }
        Ok(files)
    }

    /// 恢復隔離文件
    pub fn restore_file(&self, quarantine_path: &Path, restore_to: &Path) -> Result<(), String> {
        if !quarantine_path.exists() {
            return Err("Quarantine file not found".to_string());
        }

        fs::copy(quarantine_path, restore_to)
            .map_err(|e| format!("Cannot restore file: {}", e))?;

        fs::remove_file(quarantine_path)
            .map_err(|e| format!("Cannot remove quarantine file: {}", e))?;

        log::info!("File restored: {} -> {}", quarantine_path.display(), restore_to.display());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quarantine_manager() {
        let temp_dir = std::env::temp_dir().join("test_quarantine");
        if temp_dir.exists() {
            fs::remove_dir_all(&temp_dir).ok();
        }
        
        let manager = QuarantineManager::new(temp_dir.clone()).expect("Failed to create quarantine manager");
        assert!(temp_dir.exists());
        
        // 清理
        fs::remove_dir_all(&temp_dir).ok();
    }
}
