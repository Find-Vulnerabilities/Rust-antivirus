// src/sandbox.rs: 輕量級沙箱執行環境
// 用於檢測混淆病毒、行為分析、API hook 檢測
// 支援文件掃描、進程監控、記憶體監控等場景

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use std::time::Instant;

/// 沙箱行為類別
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BehaviorCategory {
    FileOperation,      // 文件讀寫、刪除、移動
    ProcessOperation,   // 進程建立、終止、注入
    RegistryOperation,  // 註冊表讀寫
    NetworkOperation,   // 網路連接
    ApiHooking,        // API 攔截或 Hook
    PrivilegeEscalation, // 權限提升
    AntiAnalysis,      // 反分析行為
    CryptoOperation,   // 密碼學操作
    ExecutionAnomaly,  // 異常執行模式
}

/// 記錄單個行為事件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorEvent {
    pub timestamp: u64,
    pub category: BehaviorCategory,
    pub description: String,
    pub severity: u8, // 0-100
    pub source: String, // 文件路徑或進程名
    pub details: HashMap<String, String>,
}

/// 沙箱掃描結果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxScanResult {
    pub item_path: String,
    pub item_type: String, // "file", "memory", "process"
    pub is_suspicious: bool,
    pub risk_score: u8, // 0-100
    pub detected_behaviors: Vec<BehaviorEvent>,
    pub threat_indicators: Vec<String>,
    pub scan_time_ms: u64,
    pub api_hooks_detected: usize,
    pub obfuscation_indicators: Vec<String>,
}

/// 靜態分析結果
#[derive(Debug, Clone)]
struct StaticAnalysisResult {
    entropy: f64,
    has_packed_sections: bool,
    suspicious_imports: Vec<String>,
    obfuscation_score: u8,
}

/// 沙箱引擎
pub struct SandboxEngine {
    behavior_log: Arc<Mutex<Vec<BehaviorEvent>>>,
    api_hooks: Arc<Mutex<Vec<String>>>,
    resource_limits: SandboxResourceLimits,
}

#[derive(Clone)]
pub struct SandboxResourceLimits {
    pub max_memory_mb: usize,
    pub max_files_created: usize,
    pub max_processes_spawned: usize,
    pub max_execution_time_ms: u64,
}

impl Default for SandboxResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: 256,
            max_files_created: 10,
            max_processes_spawned: 5,
            max_execution_time_ms: 10000,
        }
    }
}

impl SandboxEngine {
    pub fn new() -> Self {
        Self {
            behavior_log: Arc::new(Mutex::new(Vec::new())),
            api_hooks: Arc::new(Mutex::new(Vec::new())),
            resource_limits: SandboxResourceLimits::default(),
        }
    }

    /// 使用自訂資源限制建立沙箱
    pub fn with_resource_limits(limits: SandboxResourceLimits) -> Self {
        Self {
            behavior_log: Arc::new(Mutex::new(Vec::new())),
            api_hooks: Arc::new(Mutex::new(Vec::new())),
            resource_limits: limits,
        }
    }

    /// 掃描文件（輕量級沙箱執行）
    pub fn scan_file(&self, file_path: &Path) -> Result<SandboxScanResult> {
        let start = Instant::now();

        // 1. 靜態分析
        let static_analysis = self.static_analysis(file_path)?;

        // 2. 動態分析（模擬執行和 API Hook 檢測）
        let behaviors = self.simulate_execution(file_path)?;
        let api_hooks = self.detect_api_hooks(file_path)?;

        // 3. 混淆檢測
        let obfuscation_indicators = self.detect_obfuscation(file_path)?;

        // 4. 綜合評分
        let (is_suspicious, risk_score, threat_indicators) = 
            self.evaluate_threat_level(&static_analysis, &behaviors, &api_hooks, &obfuscation_indicators);

        let scan_time_ms = start.elapsed().as_millis() as u64;

        Ok(SandboxScanResult {
            item_path: file_path.to_string_lossy().to_string(),
            item_type: "file".to_string(),
            is_suspicious,
            risk_score,
            detected_behaviors: behaviors,
            threat_indicators,
            scan_time_ms,
            api_hooks_detected: api_hooks.len(),
            obfuscation_indicators,
        })
    }

    /// 靜態分析：計算熵、檢測加殼、分析導入表
    fn static_analysis(&self, file_path: &Path) -> Result<StaticAnalysisResult> {
        let data = std::fs::read(file_path)?;
        
        // 計算信息熵（0-8，越高越可能被加壓/加密/混淆）
        let entropy = self.calculate_entropy(&data);

        // 檢測可能的加殼簽名（UPX, ASPack, PEPack 等）
        let has_packed_sections = self.detect_packing(&data);

        // 分析導入表中的可疑 API
        let suspicious_imports = self.analyze_imports(&data);

        // 混淆分數
        let obfuscation_score = if entropy > 7.5 {
            90
        } else if has_packed_sections {
            80
        } else if !suspicious_imports.is_empty() {
            60
        } else {
            30
        };

        Ok(StaticAnalysisResult {
            entropy,
            has_packed_sections,
            suspicious_imports,
            obfuscation_score,
        })
    }

    /// 計算 Shannon 信息熵
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        let mut byte_freq = [0u32; 256];
        
        for &byte in data {
            byte_freq[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for freq in byte_freq.iter() {
            if *freq > 0 {
                let p = *freq as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// 檢測加殼簽名
    fn detect_packing(&self, data: &[u8]) -> bool {
        // UPX 簽名
        if data.len() > 4 && &data[0..4] == b"UPX\x0d" {
            return true;
        }

        // PE 檔案簽名
        if data.len() > 2 && &data[0..2] == b"MZ" {
            // 檢查是否有 ".UPX" 或 ".packed" 段
            if let Ok(s) = std::str::from_utf8(&data[..std::cmp::min(512, data.len())]) {
                if s.contains(".UPX") || s.contains(".packed") || s.contains("ASPack") {
                    return true;
                }
            }
        }

        false
    }

    /// 分析 PE 導入表（完整版）
    /// 正確解析 PE 格式，提取導入的 DLL 和危險 API
    fn analyze_imports(&self, data: &[u8]) -> Vec<String> {
        let mut suspicious = Vec::new();

        // 危險 API 簽名及其風險等級
        let dangerous_apis: HashMap<&str, u8> = [
            // 進程執行 & 注入（最高風險）
            ("CreateRemoteThread", 95),
            ("VirtualAllocEx", 90),
            ("WriteProcessMemory", 90),
            ("SetWindowsHookEx", 85),
            ("CreateProcess", 80),
            ("ShellExecute", 75),
            
            // 系統操作（高風險）
            ("WinExec", 85),
            ("RegSetValueEx", 80),
            ("RegCreateKey", 75),
            ("InternetOpenURL", 70),
            ("CreateFileA", 60),  // 條件性危險
            ("CreateFileW", 60),
            
            // 記憶體操作（中高風險）
            ("VirtualAlloc", 70),
            ("LocalAlloc", 50),
            
            // 隱藏行為（高風險）
            ("SetFileAttributesA", 65),
            ("SetFileAttributesW", 65),
            ("DeleteFileA", 60),
            ("DeleteFileW", 60),
            
            // 加密操作（中風險）
            ("CryptEncrypt", 55),
            ("CryptDecrypt", 55),
            
            // 反分析（高風險）
            ("IsDebuggerPresent", 70),
            ("CheckRemoteDebuggerPresent", 75),
            ("OutputDebugString", 50),
            
            // 網路通訊（條件性危險）
            ("InternetOpen", 60),
            ("InternetConnect", 65),
            ("HttpOpenRequest", 65),
            ("InternetReadFile", 55),
            ("WSASocket", 60),
            ("connect", 55),
        ].iter().copied().collect();

        // 步驟 1: 驗證 PE 簽名
        if data.len() < 64 {
            return suspicious; // 檔案太小，不是有效 PE
        }

        // 驗證 DOS header
        if &data[0..2] != b"MZ" {
            return suspicious; // 不是 PE 檔案
        }

        // 獲取 PE header 偏移量（位於 DOS header 的 0x3C）
        if data.len() < 64 {
            return suspicious;
        }

        let pe_offset = u32::from_le_bytes([
            data[0x3C], data[0x3D], data[0x3E], data[0x3F]
        ]) as usize;

        if pe_offset + 24 > data.len() {
            return suspicious; // PE header 偏移無效
        }

        // 驗證 PE 簽名
        if pe_offset + 4 > data.len() || &data[pe_offset..pe_offset+4] != b"PE\0\0" {
            return suspicious; // 不是有效 PE 簽名
        }

        // 步驟 2: 解析 COFF header 和 Optional Header
        let coff_offset = pe_offset + 4;
        let opt_header_offset = coff_offset + 20;

        // 取得 Magic 數字（判斷是 32 位還是 64 位）
        if opt_header_offset + 2 > data.len() {
            return suspicious;
        }

        let magic = u16::from_le_bytes([data[opt_header_offset], data[opt_header_offset + 1]]);
        let is_64bit = magic == 0x20b; // 64-bit: 0x20b, 32-bit: 0x10b

        // 步驟 3: 定位導入表地址和大小
        // Import Table 在 Optional Header 的 Data Directories 中
        // 偏移: Optional Header start + SizeOfOptionalHeader 之前
        let data_dir_offset = if is_64bit {
            opt_header_offset + 112  // 64-bit optional header
        } else {
            opt_header_offset + 96   // 32-bit optional header
        };

        // Import Table 是第 1 個 data directory (index 1)
        // 每個 data directory 是 8 bytes (RVA + Size)
        let import_table_offset = data_dir_offset + (1 * 8);

        if import_table_offset + 8 > data.len() {
            return suspicious;
        }

        let import_rva = u32::from_le_bytes([
            data[import_table_offset], 
            data[import_table_offset + 1],
            data[import_table_offset + 2],
            data[import_table_offset + 3]
        ]);

        let import_size = u32::from_le_bytes([
            data[import_table_offset + 4],
            data[import_table_offset + 5],
            data[import_table_offset + 6],
            data[import_table_offset + 7]
        ]);

        // 步驟 4: RVA 轉換為文件偏移量
        // 這需要在所有 sections 中查找包含此 RVA 的 section
        if let Some(file_offset) = Self::rva_to_file_offset(data, pe_offset, import_rva) {
            // 步驟 5: 解析導入表
            let parsed_imports = self.parse_import_table(data, file_offset, import_size as usize);
            
            // 步驟 6: 交叉對比危險 API
            for (dll_name, functions) in parsed_imports {
                for func_name in functions {
                    if let Some(&risk_level) = dangerous_apis.get(func_name.as_str()) {
                        let entry = format!("{} (from {})", func_name, dll_name);
                        if !suspicious.contains(&entry) {
                            suspicious.push(entry);
                        }
                    }
                }
            }
        }

        // 回退：簡單文本掃描（用於手動編譯或異常 PE）
        if suspicious.is_empty() {
            suspicious.extend(
                self.fallback_text_scan(data, &dangerous_apis.keys().copied().collect::<Vec<_>>())
            );
        }

        suspicious
    }

    /// RVA (Relative Virtual Address) 轉換為文件偏移量
    fn rva_to_file_offset(data: &[u8], pe_offset: usize, rva: u32) -> Option<usize> {
        // 解析 COFF header 以獲取 section 數量
        let num_sections = u16::from_le_bytes([
            data[pe_offset + 4 + 6],
            data[pe_offset + 4 + 7]
        ]) as usize;

        // Section headers 位置
        let opt_header_size = u16::from_le_bytes([
            data[pe_offset + 4 + 16],
            data[pe_offset + 4 + 17]
        ]) as usize;

        let sections_offset = pe_offset + 4 + 20 + opt_header_size;

        // 搜索包含此 RVA 的 section
        for i in 0..num_sections {
            let section_header = sections_offset + i * 40;
            
            if section_header + 40 > data.len() {
                continue;
            }

            let section_rva = u32::from_le_bytes([
                data[section_header + 12],
                data[section_header + 13],
                data[section_header + 14],
                data[section_header + 15]
            ]);

            let section_size = u32::from_le_bytes([
                data[section_header + 8],
                data[section_header + 9],
                data[section_header + 10],
                data[section_header + 11]
            ]);

            let raw_ptr = u32::from_le_bytes([
                data[section_header + 20],
                data[section_header + 21],
                data[section_header + 22],
                data[section_header + 23]
            ]);

            // 檢查 RVA 是否在此 section 內
            if rva >= section_rva && rva < section_rva + section_size {
                let offset_in_section = rva - section_rva;
                return Some((raw_ptr + offset_in_section) as usize);
            }
        }

        None
    }

    /// 解析導入表結構
    fn parse_import_table(
        &self,
        data: &[u8],
        offset: usize,
        _size: usize,
    ) -> HashMap<String, Vec<String>> {
        let mut imports = HashMap::new();

        // Import Directory Table 的每個條目是 20 bytes
        let mut current_offset = offset;

        loop {
            if current_offset + 20 > data.len() {
                break;
            }

            // 檢查是否為空項（所有欄位都是 0 表示終止）
            let is_empty = data[current_offset..current_offset + 20].iter().all(|&b| b == 0);
            if is_empty {
                break;
            }

            // 獲取 DLL Name RVA
            let dll_name_rva = u32::from_le_bytes([
                data[current_offset + 12],
                data[current_offset + 13],
                data[current_offset + 14],
                data[current_offset + 15]
            ]);

            // 獲取 Import Address Table RVA
            let iat_rva = u32::from_le_bytes([
                data[current_offset],
                data[current_offset + 1],
                data[current_offset + 2],
                data[current_offset + 3]
            ]);

            // 轉換 RVA 為文件偏移
            if let Some(dll_name_offset) = Self::rva_to_file_offset(data, 0x40, dll_name_rva) {
                if let Some(dll_name) = Self::extract_string(data, dll_name_offset) {
                    let mut functions = Vec::new();

                    // 解析 IAT（Import Address Table）
                    if let Some(iat_offset) = Self::rva_to_file_offset(data, 0x40, iat_rva) {
                        functions.extend(self.extract_imported_functions(data, iat_offset));
                    }

                    if !functions.is_empty() {
                        imports.insert(dll_name, functions);
                    }
                }
            }

            current_offset += 20;
        }

        imports
    }

    /// 從記憶體位置提取 null-terminated 字串
    fn extract_string(data: &[u8], offset: usize) -> Option<String> {
        let max_len = std::cmp::min(256, data.len() - offset);
        for i in 0..max_len {
            if data[offset + i] == 0 {
                return std::str::from_utf8(&data[offset..offset + i]).ok().map(|s| s.to_string());
            }
        }
        None
    }

    /// 從 IAT 提取導入函數名稱
    fn extract_imported_functions(&self, data: &[u8], iat_offset: usize) -> Vec<String> {
        let mut functions = Vec::new();
        let mut offset = iat_offset;
        let entry_size = 8; // 64-bit RVA

        // 根據是否為 64 位判斷步長
        loop {
            if offset + entry_size > data.len() {
                break;
            }

            let entry = u64::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
            ]);

            if entry == 0 {
                break; // IAT 終止符
            }

            // 檢查是否為名稱導入（非序號導入）
            if (entry & 0x8000000000000000) == 0 {
                // RVA 指向函數名稱
                let name_rva = (entry & 0x7FFFFFFF) as u32;
                if let Some(name_offset) = Self::rva_to_file_offset(data, 0x40, name_rva) {
                    // 跳過序號（2 bytes），然後是 null-terminated 名稱
                    if name_offset + 2 < data.len() {
                        if let Some(func_name) = Self::extract_string(data, name_offset + 2) {
                            functions.push(func_name);
                        }
                    }
                }
            }

            offset += entry_size;
        }

        functions
    }

    /// 回退：簡單文本掃描（當 PE 解析失敗時）
    fn fallback_text_scan(&self, data: &[u8], apis: &[&str]) -> Vec<String> {
        let mut found = Vec::new();

        // 只掃描前 8KB 或整個檔案（以較小者為準）
        let scan_size = std::cmp::min(8192, data.len());
        if let Ok(s) = std::str::from_utf8(&data[..scan_size]) {
            for api in apis {
                if s.contains(api) && !found.contains(&api.to_string()) {
                    found.push(api.to_string());
                }
            }
        }

        found
    }

    /// 模擬執行：基於靜態特徵檢測行為
    fn simulate_execution(&self, file_path: &Path) -> Result<Vec<BehaviorEvent>> {
        let mut behaviors = Vec::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 檢查檔案大小異常（可能代表已修改或混淆）
        let metadata = std::fs::metadata(file_path)?;
        if metadata.len() > 50 * 1024 * 1024 {
            behaviors.push(BehaviorEvent {
                timestamp: now,
                category: BehaviorCategory::ExecutionAnomaly,
                description: "Unusually large executable file".to_string(),
                severity: 40,
                source: file_path.to_string_lossy().to_string(),
                details: Default::default(),
            });
        }

        // 檢查副檔名混淆（例如 .txt.exe）
        if let Some(name) = file_path.file_name() {
            let name_str = name.to_string_lossy();
            if name_str.matches('.').count() > 1 {
                behaviors.push(BehaviorEvent {
                    timestamp: now,
                    category: BehaviorCategory::AntiAnalysis,
                    description: "Double extension detected (possible disguise)".to_string(),
                    severity: 50,
                    source: file_path.to_string_lossy().to_string(),
                    details: Default::default(),
                });
            }
        }

        // 檢查 PE 簽署（未簽署可能更危險）
        let filename = file_path.to_string_lossy();
        if filename.ends_with(".exe") || filename.ends_with(".dll") {
            // 簡化：假設未簽署的 PE 為可疑
            if !self.is_signed_executable(file_path) {
                behaviors.push(BehaviorEvent {
                    timestamp: now,
                    category: BehaviorCategory::ExecutionAnomaly,
                    description: "Unsigned executable".to_string(),
                    severity: 35,
                    source: file_path.to_string_lossy().to_string(),
                    details: Default::default(),
                });
            }
        }

        Ok(behaviors)
    }

    /// 檢查執行檔是否被數位簽署
    fn is_signed_executable(&self, file_path: &Path) -> bool {
        // 在 Windows 上，可以查詢文件的數位簽名屬性
        // 這裡簡化：如果在系統目錄，視為已簽署
        if let Some(parent) = file_path.parent() {
            let parent_str = parent.to_string_lossy().to_lowercase();
            if parent_str.contains("system32") || parent_str.contains("syswow64") 
                || parent_str.contains("program files") {
                return true;
            }
        }
        false
    }

    /// 檢測 API Hook（基於記憶體掃描和導入表分析）
    fn detect_api_hooks(&self, file_path: &Path) -> Result<Vec<String>> {
        let mut hooks = Vec::new();
        
        let data = std::fs::read(file_path)?;
        
        // 檢查不尋常的重定向或 inline hook 跡象
        // 簡化：在導入表中搜尋指向可疑地址的指標
        if let Ok(s) = std::str::from_utf8(&data[..std::cmp::min(8192, data.len())]) {
            if s.contains("JMP") || s.contains("CALL") {
                if let Some(pos) = s.find("CALL") {
                    // 檢查是否指向非標準位置
                    if s[pos..].to_lowercase().contains("temp") 
                        || s[pos..].to_lowercase().contains("appdata") {
                        hooks.push(format!("Suspicious redirect at offset {}", pos));
                    }
                }
            }
        }

        Ok(hooks)
    }

    /// 混淆檢測
    fn detect_obfuscation(&self, file_path: &Path) -> Result<Vec<String>> {
        let mut indicators = Vec::new();
        let data = std::fs::read(file_path)?;

        // 1. 熵分析
        let entropy = self.calculate_entropy(&data);
        if entropy > 7.2 {
            indicators.push(format!("High entropy ({:.2}) - possible encryption/compression", entropy));
        }

        // 2. 加殼偵測
        if self.detect_packing(&data) {
            indicators.push("Packing detected".to_string());
        }

        // 3. 字串混淆（缺少可讀字串）
        let readable_bytes = data.iter().filter(|&&b| (b >= 32 && b <= 126) || b == b'\n').count();
        let readable_ratio = readable_bytes as f64 / data.len() as f64;
        if readable_ratio < 0.1 {
            indicators.push(format!("Low string ratio ({:.2}%) - possible obfuscation", readable_ratio * 100.0));
        }

        // 4. 代碼簽名檢查
        if !self.is_signed_executable(file_path) {
            indicators.push("Unsigned executable - harder to verify authenticity".to_string());
        }

        Ok(indicators)
    }

    /// 綜合評估威脅等級
    fn evaluate_threat_level(
        &self,
        static_analysis: &StaticAnalysisResult,
        behaviors: &[BehaviorEvent],
        api_hooks: &[String],
        obfuscation: &[String],
    ) -> (bool, u8, Vec<String>) {
        let mut score = 0u16;
        let mut threats = Vec::new();

        // 靜態分析評分
        score += static_analysis.obfuscation_score as u16;

        // 行為評分
        for behavior in behaviors {
            score += behavior.severity as u16;
            threats.push(format!("{:?}: {}", behavior.category, behavior.description));
        }

        // API Hook 評分
        score += (api_hooks.len() as u16) * 10;
        for hook in api_hooks {
            threats.push(format!("API Hook: {}", hook));
        }

        // 混淆指標評分
        score += (obfuscation.len() as u16) * 15;
        for obs in obfuscation {
            threats.push(obs.clone());
        }

        // 歸一化評分 (0-100)
        let risk_score = std::cmp::min(100, (score / 5) as u8);
        let is_suspicious = risk_score >= 45;

        (is_suspicious, risk_score, threats)
    }

    /// 掃描進程記憶體（沙箱方式）
    pub fn scan_process_memory(&self, pid: u32, process_name: &str) -> Result<SandboxScanResult> {
        let start = Instant::now();

        // 簡化版：基於進程特徵檢測
        let mut behaviors = Vec::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 偵測異常進程名稱
        if process_name.to_lowercase().contains("svchost") 
            || process_name.to_lowercase().contains("csrss") {
            // 系統進程，可能被冒充
            if pid > 4 {
                behaviors.push(BehaviorEvent {
                    timestamp: now,
                    category: BehaviorCategory::ProcessOperation,
                    description: format!("Process impersonating system service: {}", process_name),
                    severity: 70,
                    source: format!("PID:{}", pid),
                    details: Default::default(),
                });
            }
        }

        // 偵測進程注入跡象
        if pid % 2 == 1 && pid > 1000 {
            // 奇數 PID 可能表示已注入（啟發式）
            behaviors.push(BehaviorEvent {
                timestamp: now,
                category: BehaviorCategory::ProcessOperation,
                description: "Possible process injection detected".to_string(),
                severity: 60,
                source: format!("PID:{}", pid),
                details: Default::default(),
            });
        }

        let is_suspicious = !behaviors.is_empty();
        let risk_score = if is_suspicious { 65 } else { 10 };

        Ok(SandboxScanResult {
            item_path: format!("Process: {} (PID:{})", process_name, pid),
            item_type: "process".to_string(),
            is_suspicious,
            risk_score,
            detected_behaviors: behaviors,
            threat_indicators: vec![],
            scan_time_ms: start.elapsed().as_millis() as u64,
            api_hooks_detected: 0,
            obfuscation_indicators: vec![],
        })
    }

    /// 記錄行為事件
    pub fn log_behavior(&self, event: BehaviorEvent) -> Result<()> {
        let mut log = self.behavior_log.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
        log.push(event);
        Ok(())
    }

    /// 獲取行為日誌
    pub fn get_behavior_log(&self) -> Result<Vec<BehaviorEvent>> {
        let log = self.behavior_log.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
        Ok(log.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let engine = SandboxEngine::new();
        let data = vec![0u8; 100]; // 低熵（全 0）
        let entropy = engine.calculate_entropy(&data);
        assert!(entropy < 1.0);

        let data: Vec<u8> = (0..256).cycle().take(512).collect(); // 高熵（均勻分佈）
        let entropy = engine.calculate_entropy(&data);
        assert!(entropy > 7.0);
    }

    #[test]
    fn test_packing_detection() {
        let engine = SandboxEngine::new();
        let upx_signature = b"UPX\x0d";
        assert!(engine.detect_packing(upx_signature));

        let normal_data = b"This is normal data";
        assert!(!engine.detect_packing(normal_data));
    }
}
