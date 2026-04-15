// src/yara_integration_helpers.rs
// 輔助函數，用於在 engine.rs 中集成 YARA 掃描

use std::sync::Arc;
use crate::yara_engine::YaraEngine;
use std::path::Path;

/// 集成 YARA 掃描到現有引擎的幫助函數
/// 在 engine.rs 中使用此模塊進行增強掃描

pub struct YaraIntegrationHelper {
    engine: Arc<YaraEngine>,
}

impl YaraIntegrationHelper {
    /// 創建新的 YARA 集成助手
    pub fn new(rules_path: &str) -> Result<Self, String> {
        // 初始化 YARA
        YaraEngine::init()?;
        
        // 加載規則
        let engine = Arc::new(YaraEngine::with_rules(rules_path)?);
        
        Ok(YaraIntegrationHelper { engine })
    }

    /// 快速掃描文件（返回是否檢測到威脅）
    pub fn quick_scan_file(&self, file_path: &Path) -> Result<(bool, Vec<String>), String> {
        let data = std::fs::read(file_path)
            .map_err(|e| format!("Cannot read file: {}", e))?;
        
        // 限制掃描大小（最多 500MB）
        let scan_data = if data.len() > 500 * 1024 * 1024 {
            &data[..500 * 1024 * 1024]
        } else {
            &data
        };

        let result = self.engine.scan_mem(scan_data)?;
        let is_malicious = !result.matched_rules.is_empty();
        let rule_names: Vec<String> = result.matched_rules
            .iter()
            .map(|r| r.rule_name.clone())
            .collect();

        Ok((is_malicious, rule_names))
    }

    /// 掃描文件並返回詳細結果
    pub fn detailed_scan_file(&self, file_path: &Path) -> Result<ScanDetail, String> {
        let file_size = std::fs::metadata(file_path)
            .map_err(|e| format!("Cannot get metadata: {}", e))?
            .len();

        let (is_malicious, matched_rules) = self.quick_scan_file(file_path)?;

        Ok(ScanDetail {
            file_path: file_path.to_string_lossy().to_string(),
            file_size,
            is_malicious,
            matched_rules,
            confidence: if is_malicious { 95 } else { 0 },
        })
    }

    /// 批量掃描多個文件
    pub fn batch_scan_files(&self, file_paths: &[&Path]) -> Result<Vec<ScanDetail>, String> {
        let mut results = Vec::new();

        for file_path in file_paths {
            match self.detailed_scan_file(file_path) {
                Ok(detail) => results.push(detail),
                Err(e) => log::warn!("Error scanning {}: {}", file_path.display(), e),
            }
        }

        Ok(results)
    }

    /// 掃描記憶體緩衝區（用於進程記憶體）
    pub fn scan_memory_buffer(&self, buffer: &[u8]) -> Result<(bool, Vec<String>), String> {
        let result = self.engine.scan_mem(buffer)?;
        let is_malicious = !result.matched_rules.is_empty();
        let rule_names: Vec<String> = result.matched_rules
            .iter()
            .map(|r| r.rule_name.clone())
            .collect();

        Ok((is_malicious, rule_names))
    }
}

#[derive(Debug, Clone)]
pub struct ScanDetail {
    pub file_path: String,
    pub file_size: u64,
    pub is_malicious: bool,
    pub matched_rules: Vec<String>,
    pub confidence: u8,
}

/// 在 engine.rs 中的集成示例
/// 
/// 在 AntivirusEngine 中添加以下代碼：
/// 
/// ```rust
/// use crate::yara_integration_helpers::YaraIntegrationHelper;
/// 
/// pub struct AntivirusEngine {
///     // ... existing fields ...
///     yara_helper: Option<YaraIntegrationHelper>,
/// }
/// 
/// impl AntivirusEngine {
///     pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
///         // ... existing initialization ...
///         
///         // 初始化 YARA
///         let yara_helper = match YaraIntegrationHelper::new("Configuration/anti.yarac") {
///             Ok(helper) => {
///                 log::info!("YARA engine initialized successfully");
///                 Some(helper)
///             }
///             Err(e) => {
///                 log::warn!("YARA initialization failed: {}", e);
///                 None
///             }
///         };
///         
///         Ok(AntivirusEngine {
///             // ... existing fields ...
///             yara_helper,
///         })
///     }
///     
///     pub fn scan_file_enhanced(&self, file_path: &Path) -> ScanResult {
///         // 首先嘗試 YARA 掃描
///         if let Some(yara) = &self.yara_helper {
///             match yara.quick_scan_file(file_path) {
///                 Ok((is_malicious, rules)) => {
///                     if is_malicious {
///                         return ScanResult {
///                             file_path: file_path.to_path_buf(),
///                             result: format!("YARA threat detected: {}", rules.join(", ")),
///                             risk_score: 100,
///                             threat_detected: true,
///                             rule_matches: rules,
///                         };
///                     }
///                 }
///                 Err(e) => log::warn!("YARA scan error: {}", e),
///             }
///         }
///         
///         // 降級到現有掃描方法
///         self.scan_file(file_path)
///     }
/// }
/// ```

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yara_helper_creation() {
        // 測試 YARA 助手創建
        let result = YaraIntegrationHelper::new("Configuration/anti.yarac");
        match result {
            Ok(_) => println!("✓ YARA helper created successfully"),
            Err(e) => println!("✗ Failed to create YARA helper: {}", e),
        }
    }

    #[test]
    fn test_scan_detail() {
        let detail = ScanDetail {
            file_path: "test.exe".to_string(),
            file_size: 1024 * 1024,
            is_malicious: false,
            matched_rules: vec![],
            confidence: 0,
        };

        assert_eq!(detail.file_size, 1024 * 1024);
        assert!(!detail.is_malicious);
    }
}
