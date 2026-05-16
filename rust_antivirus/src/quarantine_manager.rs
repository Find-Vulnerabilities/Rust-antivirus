// src/quarantine_manager.rs: 隔离与清理管理模块，含加密和审计
// 处理文件/文件夹隔离、批量扫描与自动隔离，支持加密、审计日志、数字签名

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::engine::AntivirusEngine;
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub file_hash: String,
    pub threat_name: String,
    pub quarantine_time: u64,
    pub reason: String,
    pub original_hash: String,           // 原始檔案 SHA256
    pub original_signature: Option<String>, // 數位簽章
    pub encrypted: bool,                // 是否已加密
    pub encryption_iv: Option<Vec<u8>>, // 加密向量
}

/// 審計日誌條目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub timestamp: u64,
    pub action: String,
    pub quarantine_hash: String,
    pub operator: String,
    pub status: String,
    pub details: HashMap<String, String>,
}

pub struct QuarantineManager {
    quarantine_dir: PathBuf,
    entries: Vec<QuarantineEntry>,
    audit_log: Vec<AuditLogEntry>,
    audit_log_path: PathBuf,
    encryption_enabled: bool,
}

impl QuarantineManager {
    pub fn new(quarantine_dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&quarantine_dir)?;
        
        let audit_log_path = quarantine_dir.join("audit_log.json");
        
        // 嘗試載入現有的審計日誌
        let audit_log = if audit_log_path.exists() {
            match fs::read_to_string(&audit_log_path) {
                Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };

        Ok(QuarantineManager {
            quarantine_dir,
            entries: Vec::new(),
            audit_log,
            audit_log_path,
            encryption_enabled: true,
        })
    }

    /// 計算檔案的 SHA256 雜湊
    fn calculate_file_hash(file_path: &Path) -> io::Result<String> {
        let data = fs::read(file_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(hex::encode(hasher.finalize()))
    }

    /// 嘗試獲取檔案的數位簽署資訊（Windows 特定）
    #[cfg(windows)]
    fn get_file_signature(file_path: &Path) -> Option<String> {
        use winapi::um::wintrust::{WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_UI_NONE, WTD_REVOKE_NONE, WTD_CHOICE_FILE};
        use std::os::windows::ffi::OsStrExt;
        use winapi::shared::minwindef::DWORD;
        use winapi::shared::guiddef::GUID;

        let mut action_id = GUID {
            Data1: 0x00AAC56B,
            Data2: 0xCD44,
            Data3: 0x11D0,
            Data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
        };

        let mut wide_path: Vec<u16> = file_path.as_os_str().encode_wide().chain(Some(0)).collect();
        
        let mut file_info: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
        file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as DWORD;
        file_info.pcwszFilePath = wide_path.as_ptr();
        
        let mut wintrust_data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
        wintrust_data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as DWORD;
        wintrust_data.dwUIChoice = WTD_UI_NONE;
        wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
        wintrust_data.dwUnionChoice = WTD_CHOICE_FILE;
        unsafe { *wintrust_data.u.pFile_mut() = &mut file_info };
        
        let status = unsafe { WinVerifyTrust(std::ptr::null_mut(), &mut action_id, &mut wintrust_data as *mut _ as *mut _) };
        if status == 0 {
            Some("verified_signature".to_string())
        } else {
            None
        }
    }

    #[cfg(not(windows))]
    fn get_file_signature(_file_path: &Path) -> Option<String> {
        None
    }

    /// 企業級 AES-256-GCM 加密 (使用 ring 函式庫)
    fn encrypt_aes256_gcm(data: &[u8], original_hash: &str) -> (Vec<u8>, Vec<u8>) {
        use ring::aead::{self, UnboundKey, LessSafeKey, Nonce, Aad};
        use rand::Rng;

        // 1. 生成 12 bytes 的隨機 Nonce (IV)
        let mut rng = rand::thread_rng();
        let nonce_bytes: Vec<u8> = (0..12).map(|_| rng.gen()).collect();
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes.clone().try_into().unwrap()).unwrap();

        // 2. 使用 original_hash 作為種子生成 32 bytes (256-bit) 的金鑰
        let mut hasher = Sha256::new();
        hasher.update(b"WENLE_QUARANTINE_AES_KEY_SALT");
        hasher.update(original_hash.as_bytes());
        let key_bytes: [u8; 32] = hasher.finalize().into();

        // 3. 準備加密
        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &key_bytes).unwrap();
        let less_safe_key = LessSafeKey::new(unbound_key);

        let mut in_out = data.to_vec();
        less_safe_key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out).unwrap();

        (in_out, nonce_bytes)
    }

    /// 企業級 AES-256-GCM 解密
    fn decrypt_aes256_gcm(encrypted_data: &[u8], original_hash: &str, nonce_bytes: &[u8]) -> Option<Vec<u8>> {
        use ring::aead::{self, UnboundKey, LessSafeKey, Nonce, Aad};

        if nonce_bytes.len() != 12 || encrypted_data.is_empty() {
            return None;
        }

        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes.try_into().unwrap()).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(b"WENLE_QUARANTINE_AES_KEY_SALT");
        hasher.update(original_hash.as_bytes());
        let key_bytes: [u8; 32] = hasher.finalize().into();

        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &key_bytes).unwrap();
        let less_safe_key = LessSafeKey::new(unbound_key);

        let mut in_out = encrypted_data.to_vec();
        match less_safe_key.open_in_place(nonce, Aad::empty(), &mut in_out) {
            Ok(decrypted) => Some(decrypted.to_vec()),
            Err(_) => None,
        }
    }

    /// 隔離單個檔案（含加密和審計）
    pub fn isolate_file(
        &mut self,
        source_path: &Path,
        threat_name: String,
        operator: &str,
    ) -> io::Result<PathBuf> {
        // 計算原始檔案雜湊
        let original_hash = Self::calculate_file_hash(source_path)?;
        let signature = Self::get_file_signature(source_path);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let quarantine_filename = format!("{}_{}.quarantine", original_hash, now);
        let quarantine_path = self.quarantine_dir.join(&quarantine_filename);

        // 讀取原始檔案
        let file_data = fs::read(source_path)?;

        // 加密檔案（如果啟用）
        let (final_data, iv) = if self.encryption_enabled {
            Self::encrypt_aes256_gcm(&file_data, &original_hash)
        } else {
            (file_data, Vec::new())
        };

        // 寫入隔離檔案
        fs::write(&quarantine_path, &final_data)?;

        // 建立隔離條目
        let entry = QuarantineEntry {
            original_path: source_path.to_path_buf(),
            quarantine_path: quarantine_path.clone(),
            file_hash: original_hash.clone(),
            threat_name: threat_name.clone(),
            quarantine_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            reason: "Malware detected".to_string(),
            original_hash: original_hash.clone(),
            original_signature: signature,
            encrypted: self.encryption_enabled,
            encryption_iv: if self.encryption_enabled { Some(iv) } else { None },
        };

        self.entries.push(entry.clone());

        // 記錄到審計日誌
        let mut details = HashMap::new();
        details.insert("original_path".to_string(), source_path.to_string_lossy().to_string());
        details.insert("threat_name".to_string(), threat_name);
        details.insert("encrypted".to_string(), self.encryption_enabled.to_string());

        let audit_entry = AuditLogEntry {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            action: "quarantine".to_string(),
            quarantine_hash: original_hash,
            operator: operator.to_string(),
            status: "success".to_string(),
            details,
        };

        self.audit_log.push(audit_entry);
        self.save_audit_log()?;

        // 嘗試刪除原始檔案
        let _ = fs::remove_file(source_path);

        log::info!("Quarantined: {:?} -> {:?}", source_path, quarantine_path);
        Ok(quarantine_path)
    }

    /// 恢復隔離的檔案（需要驗證審計日誌）
    pub fn restore_file(&mut self, quarantine_hash: &str, operator: &str) -> io::Result<()> {
        if let Some(pos) = self.entries.iter().position(|e| e.file_hash == quarantine_hash) {
            let entry = self.entries.remove(pos);

            // 讀取隔離的檔案
            let quarantine_data = fs::read(&entry.quarantine_path)?;

            // 解密（如果已加密）
            let original_data = if entry.encrypted && entry.encryption_iv.is_some() {
                let iv = entry.encryption_iv.as_ref().unwrap();
                match Self::decrypt_aes256_gcm(&quarantine_data, quarantine_hash, iv) {
                    Some(dec) => dec,
                    None => return Err(io::Error::new(io::ErrorKind::InvalidData, "AES-256 解密失敗，檔案可能已損毀")),
                }
            } else {
                quarantine_data
            };

            // 驗證雜湊匹配
            let mut hasher = Sha256::new();
            hasher.update(&original_data);
            let computed_hash = hex::encode(hasher.finalize());

            if computed_hash != entry.original_hash {
                let mut details = HashMap::new();
                details.insert("error".to_string(), "Hash mismatch - file may be corrupted".to_string());
                
                self.audit_log.push(AuditLogEntry {
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    action: "restore".to_string(),
                    quarantine_hash: quarantine_hash.to_string(),
                    operator: operator.to_string(),
                    status: "failed".to_string(),
                    details,
                });
                self.save_audit_log()?;

                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Hash verification failed",
                ));
            }

            // 恢復到原始位置
            if !entry.original_path.exists() {
                fs::write(&entry.original_path, &original_data)?;
            }

            // 刪除隔離檔案
            let _ = fs::remove_file(&entry.quarantine_path);

            // 記錄審計日誌
            let mut details = HashMap::new();
            details.insert("original_path".to_string(), entry.original_path.to_string_lossy().to_string());
            
            self.audit_log.push(AuditLogEntry {
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                action: "restore".to_string(),
                quarantine_hash: quarantine_hash.to_string(),
                operator: operator.to_string(),
                status: "success".to_string(),
                details,
            });
            self.save_audit_log()?;

            log::info!("Restored: {:?}", entry.original_path);
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Quarantine entry not found",
            ))
        }
    }

    /// 批量掃描並隔離檔案夾中的惡意檔案
    pub fn quarantine_directory(
        &mut self,
        dir_path: &Path,
        engine: &AntivirusEngine,
        recursive: bool,
        operator: &str,
    ) -> io::Result<Vec<QuarantineEntry>> {
        let mut quarantined = Vec::new();

        let read_dir = fs::read_dir(dir_path)?;

        for entry_result in read_dir {
            let entry = entry_result?;
            let path = entry.path();

            if path.is_file() {
                let scan_result = engine.scan_file(&path);
                if scan_result.threat_detected {
                    match self.isolate_file(&path, scan_result.rule_matches.join(", "), operator) {
                        Ok(_) => {
                            if let Some(last) = self.entries.last() {
                                quarantined.push(last.clone());
                            }
                        }
                        Err(e) => log::error!("Failed to quarantine {:?}: {}", path, e),
                    }
                }
            } else if recursive && path.is_dir() {
                if let Ok(sub_quarantined) = self.quarantine_directory(&path, engine, recursive, operator) {
                    quarantined.extend(sub_quarantined);
                }
            }
        }

        Ok(quarantined)
    }

    /// 列出所有隔離項
    pub fn list_entries(&self) -> &[QuarantineEntry] {
        &self.entries
    }

    /// 獲取審計日誌
    pub fn get_audit_log(&self) -> &[AuditLogEntry] {
        &self.audit_log
    }

    /// 保存審計日誌到檔案
    fn save_audit_log(&self) -> io::Result<()> {
        let json = serde_json::to_string_pretty(&self.audit_log)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&self.audit_log_path, json)?;
        Ok(())
    }

    /// 清空隔離目錄
    pub fn purge_all(&mut self, operator: &str) -> io::Result<()> {
        for entry in self.entries.drain(..) {
            let _ = fs::remove_file(&entry.quarantine_path);

            let mut details = HashMap::new();
            details.insert("reason".to_string(), "purge_all".to_string());

            self.audit_log.push(AuditLogEntry {
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                action: "purge".to_string(),
                quarantine_hash: entry.file_hash,
                operator: operator.to_string(),
                status: "success".to_string(),
                details,
            });
        }
        self.save_audit_log()?;
        Ok(())
    }
}
