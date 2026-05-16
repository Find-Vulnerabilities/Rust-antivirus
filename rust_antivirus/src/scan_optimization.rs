// src/scan_optimization.rs: 性能优化与智能缓存
// 实现缓存、白名单、快速路径与扫描优先级

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub file_hash: String,
    pub scan_result: bool, // true = clean, false = malicious
    pub timestamp: u64,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    pub file_hash: String,
    pub file_path: PathBuf,
    pub reason: String,
    pub timestamp: u64,
    pub expiry: Option<u64>, // None = permanent
}

pub struct ScanOptimizer {
    // LRU cache: hash -> scan result
    scan_cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    whitelist: Arc<Mutex<Vec<WhitelistEntry>>>,
    cache_max_size: usize,
    cache_ttl: Duration,
}

impl ScanOptimizer {
    pub fn new(max_cache_size: usize, ttl_seconds: u64) -> Self {
        ScanOptimizer {
            scan_cache: Arc::new(Mutex::new(HashMap::new())),
            whitelist: Arc::new(Mutex::new(Vec::new())),
            cache_max_size: max_cache_size,
            cache_ttl: Duration::from_secs(ttl_seconds),
        }
    }

    /// Check if file is whitelisted
    pub fn is_whitelisted(&self, file_hash: &str) -> bool {
        if let Ok(whitelist) = self.whitelist.lock() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            whitelist.iter().any(|entry| {
                entry.file_hash == file_hash && entry.expiry.map_or(true, |exp| now < exp)
            })
        } else {
            false
        }
    }

    /// Add file to whitelist
    pub fn add_whitelist(
        &self,
        file_hash: String,
        file_path: PathBuf,
        reason: String,
        expiry: Option<u64>,
    ) {
        if let Ok(mut whitelist) = self.whitelist.lock() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            whitelist.push(WhitelistEntry {
                file_hash,
                file_path,
                reason,
                timestamp: now,
                expiry,
            });
        }
    }

    /// Remove from whitelist
    pub fn remove_whitelist(&self, file_hash: &str) {
        if let Ok(mut whitelist) = self.whitelist.lock() {
            whitelist.retain(|e| e.file_hash != file_hash);
        }
    }

    /// Get cached scan result
    pub fn get_cached(&self, file_hash: &str) -> Option<bool> {
        if let Ok(cache) = self.scan_cache.lock() {
            if let Some(entry) = cache.get(file_hash) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Check if cache entry is still valid (not expired)
                if now - entry.timestamp < entry.ttl_seconds {
                    return Some(entry.scan_result);
                }
            }
        }
        None
    }

    /// Update cache with scan result
    pub fn cache_result(&self, file_hash: String, is_clean: bool) {
        if let Ok(mut cache) = self.scan_cache.lock() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Evict oldest entries if cache is full
            if cache.len() >= self.cache_max_size {
                if let Some(oldest_key) = cache
                    .iter()
                    .min_by_key(|(_, v)| v.timestamp)
                    .map(|(k, _)| k.clone())
                {
                    cache.remove(&oldest_key);
                }
            }

            cache.insert(
                file_hash,
                CacheEntry {
                    file_hash: String::new(),
                    scan_result: is_clean,
                    timestamp: now,
                    ttl_seconds: self.cache_ttl.as_secs(),
                },
            );
        }
    }

    /// Clear expired cache entries
    pub fn cleanup_expired(&self) {
        if let Ok(mut cache) = self.scan_cache.lock() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            cache.retain(|_, entry| now - entry.timestamp < entry.ttl_seconds);
        }
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        if let Ok(cache) = self.scan_cache.lock() {
            let total = cache.len();
            let whitelist_count = if let Ok(wl) = self.whitelist.lock() {
                wl.len()
            } else {
                0
            };
            (total, whitelist_count)
        } else {
            (0, 0)
        }
    }

    /// Prefetch and cache critical system files
    pub fn prefetch_system_files(&self, hashes: &[&str]) {
        for hash in hashes {
            self.cache_result(hash.to_string(), true); // Mark system files as clean
        }
    }

    /// Get priority scan list (high-risk files)
    pub fn get_priority_extensions() -> Vec<&'static str> {
        vec![
            "exe", "dll", "sys", "bat", "cmd", "vbs", "js", "jar",
            "scr", "pif", "ps1", "msi", "com", "ocx", "drv",
        ]
    }

    /// Estimate scan time based on file size and type
    pub fn estimate_scan_time_ms(file_size: u64, extension: &str) -> u64 {
        let base_time = match extension {
            "exe" | "dll" | "sys" => 50,  // Higher priority
            "zip" | "rar" | "7z" => 100,  // Archive, needs extraction
            "pdf" | "doc" | "xls" => 30,  // Office/document
            _ => 20,                       // Default
        };

        // Add time for file size (approximate: 1ms per 1MB)
        let size_time = (file_size / 1_000_000).max(1);

        base_time + size_time as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_and_whitelist() {
        let optimizer = ScanOptimizer::new(100, 3600);

        // Test caching
        let hash = "test_hash_123";
        optimizer.cache_result(hash.to_string(), true);
        assert_eq!(optimizer.get_cached(hash), Some(true));

        // Test whitelist
        optimizer.add_whitelist(
            "white_hash".to_string(),
            PathBuf::from("C:\\test.exe"),
            "Trusted app".to_string(),
            None,
        );
        assert!(optimizer.is_whitelisted("white_hash"));
    }

    #[test]
    fn test_cache_expiry() {
        let optimizer = ScanOptimizer::new(100, 1); // 1 second TTL
        let hash = "test_hash_short";
        optimizer.cache_result(hash.to_string(), false);

        // Should be cached immediately
        assert_eq!(optimizer.get_cached(hash), Some(false));

        // Wait and verify expiry
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(optimizer.get_cached(hash), None);
    }
}
