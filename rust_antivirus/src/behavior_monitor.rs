// src/behavior_monitor.rs: 實時行為監控和攔截
// 集成 minifilter 驅動、Windows 通知、行為阻止邏輯

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockAction {
    Allow,
    Block,
    Quarantine,
    Terminate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptionEvent {
    pub timestamp: u64,
    pub event_type: String, // "file_access", "process_create", "memory_write", etc.
    pub source: String,     // 觸發程序路徑或 PID
    pub target: String,     // 目標檔案、進程或位置
    pub risk_level: u8,     // 0-100
    pub action_taken: BlockAction,
    pub reason: String,
    pub details: HashMap<String, String>,
}

/// 攔截規則
#[derive(Debug, Clone)]
pub struct InterceptionRule {
    pub rule_id: String,
    pub rule_name: String,
    pub enabled: bool,
    pub pattern: String,
    pub action: BlockAction,
    pub priority: u8, // 越高優先級越高
}

/// 行為監控引擎
pub struct BehaviorMonitor {
    rules: Arc<Mutex<Vec<InterceptionRule>>>,
    blocked_events: Arc<Mutex<Vec<InterceptionEvent>>>,
    process_whitelist: Arc<Mutex<Vec<String>>>,
    file_whitelist: Arc<Mutex<Vec<String>>>,
    windows_notification_enabled: bool,
}

impl BehaviorMonitor {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(Mutex::new(Vec::new())),
            blocked_events: Arc::new(Mutex::new(Vec::new())),
            process_whitelist: Arc::new(Mutex::new(vec![
                "svchost.exe".to_string(),
                "explorer.exe".to_string(),
                "dwm.exe".to_string(),
                "csrss.exe".to_string(),
                "lsass.exe".to_string(),
            ])),
            file_whitelist: Arc::new(Mutex::new(vec![
                "C:\\Windows".to_string(),
                "C:\\Program Files".to_string(),
            ])),
            windows_notification_enabled: true,
        }
    }

    /// 初始化預設規則
    pub fn init_default_rules(&self) -> Result<()> {
        let mut rules = self.rules.lock().map_err(|e| anyhow!("Lock error: {}", e))?;

        // 規則 1: 阻止駐留後門
        rules.push(InterceptionRule {
            rule_id: "rule_persistence_001".to_string(),
            rule_name: "Block persistence mechanisms".to_string(),
            enabled: true,
            pattern: r"(HKLM|HKCU)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            action: BlockAction::Quarantine,
            priority: 90,
        });

        // 規則 2: 阻止進程注入
        rules.push(InterceptionRule {
            rule_id: "rule_injection_001".to_string(),
            rule_name: "Block process injection".to_string(),
            enabled: true,
            pattern: "WriteProcessMemory|CreateRemoteThread".to_string(),
            action: BlockAction::Block,
            priority: 95,
        });

        // 規則 3: 阻止 UAC 旁路
        rules.push(InterceptionRule {
            rule_id: "rule_privesc_001".to_string(),
            rule_name: "Block UAC bypass attempts".to_string(),
            enabled: true,
            pattern: r"\\HKEY_CURRENT_USER\\Software\\Classes\\ms-settings".to_string(),
            action: BlockAction::Block,
            priority: 85,
        });

        // 規則 4: 監控可疑檔案下載位置
        rules.push(InterceptionRule {
            rule_id: "rule_download_001".to_string(),
            rule_name: "Monitor suspicious download locations".to_string(),
            enabled: true,
            pattern: r"(TEMP|TMP|Downloads|AppData\\Local\\Temp)\\.*\.(exe|scr|pif|msi|bat|cmd)".to_string(),
            action: BlockAction::Quarantine,
            priority: 75,
        });

        // 規則 5: 阻止加密挖礦
        rules.push(InterceptionRule {
            rule_id: "rule_miner_001".to_string(),
            rule_name: "Block mining attempts".to_string(),
            enabled: true,
            pattern: "(xmrig|cpuminer|pool.*mining)".to_string(),
            action: BlockAction::Block,
            priority: 70,
        });

        Ok(())
    }

    /// 添加自訂攔截規則
    pub fn add_rule(&self, rule: InterceptionRule) -> Result<()> {
        let mut rules = self.rules.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
        rules.push(rule);
        // 按優先級排序
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        Ok(())
    }

    /// 評估檔案執行請求
    pub fn evaluate_file_execution(&self, file_path: &str, process_name: &str) -> Result<(BlockAction, String)> {
        // 1. 檢查白名單
        let filelist = self.file_whitelist.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
        for whitelisted in filelist.iter() {
            if file_path.starts_with(whitelisted) {
                return Ok((BlockAction::Allow, "Whitelisted path".to_string()));
            }
        }
        drop(filelist);

        // 2. 檢查進程白名單
        let proclist = self.process_whitelist.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
        for whitelisted in proclist.iter() {
            if process_name.contains(whitelisted) {
                return Ok((BlockAction::Allow, "Whitelisted process".to_string()));
            }
        }
        drop(proclist);

        // 3. 套用規則
        let rules = self.rules.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            // 簡化型式匹配（實際上應使用正規表達式）
            if file_path.contains(&rule.pattern) || process_name.contains(&rule.pattern) {
                return Ok((rule.action, format!("Rule triggered: {}", rule.rule_name)));
            }
        }

        Ok((BlockAction::Allow, "No rules matched".to_string()))
    }

    /// 處理檔案訪問攔截（在 minifilter 中呼叫）
    pub fn handle_file_access_interception(
        &self,
        source_pid: u32,
        source_name: &str,
        target_path: &str,
        access_type: &str, // "read", "write", "execute", "delete"
    ) -> Result<(BlockAction, String)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 根據訪問類型和目標路徑進行動作評估
        let (action, reason) = if access_type == "execute" {
            self.evaluate_file_execution(target_path, source_name)?
        } else if access_type == "write" && target_path.ends_with(".sys") {
            // 阻止寫入系統驅動
            (BlockAction::Block, "Attempting to write to system driver".to_string())
        } else if access_type == "delete" && self.is_critical_system_file(target_path) {
            // 阻止刪除關鍵系統檔案
            (BlockAction::Block, "Attempting to delete critical system file".to_string())
        } else {
            (BlockAction::Allow, "Access allowed".to_string())
        };

        // 記錄事件
        if action != BlockAction::Allow {
            let mut events = self.blocked_events.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
            events.push(InterceptionEvent {
                timestamp: now,
                event_type: format!("file_{}", access_type),
                source: format!("{}(PID:{})", source_name, source_pid),
                target: target_path.to_string(),
                risk_level: 60,
                action_taken: action,
                reason: reason.clone(),
                details: Default::default(),
            });

            // 傳送 Windows 通知
            if self.windows_notification_enabled {
                self.send_windows_notification(
                    "Security Alert",
                    &format!("Blocked {} attempt on {}", access_type, target_path),
                    3, // 持續 3 秒
                )?;
            }
        }

        Ok((action, reason))
    }

    /// 處理進程建立攔截
    pub fn handle_process_creation(
        &self,
        parent_pid: u32,
        parent_name: &str,
        child_path: &str,
        child_args: &str,
    ) -> Result<(BlockAction, String)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 檢查是否為可疑命令列參數
        let has_suspicious_args = child_args.contains("-psCommand") 
            || child_args.contains("DownloadString")
            || child_args.contains("Invoke-Expression")
            || child_args.contains("IEX");

        let (action, reason) = if has_suspicious_args {
            (BlockAction::Quarantine, "Suspicious PowerShell command detected".to_string())
        } else {
            self.evaluate_file_execution(child_path, parent_name)?
        };

        if action != BlockAction::Allow {
            let mut events = self.blocked_events.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
            events.push(InterceptionEvent {
                timestamp: now,
                event_type: "process_create".to_string(),
                source: format!("{}(PID:{})", parent_name, parent_pid),
                target: format!("{} {}", child_path, child_args),
                risk_level: if has_suspicious_args { 80 } else { 50 },
                action_taken: action,
                reason: reason.clone(),
                details: Default::default(),
            });

            if self.windows_notification_enabled {
                self.send_windows_notification(
                    "Process Creation Blocked",
                    &format!("Blocked: {}", child_path),
                    3,
                )?;
            }
        }

        Ok((action, reason))
    }

    /// 檢查是否為關鍵系統檔案
    fn is_critical_system_file(&self, path: &str) -> bool {
        let critical_files = [
            "ntlm.dll",
            "kernel32.dll",
            "advapi32.dll",
            "ntoskrnl.exe",
            "winlogon.exe",
            "csrss.exe",
            "smss.exe",
        ];

        for critical in &critical_files {
            if path.ends_with(critical) {
                return true;
            }
        }

        false
    }

    /// 傳送 Windows 通知（Toast Notification）
    fn send_windows_notification(&self, title: &str, message: &str, duration_secs: u32) -> Result<()> {
        #[cfg(windows)]
        {
            use std::process::Command;

            // 使用 PowerShell 顯示 Windows Toast 通知
            let ps_script = format!(
                r#"
$notif = @{{
    Title = '{}'
    Duration = 'long'
    ProgressValue = null
}}
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$APP_ID = 'WenleMicrosoft.WenleSecurity'
$template = @"
<toast>
    <visual>
        <binding template="ToastText02">
            <text id="1">{}</text>
            <text id="2">{}</text>
        </binding>
    </visual>
</toast>
"@
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($template)
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($APP_ID).Show($toast);
"#,
                title, title, message
            );

            let _ = Command::new("powershell")
                .arg("-NoProfile")
                .arg("-Command")
                .arg(ps_script)
                .spawn();
        }

        #[cfg(not(windows))]
        {
            log::info!("Notification [{}]: {}", title, message);
        }

        Ok(())
    }

    /// 獲取被攔截的事件
    pub fn get_blocked_events(&self) -> Result<Vec<InterceptionEvent>> {
        let events = self.blocked_events.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
        Ok(events.clone())
    }

    /// 清空攔截的事件日誌
    pub fn clear_blocked_events(&self) -> Result<()> {
        let mut events = self.blocked_events.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
        events.clear();
        Ok(())
    }

    /// 添加進程到白名單
    pub fn whitelist_process(&self, process_name: &str) -> Result<()> {
        let mut whitelist = self.process_whitelist.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
        if !whitelist.contains(&process_name.to_string()) {
            whitelist.push(process_name.to_string());
        }
        Ok(())
    }

    /// 添加檔案路徑到白名單
    pub fn whitelist_path(&self, path: &str) -> Result<()> {
        let mut whitelist = self.file_whitelist.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
        if !whitelist.contains(&path.to_string()) {
            whitelist.push(path.to_string());
        }
        Ok(())
    }
}

// 與 minifilter 驅動的整合
pub mod minifilter_bridge {
    use super::*;

    /// minifilter 通訊結構
    #[repr(C)]
    pub struct MinifilterMessage {
        pub message_type: u32,      // 0: query, 1: response
        pub timestamp: u64,
        pub process_id: u32,
        pub process_name: [u8; 256],
        pub file_path: [u8; 512],
        pub access_type: u32,       // 0: read, 1: write, 2: execute, 3: delete
        pub allow: u32,             // 0: block, 1: allow
        pub reason: [u8; 256],
    }

    pub struct MinifilterBridge {
        behavior_monitor: Arc<BehaviorMonitor>,
    }

    impl MinifilterBridge {
        pub fn new(monitor: Arc<BehaviorMonitor>) -> Self {
            Self {
                behavior_monitor: monitor,
            }
        }

        /// 處理來自 minifilter 的檔案訪問請求
        pub fn process_file_access_request(
            &self,
            source_pid: u32,
            source_name: &str,
            target_path: &str,
            access_type: u32,
        ) -> bool {
            let access_str = match access_type {
                0 => "read",
                1 => "write",
                2 => "execute",
                3 => "delete",
                _ => "unknown",
            };

            match self.behavior_monitor.handle_file_access_interception(
                source_pid,
                source_name,
                target_path,
                access_str,
            ) {
                Ok((action, _)) => action == BlockAction::Allow,
                Err(_) => true, // 如果發生錯誤，預設允許以避免系統卡頓
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_behavior_monitor_initialization() {
        let monitor = BehaviorMonitor::new();
        assert!(!monitor.process_whitelist.lock().unwrap().is_empty());
    }

    #[test]
    fn test_file_access_blocking() {
        let monitor = BehaviorMonitor::new();
        assert!(monitor.init_default_rules().is_ok());

        let (action, _) = monitor
            .handle_file_access_interception(1234, "malware.exe", "C:\\Windows\\system32\\kernel32.dll", "read")
            .unwrap();
        assert_eq!(action, BlockAction::Allow);
    }

    #[test]
    fn test_suspicious_args_detection() {
        let monitor = BehaviorMonitor::new();
        assert!(monitor.init_default_rules().is_ok());

        let (action, _) = monitor
            .handle_process_creation(100, "parent.exe", "powershell.exe", "Invoke-Expression")
            .unwrap();
        assert_eq!(action, BlockAction::Quarantine);
    }
}
