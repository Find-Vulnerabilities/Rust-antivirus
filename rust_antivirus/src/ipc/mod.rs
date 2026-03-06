//! Inter-process communication module for three-process architecture
//!
//! This module defines messages passed between:
//! - wenle-antivirus.exe (main GUI)
//! - file-monitor.exe (file system monitoring)
//! - memory-monitor.exe (process and memory monitoring)

use serde::{Deserialize, Serialize};

pub mod named_pipe;

/// Threat alert message sent from monitor to main GUI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    /// Source of threat: "process" | "file" | "memory"
    pub source: String,

    /// Process ID (if applicable)
    pub pid: u32,

    /// File path or process executable path
    pub path: String,

    /// Detected threat name (YARA rule or signature)
    pub threat_name: String,

    /// Risk score 0-100
    pub risk_score: u8,

    /// Unix timestamp
    pub timestamp: u64,

    /// Action taken: "killed" | "suspended" | "quarantined" | "logged"
    pub action_taken: String,
}

/// Configuration update message sent from main app to monitors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigUpdate {
    /// Whitelist of safe file hashes
    pub whitelist: Vec<String>,

    /// Directories to monitor
    pub monitored_paths: Vec<String>,

    /// Enable/disable memory scanning
    pub enable_memory_scan: bool,

    /// Memory scan interval in milliseconds
    pub memory_scan_interval_ms: u32,
}

/// Generic IPC message enum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    /// Threat alert from monitor -> main
    ThreatAlert(ThreatAlert),

    /// Config update from main -> monitor
    ConfigUpdate(ConfigUpdate),

    /// Heartbeat to check monitor is alive
    Heartbeat,

    /// Monitor startup notification
    MonitorStarted { name: String, pid: u32 },

    /// Shutdown signal
    Shutdown,
}

impl IpcMessage {
    /// Serialize to binary using bincode
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize from binary
    pub fn decode(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }
}

// Named pipe names for Windows IPC
pub const THREAT_ALERT_PIPE: &str = r"\.\pipe\wenle_threat_alerts";
pub const CONFIG_UPDATE_PIPE: &str = r"\.\pipe\wenle_config";
pub const HEARTBEAT_PIPE: &str = r"\.\pipe\wenle_heartbeat";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_alert_serialization() {
        let alert = ThreatAlert {
            source: "process".to_string(),
            pid: 1234,
            path: "C:\\malware.exe".to_string(),
            threat_name: "Trojan.Generic".to_string(),
            risk_score: 95,
            timestamp: 1609459200,
            action_taken: "killed".to_string(),
        };

        let msg = IpcMessage::ThreatAlert(alert.clone());
        let encoded = msg.encode().expect("encode failed");
        let decoded = IpcMessage::decode(&encoded).expect("decode failed");

        match decoded {
            IpcMessage::ThreatAlert(t) => {
                assert_eq!(t.source, "process");
                assert_eq!(t.pid, 1234);
                assert_eq!(t.risk_score, 95);
            }
            _ => panic!("Expected ThreatAlert"),
        }
    }
}
