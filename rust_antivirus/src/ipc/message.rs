use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// IPC消息类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IPCMessage {
    /// 威胁检测事件
    ThreatDetected(ThreatAlert),
    /// 配置更新
    ConfigUpdate(ConfigUpdateRequest),
    /// 状态查询
    StatusRequest,
    /// 状态响应
    StatusResponse(MonitorStatus),
    /// 心跳/保活
    Heartbeat,
}

/// 威胁警报
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    /// 监控类型：process | file | memory
    pub monitor_type: String,
    /// 进程ID（如果适用）
    pub pid: Option<u32>,
    /// 文件路径
    pub file_path: Option<PathBuf>,
    /// 威胁名称
    pub threat_name: String,
    /// 风险评分 (0-100)
    pub risk_score: u8,
    /// 规则匹配
    pub rule_matches: Vec<String>,
    /// 时间戳 (Unix时间)
    pub timestamp: u64,
    /// 建议操作
    pub action: ThreatAction,
}

/// 威胁应对行为
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatAction {
    /// 立即隔离
    ImmediateQuarantine,
    /// 暂停进程，等待用户确认
    SuspendWaitForConfirm,
    /// 仅记录，不采取行动
    LogOnly,
}

/// 配置更新请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigUpdateRequest {
    /// 白名单路径列表
    pub whitelist_hashes: Option<Vec<String>>,
    /// 监控路径列表
    pub monitored_paths: Option<Vec<PathBuf>>,
    /// 是否启用内存扫描
    pub enable_memory_scan: Option<bool>,
    /// 扫描周期（秒）
    pub scan_interval: Option<u64>,
}

/// 监控程序状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorStatus {
    /// 文件监控是否运行
    pub file_monitor_active: bool,
    /// 内存监控是否运行
    pub memory_monitor_active: bool,
    /// 最后检测时间
    pub last_detection_time: Option<u64>,
    /// 检测到的威胁计数
    pub threat_count: u32,
    /// 内存使用（MB）
    pub memory_usage_mb: u32,
    /// CPU使用率（%）
    pub cpu_usage_percent: f32,
}

/// IPC通话结果
#[derive(Debug, Serialize, Deserialize)]
pub enum IpcResult<T> {
    Ok(T),
    Err(String),
}

impl<T> IpcResult<T> {
    pub fn result(self) -> Result<T, String> {
        match self {
            IpcResult::Ok(t) => Ok(t),
            IpcResult::Err(e) => Err(e),
        }
    }
}
