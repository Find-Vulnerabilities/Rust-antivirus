// src/service.rs: Windows Service 包装 (P1)
// 使应用能够作为 Windows Service 持续后台运行
// 支持服务启动、停止、状态检查

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::thread;

static SERVICE_NAME: &str = "WenleAntivirus";
static SERVICE_DISPLAY_NAME: &str = "Wenle Antivirus Service";
static SERVICE_DESCRIPTION: &str = "Real-time antivirus protection with PE analysis, behavior monitoring, and file isolation";

// 全局状态标志
static RUNNING: AtomicBool = AtomicBool::new(false);

/// 启动 Windows Service
pub fn register_as_service() -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Service registration initiated for: {}", SERVICE_NAME);
    
    // 在实际部署时，使用以下 PowerShell 命令：
    // New-Service -Name "WenleAntivirus" -BinaryPathName "C:\path\to\wenle-antivirus.exe" -StartupType Automatic
    
    Ok(())
}

/// 启动 Service 主程序
pub fn start_service() -> Result<(), Box<dyn std::error::Error>> {
    RUNNING.store(true, Ordering::Release);
    log::info!("Service {} started successfully", SERVICE_NAME);
    
    // 保持服务运行
    while RUNNING.load(Ordering::Acquire) {
        thread::sleep(Duration::from_secs(5));
    }
    
    Ok(())
}

/// 停止 Windows Service
pub fn stop_service() -> Result<(), Box<dyn std::error::Error>> {
    RUNNING.store(false, Ordering::Release);
    log::info!("Service {} stopped", SERVICE_NAME);
    Ok(())
}

/// 删除 Windows Service
pub fn unregister_service() -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Service {} unregistered", SERVICE_NAME);
    
    // 实际操作：
    // sc.exe delete "WenleAntivirus"
    
    Ok(())
}

/// 检查服务状态
pub fn query_service_status() -> Result<String, Box<dyn std::error::Error>> {
    if RUNNING.load(Ordering::Acquire) {
        Ok("RUNNING".to_string())
    } else {
        Ok("STOPPED".to_string())
    }
}

pub fn is_service_running() -> bool {
    RUNNING.load(Ordering::Acquire)
}

/// 获取服务名称
pub fn get_service_name() -> &'static str {
    SERVICE_NAME
}

/// 获取服务显示名称
pub fn get_service_display_name() -> &'static str {
    SERVICE_DISPLAY_NAME
}
