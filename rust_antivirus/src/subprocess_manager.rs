//! 子进程管理模块
//!
//! 负责启动和管理file-monitor和memory-monitor子进程
//! 每个监控器作为独立的二进制程序运行

use std::process::{Child, Command};
use std::os::windows::process::CommandExt;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct MonitorInfo {
    pub name: String,
    pub pid: u32,
    pub running: bool,
}

pub struct SubprocessManager {
    file_monitor: Option<Child>,
    memory_monitor: Option<Child>,
}

impl SubprocessManager {
    pub fn new() -> Self {
        Self {
            file_monitor: None,
            memory_monitor: None,
        }
    }

    /// 启动所有监控子进程
    pub fn start_all_monitors(&mut self) -> Result<(), String> {
        log::info!("Starting all monitor subprocesses...");

        match self.start_file_monitor() {
            Ok(_) => log::info!("File monitor started successfully"),
            Err(e) => {
                log::warn!("Failed to start file monitor: {}", e);
                // 继续尝试启动其他进程，不中断
            }
        }

        // 给第一个进程一些时间启动
        thread::sleep(Duration::from_millis(500));

        match self.start_memory_monitor() {
            Ok(_) => log::info!("Memory monitor started successfully"),
            Err(e) => {
                log::warn!("Failed to start memory monitor: {}", e);
            }
        }

        Ok(())
    }

    /// 启动文件监控子进程
    fn start_file_monitor(&mut self) -> Result<(), String> {
        let exe_path = self.get_binary_path("file-monitor.exe")?;

        let child = Command::new(&exe_path)
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .spawn()
            .map_err(|e| format!("Failed to spawn file-monitor: {}", e))?;

        let pid = child.id();
        log::info!("File monitor process started with PID: {}", pid);

        self.file_monitor = Some(child);
        Ok(())
    }

    /// 启动内存监控子进程
    fn start_memory_monitor(&mut self) -> Result<(), String> {
        let exe_path = self.get_binary_path("memory-monitor.exe")?;

        let child = Command::new(&exe_path)
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .spawn()
            .map_err(|e| format!("Failed to spawn memory-monitor: {}", e))?;

        let pid = child.id();
        log::info!("Memory monitor process started with PID: {}", pid);

        self.memory_monitor = Some(child);
        Ok(())
    }

    /// 获取二进制程序的路径
    fn get_binary_path(&self, binary_name: &str) -> Result<String, String> {
        // 尝试从多个位置查找二进制文件
        let possible_paths = vec![
            // 当前可执行文件的目录
            format!(
                "{}\\{}",
                std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|d| d.to_string_lossy().to_string()))
                    .unwrap_or_default(),
                binary_name
            ),
            // 编译输出目录
            format!(".\\target\\release\\{}", binary_name),
            format!(".\\target\\debug\\{}", binary_name),
            // 绝对路径
            binary_name.to_string(),
        ];

        for path in possible_paths {
            if std::path::Path::new(&path).exists() {
                log::debug!("Found binary at: {}", path);
                return Ok(path);
            }
        }

        Err(format!("Binary {} not found in any expected location", binary_name))
    }

    /// 获取文件监控进程的PID
    pub fn get_file_monitor_pid(&self) -> Option<u32> {
        self.file_monitor.as_ref().map(|p| p.id())
    }

    /// 获取内存监控进程的PID
    pub fn get_memory_monitor_pid(&self) -> Option<u32> {
        self.memory_monitor.as_ref().map(|p| p.id())
    }

    /// 检查文件监控进程是否运行
    pub fn is_file_monitor_running(&mut self) -> bool {
        if let Some(ref mut child) = self.file_monitor {
            match child.try_wait() {
                Ok(Some(_)) => {
                    // 进程已退出
                    self.file_monitor = None;
                    false
                }
                Ok(None) => {
                    // 进程仍在运行
                    true
                }
                Err(_) => {
                    // 检查出错，假设已退出
                    false
                }
            }
        } else {
            false
        }
    }

    /// 检查内存监控进程是否运行
    pub fn is_memory_monitor_running(&mut self) -> bool {
        if let Some(ref mut child) = self.memory_monitor {
            match child.try_wait() {
                Ok(Some(_)) => {
                    // 进程已退出
                    self.memory_monitor = None;
                    false
                }
                Ok(None) => {
                    // 进程仍在运行
                    true
                }
                Err(_) => {
                    // 检查出错，假设已退出
                    false
                }
            }
        } else {
            false
        }
    }

    /// 重启已退出的监控器
    pub fn restart_failed_monitors(&mut self) {
        if !self.is_file_monitor_running() {
            log::warn!("File monitor process exited unexpectedly, restarting...");
            if let Err(e) = self.start_file_monitor() {
                log::error!("Failed to restart file monitor: {}", e);
            }
        }

        if !self.is_memory_monitor_running() {
            log::warn!("Memory monitor process exited unexpectedly, restarting...");
            if let Err(e) = self.start_memory_monitor() {
                log::error!("Failed to restart memory monitor: {}", e);
            }
        }
    }

    /// 获取所有监控器的状态信息
    pub fn get_all_monitors_info(&mut self) -> (MonitorInfo, MonitorInfo) {
        let file_monitor_running = self.is_file_monitor_running();
        let memory_monitor_running = self.is_memory_monitor_running();

        (
            MonitorInfo {
                name: "File Monitor".to_string(),
                pid: self.get_file_monitor_pid().unwrap_or(0),
                running: file_monitor_running,
            },
            MonitorInfo {
                name: "Memory Monitor".to_string(),
                pid: self.get_memory_monitor_pid().unwrap_or(0),
                running: memory_monitor_running,
            },
        )
    }

    /// 终止所有监控子进程
    pub fn stop_all(&mut self) {
        if let Some(mut child) = self.file_monitor.take() {
            let _ = child.kill();
            let _ = child.wait();
            log::info!("File monitor process terminated");
        }

        if let Some(mut child) = self.memory_monitor.take() {
            let _ = child.kill();
            let _ = child.wait();
            log::info!("Memory monitor process terminated");
        }
    }
}

impl Drop for SubprocessManager {
    fn drop(&mut self) {
        self.stop_all();
    }
}
