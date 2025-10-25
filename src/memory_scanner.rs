use std::collections::HashMap;
use sysinfo::{Pid, Process, ProcessExt, System, SystemExt};
use winapi::{
    shared::minwindef::{DWORD, FALSE, TRUE},
    um::{
        handleapi::CloseHandle,
        memoryapi::{ReadProcessMemory, VirtualQueryEx},
        processthreadsapi::{
            OpenProcess, TerminateProcess, CreateToolhelp32Snapshot, Process32First, 
            Process32Next, SuspendThread, ResumeThread,
        },
        psapi::{GetModuleFileNameExA, EnumProcessModules, GetModuleInformation},
        tlhelp32::{TH32CS_SNAPMODULE, TH32CS_SNAPTHREAD, MODULEENTRY32, THREADENTRY32},
        winnt::{
            PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_TERMINATE, PROCESS_SUSPEND_RESUME,
            PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE,
            MEM_COMMIT, MEM_PRIVATE,
        },
    },
};
use anyhow::{Result, anyhow};

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub size: usize,
    pub protection: u32,
    pub is_executable: bool,
    pub is_writable: bool,
    pub region_type: String,
    pub content_hash: String,
}

#[derive(Debug, Clone)]
pub struct MemoryScanResult {
    pub pid: Pid,
    pub process_name: String,
    pub suspicious_regions: Vec<MemoryRegion>,
    pub is_malicious: bool,
    pub reason: String,
    pub risk_score: u8,
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: Pid,
    pub name: String,
    pub exe_path: String,
    pub parent_pid: Pid,
}

pub struct MemoryScanner {
    system: System,
}

impl MemoryScanner {
    pub fn new() -> Self {
        Self {
            system: System::new_all(),
        }
    }

    pub fn refresh(&mut self) {
        self.system.refresh_all();
    }

    pub fn is_system_process(&self, pid: Pid) -> bool {
        let pid_value = pid.as_u32();
        if pid_value <= 4 {
            return true;
        }

        if let Some(process) = self.system.process(pid) {
            let exe_path = process.exe().to_string_lossy().to_lowercase();
            exe_path.contains("system32") || 
            exe_path.contains("syswow64") ||
            exe_path.contains("windows\\system") ||
            process.name().to_lowercase() == "system" ||
            process.name().to_lowercase() == "svchost.exe" ||
            process.name().to_lowercase().contains("csrss") ||
            process.name().to_lowercase().contains("lsass") ||
            process.name().to_lowercase().contains("services") ||
            process.name().to_lowercase().contains("winlogon")
        } else {
            false
        }
    }

    /// 扫描所有进程内存
    pub fn scan_all_processes(&self) -> Vec<MemoryScanResult> {
        let mut results = Vec::new();
        
        for (pid, process) in self.system.processes() {
            if self.is_system_process(*pid) {
                continue;
            }

            match self.scan_process_memory(*pid) {
                Ok(result) => results.push(result),
                Err(e) => {
                    log::warn!("Failed to scan process {} (PID: {}): {}", process.name(), pid, e);
                }
            }
        }

        results
    }

    /// 扫描单个进程内存
    pub fn scan_process_memory(&self, pid: Pid) -> Result<MemoryScanResult> {
        let process_name = self.system.process(pid)
            .map(|p| p.name().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        if self.is_system_process(pid) {
            return Ok(MemoryScanResult {
                pid,
                process_name,
                suspicious_regions: Vec::new(),
                is_malicious: false,
                reason: "System process skipped".to_string(),
                risk_score: 0,
            });
        }

        // 获取内存映射
        let memory_regions = self.get_process_memory_map(pid)?;
        let suspicious_regions = self.analyze_memory_regions(pid, &memory_regions)?;
        
        // 分析进程行为
        let behavior_analysis = self.analyze_process_behavior(pid);
        
        // 综合评估
        let (is_malicious, reason, risk_score) = self.evaluate_threat_level(
            &suspicious_regions, 
            &behavior_analysis
        );

        Ok(MemoryScanResult {
            pid,
            process_name,
            suspicious_regions,
            is_malicious,
            reason,
            risk_score,
        })
    }

    /// 获取进程内存映射
    fn get_process_memory_map(&self, pid: Pid) -> Result<Vec<MemoryRegion>> {
        let mut regions = Vec::new();
        
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid.as_u32());
            if handle.is_null() {
                return Err(anyhow!("Failed to open process PID {}", pid));
            }

            let mut address: usize = 0;
            let mut memory_basic_info = std::mem::zeroed::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>();

            while VirtualQueryEx(handle, address as *const _, &mut memory_basic_info, std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>()) != 0 {
                let protection = memory_basic_info.Protect;
                let is_executable = (protection & 0xF0) != 0; // PAGE_EXECUTE_*
                let is_writable = (protection & 0x0C) != 0;   // PAGE_READWRITE, PAGE_WRITECOPY
                
                let region_type = match memory_basic_info.Type {
                    0x1000000 => "MEM_IMAGE".to_string(),
                    0x40000 => "MEM_MAPPED".to_string(),
                    0x20000 => "MEM_PRIVATE".to_string(),
                    _ => "UNKNOWN".to_string(),
                };

                // 读取内存内容进行哈希计算
                let content_hash = self.read_and_hash_memory(handle, address, memory_basic_info.RegionSize)?;

                let region = MemoryRegion {
                    base_address: address,
                    size: memory_basic_info.RegionSize,
                    protection,
                    is_executable,
                    is_writable,
                    region_type,
                    content_hash,
                };
                
                regions.push(region);
                address = memory_basic_info.BaseAddress as usize + memory_basic_info.RegionSize;
            }

            CloseHandle(handle);
        }

        Ok(regions)
    }

    /// 读取内存内容并计算哈希
    fn read_and_hash_memory(&self, handle: winapi::um::winnt::HANDLE, address: usize, size: usize) -> Result<String> {
        if size == 0 || size > 1024 * 1024 { // 限制读取大小
            return Ok("skipped".to_string());
        }

        unsafe {
            let mut buffer = vec![0u8; size];
            let mut bytes_read = 0;

            let success = ReadProcessMemory(
                handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                size,
                &mut bytes_read,
            );

            if success == 0 {
                return Ok("read_failed".to_string());
            }

            // 计算SHA256哈希
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&buffer[..bytes_read]);
            let result = hasher.finalize();
            Ok(hex::encode(result))
        }
    }

    /// 分析内存区域
    fn analyze_memory_regions(&self, pid: Pid, regions: &[MemoryRegion]) -> Result<Vec<MemoryRegion>> {
        let mut suspicious_regions = Vec::new();
        let mut executable_writable_count = 0;

        for region in regions {
            // 检测可执行且可写的内存区域（代码注入的典型特征）
            if region.is_executable && region.is_writable {
                executable_writable_count += 1;
                suspicious_regions.push(region.clone());
            }

            // 检测私有可执行内存（可能是shellcode）
            if region.is_executable && region.region_type == "MEM_PRIVATE" {
                suspicious_regions.push(region.clone());
            }

            // 检测异常大的可执行区域
            if region.is_executable && region.size > 10 * 1024 * 1024 {
                suspicious_regions.push(region.clone());
            }
        }

        // 记录检测结果
        if executable_writable_count > 0 {
            log::info!("PID {}: Found {} executable+writable memory regions", pid, executable_writable_count);
        }

        Ok(suspicious_regions)
    }

    /// 分析进程行为
    fn analyze_process_behavior(&self, pid: Pid) -> HashMap<String, bool> {
        let mut behaviors = HashMap::new();

        // 检查进程是否注入其他进程
        behaviors.insert("process_injection".to_string(), self.check_process_injection(pid));
        
        // 检查是否有隐藏模块
        behaviors.insert("hidden_modules".to_string(), self.check_hidden_modules(pid));
        
        // 检查是否有可疑的线程
        behaviors.insert("suspicious_threads".to_string(), self.check_suspicious_threads(pid));

        behaviors
    }

    /// 检查进程注入
    fn check_process_injection(&self, pid: Pid) -> bool {
        // 简化实现 - 实际中需要更复杂的检测逻辑
        false
    }

    /// 检查隐藏模块
    fn check_hidden_modules(&self, pid: Pid) -> bool {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid.as_u32());
            if handle.is_null() {
                return false;
            }

            let mut modules = [std::ptr::null_mut(); 1024];
            let mut cb_needed = 0;

            let success = EnumProcessModules(
                handle,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<winapi::um::winnt::HMODULE>()) as u32,
                &mut cb_needed,
            );

            CloseHandle(handle);

            success != 0
        }
    }

    /// 检查可疑线程
    fn check_suspicious_threads(&self, pid: Pid) -> bool {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot.is_null() {
                return false;
            }

            let mut thread_entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..std::mem::zeroed()
            };

            let mut has_suspicious_threads = false;
            let mut thread_count = 0;

            if Process32First(snapshot, &mut thread_entry) == TRUE {
                while Process32Next(snapshot, &mut thread_entry) == TRUE {
                    if thread_entry.th32OwnerProcessID == pid.as_u32() {
                        thread_count += 1;
                        
                        // 检测异常线程特征
                        if thread_entry.tpBasePri != 8 { // 非标准优先级
                            has_suspicious_threads = true;
                        }
                    }
                }
            }

            CloseHandle(snapshot);

            // 如果线程数量异常多
            if thread_count > 50 {
                has_suspicious_threads = true;
            }

            has_suspicious_threads
        }
    }

    /// 评估威胁级别
    fn evaluate_threat_level(&self, suspicious_regions: &[MemoryRegion], behaviors: &HashMap<String, bool>) -> (bool, String, u8) {
        let mut risk_score = 0;
        let mut reasons = Vec::new();

        // 基于可疑内存区域评分
        let exec_writable_count = suspicious_regions.iter()
            .filter(|r| r.is_executable && r.is_writable)
            .count();

        if exec_writable_count > 0 {
            risk_score += exec_writable_count as u8 * 20;
            reasons.push(format!("{} executable+writable memory regions", exec_writable_count));
        }

        // 基于进程行为评分
        if behaviors.get("process_injection").copied().unwrap_or(false) {
            risk_score += 40;
            reasons.push("Process injection detected".to_string());
        }

        if behaviors.get("hidden_modules").copied().unwrap_or(false) {
            risk_score += 30;
            reasons.push("Hidden modules detected".to_string());
        }

        if behaviors.get("suspicious_threads").copied().unwrap_or(false) {
            risk_score += 25;
            reasons.push("Suspicious threads detected".to_string());
        }

        let is_malicious = risk_score > 50;
        let reason = if reasons.is_empty() {
            "No threats detected".to_string()
        } else {
            reasons.join("; ")
        };

        (is_malicious, reason, risk_score.min(100))
    }

    // === 进程控制函数 ===

    /// 终止进程
    pub fn terminate_process(&self, pid: Pid) -> bool {
        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, 0, pid.as_u32());
            if handle.is_null() {
                log::error!("Failed to open process for termination: PID {}", pid);
                return false;
            }

            let result = TerminateProcess(handle, 0);
            CloseHandle(handle);

            if result != 0 {
                log::info!("Successfully terminated process: PID {}", pid);
                true
            } else {
                log::error!("Failed to terminate process: PID {}", pid);
                false
            }
        }
    }

    /// 暂停进程
    pub fn suspend_process(&self, pid: Pid) -> bool {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot.is_null() {
                return false;
            }

            let mut thread_entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..std::mem::zeroed()
            };

            let mut success_count = 0;

            if Process32First(snapshot, &mut thread_entry) == TRUE {
                while Process32Next(snapshot, &mut thread_entry) == TRUE {
                    if thread_entry.th32OwnerProcessID == pid.as_u32() {
                        let thread_handle = OpenProcess(PROCESS_SUSPEND_RESUME, 0, thread_entry.th32ThreadID);
                        if !thread_handle.is_null() {
                            if SuspendThread(thread_handle) != u32::MAX {
                                success_count += 1;
                            }
                            CloseHandle(thread_handle);
                        }
                    }
                }
            }

            CloseHandle(snapshot);

            if success_count > 0 {
                log::info!("Suspended {} threads in process: PID {}", success_count, pid);
                true
            } else {
                log::error!("Failed to suspend process: PID {}", pid);
                false
            }
        }
    }

    /// 恢复进程
    pub fn resume_process(&self, pid: Pid) -> bool {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot.is_null() {
                return false;
            }

            let mut thread_entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..std::mem::zeroed()
            };

            let mut success_count = 0;

            if Process32First(snapshot, &mut thread_entry) == TRUE {
                while Process32Next(snapshot, &mut thread_entry) == TRUE {
                    if thread_entry.th32OwnerProcessID == pid.as_u32() {
                        let thread_handle = OpenProcess(PROCESS_SUSPEND_RESUME, 0, thread_entry.th32ThreadID);
                        if !thread_handle.is_null() {
                            if ResumeThread(thread_handle) != u32::MAX {
                                success_count += 1;
                            }
                            CloseHandle(thread_handle);
                        }
                    }
                }
            }

            CloseHandle(snapshot);

            if success_count > 0 {
                log::info!("Resumed {} threads in process: PID {}", success_count, pid);
                true
            } else {
                log::error!("Failed to resume process: PID {}", pid);
                false
            }
        }
    }

    /// 获取进程列表
    pub fn get_process_list(&self) -> Vec<ProcessInfo> {
        let mut processes = Vec::new();

        for (pid, process) in self.system.processes() {
            let exe_path = process.exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "Unknown".to_string());

            let parent_pid = process.parent().unwrap_or(Pid::from(0));

            processes.push(ProcessInfo {
                pid: *pid,
                name: process.name().to_string(),
                exe_path,
                parent_pid,
            });
        }

        processes
    }

    /// 强制终止进程树
    pub fn terminate_process_tree(&self, pid: Pid) -> bool {
        let processes = self.get_process_list();
        let mut to_terminate = vec![pid];
        
        // 查找子进程
        for process in &processes {
            if process.parent_pid == pid {
                to_terminate.push(process.pid);
            }
        }

        let mut all_success = true;
        for target_pid in to_terminate {
            if !self.terminate_process(target_pid) {
                all_success = false;
            }
        }

        all_success
    }
}

impl Default for MemoryScanner {
    fn default() -> Self {
        Self::new()
    }
}

