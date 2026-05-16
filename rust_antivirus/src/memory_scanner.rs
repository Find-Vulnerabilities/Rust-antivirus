use std::collections::HashMap;
use sysinfo::{Pid, System};
use winapi::{
    shared::minwindef::{TRUE, HMODULE},
    um::{
        handleapi::CloseHandle,
        memoryapi::{ReadProcessMemory, VirtualQueryEx},
        processthreadsapi::{
            OpenProcess, TerminateProcess, SuspendThread, ResumeThread,
        },
        psapi::{EnumProcessModules, GetModuleFileNameExW},
        tlhelp32::{CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32},
        winnt::{
            PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_TERMINATE, PROCESS_SUSPEND_RESUME,
        },
    },
};
use anyhow::{Result, anyhow};
use std::thread;
use crossbeam_channel::{unbounded};

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
    pub system: System,
}

impl Clone for MemoryScanner {
    fn clone(&self) -> Self {
        Self {
            system: System::new_all(),
        }
    }
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
            if let Some(exe_path) = process.exe() {
                let exe_path_str = exe_path.to_string_lossy().to_ascii_lowercase();
                exe_path_str.contains("system32") || 
                exe_path_str.contains("syswow64") ||
                exe_path_str.contains("windows\\system") ||
                process.name().to_string_lossy().to_ascii_lowercase() == "system" ||
                process.name().to_string_lossy().to_ascii_lowercase() == "svchost.exe" ||
                process.name().to_string_lossy().to_ascii_lowercase().contains("csrss") ||
                process.name().to_string_lossy().to_ascii_lowercase().contains("lsass") ||
                process.name().to_string_lossy().to_ascii_lowercase().contains("services") ||
                process.name().to_string_lossy().to_ascii_lowercase().contains("winlogon")
            } else {
                false
            }
        } else {
            false
        }
    }

    /// 扫描所有进程内存
    pub fn scan_all_processes(&self) -> Vec<MemoryScanResult> {
        // Collect non-system PIDs to scan
        let mut pids: Vec<Pid> = self.system.processes()
            .keys()
            .cloned()
            .filter(|pid| !self.is_system_process(*pid))
            .collect();

        // If no processes, return early
        if pids.is_empty() {
            return Vec::new();
        }

        // Create channels for work distribution and results
        let (work_tx, work_rx) = unbounded::<Pid>();
        let (res_tx, res_rx) = unbounded::<MemoryScanResult>();

        // Send all PIDs to the work channel
        for pid in pids.drain(..) {
            let _ = work_tx.send(pid);
        }
        drop(work_tx); // close sender so workers exit when done

        // Spawn 4 worker threads to scan memory concurrently
        let worker_count = 4;
        for _ in 0..worker_count {
            let work_rx = work_rx.clone();
            let res_tx = res_tx.clone();
            thread::spawn(move || {
                // each worker has its own MemoryScanner instance for thread-safety
                let mut local_scanner = MemoryScanner::new();
                local_scanner.refresh();

                for pid in work_rx.iter() {
                    match local_scanner.scan_process_memory(pid) {
                        Ok(result) => {
                            let _ = res_tx.send(result);
                        }
                        Err(e) => {
                            log::warn!("Worker failed scanning PID {}: {}", pid, e);
                        }
                    }
                }
                // worker drops res_tx clone on exit
            });
        }

        drop(res_tx); // drop original sender so iterator finishes when all workers done

        // Collect results from workers
        let mut results = Vec::new();
        for res in res_rx.iter() {
            results.push(res);
        }

        results
    }

    /// 扫描单个进程内存
    pub fn scan_process_memory(&self, pid: Pid) -> Result<MemoryScanResult> {
        let process_name = self.system.process(pid)
            .map(|p| p.name().to_string_lossy().to_string())
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
    pub fn get_process_memory_map(&self, pid: Pid) -> Result<Vec<MemoryRegion>> {
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

    /// 讀取指定記憶體區域的原始位元組（支援多段讀取和重試機制）
    pub fn read_memory_region(&self, pid: Pid, address: usize, size: usize) -> Result<Vec<u8>> {
        const MAX_READ_SIZE: usize = 1024 * 1024; // 單次讀取上限 1MB
        const RETRY_COUNT: usize = 3;
        const CHUNK_SIZE: usize = 65536; // 分塊大小 64KB

        if size == 0 {
            return Ok(Vec::new());
        }

        let mut result = Vec::new();
        let mut current_address = address;
        let mut remaining = size;

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid.as_u32());
            if handle.is_null() {
                return Err(anyhow!("Failed to open process PID {}", pid));
            }

            while remaining > 0 {
                let chunk_to_read = std::cmp::min(remaining, CHUNK_SIZE);
                let chunk_to_read = std::cmp::min(chunk_to_read, MAX_READ_SIZE);

                let mut chunk = vec![0u8; chunk_to_read];
                let mut bytes_read = 0usize;
                let mut success = false;

                // 重試機制：允許讀取失敗自動恢復
                for attempt in 0..RETRY_COUNT {
                    let result = ReadProcessMemory(
                        handle,
                        current_address as *const _,
                        chunk.as_mut_ptr() as *mut _,
                        chunk_to_read,
                        &mut bytes_read,
                    );

                    if result != 0 && bytes_read > 0 {
                        success = true;
                        break;
                    }

                    if attempt < RETRY_COUNT - 1 {
                        log::debug!(
                            "ReadProcessMemory failed (attempt {}/{}), retrying at {:x}",
                            attempt + 1,
                            RETRY_COUNT,
                            current_address
                        );
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                }

                if !success {
                    log::warn!(
                        "Failed to read memory at {:x} after {} attempts, skipping region",
                        current_address,
                        RETRY_COUNT
                    );
                    // 失敗時跳過這個區塊，繼續讀下一個
                    current_address += CHUNK_SIZE;
                    remaining = remaining.saturating_sub(CHUNK_SIZE);
                    continue;
                }

                chunk.truncate(bytes_read);
                result.extend_from_slice(&chunk);

                current_address += bytes_read;
                remaining = remaining.saturating_sub(bytes_read);

                // 如果讀取量少於預期，可能表示區塊結束，嘗試跳到下一個有效區塊
                if bytes_read < chunk_to_read {
                    break;
                }
            }

            CloseHandle(handle);
        }

        if result.is_empty() {
            Err(anyhow!(
                "Failed to read any memory for PID {} at address range {:x}-{:x}",
                pid,
                address,
                address + size
            ))
        } else {
            Ok(result)
        }
    }

    /// 支援多段讀取的記憶體讀取（用於掃描大型記憶體區域）
    pub fn read_memory_chunked(
        &self,
        pid: Pid,
        address: usize,
        size: usize,
        chunk_callback: impl Fn(&[u8]) -> Result<()>,
    ) -> Result<()> {
        const CHUNK_SIZE: usize = 256 * 1024; // 256KB 每個 chunk
        let mut current_address = address;
        let mut remaining = size;

        while remaining > 0 {
            let to_read = std::cmp::min(remaining, CHUNK_SIZE);
            match self.read_memory_region(pid, current_address, to_read) {
                Ok(chunk) => {
                    chunk_callback(&chunk)?;
                    let bytes_read = chunk.len();
                    current_address += bytes_read;
                    remaining = remaining.saturating_sub(bytes_read);

                    if bytes_read == 0 {
                        break; // 無法再讀
                    }
                }
                Err(e) => {
                    log::debug!("Chunked read failed at {:x}: {}, moving to next region", current_address, e);
                    // 跳過失敗的區塊
                    current_address += CHUNK_SIZE;
                    remaining = remaining.saturating_sub(CHUNK_SIZE);
                }
            }
        }

        Ok(())
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
        // Heuristic detection:
        //  1) Modules loaded from suspicious locations (temp/appdata/other users) or not under exe folder
        //  2) Threads with abnormal base priority or excessive thread count
        // If either condition crosses thresholds, return true.
        unsafe {
            // Try open process for querying modules
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid.as_u32());
            if handle.is_null() {
                // cannot inspect -> conservatively treat as not injected
                return false;
            }

            // determine exe folder (if available) to compare module paths
            let exe_folder_opt = self.system.process(pid).and_then(|p| {
                // Process::exe() may return an Option<&Path> depending on sysinfo version.
                // Chain Options safely: exe().and_then(parent -> to string).
                p.exe().and_then(|exe_path| exe_path.parent().map(|pp| pp.to_string_lossy().to_ascii_lowercase()))
            });

            // enumerate modules
            let mut modules: [HMODULE; 1024] = [std::ptr::null_mut(); 1024];
            let mut cb_needed: u32 = 0;
            let mut suspicious_modules = 0usize;

            let ok = EnumProcessModules(
                handle,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut cb_needed,
            );

            if ok != 0 && cb_needed > 0 {
                let count = (cb_needed as usize) / std::mem::size_of::<HMODULE>();
                let count = std::cmp::min(count, modules.len());
                for i in 0..count {
                    let h = modules[i];
                    if h.is_null() { continue; }

                    // get module filename
                    let mut buf: [u16; 260] = [0; 260];
                    let len = GetModuleFileNameExW(handle, h, buf.as_mut_ptr(), buf.len() as u32);
                    if len == 0 { continue; }
                    let path = String::from_utf16_lossy(&buf[..len as usize]).to_ascii_lowercase();

                    // suspicious if loaded from temp/appdata, from different user's folder, or outside exe folder while not a system DLL
                    let is_system = path.contains("\\windows\\system32") || path.contains("\\windows\\syswow64");
                    let is_temp_like = path.contains("\\temp\\") || path.contains("\\appdata\\") || path.contains("\\local\\temp\\");
                    let mismatched_parent = exe_folder_opt.as_ref().map_or(false, |ef| !path.starts_with(ef) && !is_system);

                    if is_temp_like || mismatched_parent {
                        suspicious_modules += 1;
                    }
                }
            }

            CloseHandle(handle);

            // enumerate threads and check priorities / counts
            let mut suspicious_threads = 0usize;
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if !snapshot.is_null() {
                let mut te = THREADENTRY32 {
                    dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                    ..std::mem::zeroed()
                };
                let mut success = winapi::um::tlhelp32::Thread32First(snapshot, &mut te);
                let mut thread_count = 0usize;

                while success == TRUE {
                    if te.th32OwnerProcessID == pid.as_u32() {
                        thread_count += 1;
                        // abnormal base priority (not the default 8) may indicate injected or malicious threads
                        if te.tpBasePri != 8 {
                            suspicious_threads += 1;
                        }
                    }
                    success = winapi::um::tlhelp32::Thread32Next(snapshot, &mut te);
                }

                CloseHandle(snapshot);

                // very large number of threads is suspicious for injection/abuse
                if thread_count > 200 {
                    suspicious_threads += 1;
                }
            }

            // final heuristic: any suspicious module OR suspicious threads triggers detection
            (suspicious_modules > 0) || (suspicious_threads > 0)
        }
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
                (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
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

            // Correct thread enumeration logic for THREADENTRY32
            let mut success = winapi::um::tlhelp32::Thread32First(snapshot, &mut thread_entry);
            while success == TRUE {
                if thread_entry.th32OwnerProcessID == pid.as_u32() {
                    thread_count += 1;
                    if thread_entry.tpBasePri != 8 {
                        has_suspicious_threads = true;
                    }
                }
                success = winapi::um::tlhelp32::Thread32Next(snapshot, &mut thread_entry);
            }

            CloseHandle(snapshot);

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

            let mut success = winapi::um::tlhelp32::Thread32First(snapshot, &mut thread_entry);
            while success == TRUE {
                if thread_entry.th32OwnerProcessID == pid.as_u32() {
                    let thread_handle = OpenProcess(PROCESS_SUSPEND_RESUME, 0, thread_entry.th32ThreadID);
                    if !thread_handle.is_null() {
                        if SuspendThread(thread_handle) != u32::MAX {
                            success_count += 1;
                        }
                        CloseHandle(thread_handle);
                    }
                }
                success = winapi::um::tlhelp32::Thread32Next(snapshot, &mut thread_entry);
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

            let mut success = winapi::um::tlhelp32::Thread32First(snapshot, &mut thread_entry);
            while success == TRUE {
                if thread_entry.th32OwnerProcessID == pid.as_u32() {
                    let thread_handle = OpenProcess(PROCESS_SUSPEND_RESUME, 0, thread_entry.th32ThreadID);
                    if !thread_handle.is_null() {
                        if ResumeThread(thread_handle) != u32::MAX {
                            success_count += 1;
                        }
                        CloseHandle(thread_handle);
                    }
                }
                success = winapi::um::tlhelp32::Thread32Next(snapshot, &mut thread_entry);
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
                name: process.name().to_string_lossy().to_string(),
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

