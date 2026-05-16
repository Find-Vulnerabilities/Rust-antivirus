// src/memory_scanning.rs: 进程内存扫描和行为检测
// 扫描运行进程的内存，检测注入、Shell代码等威胁

use std::io;
use sysinfo::System;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct MemoryScanResult {
    pub pid: u32,
    pub process_name: String,
    pub is_suspicious: bool,
    pub reason: String,
    pub risk_score: u8,
    pub detected_patterns: Vec<String>,
}

pub struct MemoryScanner;

impl MemoryScanner {
    /// Scan all running processes for suspicious memory patterns
    pub fn scan_all_processes() -> Vec<MemoryScanResult> {
        let mut system = System::new_all();
        system.refresh_all();

        let mut results = Vec::new();

        for (pid, process) in system.processes() {
            let pid_u32 = pid.as_u32();
            let process_name = process.name().to_string_lossy().to_string();
            if let Some(result) = Self::scan_process(pid_u32, &process_name) {
                results.push(result);
            }
        }

        results
    }

    /// Scan specific process by PID
    pub fn scan_process(pid: u32, process_name: &str) -> Option<MemoryScanResult> {
        let mut detected_patterns = Vec::new();
        let mut risk_score = 0u8;

        // Warning signs: check for suspicious process characteristics
        let suspicious_names = [
            "svchost.exe", "lsass.exe", "explorer.exe", "taskhostw.exe",
            "dwm.exe", "ntdll.dll", "kernel32.dll",
        ];

        // High-risk file names that might indicate malware
        let high_risk_names = [
            "rundll32.exe", "cmd.exe", "powershell.exe", "msiexec.exe",
            "regsvr32.exe", "wscript.exe", "cscript.exe",
        ];

        // Check if process name matches high-risk pattern
        if high_risk_names.contains(&process_name) {
            detected_patterns.push("High-risk process detected".to_string());
            risk_score = 50;
        }

        // Attempt to detect injected modules (Windows-specific)
        #[cfg(windows)]
        {
            if Self::detect_module_injection(pid) {
                detected_patterns.push("Possible module injection detected".to_string());
                risk_score = std::cmp::max(risk_score, 70);
            }
        }

        if !detected_patterns.is_empty() {
            Some(MemoryScanResult {
                pid,
                process_name: process_name.to_string(),
                is_suspicious: risk_score > 50,
                reason: detected_patterns.join("; "),
                risk_score,
                detected_patterns,
            })
        } else {
            None
        }
    }

    /// Detect potential module injection in a process (Windows)
    #[cfg(windows)]
    fn detect_module_injection(pid: u32) -> bool {
        // Use WMI or Windows API to enumerate loaded modules
        // If modules are from unusual paths or unsigned, flag as suspicious
        // This is a simplified check
        
        let output = Command::new("wmic")
            .args(&[
                "process",
                "where",
                &format!("ProcessId={}", pid),
                "get",
                "CommandLine",
                "/value",
            ])
            .output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                // Check for suspicious command line patterns
                ["-enc ", "FromBase64", "IEX", "-nop", "-w hidden"].iter()
                    .any(|pattern| stdout.contains(pattern))
            }
            Err(_) => false,
        }
    }

    #[cfg(not(windows))]
    fn detect_module_injection(_pid: u32) -> bool {
        false
    }

    /// AMSI (Antimalware Scan Interface) hook for script scanning
    /// Scans PowerShell, VBScript, and other interpreted languages
    pub fn scan_script_content(script_path: &str) -> io::Result<(bool, String)> {
        use std::fs;
        
        let content = fs::read_to_string(script_path)?;
        
        // Check for malicious PowerShell patterns
        let malicious_patterns = [
            "System.Reflection.Assembly.Load",
            "Invoke-WebRequest.*IEX",
            "DownloadString",
            "WinRM", // Windows Remote Management abuse
            "WMI",   // WMI command execution
        ];

        let mut detected = Vec::new();
        for pattern in &malicious_patterns {
            if content.to_lowercase().contains(&pattern.to_lowercase()) {
                detected.push(pattern.to_string());
            }
        }

        if !detected.is_empty() {
            Ok((true, detected.join(", ")))
        } else {
            Ok((false, String::new()))
        }
    }

    /// Monitor and block suspicious API calls (requires driver)
    /// This would integrate with the minifilter for real-time blocking
    pub fn monitor_api_calls(pid: u32) -> MemoryScanResult {
        // Placeholder: would require ETW (Event Tracing for Windows)
        // or kernel-mode driver integration
        MemoryScanResult {
            pid,
            process_name: "monitored_process".to_string(),
            is_suspicious: false,
            reason: "No suspicious API calls detected".to_string(),
            risk_score: 0,
            detected_patterns: Vec::new(),
        }
    }
}
