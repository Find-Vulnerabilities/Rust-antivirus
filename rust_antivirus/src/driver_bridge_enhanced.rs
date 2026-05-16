use std::ffi::CString;
use std::io;
use std::os::raw::c_int;
use std::ptr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use winapi::um::fileapi::{CreateFileA, ReadFile, WriteFile};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, HANDLE};
use std::os::raw::c_void;
use winapi::um::ioapiset::DeviceIoControl;
use winapi::shared::minwindef::{DWORD, LPVOID, LPDWORD, FALSE};
use winapi::um::processthreadsapi::{OpenProcess, TerminateProcess};
use winapi::um::winnt::{PROCESS_TERMINATE, PROCESS_QUERY_INFORMATION};
use crate::engine::AntivirusEngine;
use crate::behavior_monitor::BehaviorMonitor;
use crate::memory_scanner::MemoryScanner;
use log;
use std::path::Path;
use std::fs;

const OPEN_EXISTING: u32 = 3;

#[repr(transparent)]
#[derive(Clone, Copy)]
struct SendableHandle(HANDLE);

unsafe impl Send for SendableHandle {}
unsafe impl Sync for SendableHandle {}

#[repr(C)]
pub enum MessageType {
    ScanRequest = 1,
    ScanResponse = 2,
}

#[repr(C, packed)]
pub struct ScanRequestMessage {
    pub message_type: u32,
    pub message_length: DWORD,
    pub process_id: DWORD,
    pub file_path: [u16; 512],
    pub file_size: u64,
    pub file_attributes: DWORD,
}

#[repr(C, packed)]
pub struct ScanResponseMessage {
    pub message_type: u32,
    pub message_length: DWORD,
    pub is_malicious: u8,
    pub threat_level: DWORD,
    pub threat_name: [u16; 256],
}

#[link(name = "fltlib")]
extern "system" {
    fn FilterConnectCommunicationPort(
        lpPortName: winapi::um::winnt::LPCWSTR,
        dwOptions: DWORD,
        lpContext: LPVOID,
        wSizeOfContext: winapi::shared::minwindef::WORD,
        lpSecurityAttributes: LPVOID,
        hPort: *mut HANDLE
    ) -> winapi::shared::ntdef::HRESULT;

    fn FilterGetMessage(
        hPort: HANDLE,
        lpMessageBuffer: LPVOID,
        dwMessageBufferSize: DWORD,
        lpOverlapped: LPVOID
    ) -> winapi::shared::ntdef::HRESULT;

    fn FilterReplyMessage(
        hPort: HANDLE,
        lpReplyBuffer: LPVOID,
        dwReplyBufferSize: DWORD
    ) -> winapi::shared::ntdef::HRESULT;
}

#[repr(C)]
pub struct FilterMessageHeader {
    pub reply_length: DWORD,
    pub message_id: u64,
}

#[repr(C)]
pub struct FilterReplyHeader {
    pub status: winapi::shared::ntdef::NTSTATUS,
    pub message_id: u64,
}

pub struct DriverInterface {
    handle: Option<HANDLE>,
}

impl DriverInterface {
    pub fn open(port_name: &str) -> io::Result<Self> {
        let mut port_name_wide = vec![0u16; 100];
        Self::string_to_wide(port_name, &mut port_name_wide);
        
        let mut handle: HANDLE = ptr::null_mut();
        
        let secret = b"WENLE_ANTIVIRUS_SECRET_2026\0";
        
        let hr = unsafe {
            FilterConnectCommunicationPort(
                port_name_wide.as_ptr(),
                0,
                secret.as_ptr() as LPVOID,
                secret.len() as winapi::shared::minwindef::WORD,
                ptr::null_mut(),
                &mut handle
            )
        };
        
        if hr < 0 {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("FilterConnectCommunicationPort failed matching HRESULT 0x{:08X}", hr as u32)));
        }
        Ok(DriverInterface { handle: Some(handle) })
    }

    pub fn is_available(&self) -> bool {
        self.handle.is_some()
    }

    pub fn device_ioctl(&self, code: u32, in_buf: Option<&[u8]>, out_buf: Option<&mut [u8]>) -> io::Result<u32> {
        let h = self.handle.ok_or(io::Error::new(io::ErrorKind::NotConnected, "Driver not open"))?;
        let (in_ptr, in_len) = match in_buf {
            Some(b) => (b.as_ptr() as LPVOID, b.len() as DWORD),
            None => (ptr::null_mut(), 0),
        };
        let (out_ptr, out_len) = match out_buf {
            Some(b) => (b.as_mut_ptr() as LPVOID, b.len() as DWORD),
            None => (ptr::null_mut(), 0),
        };
        let mut bytes_returned: DWORD = 0;
        let res = unsafe {
            DeviceIoControl(
                h,
                code,
                in_ptr,
                in_len,
                out_ptr,
                out_len,
                &mut bytes_returned as LPDWORD,
                ptr::null_mut(),
            )
        };
        if res == FALSE {
            Err(io::Error::last_os_error())
        } else {
            Ok(bytes_returned)
        }
    }

    pub fn wide_to_string(wide_str: &[u16]) -> String {
        use std::os::windows::ffi::OsStringExt;
        use std::ffi::OsString;
        
        let len = wide_str.iter().position(|&c| c == 0).unwrap_or(wide_str.len());
        let wide_slice = &wide_str[..len];
        
        OsString::from_wide(wide_slice)
            .to_string_lossy()
            .into_owned()
    }

    pub fn string_to_wide(s: &str, buffer: &mut [u16]) {
        use std::os::windows::ffi::OsStrExt;
        use std::ffi::OsStr;
        
        let wide: Vec<u16> = OsStr::new(s)
            .encode_wide()
            .chain(Some(0))
            .collect();
        
        let len = std::cmp::min(wide.len(), buffer.len());
        buffer[..len].copy_from_slice(&wide[..len]);
    }

    pub fn connect_to_minifilter(
        engine: Arc<AntivirusEngine>,
        behavior_monitor: Arc<BehaviorMonitor>,
        memory_scanner: Arc<crate::memory_scanner::MemoryScanner>
    ) -> io::Result<()> {
        let mut port_name = vec![0u16; 50];
        Self::string_to_wide("\\WenlePort", &mut port_name);
        
        let mut handle: HANDLE = std::ptr::null_mut();
        
        // [CRITICAL FIX] 2. Anti-Spoofing: 通訊防偽造 (Connection Secret)
        // Pass the digital signature simulation / secret key when connecting
        let secret = b"WENLE_ANTIVIRUS_SECRET_2026\0";
        
        let hr = unsafe {
            FilterConnectCommunicationPort(
                port_name.as_ptr(),
                0,
                secret.as_ptr() as LPVOID,
                secret.len() as winapi::shared::minwindef::WORD,
                std::ptr::null_mut(),
                &mut handle
            )
        };
        
        if hr < 0 {
            log::warn!("WenleMinifilter port not loaded (HRESULT 0x{:08X})", hr as u32);
            return Ok(());
        }
        
        log::info!("✓ WenleMinifilter FilterConnectCommunicationPort connected successfully");
        let sendable_handle = SendableHandle(handle);
        
        thread::spawn(move || {
            log::info!("Driver FilterGetMessage listener started");
            Self::driver_flt_listener(sendable_handle, engine, behavior_monitor, memory_scanner);
        });
        
        Ok(())
    }

    fn driver_flt_listener(
        handle: SendableHandle,
        engine: Arc<AntivirusEngine>,
        behavior_monitor: Arc<crate::behavior_monitor::BehaviorMonitor>,
        memory_scanner: Arc<crate::memory_scanner::MemoryScanner>
    ) {
        let handle = handle.0;
        
        #[repr(C, packed)]
        struct FltMessageBuffer {
            header: FilterMessageHeader,
            payload: ScanRequestMessage,
        }
        
        #[repr(C, packed)]
        struct FltReplyBuffer {
            header: FilterReplyHeader,
            payload: ScanResponseMessage,
        }

        let mut request_buf = FltMessageBuffer {
            header: FilterMessageHeader { reply_length: 0, message_id: 0 },
            payload: unsafe { std::mem::zeroed() }
        };

        loop {
            let hr = unsafe {
                FilterGetMessage(
                    handle,
                    &mut request_buf as *mut _ as LPVOID,
                    std::mem::size_of::<FltMessageBuffer>() as DWORD,
                    std::ptr::null_mut(),
                )
            };

            if hr < 0 {
                log::error!("FilterGetMessage failed: 0x{:08X}", hr as u32);
                break;
            }
            
            let request = &request_buf.payload;
            let file_path_arr = { request.file_path };
            let file_path = Self::wide_to_string(&file_path_arr);
            let msg_type = { request.message_type };
            let req_process_id = { request.process_id };
            
            // Check message_type: 1=Create, 2=Write, 3=ImageLoad
            if msg_type == 3 {
                log::info!("[Minifilter ImageLoad] PID: {}, File: {}", req_process_id, file_path);
                let mem_threats = memory_scanner.scan_process_memory(sysinfo::Pid::from_u32(req_process_id as u32)).unwrap_or_else(|_| crate::memory_scanner::MemoryScanResult {
                    pid: sysinfo::Pid::from_u32(0),
                    process_name: String::new(),
                    suspicious_regions: vec![],
                    is_malicious: false,
                    reason: String::new(),
                    risk_score: 0,
                });
                if !mem_threats.suspicious_regions.is_empty() {
                    log::warn!("🚧 Memory scanner found threats in PID {}: {:?}", req_process_id, mem_threats.suspicious_regions);
                }
                
                // Allow ImageLoad without blocking
                let mut reply_buf = FltReplyBuffer {
                    header: FilterReplyHeader { status: 0, message_id: request_buf.header.message_id },
                    payload: ScanResponseMessage { message_type: 2, message_length: 532, is_malicious: 0, threat_level: 0, threat_name: [0; 256] }
                };
                unsafe { FilterReplyMessage(handle, &mut reply_buf as *mut _ as LPVOID, std::mem::size_of::<FltReplyBuffer>() as DWORD); }
                continue;
            }

            log::info!("[Minifilter Intercept] PID: {}, File: {}", req_process_id, file_path);

            // Behavior Eval Check
            let mut behavior_is_malicious = false;
            let access_type = if msg_type == 2 { "write" } else { "execute" };
            if let Ok((action, reason)) = behavior_monitor.handle_file_access_interception(
                req_process_id as u32,
                "Unknown",
                &file_path,
                access_type
            ) {
                if format!("{:?}", action).contains("Block") {
                    behavior_is_malicious = true;
                    log::warn!("🚧 Behavior monitor blocked PID {}: {}", req_process_id, reason);
                }
            }

            let scan_result = engine.scan_file(Path::new(&file_path));
            let mut is_malicious = false;
            
            if scan_result.threat_detected {
                is_malicious = true;
            }

            is_malicious = is_malicious || behavior_is_malicious;

            if is_malicious {
                log::warn!("🚧 Minifilter BLOCKED Execution of {}", file_path);
            } else {
                log::info!("✅ Minifilter ALLOWED Execution of {}", file_path);
            }

            let mut reply_buf = FltReplyBuffer {
                header: FilterReplyHeader { status: 0, message_id: request_buf.header.message_id },
                payload: ScanResponseMessage {
                    message_type: 2,
                    message_length: std::mem::size_of::<ScanResponseMessage>() as DWORD,
                    is_malicious: if is_malicious { 1 } else { 0 },
                    threat_level: if is_malicious { 100 } else { 0 },
                    threat_name: [0u16; 256],
                },
            };

            let hr_reply = unsafe {
                FilterReplyMessage(
                    handle,
                    &mut reply_buf as *mut _ as LPVOID,
                    std::mem::size_of::<FltReplyBuffer>() as DWORD,
                )
            };

            if hr_reply < 0 {
                log::warn!("FilterReplyMessage failed: 0x{:08X}", hr_reply as u32);
            }
        }
    }
}
