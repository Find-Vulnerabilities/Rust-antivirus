use std::ffi::{CString, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::ptr;
use std::os::raw::{c_char, c_int};
use rust_antivirus::yara_sys;

// Minimal hand-written FFI for a subset of libyara used by this project.
// Relies on build.rs to link the libyara static library.

const CALLBACK_MSG_RULE_MATCHING: c_int = 1;
const CALLBACK_CONTINUE: c_int = 0;

static YARA_MATCHED: AtomicBool = AtomicBool::new(false);

#[cfg(not(yara_stub))]
extern "C" {
    pub fn yr_initialize() -> c_int;
    pub fn yr_finalize() -> c_int;

    pub fn yr_rules_load(filename: *const c_char, rules: *mut *mut c_void) -> c_int;
    pub fn yr_rules_destroy(rules: *mut c_void) -> c_int;

    pub fn yr_rules_scan_file(
        rules: *mut c_void,
        filename: *const c_char,
        flags: c_int,
        callback: Option<extern "C" fn(c_int, *mut c_void, *mut c_void) -> c_int>,
        user_data: *mut c_void,
        timeout: c_int,
    ) -> c_int;

    pub fn yr_rules_scan_proc(
        rules: *mut c_void,
        pid: c_int,
        flags: c_int,
        callback: Option<extern "C" fn(c_int, *mut c_void, *mut c_void) -> c_int>,
        user_data: *mut c_void,
        timeout: c_int,
    ) -> c_int;

    pub fn yr_rules_scan_mem(
        rules: *mut c_void,
        buffer: *const u8,
        buffer_size: usize,
        flags: c_int,
        callback: Option<extern "C" fn(c_int, *mut c_void, *mut c_void) -> c_int>,
        user_data: *mut c_void,
        timeout: c_int,
    ) -> c_int;
}

#[cfg(yara_stub)]
#[no_mangle]
pub extern "C" fn yr_initialize() -> c_int { 0 }

#[cfg(yara_stub)]
#[no_mangle]
pub extern "C" fn yr_finalize() -> c_int { 0 }

#[cfg(yara_stub)]
#[no_mangle]
pub extern "C" fn yr_rules_load(_filename: *const c_char, rules: *mut *mut c_void) -> c_int {
    unsafe {
        if !rules.is_null() {
            let boxed: *mut i32 = Box::into_raw(Box::new(1));
            *(rules) = boxed as *mut c_void;
            return 0;
        }
    }
    -1
}

#[cfg(yara_stub)]
#[no_mangle]
pub extern "C" fn yr_rules_destroy(rules: *mut c_void) -> c_int {
    if rules.is_null() { return -1; }
    unsafe { Box::from_raw(rules as *mut i32); }
    0
}

#[cfg(yara_stub)]
#[no_mangle]
pub extern "C" fn yr_rules_scan_file(_rules: *mut c_void, _filename: *const c_char, _flags: c_int, _callback: Option<extern "C" fn(c_int, *mut c_void, *mut c_void) -> c_int>, _user_data: *mut c_void, _timeout: c_int) -> c_int { 0 }

#[cfg(yara_stub)]
#[no_mangle]
pub extern "C" fn yr_rules_scan_proc(_rules: *mut c_void, _pid: c_int, _flags: c_int, _callback: Option<extern "C" fn(c_int, *mut c_void, *mut c_void) -> c_int>, _user_data: *mut c_void, _timeout: c_int) -> c_int { 0 }

#[cfg(yara_stub)]
#[no_mangle]
pub extern "C" fn yr_rules_scan_mem(_rules: *mut c_void, _buffer: *const u8, _buffer_size: usize, _flags: c_int, _callback: Option<extern "C" fn(c_int, *mut c_void, *mut c_void) -> c_int>, _user_data: *mut c_void, _timeout: c_int) -> c_int { 0 }

extern "C" fn yara_callback(msg: c_int, _data: *mut c_void, _user: *mut c_void) -> c_int {
    if msg == CALLBACK_MSG_RULE_MATCHING {
        YARA_MATCHED.store(true, Ordering::Relaxed);
    }
    CALLBACK_CONTINUE
}

pub struct YaraEngine {
    rules: Option<*mut c_void>,
}

impl YaraEngine {
    pub fn new() -> Result<Self, String> {
        unsafe {
            if yr_initialize() != 0 {
                return Err("yr_initialize failed".into());
            }
        }
        Ok(Self { rules: None })
    }

    pub fn load_compiled_rules(&mut self, path: &str) -> Result<(), String> {
        let cpath = CString::new(path).map_err(|e| format!("CString error: {}", e))?;
        let mut rules_ptr: *mut c_void = ptr::null_mut();
        let rc = unsafe { yr_rules_load(cpath.as_ptr(), &mut rules_ptr) };
        if rc != 0 || rules_ptr.is_null() {
            Err(format!("yr_rules_load failed: {}", rc))
        } else {
            self.rules = Some(rules_ptr);
            Ok(())
        }
    }

    pub fn scan_file(&self, path: &std::path::Path) -> Result<bool, String> {
        if self.rules.is_none() {
            return Err("No rules loaded".into());
        }
        let cpath = CString::new(path.to_string_lossy().to_string())
            .map_err(|e| format!("CString error: {}", e))?;
        YARA_MATCHED.store(false, Ordering::Relaxed);
        let rules = self.rules.ok_or("No rules loaded")?;
        let rc = unsafe {
            yr_rules_scan_file(
                rules,
                cpath.as_ptr(),
                0,
                Some(yara_callback),
                ptr::null_mut(),
                0,
            )
        };
        if rc < 0 {
            return Err(format!("yr_rules_scan_file error: {}", rc));
        }
        Ok(YARA_MATCHED.load(Ordering::Relaxed))
    }

    pub fn scan_proc(&self, pid: i32) -> Result<bool, String> {
        if self.rules.is_none() {
            return Err("No rules loaded".into());
        }
        YARA_MATCHED.store(false, Ordering::Relaxed);
        let rules = self.rules.ok_or("No rules loaded")?;
        let rc = unsafe {
            yr_rules_scan_proc(rules, pid as c_int, 0, Some(yara_callback), ptr::null_mut(), 0)
        };
        if rc < 0 {
            return Err(format!("yr_rules_scan_proc error: {}", rc));
        }
        Ok(YARA_MATCHED.load(Ordering::Relaxed))
    }

    pub fn scan_mem(&self, buf: &[u8]) -> Result<bool, String> {
        if self.rules.is_none() {
            return Err("No rules loaded".into());
        }
        YARA_MATCHED.store(false, Ordering::Relaxed);
        let rules = self.rules.ok_or("No rules loaded")?;
        let rc = unsafe {
            yr_rules_scan_mem(rules, buf.as_ptr(), buf.len(), 0, Some(yara_callback), ptr::null_mut(), 0)
        };
        if rc < 0 {
            return Err(format!("yr_rules_scan_mem error: {}", rc));
        }
        Ok(YARA_MATCHED.load(Ordering::Relaxed))
    }
}

impl Drop for YaraEngine {
    fn drop(&mut self) {
        if let Some(r) = self.rules {
            unsafe { yr_rules_destroy(r); }
        }
        unsafe { yr_finalize(); }
    }
}

// Minimal main so Cargo treats this file as a valid binary when present in src/bin.
fn main() {
    // This binary is a helper module placeholder; actual usage is via library modules.
}
