// src/yara_sys.rs: YARA C API 的 Rust FFI 包裝
// 靜態鏈接 libyara.lib

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::os::raw::{c_char, c_int, c_void, c_uint};
use std::sync::Mutex;

pub const YARA_ERROR_SUCCESS: c_int = 0;
pub const YARA_SCAN_FLAGS_SHOW_STRINGS: c_uint = 0x0001;
pub const YARA_SCAN_FLAGS_SHOW_METADATA: c_uint = 0x0002;

// 回調消息類型
pub const CALLBACK_MSG_RULE_MATCHING: c_int = 1;
pub const CALLBACK_MSG_RULE_NOT_MATCHING: c_int = 2;
pub const CALLBACK_MSG_SCAN_FINISHED: c_int = 3;

pub const CALLBACK_CONTINUE: c_int = 0;
pub const CALLBACK_ABORT: c_int = 1;

// 錯誤代碼映射
pub fn error_code_to_string(code: c_int) -> &'static str {
    match code {
        0 => "ERROR_SUCCESS",
        1 => "ERROR_INSUFFICIENT_MEMORY",
        2 => "ERROR_COULD_NOT_ATTACH_TO_PROCESS",
        3 => "ERROR_COULD_NOT_OPEN_FILE",
        4 => "ERROR_COULD_NOT_MAP_FILE",
        6 => "ERROR_INVALID_FILE",
        7 => "ERROR_CORRUPT_FILE",
        8 => "ERROR_UNSUPPORTED_FILE_VERSION",
        9 => "ERROR_INVALID_REGULAR_EXPRESSION",
        10 => "ERROR_INVALID_HEX_STRING",
        11 => "ERROR_SYNTAX_ERROR",
        26 => "ERROR_SCAN_TIMEOUT",
        28 => "ERROR_CALLBACK_ERROR",
        30 => "ERROR_TOO_MANY_MATCHES",
        34 => "ERROR_UNKNOWN_MODULE",
        _ => "ERROR_UNKNOWN",
    }
}

// 不透明類型（opaque types）
#[repr(C)]
pub struct YR_RULES {
    _private: [u8; 0],
}

#[repr(C)]
pub struct YR_SCANNER {
    _private: [u8; 0],
}

#[repr(C)]
pub struct YR_SCAN_CONTEXT {
    _private: [u8; 0],
}

#[repr(C)]
pub struct YR_RULE {
    _private: [u8; 0],
}

#[repr(C)]
pub struct YR_STRING {
    _private: [u8; 0],
}

#[repr(C)]
pub struct YR_MATCH {
    _private: [u8; 0],
}

// YARA 回調消息結構體 - 規則匹配時的消息數據
#[repr(C)]
pub struct YR_RULE_MATCH {
    pub rule: *mut YR_RULE,
}

// 掃描回調類型 - YARA 4.5+ API
// Correct signature: context, message, message_data, user_data
pub type YR_CALLBACK_FUNC = extern "C" fn(
    context: *mut YR_SCAN_CONTEXT,
    message: c_int,
    message_data: *mut c_void,
    user_data: *mut c_void,
) -> c_int;

// 線程本地存儲，用於收集匹配規則
thread_local! {
    static MATCHED_RULES: Mutex<Vec<String>> = Mutex::new(Vec::new());
}

// ==================== 外部 C 函數綁定 ====================

#[link(name = "libyara", kind = "static")]
extern "C" {
    // 初始化與清理
    pub fn yr_initialize() -> c_int;
    pub fn yr_finalize() -> c_int;

    // 規則管理
    pub fn yr_rules_load(filename: *const c_char, rules: *mut *mut YR_RULES) -> c_int;
    pub fn yr_rules_destroy(rules: *mut YR_RULES) -> c_int;

    // 文件掃描 - 使用回調方式
    pub fn yr_rules_scan_file(
        rules: *mut YR_RULES,
        filename: *const c_char,
        flags: c_int,
        callback: YR_CALLBACK_FUNC,
        user_data: *mut c_void,
        timeout: c_int,
    ) -> c_int;

    // 內存掃描 - 使用回調方式
    pub fn yr_rules_scan_mem(
        rules: *mut YR_RULES,
        buffer: *const u8,
        buffer_size: usize,
        flags: c_int,
        callback: YR_CALLBACK_FUNC,
        user_data: *mut c_void,
        timeout: c_int,
    ) -> c_int;

    // 錯誤處理
    pub fn yr_get_last_error() -> c_int;
}

// ==================== 安全包裝函數 ====================

/// 初始化 YARA 庫
pub fn initialize_yara() -> Result<(), String> {
    unsafe {
        let result = yr_initialize();
        if result == YARA_ERROR_SUCCESS {
            Ok(())
        } else {
            Err(format!("yr_initialize failed with code: {}", result))
        }
    }
}

/// 清理 YARA 庫
pub fn finalize_yara() -> Result<(), String> {
    unsafe {
        let result = yr_finalize();
        if result == YARA_ERROR_SUCCESS {
            Ok(())
        } else {
            Err(format!("yr_finalize failed with code: {}", result))
        }
    }
}

/// 安全加載規則文件
pub fn load_rules(path: &str) -> Result<*mut YR_RULES, String> {
    use std::ffi::CString;

    let c_path = CString::new(path).map_err(|e| format!("Invalid path: {}", e))?;
    let mut rules: *mut YR_RULES = std::ptr::null_mut();

    unsafe {
        let result = yr_rules_load(c_path.as_ptr(), &mut rules);
        if result == YARA_ERROR_SUCCESS && !rules.is_null() {
            Ok(rules)
        } else {
            Err(format!("yr_rules_load failed with code: {}", result))
        }
    }
}

/// 安全銷毀規則
pub fn destroy_rules(rules: *mut YR_RULES) -> Result<(), String> {
    unsafe {
        let result = yr_rules_destroy(rules);
        if result == YARA_ERROR_SUCCESS {
            Ok(())
        } else {
            Err(format!("yr_rules_destroy failed with code: {}", result))
        }
    }
}

/// 提取所有已匹配的規則名稱（使用回調方式）
/// 返回一個空的 Vec，現在使用回調方式來處理匹配結果
pub fn extract_matched_rules(_rules: *mut YR_RULES) -> Result<Vec<String>, String> {
    // YARA 4.5 版本使用回調方式，不支持後期提取匹配規則
    // 請使用 YR_CALLBACK_FUNC 方式處理匹配結果
    Ok(Vec::new())
}

#[repr(C)]
struct YrRuleHeader {
    flags: i32,
    num_atoms: i32,
    identifier: *const std::os::raw::c_char,
}

/// 內部回調函數，用於收集掃描期間的匹配規則
extern "C" fn scan_callback(
    _context: *mut YR_SCAN_CONTEXT,
    message: c_int,
    message_data: *mut c_void,
    _user_data: *mut c_void,
) -> c_int {
    if message == CALLBACK_MSG_RULE_MATCHING {
        unsafe {
            // message_data 是 YR_RULE* 指針
            let rule = message_data as *mut YR_RULE;
            if !rule.is_null() {
                MATCHED_RULES.with(|mr| {
                    if let Ok(mut matches) = mr.lock() {
                        let header = rule as *const YrRuleHeader;
                        let c_str = std::ffi::CStr::from_ptr((*header).identifier);
                        matches.push(c_str.to_string_lossy().into_owned());
                    }
                });
            }
        }
    }
    CALLBACK_CONTINUE
}

/// 執行掃描並收集匹配規則（YARA 4.5 兼容版本）
pub fn scan_file_with_callback(path: &str, rules: *mut YR_RULES) -> Result<Vec<String>, String> {
    use std::ffi::CString;
    
    // 清空之前的匹配結果
    MATCHED_RULES.with(|mr| {
        if let Ok(mut matches) = mr.lock() {
            matches.clear();
        }
    });

    let c_path = CString::new(path).map_err(|e| format!("Invalid path: {}", e))?;

    unsafe {
        let result = yr_rules_scan_file(
            rules,
            c_path.as_ptr(),
            0,  // flags
            scan_callback,  // 使用我們的回調函數
            std::ptr::null_mut(),  // user_data
            0,  // timeout
        );

        if result != YARA_ERROR_SUCCESS {
            return Err(format!("Scan failed with code: {}", result));
        }
    }

    // 返回收集到的匹配規則
    MATCHED_RULES.with(|mr| {
        mr.lock()
            .map(|m| m.clone())
            .map_err(|e| format!("Failed to lock matches: {}", e))
    })
}