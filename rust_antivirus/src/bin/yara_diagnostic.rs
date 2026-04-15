/// Diagnostic test to check YARA rule loading and scanning
use std::ffi::CString;
use std::path::Path;
use std::os::raw::c_int;

fn main() {
    println!("════════════════════════════════════════════════════════════");
    println!("  YARA 诊断测试 - 直接调用 C API");
    println!("════════════════════════════════════════════════════════════\n");

    // Get executable directory
    let exe_path = std::env::current_exe().expect("Failed to get exe path");
    let exe_dir = exe_path.parent().expect("Failed to get exe dir");

    let rules_path = exe_dir.join("test_rules.yarac");
    let target_file = exe_dir.join("test.txt");

    println!("📋 规则文件: {}", rules_path.display());
    println!("📋 扫描目标: {}\n", target_file.display());

    // Check files exist
    if !rules_path.exists() {
        eprintln!("❌ 规则文件不存在");
        return;
    }
    if !target_file.exists() {
        eprintln!("❌ 目标文件不存在");
        return;
    }
    println!("✓ 文件都存在\n");

    unsafe {
        // Initialize YARA
        println!("🚀 初始化 YARA...");
        let init_result = rust_antivirus::yara_sys::yr_initialize();
        println!("  初始化返回值: {}", init_result);
        if init_result != 0 {
            eprintln!("❌ 初始化失败");
            return;
        }
        println!("✓ 初始化成功\n");

        // Load rules
        println!("📦 加载规则...");
        let c_rules_path = CString::new(rules_path.to_string_lossy().into_owned())
            .expect("Failed to create CString");
        let mut rules_ptr: *mut rust_antivirus::yara_sys::YR_RULES = std::ptr::null_mut();
        let load_result = rust_antivirus::yara_sys::yr_rules_load(
            c_rules_path.as_ptr(),
            &mut rules_ptr,
        );
        println!("  加载返回值: {}", load_result);
        if load_result != 0 {
            let error_str = rust_antivirus::yara_sys::error_code_to_string(load_result);
            eprintln!("❌ 加载规则失败: {} ({})", load_result, error_str);
            return;
        }
        println!("  规则指针: {:?}", rules_ptr);
        if rules_ptr.is_null() {
            eprintln!("❌ 规则指针为空");
            return;
        }
        println!("✓ 规则加载成功\n");

        // Scan file
        println!("🔍 扫描文件...");
        let c_file_path = CString::new(target_file.to_string_lossy().into_owned())
            .expect("Failed to create CString");
        
        let mut match_count: i32 = 0;
        let user_data = &mut match_count as *mut i32 as *mut std::os::raw::c_void;
        
        let scan_result = rust_antivirus::yara_sys::yr_rules_scan_file(
            rules_ptr,
            c_file_path.as_ptr(),
            0,  // flags = 0
            test_callback,
            user_data,
            0,  // no timeout
        );
        println!("  扫描返回值: {}", scan_result);
        if scan_result != 0 && scan_result != 34 {
            let error_str = rust_antivirus::yara_sys::error_code_to_string(scan_result);
            eprintln!("❌ 扫描失败: {} ({})", scan_result, error_str);
        }
        println!("  检测到的匹配数: {}\n", match_count);

        // Cleanup
        println!("🧹 清理资源...");
        let destroy_result = rust_antivirus::yara_sys::yr_rules_destroy(rules_ptr);
        println!("  销毁返回值: {}", destroy_result);
        
        let finalize_result = rust_antivirus::yara_sys::yr_finalize();
        println!("  终止返回值: {}", finalize_result);
    }

    println!("\n════════════════════════════════════════════════════════════");
    println!("  诊断完成");
    println!("════════════════════════════════════════════════════════════");
}

extern "C" fn test_callback(
    _context: *mut rust_antivirus::yara_sys::YR_SCAN_CONTEXT,
    message: c_int,
    _message_data: *mut std::os::raw::c_void,
    user_data: *mut std::os::raw::c_void,
) -> c_int {
    if message == rust_antivirus::yara_sys::CALLBACK_MSG_RULE_MATCHING {
        println!("  [CALLBACK] 规则匹配!");
        if !user_data.is_null() {
            let count = user_data as *mut i32;
            unsafe {
                *count += 1;
                println!("    匹配计数: {}", *count);
            }
        }
    } else if message == rust_antivirus::yara_sys::CALLBACK_MSG_RULE_NOT_MATCHING {
        println!("  [CALLBACK] 规则不匹配");
    } else if message == rust_antivirus::yara_sys::CALLBACK_MSG_SCAN_FINISHED {
        println!("  [CALLBACK] 扫描完成");
    } else {
        println!("  [CALLBACK] 未知消息类型: {}", message);
    }
    rust_antivirus::yara_sys::CALLBACK_CONTINUE
}
