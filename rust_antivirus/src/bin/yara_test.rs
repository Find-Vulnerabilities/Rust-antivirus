// Simple YARA diagnostic test program
use std::path::Path;
use rust_antivirus::yara_sys;

fn main() {
    // Initialize logging
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Debug)
        .format_timestamp_secs()
        .init();

    println!("\n════════════════════════════════════════════════════════════");
    println!("  YARA 引擎诊断测试");
    println!("════════════════════════════════════════════════════════════\n");

    // Get the release directory
    let exe_path = std::env::current_exe().expect("Failed to get exe path");
    let exe_dir = exe_path.parent().expect("Failed to get exe directory");
    
    println!("📁 可执行文件目录: {:?}", exe_dir);

    // Build paths
    let rules_path = exe_dir.join("anti.yarac");
    let yara_lib_path = exe_dir.join("yara.lib");

    println!("📋 路径检查:");
    println!("  规则文件: {:?}", rules_path);
    println!("    存在: {}", rules_path.exists());
    
    println!("  YARA 库: {:?}", yara_lib_path);
    println!("    存在: {}", yara_lib_path.exists());

    // Try to initialize YARA
    println!("\n🚀 初始化 YARA 引擎...");
    match rust_antivirus::yara_engine::YaraEngine::init() {
        Ok(_) => println!("✓ YARA 引擎初始化成功"),
        Err(e) => {
            println!("✗ YARA 初始化失败: {}", e);
            return;
        }
    }

    // Try to load rules
    let rules_path_str = rules_path.to_string_lossy();
    println!("\n📦 加载规则文件: {}", rules_path_str);
    
    match rust_antivirus::yara_engine::YaraEngine::with_rules(&rules_path_str) {
        Ok(engine) => {
            println!("✓ 规则加载成功");

            // Create test file
            let test_dir = exe_dir.join("test_files");
            let _ = std::fs::create_dir_all(&test_dir);
            let test_file = test_dir.join("test_eicar.txt");
            
            // EICAR test string
            let eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            let _ = std::fs::write(&test_file, eicar);
            
            println!("\n📝 创建测试文件: {:?}", test_file);
            
            // Try to scan
            println!("\n🔍 扫描测试文件...");
            match engine.scan_file(test_file.to_string_lossy().as_ref()) {
                Ok(result) => {
                    println!("✓ 扫描成功");
                    println!("  耗时: {} ms", result.scan_time_ms);
                    println!("  匹配规则数: {}", result.matched_rules.len());
                    
                    if !result.matched_rules.is_empty() {
                        println!("\n  📌 匹配的规则:");
                        for rule_match in &result.matched_rules {
                            println!("    - {} (命名空间: {})", rule_match.rule_name, rule_match.namespace);
                        }
                    } else {
                        println!("\n  ℹ  未找到匹配的规则");
                    }
                }
                Err(e) => println!("✗ 扫描失败: {}", e),
            }
        }
        Err(e) => {
            println!("✗ 规则加载失败: {}", e);
            println!("\n💡 可能的原因:");
            println!("  1. anti.yarac 文件不在 {:?}", exe_dir);
            println!("  2. 规则文件已损坏");
            println!("  3. YARA 库无法访问");
        }
    }

    println!("\n════════════════════════════════════════════════════════════");
    println!("  诊断测试完成");
    println!("════════════════════════════════════════════════════════════\n");
}
