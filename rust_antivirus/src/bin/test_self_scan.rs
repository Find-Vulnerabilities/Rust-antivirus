// Test scanning anti.yarac rules file with current engine
use rust_antivirus::yara_engine::YaraEngine;
use std::path::PathBuf;

fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Debug)
        .format_timestamp_secs()
        .init();

    println!("\n════════════════════════════════════════════════════════════");
    println!("  自扫描测试 - 掃描 anti.yarac 規則文件本身");
    println!("════════════════════════════════════════════════════════════\n");

    // Get current directory
    let exe_path = std::env::current_exe().expect("Failed to get exe path");
    let exe_dir = exe_path.parent().expect("Failed to get exe directory");
    
    let rules_file = exe_dir.join("anti.yarac");
    let target_file = exe_dir.join("anti.yarac");  // Scan the rules file itself

    println!("📁 可执行文件目录: {:?}", exe_dir);
    println!("📋 规则文件: {:?}", rules_file);
    println!("📋 扫描目标: {:?}", target_file);
    
    if !rules_file.exists() {
        println!("✗ 规则文件不存在!");
        return;
    }

    if !target_file.exists() {
        println!("✗ 扫描目标文件不存在!");
        return;
    }

    // Initialize YARA engine
    println!("\n🚀 初始化 YARA 引擎...");
    match rust_antivirus::yara_engine::YaraEngine::init() {
        Ok(_) => println!("✓ YARA 引擎初始化成功"),
        Err(e) => {
            println!("✗ 初始化失败: {}", e);
            return;
        }
    }

    // Load rules
    let rules_path_str = rules_file.to_string_lossy();
    println!("\n📦 加载规则: {}", rules_path_str);
    
    match YaraEngine::with_rules(&rules_path_str) {
        Ok(engine) => {
            println!("✓ 规则加载成功");

            // Scan the rules file itself
            let target_str = target_file.to_string_lossy();
            println!("\n🔍 扫描文件: {}", target_str);
            println!("   文件大小: {} MB", target_file.metadata().map(|m| m.len() / 1_000_000).unwrap_or(0));

            match engine.scan_file(&target_str) {
                Ok(result) => {
                    println!("\n✓ 扫描完成:");
                    println!("  耗时: {} ms", result.scan_time_ms);
                    println!("  匹配规则数: {}", result.matched_rules.len());
                    
                    if !result.matched_rules.is_empty() {
                        println!("\n  📌 匹配的规则:");
                        for (i, rule) in result.matched_rules.iter().enumerate() {
                            println!("    {}. {} (ns: {})", i+1, rule.rule_name, rule.namespace);
                        }
                    } else {
                        println!("\n  ⚠ 未检测到任何匹配");
                        println!("  这可能表示:");
                        println!("    - 回调函数未被触发");
                        println!("    - 规则与文件内容不匹配");
                        println!("    - 扫描逻辑有问题");
                    }
                }
                Err(e) => println!("✗ 扫描失败: {}", e),
            }
        }
        Err(e) => {
            println!("✗ 规则加载失败: {}", e);
        }
    }

    println!("\n════════════════════════════════════════════════════════════");
    println!("  测试完成");
    println!("════════════════════════════════════════════════════════════\n");
}
