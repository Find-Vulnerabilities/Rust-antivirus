fn main() {
    println!("════════════════════════════════════════════════════════════");
    println!("  简单规则扫描测试 - 使用 no-module 规则扫描 test.txt");
    println!("════════════════════════════════════════════════════════════\n");

    // Get executable directory
    let exe_path = std::env::current_exe().expect("Failed to get exe path");
    let exe_dir = exe_path.parent().expect("Failed to get exe dir");

    let rules_path = exe_dir.join("test_rules.yarac");
    let target_file = exe_dir.join("test.txt");

    println!("📁 可执行文件目录: {}", exe_dir.display());
    println!("📋 规则文件: {}", rules_path.display());
    println!("📋 扫描目标: {}\n", target_file.display());

    // Create engine with rules
    println!("🚀 初始化 YARA 引擎...");
    let engine = match rust_antivirus::yara_engine::YaraEngine::with_rules(rules_path.to_str().unwrap()) {
        Ok(engine) => {
            println!("✓ YARA 引擎初始化成功\n");
            engine
        }
        Err(e) => {
            eprintln!("❌ 初始化失败: {}", e);
            return;
        }
    };

    // Scan file
    println!("🔍 扫描文件: {}", target_file.display());
    match engine.scan_file(target_file.to_str().unwrap()) {
        Ok(result) => {
            println!("✓ 扫描完成:");
            println!("  耗时: {} ms", result.scan_time_ms);
            println!("  匹配规则数: {}", result.matched_rules.len());
            
            if result.matched_rules.len() > 0 {
                println!("\n✅ 检测到威胁!");
                println!("这表示简单规则工作正常 ✓");
                for (i, matched_rule) in result.matched_rules.iter().enumerate() {
                    println!("  规则 {}: {}", i + 1, matched_rule.rule_name);
                }
            } else {
                println!("\n⚠ 未检测到任何匹配");
                println!("这表示回调函数未被触发或规则不匹配");
            }
        }
        Err(e) => {
            eprintln!("❌ 扫描失败: {}", e);
        }
    }

    println!("\n════════════════════════════════════════════════════════════");
    println!("  测试完成");
    println!("════════════════════════════════════════════════════════════");
}
