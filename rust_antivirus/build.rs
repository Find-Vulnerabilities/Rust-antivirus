// build.rs: YARA 本機庫鏈接配置
use std::path::PathBuf;
use std::env;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    
    if target_os != "windows" {
        println!("cargo:warning=This application is Windows-only");
        return;
    }

    println!("cargo:rustc-check-cfg=cfg(yara_stub)");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    
    // 配置 libyara 本機庫鏈接 - 包括 x64 子目錄
    let yara_lib_paths = vec![
        manifest_dir.join("third_party").join("yara").join("lib").join("x64"),  // 優先級最高
        manifest_dir.join("third_party").join("yara").join("lib"),
        manifest_dir.join("third_party").join("yara").join("lib64"),
        manifest_dir.join("target").join("lib"),
        PathBuf::from("C:\\vcpkg\\installed\\x64-windows\\lib"),
    ];

    let mut lib_found = false;
    for lib_path in yara_lib_paths {
        if lib_path.exists() {
            // 檢查是否有 libyara.lib
            if lib_path.join("libyara.lib").exists() {
                println!("cargo:rustc-link-search=native={}", lib_path.display());
                lib_found = true;
                println!("cargo:warning=✓ Found YARA lib path: {}", lib_path.display());
                break;
            }
        }
    }

    if !lib_found {
        println!("cargo:warning=⚠ Warning: Could not find libyara.lib");
        println!("cargo:rustc-link-search=native=C:\\vcpkg\\installed\\x64-windows\\lib");
    }

    // 鏈接必要的庫 - 使用完整路徑確保找到
    let target_lib_path = manifest_dir.join("target").join("lib");
    
    let libs_ok = target_lib_path.exists() 
        && target_lib_path.join("libyara.lib").exists()
        && target_lib_path.join("libcrypto.lib").exists()
        && target_lib_path.join("libssl.lib").exists();
    
    if libs_ok {
        // 使用完整文件路径
        let libyara_path = target_lib_path.join("libyara.lib").display().to_string();
        let libcrypto_path = target_lib_path.join("libcrypto.lib").display().to_string();
        let libssl_path = target_lib_path.join("libssl.lib").display().to_string();
        
        println!("cargo:rustc-link-arg=/LIBPATH:{}", target_lib_path.display());
        println!("cargo:rustc-link-arg={}", libyara_path);
        println!("cargo:rustc-link-arg={}", libcrypto_path);
        println!("cargo:rustc-link-arg={}", libssl_path);
    } else {
        // 備用：使用搜索路徑方式
        let vcpkg_lib = "C:\\vcpkg\\installed\\x64-windows\\lib";
        println!("cargo:rustc-link-search=native={}", vcpkg_lib);
        println!("cargo:rustc-link-lib=static=libyara");
        println!("cargo:rustc-link-lib=static=libcrypto");
        println!("cargo:rustc-link-lib=static=libssl");
    }

    println!("cargo:rustc-link-lib=dylib=kernel32");
    println!("cargo:rustc-link-lib=dylib=advapi32");
    println!("cargo:rustc-link-lib=dylib=ws2_32");
}