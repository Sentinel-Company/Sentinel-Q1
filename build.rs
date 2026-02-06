//! Sentinel-X Build Script
//! 
//! Kernel modül derleme ve kurulum betiği

use std::process::Command;
use std::path::Path;
use std::fs;

fn main() {
    println!("🔧 Sentinel-X Build Script");
    println!("Building kernel module and userspace components...");
    
    // Check dependencies
    if !check_dependencies() {
        eprintln!("❌ Missing dependencies. Please install required tools.");
        std::process::exit(1);
    }
    
    // Build kernel module
    if !build_kernel_module() {
        eprintln!("❌ Failed to build kernel module");
        std::process::exit(1);
    }
    
    // Build userspace components
    if !build_userspace() {
        eprintln!("❌ Failed to build userspace components");
        std::process::exit(1);
    }
    
    println!("✅ Sentinel-X build completed successfully!");
}

fn check_dependencies() -> bool {
    println!("🔍 Checking dependencies...");
    
    let dependencies = vec![
        ("rustc", "Rust compiler"),
        ("cargo", "Rust package manager"),
        ("gcc", "C compiler"),
        ("make", "Build tool"),
        ("clang", "LLVM compiler"),
    ];
    
    let mut all_found = true;
    
    for (cmd, desc) in dependencies {
        if Command::new(cmd).arg("--version").output().is_ok() {
            println!("  ✅ {}: Found", desc);
        } else {
            println!("  ❌ {}: Not found", desc);
            all_found = false;
        }
    }
    
    // Check kernel headers
    if Path::new("/lib/modules/$(uname -r)/build").exists() {
        println!("  ✅ Kernel headers: Found");
    } else {
        println!("  ❌ Kernel headers: Not found");
        all_found = false;
    }
    
    all_found
}

fn build_kernel_module() -> bool {
    println!("🏗️  Building kernel module...");
    
    // Change to kernel directory
    std::env::set_current_dir("kernel").unwrap();
    
    // Run cargo build for kernel module
    let output = Command::new("cargo")
        .args(&["build", "--release", "--target=x86_64-unknown-linux-gnu"])
        .output();
    
    match output {
        Ok(result) => {
            if result.status.success() {
                println!("  ✅ Kernel module built successfully");
                true
            } else {
                println!("  ❌ Kernel module build failed:");
                println!("{}", String::from_utf8_lossy(&result.stderr));
                false
            }
        },
        Err(e) => {
            println!("  ❌ Failed to run cargo build: {}", e);
            false
        }
    }
}

fn build_userspace() -> bool {
    println!("🏗️  Building userspace components...");
    
    // Change to userspace/cli directory
    std::env::set_current_dir("../userspace/cli").unwrap();
    
    // Build CLI
    let output = Command::new("cargo")
        .args(&["build", "--release"])
        .output();
    
    match output {
        Ok(result) => {
            if result.status.success() {
                println!("  ✅ CLI built successfully");
                
                // Build monitor
                std::env::set_current_dir("../monitor").unwrap();
                if build_component("monitor") {
                    println!("  ✅ Monitor built successfully");
                    true
                } else {
                    false
                }
            } else {
                println!("  ❌ CLI build failed:");
                println!("{}", String::from_utf8_lossy(&result.stderr));
                false
            }
        },
        Err(e) => {
            println!("  ❌ Failed to run cargo build: {}", e);
            false
        }
    }
}

fn build_component(name: &str) -> bool {
    let output = Command::new("cargo")
        .args(&["build", "--release"])
        .output();
    
    match output {
        Ok(result) => result.status.success(),
        Err(_) => false,
    }
}