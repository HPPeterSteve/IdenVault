// build.rs

use std::process::Command;

fn main() {
    // ====================== ÍCONE DO EXECUTÁVEL (Windows) ======================
    #[cfg(target_os = "windows")]
    {
        let mut res = winresource::WindowsResource::new();
        
        // ←←← MUDE AQUI para o caminho correto da sua logo
        res.set_icon("img/komodo-secure.ico");    
        
        res.set("FileDescription", "Komodo Secure - Vault Security System");
        res.set("ProductName", "Komodo-Secure");
        res.set("CompanyName", "Pedrão Projects");
        res.set("LegalCopyright", "© 2026 Pedrão");
        res.set("FileVersion", env!("CARGO_PKG_VERSION"));
        res.set("ProductVersion", env!("CARGO_PKG_VERSION"));
        
        res.compile().unwrap();
    }

    // ====================== COMPILAÇÃO DOS ARQUIVOS C ======================
    let out_dir = std::env::var("OUT_DIR").unwrap();

    // 1. Compilar vault_security.c
    let status = Command::new("gcc")
        .args([
            "-O2", "-Wall", "-Wextra",
            "-DVAULT_FFI_BUILD", "-fPIC", "-c",
            "c_src/vault_security.c",
            "-o",
        ])
        .arg(format!("{}/vault_security.o", out_dir))
        .status()
        .expect("Falha ao compilar vault_security.c");

    assert!(status.success(), "Compilação de vault_security.c falhou");

    // 2. Compilar vault_ffi.c
    let status = Command::new("gcc")
        .args([
            "-O2", "-Wall", "-Wextra",
            "-DVAULT_FFI_BUILD", "-fPIC", "-c",
            "c_src/vault_ffi.c",
            "-o",
        ])
        .arg(format!("{}/vault_ffi.o", out_dir))
        .status()
        .expect("Falha ao compilar vault_ffi.c");

    assert!(status.success(), "Compilação de vault_ffi.c falhou");

    // 3. Criar biblioteca estática
    let status = Command::new("ar")
        .args(["rcs"])
        .arg(format!("{}/libvault_security.a", out_dir))
        .arg(format!("{}/vault_security.o", out_dir))
        .arg(format!("{}/vault_ffi.o", out_dir))
        .status()
        .expect("Falha ao criar libvault_security.a");

    assert!(status.success(), "Criação da biblioteca estática falhou");

    // 4. Linkar para o Rust
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=vault_security");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=pthread");

    // Recompilar se os arquivos C mudarem
    println!("cargo:rerun-if-changed=c_src/vault_security.c");
    println!("cargo:rerun-if-changed=c_src/vault_ffi.c");
    println!("cargo:rerun-if-changed=c_src/vault_ffi.h");
}