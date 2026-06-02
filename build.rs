use std::{env, process::Command as C};

fn main() {
    let o = env::var("OUT_DIR").unwrap();

    let s = [
        "c_src/vault_crypto.c",
        "c_src/vault_catalog.c",
        "c_src/vault_monitor.c",
        "c_src/vault_sandbox.c",
        "c_src/vault_engine.c",
        "c_src/vault_ffi.c",
        "c_src/vault_fuse.c",
    ];

    let mut x = Vec::new();

    for i in s {
        let f = i.rsplit('/').next().unwrap();
        let n = &f[..f.len() - 2];
        let p = format!("{}/{}.o", o, n);

        assert!(C::new("gcc")
            .args([
                "-Oz",
                "-flto",
                "-fno-asynchronous-unwind-tables",
                "-fno-unwind-tables",
                "-fdata-sections",
                "-ffunction-sections",
                "-fvisibility=hidden",
                "-fmerge-all-constants",
                "-fno-ident",
                "-D_FILE_OFFSET_BITS=64",
                "-fPIC",
                "-c",
                "-I",
                "c_src",
                i,
                "-o",
                &p
            ])
            .status()
            .unwrap()
            .success());

        x.push(p);
    }

    let l = format!("{}/libvault_security.a", o);

    assert!(C::new("ar")
        .args(["rcs", &l])
        .args(&x)
        .status()
        .unwrap()
        .success());

    println!("cargo:rustc-link-search=native={}", o);
    println!("cargo:rustc-link-lib=static=vault_security");

    println!("cargo:rustc-link-arg=-Wl,--gc-sections");
    println!("cargo:rustc-link-arg=-Wl,-s");

    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=seccomp");
    println!("cargo:rustc-link-lib=cap");
    println!("cargo:rustc-link-lib=fuse");

    for i in s {
        println!("cargo:rerun-if-changed={}", i);
    }
    println!("cargo:rerun-if-changed=c_src/vault_core.h");
}
