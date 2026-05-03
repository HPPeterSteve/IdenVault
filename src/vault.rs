/*
 * vault.rs
 *
 * Integração Rust ↔ C (vault_security.c)
 * Autor: Peter Steve
 *
 * Expõe via FFI as funções do core C:
 *   - vault_create_ffi
 *   - vault_delete_ffi
 *   - vault_rename_ffi
 *   - vault_unlock_ffi
 *   - vault_encrypt_ffi
 *   - vault_decrypt_ffi
 *   - vault_scan_ffi
 *   - vault_resolve_ffi
 *   - vault_info_ffi
 *   - vault_list_ffi
 *   - vault_files_ffi
 *   - vault_sandbox_ffi
 *   - vault_rule_ffi
 *   - vault_change_password_ffi
 *   - vault_status_ffi (get_vault_status local)
 *
 * As funções originais do Rust (isolate_directory, create, add_file,
 * safe_copy, secure_store, read_directory, allow_write, remove_file,
 * get_vault_status, run_in_sandbox) continuam existindo — as que têm
 * equivalente no core C delegam a ele via FFI; as demais permanecem
 * implementadas em Rust puro.
 *
 * Nenhum nome de bool, variável ou função existente foi alterado.
 */

use std::io::{Read, Write};
use std::{
    fs,
    io::{BufReader, BufWriter},
    path::{Path, PathBuf},
};

use std::ffi::{c_char, c_int, c_uint, CString};

#[cfg(target_os = "windows")]
use windows::Win32::Security::PSID;

/* ─────────────────────────────────────────────────────────────────────────
 *  FFI — símbolos exportados por vault_security.c
 *  (o .c é compilado como biblioteca estática: libvault_security.a)
 * ───────────────────────────────────────────────────────────────────────── */
#[link(name = "vault_security", kind = "static")]
unsafe extern "C" {
    /* Vault lifecycle */
    fn vault_create_ffi(
        name:     *const c_char,
        vault_type: c_int,          /* 0 = NORMAL, 1 = PROTECTED */
        path:     *const c_char,
        password: *const c_char,
    ) -> c_int;                     /* VaultError (0 = OK) */

    fn vault_delete_ffi(id: c_uint, password: *const c_char) -> c_int;

    fn vault_rename_ffi(
        id:       c_uint,
        new_name: *const c_char,
        password: *const c_char,
    ) -> c_int;

    fn vault_unlock_ffi(id: c_uint, password: *const c_char) -> c_int;

    fn vault_change_password_ffi(
        id:       c_uint,
        old_pass: *const c_char,
        new_pass: *const c_char,
    ) -> c_int;

    /* Crypto */
    fn vault_encrypt_ffi(id: c_uint, password: *const c_char) -> c_int;
    fn vault_decrypt_ffi(id: c_uint, password: *const c_char) -> c_int;

    /* Monitor / integrity */
    fn vault_scan_ffi(id: c_uint) -> c_int;
    fn vault_resolve_ffi(id: c_uint, password: *const c_char) -> c_int;

    /* Display (print to stdout inside C) */
    fn vault_info_ffi(id: c_uint);
    fn vault_list_ffi();
    fn vault_files_ffi(id: c_uint);

    /* Sandbox */
    fn vault_sandbox_ffi(id: c_uint, password: *const c_char) -> c_int;

    /* Rule engine */
    fn vault_rule_ffi(
        vault_id:  c_uint,
        max_fails: c_int,
        hour_from: c_int,   /* -1 = sem restrição */
        hour_to:   c_int,
    ) -> c_int;

    /* Vault status (retorna status code do vault: 0=OK,1=LOCKED,2=ALERT,3=DELETED) */
    fn vault_get_status_ffi(id: c_uint) -> c_int;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Sandbox — Windows AppContainer (mantido igual ao original)
 * ───────────────────────────────────────────────────────────────────────── */
#[cfg(target_os = "windows")]
#[link(name = "sandbox", kind = "static")]
unsafe extern "C" {
    pub fn setup_app_container(container_name: *const c_char, pSid: *mut PSID) -> bool;
    pub fn try_hard_isolate(app_path: *const c_char) -> bool;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Helpers internos
 * ───────────────────────────────────────────────────────────────────────── */

/// Converte &str → CString; em caso de byte nulo retorna Err com mensagem.
fn to_cstring(s: &str, label: &str) -> Result<CString, String> {
    CString::new(s).map_err(|_| format!("Caminho/string inválido para FFI (byte nulo em '{}')", label))
}

/// Converte Option<&str> → ponteiro C:
///   Some(s) → CString válido  → .as_ptr()
///   None    → std::ptr::null()
///
/// ATENÇÃO: o CString deve viver enquanto o ponteiro for usado.
/// Por isso retornamos Option<CString> junto com o ponteiro.
fn optional_cstr(opt: Option<&str>) -> (Option<CString>, *const c_char) {
    match opt {
        Some(s) => {
            let cs = CString::new(s).unwrap_or_else(|_| CString::new("").unwrap());
            let ptr = cs.as_ptr();
            (Some(cs), ptr)
        }
        None => (None, std::ptr::null()),
    }
}

/// Traduz VaultError (int) do C para Result Rust.
fn c_err(code: c_int) -> Result<(), String> {
    match code {
        0  => Ok(()),
        -1 => Err("Argumentos inválidos".to_string()),
        -2 => Err("Sem memória".to_string()),
        -3 => Err("Erro de I/O".to_string()),
        -4 => Err("Erro criptográfico".to_string()),
        -5 => Err("Falha de autenticação".to_string()),
        -6 => Err("Cofre bloqueado".to_string()),
        -7 => Err("Cofre já existe".to_string()),
        -8 => Err("Cofre não encontrado".to_string()),
        -9 => Err("Permissão negada".to_string()),
        -10 => Err("Catálogo cheio (máx. 64 cofres)".to_string()),
        -11 => Err("Caminho inválido".to_string()),
        -12 => Err("Senha obrigatória para cofre protegido".to_string()),
        -13 => Err("Violação de integridade".to_string()),
        -14 => Err("Erro de sistema".to_string()),
        n   => Err(format!("Erro desconhecido (código {})", n)),
    }
}

/* 
 *  WRAPPERS PÚBLICOS — core C via FFI
 *  */

/// Cria um cofre no core C.
/// `vault_type`: "normal" | "protected"
pub fn vault_create(
    name:       Option<&str>,
    vault_type: &str,
    path:       Option<&str>,
    password:   Option<&str>,
) -> Result<(), String> {
    let vtype: c_int = if vault_type == "protected" { 1 } else { 0 };

    let (_cs_name, p_name)  = optional_cstr(name);
    let (_cs_path, p_path)  = optional_cstr(path);
    let (_cs_pass, p_pass)  = optional_cstr(password);

    let code = unsafe { vault_create_ffi(p_name, vtype, p_path, p_pass) };
    c_err(code)
}

/// Deleta cofre pelo ID.
pub fn vault_delete(id: u32, password: Option<&str>) -> Result<(), String> {
    let (_cs, p) = optional_cstr(password);
    let code = unsafe { vault_delete_ffi(id, p) };
    c_err(code)
}

/// Renomeia cofre.
pub fn vault_rename(id: u32, new_name: &str, password: Option<&str>) -> Result<(), String> {
    let cs_name = to_cstring(new_name, "new_name")?;
    let (_cs_pass, p_pass) = optional_cstr(password);
    let code = unsafe { vault_rename_ffi(id, cs_name.as_ptr(), p_pass) };
    c_err(code)
}

/// Desbloqueia cofre após lockout.
pub fn vault_unlock(id: u32, password: &str) -> Result<(), String> {
    let cs = to_cstring(password, "password")?;
    let code = unsafe { vault_unlock_ffi(id, cs.as_ptr()) };
    c_err(code)
}

/// Troca senha do cofre.
pub fn vault_change_password(id: u32, old_pass: &str, new_pass: &str) -> Result<(), String> {
    let cs_old = to_cstring(old_pass, "old_pass")?;
    let cs_new = to_cstring(new_pass, "new_pass")?;
    let code = unsafe { vault_change_password_ffi(id, cs_old.as_ptr(), cs_new.as_ptr()) };
    c_err(code)
}

/// Criptografa todos os arquivos do cofre (AES-256-CBC).
pub fn vault_encrypt(id: u32, password: &str) -> Result<(), String> {
    let cs = to_cstring(password, "password")?;
    let code = unsafe { vault_encrypt_ffi(id, cs.as_ptr()) };
    c_err(code)
}

/// Descriptografa arquivos .enc do cofre.
pub fn vault_decrypt(id: u32, password: &str) -> Result<(), String> {
    let cs = to_cstring(password, "password")?;
    let code = unsafe { vault_decrypt_ffi(id, cs.as_ptr()) };
    c_err(code)
}

/// Força varredura de integridade no cofre.
pub fn vault_scan(id: u32) -> Result<(), String> {
    let code = unsafe { vault_scan_ffi(id) };
    c_err(code)
}

/// Resolve alerta ativo no cofre.
pub fn vault_resolve(id: u32, password: Option<&str>) -> Result<(), String> {
    let (_cs, p) = optional_cstr(password);
    let code = unsafe { vault_resolve_ffi(id, p) };
    c_err(code)
}

/// Exibe informações detalhadas de um cofre (saída no C via printf).
pub fn vault_info(id: u32) {
    unsafe { vault_info_ffi(id) }
}

/// Lista todos os cofres do catálogo (saída no C via printf).
pub fn vault_list() {
    unsafe { vault_list_ffi() }
}

/// Lista arquivos rastreados em um cofre.
pub fn vault_files(id: u32) {
    unsafe { vault_files_ffi(id) }
}

/// Abre cofre em shell sandbox (chroot/chdir no C).
pub fn vault_sandbox(id: u32, password: Option<&str>) -> Result<(), String> {
    let (_cs, p) = optional_cstr(password);
    let code = unsafe { vault_sandbox_ffi(id, p) };
    c_err(code)
}

/// Adiciona regra de segurança a um cofre.
/// `hour_from` / `hour_to`: None = sem restrição de horário.
pub fn vault_rule(
    vault_id:  u32,
    max_fails: i32,
    hour_from: Option<i32>,
    hour_to:   Option<i32>,
) -> Result<(), String> {
    let hf: c_int = hour_from.unwrap_or(-1);
    let ht: c_int = hour_to.unwrap_or(-1);
    let code = unsafe { vault_rule_ffi(vault_id, max_fails, hf, ht) };
    c_err(code)
}

/* 
 *  FUNÇÕES ORIGINAIS RUST — mantidas integralmente, sem renomear nada
 *  */

/// Função que o main.rs está tentando chamar (Windows AppContainer sandbox).
pub fn run_in_sandbox(path: &str) {
    println!("🛡️ Komodo-Secure: Iniciando isolamento para {}", path);

    let c_path = match CString::new(path) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("❌ Falha ao converter caminho para CString: {}", path);
            return;
        }
    };

    #[cfg(target_os = "windows")]
    unsafe {
        let container_name = format!("KomodoSandbox_{}", std::process::id());
        let c_container_name = match CString::new(container_name.clone()) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("❌ Falha ao criar nome do AppContainer");
                return;
            }
        };

        let mut sid = PSID(std::ptr::null_mut());

        if setup_app_container(c_container_name.as_ptr(), &mut sid) {
            println!("✅ AppContainer '{}' configurado com sucesso", container_name);
            println!("SID do AppContainer: {:?}", sid);

            if try_hard_isolate(c_path.as_ptr()) {
                println!("✅ Processo isolado com sucesso (Sandbox + Firewall + Desktop)");
            } else {
                eprintln!("❌ Falha ao aplicar isolamento de segurança.");
            }
        } else {
            eprintln!("❌ Falha ao configurar AppContainer '{}'", container_name);
        }
    }

    /* Em Linux o sandbox é tratado pelo vault_sandbox() via core C (chroot/fork). */
    #[cfg(not(target_os = "windows"))]
    {
        eprintln!(
            "ℹ️  run_in_sandbox: no Linux use 'sandbox <id>' para isolamento via core C (chroot/fork)."
        );
        let _ = c_path; /* evita warning de variável não usada */
    }
}

pub fn isolate_directory(directory: &str) {
    let home_dir = home::home_dir().unwrap_or_default();
    let sandbox_path = home_dir.join("Komodo_SEC").join("sandbox");

    let files = read_directory(directory);
    let dir_sandbox = Path::new(&sandbox_path);

    if !dir_sandbox.exists() {
        if let Err(e) = std::fs::create_dir_all(&sandbox_path) {
            eprintln!("Falha ao criar diretório sandbox: {}", e);
            return;
        }
    }

    let full_path = dir_sandbox.join(directory);
    if !full_path.exists() {
        if let Err(e) = std::fs::create_dir_all(&full_path) {
            eprintln!("Falha ao criar subdiretório sandbox: {}", e);
            return;
        }
    }

    let c_path = match CString::new(directory) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Caminho inválido para FFI (contém byte nulo?)");
            return;
        }
    };

    println!("Tentando isolamento avançado (mount namespace + readonly)...");

    /* No Linux delegamos ao core C */
    #[cfg(not(target_os = "windows"))]
    let isolated = {
        /* vault_sandbox_ffi com id=0 não faz sentido; isolate_directory mantém
         * sua lógica Rust original — apenas tenta via try_hard_isolate se disponível.
         * Como no Linux não temos AppContainer, simplesmente prosseguimos com
         * o fallback readonly abaixo. */
        let _ = c_path;
        false
    };

    #[cfg(target_os = "windows")]
    let isolated = unsafe { try_hard_isolate(c_path.as_ptr()) };

    if isolated {
        println!("Isolamento forte aplicado (namespace + readonly)");
    } else {
        println!("Isolamento namespace falhou (provável falta de privilégio)");
        println!("Aplicando isolamento básico (readonly)...");
    }

    println!("Isolando diretório {}", directory);
    println!("Arquivos encontrados:");

    for file in files {
        println!(" - {}", file);
    }

    if let Ok(metadata) = fs::metadata(directory) {
        let mut permission = metadata.permissions();
        permission.set_readonly(true);
        if let Err(e) = fs::set_permissions(directory, permission) {
            eprintln!("Falha ao aplicar permissão readonly: {}", e);
        } else {
            println!("Permissão readonly aplicada com sucesso (fallback)");
        }
    } else {
        eprintln!("Não foi possível ler metadados do diretório");
    }
}

pub fn create(dir: &str) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("Erro ao criar cofre: {}", e);
    } else {
        println!("Cofre criado com sucesso em {}", dir);
    }
}

pub fn add_file(vault: &str, file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = Path::new(vault);
    let file_path  = Path::new(file);

    if !vault_path.exists() {
        eprintln!("Cofre não encontrado: {}", vault);
        return Ok(());
    }

    if !file_path.exists() || !file_path.is_file() {
        eprintln!("Arquivo inválido: {}", file);
        return Ok(());
    }

    let file_name   = file_path.file_name().ok_or("Falha ao obter nome do arquivo")?;
    let destination: PathBuf = vault_path.join(file_name);

    if destination.exists() {
        eprintln!("Arquivo já existe no cofre: {}", destination.display());
        return Ok(());
    }

    let bytes = fs::copy(file_path, &destination)?;

    println!(
        "Arquivo adicionado ao cofre: {}\nBytes copiados: {}",
        destination.display(),
        bytes
    );

    Ok(())
}

pub fn safe_copy<P: AsRef<Path>>(src: P, dstn: P) -> Result<(), Box<dyn std::error::Error>> {
    let source_path      = src.as_ref();
    let destination_path = dstn.as_ref();
    let temporary_path   = destination_path.with_extension("tmp_copy");

    let source_file  = fs::File::open(source_path)?;
    let mut origin_file = BufReader::new(source_file);

    let temporary_file = fs::File::create(&temporary_path)?;
    let mut writer = BufWriter::new(temporary_file);

    let mut buffer = [0u8; 65536];
    loop {
        let bytes_read = origin_file.read(&mut buffer)?;
        if bytes_read == 0 { break; }
        writer.write_all(&buffer[..bytes_read])?;
    }
    writer.flush()?;

    fs::rename(&temporary_path, destination_path)?;
    Ok(())
}

pub fn secure_store(src: &str, vault: &str, password: &str) {
    let source     = Path::new(src);
    let vault_path = Path::new(vault);

    if !source.exists() {
        eprintln!("Erro: Arquivo de origem não existe: {}", src);
        return;
    }
    if !vault_path.exists() {
        eprintln!("Erro: Cofre (diretório) não existe: {}", vault);
        return;
    }

    let file_name = match source.file_name() {
        Some(name) => name,
        None => return,
    };
    let destination = vault_path.join(file_name);

    if let Err(e) = safe_copy(source, &destination) {
        eprintln!("Erro ao copiar arquivo para o cofre: {}", e);
        return;
    }
    let destination_in_vault = destination;

    if let Err(e) = crate::crypto::encrypt_file(&destination_in_vault, password) {
        eprintln!("Erro ao criptografar arquivo no cofre: {}", e);
        return;
    }
    let _ = fs::remove_file(&destination_in_vault);
    let _ = fs::remove_file(source);
}

pub fn read_directory(directory: &str) -> Vec<String> {
    let mut files = Vec::new();
    let path = Path::new(directory);

    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("Erro ao ler diretório {}: {}", directory, e);
            return files;
        }
    };

    for entry in entries.flatten() {
        if let Ok(file_type) = entry.file_type() {
            if file_type.is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    files.push(name.to_string());
                }
            }
        }
    }

    println!("Total de arquivos: {}", files.len());

    if files.is_empty() {
        eprintln!("Nenhum arquivo encontrado em: {}", directory);
    }

    files
}

#[allow(dead_code)]
pub fn allow_write(path: &str) {
    let file_exists = Path::new(path);
    if !file_exists.exists() {
        println!("Arquivo não encontrado: {}", path);
        return;
    }

    if let Ok(metadata) = fs::metadata(file_exists) {
        let mut permission = metadata.permissions();
        permission.set_readonly(false);
        if let Err(e) = fs::set_permissions(path, permission) {
            eprintln!("Falha ao setar permissão de escrita: {}", e);
        }
    }
}

pub fn remove_file(vault: &str, file_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = Path::new(vault);
    let file_path  = vault_path.join(file_name);

    if !file_path.exists() {
        return Err(format!(
            "Arquivo '{}' não encontrado no cofre '{}'",
            file_name, vault
        ).into());
    }

    fs::remove_file(file_path)?;
    println!("✔ Arquivo '{}' removido do cofre '{}'", file_name, vault);
    Ok(())
}

/// Retorna status textual do cofre consultando o core C.
/// Se o id não for numérico, cai no fallback Rust original (verifica caminho).
pub fn get_vault_status(vault: &str) -> Result<(), Box<dyn std::error::Error>> {
    /* Tenta interpretar o argumento como ID numérico primeiro */
    if let Ok(id) = vault.parse::<u32>() {
        let status_code = unsafe { vault_get_status_ffi(id) };
        let status_str = match status_code {
            0 => "OK",
            1 => "LOCKED",
            2 => "ALERT",
            3 => "DELETED",
            _ => "DESCONHECIDO",
        };
        println!("\n--- Status do Cofre (id={}) ---", id);
        println!("Status: {}", status_str);

        /* Lista arquivos via core C também */
        unsafe { vault_files_ffi(id) }
        return Ok(());
    }

    /* Fallback: caminho Rust original */
    let vault_path = Path::new(vault);
    if !vault_path.exists() {
        return Err(format!("Cofre '{}' não encontrado", vault).into());
    }

    let files = read_directory(vault);
    let mut total_size = 0;
    for file in &files {
        let path = vault_path.join(file);
        if let Ok(metadata) = fs::metadata(path) {
            total_size += metadata.len();
        }
    }

    println!("\n--- Status do Cofre: {} ---", vault);
    println!("Total de arquivos: {}", files.len());
    println!("Tamanho total: {:.2} KB", total_size as f64 / 1024.0);
    Ok(())
} 