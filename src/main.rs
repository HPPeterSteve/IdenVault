/*
 * main.rs
 *
 * VaranusCore — ponto de entrada
 * Integra o core C (vault_security.c) via vault.rs
 *
 * Novos comandos adicionados (delegam ao core C):
 *   vault-list
 *   vault-create  <name> <path> <type>
 *   vault-delete  <id>
 *   vault-rename  <id> <new_name>
 *   vault-unlock  <id>
 *   vault-passwd  <id>
 *   vault-encrypt <id>
 *   vault-decrypt <id>
 *   vault-scan    <id>
 *   vault-resolve <id>
 *   vault-info    <id>
 *   vault-files   <id>
 *   vault-sandbox <id>
 *   vault-rule    <id> <max_fails> [hour_from hour_to]
 *
 * Levenshtein reintegrado: sugestão automática de comando para typos.
 * Nenhum bool, variável ou função existente foi renomeado.
 */

mod cli;
mod vault;
mod crypto;
mod log;
mod path_assistant;
mod sys_info;

use colored::*;
use inquire::Password;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::io::{self, IsTerminal};
use std::path::PathBuf;

/* ─────────────────────────────────────────────────────────────────────────
 *  Lista canônica de todos os comandos — usada pelo Levenshtein
 * ───────────────────────────────────────────────────────────────────────── */
const ALL_COMMANDS: &[&str] = &[
    /* originais */
    "isolate-directory",
    "create-vault",
    "safe-copy",
    "allow-write",
    "read-directory",
    "add-file",
    "remove-file",
    "status",
    "encrypt",
    "decrypt",
    "secure-copy",
    "run-in-sandbox",
    "system-information",
    "list-process-status",
    "derive-master-key",
    "help",
    "exit",
    /* novos — core C */
    "vault-list",
    "vault-create",
    "vault-delete",
    "vault-rename",
    "vault-unlock",
    "vault-passwd",
    "vault-encrypt",
    "vault-decrypt",
    "vault-scan",
    "vault-resolve",
    "vault-info",
    "vault-files",
    "vault-sandbox",
    "vault-rule",
    "vault-export",
];

fn show_help() {
    println!(
        "{}",
        "
Comandos disponíveis:

── Operações de arquivo / diretório ──────────────────────────────────────
create-vault <path>        → cria um cofre (diretório)
add-file <vault> <file>    → adiciona arquivo ao cofre
safe-copy <src> <dst>      → copia com segurança
allow-write <file>         → libera escrita
read-directory <dir>       → lista arquivos
isolate-directory <dir>    → isola diretório
secure-copy <file> <vault> [pass] → protege e armazena (senha opcional)
encrypt <file> [pass]      → criptografa arquivo (senha opcional)
decrypt <file> [pass]      → descriptografa arquivo (senha opcional)
remove-file <vault> <file> → remove arquivo do cofre
status <vault|id>          → mostra status do cofre
run-in-sandbox <dir>       → roda diretório em sandbox

── Core C — Vault Security System ────────────────────────────────────────
vault-list                             → lista todos os cofres (catálogo)
vault-create <name> <path> <type>      → cria cofre no core C
  type: normal | protected
vault-delete  <id>                     → deleta cofre pelo ID
vault-rename  <id> <new_name>          → renomeia cofre
vault-unlock  <id>                     → desbloqueia cofre após lockout
vault-passwd  <id>                     → troca senha do cofre
vault-encrypt <id>                     → criptografa arquivos (AES-256)
vault-decrypt <id>                     → descriptografa arquivos
vault-scan    <id>                     → força varredura de integridade
vault-resolve <id>                     → resolve alerta ativo
vault-info    <id>                     → detalhes do cofre
vault-files   <id>                     → lista arquivos rastreados
vault-sandbox <id>                     → abre cofre em shell sandbox
vault-rule    <id> <max_fails> [h_from h_to]  → adiciona regra de segurança
vault-export  <id> <file> <dst>              → exporta arquivo do cofre

── Sistema ───────────────────────────────────────────────────────────────
system-information [cpu] [memory] [disks] [networks] [processes]
list-process-status        → lista status dos processos ativos
derive-master-key          → deriva master key (senha + chave USB)

help                       → esta ajuda
exit                       → sair
"
        .cyan()
    );
}

fn get_password(prompt_text: &str, provided_pass: Option<&&str>) -> String {
    if let Some(pass) = provided_pass {
        return pass.to_string();
    }

    if !io::stdin().is_terminal() {
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            return input.trim().to_string();
        }
    }

    Password::new(prompt_text)
        .without_confirmation()
        .prompt()
        .unwrap_or_default()
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Levenshtein — reintegrado e conectado à sugestão de comandos
 * ───────────────────────────────────────────────────────────────────────── */
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let mut costs = (0..=b.len()).collect::<Vec<_>>();

    for (i, ca) in a.chars().enumerate() {
        costs[0] = i + 1;
        let mut last_cost = i;
        for (j, cb) in b.chars().enumerate() {
            let new_cost = if ca == cb {
                last_cost
            } else {
                1 + last_cost.min(costs[j]).min(costs[j + 1])
            };
            last_cost = costs[j + 1];
            costs[j + 1] = new_cost;
        }
    }

    costs[b.len()]
}

/// Encontra o comando mais próximo pelo Levenshtein.
/// Retorna Some(sugestão) se distância ≤ threshold, None caso contrário.
fn suggest_command(unknown: &str) -> Option<&'static str> {
    const THRESHOLD: usize = 3;

    ALL_COMMANDS
        .iter()
        .map(|&cmd| (cmd, levenshtein_distance(unknown, cmd)))
        .filter(|&(_, d)| d <= THRESHOLD)
        .min_by_key(|&(_, d)| d)
        .map(|(cmd, _)| cmd)
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Helpers para parsing de ID e senha (comandos vault-*)
 * ───────────────────────────────────────────────────────────────────────── */
fn parse_id(s: Option<&&str>, cmd: &str) -> Option<u32> {
    match s {
        Some(v) => match v.parse::<u32>() {
            Ok(id) => Some(id),
            Err(_) => {
                eprintln!("{}", format!("✖ '{}': ID deve ser numérico, recebeu '{}'", cmd, v).red());
                None
            }
        },
        None => {
            eprintln!("{}", format!("✖ '{}': ID obrigatório", cmd).red());
            None
        }
    }
}

fn prompt_password(label: &str) -> String {
    Password::new(label)
        .without_confirmation()
        .prompt()
        .unwrap_or_default()
}

fn prompt_password_opt(label: &str) -> Option<String> {
    let p = prompt_password(label);
    if p.is_empty() { None } else { Some(p) }
}

/* 
 *  DISPATCHER DE COMANDOS
 *  */
fn handle_command(parts: Vec<&str>) {
    match parts[0] {

        /* ── originais ────────────────────────────────────────────────── */

        "isolate-directory" => {
            if let Some(dir) = path_assistant::ensure_path(parts.get(1), "Diretório para isolar:", true) {
                log::info(&format!("Isolando diretório: {:?}", dir));
                vault::isolate_directory(dir.to_str().unwrap());
            }
        }

        "create-vault" => {
            let path = if let Some(p) = parts.get(1) {
                PathBuf::from(p)
            } else {
                let input = inquire::Text::new("Caminho para o novo cofre:").prompt().unwrap_or_default();
                PathBuf::from(input)
            };

            if !path.as_os_str().is_empty() {
                log::info(&format!("Criando cofre em: {:?}", path));
                vault::create(path.to_str().unwrap());
                println!("{}", "✔ Cofre criado".green());
            }
        }

        "safe-copy" => {
            let src = path_assistant::ensure_path(parts.get(1), "Arquivo de origem:", false);
            let dst = if let Some(p) = parts.get(2) {
                Some(PathBuf::from(p))
            } else {
                let input = inquire::Text::new("Caminho de destino:").prompt().ok();
                input.map(PathBuf::from)
            };

            if let (Some(s), Some(d)) = (src, dst) {
                log::info(&format!("Cópia segura: {:?} -> {:?}", s, d));
                match vault::safe_copy(s.to_str().unwrap(), d.to_str().unwrap()) {
                    Ok(_) => println!("{}", "✔ Arquivo copiado".green()),
                    Err(e) => {
                        log::error(&format!("Erro em safe-copy: {}", e));
                        eprintln!("{}", format!("✖ Erro: {}", e).red());
                    }
                }
            }
        }

        "allow-write" => {
            if let Some(path) = path_assistant::ensure_path(parts.get(1), "Arquivo para liberar escrita:", false) {
                log::info(&format!("Liberando escrita: {:?}", path));
                vault::allow_write(path.to_str().unwrap());
                println!("{}", "✔ Escrita liberada".green());
            }
        }

        "read-directory" => {
            if let Some(dir) = path_assistant::ensure_path(parts.get(1), "Diretório para listar:", true) {
                let dir_str = dir.to_str().unwrap();
                log::info(&format!("Listando diretório: {}", dir_str));
                let files = vault::read_directory(dir_str);
                println!("{}", format!("📁 {}:", dir_str).blue());
                for f in files {
                    println!("  {}", format!("• {}", f).white());
                }
            }
        }

        "add-file" => {
            let vault_path = path_assistant::ensure_path(parts.get(1), "Caminho do cofre:", true);
            let file       = path_assistant::ensure_path(parts.get(2), "Arquivo para adicionar:", false);

            if let (Some(v), Some(f)) = (vault_path, file) {
                log::info(&format!("Adicionando arquivo {:?} ao cofre {:?}", f, v));
                match vault::add_file(v.to_str().unwrap(), f.to_str().unwrap()) {
                    Ok(_) => println!("{}", "✔ Arquivo adicionado".green()),
                    Err(e) => {
                        log::error(&format!("Erro em add-file: {}", e));
                        eprintln!("{}", format!("✖ Erro: {}", e).red());
                    }
                }
            }
        }

        "remove-file" => {
            let vault_path = path_assistant::ensure_path(parts.get(1), "Caminho do cofre:", true);
            let file = if let Some(f) = parts.get(2) {
                Some(f.to_string())
            } else {
                inquire::Text::new("Nome do arquivo no cofre:").prompt().ok()
            };

            if let (Some(v), Some(f)) = (vault_path, file) {
                log::info(&format!("Removendo arquivo {} do cofre {:?}", f, v));
                match vault::remove_file(v.to_str().unwrap(), &f) {
                    Ok(_) => println!("{}", "✔ Arquivo removido".green()),
                    Err(e) => {
                        log::error(&format!("Erro em remove-file: {}", e));
                        eprintln!("{}", format!("✖ Erro: {}", e).red());
                    }
                }
            }
        }

        "status" => {
            if let Some(vault_path) = path_assistant::ensure_path(parts.get(1), "Caminho ou ID do cofre:", true) {
                log::info(&format!("Verificando status do cofre: {:?}", vault_path));
                match vault::get_vault_status(vault_path.to_str().unwrap()) {
                    Ok(_)  => (),
                    Err(e) => {
                        log::error(&format!("Erro em status: {}", e));
                        eprintln!("{}", format!("✖ Erro: {}", e).red());
                    }
                }
            }
        }

        "encrypt" => {
            if let Some(file) = path_assistant::ensure_path(parts.get(1), "Arquivo para criptografar:", false) {
                let pass = get_password("Senha:", parts.get(2));
                if !pass.is_empty() {
                    log::info(&format!("Criptografando arquivo: {:?}", file));
                    match crypto::encrypt_file(&file, &pass) {
                        Ok(_) => println!("{}", "✔ Arquivo criptografado".green()),
                        Err(e) => {
                            log::error(&format!("Erro em encrypt: {}", e));
                            eprintln!("{}", format!("✖ Erro: {}", e).red());
                        }
                    }
                } else {
                    println!("{}", "✖ Senha vazia ou erro ao ler senha".red());
                }
            }
        }

        "decrypt" => {
            if let Some(file) = path_assistant::ensure_path(parts.get(1), "Arquivo para descriptografar:", false) {
                let pass = get_password("Senha:", parts.get(2));
                if !pass.is_empty() {
                    log::info(&format!("Descriptografando arquivo: {:?}", file));
                    match crypto::decrypt_file(&file, &pass) {
                        Ok(_) => println!("{}", "✔ Arquivo descriptografado".green()),
                        Err(e) => {
                            log::error(&format!("Erro em decrypt: {}", e));
                            eprintln!("{}", format!("✖ Erro: {}", e).red());
                        }
                    }
                } else {
                    println!("{}", "✖ Senha vazia ou erro ao ler senha".red());
                }
            }
        }

        "secure-copy" => {
            let file       = path_assistant::ensure_path(parts.get(1), "Arquivo de origem:", false);
            let vault_path = path_assistant::ensure_path(parts.get(2), "Caminho do cofre:", true);

            if let (Some(f), Some(v)) = (file, vault_path) {
                let pass = get_password("Defina uma senha para o cofre:", parts.get(3));
                if !pass.is_empty() {
                    log::info(&format!("Secure-copy: {:?} para {:?}", f, v));
                    vault::secure_store(f.to_str().unwrap(), v.to_str().unwrap(), &pass);
                    println!("{}", "✔ Arquivo protegido e armazenado no cofre".green());
                } else {
                    println!("{}", "✖ Senha vazia ou erro ao processar senha".red());
                }
            }
        }

        "system-information" => {
            let options = sys_info::SystemOptions {
                cpu:       parts.contains(&"cpu"),
                memory:    parts.contains(&"memory"),
                disks:     parts.contains(&"disks"),
                networks:  parts.contains(&"networks"),
                processes: parts.contains(&"processes"),
            };
            sys_info::system_information(options);
        }

        "list-process-status" => {
            let options = sys_info::SystemOptions {
                cpu:       false,
                memory:    false,
                disks:     false,
                networks:  false,
                processes: true,
            };
            sys_info::list_process_status(&options);
        }

        "derive-master-key" => {
            let password = inquire::Password::new("Senha:").prompt().unwrap_or_default();
            let usb_key_input = inquire::Text::new("Chave USB (hex):").prompt().unwrap_or_default();
            let usb_key_bytes = match hex::decode(usb_key_input.trim()) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error(&format!("Erro ao decodificar chave USB: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                    return;
                }
            };

            match crypto::derive_master_key(&password, &usb_key_bytes) {
                Ok(master_key) => println!("{}", format!("Master Key derivada: {}", hex::encode(master_key)).green()),
                Err(e) => {
                    log::error(&format!("Erro em derive-master-key: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }


        "help" => {
            show_help();
            println!("{}", "Digite o número da pergunta (ou Enter para pular):".purple());
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            let answer = input.trim();
            if !answer.is_empty() {
                cli::questions(answer);
            }
        }

        "exit" => {
            log::info("Aplicação encerrada pelo usuário.");
            println!("{}", "Saindo...".yellow());
            std::process::exit(0);
        }

        /* ══ novos — core C ════════════════════════════════════════════ */

        /* vault-list */
        "vault-list" => {
            log::info("Listando cofres do catálogo (core C)");
            vault::vault_list();
        }

        /* vault-create <name> <path> <type> */
        "vault-create" => {
            let name      = parts.get(1).map(|s| *s);
            let path      = parts.get(2).map(|s| *s);
            let vtype_str = parts.get(3).copied().unwrap_or("normal");

            let password = if vtype_str == "protected" {
                let p1 = prompt_password("Senha do cofre:");
                if p1.is_empty() {
                    eprintln!("{}", "✖ Senha obrigatória para cofre protegido.".red());
                    return;
                }
                let p2 = prompt_password("Confirme a senha:");
                if p1 != p2 {
                    eprintln!("{}", "✖ Senhas não coincidem.".red());
                    return;
                }
                Some(p1)
            } else {
                None
            };

            log::info(&format!("vault-create name={:?} path={:?} type={}", name, path, vtype_str));
            match vault::vault_create(name, vtype_str, path, password.as_deref()) {
                Ok(_)  => println!("{}", "✔ Cofre criado no core C.".green()),
                Err(e) => {
                    log::error(&format!("vault-create: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-delete <id> */
        "vault-delete" => {
            let Some(id) = parse_id(parts.get(1), "vault-delete") else { return };
            let pass = prompt_password_opt("Senha (Enter para pular):");

            log::info(&format!("vault-delete id={}", id));
            match vault::vault_delete(id, pass.as_deref()) {
                Ok(_)  => println!("{}", "✔ Cofre deletado.".green()),
                Err(e) => {
                    log::error(&format!("vault-delete: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-rename <id> <new_name> */
        "vault-rename" => {
            let Some(id) = parse_id(parts.get(1), "vault-rename") else { return };
            let new_name = match parts.get(2) {
                Some(n) => *n,
                None => {
                    eprintln!("{}", "✖ vault-rename: novo nome obrigatório.".red());
                    return;
                }
            };
            let pass = prompt_password_opt("Senha (Enter para pular):");

            log::info(&format!("vault-rename id={} new_name={}", id, new_name));
            match vault::vault_rename(id, new_name, pass.as_deref()) {
                Ok(_)  => println!("{}", "✔ Cofre renomeado.".green()),
                Err(e) => {
                    log::error(&format!("vault-rename: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-unlock <id> */
        "vault-unlock" => {
            let Some(id) = parse_id(parts.get(1), "vault-unlock") else { return };
            let pass = prompt_password("Senha:");
            if pass.is_empty() {
                eprintln!("{}", "✖ Senha obrigatória para desbloquear.".red());
                return;
            }

            log::info(&format!("vault-unlock id={}", id));
            match vault::vault_unlock(id, &pass) {
                Ok(_)  => println!("{}", "✔ Cofre desbloqueado.".green()),
                Err(e) => {
                    log::error(&format!("vault-unlock: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-passwd <id> */
        "vault-passwd" => {
            let Some(id) = parse_id(parts.get(1), "vault-passwd") else { return };
            let old_pass = prompt_password("Senha atual:");
            let new_pass = prompt_password("Nova senha:");
            let cnf_pass = prompt_password("Confirme nova senha:");

            if new_pass != cnf_pass {
                eprintln!("{}", "✖ Senhas não coincidem.".red());
                return;
            }
            if new_pass.is_empty() {
                eprintln!("{}", "✖ Nova senha não pode ser vazia.".red());
                return;
            }

            log::info(&format!("vault-passwd id={}", id));
            match vault::vault_change_password(id, &old_pass, &new_pass) {
                Ok(_)  => println!("{}", "✔ Senha alterada.".green()),
                Err(e) => {
                    log::error(&format!("vault-passwd: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-encrypt <id> */
        "vault-encrypt" => {
            let Some(id) = parse_id(parts.get(1), "vault-encrypt") else { return };
            let pass = prompt_password("Senha do cofre:");
            if pass.is_empty() {
                eprintln!("{}", "✖ Senha obrigatória para criptografar.".red());
                return;
            }

            log::info(&format!("vault-encrypt id={}", id));
            match vault::vault_encrypt(id, &pass) {
                Ok(_)  => println!("{}", "✔ Arquivos criptografados (AES-256).".green()),
                Err(e) => {
                    log::error(&format!("vault-encrypt: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-decrypt <id> */
        "vault-decrypt" => {
            let Some(id) = parse_id(parts.get(1), "vault-decrypt") else { return };
            let pass = prompt_password("Senha do cofre:");
            if pass.is_empty() {
                eprintln!("{}", "✖ Senha obrigatória para descriptografar.".red());
                return;
            }

            log::info(&format!("vault-decrypt id={}", id));
            match vault::vault_decrypt(id, &pass) {
                Ok(_)  => println!("{}", "✔ Arquivos descriptografados.".green()),
                Err(e) => {
                    log::error(&format!("vault-decrypt: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-scan <id> */
        "vault-scan" => {
            let Some(id) = parse_id(parts.get(1), "vault-scan") else { return };
            log::info(&format!("vault-scan id={}", id));
            match vault::vault_scan(id) {
                Ok(_)  => println!("{}", "✔ Varredura concluída.".green()),
                Err(e) => {
                    log::error(&format!("vault-scan: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-resolve <id> */
        "vault-resolve" => {
            let Some(id) = parse_id(parts.get(1), "vault-resolve") else { return };
            let pass = prompt_password_opt("Senha (Enter para pular):");

            log::info(&format!("vault-resolve id={}", id));
            match vault::vault_resolve(id, pass.as_deref()) {
                Ok(_)  => println!("{}", "✔ Alerta resolvido.".green()),
                Err(e) => {
                    log::error(&format!("vault-resolve: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-info <id> */
        "vault-info" => {
            let Some(id) = parse_id(parts.get(1), "vault-info") else { return };
            log::info(&format!("vault-info id={}", id));
            vault::vault_info(id);
        }

        /* vault-files <id> */
        "vault-files" => {
            let Some(id) = parse_id(parts.get(1), "vault-files") else { return };
            log::info(&format!("vault-files id={}", id));
            vault::vault_files(id);
        }

        /* vault-sandbox <id> */
        "vault-sandbox" => {
            let Some(id) = parse_id(parts.get(1), "vault-sandbox") else { return };
            let pass = prompt_password_opt("Senha (Enter para pular):");

            log::info(&format!("vault-sandbox id={}", id));
            match vault::vault_sandbox(id, pass.as_deref()) {
                Ok(_)  => (),
                Err(e) => {
                    log::error(&format!("vault-sandbox: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
        }

        /* vault-rule <id> <max_fails> [hour_from hour_to] */
        "vault-rule" => {
            let Some(id) = parse_id(parts.get(1), "vault-rule") else { return };
            let max_fails: i32 = match parts.get(2) {
                Some(v) => match v.parse() {
                    Ok(n) => n,
                    Err(_) => {
                        eprintln!("{}", "✖ vault-rule: max_fails deve ser inteiro.".red());
                        return;
                    }
                },
                None => {
                    eprintln!("{}", "✖ vault-rule: max_fails obrigatório.".red());
                    return;
                }
            };

            let hour_from: Option<i32> = parts.get(3).and_then(|v| v.parse().ok());
            let hour_to:   Option<i32> = parts.get(4).and_then(|v| v.parse().ok());

            log::info(&format!(
                "vault-rule id={} max_fails={} hours={:?}-{:?}",
                id, max_fails, hour_from, hour_to
            ));
            match vault::vault_rule(id, max_fails, hour_from, hour_to) {
                Ok(_)  => println!("{}", "✔ Regra adicionada.".green()),
                Err(e) => {
                    log::error(&format!("vault-rule: {}", e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }
            
        }

        /* vault-export <id> <file> <dst> */
        "vault-export" => {
            let Some(id) = parse_id(parts.get(1), "vault-export") else { return };
            let filename = parts.get(2).map(|s| *s);
            let dst_path = parts.get(3).map(|s| *s);

            if let (Some(f), Some(d)) = (filename, dst_path) {
                log::info(&format!("vault-export id={} file={} dst={}", id, f, d));
                match vault::vault_export_file(id, f, d) {
                    Ok(_)  => println!("{}", "✔ Arquivo exportado com sucesso.".green()),
                    Err(e) => {
                        log::error(&format!("vault-export: {}", e));
                        eprintln!("{}", format!("✖ Erro: {}", e).red());
                    }
                }
            } else {
                eprintln!("{}", "✖ vault-export: nome do arquivo e destino obrigatórios.".red());
            }
        }

        /* ── comando desconhecido — Levenshtein sugere o mais próximo ── */
        unknown => {
            log::warn(&format!("Comando inválido: {}", unknown));

            match suggest_command(unknown) {
                Some(suggestion) => {
                    println!(
                        "{}",
                        format!("✖ Comando '{}' não existe.", unknown).red()
                    );
                    println!(
                        "{}",
                        format!("  Você quis dizer '{}'?", suggestion).yellow()
                    );
                }
                None => {
                    println!("{}", format!("✖ Comando '{}' não existe.", unknown).red());
                    println!("{}", "Digite 'help' para ver os comandos.".yellow());
                }
            }
        }
    }
}

/* 
 *  MAIN
 *  */
fn main() {
    let mut rl = DefaultEditor::new().unwrap();
    log::info("Aplicação iniciada.");

    /* ── Inicializa o core C: carrega catálogo do disco, inicia monitor ── */
    match vault::vault_init() {
        Ok(()) => log::info("Core C inicializado: catálogo carregado do disco."),
        Err(e) => {
            eprintln!(
                "{}",
                format!("⚠ Falha ao inicializar core C: {} (continuando sem persistência)", e)
                    .yellow()
            );
        }
    }

    println!(
        "{}",
        "VaranusCore v0.8.1 iniciado!  Sub-sistema de Assistência de Caminhos ATIVO.
        todos os direitos reservados.
        Digite 'help'"
            .bright_green()
    );

    /* ── Ctrl+C: shutdown graceful — salva catálogo antes de sair ─────── */
    ctrlc::set_handler(|| {
        println!("\n{}", "^C — Salvando catálogo...".yellow());
        log::info("Ctrl+C recebido — executando shutdown graceful");

        /* Salva catálogo no disco e limpa memória sensível */
        match vault::vault_shutdown() {
            Ok(()) => log::info("Catálogo salvo com sucesso."),
            Err(e) => {
                eprintln!("⚠ Erro ao salvar catálogo: {}", e);
                log::error(&format!("Erro no shutdown: {}", e));
            }
        }

        log::info("Aplicação fechando (graceful)");
        std::process::exit(0);
    })
    .expect("Erro ao definir handler");

    loop {
        let readline = rl.readline(&"VaranusCore> ".bright_blue().to_string());

        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str()).ok();
                let input = line.trim();
                if input.is_empty() {
                    continue;
                }

                /* Comando 'quit' / 'exit' → shutdown graceful */
                if input == "quit" || input == "exit" {
                    println!("{}", "Salvando catálogo e encerrando...".yellow());
                    match vault::vault_shutdown() {
                        Ok(()) => log::info("Catálogo salvo com sucesso."),
                        Err(e) => eprintln!("⚠ Erro ao salvar: {}", e),
                    }
                    log::info("Aplicação encerrada pelo usuário.");
                    break;
                }

                let parts: Vec<&str> = input.split_whitespace().collect();
                handle_command(parts);
            }

            Err(ReadlineError::Eof) => {
                println!("\n{}", "^D — Salvando catálogo...".yellow());
                match vault::vault_shutdown() {
                    Ok(()) => log::info("Catálogo salvo com sucesso (EOF)."),
                    Err(e) => eprintln!("⚠ Erro ao salvar: {}", e),
                }
                log::info("EOF detectado.");
                break;
            }

            Err(err) => {
                log::error(&format!("Erro na leitura: {:?}", err));
                /* Tenta salvar mesmo em erro */
                let _ = vault::vault_shutdown();
                break;
            }
        }
    }
}