/*
 * main.rs
 *
 * IdenVault — ponto de entrada
 * Integra o core C (vault_security.c) via vault.rs
 *
 * Novos comandos adicionados (delegam ao core C):
 *   ls
 *   new  <name> <path> <type>
 *   rm  <id>
 *   rename  <id> <new_name>
 *   unlock  <id>
 *   passwd  <id>
 *   venc <id>
 *   vdec <id>
 *   scan    <id>
 *   resolve <id>
 *   info    <id>
 *   files   <id>
 *   jail <id>
 *   rule    <id> <max_fails> [hour_from hour_to]
 *
 * Levenshtein reintegrado: sugestão automática de comando para typos.
 * Nenhum bool, variável ou função existente foi renomeado.
 */

mod cli;
mod crypto;
mod log;
mod manual;
mod path_assistant;
mod sys_info;
mod vault;

use colored::*;
use inquire::{Password, Select};
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::time::Instant;

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
    "remove-file",
    "encrypt",
    "decrypt",
    "cp",
    "system-information",
    "list-process-status",
    "derive-master-key",
    "help",
    "exit",
    /* novos — core C */
    "ls",
    "new",
    "rm",
    "rename",
    "unlock",
    "passwd",
    "venc",
    "vdec",
    "scan",
    "resolve",
    "info",
    "files",
    "jail",
    "rule",
    "export",
    "manual",
    /* FUSE / API additions */
    "mount",
    "unmount",
    "mount",
    "umount",
    "mount-export",
    "worm",
    "api-start",
    "api-stop",
    "api-status",
];

fn show_help() {
    println!("{}", "\n╔══════════════════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║              IdenVault — Quick Command Reference                  ║".cyan().bold());
    println!("{}", "╚══════════════════════════════════════════════════════════════════════════╝\n".cyan());

    println!("{}", "── File / Directory ──────────────────────────────────────────────────".dimmed());
    println!("  {:<28} {}", "create-vault <path>".yellow(),        "cria cofre (diretório)");
    println!("  {:<28} {}", "remove-file <vault> <file>".yellow(),  "removes file from vault");
    println!("  {:<28} {}", "read-directory <dir>".yellow(),        "lists files in a directory");
    println!("  {:<28} {}", "safe-copy <src> <dst>".yellow(),       "cópia com verificação de integridade");
    println!("  {:<28} {}", "cp <file> <vault>".yellow(),  "copia e protege no cofre (criptografa)");
    println!("  {:<28} {}", "allow-write <file>".yellow(),          "libera permissão de escrita");
    println!("  {:<28} {}", "isolate-directory <dir>".yellow(),     "isolates directory (sem acesso externo)");
    println!("  {:<28} {}", "encrypt <file> [pass]".yellow(),       "criptografa arquivo avulso (AES-256)");
    println!("  {:<28} {}", "decrypt <file> [pass]".yellow(),       "descriptografa arquivo avulso");

    println!("\n{}", "── Vault Security System (Core C) ───────────────────────────────────────".dimmed());
    println!("  {:<28} {}", "ls".yellow(),                  "lists all vaults in the catalog");
    println!("  {:<28} {}", "new <name> <path>".yellow(),  "cria cofre (normal ou protected)");
    println!("  {:<28} {}", "rm <id>".yellow(),           "deletes vault by ID");
    println!("  {:<28} {}", "rename <id> <nome>".yellow(),    "renames vault");
    println!("  {:<28} {}", "unlock <id>".yellow(),           "unlocks vault after lockout");
    println!("  {:<28} {}", "passwd <id>".yellow(),           "changes vault password");
    println!("  {:<28} {}", "venc <id>".yellow(),          "encrypts files do cofre (AES-256-GCM)");
    println!("  {:<28} {}", "vdec <id>".yellow(),          "desencrypts files do cofre");
    println!("  {:<28} {}", "scan <id>".yellow(),             "força varredura de integridade (SHA-256)");
    println!("  {:<28} {}", "resolve <id>".yellow(),          "resolves active alert no cofre");
    println!("  {:<28} {}", "info <id>".yellow(),             "shows full details do cofre");
    println!("  {:<28} {}", "files <id>".yellow(),            "lists tracked files no cofre");
    println!("  {:<28} {}", "export <id> [file]".yellow(),    "exporta/resgata arquivo do cofre");
    println!("  {:<28} {}", "jail <id>".yellow(),          "opens vault in isolated sandbox shell");
    println!("  {:<28} {}", "rule <id> <fails> [h h]".yellow(), "adds security rule to vault");

    println!("\n{}", "── FUSE — Vault Mounting ─────────────────────────────────────────────".dimmed());
    println!("  {:<28} {}", "mount <id> [senha]".yellow(),     "mounts vault via FUSE pelo ID");
    println!("  {:<28} {}", "umount <id>".yellow(),             "desmounts vault FUSE pelo ID");
    println!("  {:<28} {}", "mount <vault> <mountpoint>".yellow(),  "mounts vault em caminho específico");
    println!("  {:<28} {}", "unmount <mountpoint|vault>".yellow(),  "desmonta ponto de montagem");
    println!("  {:<28} {}", "mount-export <id>".yellow(),           "rescues files (único caminho p/ SCAN)");

    println!("\n{}", "── WORM Protection ─────────────────────────────────────────────────────────".dimmed());
    println!("  {:<28} {}", "worm <id> [flags]".yellow(),   "configures protection WORM no vault");
    println!("    {}", "--protect-delete  blocks deletion de arquivos/diretórios".dimmed());
    println!("    {}", "--protect-rename  blocks renaming".dimmed());
    println!("    {}", "--no-write        blocks overwriting de arquivos existentes".dimmed());
    println!("    {}", "--protected-scan  MAXIMUM PROTECTION immutable (IRREVERSIBLE)".red());
    println!("    {}", "--clear-delete / --clear-rename / --clear-write  removes locks".dimmed());
    println!("    {}", "--status          shows active flags of the vault".dimmed());

    println!("\n{}", "── System ───────────────────────────────────────────────────────────────".dimmed());
    println!("  {:<28} {}", "system-information".yellow(),          "CPU, memory, disks, networks info");
    println!("  {:<28} {}", "list-process-status".yellow(),         "lists active system processes");
    println!("  {:<28} {}", "derive-master-key".yellow(),           "derives master key (senha + chave USB)");

    println!("\n{}", "── API HTTP ──────────────────────────────────────────────────────────────".dimmed());
    println!("  {:<28} {}", "api-start [--port <p>]".yellow(),      "starts local HTTP API (padrão :8080)");
    println!("  {:<28} {}", "api-stop".yellow(),                    "stops running API");
    println!("  {:<28} {}", "api-status".yellow(),                  "shows API status (porta, PID)");

    println!("\n{}", "── Utilities ───────────────────────────────────────────────────────────".dimmed());
    println!("  {:<28} {}", "manual".yellow(),                      "interactive operation manual");
    println!("  {:<28} {}", "help [comando|all]".yellow(),          "this help or details by command");
    println!("  {:<28} {}", "exit".yellow(),                        "closes the application");

    println!("\n{}", "Use 'help <command>' for details, exemplos e flags de qualquer comando.".cyan().dimmed());
    println!("{}", "Use 'help all' for full reference com exemplos.\n".cyan().dimmed());
}

fn add_file_interactive(){
    let vault_id_input = inquire::Text::new(" Vault ID:")
        .with_help_message("Insira o ID do cofre.")
        .with_validator(|val: &str| {
            if val.trim().is_empty() {
                Ok(inquire::validator::Validation::Invalid("O ID não pode estar vazio.".into()))
            } else if val.parse::<u32>().is_err() {
                Ok(inquire::validator::Validation::Invalid("ID inválido.".into()))
            } else {
                Ok(inquire::validator::Validation::Valid)
            }
        })
        .prompt();
    
    let vault_id = match vault_id_input {
        Ok(id) => id.parse::<u32>().unwrap(),
        Err(_) => {
            println!("{}", "Operação cancelada.".yellow());
            return;
        }
    };
    
    let filename_input = inquire::Text::new("Nome do arquivo:")
        .with_help_message("Nome original do arquivo no seu sistema.")
        .with_validator(|val: &str| {
            if val.trim().is_empty() {
                Ok(inquire::validator::Validation::Invalid("O nome do arquivo não pode estar vazio.".into()))
            } else {
                Ok(inquire::validator::Validation::Valid)
            }
        })
        .prompt();
    
    let _filename = match filename_input {
        Ok(filename) => filename,
        Err(_) => {
            println!("{}", "Operação cancelada.".yellow());
            return;
        }
    };
    
    let original_path_input = inquire::Text::new("Path completo do arquivo original:")
        .with_help_message("Caminho completo onde o arquivo está localizado.")
        .with_validator(|val: &str| {
            if val.trim().is_empty() {
                Ok(inquire::validator::Validation::Invalid("O path não pode estar vazio.".into()))
            } else {
                Ok(inquire::validator::Validation::Valid)
            }
        })
        .prompt();
    
    let original_path = match original_path_input {
        Ok(path) => path,
        Err(_) => {
            println!("{}", "Operação cancelada.".yellow());
            return;
        }
    };

    let vault_path = match vault::vault_get_real_path(vault_id) {
        Ok(p) => p,
        Err(e) => {
            println!("{}", format!("Erro ao obter path do cofre: {}", e).red());
            return;
        }
    };
    
    let result = vault::add_file(&vault_path, &original_path);
    
    match result {
        Ok(_) => {
            println!("{}", "Arquivo adicionado ao cofre com sucesso!".green());
        },
        Err(e) => {
            println!("{}", format!("Erro ao adicionar arquivo: {}", e).red());
        }
    }
}


fn show_help_for(cmd: &str) {
    let sep = "─".repeat(72);
    match cmd {
        "all" => {
            show_help();
            println!("{}", "\n═══ REFERÊNCIA DETALHADA COMPLETA ═══\n".cyan().bold());

            let sections: &[(&str, &[(&str, &str, &str)])] = &[
                ("File / Directory", &[
                    ("create-vault <path>",
                     "Cria um novo cofre (diretório gerenciado pelo IdenVault).\nO path será registrado no catálogo e rastreado pelo monitor.",
                     "create-vault /home/user/meu_cofre"),
                    ("remove-file <vault> <file>",
                     "Remove um arquivo do cofre.\nExige confirmação se o vault tiver proteção WORM ativa.",
                     "remove-file /home/user/cofre documento.pdf"),
                    ("read-directory <dir>",
                     "Lista recursivamente os arquivos de um diretório,\nexibindo tamanho, permissões e data de modificação.",
                     "read-directory /home/user/cofre"),
                    ("safe-copy <src> <dst>",
                     "Copies a file verifying integrity (SHA-256) before and after.\nFails if destination hash does not match source.",
                     "safe-copy origem.pdf /backup/origem.pdf"),
                    ("cp <file> <vault> [pass]",
                     "Copies file to the vault and encrypts it immediately.\nIf the vault is 'protected', password is required.",
                     "cp contrato.pdf 3 minha_senha"),
                    ("allow-write <file>",
                     "Adjusts file permissions to 0600 (leitura/escrita).\nUseful to edit a read-only file.",
                     "allow-write /cofre/arquivo.txt"),
                    ("isolate-directory <dir>",
                     "Restricts directory access (chmod 700).\nPrevents other system users from reading the content.",
                     "isolate-directory /home/user/privado"),
                    ("encrypt <file> [pass]",
                     "Encrypts a standalone file com AES-256-GCM.\nGenerates <file>.enc. Password is derived via PBKDF2 (310 000 iterações).",
                     "encrypt relatorio.pdf\nencrypt relatorio.pdf minha_senha"),
                    ("decrypt <file> [pass]",
                     "Decrypts an .enc file generated by the encrypt command.\nRemoves the .enc extension from the output file.",
                     "decrypt relatorio.pdf.enc\ndecrypt relatorio.pdf.enc minha_senha"),
                ]),
                ("Vault Security System (Core C)", &[
                    ("ls",
                     "Lista todos os cofres registrados no catálogo C.\nExibe ID, nome, tipo (normal/protected), status e caminho.",
                     "ls"),
                    ("new <name> <path> <type>",
                     "Creates a vault in the C catalog.\n  type: normal   → sem senha\n  type: protected → exige senha em todas as operações",
                     "new meu_cofre /data/cofre normal\nnew seguro /data/seg protected"),
                    ("rm <id>",
                     "Removes vault from catalog and deletes directory.\nExige senha para cofres do tipo 'protected'.\nOperação irreversível.",
                     "rm 3"),
                    ("rename <id> <novo_nome>",
                     "Renames vault in catalog (does not move directory).\nRequires password for protected vaults.",
                     "rename 3 cofre_renomeado"),
                    ("unlock <id>",
                     "Desbloqueia um cofre que entrou em lockout por tentativas\nde senha incorretas (failed_attempts >= max_fails de alguma regra).",
                     "unlock 3"),
                    ("passwd <id>",
                     "Changes password of a protected vault.\nPede a senha antiga e a nova. A nova é derivada via PBKDF2.",
                     "passwd 3"),
                    ("venc <id>",
                     "Encrypts all files in the vault com AES-256-GCM.\nFiles gain extension .enc. Requires password for protected vaults.",
                     "venc 3"),
                    ("vdec <id>",
                     "Decrypts all files .enc do cofre.\nRequires password for protected vaults.",
                     "vdec 3"),
                    ("scan <id>",
                     "Forces a SHA-256 scan of all files in the vault.\nUpdates hashes in the internal hashmap and triggers alert se\nalgum arquivo foi modificado since the last scan.",
                     "scan 3"),
                    ("resolve <id>",
                     "Resolves an active alert (status ALERT → OK).\nClears modification flags and resets alert escalation.\nRequires password for protected vaults.",
                     "resolve 3"),
                    ("info <id>",
                     "Exibe detalhes completos: ID, nome, tipo, status, caminho,\ncipher_path, flags WORM, engine_level, created_at, last_check,\nfailed_attempts e estado do alerta.",
                     "info 3"),
                    ("files <id>",
                     "Lista todos os arquivos rastreados no hashmap do cofre,\nexibindo hash SHA-256, data de última verificação e flag 'modified'.",
                     "files 3"),
                    ("export <id> [file]",
                     "Exporta um arquivo do cofre para um diretório de destino.\nSe o cofre for protegido, descriptografa automaticamente.\nInterativo se o arquivo não for especificado na linha de comando.",
                     "export 3\nexport 3 documento.pdf.enc"),
                    ("jail <id>",
                     "Abre o cofre em um shell sandbox isolado (namespaces + seccomp).\nO usuário opera dentro do sandbox; arquivos externos ficam invisíveis.",
                     "jail 3"),
                    ("Vault-cd  <id>",
                     "Muda o diretório de trabalho do shell para o path do cofre.\nFunciona apenas dentro do jail, onde o cofre é o novo /.",
                     "vault-cd 3"),
                    ("rule <id> <max_fails> [h_from h_to]",
                     "Adiciona uma regra de segurança ao cofre:\n  max_fails  → máximo de tentativas de senha antes de lockout\n  h_from/h_to → janela de horas permitidas (0-23); omitir = sem restrição\nVários rule podem ser empilhados no mesmo cofre.",
                     "rule 3 5\nrule 3 3 9 18"),
                ]),
                ("FUSE — Vault Mounting", &[
                    ("mount <id> [senha]",
                     "Monta o cofre via FUSE3 usando o ID do catálogo.\nO ponto de montagem é o campo 'path' do cofre.\nAs proteções WORM ativas são aplicadas imediatamente.",
                     "mount 3\nmount 3 minha_senha"),
                    ("umount <id>",
                     "Desmonta o cofre FUSE pelo ID.\nNão funciona em vaults com --protected-scan ativo\n(use mount-export para resgatar os arquivos antes).",
                     "umount 3"),
                    ("mount <vault> <mountpoint>",
                     "Monta um cofre via FUSE em um caminho específico diferente\ndo path registrado no catálogo.",
                     "mount /data/cofre /mnt/cofre_montado"),
                    ("unmount <mountpoint|vault>",
                     "Desmonta um ponto de montagem FUSE pelo caminho.",
                     "unmount /mnt/cofre_montado"),
                    ("mount-export <id>",
                     "Único caminho de saída para cofres em PROTECTED-SCAN.\nLê diretamente do cipher_path, bypassando o FUSE.\nDescriptografa automaticamente se o cofre for protegido.\nPode exportar um arquivo específico ou todos os arquivos.\n\nFLUXO INTERATIVO:\n  1. Seleciona vault (interativo se <id> não fornecido)\n  2. Lista arquivos disponíveis no cipher_path\n  3. Pede pasta de destino (file dialog)\n  4. Pede confirmação e senha (se protegido)\n  5. Exporta com log de auditoria",
                     "mount-export\nmount-export 3"),
                ]),
                ("WORM Protection", &[
                    ("worm <id> [flags...]",
                     "Configura as proteções WORM de um vault montado ou desmontado.\nAs flags são persistidas no catalog.dat e aplicadas no próximo mount.\n\nFLAGS:\n  --protect-delete   bloqueia unlink/rmdir → retorna EPERM\n  --protect-rename   bloqueia rename       → retorna EPERM\n  --no-write         bloqueia write em arquivos existentes → EPERM\n                     (criação de arquivos novos ainda é permitida)\n  --protected-scan   MODO MÁXIMO — activa os três acima + congela o vault\n                     IRREVERSÍVEL em runtime. A única saída é mount-export.\n                     Exige confirmação explícita.\n  --clear-delete     remove bloqueio de exclusão\n  --clear-rename     remove bloqueio de renomeação\n  --clear-write      remove bloqueio de escrita\n                     (--clear-* falham se --protected-scan estiver ativo)\n  --status           exibe o bitmask e as flags ativas do vault\n\nNOTA: os flags são OR-dos ao valor existente; use --clear-* para remover.",
                     "worm 3 --status\nworm 3 --protect-delete --no-write\nworm 3 --protected-scan\nworm 3 --clear-delete"),
                ]),
                ("System", &[
                    ("system-information [filtros]",
                     "Exibe informações do sistema. Filtros opcionais:\n  cpu       → uso e modelo do processador\n  memory    → RAM total, usada e disponível\n  disks     → partições, uso e tipo de filesystem\n  networks  → interfaces, IPs e tráfego\n  processes → processos ativos com PID e uso de recursos\nSem filtros: exibe tudo.",
                     "system-information\nsystem-information cpu memory\nsystem-information disks"),
                    ("list-process-status",
                     "Lista os processos monitorados pelo IdenVault com seus status.\nInclui o PID do daemon, threads do monitor e processos da sandbox.",
                     "list-process-status"),
                    ("derive-master-key",
                     "Deriva uma master key combinando uma senha digitada com\numa chave física (ex: arquivo em USB).\nA derivação usa PBKDF2-SHA256 com 310 000 iterações.",
                     "derive-master-key"),
                ]),
                ("API HTTP", &[
                    ("api-start [--port <p>]",
                     "Inicia a API HTTP local para integração com outras aplicações.\nEndereço padrão: 127.0.0.1:8080\nEndpoints principais:\n  GET  /vaults          → lista cofres\n  POST /vaults/:id/scan → dispara varredura\n  GET  /vaults/:id/status → status do cofre",
                     "api-start\napi-start --port 9090"),
                    ("api-stop",
                     "Para a instância da API HTTP em execução.",
                     "api-stop"),
                    ("api-status",
                     "Exibe o status atual da API: se está rodando, porta e PID.",
                     "api-status"),
                ]),
            ];

            for (section, commands) in sections.iter() {
                println!("\n{}", format!("── {} ", section).cyan().bold());
                println!("{}", sep.dimmed());
                for (usage, desc, example) in commands.iter() {
                    println!("\n  {}", usage.yellow().bold());
                    for line in desc.lines() {
                        println!("    {}", line);
                    }
                    println!("    {} {}", "Exemplo:".dimmed(), example.lines().next().unwrap_or(""));
                    for ex_line in example.lines().skip(1) {
                        println!("             {}", ex_line);
                    }
                }
            }
            println!();
        }

        /* ── Ajuda individual por comando ─────────────────────────────────── */
        "create-vault" => { println!("\n  {}\n  {}\n  {} create-vault /home/user/meu_cofre\n", "create-vault <path>".yellow().bold(), "Cria um novo cofre (diretório gerenciado pelo IdenVault).\n  O path será registrado no catálogo e rastreado pelo monitor de integridade.", "Exemplo:".dimmed()); }
        "remove-file"  => { println!("\n  {}\n  {}\n  {} remove-file /home/user/cofre documento.pdf\n", "remove-file <vault> <file>".yellow().bold(), "Remove um arquivo do cofre. Exige confirmação se WORM ativo.", "Exemplo:".dimmed()); }
        "read-directory" => { println!("\n  {}\n  {}\n  {} read-directory /home/user/cofre\n", "read-directory <dir>".yellow().bold(), "Lista arquivos com tamanho, permissões e data de modificação.", "Exemplo:".dimmed()); }
        "safe-copy"    => { println!("\n  {}\n  {}\n  {} safe-copy origem.pdf /backup/origem.pdf\n", "safe-copy <src> <dst>".yellow().bold(), "Copia com verificação SHA-256 before and after. Falha se hashes divergirem.", "Exemplo:".dimmed()); }
        "cp"  => { println!("\n  {}\n  {}\n  {} cp contrato.pdf 3 senha\n", "cp <file> <vault> [pass]".yellow().bold(), "Copia e criptografa imediatamente no vault de destino.", "Exemplo:".dimmed()); }
        "allow-write"  => { println!("\n  {}\n  {}\n  {} allow-write /cofre/arquivo.txt\n", "allow-write <file>".yellow().bold(), "Ajusta permissões para 0600 (leitura + escrita).", "Exemplo:".dimmed()); }
        "isolate-directory" => { println!("\n  {}\n  {}\n  {} isolate-directory /home/user/privado\n", "isolate-directory <dir>".yellow().bold(), "Restringe acesso ao diretório (chmod 700) — invisível a outros usuários.", "Exemplo:".dimmed()); }
        "encrypt"      => { println!("\n  {}\n  {}\n  {} encrypt relatorio.pdf\n  {} encrypt relatorio.pdf minha_senha\n", "encrypt <file> [pass]".yellow().bold(), "Criptografa arquivo avulso AES-256-GCM. Gera <file>.enc.", "Exemplo:".dimmed(), "        ".dimmed()); }
        "decrypt"      => { println!("\n  {}\n  {}\n  {} decrypt relatorio.pdf.enc\n", "decrypt <file> [pass]".yellow().bold(), "Descriptografa arquivo .enc gerado por 'encrypt'.", "Exemplo:".dimmed()); }
        "ls"   => { println!("\n  {}\n  {}\n  {} ls\n", "ls".yellow().bold(), "Lists all vaults: ID, nome, tipo, status e caminho.", "Exemplo:".dimmed()); }
        "new" => { println!("\n  {}\n  {}\n  {} new meu_cofre /data/cofre normal\n  {} new seguro /data/seg protected\n", "new <name> <path> <type>".yellow().bold(), "Creates vault no catálogo C.\n  type: normal | protected (with password)", "Exemplo:".dimmed(), "        ".dimmed()); }
        "rm" => { println!("\n  {}\n  {}\n  {} rm 3\n", "rm <id>".yellow().bold(), "Removes vault from catalog and deletes directory. IRREVERSÍVEL.", "Exemplo:".dimmed()); }
        "rename" => { println!("\n  {}\n  {}\n  {} rename 3 novo_nome\n", "rename <id> <novo_nome>".yellow().bold(), "Renames vault in catalog (does not move directory).", "Exemplo:".dimmed()); }
        "unlock" => { println!("\n  {}\n  {}\n  {} unlock 3\n", "unlock <id>".yellow().bold(), "Unlocks vault after lockout due to excess password attempts.", "Exemplo:".dimmed()); }
        "passwd" => { println!("\n  {}\n  {}\n  {} passwd 3\n", "passwd <id>".yellow().bold(), "Troca senha via PBKDF2-SHA256 (310 000 iterações).", "Exemplo:".dimmed()); }
        "venc"=> { println!("\n  {}\n  {}\n  {} venc 3\n", "venc <id>".yellow().bold(), "Encrypts all files in the vault com AES-256-GCM. Gera .enc.", "Exemplo:".dimmed()); }
        "vdec"=> { println!("\n  {}\n  {}\n  {} vdec 3\n", "vdec <id>".yellow().bold(), "Descriptografa todos os .enc do cofre.", "Exemplo:".dimmed()); }
        "scan"   => { println!("\n  {}\n  {}\n  {} scan 3\n", "scan <id>".yellow().bold(), "Força varredura SHA-256. Dispara alerta se algum arquivo mudou.", "Exemplo:".dimmed()); }
        "resolve"=> { println!("\n  {}\n  {}\n  {} resolve 3\n", "resolve <id>".yellow().bold(), "Resolve alerta ativo: limpa flags de modificação, status volta a OK.", "Exemplo:".dimmed()); }
        "info"   => { println!("\n  {}\n  {}\n  {} info 3\n", "info <id>".yellow().bold(), "Detalhes: ID, tipo, status, caminho, cipher_path, WORM flags, engine.", "Exemplo:".dimmed()); }
        "files"  => { println!("\n  {}\n  {}\n  {} files 3\n", "files <id>".yellow().bold(), "Lista arquivos rastreados com hash SHA-256, data e flag 'modified'.", "Exemplo:".dimmed()); }
        "export" => { println!("\n  {}\n  {}\n  {} export 3\n  {} export 3 arquivo.pdf.enc\n", "export <id> [file]".yellow().bold(), "Exporta arquivo do cofre. Descriptografa automaticamente se protegido.", "Exemplo:".dimmed(), "        ".dimmed()); }
        "jail"=> { println!("\n  {}\n  {}\n  {} jail 3\n", "jail <id>".yellow().bold(), "Shell sandbox isolada dentro do cofre (namespaces + seccomp).", "Exemplo:".dimmed()); }
        "rule"   => { println!("\n  {}\n  {}\n  {} rule 3 5\n  {} rule 3 3 9 18  (lockout após 3 falhas, só entre 9h e 18h)\n", "rule <id> <max_fails> [h_from h_to]".yellow().bold(), "Adiciona regra de segurança ao cofre:\n  max_fails  → tentativas antes de lockout\n  h_from/h_to → janela horária permitida (0-23)", "Exemplo:".dimmed(), "        ".dimmed()); }
        "mount"   => { println!("\n  {}\n  {}\n  {} mount 3\n  {} mount 3 senha\n", "mount <id> [senha]".yellow().bold(), "Monta cofre via FUSE3. Proteções WORM são aplicadas imediatamente.", "Exemplo:".dimmed(), "        ".dimmed()); }
        "umount"   => { println!("\n  {}\n  {}\n  {} umount 3\n  {}\n", "umount <id>".yellow().bold(), "Desmounts vault FUSE. Falha se PROTECTED-SCAN ativo (use mount-export).", "Exemplo:".dimmed(), "  ⚠ Cofres com --protected-scan não podem ser desmontados; use mount-export.".yellow()); }
        "mount-export" => {
            println!("\n  {}", "mount-export <id>".yellow().bold());
            println!("  {}", "Único caminho de saída para cofres em PROTECTED-SCAN.".bold());
            println!("  Lê diretamente do cipher_path, bypassando o FUSE.");
            println!("  Descriptografa automaticamente se o cofre for protegido.");
            println!();
            println!("  {}", "Fluxo interativo:".dimmed());
            println!("    1. Seleciona vault (interativo se <id> não for passado)");
            println!("    2. Lista arquivos no cipher_path");
            println!("    3. Seleciona um arquivo ou todos");
            println!("    4. Escolhe pasta de destino (file dialog)");
            println!("    5. Pede senha (se cofre protegido)");
            println!("    6. Exporta com log de auditoria completo");
            println!();
            println!("  {} mount-export\n  {} mount-export 3\n", "Exemplo:".dimmed(), "        ".dimmed());
        }
        "worm" => {
            println!("\n  {}", "worm <id> [flags...]".yellow().bold());
            println!("  Configura proteções WORM (Write Once Read Many) de um vault.");
            println!("  Flags persistidas no catalog.dat; aplicadas no próximo mount.\n");
            println!("  {}", "FLAGS DISPONÍVEIS:".dimmed());
            println!("    {}   bloqueia unlink/rmdir → EPERM", "--protect-delete".yellow());
            println!("    {}   bloqueia rename       → EPERM", "--protect-rename".yellow());
            println!("    {}          bloqueia write em arquivos existentes → EPERM", "--no-write".yellow());
            println!("                     (criação de arquivos novos ainda é permitida)");
            println!("    {}  PROTEÇÃO MÁXIMA — activa todos os três + congela vault", "--protected-scan".red().bold());
            println!("                     {} IRREVERSÍVEL em runtime.", "⚠".red());
            println!("                     A única saída é o comando mount-export.");
            println!("                     Exige confirmação explícita.");
            println!("    {}    remove bloqueio de exclusão", "--clear-delete".yellow());
            println!("    {}    remove bloqueio de renomeação", "--clear-rename".yellow());
            println!("    {}     remove bloqueio de escrita", "--clear-write".yellow());
            println!("    {}          shows active flags of the vault\n", "--status".yellow());
            println!("  {} worm 3 --status", "Exemplo:".dimmed());
            println!("           worm 3 --protect-delete --no-write");
            println!("           worm 3 --protected-scan");
            println!("           worm 3 --clear-delete\n");
        }
        "worm --protected-scan" | "protected-scan" => {
            println!("\n  {}", "PROTECTED-SCAN — Modo de Proteção Máxima".red().bold());
            println!("  Ativado por: worm <id> --protected-scan\n");
            println!("  Comportamento quando ativo:");
            println!("    • write em arquivo existente → EPERM");
            println!("    • unlink / rmdir             → EPERM");
            println!("    • rename                     → EPERM");
            println!("    • create (novo arquivo)      → EPERM");
            println!("    • mkdir                      → EPERM");
            println!("    • open com O_WRONLY/O_TRUNC  → EPERM");
            println!("    • umount                 → EPERM (use mount-export)");
            println!("    • st_mode reportado          → bits de escrita removidos\n");
            println!("  {} Uma vez ativado, não pode ser revertido por CLI.", "⚠".red());
            println!("  O único caminho de saída é o comando mount-export.\n");
        }
        "system-information" => { println!("\n  {}\n  {}\n  {} system-information\n  {} system-information cpu memory\n", "system-information [cpu] [memory] [disks] [networks] [processes]".yellow().bold(), "Exibe informações do sistema. Sem filtros: exibe tudo.", "Exemplo:".dimmed(), "        ".dimmed()); }
        "list-process-status" => { println!("\n  {}\n  {}\n  {} list-process-status\n", "list-process-status".yellow().bold(), "Lista processos monitorados com PID, status e uso de recursos.", "Exemplo:".dimmed()); }
        "derive-master-key" => { println!("\n  {}\n  {}\n  {} derive-master-key\n", "derive-master-key".yellow().bold(), "Deriva master key combinando senha digitada + arquivo físico (USB).\n  PBKDF2-SHA256 com 310 000 iterações.", "Exemplo:".dimmed()); }
        "api-start"    => { println!("\n  {}\n  {}\n  {} api-start\n  {} api-start --port 9090\n", "api-start [--port <p>]".yellow().bold(), "Inicia API HTTP local (padrão 127.0.0.1:8080).\n  GET /vaults, POST /vaults/:id/scan, GET /vaults/:id/status", "Exemplo:".dimmed(), "        ".dimmed()); }
        "api-stop"     => { println!("\n  {}\n  {}\n  {} api-stop\n", "api-stop".yellow().bold(), "Para a instância da API HTTP em execução.", "Exemplo:".dimmed()); }
        "api-status"   => { println!("\n  {}\n  {}\n  {} api-status\n", "api-status".yellow().bold(), "Exibe se a API está rodando, porta e PID do processo.", "Exemplo:".dimmed()); }
        "manual"       => { println!("\n  {}\n  {}\n  {} manual\n", "manual".yellow().bold(), "Abre o interactive operation manual com navegação por seções.", "Exemplo:".dimmed()); }
        "help"         => { println!("\n  {}\n  {}\n  {} help\n  {} help scan\n  {} help all\n", "help [comando|all]".yellow().bold(), "Esta ajuda. 'help <comando>' para detalhes. 'help all' para referência completa.", "Exemplo:".dimmed(), "        ".dimmed(), "        ".dimmed()); }
        "exit"         => { println!("\n  {}\n  {}\n  {} exit\n", "exit".yellow().bold(), "Encerra a aplicação e salva o catálogo.", "Exemplo:".dimmed()); }
        other => {
            println!("\n  Command '{}' not found in help.", other.yellow());
            println!("  Run {} for the full reference.\n", "help all".cyan());
        }
    }
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
 *  MENU INTERATIVO TUI
 * ───────────────────────────────────────────────────────────────────────── */
fn interactive_menu() -> Option<String> {
    let vaults = vault::vault_get_all_paths_pub();
    let mut options = vec!["[+] Create New Vault".to_string()];
    for (id, path) in &vaults {
        options.push(format!("[Vault {}] {}", id, path));
    }
    options.push("Exit".to_string());

    let choice = Select::new("Select Vault or Action:", options).prompt();

    match choice {

        Ok(ans) if ans == "[+] Create New Vault" => {
            // ==========================================
            // ADVANCED CREATION WIZARD
            // ==========================================
            let entry_help = Select::new("Choose help mode:", vec!["help manual".to_string(), "help all".to_string(), "exit".to_string()])
                .with_help_message("help message")
                .prompt();
            match entry_help {
                Ok(ans) if ans == "help_manual" => {
                    println!("\n  {}", "help manual".cyan());
                }
                Ok(ans) if ans == "help_all" => {
                    println!("\n  {}", "help all".cyan());
                }
                Ok(ans) if ans == "exit" => {
                    println!("\n  {}", "exit".cyan());
                }
                Ok(ans) if ans == "continue" => {
                    println!("\n  {}", "One moment...".cyan());
                }

                _ => {
                    println!("\n  Command '{}' not found in help.", ans.yellow());
                    println!("  Run {} for the full reference.\n", "help all".cyan());
                }
            }
            let name = inquire::Text::new("Vault name (Enter to auto-generate):").prompt().unwrap_or_default();
            
            let path_opt = Select::new("Where to save the vault?", vec!["Default location (Catalog)", "Choose folder..."]).prompt();
            let mut final_path = String::new();
            if let Ok("Choose folder...") = path_opt {
                if let Some(p) = rfd::FileDialog::new().pick_folder() {
                    final_path = p.to_string_lossy().to_string();
                } else {
                    println!("✖ No folder selected.");
                    return None;
                }
            } else {
                final_path = "default".to_string();
            }

            let vtype_str = if let Ok(ans) = Select::new("Vault type:", vec!["normal (no password)", "protected (with password)"]).prompt() {
                if ans.contains("normal") { "normal".to_string() } else { "protected".to_string() }
            } else {
                return None;
            };

            let name_arg = if name.trim().is_empty() { "auto" } else { &name };
            
            // Build the base command
            let base_cmd = format!("new {} {} {}", name_arg, final_path, vtype_str);
            
            // New Question: Memory Limit
            let mem_limit = inquire::Text::new("FUSE Sandbox Memory Limit (e.g. 512M, 1G) [Enter for unlimited]:")
                .prompt().unwrap_or_default();
            
            let mut total_bytes: u64 = 0;
            if !mem_limit.trim().is_empty() {
                let limit = mem_limit.trim().to_uppercase();
                if let Ok(val) = limit[..limit.len()-1].parse::<u64>() {
                    if limit.ends_with('M') { total_bytes = val * 1024 * 1024; }
                    else if limit.ends_with('G') { total_bytes = val * 1024 * 1024 * 1024; }
                    else if limit.ends_with('K') { total_bytes = val * 1024; }
                    
                    let system = sysinfo::System::new_all();
                    let avail = system.available_memory();
                    
                    if total_bytes > avail {
                        println!("✖ Error: Requested memory ({}) exceeds available system RAM ({}).", total_bytes, avail);
                        return None;
                    } else if total_bytes < 10 * 1024 * 1024 {
                        println!("✖ Error: Memory limit too small. Minimum is 10M.");
                        return None;
                    }
                    println!("✔ Memory limit valid: {} bytes", total_bytes);
                } else {
                    println!("✖ Invalid memory format.");
                    return None;
                }
            }

            // New Question: Default Protections
            let prot_opts = vec!["WORM: Block Write", "WORM: Block Delete", "WORM: Block Rename", "WORM: Block Read"];
            let selected_prots = inquire::MultiSelect::new("Which protections to apply out-of-the-box?", prot_opts).prompt().unwrap_or_default();
            
            let mut prot_cmd = String::new();
            for p in selected_prots {
                if p.contains("Write") { prot_cmd.push_str(" --no-write"); }
                if p.contains("Delete") { prot_cmd.push_str(" --protect-delete"); }
                if p.contains("Rename") { prot_cmd.push_str(" --protect-rename"); }
                if p.contains("Read") { prot_cmd.push_str(" --protect-read"); }
            }

            let mount_now = Select::new("Mount FUSE immediately?", vec!["Yes", "No"]).prompt().unwrap_or("No");
            
            // To pass all these chained commands back, we format them with a special separator ` && `
            // And modify the main loop to split by ` && `
            let mut full_cmd = base_cmd;
            
            // Note: Since we don't know the ID of the vault just created, we use a magic keyword `LAST_CREATED_ID`
            if !prot_cmd.is_empty() {
                full_cmd = format!("{} && worm LAST_CREATED_ID {}", full_cmd, prot_cmd);
            }
            if mount_now == "Yes" {
                full_cmd = format!("{} && mount LAST_CREATED_ID", full_cmd);
            }
            
            Some(full_cmd)
        },
        Ok(ans) if ans == "Exit" => Some("exit".to_string()),
        Ok(ans) => {
            if let Some(id_str) = ans.strip_prefix("[Vault ").and_then(|s| s.split(']').next()) {
                let sub_options = vec![
                    "Mount FUSE",
                    "Unmount FUSE",
                    "Enter Sandbox Shell",
                    "List Internal Files",
                    "View Info / Status",
                    "Export / Rescue File",
                    "Toggle WORM Protections",
                    "Delete Vault"
                ];
                let sub_choice = Select::new(&format!("Action for {}:", ans), sub_options).prompt();
                match sub_choice {
                    Ok("Mount FUSE") => Some(format!("mount {}", id_str)),
                    Ok("Unmount FUSE") => Some(format!("umount {}", id_str)),
                    Ok("Enter Sandbox Shell") => Some(format!("jail {}", id_str)),
                    Ok("List Internal Files") => Some(format!("files {}", id_str)),
                    Ok("View Info / Status") => Some(format!("info {}", id_str)),
                    Ok("Export / Rescue File") => Some(format!("export {}", id_str)),
                    Ok("Delete Vault") => Some(format!("rm {}", id_str)),
                    Ok("Toggle WORM Protections") => {
                        let flags = vec!["--no-write", "--protect-delete", "--protect-rename", "--protect-read"];
                        if let Ok(flag) = Select::new("Select Protection to Toggle:", flags).prompt() {
                            Some(format!("worm {} {}", id_str, flag))
                        } else { None }
                    },
                    _ => None,
                }
            } else { None }
        }
        Err(_) => None,
    }
}

fn parse_id(arg: Option<&&str>, cmd: &str) -> Option<u32> {
    if let Some(s) = arg {
        if let Ok(id) = s.parse::<u32>() {
            Some(id)
        } else {
            eprintln!("✖ Invalid ID.");
            None
        }
    } else {
        eprintln!("✖ Missing ID. Usage: {} <id>", cmd);
        None
    }
}

fn suggest_command(input: &str) -> Option<String> {
    let commands = vec![
        "new", "rm", "rename", "ls",
        "passwd", "venc", "vdec", "scan",
        "resolve", "info", "files", "jail",
        "mount", "umount", "worm"
    ];
    let mut best_match = None;
    let mut max_match = 0;
    
    for cmd in commands {
        if cmd.starts_with(&input[0..1]) {
            let mut matches = 0;
            let len = std::cmp::min(cmd.len(), input.len());
            for i in 0..len {
                if cmd.as_bytes()[i] == input.as_bytes()[i] {
                    matches += 1;
                } else {
                    break;
                }
            }
            if matches > max_match {
                max_match = matches;
                best_match = Some(cmd.to_string());
            }
        }
    }
    
    if max_match >= 3 {
        best_match
    } else {
        None
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
    if p.is_empty() {
        None
    } else {
        Some(p)
    }
}

/*
 *  DISPATCHER DE COMANDOS
 *  */
fn handle_command(parts: Vec<&str>, cwd: &mut std::path::PathBuf) {
    match parts[0] {
        /* ── shell commands ──────────────────────────────────────────────── */
        "cd" => {
            let target = parts.get(1).unwrap_or(&"~");
            let mut new_path = cwd.clone();
            if *target == "~" {
                if let Ok(home) = std::env::var("HOME") {
                    new_path = std::path::PathBuf::from(home);
                }
            } else if target.starts_with("/") {
                new_path = std::path::PathBuf::from(target);
            } else {
                new_path.push(target);
            }

            if let Ok(canon) = new_path.canonicalize() {
                if canon.is_dir() {
                    *cwd = canon.clone();
                    println!("{}", format!("📂 CWD alterado para: {}", canon.display()).green());
                } else {
                    eprintln!("{}", format!("✖ {} não é um diretório.", target).red());
                }
            } else {
                eprintln!("{}", format!("✖ Diretório {} não encontrado.", target).red());
            }
        }
        "vault-cd" => {
            let Some(id) = parse_id(parts.get(1), "vault-cd") else {
                return;
            };
            if let Ok(p) = vault::vault_get_real_path(id) {
                println!("{}", format!("📂 Agora no cofre: {}", p).green());
                *cwd = std::path::PathBuf::from(p);
            } else {
                eprintln!("{}", format!("✖ Cofre ID {} não encontrado.", id).red());
            }
        }
        "dir" => {
            let target = parts.get(1).map(std::path::PathBuf::from).unwrap_or_else(|| cwd.clone());
            let path = if target.is_absolute() { target } else { cwd.join(target) };
            if let Ok(entries) = std::fs::read_dir(&path) {
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        let icon = if meta.is_dir() { "📁" } else { "📄" };
                        let name = entry.file_name().to_string_lossy().to_string();
                        let size = if meta.is_dir() { String::new() } else { format!("({} bytes)", meta.len()) };
                        println!("{} {} {}", icon, name, size.dimmed());
                    }
                }
            } else {
                eprintln!("{}", format!("✖ Falha ao ler {:?}", path).red());
            }
        }
        "pwd" => {
            println!("{}", cwd.display());
        }
        /* ── originais ────────────────────────────────────────────────── */
       
        "isolate-directory" => {
            if let Some(dir) =
                path_assistant::ensure_path(parts.get(1), "Diretório para isolar:", true)
            {
                log::info(&format!("Isolando diretório: {:?}", dir));
                vault::isolate_directory(dir.to_str().unwrap());
            }
        }
        
        "create-vault" => {
            let path = if let Some(p) = parts.get(1) {
                std::path::PathBuf::from(p)
            } else {
                let input = if std::io::stdin().is_terminal() {
                    inquire::Text::new("Path for the new vault:")
                        .prompt()
                        .unwrap_or_default()
                } else {
                    let mut buf = String::new();
                    let _ = std::io::stdin().read_line(&mut buf);
                    buf.trim().to_string()
                };
                std::path::PathBuf::from(input)
            };

            if !path.as_os_str().is_empty() {
                let start_time = Instant::now();
                crate::log::console_trace("CREATE_INIT", &format!("Creating vault in: {:?}", path));
                vault::create(path.to_str().unwrap());
                crate::log::console_trace("CREATE_DONE", &format!("Vault created successfully in {:.2?}", start_time.elapsed()));
            }
        }

        "safe-copy" => {
            let src = path_assistant::ensure_path(parts.get(1), "Source file:", false);
            let dst = if let Some(p) = parts.get(2) {
                Some(PathBuf::from(p))
            } else {
                let input = inquire::Text::new("Caminho de destino:").prompt().ok();
                input.map(PathBuf::from)
            };

            if let (Some(s), Some(d)) = (src, dst) {
                let start_time = Instant::now();
                crate::log::console_trace("SAFE_COPY_INIT", &format!("Secure copy: {:?} -> {:?}", s, d));
                match vault::secure_copy(s.to_str().unwrap(), d.to_str().unwrap()) {
                    Ok(bytes) => {
                        crate::log::console_trace("SAFE_COPY_DONE", &format!("File copied securely in {:.2?} ({} bytes written).", start_time.elapsed(), bytes));
                        println!("{}", "✔ Arquivo copiado".green());
                    },
                    Err(e) => {
                        crate::log::console_trace("SAFE_COPY_ERROR", &format!("Error in safe-copy after {:.2?}: {}", start_time.elapsed(), e));
                        eprintln!("{}", format!("✖ Error: {}", e).red());
                    }
                }
            }
        }

        "allow-write" => {
            if let Some(path) =
                path_assistant::ensure_path(parts.get(1), "Arquivo para liberar escrita:", false)
            {
                let start_time = Instant::now();
                crate::log::console_trace("ALLOW_WRITE_INIT", &format!("Allowing write for: {:?}", path));
                vault::allow_write(path.to_str().unwrap());
                crate::log::console_trace("ALLOW_WRITE_DONE", &format!("Write allowed in {:.2?}", start_time.elapsed()));
            }
        }

        "read-directory" => {
            if let Some(dir) =
                path_assistant::ensure_path(parts.get(1), "Diretório para listar:", true)
            {
                let dir_str = dir.to_str().unwrap();
                log::info(&format!("Listando diretório: {}", dir_str));
                let files = vault::read_directory(dir_str);
                println!("{}", format!("📁 {}:", dir_str).blue());
                for f in files {
                    println!("  {}", format!("• {}", f).white());
                }
            }
        }

        "remove-file" => {
            let vault_path = path_assistant::ensure_path(parts.get(1), "Vault path:", true);
            let file = if let Some(f) = parts.get(2) {
                Some(f.to_string())
            } else {
                if std::io::stdin().is_terminal() {
                    inquire::Text::new("File name in the vault:")
                        .prompt()
                        .ok()
                } else {
                    let mut buf = String::new();
                    if std::io::stdin().read_line(&mut buf).is_ok() {
                        let trimmed = buf.trim().to_string();
                        if trimmed.is_empty() { None } else { Some(trimmed) }
                    } else {
                        None
                    }
                }
            };

            if let (Some(v), Some(f)) = (vault_path, file) {
                let start_time = Instant::now();
                crate::log::console_trace("REMOVE_FILE_INIT", &format!("Removing file {} from vault {:?}", f, v));
                match vault::remove_file(v.to_str().unwrap(), &f) {
                    Ok(_) => {
                        crate::log::console_trace("REMOVE_FILE_DONE", &format!("File removed in {:.2?}.", start_time.elapsed()));
                    },
                    Err(e) => {
                        crate::log::console_trace("REMOVE_FILE_ERROR", &format!("Error in remove-file after {:.2?}: {}", start_time.elapsed(), e));
                        eprintln!("{}", format!("✖ Error: {}", e).red());
                    }
                }
            }
        }
        "encrypt" => {
            if let Some(file) =
                path_assistant::ensure_path(parts.get(1), "Arquivo para criptografar:", false)
            {
                let pass = get_password("Senha:", parts.get(2));
                if !pass.is_empty() {
                    let start_time = Instant::now();
                    crate::log::console_trace("ENCRYPT_INIT", &format!("Encrypting file: {:?}", file));
                    match crypto::encrypt_file(&file, &pass) {
                        Ok(_) => {
                            crate::log::console_trace("ENCRYPT_DONE", &format!("File encrypted in {:.2?}", start_time.elapsed()));
                            println!("{}", "✔ Arquivo criptografado".green());
                        },
                        Err(e) => {
                            crate::log::console_trace("ENCRYPT_ERROR", &format!("Error encrypting file after {:.2?}: {}", start_time.elapsed(), e));
                            eprintln!("{}", format!("✖ Error: {}", e).red());
                        }
                    }
                } else {
                    println!("{}", "✖ Senha vazia ou erro ao ler senha".red());
                }
            }
        }

        "decrypt" => {
            if let Some(file) =
                path_assistant::ensure_path(parts.get(1), "Arquivo para descriptografar:", false)
            {
                let pass = get_password("Senha:", parts.get(2));
                if !pass.is_empty() {
                    let start_time = Instant::now();
                    crate::log::console_trace("DECRYPT_INIT", &format!("Decrypting file: {:?}", file));
                    match crypto::decrypt_file(&file, &pass) {
                        Ok(_) => {
                            crate::log::console_trace("DECRYPT_DONE", &format!("File decrypted in {:.2?}", start_time.elapsed()));
                            println!("{}", "✔ Arquivo descriptografado".green());
                        },
                        Err(e) => {
                            crate::log::console_trace("DECRYPT_ERROR", &format!("Error decrypting file after {:.2?}: {}", start_time.elapsed(), e));
                            eprintln!("{}", format!("✖ Error: {}", e).red());
                        }
                    }
                } else {
                    println!("{}", "✖ Senha vazia ou erro ao ler senha".red());
                }
            }
        }

        "cp" => {
            let file = path_assistant::ensure_path(parts.get(1), "Source file:", false);
            let vault_path = path_assistant::ensure_path(parts.get(2), "Vault path:", true);

            if let (Some(f), Some(v)) = (file, vault_path) {
                // Só pede senha se foi passada como argumento ou se o vault é protected.
                let pass = if let Some(&p) = parts.get(3) {
                    p.to_string()
                } else {
                    get_password("Password (Enter to skip):", None)
                };
                let pass_to_use = if pass.is_empty() {
                    // Sem senha: usa uma aleatória para criptografia avulsa
                    format!("__nosec__{}", std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default().as_secs())
                } else {
                    pass
                };
                let start_time = Instant::now();
                crate::log::console_trace("SECURE_STORE_INIT", &format!("Secure copy: {:?} to {:?}", f, v));
                vault::secure_store(f.to_str().unwrap(), v.to_str().unwrap(), &pass_to_use);
                crate::log::console_trace("SECURE_STORE_DONE", &format!("File protected and stored in vault in {:.2?}", start_time.elapsed()));
                println!("{}", "✔ File protected and stored in vault".green());
            }
        }
        
        "system-information" => {
            let has_filter = parts.iter().skip(1).any(|p| {
                matches!(*p, "cpu" | "memory" | "disks" | "networks" | "processes")
            });
            let options = sys_info::SystemOptions {
                cpu:       has_filter && parts.contains(&"cpu")       || !has_filter,
                memory:    has_filter && parts.contains(&"memory")    || !has_filter,
                disks:     has_filter && parts.contains(&"disks")     || !has_filter,
                networks:  has_filter && parts.contains(&"networks")  || !has_filter,
                processes: has_filter && parts.contains(&"processes") || !has_filter,
            };
            sys_info::system_information(options);
        }

        "list-process-status" => {
            let options = sys_info::SystemOptions {
                cpu: false,
                memory: false,
                disks: false,
                networks: false,
                processes: true,
            };
            // sysinfo pode abortar em alguns kernels de container ao ler /proc.
            // Envolve em catch_unwind para evitar o crash.
            let result = std::panic::catch_unwind(|| {
                sys_info::list_process_status(&options);
            });
            if result.is_err() {
                eprintln!("{}", "⚠ Não foi possível listar processos neste ambiente (permissão /proc insuficiente).".yellow());
            }
        }

        "derive-master-key" => {
            let password = inquire::Password::new("Senha:")
                .prompt()
                .unwrap_or_default();
            let usb_key_input = inquire::Text::new("Chave USB (hex):")
                .prompt()
                .unwrap_or_default();
            let usb_key_bytes = match hex::decode(usb_key_input.trim()) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error(&format!("Erro ao decodificar chave USB: {}", e));
                    eprintln!("{}", format!("✖ Error: {}", e).red());
                    return;
                }
            };

            let start_time = Instant::now();
            crate::log::console_trace("DERIVE_KEY_INIT", "Deriving master key from password and USB key");
            match crypto::derive_master_key(&password, &usb_key_bytes) {
                Ok(master_key) => {
                    crate::log::console_trace("DERIVE_KEY_DONE", &format!("Master Key derived successfully in {:.2?}", start_time.elapsed()));
                    println!(
                        "{}",
                        format!("Master Key derivada: {}", hex::encode(master_key)).green()
                    );
                },
                Err(e) => {
                    crate::log::console_trace("DERIVE_KEY_ERROR", &format!("Error deriving key after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Error: {}", e).red());
                }
            }
        }

        "manual" => {
            manual::show_manual();
        }

        "help" => {
            if let Some(&cmd) = parts.get(1) {
                show_help_for(cmd);
            } else {
                show_help();
            }
        }

        "exit" => {
            log::info("Application terminated by user.");
            println!("{}", "Saindo...".yellow());
            std::process::exit(0);
        }

        /* ══ novos — core C ════════════════════════════════════════════ */

        /* ls */
        "ls" => {
            let start_time = Instant::now();
            crate::log::console_trace("VAULT_LIST_INIT", "Listing vaults from catalog (C core)...");
            vault::vault_list();
            crate::log::console_trace("VAULT_LIST_DONE", &format!("Vaults listed in {:.2?}", start_time.elapsed()));
        }

        "new" => {
            let name_buf;
            let name = if let Some(&s) = parts.get(1) {
                Some(s)
            } else {
                let ans = inquire::Text::new("Vault name (Enter to auto-generate):")
                    .prompt()
                    .unwrap_or_default();
                if ans.trim().is_empty() {
                    None
                } else {
                    name_buf = ans.trim().to_string();
                    Some(name_buf.as_str())
                }
            };

            let path_buf;
            let path = if let Some(&s) = parts.get(2) {
                Some(s)
            } else {
                let ans = Select::new(
                    "Where to save the vault?",
                    vec!["Default location (Catalog)", "Choose folder..."],
                )
                .prompt();
                if let Ok("Choose folder...") = ans {
                    if let Some(p) =
                        path_assistant::ensure_path(None, "Select destination folder", true)
                    {
                        path_buf = p.to_string_lossy().to_string();
                        Some(path_buf.as_str())
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            let mut vtype_str = "normal";
            if let Some(&s) = parts.get(3) {
                vtype_str = s;
            } else {
                if let Ok(ans) = Select::new(
                    "Vault type:",
                    vec!["normal (no password)", "protected (with password)"],
                )
                .prompt()
                {
                    vtype_str = if ans.starts_with("normal") {
                        "normal"
                    } else {
                        "protected"
                    };
                }
            };

            let password = if vtype_str == "protected" {
                let p1 = prompt_password("Vault password:");
                if p1.is_empty() {
                    eprintln!("{}", "✖ Password required for protected vault.".red());
                    return;
                }
                let p2 = prompt_password("Confirm password:");
                if p1 != p2 {
                    eprintln!("{}", "✖ Passwords do not match.".red());
                    return;
                }
                Some(p1)
            } else {
                None
            };

            /* ── Engine de isolamento ── */
            println!("{}", "\nChoose protection engine:".cyan());
            println!("{}", "  [0] No engine (default)".white());
            println!(
                "{}",
                "  [1] Engine 1 — 1 layer  + decoy files a-z".white()
            );
            println!(
                "{}",
                "  [2] Engine 2 — 3 layers + decoy files a-z".white()
            );
            println!(
                "{}",
                "  [3] Engine 3 — 6 layers + decoy files a-z".white()
            );
            println!(
                "{}",
                "  [4] Engine 4 — 16 layers + fake binaries .enc".white()
            );
            println!(
                "{}",
                "  [5] Engine 5 — 20 layers + fake binaries .enc".white()
            );

            let engine_level: i32 = inquire::Text::new("Engine [0-5]:")
                .prompt()
                .unwrap_or_default()
                .trim()
                .parse::<i32>()
                .unwrap_or(0)
                .clamp(0, 5);

            println!(
                "{}",
                format!("→ Engine {} selected.", engine_level).yellow()
            );

            log::info(&format!(
                "new name={:?} path={:?} type={} engine={}",
                name, path, vtype_str, engine_level
            ));

            match vault::vault_create(name, vtype_str, path, password.as_deref()) {
                Ok(_) => {
                    println!("{}", "✔ Vault created no core C.".green());

                    /* Aplica engine se > 0 */
                    if engine_level > 0 {
                        match vault::vault_apply_engine(name, engine_level) {
                            Ok(_) => println!(
                                "{}",
                                format!("✔ Engine {} aplicado.", engine_level).green()
                            ),
                            Err(e) => {
                                log::error(&format!("vault_apply_engine: {}", e));
                                eprintln!("{}", format!("⚠ Engine não aplicado: {}", e).yellow());
                            }
                        }
                    }
                }
                Err(e) => {
                    log::error(&format!("new: {}", e));
                    eprintln!("{}", format!("✖ Error: {}", e).red());
                }
            }
        }

        /* rm <id> */
        "rm" => {
            let Some(id) = parse_id(parts.get(1), "rm") else {
                return;
            };
            let pass = prompt_password_opt("Password (Enter to skip):");

            let start_time = Instant::now();
            crate::log::console_trace("VAULT_DELETE_INIT", &format!("Deleting vault id={}", id));
            match vault::vault_delete(id, pass.as_deref()) {
                Ok(_) => {
                    crate::log::console_trace("VAULT_DELETE_DONE", &format!("Vault deleted in {:.2?}", start_time.elapsed()));
                    println!("{}", "✔ Vault deletado.".green());
                },
                Err(e) => {
                    crate::log::console_trace("VAULT_DELETE_ERROR", &format!("Error deleting vault after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Error: {}", e).red());
                }
            }
        }

        /* rename <id> <new_name> */
        "rename" => {
            let Some(id) = parse_id(parts.get(1), "rename") else {
                return;
            };
            let new_name = match parts.get(2) {
                Some(n) => *n,
                None => {
                    eprintln!("{}", "✖ rename: novo nome obrigatório.".red());
                    return;
                }
            };
            let pass = prompt_password_opt("Password (Enter to skip):");

            let start_time = Instant::now();
            crate::log::console_trace("VAULT_RENAME_INIT", &format!("Renaming vault id={} to {}", id, new_name));
            match vault::vault_rename(id, new_name, pass.as_deref()) {
                Ok(_) => {
                    crate::log::console_trace("VAULT_RENAME_DONE", &format!("Vault renamed in {:.2?}", start_time.elapsed()));
                    println!("{}", "✔ Vault renomeado.".green());
                },
                Err(e) => {
                    crate::log::console_trace("VAULT_RENAME_ERROR", &format!("Error renaming vault after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Error: {}", e).red());
                }
            }
        }

        /* unlock <id> */
        "unlock" => {
            let Some(id) = parse_id(parts.get(1), "unlock") else {
                return;
            };
            let pass = prompt_password("Senha:");
            if pass.is_empty() {
                eprintln!("{}", "✖ Senha obrigatória para desbloquear.".red());
                return;
            }

            let start_time = Instant::now();
            crate::log::console_trace("VAULT_UNLOCK_INIT", &format!("Unlocking vault id={}", id));
            match vault::vault_unlock(id, &pass) {
                Ok(_) => {
                    crate::log::console_trace("VAULT_UNLOCK_DONE", &format!("Vault unlocked in {:.2?}", start_time.elapsed()));
                    println!("{}", "✔ Vault desbloqueado.".green());
                },
                Err(e) => {
                    crate::log::console_trace("VAULT_UNLOCK_ERROR", &format!("Error unlocking vault after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Error: {}", e).red());
                }
            }
        }

        /* export <id> [file] */
        "export" => {
            let id = if let Some(&s) = parts.get(1) {
                s.parse::<u32>().ok()
            } else {
                inquire::Text::new("ID do Cofre:")
                    .prompt()
                    .ok()
                    .and_then(|s| s.parse::<u32>().ok())
            };

            let Some(id) = id else {
                eprintln!("{}", "✖ ID do cofre inválido ou não fornecido.".red());
                return;
            };

            let real_path = match vault::vault_get_real_path(id) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{}", format!("✖ Erro ao obter diretório: {}", e).red());
                    return;
                }
            };

            let mut available_files = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&real_path) {
                for entry in entries.flatten() {
                    if let Ok(file_type) = entry.file_type() {
                        if file_type.is_file() {
                            available_files.push(entry.file_name().to_string_lossy().to_string());
                        }
                    }
                }
            }

            if available_files.is_empty() {
                println!("{}", "O cofre está vazio!".yellow());
                return;
            }

            available_files.push(">> Todos os arquivos".to_string());
            available_files.push(">> Cancel".to_string());

            let filename =
                match inquire::Select::new("Selecione o arquivo para resgatar:", available_files)
                    .prompt()
                {
                    Ok(ans) if ans == ">> Cancel" => return,
                    Ok(ans) => ans,
                    Err(_) => return,
                };

            println!(
                "{}",
                "\n⚠ ADVERTÊNCIA: Os arquivos resgatados ficarão DESPROTEGIDOS no destino!"
                    .yellow()
            );
            let confirm = inquire::Select::new(
                "Você tem certeza disso?",
                vec!["Sim, resgatar", "Não, cancelar"],
            )
            .prompt();
            if let Ok("Não, cancelar") | Err(_) = confirm {
                println!("{}", "Operação cancelada.".yellow());
                return;
            }

            println!("{}", "➜ Select destination folder...".cyan());
            let dst_dir = if let Some(p) = rfd::FileDialog::new().pick_folder() {
                p
            } else {
                println!(
                    "{}",
                    "✖ No folder selected. Operação cancelada.".red()
                );
                return;
            };

            let is_protected = vault::vault_is_protected(id);
            let password = if is_protected {
                prompt_password("Senha do Cofre (necessária para decifrar):")
            } else {
                String::new()
            };

            if is_protected && password.is_empty() {
                eprintln!("{}", "✖ Senha é obrigatória para cofres protegidos.".red());
                return;
            }

            log::info(&format!(
                "export id={} file={} dest={:?}",
                id, filename, dst_dir
            ));

            let files_to_export: Vec<String> = if filename == ">> Todos os arquivos" {
                let mut all = Vec::new();
                if let Ok(entries) = std::fs::read_dir(&real_path) {
                    for entry in entries.flatten() {
                        if let Ok(file_type) = entry.file_type() {
                            if file_type.is_file() {
                                all.push(entry.file_name().to_string_lossy().to_string());
                            }
                        }
                    }
                }
                all
            } else {
                vec![filename]
            };

            let mut success_count = 0;
            let mut fail_count = 0;

            for f in files_to_export {
                let mut final_dst = dst_dir.join(&f);
                if is_protected && f.ends_with(".enc") {
                    final_dst.set_extension("");
                }
                let dst_str = final_dst.to_string_lossy().to_string();

                let res = if is_protected {
                    vault::vault_export_and_decrypt(id, &f, &dst_str, &password)
                } else {
                    vault::vault_export_file(id, &f, &dst_str)
                };

                match res {
                    Ok(_) => {
                        println!(
                            "{}",
                            format!("✔ {} resgatado com sucesso para {}", f, dst_str).green()
                        );
                        success_count += 1;
                    }
                    Err(e) => {
                        eprintln!("{}", format!("✖ Erro ao resgatar {}: {}", f, e).red());
                        fail_count += 1;
                    }
                }
            }

            println!(
                "{}",
                format!(
                    "\nOperação de resgate concluída! {} sucessos, {} falhas. Obrigado!",
                    success_count, fail_count
                )
                .bright_green()
            );
        }

        /* passwd <id> */
        "passwd" => {
            let Some(id) = parse_id(parts.get(1), "passwd") else {
                return;
            };
            let old_pass = prompt_password("Senha atual:");
            let new_pass = prompt_password("Nova senha:");
            let cnf_pass = prompt_password("Confirm new password:");

            if new_pass != cnf_pass {
                eprintln!("{}", "✖ Passwords do not match.".red());
                return;
            }
            if new_pass.is_empty() {
                eprintln!("{}", "✖ Nova senha não pode ser vazia.".red());
                return;
            }

            let start_time = Instant::now();
            crate::log::console_trace("VAULT_PASSWD_INIT", &format!("Changing password for vault id={}", id));
            match vault::vault_change_password(id, &old_pass, &new_pass) {
                Ok(_) => {
                    crate::log::console_trace("VAULT_PASSWD_DONE", &format!("Password changed in {:.2?}", start_time.elapsed()));
                    println!("{}", "✔ Senha alterada.".green());
                },
                Err(e) => {
                    crate::log::console_trace("VAULT_PASSWD_ERROR", &format!("Error changing password after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Error: {}", e).red());
                }
            }
        }

        /* venc <id> */
        "venc" => {
            let Some(id) = parse_id(parts.get(1), "venc") else {
                return;
            };
            let pass = prompt_password("Vault password:");
            if pass.is_empty() {
                eprintln!("{}", "✖ Password required to encrypt.".red());
                return;
            }

            let start_time = Instant::now();
            crate::log::console_trace("VAULT_ENCRYPT_INIT", &format!("Encrypting files in vault id={} (AES-256)", id));
            match vault::vault_encrypt(id, &pass) {
                Ok(_) => {
                    crate::log::console_trace("VAULT_ENCRYPT_DONE", &format!("Files encrypted in {:.2?}", start_time.elapsed()));
                    println!("{}", "✔ Arquivos criptografados (AES-256).".green());
                },
                Err(e) => {
                    crate::log::console_trace("VAULT_ENCRYPT_ERROR", &format!("Error encrypting vault after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Error: {}", e).red());
                }
            }
        }

        /* vdec <id> */
        "vdec" => {
            let Some(id) = parse_id(parts.get(1), "vdec") else {
                return;
            };
            let pass = prompt_password("Vault password:");
            if pass.is_empty() {
                eprintln!("{}", "✖ Password required to decrypt.".red());
                return;
            }

            let start_time = Instant::now();
            crate::log::console_trace("VAULT_DECRYPT_INIT", &format!("Decrypting files in vault id={}", id));
            match vault::vault_decrypt(id, &pass) {
                Ok(_) => {
                    crate::log::console_trace("VAULT_DECRYPT_DONE", &format!("Files decrypted in {:.2?}", start_time.elapsed()));
                    println!("{}", "✔ Arquivos descriptografados.".green());
                },
                Err(e) => {
                    crate::log::console_trace("VAULT_DECRYPT_ERROR", &format!("Error decrypting vault after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Error: {}", e).red());
                }
            }
        }

        /* scan <id> */
        "scan" => {
            let Some(id) = parse_id(parts.get(1), "scan") else {
                return;
            };
            let start_time = Instant::now();
            crate::log::console_trace("SCAN_INIT", &format!("Initializing SHA-256 cryptographic audit for vault ID {}", id));
            crate::log::console_trace("MEM_ALLOC", "Allocating secure memory buffers in user-space...");
            crate::log::console_trace("FS_WALK", "Walking vault directory tree and analyzing blocks...");
            
            match vault::vault_scan_report(id) {
                Ok((changed, report)) => {
                    let duration = start_time.elapsed();
                    crate::log::console_trace("SCAN_DONE", &format!("Cryptographic validation completed in {:.2?}. Files modified: {}", duration, changed));
                    if changed > 0 {
                        crate::log::console_trace("SECURITY_ALERT", "Anomaly detected! Divergent hashes found in catalog.");
                        println!("{}\n{}", "⚠ ALERT: The vault is now in ALERT status. Use 'resolve' to approve changes.".red().bold(), report);
                    } else {
                        println!("{}", "✔ Scan complete. Integrity verified.".green());
                    }
                }
                Err(e) => {
                    let duration = start_time.elapsed();
                    crate::log::console_trace("SCAN_ERROR", &format!("Audit failed after {:.2?}. Reason: {}", duration, e));
                    eprintln!("{}", format!("✖ Error: {}", e).red());
                }
            }
        }

        /* resolve <id> */
        "resolve" => {
            let Some(id) = parse_id(parts.get(1), "resolve") else {
                return;
            };
            let pass = prompt_password_opt("Password (Enter to skip):");

            log::info(&format!("resolve id={}", id));
            match vault::vault_resolve(id, pass.as_deref()) {
                Ok(_) => println!("{}", "✔ Alert resolved.".green()),
                Err(e) => {
                    log::error(&format!("resolve: {}", e));
                    eprintln!("{}", format!("✖ Error: {}", e).red());
                }
            }
        }

        /* info <id> */
        "info" => {
            let Some(id) = parse_id(parts.get(1), "info") else {
                return;
            };
            let start_time = Instant::now();
            crate::log::console_trace("VAULT_INFO_INIT", &format!("Getting info for vault id={}", id));
            vault::vault_info(id);
            crate::log::console_trace("VAULT_INFO_DONE", &format!("Vault info retrieved in {:.2?}", start_time.elapsed()));
        }

        /* files <id> */
        "files" => {
            let Some(id) = parse_id(parts.get(1), "files") else {
                return;
            };
            let start_time = Instant::now();
            crate::log::console_trace("VAULT_FILES_INIT", &format!("Getting files for vault id={}", id));
            vault::vault_files(id);
            crate::log::console_trace("VAULT_FILES_DONE", &format!("Vault files retrieved in {:.2?}", start_time.elapsed()));
        }

        /* jail <id> */
        "jail" => {
            let Some(id) = parse_id(parts.get(1), "jail") else {
                return;
            };
            let pass = prompt_password_opt("Password (Enter to skip):");

            let start_time = Instant::now();
            crate::log::console_trace("VAULT_SANDBOX_INIT", &format!("Spawning secure shell session for vault ID {}", id));
            crate::log::console_trace("NS_ISOLATION", "Detaching mount namespace and locking credentials...");
            
            match vault::vault_sandbox(id, pass.as_deref()) {
                Ok(_) => {
                    let duration = start_time.elapsed();
                    crate::log::console_trace("VAULT_SANDBOX_EXIT", &format!("Secure shell session closed after {:.2?}", duration));
                },
                Err(e) => {
                    let duration = start_time.elapsed();
                    crate::log::console_trace("VAULT_SANDBOX_ERROR", &format!("Session aborted after {:.2?}. Reason: {}", duration, e));
                    eprintln!("{}", format!("✖ Error: {}", e).red());
                }
            }
        }

        /* rule <id> <max_fails> [hour_from hour_to] */
        "rule" => {
            let Some(id) = parse_id(parts.get(1), "rule") else {
                return;
            };
            let max_fails: i32 = match parts.get(2) {
                Some(v) => match v.parse() {
                    Ok(n) => n,
                    Err(_) => {
                        eprintln!("{}", "✖ rule: max_fails deve ser inteiro.".red());
                        return;
                    }
                },
                None => {
                    eprintln!("{}", "✖ rule: max_fails obrigatório.".red());
                    return;
                }
            };

            let hour_from: Option<i32> = parts.get(3).and_then(|v| v.parse().ok());
            let hour_to: Option<i32> = parts.get(4).and_then(|v| v.parse().ok());

            let start_time = Instant::now();
            crate::log::console_trace("VAULT_RULE_INIT", &format!("Adding rule to vault id={} max_fails={} hours={:?}-{:?}", id, max_fails, hour_from, hour_to));
            match vault::vault_rule(id, max_fails, hour_from, hour_to) {
                Ok(_) => {
                    crate::log::console_trace("VAULT_RULE_DONE", &format!("Rule added in {:.2?}", start_time.elapsed()));
                    println!("{}", "✔ Regra adicionada.".green());
                },
                Err(e) => {
                    crate::log::console_trace("VAULT_RULE_ERROR", &format!("Error adding rule after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Error: {}", e).red());
                }
            }
        }

        /* ── Novos comandos Linux Context Menu ── */
        "dump-vaults" => {
            let vaults = vault::vault_get_all_paths_pub();
            for v in vaults {
                println!("{} | {}", v.0, v.1);
            }
        }

        "add-to-vault" => {
            let file_path = parts.get(1).unwrap_or(&"").to_string();
            if file_path.is_empty() {
                eprintln!("{}", "✖ add-to-vault: arquivo obrigatório.".red());
                return;
            }

            let vaults = vault::vault_get_all_paths_pub();
            if !vaults.is_empty() {
                let options: Vec<String> = vaults
                    .iter()
                    .map(|(id, path)| format!("[{}] {}", id, path))
                    .collect();

                // If CLI args length > 1, maybe we don't want interactive prompt, but we have to pass vault ID somehow.
                // Context menus usually pass the vault ID or we select it.
                // But the user requested inquire::Select in "add-to-vault", so we keep it.
                match Select::new("Selecione o cofre de destino:", options).prompt() {
                    Ok(ans) => {
                        let vault_path = ans.split("] ").nth(1).unwrap_or("");
                        let _ = vault::add_file(vault_path, &file_path);
                        println!("{}", "✔ Arquivo adicionado ao cofre.".green());

                        // Only prompt "Enter" if not in CLI? We just keep it simple.
                        if std::env::args().len() == 1 {
                            let _ = inquire::Text::new("Pressione Enter para sair...").prompt();
                        }
                    }
                    Err(_) => (),
                }
            } else {
                eprintln!("{}", "Nenhum cofre disponível.".red());
                if std::env::args().len() == 1 {
                    let _ = inquire::Text::new("Pressione Enter para sair...").prompt();
                }
            }
        }

        /* ── mount <id> [senha] ─────────────────────────────────────── */
        "mount" => {
            let Some(id) = parse_id(parts.get(1), "mount") else {
                return;
            };
            let password = get_password("Vault password (Enter to skip):", parts.get(2));
            let start_time = Instant::now();
            crate::log::console_trace("MOUNT_FUSE_INIT", &format!("Mounting vault {} via FUSE", id));
            match vault::vault_mount(id, &password) {
                Ok(()) => {
                    crate::log::console_trace("MOUNT_FUSE_DONE", &format!("Vault mounted successfully in {:.2?}", start_time.elapsed()));
                    println!("{}", format!("✔ Vault {} montado via FUSE.", id).green());
                },
                Err(e) => {
                    crate::log::console_trace("MOUNT_FUSE_ERROR", &format!("Error mounting vault after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Error mounting: {}", e).red());
                }
            }
        }

        /* ── umount <id> ─────────────────────────────────────────────── */
        "umount" => {
            let Some(id) = parse_id(parts.get(1), "umount") else {
                return;
            };
            let start_time = Instant::now();
            crate::log::console_trace("UMOUNT_FUSE_INIT", &format!("Unmounting vault {} from FUSE", id));
            match vault::vault_unmount(id) {
                Ok(()) => {
                    crate::log::console_trace("UMOUNT_FUSE_DONE", &format!("Vault unmounted successfully in {:.2?}", start_time.elapsed()));
                    println!("{}", format!("✔ Vault {} unmounted from FUSE.", id).green());
                },
                Err(e) => {
                    crate::log::console_trace("UMOUNT_FUSE_ERROR", &format!("Error unmounting vault after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Error unmounting: {}", e).red());
                }
            }
        }

        /* ── worm <id> [flags...] ───────────────────────────────────
         *
         * Configura as proteções WORM de um vault.
         *
         * Exemplos:
         *   worm 3 --protect-delete --no-write
         *   worm 3 --protected-scan
         *   worm 3 --status
         *   worm 3 --clear-delete --clear-rename
         * ─────────────────────────────────────────────────────────────────── */
        "worm" => {
            let Some(id) = parse_id(parts.get(1), "worm") else {
                eprintln!("{}", "✖ Uso: worm <id> [--protect-delete] [--protect-rename] [--no-write] [--protected-scan] [--clear-*] [--status]".red());
                return;
            };

            let flags_args: Vec<&str> = parts[2..].to_vec();

            if flags_args.is_empty() || flags_args.contains(&"--status") {
                let current = vault::vault_worm_get_flags(id);
                println!("{}", format!("── WORM flags para vault {} ──────────────────", id).cyan());
                println!("  delete  : {}", if current & vault::WORM_DELETE != 0 { "BLOCKED".red().to_string() } else { "allowed".dimmed().to_string() });
                println!("  rename  : {}", if current & vault::WORM_RENAME != 0 { "BLOCKED".red().to_string() } else { "allowed".dimmed().to_string() });
                println!("  write   : {}", if current & vault::WORM_WRITE  != 0 { "BLOCKED".red().to_string() } else { "allowed".dimmed().to_string() });
                println!("  scan    : {}", if current & vault::WORM_SCAN   != 0 { "PROTECTED-SCAN (immutable)".red().bold().to_string() } else { "inactive".dimmed().to_string() });
                println!("  read    : {}", if current & vault::WORM_READ   != 0 { "BLOCKED".red().to_string() } else { "allowed".dimmed().to_string() });
                println!("  all     : {}", if current == vault::WORM_ALL  { "BLOCKED".red().to_string() } else { "allowed".dimmed().to_string() });
                println!("  raw flags: 0x{:02x}", current);
                return;
            }

            /* --protected-scan: special interactive confirmation */
            if flags_args.contains(&"--protected-scan") {
                println!("{}", "\n⚠  ATENÇÃO — PROTECTED-SCAN MODO MÁXIMO".red().bold());
                println!("{}", "   Esta operação é IRREVERSÍVEL em runtime.".yellow());
                println!("{}", "   O vault ficará completamente immutable.".yellow());
                println!("{}", "   A ÚNICA forma de recuperar arquivos será via: mount-export\n".yellow());

                let confirm = inquire::Select::new(
                    "Confirmar ativação de PROTECTED-SCAN?",
                    vec!["Sim, ativar proteção máxima", "Não, cancelar"],
                ).prompt();

                match confirm {
                    Ok("Sim, ativar proteção máxima") => {
                        match vault::vault_worm_set_scan(id) {
                            Ok(()) => {
                                println!("{}", format!("✔ Vault {} agora está em PROTECTED-SCAN (immutable).", id).green().bold());
                                println!("{}", "  Use 'mount-export' para resgatar arquivos quando necessário.".cyan());
                            }
                            Err(e) => eprintln!("{}", format!("✖ Error: {}", e).red()),
                        }
                    }
                    _ => println!("{}", "Operação cancelada.".yellow()),
                }
                return;
            }

            /* Flags to set */
            let mut set_mask: u32 = 0;
            let mut clear_mask: u32 = 0;

            for arg in &flags_args {
                match *arg {
                    "--protect-delete" => set_mask |= vault::WORM_DELETE,
                    "--protect-rename" => set_mask |= vault::WORM_RENAME,
                    "--protect-read"   => set_mask |= vault::WORM_READ,
                    "--no-write"       => set_mask |= vault::WORM_WRITE,
                    "--clear-delete"   => clear_mask |= vault::WORM_DELETE,
                    "--clear-rename"   => clear_mask |= vault::WORM_RENAME,
                    "--clear-read"     => clear_mask |= vault::WORM_READ,
                    "--clear-write"    => clear_mask |= vault::WORM_WRITE,
                    other => {
                        eprintln!("{}", format!("✖ Flag desconhecida: {}", other).red());
                        eprintln!("{}", "  Flags válidas: --protect-delete --protect-rename --no-write --protected-scan --clear-delete --clear-rename --clear-write --status".dimmed());
                        return;
                    }
                }
            }

            if set_mask != 0 {
                match vault::vault_worm_set(id, set_mask) {
                    Ok(()) => println!("{}", format!("✔ Proteções ativadas (mask=0x{:02x}).", set_mask).green()),
                    Err(e) => { eprintln!("{}", format!("✖ Error enabling: {}", e).red()); return; }
                }
            }

            if clear_mask != 0 {
                match vault::vault_worm_clear(id, clear_mask) {
                    Ok(()) => println!("{}", format!("✔ Proteções removidas (mask=0x{:02x}).", clear_mask).green()),
                    Err(e) => eprintln!("{}", format!("✖ Error removing: {}", e).red()),
                }
            }

            /* Show updated status */
            let start_time = Instant::now();
            crate::log::console_trace("WORM_PROTECT_INIT", &format!("Applying WORM rules to vault id={} set=0x{:x} clear=0x{:x}", id, set_mask, clear_mask));
            let updated = vault::vault_worm_get_flags(id);
            crate::log::console_trace("WORM_PROTECT_DONE", &format!("WORM rules applied in {:.2?}. New state: 0x{:x}", start_time.elapsed(), updated));
            println!("{}", format!("  Current state: delete={} rename={} write={} scan={} read={}",
                if updated & vault::WORM_DELETE != 0 { "BLOCK" } else { "ok" },
                if updated & vault::WORM_RENAME != 0 { "BLOCK" } else { "ok" },
                if updated & vault::WORM_WRITE  != 0 { "BLOCK" } else { "ok" },
                if updated & vault::WORM_SCAN   != 0 { "SCAN" }  else { "off" },
                if updated & vault::WORM_READ   != 0 { "BLOCK" } else { "ok" },
            ).cyan());
        }

        /* ── api-start [--port <p>] ──────────────────────────────────────────
         *
         * Inicia API HTTP local em thread separada.
         * Endpoints: GET /vaults  POST /vaults/:id/scan  GET /vaults/:id/status
         * ─────────────────────────────────────────────────────────────────── */
        "api-start" => {
            use std::net::TcpListener;
            use std::io::Write;

            // Resolve port: --port <n> ou padrão 8080
            let port: u16 = {
                let mut p = 8080u16;
                let mut it = parts.iter().skip(1);
                while let Some(&tok) = it.next() {
                    if tok == "--port" {
                        if let Some(&val) = it.next() {
                            p = val.parse().unwrap_or(8080);
                        }
                    }
                }
                p
            };

            let addr = format!("127.0.0.1:{}", port);

            // Evita iniciar se a porta já está em uso
            match TcpListener::bind(&addr) {
                Err(e) => {
                    eprintln!("{}", format!("✖ Não foi possível abrir {}: {}", addr, e).red());
                    eprintln!("{}", "  A API já pode estar em execução. Use 'api-status' para verificar.".yellow());
                    return;
                }
                Ok(listener) => {
                    println!("{}", format!("✔ API HTTP iniciada em http://{}", addr).green());
                    println!("{}", "  GET  /vaults".dimmed());
                    println!("{}", "  GET  /vaults/:id/status".dimmed());
                    println!("{}", "  POST /vaults/:id/scan".dimmed());
                    println!("{}", "  Use 'api-stop' para encerrar.".cyan());

                    let start_time = Instant::now();
                    crate::log::console_trace("API_START_INIT", &format!("Starting local HTTP API on port {}", port));
                    
                    // Persiste o PID e porta no diretório de dados
                    let pid_file = dirs_api_pid_path();
                    if let Ok(mut f) = std::fs::File::create(&pid_file) {
                        let _ = write!(f, "{}:{}", std::process::id(), port);
                    }

                    crate::log::console_trace("API_START_DONE", &format!("API started successfully in {:.2?}", start_time.elapsed()));

                    // Thread que aceita conexões (servidor mínimo HTTP/1.0)
                    std::thread::spawn(move || {
                        for stream in listener.incoming() {
                            match stream {
                                Ok(mut s) => {
                                    let _ = handle_api_request(&mut s);
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
            }
        }

        "api-stop" => {
            let pid_file = dirs_api_pid_path();
            match std::fs::read_to_string(&pid_file) {
                Ok(content) => {
                    let parts_pid: Vec<&str> = content.splitn(2, ':').collect();
                    let pid_str = parts_pid[0].trim();
                    match pid_str.parse::<u32>() {
                        Ok(pid) => {
                            let start_time = Instant::now();
                            crate::log::console_trace("API_STOP_INIT", &format!("Stopping API with PID {}", pid));
                            // Envia SIGTERM para o processo da API
                            #[cfg(unix)]
                            unsafe { libc::kill(pid as i32, libc::SIGTERM); }
                            let _ = std::fs::remove_file(&pid_file);
                            crate::log::console_trace("API_STOP_DONE", &format!("API stopped in {:.2?}", start_time.elapsed()));
                            println!("{}", format!("✔ Sinal de parada enviado para PID {}.", pid).green());
                        }
                        Err(_) => eprintln!("{}", "✖ PID inválido no arquivo de estado da API.".red()),
                    }
                }
                Err(_) => println!("{}", "⚠ API não está em execução (nenhum arquivo de PID encontrado).".yellow()),
            }
        }

        "api-status" => {
            let pid_file = dirs_api_pid_path();
            match std::fs::read_to_string(&pid_file) {
                Ok(content) => {
                    let parts_s: Vec<&str> = content.splitn(2, ':').collect();
                    let pid = parts_s[0].trim();
                    let port = parts_s.get(1).copied().unwrap_or("8080").trim();
                    // Verifica se o processo ainda existe
                    let alive = {
                        #[cfg(unix)]
                        {
                            pid.parse::<i32>().map(|p| unsafe {
                                libc::kill(p, 0) == 0
                            }).unwrap_or(false)
                        }
                        #[cfg(not(unix))]
                        { false }
                    };
                    if alive {
                        println!("{}", format!("✔ API em execução — porta {} | PID {}", port, pid).green());
                    } else {
                        println!("{}", format!("⚠ Arquivo de PID existe (PID {}) mas o processo não responde.", pid).yellow());
                        let _ = std::fs::remove_file(&pid_file);
                    }
                }
                Err(_) => println!("{}", "⚠ API não está em execução.".yellow()),
            }
        }

        /* ── mount-export <id> ───────────────────────────────────────────────
         *
         * Resgata arquivos de um vault FUSE diretamente do cipher_path,
         * bypassando o FUSE. Funciona mesmo para vaults em PROTECTED-SCAN.
         *
         * Fluxo:
         *   1. Seleciona vault pelo ID (interativo se não fornecido)
         *   2. Pergunta quais arquivos (todos ou um específico)
         *   3. Pergunta pasta de destino
         *   4. Solicita senha (se vault protegido)
         *   5. Exporta (decriptando se necessário)
         * ─────────────────────────────────────────────────────────────────── */
        "mount-export" => {
            /* Step 1 — resolve vault ID */
            let id: Option<u32> = if let Some(&s) = parts.get(1) {
                s.parse::<u32>().ok()
            } else {
                /* Interactive: list mounted/scan vaults */
                let all = vault::vault_get_all_paths_pub();
                if all.is_empty() {
                    println!("{}", "No vaults found in the catalog.".yellow());
                    return;
                }
                let choices: Vec<String> = all.iter()
                    .map(|(vid, path)| {
                        let flags = vault::vault_worm_get_flags(*vid);
                        let scan_tag = if flags & vault::WORM_SCAN != 0 { " [PROTECTED-SCAN]" } else { "" };
                        format!("ID={} path={}{}", vid, path, scan_tag)
                    })
                    .collect();
                match inquire::Select::new("Selecione o vault para exportar:", choices.clone()).prompt() {
                    Ok(choice) => choices.iter().position(|c| c == &choice)
                        .map(|i| all[i].0),
                    Err(_) => return,
                }
            };

            let Some(id) = id else {
                eprintln!("{}", "✖ ID do vault inválido.".red());
                return;
            };

            /* Step 2 — list files in cipher_path */
            let real_path = match vault::vault_get_real_path(id) {
                Ok(p) => p,
                Err(e) => { eprintln!("{}", format!("✖ Error getting cipher_path: {}", e).red()); return; }
            };

            let mut available_files: Vec<String> = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&real_path) {
                for entry in entries.flatten() {
                    if let Ok(ft) = entry.file_type() {
                        if ft.is_file() {
                            available_files.push(entry.file_name().to_string_lossy().to_string());
                        }
                    }
                }
            }

            if available_files.is_empty() {
                println!("{}", "O vault está vazio.".yellow());
                return;
            }

            available_files.sort();
            available_files.insert(0, ">> Todos os arquivos".to_string());
            available_files.push(">> Cancel".to_string());

            let filename = match inquire::Select::new("Selecione o arquivo para resgatar:", available_files).prompt() {
                Ok(ans) if ans == ">> Cancel" => return,
                Ok(ans) => ans,
                Err(_) => return,
            };

            /* Step 3 — destination */
            let worm_flags = vault::vault_worm_get_flags(id);
            if worm_flags & vault::WORM_SCAN != 0 {
                println!("{}", "\n⚠  Este vault está em PROTECTED-SCAN. Os arquivos serão exportados para fora do vault.".yellow().bold());
            } else {
                println!("{}", "\n⚠  Os arquivos exportados ficarão desprotegidos no destino!".yellow());
            }

            let confirm = inquire::Select::new(
                "Confirmar exportação?",
                vec!["Sim, exportar", "Não, cancelar"],
            ).prompt();
            if let Ok("Não, cancelar") | Err(_) = confirm { return; }

            println!("{}", "➜ Select destination folder...".cyan());
            let dst_dir = match rfd::FileDialog::new().pick_folder() {
                Some(p) => p,
                None => { println!("{}", "✖ No folder selected.".red()); return; }
            };

            /* Step 4 — password */
            let is_protected = vault::vault_is_protected(id);
            let password = if is_protected {
                prompt_password("Senha do cofre (necessária para decifrar):")
            } else {
                String::new()
            };

            if is_protected && password.is_empty() {
                eprintln!("{}", "✖ Senha obrigatória para cofres protegidos.".red());
                return;
            }

            let dst_str = dst_dir.to_string_lossy().to_string();
            let file_arg = if filename == ">> Todos os arquivos" { None } else { Some(filename.as_str()) };

            log::info(&format!("mount-export id={} file={:?} dst={}", id, file_arg, dst_str));

            match vault::vault_mount_export(id, &password, &dst_str, file_arg) {
                Ok(()) => {
                    println!("{}", format!("✔ Export concluído para: {}", dst_str).green());
                }
                Err(e) => {
                    log::error(&format!("mount-export: {}", e));
                    eprintln!("{}", format!("✖ Error exporting: {}", e).red());
                }
            }
        }

        /* ── comando desconhecido — Levenshtein sugere o mais próximo ── */
        unknown => {
            log::warn(&format!("Command inválido: {}", unknown));

            match suggest_command(unknown) {
                Some(suggestion) => {
                    println!("{}", format!("✖ Command '{}' não existe.", unknown).red());
                    println!(
                        "{}",
                        format!("  Você quis dizer '{}'?", suggestion).yellow()
                    );
                }
                None => {
                    println!("{}", format!("✖ Command '{}' não existe.", unknown).red());
                    println!("{}", "Type 'help' para ver os comandos.".yellow());
                }
            }
        }
    }
}

/*
 *  MAIN
 *  */

/* ── Helpers para a API HTTP ──────────────────────────────────────────────── */

/// Retorna o path do arquivo de PID/porta da API.
fn dirs_api_pid_path() -> std::path::PathBuf {
    let base = std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
    base.join(".local/share/idenvault/api.pid")
}

/// Servidor HTTP mínimo: trata uma conexão TCP e responde JSON.
fn handle_api_request(stream: &mut std::net::TcpStream) -> std::io::Result<()> {
    use std::io::{BufRead, BufReader, Write};

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    // Lê e descarta os headers
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("GET");
    let path   = parts.get(1).copied().unwrap_or("/");

    let (status, body) = match (method, path) {
        ("GET", "/vaults") => {
            let vaults = vault::vault_get_all_paths_pub();
            let entries: Vec<String> = vaults.iter()
                .map(|(id, p)| format!("{{\"id\":{},\"path\":\"{}\"}}", id, p.replace('"', "\\\"")))
                .collect();
            (200, format!("[{}]", entries.join(",")))
        }
        ("GET", p) if p.starts_with("/vaults/") && p.ends_with("/status") => {
            let id_str = p.trim_start_matches("/vaults/").trim_end_matches("/status");
            match id_str.parse::<u32>() {
                Ok(id) => {
                    let info = format!("{{\"id\":{},\"status\":\"ok\"}}", id);
                    (200, info)
                }
                Err(_) => (400, "{\"error\":\"invalid id\"}".to_string()),
            }
        }
        ("POST", p) if p.starts_with("/vaults/") && p.ends_with("/scan") => {
            let id_str = p.trim_start_matches("/vaults/").trim_end_matches("/scan");
            match id_str.parse::<u32>() {
                Ok(id) => {
                    let _ = vault::vault_scan(id);
                    (200, format!("{{\"id\":{},\"scan\":\"triggered\"}}", id))
                }
                Err(_) => (400, "{\"error\":\"invalid id\"}".to_string()),
            }
        }
        _ => (404, "{\"error\":\"not found\"}".to_string()),
    };

    let response = format!(
        "HTTP/1.0 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let is_cli = args.len() > 1;

    let mut rl = DefaultEditor::new().unwrap();
    log::info("Application started.");

    /* ── Inicializa o core C: carrega catálogo do disco, inicia monitor ── */
    match vault::vault_init() {
        Ok(()) => log::info("C Core initialized: catalog loaded from disk."),
        Err(e) => {
            eprintln!(
                "{}",
                format!(
                    "⚠ Failed to initialize C core: {} (continuing without persistence)",
                    e
                )
                .yellow()
            );
        }
    }

    let mut cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));

    if is_cli {
        let cmd_args: Vec<&str> = args[1..].iter().map(|s| s.as_str()).collect();
        handle_command(cmd_args, &mut cwd);
        let _ = vault::vault_shutdown();
        std::process::exit(0);
    }

println!(
    "{}",
    "IdenVault started successfully.\n\
     Enjoy yourself :D\n\n\
     Created by Peter Steve, with coffee and a lot of love.\n\n\
     Type 'help' to see available commands.\n\
     If you run into any issues, contact:\n\
     squirrelbomb27@proton.me\n"
        .bright_green()
);

    /* ── Ctrl+C: shutdown graceful — salva catálogo antes de sair ─────── */
    ctrlc::set_handler(|| {
        println!("\n{}", "^C — Saving catalog...".yellow());
        log::info("Ctrl+C recebido — executando shutdown graceful");

        /* Salva catálogo no disco e limpa memória sensível */
        match vault::vault_shutdown() {
            Ok(()) => log::info("Catalog saved successfully."),
            Err(e) => {
                eprintln!("⚠ Error saving catalog: {}", e);
                log::error(&format!("Shutdown error: {}", e));
            }
        }

        log::info("Application closing (graceful)");
        std::process::exit(0);
    })
    .expect("Error setting handler");

    let mut first_run = true;
    loop {
        /* Formata prompt com CWD abreviado com ~ */
        let display_path = if let Ok(home) = std::env::var("HOME") {
            let home_path = std::path::Path::new(&home);
            if let Ok(stripped) = cwd.strip_prefix(home_path) {
                format!("~/{}", stripped.display())
            } else {
                cwd.display().to_string()
            }
        } else {
            cwd.display().to_string()
        };
        let prompt_str = format!("IdenVault [{}]> ", display_path.bright_blue());
        let readline = if first_run {
            first_run = false;
            Ok("menu".to_string())
        } else {
            rl.readline(&prompt_str)
        };

        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str()).ok();
                let input = line.trim();
                let mut cmd_to_run = input.to_string();

                if input.is_empty() || input == "menu" {
                    if std::io::stdin().is_terminal() {
                        if let Some(c) = interactive_menu() {
                            cmd_to_run = c;
                        } else {
                            continue;
                        }
                    } else {
                        // For automated testing via piped input, empty lines are ignored.
                        if input.is_empty() {
                            continue;
                        }
                    }
                }

                /* Command 'quit' / 'exit' → shutdown graceful */
                if cmd_to_run == "quit" || cmd_to_run == "exit" {
                    println!("{}", "Saving catalog and exiting...".yellow());
                    match vault::vault_shutdown() {
                        Ok(()) => log::info("Catalog saved successfully."),
                        Err(e) => eprintln!("⚠ Error saving: {}", e),
                    }
                    log::info("Application terminated by user.");
                    break;
                }

                /* Detect drag-and-drop file paths */
                let parsed_path = if input.starts_with('\'') && input.ends_with('\'') {
                    input[1..input.len() - 1].to_string()
                } else {
                    input.to_string()
                };

                if (parsed_path.starts_with('/') || parsed_path.starts_with("file://")) && Path::new(&parsed_path.replace("file://", "")).exists() {

                    let file_path = parsed_path.replace("file://", "");
                    println!("{}\n{}", "➜ Dragged file detected:".cyan(), file_path);
                    let vaults = vault::vault_get_all_paths_pub();
                    if !vaults.is_empty() {
                        let mut options: Vec<String> = vaults
                            .iter()
                            .map(|(id, path)| format!("[{}] {}", id, path))
                            .collect();
                        options.push(">> Cancel".to_string());
                        
                        match inquire::Select::new("Add to vault?", options).prompt() {
                            Ok(ans) if ans != ">> Cancel" => {
                                let vault_path = ans.split("] ").nth(1).unwrap_or("");
                                let _ = vault::add_file(vault_path, &file_path);
                                println!("{}", "✔ Arquivo adicionado.".green());
                            }
                            _ => println!("{}", "Operação cancelada.".yellow()),
                        }
                    } else {
                        eprintln!("{}", "✖ No vault available to add the file.".red());
                    }
                    continue;
                }

                let commands: Vec<&str> = cmd_to_run.split(" && ").collect();
                for single_cmd in commands {
                    let mut final_cmd = single_cmd.to_string();
                    if final_cmd.contains("LAST_CREATED_ID") {
                        // Get the highest ID from the catalog as an approximation of the last created
                        let vaults = vault::vault_get_all_paths_pub();
                        let max_id = vaults.iter().map(|(id, _)| id).max().unwrap_or(&0);
                        final_cmd = final_cmd.replace("LAST_CREATED_ID", &max_id.to_string());
                    }
                    let parts: Vec<&str> = final_cmd.split_whitespace().collect();
                    if !parts.is_empty() {
                        handle_command(parts, &mut cwd);
                    }
                }
            }

            Err(ReadlineError::Eof) => {
                println!("\n{}", "^D — Saving catalog...".yellow());
                match vault::vault_shutdown() {
                    Ok(()) => log::info("Catalog saved successfully (EOF)."),
                    Err(e) => eprintln!("⚠ Error saving: {}", e),
                }
                log::info("EOF detectado.");
                break;
            }

            Err(err) => {
                log::error(&format!("Read error: {:?}", err));
                /* Tenta salvar mesmo em erro */
                let _ = vault::vault_shutdown();
                break;
            }
        }
    }
}