import re

with open("src/main.rs", "r") as f:
    content = f.read()

# Define the replacements for each command
replacements = {
    # Isolate Directory
    r'log::info\(&format!\("Isolando diretório: \Q{:?}\E", dir\)\);\n\s*vault::isolate_directory\(dir\.to_str\(\)\.unwrap\(\)\);':
    '''let start_time = Instant::now();
                crate::log::console_trace("ISOLATE_INIT", &format!("Isolating directory: {:?}", dir));
                vault::isolate_directory(dir.to_str().unwrap());
                crate::log::console_trace("ISOLATE_DONE", &format!("Directory isolated in {:.2?}", start_time.elapsed()));''',

    # Create Vault (basic)
    r'log::info\(&format!\("Criando cofre em: \Q{:?}\E", path\)\);\n\s*vault::create\(path\.to_str\(\)\.unwrap\(\)\);\n\s*println!\("\{\}", "✔ Vault created"\.green\(\)\);':
    '''let start_time = Instant::now();
                crate::log::console_trace("CREATE_INIT", &format!("Creating vault in: {:?}", path));
                vault::create(path.to_str().unwrap());
                crate::log::console_trace("CREATE_DONE", &format!("Vault created successfully in {:.2?}", start_time.elapsed()));
                println!("{}", "✔ Vault created".green());''',

    # Safe Copy
    r'log::info\(&format!\("Cópia segura: \Q{:?} -> {:?}\E", s, d\)\);\n\s*match vault::secure_copy\(s\.to_str\(\)\.unwrap\(\), d\.to_str\(\)\.unwrap\(\)\) \{\n\s*Ok\(_\) => println!\("\{\}", "✔ Arquivo copiado"\.green\(\)\),\n\s*Err\(e\) => \{\n\s*log::error\(&format!\("Erro em safe-copy: \{\}", e\)\);\n\s*eprintln!\("\{\}", format!\("✖ Erro: \{\}", e\)\.red\(\)\);\n\s*\}\n\s*\}':
    '''let start_time = Instant::now();
                crate::log::console_trace("SAFE_COPY_INIT", &format!("Secure copy: {:?} -> {:?}", s, d));
                match vault::secure_copy(s.to_str().unwrap(), d.to_str().unwrap()) {
                    Ok(_) => {
                        crate::log::console_trace("SAFE_COPY_DONE", &format!("File copied securely in {:.2?}", start_time.elapsed()));
                        println!("{}", "✔ Arquivo copiado".green());
                    },
                    Err(e) => {
                        crate::log::console_trace("SAFE_COPY_ERROR", &format!("Error in safe-copy after {:.2?}: {}", start_time.elapsed(), e));
                        eprintln!("{}", format!("✖ Erro: {}", e).red());
                    }
                }''',

    # Allow Write
    r'log::info\(&format!\("Liberando escrita: \Q{:?}\E", path\)\);\n\s*vault::allow_write\(path\.to_str\(\)\.unwrap\(\)\);\n\s*println!\("\{\}", "✔ Escrita liberada"\.green\(\)\);':
    '''let start_time = Instant::now();
                crate::log::console_trace("ALLOW_WRITE_INIT", &format!("Allowing write for: {:?}", path));
                vault::allow_write(path.to_str().unwrap());
                crate::log::console_trace("ALLOW_WRITE_DONE", &format!("Write allowed in {:.2?}", start_time.elapsed()));
                println!("{}", "✔ Escrita liberada".green());''',

    # Read Directory
    r'log::info\(&format!\("Listando diretório: \{\}", dir_str\)\);\n\s*let files = vault::read_directory\(dir_str\);':
    '''let start_time = Instant::now();
                crate::log::console_trace("READ_DIR_INIT", &format!("Listing directory: {}", dir_str));
                let files = vault::read_directory(dir_str);
                crate::log::console_trace("READ_DIR_DONE", &format!("Directory listed in {:.2?}", start_time.elapsed()));''',

    # Remove File
    r'log::info\(&format!\("Removendo arquivo \{\} do cofre \Q{:?}\E", f, v\)\);\n\s*match vault::remove_file\(v\.to_str\(\)\.unwrap\(\), &f\) \{\n\s*Ok\(_\) => println!\("\{\}", "✔ Arquivo removido"\.green\(\)\),\n\s*Err\(e\) => \{\n\s*log::error\(&format!\("Erro em remove-file: \{\}", e\)\);\n\s*eprintln!\("\{\}", format!\("✖ Erro: \{\}", e\)\.red\(\)\);\n\s*\}\n\s*\}':
    '''let start_time = Instant::now();
                crate::log::console_trace("REMOVE_FILE_INIT", &format!("Removing file {} from vault {:?}", f, v));
                match vault::remove_file(v.to_str().unwrap(), &f) {
                    Ok(_) => {
                        crate::log::console_trace("REMOVE_FILE_DONE", &format!("File removed in {:.2?}", start_time.elapsed()));
                        println!("{}", "✔ Arquivo removido".green());
                    },
                    Err(e) => {
                        crate::log::console_trace("REMOVE_FILE_ERROR", &format!("Error in remove-file after {:.2?}: {}", start_time.elapsed(), e));
                        eprintln!("{}", format!("✖ Erro: {}", e).red());
                    }
                }''',

    # Status
    r'log::info\(&format!\("Verificando status do cofre: \Q{:?}\E", vault_path\)\);\n\s*match vault::get_vault_status\(vault_path\.to_str\(\)\.unwrap\(\)\) \{\n\s*Ok\(_\) => \(\),\n\s*Err\(e\) => \{\n\s*log::error\(&format!\("Erro em status: \{\}", e\)\);\n\s*eprintln!\("\{\}", format!\("✖ Erro: \{\}", e\)\.red\(\)\);\n\s*\}\n\s*\}':
    '''let start_time = Instant::now();
                crate::log::console_trace("STATUS_INIT", &format!("Checking vault status: {:?}", vault_path));
                match vault::get_vault_status(vault_path.to_str().unwrap()) {
                    Ok(_) => {
                        crate::log::console_trace("STATUS_DONE", &format!("Status checked in {:.2?}", start_time.elapsed()));
                    },
                    Err(e) => {
                        crate::log::console_trace("STATUS_ERROR", &format!("Error in status check after {:.2?}: {}", start_time.elapsed(), e));
                        eprintln!("{}", format!("✖ Erro: {}", e).red());
                    }
                }''',

    # Encrypt
    r'log::info\(&format!\("Criptografando arquivo: \Q{:?}\E", file\)\);\n\s*match crypto::encrypt_file\(&file, &pass\) \{\n\s*Ok\(_\) => println!\("\{\}", "✔ Arquivo criptografado"\.green\(\)\),\n\s*Err\(e\) => \{\n\s*log::error\(&format!\("Erro em encrypt: \{\}", e\)\);\n\s*eprintln!\("\{\}", format!\("✖ Erro: \{\}", e\)\.red\(\)\);\n\s*\}\n\s*\}':
    '''let start_time = Instant::now();
                    crate::log::console_trace("ENCRYPT_INIT", &format!("Encrypting file: {:?}", file));
                    match crypto::encrypt_file(&file, &pass) {
                        Ok(_) => {
                            crate::log::console_trace("ENCRYPT_DONE", &format!("File encrypted in {:.2?}", start_time.elapsed()));
                            println!("{}", "✔ Arquivo criptografado".green());
                        },
                        Err(e) => {
                            crate::log::console_trace("ENCRYPT_ERROR", &format!("Error encrypting file after {:.2?}: {}", start_time.elapsed(), e));
                            eprintln!("{}", format!("✖ Erro: {}", e).red());
                        }
                    }''',

    # Decrypt
    r'log::info\(&format!\("Descriptografando arquivo: \Q{:?}\E", file\)\);\n\s*match crypto::decrypt_file\(&file, &pass\) \{\n\s*Ok\(_\) => println!\("\{\}", "✔ Arquivo descriptografado"\.green\(\)\),\n\s*Err\(e\) => \{\n\s*log::error\(&format!\("Erro em decrypt: \{\}", e\)\);\n\s*eprintln!\("\{\}", format!\("✖ Erro: \{\}", e\)\.red\(\)\);\n\s*\}\n\s*\}':
    '''let start_time = Instant::now();
                    crate::log::console_trace("DECRYPT_INIT", &format!("Decrypting file: {:?}", file));
                    match crypto::decrypt_file(&file, &pass) {
                        Ok(_) => {
                            crate::log::console_trace("DECRYPT_DONE", &format!("File decrypted in {:.2?}", start_time.elapsed()));
                            println!("{}", "✔ Arquivo descriptografado".green());
                        },
                        Err(e) => {
                            crate::log::console_trace("DECRYPT_ERROR", &format!("Error decrypting file after {:.2?}: {}", start_time.elapsed(), e));
                            eprintln!("{}", format!("✖ Erro: {}", e).red());
                        }
                    }''',

    # Secure Copy
    r'log::info\(&format!\("Secure-copy: \Q{:?}\E para \Q{:?}\E", f, v\)\);\n\s*vault::secure_store\(f\.to_str\(\)\.unwrap\(\), v\.to_str\(\)\.unwrap\(\), &pass_to_use\);\n\s*println!\("\{\}", "✔ File protected and stored in vault"\.green\(\)\);':
    '''let start_time = Instant::now();
                crate::log::console_trace("SECURE_STORE_INIT", &format!("Secure copy: {:?} to {:?}", f, v));
                vault::secure_store(f.to_str().unwrap(), v.to_str().unwrap(), &pass_to_use);
                crate::log::console_trace("SECURE_STORE_DONE", &format!("File protected and stored in vault in {:.2?}", start_time.elapsed()));
                println!("{}", "✔ File protected and stored in vault".green());''',

    # Vault List
    r'log::info\("Listando cofres do catálogo \(core C\)"\);\n\s*vault::vault_list\(\);':
    '''let start_time = Instant::now();
            crate::log::console_trace("VAULT_LIST_INIT", "Listing vaults from catalog (C core)...");
            vault::vault_list();
            crate::log::console_trace("VAULT_LIST_DONE", &format!("Vaults listed in {:.2?}", start_time.elapsed()));''',

    # Vault Delete
    r'log::info\(&format!\("vault-delete id=\{\}", id\)\);\n\s*match vault::vault_delete\(id, pass\.as_deref\(\)\) \{\n\s*Ok\(_\) => println!\("\{\}", "✔ Cofre deletado\."\.green\(\)\),\n\s*Err\(e\) => \{\n\s*log::error\(&format!\("vault-delete: \{\}", e\)\);\n\s*eprintln!\("\{\}", format!\("✖ Erro: \{\}", e\)\.red\(\)\);\n\s*\}\n\s*\}':
    '''let start_time = Instant::now();
            crate::log::console_trace("VAULT_DELETE_INIT", &format!("Deleting vault id={}", id));
            match vault::vault_delete(id, pass.as_deref()) {
                Ok(_) => {
                    crate::log::console_trace("VAULT_DELETE_DONE", &format!("Vault deleted in {:.2?}", start_time.elapsed()));
                    println!("{}", "✔ Cofre deletado.".green());
                },
                Err(e) => {
                    crate::log::console_trace("VAULT_DELETE_ERROR", &format!("Error deleting vault after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }''',

    # Vault Rename
    r'log::info\(&format!\("vault-rename id=\{\} new_name=\{\}", id, new_name\)\);\n\s*match vault::vault_rename\(id, new_name, pass\.as_deref\(\)\) \{\n\s*Ok\(_\) => println!\("\{\}", "✔ Cofre renomeado\."\.green\(\)\),\n\s*Err\(e\) => \{\n\s*log::error\(&format!\("vault-rename: \{\}", e\)\);\n\s*eprintln!\("\{\}", format!\("✖ Erro: \{\}", e\)\.red\(\)\);\n\s*\}\n\s*\}':
    '''let start_time = Instant::now();
            crate::log::console_trace("VAULT_RENAME_INIT", &format!("Renaming vault id={} to {}", id, new_name));
            match vault::vault_rename(id, new_name, pass.as_deref()) {
                Ok(_) => {
                    crate::log::console_trace("VAULT_RENAME_DONE", &format!("Vault renamed in {:.2?}", start_time.elapsed()));
                    println!("{}", "✔ Cofre renomeado.".green());
                },
                Err(e) => {
                    crate::log::console_trace("VAULT_RENAME_ERROR", &format!("Error renaming vault after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }''',

    # Vault Unlock
    r'log::info\(&format!\("vault-unlock id=\{\}", id\)\);\n\s*match vault::vault_unlock\(id, &pass\) \{\n\s*Ok\(_\) => println!\("\{\}", "✔ Cofre desbloqueado\."\.green\(\)\),\n\s*Err\(e\) => \{\n\s*log::error\(&format!\("vault-unlock: \{\}", e\)\);\n\s*eprintln!\("\{\}", format!\("✖ Erro: \{\}", e\)\.red\(\)\);\n\s*\}\n\s*\}':
    '''let start_time = Instant::now();
            crate::log::console_trace("VAULT_UNLOCK_INIT", &format!("Unlocking vault id={}", id));
            match vault::vault_unlock(id, &pass) {
                Ok(_) => {
                    crate::log::console_trace("VAULT_UNLOCK_DONE", &format!("Vault unlocked in {:.2?}", start_time.elapsed()));
                    println!("{}", "✔ Cofre desbloqueado.".green());
                },
                Err(e) => {
                    crate::log::console_trace("VAULT_UNLOCK_ERROR", &format!("Error unlocking vault after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }''',

    # Vault Passwd
    r'log::info\(&format!\("vault-passwd id=\{\}", id\)\);\n\s*match vault::vault_change_password\(id, &old_pass, &new_pass\) \{\n\s*Ok\(_\) => println!\("\{\}", "✔ Senha alterada\."\.green\(\)\),\n\s*Err\(e\) => \{\n\s*log::error\(&format!\("vault-passwd: \{\}", e\)\);\n\s*eprintln!\("\{\}", format!\("✖ Erro: \{\}", e\)\.red\(\)\);\n\s*\}\n\s*\}':
    '''let start_time = Instant::now();
            crate::log::console_trace("VAULT_PASSWD_INIT", &format!("Changing password for vault id={}", id));
            match vault::vault_change_password(id, &old_pass, &new_pass) {
                Ok(_) => {
                    crate::log::console_trace("VAULT_PASSWD_DONE", &format!("Password changed in {:.2?}", start_time.elapsed()));
                    println!("{}", "✔ Senha alterada.".green());
                },
                Err(e) => {
                    crate::log::console_trace("VAULT_PASSWD_ERROR", &format!("Error changing password after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }''',

    # Vault Encrypt
    r'log::info\(&format!\("vault-encrypt id=\{\}", id\)\);\n\s*match vault::vault_encrypt\(id, &pass\) \{\n\s*Ok\(_\) => println!\("\{\}", "✔ Arquivos criptografados \(AES-256\)\."\.green\(\)\),\n\s*Err\(e\) => \{\n\s*log::error\(&format!\("vault-encrypt: \{\}", e\)\);\n\s*eprintln!\("\{\}", format!\("✖ Erro: \{\}", e\)\.red\(\)\);\n\s*\}\n\s*\}':
    '''let start_time = Instant::now();
            crate::log::console_trace("VAULT_ENCRYPT_INIT", &format!("Encrypting files in vault id={} (AES-256)", id));
            match vault::vault_encrypt(id, &pass) {
                Ok(_) => {
                    crate::log::console_trace("VAULT_ENCRYPT_DONE", &format!("Files encrypted in {:.2?}", start_time.elapsed()));
                    println!("{}", "✔ Arquivos criptografados (AES-256).".green());
                },
                Err(e) => {
                    crate::log::console_trace("VAULT_ENCRYPT_ERROR", &format!("Error encrypting vault after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }''',

    # Vault Decrypt
    r'log::info\(&format!\("vault-decrypt id=\{\}", id\)\);\n\s*match vault::vault_decrypt\(id, &pass\) \{\n\s*Ok\(_\) => println!\("\{\}", "✔ Arquivos descriptografados\."\.green\(\)\),\n\s*Err\(e\) => \{\n\s*log::error\(&format!\("vault-decrypt: \{\}", e\)\);\n\s*eprintln!\("\{\}", format!\("✖ Erro: \{\}", e\)\.red\(\)\);\n\s*\}\n\s*\}':
    '''let start_time = Instant::now();
            crate::log::console_trace("VAULT_DECRYPT_INIT", &format!("Decrypting files in vault id={}", id));
            match vault::vault_decrypt(id, &pass) {
                Ok(_) => {
                    crate::log::console_trace("VAULT_DECRYPT_DONE", &format!("Files decrypted in {:.2?}", start_time.elapsed()));
                    println!("{}", "✔ Arquivos descriptografados.".green());
                },
                Err(e) => {
                    crate::log::console_trace("VAULT_DECRYPT_ERROR", &format!("Error decrypting vault after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }''',

    # Vault Resolve
    r'log::info\(&format!\("vault-resolve id=\{\}", id\)\);\n\s*match vault::vault_resolve\(id, pass\.as_deref\(\)\) \{\n\s*Ok\(_\) => println!\("\{\}", "✔ Alert resolved\."\.green\(\)\),\n\s*Err\(e\) => \{\n\s*log::error\(&format!\("vault-resolve: \{\}", e\)\);\n\s*eprintln!\("\{\}", format!\("✖ Erro: \{\}", e\)\.red\(\)\);\n\s*\}\n\s*\}':
    '''let start_time = Instant::now();
            crate::log::console_trace("VAULT_RESOLVE_INIT", &format!("Resolving alert for vault id={}", id));
            match vault::vault_resolve(id, pass.as_deref()) {
                Ok(_) => {
                    crate::log::console_trace("VAULT_RESOLVE_DONE", &format!("Alert resolved in {:.2?}", start_time.elapsed()));
                    println!("{}", "✔ Alert resolved.".green());
                },
                Err(e) => {
                    crate::log::console_trace("VAULT_RESOLVE_ERROR", &format!("Error resolving alert after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Erro: {}", e).red());
                }
            }''',

    # Vault Info
    r'log::info\(&format!\("vault-info id=\{\}", id\)\);\n\s*vault::vault_info\(id\);':
    '''let start_time = Instant::now();
            crate::log::console_trace("VAULT_INFO_INIT", &format!("Getting info for vault id={}", id));
            vault::vault_info(id);
            crate::log::console_trace("VAULT_INFO_DONE", &format!("Vault info retrieved in {:.2?}", start_time.elapsed()));''',

    # Vault Files
    r'log::info\(&format!\("vault-files id=\{\}", id\)\);\n\s*vault::vault_files\(id\);':
    '''let start_time = Instant::now();
            crate::log::console_trace("VAULT_FILES_INIT", &format!("Getting files for vault id={}", id));
            vault::vault_files(id);
            crate::log::console_trace("VAULT_FILES_DONE", &format!("Vault files retrieved in {:.2?}", start_time.elapsed()));''',

    # Mount FUSE
    r'log::info\(&format!\("mount-fuse id=\{\}", id\)\);\n\s*match vault::vault_mount\(id, &password\) \{\n\s*Ok\(\(\)\) => println!\(\n\s*\"\{\}",\n\s*format!\("✔ Cofre \{\} montado via FUSE\.", id\)\.green\(\)\n\s*\),\n\s*Err\(e\) => \{\n\s*log::error\(&format!\("mount-fuse: \{\}", e\)\);\n\s*eprintln!\("\{\}", format!\("✖ Erro ao montar: \{\}", e\)\.red\(\)\);\n\s*\}\n\s*\}':
    '''let start_time = Instant::now();
            crate::log::console_trace("MOUNT_FUSE_INIT", &format!("Mounting vault {} via FUSE", id));
            match vault::vault_mount(id, &password) {
                Ok(()) => {
                    crate::log::console_trace("MOUNT_FUSE_DONE", &format!("Vault mounted successfully in {:.2?}", start_time.elapsed()));
                    println!("{}", format!("✔ Cofre {} montado via FUSE.", id).green());
                },
                Err(e) => {
                    crate::log::console_trace("MOUNT_FUSE_ERROR", &format!("Error mounting vault after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Erro ao montar: {}", e).red());
                }
            }''',

    # Unmount FUSE
    r'log::info\(&format!\("umont-fuse id=\{\}", id\)\);\n\s*match vault::vault_unmount\(id\) \{\n\s*Ok\(\(\)\) => println!\(\n\s*\"\{\}",\n\s*format!\("✔ Cofre \{\} desmontado do FUSE\.", id\)\.green\(\)\n\s*\),\n\s*Err\(e\) => \{\n\s*log::error\(&format!\("umont-fuse: \{\}", e\)\);\n\s*eprintln!\("\{\}", format!\("✖ Erro ao desmontar: \{\}", e\)\.red\(\)\);\n\s*\}\n\s*\}':
    '''let start_time = Instant::now();
            crate::log::console_trace("UMOUNT_FUSE_INIT", &format!("Unmounting vault {} from FUSE", id));
            match vault::vault_unmount(id) {
                Ok(()) => {
                    crate::log::console_trace("UMOUNT_FUSE_DONE", &format!("Vault unmounted successfully in {:.2?}", start_time.elapsed()));
                    println!("{}", format!("✔ Cofre {} desmontado do FUSE.", id).green());
                },
                Err(e) => {
                    crate::log::console_trace("UMOUNT_FUSE_ERROR", &format!("Error unmounting vault after {:.2?}: {}", start_time.elapsed(), e));
                    eprintln!("{}", format!("✖ Erro ao desmontar: {}", e).red());
                }
            }''',
}

for old, new in replacements.items():
    content = re.sub(old, new, content, flags=re.DOTALL)

with open("src/main.rs", "w") as f:
    f.write(content)

