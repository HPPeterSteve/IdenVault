import sys

with open("src/main.rs", "r", encoding="utf-8") as f:
    code = f.read()

# 1. Update interactive_menu to handle the new Advanced Creation Wizard
start_idx = code.find("fn interactive_menu() -> Option<String> {")
end_idx = code.find("fn parse_id(arg: Option<&&str>", start_idx)

new_menu = """fn interactive_menu() -> Option<String> {
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
            let base_cmd = format!("vault-create {} {} {}", name_arg, final_path, vtype_str);
            
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
                full_cmd = format!("{} && worm-protect LAST_CREATED_ID {}", full_cmd, prot_cmd);
            }
            if mount_now == "Yes" {
                full_cmd = format!("{} && mount-fuse LAST_CREATED_ID", full_cmd);
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
                    "Toggle WORM Protections",
                    "View Info / Status",
                    "Export / Rescue File",
                    "Delete Vault"
                ];
                let sub_choice = Select::new(&format!("Action for {}:", ans), sub_options).prompt();
                match sub_choice {
                    Ok("Mount FUSE") => Some(format!("mount-fuse {}", id_str)),
                    Ok("Unmount FUSE") => Some(format!("umount-fuse {}", id_str)),
                    Ok("Enter Sandbox Shell") => Some(format!("run-in-sandbox {}", id_str)),
                    Ok("View Info / Status") => Some(format!("status {}", id_str)),
                    Ok("Export / Rescue File") => Some(format!("vault-export {}", id_str)),
                    Ok("Delete Vault") => Some(format!("vault-delete {}", id_str)),
                    Ok("Toggle WORM Protections") => {
                        let flags = vec!["--no-write", "--protect-delete", "--protect-rename", "--protect-read"];
                        if let Ok(flag) = Select::new("Select Protection to Toggle:", flags).prompt() {
                            Some(format!("worm-protect {} {}", id_str, flag))
                        } else { None }
                    },
                    _ => None,
                }
            } else { None }
        }
        Err(_) => None,
    }
}

"""

code = code[:start_idx] + new_menu + code[end_idx:]

# 2. Update the main loop to handle `&&` chained commands and `LAST_CREATED_ID`
# Find handle_command execution inside the loop
repl_block_start = code.find("let parts: Vec<&str> = cmd_to_run.split_whitespace().collect();")
repl_block_end = code.find("}", repl_block_start) + 1

new_repl_block = """let commands: Vec<&str> = cmd_to_run.split(" && ").collect();
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
                }"""

code = code[:repl_block_start] + new_repl_block + code[repl_block_end:]

# 3. Change loop to ALWAYS run menu if input is empty, and simulate an empty input right away
# Actually, the user wants it to just run automatically.
# We will change the prompt to skip Rustyline entirely if they don't want it, 
# but for now, we just make it automatically trigger `interactive_menu()` at the very start of the loop
# by injecting `let mut first_run = true;` before the loop.

loop_idx = code.find("    loop {")
code = code[:loop_idx] + "    let mut first_run = true;\n" + code[loop_idx:]

match_read_idx = code.find("let readline = rl.readline(&prompt_str);")
new_readline = """let readline = if first_run {
            first_run = false;
            Ok("menu".to_string())
        } else {
            rl.readline(&prompt_str)
        };"""
code = code[:match_read_idx] + new_readline + code[match_read_idx + len("let readline = rl.readline(&prompt_str);"):]

with open("src/main.rs", "w", encoding="utf-8") as f:
    f.write(code)

