import re

with open("src/main.rs", "r", encoding="utf-8") as f:
    code = f.read()

# We need to replace the entire interactive_menu function.
start_idx = code.find("fn interactive_menu() -> Option<String> {")
end_idx = code.find("fn prompt_password", start_idx)

new_func = """fn interactive_menu() -> Option<String> {
    let vaults = vault::vault_get_all_paths_pub();
    let mut options = vec!["[+] Create New Vault".to_string()];
    for (id, path) in &vaults {
        options.push(format!("[Vault {}] {}", id, path));
    }
    options.push("Exit".to_string());

    let choice = Select::new("Select Vault or Action:", options).prompt();

    match choice {
        Ok(ans) if ans == "[+] Create New Vault" => Some("vault-create".to_string()),
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
                        } else {
                            None
                        }
                    },
                    _ => None,
                }
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

"""

new_code = code[:start_idx] + new_func + code[end_idx:]

with open("src/main.rs", "w", encoding="utf-8") as f:
    f.write(new_code)

