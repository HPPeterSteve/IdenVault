with open("src/main.rs", "r", encoding="utf-8") as f:
    code = f.read()

funcs = """
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
        "vault-create", "vault-delete", "vault-rename", "vault-list",
        "vault-passwd", "vault-encrypt", "vault-decrypt", "vault-scan",
        "vault-resolve", "vault-info", "vault-files", "vault-sandbox",
        "mount-fuse", "umount-fuse", "worm-protect", "status"
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

"""

idx = code.find("fn prompt_password")
new_code = code[:idx] + funcs + code[idx:]

with open("src/main.rs", "w", encoding="utf-8") as f:
    f.write(new_code)

