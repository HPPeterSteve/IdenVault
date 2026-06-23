with open("src/main.rs", "r", encoding="utf-8") as f:
    code = f.read()

# remove bad first_run
code = code.replace("    let mut first_run = true;\n    loop {", "    loop {")

# find the REPL loop which is after ctrlc::set_handler
ctrlc_idx = code.find("ctrlc::set_handler(|| {")
loop_idx = code.find("    loop {", ctrlc_idx)

code = code[:loop_idx] + "    let mut first_run = true;\n" + code[loop_idx:]

with open("src/main.rs", "w", encoding="utf-8") as f:
    f.write(code)

