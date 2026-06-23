with open("src/main.rs", "r") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "loop {" in line and i > 2000:
        print("".join(lines[i:i+30]))
        break
