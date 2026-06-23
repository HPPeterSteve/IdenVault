import re

with open("src/path_assistant.rs", "r", encoding="utf-8") as f:
    code = f.read()

replacements = {
    "Erro ao acessar diretório pai": "Error accessing parent directory"
}

for pt, en in replacements.items():
    code = code.replace(pt, en)

with open("src/path_assistant.rs", "w", encoding="utf-8") as f:
    f.write(code)

