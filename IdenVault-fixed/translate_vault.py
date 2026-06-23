import re

with open("src/vault.rs", "r", encoding="utf-8") as f:
    code = f.read()

replacements = {
    "Monta cofre via FUSE.": "Mounts vault via FUSE.",
    "Desmonta cofre via FUSE.": "Unmounts vault via FUSE.",
    "Retorna a máscara de bits atual (worm_flags).": "Returns current bitmask (worm_flags).",
    "Aplica novas regras e retorna o novo estado.": "Applies new rules and returns new state."
}

for pt, en in replacements.items():
    code = code.replace(pt, en)

with open("src/vault.rs", "w", encoding="utf-8") as f:
    f.write(code)

with open("src/crypto.rs", "r", encoding="utf-8") as f:
    code = f.read()

replacements = {
    "Deriva uma chave AES-256 a partir de uma senha e salt usando Argon2": "Derives an AES-256 key from password and salt using Argon2",
    "Erro na criptografia:": "Encryption error:",
    "Erro: Arquivo corrompido ou muito pequeno.": "Error: File corrupted or too small.",
    "Erro na descriptografia:": "Decryption error:",
    "Deriva a chave mestre combinando senha + USB key": "Derives master key combining password + USB key"
}

for pt, en in replacements.items():
    code = code.replace(pt, en)

with open("src/crypto.rs", "w", encoding="utf-8") as f:
    f.write(code)

