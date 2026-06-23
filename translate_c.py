import os

replacements = {
    # vault_engine.c
    "VALIDADO com sucesso": "SUCCESSFULLY VALIDATED",
    "camadas OK": "layers OK",
    "Camada criada com sucesso — log de progresso": "Layer created successfully - progress log",
    "Logs em cada etapa (início, progresso, sucesso, erro)": "Logs at each stage (start, progress, success, error)",
    "Retorna ERR_OK se já existir ou se criou com sucesso.": "Returns ERR_OK if already exists or created successfully.",
    # vault_ffi.c
    "Chamado pelo Rust logo após vault_create_ffi() com sucesso.": "Called by Rust immediately after successful vault_create_ffi().",
    "Retorna VaultError (0 = OK).": "Returns VaultError (0 = OK).",
    "Persiste engine_level no catálogo": "Persists engine_level in the catalog",
    # General logging
    "Erro": "Error",
    "Aviso": "Warning",
    "Falha": "Failure",
    "sucesso": "success",
    "catálogo": "catalog",
    "cofre": "vault",
    "permissão": "permission"
}

c_files = [os.path.join("c_src", f) for f in os.listdir("c_src") if f.endswith(('.c', '.h'))]

for filepath in c_files:
    with open(filepath, "r", encoding="utf-8") as f:
        code = f.read()
    
    modified = False
    for pt, en in replacements.items():
        if pt in code:
            code = code.replace(pt, en)
            modified = True
            
    if modified:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(code)

