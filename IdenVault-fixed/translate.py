import re

with open("src/main.rs", "r") as f:
    content = f.read()

replacements = [
    ("IdenVault iniciado!  Sub-sistema de Assistência de Caminhos ATIVO.", "IdenVault started! Path Assistant subsystem ACTIVE."),
    ("todos os direitos reservados.", "All rights reserved."),
    ("Digite 'help'", "Type 'help'"),
    ("Aplicação iniciada.", "Application started."),
    ("Core C inicializado: catálogo carregado do disco.", "C Core initialized: catalog loaded from disk."),
    ("Falha ao inicializar core C", "Failed to initialize C core"),
    ("continuando sem persistência", "continuing without persistence"),
    ("Salvando catálogo e encerrando...", "Saving catalog and exiting..."),
    ("Catálogo salvo com sucesso.", "Catalog saved successfully."),
    ("Erro ao salvar catálogo", "Error saving catalog"),
    ("Erro ao salvar", "Error saving"),
    ("Aplicação encerrada pelo usuário.", "Application terminated by user."),
    ("Aplicação fechando", "Application closing"),
    ("Arquivo arrastado detectado", "Dragged file detected"),
    ("Cancelar", "Cancel"),
    ("Adicionar ao cofre?", "Add to vault?"),
    ("Nenhum cofre disponível para adicionar o arquivo.", "No vault available to add the file."),
    ("Selecione uma ação:", "Select an action:"),
    ("Criar Novo Cofre", "Create New Vault"),
    ("Listar Todos os Cofres", "List All Vaults"),
    ("Ver Info de um Cofre", "View Vault Info"),
    ("Listar Arquivos do Cofre", "List Vault Files"),
    ("Exportar / Resgatar Arquivo", "Export / Rescue File"),
    ("Desbloquear Cofre", "Unlock Vault"),
    ("Criptografar Cofre", "Encrypt Vault"),
    ("Descriptografar Cofre", "Decrypt Vault"),
    ("Mudar Senha", "Change Password"),
    ("Deletar Cofre", "Delete Vault"),
    ("Sair", "Exit"),
    ("Caminho para o novo cofre:", "Path for the new vault:"),
    ("Cofre criado com sucesso em", "Vault created successfully in"),
    ("✔ Cofre criado", "✔ Vault created"),
    ("✔ Varredura concluída.", "✔ Scan complete."),
    ("✖ Erro ao escanear cofre", "✖ Error scanning vault"),
    ("✔ Alerta resolvido.", "✔ Alert resolved."),
    ("Senha (Enter para pular):", "Password (Enter to skip):"),
    ("Nome do arquivo no cofre:", "File name in the vault:"),
    ("Arquivo de origem:", "Source file:"),
    ("Caminho do cofre:", "Vault path:"),
    ("✔ Arquivo protegido e armazenado no cofre", "✔ File protected and stored in vault"),
    ("Executando sandbox", "Executing sandbox"),
    ("Diretório para sandbox:", "Directory for sandbox:"),
    ("Forçando scan no cofre", "Forcing scan on vault"),
]

for old, new in replacements:
    content = content.replace(old, new)

with open("src/main.rs", "w") as f:
    f.write(content)

