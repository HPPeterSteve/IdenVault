import re

with open("src/main.rs", "r") as f:
    content = f.read()

replacements = [
    ("Referência Rápida de Comandos", "Quick Command Reference"),
    ("Arquivo / Diretório", "File / Directory"),
    ("Sistema", "System"),
    ("Utilitários", "Utilities"),
    ("Cria cofre", "Creates vault"),
    ("remove arquivo do cofre", "removes file from vault"),
    ("lista arquivos de um diretório", "lists files in a directory"),
    ("isola diretório", "isolates directory"),
    ("mostra status resumido", "shows summary status"),
    ("lista todos os cofres do catálogo", "lists all vaults in the catalog"),
    ("deleta cofre pelo ID", "deletes vault by ID"),
    ("renomeia cofre", "renames vault"),
    ("desbloqueia cofre após lockout", "unlocks vault after lockout"),
    ("troca senha do cofre", "changes vault password"),
    ("criptografa arquivos", "encrypts files"),
    ("descriptografa arquivos", "decrypts files"),
    ("resolve alerta ativo", "resolves active alert"),
    ("exibe detalhes completos", "shows full details"),
    ("lista arquivos rastreados", "lists tracked files"),
    ("abre cofre em shell sandbox isolada", "opens vault in isolated sandbox shell"),
    ("adiciona regra de segurança ao cofre", "adds security rule to vault"),
    ("Montagem de Cofres", "Vault Mounting"),
    ("monta cofre", "mounts vault"),
    ("desmonta cofre", "unmounts vault"),
    ("resgata arquivos", "rescues files"),
    ("Proteção WORM", "WORM Protection"),
    ("configura proteção", "configures protection"),
    ("bloqueia exclusão", "blocks deletion"),
    ("bloqueia renomeação", "blocks renaming"),
    ("bloqueia sobrescrita", "blocks overwriting"),
    ("PROTEÇÃO MÁXIMA imutável (IRREVERSÍVEL)", "MAXIMUM PROTECTION immutable (IRREVERSIBLE)"),
    ("remove bloqueios", "removes locks"),
    ("exibe flags ativas do vault", "shows active flags of the vault"),
    ("info de CPU, memória, discos, redes", "CPU, memory, disks, networks info"),
    ("lista processos ativos do sistema", "lists active system processes"),
    ("deriva master key", "derives master key"),
    ("inicia API HTTP local", "starts local HTTP API"),
    ("para a API em execução", "stops running API"),
    ("exibe status da API", "shows API status"),
    ("manual de operação interativo", "interactive operation manual"),
    ("esta ajuda ou detalhes por comando", "this help or details by command"),
    ("encerra a aplicação", "closes the application"),
    ("Use 'help <comando>' para detalhes", "Use 'help <command>' for details"),
    ("Use 'help all' para a referência completa", "Use 'help all' for full reference"),
    ("Comando", "Command"),
    ("não encontrado na ajuda.", "not found in help."),
    ("Execute", "Run"),
    ("para a referência completa", "for the full reference"),
]

for old, new in replacements:
    content = content.replace(old, new)

with open("src/main.rs", "w") as f:
    f.write(content)

