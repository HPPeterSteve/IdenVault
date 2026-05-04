# 🦎 Komodo Core (VaranusCore)

**Komodo Core** (ou *VaranusCore*) é uma engine de cofre digital (digital vault) e ambiente de execução restrito, focada em segurança prática para sistemas operacionais. 

Construído com uma fundação robusta em **Rust** e um core de alta performance em **C**, o projeto não promete "segurança inquebrável por mágica". Em vez disso, ele fornece ferramentas maduras e utilitários para proteger seus arquivos sensíveis e isolar execuções perigosas, extraindo o melhor das APIs do kernel Linux.

## 🎯 O que o Komodo Core faz?

No mundo real, armazenar chaves de API, bancos de dados sensíveis ou rodar scripts de origens desconhecidas exige cautela. O Komodo Core resolve isso através de duas frentes práticas:

1. **Cofres Criptografados (Vaults):** Diretórios protegidos com criptografia padrão da indústria (AES-256-GCM + Argon2).
2. **Sandboxing Nativo (Linux):** Execução de processos isolados, impedindo que acessem o disco inteiro ou a rede sem permissão.

## 🛡️ Features de Segurança

Acreditamos em aproveitar os mecanismos do sistema operacional:

- **Isolamento de Processos (Sandboxing no Linux):** Utiliza *PID, Mount e Network Namespaces* para rodar processos em um ambiente onde eles não conseguem enxergar ou interagir com o resto do sistema.
- **Filtragem de Syscalls:** Restringe o que um processo isolado pode solicitar ao kernel através do *Seccomp*.
- **Monitoramento de Arquivos:** Usa *inotify* para rastrear em tempo real quem e o que está mexendo nos arquivos do cofre.
- **Criptografia Realista:** Criptografia e derivação de chaves usando OpenSSL/Rust Crypto. Protege os dados em repouso contra acesso físico ou exploração de diretórios.
- **Políticas de Acesso:** Permite configurar número máximo de tentativas de senha (lockout automático) e janelas de horário permitidas para desbloqueio (`vault-rule`).

## 🛠️ Como usar a Interface CLI

O Komodo Core funciona como um shell interativo contínuo (REPL). Para iniciar o console:

```bash
cargo run --release
```

Dentro do shell `VaranusCore>`, você pode digitar `help` ou usar diretamente os comandos:

### Gerenciamento Básico
- `vault-create <nome> <caminho> [normal|protected]`: Cria um novo cofre.
- `secure-copy <arquivo> <cofre>`: Copia e protege um arquivo enviando-o para dentro do cofre.
- `vault-encrypt <id>` / `vault-decrypt <id>`: Aplica ou remove a proteção criptográfica nos arquivos do cofre ativo.
- `vault-files <id>`: Lista todo o conteúdo e arquivos atualmente rastreados.

### Isolamento e Sandbox
- `run-in-sandbox <diretório>`: Executa os binários ou scripts de um diretório dentro do ambiente isolado.
- `isolate-directory <dir>`: Aplica travas no diretório para isolá-lo de leituras não autorizadas do restante do sistema.

### Controle de Segurança
- `vault-rule <id> <max_fails> [hora_inicio hora_fim]`: Configura limites de tentativas erradas e restringe em quais horas do dia o cofre pode ser aberto.
- `derive-master-key`: Gera uma chave mestre unindo uma senha e uma entrada física (como uma chave USB/Hex).

## ⚙️ Dependências e Compilação

Sendo um projeto que interage baixo-nível com o sistema, certifique-se de ter instalado:
- Toolchain do **Rust** (Cargo/rustc).
- Compilador **C** (GCC ou Clang) para o core FFI.
- **OpenSSL** (`libssl-dev` no Ubuntu/Debian ou `openssl-devel` no RHEL/Fedora).

Compile o projeto localmente com:
```bash
cargo build --release
```

## 🤝 Integração Externa (FFI C-Bindings)

O Komodo foi pensado para ser incorporado. Se você não quiser usar a CLI e sim integrar a engine a um servidor web ou script, ele expõe uma interface FFI (Foreign Function Interface) em C puro. 

Verifique no código as funções prefixadas com `vault_*_ffi` (ex: `vault_create_ffi`, `vault_encrypt_ffi`) para fazer chamadas diretas via Python (`ctypes`), Node.js ou C/C++.

---
**Nota Final:** Não existe bala de prata em segurança da informação. O Komodo Core mitiga diversos riscos usando boas práticas e namespaces nativos do Linux, mas a segurança final do seu ambiente também depende de senhas fortes, de um host atualizado e do bom gerenciamento das chaves.
