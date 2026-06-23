

<img width="1004" height="428" alt="image" src="https://github.com/user-attachments/assets/5c0c4f5b-9075-4aca-afdc-5a777f5ceb85" />


# **IdenVault** is a hardened digital vault engine environment, built natively for Linux.

Written in **C** (security core) and **Rust** (CLI layer), it provides cryptographic file protection and kernel-level process sandboxing — extracting the full isolation capability of the Linux kernel rather than relying on userspace abstractions.

> Beta. Tested on Linux 5.15+. Contributions and pentest reports welcome.

---

## Architecture

The project operates on two independent subsystems:

**Vault subsystem** — encrypted directories protected with AES-256-GCM, key derivation via PBKDF2-HMAC-SHA256 (310,000 iterations, OWASP 2023), real-time integrity monitoring via fanotify, binary catalog with HMAC-SHA256 tamper detection, and a rate-limited authentication engine with exponential backoff alerting.

**Sandbox subsystem** — five independent isolation layers where each layer assumes the previous one has been compromised:

```
Layer 1  User Namespace      — sandbox root maps to nobody (UID 65534) on host
Layer 2  Mount + PID NS      — isolated process tree and filesystem view
Layer 3  Pivot Root          — replaces chroot; old root unmounted with MNT_DETACH
Layer 4  Capability Drop     — all Linux capabilities removed + PR_SET_NO_NEW_PRIVS
Layer 5  Seccomp-BPF         — syscall allowlist, SCMP_ACT_KILL_PROCESS as default
```

---

## Security Properties

| Property | Implementation |
|---|---|
| Encryption | AES-256-GCM (authenticated) |
| Key derivation | PBKDF2-HMAC-SHA256, 310 000 iterations |
| Password verification | CRYPTO_memcmp (constant-time) |
| Catalog integrity | HMAC-SHA256 over full payload |
| File integrity | SHA-256 per file, inotify-triggered rescan |
| Sandbox escape prevention | UserNS + PivotRoot + Caps + Seccomp-BPF |
| Memory hygiene | explicit_bzero on all key/password buffers |
| Auth lockout | Configurable max attempts + exponential alert backoff |

---

## Build

Dependencies:

```bash
sudo apt install libssl-dev libseccomp-dev libcap-dev
```

```bash
cargo build --release
./target/release/VaranusCore
```

The build script compiles the C core (`diamondVaults.c`) and links it into the Rust binary via FFI.

---

## Usage

### Vault operations

```
vault-create <name> <path> <type>     Create a vault (type: normal | protected)
vault-encrypt <id>                    Encrypt all files in vault (AES-256-GCM)
vault-decrypt <id>                    Decrypt vault files
vault-scan <id>                       Force integrity scan
vault-resolve <id>                    Resolve active alert
vault-info <id>                       Show vault details
vault-files <id>                      List tracked files and hash status
vault-rule <id> <max_fails> [h h]     Add security rule (lockout + time window)
vault-passwd <id>                     Change vault password
vault-unlock <id>                     Unlock after failed-attempt lockout
vault-delete <id>                     Delete vault
```

```bash
# Create a protected vault
vault-create secrets /home/user/vaults/secrets protected

# Move and encrypt a file into it
secure-copy /home/user/docs/private.pdf /home/user/vaults/secrets

# Encrypt everything inside
vault-encrypt 1

# Open vault in hardened sandbox shell
vault-sandbox 1
```

### Sandbox

```
vault-sandbox <id>     Open vault directory in isolated shell (5-layer sandbox)
run-in-sandbox <dir>   Run directory in sandbox
isolate-directory <dir> Apply isolation policies to directory
```

### Key derivation

```
derive-master-key      Derive master key from password + USB hardware key (hex)
```

---

## FFI Interface

The C security core exposes a stable FFI interface consumed by the Rust CLI layer via `build.rs`. The interface is designed to be callable from any language with C FFI support — C++, Python (ctypes), Go (cgo).

See `c_src/` for the C API and `src/vault.rs` for the Rust bindings.

---

## Security Documents

| Document | Description |
|---|---|
| `SECURITY_AUDIT_SUMMARY.md` | Full audit: 9 vulnerabilities identified and fixed |
| `VULNERABILITIES.md` | Detailed vulnerability breakdown by severity |
| `REMEDIATION_CHECKLIST.md` | Fix status per finding |
| `SECURITY_REVIEW.md` | Architecture security review |

---

## Status

- C core: feature-complete, hardened
- Rust CLI: feature-complete
- Module split (single-file → multi-file): in progress
- Windows support: not planned
- Pentest: in progress (external)

---

## License

MPL2.0 — see `LICENSE`.

# IdenVault

**IdenVault** é um motor de cofre digital reforçado, construído nativamente para Linux.

Escrito em **C** (núcleo de segurança) e **Rust** (camada CLI), oferece proteção criptográfica de arquivos e sandboxing de processos em nível de kernel — extraindo toda a capacidade de isolamento do kernel Linux em vez de depender de abstrações no espaço do usuário.

> Beta. Testado no Linux 5.15+. Contribuições e relatórios de pentest são bem-vindos.

---

## Arquitetura

O projeto opera em dois subsistemas independentes:

**Subsistema de cofre** — diretórios criptografados protegidos com AES-256-GCM, derivação de chaves via PBKDF2-HMAC-SHA256 (310.000 iterações, OWASP 2023), monitoramento de integridade em tempo real via fanotify, catálogo binário com detecção de adulteração por HMAC-SHA256 e motor de autenticação com limitação de taxa e backoff exponencial com alertas.

**Subsistema de sandbox** — cinco camadas de isolamento independentes, onde cada camada assume que a anterior foi comprometida:

```
Camada 1  User Namespace      — root do sandbox mapeado para nobody (UID 65534) no host
Camada 2  Mount + PID NS      — árvore de processos e visão do sistema de arquivos isolados
Camada 3  Pivot Root          — substitui o chroot; root antigo desmontado com MNT_DETACH
Camada 4  Remoção de Caps     — todas as capabilities Linux removidas + PR_SET_NO_NEW_PRIVS
Camada 5  Seccomp-BPF         — lista de syscalls permitidas, SCMP_ACT_KILL_PROCESS como padrão
```

---

## Propriedades de Segurança

| Propriedade | Implementação |
|---|---|
| Criptografia | AES-256-GCM (autenticada) |
| Derivação de chaves | PBKDF2-HMAC-SHA256, 310.000 iterações |
| Verificação de senha | CRYPTO_memcmp (tempo constante) |
| Integridade do catálogo | HMAC-SHA256 sobre todo o payload |
| Integridade de arquivos | SHA-256 por arquivo, rescan disparado por inotify |
| Prevenção de escape de sandbox | UserNS + PivotRoot + Caps + Seccomp-BPF |
| Higiene de memória | explicit_bzero em todos os buffers de chave/senha |
| Bloqueio de autenticação | Máximo de tentativas configurável + backoff exponencial de alertas |

---

## Compilação

Dependências:

```bash
sudo apt install libssl-dev libseccomp-dev libcap-dev
```

```bash
cargo build --release
./target/release/VaranusCore
```

O script de build compila o núcleo C (`diamondVaults.c`) e o vincula ao binário Rust via FFI.

---

## Uso

### Operações de cofre

```
vault-create <nome> <caminho> <tipo>     Cria um cofre (tipo: normal | protected)
vault-encrypt <id>                       Criptografa todos os arquivos do cofre (AES-256-GCM)
vault-decrypt <id>                       Descriptografa os arquivos do cofre
vault-scan <id>                          Força uma varredura de integridade
vault-resolve <id>                       Resolve alerta ativo
vault-info <id>                          Exibe detalhes do cofre
vault-files <id>                         Lista arquivos rastreados e status de hash
vault-rule <id> <max_falhas> [h h]       Adiciona regra de segurança (bloqueio + janela de tempo)
vault-passwd <id>                        Altera a senha do cofre
vault-unlock <id>                        Desbloqueia após bloqueio por tentativas falhas
vault-delete <id>                        Remove o cofre
```

```bash
# Cria um cofre protegido
vault-create secrets /home/usuario/cofres/secrets protected

# Move e criptografa um arquivo para dentro dele
secure-copy /home/usuario/docs/privado.pdf /home/usuario/cofres/secrets

# Criptografa tudo dentro do cofre
vault-encrypt 1

# Abre o diretório do cofre em um shell de sandbox reforçado
vault-sandbox 1
```

### Sandbox

```
vault-sandbox <id>       Abre o diretório do cofre em um shell isolado (sandbox de 5 camadas)
run-in-sandbox <dir>     Executa um diretório no sandbox
isolate-directory <dir>  Aplica políticas de isolamento ao diretório
```

### Derivação de chaves

```
derive-master-key      Deriva a chave mestra a partir de senha + chave de hardware USB (hex)
```

---

## Interface FFI

O núcleo de segurança em C expõe uma interface FFI estável consumida pela camada CLI em Rust via `build.rs`. A interface foi projetada para ser chamada a partir de qualquer linguagem com suporte a FFI C — C++, Python (ctypes), Go (cgo).

Consulte `c_src/` para a API em C e `src/vault.rs` para os bindings em Rust.

---

## Documentos de Segurança

| Documento | Descrição |
|---|---|
| `SECURITY_AUDIT_SUMMARY.md` | Auditoria completa: 9 vulnerabilidades identificadas e corrigidas |
| `VULNERABILITIES.md` | Detalhamento das vulnerabilidades por severidade |
| `REMEDIATION_CHECKLIST.md` | Status de correção por achado |
| `SECURITY_REVIEW.md` | Revisão de segurança da arquitetura |

---

## Status

- Núcleo C: completo em funcionalidades, reforçado
- CLI Rust: completo em funcionalidades
- Divisão de módulos (arquivo único → múltiplos arquivos): em andamento
- Suporte a Windows: não planejado
- Pentest: em andamento (externo)

---

## Licença

MPL2.0 — consulte `LICENSE`.
