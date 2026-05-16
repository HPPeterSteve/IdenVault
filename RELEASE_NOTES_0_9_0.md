# IdenVault v0.9.0 — Inotify Precision & Anti-Ransomware Fix

Data: 2026-05-16

A versão **0.9.0** resolve definitivamente o problema crítico de **falsos positivos do monitor inotify** que classificava operações legítimas do próprio VaranusCore como tentativas de ransomware. Esta release representa um marco na maturidade do subsistema de monitoramento.

---

## 🔴 Correções Críticas

### 1. IN_DELETE sem verificação de autorização
O handler de `IN_DELETE` / `IN_MOVED_FROM` no monitor inotify **nunca verificava** se a operação era interna. Resultado: todo `vault-encrypt` e `vault-decrypt` disparava alertas de "File deleted/moved" ao remover os originais após criptografia.

**Correção:** O handler agora consulta `self_authorized` antes de disparar alerta, da mesma forma que IN_MODIFY.

### 2. Race condition: write_mode vs. eventos enfileirados
O kernel enfileira eventos inotify no instante da syscall (`write`, `unlink`), mas o monitor thread só os processa depois que o mutex é liberado — quando `write_mode` já retornou a `false`.

**Correção:** Implementado sistema de **duas camadas de autorização**:
- **`authorized_ops`** (contador atômico) — marca operações em andamento
- **`authorized_op_end`** (timestamp) — grace period de 3 segundos para eventos enfileirados

### 3. Funções Rust sem sinalização ao monitor
As funções `add_file`, `remove_file` e `secure_store` (implementadas em Rust puro) escreviam diretamente no diretório do cofre via `fs::copy` / `fs::remove_file` sem avisar o core C. O monitor tratava essas escritas como ataques externos.

**Correção:** Novo par de funções FFI `vault_authorize_path_ffi` / `vault_deauthorize_path_ffi` permite que o Rust sinalize operações autorizadas por caminho.

---

## 🛡️ Melhorias de Segurança

### Re-scan pós-operação
As funções `vault_encrypt_ffi` e `vault_decrypt_ffi` agora executam `monitor_scan_vault()` antes de liberar o mutex, garantindo que os hashes SHA-256 na hashmap reflitam o estado pós-operação. Isso elimina falsos positivos de "File MODIFIED" causados por hashes desatualizados.

### Cleanup em caminhos de erro
Todos os early-return paths em encrypt/decrypt agora fazem cleanup correto: decrementam `authorized_ops`, setam `authorized_op_end`, e restauram `write_mode = false`. Sem isso, um erro durante encrypt deixaria `authorized_ops > 0` permanentemente, desativando a proteção anti-ransomware.

---

## 📋 Arquivos Modificados

| Arquivo | Mudança |
|---|---|
| `c_src/vault_core.h` | +2 campos no Vault struct (`authorized_ops`, `authorized_op_end`), +4 declarações FFI |
| `c_src/vault_monitor.c` | Handler de eventos reescrito com `self_authorized` (3 critérios combinados) |
| `c_src/vault_ffi.c` | `authorized_ops` em encrypt/decrypt, +4 funções (`begin/end_authorized_op`, `authorize/deauthorize_path`) |
| `src/vault.rs` | FFI bindings para authorized ops, wrappers em `add_file`, `remove_file`, `secure_store` |
| `src/main.rs` | Versão atualizada no help banner |
| `Cargo.toml` | Bump `0.8.15` → `0.9.0` |

---

## 🔧 Novas APIs FFI

```c
// Por ID — para operações C internas
void vault_begin_authorized_op_ffi(uint32_t id);
void vault_end_authorized_op_ffi(uint32_t id);

// Por path — para funções Rust que operam por caminho
void vault_authorize_path_ffi(const char *path);
void vault_deauthorize_path_ffi(const char *path);
```

---

## ⬆️ Upgrade

A atualização é **fortemente recomendada** para todos os ambientes Linux. Sem ela, qualquer operação de encrypt/decrypt/add-file continuará gerando alertas falsos que poluem os logs de auditoria e podem mascarar ataques reais.

Nenhuma dependência nova foi adicionada. O build segue idêntico:
```bash
cargo build --release
```

---

*IdenVault: Precisão cirúrgica na detecção, zero tolerância a ameaças reais.*
