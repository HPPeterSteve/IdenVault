## 🔐 Security Features

### 🪟 Windows
- AppContainer Isolation  
- Restricted Tokens  
- DEP / ASLR  
- WFP Firewall  
- Win32k Blocking  
- Isolated Desktop  

### 🐧 Linux
- inotify Monitoring  
- Namespaces (PID, Mount, Network)  
- Seccomp Filtering  
- OpenSSL Cryptography  
- pthread Mutex Locking  

---

## 📦 FFI Bindings

O projeto expõe funções C para Rust via FFI:

### Vault Lifecycle
```c
int vault_create_ffi(const char *name, int vault_type, const char *path, const char *password);
int vault_delete_ffi(uint32_t id, const char *password);
int vault_rename_ffi(uint32_t id, const char *new_name, const char *password);
int vault_unlock_ffi(uint32_t id, const char *password);
int vault_change_password_ffi(uint32_t id, const char *old_pass, const char *new_pass);
Cryptography
c
int vault_encrypt_ffi(uint32_t id, const char *password);
int vault_decrypt_ffi(uint32_t id, const char *password);
Monitoring
c
int vault_scan_ffi(uint32_t id);
int vault_resolve_ffi(uint32_t id, const char *password);
Info
c
void vault_info_ffi(uint32_t id);
void vault_list_ffi();
void vault_files_ffi(uint32_t id);
Sandbox
c
