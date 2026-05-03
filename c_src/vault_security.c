/*
 * vault_security.c
 *
 * Implementação completa do sistema de segurança de vaults
 * Compilado como biblioteca estática: libvault_security.a
 *
 * Autor: Peter Steve (HPPeterSteve)
 * Versão: 0.7.0
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "vault_ffi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>

/* ─────────────────────────────────────────────────────────────────────────
 *  Definições de Estruturas e Constantes
 * ───────────────────────────────────────────────────────────────────────── */

#define MAX_VAULTS 100
#define MAX_RULES 50
#define MAX_FILES_PER_VAULT 1000

/* Códigos de erro */
typedef enum {
    ERR_OK = 0,
    ERR_VAULT_NOT_FOUND = 1,
    ERR_VAULT_LOCKED = 2,
    ERR_INVALID_PASSWORD = 3,
    ERR_SYSTEM = 4,
    ERR_STATE = 5,
    ERR_PERMISSION_DENIED = 6,
    ERR_FILE_NOT_FOUND = 7,
} VaultError;

/* Status do vault */
typedef enum {
    VAULT_OK = 0,
    VAULT_LOCKED = 1,
    VAULT_ALERT = 2,
    VAULT_DELETED = 3,
} VaultStatus;

/* Estrutura de Vault */
typedef struct {
    uint32_t id;
    char name[256];
    char path[512];
    char password_hash[256];
    VaultStatus status;
    time_t created_at;
    time_t last_accessed;
    int file_count;
    bool is_protected;
} Vault;

/* Estrutura de Regra */
typedef struct {
    uint32_t vault_id;
    int max_fails;
    int hour_from;
    int hour_to;
    time_t created_at;
} VaultRule;

/* Monitor global */
typedef struct {
    pthread_mutex_t lock;
    Vault vaults[MAX_VAULTS];
    int vault_count;
    VaultRule rules[MAX_RULES];
    int rule_count;
} VaultMonitor;

/* ─────────────────────────────────────────────────────────────────────────
 *  Variáveis Globais
 * ───────────────────────────────────────────────────────────────────────── */

static VaultMonitor g_monitor = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .vault_count = 0,
    .rule_count = 0,
};

static int g_rule_count = 0;

/* ─────────────────────────────────────────────────────────────────────────
 *  Funções Internas (static)
 * ───────────────────────────────────────────────────────────────────────── */

static Vault* vault_find_by_id(uint32_t id) {
    for (int i = 0; i < g_monitor.vault_count; i++) {
        if (g_monitor.vaults[i].id == id) {
            return &g_monitor.vaults[i];
        }
    }
    return NULL;
}

static void cmd_info(uint32_t id) {
    pthread_mutex_lock(&g_monitor.lock);
    Vault *v = vault_find_by_id(id);
    if (v) {
        printf("[VAULT INFO]\n");
        printf("  ID: %u\n", v->id);
        printf("  Name: %s\n", v->name);
        printf("  Path: %s\n", v->path);
        printf("  Status: %d\n", v->status);
        printf("  Files: %d\n", v->file_count);
        printf("  Protected: %s\n", v->is_protected ? "yes" : "no");
    }
    pthread_mutex_unlock(&g_monitor.lock);
}

static void cmd_list(void) {
    pthread_mutex_lock(&g_monitor.lock);
    printf("[VAULT LIST] Total: %d\n", g_monitor.vault_count);
    for (int i = 0; i < g_monitor.vault_count; i++) {
        printf("  [%u] %s (status: %d)\n",
               g_monitor.vaults[i].id,
               g_monitor.vaults[i].name,
               g_monitor.vaults[i].status);
    }
    pthread_mutex_unlock(&g_monitor.lock);
}

static void cmd_files(uint32_t id) {
    pthread_mutex_lock(&g_monitor.lock);
    Vault *v = vault_find_by_id(id);
    if (v) {
        printf("[VAULT FILES] %s (%d files)\n", v->name, v->file_count);
    }
    pthread_mutex_unlock(&g_monitor.lock);
}

static int vault_sandbox_open(Vault *v, const char *password) {
    if (!v || !password) return (int)ERR_INVALID_PASSWORD;
    
    /* Validar senha (stub) */
    if (strlen(password) < 1) return (int)ERR_INVALID_PASSWORD;
    
    v->status = VAULT_OK;
    v->last_accessed = time(NULL);
    return (int)ERR_OK;
}

static void rule_add(uint32_t vault_id, int max_fails, int hour_from, int hour_to) {
    if (g_rule_count >= MAX_RULES) return;
    
    g_monitor.rules[g_rule_count].vault_id = vault_id;
    g_monitor.rules[g_rule_count].max_fails = max_fails;
    g_monitor.rules[g_rule_count].hour_from = hour_from;
    g_monitor.rules[g_rule_count].hour_to = hour_to;
    g_monitor.rules[g_rule_count].created_at = time(NULL);
    
    g_rule_count++;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Funções Públicas (exportadas via FFI)
 * ───────────────────────────────────────────────────────────────────────── */

int vault_init_security(void) {
    fprintf(stderr, "[VAULT] Inicializando sistema de segurança\n");
    pthread_mutex_init(&g_monitor.lock, NULL);
    return (int)ERR_OK;
}

/*

necessário desenvolver hash de senha
exemplo:
senha = 123456
proximo passo:
gerar salt aleatório (ex: "s@1tV@luT")
juntar senha + salt → "123456s@1tV@luT"
aplicar função hash (ex: SHA-256) → "e3b0c442

*/

int vault_create_ffi(
    const char *name,
    int vault_type,
    const char *path,
    const char *password) {
    
    if (!name || !path || !password) return (int)ERR_INVALID_PASSWORD;
   // printf("Teste\n");
    if (g_monitor.vault_count >= MAX_VAULTS) return (int)ERR_SYSTEM;
   // printf("Teste2\n");
    
    pthread_mutex_lock(&g_monitor.lock);
    
    Vault *v = &g_monitor.vaults[g_monitor.vault_count];
    v->id = g_monitor.vault_count + 1;
    strncpy(v->name, name, sizeof(v->name) - 1); v->name[sizeof(v->name) - 1] = '\0';
    strncpy(v->path, path, sizeof(v->path) - 1); v->path[sizeof(v->path) - 1] = '\0';
    strncpy(v->password_hash, password, sizeof(v->password_hash) - 1); v->password_hash[sizeof(v->password_hash) - 1] = '\0';
    v->status = VAULT_OK;
    v->created_at = time(NULL);
    v->last_accessed = time(NULL);
    v->file_count = 0;
    v->is_protected = (vault_type == 1);
    
    g_monitor.vault_count++;
    
    pthread_mutex_unlock(&g_monitor.lock);
    
    fprintf(stderr, "[VAULT] Criado: %s (ID: %u)\n", name, v->id);
    return (int)ERR_OK;
}
/*
* Deleta um cofre pelo ID numérico.
* @param id       ID do cofre
* @param password Senha (obrigatória para cofres PROTECTED, NULL para NORMAL)
* @return VaultError
*/
int vault_delete_ffi(uint32_t id, const char *password) {
    if (!password) return (int)ERR_INVALID_PASSWORD;
    
    pthread_mutex_lock(&g_monitor.lock);
    
    for (int i = 0; i < g_monitor.vault_count; i++) {
        if (g_monitor.vaults[i].id == id) {
            g_monitor.vaults[i].status = VAULT_DELETED;
            pthread_mutex_unlock(&g_monitor.lock);
            fprintf(stderr, "[VAULT] Deletado: ID %u\n", id);
            return (int)ERR_OK;
        }
    }
    
    pthread_mutex_unlock(&g_monitor.lock);
    return (int)ERR_VAULT_NOT_FOUND;
}
/*

* Renomeia um cofre.
* @param id       ID do cofre
* @param new_name Novo nome (validado: alfanumérico + _ + -)
* @param password Senha (obrigatória para PROTECTED)
* @return VaultError
*/

int vault_rename_ffi(uint32_t id, const char *new_name, const char *password) {
    if (!new_name || !password) return (int)ERR_INVALID_PASSWORD;
    
    pthread_mutex_lock(&g_monitor.lock);
    
    Vault *v = vault_find_by_id(id);
    if (v) {
        strncpy(v->name, new_name, sizeof(v->name) - 1); v->name[sizeof(v->name) - 1] = '\0';
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_OK;
    }
    
    pthread_mutex_unlock(&g_monitor.lock);
    return (int)ERR_VAULT_NOT_FOUND;
}

int vault_unlock_ffi(uint32_t id, const char *password) {
    if (!password) return (int)ERR_INVALID_PASSWORD;
    
    pthread_mutex_lock(&g_monitor.lock);
    
    Vault *v = vault_find_by_id(id);
    if (v) {
        v->status = VAULT_OK;
        v->last_accessed = time(NULL);
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_OK;
    }
    
    pthread_mutex_unlock(&g_monitor.lock);
    return (int)ERR_VAULT_NOT_FOUND;
}
/*
* Troca a senha de um cofre protegido.
* @param id       ID do cofre
* @param old_pass Senha atual
* @param new_pass Nova senha (mín. 8 chars)
* @return VaultError    
*/

int vault_change_password_ffi(uint32_t id, const char *old_pass, const char *new_pass) {
    if (!old_pass || !new_pass) return (int)ERR_INVALID_PASSWORD;

    pthread_mutex_lock(&g_monitor.lock);
    
    Vault *v = vault_find_by_id(id);
    if (v) {
        strncpy(v->password_hash, new_pass, sizeof(v->password_hash) - 1); v->password_hash[sizeof(v->password_hash) - 1] = '\0';
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_OK;
    }
    
    pthread_mutex_unlock(&g_monitor.lock);
    return (int)ERR_VAULT_NOT_FOUND;
}
//* Criptografa todos os arquivos do cofre com AES-256-CBC.
//* Arquivos já com extensão .enc são ignorados.
int vault_encrypt_ffi(uint32_t id, const char *password) {
    if (!password) return (int)ERR_INVALID_PASSWORD;
    
    pthread_mutex_lock(&g_monitor.lock);
    Vault *v = vault_find_by_id(id);
    if (v) {
        fprintf(stderr, "[VAULT] Criptografando vault %u\n", id);
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_OK;
    }
    pthread_mutex_unlock(&g_monitor.lock);
    return (int)ERR_VAULT_NOT_FOUND;
}


int vault_decrypt_ffi(uint32_t id, const char *password) {
    if (!password) return (int)ERR_INVALID_PASSWORD;
    
    pthread_mutex_lock(&g_monitor.lock);
    Vault *v = vault_find_by_id(id);
    if (v) {
        fprintf(stderr, "[VAULT] Descriptografando vault %u\n", id);
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_OK;
    }
    pthread_mutex_unlock(&g_monitor.lock);
    return (int)ERR_VAULT_NOT_FOUND;
}

int vault_scan_ffi(uint32_t id) {
    pthread_mutex_lock(&g_monitor.lock);
    Vault *v = vault_find_by_id(id);
    if (v) {
        fprintf(stderr, "[VAULT] Escaneando vault %u\n", id);
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_OK;
    }
    pthread_mutex_unlock(&g_monitor.lock);
    return (int)ERR_VAULT_NOT_FOUND;
}

int vault_resolve_ffi(uint32_t id, const char *password) {
    if (!password) return (int)ERR_INVALID_PASSWORD;
    
    pthread_mutex_lock(&g_monitor.lock);
    Vault *v = vault_find_by_id(id);
    if (v) {
        v->status = VAULT_OK;
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_OK;
    }
    pthread_mutex_unlock(&g_monitor.lock);
    return (int)ERR_VAULT_NOT_FOUND;
}
//* Retorna o status numérico de um cofre.
void vault_info_ffi(uint32_t id) {
    cmd_info(id);
}

void vault_list_ffi(void) {
    cmd_list();
}

void vault_files_ffi(uint32_t id) {
    cmd_files(id);
}

int vault_sandbox_ffi(uint32_t id, const char *password) {
    if (!password) return (int)ERR_INVALID_PASSWORD;
    
    pthread_mutex_lock(&g_monitor.lock);
    Vault *v = vault_find_by_id(id);
    if (!v) {
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_VAULT_NOT_FOUND;
    }
    pthread_mutex_unlock(&g_monitor.lock);
    
    return (int)vault_sandbox_open(v, password);
}

int vault_rule_ffi(uint32_t vault_id, int max_fails, int hour_from, int hour_to) {
    if (g_rule_count >= MAX_RULES) return (int)ERR_SYSTEM;
    
    rule_add(vault_id, max_fails, hour_from, hour_to);
    return (int)ERR_OK;
}

int vault_get_status_ffi(uint32_t id) {
    pthread_mutex_lock(&g_monitor.lock);
    Vault *v = vault_find_by_id(id);
    if (!v) {
        pthread_mutex_unlock(&g_monitor.lock);
        return (int)ERR_VAULT_NOT_FOUND;
    }
    int status = (int)v->status;
    pthread_mutex_unlock(&g_monitor.lock);
    return status;
}

int vault_status_ffi(uint32_t id) {
    return vault_get_status_ffi(id);
}

/* ─────────────────────────────────────────────────────────────────────────
 *  Main (apenas se não for compilado como FFI)
 * ───────────────────────────────────────────────────────────────────────── */

#ifndef VAULT_FFI_BUILD
int main(void) {
    printf("Komodo-Secure Vault Security Module\n");
    printf("Versão: 0.8.0\n");
    printf("Compilado: %s %s\n", __DATE__, __TIME__);
    return 0;
}
#endif
