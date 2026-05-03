/*
 * vault_ffi.c (Simplificado)
 *
 * Wrappers FFI para vault_security.c
 * Compilado junto com vault_security.c como libvault_security.a
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "vault_ffi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Funções definidas em vault_security.c (linkadas automaticamente) */
extern int vault_init_security(void);
extern int vault_create_ffi(const char *name, int vault_type, const char *path, const char *password);
extern int vault_delete_ffi(uint32_t id, const char *password);
extern int vault_rename_ffi(uint32_t id, const char *new_name, const char *password);
extern int vault_unlock_ffi(uint32_t id, const char *password);
extern int vault_change_password_ffi(uint32_t id, const char *old_pass, const char *new_pass);
extern int vault_encrypt_ffi(uint32_t id, const char *password);
extern int vault_decrypt_ffi(uint32_t id, const char *password);
extern int vault_scan_ffi(uint32_t id);
extern int vault_resolve_ffi(uint32_t id, const char *password);
extern void vault_info_ffi(uint32_t id);
extern void vault_list_ffi(void);
extern void vault_files_ffi(uint32_t id);
extern int vault_sandbox_ffi(uint32_t id, const char *password);
extern int vault_rule_ffi(uint32_t vault_id, int max_fails, int hour_from, int hour_to);
extern int vault_get_status_ffi(uint32_t id);
extern int vault_status_ffi(uint32_t id);

/* Inicialização */
int vault_ffi_init(void) {
    return vault_init_security();
}

#ifndef VAULT_FFI_BUILD
int main(void) {
    printf("Komodo-Secure FFI Module\n");
    printf("Versão: 0.7.0\n");
    return 0;
}
#endif
