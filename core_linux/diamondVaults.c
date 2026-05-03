/*
 * diamondVaults.c
 *
 * VAULT SECURITY SYSTEM - Full Linux Implementation
 * Author: Peter Steve (architecture) | Senior Linux Engineer (implementation)
 * Date: 2026-04-11
 * Sandbox v2: 2026-04-19 — DiamondVault Hardened Sandbox Architecture
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -o diamondVaults diamondVaults.c \
 *       -lssl -lcrypto -lpthread -lseccomp -lcap
 *
 * Dependencies:
 *   openssl-dev    (AES-256-CBC, SHA-256, PBKDF2)
 *   libseccomp-dev (sandbox seccomp-BPF via libseccomp)
 *   libcap-dev     (drop de capabilities Linux)
 *   pthreads       (monitor loop)
 *
 * Linux-only: uses inotify, namespaces, pivot_root, seccomp, capabilities
 *
 * Sandbox v2 — Defense in Depth (5 camadas independentes):
 *   1. User Namespace    — root do sandbox → nobody no host
 *   2. Mount + PID NS   — visão própria de processos e filesystem
 *   3. Pivot Root        — substitui chroot, mais seguro
 *   4. Capability Drop  — remove todas as Linux Caps + PR_SET_NO_NEW_PRIVS
 *   5. Seccomp-BPF       — allowlist mínima, SCMP_ACT_KILL como default
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/wait.h>
#include <pthread.h>
#include <termios.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <seccomp.h>
#include <sched.h>
#include <sys/capability.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/* ─────────────────────────────────────────────
 *  COMPILE-TIME CONSTANTS
 * ───────────────────────────────────────────── */
#define VAULT_CATALOG_PATH      "/var/lib/vault_security"
#define VAULT_CATALOG_FILE      "/var/lib/vault_security/catalog.dat"
#define VAULT_LOG_FILE          "/var/log/vault_security.log"
#define VAULT_LOCK_FILE         "/var/run/vault_security.pid"

#define MAX_VAULTS              2048
#define MAX_FILES_PER_VAULT     4096
#define VAULT_NAME_MAX          128
#define VAULT_PATH_MAX          512
#define HASH_HEX_LEN            65      /* SHA-256 hex + NUL */
#define SALT_LEN                32
#define KEY_LEN                 32      /* AES-256 */

#define PBKDF2_ITER             310000  /* OWASP 2023 recommendation */
#define MAX_PASS_ATTEMPTS       3
#define MAX_PASS_LEN            256
#define INOTIFY_BUFSZ           (4096 * (sizeof(struct inotify_event) + NAME_MAX + 1))

/* Sandbox v2 */
#define SANDBOX_NOBODY_UID      65534   /* UID/GID nobody — sem privilégios */
#define SANDBOX_NOBODY_GID      65534
#define SANDBOX_JAIL_MARKER     ".diamond_jail_ready"
#define SANDBOX_TMP_SIZE        "mode=1777,size=64m"

/* Alert intervals in seconds */
static const long ALERT_INTERVALS[] = {
    300, 600, 900, 1800, 3600, 7200, 14400, 28800,
    43200, 86400, 172800, 259200, 604800, 1209600,
    1814400, 2592000, 5184000, 7776000, 15552000, 31536000
};
#define NUM_ALERT_INTERVALS (sizeof(ALERT_INTERVALS) / sizeof(ALERT_INTERVALS[0]))

/* ─────────────────────────────────────────────
 *  ENUMERATIONS
 * ───────────────────────────────────────────── */
typedef enum {
    VAULT_TYPE_NORMAL    = 0,
    VAULT_TYPE_PROTECTED = 1
} VaultType;

typedef enum {
    VAULT_STATUS_OK      = 0,
    VAULT_STATUS_LOCKED  = 1,
    VAULT_STATUS_ALERT   = 2,
    VAULT_STATUS_DELETED = 3
} VaultStatus;

typedef enum {
    LOG_INFO    = 0,
    LOG_WARN    = 1,
    LOG_ERROR   = 2,
    LOG_ALERT   = 3,
    LOG_AUDIT   = 4
} LogLevel;

typedef enum {
    ERR_OK              =  0,
    ERR_INVALID_ARGS    = -1,
    ERR_NO_MEMORY       = -2,
    ERR_IO              = -3,
    ERR_CRYPTO          = -4,
    ERR_AUTH_FAIL       = -5,
    ERR_VAULT_LOCKED    = -6,
    ERR_VAULT_EXISTS    = -7,
    ERR_VAULT_NOT_FOUND = -8,
    ERR_PERM_DENIED     = -9,
    ERR_CATALOG_FULL    = -10,
    ERR_PATH_INVALID    = -11,
    ERR_PASS_REQUIRED   = -12,
    ERR_INTEGRITY       = -13,
    ERR_SYSTEM          = -14
} VaultError;

/* ─────────────────────────────────────────────
 *  DATA STRUCTURES
 * ───────────────────────────────────────────── */

/* One file entry in the hash map */
typedef struct FileEntry {
    char            filename[NAME_MAX + 1];
    char            hash[HASH_HEX_LEN];
    time_t          last_seen;
    bool            modified;
    struct FileEntry *next;
} FileEntry;

/* Hash map bucket */
#define HASHMAP_BUCKETS 256
typedef struct {
    FileEntry *buckets[HASHMAP_BUCKETS];
    size_t     count;
} FileHashMap;

/* Alert state per vault */
typedef struct {
    time_t      first_triggered;
    time_t      last_alerted;
    size_t      interval_idx;
    size_t      alert_count;
    char        reason[256];
} AlertState;

/* Core vault structure */
typedef struct {
    uint32_t    id;
    char        name[VAULT_NAME_MAX];
    VaultType   type;
    VaultStatus status;
    bool        has_pass;
    char        path[VAULT_PATH_MAX];
    time_t      created_at;
    time_t      last_check;
    int         failed_attempts;

    /* Auth */
    uint8_t     salt[SALT_LEN];
    uint8_t     pass_hash[SHA256_DIGEST_LENGTH];  /* PBKDF2(pass, salt) */

    /* File integrity */
    FileHashMap hashmap;

    /* Alert state */
    AlertState  alert;

    /* inotify watch descriptor */
    int         inotify_wd;
} Vault;

/* Catalog: flat array of vaults */
typedef struct {
    Vault    vaults[MAX_VAULTS];
    uint32_t count;
    uint32_t next_id;
    char     category[32];   /* "diamond" */
} Catalog;

/* Monitor thread context */
typedef struct {
    Catalog        *catalog;
    int             inotify_fd;
    volatile bool   running;
    pthread_mutex_t lock;
} MonitorCtx;

/* ─────────────────────────────────────────────
 *  GLOBALS
 * ───────────────────────────────────────────── */
static Catalog     g_catalog;
static MonitorCtx  g_monitor;
static FILE       *g_logfp   = NULL;
static bool        g_verbose = false;

/* ─────────────────────────────────────────────
 *  FORWARD DECLARATIONS
 * ───────────────────────────────────────────── */
static VaultError catalog_save(void);
static VaultError catalog_load(void);
static void       monitor_scan_vault(Vault *v);
static void       alert_trigger(Vault *v, const char *reason);

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 1: LOGGING
 * ═══════════════════════════════════════════════════════════════════════════ */

static const char *log_level_str(LogLevel lvl) {
    switch (lvl) {
        case LOG_INFO:  return "INFO ";
        case LOG_WARN:  return "WARN ";
        case LOG_ERROR: return "ERROR";
        case LOG_ALERT: return "ALERT";
        case LOG_AUDIT: return "AUDIT";
        default:        return "?????";
    }
}

static void vault_log(LogLevel lvl, const char *fmt, ...) {
    char    timebuf[32];
    time_t  now = time(NULL);
    struct  tm *tm_info = localtime(&now);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);

    va_list ap;
    va_start(ap, fmt);

    /* Console */
    if (lvl >= LOG_WARN || g_verbose) {
        if (lvl == LOG_ALERT || lvl == LOG_ERROR)
            fprintf(stderr, "[%s] [%s] ", timebuf, log_level_str(lvl));
        else
            fprintf(stdout, "[%s] [%s] ", timebuf, log_level_str(lvl));

        if (lvl == LOG_ALERT || lvl == LOG_ERROR)
            vfprintf(stderr, fmt, ap);
        else
            vfprintf(stdout, fmt, ap);

        if (lvl >= LOG_WARN)
            fputc('\n', stderr);
        else
            fputc('\n', stdout);
    }

    va_end(ap);
    va_start(ap, fmt);

    /* File */
    if (g_logfp) {
        fprintf(g_logfp, "[%s] [%s] ", timebuf, log_level_str(lvl));
        vfprintf(g_logfp, fmt, ap);
        fputc('\n', g_logfp);
        fflush(g_logfp);
    }

    va_end(ap);
}

static void log_init(void) {
    g_logfp = fopen(VAULT_LOG_FILE, "a");
    if (!g_logfp) {
        /* Fallback: try home dir */
        char fallback[256];
        const char *home = getenv("HOME");
        if (home) {
            snprintf(fallback, sizeof(fallback), "%s/.vault_security.log", home);
            g_logfp = fopen(fallback, "a");
        }
        if (!g_logfp)
            fprintf(stderr, "WARNING: cannot open log file, logging to stderr only\n");
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 2: ERROR HANDLING
 * ═══════════════════════════════════════════════════════════════════════════ */

static const char *vault_strerror(VaultError err) {
    switch (err) {
        case ERR_OK:              return "Success";
        case ERR_INVALID_ARGS:    return "Invalid arguments";
        case ERR_NO_MEMORY:       return "Out of memory";
        case ERR_IO:              return "I/O error";
        case ERR_CRYPTO:          return "Cryptographic error";
        case ERR_AUTH_FAIL:       return "Authentication failure";
        case ERR_VAULT_LOCKED:    return "Vault is locked";
        case ERR_VAULT_EXISTS:    return "Vault already exists";
        case ERR_VAULT_NOT_FOUND: return "Vault not found";
        case ERR_PERM_DENIED:     return "Permission denied";
        case ERR_CATALOG_FULL:    return "Catalog is full (max 64 vaults)";
        case ERR_PATH_INVALID:    return "Invalid path";
        case ERR_PASS_REQUIRED:   return "Password required for protected vault";
        case ERR_INTEGRITY:       return "File integrity violation";
        case ERR_SYSTEM:          return "System error";
        default:                  return "Unknown error";
    }
}

#define VAULT_ASSERT(cond, err, fmt, ...) \
    do { \
        if (!(cond)) { \
            vault_log(LOG_ERROR, "ASSERT FAILED [%s:%d]: " fmt, \
                      __FILE__, __LINE__, ##__VA_ARGS__); \
            return (err); \
        } \
    } while (0)

#define VAULT_ASSERT_VOID(cond, fmt, ...) \
    do { \
        if (!(cond)) { \
            vault_log(LOG_ERROR, "ASSERT FAILED [%s:%d]: " fmt, \
                      __FILE__, __LINE__, ##__VA_ARGS__); \
            return; \
        } \
    } while (0)

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 3: ARGUMENT & STRING SANITISATION
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Strip leading/trailing whitespace and surrounding quotes (" or ')
 * Modifies buffer in place, returns pointer to result inside buffer.
 */
static char *sanitize_arg(char *s) {
    if (!s) return NULL;

    /* Trim leading whitespace */
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++;

    /* Strip surrounding quotes */
    size_t len = strlen(s);
    if (len >= 2) {
        if ((s[0] == '"' && s[len-1] == '"') ||
            (s[0] == '\'' && s[len-1] == '\'')) {
            s[len-1] = '\0';
            s++;
            len -= 2;
        }
    }

    /* Trim trailing whitespace */
    if (len > 0) {
        char *end = s + len - 1;
        while (end > s && (*end == ' ' || *end == '\t' ||
                           *end == '\n' || *end == '\r')) {
            *end-- = '\0';
        }
    }

    return s;
}

/* Validate that a path is safe (no null bytes, reasonable length, not relative) */
static VaultError validate_path(const char *path) {
    if (!path || path[0] == '\0')
        return ERR_PATH_INVALID;
    if (strlen(path) >= VAULT_PATH_MAX)
        return ERR_PATH_INVALID;
    /* Deve ser absoluto */
    if (path[0] != '/')
        return ERR_PATH_INVALID;
    /* Rejeita path traversal */
    if (strstr(path, "/../") ||
        (strlen(path) >= 3 && strcmp(path + strlen(path) - 3, "/..") == 0))
        return ERR_PATH_INVALID;
    /* Rejeita caracteres de controle — null bytes embutidos, tabs, newlines */
    for (const char *p = path; *p; p++) {
        if ((unsigned char)*p < 0x20) {
            vault_log(LOG_ERROR, "validate_path: caractere de controle (0x%02x) no path",
                      (unsigned char)*p);
            return ERR_PATH_INVALID;
        }
    }
    return ERR_OK;
}

/* Validate vault name: alphanumeric + underscore + hyphen only */
static VaultError validate_name(const char *name) {
    if (!name || name[0] == '\0') return ERR_INVALID_ARGS;
    if (strlen(name) >= VAULT_NAME_MAX) return ERR_INVALID_ARGS;
    for (const char *p = name; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')) {
            vault_log(LOG_ERROR, "Invalid character '%c' in vault name", *p);
            return ERR_INVALID_ARGS;
        }
    }
    return ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 4: CRYPTOGRAPHY
 * ═══════════════════════════════════════════════════════════════════════════ */

/* SHA-256 of a buffer → hex string */
static void sha256_hex(const uint8_t *data, size_t len, char out[HASH_HEX_LEN]) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(data, len, digest);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[HASH_HEX_LEN - 1] = '\0';
}

/* SHA-256 of a file → hex string */
static VaultError sha256_file(const char *path, char out[HASH_HEX_LEN]) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return ERR_IO;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(fp); return ERR_CRYPTO; }

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return ERR_CRYPTO;
    }

    uint8_t buf[65536];
    size_t  n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        EVP_DigestUpdate(ctx, buf, n);

    if (ferror(fp)) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return ERR_IO;
    }

    uint8_t digest[SHA256_DIGEST_LENGTH];
    unsigned int dlen = 0;
    EVP_DigestFinal_ex(ctx, digest, &dlen);
    if (dlen != SHA256_DIGEST_LENGTH) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return ERR_CRYPTO;
    }
    EVP_MD_CTX_free(ctx);
    if (fclose(fp) != 0)
        return ERR_IO;

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[HASH_HEX_LEN - 1] = '\0';

    return ERR_OK;
}

/* PBKDF2-HMAC-SHA256: password → derived key */
static VaultError derive_key(const char *password, const uint8_t *salt,
                              uint8_t key[KEY_LEN]) {
    if (!password || !salt || !key)
        return ERR_INVALID_ARGS;

    int rc = PKCS5_PBKDF2_HMAC(
        password, (int)strlen(password),
        salt, SALT_LEN,
        PBKDF2_ITER,
        EVP_sha256(),
        KEY_LEN, key
    );

    if (rc != 1) {
        vault_log(LOG_ERROR, "PBKDF2 failed: %s",
                  ERR_error_string(ERR_get_error(), NULL));
        return ERR_CRYPTO;
    }
    return ERR_OK;
}

/* Store password verifier: PBKDF2(pass, salt) stored in vault */
static VaultError auth_set_password(Vault *v, const char *password) {
    VAULT_ASSERT(v && password, ERR_INVALID_ARGS, "null vault or password");
    VAULT_ASSERT(strlen(password) >= 8, ERR_INVALID_ARGS,
                 "Password must be at least 8 characters");
    VAULT_ASSERT(strlen(password) < MAX_PASS_LEN, ERR_INVALID_ARGS,
                 "Password too long (max %d chars)", MAX_PASS_LEN - 1);

    /* Generate random salt */
    if (RAND_bytes(v->salt, SALT_LEN) != 1) {
        vault_log(LOG_ERROR, "Cannot generate random salt");
        return ERR_CRYPTO;
    }

    uint8_t key[KEY_LEN];
    VaultError err = derive_key(password, v->salt, key);
    if (err != ERR_OK) return err;

    /* Store PBKDF2 output as verifier */
    memcpy(v->pass_hash, key, SHA256_DIGEST_LENGTH);
    explicit_bzero(key, KEY_LEN);

    v->has_pass = true;
    vault_log(LOG_AUDIT, "Password set for vault '%s' (id=%u)", v->name, v->id);
    return ERR_OK;
}

/* Verify password: re-derive and compare */
static VaultError auth_verify_password(Vault *v, const char *password) {
    VAULT_ASSERT(v && password, ERR_INVALID_ARGS, "null vault or password");

    if (!v->has_pass) {
        vault_log(LOG_WARN, "Vault '%s' has no password set", v->name);
        return ERR_PASS_REQUIRED;
    }

    uint8_t key[KEY_LEN];
    VaultError err = derive_key(password, v->salt, key);
    if (err != ERR_OK) return err;

    bool match = (CRYPTO_memcmp(v->pass_hash, key, SHA256_DIGEST_LENGTH) == 0);
    explicit_bzero(key, KEY_LEN);

    if (!match) {
        v->failed_attempts++;
        vault_log(LOG_AUDIT, "Auth FAILED for vault '%s' (attempt %d/%d)",
                  v->name, v->failed_attempts, MAX_PASS_ATTEMPTS);

        if (v->failed_attempts >= MAX_PASS_ATTEMPTS) {
            v->status = VAULT_STATUS_LOCKED;
            vault_log(LOG_ALERT, "Vault '%s' LOCKED after %d failed attempts",
                      v->name, MAX_PASS_ATTEMPTS);
            catalog_save();
        }
        return ERR_AUTH_FAIL;
    }

    v->failed_attempts = 0;
    vault_log(LOG_AUDIT, "Auth OK for vault '%s'", v->name);
    return ERR_OK;
}

/* AES-256-CBC encrypt a file to an output file.
 * IV is prepended (16 bytes) to the ciphertext file. */
#define GCM_IV_LEN  12   /* 96 bits — recomendado para GCM */
#define GCM_TAG_LEN 16

static VaultError encrypt_file(const char *inpath, const char *outpath,
                                const uint8_t key[KEY_LEN]) {
    FILE *fin  = fopen(inpath,  "rb");
    FILE *fout = fopen(outpath, "wb");
    VaultError ret = ERR_OK;
    EVP_CIPHER_CTX *ctx = NULL;

    if (!fin || !fout) {
        vault_log(LOG_ERROR, "encrypt_file: cannot open files: %s", strerror(errno));
        ret = ERR_IO; goto cleanup;
    }

    uint8_t iv[GCM_IV_LEN];
    if (RAND_bytes(iv, GCM_IV_LEN) != 1) { ret = ERR_CRYPTO; goto cleanup; }

    if (fwrite(iv, 1, GCM_IV_LEN, fout) != GCM_IV_LEN) {
        ret = ERR_IO; goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { ret = ERR_CRYPTO; goto cleanup; }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        ret = ERR_CRYPTO; goto cleanup;
    }

    uint8_t inbuf[65536], outbuf[65536];
    int outlen;
    size_t n;

    while ((n = fread(inbuf, 1, sizeof(inbuf), fin)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, (int)n) != 1) {
            ret = ERR_CRYPTO; goto cleanup;
        }
        if (fwrite(outbuf, 1, (size_t)outlen, fout) != (size_t)outlen) {
            ret = ERR_IO; goto cleanup;
        }
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        ret = ERR_CRYPTO; goto cleanup;
    }
    if (outlen > 0 && fwrite(outbuf, 1, (size_t)outlen, fout) != (size_t)outlen) {
        ret = ERR_IO; goto cleanup;
    }

    /* Grava tag de autenticação — 16 bytes no final */
    uint8_t tag[GCM_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) {
        ret = ERR_CRYPTO; goto cleanup;
    }
    if (fwrite(tag, 1, GCM_TAG_LEN, fout) != GCM_TAG_LEN) {
        ret = ERR_IO;
    }

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (fin)  fclose(fin);
    if (fout) { fclose(fout); if (ret != ERR_OK) unlink(outpath); }
    return ret;
}

static VaultError decrypt_file(const char *inpath, const char *outpath,
                                const uint8_t key[KEY_LEN]) {
    FILE *fin  = fopen(inpath,  "rb");
    FILE *fout = fopen(outpath, "wb");
    VaultError ret = ERR_OK;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *filebuf = NULL;

    if (!fin || !fout) { ret = ERR_IO; goto cleanup; }

    /* Lê o arquivo inteiro para separar ciphertext da tag */
    fseek(fin, 0, SEEK_END);
    long fsize = ftell(fin);
    rewind(fin);

    /* mínimo: IV + tag */
    if (fsize < (long)(GCM_IV_LEN + GCM_TAG_LEN)) {
        vault_log(LOG_ERROR, "decrypt_file: arquivo muito pequeno");
        ret = ERR_IO; goto cleanup;
    }

    filebuf = malloc((size_t)fsize);
    if (!filebuf) { ret = ERR_NO_MEMORY; goto cleanup; }

    if (fread(filebuf, 1, (size_t)fsize, fin) != (size_t)fsize) {
        ret = ERR_IO; goto cleanup;
    }

    uint8_t *iv         = filebuf;
    uint8_t *ciphertext = filebuf + GCM_IV_LEN;
    size_t   ct_len     = (size_t)fsize - GCM_IV_LEN - GCM_TAG_LEN;
    uint8_t *tag        = filebuf + GCM_IV_LEN + ct_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { ret = ERR_CRYPTO; goto cleanup; }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        ret = ERR_CRYPTO; goto cleanup;
    }

    /* Informa a tag ANTES do Final — GCM verifica na chamada do Final */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag) != 1) {
        ret = ERR_CRYPTO; goto cleanup;
    }

    uint8_t outbuf[65536];
    int outlen;
    size_t offset = 0;

    while (offset < ct_len) {
        size_t chunk = ct_len - offset;
        if (chunk > sizeof(outbuf)) chunk = sizeof(outbuf);

        if (EVP_DecryptUpdate(ctx, outbuf, &outlen,
                              ciphertext + offset, (int)chunk) != 1) {
            ret = ERR_CRYPTO; goto cleanup;
        }
        if (fwrite(outbuf, 1, (size_t)outlen, fout) != (size_t)outlen) {
            ret = ERR_IO; goto cleanup;
        }
        offset += chunk;
    }

    /* Final verifica a tag — se falhar, ciphertext foi adulterado */
    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        vault_log(LOG_ERROR, "decrypt_file: falha na verificação GCM — dados adulterados ou chave errada");
        ret = ERR_CRYPTO; goto cleanup;
    }
    if (outlen > 0 && fwrite(outbuf, 1, (size_t)outlen, fout) != (size_t)outlen) {
        ret = ERR_IO;
    }

cleanup:
    if (filebuf) { explicit_bzero(filebuf, (size_t)(fsize > 0 ? fsize : 0)); free(filebuf); }
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (fin)  fclose(fin);
    if (fout) { fclose(fout); if (ret != ERR_OK) unlink(outpath); }
    return ret;
}
/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 5: FILE HASH MAP
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint32_t hashmap_bucket(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (uint8_t)*s++; h *= 16777619u; }
    return h % HASHMAP_BUCKETS;
}

static FileEntry *hashmap_find(FileHashMap *m, const char *filename) {
    uint32_t b = hashmap_bucket(filename);
    for (FileEntry *e = m->buckets[b]; e; e = e->next)
        if (strcmp(e->filename, filename) == 0)
            return e;
    return NULL;
}

static FileEntry *hashmap_insert(FileHashMap *m, const char *filename) {
    uint32_t b = hashmap_bucket(filename);
    FileEntry *e = hashmap_find(m, filename);
    if (e) return e;

    e = calloc(1, sizeof(FileEntry));
    if (!e) return NULL;

    strncpy(e->filename, filename, NAME_MAX);
    e->filename[NAME_MAX] = '\0';
    e->next = m->buckets[b];
    m->buckets[b] = e;
    m->count++;
    return e;
}

static void hashmap_clear(FileHashMap *m) {
    for (int i = 0; i < HASHMAP_BUCKETS; i++) {
        FileEntry *e = m->buckets[i];
        while (e) {
            FileEntry *next = e->next;
            free(e);
            e = next;
        }
        m->buckets[i] = NULL;
    }
    m->count = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 6: CATALOG SERIALISATION
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Binary catalog format (version 1):
 *   [4]  magic "VLTS"
 *   [1]  version = 1
 *   [4]  count
 *   [4]  next_id
 *   [32] category
 *   For each vault:
 *     [4]  id
 *     [128] name
 *     [4]  type
 *     [4]  status
 *     [1]  has_pass
 *     [512] path
 *     [8]  created_at
 *     [8]  last_check
 *     [4]  failed_attempts
 *     [4]  alert.interval_idx
 *     [8]  alert.first_triggered
 *     [8]  alert.last_alerted
 *     [8]  alert.alert_count
 *     [256] alert.reason
 *     [32] salt
 *     [32] pass_hash
 *     [4]  file_count
 *     For each file entry:
 *       [NAME_MAX+1] filename
 *       [65]         hash
 *       [8]          last_seen
 *       [1]          modified
 */

#define CATALOG_MAGIC "VLTS"
#define CATALOG_VER    1
#define FCOUNT_MAX 1000

static VaultError catalog_save(void) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", VAULT_CATALOG_FILE);

    FILE *fp = fopen(tmp, "wb");
    if (!fp) {
        vault_log(LOG_ERROR, "catalog_save: cannot open %s: %s", tmp, strerror(errno));
        return ERR_IO;
    }

    /* Header */
    fwrite(CATALOG_MAGIC, 1, 4, fp);
    uint8_t ver = CATALOG_VER;
    fwrite(&ver, 1, 1, fp);
    fwrite(&g_catalog.count, 4, 1, fp);
    fwrite(&g_catalog.next_id, 4, 1, fp);
    fwrite(g_catalog.category, 1, 32, fp);

    for (uint32_t i = 0; i < g_catalog.count; i++) {
        Vault *v = &g_catalog.vaults[i];

        fwrite(&v->id,              sizeof(v->id),              1, fp);
        fwrite(v->name,             VAULT_NAME_MAX,             1, fp);
        fwrite(&v->type,            sizeof(v->type),            1, fp);
        fwrite(&v->status,          sizeof(v->status),          1, fp);
        uint8_t hp = v->has_pass ? 1 : 0;
        fwrite(&hp,                 1,                          1, fp);
        fwrite(v->path,             VAULT_PATH_MAX,             1, fp);
        fwrite(&v->created_at,      sizeof(v->created_at),      1, fp);
        fwrite(&v->last_check,      sizeof(v->last_check),      1, fp);
        fwrite(&v->failed_attempts, sizeof(v->failed_attempts), 1, fp);

        fwrite(&v->alert.interval_idx,    sizeof(size_t), 1, fp);
        fwrite(&v->alert.first_triggered, sizeof(time_t), 1, fp);
        fwrite(&v->alert.last_alerted,    sizeof(time_t), 1, fp);
        fwrite(&v->alert.alert_count,     sizeof(size_t), 1, fp);
        fwrite(v->alert.reason,           256,            1, fp);

        fwrite(v->salt,      SALT_LEN,                  1, fp);
        fwrite(v->pass_hash, SHA256_DIGEST_LENGTH,      1, fp);

        /* File entries */
        uint32_t fcount = (uint32_t)v->hashmap.count;
        if (fcount > FCOUNT_MAX) {
            fcount = FCOUNT_MAX;
        }
        uint32_t write = 0;

        fwrite(&fcount, sizeof(fcount), 1, fp);

        for (int b = 0; b < HASHMAP_BUCKETS && write < fcount; b++) {
    for (FileEntry *e = v->hashmap.buckets[b]; e && write < fcount; e = e->next) {
        fwrite(e->filename, NAME_MAX + 1, 1, fp);
        fwrite(e->hash,     HASH_HEX_LEN, 1, fp);
        fwrite(&e->last_seen, sizeof(time_t), 1, fp);
        uint8_t mod = e->modified ? 1 : 0;
        fwrite(&mod, 1, 1, fp);
        write++;
    }
}
    }

    fclose(fp);

    /* Atomic rename */
    if (rename(tmp, VAULT_CATALOG_FILE) != 0) {
        vault_log(LOG_ERROR, "catalog_save: rename failed: %s", strerror(errno));
        unlink(tmp);
        return ERR_IO;
    }

    chmod(VAULT_CATALOG_FILE, 0600);
    vault_log(LOG_INFO, "Catalog saved (%u vaults)", g_catalog.count);
    return ERR_OK;
}

static VaultError catalog_load(void) {
    FILE *fp = fopen(VAULT_CATALOG_FILE, "rb");
    if (!fp) {
        if (errno == ENOENT) {
            vault_log(LOG_INFO, "No catalog found, starting fresh");
            strncpy(g_catalog.category, "diamond", 31);
            g_catalog.next_id = 1;
            return ERR_OK;
        }
        vault_log(LOG_ERROR, "catalog_load: %s", strerror(errno));
        return ERR_IO;
    }

    char magic[5] = {0};
    if (fread(magic, 1, 4, fp) != 4 || memcmp(magic, CATALOG_MAGIC, 4) != 0) {
        fclose(fp);
        vault_log(LOG_ERROR, "Catalog file corrupt or wrong format");
        return ERR_IO;
    }

    uint8_t ver;
    if (fread(&ver, 1, 1, fp) != 1 || ver != CATALOG_VER) {
        fclose(fp);
        vault_log(LOG_ERROR, "Unsupported catalog version %d", ver);
        return ERR_IO;
    }
    #define FREAD_CHECK(dst, sz, fp) \
    do { if (fread(dst, sz, 1, fp) != 1) { \
        vault_log(LOG_ERROR, "catalog_load: leitura truncada em %s:%d", __FILE__, __LINE__); \ 
        fclose(fp); return ERR_IO; } } while(0)
    
    FREAD_CHECK(&g_catalog.count,   4, fp);
    FREAD_CHECK(&g_catalog.next_id, 4, fp);
    FREAD_CHECK(g_catalog.category, 32, fp);

    if (g_catalog.count > MAX_VAULTS) {
        fclose(fp);
        vault_log(LOG_ERROR, "Catalog claims %u vaults (max %d)", g_catalog.count, MAX_VAULTS);
        return ERR_IO;
    }

    for (uint32_t i = 0; i < g_catalog.count; i++) {
        Vault *v = &g_catalog.vaults[i];
        memset(v, 0, sizeof(Vault));

        FREAD_CHECK(&v->id,              sizeof(v->id),              fp);
        FREAD_CHECK(v->name,             VAULT_NAME_MAX,             fp);
        FREAD_CHECK(&v->type,            sizeof(v->type),            fp);
        FREAD_CHECK(&v->status,          sizeof(v->status),          fp);
        uint8_t hp;
        FREAD_CHECK(&hp,                 1,                          fp);
        v->has_pass = (hp != 0);
        FREAD_CHECK(v->path,             VAULT_PATH_MAX,             fp);
        FREAD_CHECK(&v->created_at,      sizeof(v->created_at),      fp);
        FREAD_CHECK(&v->last_check,      sizeof(v->last_check),      fp);
        FREAD_CHECK(&v->failed_attempts, sizeof(v->failed_attempts), fp);
        FREAD_CHECK(&v->alert.interval_idx,    sizeof(size_t), fp);
        FREAD_CHECK(&v->alert.first_triggered, sizeof(time_t), fp);
        FREAD_CHECK(&v->alert.last_alerted,    sizeof(time_t), fp);
        FREAD_CHECK(&v->alert.alert_count,     sizeof(size_t), fp);
        FREAD_CHECK(v->alert.reason,           256,            fp);
        FREAD_CHECK(v->salt,      SALT_LEN,             fp);
        FREAD_CHECK(v->pass_hash, SHA256_DIGEST_LENGTH, fp);

uint32_t fcount;
FREAD_CHECK(&fcount, 4, fp);
if (fcount > MAX_FILES_PER_VAULT) {
    vault_log(LOG_ERROR, "catalog_load: fcount inválido: %u", fcount);
    fclose(fp); return ERR_IO;
}

for (uint32_t f = 0; f < fcount; f++) {
    char    fname[NAME_MAX + 1];
    char    fhash[HASH_HEX_LEN];
    time_t  ls;
    uint8_t mod;

    FREAD_CHECK(fname,  NAME_MAX + 1,   fp);
    FREAD_CHECK(fhash,  HASH_HEX_LEN,   fp);
    FREAD_CHECK(&ls,    sizeof(time_t), fp);
    FREAD_CHECK(&mod,   1,              fp);

    FileEntry *e = hashmap_insert(&v->hashmap, fname);
    if (e) {
        memcpy(e->hash, fhash, HASH_HEX_LEN);
        e->last_seen = ls;
        e->modified  = (mod != 0);
       }
    }

        v->inotify_wd = -1;
    }

    fclose(fp);
    vault_log(LOG_INFO, "Catalog loaded: %u vaults (category: %s)",
              g_catalog.count, g_catalog.category);
    return ERR_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 7: VAULT MANAGER
 * ═══════════════════════════════════════════════════════════════════════════ */

static Vault *vault_find_by_id(uint32_t id) {
    for (uint32_t i = 0; i < g_catalog.count; i++)
        if (g_catalog.vaults[i].id == id)
            return &g_catalog.vaults[i];
    return NULL;
}

static Vault *vault_find_by_name(const char *name) {
    for (uint32_t i = 0; i < g_catalog.count; i++)
        if (strcmp(g_catalog.vaults[i].name, name) == 0)
            return &g_catalog.vaults[i];
    return NULL;
}

/* Auto-increment naming: diamond_vault_N */
static void vault_auto_name(char *out, size_t outsz) {
    uint32_t n = 1;
    char candidate[VAULT_NAME_MAX];
    do {
        snprintf(candidate, sizeof(candidate), "diamond_vault_%u", n++);
    } while (vault_find_by_name(candidate) != NULL);
    strncpy(out, candidate, outsz - 1);
    out[outsz - 1] = '\0';
}

static VaultError vault_create(const char *name_arg, VaultType type,
                                const char *path_arg, const char *password) {
    if (g_catalog.count >= MAX_VAULTS)
        return ERR_CATALOG_FULL;

    /* Sanitize inputs */
    char name_buf[VAULT_NAME_MAX];
    char path_buf[VAULT_PATH_MAX];

    if (name_arg && *name_arg) {
        char *n = sanitize_arg((char *)name_arg);  /* safe: we own copy below */
        snprintf(name_buf, sizeof(name_buf), "%s", n);
    } else {
        vault_auto_name(name_buf, sizeof(name_buf));
        vault_log(LOG_INFO, "No name given, using auto-name: %s", name_buf);
    }

    VaultError err;
    err = validate_name(name_buf);
    if (err != ERR_OK) return err;

    if (vault_find_by_name(name_buf)) {
        vault_log(LOG_ERROR, "Vault '%s' already exists", name_buf);
        return ERR_VAULT_EXISTS;
    }

    if (path_arg && *path_arg) {
        char *p = sanitize_arg((char *)path_arg);
        snprintf(path_buf, sizeof(path_buf), "%s", p);
        err = validate_path(path_buf);
        if (err != ERR_OK) return err;
    } else {
        snprintf(path_buf, sizeof(path_buf), "%s/%s", VAULT_CATALOG_PATH, name_buf);
    }

    if (type == VAULT_TYPE_PROTECTED && (!password || !*password)) {
        vault_log(LOG_ERROR, "Protected vault requires a password");
        return ERR_PASS_REQUIRED;
    }

    /* Create directory */
    if (mkdir(path_buf, 0700) != 0 && errno != EEXIST) {
        vault_log(LOG_ERROR, "mkdir '%s' failed: %s", path_buf, strerror(errno));
        return ERR_IO;
    }

    Vault *v = &g_catalog.vaults[g_catalog.count];
    memset(v, 0, sizeof(Vault));

    v->id         = g_catalog.next_id++;
    v->type       = type;
    v->status     = VAULT_STATUS_OK;
    v->created_at = time(NULL);
    v->last_check = v->created_at;
    v->inotify_wd = -1;

    strncpy(v->name, name_buf, VAULT_NAME_MAX - 1);
    strncpy(v->path, path_buf, VAULT_PATH_MAX - 1);

    if (type == VAULT_TYPE_PROTECTED) {
        err = auth_set_password(v, password);
        if (err != ERR_OK) return err;
    }

    g_catalog.count++;
    err = catalog_save();

    vault_log(LOG_AUDIT, "Vault CREATED: id=%u name='%s' type=%s path='%s'",
              v->id, v->name,
              type == VAULT_TYPE_PROTECTED ? "PROTECTED" : "NORMAL",
              v->path);

    printf("\n  ✓ Vault created successfully\n");
    printf("    ID   : %u\n", v->id);
    printf("    Name : %s\n", v->name);
    printf("    Type : %s\n", type == VAULT_TYPE_PROTECTED ? "PROTECTED" : "NORMAL");
    printf("    Path : %s\n\n", v->path);

    return err;
}

static VaultError vault_delete(uint32_t id, const char *password) {
    Vault *v = vault_find_by_id(id);
    if (!v) return ERR_VAULT_NOT_FOUND;

    if (v->type == VAULT_TYPE_PROTECTED) {
        if (!password || !*password) return ERR_PASS_REQUIRED;
        VaultError err = auth_verify_password(v, password);
        if (err != ERR_OK) return err;
    }

    vault_log(LOG_AUDIT, "Vault DELETED: id=%u name='%s'", v->id, v->name);

    /* Clear sensitive data before removal */
    explicit_bzero(v->salt, SALT_LEN);
    explicit_bzero(v->pass_hash, SHA256_DIGEST_LENGTH);
    hashmap_clear(&v->hashmap);

    /* Compact array */
    uint32_t idx = (uint32_t)(v - g_catalog.vaults);
    memmove(&g_catalog.vaults[idx],
            &g_catalog.vaults[idx + 1],
            (g_catalog.count - idx - 1) * sizeof(Vault));
    g_catalog.count--;

    return catalog_save();
}

static VaultError vault_rename(uint32_t id, const char *new_name, const char *password) {
    Vault *v = vault_find_by_id(id);
    if (!v) return ERR_VAULT_NOT_FOUND;

    char *n = sanitize_arg((char *)new_name);
    VaultError err = validate_name(n);
    if (err != ERR_OK) return err;

    if (vault_find_by_name(n)) {
        vault_log(LOG_ERROR, "Vault name '%s' already in use", n);
        return ERR_VAULT_EXISTS;
    }

    if (v->type == VAULT_TYPE_PROTECTED) {
        if (!password || !*password) return ERR_PASS_REQUIRED;
        err = auth_verify_password(v, password);
        if (err != ERR_OK) return err;
    }

    vault_log(LOG_AUDIT, "Vault RENAMED: id=%u '%s' → '%s'", v->id, v->name, n);
    strncpy(v->name, n, VAULT_NAME_MAX - 1);
    return catalog_save();
}

static VaultError vault_unlock(uint32_t id, const char *password) {
    Vault *v = vault_find_by_id(id);
    if (!v) return ERR_VAULT_NOT_FOUND;
    if (v->status != VAULT_STATUS_LOCKED) {
        printf("Vault '%s' is not locked.\n", v->name);
        return ERR_OK;
    }
    if (!password || !*password) return ERR_PASS_REQUIRED;

    /* Re-derive and verify — even locked state can be unlocked by admin */
    VaultError err = auth_verify_password(v, password);
    if (err != ERR_OK) {
        vault_log(LOG_ALERT, "Unlock attempt failed for locked vault '%s'", v->name);
        return err;
    }

    v->status = VAULT_STATUS_OK;
    v->failed_attempts = 0;
    vault_log(LOG_AUDIT, "Vault UNLOCKED: id=%u name='%s'", v->id, v->name);
    return catalog_save();
}

static VaultError vault_change_password(uint32_t id, const char *old_pass,
                                         const char *new_pass) {
    Vault *v = vault_find_by_id(id);
    if (!v) return ERR_VAULT_NOT_FOUND;
    if (!v->has_pass) {
        vault_log(LOG_ERROR, "Vault '%s' has no password to change", v->name);
        return ERR_PASS_REQUIRED;
    }

    VaultError err = auth_verify_password(v, old_pass);
    if (err != ERR_OK) return err;

    err = auth_set_password(v, new_pass);
    if (err != ERR_OK) return err;

    vault_log(LOG_AUDIT, "Password CHANGED for vault '%s'", v->name);
    return catalog_save();
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 8: FILE INTEGRITY MONITOR
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Scan a vault directory: hash every file and compare with stored hashes.
 * Calls alert_trigger() for modifications.
 */
static void monitor_scan_vault(Vault *v) {
    if (v->status == VAULT_STATUS_DELETED) return;

    DIR *dir = opendir(v->path);
    if (!dir) {
        vault_log(LOG_ERROR, "Cannot scan vault '%s' at '%s': %s",
                  v->name, v->path, strerror(errno));
        return;
    }

    struct dirent *de;
    char filepath[VAULT_PATH_MAX + NAME_MAX + 2];

    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') continue;  /* skip hidden / . .. */

        snprintf(filepath, sizeof(filepath), "%s/%s", v->path, de->d_name);

        struct stat st;
        if (stat(filepath, &st) != 0) continue;
        if (!S_ISREG(st.st_mode))     continue;  /* files only */

        char new_hash[HASH_HEX_LEN];
        if (sha256_file(filepath, new_hash) != ERR_OK) continue;

        FileEntry *e = hashmap_find(&v->hashmap, de->d_name);

        if (!e) {
            /* New file — record it */
            e = hashmap_insert(&v->hashmap, de->d_name);
            if (e) {
                memcpy(e->hash, new_hash, HASH_HEX_LEN);
                e->last_seen = time(NULL);
                e->modified  = false;
                vault_log(LOG_INFO, "[%s] New file registered: %s", v->name, de->d_name);
            }
        } else {
            /* Existing file — compare */
            if (memcmp(e->hash, new_hash, HASH_HEX_LEN) != 0) {
                if (!e->modified) {
                    e->modified = true;
                    vault_log(LOG_ALERT, "[%s] File MODIFIED: %s", v->name, de->d_name);
                    char reason[256];
                    snprintf(reason, sizeof(reason), "File modified: %s", de->d_name);
                    alert_trigger(v, reason);
                }
                memcpy(e->hash, new_hash, HASH_HEX_LEN);
            } else {
                e->modified = false;
            }
            e->last_seen = time(NULL);
        }
    }

    closedir(dir);
    v->last_check = time(NULL);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 9: ALERT SYSTEM
 * ═══════════════════════════════════════════════════════════════════════════ */

static void alert_trigger(Vault *v, const char *reason) {
    time_t now = time(NULL);

    if (v->alert.first_triggered == 0) {
        v->alert.first_triggered = now;
        v->alert.interval_idx    = 0;
    }

    strncpy(v->alert.reason, reason, 255);
    v->alert.reason[255] = '\0';
    v->status = VAULT_STATUS_ALERT;

    vault_log(LOG_ALERT, "ALERT [vault=%s id=%u]: %s", v->name, v->id, reason);
    catalog_save();
}

static void alert_check_escalation(Vault *v) {
    if (v->status != VAULT_STATUS_ALERT) return;

    time_t now = time(NULL);

    if (v->alert.last_alerted == 0) {
        /* First notification immediately */
        vault_log(LOG_ALERT, "REPEAT ALERT [%s] (count=%zu): %s",
                  v->name, ++v->alert.alert_count, v->alert.reason);

        /* Print to terminal */
        fprintf(stderr, "\n  *** VAULT ALERT *** [%s] %s\n\n", v->name, v->alert.reason);
        v->alert.last_alerted = now;
        return;
    }

    long interval = (v->alert.interval_idx < NUM_ALERT_INTERVALS)
                  ? ALERT_INTERVALS[v->alert.interval_idx]
                  : ALERT_INTERVALS[NUM_ALERT_INTERVALS - 1];

    if (now - v->alert.last_alerted >= interval) {
        v->alert.alert_count++;
        vault_log(LOG_ALERT, "REPEAT ALERT [%s] (count=%zu, interval=%lds): %s",
                  v->name, v->alert.alert_count, interval, v->alert.reason);
        fprintf(stderr, "\n  *** VAULT ALERT (×%zu) *** [%s] %s\n\n",
                v->alert.alert_count, v->name, v->alert.reason);

        v->alert.last_alerted = now;
        if (v->alert.interval_idx < NUM_ALERT_INTERVALS - 1)
            v->alert.interval_idx++;
    }
}

static VaultError alert_resolve(uint32_t id, const char *password) {
    Vault *v = vault_find_by_id(id);
    if (!v) return ERR_VAULT_NOT_FOUND;

    if (v->type == VAULT_TYPE_PROTECTED) {
        if (!password || !*password) return ERR_PASS_REQUIRED;
        VaultError err = auth_verify_password(v, password);
        if (err != ERR_OK) return err;
    }

    /* Clear modified flags */
    for (int b = 0; b < HASHMAP_BUCKETS; b++)
        for (FileEntry *e = v->hashmap.buckets[b]; e; e = e->next)
            e->modified = false;

    memset(&v->alert, 0, sizeof(v->alert));
    v->status = VAULT_STATUS_OK;

    vault_log(LOG_AUDIT, "Alert RESOLVED for vault '%s' (id=%u)", v->name, v->id);
    return catalog_save();
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 10: RULE ENGINE
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint32_t vault_id;
    int      max_failed_attempts;
    int      allowed_hour_from;   /* 0-23, -1 = no restriction */
    int      allowed_hour_to;
} VaultRule;

#define MAX_RULES 64
static VaultRule g_rules[MAX_RULES];
static uint32_t  g_rule_count = 0;

static void rule_add(uint32_t vault_id, int max_fails,
                     int hour_from, int hour_to) {
    if (g_rule_count >= MAX_RULES) {
        vault_log(LOG_WARN, "Rule table full");
        return;
    }
    g_rules[g_rule_count++] = (VaultRule){
        .vault_id            = vault_id,
        .max_failed_attempts = max_fails,
        .allowed_hour_from   = hour_from,
        .allowed_hour_to     = hour_to
    };
    vault_log(LOG_INFO, "Rule added for vault %u: max_fails=%d hours=%d-%d",
              vault_id, max_fails, hour_from, hour_to);
}

static void rule_evaluate(Vault *v) {
    for (uint32_t i = 0; i < g_rule_count; i++) {
        VaultRule *r = &g_rules[i];
        if (r->vault_id != v->id) continue;

        /* Rule: too many failed attempts → lock */
        if (r->max_failed_attempts > 0 &&
            v->failed_attempts >= r->max_failed_attempts &&
            v->status != VAULT_STATUS_LOCKED) {
            v->status = VAULT_STATUS_LOCKED;
            vault_log(LOG_ALERT, "[RULE] Vault '%s' LOCKED: %d failed attempts",
                      v->name, v->failed_attempts);
            catalog_save();
        }

        /* Rule: access outside allowed time window */
        if (r->allowed_hour_from >= 0 && r->allowed_hour_to >= 0) {
            time_t now = time(NULL);
            struct tm *tm = localtime(&now);
            int hour = tm->tm_hour;
            bool in_window = (r->allowed_hour_from <= r->allowed_hour_to)
                           ? (hour >= r->allowed_hour_from && hour < r->allowed_hour_to)
                           : (hour >= r->allowed_hour_from || hour < r->allowed_hour_to);
            if (!in_window) {
                char reason[256];
                snprintf(reason, sizeof(reason),
                         "Access outside allowed time window (%02d:00-%02d:00), current hour=%02d",
                         r->allowed_hour_from, r->allowed_hour_to, hour);
                alert_trigger(v, reason);
            }
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 11: INOTIFY MONITOR THREAD
 * ═══════════════════════════════════════════════════════════════════════════ */

static void monitor_add_vault_watches(MonitorCtx *ctx) {
    for (uint32_t i = 0; i < ctx->catalog->count; i++) {
        Vault *v = &ctx->catalog->vaults[i];
        if (v->status == VAULT_STATUS_DELETED) continue;
        if (v->inotify_wd >= 0) continue;

        v->inotify_wd = inotify_add_watch(
            ctx->inotify_fd, v->path,
            IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO
        );

        if (v->inotify_wd < 0)
            vault_log(LOG_WARN, "inotify_add_watch '%s': %s", v->path, strerror(errno));
        else
            vault_log(LOG_INFO, "inotify watching vault '%s' (wd=%d)", v->name, v->inotify_wd);
    }
}

static Vault *monitor_vault_by_wd(MonitorCtx *ctx, int wd) {
    for (uint32_t i = 0; i < ctx->catalog->count; i++)
        if (ctx->catalog->vaults[i].inotify_wd == wd)
            return &ctx->catalog->vaults[i];
    return NULL;
}

static void *monitor_thread(void *arg) {
    MonitorCtx *ctx = (MonitorCtx *)arg;
    char buf[INOTIFY_BUFSZ] __attribute__((aligned(8)));

    vault_log(LOG_INFO, "Monitor thread started (inotify fd=%d)", ctx->inotify_fd);

    /* Initial scan */
    pthread_mutex_lock(&ctx->lock);
    monitor_add_vault_watches(ctx);
    for (uint32_t i = 0; i < ctx->catalog->count; i++)
        monitor_scan_vault(&ctx->catalog->vaults[i]);
    pthread_mutex_unlock(&ctx->lock);

    while (ctx->running) {
        /* Use select() so we can timeout and check alerts */
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctx->inotify_fd, &rfds);
        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};

        int ret = select(ctx->inotify_fd + 1, &rfds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR) continue;
            vault_log(LOG_ERROR, "monitor select(): %s", strerror(errno));
            break;
        }

        pthread_mutex_lock(&ctx->lock);

        if (ret > 0 && FD_ISSET(ctx->inotify_fd, &rfds)) {
            ssize_t len = read(ctx->inotify_fd, buf, INOTIFY_BUFSZ);
            if (len < 0) {
                if (errno != EAGAIN)
                    vault_log(LOG_ERROR, "inotify read: %s", strerror(errno));
            } else {
                /* Process events */
                char *ptr = buf;
                while (ptr < buf + len) {
                    struct inotify_event *ev = (struct inotify_event *)ptr;

                    Vault *v = monitor_vault_by_wd(ctx, ev->wd);
                    if (v) {
                        const char *evname = (ev->len > 0) ? ev->name : "(unknown)";

                        if (ev->mask & IN_MODIFY) {
                            vault_log(LOG_ALERT, "[%s] inotify: MODIFIED %s", v->name, evname);
                            monitor_scan_vault(v);
                        } else if (ev->mask & IN_CREATE) {
                            vault_log(LOG_INFO, "[%s] inotify: CREATED %s", v->name, evname);
                            monitor_scan_vault(v);
                        } else if (ev->mask & (IN_DELETE | IN_MOVED_FROM)) {
                            vault_log(LOG_ALERT, "[%s] inotify: DELETED/MOVED %s", v->name, evname);
                            char reason[256];
                            snprintf(reason, sizeof(reason), "File deleted/moved: %s", evname);
                            alert_trigger(v, reason);
                        }
                        rule_evaluate(v);
                    }

                    ptr += sizeof(struct inotify_event) + ev->len;
                }
            }
        }

        /* Periodic alert escalation check */
        for (uint32_t i = 0; i < ctx->catalog->count; i++)
            alert_check_escalation(&ctx->catalog->vaults[i]);

        /* Re-add watches for new vaults */
        monitor_add_vault_watches(ctx);

        pthread_mutex_unlock(&ctx->lock);
    }

    vault_log(LOG_INFO, "Monitor thread stopped");
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 12: SANDBOX v2 — DiamondVault Hardened Sandbox Architecture
 *
 *  Princípios:
 *    - Defense in Depth   (5 camadas independentes)
 *    - Least Privilege    (menor privilégio em cada camada)
 *    - Deny by Default    (seccomp: tudo bloqueado exceto allowlist)
 *    - Fail Closed        (qualquer falha → _exit(1) imediato)
 *    - Auditabilidade     (todos os passos logados em LOG_AUDIT)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_drop_caps():
 *   Remove todas as Linux Capabilities do processo filho.
 *   Após isso, mesmo rodando como UID 0 dentro do namespace,
 *   o processo não tem nenhum poder especial sobre o host.
 *
 *   Sequência obrigatória:
 *     1. cap_set_proc(empty) via libcap — limpa effective + permitted
 *     2. prctl(PR_SET_KEEPCAPS, 0)     — impede recuperação via setuid
 *     3. prctl(PR_SET_NO_NEW_PRIVS, 1) — impede escalada futura
 * ───────────────────────────────────────────────────────────────────────── */
static int sandbox_drop_caps(void) {
    /* Passo 1: zerar todas as capabilities via libcap
     * Limpa effective, permitted e inheritable de uma vez */
    cap_t empty = cap_init();
    if (empty == NULL) {
        perror("[SANDBOX] cap_init");
        return -1;
    }

    if (cap_set_proc(empty) != 0) {
        perror("[SANDBOX] cap_set_proc");
        cap_free(empty);
        return -1;
    }
    cap_free(empty);

    /* Passo 2: impedir recuperação de caps via setuid
     * sem isso, um exec() posterior poderia restaurar capabilities */
    if (prctl(PR_SET_KEEPCAPS, 0) != 0) {
        perror("[SANDBOX] PR_SET_KEEPCAPS");
        return -1;
    }

    /* Passo 3: impedir escalada futura de privilégio
     * deve ser chamado ANTES do seccomp — o seccomp bloqueia prctl depois */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("[SANDBOX] PR_SET_NO_NEW_PRIVS");
        return -1;
    }

    /* Verificação: confirmar que ficou vazio de fato */
    cap_t check = cap_get_proc();
    if (check != NULL) {
        char *text = cap_to_text(check, NULL);
        if (text && strcmp(text, "=") != 0) {
            fprintf(stderr, "[SANDBOX] caps residuais após drop: %s\n", text);
            cap_free(text);
            cap_free(check);
            return -1;
        }
        cap_free(text);
        cap_free(check);
    }

    return 0;
}

static int sandbox_pivot_root(const char *new_root) {
    if (new_root == NULL || new_root[0] == '\0') {
        fprintf(stderr, "[SANDBOX] pivot_root: new_root vazio\n");
        return -1;
    }

    int ret = -1;
    char oldroot[64] = ".sandbox_XXXXXX";

    /* Recurso 1: bind mount — precisa ser desfeito se algo falhar depois */
    if (mount(new_root, new_root, NULL, MS_BIND | MS_REC, NULL) != 0) {
        perror("[SANDBOX] mount MS_BIND");
        return -1;   /* nada para limpar ainda */
    }

    if (chdir(new_root) != 0) {
        perror("[SANDBOX] chdir new_root");
        goto cleanup_bind;
    }

    /* Recurso 2: diretório temporário com nome imprevisível */
    if (mkdtemp(oldroot) == NULL) {
        perror("[SANDBOX] mkdtemp oldroot");
        goto cleanup_bind;
    }

    /* Verificação extra: garantir que é dir real, não symlink plantado */
    struct stat st;
    if (lstat(oldroot, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "[SANDBOX] oldroot não é diretório real\n");
        rmdir(oldroot);
        goto cleanup_bind;
    }

    if (syscall(SYS_pivot_root, ".", oldroot) != 0) {
        perror("[SANDBOX] pivot_root");
        rmdir(oldroot);
        goto cleanup_bind;
    }

    char oldroot_abs[80];
    snprintf(oldroot_abs, sizeof(oldroot_abs), "/%s", oldroot);

    umount2(oldroot_abs, MNT_DETACH);  
    rmdir(oldroot_abs);

    if (chdir("/") != 0) {
        perror("[SANDBOX] chdir / após pivot_root");
        goto cleanup_bind;   /* bind mount já pivotado — melhor matar o processo */
    }

    ret = 0;   /* sucesso */
    goto done;

cleanup_bind:
    umount2(new_root, MNT_DETACH);

done:
    return ret;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_prepare_mounts():
 *   Monta sistemas de arquivos mínimos necessários para o shell funcionar.
 *
 *   - MS_PRIVATE em "/" evita propagação de qualquer mount ao host
 *   - /proc  → procfs privado (PID namespace próprio)
 *   - /tmp   → tmpfs volátil (64 MB máx, sem exec, sem suid)
 *
 *   Falhas em /proc e /tmp são não-fatais: o shell funciona sem eles,
 *   apenas com funcionalidade reduzida.
 * ───────────────────────────────────────────────────────────────────────── */
static void sandbox_prepare_mounts(void) {
    /* Torna todos os mounts privados — nenhuma propagação para o host */
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
        perror("sandbox: MS_PRIVATE / (non-fatal)");

    /* /proc: necessário para o shell consultar PID, status, etc. */
    if (mkdir("/proc", 0555) != 0 && errno != EEXIST)
        perror("sandbox: mkdir /proc (non-fatal)");

    if (mount("proc", "/proc", "proc",
              MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) != 0)
        perror("sandbox: mount /proc (non-fatal)");

    /* /tmp: tmpfs volátil, nunca persiste entre sessões */
    if (mkdir("/tmp", 01777) != 0 && errno != EEXIST)
        perror("sandbox: mkdir /tmp (non-fatal)");

    if (mount("tmpfs", "/tmp", "tmpfs",
              MS_NOSUID | MS_NODEV,
              SANDBOX_TMP_SIZE) != 0)
        perror("sandbox: mount /tmp (non-fatal)");
}

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_limit_resources():
 *   Aplica rlimits ao processo filho para prevenir DoS:
 *   - NPROC: máx 32 subprocessos (impede fork bomb)
 *   - AS:    máx 128 MB de memória virtual
 *   - FSIZE: máx 32 MB por arquivo criado dentro do sandbox
 *   - NOFILE: máx 64 descritores abertos simultaneamente
 * ───────────────────────────────────────────────────────────────────────── */
static void sandbox_limit_resources(void) {
    struct rlimit rl;

    /* Fork bomb protection */
    rl.rlim_cur = rl.rlim_max = 32;
    setrlimit(RLIMIT_NPROC, &rl);

    /* Memória virtual máxima */
    rl.rlim_cur = rl.rlim_max = 128 * 1024 * 1024; /* 128 MB */
    setrlimit(RLIMIT_AS, &rl);

    /* Tamanho máximo de arquivo */
    rl.rlim_cur = rl.rlim_max = 32 * 1024 * 1024;  /* 32 MB */
    setrlimit(RLIMIT_FSIZE, &rl);

    /* Descritores de arquivo */
    rl.rlim_cur = rl.rlim_max = 64;
    setrlimit(RLIMIT_NOFILE, &rl);
}

/* ─────────────────────────────────────────────────────────────────────────
 * apply_seccomp_policy() — DiamondVault Hardened Sandbox v2
 *
 * Última camada de defesa antes do execl().
 * Deve ser chamada APÓS PR_SET_NO_NEW_PRIVS já ter sido ativado.
 *
 * Estratégia:
 *   - Default: SCMP_ACT_KILL_PROCESS (mata o processo inteiro)
 *   - Allowlist mínima e justificada para um shell interativo seguro
 *   - Bloqueio explícito de syscalls perigosas
 *   - Uso de SCMP_ACT_LOG em algumas syscalls para auditoria durante testes
 *
 * Nota: Esta allowlist é intencionalmente restrita. Se o shell ficar muito
 * limitado, podemos afrouxar gradualmente após testes.
 * ───────────────────────────────────────────────────────────────────────── */
static int apply_seccomp_policy(void)
{
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
    if (!ctx) { perror("[SANDBOX] seccomp_init"); return -1; }

    /* I/O básico */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64), 0);

    /* Arquivos */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);       /* + adicionado */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);      /* + adicionado */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);        /* + adicionado */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);       /* + adicionado */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup3), 0);       /* + adicionado */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe), 0);       /* + adicionado */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe2), 0);      /* + adicionado */

    /* Diretórios */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rename), 0);

    /* Memória — malloc/free não funcionam sem isso */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);       /* + adicionado */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);     /* + adicionado */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);   /* + adicionado */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);        /* + adicionado */

    /* Processos e subprocessos — shell precisa de tudo isso */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork), 0);       /* + adicionado */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vfork), 0);      /* + adicionado */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);      /* + adicionado — fork interno do libc */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(waitid), 0);     /* + adicionado */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgrp), 0);    
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setpgid), 0);   
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsid), 0);     

    /* Sinais */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 0);      
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);     
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0); 
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigsuspend), 0); 

    /* Identidade — shell exibe usuário no prompt */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);    
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);     
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0); 
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0);   
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgroups), 0);

    /* Sincronização — futex é usado internamente pelo libc em qualquer malloc */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);    

    /* Inicialização do libc */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);  
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0); 
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0); 

    /* Tempo */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);

    /* ── Bloqueios explícitos ── */
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(ptrace), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(mount), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(umount2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(chroot), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(pivot_root), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(unshare), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(setuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(setgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(setns), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(capset), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(prctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(process_vm_readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(process_vm_writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(perf_event_open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(kexec_load), 0);

    int ret = seccomp_load(ctx);
    if (ret != 0) perror("[SANDBOX] seccomp_load");
    seccomp_release(ctx);
    return ret;
}
/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_write_uid_gid_map():
 *   Escreve uid_map e gid_map do User Namespace para mapear
 *   UID 0 (root dentro do sandbox) → SANDBOX_NOBODY_UID no host.
 *
 *   Deve ser chamada pelo PROCESSO PAI após fork() porque
 *   /proc/<pid>/uid_map só pode ser escrito pelo pai antes
 *   de o filho chamar execve().
 *
 *   Também escreve "deny" em /proc/<pid>/setgroups (obrigatório
 *   em kernels >= 3.19 antes de escrever gid_map).
 * ───────────────────────────────────────────────────────────────────────── */
static void sandbox_write_uid_gid_map(pid_t child_pid) {
    char path[256];
    char map[64];
    int  fd;

    /* setgroups: "deny" — obrigatório antes de escrever gid_map */
    snprintf(path, sizeof(path), "/proc/%d/setgroups", (int)child_pid);
    fd = open(path, O_WRONLY);
    if (fd >= 0) {
        write(fd, "deny", 4);
        close(fd);
    }

    /* uid_map: "0 <host_uid> 1"
     *   O UID 0 dentro do namespace mapeia para SANDBOX_NOBODY_UID no host */
    snprintf(path, sizeof(path), "/proc/%d/uid_map", (int)child_pid);
    snprintf(map,  sizeof(map),  "0 %d 1\n", SANDBOX_NOBODY_UID);
    fd = open(path, O_WRONLY);
    if (fd >= 0) {
        write(fd, map, strlen(map));
        close(fd);
    }

    /* gid_map: mesmo mapeamento para GID */
    snprintf(path, sizeof(path), "/proc/%d/gid_map", (int)child_pid);
    snprintf(map,  sizeof(map),  "0 %d 1\n", SANDBOX_NOBODY_GID);
    fd = open(path, O_WRONLY);
    if (fd >= 0) {
        write(fd, map, strlen(map));
        close(fd);
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 *  vault_prepare_jail():
 *   Prepara a estrutura mínima do jail dentro do vault->path
 *   para que o sandbox possa funcionar de forma autossuficiente.
 *
 *   Cria os diretórios necessários e o arquivo marcador
 *   .diamond_jail_ready — se já existir, retorna imediatamente
 *   (idempotente).
 *
 *   Nota: NÃO copia /bin/sh ou libs. Em cloud isso é feito
 *   pela imagem base. Em bare-metal o usuário deve garantir
 *   um /bin/sh estático dentro do vault ou usar busybox.
 * ───────────────────────────────────────────────────────────────────────── */
static void vault_prepare_jail(const char *vault_path) {
    char marker[VAULT_PATH_MAX];
    snprintf(marker, sizeof(marker), "%s/%s", vault_path, SANDBOX_JAIL_MARKER);

    /* Idempotente: se já foi preparado, sai */
    struct stat st;
    if (stat(marker, &st) == 0) return;

    vault_log(LOG_INFO, "[SANDBOX] Preparando jail em '%s'", vault_path);

    char dir[VAULT_PATH_MAX];
    const char *subdirs[] = { "proc", "tmp", "dev", "bin", "lib", "lib64", NULL };
    for (int i = 0; subdirs[i]; i++) {
        snprintf(dir, sizeof(dir), "%s/%s", vault_path, subdirs[i]);
        if (mkdir(dir, 0755) != 0 && errno != EEXIST)
            vault_log(LOG_WARN, "[SANDBOX] mkdir %s: %s", dir, strerror(errno));
    }

    /* /dev/null e /dev/zero mínimos (criados com mknod se root) */
    if (geteuid() == 0) {
        char dev_null[VAULT_PATH_MAX], dev_zero[VAULT_PATH_MAX];
        snprintf(dev_null, sizeof(dev_null), "%s/dev/null", vault_path);
        snprintf(dev_zero, sizeof(dev_zero), "%s/dev/zero", vault_path);
        if (stat(dev_null, &st) != 0)
            mknod(dev_null, S_IFCHR | 0666, makedev(1, 3));
        if (stat(dev_zero, &st) != 0)
            mknod(dev_zero, S_IFCHR | 0666, makedev(1, 5));
    }

    /* Marca o jail como pronto */
    int fd = open(marker, O_CREAT | O_WRONLY | O_TRUNC, 0400);
    if (fd >= 0) {
        write(fd, "DiamondVault Jail v2\n", 21);
        close(fd);
    }

    vault_log(LOG_AUDIT, "[SANDBOX] Jail preparado em '%s'", vault_path);
}

/* ─────────────────────────────────────────────────────────────────────────
 *  vault_sandbox_open() — DiamondVault Hardened Sandbox v2
 *
 *  Fluxo completo (5 camadas, Fail Closed):
 *
 *  PAI:
 *    1. Autenticação do vault
 *    2. Prepara estrutura do jail (idempotente)
 *    3. fork()
 *    4. Escreve uid_map/gid_map (User Namespace)
 *    5. waitpid() + auditoria
 *
 *  FILHO (sandbox):
 *    [Camada 1] unshare(CLONE_NEWUSER)         — User Namespace
 *    [Camada 2] unshare(CLONE_NEWNS|NEWPID)    — Mount + PID Namespace
 *    [Camada 3] sandbox_pivot_root()            — Pivot Root (> chroot)
 *    [Camada 3] sandbox_prepare_mounts()        — /proc + /tmp privados
 *    [Camada 4] sandbox_drop_caps()             — Drop caps + NO_NEW_PRIVS
 *    [Camada 4] sandbox_limit_resources()       — rlimits anti-DoS
 *    [Camada 5] apply_seccomp_policy()          — Seccomp-BPF (LAST STEP)
 *    execl("/bin/sh", "sh", "-i", NULL)
 * ───────────────────────────────────────────────────────────────────────── */
static VaultError vault_sandbox_open(Vault *v, const char *password) {
    if (!v) return ERR_INVALID_ARGS;

    /* ── Autenticação ─────────────────────────────── */
    if (v->type == VAULT_TYPE_PROTECTED) {
        if (!password || !*password) return ERR_PASS_REQUIRED;
        VaultError err = auth_verify_password(v, password);
        if (err != ERR_OK) return err;
    }

    if (v->path[0] == '\0') {
        vault_log(LOG_ERROR, "[SANDBOX] vault path vazio");
        return ERR_PATH_INVALID;
    }

    vault_log(LOG_AUDIT, "[SANDBOX] Iniciando DiamondVault Hardened Sandbox v2 "
              "para vault '%s' (id=%u)", v->name, v->id);

    /* ── Prepara jail (idempotente) ───────────────── */
    vault_prepare_jail(v->path);

    /* ── Pipe de sincronização — criado ANTES do fork ─
     * Garante que o filho espera o pai escrever uid_map/gid_map
     * antes de continuar. O pai fecha sync_pipe[1] como sinal. */
    int sync_pipe[2];
    if (pipe(sync_pipe) != 0) {
        vault_log(LOG_ERROR, "[SANDBOX] pipe falhou: %s", strerror(errno));
        return ERR_SYSTEM;
    }

    /* ── fork ─────────────────────────────────────── */
    pid_t pid = fork();
    if (pid < 0) {
        close(sync_pipe[0]);
        close(sync_pipe[1]);
        vault_log(LOG_ERROR, "[SANDBOX] fork falhou: %s", strerror(errno));
        return ERR_SYSTEM;
    }

    /* ════════════════════════════════════════════════
     *  PROCESSO PAI
     * ════════════════════════════════════════════════ */
    if (pid > 0) {
        close(sync_pipe[0]);              /* pai não lê — fecha lado leitura */

        /* Escreve uid/gid map enquanto filho está bloqueado no read() */
        sandbox_write_uid_gid_map(pid);

        close(sync_pipe[1]);              /* sinaliza filho: uid_map pronto */

        int status;
        waitpid(pid, &status, 0);

        if (WIFSIGNALED(status)) {
            vault_log(LOG_ALERT,
                "[SANDBOX] Sessão de '%s' terminada por sinal %d "
                "(possível violação de seccomp)",
                v->name, WTERMSIG(status));
        } else {
            vault_log(LOG_AUDIT,
                "[SANDBOX] Sessão de '%s' encerrada (exit %d)",
                v->name, WEXITSTATUS(status));
        }

        return ERR_OK;
    }

    /*
     *  PROCESSO FILHO — SANDBOX
     *  A partir daqui: Fail Closed em tudo
     */

    /* ── [Camada 1] User Namespace ────────────────────────────────────────
     * Cria namespace de usuário próprio. O processo passa a ter UID 0
     * DENTRO do namespace, mas mapeado para SANDBOX_NOBODY_UID no host
     * (via uid_map escrita pelo pai). */
    if (unshare(CLONE_NEWUSER) != 0) {
        fprintf(stderr, "[SANDBOX][FATAL] unshare(CLONE_NEWUSER): %s\n", strerror(errno));
        _exit(1);
    }

    /* Aguarda o pai escrever uid_map/gid_map.
     * O read() bloqueia até o pai fechar sync_pipe[1]. */
    {
        char c;
        close(sync_pipe[1]);          /* filho não escreve — fecha lado escrita */
        read(sync_pipe[0], &c, 1);    /* bloqueia aqui até pai sinalizar */
        close(sync_pipe[0]);
    }

    /* ── [Camada 2] Mount + PID Namespace ─────────────────────────────────
     * Cria namespace de mount e PID isolados. */
    if (unshare(CLONE_NEWNS | CLONE_NEWPID) != 0) {
        fprintf(stderr, "[SANDBOX][FATAL] unshare(CLONE_NEWNS|CLONE_NEWPID): %s\n",
                strerror(errno));
        _exit(1);
    }

    /* ── Fork adicional — entra de fato no PID namespace ─────────────────
     * unshare(CLONE_NEWPID) só afeta os FILHOS do processo atual, não ele
     * mesmo. Sem este fork, o shell execl'd ainda enxerga o PID NS do host.
     * O filho deste fork nasce como PID 1 dentro do novo namespace. */
    pid_t ns_pid = fork();
    if (ns_pid < 0) {
        fprintf(stderr, "[SANDBOX][FATAL] fork PID NS: %s\n", strerror(errno));
        _exit(1);
    }
    if (ns_pid > 0) {
        /* Processo intermediário: apenas repassa o exit code do shell */
        int st;
        waitpid(ns_pid, &st, 0);
        _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 1);
    }

    /* A partir daqui: este processo é PID 1 dentro do novo PID namespace */

    /* ── [Camada 3] Pivot Root ────────────────────────────────────────────
     * Torna vault->path a nova raiz real do processo.
     * O root antigo é desmontado com MNT_DETACH — impossível de acessar. */
    if (sandbox_pivot_root(v->path) != 0) {
        fprintf(stderr, "[SANDBOX][FATAL] pivot_root falhou\n");
        _exit(1);
    }

    /* ── [Camada 3b] Mounts mínimos e privados ────────────────────────────
     * /proc e /tmp dentro do novo root, MS_PRIVATE em tudo.
     * Falhas são não-fatais — shell funciona com funcionalidade reduzida. */
    sandbox_prepare_mounts();

    /* ── [Camada 4] Drop de capabilities + PR_SET_NO_NEW_PRIVS ───────────
     * Remove todas as Linux Capabilities. Mesmo com UID 0 dentro do
     * namespace, o processo não tem poder sobre o host após isso. */
    if (sandbox_drop_caps() != 0) {
        fprintf(stderr, "[SANDBOX][FATAL] drop de capabilities falhou\n");
        _exit(1);
    }

    /* ── [Camada 4b] Limites de recursos anti-DoS ─────────────────────── */
    sandbox_limit_resources();

    /* ── [Camada 5] Seccomp-BPF — ÚLTIMA camada, antes do exec ───────────
     * Depois deste ponto, qualquer syscall fora da allowlist mata o
     * processo com SCMP_ACT_KILL_PROCESS (irrecuperável).
     * PR_SET_NO_NEW_PRIVS já foi ativado em sandbox_drop_caps(). */
    if (apply_seccomp_policy() != 0) {
        fprintf(stderr, "[SANDBOX][FATAL] seccomp policy falhou\n");
        _exit(1);
    }

    /* ── Shell interativo dentro do ambiente fortemente isolado ─────────── */
    printf("\n");
    printf("  ┌─────────────────────────────────────────────────────────┐\n");
    printf("  │     DIAMONDVAULT HARDENED SANDBOX v2                    │\n");
    printf("  │     Vault : %-43s│\n", v->name);
    printf("  │     Isolamento: UserNS + PivotRoot + Caps + Seccomp-BPF│\n");
    printf("  │     Modo: Least Privilege · Deny by Default             │\n");
    printf("  │     Digite 'exit' para encerrar a sessão.               │\n");
    printf("  └─────────────────────────────────────────────────────────┘\n\n");

    execl("/bin/sh", "sh", "-i", NULL);

    /* Se chegar aqui, execl falhou — /bin/sh não existe no jail */
    fprintf(stderr,
        "[SANDBOX][FATAL] execl(/bin/sh) falhou: %s\n"
        "  Dica: coloque um /bin/sh estático (busybox) dentro do vault.\n",
        strerror(errno));
    _exit(127);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 13: INTERACTIVE CLI
 * ═══════════════════════════════════════════════════════════════════════════ */

static char *read_password_silent(const char *prompt) {
    struct termios old_t, new_t;
    static char buf[MAX_PASS_LEN];

    printf("%s", prompt);
    fflush(stdout);

    if (tcgetattr(STDIN_FILENO, &old_t) != 0) {
        /* Fallback: read normally */
        if (!fgets(buf, sizeof(buf), stdin)) return NULL;
        buf[strcspn(buf, "\n")] = '\0';
        return buf;
    }

    new_t = old_t;
    new_t.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_t);

    memset(buf, 0, sizeof(buf));
    if (fgets(buf, sizeof(buf), stdin)) {
        buf[strcspn(buf, "\n")] = '\0';
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
    printf("\n");
    return buf;
}

static void cmd_list(void) {
    printf("\n  ┌────────────────────────────────────────────────────────────────┐\n");
    printf("  │  CATALOG: %-20s  (%u vaults)              │\n",
           g_catalog.category, g_catalog.count);
    printf("  ├──────┬──────────────────────────┬────────────┬────────────┬────┤\n");
    printf("  │  ID  │  Name                    │  Type      │  Status    │ 🔑 │\n");
    printf("  ├──────┼──────────────────────────┼────────────┼────────────┼────┤\n");

    if (g_catalog.count == 0)
        printf("  │  (no vaults)                                                  │\n");

    for (uint32_t i = 0; i < g_catalog.count; i++) {
        Vault *v = &g_catalog.vaults[i];
        const char *status_s;
        switch (v->status) {
            case VAULT_STATUS_OK:      status_s = "OK      "; break;
            case VAULT_STATUS_LOCKED:  status_s = "LOCKED  "; break;
            case VAULT_STATUS_ALERT:   status_s = "ALERT   "; break;
            case VAULT_STATUS_DELETED: status_s = "DELETED "; break;
            default:                   status_s = "?       ";
        }
        printf("  │ %4u │ %-24s │ %-10s │ %-10s │ %s  │\n",
               v->id,
               v->name,
               v->type == VAULT_TYPE_PROTECTED ? "PROTECTED " : "NORMAL    ",
               status_s,
               v->has_pass ? "✓" : " ");
    }
    printf("  └──────┴──────────────────────────┴────────────┴────────────┴────┘\n\n");
}

static void cmd_info(uint32_t id) {
    Vault *v = vault_find_by_id(id);
    if (!v) { printf("  Vault #%u not found.\n", id); return; }

    char tbuf[32];
    struct tm *tm;

    printf("\n  ── Vault Info ──────────────────────────────────────\n");
    printf("  ID           : %u\n", v->id);
    printf("  Name         : %s\n", v->name);
    printf("  Type         : %s\n", v->type == VAULT_TYPE_PROTECTED ? "PROTECTED" : "NORMAL");
    printf("  Status       : ");
    switch (v->status) {
        case VAULT_STATUS_OK:      printf("OK\n");      break;
        case VAULT_STATUS_LOCKED:  printf("LOCKED\n");  break;
        case VAULT_STATUS_ALERT:   printf("ALERT\n");   break;
        case VAULT_STATUS_DELETED: printf("DELETED\n"); break;
    }
    printf("  Password     : %s\n", v->has_pass ? "Yes" : "No");
    printf("  Path         : %s\n", v->path);

    tm = localtime(&v->created_at);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm);
    printf("  Created      : %s\n", tbuf);

    tm = localtime(&v->last_check);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm);
    printf("  Last check   : %s\n", tbuf);

    printf("  Files tracked: %zu\n", v->hashmap.count);
    printf("  Fail attempts: %d\n", v->failed_attempts);

    if (v->status == VAULT_STATUS_ALERT) {
        printf("  Alert reason : %s\n", v->alert.reason);
        printf("  Alert count  : %zu\n", v->alert.alert_count);
    }
    printf("  ────────────────────────────────────────────────────\n\n");
}

static void cmd_files(uint32_t id) {
    Vault *v = vault_find_by_id(id);
    if (!v) { printf("  Vault #%u not found.\n", id); return; }

    printf("\n  Files in vault '%s':\n", v->name);
    printf("  %-40s  %-16s  %s\n", "Filename", "Last seen", "Modified");
    printf("  %s\n", "─────────────────────────────────────────────────────────────────");

    bool any = false;
    for (int b = 0; b < HASHMAP_BUCKETS; b++) {
        for (FileEntry *e = v->hashmap.buckets[b]; e; e = e->next) {
            char tbuf[32];
            struct tm *tm = localtime(&e->last_seen);
            strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M", tm);
            printf("  %-40s  %-16s  %s\n",
                   e->filename, tbuf,
                   e->modified ? "YES ⚠" : "no");
            any = true;
        }
    }
    if (!any) printf("  (no files tracked)\n");
    printf("\n");
}

static void cmd_encrypt_vault(uint32_t id) {
    Vault *v = vault_find_by_id(id);
    if (!v) { printf("  Vault #%u not found.\n", id); return; }

    if (!v->has_pass) {
        printf("  Error: vault '%s' has no password. Set a password first.\n", v->name);
        return;
    }

    char *pass = read_password_silent("  Enter vault password: ");
    if (auth_verify_password(v, pass) != ERR_OK) {
        printf("  Authentication failed.\n");
        return;
    }

    uint8_t key[KEY_LEN];
    if (derive_key(pass, v->salt, key) != ERR_OK) {
        printf("  Key derivation failed.\n");
        return;
    }
    explicit_bzero(pass, strlen(pass));

    /* Encrypt every file in the vault */
    DIR *dir = opendir(v->path);
    if (!dir) { printf("  Cannot open vault path.\n"); return; }

    struct dirent *de;
    int count = 0;
    char inpath[VAULT_PATH_MAX + NAME_MAX + 2];
    char outpath[VAULT_PATH_MAX + NAME_MAX + 10];

    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') continue;
        /* Skip already-encrypted files (.enc) */
        size_t nlen = strlen(de->d_name);
        if (nlen > 4 && strcmp(de->d_name + nlen - 4, ".enc") == 0) continue;

        snprintf(inpath,  sizeof(inpath),  "%s/%s",     v->path, de->d_name);
        snprintf(outpath, sizeof(outpath), "%s/%s.enc", v->path, de->d_name);

        struct stat st;
        if (stat(inpath, &st) != 0 || !S_ISREG(st.st_mode)) continue;

        if (encrypt_file(inpath, outpath, key) == ERR_OK) {
            unlink(inpath);
            count++;
            printf("  Encrypted: %s → %s.enc\n", de->d_name, de->d_name);
        } else {
            printf("  FAILED:    %s\n", de->d_name);
        }
    }
    closedir(dir);
    explicit_bzero(key, KEY_LEN);
    vault_log(LOG_AUDIT, "Vault '%s': encrypted %d files", v->name, count);
    printf("  Done. %d file(s) encrypted.\n\n", count);
}

static void cmd_decrypt_vault(uint32_t id) {
    Vault *v = vault_find_by_id(id);
    if (!v) { printf("  Vault #%u not found.\n", id); return; }

    if (!v->has_pass) {
        printf("  Error: vault '%s' has no password.\n", v->name);
        return;
    }

    char *pass = read_password_silent("  Enter vault password: ");
    if (auth_verify_password(v, pass) != ERR_OK) {
        printf("  Authentication failed.\n");
        return;
    }

    uint8_t key[KEY_LEN];
    if (derive_key(pass, v->salt, key) != ERR_OK) {
        printf("  Key derivation failed.\n");
        return;
    }
    explicit_bzero(pass, strlen(pass));

    DIR *dir = opendir(v->path);
    if (!dir) { printf("  Cannot open vault path.\n"); return; }

    struct dirent *de;
    int count = 0;
    char inpath[VAULT_PATH_MAX + NAME_MAX + 2];
    char outpath[VAULT_PATH_MAX + NAME_MAX + 2];

    while ((de = readdir(dir)) != NULL) {
        size_t nlen = strlen(de->d_name);
        if (nlen <= 4 || strcmp(de->d_name + nlen - 4, ".enc") != 0) continue;

        snprintf(inpath, sizeof(inpath), "%s/%s", v->path, de->d_name);

        /* Output name: strip .enc */
        snprintf(outpath, sizeof(outpath), "%s/%.*s", v->path,
                 (int)(nlen - 4), de->d_name);

        struct stat st;
        if (stat(inpath, &st) != 0 || !S_ISREG(st.st_mode)) continue;

        if (decrypt_file(inpath, outpath, key) == ERR_OK) {
            unlink(inpath);
            count++;
            printf("  Decrypted: %s\n", outpath);
        } else {
            printf("  FAILED:    %s (wrong key or corrupt)\n", de->d_name);
        }
    }
    closedir(dir);
    explicit_bzero(key, KEY_LEN);
    vault_log(LOG_AUDIT, "Vault '%s': decrypted %d files", v->name, count);
    printf("  Done. %d file(s) decrypted.\n\n", count);
}

static void cmd_scan(uint32_t id) {
    Vault *v = vault_find_by_id(id);
    if (!v) { printf("  Vault #%u not found.\n", id); return; }

    pthread_mutex_lock(&g_monitor.lock);
    monitor_scan_vault(v);
    pthread_mutex_unlock(&g_monitor.lock);
    catalog_save();
    printf("  Scan complete for vault '%s'. Files: %zu\n\n", v->name, v->hashmap.count);
}

static void cmd_help(void) {
    printf("\n");
    printf("  ╔══════════════════════════════════════════════════════════════╗\n");
    printf("  ║           VAULT SECURITY SYSTEM  –  Commands                ║\n");
    printf("  ╠══════════════════════════════════════════════════════════════╣\n");
    printf("  ║  list                         List all vaults               ║\n");
    printf("  ║  info <id>                    Show vault details            ║\n");
    printf("  ║  files <id>                   Show tracked files            ║\n");
    printf("  ║                                                              ║\n");
    printf("  ║  create [name] [path] [type]  Create vault                  ║\n");
    printf("  ║    type: normal | protected                                  ║\n");
    printf("  ║  delete <id>                  Delete vault                  ║\n");
    printf("  ║  rename <id> <new_name>       Rename vault                  ║\n");
    printf("  ║  unlock <id>                  Unlock locked vault           ║\n");
    printf("  ║  passwd <id>                  Change password               ║\n");
    printf("  ║                                                              ║\n");
    printf("  ║  encrypt <id>                 Encrypt vault files (AES-256) ║\n");
    printf("  ║  decrypt <id>                 Decrypt vault files           ║\n");
    printf("  ║  scan <id>                    Force integrity scan          ║\n");
    printf("  ║  resolve <id>                 Resolve alert for vault       ║\n");
    printf("  ║                                                              ║\n");
    printf("  ║  rule <id> <max_fails> [h_from h_to]  Add security rule     ║\n");
    printf("  ║  sandbox <id>                 Open vault in sandbox shell   ║\n");
    printf("  ║                                                              ║\n");
    printf("  ║  verbose                      Toggle verbose logging        ║\n");
    printf("  ║  help                         Show this help                ║\n");
    printf("  ║  quit / exit                  Exit                         ║\n");
    printf("  ╚══════════════════════════════════════════════════════════════╝\n\n");
}

/* Token parser: handles quoted strings, strips quotes */
#define MAX_TOKENS 16
static int tokenize(char *line, char *tokens[], int max) {
    int count = 0;
    char *p = line;

    while (*p && count < max) {
        /* Skip whitespace */
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        char *start;
        if (*p == '"' || *p == '\'') {
            char quote = *p++;
            start = p;
            while (*p && *p != quote) p++;
            if (*p) *p++ = '\0';
        } else {
            start = p;
            while (*p && *p != ' ' && *p != '\t') p++;
            if (*p) *p++ = '\0';
        }
        tokens[count++] = start;
    }
    return count;
}

static void process_command(char *line) {
    if (!line || !*line) return;

    /* Trim newline */
    line[strcspn(line, "\n\r")] = '\0';
    if (!*line) return;

    char *tokens[MAX_TOKENS];
    int   n = tokenize(line, tokens, MAX_TOKENS);
    if (n == 0) return;

    char *cmd = tokens[0];

    /* ── list ─────────────────────────────────────── */
    if (strcmp(cmd, "list") == 0) {
        cmd_list();
    }
    /* ── info ─────────────────────────────────────── */
    else if (strcmp(cmd, "info") == 0) {
        if (n < 2) { printf("  Usage: info <id>\n"); return; }
        uint32_t id = (uint32_t)atoi(tokens[1]);
        cmd_info(id);
    }
    /* ── files ────────────────────────────────────── */
    else if (strcmp(cmd, "files") == 0) {
        if (n < 2) { printf("  Usage: files <id>\n"); return; }
        cmd_files((uint32_t)atoi(tokens[1]));
    }
    /* ── create ───────────────────────────────────── */
    else if (strcmp(cmd, "create") == 0) {
        char *name = (n >= 2) ? tokens[1] : NULL;
        char *path = (n >= 3) ? tokens[2] : NULL;
        char *type = (n >= 4) ? tokens[3] : NULL;

        VaultType vtype = VAULT_TYPE_NORMAL;
        if (type && strcmp(type, "protected") == 0)
            vtype = VAULT_TYPE_PROTECTED;

        char *password = NULL;
        char pass_buf[MAX_PASS_LEN] = {0};
        if (vtype == VAULT_TYPE_PROTECTED) {
            char *p1 = read_password_silent("  Set vault password: ");
            if (!p1 || !*p1) { printf("  Password required.\n"); return; }
            strncpy(pass_buf, p1, MAX_PASS_LEN - 1);
            char *p2 = read_password_silent("  Confirm password  : ");
            if (!p2 || strcmp(pass_buf, p2) != 0) {
                printf("  Passwords do not match.\n");
                explicit_bzero(pass_buf, sizeof(pass_buf));
                return;
            }
            password = pass_buf;
        }

        pthread_mutex_lock(&g_monitor.lock);
        VaultError err = vault_create(name, vtype, path, password);
        pthread_mutex_unlock(&g_monitor.lock);
        explicit_bzero(pass_buf, sizeof(pass_buf));

        if (err != ERR_OK)
            printf("  Error: %s\n", vault_strerror(err));
    }
    /* ── delete ───────────────────────────────────── */
    else if (strcmp(cmd, "delete") == 0) {
        if (n < 2) { printf("  Usage: delete <id>\n"); return; }
        uint32_t id = (uint32_t)atoi(tokens[1]);

        Vault *v = vault_find_by_id(id);
        if (!v) { printf("  Vault #%u not found.\n", id); return; }

        printf("  Delete vault '%s' (id=%u)? [yes/no]: ", v->name, id);
        char confirm[8] = {0};
        if (!fgets(confirm, sizeof(confirm), stdin)) return;
        confirm[strcspn(confirm, "\n")] = '\0';
        if (strcmp(confirm, "yes") != 0) { printf("  Cancelled.\n"); return; }

        char *pass = NULL;
        char pass_buf[MAX_PASS_LEN] = {0};
        if (v->type == VAULT_TYPE_PROTECTED) {
            pass = read_password_silent("  Enter password: ");
            strncpy(pass_buf, pass, MAX_PASS_LEN - 1);
            pass = pass_buf;
        }

        pthread_mutex_lock(&g_monitor.lock);
        VaultError err = vault_delete(id, pass);
        pthread_mutex_unlock(&g_monitor.lock);
        explicit_bzero(pass_buf, sizeof(pass_buf));

        if (err == ERR_OK)
            printf("  Vault deleted.\n");
        else
            printf("  Error: %s\n", vault_strerror(err));
    }
    /* ── rename ───────────────────────────────────── */
    else if (strcmp(cmd, "rename") == 0) {
        if (n < 3) { printf("  Usage: rename <id> <new_name>\n"); return; }
        uint32_t id = (uint32_t)atoi(tokens[1]);
        char *pass = NULL;
        char pass_buf[MAX_PASS_LEN] = {0};

        Vault *v = vault_find_by_id(id);
        if (v && v->type == VAULT_TYPE_PROTECTED) {
            pass = read_password_silent("  Enter password: ");
            strncpy(pass_buf, pass, MAX_PASS_LEN - 1);
            pass = pass_buf;
        }

        VaultError err = vault_rename(id, tokens[2], pass);
        explicit_bzero(pass_buf, sizeof(pass_buf));
        if (err == ERR_OK)
            printf("  Vault renamed.\n");
        else
            printf("  Error: %s\n", vault_strerror(err));
    }
    /* ── unlock ───────────────────────────────────── */
    else if (strcmp(cmd, "unlock") == 0) {
        if (n < 2) { printf("  Usage: unlock <id>\n"); return; }
        uint32_t id = (uint32_t)atoi(tokens[1]);
        char *pass = read_password_silent("  Enter password: ");
        char pass_buf[MAX_PASS_LEN] = {0};
        strncpy(pass_buf, pass, MAX_PASS_LEN - 1);

        VaultError err = vault_unlock(id, pass_buf);
        explicit_bzero(pass_buf, sizeof(pass_buf));
        if (err == ERR_OK) printf("  Vault unlocked.\n");
        else printf("  Error: %s\n", vault_strerror(err));
    }
    /* ── passwd ───────────────────────────────────── */
    else if (strcmp(cmd, "passwd") == 0) {
        if (n < 2) { printf("  Usage: passwd <id>\n"); return; }
        uint32_t id = (uint32_t)atoi(tokens[1]);

        char old_buf[MAX_PASS_LEN] = {0}, new_buf[MAX_PASS_LEN] = {0}, cnf_buf[MAX_PASS_LEN] = {0};
        char *p;

        p = read_password_silent("  Current password : "); strncpy(old_buf, p, MAX_PASS_LEN - 1);
        p = read_password_silent("  New password     : "); strncpy(new_buf, p, MAX_PASS_LEN - 1);
        p = read_password_silent("  Confirm new      : "); strncpy(cnf_buf, p, MAX_PASS_LEN - 1);

        if (strcmp(new_buf, cnf_buf) != 0) {
            printf("  Passwords do not match.\n");
        } else {
            VaultError err = vault_change_password(id, old_buf, new_buf);
            if (err == ERR_OK) printf("  Password changed.\n");
            else printf("  Error: %s\n", vault_strerror(err));
        }
        explicit_bzero(old_buf, sizeof(old_buf));
        explicit_bzero(new_buf, sizeof(new_buf));
        explicit_bzero(cnf_buf, sizeof(cnf_buf));
    }
    /* ── encrypt ──────────────────────────────────── */
    else if (strcmp(cmd, "encrypt") == 0) {
        if (n < 2) { printf("  Usage: encrypt <id>\n"); return; }
        cmd_encrypt_vault((uint32_t)atoi(tokens[1]));
    }
    /* ── decrypt ──────────────────────────────────── */
    else if (strcmp(cmd, "decrypt") == 0) {
        if (n < 2) { printf("  Usage: decrypt <id>\n"); return; }
        cmd_decrypt_vault((uint32_t)atoi(tokens[1]));
    }
    /* ── scan ─────────────────────────────────────── */
    else if (strcmp(cmd, "scan") == 0) {
        if (n < 2) { printf("  Usage: scan <id>\n"); return; }
        cmd_scan((uint32_t)atoi(tokens[1]));
    }
    /* ── resolve ──────────────────────────────────── */
    else if (strcmp(cmd, "resolve") == 0) {
        if (n < 2) { printf("  Usage: resolve <id>\n"); return; }
        uint32_t id = (uint32_t)atoi(tokens[1]);
        char *pass = NULL;
        char pass_buf[MAX_PASS_LEN] = {0};
        Vault *v = vault_find_by_id(id);
        if (v && v->type == VAULT_TYPE_PROTECTED) {
            pass = read_password_silent("  Enter password: ");
            strncpy(pass_buf, pass, MAX_PASS_LEN - 1);
            pass = pass_buf;
        }
        VaultError err = alert_resolve(id, pass);
        explicit_bzero(pass_buf, sizeof(pass_buf));
        if (err == ERR_OK) printf("  Alert resolved.\n");
        else printf("  Error: %s\n", vault_strerror(err));
    }
    /* ── rule ─────────────────────────────────────── */
    else if (strcmp(cmd, "rule") == 0) {
        if (n < 3) {
            printf("  Usage: rule <vault_id> <max_fails> [hour_from hour_to]\n");
            printf("  Example: rule 1 3 9 18   (lock after 3 fails, alert outside 09-18)\n");
            return;
        }
        uint32_t id   = (uint32_t)atoi(tokens[1]);
        int max_fails = atoi(tokens[2]);
        int hf = -1, ht = -1;
        if (n >= 5) { hf = atoi(tokens[3]); ht = atoi(tokens[4]); }
        rule_add(id, max_fails, hf, ht);
        printf("  Rule added for vault #%u.\n", id);
    }
    /* ── sandbox ──────────────────────────────────── */
    else if (strcmp(cmd, "sandbox") == 0) {
        if (n < 2) { printf("  Usage: sandbox <id>\n"); return; }
        uint32_t id = (uint32_t)atoi(tokens[1]);
        Vault *v = vault_find_by_id(id);
        if (!v) { printf("  Vault not found.\n"); return; }

        char *pass = NULL;
        char pass_buf[MAX_PASS_LEN] = {0};
        if (v->type == VAULT_TYPE_PROTECTED) {
            pass = read_password_silent("  Enter password: ");
            strncpy(pass_buf, pass, MAX_PASS_LEN - 1);
            pass = pass_buf;
        }
        vault_sandbox_open(v, pass);
        explicit_bzero(pass_buf, sizeof(pass_buf));
    }
    /* ── verbose ──────────────────────────────────── */
    else if (strcmp(cmd, "verbose") == 0) {
        g_verbose = !g_verbose;
        printf("  Verbose logging: %s\n", g_verbose ? "ON" : "OFF");
    }
    /* ── help ─────────────────────────────────────── */
    else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
        cmd_help();
    }
    /* ── quit ─────────────────────────────────────── */
    else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) {
        /* handled in main loop */
    }
    else {
        printf("  Unknown command: '%s'  (type 'help' for list)\n", cmd);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SECTION 14: INIT / SHUTDOWN / MAIN
 * ═══════════════════════════════════════════════════════════════════════════ */

static volatile bool g_running = true;

static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        vault_log(LOG_INFO, "Signal %d received, shutting down...", sig);
        g_running        = false;
        g_monitor.running = false;
    }
}

static VaultError system_init(void) {
    /* Create catalog directory */
    struct stat st;
    if (stat(VAULT_CATALOG_PATH, &st) != 0) {
        if (mkdir(VAULT_CATALOG_PATH, 0700) != 0 && errno != EEXIST) {
            fprintf(stderr, "Cannot create catalog dir %s: %s\n",
                    VAULT_CATALOG_PATH, strerror(errno));
            return ERR_IO;
        }
    }

    log_init();
    vault_log(LOG_INFO, "=== Vault Security System starting ===");

    /* OpenSSL init */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Load catalog */
    VaultError err = catalog_load();
    if (err != ERR_OK) return err;

    /* Init monitor */
    g_monitor.catalog    = &g_catalog;
    g_monitor.running    = true;
    g_monitor.inotify_fd = inotify_init1(IN_NONBLOCK);

    if (g_monitor.inotify_fd < 0) {
        vault_log(LOG_ERROR, "inotify_init1: %s", strerror(errno));
        return ERR_SYSTEM;
    }

    if (pthread_mutex_init(&g_monitor.lock, NULL) != 0) {
        vault_log(LOG_ERROR, "pthread_mutex_init failed");
        return ERR_SYSTEM;
    }

    /* Signals */
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    return ERR_OK;
}

static void system_shutdown(pthread_t monitor_tid) {
    g_monitor.running = false;
    pthread_join(monitor_tid, NULL);

    pthread_mutex_destroy(&g_monitor.lock);
    close(g_monitor.inotify_fd);
    catalog_save();

    /* Wipe catalog from memory */
    for (uint32_t i = 0; i < g_catalog.count; i++) {
        Vault *v = &g_catalog.vaults[i];
        explicit_bzero(v->salt, SALT_LEN);
        explicit_bzero(v->pass_hash, SHA256_DIGEST_LENGTH);
        hashmap_clear(&v->hashmap);
    }
    explicit_bzero(&g_catalog, sizeof(g_catalog));

    EVP_cleanup();
    ERR_free_strings();

    if (g_logfp) {
        vault_log(LOG_INFO, "=== Vault Security System stopped ===");
        fclose(g_logfp);
    }
}

static void print_banner(void) {
    printf("\n");
    printf("  ╔══════════════════════════════════════════════════════════════╗\n");
    printf("  ║                                                              ║\n");
    printf("  ║   ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗                 ║\n");
    printf("  ║   ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝                 ║\n");
    printf("  ║   ██║   ██║███████║██║   ██║██║     ██║                     ║\n");
    printf("  ║   ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║                     ║\n");
    printf("  ║    ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║                     ║\n");
    printf("  ║     ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝                    ║\n");
    printf("  ║          SECURITY SYSTEM  –  Diamond Catalog                ║\n");
    printf("  ║      AES-256 | SHA-256 | PBKDF2 | inotify | pthreads       ║\n");
    printf("  ╚══════════════════════════════════════════════════════════════╝\n");
    printf("  Type 'help' for available commands.\n\n");
}

int main(int argc, char *argv[]) {
    /* Optional: --verbose flag */
    for (int i = 1; i < argc; i++) {
        char *a = sanitize_arg(argv[i]);
        if (strcmp(a, "--verbose") == 0 || strcmp(a, "-v") == 0)
            g_verbose = true;
        else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            printf("Usage: %s [--verbose] [--help]\n", argv[0]);
            printf("  Interactive vault security system.\n");
            return 0;
        }
    }

    VaultError err = system_init();
    if (err != ERR_OK) {
        fprintf(stderr, "Initialization failed: %s\n", vault_strerror(err));
        return 1;
    }

    /* Start monitor thread */
    pthread_t monitor_tid;
    if (pthread_create(&monitor_tid, NULL, monitor_thread, &g_monitor) != 0) {
        fprintf(stderr, "Failed to start monitor thread: %s\n", strerror(errno));
        return 1;
    }

    print_banner();

    /* Interactive REPL */
    char line[1024];
    while (g_running) {
        printf("vault> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            if (feof(stdin)) break;
            if (errno == EINTR) continue;
            break;
        }

        char *trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        trimmed[strcspn(trimmed, "\n\r")] = '\0';

        if (strcmp(trimmed, "quit") == 0 || strcmp(trimmed, "exit") == 0) {
            printf("  Goodbye ;D.\n\n");
            break;
        }

        process_command(trimmed);
    }

    system_shutdown(monitor_tid);
    return 0;
}
