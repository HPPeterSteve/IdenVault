#define FUSE_USE_VERSION 31
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>

#include "vault_core.h"

/* Helper to map virtual path to cipher_path */
static void get_cipher_path(char *out_path, const char *path) {
    Vault *v = (Vault *)fuse_get_context()->private_data;
    if (v) {
        snprintf(out_path, VAULT_PATH_MAX, "%s%s", v->cipher_path, path);
    } else {
        out_path[0] = '\0';
    }
}

static int vfuse_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void) fi;
    char full_path[VAULT_PATH_MAX];
    get_cipher_path(full_path, path);

    int res = lstat(full_path, stbuf);
    if (res == -1)
        return -errno;

    /* For WORM simulation or read-only view, we could modify stbuf->st_mode here.
       But we'll keep real attributes and just block unlink/rename. */
    return 0;
}

static int vfuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    (void) offset;
    (void) fi;
    (void) flags;

    char full_path[VAULT_PATH_MAX];
    get_cipher_path(full_path, path);

    DIR *dp = opendir(full_path);
    if (dp == NULL)
        return -errno;

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, 0))
            break;
    }
    closedir(dp);
    return 0;
}

static int vfuse_open(const char *path, struct fuse_file_info *fi) {
    char full_path[VAULT_PATH_MAX];
    get_cipher_path(full_path, path);

    int res = open(full_path, fi->flags);
    if (res == -1)
        return -errno;

    close(res);
    return 0;
}

static int vfuse_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    char full_path[VAULT_PATH_MAX];
    get_cipher_path(full_path, path);
    
    (void) fi;
    int fd = open(full_path, O_RDONLY);
    if (fd == -1)
        return -errno;

    int res = pread(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    /* TODO: On-the-fly decryption should happen here using vault_crypto.c primitives */

    close(fd);
    return res;
}

static int vfuse_write(const char *path, const char *buf, size_t size, off_t offset,
                       struct fuse_file_info *fi) {
    char full_path[VAULT_PATH_MAX];
    get_cipher_path(full_path, path);
    
    (void) fi;
    int fd = open(full_path, O_WRONLY);
    if (fd == -1)
        return -errno;

    /* TODO: On-the-fly encryption should happen here using vault_crypto.c primitives */

    int res = pwrite(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

static int vfuse_mkdir(const char *path, mode_t mode) {
    char full_path[VAULT_PATH_MAX];
    get_cipher_path(full_path, path);

    int res = mkdir(full_path, mode);
    if (res == -1)
        return -errno;
    return 0;
}

static int vfuse_unlink(const char *path) {
    (void) path;
    /* WORM Protection: Block unlink on FUSE mount */
    vault_log(LOG_ALERT, "FUSE: Blocked unlink attempt on %s (WORM Protection)", path);
    return -EPERM;
}

static int vfuse_rmdir(const char *path) {
    (void) path;
    vault_log(LOG_ALERT, "FUSE: Blocked rmdir attempt on %s (WORM Protection)", path);
    return -EPERM;
}

static int vfuse_rename(const char *from, const char *to, unsigned int flags) {
    (void) from;
    (void) to;
    (void) flags;
    vault_log(LOG_ALERT, "FUSE: Blocked rename attempt %s -> %s (WORM Protection)", from, to);
    return -EPERM;
}

static int vfuse_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    char full_path[VAULT_PATH_MAX];
    get_cipher_path(full_path, path);

    int res = open(full_path, fi->flags, mode);
    if (res == -1)
        return -errno;
    fi->fh = res;
    close(res);
    return 0;
}

static struct fuse_operations vault_oper = {
    .getattr    = vfuse_getattr,
    .readdir    = vfuse_readdir,
    .open       = vfuse_open,
    .read       = vfuse_read,
    .write      = vfuse_write,
    .mkdir      = vfuse_mkdir,
    .unlink     = vfuse_unlink,    /* WORM: Deny */
    .rmdir      = vfuse_rmdir,     /* WORM: Deny */
    .rename     = vfuse_rename,    /* WORM: Deny */
    .create     = vfuse_create,
};

struct fuse_thread_data {
    Vault *v;
    struct fuse *f;
    struct fuse_session *se;
};

static void *vault_fuse_loop(void *arg) {
    struct fuse_thread_data *td = (struct fuse_thread_data *)arg;
    vault_log(LOG_INFO, "FUSE thread started for vault %u", td->v->id);

    int res = fuse_loop_mt(td->f, 1); /* multi-threaded FUSE loop */
    
    vault_log(LOG_INFO, "FUSE loop ended for vault %u with code %d", td->v->id, res);
    
    fuse_unmount(td->f);
    fuse_destroy(td->f);
    td->v->is_mounted = false;
    free(td);
    return NULL;
}

VaultError vault_fuse_mount(Vault *v) {
    if (v->is_mounted) return ERR_OK;

    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    fuse_opt_add_arg(&args, "idenvault");
    fuse_opt_add_arg(&args, "-o");
    fuse_opt_add_arg(&args, "auto_unmount");
    fuse_opt_add_arg(&args, v->path);

    struct fuse *f = fuse_new(&args, &vault_oper, sizeof(vault_oper), v);
    fuse_opt_free_args(&args);
    if (!f) {
        vault_log(LOG_ERROR, "Failed to create fuse struct for vault %u", v->id);
        return ERR_IO;
    }

    if (fuse_mount(f, v->path) != 0) {
        fuse_destroy(f);
        vault_log(LOG_ERROR, "Failed to mount fuse at %s", v->path);
        return ERR_IO;
    }

    struct fuse_thread_data *td = calloc(1, sizeof(struct fuse_thread_data));
    td->v = v;
    td->f = f;
    v->is_mounted = true;

    pthread_t th;
    if (pthread_create(&th, NULL, vault_fuse_loop, td) != 0) {
        fuse_unmount(f);
        fuse_destroy(f);
        free(td);
        v->is_mounted = false;
        return ERR_IO;
    }
    pthread_detach(th);

    vault_log(LOG_INFO, "Vault FUSE mounted successfully at %s", v->path);
    return ERR_OK;
}

VaultError vault_fuse_unmount(Vault *v) {
    if (!v->is_mounted) return ERR_OK;
    
    /* Actually we can unmount externally or by sending a signal,
       libfuse 3 provides fuse_exit(f). We don't easily have `f` pointer here without storing it in Vault.
       So let's store it or just use umount2 */
    vault_log(LOG_INFO, "Unmounting vault %u from %s", v->id, v->path);
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "fusermount -u \"%s\"", v->path);
    if (system(cmd) != 0) {
        vault_log(LOG_ERROR, "Failed to fusermount -u %s", v->path);
        return ERR_IO;
    }
    
    /* The fuse_loop_mt will exit and cleanup */
    return ERR_OK;
}
