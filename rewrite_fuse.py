import re

with open("c_src/vault_fuse.c", "r", encoding="utf-8") as f:
    code = f.read()

header_addition = """
#include <time.h>

#define FUSE_LOG_START(op) \\
    struct timespec _ts_start, _ts_end; \\
    clock_gettime(CLOCK_MONOTONIC, &_ts_start); \\
    Vault *_v_log = (Vault *)fuse_get_context()->private_data;

#define FUSE_LOG_END(op, path, res) \\
    clock_gettime(CLOCK_MONOTONIC, &_ts_end); \\
    double _elapsed = (_ts_end.tv_sec - _ts_start.tv_sec) * 1000.0 + \\
                      (_ts_end.tv_nsec - _ts_start.tv_nsec) / 1e6; \\
    if ((res) < 0) { \\
        vault_log(LOG_ERROR, "[FUSE] %s '%s' failed: %d (%.3fms) [vault=%s]", op, path, (res), _elapsed, _v_log ? _v_log->name : "?"); \\
    } else { \\
        vault_log(LOG_INFO, "[FUSE] %s '%s' OK (%.3fms) [vault=%s]", op, path, _elapsed, _v_log ? _v_log->name : "?"); \\
    }

"""

if "#define FUSE_LOG_START" not in code:
    code = code.replace('#include "vault_core.h"', '#include "vault_core.h"\n' + header_addition)


def wrap_func(name, return_type, args_sig, path_var):
    # This is a bit tricky, better to just replace the bodies of the known FUSE functions
    pass

# We will just manually inject FUSE_LOG_START and FUSE_LOG_END for each function.
funcs = [
    ("vfuse_getattr", "path", "return res;", "FUSE_LOG_END(\"getattr\", path, res);\n    return res;"),
    ("vfuse_readdir", "path", "return 0;", "int res = 0;\n    FUSE_LOG_END(\"readdir\", path, res);\n    return res;"),
    ("vfuse_open", "path", "return 0;", "int res_ok = 0;\n    FUSE_LOG_END(\"open\", path, res_ok);\n    return res_ok;"),
    ("vfuse_read", "path", "return res;", "FUSE_LOG_END(\"read\", path, res);\n    return res;"),
    ("vfuse_write", "path", "return res;", "FUSE_LOG_END(\"write\", path, res);\n    return res;"),
    ("vfuse_mkdir", "path", "return 0;", "int res_ok = 0;\n    FUSE_LOG_END(\"mkdir\", path, res_ok);\n    return res_ok;"),
    ("vfuse_unlink", "path", "return 0;", "int res_ok = 0;\n    FUSE_LOG_END(\"unlink\", path, res_ok);\n    return res_ok;"),
    ("vfuse_rmdir", "path", "return 0;", "int res_ok = 0;\n    FUSE_LOG_END(\"rmdir\", path, res_ok);\n    return res_ok;"),
    ("vfuse_rename", "from", "return 0;", "int res_ok = 0;\n    FUSE_LOG_END(\"rename\", from, res_ok);\n    return res_ok;"),
    ("vfuse_create", "path", "return 0;", "int res_ok = 0;\n    FUSE_LOG_END(\"create\", path, res_ok);\n    return res_ok;"),
]

for func, path_var, old_ret, new_ret in funcs:
    # Find the start of the function body
    match = re.search(r'static int ' + func + r'\([^)]+\)\n\{', code)
    if match:
        start_idx = match.end()
        # insert FUSE_LOG_START if not already there
        if "FUSE_LOG_START" not in code[start_idx:start_idx+50]:
            code = code[:start_idx] + f'\n    FUSE_LOG_START("{func.replace("vfuse_","")}");' + code[start_idx:]
            
            # replace return
            # find the end of the function (a bit simplistic but works for these short functions)
            # just replace the last return before the next function
            next_func = code.find("static int vfuse_", start_idx)
            if next_func == -1:
                next_func = len(code)
            
            chunk = code[start_idx:next_func]
            chunk = chunk.replace(old_ret, new_ret)
            code = code[:start_idx] + chunk + code[next_func:]

# Also change the return -errno; to res = -errno; FUSE_LOG_END... return res;
# It's easier to just do it via regex in the chunk
for func in [f[0] for f in funcs]:
    path_var = [f[1] for f in funcs if f[0] == func][0]
    match = re.search(r'static int ' + func + r'\([^)]+\)\n\{', code)
    if match:
        start_idx = match.end()
        next_func = code.find("static int vfuse_", start_idx)
        if next_func == -1: next_func = len(code)
        chunk = code[start_idx:next_func]
        chunk = re.sub(r'return -errno;', f'{{ int err = -errno; FUSE_LOG_END("{func.replace("vfuse_","")}", {path_var}, err); return err; }}', chunk)
        chunk = re.sub(r'return -EPERM;', f'{{ int err = -EPERM; FUSE_LOG_END("{func.replace("vfuse_","")}", {path_var}, err); return err; }}', chunk)
        code = code[:start_idx] + chunk + code[next_func:]

with open("c_src/vault_fuse.c", "w", encoding="utf-8") as f:
    f.write(code)

