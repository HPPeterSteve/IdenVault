#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main() {
    if (unshare(CLONE_NEWUSER) != 0) {
        perror("unshare");
        return 1;
    }
    
    int fd;
    char map[64];
    sprintf(map, "0 %d 1\n", getuid());
    
    fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd >= 0) {
        write(fd, "deny", 4);
        close(fd);
    }
    
    fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd < 0) { perror("open uid_map"); return 1; }
    if (write(fd, map, strlen(map)) < 0) { perror("write uid_map"); return 1; }
    close(fd);
    
    fd = open("/proc/self/gid_map", O_WRONLY);
    if (fd < 0) { perror("open gid_map"); return 1; }
    if (write(fd, map, strlen(map)) < 0) { perror("write gid_map"); return 1; }
    close(fd);
    
    printf("Success!\n");
    return 0;
}
