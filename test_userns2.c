#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/wait.h>

int main() {
    int p[2]; pipe(p);
    pid_t pid = fork();
    if (pid == 0) {
        unshare(CLONE_NEWUSER);
        char c = 'r'; write(p[1], &c, 1);
        read(p[0], &c, 1);
        printf("Child done.\n");
        exit(0);
    } else {
        char c; read(p[0], &c, 1);
        char path[64]; sprintf(path, "/proc/%d/setgroups", pid);
        int fd = open(path, O_WRONLY); write(fd, "deny", 4); close(fd);
        
        sprintf(path, "/proc/%d/uid_map", pid);
        fd = open(path, O_WRONLY);
        char map[64]; sprintf(map, "0 %d 1\n", getuid());
        if (write(fd, map, strlen(map)) < 0) perror("uid_map");
        close(fd);
        
        sprintf(path, "/proc/%d/gid_map", pid);
        fd = open(path, O_WRONLY);
        sprintf(map, "0 %d 1\n", getgid());
        if (write(fd, map, strlen(map)) < 0) perror("gid_map");
        close(fd);
        
        write(p[1], "k", 1);
        wait(NULL);
        printf("Parent done.\n");
    }
    return 0;
}
