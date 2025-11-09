#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#include "layer.h"
#include "poddos.h"

int emptydir(int dirfd)
{
    int n = 0;

    // Duplicate file pointer such that we can close it
    int dirfd2 = dup(dirfd);
    if (dirfd2 == -1)
        return -1;
    DIR *dir = fdopendir(dirfd2);
    if (!dir) {
        close(dirfd2);
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, "..") || !strcmp(entry->d_name, ".")) {
            continue;
        }
        // Attempt to open the entry as a directory
        int fd = openat(dirfd, entry->d_name, O_DIRECTORY | O_NOFOLLOW);
        if (fd == -1 && (errno == ENOTDIR || errno == ELOOP)) {
            // It is a file, unlink it
            if (unlinkat(dirfd, entry->d_name, 0) == -1) {
                n = -1;
                goto out;
            }
            n++;
        } else if (fd > 0) {
            // It is a directory, recurse and remove it
            int ret = emptydir(fd);
            close(fd);

            if (ret == -1) {
                n = -1;
                goto out;
            }

            n += ret;
            if (unlinkat(dirfd, entry->d_name, AT_REMOVEDIR) == -1) {
                warn("Could not delete %s", entry->d_name);
                n = -1;
                goto out;
            }
        } else {
            n = -1;
            goto out;
        }
    }

  out:
    closedir(dir);
    return n;
}

int prune(const char *layer)
{
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) == -1)
        die("pipe");

    struct clone_args cl_args = { 0 };
    cl_args.flags = CLONE_NEWUSER;
    cl_args.exit_signal = SIGCHLD;

    // Explicitly flush the streams such that we can do printf in the child
    // (otherwise buffering may give double output).
    fflush(NULL);

    pid_t pid = syscall(SYS_clone3, &cl_args, sizeof(struct clone_args));
    if (pid == -1)
        die("clone3");
    if (pid == 0) {
        // Child, wait for the parent to setup the uid / gid map
        close(pipefd[1]);
        char buf;
        if (read(pipefd[0], &buf, 1) == -1)
            die("read(pipefd)");
        close(pipefd[0]);

        int dirfd = openat(layer_fd, layer, O_DIRECTORY);
        if (dirfd == -1)
            die("could not open %s", layer);
        int n = emptydir(dirfd);
        if (n == -1)
            die("could not empty %s", layer);
        close(dirfd);
        if (unlinkat(layer_fd, layer, AT_REMOVEDIR) == -1)
            die("could not remove %s", layer);

        printf("Removed %s (%d files).\n", layer, n);

        exit(0);
    }
    makeugmap(pid);
    close(pipefd[0]);
    close(pipefd[1]);

    int wstatus;
    if (wait(&wstatus) == -1)
        die("wait");
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus))
        diex("Child crashed (exit status %d).", WEXITSTATUS(wstatus));
    return 0;
}

void pruneall(bool force)
{
    int dirfd = dup(layer_fd);
    if (dirfd == -1)
        die("dup(layer_fd)");
    DIR *dir = fdopendir(dirfd);
    if (!dir)
        die("fdopendir(dirfd)");

    struct dirent *entry;
    char layer[PATH_MAX] = { 0 };
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;

        strcpy(layer, entry->d_name);

        // Check if this entry is a directory or not
        int fd = openat(layer_fd, layer, O_DIRECTORY);
        if (fd > 0) {
            // Check whether there is a file with this hash there
            bool somewhere = false;

            long pos = telldir(dir);
            rewinddir(dir);
            struct dirent *file;
            while ((file = readdir(dir))) {
                if (!strcmp(file->d_name, ".") || !strcmp(file->d_name, ".."))
                    continue;

                int fd = openat(layer_fd, file->d_name, O_RDONLY);
                if (fd == -1)
                    die("could not open %s", file->d_name);

                FILE *f = fdopen(fd, "r");
                char buf[4097];
                while (fscanf(f, " %4096s", buf) > 0) {
                    if (strstr(buf, layer)) {
                        if (somewhere)
                            printf(", %s", file->d_name);
                        else
                            printf("Found %s in %s", layer, file->d_name);
                        somewhere = true;
                        break;
                    }
                }

                close(fd);
            }
            seekdir(dir, pos);

            if (!strstr(layer, ":merged") && !strstr(layer, ":work")) {
                if (!somewhere) {
                    bool remove = force;

                    printf("Layer %s is orphaned. ", layer);
                    if (!remove) {
                        printf("Do you want to remove it? [y/N] ");

                        char s[16];
                        remove = scanf(" %15s", s) > 0 && !strcmp(s, "y");
                    }
                    if (remove)
                        prune(layer);
                    else
                        printf("Skipping.\n");
                } else
                    printf(". Skipping.\n");
            }

            close(fd);
        }
    }

    closedir(dir);
}
