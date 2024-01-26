#ifndef UNTAR_H
#define UNTAR_H

#include <stdio.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/time.h>

struct tarfile
{
    char path[PATH_MAX];
    char linkpath[PATH_MAX];

    mode_t mode;
    uid_t uid;
    gid_t gid;

    int major;
    int minor;

    unsigned long size;
    struct timeval mtime;
    struct timeval atime;

    char type;
};

FILE *untar(FILE *f, struct tarfile *file);
void tarwrite(struct tarfile file, FILE *f, int dir_fd);

#endif
