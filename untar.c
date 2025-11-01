#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <utime.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "untar.h"
#include "truncate.h"
#include "poddos.h"

#define PAX_MAX 16384

#define PAX_ATIME 1
#define PAX_MTIME 2
#define PAX_UID 4
#define PAX_GID 8
#define PAX_LINKPATH 16
#define PAX_PATH 32

struct tarheader {
    char path[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char checksum[8];
    char type;
    char linkpath[100];
    char ustar[6];
    char ustarv[2];
    char uname[32];
    char gname[32];
    char major[8];
    char minor[8];
    char prefix[155];
};

const char zerobuf[512] = { 0 };

void tarwrite(struct tarfile file, FILE * f, int dir_fd)
{
    switch (file.type) {
    case '0':
    case '7':
        int fd = openat(dir_fd, file.path, O_CREAT | O_WRONLY | O_TRUNC, file.mode);
        if (fd == -1)
            err("open(%s)", file.path);

        char buf[512];
        int n;
        while ((n = fread(buf, 1, 512, f)) > 0) {
            if (write(fd, buf, n) == -1)
                err("write(%s)", file.path);
        }
        if (n == -1)
            err("fread");

        if (fchown(fd, file.uid, file.gid) == -1)
            err("fchown(%s, %d, %d)", file.path, file.uid, file.gid);
        if (fchmod(fd, file.mode))
            err("fchmod(%s, 0%03o)", file.path, file.mode);

        const struct timeval tvp[] = { file.mtime, file.atime };
        if (futimes(fd, tvp))
            err("futimes(%s)", file.path);

        close(fd);
        break;

    case '1':
        if (linkat(dir_fd, file.linkpath, dir_fd, file.path, 0) == -1)
            err("linkat(%s, %s)", file.linkpath, file.path);
        break;

    case '2':
        if (symlinkat(file.linkpath, dir_fd, file.path) == -1)
            err("symlinkat(%s, %s)", file.linkpath, file.path);
        break;

    case '3':
        if (mknodat(dir_fd, file.path, file.mode, makedev(file.major, file.minor) | S_IFCHR) == -1)
            err("mknodat(%s)", file.path);
        if (fchmodat(dir_fd, file.path, file.mode, 0) == -1)
            err("chmod(%s)", file.path);
        break;

    case '4':
        if (mknodat(dir_fd, file.path, file.mode, makedev(file.major, file.minor) | S_IFBLK) == -1)
            err("mknodat(%s)", file.path);
        if (fchmodat(dir_fd, file.path, file.mode, 0) == -1)
            err("chmod(%s)", file.path);
        break;

    case '5':
        if (mkdirat(dir_fd, file.path, 0777) == -1 && errno != EEXIST)
            err("mkdir(%s)", file.path);
        if (fchmodat(dir_fd, file.path, file.mode, 0) == -1)
            err("fchmod(%s, 0%03o)", file.path, file.mode);
        break;

    default:
        errx("Unrecognized type: %c\n", file.type);
    }
}

unsigned unpax(FILE * f, struct tarfile *file)
{
    unsigned flags = 0;

    while (!ferror(f) && !feof(f)) {
        // Read the length
        int n = 0;
        int len = 0;
        for (;;) {
            int c = fgetc(f);
            n++;
            if (c == ' ')
                break;
            else if ('0' <= c && c <= '9')
                len = 10 * len + (c - '0');
            else
                return flags;   // Ignore invalid pax headers
        }

        if (len > PAX_MAX)
            errx("Pax header too long: %d", len);

        // Read the rest
        char key[PAX_MAX];
        if (fread(key, 1, len - n, f) < len - n)
            return flags;
        key[len - n - 1] = 0;   // Overwrite the new line

        // Split the string in a key / value pair
        char *val = strchr(key, '=') + 1;
        *(val - 1) = 0;

        if (!strcmp(key, "atime")) {
            double v;
            if (!sscanf(val, "%lf", &v))
                return flags;
            file->atime.tv_sec = v;

            v -= (long) v;
            file->atime.tv_usec = v * 1e6;

            flags |= PAX_ATIME;
        } else if (!strcmp(key, "mtime")) {
            double v;
            if (!sscanf(val, "%lf", &v))
                return flags;
            file->mtime.tv_sec = v;

            v -= (long) v;
            file->mtime.tv_usec = v * 1e6;

            flags |= PAX_MTIME;
        } else if (!strcmp(key, "uid")) {
            if (!sscanf(val, "%d", &file->uid))
                return 0;
            flags |= PAX_UID;
        } else if (!strcmp(key, "gid")) {
            if (!sscanf(val, "%d", &file->gid))
                return 0;
            flags |= PAX_GID;
        } else if (!strcmp(key, "linkpath")) {
            strcpy(file->linkpath, val);
            flags |= PAX_LINKPATH;
        } else if (!strcmp(key, "path")) {
            strcpy(file->path, val);
            flags |= PAX_PATH;
        } else
            warnx("Unrecognized pax key in %s: %s", file->path, key);
    }

    return flags;
}

FILE *untar(FILE * f, struct tarfile *file)
{
    unsigned paxflags = 0;

    while (!ferror(f) && !feof(f)) {
        char buf[512];
        int n = fread(buf, 1, 512, f);
        if (n != 512)
            return NULL;
        if (!memcmp(buf, zerobuf, 512)) {
            return NULL;
        }

        struct tarheader *tar = (struct tarheader *) buf;
        unsigned long blksize = strtoul(tar->size, NULL, 8);
        if (blksize % 512)
            blksize += 512 - (blksize % 512);

        if (strncmp(tar->ustar, "ustar", 5))
            return NULL;

        switch (tar->type) {
        case 'x':
            FILE * g = ftrunc(f, blksize, TRUNC_DRAIN);
            paxflags = unpax(g, file);
            fclose(g);
            continue;

        case 'L':
            // GNU longname; contents are part of path
            paxflags |= PAX_PATH;
            if (fread(file->path, 1, blksize, f) != blksize)
                return NULL;
            continue;

        case 'K':
            // Same as 'L', but then for the linkpath
            paxflags |= PAX_LINKPATH;
            if (fread(file->linkpath, 1, blksize, f) != blksize)
                return NULL;
            continue;
        }

        file->type = tar->type;
        if (!(paxflags & PAX_PATH)) {
            if (tar->prefix[0]) {
                strncpy(file->path, tar->prefix, 155);
                file->path[155] = 0;

                strcat(file->path, "/");
                file->path[156] = 0;
            } else
                file->path[0] = 0;
            strncat(file->path, tar->path, 100);
            file->path[256] = 0;
        }
        if (!(paxflags & PAX_LINKPATH)) {
            strncpy(file->linkpath, tar->linkpath, 100);
            file->linkpath[100] = 0;
        }
        file->mode = strtoul(tar->mode, NULL, 8);
        if (!(paxflags & PAX_UID))
            file->uid = strtoul(tar->uid, NULL, 8);
        if (!(paxflags & PAX_GID))
            file->gid = strtoul(tar->gid, NULL, 8);
        file->major = strtoul(tar->major, NULL, 8);
        file->minor = strtoul(tar->minor, NULL, 8);
        file->size = strtoul(tar->size, NULL, 8);
        if (!(paxflags & PAX_MTIME)) {
            file->mtime.tv_sec = strtoul(tar->mtime, NULL, 8);
            file->mtime.tv_usec = 0;
        }
        if (!(paxflags & PAX_ATIME)) {
            file->atime.tv_sec = strtoul(tar->mtime, NULL, 8);
            file->atime.tv_usec = 0;
        }

        return ftrunc(ftrunc(f, blksize, TRUNC_DRAIN), file->size, TRUNC_AUTOCLOSE);
    }

    return NULL;
}
