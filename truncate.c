#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

#include "truncate.h"

struct ftrunc {
    FILE *f;
    size_t n;
    unsigned flags;
};

static ssize_t truncread(void *cookie, char *buf, size_t n)
{
    struct ftrunc *t = (struct ftrunc *) cookie;
    if (n > t->n)
        n = t->n;
    if (n == 0)
        return 0;

    size_t m = fread(buf, 1, n, t->f);
    if (ferror(t->f))
        return -1;
    t->n -= m;
    return m;
}

static ssize_t truncwrite(void *cookie, const char *buf, size_t n)
{
    struct ftrunc *t = (struct ftrunc *) cookie;
    return fwrite(buf, 1, n, t->f);
}

static int truncclose(void *cookie)
{
    int ret = 0;
    struct ftrunc *t = (struct ftrunc *) cookie;
    if (t->flags & TRUNC_DRAIN)
        while (t->n--)
            (void) fgetc(t->f);
    if (t->flags & TRUNC_AUTOCLOSE)
        ret = fclose(t->f) ? -1 : 0;
    free(t);
    return ret;
}

FILE *ftrunc(FILE * f, size_t n, unsigned flags)
{
    struct ftrunc *t = malloc(sizeof(struct ftrunc));
    t->f = f;
    t->n = n;
    t->flags = flags;

    cookie_io_functions_t io_funcs = {
        .close = truncclose,
        .read = truncread,
        .write = truncwrite,
        .seek = NULL
    };

    return fopencookie(t, "w+", io_funcs);
}
