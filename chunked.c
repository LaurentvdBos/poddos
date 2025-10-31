#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

#include "chunked.h"

struct fchunk {
    FILE *f;
    ssize_t n;
    unsigned flags;
};

static ssize_t chunkread(void *cookie, char *buf, size_t n)
{
    struct fchunk *c = (struct fchunk *) cookie;
    if (c->n == 0) {
        size_t m;
        if (!fscanf(c->f, " %lx", &m))
            return -1;
        if (fgetc(c->f) != '\r')
            return -1;
        if (fgetc(c->f) != '\n')
            return -1;
        if (m == 0)
            c->n = -1;
        else
            c->n = m;
    }
    if (c->n == -1)
        return 0;
    if (n > c->n)
        n = c->n;

    size_t m = fread(buf, 1, n, c->f);
    if (ferror(c->f))
        return -1;
    c->n -= m;
    return m;
}

static ssize_t chunkwrite(void *cookie, const char *buf, size_t n)
{
    struct fchunk *c = (struct fchunk *) cookie;
    return fwrite(buf, 1, n, c->f);
}

static int chunkclose(void *cookie)
{
    int ret = 0;
    struct fchunk *c = (struct fchunk *) cookie;
    if (c->flags & CHUNK_AUTOCLOSE)
        ret = fclose(c->f) ? -1 : 0;
    free(c);
    return ret;
}

/**
 * Read HTTP chunked data from a file pointer. Such data comes in chunks, where
 * each chunk consists of an ASCII number, indicating the size of the chunk in
 * bytes, followed by a \r\n.
 */
FILE *fchunk(FILE * f, unsigned flags)
{
    struct fchunk *c = malloc(sizeof(struct fchunk));
    c->f = f;
    c->n = 0;
    c->flags = flags;

    cookie_io_functions_t io_funcs = {
        .close = chunkclose,
        .read = chunkread,
        .write = chunkwrite,
        .seek = NULL
    };

    return fopencookie(c, "w+", io_funcs);
}
