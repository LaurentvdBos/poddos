#define _GNU_SOURCE

#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "inflate.h"

#define CHUNK 1024

struct finf {
    z_stream strm;
    FILE *f;
    unsigned flags;
    char buf[CHUNK];
};

static ssize_t zread(void *cookie, char *buf, size_t n)
{
    struct finf *z = (struct finf *) cookie;
    z_stream *strm = &z->strm;
    ssize_t have = 0;

    do {
        strm->next_out = (unsigned char *) buf + have;
        strm->avail_out = n - have;

        if (!strm->avail_in) {
            strm->avail_in = fread(z->buf, 1, CHUNK, z->f);
            if (ferror(z->f))
                return -1;
            if (strm->avail_in == 0)
                break;
            strm->next_in = (unsigned char *) z->buf;
        }

        int ret = inflate(strm, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
            fprintf(stderr, "zread: %s\n", strm->msg);
            return -1;
        }
        have = n - strm->avail_out;

        if (ret == Z_STREAM_END && strm->avail_in)
            fprintf(stderr, "zread: end of stream with bytes pending.\n");
        if (ret == Z_STREAM_END)
            break;
    } while (have < n);

    return have;
}

static ssize_t zwrite(void *cookie, const char *buf, size_t n)
{
    struct finf *z = (struct finf *) cookie;
    return fwrite(buf, 1, n, z->f);
}

static int zclose(void *cookie)
{
    int ret = 0;
    struct finf *z = (struct finf *) cookie;
    z_stream *strm = &z->strm;
    inflateEnd(strm);
    if (z->flags | INFL_AUTOCLOSE)
        ret = fclose(z->f) ? -1 : 0;
    free(z);
    return ret;
}

FILE *finfl(FILE * f, unsigned flags)
{
    struct finf *z = malloc(sizeof(struct finf));
    memset(z, 0, sizeof(struct finf));
    z->flags = flags;

    if (inflateInit2(&z->strm, (flags & INFL_RAW) ? -MAX_WBITS : (MAX_WBITS + 32)) != Z_OK) {
        fprintf(stderr, "Could not initialize inflate\n");
        return NULL;
    }
    z->f = f;

    cookie_io_functions_t io_funcs = {
        .close = zclose,
        .read = zread,
        .write = zwrite,
        .seek = NULL
    };

    return fopencookie(z, "w+", io_funcs);
}
