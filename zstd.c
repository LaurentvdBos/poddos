#define _GNU_SOURCE

#include <zstd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zstd.h"

struct fzstd {
    unsigned flags;
    FILE *f;
    ZSTD_DCtx *dctx;

    char *in;
    size_t in_n, in_sz, in_pos;
    char *out;
    size_t out_n, out_sz, out_pos;
};

static ssize_t zread(void *cookie, char *buf, size_t n)
{
    struct fzstd *z = (struct fzstd *)cookie;

    ssize_t have = 0;

    do {
        // Check if output buffer contains data
        if (z->out_pos >= z->out_sz) {
            // Check if input buffer is depleted
            if (z->in_pos >= z->in_sz) {
                // Read more compressed data into the in buffer
                z->in_sz = fread(z->in, 1, z->in_n, z->f);
                z->in_pos = 0;
                if (ferror(z->f))
                    return -1;
                if (z->in_sz == 0)
                    break;
            }

            ZSTD_inBuffer input = { z->in, z->in_sz, z->in_pos };
            ZSTD_outBuffer output = { z->out, z->out_n, 0 };
            size_t ret = ZSTD_decompressStream(z->dctx, &output, &input);
            if (ZSTD_isError(ret)) {
                fprintf(stderr, "zstd error: %s\n", ZSTD_getErrorName(ret));
                return -1;
            }

            z->in_pos = input.pos;

            z->out_sz = output.pos;
            z->out_pos = 0;
        }

        // Copy decompressed data to the output buffer
        size_t to_copy = z->out_sz - z->out_pos;
        if (to_copy > n - have)
            to_copy = n - have;
        memcpy(buf + have, z->out + z->out_pos, to_copy);
        have += to_copy;
        z->out_pos += to_copy;
    } while (have < n);

    return have;
}

static ssize_t zwrite(void *cookie, const char *buf, size_t n)
{
    struct fzstd *z = (struct fzstd *) cookie;
    return fwrite(buf, 1, n, z->f);
}

static int zclose(void *cookie)
{
    struct fzstd *z = (struct fzstd *) cookie;
    ZSTD_freeDCtx(z->dctx);

    if (z->flags & ZSTD_AUTOCLOSE)
        fclose(z->f);

    free(z->in);
    free(z->out);
    free(z);
    return 0;
}

FILE *fzstd(FILE *f, unsigned flags)
{
    struct fzstd *z = malloc(sizeof(struct fzstd));
    memset(z, 0, sizeof(struct fzstd));

    z->f = f;
    z->flags = flags;

    z->in_n = ZSTD_DStreamInSize();
    z->in_sz = 0;
    z->in_pos = 0;
    z->in = malloc(z->in_n);

    z->out_n = ZSTD_DStreamOutSize();
    z->out_sz = 0;
    z->out_pos = 0;
    z->out = malloc(z->out_n);

    z->dctx = ZSTD_createDCtx();
    if (!z->dctx || !z->in || !z->out) {
        fprintf(stderr, "Could not initialize zstd context\n");
        return NULL;
    }

    cookie_io_functions_t io_funcs = {
        .read = zread,
        .write = zwrite,
        .seek = NULL,
        .close = zclose
    };

    return fopencookie(z, "w+", io_funcs);
}
