#ifndef ZSTD_H
#define ZSTD_H

#include <stdio.h>

#define ZSTD_AUTOCLOSE 1

FILE *fzstd(FILE *f, unsigned flags);

#endif
