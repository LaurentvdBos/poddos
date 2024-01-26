#ifndef TRUNCATE_H
#define TRUNCATE_H

#include <stdio.h>

#define TRUNC_AUTOCLOSE 1
#define TRUNC_DRAIN 2

FILE *ftrunc(FILE *f, size_t n, unsigned flags);

#endif