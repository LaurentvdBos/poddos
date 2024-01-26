#ifndef CHUNKED_H
#define CHUNKED_H

#include <stdio.h>

#define CHUNK_AUTOCLOSE 1

FILE *fchunk(FILE *f, unsigned flags);

#endif