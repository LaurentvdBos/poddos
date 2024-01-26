#ifndef INFLATE_H
#define INFLATE_H

#include <stdio.h>

#define INFL_AUTOCLOSE 1
#define INFL_RAW 2

FILE *finfl(FILE *f, unsigned flags);

#endif