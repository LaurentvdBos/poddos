#ifndef HTTP_H
#define HTTP_H

#include <stdio.h>

#define URLLEN 2048
#define URLLEN_S "2048"

// Do not redirect on HTTP 3xx responses
#define HTTP_IGNREDIR 1

// Ignore SSL verification failures, if any
#define HTTP_IGNSSL 2

// Ignore Bearer authentication
#define HTTP_IGNBEARER 4

FILE *urlopen(char *url, unsigned flags, const char *accept);

#endif