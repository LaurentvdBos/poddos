#ifndef HTTP_H
#define HTTP_H

#include <stdio.h>

#define URL_MAX 2048
#define URLLEN_S "2048"

// Do not redirect on HTTP 3xx responses
#define HTTP_IGNREDIR 1

// Ignore SSL verification failures, if any
#define HTTP_IGNSSL 2

// Ignore Bearer authentication challenges
#define HTTP_IGNBEARER 4

// Caller adds a custom accept header
#define HTTP_ACCEPT 8

// Caller adds a Bearer token; if both accept / token are present, accept should be given first.
#define HTTP_TOKEN 16

FILE *urlopen(char *url, unsigned flags, ...);

#endif
