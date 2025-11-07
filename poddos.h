#ifndef PODDOS_H
#define PODDOS_H

#include <limits.h>
#include <error.h>
#include <errno.h>

#define err(...) error_at_line(128, errno, __FILE__, __LINE__, __VA_ARGS__)
#define errx(...) error_at_line(128, 0, __FILE__, __LINE__, __VA_ARGS__)
#define warn(...) error_at_line(0, errno, __FILE__, __LINE__, __VA_ARGS__)
#define warnx(...) error_at_line(0, 0, __FILE__, __LINE__, __VA_ARGS__)

int dircnt(const char *name);

extern char *name;

extern int layer_fd;
extern char layer_path[PATH_MAX];

extern char lowerdir[4096];
extern char upperdir[4096];

extern char *ifname;
extern char mac[6];

extern int nbind;
extern char **bind_from, **bind_to;

extern char *directory;

#endif
