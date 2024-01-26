#ifndef PODDOS_H
#define PODDOS_H

#include <limits.h>

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
