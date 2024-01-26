#ifndef LAYER_H
#define LAYER_H

#include <sys/types.h>

#define LAYER_EPHEMERAL 1
#define LAYER_NET 2

void makeugmap(pid_t pid);
void lstart(unsigned flags, char **argv, char **envp);
void lexec(unsigned flags, char **argv, char **envp);

#endif
