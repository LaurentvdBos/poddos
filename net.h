#ifndef NET_H
#define NET_H

#include <sys/types.h>
#include <net/if.h>

extern char *macvlan;

void bringloup();
void makemacvlan(pid_t pid);

#endif
