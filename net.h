#ifndef NET_H
#define NET_H

#include <sys/types.h>
#include <net/if.h>

extern char *macvlan;
extern int seq;

void bringloup();
void ifremove(char *ifname);
void makemacvlan(pid_t pid);

#endif
