#ifndef NET_H
#define NET_H

#include <sys/types.h>
#include <net/if.h>

extern char tapname[IFNAMSIZ];

void bringloup();
int rawsock(char *ifname);
int maketap();

#endif
