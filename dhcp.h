#ifndef DHCP_H
#define DHCP_H

extern int dhcpconfigured;

int dhcpstart(char *ifname);
int dhcpstep(char *ifname, int sock);

#endif
