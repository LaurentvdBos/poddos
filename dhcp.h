#ifndef DHCP_H
#define DHCP_H

int dhcpstart(char *ifname);
int dhcpstep(char *ifname, int sock);

#endif
