#define _GNU_SOURCE
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include "net.h"
#include "poddos.h"

void bringloup()
{
    struct ifreq req = {
        .ifr_name = "lo",
        .ifr_flags = IFF_UP | IFF_RUNNING
    };
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) err(1, "socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)");
    if (ioctl(sock, SIOCSIFFLAGS, &req) == -1) err(1, "ioctl(SIOCSIFFLAGS)");
    close(sock);
}

int sendnl(int fd, struct nlmsghdr *hdr)
{
    static int seq = 0;

    struct iovec iov = { hdr, hdr->nlmsg_len };
    struct sockaddr_nl sa;
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    hdr->nlmsg_pid = 0;
    hdr->nlmsg_seq = seq++;

    return sendmsg(fd, &msg, 0);
}

int net(pid_t pid)
{
    // Initialize the netlink socket
    char buf[4096];
    int netfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (netfd < 0) err(1, "socket(AF_NETLINK)");

    struct sockaddr_nl sa;
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK;
    if (bind(netfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) err(1, "bind(netfd)");

    struct
    {
        struct nlmsghdr hdr;
        struct ifinfomsg ifinfo;
        char attrbuf[512];
    } req;

    // Send a request to obtain the link index of the provided link
    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifinfo));
    req.hdr.nlmsg_flags = NLM_F_REQUEST;
    req.hdr.nlmsg_type = RTM_GETLINK;

    req.ifinfo.ifi_family = AF_UNSPEC;
    req.ifinfo.ifi_index = 0;
    req.ifinfo.ifi_change = 0xFFFFFFFF; 

    int n = 512;
    struct rtattr *rta0 = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
    rta0->rta_type = IFLA_IFNAME;
    rta0->rta_len = RTA_LENGTH(strlen(ifname));
    strcpy(RTA_DATA(rta0), ifname);
    rta0 = RTA_NEXT(rta0, n);

    req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + (512 - n);

    if (sendnl(netfd, &req.hdr) == -1) err(1, "sendnl");

    n = read(netfd, buf, 4096);

    int ifindex = 0;
    for (struct nlmsghdr *hdr = (struct nlmsghdr *)buf; NLMSG_OK(hdr, n); hdr = NLMSG_NEXT(hdr, n)) {
        if (hdr->nlmsg_type == NLMSG_DONE) {
            break;
        }

        if (hdr->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *nlerr = (struct nlmsgerr *)NLMSG_DATA(hdr);
            if (nlerr->error < 0) errno = -nlerr->error, err(1, "rtnetlink");
        }

        if (hdr->nlmsg_type == RTM_NEWLINK) {
            memcpy(&req, hdr, sizeof(struct nlmsghdr) + sizeof(struct ifinfomsg));
            ifindex = req.ifinfo.ifi_index;
        }
    }

    if (!ifindex) err(1, "Interface %s does not exist.", ifname);

    // Create the macvlan
    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifinfo));
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
    req.hdr.nlmsg_type = RTM_NEWLINK;

    req.ifinfo.ifi_family = AF_UNSPEC;
    req.ifinfo.ifi_index = 0;
    req.ifinfo.ifi_change = 0xFFFFFFFF; 
    req.ifinfo.ifi_flags = IFF_UP | IFF_BROADCAST | IFF_MULTICAST | IFF_RUNNING;

    n = 512;

    struct rtattr *rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.hdr.nlmsg_len));

    rta->rta_type = IFLA_LINK;
    rta->rta_len = RTA_LENGTH(sizeof(ifindex));
    memcpy(RTA_DATA(rta), &ifindex, sizeof(ifindex));
    rta = RTA_NEXT(rta, n);

    const char *macvlan = "macvlan0";
    rta->rta_type = IFLA_IFNAME;
    rta->rta_len = RTA_LENGTH(strlen(macvlan));
    strcpy(RTA_DATA(rta), macvlan);
    rta = RTA_NEXT(rta, n);

    rta->rta_type = IFLA_NET_NS_PID;
    rta->rta_len = RTA_LENGTH(sizeof(pid));
    memcpy(RTA_DATA(rta), &pid, sizeof(pid));
    rta = RTA_NEXT(rta, n);

    if (mac[0] || mac[1] || mac[2] || mac[3] || mac[4] || mac[5]) {
        rta->rta_type = IFLA_ADDRESS;
        rta->rta_len = RTA_LENGTH(sizeof(mac));
        memcpy(RTA_DATA(rta), mac, sizeof(mac));
        rta = RTA_NEXT(rta, n);
    }

    rta->rta_type = IFLA_LINKINFO;

    int m = n;
    struct rtattr *subrta = RTA_DATA(rta);
    subrta->rta_type = IFLA_INFO_KIND;
    subrta->rta_len = RTA_LENGTH(strlen("macvlan"));
    strcpy(RTA_DATA(subrta), "macvlan");
    subrta = RTA_NEXT(subrta, m);

    /*subrta->rta_type = IFLA_INFO_DATA;
    subrta->rta_len = RTA_LENGTH(8);
    uint16_t data[] = { 8, IFLA_MACVLAN_MODE, MACVLAN_MODE_VEPA, 0 };
    memcpy(RTA_DATA(subrta), data, 8);
    subrta = RTA_NEXT(subrta, m);*/

    rta->rta_len = RTA_LENGTH(n - m);
    rta = RTA_NEXT(rta, n);

    req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + (512 - n);

    if (sendnl(netfd, &req.hdr) == -1) err(1, "sendnl");

    n = read(netfd, buf, 4096);

    for (struct nlmsghdr *hdr = (struct nlmsghdr *)buf; NLMSG_OK(hdr, n); hdr = NLMSG_NEXT(hdr, n)) {
        if (hdr->nlmsg_type == NLMSG_DONE) {
            break;
        }

        if (hdr->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *nlerr = (struct nlmsgerr *)NLMSG_DATA(hdr);
            if (nlerr->error < 0) errno = -nlerr->error, err(1, "rtnetlink");
        }

        if (hdr->nlmsg_type == RTM_NEWLINK) {
            // Todo, we should be able to get the mac address here
            // struct rtattr *rta = (struct rtattr *)(((char *)&hdr) + NLMSG_ALIGN(hdr->nlmsg_len));

            memcpy(&req, hdr, sizeof(struct nlmsghdr) + sizeof(struct ifinfomsg));
            return req.ifinfo.ifi_index;
        }
    }

    return -1;
}
