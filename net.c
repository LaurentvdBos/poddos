#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/rtnetlink.h>

#include <string.h>

#include "net.h"
#include "poddos.h"

char *macvlan = "macvlan0";

static int seq = 0;

void bringloup()
{
    struct ifreq req = {
        .ifr_name = "lo",
        .ifr_flags = IFF_UP | IFF_RUNNING
    };
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1)
        die("socket(AF_INET, SOCK_DGRAM, 0)");
    if (ioctl(sock, SIOCSIFFLAGS, &req) == -1)
        die("ioctl(SIOCSIFFLAGS)");
    close(sock);
}

void ifremove(char *ifname)
{
    // Initialize the netlink socket
    char buf[4096];
    int netfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (netfd < 0)
        die("socket(AF_NETLINK)");

    struct sockaddr_nl sa;
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK;
    sa.nl_pid = 0;
    if (bind(netfd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
        die("bind(netfd)");

    struct {
        struct nlmsghdr hdr;
        struct ifinfomsg ifinfo;
        char attrbuf[512];
    } req;

    // Send a request to obtain the link index of the provided link
    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifinfo));
    req.hdr.nlmsg_flags = NLM_F_REQUEST;
    req.hdr.nlmsg_type = RTM_GETLINK;
    req.hdr.nlmsg_pid = 0;
    req.hdr.nlmsg_seq = seq++;

    req.ifinfo.ifi_family = AF_UNSPEC;
    req.ifinfo.ifi_index = 0;
    req.ifinfo.ifi_change = 0xFFFFFFFF;

    int n = 512;
    struct rtattr *rta0 = (struct rtattr *) (((char *) &req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
    rta0->rta_type = IFLA_IFNAME;
    rta0->rta_len = RTA_LENGTH(strlen(ifname));
    strcpy(RTA_DATA(rta0), ifname);
    rta0 = RTA_NEXT(rta0, n);

    req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + (512 - n);

    if (write(netfd, &req, req.hdr.nlmsg_len) == -1)
        die("write");

    if ((n = read(netfd, buf, 4096)) == -1)
        die("read(netfd)");

    int ifindex = -1;
    for (struct nlmsghdr * hdr = (struct nlmsghdr *)buf; NLMSG_OK(hdr, n); hdr = NLMSG_NEXT(hdr, n)) {
        if (hdr->nlmsg_type == NLMSG_DONE)
            break;

        if (hdr->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *nlerr = (struct nlmsgerr *) NLMSG_DATA(hdr);
            if (nlerr->error < 0)
                errno = -nlerr->error, die("rtnetlink");
        }

        if (hdr->nlmsg_type == RTM_NEWLINK) {
            memcpy(&req, hdr, sizeof(struct nlmsghdr) + sizeof(struct ifinfomsg));
            ifindex = req.ifinfo.ifi_index;
        }
    }
    if (ifindex == -1)
        die("Interface %s went missing.", ifname);

    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifinfo));
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.hdr.nlmsg_type = RTM_DELLINK;
    req.hdr.nlmsg_pid = 0;
    req.hdr.nlmsg_seq = seq++;

    req.ifinfo.ifi_family = AF_UNSPEC;
    req.ifinfo.ifi_index = ifindex;
    req.ifinfo.ifi_change = 0xFFFFFFFF;
    req.ifinfo.ifi_flags = 0;

    req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len);

    if (write(netfd, &req, req.hdr.nlmsg_len) == -1)
        die("write");

    // Wait for acknowledgement or error, whichever comes first
    int ack = 0;
    while (!ack) {
        if ((n = read(netfd, buf, 4096)) == -1)
            die("read(netfd)");

        for (struct nlmsghdr * hdr = (struct nlmsghdr *)buf; NLMSG_OK(hdr, n); hdr = NLMSG_NEXT(hdr, n)) {
            if (hdr->nlmsg_type == NLMSG_DONE)
                break;

            if (hdr->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *nlerr = (struct nlmsgerr *) NLMSG_DATA(hdr);
                if (nlerr->error < 0)
                    errno = -nlerr->error, die("rtnetlink");
                if (nlerr->error == 0)
                    ack = 1;
            }
        }
    }

    close(netfd);
}

void makemacvlan(pid_t pid)
{
    // Initialize the netlink socket
    char buf[4096];
    int netfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (netfd < 0)
        die("socket(AF_NETLINK)");

    struct sockaddr_nl sa;
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK;
    sa.nl_pid = 0;
    if (bind(netfd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
        die("bind(netfd)");

    struct {
        struct nlmsghdr hdr;
        struct ifinfomsg ifinfo;
        char attrbuf[512];
    } req;

    // Send a request to obtain the link index of the provided link
    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifinfo));
    req.hdr.nlmsg_flags = NLM_F_REQUEST;
    req.hdr.nlmsg_type = RTM_GETLINK;
    req.hdr.nlmsg_pid = 0;
    req.hdr.nlmsg_seq = seq++;

    req.ifinfo.ifi_family = AF_UNSPEC;
    req.ifinfo.ifi_index = 0;
    req.ifinfo.ifi_change = 0xFFFFFFFF;

    int n = 512;
    struct rtattr *rta0 = (struct rtattr *) (((char *) &req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
    rta0->rta_type = IFLA_IFNAME;
    rta0->rta_len = RTA_LENGTH(strlen(ifname));
    strcpy(RTA_DATA(rta0), ifname);
    rta0 = RTA_NEXT(rta0, n);

    req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + (512 - n);

    if (write(netfd, &req, req.hdr.nlmsg_len) == -1)
        die("write");

    if ((n = read(netfd, buf, 4096)) == -1)
        die("read(netfd)");

    int ifindex = 0;
    for (struct nlmsghdr * hdr = (struct nlmsghdr *)buf; NLMSG_OK(hdr, n); hdr = NLMSG_NEXT(hdr, n)) {
        if (hdr->nlmsg_type == NLMSG_DONE)
            break;

        if (hdr->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *nlerr = (struct nlmsgerr *) NLMSG_DATA(hdr);
            if (nlerr->error < 0)
                errno = -nlerr->error, die("rtnetlink");
        }

        if (hdr->nlmsg_type == RTM_NEWLINK) {
            memcpy(&req, hdr, sizeof(struct nlmsghdr) + sizeof(struct ifinfomsg));
            ifindex = req.ifinfo.ifi_index;
        }
    }

    // Create the macvlan
    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifinfo));
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
    req.hdr.nlmsg_type = RTM_NEWLINK;
    req.hdr.nlmsg_pid = 0;
    req.hdr.nlmsg_seq = seq++;

    req.ifinfo.ifi_family = AF_UNSPEC;
    req.ifinfo.ifi_index = 0;
    req.ifinfo.ifi_change = 0xFFFFFFFF;
    req.ifinfo.ifi_flags = IFF_UP | IFF_BROADCAST | IFF_MULTICAST | IFF_RUNNING;

    n = 512;

    struct rtattr *rta = (struct rtattr *) (((char *) &req) + NLMSG_ALIGN(req.hdr.nlmsg_len));

    rta->rta_type = IFLA_LINK;
    rta->rta_len = RTA_LENGTH(sizeof(ifindex));
    memcpy(RTA_DATA(rta), &ifindex, sizeof(ifindex));
    rta = RTA_NEXT(rta, n);

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

    subrta->rta_type = IFLA_INFO_DATA;
    subrta->rta_len = RTA_LENGTH(8);
    uint16_t data[] = { 8, IFLA_MACVLAN_MODE, MACVLAN_MODE_BRIDGE, 0 };
    memcpy(RTA_DATA(subrta), data, 8);
    subrta = RTA_NEXT(subrta, m);

    rta->rta_len = RTA_LENGTH(n - m);
    rta = RTA_NEXT(rta, n);

    req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + (512 - n);

    if (write(netfd, &req, req.hdr.nlmsg_len) == -1)
        die("write");

    // Wait for acknowledgement or error, whichever comes first
    int ack = 0;
    while (!ack) {
        if ((n = read(netfd, buf, 4096)) == -1)
            die("read(netfd)");

        for (struct nlmsghdr * hdr = (struct nlmsghdr *)buf; NLMSG_OK(hdr, n); hdr = NLMSG_NEXT(hdr, n)) {
            if (hdr->nlmsg_type == NLMSG_DONE)
                break;

            if (hdr->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *nlerr = (struct nlmsgerr *) NLMSG_DATA(hdr);
                if (nlerr->error < 0)
                    errno = -nlerr->error, die("rtnetlink");
                if (nlerr->error == 0)
                    ack = 1;
            }
        }
    }

    close(netfd);
}
