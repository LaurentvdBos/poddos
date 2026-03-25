#define _GNU_SOURCE
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "dhcp.h"
#include "poddos.h"
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "net.h"

#define MAGIC_COOKIE 0x63825363

extern char *dnsserver;

enum dhcpopt {
    PAD = 0,
    SUBNET_MASK = 1,
    TIME_OFFSET = 2,
    ROUTER = 3,
    TIME_SERVER = 4,
    NAME_SERVER = 5,
    DOMAIN_NAME_SERVER = 6,
    LOG_SERVER = 7,
    COOKIE_SERVER = 8,
    LPR_SERVER = 9,
    IMPRESS_SERVER = 10,
    RESOURCE_LOCATION_SERVER = 11,
    HOST_NAME = 12,
    BOOT_FILE_SIZE = 13,
    MERIT_DUMP_FILE = 14,
    DOMAIN_NAME = 15,
    SWAP_SERVER = 16,
    ROOT_PATH = 17,
    EXTENSIONS_PATH = 18,

    IP_FORWARDING = 19,
    NONLOCAL_SOURCE_ROUTING = 20,
    POLICY_FILTER = 21,
    MAXIMUM_DATAGRAM_REASSEMBLY_SIZE = 22,
    IP_TIME_TO_LIVE = 23,
    MTU_AGING_TIMEOUT = 24,
    MTU_PLATEAU_TABLE = 25,

    INTERFACE_MTU = 26,
    SUBNETS_ARE_LOCAL = 27,
    BROADCAST = 28,
    MASK_DISCOVERY = 29,
    MASK_SUPPLIER = 30,
    ROUTER_DISCOVERY = 31,
    ROUTER_SOLICITATION = 32,
    STATIC_ROUTE = 33,

    TRAILER_ENCAPSULATION = 34,
    ARP_CACHE_TIMEOUT = 35,
    ETHERNET_ENCAPSULATION = 36,

    TCP_DEFAULT_TTL = 37,
    TCP_KEEPALIVE_INTERVAL = 38,
    TCP_KEEPALIVE_GARBAGE = 39,

    NETWORK_INFORMATION_SERVICE_DOMAIN = 40,
    NETWORK_INFORMATION_SERVICE_SERVERS = 41,
    NETWORK_TIME_PROTOCOL_SERVERS = 42,
    VENDOR_SPECIFIC_INFORMATION = 43,
    NETBIOS_OVER_TCP_IP_NAME_SERVER = 44,
    NETBIOS_OVER_TCP_IP_DATAGRAM_DISTRIBUTION_SERVER = 45,
    NETBIOS_OVER_TCP_IP_NODE_TYPE = 46,
    NETBIOS_OVER_TCP_IP_SCOPE = 47,
    X_WINDOW_SYSTEM_FONT_SERVER = 48,
    X_WINDOW_SYSTEM_DISPLAY_MANAGER = 49,

    REQUESTED_IP_ADDRESS = 50,
    IP_ADDRESS_LEASE_TIME = 51,
    OPTION_OVERLOAD = 52,
    DHCP_MESSAGE_TYPE = 53,
    SERVER_IDENTIFIER = 54,
    PARAMETER_REQUEST_LIST = 55,
    MESSAGE = 56,
    MAXIMUM_DHCP_MESSAGE_SIZE = 57,
    RENEWAL_TIME_VALUE = 58,
    REBINDING_TIME_VALUE = 59,
    VENDOR_CLASS_IDENTIFIER = 60,
    CLIENT_IDENTIFIER = 61,
    TFTP_SERVER_NAME = 66,
    BOOTFILE_NAME = 67,

    NETWORK_INFORMATION_SERVICEPLUS_DOMAIN = 64,
    NETWORK_INFORMATION_SERVICEPLUS_SERVERS = 65,
    MOBILE_IP_HOME_AGENT = 68,
    SMTP_SERVER = 69,
    POP3_SERVERS = 70,
    NNTP_SERVER = 71,
    DEFAULT_WWW_SERVER = 72,
    DEFAULT_FINGER_SERVER = 73,
    DEFAULT_IRC_SERVER = 74,
    STREETTALK_SERVER = 75,
    STDA_SERVER = 76,

    END = 255,
};

enum dhcptype {
    DISCOVER = 1,
    OFFER = 2,
    REQUEST = 3,
    DECLINE = 4,
    ACK = 5,
    NACK = 6,
    RELEASE = 7,
    INFORM = 8,
    FORCERENEW = 9,
    LEASEQUERY = 10,
    LEASEUNASSIGNED = 11,
    LEASEUNKNOWN = 12,
    LEASEACTIVE = 13,
    BULKLEASEQUERY = 14,
    LEASEQUERYDONE = 15,
    ACTIVELEASEQUERY = 16,
    LEASEQUERYSTATUS = 17,
    TLS = 18,
};

struct dhcphdr {
    uint8_t op, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    uint8_t chaddr[16];

    uint8_t sname[64];
    uint8_t file[128];

    uint32_t magic;
};

// Indicator whether dhcp is configured
int dhcpconfigured = 0;

// My address and server address. Used as state (i.e., 0 indicates discovery,
// non-zero indicates request)
in_addr_t yiaddr = 0, siaddr = 0;

uint32_t xid = 0;

int ifindex = -1;

uint16_t chksum(void *buf, int n)
{
    uint8_t *buf8 = (uint8_t *) buf;
    uint16_t *buf16 = (uint16_t *) buf;
    uint32_t ret = 0;

    for (int i = 0; i < n; i += 2) {
        ret += *(buf16++);
    }
    if (n % 2)
        ret += buf8[n - 1];

    ret = (ret >> 16) + (ret & 0xFFFF);
    ret = (ret >> 16) + (ret & 0xFFFF);
    return ~ret;
}

int optlen(uint8_t *buf)
{
    int n = 0;
    while (buf[n] != END) {
        uint8_t len = buf[n + 1];
        n += len + 2;
    }
    return n + 1;
}

uint8_t *optget(uint8_t *buf, enum dhcpopt which)
{
    int n = 0;
    while (buf[n] != END) {
        if (buf[n] == PAD) {
            n += 1;
            continue;
        }

        if (buf[n] == which)
            return buf + n + 2;

        uint8_t len = buf[n + 1];
        n += len + 2;
    }
    return NULL;
}

bool dhcpvalid(int n, uint8_t *buf)
{
    int i = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dhcphdr);

    while (i + 1 < n && buf[i] != END) {
        uint8_t len = buf[i + 1];
        i += len + 2;
    }

    return i < n && buf[i] == END;
}

void addopt(uint8_t * buf, enum dhcpopt which, ...)
{
    // Search for END and put the new op in there
    int n = optlen(buf);
    buf[n - 1] = which;

    int len;

    va_list va;
    va_start(va, which);
    switch (which) {
    case REQUESTED_IP_ADDRESS:
    case SERVER_IDENTIFIER:
        buf[n++] = sizeof(uint32_t);
        uint32_t ipaddr = va_arg(va, uint32_t);
        memcpy(buf + n, &ipaddr, sizeof(uint32_t));
        n += sizeof(uint32_t);
        break;

    case DHCP_MESSAGE_TYPE:
        buf[n++] = 1;
        buf[n++] = va_arg(va, enum dhcptype);
        break;

    case PARAMETER_REQUEST_LIST:
        enum dhcpopt param = 0;
        buf[n++] = 0;

        len = n;
        while ((param = va_arg(va, enum dhcpopt)))
             buf[n++] = param;
        buf[len - 1] = n - len;
        break;

    case END:
        // Nothing to do, END is already inserted
        return;

    default:
        len = va_arg(va, int);
        uint8_t *payload = va_arg(va, uint8_t *);
        buf[n++] = len;
        for (int i = 0; i < len; i++)
            buf[n++] = payload[i];
        break;
    }
    va_end(va);

    buf[n] = END;
}

void dhcpsend(int sock)
{
    char buf[1000];
    memset(buf, 0, 1000);
    struct iphdr *iphdr = (struct iphdr *) buf;
    struct udphdr *udphdr = (struct udphdr *) (iphdr + 1);
    struct dhcphdr *dhcphdr = (struct dhcphdr *) (udphdr + 1);

    uint8_t *opt = (uint8_t *) (dhcphdr + 1);
    opt[0] = END;

    memset(dhcphdr, 0, sizeof(struct dhcphdr));

    dhcphdr->op = 1; // 1 means "REQUEST"
    dhcphdr->htype = 1; // Ethernet, can also be found as the ARPHRD_ETHER constant in linux/if_arp.h
    dhcphdr->hlen = ETHER_ADDR_LEN;
    dhcphdr->xid = htonl(xid);
    memcpy(dhcphdr->chaddr, mac, 6);
    dhcphdr->magic = htonl(MAGIC_COOKIE);

    if (yiaddr == 0) {
        syslog(LOG_INFO, "dhcp: discover");

        addopt(opt, DHCP_MESSAGE_TYPE, DISCOVER);
    } else {
        syslog(LOG_INFO, "dhcp: request %d.%d.%d.%d from %d.%d.%d.%d",
            yiaddr & 0xFF, (yiaddr >> 8) & 0xFF, (yiaddr >> 16) & 0xFF, (yiaddr >> 24) & 0xFF,
            siaddr & 0xFF, (siaddr >> 8) & 0xFF, (siaddr >> 16) & 0xFF, (siaddr >> 24) & 0xFF);

        dhcphdr->siaddr = siaddr;

        addopt(opt, DHCP_MESSAGE_TYPE, REQUEST);
        addopt(opt, REQUESTED_IP_ADDRESS, yiaddr);
        addopt(opt, SERVER_IDENTIFIER, siaddr);
        addopt(opt, PARAMETER_REQUEST_LIST, SUBNET_MASK, ROUTER, DOMAIN_NAME_SERVER, DOMAIN_NAME);
        if (name)
            addopt(opt, HOST_NAME, strlen(name), name);
    }

    uint16_t len = sizeof(struct dhcphdr) + optlen(opt);

    len += sizeof(struct udphdr);
    udphdr->check = 0;
    udphdr->dest = htons(67);
    udphdr->len = htons(len);
    udphdr->source = htons(68);

    len += sizeof(struct iphdr);
    iphdr->daddr = INADDR_BROADCAST;
    iphdr->frag_off = 0;
    iphdr->id = htons(0);
    iphdr->ihl = 5;
    iphdr->protocol = IPPROTO_UDP;
    iphdr->saddr = INADDR_ANY;
    iphdr->tos = 0x0;
    iphdr->tot_len = htons(len);
    iphdr->ttl = 16;
    iphdr->version = 4;
    iphdr->check = chksum(iphdr, sizeof(struct iphdr));

    struct sockaddr_ll addr_ll;
    memset(&addr_ll, 0, sizeof(struct sockaddr_ll));
    addr_ll.sll_family = AF_PACKET;
    addr_ll.sll_protocol = htons(ETH_P_IP);
    addr_ll.sll_ifindex = ifindex;
    addr_ll.sll_addr[0] = addr_ll.sll_addr[1] = addr_ll.sll_addr[2] = addr_ll.sll_addr[3] = addr_ll.sll_addr[4] =
        addr_ll.sll_addr[5] = 0xff;
    addr_ll.sll_halen = ETHER_ADDR_LEN;

    if (sendto(sock, buf, len, 0, (struct sockaddr *) &addr_ll, sizeof(struct sockaddr_ll)) == -1)
        die("sendto");
}

int dhcpstep(char *ifname, int sock)
{
    int n;
    uint8_t buf[65535];

    if ((n = recv(sock, buf, 65535, 0)) == -1) {
        if (errno == ENOTSOCK) {
            // If it is not a socket, it is probably a timerfd timing out
            close(sock);
            sock = dhcpstart(ifname);
            if ((n = recv(sock, buf, 65535, 0)) == -1)
                die("recv");
        } else
            die("recv");
    }

    if (!dhcpvalid(n, buf))
        return sock; // Package is for whatever reason not a valid DHCP package

    struct iphdr *iphdr = (struct iphdr *) buf;
    struct udphdr *udphdr = (struct udphdr *) (iphdr + 1);
    struct dhcphdr *dhcphdr = (struct dhcphdr *) (udphdr + 1);
    if (iphdr->protocol == IPPROTO_UDP && // Is it an UDP package ...
        ntohs(udphdr->dest) == 68 && // ... sent to port 68 ...
        ntohl(dhcphdr->magic) == MAGIC_COOKIE && // ... with the correct magic cookie ...
        ntohl(dhcphdr->xid) == xid && // ... our xid ...
        !memcmp(dhcphdr->chaddr, mac, ETHER_ADDR_LEN) && // ... our MAC address ...
        dhcphdr->op == 0x02) { // ... and a response? ...
        // ... then it is a DHCP package for us

        uint8_t *options = (uint8_t *) (dhcphdr + 1);
        uint8_t *msgtype = optget(options, DHCP_MESSAGE_TYPE);
        if (!msgtype)
            return sock; // Ignore DHCP package without message type

        if (*msgtype == OFFER) {
            syslog(LOG_INFO, "dhcp: received offer %d.%d.%d.%d from %d.%d.%d.%d",
                dhcphdr->yiaddr & 0xFF, (dhcphdr->yiaddr >> 8) & 0xFF, (dhcphdr->yiaddr >> 16) & 0xFF, (dhcphdr->yiaddr >> 24) & 0xFF,
                dhcphdr->siaddr & 0xFF, (dhcphdr->siaddr >> 8) & 0xFF, (dhcphdr->siaddr >> 16) & 0xFF, (dhcphdr->siaddr >> 24) & 0xFF);

            yiaddr = dhcphdr->yiaddr;
            siaddr = dhcphdr->siaddr;

            dhcpsend(sock);
        } else if (*msgtype == ACK) {
            syslog(LOG_INFO, "dhcp: acknowledged");

            const uint8_t *router = optget(options, ROUTER);
            const uint8_t *brdcast = optget(options, BROADCAST);
            const uint8_t *lease = optget(options, IP_ADDRESS_LEASE_TIME);
            const uint8_t *mask = optget(options, SUBNET_MASK);
            if (!router || !brdcast || !lease || !mask)
                diex("Missing required DHCP options in ACK");
            if (*(router - 1) != 4 || *(brdcast - 1) != 4 || *(lease - 1) != 4 || *(mask - 1) != 4)
                diex("Invalid length of required DHCP options in ACK");

            uint32_t lease_time = ntohl(*(uint32_t *)lease);

            uint8_t nlbuf[4096];
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
            } req_info;

            // Send a request to obtain the link index of the provided link
            memset(&req_info, 0, sizeof(req_info));
            req_info.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req_info.ifinfo));
            req_info.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
            req_info.hdr.nlmsg_type = RTM_GETLINK;
            req_info.hdr.nlmsg_pid = 0;
            req_info.hdr.nlmsg_seq = seq++;

            req_info.ifinfo.ifi_family = AF_UNSPEC;
            req_info.ifinfo.ifi_index = 0;
            req_info.ifinfo.ifi_change = 0xFFFFFFFF;

            int n = 512;
            struct rtattr *rta_info = (struct rtattr *) (((char *) &req_info) + NLMSG_ALIGN(req_info.hdr.nlmsg_len));
            rta_info->rta_type = IFLA_IFNAME;
            rta_info->rta_len = RTA_LENGTH(strlen(ifname));
            strcpy(RTA_DATA(rta_info), ifname);
            rta_info = RTA_NEXT(rta_info, n);

            req_info.hdr.nlmsg_len = NLMSG_ALIGN(req_info.hdr.nlmsg_len) + (512 - n);

            if (write(netfd, &req_info, req_info.hdr.nlmsg_len) == -1)
                die("write");

            if ((n = read(netfd, nlbuf, 4096)) == -1)
                die("read(netfd)");

            int ifindex = -1;
            for (struct nlmsghdr * hdr = (struct nlmsghdr *)nlbuf; NLMSG_OK(hdr, n); hdr = NLMSG_NEXT(hdr, n)) {
                if (hdr->nlmsg_type == NLMSG_DONE)
                    break;

                if (hdr->nlmsg_type == NLMSG_ERROR) {
                    struct nlmsgerr *nlerr = (struct nlmsgerr *) NLMSG_DATA(hdr);
                    if (nlerr->error < 0)
                        errno = -nlerr->error, die("rtnetlink");
                }

                if (hdr->nlmsg_type == RTM_NEWLINK) {
                    memcpy(&req_info, hdr, sizeof(struct nlmsghdr) + sizeof(struct ifinfomsg));
                    ifindex = req_info.ifinfo.ifi_index;
                }
            }
            if (ifindex == -1)
                diex("Interface %s went missing.", ifname);

            // Set the IP address received from the DHCP server
            struct {
                struct nlmsghdr hdr;
                struct ifaddrmsg ifaddr;
                char attrbuf[512];
            } req_addr;

            memset(&req_addr, 0, sizeof(req_addr));
            req_addr.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
            req_addr.hdr.nlmsg_type = RTM_NEWADDR;
            req_addr.hdr.nlmsg_pid = 0;
            req_addr.hdr.nlmsg_seq = seq++;

            req_addr.ifaddr.ifa_family = AF_INET;
            req_addr.ifaddr.ifa_scope = RT_SCOPE_UNIVERSE;
            req_addr.ifaddr.ifa_index = ifindex;
            req_addr.ifaddr.ifa_prefixlen = __builtin_popcount(mask[0] | (mask[1] << 8) | (mask[2] << 16) | (mask[3] << 24));

            // Set the IP address as local address
            n = 512;
            struct rtattr *rta_addr = (struct rtattr *) req_addr.attrbuf;
            rta_addr->rta_type = IFA_LOCAL;
            rta_addr->rta_len = RTA_LENGTH(sizeof(yiaddr));
            memcpy(RTA_DATA(rta_addr), &yiaddr, sizeof(yiaddr));
            rta_addr = RTA_NEXT(rta_addr, n);

            // Set the broadcast address
            struct in_addr baddr;
            memcpy(&baddr, brdcast, sizeof(baddr));
            rta_addr->rta_type = IFA_BROADCAST;
            rta_addr->rta_len = RTA_LENGTH(sizeof(baddr));
            memcpy(RTA_DATA(rta_addr), &baddr, sizeof(baddr));
            rta_addr = RTA_NEXT(rta_addr, n);

            // Set the preferred and valid lifetime of the address to the lease time
            struct ifa_cacheinfo ci = {
                .ifa_prefered = lease_time,
                .ifa_valid = lease_time,
                .cstamp = 0,
                .tstamp = 0
            };

            rta_addr->rta_type = IFA_CACHEINFO;
            rta_addr->rta_len = RTA_LENGTH(sizeof(ci));
            memcpy(RTA_DATA(rta_addr), &ci, sizeof(ci));
            rta_addr = RTA_NEXT(rta_addr, n);

            req_addr.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req_addr.ifaddr)) + (512 - n);

            if (write(netfd, &req_addr, req_addr.hdr.nlmsg_len) == -1)
                die("write(netfd)");

            if ((n = read(netfd, nlbuf, sizeof(nlbuf))) == -1)
                die("read(netfd)");

            for (struct nlmsghdr *hdr = (struct nlmsghdr *) nlbuf; NLMSG_OK(hdr, n); hdr = NLMSG_NEXT(hdr, n)) {
                if (hdr->nlmsg_type == NLMSG_ERROR) {
                    struct nlmsgerr *nlerr = (struct nlmsgerr *) NLMSG_DATA(hdr);
                    if (nlerr->error < 0)
                        errno = -nlerr->error, die("rtnetlink RTM_NEWADDR");
                }
            }

            // Set a default routing entry (the "gateway")
            struct in_addr gw;
            memcpy(&gw, router, sizeof(gw));

            struct {
                struct nlmsghdr nh;
                struct rtmsg rt;
                char attrbuf[256];
            } req_rt;

            memset(&req_rt, 0, sizeof(req_rt));
            req_rt.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
            req_rt.nh.nlmsg_type = RTM_NEWROUTE;
            req_rt.nh.nlmsg_seq = seq++;

            req_rt.rt.rtm_family = AF_INET;
            req_rt.rt.rtm_table = RT_TABLE_MAIN;
            req_rt.rt.rtm_protocol = RTPROT_DHCP;
            req_rt.rt.rtm_scope = RT_SCOPE_UNIVERSE;
            req_rt.rt.rtm_type = RTN_UNICAST;
            req_rt.rt.rtm_flags = RTF_GATEWAY;
            req_rt.rt.rtm_dst_len = 0;
            req_rt.rt.rtm_src_len = 0;

            // Destionation is zero (i.e., default route)
            n = 512;
            struct rtattr *rta_rt = (struct rtattr *)req_rt.attrbuf;
            rta_rt->rta_type = RTA_DST;
            rta_rt->rta_len = RTA_LENGTH(sizeof(struct in_addr));
            memset(RTA_DATA(rta_rt), 0, sizeof(struct in_addr));
            rta_rt = RTA_NEXT(rta_rt, n);

            rta_rt->rta_type = RTA_OIF;
            rta_rt->rta_len = RTA_LENGTH(sizeof(int));
            memcpy(RTA_DATA(rta_rt), &ifindex, sizeof(ifindex));
            rta_rt = RTA_NEXT(rta_rt, n);

            rta_rt->rta_type = RTA_GATEWAY;
            rta_rt->rta_len = RTA_LENGTH(sizeof(gw));
            memcpy(RTA_DATA(rta_rt), &gw, sizeof(gw));
            rta_rt = RTA_NEXT(rta_rt, n);

            req_rt.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req_rt.rt)) + (512 - n);

            if (write(netfd, &req_rt, req_rt.nh.nlmsg_len) == -1)
                die("write(netfd)");

            if ((n = read(netfd, nlbuf, sizeof(nlbuf))) == -1)
                die("read(netfd)");

            for (struct nlmsghdr *hdr = (struct nlmsghdr *) nlbuf; NLMSG_OK(hdr, n); hdr = NLMSG_NEXT(hdr, n)) {
                if (hdr->nlmsg_type == NLMSG_ERROR) {
                    struct nlmsgerr *nlerr = (struct nlmsgerr *) NLMSG_DATA(hdr);
                    if (nlerr->error < 0)
                        errno = -nlerr->error, die("rtnetlink RTM_NEWROUTE");
                }
            }

            // Create a /etc/resolv.conf
            FILE *f = fopen("/etc/resolv.conf", "w");

            if (dnsserver) {
                fprintf(f, "nameserver %s\n", dnsserver);
            } else {
                uint8_t *dns = optget(options, DOMAIN_NAME_SERVER);
                if (dns) {
                    uint8_t *len = dns - 1;
                    for (int i = 0; i + 3 < *len; i += 4) {
                        struct in_addr addr;
                        memcpy(&addr, dns + i, 4);
                        fprintf(f, "nameserver %s\n", inet_ntoa(addr));
                    }
                }
            }

            uint8_t *domain = optget(options, DOMAIN_NAME);
            if (domain) {
                uint8_t *len = domain - 1;
                fprintf(f, "search %.*s\n", *len, domain);
            }

            fclose(f);
            close(sock);
            close(netfd);

            // Cap lease time to 4 days
            if (lease_time > 60*60*24*4)
                lease_time = 60*60*24*4;

            // Create timerfd ...
            int timerfd = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC);
            if (timerfd == -1)
                die("timerfd_create");

            // ... and arm it to 90% of the lease time + random jitter between 0 and 128
            struct itimerspec val = {
                .it_value = { .tv_sec = lease_time / 10 * 9 + (xid & 0x7F), .tv_nsec = 0 },
                .it_interval = { 0 }
            };
            if (timerfd_settime(timerfd, 0, &val, NULL) == -1)
                die("timerfd_settime");

            dhcpconfigured = 1;
            syslog(LOG_INFO, "dhcp: configured (for %ld secs)", val.it_value.tv_sec);

            return timerfd;
        } else {
            // In case of any other message (e.g., NACK) we go back to uninitialized state
            syslog(LOG_INFO, "dhcp: deconfigured");

            yiaddr = siaddr = 0;

            dhcpsend(sock);
        }
    }

    return sock;
}

// Initiate a DHCP handshake
int dhcpstart(char *ifname)
{
    struct ifreq req;
    int sock;

    while (!xid) {
        if (getrandom(&xid, sizeof(xid), 0) == -1)
            die("getrandom");
    }

    // Get a raw socket
    sock = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_IP));
    if (sock == -1)
        die("socket");

    // Get the index of the interface;
    strncpy(req.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFINDEX, &req) == -1)
        die("ioctl(SIOCGIFINDEX)");
    ifindex = req.ifr_ifindex;

    // Get the mac address of the interface
    strncpy(req.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &req) == -1)
        die("ioctl(SIOCGIFHWADDR)");
    memcpy(mac, &req.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

    // Bind the socket to the provided index and start receiving IP packages.
    struct sockaddr_ll addr_ll;
    memset(&addr_ll, 0, sizeof(struct sockaddr_ll));
    addr_ll.sll_family = AF_PACKET;
    addr_ll.sll_protocol = htons(ETH_P_IP);
    addr_ll.sll_ifindex = ifindex;
    if (bind(sock, (struct sockaddr *) &addr_ll, sizeof(struct sockaddr_ll)) == -1)
        die("bind");

    // Initiate a DHCP handshake
    dhcpsend(sock);

    return sock;
}
