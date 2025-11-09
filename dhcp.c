#define _GNU_SOURCE
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "dhcp.h"
#include "poddos.h"

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
        if (buf[n] == which)
            return buf + n + 2;
        uint8_t len = buf[n + 1];
        n += len + 2;
    }
    return NULL;
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
        addopt(opt, DHCP_MESSAGE_TYPE, DISCOVER);
    } else {
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
    char buf[65535];

    if ((n = recv(sock, buf, 65535, 0)) == -1)
        die("recv");

    const size_t minsize = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dhcphdr) + 1;
    if (n < minsize)
        return sock; // Package is too small to be a DHCP package

    struct iphdr *iphdr = (struct iphdr *) buf;
    struct udphdr *udphdr = (struct udphdr *) (iphdr + 1);
    struct dhcphdr *dhcphdr = (struct dhcphdr *) (udphdr + 1);
    if (iphdr->protocol == IPPROTO_UDP && // Is it an UDP package ...
        ntohs(udphdr->dest) == 68 && // ... sent to port 68 ...
        ntohl(dhcphdr->magic) == MAGIC_COOKIE && // ... with the correct magic cookie ...
        ntohl(dhcphdr->xid) == xid && // ... our xid ...
        !memcmp(dhcphdr->chaddr, mac, ETHER_ADDR_LEN) && // ... our MAC address ...
        dhcphdr->op == 0x02) { // ... and a response? ...
        // ... then it is a DHCP package (probably)

        uint8_t *msgtype = optget((uint8_t *) (dhcphdr + 1), DHCP_MESSAGE_TYPE);
        if (!msgtype)
            return sock; // Ignore malformed DHCP package

        if (*msgtype == OFFER) {
            yiaddr = dhcphdr->yiaddr;
            siaddr = dhcphdr->siaddr;

            dhcpsend(sock);
        } else if (*msgtype == ACK) {
            // Initialize the link
            struct ifreq req;
            strncpy(req.ifr_name, ifname, IFNAMSIZ);
            uint8_t *options = (uint8_t *) (dhcphdr + 1);
            struct sockaddr_in *sai = (struct sockaddr_in *) &req.ifr_addr;
            sai->sin_family = AF_INET;
            sai->sin_port = 0;

            // Set ip
            sai->sin_addr.s_addr = yiaddr;
            if (ioctl(sock, SIOCSIFADDR, &req) == -1)
                die("ioctl(SIOCSIFADDR)");

            // Set netmask
            memcpy(&sai->sin_addr, optget(options, SUBNET_MASK), 4);
            if (ioctl(sock, SIOCSIFNETMASK, &req) == -1)
                die("ioctl(SIOCIFNETMASK)");

            // Set broadcast address
            memcpy(&sai->sin_addr, optget(options, BROADCAST), 4);
            if (ioctl(sock, SIOCSIFBRDADDR, &req) == -1)
                die("ioctl(SIOCSIFBRDADDR)");

            // Set a default routing entry (the "gateway")
            struct rtentry route = { 0 };
            sai = (struct sockaddr_in *) &route.rt_gateway;
            sai->sin_family = AF_INET;
            memcpy(&sai->sin_addr, optget(options, ROUTER), 4);
            sai = (struct sockaddr_in *) &route.rt_dst;
            sai->sin_family = AF_INET;
            sai->sin_addr.s_addr = INADDR_ANY;
            sai = (struct sockaddr_in *) &route.rt_genmask;
            sai->sin_family = AF_INET;
            sai->sin_addr.s_addr = INADDR_ANY;

            route.rt_flags = RTF_UP | RTF_GATEWAY;
            route.rt_metric = 0;
            route.rt_dev = ifname;

            ioctl(sock, SIOCDELRT, &route); // Errors are ignored
            if (ioctl(sock, SIOCADDRT, &route) == -1)
                die("ioctl(SIOCADDRT)");

            // Create a /etc/resolv.conf
            FILE *f = fopen("/etc/resolv.conf", "w");
            uint8_t *dns = optget(options, DOMAIN_NAME_SERVER);
            uint8_t *len = dns - 1;
            if (!dnsserver) {
                for (int i = 0; i < *len; i += 4) {
                    struct in_addr addr;
                    memcpy(&addr, dns + i, 4);
                    fprintf(f, "nameserver %s\n", inet_ntoa(addr));
                }
            } else {
                fprintf(f, "nameserver %s\n", dnsserver);
            }

            uint8_t *domain = optget(options, DOMAIN_NAME);
            len = domain - 1;
            if (domain) {
                fprintf(f, "search %.*s\n", *len, domain);
            }

            fclose(f);
            close(sock);

            // Return when dhcp should be restarted (when the lease time is 90%)
            uint8_t *lease = optget(options, IP_ADDRESS_LEASE_TIME);
            int lease_time = (int) ntohl(*(uint32_t *) lease);
            sock = -lease_time / 10 * 9;
        } else {
            // In case of any other message (e.g., NACK) we go back to start
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
