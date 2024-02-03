#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_tun.h>

#include <string.h>

#include "net.h"
#include "poddos.h"

char tapname[IFNAMSIZ] = { 0 };

void bringloup()
{
    struct ifreq req = {
        .ifr_name = "lo",
        .ifr_flags = IFF_UP | IFF_RUNNING
    };
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) err(1, "socket(AF_INET, SOCK_DGRAM, 0)");
    if (ioctl(sock, SIOCSIFFLAGS, &req) == -1) err(1, "ioctl(SIOCSIFFLAGS)");
    close(sock);
}

int rawsock(char *ifname)
{
    struct ifreq req;
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) err(1, "socket(AF_PACKET)");

    // Make the socket cloexec
    fcntl(sock, F_SETFD, O_CLOEXEC);

    // Get the index of the interface;
    memset(&req, 0, sizeof(struct ifreq));
    strcpy(req.ifr_name, ifname);
    if (ioctl(sock, SIOCGIFINDEX, &req) == -1) err(1, "ioctl(SIOCGIFINDEX)");
    int ifindex = req.ifr_ifindex;

    // Make the socket receive all frames (promiscuous mode)
    struct packet_mreq mreq = {
        .mr_ifindex = ifindex,
        .mr_type = PACKET_MR_PROMISC,
    };
    if (setsockopt(sock, SOL_SOCKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) err(1, "setsockopt(PACKET_ADD_MEMBERSHIP)");

    // Bind the socket to the provided index and start receiving all packages.
    struct sockaddr_ll addr_ll;
    memset(&addr_ll, 0, sizeof(struct sockaddr_ll));
    addr_ll.sll_family = AF_PACKET;
    addr_ll.sll_protocol = htons(ETH_P_ALL);
    addr_ll.sll_ifindex = ifindex;
    if (bind(sock, (struct sockaddr *)&addr_ll, sizeof(struct sockaddr_ll)) == -1) err(1, "bind");

    return sock;
}

int maketap()
{
    struct ifreq req;
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd == -1) err(1, "open(/dev/net/tun)");

    // Initialize the tap, which populates req.ifr_name for us
    memset(&req, 0, sizeof(struct ifreq));
    req.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &req) == -1) err(1, "ioctl(TUNSETIFF)");

    // Store the name
    strncpy(tapname, req.ifr_name, IFNAMSIZ);

    // Initialize an arbitrary socket to configure the device
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) err(1, "socket(AF_INET, SOCK_DGRAM, 0)");

    // Set the mac address requested by the user (if any)
    if (mac[0] || mac[1] || mac[2] || mac[3] || mac[4] || mac[5]) {
        req.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(req.ifr_hwaddr.sa_data, mac, ETHER_ADDR_LEN);
        if (ioctl(sock, SIOCSIFHWADDR, &req) == -1) err(1, "ioctl(SIOCSIFHWADDR)");
    }

    // Bring the tap up
    req.ifr_flags = IFF_UP | IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, &req) == -1) err(1, "ioctl(SIOCSIFFLAGS)");

    close(sock);

    return fd;
}
