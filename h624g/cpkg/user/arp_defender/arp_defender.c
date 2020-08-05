#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <typedefs.h>

#include <bcmnvram.h>
#include <arpa/inet.h>
#include <shutils.h>

#include <error.h>
#include <sys/signal.h>

#include <linux/sockios.h>
#include <linux/if_arp.h>

#include <syslog.h>

#define MAC_BCAST_ADDR          (unsigned char *) "\xff\xff\xff\xff\xff\xff"

static FILE *fp_out = NULL;

static int validate_ip_address(char *addr)
{
    unsigned int buf[4];
    int i;

    if (strlen(addr) < 7 || strlen(addr) > 15)
        return -1;

    if (sscanf(addr, "%d.%d.%d.%d", &buf[0], &buf[1], &buf[2], &buf[3]) < 4)
        return -1;

    for (i = 0; i < 4; i++) {
        if (buf[i] > 255)
            return -1;
    }

    return (0);
}

static int validate_mac_address(char *addr, unsigned char *mac)
{
    unsigned int buf[6];
    int i;

    if (strlen(addr) < 11 || strlen(addr) > 18)
        return -1;

    if ((sscanf(addr, "%x:%x:%x:%x:%x:%x", &buf[0], &buf[1], &buf[2], &buf[3], &buf[4], &buf[5]) < 6) &&
        (sscanf(addr, "%x-%x-%x-%x-%x-%x", &buf[0], &buf[1], &buf[2], &buf[3], &buf[4], &buf[5]) < 6) &&
        (sscanf(addr, "%x;%x;%x;%x;%x;%x", &buf[0], &buf[1], &buf[2], &buf[3], &buf[4], &buf[5]) < 6)) {
        return -1;
    }

    for (i = 0; i < 6; i++) {
        if (buf[i] > 255)
            return -1;
    }

    if (mac != NULL) {
        for (i = 0; i < 6; i++) {
            mac[i] = (unsigned char)buf[i];
        }
    }

    return (0);
}

static void arp_help(void)
{
    fprintf(stdout,
            "\n" "Usage: arp_defender <IP address> <interface>\n"
            "       arp_defender --help\n");
}

static int arp_table_add(char *ip, char *mac)
{
    struct arpreq req;
    struct sockaddr sa;
    struct sockaddr_in *addr = (struct sockaddr_in *)&sa;
    int sts = 0, sockfd = 0;
    char msg[80];

    if (validate_ip_address(ip) != 0) {
        return -1;
    }
    if (validate_mac_address(mac, NULL) != 0) {
        return -1;
    }

    addr->sin_family = AF_INET;
    addr->sin_port = 0;
    if (inet_aton(ip, &addr->sin_addr) != 0) {
        memcpy((char *)&req.arp_pa, (char *)&sa, sizeof(struct sockaddr));
        bzero((char *)&sa, sizeof(struct sockaddr));
        validate_mac_address(mac, (unsigned char *)sa.sa_data);
        sa.sa_family = ARPHRD_ETHER;
        memcpy((char *)&req.arp_ha, (char *)&sa, sizeof(struct sockaddr));
        req.arp_flags = ATF_PERM;
        req.arp_dev[0] = '\0';

        if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            strcpy(msg, "Error in create socket");
            sts = -1;
        } else {
            if (ioctl(sockfd, SIOCSARP, &req) < 0) {
                strcpy(msg, "Error in SIOCSARP");
                sts = -1;
            }
        }
        if (sockfd > 0)
            close(sockfd);
    } else {
        strcpy(msg, "Invalid IP address");
        sts = -1;
    }

    if (sts != 0) {
        fprintf(stderr, "arp: add %s failed, status: %s\n", ip, msg);
    }

    return (0);
}

static int arp_table_delete(char *ip)
{
    struct arpreq req;
    struct sockaddr sa;
    struct sockaddr_in *addr = (struct sockaddr_in *)&sa;
    int sts = 0, sockfd = 0;
    char msg[80];

    if (validate_ip_address(ip) != 0) {
        return -1;
    }

    addr->sin_family = AF_INET;
    addr->sin_port = 0;
    if (inet_aton(ip, &addr->sin_addr) != 0) {
        memcpy((char *)&req.arp_pa, (char *)&sa, sizeof(struct sockaddr));
        bzero((char *)&sa, sizeof(struct sockaddr));
        sa.sa_family = ARPHRD_ETHER;
        memcpy((char *)&req.arp_ha, (char *)&sa, sizeof(struct sockaddr));
        req.arp_flags = ATF_PERM;
        req.arp_dev[0] = '\0';

        if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            strcpy(msg, "Error in create socket");
            sts = -1;
        } else {
            if (ioctl(sockfd, SIOCDARP, &req) < 0) {
                strcpy(msg, "Error in SIOCDARP");
                sts = -1;
            }
        }
        if (sockfd > 0)
            close(sockfd);
    } else {
        strcpy(msg, "Invalid IP address");
        sts = -1;
    }

    if (sts != 0) {
        fprintf(stderr, "arp: remove %s failed, status: %s\n", ip, msg);
    }

    return (0);
}

struct arpMsg {
    struct ethhdr ethhdr;       /* Ethernet header */
    u_short htype;              /* hardware type (must be ARPHRD_ETHER) */
    u_short ptype;              /* protocol type (must be ETH_P_IP) */
    u_char hlen;                /* hardware address length (must be 6) */
    u_char plen;                /* protocol address length (must be 4) */
    u_short operation;          /* ARP opcode */
    u_char sHaddr[6];           /* sender's hardware address */
    u_char sInaddr[4];          /* sender's IP address */
    u_char tHaddr[6];           /* target's hardware address */
    u_char tInaddr[4];          /* target's IP address */
    u_char pad[18];             /* pad for min. Ethernet payload (60 bytes) */
};

static int get_interface_ipaddr(char *interface, char *mac, u_int32_t * ip, u_int32_t * nm)
{
    u_int32_t ret = 0;
    int s;
    struct ifreq ifr;

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return 0;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr) == 0)
        ret = ((struct sockaddr_in *)(&(ifr.ifr_addr)))->sin_addr.s_addr;
    if (ip)
        *ip = ret;

    if (nm && ioctl(s, SIOCGIFNETMASK, &ifr) == 0)
        *nm = ((struct sockaddr_in *)(&(ifr.ifr_addr)))->sin_addr.s_addr;

    if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0)
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    else
        ret = 0;
    close(s);
    return ret;
}

static int arpping(u_int32_t yiaddr, char *interface, char *mac_out, int sendonly)
{
    int timeout = 2;
    int optval = 1;
    int s;                      /* socket */
    int rv = 1;                 /* return value */
    struct sockaddr addr;       /* for interface name */
    struct arpMsg arp;
    fd_set fdset;
    struct timeval tm;
    time_t prevTime;
    u_int32_t ip, nm;
    char mac[6];
    u_int32_t tmp_ip, start_ip = 0, end_ip = 0;


    if (get_interface_ipaddr(interface, mac, &ip, &nm) == 0) {
        fprintf(fp_out, "Failed to get interface IP and HWADDR\n");
        return -1;
    }

    if ((s = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ARP))) == -1) {
        fprintf(fp_out, "Could not open raw socket");
        return -1;
    }

    if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) == -1) {
        fprintf(fp_out, "Could not setsocketopt on raw socket");
        close(s);
        return -1;
    }

    if (yiaddr == 0xffffffff || yiaddr == ((ip & nm) | (0xffffffff & ~nm))) {
        start_ip = ntohl((ip & nm)) + 1;
        end_ip = ntohl(((ip & nm) | (0xffffffff & ~nm)));
        if (end_ip > (start_ip + 65534))
            end_ip = start_ip + 65534;
    }

    /* send arp request */
    memset(&arp, 0, sizeof(arp));
    memcpy(arp.ethhdr.h_dest, MAC_BCAST_ADDR, 6);       /* MAC DA */
    memcpy(arp.ethhdr.h_source, mac, 6);        /* MAC SA */
    arp.ethhdr.h_proto = htons(ETH_P_ARP);      /* protocol type (Ethernet) */
    arp.htype = htons(ARPHRD_ETHER);    /* hardware type */
    arp.ptype = htons(ETH_P_IP);        /* protocol type (ARP message) */
    arp.hlen = 6;               /* hardware address length */
    arp.plen = 4;               /* protocol address length */
    arp.operation = htons(ARPOP_REQUEST);       /* ARP op code */
    *((u_int *) arp.sInaddr) = ip;      /* source IP address */
    memcpy(arp.sHaddr, mac, 6); /* source hardware address */
    if (start_ip != 0) {
        for (tmp_ip = start_ip; tmp_ip < end_ip; tmp_ip++) {
            *((u_int *) arp.tInaddr) = htonl(tmp_ip);   /* target IP address */

            memset(&addr, 0, sizeof(addr));
            strcpy(addr.sa_data, interface);
            sendto(s, &arp, sizeof(arp), 0, &addr, sizeof(addr));
            if (((tmp_ip % 100) == 99) && (tmp_ip < (start_ip + 255))) {
                sleep(1);
            }
        }
        fprintf(fp_out, "send ARP request packet to all client\n");
    } else {
        *((u_int *) arp.tInaddr) = yiaddr;      /* target IP address */

        memset(&addr, 0, sizeof(addr));
        strcpy(addr.sa_data, interface);
        if (sendto(s, &arp, sizeof(arp), 0, &addr, sizeof(addr)) < 0)
            rv = 0;
    }

    // for gratuitous arp
    if (yiaddr == ip) {
        close(s);
        return 0;
    }

	if (sendonly) {
        close(s);
        return 0;
    }

    /* wait arp reply, and check it */
    tm.tv_usec = 0;
    time(&prevTime);
    while (timeout > 0) {
        FD_ZERO(&fdset);
        FD_SET(s, &fdset);
        tm.tv_sec = timeout;
        if (select(s + 1, &fdset, (fd_set *) NULL, (fd_set *) NULL, &tm) < 0) {
            fprintf(fp_out, "Error on ARPING request: %s", strerror(errno));
            if (errno != EINTR)
                rv = 0;
        } else if (FD_ISSET(s, &fdset)) {
            if (recv(s, &arp, sizeof(arp), 0) < 0)
                rv = 0;
            if (arp.operation == htons(ARPOP_REPLY) && bcmp(arp.tHaddr, mac, 6) == 0) {
                if (start_ip != 0) {
                    struct in_addr tmp_addr;
                    tmp_addr.s_addr = *((u_int *) arp.sInaddr);
                    fprintf(fp_out, "%-15s 0x1 0x2 %02X:%02X:%02X:%02X:%02X:%02X * %s\n", inet_ntoa(tmp_addr),
                            arp.sHaddr[0], arp.sHaddr[1], arp.sHaddr[2], arp.sHaddr[3], arp.sHaddr[4], arp.sHaddr[5],
                            interface);
                } else {
                    if (*((u_int *) arp.sInaddr) == yiaddr) {
                        fprintf(fp_out, "Valid arp reply receved for this address\n");
                        if (mac_out) {
                            sprintf(mac_out, "%02X:%02X:%02X:%02X:%02X:%02X",
                                    arp.sHaddr[0], arp.sHaddr[1], arp.sHaddr[2], arp.sHaddr[3], arp.sHaddr[4], arp.sHaddr[5]);
                        }

                        rv = 0;
                        break;
                    }
                }
            }
        }
        timeout -= time(NULL) - prevTime;
        time(&prevTime);
    }
    close(s);
    if (start_ip == 0) {
        fprintf(fp_out, "%salid arp replies for this address\n", rv ? "No v" : "V");
    }
    return rv;
}


static int find_hwaddr(char *ip, char *mac)
{
    char buf[120];
    int ip_len = strlen(ip);
    int ret = 0;
    FILE *fp;
    char *p;

    fp = fopen("/proc/net/arp", "r");
    if (!fp)
        return 0;

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        if ((strncmp(buf, ip, ip_len)) == 0) {
            p = strtok(buf, " \t");     // ipaddr
            if (!p)
                break;
            p = strtok(NULL, " \t");    // hw_type
            if (!p)
                break;
            p = strtok(NULL, " \t");    // flags
            if (!p)
                break;
            p = strtok(NULL, " \t");    // hw_addr
            if (!p)
                break;
            if (strcmp(p, "00:00:00:00:00:00") != 0) {
                strcpy(mac, p);
                ret = 1;
            }
            break;
        }
    }
    fclose(fp);
    return ret;
}

static void logging(char *ip, char *mac)
{
    if (!mac) {
#if defined(__KOREAN__)
        syslog(LOG_INFO, "ARP " H_TRYING_STT, ip);
#else
        syslog(LOG_INFO, "ARP static [%s] trying", ip);
#endif
    } else {
#if defined(__KOREAN__)
        syslog(LOG_INFO, "ARP " H_STT, ip, mac);
#else
        syslog(LOG_INFO, "ARP static [%s][%s]", ip, mac);
#endif
    }
}

static int arp_static(char *ip, char *intf)
{
    char mac[40];
    struct in_addr yiaddr;
    char cmd[256];

    if (inet_aton(ip, &yiaddr) == 0)
        return -1;

    daemon(0, 0);

#if 0
    logging(ip, NULL);
#endif

    arp_table_delete(ip);       // delete and re-insert mac/ip

    while (1) {
        sprintf(cmd, "/bin/ping -c 1 %s", ip);
        system(cmd);

        if (find_hwaddr(ip, mac)) {
            arp_table_delete(ip);       // delete and re-insert mac/ip
            break;
        } else {
            mac[0] = 0;
            arpping(yiaddr.s_addr, intf, mac, 0);
            if (mac[0] != 0)
                break;
        }
    }
    arp_table_add(ip, mac);     // add static entry
    mac[9] = mac[10] = mac[12] = mac[13] = 'X';
#if 0
    logging(ip, mac);
#endif
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        arp_help();
        return (1);
    }
    
    fp_out = stdout;
    
    arp_static(argv[1], argv[2]);

    return (0);
}
