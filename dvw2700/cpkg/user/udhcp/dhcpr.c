#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <features.h>
#if __GLIBC__ >=2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#endif
#include <net/if_arp.h>
#include <linux/filter.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>

#include "packet.h"
#include "debug.h"
#include "dhcpd.h"
#include "options.h"
#include "socket.h"
#include "linux_list.h"
#include "../../../linux-2.6.30/include/net/snoop_dhcp.h"

#define DEBUG_DHCPR

#ifdef DEBUG_DHCPR
#define dprint(arg...) \
	do {\
		if (verbose) \
			printf(arg);\
	} while (0)
#else
#define dprint(arg...) do {} while (0)
#endif

extern int getportbyhaddr(unsigned char *addr);

static char *ifname = NULL;
static int verbose = 0;


#if 0
static void dump(unsigned char *p, unsigned int s, unsigned char *base)
{
	int i, c;

	while ((int)s > 0) {
		printf("%04x: ", (unsigned int)base);

		for (i = 0; i < 16; i++) {
			if (i < (int)s)
				printf("%02x ", p[i] & 0xFF);
			else
				printf("   ");

			if (i == 7)
				printf(" ");
		}
		printf(" |");
		for (i = 0; i < 16; i++) {
			if (i < (int)s) {
				c = p[i] & 0xFF;
				if ((c < 0x20) || (c >= 0x7F))
					c = '.';
			} else
				c = ' ';

			printf("%c", c);
		}
		printf("|\n");
		s -= 16;
		p += 16;
		base += 16;
	}
}
#endif	/* DEBUG_DHCPR */

// tcpdump -i eth0 -s 0 ether src ! 01:01:02:03:04:05 and 'udp port 67' -dd
static struct sock_filter __F__[] = {
	{0x20, 0, 0, 0x00000008},
	{0x15, 0, 2, 0x02030405},	// 1
	{0x28, 0, 0, 0x00000006},
	{0x15, 19, 0, 0x00000101},	// 3
	{0x28, 0, 0, 0x0000000c},
	{0x15, 0, 6, 0x000086dd},
	{0x30, 0, 0, 0x00000014},
	{0x15, 0, 15, 0x00000011},
	{0x28, 0, 0, 0x00000036},
	{0x15, 12, 0, 0x00000043},
	{0x28, 0, 0, 0x00000038},
	{0x15, 10, 11, 0x00000043},
	{0x15, 0, 10, 0x00000800},
	{0x30, 0, 0, 0x00000017},
	{0x15, 0, 8, 0x00000011},
	{0x28, 0, 0, 0x00000014},
	{0x45, 6, 0, 0x00001fff},
	{0xb1, 0, 0, 0x0000000e},
	{0x48, 0, 0, 0x0000000e},
	{0x15, 2, 0, 0x00000043},
	{0x48, 0, 0, 0x00000010},
	{0x15, 0, 1, 0x00000043},
	{0x6, 0, 0, 0x0000ffff},
	{0x6, 0, 0, 0x00000000}
};

static struct sock_fprog dhcpr_filter = {
	sizeof(__F__) / sizeof(struct sock_filter),
	__F__
};

static int dhcpr_socket(int ifindex, unsigned char *addr)
{
	int fd;
	struct sockaddr_ll sock;

	if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		return -1;

	sock.sll_family = AF_PACKET;
	sock.sll_protocol = htons(ETH_P_ALL);
	sock.sll_ifindex = ifindex;
	if (bind(fd, (struct sockaddr *)&sock, sizeof(sock)) < 0) {
		close(fd);
		return -1;
	}

	__F__[3].k = (addr[0] << 8) | addr[1];
	__F__[1].k = (addr[2] << 24) | (addr[3] << 16) | (addr[4] << 8) | addr[5];
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &dhcpr_filter, sizeof(dhcpr_filter)) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

struct dhcp_ether_packet {
	unsigned short pad;
	unsigned char ether[14];
	struct iphdr ip;
	struct udphdr udp;
	struct dhcpMessage data;
	char bumper[512];
};

static int dhcpr_recv(struct dhcp_ether_packet *pbuf, int fd)
{
	int bytes;
	struct ethhdr *eh;
	struct udp_dhcp_packet *P = NULL;
#define packet (P[0])
	u_int32_t source, dest;
	u_int16_t check;
	struct iphdr ip;

	/* 4 align from ip header */
	bytes = read(fd, &pbuf->ether[0], sizeof(*pbuf) - sizeof(pbuf->pad));
	if (bytes < 0)
		return -1;

	if (bytes < (int)(14 + sizeof(struct iphdr) + sizeof(struct udphdr)))
		return -2;

	eh = (struct ethhdr *)&pbuf->ether[0];
	P = (struct udp_dhcp_packet *)&eh[1];
	if (bytes < ntohs(packet.ip.tot_len))
		return -3;

	/* ignore any extra garbage bytes */
	bytes = ntohs(packet.ip.tot_len);

	/* Make sure its the right packet for us, and that it passes sanity checks */
	if (packet.ip.protocol != IPPROTO_UDP ||
	    packet.ip.version != IPVERSION ||
	    packet.ip.ihl != sizeof(packet.ip) >> 2 ||
	    bytes > (int)sizeof(struct udp_dhcp_packet) ||
	    ntohs(packet.udp.len) != (short)(bytes - sizeof(packet.ip)))
		return -4;

	/* check IP checksum */
	check = packet.ip.check;
	packet.ip.check = 0;
	if (check != checksum(&(packet.ip), sizeof(packet.ip)))
		return -5;

	/* verify the UDP checksum by replacing the header with a psuedo header */
	ip = packet.ip;
	source = packet.ip.saddr;
	dest = packet.ip.daddr;
	check = packet.udp.check;
	packet.udp.check = 0;
	memset(&packet.ip, 0, sizeof(packet.ip));

	packet.ip.protocol = IPPROTO_UDP;
	packet.ip.saddr = source;
	packet.ip.daddr = dest;
	packet.ip.tot_len = packet.udp.len;	/* cheat on the psuedo-header */
	if (check && check != checksum(&packet, bytes))
		return -6;

	if (ntohl(pbuf->data.cookie) != DHCP_MAGIC)
		return -7;

	packet.ip = ip;
	return 0;
#undef packet
}

static int dhcpr_send(int fd, struct dhcp_ether_packet *ll_packet,
		      int ifindex, unsigned int mark)
{
	struct sockaddr_ll dest;
	struct iphdr ip;
	int result;

	memcpy(ll_packet->ether, MAC_BCAST_ADDR, ETH_ALEN);
	ll_packet->ip.daddr = INADDR_BROADCAST;

	memset(&dest, 0, sizeof(dest));
	dest.sll_family = PF_PACKET;
	dest.sll_protocol = htons(ETH_P_IP);
	dest.sll_ifindex = ifindex;
	dest.sll_hatype = ARPHRD_ETHER;
	dest.sll_pkttype = PACKET_OTHERHOST;
	dest.sll_halen = ETH_ALEN;
	memcpy(dest.sll_addr, ll_packet->ether, ETH_ALEN);

	ip = ll_packet->ip;
	memset(&ll_packet->ip, 0, sizeof(struct iphdr));
	ll_packet->ip.protocol = ip.protocol;
	ll_packet->ip.saddr = ip.saddr;
	ll_packet->ip.daddr = ip.daddr;
	ll_packet->udp.len = htons(sizeof(struct udphdr) + sizeof(struct dhcpMessage));
	ll_packet->ip.tot_len = ll_packet->udp.len;
	ll_packet->udp.check = checksum(&ll_packet->ip, sizeof(struct udp_dhcp_packet));

	ll_packet->ip.tot_len = htons(sizeof(struct udp_dhcp_packet));
	ll_packet->ip.ihl = sizeof(ip) >> 2;
	ll_packet->ip.version = IPVERSION;
	ll_packet->ip.ttl = IPDEFTTL - 3;
	ll_packet->ip.check = checksum(&ll_packet->ip, sizeof(ip));

	setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(int));

	result = sendto(fd, ll_packet->ether, sizeof(struct udp_dhcp_packet) + 14,
			0, (struct sockaddr*)&dest, sizeof(dest));
	if (result <= 0)
		perror("write");
//#ifdef DEBUG_DHCPR
//	dump((void *)ll_packet->ether, 48, NULL);
//	printf("\n");
//#endif
	return result;
}

struct relay_host {
	struct hlist_node	hlist;
	u_int8_t		chaddr[ETH_ALEN];
	int			at_port;
	signed int		expires;
};

#define ARRAY_SIZE(X) (sizeof(X) / sizeof((X)[0]))
#define RHOST_HASHBITS	6
#define RHOST_AGING	5

static struct hlist_head relay_hosts_buckets[1 << RHOST_HASHBITS];

static inline struct hlist_head *chaddr_hash(const unsigned char *chaddr)
{
	unsigned hash = chaddr[5];
	return &relay_hosts_buckets[hash & ((1 << RHOST_HASHBITS) - 1)];
}

static struct relay_host *find_relay_host(const unsigned char *chaddr)
{
	struct relay_host *rhost;
	struct hlist_node *p;

	hlist_for_each(p, chaddr_hash(chaddr)) {
		rhost = hlist_entry(p, struct relay_host, hlist);
		if (!memcmp(rhost->chaddr, chaddr, ETH_ALEN))
			return rhost;
	}
	return NULL;
}

static struct relay_host *add_relay_host(const unsigned char *chaddr,
					 int port)
{
	struct relay_host *rhost = find_relay_host(chaddr);

	if (rhost)
		goto update_rhost;

	rhost = (struct relay_host *)malloc(sizeof(struct relay_host));
	if (!rhost)
		return NULL;

	hlist_add_head(&rhost->hlist, chaddr_hash(chaddr));
	memcpy(rhost->chaddr, chaddr, ETH_ALEN);

 update_rhost:
	rhost->at_port = port;
	rhost->expires = (int)monotonic_sec() + RHOST_AGING;	/* 5sec aging */
	return rhost;
}

//static void del_relay_host(const unsigned char *chaddr)
//{
//	struct relay_host *rhost = find_relay_host(chaddr);
//	if (rhost) {
//		hlist_del(&rhost->hlist);
//		free(rhost);
//	}
//}

static int timeout_relay_host(void)
{
	int i, curr = (int)monotonic_sec();
	int killed;

	for (i = killed = 0; i < ARRAY_SIZE(relay_hosts_buckets); i++) {
		struct hlist_node *h, *g;
		hlist_for_each_safe(h, g, &relay_hosts_buckets[i]) {
			struct relay_host *rhost
				= hlist_entry(h, struct relay_host, hlist);
			if ((curr - rhost->expires) >= 0) {
				hlist_del(&rhost->hlist);
				free(rhost);
				killed++;
			}
		}
	}
	return killed;
}

static int
add_option_relay_agent(struct dhcpMessage *packet, u_int8_t *ifarp, int port)
{
	unsigned char string[32];
	unsigned short circuit = (port < 0) ? 0 : port;

	string[0] = DHCP_AGENT_INFO;		// Agent Information
	string[1] = 0x0e;			// Agent Information's Length
	string[2] = 0x01;			//   + Agent Circuit ID Sub-option
	string[3] = 0x04;			//   + Agent Circuit ID Sub-option's Length
	string[4] = (u_int8_t)(circuit >> 8);	//     + Physical port
	string[5] = (u_int8_t)circuit;
	string[6] = 0;				//     + Vlan ID
	string[7] = 0;
	string[8] = 0x02;			//   + Agent Remote ID Sub-option
	string[9] = ETH_ALEN;			//   + Agent Remote ID Sub-option's Length
	memcpy(&string[10], ifarp, ETH_ALEN);	//     + br0's HW address
	return add_option_string(packet->options, string);
}

static int strip_option_relay_agent(struct dhcpMessage *packet)
{
	unsigned char *optionptr = get_option(packet, DHCP_AGENT_INFO);
	unsigned char *endptr = &packet->options[sizeof(packet->options)];
	int optlen;

	if (!optionptr)
		return 0;
	optlen = optionptr[-1] + 2;
	optionptr -= 2;
	memmove(optionptr, &optionptr[optlen], (size_t)(endptr - &optionptr[optlen]));
	memset(&endptr[-optlen], 0, optlen);
	return optlen;
}

#ifdef DEBUG_DHCPR
static const char *dhcp_message_names[] = {
	"",
	"DHCPDISCOVER",
	"DHCPOFFER",
	"DHCPREQUEST",
	"DHCPDECLINE",
	"DHCPACK",
	"DHCPNAK",
	"DHCPRELEASE",
	"DHCPINFORM"
};

static char *
sprint_packet(struct dhcp_ether_packet *ll_packet, u_int8_t type, char *buf)
{
	char *p = buf;
	p += sprintf(p, "%s", ether_ntoa(ll_packet->ether));
	p += sprintf(p, " %s", ether_ntoa(&ll_packet->ether[ETH_ALEN]));
	p += sprintf(p, " %u.%u.%u.%u %u.%u.%u.%u",
		     NIPQUAD(ll_packet->ip.saddr), NIPQUAD(ll_packet->ip.daddr));
	p += sprintf(p, " %s - xid 0x%08x", dhcp_message_names[type], ll_packet->data.xid);
	return buf;
}
#endif

static void enable_snoop(int enable)
{
	FILE *f;

	_exclp("2>/dev/null", "aclwrite %s br0 -a cpu -o 7 -r udp -p 0:65535_67:68", (enable) ? "add" : "del");
	_exclp(NULL, "ifconfig %s %spromisc", ifname, (enable) ? "" : "-");
	f = fopen("/proc/sys/net/private/snoop_dhcp", "w");
	if (f) {
		fprintf(f, "%d\n", !!(enable));
		fclose(f);
	}
}

static void exit_dhcpr(int signo)
{
	if (signo)
		enable_snoop(0);
	else
		printf("Usage: dhcpr [options]\n"
		       "  -i interface          Interface to use\n"
		       "  -d                    Verboseness\n\n");
	exit(0);
}

int dhcpr_main(int argc, char **argv)
{
	int fd, opt;
	fd_set rfds;
	struct timeval tv;
	long timeout = 60;
	int i, ifindex = 0;
	unsigned char ifhaddr[ETH_ALEN];
	struct dhcp_ether_packet ll_packet;
	unsigned char *optionptr;
	struct relay_host *rhost;
	int port;
	unsigned int mark;
	char dbuff[128];

	while ((opt = getopt(argc, argv, "i:d")) != EOF) {
		switch (opt) {
		case 'i':
			ifname = optarg;
			break;
		case 'd':
			verbose++;
			break;
  		default:
  			exit_dhcpr(0);
		}
	}

	if (!ifname || !ifname[0])
		exit_dhcpr(0);

	enable_snoop(0);

	if ((read_interface(ifname, &ifindex, NULL, ifhaddr) < 0) ||
	    (fd = dhcpr_socket(ifindex, ifhaddr)) < 0) {
		perror((ifindex) ? "socket" : ifname);
		return -1;
	}

	signal(SIGTERM, exit_dhcpr);
	enable_snoop(1);

	for (i = 0; i < ARRAY_SIZE(relay_hosts_buckets); i++)
		INIT_HLIST_HEAD(&relay_hosts_buckets[i]);

	while (1) {
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		tv.tv_sec = timeout;
		tv.tv_usec = 0;

		if ((i = select(fd + 1, &rfds, NULL, NULL, &tv)) > 0) {
			timeout = RHOST_AGING;
			if (!(i = dhcpr_recv(&ll_packet, fd))) {
				mark = 0;
				if ((optionptr = get_option(&ll_packet.data, DHCP_MESSAGE_TYPE)) == NULL)
					continue;
				switch (optionptr[0]) {
				case DHCPDISCOVER:
				case DHCPREQUEST:
				case DHCPRELEASE:
				case DHCPINFORM:
				case DHCPDECLINE:
					port = getportbyhaddr(&ll_packet.ether[ETH_ALEN]);
					if (port == SNOOP_UPLINK_PORT)	/* WAN port? */
						break;
					if (!add_relay_host(ll_packet.data.chaddr, port))
						perror("add_relay_host");
					else if (add_option_relay_agent(&ll_packet.data, ifhaddr, (port > -1) ? port : 8) > 0) {
						SNOOP_MARK_SET(mark, SNOOP_UPLINK_PORT);	/* forward only to uplink port (WAN) */
						SNOOP_MARK_SET(mark, SNOOP_DROP_WLAN);		/* force for bridge not to forward to WLAN */
						dhcpr_send(fd, &ll_packet, ifindex, mark);
						dprint("REQ: %s [%d]\n", sprint_packet(&ll_packet, optionptr[0], dbuff), port);
					}
					break;
				case DHCPOFFER:
				case DHCPACK:
				case DHCPNAK:
					port = getportbyhaddr(&ll_packet.ether[ETH_ALEN]);
					if (port != SNOOP_UPLINK_PORT)	{	/* Not WAN port? */
						dprint("DHCP response comes from %d port - discard it\n", port);
						break;
					}
					rhost = find_relay_host(ll_packet.data.chaddr);
					if (rhost) {
						strip_option_relay_agent(&ll_packet.data);
						switch (rhost->at_port) {
						case -1:
						case 8:
							SNOOP_MARK_SET(mark, SNOOP_DROP_ETH);
							break;
						default:
							SNOOP_MARK_SET(mark, rhost->at_port);	/* forward to that port from which request come */
							SNOOP_MARK_SET(mark, SNOOP_DROP_WLAN);	/* force for bridge not to forward to WLAN */
							break;
						}
						dhcpr_send(fd, &ll_packet, ifindex, mark);
						dprint("RES: %s [%d:%02x]\n", sprint_packet(&ll_packet, optionptr[0], dbuff),
						       port, SNOOP_MARK_GET(mark));
					} else if (memcmp(ll_packet.data.chaddr, ifhaddr, ETH_ALEN))
						dprint("Not found %s to respond\n", ether_ntoa(ll_packet.data.chaddr));
					break;
				default:
					break;
				}
			} else
				dprint("Not dhcp packet (%d)\n", i);
		} else if (i == 0) {
			timeout_relay_host();
			timeout <<= 1;
			if (timeout > 160)
				timeout = 160;
		} else if (errno != EINTR)
			break;
	}

	close(fd);
	return 0;
}
