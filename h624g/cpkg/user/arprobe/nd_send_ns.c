#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>		// macro ioctl is defined
#include <net/if.h>
#include <netinet/in.h>       // IPPROTO_IPV6, IPPROTO_ICMPV6
#include <netinet/icmp6.h>    // struct nd_neighbor_solicit, which contains icmp6_hdr, ND_NEIGHBOR_SOLICIT
#include <netinet/ip6.h>
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <ifaddrs.h>
#include <syslog.h>
#include <sys/syscall.h>
#include <linux/if_addr.h>
#include <dvflag.h>
#include <libytool.h>

#define INFINITE -1
#define POLLTIMEO 100

extern int nd_socket(unsigned ifindex);
extern int nd_recv_na(int fd, void *packet, int pktlen, struct in6_addr *target, int tglen);

struct nd_neighbor_solicit_packet {
	struct ip6_hdr ip6;
	struct nd_neighbor_solicit ns;
	uint8_t opt[32];
} __attribute__ ((aligned(1), packed));

static int current_time_millis(void)
{
	struct timespec ts;
	if (syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &ts))
		return (time_t)-1;
	return (int)((ts.tv_sec * 1000) + (ts.tv_nsec / 1000000));
}

uint16_t inet_cksum(void *addr, int count)
{
	/* Compute Internet Checksum for "count" bytes
	 *         beginning at location "addr".
	 */
	register int32_t sum = 0;
	uint16_t *source = (uint16_t *)addr;

	while (count > 1) {
		/*  This is the inner loop */
		sum += *source++;
		count -= 2;
	}

	/*  Add left-over byte, if any */
	if (count > 0) {
		/* Make sure that the left-over byte is added correctly both
		 * with little and big endian hosts */
		uint16_t tmp = 0;
		*(u_int8_t *) (&tmp) = *(u_int8_t *) source;
		sum += tmp;
	}

	/*  Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

static inline void ipv6_eth_mc_map(struct in6_addr *addr, uint8_t *buf)
{
	/*
	 *	+-------+-------+-------+-------+-------+-------+
	 *      |   33  |   33  | DST13 | DST14 | DST15 | DST16 |
	 *      +-------+-------+-------+-------+-------+-------+
	 */

	buf[0] = 0x33;
	buf[1] = 0x33;

	memcpy(buf + 2, &addr->s6_addr32[3], sizeof(__u32));
}

static inline void ipv6_addr_set(struct in6_addr *addr,
				uint32_t w1, uint32_t w2,
				uint32_t w3, uint32_t w4)
{
	addr->s6_addr32[0] = w1;
	addr->s6_addr32[1] = w2;
	addr->s6_addr32[2] = w3;
	addr->s6_addr32[3] = w4;
}

static inline int ipv6_addr_any(const struct in6_addr *a)
{
	return ((a->s6_addr32[0] | a->s6_addr32[1] |
		 a->s6_addr32[2] | a->s6_addr32[3] ) == 0);
}

static char *in6_ntop(struct in6_addr *addr)
{
	static char str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, addr, str, INET6_ADDRSTRLEN);
	return str;
}

static char *ether_ntoa(uint8_t *addr)
{
	static char str[24];
	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return str;
}

int nd_send_neighor_solicit_packet(struct in6_addr *src_ipv6,
				   struct in6_addr *target_ipv6,
				   int ifindex)
{
	struct sockaddr_ll dest_sll;
	struct nd_neighbor_solicit_packet packet;
	struct ifreq ifr;
	int i, plen, fd, result = -1;
	int unspecified = ipv6_addr_any(src_ipv6);
	const char *msg;

	fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IPV6));
	if (fd < 0) {
		msg = "socket";
		goto ret_msg;
	}

	memset(&dest_sll, 0, sizeof(dest_sll));
	memset(&packet, 0, sizeof(struct nd_neighbor_solicit_packet));

	/* compute link-local solicited-node multicast address */
	ipv6_addr_set(&packet.ip6.ip6_dst,
		      htonl(0xff020000), 0,
		      htonl(0x1),
		      htonl(0xff000000) | target_ipv6->s6_addr32[3]);

	dest_sll.sll_family = AF_PACKET;
	dest_sll.sll_protocol = htons(ETH_P_IPV6);
	dest_sll.sll_ifindex = ifindex;
	dest_sll.sll_halen = 6;
	ipv6_eth_mc_map(&packet.ip6.ip6_dst, dest_sll.sll_addr);

	if (bind(fd, (struct sockaddr *)&dest_sll, sizeof(dest_sll)) < 0) {
		msg = "bind";
		goto ret_close;
	}

	packet.ns.nd_ns_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;
	packet.ns.nd_ns_hdr.icmp6_code = 0;
	packet.ns.nd_ns_target = *target_ipv6;

	plen = sizeof(struct nd_neighbor_solicit) + ((!unspecified) ? 8 : 0);

	if (!unspecified) {
		memset(&ifr, 0, sizeof(ifr));
		if (if_indextoname(ifindex, ifr.ifr_name) == NULL ||
		    ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
			msg = "ioctl";
			goto ret_close;
		}
		packet.opt[0] = ND_OPT_SOURCE_LINKADDR;
		packet.opt[1] = 1;		// units of 8 octets (RFC 4861)
		for (i = 0; i < 6; i++)
			packet.opt[i + 2] = (uint8_t)ifr.ifr_addr.sa_data[i];
	}

	packet.ip6.ip6_vfc = (6 << 4);	/* 4 bits version, top 4 bits of tclass */
	packet.ip6.ip6_src = *src_ipv6;
	packet.ip6.ip6_plen = htons(plen);

	/*
	 * Someone was smoking weed (at least) while inventing UDP checksumming:
	 * UDP checksum skips first four bytes of IPv6 header.
	 * 'next header' field should be summed as if it is one more byte
	 * to the right, therefore we write its value (IPPROTO_ICMPV6)
	 * into ip6_hlim, and its 'real' location remains zero-filled for now.
         *
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  |Version| Traffic Class |           Flow Label                  |
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  |         Payload Length        |  Next Header  |   Hop Limit   |
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  ~                                                               ~
	 *  +                         Source Address                        +
	 *  ~                                                               ~
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  ~                                                               ~
	 *  +                      Destination Address                      +
	 *  ~                                                               ~
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 *  [RFC2460 8.1]
	 *  Any transport or other upper-layer protocol that includes the
	 *  addresses from the IP header in its checksum computation must be
	 *  modified for use over IPv6, to include the 128-bit IPv6 addresses
	 *  instead of 32-bit IPv4 addresses. In particular, the following
	 *  illustration shows the TCP and UDP "pseudo-header" for IPv6:
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  ~                                                               ~
	 *  +                         Source Address                        +
	 *  ~                                                               ~
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  ~                                                               ~
	 *  +                      Destination Address                      +
	 *  ~                                                               ~
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  |                   Upper-Layer Packet Length                   |
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  |                      zero                     |  Next Header  |
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	packet.ip6.ip6_hlim = IPPROTO_ICMPV6;
	packet.ns.nd_ns_hdr.icmp6_cksum = inet_cksum((uint16_t *)&packet + 2,
				sizeof(struct ip6_hdr) - 4 + plen);

	packet.ip6.ip6_hlim = 255;
	packet.ip6.ip6_nxt = IPPROTO_ICMPV6;

	result = sendto(fd, &packet, sizeof(struct ip6_hdr) + plen,
			0, (struct sockaddr *)&dest_sll, sizeof(dest_sll));

	//fprintf(stderr, "Sending NS for %s on %s\n",
	//	in6_ntop(target_ipv6), if_indextoname(ifindex, ifr.ifr_name));

	msg = "sendto";
 ret_close:
	close(fd);
	if (result < 0) {
 ret_msg:
		perror(msg);
	}
	return result;
}

#define IFA_F_DADFAILED	0x08

static int in6_getaddrs(const char *ifname, struct in6_addr *dst, int len)
{
	FILE *f;
	char addr6[40], devname[20];
	int plen, scope, if_idx, ifa_flags, n = 0;
	char addr6p[8][5];

	f = fopen("/proc/net/if_inet6", "r");
	if (f == NULL)
		return 0;

	while (fscanf(f, "%4s%4s%4s%4s%4s%4s%4s%4s %08x %02x %02x %02x %20s\n",
		      addr6p[0], addr6p[1], addr6p[2], addr6p[3], addr6p[4],
		      addr6p[5], addr6p[6], addr6p[7], &if_idx, &plen, &scope,
		      &ifa_flags, devname) != EOF && n < len) {
		if (!strcmp(devname, ifname)) {
			if (!(scope & 0x0010) &&
			    !(ifa_flags & (IFA_F_DADFAILED|IFA_F_NODAD|IFA_F_DEPRECATED|IFA_F_TENTATIVE))) {
				sprintf(addr6, "%s:%s:%s:%s:%s:%s:%s:%s",
					addr6p[0], addr6p[1], addr6p[2], addr6p[3],
					addr6p[4], addr6p[5], addr6p[6], addr6p[7]);
				inet_pton(AF_INET6, addr6, &dst[n++]);
			}
		}
	}

	fclose(f);
	return n;
}

int main(int argc, char **argv)
{
	struct in6_addr dst[12], src;
	char interface[IFNAMSIZ] = "br0";
	int opt, fd, ffd;
	char buffer[1600];
	struct nd_neighbor_advert *na;
	uint32_t fmask = (DF_WANLINK|DF_LANLINK1|DF_LANLINK2|DF_LANLINK3|DF_LANLINK4);
	uint32_t flags, tmp;
	struct pollfd pfd[2];
	int i, ifindex, cnt, probing = 0;
	int expiry, timeout;
	FILE *f;
	char path[80];

	memset(dst, 0, sizeof(dst));
	memset(&src, 0, sizeof(src));

	while ((opt = getopt(argc, argv, "i:")) != -1) {
		switch (opt) {
		case 'i':
			snprintf(interface, IFNAMSIZ, "%s", optarg);
			break;
		default:
			return -1;
		}
	}

	ffd = open("/proc/dvflag", O_RDWR);
	if (ffd == -1)
		exit(EXIT_FAILURE);

	if (ioctl(ffd, DVFLGIO_SETMASK, &fmask))
		perror("ioctl");
	read(ffd, (void *)&tmp, sizeof(tmp));
	flags = tmp & fmask;

	pfd[0].fd = ffd;
	pfd[0].events = POLLIN;
	pfd[1].events = POLLIN;

	probing = !!(flags & fmask);

	for (;;) {
		fd = -1;
		if (probing) {
			if ((cnt = in6_getaddrs(interface, dst, _countof(dst))) > 0)
				fd = nd_socket(if_nametoindex(interface));
			if (fd > -1) {
				ifindex = if_nametoindex(interface);
				for (i = 0; i < cnt; i++)
					nd_send_neighor_solicit_packet(&src, &dst[i],
						ifindex);
			} else
				probing = 0;
		}

		if (fd > -1) {
			pfd[1].fd = fd;
			timeout = POLLTIMEO;
			expiry = current_time_millis() + timeout;
		} else
			timeout = INFINITE;

		while (poll(pfd, (fd > -1) ? 2 : 1, timeout) > 0) {
			if (pfd[0].revents) {
				if (read(ffd, (void *)&tmp, sizeof(tmp)) > 0) {
					tmp &= fmask;
					probing = !!((flags ^ tmp) && ((flags ^ tmp) & tmp));
					flags = tmp;
				}
			}

			if (fd < 0)
				break;
			else if (pfd[1].revents) {
				i = nd_recv_na(fd, buffer, sizeof(buffer), dst, cnt);
				if (i > -1) {
					na = (struct nd_neighbor_advert *)buffer;

					snprintf(path, sizeof(path),
						"/proc/sys/net/ipv6/conf/%s/force_dad_failure",
						interface);
					f = fopen(path, "w");
					if (f) {
						fprintf(f, "%s", in6_ntop(&na->nd_na_target));
						fclose(f);
					}

					syslog(LOG_INFO, "IPv6 duplicate address %s on %s lladdr %s %s%s%s\n",
					       in6_ntop(&na->nd_na_target), interface,
					       ether_ntoa((uint8_t *)&na[1] + 2),
					       (na->nd_na_flags_reserved & ND_NA_FLAG_ROUTER) ? "rtr " : "",
					       (na->nd_na_flags_reserved & ND_NA_FLAG_SOLICITED) ? "sol " : "",
					       (na->nd_na_flags_reserved & ND_NA_FLAG_OVERRIDE) ? "ovr " : "");

					for (cnt--; i < cnt; i++)
						dst[i] = dst[i + 1];
				}
				if (cnt <= 0)
					break;
			}
			timeout = expiry - current_time_millis();
			if (timeout <= 0)
				break;
		}

		if (fd > -1) {
			close(fd);
			probing = 0;
		}
	}

	return 0;
}
