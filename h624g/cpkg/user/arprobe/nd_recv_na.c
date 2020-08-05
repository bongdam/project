#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>		// macro ioctl is defined
#include <net/if.h>
#include <netinet/in.h>       // IPPROTO_IPV6, IPPROTO_ICMPV6
#include <netinet/icmp6.h>    // struct nd_neighbor_solicit, which contains icmp6_hdr, ND_NEIGHBOR_SOLICIT
#include <netinet/ip6.h>
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <netinet/if_ether.h>
#include <netpacket/packet.h>

int nd_socket(unsigned ifindex)
{
	struct ifreq ifr;
	int fd;
	const int on = 1;
	const char *msg;

	if ((fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
		msg = "socket";
		goto ret_msg;
	}

	memset(&ifr, 0, sizeof(ifr));
	if_indextoname(ifindex, ifr.ifr_name);
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
		msg = "BINDTODEVICE";
		goto ret_close;
	}
#ifdef ICMP6_FILTER
	{
		struct icmp6_filter filt;

		ICMP6_FILTER_SETBLOCKALL(&filt);
		ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &filt);

		if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filt,
					sizeof(filt)) < 0)
			perror("ICMP6_FILTER");
	}
#endif /*ICMP6_FILTER*/
	setsockopt(fd, SOL_IPV6, IPV6_HOPLIMIT, &on, sizeof(on));

	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
	return fd;
 ret_close:
	close(fd);
 ret_msg:
	perror(msg);
	return -1;
}

int nd_recv_na(int fd, void *packet, int pktlen, struct in6_addr *addr, int len)
{
	struct msghdr msg;
	struct sockaddr_in6 from;
	struct iovec iov;
	char control_buf[CMSG_SPACE(36)];
	struct nd_neighbor_advert *na = packet;
	int i;

	msg.msg_name = &from;
	msg.msg_namelen = sizeof(from);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control_buf;
	iov.iov_base = na;
	iov.iov_len = pktlen;

	while (1) {
		int c;
		struct cmsghdr *mp;
		int hoplimit = -1;

		msg.msg_controllen = sizeof(control_buf);

		c = recvmsg(fd, &msg, 0);
		if (c < 0) {
			if (errno != EINTR)
				break;
			continue;
		}

		if (na->nd_na_type != ND_NEIGHBOR_ADVERT)
			continue;

		for (mp = CMSG_FIRSTHDR(&msg); mp; mp = CMSG_NXTHDR(&msg, mp)) {
			if (mp->cmsg_level == SOL_IPV6 &&
			    mp->cmsg_type == IPV6_HOPLIMIT
			    /* don't check len - we trust the kernel: */
			    /* && mp->cmsg_len >= CMSG_LEN(sizeof(int)) */
			) {
				/*hoplimit = *(int*)CMSG_DATA(mp); - unaligned access */
				memcpy(&hoplimit, CMSG_DATA(mp), sizeof(hoplimit));
			}
		}

		for (i = 0; i < len; i++) {
			if (!memcmp(&na->nd_na_target, &addr[i], sizeof(addr[0])))
				return i;
		}
	}

	return -1;
}
