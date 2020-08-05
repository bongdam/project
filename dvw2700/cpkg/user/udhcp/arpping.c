/*
 * arpping.c
 *
 * Mostly stolen from: dhcpcd - DHCP client daemon
 * by Yoichi Hariguchi <yoichi@fore.com>
 */

#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include "dhcpd.h"
#include "debug.h"
#include "arpping.h"

#define PROBETMOUT	460

/* args:	yiaddr - what IP to ping
 *		ip - our ip
 *		mac - our arp address
 *		interface - interface to use
 *		thwa - peer arp address included in ARP resp
 * retn: 	1 addr free
 *		0 addr used
 *		-1 error
 */

int
arpping(u_int32_t yiaddr, u_char *thwa, u_int32_t ip, u_char *mac, char *interface)
{
	struct pollfd pfd;
	long timeout, expiry;
	int res, optval, s, rv = 1;
	struct sockaddr addr;	/* for interface name */
	struct arpMsg arp;

	if (!yiaddr || yiaddr == (u_int32_t)-1)
		return -1;

	if ((s = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ARP))) < 0) {
		LOG(LOG_ERR, "Could not open raw socket");
		return -1;
	}

	optval = 1;
	if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval))) {
		LOG(LOG_ERR, "Could not setsocketopt on raw socket");
		close(s);
		return -1;
	}

	/* send arp request */
	memset(&arp, 0, sizeof(arp));
	memcpy(arp.ethhdr.h_dest, MAC_BCAST_ADDR, 6);	/* MAC DA */
	memcpy(arp.ethhdr.h_source, mac, 6);	/* MAC SA */
	arp.ethhdr.h_proto = htons(ETH_P_ARP);	/* protocol type (Ethernet) */
	arp.htype = htons(ARPHRD_ETHER);	/* hardware type */
	arp.ptype = htons(ETH_P_IP);	/* protocol type (ARP message) */
	arp.hlen = 6;		/* hardware address length */
	arp.plen = 4;		/* protocol address length */
	arp.operation = htons(ARPOP_REQUEST);	/* ARP op code */
	*((u_int *)arp.sInaddr) = ip;	/* source IP address */
	memcpy(arp.sHaddr, mac, 6);	/* source hardware address */
	*((u_int *)arp.tInaddr) = yiaddr;	/* target IP address */

	memset(&addr, 0, sizeof(addr));
	strcpy(addr.sa_data, interface);

	if (sendto(s, &arp, sizeof(arp), 0, &addr, sizeof(addr)) < 0)
		rv = 0;

	/* wait arp reply, and check it */
	pfd.fd = s;
	pfd.events = POLLIN;
	pfd.revents = 0;
	timeout = PROBETMOUT;
	expiry = (long)monotonic_ms() + timeout;

	while (timeout > 0) {
		res = poll(&pfd, 1, timeout);
		if (res < 0) {
			if (errno != EINTR)
				rv = 0;
		} else if (res > 0 && pfd.revents) {
			if (recv(s, &arp, sizeof(arp), 0) < 0)
				rv = 0;
			else if (arp.operation == htons(ARPOP_REPLY) &&
				 bcmp(arp.tHaddr, mac, 6) == 0 &&
				 *((u_int *)arp.sInaddr) == yiaddr) {
				DEBUG(LOG_INFO, "Valid arp reply receved for this address");
				rv = 0;
				if (thwa)
					memcpy(thwa, arp.sHaddr, ETH_ALEN);
				break;
			}
		}
		timeout = expiry - (long)monotonic_ms();
	}

	close(s);
	DEBUG(LOG_INFO, "%salid arp replies for this address", rv ? "No v" : "V");
	return rv;
}

int arplookup(u_int32_t tina, u_char thwa[ETH_ALEN], char *ifname)
{
	int s, retval = -1;
	struct arpreq ar;
	struct sockaddr_in *sin;

	if (ifname == 0 || *ifname == 0)
		return -1;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;

	bzero(&ar, sizeof(ar));
	sin = (struct sockaddr_in *)&ar.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = tina;
	strcpy(ar.arp_dev, ifname);

	if (ioctl(s, SIOCGARP, (caddr_t)&ar) == 0) {
		if (ar.arp_flags & ATF_COM) {
			bcopy(ar.arp_ha.sa_data, thwa, ETH_ALEN);
			retval = 0;
		}
	}
	close(s);
	return retval;
}
