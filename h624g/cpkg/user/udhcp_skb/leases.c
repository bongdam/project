/*
 * leases.c -- tools to manage DHCP leases
 * Russ Dill <Russ.Dill@asu.edu> July 2001
 */

#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "debug.h"
#include "dhcpd.h"
#include "files.h"
#include "options.h"
#include "leases.h"
#include "arpping.h"

#ifdef COMBINED_BINARY
unsigned long random_xid(void);
#define RAND		random_xid
#else
#define RAND()		0
#endif

/* clear every lease out that chaddr OR yiaddr matches and is nonzero */
void clear_lease(u_int8_t * chaddr, u_int32_t yiaddr)
{
	unsigned int i, j;

	for (j = 0; j < 16 && !chaddr[j]; j++) ;

	for (i = 0; i < server_config.max_leases; i++)
		if ((j != 16 && !memcmp(leases[i].chaddr, chaddr, 16)) ||
		    (yiaddr && leases[i].yiaddr == yiaddr)) {
			memset(&(leases[i]), 0, sizeof(struct dhcpOfferedAddr));
		}
}

/* add a lease into the table, clearing out any old ones */
struct dhcpOfferedAddr *add_lease(u_int8_t * chaddr, u_int32_t yiaddr,
				  unsigned long lease)
{
	struct dhcpOfferedAddr *oldest;

	/* clean out any old ones */
	clear_lease(chaddr, yiaddr);

	oldest = oldest_expired_lease();

	if (oldest) {
		memcpy(oldest->chaddr, chaddr, 16);
		oldest->yiaddr = yiaddr;
		oldest->expires = monotonic_sec() + lease;
	}

	return oldest;
}

/* true if a lease has expired */
int lease_expired(struct dhcpOfferedAddr *lease)
{
	return (((long)monotonic_sec() - (long)lease->expires) > 0);
}

/* Find the oldest expired lease, NULL if there are no expired leases */
struct dhcpOfferedAddr *oldest_expired_lease(void)
{
	struct dhcpOfferedAddr *oldest = NULL;
	unsigned long oldest_lease = monotonic_sec();
	unsigned int i;

	for (i = 0; i < server_config.max_leases; i++)
		if (oldest_lease > leases[i].expires) {
			oldest_lease = leases[i].expires;
			oldest = &(leases[i]);
		}

	return oldest;
}

/* Find the first lease that matches chaddr, NULL if no match */
struct dhcpOfferedAddr *find_lease_by_chaddr(u_int8_t * chaddr)
{
	unsigned int i;

	for (i = 0; i < server_config.max_leases; i++)
		if (!memcmp(leases[i].chaddr, chaddr, 16))
			return &(leases[i]);

	return NULL;
}

/* Find the first lease that matches yiaddr, NULL is no match */
struct dhcpOfferedAddr *find_lease_by_yiaddr(u_int32_t yiaddr)
{
	unsigned int i;

	if (yiaddr == INADDR_ANY || yiaddr == INADDR_NONE)
		return NULL;

	for (i = 0; i < server_config.max_leases; i++)
		if (leases[i].yiaddr == yiaddr)
			return &(leases[i]);

	return NULL;
}

u_int32_t find_address(const u_int8_t *safe_mac)
{
	u_int32_t addr, nip;
	struct dhcpOfferedAddr *oldest_lease = NULL;
	u_int32_t stop;
	unsigned i, hash;

	/* hash hwaddr: use the SDBM hashing algorithm.  Seems to give good
	 * dispersal even with similarly-valued "strings".
	 */
	hash = RAND();
	for (i = 0; i < 6; i++)
		hash += safe_mac[i] + (hash << 6) + (hash << 16) - hash;

	/* pick a seed based on hwaddr then iterate until we find a free address. */
	addr = ntohl(server_config.start)
		+ (hash % (1 + ntohl(server_config.end) - ntohl(server_config.start)));
	stop = addr;

	do {
		struct dhcpOfferedAddr *lease;

		/* ie, 192.168.55.0 */
		if ((addr & 0xff) == 0)
			goto next_addr;
		/* ie, 192.168.55.255 */
		if ((addr & 0xff) == 0xff)
			goto next_addr;

		nip = htonl(addr);
		if (nip == server_config.server || find_static_by_yiaddr(nip))
			goto next_addr;

		lease = find_lease_by_yiaddr(nip);
		if (!lease) {
			if (!check_ip(nip, safe_mac))
				return nip;
		} else {
			if (!oldest_lease || lease->expires < oldest_lease->expires)
				oldest_lease = lease;
		}
 next_addr:
		addr++;
		if (addr > ntohl(server_config.end))
			addr = ntohl(server_config.start);
	} while (addr != stop);

	if (oldest_lease && lease_expired(oldest_lease) &&
	    !check_ip(oldest_lease->yiaddr, safe_mac))
		return oldest_lease->yiaddr;

	return 0;
}

/* find static ip address from static lease table */
struct static_lease *find_static_by_chaddr(u_int8_t * chaddr)
{
	struct static_lease *slease;
	struct list_head *pos;

	if (sdmz_host_match(chaddr, ETH_ALEN))
		return 0;

	list_for_each(pos, &server_config.static_leases) {
		slease = list_entry(pos, struct static_lease, list);
		if (!memcmp(slease->chaddr, chaddr, ETH_ALEN))
			return slease;
	}

	return NULL;
}

struct static_lease *find_static_by_yiaddr(u_int32_t yiaddr)
{
	struct static_lease *slease;
	struct list_head *pos;

	list_for_each(pos, &server_config.static_leases) {
		slease = list_entry(pos, struct static_lease, list);
		if (slease->ipaddr == yiaddr)
			return slease;
	}

	return NULL;
}

/* check whether an IP is taken. if it is, add it to the lease table */
int check_ip(u_int32_t addr, const u_int8_t *excluded_chaddr)
{
	u_int8_t M[16];

	memset(M, 0, sizeof(M));
	if (arpping(addr, M, server_config.server,
	            server_config.arp, server_config.interface) == 0) {

		if (excluded_chaddr && !memcmp(excluded_chaddr, M, 6))
			return 0;

		LOG(LOG_DEBUG, "DHCPD IP " NQF " " L_USEDIP, NIPQUAD(addr));
		add_lease(M, addr, server_config.conflict_time);
		return 1;
	} else
		return 0;
}
