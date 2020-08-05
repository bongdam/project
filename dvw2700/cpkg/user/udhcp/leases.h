/* leases.h */
#ifndef _LEASES_H
#define _LEASES_H

#include "linux_list.h"

struct dhcpOfferedAddr {
	u_int8_t chaddr[16];
	u_int32_t yiaddr;	/* network order */
	u_int32_t expires;	/* host order */
	char hostname[64];
	int VoIP_Device;	/* wifi phone check */
};

void clear_lease(u_int8_t *chaddr, u_int32_t yiaddr);
struct dhcpOfferedAddr *add_lease(u_int8_t *chaddr, u_int32_t yiaddr, unsigned long lease);
int lease_expired(struct dhcpOfferedAddr *lease);
struct dhcpOfferedAddr *oldest_expired_lease(void);
struct dhcpOfferedAddr *find_lease_by_chaddr(u_int8_t *chaddr);
struct dhcpOfferedAddr *find_lease_by_yiaddr(u_int32_t yiaddr);
u_int32_t find_address(const u_int8_t *safe_mac);
int check_ip(u_int32_t addr, const u_int8_t *excluded_chaddr);

struct static_lease {
	struct list_head list;
	unsigned int ipaddr;
	unsigned char chaddr[ETH_ALEN];
};

struct static_lease * find_static_by_chaddr(u_int8_t *chaddr);
struct static_lease * find_static_by_yiaddr(u_int32_t yiaddr);

#endif
