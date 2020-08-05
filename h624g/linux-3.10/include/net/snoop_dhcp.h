#ifndef __SNOOP_DHCP_H
#define __SNOOP_DHCP_H

#define SNOOP_UPLINK_PORT	4	/* WAN */
#define SNOOP_DROP_ALWAYS	5
#define SNOOP_DROP_ETH		6
#define SNOOP_DROP_WLAN		7
#define SNOOP_DROP_MASK		0xe0	/* 1<<SNOOP_DROP_ALWAYS | 1<<SNOOP_DROP_ETH | 1<<SNOOP_DROP_WLAN */
#define SNOOP_MASK_ETH		0x1f	/* physical port */

#define SNOOP_MARK_MASK		0xff
#define SNOOP_MARK_SHIFT	20

#define SNOOP_MARK_CLR(m)	do { \
					(m) &= ~(SNOOP_MARK_MASK << SNOOP_MARK_SHIFT); \
				} while (0)

#define SNOOP_MARK_SET(m, p)	(m) |= (1 << (SNOOP_MARK_SHIFT + (p)))

#define SNOOP_MARK_GET(m)	(((m) >> SNOOP_MARK_SHIFT) & SNOOP_MARK_MASK)

#define SNOOP_MARK_ISSET(m, p)	((m) & (1 << (SNOOP_MARK_SHIFT + (p))))

#define pntohl(p)  ((((unsigned int)(p)[0] & 0xff) << 24) | \
                    (((unsigned int)(p)[1] & 0xff) << 16) | \
                    (((unsigned int)(p)[2] & 0xff) <<  8) | \
                    (((unsigned int)(p)[3] & 0xff)      ))

#define pntohs(p)  ((((unsigned short)(p)[0] & 0xff) <<  8) | \
                    (((unsigned short)(p)[1] & 0xff)      ))

#ifdef __KERNEL__
#include <linux/etherdevice.h>
#define DHCPRES_PORT32	0x00430044
#define DHCPREQ_PORT32	0x00440043

extern int snoop_dhcp;

static inline int test_dhcp_packet(unsigned char *p)
{
	u32 port, udp_off;
	return ((pntohs(&p[12]) == ETH_P_IP) &&
	        (p[23] == IPPROTO_UDP) &&
	        ({udp_off = ((p[14] & 0xf) << 2) + 14;
	          port = pntohl(&p[udp_off]); 1;}) &&
	        (port == DHCPRES_PORT32 || port == DHCPREQ_PORT32));
}

static inline int snoop_dhcp_packet(struct sk_buff *skb)
{
	struct net_device *dev;
	u8 *p = skb->data;
	if (test_dhcp_packet(p)) {
		if (is_broadcast_ether_addr(p) &&
		    (dev = dev_get_by_name(&init_net, "br0"))) {
			memcpy(p, dev->dev_addr, ETH_ALEN);
			dev_put(dev);
		}
	    	SNOOP_MARK_CLR(skb->mark);
	    	SNOOP_MARK_SET(skb->mark, SNOOP_DROP_ALWAYS);
		return 0;
	}
	return -1;
}
#endif	/* __KERNEL__ */
#endif	/* __SNOOP_DHCP_H */
