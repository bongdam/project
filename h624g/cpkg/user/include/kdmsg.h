#ifndef __kdmsg_h_
#define __kdmsg_h_

#include <linux/net.h>

extern unsigned int debug_msg_mask;

#define kdmsg(p, arg...) \
	do {\
		if (debug_msg_mask & (p))\
			printk(arg);\
	} while (0)

#define kdmsg_quiet(p, arg...) \
	do {\
		if ((debug_msg_mask & (p)) && net_ratelimit())\
			printk(arg);\
	} while (0)

enum {
	KDMSG_NET_DRV = 0x0001,
	KDMSG_NET_NETFILTER = 0x0002,
	KDMSG_NET_IF = 0x0004,
	KDMSG_HW_NAPT = 0x0008,
};

#endif	/* __kdmsg_h_ */
