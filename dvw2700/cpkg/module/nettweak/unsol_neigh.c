#include <linux/module.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/gfp.h>
#include <net/xfrm.h>
#include <linux/jhash.h>
#include <linux/rtnetlink.h>
#include <net/arp.h>
#include <linux/etherdevice.h>

#include <net/rtl/rtl_types.h>
#include <net/rtl/rtl_glue.h>
#include <net/rtl/rtl_queue.h>
#include <net/rtl/rtl865x_netif.h>
#include <net/rtl/rtl865x_fdb_api.h>
#include "common/rtl_utils.h"
#include "AsicDriver/rtl865x_asicBasic.h"
#include "AsicDriver/rtl865x_asicCom.h"
#include "AsicDriver/rtl865x_asicL2.h"
#include "AsicDriver/rtl865xc_asicregs.h"
#include "AsicDriver/rtl865xC_hs.h"
#include "l2Driver/rtl865x_fdb.h"
#include <os_util.h>

extern struct list_head pf_netif_receive_skb;
extern int neigh_ipv4_add(struct net_device *dev, __be32 addr, __u8 *lladdr,
		   __u16 state, __u32 request);
extern int is_ifa_subnet(__be32 address, int ifindex);

static int flags;

static inline int __neigh_unsolicited_add(struct net_device *dev, __be32 address,
				   u8 *lladdr, int port)
{
	struct neighbour *n = __ipv4_neigh_lookup(dev, address);
	int ret = -1;

	if (n == NULL) {
		_rtl865x_addFilterDatabaseEntry(RTL865x_L2_TYPEI,
			!strcmp(dev->name, "eth1") ? RTL_WAN_FID : RTL_LAN_FID,
			(ether_addr_t *)lladdr,
			FDB_TYPE_FWD,
			1 << port,
			false, false);

		ret = neigh_ipv4_add(dev, address, lladdr,
			NUD_REACHABLE, NLM_F_CREATE|NLM_F_EXCL);

		pr_debug("adding neighbour %pI4 %pM(%d) on %s\n",
			 &address, lladdr, port, dev->name);
	}

	return ret;
}

static int neigh_unsolicited_add(struct pf_hook_ops *h, struct sk_buff *skb, void *unused)
{
	struct ethhdr *eh = eth_hdr(skb);
	struct iphdr *ih;

	if (eh->h_proto == ETH_P_IP &&
	    !compare_ether_addr(eh->h_dest, skb->dev->dev_addr) &&
	    ({ ih = (struct iphdr *)&eh[1]; 1;}) &&
	    ih->protocol == IPPROTO_UDP &&
	    is_ifa_subnet(ih->saddr, skb->dev->ifindex))
		__neigh_unsolicited_add(skb->dev, ih->saddr, eh->h_source, skb->srcPhyPort);
	return PF_ACCEPT;
}

static struct pf_hook_ops nua_pf_ops = {
	.list = LIST_HEAD_INIT(nua_pf_ops.list),
	.hook = neigh_unsolicited_add,
	.priority = PFH_PRI_HIGH,
};

static int proc_donuavect(struct ctl_table *table, int write,
		     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (ret == 0 && write) {
		if (flags) {
			if (list_empty(&nua_pf_ops.list))
				pf_register_hook(&pf_netif_receive_skb, &nua_pf_ops);
		} else {
			if (!list_empty(&nua_pf_ops.list))
				pf_unregister_hook(&nua_pf_ops);
		}
	}
	return ret;
}

static ctl_table nua_table[] = {
        { .procname     = "neigh_unsolicited_add",
          .data         = &flags,
          .maxlen       = sizeof(flags),
          .mode         = 0644,
          .proc_handler = proc_donuavect },
        { }
};

static ctl_table nua_root_table[] = {
        { .procname     = "private",
          .mode         = 0555,
          .child        = nua_table },
        { }
};

static struct ctl_table_header *nua_table_header;

static int __init nua_init(void)
{
	nua_table_header = register_sysctl_table(nua_root_table);
	return 0;
}

static void __exit nua_fini(void)
{
	if (nua_table_header)
		unregister_sysctl_table(nua_table_header);
	if (!list_empty(&nua_pf_ops.list))
		pf_unregister_hook(&nua_pf_ops);
}

module_init(nua_init);
module_exit(nua_fini);
