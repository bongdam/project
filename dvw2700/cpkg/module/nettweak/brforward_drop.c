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
#include <os_util.h>

extern struct list_head pf_netif_receive_skb;

static int flags;
static unsigned long brforward_drop_packet;

static int brforward_drop(struct pf_hook_ops *h, struct sk_buff *skb, void *unused)
{
	if (eth_hdr(skb)->h_proto == ETH_P_IP &&
	    skb->dev->priv_flags & (IFF_EBRIDGE|IFF_BRIDGE_PORT)) {
	    	kfree_skb(skb);
	    	brforward_drop_packet++;
		return PF_CONSUME;
	}
	return PF_ACCEPT;
}

static struct pf_hook_ops brforward_drop_pf_ops = {
	.list = LIST_HEAD_INIT(brforward_drop_pf_ops.list),
	.hook = brforward_drop,
	.priority = PFH_PRI_HIGH + 1,
};

static void install_brforward_drop(int install)
{
	if (install) {
		if (list_empty(&brforward_drop_pf_ops.list))
			pf_register_hook(&pf_netif_receive_skb, &brforward_drop_pf_ops);
	} else if (!list_empty(&brforward_drop_pf_ops.list))
		pf_unregister_hook(&brforward_drop_pf_ops);
}

static int proc_do_brforward_drop_vect(struct ctl_table *table, int write,
		     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (ret == 0 && write)
		install_brforward_drop(flags);
	return ret;
}

static ctl_table brforward_drop_tbl[] = {
        { .procname     = "brforward_drop",
          .data         = &flags,
          .maxlen       = sizeof(flags),
          .mode         = 0644,
          .proc_handler = proc_do_brforward_drop_vect },
        { .procname     = "brforward_drop_packet",
          .data         = &brforward_drop_packet,
          .maxlen       = sizeof(brforward_drop_packet),
          .mode         = 0444,
          .proc_handler = proc_dointvec },
        { }
};

static ctl_table brforward_drop_root_tbl[] = {
        { .procname     = "private",
          .mode         = 0555,
          .child        = brforward_drop_tbl },
        { }
};

static struct ctl_table_header *brforward_drop_tbl_header;

static int __init brforward_drop_init(void)
{
	brforward_drop_tbl_header = register_sysctl_table(brforward_drop_root_tbl);
	return 0;
}

static void __exit brforward_drop_fini(void)
{
	if (brforward_drop_tbl_header)
		unregister_sysctl_table(brforward_drop_tbl_header);
	if (!list_empty(&brforward_drop_pf_ops.list))
		pf_unregister_hook(&brforward_drop_pf_ops);
}

module_init(brforward_drop_init);
module_exit(brforward_drop_fini);
