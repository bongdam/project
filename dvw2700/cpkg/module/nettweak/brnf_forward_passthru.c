#include <linux/module.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/gfp.h>
#include <net/xfrm.h>
#include <linux/jhash.h>
#include <linux/rtnetlink.h>
#include <net/arp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_pppox.h>
#include <linux/ppp_defs.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_arp.h>
#include <linux/in_route.h>
#include <linux/inetdevice.h>
#include <net/ip.h>
#include <net/ipv6.h>

extern bool in6_mcast_reserved(const struct in6_addr *daddr);

#ifdef CONFIG_SYSCTL

static int flags;

static inline __be16 pppoe_proto(const struct sk_buff *skb)
{
	return *((__be16 *)(skb_mac_header(skb) + ETH_HLEN +
			    sizeof(struct pppoe_hdr)));
}

static struct ipv6hdr *ip6_hdr(struct sk_buff *skb)
{
	struct ipv6hdr *hdr;

	switch (skb->protocol) {
	case __constant_htons(ETH_P_IPV6):
		hdr = (struct ipv6hdr *)(skb_mac_header(skb) + ETH_HLEN);
		break;
	case __constant_htons(ETH_P_8021Q):
		if (vlan_eth_hdr(skb)->h_vlan_encapsulated_proto != htons(ETH_P_IPV6))
			return NULL;
		hdr = (struct ipv6hdr *)(skb_mac_header(skb) + VLAN_ETH_HLEN);
		break;
	case __constant_htons(ETH_P_PPP_SES):
		if (pppoe_proto(skb) != htons(PPP_IPV6))
			return NULL;
		hdr = (struct ipv6hdr *)(skb_mac_header(skb) + ETH_HLEN + PPPOE_SES_HLEN);
		break;
	default:
		return NULL;
	}

	return (hdr->version == 6) ? hdr : NULL;
}

static unsigned int
br_nf_forward_passthru_hook(unsigned int hook, struct sk_buff *skb,
			    const struct net_device *in,
			    const struct net_device *out,
			    int (*okfn)(struct sk_buff *))
{
	struct ipv6hdr *hdr;

	if (!(out->priv_flags & IFF_IPV6_PASSTHRU))
		return NF_ACCEPT;

	if (!(in->priv_flags & IFF_802_11_LAN))
		return NF_DROP;

	hdr = ip6_hdr(skb);
	if (hdr == NULL || in6_mcast_reserved(&hdr->daddr))
		return NF_DROP;

	return NF_ACCEPT;
}

static struct nf_hook_ops br_nf_passthru_ops __read_mostly = {
	.hook = br_nf_forward_passthru_hook,
	.owner = THIS_MODULE,
	.pf = NFPROTO_BRIDGE,
	.hooknum = NF_BR_FORWARD,
	.priority = NF_BR_PRI_BRNF - 2,
};

static void install_brnf_forward_passthru(int install)
{
	if (install) {
		if (list_empty(&br_nf_passthru_ops.list) &&
		    nf_register_hooks(&br_nf_passthru_ops, 1))
			INIT_LIST_HEAD(&br_nf_passthru_ops.list);
	} else if (!list_empty(&br_nf_passthru_ops.list)) {
		nf_unregister_hooks(&br_nf_passthru_ops, 1);
		INIT_LIST_HEAD(&br_nf_passthru_ops.list);
	}
}

static int proc_do_brnf_forward_passthru_vect(struct ctl_table *table, int write,
		     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (ret == 0 && write)
		install_brnf_forward_passthru(flags);
	return ret;
}

static ctl_table brnf_forward_passthru_tbl[] = {
	{
		.procname     = "brnf_forward_passthru",
		.data         = &flags,
		.maxlen       = sizeof(flags),
		.mode         = 0644,
		.proc_handler = proc_do_brnf_forward_passthru_vect
	},
	{
	},
};

static ctl_table brnf_forward_passthru_root_tbl[] = {
	{
		.procname     = "private",
		.mode         = 0555,
		.child        = brnf_forward_passthru_tbl
	},
	{
	},
};

static struct ctl_table_header *brnf_fwd_tbl_header;

static int __init brnf_forward_passthru_init(void)
{
	brnf_fwd_tbl_header = register_sysctl_table(brnf_forward_passthru_root_tbl);
	INIT_LIST_HEAD(&br_nf_passthru_ops.list);
	return 0;
}

static void __exit brnf_forward_passthru_fini(void)
{
	unregister_sysctl_table(brnf_fwd_tbl_header);
	install_brnf_forward_passthru(false);
}

module_init(brnf_forward_passthru_init);
module_exit(brnf_forward_passthru_fini);
#endif
