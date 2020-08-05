#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/sysctl.h>
#include <linux/if.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_l3proto.h>
#include <net/netfilter/nf_nat_l4proto.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_helper.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <linux/netfilter/nf_nat.h>

#include <os_util.h>

extern int is_ifa_local(__be32 address);

struct in_addr twin_inaddr;
uint8_t twin_haddr[ETH_ALEN];
char up_ifname[IFNAMSIZ];
static uint8_t twin_haddr_buffer[32];

void nf_nat_preprocess_twin_ip(struct nf_conn *ct, unsigned int hooknum,
			      struct sk_buff *skb)
{
	struct iphdr *iph;

	if (twin_inaddr.s_addr && !test_bit(IPS_SDMZCONN_BIT, &ct->status)) {
		iph = ip_hdr(skb);
		if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
			return;

		switch (hooknum) {
		case NF_INET_PRE_ROUTING:
			if (iph->saddr == twin_inaddr.s_addr &&
	    	      	    !compare_ether_addr(eth_hdr(skb)->h_source, twin_haddr) &&
	    	      	    ((iph->protocol != IPPROTO_UDP) || !IN_MULTICAST(ntohl(iph->daddr))))
				set_bit(IPS_SDMZCONN_BIT, &ct->status);
			break;
		case NF_INET_POST_ROUTING:
			/* hist1. safe to confirm that eth1 had been de-configured */
			/* hist2. @note:20140328, fixed error.
				In sdmz, add condition that, "!is_ifa_local(iph->saddr)":
				receive ssdp from sdmz's host and
				when sending response(200ok) it, occur to reset system.
			*/
			if (iph->daddr == twin_inaddr.s_addr && !is_ifa_local(iph->saddr))
				set_bit(IPS_SDMZCONN_BIT, &ct->status);
		default:
			break;
		}
	}
}
EXPORT_SYMBOL(nf_nat_preprocess_twin_ip);

static int twin_haddr_proc_dostring(struct ctl_table *table, int write,
			void __user *buffer, size_t *lenp, loff_t *ppos)
{
	char buf[64];
	uint8_t haddr[ETH_ALEN];
	size_t size = *lenp;
	int r = 0;

	if (write) {
		if (size > (sizeof(buf) - 1))
			size = sizeof(buf) - 1;
		if (copy_from_user(buf, buffer, size))
			return -EFAULT;
		buf[size] = '\0';
		r = h_atoe(buf, haddr);
		if (!r)
			memcpy(twin_haddr, haddr, ETH_ALEN);
	} else {
		sprintf(twin_haddr_buffer,
		        "%02x:%02x:%02x:%02x:%02x:%02x",
		        twin_haddr[0], twin_haddr[1], twin_haddr[2],
		        twin_haddr[3], twin_haddr[4], twin_haddr[5]);
		table->data = twin_haddr_buffer;
		r = proc_dostring(table, write, buffer, lenp, ppos);
	}

	return r;
}

static ctl_table twin_ip_proc_tbl[] = {
	{
	.procname	= "twin_inaddr",
	.data		= &twin_inaddr.s_addr,
	.maxlen		= sizeof(int),
	.mode		= 0644,
	.proc_handler	= proc_dointvec,
	},
	{
	.procname	= "twin_hwaddr",
	.data		= NULL,
	.maxlen		= sizeof(twin_haddr_buffer),
	.mode		= 0644,
	.proc_handler	= twin_haddr_proc_dostring,
	},
	{
	.procname	= "up_ifname",
	.data		= up_ifname,
	.maxlen		= IFNAMSIZ,
	.mode		= 0644,
	.proc_handler	= &proc_dostring,
	},
        {}
};

static ctl_table twin_ip_parent_proc_tbl[] = {
        { .procname     = "private",
          .mode         = 0555,
          .child        = twin_ip_proc_tbl },
        {}
};

static struct ctl_table_header *twin_ip_proc_header;

static int __init twin_init(void)
{
	twin_ip_proc_header = register_sysctl_table(twin_ip_parent_proc_tbl);
	return 0;
}

static void __exit twin_fini(void)
{
	if (twin_ip_proc_header)
		unregister_sysctl_table(twin_ip_proc_header);
}

module_init(twin_init);
module_exit(twin_fini);
