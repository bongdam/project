#include <linux/module.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/gfp.h>
#include <net/xfrm.h>
#include <linux/jhash.h>
#include <linux/in.h>
#include <linux/inetdevice.h>
#include <os_util.h>

#ifdef CONFIG_NF_NAT_TWINIP
extern struct in_addr twin_inaddr;
extern char up_ifname[];
#endif

static LIST_HEAD(in_addr_locals);
static char ifa_stringbuffer[192];

struct if_addr_entry {
	struct in_addr_entry addr;	/* MUST be first field */
	struct in_addr mask;
	int ifindex;
};

static int ifa_cmpr(struct if_addr_entry *ifa, struct if_addr_entry *ifb)
{
	return (ifa->ifindex == ifb->ifindex &&
		ifa->addr.addr.s_addr == ifb->addr.addr.s_addr)
		? 0 : -1;
}

static int ifa_cmpr2(struct if_addr_entry *ifa, __be32 dst)
{
	return (ifa->addr.addr.s_addr == dst) ? 0 : -1;
}

static void add_ifa_local(__be32 address, __be32 mask, int ifindex)
{
	struct if_addr_entry *ifa;
	struct if_addr_entry ifb = {
		.addr = { .addr = { .s_addr = address, }},
		.ifindex = ifindex };

	if (ipv4_is_loopback(address) || address == INADDR_ANY || address == INADDR_NONE)
		return;

	ifa = (struct if_addr_entry *)ip_addr_entry_get(&in_addr_locals,
						(void *)ifa_cmpr, (void *)&ifb);
	if (ifa == NULL) {
		ifa = kmalloc(sizeof(*ifa), GFP_ATOMIC);
		ifa->addr.addr.s_addr = address;
		ifa->mask.s_addr = mask;
		ifa->ifindex = ifindex;
		in_addr_entry_add(&ifa->addr, &in_addr_locals);
	} else
		ip_addr_entry_put(&ifa->addr);
}

static void del_ifa_local(__be32 address, int ifindex)
{
	struct if_addr_entry *ifa;
	struct if_addr_entry ifb = {
		.addr = { .addr = { .s_addr = address, }},
		.ifindex = ifindex };

	ifa = (struct if_addr_entry *)ip_addr_entry_get(&in_addr_locals,
						(void *)ifa_cmpr, (void *)&ifb);
	if (ifa && ip_addr_entry_put(&ifa->addr))
		ip_addr_entry_put(&ifa->addr);
}

int is_ifa_local(__be32 address)
{
	struct if_addr_entry *ifa;
	ifa = (struct if_addr_entry *)ip_addr_entry_get(&in_addr_locals,
					(void *)ifa_cmpr2, (void *)address);
	if (ifa != NULL)
		ip_addr_entry_put(&ifa->addr);
	return (ifa != NULL) ? : 0;
}
EXPORT_SYMBOL(is_ifa_local);

#ifdef CONFIG_NEIGH_UNSOLICITED_ADD
static int ifa_cmpr3(struct if_addr_entry *ifa, struct if_addr_entry *ifb)
{
	return (ifa->ifindex == ifb->ifindex &&
		ifa->addr.addr.s_addr != ifb->addr.addr.s_addr &&
		((ifb->addr.addr.s_addr & ifa->mask.s_addr) ==
		 (ifa->addr.addr.s_addr & ifa->mask.s_addr)))
		? 0 : -1;
}

int is_ifa_subnet(__be32 address, int ifindex)
{
	struct if_addr_entry *ifa;
	struct if_addr_entry ifb = {
		.addr = { .addr = { .s_addr = address }},
		.mask = { .s_addr = address },
		.ifindex = ifindex };

	ifa = (struct if_addr_entry *)ip_addr_entry_get(&in_addr_locals,
					(void *)ifa_cmpr3, (void *)&ifb);
	if (ifa != NULL)
		ip_addr_entry_put(&ifa->addr);
	return (ifa != NULL) ? : 0;
}
EXPORT_SYMBOL(is_ifa_subnet);
#endif

static int ifa_sconcat(struct in_addr_entry *addr, struct seq_file *m)
{
	return seq_printf(m, "%pI4 ", &addr->addr);
}

static int ifa_proc_handler(struct ctl_table *table, int write,
		 void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct seq_file m;
	int r = 0;

	if (!write) {
		memset(&m, 0, sizeof(m));
		m.buf = ifa_stringbuffer;
		m.size = sizeof(ifa_stringbuffer);
		ip_addr_entry_iterate(&in_addr_locals, (void *)ifa_sconcat, (void *)&m);
		if (m.count > 0)
			--m.count;
		ifa_stringbuffer[m.count] = '\0';
		table->data = ifa_stringbuffer;
		r = proc_dostring(table, write, buffer, lenp, ppos);
	}

	return r;
}

static int in_ipv4_addr_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct net_device *dev = ifa->ifa_dev->dev;

        switch (event) {
	case NETDEV_REGISTER:
	case NETDEV_UNREGISTER:
		break;
	case NETDEV_UP:
#ifdef CONFIG_NF_NAT_TWINIP
		if (twin_inaddr.s_addr && !strcmp(dev->name, up_ifname))
			twin_inaddr.s_addr = INADDR_ANY;
#endif
	/* fall thru */
	case NETDEV_DOWN:
		for (; ifa; ifa = ifa->ifa_next) {
			if (event == NETDEV_UP)
				add_ifa_local(ifa->ifa_address, ifa->ifa_mask, dev->ifindex);
			else
				del_ifa_local(ifa->ifa_address, dev->ifindex);
		}
		break;
	case NETDEV_CHANGENAME:
	case NETDEV_CHANGEADDR:
        default:
                break;
        };

        return NOTIFY_DONE;
}

static struct notifier_block in_ipv4_addr_notifier = {
        .notifier_call = in_ipv4_addr_event,
};

static struct ctl_table in_local_childs[] = {
	{
	.procname	= "ifalist",
	.data		= NULL,
	.maxlen		= sizeof(ifa_stringbuffer),
	.mode		= 0444,
	.proc_handler	= ifa_proc_handler,
	},
	{}
};

static struct ctl_table in_local_root[] = {
	{
		.procname	= "private",
		.mode		= 0555,
		.child		= in_local_childs,
	},
	{}
};

static struct ctl_table_header *in_local_sysctls;

static int __init in_ipv4_addr_init(void)
{
	register_inetaddr_notifier(&in_ipv4_addr_notifier);
	in_local_sysctls = register_sysctl_table(in_local_root);
	return 0;
}

static void __exit in_ipv4_addr_exit(void)
{
	unregister_inetaddr_notifier(&in_ipv4_addr_notifier);
	if (in_local_sysctls)
		unregister_sysctl_table(in_local_sysctls);
}

module_init(in_ipv4_addr_init);
module_exit(in_ipv4_addr_exit);
