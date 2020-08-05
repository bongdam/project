#include <linux/module.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/gfp.h>
#include <net/xfrm.h>
#include <linux/jhash.h>
#include <linux/rtnetlink.h>

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

#ifdef CONFIG_NF_NAT_TWINIP
void nf_nat_preprocess_twin_ip(struct nf_conn *ct, unsigned int hooknum,
			      struct sk_buff *skb);
#endif

/* APNRTL-291
 * 1. DHCP server prober sent DISCOVER.
 * 2. If exists, dhcp server replied with OFFER.
 * 3. A fastpath and hardware NAT entry might be created.
 * 4. DHCP server prober sent DISCOVER by periods.
 * 5. DHCP server replied also but prober COULD not receive it from socket.
 * ------------------------
 * DECIDE NOT to enter into Realtek-hook when service is DNS and BOOTP.
 * 2012-08-29 young.
 */
static int nf_pass_port_init(void);
static void nf_pass_port_exit(void);

static DEFINE_SPINLOCK(u16_range_lock);
#define BITS_PER_INT 32
#define RANGE_HASHBITS 6
#define RANGE_EXTENT (1 << (16 - RANGE_HASHBITS))

struct ushort_range {
	unsigned int bval[(RANGE_EXTENT + (BITS_PER_INT - 1)) / BITS_PER_INT];
};

static inline
struct ushort_range *u16_range_get(struct ushort_range **base, u_int16_t port)
{
	return base[port >> ((16 - RANGE_HASHBITS))];
}

static int u16_range_match(struct ushort_range **base, unsigned short port)
{
	struct ushort_range *r = u16_range_get(base, port);
	if (r == NULL)
		return false;
	return (r->bval[(port & (RANGE_EXTENT - 1)) >> 5]
			& (1 << (port & ((1 << 5) - 1)))) ? true : false;
}

static int u16_range_add(struct ushort_range **base, unsigned short port)
{
	struct ushort_range *r;

	r = (struct ushort_range *)kmalloc(sizeof(*r), GFP_ATOMIC);
	if (r == NULL)
		return -1;
	memset(r->bval, 0, sizeof(r->bval));
    	r->bval[(port & (RANGE_EXTENT - 1)) >> 5] |= (1 << (port & ((1 << 5) - 1)));
    	smp_wmb();
	base[port >> ((16 - RANGE_HASHBITS))] = r;
	return 0;
}

static int u16_range_set(struct ushort_range **base, unsigned short port)
{
	struct ushort_range *r = u16_range_get(base, port);
	if (r == NULL)
		return u16_range_add(base, port);
    	r->bval[(port & (RANGE_EXTENT - 1)) >> 5] |= (1 << (port & ((1 << 5) - 1)));
	return 0;
}

static void u16_range_unset(struct ushort_range **base, unsigned short port)
{
	struct ushort_range *r = u16_range_get(base, port);
	int i;

	if (r == NULL)
		return;
	r->bval[(port & (RANGE_EXTENT - 1)) >> 5] &= ~(1 << (port & ((1 << 5) - 1)));
	for (i = 0; i < ARRAY_SIZE(r->bval) && !r->bval[i]; i++) {}
	if (i >= ARRAY_SIZE(r->bval)) {
		base[port >> ((16 - RANGE_HASHBITS))] = NULL;
		smp_wmb();
		kfree(r);
	}
}

static int port_range(struct ushort_range **base, char *s, int do_set)
{
	int min_dpt, max_dpt;
	char *args[4], *p;

	if (strargs(s, args, ARRAY_SIZE(args), "-") >= 1) {
		min_dpt = simple_strtol(args[0], &p, 10);
		if (min_dpt <= 0 || min_dpt > 65535 || *p)
			return -1;
		if (args[1] != NULL) {
			max_dpt = simple_strtol(args[1], &p, 10);
			if (min_dpt > max_dpt || max_dpt > 65535 || *p)
				return -1;
		} else
			max_dpt = min_dpt;
		spin_lock_bh(&u16_range_lock);
		if (do_set) {
			for (; min_dpt <= max_dpt; min_dpt++)
				u16_range_set(base, min_dpt);
		} else {
			for (; min_dpt <= max_dpt; min_dpt++)
				u16_range_unset(base, min_dpt);
		}
		spin_unlock_bh(&u16_range_lock);
		return 0;
	}

	return -1;
}

static ssize_t u16_range_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *data)
{
	enum { S_CMD, S_PROTO, S_PORT };
	struct ushort_range *(*base)[1 << RANGE_HASHBITS] =
		(struct ushort_range *(*)[1 << RANGE_HASHBITS])PDE_DATA(file_inode(file));
	char all[] = "1-65535";
	char *tmp, *q, *p;
	int comm = 0, status = S_CMD;
	u8 b = 0;

	tmp = (char *)kmalloc(count + 1, GFP_KERNEL);
	if (tmp && strtrim_from_user(tmp, count + 1, buffer, count) > 0) {
		for (p = tmp; (q = strsep(&p, " ,\r\n")); ) {
			despaces(q);
			if (!*q)
				continue;
			if (status == S_CMD) {
				if (!strcmp(q, "clear") ||
				    !strcmp(q, "add") ||
				    !strcmp(q, "del"))
					comm = *q;
				else
					break;
				status = S_PROTO;
			} else if (status == S_PROTO) {
				if (!strcmp(q, "tcp"))
					b = 1;
				else if (!strcmp(q, "udp"))
					b = 0;
				else
					break;
				if (comm == 'c') {
					for (b = 0; b < 2; b++) {
						strcpy(all, "1-65535");
						port_range(base[b], all, 0);
					}
					break;
				} else
					status = S_PORT;
			} else if (status == S_PORT)
				port_range(base[b], q, !!(comm == 'a'));
		}
	}

 	if (tmp)
 		kfree(tmp);
	return count;
}

static int u16_range_dump(struct ushort_range **base,
			  const char *proto, struct seq_file *m)
{
	enum { S_NONE, S_MARKED };
	int i, port, status = S_NONE;
	size_t count = m->count;

	seq_printf(m, "%s:\n", proto);
	for (i = 0; i < (1 << 16); i++) {
		if (status == S_NONE) {
			if (u16_range_match(base, i)) {
				port = i;
				status = S_MARKED;
			}
		} else {
			if (!u16_range_match(base, i)) {
				status = S_NONE;
				if ((i - port) > 2)
					seq_printf(m, " %d-%d", port, i - 1);
				else
					seq_printf(m, " %d", port);

				if ((m->count - count) > 80) {
					count = m->count;
					seq_putc(m, '\n');
				}
			}
		}
	}

	if (status == S_MARKED) {
		if ((i - port) > 2)
			seq_printf(m, " %d-%d", port, i - 1);
		else
			seq_printf(m, " %d", port);
	}

	seq_putc(m, '\n');
	return 0;
}


static int u16_range_show(struct seq_file *m, void *v)
{
	struct ushort_range *(*p)[1 << RANGE_HASHBITS] =
		(struct ushort_range *(*)[1 << RANGE_HASHBITS])m->private;
	u16_range_dump(p[1], "TCP", m);
	u16_range_dump(p[0], "UDP", m);
	return 0;
}

static int u16_range_single_open(struct inode *inode, struct file *file)
{
	return (single_open(file, u16_range_show, PDE_DATA(inode)));
}

static struct file_operations u16_range_fops = {
	.open = u16_range_single_open,
	.read = seq_read,
	.write = u16_range_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static struct ushort_range *fastpath_forbidden_range_slot[2][1 << RANGE_HASHBITS];

static inline int test_put_fastpath(struct nf_conntrack_tuple *t)
{
	u16 src, dst;

	switch (t->dst.protonum) {
	case IPPROTO_UDP:
		dst = ntohs(t->dst.u.udp.port);
		if (u16_range_match(fastpath_forbidden_range_slot[0], dst))
			return 0;
		src = ntohs(t->src.u.udp.port);
		if (u16_range_match(fastpath_forbidden_range_slot[0], src))
			return 0;
		break;
	case IPPROTO_TCP:
		dst = ntohs(t->dst.u.tcp.port);
		if (u16_range_match(fastpath_forbidden_range_slot[1], dst))
			return 0;
		src = ntohs(t->src.u.tcp.port);
		if (u16_range_match(fastpath_forbidden_range_slot[1], src))
			return 0;
		break;
	default:
		break;
	}
	return 1;
}

int nf_nat_preprocess_packet(struct nf_conn *ct, unsigned int hooknum,
			     struct sk_buff *skb)
{
	int ret = test_put_fastpath(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
#ifdef CONFIG_NF_NAT_TWINIP
	if (ret)
		nf_nat_preprocess_twin_ip(ct, hooknum, skb);
#endif
	return ret;
}
EXPORT_SYMBOL(nf_nat_preprocess_packet);

#ifdef CONFIG_NF_NAT_PROTO_RESERVED
static struct ushort_range *snat_once_range_slot[2][1 << RANGE_HASHBITS];

int nf_nat_l4proto_test_snat_once(u_int16_t protonum, __be16 port)
{
	switch (protonum) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		return u16_range_match(snat_once_range_slot[!!(protonum == IPPROTO_TCP)], ntohs(port));
	default:
		return 0;
	}
}
EXPORT_SYMBOL(nf_nat_l4proto_test_snat_once);
#endif /* CONFIG_NF_NAT_PROTO_RESERVED */

static int napt_hash_score_min = 1;
static int napt_hash_score_max = 100;

unsigned int napt_hash_score = 1;

static struct ctl_table nettweak_childs[] = {
	{
		.procname	= "napt_hash_score",
		.data		= &napt_hash_score,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= (void *)&napt_hash_score_min,
		.extra2		= (void *)&napt_hash_score_max,
	},
	{}
};

static struct ctl_table nettweak_root[] = {
	{
		.procname	= "private",
		.mode		= 0555,
		.child		= nettweak_childs,
	},
	{}
};

static struct ctl_table_header *nettweak_sysctls;

static int __init nf_pass_port_init(void)
{
	proc_create_data("res_ports", 0644, NULL, &u16_range_fops,
		(void *)fastpath_forbidden_range_slot);
#ifdef CONFIG_NF_NAT_PROTO_RESERVED
	proc_create_data("snat_once_sports", 0644, NULL, &u16_range_fops,
		(void *)snat_once_range_slot);
#endif /* CONFIG_NF_NAT_PROTO_RESERVED */
	nettweak_sysctls = register_sysctl_table(nettweak_root);
	return 0;
}

static void __exit nf_pass_port_exit(void)
{
	remove_proc_entry("res_ports", NULL);
#ifdef CONFIG_NF_NAT_PROTO_RESERVED
	remove_proc_entry("snat_once_sports", NULL);
#endif /* CONFIG_NF_NAT_PROTO_RESERVED */
	if (nettweak_sysctls)
		unregister_sysctl_table(nettweak_sysctls);
}

module_init(nf_pass_port_init);
module_exit(nf_pass_port_exit);
