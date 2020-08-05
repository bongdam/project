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

static u8 __nf_passing_ports[2][65536 / 8];

static inline int test_put_fastpath(struct nf_conntrack_tuple *t)
{
	u16 src, dst;

	switch (t->dst.protonum) {
	case IPPROTO_UDP:
		dst = ntohs(t->dst.u.udp.port);
		if (__nf_passing_ports[0][dst >> 3] & (1 << (dst & 7)))
			return 0;
		src = ntohs(t->src.u.udp.port);
		if (__nf_passing_ports[0][src >> 3] & (1 << (src & 7)))
			return 0;
		break;
	case IPPROTO_TCP:
		dst = ntohs(t->dst.u.tcp.port);
		if (__nf_passing_ports[1][dst >> 3] & (1 << (dst & 7)))
			return 0;
		src = ntohs(t->src.u.tcp.port);
		if (__nf_passing_ports[1][src >> 3] & (1 << (src & 7)))
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
	return test_put_fastpath(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
}
EXPORT_SYMBOL(nf_nat_preprocess_packet);

static int port_range(char *s, int do_set, u8 b)
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

		if (do_set) {
			for (; min_dpt <= max_dpt; min_dpt++)
				__nf_passing_ports[b][min_dpt >> 3] |= (1 << (min_dpt & 7));
		} else {
			for (; min_dpt <= max_dpt; min_dpt++)
				__nf_passing_ports[b][min_dpt >> 3] &= ~(1 << (min_dpt & 7));
		}
		return 0;
	}

	return -1;
}

static ssize_t nf_pass_port_write(struct file *file, const char __user *buffer,
				  size_t count, loff_t * data)
{
	enum { S_CMD, S_PROTO, S_PORT };
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
						port_range(all, 0, b);
					}
					break;
				} else
					status = S_PORT;
			} else if (status == S_PORT)
				port_range(q, !!(comm == 'a'), b);
		}
	}

 	if (tmp)
 		kfree(tmp);
	return count;
}

static int nf_pass_port_dump(const char *proto, struct seq_file *m, u8 b)
{
	enum { S_NONE, S_MARKED };
	int i, port, status = S_NONE;
	size_t count = m->count;

	seq_printf(m, "%s:\n", proto);
	for (i = 0; i < 65536; i++) {
		if (status == S_NONE) {
			if (__nf_passing_ports[b][i >> 3] & (1 << (i & 7))) {
				port = i;
				status = S_MARKED;
			}
		} else {
			if (!(__nf_passing_ports[b][i >> 3] & (1 << (i & 7)))) {
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

static int nf_pass_port_show(struct seq_file *m, void *v)
{
	nf_pass_port_dump("TCP", m, 1);
	nf_pass_port_dump("UDP", m, 0);
	return 0;
}

static int nf_pass_port_single_open(struct inode *inode, struct file *file)
{
	return (single_open(file, nf_pass_port_show, NULL));
}

static struct file_operations nf_pass_port_fops = {
	.open = nf_pass_port_single_open,
	.read = seq_read,
	.write = nf_pass_port_write,
	.llseek = seq_lseek,
	.release = single_release,
};

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
	proc_create_data("res_ports", 0644, NULL, &nf_pass_port_fops, NULL);
	nettweak_sysctls = register_sysctl_table(nettweak_root);
	return 0;
}

static void __exit nf_pass_port_exit(void)
{
	remove_proc_entry("res_ports", NULL);
	if (nettweak_sysctls)
		unregister_sysctl_table(nettweak_sysctls);
}

module_init(nf_pass_port_init);
module_exit(nf_pass_port_exit);
