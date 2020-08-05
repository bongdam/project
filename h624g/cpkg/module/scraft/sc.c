#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/proc_fs.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_helper.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <br_private.h>
#include <os_util.h>

static unsigned int lo_ip = 0;

#ifdef MODULE
module_param(lo_ip, uint, 0644);
MODULE_PARM_DESC(lo_ip, "Local inet address");
#endif

static unsigned int lo_mask = 0;
#ifdef MODULE
module_param(lo_mask, uint, 0644);
MODULE_PARM_DESC(lo_mask, "Local inet mask");
#endif

static unsigned int man_ip = 0;
#ifdef MODULE
module_param(man_ip, uint, 0644);
MODULE_PARM_DESC(man_ip, "External inet address");
#endif

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Starcraft NAT helper");
MODULE_ALIAS("Starcraft helper");

#define SC_SNAT_BASEPORT	60000

extern struct list_head pf_netif_receive_skb;

enum {
	SCS_APPLIED_BIT = 0,
	SCS_APPLIED = (1 << SCS_APPLIED_BIT),

	/* We've seen packets both ways: bit 1 set.  Can be set, not unset. */
	SCS_DYING_BIT = 1,
	SCS_DYING = (1 << SCS_DYING_BIT),
};

struct sc_user {
	struct hlist_node	hlist;
	struct in_addr		usrip;
	struct in_addr		manip;
	__be16			manprt;
	__be16			scprt;
	unsigned long		status;
	atomic_t		use;
};

struct sc_work_struct {
	struct work_struct	work;
	struct in_addr		user[2];
	int			detach;
};

struct sc_uwork_struct {
	struct work_struct	work;
	struct completion	*waiting;
	struct sc_user		user;
};

struct sc_skb_cb {
	unsigned int mark;
};
#define BNET	0x626e6574	/* loop-safe */
#define SC_SKB_CB(skb) ((struct sc_skb_cb *)&skb->cb[(sizeof(struct br_input_skb_cb) + 3) & ~3])

static struct sk_buff_head sc_queue;
static DEFINE_SPINLOCK(sc_lock);
#define SCUSR_HASHBITS	6
static struct hlist_head sc_user_head[1 << SCUSR_HASHBITS];
static const __be16 sc_prt = __constant_htons(6112);

static int sc_test_local(__be32 source)
{
	unsigned int subnet = (lo_ip & lo_mask);
	return (subnet && ((source & lo_mask) == subnet)) ? 1 : 0;
}

static int run_usermode(const char *fmt, ...)
{
	char buffer[160];
	char *argv[24];
	va_list ap;
	int status = -1;
	char *envp[3] = { "HOME=/", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);
	if (strargs(buffer, argv, ARRAY_SIZE(argv), " \t\r\n") > 0)
		status = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
	return status;
}

static inline struct hlist_head *sc_inet_hash(__be32 addr)
{
	return &sc_user_head[((u8 *)&addr)[3] & ((1 << SCUSR_HASHBITS) - 1)];
}

struct sc_user *sc_user_get(__be32 addr)
{
	struct sc_user *u;

	hlist_for_each_entry(u, sc_inet_hash(addr), hlist) {
		if (u->usrip.s_addr == addr)
			return u;
	}

	return NULL;
}

static void sc_do_ipt(struct sc_user *u, bool add)
{
	run_usermode("/bin/iptables -t nat -%s PREROUTING -p udp --dport %u -j sc-in",
		     add ? "I" : "D", ntohs(u->manprt));
	run_usermode("/bin/iptables -t nat -%s sc-in -p udp -d %pI4 --dport %u -j DNAT --to %pI4:%u",
		     add ? "I" : "D", &u->manip.s_addr, ntohs(u->manprt), &u->usrip.s_addr, ntohs(u->scprt));
	run_usermode("/bin/iptables -t nat -%s sc-out -p udp -s %pI4 --sport %u --dport %u -j SNAT --to %pI4:%u",
		     add ? "I" : "D", &u->usrip.s_addr, ntohs(u->scprt),
		     ntohs(u->scprt), &u->manip.s_addr, ntohs(u->manprt));
}

static void sc_user_delete(struct sc_user *u)
{
	set_bit(SCS_DYING_BIT, &u->status);
	if (test_bit(SCS_APPLIED_BIT, &u->status))
		sc_do_ipt(u, false);
	spin_lock_bh(&sc_lock);
	hlist_del(&u->hlist);
	spin_unlock_bh(&sc_lock);
	kfree(u);
}

static bool sc_manprt_used(__be16 port)
{
	struct sc_user *u;
	int i;

	for (i = 0; i < ARRAY_SIZE(sc_user_head); i++) {
		hlist_for_each_entry(u, &sc_user_head[i], hlist)
			if (u->manprt == port)
				return true;
	}

	return false;
}

static __be16 sc_manport_uniq(struct nf_conntrack_tuple *tuple)
{
	unsigned int range_size, min, i;
	__be16 *portptr = &tuple->src.u.all;
	u_int16_t off;
	struct nf_conn ct = {
#ifdef CONFIG_NET_NS
		.ct_net = &init_net;
#endif
	};

	range_size = USHRT_MAX - SC_SNAT_BASEPORT;
	min = SC_SNAT_BASEPORT;
	off = ((u8 *)&(tuple->src.u3.ip))[3];
	for (i = 0; i < range_size; i++, off++) {
		*portptr = htons(min + off % range_size);
		if (nf_nat_used_tuple(tuple, &ct) ||
		    sc_manprt_used(*portptr))
			continue;
		return *portptr;
	}
	return 0;
}

static void sc_do_ipt_worker(struct work_struct *work)
{
	struct sk_buff *skb;
	struct sc_user *u;
	struct iphdr *iph;

	while ((skb = skb_dequeue(&sc_queue)) != NULL) {
		iph = (struct iphdr *)((skb->protocol == ETH_P_IP) ? skb->data : skb->data + VLAN_HLEN);
		u = sc_user_get(iph->saddr);
		if (u && !test_bit(SCS_APPLIED_BIT, &u->status)) {
			sc_do_ipt(u, true);
			set_bit(SCS_APPLIED_BIT, &u->status);
		}
		netif_rx(skb);
	}

	kfree(work);
}

static int sc_user_create(struct sk_buff *skb, struct iphdr *iph, struct udphdr *uh)
{
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *h;
	struct work_struct *work;
	struct sc_user *u;
	__be16 manprt;

	if (SC_SKB_CB(skb)->mark == BNET)
		return -1;
	memset(&tuple, 0, sizeof(tuple));
	tuple.src.u3.ip = iph->saddr;
	tuple.dst.u3.ip = iph->daddr;
	tuple.src.u.all = uh->source;
	tuple.dst.u.all = uh->dest;
	tuple.dst.protonum = IPPROTO_UDP;
	tuple.src.l3num = PF_INET;
	tuple.dst.dir = IP_CT_DIR_ORIGINAL;
	h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
	if (h) {
		struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);
		nf_ct_put(ct);
		return -1;
	}

	if (sc_test_local(iph->saddr) &&
	    !sc_test_local(iph->daddr) &&
	    uh->dest == sc_prt) {
	    	u = sc_user_get(iph->saddr);
	    	if (likely(u == NULL)) {
			manprt = sc_manport_uniq(&tuple);
			if (unlikely(!manprt))
				return -1;

	    		u = (struct sc_user *)kzalloc(sizeof(*u), GFP_ATOMIC);
	    		if (unlikely(u == NULL))
	    			return -1;
			u->usrip.s_addr = iph->saddr;
			u->manip.s_addr = man_ip;
			u->manprt = manprt;
			u->scprt = sc_prt;
			spin_lock_bh(&sc_lock);
			hlist_add_head(&u->hlist, sc_inet_hash(iph->saddr));
			spin_unlock_bh(&sc_lock);
			if ((work = kmalloc(sizeof(*work), GFP_ATOMIC))) {
				SC_SKB_CB(skb)->mark = BNET;
				skb_queue_tail(&sc_queue, skb);
				INIT_WORK(work, sc_do_ipt_worker);
				schedule_work(work);
				return 0;
			}
	    	} else if (!test_bit(SCS_APPLIED_BIT, &u->status) ||
	    	           test_bit(SCS_DYING_BIT, &u->status)) {
			dev_kfree_skb_any(skb);
			return 0;
	    	}
	}

	return -1;
}

static void sc_user_event(struct sc_work_struct *w)
{
	struct sc_user *u;
	int i;

	for (i = 0; i < ARRAY_SIZE(w->user); i++) {
		if (w->user[i].s_addr != INADDR_NONE &&
		    (u = sc_user_get(w->user[i].s_addr))) {
			if (w->detach) {
				if (atomic_sub_return(1, &u->use) <= 0)
					sc_user_delete(u);
			} else
				atomic_inc(&u->use);
		}
	}

	kfree(w);
}

static void sc_user_event_post(int detach, __be32 user1, __be32 user2)
{
	struct sc_work_struct *w = kmalloc(sizeof(*w), GFP_ATOMIC);

	if (w != NULL) {
		w->detach = detach;
		w->user[0].s_addr = user1;
		w->user[1].s_addr = user2;
		INIT_WORK(&w->work, (void *)sc_user_event);
		schedule_work(&w->work);
	}
}

static int sc_ct_event(unsigned int events, struct nf_ct_event *item)
{
	struct nf_conn *ct = item->ct;
	const unsigned int emask = (1 << IPCT_DESTROY)|(1 << IPCT_NEW)|(1 << IPCT_RELATED);

	if ((ct != &nf_conntrack_untracked) &&
	    (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_UDP) &&
	    (events & emask)) {
		if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all == sc_prt &&
		    ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all == sc_prt)
			sc_user_event_post(!!(events & (1 << IPCT_DESTROY)),
					ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, INADDR_NONE);
		else if (ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all == sc_prt &&
			 ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all == sc_prt)
			sc_user_event_post(!!(events & (1 << IPCT_DESTROY)),
					ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, INADDR_NONE);
		else if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all == sc_prt &&
			 ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all == sc_prt)
			sc_user_event_post(!!(events & (1 << IPCT_DESTROY)),
					ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
					ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip);
        }

        return NOTIFY_DONE;
}

#if defined(CONFIG_NF_CT_NETLINK) && defined(CONFIG_NF_CONNTRACK_EVENTS)
extern struct nf_ct_event_notifier sc_ct_notifier;
#else
static struct nf_ct_event_notifier sc_ct_notifier = {
	.fcn  = sc_ct_event,
};
#endif

static int sc_show(struct seq_file *m, void *v)
{
	struct sc_user *u;
	int i;

	spin_lock_bh(&sc_lock);
	for (i = 0; i < ARRAY_SIZE(sc_user_head); i++) {
		hlist_for_each_entry(u, &sc_user_head[i], hlist)
			seq_printf(m, " %pI4    %pI4:%u    %d    %08lx\n",
				   &u->usrip.s_addr, &u->manip.s_addr, ntohs(u->manprt),
				   atomic_read(&u->use), u->status);
	}
	spin_unlock_bh(&sc_lock);

	return 0;
}

static struct proc_dir_thunk sc_ct_top = {
	.read_proc = sc_show,
};

static int sc_probe(struct pf_hook_ops *h, struct sk_buff *skb, void *unused)
{
	struct vlan_ethhdr *veh;
	struct iphdr *iph;
	struct udphdr *uh;
	unsigned char *data = skb->data;

	(void)unused;

	if (unlikely(man_ip == INADDR_ANY || man_ip == INADDR_NONE))
		return PF_ACCEPT;

	switch (skb->protocol) {
	case __constant_htons(ETH_P_IP):
 p_ip_match:
		iph = (struct iphdr *)data;
 		if (iph->protocol != IPPROTO_UDP)
 			break;
		uh = (struct udphdr *)((u32 *)iph + iph->ihl);
		if (unlikely(uh->source == sc_prt &&
			     !sc_user_create(skb, iph, uh)))
			return PF_CONSUME;
		break;
	case __constant_htons(ETH_P_8021Q):
		veh = (struct vlan_ethhdr *)eth_hdr(skb);
		if (veh->h_vlan_encapsulated_proto == __constant_htons(ETH_P_IP)) {
			data += VLAN_HLEN;
			goto p_ip_match;
		}
	default:
		break;
	}
	return PF_ACCEPT;
}

static struct pf_hook_ops sc_pf_ops = {
	.list = LIST_HEAD_INIT(sc_pf_ops.list),
	.hook = sc_probe,
	.priority = PFH_PRI_LOW,
};

static void sc_user_destroy_worker(struct sc_uwork_struct *w)
{
	struct completion *waiting = w->waiting;

	sc_do_ipt(&w->user, false);
	kfree(w);
	complete(waiting);
}

#ifndef MODULE
static int proc_doman_ip(struct ctl_table *table, int write,
		     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (ret == 0 && write) {
		if (man_ip && (man_ip != INADDR_NONE)) {
			if (list_empty(&sc_pf_ops.list))
				pf_register_hook(&pf_netif_receive_skb, &sc_pf_ops);
		} else {
			if (!list_empty(&sc_pf_ops.list))
				pf_unregister_hook(&sc_pf_ops);
		}
	}
	return ret;
}

static ctl_table sc_table[] = {
        { .procname     = "lo_ip",
          .data         = &lo_ip,
          .maxlen       = sizeof(lo_ip),
          .mode         = 0644,
          .proc_handler = proc_dointvec },
        { .procname     = "lo_mask",
          .data         = &lo_mask,
          .maxlen       = sizeof(lo_mask),
          .mode         = 0644,
          .proc_handler = proc_dointvec },
        { .procname     = "man_ip",
          .data         = &man_ip,
          .maxlen       = sizeof(man_ip),
          .mode         = 0644,
          .proc_handler = proc_doman_ip },
        { }
};

static ctl_table sc_dir_table[] = {
        { .procname     = "sc",
          .mode         = 0555,
          .child        = sc_table },
        { }
};

static ctl_table sc_root_table[] = {
        { .procname     = "private",
          .mode         = 0555,
          .child        = sc_dir_table },
        { }
};

static struct ctl_table_header *sc_table_header;
#endif

static void __exit sc_fini(void)
{
	struct sc_user *u;
	struct hlist_node *h;
	int i;
	struct completion wait;

	if (!list_empty(&sc_pf_ops.list))
		pf_unregister_hook(&sc_pf_ops);
#if defined(CONFIG_NF_CT_NETLINK) && defined(CONFIG_NF_CONNTRACK_EVENTS)
	rcu_assign_pointer(sc_ct_notifier.fcn, NULL);
#else
	nf_conntrack_unregister_notifier(&init_net, &sc_ct_notifier);
#endif
	remove_proc_entry("scraft", NULL);
#ifndef MODULE
	if (sc_table_header)
		unregister_sysctl_table(sc_table_header);
#endif
	for (i = 0; i < ARRAY_SIZE(sc_user_head); i++) {
		hlist_for_each_entry_safe(u, h, &sc_user_head[i], hlist) {
			hlist_del(&u->hlist);
			if (test_bit(SCS_APPLIED_BIT, &u->status)) {
				struct sc_uwork_struct *w = kmalloc(sizeof(*w), GFP_ATOMIC);
				if (w != NULL) {
					memcpy(&w->user, u, sizeof(*u));
					init_completion(&wait);
					w->waiting = &wait;
					INIT_WORK(&w->work, (void *)sc_user_destroy_worker);
					schedule_work(&w->work);
					wait_for_completion(&wait);
				}
			}
			kfree(u);
		}
	}
	synchronize_rcu();
}

static int __init sc_init(void)
{
	int i;

	skb_queue_head_init(&sc_queue);
	for (i = 0; i < ARRAY_SIZE(sc_user_head); i++)
		INIT_HLIST_HEAD(&sc_user_head[i]);
#if defined(CONFIG_NF_CT_NETLINK) && defined(CONFIG_NF_CONNTRACK_EVENTS)
	rcu_assign_pointer(sc_ct_notifier.fcn, sc_ct_event);
#else
	nf_conntrack_register_notifier(&init_net, &sc_ct_notifier);
#endif
	create_proc_thunk("scraft", NULL, &sc_ct_top);
#ifndef MODULE
	sc_table_header = register_sysctl_table(sc_root_table);
#else
	pf_register_hook(&pf_netif_receive_skb, &sc_pf_ops);	/* in loadable module */
#endif
	return 0;
}

module_init(sc_init);
module_exit(sc_fini);
