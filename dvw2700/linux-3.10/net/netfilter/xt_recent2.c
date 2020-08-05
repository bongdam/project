/*
 * Copyright (c) 2006 Patrick McHardy <kaber@trash.net>
 * Copyright © CC Computer Consultants GmbH, 2007 - 2008
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This is a replacement of the old ipt_recent module, which carried the
 * following copyright notice:
 *
 * Author: Stephen Frost <sfrost@snowman.net>
 * Copyright 2002-2003, Stephen Frost, 2.5.x port by laforge@netfilter.org
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/bitops.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_recent.h>

MODULE_AUTHOR("Patrick McHardy <kaber@trash.net>");
MODULE_AUTHOR("Jan Engelhardt <jengelh@computergmbh.de>");
MODULE_DESCRIPTION("Xtables: \"recently-seen\" host matching for IPv4");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_recent");
MODULE_ALIAS("ip6t_recent");

static unsigned int ip_list_tot = 100;
static unsigned int ip_list_hash_size = 0;
static unsigned int ip_list_perms = 0644;
static unsigned int ip_list_uid = 0;
static unsigned int ip_list_gid = 0;
module_param(ip_list_tot, uint, 0400);
module_param(ip_list_hash_size, uint, 0400);
module_param(ip_list_perms, uint, 0400);
module_param(ip_list_uid, uint, 0400);
module_param(ip_list_gid, uint, 0400);
MODULE_PARM_DESC(ip_list_tot, "number of IPs to remember per list");
MODULE_PARM_DESC(ip_list_hash_size, "size of hash table used to look up IPs");
MODULE_PARM_DESC(ip_list_perms, "permissions on /proc/net/xt_recent/* files");
MODULE_PARM_DESC(ip_list_uid,"owner of /proc/net/xt_recent/* files");
MODULE_PARM_DESC(ip_list_gid,"owning group of /proc/net/xt_recent/* files");

struct recent_entry {
	struct list_head	list;
	struct list_head	lru_list;
	union nf_inet_addr	addr;
	u_int16_t		family;
	u_int8_t		ttl;
	int			accepted;
	int			dropped;
	unsigned long		begin;
};

struct recent_table {
	struct list_head	list;
	char			name[XT_RECENT_NAME_LEN];
	unsigned int		refcnt;
	unsigned int		entries;
	struct list_head	lru_list;
	struct list_head	iphash[0];
};

static LIST_HEAD(tables);
static DEFINE_SPINLOCK(recent_lock);
static DEFINE_MUTEX(recent_mutex);

#ifdef CONFIG_PROC_FS
static struct proc_dir_entry *recent_proc_dir;
static const struct file_operations recent_old_fops, recent_mt_fops;
#endif

extern int rtl_blockoff_source(__be32 ip, int ifindex, int blocking);

struct bhost_entry {
	struct hlist_node hlist;
	__be32 ip;
	int ifindex;
	struct timer_list forward_delay_timer;
};

#define BLKHOST_HASHBITS	6
static struct hlist_head blackhost_head[1 << BLKHOST_HASHBITS];

static inline struct hlist_head *blackhost_hash(__be32 ip)
{
	return &blackhost_head[((u8 *)&ip)[3] & ((1 << BLKHOST_HASHBITS) - 1)];
}

static struct bhost_entry *black_host_find(__be32 ip, int index)
{
	struct bhost_entry *h;
	hlist_for_each_entry(h, blackhost_hash(ip), hlist) {
		if (h->ip == ip && (index < 0 || index == h->ifindex))
			return h;
	}
	return NULL;
}

static void black_host_delete(struct bhost_entry *h)
{
	rtl_blockoff_source(h->ip, h->ifindex, 0);
	del_timer(&h->forward_delay_timer);
	hlist_del(&h->hlist);
	kfree(h);
}

static void black_host_free(struct bhost_entry *h)
{
	spin_lock_bh(&recent_lock);
	rtl_blockoff_source(h->ip, h->ifindex, 0);
	hlist_del(&h->hlist);
	kfree(h);
	spin_unlock_bh(&recent_lock);
}

static struct bhost_entry *
black_host_update(__be32 ip, int ifindex, unsigned long period)
{
	struct bhost_entry *h = black_host_find(ip, ifindex);

	if (h)
		return h;
	h = kmalloc(sizeof(*h), GFP_ATOMIC);
	if (h) {
		rtl_blockoff_source(ip, ifindex, 1);
		h->ip = ip;
		h->ifindex = ifindex;
		setup_timer(&h->forward_delay_timer, (void *)black_host_free,
			(unsigned long)h);
		mod_timer(&h->forward_delay_timer, jiffies + (period * HZ));
		hlist_add_head(&h->hlist, blackhost_hash(ip));
	}
	return h;
}

static void black_host_init(void)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(blackhost_head); i++)
		INIT_HLIST_HEAD(&blackhost_head[i]);
}

static void black_host_fini(void)
{
	struct bhost_entry *h;
	struct hlist_node *node;
	int i;

	spin_lock_bh(&recent_lock);
	for (i = 0; i < ARRAY_SIZE(blackhost_head); i++) {
		hlist_for_each_entry_safe(h, node, &blackhost_head[i], hlist)
			black_host_delete(h);
	}
	spin_unlock_bh(&recent_lock);
}

static u_int32_t hash_rnd;
static bool hash_rnd_initted;

static unsigned int recent_entry_hash4(const union nf_inet_addr *addr)
{
	if (!hash_rnd_initted) {
		get_random_bytes(&hash_rnd, sizeof(hash_rnd));
		hash_rnd_initted = true;
	}
	return jhash_1word((__force u32)addr->ip, hash_rnd) &
	       (ip_list_hash_size - 1);
}

static unsigned int recent_entry_hash6(const union nf_inet_addr *addr)
{
	if (!hash_rnd_initted) {
		get_random_bytes(&hash_rnd, sizeof(hash_rnd));
		hash_rnd_initted = true;
	}
	return jhash2((u32 *)addr->ip6, ARRAY_SIZE(addr->ip6), hash_rnd) &
	       (ip_list_hash_size - 1);
}

static struct recent_entry *
recent_entry_lookup(const struct recent_table *table,
		    const union nf_inet_addr *addrp, u_int16_t family,
		    u_int8_t ttl)
{
	struct recent_entry *e;
	unsigned int h;

	if (family == NFPROTO_IPV4)
		h = recent_entry_hash4(addrp);
	else
		h = recent_entry_hash6(addrp);

	list_for_each_entry(e, &table->iphash[h], list)
		if (e->family == family &&
		    memcmp(&e->addr, addrp, sizeof(e->addr)) == 0 &&
		    (ttl == e->ttl || ttl == 0 || e->ttl == 0))
			return e;
	return NULL;
}

static void recent_entry_remove(struct recent_table *t, struct recent_entry *e)
{
	if (e->family == NFPROTO_IPV4) {
		struct bhost_entry *h = black_host_find(e->addr.ip, -1);
		if (h)
			black_host_delete(h);
	}
	list_del(&e->list);
	list_del(&e->lru_list);
	kfree(e);
	t->entries--;
}

static struct recent_entry *
recent_entry_init(struct recent_table *t, const union nf_inet_addr *addr,
		  u_int16_t family, u_int8_t ttl)
{
	struct recent_entry *e;

	if (t->entries >= ip_list_tot) {
		e = list_entry(t->lru_list.next, struct recent_entry, lru_list);
		recent_entry_remove(t, e);
	}

	e = kmalloc(sizeof(*e), GFP_ATOMIC);
	if (e == NULL)
		return NULL;
	memcpy(&e->addr, addr, sizeof(e->addr));
	e->ttl      = ttl;
	e->begin    = 0;
	e->accepted = 0;
	e->dropped  = 0;
	e->family   = family;
	if (family == NFPROTO_IPV4)
		list_add_tail(&e->list, &t->iphash[recent_entry_hash4(addr)]);
	else
		list_add_tail(&e->list, &t->iphash[recent_entry_hash6(addr)]);
	list_add_tail(&e->lru_list, &t->lru_list);
	t->entries++;
	return e;
}

static void recent_entry_update(struct recent_table *t, struct recent_entry *e)
{
	list_move_tail(&e->lru_list, &t->lru_list);
}

static struct recent_table *recent_table_lookup(const char *name)
{
	struct recent_table *t;

	list_for_each_entry(t, &tables, list)
		if (!strcmp(t->name, name))
			return t;
	return NULL;
}

static void recent_table_flush(struct recent_table *t)
{
	struct recent_entry *e, *next;
	unsigned int i;

	for (i = 0; i < ip_list_hash_size; i++)
		list_for_each_entry_safe(e, next, &t->iphash[i], list)
			recent_entry_remove(t, e);
}

static int recent_ratelimit(struct recent_entry *e, int interval, int burst)
{
	if (interval == 0)
		interval = 5 * HZ;

	if (!e->begin)
		e->begin = jiffies;

	if (time_is_before_jiffies(e->begin + interval)) {
		e->begin = 0;
		e->accepted = 0;
	}
	if (burst && burst > e->accepted)
		goto accept;

	e->dropped++;
	return 0;
accept:
	e->accepted++;
	return 1;
}

static bool
recent_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_recent_mtinfo *info = par->matchinfo;
	struct recent_table *t;
	struct recent_entry *e;
	union nf_inet_addr addr = {};
	u_int8_t ttl;
	bool ret = info->invert;

	if (par->match->family == NFPROTO_IPV4) {
		const struct iphdr *iph = ip_hdr(skb);

		if (info->side == XT_RECENT_DEST)
			addr.ip = iph->daddr;
		else
			addr.ip = iph->saddr;

		ttl = iph->ttl;
	} else {
		const struct ipv6hdr *iph = ipv6_hdr(skb);

		if (info->side == XT_RECENT_DEST)
			memcpy(&addr.in6, &iph->daddr, sizeof(addr.in6));
		else
			memcpy(&addr.in6, &iph->saddr, sizeof(addr.in6));

		ttl = iph->hop_limit;
	}

	/* use TTL as seen before forwarding */
	if (par->out != NULL && skb->sk == NULL)
		ttl++;

	spin_lock_bh(&recent_lock);
	t = recent_table_lookup(info->name);
	e = recent_entry_lookup(t, &addr, par->match->family,
				(info->check_set & XT_RECENT_TTL) ? ttl : 0);
	if (e == NULL) {
		if (!(info->check_set & XT_RECENT_SET))
			goto out;
		e = recent_entry_init(t, &addr, par->match->family, ttl);
		if (e == NULL)
			par->hotdrop = true;
		ret = !ret;
		goto out;
	}

	if (info->check_set & XT_RECENT_SET)
		ret = !ret;
	else if (info->check_set & XT_RECENT_REMOVE) {
		recent_entry_remove(t, e);
		ret = !ret;
	} else if (info->check_set & (XT_RECENT_CHECK | XT_RECENT_UPDATE)) {
		if (!recent_ratelimit(e, (int)info->seconds * HZ, (int)info->hit_count)) {
			if (info->blockoff && e->family == NFPROTO_IPV4 && info->side == XT_RECENT_SOURCE)
				black_host_update(addr.ip, (par->in) ? par->in->ifindex : -1, info->blockoff);
			ret = !ret;
		}
	}

	if (info->check_set & XT_RECENT_SET ||
	    (info->check_set & XT_RECENT_UPDATE && ret)) {
		recent_entry_update(t, e);
		e->ttl = ttl;
	}
out:
	spin_unlock_bh(&recent_lock);
	return ret;
}

static int recent_mt_check(const struct xt_mtchk_param *par)
{
	const struct xt_recent_mtinfo *info = par->matchinfo;
	struct recent_table *t;
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *pde;
	kuid_t uid;
	kgid_t gid;
#endif
	unsigned i;
	bool ret = -EINVAL;

	if (hweight8(info->check_set &
		     (XT_RECENT_SET | XT_RECENT_REMOVE |
		      XT_RECENT_CHECK | XT_RECENT_UPDATE)) != 1)
		return -EINVAL;
	if ((info->check_set & (XT_RECENT_SET | XT_RECENT_REMOVE)) &&
	    (info->seconds || info->hit_count))
		return -EINVAL;
	if (info->hit_count > INT_MAX)
		return -EINVAL;
	if (info->name[0] == '\0' ||
	    strnlen(info->name, XT_RECENT_NAME_LEN) == XT_RECENT_NAME_LEN)
		return -EINVAL;

	mutex_lock(&recent_mutex);
	t = recent_table_lookup(info->name);
	if (t != NULL) {
		t->refcnt++;
		ret = 0;
		goto out;
	}

	t = kzalloc(sizeof(*t) + sizeof(t->iphash[0]) * ip_list_hash_size,
		    GFP_KERNEL);
	if (t == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	t->refcnt = 1;
	strcpy(t->name, info->name);
	INIT_LIST_HEAD(&t->lru_list);
	for (i = 0; i < ip_list_hash_size; i++)
		INIT_LIST_HEAD(&t->iphash[i]);
#ifdef CONFIG_PROC_FS
	uid = make_kuid(&init_user_ns, ip_list_uid);
	gid = make_kgid(&init_user_ns, ip_list_gid);
	if (!uid_valid(uid) || !gid_valid(gid)) {
		kfree(t);
		ret = -EINVAL;
		goto out;
	}
	pde = proc_create_data(t->name, ip_list_perms, recent_proc_dir,
		  &recent_mt_fops, t);
	if (pde == NULL) {
		kfree(t);
		ret = -ENOMEM;
		goto out;
	}
	proc_set_user(pde, uid, gid);
#endif
	spin_lock_bh(&recent_lock);
	list_add_tail(&t->list, &tables);
	spin_unlock_bh(&recent_lock);
	ret = 0;
out:
	mutex_unlock(&recent_mutex);
	return ret;
}

static void recent_mt_destroy(const struct xt_mtdtor_param *par)
{
	const struct xt_recent_mtinfo *info = par->matchinfo;
	struct recent_table *t;

	mutex_lock(&recent_mutex);
	t = recent_table_lookup(info->name);
	if (--t->refcnt == 0) {
		spin_lock_bh(&recent_lock);
		list_del(&t->list);
		spin_unlock_bh(&recent_lock);
#ifdef CONFIG_PROC_FS
		remove_proc_entry(t->name, recent_proc_dir);
#endif
		recent_table_flush(t);
		kfree(t);
	}
	mutex_unlock(&recent_mutex);
}

#ifdef CONFIG_PROC_FS
struct recent_iter_state {
	const struct recent_table *table;
	unsigned int		bucket;
};

static void *recent_seq_start(struct seq_file *seq, loff_t *pos)
	__acquires(recent_lock)
{
	struct recent_iter_state *st = seq->private;
	const struct recent_table *t = st->table;
	struct recent_entry *e;
	loff_t p = *pos;

	spin_lock_bh(&recent_lock);

	for (st->bucket = 0; st->bucket < ip_list_hash_size; st->bucket++)
		list_for_each_entry(e, &t->iphash[st->bucket], list)
			if (p-- == 0)
				return e;
	return NULL;
}

static void *recent_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct recent_iter_state *st = seq->private;
	const struct recent_table *t = st->table;
	const struct recent_entry *e = v;
	const struct list_head *head = e->list.next;

	while (head == &t->iphash[st->bucket]) {
		if (++st->bucket >= ip_list_hash_size)
			return NULL;
		head = t->iphash[st->bucket].next;
	}
	(*pos)++;
	return list_entry(head, struct recent_entry, list);
}

static void recent_seq_stop(struct seq_file *s, void *v)
	__releases(recent_lock)
{
	spin_unlock_bh(&recent_lock);
}

static int recent_seq_show(struct seq_file *seq, void *v)
{
	const struct recent_entry *e = v;
	struct bhost_entry *h;

	if (e->family == NFPROTO_IPV4) {
		seq_printf(seq, "src=%pI4 ttl: %u begin: %lu accepted: %d dropped %d",
			   &e->addr.ip, e->ttl, e->begin, e->accepted, e->dropped);
		h = black_host_find(e->addr.ip, -1);
		if (h)
			seq_printf(seq, " blockoff %ld ifindex %d\n",
				(long)h->forward_delay_timer.expires - (long)jiffies,
				h->ifindex);
		else
			seq_printf(seq, "\n");
	} else
		seq_printf(seq, "src=%pI6 ttl: %u begin: %lu accepted: %d dropped %d\n",
			   &e->addr.in6, e->ttl, e->begin, e->accepted, e->dropped);
	return 0;
}

static const struct seq_operations recent_seq_ops = {
	.start		= recent_seq_start,
	.next		= recent_seq_next,
	.stop		= recent_seq_stop,
	.show		= recent_seq_show,
};

static int recent_seq_open(struct inode *inode, struct file *file)
{
	struct recent_iter_state *st;

	st = __seq_open_private(file, &recent_seq_ops, sizeof(*st));
	if (st == NULL)
		return -ENOMEM;

	st->table = PDE_DATA(inode);
	return 0;
}

static ssize_t
recent_mt_proc_write(struct file *file, const char __user *input,
		     size_t size, loff_t *loff)
{
	struct recent_table *t = PDE_DATA(file_inode(file));
	struct recent_entry *e;
	char buf[sizeof("+b335:1d35:1e55:dead:c0de:1715:5afe:c0de")];
	const char *c = buf;
	union nf_inet_addr addr = {};
	u_int16_t family;
	bool add, succ;

	if (size == 0)
		return 0;
	if (size > sizeof(buf))
		size = sizeof(buf);
	if (copy_from_user(buf, input, size) != 0)
		return -EFAULT;

	/* Strict protocol! */
	if (*loff != 0)
		return -ESPIPE;
	switch (*c) {
	case '/': /* flush table */
		spin_lock_bh(&recent_lock);
		recent_table_flush(t);
		spin_unlock_bh(&recent_lock);
		return size;
	case '-': /* remove address */
		add = false;
		break;
	case '+': /* add address */
		add = true;
		break;
	default:
		printk(KERN_INFO KBUILD_MODNAME ": Need +ip, -ip or /\n");
		return -EINVAL;
	}

	++c;
	--size;
	if (strnchr(c, size, ':') != NULL) {
		family = NFPROTO_IPV6;
		succ   = in6_pton(c, size, (void *)&addr, '\n', NULL);
	} else {
		family = NFPROTO_IPV4;
		succ   = in4_pton(c, size, (void *)&addr, '\n', NULL);
	}

	if (!succ) {
		printk(KERN_INFO KBUILD_MODNAME ": illegal address written "
		       "to procfs\n");
		return -EINVAL;
	}

	spin_lock_bh(&recent_lock);
	e = recent_entry_lookup(t, &addr, family, 0);
	if (e == NULL) {
		if (add)
			recent_entry_init(t, &addr, family, 0);
	} else {
		if (add)
			recent_entry_update(t, e);
		else
			recent_entry_remove(t, e);
	}
	spin_unlock_bh(&recent_lock);
	/* Note we removed one above */
	*loff += size + 1;
	return size + 1;
}

static const struct file_operations recent_mt_fops = {
	.open    = recent_seq_open,
	.read    = seq_read,
	.write   = recent_mt_proc_write,
	.release = seq_release_private,
	.owner   = THIS_MODULE,
};
#endif /* CONFIG_PROC_FS */

static struct xt_match recent_mt_reg[] __read_mostly = {
	{
		.name       = "recent",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.match      = recent_mt,
		.matchsize  = sizeof(struct xt_recent_mtinfo),
		.checkentry = recent_mt_check,
		.destroy    = recent_mt_destroy,
		.me         = THIS_MODULE,
	},
	{
		.name       = "recent",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.match      = recent_mt,
		.matchsize  = sizeof(struct xt_recent_mtinfo),
		.checkentry = recent_mt_check,
		.destroy    = recent_mt_destroy,
		.me         = THIS_MODULE,
	},
};

static int __init recent_mt_init(void)
{
	int err;

	if (!ip_list_tot)
		return -EINVAL;

	black_host_init();
	ip_list_hash_size = 1 << fls(ip_list_tot);
	err = xt_register_matches(recent_mt_reg, ARRAY_SIZE(recent_mt_reg));
#ifdef CONFIG_PROC_FS
	if (err)
		return err;
	recent_proc_dir = proc_mkdir("xt_recent", init_net.proc_net);
	if (recent_proc_dir == NULL) {
		xt_unregister_matches(recent_mt_reg, ARRAY_SIZE(recent_mt_reg));
		err = -ENOMEM;
	}
#endif
	return err;
}

static void __exit recent_mt_exit(void)
{
	BUG_ON(!list_empty(&tables));
	xt_unregister_matches(recent_mt_reg, ARRAY_SIZE(recent_mt_reg));
#ifdef CONFIG_PROC_FS
	remove_proc_entry("xt_recent", init_net.proc_net);
#endif
	black_host_fini();
}

module_init(recent_mt_init);
module_exit(recent_mt_exit);
