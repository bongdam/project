#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/spinlock.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/etherdevice.h>
#include <os_util.h>

struct dlf_limit_entry {
	struct hlist_node hlist;
	u8 addr[ETH_ALEN];
	short throt;
	atomic_t token;
	atomic_t refcnt;
	unsigned long tstamp;
	char name[IFNAMSIZ];
	struct rcu_head rcu;
};

#define DLF_ENTRY_MAX 16
#define XCEEDPPS 1587
#define QUIESCENCY (HZ << 1)

static int dlf_limit_entry_ratelimit(const u8 *addr, char *iface, bool reg);

static DEFINE_SPINLOCK(dlf_limit_entry_lock);
static atomic_t dlf_limit_entry_count;
#define HBITS 6
static struct hlist_head dlf_limit_entry_head[1 << HBITS];

static inline struct hlist_head *dlf_limit_entry_hash(const u8 *addr)
{
	return &dlf_limit_entry_head[(addr[4] + addr[5]) & ((1 << HBITS) - 1)];
}

static inline struct dlf_limit_entry *__dlf_limit_entry_get(const u8 *addr)
{
	struct dlf_limit_entry *dle;

	hlist_for_each_entry_rcu(dle, dlf_limit_entry_hash(addr), hlist)
		if (!compare_ether_addr(dle->addr, addr))
			return dle;
	return NULL;
}

struct dlf_limit_entry *dlf_limit_entry_get(const u8 *addr)
{
	struct dlf_limit_entry *dle;

	rcu_read_lock();
	dle = __dlf_limit_entry_get(addr);
	if (dle && !atomic_inc_not_zero(&dle->refcnt))
		dle = NULL;
	rcu_read_unlock();
	return dle;
}

static void dlf_limit_entry_free_rcu(struct rcu_head *head)
{
	struct dlf_limit_entry *dle = container_of(head, struct dlf_limit_entry, rcu);
	kfree(dle);
	atomic_dec(&dlf_limit_entry_count);
}

int dlf_limit_entry_put(struct dlf_limit_entry *dle)
{
	if (atomic_dec_and_test(&dle->refcnt)) {
		spin_lock_bh(&dlf_limit_entry_lock);
		hlist_del_rcu(&dle->hlist);
		spin_unlock_bh(&dlf_limit_entry_lock);
		if (dle->throt)
			dlf_limit_entry_ratelimit(dle->addr, dle->name, false);
		synchronize_rcu();
		kfree(dle);
		atomic_dec(&dlf_limit_entry_count);
		return 0;
	}
	return -1;
}

int dlf_limit_entry_delete(const u8 *addr)
{
	struct dlf_limit_entry *dle;

	spin_lock_bh(&dlf_limit_entry_lock);
	dle = __dlf_limit_entry_get(addr);
	if (dle) {
		if (dle->throt)
			dle->throt = dlf_limit_entry_ratelimit(dle->addr, dle->name, false);
		if (atomic_dec_and_test(&dle->refcnt)) {
			hlist_del_rcu(&dle->hlist);
			call_rcu(&dle->rcu, dlf_limit_entry_free_rcu);
		}
	}
	spin_unlock_bh(&dlf_limit_entry_lock);
	return (dle) ? 0 : -1;
}

int dlf_limit_entry_update(const u8 *addr, const char *iface)
{
	struct dlf_limit_entry *dle;

	if (unlikely(!iface || !iface[0]))
		return -1;

	dle = dlf_limit_entry_get(addr);
	if (dle) {
		dle->tstamp = jiffies;
		if (atomic_dec_and_test(&dle->token) && !dle->throt)
			dle->throt = dlf_limit_entry_ratelimit(addr, dle->name, true);
		dlf_limit_entry_put(dle);
	} else if (atomic_read(&dlf_limit_entry_count) < DLF_ENTRY_MAX) {
		if ((dle = kmalloc(sizeof(*dle), GFP_ATOMIC))) {
			strncpy(dle->name, iface, IFNAMSIZ);
			atomic_set(&dle->refcnt, 1);
			memcpy(dle->addr, addr, ETH_ALEN);
			dle->throt = 0;
			atomic_set(&dle->token, XCEEDPPS);
			dle->tstamp = jiffies;
			spin_lock_bh(&dlf_limit_entry_lock);
			hlist_add_head_rcu(&dle->hlist, dlf_limit_entry_hash(addr));
			spin_unlock_bh(&dlf_limit_entry_lock);
			atomic_inc(&dlf_limit_entry_count);
		} else
			return -ENOMEM;
	}
	return 0;
}

static inline void ip_eth_mc_mutate(__be32 naddr, char *buf)
{
	__u32 addr = ntohl(naddr);
	buf[0] = 0x01;
	buf[1] = 0x00;
	buf[2] = (addr >> 24);
	buf[3] = (addr << 8) >> 24;
	buf[4] = (addr << 16) >> 24;
	buf[5] = (addr << 24) >> 24;
}

int dlf_limit_entry_multicast_delete(__be32 group)
{
	u8 addr[6];
	ip_eth_mc_mutate(group, addr);
	return dlf_limit_entry_delete(addr);
}

int dlf_limit_entry_multicast_update(__be32 group, const char *iface)
{
	u8 addr[6];
	ip_eth_mc_mutate(group, addr);
	return dlf_limit_entry_update(addr, iface);
}

void dlf_limit_entry_expiry(void)
{
	struct dlf_limit_entry *dle;
	struct hlist_node *n;
	int i;

	spin_lock_bh(&dlf_limit_entry_lock);
	for (i = 0; i < ARRAY_SIZE(dlf_limit_entry_head); i++) {
		hlist_for_each_entry_safe(dle, n, &dlf_limit_entry_head[i], hlist) {
			atomic_set(&dle->token, XCEEDPPS);
			if ((long)(jiffies - dle->tstamp) < QUIESCENCY)
				continue;
			if (dle->throt)
				dle->throt = dlf_limit_entry_ratelimit(dle->addr, dle->name, false);
			if (atomic_dec_and_test(&dle->refcnt)) {
				hlist_del_rcu(&dle->hlist);
				call_rcu(&dle->rcu, dlf_limit_entry_free_rcu);
			}
		}
	}
	spin_unlock_bh(&dlf_limit_entry_lock);
}

#ifdef CONFIG_RTL_819X_SWCORE
#include <net/rtl/rtl_types.h>
#include <net/rtl/rtl_glue.h>
#include <net/rtl/rtl865x_netif.h>
#include "common/rtl_errno.h"
#include "AsicDriver/rtl865x_asicBasic.h"
#include "AsicDriver/rtl865x_asicCom.h"
#include "AsicDriver/rtl865x_asicL2.h"
#ifdef CONFIG_RTL_LAYERED_ASIC_DRIVER_L3
#include "AsicDriver/rtl865x_asicL3.h"
#endif
#if defined(CONFIG_RTL_LAYERED_ASIC_DRIVER_L4)
#include "AsicDriver/rtl865x_asicL4.h"
#endif
#include "AsicDriver/asicRegs.h"

extern struct proc_dir_entry *rtl865x_proc_dir;

#ifndef CONFIG_RTL_ENABLE_RATELIMIT_TABLE
typedef struct rtl865x_tblAsicDrv_rateLimitParam_s {
	uint32 token;
	uint32 maxToken;
	uint32 t_remainUnit;
	uint32 t_intervalUnit;
	uint32 refill_number;
} rtl865x_tblAsicDrv_rateLimitParam_t;

typedef struct {
#ifndef _LITTLE_ENDIAN
	/* word 0 */
	uint32 reserv0:2;
	uint32 refillRemainTime:6;
	uint32 token:24;
	/* word 1 */
	uint32 reserv1:2;
	uint32 refillTime:6;
	uint32 maxToken:24;
	/* word 2 */
	uint32 reserv2:8;
	uint32 refill:24;
#else
	/* word 0 */
	uint32 token:24;
	uint32 refillRemainTime:6;
	uint32 reserv0:2;
	/* word 1 */
	uint32 maxToken:24;
	uint32 refillTime:6;
	uint32 reserv1:2;
	/* word 2 */
	uint32 refill:24;
	uint32 reserv2:8;
#endif /*_LITTLE_ENDIAN*/
	/* word 3 */
	uint32 reservw3;
	/* word 4 */
	uint32 reservw4;
	/* word 5 */
	uint32 reservw5;
	/* word 6 */
	uint32 reservw6;
	/* word 7 */
	uint32 reservw7;
} rtl8651_tblAsic_rateLimitTable_t;

static int32 rtl8651_setAsicRateLimitTable(uint32 index, rtl865x_tblAsicDrv_rateLimitParam_t *rateLimit_t)
{
	rtl8651_tblAsic_rateLimitTable_t entry;

	if (rateLimit_t == NULL || index >= RTL8651_RATELIMITTBL_SIZE)
		return FAILED;
	memset(&entry, 0, sizeof(rtl8651_tblAsic_rateLimitTable_t));
	entry.maxToken = rateLimit_t->maxToken & 0xFFFFFF;
	entry.refill = rateLimit_t->refill_number & 0xFFFFFF;
	entry.refillTime = rateLimit_t->t_intervalUnit & 0x3F;
	entry.refillRemainTime = rateLimit_t->t_remainUnit & 0x3F;
	entry.token = rateLimit_t->token & 0xFFFFFF;
	return _rtl8651_forceAddAsicEntry(TYPE_RATE_LIMIT_TABLE, index, &entry);
}

static int32 rtl8651_getAsicRateLimitTable(uint32 index, rtl865x_tblAsicDrv_rateLimitParam_t *rateLimit_t)
{
	rtl8651_tblAsic_rateLimitTable_t entry;

	if (rateLimit_t == NULL || index >= RTL8651_RATELIMITTBL_SIZE)
		return FAILED;
	_rtl8651_readAsicEntry(TYPE_RATE_LIMIT_TABLE, index, &entry);
	if (entry.refillTime == 0)
		return FAILED;
	rateLimit_t->token = entry.token & 0xFFFFFF;
	rateLimit_t->maxToken = entry.maxToken & 0xFFFFFF;
	rateLimit_t->t_remainUnit = entry.refillRemainTime & 0x3F;
	rateLimit_t->t_intervalUnit = entry.refillTime & 0x3F;
	rateLimit_t->refill_number = entry.refill & 0xFFFFFF;
	return SUCCESS;
}
#endif /* !CONFIG_RTL_ENABLE_RATELIMIT_TABLE */
#endif /* CONFIG_RTL_819X_SWCORE */

static int dlf_limit_entry_ratelimit(const u8 *addr, char *iface, bool reg)
{
#ifdef CONFIG_RTL_819X_SWCORE
	rtl865x_AclRule_t rule;
	int32 (* func)(rtl865x_AclRule_t *, char *, int32) =
		reg ? rtl865x_add_acl : rtl865x_del_acl;

	memset(&rule, 0, sizeof(rule));
	if (addr[0] & 1) {
		rule.ruleType_ = RTL865X_ACL_DSTFILTER;
		rule.pktOpApp_ = RTL865X_ACL_L3_AND_L4;
		rule.dstFilterIpAddr_ = htonl((addr[2] << 24) | (addr[3] << 16) | (addr[4] << 8) | addr[5]);
		rule.dstFilterIpAddrMask_ = INADDR_NONE;
		rule.dstFilterIgnoreL4_ = 1;
	} else {
		rule.ruleType_ = RTL865X_ACL_MAC;
		rule.pktOpApp_ = RTL865X_ACL_L2_AND_L3;
		memset(rule.dstMacMask_.octet, 0xff, ETH_ALEN);
		memcpy(rule.dstMac_.octet, addr, ETH_ALEN);
	}
	rule.actionType_ = RTL865X_ACL_DROP_RATE_EXCEED_PPS;
	if (func(&rule, iface, RTL865X_ACL_IPV6_USED) == RTL_EENTRYNOTFOUND) {
		rtl865x_regist_aclChain(iface, RTL865X_ACL_IPV6_USED, RTL865X_ACL_INGRESS);
		func(&rule, iface, RTL865X_ACL_IPV6_USED);
	}
#endif
	return reg;
}

static int rate_limit_read_proc(struct seq_file *m, void *v)
{
	rtl865x_tblAsicDrv_rateLimitParam_t entry;
	int i;

	seq_printf(m, "        Token    Max-Token   RemainUnit  IntvlUnit   Refill-Num\n");
	for (i = 0; i < RTL8651_RATELIMITTBL_SIZE; i++) {
		if (rtl8651_getAsicRateLimitTable(i, &entry) != SUCCESS)
			continue;
		seq_printf(m, "[%2d] %10u  %10u  %10u  %10u  %10u\n", i,
			entry.token, entry.maxToken, entry.t_remainUnit,
			entry.t_intervalUnit, entry.refill_number);
	}
	return 0;
}

static int rate_limit_write_proc(const char *buffer, size_t count, void *data)
{
	rtl865x_tblAsicDrv_rateLimitParam_t entry;
	char tmp[128];
	char *args[12];
	int n, argc;

	if (strtrim_from_user(tmp, sizeof(tmp), buffer, count) > 0) {
		if ((argc = strargs(tmp, args, ARRAY_SIZE(args), " \t\r\n")) < 6)
			return count;
		n = simple_strtol(args[0], NULL, 0);
		entry.token = simple_strtol(args[1], NULL, 0);
		entry.maxToken = simple_strtol(args[2], NULL, 0);
		entry.t_remainUnit = simple_strtol(args[3], NULL, 0);
		entry.t_intervalUnit = simple_strtol(args[4], NULL, 0);
		entry.refill_number = simple_strtol(args[5], NULL, 0);
		rtl8651_setAsicRateLimitTable(n, &entry);
	}
	return count;
}

static struct proc_dir_thunk rate_limit_top = {
	.read_proc = rate_limit_read_proc,
	.write_proc = rate_limit_write_proc,
};

static char *addr_printf(const char *addr, char *buf)
{
	if (addr[0] & 1)
		sprintf(buf, "%pI4", &addr[2]);
	else
		sprintf(buf, "%pM", addr);
	return buf;
}

static int dlf_limit_entry_read_proc(struct seq_file *m, void *v)
{
	struct dlf_limit_entry *dle;
	struct hlist_node *n;
	int i;
	char buf[32];

	spin_lock_bh(&dlf_limit_entry_lock);
	for (i = 0; i < ARRAY_SIZE(dlf_limit_entry_head); i++) {
		hlist_for_each_entry_safe(dle, n, &dlf_limit_entry_head[i], hlist)
			seq_printf(m, "%17s  %10d  %10ld  %d  %s\n",
				addr_printf(dle->addr, buf), atomic_read(&dle->token),
				(long)(jiffies - dle->tstamp),
				dle->throt, dle->name);
	}
	spin_unlock_bh(&dlf_limit_entry_lock);
	return 0;
}

static struct proc_dir_thunk dlf_limit_entry_top = {
	.read_proc = dlf_limit_entry_read_proc,
};

int dle_limit_entry_init(void)
{
	rtl865x_tblAsicDrv_rateLimitParam_t rlim;

	memset(&rlim, 0, sizeof(rtl865x_tblAsicDrv_rateLimitParam_t));
	rlim.maxToken = 10;
	rlim.refill_number = 10;
	rlim.t_intervalUnit = 63;
	rlim.t_remainUnit = 63;
	rlim.token = 10;
	rtl8651_setAsicRateLimitTable(0, &rlim);

	create_proc_thunk("ratelimit", rtl865x_proc_dir, &rate_limit_top);
	create_proc_thunk("dlf_list", rtl865x_proc_dir, &dlf_limit_entry_top);
	return 0;
}
EXPORT_SYMBOL(dle_limit_entry_init);
