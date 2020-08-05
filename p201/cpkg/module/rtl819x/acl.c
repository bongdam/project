#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/netdevice.h>
#include <uapi/linux/if.h>
#include <uapi/linux/in.h>
#include <net/net_namespace.h>

#include "version.h"
#include <net/rtl/rtl_types.h>
#include <net/rtl/rtl_glue.h>
#include <net/rtl/rtl865x_netif.h>
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
#include "acl_write.h"

#ifndef CONFIG_RTL_HW_QOS_SUPPORT
# error CONFIG_RTL_HW_QOS_SUPPORT must be defined!
#endif

enum {
	TACL_ADD = 0,
	TACL_DEL = 1,
	TACL_FREE = 2
};

struct tail_aclrule {
	struct list_head  list;
	rtl865x_AclRule_t rule;
	char 		  name[IFNAMSIZ];
	int		  chain;
};

static LIST_HEAD(tailq_aclrule);

static int aclrule_enque_tail(rtl865x_AclRule_t *r, const char *name,
			      int chain, int direction, int deletion)
{
	struct tail_aclrule *t, *tmp;
	/* simple sanity check */
	if (deletion == TACL_ADD) {
		if (r == NULL || name == NULL || chain == 100)
			return -EINVAL;
	}
	/* iterate to find the duplicate */
	list_for_each_entry_safe(t, tmp, &tailq_aclrule, list) {
		if ((r == NULL || !memcmp(r, &t->rule, sizeof(*r))) &&
		    (name == NULL || !strcmp(name, t->name)) &&
		    (chain == 100 || chain == t->chain) &&
		    (direction == -1 || direction == t->rule.direction_)) {
		    	if (deletion != TACL_ADD) {
			    	list_del(&t->list);
			    	if (deletion == TACL_DEL)
			    		rtl865x_del_acl(&t->rule, t->name, t->chain);
			    	kfree(t);
			} else
				return -EEXIST;
		}
	}

	if (deletion == TACL_ADD) {
		t = (struct tail_aclrule *)kmalloc(sizeof(*t), GFP_ATOMIC);
		if (t == NULL)
			return -ENOMEM;
		memcpy(&t->rule, r, sizeof(*r));
		strcpy(t->name, name);
		t->chain = chain;
		list_add_tail(&t->list, &tailq_aclrule);
	}

	return 0;
}

int aclrule_keep_at_tail(const char *name, int chain, int direction)
{
	struct tail_aclrule *t;

	/* flush rules in ASIC */
	list_for_each_entry(t, &tailq_aclrule, list) {
		if ((name == NULL || !strcmp(name, t->name)) &&
		    (chain == 100 || chain == t->chain) &&
		    (direction == -1 || direction == t->rule.direction_))
			rtl865x_del_acl(&t->rule, t->name, t->chain);
	}
	list_for_each_entry(t, &tailq_aclrule, list) {
		if ((name == NULL || !strcmp(name, t->name)) &&
		    (chain == 100 || chain == t->chain) &&
		    (direction == -1 || direction == t->rule.direction_))
			rtl865x_add_acl(&t->rule, t->name, t->chain);
	}
	return 0;
}
EXPORT_SYMBOL(aclrule_keep_at_tail);

long acl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	static int aclchain_inited = 0;
	struct dvCmdAcl_t c;
	int chain, ret = 0;
	DEFINE_SPINLOCK(lock);

	if (_IOC_TYPE(cmd) != (('a' + 'c') & _IOC_TYPEMASK) || _IOC_NR(cmd) != 'l')
		return 0;

	if (!arg || copy_from_user(&c, (void *)arg, sizeof(c)))
		return -EFAULT;

	if (!aclchain_inited) {
		rtl865x_regist_aclChain("br0", RTL865X_ACL_QOS_USED0, RTL865X_ACL_EGRESS);	// -20001
		//rtl865x_regist_aclChain("br0", RTL865X_ACL_IPV6_USED, RTL865X_ACL_INGRESS);
		rtl865x_regist_aclChain("eth1", RTL865X_ACL_IPV6_USED, RTL865X_ACL_INGRESS);	// -30000
		aclchain_inited = 1;
	}

	if (strcmp(c.dir, "out") == 0)
		c.rule.direction_ = RTL865X_ACL_EGRESS;
	else
		c.rule.direction_ = RTL865X_ACL_INGRESS;

	if (strcmp(c.u.chain, "qos") == 0)
		chain = RTL865X_ACL_QOS_USED0;	// -20001
	else
		chain = c.u.chain_nr;

	if (chain == 0)
		chain = RTL865X_ACL_QOS_USED1;
	spin_lock_bh(&lock);
	if (strcmp(c.cmd, "flush") == 0) {
		ret = rtl865x_flush_allAcl_fromChain(c.intf, chain, c.rule.direction_);
		aclrule_enque_tail(NULL, c.intf, chain, c.rule.direction_, TACL_FREE);
	} else if (strcmp(c.cmd, "add") == 0) {
		ret = rtl865x_add_acl(&c.rule, c.intf, chain);
		if (c.keep_at_tail)
			aclrule_enque_tail(&c.rule, c.intf, chain, -1, TACL_ADD);
	} else if (strcmp(c.cmd, "del") == 0) {
		ret = rtl865x_del_acl(&c.rule, c.intf, chain);
		aclrule_enque_tail(&c.rule, c.intf, chain, -1, TACL_DEL);
	}
	spin_unlock_bh(&lock);
	if (put_user(ret, &((struct dvCmdAcl_t *)arg)->result))
		return -EFAULT;
	return 0;
}

int rtl_blockoff_source(__be32 ip, int ifindex, int blocking)
{
	struct net_device *dev;
	rtl865x_AclRule_t rule;
	char name[IFNAMSIZ];
	int ret;

	if (ip == INADDR_NONE || ip == INADDR_ANY || IN_MULTICAST(ntohl(ip)))
		return -1;
	dev = dev_get_by_index(&init_net, ifindex);
	if (dev == NULL)
		return -1;
	strcpy(name, dev->name);
	dev_put(dev);
	memset(&rule, 0, sizeof(rule));
	rule.direction_ = RTL865X_ACL_INGRESS;
	rule.actionType_ = RTL865X_ACL_DROP;
	rule.pktOpApp_ = RTL865X_ACL_ALL_LAYER;
	rule.ruleType_ = RTL865X_ACL_IP;
	//rule.netifIdx_ = ;
	rule.srcIpAddr_ = ntohl(ip);
	rule.srcIpAddrMask_ = 0xffffffff;
	if (blocking) {
		ret = rtl865x_add_acl(&rule, name, RTL865X_ACL_QOS_USED1);
		aclrule_keep_at_tail(name, RTL865X_ACL_QOS_USED1, rule.direction_);
	} else
		ret = rtl865x_del_acl(&rule, name, RTL865X_ACL_QOS_USED1);
	return ret;
}
EXPORT_SYMBOL(rtl_blockoff_source);
