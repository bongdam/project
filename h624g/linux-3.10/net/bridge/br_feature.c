#include <linux/kernel.h>
#include <linux/rculist.h>

#include "br_private.h"
#include "br_private_stp.h"
#include <linux/proc_fs.h>
#include <net/rtl/rtl_nic.h>
#include <net/rtl/rtk_stp.h>
#include "../../drivers/net/rtl819x/AsicDriver/asicRegs.h"
#include "../../drivers/net/rtl819x/AsicDriver/rtl865x_asicBasic.h"
#include "../../drivers/net/rtl819x/AsicDriver/rtl865x_asicCom.h"
#include "../../drivers/net/rtl819x/AsicDriver/rtl865x_asicL2.h"

extern int rtl865x_curOpMode;
static bool inited;

static inline int pmask_to_pid(int pmask)
{
	int i;
	for (i = 0; pmask && i < 5; i++)
		if (pmask & (1 << i))
			return i;
	return -1;
}

#if !defined(CONFIG_RTL_STP) && !defined(CONFIG_RTL_HW_STP)
static DEFINE_RATELIMIT_STATE(pstp_ratelimit_state, 5 * HZ, 1000);
static struct timer_list restore_state_timer[5];
static struct ratelimit_state pstp_rlim_state[5];

int32 rtl865x_setMulticastSpanningTreePortState(uint32 port, uint32 portState)
{
	__u32 flags;

	if (port >= MAX_RTL_STP_PORT_WH)
		return -EINVAL;

	if (!(REG32(MSCR) & EN_STP))
		return -EPERM;

	flags = REG32(PCRP0 + (port << 2));
	flags &= ~IPMSTP_PortST_MASK;
	switch (portState) {
	case RTL8651_PORTSTA_DISABLED:
		flags |= IPMSTP_PortST_DISABLE;
		break;
	case RTL8651_PORTSTA_BLOCKING:
		flags |= IPMSTP_PortST_BLOCKING;
		break;
	case RTL8651_PORTSTA_LISTENING:
		flags |= IPMSTP_PortST_LISTENING;
		break;
	case RTL8651_PORTSTA_LEARNING:
		flags |= IPMSTP_PortST_LEARNING;
		break;
	case RTL8651_PORTSTA_FORWARDING:
		flags |= IPMSTP_PortST_FORWARDING;
		break;
	default:
		return -EINVAL;
	}

	REG32(PCRP0 + (port << 2)) = flags;
	return 0;
}

int32 rtl865x_setSpanningTreePortState(uint32 port, uint32 portState)
{
	__u32 flags;

	if (port >= MAX_RTL_STP_PORT_WH)
		return -EINVAL;

	if (!(REG32(MSCR) & EN_STP))
		return -EPERM;

	flags = REG32(PCRP0 + (port << 2));
	flags &= ~STP_PortST_MASK;
	switch (portState) {
	case RTL8651_PORTSTA_DISABLED:
		flags |= STP_PortST_DISABLE;
		break;
	case RTL8651_PORTSTA_BLOCKING:
		flags |= STP_PortST_BLOCKING;
		break;
	case RTL8651_PORTSTA_LISTENING:
		flags |= STP_PortST_LISTENING;
		break;
	case RTL8651_PORTSTA_LEARNING:
		flags |= STP_PortST_LEARNING;
		break;
	case RTL8651_PORTSTA_FORWARDING:
		flags |= STP_PortST_FORWARDING;
		break;
	default:
		return -EINVAL;
	}

	REG32(PCRP0 + (port << 2)) = flags;
	return 0;
}

int rtl865x_setSpanningEnable(char spanningTreeEnabled)
{
	__u32 flags;
	int i;

	if (spanningTreeEnabled == TRUE) {
		REG32(MSCR) |= EN_STP;
		for (i = 0; i < MAX_RTL_STP_PORT_WH; i++) {
			if (rtl865x_curOpMode == GATEWAY_MODE &&
			    (1 << i) == RTL_WANPORT_MASK)
				continue;
			flags = REG32(PCRP0 + (i << 2));
			flags &= ~STP_PortST_MASK;
			flags |= STP_PortST_FORWARDING;
			REG32(PCRP0 + (i << 2)) = flags;
		}
	} else
		REG32(MSCR) &= ~EN_STP;
	return 0;
}

static const char *rtl_stp_state_name(int state)
{
	switch (state) {
	case RTL8651_PORTSTA_DISABLED:
		return "DISABLED";
	case RTL8651_PORTSTA_LISTENING:
		return "LISTENING";
	case RTL8651_PORTSTA_LEARNING:
		return "LEARNING";
	case RTL8651_PORTSTA_FORWARDING:
		return "FORWARDING";
	case RTL8651_PORTSTA_BLOCKING:
		return "BLOCKING";
	default:
		return "";
	}
}

static int pstp_set_state(int port, int state)
{
	rtl865x_setMulticastSpanningTreePortState(port, state);
	rtl865x_setSpanningTreePortState(port, state);
	pr_debug("port %d set stp in %s state\n", port, rtl_stp_state_name(state));
	return 0;
}

int pstp_ratelimit(struct net_bridge_port *p, struct sk_buff *skb)
{
	unsigned port = (unsigned)pmask_to_pid(BR_INPUT_SKB_CB(skb)->source_port);

	if (port <= ARRAY_SIZE(pstp_rlim_state) &&
	    __ratelimit(&pstp_rlim_state[port]) == 0 &&
	    timer_pending(&restore_state_timer[port]) == 0) {
	    	pstp_set_state(port, RTL8651_PORTSTA_BLOCKING);
	    	mod_timer(&restore_state_timer[port], jiffies + p->br->max_age);
	    	pstp_rlim_state[port] = pstp_ratelimit_state;
	    	return (int)port;
	}
	return -1;
}
EXPORT_SYMBOL(pstp_ratelimit);

int pstp_ratelimit_update(void)
{
	struct net_device *dev = dev_get_by_name(&init_net, "br0");
	int i;

	if (dev == NULL)
		return -1;
	if (dev->priv_flags & IFF_EBRIDGE) {
		for (i = 0; i < ARRAY_SIZE(pstp_rlim_state); i++)
			pstp_rlim_state[i] = pstp_ratelimit_state;
	}
	dev_put(dev);
	return 0;
}
EXPORT_SYMBOL(pstp_ratelimit_update);

int pstp_ratelimit_cancel(unsigned int port)
{
	if (port <= ARRAY_SIZE(pstp_rlim_state) &&
	    del_timer(&restore_state_timer[port]))
	    	pstp_set_state(port, RTL8651_PORTSTA_FORWARDING);
	return 0;
}
EXPORT_SYMBOL(pstp_ratelimit_cancel);

static void br_restore_state_expired(unsigned long arg)
{
	pstp_set_state(arg, RTL8651_PORTSTA_FORWARDING);
}

static int pstp_dorlimvec(ctl_table *table, int write,
			   void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int rc;
	if (strstr(table->procname, "cost"))
		rc = proc_dointvec_jiffies(table, write, buffer, lenp, ppos);
	else
		rc = proc_dointvec(table, write, buffer, lenp, ppos);
	if (!rc && write)
		pstp_ratelimit_update();
	return rc;
}

static ctl_table pstp_table[] = {
	{
	.procname	= "pstp_ratelimit_cost",
	.data		= &pstp_ratelimit_state.interval,
	.maxlen		= sizeof(int),
	.mode		= 0644,
	.proc_handler	= pstp_dorlimvec,
	},
	{
	.procname	= "pstp_ratelimit_burst",
	.data		= &pstp_ratelimit_state.burst,
	.maxlen		= sizeof(int),
	.mode		= 0644,
	.proc_handler	= pstp_dorlimvec,
	},
        { }
};

static ctl_table pstp_dir_table[] = {
        { .procname     = "stp",
          .mode         = 0555,
          .child        = pstp_table },
        { }
};

static ctl_table pstp_root_table[] = {
        { .procname     = "private",
          .mode         = 0555,
          .child        = pstp_dir_table },
        { }
};
#endif	/* !CONFIG_RTL_STP && !CONFIG_RTL_HW_STP */

#ifndef CONFIG_RTL865X_LANPORT_RESTRICTION
#include <net/rtl/rtl_queue.h>
#include <net/rtl/rtl865x_fdb_api.h>
#include "../../drivers/net/rtl819x/l2Driver/rtl865x_fdb.h"
#include <os_util.h>

static struct timer_list update_quota_timer;
static int mbr_port_quota[5];
static int mbr_port_db[5];
int mbr_port_quota_enabled;

static int l2_source_block(rtl865x_tblAsicDrv_l2Param_t *l2, int r, int c, int blocking)
{
	l2->srcBlk = !!blocking;
	l2->ageSec = (blocking) ? 150 : 450;
	return rtl8651_setAsicL2Table(r, c, l2);
}

int rtl_quota_l2_control(const u8 *addr, int cmd, void *lparm, int wparm)
{
	rtl865x_tblAsicDrv_l2Param_t l2;
	struct net_bridge_fdb_entry *f = (struct net_bridge_fdb_entry *)lparm;
	int i, row, mbr, oldmbr, req = cmd;
	int status = -1;

	/* In case of early drop in asic, DB will be inconsistent with real fdb.
	 */
	if (req == DEL_UNBLK) {
		mbr = pmask_to_pid(QUOTA_MBR(f));
		if (mbr > -1 && mbr_port_quota[mbr] && mbr_port_db[mbr] > 0)
			mbr_port_db[mbr] -= 1;
	}

	for (i = row = 0; i < 6; i++)
		row ^= addr[i];
	row %= RTL8651_L2TBL_ROW;
	for (i = 0; i < RTL8651_L2TBL_COLUMN; i++) {
		if (rtl8651_getAsicL2Table(row, i, &l2) == SUCCESS &&
		    !compare_ether_addr(addr, l2.macAddr.octet)) {
			mbr = rtl865x_ConvertPortMasktoPortNum(l2.memberPortMask);
			if (mbr < 0 || mbr >= (int)ARRAY_SIZE(mbr_port_quota))
				break;

			switch (cmd) {
			case UPDATE_BLK:
				if (wparm != mbr)
					break;
			/* fall thru */
			case TEST_AND_BLK:
tst_and_blk:
				if (mbr_port_quota[mbr] && (++mbr_port_db[mbr] > mbr_port_quota[mbr]))
					status = l2_source_block(&l2, row, i, 1);
				else if (cmd == UPDATE_BLK && l2.srcBlk == 1)
					status = l2_source_block(&l2, row, i, 0);
				f->quota_packed = (l2.srcBlk << QUOTA_BLK_BIT) | (1 << mbr);
				break;
			case DEL_UNBLK:
				if (l2.srcBlk == 1)
					status = l2_source_block(&l2, row, i, 0);
				break;
			case SYNC_BLK:
				oldmbr = pmask_to_pid(f->quota_packed & QUOTA_MBR_MASK);
				if (oldmbr < 0)
					break;
				if (oldmbr != mbr) {
					/* move to an other port */
					if (mbr_port_quota[oldmbr] && mbr_port_db[oldmbr] > 0)
						mbr_port_db[oldmbr] -= 1;
					cmd = UPDATE_BLK;
					goto tst_and_blk;
				} else if ((f->quota_packed >> QUOTA_BLK_BIT) != l2.srcBlk)
					status = l2_source_block(&l2, row, i, (f->quota_packed >> QUOTA_BLK_BIT));
				else if ((f->quota_packed >> QUOTA_BLK_BIT) &&
					 (wparm != INT_MAX) && (wparm < mbr_port_quota[mbr])) {
					status = l2_source_block(&l2, row, i, 0);
					f->quota_packed &= ~(1 << QUOTA_BLK_BIT);
				}
				break;
			default:
				break;
			}
			/* to prevent from scheduling timer doubly */
			if (req != SYNC_BLK || wparm == INT_MAX)
				if (l2.srcBlk && !timer_pending(&update_quota_timer))
					mod_timer(&update_quota_timer, jiffies + (HZ * 1));
			break;
		}
	}

	return status;
}

static void update_quota_expired(unsigned long arg)
{
	struct net_device *dev;
	struct net_bridge *br;
	struct net_bridge_fdb_entry *f;
	struct hlist_node *n;
	int i, mbr, blknr = 0;
	int blked_db[ARRAY_SIZE(mbr_port_db)];

	dev = dev_get_by_name(&init_net, "br0");
	if (!dev || !(dev->priv_flags & IFF_EBRIDGE))
		goto done;
	memcpy(blked_db, mbr_port_db, sizeof(mbr_port_db));
	br = (struct net_bridge *)netdev_priv(dev);
	spin_lock_bh(&br->hash_lock);
	for (i = 0; i < BR_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(f, n, &br->hash[i], hlist) {
			if (f->quota_packed & (1 << QUOTA_BLK_BIT)) {
				mbr = pmask_to_pid(QUOTA_MBR(f));
				if (mbr > -1) {
					--blked_db[mbr];
					rtl_quota_l2_control(f->addr.addr,
						SYNC_BLK, (void *)f, blked_db[mbr]);
					blknr++;
				}
			}
		}
	}
	spin_unlock_bh(&br->hash_lock);
 done:
 	if (dev)
		dev_put(dev);
	if (blknr)
		mod_timer(&update_quota_timer, jiffies + (HZ * 5));
}

static void rtl_quota_update_mbr_port(const char *name, int port, int quota)
{
	struct net_device *dev;
	struct net_bridge *br;
	int i;

	dev = dev_get_by_name(&init_net, name);
	if (!dev || !(dev->priv_flags & IFF_EBRIDGE))
		goto done;

	br = (struct net_bridge *)netdev_priv(dev);
	spin_lock_bh(&br->hash_lock);

	if (port >= 0 && port < (int)ARRAY_SIZE(mbr_port_quota)) {
		mbr_port_quota[port] = quota;
		mbr_port_db[port] = 0;
	}

	for (i = 0; i < BR_HASH_SIZE; i++) {
		struct net_bridge_fdb_entry *f;
		struct hlist_node *n;

		hlist_for_each_entry_safe(f, n, &br->hash[i], hlist) {
			if (f->is_static || (f->addr.addr[0] & 1))
				continue;
			rtl_quota_l2_control(f->addr.addr, UPDATE_BLK, (void *)f, port);
		}
	}
	spin_unlock_bh(&br->hash_lock);
 done:
 	if (dev)
		dev_put(dev);
}

static int lr_read_proc(struct seq_file *m, void *v)
{
	int i;
	seq_printf(m, "%s\n", "lan restrict table:");
	for (i = 0; i < 5; i++)
		seq_printf(m, "  PORT[%d]      %6s %6d %6d\n", i,
			   mbr_port_quota[i] ? "ON" : "OFF",
			   mbr_port_quota[i], mbr_port_db[i]);
	return 0;
}

static int lr_write_proc(const char *buffer, size_t count, void *data)
{
	char buf[80];
	char *args[8], *args2[12];
	int i, argc;
	int port, port_enable, maxnum;

	if (strtrim_from_user(buf, sizeof(buf), buffer, count) > 0) {
		/*
		 format: entry1;entry2;entry3
		 entry format: port_num enable max_num curr_num;
		 port_num:     0,1,2...
		 enable:       on/off
		 max_num:      0,1,2...
		 curr_num:     0,1,2..., can not write, can only read from proc
		               file and write again, just for display
		*/
		if (!strcmp(buf, "enable"))
			mbr_port_quota_enabled = 1;
		else if (!strcmp(buf, "disable")) {
			if (mbr_port_quota_enabled) {
				for (i = 0; i < 5; i++)
					rtl_quota_update_mbr_port("br0", i, 0);
			}
			mbr_port_quota_enabled = 0;
		} else if ((mbr_port_quota_enabled == 1) &&
			   (argc = strargs(buf, args, 8, ";\r\n")) > 0) {
			for (i = 0; i < argc; i++) {
				if (strargs(args[i], args2, 12, " \t\r\n") < 3)
					continue;
				port = simple_strtol(args2[0], NULL, 0);
				if (port < 1 || port >= 5)
					continue;
				port--;
				port_enable = !strcasecmp(args2[1], "on");
				maxnum = simple_strtol(args2[2], NULL, 0);
				if (maxnum < 0)
					continue;
				if (port_enable)
					rtl_quota_update_mbr_port("br0", port, maxnum);
				else
					rtl_quota_update_mbr_port("br0", port, 0);

			}
		}
	}
	return count;
}

static struct proc_dir_thunk lri_top = {
	.read_proc = lr_read_proc,
	.write_proc = lr_write_proc,
};
#endif

int br_feature_setup(void)
{
	if (inited == true)
		return 0;
#if !defined(CONFIG_RTL_STP) && !defined(CONFIG_RTL_HW_STP)
	{
		unsigned long i;

		for (i = 0; i < ARRAY_SIZE(pstp_rlim_state); i++) {
			setup_timer(&restore_state_timer[i], br_restore_state_expired, i);
			pstp_rlim_state[i] = pstp_ratelimit_state;
		}
		register_sysctl_table(pstp_root_table);
	}
#endif
#ifndef CONFIG_RTL865X_LANPORT_RESTRICTION
	create_proc_thunk("lan_restrict_info", NULL, &lri_top);
	setup_timer(&update_quota_timer, update_quota_expired, 0UL);
#endif
	inited = true;
	return 0;
}
