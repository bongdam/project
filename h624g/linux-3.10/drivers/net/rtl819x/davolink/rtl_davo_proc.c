#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
#define DRV_RELDATE		"Jan 27, 2014"
#include <linux/kconfig.h>
#else
#define DRV_RELDATE		"Mar 25, 2004"
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/compiler.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/if_vlan.h>
#include <linux/crc32.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/signal.h>
#include <linux/proc_fs.h>
#include <net/rtl/rtl_types.h>
#include <net/rtl/rtl_glue.h>

#include "AsicDriver/rtl865x_asicBasic.h"
#include "AsicDriver/rtl865x_asicCom.h"
#include "AsicDriver/rtl865x_asicL2.h"
#ifdef CONFIG_RTL_LAYERED_ASIC_DRIVER_L3
#include "AsicDriver/rtl865x_asicL3.h"
#endif
#if defined(CONFIG_RTL_LAYERED_ASIC_DRIVER_L4)
#include <net/rtl/rtl865x_nat.h>
#include "AsicDriver/rtl865x_asicL4.h"
#include "l4Driver/rtl865x_nat_local.h"
#endif

#include "AsicDriver/rtl865xc_asicregs.h"
#include "AsicDriver/rtl865xC_hs.h"
#if defined (CONFIG_RTL_IGMP_SNOOPING)
#include <net/rtl/rtl865x_igmpsnooping.h>
#endif

#include "rtl865xc_swNic.h"
#if defined(CONFIG_RTL_ETH_PRIV_SKB_DEBUG)
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/if.h>
#include <net/rtl/rtl_nic.h>
#endif
#include <os_util.h>

extern int dv_qos_init(void);

#if defined (CONFIG_RTL_IGMP_SNOOPING)
/* jihyun@davo 150614 jcode#1 */
int igmp_query_only_to_lan;
int igmp_query_received;

#if defined(__DV_IGMP_FILTER__)
typedef struct {
	unsigned long igmp_last_period;
	unsigned long igmp_last_block_time;
	unsigned long igmp_relay;
	unsigned long igmp_rx;
	unsigned long igmp_drop;
	unsigned long igmp_thresh_hold;	// packet per second
	int igmp_blocked;
	int igmp_blocked_period;
} igmp_stat_t;

static igmp_stat_t igmp_stat[5];
int igmp_block_enable = 0;

int dv_igmp_block_filter(int pid)
{
	if (igmp_stat[pid].igmp_thresh_hold == 0)
		return 0;

	if (jiffies - igmp_stat[pid].igmp_last_period < HZ) {	// 1 sec
		if (igmp_stat[pid].igmp_relay > igmp_stat[pid].igmp_thresh_hold) {	// igmp count during 1 sec
			if (igmp_stat[pid].igmp_blocked == 0)
				printk("IGMP Blocked : port=%d\n", pid);
			igmp_stat[pid].igmp_last_block_time = jiffies;
			igmp_stat[pid].igmp_blocked = 1;
		} else {
			igmp_stat[pid].igmp_relay++;
			igmp_stat[pid].igmp_rx++;
		}
	} else {
		igmp_stat[pid].igmp_last_period = jiffies;
		igmp_stat[pid].igmp_relay = 1;
	}

	if (igmp_stat[pid].igmp_blocked) {
		if (jiffies - igmp_stat[pid].igmp_last_block_time < igmp_stat[pid].igmp_blocked_period) {
			//printk("IGMP Dropped : pid=%d, remain=%lu\n",
			//      pid, 30000 - (jiffies - igmp_stat[pid].igmp_last_block_time));
			igmp_stat[pid].igmp_drop++;
			return 1;	// drop
		} else {
			igmp_stat[pid].igmp_blocked = 0;
			printk("IGMP Unblocked : port=%d\n", pid);
		}
	}

	return 0;		// pass
}
#endif

#ifdef CONFIG_RTL_PROC_NEW
static int dv_igmp_query_to_lanWriteProc(struct file *file, const char *buffer, unsigned long count, void *data)
{
	char tmp[32];
	if (strtrim_from_user(tmp, sizeof(tmp), buffer, count))
		igmp_query_only_to_lan = !!simple_strtol(tmp, NULL, 0);
	return count;
}

static int dv_igmp_query_to_lanReadProc(struct seq_file *s, void *v)
{
	seq_printf(s, "%d\n", igmp_query_only_to_lan);
	return 0;
}

int dv_igmp_query_to_lan_open(struct inode *inode, struct file *file)
{
	return (single_open(file, dv_igmp_query_to_lanReadProc, NULL));
}

static ssize_t dv_igmp_query_to_lan_write(struct file *file, const char __user *userbuf, size_t count, loff_t *off)
{
	return dv_igmp_query_to_lanWriteProc(file, userbuf, count, off);
}

static int dv_igmp_query_receivedWriteProc(struct file *file, const char *buffer, unsigned long count, void *data)
{
	char tmp[32];
	if (strtrim_from_user(tmp, sizeof(tmp), buffer, count) > 0)
		igmp_query_received = !!simple_strtol(tmp, NULL, 0);
	return count;
}

static int dv_igmp_query_receivedReadProc(struct seq_file *s, void *v)
{
	seq_printf(s, "%d\n", igmp_query_received);
	return 0;
}

int dv_igmp_query_received_open(struct inode *inode, struct file *file)
{
	return (single_open(file, dv_igmp_query_receivedReadProc, NULL));
}

static ssize_t dv_igmp_query_received_write(struct file *file, const char __user *userbuf, size_t count, loff_t *off)
{
	return dv_igmp_query_receivedWriteProc(file, userbuf, count, off);
}

#if defined(__DV_IGMP_FILTER__)
static int dv_igmp_blockWriteProc(struct file *file, const char *buffer, unsigned long count, void *data)
{
	char rcvbuf[32];
	int opcode, enable, thresh, period;
	int i, index = 0;

	memset(rcvbuf, 0, sizeof(rcvbuf));
	if (strtrim_from_user(rcvbuf, sizeof(rcvbuf), buffer, count)) {
		index += sscanf(rcvbuf + index, "%d", &opcode);
		if (opcode == 1) {
			index += sscanf(rcvbuf + index, "%d %d %d", &igmp_block_enable, &thresh, &period);
			printk("IGMP Block Control %s: Threadhold %d pps, Block period %d sec\n",
			       igmp_block_enable ? "Enabled" : "Disabled", thresh, period);
			for (i = 1; i < 5; i++) {
				igmp_stat[i].igmp_thresh_hold = thresh;
				igmp_stat[i].igmp_blocked_period = period * HZ;
			}
		} else if (opcode == 2) {
			for (i = 1; (i < 5) && (index < count); i++) {
				while (*(rcvbuf + index) == ' ')
					index++;
				index += sscanf(rcvbuf + index, "%d ", &enable);
				printk("LAN%d: %s\n", i, enable ? "Blocked" : "Unblocked");
				igmp_stat[i].igmp_blocked = enable;
			}
		} else {
			printk("Unkown opcode[%d]\n", opcode);
		}
		return count;
	}
	return -EFAULT;
}

static int dv_igmp_blockReadProc(struct seq_file *s, void *v)
{
	int i;

	seq_printf(s, "%d\n", igmp_block_enable);
	for (i = 1; i < 5; i++) {
		seq_printf(s, "%d %d %lu %lu %lu\n",
			   igmp_stat[i].igmp_blocked,
			   igmp_stat[i].igmp_blocked_period / HZ,
			   igmp_stat[i].igmp_thresh_hold,
			   igmp_stat[i].igmp_rx,
			   igmp_stat[i].igmp_drop);
	}
	return 0;
}

int dv_igmp_block_open(struct inode *inode, struct file *file)
{
	return (single_open(file, dv_igmp_blockReadProc, NULL));
}

static ssize_t dv_igmp_block_write(struct file *file, const char __user *userbuf, size_t count, loff_t *off)
{
	return dv_igmp_blockWriteProc(file, userbuf, count, off);
}
#endif

struct mc_proc_iter {
	rtl865x_tblAsicDrv_multiCastParam_t mc;
	int cp;
	int eor;		/* end of record */
};

static void *mc_iter_next(struct mc_proc_iter *it)
{
	int i;

	while ((i = it->cp++) < RTL8651_MULTICASTTBL_SIZE) {
		if (rtl8651_getAsicIpMulticastTable(i, &it->mc) != SUCCESS)
			continue;
		return (void *)&it->mc;
	}
	it->eor = 1;
	return NULL;
}

static void *mc_proc_seq_start(struct seq_file *s, loff_t *pos)
{
	struct mc_proc_iter *it = (struct mc_proc_iter *)s->private;
	return (*pos) ? mc_iter_next(it) : SEQ_START_TOKEN;
}

static void *mc_proc_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct mc_proc_iter *it = (struct mc_proc_iter *)s->private;
	++*pos;
	return mc_iter_next(it);
}

static void mc_proc_seq_stop(struct seq_file *s, void *v)
{
	if (((struct mc_proc_iter *)s->private)->eor)
		seq_printf(s, "\nTotalOpCnt: AddMcastOpCnt %d"
			   "\n            DelMcastOpCnt %d"
			   "\n            ForceAddMcastOpCnt %d\n",
			   _rtl865x_getAddMcastOpCnt(),
			   _rtl865x_getDelMcastOpCnt(),
			   _rtl865x_getForceAddMcastOpCnt());
}

static int mc_proc_seq_show(struct seq_file *s, void *v)
{
	struct mc_proc_iter *it = (struct mc_proc_iter *)s->private;
	char dip[16], sip[16];

	if (v == SEQ_START_TOKEN)
		seq_printf(s, "Slot Destination     Source          MBR SVID SPA EXT AGE  CPU\n");
	else {
		sprintf(dip, "%u.%u.%u.%u", NIPQUAD(it->mc.dip));
		sprintf(sip, "%u.%u.%u.%u", NIPQUAD(it->mc.sip));
		seq_printf(s, "%4d %-15s %-15s %3x %4d %3d %3d %4d %3d\n",
			   it->cp - 1, dip, sip, it->mc.mbr, it->mc.svid, it->mc.port, it->mc.extIdx, it->mc.age, it->mc.cpu);
	}
	return 0;
}

static struct seq_operations mc_proc_seq_ops = {
	.start = mc_proc_seq_start,
	.stop = mc_proc_seq_stop,
	.next = mc_proc_seq_next,
	.show = mc_proc_seq_show,
};

static int mc_proc_open(struct inode *inode, struct file *file)
{
	int rc = -ENOMEM;
	struct mc_proc_iter *it = kzalloc(sizeof(*it), GFP_KERNEL);

	if (!it)
		goto out;
	rc = seq_open(file, &mc_proc_seq_ops);
	if (rc)
		goto out_kfree;
	((struct seq_file *)file->private_data)->private = it;
 out:
	return rc;
 out_kfree:
	kfree(it);
	goto out;
}

struct asic_stats22 {
	unsigned long	in_unicast;
	unsigned long	in_multicast;
	unsigned long	in_broadcast;
	unsigned long	in_unicast_snap;
	unsigned long	in_multicast_snap;
	unsigned long	in_broadcast_snap;
	unsigned long	out_unicast;
	unsigned long	out_multicast;
	unsigned long	out_broadcast;
	unsigned long	out_unicast_snap;
	unsigned long	out_multicast_snap;
	unsigned long	out_broadcast_snap;
};

static struct asic_stats22 stats22[5];
static unsigned long tx_bytes_hist[5][300];
static unsigned long rx_bytes_hist[5][300];
static unsigned long tx_bytes_snap[5], rx_bytes_snap[5];
static unsigned long tx_bytes_peak[5], rx_bytes_peak[5];
static int bytes_hist_top = -1;

static unsigned long diff22(unsigned long *snapped, unsigned long curr)
{
	unsigned long old = *snapped;

	*snapped = curr;
	if (old > curr)
		return (1 << 22) - old + curr;
	else
		return curr - old;
}

void accumulate_stats22(int port)
{
	struct asic_stats22 *p;
	unsigned long tx_bytes, rx_bytes, tx_diff, rx_diff;
	int poff;

	if (port < 0 || port >= ARRAY_SIZE(stats22))
		return;

	p = &stats22[port];
	poff = port * MIB_ADDROFFSETBYPORT;
	p->in_unicast += diff22(&p->in_unicast_snap, rtl8651_returnAsicCounter(OFFSET_IFINUCASTPKTS_P0 + poff));
	p->in_multicast += diff22(&p->in_multicast_snap, rtl8651_returnAsicCounter(OFFSET_ETHERSTATSMULTICASTPKTS_P0 + poff));
	p->in_broadcast += diff22(&p->in_broadcast_snap, rtl8651_returnAsicCounter(OFFSET_ETHERSTATSBROADCASTPKTS_P0 + poff));

	p->out_unicast += diff22(&p->out_unicast_snap, rtl8651_returnAsicCounter(OFFSET_IFOUTUCASTPKTS_P0 + poff));
	p->out_multicast += diff22(&p->out_multicast_snap, rtl8651_returnAsicCounter(OFFSET_IFOUTMULTICASTPKTS_P0 + poff));
	p->out_broadcast += diff22(&p->out_broadcast_snap, rtl8651_returnAsicCounter(OFFSET_IFOUTBROADCASTPKTS_P0 + poff));

	rx_bytes  = rtl8651_returnAsicCounter(OFFSET_IFINOCTETS_P0 + poff);
	rx_bytes += (rtl8651_returnAsicCounter(OFFSET_IFINOCTETS_P0 + 4 + poff) << 22);
	tx_bytes  = rtl8651_returnAsicCounter(OFFSET_IFOUTOCTETS_P0 + poff) ;
	tx_bytes += (rtl8651_returnAsicCounter(OFFSET_IFOUTOCTETS_P0 + 4 + poff) << 22);
	if (likely(bytes_hist_top >= 0)) {
		rx_diff = rx_bytes - rx_bytes_snap[port];
		tx_diff = tx_bytes - tx_bytes_snap[port];
		rx_bytes_hist[port][bytes_hist_top] = rx_diff;
		tx_bytes_hist[port][bytes_hist_top] = tx_diff;
		if (rx_bytes_peak[port] < rx_diff)
			rx_bytes_peak[port] = rx_diff;
		if (tx_bytes_peak[port] < tx_diff)
			tx_bytes_peak[port] = tx_diff;
	}
	rx_bytes_snap[port] = rx_bytes;
	tx_bytes_snap[port] = tx_bytes;
	if (port == (ARRAY_SIZE(stats22) - 1) &&
	    (++bytes_hist_top >= ARRAY_SIZE(tx_bytes_hist[0])))
		bytes_hist_top = 0;
}

unsigned long get_stats22(int port, int out, int token)
{
	struct asic_stats22 *p;

	if (port >= 0 && port < ARRAY_SIZE(stats22)) {
		p = &stats22[port];
		if (out) {
			switch (token) {
			case 'u':
				return p->out_unicast;
			case 'm':
				return p->out_multicast;
			case 'b':
				return p->out_broadcast;
			}
		} else {
			switch (token) {
			case 'u':
				return p->in_unicast;
			case 'm':
				return p->in_multicast;
			case 'b':
				return p->in_broadcast;
			}
		}
	}
	return 0;
}

void reset_stats22(int port)
{
	if (port >= 0 && port < ARRAY_SIZE(stats22)) {
		memset(&stats22[port], 0, sizeof(stats22[0]));
		rx_bytes_snap[port] = 0;
		tx_bytes_snap[port] = 0;
	}
}

struct pstat_hist_proc_iter {
	unsigned long (*bytes_hist)[300];
	int top, step;
};

static void *pstat_hist_iter_next(struct pstat_hist_proc_iter *it)
{
	return (it->step++ < 300) ? it->bytes_hist : NULL;
}

static void *pstat_hist_proc_seq_start(struct seq_file *s, loff_t *pos)
{
	return pstat_hist_iter_next((struct pstat_hist_proc_iter *)s->private);
}

static void *pstat_hist_proc_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	++*pos;
	return pstat_hist_iter_next((struct pstat_hist_proc_iter *)s->private);
}

static void pstat_hist_proc_seq_stop(struct seq_file *s, void *v)
{
}

static int pstat_hist_proc_seq_show(struct seq_file *s, void *v)
{
	struct pstat_hist_proc_iter *it = (struct pstat_hist_proc_iter *)s->private;
	int pos;
	pos = it->top - it->step;
	if (pos < 0)
		pos = 299;
	seq_printf(s, "%-10lu  %-10lu  %-10lu  %-10lu  %-10lu\n",
		   it->bytes_hist[0][pos],
		   it->bytes_hist[1][pos],
		   it->bytes_hist[2][pos],
		   it->bytes_hist[3][pos],
		   it->bytes_hist[4][pos]);
	return 0;
}

static struct seq_operations pstat_hist_proc_seq_ops = {
	.start = pstat_hist_proc_seq_start,
	.stop = pstat_hist_proc_seq_stop,
	.next = pstat_hist_proc_seq_next,
	.show = pstat_hist_proc_seq_show,
};

static int pstat_hist_proc_open(struct inode *inode, struct file *file)
{
	int rc = -ENOMEM;
	struct pstat_hist_proc_iter *it;

	if (bytes_hist_top < 0)
		return -EAGAIN;

	it = kzalloc(sizeof(*it), GFP_KERNEL);
	if (!it)
		goto out;

	it->bytes_hist = PDE_DATA(inode);
	it->top = bytes_hist_top;
	rc = seq_open(file, &pstat_hist_proc_seq_ops);
	if (rc)
		goto out_kfree;
	((struct seq_file *)file->private_data)->private = it;
 out:
	return rc;
 out_kfree:
	kfree(it);
	goto out;
}

static struct file_operations pstat_hist_proc_fops = {
	.open = pstat_hist_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
};

static int pstat_peak_read_proc(struct seq_file *s, void *v)
{
	unsigned long *p = (unsigned long *)s->private;
	return seq_printf(s, "%-10lu  %-10lu  %-10lu  %-10lu  %-10lu\n",
			p[0], p[1], p[2], p[3], p[4]);
}

static int pstat_peak_open(struct inode *inode, struct file *file)
{
	return single_open(file, pstat_peak_read_proc, PDE_DATA(inode));
}

struct file_operations pstat_peak_proc_fops = {
	.open = pstat_peak_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

struct mib_seq_iter {
	rtl865x_tblAsicDrv_advancedCounterParam_t parm;
	int cp;
	int port, out;
};

static void mib_getstats(int port, int out, rtl865x_tblAsicDrv_advancedCounterParam_t *p)
{
	int poff = port * MIB_ADDROFFSETBYPORT;
	u32 lo, hi;

	if (port < 0 || port > CPU)
		return;

	if (!out) {
		lo = rtl8651_returnAsicCounter(OFFSET_IFINOCTETS_P0 + poff);
		hi = rtl8651_returnAsicCounter(OFFSET_IFINOCTETS_P0 + sizeof(u32) + poff);
		p->ifInOctets = (hi << 22) | (lo & 0x3FFFFF);
		*((u32 *)&p->ifInOctets) = hi >> 10;
		p->ifInUcastPkts = (port < ARRAY_SIZE(stats22)) ?
			get_stats22(port, out, 'u') : rtl8651_returnAsicCounter(OFFSET_IFINUCASTPKTS_P0 + poff);
		p->etherStatsMulticastPkts = (port < ARRAY_SIZE(stats22)) ?
			get_stats22(port, out, 'm') : rtl8651_returnAsicCounter(OFFSET_ETHERSTATSMULTICASTPKTS_P0 + poff);
		p->etherStatsBroadcastPkts = (port < ARRAY_SIZE(stats22)) ?
			get_stats22(port, out, 'b') : rtl8651_returnAsicCounter(OFFSET_ETHERSTATSBROADCASTPKTS_P0 + poff);
		p->etherStatsJabbers = rtl8651_returnAsicCounter(OFFSET_ETHERSTATSJABBERS_P0 + poff);
		p->etherStatsFraments = rtl8651_returnAsicCounter(OFFSET_ETHERSTATSFRAGMEMTS_P0 + poff);
		p->dot3FCSErrors = rtl8651_returnAsicCounter(OFFSET_DOT3STATSFCSERRORS_P0 + poff);
		p->dot3ControlInUnknownOpcodes = rtl8651_returnAsicCounter(OFFSET_DOT3CONTROLINUNKNOWNOPCODES_P0 + poff);
		p->dot3InPauseFrames = rtl8651_returnAsicCounter(OFFSET_DOT3INPAUSEFRAMES_P0 + poff);
		p->etherStatsUndersizePkts = rtl8651_returnAsicCounter(OFFSET_ETHERSTATSUNDERSIZEPKTS_P0 + poff);
		p->etherStatsPkts64Octets = rtl8651_returnAsicCounter(OFFSET_ETHERSTATSPKTS64OCTETS_P0 + poff);
		p->etherStatsPkts65to127Octets = rtl8651_returnAsicCounter(OFFSET_ETHERSTATSPKTS65TO127OCTETS_P0 + poff);
		p->etherStatsPkts128to255Octets = rtl8651_returnAsicCounter(OFFSET_ETHERSTATSPKTS128TO255OCTETS_P0 + poff);
		p->etherStatsPkts256to511Octets = rtl8651_returnAsicCounter(OFFSET_ETHERSTATSPKTS256TO511OCTETS_P0 + poff);
		p->etherStatsPkts512to1023Octets = rtl8651_returnAsicCounter(OFFSET_ETHERSTATSPKTS512TO1023OCTETS_P0 + poff);
		p->etherStatsPkts1024to1518Octets = rtl8651_returnAsicCounter(OFFSET_ETHERSTATSPKTS1024TO1518OCTETS_P0 + poff);
		p->etherStatsOversizePkts = rtl8651_returnAsicCounter(OFFSET_ETHERSTATSOVERSIZEPKTS_P0 + poff);
	} else {
		lo = rtl8651_returnAsicCounter(OFFSET_IFOUTOCTETS_P0 + poff);
		hi = rtl8651_returnAsicCounter(OFFSET_IFOUTOCTETS_P0 + sizeof(u32) + poff);
		p->ifOutOctets = (hi << 22) | (lo & 0x3FFFFF);
		*((u32 *)&p->ifOutOctets) = hi >> 10;
		p->ifOutUcastPkts = (port < ARRAY_SIZE(stats22)) ?
			get_stats22(port, out, 'u') : rtl8651_returnAsicCounter(OFFSET_IFOUTUCASTPKTS_P0 + poff);
		p->ifOutMulticastPkts = (port < ARRAY_SIZE(stats22)) ?
			get_stats22(port, out, 'm') : rtl8651_returnAsicCounter(OFFSET_IFOUTMULTICASTPKTS_P0 + poff);
		p->ifOutBroadcastPkts = (port < ARRAY_SIZE(stats22)) ?
			get_stats22(port, out, 'b') : rtl8651_returnAsicCounter(OFFSET_IFOUTBROADCASTPKTS_P0 + poff);
		p->ifOutDiscards = rtl8651_returnAsicCounter(OFFSET_IFOUTDISCARDS + poff);
		p->dot3StatsDefferedTransmissions = rtl8651_returnAsicCounter(OFFSET_DOT3STATSDEFERREDTRANSMISSIONS_P0 + poff);
		p->dot3OutPauseFrames = rtl8651_returnAsicCounter(OFFSET_DOT3OUTPAUSEFRAMES_P0 + poff);
		p->etherStatsCollisions = rtl8651_returnAsicCounter(OFFSET_ETHERSTATSCOLLISIONS_P0 + poff);
		p->dot3StatsSingleCollisionFrames = rtl8651_returnAsicCounter(OFFSET_DOT3STATSSINGLECOLLISIONFRAMES_P0 + poff);
		p->dot3StatsMultipleCollisionFrames =
		    rtl8651_returnAsicCounter(OFFSET_DOT3STATSMULTIPLECOLLISIONFRAMES_P0 + poff);
		p->dot3StatsLateCollisions = rtl8651_returnAsicCounter(OFFSET_DOT3STATSLATECOLLISIONS_P0 + poff);
		p->dot3StatsExcessiveCollisions = rtl8651_returnAsicCounter(OFFSET_DOT3STATSEXCESSIVECOLLISIONS_P0 + poff);
	}
}

static void *mib_iter_next(struct mib_seq_iter *it)
{
	while (it->cp < (2 * 9)) {
		it->out = it->cp / 9;
		it->port = it->cp % 9;
		it->cp++;
		switch (it->port) {
		case 5:
		case 7:
		case 8:
			continue;
		default:
			break;
		}
		memset(&it->parm, 0, sizeof(it->parm));
		mib_getstats(it->port, it->out, &it->parm);
		return (void *)&it->parm;
	}
	return NULL;
}

static void *mib_seq_seq_start(struct seq_file *m, loff_t *pos)
{
	struct mib_seq_iter *it = (struct mib_seq_iter *)m->private;
	return (*pos) ? mib_iter_next(it) : SEQ_START_TOKEN;
}

static void *mib_seq_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct mib_seq_iter *it = (struct mib_seq_iter *)m->private;
	++*pos;
	return mib_iter_next(it);
}

static void mib_seq_seq_stop(struct seq_file *m, void *v)
{
}

static int mib_seq_seq_show(struct seq_file *m, void *v)
{
	struct mib_seq_iter *it = (struct mib_seq_iter *)m->private;
	char port[12];

	if (v == SEQ_START_TOKEN) {
		seq_printf(m, " |       Receive\n");
		seq_printf(m, "P|        octets    unicast  multicast  broadcast  jab-error "
			   "frag-error  FCS error unknown-op pause >64/=64/<128/<256/<512/<1024/<1518/>=1518\n");
	} else {
		if (it->port < 5)
			sprintf(port, "%d", it->port);
		else
			strcpy(port, "E");
		if (!it->out) {
			seq_printf(m, "%s: %13llu %10u %10u %10u %10u %10u %10u %10u %5u %u/%u/%u/%u/%u/%u/%u/%u\n",
				   port,
				   it->parm.ifInOctets,
				   it->parm.ifInUcastPkts,
				   it->parm.etherStatsMulticastPkts,
				   it->parm.etherStatsBroadcastPkts,
				   it->parm.etherStatsJabbers,
				   it->parm.etherStatsFraments,
				   it->parm.dot3FCSErrors,
				   it->parm.dot3ControlInUnknownOpcodes,
				   it->parm.dot3InPauseFrames,
				   it->parm.etherStatsUndersizePkts,
				   it->parm.etherStatsPkts64Octets,
				   it->parm.etherStatsPkts65to127Octets,
				   it->parm.etherStatsPkts128to255Octets,
				   it->parm.etherStatsPkts256to511Octets,
				   it->parm.etherStatsPkts512to1023Octets,
				   it->parm.etherStatsPkts1024to1518Octets,
				   it->parm.etherStatsOversizePkts);
		} else {
			if (it->port == 0) {
				seq_printf(m, "\n |      Transmit\n");
				seq_printf(m, "P|        octets    unicast  multicast  broadcast   "
					   "discards    defered      pause  collision single/multiple/late/excessive-collision\n");
			}

			seq_printf(m, "%s: %13llu %10u %10u %10u %10u %10u %10u %10u %u/%u/%u/%u\n",
				   port,
				   it->parm.ifOutOctets,
				   it->parm.ifOutUcastPkts,
				   it->parm.ifOutMulticastPkts,
				   it->parm.ifOutBroadcastPkts,
				   it->parm.ifOutDiscards,
				   it->parm.dot3StatsDefferedTransmissions,
				   it->parm.dot3OutPauseFrames,
				   it->parm.etherStatsCollisions,
				   it->parm.dot3StatsSingleCollisionFrames,
				   it->parm.dot3StatsMultipleCollisionFrames,
				   it->parm.dot3StatsLateCollisions,
				   it->parm.dot3StatsExcessiveCollisions);

			if (port[0] == 'E') {
				seq_printf(m, "whole system counters\n");
				seq_printf(m, "  cpu_event_pkts %u\n", rtl8651_returnAsicCounter(OFFSET_ETHERSTATSCPUEVENTPKT));
			}
		}
	}
	return 0;
}

static struct seq_operations mib_seq_seq_ops = {
	.start = mib_seq_seq_start,
	.stop = mib_seq_seq_stop,
	.next = mib_seq_seq_next,
	.show = mib_seq_seq_show,
};

static int mib_seq_open(struct inode *inode, struct file *file)
{
	int rc = -ENOMEM;
	struct mib_seq_iter *it = kzalloc(sizeof(*it), GFP_KERNEL);

	if (!it)
		goto out;
	rc = seq_open(file, &mib_seq_seq_ops);
	if (rc)
		goto out_kfree;
	((struct seq_file *)file->private_data)->private = it;
 out:
	return rc;
 out_kfree:
	kfree(it);
	goto out;
}

static struct file_operations mib_seq_fops = {
	.open = mib_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
};

struct file_operations dv_igmp_query_to_lan_proc_fops = {
	.open = dv_igmp_query_to_lan_open,
	.write = dv_igmp_query_to_lan_write,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

struct file_operations dv_igmp_query_received_proc_fops = {
	.open = dv_igmp_query_received_open,
	.write = dv_igmp_query_received_write,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

#if defined(__DV_IGMP_FILTER__)
struct file_operations dv_igmp_block_proc_fops = {
	.open = dv_igmp_block_open,
	.write = dv_igmp_block_write,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#endif

static struct file_operations mc_proc_fops = {
	.open = mc_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
};

#else
static int davo_igmp_query_to_lan_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	if (*eof)
		return 0;
	*eof = 1;
	return sprintf(page, "%d\n", igmp_query_only_to_lan);
}

static int davo_igmp_query_to_lan_write(struct file *filp, const char *buff, unsigned long len, void *data)
{
	char tmp[32];
	if (strtrim_from_user(tmp, sizeof(tmp), buff, len) > 0)
		igmp_query_only_to_lan = !!simple_strtoul(tmp, NULL, 0);
	return len;
}

static int davo_igmp_query_received_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	if (*eof)
		return 0;
	*eof = 1;
	return sprintf(page, "%d\n", igmp_query_received);
}

static int davo_igmp_query_received_write(struct file *filp, const char *buff, unsigned long len, void *data)
{
	char tmp[32];
	if (strtrim_from_user(tmp, sizeof(tmp), buff, len) > 0)
		igmp_query_received = !!simple_strtoul(tmp, NULL, 0);
	return len;
}

#if defined(__DV_IGMP_FILTER__)
static int davo_igmp_block_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int len = 0;
	int i;

	len += sprintf(page + len, "%d\n", igmp_block_enable);
	for (i = 1; i < 5; i++) {
		len += sprintf(page + len, "%d %d %lu %lu %lu\n",
			       igmp_stat[i].igmp_blocked, igmp_stat[i].igmp_blocked_period / HZ,
			       igmp_stat[i].igmp_thresh_hold, igmp_stat[i].igmp_rx,
			       igmp_stat[i].igmp_drop);
	}

	if (len <= off + count)
		*eof = 1;

	*start = page + off;
	len -= off;

	if (len > count)
		len = count;

	if (len < 0)
		len = 0;

	return len;
}

static int davo_igmp_block_write(struct file *filp, const char *buff, unsigned long len, void *data)
{
	char rcvbuf[32];
	int opcode, enable, thresh, period;
	int i, index = 0;

	memset(rcvbuf, 0, sizeof(rcvbuf));
	if (strtrim_from_user(rcvbuf, sizeof(rcvbuf), buff, len)) {
		index += sscanf(rcvbuf + index, "%d", &opcode);
		if (opcode == 1) {
			index += sscanf(rcvbuf + index, "%d %d %d", &igmp_block_enable, &thresh, &period);
			printk("IGMP Block Control %s: Threadhold %d pps, Block period %d sec\n",
			       igmp_block_enable ? "Enabled" : "Disabled", thresh, period);
			for (i = 1; i < 5; i++) {
				igmp_stat[i].igmp_thresh_hold = thresh;
				igmp_stat[i].igmp_blocked_period = period * HZ;
			}
		} else if (opcode == 2) {
			for (i = 1; (i < 5) && (index < len); i++) {
				while (*(rcvbuf + index) == ' ')
					index++;
				index += sscanf(rcvbuf + index, "%d ", &enable);
				printk("LAN%d: %s\n", i, enable ? "Blocked" : "Unblocked");
				igmp_stat[i].igmp_blocked = enable;
			}
		} else {
			printk("Unkown opcode[%d]\n", opcode);
		}
	}
	return len;
}
#endif
#endif
#endif

#ifndef CONFIG_RTL_PROC_NEW
static struct proc_dir_entry *igmp_proc = NULL;
#else
extern struct proc_dir_entry proc_root;
#endif

void davo_proc_init(void)
{
	dv_qos_init();
#if defined (CONFIG_RTL_IGMP_SNOOPING)
/* jihyun@davo 150614 jcode#1 */
#ifdef CONFIG_RTL_PROC_NEW
	proc_create_data("dv_igmp_query_to_lan", 0, &proc_root, &dv_igmp_query_to_lan_proc_fops, NULL);
	proc_create_data("dv_igmp_query_received", 0, &proc_root, &dv_igmp_query_received_proc_fops, NULL);
#if defined(__DV_IGMP_FILTER__)
	proc_create_data("dv_igmp_block", 0, &proc_root, &dv_igmp_block_proc_fops, NULL);
#endif
	proc_create_data("n_multicast", 0, &proc_root, &mc_proc_fops, NULL);

	proc_create_data("asicCounter", 0, &proc_root, &mib_seq_fops, NULL);
	proc_create_data("tx_hist", 0, &proc_root, &pstat_hist_proc_fops, tx_bytes_hist);
	proc_create_data("rx_hist", 0, &proc_root, &pstat_hist_proc_fops, rx_bytes_hist);
	proc_create_data("tx_hist_peak", 0, &proc_root, &pstat_peak_proc_fops, tx_bytes_peak);
	proc_create_data("rx_hist_peak", 0, &proc_root, &pstat_peak_proc_fops, rx_bytes_peak);
#else

	igmp_proc = create_proc_entry("dv_igmp_query_to_lan", 0, NULL);
	if (igmp_proc != NULL) {
		igmp_proc->read_proc = davo_igmp_query_to_lan_read;
		igmp_proc->write_proc = davo_igmp_query_to_lan_write;
	}

	igmp_proc = create_proc_entry("dv_igmp_query_received", 0, NULL);
	if (igmp_proc != NULL) {
		igmp_proc->read_proc = davo_igmp_query_received_read;
		igmp_proc->write_proc = davo_igmp_query_received_write;
	}
#if defined(__DV_IGMP_FILTER__)
	igmp_proc = create_proc_entry("dv_igmp_block", 0, NULL);
	if (igmp_proc != NULL) {
		igmp_proc->read_proc = davo_igmp_block_read;
		igmp_proc->write_proc = davo_igmp_block_write;
	}
#endif
#endif
#endif
}

void davo_proc_exit(void)
{
	dv_qos_exit();

#if defined (CONFIG_RTL_IGMP_SNOOPING)
/* jihyun@davo 150614 jcode#1 */
#ifdef CONFIG_RTL_PROC_NEW
	remove_proc_entry("dv_igmp_query_to_lan", &proc_root);
	remove_proc_entry("dv_igmp_query_received", &proc_root);
#if defined(__DV_IGMP_FILTER__)
	remove_proc_entry("dv_igmp_block", &proc_root);
#endif
#else
	remove_proc_entry("dv_igmp_query_to_lan", NULL);
	remove_proc_entry("dv_igmp_query_to_lan", NULL);
#if defined(__DV_IGMP_FILTER__)
	remove_proc_entry("dv_igmp_block", NULL);
#endif
#endif
#endif
}

int force_reserveTime_expired(void)
{
	struct nat_table *nat_tbl = (struct nat_table *)0x81b89fd8;
	struct nat_entry *p = nat_tbl->nat_bucket;
	int i;

	for (i = 0; i < RTL8651_TCPUDPTBL_SIZE; i++, p++)
		if (p->flags & NAT_PRE_RESERVED)
			p->reserveTime = jiffies - (RESERVE_EXPIRE_TIME * HZ) - HZ;
	return 0;
}
EXPORT_SYMBOL(force_reserveTime_expired);

unsigned int getAsicNaptHashScore(rtl865x_napt_entry *naptEntry)
{
	rtl865x_naptHashInfo_t naptHashInfo;
	int (* _rtl865x_getNaptHashInfo)(rtl865x_napt_entry *, rtl865x_naptHashInfo_t *) = (void *)0x802a4d78;

	_rtl865x_getNaptHashInfo(naptEntry, &naptHashInfo);
	if (naptHashInfo.inCollision == FALSE) {
		if (naptHashInfo.inFreeCnt == 4) {
			if (!naptHashInfo.sameFourWay)
				return 100;
			else if (!naptHashInfo.sameLocation)
				return 80;
		} else if (naptHashInfo.inFreeCnt == 3) {
			if (!naptHashInfo.sameFourWay)
				return 80;
			else if (!naptHashInfo.sameLocation)
				return 70;
		} else if (naptHashInfo.inFreeCnt == 2) {
			if (!naptHashInfo.sameFourWay)
				return 70;
			else if (!naptHashInfo.sameLocation)
				return 60;
		} else if (naptHashInfo.inFreeCnt == 1) {
			if (naptHashInfo.sameFourWay == FALSE)
				return 60;
		}
	}
	return 0;
}
EXPORT_SYMBOL(getAsicNaptHashScore);
