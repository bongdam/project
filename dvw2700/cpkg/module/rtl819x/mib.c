#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/sysctl.h>
#include <linux/delay.h>
#include <linux/ctype.h>

#include <net/rtl/rtl_types.h>
#include <net/rtl/rtl_glue.h>
#include <net/rtl/rtl865x_netif.h>
#include "common/rtl865x_netif_local.h"
#include "common/rtl865x_eventMgr.h"
#include "common/rtl_utils.h"
#include "AsicDriver/asicRegs.h"
#include "AsicDriver/rtl865x_asicBasic.h"
#include "AsicDriver/rtl865x_asicCom.h"
#include "AsicDriver/rtl865x_asicL2.h"

extern struct proc_dir_entry proc_root;

struct asic_stats22 {
	u64 in_unicast;
	u64 in_multicast;
	u64 in_broadcast;
	u64 out_unicast;
	u64 out_multicast;
	u64 out_broadcast;

	unsigned long in_unicast_snap;
	unsigned long in_multicast_snap;
	unsigned long in_broadcast_snap;
	unsigned long out_unicast_snap;
	unsigned long out_multicast_snap;
	unsigned long out_broadcast_snap;
};

static struct asic_stats22 stats22[5];

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
}

u64 get_stats22(int port, int out, int token)
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
	if (port >= 0 && port < ARRAY_SIZE(stats22))
		memset(&stats22[port], 0, sizeof(stats22[0]));
}

struct mib_seq_iter {
	rtl865x_tblAsicDrv_advancedCounterParam_t parm;
	int cp;
	int port, out;
};

/* 2^44 = 17TB (Wraparound occurs after 16 days with constant 100mbps */
static u64 counter44(int poff)
{
	u64 lo, hi;
	lo = rtl8651_returnAsicCounter(poff);
	hi = rtl8651_returnAsicCounter(poff + sizeof(u32));
	return (hi << 22) | (lo & 0x3FFFFF);
}

static void mib_getstats(int port, int out, rtl865x_tblAsicDrv_advancedCounterParam_t *p)
{
	int poff = port * MIB_ADDROFFSETBYPORT;

	if (port < 0 || port > CPU)
		return;

	if (!out) {
		p->ifInOctets = counter44(OFFSET_IFINOCTETS_P0 + poff);
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
		p->ifOutOctets = counter44(OFFSET_IFOUTOCTETS_P0 + poff);
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
			   "frag-error  FCS error unknown-op pause <64/=64/<128/<256/<512/<1024/<1518/>=1518\n");
	} else {
		if (it->port < 5)
			sprintf(port, "%d", it->port);
		else
			strcpy(port, "C");
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

			if (port[0] == 'C') {
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

int mib_procfs_init(void)
{
	return proc_create_data("asicCounter", 0, &proc_root, &mib_seq_fops, NULL) ? 0 : -1;
}

void mib_procfs_exit(void)
{
	remove_proc_entry("asicCounter", &proc_root);
}
