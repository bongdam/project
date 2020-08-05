/*
 *      Modification from Davolink
 *
 *      For SKBB BMT: 2012.08
 */

# include <linux/module.h>
# include <linux/kernel.h>
# include <linux/proc_fs.h>
# include <linux/netdevice.h>
# include <linux/init.h>
# include <linux/if_ether.h>
# include <linux/ip.h>
# include <net/ip.h>
# include <net/udp.h>
# include <net/tcp.h>
# include <net/icmp.h>
# include <net/route.h>
/* jihyun@davo160202 jcode#7 -*/
# include <net/iw_handler.h>
//+
# include <linux/netdevice.h>
# include <linux/ctype.h>

#ifdef __DRAYTEK_OS__
# include <draytek/wl_dev.h>
#endif

#include "./8192cd_cfg.h"
#include "./8192cd.h"
#include "./8192cd_hw.h"
#include "./8192cd_headers.h"
#include "./8192cd_debug.h"

#ifndef __KERNEL__
# include "./sys-support.h"
#endif

#ifdef RTL8190_VARIABLE_USED_DMEM
# include "./8192cd_dmem.h"
#endif

#include "8192cd_davo_wlan.h"

#include "dv_wlist.h"
#include <dvflag.h>

/*--------------------------------------------------------------------------*/
#ifndef __DAVO__
# error __DAVO__ is not defined!!
#endif

#define WME_MODE_STR 	"wme_mode"
#define WME_1P_STR 		"wme_1p"
#define WME_DSCP_STR 	"wme_dscp"
#define WME_DSCP6_STR 	"wme_dscp6"
#define DV_RATE_LIMIT_STR 	"dv_rate_limit"
#define DV_RATE_MEASURE_STR "dv_rate_measure"
#define CONNECT_COUNT_STR "connect_count"
#define AUTO_BONDING_STR "auto_bonding"

#ifndef MIN
# define MIN(a, b)   ((a) < (b) ? (a) : (b))
#endif

# define ALL_ZERO(a,b) (((a)==0)&&((b)==0))
# define U4 unsigned long
# define TIME_DIFF(n,b) ((U4)(n) >= (U4)(b)) ? ((U4)(n) - (U4)(b)): (((U4)0xffffffff)-(U4)(b)+1+((U4)(n)))

LIST_HEAD(pf_rx_chains);
LIST_HEAD(pf_tx_chains);

static void pf_register_all(void);
static void pf_unregister_all(void);
static int get_mssid_idx_from_name(char *name);
static char *ascminute(unsigned int min, char *buf);
static unsigned int sum_stainfo(struct rtl8192cd_priv *priv);

//#ifdef DAVO_MAC_RESTRICT_FOR_AGING_TEST
static signed char pf_registered = 0;
//#endif
static unsigned char eng = 0;

static int g_davo_auto_bonding[2];
/***************************/
// SKB : DSCP<->AC
//       0  <-> AC_BK
//       24 <-> AC_BE
//       32 <-> AC_VI
//       46 <-> AC_VO


static struct dv_priv_t dv_priv[2] = {
	{
		.wlan_proc = NULL,
#if defined(DAVO_ENABLE_WME_OVERRIDE)
		.wme_override = DAVO_WME_OVERRIDE_DSCP,
		.rule_802_1p = {0, 1, 2, 3, 4, 5, 6, 7},
		.rule_dscp = {
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1,
			2, 2, 2, 2, 2, 2, 2, 2,
			3, 3, 3, 3, 3, 3, 3, 3,
			4, 4, 4, 4, 4, 4, 4, 4,
			6, 6, 6, 6, 6, 6, 6, 6,
			6, 6, 6, 6, 6, 6, 6, 6,
			7, 7, 7, 7, 7, 7, 7, 7
		},
		.rule_dscp6 = {
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1,
			2, 2, 2, 2, 2, 2, 2, 2,
			3, 3, 3, 3, 3, 3, 3, 3,
			4, 4, 4, 4, 4, 4, 4, 4,
			6, 6, 6, 6, 6, 6, 6, 6,
			6, 6, 6, 6, 6, 6, 6, 6,
			7, 7, 7, 7, 7, 7, 7, 7
		},
#endif
	},
	{
		.wlan_proc = NULL,
#if defined(DAVO_ENABLE_WME_OVERRIDE)
		.wme_override = DAVO_WME_OVERRIDE_DSCP,
		.rule_802_1p = {0, 1, 2, 3, 4, 5, 6, 7},
		.rule_dscp = {
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1,
			2, 2, 2, 2, 2, 2, 2, 2,
			3, 3, 3, 3, 3, 3, 3, 3,
			4, 4, 4, 4, 4, 4, 4, 4,
			6, 6, 6, 6, 6, 6, 6, 6,
			6, 6, 6, 6, 6, 6, 6, 6,
			7, 7, 7, 7, 7, 7, 7, 7
		},
		.rule_dscp6 = {
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1,
			2, 2, 2, 2, 2, 2, 2, 2,
			3, 3, 3, 3, 3, 3, 3, 3,
			4, 4, 4, 4, 4, 4, 4, 4,
			6, 6, 6, 6, 6, 6, 6, 6,
			6, 6, 6, 6, 6, 6, 6, 6,
			7, 7, 7, 7, 7, 7, 7, 7
		},
#endif
	}
};

/*--------------------------------------------------------------------------*/
/*
 * Local Functions
 */
/*--------------------------------------------------------------------------*/

static char *go_to_first_digit(char *p, char *end);

/*******************************/

#define get_radioid_from_priv(a) (a)->pshare->wlandev_idx>1?0:(a)->pshare->wlandev_idx

#if defined(DAVO_ENABLE_WME_OVERRIDE)

static int dv_wme_mode_show(struct seq_file *s, void *data)
{
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv *)(s->private);
	int idx;

	idx = get_radioid_from_priv(priv);

	if (dv_priv[idx].wme_override == DAVO_WME_OVERRIDE_DISABLE) {
		seq_printf(s, "%d: disabled\n", dv_priv[idx].wme_override);
	} else if (dv_priv[idx].wme_override == DAVO_WME_OVERRIDE_802_1P) {
		seq_printf(s, "%d: 802.1p VLAN Tag priority\n", dv_priv[idx].wme_override);
	} else if (dv_priv[idx].wme_override == DAVO_WME_OVERRIDE_DSCP) {
		seq_printf(s, "%d: IP DSCP priority\n", dv_priv[idx].wme_override);
	} else {
		seq_printf(s, "%d: unsupported\n", dv_priv[idx].wme_override);
	}

	seq_printf(s, "acl_count tx=%d,rx=%d\n", dv_priv[idx].my_acl_count[0], dv_priv[idx].my_acl_count[1]);

	return 0;
}

static int dv_wme_mode_open(struct inode *inode, struct file *file)
{
	return single_open(file, dv_wme_mode_show, PDE_DATA(file_inode(file)));
}

static int dv_wme_mode_write_real(struct file *file, const char *buffer,
				unsigned long count, void *data)
{
	int idx, len, v;
	char buf[1016], *p;
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv *)data;

	len = strtrim_from_user(buf, sizeof(buf), buffer, count);
	if (len > 0) {
		p = go_to_first_digit(buf, &buf[len]);
		if (p == NULL) {
			printk("error: cannot find digit\n");
			return count;
		}
		v = simple_strtoul(p, NULL, 10);
		if (v >= DAVO_WME_OVERRIDE_DISABLE && v <= DAVO_WME_OVERRIDE_DSCP) {
			idx = get_radioid_from_priv(priv);
			dv_priv[idx].wme_override = v;
		} else
			printk("%s error: unsupported mode", __FUNCTION__);
	}

	return count;
}

static ssize_t dv_wme_mode_write(struct file * file, const char __user * userbuf, size_t count, loff_t * off)
{
	return dv_wme_mode_write_real(file, userbuf, count, PDE_DATA(file_inode(file)));
}

struct file_operations dv_wme_mode_fops = {
	.open			= dv_wme_mode_open,
	.read			= seq_read,
	.write			= dv_wme_mode_write,
	.llseek 		= seq_lseek,
	.release		= single_release
};


/***********************************/
static int dv_wme_1p_show(struct seq_file *s, void *data)
{
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv *)(s->private);
	int idx;

	unsigned char *a;

	idx = get_radioid_from_priv(priv);

	a = dv_priv[idx].rule_802_1p;
	seq_printf(s, "PRI[0 - 7]: %2d %2d %2d %2d %2d %2d %2d %2d\n",
			a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);

	return 0;
}

static int dv_wme_1p_open(struct inode *inode, struct file *file)
{
	return single_open(file, dv_wme_1p_show, PDE_DATA(file_inode(file)));
}

static int dv_wme_1p_write_real(struct file *file, const char *buffer,
				unsigned long count, void *data)
{
	int idx, len, n, v;
	char buf[512], *p;
	unsigned char *a;
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv *)data;

	len = strtrim_from_user(buf, sizeof(buf), buffer, count);
	if (len > 0) {
		p = go_to_first_digit(buf, &buf[len]);
		if (p == NULL) {
			printk("error: cannot find digit\n");
			return (count);
		}
		idx = get_radioid_from_priv(priv);
		a = dv_priv[idx].rule_802_1p;
		n = simple_strtoul(p, &p, 10);
		while ((p = go_to_first_digit(p, &buf[len])) != NULL) {
			v = simple_strtoul(p, &p, 10);
			if (n >= 0 && v >= 0 && v <= 7) {
				if (n < DAVO_WME_RULE_SIZE_802_1P) {
					a[n] = v;
				}
			}
			n += 1;
		}
	}
	return count;
}

static ssize_t dv_wme_1p_write(struct file * file, const char __user * userbuf, size_t count, loff_t * off)
{
	return dv_wme_1p_write_real(file, userbuf, count, PDE_DATA(file_inode(file)));
}

struct file_operations dv_wme_1p_fops = {
	.open			= dv_wme_1p_open,
	.read			= seq_read,
	.write			= dv_wme_1p_write,
	.llseek 		= seq_lseek,
	.release		= single_release
};

/***********************************/
static int _dv_wme_dscp_show(struct seq_file *s,  unsigned char *rule)
{
	int i;
	for (i = 0; i < DAVO_WME_RULE_SIZE_DSCP; i += 8) {
		seq_printf(s, "DSCP[%2d - %2d]: %2d %2d %2d %2d %2d %2d %2d %2d\n",
				i, i + 7,
				rule[i + 0], rule[i + 1], rule[i + 2], rule[i + 3], rule[i + 4], rule[i + 5], rule[i + 6], rule[i + 7]);
	}
	return 0;
}

static int _dv_wme_dscp_write_real(unsigned char *rule, char *buffer, int len)
{
	char *p;
	int n, v;

	p = buffer;
	p = go_to_first_digit(p, (char *)buffer + len);

	n = simple_strtoul(p, &p, 10);
	while ((p = go_to_first_digit(p, (char *)buffer + len)) != NULL) {
		v = simple_strtoul(p, &p, 10);
		if (n >= 0 && v >= 0 && v <= 7) {
			if (n < DAVO_WME_RULE_SIZE_DSCP) {
				rule[n] = v;
			}
		}
		n += 1;
	}
	return len;
}

static int dv_wme_dscp_show(struct seq_file *s, void *data)
{
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv *)(s->private);
	int idx;

	unsigned char *a;

	idx = get_radioid_from_priv(priv);

	a = dv_priv[idx].rule_dscp;

	return _dv_wme_dscp_show(s, a);
}

static int dv_wme_dscp_open(struct inode *inode, struct file *file)
{
	return single_open(file, dv_wme_dscp_show, PDE_DATA(file_inode(file)));
}

static int dv_wme_dscp_write_real(struct file *file, const char *buffer,
				unsigned long count, void *data)
{
	int idx, len;
	unsigned char buf[1016] = {0};
	unsigned char *a;
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv *)data;

	len = MIN(count, sizeof(buf));
	idx = get_radioid_from_priv(priv);

	if (count > sizeof(buf)) {
		printk("error: too big %ld\n", count);
		return (count);
	}

	if (copy_from_user(buf, buffer, count)) {
		printk("error: copy_from_user %ld\n", count);
		return (count);
	}

	a = dv_priv[idx].rule_dscp;
	_dv_wme_dscp_write_real(a, buf, len);
	return (count);
}

static ssize_t dv_wme_dscp_write(struct file * file, const char __user * userbuf, size_t count, loff_t * off)
{
	return dv_wme_dscp_write_real(file, userbuf, count, PDE_DATA(file_inode(file)));
}

struct file_operations dv_wme_dscp_fops = {
	.open			= dv_wme_dscp_open,
	.read			= seq_read,
	.write			= dv_wme_dscp_write,
	.llseek 		= seq_lseek,
	.release		= single_release
};
/*******************************/
static int dv_wme_dscp6_show(struct seq_file *s, void *data)
{
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv *)(s->private);
	int idx;

	unsigned char *a;

	idx = get_radioid_from_priv(priv);

	a = dv_priv[idx].rule_dscp6;

	return _dv_wme_dscp_show(s, a);
}

static int dv_wme_dscp6_open(struct inode *inode, struct file *file)
{
	return single_open(file, dv_wme_dscp6_show, PDE_DATA(file_inode(file)));
}

static int dv_wme_dscp6_write_real(struct file *file, const char *buffer,
				unsigned long count, void *data)
{
	int idx, len;
	unsigned char buf[1016] = {0};
	unsigned char *a;
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv *)data;

	len = MIN(count, sizeof(buf));
	idx = get_radioid_from_priv(priv);

	if (count > sizeof(buf)) {
		printk("error: too big %ld\n", count);
		return (count);
	}

	if (copy_from_user(buf, buffer, count)) {
		printk("error: copy_from_user %ld\n", count);
		return (count);
	}

	a = dv_priv[idx].rule_dscp6;
	_dv_wme_dscp_write_real(a, buf, len);
	return (count);
}

static ssize_t dv_wme_dscp6_write(struct file * file, const char __user * userbuf, size_t count, loff_t * off)
{
	return dv_wme_dscp6_write_real(file, userbuf, count, PDE_DATA(file_inode(file)));
}

struct file_operations dv_wme_dscp6_fops = {
	.open			= dv_wme_dscp6_open,
	.read			= seq_read,
	.write			= dv_wme_dscp6_write,
	.llseek 		= seq_lseek,
	.release		= single_release
};

#endif

/*******************************/
#if defined(DAVO_ENABLE_RATELIMIT)
static inline void dv_rate_clear(struct dv_rate_t *dv_rate);

static int dv_rate_limit_show(struct seq_file *s, void *data)
{
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv *)(s->private);
	int idx, i;
	struct dv_priv_mssid_t *mssid;
	dv_ratelimit_ctrl_t *limit_f, *limit_t;

	idx = get_radioid_from_priv(priv);
	for (i = 0; i < MAX_INTF; i++) {
		mssid = &dv_priv[idx].mssid[i];
		limit_f = &mssid->ratelimit[FROM_INTF];
		limit_t = &mssid->ratelimit[TO_INTF];
		if (!eng) {
			seq_printf(s, "[%12s] index(%d) s[f %lu/%lu  t %lu/%lu]  c[f %lu/%ld  t %lu/%ld]\n",
					mssid->name,
					i,
					limit_f->intvl_jiffies ? limit_f->quota_bytes * 8 * HZ / limit_f->intvl_jiffies : 0,	// preset bps
					limit_f->intvl_jiffies * 1000 / HZ,
					limit_t->intvl_jiffies ? limit_t->quota_bytes * 8 * HZ / limit_t->intvl_jiffies : 0,	// preset bps
					limit_t->intvl_jiffies * 1000 / HZ,
					limit_f->intvl_jiffies ? limit_f->last_bytes * 8 * HZ / limit_f->intvl_jiffies : 0,	// current bps
					time_after_eq(jiffies, limit_f->due_jiffies) ? -1 : TIME_DIFF(limit_f->due_jiffies, jiffies) * 1000 / HZ,
					limit_t->intvl_jiffies ? limit_t->last_bytes * 8 * HZ / limit_t->intvl_jiffies : 0,	// current bps
					time_after_eq(jiffies, limit_t->intvl_jiffies) ? -1 : TIME_DIFF(limit_t->due_jiffies, jiffies) * 1000 / HZ);
		} else {
			seq_printf(s, "[%s] %d s[f %lu/%lu  t %lu/%lu m %lu/%lu]  c[f %lu/%ld  t %lu/%ld]\n",
					mssid->name,
					i,
					limit_f->quota_bytes,	// preset bps
					limit_f->intvl_jiffies,
					limit_t->quota_bytes,	// preset bps
					limit_t->intvl_jiffies,
					limit_f->peak_bytes,
					limit_t->peak_bytes,
					limit_f->last_bytes,	// current bps
					time_after_eq(limit_f->due_jiffies, jiffies) ? -1 : TIME_DIFF(jiffies, limit_f->due_jiffies),
					limit_t->last_bytes,	// current bps
					time_after_eq(jiffies, limit_t->due_jiffies) ? -1 : TIME_DIFF(limit_f->due_jiffies, jiffies));
		}
	}
	seq_printf(s, "burst [%d] msec\n", get_BURST_WIN());
	return 0;
}

static int dv_rate_limit_open(struct inode *inode, struct file *file)
{
	return single_open(file, dv_rate_limit_show, PDE_DATA(file_inode(file)));
}

void dv_ratelimit_set(struct dv_priv_mssid_t *mssid, int to_intf, unsigned int avg_bytes,
		unsigned int intv, unsigned int max_bytes)
{
	mssid->ratelimit_enable[to_intf] = 1;
	dv_ratelimit_set_ctrl(&mssid->ratelimit[to_intf], avg_bytes, max_bytes, intv);
}

void dv_ratelimit_unset(struct dv_priv_mssid_t *mssid, int to_intf)
{
	mssid->ratelimit_enable[to_intf] = 0;
	dv_ratelimit_set_ctrl(&mssid->ratelimit[to_intf], 0, 0, 0);
}

int dv_set_rate_limit_info(struct rtl8192cd_priv *priv, char *s)
{
	int idx, mssid_idx;
	struct dv_priv_mssid_t *mssid;
	char *argv[8];
	int ac;
	int to_intf = -1;
	unsigned int max_bytes = 0;
	unsigned int avg_bytes = 0;
	unsigned int intv = 0;
	char *p = NULL;

	idx = get_radioid_from_priv(priv);
	// argv[0] : from/to/clear
	// argv[1] : interface
	// argv[2] : bits/s
	// argv[3] : intv in ms
	// argv[4] : max. bits

	ac = strargs(s, argv, ARRAY_SIZE(argv), " \t\n\r");
	if (ac<4) {
		return -1;
	}

	if (argv[1]) {
		if (argv[0][0] == 'e') {	// eng mode
			eng = simple_strtoul(argv[1], NULL, 0);
			return 0;
		}
		if (argv[0][0] == 'b') {	// burst
			set_BURST_WIN(simple_strtoul(argv[1], NULL, 0));
			return 0;
		}
	}
	if (argv[3] == NULL)
		return -1;

	if (argv[0][0] == 'c')
		to_intf = -1;	// clear
	else if (argv[0][0] == 'f')
		to_intf = FROM_INTF;	// from
	else if (argv[0][0] == 't')
		to_intf = TO_INTF;	// to
	else if (argv[0][0] == 'a')
		to_intf = MAX_DIR;	// all direction
	else
		return -1;

	if (argv[4])
		max_bytes = simple_strtoul(argv[4], NULL, 0);

	avg_bytes = simple_strtoul(argv[2], &p, 0);
	if (p) {
		if (*p == 'm')
			avg_bytes *= 1024 * 1024;
		else if (*p == 'k')
			avg_bytes *= 1024;
	}
	avg_bytes /= 8;

#if 1
	intv = simple_strtoul(argv[3], NULL, 0);
#else
	intv = simple_strtoul(argv[3], NULL, 0) * HZ / 1000;
	avg_bytes = avg_bytes * intv / HZ;	// avg bytes in window(intv)
#endif

	mssid_idx = get_mssid_idx_from_name(argv[1]);
	if (mssid_idx<0) {
		return 0;
	}

	mssid = &dv_priv[idx].mssid[mssid_idx];
	if (to_intf == -1) {
		dv_ratelimit_unset(mssid, FROM_INTF);
		dv_ratelimit_unset(mssid, TO_INTF);
	} else if (to_intf == MAX_DIR) {	// all direction
		dv_ratelimit_set(mssid, FROM_INTF, avg_bytes, intv, max_bytes / 8);
		dv_ratelimit_set(mssid, TO_INTF, avg_bytes, intv, max_bytes / 8);
	} else {
		dv_ratelimit_set(mssid, to_intf, avg_bytes, intv, max_bytes / 8);
	}
	return 0;
}


static int dv_rate_limit_write_real(struct file *file, const char *buffer,
				unsigned long count, void *data)
{
	unsigned char buf[512];
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv *)data;

	if (strtrim_from_user(buf, sizeof(buf), buffer, count) > 0)
		dv_set_rate_limit_info(priv, buf);
	return count;
}

static ssize_t dv_rate_limit_write(struct file * file, const char __user * userbuf, size_t count, loff_t * off)
{
	return dv_rate_limit_write_real(file, userbuf, count, PDE_DATA(file_inode(file)));
}


struct file_operations dv_rate_limit_fops = {
	.open			= dv_rate_limit_open,
	.read			= seq_read,
	.write			= dv_rate_limit_write,
	.llseek 		= seq_lseek,
	.release		= single_release
};

static int dv_rate_measure_show(struct seq_file *s, void *data)
{
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv *)(s->private);
	int idx;
	struct dv_priv_mssid_t *mssid;
	struct dv_rate_t *t;
	int time_diff, i;

	idx = get_radioid_from_priv(priv);
	for (i = 0; i < MAX_INTF; i++) {
		mssid = &dv_priv[idx].mssid[i];
		t = &mssid->dv_rate;
		time_diff = TIME_DIFF(jiffies, t->jiffy);
		if (ALL_ZERO(t->bytes[0], t->bytes[1]))
			time_diff = 0;
		if (time_diff == 0)
			time_diff = 1;	// avoid divide by 0 error
		seq_printf(s, "%14s %12lu %12lu %12d %12lu %12lu %12lu %12lu\n",
				mssid->name,
				t->bytes[0], t->bytes[1],
				time_diff,
				t->bytes[0] * 8 * HZ / time_diff,
				t->bytes[1] * 8 * HZ / time_diff,
				jiffies, t->jiffy);
		dv_rate_clear(t);
	}
	return 0;
}

static int dv_rate_measure_open(struct inode *inode, struct file *file)
{
	return single_open(file, dv_rate_measure_show, PDE_DATA(file_inode(file)));
}

struct file_operations dv_rate_measure_fops = {
	.open			= dv_rate_measure_open,
	.read			= seq_read,
	.llseek 		= seq_lseek,
	.release		= single_release
};
#endif
/*******************************/

static int dv_connect_limit_show(struct seq_file *s, void *data)
{
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv *)(s->private);
	int idx, i, j;
	struct dv_priv_mssid_t *mssid;
	unsigned char tmpbuf[100];
	int drop_count = 0;
	struct rtl8192cd_priv *t_priv = NULL;

	idx = get_radioid_from_priv(priv);
	for (i = 0; i < MAX_INTF; i++) {
		mssid = &dv_priv[idx].mssid[i];
		memset(tmpbuf, 0, sizeof(tmpbuf));
		t_priv = NULL;

		if (i==0) {
			t_priv = priv;
		} else {
#if defined(UNIVERSAL_REPEATER) || defined(MBSSID)
			for(j=0; j<RTL8192CD_NUM_VWLAN; j++) {
				if(strcmp(mssid->name, priv->pvap_priv[j]->dev->name)==0) {
					t_priv = priv->pvap_priv[j];
					break;
				}
			}
#endif
		}

		if (t_priv==NULL) {
			continue;
		}

		memcpy(tmpbuf, t_priv->pmib->dot11StationConfigEntry.dot11DesiredSSID,
				t_priv->pmib->dot11StationConfigEntry.dot11DesiredSSIDLen);

		seq_printf(s, "%s(%s)=%d(%d) D:%d\n", mssid->name, tmpbuf,
				t_priv->assoc_num, mssid->max_connect, mssid->connect_drop_count);
		drop_count += mssid->connect_drop_count;
	}
	seq_printf(s, "drop count=%d \n", drop_count);
	return 0;
}

static int dv_connect_limit_open(struct inode *inode, struct file *file)
{
	return single_open(file, dv_connect_limit_show, PDE_DATA(file_inode(file)));
}

void davo_wlan_inc_drop_count(struct rtl8192cd_priv *priv)
{
	struct dv_priv_t *dv_priv;
	struct dv_priv_mssid_t *mssid;
	dv_priv = (struct dv_priv_t *)priv->dv_priv;
	mssid = &dv_priv->mssid[priv->dv_priv_mssid_index];
	mssid->connect_drop_count++;
}

int davo_wlan_get_max_conn(struct rtl8192cd_priv *priv)
{
	struct dv_priv_t *dv_priv;
	struct dv_priv_mssid_t *mssid;
	dv_priv = (struct dv_priv_t *)priv->dv_priv;
	mssid = &dv_priv->mssid[priv->dv_priv_mssid_index];
	if (mssid->max_connect>0) {
		return mssid->max_connect;
	}
	return NUM_STAT;
}

void dv_count_limit_set(struct rtl8192cd_priv *priv, char *v)
{
	int idx;
	struct dv_priv_mssid_t *mssid;

	int i;
	int num;
	char *p[MAX_INTF];

	idx = get_radioid_from_priv(priv);

	num = strargs(v, p, ARRAY_SIZE(p), " \t\n\r");
	if (num != 5) {
		return;
	}

	for (i = 0; i < MAX_INTF; i++) {
		if (p[i]) {
			mssid = &dv_priv[idx].mssid[i];
			mssid->max_connect = simple_strtoul(p[i], NULL, 0);
			mssid->connect_drop_count = 0;
		}
	}
}

static int dv_connect_limit_write_real(struct file *file, const char *buffer,
				unsigned long count, void *data)
{
	unsigned char buf[512];
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv *)data;

	if (strtrim_from_user(buf, sizeof(buf), buffer, count) > 0)
		dv_count_limit_set(priv, buf);
	return count;
}

static ssize_t dv_connect_limit_write(struct file * file, const char __user * userbuf, size_t count, loff_t * off)
{
	return dv_connect_limit_write_real(file, userbuf, count, PDE_DATA(file_inode(file)));
}

struct file_operations dv_connect_limit_fops = {
	.open			= dv_connect_limit_open,
	.read			= seq_read,
	.write			= dv_connect_limit_write,
	.llseek 		= seq_lseek,
	.release		= single_release
};

static int dv_auto_bonding_show(struct seq_file *s, void *data)
{
	int idx;
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv *)(s->private);

	idx = get_radioid_from_priv(priv);
	seq_printf(s, "%d\n", g_davo_auto_bonding[idx]);

	return 0;
}

static int dv_auto_bonding_write_real(struct file *file, const char *buffer,
				unsigned long count, void *data)
{
	int idx;
	unsigned char buf[512];
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv *)data;

	idx = get_radioid_from_priv(priv);
	if (count > 0) {
		if (strtrim_from_user(buf, sizeof(buf), buffer, count) > 0) {
			g_davo_auto_bonding[idx] = simple_strtoul(buf, NULL, 10);
		}
	}
	return count;
}

static ssize_t dv_auto_bonding_write(struct file * file, const char __user * userbuf, size_t count, loff_t * off)
{
	return dv_auto_bonding_write_real(file, userbuf, count, PDE_DATA(file_inode(file)));
}

int is_auto_bonding(int band)
{
	return g_davo_auto_bonding[((band==0)?1:0)];
}

static int dv_auto_bonding_open(struct inode *inode, struct file *file)
{
	return single_open(file, dv_auto_bonding_show, PDE_DATA(file_inode(file)));
}

struct file_operations dv_auto_bonding_fops = {
	.open			= dv_auto_bonding_open,
	.read			= seq_read,
	.write			= dv_auto_bonding_write,
	.llseek 		= seq_lseek,
	.release		= single_release
};

static char *go_to_first_digit(char *p, char *end)
{
	while (p != NULL && *p != 0 && (*p < '0' || *p > '9') && p < end)
		p++;
	if (p == NULL || *p == 0 || p >= end)
		return (NULL);
	return (p);
}


void davo_wlan_my_acl_count_inc(int acl_count[], int dir)
{
	acl_count[dir % 2]++;
}

void davo_wlan_init(struct rtl8192cd_priv *priv)
{
	int idx, mssid_idx;
	struct dv_priv_mssid_t *mssid;

	idx = get_radioid_from_priv(priv);
	priv->dv_priv = (void *)&dv_priv[idx];

	if (IS_ROOT_INTERFACE(priv)) {
		char dv_name[32];
		struct proc_dir_entry *wlan_proc;


		if (dv_priv[idx].wlan_proc != NULL)
			return;

		snprintf(dv_name, sizeof(dv_name), "dv_wlan%d", idx);
		wlan_proc = proc_mkdir(dv_name, NULL);
		dv_priv[idx].wlan_proc = wlan_proc;

#if defined(DAVO_ENABLE_WME_OVERRIDE)
		proc_create_data(WME_MODE_STR, 0644, wlan_proc, &dv_wme_mode_fops, (void *)priv);

		proc_create_data(WME_1P_STR, 0644, wlan_proc, &dv_wme_1p_fops, (void *)priv);

		proc_create_data(WME_DSCP_STR, 0644, wlan_proc, &dv_wme_dscp_fops, (void *)priv);

		proc_create_data(WME_DSCP6_STR, 0644, wlan_proc, &dv_wme_dscp_fops, (void *)priv);
#endif
#if defined(DAVO_ENABLE_RATELIMIT)
		proc_create_data(DV_RATE_LIMIT_STR, 0644, wlan_proc, &dv_rate_limit_fops, (void *)priv);
		proc_create_data(DV_RATE_MEASURE_STR, 0644, wlan_proc, &dv_rate_measure_fops, (void *)priv);
#endif
		proc_create_data(CONNECT_COUNT_STR, 0644, wlan_proc, &dv_connect_limit_fops, (void *)priv);
		proc_create_data(AUTO_BONDING_STR, 0644, wlan_proc, &dv_auto_bonding_fops, (void *)priv);

#ifdef __DV_WLCMD__	/* APACRTL-160 */
		dv_wl_cmd_init(priv, wlan_proc);
#endif
		if (pf_registered==0) {
			pf_register_all();
			pf_registered = 1;
		}
	}

	mssid_idx = get_mssid_idx_from_name(priv->dev->name);
	if(mssid_idx<0) {
		mssid_idx = 0;
	}
	priv->dv_priv_mssid_index = mssid_idx;

	mssid = &dv_priv[idx].mssid[priv->dv_priv_mssid_index];

	snprintf(mssid->name, sizeof(mssid->name), "%s", priv->dev->name);
	dv_rate_clear(&mssid->dv_rate);
}

void davo_wlan_deinit(struct rtl8192cd_priv *priv)
{
	struct proc_dir_entry *wlan_proc;
	if (IS_ROOT_INTERFACE(priv)) {
		char dv_name[32];
		int idx;

		idx = get_radioid_from_priv(priv);

		if (dv_priv[idx].wlan_proc == NULL)
			return;
		wlan_proc = dv_priv[idx].wlan_proc;

#ifdef __DV_WLCMD__	/* APACRTL-160 */
		dv_wl_cmd_deinit(priv, wlan_proc);
#endif
#if defined(DAVO_ENABLE_WME_OVERRIDE)
		remove_proc_entry(WME_MODE_STR, wlan_proc);
		remove_proc_entry(WME_1P_STR, wlan_proc);
		remove_proc_entry(WME_DSCP_STR, wlan_proc);
		remove_proc_entry(WME_DSCP6_STR, wlan_proc);
#endif
#if defined(DAVO_ENABLE_RATELIMIT)
		remove_proc_entry(DV_RATE_LIMIT_STR, wlan_proc);
		remove_proc_entry(DV_RATE_MEASURE_STR, wlan_proc);
#endif
		remove_proc_entry(CONNECT_COUNT_STR, wlan_proc);
		remove_proc_entry(AUTO_BONDING_STR, wlan_proc);

		snprintf(dv_name, sizeof(dv_name), "dv_wlan%d", idx);
		remove_proc_entry(dv_name, NULL);

		dv_priv[idx].wlan_proc=NULL;

		if (pf_registered==1) {
			pf_unregister_all();
			pf_registered = 0;
		}
	}
}

static int get_mssid_idx_from_name(char *name)
{
	int mssid_idx = -1, len;
	char *p;
/* set mssid index */
/* wlanX => 0 	  */
/* wlanX-va0 => 1 */
/* wlanX-va1 => 2 */
/* wlanX-va2 => 3 */
/* wlanX-va3 => 4 */
/* wlanX-vxd => 5 */
	if (strlen(name)==strlen("wlan0")) {
		mssid_idx = 0;
	}
#if defined(UNIVERSAL_REPEATER) || defined(MBSSID)
	else if (strlen(name)>7) {
		if (strncmp(&name[5], "-va", 3)==0) {
			p = (char *)&name[5];
			len = strlen(&name[5]);
			p = go_to_first_digit(p, (char *)&name[5] + len);
			if (p) {
				mssid_idx = simple_strtoul(p, NULL, 10);
				mssid_idx = mssid_idx+1;
				if (mssid_idx>(MAX_INTF-2)) {
					printk("unknown name : %s\n", name);
					mssid_idx = 0;
				}
			}
		} else if (strncmp(&name[5], "-vx", 3)==0) {
			mssid_idx = 5;
		}
	}
#endif
	return mssid_idx;
}

/* web redirect */
#if 1
typedef unsigned int uint32;
typedef int int32;
typedef unsigned short uint16;
typedef short int16;
typedef unsigned char uint8;
typedef char int8;
#endif

#define PKTTCP      1
#define PKTNOTTCP   0
//#define HTONS(x) ( (((x)>>8)&0x00ff) | (((x)<<8)&0xff00) )
#define HTONS(x) (x)

#define ETHER_TYPE_MIN      0x0600	/* Anything less than MIN is a length */
#define ETHER_TYPE_IP       0x0800	/* IP */
#define ETHER_TYPE_ARP      0x0806	/* ARP */
#define ETHER_TYPE_8021Q    0x8100	/* 802.1Q */
#define ETHER_TYPE_802_1X   0x888e	/* 802.1x */
#define ETHER_TYPE_802_1X_PREAUTH 0x88c7	/* 802.1x preauthentication */
#define ETHER_TYPE_WAI      0x88b4	/* WAI */

static int drv_rdrt_webrd(struct sk_buff *old_skb, char *dv_webrd_host_url);
static void gen_apple_test_success(uint8 * data, int *dlen, char *rdrt_url);
static void gen_resp302(uint8 * data, int *dlen, char *rdrt_url);
static void gen_ip_hchk(struct iphdr *iph);
static void gen_tcp_hchk(struct iphdr *iph, struct tcphdr *tcph, int tcplen);
static void gen_eh(struct ethhdr *eh);
static void gen_iph(struct iphdr *iph, int ip_payload_len);
static void gen_tcph_with_noflag(struct tcphdr *tcph, int rcvlen, int new_seq);

#define HTTP_302MOVED \
			"HTTP/1.1 302 Found\r\n"\
			"Location: %s\r\n"\
			"Content-Type: text/html\r\n"\
			"Content-Length: 0\r\n\r\n"

static int webrd_check(struct pf_hook_ops *h, struct sk_buff *skb, struct webrd_private *wp)
{
	struct iphdr *iph;
	struct udphdr *uh;
	struct tcphdr *th;

	if (likely(!wp->pstat->webrd))
		return PF_ACCEPT;	// accept it
	else if (unlikely(wp->wlist == NULL))
		return PF_DISCARD;

	switch (((struct ethhdr *)skb->data)->h_proto) {
	case __constant_htons(ETH_P_IP):
		break;		// more checks needed.
	case __constant_htons(ETH_P_PAE):
	case __constant_htons(ETHER_TYPE_802_1X_PREAUTH):
	case __constant_htons(ETH_P_ARP):
		return PF_ACCEPT;	// accept it
	default:
		return PF_DISCARD;	// drop it
	}

	iph = (struct iphdr *)&skb->data[ETH_HLEN];
	if (!(iph->frag_off & __constant_htons(IP_MF | IP_OFFSET))) {
		switch (iph->protocol) {
		case IPPROTO_UDP:
			uh = (struct udphdr *)((u32 *)iph + iph->ihl);
			if ((uh->dest == __constant_htons(53)) || (uh->dest == __constant_htons(67)))
				return PF_ACCEPT;	// accept it
			return wlist_search(wp->wlist, iph->daddr, uh->dest, PKTNOTTCP) ? PF_ACCEPT : PF_DISCARD;

		case IPPROTO_TCP:
			th = (struct tcphdr *)((u32 *)iph + iph->ihl);
			if (wlist_search(wp->wlist, iph->daddr, th->dest, PKTTCP))
				return PF_ACCEPT;
			else if (th->dest == __constant_htons(80))
				drv_rdrt_webrd(skb, wp->priv->dv_webrd_host_url);
			return PF_DISCARD;	/* drop it */

		default:
			break;
		}
	}
	// with fragmented or neither udp nor tcp, chek only dest ip
	return wlist_search(wp->wlist, iph->daddr, 0, PKTNOTTCP) ? PF_ACCEPT : PF_DISCARD;
}

static struct pf_hook_ops webrd_pf_ops = {
	.hook = (void *)webrd_check,
	.priority = PFH_PRI_HIGH,
};

static inline struct sk_buff *get_skb_copy(struct sk_buff *o_skb, int resize, uint8 ** _ndptr,
					   struct tcphdr **_tcph, struct iphdr **_iph, struct ethhdr **_eh)
{
	struct sk_buff *n_skb;
	struct ethhdr *eh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	uint8 *ndptr;

	n_skb = skb_get(o_skb);	// Increments the skb's usage count

	if (!n_skb)
		return NULL;

	eh = (struct ethhdr *)n_skb->data;
	iph = (struct iphdr *)&eh[1];
	tcph = (struct tcphdr *)((u32 *) iph + iph->ihl);

	// adjust tcph for removing ip options
	if (iph->ihl > 5) {
		uint8 *ntcph;
		ntcph = (uint8 *) ((uint8 *) tcph - (iph->ihl - 5) * sizeof(u32));
		iph->ihl = 5;
		memmove(ntcph, tcph, tcph->doff * sizeof(u32));
		tcph = (struct tcphdr *)ntcph;
	}
	if (tcph->doff > 5) {
		tcph->doff = 5;	// no option for reply
	}
	ndptr = (uint8 *) ((uint8 *) tcph + 5 * sizeof(u32));

	if (resize > 0)
		skb_padto(n_skb, resize);	// enlarge skb len to 1200

	*_eh = eh;
	*_iph = iph;
	*_tcph = tcph;
	*_ndptr = ndptr;

	return n_skb;
}

static int drv_rdrt_webrd(struct sk_buff *old_skb, char *dv_webrd_host_url)
{
	// only tcp port 80 will be entered here
	struct ethhdr *eh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	uint32 dlen;		// real tcp payload len
	uint8 *dptr;		// real tcp payload ptr
	uint32 ndlen;		// real tcp payload len
	uint8 *ndptr;		// start ptr of reply payload
	struct sk_buff *new_skb = NULL;

	eh = (struct ethhdr *)old_skb->data;
	iph = (struct iphdr *)&eh[1];
	tcph = (struct tcphdr *)((u32 *) iph + iph->ihl);

	dlen = ntohs(iph->tot_len) - ((iph->ihl + tcph->doff) * sizeof(u32));
	dptr = (uint8 *) ((u32 *) tcph + tcph->doff);

	ndlen = 0;

	if (dlen > 0) {
		// data exist
		if ((strncasecmp(dptr, "GET", 3) == 0) && ((dptr[3] == ' ') || (dptr[3] == '\t'))) {
			// HTTP get, reply with 302
			if ((new_skb = get_skb_copy(old_skb, 1200, &ndptr, &tcph, &iph, &eh)) == NULL)
				return 0;	// drop it
			dptr[dlen] = 0;	// make null terminated string
			if ((strncasecmp(&dptr[4], "/library/test/success.html", 26) == 0)) {
				gen_apple_test_success(ndptr, &ndlen, dv_webrd_host_url);
			} else {
				gen_resp302(ndptr, &ndlen, dv_webrd_host_url);
			}
			gen_tcph_with_noflag(tcph, dlen, 0);
			tcph->psh = 1;
			tcph->ack = 1;
			tcph->fin = 1;
		} else {
			// other packet, send fin
			if ((new_skb = get_skb_copy(old_skb, 0, &ndptr, &tcph, &iph, &eh)) == NULL)
				return 0;	// drop it
			gen_tcph_with_noflag(tcph, dlen, 0);
			tcph->ack = 1;
			tcph->fin = 1;
		}
	} else {
		if (tcph->syn && !tcph->ack) {
			// recv syn, send syn/ack
			if ((new_skb = get_skb_copy(old_skb, 0, &ndptr, &tcph, &iph, &eh)) == NULL)
				return 0;	// drop it
			gen_tcph_with_noflag(tcph, 1, 1);
			tcph->ack = 1;
			tcph->syn = 1;
		} else if (tcph->fin) {
			// recv fin, just send ack
			if ((new_skb = get_skb_copy(old_skb, 0, &ndptr, &tcph, &iph, &eh)) == NULL)
				return 0;	// drop it
			gen_tcph_with_noflag(tcph, 1, 0);
			tcph->ack = 1;
		} else if (tcph->rst) {
			// rst, ignore
			return 0;	// drop it
		} else if (tcph->ack) {
			// ack(not syn/fin/rst), ignore it
			return 0;	// drop it
		} else {
			// just send ack???
			if ((new_skb = get_skb_copy(old_skb, 0, &ndptr, &tcph, &iph, &eh)) == NULL)
				return 0;	// drop it
			gen_tcph_with_noflag(tcph, 1, 0);
			tcph->ack = 1;
		}
	}

	gen_iph(iph, ndlen + 20);	// tcp_payload_len(ndlen) + tcp_header_len(20)
	gen_eh(eh);

	// calc header chksum
	gen_tcp_hchk(iph, tcph, ndlen + 20);	// tcp_payload_len(ndlen) + tcp_header_len(20)
	gen_ip_hchk(iph);

	// skb->len : tcp_payload_len(ndlen) + tcp_header_len(20) + ip_header_len(20) + eth_hdr_len
	new_skb->len = ndlen + 40 + sizeof(eh[0]);
	new_skb->mark = 0;

	//if (ndlen > 0) YDBG(YD_PKT, "<2>%d: rdrt_url data [%s] len [%d] exit\n", __LINE__, ndptr, ndlen);

#if !defined(__LINUX_2_6__) || defined(CONFIG_COMPAT_NET_DEV_OPS)
	new_skb->dev->hard_start_xmit(new_skb, new_skb->dev);
#else
	new_skb->dev->netdev_ops->ndo_start_xmit(new_skb, new_skb->dev);
#endif
	return 0;		// drop _skb
}

static void gen_tcph_with_noflag(struct tcphdr *tcph, int rcvlen, int new_seq)
{
	uint32 seq;
	uint16 port;

	// swap port
	memcpy(&port, &tcph->dest, 2);
	memcpy(&tcph->dest, &tcph->source, 2);
	memcpy(&tcph->source, &port, 2);

	// gen seq/ack
	memcpy(&seq, &tcph->seq, 4);
	if (new_seq) {
		memcpy(&tcph->seq, "o1N&", 4);	// generate new seq
	} else {
		memcpy(&tcph->seq, &tcph->ack_seq, 4);
	}
	seq = htonl(ntohl(seq) + rcvlen);
	memcpy(&tcph->ack_seq, &seq, 4);

	memset(((uint8 *) tcph + 12), 0, 2);	// clear all flags

	tcph->doff = 5;		// header len: 20

	memset(((uint8 *) tcph + 16), 0, 4);	// clear chksum and urgent ptr
}

static void gen_iph(struct iphdr *iph, int ip_payload_len)
{
	uint32 addr;

	iph->ihl = 5;
	iph->tos = 0;
	iph->tot_len = htons(ip_payload_len + 20);	// ip_payload + ip_header
	iph->frag_off = 0;
	iph->ttl = 64;

	// swap addr
	memcpy(&addr, &iph->saddr, 4);
	memcpy(&iph->saddr, &iph->daddr, 4);
	memcpy(&iph->daddr, &addr, 4);
}

static void gen_eh(struct ethhdr *eh)
{
	uint8 addr[ETH_ALEN];

	// swap addr
	memcpy(&addr, &eh->h_source, ETH_ALEN);
	memcpy(&eh->h_source, &eh->h_dest, ETH_ALEN);
	memcpy(&eh->h_dest, &addr, ETH_ALEN);
}

static void gen_tcp_hchk(struct iphdr *iph, struct tcphdr *tcph, int tcplen)
{
	uint32 saddr;
	uint32 daddr;

	memcpy(&saddr, &iph->saddr, 4);
	memcpy(&daddr, &iph->daddr, 4);
	tcph->check = 0;
	tcph->check = csum_tcpudp_magic(saddr, daddr, tcplen, iph->protocol, csum_partial((uint8 *) tcph, tcplen, 0));
}

static void gen_ip_hchk(struct iphdr *iph)
{
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

// APNBCM-121
#define APPLE_SUCCESS   \
	"HTTP/1.0 200 OK\r\n"   \
	"Content-Type: text/html; charset=utf-8\r\n"    \
	"Server: Apache/2.2.14 (Unix)\r\n"  \
	"Cache-Control: max-age=517\r\n"    \
	"Content-Length: %d\r\n"    \
	"Connection: close\r\n" \
	"\r\n"  \
	"%s"

#define APPLE_SUCCESS_CONTENT \
	"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\">\n" \
	"<HTML>\n"  \
	"<HEAD>\n"  \
	"\t<TITLE>Success</TITLE>\n"    \
	"</HEAD>\n" \
	"<BODY>\n"  \
	"Success\n" \
	"</BODY>\n" \
	"</HTML>\n"

static void gen_apple_test_success(uint8 * data, int *dlen, char *rdrt_url)
{
	*dlen = sprintf(data, APPLE_SUCCESS, strlen(APPLE_SUCCESS_CONTENT), APPLE_SUCCESS_CONTENT);
}

static void gen_resp302(uint8 * data, int *dlen, char *rdrt_url)
{
	*dlen = sprintf(data, HTTP_302MOVED, rdrt_url);
}
#ifdef __DAVO__	/* APACRTL-536 */
#define IP_ETH_MC(a, b, c, d)	{ [0] = 1, [1] = 0, [2] = 0x5e, [3] = (b) & 0x7f, [4] = (c), [5] = (d), }
#define DECL_IPMC(a, b, c, d) { \
	.group = __constant_htonl(((u32)a << 24) | ((u32)b << 16) | ((u32)c << 8) | ((u32)d)), \
	.ether = IP_ETH_MC(a, b, c, d) \
}

static const struct {
	__be32 group;
	u8 ether[ETH_ALEN];
} permittee[] = {
	DECL_IPMC(239, 255, 255, 250),	/* UPnP */
	DECL_IPMC(224, 0, 0, 251),	/* mDNS */
	DECL_IPMC(224, 0, 0, 252),	/* LLMNR */
	DECL_IPMC(239, 255, 255, 246),	/* UPnP# */
	DECL_IPMC(224, 0, 1, 65),	/* iapp */
	DECL_IPMC(224, 0, 1, 76),	/* IAPP */
	DECL_IPMC(224, 0, 1, 178),	/* IEEE IAPP */
};

int ip_mc_reserved(__be32 addr)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(permittee); i++)
		if (addr == permittee[i].group)
			return 0;
	return -1;
}
#endif

static int ip_mc_pass(struct pf_hook_ops *h, struct sk_buff *skb, struct webrd_private *wp)
{
	struct rtl8192cd_priv *priv;
	int i;

	if (IP_MCAST_MAC(skb->data)) {
		for (i = 0; i < ARRAY_SIZE(permittee); i++) {
			if (!compare_ether_addr(skb->data, permittee[i].ether))
				return PF_ACCEPT;
		}
		priv = wp->priv;
		davo_wlan_my_acl_count_inc(((struct dv_priv_t *)priv->dv_priv)->my_acl_count, (int)h->private_data);
		return PF_DISCARD;
	}
	return PF_ACCEPT;
}

static struct pf_hook_ops tx_mc_pf_ops = {
	.hook = (void *)ip_mc_pass,
	.private_data = (void *)0,
	.priority = PFH_PRI_HIGH,
};

//APACRTL-91
#ifdef __DV_BSTEER__
static int bs_ip_pps_check(struct pf_hook_ops *h, struct sk_buff *skb, struct webrd_private *wp)
{
	struct iphdr *iph;

    //Case 1 : Check whether handover interface or not.
	if (wp->pstat == NULL ||
           !(wp->priv->pmib->dot11RFEntry.phyBandSelect & PHY_BAND_5G)
#ifdef MBSSID
           || wp->priv->vap_id != 3
#endif
           )
        return PF_ACCEPT;	// accept it

    switch (((struct ethhdr *)skb->data)->h_proto) {
	case __constant_htons(ETH_P_IP):
		break;		// more checks needed.
	default:
		return PF_ACCEPT;	// accept it
	}

    iph = (struct iphdr *)&skb->data[ETH_HLEN];

    //Do not check if ip src is within NAT address..(Not yet)

    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
        //count STA Upstream UDP, TCP packets
        wp->pstat->bs_last_ip_packets++;

    return PF_ACCEPT;
}

static struct pf_hook_ops rx_ip_pps_pf_ops = {
	.hook = (void *)bs_ip_pps_check,
	.priority = PFH_PRI_HIGH,
};
#endif // __DV_BSTEER__

/**********************************************/
#if defined(DAVO_ENABLE_RATELIMIT)
static inline void dv_rate_clear(struct dv_rate_t *dv_rate)
{
	memset(dv_rate->bytes, 0, sizeof(dv_rate->bytes));
	dv_rate->jiffy = jiffies;
}

static inline void dv_rate_measure(struct dv_rate_t *dv_rate, int dir, int len)
{
	dv_rate->bytes[dir] += len;
}

static int ssid_ratelimit(struct pf_hook_ops *h, struct sk_buff *skb, struct webrd_private *wp)
{
	int ret = PF_ACCEPT;
	struct ethhdr *eh;

	eh = (struct ethhdr *)skb->data;
	if (eh->h_proto == __constant_htons(ETH_P_IP)) {
		struct rtl8192cd_priv *priv = wp->priv;
		struct dv_priv_t *t_dv_priv = (struct dv_priv_t *)priv->dv_priv;
		struct dv_priv_mssid_t *dv_mssid = &t_dv_priv->mssid[priv->dv_priv_mssid_index];
		int len = skb->len - ETH_HLEN;
		int dir = (int)h->private_data;

		dir = !!dir;

		if (dv_mssid->ratelimit_enable[dir]) {
			struct iphdr *iph = (struct iphdr *)&skb->data[ETH_HLEN];
			if (iph->tos != 0xb8 && (dv_ratelimit_verdict(&dv_mssid->ratelimit[dir], len)==DV_RATELIMIT_DROP)) {
				ret = PF_DISCARD;
			}
		}
		if (ret == PF_ACCEPT) {
			dv_rate_measure(&dv_mssid->dv_rate, dir, len);
		}
	}

	return ret;
}


static struct pf_hook_ops rx_quota_pf_ops = {
	.hook = (void *)ssid_ratelimit,
	.private_data = (void *)FROM_INTF,
	.priority = PFH_PRI_HIGH,
};

static struct pf_hook_ops tx_quota_pf_ops = {
	.hook = (void *)ssid_ratelimit,
	.private_data = (void *)TO_INTF,
	.priority = PFH_PRI_HIGH,
};

#endif
/**********************************************/

static void pf_register_all(void)
{
	pf_register_hook(&pf_rx_chains, &webrd_pf_ops);
#if defined(DAVO_ENABLE_RATELIMIT)
	pf_register_hook(&pf_rx_chains, &rx_quota_pf_ops);
#endif

#ifdef __DV_BSTEER__
    pf_register_hook(&pf_rx_chains, &rx_ip_pps_pf_ops);
#endif

	pf_register_hook(&pf_tx_chains, &tx_mc_pf_ops);
#if defined(DAVO_ENABLE_RATELIMIT)
	pf_register_hook(&pf_tx_chains, &tx_quota_pf_ops);
#endif
}

static void pf_unregister_all(void)
{
	struct pf_hook_ops *h, *p;

	list_for_each_entry_safe(h, p, &pf_rx_chains, list)
		list_del_init(&h->list);
	list_for_each_entry_safe(h, p, &pf_tx_chains, list)
		list_del_init(&h->list);
}

static DEFINE_SPINLOCK(pf_hook_lock);

int pf_register_hook(struct list_head *h, struct pf_hook_ops *reg)
{
	struct pf_hook_ops *elem;

	spin_lock_bh(&pf_hook_lock);
	list_for_each_entry(elem, h, list) {
		if (reg->priority < elem->priority)
			break;
	}
	list_add(&reg->list, elem->list.prev);
	spin_unlock_bh(&pf_hook_lock);
	return 0;
}
EXPORT_SYMBOL(pf_register_hook);

void pf_unregister_hook(struct pf_hook_ops *reg)
{
	spin_lock_bh(&pf_hook_lock);
	list_del_init(&reg->list);
	spin_unlock_bh(&pf_hook_lock);
}
EXPORT_SYMBOL(pf_unregister_hook);

typedef struct {
	int threshold;
	int intfer_level;
} rfi_t;

static rfi_t fa_tbl[] = {
	{ 4000, RFI_VERY_HIGH },
	{ 2000, RFI_HIGH },
	{ 500,  RFI_MEDIUM },
	{ 150,  RFI_LOW },
	{ 0, 	RFI_NONE },
	{ -1, 	-1 },
};

static rfi_t mac_rx_tbl[] = {
	{ 4000, RFI_VERY_HIGH },
	{ 2000, RFI_HIGH },
	{ 400,  RFI_MEDIUM },
	{ 100,  RFI_LOW },
	{ 0, 	RFI_NONE },
	{ -1, 	-1 },
};

static int average_interfer_level(dv_rf_chk_t *chk, int size)
{
	int i, sz, total=0;

	for (i=0, sz=0; i<size; i++) {
		if (chk->dur > 0) {
			total += chk->rfi_level;
			sz += 1;
		}
		chk++;
	}
	return (!sz ? 0 : total/sz);
}

static int get_interfer_level(unsigned int fa_count, unsigned int mac_rx_count)
{
	int	i, v1, v2;

	v1 = 0;
	for (i=0; fa_tbl[i].threshold > 0; i++) {
		if (fa_count >= fa_tbl[i].threshold) {
			v1 = fa_tbl[i].intfer_level;
			break;
		}
	}
	v2 = 0;
	for (i=0; mac_rx_tbl[i].threshold > 0; i++) {
		if (mac_rx_count >= mac_rx_tbl[i].threshold) {
			v2 = mac_rx_tbl[i].intfer_level;
			break;
		}
	}
	return (v1>v2 ? v1 : v2);
}

static void get_assoc_act_num(struct rtl8192cd_priv *priv, int *assoc_num, int *act_num)
{
	struct list_head *p;
	struct stat_info *pstat;

	if (priv->assoc_num) {
		list_for_each(p, &priv->asoc_list) {
			pstat = list_entry(p, struct stat_info, asoc_list);
			if (pstat->state & WIFI_ASOC_STATE) {
				if (!(pstat->state & WIFI_SLEEP_STATE)) {
					*act_num += 1;
					break;
				}
				*assoc_num += 1;
			}
		}
	}
}

static void dv_rf_check_switch_channel(struct rtl8192cd_priv *priv)
{
	int i, assoc_num, act_num;
	int	f_switch = 0;

	if (priv->dv_rf.avg_rfi_level < RFI_ACTION_THR_LEVEL)
		return;

	if (priv->dv_rf.mode < DV_RF_CHK_ACT1)
		return;

	assoc_num = act_num = 0;
	get_assoc_act_num(priv, &assoc_num, &act_num);
#ifdef MBSSID
	if (!assoc_num || !act_num) {
		for (i=0; i<RTL8192CD_NUM_VWLAN; i++) {
			if (IS_DRV_OPEN(priv->pvap_priv[i])) {
				get_assoc_act_num(priv, &assoc_num, &act_num);
			}
		}
	}
#endif
	if (priv->dv_rf.mode == DV_RF_CHK_ACT1 && !assoc_num) {
		f_switch = 1;
	}
	else if (priv->dv_rf.mode == DV_RF_CHK_ACT2 && !act_num) {
		f_switch = 1;
	}
	else if (priv->dv_rf.mode == DV_RF_CHK_ACT3) {
		f_switch = 1;
	}
	if (f_switch) {
		/* channel switching */
		//printk("\n\nCH switch mode=%d assoc=%d act=%d\n\n", priv->dv_rf.mode, assoc_num, act_num);

		if (!priv->ss_req_ongoing) {
			priv->ss_ssidlen = 0;
			DEBUG_INFO("start_clnt_ss, trigger by %s, ss_ssidlen=0\n", (char *)__FUNCTION__);
			priv->ss_req_ongoing = 1;
			priv->auto_channel = 1;
			priv->dv_rf.f_chan_switching = 1;
			//printk("auto chan select restart & exclude=%d\n", priv->pmib->dot11RFEntry.dot11channel);
			start_clnt_ss(priv);
		}
	}
}

void dv_rf_env_log_update(struct rtl8192cd_priv *priv)
{
	dv_rf_env_t *rfe;
	unsigned int ofdm_ok, cck_ok, ht_ok, ceiling;
	unsigned long tx_bytes, rx_bytes;
	int i;
	dv_rf_chk_t scores[3];
	char str[40];

	if (!IS_ROOT_INTERFACE(priv))
		return;

	//if (!priv->dv_rf.mode)
	//	return;

	if (OPMODE & WIFI_SITE_MONITOR || priv->ss_req_ongoing) {
		/* TODO: reset statistics */
		return;
	}

	if (priv->dv_rf.f_chan_switching) {
		priv->dv_rf.f_chan_switching = 0;
		RTL_W32(RXERR_RPT, RXERR_RPT_RST);
		return;
	}

	tx_bytes = priv->tx_only_data_bytes;
	rx_bytes = priv->rx_only_data_bytes;
#ifdef MBSSID
	for (i=0; i<RTL8192CD_NUM_VWLAN; i++) {
		if (IS_DRV_OPEN(priv->pvap_priv[i])) {
			tx_bytes += priv->pvap_priv[i]->tx_only_data_bytes;
			rx_bytes += priv->pvap_priv[i]->rx_only_data_bytes;
		}
	}
#endif

	rfe = &priv->dv_rf.env;

#ifdef USE_OUT_SRC
	rfe->cnt[rfe->index].fa = ODMPTR->FalseAlmCnt.Cnt_all;
	rfe->cnt[rfe->index].cca = ODMPTR->FalseAlmCnt.Cnt_CCA_all;
#else
	SMP_LOCK(flags);

	hold_CCA_FA_counter(priv);

	_FA_statistic(priv);

	rfe->cnt[rfe->index].fa = priv->pshare->FA_total_cnt;
	rfe->cnt[rfe->index].cca = ((RTL_R8(0xa60)<<8)|RTL_R8(0xa61)) + RTL_R16(0xda0);

	release_CCA_FA_counter(priv);

	SMP_UNLOCK(flags);
#endif


	RTL_W32(RXERR_RPT, 0 << RXERR_RPT_SEL_SHIFT);
	ofdm_ok = RTL_R16(RXERR_RPT);

	RTL_W32(RXERR_RPT, 3 << RXERR_RPT_SEL_SHIFT);
	cck_ok = RTL_R16(RXERR_RPT);

	RTL_W32(RXERR_RPT, 6 << RXERR_RPT_SEL_SHIFT);
	ht_ok = RTL_R16(RXERR_RPT);

	RTL_W32(RXERR_RPT, RXERR_RPT_RST);

	rfe->cnt[rfe->index].mac_rx = ofdm_ok + cck_ok + ht_ok;

	if (rfe->old_tx_bytes == 0) {
		rfe->cnt[rfe->index].tx_bytes = 0;
		rfe->cnt[rfe->index].rx_bytes = 0;
	} else {
		rfe->cnt[rfe->index].tx_bytes = tx_bytes - rfe->old_tx_bytes;
		rfe->cnt[rfe->index].rx_bytes = rx_bytes - rfe->old_rx_bytes;
	}

	rfe->old_tx_bytes = tx_bytes;
	rfe->old_rx_bytes = rx_bytes;

/* APACRTL-182, WR for no rx auth from sta */
	if (priv->up_time < ((struct dv_priv_t *)priv->dv_priv)->facnt_mon.stop_time) {
		if (rfe->cnt[rfe->index].cca < 30)
			ceiling = 0;
		else if (rfe->cnt[rfe->index].cca < 50)
			ceiling = 95;
		else if (rfe->cnt[rfe->index].cca < 100)
			ceiling = 94;
		else if (rfe->cnt[rfe->index].cca < 200)
			ceiling = 93;
		else if (rfe->cnt[rfe->index].cca < 400)
			ceiling = 92;
		else if (rfe->cnt[rfe->index].cca < 800)
			ceiling = 91;
		else
			ceiling = 90;
		if (ceiling && ((rfe->cnt[rfe->index].fa * 100) / rfe->cnt[rfe->index].cca) >= ceiling)
			((struct dv_priv_t *)priv->dv_priv)->facnt_mon.alarm_occur++;
		else
			((struct dv_priv_t *)priv->dv_priv)->facnt_mon.alarm_occur = 0;
	}

	rfe->index = (rfe->index+1) % MAX_LOG_HIST;

	/* complete 3 minutes RF environment scan */
	if (rfe->index==0) {
		int				dur, rfi_level;
		unsigned long	fa, cca, mac_rx, tmp, tot_bytes;

		if (priv->dv_rf.mode == DV_RF_CHK_ONCE)
			priv->dv_rf.mode = DV_RF_MODE_NONE;

		dur = rfi_level = 0;
		fa = cca = mac_rx = tot_bytes = 0;
		for (i=0; i<MAX_LOG_HIST; i++) {
			tmp = rfe->cnt[i].tx_bytes + rfe->cnt[i].rx_bytes;
			/* It's meaningful throughput is less than 100kbps */
			if (tmp < 128000) {
				dur += 1;
				tot_bytes += tmp;
				fa += rfe->cnt[i].fa;
				cca += rfe->cnt[i].cca;
				mac_rx += rfe->cnt[i].mac_rx;
				rfi_level += get_interfer_level(rfe->cnt[i].fa, rfe->cnt[i].mac_rx);
			}
		}
		if (dur > 0) {
			priv->dv_rf.chk_mins[priv->dv_rf.index_min].dur 	= dur;
			priv->dv_rf.chk_mins[priv->dv_rf.index_min].fa		= fa/dur;
			priv->dv_rf.chk_mins[priv->dv_rf.index_min].cca		= cca/dur;
			priv->dv_rf.chk_mins[priv->dv_rf.index_min].mac_rx 	= mac_rx/dur;
			priv->dv_rf.chk_mins[priv->dv_rf.index_min].rfi_level = rfi_level/dur;
			tot_bytes /= dur;
			priv->dv_rf.index_min = (priv->dv_rf.index_min+1)%MAX_CHK_MINUTES;

			priv->dv_rf.avg_rfi_level = average_interfer_level(priv->dv_rf.chk_mins, MAX_CHK_MINUTES);

			if (priv->dv_rf.index_min==0) {
				dur = rfi_level = 0;
				fa = cca = mac_rx = 0;
				for (i=0; i<MAX_CHK_MINUTES; i++) {
					dur += priv->dv_rf.chk_mins[i].dur;
					fa += priv->dv_rf.chk_mins[i].fa;
					cca += priv->dv_rf.chk_mins[i].cca;
					mac_rx += priv->dv_rf.chk_mins[i].mac_rx;
					rfi_level += priv->dv_rf.chk_mins[i].rfi_level;
				}
				priv->dv_rf.chk_hours[priv->dv_rf.index_hour].dur 	= dur;
				priv->dv_rf.chk_hours[priv->dv_rf.index_hour].fa	= fa/MAX_CHK_MINUTES;
				priv->dv_rf.chk_hours[priv->dv_rf.index_hour].cca	= cca/MAX_CHK_MINUTES;
				priv->dv_rf.chk_hours[priv->dv_rf.index_hour].mac_rx = mac_rx/MAX_CHK_MINUTES;
				priv->dv_rf.chk_hours[priv->dv_rf.index_hour].rfi_level = rfi_level/MAX_CHK_MINUTES;
				priv->dv_rf.index_hour = (priv->dv_rf.index_hour+1)%MAX_CHK_HOURS;
				dv_get_rfi_score(priv, scores);
				WL_TRACE_RAW(WLOG_RFI, "%s %s uptime %u assoc. %lu/%lu/%lu/%d(3m) %lu/%lu/%lu/%d(15m) %lu/%lu/%lu/%d(1h) fa/cca/macrx/lvl\n",
					     priv->dev->name,
					     ascminute(priv->up_time / 60, str),
					     sum_stainfo(priv),
					     scores[0].fa, scores[0].cca, scores[0].mac_rx, scores[0].rfi_level,
					     scores[1].fa, scores[1].cca, scores[1].mac_rx, scores[1].rfi_level,
					     scores[2].fa, scores[2].cca, scores[2].mac_rx, scores[2].rfi_level);
				dv_rf_check_switch_channel(priv);
			}
		}
	}
}

int dv_get_rf_env_log(struct rtl8192cd_priv *priv, dv_rf_env_t *rfe)
{
#ifdef SMP_SYNC
	unsigned long flags;
#endif

	if (!IS_ROOT_INTERFACE(priv))
		return 0;

	if (OPMODE & WIFI_SITE_MONITOR)
		return 0;

	SMP_LOCK(flags);
	memcpy(rfe, &priv->dv_rf.env, sizeof(dv_rf_env_t));
	SMP_UNLOCK(flags);

	return (1);
}

#define RFI_CHECK_MIN	15*60	//15min
int dv_get_rfi_score(struct rtl8192cd_priv *priv, dv_rf_chk_t *score)
{
#ifdef SMP_SYNC
	unsigned long flags;
#endif
	int i, j, ret=0;

	if (!IS_ROOT_INTERFACE(priv))
		return 0;

	if (OPMODE & WIFI_SITE_MONITOR)
		return 0;

	SMP_LOCK(flags);

	memset(score, 0, sizeof(dv_rf_chk_t) * 3);
	j = (priv->dv_rf.index_min+(MAX_CHK_MINUTES-1))%MAX_CHK_MINUTES;
	for (i=0; i<MAX_CHK_MINUTES; i++) {
		if (priv->dv_rf.chk_mins[j].dur == 0)
			break;
		if (i==0) {
			memcpy(&score[0], &priv->dv_rf.chk_mins[j], sizeof(dv_rf_chk_t));
		}
		if (i < (RFI_CHECK_MIN/MAX_LOG_HIST)) {
			score[1].dur += priv->dv_rf.chk_mins[j].dur;
			score[1].fa += priv->dv_rf.chk_mins[j].fa;
			score[1].cca += priv->dv_rf.chk_mins[j].cca;
			score[1].mac_rx += priv->dv_rf.chk_mins[j].mac_rx;
			score[1].rfi_level += priv->dv_rf.chk_mins[j].rfi_level;
		}
		score[2].dur += priv->dv_rf.chk_mins[j].dur;
		score[2].fa += priv->dv_rf.chk_mins[j].fa;
		score[2].cca += priv->dv_rf.chk_mins[j].cca;
		score[2].mac_rx += priv->dv_rf.chk_mins[j].mac_rx;
		score[2].rfi_level += priv->dv_rf.chk_mins[j].rfi_level;
		j = (j+(MAX_CHK_MINUTES-1))%MAX_CHK_MINUTES;
	}

	SMP_UNLOCK(flags);

	if (i > 0) {
		ret++;
		if (i >= (RFI_CHECK_MIN/MAX_LOG_HIST)) {
			ret++;
			score[1].fa /= (RFI_CHECK_MIN/MAX_LOG_HIST);
			score[1].cca /= (RFI_CHECK_MIN/MAX_LOG_HIST);
			score[1].mac_rx /= (RFI_CHECK_MIN/MAX_LOG_HIST);
			score[1].rfi_level /= (RFI_CHECK_MIN/MAX_LOG_HIST);
			if (i >= MAX_CHK_MINUTES) {
				ret++;
				score[2].fa /= MAX_CHK_MINUTES;
				score[2].cca /= MAX_CHK_MINUTES;
				score[2].mac_rx /= MAX_CHK_MINUTES;
				score[2].rfi_level /= MAX_CHK_MINUTES;
			}
		}
	}
	return (ret);
}

void dv_set_rf_env_mode(struct rtl8192cd_priv *priv, int mode)
{
#ifdef SMP_SYNC
	unsigned long flags;
#endif

	if (!IS_ROOT_INTERFACE(priv))
		return;

	SMP_LOCK(flags);
	if (mode != 0) {
		memset(&priv->dv_rf, 0, sizeof(priv->dv_rf));
		/* to avoid mis calculation */
		RTL_W32(RXERR_RPT, RXERR_RPT_RST);
	}

	priv->dv_rf.mode = mode;
	SMP_UNLOCK(flags);
}

/* jihyun@davo150617 jcode#2 */
int del_allsta(struct rtl8192cd_priv *priv, unsigned char *data)
{
	struct stat_info *pstat_del;
#ifndef SMP_SYNC
	unsigned long flags;
#endif
	DOT11_DISASSOCIATION_IND Disassociation_Ind;
	int i;

	if (!netif_running(priv->dev))
		return 0;

	for(i=0; i<NUM_STAT; i++) {
		if (priv->pshare->aidarray[i] && (priv->pshare->aidarray[i]->used == TRUE)
#ifdef WDS
					&& !(priv->pshare->aidarray[i]->station.state & WIFI_WDS)
#endif
			   )
		{
#if defined(UNIVERSAL_REPEATER) || defined(MBSSID)
			if (priv != priv->pshare->aidarray[i]->priv)
				continue;
#endif
			pstat_del = &(priv->pshare->aidarray[i]->station);
			if (!list_empty(&pstat_del->asoc_list))
			{
#ifdef _SINUX_
				printk(KERN_INFO "Manual command to disassociating the all client\n");
#endif
#ifndef WITHOUT_ENQUEUE
				put_deauth_info(DOT11_EVENT_DISASSOCIATION_IND, 0, _STATS_OTHER_, pstat_del->hwaddr, pstat_del, &Disassociation_Ind);
				DOT11_EnQueue((unsigned long)priv, priv->pevent_queue, (UINT8 *)&Disassociation_Ind, sizeof(DOT11_DISASSOCIATION_IND));
#endif
#if defined(INCLUDE_WPA_PSK) || defined(WIFI_HAPD)
				psk_indicate_evt(priv, DOT11_EVENT_DISASSOCIATION_IND, pstat_del->hwaddr, NULL, 0);
#endif

#ifdef WIFI_HAPD
				event_indicate_hapd(priv, pstat_del->hwaddr, HAPD_EXIRED, NULL);
	#ifdef HAPD_DRV_PSK_WPS
				event_indicate(priv, pstat_del->hwaddr, 2);
	#endif
#else
#if defined(__DAVO__)
				/* jihyun@davo160202 jcode#7 -*/
				send_trap_userspace(priv, pstat_del, DISCONNECT_STA, ETC_STA);
#endif
				event_indicate(priv, pstat_del->hwaddr, 2);
#endif
				pr_info("Manual command to dissassoc %pM...%s \n", pstat_del->hwaddr, (char *)data ? : "");
				issue_disassoc(priv, pstat_del->hwaddr, _RSON_UNSPECIFIED_);
			}
			free_stainfo(priv, pstat_del);
		}
	}
	priv->assoc_num = 0;
	if (priv->pmib->dot11BssType.net_work_type & WIRELESS_11G) {
		priv->pmib->dot11ErpInfo.nonErpStaNum = 0;
		check_protection_shortslot(priv);
		priv->pmib->dot11ErpInfo.longPreambleStaNum = 0;
	}
	if (priv->pmib->dot11BssType.net_work_type & WIRELESS_11N)
		priv->ht_legacy_sta_num = 0;
	return 0;
}

unsigned int wl_trace_mask = WLOG_ASSOC_REQ|WLOG_ASSOC_RES|WLOG_DISASSOC|WLOG_AUTH|WLOG_DEAUTH|WLOG_RFI;
//unsigned int wl_trace_mask = 0;
EXPORT_SYMBOL(wl_trace_mask);

const char *strStatus(int status)
{
	static char buf[16];
	switch (status) {
	case _STATS_SUCCESSFUL_	:
		return "Success";
	case _STATS_FAILURE_	:
		return "Unspecified failure";
	case _STATS_CAP_FAIL_	:
		return "Cannot support all requested capabilities";
	case _STATS_NO_ASOC_	:
		return "Denial reassociate";
	case _STATS_OTHER_	:
		return "Denial connect, not 802.11 standard";
	case _STATS_NO_SUPP_ALG_:
		return "Unsupported authenticate algorithm";
	case _STATS_OUT_OF_AUTH_SEQ_	:
		return "Out of authenticate sequence number";
	case _STATS_CHALLENGE_FAIL_	:
		return "Denial authenticate, Response message fail";
	case _STATS_AUTH_TIMEOUT_	:
		return "Denial authenticate, timeout";
	case _STATS_UNABLE_HANDLE_STA_	:
		return "Denial authenticate, BS resource insufficient";
	case _STATS_RATE_FAIL_		:
		return "Denial authenticate, STA not support BSS request datarate";
#ifdef CONFIG_IEEE80211R
	case _STATS_INVALID_PAIRWISE_CIPHER_	:
		return "Invalid pairwise cipher";
	case _STATUS_R0KH_UNREACHABLE_		:
		return "R0KH unreachable";
#endif
	case _STATS_ASSOC_REJ_TEMP_	:
		return "Association rejected temporarily; try again later";
	case _STATS_REQ_DECLINED_	:
		return "The request has been declined";
	case __STATS_INVALID_IE_	:
		return "Invalid information element";
	case __STATS_INVALID_AKMP_	:
		return "Invalid AKMP";
	case __STATS_CIPER_REJECT_	:
		return "Cipher suite rejected because of security policy";
#ifdef CONFIG_IEEE80211R
	case _STATS_INVALID_FT_ACTION_FRAME_COUNT_:
		return "Invalid FT Action frame count";
	case _STATS_INVALID_PMKID_	:
		return "Invalid PMKID";
	case _STATS_INVALID_MDIE_	:
		return "Invalid MDIE";
	case _STATS_INVALID_FTIE_	:
		return "Invalid FTIE";
#endif
	default:
		sprintf(buf, "%d", status);
		return buf;
	}
}

const char *strReason(int reason)
{
	static char buf[16];

	switch (reason) {
	case _RSON_RESERVED_:
		return "Reserved";
	case _RSON_UNSPECIFIED_:
		return "Unspecified reason";
	case _RSON_AUTH_NO_LONGER_VALID_:
		return "Previous auth no longer valid";
	case _RSON_DEAUTH_STA_LEAVING_:
		return "STA is leaving(or has left) IBSS or ESS";
	case _RSON_INACTIVITY_:
		return "Inactivity";
	case _RSON_UNABLE_HANDLE_:
		return "Unable to handle all currently associated STAs";
	case _RSON_CLS2_:
		return "Class 2 frame from nonauthenticated STA";
	case _RSON_CLS3_:
		return "Class 3 frame from nonassociated STA";
	case _RSON_DISAOC_STA_LEAVING_:
		return "STA is leaving(or has left) BSS";
	case _RSON_ASOC_NOT_AUTH_:
		return "STA requesting (re)assoc is not authenticated with responding STA";
	case _RSON_INVALID_IE_:
		return "Invalid information element";
	case _RSON_MIC_FAILURE_:
		return "Message integrity code(MIC) failure";
	case _RSON_4WAY_HNDSHK_TIMEOUT_:
		return "4-Way Handshake timeout";
	case _RSON_GROUP_KEY_UPDATE_TIMEOUT_:
		return "Group Key Handshake timeout";
	case _RSON_DIFF_IE_:
		return "IE in 4-Way Handshake different from (Re)Assoc-Req/Probe-Resp/Beacon";
	case _RSON_MLTCST_CIPHER_NOT_VALID_:
		return "Invalid group cipher";
	case _RSON_UNICST_CIPHER_NOT_VALID_:
		return "Invalid pairwise cipher";
	case _RSON_AKMP_NOT_VALID_:
		return "Invalid AKMP";
	case _RSON_UNSUPPORT_RSNE_VER_:
		return "Unsupported RSN information element version";
	case _RSON_INVALID_RSNE_CAP_:
		return "Invalid RSN information element capabilities";
	case _RSON_IEEE_802DOT1X_AUTH_FAIL_:
		return "IEEE 802.1X authentication failed";
	case _RSON_PMK_NOT_AVAILABLE_:
		return "Cipher suite rejected because of the security policy";
	default:
		sprintf(buf, "%d", reason);
		break;
	}

	return buf;
}

int pr_wlmsg(struct rtl8192cd_priv *priv, const char *fmt, ...)
{
	char buf[128];
	va_list args;

	va_start(args, fmt);
	vscnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	return printk("+%s %.*s (%u/%u) %s", priv->dev->name,
		      priv->pmib->dot11StationConfigEntry.dot11DesiredSSIDLen,
		      priv->pmib->dot11StationConfigEntry.dot11DesiredSSID,
		      ODMPTR->FalseAlmCnt.Cnt_all,
		      ODMPTR->FalseAlmCnt.Cnt_CCA_all, buf);
}

static char *ascminute(unsigned int min, char *buf)
{
	unsigned day, hour;
	int i = 0;

	day = min / 1440;
	min %= 1440;
	hour = min / 60;
	min %= 60;
	if (day)
		i = sprintf(buf, "%dd", day);
	if (hour)
		i += sprintf(&buf[i], " %02dh", hour);
	if (min || i == 0)
		sprintf(&buf[i], " %02dm", min);
	return (buf[0] == ' ') ? &buf[1] : buf;
}

static unsigned int sum_stainfo(struct rtl8192cd_priv *priv)
{
	struct list_head *p;
	unsigned int total_assoc_sta = 0;
#ifdef MBSSID
	int i;
#endif
#if !defined(SMP_SYNC) || (defined(CONFIG_USB_HCI) || defined(CONFIG_SDIO_HCI))
	unsigned long flags = 0;
#endif

	SAVE_INT_AND_CLI(flags);
	SMP_LOCK_ASOC_LIST(flags);

	priv = GET_ROOT(priv);
	if (priv->asoc_list.next)
		list_for_each(p, &priv->asoc_list)
			total_assoc_sta++;
#ifdef MBSSID
	if (priv->pmib->miscEntry.vap_enable)
		for (i = 0; i < RTL8192CD_NUM_VWLAN; i++) {
			if (!IS_DRV_OPEN(priv->pvap_priv[i]))
				continue;
			if (priv->pvap_priv[i]->asoc_list.next)
				list_for_each(p, &priv->pvap_priv[i]->asoc_list)
					total_assoc_sta++;
		}
#endif
	SMP_UNLOCK_ASOC_LIST(flags);
	RESTORE_INT(flags);

	return total_assoc_sta;
}

/* APACRTL-94 */
int set_repeater_state(struct rtl8192cd_priv *priv, struct stat_info *pstat, int assoc)
{
	WPA_STA_INFO *pStaInfo = pstat->wpa_sta_info;

	if ((assoc == 0) && (priv->repeater_connect == 1)) {
		dvflag_set(0, DF_WLCLNT_UP);
		priv->repeater_connect = 0;
		priv->repeater_probe++;
		WL_TRACE(WLOG_DISASSOC, "%pM Repeater disconnect\n",
				(pstat) ? pstat->hwaddr : priv->pmib->dot11Bss.bssid);
	} else if ((assoc == 1 && priv->repeater_connect == 0) &&
			((priv->pmib->dot1180211AuthEntry.dot11PrivacyAlgrthm == 0 || // Disable
			  priv->pmib->dot1180211AuthEntry.dot11PrivacyAlgrthm == 1) || // WEP
			 (pStaInfo->clientHndshkDone == 1 && pStaInfo->clientHndshkProcessing == 1))) { // WPA, WPA2, WPA-Mixed
		dvflag_set(DF_WLCLNT_UP, DF_WLCLNT_UP);
		priv->repeater_connect = 1;
		priv->repeater_mic_fail = 0;
		WL_TRACE(WLOG_ASSOC_RES, "%pM Repeater connect\n",
				(pstat) ? pstat->hwaddr : priv->pmib->dot11Bss.bssid);
	}

	return 0;
}

/* jihyun@davo160202 jcode#7 */
void send_trap_userspace(struct rtl8192cd_priv *priv, struct stat_info *pstat, int event, int reason)
{
	struct monitor_sta_t *monitor_sta;
	char buf[IW_CUSTOM_MAX];
	union iwreq_data wreq;
	struct net_device *dev;
	unsigned char *rate;

	if ( !priv || !pstat )
		return;

	dev = (struct net_device *)priv->dev;

	monitor_sta = (struct monitor_sta_t *)&buf[0];
	monitor_sta->aid = pstat->aid;
	monitor_sta->link_time = pstat->link_time;
	monitor_sta->rssi = pstat->rssi;
	monitor_sta->tx_fail = pstat->tx_fail;
	monitor_sta->TxOperaRate = pstat->current_tx_rate;
	monitor_sta->tx_bytes = pstat->tx_bytes;
	monitor_sta->rx_bytes = pstat->rx_bytes;
	monitor_sta->tx_packets = pstat->tx_pkts;
	monitor_sta->rx_packets = pstat->rx_pkts;
	monitor_sta->tx_only_data_packets = pstat->tx_only_data_packets;
	monitor_sta->rx_only_data_packets = pstat->rx_only_data_packets;
	monitor_sta->tx_only_data_bytes = pstat->tx_only_data_bytes;
	monitor_sta->tx_only_data_bytes_high = pstat->tx_only_data_bytes_high;
	monitor_sta->rx_only_data_bytes = pstat->rx_only_data_bytes;
	monitor_sta->rx_only_data_bytes_high = pstat->rx_only_data_bytes_high;
	memcpy(&monitor_sta->mac[0], &pstat->hwaddr[0], MACADDRLEN);
	if (priv->pmib->dot11RFEntry.phyBandSelect & PHY_BAND_2G)
		sprintf(monitor_sta->band, "2.4");
	else
		sprintf(monitor_sta->band, "5");
	monitor_sta->assoc_sec = pstat->assoc_sec;
	monitor_sta->bandwidth = (!priv->pshare->is_40m_bw) ? 20 : (priv->pshare->is_40m_bw * 40);
	monitor_sta->channel = priv->pmib->dot11RFEntry.dot11channel;
	monitor_sta->reason = reason;

#ifdef RTK_AC_SUPPORT  //vht rate , todo, dump vht rates in Mbps
	if(pstat->current_tx_rate >= VHT_RATE_ID){
		int rate = query_vht_rate(pstat);
		snprintf(monitor_sta->current_tx_rate, sizeof(monitor_sta->current_tx_rate), "%d", rate);
	}
	else
#endif
	if (is_MCS_rate(pstat->current_tx_rate)) {
		rate = (unsigned char *)MCS_DATA_RATEStr[(pstat->ht_current_tx_info&BIT(0))?1:0][(pstat->ht_current_tx_info&BIT(1))?1:0][(pstat->current_tx_rate - HT_RATE_ID)];
		snprintf(monitor_sta->current_tx_rate, sizeof(monitor_sta->current_tx_rate), "%s", rate);
	}
	else
	{
		snprintf(monitor_sta->current_tx_rate, sizeof(monitor_sta->current_tx_rate), "%d", pstat->current_tx_rate / 2);
	}

	memset(&wreq, 0, sizeof(wreq));
	wreq.data.flags = event;
	wreq.data.length = sizeof(struct monitor_sta_t);

	wireless_send_event(dev, IWEVCUSTOM, &wreq, buf);
}

#ifdef DV_RXDESC_CHECK_WATCHDOG	/* APACRTL-182, WR for no rx auth from sta */
int dv_rxdesc_check_watchdog(struct rtl8192cd_priv *priv)
{
	struct dv_priv_t *dv_priv = (struct dv_priv_t *)priv->dv_priv;
	int ret = 0, band = 2, cca_cnt, guard_time_threshold = 7;

	if (!(priv->drv_state & DRV_STATE_OPEN) || dv_priv == NULL)
		return (0);

	if (priv->pmib->dot11RFEntry.phyBandSelect == PHY_BAND_5G)
		band = 5;

	// TODO: apply 2.4GHz I/F
	if (band != 5)
		return (0);

	cca_cnt = ODMPTR->FalseAlmCnt.Cnt_CCA_all;
	if (priv->up_time < 20) {
		if (dv_priv->rxbd_check.chk_count == dv_priv->rxbd_check.rx_count) {
			if (cca_cnt == 0) {
				// in shield room, maybe
				dv_priv->rxbd_check.guard_time = 0;
				//printk("%s:%d band=%d uptime=%lu cnt=%u, %u cca=%d\n", __FUNCTION__, __LINE__, band,
				//       priv->up_time, dv_priv->rxbd_check.rx_count, dv_priv->rxbd_check.chk_count, cca_cnt);
			} else {
				if (++dv_priv->rxbd_check.guard_time > guard_time_threshold) {
					printk("%s:%d band=%d uptime=%lu cnt=%u, %u cca=%d\n", __FUNCTION__, __LINE__, band,
					       priv->up_time, dv_priv->rxbd_check.rx_count, dv_priv->rxbd_check.chk_count,
					       cca_cnt);
					// recover wlan0
					dv_priv->rxbd_check.guard_time = 0;
					dv_priv->rxbd_check.recover_cnt += 1;
					ret = 1;
				} else {
					//printk("%s:%d band=%d uptime=%lu cnt=%u, %u cca=%d\n", __FUNCTION__, __LINE__, band,
					//       priv->up_time, dv_priv->rxbd_check.rx_count, dv_priv->rxbd_check.chk_count, cca_cnt);
				}
			}
		} else {
			//printk("%s:%d band=%d uptime=%lu cur_host_idx=%u, %u cca=%d\n", __FUNCTION__, __LINE__, band,
			//      priv->up_time, dv_priv->rxbd_check.rx_count, dv_priv->rxbd_check.chk_count, cca_cnt);
			dv_priv->rxbd_check.chk_count = dv_priv->rxbd_check.rx_count;
			dv_priv->rxbd_check.guard_time = 0;
		}
	}

	return (ret);
}

void dv_rxdesc_check_init(struct rtl8192cd_priv *priv)
{
	dv_priv->rxbd_check.guard_time = 0;
}
#endif /* #ifdef DV_RXDESC_CHECK_WATCHDOG */

/* APACRTL-182, WR for no rx auth from sta */
/* reboot or restart */
void dv_facnt_mon_init(struct rtl8192cd_priv *priv)
{
	dv_priv->facnt_mon.alarm_occur = 0;
	dv_priv->facnt_mon.start_count = 0;
}

/* interface up */
void dv_facnt_mon_start(struct rtl8192cd_priv *priv)
{
	struct dv_priv_t *dv_priv = (struct dv_priv_t *)priv->dv_priv;
	if (IS_ROOT_INTERFACE(priv)) {
		dv_priv->facnt_mon.alarm_occur = 0;
		dv_priv->facnt_mon.start_count++;
		dv_priv->facnt_mon.stop_time = priv->up_time + FA_MONITORING_TIME;
/* APACRTL-104 */
		if (priv->pmib->dot11RFEntry.phyBandSelect == PHY_BAND_5G) {
			RTL_W8(0x808, 0x66);
		}
	}
}

int dv_facnt_mon_watchdog(struct rtl8192cd_priv *priv)
{
	struct dv_priv_t *dv_priv = (struct dv_priv_t *)priv->dv_priv;
	int ret = 0, band = 2;

	if (!(priv->drv_state & DRV_STATE_OPEN) || dv_priv == NULL)
		return (0);

	if (priv->up_time > dv_priv->facnt_mon.stop_time) {
		return (0);
	}

	/* prevent an infinite loop. */
	if (dv_priv->facnt_mon.start_count > 4) {
		return (0);
	}

	if (priv->pmib->dot11RFEntry.phyBandSelect == PHY_BAND_5G)
		band = 5;

	// TODO: apply 2.4GHz I/F
	if (band != 5) {
		return (0);
	}

	if (dv_priv->facnt_mon.alarm_occur > 4) {
		dv_priv->facnt_mon.alarm_occur = -20; /* down/up guard */
		ret = 1;
		printk("+%s CCA-to-FA ratio too high (uptime=%lu)\n", priv->dev->name, priv->up_time);
	}

	return ret;
}

