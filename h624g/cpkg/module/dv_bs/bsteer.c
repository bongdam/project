#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#include <linux/jiffies.h>
#include <os_util.h>
#include <dv_bsteer.h>

//#define TIME_STA_BLOCK_DEFAULT (10)	// sec
#define TIME_STA_BLOCK_DEFAULT (1)	// sec
#define TIME_BCN_PWR_DEFAULT   (10)	// sec
#define TIME_DELAY_BSTEER (3600) //sec

#define RSSI_THRESHOLD_DEFAULT (-78)
#define PROBE_DENY_RSSI_DEFAULT (-70)
#define TIME_CHECK_TCP_PPS (20)	// sec
#define CNT_CHECK_TCP_PPS (2)	// packet count

#define MAX_BLOCKED_MAC 64
static struct t_blocked_mac {
	unsigned long expire_time;
	unsigned char mac[6];
	unsigned char used;
	unsigned char handovered;
// APACRTL-502
    unsigned short data_is_seen;
    unsigned short log_only_once;
} blocked_mac[MAX_BLOCKED_MAC];

#if 1
static DEFINE_SPINLOCK(_lock);
#define LOCK(fl) spin_lock_irqsave(&_lock, fl)
#define UNLOCK(fl) spin_unlock_irqrestore(&_lock, fl)
#else
#define UNUSED(x)	(void)(x)
#define LOCK(fl) 	UNUSED(fl)
#define UNLOCK(fl)	UNUSED(fl)
#endif

#define EXPIRED(x) time_after(jiffies, (x))

#define MAC_PR_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_PR_VAL(x) (x)[0],(x)[1],(x)[2],(x)[3],(x)[4],(x)[5]

static struct t_bcn_pwr {
	unsigned int reduced;
	unsigned long expire_time;
} bcn_pwr;

static int bs_enable = 0;
static unsigned int time_sta_block = TIME_STA_BLOCK_DEFAULT;
static unsigned int time_bcn_pwr = TIME_BCN_PWR_DEFAULT;
static unsigned int time_delay_bsteer = TIME_DELAY_BSTEER;
static int rssi_threshold = RSSI_THRESHOLD_DEFAULT;
static int probe_deny_rssi = PROBE_DENY_RSSI_DEFAULT;
static unsigned long time_to_check_ip_pps = TIME_CHECK_TCP_PPS;
static unsigned long last_ip_packets_count = CNT_CHECK_TCP_PPS;

int dv_bs_enabled(void)
{
	return bs_enable;
}

int dv_bs_rssi_threshold(void)
{
    return rssi_threshold;
}

//APACRTL-105
int dv_bs_probe_deny_rssi(void)
{
    return probe_deny_rssi;
}

//APACRTL-91
unsigned long dv_bs_ip_pps_check_time(void)
{
    return time_to_check_ip_pps;
}

//APACRTL-91
unsigned long dv_bs_time_delay_bsteer(void)
{
    return time_delay_bsteer * HZ;
}

//APACRTL-91
unsigned long dv_bs_last_ip_packets_count(void)
{
    return last_ip_packets_count;
}

unsigned int dv_bs_time_sta_block(void)
{
	return time_sta_block*HZ;
}

unsigned int dv_bs_time_bcn_pwr(void)
{
	return time_bcn_pwr*HZ;
}

int dv_bs_sta_check_rssi(struct _bs_rssi_hist *s, int rssi, int link_time)
{
	int i;
	int cnt;

	s->rssi[s->idx] = rssi;
	s->idx = (s->idx+1)%MAX_RSSI_HIST;

	if (link_time < 5)
		return DV_BS_STA_GOOD;

	for (i=0, cnt=0;i<MAX_RSSI_HIST;i++) {
		if (s->rssi[i] >= rssi_threshold) {
			break;
		} else {
			cnt++;
		}
	}

	if (cnt >= MAX_RSSI_HIST) {
		return DV_BS_STA_MOVE;
	}

	return DV_BS_STA_GOOD;
}

//APACRTL-91
int dv_bs_sta_check_ip_pps(unsigned long ip_packets, unsigned char *mac)
{
    if (last_ip_packets_count * time_to_check_ip_pps > ip_packets)
        return DV_BS_STA_MOVE;

    return DV_BS_STA_GOOD;
}


#define SEARCH_ONLY  0
#define SEARCH_ENTER 1
static struct t_blocked_mac *_find_mac(unsigned char *mac, int enter)
{
	struct t_blocked_mac *p;
	int i, e=-1;

    for (i=0, p=blocked_mac; i<MAX_BLOCKED_MAC; i++, p++) {
        if (p->used) {
            if (!EXPIRED(p->expire_time)) {
                if (mac && memcmp(mac, p->mac, sizeof(p->mac))==0) {
                    return p;
                }
            } else {
                // APACRTL-105
                //condition for removing handover information.
                //1. Information is used when STA is associating.
                //2. Time after block + 3600 seconds.(Check SKB handover condition.)
// APACRTL-502
                if (p->log_only_once == 0) {
                    printk("+handover: 5G unblock " MAC_PR_FMT " (timer)\n", MAC_PR_VAL(p->mac));
                    p->log_only_once = 1;
                }

                if (EXPIRED(p->expire_time + ((TIME_DELAY_BSTEER * HZ) - dv_bs_time_sta_block()))) {
                    printk("+handover: Delete handover info about STA. " MAC_PR_FMT " (timer)\n", MAC_PR_VAL(p->mac));
                    memset(p->mac, 0, sizeof(p->mac)); //issue code
                    p->handovered = 0;
                    p->used = 0;
// APACRTL-502
                    p->log_only_once = 0;
                    p->data_is_seen = 0;
                }

                //for dv_bs_sta_is_handovered()
                if (mac && memcmp(mac, p->mac, sizeof(p->mac))==0) {
                    return p;
                }
            }
        }

        if ((e<0) &&(!p->used)) {
            e=i;	// mark empty slot
        }
    }

	if (!enter)
		return NULL;	// if searching only, return not found

	if (e<0)
		return NULL;	// empty entry not found


	// fill new entry
	p = &blocked_mac[e];
	memcpy(p->mac, mac, sizeof(p->mac));
	p->expire_time = jiffies + dv_bs_time_sta_block();
	p->used = 1;
    p->handovered = 1;
    p->log_only_once = 0; // // APACRTL-502

	return p;
}


int dv_bs_sta_add_blocked(unsigned char *mac)
{
    //Adding sta into handover block list is ignored.
#if 1
	struct t_blocked_mac *p;
	unsigned long flags;

	LOCK(flags);
	p = _find_mac(mac, SEARCH_ENTER);
	if (!p) {
		// entry full?
		UNLOCK(flags);
		return -1;
	}

	p->expire_time = jiffies + dv_bs_time_sta_block();

	UNLOCK(flags);

	printk("+handover: 5G block " MAC_PR_FMT "\n", MAC_PR_VAL(mac));
#else
	printk("+handover: 5G block SKIPPED => " MAC_PR_FMT "\n", MAC_PR_VAL(mac));
#endif
	return 0;
}

int dv_bs_sta_del_blocked(unsigned char *mac)
{
	struct t_blocked_mac *p;
	unsigned long flags;

	LOCK(flags);
	p = _find_mac(mac, SEARCH_ONLY);
	if (!p) {
		// not found
		UNLOCK(flags);
		return -1;
	}

	memset(p->mac, 0, sizeof(p->mac));
	p->used = 0;
	UNLOCK(flags);

	printk("+handover: 5G unblock " MAC_PR_FMT " (cmd)\n", MAC_PR_VAL(mac));

	return 0;
}

int dv_bs_sta_is_blocked(unsigned char *mac)
{
	struct t_blocked_mac *p;
	unsigned long flags;

	LOCK(flags);
	p = _find_mac(mac, SEARCH_ONLY);
	UNLOCK(flags);

// APACRTL-502
	return (p && !(p->handovered)) ? 1:0;
}

//APACRTL-105
int dv_bs_sta_is_handovered(unsigned char *mac)
{
	struct t_blocked_mac *p;
	unsigned long flags;

	LOCK(flags);
	p = _find_mac(mac, SEARCH_ONLY);
	UNLOCK(flags);

// APACRTL-502
    if (p)
        p->data_is_seen = 1;

	return p ? p->handovered:0;
}

//APACRTL-105
unsigned long dv_bs_sta_handovered_time(unsigned char *mac)
{
	struct t_blocked_mac *p;
	unsigned long flags;

	LOCK(flags);
	p = _find_mac(mac, SEARCH_ONLY);
	UNLOCK(flags);

	return (p && p->handovered) ? p->expire_time:0;
}


extern void wl_recover_5g_6m_power(void *_priv);
extern void wl_reduce_5g_6m_power(void *_priv, int dbm);

void dv_bs_reduce_bcn_pwr(void *priv)
{
	if (!bcn_pwr.reduced) {
		bcn_pwr.reduced = 1;
		// reduce bcn pwr
		wl_reduce_5g_6m_power(priv, 4);
	}
	bcn_pwr.expire_time = jiffies + dv_bs_time_bcn_pwr();	// extend pwr reduced time
}

void dv_bs_recover_bcn_pwr(void *priv)
{
	if (bcn_pwr.reduced) {
		bcn_pwr.reduced = 0;
		// recover bcn pwr
		wl_recover_5g_6m_power(priv);
	}
}

void dv_bs_watchdog(void *priv)
{
	unsigned long flags;

	// check mac entry expired
	LOCK(flags);
	_find_mac(NULL, SEARCH_ONLY);
	UNLOCK(flags);

	// check bcn pwr expired
	if (bcn_pwr.reduced && EXPIRED(bcn_pwr.expire_time)) {
		dv_bs_recover_bcn_pwr(priv);
	}
}

static ctl_table _table[] = {
        { .procname     = "enable",
          .data         = &bs_enable,
          .maxlen       = sizeof(bs_enable),
          .mode         = 0644,
          .proc_handler = proc_dointvec },
        { .procname     = "time_sta_block",
          .data         = &time_sta_block,
          .maxlen       = sizeof(time_sta_block),
          .mode         = 0644,
          .proc_handler = proc_dointvec },
        { .procname     = "time_bcn_pwr",
          .data         = &time_bcn_pwr,
          .maxlen       = sizeof(time_bcn_pwr),
          .mode         = 0644,
          .proc_handler = proc_dointvec },
        { .procname     = "rssi_threshold",
          .data         = &rssi_threshold,
          .maxlen       = sizeof(rssi_threshold),
          .mode         = 0644,
          .proc_handler = proc_dointvec },
        { .procname     = "probe_deny_rssi",
          .data         = &probe_deny_rssi,
          .maxlen       = sizeof(probe_deny_rssi),
          .mode         = 0644,
          .proc_handler = proc_dointvec },
        { .procname     = "time_delay_bsteer",
          .data         = &time_delay_bsteer,
          .maxlen       = sizeof(time_delay_bsteer),
          .mode         = 0644,
          .proc_handler = proc_dointvec },
        { .procname     = "pps_checking_time",
          .data         = &time_to_check_ip_pps,
          .maxlen       = sizeof(time_to_check_ip_pps),
          .mode         = 0644,
          .proc_handler = proc_dointvec },
        { .procname     = "tcp_pkts_threshold",
          .data         = &last_ip_packets_count,
          .maxlen       = sizeof(last_ip_packets_count),
          .mode         = 0644,
          .proc_handler = proc_dointvec },
        { }
};

static ctl_table _dir_table[] = {
        { .procname     = "bs",
          .mode         = 0555,
          .child        = _table },
        { }
};

static ctl_table _root_table[] = {
        { .procname     = "private",
          .mode         = 0555,
          .child        = _dir_table },
        { }
};

static struct ctl_table_header *private_sysctls;

static int __init netpriv_sysctl_register(void)
{
	private_sysctls = register_sysctl_table(_root_table);
	return 0;
}

static void __exit netpriv_sysctl_unregister(void)
{
	if (private_sysctls)
		unregister_sysctl_table(private_sysctls);
}

module_init(netpriv_sysctl_register);
module_exit(netpriv_sysctl_unregister);

