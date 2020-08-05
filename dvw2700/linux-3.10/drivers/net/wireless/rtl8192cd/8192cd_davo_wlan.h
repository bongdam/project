/*
 *      Modification from Davolink
 *      Header file
 *
 *      For SKBB BMT: 2009.10
 */

#ifndef	_8192CD_DAVO_WLAN_H__
#define _8192CD_DAVO_WLAN_H__

#include "./8192cd_cfg.h"
#include "./8192cd.h"

// #define DAVO_ENABLE_WEBRD
// #define DAVO_ENABLE_RATELIMIT

#include "./dv_ratelimit.h"

#include <os_util.h>

#if defined(UNIVERSAL_REPEATER) || defined(MBSSID)
#define MAX_INTF (DV_MAX_WL_BSS+1) /* wlan0, wlan0-vax, wlan0-vxx */
#else
#define MAX_INTF 1 /* wlan0 */
#endif

#define MAX_DIR     2
#define TO_INTF     1   // packet DIR to interface
#define FROM_INTF   0   // packet DIR from interface

/*
 * Init davo wlan structures while initializing module
 */
void davo_wlan_init(struct rtl8192cd_priv *priv);
void davo_wlan_deinit(struct rtl8192cd_priv *priv);

/* We are sure that it's enough if we just regard 3 STAs connected to AP concurrently    */
#define MAX_DEV   6   /* wlan0, wlan0-vax, wlan0-vxx */
#define BW11B_MAX_STA   4
#define BW11B_MAX_DEV   6   /* wlan0, wlan0-vax, wlan0-vxx */
#define BW11B_TOLTAL_BW_UPDATE_TIME   (3*HZ)      /* every 2 seconds  */
#define BW11B_TOLTAL_BW_RECALC_TIME   (30*HZ)     /* it may be too old..  */

/*	2016.07.03	APACRTL-182
 *	We found rx packet interrupt doesn't occurred after reset wlan0 while booting.
 *  In our inspection, the symptom happen on following condition.
 *	 1) RF environment is very noisy. (obss is 80%, RF resource is occupied by other AP)
 *      Too many 802.11 frames are receiving at wlan0 reset phase.
 *   2) System is busy, some other jobs are doing concurrently.
 */
#define DV_RXDESC_CHECK_WATCHDOG 1

/*****************************************************************************
 *
 * To set 802.1e WME AC category according to 802.1p or DSCP marking.
 *
 * ***************************************************************************
*/
#define DAVO_ENABLE_WME_OVERRIDE          1

#define DAVO_WME_RULE_SIZE_802_1P   8
#define DAVO_WME_RULE_SIZE_DSCP     64

enum {
    DAVO_WME_OVERRIDE_DISABLE,
    DAVO_WME_OVERRIDE_802_1P,
    DAVO_WME_OVERRIDE_DSCP,
};

struct dv_rate_t {
	unsigned long jiffy;
	unsigned long bytes[MAX_DIR];
};

struct dv_priv_mssid_t {
	char name[IFNAMSIZ];
#if defined(DAVO_ENABLE_RATELIMIT)
	unsigned char ratelimit_enable[MAX_DIR];
	dv_ratelimit_ctrl_t ratelimit[MAX_DIR];
	struct dv_rate_t dv_rate;
#endif
#if 0
/* STA CONNECT LIMIT */
	unsigned short max_connect;
	unsigned short connect_drop_count;
#endif
};

struct dv_priv_t {
/* Radio */
	struct proc_dir_entry *wlan_proc;
#if defined(DAVO_ENABLE_WME_OVERRIDE)
	int wme_override;
	unsigned char rule_802_1p[DAVO_WME_RULE_SIZE_802_1P];
	unsigned char rule_dscp[DAVO_WME_RULE_SIZE_DSCP];
	unsigned char rule_dscp6[DAVO_WME_RULE_SIZE_DSCP];
#endif
	int my_acl_count[2];
/* MSSID */
	struct dv_priv_mssid_t mssid[MAX_INTF];

#if defined(__DV_DUMP_RXPKT__)
	/* APACRTL-213, for rx frame statistics */
	struct {
		unsigned int valid[3];		/* valid packet rx */
		unsigned int ibss;			/* my bss count */
		unsigned int obss;			/* other bss count */
		unsigned int crcerr;		/* broadcast count */
		unsigned int mgnt;			/* management frame count */
		unsigned int ctrl;			/* control frame count */
		unsigned int data;			/* data frame count */
		unsigned int prbreq;		/* probe request frame count */
		unsigned int auth;			/* authentication frame count */
		unsigned int deauth;		/* deauthentication frame count */
		unsigned int assoc;			/* association frame count */
		unsigned int beacon;		/* beacon frame count */
	} rxcnt;
#endif
};
#define FA_MONITORING_TIME 180

#if DAVO_ENABLE_WME_OVERRIDE
  #define davo_wme_override_enabled(a) (a->wme_override != DAVO_WME_OVERRIDE_DISABLE)
  #define davo_wme_802_1p_enabled(a) (a->wme_override == DAVO_WME_OVERRIDE_802_1P)
  #define davo_wme_dscp_enabled(a) (a->wme_override == DAVO_WME_OVERRIDE_DSCP)

  #define davo_wme_get_802_1p_priority(a, b) (((b)>=0&&(b)<DAVO_WME_RULE_SIZE_802_1P?(a)->rule_802_1p[(b)]:0))
  #define davo_wme_get_dscp_priority(a, b) (((b)>=0&&(b)<DAVO_WME_RULE_SIZE_DSCP?(a)->rule_dscp[(b)]:0))
  #define davo_wme_get_dscp6_priority(a, b) (((b)>=0&&(b)<DAVO_WME_RULE_SIZE_DSCP?(a)->rule_dscp6[(b)]:0))

#else
  #define davo_wme_override_enabled(a)             (0)
  #define davo_wme_802_1p_enabled(a)               (0)
  #define davo_wme_dscp_enabled(a)                 (0)
  #define davo_wme_get_802_1p_priority(a, index)     (0)
  #define davo_wme_get_dscp_priority(a, index)       (0)
  #define davo_wme_get_dscp6_priority(a, index)      (0)
#endif

extern struct list_head pf_rx_chains;
extern struct list_head pf_tx_chains;

struct davo_wl_private {
	struct stat_info *pstat;
	struct rtl8192cd_priv *priv;
#if defined(DAVO_ENABLE_WEBRD)
	void *wlist;
#endif
};

/*****************************************************************************
 *
 * SKBB Aging test for 120 hours.
 *
 * ***************************************************************************
*/
//#define DAVO_MAC_RESTRICT_FOR_AGING_TEST    1

void davo_wlan_my_acl_count_inc(int acl_count[], int dir);

#if defined(DAVO_ENABLE_RATELIMIT)
int dv_set_rate_limit_info(struct rtl8192cd_priv *priv, char *s);
#endif

void dv_count_limit_set(struct rtl8192cd_priv *priv, char *v);
void davo_wlan_inc_drop_count(struct rtl8192cd_priv *priv);

#if 0
int davo_wlan_get_max_conn(struct rtl8192cd_priv *priv);
#endif

extern void dv_rf_env_log_update(struct rtl8192cd_priv *priv);

/* dv_rf_info mode */
enum {
	DV_RF_MODE_NONE,
	DV_RF_CHK_ONCE,
	DV_RF_CHK_CONT,
	DV_RF_CHK_ACT1,
	DV_RF_CHK_ACT2,
	DV_RF_CHK_ACT3,
};

/* interference level */
enum {
	RFI_NONE,
	RFI_LOW			= 10,
	RFI_MEDIUM		= 20,
	RFI_HIGH		= 30,
	RFI_VERY_HIGH	= 40,
};
#define RFI_ACTION_THR_LEVEL	30


#define MAX_LOG_HIST		180
#define MAX_CHK_MINUTES		(3600/(MAX_LOG_HIST))
#define MAX_CHK_HOURS		24

typedef struct dv_rf_env {
	unsigned int	index;
	unsigned long	old_rx_bytes;
	unsigned long	old_tx_bytes;
	struct {
		unsigned int	fa;	// record FA count for idle
		unsigned int	cca;	// record CCA count for idle
		unsigned int	mac_rx;	// record ofdm, cck, ht rx error count for idle
		unsigned long	rx_bytes;	// rx bytes
		unsigned long	tx_bytes;	// tx bytes
		unsigned int	CurIGValue;
	} cnt[MAX_LOG_HIST];
} dv_rf_env_t;

typedef struct dv_rf_chk {
	int				dur;						// secs for calcuration
	unsigned long	fa;
	unsigned long	cca;
	unsigned long	mac_rx;
	int				rfi_level;
} dv_rf_chk_t;

typedef struct dv_rf_info {
	int				mode;
	int				avg_rfi_level;
	int				f_chan_switching;
	dv_rf_env_t		env;
	int 			index_min;
	dv_rf_chk_t		chk_mins[MAX_CHK_MINUTES];
	int 			index_hour;
	dv_rf_chk_t		chk_hours[MAX_CHK_HOURS];
} dv_rf_info_t;

int dv_get_rfi_score(struct rtl8192cd_priv *priv, dv_rf_chk_t *score);
int dv_get_rf_env_log(struct rtl8192cd_priv *priv, dv_rf_env_t **rfe);
void dv_set_rf_env_mode(struct rtl8192cd_priv *priv, int mode);
int del_allsta(struct rtl8192cd_priv *priv, unsigned char *data);

enum {
	WLOG_ASSOC_REQ	= (1 << 0),
	WLOG_ASSOC_RES	= (1 << 1),
	WLOG_PROBE_REQ	= (1 << 4),
	WLOG_PROBE_RES	= (1 << 5),
	WLOG_DISASSOC	= (1 << 6),
	WLOG_AUTH	= (1 << 7),
	WLOG_DEAUTH	= (1 << 8),
	WLOG_RFI	= (1 << 9)
};

#define WL_TRACE(p, arg...) \
	do {\
		if ((wl_trace_mask & (p)) && net_ratelimit())\
			pr_wlmsg(priv, arg);\
	} while (0)

#define WL_TRACE_RAW(p, arg...) \
	do {\
		if ((wl_trace_mask & (p)) && net_ratelimit())\
			printk("+" arg); \
	} while (0)

extern unsigned int wl_trace_mask;
int pr_wlmsg(struct rtl8192cd_priv *priv, const char *fmt, ...);
const char *strStatus(int status);
const char *strReason(int reason);

#if defined(__DV_DUMP_RXPKT__)
/* APACRTL-213, for rx frame statistics */
#define dv_inc_rxpkt_cnt(priv, pkt) \
{ \
	struct dv_priv_t *dv_priv = (struct dv_priv_t *)((priv)->dv_priv); \
	if (dv_priv!=NULL) { \
		dv_priv->rxcnt.pkt++; \
	} \
}
extern int dv_dump_rxpkt; /* APACRTL-213, for rx frame statistics */
#endif


#endif // _8192CD_DAVO_WLAN_H__
