/*
 *      Modification from Davolink
 *      Header file
 * 
 *      For SKBB BMT: 2009.10
 */

#ifndef	_8192CD_DAVO_WLCMD_H__
#define _8192CD_DAVO_WLCMD_H__

#include "./8192cd_cfg.h"
#include "./8192cd.h"

#include "./dv_ratelimit.h"
#include <os_util.h>

enum {
	WL_LOG_FLAG_FROM_RSSI = 1,
	WL_LOG_FLAG_FROM_TXS = 2,
	WL_LOG_FLAG_TO_CONSOLE = 4,
};

/*
 * Init davo wlan command process module
 */
void dv_wl_cmd_init(struct rtl8192cd_priv *priv, struct proc_dir_entry *wlan_proc);
void dv_wl_cmd_deinit(struct rtl8192cd_priv *priv, struct proc_dir_entry *wlan_proc);

int dv_wl_log_update(struct rtl8192cd_priv *priv, int which, char *log);
int dv_wl_log_enable(struct rtl8192cd_priv *priv, int which, unsigned int macid);

int dv_wl_force_tx_rate(struct rtl8192cd_priv *priv);
unsigned int dv_wl_get_tx_rate(struct rtl8192cd_priv *priv, unsigned int current_tx_rate);

void dv_wl_inc_debug_count(struct rtl8192cd_priv *priv, char *pos, int lineno);

int dv_wl_tx_retry_limit(struct rtl8192cd_priv *priv);

//#define DV_WLCMD_DEBUG_COUNT
#ifdef DV_WLCMD_DEBUG_COUNT
# define DV_WL_INC_COUNT()		dv_wl_inc_debug_count(priv, __FUNCTION__, __LINE__)
#else
# define DV_WL_INC_COUNT()
#endif

#endif // _8192CD_DAVO_WLCMD_H__
