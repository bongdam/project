#ifndef __DV_BS_H__
#define __DV_BS_H__

#define MAX_RSSI_HIST 3

struct _bs_rssi_hist {
	signed char rssi[MAX_RSSI_HIST];
	signed char idx;
};
#define DV_BS_STA_GOOD 0
#define DV_BS_STA_MOVE 1


extern int dv_bs_enabled(void);
extern int dv_bs_rssi_threshold(void);
extern int dv_bs_probe_deny_rssi(void);
extern unsigned long dv_bs_ip_pps_check_time(void);
extern unsigned long dv_bs_time_delay_bsteer(void);
extern unsigned int dv_bs_time_sta_block(void);
extern unsigned int dv_bs_time_bcn_pwr(void);
extern int dv_bs_sta_check_rssi(struct _bs_rssi_hist *s, int rssi, int link_time);
extern int dv_bs_sta_check_ip_pps(unsigned long ip_packets, unsigned char *mac);
extern unsigned long dv_bs_last_ip_packets_count(void);
extern int dv_bs_sta_check_delay_handover(unsigned char *mac);
extern int dv_bs_sta_add_blocked(unsigned char *mac);
extern int dv_bs_sta_del_blocked(unsigned char *mac);
extern int dv_bs_sta_is_blocked(unsigned char *mac);
extern int dv_bs_sta_is_handovered(unsigned char *mac);
extern unsigned long dv_bs_sta_handovered_time(unsigned char *mac);
extern void dv_bs_reduce_bcn_pwr(void *priv);
extern void dv_bs_recover_bcn_pwr(void *priv);
extern void dv_bs_watchdog(void *priv);

#endif
