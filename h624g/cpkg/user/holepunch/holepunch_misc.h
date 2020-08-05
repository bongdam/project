#ifndef _HOLEPUNCH_MISC_H__
#define _HOLEPUNCH_MISC_H__

#include "apmib.h"

#define HOSTINFO_FILE   "/proc/rtl865x/l2"
#define MAX_PORT		5

char *read_lines(char *p, char *out, int maxlen);
int safe_atoi(const char *s, int ndefault);
void hole_punching_pkt_set(KEYID id, void *value, struct _HolePunching_PKT *pkt);
void dump_hole_punching_pkt(struct _HolePunching_PKT *pkt);

#define DV_MALLOC 0

#if DV_MALLOC
#define MALLOC(s) dv_malloc(s)
#define FREE(s) dv_free(s)
void *dv_malloc(size_t size);
void dv_free(void *ptr);
#else
#define MALLOC(s) malloc(s)
#define FREE(s) free(s)
#endif

key_variable *get_key_tbl();

char *get_cmd_type_str(CMD_TYPE_ID id);
CMD_TYPE_ID get_cmd_type_id(char *name);

char *get_cmd_str(CMD_ID id);
cmd_variable *get_cmd_by_name(char *name);
cmd_variable *get_cmd_by_id(CMD_ID id);

int getWlStaInfo(char *interface, WLAN_STA_INFO_Tp pInfo);
int wirelessClientList(int index, struct _wlan_status *status);
void get_wirelesstraffic_check(int wlan_idx, struct _wlan_status *status);
void get_cpemac_list(int mbrport, char *cpeMac, int len, char *hostname, int h_len);
void match_wlmac_traffic(int cpeNum, unsigned long *outByte, unsigned long *inByte, struct _wlan_status *now, struct _wlan_status *pre, char *cpeMac, int len, char *hostname, int h_len);
#endif
