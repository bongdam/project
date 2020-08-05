#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <netdb.h>
#include <limits.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <linux/ethtool.h>
#include <linux/wireless.h>
#include <netinet/ip_icmp.h>
#include <wait.h>

#include <8192cd.h>

#include "holepunch.h"
#include "holepunch_misc.h"

//changes in following table should be synced to MCS_DATA_RATEStr[] in 8190n_proc.c
WLAN_RATE_T rate_11n_table_20M_LONG[] = {
	{MCS0, 		"6.5"},
	{MCS1, 		"13"},
	{MCS2, 		"19.5"},
	{MCS3, 		"26"},
	{MCS4, 		"39"},
	{MCS5, 		"52"},
	{MCS6, 		"58.5"},
	{MCS7, 		"65"},
	{MCS8, 		"13"},
	{MCS9, 		"26"},
	{MCS10, 	"39"},
	{MCS11, 	"52"},
	{MCS12, 	"78"},
	{MCS13, 	"104"},
	{MCS14, 	"117"},
	{MCS15, 	"130"},
	{0}
};

WLAN_RATE_T rate_11n_table_20M_SHORT[] = {
	{MCS0, 		"7.2"},
	{MCS1, 		"14.4"},
	{MCS2, 		"21.7"},
	{MCS3, 		"28.9"},
	{MCS4, 		"43.3"},
	{MCS5, 		"57.8"},
	{MCS6, 		"65"},
	{MCS7, 		"72.2"},
	{MCS8, 		"14.4"},
	{MCS9, 		"28.9"},
	{MCS10, 	"43.3"},
	{MCS11, 	"57.8"},
	{MCS12, 	"86.7"},
	{MCS13, 	"115.6"},
	{MCS14, 	"130"},
	{MCS15, 	"144.5"},
	{0}
};

WLAN_RATE_T rate_11n_table_40M_LONG[] = {
	{MCS0, 		"13.5"},
	{MCS1, 		"27"},
	{MCS2, 		"40.5"},
	{MCS3, 		"54"},
	{MCS4, 		"81"},
	{MCS5, 		"108"},
	{MCS6, 		"121.5"},
	{MCS7, 		"135"},
	{MCS8, 		"27"},
	{MCS9, 		"54"},
	{MCS10, 	"81"},
	{MCS11, 	"108"},
	{MCS12, 	"162"},
	{MCS13, 	"216"},
	{MCS14, 	"243"},
	{MCS15, 	"270"},
	{0}
};

WLAN_RATE_T rate_11n_table_40M_SHORT[] = {
	{MCS0, 		"15"},
	{MCS1, 		"30"},
	{MCS2, 		"45"},
	{MCS3, 		"60"},
	{MCS4, 		"90"},
	{MCS5, 		"120"},
	{MCS6, 		"135"},
	{MCS7, 		"150"},
	{MCS8, 		"30"},
	{MCS9, 		"60"},
	{MCS10, 	"90"},
	{MCS11, 	"120"},
	{MCS12, 	"180"},
	{MCS13, 	"240"},
	{MCS14, 	"270"},
	{MCS15, 	"300"},
	{0}
};

WLAN_RATE_T tx_fixed_rate[]={
	{1, 		"1"},
	{(1<<1), 	"2"},
	{(1<<2), 	"5.5"},
	{(1<<3), 	"11"},
	{(1<<4), 	"6"},
	{(1<<5), 	"9"},
	{(1<<6), 	"12"},
	{(1<<7), 	"18"},
	{(1<<8), 	"24"},
	{(1<<9), 	"36"},
	{(1<<10), 	"48"},
	{(1<<11), 	"54"},
	{(1<<12), 	"MCS0"},
	{(1<<13), 	"MCS1"},
	{(1<<14), 	"MCS2"},
	{(1<<15), 	"MCS3"},
	{(1<<16), 	"MCS4"},
	{(1<<17), 	"MCS5"},
	{(1<<18), 	"MCS6"},
	{(1<<19), 	"MCS7"},
	{(1<<20), 	"MCS8"},
	{(1<<21), 	"MCS9"},
	{(1<<22), 	"MCS10"},
	{(1<<23), 	"MCS11"},
	{(1<<24), 	"MCS12"},
	{(1<<25), 	"MCS13"},
	{(1<<26), 	"MCS14"},
	{(1<<27), 	"MCS15"},
	{((1<<31)+0), 	"NSS1-MCS0"},
	{((1<<31)+1), 	"NSS1-MCS1"},
	{((1<<31)+2), 	"NSS1-MCS2"},
	{((1<<31)+3), 	"NSS1-MCS3"},
	{((1<<31)+4), 	"NSS1-MCS4"},
	{((1<<31)+5), 	"NSS1-MCS5"},
	{((1<<31)+6), 	"NSS1-MCS6"},
	{((1<<31)+7), 	"NSS1-MCS7"},
	{((1<<31)+8), 	"NSS1-MCS8"},
	{((1<<31)+9), 	"NSS1-MCS9"},
	{((1<<31)+10), 	"NSS2-MCS0"},
	{((1<<31)+11), 	"NSS2-MCS1"},
	{((1<<31)+12), 	"NSS2-MCS2"},
	{((1<<31)+13), 	"NSS2-MCS3"},
	{((1<<31)+14), 	"NSS2-MCS4"},
	{((1<<31)+15), 	"NSS2-MCS5"},
	{((1<<31)+16), 	"NSS2-MCS6"},
	{((1<<31)+17), 	"NSS2-MCS7"},
	{((1<<31)+18), 	"NSS2-MCS8"},
	{((1<<31)+19), 	"NSS2-MCS9"},
	{0}
};

//changes in following table should be synced to VHT_MCS_DATA_RATE[] in 8812_vht_gen.c
// 				20/40/80,	ShortGI,	MCS Rate
const unsigned short VHT_MCS_DATA_RATE[3][2][30] =
	{	{	{13, 26, 39, 52, 78, 104, 117, 130, 156, 156,
			 26, 52, 78, 104, 156, 208, 234, 260, 312, 312,
			 39, 78, 117, 156, 234, 312, 351, 390, 468, 520},					// Long GI, 20MHz

			{14, 29, 43, 58, 87, 116, 130, 144, 173, 173,
			 29, 58, 87, 116, 173, 231, 260, 289, 347, 347,
			 43, 86, 130, 173, 260, 347, 390, 433, 520, 578}			},		// Short GI, 20MHz

		{	{27, 54, 81, 108, 162, 216, 243, 270, 324, 360,
			 54, 108, 162, 216, 324, 432, 486, 540, 648, 720,
			 81, 162, 243, 342, 486, 648, 729, 810, 972, 1080}, 				// Long GI, 40MHz

			{30, 60, 90, 120, 180, 240, 270, 300,360, 400,
			 60, 120, 180, 240, 360, 480, 540, 600, 720, 800,
			 90, 180, 270, 360, 540, 720, 810, 900, 1080, 1200}			},		// Short GI, 40MHz

		{	{59, 117,  176, 234, 351, 468, 527, 585, 702, 780,
			 117, 234, 351, 468, 702, 936, 1053, 1170, 1404, 1560,
			 176, 351, 527, 702, 1053, 1408, 1408, 1745, 2106, 2340}, 			// Long GI, 80MHz

			{65, 130, 195, 260, 390, 520, 585, 650, 780, 867,
			 130, 260, 390, 520, 780, 1040, 1170, 1300, 1560, 1733,
			 195, 390, 585, 780, 1170, 1560, 1560, 1950, 2340, 2600}	}		// Short GI, 80MHz

	};

static key_variable key_tbl[] = {
	{"SEQ", KEY_ID_SEQ, 1, TYPE_INT },
	{"RESP_SEQ", KEY_ID_RESP_SEQ, 0, TYPE_INT },
	{"T", KEY_ID_T, 1, TYPE_STR },
	{"NEED_ACK", KEY_ID_NEED_ACK, 0, TYPE_INT },
	{"ARGS", KEY_ID_ARGS, 0, TYPE_STR },
	{"RESULT", KEY_ID_RESULT, 0, TYPE_STR },
	{"CMD", KEY_ID_CMD, 0, TYPE_STR },
	{NULL, KEY_ID_END, 0, 0}
};

static cmd_type_variable cmd_type_tbl[] = {
	{"CMD", CMD_TYPE_ID_CMD},
	{"KEEP-ALIVE", CMD_TYPE_ID_KEEP_ALIVE},
	{"ACK", CMD_TYPE_ID_ACK},
	{"ERROR", CMD_TYPE_ID_ERROR},
	{"END", CMD_TYPE_ID_END }
};

static cmd_variable cmd_tbl[] = {
// {"COMMAND", CMD_ID, type}
	{"RESET", CMD_ID_RESET, TYPE_STR },
	{"GET-REPORT-SVR-INFO", CMD_GET_REPORT_SVR_INFO, TYPE_STR },
	{"GET-WIFI-STATUS", CMD_GET_WIFI_STATUS, TYPE_STR},
	{"SET-WIFI-STATUS", CMD_SET_WIFI_STATUS, TYPE_STR},
	{"GET-SSID-STATUS", CMD_GET_SSID_STATUS, TYPE_STR},
	{"SET-SSID-STATUS", CMD_SET_SSID_STATUS, TYPE_STR},
	{"GET-SSID-RATE", CMD_GET_SSID_RATE, TYPE_STR},
	{"SET-SSID-RATE", CMD_SET_SSID_RATE, TYPE_STR},
	{"GET-IGMP-JOIN-TABLE", CMD_GET_IGMP_JOIN_TABLE, TYPE_STR},
	{"GET-PORT-STATUS", CMD_GET_PORT_STATUS, TYPE_STR},
	{"GET-RESOURCE-STATUS", CMD_GET_RESOURCE_STATUS, TYPE_STR},
	{"START-PORT-STATUS-REPORT", CMD_START_PORT_STATUS_REPORT, TYPE_STR},
	{"SEND-PORT-STATUS-REPORT", CMD_SEND_PORT_STATUS_REPORT, TYPE_STR},
	{"STOP-PORT-STATUS-REPORT", CMD_STOP_PORT_STATUS_REPORT, TYPE_STR},
	{"START-IGMP-JOIN-TABLE-REPORT", CMD_START_IGMP_JOIN_TABLE_REPORT, TYPE_STR},
	{"STOP-IGMP-JOIN-TABLE-REPORT", CMD_STOP_IGMP_JOIN_TABLE_REPORT, TYPE_STR},
	{"SEND-IGMP-JOIN-TABLE-REPORT", CMD_SEND_IGMP_JOIN_TABLE_REPORT, TYPE_STR},
	{"START-RESOURCE-REPORT", CMD_START_RESOURCE_STATUS_REPORT, TYPE_STR},
	{"STOP-RESOURCE-REPORT", CMD_STOP_RESOURCE_STATUS_REPORT, TYPE_STR},
	{"SEND-RESOURCE-REPORT", CMD_SEND_RESOURCE_STATUS_REPORT, TYPE_STR},
	{"VERSION", CMD_GET_VERSION, TYPE_STR},
	{"SNMP-GET", CMD_GET_SNMP, TYPE_STR},
	{"SNMP-SET", CMD_SET_SNMP, TYPE_STR},
	{"SNMP-WALK", CMD_GET_SNMPWALK, TYPE_STR},
	{"START-TRAFFIC-REPORT", CMD_TRAFFIC_REPORT, TYPE_STR},
	{"STOP-TRAFFIC-REPORT", CMD_STOP_TRAFFIC_REPORT, TYPE_STR},
	{"SEND-TRAFFIC-REPORT", CMD_SEND_TRAFFIC_REPORT, TYPE_STR},
	{"SET-ADMIN-PW-INIT", CMD_SET_ADMIN_PW_INIT, TYPE_STR},
	{NULL, CMD_ID_END, 0}
};

char *read_lines(char *p, char *out, int maxlen)
{
    int c;
    char *e;

    if (p == NULL)
        return NULL;

    /* skip leading white spaces */
    while (*p && isspace(*p))
        p++;

    if (*p == '\0')
        return NULL;

    for (e = (out + maxlen - 1); (c = *p) && (out < e); p++) {
        switch (c) {
        case '\n':
            *out = 0;
            return ++p;
#if 0
        case '\r':
            if (p[1] == '\n') {
                *out = 0;
                return &p[2];
            }
#endif
        default:
            *out++ = c;
            break;
        }
    }
    *out = 0;
    return p;

}

void hole_punching_pkt_set(KEYID id, void *value, struct _HolePunching_PKT *pkt)
{
	char *tmp;
	tmp = (char *)value;

	switch (id) {
		case KEY_ID_SEQ:
			pkt->seq = atoi(tmp);
			break;
		case KEY_ID_RESP_SEQ:
			pkt->resp_seq = atoi(tmp);
			break;
		case KEY_ID_T:
		    pkt->cmd_type = get_cmd_type_id(tmp);
		    break;
		case KEY_ID_NEED_ACK:
			pkt->need_ack = atoi(tmp);
			break;
		case KEY_ID_ARGS:
			snprintf (pkt->args, sizeof(pkt->args), "%s", tmp);
			break;
		case KEY_ID_RESULT:
			snprintf (pkt->result, sizeof(pkt->result), "%s", tmp);
			break;
		case KEY_ID_CMD:
		    tmp = (char *)get_cmd_by_name(tmp);
		    if (tmp!=NULL) {
		         pkt->cmd = ((cmd_variable *)tmp)->id;
		    } else {
		        pkt->cmd = CMD_ID_END;
		    }
			break;
		default:
			break;
	}
}


key_variable *get_key_tbl()
{
    return (&key_tbl[0]);
}

char *get_cmd_type_str(CMD_TYPE_ID id)
{
    cmd_type_variable *v;
    for (v=&cmd_type_tbl[0]; v->name; v++) {
        if (id==v->id)
            return v->name;
    }
    return NULL;
}

CMD_TYPE_ID get_cmd_type_id(char *name)
{
    cmd_type_variable *v;
    for (v=&cmd_type_tbl[0]; v->name; v++) {
        if (strcmp(v->name, name)==0)
            return v->id;
    }
    return CMD_TYPE_ID_END;
}

char *get_cmd_str(CMD_ID id)
{
    cmd_variable *v;
    for (v=&cmd_tbl[0]; v->name; v++) {
        if (id==v->id)
            return v->name;
    }
    return NULL;
}

cmd_variable *get_cmd_by_id(CMD_ID id)
{
    cmd_variable *v;
    for (v=&cmd_tbl[0]; v->name; v++) {
        if (id==v->id)
            return v;
    }
    return NULL;
}

cmd_variable *get_cmd_by_name(char *name)
{
    cmd_variable *v;
    for (v=&cmd_tbl[0]; v->name; v++) {
        if (strcmp(v->name, name)==0)
            return v;
    }
    return NULL;
}

void dump_hole_punching_pkt(struct _HolePunching_PKT *pkt)
{
    printf ("==> hole_punching_pkt DUMP <== \n");
    printf ("SEQ=%d\n", pkt->seq);
    printf ("RESP_SEQ=%d\n", pkt->resp_seq);
    printf ("T=%s\n", pkt->cmd_type?get_cmd_type_str(pkt->cmd_type):"");
    printf ("NEED_ACK=%d\n", pkt->need_ack);
    printf ("ARGS=%s\n", pkt->args?pkt->args:"");
    printf ("CMD=%s\n", pkt->cmd?get_cmd_str(pkt->cmd):"");
    printf ("RESULT=%s\n", pkt->result?pkt->result:"");
    printf ("========================\n");
}

//#define isspace(c) ((((c) == ' ') || (((unsigned int)((c) - 9)) <= (13 - 9))))
#define SIOCGIWRTLSTAINFO   0x8B30
int getWlStaInfo(char *interface, WLAN_STA_INFO_Tp pInfo)
{
	int skfd = 0;
	struct iwreq wrq;
	int ret;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd == -1) {
		return -1;
	}

	wrq.u.data.pointer = (caddr_t) pInfo;
	wrq.u.data.length = sizeof(WLAN_STA_INFO_T) * (MAX_STATION_NUM + 1);
	*((unsigned char *)wrq.u.data.pointer) = MAX_STATION_NUM;

	strncpy(wrq.ifr_name, interface, IFNAMSIZ);
	if ((ret = ioctl(skfd, SIOCGIWRTLSTAINFO, &wrq)) < 0) {
		close(skfd);
		return -1;
	}
	close(skfd);
	return ret;
}

void set_11ac_txrate(WLAN_STA_INFO_Tp pInfo, char *txrate, int len)
{
	char channelWidth = 0;//20M 0,40M 1,80M 2
	char shortGi = 0;
	char rate_idx = pInfo->TxOperaRate-0xA0;

	if(!txrate)
		return;
/*
	TX_USE_40M_MODE		= BIT(0),
	TX_USE_SHORT_GI		= BIT(1),
	TX_USE_80M_MODE		= BIT(2)
*/
	if(pInfo->ht_info & 0x4)
		channelWidth = 2;
	else if(pInfo->ht_info & 0x1)
		channelWidth = 1;
	else
		channelWidth = 0;
	if(pInfo->ht_info & 0x2)
		shortGi = 1;

	snprintf(txrate, len, "%d", VHT_MCS_DATA_RATE[channelWidth][shortGi][rate_idx]>>1);
}

int wirelessClientList(int index, struct _wlan_status *status)
{
	int i, j, k = 0, found = 0;
	WLAN_STA_INFO_Tp pInfo;
	char *buff;
	char WLAN_IF[20];
	int ret, rateid = 0;

	memset(status, 0, sizeof(struct _wlan_status) * (MAX_STATION_NUM * 5));

	buff = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STATION_NUM + 1));
	if (buff == 0) {
		printf("Allocate buffer failed!\n");
		return 0;
	}

	for (i = 0; i < 5; i++) {
		if (i == 0)
			sprintf(WLAN_IF, "wlan%d", index);
		else
			sprintf(WLAN_IF, "wlan%d-va%d", index, i - 1);

		memset(buff, 0, sizeof(WLAN_STA_INFO_T) * (MAX_STATION_NUM + 1));
		if ((ret = getWlStaInfo(WLAN_IF, (WLAN_STA_INFO_Tp) buff)) < 0)
			continue;

		for (j = 1; j <= MAX_STATION_NUM; j++) {
			pInfo = (WLAN_STA_INFO_Tp)&buff[j * sizeof(WLAN_STA_INFO_T)];
			if (pInfo->aid && (pInfo->flags & STA_INFO_FLAG_ASOC)) {
                memcpy(status[k].addr, pInfo->addr, 6);
                status[k].wlanOutBytes = pInfo->tx_only_data_bytes + (pInfo->tx_only_data_bytes_high * 0x400000);
                status[k].wlanInBytes = pInfo->rx_only_data_bytes + (pInfo->rx_only_data_bytes_high * 0x400000);
                status[k].rssi = CONV_TO_RSSI(pInfo->rssi);

				if (pInfo->TxOperaRate >= 0xA0) {
					set_11ac_txrate(pInfo, status[k].txrate, sizeof(status[k].txrate));
				} else if((pInfo->TxOperaRate & 0x80) != 0x80) {
					if (pInfo->TxOperaRate % 2) {
						snprintf(status[k].txrate, sizeof(status[k].txrate), "%d%s", pInfo->TxOperaRate/2, ".5");
					} else {
						snprintf(status[k].txrate, sizeof(status[k].txrate), "%d", pInfo->TxOperaRate/2);
					}
				} else {
					if ((pInfo->ht_info & 0x1) == 0) { 					//20M
						if ((pInfo->ht_info & 0x2) == 0) {				//long
							for (rateid = 0; rateid < 16; rateid++) {
								if (rate_11n_table_20M_LONG[rateid].id == pInfo->TxOperaRate) {
									snprintf(status[k].txrate, sizeof(status[k].txrate), "%s", rate_11n_table_20M_LONG[rateid].rate);
									break;
								}
							}
						} else if ((pInfo->ht_info & 0x2) == 0x2) {		//short
							for (rateid = 0; rateid < 16; rateid++) {
								if (rate_11n_table_20M_SHORT[rateid].id == pInfo->TxOperaRate) {
									snprintf(status[k].txrate, sizeof(status[k].txrate), "%s", rate_11n_table_20M_SHORT[rateid].rate);
									break;
								}
							}
						}
					} else if ((pInfo->ht_info & 0x1) == 0x1) {			//40M
						if ((pInfo->ht_info & 0x2) == 0) {				//long
							for (rateid = 0; rateid < 16; rateid++) {
								if (rate_11n_table_40M_LONG[rateid].id == pInfo->TxOperaRate) {
									snprintf(status[k].txrate, sizeof(status[k].txrate), "%s", rate_11n_table_40M_LONG[rateid].rate);
									break;
								}
							}
						} else if ((pInfo->ht_info & 0x2) == 0x2) {		//short
							for (rateid = 0; rateid < 16; rateid++) {
								if (rate_11n_table_40M_SHORT[rateid].id == pInfo->TxOperaRate) {
									snprintf(status[k].txrate, sizeof(status[k].txrate), "%s", rate_11n_table_40M_SHORT[rateid].rate);
									break;
								}
							}
						}
					}
				}
                status[k].check = 1;
                k++;
                found++;
			}
		}
	}

	free(buff);
	return found;
}

void get_wirelesstraffic_check(int index, struct _wlan_status *status)
{
	unsigned int tx_low, tx_high, rx_low, rx_high, find;
	char fileName[128];
	char buf[128], tmp[64];
	FILE *fp;
	int i;

	/* WLAN Traffic */
	for(i = 0; i <= 4; i ++) {
		find = 0;
		tx_low = 0;
		tx_high = 0;
		rx_low = 0;
		rx_high = 0;

		if (i == 0)
			snprintf(fileName, sizeof(fileName), "/proc/wlan%d/stats", index);
		else
			snprintf(fileName, sizeof(fileName), "/proc/wlan%d-va%d/stats", index, i - 1);

		fp = fopen(fileName, "r");
		if (fp == NULL)
			return;

		while (fgets(buf, sizeof(buf), fp) != NULL) {
			if (strstr(buf, "tx_only_data_bytes:")) {
				if (sscanf(buf, "%s %u", tmp, &tx_low) == 2)
					find++;
			}

			if (strstr(buf, "tx_only_data_bytes_high:")) {
				if (sscanf(buf, "%s %u", tmp, &tx_high) == 2)
					find++;
			}

			if (strstr(buf, "rx_only_data_bytes:")) {
				if (sscanf(buf, "%s %u", tmp, &rx_low) == 2)
					find++;
			}

			if (strstr(buf, "rx_only_data_bytes_high:")) {
				if (sscanf(buf, "%s %u", tmp, &rx_high) == 2)
					find++;
			}

			if (find >= 4)
				break;
		}

		fclose(fp);

		status[i].wlanOutBytes = tx_low + (tx_high * 0x400000);
		status[i].wlanInBytes = rx_low + (rx_high * 0x400000);
	}
}

struct HOST_INFO_T {
	int portNo;
	unsigned int ipAddr;
	unsigned char mac[6];
};

struct HOST_INFO_T hostInfo;

struct dhcpOfferedAddr {
	u_int8_t chaddr[16];
	u_int32_t yiaddr;	/* network order */
	u_int32_t expires;	/* host order */
	char hostname[64];
};

static int _is_hex(char c)
{
	return (((c >= '0') && (c <= '9')) ||
			((c >= 'A') && (c <= 'F')) ||
			((c >= 'a') && (c <= 'f')));
}

static int hex_to_string(char *string, char *key, int len)
{
	char tmpBuf[4];
	int idx, ii=0;

	for (idx = 0; idx < len; idx += 2) {
		tmpBuf[0] = string[idx];
		tmpBuf[1] = string[idx+1];
		tmpBuf[2] = 0;
		if (!_is_hex(tmpBuf[0]) || !_is_hex(tmpBuf[1]))
			return 0;
		key[ii++] = (char)strtol(tmpBuf, NULL, 16);
	}

	return 1;
}

static int simple_ether_atoe(char *strVal, unsigned char *MacAddr)
{
	int ii;
	int mac[6];

	if (strlen(strVal) == 12 && hex_to_string(strVal, MacAddr, 12))
		return 1;

	ii = sscanf(strVal, "%02x:%02x:%02x:%02x:%02x:%02x", &mac[0], &mac[1], &mac[2],
			&mac[3], &mac[4], &mac[5]);

	if ( ii != 6)
		ii = sscanf(strVal, "%02x-%02x-%02x-%02x-%02x-%02x",&mac[0], &mac[1], &mac[2],
				&mac[3], &mac[4], &mac[5]);

	if (ii != 6)
		return 0;

	for (ii = 0; ii < 6; ii++)
		MacAddr[ii] = (unsigned char )(mac[ii] & 0xff);

	return 1;
}

static char *trim_spaces(char *s)
{
	int len = strlen(s);
	/* trim trailing whitespace and double quotation */
	while (len > 0 && (isspace(s[len - 1]) || s[len - 1] == '"'))
		s[--len] = '\0';
	/* trim leading whitespace and double quotation */
	memmove(s, &s[strspn(s, " \n\r\t\v\"")], len);
	return s;
}

static int is_local_port_fun(char *buf)
{
    char *ptr;
	int ptn;

	if( !(ptr = strstr(buf, "mbr(")) )
		return 0;

	if(ptr && strlen(ptr) > 4)
		ptr += 4;

	trim_spaces(ptr);

	ptn = atoi(ptr);

	if(( ptn >= 0 ) && ( ptn < 4 ))
		return 1;

	return 0;
}

void get_sta_hostname(unsigned *staMac, char *hostname, int h_len)
{
	struct dhcpOfferedAddr lease;
	int fd;

	fd = open("/var/lib/misc/udhcpd.leases", O_RDONLY);
	if (fd < 0)
		return 0;

	while (read(fd, &lease, sizeof(lease)) == sizeof(lease)) {
		if (!lease.expires || !memcmp(lease.chaddr, "\x00\x00\x00\x00\x00\x00", 6))
			continue;
		if (!memcmp(lease.chaddr, staMac, 6)) {
			snprintf(hostname, h_len, "%s", lease.hostname);
			break;
		}
	}

	close(fd);
}

void get_cpemac_list(int mbrport, char *cpeMac, int len, char *hostname, int h_len)
{
	FILE *fp;
	char tmpBuf[128];
	char *ptr1, *ptr2;
	int loc_port;
	int port;

	memset(&hostInfo, 0, sizeof(hostInfo));
	memset(cpeMac, 0, len);
	memset(hostname, 0, h_len);

	fp = fopen(HOSTINFO_FILE, "r");
	if (!fp)
		return 0;

	while (fgets(tmpBuf, sizeof(tmpBuf), fp)) {
		if( ( ptr1 = strstr(tmpBuf, "FWD DYN") ) && (loc_port = is_local_port_fun(tmpBuf)) ){
			if (ptr1) {
				char *strMac;
				ptr2 = strstr(tmpBuf, "mbr(");
				strMac = &tmpBuf[13];
				strMac[17] = 0;
				simple_ether_atoe(strMac, hostInfo.mac);
				if (ptr2 && strlen(ptr2) > 4)
					ptr2 += 4;
				trim_spaces(ptr2);
				port = atoi(ptr2);
				if ( port < 0 || port >= MAX_PORT - 1 || port != mbrport)
					continue;
				get_sta_hostname(hostInfo.mac, hostname, h_len);
				snprintf(cpeMac, len, "%02x%02x%02x%02x%02x%02x",
				            hostInfo.mac[0], hostInfo.mac[1], hostInfo.mac[2], hostInfo.mac[3], hostInfo.mac[4], hostInfo.mac[5]);
				break;

			}
		}
	}

	fclose(fp);
}

static int find_sta_mac(unsigned char *cpeMac, struct _wlan_status *sta_list)
{
    int i = 0;

    while (sta_list[i].check) {
        if (!memcmp(cpeMac, sta_list[i].addr, 6))
            return i + 1;
        i++;
    }

    return 0;
}

void match_wlmac_traffic(int cpeNum, unsigned long *outByte, unsigned long *inByte, struct _wlan_status *now, struct _wlan_status *pre, char *cpeMac, int len, char *hostname, int h_len)
{
    int index = 0;

	memset(cpeMac, 0, len);
	memset(hostname, 0, h_len);

    if ((index = find_sta_mac(&now[cpeNum].addr[0], pre))) {
        if (now[cpeNum].wlanOutBytes >= pre[index - 1].wlanOutBytes)
            *outByte = now[cpeNum].wlanOutBytes - pre[index - 1].wlanOutBytes;
        else
            *outByte = now[cpeNum].wlanOutBytes;
        if (now[cpeNum].wlanInBytes >= pre[index - 1].wlanInBytes)
            *inByte = now[cpeNum].wlanInBytes - pre[index - 1].wlanInBytes;
        else
            *inByte = now[cpeNum].wlanInBytes;
    }

    if (index == 0) {
        *outByte = now[cpeNum].wlanOutBytes;
        *inByte = now[cpeNum].wlanInBytes;
    }

	get_sta_hostname(now[cpeNum].addr, hostname, h_len);
    snprintf(cpeMac, len, "%02x%02x%02x%02x%02x%02x",
            now[cpeNum].addr[0], now[cpeNum].addr[1],
            now[cpeNum].addr[2], now[cpeNum].addr[3],
            now[cpeNum].addr[4], now[cpeNum].addr[5]);
}

#if DV_MALLOC
static int dv_mem_count = 0;

void *dv_malloc(size_t size)
{
    dv_mem_count++;
    printf ("dv_mem_count=%d\n", dv_mem_count);
    return malloc(size);
}

void dv_free(void *ptr)
{
    dv_mem_count--;
    printf ("dv_mem_count=%d\n", dv_mem_count);
    return free(ptr);
}
#endif
