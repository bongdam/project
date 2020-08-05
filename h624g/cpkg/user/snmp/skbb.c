/* General includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>
#include <signal.h>
#include <shutils.h>
/* SNMP includes */
#include "./engine/asn1.h"
#include "./engine/snmp.h"
#include "./engine/agt_mib.h"
#include "./engine/agt_engine.h"
#include "misc.h"

#include "skbb.h"
#include "skbb_api.h"
#include "../include/brdio.h"
#include "snmp_main.h"
#include "apmib_defs.h"
#include "apmib.h"
#include <bcmnvram.h>
#include <8192cd.h>

extern int snmpAction;
extern int root_vwlan_disable[MAX_WLAN_INTF_NUM][2];
extern int dns_mode;

static int scan_num = -1;
static int scan_num_5g = -1;
GB public_mib_buffer;
void register_subtrees_of_SKBB_MIB();
char *DevPortName[MAX_PORT] = { "LAN1", "LAN2", "LAN3", "LAN4", "WAN" };
extern portfw_tblnum;

static void insert_oid_to_global_array(oid a[], int size)
{
	int i;

	for (i = 0; i < size; i++) {
		public_mib_buffer.gb_oid[i] = a[i];
	}
}

/* SKBB_MIB initialisation (must also register the MIB module tree) */
void init_SKBB_MIB()
{
	register_subtrees_of_SKBB_MIB();
}



/* Unidata Communication Systems, Inc.
 */
/* wlan scan info */
#define SIOCGIWRTLSCANREQ           0x8B33  // scan request
#define SIOCGIWRTLGETBSSDB          0x8B34  // get bss data base
#define SIOCGIWRTLGETBSSINFO        0x8B37  // get currnet bss info

#if 0
static int get_wlsitesurvey_request_snmp(char *interface, int *pStatus)
{
    int skfd;
    struct iwreq wrq;
    unsigned char result;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(skfd==-1)
        return -1;

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
      close( skfd );
      /* If no wireless name : no wireless extensions */
      return -1;
    }

    wrq.u.data.pointer = (caddr_t)&result;
    wrq.u.data.length = sizeof(result);

    if (iw_get_ext(skfd, interface, SIOCGIWRTLSCANREQ, &wrq) < 0) {
      close( skfd );
      return -1;
    }
    close( skfd );

    if ( result == 0xff )
        *pStatus = -1;
    else
        *pStatus = (int) result;

    return 0;
}

int get_wlbss_info_snmp(char *interface, bss_info *pInfo)
{
    int skfd;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(skfd==-1)
        return -1;

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
        /* If no wireless name : no wireless extensions */
        close( skfd );

        return -1;
    }

    wrq.u.data.pointer = (caddr_t)pInfo;
    wrq.u.data.length = sizeof(bss_info);

    if (iw_get_ext(skfd, interface, SIOCGIWRTLGETBSSINFO, &wrq) < 0) {
        close( skfd );
        return -1;
    }
    close( skfd );

    return 0;
}
#endif
static int get_wlsitesurvey_result_snmp(char *interface, void *param, int justStatus)
{
    int skfd;
    struct iwreq wrq;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(skfd==-1)
        return -1;

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
        /* If no wireless name : no wireless extensions */
        close( skfd );

        return -1;
    }
    wrq.u.data.pointer = (caddr_t)param;
    wrq.u.data.length = (justStatus)? sizeof(unsigned char):sizeof(SS_STATUS_T);
    if (iw_get_ext(skfd, interface, SIOCGIWRTLGETBSSDB, &wrq) < 0) {
        close( skfd );
        return -1;
    }
    close( skfd );

    return 0;
}

extern int percentToDbm(int percent);

#define WLAN_INTF(x) (x==0)?"wlan0": "wlan1"
int getWlanScanInfo(int wl_idx, wlan_scan_info* wlInfo)
{
    BssDscr *pBss;
    SS_STATUS_T wl_staInfo;
    char mode_buf[80];
    int wpa_exist = 0, idx = 0;
    int i = -1;

	memset(&wl_staInfo, 0, sizeof(wl_staInfo));
    wl_staInfo.number = 0; // request BSS DB

	if ( get_wlsitesurvey_result_snmp(WLAN_INTF(wl_idx), &wl_staInfo, 0) < 0 ) {
		return -1;
	}

    for (i=0; i < wl_staInfo.number && wl_staInfo.number!= 0xff; i++) {
        pBss = &wl_staInfo.bssdb[i];
        idx = 0;
        wpa_exist = 0;
        mode_buf[0]=0;
        //ssid(string)
        memcpy(wlInfo[i].ssid, pBss->bdSsIdBuf, pBss->bdSsId.Length);
        wlInfo[i].ssid[pBss->bdSsId.Length] = '\0';

        //bssid(string)
        memcpy(&wlInfo[i].bssid[0], &pBss->bdBssId[0], 6);
        //channel(string)
        if (pBss->network==BAND_11B)
            strcpy(mode_buf, (" (B)"));
        else if (pBss->network==BAND_11G)
            strcpy(mode_buf, (" (G)"));
        else if (pBss->network==(BAND_11G|BAND_11B))
            strcpy(mode_buf, (" (B+G)"));
        else if (pBss->network==(BAND_11N))
            strcpy(mode_buf, (" (N)"));
        else if (pBss->network==(BAND_11G|BAND_11N))
            strcpy(mode_buf, (" (G+N)"));
        else if (pBss->network==(BAND_11G|BAND_11B | BAND_11N))
            strcpy(mode_buf, (" (B+G+N)"));
        else if(pBss->network== BAND_11A)
            strcpy(mode_buf, (" (A)"));
        else if(pBss->network== BAND_11N)
            strcpy(mode_buf, (" (N)"));
		else if(pBss->network== (BAND_11A | BAND_11N))
			strcpy(mode_buf, (" (A+N)"));
		else if(pBss->network== (BAND_5G_11AC | BAND_11N))
			strcpy(mode_buf, (" (AC+N)"));
		else if(pBss->network== (BAND_11A | BAND_5G_11AC))
			strcpy(mode_buf, (" (A+AC)"));
		else if(pBss->network== (BAND_11A |BAND_11N | BAND_5G_11AC))
			strcpy(mode_buf, (" (A+N+AC)"));
        else
            strcpy(mode_buf, (""));

        sprintf(wlInfo[i].channel, "%d%s", pBss->ChannelNumber, mode_buf);
        //encrypt(string)
        mode_buf[0]=0;
        if ((pBss->bdCap & 0x10) == 0) {

            sprintf(&mode_buf[0], "NONE");
		} else {
            if (pBss->bdTstamp[0] == 0) {
                sprintf(&mode_buf[0], "WEP");
			} else {
                int wpa_exist = 0, idx = 0;
                if (pBss->bdTstamp[0] & 0x0000ffff) {
                    idx = sprintf(&mode_buf[0], "WPA");
                    if (((pBss->bdTstamp[0] & 0x0000f000) >> 12) == 0x4) {
                        idx += sprintf(&mode_buf[idx], "-PSK");
					}
                    wpa_exist = 1;
                }
                if (pBss->bdTstamp[0] & 0xffff0000) {
                    if (wpa_exist) {
                        idx += sprintf(&mode_buf[idx], "/");
					}
                    idx += sprintf(mode_buf+idx, "WPA2");
                    if (((pBss->bdTstamp[0] & 0xf0000000) >> 28) == 0x4) {
                        idx += sprintf(&mode_buf[idx], "-PSK");
					}
                }
            }
        }
        sprintf(&wlInfo[i].encrypt[0], "%s", &mode_buf[0]);
        //rssi(string)
        sprintf(&wlInfo[i].rssi[0], "%d", CONV_TO_RSSI(pBss->rssi));
    }
	if (i == 0)
		return -1;

    return i;
}

int set_wlanScanDoit(int w_index, int val)
{
	FILE *fp;
	int webPid;
	char buf[80];

	if (val == 1) {
		fp = fopen("/var/run/webs.pid", "r");
		if (fp) {
			if ( fgets(buf, sizeof(buf), fp)) {
				webPid = atoi(buf);
				if (webPid != 0) {
					if(w_index == 0) {
						scan_num_5g = -1;
						kill(webPid, SIGUSR1);
					} else {
						scan_num = -1;
						kill(webPid, SIGUSR2);
					}
				}
			}
			fclose(fp);
		}
		return 0;
	}
	return SNMP_ERROR_WRONGVALUE;
}

long get_wlanScanDoit(void)
{
	return 0;
}

unsigned char *var_wlanScanActiveStatusView(int *var_len, Oid * newoid, Oid * reqoid,
						int searchType, snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int ii = newoid->namelen++;
	int idx = 1;
	wlan_scan_info wlInfo[65];
	int sta_idx;
	int web_wlscan_update;

	web_wlscan_update = access("/var/web_wlscan1", F_OK);
	if (scan_num == -1 || web_wlscan_update == 0) {
		if (!web_wlscan_update)
			unlink("/var/web_wlscan1");

		memset(wlInfo, 0, sizeof(wlInfo));
		scan_num = getWlanScanInfo(1, &wlInfo[0]);
	}

	if (scan_num == -1)
		return NO_MIBINSTANCE;

	while (idx <= scan_num) {
		newoid->name[ii] = idx;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		idx++;
	}
	if ( (sta_idx = (idx -1)) < 0)
		sta_idx = 0;

	if (scan_num == 0)
		scan_num = -1;

	if (idx > scan_num)
		return NO_MIBINSTANCE;

	if (idx == scan_num)
		scan_num = -1;

	switch(column) {
		case I_SHUBWLANSCANACTIVEINDEX:
			public_mib_buffer.gb_long = idx;
			*var_len = sizeof(long);
			return (unsigned char *)&public_mib_buffer.gb_long;
		case I_SHUBWLANSCANACTIVESSID:
			sprintf(public_mib_buffer.gb_string, "%s", &wlInfo[sta_idx].ssid[0]);
			*var_len = strlen(public_mib_buffer.gb_string);
			return (unsigned char*)public_mib_buffer.gb_string;
		case I_SHUBWLANSCANACTIVEBSSID:
			memcpy(&public_mib_buffer.gb_string[0], &wlInfo[sta_idx].bssid[0], 6);
			*var_len = 6;
			return (unsigned char*)public_mib_buffer.gb_string;
		case I_SHUBWLANSCANACTIVECHANNEL:
			sprintf(&public_mib_buffer.gb_string[0], "%s", &wlInfo[sta_idx].channel[0]);
			*var_len = strlen(public_mib_buffer.gb_string);
			return (unsigned char*)public_mib_buffer.gb_string;
		case I_SHUBWLANSCANACTIVEENCRYPT:
			sprintf(&public_mib_buffer.gb_string[0], "%s", &wlInfo[sta_idx].encrypt[0]);
			*var_len = strlen(public_mib_buffer.gb_string);
			return (unsigned char*)public_mib_buffer.gb_string;
		case I_SHUBWLANSCANACTIVERSSI:
			sprintf(&public_mib_buffer.gb_string[0], "%s", &wlInfo[sta_idx].rssi[0]);
			*var_len = strlen(public_mib_buffer.gb_string);
			return (unsigned char*)public_mib_buffer.gb_string;
		default:
			return (unsigned char *)NO_MIBINSTANCE;
	}
	return NO_MIBINSTANCE;
}

unsigned char *var_wlanScanActiveStatusView_5g(int *var_len, Oid * newoid,
						Oid * reqoid, int searchType,
						snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int ii = newoid->namelen++;
	int idx = 1;
	wlan_scan_info wlInfo[65];
	int sta_idx;
	int web_wlscan_update;

	web_wlscan_update = access("/var/web_wlscan0", F_OK);
	if (scan_num_5g == -1 || web_wlscan_update == 0) {
		if (!web_wlscan_update)
			unlink("/var/web_wlscan0");

		memset(wlInfo, 0, sizeof(wlInfo));
		scan_num_5g = getWlanScanInfo(0, &wlInfo[0]);
	}

	if (scan_num_5g == -1)
		return NO_MIBINSTANCE;

	while (idx <= scan_num_5g) {
		newoid->name[ii] = idx;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		idx++;
	}
	if ( (sta_idx = (idx -1)) < 0)
		sta_idx = 0;

	if (scan_num_5g == 0)
		scan_num_5g = -1;

	if (idx > scan_num_5g)
		return NO_MIBINSTANCE;

	if (idx == scan_num_5g)
		scan_num_5g = -1;

	switch(column) {
		case I_SHUBWLANSCANACTIVEINDEX_5g:
			public_mib_buffer.gb_long = idx;
			*var_len = sizeof(long);
			return (unsigned char *)&public_mib_buffer.gb_long;
		case I_SHUBWLANSCANACTIVESSID_5g:
			sprintf(public_mib_buffer.gb_string, "%s", &wlInfo[sta_idx].ssid[0]);
			*var_len = strlen(public_mib_buffer.gb_string);
			return (unsigned char*)public_mib_buffer.gb_string;
		case I_SHUBWLANSCANACTIVEBSSID_5g:
			memcpy(&public_mib_buffer.gb_string[0], &wlInfo[sta_idx].bssid[0], 6);
			*var_len = 6;
			return (unsigned char*)public_mib_buffer.gb_string;
		case I_SHUBWLANSCANACTIVECHANNEL_5g:
			sprintf(&public_mib_buffer.gb_string[0], "%s", &wlInfo[sta_idx].channel[0]);
			*var_len = strlen(public_mib_buffer.gb_string);
			return (unsigned char*)public_mib_buffer.gb_string;
		case I_SHUBWLANSCANACTIVEENCRYPT_5g:
			sprintf(&public_mib_buffer.gb_string[0], "%s", &wlInfo[sta_idx].encrypt[0]);
			*var_len = strlen(public_mib_buffer.gb_string);
			return (unsigned char*)public_mib_buffer.gb_string;
		case I_SHUBWLANSCANACTIVERSSI_5g:
			sprintf(&public_mib_buffer.gb_string[0], "%s", &wlInfo[sta_idx].rssi[0]);
			*var_len = strlen(public_mib_buffer.gb_string);
			return (unsigned char*)public_mib_buffer.gb_string;
		default:
			return (unsigned char *)NO_MIBINSTANCE;
	}
	return NO_MIBINSTANCE;
}

int write_delete_syslog(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
    switch (action) {
    case RESERVE1:
        break;
    case RESERVE2:
        break;
    case COMMIT:
        return set_delete_syslog((int)mhtol(var_val, var_val_len));
        break;
    case ACTION:
        break;
    case FREE:
        break;
    }

    return (0);
}

unsigned char *var_cpu_utilization(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
    public_mib_buffer.gb_long = get_cpu_utiliz();
    *write_method = 0;
    /* Set size (in bytes) and return address of the variable */
    *var_len = sizeof(public_mib_buffer.gb_long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_ram_utilization(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
    public_mib_buffer.gb_long = get_ram_utiliz();
    *write_method = 0;
    /* Set size (in bytes) and return address of the variable */
    *var_len = sizeof(public_mib_buffer.gb_long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_flash_utilization(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
    public_mib_buffer.gb_long = get_flash_utiliz();
    *write_method = 0;
    /* Set size (in bytes) and return address of the variable */
    *var_len = sizeof(public_mib_buffer.gb_long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_delete_system_log(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
    public_mib_buffer.gb_long = 0;
    *write_method = (int (*)())&write_delete_syslog;
    /* Set size (in bytes) and return address of the variable */
    *var_len = sizeof(public_mib_buffer.gb_long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_manufacturer(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	get_manufacturer(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));

	/* Set size (in bytes) and return address of the variable */
	*var_len = strlen(public_mib_buffer.gb_string);
	return (unsigned char *)public_mib_buffer.gb_string;
}

/* model name
 */

unsigned char *var_modelName(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	get_modelName(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));

	/* Set size (in bytes) and return address of the variable */
	*var_len = strlen(public_mib_buffer.gb_string);
	return (unsigned char *)public_mib_buffer.gb_string;
}

/* Version Number
 */

unsigned char *var_version(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	get_version(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));

	/* Set size (in bytes) and return address of the variable */
	*var_len = strlen(public_mib_buffer.gb_string);
	return (unsigned char *)public_mib_buffer.gb_string;
}

int write_wanMode(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_wanMethod((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_wanIpAddress(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_wanIpAddress(var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_wanSubnetMask(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_wanSubnetMask(var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_wanDefaultGW(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_wanDefaultGW(var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_wanDNS2(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int ret = 1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wanDNS2(var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_DNSMode(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_DNSMode((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_DNSMethod(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_DNSMethod((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}
/* MAC address
 */

unsigned char *var_wanMacAddress(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	get_mac(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));

	/* Set size (in bytes) and return address of the variable */
	*var_len = 6;

	return (unsigned char *)public_mib_buffer.gb_string;
}

/* WAN Optained IP Method */
unsigned char *var_wanMode(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wanMethod();
	*write_method = (int (*)())&write_wanMode;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(public_mib_buffer.gb_long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

/* WAN IP address
 */

unsigned char *var_wanIpAddress(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{

	/* Add value computations */
	get_wanIpAddress(&public_mib_buffer.gb_long, NON_STRING_TYPE);
	*write_method = 0;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(public_mib_buffer.gb_long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_wanIpAddrSet(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	get_wanIpAddress(&public_mib_buffer.gb_long, NON_STRING_TYPE);
	*write_method = (int (*)())&write_wanIpAddress;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(public_mib_buffer.gb_long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_wanDefGateway(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	get_gwIpAddress(&public_mib_buffer.gb_long, NON_STRING_TYPE);

	*write_method = (int (*)())&write_wanDefaultGW;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(public_mib_buffer.gb_long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_wanSubnetMask(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	get_wanSubnetMask(&public_mib_buffer.gb_long, NON_STRING_TYPE);
	*write_method = (int (*)())&write_wanSubnetMask;
	*var_len = sizeof(public_mib_buffer.gb_long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_wanDNS1(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	get_dnsAddress(&public_mib_buffer.gb_long, 1, NON_STRING_TYPE);
	*write_method = 0;
	*var_len = sizeof(public_mib_buffer.gb_long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_wanDNS2(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	get_dnsAddress(&public_mib_buffer.gb_long, 2, NON_STRING_TYPE);
	*write_method = (int (*)())&write_wanDNS2;
	*var_len = sizeof(public_mib_buffer.gb_long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_wanDNSMode(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_DNSMode();
	*write_method = (int (*)())&write_DNSMode;
	*var_len = sizeof(public_mib_buffer.gb_long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_wanDNSMethod(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = dns_mode + 1;
	*write_method = (int (*)())&write_DNSMethod;
	*var_len = sizeof(public_mib_buffer.gb_long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_entry(int *var_len, Oid * newoid, Oid * reqoid, int searchType, snmp_info_t * mesg, int (**write_method) ())
{
	/* Last subOID of COLUMNAR OID is column */
//  int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen;        //, i = 0;

	newoid->name[index] = 0;
	newoid->namelen = index + 1;

	/* Determine whether it is the requested OID  */
	result = compare(reqoid, newoid);

	if (((searchType == EXACT) && (result != 0)) || ((searchType == NEXT) && (result >= 0))) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	/* Set write-function */
	*write_method = 0;

	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_sysDescript(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	char *buf = public_mib_buffer.gb_string;

	gethostname(buf, MAX_SNMP_STR);
	strcat(buf, " Home Gateway");

	*write_method = 0;
	*var_len = strlen(public_mib_buffer.gb_string);

	return (unsigned char*)public_mib_buffer.gb_string;
}

unsigned int *var_sysUptime(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	struct sysinfo info;

	sysinfo(&info);

	*write_method = 0;
	public_mib_buffer.gb_long = info.uptime * 100;
	*var_len = sizeof(long);

	return (unsigned int *)&public_mib_buffer.gb_long;
}

int write_sysName(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_sysName(var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_sysName(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{

	char *buf = public_mib_buffer.gb_string;
	snprintf(buf, sizeof(public_mib_buffer.gb_string), "%s", getValue("HOST_NAME"));
	if (buf[0] == '\0')
		gethostname(buf, MAX_SNMP_STR);

	*write_method = (int (*)())&write_sysName;
	*var_len = strlen(public_mib_buffer.gb_string);

	return (unsigned char*)public_mib_buffer.gb_string;
}

int write_sysLocation(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		setValue("x_sysLocation", (char*)var_val);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return 0;
}

unsigned char *var_sysLocation(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	char *buf = public_mib_buffer.gb_string;

	strcpy(buf, getValue("x_sysLocation"));
	*write_method = (int (*)())&write_sysLocation;
	*var_len = strlen(public_mib_buffer.gb_string);

	return (unsigned char*)public_mib_buffer.gb_string;
}

unsigned char *var_sysObjectID(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	oid sysObjectID_value[] = { O_skbbEntry };
	insert_oid_to_global_array(sysObjectID_value, sizeof(sysObjectID_value));

	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(sysObjectID_value);

	return (unsigned char *)public_mib_buffer.gb_oid;
}

static oid system_oid[] = { O_system };

static Object system_variables[] = {
	{SNMP_STRING, (RONLY | SCALAR), var_sysDescript,
	 {1, {1}}},
	{SNMP_OBJID, (RONLY | SCALAR), var_sysObjectID,
	 {1, {2}}},
	{SNMP_TIMETICKS, (RONLY | SCALAR), var_sysUptime,
	 {1, {3}}},
	{SNMP_STRING, (RWRITE | SCALAR), var_sysName,
	 {1, {5}}},
	{SNMP_STRING, (RWRITE | SCALAR), var_sysLocation,
	 {1, {6}}},
	{0}
};

static SubTree system_tree = { NULL, system_variables,
	(sizeof(system_oid) / sizeof(oid)), system_oid
};

int write_ifAdminStatus(int action, unsigned char *var_val,
				unsigned char varval_type,
				int var_val_len, unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int port_index = reqOid->name[(reqOid->namelen - 1)];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_portPower(port_index, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_portView(int *var_len, Oid * newoid, Oid * reqoid, int searchType, snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen++;
	int port_index = 0;
	while (port_index < MAX_PORT) {
		newoid->name[index] = port_index;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		port_index++;
	}
	if (port_index >= MAX_PORT) {
		return (unsigned char *)NO_MIBINSTANCE;
	}
	*write_method = 0;

	switch (column) {
	case I_ifIndex:
		public_mib_buffer.gb_long = port_index + 1;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_ifDescr:
		strcpy(public_mib_buffer.gb_string, DevPortName[port_index_change(port_index)]);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char *)public_mib_buffer.gb_string;
	case I_ifSpeed:
		public_mib_buffer.gb_long = get_portSpeed(port_index);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_ifPhyAddr:
		getPortMac(port_index, public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_ifAdminStatus:
		public_mib_buffer.gb_long = get_portPower(port_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_ifAdminStatus;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_ifOperStatus:
		result = get_lanStatus(port_index);
		if (result == 1)
			public_mib_buffer.gb_long = 1;
		else if (result == 0)
			public_mib_buffer.gb_long = 2;
		else
			public_mib_buffer.gb_long = 4;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_ifLastChange:
		public_mib_buffer.gb_long = get_lastChanged_time(port_index_change(port_index));
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_ifInOctets:
		public_mib_buffer.gb_long = get_portStatus(port_index, 1);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_ifInErrors:
		public_mib_buffer.gb_long = get_portStatus(port_index, 3);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_ifOutOctets:
		public_mib_buffer.gb_long = get_portStatus(port_index, 2);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}

static oid portTable_oid[] = { 1, 3, 6, 1, 2, 1, 2, 2 };

static Object portTable_var[] = {
	{SNMP_INTEGER, (RONLY | COLUMN), var_portView,
	 {2, {1, I_ifIndex}}},
	{SNMP_STRING, (RONLY | COLUMN), var_portView,
	 {2, {1, I_ifDescr}}},
	{SNMP_GAUGE, (RONLY | COLUMN), var_portView,
	 {2, {1, I_ifSpeed}}},
	{SNMP_STRING, (RONLY | COLUMN), var_portView,
	 {2, {1, I_ifPhyAddr}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_portView,
	 {2, {1, I_ifAdminStatus}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_portView,
	 {2, {1, I_ifOperStatus}}},
	{SNMP_TIMETICKS, (RONLY | COLUMN), var_portView,
	 {2, {1, I_ifLastChange}}},
	{SNMP_COUNTER, (RONLY | COLUMN), var_portView,
	 {2, {1, I_ifInOctets}}},
	{SNMP_COUNTER, (RONLY | COLUMN), var_portView,
	 {2, {1, I_ifInErrors}}},
	{SNMP_COUNTER, (RONLY | COLUMN), var_portView,
	 {2, {1, I_ifOutOctets}}},
	{ 0 }
};

static SubTree portTable_tree = { NULL, portTable_var,
	(sizeof(portTable_oid) / sizeof(oid)), portTable_oid
};

static oid systemInfo_oid[] = { O_SystemInfo };

static Object systemInfo_variables[] = {
	{SNMP_STRING, (RONLY | SCALAR), var_modelName,
	 {1, {I_modelName}}},
	{SNMP_STRING, (RONLY | SCALAR), var_version,
	 {1, {I_version}}},
	{ 0 }
};

static SubTree systemInfo_tree = { NULL, systemInfo_variables,
	(sizeof(systemInfo_oid) / sizeof(oid)), systemInfo_oid
};

static oid wanConfig_oid[] = { O_WanConfig };

static Object wanConfig_var[] = {
	{SNMP_STRING, (RONLY | SCALAR), var_wanMacAddress,
	 {1, {I_wanMacAddress}}},
	{SNMP_IPADDRESS, (RONLY | SCALAR), var_wanIpAddress,
	 {1, {I_wanIpAddress}}},
	{SNMP_IPADDRESS, (RONLY | SCALAR), var_wanSubnetMask,
	 {1, {I_wanSubnetMask}}},
	{SNMP_IPADDRESS, (RONLY | SCALAR), var_wanDefGateway,
	 {1, {I_wanDefGateway}}},
	{SNMP_IPADDRESS, (RONLY | SCALAR), var_wanDNS1,
	 {1, {I_wanDNS1}}},
	{SNMP_IPADDRESS, (RONLY | SCALAR), var_wanDNS2,
	 {1, {I_wanDNS2}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wanMode,
	 {2, {I_wanSetup, I_wanObtainIpMethod}}},
	{SNMP_IPADDRESS, (RWRITE | SCALAR), var_wanIpAddrSet,
	 {2, {I_wanSetup, I_wanIpAddresSet}}},
	{SNMP_IPADDRESS, (RWRITE | SCALAR), var_wanSubnetMask,
	 {2, {I_wanSetup, I_wanSubnetMaskSet}}},
	{SNMP_IPADDRESS, (RWRITE | SCALAR), var_wanDefGateway,
	 {2, {I_wanSetup, I_wanDefaultGWSet}}},
#if 0	/* Unuse oid delete */
	{SNMP_IPADDRESS, (RONLY | SCALAR), var_wanDNS1,
	 {2, {I_wanSetup, I_wanDNS1Set}}},
#endif
	{SNMP_IPADDRESS, (RWRITE | SCALAR), var_wanDNS2,
	 {2, {I_wanSetup, I_wanDNS2Set}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wanDNSMode,
	 {2, {I_wanSetup, I_wanDNSMode}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wanDNSMethod,
	 {2, {I_wanSetup, I_wanDNSMethod}}},
	{ 0 }
};

static SubTree wanConfig_tree = { NULL, wanConfig_var,
	(sizeof(wanConfig_oid) / sizeof(oid)), wanConfig_oid
};

unsigned char *var_lanMacAddress(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{

	get_lanMac(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));

	/* Set size (in bytes) and return address of the variable */
	*var_len = 6;

	return (unsigned char *)&public_mib_buffer.gb_string;
}

/* LAN IP address
 */
int write_lanIPAddress(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_lanIPAddress(var_val, var_val_len, name);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

unsigned char *var_lanIPAddress(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	get_lanIpAddress(&public_mib_buffer.gb_long, NON_STRING_TYPE);

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_lanIPAddress;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

/* dhcp server
 */
int write_dhcpServer(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_dhcpServer((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_dhcpServer(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = get_dhcpServer();

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_dhcpServer;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanResetMode(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanResetMode((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanState(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = get_wlanResetMode();

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_wlanResetMode;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanReset(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanReset((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanReset(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = 0;

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_wlanReset;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_lanSubnetMask(int action,
						unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_lanSubnetMask(var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}


unsigned char *var_lanSubnetMask(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	get_lanSubnetMask(&public_mib_buffer.gb_long, NON_STRING_TYPE);

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_lanSubnetMask;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

/* IP pool  start address
 */
int write_ipPoolStartAddress(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_ipPoolStartAddress((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_ipPoolStartAddress(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	get_ipPoolStartAddress(&public_mib_buffer.gb_long);

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_ipPoolStartAddress;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

/* IP pool end address
 */
int write_ipPoolEndAddress(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_ipPoolEndAddress((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_ipPoolEndAddress(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	get_ipPoolEndAddress(&public_mib_buffer.gb_long);

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_ipPoolEndAddress;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

static oid lanConfig_oid[] = { O_LanConfig };

static Object lanConfig_var[] = {
	{SNMP_STRING, (RONLY | SCALAR), var_lanMacAddress,
	 {1, {I_lanMacAddress}}},
	{SNMP_IPADDRESS, (RONLY | SCALAR), var_lanIPAddress,
	 {1, {I_lanIpAddress}}},
	{SNMP_IPADDRESS, (RONLY | SCALAR), var_lanSubnetMask,
	 {1, {I_lanSubnetMask}}},
	{SNMP_IPADDRESS, (RWRITE | SCALAR), var_lanIPAddress,
	 {2, {I_lanSetup, I_lanIpAddressSet}}},
	{SNMP_IPADDRESS, (RWRITE | SCALAR), var_lanSubnetMask,
	 {2, {I_lanSetup, I_lanSubnetMaskSet}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_dhcpServer,
	 {2, {I_lanSetup, I_lanDhcpEnable}}},
	{SNMP_IPADDRESS, (RWRITE | SCALAR), var_ipPoolStartAddress,
	 {2, {I_lanSetup, I_lanDhcpStartIp}}},
	{SNMP_IPADDRESS, (RWRITE | SCALAR), var_ipPoolEndAddress,
	 {2, {I_lanSetup, I_lanDhcpEndIp}}},
	 {SNMP_INTEGER, (RWRITE | SCALAR), var_wlanState,
	 {2, {I_lanSetup, I_wlanState}}},
	 {SNMP_INTEGER, (RWRITE | SCALAR), var_wlanReset,
	 {2, {I_lanSetup, I_wlanReset}}},
	{ 0 }
};

static SubTree lanConfig_tree = { NULL, lanConfig_var,
	(sizeof(lanConfig_oid) / sizeof(oid)), lanConfig_oid
};

unsigned char *var_wlanMac(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	get_wlanMac(public_mib_buffer.gb_string, 1);

	*write_method = 0;

	*var_len = 6;
	return (unsigned char *)public_mib_buffer.gb_string;
}

int write_wlanMode(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanMode(1, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanMode(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanMode(1);

	*write_method = (int (*)())&write_wlanMode;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanBand(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanBand(1, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanBand(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanBand(1);

	*write_method = (int (*)())&write_wlanBand;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanChannelWidth(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanChannelWidth(1, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}
	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanChannelWidth(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanChannelWidth(1);

	*write_method = (int (*)())&write_wlanChannelWidth;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanCtrlSideBand(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanCtrlSideBand(1, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanCtrlSideBand(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanCtrlSideBand();

	*write_method = (int (*)())&write_wlanCtrlSideBand;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanChannelNumber(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanChannelNumber(1, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanChannelNumber(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanChannelNumber(1);

	*write_method = (int (*)())&write_wlanChannelNumber;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanDateRate(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanDateRate(1, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanDateRate(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanDateRate(1);

	*write_method = (int (*)())&write_wlanDateRate;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_wlan1session(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanSession(1);

	*write_method = 0;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlan1sessionLimit(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanSessionLimit(1, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlan1sessionLimit(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanSessionLimit(1);

	*write_method = (int (*)())&write_wlan1sessionLimit;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlan1autoband(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanAutoband(1, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlan1autoband(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanAutoband(1);

	*write_method = 0;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}


/* Set WLAN Configuration Table */
int write_wlanSSID(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int wl_index = name->name[(name->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_wlanSSID(1, (wl_index), var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_wlanSSIDMode(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int wl_index = name->name[(name->namelen - 1)];
	int ret=1;

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanSSIDMode(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_wlanBSSID(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int wl_index = name->name[(name->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_wlanBSSID(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_wlanSecEncryption(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int wl_index = name->name[(name->namelen - 1)];
	int ret=1;

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanSecEncryption(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_wlanRateLimit(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[reqOid->namelen - 1];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanRateLimit(1, wl_index, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanConfig(int *var_len, Oid * newoid,
				Oid * reqoid, int searchType,
				snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;

	int index = newoid->namelen++;
	int wl_index = 0;
	while (wl_index < 5) {
		newoid->name[index] = wl_index + 1;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		wl_index++;
	}
	if (wl_index >= 5) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	switch (column) {
	case I_wlanConfigIndex:
		public_mib_buffer.gb_long = wl_index + 1;
		*write_method = 0;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanSSID:
		get_wlanSSID(1, (wl_index), public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_wlanSSID;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_wlanSSIDMode:
		public_mib_buffer.gb_long = get_wlanSSIDMode(1, (wl_index));
		*write_method = (int (*)())&write_wlanSSIDMode;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanBcastSSIDMode:
		public_mib_buffer.gb_long = get_wlanBSSID(1, (wl_index));
		*write_method = (int (*)())&write_wlanBSSID;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanSecEncryption:
		public_mib_buffer.gb_long = get_wlanSecEncryption(1, (wl_index));
		*write_method = (int (*)())&write_wlanSecEncryption;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanRateLimit:
		public_mib_buffer.gb_long = get_wlanRateLimit(1, (wl_index));
		*write_method = (int (*)())&write_wlanRateLimit;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanTxInfo:
		public_mib_buffer.gb_long = get_data_size_converter(get_wlanTrafficInfo(1, (wl_index), "tx_only_data_bytes_high"), get_wlanTrafficInfo(1, (wl_index), "tx_only_data_bytes"));
		*write_method = 0;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanRxInfo:
		public_mib_buffer.gb_long = get_data_size_converter(get_wlanTrafficInfo(1, (wl_index), "rx_only_data_bytes_high"), get_wlanTrafficInfo(1, (wl_index), "rx_only_data_bytes"));
		*write_method = 0;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	default:
		return (unsigned char*)NO_MIBINSTANCE;
	}
	return NO_MIBINSTANCE;
}

int write_wlanEnable(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * reqOid)
{
	int ret=1;
 	int wl_index = reqOid->name[reqOid->namelen - 1];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
#if 0
		switch (ssid_no) {
		case 1:
			wl_index = 0;       // WiFixxx, wlan0
			break;
		case 2:                // VoIP,    wlan0-va1
			wl_index = 2;
			break;
		case 3:                // SMART,   wlan0-va2
			wl_index = 3;
			break;
		case 4:                // Anyway, wlan0-va0
			wl_index = 1;
			break;
		default:
			return SNMP_ERROR_WRONGVALUE;
		}
#endif
		ret = set_wlanSSIDMode(1, wl_index, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanMac_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	get_wlanMac(public_mib_buffer.gb_string, 0);

	*write_method = 0;

	*var_len = 6;
	return (unsigned char *)public_mib_buffer.gb_string;
}

int write_wlanMode_5g(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanMode(0, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanMode_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanMode(0);

	*write_method = (int (*)())&write_wlanMode_5g;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanBand_5g(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanBand(0, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanBand_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanBand(0);

	*write_method = (int (*)())&write_wlanBand_5g;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanChannelWidth_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanChannelWidth(0, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}
	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanChannelWidth_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanChannelWidth(0);

	*write_method = (int (*)())&write_wlanChannelWidth_5g;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanCtrlSideBand_5g(int action,
						   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_wlanCtrlSideBand(0, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanCtrlSideBand_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanCtrlSideBand_5g();

	*write_method = 0;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanChannelNumber_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanChannelNumber(0, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanChannelNumber_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanChannelNumber(0);

	*write_method = (int (*)())&write_wlanChannelNumber_5g;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanDateRate_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanDateRate(0, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanDateRate_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanDateRate(0);

	*write_method = (int (*)())&write_wlanDateRate_5g;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_wlan0session(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanSession(0);

	*write_method = 0;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlan0sessionLimit(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanSessionLimit(0, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlan0sessionLimit(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanSessionLimit(0);

	*write_method = (int (*)())&write_wlan0sessionLimit;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlan0autoband(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanAutoband(0, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlan0autoband(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanAutoband(0);

	*write_method = 0;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

/* Set WLAN Configuration Table */
int write_wlanSSID_5g(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int wl_index = name->name[(name->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_wlanSSID(0, (wl_index), var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_wlanSSIDMode_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int wl_index = name->name[(name->namelen - 1)];
	int ret=1;

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanSSIDMode(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_wlanBSSID_5g(int action,
					unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int wl_index = name->name[(name->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_wlanBSSID(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_wlanSecEncryption_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int wl_index = name->name[(name->namelen - 1)];
	int ret=1;

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanSecEncryption(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_wlanRateLimit_5g(int action,
						unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[reqOid->namelen - 1];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
#if 0
		switch (ssid_no) {
		case 1:
			wl_index = 0;       // WiFixxx, wlan0
			break;
		case 2:                // VoIP,    wlan0-va1
			wl_index = 2;
			break;
		case 3:                // SMART,   wlan0-va2
			wl_index = 3;
			break;
		case 4:                // Anyway, wlan0-va0
			wl_index = 1;
			break;
		default:
			return SNMP_ERROR_WRONGVALUE;
		}
#endif
		ret = set_wlanRateLimit(0, wl_index, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanConfig_5g(int *var_len, Oid * newoid,
				Oid * reqoid, int searchType,
				snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;

	int index = newoid->namelen++;
	int wl_index = 0;

	while (wl_index < 5) {
		newoid->name[index] = wl_index + 1;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		wl_index++;
	}
	if (wl_index >= 5) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	switch (column) {
	case I_wlanConfigIndex_5g:
		public_mib_buffer.gb_long = wl_index+1;
		*write_method = 0;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanSSID_5g:
		get_wlanSSID(0, (wl_index), public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_wlanSSID_5g;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_wlanSSIDMode_5g:
		public_mib_buffer.gb_long = get_wlanSSIDMode(0, (wl_index));
		*write_method = (int (*)())&write_wlanSSIDMode_5g;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanBcastSSIDMode_5g:
		public_mib_buffer.gb_long = get_wlanBSSID(0, (wl_index));
		*write_method = (int (*)())&write_wlanBSSID_5g;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanSecEncryption_5g:
		public_mib_buffer.gb_long = get_wlanSecEncryption(0, (wl_index));
		*write_method = (int (*)())&write_wlanSecEncryption_5g;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanRateLimit_5g:
		public_mib_buffer.gb_long = get_wlanRateLimit(0, (wl_index));
		*write_method = (int (*)())&write_wlanRateLimit_5g;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanTxInfo_5g:
		public_mib_buffer.gb_long = get_data_size_converter(get_wlanTrafficInfo(0, (wl_index), "tx_only_data_bytes_high"), get_wlanTrafficInfo(0, (wl_index), "tx_only_data_bytes"));
		*write_method = 0;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanRxInfo_5g:
		public_mib_buffer.gb_long = get_data_size_converter(get_wlanTrafficInfo(0, (wl_index), "rx_only_data_bytes_high"), get_wlanTrafficInfo(0, (wl_index), "rx_only_data_bytes"));
		*write_method = 0;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	default:
		return NO_MIBINSTANCE;
	}
	return NO_MIBINSTANCE;
}

int write_wlanEnable_5g(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[reqOid->namelen - 1];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
#if 0
		switch (ssid_no) {
		case 1:
			wl_index = 0;       // WiFixxx, wlan0
			break;
		case 2:                // VoIP,    wlan0-va1
			wl_index = 2;
			break;
		case 3:                // SMART,   wlan0-va2
			wl_index = 3;
			break;
		case 4:                // Anyway, wlan0-va0
			wl_index = 1;
			break;
		default:
			return SNMP_ERROR_WRONGVALUE;
		}
#endif
		ret = set_wlanSSIDMode(0, wl_index, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_wlanFragmentThreshold(int action,
		unsigned char *var_val, unsigned char varval_type, int var_val_len,
		unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanFragmentThreshold(1, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}


unsigned char *var_wlanFragmentThreshold(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanFragmentThreshold(1);

	*write_method = (int (*)())&write_wlanFragmentThreshold;

	*var_len = sizeof(long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanRTSThreshold(int action,
						   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanRTSThreshold(1 ,(int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanRTSThreshold(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanRTSThreshold(1);

	*write_method = (int (*)())&write_wlanRTSThreshold;

	*var_len = sizeof(long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanBeaconInterval(int action, unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanBeaconInterval(1, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanBeaconInterval(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanBeaconInterval(1);

	*write_method = (int (*)())&write_wlanBeaconInterval;

	*var_len = sizeof(long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

/* WLAN Preamble Type Configuration */
int write_wlanPreambleType(int action,
						   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanPreambleType(1, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanPreambleType(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanPreambleType(1);

	*write_method = (int (*)())&write_wlanPreambleType;

	*var_len = sizeof(long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

/* Wireless LAN IAPP Enable or Disable */
int write_wlanIAPPEnable(int action,
						 unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanIAPPEnable(1, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanIAPPEnable(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanIAPPEnable(1);

	*write_method = (int (*)())&write_wlanIAPPEnable;

	*var_len = sizeof(long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

/* Set Wireless LAN RF Output Power */
int write_wlanRFOutputPower(int action,
							unsigned char *var_val, unsigned char varval_type, int var_val_len,
							unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanRFOutputPower(1, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanRFOutputPower(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanRFOutputPower(1);

	*write_method = (int (*)())&write_wlanRFOutputPower;

	*var_len = sizeof(long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanFragmentThreshold_5g(int action,
		unsigned char *var_val, unsigned char varval_type, int var_val_len,
		unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanFragmentThreshold(0, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}


unsigned char *var_wlanFragmentThreshold_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanFragmentThreshold(0);

	*write_method = (int (*)())&write_wlanFragmentThreshold_5g;

	*var_len = sizeof(long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanRTSThreshold_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanRTSThreshold(0, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanRTSThreshold_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanRTSThreshold(0);

	*write_method = (int (*)())&write_wlanRTSThreshold_5g;

	*var_len = sizeof(long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanBeaconInterval_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanBeaconInterval(0, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanBeaconInterval_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanBeaconInterval(0);

	*write_method = (int (*)())&write_wlanBeaconInterval_5g;

	*var_len = sizeof(long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

/* WLAN Preamble Type Configuration */
int write_wlanPreambleType_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanPreambleType(0, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanPreambleType_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanPreambleType(0);

	*write_method = (int (*)())&write_wlanPreambleType_5g;

	*var_len = sizeof(long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

/* Wireless LAN IAPP Enable or Disable */
int write_wlanIAPPEnable_5g(int action,
						 unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanIAPPEnable(0, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanIAPPEnable_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanIAPPEnable(0);

	*write_method = (int (*)())&write_wlanIAPPEnable_5g;

	*var_len = sizeof(long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

/* Set Wireless LAN RF Output Power */
int write_wlanRFOutputPower_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wlanRFOutputPower(0, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_wlanRFOutputPower_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wlanRFOutputPower(0);

	*write_method = (int (*)())&write_wlanRFOutputPower_5g;

	*var_len = sizeof(long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

static oid wlanConfig_oid[] = { O_wlanConfig };

static Object wlanConfig_var[] = {
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanMode,
	 {2, {I_wlanBasicConfig, I_wlanMode}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanBand,
	 {2, {I_wlanBasicConfig, I_wlanBand}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanChannelWidth,
	 {2, {I_wlanBasicConfig, I_wlanChannelWidth}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanCtrlSideBand,
	 {2, {I_wlanBasicConfig, I_wlanControlSideband}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanChannelNumber,
	 {2, {I_wlanBasicConfig, I_wlanChannelNumber}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanDateRate,
	 {2, {I_wlanBasicConfig, I_wlanDateRate}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_wlanConfig,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable, I_wlanConfigEntry, I_wlanConfigIndex}}},
	{SNMP_STRING, (RWRITE | COLUMN), var_wlanConfig,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable, I_wlanConfigEntry, I_wlanSSID}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_wlanConfig,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable, I_wlanConfigEntry, I_wlanSSIDMode}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_wlanConfig,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable, I_wlanConfigEntry, I_wlanBcastSSIDMode}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_wlanConfig,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable, I_wlanConfigEntry, I_wlanSecEncryption}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_wlanConfig,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable, I_wlanConfigEntry, I_wlanRateLimit}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_wlanConfig,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable, I_wlanConfigEntry, I_wlanTxInfo}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_wlanConfig,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable, I_wlanConfigEntry, I_wlanRxInfo}}},
	{SNMP_STRING, (RONLY | SCALAR), var_wlanMac,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable, I_wlanConfigEntry, I_WlanMacAddress_2g}}},
	{SNMP_STRING, (RONLY | SCALAR), var_wlanMac_5g,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable, I_wlanConfigEntry, I_WlanMacAddress_5g}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanMode_5g,
	 {2, {I_wlanBasicConfig, I_wlanMode_5g}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanBand_5g,
	 {2, {I_wlanBasicConfig, I_wlanBand_5g}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanChannelWidth_5g,
	 {2, {I_wlanBasicConfig, I_wlanChannelWidth_5g}}},
	{SNMP_INTEGER, (RONLY | SCALAR), var_wlanCtrlSideBand_5g,
	 {2, {I_wlanBasicConfig, I_wlanCtrlSideband_5g}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanChannelNumber_5g,
	 {2, {I_wlanBasicConfig, I_wlanChannelNumber_5g}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanDateRate_5g,
	 {2, {I_wlanBasicConfig, I_wlanDateRate_5g}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_wlanConfig_5g,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable_5g, I_wlanConfigEntry_5g, I_wlanConfigIndex_5g}}},
	{SNMP_STRING, (RWRITE | COLUMN), var_wlanConfig_5g,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable_5g, I_wlanConfigEntry_5g, I_wlanSSID_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_wlanConfig_5g,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable_5g, I_wlanConfigEntry_5g, I_wlanSSIDMode_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_wlanConfig_5g,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable_5g, I_wlanConfigEntry_5g, I_wlanBcastSSIDMode_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_wlanConfig_5g,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable_5g, I_wlanConfigEntry_5g, I_wlanSecEncryption_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_wlanConfig_5g,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable_5g, I_wlanConfigEntry_5g, I_wlanRateLimit_5g}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_wlanConfig_5g,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable_5g, I_wlanConfigEntry_5g, I_wlanTxInfo_5g}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_wlanConfig_5g,
	 {4, {I_wlanBasicConfig, I_wlanConfigTable_5g, I_wlanConfigEntry_5g, I_wlanRxInfo_5g}}},
	{SNMP_INTEGER, (RONLY | SCALAR), var_wlan1session,
	 {2, {I_wlanBasicConfig, I_wlan1session}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlan1sessionLimit,
	 {2, {I_wlanBasicConfig, I_wlan1sessionLimit}}},
	{SNMP_INTEGER, (RONLY | SCALAR), var_wlan0session,
     {2, {I_wlanBasicConfig, I_wlan0session}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlan0sessionLimit,
	 {2, {I_wlanBasicConfig, I_wlan0sessionLimit}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlan1autoband,
	 {2, {I_wlanBasicConfig, I_wlan1autoband}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlan0autoband,
	 {2, {I_wlanBasicConfig, I_wlan0autoband}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanFragmentThreshold,
	 {2, {I_wlanAdvancedConfig, I_wlanFragmentThreshold}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanRTSThreshold,
	 {2, {I_wlanAdvancedConfig, I_wlanRTSThreshold}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanBeaconInterval,
	 {2, {I_wlanAdvancedConfig, I_wlanBeaconInterval}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanPreambleType,
	 {2, {I_wlanAdvancedConfig, I_wlanPreambleType}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanIAPPEnable,
	 {2, {I_wlanAdvancedConfig, I_wlanIAPPEnable}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanRFOutputPower,
	 {2, {I_wlanAdvancedConfig, I_wlanRFOutputPower}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanFragmentThreshold_5g,
	 {2, {I_wlanAdvancedConfig, I_wlanFragmentThreshold_5g}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanRTSThreshold_5g,
	 {2, {I_wlanAdvancedConfig, I_wlanRTSThreshold_5g}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanBeaconInterval_5g,
	 {2, {I_wlanAdvancedConfig, I_wlanBeaconInterval_5g}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanPreambleType_5g,
	 {2, {I_wlanAdvancedConfig, I_wlanPreambleType_5g}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanIAPPEnable_5g,
	 {2, {I_wlanAdvancedConfig, I_wlanIAPPEnable_5g}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wlanRFOutputPower_5g,
	 {2, {I_wlanAdvancedConfig, I_wlanRFOutputPower_5g}}},
	{ 0 }
};

static SubTree wlanConfig_tree = { NULL, wlanConfig_var,
	(sizeof(wlanConfig_oid) / sizeof(oid)), wlanConfig_oid
};


/* Security Configuration */
int write_secRadiusServerIP(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int index = name->name[name->namelen - 1];

	if(index!=0)
		index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_radiusServerIP(1, (index), var_val);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_secRadiusServerPort(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int index = name->name[name->namelen - 1];
	if(index!=0)
		index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_radiusPort(1, (index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_secRadiusPassword(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int index = name->name[name->namelen - 1];
	int ret=1;

	if(index!=0)
		index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_radiusPassword(1, (index), var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secAccountMode(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int index = name->name[name->namelen - 1];
	int ret = 1;
	if(index!=0)
		index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_radiusAccountMode(1, (index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secAccountServerIP(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int index = name->name[name->namelen - 1];
	if(index!=0)
		index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_radiusAccountServerIp(1, (index), var_val);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_secAccountServerPort(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int index = name->name[name->namelen - 1];
	if(index!=0)
		index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_radiusAccountServerPort(1, (index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_secAccountPassword(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int index = name->name[name->namelen - 1];
	int ret=1;
	if(index!=0)
		index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_radiusAccountServerPasswd(1, (index), var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_secConfig(int *var_len, Oid * newoid,
				Oid * reqoid, int searchType,
				snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;

	int index = newoid->namelen++;
	int wl_index = 0;
	int secMethod;

	while (wl_index < 5) {
		secMethod = get_wlanSecEncryption(1, (wl_index));
		if ( root_vwlan_disable[(wl_index)][1] == 0 &&
			 ((get_secWEP8021xAuthMode(1, (wl_index)) == 1) ||
				((secMethod == 3 || secMethod == 4) && ((get_secWPAxAuthMode(1, (wl_index))) == 1)) ||
				(secMethod == 5 && (get_secWPAmixAuthMode(1, (wl_index))) == 1))) {
			newoid->name[index] = wl_index + 1;
			result = compare(reqoid, newoid);
			if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
				break;
			}
		}
		wl_index++;
	}
	if (wl_index >= 5) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	switch (column) {
	case I_SecConfigSSIDIndex:
		public_mib_buffer.gb_long = wl_index + 1;
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecSSID:
		get_wlanSSID(1, (wl_index), public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = 0;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_SecRadiusServerIP:
		get_radiusServerIP(1, (wl_index), &public_mib_buffer.gb_long);
		*write_method = (int (*)())&write_secRadiusServerIP;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecRadiusServerPort:
		get_radiusPort(1, (wl_index), &public_mib_buffer.gb_long);
		*write_method = (int (*)())&write_secRadiusServerPort;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecRadiusServerPwd:
		get_radiusPassword(1, (wl_index), public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_secRadiusPassword;
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_SecAccountMode:
		public_mib_buffer.gb_long = get_radiusAccountMode(1, (wl_index));
		*write_method = (int (*)())&write_secAccountMode;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecAccountServerIP:
		get_radiusAccountServerIp(1, (wl_index), &public_mib_buffer.gb_long);
		*write_method = (int (*)())&write_secAccountServerIP;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecAccountServerPort:
		get_radiusAccountServerPort(1, (wl_index), &public_mib_buffer.gb_long);
		*write_method = (int (*)())&write_secAccountServerPort;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecAccountServerPwd:
		get_radiusAccountServerPasswd(1, (wl_index), public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_secAccountPassword;
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	default:
		return NO_MIBINSTANCE;
	}
	return NO_MIBINSTANCE;
}

/* Security Config - WEP */
int write_secWEP8021xAuthMode(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWEP8021xAuthMode(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPMacAuthMode(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWEPMacAuthMode(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPAuthMethod(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWEPAuthMethod(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPAuthKeySize(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWEPKeySize(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPAuthEnable(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWEPAuthEnable(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPKeyFormat(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWEPKeyFormat(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPEncryptionKey(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWEPEncryptionKey(1, (wl_index), var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPKeyIndex(int action, unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWEPKeyIndex(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_secWEPConfig(int *var_len, Oid * newoid, Oid * reqoid,
				int searchType, snmp_info_t * mesg,
				int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;

	int index = newoid->namelen++;
	int wl_index = 0;

	while (wl_index < 5) {
		if (root_vwlan_disable[(wl_index)][1] == 0 && get_wlanSecEncryption(1, (wl_index)) == 2) {
			newoid->name[index] = wl_index + 1;
			result = compare(reqoid, newoid);
			if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
				break;
			}
		}
		wl_index++;
	}
	if (wl_index >= 5) {
		return (unsigned char *)NO_MIBINSTANCE;
	}
	switch (column) {
	case I_SecWEPConfigSSIDIndex:
		public_mib_buffer.gb_long = wl_index + 1;
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWEPSecSSID:
		get_wlanSSID(1, (wl_index), public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = 0;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_SecWEP8021xAuthMode:
		public_mib_buffer.gb_long = get_secWEP8021xAuthMode(1, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEP8021xAuthMode;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWEPMacAuthMode:
		public_mib_buffer.gb_long = get_secWEPMacAuthMode(1, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEPMacAuthMode;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWEPAuthMethod:
		public_mib_buffer.gb_long = get_secWEPAuthMethod(1, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEPAuthMethod;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWEPAuthKeySize:
		public_mib_buffer.gb_long = get_secWEPKeySize(1, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEPAuthKeySize;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWEPAuthEnable:
		public_mib_buffer.gb_long = get_secWEPAuthEnable(1, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEPAuthEnable;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWEPKeyFormat:
		public_mib_buffer.gb_long = get_secWEPKeyFormat(1, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEPKeyFormat;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWEPEncryptionKey:
		get_secWEPEncryptionKey(1, (wl_index), public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_secWEPEncryptionKey;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_SecWEPKeyIndex:
		public_mib_buffer.gb_long = get_secWEPKeyIndex(1, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEPKeyIndex;
		return (unsigned char *)&public_mib_buffer.gb_long;
	default:
		return NO_MIBINSTANCE;
	}
	return NO_MIBINSTANCE;
}

//Security Settings: WPAx Configuration Functions
int write_secWPAxAuthMode(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAxAuthMode(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAxCipherSuite(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAxCipherSuite(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAxKeyFormat(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAxKeyFormat(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAxPreSharedKey(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAxPreSharedKey(1, (wl_index), var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_secWPAxConfig(int *var_len, Oid * newoid,
				Oid * reqoid, int searchType,
				snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;

	int index = newoid->namelen++;
	int wl_index = 0;
	int secMethod;

	while (wl_index < 5) {
		secMethod = get_wlanSecEncryption(1, (wl_index));
		if (root_vwlan_disable[(wl_index)][1] == 0 && (secMethod == 3 || secMethod == 4)) {
			newoid->name[index] = wl_index + 1;
			result = compare(reqoid, newoid);
			if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
				break;
			}
		}
		wl_index++;
	}
	if (wl_index >= 5) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	switch (column) {
	case I_SecWPAxConfigSSIDIndex:
		public_mib_buffer.gb_long = wl_index + 1;
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAxConfigSSID:
		get_wlanSSID(1, (wl_index), public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = 0;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_SecWPAxAuthMode:
		public_mib_buffer.gb_long = get_secWPAxAuthMode(1, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAxAuthMode;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAxCipherSuite:
		public_mib_buffer.gb_long = get_secWPAxCipherSuite(1, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAxCipherSuite;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAxKeyFormat:
		public_mib_buffer.gb_long = get_secWPAxKeyFormat(1, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAxKeyFormat;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAxPreSharedKey:
		get_secWPAxPreSharedKey(1, (wl_index), public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_secWPAxPreSharedKey;
		return (unsigned char*)public_mib_buffer.gb_string;
	default:
		return NO_MIBINSTANCE;
	}
	return NO_MIBINSTANCE;
}

//Security Settings: WPAmix Configuration Functions
int write_secWPAmixAuthMode(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAmixAuthMode(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAmixCipherSuite(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAmixCipherSuite(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAmix2CipherSuite(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAmix2CipherSuite(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAmixKeyFormat(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAmixKeyFormat(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAmixPreSharedKey(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAmixPreSharedKey(1, (wl_index), var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_secWPAmixConfig(int *var_len, Oid * newoid,
					Oid * reqoid, int searchType,
					snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;

	int index = newoid->namelen++;
	int wl_index = 0;

	while (wl_index < 5) {
		if (root_vwlan_disable[(wl_index)][1] == 0 && get_wlanSecEncryption(1, (wl_index)) == 5) {
			newoid->name[index] = wl_index + 1;
			result = compare(reqoid, newoid);
			if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
				break;
			}
		}
		wl_index++;
	}
	if (wl_index >= 5) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	switch (column) {
	case I_SecWPAmixConfigSSIDIndex:
		public_mib_buffer.gb_long = wl_index + 1;
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAmixSecSSID:
		get_wlanSSID(1, (wl_index), public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = 0;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_SecWPAmixAuthMode:
		public_mib_buffer.gb_long = get_secWPAmixAuthMode(1, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAmixAuthMode;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAmixCipherSuite:
		public_mib_buffer.gb_long = get_secWPAmixCipherSuite(1, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAmixCipherSuite;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAmix2CipherSuite:
		public_mib_buffer.gb_long = get_secWPAmix2CipherSuite(1, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAmix2CipherSuite;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAmixKeyFormat:
		public_mib_buffer.gb_long = get_secWPAmixKeyFormat(1, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAmixKeyFormat;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAmixPreSharedKey:
		get_secWPAmixPreSharedKey(1, (wl_index), public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_secWPAmixPreSharedKey;
		return (unsigned char*)public_mib_buffer.gb_string;
	default:
		return (unsigned char*)NO_MIBINSTANCE;
	}
	return (unsigned char*)NO_MIBINSTANCE;
}

/* Security Configuration 5g*/
int write_secRadiusServerIP_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int index = name->name[name->namelen - 1];

	if(index!=0)
		index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_radiusServerIP(0, (index), var_val);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_secRadiusServerPort_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
			  	unsigned char *statP, Oid * name)
{
	int index = name->name[name->namelen - 1];

	if(index!=0)
		index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_radiusPort(0, (index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_secRadiusPassword_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int index = name->name[name->namelen - 1];

	if(index!=0)
		index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_radiusPassword(0, (index), var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_secAccountMode_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int index = name->name[name->namelen - 1];

	if(index!=0)
		index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_radiusAccountMode(0, (index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_secAccountServerIP_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int index = name->name[name->namelen - 1];

	if(index!=0)
		index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_radiusAccountServerIp(0, (index), var_val);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_secAccountServerPort_5g(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int index = name->name[name->namelen - 1];

	if(index!=0)
		index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_radiusAccountServerPort(0, (index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

int write_secAccountPassword_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int index = name->name[name->namelen - 1];

	if(index!=0)
		index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_radiusAccountServerPasswd(0, (index), var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

unsigned char *var_secConfig_5g(int *var_len, Oid * newoid, Oid * reqoid, int searchType, snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;

	int index = newoid->namelen++;
	int wl_index = 0;
	int secMethod;

	while (wl_index < 5) {
		secMethod = get_wlanSecEncryption(0, (wl_index));
		if ( root_vwlan_disable[(wl_index)][0] == 0 &&
			((get_secWEP8021xAuthMode(0, (wl_index)) == 1) ||
			 ((secMethod == 3 || secMethod == 4) && (get_secWPAxAuthMode(0, (wl_index)) == 1)) ||
			 (secMethod == 5 && get_secWPAmixAuthMode(0, (wl_index)) == 1))) {
			newoid->name[index] = wl_index + 1;
			result = compare(reqoid, newoid);
			if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
				break;
			}
		}
		wl_index++;
	}
	if (wl_index >= 5) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	switch (column) {
	case I_SecConfigSSIDIndex_5g:
		public_mib_buffer.gb_long = wl_index + 1;
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecSSID_5g:
		get_wlanSSID(0, (wl_index), public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = 0;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_SecRadiusServerIP_5g:
		get_radiusServerIP(0, (wl_index), &public_mib_buffer.gb_long);
		*write_method = (int (*)())&write_secRadiusServerIP_5g;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecRadiusServerPort_5g:
		get_radiusPort(0, (wl_index), &public_mib_buffer.gb_long);
		*write_method = (int (*)())&write_secRadiusServerPort_5g;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecRadiusServerPwd_5g:
		get_radiusPassword(0, (wl_index), public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_secRadiusPassword_5g;
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_SecAccountMode:
		public_mib_buffer.gb_long = get_radiusAccountMode(0, (wl_index));
		*write_method = (int (*)())&write_secAccountMode_5g;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecAccountServerIP_5g:
		get_radiusAccountServerIp(0, (wl_index), &public_mib_buffer.gb_long);
		*write_method = (int (*)())&write_secAccountServerIP_5g;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecAccountServerPort_5g:
		get_radiusAccountServerPort(0, (wl_index), &public_mib_buffer.gb_long);
		*write_method = (int (*)())&write_secAccountServerPort_5g;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecAccountServerPwd_5g:
		get_radiusAccountServerPasswd(0, (wl_index), public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_secAccountPassword_5g;
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	default:
		return (unsigned char*)NO_MIBINSTANCE;
	}
	return (unsigned char*)NO_MIBINSTANCE;
}

/* Security Config - WEP */
int write_secWEP8021xAuthMode_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWEP8021xAuthMode(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPMacAuthMode_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWEPMacAuthMode(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPAuthMethod_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWEPAuthMethod(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPAuthKeySize_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWEPKeySize(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPAuthEnable_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWEPAuthEnable(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPKeyFormat_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWEPKeyFormat(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPEncryptionKey_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWEPEncryptionKey(0, (wl_index), var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPKeyIndex_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWEPKeyIndex(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_secWEPConfig_5g(int *var_len, Oid * newoid,
					Oid * reqoid, int searchType,
					snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;

	int index = newoid->namelen++;
	int wl_index = 0;

	while (wl_index < 5) {
		if (root_vwlan_disable[(wl_index)][0] == 0 && get_wlanSecEncryption(0, (wl_index)) == 2) {
			newoid->name[index] = wl_index + 1;
			result = compare(reqoid, newoid);
			if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
				break;
			}
		}
		wl_index++;
	}
	if (wl_index >= 5) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	switch (column) {
	case I_SecWEPConfigSSIDIndex_5g:
		public_mib_buffer.gb_long = wl_index + 1;
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWEPSecSSID_5g:
		get_wlanSSID(0, (wl_index), public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = 0;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_SecWEP8021xAuthMode_5g:
		public_mib_buffer.gb_long = get_secWEP8021xAuthMode(0, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEP8021xAuthMode_5g;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWEPMacAuthMode_5g:
		public_mib_buffer.gb_long = get_secWEPMacAuthMode(0, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEPMacAuthMode_5g;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWEPAuthMethod_5g:
		public_mib_buffer.gb_long = get_secWEPAuthMethod(0, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEPAuthMethod_5g;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWEPAuthKeySize_5g:
		public_mib_buffer.gb_long = get_secWEPKeySize(0, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEPAuthKeySize_5g;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWEPAuthEnable_5g:
		public_mib_buffer.gb_long = get_secWEPAuthEnable(0, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEPAuthEnable_5g;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWEPKeyFormat_5g:
		public_mib_buffer.gb_long = get_secWEPKeyFormat(0, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEPKeyFormat_5g;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWEPEncryptionKey_5g:
		get_secWEPEncryptionKey(0, (wl_index), public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_secWEPEncryptionKey_5g;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_SecWEPKeyIndex_5g:
		public_mib_buffer.gb_long = get_secWEPKeyIndex(0, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEPKeyIndex_5g;
		return (unsigned char *)&public_mib_buffer.gb_long;
	default:
		return NO_MIBINSTANCE;
	}
	return NO_MIBINSTANCE;
}

//Security Settings: WPAx Configuration Functions
int write_secWPAxAuthMode_5g(int action,
				unsigned char *var_val, unsigned char varval_type,
				int var_val_len, unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAxAuthMode(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAxCipherSuite_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAxCipherSuite(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAxKeyFormat_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAxKeyFormat(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAxPreSharedKey_5g(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAxPreSharedKey(0, (wl_index), var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_secWPAxConfig_5g(int *var_len, Oid * newoid, Oid * reqoid,
					int searchType, snmp_info_t * mesg,
					int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;

	int index = newoid->namelen++;
	int wl_index = 0;
	int secMethod;

	while (wl_index < 5) {
		secMethod = get_wlanSecEncryption(0, (wl_index));
		if (root_vwlan_disable[(wl_index)][0] == 0 && (secMethod == 3 || secMethod == 4)) {
			newoid->name[index] = wl_index + 1;
			result = compare(reqoid, newoid);
			if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
				break;
			}
		}
		wl_index++;
	}
	if (wl_index >= 5) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	switch (column) {
	case I_SecWPAxConfigSSIDIndex_5g:
		public_mib_buffer.gb_long = wl_index + 1;
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAxSecSSID_5g:
		get_wlanSSID(0, (wl_index), public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = 0;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_SecWPAxAuthMode_5g:
		public_mib_buffer.gb_long = get_secWPAxAuthMode(0, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAxAuthMode_5g;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAxCipherSuite_5g:
		public_mib_buffer.gb_long = get_secWPAxCipherSuite(0, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAxCipherSuite_5g;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAxKeyFormat_5g:
		public_mib_buffer.gb_long = get_secWPAxKeyFormat(0, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAxKeyFormat_5g;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAxPreSharedKey_5g:
		get_secWPAxPreSharedKey(0, (wl_index), public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_secWPAxPreSharedKey_5g;
		return (unsigned char*)public_mib_buffer.gb_string;
	default:
		return NO_MIBINSTANCE;
	}
	return NO_MIBINSTANCE;
}

//Security Settings: WPAmix Configuration Functions
int write_secWPAmixAuthMode_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAmixAuthMode(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAmixCipherSuite_5g(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAmixCipherSuite(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAmix2CipherSuite_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAmix2CipherSuite(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAmixKeyFormat_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAmixKeyFormat(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAmixPreSharedKey_5g(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret=1;
	int wl_index = reqOid->name[(reqOid->namelen - 1)];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAmixPreSharedKey(0, (wl_index), var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_secWPAmixConfig_5g(int *var_len, Oid * newoid, Oid * reqoid,
					int searchType, snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;

	int index = newoid->namelen++;
	int wl_index = 0;

	while (wl_index < 5) {
		if (root_vwlan_disable[(wl_index)][0] == 0 && get_wlanSecEncryption(0, (wl_index)) == 5) {
			newoid->name[index] = wl_index + 1;
			result = compare(reqoid, newoid);
			if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
				break;
			}
		}
		wl_index++;
	}
	if (wl_index >= 5) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	switch (column) {
	case I_SecWPAmixConfigSSIDIndex_5g:
		public_mib_buffer.gb_long = wl_index + 1;
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAmixSecSSID_5g:
		get_wlanSSID(0, (wl_index), public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = 0;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_SecWPAmixAuthMode_5g:
		public_mib_buffer.gb_long = get_secWPAmixAuthMode(0, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAmixAuthMode_5g;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAmixCipherSuite_5g:
		public_mib_buffer.gb_long = get_secWPAmixCipherSuite(0, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAmixCipherSuite_5g;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAmix2CipherSuite_5g:
		public_mib_buffer.gb_long = get_secWPAmix2CipherSuite(0, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAmix2CipherSuite_5g;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAmixKeyFormat_5g:
		public_mib_buffer.gb_long = get_secWPAmixKeyFormat(0, (wl_index));
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAmixKeyFormat_5g;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SecWPAmixPreSharedKey_5g:
		get_secWPAmixPreSharedKey(0, (wl_index), public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_secWPAmixPreSharedKey_5g;
		return (unsigned char*)public_mib_buffer.gb_string;
	default:
		return NO_MIBINSTANCE;
	}
	return NO_MIBINSTANCE;
}

static oid secConfig_oid[] = { O_SecurityConfig };

static Object secConfig_var[] = {
	{SNMP_INTEGER, (RONLY | COLUMN), var_secConfig,
	 {3, {I_SecConfigTable, I_SecConfigEntry, I_SecConfigSSIDIndex}}},
	{SNMP_STRING, (RONLY | COLUMN), var_secConfig,
	 {3, {I_SecConfigTable, I_SecConfigEntry, I_SecSSID}}},
	{SNMP_IPADDRESS, (RWRITE | COLUMN), var_secConfig,
	 {3, {I_SecConfigTable, I_SecConfigEntry, I_SecRadiusServerIP}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secConfig,
	 {3, {I_SecConfigTable, I_SecConfigEntry, I_SecRadiusServerPort}}},
	{SNMP_STRING, (RWRITE | COLUMN), var_secConfig,
	 {3, {I_SecConfigTable, I_SecConfigEntry, I_SecRadiusServerPwd}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secConfig,
	 {3, {I_SecConfigTable, I_SecConfigEntry, I_SecAccountMode}}},
	{SNMP_IPADDRESS, (RWRITE | COLUMN), var_secConfig,
	 {3, {I_SecConfigTable, I_SecConfigEntry, I_SecAccountServerIP}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secConfig,
	 {3, {I_SecConfigTable, I_SecConfigEntry, I_SecAccountServerPort}}},
	{SNMP_STRING, (RWRITE | COLUMN), var_secConfig,
	 {3, {I_SecConfigTable, I_SecConfigEntry, I_SecAccountServerPwd}}},
// WEP Configuration
	{SNMP_INTEGER, (RONLY | COLUMN), var_secWEPConfig,
	 {3, {I_SecWEPConfigTable, I_SecWEPConfigEntry, I_SecWEPConfigSSIDIndex}}},
	{SNMP_STRING, (RONLY | COLUMN), var_secWEPConfig,
	 {3, {I_SecWEPConfigTable, I_SecWEPConfigEntry, I_SecWEPSecSSID}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWEPConfig,
	 {3, {I_SecWEPConfigTable, I_SecWEPConfigEntry, I_SecWEP8021xAuthMode}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWEPConfig,
	 {3, {I_SecWEPConfigTable, I_SecWEPConfigEntry, I_SecWEPMacAuthMode}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWEPConfig,
	 {3, {I_SecWEPConfigTable, I_SecWEPConfigEntry, I_SecWEPAuthMethod}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWEPConfig,
	 {3, {I_SecWEPConfigTable, I_SecWEPConfigEntry, I_SecWEPAuthKeySize}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWEPConfig,
	 {3, {I_SecWEPConfigTable, I_SecWEPConfigEntry, I_SecWEPAuthEnable}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWEPConfig,
	 {3, {I_SecWEPConfigTable, I_SecWEPConfigEntry, I_SecWEPKeyFormat}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWEPConfig,
	 {3, {I_SecWEPConfigTable, I_SecWEPConfigEntry, I_SecWEPAuthMethod}}},
	{SNMP_STRING, (RWRITE | COLUMN), var_secWEPConfig,
	 {3, {I_SecWEPConfigTable, I_SecWEPConfigEntry, I_SecWEPEncryptionKey}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWEPConfig,
	 {3, {I_SecWEPConfigTable, I_SecWEPConfigEntry, I_SecWEPKeyIndex}}},
// WPAx Configuration
	{SNMP_INTEGER, (RONLY | COLUMN), var_secWPAxConfig,
	 {3, {I_SecWPAxConfigTable, I_SecWPAxConfigEntry, I_SecWPAxConfigSSIDIndex}}},
	{SNMP_STRING, (RONLY | COLUMN), var_secWPAxConfig,
	 {3, {I_SecWPAxConfigTable, I_SecWPAxConfigEntry, I_SecWPAxConfigSSID}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWPAxConfig,
	 {3, {I_SecWPAxConfigTable, I_SecWPAxConfigEntry, I_SecWPAxAuthMode}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWPAxConfig,
	 {3, {I_SecWPAxConfigTable, I_SecWPAxConfigEntry, I_SecWPAxCipherSuite}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWPAxConfig,
	 {3, {I_SecWPAxConfigTable, I_SecWPAxConfigEntry, I_SecWPAxKeyFormat}}},
	{SNMP_STRING, (RWRITE | COLUMN), var_secWPAxConfig,
	 {3, {I_SecWPAxConfigTable, I_SecWPAxConfigEntry, I_SecWPAxPreSharedKey}}},
// WPA Mixed Configuration
	{SNMP_INTEGER, (RONLY | COLUMN), var_secWPAmixConfig,
	 {3, {I_SecWPAmixConfigTable, I_SecWPAmixConfigEntry, I_SecWPAmixConfigSSIDIndex}}},
	{SNMP_STRING, (RONLY | COLUMN), var_secWPAmixConfig,
	 {3, {I_SecWPAmixConfigTable, I_SecWPAmixConfigEntry, I_SecWPAmixSecSSID}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWPAmixConfig,
	 {3, {I_SecWPAmixConfigTable, I_SecWPAmixConfigEntry, I_SecWPAmixAuthMode}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWPAmixConfig,
	 {3, {I_SecWPAmixConfigTable, I_SecWPAmixConfigEntry, I_SecWPAmixCipherSuite}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWPAmixConfig,
	 {3, {I_SecWPAmixConfigTable, I_SecWPAmixConfigEntry, I_SecWPAmix2CipherSuite}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWPAmixConfig,
	 {3, {I_SecWPAmixConfigTable, I_SecWPAmixConfigEntry, I_SecWPAmixKeyFormat}}},
	{SNMP_STRING, (RWRITE | COLUMN), var_secWPAmixConfig,
	 {3, {I_SecWPAmixConfigTable, I_SecWPAmixConfigEntry, I_SecWPAmixPreSharedKey}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_secConfig_5g,
	 {3, {I_SecConfigTable_5g, I_SecConfigEntry_5g, I_SecConfigSSIDIndex_5g}}},
	{SNMP_STRING, (RONLY | COLUMN), var_secConfig_5g,
	 {3, {I_SecConfigTable_5g, I_SecConfigEntry_5g, I_SecSSID_5g}}},
	{SNMP_IPADDRESS, (RWRITE | COLUMN), var_secConfig_5g,
	 {3, {I_SecConfigTable_5g, I_SecConfigEntry_5g, I_SecRadiusServerIP_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secConfig_5g,
	 {3, {I_SecConfigTable_5g, I_SecConfigEntry_5g, I_SecRadiusServerPort_5g}}},
	{SNMP_STRING, (RWRITE | COLUMN), var_secConfig_5g,
	 {3, {I_SecConfigTable_5g, I_SecConfigEntry_5g, I_SecRadiusServerPwd_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secConfig_5g,
	 {3, {I_SecConfigTable_5g, I_SecConfigEntry_5g, I_SecAccountMode_5g}}},
	{SNMP_IPADDRESS, (RWRITE | COLUMN), var_secConfig_5g,
	 {3, {I_SecConfigTable_5g, I_SecConfigEntry_5g, I_SecAccountServerIP_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secConfig_5g,
	 {3, {I_SecConfigTable_5g, I_SecConfigEntry_5g, I_SecAccountServerPort_5g}}},
	{SNMP_STRING, (RWRITE | COLUMN), var_secConfig_5g,
	 {3, {I_SecConfigTable_5g, I_SecConfigEntry_5g, I_SecAccountServerPwd_5g}}},
// WEP Configuration
	{SNMP_INTEGER, (RONLY | COLUMN), var_secWEPConfig_5g,
	 {3, {I_SecWEPConfigTable_5g, I_SecWEPConfigEntry_5g, I_SecWEPConfigSSIDIndex_5g}}},
	{SNMP_STRING, (RONLY | COLUMN), var_secWEPConfig_5g,
	 {3, {I_SecWEPConfigTable_5g, I_SecWEPConfigEntry_5g, I_SecWEPSecSSID_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWEPConfig_5g,
	 {3, {I_SecWEPConfigTable_5g, I_SecWEPConfigEntry_5g, I_SecWEP8021xAuthMode_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWEPConfig_5g,
	 {3, {I_SecWEPConfigTable_5g, I_SecWEPConfigEntry_5g, I_SecWEPMacAuthMode_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWEPConfig_5g,
	 {3, {I_SecWEPConfigTable_5g, I_SecWEPConfigEntry_5g, I_SecWEPAuthMethod_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWEPConfig_5g,
	 {3, {I_SecWEPConfigTable_5g, I_SecWEPConfigEntry_5g, I_SecWEPAuthKeySize_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWEPConfig_5g,
	 {3, {I_SecWEPConfigTable_5g, I_SecWEPConfigEntry_5g, I_SecWEPAuthEnable_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWEPConfig_5g,
	 {3, {I_SecWEPConfigTable_5g, I_SecWEPConfigEntry_5g, I_SecWEPKeyFormat_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWEPConfig_5g,
	 {3, {I_SecWEPConfigTable_5g, I_SecWEPConfigEntry_5g, I_SecWEPAuthMethod_5g}}},
	{SNMP_STRING, (RWRITE | COLUMN), var_secWEPConfig_5g,
	 {3, {I_SecWEPConfigTable_5g, I_SecWEPConfigEntry_5g, I_SecWEPEncryptionKey_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWEPConfig_5g,
	 {3, {I_SecWEPConfigTable_5g, I_SecWEPConfigEntry_5g, I_SecWEPKeyIndex_5g}}},
// WPAx Configuration
	{SNMP_INTEGER, (RONLY | COLUMN), var_secWPAxConfig_5g,
	 {3, {I_SecWPAxConfigTable_5g, I_SecWPAxConfigEntry_5g, I_SecWPAxConfigSSIDIndex_5g}}},
	{SNMP_STRING, (RONLY | COLUMN), var_secWPAxConfig_5g,
	 {3, {I_SecWPAxConfigTable_5g, I_SecWPAxConfigEntry_5g, I_SecWPAxSecSSID_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWPAxConfig_5g,
	 {3, {I_SecWPAxConfigTable_5g, I_SecWPAxConfigEntry_5g, I_SecWPAxAuthMode_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWPAxConfig_5g,
	 {3, {I_SecWPAxConfigTable_5g, I_SecWPAxConfigEntry_5g, I_SecWPAxCipherSuite_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWPAxConfig_5g,
	 {3, {I_SecWPAxConfigTable_5g, I_SecWPAxConfigEntry_5g, I_SecWPAxKeyFormat_5g}}},
	{SNMP_STRING, (RWRITE | COLUMN), var_secWPAxConfig_5g,
	 {3, {I_SecWPAxConfigTable_5g, I_SecWPAxConfigEntry_5g, I_SecWPAxPreSharedKey_5g}}},
// WPA Mixed Configuration
	{SNMP_INTEGER, (RONLY | COLUMN), var_secWPAmixConfig_5g,
	 {3, {I_SecWPAmixConfigTable_5g, I_SecWPAmixConfigEntry_5g, I_SecWPAmixConfigSSIDIndex_5g}}},
	{SNMP_STRING, (RONLY | COLUMN), var_secWPAmixConfig_5g,
	 {3, {I_SecWPAmixConfigTable_5g, I_SecWPAmixConfigEntry_5g, I_SecWPAmixSecSSID_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWPAmixConfig_5g,
	 {3, {I_SecWPAmixConfigTable_5g, I_SecWPAmixConfigEntry_5g, I_SecWPAmixAuthMode_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWPAmixConfig_5g,
	 {3, {I_SecWPAmixConfigTable_5g, I_SecWPAmixConfigEntry_5g, I_SecWPAmixCipherSuite_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWPAmixConfig_5g,
	 {3, {I_SecWPAmixConfigTable_5g, I_SecWPAmixConfigEntry_5g, I_SecWPAmix2CipherSuite_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_secWPAmixConfig_5g,
	 {3, {I_SecWPAmixConfigTable_5g, I_SecWPAmixConfigEntry_5g, I_SecWPAmixKeyFormat_5g}}},
	{SNMP_STRING, (RWRITE | COLUMN), var_secWPAmixConfig_5g,
	 {3, {I_SecWPAmixConfigTable_5g, I_SecWPAmixConfigEntry_5g, I_SecWPAmixPreSharedKey_5g}}},
	{ 0 }
};

static SubTree secConfig_tree = { NULL, secConfig_var,
	(sizeof(secConfig_oid) / sizeof(oid)), secConfig_oid
};

/*      Device Port Configuration           */
int write_devicePortMode(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqoid)
{
	int intVal = (int)mhtol(var_val, var_val_len);
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_devicePortMode(intVal);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}
	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;

}

unsigned char *var_devicePortMode(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_devicePortMode();

	*write_method = (int (*)())&write_devicePortMode;

	*var_len = sizeof(long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}


int write_wanPortTraffic(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqoid)
{
	int intVal = (int)mhtol(var_val, var_val_len);
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wanPortTraffic(intVal);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}
	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;

}

unsigned char *var_wanPortTraffic(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_wanPortTraffic();

	*write_method = (int (*)())&write_wanPortTraffic;

	*var_len = sizeof(long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}


int write_DevicePortNego(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqoid)
{
	int index = reqoid->name[(reqoid->namelen - 1)];
	int intVal, ret = 0;

	intVal = (int)mhtol(var_val, var_val_len);
	action = 2;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_DevicePortNego(intVal, index);
		//portReqs[index].phr_optmask &= ~PHF_AUTONEG;
		//portReqs[index].phr_option &= ~PHF_AUTONEG;
		//portReqs[index].phr_optmask |= PHF_AUTONEG;
		//portReqs[index].phr_option |= PHF_AUTONEG;
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}
	return (ret == 0)? SNMP_ERROR_WRONGVALUE : 0;

}

int write_DevicePortSpeed(int action, unsigned char *var_val,
						  unsigned char varval_type, int var_val_len,
						  unsigned char *statP, Oid * reqoid)
{
	int index = reqoid->name[(reqoid->namelen - 1)];
	int intVal;
	int ret = 0;

	intVal = (int)mhtol(var_val, var_val_len);
	action = 2;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_DevicePortSpeed(intVal, index);
		/*if (intVal == 1) {
			portReqs[index].phr_option &= ~PHF_100M;
			portReqs[index].phr_option |= PHF_10M;
		} else if (intVal == 2) {
			portReqs[index].phr_option |= PHF_100M;
			portReqs[index].phr_option &= ~PHF_10M;
		} else
			return SNMP_ERROR_WRONGVALUE;*/
		/*portReqs[index].phr_optmask |= (PHF_100M | PHF_10M);
		portReqs[index].phr_optmask &= ~PHF_AUTONEG;
		portReqs[index].phr_option &= ~PHF_AUTONEG;*/
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}
	return (ret==0)? SNMP_ERROR_WRONGVALUE : 0;
}

int write_DevicePortDuplex(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqoid)
{
	int index = reqoid->name[(reqoid->namelen - 1)];
	int intVal;
	int ret = 0;

	intVal = (int)mhtol(var_val, var_val_len);
	action = 2;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_DevicePortDuplex(intVal, index);
		/*if (intVal == 1)
			portReqs[index].phr_option &= ~PHF_FDX;
		else if (intVal == 2)
			portReqs[index].phr_option |= PHF_FDX;
		else
			return SNMP_ERROR_WRONGVALUE;
		portReqs[index].phr_optmask |= PHF_FDX;
		portReqs[index].phr_optmask &= ~PHF_AUTONEG;
		portReqs[index].phr_option &= ~PHF_AUTONEG;*/
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret ==0)? SNMP_ERROR_WRONGVALUE : 0;
}

int write_DevicePortOnOff(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqoid)
{
	int index = reqoid->name[(reqoid->namelen - 1)];
	int intVal;
	int ret = 0;

	intVal = (int)mhtol(var_val, var_val_len);
	action = 2;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_DevicePortOnOff(intVal, index);
		/*if (intVal == 1)
			portReqs[index].phr_option |= PHF_PWRUP;
		else if (intVal == 2)
			portReqs[index].phr_option &= ~PHF_PWRUP;
		else
			return SNMP_ERROR_WRONGVALUE;
		portReqs[index].phr_optmask |= PHF_PWRUP;*/
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0)? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_devicePortConfig(int *var_len, Oid * newoid,
					Oid * reqoid, int searchType,
					snmp_info_t * mesg, int (**write_method)())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen++;
	int port_index = 0;
	int i=0, unsupported = 3;
	while (port_index < MAX_PORT) {
		newoid->name[index] = port_index;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		port_index++;
	}
	if (port_index >= MAX_PORT) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	switch (column) {
		case I_DevicePortIndex:
			public_mib_buffer.gb_long = port_index + 1;
			*write_method = 0;
			*var_len = sizeof(long);
			return (unsigned char *)&public_mib_buffer.gb_long;
		case I_DevicePortNumber:
			public_mib_buffer.gb_long = port_index;
			*write_method = 0;
			*var_len = sizeof(long);
			return (unsigned char *)&public_mib_buffer.gb_long;
		case I_DevicePortName:
			strcpy(public_mib_buffer.gb_string, DevPortName[port_index_change(port_index)]);
			*var_len = strlen(DevPortName[port_index_change(port_index)]);
			*write_method = 0;
			return (unsigned char*)public_mib_buffer.gb_string;
		case I_DevicePortNego:
			public_mib_buffer.gb_long = get_DevicePortNego(port_index);
			*write_method = (int (*)())&write_DevicePortNego;
			*var_len = sizeof(long);
			return (unsigned char *)&public_mib_buffer.gb_long;
		case I_DevicePortSpeed:
			public_mib_buffer.gb_long = get_DevicePortSpeed(port_index);
			*write_method = (int (*)())&write_DevicePortSpeed;
			*var_len = sizeof(long);
			return (unsigned char *)&public_mib_buffer.gb_long;
		case I_DevicePortDuplex:
			public_mib_buffer.gb_long = get_DevicePortDuplex(port_index);
			*var_len = sizeof(long);
			*write_method = (int (*)())&write_DevicePortDuplex;
			return (unsigned char *)&public_mib_buffer.gb_long;
		case I_DevicePortOnOff:
			public_mib_buffer.gb_long = get_DevicePortOnOff(port_index);
			*var_len = sizeof(long);
			*write_method = (int (*)())&write_DevicePortOnOff;
			return (unsigned char *)&public_mib_buffer.gb_long;

		case I_DevicePortGigaLite:
			public_mib_buffer.gb_long = unsupported;
			return (unsigned char *)&public_mib_buffer.gb_long;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}

static oid devicePortConfig_oid[] = { O_DevicePortConfig };

static Object devicePortConfig_var[] = {
	{SNMP_INTEGER, (RWRITE | SCALAR), var_devicePortMode,
	 {1, {I_DevicePortMode}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_devicePortConfig,
	 {3, {I_DevicePortTable, I_DevicePortEntry, I_DevicePortIndex}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_devicePortConfig,
	 {3, {I_DevicePortTable, I_DevicePortEntry, I_DevicePortNumber}}},
	{SNMP_STRING, (RONLY | COLUMN), var_devicePortConfig,
	 {3, {I_DevicePortTable, I_DevicePortEntry, I_DevicePortName}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_devicePortConfig,
	 {3, {I_DevicePortTable, I_DevicePortEntry, I_DevicePortNego}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_devicePortConfig,
	 {3, {I_DevicePortTable, I_DevicePortEntry, I_DevicePortSpeed}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_devicePortConfig,
	 {3, {I_DevicePortTable, I_DevicePortEntry, I_DevicePortDuplex}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_devicePortConfig,
	 {3, {I_DevicePortTable, I_DevicePortEntry, I_DevicePortOnOff}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_devicePortConfig,
	 {3, {I_DevicePortTable, I_DevicePortEntry, I_DevicePortGigaLite}}},
	 {SNMP_INTEGER, (RWRITE | SCALAR), var_wanPortTraffic,
	 {1, {I_WanportTraffic}}},
	{ 0 }
};

static SubTree devicePortConfig_tree = {
	NULL, devicePortConfig_var,
	(sizeof(devicePortConfig_oid) / sizeof(oid)),
	devicePortConfig_oid
};

// IGMP Proxy Settings...
int write_IgmpMulticastEnable(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_IgmpMulticastEnable((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_IgmpIpMulticastEnable(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_IgmpMulticastEnable();
	*write_method = (int (*)())&write_IgmpMulticastEnable;
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_IgmpSelectMode(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_IgmpSelectMode();
	*write_method = 0;
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}


int write_IgmpFastLeaveEnable(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_IgmpFastLeaveEnable((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_IgmpFastLeaveEnable(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_IgmpFastLeaveEnable();
	*write_method = (int (*)())&write_IgmpFastLeaveEnable;
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_IgmpProxyMemberExpireTime(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_IgmpProxyMemberExpireTime((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_IgmpProxyMemberExpireTime(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_IgmpProxyMemberExpireTime();
	*write_method = (int (*)())&write_IgmpProxyMemberExpireTime;
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_IgmpProxyQueryInterval(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_IgmpProxyQueryInterval((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_IgmpProxyQueryInterval(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_IgmpProxyQueryInterval();
	*write_method = (int (*)())&write_IgmpProxyQueryInterval;
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_IgmpProxyQueryResInterval(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_IgmpProxyQueryResInterval((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_IgmpProxyQueryResInterval(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_IgmpProxyQueryResInterval();
	*write_method = (int (*)())&write_IgmpProxyQueryResInterval;
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_IgmpProxyGroupMemberInterval(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_IgmpProxyGroupMemberInterval((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_IgmpProxyGroupMemberInterval(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_IgmpProxyGroupMemberInterval();
	*write_method = (int (*)())&write_IgmpProxyGroupMemberInterval;
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_IgmpProxyGroupQueryInterval(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_IgmpProxyGroupQueryInterval((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_IgmpProxyGroupQueryInterval(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_IgmpProxyGroupQueryInterval();
	*write_method = (int (*)())&write_IgmpProxyGroupQueryInterval;
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

static oid IgmpConfig_oid[] = { O_IgmpConfig };

static Object IgmpConfig_var[] = {
	{SNMP_INTEGER, (RWRITE | SCALAR), var_IgmpIpMulticastEnable,
	 {1, {I_IgmpMulticastEnable}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_IgmpSelectMode,
	 {1, {I_IgmpSelectMode}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_IgmpFastLeaveEnable,
	 {1, {I_IgmpFastLeaveEnable}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_IgmpProxyMemberExpireTime,
	 {1, {I_IgmpProxyMemberExpireTime}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_IgmpProxyQueryInterval,
	 {1, {I_IgmpProxyQueryInterval}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_IgmpProxyQueryResInterval,
	 {1, {I_IgmpProxyQueryResInterval}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_IgmpProxyGroupMemberInterval,
	 {1, {I_IgmpProxyGroupMemberInterval}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_IgmpProxyGroupQueryInterval,
	 {1, {I_IgmpProxyGroupQueryInterval}}},
	{ 0 }
};

static SubTree IgmpConfig_tree = { NULL, IgmpConfig_var,
	(sizeof(IgmpConfig_oid) / sizeof(oid)), IgmpConfig_oid
};

/* Firmware Upgrade Configuration */

// Autoupgrade Settings...
int write_autoUpgradeEnable(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_autoUpgradeEnable((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

unsigned char *var_autoUpgradeEnable(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_autoUpgradeEnable();

	*write_method = (int (*)())&write_autoUpgradeEnable;

	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_autoUpgradeServer(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_autoUpgradeServer(var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

unsigned char *var_autoUpgradeServer(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	get_autoUpgradeServer(public_mib_buffer.gb_string);

	*write_method = (int (*)())&write_autoUpgradeServer;

	*var_len = strlen(public_mib_buffer.gb_string);
	return (unsigned char *)public_mib_buffer.gb_string;
}

int write_autoUpgradePrefix(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_autoUpgradePrefix(var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

unsigned char *var_autoUpgradePrefix(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	get_autoUpgradePrefix(public_mib_buffer.gb_string);

	*write_method = (int (*)())&write_autoUpgradePrefix;

	*var_len = strlen(public_mib_buffer.gb_string);
	return (unsigned char *)public_mib_buffer.gb_string;
}

int write_autoUpFWDataFile(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_autoUpFWDataFile(var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

unsigned char *var_autoUpFWDataFile(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	get_autoUpFWDataFile(public_mib_buffer.gb_string);

	*write_method = (int (*)())&write_autoUpFWDataFile;

	*var_len = strlen(public_mib_buffer.gb_string);
	return (unsigned char *)public_mib_buffer.gb_string;
}

char manualServer[128];
char manualPrefix[128];
char manualFile[128];

int write_manualUpdateServer(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		memset(manualServer, 0, sizeof(manualServer));
		strncpy(manualServer, var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

unsigned char *var_manualUpdateServer(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	strcpy(public_mib_buffer.gb_string, manualServer);
	*var_len = strlen(public_mib_buffer.gb_string);
	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_manualUpdateServer;
	/* Set size (in bytes) and return address of the variable */
	return (unsigned char *)public_mib_buffer.gb_string;

}

int write_manualUpdatePrefix(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		memset(manualPrefix, 0, sizeof(manualPrefix));
		strncpy(manualPrefix, var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

unsigned char *var_manualUpdatePrefix(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	strcpy(public_mib_buffer.gb_string, manualPrefix);
	*var_len = strlen(public_mib_buffer.gb_string);
	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_manualUpdatePrefix;
	/* Set size (in bytes) and return address of the variable */
	return (unsigned char *)public_mib_buffer.gb_string;

}

int write_manualUpdateFile(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		memset(manualFile, 0, sizeof(manualFile));
		strncpy(manualFile, var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

unsigned char *var_manualUpdateFile(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	strcpy(public_mib_buffer.gb_string, manualFile);
	*var_len = strlen(public_mib_buffer.gb_string);
	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_manualUpdateFile;
	/* Set size (in bytes) and return address of the variable */
	return (unsigned char *)public_mib_buffer.gb_string;

}

int write_manualUpdateExec(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int intVal;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		intVal = (int)mhtol(var_val, var_val_len);
		if (intVal == 1)
			snmpAction = 4/*SNMP_MANUAL_UPGRADE*/;
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}
	return (0);
}

int executeManualUpgrade(void)
{
	return (__executeManualUpgrade(manualServer, manualPrefix, manualFile));
}
unsigned char *var_manualUpdateExec(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = 0;

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_manualUpdateExec;
	*var_len = sizeof(long);
	/* Set size (in bytes) and return address of the variable */
	return (unsigned char *)&public_mib_buffer.gb_long;

}
static oid fwUpgradeConfig_oid[] = { O_fwUpgradeConfig };

static Object fwUpgradeConfig_var[] = {
	{SNMP_INTEGER, (RWRITE | SCALAR), var_autoUpgradeEnable,
	 {2, {I_autoUpgradeConfig, I_AutoUpgradeEnable}}},
	{SNMP_STRING, (RWRITE | SCALAR), var_autoUpgradeServer,
	 {2, {I_autoUpgradeConfig, I_AutoUpgradeServer}}},
	{SNMP_STRING, (RWRITE | SCALAR), var_autoUpgradePrefix,
	 {2, {I_autoUpgradeConfig, I_AutoUpgradePrefix}}},
	{SNMP_STRING, (RWRITE | SCALAR), var_autoUpFWDataFile,
	 {2, {I_autoUpgradeConfig, I_AutoUpgradeFile}}},
	{SNMP_STRING, (RWRITE | SCALAR), var_manualUpdateServer,
	 {2, {I_ManualUpgradeConfig, I_ManualUpgradeServer}}},
	{SNMP_STRING, (RWRITE | SCALAR), var_manualUpdatePrefix,
	 {2, {I_ManualUpgradeConfig, I_ManualUpgradePrefix}}},
	{SNMP_STRING, (RWRITE | SCALAR), var_manualUpdateFile,
	 {2, {I_ManualUpgradeConfig, I_ManualUpgradeFile}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_manualUpdateExec,
	 {2, {I_ManualUpgradeConfig, I_ManualUpgradeExecute}}},
	{ 0 }
};

static SubTree fwUpgradeConfig_tree = { NULL, fwUpgradeConfig_var,
	(sizeof(fwUpgradeConfig_oid) / sizeof(oid)), fwUpgradeConfig_oid
};


/* SNMP Configuration */
int write_snmpEnable(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * reqoid)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_snmpEnable((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_snmpEnable(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_snmpEnable();
	*write_method = (int (*)())&write_snmpEnable;
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_snmpCommunityName(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqoid)
{
	int ret=1;
	int index = reqoid->name[reqoid->namelen - 1];

	if(var_val_len <= 0 || var_val_len > 22)
		return SNMP_ERROR_WRONGVALUE;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		if (index == 0 || index == 1)
			ret = set_CommunityName(var_val, var_val_len, index);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_snmpCommunityType(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqoid)
{
	int ret=1;
	int index = reqoid->name[reqoid->namelen - 1];
	int res;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		res = mhtol(var_val, var_val_len);
		if (index == 0 || index == 1)
			ret = set_CommunityType(index, res);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_snmpCommunityAdmin(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqoid)
{
	int ret=1;
	int index = reqoid->name[reqoid->namelen - 1];
	int res;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		res =  mhtol(var_val, var_val_len);
		if(index ==0 || index ==1)
			ret = set_CommunityAdmin(index, res);
	break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_snmpCommunityConfig(int *var_len, Oid * newoid,
					Oid * reqoid, int searchType,
					snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int oid_idx = newoid->namelen++;
	int ii = 0;
	COM_T com_info[2];

	Community_parse(&com_info[0]);

	while (ii < 2) {
		newoid->name[oid_idx] = ii;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		ii++;
	}

	if (ii >= 2) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	switch (column) {
	case I_snmpCommunityIndex:
		public_mib_buffer.gb_long = ii+1;
		*write_method = 0;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_snmpCommunityName:
		get_CommunityName(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string), ii, &com_info[0]);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_snmpCommunityName;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_snmpCommunityType:
		public_mib_buffer.gb_long = get_CommunityType(ii, &com_info[0]);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_snmpCommunityType;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_snmpCommunityAdmin:
		public_mib_buffer.gb_long = get_CommunityAdmin(ii, &com_info[0]);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_snmpCommunityAdmin;
		return (unsigned char *)&public_mib_buffer.gb_long;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}

int write_snmpTrapDestination(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqoid)
{
	int ret=1;
	int index = reqoid->name[reqoid->namelen - 1];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_snmpTrapDestination(index, var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_snmpTrapCommunityName(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqoid)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_snmpTrapCommunityName(var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_snmpTrapDestinationAdmin(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * reqoid)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_snmpTrapDestinationAdmin((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}


unsigned char *var_snmpTrapDestinationConfig(int *var_len, Oid * newoid,
						Oid * reqoid, int searchType,
						snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int oid_idx = newoid->namelen++;
	int ii = 0;

	if (nvram_atoi("x_SNMP_TRAP_ENABLE", 1) == 0)
		return (unsigned char *)NO_MIBINSTANCE;

	while (ii < 11) {
		newoid->name[oid_idx] = ii;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		ii++;
	}

	if (ii >= 11) {
		return (unsigned char *)NO_MIBINSTANCE;
	}
	switch (column) {
	case I_snmpTrapDestinationIndex:
		public_mib_buffer.gb_long = ii + 1;
		*write_method = 0;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_snmpTrapDestination:
		get_snmpTrapDestination(ii, public_mib_buffer.gb_string, MAX_SNMP_STR);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_snmpTrapDestination;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_snmpTrapCommunityName:
		get_snmpTrapCommunityName(public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_snmpTrapCommunityName;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_snmpTrapDestinationAdmin:
		public_mib_buffer.gb_long = get_snmpTrapDestinationAdmin();
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_snmpTrapDestinationAdmin;
		return (unsigned char *)&public_mib_buffer.gb_long;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}


static oid snmpConfig_oid[] = { O_snmpConfig };

static Object snmpConfig_var[] = {
	{SNMP_INTEGER, (RWRITE | SCALAR), var_snmpEnable,
	 {1, {I_snmpEnable}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_snmpCommunityConfig,
	 {3, {I_snmpCommunityTable, I_snmpCommunityEntry, I_snmpCommunityIndex}}},
	{SNMP_STRING, (RWRITE | COLUMN), var_snmpCommunityConfig,
	 {3, {I_snmpCommunityTable, I_snmpCommunityEntry, I_snmpCommunityName}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_snmpCommunityConfig,
	 {3, {I_snmpCommunityTable, I_snmpCommunityEntry, I_snmpCommunityType}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_snmpCommunityConfig,
	 {3, {I_snmpCommunityTable, I_snmpCommunityEntry, I_snmpCommunityAdmin}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_snmpTrapDestinationConfig,
	 {3, {I_snmpTrapDestinationTable, I_snmpTrapDestinationEntry, I_snmpTrapDestinationIndex}}},
	{SNMP_STRING, (RWRITE | COLUMN), var_snmpTrapDestinationConfig,
	 {3, {I_snmpTrapDestinationTable, I_snmpTrapDestinationEntry, I_snmpTrapDestination}}},
	{SNMP_STRING, (RWRITE | COLUMN), var_snmpTrapDestinationConfig,
	 {3, {I_snmpTrapDestinationTable, I_snmpTrapDestinationEntry, I_snmpTrapCommunityName}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_snmpTrapDestinationConfig,
	 {3, {I_snmpTrapDestinationTable, I_snmpTrapDestinationEntry, I_snmpTrapDestinationAdmin}}},
	{ 0 }
};

static SubTree snmpConfig_tree = { NULL, snmpConfig_var,
	(sizeof(snmpConfig_oid) / sizeof(oid)), snmpConfig_oid
};


/* LAN AccessControl Settings */
int write_LanAccessControlPortOpMode(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;
	int port_index = name->name[(name->namelen - 1)];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_LanAccessControlPortOpMode(port_index, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_LanAccessControlPortOpMode(int *var_len, Oid * newoid,
						Oid * reqoid, int searchType,
						snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen++;
	int port_index = 1;

	while (port_index < MAX_PORT) {
		newoid->name[index] = port_index;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		port_index++;
	}

	if (port_index >= MAX_PORT) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	switch (column) {
	case I_LanAccessControlPortIndex:
		public_mib_buffer.gb_long = port_index;
		*write_method = 0;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_LanAccessControlPortNumber:
		public_mib_buffer.gb_long = port_index;
		*write_method = 0;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_LanAccessControlPortName:
		strcpy(public_mib_buffer.gb_string, DevPortName[port_index - 1]);
		*write_method = 0;
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_LanAccessControlPortOpMode:
		public_mib_buffer.gb_long = get_LanAccessControlPortOpMode(port_index);
		*write_method = (int (*)())&write_LanAccessControlPortOpMode;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	default:
		return (unsigned char *)NO_MIBINSTANCE;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}


int ACS_port_index = 0;
unsigned char ACS_hwAddr[6];
char ACS_Comment[128];

int write_LanAccessControlSetPortNumber(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;
	int res;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		res = (int)mhtol(var_val, var_val_len);
		if (res >= 1 && res < MAX_PORT) {
			ACS_port_index = res;
			ret = 1;
		} else
			ret = 0;
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_LanAccessControlSetPortNumber(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = ACS_port_index;
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_LanAccessControlSetPortNumber;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_LanAccessControlSetPortName(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	if (ACS_port_index >= 1 && ACS_port_index < MAX_PORT) {
		strcpy(public_mib_buffer.gb_string, DevPortName[ACS_port_index]);
		*var_len = strlen(public_mib_buffer.gb_string);
	} else {
		public_mib_buffer.gb_string[0] = 0;
		*var_len = 0;
	}
	*write_method = 0;
	return (unsigned char*)public_mib_buffer.gb_string;
}

int write_LanAccessControlListSetMacAddr(int action, unsigned char *var_val,
						unsigned char varval_type, int var_val_len,
						unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_AccessControlListSetMacAddr(var_val, var_val_len, ACS_hwAddr);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_LanAccessControlSetMacAddr(int *var_len, snmp_info_t * mesg,
						int (**write_method) ())
{
	memcpy(public_mib_buffer.gb_string, ACS_hwAddr, 6);
	*var_len = sizeof(ACS_hwAddr);
	*write_method = (int (*)())&write_LanAccessControlListSetMacAddr;
	return (unsigned char*)public_mib_buffer.gb_string;
}

int write_LanAccessControlListSetComment(int action, unsigned char *var_val,
						unsigned char varval_type, int var_val_len,
						unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		strcpy(ACS_Comment, var_val);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return 0;
}

unsigned char *var_LanAccessControlSetComment(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	strcpy(public_mib_buffer.gb_string, ACS_Comment);
	*var_len = strlen(public_mib_buffer.gb_string);
	*write_method = (int (*)())&write_LanAccessControlListSetComment;
	return (unsigned char*)public_mib_buffer.gb_string;
}

int write_LanAccessControlListAdd(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = LanAccessControlListAdd(ACS_port_index, ACS_hwAddr, ACS_Comment);
		ACS_port_index = 0;
		memset(ACS_hwAddr, 0, sizeof(ACS_hwAddr));
		memset(ACS_Comment, 0, sizeof(ACS_Comment));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_LanAccessControlListAdd(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = 0;
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_LanAccessControlListAdd;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_LanAccessControlListDel(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = LanAccessControlListDel(ACS_port_index, (int)mhtol(var_val, var_val_len), ACS_hwAddr);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_LanAccessControlListDel(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = 0;
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_LanAccessControlListDel;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_LanAccessControlListDelAll(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = LanAccessControlListDelAll((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_LanAccessControlListDelAll(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = 0;
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_LanAccessControlListDelAll;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_LanAccessControlListView(int *var_len, Oid * newoid,
						Oid * reqoid, int searchType,
						snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen++;
	int tbl_index = 1;
	int tbl_entryNum;
	char buf[5];
	int pn;

	snprintf(buf, sizeof(buf), "%s", getValue("x_MACFILTER_TBL_NUM"));
	tbl_entryNum = atoi(buf);
	while (tbl_index <= tbl_entryNum) {
		newoid->name[index] = tbl_index;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		tbl_index++;
	}

	if (tbl_index > tbl_entryNum) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	*write_method = 0;

	switch (column) {
		case I_LanAccessControlListIndex:
			public_mib_buffer.gb_long = tbl_index;
			*var_len = sizeof(long);
			return (unsigned char *)&public_mib_buffer.gb_long;
		case I_LanAccessControlListPortNumber:
			public_mib_buffer.gb_long = get_LanAccessControlListPortNum(tbl_index) + 1;
			*var_len = sizeof(long);
			return (unsigned char *)&public_mib_buffer.gb_long;
		case I_LanAccessControlListPortName:
			pn = get_LanAccessControlListPortNum(tbl_index);
			strcpy(public_mib_buffer.gb_string, DevPortName[pn]);
			*var_len = strlen(DevPortName[pn]);
			return (unsigned char*)public_mib_buffer.gb_string;
		case I_LanAccessControlListMacAddr:
			if (get_LanAccessControlListMacAddr(tbl_index, public_mib_buffer.gb_string))
				*var_len = 6;
			else
				*var_len = 0;
			return (unsigned char*)public_mib_buffer.gb_string;
		case I_LanAccessControlListDescription:
			get_LanAccessControlListComment(tbl_index, public_mib_buffer.gb_string);
			*var_len = strlen(public_mib_buffer.gb_string);
			return (unsigned char*)public_mib_buffer.gb_string;
	}
	return (unsigned char *)NO_MIBINSTANCE;

}

int write_LanAccessControlMode(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_LanAccessControlMode((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_LanAccessControlMode(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_LanAccessControlMode();
	*write_method = (int (*)())&write_LanAccessControlMode;
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

static oid LanAccessControlConfig_oid[] = { O_LanAccessControlConfig };

static Object LanAccessControlConfig_var[] = {
	{SNMP_INTEGER, (RONLY | COLUMN), var_LanAccessControlPortOpMode,
	 {3, {I_LanAccessControlModeTable, I_LanAccessControlModeEntry, I_LanAccessControlPortIndex}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_LanAccessControlPortOpMode,
	 {3, {I_LanAccessControlModeTable, I_LanAccessControlModeEntry, I_LanAccessControlPortNumber}}},
	{SNMP_STRING, (RONLY | COLUMN), var_LanAccessControlPortOpMode,
	 {3, {I_LanAccessControlModeTable, I_LanAccessControlModeEntry, I_LanAccessControlPortName}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_LanAccessControlPortOpMode,
	 {3, {I_LanAccessControlModeTable, I_LanAccessControlModeEntry, I_LanAccessControlPortOpMode}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_LanAccessControlSetPortNumber,
	 {2, {I_LanAccessControlListConfig, I_LanAccessControlListSetPortNumber}}},
	{SNMP_STRING, (RONLY | SCALAR), var_LanAccessControlSetPortName,
	 {2, {I_LanAccessControlListConfig, I_LanAccessControlListSetPortName}}},
	{SNMP_STRING, (RWRITE | SCALAR), var_LanAccessControlSetMacAddr,
	 {2, {I_LanAccessControlListConfig, I_LanAccessControlListSetMacAddr}}},
	{SNMP_STRING, (RWRITE | SCALAR), var_LanAccessControlSetComment,
	 {2, {I_LanAccessControlListConfig, I_LanAccessControlListSetComment}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_LanAccessControlListAdd,
	 {2, {I_LanAccessControlListConfig, I_LanAccessControlListAdd}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_LanAccessControlListDel,
	 {2, {I_LanAccessControlListConfig, I_LanAccessControlListDel}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_LanAccessControlListDelAll,
	 {2, {I_LanAccessControlListConfig, I_LanAccessControlListDelAll}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_LanAccessControlListView,
	 {4,
	  {I_LanAccessControlListConfig, I_LanAccessControlListTable, I_LanAccessControlListEntry, I_LanAccessControlListIndex}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_LanAccessControlListView,
	 {4,
	  {I_LanAccessControlListConfig, I_LanAccessControlListTable, I_LanAccessControlListEntry,
	   I_LanAccessControlListPortNumber}}},
	{SNMP_STRING, (RONLY | COLUMN), var_LanAccessControlListView,
	 {4,
	  {I_LanAccessControlListConfig, I_LanAccessControlListTable, I_LanAccessControlListEntry,
	   I_LanAccessControlListPortName}}},
	{SNMP_STRING, (RONLY | COLUMN), var_LanAccessControlListView,
	 {4,
	  {I_LanAccessControlListConfig, I_LanAccessControlListTable, I_LanAccessControlListEntry, I_LanAccessControlListMacAddr}}},
	{SNMP_STRING, (RONLY | COLUMN), var_LanAccessControlListView,
	 {4,
	  {I_LanAccessControlListConfig, I_LanAccessControlListTable, I_LanAccessControlListEntry,
	   I_LanAccessControlListDescription}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_LanAccessControlMode,
	 {1, {I_LanAccessControlMode}}},
	{0}
};

static SubTree LanAccessControlConfig_tree = { NULL, LanAccessControlConfig_var,
	(sizeof(LanAccessControlConfig_oid) / sizeof(oid)), LanAccessControlConfig_oid
};

/* WLAN Access Control List */
typedef struct {
	int idx;
	unsigned char mac[6];
	char comment[128];
} wlan_acl_t;

static wlan_acl_t wlan_acl_set;

int write_WLanAccessControlOpMode(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;
	int wl_index = name->name[name->namelen - 1];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_WLanAccessControlOpMode(1, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_WLanAccessControlOpMode(int *var_len, Oid * newoid,
						Oid * reqoid, int searchType,
						snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen++;
	int wl_index = 0;

	while (wl_index < 4) {
		newoid->name[index] = wl_index + 1;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		wl_index++;
	}
//change
	if (wl_index >= 4) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	switch (column) {
	case I_wlanAccessControlSSIDIndex:
		public_mib_buffer.gb_long = wl_index + 1;
		*write_method = 0;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanAccessControlSSID:
		get_wlanSSID(1, (wl_index), public_mib_buffer.gb_string);
		*write_method = 0;
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_wlanAccessControlOpMode:
		public_mib_buffer.gb_long = get_WLanAccessControlOpMode(1, (wl_index));
		*write_method = (int (*)())&write_WLanAccessControlOpMode;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	default:
		return (unsigned char *)NO_MIBINSTANCE;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}

int write_WLanAccessControlSetSSIDIndex(int action,
										unsigned char *var_val, unsigned char varval_type, int var_val_len,
										unsigned char *statP, Oid * name)
{
	int ret=1;
	int res;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		res = (int)mhtol(var_val, var_val_len);
		if(res > 5)
			ret = 0;
		else
			wlan_acl_set.idx = res - 1;
		/*if (res == 0)
			ret = 1;
		else
			ret = 0;*/
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_WLanAccessControlSetSSIDIndex(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = wlan_acl_set.idx + 1;
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_WLanAccessControlSetSSIDIndex;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_WLanAccessControlSetSSID(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	sprintf(public_mib_buffer.gb_string, "---");
	*var_len = strlen(public_mib_buffer.gb_string);
	*write_method = 0;
	return (unsigned char*)public_mib_buffer.gb_string;
}

int write_WLanAccessControlListSetMacAddr(int action, unsigned char *var_val,
						unsigned char varval_type, int var_val_len,
						unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_AccessControlListSetMacAddr(var_val, var_val_len, wlan_acl_set.mac);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_WLanAccessControlSetMacAddr(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	memcpy(public_mib_buffer.gb_string, wlan_acl_set.mac, 6);
	*var_len = sizeof(wlan_acl_set.mac);
	*write_method = (int (*)())&write_WLanAccessControlListSetMacAddr;
	return (unsigned char*)public_mib_buffer.gb_string;
}

int write_WLanAccessControlListSetComment(int action, unsigned char *var_val,
						unsigned char varval_type, int var_val_len,
						unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		strcpy(wlan_acl_set.comment, var_val);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return 0;
}

unsigned char *var_WLanAccessControlSetComment(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	strcpy(public_mib_buffer.gb_string, wlan_acl_set.comment);
	*var_len = strlen(public_mib_buffer.gb_string);
	*write_method = (int (*)())&write_WLanAccessControlListSetComment;
	return (unsigned char*)public_mib_buffer.gb_string;
}

int write_WLanAccessControlListAdd(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;


	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		/*int res;
		res = (int)mhtol(var_val, var_val_len);
		if(res<0 || res>4)
			ret = 0;
		else*/
			ret = WLanAccessControlListAdd(1, wlan_acl_set.idx, wlan_acl_set.mac, wlan_acl_set.comment);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_WLanAccessControlListAdd(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = 0;
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_WLanAccessControlListAdd;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_WLanAccessControlListDel(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		if(wlan_acl_set.idx > 4)
			ret = 0;
		else{
			ret = WLanAccessControlListDel(1, wlan_acl_set.idx, (int)mhtol(var_val, var_val_len));
			wlan_acl_set.idx=0;
		}
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_WLanAccessControlListDel(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = 0;
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_WLanAccessControlListDel;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_WLanAccessControlListDelAll(int action, unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret=1;
	int res;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		res = (int)mhtol(var_val, var_val_len);
		if(res > 5)
			ret = 0;
		else
			ret = WLanAccessControlListDelAll(1, (res));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}
	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_WLanAccessControlListDelAll(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = 0;
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_WLanAccessControlListDelAll;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

typedef struct {
	int ssid_idx;
	unsigned char mac[6];
	unsigned char comment[128];
	int write;
} wlan_acl_tbl_info_t;

typedef void (*sighandler_t)(int);
void fill_acltbl(int w_index, int ssid_idx, int total, wlan_acl_tbl_info_t *entry_tbl, int *line)
{
	int i, j;
	char buf[80], cmd[80];
	char *p, *sp;
	FILE *fp;
	sighandler_t save_quit, save_int, save_chld;
	int line_tmp = *line;
	wlan_idx = wlan_idx;
	vwlan_idx = ssid_idx;

	for(j = 1; j <= total; j++) {

		if (ssid_idx == 0)
			sprintf(cmd, "WLAN%d_MACAC_ADDR%d", w_index, j);
		else
			sprintf(cmd, "WLAN%d_VAP%d_MACAC_ADDR%d", w_index, ssid_idx - 1, j);

		nvram_get_r_def(cmd, buf, sizeof(buf), "");

		save_quit = signal(SIGQUIT, SIG_IGN);
		save_int = signal(SIGINT, SIG_IGN);
		save_chld = signal(SIGCHLD, SIG_IGN);

		entry_tbl[line_tmp].write = 0;

		for ( i = 0, (p=strtok_r(buf, "\r\n\t,= ", &sp)); (p && (p[0]!= 0) && (i < 3)); (p=strtok_r(NULL, "\r\n\t,= ", &sp)), i++ ) {

			entry_tbl[line_tmp].ssid_idx = ssid_idx;

			if ( i == 0) //mac
				simple_ether_atoe(p, &entry_tbl[line_tmp].mac[0]);
			if ( i == 1) //comment
				sprintf(entry_tbl[line_tmp].comment, "%s", p);

			entry_tbl[line_tmp].write = 1;
		}
		line_tmp++;

		signal(SIGQUIT, save_quit);
		signal(SIGINT, save_int);
		signal(SIGCHLD, save_chld);
		*line = line_tmp;
	}
}

int get_wlan_acl_info(int w_index, wlan_acl_tbl_info_t *pAcltbl)
{
	int i;
	int entry = 0;
	char buf[80], param[80];
	int num;
	int line =0;

	for ( i = 0; i < 4; i++ ) {

		if ( i == 0 ) {
			sprintf(param, "WLAN%d_MACAC_NUM", w_index);
			snprintf(buf, sizeof(buf), "%s", getValue(param));
		} else {
			sprintf(param, "WLAN%d_VAP%d_MACAC_NUM", w_index, i - 1);
			snprintf(buf, sizeof(buf), "%s", getValue(param));
		}
		if ( (num = atoi(buf)) > 0 )
			fill_acltbl(w_index, i, num, pAcltbl, &line);

		entry += num;
	}
	return entry;
}

wlan_acl_tbl_info_t wl_acl_tbl[100];
unsigned char *var_WLanAccessControlListView(int *var_len, Oid * newoid,
						Oid * reqoid, int searchType,
						snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen++;
	int tbl_index = 1;
	int entry_idx = 0;
	static int pre_acl_tbl_idx;
	int dp_tbl_index = 0;
	static int tbl_entryNum;
	if ( tbl_entryNum == 0)
		tbl_entryNum = get_wlan_acl_info(1, &wl_acl_tbl[0]);
	while (tbl_index <= tbl_entryNum) {
		newoid->name[index] = tbl_index;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		tbl_index++;
	}
	*write_method = 0;

	if (tbl_index > tbl_entryNum) {
		if ( column == I_wlanAccessControlListDescription) {
			tbl_entryNum = 0;
			pre_acl_tbl_idx = -1;
		}
		return NO_MIBINSTANCE;
	}

	if ( (entry_idx =(tbl_index - 1)) < 0 )
		entry_idx = 0;

	pre_acl_tbl_idx = wl_acl_tbl[entry_idx].ssid_idx;

	switch (column) {
	case I_wlanAccessControlListIndex:
		dp_tbl_index = entry_idx + 1;
		public_mib_buffer.gb_long = dp_tbl_index++;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanAccessControlListSSIDIndex:
		public_mib_buffer.gb_long = wl_acl_tbl[entry_idx].ssid_idx + 1;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanAccessControlListSSID:
		get_wlanSSID(1, wl_acl_tbl[entry_idx].ssid_idx, public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_wlanAccessControlListHwAddr:
		if ( wl_acl_tbl[entry_idx].write ) {
			memcpy(public_mib_buffer.gb_string, wl_acl_tbl[entry_idx].mac, 6);
			*var_len = 6;
		} else {
			memset(public_mib_buffer.gb_string, 0, sizeof(public_mib_buffer.gb_string));
			*var_len = 0;
		}
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_wlanAccessControlListDescription:
		if ( wl_acl_tbl[entry_idx].write )
			sprintf(public_mib_buffer.gb_string, "%s", wl_acl_tbl[entry_idx].comment);
		else
			public_mib_buffer.gb_string[0] = 0;

		*var_len = strlen(public_mib_buffer.gb_string);
		return(unsigned char*) public_mib_buffer.gb_string;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}

/* WLAN Access Control List 5g*/

int write_WLanAccessControlOpMode_5g(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;
	int wl_index = name->name[name->namelen - 1];

	if(wl_index!=0)
		wl_index -=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_WLanAccessControlOpMode(0, (wl_index), (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_WLanAccessControlOpMode_5g(int *var_len, Oid * newoid,
						Oid * reqoid, int searchType,
						snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen++;
	int wl_index = 0;
	while (wl_index < 4) {
		newoid->name[index] = wl_index + 1;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		wl_index++;
	}
//change
	if (wl_index >= 4) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	switch (column) {
	case I_wlanAccessControlSSIDIndex_5g:
		public_mib_buffer.gb_long = wl_index+1;
		*write_method = 0;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanAccessControlSSID_5g:
		get_wlanSSID(0, (wl_index), public_mib_buffer.gb_string);
		*write_method = 0;
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_wlanAccessControlOpMode_5g:
		public_mib_buffer.gb_long = get_WLanAccessControlOpMode(0, (wl_index));
		*write_method = (int (*)())&write_WLanAccessControlOpMode_5g;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	default:
		return (unsigned char *)NO_MIBINSTANCE;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}

int write_WLanAccessControlSetSSIDIndex_5g(int action, unsigned char *var_val,
						unsigned char varval_type, int var_val_len,
						unsigned char *statP, Oid * name)
{
	int ret=1;
	int res;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		res = (int)mhtol(var_val, var_val_len);
		if( res < 0 || res > 5)
			ret = 0;
		else
			wlan_acl_set.idx = res - 1;
		/*if (res == 0)
			ret = 1;
		else
			ret = 0;*/
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_WLanAccessControlSetSSIDIndex_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = wlan_acl_set.idx + 1;
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_WLanAccessControlSetSSIDIndex_5g;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_WLanAccessControlSetSSID_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	sprintf(public_mib_buffer.gb_string, "---");
	*var_len = strlen(public_mib_buffer.gb_string);
	*write_method = 0;
	return (unsigned char*)public_mib_buffer.gb_string;
}

int write_WLanAccessControlListSetMacAddr_5g(int action, unsigned char *var_val,
						unsigned char varval_type, int var_val_len,
						unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_AccessControlListSetMacAddr(var_val, var_val_len, wlan_acl_set.mac);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_WLanAccessControlSetMacAddr_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	memcpy(public_mib_buffer.gb_string, wlan_acl_set.mac, 6);
	*var_len = sizeof(wlan_acl_set.mac);
	*write_method = (int (*)())&write_WLanAccessControlListSetMacAddr_5g;
	return (unsigned char*)public_mib_buffer.gb_string;
}

int write_WLanAccessControlListSetComment_5g(int action, unsigned char *var_val,
						unsigned char varval_type, int var_val_len,
						unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		strcpy(wlan_acl_set.comment, var_val);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return 0;
}

unsigned char *var_WLanAccessControlSetComment_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	strcpy(public_mib_buffer.gb_string, wlan_acl_set.comment);
	*var_len = strlen(public_mib_buffer.gb_string);
	*write_method = (int (*)())&write_WLanAccessControlListSetComment_5g;
	return (unsigned char*)public_mib_buffer.gb_string;
}

int write_WLanAccessControlListAdd_5g(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		/*int res;
		res = (int)mhtol(var_val, var_val_len);
		if(res<0 || res>4)
			ret = 0;
		else*/
			ret = WLanAccessControlListAdd(0, wlan_acl_set.idx, wlan_acl_set.mac, wlan_acl_set.comment);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_WLanAccessControlListAdd_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = 0;
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_WLanAccessControlListAdd_5g;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_WLanAccessControlListDel_5g(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		if(wlan_acl_set.idx > 4)
			ret = 0;
		else{
			ret = WLanAccessControlListDel(0, wlan_acl_set.idx, (int)mhtol(var_val, var_val_len));
			wlan_acl_set.idx=0;
		}
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_WLanAccessControlListDel_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = 0;
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_WLanAccessControlListDel_5g;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_WLanAccessControlListDelAll_5g(int action, unsigned char *var_val,
						unsigned char varval_type, int var_val_len,
						unsigned char *statP, Oid * name)
{
	int ret=1;
	int res;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		res = (int)mhtol(var_val, var_val_len);
		if(res > 5)
			ret = 0;
		else
			ret = WLanAccessControlListDelAll(0, (res));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}
	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_WLanAccessControlListDelAll_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = 0;
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_WLanAccessControlListDelAll_5g;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

wlan_acl_tbl_info_t wl_acl_tbl_5g[100];
unsigned char *var_WLanAccessControlListView_5g(int *var_len, Oid * newoid,
						Oid * reqoid, int searchType,
						snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen++;
	int tbl_index = 1;
	int entry_idx = 0;
	static int pre_acl_tbl_idx;
	int dp_tbl_index = 0;
	static int tbl_entryNum;
	if ( tbl_entryNum == 0)
		tbl_entryNum = get_wlan_acl_info(0, &wl_acl_tbl_5g[0]);

	while (tbl_index <= tbl_entryNum) {
		newoid->name[index] = tbl_index;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		tbl_index++;
	}
	*write_method = 0;

	if (tbl_index > tbl_entryNum) {
		if ( column == I_wlanAccessControlListDescription) {
			tbl_entryNum = 0;
			pre_acl_tbl_idx = -1;
		}
		return NO_MIBINSTANCE;
	}

	if ( (entry_idx =(tbl_index - 1)) < 0 )
		entry_idx = 0;

	pre_acl_tbl_idx = wl_acl_tbl_5g[entry_idx].ssid_idx;

	switch (column) {
	case I_wlanAccessControlListIndex_5g:
		dp_tbl_index = entry_idx + 1;
		public_mib_buffer.gb_long = dp_tbl_index++;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanAccessControlListSSIDIndex_5g:
		public_mib_buffer.gb_long = wl_acl_tbl_5g[entry_idx].ssid_idx + 1;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanAccessControlListSSID_5g:
		get_wlanSSID(0, wl_acl_tbl_5g[entry_idx].ssid_idx, public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_wlanAccessControlListHwAddr_5g:
		if ( wl_acl_tbl_5g[entry_idx].write ) {
			memcpy(public_mib_buffer.gb_string, wl_acl_tbl_5g[entry_idx].mac, 6);
			*var_len = 6;
		}
		else {
			memset(public_mib_buffer.gb_string, 0, sizeof(public_mib_buffer.gb_string));
			*var_len = 0;
		}
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_wlanAccessControlListDescription_5g:
		if ( wl_acl_tbl_5g[entry_idx].write )
			sprintf(public_mib_buffer.gb_string, "%s", wl_acl_tbl_5g[entry_idx].comment);
		else
			public_mib_buffer.gb_string[0] = 0;

		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}
static oid WLanAccessControlConfig_oid[] = { O_WLanAccessControlConfig };

static Object WLanAccessControlConfig_var[] = {
	{SNMP_INTEGER, (RONLY | COLUMN), var_WLanAccessControlOpMode,
	 {3, {I_wlanAccessControlModeTable, I_wlanAccessControlModeEntry, I_wlanAccessControlSSIDIndex}}},
	{SNMP_STRING, (RONLY | COLUMN), var_WLanAccessControlOpMode,
	 {3, {I_wlanAccessControlModeTable, I_wlanAccessControlModeEntry, I_wlanAccessControlSSID}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_WLanAccessControlOpMode,
	 {3, {I_wlanAccessControlModeTable, I_wlanAccessControlModeEntry, I_wlanAccessControlOpMode}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_WLanAccessControlSetSSIDIndex,
	 {2, {I_wlanAccessControlListConfig, I_wlanAccessControlSetSSIDIndex}}},
	{SNMP_STRING, (RONLY | SCALAR), var_WLanAccessControlSetSSID,
	 {2, {I_wlanAccessControlListConfig, I_wlanAccessControlSetSSID}}},
	{SNMP_STRING, (RWRITE | SCALAR), var_WLanAccessControlSetMacAddr,
	 {2, {I_wlanAccessControlListConfig, I_wlanAccessControlListSetMacAddr}}},
	{SNMP_STRING, (RWRITE | SCALAR), var_WLanAccessControlSetComment,
	 {2, {I_wlanAccessControlListConfig, I_wlanAccessControlListSetComment}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_WLanAccessControlListAdd,
	 {2, {I_wlanAccessControlListConfig, I_wlanAccessControlListAdd}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_WLanAccessControlListDel,
	 {2, {I_wlanAccessControlListConfig, I_wlanAccessControlListDel}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_WLanAccessControlListDelAll,
	 {2, {I_wlanAccessControlListConfig, I_wlanAccessControlListDelAll}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_WLanAccessControlListView,
	 {4,
	  {I_wlanAccessControlListConfig, I_wlanAccessControlListTable, I_wlanAccessControlListEntry,
	   I_wlanAccessControlListIndex}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_WLanAccessControlListView,
	 {4,
	  {I_wlanAccessControlListConfig, I_wlanAccessControlListTable, I_wlanAccessControlListEntry,
	   I_wlanAccessControlListSSIDIndex}}},
	{SNMP_STRING, (RONLY | COLUMN), var_WLanAccessControlListView,
	 {4,
	  {I_wlanAccessControlListConfig, I_wlanAccessControlListTable, I_wlanAccessControlListEntry,
	   I_wlanAccessControlListSSID}}},
	{SNMP_STRING, (RONLY | COLUMN), var_WLanAccessControlListView,
	 {4,
	  {I_wlanAccessControlListConfig, I_wlanAccessControlListTable, I_wlanAccessControlListEntry,
	   I_wlanAccessControlListHwAddr}}},
	{SNMP_STRING, (RONLY | COLUMN), var_WLanAccessControlListView,
	 {4,
	  {I_wlanAccessControlListConfig, I_wlanAccessControlListTable, I_wlanAccessControlListEntry,
	   I_wlanAccessControlListDescription}}},
	   {0}
};

static SubTree WLanAccessControlConfig_tree = { NULL, WLanAccessControlConfig_var,
	(sizeof(WLanAccessControlConfig_oid) / sizeof(oid)), WLanAccessControlConfig_oid
};

static oid WLanAccessControlConfig_5g_oid[] = {O_WLanAccessControlConfig_5g};

static Object WLanAccessControlConfig_5g_var[] = {
	{SNMP_INTEGER, (RONLY | COLUMN), var_WLanAccessControlOpMode_5g,
	 {3, {I_wlanAccessControlModeTable_5g, I_wlanAccessControlModeEntry_5g, I_wlanAccessControlSSIDIndex_5g}}},
	{SNMP_STRING, (RONLY | COLUMN), var_WLanAccessControlOpMode_5g,
	 {3, {I_wlanAccessControlModeTable_5g, I_wlanAccessControlModeEntry_5g, I_wlanAccessControlSSID_5g}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_WLanAccessControlOpMode_5g,
	 {3, {I_wlanAccessControlModeTable_5g, I_wlanAccessControlModeEntry_5g, I_wlanAccessControlOpMode_5g}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_WLanAccessControlSetSSIDIndex_5g,
	 {2, {I_wlanAccessControlListConfig_5g, I_wlanAccessControlSetSSIDIndex_5g}}},
	{SNMP_STRING, (RONLY | SCALAR), var_WLanAccessControlSetSSID_5g,
	 {2, {I_wlanAccessControlListConfig_5g, I_wlanAccessControlSetSSID_5g}}},
	{SNMP_STRING, (RWRITE | SCALAR), var_WLanAccessControlSetMacAddr_5g,
	 {2, {I_wlanAccessControlListConfig_5g, I_wlanAccessControlListSetMacAddr_5g}}},
	{SNMP_STRING, (RWRITE | SCALAR), var_WLanAccessControlSetComment_5g,
	 {2, {I_wlanAccessControlListConfig_5g, I_wlanAccessControlListSetComment_5g}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_WLanAccessControlListAdd_5g,
	 {2, {I_wlanAccessControlListConfig_5g, I_wlanAccessControlListAdd_5g}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_WLanAccessControlListDel_5g,
	 {2, {I_wlanAccessControlListConfig_5g, I_wlanAccessControlListDel_5g}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_WLanAccessControlListDelAll_5g,
	 {2, {I_wlanAccessControlListConfig_5g, I_wlanAccessControlListDelAll_5g}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_WLanAccessControlListView_5g,
	 {4, {I_wlanAccessControlListConfig_5g, I_wlanAccessControlListTable_5g, I_wlanAccessControlListEntry_5g, I_wlanAccessControlListIndex_5g}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_WLanAccessControlListView_5g,
	 {4, {I_wlanAccessControlListConfig_5g, I_wlanAccessControlListTable_5g, I_wlanAccessControlListEntry_5g, I_wlanAccessControlListSSIDIndex_5g}}},
	{SNMP_STRING, (RONLY | COLUMN), var_WLanAccessControlListView_5g,
	 {4, {I_wlanAccessControlListConfig_5g, I_wlanAccessControlListTable_5g, I_wlanAccessControlListEntry_5g, I_wlanAccessControlListSSID_5g}}},
	{SNMP_STRING, (RONLY | COLUMN), var_WLanAccessControlListView_5g,
	 {4, {I_wlanAccessControlListConfig_5g, I_wlanAccessControlListTable_5g, I_wlanAccessControlListEntry_5g, I_wlanAccessControlListHwAddr_5g}}},
	{SNMP_STRING, (RONLY | COLUMN), var_WLanAccessControlListView_5g,
	 {4, {I_wlanAccessControlListConfig_5g, I_wlanAccessControlListTable_5g, I_wlanAccessControlListEntry_5g, I_wlanAccessControlListDescription_5g}}},
	{0}
};
static SubTree WLanAccessControlConfig_5g_tree = { NULL, WLanAccessControlConfig_5g_var,
	(sizeof(WLanAccessControlConfig_5g_oid) / sizeof(oid)), WLanAccessControlConfig_5g_oid
};

/*VLAN Configuration */
unsigned char *var_vlanConfig(int *var_len, Oid * newoid,
				Oid * reqoid, int searchType,
				snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen++;
	int tbl_index = 1;
	char param[16], *ptr;

	while (tbl_index <= 16) {
		sprintf(param, "x_VLAN_%d", tbl_index - 1);
		ptr = getValue(param);
		if(ptr) {
			newoid->name[index] = tbl_index;
			result = compare(reqoid, newoid);
			if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
				break;
			}
		}
		tbl_index++;
	}
	if (tbl_index > 16) {
		return (unsigned char *)NO_MIBINSTANCE;
	}
	*write_method = 0;

	switch (column) {
	case I_vlanConfigIndex:
		public_mib_buffer.gb_long = tbl_index;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_vlanConfigVid:
		public_mib_buffer.gb_long = get_vlanVid(tbl_index - 1);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_vlanConfigMemberPort:
		public_mib_buffer.gb_long = get_vlanMemberPort(tbl_index - 1);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}
static oid vlanConfig_oid[] = { O_vlanConfig };

static Object vlanConfig_var[] = {
	{SNMP_INTEGER, (RONLY | COLUMN), var_vlanConfig,
	 {3, {I_vlanConfigTable, I_vlanConfigEntry, I_vlanConfigIndex}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_vlanConfig,
	 {3, {I_vlanConfigTable, I_vlanConfigEntry, I_vlanConfigVid}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_vlanConfig,
	 {3, {I_vlanConfigTable, I_vlanConfigEntry, I_vlanConfigMemberPort}}},
	{ 0 }
};

static SubTree vlanConfig_tree = { NULL, vlanConfig_var,
	(sizeof(vlanConfig_oid) / sizeof(oid)), vlanConfig_oid
};

/* Port Fw Configuration */
int write_portFwProtocol(int action,
		unsigned char *var_val, unsigned char varval_type, int var_val_len,
		unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_portFwProtocol(var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_PortFwProtocol(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	get_portFwProtocol(public_mib_buffer.gb_string);

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_portFwProtocol;
	/* Set size (in bytes) and return address of the variable */
	*var_len = strlen(public_mib_buffer.gb_string);
	return public_mib_buffer.gb_string;
}

int write_PortFwExternalSport(int action,
		unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_PortFwExternalSport((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_PortFwExternalSport(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = get_PortFwExternalSport();

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_PortFwExternalSport;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_PortFwExternalEport(int action,
		unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_PortFwExternalEport((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_PortFwExternalEport(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = get_PortFwExternalEport();

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_PortFwExternalEport;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_PortFwIpAddress(int action,
		unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_PortFwIpAddress(var_val);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_PortFwIpAddress(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	get_PortFwIpAddress(&public_mib_buffer.gb_long);
	*write_method = (int (*)())&write_PortFwIpAddress;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(public_mib_buffer.gb_long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_PortFwInternalSport(int action,
		unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_PortFwInternalSport((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_PortFwInternalSport(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = get_PortFwInternalSport();
	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_PortFwInternalSport;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_PortFwInternalEport(int action,
		unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_PortFwInternalEport((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_PortFwInternalEport(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = get_PortFwInternalEport();
	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_PortFwInternalEport;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_PortFwEnable(int action,
		unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_PortFwEnable((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_PortFwEnable(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = 0;
	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_PortFwEnable;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_PortFwDelete(int action,
		unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_PortFwDelete((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_PortFwDelete(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = 0;
	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_PortFwDelete;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_PortFwDeleteAll(int action,
		unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_PortFwDeleteAll((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_PortFwDeleteAll(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = 0;
	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_PortFwDeleteAll;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_portFwStartPort(int action,
		unsigned char *var_val, unsigned char varval_type, int var_val_len,
		unsigned char *statP, Oid * reqOid)
{
	int ret = 0;
	int index = reqOid->name[(reqOid->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_portFwStartPort(index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? 0 : SNMP_ERROR_WRONGVALUE;
}

int write_portFwEndPort(int action,
		unsigned char *var_val, unsigned char varval_type, int var_val_len,
		unsigned char *statP, Oid * reqOid)
{
	int ret = 0;
	int index = reqOid->name[(reqOid->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_portFwEndPort(index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? 0 : SNMP_ERROR_WRONGVALUE;
}

int write_PortfwLanAddr(int action,
		unsigned char *var_val, unsigned char varval_type, int var_val_len,
		unsigned char *statP, Oid * reqOid)
{
	int ret = 0;
	int index = reqOid->name[(reqOid->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_PortfwLanAddr(index, var_val);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? 0 : SNMP_ERROR_WRONGVALUE;
}

int write_portFwLanPort(int action,
		unsigned char *var_val, unsigned char varval_type, int var_val_len,
		unsigned char *statP, Oid * reqOid)
{
	int ret = 0;
	int index = reqOid->name[(reqOid->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_portFwLanPort(index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? 0 : SNMP_ERROR_WRONGVALUE;
}

int write_portFwLanEndPort(int action,
		unsigned char *var_val, unsigned char varval_type, int var_val_len,
		unsigned char *statP, Oid * reqOid)
{
	int ret = 0;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? 0 : SNMP_ERROR_WRONGVALUE;
}

unsigned char *
var_PortFwdEntry(int *var_len,
		Oid *newoid, Oid *reqoid, int searchType,
		snmp_info_t *mesg, int (**write_method)())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen++;
	int tbl_index = 0;
	static int tbl_entryNum = 0;
	static int count = 0;
	char buf[12];

	if(!portfw_tblnum)
		return NO_MIBINSTANCE;
	else
		tbl_entryNum = portfw_tblnum;

	while (tbl_index + 1 <= tbl_entryNum) {
		newoid->name[index] = tbl_index;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		tbl_index++;
	}

	if (tbl_index + 1 > tbl_entryNum) {
		if(count >= tbl_entryNum){
			count = 0;
			tbl_entryNum = 0;
		}
		return NO_MIBINSTANCE;
	}

	switch (column) {
		case I_portfwConfigListIndex:
			public_mib_buffer.gb_long = tbl_index + 1;
			*var_len = sizeof(long);
			*write_method = 0;
			return (unsigned char *)&public_mib_buffer.gb_long;
		case I_portfwConfigListExternalPortStart:
			public_mib_buffer.gb_long = get_portFwStartPort(tbl_index);
			*var_len = sizeof(long);
			*write_method = (int (*)())&write_portFwStartPort;
			return (unsigned char *)&public_mib_buffer.gb_long;
		case I_portfwConfigListExternalPortEnd:
			public_mib_buffer.gb_long = get_portFwEndPort(tbl_index);
			*var_len = sizeof(long);
			*write_method = (int (*)())&write_portFwEndPort;
			return (unsigned char *)&public_mib_buffer.gb_long;
		case I_portfwConfigListIpAddres:
			get_PortfwIpAddress(tbl_index, &public_mib_buffer.gb_long);
			*var_len = sizeof(long);
			*write_method = (int (*)())&write_PortfwLanAddr;
			return (unsigned char *)&public_mib_buffer.gb_long;
		case I_portfwConfigListInternalPortStart:
			public_mib_buffer.gb_long = get_portFwLanPort(tbl_index);
			*var_len = sizeof(long);
			*write_method = (int (*)())&write_portFwLanPort;
			return (unsigned char *)&public_mib_buffer.gb_long;
		case I_portfwConfigListInternalPortEnd:
			count++;
			if(count > tbl_index + 1)
				count = tbl_index + 1;
			public_mib_buffer.gb_long = get_portFwLanPort(tbl_index);
			*var_len = sizeof(long);
			*write_method = (int (*)())&write_portFwLanEndPort;
			return (unsigned char *)&public_mib_buffer.gb_long;
		default:
			return NO_MIBINSTANCE;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}

static oid portfwConfig_oid[] = { O_portfwConfig };

static Object portfwConfig_var[] = {
	{SNMP_STRING, (RWRITE | SCALAR), var_PortFwProtocol,
 	 {1, {I_portfwConfigtype}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_PortFwExternalSport,
  	 {1, {I_portfwConfigExternalPortStrat}}},
 	{SNMP_INTEGER, (RWRITE | SCALAR), var_PortFwExternalEport,
	 {1, {I_portfwConfigExternalPortEnd}}},
	{SNMP_IPADDRESS, (RWRITE | SCALAR), var_PortFwIpAddress,
	 {1, {I_portfwConfigIpAddress}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_PortFwInternalSport,
	 {1, {I_portfwConfigInternalPortStrat}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_PortFwInternalEport,
	 {1, {I_portfwConfigInternalPortEnd}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_PortFwEnable,
	 {1, {I_portfwConfigAdd}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_PortFwDelete,
	 {1, {I_portfwConfigDel}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_PortFwDeleteAll,
	 {1, {I_portfwConfigDelAll}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_PortFwdEntry,
	 {3, {I_portfwConfigTable, I_portfwConfigListEntry, I_portfwConfigListIndex}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_PortFwdEntry,
	 {3, {I_portfwConfigTable, I_portfwConfigListEntry, I_portfwConfigListExternalPortStart}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_PortFwdEntry,
	 {3, {I_portfwConfigTable, I_portfwConfigListEntry, I_portfwConfigListExternalPortEnd}}},
	{SNMP_IPADDRESS, (RWRITE | COLUMN), var_PortFwdEntry,
	 {3, {I_portfwConfigTable, I_portfwConfigListEntry, I_portfwConfigListIpAddres}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_PortFwdEntry,
	 {3, {I_portfwConfigTable, I_portfwConfigListEntry, I_portfwConfigListInternalPortStart}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_PortFwdEntry,
	 {3, {I_portfwConfigTable, I_portfwConfigListEntry, I_portfwConfigListInternalPortEnd}}},
	{ 0 }
};

static SubTree PortfwConfig_tree = { NULL, portfwConfig_var,
	    (sizeof(portfwConfig_oid) / sizeof(oid)), portfwConfig_oid
};

/* System Log Configuration */
int write_sysLogEnable(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_sysLogEnable((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_sysLogEnable(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = get_sysLogEnable();

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_sysLogEnable;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_sysLogRemoteLogEnable(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_sysLogRemoteLogEnable((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_sysLogRemoteLogEnable(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = get_sysLogRemoteLogEnable();

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_sysLogRemoteLogEnable;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_sysLogRemoteLogServer(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_sysLogRemoteLogServer(var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_sysLogRemoteLogServer(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	get_sysLogRemoteLogServer(public_mib_buffer.gb_string);

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_sysLogRemoteLogServer;
	/* Set size (in bytes) and return address of the variable */
	*var_len = strlen(public_mib_buffer.gb_string);
	return (unsigned char*)public_mib_buffer.gb_string;
}

static oid sysLogConfig_oid[] = { O_sysLogConfig };

static Object sysLogConfig_var[] = {
	{SNMP_INTEGER, (RWRITE | SCALAR), var_sysLogEnable,
	 {1, {I_sysLogEnable}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_sysLogRemoteLogEnable,
	 {1, {I_sysLogRemoteLogEnable}}},
	{SNMP_STRING, (RWRITE | SCALAR), var_sysLogRemoteLogServer,
	 {1, {I_sysLogRemoteLogServer}}},
	{}
};

static SubTree sysLogConfig_tree = { NULL, sysLogConfig_var,
	(sizeof(sysLogConfig_oid) / sizeof(oid)), sysLogConfig_oid
};

/* NTP Configuration */
int write_ntpServer1(int action,
					 unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_ntpServer(0, var_val);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_ntpServer1(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	get_ntpServer(0, public_mib_buffer.gb_string);

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_ntpServer1;
	/* Set size (in bytes) and return address of the variable */
	*var_len = strlen(public_mib_buffer.gb_string);
	return (unsigned char*)public_mib_buffer.gb_string;
}

int write_ntpServer2(int action,
					 unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_ntpServer(1, var_val);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_ntpServer2(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	get_ntpServer(1, public_mib_buffer.gb_string);

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_ntpServer2;
	/* Set size (in bytes) and return address of the variable */
	*var_len = strlen(public_mib_buffer.gb_string);
	return (unsigned char*)public_mib_buffer.gb_string;
}

int write_ntpServer3(int action,
					 unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret=1;
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_ntpServer(2, var_val);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_ntpServer3(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	get_ntpServer(2, public_mib_buffer.gb_string);

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_ntpServer3;
	/* Set size (in bytes) and return address of the variable */
	*var_len = strlen(public_mib_buffer.gb_string);
	return (unsigned char*)public_mib_buffer.gb_string;
}

static oid ntpConfig_oid[] = { O_ntpConfig };

static Object ntpConfig_var[] = {
	{SNMP_STRING, (RWRITE | SCALAR), var_ntpServer1,
	 {1, {I_ntpServer1Name}}},
	{SNMP_STRING, (RWRITE | SCALAR), var_ntpServer2,
	 {1, {I_ntpServer2Name}}},
	{SNMP_STRING, (RWRITE | SCALAR), var_ntpServer3,
	 {1, {I_ntpServer3Name}}},
	{ 0 }
};

static SubTree ntpConfig_tree = { NULL, ntpConfig_var,
	(sizeof(ntpConfig_oid) / sizeof(oid)), ntpConfig_oid
};

// QoS Configuration

int write_PortRateLimitMode(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqoid)
{
	int ret=1;
	int port_index = reqoid->name[reqoid->namelen - 1];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_PortRateLimitMode(port_index, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_PortRateLimitIncomming(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * reqoid)
{
	int ret=1;
	int port_index = reqoid->name[reqoid->namelen - 1];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_PortRateLimitIncomming(port_index, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_PortRateLimitOutgoing(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqoid)
{
	int ret=1;
	int port_index = reqoid->name[reqoid->namelen - 1];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_PortRateLimitOutgoing(port_index, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_PortFlowControl(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqoid)
{
	int ret=1;
	int port_index = reqoid->name[reqoid->namelen - 1];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_PortFlowControl(port_index, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_PortRateLimitConfig(int *var_len, Oid * newoid,
					Oid * reqoid, int searchType,
					snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen++;
	int port_index = 0;

	while (port_index < MAX_PORT) {
		newoid->name[index] = port_index;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		port_index++;
	}
	if (port_index >= MAX_PORT) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	switch (column) {
	case I_PortRateLimitIndex:
		public_mib_buffer.gb_long = port_index+1;
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_PortRateLimitPortNumber:
		public_mib_buffer.gb_long = port_index;
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_PortRateLimitPortName:
		strcpy(public_mib_buffer.gb_string, DevPortName[port_index_change(port_index)]);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = 0;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_PortRateLimitMode:
		public_mib_buffer.gb_long = get_PortRateLimitMode(port_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_PortRateLimitMode;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_PortRateLimitIncomming:
		public_mib_buffer.gb_long = get_PortRateLimitIncomming(port_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_PortRateLimitIncomming;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_PortRateLimitOutgoing:
		public_mib_buffer.gb_long = get_PortRateLimitOutgoing(port_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_PortRateLimitOutgoing;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_PortFlowControl:
		public_mib_buffer.gb_long = get_PortFlowControl(port_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_PortFlowControl;
		return (unsigned char *)&public_mib_buffer.gb_long;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}

unsigned char *var_PortQosTableView(int *var_len, Oid * newoid, Oid * reqoid,
					int searchType, snmp_info_t * mesg,
					int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen++;
	int port_index = 0;

	while (port_index < MAX_PORT) {
		newoid->name[index] = port_index;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		port_index++;
	}
	if (port_index >= MAX_PORT) {
		return (unsigned char *)NO_MIBINSTANCE;
	}
	*write_method = 0;

	switch (column) {
	case I_PortQosIndex:
		public_mib_buffer.gb_long = port_index+1;
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_PortQosPortNumber:
		public_mib_buffer.gb_long = port_index;
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_PortQosPortName:
		strcpy(public_mib_buffer.gb_string, DevPortName[port_index_change(port_index)]);
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = 0;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_PortQosPriority:
		public_mib_buffer.gb_long = get_PortQosPriority(port_index);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}

unsigned char *var_QosClassfyView(int *var_len, Oid * newoid,
					Oid * reqoid, int searchType,
					snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int oidLen = newoid->namelen++;
	int index = 0;
	int QosRuleCount = 0;
	char *tmpBuf;

   	tmpBuf = getValue("x_Q_R_NUM");
	if(tmpBuf)
		QosRuleCount = atoi(tmpBuf);

	while (index < QosRuleCount) {
		newoid->name[oidLen] = index;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		index++;
	}
	if (index >= QosRuleCount)
		return (unsigned char *)NO_MIBINSTANCE;

	*write_method = 0;

	switch (column) {
	case I_QosClassIndex:
		public_mib_buffer.gb_long = index+1;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_QosClassDstIp:
		get_QosRuleDstIp(index, public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_QosClassSrcIp:
		get_QosRuleSrcIp(index, public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_QosClassDstPortStart:
		get_QosRuleDstPortStart(index, public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_QosClassDstPortEnd:
		get_QosRuleDstPortEnd(index, public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_QosClassSrcPortStart:
		get_QosRuleSrcPortStart(index, public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_QosClassSrcPortEnd:
		*var_len = strlen(public_mib_buffer.gb_string);
		get_QosRuleSrcPortEnd(index, public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_QosClassDstMac:
		get_QosRuleDstMacAddr(index, public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_QosClassSrcMac:
		get_QosRuleSrcMacAddr(index, public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_QosClassProtocol:
		get_QosRuleProtocol(index, public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_QosClassCos:
		public_mib_buffer.gb_long = get_QosRuleCos(index);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_QosClassIpTosType:
		public_mib_buffer.gb_long = get_QosRuleTosType(index);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_QosClassIpTos:
		public_mib_buffer.gb_long = get_QosRuleTos(index);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_QosClassEthType:
		get_QosRuleEthType(index, public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_QosClassMarkIndex:
		public_mib_buffer.gb_long = get_QosRuleMarkIndex(index);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	default:
		return (unsigned char *)NO_MIBINSTANCE;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}

unsigned char *var_QosMarkView(int *var_len, Oid * newoid, Oid * reqoid,
				int searchType, snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen++;
	int tn = 0;
	char *ptr, *ptr2;

	ptr = getValue("x_QOS_RM_1Q");
	ptr2 = getValue("x_QOS_RM_DSCP");
	if (!ptr && !ptr2)
		return (unsigned char *)NO_MIBINSTANCE;

	while (tn < 8) {
		newoid->name[index] = tn;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		tn++;
	}
	if (tn >= 8) {
		return (unsigned char *)NO_MIBINSTANCE;
	}
	*write_method = 0;

	switch (column) {
		case I_QosMarkIndex:
			public_mib_buffer.gb_long = tn+1;
			*var_len = sizeof(long);
			return (unsigned char *)&public_mib_buffer.gb_long;
		case I_QosMarkCosRemark:
			public_mib_buffer.gb_long = get_QosMarkCosRemark(tn);
			*var_len = sizeof(long);
			return (unsigned char *)&public_mib_buffer.gb_long;
		case I_QosMarkDscpRemark:
			get_QosMarkDscpRemark(tn, public_mib_buffer.gb_string);
			*var_len = strlen(public_mib_buffer.gb_string);
			return (unsigned char*)public_mib_buffer.gb_string;
		case I_QosMarkPriority:
			public_mib_buffer.gb_long = tn;
			*var_len = sizeof(long);
			return (unsigned char *)&public_mib_buffer.gb_long;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}

unsigned char *var_QosScheduleView(int *var_len, Oid * newoid,
					Oid * reqoid, int searchType,
					snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index1 = newoid->namelen++;
	int index2 = newoid->namelen++;
	int port_index = 0;
	int q_index;

	while (port_index < MAX_PORT) {
		newoid->name[index1] = port_index;
		for (q_index = 0; q_index < 4; q_index++) {
			newoid->name[index2] = q_index;
			result = compare(reqoid, newoid);
			if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
				break;
			}
		}
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0)))
			break;
		port_index++;
	}

	if (port_index >= MAX_PORT)
		return (unsigned char *)NO_MIBINSTANCE;

	*write_method = 0;

	switch (column) {
	case I_QosSchedulePortNumber:
		public_mib_buffer.gb_long = port_index;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_QosSchedulePortName:
		strcpy(public_mib_buffer.gb_string, DevPortName[port_index_change(port_index)]);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_QosScheduleQueue:
		public_mib_buffer.gb_long = q_index;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_QosScheduleMode:
		public_mib_buffer.gb_long = get_QosScheduleMode(port_index, q_index);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_QosScheduleWeight:
		public_mib_buffer.gb_long = get_QosScheduleWeight(port_index, q_index);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}

static oid QosConfig_oid[] = { O_QosConfig };

static Object QosConfig_var[] = {
	{SNMP_INTEGER, (RONLY | COLUMN), var_PortRateLimitConfig,
	 {3, {I_QosPortRateLimitTable, I_PortRateLimitEntry, I_PortRateLimitIndex}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_PortRateLimitConfig,
	 {3, {I_QosPortRateLimitTable, I_PortRateLimitEntry, I_PortRateLimitPortNumber}}},
	{SNMP_STRING, (RONLY | COLUMN), var_PortRateLimitConfig,
	 {3, {I_QosPortRateLimitTable, I_PortRateLimitEntry, I_PortRateLimitPortName}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_PortRateLimitConfig,
	 {3, {I_QosPortRateLimitTable, I_PortRateLimitEntry, I_PortRateLimitMode}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_PortRateLimitConfig,
	 {3, {I_QosPortRateLimitTable, I_PortRateLimitEntry, I_PortRateLimitIncomming}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_PortRateLimitConfig,
	 {3, {I_QosPortRateLimitTable, I_PortRateLimitEntry, I_PortRateLimitOutgoing}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_PortRateLimitConfig,
	 {3, {I_QosPortRateLimitTable, I_PortRateLimitEntry, I_PortFlowControl}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_PortQosTableView,
	 {3, {I_PortQosTable, I_PortQosEntry, I_PortQosIndex}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_PortQosTableView,
	 {3, {I_PortQosTable, I_PortQosEntry, I_PortQosPortNumber}}},
	{SNMP_STRING, (RONLY | COLUMN), var_PortQosTableView,
	 {3, {I_PortQosTable, I_PortQosEntry, I_PortQosPortName}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_PortQosTableView,
	 {3, {I_PortQosTable, I_PortQosEntry, I_PortQosPriority}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_QosClassfyView,
	 {3, {I_QosClassfyTable, I_QosClassfyEntry, I_QosClassIndex}}},
	{SNMP_STRING, (RONLY | COLUMN), var_QosClassfyView,
	 {3, {I_QosClassfyTable, I_QosClassfyEntry, I_QosClassDstIp}}},
	{SNMP_STRING, (RONLY | COLUMN), var_QosClassfyView,
	 {3, {I_QosClassfyTable, I_QosClassfyEntry, I_QosClassSrcIp}}},
	{SNMP_STRING, (RONLY | COLUMN), var_QosClassfyView,
	 {3, {I_QosClassfyTable, I_QosClassfyEntry, I_QosClassDstPortStart}}},
	{SNMP_STRING, (RONLY | COLUMN), var_QosClassfyView,
	 {3, {I_QosClassfyTable, I_QosClassfyEntry, I_QosClassDstPortEnd}}},
	{SNMP_STRING, (RONLY | COLUMN), var_QosClassfyView,
	 {3, {I_QosClassfyTable, I_QosClassfyEntry, I_QosClassSrcPortStart}}},
	{SNMP_STRING, (RONLY | COLUMN), var_QosClassfyView,
	 {3, {I_QosClassfyTable, I_QosClassfyEntry, I_QosClassSrcPortEnd}}},
	{SNMP_STRING, (RONLY | COLUMN), var_QosClassfyView,
	 {3, {I_QosClassfyTable, I_QosClassfyEntry, I_QosClassDstMac}}},
	{SNMP_STRING, (RONLY | COLUMN), var_QosClassfyView,
	 {3, {I_QosClassfyTable, I_QosClassfyEntry, I_QosClassSrcMac}}},
	{SNMP_STRING, (RONLY | COLUMN), var_QosClassfyView,
	 {3, {I_QosClassfyTable, I_QosClassfyEntry, I_QosClassProtocol}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_QosClassfyView,
	 {3, {I_QosClassfyTable, I_QosClassfyEntry, I_QosClassCos}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_QosClassfyView,
	 {3, {I_QosClassfyTable, I_QosClassfyEntry, I_QosClassIpTosType}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_QosClassfyView,
	 {3, {I_QosClassfyTable, I_QosClassfyEntry, I_QosClassIpTos}}},
	{SNMP_STRING, (RONLY | COLUMN), var_QosClassfyView,
	 {3, {I_QosClassfyTable, I_QosClassfyEntry, I_QosClassEthType}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_QosClassfyView,
	 {3, {I_QosClassfyTable, I_QosClassfyEntry, I_QosClassMarkIndex}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_QosMarkView,
	 {3, {I_QosMarkTable, I_QosMarkTableEntry, I_QosMarkIndex}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_QosMarkView,
	 {3, {I_QosMarkTable, I_QosMarkTableEntry, I_QosMarkCosRemark}}},
	{SNMP_STRING, (RONLY | COLUMN), var_QosMarkView,
	 {3, {I_QosMarkTable, I_QosMarkTableEntry, I_QosMarkDscpRemark}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_QosMarkView,
	 {3, {I_QosMarkTable, I_QosMarkTableEntry, I_QosMarkPriority}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_QosScheduleView,
	 {3, {I_QosScheduleTable, I_QosScheduleTableEntry, I_QosSchedulePortNumber}}},
	{SNMP_STRING, (RONLY | COLUMN), var_QosScheduleView,
	 {3, {I_QosScheduleTable, I_QosScheduleTableEntry, I_QosSchedulePortName}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_QosScheduleView,
	 {3, {I_QosScheduleTable, I_QosScheduleTableEntry, I_QosScheduleQueue}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_QosScheduleView,
	 {3, {I_QosScheduleTable, I_QosScheduleTableEntry, I_QosScheduleMode}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_QosScheduleView,
	 {3, {I_QosScheduleTable, I_QosScheduleTableEntry, I_QosScheduleWeight}}},
	{0}
};

static SubTree QosConfig_tree = { NULL, QosConfig_var,
	(sizeof(QosConfig_oid) / sizeof(oid)), QosConfig_oid
};

/* AP Status */
unsigned char *var_igmpJoinStatus(int *var_len, Oid * newoid,
					Oid * reqoid, int searchType,
					snmp_info_t * mesg, int (**write_method) ())
{
	//static _igmpTbl_t T[MAXTBLNUM];
	static _igmpTbl_snoop_t T[MAXTBLNUM];
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int ii = newoid->namelen++;
	int idx;
	static int count = 0;

	if (count == 0)
		count = igmp_snoop_table_info(&T);

	idx = 0;
	while (idx < count) {
		newoid->name[ii] = idx;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		idx++;
	}
	if (idx >= count) {
		return (unsigned char *)NO_MIBINSTANCE;
	}
	*write_method = 0;

// TODO....
	//dump_igmpTbl(0, idx, count, column, &T);
	switch (column) {
	case I_IgmpJoinIndex:
		public_mib_buffer.gb_long = idx+1;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_IgmpJoinIpAddress:
		public_mib_buffer.gb_long = get_igmpJoinIpAddress(&T[idx]);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_IgmpJoinMemberNumber:
		public_mib_buffer.gb_long = T[idx].join_mbn;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_IgmpJoinPort:
		public_mib_buffer.gb_long = T[idx].join_port;
		*var_len = sizeof(long);
		if (idx == count-1)
			count = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}


unsigned char *var_multicastListView(int *var_len, Oid * newoid,
					Oid * reqoid, int searchType,
					snmp_info_t * mesg, int (**write_method) ())
{
	static _igmpTbl_t T[MAXTBLNUM];
	static int count, flag = 0x7f;
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int ii = newoid->namelen++;
	int idx = 0;
	int phy_port;

	//add by kkm
	if (flag == 0x7f ){
		count = get_igmpJoinTable(1, &T);
		get_multicastTable();
		flag = 0;
	}

	while (idx < count) {
		newoid->name[ii] = idx;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		idx++;
	}

	if (idx >= count) {
		flag = 0x7f;
		return (unsigned char *)NO_MIBINSTANCE;
	}
	*write_method = 0;

	switch (column) {
	case I_multicastIndex:
		public_mib_buffer.gb_long = idx+1;
		*var_len = sizeof(long);
		if (idx == (count - 1))
			flag |= 0x1;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_multicastJoinIpAddress:
		public_mib_buffer.gb_long = get_multicastJoinIpAddress(&T[idx]);
		*var_len = sizeof(long);
		if (idx == (count - 1))
			flag |= 0x2;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_multicastPortNumber:
		public_mib_buffer.gb_long = get_multicastPortNumber(&T[idx]) + 1;
		*var_len = sizeof(long);
		if (idx == (count - 1))
			flag |= 0x4;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_multicastPortName:
		ii = get_multicastPortName(&T[idx]);
		strcpy(public_mib_buffer.gb_string, DevPortName[ii]);
		*var_len = strlen(public_mib_buffer.gb_string);
		if (idx == (count - 1))
			flag |= 0x8;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_multicastOperation:
		phy_port = get_multicastPortNumber(&T[idx]);
		//public_mib_buffer.gb_long = get_multicastOperation(phy_port);
		public_mib_buffer.gb_long = 1; //run
		*var_len = sizeof(long);
		if (idx == (count - 1))
			flag |= 0x10;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_multicastInPackets:
		phy_port = get_multicastPortNumber(&T[idx]);
		public_mib_buffer.gb_long = get_multicastInPackets(phy_port);
		*var_len = sizeof(long);
		if (idx == (count - 1))
			flag |= 0x20;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_multicastOutPackets:
		phy_port = get_multicastPortNumber(&T[idx]);
		public_mib_buffer.gb_long = get_multicastOutPackets(phy_port);
		*var_len = sizeof(long);
		if (idx == (count - 1))
			flag |= 0x40;
		return (unsigned char *)&public_mib_buffer.gb_long;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}


//sysLogStatus
#define MAX_SYSLOG_MSG      20
char sysLog[MAX_SYSLOG_MSG][256];
unsigned char *var_sysLog(int *var_len, Oid * newoid,
				Oid * reqoid, int searchType,
				snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int ii = newoid->namelen++;
	int idx = 0;
	FILE *fp;
	static int maxCount;
	static int LogCount = 0;
	int i;
	char buf[256];

	if (LogCount == 0) {
		fp = fopen("/var/tmp/messages", "r");
		if (!fp)
			return (unsigned char *)NO_MIBINSTANCE;

		while (fgets(buf, sizeof(buf), fp)) {
			if (i <= MAX_SYSLOG_MSG) {
				strcpy(sysLog[i], buf);
				i++;
				LogCount++;
			}
		}
		fclose(fp);
	}
	maxCount = LogCount < MAX_SYSLOG_MSG ? LogCount : MAX_SYSLOG_MSG;
	while (idx < maxCount) {
		newoid->name[ii] = idx;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		idx++;
	}
	if (idx >= MAX_SYSLOG_MSG) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	*write_method = 0;

	switch (column) {
	case I_SysLogIndex:
		public_mib_buffer.gb_long = idx + 1;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_SysLogString:
		strcpy(public_mib_buffer.gb_string, sysLog[idx]);
		*var_len = strlen(sysLog[idx]);
		if (idx == MAX_SYSLOG_MSG - 1) {
			memset(sysLog, 0, sizeof(sysLog));
			LogCount = 0;
		}
		if (idx == (LogCount - 1))
			LogCount = 0;
		return (unsigned char*)public_mib_buffer.gb_string;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}

unsigned char *var_HostInfoView(int *var_len, Oid * newoid,
				Oid * reqoid, int searchType,
				snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int ii = newoid->namelen++;
	int idx = 0;
	int mode;
	static int num = -1;
	mode = atoi(getValue("OP_MODE"));

	if (mode)
		return (unsigned char *)NO_MIBINSTANCE;


	if (num == -1)
		num = initHostInfo() - 1;

	while (idx <= num) {
		newoid->name[ii] = idx;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		idx++;
	}

	if (idx > num) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	*write_method = 0;

	switch (column) {
	case I_HostInfoOnPortIndex:
		public_mib_buffer.gb_long = idx + 1;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_PortNumber:
		public_mib_buffer.gb_long = get_hostInfoPortNumber(idx);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_PortName:
		ii = get_hostInfoPortNumber(idx) - 1;
		strcpy(public_mib_buffer.gb_string, DevPortName[ii]);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_PortHostMacAddr:
		get_hostInfoMacAddr(idx, public_mib_buffer.gb_string);
		*var_len = 6;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_PortHostIpAddr:
		public_mib_buffer.gb_long = get_hostInfoIpAddr(idx);
		*var_len = sizeof(long);
		if (idx == num)
			num = -1;
		return (unsigned char *)&public_mib_buffer.gb_long;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}

unsigned char *var_PortStatusView(int *var_len, Oid * newoid,
					Oid * reqoid, int searchType,
					snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int ii = newoid->namelen++;
	int idx = 0;
	while (idx < MAX_PORT) {
		newoid->name[ii] = idx;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		idx++;
	}
	if (idx >= MAX_PORT) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	*write_method = 0;
	switch (column) {
	case I_PortStatusIndex:
		public_mib_buffer.gb_long = idx + 1;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_PortStatusNumber:
		public_mib_buffer.gb_long = idx;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_PortStatusName:
		strcpy(public_mib_buffer.gb_string, DevPortName[port_index_change(idx)]);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_PortStatusInBps:
		public_mib_buffer.gb_long = get_portStatus(idx, 1);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_PortStatusOutBps:
		public_mib_buffer.gb_long = get_portStatus(idx, 2);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_PortStatusCRC:
		public_mib_buffer.gb_long = get_portStatus(idx, 3);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;

	}
	return (unsigned char *)NO_MIBINSTANCE;
}

unsigned char *var_wlanActiveStatusView(int *var_len, Oid * newoid,
					Oid * reqoid, int searchType,
					snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int ii = newoid->namelen++;
	int idx = 1;
	int num = -1;

	if (num == -1)
		num = wirelessClientList(1);
	while (idx <= num) {
		newoid->name[ii] = idx;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		idx++;
	}
	if(num ==0)
		num= -1;

	if (idx > num) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	*write_method = 0;

	switch (column) {
	case I_wlanActiveIndex:
		public_mib_buffer.gb_long = idx;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanActiveSSID:
		get_wlanActiveSSID(1, idx - 1, public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_wlanActiveMacAddr:
		get_wlanActiveMac(1, idx - 1, public_mib_buffer.gb_string);
		*var_len = 6;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_wlanActiveMode:
		public_mib_buffer.gb_long = get_wlanActiveMode(1, idx - 1);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanActiveAuthResult:
		public_mib_buffer.gb_long = 2;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanActiveRSSI:
		get_wlanActiveRSSI(1, idx - 1, public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}


int write_wlanScanDoit(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		return set_wlanScanDoit(1, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return 0;
}

unsigned char *var_wlanScanDoit(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = get_wlanScanDoit();
	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_wlanScanDoit;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *var_wlanActiveStatusView_5g(int *var_len, Oid * newoid, Oid * reqoid,
						int searchType, snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int ii = newoid->namelen++;
	int idx = 1;
	int num = -1;

	if (num == -1)
		num = wirelessClientList(0);
	while (idx <= num) {
		newoid->name[ii] = idx;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		idx++;
	}
	if(num ==0)
		num= -1;

	if (idx > num) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	*write_method = 0;

	switch (column) {
	case I_wlanActiveIndex_5g:
		public_mib_buffer.gb_long = idx;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanActiveSSID_5g:
		get_wlanActiveSSID(0, idx - 1, public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_wlanActiveMacAddr_5g:
		get_wlanActiveMac(0, idx - 1, public_mib_buffer.gb_string);
		*var_len = 6;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_wlanActiveMode_5g:
		public_mib_buffer.gb_long = get_wlanActiveMode(0, idx - 1);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanActiveAuthResult_5g:
		public_mib_buffer.gb_long = 2;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_wlanActiveRSSI_5g:
		get_wlanActiveRSSI(0, idx - 1, public_mib_buffer.gb_string);
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char*)public_mib_buffer.gb_string;

	}
	return (unsigned char *)NO_MIBINSTANCE;
}


int write_wlanScanDoit_5g(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		return set_wlanScanDoit(0, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return 0;
}

unsigned char *var_wlanScanDoit_5g(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = get_wlanScanDoit();
	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_wlanScanDoit_5g;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

static oid Status_oid[] = { O_Status };

static Object Status_var[] = {
	{SNMP_INTEGER, (RONLY | COLUMN), var_igmpJoinStatus,
	 {4, {I_IgmpStatus, I_IgmpJoinTable, I_IgmpJoinEntry, I_IgmpJoinIndex}}},
	{SNMP_IPADDRESS, (RONLY | COLUMN), var_igmpJoinStatus,
	 {4, {I_IgmpStatus, I_IgmpJoinTable, I_IgmpJoinEntry, I_IgmpJoinIpAddress}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_igmpJoinStatus,
	 {4, {I_IgmpStatus, I_IgmpJoinTable, I_IgmpJoinEntry, I_IgmpJoinMemberNumber}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_igmpJoinStatus,
	 {4, {I_IgmpStatus, I_IgmpJoinTable, I_IgmpJoinEntry, I_IgmpJoinPort}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_multicastListView,
	 {4, {I_IgmpStatus, I_multicastTable, I_multicastEntry, I_multicastIndex}}},
	{SNMP_IPADDRESS, (RONLY | COLUMN), var_multicastListView,
	 {4, {I_IgmpStatus, I_multicastTable, I_multicastEntry, I_multicastJoinIpAddress}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_multicastListView,
	 {4, {I_IgmpStatus, I_multicastTable, I_multicastEntry, I_multicastPortNumber}}},
	{SNMP_STRING, (RONLY | COLUMN), var_multicastListView,
	 {4, {I_IgmpStatus, I_multicastTable, I_multicastEntry, I_multicastPortName}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_multicastListView,
	 {4, {I_IgmpStatus, I_multicastTable, I_multicastEntry, I_multicastOperation}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_multicastListView,
	 {4, {I_IgmpStatus, I_multicastTable, I_multicastEntry, I_multicastInPackets}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_multicastListView,
	 {4, {I_IgmpStatus, I_multicastTable, I_multicastEntry, I_multicastOutPackets}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_sysLog,
	 {4, {I_SysLogStatus, I_SysLogTable, I_SysLogEntry, I_SysLogIndex}}},
	{SNMP_STRING, (RONLY | COLUMN), var_sysLog,
	 {4, {I_SysLogStatus, I_SysLogTable, I_SysLogEntry, I_SysLogString}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_HostInfoView,
	 {4, {I_HostInfoOnPort, I_HostInfoOnPortTable, I_HostInfoOnPortEntry, I_HostInfoOnPortIndex}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_HostInfoView,
	 {4, {I_HostInfoOnPort, I_HostInfoOnPortTable, I_HostInfoOnPortEntry, I_PortNumber}}},
	{SNMP_STRING, (RONLY | COLUMN), var_HostInfoView,
	 {4, {I_HostInfoOnPort, I_HostInfoOnPortTable, I_HostInfoOnPortEntry, I_PortName}}},
	{SNMP_STRING, (RONLY | COLUMN), var_HostInfoView,
	 {4, {I_HostInfoOnPort, I_HostInfoOnPortTable, I_HostInfoOnPortEntry, I_PortHostMacAddr}}},
	{SNMP_IPADDRESS, (RONLY | COLUMN), var_HostInfoView,
	 {4, {I_HostInfoOnPort, I_HostInfoOnPortTable, I_HostInfoOnPortEntry, I_PortHostIpAddr}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_PortStatusView,
	 {4, {I_PortStatus, I_PortStatusTable, I_PortStatusEntry, I_PortStatusIndex}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_PortStatusView,
	 {4, {I_PortStatus, I_PortStatusTable, I_PortStatusEntry, I_PortStatusNumber}}},
	{SNMP_STRING, (RONLY | COLUMN), var_PortStatusView,
	 {4, {I_PortStatus, I_PortStatusTable, I_PortStatusEntry, I_PortStatusName}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_PortStatusView,
	 {4, {I_PortStatus, I_PortStatusTable, I_PortStatusEntry, I_PortStatusInBps}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_PortStatusView,
	 {4, {I_PortStatus, I_PortStatusTable, I_PortStatusEntry, I_PortStatusOutBps}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_PortStatusView,
	 {4, {I_PortStatus, I_PortStatusTable, I_PortStatusEntry, I_PortStatusCRC}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_wlanActiveStatusView,
	 {4, {I_wlanActiveStatus, I_wlanActiveStatusTable, I_wlanActiveStatusEntry, I_wlanActiveIndex}}},
	{SNMP_STRING, (RONLY | COLUMN), var_wlanActiveStatusView,
	 {4, {I_wlanActiveStatus, I_wlanActiveStatusTable, I_wlanActiveStatusEntry, I_wlanActiveSSID}}},
	{SNMP_STRING, (RONLY | COLUMN), var_wlanActiveStatusView,
	 {4, {I_wlanActiveStatus, I_wlanActiveStatusTable, I_wlanActiveStatusEntry, I_wlanActiveMacAddr}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_wlanActiveStatusView,
	 {4, {I_wlanActiveStatus, I_wlanActiveStatusTable, I_wlanActiveStatusEntry, I_wlanActiveMode}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_wlanActiveStatusView,
	 {4, {I_wlanActiveStatus, I_wlanActiveStatusTable, I_wlanActiveStatusEntry, I_wlanActiveAuthResult}}},
	{SNMP_STRING, (RONLY | COLUMN), var_wlanActiveStatusView,
	 {4, {I_wlanActiveStatus, I_wlanActiveStatusTable, I_wlanActiveStatusEntry, I_wlanActiveRSSI}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_wlanScanActiveStatusView,
	 {4, {I_wlanScanActiveStatus, I_wlanScanActiveStatusTable, I_wlanScanActiveStatusEntry, I_SHUBWLANSCANACTIVEINDEX}}},
	{SNMP_STRING, (RONLY | COLUMN), var_wlanScanActiveStatusView,
	 {4, {I_wlanScanActiveStatus, I_wlanScanActiveStatusTable, I_wlanScanActiveStatusEntry, I_SHUBWLANSCANACTIVESSID}}},
	{SNMP_STRING, (RONLY | COLUMN), var_wlanScanActiveStatusView,
	 {4, {I_wlanScanActiveStatus, I_wlanScanActiveStatusTable, I_wlanScanActiveStatusEntry, I_SHUBWLANSCANACTIVEBSSID}}},
	{SNMP_STRING, (RONLY | COLUMN), var_wlanScanActiveStatusView,
	 {4, {I_wlanScanActiveStatus, I_wlanScanActiveStatusTable, I_wlanScanActiveStatusEntry, I_SHUBWLANSCANACTIVECHANNEL}}},
	{SNMP_STRING, (RONLY | COLUMN), var_wlanScanActiveStatusView,
	 {4, {I_wlanScanActiveStatus, I_wlanScanActiveStatusTable, I_wlanScanActiveStatusEntry, I_SHUBWLANSCANACTIVEENCRYPT}}},
	{SNMP_STRING, (RONLY | COLUMN), var_wlanScanActiveStatusView,
	 {4, {I_wlanScanActiveStatus, I_wlanScanActiveStatusTable, I_wlanScanActiveStatusEntry, I_SHUBWLANSCANACTIVERSSI}}},
    {SNMP_INTEGER, (RWRITE | SCALAR), var_wlanScanDoit,
	 {3, {I_wlanScanActiveStatus, I_SHUBWLANSCAN, I_SHUBWLANSCAN_DOIT}}},
	{SNMP_INTEGER, (RONLY | SCALAR), var_cpu_utilization,
     {2, {I_Resource, I_CPU_Utilization}}},
    {SNMP_INTEGER, (RONLY | SCALAR), var_ram_utilization,
     {2, {I_Resource, I_RAM_Utilization}}},
    {SNMP_INTEGER, (RONLY | SCALAR), var_flash_utilization,
     {2, {I_Resource, I_Flash_Utilization}}},
     {SNMP_INTEGER, (RWRITE | SCALAR), var_delete_system_log,
     {2, {I_System_Log, I_Delete_System_Log}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_wlanActiveStatusView_5g,
	 {4, {I_wlanActiveStatus_5g, I_wlanActiveStatusTable_5g, I_wlanActiveStatusEntry_5g, I_wlanActiveIndex_5g}}},
	{SNMP_STRING, (RONLY | COLUMN), var_wlanActiveStatusView_5g,
	 {4, {I_wlanActiveStatus_5g, I_wlanActiveStatusTable_5g, I_wlanActiveStatusEntry_5g, I_wlanActiveSSID_5g}}},
	{SNMP_STRING, (RONLY | COLUMN), var_wlanActiveStatusView_5g,
	 {4, {I_wlanActiveStatus_5g, I_wlanActiveStatusTable_5g, I_wlanActiveStatusEntry_5g, I_wlanActiveMacAddr_5g}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_wlanActiveStatusView_5g,
	 {4, {I_wlanActiveStatus_5g, I_wlanActiveStatusTable_5g, I_wlanActiveStatusEntry_5g, I_wlanActiveMode_5g}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_wlanActiveStatusView_5g,
	 {4, {I_wlanActiveStatus_5g, I_wlanActiveStatusTable_5g, I_wlanActiveStatusEntry_5g, I_wlanActiveAuthResult_5g}}},
	{SNMP_STRING, (RONLY | COLUMN), var_wlanActiveStatusView_5g,
	 {4, {I_wlanActiveStatus_5g, I_wlanActiveStatusTable_5g, I_wlanActiveStatusEntry_5g, I_wlanActiveRSSI_5g}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_wlanScanActiveStatusView_5g,
	 {4, {I_wlanScanActiveStatus_5g, I_wlanScanActiveStatusTable, I_wlanScanActiveStatusEntry_5g, I_SHUBWLANSCANACTIVEINDEX_5g}}},
	{SNMP_STRING, (RONLY | COLUMN), var_wlanScanActiveStatusView_5g,
	 {4, {I_wlanScanActiveStatus_5g, I_wlanScanActiveStatusTable_5g, I_wlanScanActiveStatusEntry_5g, I_SHUBWLANSCANACTIVESSID_5g}}},
	{SNMP_STRING, (RONLY | COLUMN), var_wlanScanActiveStatusView_5g,
	 {4, {I_wlanScanActiveStatus_5g, I_wlanScanActiveStatusTable_5g, I_wlanScanActiveStatusEntry_5g, I_SHUBWLANSCANACTIVEBSSID_5g}}},
	{SNMP_STRING, (RONLY | COLUMN), var_wlanScanActiveStatusView_5g,
	 {4, {I_wlanScanActiveStatus_5g, I_wlanScanActiveStatusTable_5g, I_wlanScanActiveStatusEntry_5g, I_SHUBWLANSCANACTIVECHANNEL_5g}}},
	{SNMP_STRING, (RONLY | COLUMN), var_wlanScanActiveStatusView_5g,
	 {4, {I_wlanScanActiveStatus_5g, I_wlanScanActiveStatusTable_5g, I_wlanScanActiveStatusEntry_5g, I_SHUBWLANSCANACTIVEENCRYPT_5g}}},
	{SNMP_STRING, (RONLY | COLUMN), var_wlanScanActiveStatusView_5g,
	 {4, {I_wlanScanActiveStatus_5g, I_wlanScanActiveStatusTable_5g, I_wlanScanActiveStatusEntry_5g, I_SHUBWLANSCANACTIVERSSI_5g}}},
     {SNMP_INTEGER, (RWRITE | SCALAR), var_wlanScanDoit_5g,
	 {3, {I_wlanScanActiveStatus_5g, I_SHUBWLANSCAN_5g, I_SHUBWLANSCAN_DOIT_5g}}},
	 {0}
};

static SubTree Status_tree = { NULL, Status_var,
    (sizeof(Status_oid) / sizeof(oid)), Status_oid
};

/* SystemDiag */

/* reset
 */
int write_faultreset(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_faultreset((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_faultreset(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = 0;

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_faultreset;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}


int write_HardWareReset(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_HardWareReset((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_HWreset(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = 0;

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_HardWareReset;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_autoResetMode(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_autoResetMode((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_autoReset(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_autoResetMode();
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_autoResetMode;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_autoResetWanTraffic(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_autoResetWanTraffic((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_autoResetWanTraffic(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_autoResetWanTraffic();
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_autoResetWanTraffic;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_pingProtocol(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * reqOid)
{
	int ret = 0;
	int no = reqOid->name[(reqOid->namelen - 1)];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_pingProtocol(no, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? 0 : SNMP_ERROR_WRONGVALUE;
}

int write_pingAddress(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * reqOid)
{
	int ret = 0;
	int no = reqOid->name[(reqOid->namelen - 1)];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_pingAddress(no, var_val);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? 0 : SNMP_ERROR_WRONGVALUE;
}

int write_pingPktCount(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * reqOid)
{
	int ret = 0;
	int no = reqOid->name[(reqOid->namelen - 1)];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_pktCount(no, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? 0 : SNMP_ERROR_WRONGVALUE;
}

int write_pingPktSize(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * reqOid)
{
	int ret = 0;
	int no = reqOid->name[(reqOid->namelen - 1)];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_pktSize(no, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? 0 : SNMP_ERROR_WRONGVALUE;
}

int write_pingPktTimeout(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret = 0;
	int no = reqOid->name[(reqOid->namelen - 1)];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_pktTimeout(no, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? 0 : SNMP_ERROR_WRONGVALUE;
}

int write_pingDelay(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * reqOid)
{
	int ret = 0;
	int no = reqOid->name[(reqOid->namelen - 1)];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_pktDelay(no, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? 0 : SNMP_ERROR_WRONGVALUE;
}

int write_pingTrapOnCompletion(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret = 0;
	int no = reqOid->name[(reqOid->namelen - 1)];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_TrapOnCompletion(no, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? 0 : SNMP_ERROR_WRONGVALUE;
}

int write_pingEntryOwner(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret = 0;
	int no = reqOid->name[(reqOid->namelen - 1)];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_EntryOwner(no, var_val);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? 0 : SNMP_ERROR_WRONGVALUE;
}

int write_pingEntryStatus(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * reqOid)
{
	int ret = 0;
	int no = reqOid->name[(reqOid->namelen - 1)];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_pingEntryStatus(no, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? 0 : SNMP_ERROR_WRONGVALUE;
}

#define PING_RESULT_PATH "/var/tmp/snmp_ping"

unsigned char *var_pingTest(int *var_len, Oid * newoid, Oid * reqoid,
				int searchType, snmp_info_t * mesg, int (**write_method) ())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int ii = newoid->namelen++;
	int idx = 1;
	int old_idx=0;
	char tmp[80];

	while (idx <= MAX_PING_ENTRY) {
		newoid->name[ii] = idx;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		idx++;
	}
	if (idx > MAX_PING_ENTRY) {
		return (unsigned char *)NO_MIBINSTANCE;
	}
	if ( idx != old_idx) {
		sprintf(tmp, "%s%d", PING_RESULT_PATH, idx-1);
		if ( !access(tmp, F_OK))
			update_ping_result(idx-1);
		old_idx = idx;
	}

	switch (column) {

	case I_pingSerialNumber:
		public_mib_buffer.gb_long = idx;
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;

	case I_pingProtocol:
		public_mib_buffer.gb_long = 1;
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_pingProtocol;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_pingAddress:
		strcpy(public_mib_buffer.gb_string, get_pingAddress(idx));
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_pingAddress;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_pingPacketCount:
		public_mib_buffer.gb_long = get_pktCount(idx);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_pingPktCount;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_pingPacketSize:
		public_mib_buffer.gb_long = get_pktSize(idx);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_pingPktSize;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_pingPacketTimeout:
		public_mib_buffer.gb_long = get_pktTimeout(idx);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_pingPktTimeout;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_pingDelay:
		public_mib_buffer.gb_long = get_pktDelay(idx);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_pingDelay;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_pingTraponCompletion:
		public_mib_buffer.gb_long = get_TrapOnCompletion(idx);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_pingTrapOnCompletion;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_pingSentPackets:
		public_mib_buffer.gb_long = get_sentPktCount(idx);
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_pingReceivePackets:
		public_mib_buffer.gb_long = get_recvPktCount(idx);
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_pingMinRtt:
		public_mib_buffer.gb_long = get_minPingTime(idx);
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_pingAvgRtt:
		public_mib_buffer.gb_long = get_avgPingTime(idx);
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_pingMaxRtt:
		public_mib_buffer.gb_long = get_maxPingTime(idx);
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_pingCompleted:
		public_mib_buffer.gb_long = get_pingCompleted(idx);
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_pingEntryOwner:
		strcpy(public_mib_buffer.gb_string, get_EntryOwner(idx));
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_pingEntryOwner;
		return (unsigned char*)public_mib_buffer.gb_string;
	case I_pingEntryStatus:
		public_mib_buffer.gb_long = get_pingEntryStatus(idx);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_pingEntryStatus;
		return (unsigned char *)&public_mib_buffer.gb_long;
	}
	return (unsigned char *)NO_MIBINSTANCE;
}

int write_cpepingtrap_enable(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_cpepingtrap_enable((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_cpePingTrapSet(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_cpepingtrap_enable();
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_cpepingtrap_enable;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_cpepingEntryStatus(int action,
						  unsigned char *var_val, unsigned char varval_type, int var_val_len,
						  unsigned char *statP, Oid * reqOid)
{
	int ret = 0;
	int no = reqOid->name[(reqOid->namelen - 1)];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_cpepingEntryStatus(no, (int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? 0 : SNMP_ERROR_WRONGVALUE;
}

unsigned char *var_cpepingTest(int *var_len, Oid * newoid, Oid * reqoid, int searchType, snmp_info_t * mesg, int (**write_method) ())
{
    int column = newoid->name[(newoid->namelen - 1)];
    int result;
    int ii = newoid->namelen++;
    int idx = 1;
    int old_idx=0;
    int mode = atoi(getValue("OP_MODE"));
    static int num = -1;
    static int count = 0;
	char tmp[80];

    if (mode)
	return (unsigned char *)NO_MIBINSTANCE;


	if (num == -1)
		num = initHostInfo();

    while (idx <= num) {
        newoid->name[ii] = idx;
	 result = compare(reqoid, newoid);
	 if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
	 	break;
	 }
	 idx++;
    }

	if (idx > num) {
		if(count >= num){
			count = 0;
			num =-1;
		}
		return (unsigned char *)NO_MIBINSTANCE;
	}

	if ( idx != old_idx) {
		sprintf(tmp, "%s%d", CPEPING_RESULT_PATH, idx-1);
		if (!access(tmp, F_OK))
			update_cpeping_result(idx-1);
		old_idx = idx;
	}

	switch (column) {
	case I_cpePingTablePortIndex:
		public_mib_buffer.gb_long = get_hostInfoPortNumber(idx-1);
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cpePingTableAction:
		public_mib_buffer.gb_long = get_cpepingEntryStatus(idx);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_cpepingEntryStatus;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cpePingTableCpeMac:
		get_hostInfoMacAddr(idx-1, public_mib_buffer.gb_string);
		*var_len = 6;
		return public_mib_buffer.gb_string;
	case I_cpePingTableAddress:
		public_mib_buffer.gb_long = get_hostInfoIpAddr(idx-1);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cpePingTableRttMin:
		public_mib_buffer.gb_long = get_mincpePingTime(idx);
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cpePingTableRttAvg:
		public_mib_buffer.gb_long = get_avgcpePingTime(idx);
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cpePingTableRttMax:
		public_mib_buffer.gb_long = get_maxcpePingTime(idx);
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cpePingTableTimeout:
		public_mib_buffer.gb_long = get_timeoutcpePingTime(idx);
		*var_len = sizeof(long);
		*write_method = 0;
		count++;
		if(count > num)
			count = num;
		return (unsigned char *)&public_mib_buffer.gb_long;

	}

	return (unsigned char *)NO_MIBINSTANCE;
}

int write_FactoryReset(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_FactoryReset((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_FatctoryReset(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = 0;
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_FactoryReset;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_AdminReset(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_AdminReset((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_AdminUserReset(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = 0;
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_AdminReset;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_IgmpJoinTestGroupAddr(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_IgmpJoinTestGroupAddr((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_IgmpJoinTestGroupAddr(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_IgmpJoinTestGroupAddr();
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_IgmpJoinTestGroupAddr;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_IgmpJoinTestGroupPort(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_IgmpJoinTestGroupPort((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_IgmpJoinTestGroupPort(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_IgmpJoinTestGroupPort();
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_IgmpJoinTestGroupPort;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_IgmpJoinTestVersion(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_IgmpJoinTestVersion((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_IgmpJoinTestVersion(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_IgmpJoinTestVersion();
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_IgmpJoinTestVersion;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_IgmpJoinTest(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_IgmpJoinTest((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_IgmpJoinTest(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = 0;
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_IgmpJoinTest;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

static oid SystemDiag_oid[] = { O_SystemDiag };

static Object systemDiag_var[] = {
	{SNMP_INTEGER, (RWRITE | SCALAR), var_faultreset,
	 {3, {I_SystemRemoteResetConfig, I_SystemRemoteReset, 0}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_autoReset,
	 {2, {I_SystemRemoteResetConfig, I_AutoResetMode}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_autoResetWanTraffic,
	 {2, {I_SystemRemoteResetConfig, I_AutoResetWanTraffic}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_pingTest,
	 {4, {I_pingTest, I_pingTable, I_pingEntry, I_pingSerialNumber}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_pingTest,
	 {4, {I_pingTest, I_pingTable, I_pingEntry, I_pingProtocol}}},
	{SNMP_STRING, (RWRITE | COLUMN), var_pingTest,
	 {4, {I_pingTest, I_pingTable, I_pingEntry, I_pingAddress}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_pingTest,
	 {4, {I_pingTest, I_pingTable, I_pingEntry, I_pingPacketCount}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_pingTest,
	 {4, {I_pingTest, I_pingTable, I_pingEntry, I_pingPacketSize}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_pingTest,
	 {4, {I_pingTest, I_pingTable, I_pingEntry, I_pingPacketTimeout}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_pingTest,
	 {4, {I_pingTest, I_pingTable, I_pingEntry, I_pingDelay}}},
#if 0	/* Unuse oid delete */
	{SNMP_INTEGER, (RWRITE | COLUMN), var_pingTest,
	 {4, {I_pingTest, I_pingTable, I_pingEntry, I_pingTraponCompletion}}},
#endif
	{SNMP_INTEGER, (RONLY | COLUMN), var_pingTest,
	 {4, {I_pingTest, I_pingTable, I_pingEntry, I_pingSentPackets}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_pingTest,
	 {4, {I_pingTest, I_pingTable, I_pingEntry, I_pingReceivePackets}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_pingTest,
	 {4, {I_pingTest, I_pingTable, I_pingEntry, I_pingMinRtt}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_pingTest,
	 {4, {I_pingTest, I_pingTable, I_pingEntry, I_pingAvgRtt}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_pingTest,
	 {4, {I_pingTest, I_pingTable, I_pingEntry, I_pingMaxRtt}}},
#if 0	/* Unuse oid delete */
	{SNMP_INTEGER, (RONLY | COLUMN), var_pingTest,
	 {4, {I_pingTest, I_pingTable, I_pingEntry, I_pingCompleted}}},
	{SNMP_STRING, (RWRITE | COLUMN), var_pingTest,
	 {4, {I_pingTest, I_pingTable, I_pingEntry, I_pingEntryOwner}}},
#endif
	{SNMP_INTEGER, (RWRITE | COLUMN), var_pingTest,
  	 {4, {I_pingTest, I_pingTable, I_pingEntry, I_pingEntryStatus}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_cpepingTest,
 	 {4, {I_cpePing, I_cpePingTable, I_cpePingEntry, I_cpePingTablePortIndex}}},
	{SNMP_INTEGER, (RWRITE | COLUMN), var_cpepingTest,
	 {4, {I_cpePing, I_cpePingTable, I_cpePingEntry, I_cpePingTableAction}}},
	{SNMP_STRING, (RONLY | COLUMN), var_cpepingTest,
	 {4, {I_cpePing, I_cpePingTable, I_cpePingEntry, I_cpePingTableCpeMac}}},
	{SNMP_IPADDRESS, (RONLY | COLUMN), var_cpepingTest,
	 {4, {I_cpePing, I_cpePingTable, I_cpePingEntry, I_cpePingTableAddress}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_cpepingTest,
	 {4, {I_cpePing, I_cpePingTable, I_cpePingEntry, I_cpePingTableRttMin}}},
 	{SNMP_INTEGER, (RONLY | COLUMN), var_cpepingTest,
	 {4, {I_cpePing, I_cpePingTable, I_cpePingEntry, I_cpePingTableRttAvg}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_cpepingTest,
	 {4, {I_cpePing, I_cpePingTable, I_cpePingEntry, I_cpePingTableRttMax}}},
	{SNMP_INTEGER, (RONLY | COLUMN), var_cpepingTest,
	 {4, {I_cpePing, I_cpePingTable, I_cpePingEntry, I_cpePingTableTimeout}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_cpePingTrapSet,
	 {3, {I_cpePing, I_cpePingTrap, I_cpePingTrapSet}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_FatctoryReset,
	 {2, {I_FactoryReset, I_FactoryResetSet}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_AdminUserReset,
	 {4, {I_FactoryReset, I_AdminAccountReset, I_AdminAccountResetSet, 0}}},
	{SNMP_IPADDRESS, (RWRITE | SCALAR), var_IgmpJoinTestGroupAddr,
	 {2, {I_IgmpJoinTest, I_IgmpJoinGroupAddr}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_IgmpJoinTestGroupPort,
	 {2, {I_IgmpJoinTest, I_IgmpJoinGroupPort}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_IgmpJoinTestVersion,
	 {2, {I_IgmpJoinTest, I_IgmpJoinVersion}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_IgmpJoinTest,
	 {2, {I_IgmpJoinTest, I_IgmpJoinMessage}}},
	{0}
};

static SubTree systemDiag_tree = { NULL, systemDiag_var,
	(sizeof(SystemDiag_oid) / sizeof(oid)), SystemDiag_oid
};

int write_SaveApply(int action, unsigned char *var_val,
			unsigned char varval_type, int var_val_len,
			unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = SaveAndApply((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_saveAndApply(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = 0;

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_SaveApply;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_systemInitMode(int action, unsigned char *var_val,
				unsigned char varval_type, int var_val_len,
				unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_systemInitMode((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_systemInitMode(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = get_systemInitMode();

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_systemInitMode;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_systemConfigRootAccount(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_systemConfigRootAccount(var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_systemConfigRootAccount(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	get_systemConfigRootAccount(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_systemConfigRootAccount;
	/* Set size (in bytes) and return address of the variable */
	*var_len = strlen(public_mib_buffer.gb_string);

	return (unsigned char *)public_mib_buffer.gb_string;
}

unsigned char *var_systemConfigAdminAccount(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	/* Set write-function (uncomment if you want to implement it)  */
	/* Set size (in bytes) and return address of the variable */

	return (unsigned char *)public_mib_buffer.gb_string;
}

int write_RootAccountMode(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_RootAccountMode((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}
unsigned char *var_RootAccountMode(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_RootAccountMode();
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_RootAccountMode;
	return (unsigned char *)&public_mib_buffer.gb_long;
}
int write_Ipv6PassThruMode(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_Ipv6PassThruMode((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}
unsigned char *var_I_Ipv6PassThru(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_Ipv6PassThruMode();
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_Ipv6PassThruMode;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_AutoResetActive(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_autoResetMode((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_AutoResetActive(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_autoResetMode();
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_AutoResetActive;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_AutoResetWanCRC(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_autoResetWanCrc((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *var_AutoResetWanCRC(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	public_mib_buffer.gb_long = get_autoResetWanCrc();
	*var_len = sizeof(long);
	*write_method = (int (*)())&write_AutoResetWanCRC;
	return (unsigned char *)&public_mib_buffer.gb_long;
}

static oid ConfigSave_oid[] = { O_Extra };

static Object configSave_var[] = {
	{SNMP_INTEGER, (RWRITE | SCALAR), var_saveAndApply,
	 {3, {I_ConfigSave, I_ConfigSaveAndApply, 0}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_systemInitMode,
	 {2, {I_ConfigMode, I_SystemInitConfMode}}},
#if 0	/* Unuse oid delete */
	{SNMP_STRING, (RWRITE | SCALAR), var_systemConfigRootAccount,
	 {2, {I_ConfigRootAccount, I_SystemConfigRootAccount}}},
#endif
	{SNMP_STRING, (RWRITE | SCALAR), var_systemConfigAdminAccount,
	 {2, {I_ConfigRootAccount, I_SystemConfigAdminAccount}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_RootAccountMode,
	 {2, {I_ConfigRootAccount, I_RootAccountMode}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_I_Ipv6PassThru,
	 {2, {I_ConfigIpv6PassThru, I_Ipv6PassThru}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_AutoResetActive,
	 {2, {I_AutoReset, I_AutoResetActive}}},
	{SNMP_INTEGER, (RWRITE | SCALAR), var_AutoResetWanCRC,
	 {2, {I_AutoReset, I_AutoResetWanCRC}}},
	{0}
};

static SubTree configSave_tree = { NULL, configSave_var,
	(sizeof(ConfigSave_oid) / sizeof(oid)), ConfigSave_oid
};

/* Auto transmission
 */
int write_autoTransmission(int action,
						   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		set_autoTransmission(var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (0);
}

unsigned char *var_autoTransmission(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = 0;

	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_autoTransmission;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

static oid autoTrap_oid[] = { O_Trap };

static Object autoTrap_var[] = {
	{SNMP_IPADDRESS, (RWRITE | SCALAR), var_autoTransmission,
	 {1, {I_newIpAllocation}}},
	{0}
};

static SubTree autoTrap_tree = { NULL, autoTrap_var,
	(sizeof(autoTrap_oid) / sizeof(oid)), autoTrap_oid
};

int write_wirelessHandover(int action, unsigned char *var_val,
					unsigned char varval_type, int var_val_len,
					unsigned char *statP, Oid * name)
{
	int ret=1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wirelessHandover((int)mhtol(var_val, var_val_len));
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}
unsigned char *var_wirelessHandover(int *var_len, snmp_info_t * mesg, int (**write_method) ())
{
	/* Add value computations */
	public_mib_buffer.gb_long = get_wirelessHandover();
	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_wirelessHandover;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

static oid wirelessHandover_oid[] = { O_advancedWirelessConfig };

static Object wirelessHandover_var[] = {
	{SNMP_INTEGER, (RWRITE | SCALAR), var_wirelessHandover,
	 {1, {I_advancedWirelessHandover}}},
	{0}
};
static SubTree wirelessHandover_tree = { NULL, wirelessHandover_var,
	(sizeof(wirelessHandover_oid) / sizeof(oid)), wirelessHandover_oid
};
/* This is the MIB registration function. This should be called */
/* within the init_DAVOLINK_MIB-function */
void register_subtrees_of_SKBB_MIB()
{
	insert_group_in_mib(&system_tree);
	insert_group_in_mib(&portTable_tree);
	insert_group_in_mib(&systemInfo_tree);
	insert_group_in_mib(&wanConfig_tree);
	insert_group_in_mib(&lanConfig_tree);
	insert_group_in_mib(&wlanConfig_tree);
	insert_group_in_mib(&secConfig_tree);
	insert_group_in_mib(&devicePortConfig_tree);
	insert_group_in_mib(&IgmpConfig_tree);
	insert_group_in_mib(&fwUpgradeConfig_tree);
	insert_group_in_mib(&snmpConfig_tree);
	insert_group_in_mib(&sysLogConfig_tree);
	insert_group_in_mib(&ntpConfig_tree);
	insert_group_in_mib(&QosConfig_tree);
	insert_group_in_mib(&LanAccessControlConfig_tree);
	insert_group_in_mib(&WLanAccessControlConfig_tree);
	insert_group_in_mib(&WLanAccessControlConfig_5g_tree);
	insert_group_in_mib(&vlanConfig_tree);
	insert_group_in_mib(&PortfwConfig_tree);
	insert_group_in_mib(&Status_tree);
	insert_group_in_mib(&systemDiag_tree);
	insert_group_in_mib(&configSave_tree);
	insert_group_in_mib(&autoTrap_tree);
	insert_group_in_mib(&wirelessHandover_tree);
}
//END
