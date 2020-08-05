#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <ctype.h>
#include <regex.h>
#include <syslog.h>
#include <sys/wait.h>
#define noPARSE_TXT_FILE

#define WLAN_FAST_INIT
#define BR_SHORTCUT

#include <linux_list.h>
/* Local include files */
#include "apmib.h"
#include "mibtbl.h"

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_pppox.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>

#ifdef WLAN_FAST_INIT
# include <sys/socket.h>
# include <linux/wireless.h>
# include <ieee802_mib.h>
#endif

#include <bcmnvram.h>
#include <libytool.h>
#include <shutils.h>
#include "nvram_mib/nvram_mib.h"

#define SDEBUG(fmt, args...) do {} while (0)
#define P2P_DEBUG(fmt, args...) do {} while (0)
#if 1//!defined(CONFIG_RTL_8198C)
#define RTL_L2TP_POWEROFF_PATCH 1
#endif

typedef enum {
	eWLIF_NONE = 0,
	eWLIF_ROOT = 1,
	eWLIF_VIRTUAL = 2,
	eWLIF_BAD = 3
} eWLIF_CODE_T;

struct cbuffer {
	char *buf;
	size_t size, count;
};

static int generateWpaConf(char *outputFile, int isWds, char *wlanif_name);
static int setmib(int argc, char **argv);
static int test_and_import(const char *filename, int overwrite);
static int diff_version(void);

static int sethw_mac(u_char mac[6], BOOL from_base);
static int generatePPPConf(int is_pppoe, char *option_file, char *pap_file, char *chap_file
# ifdef MULTI_WAN_SUPPORT
			   , char *order_file
# endif
	);
static int send_ppp_msg(int sessid, unsigned char *peerMacStr);
static int set_default_ssid(void);
static int set_http_passwd(void);

static void *Malloc(size_t size)
{
	void *ptr;
	if ((ptr = malloc(size)) == NULL) {
		perror("malloc error");
		exit(EXIT_FAILURE);
	}
	return (ptr);
}

static int vcbprintf(struct cbuffer *m, const char *f, va_list args)
{
	size_t len;

	while (m->count < m->size) {
		len = (size_t)vsnprintf(m->buf + m->count, m->size - m->count, f, args);
		if (len < (m->size - m->count)) {
			m->count += len;
			return 0;
		} else {
			char *p = realloc(m->buf, len + m->count + 1);
			if (!p)
				break;
			m->buf = p;
			m->size = len + m->count + 1;
		}
	}

	m->count = m->size;
	return -1;
}

int cbprintf(struct cbuffer *m, const char *f, ...)
{
	int status;
	va_list args;

	va_start(args, f);
	status = vcbprintf(m, f, args);
	va_end(args);
	return status;
}

static int validate_wlindex(int wlroot, int wlvap)
{
	if ((unsigned)wlan_idx >= NUM_WLAN_INTERFACE ||
	    (unsigned)vwlan_idx > NUM_VWLAN_INTERFACE)
		return -1;
	return 0;
}

static eWLIF_CODE_T if_nametowlindex(const char *name, int *wlroot, int *wlvap)
{
	const char *p;
	char *q;

	if (name && !strncmp(name, "wlan", sizeof("wlan") - 1)) {
		p = &name[sizeof("wlan") - 1];
		*wlroot = strtol(p, &q, 10);
		if (*wlroot >= 0 && p != q) {
			if (!*q)
				return eWLIF_ROOT;
			else if (*q++ == '-') {
#ifdef MBSSID
				if (!strncmp(q, "va", sizeof("va") - 1)) {
					p = &q[sizeof("va") - 1];
					*wlvap = strtol(p, &q, 10) + 1;
					if (*wlvap >= 1 && p != q && !*q)
						return eWLIF_VIRTUAL;
					else
						return eWLIF_BAD;
				}
# ifdef UNIVERSAL_REPEATER
				else if (!strcmp(q, "vxd")) {
					*wlvap = NUM_VWLAN_INTERFACE;
					return eWLIF_VIRTUAL;
				}
# endif
			}
#endif
		}
		return eWLIF_BAD;
	}
	return eWLIF_NONE;
}

static int getWLAN_ChipVersion(void)
{
	char buf[128];
	FILE *f;
	int chipVersion = CHIP_UNKNOWN;

	snprintf(buf, sizeof(buf), "/proc/wlan%d/mib_rf", wlan_idx);
	f = fopen(buf, "r");
	if (f == NULL)
		return -1;
	while (fscanf(f, "%127s", buf) != EOF) {
		if (strncasecmp(buf, "chipVersion", sizeof("chipVersion") - 1))
			fscanf(f, "%*[^\n]\n");
		else if (fgets(buf, sizeof(buf), f)) {
			ystrtrim(buf, " \f\n\r\t\v:");
			if (strstr(buf, "RTL8188C") ||
			    strstr(buf, "RTL8188R") ||
			    strstr(buf, "RTL6195B"))
				chipVersion = CHIP_RTL8188C;
			else if (strstr(buf, "RTL8188E"))
				chipVersion = CHIP_RTL8188E;
			else if (strstr(buf, "RTL8192C"))
				chipVersion = CHIP_RTL8192C;
			else if (strstr(buf, "RTL8192D"))
				chipVersion = CHIP_RTL8192D;
			else if (strstr(buf, "RTL8812F"))
				chipVersion = CHIP_RTL8812F;
			else if (strstr(buf, "RTL8812"))
				chipVersion = CHIP_RTL8812A;
			else if (strstr(buf, "RTL8192E"))
				chipVersion = CHIP_RTL8192E;
			else if (strstr(buf, "RTL8197G"))
				chipVersion = CHIP_RTL8197G;
			else if (strstr(buf, "RTL8814B"))
				chipVersion = CHIP_RTL8814B;
			else if (strstr(buf, "RTL8822B"))
				chipVersion = CHIP_RTL8822B;
		} else
			break;
	}
	fclose(f);
	return chipVersion;
}

static int SetWlan_idx(char *wlan_iface_name)
{
	int old = wlan_idx;

	switch (if_nametowlindex(wlan_iface_name, &wlan_idx, &vwlan_idx)) {
	case eWLIF_ROOT:
	case eWLIF_VIRTUAL:
		if (!validate_wlindex(wlan_idx, vwlan_idx))
			return 1;
	default:
		wlan_idx = old;
		vwlan_idx = 0;
		break;
	}
	return 0;
}

static int set_mac_address(const char *interface, unsigned char *mac_address)
{
	int s, i;
	struct ifreq ifr;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;
	ystrncpy(ifr.ifr_name, interface, IFNAMSIZ);
	for (i = 0; i < 6; i++)
		ifr.ifr_hwaddr.sa_data[i] = mac_address[i];
	i = ioctl(s, SIOCSIFHWADDR, &ifr);
	close(s);
	return i;
}

#if defined(CONFIG_RTL_8812_SUPPORT)
#define B1_G1	40
#define B1_G2	48

#define B2_G1	56
#define B2_G2	64

#define B3_G1	104
#define B3_G2	112
#define B3_G3	120
#define B3_G4	128
#define B3_G5	136
#define B3_G6	144

#define B4_G1	153
#define B4_G2	161
#define B4_G3	169
#define B4_G4	177

void assign_diff_AC(unsigned char *pMib, unsigned char *pVal)
{
	memset((pMib + 35), pVal[0], (B1_G1 - 35));
	memset((pMib + B1_G1), pVal[1], (B1_G2 - B1_G1));
	memset((pMib + B1_G2), pVal[2], (B2_G1 - B1_G2));
	memset((pMib + B2_G1), pVal[3], (B2_G2 - B2_G1));
	memset((pMib + B2_G2), pVal[4], (B3_G1 - B2_G2));
	memset((pMib + B3_G1), pVal[5], (B3_G2 - B3_G1));
	memset((pMib + B3_G2), pVal[6], (B3_G3 - B3_G2));
	memset((pMib + B3_G3), pVal[7], (B3_G4 - B3_G3));
	memset((pMib + B3_G4), pVal[8], (B3_G5 - B3_G4));
	memset((pMib + B3_G5), pVal[9], (B3_G6 - B3_G5));
	memset((pMib + B3_G6), pVal[10], (B4_G1 - B3_G6));
	memset((pMib + B4_G1), pVal[11], (B4_G2 - B4_G1));
	memset((pMib + B4_G2), pVal[12], (B4_G3 - B4_G2));
	memset((pMib + B4_G3), pVal[13], (B4_G4 - B4_G3));
}
#endif	// CONFIG_RTL_8812_SUPPORT

#ifdef WLAN_PROFILE
void set_profile(int id, struct wifi_mib *pmib)
{
	int i, i1, i2;
	WLAN_PROFILE_T profile;

	if (id == 0) {
		apmib_get(MIB_PROFILE_ENABLED1, (void *)&i1);
		apmib_get(MIB_PROFILE_NUM1, (void *)&i2);
	} else {
		apmib_get(MIB_PROFILE_ENABLED2, (void *)&i1);
		apmib_get(MIB_PROFILE_NUM2, (void *)&i2);
	}

	pmib->ap_profile.enable_profile = ((i1 && i2) ? 1 : 0);
	if (i1 && i2) {
		_DEBUG(L_DBG, "Init wireless[%d] profile...", id);
		for (i = 0; i < i2; i++) {
			*((char *)&profile) = (char)(i + 1);
			if (id == 0)
				apmib_get(MIB_PROFILE_TBL1, (void *)&profile);
			else
				apmib_get(MIB_PROFILE_TBL2, (void *)&profile);

			ystrncpy(pmib->ap_profile.profile[i].ssid,
				 (char *)profile.ssid, sizeof(pmib->ap_profile.profile[0].ssid));
			pmib->ap_profile.profile[i].encryption		= profile.encryption;
			pmib->ap_profile.profile[i].auth_type		= profile.auth;
			pmib->ap_profile.profile[i].wep_default_key	= profile.wep_default_key;
			memcpy(pmib->ap_profile.profile[i].wep_key1, profile.wepKey1, 13);
			memcpy(pmib->ap_profile.profile[i].wep_key2, profile.wepKey2, 13);
			memcpy(pmib->ap_profile.profile[i].wep_key3, profile.wepKey3, 13);
			memcpy(pmib->ap_profile.profile[i].wep_key4, profile.wepKey4, 13);
			pmib->ap_profile.profile[i].wpa_cipher		= profile.wpa_cipher;
			ystrncpy((char *)pmib->ap_profile.profile[i].wpa_psk,
				 (char *)profile.wpaPSK, sizeof(pmib->ap_profile.profile[0].wpa_psk));
		}
	}
	pmib->ap_profile.profile_num = i2;
}
#endif

#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
static char wlan_1x_ifname[16];
#endif
#ifdef DOT11K
#define NEIGHBOR_REPORT_FILE	"/proc/%s/rm_neighbor_report"
#endif

#ifdef CONFIG_RTL_AIRTIME
# include <errno.h>

# define SIOCMIBSYNC_ATM 0x8B50	/* Sorry! we don't have a header to include this!!
				   copy from drivers/net/wireless/rtl8192cd/8192cd_ioctl.c */

//#define DUMP_ATM_STATION_TABLE

# ifdef DUMP_ATM_STATION_TABLE
static void dumpAirtime(struct ATMConfigEntry *pEntry, int num_id)
{
	int i, val;
	apmib_get(num_id, (void *)&val);

	printf("=== %s =============================================\n", __FILE__);
	printf("enable: %d\n", pEntry->atm_en);
	printf("mode:   %d\n", pEntry->atm_mode);
	printf("num:    %d\n", val);

	printf("\nInterface:\n", pEntry->atm_mode);
	for (i = 0; i < 6; i++) {
		printf("  intf[%d]:%d\n", i, pEntry->atm_iftime[i]);
	}

	printf("\nStation:\n", pEntry->atm_mode);
	for (i = 0; i < val; i++) {
		printf("atm_sta[%d]:\n", i);
		printf("  ipAddr:%d.%d.%d.%d\n",
		       pEntry->atm_sta[i].ipaddr[0],
		       pEntry->atm_sta[i].ipaddr[1],
		       pEntry->atm_sta[i].ipaddr[2],
		       pEntry->atm_sta[i].ipaddr[3]);
		printf("  macAddr:%02X%02X%02X%02X%02X%02X\n",
		       pEntry->atm_sta[i].hwaddr[0],
		       pEntry->atm_sta[i].hwaddr[1],
		       pEntry->atm_sta[i].hwaddr[2],
		       pEntry->atm_sta[i].hwaddr[3],
		       pEntry->atm_sta[i].hwaddr[4],
		       pEntry->atm_sta[i].hwaddr[5]);
		printf("  atm_time:%d\n\n", pEntry->atm_sta[i].atm_time);
	}
	printf("=== %s =============================================\n", __FILE__);
}
# endif				/* DUMP_ATM_STATION_TABLE */

static int initAirtime(char *ifname)
{
	struct ATMConfigEntry *pEntry;
	AIRTIME_T atmEntry;
	struct iwreq wrq;
	unsigned char atime[6];
	unsigned int val;
	int i;
	int skfd;
	int enable_id, mode_id, iftime_id, num_id, tbl_id;

	if (wlan_idx == 0) {
		enable_id = MIB_AIRTIME_ENABLED;
		mode_id = MIB_AIRTIME_MODE;
		iftime_id = MIB_AIRTIME_IFTIME;
		num_id = MIB_AIRTIME_TBL_NUM;
		tbl_id = MIB_AIRTIME_TBL;
	} else {
		enable_id = MIB_AIRTIME2_ENABLED;
		mode_id = MIB_AIRTIME2_MODE;
		iftime_id = MIB_AIRTIME2_IFTIME;
		num_id = MIB_AIRTIME2_TBL_NUM;
		tbl_id = MIB_AIRTIME2_TBL;
	}

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd < 0) {
		fprintf(stderr, "socket() fail\n");
		return -1;
	}

	strncpy(wrq.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(skfd, SIOCGIWNAME, &wrq) < 0) {
		fprintf(stderr, "Interface %s open failed!\n", ifname);
		close(skfd);
		return -1;
	}

	if ((pEntry = (struct ATMConfigEntry *)malloc(sizeof(struct ATMConfigEntry))) == NULL) {
		fprintf(stderr, "MIB buffer allocation failed!\n");
		close(skfd);
		return -1;
	}

	memset(pEntry, 0, sizeof(struct ATMConfigEntry));
	wrq.u.data.pointer = (caddr_t)pEntry;
	wrq.u.data.length = sizeof(struct ATMConfigEntry);

	apmib_get(enable_id, (void *)&val);
	pEntry->atm_en = (unsigned char)val;

	apmib_get(mode_id, (void *)&val);
	pEntry->atm_mode = (unsigned char)val;

	apmib_get(iftime_id, (void *)atime);
	for (i = 0; i <= NUM_VWLAN_INTERFACE; i++) {
		pEntry->atm_iftime[i] = (unsigned char)atime[i];
	}

	apmib_get(num_id, (void *)&val);
	for (i = 1; i <= val; i++) {
		memset(&atmEntry, 0x00, sizeof(atmEntry));
		*((char *)&atmEntry) = (char)i;
		if (apmib_get(tbl_id, (void *)&atmEntry)) {
			memcpy(pEntry->atm_sta[i - 1].hwaddr, atmEntry.macAddr, 6);
			memcpy(pEntry->atm_sta[i - 1].ipaddr, atmEntry.ipAddr, 4);
			pEntry->atm_sta[i - 1].atm_time = atmEntry.atm_time;
		}
	}

# ifdef DUMP_ATM_STATION_TABLE
	dumpAirtime(pEntry, num_id);
# endif

	if (ioctl(skfd, SIOCMIBSYNC_ATM, &wrq) < 0) {
		fprintf(stderr, "set airtime failed!: %m\n");
		free(pEntry);
		close(skfd);
		return -1;
	}
	close(skfd);
	return 0;
}
#endif				/* CONFIG_RTL_AIRTIME */

static int _initWlan(const char *ifname, int skfd, struct wifi_mib *pmib, struct iwreq *pwrq)
{
	int intVal3;
	int tx_bandwidth, rx_bandwidth, qbwc_mode;
	int i, intVal, intVal2, encrypt, enable1x, wep, mode /*, enable1xVxd */ ;
	char buf1[1024];
#ifdef CONFIG_RTL_WAPI_SUPPORT
	char buf2[1024];
#endif
	u_char mac[6];
	struct iwreq wrq_root, *proot;
	int wlan_band = 0, channel_bound = 0, aggregation = 0;
	MACFILTER_T *pAcl = NULL;
	struct wdsEntry *wds_Entry = NULL;
	WDS_Tp pwds_EntryUI;
#ifdef MBSSID
	int v_previous = 0;
# ifdef CONFIG_RTL_819X
	int vap_enable = 0, intVal4 = 0;
# endif
#endif
	int opmode;
	char *pstr = NULL;

	ifconfig(ifname, 0, NULL, NULL);

	if (vwlan_idx == 0) {
		// shutdown all WDS interface
		for (i = 0; i < 8; i++) {
			sprintf(buf1, "%s-wds%d", ifname, i);
			ifconfig(buf1, 0, NULL, NULL);
		}
#ifndef RTK_REINIT_SUPPORT
		// kill wlan application daemon
		yexecl(NULL, "wlanapp.sh kill %s", ifname);
#endif
	} else {	// virtual interface
		snprintf(wrq_root.ifr_name, IFNAMSIZ, "wlan%d", wlan_idx);
		if (ioctl(skfd, SIOCGIWNAME, &wrq_root) < 0)
			return -1;
	}

	proot = (vwlan_idx == 0) ? pwrq : &wrq_root;

	if (vwlan_idx == 0) {
		apmib_get(MIB_HW_RF_TYPE, (void *)&intVal);
		if (intVal == 0) {
			_DEBUG(L_CRIT, "RF type is NULL");
			return 0;
		}
	}

	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
	if (intVal == 1)
		return 0;

#ifdef CONFIG_RTL_AIRTIME
	if (vwlan_idx == 0 && initAirtime(ifname) != 0)
		return -1;
#endif /* CONFIG_RTL_AIRTIME */

	// get mib from driver
	proot->u.data.pointer = (caddr_t)pmib;
	proot->u.data.length = sizeof(struct wifi_mib);
#ifdef CONFIG_RTL_COMAPI_CFGFILE
	if (vwlan_idx != 0)
		yexecl(NULL, "iwpriv wlan0 cfgfile");	// is it right to be here ?
#endif
	if (ioctl(skfd, 0x8B42, proot) < 0) {
		_DEBUG(L_ERR, "failed to get WLAN MIB");
		return -1;
	}

	// check mib version
	if (pmib->mib_version != MIB_VERSION) {
		_DEBUG(L_CRIT, "WLAN MIB version mismatch!");
		return -1;
	}

	if (vwlan_idx > 0) {	// Unless root interface, clone root mib to virtual interface
		pwrq->u.data.pointer = (caddr_t)pmib;
		pwrq->u.data.length = sizeof(struct wifi_mib);
		if (ioctl(skfd, 0x8B43, pwrq) < 0) {
			_DEBUG(L_ERR, "failed to set WLAN MIB");
			return -1;
		}
		pmib->miscEntry.func_off = 0;
	}
	// Set parameters to driver

	if (vwlan_idx == 0) {
		apmib_get(MIB_HW_REG_DOMAIN, (void *)&intVal);
		pmib->dot11StationConfigEntry.dot11RegDomain = intVal;
	}

	apmib_get(MIB_WLAN_WLAN_MAC_ADDR, (void *)mac);
	if (!memcmp(mac, "\x00\x00\x00\x00\x00\x00", 6)) {
#ifdef WLAN_MAC_FROM_EFUSE
		if (!get_root_mac(ifname, mac)) {
# ifdef MBSSID
			if (vwlan_idx > 0) {
				if (*(char *)(ifname + 4) == '0')	//wlan0
					*(char *)mac |= LOCAL_ADMIN_BIT;
				else {
					(*(char *)mac) += 4;
					(*(char *)mac) |= LOCAL_ADMIN_BIT;
				}
			}
			calc_incr((char *)mac + MACADDRLEN - 1, vwlan_idx);
# endif
		} else
#endif
		{
			apmib_get(MIB_HW_WLAN_ADDR, (void *)mac);
#ifdef MBSSID
			/* Utilize Local-bit - young@davolink.co.kr */
			if (vwlan_idx > 0) {
				if (vwlan_idx < NUM_VWLAN_INTERFACE) {
					mac[0] = (mac[0] + (vwlan_idx << 4)) | 2;
				} else if (vwlan_idx != NUM_VWLAN_INTERFACE) { /* not vxd (Repeater) */
					_DEBUG(L_WARN, "Fail to get MAC address of VAP%d!", vwlan_idx - 1);
					return 0;
				}
			}
#endif
		}
	}

	// ifconfig all wlan interface when not in WISP
	// ifconfig wlan1 later interface when in WISP mode, the wlan0  will be setup in WAN interface
	apmib_get(MIB_OP_MODE, (void *)&intVal);
	apmib_get(MIB_WISP_WAN_ID, (void *)&intVal2);
	sprintf(buf1, "wlan%d", intVal2);

	/* NOTICE: configure repeater interface's mac address will overwrite root interface's mac */
	if (
#ifdef MBSSID
	    (vwlan_idx != NUM_VWLAN_INTERFACE) &&
#endif
	    ((intVal != 2) || strcmp(buf1, ifname) ||
#ifdef MBSSID
	    vwlan_idx > 0
#endif
	    )) {
		set_mac_address(ifname, mac);
		memcpy(&(pmib->dot11OperationEntry.hwaddr[0]), mac, 6);
	}
#ifdef BR_SHORTCUT
	if (intVal == 2
# ifdef MBSSID
	    && vwlan_idx == 0
# endif
	    )
		pmib->dot11OperationEntry.disable_brsc = 1;
	else
		pmib->dot11OperationEntry.disable_brsc = 0;
#endif

	apmib_get(MIB_HW_LED_TYPE, (void *)&intVal);
	pmib->dot11OperationEntry.ledtype = intVal;

	// set AP/client/WDS mode
	apmib_get(MIB_WLAN_SSID, (void *)buf1);
	intVal2 = strlen(buf1);
	if (intVal2 > sizeof(pmib->dot11StationConfigEntry.dot11DesiredSSID))
		intVal2 = sizeof(pmib->dot11StationConfigEntry.dot11DesiredSSID);
	pmib->dot11StationConfigEntry.dot11DesiredSSIDLen = intVal2;
	strncpy((char *)pmib->dot11StationConfigEntry.dot11DesiredSSID, buf1, intVal2);

	if (!strcasecmp(buf1, "any")) {
		pmib->dot11StationConfigEntry.dot11SSIDtoScanLen = 0;
		memset(pmib->dot11StationConfigEntry.dot11SSIDtoScan, 0, 32);
	} else {
		pmib->dot11StationConfigEntry.dot11SSIDtoScanLen = intVal2;
		strncpy((char *)pmib->dot11StationConfigEntry.dot11SSIDtoScan, buf1, intVal2);
	}

	apmib_get(MIB_WLAN_MODE, (void *)&mode);

#ifdef RTL_MULTI_CLONE_SUPPORT
	// when RTL_MULTI_CLONE_SUPPORT enabled let wlan0-va1,wlan0-va2 can setting macclone
	apmib_get(MIB_WLAN_MACCLONE_ENABLED, (void *)&intVal);
	if ((intVal == 1) && (mode == 1))
		pmib->ethBrExtInfo.macclone_enable = 1;
	else if ((intVal == 2) && (mode == 1))
		pmib->ethBrExtInfo.macclone_enable = 2;
	else
		pmib->ethBrExtInfo.macclone_enable = 0;
#endif

	if (mode == 1) {
		// client mode
		apmib_get(MIB_WLAN_NETWORK_TYPE, (void *)&intVal2);
		if (intVal2 == 0) {
			pmib->dot11OperationEntry.opmode = 8;
#ifdef WLAN_PROFILE
			set_profile(*((char *)(ifname + 4)) - '0', pmib);
#endif
		} else {
			pmib->dot11OperationEntry.opmode = 32;
			apmib_get(MIB_WLAN_DEFAULT_SSID, (void *)buf1);
			intVal2 = strlen(buf1);
			if (intVal2 > sizeof(pmib->dot11StationConfigEntry.dot11DefaultSSID))
				intVal2 = sizeof(pmib->dot11StationConfigEntry.dot11DefaultSSID);
			pmib->dot11StationConfigEntry.dot11DefaultSSIDLen = intVal2;
			strncpy((char *)pmib->dot11StationConfigEntry.dot11DefaultSSID, buf1, intVal2);
#ifdef WLAN_PROFILE
			set_profile(*((char *)(ifname + 4)) - '0', pmib);
#endif
		}

#ifdef CONFIG_IEEE80211W
		apmib_get(MIB_WLAN_IEEE80211W, (void *)&intVal);
		pmib->dot1180211AuthEntry.dot11IEEE80211W = intVal;
		apmib_get(MIB_WLAN_SHA256_ENABLE, (void *)&intVal);
		pmib->dot1180211AuthEntry.dot11EnableSHA256 = intVal;
#endif
		pmib->dot11hTPCEntry.tpc_enable = 0;	/*disable TPC in client mode */
	} else
		pmib->dot11OperationEntry.opmode = 16;

	if (mode == 2)		// WDS only
		pmib->dot11WdsInfo.wdsPure = 1;
	else
		pmib->dot11WdsInfo.wdsPure = 0;
#ifdef CONFIG_RTL_P2P_SUPPORT
# define WIFI_AP_STATE	 0x00000010
# define WIFI_STATION_STATE 0x08
	apmib_get(MIB_WLAN_P2P_TYPE, (void *)&intVal);
	pmib->p2p_mib.p2p_enabled = 0;
	if (mode == P2P_SUPPORT_MODE) {
		switch (intVal) {
			P2P_DEBUG("initWlan:");
		case P2P_DEVICE:
			P2P_DEBUG("P2P_DEVICE mode \n");
			break;
		case P2P_PRE_CLIENT:
			P2P_DEBUG("P2P_PRE_CLIENT mode \n");
			break;
		case P2P_CLIENT:
			P2P_DEBUG("P2P_CLIENT mode \n");
			break;
		case P2P_PRE_GO:
			P2P_DEBUG("P2P_PRE_GO mode \n");
			break;
		case P2P_TMP_GO:
			P2P_DEBUG("P2P_TMP_GO mode \n");
			break;
		default:
			P2P_DEBUG("Unknow P2P type;use dev as default!\n");
			intVal = P2P_DEVICE;
			apmib_set(MIB_WLAN_P2P_TYPE, (void *)&intVal);	// save to flash mib
			SDEBUG("\n");

		}

		if (intVal >= P2P_DEVICE && intVal <= P2P_CLIENT) {
			/*use STA mode as base */
			if (intVal == P2P_DEVICE) {
				/*if is P2P device mode then clear dot11DesiredSSIDLen and dot11DesiredSSID */
				pmib->dot11StationConfigEntry.dot11DesiredSSIDLen = 0;
				memset(pmib->dot11StationConfigEntry.dot11DesiredSSID, 0, 32);
			}
			pmib->dot11OperationEntry.opmode = WIFI_STATION_STATE;
		} else if (intVal >= P2P_PRE_GO && intVal <= P2P_TMP_GO) {
			/*use AP as base */
			pmib->dot11OperationEntry.opmode = WIFI_AP_STATE;

		} else {
			SDEBUG("unknow P2P type chk!\n");
		}

		/* fill p2p type */
		pmib->p2p_mib.p2p_type = intVal;
		pmib->p2p_mib.p2p_enabled = 2;

		// wlan driver will know it will start under p2p client mode, but flash reset to P2P_device mode
		/*if (intVal == P2P_CLIENT) {
			intVal = P2P_DEVICE;
			apmib_set(MIB_WLAN_P2P_TYPE, (void *)&intVal);
		}*/

		// set DHCP=0 ; will dymanic deter start dhcp server or dhcp client
		//P2P_DEBUG("under P2P mode disable DHCP\n\n");
		//intVal = DHCP_DISABLED;
		//apmib_set(MIB_DHCP, (void *)&intVal);

		/* fill intent value */
		apmib_get(MIB_WLAN_P2P_INTENT, (void *)&intVal2);
		pmib->p2p_mib.p2p_intent = (unsigned char)intVal2;

		/* fill listen channel value */
		apmib_get(MIB_WLAN_P2P_LISTEN_CHANNEL, (void *)&intVal2);
		pmib->p2p_mib.p2p_listen_channel = (unsigned char)intVal2;

		/* fill op_channel value */
		apmib_get(MIB_WLAN_P2P_OPERATION_CHANNEL, (void *)&intVal2);
		pmib->p2p_mib.p2p_op_channel = (unsigned char)intVal2;

		/* get device  name */
		apmib_get(MIB_DEVICE_NAME, (void *)buf1);
		memcpy(pmib->p2p_mib.p2p_device_name, buf1, MAX_SSID_LEN);

		/* get pin code */
		apmib_get(MIB_HW_WSC_PIN, (void *)buf1);
		memcpy(pmib->p2p_mib.p2p_wsc_pin_code, buf1, 9);

		/* get wsc method */
		apmib_get(MIB_WLAN_WSC_METHOD, (void *)&intVal);

		// 2011/ 03 / 07
		if (mode == P2P_SUPPORT_MODE)
			intVal = (CONFIG_METHOD_PBC | CONFIG_METHOD_DISPLAY | CONFIG_METHOD_KEYPAD);
		else {
			//Ethernet(0x2)+Label(0x4)+PushButton(0x80) Bitwise OR
			if (intVal == 1)	//Pin+Ethernet
				intVal = (CONFIG_METHOD_ETH | CONFIG_METHOD_PIN);
			else if (intVal == 2)	//PBC+Ethernet
				intVal = (CONFIG_METHOD_ETH | CONFIG_METHOD_PBC);
			if (intVal == 3)	//Pin+PBC+Ethernet
				intVal = (CONFIG_METHOD_ETH | CONFIG_METHOD_PIN | CONFIG_METHOD_PBC);
		}
		pmib->p2p_mib.p2p_wsc_config_method = (unsigned short)intVal;
	}
#endif	// CONFIG_RTL_P2P_SUPPORT

	pmib->dot11StationConfigEntry.dot11AclNum = 0;
	apmib_get(MIB_WLAN_MACAC_ENABLED, (void *)&intVal);
	pmib->dot11StationConfigEntry.dot11AclMode = intVal;
	/* APACRTL-524 */
	if (intVal == 0) {
		if ((pstr = nvram_get("sta_protection_num"))) {
			intVal = atoi(pstr);
			pmib->dot11StationConfigEntry.dot11AclMode = 2;
		}
	} else if (intVal != 0) {
		apmib_get(MIB_WLAN_MACAC_NUM, (void *)&intVal);
		for (i = 0; i < intVal; i++) {
			buf1[0] = i + 1;
			apmib_get(MIB_WLAN_MACAC_ADDR, (void *)buf1);
			pAcl = (MACFILTER_T *)buf1;
			memcpy(&(pmib->dot11StationConfigEntry.dot11AclAddr[i][0]), &(pAcl->macAddr[0]), 6);
			pmib->dot11StationConfigEntry.dot11AclNum++;
		}
	}

	if (vwlan_idx == 0) {	// root interface
#ifdef RF_DPK_SETTING_SUPPORT
		/* Set DPK parameters */
		{
#define COPY_LUT_VAL(_MIB_NAME_, _SRC_, _DST_, _LEN_) \
	do { \
		apmib_get(_MIB_NAME_, (void *)_SRC_); \
		memcpy((void*)(pmib->dot11RFDPKEntry._DST_), (void*)(_SRC_), _LEN_ * 4); \
		{ \
			int k; \
			for (k = 0; k < _LEN_; k++) \
				pmib->dot11RFDPKEntry._DST_[k] = DWORD_SWAP(pmib->dot11RFDPKEntry._DST_[k]); \
		} \
	} while (0)

			unsigned char lut_val[LUT_2G_LEN * 4 + 1];
			int wlan_2g;
			int len, offset;
			int i;

#ifdef CONFIG_BAND_2G_ON_WLAN0
			wlan_2g = 0;
#else
			wlan_2g = 1;
#endif

			/* load 2G parameters */
			len = LUT_2G_LEN;
			offset = MIB_RF_DPK_LUT_2G_EVEN_A1 - MIB_RF_DPK_LUT_2G_EVEN_A0;

			apmib_get(MIB_RF_DPK_DP_PATH_A_OK, (void *)&intVal);
			pmib->dot11RFDPKEntry.bDPPathAOK = intVal;
			apmib_get(MIB_RF_DPK_DP_PATH_B_OK, (void *)&intVal);
			pmib->dot11RFDPKEntry.bDPPathBOK = intVal;

			apmib_get(MIB_RF_DPK_PWSF_2G_A, (void *)lut_val);
			memcpy((void *)(pmib->dot11RFDPKEntry.pwsf_2g_a), (void *)(lut_val), PWSF_2G_LEN);
			apmib_get(MIB_RF_DPK_PWSF_2G_B, (void *)lut_val);
			memcpy((void *)(pmib->dot11RFDPKEntry.pwsf_2g_b), (void *)(lut_val), PWSF_2G_LEN);

			for (i = 0; i < PWSF_2G_LEN; i++) {	//0~2
				COPY_LUT_VAL(MIB_RF_DPK_LUT_2G_EVEN_A0 + i * offset, lut_val, lut_2g_even_a[i], len);
				COPY_LUT_VAL(MIB_RF_DPK_LUT_2G_ODD_A0 + i * offset, lut_val, lut_2g_odd_a[i], len);
				COPY_LUT_VAL(MIB_RF_DPK_LUT_2G_EVEN_B0 + i * offset, lut_val, lut_2g_even_b[i], len);
				COPY_LUT_VAL(MIB_RF_DPK_LUT_2G_ODD_B0 + i * offset, lut_val, lut_2g_odd_b[i], len);
			}
#if defined(CONFIG_RTL_11AC_SUPPORT)
			/* load 5G parameters */
			len = LUT_5G_LEN;
			offset = MIB_RF_DPK_LUT_5G_EVEN_A1 - MIB_RF_DPK_LUT_5G_EVEN_A0;

			apmib_get(MIB_RF_DPK_DP_5G_PATH_A_OK, (void *)&intVal);
			pmib->dot11RFDPKEntry.is_5g_pdk_patha_ok = intVal;
			apmib_get(MIB_RF_DPK_DP_5G_PATH_B_OK, (void *)&intVal);
			pmib->dot11RFDPKEntry.is_5g_pdk_pathb_ok = intVal;

			COPY_LUT_VAL(MIB_RF_DPK_PWSF_5G_A, lut_val, pwsf_5g_a, PWSF_5G_LEN);
			COPY_LUT_VAL(MIB_RF_DPK_PWSF_5G_B, lut_val, pwsf_5g_b, PWSF_5G_LEN);

			for (i = 0; i < PWSF_5G_LEN; i++) {	//0~8
				COPY_LUT_VAL(MIB_RF_DPK_LUT_5G_EVEN_A0 + i * offset, lut_val, lut_5g_even_a[i], len);
				COPY_LUT_VAL(MIB_RF_DPK_LUT_5G_ODD_A0 + i * offset, lut_val, lut_5g_odd_a[i], len);
				COPY_LUT_VAL(MIB_RF_DPK_LUT_5G_EVEN_B0 + i * offset, lut_val, lut_5g_even_b[i], len);
				COPY_LUT_VAL(MIB_RF_DPK_LUT_5G_ODD_B0 + i * offset, lut_val, lut_5g_odd_b[i], len);
			}
#endif

			//test_dpk2(pmib, wlan_2g);

#undef COPY_LUT_VAL
		}
#endif	/* RF_DPK_SETTING_SUPPORT */

		// set RF parameters
		apmib_get(MIB_HW_RF_TYPE, (void *)&intVal);
		pmib->dot11RFEntry.dot11RFType = intVal;
#if defined(CONFIG_RTL_8196B)
		apmib_get(MIB_HW_BOARD_VER, (void *)&intVal);
		if (intVal == 1)
			pmib->dot11RFEntry.MIMO_TR_mode = 3;	// 2T2R
		else if (intVal == 2)
			pmib->dot11RFEntry.MIMO_TR_mode = 4;	// 1T1R
		else
			pmib->dot11RFEntry.MIMO_TR_mode = 1;	// 1T2R

		apmib_get(MIB_HW_TX_POWER_CCK, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevelCCK, buf1, 14);

		apmib_get(MIB_HW_TX_POWER_OFDM_1S, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevelOFDM_1SS, buf1, 162);

		apmib_get(MIB_HW_TX_POWER_OFDM_2S, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevelOFDM_2SS, buf1, 162);

		// Not used for RTL8192SE
		//apmib_get(MIB_HW_11N_XCAP, (void *)&intVal);
		//pmib->dot11RFEntry.crystalCap = intVal;

		apmib_get(MIB_HW_11N_LOFDMPWDA, (void *)&intVal);
		pmib->dot11RFEntry.LOFDM_pwd_A = intVal;

		apmib_get(MIB_HW_11N_LOFDMPWDB, (void *)&intVal);
		pmib->dot11RFEntry.LOFDM_pwd_B = intVal;

		apmib_get(MIB_HW_11N_TSSI1, (void *)&intVal);
		pmib->dot11RFEntry.tssi1 = intVal;

		apmib_get(MIB_HW_11N_TSSI2, (void *)&intVal);
		pmib->dot11RFEntry.tssi2 = intVal;

		apmib_get(MIB_HW_11N_THER, (void *)&intVal);
		pmib->dot11RFEntry.ther = intVal;

		if (pmib->dot11RFEntry.dot11RFType == 10) {	// Zebra
			apmib_get(MIB_WLAN_RFPOWER_SCALE, (void *)&intVal);
			if (intVal == 1)
				intVal = 3;
			else if (intVal == 2)
				intVal = 6;
			else if (intVal == 3)
				intVal = 9;
			else if (intVal == 4)
				intVal = 17;
			if (intVal) {
				for (i = 0; i < 14; i++) {
					if (pmib->dot11RFEntry.pwrlevelCCK[i] != 0) {
						if ((pmib->dot11RFEntry.pwrlevelCCK[i] - intVal) >= 1)
							pmib->dot11RFEntry.pwrlevelCCK[i] -= intVal;
						else
							pmib->dot11RFEntry.pwrlevelCCK[i] = 1;
					}
				}
				for (i = 0; i < 162; i++) {
					if (pmib->dot11RFEntry.pwrlevelOFDM_1SS[i] != 0) {
						if ((pmib->dot11RFEntry.pwrlevelOFDM_1SS[i] - intVal) >= 1)
							pmib->dot11RFEntry.pwrlevelOFDM_1SS[i] -= intVal;
						else
							pmib->dot11RFEntry.pwrlevelOFDM_1SS[i] = 1;
					}
					if (pmib->dot11RFEntry.pwrlevelOFDM_2SS[i] != 0) {
						if ((pmib->dot11RFEntry.pwrlevelOFDM_2SS[i] - intVal) >= 1)
							pmib->dot11RFEntry.pwrlevelOFDM_2SS[i] -= intVal;
						else
							pmib->dot11RFEntry.pwrlevelOFDM_2SS[i] = 1;
					}
				}
			}
		}
#elif defined(CONFIG_RTL_8198C) || \
      defined(CONFIG_RTL_8196C) || \
      defined(CONFIG_RTL_8198) || \
      defined(CONFIG_RTL_819XD) || \
      defined(CONFIG_RTL_8196E) || \
      defined(CONFIG_RTL_8198B) || \
      defined(CONFIG_RTL_8197F) || \
      defined(CONFIG_RTL_8197G)
# ifdef CONFIG_WLAN_HAL_8814AE
		apmib_get(MIB_HW_BOARD_VER, (void *)&intVal);
		if (intVal == 1)
			pmib->dot11RFEntry.MIMO_TR_mode = 5;	// 3T3R
		else if (intVal == 2)
			pmib->dot11RFEntry.MIMO_TR_mode = 2;	// 2T2R
		else if (intVal == 3)
			pmib->dot11RFEntry.MIMO_TR_mode = 4;	// 2T4R
		else
			pmib->dot11RFEntry.MIMO_TR_mode = 5;	// 3T3R

#  ifdef CONFIG_RTL_8814_8194_2T2R_SUPPORT
		_DEBUG(L_INFO, "Force 2T2R for 8814/8194");
		pmib->dot11RFEntry.MIMO_TR_mode = 2;	// 2T2R
#  endif
# elif defined(CONFIG_WLAN_HAL_8814BE)
#  if defined(CONFIG_RTL_8197F) || defined(CONFIG_RTL_8197G)
#   if defined(CONFIG_BAND_2G_ON_WLAN0)
		if (wlan_idx == 0)
			pmib->dot11RFEntry.MIMO_TR_mode = 2; // 2T2R
		else
			pmib->dot11RFEntry.MIMO_TR_mode = 7; // 4T4R
#   endif
#   if defined(CONFIG_BAND_5G_ON_WLAN0)
		if (wlan_idx == 0)
			pmib->dot11RFEntry.MIMO_TR_mode = 7; // 4T4R
		else
			pmib->dot11RFEntry.MIMO_TR_mode = 2; // 2T2R
#   endif
#  endif
# else	// CONFIG_WLAN_HAL_8814AE
		apmib_get(MIB_HW_BOARD_VER, (void *)&intVal);
		if (intVal == 1)
			pmib->dot11RFEntry.MIMO_TR_mode = 2;	// 2T2R
		else if (intVal == 2)
			pmib->dot11RFEntry.MIMO_TR_mode = 0;	// 1T1R
		else
			pmib->dot11RFEntry.MIMO_TR_mode = 1;	// 1T2R

#  ifdef CONFIG_RTL_8812_1T1R_SUPPORT
		if (wlan_idx == 0) {
			_DEBUG(L_INFO, "Force 1T1R for WLAN0");
			pmib->dot11RFEntry.MIMO_TR_mode = 0;	// 1T1R
		}
#  endif
# endif	// !CONFIG_WLAN_HAL_8814AE

		apmib_get(MIB_HW_TX_POWER_CCK_A, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevelCCK_A, buf1, MAX_2G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_CCK_B, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevelCCK_B, buf1, MAX_2G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_HT40_1S_A, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevelHT40_1S_A, buf1, MAX_2G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_HT40_1S_B, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevelHT40_1S_B, buf1, MAX_2G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_DIFF_HT40_2S, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiffHT40_2S, buf1, MAX_2G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_DIFF_HT20, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiffHT20, buf1, MAX_2G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_DIFF_OFDM, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiffOFDM, buf1, MAX_2G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_TSSI_CCK_A, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevel_TSSICCK_A, buf1, MAX_2G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_TSSI_CCK_B, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevel_TSSICCK_B, buf1, MAX_2G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_TSSI_CCK_C, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevel_TSSICCK_C, buf1, MAX_2G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_TSSI_CCK_D, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevel_TSSICCK_D, buf1, MAX_2G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_TSSI_HT40_1S_A, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_A, buf1, MAX_2G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_TSSI_HT40_1S_B, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_B, buf1, MAX_2G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_TSSI_HT40_1S_C, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_C, buf1, MAX_2G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_TSSI_HT40_1S_D, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_D, buf1, MAX_2G_CHANNEL_NUM_MIB);

# if defined(CONFIG_RTL_92D_SUPPORT) || defined(CONFIG_RTL_8812_SUPPORT) || defined(CONFIG_WLAN_HAL_8814BE)
		apmib_get(MIB_HW_TX_POWER_5G_HT40_1S_A, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevel5GHT40_1S_A, buf1, MAX_5G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_5G_HT40_1S_B, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevel5GHT40_1S_B, buf1, MAX_5G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_TSSI_5G_HT40_1S_A, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_A, buf1, MAX_5G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_TSSI_5G_HT40_1S_B, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_B, buf1, MAX_5G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_TSSI_5G_HT40_1S_C, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_C, buf1, MAX_5G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_TSSI_5G_HT40_1S_D, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_D, buf1, MAX_5G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_DIFF_5G_HT40_2S, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiff5GHT40_2S, buf1, MAX_5G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_DIFF_5G_HT20, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiff5GHT20, buf1, MAX_5G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_DIFF_5G_OFDM, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiff5GOFDM, buf1, MAX_5G_CHANNEL_NUM_MIB);
# endif

# if defined(CONFIG_RTL_8812_SUPPORT) || defined(CONFIG_WLAN_HAL_8814BE)
		// 5G
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_A, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_20BW1S_OFDM1T_A, (unsigned char *)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_40BW2S_20BW2S_A, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_40BW2S_20BW2S_A, (unsigned char *)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_80BW1S_160BW1S_A, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_80BW1S_160BW1S_A, (unsigned char *)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_80BW2S_160BW2S_A, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_80BW2S_160BW2S_A, (unsigned char *)buf1);

		apmib_get(MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_B, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_20BW1S_OFDM1T_B, (unsigned char *)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_40BW2S_20BW2S_B, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_40BW2S_20BW2S_B, (unsigned char *)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_80BW1S_160BW1S_B, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_80BW1S_160BW1S_B, (unsigned char *)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_80BW2S_160BW2S_B, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_80BW2S_160BW2S_B, (unsigned char *)buf1);

		// 2G
		apmib_get(MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_A, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiff_20BW1S_OFDM1T_A, buf1, MAX_2G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_DIFF_40BW2S_20BW2S_A, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiff_40BW2S_20BW2S_A, buf1, MAX_2G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_B, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiff_20BW1S_OFDM1T_B, buf1, MAX_2G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_DIFF_40BW2S_20BW2S_B, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiff_40BW2S_20BW2S_B, buf1, MAX_2G_CHANNEL_NUM_MIB);
# endif

# if defined(CONFIG_WLAN_HAL_8814AE) || defined(CONFIG_WLAN_HAL_8814BE)
		//3 5G
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_40BW3S_20BW3S_A, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_40BW3S_20BW3S_A, (unsigned char *)buf1);

		apmib_get(MIB_HW_TX_POWER_DIFF_5G_80BW3S_160BW3S_A, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_80BW3S_160BW3S_A, (unsigned char *)buf1);

		apmib_get(MIB_HW_TX_POWER_DIFF_5G_40BW3S_20BW3S_B, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_40BW3S_20BW3S_B, (unsigned char *)buf1);

		apmib_get(MIB_HW_TX_POWER_DIFF_5G_80BW3S_160BW3S_B, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_80BW3S_160BW3S_B, (unsigned char *)buf1);

		apmib_get(MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_C, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_20BW1S_OFDM1T_C, (unsigned char *)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_40BW2S_20BW2S_C, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_40BW2S_20BW2S_C, (unsigned char *)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_80BW1S_160BW1S_C, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_80BW1S_160BW1S_C, (unsigned char *)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_80BW2S_160BW2S_C, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_80BW2S_160BW2S_C, (unsigned char *)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_40BW3S_20BW3S_C, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_40BW3S_20BW3S_C, (unsigned char *)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_80BW3S_160BW3S_C, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_80BW3S_160BW3S_C, (unsigned char *)buf1);

		apmib_get(MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_D, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_20BW1S_OFDM1T_D, (unsigned char *)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_40BW2S_20BW2S_D, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_40BW2S_20BW2S_D, (unsigned char *)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_40BW3S_20BW3S_D, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_40BW3S_20BW3S_D, (unsigned char *)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_80BW1S_160BW1S_D, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_80BW1S_160BW1S_D, (unsigned char *)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_80BW2S_160BW2S_D, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_80BW2S_160BW2S_D, (unsigned char *)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_80BW3S_160BW3S_D, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_80BW3S_160BW3S_D, (unsigned char *)buf1);
#  if defined(CONFIG_WLAN_HAL_8814BE)
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_40BW4S_20BW4S_A, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_40BW4S_20BW4S_A, (unsigned char*)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_A, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_80BW4S_160BW4S_A, (unsigned char*)buf1);

		apmib_get(MIB_HW_TX_POWER_DIFF_5G_40BW4S_20BW4S_B, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_40BW4S_20BW4S_B, (unsigned char*)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_B, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_80BW4S_160BW4S_B, (unsigned char*)buf1);

		apmib_get(MIB_HW_TX_POWER_DIFF_5G_40BW4S_20BW4S_C, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_40BW4S_20BW4S_C, (unsigned char*)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_C, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_80BW4S_160BW4S_C, (unsigned char*)buf1);

		apmib_get(MIB_HW_TX_POWER_DIFF_5G_40BW4S_20BW4S_D, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_40BW4S_20BW4S_D, (unsigned char*)buf1);
		apmib_get(MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_D, (void *)buf1);
		assign_diff_AC(pmib->dot11RFEntry.pwrdiff_5G_80BW4S_160BW4S_D, (unsigned char*)buf1);
#  endif
		//3 2G
		apmib_get(MIB_HW_TX_POWER_HT40_1S_C, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevelHT40_1S_C, buf1, MAX_2G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_HT40_1S_D, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevelHT40_1S_D, buf1, MAX_2G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_CCK_C, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevelCCK_C, buf1, MAX_2G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_CCK_D, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevelCCK_D, buf1, MAX_2G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_DIFF_40BW3S_20BW3S_A, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiff_40BW3S_20BW3S_A, buf1, MAX_2G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_DIFF_40BW3S_20BW3S_B, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiff_40BW3S_20BW3S_B, buf1, MAX_2G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_C, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiff_20BW1S_OFDM1T_C, buf1, MAX_2G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_DIFF_40BW2S_20BW2S_C, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiff_40BW2S_20BW2S_C, buf1, MAX_2G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_DIFF_40BW3S_20BW3S_C, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiff_40BW3S_20BW3S_C, buf1, MAX_2G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_D, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiff_20BW1S_OFDM1T_D, buf1, MAX_2G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_DIFF_40BW2S_20BW2S_D, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiff_40BW2S_20BW2S_D, buf1, MAX_2G_CHANNEL_NUM_MIB);
		apmib_get(MIB_HW_TX_POWER_DIFF_40BW3S_20BW3S_D, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrdiff_40BW3S_20BW3S_D, buf1, MAX_2G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_5G_HT40_1S_C, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevel5GHT40_1S_C, buf1, MAX_5G_CHANNEL_NUM_MIB);

		apmib_get(MIB_HW_TX_POWER_5G_HT40_1S_D, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevel5GHT40_1S_D, buf1, MAX_5G_CHANNEL_NUM_MIB);
# endif

		apmib_get(MIB_HW_11N_TSSI1, (void *)&intVal);
		pmib->dot11RFEntry.tssi1 = intVal;

		apmib_get(MIB_HW_11N_TSSI2, (void *)&intVal);
		pmib->dot11RFEntry.tssi2 = intVal;

# if defined(CONFIG_RTL_8881A_SELECTIVE) && !defined(CONFIG_WLAN_HAL_8814AE)
		apmib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&intVal);

		apmib_get(MIB_HW_11N_THER, (void *)&intVal);
		pmib->dot11RFEntry.ther = intVal;

		apmib_get(MIB_HW_11N_XCAP, (void *)&intVal);
		pmib->dot11RFEntry.xcap = intVal;

		apmib_get(MIB_HW_11N_THER_2, (void *)&intVal);
		pmib->dot11RFEntry.ther2 = intVal;

		apmib_get(MIB_HW_11N_XCAP_2, (void *)&intVal);
		pmib->dot11RFEntry.xcap2 = intVal;
# else
		apmib_get(MIB_HW_11N_THER, (void *)&intVal);
		pmib->dot11RFEntry.ther = intVal;
		pmib->dot11RFEntry.thermal[0] = intVal;

		apmib_get(MIB_HW_11N_THER_2, (void *)&intVal);
		pmib->dot11RFEntry.thermal[1] = intVal;

		apmib_get(MIB_HW_11N_THER_3, (void *)&intVal);
		pmib->dot11RFEntry.thermal[2] = intVal;

		apmib_get(MIB_HW_11N_THER_4, (void *)&intVal);
		pmib->dot11RFEntry.thermal[3] = intVal;

		apmib_get(MIB_HW_11N_XCAP, (void *)&intVal);
		pmib->dot11RFEntry.xcap = intVal;
# endif
# ifdef CONFIG_RF_KFREE_SUPPORT
		apmib_get(MIB_HW_11N_KFREE_ENABLE, (void *)&intVal);
		pmib->dot11RFEntry.kfree_enable = intVal;
# endif
		apmib_get(MIB_HW_11N_TSSI_ENABLE, (void *)&intVal);
		pmib->dot11RFEntry.tssi_enable = intVal;

		apmib_get(MIB_HW_11N_TRSWITCH, (void *)&intVal);
		pmib->dot11RFEntry.trswitch = intVal;

		apmib_get(MIB_HW_11N_TRSWPAPE_C9, (void *)&intVal);
		pmib->dot11RFEntry.trsw_pape_C9 = intVal;

		apmib_get(MIB_HW_11N_TRSWPAPE_CC, (void *)&intVal);
		pmib->dot11RFEntry.trsw_pape_CC = intVal;

		apmib_get(MIB_HW_11N_TARGET_PWR, (void *)&intVal);
		pmib->dot11RFEntry.target_pwr = intVal;

		//apmib_get(MIB_HW_11N_PA_TYPE, (void *)&intVal);
		//pmib->dot11RFEntry.pa_type = intVal;

		if (pmib->dot11RFEntry.dot11RFType == 10) {	// Zebra
			apmib_get(MIB_WLAN_RFPOWER_SCALE, (void *)&intVal);
			if (intVal == 1)
				intVal = 3;
			else if (intVal == 2)
				intVal = 6;
			else if (intVal == 3)
				intVal = 9;
			else if (intVal == 4)
				intVal = 17;

			/* 97G 8812F 8814B is 0.25dBm per number, rather than is 0.5dBm */
# if defined(CONFIG_WLAN_HAL_8812FE) || defined(CONFIG_WLAN_HAL_8197G) || defined(CONFIG_WLAN_HAL_8814BE)
			switch (getWLAN_ChipVersion()) {
			case CHIP_RTL8197G:
			case CHIP_RTL8812F:
			case CHIP_RTL8814B:
				intVal <<= 1;
				break;
			default:
				break;
			}
# endif
			if (intVal) {
				for (i = 0; i < MAX_2G_CHANNEL_NUM_MIB; i++) {
					if (pmib->dot11RFEntry.pwrlevelCCK_A[i] != 0) {
						if ((pmib->dot11RFEntry.pwrlevelCCK_A[i] - intVal) >= 1)
							pmib->dot11RFEntry.pwrlevelCCK_A[i] -= intVal;
						else
							pmib->dot11RFEntry.pwrlevelCCK_A[i] = 1;
					}
					if (pmib->dot11RFEntry.pwrlevelCCK_B[i] != 0) {
						if ((pmib->dot11RFEntry.pwrlevelCCK_B[i] - intVal) >= 1)
							pmib->dot11RFEntry.pwrlevelCCK_B[i] -= intVal;
						else
							pmib->dot11RFEntry.pwrlevelCCK_B[i] = 1;
					}
# if defined(CONFIG_WLAN_HAL_8814AE) || defined(CONFIG_WLAN_HAL_8814BE)
					if (pmib->dot11RFEntry.pwrlevelCCK_C[i] != 0) {
						if ((pmib->dot11RFEntry.pwrlevelCCK_C[i] - intVal) >= 1)
							pmib->dot11RFEntry.pwrlevelCCK_C[i] -= intVal;
						else
							pmib->dot11RFEntry.pwrlevelCCK_C[i] = 1;
					}
					if (pmib->dot11RFEntry.pwrlevelCCK_D[i] != 0) {
						if ((pmib->dot11RFEntry.pwrlevelCCK_D[i] - intVal) >= 1)
							pmib->dot11RFEntry.pwrlevelCCK_D[i] -= intVal;
						else
							pmib->dot11RFEntry.pwrlevelCCK_D[i] = 1;
					}
# endif
					if (pmib->dot11RFEntry.pwrlevelHT40_1S_A[i] != 0) {
						if ((pmib->dot11RFEntry.pwrlevelHT40_1S_A[i] - intVal) >= 1)
							pmib->dot11RFEntry.pwrlevelHT40_1S_A[i] -= intVal;
						else
							pmib->dot11RFEntry.pwrlevelHT40_1S_A[i] = 1;
					}
					if (pmib->dot11RFEntry.pwrlevelHT40_1S_B[i] != 0) {
						if ((pmib->dot11RFEntry.pwrlevelHT40_1S_B[i] - intVal) >= 1)
							pmib->dot11RFEntry.pwrlevelHT40_1S_B[i] -= intVal;
						else
							pmib->dot11RFEntry.pwrlevelHT40_1S_B[i] = 1;
					}
# if defined(CONFIG_WLAN_HAL_8814AE) || defined(CONFIG_WLAN_HAL_8814BE)
					if (pmib->dot11RFEntry.pwrlevelHT40_1S_C[i] != 0) {
						if ((pmib->dot11RFEntry.pwrlevelHT40_1S_C[i] - intVal) >= 1)
							pmib->dot11RFEntry.pwrlevelHT40_1S_C[i] -= intVal;
						else
							pmib->dot11RFEntry.pwrlevelHT40_1S_C[i] = 1;
					}
					if (pmib->dot11RFEntry.pwrlevelHT40_1S_D[i] != 0) {
						if ((pmib->dot11RFEntry.pwrlevelHT40_1S_D[i] - intVal) >= 1)
							pmib->dot11RFEntry.pwrlevelHT40_1S_D[i] -= intVal;
						else
							pmib->dot11RFEntry.pwrlevelHT40_1S_D[i] = 1;
					}
# endif
				}

# if defined(CONFIG_RTL_92D_SUPPORT) || defined(CONFIG_RTL_8812_SUPPORT)
				for (i = 0; i < MAX_5G_CHANNEL_NUM_MIB; i++) {
					if (pmib->dot11RFEntry.pwrlevel5GHT40_1S_A[i] != 0) {
						if ((pmib->dot11RFEntry.pwrlevel5GHT40_1S_A[i] - intVal) >= 1)
							pmib->dot11RFEntry.pwrlevel5GHT40_1S_A[i] -= intVal;
						else
							pmib->dot11RFEntry.pwrlevel5GHT40_1S_A[i] = 1;
					}
					if (pmib->dot11RFEntry.pwrlevel5GHT40_1S_B[i] != 0) {
						if ((pmib->dot11RFEntry.pwrlevel5GHT40_1S_B[i] - intVal) >= 1)
							pmib->dot11RFEntry.pwrlevel5GHT40_1S_B[i] -= intVal;
						else
							pmib->dot11RFEntry.pwrlevel5GHT40_1S_B[i] = 1;
					}
#  if defined(CONFIG_WLAN_HAL_8814AE) || defined(CONFIG_WLAN_HAL_8814BE)
					if (pmib->dot11RFEntry.pwrlevel5GHT40_1S_C[i] != 0) {
						if ((pmib->dot11RFEntry.pwrlevel5GHT40_1S_C[i] - intVal) >= 1)
							pmib->dot11RFEntry.pwrlevel5GHT40_1S_C[i] -= intVal;
						else
							pmib->dot11RFEntry.pwrlevel5GHT40_1S_C[i] = 1;
					}
					if (pmib->dot11RFEntry.pwrlevel5GHT40_1S_D[i] != 0) {
						if ((pmib->dot11RFEntry.pwrlevel5GHT40_1S_D[i] - intVal) >= 1)
							pmib->dot11RFEntry.pwrlevel5GHT40_1S_D[i] -= intVal;
						else
							pmib->dot11RFEntry.pwrlevel5GHT40_1S_D[i] = 1;
					}
#  endif
				}
# endif	//#if defined(CONFIG_RTL_92D_SUPPORT)
			}
		}
		if (pmib->dot11RFEntry.dot11RFType == 10) { // Zebra
			if (pmib->dot11RFEntry.tssi_enable) {
				apmib_get(MIB_WLAN_RFPOWER_SCALE, (void *)&intVal);
				if (intVal == 1)
					intVal = -12;
				else if (intVal == 2)
					intVal = -24;
				else if (intVal == 3)
					intVal = -36;
				else if (intVal == 4)
					intVal = -68;
				if (intVal) {
					for (i = 0; i < MAX_2G_CHANNEL_NUM_MIB; i++) {
						pmib->dot11RFEntry.pwrlevel_TSSICCK_A[i] -= intVal;
						pmib->dot11RFEntry.pwrlevel_TSSICCK_B[i] -= intVal;
						pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_A[i] -= intVal;
						pmib->dot11RFEntry.pwrlevel_TSSIHT40_1S_B[i] -= intVal;
					}

					for (i = 0; i < MAX_5G_CHANNEL_NUM_MIB; i++) {
						pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_A[i] -= intVal;
						pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_B[i] -= intVal;
						pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_C[i] -= intVal;
						pmib->dot11RFEntry.pwrlevel_TSSI5GHT40_1S_D[i] -= intVal;
					}
				}
			}
		}
#else	// !CONFIG_RTL_8198C && !CONFIG_RTL_8196C && !CONFIG_RTL_8198 && !CONFIG_RTL_819XD && !CONFIG_RTL_8196E && !CONFIG_RTL_8198B
//!CONFIG_RTL_8196B => rtl8651c+rtl8190
		apmib_get(MIB_HW_ANT_DIVERSITY, (void *)&intVal);
		pmib->dot11RFEntry.dot11DiversitySupport = intVal;

		apmib_get(MIB_HW_TX_ANT, (void *)&intVal);
		pmib->dot11RFEntry.defaultAntennaB = intVal;
# if 0
		apmib_get(MIB_HW_INIT_GAIN, (void *)&intVal);
		pmib->dot11RFEntry.initialGain = intVal;
# endif
		apmib_get(MIB_HW_TX_POWER_CCK, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevelCCK, buf1, 14);

		apmib_get(MIB_HW_TX_POWER_OFDM, (void *)buf1);
		memcpy(pmib->dot11RFEntry.pwrlevelOFDM, buf1, 162);

		apmib_get(MIB_HW_11N_LOFDMPWD, (void *)&intVal);
		pmib->dot11RFEntry.legacyOFDM_pwrdiff = intVal;

		apmib_get(MIB_HW_11N_ANTPWD_C, (void *)&intVal);
		pmib->dot11RFEntry.antC_pwrdiff = intVal;

		apmib_get(MIB_HW_11N_THER_RFIC, (void *)&intVal);
		pmib->dot11RFEntry.ther_rfic = intVal;

		apmib_get(MIB_HW_11N_XCAP, (void *)&intVal);
		pmib->dot11RFEntry.crystalCap = intVal;

		// set output power scale
		//if (pmib->dot11RFEntry.dot11RFType == 7) { // Zebra
		if (pmib->dot11RFEntry.dot11RFType == 10) {	// Zebra
			apmib_get(MIB_WLAN_RFPOWER_SCALE, (void *)&intVal);
			if (intVal == 1)
				intVal = 3;
			else if (intVal == 2)
				intVal = 6;
			else if (intVal == 3)
				intVal = 9;
			else if (intVal == 4)
				intVal = 17;
			if (intVal) {
				for (i = 0; i < 14; i++) {
					if (pmib->dot11RFEntry.pwrlevelCCK[i] != 0) {
						if ((pmib->dot11RFEntry.pwrlevelCCK[i] - intVal) >= 1)
							pmib->dot11RFEntry.pwrlevelCCK[i] -= intVal;
						else
							pmib->dot11RFEntry.pwrlevelCCK[i] = 1;
					}
				}
				for (i = 0; i < 162; i++) {
					if (pmib->dot11RFEntry.pwrlevelOFDM[i] != 0) {
						if ((pmib->dot11RFEntry.pwrlevelOFDM[i] - intVal) >= 1)
							pmib->dot11RFEntry.pwrlevelOFDM[i] -= intVal;
						else
							pmib->dot11RFEntry.pwrlevelOFDM[i] = 1;
					}
				}
			}
		}
#endif	// For Check CONFIG_RTL_8196B
		apmib_get(MIB_WLAN_BEACON_INTERVAL, (void *)&intVal);
		pmib->dot11StationConfigEntry.dot11BeaconPeriod = intVal;

#ifdef __DAVO__
		//pmib->dot11RFEntry.request_autochan = 0;
		//pmib->dot11RFEntry.request_autochan_rst = 0;
#endif
		apmib_get(MIB_WLAN_CHANNEL, (void *)&intVal);
		pmib->dot11RFEntry.dot11channel = intVal;

		apmib_get(MIB_WLAN_RTS_THRESHOLD, (void *)&intVal);
		pmib->dot11OperationEntry.dot11RTSThreshold = intVal;

		apmib_get(MIB_WLAN_RETRY_LIMIT, (void *)&intVal);
		pmib->dot11OperationEntry.dot11ShortRetryLimit = intVal;

		apmib_get(MIB_WLAN_FRAG_THRESHOLD, (void *)&intVal);
		pmib->dot11OperationEntry.dot11FragmentationThreshold = intVal;

		apmib_get(MIB_WLAN_INACTIVITY_TIME, (void *)&intVal);
		pmib->dot11OperationEntry.expiretime = intVal;

		apmib_get(MIB_WLAN_PREAMBLE_TYPE, (void *)&intVal);
		pmib->dot11RFEntry.shortpreamble = intVal;

		apmib_get(MIB_WLAN_DTIM_PERIOD, (void *)&intVal);
		pmib->dot11StationConfigEntry.dot11DTIMPeriod = intVal;

		/*STBC and Coexist */
		apmib_get(MIB_WLAN_STBC_ENABLED, (void *)&intVal);
		pmib->dot11nConfigEntry.dot11nSTBC = intVal;

		apmib_get(MIB_WLAN_LDPC_ENABLED, (void *)&intVal);
		pmib->dot11nConfigEntry.dot11nLDPC = intVal;

		apmib_get(MIB_WLAN_COEXIST_ENABLED, (void *)&intVal);
		pmib->dot11nConfigEntry.dot11nCoexist = intVal;
#ifdef CONFIG_IEEE80211V
		apmib_get(MIB_WLAN_DOT11V_ENABLE, (void *)&intVal);
		pmib->wnmEntry.dot11vBssTransEnable = intVal;
#endif
#ifdef TDLS_SUPPORT
		apmib_get(MIB_WLAN_TDLS_PROHIBITED, (void *)&intVal);
		pmib->dot11OperationEntry.tdls_prohibited = intVal;

		apmib_get(MIB_WLAN_TDLS_CS_PROHIBITED, (void *)&intVal);
		pmib->dot11OperationEntry.tdls_cs_prohibited = intVal;
#endif
#ifdef FAST_BSS_TRANSITION
		if (mode == AP_MODE || mode == AP_MESH_MODE || mode == AP_WDS_MODE) {
			apmib_get(MIB_WLAN_ENABLE_1X, (void *)&enable1x);
			apmib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt);

			if ((enable1x != 1) && (encrypt == ENCRYPT_WPA2 || encrypt == ENCRYPT_WPA2_MIXED)) {
				apmib_get(MIB_WLAN_FT_ENABLE, (void *)&intVal);
				pmib->dot11FTEntry.dot11FastBSSTransitionEnabled = intVal;
				apmib_get(MIB_WLAN_FT_OVER_DS, (void *)&intVal);
				pmib->dot11FTEntry.dot11FTOverDSEnabled = intVal;
			} else {
				pmib->dot11FTEntry.dot11FastBSSTransitionEnabled = 0;
				pmib->dot11FTEntry.dot11FTOverDSEnabled = 0;
			}
		}
#endif
		apmib_get(MIB_WLAN_ACK_TIMEOUT, (void *)&intVal);
		pmib->miscEntry.ack_timeout = intVal;

		//### add by sen_liu 2011.3.29 TX Beamforming update to mib in 92D
		apmib_get(MIB_WLAN_TX_BEAMFORMING, (void *)&intVal);
		pmib->dot11RFEntry.txbf = intVal;

		apmib_get(MIB_WLAN_TXBF_MU, (void *)&intVal);
		pmib->dot11RFEntry.txbf_mu = intVal;
		//### end priv->pmib->dot11RFEntry.txbf

		// enable/disable the notification for IAPP
		apmib_get(MIB_WLAN_IAPP_DISABLED, (void *)&intVal);
		if (intVal == 0)
			pmib->dot11OperationEntry.iapp_enable = 1;
		else
			pmib->dot11OperationEntry.iapp_enable = 0;

		// set 11g protection mode
		apmib_get(MIB_WLAN_PROTECTION_DISABLED, (void *)&intVal);
		pmib->dot11StationConfigEntry.protectionDisabled = intVal;

		// set block relay
		apmib_get(MIB_WLAN_BLOCK_RELAY, (void *)&intVal);
		pmib->dot11OperationEntry.block_relay = intVal;

		// set WiFi specific mode
		apmib_get(MIB_WIFI_SPECIFIC, (void *)&intVal);
		pmib->dot11OperationEntry.wifi_specific = intVal;

		// Set WDS
		apmib_get(MIB_WLAN_WDS_ENABLED, (void *)&intVal);
		apmib_get(MIB_WLAN_WDS_NUM, (void *)&intVal2);
		pmib->dot11WdsInfo.wdsNum = 0;
#ifdef MBSSID
		if (v_previous > 0)
			intVal = 0;
#endif
		if (((mode == 2) || (mode == 3)) && (intVal != 0) && (intVal2 != 0)) {
			for (i = 0; i < intVal2; i++) {
				buf1[0] = i + 1;
				apmib_get(MIB_WLAN_WDS, (void *)buf1);
				pwds_EntryUI = (WDS_Tp) buf1;
				wds_Entry = &(pmib->dot11WdsInfo.entry[i]);
				memcpy(wds_Entry->macAddr, &(pwds_EntryUI->macAddr[0]), 6);
				wds_Entry->txRate = pwds_EntryUI->fixedTxRate;
				pmib->dot11WdsInfo.wdsNum++;
				set_mac_address(ifname, mac);
			}
			pmib->dot11WdsInfo.wdsEnabled = intVal;
		} else
			pmib->dot11WdsInfo.wdsEnabled = 0;

		if (((mode == 2) || (mode == 3)) && (intVal != 0)) {
			apmib_get(MIB_WLAN_WDS_ENCRYPT, (void *)&intVal);
			if (intVal == 0)
				pmib->dot11WdsInfo.wdsPrivacy = 0;
			else if (intVal == 1) {
				apmib_get(MIB_WLAN_WDS_WEP_KEY, (void *)buf1);
				pmib->dot11WdsInfo.wdsPrivacy = 1;
				yxatoi(&(pmib->dot11WdsInfo.wdsWepKey[0]), buf1, 10);
			} else if (intVal == 2) {
				apmib_get(MIB_WLAN_WDS_WEP_KEY, (void *)buf1);
				pmib->dot11WdsInfo.wdsPrivacy = 5;
				yxatoi(&(pmib->dot11WdsInfo.wdsWepKey[0]), buf1, 26);
			} else if (intVal == 3) {
				pmib->dot11WdsInfo.wdsPrivacy = 2;
				apmib_get(MIB_WLAN_WDS_PSK, (void *)buf1);
				strcpy((char *)pmib->dot11WdsInfo.wdsPskPassPhrase, buf1);
			} else {
				pmib->dot11WdsInfo.wdsPrivacy = 4;
				apmib_get(MIB_WLAN_WDS_PSK, (void *)buf1);
				strcpy((char *)pmib->dot11WdsInfo.wdsPskPassPhrase, buf1);
			}
		}
		// enable/disable the notification for IAPP
		apmib_get(MIB_WLAN_IAPP_DISABLED, (void *)&intVal);
		if (intVal == 0)
			pmib->dot11OperationEntry.iapp_enable = 1;
		else
			pmib->dot11OperationEntry.iapp_enable = 0;

#if defined(CONFIG_RTK_MESH) && defined(_MESH_ACL_ENABLE_)	// below code copy above ACL code
		// Copy Webpage setting to userspace MIB struct table
		pmib->dot1180211sInfo.mesh_acl_num = 0;
		apmib_get(MIB_WLAN_MESH_ACL_ENABLED, (void *)&intVal);
		pmib->dot1180211sInfo.mesh_acl_mode = intVal;

		if (intVal != 0) {
			apmib_get(MIB_WLAN_MESH_ACL_NUM, (void *)&intVal);
			if (intVal != 0) {
				for (i = 0; i < intVal; i++) {
					buf1[0] = i + 1;
					apmib_get(MIB_WLAN_MESH_ACL_ADDR, (void *)buf1);
					pAcl = (MACFILTER_T *) buf1;
					memcpy(&(pmib->dot1180211sInfo.mesh_acl_addr[i][0]), &(pAcl->macAddr[0]), 6);
					pmib->dot1180211sInfo.mesh_acl_num++;
				}
			}
		}
#endif

		// set nat2.5 disable when client and mac clone is set
		apmib_get(MIB_WLAN_MACCLONE_ENABLED, (void *)&intVal);
		if ((intVal == 1) && (mode == 1)) {
			// let Nat25 and CloneMacAddr can use concurrent
			//pmib->ethBrExtInfo.nat25_disable = 1;
			pmib->ethBrExtInfo.macclone_enable = 1;
		} else if ((intVal == 2) && (mode == 1)) {
			// let Nat25 and CloneMacAddr can use concurrent
			//pmib->ethBrExtInfo.nat25_disable = 1;
			pmib->ethBrExtInfo.macclone_enable = 2;
		} else {
			// let Nat25 and CloneMacAddr can use concurrent
			//pmib->ethBrExtInfo.nat25_disable = 0;
			pmib->ethBrExtInfo.macclone_enable = 0;
		}

		// set nat2.5 disable and macclone disable when wireless isp mode
		apmib_get(MIB_OP_MODE, (void *)&intVal);
		if (intVal == 2) {
			pmib->ethBrExtInfo.nat25_disable = 0;	// enable nat25 for ipv6-passthru ping6 fail issue at wisp mode && wlan client mode .
			pmib->ethBrExtInfo.macclone_enable = 0;
		}

#ifdef WLAN_HS2_CONFIG
		// enable/disable the notification for IAPP
		apmib_get(MIB_WLAN_HS2_ENABLE, (void *)&intVal);
		if (intVal == 0)
			pmib->hs2Entry.hs_enable = 0;
		else
			pmib->hs2Entry.hs_enable = 1;
#endif

		// for 11n
		apmib_get(MIB_WLAN_CHANNEL_BONDING, &channel_bound);
		pmib->dot11nConfigEntry.dot11nUse40M = channel_bound;
		apmib_get(MIB_WLAN_CONTROL_SIDEBAND, &intVal);
		if (channel_bound == 0) {
			pmib->dot11nConfigEntry.dot11n2ndChOffset = 0;
		} else {
			if (intVal == 0)
				pmib->dot11nConfigEntry.dot11n2ndChOffset = 1;
			if (intVal == 1)
				pmib->dot11nConfigEntry.dot11n2ndChOffset = 2;
#ifdef CONFIG_RTL_8812_SUPPORT
			apmib_get(MIB_WLAN_CHANNEL, (void *)&intVal);
			if (intVal > 14) {
				_DEBUG(L_INFO, "adjust 5G 2ndoffset for 8812");	//eric_pf3
				if (intVal == 36 || intVal == 44 || intVal == 52 || intVal == 60
				    || intVal == 100 || intVal == 108 || intVal == 116 || intVal == 124
				    || intVal == 132 || intVal == 140 || intVal == 149 || intVal == 157
				    || intVal == 165 || intVal == 173)
					pmib->dot11nConfigEntry.dot11n2ndChOffset = 2;
				else
					pmib->dot11nConfigEntry.dot11n2ndChOffset = 1;
			}
# if 0
			else {
				apmib_get(MIB_WLAN_BAND, (void *)&intVal);
				wlan_band = intVal;
				if (wlan_band == 75) {
					_DEBUG(L_INFO, "adjust 2.4G AC mode 2ndoffset for 8812");	//ac2g
					if (intVal == 1 || intVal == 9)
						pmib->dot11nConfigEntry.dot11n2ndChOffset = 2;
					else
						pmib->dot11nConfigEntry.dot11n2ndChOffset = 1;
				}
			}
# endif
#endif
		}
		apmib_get(MIB_WLAN_SHORT_GI, &intVal);
		pmib->dot11nConfigEntry.dot11nShortGIfor20M = intVal;
		pmib->dot11nConfigEntry.dot11nShortGIfor40M = intVal;
		pmib->dot11nConfigEntry.dot11nShortGIfor80M = intVal;
		/*
		apmib_get(MIB_WLAN_11N_STBC, &intVal);
		pmib->dot11nConfigEntry.dot11nSTBC = intVal;
		apmib_get(MIB_WLAN_11N_COEXIST, &intVal);
		pmib->dot11nConfigEntry.dot11nCoexist = intVal;
		 */
		apmib_get(MIB_WLAN_AGGREGATION, &aggregation);
		if (aggregation == 0) {
			pmib->dot11nConfigEntry.dot11nAMPDU = 0;
			pmib->dot11nConfigEntry.dot11nAMSDU = 0;
		} else if (aggregation == 1) {
			pmib->dot11nConfigEntry.dot11nAMPDU = 1;
			pmib->dot11nConfigEntry.dot11nAMSDU = 0;
		} else if (aggregation == 2) {
			pmib->dot11nConfigEntry.dot11nAMPDU = 0;
			pmib->dot11nConfigEntry.dot11nAMSDU = 1;
		} else if (aggregation == 3) {
			pmib->dot11nConfigEntry.dot11nAMPDU = 1;
			pmib->dot11nConfigEntry.dot11nAMSDU = 2;
		}

#if defined(CONFIG_RTL_819X) && defined(MBSSID)
		if (pmib->dot11OperationEntry.opmode & 0x00000010) {	// AP mode
			for (vwlan_idx = 1; vwlan_idx < 5; vwlan_idx++) {
				apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&intVal4);
				if (intVal4 == 0)
					vap_enable++;
				intVal4 = 0;
			}
			vwlan_idx = 0;
		}
		if (vap_enable && (mode == AP_MODE || mode == AP_WDS_MODE || mode == AP_MESH_MODE))
			pmib->miscEntry.vap_enable = 1;
		else
			pmib->miscEntry.vap_enable = 0;
#endif
		apmib_get(MIB_WLAN_LOWEST_MLCST_RATE, &intVal);
		pmib->dot11StationConfigEntry.lowestMlcstRate = intVal;
	}

#ifdef WIFI_SIMPLE_CONFIG
	pmib->wscEntry.wsc_enable = 0;
#endif

	if (vwlan_idx != NUM_VWLAN_INTERFACE) {	// not repeater interface
		apmib_get(MIB_WLAN_BASIC_RATES, (void *)&intVal);
		pmib->dot11StationConfigEntry.dot11BasicRates = intVal;

		apmib_get(MIB_WLAN_SUPPORTED_RATES, (void *)&intVal);
		pmib->dot11StationConfigEntry.dot11SupportedRates = intVal;

		apmib_get(MIB_WLAN_RATE_ADAPTIVE_ENABLED, (void *)&intVal);
		if (intVal == 0) {
			unsigned int uintVal = 0;
			pmib->dot11StationConfigEntry.autoRate = 0;
			apmib_get(MIB_WLAN_FIX_RATE, (void *)&uintVal);
			pmib->dot11StationConfigEntry.fixedTxRate = uintVal;
		} else
			pmib->dot11StationConfigEntry.autoRate = 1;

		apmib_get(MIB_WLAN_HIDDEN_SSID, (void *)&intVal);
		pmib->dot11OperationEntry.hiddenAP = intVal;

#if defined(CONFIG_RTL_92D_SUPPORT) || defined(CONFIG_RTL_8812_SUPPORT)
		apmib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&intVal);
		pmib->dot11RFEntry.phyBandSelect = intVal;
		apmib_get(MIB_WLAN_MAC_PHY_MODE, (void *)&intVal);
		pmib->dot11RFEntry.macPhyMode = intVal;
#endif
		// set band
		apmib_get(MIB_WLAN_BAND, (void *)&intVal);
		wlan_band = intVal;
		if ((mode != 1) && (pmib->dot11OperationEntry.wifi_specific == 1) && (wlan_band == 2))
			wlan_band = 3;

		if (wlan_band == 8) {		// pure-11n
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(CONFIG_RTL_8812_SUPPORT)
			if (pmib->dot11RFEntry.phyBandSelect == PHYBAND_5G) {
				wlan_band += 4;	// a+n
				pmib->dot11StationConfigEntry.legacySTADeny = 4;
			} else if (pmib->dot11RFEntry.phyBandSelect == PHYBAND_2G)
#endif
			{
				wlan_band += 3;	// b+g+n
				pmib->dot11StationConfigEntry.legacySTADeny = 3;
			}
		} else if (wlan_band == 2) {	// pure-11g
			wlan_band += 1;	// b+g
			pmib->dot11StationConfigEntry.legacySTADeny = 1;
		} else if (wlan_band == 10) {	// g+n
			wlan_band += 1;		// b+g+n
			pmib->dot11StationConfigEntry.legacySTADeny = 1;
		} else if (wlan_band == 64) {	// pure-11ac
			wlan_band += 12;	// a+n
			pmib->dot11StationConfigEntry.legacySTADeny = 12;
		} else if (wlan_band == 72) {	// ac+n
			wlan_band += 4;		// a
			pmib->dot11StationConfigEntry.legacySTADeny = 4;
		} else
			pmib->dot11StationConfigEntry.legacySTADeny = 0;

		pmib->dot11BssType.net_work_type = wlan_band;

		// set guest access

		apmib_get(MIB_OP_MODE, (void*)&opmode);
		apmib_get(MIB_WLAN_ACCESS, (void *)&intVal);
		// bridge mode and guest access
		pmib->dot11OperationEntry.guest_access = (opmode == 1 && intVal == 1) ? 2 : intVal;
		// SSOL requires
		apmib_get(MIB_WLAN_SSID_SEPARATOR, (void *)&intVal);
		pmib->dot11OperationEntry.ssid_separator = intVal;

		// set WMM
		apmib_get(MIB_WLAN_WMM_ENABLED, (void *)&intVal);
		pmib->dot11QosEntry.dot11QosEnable = intVal;

		apmib_get(MIB_WLAN_UAPSD_ENABLED, (void *)&intVal);
		pmib->dot11QosEntry.dot11QosAPSD = intVal;
	}

	apmib_get(MIB_WLAN_AUTH_TYPE, (void *)&intVal);
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt);
#ifdef CONFIG_RTL_WAPI_SUPPORT
	/* WAPI is independent. disable WAPI first if not WAPI */
	if (7 != encrypt)
		pmib->wapiInfo.wapiType = 0;
#endif
	if ((intVal == 1) && (encrypt != 1))
		intVal = 0;	// shared-key and not WEP enabled, force to open-system

	pmib->dot1180211AuthEntry.dot11AuthAlgrthm = intVal;
	if (encrypt == 0)
		pmib->dot1180211AuthEntry.dot11PrivacyAlgrthm = 0;
	else if (encrypt == 1) {
		// WEP mode
		apmib_get(MIB_WLAN_WEP, (void *)&wep);
		if (wep == 1) {
			pmib->dot1180211AuthEntry.dot11PrivacyAlgrthm = 1;
			apmib_get(MIB_WLAN_WEP64_KEY1, (void *)buf1);
			memcpy(&(pmib->dot11DefaultKeysTable.keytype[0]), buf1, 5);
			apmib_get(MIB_WLAN_WEP64_KEY2, (void *)buf1);
			memcpy(&(pmib->dot11DefaultKeysTable.keytype[1]), buf1, 5);
			apmib_get(MIB_WLAN_WEP64_KEY3, (void *)buf1);
			memcpy(&(pmib->dot11DefaultKeysTable.keytype[2]), buf1, 5);
			apmib_get(MIB_WLAN_WEP64_KEY4, (void *)buf1);
			memcpy(&(pmib->dot11DefaultKeysTable.keytype[3]), buf1, 5);
			apmib_get(MIB_WLAN_WEP_DEFAULT_KEY, (void *)&intVal);
			pmib->dot1180211AuthEntry.dot11PrivacyKeyIndex = intVal;
		} else {
			pmib->dot1180211AuthEntry.dot11PrivacyAlgrthm = 5;
			apmib_get(MIB_WLAN_WEP128_KEY1, (void *)buf1);
			memcpy(&(pmib->dot11DefaultKeysTable.keytype[0]), buf1, 13);
			apmib_get(MIB_WLAN_WEP128_KEY2, (void *)buf1);
			memcpy(&(pmib->dot11DefaultKeysTable.keytype[1]), buf1, 13);
			apmib_get(MIB_WLAN_WEP128_KEY3, (void *)buf1);
			memcpy(&(pmib->dot11DefaultKeysTable.keytype[2]), buf1, 13);
			apmib_get(MIB_WLAN_WEP128_KEY4, (void *)buf1);
			memcpy(&(pmib->dot11DefaultKeysTable.keytype[3]), buf1, 13);
			apmib_get(MIB_WLAN_WEP_DEFAULT_KEY, (void *)&intVal);
			pmib->dot1180211AuthEntry.dot11PrivacyKeyIndex = intVal;
		}
	}
#ifdef CONFIG_RTL_WAPI_SUPPORT
	else if (7 == encrypt) {
		pmib->dot1180211AuthEntry.dot11PrivacyAlgrthm = 7;
		pmib->dot1180211AuthEntry.dot11AuthAlgrthm = 0;
	}
#endif
	else {
		// WPA mode
		pmib->dot1180211AuthEntry.dot11PrivacyAlgrthm = 2;
	}

#ifndef CONFIG_RTL8196B_TLD
# ifdef MBSSID
	if (vwlan_idx > 0 && pmib->dot11OperationEntry.guest_access)
		pmib->dot11OperationEntry.block_relay = 1;
# endif
#endif
#ifdef CONFIG_IEEE80211W
	apmib_get(MIB_WLAN_IEEE80211W, (void *)&intVal);
	pmib->dot1180211AuthEntry.dot11IEEE80211W = intVal;
	apmib_get(MIB_WLAN_SHA256_ENABLE, (void *)&intVal);
	pmib->dot1180211AuthEntry.dot11EnableSHA256 = intVal;
#endif
	// Set 802.1x flag
	enable1x = 0;
	apmib_get(MIB_WLAN_ENABLE_1X, (void *)&intVal);
	if (encrypt < 2) {
		apmib_get(MIB_WLAN_MAC_AUTH_ENABLED, (void *)&intVal2);
		if ((intVal != 0) || (intVal2 != 0))
			enable1x = 1;
	}
#ifdef CONFIG_RTL_WAPI_SUPPORT
	else if (encrypt == 7) {
		/*wapi */
		enable1x = 0;
	}
#endif
	else
		enable1x = intVal;
	pmib->dot118021xAuthEntry.dot118021xAlgrthm = enable1x;
	apmib_get(MIB_WLAN_ACCOUNT_RS_ENABLED, (void *)&intVal);
	pmib->dot118021xAuthEntry.acct_enabled = intVal;

#ifdef CONFIG_RTL_WAPI_SUPPORT
	if (7 == encrypt) {
		//apmib_get(MIB_WLAN_WAPI_ASIPADDR,);
		apmib_get(MIB_WLAN_WAPI_AUTH, (void *)&intVal);
		pmib->wapiInfo.wapiType = intVal;

		apmib_get(MIB_WLAN_WAPI_MCAST_PACKETS, (void *)&intVal);
		pmib->wapiInfo.wapiUpdateMCastKeyPktNum = intVal;

		apmib_get(MIB_WLAN_WAPI_MCASTREKEY, (void *)&intVal);
		pmib->wapiInfo.wapiUpdateMCastKeyType = intVal;

		apmib_get(MIB_WLAN_WAPI_MCAST_TIME, (void *)&intVal);
		pmib->wapiInfo.wapiUpdateMCastKeyTimeout = intVal;

		apmib_get(MIB_WLAN_WAPI_UCAST_PACKETS, (void *)&intVal);
		pmib->wapiInfo.wapiUpdateUCastKeyPktNum = intVal;

		apmib_get(MIB_WLAN_WAPI_UCASTREKEY, (void *)&intVal);
		pmib->wapiInfo.wapiUpdateUCastKeyType = intVal;

		apmib_get(MIB_WLAN_WAPI_UCAST_TIME, (void *)&intVal);
		pmib->wapiInfo.wapiUpdateUCastKeyTimeout = intVal;

		/*1: hex  -else passthru */
		apmib_get(MIB_WLAN_WAPI_PSK_FORMAT, (void *)&intVal2);
		apmib_get(MIB_WLAN_WAPI_PSKLEN, (void *)&intVal);
		apmib_get(MIB_WLAN_WAPI_PSK, (void *)buf1);
		pmib->wapiInfo.wapiPsk.len = intVal;
		if (1 == intVal2) {
			/* hex */
			yxatoi((unsigned char *)buf2, buf1, pmib->wapiInfo.wapiPsk.len * 2);
		} else {
			/* passthru */
			strcpy(buf2, buf1);
		}
		memcpy(pmib->wapiInfo.wapiPsk.octet, buf2, pmib->wapiInfo.wapiPsk.len);
	}
#endif

	// for QoS control
#define GBWC_MODE_DISABLE		0
#define GBWC_MODE_LIMIT_MAC_INNER	1	// limit bw by mac address
#define GBWC_MODE_LIMIT_MAC_OUTTER	2	// limit bw by excluding the mac
#define GBWC_MODE_LIMIT_IF_TX		3	// limit bw by interface tx
#define GBWC_MODE_LIMIT_IF_RX		4	// limit bw by interface rx
#define GBWC_MODE_LIMIT_IF_TRX		5	// limit bw by interface tx/rx
	qbwc_mode = GBWC_MODE_DISABLE;

	apmib_get(MIB_WLAN_TX_RESTRICT, (void *)&tx_bandwidth);
	apmib_get(MIB_WLAN_RX_RESTRICT, (void *)&rx_bandwidth);
	if (tx_bandwidth && rx_bandwidth == 0)
		qbwc_mode = GBWC_MODE_LIMIT_IF_TX;
	else if (tx_bandwidth == 0 && rx_bandwidth)
		qbwc_mode = GBWC_MODE_LIMIT_IF_RX;
	else if (tx_bandwidth && rx_bandwidth)
		qbwc_mode = GBWC_MODE_LIMIT_IF_TRX;

	pmib->gbwcEntry.GBWCMode = qbwc_mode;
	pmib->gbwcEntry.GBWCThrd_tx = tx_bandwidth * 1024;
	pmib->gbwcEntry.GBWCThrd_rx = rx_bandwidth * 1024;

#ifdef STA_CONTROL
	pmib->staControl.stactrl_enable = 0;
	if ((mode == AP_MODE || mode == AP_MESH_MODE || mode == AP_WDS_MODE)) {
		apmib_get(MIB_WLAN_STACTRL_ENABLE, (void *)&intVal);
		if (intVal) {
			apmib_get(MIB_WLAN_SSID, (void *)buf1);
			apmib_save_wlanIdx();
			/*get the other band's mib */
			wlan_idx = wlan_idx ? 0 : 1;
			apmib_get(MIB_WLAN_SSID, (void *)buf2);
			apmib_recov_wlanIdx();

			/* shift SSID check to wlan driver */
			if (1 /*strcmp(buf1, buf2) == 0*/) {
				pmib->staControl.stactrl_enable = 1;
				pmib->staControl.stactrl_groupID = vwlan_idx;
				apmib_get(MIB_WLAN_STACTRL_PREFER, (void *)&intVal);
				pmib->staControl.stactrl_prefer_band = intVal;
			}
		}
	}
#endif
#ifdef RTK_CAPWAP
# if defined(RTK_SMART_ROAMING) || defined(CONFIG_IEEE80211V)
	pmib->sr_profile.enable = 0;
	apmib_get(MIB_CAPWAP_MODE, (void *)&intVal);

#  if defined(CONFIG_IEEE80211V)
	apmib_get(MIB_WLAN_DOT11V_ENABLE, (void *)&intVal2);
	if (intVal2 && (intVal & CAPWAP_11V_ENABLE))
		pmib->sr_profile.enable = 1;
	else
#  endif
		if (intVal & CAPWAP_ROAMING_ENABLE)
			pmib->sr_profile.enable = 1;
# endif
#endif

#ifdef RTK_CROSSBAND_REPEATER
	pmib->crossBand.crossband_enable = 0;

	apmib_save_wlanIdx();
	wlan_idx = 0;
	apmib_get(MIB_WLAN_CROSSBAND_ACTIVATE, (void *)&intVal);
	apmib_get(MIB_WLAN_CROSSBAND_ENABLE, (void *)&intVal2);
	apmib_recov_wlanIdx();

	if ((mode == AP_MODE || mode == AP_MESH_MODE || mode == AP_WDS_MODE)) {
		if (intVal && intVal2) {
			pmib->crossBand.crossband_enable = 1;	//setmib to enable crossband in driver
		}
	}
#endif

#if defined(DOT11K)
	pmib->dot11StationConfigEntry.dot11RadioMeasurementActivated = 0;
	/*if Fast BSS Transition is enabled,  activate 11k and set 11K neighbor report */
	apmib_get(MIB_WLAN_DOT11K_ENABLE, (void *)&intVal);
	if (intVal && (mode == AP_MODE || mode == AP_MESH_MODE || mode == AP_WDS_MODE)) {
		/*delete all neightbor report first */
		snprintf(buf1, sizeof(buf1), NEIGHBOR_REPORT_FILE, ifname);
		yecho(buf1, "delall\n");
		/* activate 11k */
		pmib->dot11StationConfigEntry.dot11RadioMeasurementActivated = 1;
	}
# if defined(CONFIG_IEEE80211V)
	if (intVal)
		pmib->wnmEntry.Is11kDaemonOn = 1;
# endif
#endif

#ifdef CONFIG_RTK_MESH
# ifdef CONFIG_NEW_MESH_UI
	//new feature:Mesh enable/disable
	//brian add new key:MIB_MESH_ENABLE
	pmib->dot1180211sInfo.meshSilence = 0;

	apmib_get(MIB_WLAN_MESH_ENABLE, (void *)&intVal);
	if (mode == AP_MESH_MODE || mode == MESH_MODE) {
		if (intVal)
			pmib->dot1180211sInfo.mesh_enable = 1;
		else
			pmib->dot1180211sInfo.mesh_enable = 0;
	} else
		pmib->dot1180211sInfo.mesh_enable = 0;

	// set mesh argument
	// brian change to shutdown portal/root as default
	if (mode == AP_MESH_MODE) {
		pmib->dot1180211sInfo.mesh_ap_enable = 1;
		pmib->dot1180211sInfo.mesh_portal_enable = 0;
	} else if (mode == MESH_MODE) {
		if (!intVal)
			//pmib->dot11OperationEntry.opmode += 64; // WIFI_MESH_STATE = 0x00000040
			pmib->dot1180211sInfo.meshSilence = 1;

		pmib->dot1180211sInfo.mesh_ap_enable = 0;
		pmib->dot1180211sInfo.mesh_portal_enable = 0;
	} else {
		pmib->dot1180211sInfo.mesh_ap_enable = 0;
		pmib->dot1180211sInfo.mesh_portal_enable = 0;
	}
#  if 0				//by brian, dont enable root by default
	apmib_get(MIB_WLAN_MESH_ROOT_ENABLE, (void *)&intVal);
	pmib->dot1180211sInfo.mesh_root_enable = intVal;
#  else
	pmib->dot1180211sInfo.mesh_root_enable = 0;
#  endif
# else
	if (mode == AP_MPP_MODE) {
		pmib->dot1180211sInfo.mesh_enable = 1;
		pmib->dot1180211sInfo.mesh_ap_enable = 1;
		pmib->dot1180211sInfo.mesh_portal_enable = 1;
	} else if (mode == MPP_MODE) {
		pmib->dot1180211sInfo.mesh_enable = 1;
		pmib->dot1180211sInfo.mesh_ap_enable = 0;
		pmib->dot1180211sInfo.mesh_portal_enable = 1;
	} else if (mode == MAP_MODE) {
		pmib->dot1180211sInfo.mesh_enable = 1;
		pmib->dot1180211sInfo.mesh_ap_enable = 1;
		pmib->dot1180211sInfo.mesh_portal_enable = 0;
	} else if (mode == MP_MODE) {
		pmib->dot1180211sInfo.mesh_enable = 1;
		pmib->dot1180211sInfo.mesh_ap_enable = 0;
		pmib->dot1180211sInfo.mesh_portal_enable = 0;
	} else {
		pmib->dot1180211sInfo.mesh_enable = 0;
		pmib->dot1180211sInfo.mesh_ap_enable = 0;
		pmib->dot1180211sInfo.mesh_portal_enable = 0;
	}

	apmib_get(MIB_WLAN_MESH_ROOT_ENABLE, (void *)&intVal);
	pmib->dot1180211sInfo.mesh_root_enable = intVal;
# endif
	pmib->dot1180211sInfo.mesh_max_neightbor = 16;
	apmib_get(MIB_SCRLOG_ENABLED, (void *)&intVal);
	pmib->dot1180211sInfo.log_enabled = intVal;

	apmib_get(MIB_WLAN_MESH_ID, (void *)buf1);
	intVal2 = strlen(buf1);
	memset(pmib->dot1180211sInfo.mesh_id, 0, 32);
	memcpy(pmib->dot1180211sInfo.mesh_id, buf1, intVal2);

	apmib_get(MIB_WLAN_MESH_ENCRYPT, (void *)&intVal);
	apmib_get(MIB_WLAN_MESH_WPA_AUTH, (void *)&intVal2);
	if (intVal2 == 2 && intVal) {
		pmib->dot11sKeysTable.dot11Privacy = 4;
		apmib_get(MIB_WLAN_MESH_WPA_PSK, (void *)buf1);
		strcpy((char *)pmib->dot1180211sInfo.dot11PassPhrase, (char *)buf1);
	} else
		pmib->dot11sKeysTable.dot11Privacy = 0;
# ifdef RTK_MESH_METRIC_REFINE
	apmib_get(MIB_WLAN_MESH_CROSSBAND_ENABLED, (void *)&intVal);
	if (pmib->dot1180211sInfo.mesh_enable && intVal) //keith-mesh crossband
		pmib->meshPathsel.mesh_crossbandEnable = 1;
	else
		pmib->meshPathsel.mesh_crossbandEnable = 0;
# endif
#endif	// CONFIG_RTK_MESH

	// When using driver base WPA, set wpa setting to driver
#if 1
	apmib_get(MIB_WLAN_WPA_AUTH, (void *)&intVal3);
//#ifdef CONFIG_RTL_8196B
// button 2009.05.21
# if 1
	if ((intVal3 & WPA_AUTH_PSK) && encrypt >= 2
#  ifdef CONFIG_RTL_WAPI_SUPPORT
	    && encrypt < 7
#  endif
	    )
# else
	if (mode != 1 && (intVal3 & WPA_AUTH_PSK) && encrypt >= 2
#  ifdef CONFIG_RTL_WAPI_SUPPORT
	    && encrypt < 7
#  endif
	    )
# endif
	{
		if (encrypt == 2)
			intVal = 1;
		else if (encrypt == 4)
			intVal = 2;
		else if (encrypt == 6)
			intVal = 3;
		else if (encrypt == 8)
			intVal = 8;
		else if (encrypt == 10)
			intVal = 10;
		else {
			_DEBUG(L_ERR, "invalid ENCRYPT value(%d)", encrypt);
			return -1;
		}
		pmib->dot1180211AuthEntry.dot11EnablePSK = intVal;

		apmib_get(MIB_WLAN_WPA_PSK, (void *)buf1);
		strcpy((char *)pmib->dot1180211AuthEntry.dot11PassPhrase, (char *)buf1);

		apmib_get(MIB_WLAN_WPA_GROUP_REKEY_TIME, (void *)&intVal);
		pmib->dot1180211AuthEntry.dot11GKRekeyTime = intVal;
	} else
		pmib->dot1180211AuthEntry.dot11EnablePSK = 0;

# ifdef CONFIG_RTL_P2P_SUPPORT
	if (mode == P2P_SUPPORT_MODE) {
		apmib_get(MIB_WLAN_WPA_GROUP_REKEY_TIME, (void *)&intVal);
		pmib->dot1180211AuthEntry.dot11GKRekeyTime = intVal;
	}
# endif

# if 1
	if (intVal3 != 0 && encrypt >= 2
#  ifdef CONFIG_RTL_WAPI_SUPPORT
	    && encrypt < 7
#  endif
	    )
# else
	if (mode != 1 && intVal3 != 0 && encrypt >= 2
#  ifdef CONFIG_RTL_WAPI_SUPPORT
	    && encrypt < 7
#  endif
	    )
# endif
	{
		if (encrypt == 2 || encrypt == 6) {
			apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&intVal2);
			if (intVal2 == 1)
				intVal = 2;
			else if (intVal2 == 2)
				intVal = 8;
			else if (intVal2 == 3)
				intVal = 10;
			else {
				_DEBUG(L_ERR, "invalid WPA_CIPHER_SUITE value(%d)", intVal2);
				return -1;
			}
			pmib->dot1180211AuthEntry.dot11WPACipher = intVal;
		}
# ifdef WLAN_WPA3
		if (encrypt == 8 || encrypt == 10) {
			pmib->dot1180211AuthEntry.dot11WPACipher = 0;
		}
# endif

		if (encrypt == 4 || encrypt == 6) {
			apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&intVal2);
			if (intVal2 == 1)
				intVal = 2;
			else if (intVal2 == 2)
				intVal = 8;
			else if (intVal2 == 3)
				intVal = 10;
			else {
				_DEBUG(L_ERR, "invalid WPA2_CIPHER_SUITE value(%d)", intVal2);
				return -1;
			}
			pmib->dot1180211AuthEntry.dot11WPA2Cipher = intVal;
		}
#if 0 /* APACRTL-93 */
		if (encrypt == 6) {
			pmib->dot1180211AuthEntry.dot11WPACipher = 10;
			pmib->dot1180211AuthEntry.dot11WPA2Cipher = 10;
		}
#endif
# ifdef WLAN_WPA3
		if (encrypt == 8 || encrypt == 10) {
			pmib->dot1180211AuthEntry.dot11WPA2Cipher = 8;
		}
# endif
	}
#endif	// 1
#ifdef RTK_MULTI_AP
	apmib_get(MIB_WLAN_MAP_BSS_TYPE, (void *)&intVal);
	pmib->multi_ap.multiap_bss_type = (unsigned char)intVal;
#endif

#ifdef CONFIG_APP_SIMPLE_CONFIG
	apmib_get(MIB_WLAN_MODE, (void *)&intVal);
	if (intVal != CLIENT_MODE)
		pmib->dot11StationConfigEntry.sc_enabled = 0;
	apmib_get(MIB_SC_DEVICE_TYPE, (void *)&intVal);
	pmib->dot11StationConfigEntry.sc_device_type = intVal;
	apmib_get(MIB_SC_DEVICE_NAME, (void *)buf1);
	strcpy((char *)pmib->dot11StationConfigEntry.sc_device_name, (char *)buf1);
	apmib_get(MIB_HW_WSC_PIN, (void *)buf1);
	strcpy((char *)pmib->dot11StationConfigEntry.sc_pin, (char *)buf1);
	//apmib_get(MIB_HW_SC_DEFAULT_PIN, (void *)buf1);
	strcpy((char *)pmib->dot11StationConfigEntry.sc_default_pin, sc_default_pin);
	apmib_get(MIB_WLAN_SC_PASSWD, (void *)buf1);
	strcpy((char *)pmib->dot11StationConfigEntry.sc_passwd, (char *)buf1);
	apmib_get(MIB_WLAN_SC_SYNC_PROFILE, (void *)&intVal);
# ifdef SYNC_VXD_PROFILE
	intVal = 1;
# endif
	pmib->dot11StationConfigEntry.sc_sync_vxd_to_root = intVal;
	apmib_get(MIB_WLAN_SC_PIN_ENABLED, (void *)&intVal);
	pmib->dot11StationConfigEntry.sc_pin_enabled = intVal;
#endif

	apmib_get(MIB_WLAN_COUNTRY_STRING, (void *)&buf1);
	if (buf1[0] != '\0')
		memcpy(pmib->dot11dCountry.dot11CountryString, buf1, 3);
#ifdef __DAVO__
	if (pmib->dot11RFEntry.phyBandSelect == PHYBAND_5G) {
		if ((pstr = nvram_get("x_dfs_enable"))) {
			if (atoi(pstr) == 0)
				pmib->dot11DFSEntry.disable_DFS = 1;
			else
				pmib->dot11DFSEntry.disable_DFS = 0;
		}
	}
#endif

#ifdef CONFIG_RTL_COMAPI_CFGFILE
	dumpCfgFile(ifname, pmib, vwlan_idx);
#else
	pwrq->u.data.pointer = (caddr_t)pmib;
	pwrq->u.data.length = sizeof(struct wifi_mib);
	if (ioctl(skfd, 0x8B43, pwrq) < 0) {
		_DEBUG(L_ERR, "failed to set WLAN MIB");
		return -1;
	}
#endif
	return 0;
}

static int initWlan(const char *ifname)
{
	struct wifi_mib *pmib = NULL;
	int skfd, res = -1;
	struct iwreq wrq;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd < 0)
		return -1;

	ystrncpy(wrq.ifr_name, ifname, IFNAMSIZ);
	if (!ioctl(skfd, SIOCGIWNAME, &wrq)) {
		pmib = (struct wifi_mib *)Malloc(sizeof(struct wifi_mib));
		if (apmib_init())
			res = _initWlan(ifname, skfd, pmib, &wrq);
		else
			_DEBUG(L_ERR, "apmib_init failed");
	} else
		_DEBUG(L_ERR, "%s: %s", ifname, strerror(errno));

	free(pmib);
	close(skfd);

	return res;
}

#ifdef WIFI_SIMPLE_CONFIG
enum {
	MODE_AP_UNCONFIG = 1,	// AP unconfigured (enrollee)
	MODE_CLIENT_UNCONFIG = 2,	// client unconfigured (enrollee)
	MODE_CLIENT_CONFIG = 3,	// client configured (registrar)
	MODE_AP_PROXY = 4,	// AP configured (proxy)
	MODE_AP_PROXY_REGISTRAR = 5,	// AP configured (proxy and registrar)
	MODE_CLIENT_UNCONFIG_REGISTRAR = 6,	// client unconfigured (registrar)
	MODE_P2P_DEVICE = 7	//  P2P_SUPPORT  for p2p_device mode
};

static int compute_pin_checksum(unsigned long int PIN)
{
	unsigned long int accum = 0;
	int digit;

	PIN *= 10;
	accum += 3 * ((PIN / 10000000) % 10);
	accum += 1 * ((PIN / 1000000) % 10);
	accum += 3 * ((PIN / 100000) % 10);
	accum += 1 * ((PIN / 10000) % 10);
	accum += 3 * ((PIN / 1000) % 10);
	accum += 1 * ((PIN / 100) % 10);
	accum += 3 * ((PIN / 10) % 10);

	digit = (accum % 10);
	return (10 - digit) % 10;
}

static int updateWscConf(char *in, char *out, int genpin, char *wlanif_name)
{
	int fh, rc = -1;
	FILE *f;
	struct cbuffer cb;
	struct stat status;
	char *p;
	int intVal;
	//int intVal2;
	int wlan0_mode = 0;
	int wlan1_mode = 0;
	int is_config, is_registrar, is_wep = 0, wep_key_type = 0, wep_transmit_key = 0;
	char tmp1[256];

	//int is_repeater_enabled=0;
	int isUpnpEnabled = 0, wsc_method = 0, wsc_auth = 0, wsc_enc = 0;
	int wlan_network_type = 0, wsc_manual_enabled = 0, wlan_wep = 0;
	u_char wlan_wep64_key1[32], wlan_wep64_key2[32], wlan_wep64_key3[32], wlan_wep64_key4[32];
	u_char wlan_wep128_key1[48], wlan_wep128_key2[48], wlan_wep128_key3[48], wlan_wep128_key4[48];
	char wlan_wpa_psk[80];
	char wlan_ssid[40], device_name[40], wsc_pin[16];
	u_char mac[6];
	int wlan_chan_num = 0, wsc_config_by_ext_reg = 0;

	P2P_DEBUG("\n\n       wlanif_name=[%s]  \n\n\n", wlanif_name);
	// 1104
	int wlan0_wlan_disabled = 0;
	int wlan1_wlan_disabled = 0;
	int wlan0_wsc_disabled = 0;
# ifdef FOR_DUAL_BAND
	int wlan1_wsc_disabled = 0;
# endif
	/* for detail mixed mode info */
# define WSC_WPA_TKIP		1
# define WSC_WPA_AES		2
# define WSC_WPA2_TKIP		4
# define WSC_WPA2_AES		8

	int wlan0_encrypt = 0;
	int wlan0_wpa_cipher = 0;
	int wlan0_wpa2_cipher = 0;

	int wlan1_encrypt = 0;
	int wlan1_wpa_cipher = 0;
	int wlan1_wpa2_cipher = 0;
	/* for detail mixed mode info */
	int band_select_5g2g;	// 0:2.4g  ; 1:5G   ; 2:both
	char *token = NULL, *token1 = NULL, *savestr1 = NULL;
#if defined(WIFI_SIMPLE_CONFIG) && defined(CONFIG_APP_TR069)
	int auto_lockdown = 0, auto_lockdown1 = 0, auto_lockdown2 = 0;
	extRegInfoT extReg;
	int entryNum = 0, entryNum1 = 0, ii = 0, entryNum2 = 0;
#endif

	if (!apmib_init())
		return -1;

	if (wlanif_name) {
		token = strtok_r(wlanif_name, " ", &savestr1);
		if (token)
			token1 = strtok_r(NULL, " ", &savestr1);
	} else
		token = "wlan0";

	SetWlan_idx(token);
	apmib_get(MIB_HW_WSC_PIN, (void *)wsc_pin);
	apmib_get(MIB_WLAN_WSC_MANUAL_ENABLED, (void *)&wsc_manual_enabled);
	apmib_get(MIB_DEVICE_NAME, (void *)&device_name);
	apmib_get(MIB_WLAN_BAND2G5G_SELECT, (void *)&band_select_5g2g);
	apmib_get(MIB_WLAN_NETWORK_TYPE, (void *)&wlan_network_type);
	apmib_get(MIB_WLAN_WSC_REGISTRAR_ENABLED, (void *)&is_registrar);
	apmib_get(MIB_WLAN_WSC_METHOD, (void *)&wsc_method);
	apmib_get(MIB_WLAN_WSC_UPNP_ENABLED, (void *)&isUpnpEnabled);
	apmib_get(MIB_WLAN_WSC_CONFIGURED, (void *)&is_config);
	apmib_get(MIB_WLAN_WSC_CONFIGBYEXTREG, (void *)&wsc_config_by_ext_reg);
	apmib_get(MIB_WLAN_MODE, (void *)&wlan0_mode);

	if (genpin || !memcmp(wsc_pin, "\x0\x0\x0\x0\x0\x0\x0\x0", PIN_LEN)) {
		struct timeval tod;
		unsigned long num;

		memcpy(tmp1, wsc_pin, sizeof(wsc_pin));
		gettimeofday(&tod, NULL);
		apmib_get(MIB_HW_NIC0_ADDR, (void *)mac);
		tod.tv_sec += mac[4] + mac[5];
		srand(tod.tv_sec);
		num = rand() % 10000000;
		num = num * 10 + compute_pin_checksum(num);
		// 8 digits with zero padded
		memmove(wsc_pin, &wsc_pin[2], sprintf(wsc_pin, "%010lu", num) - 2 + 1);
		//convert_hex_to_ascii((unsigned long)num, wsc_pin);
		if (strcmp(tmp1, wsc_pin)) {
			apmib_set(MIB_HW_WSC_PIN, (void *)wsc_pin);
# ifdef FOR_DUAL_BAND		// 2010-10-20
			wlan_idx = 1;
			apmib_set(MIB_HW_WSC_PIN, (void *)wsc_pin);
			wlan_idx = 0;
# endif
			//apmib_update(CURRENT_SETTING);
			apmib_update(HW_SETTING);
		}
		_DEBUG(L_DBG, "Generated PIN = %s", wsc_pin);
		if (genpin)
			return 0;
	}

	if (stat(in, &status) < 0) {
		_DEBUG(L_ERR, "%s: %s", in, strerror(errno));
		return -1;
	}

	cb.size = status.st_size + 2048;
	cb.count = 0;
	cb.buf = (char *)Malloc(cb.size);

	if (wlan0_mode == CLIENT_MODE) {
		if (is_registrar) {
			if (!is_config)
				intVal = MODE_CLIENT_UNCONFIG_REGISTRAR;
			else
				intVal = MODE_CLIENT_CONFIG;
		} else
			intVal = MODE_CLIENT_UNCONFIG;
	} else {
		if (!is_config)
			intVal = MODE_AP_UNCONFIG;
		else
			intVal = MODE_AP_PROXY_REGISTRAR;
	}

# ifdef CONFIG_RTL_P2P_SUPPORT
	/*for *CONFIG_RTL_P2P_SUPPORT */
	if (wlan0_mode == P2P_SUPPORT_MODE) {
		int intVal2;
		apmib_get(MIB_WLAN_P2P_TYPE, (void *)&intVal2);
		if (intVal2 == P2P_DEVICE) {
			cbprintf(&cb, "p2pmode = %d\n", intVal2);
			intVal = MODE_CLIENT_UNCONFIG;
		}
	}
# endif

	cbprintf(&cb, "mode = %d\n", intVal);

	if (wlan0_mode == CLIENT_MODE) {
# ifdef CONFIG_RTL8186_KLD_REPEATER
		if (wps_vxdAP_enabled)
			apmib_get(MIB_WSC_UPNP_ENABLED, (void *)&intVal);
		else
# endif
			intVal = 0;
	}
# ifdef CONFIG_RTL_P2P_SUPPORT
	else if (wlan0_mode == P2P_SUPPORT_MODE) {
		/* when the board has two interfaces, system will issue two wscd then should consider upnp conflict 20130927 */
		intVal = 0;
	}
# endif
	else {
		intVal = isUpnpEnabled;
	}

	cbprintf(&cb, "upnp = %d\n", intVal);

	intVal = wsc_method;
# ifdef CONFIG_RTL_P2P_SUPPORT
	if (wlan0_mode == P2P_SUPPORT_MODE)
		intVal = (CONFIG_METHOD_PIN | CONFIG_METHOD_PBC | CONFIG_METHOD_DISPLAY | CONFIG_METHOD_KEYPAD);
	else
# endif
	{
#if 0
		//Ethernet(0x2)+Label(0x4)+PushButton(0x80) Bitwise OR
		if (intVal == 1)	//Pin+Ethernet
			intVal = (CONFIG_METHOD_ETH | CONFIG_METHOD_PIN);
		else if (intVal == 2)	//PBC+Ethernet
			intVal = (CONFIG_METHOD_ETH | CONFIG_METHOD_PBC);
		if (intVal == 3)	//Pin+PBC+Ethernet
			intVal = (CONFIG_METHOD_ETH | CONFIG_METHOD_PIN | CONFIG_METHOD_PBC);
#else
		intVal = CONFIG_METHOD_PBC;
#endif
	}
	cbprintf(&cb, "config_method = %d\n", intVal);

	if (wlan0_mode == CLIENT_MODE) {
		if (wlan_network_type == 0)
			intVal = 1;
		else
			intVal = 2;
	} else
		intVal = 1;

	cbprintf(&cb, "connection_type = %d\n", intVal);

	cbprintf(&cb, "manual_config = %d\n", wsc_manual_enabled);

	cbprintf(&cb, "pin_code = %s\n", wsc_pin);

	if (token && strstr(token, "wlan0"))
		SetWlan_idx(token);
	else if (token1 && strstr(token1, "wlan0"))
		SetWlan_idx(token1);
	else
		SetWlan_idx("wlan0");

	apmib_get(MIB_WLAN_CHANNEL, (void *)&wlan_chan_num);
	if (wlan_chan_num > 14)
		intVal = 2;
	else
		intVal = 1;
	cbprintf(&cb, "rf_band = %d\n", intVal);

	apmib_get(MIB_WLAN_WSC_AUTH, (void *)&wsc_auth);
	apmib_get(MIB_WLAN_WSC_ENC, (void *)&wsc_enc);
	apmib_get(MIB_WLAN_SSID, (void *)&wlan_ssid);
	apmib_get(MIB_WLAN_MODE, (void *)&wlan0_mode);
	apmib_get(MIB_WLAN_WEP, (void *)&wlan_wep);
	apmib_get(MIB_WLAN_WEP_KEY_TYPE, (void *)&wep_key_type);
	apmib_get(MIB_WLAN_WEP_DEFAULT_KEY, (void *)&wep_transmit_key);
	apmib_get(MIB_WLAN_WEP64_KEY1, (void *)&wlan_wep64_key1);
	apmib_get(MIB_WLAN_WEP64_KEY2, (void *)&wlan_wep64_key2);
	apmib_get(MIB_WLAN_WEP64_KEY3, (void *)&wlan_wep64_key3);
	apmib_get(MIB_WLAN_WEP64_KEY4, (void *)&wlan_wep64_key4);
	apmib_get(MIB_WLAN_WEP128_KEY1, (void *)&wlan_wep128_key1);
	apmib_get(MIB_WLAN_WEP128_KEY2, (void *)&wlan_wep128_key2);
	apmib_get(MIB_WLAN_WEP128_KEY3, (void *)&wlan_wep128_key3);
	apmib_get(MIB_WLAN_WEP128_KEY4, (void *)&wlan_wep128_key4);
	apmib_get(MIB_WLAN_WPA_PSK, (void *)&wlan_wpa_psk);
	apmib_get(MIB_WLAN_WSC_DISABLE, (void *)&wlan0_wsc_disabled);	// 1104
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan0_wlan_disabled);	// 0908
#if defined(WIFI_SIMPLE_CONFIG) && defined(CONFIG_APP_TR069)
	apmib_get(MIB_WLAN_WSC_AUTO_LOCK_DOWN, (void *)&auto_lockdown1);
	apmib_get(MIB_WLAN_WSC_ER_NUM, (void *)&entryNum1);
#endif

	/* for detail mixed mode info */
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&wlan0_encrypt);
	apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wlan0_wpa_cipher);
	apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wlan0_wpa2_cipher);
	/* for detail mixed mode info */

	/* if wlanif_name doesn't include "wlan0", disable wlan0 wsc */
	if ((token == NULL || strstr(token, "wlan0") == 0) &&
	    (token1 == NULL || strstr(token1, "wlan0") == 0)) {
		wlan0_wsc_disabled = 1;
	}

	/* for dual band */
	if (wlan0_wlan_disabled) {
		wlan0_wsc_disabled = 1;	// if wlan0 interface is disabled ;
	}
	/* for dual band */

	cbprintf(&cb,
		"###############################################################\n"
		"# %s\n"
		"###############################################################\n", "wlan0");
	// 1104
	cbprintf(&cb, "wlan0_wsc_disabled = %d\n", wlan0_wsc_disabled);

	cbprintf(&cb, "auth_type = %d\n", wsc_auth);

	cbprintf(&cb, "encrypt_type = %d\n", wsc_enc);

	/* for detail mixed mode info */
	intVal = 0;
	if (wlan0_encrypt == 6) {	// mixed mode
		if (wlan0_wpa_cipher == 1) {
			intVal |= WSC_WPA_TKIP;
		} else if (wlan0_wpa_cipher == 2) {
			intVal |= WSC_WPA_AES;
		} else if (wlan0_wpa_cipher == 3) {
			intVal |= (WSC_WPA_TKIP | WSC_WPA_AES);
		}
		if (wlan0_wpa2_cipher == 1) {
			intVal |= WSC_WPA2_TKIP;
		} else if (wlan0_wpa2_cipher == 2) {
			intVal |= WSC_WPA2_AES;
		} else if (wlan0_wpa2_cipher == 3) {
			intVal |= (WSC_WPA2_TKIP | WSC_WPA2_AES);
		}
	}
	cbprintf(&cb, "mixedmode = %d\n", intVal);

	/* for detail mixed mode info */
	if (wsc_enc == WSC_ENCRYPT_WEP)
		is_wep = 1;

	if (is_wep) {		// only allow WEP in none-MANUAL mode (configured by external registrar)
		if (wlan0_encrypt != ENCRYPT_WEP) {
			_DEBUG(L_ERR, "WEP mismatched between WPS & host system");
			goto step_out;
		}
		if (wlan_wep <= WEP_DISABLED || wlan_wep > WEP128) {
			_DEBUG(L_ERR, "WEP encrypt length error");
			goto step_out;
		}

		wep_transmit_key++;
		cbprintf(&cb, "wep_transmit_key = %d\n", wep_transmit_key);

		/*whatever key type is ASSIC or HEX always use String-By-Hex fromat
		   ;2011-0419,fixed,need patch with wscd daemon , search 2011-0419 */
		if (wlan_wep == WEP64) {
			cbprintf(&cb, "network_key = %s\n", yitoxa(tmp1, wlan_wep64_key1, 5));
			cbprintf(&cb, "wep_key2 = %s\n", yitoxa(tmp1, wlan_wep64_key2, 5));
			cbprintf(&cb, "wep_key3 = %s\n", yitoxa(tmp1, wlan_wep64_key3, 5));
			cbprintf(&cb, "wep_key4 = %s\n", yitoxa(tmp1, wlan_wep64_key4, 5));
		} else {
			cbprintf(&cb, "network_key = %s\n", yitoxa(tmp1, wlan_wep128_key1, 13));
			cbprintf(&cb, "wep_key2 = %s\n", yitoxa(tmp1, wlan_wep128_key2, 13));
			cbprintf(&cb, "wep_key3 = %s\n", yitoxa(tmp1, wlan_wep128_key3, 13));
			cbprintf(&cb, "wep_key4 = %s\n", yitoxa(tmp1, wlan_wep128_key4, 13));
		}
	} else
		cbprintf(&cb, "network_key = \"%s\"\n", wlan_wpa_psk);

	cbprintf(&cb, "ssid = \"%s\"\n", wlan_ssid);

	cbprintf(&cb, "\n");

# ifdef FOR_DUAL_BAND
	/* switch to wlan1 */
	if (token && strstr(token, "wlan1"))
		SetWlan_idx(token);
	else if (token1 && strstr(token1, "wlan1"))
		SetWlan_idx(token1);
	else
		SetWlan_idx("wlan1");

	apmib_get(MIB_WLAN_WSC_AUTH, (void *)&wsc_auth);
	apmib_get(MIB_WLAN_WSC_ENC, (void *)&wsc_enc);
	apmib_get(MIB_WLAN_SSID, (void *)&wlan_ssid);
	apmib_get(MIB_WLAN_MODE, (void *)&wlan1_mode);
	apmib_get(MIB_WLAN_WEP, (void *)&wlan_wep);
	apmib_get(MIB_WLAN_WEP_KEY_TYPE, (void *)&wep_key_type);
	apmib_get(MIB_WLAN_WEP_DEFAULT_KEY, (void *)&wep_transmit_key);
	apmib_get(MIB_WLAN_WEP64_KEY1, (void *)&wlan_wep64_key1);
	apmib_get(MIB_WLAN_WEP64_KEY2, (void *)&wlan_wep64_key2);
	apmib_get(MIB_WLAN_WEP64_KEY3, (void *)&wlan_wep64_key3);
	apmib_get(MIB_WLAN_WEP64_KEY4, (void *)&wlan_wep64_key4);
	apmib_get(MIB_WLAN_WEP128_KEY1, (void *)&wlan_wep128_key1);
	apmib_get(MIB_WLAN_WEP128_KEY2, (void *)&wlan_wep128_key2);
	apmib_get(MIB_WLAN_WEP128_KEY3, (void *)&wlan_wep128_key3);
	apmib_get(MIB_WLAN_WEP128_KEY4, (void *)&wlan_wep128_key4);
	apmib_get(MIB_WLAN_WPA_PSK, (void *)&wlan_wpa_psk);
	apmib_get(MIB_WLAN_WSC_DISABLE, (void *)&wlan1_wsc_disabled);	// 1104
	apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&wlan1_wlan_disabled);	// 0908
#if defined(WIFI_SIMPLE_CONFIG) && defined(CONFIG_APP_TR069)
	apmib_get(MIB_WLAN_WSC_AUTO_LOCK_DOWN, (void *)&auto_lockdown2);
	apmib_get(MIB_WLAN_WSC_ER_NUM, (void *)&entryNum2);
#endif

	/* for detail mixed mode info */
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&wlan1_encrypt);
	apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wlan1_wpa_cipher);
	apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wlan1_wpa2_cipher);
	/* for detail mixed mode info */

	/*if  wlanif_name doesn't include "wlan1", disable wlan1 wsc */
	if ((token == NULL || strstr(token, "wlan1") == 0) &&
	    (token1 == NULL || strstr(token1, "wlan1") == 0)) {
		wlan1_wsc_disabled = 1;
	}

	/* for dual band */
	if (wlan1_wlan_disabled) {
		wlan1_wsc_disabled = 1;	// if wlan1 interface is disabled
	}
	/* for dual band */

	cbprintf(&cb,
		"###############################################################\n"
		"# %s\n"
		"###############################################################\n", "wlan1");
	cbprintf(&cb, "ssid2 = \"%s\"\n", wlan_ssid);
	cbprintf(&cb, "auth_type2 = %d\n", wsc_auth);
	cbprintf(&cb, "encrypt_type2 = %d\n", wsc_enc);

	/* for detail mixed mode info */
	intVal = 0;
	if (wlan1_encrypt == 6) {	// mixed mode
		if (wlan1_wpa_cipher == 1) {
			intVal |= WSC_WPA_TKIP;
		} else if (wlan1_wpa_cipher == 2) {
			intVal |= WSC_WPA_AES;
		} else if (wlan1_wpa_cipher == 3) {
			intVal |= (WSC_WPA_TKIP | WSC_WPA_AES);
		}
		if (wlan1_wpa2_cipher == 1) {
			intVal |= WSC_WPA2_TKIP;
		} else if (wlan1_wpa2_cipher == 2) {
			intVal |= WSC_WPA2_AES;
		} else if (wlan1_wpa2_cipher == 3) {
			intVal |= (WSC_WPA2_TKIP | WSC_WPA2_AES);
		}
	}
	cbprintf(&cb, "mixedmode2 = %d\n", intVal);

	/* for detail mixed mode info */
	if (band_select_5g2g != 2) {	//  != dual band
		intVal = 1;
		cbprintf(&cb, "wlan1_wsc_disabled = %d\n", intVal);
	} else			// else see if wlan1 is enabled
		cbprintf(&cb, "wlan1_wsc_disabled = %d\n", wlan1_wsc_disabled);

	is_wep = 0;
	if (wsc_enc == WSC_ENCRYPT_WEP)
		is_wep = 1;

	if (is_wep) {		// only allow WEP in none-MANUAL mode (configured by external registrar)
		if (wlan1_encrypt != ENCRYPT_WEP) {
			_DEBUG(L_ERR, "WEP mismatched between WPS & host system");
			goto step_out;
		}
		if (wlan_wep <= WEP_DISABLED || wlan_wep > WEP128) {
			_DEBUG(L_ERR, "WEP encrypt length error");
			goto step_out;
		}

		wep_transmit_key++;
		cbprintf(&cb, "wep_transmit_key2 = %d\n", wep_transmit_key);

		/* whatever key type is ASCII or HEX always use String-By-Hex fromat
		   ;2011-0419,fixed,need patch with wscd daemon , search 2011-0419 */
		if (wlan_wep == WEP64) {
			cbprintf(&cb, "network_key2 = %s\n", yitoxa(tmp1, wlan_wep64_key1, 5));
			cbprintf(&cb, "wep_key22 = %s\n", yitoxa(tmp1, wlan_wep64_key2, 5));
			cbprintf(&cb, "wep_key32 = %s\n", yitoxa(tmp1, wlan_wep64_key3, 5));
			cbprintf(&cb, "wep_key42 = %s\n", yitoxa(tmp1, wlan_wep64_key4, 5));
		} else {
			cbprintf(&cb, "network_key2 = %s\n", yitoxa(tmp1, wlan_wep128_key1, 13));
			cbprintf(&cb, "wep_key22 = %s\n", yitoxa(tmp1, wlan_wep128_key2, 13));
			cbprintf(&cb, "wep_key32 = %s\n", yitoxa(tmp1, wlan_wep128_key3, 13));
			cbprintf(&cb, "wep_key42 = %s\n", yitoxa(tmp1, wlan_wep128_key4, 13));
		}
	} else
		cbprintf(&cb, "network_key2 = \"%s\"\n", wlan_wpa_psk);

	cbprintf(&cb, "\n");

	/*sync the PIN code of wlan0 and wlan1 */
	apmib_set(MIB_HW_WSC_PIN, (void *)wsc_pin);

	/* switch back to wlan0 */
	wlan_idx = 0;
	vwlan_idx = 0;
# endif	// FOR_DUAL_BAND
# if defined(WIFI_SIMPLE_CONFIG) && defined(CONFIG_APP_TR069)
	/* auto lock down state */
	if (auto_lockdown1 || auto_lockdown2)
		auto_lockdown = 1;
	else
		auto_lockdown = 0;
	cbprintf(&cb, "auto_lockdown = %d\n", auto_lockdown);

	/* external registrar information
	  take example for wlan0 (wlan1 is the same as wlan0 )
	 */
	if (entryNum1 || entryNum2) {
		entryNum = entryNum1;
	}
	cbprintf(&cb, "external_reg_num = %d\n", entryNum);
	if (entryNum) {
		for (ii = 1; ii <= entryNum; ii++) {
			memset(&extReg, 0x00, sizeof(extReg));
			*((char *)&extReg) = (char)ii;
			if (apmib_get(MIB_WLAN_WSC_ER_TBL, (void *)&extReg)) {
				cbprintf(&cb, "ER_disable%d = %d\n", ii, extReg.disable);
				cbprintf(&cb, "ER_uuid%d= %s\n", ii, extReg.uuid);
				cbprintf(&cb, "ER_devname%d = %s\n", ii, extReg.devicename);
			}
		}
	}
# endif
	cbprintf(&cb, "device_name = \"%s\"\n", device_name);
	cbprintf(&cb, "config_by_ext_reg = %d\n", wsc_config_by_ext_reg);

	f = fopen(in, "r");
	if (f) {
		while (fgets(tmp1, sizeof(tmp1), f)) {
			ydespaces(tmp1);
			if (tmp1[0] == '#')
				continue;
			if (!strncmp(tmp1, "uuid =", sizeof("uuid =") - 1)) {
				p = ydespaces(&tmp1[sizeof("uuid =") - 1]);
				apmib_get(MIB_WLAN_WLAN_MAC_ADDR, (void *)mac);
				if (!memcmp(mac, "\x00\x00\x00\x00\x00\x00", 6))
					apmib_get(MIB_HW_NIC0_ADDR, (void *)mac);
				yitoxa(&p[20], mac, 6);
				cbprintf(&cb, "uuid = %s\n", p);
			} else
				cbprintf(&cb, "%s\n", tmp1);
		}
		fclose(f);

		fh = open(out, O_RDWR | O_CREAT | O_TRUNC);
		if (fh > -1) {
			rc = (write(fh, cb.buf, cb.count) == cb.count) ? 0 : -1;
			close(fh);
		}
	}

step_out:
	free(cb.buf);
	return rc;
}
#endif

static const char *getrootname(const char *name, int *wlroot, int *wlvap)
{
	const char *p;
	char *q;

	if (name == NULL)
		return NULL;

	if (!strncmp(name, "HW_WLAN", sizeof("HW_WLAN") - 1)) {
		p = &name[sizeof("HW_WLAN") - 1];
		*wlroot = strtol(p, &q, 10);
		if (p != q && *q++ == '_')
			return q;
	} else if (!strncmp(name, "HW_", sizeof("HW_") - 1))
		return &name[sizeof("HW_") - 1];
	else if (!strncmp(name, "WLAN", sizeof("WLAN") - 1)) {
		p = &name[sizeof("WLAN") - 1];
		*wlroot = strtol(p, &q, 10);
		if (p != q && *q++ == '_') {
#ifdef MBSSID
			if (!strncmp(q, "VAP", sizeof("VAP") - 1)) {
				p = &q[sizeof("VAP") - 1];
				*wlvap = strtol(p, &q, 10) + 1;
				if (*wlvap > 0 && p != q && *q++ == '_')
					return q;
			}
# ifdef UNIVERSAL_REPEATER
			else if (!strncmp(q, "VXD_", sizeof("VXD_") - 1)) {
				*wlvap = NUM_VWLAN_INTERFACE;
				return &q[sizeof("VXD_") - 1];
			}
# endif
			else
#endif
				return q;
		}
	}

	return name;
}

#define SHIFT_ARGV() \
do { \
	if (--argc <= 0) return -1; \
	argv++; \
} while (0)

static void input_default_mac(char *val)
{
	unsigned char ea[6];

	yxatoi(ea, val, 6 << 1);
	ea[5] -= 2; // Base MAC
	ynvram_put("HW_NIC0_ADDR=%02x%02x%02x%02x%02x%02x",
		   ea[0], ea[1], ea[2], ea[3], ea[4], ea[5]);
	nvram_commit();
}

void set_timeZone(void)
{
	unsigned int daylight_save = 1;
	//char daylight_save_str[5];
	char time_zone[8];
	char str_datnight[100];
	char str_tz1[32];

	apmib_get(MIB_DAYLIGHT_SAVE, (void *)&daylight_save);
	//memset(daylight_save_str, 0x00, sizeof(daylight_save_str));
	//sprintf(daylight_save_str, "%u", daylight_save);
	apmib_get(MIB_NTP_TIMEZONE, (void *)&time_zone);

	if (daylight_save == 0)
		str_datnight[0] = '\0';
	else if (strcmp(time_zone, "9 1") == 0)
		strcpy(str_datnight, "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
	else if (strcmp(time_zone, "8 1") == 0)
		strcpy(str_datnight, "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
	else if (strcmp(time_zone, "7 2") == 0)
		strcpy(str_datnight, "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
	else if (strcmp(time_zone, "6 1") == 0)
		strcpy(str_datnight, "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
	else if (strcmp(time_zone, "6 2") == 0)
		strcpy(str_datnight, "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
	else if (strcmp(time_zone, "5 2") == 0)
		strcpy(str_datnight, "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
	else if (strcmp(time_zone, "5 3") == 0)
		strcpy(str_datnight, "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
	else if (strcmp(time_zone, "4 3") == 0)
		strcpy(str_datnight, "PDT,M10.2.0/00:00:00,M3.2.0/00:00:00");
	else if (strcmp(time_zone, "3 1") == 0)
		strcpy(str_datnight, "PDT,M4.1.0/00:00:00,M10.5.0/00:00:00");
	else if (strcmp(time_zone, "3 2") == 0)
		strcpy(str_datnight, "PDT,M2.2.0/00:00:00,M10.2.0/00:00:00");
	else if (strcmp(time_zone, "1 1") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/00:00:00,M10.5.0/01:00:00");
	else if (strcmp(time_zone, "0 2") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/01:00:00,M10.5.0/02:00:00");
	else if (strcmp(time_zone, "-1") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/02:00:00,M10.5.0/03:00:00");
	else if (strcmp(time_zone, "-2 1") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/02:00:00,M10.5.0/03:00:00");
	else if (strcmp(time_zone, "-2 2") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/03:00:00,M10.5.0/04:00:00");
	else if (strcmp(time_zone, "-2 3") == 0)
		strcpy(str_datnight, "PDT,M4.5.5/00:00:00,M9.5.5/00:00:00");
	else if (strcmp(time_zone, "-2 5") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/03:00:00,M10.5.5/04:00:00");
	else if (strcmp(time_zone, "-2 6") == 0)
		strcpy(str_datnight, "PDT,M3.5.5/02:00:00,M10.1.0/02:00:00");
	else if (strcmp(time_zone, "-3 2") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/02:00:00,M10.5.0/03:00:00");
	else if (strcmp(time_zone, "-4 2") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/04:00:00,M10.5.0/05:00:00");
	else if (strcmp(time_zone, "-9 4") == 0)
		strcpy(str_datnight, "PDT,M10.5.0/02:00:00,M4.1.0/03:00:00");
	else if (strcmp(time_zone, "-10 2") == 0)
		strcpy(str_datnight, "PDT,M10.5.0/02:00:00,M4.1.0/03:00:00");
	else if (strcmp(time_zone, "-10 4") == 0)
		strcpy(str_datnight, "PDT,M10.1.0/02:00:00,M4.1.0/03:00:00");
	else if (strcmp(time_zone, "-10 5") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/02:00:00,M10.5.0/03:00:00");
	else if (strcmp(time_zone, "-12 1") == 0)
		strcpy(str_datnight, "PDT,M3.2.0/03:00:00,M10.1.0/02:00:00");
	else
		str_datnight[0] = '\0';

	//str_tz1 = gettoken((unsigned char *)time_zone, 0, ' ');
	sscanf(time_zone, "%s", str_tz1);
	if (strcmp(time_zone, "3 1") == 0 ||
	    strcmp(time_zone, "-3 4") == 0 ||
	    strcmp(time_zone, "-4 3") == 0 ||
	    strcmp(time_zone, "-5 3") == 0 ||
	    strcmp(time_zone, "-9 4") == 0 ||
	    strcmp(time_zone, "-9 5") == 0)
		yecho("/var/TZ", "GMT%s:30%s\n", str_tz1, str_datnight);
	else
		yecho("/var/TZ", "GMT%s%s\n", str_tz1, str_datnight);
}

static int inline
mib_name_cmpr(char *dst, size_t n, const struct mib *mib, const char *fullname)
{
	return strcmp(ynvram_name(dst, n, mib->name, mib->section), fullname);
}

int main(int argc, char **argv)
{
	const struct mib *mib, *nib;
	const char *fullname;
	char buf[sizeof(((mib_table_entry_T *)0)->name) << 1];
	char **argvp, *p;
	int i, num, rc;
	u_char mac[6];

	for (i = 0; i < (argc - 1); i++)
		_PDEBUG("%s ", argv[i]);
	_PDEBUG("%s\n", argv[i]);

	SHIFT_ARGV();

	if (!strcmp(*argv, "get") || !strcmp(*argv, "gethw")) {
		SHIFT_ARGV();
		rc = if_nametowlindex(*argv, &wlan_idx, &vwlan_idx);
		if (rc != eWLIF_NONE) {
			SHIFT_ARGV();
			if (rc == eWLIF_BAD || validate_wlindex(wlan_idx, vwlan_idx))
				return -1;
		}

		if (getrootname((fullname = *argv), &wlan_idx, &vwlan_idx) == NULL ||
		    validate_wlindex(wlan_idx, vwlan_idx))
			return -1;
		argc--;
		argvp = ++argv;

		for (mib = ymib_first(); mib && mib_name_cmpr(buf, sizeof(buf), mib, fullname); )
			mib = ymib_next(mib);

		if (mib == NULL)
			return -1;

		if (mib->type > TABLE_LIST_T) {
			nib = ysearch_mib_struct((mib->id & MIB_ID_MASK) - 1);
			if (!nib)
				return -1;
			ynvram_name(buf, sizeof(buf), nib->name, nib->section);
			num = strtol(nvram_safe_get(buf), NULL, 0);
			//printf("%s=%d\n", buf, num);
			if (num > 0)
				ynvram_name(buf, sizeof(buf), mib->name, mib->section);
			for (i = 0; i < num; i++) {
				p = ynvram_get("%s%d", buf, i + 1);
				printf("%s%d=%s\n", fullname, i + 1, (p) ? : "");
			}
		} else if (mib->type < TABLE_LIST_T) {
			printf((mib->type != STRING_T) ? "%s=%s\n" : "%s=\"%s\"\n",
			       fullname, nvram_safe_get(buf));
		}
	} else if (!strcmp(*argv, "set") || !strcmp(*argv, "sethw")) {
		if ((!strcmp(argv[1], "ELAN_MAC_ADDR")) && (!strcmp(argv[2], "--sub"))) {
			input_default_mac(argv[3]);
		}
		if (setmib(argc, argv))
			return -1;
		apmib_update(CURRENT_SETTING);
		return 0;
	}
#ifdef WLAN_FAST_INIT
	else if (!strcmp(*argv, "set_mib")) {
		SHIFT_ARGV();
		rc = if_nametowlindex(*argv, &wlan_idx, &vwlan_idx);
		if (rc == eWLIF_NONE || rc == eWLIF_BAD || validate_wlindex(wlan_idx, vwlan_idx))
			return -1;
		rc = initWlan(*argv);
		vwlan_idx = 0;
		return rc;
	}
#endif
	else if (!strcmp(*argv, "settime")) {
		set_timeZone();
		return 0;
	}
#ifdef WIFI_SIMPLE_CONFIG
	else if (!strcmp(*argv, "upd-wsc-conf")) {
		if (argc > 2)
			return updateWscConf(argv[1], argv[2], 0, argv[3]);
	} else if (!strcmp(*argv, "gen-pin")) {
		sprintf(buf, "wlan%d", wlan_idx);
		return updateWscConf(0, 0, 1, buf);
	}
#endif // WIFI_SIMPLE_CONFIG
	else if (!strcmp(*argv, "probe")) {
		i = test_and_import(apmib_file_dfl(HW_DFL), 0);
		i += test_and_import(apmib_file_dfl(RUN_DFL), 0);
		i += diff_version();

		if (i > 0)
			nvram_commit();
		if (access("/etc/boot.bin", F_OK) == 0) {
			rc = yexecl("2>/dev/null", "ub /etc/boot.bin");
			if (WIFEXITED(rc) && WEXITSTATUS(rc) == 0)
				yexecl(NULL, "reboot");
		}
		return 0;
	} else if (!strcmp(*argv, "test-hwconf") ||
		   !strcmp(*argv, "test-dsconf") ||
		   !strcmp(*argv, "test-csconf") ||
		   !strcmp(*argv, "test-bluetoothhwconf") ||
		   !strcmp(*argv, "test-customerhwconf") ||
		   !strcmp(*argv, "test-alignment")) {
#ifdef BLUETOOTH_HW_SETTING_SUPPORT
# error BLUETOOTH_HW_SETTING_SUPPORT must be implemented!
#endif
#ifdef CUSTOMER_HW_SETTING_SUPPORT
# error CUSTOMER_HW_SETTING_SUPPORT must be implemented!
#endif
		/* Not implemented anymore */
		return 0;
	} else if (!strcmp(*argv, "wpa")) {
		int isWds = 0;
		SHIFT_ARGV();
/* flash wap iface_name outoutfile [wds] */
		if (argc > 1) {
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
			strncpy(wlan_1x_ifname, *argv, sizeof(wlan_1x_ifname));
#endif
			rc = if_nametowlindex(*argv, &wlan_idx, &vwlan_idx);
			if (rc == eWLIF_NONE || rc == eWLIF_BAD || validate_wlindex(wlan_idx, vwlan_idx))
				return -1;
			if (((argc) > 2) && !strcmp(argv[2], "wds"))
				isWds = 1;

			return generateWpaConf(argv[1], isWds, *argv);
		}
	} else if (!strcmp(*argv, "reset")) {
		struct stat st;

		if (argc > 1 && !stat(argv[1], &st) && (st.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH)))
			yexecl(NULL, "%s", argv[1]);

		i = !nvram_set("MIB_REVISION", "1");
		i += test_and_import(apmib_file_dfl(RUN_DFL), 1);
		i += set_default_ssid();
		i += set_http_passwd();
		i += diff_version();
		/* MAC assignment policy */
		if (yxatoi(mac, nvram_safe_get("HW_NIC0_ADDR"), sizeof(mac) << 1))
			i += sethw_mac(mac, FALSE);
		if (i > 0)
			nvram_commit();
		return 0;
	} else if (!strcmp(*argv, "virtual_flash_init")) {
#ifdef AP_CONTROLER_SUPPORT
# error virtual_flash_init must be implemented!
#else
		return 0;
#endif
	} else if (!strcmp(*argv, "gen-pppoe")) {
		SHIFT_ARGV();
#if defined(MULTI_WAN_SUPPORT)
		if (argc > 3)
			return generatePPPConf(1, argv[0], argv[1], argv[2], argv[3]);
#else
		if (argc > 2)
			return generatePPPConf(1, argv[0], argv[1], argv[2]);
#endif
		else
			fprintf(stderr, "Miss arguments [option-file pap-file chap-file]!\n");
	} else if (!strcmp(*argv, "clearppp")) {
		SHIFT_ARGV();
		send_ppp_msg(atoi(argv[0]), (unsigned char *)argv[1]);
	} else
		yecho("/dev/kmsg", "flash %s ...\n", *argv);

	return -1;
}

#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
static inline int iw_get_ext(int skfd,		/* Socket to the kernel */
			     char *ifname,	/* Device name */
			     int request,	/* WE ID */
			     struct iwreq *pwrq)
{				/* Fixed part of the request */
	/* Set device name */
	strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);
	/* Do the request */
	return (ioctl(skfd, request, pwrq));
}

int getWlSiteSurveyRequest(char *interface, int *pStatus)
{
#ifndef NO_ACTION
	int skfd = 0;
	struct iwreq wrq;
	unsigned char result;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd == -1)
		return -1;

	/* Get wireless name */
	if (iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
		/* If no wireless name : no wireless extensions */
		close(skfd);
		return -1;
	}
	wrq.u.data.pointer = (caddr_t) & result;
	wrq.u.data.length = sizeof(result);

	if (iw_get_ext(skfd, interface, SIOCGIWRTLSCANREQ, &wrq) < 0) {
		//close( skfd );
		//return -1;
	}
	close(skfd);

	if (result == 0xff)
		*pStatus = -1;
	else
		*pStatus = (int)result;
#else
	*pStatus = -1;
#endif
#ifdef CONFIG_RTK_MESH
	// ==== modified by GANTOE for site survey 2008/12/26 ====
	return (int)*(char *)wrq.u.data.pointer;
#else
	return 0;
#endif
}

int getWlSiteSurveyResult(char *interface, SS_STATUS_Tp pStatus)
{
#ifndef NO_ACTION
	int skfd = 0;
	struct iwreq wrq;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd == -1)
		return -1;
	/* Get wireless name */
	if (iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
		/* If no wireless name : no wireless extensions */
		close(skfd);
		return -1;
	}
	wrq.u.data.pointer = (caddr_t) pStatus;
	if (pStatus->number == 0)
		wrq.u.data.length = sizeof(SS_STATUS_T);
	else
		wrq.u.data.length = sizeof(pStatus->number);

	if (iw_get_ext(skfd, interface, SIOCGIWRTLGETBSSDB, &wrq) < 0) {
		close(skfd);
		return -1;
	}
	close(skfd);
#else
	return -1;
#endif
	return 0;
}

int getEncryptInfoAccordingAP(int *encryption, int *unicastCipher, int *wpa2UnicastCipher)
{
	int wait_time, sts, i;
	wait_time = 0;
	unsigned char res;
	int wpa_exist = 0, idx = 0;
	char ssidBuf[64], tmp_ssidBuf[64], tmp2Buf[20];
	BssDscr *pBss = NULL;
	SS_STATUS_Tp pStatus = NULL;

	pStatus = calloc(1, sizeof(SS_STATUS_T));
	if (pStatus == NULL) {
		printf("Allocate buffer failed!\n");
		return 0;
	}
	pStatus->number = 0;

	if (getWlSiteSurveyResult(wlan_1x_ifname, pStatus) < 0 || pStatus->number == 0) {
		while (1) {
			switch (getWlSiteSurveyRequest(wlan_1x_ifname, &sts)) {
			case -2:
				printf("Auto scan running!!\n");
				break;
			case -1:
				printf("Site-survey request failed!\n");
				break;
			default:
				break;
			}
			if (sts != 0) {	// not ready
				if (wait_time++ > 15) {
					// enlarge wait time for root can't scan when vxd
					// is do site survey. wait until vxd finish scan
					printf("scan request timeout!\n");
					goto ss_err;
				}
#ifdef CONFIG_RTK_MESH
				// ==== modified by GANTOE for site survey 2008/12/26 ====
				usleep(1000000 + (rand() % 2000000));
#else
				sleep(1);
#endif
			} else
				break;
		}

		wait_time = 0;

		while (1) {
			res = 1;	// only request request status
			if (getWlSiteSurveyResult(wlan_1x_ifname, (SS_STATUS_Tp) & res) < 0) {
				printf("Read site-survey status failed!\n");
				goto ss_err;
			}
			if (res == 0xff) {	// in progress
				/*prolong wait time due to scan both 2.4G and 5G */
				if (wait_time++ > 20) {
					printf("scan timeout!\n");
					goto ss_err;
				}
				sleep(1);
			} else
				break;
		}

		pStatus->number = 0;

		if (getWlSiteSurveyResult(wlan_1x_ifname, pStatus) < 0)
			goto ss_err;
	}

	apmib_get(MIB_WLAN_SSID, (void *)ssidBuf);

	for (i = 0; i < pStatus->number && pStatus->number != 0xff; i++) {
		pBss = &pStatus->bssdb[i];
		memcpy(tmp_ssidBuf, pBss->ssid, pBss->ssidlen);
		tmp_ssidBuf[pBss->ssidlen] = '\0';
		if (strcmp(ssidBuf, tmp_ssidBuf) == 0) {
			if (pBss->t_stamp[0] & 0x0000ffff) {
				idx = sprintf(tmp2Buf, "WPA");
				if (((pBss->t_stamp[0] & 0x0000f000) >> 12) == 0x4)
					idx += sprintf(tmp2Buf + idx, "-PSK");
				else if (((pBss->t_stamp[0] & 0x0000f000) >> 12) == 0x2)
					idx += sprintf(tmp2Buf + idx, "-1X");

				wpa_exist = 1;

				if (((pBss->t_stamp[0] & 0x00000f00) >> 8) == 0x5) {
					//sprintf(wpa_tkip_aes,"%s","aes/tkip");
					*unicastCipher = 2;
					*wpa2UnicastCipher = 2;
				} else if (((pBss->t_stamp[0] & 0x00000f00) >> 8) == 0x4) {
					//sprintf(wpa_tkip_aes,"%s","aes");
					*unicastCipher = 2;
					*wpa2UnicastCipher = 2;
				} else if (((pBss->t_stamp[0] & 0x00000f00) >> 8) == 0x1) {
					//sprintf(wpa_tkip_aes,"%s","tkip");
					*unicastCipher = 1;
					*wpa2UnicastCipher = 1;
				}
			}
			if (pBss->t_stamp[0] & 0xffff0000) {
				if (wpa_exist)
					idx += sprintf(tmp2Buf + idx, "/");
				idx += sprintf(tmp2Buf + idx, "WPA2");
				if (((pBss->t_stamp[0] & 0xf0000000) >> 28) == 0x4)
					idx += sprintf(tmp2Buf + idx, "-PSK");
				else if (((pBss->t_stamp[0] & 0xf0000000) >> 28) == 0x2)
					idx += sprintf(tmp2Buf + idx, "-1X");

				if (((pBss->t_stamp[0] & 0x0f000000) >> 24) == 0x5) {
					//sprintf(wpa2_tkip_aes,"%s","aes/tkip");
					*unicastCipher = 1;
					*wpa2UnicastCipher = 2;
				} else if (((pBss->t_stamp[0] & 0x0f000000) >> 24) == 0x4) {
					//sprintf(wpa2_tkip_aes,"%s","aes");
					*unicastCipher = 1;
					*wpa2UnicastCipher = 2;
				} else if (((pBss->t_stamp[0] & 0x0f000000) >> 24) == 0x1) {
					//sprintf(wpa2_tkip_aes,"%s","tkip");
					*unicastCipher = 1;
					*wpa2UnicastCipher = 1;
				}
			}
			if (strcmp(tmp2Buf, "WPA-1X") == 0)
				*encryption = 2;
			if (strcmp(tmp2Buf, "WPA2-1X") == 0)
				*encryption = 4;
			if (strcmp(tmp2Buf, "WPA-1X/WPA2-1X") == 0)
				*encryption = 4;
			break;
		}
	}

	if (pStatus != NULL)
		free(pStatus);
	return 0;

 ss_err:
	if (pStatus != NULL)
		free(pStatus);
	return -1;
}
#endif	/* CONFIG_RTL_802_1X_CLIENT_SUPPORT */

static int generateWpaConf(char *outputFile, int isWds, char *wlanif_name)
{
	int fh, intVal, encrypt, enable1x, wep;
	int rc;
	struct cbuffer cb;
	char buf1[1024];
	char *token = NULL, *token1 = NULL, *savestr1 = NULL;
	int radio_id = 0, wlan_id = 0;
	char wl_prefix[16], nv_name[64], *nv_val;
	int i;
	struct in_addr *p_in_addr = NULL;
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
	int encryption, unicastCipher, wpa2UnicastCipher;
	int wlan_mode;
#endif

#if 0
	//#ifdef UNIVERSAL_REPEATER
	int isVxd = 0;

	if (strstr(outputFile, "-vxd"))
		isVxd = 1;
#endif

	if (!apmib_init())
		return -1;

	if (wlanif_name) {
		token = strtok_r(wlanif_name, " ", &savestr1);
		if (token)
			token1 = strtok_r(NULL, " ", &savestr1);
	} else
		token = "wlan0";

	cb.size = 4096;
	cb.count = 0;
	cb.buf = (char *)Malloc(cb.size);

	SetWlan_idx(token);
	rc = if_nametowlindex(token, &radio_id, &wlan_id);
	if (rc == eWLIF_VIRTUAL)
		snprintf(wl_prefix, sizeof(wl_prefix), "x_wl%d.%d", radio_id, wlan_id - 1);
	else
		snprintf(wl_prefix, sizeof(wl_prefix), "x_wl%d", radio_id);

#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
	apmib_get(MIB_WLAN_MODE, (void *)&wlan_mode);
	if (wlan_mode == CLIENT_MODE)
		getEncryptInfoAccordingAP(&encryption, &unicastCipher, &wpa2UnicastCipher);
#endif

	if (!isWds) {
		apmib_get(MIB_WLAN_ENCRYPT, (void *)&encrypt);

#if 0
		//#ifdef UNIVERSAL_REPEATER
		if (isVxd && (encrypt == ENCRYPT_WPA2_MIXED)) {
			apmib_get(MIB_WLAN_MODE, (void *)&intVal);
			if (intVal == AP_MODE || intVal == AP_WDS_MODE)
				encrypt = ENCRYPT_WPA;
		}
#endif
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
		if (wlan_mode == CLIENT_MODE)
			encrypt = encryption;
#endif
		cbprintf(&cb, "encryption = %d\n", encrypt);

#if 0
		//#ifdef UNIVERSAL_REPEATER
		if (isVxd) {
			if (strstr(outputFile, "wlan0-vxd"))
				apmib_get(MIB_REPEATER_SSID1, (void *)buf1);
			else
				apmib_get(MIB_REPEATER_SSID2, (void *)buf1);
		} else
#endif
			apmib_get(MIB_WLAN_SSID, (void *)buf1);
		cbprintf(&cb, "ssid = \"%s\"\n", buf1);

		apmib_get(MIB_WLAN_ENABLE_1X, (void *)&enable1x);
		cbprintf(&cb, "enable1x = %d\n", enable1x);

		apmib_get(MIB_WLAN_MAC_AUTH_ENABLED, (void *)&intVal);
		cbprintf(&cb, "enableMacAuth = %d\n", intVal);

#ifdef CONFIG_IEEE80211W
		apmib_get(MIB_WLAN_IEEE80211W, (void *)&intVal);
		cbprintf(&cb, "ieee80211w = %d\n", intVal);

		apmib_get(MIB_WLAN_SHA256_ENABLE, (void *)&intVal);
		cbprintf(&cb, "sha256 = %d\n", intVal);
#endif
		apmib_get(MIB_WLAN_ENABLE_SUPP_NONWPA, (void *)&intVal);
		if (intVal)
			apmib_get(MIB_WLAN_SUPP_NONWPA, (void *)&intVal);

		cbprintf(&cb, "supportNonWpaClient = %d\n", intVal);

		apmib_get(MIB_WLAN_WEP, (void *)&wep);
		cbprintf(&cb, "wepKey = %d\n", wep);

		if (encrypt == 1 && enable1x) {
			u_char *p = (u_char *) buf1;
			if (wep == 1) {
				apmib_get(MIB_WLAN_WEP64_KEY1, p);
				cbprintf(&cb, "wepGroupKey = \"%02x%02x%02x%02x%02x\"\n", p[0], p[1], p[2], p[3], p[4]);
			} else {
				apmib_get(MIB_WLAN_WEP128_KEY1, p);
				cbprintf(&cb, "wepGroupKey = \"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\"\n",
					 p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12]);
			}
		} else
			cbprintf(&cb, "wepGroupKey = \"\"\n");

		apmib_get(MIB_WLAN_WPA_AUTH, (void *)&intVal);
		cbprintf(&cb, "authentication = %d\n", intVal);

		apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&intVal);
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
		if (wlan_mode == CLIENT_MODE)
			intVal = unicastCipher;
#endif
		cbprintf(&cb, "unicastCipher = %d\n", intVal);

		apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&intVal);
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
		if (wlan_mode == CLIENT_MODE)
			intVal = wpa2UnicastCipher;
#endif
		cbprintf(&cb, "wpa2UnicastCipher = %d\n", intVal);

		apmib_get(MIB_WLAN_WPA2_PRE_AUTH, (void *)&intVal);
		cbprintf(&cb, "enablePreAuth = %d\n", intVal);

		apmib_get(MIB_WLAN_PSK_FORMAT, (void *)&intVal);
		if (intVal == 0)
			cbprintf(&cb, "usePassphrase = 1\n");
		else
			cbprintf(&cb, "usePassphrase = 0\n");

		apmib_get(MIB_WLAN_WPA_PSK, (void *)buf1);
		cbprintf(&cb, "psk = \"%s\"\n", buf1);

		apmib_get(MIB_WLAN_WPA_GROUP_REKEY_TIME, (void *)&intVal);
		cbprintf(&cb, "groupRekeyTime = %d\n", intVal);

		apmib_get(MIB_WLAN_RS_REAUTH_TO, (void *)&intVal);
		cbprintf(&cb, "rsReAuthTO = %d\n", intVal);
#ifdef CONFIG_PMKCACHE
		apmib_get(MIB_WLAN_MAX_PMKSA, (void *)&intVal);
		cbprintf(&cb, "MaxPmksa = %d\n", intVal);
#endif
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
		if (wlan_mode == CLIENT_MODE) {	// wlan client mode
			apmib_get(MIB_WLAN_EAP_TYPE, (void *)&intVal);
			cbprintf(&cb, "eapType = %d\n", intVal);

			apmib_get(MIB_WLAN_EAP_INSIDE_TYPE, (void *)&intVal);
			cbprintf(&cb, "eapInsideType = %d\n", intVal);

			apmib_get(MIB_WLAN_EAP_USER_ID, (void *)buf1);
			cbprintf(&cb, "eapUserId = \"%s\"\n", buf1);

			apmib_get(MIB_WLAN_RS_USER_NAME, (void *)buf1);
			cbprintf(&cb, "rsUserName = \"%s\"\n", buf1);

			apmib_get(MIB_WLAN_RS_USER_PASSWD, (void *)buf1);
			cbprintf(&cb, "rsUserPasswd = \"%s\"\n", buf1);

			apmib_get(MIB_WLAN_RS_USER_CERT_PASSWD, (void *)buf1);
			cbprintf(&cb, "rsUserCertPasswd = \"%s\"\n", buf1);

			apmib_get(MIB_WLAN_RS_BAND_SEL, (void *)&intVal);
			cbprintf(&cb, "rsBandSel = %d\n", intVal);

			//Patch for auth daemon at wlan client mode
			// 127.0.0.1 : 12345
			if (intVal == PHYBAND_5G)
				cbprintf(&cb, "rsPort = %d\n", 12344);
			else
				cbprintf(&cb, "rsPort = %d\n", 12345);

			cbprintf(&cb, "rsIP = %s\n", "127.0.0.1");
			//End patch.
		} else
#endif
		{
			apmib_get(MIB_WLAN_RS_PORT, (void *)&intVal);
			cbprintf(&cb, "rsPort = %d\n", intVal);

			apmib_get(MIB_WLAN_RS_IP, (void *)buf1);
			p_in_addr = (struct in_addr *)buf1;
			cbprintf(&cb, "rsIP = %s\n", inet_ntoa(*p_in_addr));

			apmib_get(MIB_WLAN_RS_PASSWORD, (void *)buf1);
			cbprintf(&cb, "rsPassword = \"%s\"\n", buf1);

			apmib_get(MIB_WLAN_RS_MAXRETRY, (void *)&intVal);
			cbprintf(&cb, "rsMaxReq = %d\n", intVal);

			apmib_get(MIB_WLAN_RS_INTERVAL_TIME, (void *)&intVal);
			cbprintf(&cb, "rsAWhile = %d\n", intVal);
#ifdef CONFIG_APP_AUTH_2NDSRV
			apmib_get(MIB_WLAN_RS2_PORT, (void *)&intVal);
			cbprintf(&cb, "rs2Port = %d\n", intVal);

			apmib_get(MIB_WLAN_RS2_IP, (void *)buf1);
			p_in_addr = (struct in_addr *)buf1;
			cbprintf(&cb, "rs2IP = %s\n", inet_ntoa(*p_in_addr));

			apmib_get(MIB_WLAN_RS2_PASSWORD, (void *)buf1);
			cbprintf(&cb, "rs2Password = \"%s\"\n", buf1);
#endif

			apmib_get(MIB_WLAN_ACCOUNT_RS_ENABLED, (void *)&intVal);
			cbprintf(&cb, "accountRsEnabled = %d\n", intVal);

			apmib_get(MIB_WLAN_ACCOUNT_RS_PORT, (void *)&intVal);
			cbprintf(&cb, "accountRsPort = %d\n", intVal);

			apmib_get(MIB_WLAN_ACCOUNT_RS_IP, (void *)buf1);
			p_in_addr = (struct in_addr *)buf1;
			cbprintf(&cb, "accountRsIP = %s\n", inet_ntoa(*p_in_addr));

			apmib_get(MIB_WLAN_ACCOUNT_RS_PASSWORD, (void *)buf1);
			cbprintf(&cb, "accountRsPassword = \"%s\"\n", buf1);

#ifdef CONFIG_APP_AUTH_2NDSRV
			apmib_get(MIB_WLAN_ACCOUNT_RS2_PORT, (void *)&intVal);
			cbprintf(&cb, "accountRs2Port = %d\n", intVal);

			apmib_get(MIB_WLAN_ACCOUNT_RS2_IP, (void *)buf1);
			p_in_addr = (struct in_addr *)buf1;
			cbprintf(&cb, "accountRs2IP = %s\n", inet_ntoa(*p_in_addr));

			apmib_get(MIB_WLAN_ACCOUNT_RS2_PASSWORD, (void *)buf1);
			cbprintf(&cb, "accountRs2Password = \"%s\"\n", buf1);
#endif

			apmib_get(MIB_WLAN_ACCOUNT_RS_UPDATE_ENABLED, (void *)&intVal);
			cbprintf(&cb, "accountRsUpdateEnabled = %d\n", intVal);

			apmib_get(MIB_WLAN_ACCOUNT_RS_UPDATE_DELAY, (void *)&intVal);
			cbprintf(&cb, "accountRsUpdateTime = %d\n", intVal);

			apmib_get(MIB_WLAN_ACCOUNT_RS_MAXRETRY, (void *)&intVal);
			cbprintf(&cb, "accountRsMaxReq = %d\n", intVal);

			apmib_get(MIB_WLAN_ACCOUNT_RS_INTERVAL_TIME, (void *)&intVal);
			cbprintf(&cb, "accountRsAWhile = %d\n", intVal);
		}
	} else {
		apmib_get(MIB_WLAN_WDS_ENCRYPT, (void *)&encrypt);
		if (encrypt == WDS_ENCRYPT_TKIP)
			encrypt = ENCRYPT_WPA;
		else if (encrypt == WDS_ENCRYPT_AES)
			encrypt = ENCRYPT_WPA2;
		else
			encrypt = 0;

		cbprintf(&cb, "encryption = %d\n", encrypt);
		cbprintf(&cb, "%s", "ssid = \"REALTEK\"\n");
		cbprintf(&cb, "%s", "ssid = \"REALTEK\"\n");
		cbprintf(&cb, "%s", "enable1x = 1\n");
		cbprintf(&cb, "%s", "enableMacAuth = 0\n");
		cbprintf(&cb, "%s", "supportNonWpaClient = 0\n");
		cbprintf(&cb, "%s", "wepKey = 0\n");
		cbprintf(&cb, "%s", "wepGroupKey = \"\"\n");
		cbprintf(&cb, "%s", "authentication = 2\n");

		if (encrypt == ENCRYPT_WPA)
			intVal = WPA_CIPHER_TKIP;
		else
			intVal = WPA_CIPHER_AES;

		cbprintf(&cb, "unicastCipher = %d\n", intVal);

		cbprintf(&cb, "wpa2UnicastCipher = %d\n", intVal);

		cbprintf(&cb, "%s", "enablePreAuth = 0\n");

		apmib_get(MIB_WLAN_WDS_PSK_FORMAT, (void *)&intVal);
		if (intVal == 0)
			cbprintf(&cb, "usePassphrase = 1\n");
		else
			cbprintf(&cb, "usePassphrase = 0\n");

		apmib_get(MIB_WLAN_WDS_PSK, (void *)buf1);
		cbprintf(&cb, "psk = \"%s\"\n", buf1);

		cbprintf(&cb, "%s", "groupRekeyTime = 0\n");
		cbprintf(&cb, "%s", "rsPort = 1812\n");
		cbprintf(&cb, "%s", "rsIP = 192.168.1.1\n");
		cbprintf(&cb, "%s", "rsPassword = \"\"\n");
		cbprintf(&cb, "%s", "rsMaxReq = 3\n");
		cbprintf(&cb, "%s", "rsAWhile = 10\n");
		cbprintf(&cb, "%s", "accountRsEnabled = 0\n");
		cbprintf(&cb, "%s", "accountRsPort = 1813\n");
		cbprintf(&cb, "%s", "accountRsIP = 192.168.1.1\n");
		cbprintf(&cb, "%s", "accountRsPassword = \"\"\n");
		cbprintf(&cb, "%s", "accountRsUpdateEnabled = 0\n");
		cbprintf(&cb, "%s", "accountRsUpdateTime = 1000\n");
		cbprintf(&cb, "%s", "accountRsMaxReq = 3\n");
		cbprintf(&cb, "%s", "accountRsAWhile = 1\n");
	}

	if (yfcat("/etc/version", "%s", buf1) && strlen(buf1) > 3)
		cbprintf(&cb, "rsNasId = %s\n", buf1);

	snprintf(nv_name, sizeof(nv_name), "x_wlan%d_WLS_REDIR_ENABLE", radio_id);
	if ((nv_val = nvram_get(nv_name)))
		cbprintf(&cb, "redirect = %d\n", atoi(nv_val));
	else
		cbprintf(&cb, "%s", "redirect = 0\n");

	snprintf(nv_name, sizeof(nv_name), "x_wlan%d_WLS_REDIR_HOST", radio_id);
	if ((nv_val = nvram_get(nv_name)))
		cbprintf(&cb, "redir_host = \"%s\"\n", nv_val);
	else
		cbprintf(&cb, "%s", "redir_host = \"\"\n");

	if (wlan_id == 0)
		snprintf(buf1, sizeof(buf1), "/var/wlist_wl%d", radio_id);
	else
		snprintf(buf1, sizeof(buf1), "/var/wlist_wl%d.%d", radio_id, wlan_id - 1);

	cbprintf(&cb, "wlist_file = \"%s\"\n", buf1);
	fh = open(outputFile, O_RDWR | O_CREAT | O_TRUNC);
	if (fh > -1) {
		rc = (write(fh, cb.buf, cb.count) == cb.count) ? 0 : -1;
		close(fh);
	}

	/* generate White list */
	cb.count = 0;
	for (i = 0; i < 5; i++) {
		snprintf(nv_name, sizeof(nv_name), "x_wlan%d_WLS_REDIR_ALLOW%d", radio_id, i);
		if ((nv_val = nvram_get(nv_name)))
			cbprintf(&cb, "%s\n", nv_val);
	}

	fh = open(buf1, O_RDWR | O_CREAT | O_TRUNC);
	if (fh > -1) {
		rc = (write(fh, cb.buf, cb.count) == cb.count) ? 0 : -1;
		close(fh);
	}
	free(cb.buf);

	return rc;
}

extern int apmib_trans_type(void *value, const char *string, const struct mib *mib);
static char *single_argumentize(int argc, char **argv)
{
	struct cbuffer cb = { .size = 128, .count = 0 };
	int i;

	if (argc < 1)
		return NULL;
	cb.buf = (char *)Malloc(cb.size);
	cbprintf(&cb, "%s", *argv++);
	for (i = 1; i < argc; i++)
		cbprintf(&cb, ",%s", *argv++);
	return cb.buf;
}

static int setmib(int argc, char **argv)
{
	const struct mib *mib, *nib;
	const struct mib_tbl_operation *top;
	const char *fullname;
	u_char *value;
	char *p;
	int i, rc, id, cmd, max_chan_num = -1;
	size_t max_unit_len = (_mib_max_unitsiz + 3) & ~3;
	char buf[sizeof(((mib_table_entry_T *)0)->name) << 1];

	SHIFT_ARGV();

	value = (u_char *)alloca(max_unit_len << 1);
	memset(value, 0, max_unit_len << 1);

	rc = if_nametowlindex(*argv, &wlan_idx, &vwlan_idx);
	if (rc != eWLIF_NONE) {
		SHIFT_ARGV();
		if (rc == eWLIF_BAD || validate_wlindex(wlan_idx, vwlan_idx))
			return -1;
	}

	if (getrootname((fullname = *argv), &wlan_idx, &vwlan_idx) == NULL ||
	    validate_wlindex(wlan_idx, vwlan_idx))
		return -1;

	SHIFT_ARGV();

	for (mib = ymib_first(); mib && mib_name_cmpr(buf, sizeof(buf), mib, fullname); )
		mib = ymib_next(mib);

	if (mib == NULL)
		return -1;

	id = mib->id;
	if (mib->type > TABLE_LIST_T) {
		nib = ysearch_mib_struct((mib->id & MIB_ID_MASK) - 1);
		if (!nib)
			return -1;
		if (!strcmp(*argv, "add"))
			cmd = (nib->id + 2) | MIB_ADD_TBL_ENTRY;
		else if (!strcmp(*argv, "del"))
			cmd = (nib->id + 3) | MIB_DEL_TBL_ENTRY;
		else if (!strcmp(*argv, "delall"))
			cmd = (nib->id + 4) | MIB_DELALL_TBL_ENTRY;
		else if (!strcmp(*argv, "mod"))
			cmd = (nib->id + 3) | MIB_DEL_TBL_ENTRY | MIB_MOD_TBL_ENTRY;
		else
			return -1;

		if (--argc <= 0 && !(cmd & MIB_DELALL_TBL_ENTRY))
			return -1;
		argv++;

		top = ysearch_mib_top(mib->type);
		if (!top) {
			_DEBUG(L_CRIT, "must be implemented for %x type!", mib->type);
			return -1;
		}
		if (cmd & MIB_ADD_TBL_ENTRY) {
			p = single_argumentize(argc, argv);
			rc = top->_get((void *)value, p, mib);
			if (p)
				free(p);
			if (rc == FALSE)
				return -1;
		} else if (cmd & MIB_DEL_TBL_ENTRY) {
			*(char *)value = (char)strtol(*argv, &p, 10);
			if (*argv == p || *p)
				return -1;
			if (apmib_get((nib->id + 1) + MIB_TABLE_LIST, (void *)value) == FALSE)
				return -1;
		}
		return (apmib_set(cmd, (void *)value)) ? 0 : -1;
	} else if (mib->type < TABLE_LIST_T) {
		if (mib->type != BYTE_ARRAY_T
#ifdef RTL_L2TP_POWEROFF_PATCH
		   || id == MIB_L2TP_PAYLOAD
#endif
		   ) {
			if (apmib_trans_type(value, *argv, mib))
				return (apmib_set(id, value)) ? 0 : -1;
		} else {
			if (!(id >= MIB_HW_TX_POWER_CCK_A && id <= MIB_HW_TX_POWER_DIFF_OFDM) && !(id >= MIB_HW_TX_POWER_TSSI_CCK_A && id <= MIB_HW_TX_POWER_TSSI_HT40_1S_D) &&
			    !(id >= MIB_HW_TX_POWER_5G_HT40_1S_A && id <= MIB_HW_TX_POWER_TSSI_5G_HT40_1S_D)
#if defined(CONFIG_RTL_8812_SUPPORT) || defined(CONFIG_WLAN_HAL_8822BE) || defined(CONFIG_WLAN_HAL_8822CE) || defined(CONFIG_WLAN_HAL_8812FE)
			    && !(id >= MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_A && id <= MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_B)
#endif
#if defined(CONFIG_WLAN_HAL_8814AE) || defined(CONFIG_WLAN_HAL_8814BE)
			    && !(id >= MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_C && id <= MIB_HW_TX_POWER_5G_HT40_1S_D)
#endif
			    && (id != MIB_L2TP_PAYLOAD)) {
				fprintf(stderr, "invalid mib!\n");
				return -1;
			}
			if ((id >= MIB_HW_TX_POWER_CCK_A && id <= MIB_HW_TX_POWER_DIFF_OFDM) || (id >= MIB_HW_TX_POWER_TSSI_CCK_A && id <= MIB_HW_TX_POWER_TSSI_HT40_1S_D)
#if defined(CONFIG_WLAN_HAL_8814AE) || defined(CONFIG_WLAN_HAL_8814BE)
			    || (id >= MIB_HW_TX_POWER_CCK_C && id <= MIB_HW_TX_POWER_CCK_D)
			    || (id >= MIB_HW_TX_POWER_HT40_1S_C && id <= MIB_HW_TX_POWER_HT40_1S_D)
#endif
			    )
				max_chan_num = MAX_2G_CHANNEL_NUM_MIB;
			else if ((id >= MIB_HW_TX_POWER_5G_HT40_1S_A && id <= MIB_HW_TX_POWER_TSSI_5G_HT40_1S_D)
#if defined(CONFIG_WLAN_HAL_8814AE) || defined(CONFIG_WLAN_HAL_8814BE)
				 || (id >= MIB_HW_TX_POWER_5G_HT40_1S_C && id <= MIB_HW_TX_POWER_5G_HT40_1S_D)
#endif
			    )
				max_chan_num = MAX_5G_CHANNEL_NUM_MIB;

#if defined(CONFIG_RTL_8812_SUPPORT) || defined(CONFIG_WLAN_HAL_8822BE)
			if (((id >= MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_A) && (id <= MIB_HW_TX_POWER_DIFF_OFDM4T_CCK4T_A))
			    || ((id >= MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_B) && (id <= MIB_HW_TX_POWER_DIFF_OFDM4T_CCK4T_B)))
				max_chan_num = MAX_2G_CHANNEL_NUM_MIB;

			if (((id >= MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_A) && (id <= MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_A))
			    || ((id >= MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_B) && (id <= MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_B)))
				max_chan_num = MAX_5G_DIFF_NUM;
#endif

#if defined(CONFIG_WLAN_HAL_8814AE) || defined(CONFIG_WLAN_HAL_8814BE)
			if (((id >= MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_C) && (id <= MIB_HW_TX_POWER_DIFF_OFDM4T_CCK4T_C))
			    || ((id >= MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_D) && (id <= MIB_HW_TX_POWER_DIFF_OFDM4T_CCK4T_D)))
				max_chan_num = MAX_2G_CHANNEL_NUM_MIB;

			if (((id >= MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_C) && (id <= MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_C))
			    || ((id >= MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_D) && (id <= MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_D)))
				max_chan_num = MAX_5G_DIFF_NUM;
#endif
			for (i = 0; i < max_chan_num && argv[i]; i++) {
				value[i + 1] = (char)strtol(argv[i], &p, 10);
				if (argv[i] == p || *p)
					return -1;
				value[0] = value[0] + 1;
			}

			if (value[0] == 1) {
				for (i = 2; i <= max_chan_num; i++)
					value[i] = value[1];
			} else if (value[0] == 2) {
				/* [1] channel number
				 * [2] TxPWR value
				 * [3] TxPWR key for checking set mode
				 */
				if (value[1] < 1 || value[1] > max_chan_num) {
					if ((value[1] < 1) ||
					    ((id >= MIB_HW_TX_POWER_CCK_A && id <= MIB_HW_TX_POWER_DIFF_OFDM) || (id >= MIB_HW_TX_POWER_TSSI_CCK_A && id <= MIB_HW_TX_POWER_TSSI_HT40_1S_D)) ||
					    ((id >= MIB_HW_TX_POWER_5G_HT40_1S_A && id <= MIB_HW_TX_POWER_TSSI_5G_HT40_1S_D) && (value[1] > 216))) {
						fprintf(stderr, "invalid channel number\n");
						return -1;
					}
				}
				value[3] = 0xff;
			} else if (value[0] < max_chan_num) {
				memcpy(&value[(_mib_max_unitsiz + 3) & ~3], &value[1], value[0]);
				apmib_get(id, &value[1]);
				memcpy(&value[1], &value[(_mib_max_unitsiz + 3) & ~3], value[0]);
			}

			return (apmib_set(id, value)) ? 0 : -1;;
		}
	}

	return -1;
}

/* return the number of set
 */
static int test_and_import(const char *filename, int overwrite)
{
	char buf[APMIB_NVRAM_MAX_VALUE_LEN << 1];
	FILE *f;
	char *current;
	int count = 0;

	if (filename && (f = fopen(filename, "r"))) {
		while (fgets(buf, sizeof(buf), f)) {
			char *p = strchr(buf, '=');
			if (p == NULL)
				continue;
			*p++ = '\0';
			current = nvram_get(ydespaces(buf));
			if (current == NULL || overwrite) {
				ystrtrim(yunescape(p), " \f\n\r\t\v\"");
				if (current == NULL || strcmp(current, p))
					count += !nvram_set(buf, p);
			}
		}
		fclose(f);
	}
	return count;
}

struct variable {
	struct list_head list;
	char *variable;
};

struct category {
	struct list_head list;
	int number;
	struct list_head head;
};

static int load_mib_revision(const char *filepath, struct list_head *top)
{
	FILE *f;
	char cur[APMIB_NVRAM_MAX_VALUE_LEN << 1];
	char *c;
	struct category *t = NULL, *s;
	int num, state = 0;

	if (!filepath || !(f = fopen(filepath, "r")))
		return -1;

	while (fgets(cur, sizeof(cur), f)) {
		ydespaces(cur);
		switch (state) {
		case 1:
			if (cur[0] != '[') {
				if (isalpha(cur[0])) {
					struct variable *v =
						Malloc(sizeof(struct variable));
					v->variable = strdup(cur);
					list_add_tail(&v->list, &t->head);
				}
				break;
			} else
				state = 0;
		case 0:
			if (cur[0] != '[' || !(c = strchr(cur, ']')))
				continue;
			*c = '\0';
			ystrtrim(cur, " \f\n\r\t\v\"[]");
			num = strtol(cur, &c, 0);
			if (cur == c || *c)
				continue;

			t = (struct category *)Malloc(sizeof(struct category));
			t->number = num;
			INIT_LIST_HEAD(&t->head);
			list_for_each_entry(s, top, list)
				if (s->number > num)
					break;
			__list_add(&t->list, s->list.prev, &s->list);
			state = 1;
			break;
		}
	}

	fclose(f);
	return 0;
}

static int diff_set(char *str)
{
	char *p;

	p = strchr(str, '=');
	if (p == NULL)
		return 0;

	*p++ = '\0';
	ystrtrim(yunescape(p), " \f\n\r\t\v\"");
	nvram_set(str, p);

	return 1;
}

static int diff_version(void)
{
	struct list_head cats;
	struct category *cat, *tmp;
	struct variable *var, *tmp1;
	int cur, highest, count = 0;
	char *p = nvram_safe_get("MIB_REVISION");

	INIT_LIST_HEAD(&cats);
	load_mib_revision(apmib_file_dfl(REV_DFL), &cats);

	if (list_empty(&cats))
		return (p == NULL) ? !nvram_set("MIB_REVISION", "1") : 0;

	cat = list_entry(cats.prev, struct category, list);
	highest = cat->number;
	cur = strtol(p, NULL, 0);

	if (cur < highest)
		count += ynvram_put("MIB_REVISION=%d", highest);

	list_for_each_entry(cat, &cats, list) {
		if (cat->number <= cur)
			continue;
		list_for_each_entry(var, &cat->head, list)
			count += diff_set(var->variable);
	}

	/* clean up */
	list_for_each_entry_safe(cat, tmp, &cats, list) {
		list_for_each_entry_safe(var, tmp1, &cat->head, list) {
			list_del(&var->list);
			free(var->variable);
			free(var);
		}
		list_del(&cat->list);
		free(cat);
	}

	return count;
}

static int sethw_mac(u_char mac[6], BOOL from_base)
{
	u_char tmp[6], lsb = mac[5];
	int i = 0;

	/* eth0(br0) */
	if (from_base &&
	    (!yxatoi(tmp, nvram_safe_get("HW_NIC0_ADDR"), sizeof(tmp) << 1) ||
	     memcmp(mac, tmp, sizeof(tmp))))
		i += ynvram_put("HW_NIC0_ADDR=%02x%02x%02x%02x%02x%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	/* wlan0(5g) +0 */
	if (!yxatoi(tmp, nvram_safe_get("HW_WLAN0_WLAN_ADDR"), sizeof(tmp) << 1) ||
	    memcmp(mac, tmp, sizeof(tmp)))
		i += ynvram_put("HW_WLAN0_WLAN_ADDR=%02x%02x%02x%02x%02x%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	/* wlan1(2.4g) +1 */
	mac[5] += 1;
	if (!yxatoi(tmp, nvram_safe_get("HW_WLAN1_WLAN_ADDR"), sizeof(tmp) << 1) ||
	    memcmp(mac, tmp, sizeof(tmp)))
		i += ynvram_put("HW_WLAN1_WLAN_ADDR=%02x%02x%02x%02x%02x%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	/* eth1(WAN) +2 : Labeling */
	mac[5] += 1;
	if (!yxatoi(tmp, nvram_safe_get("HW_NIC1_ADDR"), sizeof(tmp) << 1) ||
	    memcmp(mac, tmp, sizeof(tmp)))
		i += ynvram_put("HW_NIC1_ADDR=%02x%02x%02x%02x%02x%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	mac[5] = lsb;
	return i;
}

#ifdef HOME_GATEWAY
static int generatePPPConf(int is_pppoe, char *option_file, char *pap_file, char *chap_file
# ifdef MULTI_WAN_SUPPORT
			   , char *order_file
# endif
    )
{
	FILE *fd;
	char tmpbuf[200], buf1[100], buf2[100];
	int srcIdx, dstIdx;

	if (!apmib_init()) {
		fprintf(stderr, "Initialize AP MIB failed!\n");
		return -1;
	}

	if (is_pppoe) {
# if defined(MULTI_WAN_SUPPORT)
		{
			int index;
			WANIFACE_T WanIfaceEntry;
			sscanf(order_file, "%d", &index);
			memset(&WanIfaceEntry, '\0', sizeof(WanIfaceEntry));
			*((char *)&WanIfaceEntry) = (char)index;
			apmib_get(MIB_WANIFACE_TBL, (void *)&WanIfaceEntry);
			strcpy(buf1, WanIfaceEntry.pppUsername);
			strcpy(buf2, WanIfaceEntry.pppPassword);
		}
# elif defined(MULTI_PPPOE)
		if (!strcmp(order_file, "FIRST")) {
			apmib_get(MIB_PPP_USER_NAME, (void *)buf1);
			apmib_get(MIB_PPP_PASSWORD, (void *)buf2);
		} else if (!strcmp(order_file, "SECOND")) {
			apmib_get(MIB_PPP_USER_NAME2, (void *)buf1);
			apmib_get(MIB_PPP_PASSWORD2, (void *)buf2);

		} else if (!strcmp(order_file, "THIRD")) {
			apmib_get(MIB_PPP_USER_NAME3, (void *)buf1);
			apmib_get(MIB_PPP_PASSWORD3, (void *)buf2);

		} else if (!strcmp(order_file, "FORTH")) {
			apmib_get(MIB_PPP_USER_NAME4, (void *)buf1);
			apmib_get(MIB_PPP_PASSWORD4, (void *)buf2);
		}
# else
		apmib_get(MIB_PPP_USER_NAME, (void *)buf1);
		apmib_get(MIB_PPP_PASSWORD, (void *)buf2);
# endif
	} else {
# if defined(MULTI_WAN_SUPPORT)
#  if defined(SINGLE_WAN_SUPPORT)

		{
			int index;
			WANIFACE_T WanIfaceEntry;
			sscanf(order_file, "%d", &index);
			memset(&WanIfaceEntry, '\0', sizeof(WanIfaceEntry));
			*((char *)&WanIfaceEntry) = (char)index;
			apmib_get(MIB_WANIFACE_TBL, (void *)&WanIfaceEntry);
			strcpy(buf1, WanIfaceEntry.pptpUserName);
			strcpy(buf2, WanIfaceEntry.pptpPassword);
		}
#  endif
# else
		apmib_get(MIB_PPTP_USER_NAME, (void *)buf1);
		apmib_get(MIB_PPTP_PASSWORD, (void *)buf2);
# endif
	}
	// delete '"' in the value
	for (srcIdx = 0, dstIdx = 0; buf1[srcIdx]; srcIdx++, dstIdx++) {
		if (buf1[srcIdx] == '"')
			tmpbuf[dstIdx++] = '\\';
		tmpbuf[dstIdx] = buf1[srcIdx];
	}
	if (dstIdx != srcIdx) {
		memcpy(buf1, tmpbuf, dstIdx);
		buf1[dstIdx] = '\0';
	}

	for (srcIdx = 0, dstIdx = 0; buf2[srcIdx]; srcIdx++, dstIdx++) {
		if (buf2[srcIdx] == '"')
			tmpbuf[dstIdx++] = '\\';
		tmpbuf[dstIdx] = buf2[srcIdx];
	}
	if (dstIdx != srcIdx) {
		memcpy(buf2, tmpbuf, dstIdx);
		buf2[dstIdx] = '\0';
	}

	fd = fopen(option_file, "w");
	if (fd == NULL) {
		fprintf(stderr, "open file %s error!\n", option_file);
		return -1;
	}
	sprintf(tmpbuf, "name \"%s\"\n", buf1);
	fputs(tmpbuf, fd);
	if (strlen(buf2) > 31) {
		sprintf(tmpbuf, "-mschap\r\n");
		fputs(tmpbuf, fd);
		sprintf(tmpbuf, "-mschap-v2\r\n");
		fputs(tmpbuf, fd);
	}
	fclose(fd);

	fd = fopen(pap_file, "w");
	if (fd == NULL) {
		fprintf(stderr, "open file %s error!\n", pap_file);
		return -1;
	}
	fputs("#################################################\n", fd);
	sprintf(tmpbuf, "\"%s\"	*	\"%s\"\n", buf1, buf2);
	fputs(tmpbuf, fd);
	fclose(fd);

	fd = fopen(chap_file, "w");
	if (fd == NULL) {
		fprintf(stderr, "open file %s error!\n", chap_file);
		return -1;
	}
	fputs("#################################################\n", fd);
	sprintf(tmpbuf, "\"%s\"	*	\"%s\"\n", buf1, buf2);
	fputs(tmpbuf, fd);
	fclose(fd);
	return 0;
}
#endif				// HOME_GATEWAY

static int send_ppp_terminate(int sock, struct sockaddr_ll *ME, struct sockaddr_ll *HE, int sessid)
{
	unsigned char buf[256];
	struct pppoe_hdr *ah = (struct pppoe_hdr *)buf;
//      unsigned char *p = (unsigned char *) (ah + 1);
	unsigned char *p = buf;
	int c;

	ah->ver = 1;
	ah->type = 1;
	ah->code = 0;

	//ah->sid = (short*)sessid;
	ah->sid = (short)sessid;

	ah->length = 18;

	p += sizeof(struct pppoe_hdr);

	memcpy(p, "\xc0\x21", 2);
	p += 2;

	memcpy(p, "\x05", 1);
	p += 1;

	memcpy(p, "\x02", 1);
	p += 1;

	memcpy(p, "\x00\x10", 2);
	p += 2;

	memcpy(p, "\x55\x73\x65\x72\x20\x72\x65\x71\x75\x65\x73\x74", 12);
	p += 12;

	c = sendto(sock, buf, p - buf, 0, (struct sockaddr *)HE, sizeof(*HE));

	if (c < 0 || c != p - buf) {
		fprintf(stderr, "c = %d", c);
		return -1;
	}

	return 0;
}

static int send_PPPoE_PADT(int sock, struct sockaddr_ll *ME, struct sockaddr_ll *HE, int sessid)
{
	unsigned char buf[256];
	struct pppoe_hdr *ah = (struct pppoe_hdr *)buf;
	int c;

	ah->ver = 1;
	ah->type = 1;
	ah->code = 0xa7;

	//ah->sid = (short*)sessid;
	ah->sid = (short)sessid;
	ah->length = 0;
	HE->sll_protocol = htons(ETH_P_PPP_DISC);
	c = sendto(sock, buf, sizeof(struct pppoe_hdr), 0, (struct sockaddr *)HE, sizeof(*HE));
	if (c < 0 || c != sizeof(struct pppoe_hdr)) {
		fprintf(stderr, "c = %d", c);
		return -1;
	}
	return 0;
}

static int send_ppp_msg(int sessid, unsigned char *peerMacStr)
{
	unsigned char peerMacAddr[MAC_ADDR_LEN];
	char *device_if[] = { "eth1" };
	char *device = NULL;
	int i;
	char mac[24];

	for (i = 0; i < 1; i++) {
		struct sockaddr_ll me;
		struct sockaddr_ll he;
		int sock;
		struct ifreq ifr;

		int ifindex = 0;
		//unsigned char lanIp[4];

		//int   entryNum, index;
		//DHCPRSVDIP_T entry;

		device = device_if[i];

		sock = socket(PF_PACKET, SOCK_DGRAM, 0);

		if (sock < 0) {
			fprintf(stderr, "\r\n  Get sock fail!");
			return -1;
		}

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);
		if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
			fprintf(stderr, "\r\n Interface %s not found", device);
			close(sock);
			continue;
		}
		ifindex = ifr.ifr_ifindex;

		if (ioctl(sock, SIOCGIFFLAGS, (char *)&ifr)) {
			fprintf(stderr, "\r\n SIOCGIFFLAGS");
			close(sock);
			return -1;
		}
		if (!(ifr.ifr_flags & IFF_UP)) {
			fprintf(stderr, "\r\n Interface %s is down", device);
			close(sock);
			continue;
		}
		if (ifr.ifr_flags & (IFF_NOARP | IFF_LOOPBACK)) {
			fprintf(stderr, "\r\n Interface %s is not ARPable", device);
			close(sock);
			return -1;
		}
		//apmib_get(MIB_IP_ADDR,  (void *)lanIp);
		//memcpy(&src, lanIp, 4);

		//if (src.s_addr)
		{
			struct sockaddr_in saddr;
			int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);

			if (probe_fd < 0) {
				fprintf(stderr, "\r\n socket");
				close(sock);
				return -1;
			}

			if (setsockopt(probe_fd, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device) + 1) == -1)
				fprintf(stderr, "\r\n WARNING: interface %s is ignored", device);

			memset(&saddr, 0, sizeof(saddr));
			saddr.sin_family = AF_INET;

			//saddr.sin_addr = src;
			if (bind(probe_fd, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
				fprintf(stderr, "bind");
				close(sock);
				close(probe_fd);
				return -1;
			}
			close(probe_fd);
		}

		me.sll_family = AF_PACKET;
		me.sll_ifindex = ifindex;
		me.sll_protocol = htons(ETH_P_PPP_SES);
		if (bind(sock, (struct sockaddr *)&me, sizeof(me)) == -1) {
			fprintf(stderr, "\r\n bind");
			close(sock);
			return -1;
		}

		{
			//int alen = sizeof(me);
			socklen_t alen = sizeof(me);

			if (getsockname(sock, (struct sockaddr *)&me, &alen) == -1) {
				fprintf(stderr, "\r\n getsockname");
				close(sock);
				return -1;
			}
		}
		if (me.sll_halen == 0) {
			fprintf(stderr, "\r\n Interface \"%s\" is not ARPable (no ll address)", device);
			close(sock);
			return -1;
		}
		he = me;
		memset(he.sll_addr, -1, he.sll_halen);

		//apmib_get(MIB_DHCPRSVDIP_NUM, (void *)&entryNum);

		//for(index = 1; index<=entryNum ; index++)
		{
#if 0
			*((char *)&entry) = (char)index;
			if (!apmib_get(MIB_DHCPRSVDIP, (void *)&entry))
				continue;

			if (strlen(entry.hostName) == 0)
				continue;

			memcpy(&dst, entry.ipAddr, 4);
#endif
			memset(peerMacAddr, 0, sizeof(peerMacAddr));
			ether_atoe((char *)peerMacStr, peerMacAddr);

			if ((he.sll_halen != MAC_ADDR_LEN) ||
			    (!memcmp(peerMacAddr, "\x00\x00\x00\x00\x00\x00", MAC_ADDR_LEN))) {
				fprintf(stderr, "%s(%d): wrong he.sll_halen(%d) or wrong peerMacAddr[%s]!\n",
					__FUNCTION__, __LINE__, he.sll_halen, ether_etoa(peerMacAddr, mac));	//Added for test
				close(sock);
				return -1;
			} else {
				memcpy(he.sll_addr, peerMacAddr, he.sll_halen);
			}

			if (send_ppp_terminate(sock, &me, &he, sessid) == -1) {
				fprintf(stderr, "send ppp lcp terminate Fail!");
				close(sock);
				return -1;

			}

			if (send_PPPoE_PADT(sock, &me, &he, sessid) == -1) {
				fprintf(stderr, "send PADT Fail!");
				close(sock);
				return -1;

			}
		}
		close(sock);
	} //end of for(i=0 ; i<3 ; i++)

	return 0;
}

static char *fdigest(char *dst, const char *fmt, ...)
{
	char *p, buf[128];
	va_list ap;
	FILE *f;
	int fd, i;
	char tmp[] = "/tmp/XXXXXX";

	fd = mkstemp(tmp);
	if (fd < 0)
		return NULL;

	va_start(ap, fmt);
	p = yvasprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	for (i = 0; p[i]; i++)
		p[i] = toupper(p[i]);
	write(fd, p, strlen(p));
	close(fd);
	if (p != buf)
		free(p);

	snprintf(buf, sizeof(buf), "md5sum %s", tmp);
	f = popen(buf, "r");
	fscanf(f, "%s%*s", dst);
	pclose(f);
	unlink(tmp);

	return dst;
}

static char *strmodulo(char *input, char *output, size_t outlen, const char *accept)
{
	int i, m;

	for (m = strlen(accept), i = 0; m > 0 && i < outlen; i++)
		output[i] = accept[toupper(input[i]) % m];
	output[i] = '\0';
	return output;
}

static char *gen_passphrase(unsigned char mac[6], const char *sn, int primary, char *dst)
{
	char dgst[32 + 1];

	fdigest(dgst, "%s@P201@%02X%02X%02X%02X%02X%02X%s",
		sn ? : "",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
		primary ? "primary" : "secondary");

	strmodulo(dgst, dst, 13, "0123456789");
	return dst;
}

static char *wlan_prefix(char *dst, size_t len, int band, int idx)
{
	if (!idx)
		snprintf(dst, len, "WLAN%d", band);
	else
		snprintf(dst, len, "WLAN%d_VAP%d", band, idx - 1);
	return dst;
}

static int set_default_ssid(void)
{
	unsigned char mac[6];
	char passphrase[2][16], prefix[32], *sn;
	int band, i;

	if (!ether_atoe(nvram_safe_get("HW_NIC0_ADDR"), mac))
		return 0;

	gen_passphrase(mac, sn = nvram_safe_get("HW_SERIAL_NO"), 1, passphrase[0]);
	gen_passphrase(mac, sn, 0, passphrase[1]);
	for (band = 0; band < 2; band++) {
		for (i = 0; i < 2; i++) {
			wlan_prefix(prefix, sizeof(prefix), band, i);
			ynvram_put("%s_SSID=MBR210-%02X%02X%02X-%d", prefix, mac[3], mac[4], mac[5], i + 1);
			ynvram_put("%s_WLAN_DISABLED=0", prefix);

			// WPA3-Mixed | AES
			ynvram_put("%s_ENCRYPT=10", prefix);
			ynvram_put("%s_WPA_AUTH=2", prefix);
			ynvram_put("%s_WPA_CIPHER_SUITE=2", prefix);
			ynvram_put("%s_WPA2_CIPHER_SUITE=2", prefix);
			ynvram_put("%s_SHA256_ENABLE=1", prefix);

			// Randomized 13 digit string
			ynvram_put("%s_WPA_PSK=%s", prefix, passphrase[i]);
			ynvram_put("%s_WSC_PSK=%s", prefix, passphrase[i]);

			ynvram_put("%s_IEEE80211W=1", prefix);

			if (i == 0) {
				ynvram_put("%s_WSC_AUTH=96", prefix);
				ynvram_put("%s_WSC_ENC=8", prefix);
			}
		}
	}
	return 1;
}

static int set_http_passwd(void)
{
	unsigned char mac[6];
	char pwd[8], dgst[32 + 1];

	if (!ether_atoe(nvram_safe_get("HW_NIC0_ADDR"), mac))
		return 0;

	fdigest(dgst, "$%s$P201EmbeddedWebServer%02X%02X%02X%02X%02X%02X",
		nvram_safe_get("HW_SERIAL_NO"),
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	strmodulo(dgst, pwd, 6, "0123456789");
	return nvram_aes_cbc_set("USER_PASSWORD", pwd) ? 0 : 1;
}
