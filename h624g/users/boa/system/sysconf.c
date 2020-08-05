/*
 *
 *
 */

/* System include files */
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/wait.h>
/* Local include files */
#include "apmib.h"
#include "mibtbl.h"

#include "sysconf.h"
#include "sys_utility.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <net/if.h>
#include <stddef.h>		/* offsetof */
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include "nvram_mib/nvram_mib.h"

int apmib_initialized = 0;
extern int setinit(int argc, char **argv);
extern int Init_Internet(int argc, char **argv);
extern int setbridge(char *argv);
extern int setFirewallIptablesRules(int argc, char **argv);
extern int setWlan_Applications(char *action, char *argv);
#if defined(CONFIG_IPV6) && defined(__CONFIG_APP_RADVD__)
extern void set_6to4tunnel();
extern void set_radvd();
#endif

#if 1				//!defined(CONFIG_RTL_8198C)
#define RTL_L2TP_POWEROFF_PATCH 1
#endif

#if defined(CONFIG_APP_TR069)
extern void start_tr069(void);
#endif

#ifdef MULTI_PPPOE
extern void wan_disconnect(char *option, char *conncetOrder);
#else
extern void wan_disconnect(char *option);
#endif
extern int dhcpcNeedRenewConn(char *interface, char *option);
extern void wan_connect(char *interface, char *option);
extern void lan_connect(char *interface, char *option);

#ifdef __DAVO__
static int boundcmp(int argc, char **argv);
static int boundsave(int argc, char **argv);
extern void restrict_uplink_at_startup(int on);
#ifdef CONFIG_IPV6
static int dhcp6c_state(const char *state);

extern char **environ;
extern int in6_addrconf(const char *ifname, int method);
#endif				/* CONFIG_IPV6 */
#endif				/* __DAVO__ */

#ifdef CONFIG_IPV6
extern void ppp_connect_ipv6(char *ifname, char *option);
#endif

extern int Init_QoS(int argc, char **argv);
extern void start_lan_dhcpd(char *interface);
//extern int save_cs_to_file();

#ifdef CONFIG_DOMAIN_NAME_QUERY_SUPPORT
extern void wan_connect_pocket(char *interface, char *option);
extern int Check_setting_default(int opmode, int wlan_mode);
extern int Check_setting(int type);
extern void start_upnpd(int isgateway, int sys_op);
#endif
//////////////////////////////////////////////////////////////////////

#ifdef CONFIG_POCKET_ROUTER_SUPPORT
#define POCKETAP_HW_SET_FLAG "/proc/pocketAP_hw_set_flag"
#define AP_CLIENT_ROU_FILE "/proc/ap_client_rou"
#define DC_PWR_FILE "/proc/dc_pwr"

static void set_wlan_low_power()
{
//fprintf(stderr,"\r\n __[%s_%u]\r\n",__FILE__,__LINE__);
	system("iwpriv wlan0 set_mib txPowerPlus_cck_1=0");
	system("iwpriv wlan0 set_mib txPowerPlus_cck_2=0");
	system("iwpriv wlan0 set_mib txPowerPlus_cck_5=0");
	system("iwpriv wlan0 set_mib txPowerPlus_cck_11=0");
	system("iwpriv wlan0 set_mib txPowerPlus_ofdm_6=0");
	system("iwpriv wlan0 set_mib txPowerPlus_ofdm_9=0");
	system("iwpriv wlan0 set_mib txPowerPlus_ofdm_12=0");
	system("iwpriv wlan0 set_mib txPowerPlus_ofdm_18=0");
	system("iwpriv wlan0 set_mib txPowerPlus_ofdm_24=0");
	system("iwpriv wlan0 set_mib txPowerPlus_ofdm_36=0");
	system("iwpriv wlan0 set_mib txPowerPlus_ofdm_48=0");
	system("iwpriv wlan0 set_mib txPowerPlus_ofdm_54=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_0=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_1=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_2=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_3=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_4=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_5=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_6=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_7=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_8=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_9=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_10=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_11=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_12=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_13=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_14=0");
	system("iwpriv wlan0 set_mib txPowerPlus_mcs_15=0");
//fprintf(stderr,"\r\n __[%s-%u]\r\n",__FILE__,__LINE__);
}

/* Fix whan device is change wlan mode from client to AP or Router. *
  * The CIPHER_SUITE of wpa or wpa2 can't be tkip                           */
static int check_wpa_cipher_suite()
{
	int wlan_band, wlan_onoff_tkip, wlan_encrypt, wpaCipher, wpa2Cipher, wdsEncrypt;

	apmib_get(MIB_WLAN_BAND, (void *)&wlan_band);
	apmib_get(MIB_WLAN_11N_ONOFF_TKIP, (void *)&wlan_onoff_tkip);
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&wlan_encrypt);
	apmib_get(MIB_WLAN_WDS_ENCRYPT, (void *)&wdsEncrypt);
	if (wlan_onoff_tkip == 0) {	//Wifi request
		if (wlan_band == 8 || wlan_band == 10 || wlan_band == 11) {	//8:n; 10:gn; 11:bgn
			if (wlan_encrypt == ENCRYPT_WPA || wlan_encrypt == ENCRYPT_WPA2) {
				wpaCipher = WPA_CIPHER_AES;
				apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wpaCipher);

				wpa2Cipher = WPA_CIPHER_AES;
				apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wpa2Cipher);
			}
			if (wdsEncrypt == WDS_ENCRYPT_TKIP) {
				wdsEncrypt = WDS_ENCRYPT_DISABLED;
				apmib_set(MIB_WLAN_WDS_ENCRYPT, (void *)&wdsEncrypt);
			}
		}
	}
}

#if defined(FOR_DUAL_BAND)
short whichWlanIfIs(PHYBAND_TYPE_T phyBand)
{
	int i;
	int ori_wlan_idx = wlan_idx;
	int ret = -1;

	for (i = 0; i < NUM_WLAN_INTERFACE; i++) {
		unsigned char wlanif[10];
		memset(wlanif, 0x00, sizeof(wlanif));
		sprintf(wlanif, "wlan%d", i);
		if (SetWlan_idx(wlanif)) {
			int phyBandSelect;
			apmib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&phyBandSelect);
			if (phyBandSelect == phyBand) {
				ret = i;
				break;
			}
		}
	}

	wlan_idx = ori_wlan_idx;
	return ret;
}

#if defined(CONFIG_RTL_92D_SUPPORT)
void swapWlanMibSetting(unsigned char wlanifNumA, unsigned char wlanifNumB)
{
	unsigned char *wlanMibBuf = NULL;
	unsigned int totalSize = sizeof(CONFIG_WLAN_SETTING_T) * (NUM_VWLAN_INTERFACE + 1);	// 4vap+1rpt+1root
	wlanMibBuf = malloc(totalSize);
	if (wlanMibBuf != NULL) {
		memcpy(wlanMibBuf, pMib->wlan[wlanifNumA], totalSize);
		memcpy(pMib->wlan[wlanifNumA], pMib->wlan[wlanifNumB], totalSize);
		memcpy(pMib->wlan[wlanifNumB], wlanMibBuf, totalSize);

		free(wlanMibBuf);
	}
#ifdef UNIVERSAL_REPEATER

	int rptEnable1, rptEnable2;
	char rptSsid1[MAX_SSID_LEN], rptSsid2[MAX_SSID_LEN];

	memset(rptSsid1, 0x00, MAX_SSID_LEN);
	memset(rptSsid2, 0x00, MAX_SSID_LEN);

	apmib_get(MIB_REPEATER_ENABLED1, (void *)&rptEnable1);
	apmib_get(MIB_REPEATER_ENABLED2, (void *)&rptEnable2);
	apmib_get(MIB_REPEATER_SSID1, (void *)rptSsid1);
	apmib_get(MIB_REPEATER_SSID2, (void *)rptSsid2);

	apmib_set(MIB_REPEATER_ENABLED1, (void *)&rptEnable2);
	apmib_set(MIB_REPEATER_ENABLED2, (void *)&rptEnable1);
	apmib_set(MIB_REPEATER_SSID1, (void *)rptSsid2);
	apmib_set(MIB_REPEATER_SSID2, (void *)rptSsid1);
#endif
}
#endif
int switchToClientMode(void)
{
	int intVal = 0;
	int i;

	intVal = BANDMODESINGLE;
	apmib_set(MIB_WLAN_BAND2G5G_SELECT, (void *)&intVal);

	intVal = 15;		//A+B+G+N mode
	apmib_set(MIB_WLAN_BAND, (void *)&intVal);

	for (i = 0; i < NUM_WLAN_INTERFACE; i++) {
		unsigned char wlanif[10];
		memset(wlanif, 0x00, sizeof(wlanif));
		sprintf(wlanif, "wlan%d", i);
		if (SetWlan_idx(wlanif)) {
			int intVal;
			intVal = SMACSPHY;
			apmib_set(MIB_WLAN_MAC_PHY_MODE, (void *)&intVal);
		}
	}

	SetWlan_idx("wlan0");
	/*enable wlan0 */
	intVal = 0;
	apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);

	/*set wlan0 mode to client mode */
	intVal = 1;
	apmib_set(MIB_WLAN_MODE, (void *)&intVal);

	/*set wlan0 Channel Width to 40Mhz */
	intVal = 1;
	apmib_set(MIB_WLAN_CHANNEL_BONDING, (void *)&intVal);

	SetWlan_idx("wlan1");
	/*disable wlan1 */
	intVal = 1;
	apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);

	/*set wlan1 mode to client mode */
	intVal = 1;
	apmib_set(MIB_WLAN_MODE, (void *)&intVal);

	/*set wlan1 Channel Width to 40Mhz */
	intVal = 1;
	apmib_set(MIB_WLAN_CHANNEL_BONDING, (void *)&intVal);

	SetWlan_idx("wlan0");
	return 0;
}

int switchFromClientMode(void)
{

	int i;
	int macPhyMode;
	int wlanBand2G5GSelect;
	int val;
	/*qinjunjie:should not force config pocket as to dual mac dual phy in AP/Router mode,
	   because, if user config pocket as single mac single phy in AP/Router mode,
	   but change to dual mac dual phy after reboot, ,it's un-reasonable */

	apmib_get(MIB_WLAN_BAND2G5G_SELECT, (void *)&wlanBand2G5GSelect);
	/* Set both wireless interface is radio on and DMACDPHY */
	if (wlanBand2G5GSelect == BANDMODEBOTH) {
		int intVal;
		for (i = 0; i < NUM_WLAN_INTERFACE; i++) {
			unsigned char wlanif[10];

			memset(wlanif, 0x00, sizeof(wlanif));
			sprintf(wlanif, "wlan%d", i);
			if (SetWlan_idx(wlanif)) {
#if defined(CONFIG_RTL_92D_SUPPORT) && defined(CONFIG_RTL_92D_DMDP) && !defined(CONFIG_RTL_DUAL_PCIESLOT_BIWLAN_D)
				intVal = DMACDPHY;
#else
				intVal = SMACSPHY;
#endif
				apmib_set(MIB_WLAN_MAC_PHY_MODE, (void *)&intVal);
				intVal = 0;
				apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
			}
		}

		/* 92d rule, 5g must up in wlan0 */
		/* phybandcheck */
		if (whichWlanIfIs(PHYBAND_5G) != 0) {
			swapWlanMibSetting(0, 1);
		}

		SetWlan_idx("wlan0");
		apmib_get(MIB_WLAN_BAND, (void *)&intVal);
		if (intVal == 15)	//15:abgn there is no abgn band selection in ap mode
		{
			intVal = BAND_5G_11AN;
			apmib_set(MIB_WLAN_BAND, (void *)&intVal);
		}

		SetWlan_idx("wlan1");
		apmib_get(MIB_WLAN_BAND, (void *)&intVal);
		if (intVal == 15)	//15:abgn there is no abgn band selection in ap mode
		{
			intVal = BAND_11BG + BAND_11N;
			apmib_set(MIB_WLAN_BAND, (void *)&intVal);
		}
	} else if (wlanBand2G5GSelect == BANDMODESINGLE) {
		int intVal = 0;
		for (i = 0; i < NUM_WLAN_INTERFACE; i++) {
			unsigned char wlanif[10];
			memset(wlanif, 0x00, sizeof(wlanif));
			sprintf(wlanif, "wlan%d", i);
			if (SetWlan_idx(wlanif)) {
				int intVal;
				intVal = SMACSPHY;
				apmib_set(MIB_WLAN_MAC_PHY_MODE, (void *)&intVal);
			}
		}

		SetWlan_idx("wlan0");
		intVal = 0;
		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);

		apmib_get(MIB_WLAN_BAND, (void *)&intVal);
		if (intVal == 15)	//15:abgn there is no abgn band selection in ap mode
		{
			apmib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&intVal);
			if (intVal == PHYBAND_2G)
				intVal = BAND_11BG + BAND_11N;
			else
				intVal = BAND_5G_11AN;

			apmib_set(MIB_WLAN_BAND, (void *)&intVal);
		}

		SetWlan_idx("wlan1");
		intVal = 1;
		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);

		apmib_get(MIB_WLAN_BAND, (void *)&intVal);
		if (intVal == 15)	//15:abgn there is no abgn band selection in ap mode
		{
			apmib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&intVal);
			if (intVal == PHYBAND_2G)
				intVal = BAND_11BG + BAND_11N;
			else
				intVal = BAND_5G_11AN;

			apmib_set(MIB_WLAN_BAND, (void *)&intVal);
		}
	}

	/*set wlan0 mode to ap mode */
	SetWlan_idx("wlan0");
	val = 0;
	apmib_set(MIB_WLAN_MODE, (void *)&val);

	/*set wlan1 mode to ap mode */
	SetWlan_idx("wlan1");
	val = 0;
	apmib_set(MIB_WLAN_MODE, (void *)&val);

	SetWlan_idx("wlan0");
	return 0;
}
#endif

static int pocketAP_bootup()
{
	char pocketAP_hw_set_flag = 0;
	int op_mode = 1;
	int lan_dhcp;
	int cur_op_mode;
	int wlan0_mode;
	int ret = 0;

	apmib_get(MIB_OP_MODE, (void *)&cur_op_mode);
	apmib_get(MIB_WLAN_MODE, (void *)&wlan0_mode);
	if (isFileExist(DC_PWR_FILE)) {
		FILE *fp = NULL;
		unsigned char dcPwr_str[100];
		memset(dcPwr_str, 0x00, sizeof(dcPwr_str));

		fp = fopen(DC_PWR_FILE, "r");
		if (fp != NULL) {
			fgets(dcPwr_str, sizeof(dcPwr_str), fp);
			fclose(fp);

			if (strlen(dcPwr_str) != 0) {
				dcPwr_str[1] = '\0';
				if (strcmp(dcPwr_str, "2") == 0) {
					set_wlan_low_power();
				}
			}
		}
	}

	if (isFileExist(POCKETAP_HW_SET_FLAG)) {
		FILE *fp = NULL;
		unsigned char pocketAP_hw_set_flag_str[10];
		memset(pocketAP_hw_set_flag_str, 0x00, sizeof(pocketAP_hw_set_flag_str));

		fp = fopen(POCKETAP_HW_SET_FLAG, "r");
		if (fp != NULL) {
			fgets(pocketAP_hw_set_flag_str, sizeof(pocketAP_hw_set_flag_str), fp);
			fclose(fp);

			if (strlen(pocketAP_hw_set_flag_str) != 0) {
				pocketAP_hw_set_flag_str[1] = '\0';
				if (strcmp(pocketAP_hw_set_flag_str, "1") == 0) {
					pocketAP_hw_set_flag = 1;
				} else {
					pocketAP_hw_set_flag = 0;
					system("echo 1 > /proc/pocketAP_hw_set_flag");
				}
			}
		}

	}

	if (pocketAP_hw_set_flag == 0 && isFileExist(AP_CLIENT_ROU_FILE)) {
		FILE *fp = NULL;
		unsigned char ap_cli_rou_str[10];
		unsigned char kill_webs_flag = 0;
		memset(ap_cli_rou_str, 0x00, sizeof(ap_cli_rou_str));

		fp = fopen(AP_CLIENT_ROU_FILE, "r");
		if (fp != NULL) {
			fgets(ap_cli_rou_str, sizeof(ap_cli_rou_str), fp);
			fclose(fp);

			if (strlen(ap_cli_rou_str) != 0) {
				ap_cli_rou_str[1] = '\0';

				if ((cur_op_mode != 1 || wlan0_mode == CLIENT_MODE) && strcmp(ap_cli_rou_str, "2") == 0)	//AP
				{
					cur_op_mode = 1;
					wlan0_mode = 0;
					lan_dhcp = 15;
					apmib_set(MIB_OP_MODE, (void *)&cur_op_mode);
					apmib_set(MIB_WLAN_MODE, (void *)&wlan0_mode);
#if defined(FOR_DUAL_BAND)
					switchFromClientMode();
#endif
					check_wpa_cipher_suite();
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
					apmib_set(MIB_DHCP, (void *)&lan_dhcp);
					Check_setting(2);	//ap
#endif
					if (apmib_update(CURRENT_SETTING) == 1)
						save_cs_to_file();

					reinit_webs();
					//RunSystemCmd(NULL_FILE, "boa", NULL_STR);
				} else if ((cur_op_mode != 1 || wlan0_mode != CLIENT_MODE) && strcmp(ap_cli_rou_str, "1") == 0)	//CLIENT
				{
					cur_op_mode = 1;
					wlan0_mode = 1;
					lan_dhcp = 15;

					apmib_set(MIB_OP_MODE, (void *)&cur_op_mode);
					apmib_set(MIB_WLAN_MODE, (void *)&wlan0_mode);
#if defined(FOR_DUAL_BAND)
					switchToClientMode();
#endif
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
					apmib_set(MIB_DHCP, (void *)&lan_dhcp);
					Check_setting(1);	//client
#endif
					if (apmib_update(CURRENT_SETTING) == 1)
						save_cs_to_file();
					reinit_webs();

				} else if (cur_op_mode != 0 && strcmp(ap_cli_rou_str, "3") == 0)	//router
				{
					cur_op_mode = 0;
					wlan0_mode = 0;
					lan_dhcp = 2;

					apmib_set(MIB_OP_MODE, (void *)&cur_op_mode);
					apmib_set(MIB_WLAN_MODE, (void *)&wlan0_mode);
#if defined(FOR_DUAL_BAND)
					switchFromClientMode();
#endif
					check_wpa_cipher_suite();
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
					apmib_set(MIB_DHCP, (void *)&lan_dhcp);
					Check_setting(3);	//router
#endif
					if (apmib_update(CURRENT_SETTING) == 1)
						save_cs_to_file();
					reinit_webs();
					//RunSystemCmd(NULL_FILE, "boa", NULL_STR);
				} else {
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
					apmib_get(MIB_OP_MODE, (void *)&op_mode);
					if (op_mode == 0) {
						lan_dhcp = 2;
						apmib_set(MIB_DHCP, (void *)&lan_dhcp);
					} else {
						lan_dhcp = 15;
						apmib_set(MIB_DHCP, (void *)&lan_dhcp);
					}
					ret = Check_setting_default(cur_op_mode, wlan0_mode);
#if defined(FOR_DUAL_BAND)
					apmib_get(MIB_WLAN_MODE, (void *)&wlan0_mode);
					if (wlan0_mode == 1) {
						switchToClientMode();
					}
#endif

					if (ret == 1) {
						if (apmib_update(CURRENT_SETTING) == 1)
							save_cs_to_file();

						reinit_webs();
					}
#endif
				}
			}
		}
	} else {

#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
		apmib_get(MIB_OP_MODE, (void *)&op_mode);
		if (op_mode == 0) {
			lan_dhcp = 2;
			apmib_set(MIB_DHCP, (void *)&lan_dhcp);
		} else {
			lan_dhcp = 15;
			apmib_set(MIB_DHCP, (void *)&lan_dhcp);
		}

		ret = Check_setting_default(cur_op_mode, wlan0_mode);
		if (ret == 1) {
			if (apmib_update(CURRENT_SETTING) == 1)
				save_cs_to_file();

			reinit_webs();
		}
#endif
	}

}
#endif

#if defined(CONFIG_RTL_ULINKER)
extern int ulinker_bootup(void);
extern int ulinker_wlan_init(void);
#endif				/* #if defined(CONFIG_RTL_ULINKER)  */

///***************************************
// to decide whether should reconn dhcp
//***************************************/
int dhcpcNeedRenewConn(char *interface, char *option)
{
	FILE *fp = NULL;
	char *filename = NULL;
	char pre_dhcp_info[256];
	memset(pre_dhcp_info, 0, sizeof(pre_dhcp_info));

	if (strcmp(interface, "br0") == 0)
		filename = PREVIOUS_LAN_DHCP_INFO;
	else
		filename = PREVIOUS_WAN_DHCP_INFO;
	if ((fp = fopen(filename, "r")) != NULL) {
		fgets(pre_dhcp_info, sizeof(pre_dhcp_info), fp);
		pre_dhcp_info[strlen(pre_dhcp_info) - 1] = 0;
		fclose(fp);

		if (strcmp(pre_dhcp_info, option) == 0)
			return 0;
		else
			return 1;
	}
	return 0;
}

int sysconf_lock(int fd, struct flock lock)
{
	int ret;
	lock.l_type = F_WRLCK;
	lock.l_start = 0;
	lock.l_len = 0;
	lock.l_whence = SEEK_SET;
 try_again:
	ret = fcntl(fd, F_SETLKW, &lock);

	if (ret == -1) {

		printf("errno:%d\n", errno);
		if (errno == EINTR) {
			printf("try again\n");
			goto try_again;
		}
	}
	return ret;
}

int sysconf_unlock(int fd, struct flock lock)
{
	return close(fd);
}

int main(int argc, char **argv)
{
	char line[300];
	char action[16];
	int i;
	int wan_type = 0;
	int lan_type = 0;
	//printf("start.......:%s\n",argv[1]);
	struct flock lock;
	int fd;
#ifdef CONFIG_IPV6
	const char *applet_name = argv[0];
#endif

	for (i = 0; i < (argc - 1); i++)
		_PDEBUG("%s ", argv[i]);
	_PDEBUG("%s\n", argv[i]);

#ifdef CONFIG_IPV6
	if (applet_name[0] == '-')
		applet_name++;
	applet_name = base_name(applet_name);
	if (!strcmp(applet_name, "dhcp6c.script")) {
		dhcp6c_state(argv[1]);
		exit(EXIT_SUCCESS);
	} else if (argv[1] && (strcmp(argv[1], "-6") == 0)) {
		// sysconf -6 br0 <0|1|2>
		if (argc >= 4)
			in6_addrconf(argv[2], strtol(argv[3], NULL, 10));
		exit(EXIT_SUCCESS);
	}
#endif
	fd = open("/tmp/lock", O_RDWR | O_CREAT | O_TRUNC);
	if (fd < 0) {
		printf("create file lock erro\n");
	}
	if (!apmib_init()) {
		printf("Initialize AP MIB failed !\n");
		return -1;
	}
	apmib_initialized = 1;
	memset(line, 0x00, 300);

	apmib_get(MIB_WAN_DHCP, (void *)&wan_type);
	apmib_get(MIB_DHCP, (void *)&lan_type);

	if (argv[1] && (strcmp(argv[1], "init") == 0)) {
		sysconf_lock(fd, lock);
#if defined(CONFIG_RTL_ULINKER)
#if defined(CONFIG_RTL_ULINKER_WLAN_DELAY_INIT)
		int ulinker_auto = 0;
		apmib_get(MIB_ULINKER_AUTO, (void *)&ulinker_auto);
		if (ulinker_auto == 0)
			system("echo \"wlan 1\" > /proc/wlan_init");
#endif

		if (strcmp(argv[3], "all") == 0) {
			ulinker_bootup();
		}
#elif defined(CONFIG_POCKET_ROUTER_SUPPORT)
		pocketAP_bootup();
#endif
#ifdef CONFIG_POCKET_AP_SUPPORT
		i = BRIDGE_MODE;
		apmib_set(MIB_OP_MODE, (void *)&i);
		apmib_get(MIB_DHCP, (void *)&i);	//for FC, dhcp server not allowed when client
		if (i > DHCP_CLIENT)
			i = 0;
		apmib_set(MIB_DHCP, (void *)&i);	//0:DHCP_DISABLED
		i = 0xc0a801fa;
		apmib_set(MIB_IP_ADDR, (void *)&i);	//for FC, default IP to 192.168.1.250
#endif
		setinit(argc, argv);

#if defined(CONFIG_RTL_ULINKER_WLAN_DELAY_INIT)
		if (ulinker_auto == 1)
			ulinker_wlan_init();
#endif
		sysconf_unlock(fd, lock);
		return 0;
	} else if (argv[1] && (strcmp(argv[1], "br") == 0)) {
		for (i = 0; i < argc; i++) {
			if (i > 2)
				string_casecade(line, argv[i]);
		}
		setbridge(line);
	}
#ifdef   HOME_GATEWAY
	else if (argv[1] && (strcmp(argv[1], "firewall") == 0)) {

		if (argv[2] && (strcmp(argv[2], "Send_GARP") == 0))	//it will be call by set_staticIP function
		{
#ifdef SEND_GRATUITOUS_ARP
			sendArp();
#endif
		} else {
			setFirewallIptablesRules(argc, argv);
		}
	} else if (argv[1] && (strcmp(argv[1], "wlanapp") == 0)) {
		for (i = 0; i < argc; i++) {
			if (i > 2)
				string_casecade(line, argv[i]);
			if (i == 2)
				sprintf(action, "%s", argv[i]);
		}
		setWlan_Applications(action, line);
	} else if (argv[1] && (strcmp(argv[1], "disc") == 0)) {
		sprintf(line, "%s", argv[2]);
#ifdef MULTI_PPPOE
		if (argv[3])
			wan_disconnect(line, argv[3]);
		else
			wan_disconnect(line, "NOMULPPPOE");
#else
		if (argv[2] && !strcmp(argv[2], "option"))
			wan_disconnect(line);
		if (argv[2] && !strcmp(argv[2], "all"))
			wan_disconnect(line);
		else if ((argv[2] && !strcmp(argv[2], "option_l2tp")) && !isFileExist(TEMP_WAN_PPPOE_L2TP_CHECK))
			wan_disconnect(line);
#if defined(RTL_L2TP_POWEROFF_PATCH)
		else if (argv[2] && !strcmp(argv[2], "clear_l2tp")) {
			send_l2tp_cdn_packet();
		}
#endif				// RTL_L2TP_POWEROFF_PATCH
#endif				// MULTI_PPPOE
		yfecho("/var/wan_ip", O_WRONLY | O_CREAT | O_TRUNC, 0644, "0.0.0.0");
		yfecho("/var/gateway", O_WRONLY | O_CREAT | O_TRUNC, 0644, "0.0.0.0");
	}
#if 0
	else if (argv[1] && (argc >= 3 && strcmp(argv[3], "br0") != 0) &&
		   ((strcmp(argv[1], "conn") == 0) || ((strcmp(argv[1], "renew") == 0) && (wan_type == DHCP_CLIENT))))
#else
	else if (argv[1] && ((strcmp(argv[1], "conn") == 0) ||
			       ((strcmp(argv[1], "renew") == 0) && (wan_type == DHCP_CLIENT))))
#endif
	{
		/* APACRTL-84 if repeater mode start then kill dhcp  */
		if (get_repeater_mode()) {
			int pid;
			yfcat("/var/run/udhcpd.pid", "%d", &pid);

			if (pid > 0) {
				kill(pid, SIGTERM);
			}
			unlink("/var/run/udhcpd.pid");
			unlink("/var/udhcpd.conf");
		}

		sysconf_lock(fd, lock);
		if (argc < 4) {
			printf("sysconf conn Invalid agrments!\n");
			sysconf_unlock(fd, lock);
			return 0;
		}
#ifdef __DAVO__
		if (argc > 4 && !boundcmp(argc - 4, &argv[4])) {
			sysconf_unlock(fd, lock);
			return 0;
		}
#endif

		sprintf(action, "%s", argv[3]);

		for (i = 0; i < argc; i++) {
			if (i > 2)
				string_casecade(line, argv[i]);
		}

#ifdef __DAVO__
		boundsave(argc - 4, &argv[4]);
		/* clean up drop rules if any */
		restrict_uplink_at_startup(0);
#endif

		if ((!strcmp(argv[1], "renew")) && !strcmp(argv[2], "dhcp") && !dhcpcNeedRenewConn(action, line)) {
			sysconf_unlock(fd, lock);
			return 0;
		}
		if (wan_type == DHCP_CLIENT && (!strcmp(argv[2], "dhcp")))
			RunSystemCmd(PREVIOUS_WAN_DHCP_INFO, "echo", line, NULL_STR);

#if defined(CONFIG_DYNAMIC_WAN_IP)
		if ((!strcmp(argv[2], "dhcp")) && (isFileExist(TEMP_WAN_CHECK))) {
			RunSystemCmd(TEMP_WAN_DHCP_INFO, "echo", line, NULL_STR);
		}
#endif

#if defined(CONFIG_RTL_ULINKER)
		/* notice ulinker_process to reset domain name query */
		system("echo 1 > /var/ulinker_reset_domain");
#endif

#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
		if (!strcmp(action, "br0"))
			wan_connect_pocket(action, line);
		else
			wan_connect(action, line);
#else
		wan_connect(action, line);
#endif
		sysconf_unlock(fd, lock);

#ifdef CONFIG_IPV6
#ifdef __CONFIG_APP_RADVD__
		set_6to4tunnel();
		set_radvd();
#endif
#endif
	}
#ifdef CONFIG_IPV6
	else if (argv[1] && (strcmp(argv[1], "ipv6cp") == 0)) {
		if (argc < 4) {
			printf("sysconf ipv6cp Invalid agrments:%d!\n", argc);
			return 0;
		}
		sprintf(action, "%s", "ppp0");
		for (i = 0; i < argc; i++) {
			if (i > 2)
				string_casecade(line, argv[i]);
		}
		ppp_connect_ipv6(action, line);
	}
#endif
	else if (argv[1] && (strcmp(argv[1], "pppoe") == 0)) {
		Init_Internet(argc, argv);
	} else if (argv[1] && (strcmp(argv[1], "pptp") == 0)) {
		Init_Internet(argc, argv);
	} else if (argv[1] && (strcmp(argv[1], "l2tp") == 0)) {
		Init_Internet(argc, argv);
	} else if (argv[1] && (strcmp(argv[1], "setQos") == 0)) {
		Init_QoS(argc, argv);
	} else if (argv[1] && (strcmp(argv[1], "dhcpd") == 0)) {
		sprintf(action, "%s", argv[2]);
		start_lan_dhcpd(action);
	}
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
	else if (argv[1] && (strcmp(argv[1], "upnpd") == 0)) {
		if (argc < 4) {
			printf("sysconf upnpd Invalid agrments!\n");
			return 0;
		}
		start_upnpd(atoi(argv[2]), atoi(argv[3]));
	}
#endif

#ifdef SUPPORT_ZIONCOM_RUSSIA
	else if (argv[1] && (strcmp(argv[1], "check_l2tp_status") == 0))
		check_l2tp_status();
#endif
//### add by sen_liu 2011.4.21 sync the system log update (enlarge from 1 pcs to 8 pcs) to      SDKv2.5 from kernel 2.4
#if defined(RINGLOG)
	else if (argv[1] && (strcmp(argv[1], "log") == 0)) {
#ifdef __DAVO__
		set_log();
#else
		if (argc == 6 && !strcmp(argv[2], "-s") && !strcmp(argv[4], "-b")) {
			system("killall syslogd >/dev/null 2>&1");
			system("rm /var/log/log_split >/dev/null 2>&1");
			sprintf(line, "echo %s > /var/log/log_split", argv[5]);
			system(line);
			RunSystemCmd(NULL_FILE, "syslogd", "-L", "-s", argv[3], "-b", argv[5], NULL_STR);
			fprintf(stderr, "syslog will use %dKB for log(%s rotate, 1 original, %sKB for each).\n",
				atoi(argv[3]) * ((atoi(argv[5])) + 1), argv[5], argv[3]);
		}
		/*
		else if (argc == 4 && !strcmp(argv[2], "-R")) {
			RunSystemCmd(NULL_FILE, "killall syslogd", NULL_STR);
			RunSystemCmd(NULL_FILE, "syslogd", "-L", "-R", argv[3], NULL_STR);
		}
		 */
		else {
			fprintf(stderr, "usage:\n");
			fprintf(stderr, "sysconf log -s size -b number-of-rotate-backup\n");
			//fprintf(stderr, "sysconf log -R IP\n");
		}
#endif
	}
#endif
//### end
//add for start tr069 when system is boot
#if defined(CONFIG_APP_TR069)
	else if (argv[1] && (strcmp(argv[1], "tr069") == 0)) {
		start_tr069();
	}
#endif
#endif				//HOME_GATEWAY
	else if (argv[1] &&
		 ((strcmp(argv[1], "conn") == 0) || ((strcmp(argv[1], "renew") == 0) && (lan_type == DHCP_CLIENT)))) {	//conn/renew dhcp br0 [IP] [mask] [GW]
		sysconf_lock(fd, lock);
		if (argc < 4 || strcmp(argv[3], "br0") != 0) {
			printf("sysconf conn Invalid agrments!\n");
			return 0;
		}
		sprintf(action, "%s", argv[3]);
		for (i = 0; i < argc; i++) {
			if (i > 2)
				string_casecade(line, argv[i]);
		}
#if 1
		if ((strcmp(argv[1], "renew") == 0) && !strcmp(argv[2], "dhcp") && !dhcpcNeedRenewConn(action, line)) {
			return 0;
		}
#endif
		if (lan_type == DHCP_CLIENT && (!strcmp(argv[2], "dhcp")))
			RunSystemCmd(PREVIOUS_LAN_DHCP_INFO, "echo", line, NULL_STR);
		lan_connect(action, line);
		sysconf_unlock(fd, lock);
	}
#ifdef CONFIG_IPV6
	else if (argv[1] && (strcmp(argv[1], "dhcp6c_get") == 0)) {
		checkDhcp6pd();
#ifdef CONFIG_IPV6_CE_ROUTER_SUPPORT
		check_ipv6_ce();
#else
		checkDnsv6();
#endif
	}
#endif
#ifdef __DAVO__
	else if (argv[1] && !strcmp(argv[1], "boa"))
		start_httpd();
#endif
//#ifdef CONFIG_POCKET_ROUTER_SUPPORT
//      system("boa");
//#endif
	return 0;
}

////////////////////////////////////////////////////////////////////////
#ifdef __DAVO__

static struct {
	const char *path;
	int line;
} F[] = {{ "/var/wan_ip", 0 },
	 { "/var/netmask", 0 },
	 { "/var/gateway", 0 },
	 { "/var/dns", 0 },
	 { "/var/dns", 1 },
	 { NULL, -1 }};

//
// $(ip) $(netmask) $(gateway) $(dns1) $(dns2)
//
static char *fread_line(const char *path, int line, char *buf)
{
	if (yfcat(path, "%s", buf) > 0) {
		if (line) {
			yfcat(path, "%*[^\n] %s", buf);
		}
		ydespaces(buf);
		return buf;
	}

	return NULL;
}

static int boundcmp(int argc, char **argv)
{
	int i;
	char tmp[40];

	for (i = 0; i < argc && F[i].path; i++) {
		if (!fread_line(F[i].path, F[i].line, tmp))
			return -1;
		if (inet_addr(tmp) != inet_addr(argv[i]))
			return -1;
	}

	return 0;
}

static int boundsave(int argc, char **argv)
{
	int i;

	for (i = 0; i < argc && F[i].path; i++) {
		if (F[i].line == 0) {
			yfecho(F[i].path, O_WRONLY | O_CREAT | O_TRUNC, 0644, "%s\n", argv[i]);
		} else {
			yfecho(F[i].path, O_WRONLY | O_APPEND, 0644, "%s\n", argv[i]);
		}
	}
	return i;
}
#endif				// __DAVO__

#ifdef CONFIG_IPV6
static int dhcp6c_state(const char *state)
{
	char **envp;
	int i, newlen, len, ac;
	struct nameserver_addr N[8], O[8];
	char *ag[8];
	char *p;
	struct abuffer m;

	for (envp = environ; *envp; envp++) {
		if (!strncmp(*envp, "new_domain_name_servers=",
				sizeof "new_domain_name_servers=" - 1)) {
			if (nvram_atoi("x_ipv6_dns_method", 0))	/* 0 - Provisioned by DHCP server */
				continue;

			p = strdup(&(*envp)[sizeof "new_domain_name_servers=" - 1]);
			ac = ystrargs(p, ag, _countof(ag), " \t\r\n", 0);
			for (i = newlen = 0; i < ac && newlen < _countof(N); i++) {
				if (inet_pton(AF_INET6, ag[i], &N[newlen].na_addr6) == 1)
					N[newlen++].na_family = AF_INET6;
			}
			free(p);

			newlen = rmdup_nameserver(N, newlen);
			len = sort_nameserver(RESOLV_CONF, O, _countof(O), AF_INET6);
			if (newlen != len || (newlen && memcmp(N, O, sizeof(N[0]) * newlen)))
				commit_nameserver(RESOLV_CONF, N, newlen, AF_INET6);
		} else if (!strncmp(*envp, "new_domain_name=",
				sizeof "new_domain_name=" - 1)) {
			p = strdup(&(*envp)[sizeof "new_domain_name=" - 1]);
			ac = ystrargs(p, ag, _countof(ag), " \t\r\n", 0);
			init_abuffer(&m, 128);
			for (i = 0; i < ac; i++)
				aprintf(&m, "%s ", ystrtrim(ag[i], "."));
			free(p);
			if (m.count > 0)
				m.buf[m.count - 1] = '\0';
			commit_search(RESOLV_CONF, m.buf);
			fini_abuffer(&m);
		}
	}

	return 0;
}
#endif
