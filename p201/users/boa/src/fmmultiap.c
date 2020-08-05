/*This file handles MultiAP webpage form request
 *
 */
#include <arpa/inet.h>
#include <dirent.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*-- Local inlcude files --*/
#include "boa.h"
#include "asp_page.h"
#include "apmib.h"
#include "globals.h"
#include "utility.h"
#include "apform.h"

void _set_up_backhaul_credentials()
{
	unsigned int seed       = 0;
	int          randomData = open("/dev/urandom", O_RDONLY);
	int          mibVal     = 1;
	if (randomData < 0) {
		// something went wrong, use fallback
		seed = time(NULL) + rand();
	} else {
		char    myRandomData[50];
		ssize_t result = read(randomData, myRandomData, sizeof myRandomData);
		if (result < 0) {
			// something went wrong, use fallback
			seed = time(NULL) + rand();
		}
		int i = 0;
		for (i = 0; i < 50; i++) {
			seed += (unsigned char)myRandomData[i];
			if (i % 5 == 0) {
				seed = seed * 10;
			}
		}
	}
	srand(seed);
	char SSIDDic[62]       = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
	char NetworkKeyDic[83] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy"
	                         "z1234567890~!@#0^&*()_+{}[]:;..?";

	char backhaulSSID[21], backhaulNetworkKey[31];
	strcpy(backhaulSSID, "EasyMeshBH-");
	backhaulSSID[20]       = '\0';
	backhaulNetworkKey[30] = '\0';

	// randomly generate SSID post-fix
	int i;
	for (i = 11; i < 20; i++) {
		backhaulSSID[i] = SSIDDic[rand() % 62];
	}
	// randomly generate network key
	for (i = 0; i < 30; i++) {
		backhaulNetworkKey[i] = NetworkKeyDic[rand() % 83];
	}

	// set into mib
	if (!apmib_set(MIB_WLAN_SSID, (void *)backhaulSSID)) {
		printf("[Error] : Failed to set AP mib MIB_WLAN_SSID\n");
		return 0;
	}

	if (!apmib_set(MIB_WLAN_WPA_PSK, (void *)backhaulNetworkKey)) {
		printf("[Error] : Failed to set AP mib MIB_WLAN_WPA_PSK\n");
		return 0;
	}

	if (!apmib_set(MIB_WLAN_WSC_PSK, (void *)backhaulNetworkKey)) {
		printf("[Error] : Failed to set AP mib MIB_WLAN_WPA_PSK\n");
		return 0;
	}

	mibVal = WSC_AUTH_WPA2PSK;
	apmib_set(MIB_WLAN_WSC_AUTH, (void *)&mibVal);
	mibVal = WSC_ENCRYPT_AES;
	apmib_set(MIB_WLAN_WSC_ENC, (void *)&mibVal);
	mibVal = 1;
	apmib_set(MIB_WLAN_WSC_CONFIGURED, (void *)&mibVal);
	mibVal = WPA_CIPHER_AES;
	apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&mibVal);

	mibVal = 1;
	if (!apmib_set(MIB_WLAN_HIDDEN_SSID, (void *)&mibVal)) {
		printf("[Error] : Failed to set AP mib MIB_WLAN_HIDDEN_SSID\n");
		return 0;
	}
}

void formMultiAP(request *wp, char *path, char *query)
{
	char *submitUrl, *strVal;

	//Check if it is push button press, trigger push button then return.
	strVal    = req_get_cstream_var(wp, ("start_wsc"), "");
	if (strVal[0]) {
		submitUrl = req_get_cstream_var(wp, ("submit-url"), "");
		system("echo 1 > /tmp/virtual_push_button");
		send_redirect_perm(wp, submitUrl);
		return;
	}

	int i, j;
	// Enable dot11kv if not already enabled
	int mibVal = 1;
	strVal     = req_get_cstream_var(wp, ("needEnable11kv"), "");
	if (!strcmp(strVal, "1")) {
		for (i = 0; i < 2; i++) {
			wlan_idx = i;
			for (j = 0; j < 6; j++) {
				vwlan_idx = j;
				apmib_set(MIB_WLAN_DOT11K_ENABLE, (void *)&mibVal);
				apmib_set(MIB_WLAN_DOT11V_ENABLE, (void *)&mibVal);
			}
		}
	}

	char *device_name = req_get_cstream_var(wp, ("device_name_text"), "");
	apmib_set(MIB_MAP_DEVICE_NAME, (void *)device_name);

	// mibVal = 1;
	// apmib_set(MIB_STP_ENABLED, (void *)&mibVal);

	char *role_prev = req_get_cstream_var(wp, ("role_prev"), "");

	// Read role info from form and set to mib accordingly
	strVal = req_get_cstream_var(wp, ("role"), "");
	mibVal = 0;
	if (!strcmp(strVal, "controller")) {
		// Set to controller
		mibVal = 1;
		apmib_set(MIB_MAP_CONTROLLER, (void *)&mibVal);
		apmib_get(MIB_OP_MODE, (void *)&mibVal);
		if(WISP_MODE != mibVal) {
			// Disable repeater
			mibVal = 0;
			apmib_set(MIB_REPEATER_ENABLED1, (void *)&mibVal);
			apmib_set(MIB_REPEATER_ENABLED2, (void *)&mibVal);
			// Disable vxd
			mibVal    = 1;
			wlan_idx  = 0;
			vwlan_idx = 5;
			apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&mibVal);
			wlan_idx  = 1;
			vwlan_idx = 5;
			apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&mibVal);
		}

		// if different from prev role, reset this mib to 0
		if (strcmp(strVal, role_prev)) {
			mibVal = 0;
			apmib_set(MIB_MAP_CONFIGURED_BAND, (void *)&mibVal);
		}

		// enable va0 on both wlan0 and wlan1
		mibVal    = 0;
		wlan_idx  = 0;
		vwlan_idx = 1;
		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&mibVal);
		mibVal = ENCRYPT_WPA2;
		apmib_set(MIB_WLAN_ENCRYPT, (void *)&mibVal);
		mibVal = WPA_AUTH_PSK;
		apmib_set(MIB_WLAN_WPA_AUTH, (void *)&mibVal);

		mibVal    = 0;
		wlan_idx  = 1;
		vwlan_idx = 1;
		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&mibVal);
		mibVal = ENCRYPT_WPA2;
		apmib_set(MIB_WLAN_ENCRYPT, (void *)&mibVal);
		mibVal = WPA_AUTH_PSK;
		apmib_set(MIB_WLAN_WPA_AUTH, (void *)&mibVal);

		mibVal = 0x20; // fronthaul value
		int val;
		for (i = 0; i < 2; i++) {
			for (j = 0; j < 5; j++) {
				wlan_idx  = i;
				vwlan_idx = j;
				if (!apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&val))
					return -1;
				if (val == 0) // only set to fronthaul if this interface is enabled
					apmib_set(MIB_WLAN_MAP_BSS_TYPE, (void *)&mibVal);
			}
		}

		wlan_idx  = 0;
		vwlan_idx = 0;
		mibVal = 1;
		apmib_set(MIB_WLAN_STACTRL_ENABLE, (void *)&mibVal);
		apmib_set(MIB_WLAN_STACTRL_PREFER, (void *)&mibVal);

		wlan_idx  = 1;
		vwlan_idx = 0;
		mibVal = 1;
		apmib_set(MIB_WLAN_STACTRL_ENABLE, (void *)&mibVal);
		mibVal = 0;
		apmib_set(MIB_WLAN_STACTRL_PREFER, (void *)&mibVal);

		mibVal = 0x40; // backhaul value
		// wlan0
		wlan_idx  = 0;
		vwlan_idx = 1;
		if (strcmp(strVal, role_prev)) {
			_set_up_backhaul_credentials();
		}
		apmib_set(MIB_WLAN_MAP_BSS_TYPE, (void *)&mibVal);

		// wlan1
		wlan_idx  = 1;
		vwlan_idx = 1;
		if (strcmp(strVal, role_prev)) {
			_set_up_backhaul_credentials();
		}
		apmib_set(MIB_WLAN_MAP_BSS_TYPE, (void *)&mibVal);
	} else if (!strcmp(strVal, "agent")) {
		mibVal = DHCP_CLIENT;
		apmib_set(MIB_DHCP, (void *)&mibVal);

		mibVal = 480;
		apmib_set(MIB_DHCP_LEASE_TIME, (void *)&mibVal);
		// Set to agent
		mibVal = 2;
		apmib_set(MIB_MAP_CONTROLLER, (void *)&mibVal);
		// Enable repeater
		mibVal = 1;
		apmib_set(MIB_REPEATER_ENABLED1, (void *)&mibVal);
		mibVal = 0;
		apmib_set(MIB_REPEATER_ENABLED2, (void *)&mibVal);

		// wlan_idx  = 0;
		// vwlan_idx = 0;
		// mibVal = 1;
		// apmib_set(MIB_WLAN_STACTRL_ENABLE, (void *)&mibVal);
		// apmib_set(MIB_WLAN_STACTRL_PREFER, (void *)&mibVal);

		// wlan_idx  = 1;
		// vwlan_idx = 0;
		// mibVal = 1;
		// apmib_set(MIB_WLAN_STACTRL_ENABLE, (void *)&mibVal);
		// mibVal = 0;
		// apmib_set(MIB_WLAN_STACTRL_PREFER, (void *)&mibVal);

		// Enable vxd on 5g, set mode and enable wsc on vxd
		mibVal    = 0;
		wlan_idx  = 0;
		vwlan_idx = 5;
		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&mibVal);
		apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&mibVal);
		mibVal = 1;
		apmib_set(MIB_WLAN_MODE, (void *)&mibVal);
		// Set bss type to 128 for vxd
		mibVal = 0x80;
		apmib_set(MIB_WLAN_MAP_BSS_TYPE, (void *)&mibVal);

		// mibVal    = 0;
		wlan_idx  = 1;
		vwlan_idx = 5;
		// // Turn on vxd on 2.4g
		// apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&mibVal);
		// apmib_set(MIB_WLAN_WSC_DISABLE, (void *)&mibVal);
		// mibVal = 1;
		// apmib_set(MIB_WLAN_MODE, (void *)&mibVal);
		// Set bss type to 0 for vxd
		mibVal = 0x00;
		apmib_set(MIB_WLAN_MAP_BSS_TYPE, (void *)&mibVal);

		// if different from prev role, reset this mib to 0
		if (strcmp(strVal, role_prev)) {
			mibVal = 0;
			apmib_set(MIB_MAP_CONFIGURED_BAND, (void *)&mibVal);
		}
	} else if (!strcmp(strVal, "disabled")) {
		mibVal = 0;
		apmib_set(MIB_MAP_CONTROLLER, (void *)&mibVal);

		// Disable repeater
		mibVal = 0;
		apmib_set(MIB_REPEATER_ENABLED1, (void *)&mibVal);
		apmib_set(MIB_REPEATER_ENABLED2, (void *)&mibVal);
		// Disable vxd
		mibVal    = 1;
		wlan_idx  = 0;
		vwlan_idx = 5;
		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&mibVal);
		wlan_idx  = 1;
		vwlan_idx = 5;
		apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&mibVal);
		// reset configured band to 0
		mibVal = 0;
		apmib_set(MIB_MAP_CONFIGURED_BAND, (void *)&mibVal);
	}

	// update flash
	apmib_update_web(CURRENT_SETTING);

	submitUrl = req_get_cstream_var(wp, ("submit-url"), "");
	strVal    = req_get_cstream_var(wp, ("save_apply"), "");
	// sysconf init   if save_apply
	if (strVal[0]) {
		OK_MSG(submitUrl);
	} else {
		send_redirect_perm(wp, submitUrl);
	}

	return;
}
