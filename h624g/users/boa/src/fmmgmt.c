/*
 *      Web server handler routines for management (password, save config, f/w update)
 *
 *      Authors: David Hsu	<davidhsu@realtek.com.tw>
 *
 *      $Id: fmmgmt.c,v 1.45 2009/09/03 05:04:42 keith_huang Exp $
 *
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/reboot.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/sysinfo.h>

#include "boa.h"
#include "globals.h"
#include "apmib.h"
#include "apform.h"
#include "utility.h"
#include "mibtbl.h"
#include "asp_page.h"
#include "linux_list.h"
#include "dv_make_uniqcookie.h"

// added by rock /////////////////////////////////////////
#ifdef VOIP_SUPPORT
#include "web_voip.h"
#include "voip_flash_mib.h"
#include "voip_flash_tool.h"
#endif

#if defined(POWER_CONSUMPTION_SUPPORT)
#include "powerCon.h"
#endif

#define DEFAULT_GROUP		"administrators"
#define ACCESS_URL		"/"

#ifdef CONFIG_RTL_WAPI_SUPPORT
#define MTD1_SIZE 0x2d0000	//Address space: 0x2d0000
#define WAPI_SIZE 0x10000	//Address space: 64K
#define WAPI_AREA_BASE (MTD1_SIZE-WAPI_SIZE)
#endif

extern int Decode(unsigned char *ucInput, unsigned int inLen, unsigned char *ucOutput);

#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
extern void Stop_Domain_Query_Process(void);
extern unsigned char WaitCountTime;
#endif
//static char superName[MAX_NAME_LEN]={0}, superPass[MAX_NAME_LEN]={0};
//static char userName[MAX_NAME_LEN]={0}, userPass[MAX_NAME_LEN]={0};
int isUpgrade_OK=0;
int isFWUPGRADE=0;
int isCFGUPGRADE=0;
int isREBOOTASP=0;
int Reboot_Wait=0;
int isCFG_ONLY=0;

#if defined(CONFIG_APP_FWD)
int isCountDown=0;
#endif
#ifdef LOGIN_URL
static void delete_user(request *wp);
#endif
int configlen = 0;

int opModeHandler(request *wp, char *tmpBuf);
int find_head_offset(char *upload_data);

#ifdef __DAVO__
extern int dv_reboot_system;
extern int dv_script_reboot;
extern int need_reboot;
extern void translate_control_code(char *buffer);

unsigned long connection_init_time=0;

#endif

////////////////////////////////////////////////////////////////////////////////
#ifdef _LITTLE_ENDIAN_
#if 0
void swap_mib_word_value(APMIB_Tp pMib)
{
	pMib->wlan[wlan_idx][vwlan_idx].fragThreshold = WORD_SWAP(pMib->wlan[wlan_idx][vwlan_idx].fragThreshold);
	pMib->wlan[wlan_idx][vwlan_idx].rtsThreshold = WORD_SWAP(pMib->wlan[wlan_idx][vwlan_idx].rtsThreshold);
	pMib->wlan[wlan_idx][vwlan_idx].supportedRates = WORD_SWAP(pMib->wlan[wlan_idx][vwlan_idx].supportedRates);
	pMib->wlan[wlan_idx][vwlan_idx].basicRates = WORD_SWAP(pMib->wlan[wlan_idx][vwlan_idx].basicRates);
	pMib->wlan[wlan_idx][vwlan_idx].beaconInterval = WORD_SWAP(pMib->wlan[wlan_idx][vwlan_idx].beaconInterval);
	pMib->wlan[wlan_idx][vwlan_idx].inactivityTime = DWORD_SWAP(pMib->wlan[wlan_idx][vwlan_idx].inactivityTime);
	pMib->wlan[wlan_idx][vwlan_idx].wpaGroupRekeyTime = DWORD_SWAP(pMib->wlan[wlan_idx][vwlan_idx].wpaGroupRekeyTime);
	pMib->wlan[wlan_idx][vwlan_idx].rsPort = WORD_SWAP(pMib->wlan[wlan_idx][vwlan_idx].rsPort);

#ifdef HOME_GATEWAY
{
	int i;
	pMib->pppIdleTime = WORD_SWAP(pMib->pppIdleTime);
	for (i=0; i<pMib->portFwNum; i++) {
		pMib->portFwArray[i].fromPort = WORD_SWAP(pMib->portFwArray[i].fromPort);
		pMib->portFwArray[i].toPort = WORD_SWAP(pMib->portFwArray[i].toPort);
	}

	for (i=0; i<pMib->portFilterNum; i++) {
		pMib->portFilterArray[i].fromPort = WORD_SWAP(pMib->portFilterArray[i].fromPort);
		pMib->portFilterArray[i].toPort = WORD_SWAP(pMib->portFilterArray[i].toPort);
	}
	for (i=0; i<pMib->triggerPortNum; i++) {
		pMib->triggerPortArray[i].tri_fromPort = WORD_SWAP(pMib->triggerPortArray[i].tri_fromPort);
		pMib->triggerPortArray[i].tri_toPort = WORD_SWAP(pMib->triggerPortArray[i].tri_toPort);
		pMib->triggerPortArray[i].inc_fromPort = WORD_SWAP(pMib->triggerPortArray[i].inc_fromPort);
		pMib->triggerPortArray[i].inc_toPort = WORD_SWAP(pMib->triggerPortArray[i].inc_toPort);
	}
#ifdef GW_QOS_ENGINE
	pMib->qosManualUplinkSpeed = DWORD_SWAP(pMib->qosManualUplinkSpeed);
	pMib->qosManualDownLinkSpeed = DWORD_SWAP(pMib->qosManualDownLinkSpeed);

	for (i=0; i<pMib->qosRuleNum; i++) {
		pMib->qosRuleArray[i].protocol = WORD_SWAP(pMib->qosRuleArray[i].protocol);
		pMib->qosRuleArray[i].local_port_start = WORD_SWAP(pMib->qosRuleArray[i].local_port_start);
		pMib->qosRuleArray[i].local_port_end = WORD_SWAP(pMib->qosRuleArray[i].local_port_end);
		pMib->qosRuleArray[i].remote_port_start = WORD_SWAP(pMib->qosRuleArray[i].remote_port_start);
		pMib->qosRuleArray[i].remote_port_end = WORD_SWAP(pMib->qosRuleArray[i].remote_port_end);
	}
#endif

#ifdef QOS_BY_BANDWIDTH
	pMib->qosManualUplinkSpeed = DWORD_SWAP(pMib->qosManualUplinkSpeed);
	pMib->qosManualDownLinkSpeed = DWORD_SWAP(pMib->qosManualDownLinkSpeed);

	for (i=0; i<pMib->qosRuleNum; i++) {
		pMib->qosRuleArray[i].bandwidth = DWORD_SWAP(pMib->qosRuleArray[i].bandwidth);
	}
#endif
}
#endif

// added by rock /////////////////////////////////////////
#ifdef VOIP_SUPPORT
	voip_mibtbl_swap_value(&pMib->voipCfgParam);
#endif
}
#else
static int _mib_swap_value(const mib_table_entry_T *mib, void *data)
{
	short *pShort;
	int *pInt;

	switch (mib->type)
	{
	case WORD_T:
		pShort = (short *) data;
		*pShort = htons(*pShort);
		break;
	case DWORD_T:
		pInt = (int *) data;
		*pInt = htonl(*pInt);
		break;
	default:
		break;
	}

	return 0;
}

static int _mibtbl_swap_value(const mib_table_entry_T *mib_tbl, void *data, int offset)
{
	int i, j;
	const mib_table_entry_T *mib;
	int new_offset;

	for (i=0; mib_tbl[i].id; i++)
	{
		mib = &mib_tbl[i];
		new_offset = offset + mib->offset;
		for (j=0; j<(mib->total_size / mib->unit_size); j++)
		{
			if (mib->type >= TABLE_LIST_T)
			{
				if (_mibtbl_swap_value(mib->next_mib_table, data, new_offset) != 0)
				{
					fprintf(stderr, "MIB (%s, %d, %d) Error: swap failed\n",
						mib_tbl[i].name, mib_tbl[i].total_size, mib_tbl[i].unit_size);
					return -1;
				}
			}
			else
			{
				_mib_swap_value(mib, (void *)((int) data + new_offset));
			}
			new_offset += mib->unit_size;
		}
	}

	return 0;
}

void swap_mib_word_value(APMIB_Tp pMib)
{
	mib_table_entry_T *pmib_tl;

	pmib_tl = mib_get_table(CURRENT_SETTING);
	_mibtbl_swap_value(pmib_tl, pMib, 0);
#ifdef VOIP_SUPPORT
	voip_mibtbl_swap_value(&pMib->voipCfgParam);
#endif
}
#endif // if 0
#endif // _LITTLE_ENDIAN_

///////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
static int check_config_tag(unsigned char *data, int total_len)
{
	char tag_local[32],tag_config[32];
	memset(tag_local,0,sizeof(tag_local));
	apmib_get(MIB_CONFIG_TAG,tag_local);
	printf("tag_local(%s)\n",tag_local);
	if(strcmp(tag_local,"")==0) {
		return 1;
	}
	memset(tag_config,0,sizeof(tag_config));
	if(tlv_simple_mib_get(MIB_CONFIG_TAG,data,total_len,tag_config)<0)
	{
		return 0;
	}
	if(strcmp(tag_config,"")==0) {
		return 0;
	}
	if(strcmp(tag_local,tag_config)==0)
	{
		return 1;
	}
	return 0;
}
static int check_config_valid(unsigned char *data, int total_len)
{
	int len=0, status=1;
#ifdef HEADER_LEN_INT
	HW_PARAM_HEADER_Tp phwHeader;
#endif
	int isHdware=0;
	PARAM_HEADER_Tp pHeader;
#ifdef COMPRESS_MIB_SETTING
	COMPRESS_MIB_HEADER_Tp pCompHeader;
	unsigned char *expFile=NULL;
	unsigned int expandLen=0;
	int complen=0;
#endif
	unsigned char isValidfw = 0;
	char *ptr;
	do {
		if (
#ifdef COMPRESS_MIB_SETTING
			memcmp(&data[complen], COMP_HS_SIGNATURE, COMP_SIGNATURE_LEN) &&
			memcmp(&data[complen], COMP_DS_SIGNATURE, COMP_SIGNATURE_LEN) &&
			memcmp(&data[complen], COMP_CS_SIGNATURE, COMP_SIGNATURE_LEN)
#else
			memcmp(&data[len], CURRENT_SETTING_HEADER_TAG, TAG_LEN) &&
			memcmp(&data[len], CURRENT_SETTING_HEADER_FORCE_TAG, TAG_LEN) &&
			memcmp(&data[len], CURRENT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) &&
			memcmp(&data[len], DEFAULT_SETTING_HEADER_TAG, TAG_LEN) &&
			memcmp(&data[len], DEFAULT_SETTING_HEADER_FORCE_TAG, TAG_LEN) &&
			memcmp(&data[len], DEFAULT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) &&
			memcmp(&data[len], HW_SETTING_HEADER_TAG, TAG_LEN) &&
			memcmp(&data[len], HW_SETTING_HEADER_FORCE_TAG, TAG_LEN) &&
			memcmp(&data[len], HW_SETTING_HEADER_UPGRADE_TAG, TAG_LEN)
#endif
		) {
			if(isValidfw)
				break;
		}
	if(
	#ifdef COMPRESS_MIB_SETTING
		memcmp(&data[complen], COMP_HS_SIGNATURE, COMP_SIGNATURE_LEN)==0
	#else
		memcmp(&data[len], HW_SETTING_HEADER_TAG, TAG_LEN)==0 ||
		memcmp(&data[len], HW_SETTING_HEADER_FORCE_TAG, TAG_LEN)==0 ||
		memcmp(&data[len], HW_SETTING_HEADER_UPGRADE_TAG, TAG_LEN)
	#endif
	)
	{
		isHdware=1;
	}
	else
	{
		isHdware=0;
	}
#ifdef COMPRESS_MIB_SETTING
		pCompHeader =(COMPRESS_MIB_HEADER_Tp)&data[complen];
#ifdef _LITTLE_ENDIAN_
		pCompHeader->compRate = WORD_SWAP(pCompHeader->compRate);
		pCompHeader->compLen = DWORD_SWAP(pCompHeader->compLen);
#endif
		expFile=malloc(pCompHeader->compLen*pCompHeader->compRate);
		if (NULL==expFile) {
			printf("malloc for expFile error!!\n");
			return 0;
		}
		expandLen = Decode(data+complen+sizeof(COMPRESS_MIB_HEADER_T), pCompHeader->compLen, expFile);
#ifdef HEADER_LEN_INT
		if(isHdware)
			phwHeader = (HW_PARAM_HEADER_Tp)expFile;
		else
#endif
		pHeader = (PARAM_HEADER_Tp)expFile;
#else
#ifdef HEADER_LEN_INT
		if(isHdware)
			phwHeader = (HW_PARAM_HEADER_Tp)expFile;
		else
#endif
		pHeader = (PARAM_HEADER_Tp)&data[len];
#endif
#ifdef _LITTLE_ENDIAN_
#ifdef HEADER_LEN_INT
		if(isHdware)
			phwHeader->len = DWORD_SWAP(phwHeader->len);
		else
#endif
		pHeader->len = WORD_SWAP(pHeader->len);
#endif
#ifdef HEADER_LEN_INT
		if(isHdware)
			len += sizeof(HW_PARAM_HEADER_T);
		else
#endif
		len += sizeof(PARAM_HEADER_T);
#ifdef COMPRESS_MIB_SETTING
#ifdef HEADER_LEN_INT
			if(isHdware)
				ptr = (char *)(expFile+sizeof(HW_PARAM_HEADER_T));
			else
#endif
			ptr = (char *)(expFile+sizeof(PARAM_HEADER_T));
#else
			ptr = &data[len];
#endif
#ifdef COMPRESS_MIB_SETTING
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				DECODE_DATA(ptr, phwHeader->len);
			else
#endif
			DECODE_DATA(ptr, pHeader->len);
#endif
#ifdef HEADER_LEN_INT
			if(isHdware)
			{
				if ( !CHECKSUM_OK((unsigned char *)ptr, phwHeader->len)) {
				status = 0;
				break;
				}
			}
			else
#endif
			if ( !CHECKSUM_OK((unsigned char *)ptr, pHeader->len)) {
				status = 0;
				break;
			}
#ifdef COMPRESS_MIB_SETTING
			if(isHdware == 0)
			{
				status=check_config_tag(ptr,pHeader->len);
				if(0 == status) {
					break;
				}
			}
#endif
#ifdef COMPRESS_MIB_SETTING
			complen += pCompHeader->compLen+sizeof(COMPRESS_MIB_HEADER_T);
			if (expFile) {
				free(expFile);
				expFile=NULL;
			}
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				len += phwHeader->len;
			else
#endif
			len += pHeader->len;
#endif
			isValidfw=1;
			continue;
	}while (
#ifdef COMPRESS_MIB_SETTING
	(complen < total_len)
#else
	(len < total_len)
#endif
	);
	return status;
}
static int updateConfigIntoFlash(unsigned char *data, int total_len, int *pType, int *pStatus)
{
#ifdef CONFIG_NVRAM_APMIB
	*pType = *pStatus = 0;
#else
	int len=0, status=1, type=0, ver, force;
#ifdef HEADER_LEN_INT
	HW_PARAM_HEADER_Tp phwHeader;
	int isHdware=0;
#endif
	PARAM_HEADER_Tp pHeader;
#ifdef COMPRESS_MIB_SETTING
	COMPRESS_MIB_HEADER_Tp pCompHeader;
	unsigned char *expFile=NULL;
	unsigned int expandLen=0;
	int complen=0;
#endif
	char *ptr;
	unsigned char isValidfw = 0;

	do {
		if (
#ifdef COMPRESS_MIB_SETTING
			memcmp(&data[complen], COMP_HS_SIGNATURE, COMP_SIGNATURE_LEN) &&
			memcmp(&data[complen], COMP_DS_SIGNATURE, COMP_SIGNATURE_LEN) &&
			memcmp(&data[complen], COMP_CS_SIGNATURE, COMP_SIGNATURE_LEN)
#else
			memcmp(&data[len], CURRENT_SETTING_HEADER_TAG, TAG_LEN) &&
			memcmp(&data[len], CURRENT_SETTING_HEADER_FORCE_TAG, TAG_LEN) &&
			memcmp(&data[len], CURRENT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) &&
			memcmp(&data[len], DEFAULT_SETTING_HEADER_TAG, TAG_LEN) &&
			memcmp(&data[len], DEFAULT_SETTING_HEADER_FORCE_TAG, TAG_LEN) &&
			memcmp(&data[len], DEFAULT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) &&
			memcmp(&data[len], HW_SETTING_HEADER_TAG, TAG_LEN) &&
			memcmp(&data[len], HW_SETTING_HEADER_FORCE_TAG, TAG_LEN) &&
			memcmp(&data[len], HW_SETTING_HEADER_UPGRADE_TAG, TAG_LEN)
#endif
		) {
			if (isValidfw == 1)
				break;
		}
#ifdef HEADER_LEN_INT
	if(
	#ifdef COMPRESS_MIB_SETTING
		memcmp(&data[complen], COMP_HS_SIGNATURE, COMP_SIGNATURE_LEN)==0
	#else
		memcmp(&data[len], HW_SETTING_HEADER_TAG, TAG_LEN)==0 ||
		memcmp(&data[len], HW_SETTING_HEADER_FORCE_TAG, TAG_LEN)==0 ||
		memcmp(&data[len], HW_SETTING_HEADER_UPGRADE_TAG, TAG_LEN)
	#endif
	)
	{
		isHdware=1;
	}
#endif
#ifdef COMPRESS_MIB_SETTING
		pCompHeader =(COMPRESS_MIB_HEADER_Tp)&data[complen];
#ifdef _LITTLE_ENDIAN_
		pCompHeader->compRate = WORD_SWAP(pCompHeader->compRate);
		pCompHeader->compLen = DWORD_SWAP(pCompHeader->compLen);
#endif
		/*decompress and get the tag*/
		expFile=malloc(pCompHeader->compLen*pCompHeader->compRate);
		if (NULL==expFile) {
			printf("malloc for expFile error!!\n");
			return 0;
		}
		expandLen = Decode(data+complen+sizeof(COMPRESS_MIB_HEADER_T), pCompHeader->compLen, expFile);
#ifdef HEADER_LEN_INT
		if(isHdware)
			phwHeader = (HW_PARAM_HEADER_Tp)expFile;
		else
#endif
		pHeader = (PARAM_HEADER_Tp)expFile;
#else
#ifdef HEADER_LEN_INT
		if(isHdware)
			phwHeader = (HW_PARAM_HEADER_Tp)expFile;
		else
#endif
		pHeader = (PARAM_HEADER_Tp)&data[len];
#endif

#ifdef _LITTLE_ENDIAN_
#ifdef HEADER_LEN_INT
		if(isHdware)
			phwHeader->len = DWORD_SWAP(phwHeader->len);
		else
#endif
		pHeader->len = WORD_SWAP(pHeader->len);
#endif
#ifdef HEADER_LEN_INT
		if(isHdware)
			len += sizeof(HW_PARAM_HEADER_T);
		else
#endif
		len += sizeof(PARAM_HEADER_T);

		if ( sscanf((char *)&pHeader->signature[TAG_LEN], "%02d", &ver) != 1)
			ver = -1;

		force = -1;
		if ( !memcmp(pHeader->signature, CURRENT_SETTING_HEADER_TAG, TAG_LEN) ) {
			isValidfw = 1;
			force = 1; // update
		}
		else if ( !memcmp(pHeader->signature, CURRENT_SETTING_HEADER_FORCE_TAG, TAG_LEN)) {
			isValidfw = 1;
			force = 2; // force
		}
		else if ( !memcmp(pHeader->signature, CURRENT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN)) {
			isValidfw = 1;
			force = 0; // upgrade
		}

		if ( force >= 0 ) {
#if 0
			if ( !force && (ver < CURRENT_SETTING_VER || // version is less than current
				(pHeader->len < (sizeof(APMIB_T)+1)) ) { // length is less than current
				status = 0;
				break;
			}
#endif

#ifdef COMPRESS_MIB_SETTING
#ifdef HEADER_LEN_INT
			if(isHdware)
				ptr = (char *)(expFile+sizeof(HW_PARAM_HEADER_T));
			else
#endif
			ptr = (char *)(expFile+sizeof(PARAM_HEADER_T));
#else
			ptr = &data[len];
#endif

#ifdef COMPRESS_MIB_SETTING
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				DECODE_DATA(ptr, phwHeader->len);
			else
#endif
			DECODE_DATA(ptr, pHeader->len);
#endif
#ifdef HEADER_LEN_INT
			if(isHdware)
			{
					if ( !CHECKSUM_OK((unsigned char *)ptr, phwHeader->len)) {
						status = 0;
						break;
					}
			}
			else
#endif
			if ( !CHECKSUM_OK((unsigned char *)ptr, pHeader->len)) {
				status = 0;
				break;
			}
#ifdef _LITTLE_ENDIAN_
			swap_mib_word_value((APMIB_Tp)ptr);
#endif

// added by rock /////////////////////////////////////////
#ifdef VOIP_SUPPORT
		#ifndef VOIP_SUPPORT_TLV_CFG
			flash_voip_import_fix(&((APMIB_Tp)ptr)->voipCfgParam, &pMib->voipCfgParam);
#endif
#endif

#ifdef COMPRESS_MIB_SETTING
			apmib_updateFlash(CURRENT_SETTING, (char *)&data[complen], pCompHeader->compLen+sizeof(COMPRESS_MIB_HEADER_T), force, ver);
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				apmib_updateFlash(CURRENT_SETTING, ptr, phwHeader->len-1, force, ver);
			else
#endif
			apmib_updateFlash(CURRENT_SETTING, ptr, pHeader->len-1, force, ver);
#endif

#ifdef COMPRESS_MIB_SETTING
			complen += pCompHeader->compLen+sizeof(COMPRESS_MIB_HEADER_T);
			if (expFile) {
				free(expFile);
				expFile=NULL;
			}
#else

#ifdef HEADER_LEN_INT
			if(isHdware)
				len += phwHeader->len;
			else
#endif
			len += pHeader->len;
#endif
			type |= CURRENT_SETTING;
			continue;
		}


		if ( !memcmp(pHeader->signature, DEFAULT_SETTING_HEADER_TAG, TAG_LEN) ) {
			isValidfw = 1;
			force = 1;	// update
		}
		else if ( !memcmp(pHeader->signature, DEFAULT_SETTING_HEADER_FORCE_TAG, TAG_LEN) ) {
			isValidfw = 1;
			force = 2;	// force
		}
		else if ( !memcmp(pHeader->signature, DEFAULT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) ) {
			isValidfw = 1;
			force = 0;	// upgrade
		}

		if ( force >= 0 ) {
#if 0
			if ( (ver < DEFAULT_SETTING_VER) || // version is less than current
				(pHeader->len < (sizeof(APMIB_T)+1)) ) { // length is less than current
				status = 0;
				break;
			}
#endif

#ifdef COMPRESS_MIB_SETTING
#ifdef HEADER_LEN_INT
			if(isHdware)
				ptr = (char *)(expFile+sizeof(HW_PARAM_HEADER_T));
			else
#endif
			ptr = (char *)(expFile+sizeof(PARAM_HEADER_T));
#else
			ptr = &data[len];
#endif

#ifdef COMPRESS_MIB_SETTING
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				DECODE_DATA(ptr, phwHeader->len);
			else
#endif
			DECODE_DATA(ptr, pHeader->len);
#endif
#ifdef HEADER_LEN_INT
			if(isHdware)
			{
				if ( !CHECKSUM_OK((unsigned char *)ptr, phwHeader->len)) {
				status = 0;
				break;
				}
			}
			else
#endif
			if ( !CHECKSUM_OK((unsigned char *)ptr, pHeader->len)) {
				status = 0;
				break;
			}

#ifdef _LITTLE_ENDIAN_
			swap_mib_word_value((APMIB_Tp)ptr);
#endif

// added by rock /////////////////////////////////////////
#ifdef VOIP_SUPPORT
		#ifndef VOIP_SUPPORT_TLV_CFG
			flash_voip_import_fix(&((APMIB_Tp)ptr)->voipCfgParam, &pMibDef->voipCfgParam);
#endif
#endif

#ifdef COMPRESS_MIB_SETTING
			apmib_updateFlash(DEFAULT_SETTING, (char *)&data[complen], pCompHeader->compLen+sizeof(COMPRESS_MIB_HEADER_T), force, ver);
#else

#ifdef HEADER_LEN_INT
			if(isHdware)
				apmib_updateFlash(DEFAULT_SETTING, ptr, phwHeader->len-1, force, ver);
			else
#endif
			apmib_updateFlash(DEFAULT_SETTING, ptr, pHeader->len-1, force, ver);
#endif

#ifdef COMPRESS_MIB_SETTING
			complen += pCompHeader->compLen+sizeof(COMPRESS_MIB_HEADER_T);
			if (expFile) {
				free(expFile);
				expFile=NULL;
			}
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				len += phwHeader->len;
			else
#endif
			len += pHeader->len;
#endif
			type |= DEFAULT_SETTING;
			continue;
		}

		if ( !memcmp(pHeader->signature, HW_SETTING_HEADER_TAG, TAG_LEN) ) {
			isValidfw = 1;
			force = 1;	// update
		}
		else if ( !memcmp(pHeader->signature, HW_SETTING_HEADER_FORCE_TAG, TAG_LEN) ) {
			isValidfw = 1;
			force = 2;	// force
		}
		else if ( !memcmp(pHeader->signature, HW_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) ) {
			isValidfw = 1;
			force = 0;	// upgrade
		}

		if ( force >= 0 ) {
#if 0
			if ( (ver < HW_SETTING_VER) || // version is less than current
				(pHeader->len < (sizeof(HW_SETTING_T)+1)) ) { // length is less than current
				status = 0;
				break;
			}
#endif
#ifdef COMPRESS_MIB_SETTING
#ifdef HEADER_LEN_INT
			if(isHdware)
				ptr = (char *)(expFile+sizeof(HW_PARAM_HEADER_T));
			else
#endif
			ptr = (char *)(expFile+sizeof(PARAM_HEADER_T));
#else
			ptr = &data[len];
#endif


#ifdef COMPRESS_MIB_SETTING
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				DECODE_DATA(ptr, phwHeader->len);
			else
#endif
			DECODE_DATA(ptr, pHeader->len);
#endif
#ifdef HEADER_LEN_INT
			if(isHdware)
			{
				if ( !CHECKSUM_OK((unsigned char *)ptr, phwHeader->len)) {
				status = 0;
				break;
				}
			}
			else
#endif
			if ( !CHECKSUM_OK((unsigned char *)ptr, pHeader->len)) {
				status = 0;
				break;
			}
#ifdef COMPRESS_MIB_SETTING
			apmib_updateFlash(HW_SETTING, (char *)&data[complen], pCompHeader->compLen+sizeof(COMPRESS_MIB_HEADER_T), force, ver);
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				apmib_updateFlash(HW_SETTING, ptr, phwHeader->len-1, force, ver);
			else
#endif
			apmib_updateFlash(HW_SETTING, ptr, pHeader->len-1, force, ver);
#endif

#ifdef COMPRESS_MIB_SETTING
			complen += pCompHeader->compLen+sizeof(COMPRESS_MIB_HEADER_T);
			if (expFile) {
				free(expFile);
				expFile=NULL;
			}
#else
#ifdef HEADER_LEN_INT
			if(isHdware)
				len += phwHeader->len;
			else
#endif
			len += pHeader->len;
#endif

			type |= HW_SETTING;
			continue;
		}
	}
#ifdef COMPRESS_MIB_SETTING
	while (complen < total_len);

	if (expFile) {
		free(expFile);
		expFile=NULL;
	}
#else
	while (len < total_len);
#endif

	*pType = type;
	*pStatus = status;
#ifdef COMPRESS_MIB_SETTING
	return complen;
#else
	return len;
#endif
#endif
}

///////////////////////////////////////////////////////////////////////////////
/*
void sig_alm(int signo)
{
	if(isUpgrade_OK ==1){
		reboot( RB_AUTOBOOT);
		return;
	}

}
*/
///////////////////////////////////////////////////////////////////////////////
#ifdef CONFIG_SNMP
void formSetSNMP(request *wp, char *path, char *query)
{

		char *submitUrl;
        char *strValue;
        int     snmpEnabled;
        struct in_addr ip;
        char tmpBuf[100];
		submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page

        strValue = (char *)req_get_cstream_var(wp, ("snmp_enabled"), "");
		if(!strcmp(strValue, "ON")){
                snmpEnabled = 1;
        } else {
                snmpEnabled = 0;
        }
        if (!apmib_set(MIB_SNMP_ENABLED, (void *)&snmpEnabled)) {
                strcpy(tmpBuf, ("Set SNMP enabled error!"));
                goto setErr;
        }

        strValue = (char *)req_get_cstream_var(wp, ("snmp_name"), "");
        if (strValue[0]) {
                if (!apmib_set(MIB_SNMP_NAME, (void *)strValue)) {
                        strcpy(tmpBuf, ("Set SNMP location error!"));
                        goto setErr;
                }
        }

        strValue = (char *)req_get_cstream_var(wp, ("snmp_location"), "");
        if (strValue[0]) {
                if (!apmib_set(MIB_SNMP_LOCATION, (void *)strValue)) {
                        strcpy(tmpBuf, ("Set SNMP location error!"));
                        goto setErr;
                }
        }

        strValue = (char *)req_get_cstream_var(wp, ("snmp_contact"), "");
        if (strValue[0]) {
                if (!apmib_set(MIB_SNMP_CONTACT, (void *)strValue)) {
                        strcpy(tmpBuf, ("Set SNMP contact error!"));
                        goto setErr;
                }
        }

        strValue = (char *)req_get_cstream_var(wp, ("snmp_rwcommunity"), "");
        if (strValue[0]) {
                if (!apmib_set(MIB_SNMP_RWCOMMUNITY, (void *)strValue)) {
                        strcpy(tmpBuf, ("Set SNMP community error!"));
                        goto setErr;
                }
        }


        strValue = (char *)req_get_cstream_var(wp, ("snmp_rocommunity"), "");
        if (strValue[0]) {
                if (!apmib_set(MIB_SNMP_ROCOMMUNITY, (void *)strValue)) {
                        strcpy(tmpBuf, ("Set SNMP community error!"));
                        goto setErr;
                }
        }

        strValue = (char *)req_get_cstream_var(wp, ("snmp_trap1"), "");
        if (strValue[0]) {
                if (!inet_aton(strValue, &ip) ) {
                        strcpy(tmpBuf, ("Invalid Trap Receiver 1 IP-address value!"));
                        goto setErr;
                }
                if (!apmib_set(MIB_SNMP_TRAP_RECEIVER1, (void *)&ip)) {
                        strcpy(tmpBuf, ("Set Trap Receiver 1 IP-address error!"));
                        goto setErr;
                }
        }

        strValue = (char *)req_get_cstream_var(wp, ("snmp_trap2"), "");
        if (strValue[0]) {
                if (!inet_aton(strValue, &ip) ) {
                        strcpy(tmpBuf, ("Invalid Trap Receiver 2 IP-address value!"));
                        goto setErr;
                }
                if (!apmib_set(MIB_SNMP_TRAP_RECEIVER2, (void *)&ip)) {
                        strcpy(tmpBuf, ("Set Trap Receiver 2 IP-address error!"));
                        goto setErr;
                }
        }

        strValue = (char *)req_get_cstream_var(wp, ("snmp_trap3"), "");
        if (strValue[0]) {
                if (!inet_aton(strValue, &ip) ) {
                        strcpy(tmpBuf, ("Invalid Trap Receiver 3 IP-address value!"));
                        goto setErr;
                }
                if (!apmib_set(MIB_SNMP_TRAP_RECEIVER3, (void *)&ip)) {
                        strcpy(tmpBuf, ("Set Trap Receiver 3 IP-address error!"));
                        goto setErr;
                }
        }

        apmib_update_web(CURRENT_SETTING);

#ifndef NO_ACTION
        run_init_script("all");
#endif
		OK_MSG(submitUrl);
        return;

setErr:
		ERR_MSG(tmpBuf);
}
#endif /* CONFIG_SNMP */

#ifdef __DAVO__
struct mcast_mbr {
	struct list_head list;
	struct in_addr address;
	uint8_t version;
	uint8_t port;
	uint16_t exclude;
};

struct mcast_group {
	struct list_head list;
	struct in_addr group;
	struct list_head mbrlist;
};

static void mcast_group_free(struct list_head *head)
{
	while(!list_empty(head)) {
		struct mcast_group *g =
			list_entry(head->next, struct mcast_group, list);
		while (!list_empty(&g->mbrlist)) {
			struct mcast_mbr *m =
				list_entry(g->mbrlist.next, struct mcast_mbr, list);
			list_del(&m->list);
			free(m);
		}
		list_del(&g->list);
		free(g);
	}
}

static int mcast_group_add(struct list_head *head, uint32_t addr)
{
	struct mcast_group *gp;
	struct list_head *pos;

	list_for_each(pos, head) {
		gp = list_entry(pos, struct mcast_group, list);
		if (gp->group.s_addr == addr)
			return 0;
	}

	gp = (struct mcast_group *)malloc(sizeof(*gp));
	if (gp == NULL)
		return -1;

	gp->group.s_addr = addr;
	INIT_LIST_HEAD(&gp->mbrlist);
	list_add_tail(&gp->list, head);
	return 1;
}

static struct mcast_mbr *
mcast_mbr_add(struct list_head *head, uint32_t group, uint32_t addr)
{
	struct mcast_group *g = NULL;
	struct mcast_mbr *m;
	struct list_head *pos, *pos2;

	list_for_each(pos, head) {
		g = list_entry(pos, struct mcast_group, list);
		if (g->group.s_addr == group) {
			list_for_each(pos2, &g->mbrlist) {
				m = list_entry(pos2, struct mcast_mbr, list);
				if (m->address.s_addr == addr)
					return m;
			}
			break;
		}
	}

	if (pos == head)
		return NULL;

	m = (struct mcast_mbr *)malloc(sizeof(*m));
	if (m != NULL) {
		m->address.s_addr = addr;
		list_add_tail(&m->list, &g->mbrlist);
	}
	return m;
}

static int read_mbr(FILE *f, uint32_t group, struct list_head *mc)
{
	int count = 0;
	char *argv[12], *p;
	char buf[128];
	struct mcast_mbr *mbr;

	while (fgets(buf, sizeof(buf), f)) {
		if (parse_line(buf, argv, 12, " (,:\\\r\n") != 7 ||
		    !(p = strchr(argv[0], '>')))
			break;
		mbr = mcast_mbr_add(mc, group, inet_addr(&p[1]));
		if (mbr != NULL) {
			mbr->port = atoi(argv[3])+1;
			mbr->version = argv[4][5] - '0';
			mbr->exclude = atoi(argv[6]);
			count += 1;
		}
	}
	return count;
}

static int read_group(FILE *f, struct list_head *mc)
{
	int count = 0;
	char *argv[12], *p;
	char buf[128];
	uint32_t addr;

	for (p = NULL; fgets(buf, sizeof(buf), f); )
		if (!strncmp(buf, "igmp list:", strlen("igmp list:"))) {
			p = buf;
			break;
		}

	if (p != NULL) {
		while (fgets(buf, sizeof(buf), f)) {
			if (parse_line(buf, argv, 12, " ,:\\\r\n") != 4 ||
			    strcmp("Group", argv[1]))
				break;
			addr = inet_addr(argv[3]);
			if (IN_MULTICAST(ntohl(addr)) &&
			    mcast_group_add(mc, addr) == 1) {
				read_mbr(f, addr, mc);
				count++;
			}
		}
	}
	return count;
}

static int read_mcast(struct list_head *mc, const char *path)
{
	FILE *f;
	char *argv[12];
	char buf[128];

	if ((f = fopen(path, "r")) == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), f)) {
		if (parse_line(buf, argv, 12, " ,:\\\r\n") > 7 &&
		    !strcmp(argv[0], "module") && !strcmp(argv[4], "eth*")) {
			read_group(f, mc);
		}
	}

	fclose(f);
	return 0;
}

static int if_readgroup(struct list_head *h, const char *ifname)
{
	FILE *f;
	char *argv[12];
	char buf[128];
	uint32_t addr;
	int num_group, count = 0;

	if ((f = fopen("/proc/net/igmp", "r")) == NULL)
		return 0;

	fgets(buf, sizeof(buf), f);
	while (fgets(buf, sizeof(buf), f)) {
		if (parse_line(buf, argv, 12, " \t\r\n") < 4)
			continue;
		if (strcmp(argv[1], ifname))
			continue;
		for (num_group = strtol(argv[3], NULL, 10);
		     num_group > 0 && fgets(buf, sizeof(buf), f) != NULL;
		     num_group--) {
			if (parse_line(buf, argv, 12, " \t\r\n") < 4)
				continue;
			/* reporter > 0 */
			if (strtol(argv[3], NULL, 10) > 0) {
				addr = strtoul(argv[0], NULL, 16);
				if (IN_MULTICAST(addr) &&
				    mcast_group_add(h, htonl(addr)) == 1) {
					count++;
				}
			}
		}
		break;
	}

	fclose(f);
	return count;
}

static int is_joined_to_if(struct list_head *h, uint32_t addr)
{
	struct list_head *pos;

	list_for_each(pos, h) {
		struct mcast_group *g = list_entry(pos, struct mcast_group, list);
		if (g->group.s_addr == addr)
			return 1;
	}

	return 0;
}

static void arp_lookup(uint32_t nip, char *buf, int len)
{
	FILE *f;
	char *argv[12];
	char tmp[128];

	if ((f = fopen("/proc/net/arp", "r"))) {
		fgets(tmp, sizeof(tmp), f);	// skip title
		while (fgets(tmp, sizeof(tmp), f)) {
			if (parse_line(tmp, argv, 12, " \t\r\n") != 6)
				break;
			if (inet_addr(argv[0]) == nip) {
				snprintf(buf, len, "%s", argv[3]);
				break;
			}
		}
		fclose(f);
	}
}

#define LOCAL_MCAST(x)  (((x) &0xFFFFFF00) == 0xE0000000)

int igmpBlockStatus(request *wp, int argc, char **argv)
{
	FILE *fp;
	int nBytesSent=0;
	char *port_status_str;
	int port_status[4];
	int i, enable=0, thresh=0, period=0, relay=0, drop=0;

	fp = fopen("proc/dv_igmp_block", "r");
	if(fp){
		fscanf(fp, "%d\n", &enable);

		for(i=0; i<4; i++){
			fscanf(fp, "%d %d %d %d %d\n", &port_status[i], &period, &thresh, &relay, &drop);

			if(port_status[i])
				port_status_str = "차단";
			else
				port_status_str = "사용중";

			nBytesSent += req_format_write(wp, "<tr bgcolor=#DDDDDD align='center'><td>LAN%d</td>\
			<td>%d</td><td>%d</td><td>%s</td><td><input type='submit' value='강제해제' name='lan%d_control' ></td>\
			</tr>\n", i+1, relay, drop, port_status_str, i+1);
		}
		fclose(fp);

		nBytesSent += req_format_write(wp, "</table>");
		nBytesSent += req_format_write(wp, "<input type='hidden' value='%d' name='port1_status'>\n",port_status[0]);
		nBytesSent += req_format_write(wp, "<input type='hidden' value='%d' name='port2_status'>\n",port_status[1]);
		nBytesSent += req_format_write(wp, "<input type='hidden' value='%d' name='port3_status'>\n",port_status[2]);
		nBytesSent += req_format_write(wp, "<input type='hidden' value='%d' name='port4_status'>\n",port_status[3]);
	} else {
		memset(port_status, 0, sizeof(port_status));
		for(i=0; i<4; i++){
			if(port_status[i])
				port_status_str = "차단";
			else
				port_status_str = "사용중";

			nBytesSent += req_format_write(wp, "<tr bgcolor=#DDDDDD align='center'><td>LAN%d</td>\
			<td>%d</td><td>%d</td><td>%s</td><td><input type='submit' value='강제해제' name='lan%d_control' ></td>\
			</tr>\n", i+1, relay, drop, port_status_str, i+1);
		}
		nBytesSent += req_format_write(wp, "</table>");
		nBytesSent += req_format_write(wp, "<input type='hidden' value='%d' name='port1_status'>\n",port_status[0]);
		nBytesSent += req_format_write(wp, "<input type='hidden' value='%d' name='port2_status'>\n",port_status[1]);
		nBytesSent += req_format_write(wp, "<input type='hidden' value='%d' name='port3_status'>\n",port_status[2]);
		nBytesSent += req_format_write(wp, "<input type='hidden' value='%d' name='port4_status'>\n",port_status[3]);
	}

	return nBytesSent;
}

int igmp_snoop_table(request *wp, int argc, char **argv)
{
	struct mcast_group *g;
	struct mcast_mbr *m;
	struct mcast_mbr *mbr[5];
	struct list_head *pos, *pos2;
	struct list_head mc;
	struct list_head upif_grp;
	uint32_t i = 0, ii, tmp, nbyte = 0;
	uint16_t age;
	char haddr[32];
	int opmode = -1;

	INIT_LIST_HEAD(&mc);
	INIT_LIST_HEAD(&upif_grp);
	apmib_get(MIB_OP_MODE, (void *)&opmode);
	if (opmode == 0)
		if_readgroup(&upif_grp, "eth1");
	read_mcast(&mc, "/proc/rtl865x/igmp");
	list_for_each(pos, &mc) {
		g = list_entry(pos, struct mcast_group, list);
		tmp = ntohl(g->group.s_addr);
		// SSDP (Simple Service Discovery Protocol): 239.255.255.250
		// mDNS (Multicast DNS): 224.0.0.251
		// Local Peer Discovery: 239.192.152.143
		if (tmp == 0xeffffffa || tmp == 0xe00000fb || tmp == 0xefc0988f || LOCAL_MCAST(tmp))
			continue;
		if (!list_empty(&upif_grp) && !is_joined_to_if(&upif_grp, g->group.s_addr))
			continue;
		tmp = 0;
		memset(mbr, 0, sizeof(mbr));
		list_for_each(pos2, &g->mbrlist) {
			m = list_entry(pos2, struct mcast_mbr, list);
			if (m->port >= ARRAY_SIZE(mbr))
				continue;
			tmp |= (1 << m->port);
			if (mbr[m->port] == NULL || mbr[m->port]->exclude < m->exclude)
				mbr[m->port] = m;
		}

		if (tmp & 0x1E) {
			nbyte += req_format_write(wp, "<tr align='center' bgcolor='#DDDDDD'>\n");
			nbyte += req_format_write(wp, "<td>%d</td>\n", ++i);
			nbyte += req_format_write(wp, "<td>%s</td>\n", inet_ntoa(g->group));
			age = 0;
			for (ii = 1; ii < ARRAY_SIZE(mbr); ii++) {
				if ((m = mbr[ii]) != NULL) {
					strcpy(haddr, "N/A");
					arp_lookup(m->address.s_addr, haddr, sizeof(haddr));
					nbyte += req_format_write(wp, "<td width=\"60\" height=\"25\" bgcolor='#DDDDDD'>\n");
					nbyte += req_format_write(wp, "<input type=\"button\" ");
					nbyte += req_format_write(wp, "value=\"JOIN\" name=\"showJoin\" onClick=\""
							       "showJoinClick('%d|%u.%u.%u.%u|%u.%u.%u.%u|%s|')\"></td>\n",
							   ii, NIPQUAD(g->group), NIPQUAD(m->address), haddr);
					if (age < m->exclude)
						age = m->exclude;
				} else
					nbyte += req_format_write(wp, "<td> </td>\n");
			}
			nbyte += req_format_write(wp, "<td>%u</td>\n", age);
			nbyte += req_format_write(wp, "</tr>\n");
		}
	}

	mcast_group_free(&mc);
	if (i == 0) {
		nbyte += req_format_write(wp, "<tr align='center' bgcolor='#DDDDDD'>\n");
		nbyte += req_format_write(wp, "<td>---</td><td>---</td><td>---</td><td>---</td><td>---</td><td>---</td><td>---</td>\n");
		nbyte += req_format_write(wp, "</tr>\n");
	}

	nbyte += req_format_write(wp, "   </table>\n");
	return nbyte;
}

static int str_masking_check(char *check_str)
{
	int i, len, ret;

	len = strlen(check_str);
	for (i = 0; i < len; i++) {
		if (check_str[i] != '*') {
			break;
		}
	}

	if (i != len) {
		ret = 1;
	} else {
		ret = 0;
	}
	return ret;
}

void formHolepunchSet(request * wp, char *path, char *query)
{
	char *strVal, *submitUrl, *uforce;
	int intVal;

	if (wp->superUser != 1)
		return;

	apmib_set_hist_clear();
	submitUrl = req_get_cstream_var(wp, "submit-url", "");	// hidden page

	strVal = req_get_cstream_var(wp, ("holepunch_enabled"), "");
	if (!strcmp(strVal, "ON"))
		apmib_nvram_set("x_holepunch_enabled", "1");
	else
		apmib_nvram_set("x_holepunch_enabled", "0");

	strVal = req_get_cstream_var(wp, ("holepunch_server"), "");
	if (strVal[0]) {
		if (str_masking_check(strVal) == 1) {
			apmib_nvram_set("x_holepunch_cserver", strVal);
		}
	}

	strVal = req_get_cstream_var(wp, ("holepunch_port"), "");
	if (strVal[0]) {
		if (str_masking_check(strVal) == 1) {
			apmib_nvram_set("x_holepunch_cport", strVal);
		}
	}
	web_config_trace(5, 4);		/* management/holepunch */
	nvram_commit();
	need_reboot = 1;
	OK_MSG("/skb_holepunch.htm");
	return;

 setErr:
	ERR_MSG("설정을 확인해주시기 바랍니다.");
}

void formSNMP(request *wp, char *path, char *query)
{
	char *submitUrl, *tmpStr;
	char get_community[12], set_community[12], buf[12];
	int enabled = 0, get_enable = 0, set_enable = 0, get_type = 0, set_type = 0;

	if (wp->superUser != 1)
		return;

	apmib_set_hist_clear();
	submitUrl = req_get_cstream_var(wp, ("submit-url"), (""));	// hidden page

	tmpStr = req_get_cstream_var(wp, ("snmpEnable"), (""));
	if (!strcmp(tmpStr, "ON"))
		enabled = 1;
	else
		enabled = 0;

	tmpStr = req_get_cstream_var(wp, ("getsnmpEnable"), (""));
	if (!strcmp(tmpStr, "ON"))
		get_enable = 1;
	else
		get_enable = 0;

	tmpStr = req_get_cstream_var(wp, ("setsnmpEnable"), (""));
	if (!strcmp(tmpStr, "ON"))
		set_enable = 1;
	else
		set_enable = 0;

	tmpStr = req_get_cstream_var(wp, ("getType"), (""));
	if (!strcmp(tmpStr, "write_only"))
		get_type = 1;
	else if (!strcmp(tmpStr, "read_only"))
		get_type = 0;
	else {
		nvram_get_r_def("x_SNMP_COM1", buf, sizeof(buf), "1_0");
		get_type = (buf[2] == '0') ? 0 : 1;
	}

	tmpStr = req_get_cstream_var(wp, ("setType"), (""));
	if (!strcmp(tmpStr, "read_only"))
		set_type = 0;
	else if (!strcmp(tmpStr, "write_only"))
		set_type = 1;
	else {
		nvram_get_r_def("x_SNMP_COM2", buf, sizeof(buf), "1_0");
		set_type = (buf[2] == '1') ? 1 : 0;
	}

	snprintf(get_community, sizeof(get_community), "%d_%d", get_enable, get_type);
	snprintf(set_community, sizeof(set_community), "%d_%d", set_enable, set_type);
	apmib_nvram_set("x_SNMP_COM1", get_community);
	apmib_nvram_set("x_SNMP_COM2", set_community);

	if (enabled) {
		apmib_nvram_set("x_SNMP_ENABLE", "1");
		if ((tmpStr = req_get_cstream_var(wp, ("getCom"), ("iptvshro^_"))) &&
		    strcmp("********", tmpStr)) {
			apmib_nvram_set("x_SNMP_GET_COMMUNITY", tmpStr);
		}

		if ((tmpStr = req_get_cstream_var(wp, ("setCom"), ("iptvshrw^_"))) &&
		    strcmp("********", tmpStr)) {
			apmib_nvram_set("x_SNMP_SET_COMMUNITY", tmpStr);
		}
		tmpStr = req_get_cstream_var(wp, ("snmpTrapEnable"), (""));
		if (tmpStr[0] && !strcasecmp(tmpStr, "ON")) {
			apmib_nvram_set("x_SNMP_TRAP_ENABLE", "1");
			if ((tmpStr = req_get_cstream_var(wp, ("trapCommunity"), ("iptvshrw^_"))) &&
			    strcmp("********", tmpStr))
				apmib_nvram_set("x_SNMP_TRAP_COMMUNITY", tmpStr);
			if ((tmpStr = req_get_cstream_var(wp, ("trapServer"), ("iptvsh-trap.skbroadband.com")))
			    && strcmp("********", tmpStr))
				apmib_nvram_set("x_SNMP_TRAP_SERVER", tmpStr);
			if ((tmpStr = req_get_cstream_var(wp, ("trapServer2"), ("iptvap-trap.skbroadband.com")))
			    && strcmp("********", tmpStr))
				apmib_nvram_set("x_WIFI_TRAP_SERVER", tmpStr);
		} else {
			apmib_nvram_set("x_SNMP_TRAP_ENABLE", "0");
		}
	} else {
		apmib_nvram_set("x_SNMP_ENABLE", "0");
	}
	web_config_trace(5, 16);	/* management/snmp */
	nvram_commit();
#ifdef __DAVO__
	need_reboot = 1;
	OK_MSG("/skb_snmp.htm");
#else
	system("killall snmp");
	//unlink("/var/run/snmp_agentd.pid");
	if (enabled)
		system("snmp -a s");

	send_redirect_perm(wp, "/skb_snmp.htm");
#endif
	//OK_MSG(submitUrl);
	return;
}
#endif
///////////////////////////////////////////////////////////////////////////////
/* rewritten in private.c - 2015-04-13 14:44 young */
#ifndef __DAVO__
void formSaveConfig(request *wp, char *path, char *query)
{
	char tmpBuf[200];
	char *strRequest;
	char *buf, *ptr=NULL;
	unsigned char checksum;
	int len, len1;
	//char tmpBuf[200];
	CONFIG_DATA_T type=0;
	//char *submitUrl;
	char lan_ip_buf[30], lan_ip[30];

	len1 = sizeof(PARAM_HEADER_T) + sizeof(APMIB_T) + sizeof(checksum) + 100;  // 100 for expansion
	len = csHeader.len;
#ifdef _LITTLE_ENDIAN_
#ifdef VOIP_SUPPORT
	// rock: don't need swap here
	// 1. write to private space (ex: flash)
	// 2. read from private space (ex: flash)
#else
	len  = WORD_SWAP(len);
#endif
#endif
	len += sizeof(PARAM_HEADER_T) + 100;
	if (len1 > len)
		len = len1;

	buf = malloc(len);
	if ( buf == NULL ) {
		strcpy(tmpBuf, "Allocate buffer failed!");
		goto back;
	}

	strRequest = req_get_cstream_var(wp, ("save-cs"), "");
	if (strRequest[0])
		type |= CURRENT_SETTING;

	strRequest = req_get_cstream_var(wp, ("save"), "");
	if (strRequest[0])
		type |= CURRENT_SETTING;

	strRequest = req_get_cstream_var(wp, ("save-hs"), "");
	if (strRequest[0])
		type |= HW_SETTING;

	strRequest = req_get_cstream_var(wp, ("save-ds"), "");
	if (strRequest[0])
		type |= DEFAULT_SETTING;

	strRequest = req_get_cstream_var(wp, ("save-all"), "");
	if (strRequest[0])
		type |= HW_SETTING | DEFAULT_SETTING | CURRENT_SETTING;
	if (type) {
		send_redirect_perm(wp, "/config.dat");
		return;
	}

	strRequest = req_get_cstream_var(wp, ("reset"), "");
	if (strRequest[0] && strcmp(strRequest,"Reset") == 0) {
#ifdef RTL_DEF_SETTING_IN_FW
		system("flash reset");
#else
		if ( !apmib_updateDef() ) {
			free(ptr);
			strcpy(tmpBuf, "Write default to current setting failed!\n");
			free(buf);
			goto back;
		}
#endif
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
		//To clear 802.1x certs
		//RunSystemCmd(NULL_FILE, "rsCert","-rst", NULL_STR);
		system("rsCert -rst");
#endif
#ifdef CONFIG_RTL_WAPI_SUPPORT
		//To clear CA files
		system("storeWapiFiles -reset");
#endif

#if defined(CONFIG_RTL_92D_SUPPORT) || defined(CONFIG_POCKET_AP_SUPPORT)
		Reboot_Wait = 60;
#else
		Reboot_Wait = 40;
#endif
#ifdef HOME_GATEWAY
		sprintf(tmpBuf, "%s","Reload setting successfully!<br><br>The Router is booting.<br>Do not turn off or reboot the Device during this time.<br>");
#else
		sprintf(tmpBuf, "%s", "Reload setting successfully!<br><br>The AP is booting.<br>");
#endif
		//ERR_MSG(tmpBuf);
		apmib_reinit();
		apmib_update_web(CURRENT_SETTING);	// update configuration to flash
		apmib_get( MIB_IP_ADDR,  (void *)lan_ip_buf);
		sprintf(lan_ip,"%s",inet_ntoa(*((struct in_addr *)lan_ip_buf)) );
		OK_MSG_FW(tmpBuf, submitUrl,Reboot_Wait,lan_ip);
		if(ptr != NULL) {
			free(ptr);
		}
		/* Reboot DUT. Keith */
		isUpgrade_OK=1;
		REBOOT_WAIT_COMMAND(2);
		return;
	}

back:
	ERR_MSG(tmpBuf);
	return;
}

void formUploadConfig(request *wp, char *path, char *query)
{
	int status=0;
	char tmpBuf[200];
	CONFIG_DATA_T type=0;
	char *submitUrl;
	char lan_ip_buf[30], lan_ip[30];
	int head_offset=0;

#if defined(CONFIG_APP_FWD)
#define FWD_CONF "/var/fwd.conf"
	int newfile = 1;
	extern int get_shm_id();
	extern int clear_fwupload_shm();
	int shm_id = get_shm_id();
#endif

	head_offset = find_head_offset((char *)wp->upload_data);
	//fprintf(stderr,"####%s:%d head_offset=%d###\n",  __FILE__, __LINE__ , head_offset);
	if (head_offset == -1) {
		strcpy(tmpBuf, "Invalid file format!");
		goto back;
	}
	if(
#ifdef COMPRESS_MIB_SETTING
		!memcmp(&wp->upload_data[head_offset], COMP_HS_SIGNATURE, COMP_SIGNATURE_LEN) ||
		!memcmp(&wp->upload_data[head_offset], COMP_DS_SIGNATURE, COMP_SIGNATURE_LEN) ||
		!memcmp(&wp->upload_data[head_offset], COMP_CS_SIGNATURE, COMP_SIGNATURE_LEN)
#else
		!memcmp(&wp->upload_data[head_offset], CURRENT_SETTING_HEADER_TAG, TAG_LEN) ||
		!memcmp(&wp->upload_data[head_offset], CURRENT_SETTING_HEADER_FORCE_TAG, TAG_LEN) ||
		!memcmp(&wp->upload_data[head_offset], CURRENT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) ||
		!memcmp(&wp->upload_data[head_offset], DEFAULT_SETTING_HEADER_TAG, TAG_LEN) ||
		!memcmp(&wp->upload_data[head_offset], DEFAULT_SETTING_HEADER_FORCE_TAG, TAG_LEN) ||
		!memcmp(&wp->upload_data[head_offset], DEFAULT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) ||
		!memcmp(&wp->upload_data[head_offset], HW_SETTING_HEADER_TAG, TAG_LEN) ||
		!memcmp(&wp->upload_data[head_offset], HW_SETTING_HEADER_FORCE_TAG, TAG_LEN) ||
		!memcmp(&wp->upload_data[head_offset], HW_SETTING_HEADER_UPGRADE_TAG, TAG_LEN)
#endif
	) {
		updateConfigIntoFlash((unsigned char *)&wp->upload_data[head_offset], (wp->upload_len-head_offset), (int *)&type, &status);
	}
	if (status == 0 || type == 0) { // checksum error
		strcpy(tmpBuf, "Invalid configuration file!");
		goto back;
	}
	else {
		if (type) { // upload success
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
			//To clear 802.1x certs
			//RunSystemCmd(NULL_FILE, "rsCert","-rst", NULL_STR);
			system("rsCert -rst");
#endif
#ifdef CONFIG_RTL_WAPI_SUPPORT
			//To clear CA files
			system("storeWapiFiles -reset");
#endif
		}

#ifdef HOME_GATEWAY
		sprintf(tmpBuf, ("%s"), "Update successfully!<br><br>Update in progressing.<br>Do not turn off or reboot the Device during this time.<br>");
#else
		sprintf(tmpBuf, ("%s"), "Update successfully!<br><br>Update in progress.<br> Do not turn off or reboot the AP during this time.");
#endif
		Reboot_Wait = 45;
		submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page

		apmib_reinit();
		apmib_update_web(CURRENT_SETTING);	// update configuration to flash
		apmib_get( MIB_IP_ADDR,  (void *)lan_ip_buf) ;
		sprintf(lan_ip,"%s",inet_ntoa(*((struct in_addr *)lan_ip_buf)) );
#ifdef REBOOT_CHECK
		sprintf(lastUrl,"%s",submitUrl);
		sprintf(okMsg,"%s",tmpBuf);
		countDownTime = Reboot_Wait;
		send_redirect_perm(wp, COUNTDOWN_PAGE);
		/*Reboot DUT in main loop*/
		isCFGUPGRADE=1;
#else
		OK_MSG_FW(tmpBuf, submitUrl,Reboot_Wait,lan_ip);

		/* Reboot DUT. Keith */
		isUpgrade_OK=1;
		REBOOT_WAIT_COMMAND(2);
#endif
		return;
	}
back:
#if defined(CONFIG_APP_FWD)
	clear_fwupload_shm(shm_id);
#endif
	ERR_MSG(tmpBuf);
	return;
}
#endif

///////////////////////////////////////////////////////////////////////////////

#if 0 //Keith. move to utility.c
void kill_processes(void)
{


	printf("upgrade: killing tasks...\n");

	kill(1, SIGTSTP);		/* Stop init from reforking tasks */
	kill(1, SIGSTOP);
	kill(2, SIGSTOP);
	kill(3, SIGSTOP);
	kill(4, SIGSTOP);
	kill(5, SIGSTOP);
	kill(6, SIGSTOP);
	kill(7, SIGSTOP);
	//atexit(restartinit);		/* If exit prematurely, restart init */
	sync();

	signal(SIGTERM,SIG_IGN);	/* Don't kill ourselves... */
	setpgrp(); 			/* Don't let our parent kill us */
	sleep(1);
	signal(SIGHUP, SIG_IGN);	/* Don't die if our parent dies due to
					 * a closed controlling terminal */

}
#endif //#if 0 //Keith. move to utility.c

//////////////////////////////////////////////////////////////////////////////
#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE

#define SQSH_SIGNATURE		((char *)"sqsh")
#define SQSH_SIGNATURE_LE       ((char *)"hsqs")

#define IMAGE_ROOTFS 2
#define IMAGE_KERNEL 1
#define GET_BACKUP_BANK 2
#define GET_ACTIVE_BANK 1

#define GOOD_BANK_MARK_MASK 0x80000000  //goo abnk mark must set bit31 to 1

#define NO_IMAGE_BANK_MARK 0x80000000
#define OLD_BURNADDR_BANK_MARK 0x80000001
#define BASIC_BANK_MARK 0x80000002
#define FORCEBOOT_BANK_MARK 0xFFFFFFF0  //means always boot/upgrade in this bank

char *Kernel_dev_name[2]=
 {
   "/dev/mtdblock0", "/dev/mtdblock2"
 };
char *Rootfs_dev_name[2]=
 {
   "/dev/mtdblock1", "/dev/mtdblock3"
 };

#if defined(CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE)
#if defined(CONFIG_RTL_FLASH_DUAL_IMAGE_WEB_BACKUP_ENABLE)
char *Web_dev_name[2]=
{
	"/dev/mtdblock0", "/dev/mtdblock2"
};
#endif
#endif

static int get_actvie_bank()
{
	FILE *fp;
	char buffer[2];
	int bootbank;
	fp = fopen("/proc/bootbank", "r");

	if (!fp) {
		fprintf(stderr,"%s\n","Read /proc/bootbank failed!\n");
	}else
	{
			//fgets(bootbank, sizeof(bootbank), fp);
			fgets(buffer, sizeof(buffer), fp);
			fclose(fp);
	}
	bootbank = buffer[0] - 0x30;
	if ( bootbank ==1 || bootbank ==2)
		return bootbank;
	else
		return 1;
}

void get_bank_info(int dual_enable,int *active,int *backup)
{
	int bootbank=0,backup_bank;

	bootbank = get_actvie_bank();

	if(bootbank == 1 )
	{
		if( dual_enable ==0 )
			backup_bank =1;
		else
			backup_bank =2;
	}
	else if(bootbank == 2 )
	{
		if( dual_enable ==0 )
			backup_bank =2;
		else
			backup_bank =1;
	}
	else
	{
		bootbank =1 ;
		backup_bank =1 ;
	}

	*active = bootbank;
	*backup = backup_bank;

	//fprintf(stderr,"get_bank_info active_bank =%d , backup_bank=%d  \n",*active,*backup); //mark_debug
}
static unsigned long header_to_mark(int  flag, IMG_HEADER_Tp pHeader)
{
	unsigned long ret_mark=NO_IMAGE_BANK_MARK;
	//mark_dual ,  how to diff "no image" "image with no bank_mark(old)" , "boot with lowest priority"
	if(flag) //flag ==0 means ,header is illegal
	{
		if( (pHeader->burnAddr & GOOD_BANK_MARK_MASK) )
			ret_mark=pHeader->burnAddr;
		else
			ret_mark = OLD_BURNADDR_BANK_MARK;
	}
	return ret_mark;
}

// return,  0: not found, 1: linux found, 2:linux with root found
static int check_system_image(int fh,IMG_HEADER_Tp pHeader)
{
	// Read header, heck signature and checksum
	int i, ret=0;
	char image_sig[4]={0};
	char image_sig_root[4]={0};

        /*check firmware image.*/
	if ( read(fh, pHeader, sizeof(IMG_HEADER_T)) != sizeof(IMG_HEADER_T))
     		return 0;

	memcpy(image_sig, FW_HEADER, SIGNATURE_LEN);
	memcpy(image_sig_root, FW_HEADER_WITH_ROOT, SIGNATURE_LEN);

	if (!memcmp(pHeader->signature, image_sig, SIGNATURE_LEN))
		ret=1;
	else if  (!memcmp(pHeader->signature, image_sig_root, SIGNATURE_LEN))
		ret=2;
	else{
		printf("no sys signature at !\n");
	}
       //mark_dual , ignore checksum() now.(to do)
	return (ret);
}

static int check_rootfs_image(int fh)
{
	// Read header, heck signature and checksum
	int i;
	unsigned short sum=0, *word_ptr;
	unsigned long length=0;
	unsigned char rootfs_head[SIGNATURE_LEN];

	if ( read(fh, &rootfs_head, SIGNATURE_LEN ) != SIGNATURE_LEN )
     		return 0;

	if ( memcmp(rootfs_head, SQSH_SIGNATURE, SIGNATURE_LEN) && memcmp(rootfs_head, SQSH_SIGNATURE_LE, SIGNATURE_LEN)) {
		printf("no rootfs signature at !\n");
		return 0;
	}

	return 1;
}

static int get_image_header(int fh,IMG_HEADER_Tp header_p)
{
	int ret=0;
	//check 	CODE_IMAGE_OFFSET2 , CODE_IMAGE_OFFSET3 ?
	//ignore check_image_header () for fast get header , assume image are same offset......
	// support CONFIG_RTL_FLASH_MAPPING_ENABLE ? , scan header ...

	lseek(fh, CODE_IMAGE_OFFSET, SEEK_SET);
	ret = check_system_image(fh,header_p);

	//assume , we find the image header in CODE_IMAGE_OFFSET
	lseek(fh, CODE_IMAGE_OFFSET, SEEK_SET);

	return ret;
}

 int check_bank_image(int bank)
{
	int i,ret=0;
    	int fh,fh_rootfs;
	char *rootfs_dev = Rootfs_dev_name[bank-1];
	char *kernel_dev = Kernel_dev_name[bank-1];
	IMG_HEADER_T header;

	fh = open(kernel_dev, O_RDONLY);
	if ( fh == -1 ) {
      		printf("Open file failed!\n");
		return 0;
	}
	ret = get_image_header(fh,&header);

	close(fh);
	if(ret==2)
        {
	      	fh_rootfs = open(rootfs_dev, O_RDONLY);
		if ( fh_rootfs == -1 ) {
      		printf("Open file failed!\n");
		return 0;
		}
              ret=check_rootfs_image(fh_rootfs);
		close(fh_rootfs);
	  }
	return ret;
}

int write_header_bankmark(char *kernel_dev, unsigned long bankmark)
{
	int ret=0,fh,numWrite;
	IMG_HEADER_T header,*header_p;
	char buffer[200]; //mark_debug

	header_p = &header;
	fh = open(kernel_dev, O_RDWR);

	if ( fh == -1 ) {
      		printf("Open file failed!\n");
		return -1;
	}
	ret = get_image_header(fh,&header);

	if(!ret)
		return -2; //can't find active(current) imager header ...something wrong

	//fh , has been seek to correct offset

	header_p->burnAddr = bankmark;

	//sprintf(buffer, ("write_header_bankmark kernel_dev =%s , bankmark=%x \n"), kernel_dev , header_p->burnAddr);
       //fprintf(stderr, "%s\n", buffer); //mark_debug

	 //move to write image header will be done in get_image_header
	numWrite = write(fh, (char *)header_p, sizeof(IMG_HEADER_T));

	close(fh);

	return 0;	//success
}


// return,  0: not found, 1: linux found, 2:linux with root found

unsigned long get_next_bankmark(char *kernel_dev,int dual_enable)
{
    unsigned long bankmark=NO_IMAGE_BANK_MARK;
    int ret=0,fh;
    IMG_HEADER_T header;

	fh = open(kernel_dev, O_RDONLY);
	if ( fh == -1 ) {
      		fprintf(stderr,"%s\n","Open file failed!\n");
		return NO_IMAGE_BANK_MARK;
	}
	ret = get_image_header(fh,&header);

	//fprintf(stderr,"get_next_bankmark = %s , ret = %d \n",kernel_dev,ret); //mark_debug

	bankmark= header_to_mark(ret, &header);
	close(fh);
	//get next boot mark

	if( bankmark < BASIC_BANK_MARK)
		return BASIC_BANK_MARK;
	else if( (bankmark ==  FORCEBOOT_BANK_MARK) || (dual_enable == 0)) //dual_enable = 0 ....
	{
		return FORCEBOOT_BANK_MARK;//it means dual bank disable
	}
	else
		return bankmark+1;

}

// set mib at the same time or get mib to set this function?
int set_dualbank(int enable)
{
	int ret =0, active_bank=0, backup_bank=0;
	unsigned long bankmark=0;

	get_bank_info(enable,&active_bank,&backup_bank);
	if(enable)
	{
		//set_to mib to 1.??
		bankmark = get_next_bankmark(Kernel_dev_name[backup_bank-1],enable);
		ret = write_header_bankmark(Kernel_dev_name[active_bank-1], bankmark);
	}
	else //disable this
	{
		//set_to mib to 0 .??
		ret = write_header_bankmark(Kernel_dev_name[active_bank-1], FORCEBOOT_BANK_MARK);
	}
	if(!ret)
	{
   	       apmib_set( MIB_DUALBANK_ENABLED, (void *)&enable);
		//fprintf(stderr,"set_dualbank enable =%d ,ret2 =%d  \n",enable,ret2); //mark_debug
	}

	return ret; //-1 fail , 0 : ok
}

// need to reject this function if dual bank is disable
int  boot_from_backup()
{
	int ret =0, active_bank=0, backup_bank=0;
	unsigned long bankmark=0;

	get_bank_info(1,&active_bank,&backup_bank);

	ret = check_bank_image(backup_bank);
	if(!ret)
	    return -2;
	bankmark = get_next_bankmark(Kernel_dev_name[active_bank-1],1);

	ret = write_header_bankmark(Kernel_dev_name[backup_bank-1], bankmark);

	return ret; //-2 , no kernel , -1 fail , 0 : ok}
}
#endif

int find_head_offset(char *upload_data)
{
	int head_offset=0 ;
	char *pStart=NULL;
	int iestr_offset=0;
	char *dquote;
	char *dquote1;

	if (upload_data==NULL) {
		//fprintf(stderr, "upload data is NULL\n");
		return -1;
	}

	pStart = strstr(upload_data, WINIE6_STR);
	if (pStart == NULL) {
		pStart = strstr(upload_data, LINUXFX36_FWSTR);
		if (pStart == NULL) {
			pStart = strstr(upload_data, MACIE5_FWSTR);
			if (pStart == NULL) {
				pStart = strstr(upload_data, OPERA_FWSTR);
				if (pStart == NULL) {
					pStart = strstr(upload_data, "filename=");
					if (pStart == NULL) {
						return -1;
					}
					else {
						dquote =  strstr(pStart, "\"");
						if (dquote !=NULL) {
							dquote1 = strstr(dquote, LINE_FWSTR);
							if (dquote1!=NULL) {
								iestr_offset = 4;
								pStart = dquote1;
							}
							else {
								return -1;
							}
						}
						else {
							return -1;
						}
					}
				}
				else {
					iestr_offset = 16;
				}
			}
			else {
				iestr_offset = 14;
			}
		}
		else {
			iestr_offset = 26;
		}
	}
	else {
		iestr_offset = 17;
	}
	//fprintf(stderr,"####%s:%d %d###\n",  __FILE__, __LINE__ , iestr_offset);
	head_offset = (int)(((unsigned long)pStart)-((unsigned long)upload_data)) + iestr_offset;
	return head_offset;
}

/* rewritten in private.c - 2015-04-13 14:44 young */
#ifndef __DAVO__
int FirmwareUpgrade(char *upload_data, int upload_len, int is_root, char *buffer)
{
	int head_offset=0 ;
	int isIncludeRoot=0;
	int		 len;
	int          locWrite;
	int          numLeft;
	int          numWrite;
	IMG_HEADER_Tp pHeader;
	int flag=0, startAddr=-1, startAddrWeb=-1;
	int update_fw=0, update_cfg=0;
	int fh;
	//unsigned char cmdBuf[30];
	//Support WAPI/openssl, the flash MUST up to 4m
/*
#if defined(CONFIG_RTL_WAPI_SUPPORT) || defined(HTTP_FILE_SERVER_SUPPORTED) || defined(CONFIG_APP_TR069)
	int fwSizeLimit = 0x400000;
#elif defined( CONFIG_RTK_VOIP )
	int fwSizeLimit = 0x400000;
#else
	int fwSizeLimit = 0x200000;
#endif
*/
	int fwSizeLimit = CONFIG_FLASH_SIZE;
#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
	int active_bank,backup_bank;
	int dual_enable =0;
#endif

	unsigned char isValidfw = 0;



#if defined(CONFIG_APP_FWD)
#define FWD_CONF "/var/fwd.conf"
	int newfile = 1;
	extern int get_shm_id();
	extern int clear_fwupload_shm();
	int shm_id = get_shm_id();
#endif

	if (isCFG_ONLY == 0) {
		/*
		#ifdef CONFIG_RTL_8196B
			sprintf(cmdBuf, "echo \"4 %d\" > /proc/gpio", (Reboot_Wait+12));
		#else
			sprintf(cmdBuf, "echo \"4 %d\" > /proc/gpio", (Reboot_Wait+20));
		#endif

			system(cmdBuf);
		*/
		system("ifconfig br0 down 2> /dev/null");
	}
#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
	apmib_get(MIB_DUALBANK_ENABLED,(void *)&dual_enable);
	get_bank_info(dual_enable,&active_bank,&backup_bank);
#endif
	head_offset = find_head_offset(upload_data);
//	fprintf(stderr,"####%s:%d head_offset=%d upload_data=%p###\n",  __FILE__, __LINE__ , head_offset, upload_data);
	if (head_offset == -1) {
		strcpy(buffer, "Invalid file format!");
		goto ret_upload;
	}
	while ((head_offset+sizeof(IMG_HEADER_T)) < upload_len) {
		locWrite = 0;
		pHeader = (IMG_HEADER_Tp) &upload_data[head_offset];
		len = pHeader->len;
#ifdef _LITTLE_ENDIAN_
		len  = DWORD_SWAP(len);
#endif
		numLeft = len + sizeof(IMG_HEADER_T) ;
		// check header and checksum
		if (!memcmp(&upload_data[head_offset], FW_HEADER, SIGNATURE_LEN) ||
			!memcmp(&upload_data[head_offset], FW_HEADER_WITH_ROOT, SIGNATURE_LEN)) {
			isValidfw = 1;
			flag = 1;
		}
		else if (!memcmp(&upload_data[head_offset], WEB_HEADER, SIGNATURE_LEN)) {
			isValidfw = 1;
			flag = 2;
		}
		else if (!memcmp(&upload_data[head_offset], ROOT_HEADER, SIGNATURE_LEN)) {
			isValidfw = 1;
			flag = 3;
			isIncludeRoot = 1;
		}else if (
#ifdef COMPRESS_MIB_SETTING
				!memcmp(&upload_data[head_offset], COMP_HS_SIGNATURE, COMP_SIGNATURE_LEN) ||
				!memcmp(&upload_data[head_offset], COMP_DS_SIGNATURE, COMP_SIGNATURE_LEN) ||
				!memcmp(&upload_data[head_offset], COMP_CS_SIGNATURE, COMP_SIGNATURE_LEN)
#else
				!memcmp(&upload_data[head_offset], CURRENT_SETTING_HEADER_TAG, TAG_LEN) ||
				!memcmp(&upload_data[head_offset], CURRENT_SETTING_HEADER_FORCE_TAG, TAG_LEN) ||
				!memcmp(&upload_data[head_offset], CURRENT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) ||
				!memcmp(&upload_data[head_offset], DEFAULT_SETTING_HEADER_TAG, TAG_LEN) ||
				!memcmp(&upload_data[head_offset], DEFAULT_SETTING_HEADER_FORCE_TAG, TAG_LEN) ||
				!memcmp(&upload_data[head_offset], DEFAULT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) ||
				!memcmp(&upload_data[head_offset], HW_SETTING_HEADER_TAG, TAG_LEN) ||
				!memcmp(&upload_data[head_offset], HW_SETTING_HEADER_FORCE_TAG, TAG_LEN) ||
				!memcmp(&upload_data[head_offset], HW_SETTING_HEADER_UPGRADE_TAG, TAG_LEN)
#endif
				) {
			int type=0, status=0, cfg_len;
			cfg_len = updateConfigIntoFlash((unsigned char *)&upload_data[head_offset],configlen , &type, &status);

			if (status == 0 || type == 0) { // checksum error
				strcpy(buffer, "Invalid configuration file!");
				goto ret_upload;
			}
			else { // upload success
				strcpy(buffer, "Update successfully!");
				head_offset += cfg_len;
				isValidfw = 1;
				update_cfg = 1;
			}
			continue;
		}
		else {
			if (isValidfw == 1)
				break;
			strcpy(buffer, ("Invalid file format!"));
			goto ret_upload;
		}

		if (len > fwSizeLimit) { //len check by sc_yang
			sprintf(buffer, ("Image len exceed max size 0x%x ! len=0x%x</b><br>"),fwSizeLimit, len);
			goto ret_upload;
		}
		if ( (flag == 1) || (flag == 3)) {
			if ( !fwChecksumOk(&upload_data[sizeof(IMG_HEADER_T)+head_offset], len)) {
				sprintf(buffer, ("Image checksum mismatched! len=0x%x, checksum=0x%x</b><br>"), len,
					*((unsigned short *)&upload_data[len-2]) );
				goto ret_upload;
			}
		}
		else {
			char *ptr = &upload_data[sizeof(IMG_HEADER_T)+head_offset];
			if ( !CHECKSUM_OK((unsigned char *)ptr, len) ) {
				sprintf(buffer, ("Image checksum mismatched! len=0x%x</b><br>"), len);
				goto ret_upload;
			}
		}

#ifndef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
		if (flag == 3)
		{
			fh = open(FLASH_DEVICE_NAME1, O_RDWR);

#if defined(CONFIG_APP_FWD)
			write_line_to_file(FWD_CONF, (newfile==1?1:2), FLASH_DEVICE_NAME1);
			newfile = 2;
#endif
		}
		else
		{
			fh = open(FLASH_DEVICE_NAME, O_RDWR);
#if defined(CONFIG_APP_FWD)
			write_line_to_file(FWD_CONF, (newfile==1?1:2), FLASH_DEVICE_NAME);
			newfile = 2;
#endif
		}
#else
		if (flag == 3) //rootfs
		{
			fh = open(Rootfs_dev_name[backup_bank-1], O_RDWR);

#if defined(CONFIG_APP_FWD)
			write_line_to_file(FWD_CONF, (newfile==1?1:2), Rootfs_dev_name[backup_bank-1]);
			newfile = 2;
#endif
		}
		else if (flag == 1) //linux
		{
			fh = open(Kernel_dev_name[backup_bank-1], O_RDWR);
#if defined(CONFIG_APP_FWD)
			write_line_to_file(FWD_CONF, (newfile==1?1:2), Kernel_dev_name[backup_bank-1]);
			newfile = 2;
#endif
		}
		else //web
		{
#if defined(CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE)
#if defined(CONFIG_RTL_FLASH_DUAL_IMAGE_WEB_BACKUP_ENABLE)
			fh = open(Web_dev_name[backup_bank-1],O_RDWR);
#if defined(CONFIG_APP_FWD)
			write_line_to_file(FWD_CONF, (newfile==1?1:2), Web_dev_name[backup_bank-1]);
			newfile = 2;
#endif
#else
			fh = open(FLASH_DEVICE_NAME, O_RDWR);
#if defined(CONFIG_APP_FWD)
			write_line_to_file(FWD_CONF, (newfile==1?1:2), FLASH_DEVICE_NAME);
			newfile = 2;
#endif
#endif
#else
			fh = open(FLASH_DEVICE_NAME, O_RDWR);
#if defined(CONFIG_APP_FWD)
			write_line_to_file(FWD_CONF, (newfile==1?1:2), FLASH_DEVICE_NAME);
			newfile = 2;
#endif
#endif
		}
#endif

		if ( fh == -1 ) {
			strcpy(buffer, ("File open failed!"));
		} else {
			if (flag == 1) {
				if (startAddr == -1) {
					//startAddr = CODE_IMAGE_OFFSET;
					startAddr = pHeader->burnAddr ;
#ifdef _LITTLE_ENDIAN_
					startAddr = DWORD_SWAP(startAddr);
#endif
				}
			}
			else if (flag == 3) {
				if (startAddr == -1) {
					startAddr = 0; // always start from offset 0 for 2nd FLASH partition
				}
			}
			else {
				if (startAddrWeb == -1) {
					//startAddr = WEB_PAGE_OFFSET;
					startAddr = pHeader->burnAddr ;
#ifdef _LITTLE_ENDIAN_
					startAddr = DWORD_SWAP(startAddr);
#endif
				}
				else
					startAddr = startAddrWeb;
			}
			lseek(fh, startAddr, SEEK_SET);

#if defined(CONFIG_APP_FWD)
			{
				char tmpStr[20]={0};
				sprintf(tmpStr,"\n%d",startAddr);
				write_line_to_file(FWD_CONF, (newfile==1?1:2), tmpStr);
				newfile = 2;
			}
#endif



			if (flag == 3) {
				locWrite += sizeof(IMG_HEADER_T); // remove header
				numLeft -=  sizeof(IMG_HEADER_T);
				system("ifconfig br0 down 2> /dev/null");
				system("ifconfig eth0 down 2> /dev/null");
				system("ifconfig eth1 down 2> /dev/null");
				system("ifconfig ppp0 down 2> /dev/null");
				system("ifconfig wlan0 down 2> /dev/null");
				system("ifconfig wlan0-vxd down 2> /dev/null");
				system("ifconfig wlan0-va0 down 2> /dev/null");
				system("ifconfig wlan0-va1 down 2> /dev/null");
				system("ifconfig wlan0-va2 down 2> /dev/null");
				system("ifconfig wlan0-va3 down 2> /dev/null");
				system("ifconfig wlan0-wds0 down 2> /dev/null");
				system("ifconfig wlan0-wds1 down 2> /dev/null");
				system("ifconfig wlan0-wds2 down 2> /dev/null");
				system("ifconfig wlan0-wds3 down 2> /dev/null");
				system("ifconfig wlan0-wds4 down 2> /dev/null");
				system("ifconfig wlan0-wds5 down 2> /dev/null");
				system("ifconfig wlan0-wds6 down 2> /dev/null");
				system("ifconfig wlan0-wds7 down 2> /dev/null");
#if defined(CONFIG_RTL_92D_SUPPORT)
				system("ifconfig wlan1 down 2> /dev/null");
				system("ifconfig wlan1-vxd down 2> /dev/null");
				system("ifconfig wlan1-va0 down 2> /dev/null");
				system("ifconfig wlan1-va1 down 2> /dev/null");
				system("ifconfig wlan1-va2 down 2> /dev/null");
				system("ifconfig wlan1-va3 down 2> /dev/null");
				system("ifconfig wlan1-wds0 down 2> /dev/null");
				system("ifconfig wlan1-wds1 down 2> /dev/null");
				system("ifconfig wlan1-wds2 down 2> /dev/null");
				system("ifconfig wlan1-wds3 down 2> /dev/null");
				system("ifconfig wlan1-wds4 down 2> /dev/null");
				system("ifconfig wlan1-wds5 down 2> /dev/null");
				system("ifconfig wlan1-wds6 down 2> /dev/null");
				system("ifconfig wlan1-wds7 down 2> /dev/null");
#endif
				kill_processes();
				sleep(2);
			}
#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
			if (flag == 1) {  //kernel image
				pHeader->burnAddr = get_next_bankmark(Kernel_dev_name[active_bank-1],dual_enable);	//replace the firmware header with new bankmark //mark_debug
			}
#endif

#if defined(CONFIG_APP_FWD)
			{
				char tmpStr[20]={0};

				sprintf(tmpStr,"\n%d",numLeft);
				write_line_to_file(FWD_CONF, (newfile==1?1:2), tmpStr);
				sprintf(tmpStr,"\n%d\n",locWrite+head_offset);
				write_line_to_file(FWD_CONF, (newfile==1?1:2), tmpStr);
				newfile = 2;
			}

#else //#if defined(CONFIG_APP_FWD)
			numWrite = write(fh, &(upload_data[locWrite+head_offset]), numLeft);
			if (numWrite < numLeft) {
				sprintf(buffer, ("File write failed. locWrite=%d numLeft=%d numWrite=%d Size=%d bytes."), locWrite, numLeft, numWrite, upload_len);
				goto ret_upload;
			}

#endif //#if defined(CONFIG_APP_FWD)

			locWrite += numWrite;
			numLeft -= numWrite;
			sync();
			close(fh);

			head_offset += len + sizeof(IMG_HEADER_T) ;
			startAddr = -1 ; //by sc_yang to reset the startAddr for next image
			update_fw = 1;
		}
	} //while //sc_yang

	//fprintf(stderr,"####isUpgrade_OK###\n");
#ifndef NO_ACTION
	isUpgrade_OK=1;

#if defined(CONFIG_APP_FWD)
	{
			char tmpStr[20]={0};

			sprintf(tmpStr,"%d",shm_id);

			write_line_to_file("/var/fwd.ready", 1, tmpStr);

			sync();
			exit(0);
	}
#else	//#if defined(CONFIG_APP_FWD)
	REBOOT_WAIT_COMMAND(2);
	for(;;);
#endif //#if defined(CONFIG_APP_FWD)


#else
#ifdef VOIP_SUPPORT
	// rock: for x86 simulation
	if (update_cfg && !update_fw) {
		if (apmib_reinit()) {
			//reset_user_profile();  // re-initialize user password
		}
	}
#endif
#endif

	return 1;
ret_upload:
	fprintf(stderr, "%s\n", buffer);

#if defined(CONFIG_APP_FWD)
	clear_fwupload_shm(shm_id);
#endif

	return 0;
}
#endif

//////////////////////////////////////////////////////////////////////////////
#if defined(CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE)
void formDualFirmware(request *wp, char *path, char *query)
{
	char *strRequest, *submitUrl, *strVal;
	unsigned char enableDualFW=0, whichBand=0;
	unsigned char tmpBuf[200];

	//displayPostDate(wp->post_data);

	submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page

	strVal = req_get_cstream_var(wp, ("active"), "");
	if(strVal[0])
	{
		if(strcmp(strVal,"save") == 0)
		{
//fprintf(stderr,"\r\n apply setting,__[%s-%u]",__FILE__,__LINE__);
			strVal = req_get_cstream_var(wp, ("dualFw"), "");
			if (strVal[0])
			{
				enableDualFW = 1;
			}
			set_dualbank(enableDualFW);


		}
		else if(strcmp(strVal,"reboot") == 0)
		{

			if( boot_from_backup() == 0)
			{
			 	strcpy(tmpBuf, ("Rebooting !!~~~~Please wait for 40~50secs! "));
				 goto setReboot;
			}
			else {
				strcpy(tmpBuf, ("Reboot Fail!!The image in Backup Bank maybe corrupted!! "));
       	              goto setErr;
			}

		}
	}

	apmib_update_web(CURRENT_SETTING);

#ifndef NO_ACTION
	run_init_script("all");
#endif

	OK_MSG(submitUrl);

	return;

setErr:
	ERR_MSG(tmpBuf);
	return ;

setReboot:
	ERR_MSG(tmpBuf);
	REBOOT_WAIT_COMMAND(2);
}
#endif

#if defined(CONFIG_USBDISK_UPDATE_IMAGE)
void formUploadFromUsb(request *wp, char * path, char * query)
{
	int oneReadMax = 4096;
	int oneRead = 0;
	int fileLen=0;
	char *buff = NULL;
	char tmpBuf[200];
	char *submitUrl;
	char lan_ip[30];
	char lan_ip_buf[30];
    	FILE *       fd;

	 if(!isFileExist(USB_UPLOAD_FORM_PATH))
	 {
      		strcpy(tmpBuf, ("Error!form ware is not exist in usb storage!\n"));
	 	goto ret_err;
	 }
	fd = open(USB_UPLOAD_FORM_PATH, O_RDONLY);
	if (!fd){
      		strcpy(tmpBuf, ("Open image file  failed!\n"));
	 	goto ret_err;
	}
	lseek(fd, 0L, SEEK_SET);
	printf("		<read image from usb storage device>\n");
	/* read image from file to buff */
	 do{
		 buff = realloc(buff, fileLen + oneReadMax);
		 if(buff == NULL)
		 {
      			strcpy(tmpBuf, ("my god breallco failed !\n"));
	 		goto ret_err;
		 }
		oneRead = read(fd, (void *)(buff + fileLen), oneReadMax);
		fileLen += oneRead;
		printf(".");
		if(oneRead == -1)
		{
			printf("file read error!\n");
	 		goto ret_err;
		 }
	 }while(oneRead == oneReadMax);
	 printf("\n");

	free(wp->post_data);
	wp->post_data = buff;
	wp->post_data_len = fileLen;
	formUpload(wp, NULL, NULL);/*further check and upload */
	return;
ret_err:
	ERR_MSG(tmpBuf);
	return;

}
#endif

#ifdef SAMBA_WEB_SUPPORT
void formDiskCreateFolder(request *wp, char * path, char * query)
{
	char *submitUrl,*strLocation,*strFolder;
	char cmdBuffer[40];

	strLocation = req_get_cstream_var(wp,("Location"),"");
	strFolder = req_get_cstream_var(wp,("newfolder"),"");

	memset(cmdBuffer,'\0',40);
	snprintf(cmdBuffer,40,"mkdir %s/%s",strLocation,strFolder);
	system(cmdBuffer);

setOk_DiskCreateFolder:
	apmib_update_web(CURRENT_SETTING);

	submitUrl = req_get_cstream_var(wp, "submit-url", "");
	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);
	return;
}

void formDiskCreateShare(request *wp, char * path, char * query)
{
	char *submitUrl,*strDisplayName,*strShareAll,*strDelete,*strSelect,*strGroup;
	char *strDirNum,*strLocation;
	char cmdBuffer[50];;
	char tmpBuff[100];
	FILE	*fp;
	STORAGE_USER_T		s_user;
	STORAGE_GROUP_T		s_group;
	STORAGE_GROUP_T		s_groups[2] = {0};
	int					number,i,j;

	strDisplayName = req_get_cstream_var(wp,("displayname"),"");
	strShareAll = req_get_cstream_var(wp,("shareall"),"");
	strGroup = req_get_cstream_var(wp,("Group"),"");
	strDirNum = req_get_cstream_var(wp,("DirNum"),"");
	strLocation = req_get_cstream_var(wp,("Location"),"");

	if(strShareAll[0]){
		//printf("in strShareAll\n");
		memset(&s_group,'\0',sizeof(STORAGE_GROUP_T));
		*((char*)&s_group) = (char)atoi(strGroup);
		apmib_get(MIB_STORAGE_GROUP_TBL,(void*)&s_group);
		s_group.storage_group_sharefolder_flag = 1;
		strcpy(s_group.storage_group_sharefolder,strLocation);
		strcpy(s_group.storage_group_displayname,strDisplayName);

		*((char*)&s_groups) = (char)atoi(strGroup);
		apmib_get(MIB_STORAGE_GROUP_TBL,(void*)(s_groups));
		memcpy(&(s_groups[1]),&s_group,sizeof(STORAGE_GROUP_T));
		apmib_set(MIB_STORAGE_GROUP_MOD,(void*)s_groups);

		/*memset(cmdBuffer,'\0',50);
		snprintf(cmdBuffer,50,"chgrp %s %s",s_group.storage_group_name,strLocation);
		system(cmdBuffer);*/

		storage_UpdateSambaConf();
		goto setOk_DiskCreateShare;
	}

	for(i = 0;i < atoi(strDirNum);i++)
	{
		//delete Dir
		memset(cmdBuffer,'\0',50);
		snprintf(cmdBuffer,50,"delete%d",i);
		strDelete =  req_get_cstream_var(wp,(cmdBuffer),"");
		memset(cmdBuffer,'\0',50);
		if(strDelete[0]){
			snprintf(cmdBuffer,50,"rm -rf %s",strDelete);
			system(cmdBuffer);
		}
		apmib_get(MIB_STORAGE_GROUP_TBL_NUM,(void*)&number);
		for(j = 0;j < number;j++)
		{
			memset(&s_group,'\0',sizeof(STORAGE_GROUP_T));
			*((char*)&s_group) = (char)(j+1);
			apmib_get(MIB_STORAGE_GROUP_TBL,(void*)&s_group);

			if(s_group.storage_group_sharefolder_flag == 1){
				if(!strcmp(s_group.storage_group_sharefolder,strDelete)){
					s_group.storage_group_sharefolder_flag = 0;
					memset(s_group.storage_group_sharefolder,'\0',MAX_FOLDER_NAME_LEN);
					memset(s_group.storage_group_displayname,'\0',MAX_DISPLAY_NAME_LEN);

					*((char*)&s_groups) = (char)(j+1);
					apmib_get(MIB_STORAGE_GROUP_TBL,(void*)(s_groups));
					memcpy(&(s_groups[1]),&s_group,sizeof(STORAGE_GROUP_T));
					apmib_set(MIB_STORAGE_GROUP_MOD,(void*)s_groups);
					break;
				}
			}
		}

		snprintf(cmdBuffer,50,"select%d",i);
		strSelect =  req_get_cstream_var(wp,(cmdBuffer),"");
		if(!strSelect[0])
			continue;

		apmib_get(MIB_STORAGE_GROUP_TBL_NUM,(void*)&number);
		for(j = 0;j < number;j++)
		{
			memset(&s_group,'\0',sizeof(STORAGE_GROUP_T));
			*((char*)&s_group) = (char)(j+1);
			apmib_get(MIB_STORAGE_GROUP_TBL,(void*)&s_group);

			//printf("flag2:%d.\n",s_group.storage_group_sharefolder_flag);
			if(atoi(strGroup) == (j+1)){
				if(s_group.storage_group_sharefolder_flag == 1){
					memset(tmpBuff,'\0',100);
					strcpy(tmpBuff,"group is already have share folder");
					goto setErr_DiskCreateShare;
				}
				strcpy(s_group.storage_group_sharefolder,strSelect);
				strcpy(s_group.storage_group_displayname,strDisplayName);
				s_group.storage_group_sharefolder_flag = 1;

				*((char*)&s_groups) = (char)atoi(strGroup);
				apmib_get(MIB_STORAGE_GROUP_TBL,(void*)(s_groups));
				memcpy(&(s_groups[1]),&s_group,sizeof(STORAGE_GROUP_T));
				apmib_set(MIB_STORAGE_GROUP_MOD,(void*)s_groups);

				/*memset(cmdBuffer,'\0',50);
				snprintf(cmdBuffer,50,"chgrp %s %s",s_group.storage_group_name,strSelect);
				system(cmdBuffer);*/

				storage_UpdateSambaConf();
				goto setOk_DiskCreateShare;
			}
		}
	}

setOk_DiskCreateShare:
	apmib_update_web(CURRENT_SETTING);

	submitUrl = req_get_cstream_var(wp, "submit-url", "");
	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);
	return;

setErr_DiskCreateShare:
	ERR_MSG(tmpBuff);

}

void formDiskCfg(request *wp, char * path, char * query)
{
	char *submitUrl,*strLocation,*strDeleteAll,*strDeleteSelect,*strDeleteVal;
	int number,i,shareNum = 0;
	char tmpBuff[20];

	STORAGE_GROUP_T	s_group;
	STORAGE_GROUP_T s_groups[2];

	submitUrl = req_get_cstream_var(wp, "submit_url", "");

	if(strcmp(submitUrl,"/skb_storage_createsharefolder.htm")){
		strDeleteAll =  req_get_cstream_var(wp, "Delete_All", "");
		if(strDeleteAll[0]){
			apmib_get(MIB_STORAGE_GROUP_TBL_NUM,(void*)&number);
			for(i = 0;i < number;i++)
			{
				memset(&s_group,'\0',sizeof(STORAGE_GROUP_T));
				*((char*)&s_group) = (char)(i+1);
				apmib_get(MIB_STORAGE_GROUP_TBL,(void*)&s_group);

				if(s_group.storage_group_sharefolder_flag == 1){
					s_group.storage_group_sharefolder_flag = 0;
					memset(s_group.storage_group_sharefolder,'\0',MAX_FOLDER_NAME_LEN);
					memset(s_group.storage_group_displayname,'\0',MAX_DISPLAY_NAME_LEN);

					memset(s_groups,'\0',2*sizeof(STORAGE_GROUP_T));
					*((char*)s_groups) = (char)(i+1);
					apmib_get(MIB_STORAGE_GROUP_TBL,(void*)s_groups);
					memcpy(&(s_groups[1]),&s_group,sizeof(STORAGE_GROUP_T));
					apmib_set(MIB_STORAGE_GROUP_MOD,(void*)s_groups);
				}
			}
			goto setOk_DiskCfg;
		}

		strDeleteSelect =  req_get_cstream_var(wp, "Delete_Selected", "");
		apmib_get(MIB_STORAGE_GROUP_TBL_NUM,(void*)&number);
		for(i = 0;i < number;i++)
		{
			memset(&s_group,'\0',sizeof(STORAGE_GROUP_T));
			*((char*)&s_group) = (char)(i+1);
			apmib_get(MIB_STORAGE_GROUP_TBL,(void*)&s_group);

			if(s_group.storage_group_sharefolder_flag == 1){
				memset(tmpBuff,'\0',20);
				snprintf(tmpBuff,20,"delete%d",i);
				strDeleteVal = req_get_cstream_var(wp, tmpBuff, "");

				if(!strcmp(strDeleteVal,s_group.storage_group_name)){
					s_group.storage_group_sharefolder_flag = 0;
					memset(s_group.storage_group_sharefolder,'\0',MAX_FOLDER_NAME_LEN);
					memset(s_group.storage_group_displayname,'\0',MAX_DISPLAY_NAME_LEN);

					memset(s_groups,'\0',2*sizeof(STORAGE_GROUP_T));
					*((char*)s_groups) = (char)(i+1);
					apmib_get(MIB_STORAGE_GROUP_TBL,(void*)s_groups);
					memcpy(&(s_groups[1]),&s_group,sizeof(STORAGE_GROUP_T));
					apmib_set(MIB_STORAGE_GROUP_MOD,(void*)s_groups);
				}
			}
		}
		storage_UpdateSambaConf();
	}else{
		strLocation =  req_get_cstream_var(wp, "Create_Share", "");
		apmib_set(MIB_STORAGE_FOLDER_LOCAL,(void*)strLocation);
		goto setOk_DiskCfg;
	}
setOk_DiskCfg:
	apmib_update_web(CURRENT_SETTING);
	if(submitUrl[0])
		send_redirect_perm(wp, submitUrl);
	return;

}

void formDiskManagementAnon(request *wp, char * path, char * query)
{
	char *submitUrl,*strAnonDiskEnable,*strAnonEnable;
	char *strAnonFtpEnable;
	int mib_val = 0;

	strAnonEnable = req_get_cstream_var(wp,("AnonEnabled"),"");

	if(!strcmp(strAnonEnable,"ON")){
		mib_val = 1;
		apmib_set(MIB_STORAGE_ANON_ENABLE,(void*)&mib_val);

		//strAnonFtpEnable = req_get_cstream_var(wp,("anonymous_ftp_enable"),"");
		strAnonDiskEnable = req_get_cstream_var(wp,("anonymous_disk_enable"),"");
		/*if(!strcmp(strAnonFtpEnable,"enabled")){
			mib_val = 1;
			apmib_set(MIB_STORAGE_ANON_FTP_ENABLE,(void*)&mib_val);
		}else{
			mib_val = 0;
			apmib_set(MIB_STORAGE_ANON_FTP_ENABLE,(void*)&mib_val);
		}*/

		if(!strcmp(strAnonDiskEnable,"enabled")){
			mib_val = 1;
			apmib_set(MIB_STORAGE_ANON_DISK_ENABLE,(void*)&mib_val);
		}else{
			mib_val = 0;
			apmib_set(MIB_STORAGE_ANON_DISK_ENABLE,(void*)&mib_val);
		}
	}else{
		mib_val = 0;
		apmib_set(MIB_STORAGE_ANON_ENABLE,(void*)&mib_val);

		apmib_set(MIB_STORAGE_ANON_DISK_ENABLE,(void*)&mib_val);
		//apmib_set(MIB_STORAGE_ANON_FTP_ENABLE,(void*)&mib_val);
	}

setOk_AnonAccessCfg:
	apmib_update_web(CURRENT_SETTING);
	storage_UpdateSambaConf();

	submitUrl = req_get_cstream_var(wp, "submit-url", "");
	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);
	return;

}

void formDiskManagementUser(request *wp, char * path, char * query)
{
	char *submitUrl, *strDeleAll,*strVal,*strUserIndex;
	char tmpBuff[20];
	char cmdBuffer[30];
	int number,i;
	STORAGE_USER_T	s_user;
	int	index;

	submitUrl = req_get_cstream_var(wp, "submit_url", "");
	if(strcmp(submitUrl,"/skb_storage_edituser.htm")){
		apmib_get(MIB_STORAGE_USER_TBL_NUM,(void*)&number);
		strDeleAll = req_get_cstream_var(wp,("Delete_All"),"");
		if(strDeleAll[0]){

			for(i = 0; i < number;i++)
			{
				memset(&s_user,'\0',sizeof(STORAGE_USER_T));
				*((char*)&s_user) = (char)(i+1);
				apmib_get(MIB_STORAGE_USER_TBL,(void*)&s_user);

				memset(cmdBuffer,'\0',30);
				snprintf(cmdBuffer,30,"deluser %s",s_user.storage_user_name);
				system(cmdBuffer);
				memset(cmdBuffer,'\0',30);
				snprintf(cmdBuffer,30,"smbpasswd -del %s",s_user.storage_user_name);
				system(cmdBuffer);
				memset(cmdBuffer,'\0',30);
				snprintf(cmdBuffer,30,"rm -rf /home/%s",s_user.storage_user_name);
				system(cmdBuffer);
			}

			apmib_set(MIB_STORAGE_USER_DELALL,(void*)&s_user);
			goto setOk_deleteUser;
		}


		for(i = number;i > 0;i--)
		{
			memset(tmpBuff,'\0',20);
			snprintf(tmpBuff, 20, "select%d", i);
			strVal =  req_get_cstream_var(wp,tmpBuff,"");

			if(!strcmp(strVal,"ON")){
				*((char*)&s_user) = (char)i;
				apmib_get(MIB_STORAGE_USER_TBL,(void*)&s_user);

				memset(cmdBuffer,'\0',30);
				snprintf(cmdBuffer,30,"deluser %s",s_user.storage_user_name);
				system(cmdBuffer);
				memset(cmdBuffer,'\0',30);
				snprintf(cmdBuffer,30,"smppasswd -del %s",s_user.storage_user_name);
				system(cmdBuffer);
				memset(cmdBuffer,'\0',30);
				snprintf(cmdBuffer,30,"rm -rf /home/%s",s_user.storage_user_name);
				system(cmdBuffer);

				apmib_set(MIB_STORAGE_USER_DEL,(void*)&s_user);
			}
		}
	}else{
		strUserIndex = req_get_cstream_var(wp, "userindex", "");
		index = atoi(strUserIndex);
		if(strUserIndex[0])
			apmib_set(MIB_STORAGE_USER_EDIT_INDEX,(void*)&index);
		goto setOk_deleteUser;
	}

setOk_deleteUser:
	apmib_update_web(CURRENT_SETTING);

	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);
	return;
}

void formDiskManagementGroup(request *wp, char * path, char * query)
{
	char *submitUrl, *strDeleAll,*strVal,*strGroupIndex;
	char tmpBuff[20];
	char cmdBuffer[30];
	int number,i,user_num,j;
	STORAGE_GROUP_T	s_group;
	STORAGE_USER_T	s_user;
	STORAGE_USER_T	s_users[2] = {0};
	int			 index;
	submitUrl = req_get_cstream_var(wp, "submit_url", "");

	if(strcmp(submitUrl,"/skb_storage_editgroup.htm")){
		apmib_get(MIB_STORAGE_GROUP_TBL_NUM,(void*)&number);
		apmib_get(MIB_STORAGE_USER_TBL_NUM,(void*)&user_num);

		/*Delete All Group Process*/
		strDeleAll = req_get_cstream_var(wp,("Delete_All"),"");
		if(strDeleAll[0]){
			for(i = 0;i < user_num;i++)
			{
				memset(&s_user,'\0',sizeof(STORAGE_USER_T));
				*((char*)&s_user) = (char)(i+1);
				apmib_get(MIB_STORAGE_USER_TBL,(void*)&s_user);

				strcpy(s_user.storage_user_group,"--");
				*((char*)s_users) = (char)(i+1);
				apmib_get(MIB_STORAGE_USER_TBL,(void*)(s_users));
				memcpy(&(s_users[1]),&s_user,sizeof(STORAGE_USER_T));
				apmib_set(MIB_STORAGE_USER_MOD,(void*)s_users);

				memset(cmdBuffer,'\0',30);
				snprintf(cmdBuffer,30,"deluser %s",s_user.storage_user_name);
				system(cmdBuffer);
				memset(cmdBuffer,'\0',30);
				snprintf(cmdBuffer,30,"rm -rf  /home/%s",s_user.storage_user_name);
				system(cmdBuffer);
				memset(cmdBuffer,'\0',30);
				snprintf(cmdBuffer,30,"adduser %s",s_user.storage_user_name);
				system(cmdBuffer);
				//may be need modify

			}

			for(i = 0;i < number;i++)
			{
				memset(&s_group,'\0',sizeof(STORAGE_GROUP_T));
				*((char*)&s_group) = (char)(i+1);
				apmib_get(MIB_STORAGE_GROUP_TBL,(void*)&s_group);

				memset(cmdBuffer,'\0',30);
				snprintf(cmdBuffer,30,"delgroup %s",s_group.storage_group_name);
				system(cmdBuffer);

			}

			apmib_set(MIB_STORAGE_GROUP_DELALL,(void*)&s_group);
			storage_UpdateSambaConf();
			goto setOk_deleteGroup;
		}


		/*Delete Selected Group Process*/
		for(i = number;i > 0;i--)
		{
			memset(tmpBuff,'\0',20);
			snprintf(tmpBuff, 20, "select%d", i);
			strVal =  req_get_cstream_var(wp,tmpBuff,"");

			if(!strcmp(strVal,"ON")){
				*((char*)&s_group) = (char)i;
				apmib_get(MIB_STORAGE_GROUP_TBL,(void*)&s_group);
				apmib_set(MIB_STORAGE_GROUP_DEL,(void*)&s_group);


				memset(cmdBuffer,'\0',30);
				snprintf(cmdBuffer,30,"delgroup %s",s_group.storage_group_name);
				system(cmdBuffer);

				//apmib_get(MIB_STORAGE_USER_TBL_NUM,(void*)&user_num);
				for(j = 0;j < user_num;j++)
				{
					*((char*)&s_user) = (char)(j+1);
					apmib_get(MIB_STORAGE_USER_TBL,(void*)&s_user);

					if(!strcmp(s_user.storage_user_group,s_group.storage_group_name)){
						memset(s_user.storage_user_group,'\0',10);
						strcpy(s_user.storage_user_group,"--");
						*((char*)s_users) = (char)(j+1);
						apmib_get(MIB_STORAGE_USER_TBL,(void*)(s_users));
						memcpy(&(s_users[1]),&s_user,sizeof(STORAGE_USER_T));
						apmib_set(MIB_STORAGE_USER_MOD,(void*)s_users);

						memset(cmdBuffer,'\0',30);
						snprintf(cmdBuffer,30,"deluser %s",s_user.storage_user_name);
						system(cmdBuffer);
						memset(cmdBuffer,'\0',30);
						snprintf(cmdBuffer,30,"rm -rf  /home/%s",s_user.storage_user_name);
						system(cmdBuffer);
						memset(cmdBuffer,'\0',30);
						snprintf(cmdBuffer,30,"adduser %s",s_user.storage_user_name);
						system(cmdBuffer);
						//may be need modify
					}
				}

			}
		}
		storage_UpdateSambaConf();
		goto setOk_deleteGroup;
	}else{
		strGroupIndex = req_get_cstream_var(wp, "groupindex", "");
		index = atoi(strGroupIndex);
		if(strGroupIndex[0]){
			apmib_set(MIB_STORAGE_GROUP_EDIT_INDEX,(void*)&index);
		}
		goto setOk_deleteGroup;
	}

setOk_deleteGroup:
	apmib_update_web(CURRENT_SETTING);

	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);
	return;
}

void formDiskCreateUser(request *wp, char * path, char * query)
{
		char *submitUrl, *strName, *strPasswd, *strConfPasswd,*strGroup;
		char tmpBuff[100];
		char cmdBuffer[100];
		STORAGE_USER_T	s_user;
		STORAGE_GROUP_T	s_group;

		unsigned char number,i;

		strName = req_get_cstream_var(wp,("username"),"");
		strPasswd = req_get_cstream_var(wp,("newpass"),"");
		strConfPasswd = req_get_cstream_var(wp,("confpass"),"");
		strGroup = req_get_cstream_var(wp,("Group"),"");

		if(!strName[0]){
			strcpy(tmpBuff, ("userName should not be NULL!"));
			goto setErr_createUser;
		}

		if(!strPasswd[0] || !strConfPasswd[0]){
			strcpy(tmpBuff, ("passwd or confpasswd should not be NULL!"));
			goto setErr_createUser;
		}

		if(strcmp(strPasswd,strConfPasswd)){
			strcpy(tmpBuff, ("passwd should be equal to confpasswd"));
			goto setErr_createUser;
		}

		if(!strcmp(strName,"root") || !strcmp(strName,"nobody")){
			strcpy(tmpBuff,"user Name should not be nobody or root");
			goto setErr_createUser;
		}

		apmib_get(MIB_STORAGE_USER_TBL_NUM,(void*)&number);
		if(number >= MAX_USER_NUM){
			snprintf(tmpBuff,100,"user num shoule not be more than %d",MAX_USER_NUM);
			goto setErr_createUser;
		}

		for(i = 0;i <number;i++)
		{
			memset(&s_user,'\0',sizeof(STORAGE_USER_T));
			*((char*)&s_user) = (char)(i+1);
			apmib_get(MIB_STORAGE_USER_TBL,(void*)&s_user);

			if(strlen(s_user.storage_user_name) == strlen(strName)
				&& strncmp(s_user.storage_user_name,strName,strlen(strName))){
				strcpy(tmpBuff, ("user name is already exist,Please choose another user name"));
				goto setErr_createUser;
			}
		}

		*((char*)&s_group) = (char)(atoi(strGroup));
		if(atoi(strGroup) == 0){
			memset(&s_user,'\0',sizeof(STORAGE_USER_T));
			strcpy(s_user.storage_user_group,"--");
		}else{
			*((char*)&s_group) = (char)(atoi(strGroup));
			apmib_get(MIB_STORAGE_GROUP_TBL,(void*)&s_group);
			memset(&s_user,'\0',sizeof(STORAGE_USER_T));
			strcpy(s_user.storage_user_group,s_group.storage_group_name);
		}

		number++;
		apmib_set(MIB_STORAGE_USER_TBL_NUM,(void*)&number);

		strcpy(s_user.storage_user_name,strName);
		strcpy(s_user.storage_user_password,strPasswd);
		apmib_set(MIB_STORAGE_USER_ADD,(void*)&s_user);

		memset(cmdBuffer,'\0',100);
		if(atoi(strGroup) == 0){
			snprintf(cmdBuffer,100,"adduser %s",strName);
		}else{
			snprintf(cmdBuffer,100,"adduser -G %s %s",s_group.storage_group_name,strName);
		}

		system(cmdBuffer);
		memset(cmdBuffer,'\0',100);
		snprintf(cmdBuffer,100,"smbpasswd %s %s",strName,strPasswd);
		system(cmdBuffer);

	setOk_createUser:
		apmib_update_web(CURRENT_SETTING);

		submitUrl = req_get_cstream_var(wp, "submit-url", "");
		if (submitUrl[0])
			send_redirect_perm(wp, submitUrl);
		return;

	setErr_createUser:
		ERR_MSG(tmpBuff);
}


void formDiskEditUser(request *wp, char * path, char * query)
{
	char 	*submitUrl, *strOrigPasswd,*strNewPasswd,*strConfPasswd,*strGroup;
	int	    index;
	char	tmpBuff[100];
	char	cmdBuffer[50];

	STORAGE_USER_T 	s_user;
	STORAGE_GROUP_T	s_group;
	STORAGE_USER_T	s_users[2] = {0};

	memset(tmpBuff,'\0',100);
	memset(cmdBuffer,'\0',50);
	strOrigPasswd = req_get_cstream_var(wp,("origpass"),"");
	strNewPasswd = req_get_cstream_var(wp,("newpass"),"");
	strConfPasswd = req_get_cstream_var(wp,("confpass"),"");
	strGroup = req_get_cstream_var(wp,("Group"),"");

	apmib_get(MIB_STORAGE_USER_EDIT_INDEX,(void*)&index);
	memset(&s_user,'\0',sizeof(STORAGE_USER_T));
	*((char*)&s_user) = (char)index;
	apmib_get(MIB_STORAGE_USER_TBL,(void*)&s_user);

	if(strcmp(strOrigPasswd,s_user.storage_user_password)){
		strcpy(tmpBuff,"Orig Password is wrong,Please Enter the password again");
		goto setError_EditUser;
	}
	if(!strNewPasswd[0] || !strConfPasswd[0]){
		strcpy(tmpBuff,"newpassword or confpassword should not be empty");
		goto setError_EditUser;
	}
	if(strcmp(strNewPasswd,strConfPasswd)){
		strcpy(tmpBuff,"newpassword is not equal confpassword");
		goto setError_EditUser;
	}

	strcpy(s_user.storage_user_password,strNewPasswd);
	if(atoi(strGroup) == 0)
		strcpy(s_user.storage_user_group,"--");
	else{
		memset(&s_group,'\0',sizeof(STORAGE_GROUP_T));
		*((char*)&s_group) = (char)atoi(strGroup);
		apmib_get(MIB_STORAGE_GROUP_TBL,(void*)&s_group);
		strcpy(s_user.storage_user_group,s_group.storage_group_name);
	}

	*((char*)s_users) = (char)index;
	apmib_get(MIB_STORAGE_USER_TBL,(void*)s_users);
	memcpy(&(s_users[1]),&s_user,sizeof(STORAGE_USER_T));
	apmib_set(MIB_STORAGE_USER_MOD,(void*)s_users);

	snprintf(cmdBuffer,50,"smbpasswd -del %s",s_user.storage_user_name);
	system(cmdBuffer);
	memset(cmdBuffer,'\0',50);
	snprintf(cmdBuffer,50,"smbpasswd %s %s",s_user.storage_user_name,s_user.storage_user_password);
	system(cmdBuffer);

setOk_EditUser:
	apmib_update_web(CURRENT_SETTING);
	storage_UpdateSambaConf();

	submitUrl = req_get_cstream_var(wp, "submit-url", "");
	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);
	return;

setError_EditUser:
	ERR_MSG(tmpBuff);
}

void formDiskEditGroup(request *wp, char * path, char * query)
{
	char 	*submitUrl, *strAccess;
	int		 index;

	STORAGE_GROUP_T s_group;
	STORAGE_GROUP_T	s_groups[2] = {0};
	strAccess = req_get_cstream_var(wp,("Access"),"");

	apmib_get(MIB_STORAGE_GROUP_EDIT_INDEX,(void*)&index);
	memset(&s_group,'\0',sizeof(STORAGE_GROUP_T));
	*((char*)&s_group) = (char)index;
	apmib_get(MIB_STORAGE_GROUP_TBL,(void*)&s_group);
	strcpy(s_group.storage_group_access,strAccess);

	*((char*)s_groups) = (char)index;
	apmib_get(MIB_STORAGE_GROUP_TBL,(void*)s_groups);
	memcpy(&(s_groups[1]),&s_group,sizeof(STORAGE_GROUP_T));
	apmib_set(MIB_STORAGE_GROUP_MOD,(void*)s_groups);

setOk_EditGroup:
	apmib_update_web(CURRENT_SETTING);
	storage_UpdateSambaConf();

	submitUrl = req_get_cstream_var(wp, "submit-url", "");
	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);
	return;
}


void formDiskCreateGroup(request *wp, char * path, char * query)
{
		char *submitUrl, *strName,*strAccess;
		char tmpBuff[100];
		char cmdBuffer[100];
		STORAGE_GROUP_T	s_group;
		unsigned char	 number,i;

		strName = req_get_cstream_var(wp,("groupname"),"");
		strAccess = req_get_cstream_var(wp,("Access"),"");

		if(!strcmp(strName,"root") || !strcmp(strName,"nobody")){
			strcpy(tmpBuff,"group name should not be root or nobody");
			goto setErr_createGroup;
		}

		apmib_get(MIB_STORAGE_GROUP_TBL_NUM,(void*)&number);

		if(number >= MAX_GROUP_NUM){
			snprintf(tmpBuff,100,"group num shoule not be more than %d",MAX_GROUP_NUM);
			goto setErr_createGroup;
		}

		for(i = 0;i <number;i++)
		{
			memset(&s_group,'\0',sizeof(STORAGE_GROUP_T));
			*((char*)&s_group) = (char)(i+1);
			apmib_get(MIB_STORAGE_GROUP_TBL,(void*)&s_group);

			if(!strcmp(strName,s_group.storage_group_name)){
				strcpy(tmpBuff,("group name repeat"));
				goto setErr_createGroup;
			}

			if(strlen(s_group.storage_group_name) == strlen(strName)
				&& strncmp(s_group.storage_group_name,strName,strlen(strName))){
				strcpy(tmpBuff, ("group name is already exist,Please choose another group name"));
				goto setErr_createGroup;
			}
		}

		number++;
		apmib_set(MIB_STORAGE_GROUP_TBL_NUM,(void*)&number);

		memset(&s_group,'\0',sizeof(STORAGE_GROUP_T));
		strcpy(s_group.storage_group_name,strName);
		strcpy(s_group.storage_group_access,strAccess);
		s_group.storage_group_sharefolder_flag = 0;
		apmib_set(MIB_STORAGE_GROUP_ADD,(void*)&s_group);

		memset(cmdBuffer,'\0',100);
		snprintf(cmdBuffer,100,"addgroup %s",strName);
		system(cmdBuffer);

	setOk_createGroup:
		apmib_update_web(CURRENT_SETTING);

		submitUrl = req_get_cstream_var(wp, "submit-url", "");
		if (submitUrl[0])
			send_redirect_perm(wp, submitUrl);
		return;

	setErr_createGroup:
		ERR_MSG(tmpBuff);
}
#endif

/* rewritten in private.c - 2015-04-13 14:44 young */
#ifndef __DAVO__
void formUpload(request *wp, char * path, char * query)
{
	//int fh;
	int len;
	int locWrite;
	int numLeft;
	//int numWrite;
	IMG_HEADER_Tp pHeader;
	char tmpBuf[200];
#ifndef REBOOT_CHECK
	char lan_ip_buf[30];
	char lan_ip[30];
#endif
	char *submitUrl;
	int flag=0, startAddr=-1;
	int isIncludeRoot=0;
#ifndef NO_ACTION
	//int pid;
#endif
	int head_offset=0;
	int update_fw=0, update_cfg=0;
	//Support WAPI/openssl, the flash MUST up to 4m
/*
#if defined(CONFIG_RTL_WAPI_SUPPORT) || defined(HTTP_FILE_SERVER_SUPPORTED)
	int fwSizeLimit = 0x400000;
#elif defined( CONFIG_RTK_VOIP )
	int fwSizeLimit = 0x400000;
#else
	int fwSizeLimit = 0x200000;
#endif
*/
	int fwSizeLimit = CONFIG_FLASH_SIZE;
	unsigned char isValidfw = 0;

#if defined(CONFIG_APP_FWD)
#define FWD_CONF "/var/fwd.conf"
	int newfile = 1;
	extern int get_shm_id();
	extern int clear_fwupload_shm();
	int shm_id = get_shm_id();
#endif

#ifndef REBOOT_CHECK
	apmib_get( MIB_IP_ADDR,  (void *)lan_ip_buf) ;
	sprintf(lan_ip,"%s",inet_ntoa(*((struct in_addr *)lan_ip_buf)) );
#endif

	submitUrl = req_get_cstream_var(wp, "submit-url", "");
	//fprintf(stderr,"####%s:%d submitUrl=%s###\n",  __FILE__, __LINE__ , submitUrl);
	//support multiple image
	head_offset = find_head_offset((char *)wp->upload_data);
	//fprintf(stderr,"####%s:%d %d wp->upload_data=%p###\n",  __FILE__, __LINE__ , head_offset, wp->upload_data);
	//fprintf(stderr,"####%s:%d content_length=%s###contenttype=%s###\n",  __FILE__, __LINE__ ,wp->content_length , wp->content_type);
	if (head_offset == -1) {
		strcpy(tmpBuf, "<b>Invalid file format!");
		goto ret_upload;
	}
	while ((head_offset+sizeof(IMG_HEADER_T)) <  wp->upload_len) {
		locWrite = 0;
		pHeader = (IMG_HEADER_Tp) &wp->upload_data[head_offset];
		len = pHeader->len;
#ifdef _LITTLE_ENDIAN_
		len  = DWORD_SWAP(len);
#endif
		numLeft = len + sizeof(IMG_HEADER_T);
		// check header and checksum
		if (!memcmp(&wp->upload_data[head_offset], FW_HEADER, SIGNATURE_LEN) ||
		    !memcmp(&wp->upload_data[head_offset], FW_HEADER_WITH_ROOT, SIGNATURE_LEN)) {
		    	isValidfw = 1;
			flag = 1;
			//Reboot_Wait = Reboot_Wait+ 50;
		} else if (!memcmp(&wp->upload_data[head_offset], WEB_HEADER, SIGNATURE_LEN)) {
			isValidfw = 1;
			flag = 2;
			//Reboot_Wait = Reboot_Wait+ 40;
		} else if (!memcmp(&wp->upload_data[head_offset], ROOT_HEADER, SIGNATURE_LEN)) {
			isValidfw = 1;
			flag = 3;
			//Reboot_Wait = Reboot_Wait+ 60;
			isIncludeRoot = 1;
		}else if (
#ifdef COMPRESS_MIB_SETTING
				!memcmp(&wp->upload_data[head_offset], COMP_HS_SIGNATURE, COMP_SIGNATURE_LEN) ||
				!memcmp(&wp->upload_data[head_offset], COMP_DS_SIGNATURE, COMP_SIGNATURE_LEN) ||
				!memcmp(&wp->upload_data[head_offset], COMP_CS_SIGNATURE, COMP_SIGNATURE_LEN)
#else
				!memcmp(&wp->upload_data[head_offset], CURRENT_SETTING_HEADER_TAG, TAG_LEN) ||
				!memcmp(&wp->upload_data[head_offset], CURRENT_SETTING_HEADER_FORCE_TAG, TAG_LEN) ||
				!memcmp(&wp->upload_data[head_offset], CURRENT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) ||
				!memcmp(&wp->upload_data[head_offset], DEFAULT_SETTING_HEADER_TAG, TAG_LEN) ||
				!memcmp(&wp->upload_data[head_offset], DEFAULT_SETTING_HEADER_FORCE_TAG, TAG_LEN) ||
				!memcmp(&wp->upload_data[head_offset], DEFAULT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN) ||
				!memcmp(&wp->upload_data[head_offset], HW_SETTING_HEADER_TAG, TAG_LEN) ||
				!memcmp(&wp->upload_data[head_offset], HW_SETTING_HEADER_FORCE_TAG, TAG_LEN) ||
				!memcmp(&wp->upload_data[head_offset], HW_SETTING_HEADER_UPGRADE_TAG, TAG_LEN)
#endif
			) {
#if 1
			strcpy(tmpBuf, ("<b>Invalid file format! Should upload fireware but not config dat!"));
			goto ret_upload;
#else
#ifdef COMPRESS_MIB_SETTING
				COMPRESS_MIB_HEADER_Tp pHeader_cfg;
				pHeader_cfg = (COMPRESS_MIB_HEADER_Tp)&wp->upload_data[head_offset];
				if(!memcmp(&wp->upload_data[head_offset], COMP_CS_SIGNATURE, COMP_SIGNATURE_LEN)) {
					head_offset +=  pHeader_cfg->compLen+sizeof(COMPRESS_MIB_HEADER_T);
					configlen = head_offset;
				}
				else {
					head_offset +=  pHeader_cfg->compLen+sizeof(COMPRESS_MIB_HEADER_T);
				}
#else
#ifdef HEADER_LEN_INT
				if(!memcmp(&wp->upload_data[head_offset], HW_SETTING_HEADER_TAG, TAG_LEN) ||
				!memcmp(&wp->upload_data[head_offset], HW_SETTING_HEADER_FORCE_TAG, TAG_LEN) ||
				!memcmp(&wp->upload_data[head_offset], HW_SETTING_HEADER_UPGRADE_TAG, TAG_LEN))
				{
					HW_PARAM_HEADER_Tp phwHeader_cfg;
					phwHeader_cfg = (HW_PARAM_HEADER_Tp)&wp->upload_data[head_offset];
					head_offset +=  phwHeader_cfg->len+sizeof(HW_PARAM_HEADER_T);
				}
				else
#endif
				{
					PARAM_HEADER_Tp pHeader_cfg;
					pHeader_cfg = (PARAM_HEADER_Tp)&wp->upload_data[head_offset];
					head_offset +=  pHeader_cfg->len+sizeof(PARAM_HEADER_T);
				}
#endif
				isValidfw = 1;
				update_cfg = 1;
				continue;
#endif
		}
		else {
			if (isValidfw == 1)
				break;
			strcpy(tmpBuf, "<b>Invalid file format!");
			goto ret_upload;
		}

		if (len > fwSizeLimit) { //len check by sc_yang
			sprintf(tmpBuf, "<b>Image len exceed max size 0x%x ! len=0x%x</b><br>",fwSizeLimit, len);
			goto ret_upload;
		}
#ifdef CONFIG_RTL_WAPI_SUPPORT
		if((flag == 3) && (len>WAPI_AREA_BASE)) {
			sprintf(tmpBuf, "<b>Root image len 0x%x exceed 0x%x which will overwrite wapi area at flash ! </b><br>", len, WAPI_AREA_BASE);
			goto ret_upload;
		}
#endif
		if ( (flag == 1) || (flag == 3)) {
			if ( !fwChecksumOk((char *)&wp->upload_data[sizeof(IMG_HEADER_T)+head_offset], len)) {
				sprintf(tmpBuf, "<b>Image checksum mismatched! len=0x%x, checksum=0x%x</b><br>", len,
					*((unsigned short *)&wp->upload_data[len-2]) );
				goto ret_upload;
			}
		}
		else {
			char *ptr = (char *)&wp->upload_data[sizeof(IMG_HEADER_T)+head_offset];
			if ( !CHECKSUM_OK((unsigned char *)ptr, len) ) {
				sprintf(tmpBuf, "<b>Image checksum mismatched! len=0x%x</b><br>", len);
				goto ret_upload;
			}
		}
#ifdef HOME_GATEWAY
#ifdef REBOOT_CHECK
		sprintf(tmpBuf, "Upload successfully (size = %d bytes)!<br><br>Firmware update in progress.", wp->upload_len);
#else
		sprintf(tmpBuf, "Upload successfully (size = %d bytes)!<br><br>Firmware update in progress.<br> Do not turn off or reboot the AP during this time.", wp->upload_len);
#endif
#else
		sprintf(tmpBuf, "Upload successfully (size = %d bytes)!<br><br>Firmware update in progress.<br> Do not turn off or reboot the AP during this time.", wp->upload_len);
#endif
		//sc_yang
		head_offset += len + sizeof(IMG_HEADER_T);
		startAddr = -1 ; //by sc_yang to reset the startAddr for next image
		update_fw = 1;
	} //while //sc_yang

	isFWUPGRADE = 1;

#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
	Stop_Domain_Query_Process();
	WaitCountTime=2;
#endif

#if defined(CONFIG_RTL_819X)
#ifdef RTL_8367R_DUAL_BAND
	Reboot_Wait = (wp->upload_len/69633)+57+5+15;
#elif defined(RTL_8367R_8881a_DUAL_BAND)
	Reboot_Wait = (wp->upload_len/69633)+57+5+25;
#elif defined(CONFIG_RTL_8198C)
	Reboot_Wait = (wp->upload_len/19710)+50+5;
#else
	Reboot_Wait = (wp->upload_len/69633)+57+5;
#endif
	if (update_cfg==1 && update_fw==0) {
		strcpy(tmpBuf, "<b>Update successfully!");
		Reboot_Wait = (wp->upload_len/69633)+45+5;
		isCFG_ONLY= 1;
	}
#else
	Reboot_Wait = (wp->upload_len/43840)+35;
	if (update_cfg==1 && update_fw==0) {
		strcpy(tmpBuf, "<b>Update successfully!");
		Reboot_Wait = (wp->upload_len/43840)+30;
		isCFG_ONLY= 1;
	}
#endif

#ifdef REBOOT_CHECK
	sprintf(lastUrl,"%s","/skb_status.htm");
	sprintf(okMsg,"%s",tmpBuf);
	countDownTime = Reboot_Wait;
	send_redirect_perm(wp, COUNTDOWN_PAGE);
#else
	OK_MSG_FW(tmpBuf, submitUrl,Reboot_Wait,lan_ip);
#endif
	return;

ret_upload:

#if defined(CONFIG_APP_FWD)
	clear_fwupload_shm(shm_id);
#endif
	Reboot_Wait=0;
	ERR_MSG(tmpBuf);
}
#endif

/////////////////////////////////////////////////////////////////////////////
void formPasswordSetup(request *wp, char *path, char *query)
{
	char *submitUrl, *strUser, *strPassword, *strConfpass;
	char tmpBuf[100];
	char orgsuper[65];
	char sha256_user[65];
	char sha256_pass[65];

	apmib_set_hist_clear();

	strUser = req_get_cstream_var(wp, "username", "");
	strPassword = req_get_cstream_var(wp, "newpass", "");
	strConfpass = req_get_cstream_var(wp, "confpass", "");

	if (strUser[0] && !strPassword[0]) {
		strcpy(tmpBuf, ("오류: 비밀번호가 비어있습니다."));
		goto setErr_pass;
	}

	if (strcmp(strPassword, strConfpass)) {
		strcpy(tmpBuf, ("오류: 비밀번호를 확인해 주세요."));
		goto setErr_pass;
	}

	if (check_saved_passwd(strPassword) == 0) {
		strcpy(tmpBuf, ("오류: 비밀번호를 확인해 주세요."));
		goto setErr_pass;
	}

	cal_sha256(strUser, sha256_user);
	cal_sha256(strPassword, sha256_pass);

	if (strUser[0]) {
#ifdef SUPER_NAME_SUPPORT
		/* Check if user name is the same as supervisor name */
		nvram_get_r_def("x_SUPER_NAME", orgsuper, sizeof(orgsuper), "");
		if (!orgsuper[0]) {
			strcpy(tmpBuf, ("오류: 관리자 이름 MIB 읽기 실패!"));
			goto setErr_pass;
		}
		if (!strcmp(orgsuper, sha256_user)) {
			strcpy(tmpBuf, ("오류: 사용자 이름과 관리자 이름이 같습니다."));
			goto setErr_pass;
		}
#endif
	} else {
		/* Set NULL account */
		strcpy(tmpBuf, ("오류: 사용자 이름이 비어있습니다."));
		goto setErr_pass;

	}

	/* Set user account to MIB */
	/*
	if ( apmib_nvram_set("x_USER_NAME", sha256_user) < 0 ) {
		strcpy(tmpBuf, ("오류: 사용자 이름을 MIB 데이터베이스에 설정할 수 없습니다."));
		goto setErr_pass;
	}
	 */
	if (apmib_nvram_set("x_USER_PASSWORD", sha256_pass) < 0) {
		strcpy(tmpBuf, ("오류: 사용자 비밀번호를 MIB 데이터베이스에 설정할 수 없습니다."));
		goto setErr_pass;
	}
	web_config_trace(5, 12);	/* management/password */
	/* Retrieve next page URL */
	apmib_update_web(CURRENT_SETTING);

	submitUrl = req_get_cstream_var(wp, "submit-url", "");	// hidden page

//#ifdef LOGIN_URL
//      if (strUser[0])
//              submitUrl = "/skb_login.htm";
//#endif
	if (wp->userName && strcmp(wp->userName, orgsuper) == 0) {
		send_redirect_perm(wp, "/skb_status.htm");
	} else {
		send_redirect_perm(wp, "/skb_login.htm");
	}

	return;

 setErr_pass:
	ERR_MSG(tmpBuf);
}

////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
void formStats(request *wp, char *path, char *query)
{
	char *submitUrl;

	submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page

	if (submitUrl[0])
		send_redirect_perm(wp, "/skb_stats.htm");
}

static int get_mac_wlan_traffic(char *mac_str, char *ip_traffic_info)
{

	int wlan_if, vwlan_if;
	char wlan_name[32];
	char vwlan_name[8];
	WLAN_STA_INFO_Tp pInfo;
	char *buff;
	int i;
	char client_mac[20];

	buff = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM+1));
	if ( buff == NULL ) {
		printf("Allocate buffer failed!\n");
		return 0;
	}

	for(wlan_if=0; wlan_if<2; wlan_if++) {
		for(vwlan_if=0; vwlan_if<5; vwlan_if++) {

			memset(buff, 0, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM+1));
			if (vwlan_if > 0) {
				sprintf(vwlan_name, "-va%d", vwlan_if-1);
			}
			sprintf(wlan_name, "wlan%d%s", wlan_if, vwlan_if==0?"":vwlan_name);

			if ( getWlStaInfo(wlan_name,  (WLAN_STA_INFO_Tp)buff ) < 0 ) {
				continue;
			}

			for (i=1; i<=MAX_STA_NUM; i++) {
				pInfo = (WLAN_STA_INFO_Tp)&buff[i*sizeof(WLAN_STA_INFO_T)];
				if (pInfo->aid && (pInfo->flags & STA_INFO_FLAG_ASOC)) {
					sprintf(client_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
							pInfo->addr[0],pInfo->addr[1],pInfo->addr[2],pInfo->addr[3],pInfo->addr[4],pInfo->addr[5]);
					if (strcmp(mac_str, client_mac) != 0) {
						continue;
					}

					sprintf(ip_traffic_info, "%s %lu %lu %lu %lu %lu %lu\n",
							mac_str,
							pInfo->rx_only_data_packets,
							pInfo->tx_only_data_packets,
							pInfo->rx_only_data_bytes_high,
							pInfo->rx_only_data_bytes,
							pInfo->tx_only_data_bytes_high,
							pInfo->tx_only_data_bytes
							);

					if (buff)
						free(buff);
					return 1;

				}
			}
		}
	}
	if (buff)
		free(buff);

	return 0;
}

/* APACRTL-92 smlee  */
#define ALL_CONNECTION_INFO "/tmp/all_connection_info"
#define IP_CONNECTION_INFO "/tmp/ip_connection_info"
void formIpConnection(request *wp, char *path, char *query)
{
	char *submitUrl;
	FILE *fp, *fp2;
	char line_buffer[512]={0}, tmp_mac_str[18]={0}, ip_str[16]={0}, if_name[16]={0};
	int lan_port=-1;
	unsigned long long tx_p=0, rx_p=0, tx_bytes=0, rx_bytes=0;
	unsigned long tx_bytes_only_high=0, tx_bytes_only=0, rx_bytes_only_high=0, rx_bytes_only=0;
	int ret=0;
	char ip_traffic_info[512];
	char str_traffic[128];
	char str_wan_traffic[128];
	struct sysinfo info ;

	sysinfo(&info);
	connection_init_time = (unsigned long) info.uptime ;

	/*all connection info*/
	if (access(ALL_CONNECTION_INFO, F_OK)==0)
		unlink(ALL_CONNECTION_INFO);

	fp = fopen(ALL_CONNECTION_INFO, "w");

	if (fp) {
		if (getPortStats(4, str_wan_traffic))
		{
			sscanf(str_wan_traffic, "%llu %llu %llu %llu", &tx_p, &rx_p, &tx_bytes, &rx_bytes);
		}

		fprintf(fp, "%llu %llu %llu %llu\n", tx_p, rx_p, tx_bytes, rx_bytes);
		fclose(fp);
	}


	/*ip connection info*/
	if (access(IP_CONNECTION_INFO, F_OK)==0)
		unlink(IP_CONNECTION_INFO);

	fp = fopen(IP_CONNECTION_INFO, "w");

	if (fp) {
		if((fp2=fopen("/proc/net/arp", "r"))==NULL) {
			fclose(fp);
			return;
		}
		/*lan ip connection info*/
		while(fgets(line_buffer, sizeof(line_buffer), fp2))
		{
			tx_p=0;
			rx_p=0;
			tx_bytes=0;
			rx_bytes=0;

			line_buffer[strlen(line_buffer)-1]='\0';

			sscanf(line_buffer,"%s %*s %*s %s %*s %s",ip_str,tmp_mac_str,if_name);

			if(strcmp(if_name, "br0")!=0 )
				continue;

			lan_port = check_lan(tmp_mac_str);	// lan port check : LAN(0 1 2 3 ), wlan(-1)
			if (lan_port < 0 || lan_port >3)
				continue;

			if (getPortStats(lan_port, str_traffic))
			{
				sscanf(str_traffic, "%llu %llu %llu %llu", &tx_p, &rx_p, &tx_bytes, &rx_bytes);
			}

			fprintf(fp, "%s %llu %llu %llu %llu\n",
					tmp_mac_str, rx_p, tx_p, rx_bytes, tx_bytes);
		}
		//fclose(fp2);

	/*wlan client ip connection info*/
		fseek(fp2, 0l, SEEK_SET);

		while(fgets(line_buffer, sizeof(line_buffer), fp2))
		{
			line_buffer[strlen(line_buffer)-1]='\0';

			sscanf(line_buffer,"%s %*s %*s %s %*s %s",ip_str,tmp_mac_str,if_name);

			if(strcmp(if_name, "br0")!=0 )
				continue;

			lan_port = check_lan(tmp_mac_str);	// lan port check : LAN(0 1 2 3 ) wan 4
			if (lan_port >=0 && lan_port < 4)
				continue;

			ret = get_mac_wlan_traffic(tmp_mac_str, ip_traffic_info);

			if (ret) {
				fprintf(fp, "%s", ip_traffic_info);
			}
		}
		fclose(fp2);

		fclose(fp);
	}

	send_redirect_perm(wp, "/skb_ip_connection.htm?init=1");
}

#ifdef CONFIG_RTK_MESH
void formMeshStatus(request *wp, char *path, char *query)
{
	char *submitUrl;

	submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page

	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);
}
#endif // CONFIG_RTK_MESH

/////////////////////////////////////////////////////////////////////////////
int ntpHandler(request *wp, char *tmpBuf, int fromWizard)
{
	int enabled = 0, ntpServerIdx;
	struct in_addr ipAddr;
	char *tmpStr;
	char value[32] = {0,};
//Brad add for daylight save
	int dlenabled = 0;
//Brad add end
	if (fromWizard) {
		tmpStr = req_get_cstream_var(wp, ("enabled"), "");
		if (!strcmp(tmpStr, "ON"))
			enabled = 1;
		else
			enabled = 0;

		if (apmib_set(MIB_NTP_ENABLED, (void *)&enabled) == 0) {
			strcpy(tmpBuf, ("Set enabled flag error!"));
			goto setErr_ntp;
		}
//Brad add for daylight save
		tmpStr = req_get_cstream_var(wp, ("dlenabled"), "");
		if (!strcmp(tmpStr, "ON"))
			dlenabled = 1;
		else
			dlenabled = 0;

		if (apmib_set(MIB_DAYLIGHT_SAVE, (void *)&dlenabled) == 0) {
			strcpy(tmpBuf, ("Set enabled flag error!"));
			goto setErr_ntp;
		}
//Brad add end
	} else
		enabled = 1;
	if (enabled) {
		tmpStr = req_get_cstream_var(wp, ("ntpServerId"), "");
		if (tmpStr[0]) {
			ntpServerIdx = tmpStr[0] - '0';
			if (apmib_set(MIB_NTP_SERVER_ID, (void *)&ntpServerIdx) == 0) {
				strcpy(tmpBuf, ("Set Time Zone error!"));
				goto setErr_ntp;
			}
		}
		tmpStr = req_get_cstream_var(wp, ("timeZone"), "");
		if (tmpStr[0]) {
			if (apmib_set(MIB_NTP_TIMEZONE, (void *)tmpStr) == 0) {
				strcpy(tmpBuf, ("Set Time Zone error!"));
				goto setErr_ntp;
			}
		}

		tmpStr = req_get_cstream_var(wp, ("ntpServerIp1"), "");
		if (tmpStr[0]) {
			snprintf(value, sizeof(value), "%s", tmpStr);
			apmib_nvram_set("x_ntp_server_ip1", value);
		}
		tmpStr = req_get_cstream_var(wp, ("ntpServerIp2"), "");
		if (tmpStr[0]) {
			snprintf(value, sizeof(value), "%s", tmpStr);
			apmib_nvram_set("x_ntp_server_ip2", value);
		}
		tmpStr = req_get_cstream_var(wp, ("ntpServerIp3"), "");
		if (tmpStr[0]) {
			snprintf(value, sizeof(value), "%s", tmpStr);
			apmib_nvram_set("x_ntp_server_ip3", value);
		}
	}
	return 0;
 setErr_ntp:
	return -1;
}

void formNtp(request *wp, char *path, char *query)
{
	char *submitUrl, *strVal, *tmpStr;
	char tmpBuf[100];
	int enabled = 0;
//Brad add for daylight save
	int dlenabled = 0;
//Brad add end
#ifndef NO_ACTION
//      int pid;
#endif
	int time_value = 0;
	int cur_year = 0;

	apmib_set_hist_clear();
	submitUrl = req_get_cstream_var(wp, "submit-url", "");	// hidden page
	strVal = req_get_cstream_var(wp, ("save"), "");

	tmpStr = req_get_cstream_var(wp, ("timeZone"), "");
	if (tmpStr[0]) {
		if (apmib_set(MIB_NTP_TIMEZONE, (void *)tmpStr) == 0) {
			strcpy(tmpBuf, ("Set Time Zone error!"));
			goto setErr_end;
		}
	}
//Brad add for daylight save
	tmpStr = req_get_cstream_var(wp, ("dlenabled"), "");
	if (!strcmp(tmpStr, "ON"))
		dlenabled = 1;
	else
		dlenabled = 0;
	if (apmib_set(MIB_DAYLIGHT_SAVE, (void *)&dlenabled) == 0) {
		strcpy(tmpBuf, ("Set dl enabled flag error!"));
		goto setErr_end;
	}
//Brad add end
	set_timeZone();
	if (strVal[0]) {
		struct tm tm_time;
		time_t tm;

		tmpStr = req_get_cstream_var(wp, ("enabled"), "");
		if (!strcmp(tmpStr, "ON"))
			enabled = 1;
		else
			enabled = 0;

#ifdef __DAVO__
		if (enabled) {
			memcpy(&tm_time, localtime(&tm), sizeof(tm_time));
			tm_time.tm_sec = 0;
			tm_time.tm_min = 0;
			tm_time.tm_hour = 0;
			tm_time.tm_isdst = -1;	/* Be sure to recheck dst. */
			strVal = req_get_cstream_var(wp, ("year"), "");
			cur_year = atoi(strVal);
			tm_time.tm_year = atoi(strVal) - 1900;
			strVal = req_get_cstream_var(wp, ("month"), "");
			tm_time.tm_mon = atoi(strVal) - 1;
			strVal = req_get_cstream_var(wp, ("day"), "");
			tm_time.tm_mday = atoi(strVal);
			strVal = req_get_cstream_var(wp, ("hour"), "");
			tm_time.tm_hour = atoi(strVal);
			strVal = req_get_cstream_var(wp, ("minute"), "");
			tm_time.tm_min = atoi(strVal);
			strVal = req_get_cstream_var(wp, ("second"), "");
			tm_time.tm_sec = atoi(strVal);
			tm = mktime(&tm_time);
			if (tm < 0) {
				sprintf(tmpBuf, "set Time Error\n");
				goto setErr_end;
			}
			if (stime(&tm) < 0) {
				sprintf(tmpBuf, "set Time Error\n");
				goto setErr_end;
			}

			apmib_set(MIB_SYSTIME_YEAR, (void *)&cur_year);
			time_value = tm_time.tm_mon;
			apmib_set(MIB_SYSTIME_MON, (void *)&time_value);
			time_value = tm_time.tm_mday;
			apmib_set(MIB_SYSTIME_DAY, (void *)&time_value);
			time_value = tm_time.tm_hour;
			apmib_set(MIB_SYSTIME_HOUR, (void *)&time_value);
			time_value = tm_time.tm_min;
			apmib_set(MIB_SYSTIME_MIN, (void *)&time_value);
			time_value = tm_time.tm_sec;
			apmib_set(MIB_SYSTIME_SEC, (void *)&time_value);
		}
#endif

		if (apmib_set(MIB_NTP_ENABLED, (void *)&enabled) == 0) {
			strcpy(tmpBuf, ("Set enabled flag error!"));
			goto setErr_end;
		}

	}
	if (enabled == 0)
		goto set_ntp_end;

	if (ntpHandler(wp, tmpBuf, 0) < 0)
		goto setErr_end;

 set_ntp_end:
	web_config_trace(5, 8);		/* management/time */
	apmib_update_web(CURRENT_SETTING);
//Brad modify for system re-init method
#if 0
	pid = find_pid_by_name("ntp.sh");
	if (pid)
		kill(pid, SIGTERM);

	pid = fork();
	if (pid)
		waitpid(pid, NULL, 0);
	else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _NTP_SCRIPT_PROG);
		execl(tmpBuf, _NTP_SCRIPT_PROG, NULL);
		exit(1);
	}
#endif
#ifndef NO_ACTION
	run_init_script("all");
#endif
#ifdef __DAVO__
	need_reboot = 1;
#endif
	OK_MSG("/skb_ntp.htm");
	return;

 setErr_end:
	ERR_MSG(tmpBuf);
}

void formPocketWizard(request *wp, char *path, char *query)
{
	char *tmpStr, *strVal;
	char tmpBuf[100];
	char varName[20];
	int i=0;
	int mode=-1;
	int val;
	int wlBandMode;
	int band2G5GSelect;
	int dns_changed=0;
    char ssidbuf[33];
#if defined(CONFIG_RTL_ULINKER)
	int ulinker_auto_changed;
#endif

//displayPostDate(wp->post_data);

/*
	strVal = req_get_cstream_var(wp, "band0", "");
	val = strtol( strVal, (char **)NULL, 10);
	val = (val + 1);
	apmib_set( MIB_WLAN_BAND, (void *)&val);
*/

#if defined(CONFIG_RTL_ULINKER)
	tmpStr = req_get_cstream_var(wp, "otg_auto_val", "");
	if(tmpStr[0] != 0)
	{
		apmib_get(MIB_ULINKER_AUTO, (void *)&ulinker_auto_changed);
		val = atoi(tmpStr);
		apmib_set(MIB_ULINKER_AUTO, (void *)&val);

		if (ulinker_auto_changed != val)
			ulinker_auto_changed = 1;
		else
			ulinker_auto_changed = 0;
	}
#endif

#ifdef HOME_GATEWAY
	if(tcpipWanHandler(wp, tmpBuf, &dns_changed) < 0){
		goto setErr_end;
	}
#endif

#if defined(CONFIG_RTL_92D_SUPPORT)
	tmpStr = req_get_cstream_var(wp, "wlBandMode", "");
	if(tmpStr[0] != 0)
	{
		wlBandMode = atoi(tmpStr);
		apmib_set(MIB_WLAN_BAND2G5G_SELECT, (void *)&wlBandMode);
	}

	apmib_get(MIB_WLAN_BAND2G5G_SELECT, (void *)&wlBandMode);
	if(wlBandMode == BANDMODEBOTH)
	{
		unsigned char wlanIfStr[10];

		for(i=0 ; i<NUM_WLAN_INTERFACE ; i++)
		{
			unsigned char wlanif[10];
			memset(wlanif,0x00,sizeof(wlanif));
			sprintf(wlanif, "wlan%d",i);
			if(SetWlan_idx(wlanif))
			{
				int intVal;
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
		if(whichWlanIfIs(PHYBAND_5G) != 0)
		{
			swapWlanMibSetting(0,1);
		}


	}
	else if(wlBandMode == BANDMODESINGLE)
	{
		unsigned int wlanif;

		for(i=0 ; i<NUM_WLAN_INTERFACE ; i++)
		{
			unsigned char wlanif[10];
			memset(wlanif,0x00,sizeof(wlanif));
			sprintf(wlanif, "wlan%d",i);
			if(SetWlan_idx(wlanif))
			{
				int intVal;
				intVal = SMACSPHY;
				apmib_set(MIB_WLAN_MAC_PHY_MODE, (void *)&intVal);
				intVal = 1;
				apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
			}
		}

		tmpStr = req_get_cstream_var(wp, "Band2G5GSupport", ""); //wlan0 PHYBAND_TYPE
		if(tmpStr[0] != 0)
		{
			band2G5GSelect = atoi(tmpStr);
		}

		wlanif = whichWlanIfIs(band2G5GSelect);

		/* 92d rule, 5g must up in wlan0 */
		/* phybandcheck */
		if(wlanif != 0)
		{
			swapWlanMibSetting(0,1);
		}

		wlan_idx = 0 ;

		val = 0;
		apmib_set( MIB_WLAN_WLAN_DISABLED, (void *)&val); // enable wlan0 and disable wlan1


	}
#endif //#if defined(CONFIG_RTL_92D_SUPPORT)

	wlan_idx = 0 ;
	tmpStr = req_get_cstream_var(wp, "pocket_ssid", "");
            //strSSID is BSSID, below transfer it to SSID. This fix the issue of AP ssid contains "


	if(tmpStr[0] != 0){
		if( bssid_to_ssid(tmpStr,ssidbuf) < 0)
			apmib_set(MIB_WLAN_SSID, (void *)tmpStr);
		else
			apmib_set(MIB_WLAN_SSID, (void *)ssidbuf);
	}

	for(i = 0 ; i<NUM_WLAN_INTERFACE ; i++)
	{
		wlan_idx = i;
		vwlan_idx = 0;

		if(i == 1)
		{
			if(wlBandMode != BANDMODEBOTH) // single band, no need process wlan1
				continue;

			tmpStr = req_get_cstream_var(wp, "pocket_ssid1", "");
			if(tmpStr[0] != 0){
				if( bssid_to_ssid(tmpStr,ssidbuf) < 0)
					apmib_set(MIB_WLAN_SSID, (void *)tmpStr);
				else
					apmib_set(MIB_WLAN_SSID, (void *)ssidbuf);
			}
		}
		sprintf(varName, "mode%d", i);
		tmpStr = req_get_cstream_var(wp, varName, "");
		if(tmpStr[0])
		{
			val = atoi(tmpStr);
			apmib_set( MIB_WLAN_MODE, (void *)&val);
		}



		sprintf(varName, "method%d", i);
		tmpStr = req_get_cstream_var(wp, varName, "");
		if(tmpStr[0])
		{
			val = atoi(tmpStr);
			if(val == ENCRYPT_DISABLED)
			{
				ENCRYPT_T encrypt = ENCRYPT_DISABLED;
				apmib_set( MIB_WLAN_ENCRYPT, (void *)&encrypt);
			}
			else if(val == ENCRYPT_WEP)
			{
				if(wepHandler(wp, tmpBuf, i) < 0)
				{
					goto setErr_end;
				}
			}
			else if(val > ENCRYPT_WEP && val <= WSC_AUTH_WPA2PSKMIXED)
			{
				if(wpaHandler(wp, tmpBuf, i) < 0)
				{
					goto setErr_end;
				}
			}
		}

#if defined(WLAN_PROFILE)
		if(addWlProfileHandler(wp, tmpBuf, i) < 0){
			//submitUrl = req_get_cstream_var(wp, ("submit-url-wlan2"), "");   // hidden page
			//goto setErr_end;
		}

#endif //#if defined(WLAN_PROFILE)


	}


#if defined(CONFIG_RTL_ULINKER) //repeater mode: clone wlan setting to wlan-vxd and modify wlan ssid
		int wlan_mode;
		int rptEnabled;
		int wlanvxd_mode;


		if(wlan_idx == 0)
			apmib_get(MIB_REPEATER_ENABLED1, (void *)&rptEnabled);
		else
			apmib_get(MIB_REPEATER_ENABLED2, (void *)&rptEnabled);



		apmib_get(MIB_WLAN_MODE, (void *)&wlan_mode);

		if(wlan_mode != CLIENT_MODE && wlan_mode != WDS_MODE && rptEnabled == 1)
		{
			int isUpnpEnabled=0;
			int ori_vwlan_idx = vwlan_idx;
			char ssidBuf[64];


			vwlan_idx = NUM_VWLAN_INTERFACE;


			/* get original setting in vxd interface */
			apmib_get(MIB_WLAN_WSC_UPNP_ENABLED, (void *)&isUpnpEnabled);
			apmib_get(MIB_WLAN_MODE, (void *)&wlanvxd_mode);


			ulinker_wlan_mib_copy(&pMib->wlan[wlan_idx][NUM_VWLAN_INTERFACE], &pMib->wlan[wlan_idx][0]);

			/* restore original setting in vxd interface and repeater ssid*/
			apmib_set(MIB_WLAN_WSC_UPNP_ENABLED, (void *)&isUpnpEnabled);
			apmib_set(MIB_WLAN_MODE, (void *)&wlanvxd_mode);

			vwlan_idx = ori_vwlan_idx;

			/* add "-ext" at last of wlan ssid */
			apmib_get( MIB_WLAN_SSID,  (void *)ssidBuf);

			if(wlan_idx == 0)
				apmib_set(MIB_REPEATER_SSID1, (void *)&ssidBuf);
			else
				apmib_set(MIB_REPEATER_SSID2, (void *)&ssidBuf);


			if(strlen(ssidBuf)<sizeof(ssidBuf)+4)
			{
				strcat(ssidBuf,"-ext");
				apmib_set( MIB_WLAN_SSID,  (void *)ssidBuf);
				apmib_set( MIB_WLAN_WSC_SSID, (void *)ssidBuf);
			}
		}
#endif


	apmib_update_web(CURRENT_SETTING);

#if defined(CONFIG_RTL_ULINKER)
	if (ulinker_auto_changed == 1) {
		char *submitUrl;
		needReboot = 1;
		submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page
		sprintf(lastUrl,"%s",submitUrl);
		send_redirect_perm(wp, "/skb_reload.htm");
		return ;
	}
#endif


#ifdef REBOOT_CHECK
	run_init_script_flag = 1;
#endif
#ifndef NO_ACTION
	run_init_script("all");
#endif
	tmpStr = req_get_cstream_var(wp, ("method0"), "");
	REBOOT_WAIT("/skb_wizard.htm");

	return ;
setErr_end:

	OK_MSG1(tmpBuf,"/skb_wizard.htm");
	return ;
}


#if defined(MIB_TLV)
extern int mib_search_by_id(const mib_table_entry_T *mib_tbl, unsigned short mib_id, unsigned char *pmib_num, const mib_table_entry_T **ppmib, unsigned int *offset);
extern mib_table_entry_T mib_root_table[];
#else
extern int update_linkchain(int fmt, void *Entry_old, void *Entry_new, int type_size);
#endif
void formWizard(request *wp, char *path, char *query)
{
	char *tmpStr;
	char tmpBuf[100];
	char varName[20];
	int i;
	int showed_wlan_num;
	int wlBandMode;
#ifdef HOME_GATEWAY
	int dns_changed=0;
#endif
	int mode=-1;
	char *submitUrl;
	char buffer[200];
	struct in_addr inLanaddr_orig, inLanaddr_new;
	struct in_addr inLanmask_orig, inLanmask_new;
	int	entryNum_resvdip;
	DHCPRSVDIP_T entry_resvdip, checkentry_resvdip;
	int link_type;
	struct in_addr private_host, tmp_private_host, update;
	struct in_addr dhcpRangeStart, dhcpRangeEnd;
#ifdef MIB_TLV
	char pmib_num[10]={0};
	mib_table_entry_T *pmib_tl = NULL;
	unsigned int offset;
#endif

//displayPostDate(wp->post_data);


	apmib_get( MIB_IP_ADDR,  (void *)buffer); //save the orig lan subnet
	memcpy((void *)&inLanaddr_orig, buffer, 4);

	apmib_get( MIB_SUBNET_MASK,  (void *)buffer); //save the orig lan mask
	memcpy((void *)&inLanmask_orig, buffer, 4);
#ifdef HOME_GATEWAY
	if(opModeHandler(wp, tmpBuf) < 0)
		goto setErr_end;
#endif

	if(ntpHandler(wp, tmpBuf, 1) < 0)
		goto setErr_end;

	if(tcpipLanHandler(wp, tmpBuf) < 0){
		submitUrl = req_get_cstream_var(wp, ("submit-url-lan"), "");   // hidden page
		goto setErr_end;
	}

#ifdef HOME_GATEWAY
	if(tcpipWanHandler(wp, tmpBuf, &dns_changed) < 0){
		submitUrl = req_get_cstream_var(wp, ("submit-url-wan"), "");   // hidden page
		goto setErr_end;
	}
#endif

#if defined(CONFIG_RTL_92D_SUPPORT)

	tmpStr = req_get_cstream_var(wp, "wlBandMode", "");
	if(tmpStr[0] != 0)
	{
		wlBandMode = atoi(tmpStr);
		apmib_set(MIB_WLAN_BAND2G5G_SELECT, (void *)&wlBandMode);
	}

	for(i=0 ; i<NUM_WLAN_INTERFACE ; i++)
	{
		unsigned char wlanif[10];
		memset(wlanif,0x00,sizeof(wlanif));
		sprintf(wlanif, "wlan%d",i);
		if(SetWlan_idx(wlanif))
		{
			int intVal;

			intVal = 1;
			apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
		}
	}
#endif

	for(i=0 ; i < wlan_num ;i++){
		wlan_idx = i ;
		sprintf(WLAN_IF, "wlan%d", wlan_idx);
		if(wlanHandler(wp, tmpBuf,&mode, i) < 0){
		submitUrl = req_get_cstream_var(wp, ("submit-url-wlan1"), "");   // hidden page
		goto setErr_end;
	}

		sprintf(varName, "method%d", i);
		tmpStr = req_get_cstream_var(wp, varName, "");
	if(tmpStr[0] && tmpStr[0] == '1'){
			if(wepHandler(wp, tmpBuf, i) < 0){
			submitUrl = req_get_cstream_var(wp, ("submit-url-wlan2"), "");   // hidden page
			goto setErr_end;
		}
	}
		if(wpaHandler(wp, tmpBuf, i) < 0){
		submitUrl = req_get_cstream_var(wp, ("submit-url-wlan2"), "");   // hidden page
		goto setErr_end;
	}



#if defined(WLAN_PROFILE)
		if(addWlProfileHandler(wp, tmpBuf, i) < 0){
			//submitUrl = req_get_cstream_var(wp, ("submit-url-wlan2"), "");   // hidden page
			//goto setErr_end;
		}

#endif //#if defined(WLAN_PROFILE)


	}

#if defined(CONFIG_RTL_92D_SUPPORT)
	apmib_get(MIB_WLAN_BAND2G5G_SELECT, (void *)&wlBandMode);
	if(BANDMODEBOTH == wlBandMode)
	{
		unsigned char wlanIfStr[10];

		for(i=0 ; i<NUM_WLAN_INTERFACE ; i++)
		{
			unsigned char wlanif[10];
			memset(wlanif,0x00,sizeof(wlanif));
			sprintf(wlanif, "wlan%d",i);
			if(SetWlan_idx(wlanif))
			{
				int intVal;
#if defined(CONFIG_RTL_92D_SUPPORT) && defined(CONFIG_RTL_92D_DMDP) && !defined(CONFIG_RTL_DUAL_PCIESLOT_BIWLAN_D)
				intVal = DMACDPHY;
#else
				intVal = SMACSPHY;
#endif
				apmib_set(MIB_WLAN_MAC_PHY_MODE, (void *)&intVal);
			}
		}

		/* 92d rule, 5g must up in wlan0 */
		/* phybandcheck */
		if(whichWlanIfIs(PHYBAND_5G) != 0)
		{
			swapWlanMibSetting(0,1);
		}
	}
	else
	{
		int band2G5GSelect;
		int intVal;

		for(i=0 ; i<NUM_WLAN_INTERFACE ; i++)
		{
			unsigned char wlanif[10];
			memset(wlanif,0x00,sizeof(wlanif));
			sprintf(wlanif, "wlan%d",i);
			if(SetWlan_idx(wlanif))
			{
				intVal = SMACSPHY;
				apmib_set(MIB_WLAN_MAC_PHY_MODE, (void *)&intVal);
			}
		}

		tmpStr = req_get_cstream_var(wp, "Band2G5GSupport", "");

		if(tmpStr[0] != 0)
		{
			band2G5GSelect = atoi(tmpStr);
		}

		/* 92d rule, 5g must up in wlan0 */
		/* phybandcheck */
		if(whichWlanIfIs(band2G5GSelect) != 0)
		{
			swapWlanMibSetting(0,1);
		}
		apmib_save_wlanIdx();
		wlan_idx = 1;
		intVal = 1;
		apmib_set( MIB_WLAN_WLAN_DISABLED, (void *)&intVal); // disable wlan1
		apmib_recov_wlanIdx();
	}
#endif //#if defined(CONFIG_RTL_92D_SUPPORT)

	apmib_update_web(CURRENT_SETTING);
	apmib_get( MIB_IP_ADDR,  (void *)buffer); //check the new lan subnet
	memcpy((void *)&inLanaddr_new, buffer, 4);

	apmib_get( MIB_SUBNET_MASK,  (void *)buffer); //check the new lan mask
	memcpy((void *)&inLanmask_new, buffer, 4);

	if((inLanaddr_orig.s_addr & inLanmask_orig.s_addr) != (inLanaddr_new.s_addr & inLanmask_new.s_addr)){
/* 2015-04-02 00:40 young */
#ifndef CONFIG_NVRAM_APMIB
		//check static dhcp ip
		apmib_get(MIB_DHCPRSVDIP_TBL_NUM, (void *)&entryNum_resvdip);
		link_type = 8; //DHCPRSVDIP_ARRY_T
		for (i=1; i<=entryNum_resvdip; i++) {
			memset(&checkentry_resvdip, '\0', sizeof(checkentry_resvdip));
			*((char *)&entry_resvdip) = (char)i;
			apmib_get(MIB_DHCPRSVDIP_TBL, (void *)&entry_resvdip);
			memcpy(&checkentry_resvdip, &entry_resvdip, sizeof(checkentry_resvdip));
			memcpy((void *)&private_host, &(entry_resvdip.ipAddr), 4);
			if((inLanaddr_new.s_addr & inLanmask_new.s_addr) != (private_host.s_addr & inLanmask_new.s_addr)){
				update.s_addr = inLanaddr_new.s_addr & inLanmask_new.s_addr;
				tmp_private_host.s_addr  = ~(inLanmask_new.s_addr) & private_host.s_addr;
				update.s_addr = update.s_addr | tmp_private_host.s_addr;
				memcpy((void *)&(checkentry_resvdip.ipAddr), &(update), 4);
#if defined(MIB_TLV)
				offset=0;//must initial first for mib_search_by_id
				mib_search_by_id(mib_root_table, MIB_DHCPRSVDIP_TBL, (unsigned char *)pmib_num, &pmib_tl, &offset);
				update_tblentry(pMib,offset,entryNum_resvdip,pmib_tl,&entry_resvdip, &checkentry_resvdip);
#else
				update_linkchain(link_type, &entry_resvdip, &checkentry_resvdip , sizeof(checkentry_resvdip));
#endif

			}
		}
#endif
		apmib_get( MIB_DHCP_CLIENT_START,  (void *)buffer); //save the orig dhcp start
		memcpy((void *)&dhcpRangeStart, buffer, 4);
		apmib_get( MIB_DHCP_CLIENT_END,  (void *)buffer); //save the orig dhcp end
		memcpy((void *)&dhcpRangeEnd, buffer, 4);

		if((dhcpRangeStart.s_addr & inLanmask_new.s_addr) != (inLanaddr_new.s_addr & inLanmask_new.s_addr)){
			update.s_addr = inLanaddr_new.s_addr & inLanmask_new.s_addr;
			tmp_private_host.s_addr  = ~(inLanmask_new.s_addr) & dhcpRangeStart.s_addr;
			update.s_addr = update.s_addr | tmp_private_host.s_addr;
			memcpy((void *)&(dhcpRangeStart), &(update), 4);
			apmib_set(MIB_DHCP_CLIENT_START, (void *)&dhcpRangeStart);
		}
		if((dhcpRangeEnd.s_addr & inLanmask_new.s_addr) != (inLanaddr_new.s_addr & inLanmask_new.s_addr)){
			update.s_addr = inLanaddr_new.s_addr & inLanmask_new.s_addr;
			tmp_private_host.s_addr  = ~(inLanmask_new.s_addr) & dhcpRangeEnd.s_addr;
			update.s_addr = update.s_addr | tmp_private_host.s_addr;
			memcpy((void *)&(dhcpRangeEnd), &(update), 4);
			apmib_set(MIB_DHCP_CLIENT_END, (void *)&dhcpRangeEnd);
		}
		apmib_update_web(CURRENT_SETTING);
	}
#ifdef REBOOT_CHECK
	run_init_script_flag = 1;
#endif
#ifndef NO_ACTION
	run_init_script("all");
#endif
	submitUrl = req_get_cstream_var(wp, ("next_url"), "");
	REBOOT_WAIT("/skb_wizard.htm");

	return ;
setErr_end:

	OK_MSG1(tmpBuf,"/skb_wizard.htm");
	return ;

}

///////////////////////////////////////////////////////////////////////////////////////////////
int logout = 0;
void formLogout(request * wp, char *path, char *query)
{
	char *logout_str, *return_url;
	logout_str = req_get_cstream_var(wp, ("logout"), "");
	if (logout_str[0]) {
		logout = 1;
		if (!free_from_login_list(wp)) {
			//syslog(LOG_ERR, "logout error from %s\n",wp->remote_ip_addr);
			goto setErr_Signal;
		}
	}
	if (logout == 1) {
		return_url = req_get_cstream_var(wp, ("return-url"), "");
		send_redirect_perm(wp, "/skb_login.htm");
		LOG(LOG_INFO, "웹 %s 사용자 로그 아웃", wp->remote_ip_addr);
		return;
	} else {
		goto setErr_Signal;
	}

 setErr_Signal:
	ERR_MSG("오류:로그아웃을 실패하였습니다. 아마 로그아웃 되어있을 수도 있습니다.!");
	return;
}

#ifndef __DAVO__
#define _PATH_SYSCMD_LOG "/tmp/syscmd.log"
void formSysCmd(request *wp, char *path, char *query)
{
	char  *submitUrl, *sysCmd;
#ifndef NO_ACTION
	char tmpBuf[100];
#endif

	submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page
	sysCmd = req_get_cstream_var(wp, "sysCmd", "");   // hidden page

#ifndef NO_ACTION
	if(sysCmd[0]){
		snprintf(tmpBuf, 100, "%s 2>&1 > %s",sysCmd,  _PATH_SYSCMD_LOG);
		system(tmpBuf);
	}
#endif
		send_redirect_perm(wp, submitUrl);
	return;
}

int sysCmdLog(request *wp, int argc, char **argv)
{
        FILE *fp;
	char  buf[150];
	int nBytesSent=0;

        fp = fopen(_PATH_SYSCMD_LOG, "r");
        if ( fp == NULL )
                goto err1;
        while(fgets(buf,150,fp)){
		nBytesSent += req_format_write(wp, ("%s"), buf);
        }
	fclose(fp);
	unlink(_PATH_SYSCMD_LOG);
err1:
	return nBytesSent;
}
#endif

#if defined(CONFIG_RTL_ULINKER)

void formUlkOpMode(request *wp, char *path, char *query)
{
	char *submitUrl;
	char *tmpStr;
	int ulinker_auto, opmode, wlanMode, rpt_enabled;
	char tmpBuf[100];

//displayPostDate(wp->post_data);

	submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page


	tmpStr = req_get_cstream_var(wp, ("ulinker_auto"), "");
	if(tmpStr[0])
	{
		ulinker_auto = tmpStr[0] - '0' ;
		apmib_set( MIB_ULINKER_AUTO, (void *)&ulinker_auto);

		if(ulinker_auto == 0)
		{
			int selVal;
			tmpStr = req_get_cstream_var(wp, ("ulinker_manual_Sel"), "");
			if(tmpStr[0])
			{
				selVal = tmpStr[0] - '0';

				switch(selVal)
				{
					case 0:
ulinker_wlan_mib_copy(&pMib->wlan[0][0], &pMib->wlan[0][ULINKER_AP_MIB]);
						opmode = BRIDGE_MODE;
						wlanMode = AP_MODE;
						rpt_enabled = 0;
						break;
					case 1:
ulinker_wlan_mib_copy(&pMib->wlan[0][0], &pMib->wlan[0][ULINKER_CL_MIB]);
						opmode = BRIDGE_MODE;
						wlanMode = CLIENT_MODE;
						rpt_enabled = 0;
						break;
					case 2:
ulinker_wlan_mib_copy(&pMib->wlan[0][0], &pMib->wlan[0][ULINKER_AP_MIB]);
						opmode = GATEWAY_MODE;
						wlanMode = AP_MODE;
						rpt_enabled = 0;
						break;
					case 3:
ulinker_wlan_mib_copy(&pMib->wlan[0][0], &pMib->wlan[0][ULINKER_RPT_MIB]);
						opmode = BRIDGE_MODE;
						wlanMode = AP_MODE;
						rpt_enabled = 1;
						break;
					case 4:
ulinker_wlan_mib_copy(&pMib->wlan[0][0], &pMib->wlan[0][ULINKER_RPT_MIB]);
						opmode = WISP_MODE;
						wlanMode = AP_MODE;
						rpt_enabled = 1;
						break;
				}
				apmib_set( MIB_OP_MODE, (void *)&opmode);
				apmib_set( MIB_WLAN_MODE, (void *)&wlanMode);
				pMib->wlan[wlan_idx][NUM_VWLAN_INTERFACE].wlanMode = CLIENT_MODE;

				if(wlanMode == CLIENT_MODE) //set cipher suit to AES and encryption to wpa2 only if wpa2 mixed mode is set
				{

					ENCRYPT_T encrypt;
					int intVal;
					apmib_get( MIB_WLAN_ENCRYPT, (void *)&encrypt);
					if(encrypt == ENCRYPT_WPA2_MIXED)
					{
						intVal =   WPA_CIPHER_AES ;
						encrypt = ENCRYPT_WPA2;

						apmib_set(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&intVal);
						apmib_set(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&intVal);
						apmib_set(MIB_WLAN_ENCRYPT, (void *)&encrypt);
					}
				}

				if(wlan_idx == 0)
				{
					apmib_set( MIB_REPEATER_ENABLED1, (void *)&rpt_enabled);
				}
				else
				{
					apmib_set( MIB_REPEATER_ENABLED2, (void *)&rpt_enabled);
				}
				pMib->wlan[wlan_idx][NUM_VWLAN_INTERFACE].wlanDisabled = (rpt_enabled?0:1);

			}
		}
	}

	apmib_update_web(CURRENT_SETTING);

#if defined(CONFIG_RTL_ULINKER)
	if (ulinker_auto == 0) {
		char *submitUrl;
		needReboot = 1;
		submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page
		sprintf(lastUrl,"%s",submitUrl);
		send_redirect_perm(wp, "/skb_reload.htm");
		return ;
	}
#endif

#ifdef REBOOT_CHECK
	run_init_script_flag = 1;
#endif

#ifdef REBOOT_CHECK
	REBOOT_WAIT(submitUrl);
#else //#ifdef REBOOT_CHECK	.
	OK_MSG(submitUrl);
#endif //#ifdef REBOOT_CHECK


#ifndef NO_ACTION
	run_init_script("all");
#endif
return;

setErr:
	ERR_MSG(tmpBuf);
}
#endif//#if defined(CONFIG_RTL_ULINKER)

#ifdef HOME_GATEWAY
int  opModeHandler(request *wp, char *tmpBuf)
{
	char *tmpStr;
	int opmode, wanId;
	char repeaterSSID[40];
	tmpStr = req_get_cstream_var(wp, ("opMode"), "");
	if(tmpStr[0]){
		opmode = tmpStr[0] - '0' ;
		if ( apmib_set(MIB_OP_MODE, (void *)&opmode) == 0) {
			strcpy(tmpBuf, ("Set Opmode error!"));
			goto setErr_opmode;
		}
		if (opmode == 0) {
			nvram_set("DHCP", "2");
		} else if (opmode == 1) {
			nvram_set("DHCP", "0");
		}
		nvram_commit();
	}
#if defined(CONFIG_SMART_REPEATER)
	if(opmode==2)
	{//wisp mode
#endif
		tmpStr = req_get_cstream_var(wp, ("wispWanId"), "");
		if(tmpStr[0]){
			wanId = tmpStr[0] - '0' ;
			if ( apmib_set(MIB_WISP_WAN_ID, (void *)&wanId) == 0) {
				strcpy(tmpBuf, ("Set WISP WAN Id error!"));
				goto setErr_opmode;
			}
#if defined(CONFIG_SMART_REPEATER)
			int rpt_enabled = 1;
			char wlanifStr[20];
			int wlanMode;

			apmib_save_wlanIdx();
			if(wanId == 0)
			{
				apmib_set( MIB_REPEATER_ENABLED1, (void *)&rpt_enabled);
				apmib_get( MIB_REPEATER_SSID1, (void *)repeaterSSID);
				rpt_enabled=0;
				apmib_set(MIB_REPEATER_ENABLED2,(void *)&rpt_enabled);
			}
			else
			{
				apmib_set( MIB_REPEATER_ENABLED2, (void *)&rpt_enabled);
				apmib_get( MIB_REPEATER_SSID2, (void *)repeaterSSID);
				rpt_enabled=0;
				apmib_set(MIB_REPEATER_ENABLED1,(void *)&rpt_enabled);
			}

			sprintf(wlanifStr, "wlan%d", wanId);
			SetWlan_idx(wlanifStr);
			wlanMode = AP_MODE;
			apmib_set( MIB_WLAN_MODE, (void *)&wlanMode);

			sprintf(wlanifStr, "wlan%d-vxd", wanId);
			SetWlan_idx(wlanifStr);
			wlanMode = CLIENT_MODE;
			apmib_set( MIB_WLAN_MODE, (void *)&wlanMode);
			apmib_set(MIB_WLAN_SSID,(void *)repeaterSSID);
			rpt_enabled = 0;
			apmib_set( MIB_WLAN_WLAN_DISABLED, (void *)&rpt_enabled);
			apmib_recov_wlanIdx();

#endif
		}
#if defined(CONFIG_SMART_REPEATER)
		else{//only one wlan:92c
			int rpt_enabled = 1;
			char wlanifStr[20]={0};
			int wlanMode;

			wanId=0;
			apmib_save_wlanIdx();
			apmib_set( MIB_REPEATER_ENABLED1, (void *)&rpt_enabled);
			apmib_get( MIB_REPEATER_SSID1, (void *)repeaterSSID);
			sprintf(wlanifStr, "wlan%d", wanId);
			SetWlan_idx(wlanifStr);
			wlanMode = AP_MODE;
			apmib_set( MIB_WLAN_MODE, (void *)&wlanMode);

			sprintf(wlanifStr, "wlan%d-vxd", wanId);
			SetWlan_idx(wlanifStr);
			wlanMode = CLIENT_MODE;
			apmib_set( MIB_WLAN_MODE, (void *)&wlanMode);
			apmib_set(MIB_WLAN_SSID,(void *)repeaterSSID);
			rpt_enabled = 0;
			apmib_set( MIB_WLAN_WLAN_DISABLED, (void *)&rpt_enabled);
			apmib_recov_wlanIdx();
		}
	}else //opmode is gw or bridge
	{

		int rpt_enabled=0;
		apmib_set(MIB_REPEATER_ENABLED1, (void *)&rpt_enabled);
		apmib_set(MIB_REPEATER_ENABLED2,(void *)&rpt_enabled);
	}
#endif
	return 0;

setErr_opmode:
	return -1;

}
void formOpMode(request *wp, char *path, char *query)
{
	char *submitUrl;
	char tmpBuf[100];

	submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page

	if(opModeHandler(wp, tmpBuf) < 0)
			goto setErr;

	apmib_update_web(CURRENT_SETTING);

#ifdef REBOOT_CHECK
	run_init_script_flag = 1;
#endif

#ifdef REBOOT_CHECK
	REBOOT_WAIT(submitUrl);
#else //#ifdef REBOOT_CHECK	.
	OK_MSG(submitUrl);
#endif //#ifdef REBOOT_CHECK


#ifndef NO_ACTION
	run_init_script("all");
#endif
return;

setErr:
	ERR_MSG(tmpBuf);
}
#endif

#ifdef REBOOT_CHECK
void formRebootCheck(request *wp, char *path, char *query)
{
	char *submitUrl;

	submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page
	REBOOT_WAIT(submitUrl);
	apmib_update_web(CURRENT_SETTING);
#ifdef REBOOT_CHECK
	run_init_script_flag = 1;
#endif
	if (sdmz_enable())
		need_reboot = 1;

	if (need_reboot == 1)
		dv_reboot_system = 1;
	else
		dv_script_reboot = 1;
#ifndef NO_ACTION
		//run_init_script("all");
#endif
	/*else
		dv_run_init_script = 1;*/
	needReboot = 0;
}

#if defined(WLAN_PROFILE)
void formSiteSurveyProfile(request *wp, char *path, char *query)
{
	char *submitUrl, *strTmp, *addProfileTmp;
	char tmpBuf[100];
	char varName[20];

//displayPostDate(wp->post_data);


	sprintf(varName, "wizardAddProfile%d", wlan_idx);
	addProfileTmp = req_get_cstream_var(wp, varName, "");

	if(addProfileTmp[0])
	{
		int rptEnabled, wlan_mode;
		int ori_vwlan_idx=vwlan_idx;
		int profile_enabled_id, profile_num_id, profile_tbl_id;
		int profileEnabledVal=1;
		char iwprivCmd[600]={0};
		int entryNum;
		WLAN_PROFILE_T entry;
		int profileIdx;
		char ifname[10]={0}; //max is wlan0-vxd

		memset(iwprivCmd, 0x00, sizeof(iwprivCmd));
		apmib_get(MIB_WLAN_MODE, (void *)&wlan_mode);

		if(wlan_idx == 0)
			apmib_get(MIB_REPEATER_ENABLED1, (void *)&rptEnabled);
		else
			apmib_get(MIB_REPEATER_ENABLED2, (void *)&rptEnabled);


		if( (wlan_mode == AP_MODE || wlan_mode == AP_WDS_MODE) && (rptEnabled == 1))
		{
			sprintf(ifname,"wlan%d-vxd",wlan_idx);
			vwlan_idx = NUM_VWLAN_INTERFACE;
		}
		else
		{
			sprintf(ifname,"wlan%d",wlan_idx);
			vwlan_idx = 0;
		}

		if(wlan_idx == 0)
		{
			profile_num_id = MIB_PROFILE_NUM1;
			profile_tbl_id = MIB_PROFILE_TBL1;
			profile_enabled_id = MIB_PROFILE_ENABLED1;
		}
		else
		{
			profile_num_id = MIB_PROFILE_NUM2;
			profile_tbl_id = MIB_PROFILE_TBL2;
			profile_enabled_id = MIB_PROFILE_ENABLED2;
		}

		apmib_set(profile_enabled_id, (void *)&profileEnabledVal);



		if(addWlProfileHandler(wp, tmpBuf, wlan_idx) < 0){
	printf("\r\n Add wireless profile fail__[%s-%u]\r\n",__FILE__,__LINE__);
			//strcpy(tmpBuf, ("Add wireless profile fail!"));
			//goto ss_err;
		}

		sprintf(iwprivCmd,"iwpriv %s set_mib ap_profile_enable=%d",ifname, profileEnabledVal);
		system(iwprivCmd);

		sprintf(iwprivCmd,"iwpriv %s set_mib ap_profile_num=0",ifname);
		system(iwprivCmd);

		apmib_get(profile_num_id, (void *)&entryNum);

		for(profileIdx=1; profileIdx<=entryNum;profileIdx++)
		{
			memset(iwprivCmd, 0x00, sizeof(iwprivCmd));
			memset(&entry, 0x00, sizeof(WLAN_PROFILE_T));
			*((char *)&entry) = (char)profileIdx;
			apmib_get(profile_tbl_id, (void *)&entry);








			//iwpriv wlan0 set_mib ap_profile_add="open-ssid",0,0
			if(entry.encryption == ENCRYPT_DISABLED)
			{
				sprintf(iwprivCmd,"iwpriv %s set_mib ap_profile_add=\"%s\",%d,%d",ifname,entry.ssid,0,0);
			}
			else if(entry.encryption == WEP64 || entry.encryption == WEP128)
			{
				char tmp1[400];
				if (entry.encryption == WEP64)
					sprintf(tmp1,"%d,%d,%02x%02x%02x%02x%02x,%02x%02x%02x%02x%02x,%02x%02x%02x%02x%02x,%02x%02x%02x%02x%02x",
						entry.auth,
						entry.wep_default_key,
						entry.wepKey1[0],entry.wepKey1[1],entry.wepKey1[2],entry.wepKey1[3],entry.wepKey1[4],
						entry.wepKey2[0],entry.wepKey2[1],entry.wepKey2[2],entry.wepKey2[3],entry.wepKey2[4],
						entry.wepKey3[0],entry.wepKey3[1],entry.wepKey3[2],entry.wepKey3[3],entry.wepKey3[4],
						entry.wepKey4[0],entry.wepKey4[1],entry.wepKey4[2],entry.wepKey4[3],entry.wepKey4[4]);
				else
					sprintf(tmp1,"%d,%d,%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x,%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x,%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x,%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
						entry.auth,
						entry.wep_default_key,
						entry.wepKey1[0],entry.wepKey1[1],entry.wepKey1[2],entry.wepKey1[3],entry.wepKey1[4],entry.wepKey1[5],entry.wepKey1[6],entry.wepKey1[7],entry.wepKey1[8],
						entry.wepKey1[9],entry.wepKey1[10],entry.wepKey1[11],entry.wepKey1[12],
						entry.wepKey2[0],entry.wepKey2[1],entry.wepKey2[2],entry.wepKey2[3],entry.wepKey2[4],entry.wepKey2[5],entry.wepKey2[6],entry.wepKey2[7],entry.wepKey2[8],
						entry.wepKey2[9],entry.wepKey2[10],entry.wepKey2[11],entry.wepKey2[12],
						entry.wepKey3[0],entry.wepKey3[1],entry.wepKey3[2],entry.wepKey3[3],entry.wepKey3[4],entry.wepKey3[5],entry.wepKey3[6],entry.wepKey3[7],entry.wepKey3[8],
						entry.wepKey3[9],entry.wepKey3[10],entry.wepKey3[11],entry.wepKey3[12],
						entry.wepKey4[0],entry.wepKey4[1],entry.wepKey4[2],entry.wepKey4[3],entry.wepKey4[4],entry.wepKey4[5],entry.wepKey4[6],entry.wepKey4[7],entry.wepKey4[8],
						entry.wepKey4[9],entry.wepKey4[10],entry.wepKey4[11],entry.wepKey4[12]);

				sprintf(iwprivCmd,"iwpriv %s set_mib ap_profile_add=\"%s\",%d,%s,",ifname,entry.ssid,entry.encryption, tmp1);
			}
			else if(entry.encryption == 2 || entry.encryption == 4 || entry.encryption == 6) //wpa or wpa2
			{
				char tmp1[400];
				sprintf(tmp1, "%d,%s", entry.wpa_cipher, entry.wpaPSK);
				sprintf(iwprivCmd,"iwpriv %s set_mib ap_profile_add=\"%s\",%d,0,%s",ifname,entry.ssid,entry.encryption,tmp1 );
			}


			system(iwprivCmd);
		}

		vwlan_idx = ori_vwlan_idx;
		apmib_update_web(CURRENT_SETTING);


	}

	submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page

	strTmp = req_get_cstream_var(wp, "restartNow", "");
	if(strTmp[0])
	{

		//apmib_update_web(CURRENT_SETTING);
#ifdef REBOOT_CHECK
		run_init_script_flag = 1;
#endif
#ifndef NO_ACTION
		run_init_script("all");
#endif
		REBOOT_WAIT(submitUrl);
		needReboot = 0;
	}
	else
	{
		send_redirect_perm(wp,submitUrl);
	}

}
#endif //#if defined(WLAN_PROFILE)



#endif //#ifdef REBOOT_CHECK

int WriteBlock(request *req, char *buf, int nChars)
{
	int bob=nChars;
	int i,j;
#ifndef SUPPORT_ASP
	if ((bob+req->buffer_end) > BUFFER_SIZE) {
		bob = BUFFER_SIZE - req->buffer_end;
	}
#else
	while ((bob+req->buffer_end+10) > req->max_buffer_size) {  //Brad modify
		int ret;
		ret = allocNewBuffer(req);
		if (ret==FAILED) {
			bob = BUFFER_SIZE - req->buffer_end;
			break;
		}
	}
#endif
	if(bob > 0)
	{
		memcpy(req->buffer + req->buffer_end,  buf, bob);
		req->buffer_end+=bob;
	}
	return bob;
}

static void saveLogFile(request * wp, FILE *fp)
{
	unsigned char *ptr;
	unsigned int fileSize,filelen;
	unsigned int fileSector;
	unsigned int maxFileSector;

	fseek(fp, 0, SEEK_END);
	filelen = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	fileSize=filelen;

	while (fileSize>0) {
		char buf[0x100];
		maxFileSector = 0x50;
		int nRead;

		fileSector = (fileSize > maxFileSector) ? maxFileSector : fileSize;
		nRead = fread((void *)buf, 1, fileSector, fp);

		WriteBlock(wp, buf, nRead);

		fileSize -= fileSector;
		ptr += fileSector;
	}
}

void formSysLog(request *wp, char *path, char *query)
{
	char *tmpStr, *args[2] = {NULL,};
	char tmpBuf[100] = {0,};
	char logServer[128] = {0,};
	int enabled, rt_enabled;
	int rlog_port;

	apmib_set_hist_clear();
	tmpStr = req_get_cstream_var(wp, ("clear"), "");
	if (tmpStr[0]) {
		snprintf(tmpBuf, 100, "echo \" \" > %s", "/var/log/messages");
		system(tmpBuf);
		//### add by sen_liu 2011.4.21 sync the system log update (enlarge from 1 pcs to 8 pcs) to  SDKv2.5 from kernel 2.4
#ifdef RINGLOG
		system("rm /var/log/messages.* >/dev/null 2>&1");
#endif
		//### end
		send_redirect_perm(wp, "/skb_syslog.htm");
		return;
	}
/*
 *	NOTE: If variable enabled (MIB_SCRLOG_ENABLED) bitmask modify(bitmap),
 *	 	Please modify driver rtl8190 reference variable (dot1180211sInfo.log_enabled in linux-2.4.18/drivers/net/rtl8190/8190n_cfg.h)
 */
	apmib_get(MIB_SCRLOG_ENABLED, (void *)&enabled);
	tmpStr = req_get_cstream_var(wp, ("logEnabled"), "");
	if (!strcmp(tmpStr, "ON")) {
		enabled = 1;

		tmpStr = req_get_cstream_var(wp, ("syslogEnabled"), "");
		if (!strcmp(tmpStr, "ON"))
			enabled = 3;

		tmpStr = req_get_cstream_var(wp, ("wlanlogEnabled"), "");
		if (!strcmp(tmpStr, "ON"))
			enabled |= 4;
		else
			enabled &= ~4;

#ifdef HOME_GATEWAY
#ifdef DOS_SUPPORT
		tmpStr = req_get_cstream_var(wp, ("doslogEnabled"), "");
		if (!strcmp(tmpStr, "ON"))
			enabled |= 8;
		else
			enabled &= ~8;
#endif
#endif

#ifdef CONFIG_RTK_MESH
		tmpStr = req_get_cstream_var(wp, ("meshlogEnabled"), "");
		if (!strcmp(tmpStr, "ON"))
			enabled |= 16;
		else
			enabled &= ~16;
#endif
	} else
		enabled = 0;

	if (apmib_set(MIB_SCRLOG_ENABLED, (void *)&enabled) == 0) {
		strcpy(tmpBuf, ("로그설정 오류!"));
		goto setErr;
	}

	if (enabled & 1) {
		tmpStr = req_get_cstream_var(wp, ("rtLogEnabled"), "");

		if (!strcmp(tmpStr, "ON"))
			rt_enabled = 1;
		else
			rt_enabled = 0;

		if (apmib_set(MIB_REMOTELOG_ENABLED, (void *)&rt_enabled) == 0) {
			strcpy(tmpBuf, ("원격 로그 설정 오류!"));
			goto setErr;
		}

		if (rt_enabled) {
			tmpStr = req_get_cstream_var(wp, ("rlog_addr"), "");
			if (tmpStr[0]) {
				if (ystrargs(tmpStr, args, _countof(args), ":", 0) == 2) {
					rlog_port = strtol(args[1], NULL, 10);
					if (rlog_port <= 0 || rlog_port > 65535) {
						strcpy(tmpBuf, ("포트번호를 확인해주세요!"));
						goto setErr;
					}
					snprintf(logServer, sizeof(logServer), "%s:%d", args[0], rlog_port);
				} else {
					strcpy(tmpBuf, ("포트번호를 확인해주세요!"));
					goto setErr;
				}
				nvram_set("x_remote_logserver", logServer);
			}
		}
	}

	tmpStr = req_get_cstream_var(wp, ("save"), "");
	if (tmpStr[0]) {
		FILE *fp, *fp2;

		fp = fopen("/var/tmp/messages", "r");
		if (fp == NULL) {
			strcpy(tmpBuf, "삭제할 시스템 로그가 없습니다!");
			goto setErr;
		}

		wp->buffer_end = 0;
		req_format_write(wp, "HTTP/1.0 200 OK\n");
		req_format_write(wp, "Content-Type: application/octet-stream;\n");
		req_format_write(wp, "Content-Disposition: attachment;filename=\"messages.txt\" \n");
		req_format_write(wp, "Pragma: no-cache\n");
		req_format_write(wp, "Cache-Control: no-cache\n");
		req_format_write(wp, "\n");

		saveLogFile(wp, fp);
		fclose(fp);

		return;
	}

	web_config_trace(5, 9);		/* management/log */
	nvram_commit();
#ifndef NO_ACTION
	run_init_script("all");
#endif
	need_reboot = 1;
	OK_MSG("/skb_syslog.htm");
	return;

setErr:
	ERR_MSG(tmpBuf);
}

#ifdef __DAVO__
int sysLogList(request *wp, int argc, char **argv)
{
	FILE *f;
	int nbytes, i = 0;
	char *tstamp, *s, buf[256];
	const char *filenames[] = { "/var/tmp/messages", NULL };

	/*apmib_get(MIB_SCRLOG_ENABLED, (void *)&i);
	if (!(i & 1))
		return 0;*/
	for (i = nbytes = 0; filenames[i]; i++) {
		f = fopen(filenames[i], "r");
		if (f == NULL)
			continue;
		while (fgets(buf, sizeof(buf), f)) {
			tstamp = buf;
			s = &buf[15];
			*s++ = '\0';
			while (*s && isspace(*s))
				++s;
			while (*s && !isspace(*s))
				++s;
			while (*s && isspace(*s))
				++s;
			translate_control_code(s);
			nbytes += req_format_write(wp, "<tr><td class='mn24'><center>%s</center></td><td class='mn24'>%s</td></tr>", tstamp, s);
		}
		fclose(f);
	}
	return nbytes;
}
#else	/* __DAVO__ */
static int process_msg(char *msg, int is_wlan_only)
{
	char *p1, *p2;
	p1 = strstr(msg, "rlx-linux"); // host name
	if (p1 == NULL)
		return 0;

#ifdef CONFIG_RTK_MESH
	if (is_wlan_only == 4) {
		p2 = strstr(p1, "msh");
		if (p2 && p2[4]==':')
			memcpy(p1, p2, strlen(p2)+1);
		else
			return 0;

	}else
#endif

	if (is_wlan_only == 3){
		p2 = strstr(p1, "DoS");
		if (p2 && p2[3]==':'){
			memcpy(p1, p2, strlen(p2)+1);
		}else{
			p2 = strstr(p1, "wlan");
			if ((p2 && p2[5]==':') || (p2 && p2[9]==':'))	{// vxd interface
				memcpy(p1, p2, strlen(p2)+1);
			}else
				return 0;
			}
	}else if (is_wlan_only == 2){
		p2 = strstr(p1, "DoS");
		if (p2 && p2[3]==':')
			memcpy(p1, p2, strlen(p2)+1);
		else
			return 0;

	}else{
		p2 = strstr(p1, "wlan");
		if ((p2 && p2[5]==':') ||
			 (p2 && p2[9]==':'))	// vxd interface
			memcpy(p1, p2, strlen(p2)+1);
		else {
			if (is_wlan_only)
				return 0;

			p2 = strstr(p1, "kernel: ");
			if (p2 == NULL)
				return 0;
			memcpy(p1, p2+7, strlen(p2)-7+1);
		}
	}
	return 1;
}


int sysLogList(request *wp, int argc, char **argv)
{
	FILE *fp;
	char  buf[200];
	int nBytesSent=0;
	int enabled;

//### add by sen_liu 2011.4.21 sync the system log update (enlarge from 1 pcs to 8 pcs) to  SDKv2.5 from kernel 2.4
#ifdef RINGLOG
	char logname[32];
	int lognum = LOG_SPLIT;
#endif

//### end
	apmib_get(MIB_SCRLOG_ENABLED, (void *)&enabled);
	if ( !(enabled & 1))
		goto err1;
//### add by sen_liu 2011.4.21 sync the system log update (enlarge from 1 pcs to 8 pcs) to  SDKv2.5 from kernel 2.4
#ifdef RINGLOG
		fp = fopen("/var/log/log_split", "r");
		if (fp == NULL)
			goto err1;
		fgets(buf,200,fp);
		lognum = atoi(buf);
		fclose(fp);

	while (lognum >= 0)
	{
		if (lognum > 0)
			snprintf(logname, 32, "/var/log/messages.%d", lognum-1);
		else if (lognum == 0)
			snprintf(logname, 32, "/var/log/messages");
		else
			goto err1;

		fp = fopen(logname, "r");
		if (fp == NULL)
			goto next_log;
#else
//### end
	fp = fopen("/var/log/messages", "r");
	if (fp == NULL)
		goto err1;
#endif

	while(fgets(buf,200,fp)){
		int ret=0;
		if (enabled&2) // system all
			ret = process_msg(buf, 0);
		else {
			if((enabled&0xC) == 0xC){ //both wlan and DoS
				ret = process_msg(buf, 3);
			}else if (enabled&4)	// wlan only
				ret = process_msg(buf, 1);
			else if (enabled&8)	//DoS only
				ret = process_msg(buf, 2);

#ifdef CONFIG_RTK_MESH
			 if(enabled&16 && ret==0)	// mesh only
				ret = process_msg(buf, 4);
#endif

		}
		if (ret==0)
			continue;

		if (strlen(buf)<=16) continue;
			buf[15] = 0;
			remove_html_lt_gt(buf2, &buf[16], sizeof(buf2));

		nBytesSent += req_format_write(wp, ("%s"), buf);
	}
	fclose(fp);

//### add by sen_liu 2011.4.21 sync the system log update (enlarge from 1 pcs to 8 pcs) to	SDKv2.5 from kernel 2.4
#ifdef RINGLOG
next_log:
	lognum--;
}
#endif
//### end
err1:
	return nBytesSent;
}
#endif	/* !__DAVO__ */

#ifdef  CONFIG_APP_SMTP_CLIENT
void formSmtpClient(request *wp, char *path, char *query)
{
	extern char* p_email_infor;
	char *send_form, *password,*send_to,*theme,*body, *attachment;
	char *timing,*year,*month,*day,*hour,*minute,*syslog_check,*usbstoragemsg,*now_time;
	char *tmpStr;
	int  enable,i,status;
	char tmpEmpty[] = "OFF";
	char tmpBuf[500];


	tmpStr= req_get_cstream_var(wp, ("smtpClientEnabled"), "");
	if(!strcmp(tmpStr, "ON"))
		enable = 1;
	else
		enable = 0;
	/*if ( apmib_set(MIB_SMTP_CLIENT_ENABLED, (void *)&rt_enabled) == 0) {
			strcpy(tmpBuf, ("Set smtp client enable error!"));
			ERR_MSG(tmpBuf);
			return;
	}*/

	if(enable){
		syslog_check= req_get_cstream_var(wp, ("syslogmsg"), "");
		if(!strcmp(syslog_check, ""))
			syslog_check = tmpEmpty;
		send_form= req_get_cstream_var(wp, ("sendFrom"), "");
		if(!strcmp(send_form, ""))
			goto ipput_error;
		password= req_get_cstream_var(wp, ("password"), "");
		if(!strcmp(password, ""))
			goto ipput_error;
		send_to= req_get_cstream_var(wp, ("sendTo"), "");
		if(!strcmp(send_to, ""))
			goto ipput_error;
		theme= req_get_cstream_var(wp, ("theme"), "");
		if(!strcmp(theme, ""))
			theme = tmpEmpty;
		body = req_get_cstream_var(wp, ("msg"), "");
		if(!strcmp(body, ""))
			body = tmpEmpty;
		attachment = req_get_cstream_var(wp, ("attachment"), "");
		if(!strcmp(attachment, ""))
			attachment = tmpEmpty;
		usbstoragemsg = req_get_cstream_var(wp, ("usbstoragemsg"), "");
		if(!strcmp(usbstoragemsg, ""))
			usbstoragemsg = tmpEmpty;
		timing = req_get_cstream_var(wp, ("timing"), "");
		if(!strcmp(timing, "")){
			timing = tmpEmpty;
			year = tmpEmpty;
			month = tmpEmpty;
			day = tmpEmpty;
			hour = tmpEmpty;
			minute = tmpEmpty;
			now_time = tmpEmpty;
		}
		else{
			year = req_get_cstream_var(wp, ("year"), "");
			month = req_get_cstream_var(wp, ("month"), "");
			day = req_get_cstream_var(wp, ("day"), "");
			hour = req_get_cstream_var(wp, ("hour"), "");
			minute = req_get_cstream_var(wp, ("minute"), "");
			now_time  = req_get_cstream_var(wp, ("now_time"), "");
		}

		sprintf(tmpBuf,"%s \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" ","smtpclient",send_form,password,send_to,syslog_check,timing,year,month,day,hour,minute,now_time,theme,body,attachment,usbstoragemsg);
		status = system( tmpBuf);
	}
	strcpy(tmpBuf, ("Send Email End!"));
	//OK_MSG(tmpBuf);
	ERR_MSG(tmpBuf);
	return;

	ipput_error:
		strcpy(tmpBuf, ("Send Email Error!"));
		//OK_MSG(tmpBuf);
		ERR_MSG(tmpBuf);
}
#endif


#ifdef HOME_GATEWAY
#ifdef DOS_SUPPORT
void formDosCfg(request * wp, char *path, char *query)
{
	char *submitUrl, *tmpStr;
	char tmpBuf[100];
	int floodCount = 0, blockTimer = 0;
	long prev, enabled = 0;

	if (wp->superUser != 1)
		return;

	apmib_set_hist_clear();
	submitUrl = req_get_cstream_var(wp, "submit-url", "");	// hidden page

	apmib_get(MIB_DOS_ENABLED, (void *)&enabled);
	prev = enabled;
	tmpStr = req_get_cstream_var(wp, ("dosEnabled"), "");
	if (!strcmp(tmpStr, "ON")) {
		enabled |= 1;

		tmpStr = req_get_cstream_var(wp, ("sysfloodSYN"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 2;
			tmpStr = req_get_cstream_var(wp, ("sysfloodSYNcount"), "");
			string_to_dec(tmpStr, &floodCount);
			if (apmib_set(MIB_DOS_SYSSYN_FLOOD, (void *)&floodCount) == 0) {
				strcpy(tmpBuf, ("Set DoS SYSSYN_FLOOD error!"));
				goto setErr;
			}
		} else {
			enabled &= ~2;
		}
		tmpStr = req_get_cstream_var(wp, ("sysfloodFIN"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 4;
			tmpStr = req_get_cstream_var(wp, ("sysfloodFINcount"), "");
			string_to_dec(tmpStr, &floodCount);
			if (apmib_set(MIB_DOS_SYSFIN_FLOOD, (void *)&floodCount) == 0) {
				strcpy(tmpBuf, ("Set DoS SYSFIN_FLOOD error!"));
				goto setErr;
			}
		} else {
			enabled &= ~4;
		}
		tmpStr = req_get_cstream_var(wp, ("sysfloodUDP"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 8;
			tmpStr = req_get_cstream_var(wp, ("sysfloodUDPcount"), "");
			string_to_dec(tmpStr, &floodCount);
			if (apmib_set(MIB_DOS_SYSUDP_FLOOD, (void *)&floodCount) == 0) {
				strcpy(tmpBuf, ("Set DoS SYSUDP_FLOOD error!"));
				goto setErr;
			}
		} else {
			enabled &= ~8;
		}
		tmpStr = req_get_cstream_var(wp, ("sysfloodICMP"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 0x10;
			tmpStr = req_get_cstream_var(wp, ("sysfloodICMPcount"), "");
			string_to_dec(tmpStr, &floodCount);
			if (apmib_set(MIB_DOS_SYSICMP_FLOOD, (void *)&floodCount) == 0) {
				strcpy(tmpBuf, ("Set DoS SYSICMP_FLOOD error!"));
				goto setErr;
			}
		} else {
			enabled &= ~0x10;
		}
		tmpStr = req_get_cstream_var(wp, ("ipfloodSYN"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 0x20;
			tmpStr = req_get_cstream_var(wp, ("ipfloodSYNcount"), "");
			string_to_dec(tmpStr, &floodCount);
			if (apmib_set(MIB_DOS_PIPSYN_FLOOD, (void *)&floodCount) == 0) {
				strcpy(tmpBuf, ("Set DoS PIPSYN_FLOOD error!"));
				goto setErr;
			}
		} else {
			enabled &= ~0x20;
		}
		tmpStr = req_get_cstream_var(wp, ("ipfloodFIN"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 0x40;
			tmpStr = req_get_cstream_var(wp, ("ipfloodFINcount"), "");
			string_to_dec(tmpStr, &floodCount);
			if (apmib_set(MIB_DOS_PIPFIN_FLOOD, (void *)&floodCount) == 0) {
				strcpy(tmpBuf, ("Set DoS PIPFIN_FLOOD error!"));
				goto setErr;
			}
		} else {
			enabled &= ~0x40;
		}
		tmpStr = req_get_cstream_var(wp, ("ipfloodUDP"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 0x80;
			tmpStr = req_get_cstream_var(wp, ("ipfloodUDPcount"), "");
			string_to_dec(tmpStr, &floodCount);
			if (apmib_set(MIB_DOS_PIPUDP_FLOOD, (void *)&floodCount) == 0) {
				strcpy(tmpBuf, ("Set DoS PIPUDP_FLOOD error!"));
				goto setErr;
			}
		} else {
			enabled &= ~0x80;
		}
		tmpStr = req_get_cstream_var(wp, ("ipfloodICMP"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 0x100;
			tmpStr = req_get_cstream_var(wp, ("ipfloodICMPcount"), "");
			string_to_dec(tmpStr, &floodCount);
			if (apmib_set(MIB_DOS_PIPICMP_FLOOD, (void *)&floodCount) == 0) {
				strcpy(tmpBuf, ("Set DoS PIPICMP_FLOOD error!"));
				goto setErr;
			}
		} else {
			enabled &= ~0x100;
		}
		tmpStr = req_get_cstream_var(wp, ("TCPUDPPortScan"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 0x200;

			tmpStr = req_get_cstream_var(wp, ("portscanSensi"), "");
			if (tmpStr[0] == '1') {
				enabled |= 0x800000;
			} else {
				enabled &= ~0x800000;
			}
		} else {
			enabled &= ~0x200;
		}
		tmpStr = req_get_cstream_var(wp, ("ICMPSmurfEnabled"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 0x400;
		} else {
			enabled &= ~0x400;
		}
		tmpStr = req_get_cstream_var(wp, ("IPLandEnabled"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 0x800;
		} else {
			enabled &= ~0x800;
		}
		tmpStr = req_get_cstream_var(wp, ("IPSpoofEnabled"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 0x1000;
		} else {
			enabled &= ~0x1000;
		}
		tmpStr = req_get_cstream_var(wp, ("IPTearDropEnabled"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 0x2000;
		} else {
			enabled &= ~0x2000;
		}
		tmpStr = req_get_cstream_var(wp, ("PingOfDeathEnabled"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 0x4000;
		} else {
			enabled &= ~0x4000;
		}
		tmpStr = req_get_cstream_var(wp, ("TCPScanEnabled"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 0x8000;
		} else {
			enabled &= ~0x8000;
		}
		tmpStr = req_get_cstream_var(wp, ("TCPSynWithDataEnabled"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 0x10000;
		} else {
			enabled &= ~0x10000;
		}
		tmpStr = req_get_cstream_var(wp, ("UDPBombEnabled"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 0x20000;
		} else {
			enabled &= ~0x20000;
		}
		tmpStr = req_get_cstream_var(wp, ("UDPEchoChargenEnabled"), "");
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 0x40000;
		} else {
			enabled &= ~0x40000;
		}
#if !defined(__DAVO__)
		tmpStr = req_get_cstream_var(wp, ("sourceIPblock"), (""));
		if (!strcmp(tmpStr, "ON")) {
			enabled |= 0x400000;
			tmpStr = req_get_cstream_var(wp, ("IPblockTime"), "");
			string_to_dec(tmpStr, &blockTimer);
			if (apmib_set(MIB_DOS_BLOCK_TIME, (void *)&blockTimer) == 0) {
				strcpy(tmpBuf, ("Set DoS IP Block Timer error!"));
				goto setErr;
			}
		} else {
			enabled &= ~0x400000;
		}

#endif	// !__DAVO__
#endif
	} else
		enabled = 0;

	if (apmib_set(MIB_DOS_ENABLED, (void *)&enabled) == 0) {
		strcpy(tmpBuf, ("Set DoS enable error!"));
		goto setErr;
	}
#if defined(__DAVO__)
	tmpStr = req_get_cstream_var(wp, ("IPblockTime"), (""));
	if (tmpStr && tmpStr[0] != 0) {
		string_to_dec(tmpStr, &blockTimer);
		if (apmib_set(MIB_DOS_BLOCK_TIME, (void *)&blockTimer) == 0) {
			strcpy(tmpBuf, ("Set DoS IP Block Timer error!"));
			goto setErr;
		}
	}

	tmpStr = req_get_cstream_var(wp, ("pingSecEnabled"), (""));
	if (!strcmp(tmpStr, "ON")) {
		apmib_nvram_set("x_pingSecEnabled", "1");
		tmpStr = req_get_cstream_var(wp, ("pingSecCount"), (""));
		string_to_dec(tmpStr, &floodCount);
		if (floodCount < 0)
			floodCount = 0;
		sprintf(tmpBuf, "%d", floodCount);
		apmib_nvram_set("x_icmp_reply_rate", tmpBuf);
	} else {
		apmib_nvram_set("x_pingSecEnabled", "0");
		apmib_nvram_set("x_icmp_reply_rate", "0");
	}

	tmpStr = req_get_cstream_var(wp, ("input_policy_accept"), (""));
	if (tmpStr && !strcmp(tmpStr, "ON")) {
		apmib_nvram_set("x_input_policy_accept", "1");
	} else {
		apmib_nvram_set("x_input_policy_accept", "0");
	}

	tmpStr = req_get_cstream_var(wp, ("snmp_input_rate"), (""));
	if (tmpStr && tmpStr[0])
		apmib_nvram_set("x_snmp_input_rate", tmpStr);
	else
		apmib_nvram_set("x_snmp_input_rate", "0");

	tmpStr = req_get_cstream_var(wp, ("ARPspoofEnabled"), (""));
	apmib_nvram_set("x_ARP_DEFENDER_ENABLE", !strcmp(tmpStr, ("ON")) ? "1" : "0");

	tmpStr = req_get_cstream_var(wp, ("TraceRtEnabled"), (""));
	apmib_nvram_set("x_noreply_tracert", !strcmp(tmpStr, ("ON")) ? "1" : "0");

	tmpStr = req_get_cstream_var(wp, ("NTPDefEnabled"), (""));
	apmib_nvram_set("x_NTPDefEnabled", !strcmp(tmpStr, ("ON")) ? "1" : "0");

	tmpStr = req_get_cstream_var(wp, ("DNSRelayEnabled"), (""));
	apmib_nvram_set("x_DNSRelayEnabled", !strcmp(tmpStr, ("ON")) ? "1" : "0");
#endif
	web_config_trace(3, 5, &prev);		/* firewall/ddos */
	apmib_update_web(CURRENT_SETTING);
	nvram_commit();
#ifdef __DAVO__
	need_reboot = 1;
	OK_MSG("/skb_dos.htm");
	return;
#endif
#ifndef NO_ACTION
	run_init_script("all");
#endif

	OK_MSG(submitUrl);
	return;

 setErr:
	ERR_MSG(tmpBuf);
}
#endif

//#ifdef LOGIN_URL
#ifdef USE_LOGINWEB_OF_SERVER
extern struct user_info * search_login_list(request * req);

static void delete_captcha_img(char *img)
{
	char cmd[256];

	snprintf(cmd, sizeof(cmd), "rm /tmp/img/%s.gif", img);

	yexecl(NULL, cmd);
}

static int is_exist_captcha_img(char *img)
{
	FILE *pp = NULL;
	int exist = 0;
	char cmd[256], buf[256] = {0,};

	snprintf(cmd, sizeof(cmd), "ls /tmp/img/ | grep %s", img);

	pp = popen(cmd, "r");
	if (pp) {
		if (fgets(buf, sizeof(buf), pp)) {
			exist = 1;
		}
		pclose(pp);
	}

	return exist;
}

static char *wan_mac_parsing(char *wan_mac)
{
	char buf[20];
	int len;

	if (wan_mac) {
		nvram_get_r_def("HW_NIC1_ADDR", buf, sizeof(buf), "");
		for (len = 0; len < strlen(buf); len++)
			buf[len] = (char)toupper(buf[len]);
		if (strspn(buf, "1234567890abcdefABCDEF") != 12) //wan_mac_length_checked
			return NULL;
		strcpy(wan_mac, buf);
	}
	return wan_mac;
}

void formLogin(request *wp, char *path, char *query)
{
	char *strUser, *strPassword, *userpass;
	char *tmp_captcha = NULL, *images = NULL;;
	char tmpbuf[200];
	char DecodePassword[65];
	char usrName[65], usrPasswd[65];
	char superName[65], superPasswd[65];
	struct user_info *pUser_info;
	int denied = 1;
	int login_super = 0, j, redirect_pwd = 0;
	int login_session_num = 0;
	char sha256_user[65];
	char sha256_pass[65];
	char hash_captcha[65];
	char buf[1024], captcha[500];
	char *cookie = NULL;
	struct in_addr peer;
	unsigned long lanip = 0, lanmask = 0, peer_ip = 0, dhcpEnd = 0, dhcpStart = 0, lan_netaddr = 0;
	char wanMac[32] = {0,}, decode_user[65] = {0,}, buffer[65] = {0,}, passwd[65] = {0,}, user_pw[65] = {0,};
	char initPage[32] = {0,};

	strUser = req_get_cstream_var(wp, ("username"), "");
	strPassword = req_get_cstream_var(wp, ("password"), "");
	tmp_captcha = req_get_cstream_var(wp, "captcha", "");
	images = req_get_cstream_var(wp, "images", "");

	memset(DecodePassword, 0, sizeof(DecodePassword));
	b64_decode(strPassword, DecodePassword, sizeof(DecodePassword));

	j = b64_decode(tmp_captcha, (unsigned char *)captcha, sizeof(captcha));
	captcha[j] = '\0';

	hash_sha256_captcha(captcha, hash_captcha);
	ydespaces(images);

	if (strcmp(hash_captcha, images) || (is_exist_captcha_img(images) == 0)) {
		denied = 13;
		goto login_err;
	}

	cal_sha256(strUser, sha256_user);
	cal_sha256(DecodePassword, sha256_pass);

	pUser_info = search_login_list(wp);
	if (pUser_info) {
		denied = 5;
		goto login_err;
	}

	if (!strUser[0]) {
		denied = 3;
		goto login_err;
	}

	if (strUser[0] && !strPassword[0]) {
		denied = 3;
		goto login_err;
	}

	nvram_get_r_def("x_USER_NAME", usrName, sizeof(usrName), "");
	if (!usrName[0]) {
		denied = 10;
		goto login_err;
	}

	if (strcmp(usrName, sha256_user) == 0) {
		nvram_get_r_def("x_USER_PASSWORD", usrPasswd, sizeof(usrPasswd), "");
		if (!usrPasswd[0]) {
			denied = 10;
			goto login_err;
		}

		if (strcmp(sha256_pass, usrPasswd)) {
			denied = 1;
			goto login_err;
		}
		denied = 0;
		goto pass_check;
	}

	nvram_get_r_def("x_SUPER_NAME", superName, sizeof(superName), "");
	if (!superName[0]) {
		denied = 10;
		goto login_err;
	}

	if (strcmp(sha256_user, superName) == 0) {
		nvram_get_r_def("x_SUPER_PASSWORD", superPasswd, sizeof(superPasswd), "");
		if (!superPasswd[0]) {
			denied = 10;
			goto login_err;
		}
		if (strcmp(sha256_pass, superPasswd)) {
			denied = 1;
			goto login_err;
		}
		denied = 0;
		login_super = 1;
		goto pass_check;
	} else {
		denied = 1;
		goto login_err;
	}

 pass_check:

	login_session_num = search_login_session_num();
	if (login_session_num >= MAX_LOGIN_SESSION_NUM) {
		//send_r_forbidden(req);
		denied = 12;
		goto login_err;
	}

#ifdef ONE_USER_LIMITED
	if (!strcmp(sha256_user, usrName) && usStatus.busy) {
		if (strcmp(usStatus.remote_ip_addr, wp->remote_ip_addr)) {
			denied = 4;
			goto login_err;
		}
	} else if (!strcmp(sha256_user, superName) && suStatus.busy) {
		if (strcmp(suStatus.remote_ip_addr, wp->remote_ip_addr)) {
			denied = 4;
			goto login_err;
		}
	}
#endif

	pUser_info = search_login_list(wp);
	if (!pUser_info) {
		free_from_login_list(wp);
		pUser_info = malloc(sizeof(struct user_info));
		pUser_info->last_time = time_counter;
//		pUser_info->login_status = STATUS_LOGIN;
		strncpy(pUser_info->remote_ip_addr, wp->remote_ip_addr,
			sizeof(pUser_info->remote_ip_addr));
		peer.s_addr = inet_addr(wp->remote_ip_addr);
		cookie = creat_cookie(sha256_user, sha256_pass, peer, buf, sizeof(buf));
		if (cookie[0])
			snprintf(pUser_info->uniq_cookie, sizeof(pUser_info->uniq_cookie), "%s", cookie);
		if (strcmp(sha256_user, usrName) == 0) {
			pUser_info->directory = strdup("skb_home.htm");
#ifdef ONE_USER_LIMITED
			pUser_info->paccount = &usStatus;
			pUser_info->paccount->busy = 1;
			strncpy(pUser_info->paccount->remote_ip_addr, wp->remote_ip_addr,
				sizeof(pUser_info->paccount->remote_ip_addr));
#endif
		} else {
			pUser_info->directory = strdup("/skb_home.htm");
#ifdef ONE_USER_LIMITED
			pUser_info->paccount = &suStatus;
			pUser_info->paccount->busy = 1;
			strncpy(pUser_info->paccount->remote_ip_addr, wp->remote_ip_addr,
				sizeof(pUser_info->paccount->remote_ip_addr));
#endif
		}
		//list it to user_login_list
		pUser_info->next = user_login_list;
		user_login_list = pUser_info;
	} else {
//		if (pUser_info->login_status != STATUS_FORBIDDEN) {
			pUser_info->last_time = time_counter;
//			pUser_info->login_status = STATUS_LOGIN;
//		}
	}

	if (login_super) {
		apmib_get(MIB_IP_ADDR, (void *)&lanip);
		apmib_get(MIB_SUBNET_MASK, (void *)&lanmask);

		if (inet_aton(wp->remote_ip_addr, (struct in_addr *)&peer_ip)) {
			// check local connect
			if ((lanip & lanmask) == (peer_ip & lanmask)) {
				lan_netaddr = lanip;
				lan_netaddr &= lanmask;
				dhcpStart = 0x1;
				dhcpStart |= lan_netaddr;
				dhcpEnd = 0xfffffffe;
				dhcpEnd &= ~lanmask;
				dhcpEnd |= lan_netaddr;
				if (lanip >= dhcpStart && lanip <= dhcpEnd) {
					if ((lanip - dhcpStart) > (dhcpStart - lanip)) {
						dhcpEnd = lanip - 0x1;
						dhcpEnd &= ~lanmask;
						dhcpEnd |= lan_netaddr;
					} else {
						dhcpStart = lanip + 0x1;
						dhcpStart &= ~lanmask;
						dhcpStart |= lan_netaddr;
					}
				}
				if (peer_ip != dhcpEnd) {
					denied = 14;
					free_from_login_list(wp);
					goto login_err;
				}
			}
		}
	} else { //user password check -> default password redirect password page
		if (wan_mac_parsing(wanMac)) {
			b64_decode("xcjRzdI=", decode_user, sizeof(decode_user));
			shift_str(decode_user, buffer, DECRYPT_ADD_VAL);
			sprintf(passwd, "%s_%s", &wanMac[6], buffer);
			cal_sha256(passwd, user_pw);
			if (strcmp(user_pw, sha256_pass) == 0) {
				redirect_pwd = 1;
			}
		}
	}

	syslog(LOG_INFO, "%s 사용자 웹 로그인", wp->remote_ip_addr);
	snprintf(initPage, sizeof(initPage), "%s", (redirect_pwd) ? "skb_redirect_password.htm" : "skb_home.htm");
	send_redirect_perm(wp, (initPage));
	delete_captcha_img(images);

	return;

 login_err:

	switch (denied) {
	case 1:
	case 2:
	case 5:
		FAIL_TO_LOGIN("오류: 사용자 계정 또는 비밀번호가 잘못되었습니다.!");
		break;
	case 3:
		FAIL_TO_LOGIN("오류: 사용자 계정 또는 비밀번호가 비어있습니다.!");
		break;
#ifdef ONE_USER_LIMITED
	case 4:
		FAIL_TO_LOGIN("오류: 다른 사용자가 이 계정으로 로그인 중입니다. 오직 한 사용자만이 동일시간에 로그인 할 수 있습니다.!");
		break;
#endif
	case 12:
		FAIL_TO_LOGIN("오류: 너무 많은 사용자가 로그인 중입니다. 잠시후 다시 로그인해주세요.!");
		break;
	case 13:
		FAIL_TO_LOGIN("오류: 복합 문자가 틀립니다.");
		break;
	case 14:
		FAIL_TO_LOGIN("오류: 로그인에 실패하였습니다.");
		break;
	default:
		FAIL_TO_LOGIN("오류: 웹 인증 오류! 웹 브라우저 창을 닫고 다시 로그인해주세요!");
		break;
	}
}
#endif // LOGIN_URL

#ifdef CONFIG_CPU_UTILIZATION
void formCpuUtilization(request *wp, char *path, char *query)
{
	char *submitUrl, *tmpStr;
	int enable, interval;
	char tmpbuf[200];

	submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page

	tmpStr = req_get_cstream_var(wp, ("enableCpuUtilization"), "");
	if(!strcmp(tmpStr, "ON"))
		enable = 1 ;
	else
		enable = 0 ;
	if ( apmib_set( MIB_ENABLE_CPU_UTILIZATION, (void *)&enable) == 0) {
		strcpy(tmpbuf, ("Set cpu utilization enabled flag error!"));
		goto setErr_end;
	}

	tmpStr = req_get_cstream_var(wp, ("cpuUtilizationInterval"), "");
	if(tmpStr[0])
	{
		interval = atoi(tmpStr);
		if ( apmib_set( MIB_CPU_UTILIZATION_INTERVAL, (void *)&interval) == 0) {
			strcpy(tmpbuf, ("Set cpu utilization interval error!"));
			goto setErr_end;
		}
	}

	apmib_update_web(CURRENT_SETTING);

	OK_MSG(submitUrl);
	return;

setErr_end:
	ERR_MSG(tmpbuf);
}

#endif // CONFIG_CPU_UTILIZATION

#if defined(POWER_CONSUMPTION_SUPPORT)
unsigned int pre_cpu_d4, pre_time_secs, max_cpu_delta=0;
unsigned int ethBytesCount_previous[5] = {0};

/* http://www.360doc.com/content/070213/11/17255_365683.html */
int getPowerConsumption(request *wp, int argc, char **argv)
{
	//char dev[80];
	//char *devPtr;
	FILE *stream;
	int i=1;
	//int j;
	//char logbuf[500];
	//unsigned int rxbytes=0,rxpackets=0,rxerrs=0,rxdrops=0,txbytes=0,txpackets=0,txerrs=0,txdrops=0,txcolles=0;
	//unsigned int txeth0packets=0;
	//unsigned int tmp1,tmp2,tmp3,tmp4;
	char askfor[20];

//	unsigned int totalPwrCon = 0;
	unsigned int totalPwrCon = (rand()%2 ? 10 :0);

	typedef enum { NO_LINK=0, NORMAL_LINK=1, EEE_LINK=2} ETHERNET_LINK_T;
	unsigned short isLink_eth0[5]={0};
	unsigned short ethLinkNum= 0, ethEeeLinkNum = 0;
	unsigned short perEthPwrCon = PWRCON_PER_ETHERNET;
	unsigned int perEthEeeMinus = PWRCON_PER_EEE_ETHERNET_LINK_MINUS; // mw*100
	unsigned int perEthEeePwrCon = PWRCON_PER_EEE_ETHERNET; // mw*100/Mbps
	unsigned int ethThroughPut[5] = {0};
	unsigned int ethEeeThroughPut_Total = 0;
	int ethPwrCon_Total = 0;

	typedef enum { CHIP_UNKNOWN=0, CHIP_RTL8188C=1, CHIP_RTL8192C=2} CHIP_VERSION_T;
	CHIP_VERSION_T chipVersion = CHIP_UNKNOWN;

	typedef enum { CPU_NORMAL=0, CPU_SUSPEND=1} CPU_MODE_T;
	CPU_MODE_T cpuMode = CPU_NORMAL;
	unsigned short cpuPwrCon[3][2] = { {0,0},{PWRCON_CPU_NORMAL_88C,PWRCON_CPU_SUSPEND_88C},{PWRCON_CPU_NORMAL_92C,PWRCON_CPU_SUSPEND_92C} }; // 3:chipVersion; 2:cpu mode

	typedef enum { WLAN_OFF=0, WLAN_NO_LINK=1, WLAN_LINK=2} WLAN_STATE_T;
	WLAN_STATE_T wlanState = WLAN_OFF;
	unsigned short wlanStatePwrCon[3][3] = { {0,0,0},{PWRCON_WLAN_OFF_88C,PWRCON_WLAN_NOLINK_88C,PWRCON_WLAN_LINK_88C},{PWRCON_WLAN_OFF_92C,PWRCON_WLAN_NOLINK_92C,PWRCON_WLAN_LINK_92C}}; //3:chipVersion; 3:wlanState
	int wlanOff = 0;

	typedef enum { WLAN_MCS8_15=0, WLAN_MCS0_7=1, WLAN_OFDM=2, WLAN_CCK=3} WLAN_TRAFFIC_STATE_T;
	WLAN_TRAFFIC_STATE_T wlanTrafficState = WLAN_MCS8_15;
	unsigned int wlanTrafficStatePwrCon[3][4] = { {0,0,0,0},{PWRCON_WLAN_TRAFFIC_MCS8_15_88C,PWRCON_WLAN_TRAFFIC_MCS0_7_88C,PWRCON_WLAN_TRAFFIC_OFDM_88C,PWRCON_WLAN_TRAFFIC_CCK_88C},{PWRCON_WLAN_TRAFFIC_MCS8_15_92C,PWRCON_WLAN_TRAFFIC_MCS0_7_92C,PWRCON_WLAN_TRAFFIC_OFDM_92C,PWRCON_WLAN_TRAFFIC_CCK_92C}}; //3:chipVersion; 4:wlanTrafficState
	unsigned int wlanTrafficStatePwrConZ[3][28] = {
		{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
		{1000,1099,1188,1454,2014,3254,4271,8039,1082,1176,1289,1681,2768,4482,6275,10458,719,919,1225,1697,2377,3735,5038,7557,938,1681,2894,5865},
		{1000,1099,1188,1454,2014,3254,4271,8039,1082,1176,1289,1681,2768,4482,6275,10458,1000,1278,1705,2360,3306,5195,7008,10511,938,1681,2894,5865}
	};//3:chipVersion; 28:DataRate MCS15~1
	unsigned int wlanTrafficZ = 0;

	unsigned int tx_average = 0;
	unsigned short tx_average_multiply2 = 0;
	unsigned int rx_average = 0;
	unsigned int wlanTrafficStatePwrCon_Total;

	unsigned int cpuUtilizationPwrCon[3] = { 0,PWRCON_CPU_UTILIZATION_88C,PWRCON_CPU_UTILIZATION_92C}; //3:chipVersion;
	unsigned short cpu_utilization=0;

	unsigned short debug_check = 0;

	time_t current_secs;
	unsigned int time_delta = 1;
#if 0
	for(i=0 ;i<3;i++)
		for(j=0; j<1; j++)
			fprintf(stderr,"\r\n cpuUtilizationPwrCon[%d][%d]=[%f]",i,j,cpuUtilizationPwrCon[i][j]);
#endif

	//get current system time in second.
	time(&current_secs);
	if(pre_time_secs == 0) //first time
	{
		pre_time_secs = (int)(current_secs);
		time_delta = 1;
	}
	else
	{
		time_delta = (int)(current_secs) - (int)(pre_time_secs);
		pre_time_secs = (int)(current_secs);
	}


	//get chipVersion
	stream = fopen ( "/var/pwrConDebug", "r" );
	if ( stream != NULL )
	{
		char *strtmp;
		char line[100];
		char strTmp[10];

		while (fgets(line, sizeof(line), stream))
		{
			strtmp = line;

			while(*strtmp == ' ')
			{
				strtmp++;
			}

			sscanf(strtmp,"%[01]",strTmp);

			debug_check=atoi(strTmp);

		}

		fclose ( stream );
	}


	if(debug_check)
		fprintf(stderr,"\r\n  === Pwr Con Debug ===");
	//get chipVersion
	chipVersion = getWLAN_ChipVersion();
#if 0
	stream = fopen ( "/proc/wlan0/mib_rf", "r" );
	if ( stream != NULL )
	{
		char *strtmp;
		char line[100];

		while (fgets(line, sizeof(line), stream))
		{

			strtmp = line;
			while(*strtmp == ' ')
			{
				strtmp++;
			}


			if(strstr(strtmp,"RTL8192SE") != 0)
			{
				chipVersion = CHIP_UNKNOWN;
			}
			else if(strstr(strtmp,"RTL8188C") != 0)
			{
				if(debug_check)
					fprintf(stderr,"\r\n [%s]",strtmp);
				chipVersion = CHIP_RTL8188C;
			}
			else if(strstr(strtmp,"RTL8192C") != 0)
			{
				if(debug_check)
					fprintf(stderr,"\r\n [%s]",strtmp);
				chipVersion = CHIP_RTL8192C;
			}
		}
		fclose ( stream );
	}
#endif

	if(debug_check)
	{
		fprintf(stderr,"\r\n chipVersion=[%u]",chipVersion);
		fprintf(stderr,"\r\n");
	}

	//get cpu mode
	stream = fopen ( "/proc/suspend_check", "r" );
	if ( stream != NULL )
	{
		char *strtmp;
		char line[100];

		while (fgets(line, sizeof(line), stream))
		{
			//enable=1, winsize=5(10), high=3200, low=2200, suspend=1
			strtmp = strstr(line,"suspend");
			if(strtmp != NULL)
			{

				//suspend=1
				if(debug_check)
					fprintf(stderr,"\r\n [%s]",strtmp);
				sscanf(strtmp,"%*[^=]=%u",&cpuMode);
			}

		}
		fclose ( stream );
	}
	if(debug_check)
	{
		fprintf(stderr,"\r\n cpuMode=[%u]",cpuMode);
		fprintf(stderr,"\r\n cpuPwrCon=[%u]",cpuPwrCon[chipVersion][cpuMode]);
		fprintf(stderr,"\r\n");
	}
	totalPwrCon+=cpuPwrCon[chipVersion][cpuMode];

	//get Eth0 port link and bytesCount
	for(i=0; i<5; i++)
	{
		unsigned int ethBytesCount[5] = {0};

		isLink_eth0[i]=getEth0PortLink(i);
		if(isLink_eth0[i])
		{
			isLink_eth0[i] = NORMAL_LINK;
			if(getEthernetEeeState(i))
				isLink_eth0[i] = EEE_LINK;
	}
		else
		{
			isLink_eth0[i] = NO_LINK;
		}

		ethBytesCount[i] = getEthernetBytesCount(i);

		if(time_delta <= 0)
			time_delta = 1;
		ethThroughPut[i] = (ethBytesCount[i] - ethBytesCount_previous[i])/time_delta;
		ethBytesCount_previous[i] = ethBytesCount[i];
	}

	for(i=0; i<5; i++)
	{
		if(isLink_eth0[i] == NORMAL_LINK)
		{
			ethLinkNum++;
		}
		else if(isLink_eth0[i] == EEE_LINK)
		{
			ethEeeLinkNum++;
			ethEeeThroughPut_Total += ethThroughPut[i];
		}
	}
	ethEeeThroughPut_Total *= 8; // transfer to bits.

	ethPwrCon_Total += ethLinkNum*perEthPwrCon;
	ethPwrCon_Total -= (ethEeeLinkNum*perEthEeeMinus)/100;
	ethPwrCon_Total += (((float)ethEeeThroughPut_Total*perEthEeePwrCon)/100)/1000000;


	if(debug_check)
	{
		fprintf(stderr,"\r\n Eth Link State:%u-%u-%u-%u-%u", isLink_eth0[0],isLink_eth0[1],isLink_eth0[2],isLink_eth0[3],isLink_eth0[4]);
		fprintf(stderr,"\r\n Eth ThroughPut:%u-%u-%u-%u-%u (bits/sec)", ethThroughPut[0]*8,ethThroughPut[1]*8,ethThroughPut[2]*8,ethThroughPut[3]*8,ethThroughPut[4]*8);
		fprintf(stderr,"\r\n ethEeeThroughPut_Total: %u (bits/sec)",ethEeeThroughPut_Total);
		fprintf(stderr,"\r\n perEthPwrCon Total: (%u*%u)-(%u*%u)/100+(%u*%u)/100/10^6 = %u",ethLinkNum,perEthPwrCon,ethEeeLinkNum,perEthEeeMinus,ethEeeThroughPut_Total,perEthEeePwrCon,ethPwrCon_Total);
		fprintf(stderr,"\r\n");
	}
	totalPwrCon+=ethPwrCon_Total;

	//get wlan state
	apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&wlanOff);
	if(wlanOff)
		wlanState = WLAN_OFF;
	else
	{
		wlanState = updateWlanifState("wlan0");
	}


	if(debug_check)
					{
		fprintf(stderr,"\r\n wlanState=[%u]",wlanState);
		fprintf(stderr,"\r\n wlanStatePwrCon = [%u]",wlanStatePwrCon[chipVersion][wlanState]);
		fprintf(stderr,"\r\n");
	}

	totalPwrCon+=wlanStatePwrCon[chipVersion][wlanState];

	// get wlan traffic power consumption
	if(wlanState == WLAN_LINK)
	{
			//get chipVersion
		stream = fopen ( "/proc/wlan0/stats", "r" );
		if ( stream != NULL )
		{
			char *strtmp;
			char line[100];
			while (fgets(line, sizeof(line), stream))
			{
				char *p;
				strtmp = line;


				while(*strtmp == ' ')
					strtmp++;


				if(strstr(strtmp,"tx_avarage") != 0)
				{
					char str1[10];

					if(debug_check)
						fprintf(stderr,"\r\n [%s]",strtmp);

					//tx_avarage:    1449
					sscanf(strtmp, "%*[^:]:%s",str1);

					p = str1;
					while(*p == ' ')
						p++;

					tx_average = atoi(p);
					tx_average*=8; // bytes->bits

					if(debug_check)
						fprintf(stderr,"\r\n tx_average=[%u]",tx_average);
				}
				else if(strstr(strtmp,"rx_avarage") != 0)
				{
					char str1[10];

					if(debug_check)
						fprintf(stderr,"\r\n [%s]",strtmp);

					//rx_avarage:    1449
					sscanf(strtmp, "%*[^:]:%s",str1);

					p = str1;
					while(*p == ' ')
						p++;

					rx_average = atoi(p);
					rx_average*=8; // bytes->bits

					if(debug_check)
						fprintf(stderr,"\r\n rx_average=[%u]",rx_average);
					}
				else if(strstr(strtmp,"cur_tx_rate") != 0)
				{
					char str1[10];
					unsigned short OFDM_CCK = 0;

					if(debug_check)
						fprintf(stderr,"\r\n [%s]",strtmp);

					//cur_tx_rate:   MCS[8-15]
					//cur_tx_rate:   MCS[0-7]
					//cur_tx_rate:   [1,2,5,11]
					//cur_tx_rate:   [6,9,12,18,24,36,48,54]
					sscanf(strtmp, "%*[^:]:%s",str1);
					p = str1;
					while(*p == ' ')
						p++;

					if(debug_check)
						fprintf(stderr,"\r\n p=[%s]",p);

					if(strstr(p, "MCS8") != 0 || strstr(p, "MCS9") != 0 ||
						 strstr(p, "MCS10") != 0 || strstr(p, "MCS11") != 0 ||
						 strstr(p, "MCS12") != 0 || strstr(p, "MCS13") != 0 ||
						 strstr(p, "MCS14") != 0 || strstr(p, "MCS15") != 0 )
					{
						wlanTrafficState = WLAN_MCS8_15;
					}
					else if(strstr(p, "MCS0") != 0 || strstr(p, "MCS1") != 0 ||
									 strstr(p, "MCS2") != 0 || strstr(p, "MCS3") != 0 ||
									 strstr(p, "MCS4") != 0 || strstr(p, "MCS5") != 0 ||
									 strstr(p, "MCS6") != 0 || strstr(p, "MCS7") != 0 )
					{
						wlanTrafficState = WLAN_MCS0_7;
					}
					else
					{
						OFDM_CCK = atoi(p);

						if(OFDM_CCK == 1 || OFDM_CCK == 2 || OFDM_CCK == 5 || OFDM_CCK ==11)
						{
							wlanTrafficState = WLAN_CCK;
						}
						else if(OFDM_CCK == 6 || OFDM_CCK == 9 || OFDM_CCK == 12 || OFDM_CCK == 18 ||
							      OFDM_CCK == 24 || OFDM_CCK == 36 || OFDM_CCK == 48 || OFDM_CCK == 54 )
						{
							wlanTrafficState = WLAN_OFDM;
						}
					}

					if(strstr(p, "MCS15") != 0)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][0];
					else if(strstr(p, "MCS14") != 0)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][1];
					else if(strstr(p, "MCS13") != 0)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][2];
					else if(strstr(p, "MCS12") != 0)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][3];
					else if(strstr(p, "MCS11") != 0)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][4];
					else if(strstr(p, "MCS10") != 0)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][5];
					else if(strstr(p, "MCS9") != 0)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][6];
					else if(strstr(p, "MCS8") != 0)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][7];
					else if(strstr(p, "MCS7") != 0)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][8];
					else if(strstr(p, "MCS6") != 0)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][9];
					else if(strstr(p, "MCS5") != 0)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][10];
					else if(strstr(p, "MCS4") != 0)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][11];
					else if(strstr(p, "MCS3") != 0)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][12];
					else if(strstr(p, "MCS2") != 0)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][13];
					else if(strstr(p, "MCS1") != 0)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][14];
					else if(strstr(p, "MCS0") != 0)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][15];
					else if(OFDM_CCK == 54)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][16];
					else if(OFDM_CCK == 48)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][17];
					else if(OFDM_CCK == 36)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][18];
					else if(OFDM_CCK == 24)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][19];
					else if(OFDM_CCK == 18)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][20];
					else if(OFDM_CCK == 12)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][21];
					else if(OFDM_CCK == 9)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][22];
					else if(OFDM_CCK == 6)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][23];
					else if(OFDM_CCK == 11)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][24];
					else if(OFDM_CCK == 5)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][25];
					else if(OFDM_CCK == 2)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][26];
					else if(OFDM_CCK == 1)
						wlanTrafficZ = wlanTrafficStatePwrConZ[chipVersion][27];

				}

			}
			fclose(stream );

		}
	}

	if(debug_check)
		fprintf(stderr,"\r\n wlanTrafficState=[%u], wlanTrafficZ=[%u]",wlanTrafficState, wlanTrafficZ);

	switch(wlanTrafficState)
	{
		case WLAN_MCS8_15:
			//tx_average /= 1000000;
			if(tx_average > 95000000)
				tx_average = 95000000;

			wlanTrafficStatePwrCon_Total = ((((float)tx_average*wlanTrafficStatePwrCon[chipVersion][wlanTrafficState]*wlanTrafficZ)/1000)/100)/1000000;
			if(debug_check)
				fprintf(stderr,"\r\n wlanTrafficStatePwrCon_Total:(((%u*%u*%u)/1000)/100)/10^6 = [%u]",tx_average,wlanTrafficStatePwrCon[chipVersion][wlanTrafficState],wlanTrafficZ,wlanTrafficStatePwrCon_Total);

			totalPwrCon+=wlanTrafficStatePwrCon_Total;
			break;
		case WLAN_MCS0_7:
			//tx_average /= 1000000;
			if(tx_average > 90000000)
				tx_average = 90000000;

			wlanTrafficStatePwrCon_Total = ((((float)tx_average*wlanTrafficStatePwrCon[chipVersion][wlanTrafficState]*wlanTrafficZ)/1000)/100)/1000000;
			if(debug_check)
				fprintf(stderr,"\r\n wlanTrafficStatePwrCon_Total:(((%u*%u*%u)/1000)/100)/10^6 = [%u]",tx_average,wlanTrafficStatePwrCon[chipVersion][wlanTrafficState],wlanTrafficZ,wlanTrafficStatePwrCon_Total);

			totalPwrCon+=wlanTrafficStatePwrCon_Total;
			break;
		case WLAN_OFDM:
			//tx_average /= 1000000;
			if(tx_average > 25000000)
				tx_average = 25000000;

			wlanTrafficStatePwrCon_Total = ((((float)tx_average*wlanTrafficStatePwrCon[chipVersion][wlanTrafficState]*wlanTrafficZ)/1000)/100)/1000000;
			if(debug_check)
				fprintf(stderr,"\r\n wlanTrafficStatePwrCon_Total:(((%u*%u*%u)/1000)/100)/10^6 = [%u]",tx_average,wlanTrafficStatePwrCon[chipVersion][wlanTrafficState],wlanTrafficZ,wlanTrafficStatePwrCon_Total);

			totalPwrCon+=wlanTrafficStatePwrCon_Total;
			break;
		case WLAN_CCK:

		wlanTrafficStatePwrCon_Total = ((((float)tx_average*wlanTrafficStatePwrCon[chipVersion][wlanTrafficState]*wlanTrafficZ)/1000)/100)/1000000;
			if(debug_check)
				fprintf(stderr,"\r\n wlanTrafficStatePwrCon_Total:(((%u*%u*%u)/1000)/100)/10^6 = [%u]",tx_average, wlanTrafficStatePwrCon[chipVersion][wlanTrafficState],wlanTrafficZ,wlanTrafficStatePwrCon_Total);
			totalPwrCon+=wlanTrafficStatePwrCon_Total;
			break;
	}

	//get CPU utilization
	stream = fopen ( "/proc/stat", "r" );
	if ( stream != NULL )
	{
		char buf[512];
		unsigned int d1, d2, d3, d4;

		fgets(buf, sizeof(buf), stream);	/* eat line */


		sscanf(buf, "cpu %d %d %d %d", &d1, &d2, &d3, &d4);
		fclose(stream);

		if(pre_cpu_d4 == 0)
		{
			pre_cpu_d4 = d4;
		}
		else
		{

			unsigned int delta = 0;

			delta = (d4 - pre_cpu_d4)/time_delta;

			pre_cpu_d4 = d4;
			if(delta > max_cpu_delta)
				max_cpu_delta = delta;

			cpu_utilization = 100 - (int)(delta*100/max_cpu_delta);

			if(debug_check)
				fprintf(stderr,"\r\n cpu_busy: (%u*%u)/100=[%u] ",cpu_utilization,cpuUtilizationPwrCon[chipVersion],((cpu_utilization*cpuUtilizationPwrCon[chipVersion])/100));

	}

	}

	if(cpuMode == CPU_NORMAL)
		totalPwrCon+=((cpu_utilization*cpuUtilizationPwrCon[chipVersion])/100);


	if(1 || strcmp(askfor,"all")==0){


		if(debug_check)
		fprintf(stderr,"\r\n totalPwrCon=%u",totalPwrCon);

		if(tx_average_multiply2)
			tx_average/=2;

		req_format_write(wp, "<interface><name>LAN</name><type>LAN</type><totalPwrCon>%d</totalPwrCon><wlanTx>%d</wlanTx><wlanRx>%d</wlanRx></interface>",totalPwrCon,tx_average,rx_average);

	}

	return 0;

}
#endif // #if defined(POWER_CONSUMPTION_SUPPORT)

#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
#define RS_CERT_START "-----BEGIN CERTIFICATE-----"
#define RS_CERT_END "-----END CERTIFICATE-----"

#define RS_RSA_PRIV_KEY_START "-----BEGIN RSA PRIVATE KEY-----"
#define RS_RSA_PRIV_KEY_END "-----END RSA PRIVATE KEY-----"
#define RS_PRIV_KEY_TIP "PRIVATE KEY-----"



void formUploadEth8021xUserCert(request *wp, char * path, char * query)
{
	char *submitUrl,*strVal, *deleteAllCerts, *user_certstart,*ca_certstart;
	char tmpBuf[MAX_MSG_BUFFER_SIZE]={0};
	int user_cert_len,ca_cert_len;
	char cmd[256];
	FILE *fp;
	char tryFormChange;
	char line[256];
	unsigned char userKeyPass[MAX_RS_USER_CERT_PASS_LEN+1];
	char certOk, userKeyOk;
	int wlanIdx_5G,wlanIdx_2G,rsBandSel;

	//printf("---%s:%d---sizeof(upload_data)=%d	upload_len=%d\n",__FUNCTION__,__LINE__,wp->upload_data,wp->upload_len);

	strVal = req_get_cstream_var_in_mime(wp, ("uploadCertType"), "",NULL);
	submitUrl = req_get_cstream_var_in_mime(wp, ("submit-url"), "",NULL);   // hidden page
	deleteAllCerts = req_get_cstream_var_in_mime(wp, ("delAllCerts"), "",NULL);   // hidden page

	if(deleteAllCerts[0]=='1')
	{
		//To delete all 802.1x certs
		system("rsCert -rst_eth");
		strcpy(tmpBuf,"Delete all 802.1x cerificates of ethernet success!");

	}
	else
	{
		//Initial
		tryFormChange=0;
		certOk=0;
		userKeyOk=0;

		if(NULL == strstr(wp->upload_data,RS_CERT_START)|| NULL ==strstr(wp->upload_data,RS_CERT_END))
		{
			//printf("---%s:%d---No 802.1x cert inclued in upload file!\n",__FUNCTION__,__LINE__);
			strcpy(tmpBuf,"No 802.1x cert inclued in upload file!");
			tryFormChange=1;
		}

		if((tryFormChange==0)&&(!strcmp(strVal,"user")))
		{
			//if(NULL == strstr(wp->upload_data,RS_PRIV_KEY_TIP))
			if((NULL ==strstr(wp->upload_data,RS_RSA_PRIV_KEY_START)) || (NULL ==strstr(wp->upload_data,RS_RSA_PRIV_KEY_END)))
			{
				//printf("---%s:%d---No 802.1x private key inclued in upload file!\n",__FUNCTION__,__LINE__);
				strcpy(tmpBuf,"No 802.1x private key inclued in upload file!");
				tryFormChange=1;
			}
		}
		if(!strcmp(strVal,"user"))
		{
			user_certstart= req_get_cstream_var_in_mime(wp, ("radiusUserCert"), "",&user_cert_len);

			if(tryFormChange==0)
			{

				fp=fopen(RS_USER_CERT_ETH,"w");
				if(NULL == fp)
				{
					sprintf(tmpBuf,"Can not open tmp RS cert(%s)!", RS_USER_CERT_5G);
					goto upload_ERR;
				}


				fwrite(user_certstart,user_cert_len,0x1,fp);

				fclose(fp);
			}
			else
			{
				//To store user cert in tmp file: RS_USER_CERT_TMP
				fp=fopen(RS_USER_CERT_TMP,"w");
				if(NULL == fp)
				{
					sprintf(tmpBuf,"[2] Can not open tmp user cert(%s)!", RS_USER_CERT_TMP);
					goto upload_ERR;
				}
				fwrite(user_certstart,user_cert_len,0x1,fp);
				fclose(fp);

				// try change user cert form from pfx to pem
				memset(userKeyPass, 0, sizeof(userKeyPass));
				apmib_get( MIB_ELAN_RS_USER_CERT_PASSWD, (void *)userKeyPass);

				sprintf(cmd, "openssl pkcs12 -in %s -nodes -out %s -passin pass:%s", RS_USER_CERT_TMP, RS_USER_CERT_ETH, userKeyPass);

				system(cmd);

				sleep(3); // wait for system(cmd) and avoid to open file failure;
				fp=fopen(RS_USER_CERT_ETH,"r");
				if(NULL == fp)
				{
					sprintf(tmpBuf,"[2] Can not open tmp user cert(%s)!Maybe you should upload your user certificate once again", RS_USER_CERT_ETH);
					goto upload_ERR;
				}

				while (fgets(line, sizeof(line), fp))
				{
					if((NULL != strstr(line,RS_CERT_START) ) || (NULL != strstr(line,RS_CERT_END) ))
						certOk=1;
					//if(NULL != strstr(line,RS_PRIV_KEY_TIP))
					if((NULL !=strstr(line,RS_RSA_PRIV_KEY_START)) || (NULL !=strstr(line,RS_RSA_PRIV_KEY_END)))
						userKeyOk=1;

					if((certOk == 1) && (userKeyOk == 1))
						break;
				}

				if((certOk != 1) || (userKeyOk != 1))
				{

					sprintf(cmd, "rm -rf %s", RS_USER_CERT_ETH);

					system(cmd);

					sprintf(tmpBuf,"Upload user cert failed. Please make sure: 1) uploaded file in pem or pfx form, 2) uploaded file contain user cert and user key.");
					goto upload_ERR;
				}

				fclose(fp);
			}

			//To store 802.1x user cert

			system("rsCert -wrUser_eth");

			strcpy(tmpBuf,"802.1x user cerificate and user key upload success!");
		}
		else if(!strcmp(strVal,"root"))
		{
			ca_certstart= req_get_cstream_var_in_mime(wp, ("radiusRootCert"), "",&ca_cert_len);

			if(tryFormChange == 0)
			{
				fp=fopen(RS_ROOT_CERT_ETH,"w");
				if(NULL == fp)
				{
					sprintf(tmpBuf,"Can not open tmp RS cert(%s)!", RS_ROOT_CERT_ETH);
					goto upload_ERR;
				}

				fwrite(ca_certstart,ca_cert_len,0x1,fp);
				fclose(fp);
			}
			else
			{
				// To store ca cert in tmp file: RS_ROOT_CERT_TMP
				fp=fopen(RS_ROOT_CERT_TMP,"w");
				if(NULL == fp)
				{
					sprintf(tmpBuf,"Can not open tmp RS cert(%s)!", RS_ROOT_CERT_TMP);
					goto upload_ERR;
				}
				fwrite(ca_certstart,ca_cert_len,0x1,fp);
				fclose(fp);

				// try change ca cert form from der to pem

				sprintf(cmd, "openssl x509 -inform DER -in %s -outform PEM -out %s",RS_ROOT_CERT_TMP,RS_ROOT_CERT_ETH);


				system(cmd);

				sleep(3);	// wait for system(cmd) and avoid to open file failure;


				fp=fopen(RS_ROOT_CERT_ETH,"r");
				if(NULL == fp)
				{
					sprintf(tmpBuf,"[2] Can not open tmp RS cert(%s)!\nMaybe you should upload your root certificate once again!", RS_ROOT_CERT_ETH);
					goto upload_ERR;
				}

				while (fgets(line, sizeof(line), fp))
				{
					if((NULL != strstr(line,RS_CERT_START) ) || (NULL != strstr(line,RS_CERT_END) ))
					{
						certOk=1;
						break;
					}
				}

				if(certOk != 1)
				{

					sprintf(cmd, "rm -rf %s", RS_ROOT_CERT_ETH);

					system(cmd);

					strcpy(tmpBuf,"[2] No 802.1x cert inclued in upload file!");
					goto upload_ERR;
				}

				fclose(fp);
			}

			//To store 802.1x root cert

			system("rsCert -wrRoot_eth");

			strcpy(tmpBuf,"802.1x root cerificate upload success!");
		}
		else
		{
			sprintf(tmpBuf,"Upload cert type(%s) is not supported!", strVal);
			goto upload_ERR;
		}
	}

	OK_MSG1(tmpBuf, submitUrl);
	return;

upload_ERR:
	if(fp != NULL)
		fclose(fp);

	ERR_MSG(tmpBuf);
}
#endif

#ifdef CONFIG_RTL_TRANSMISSION
void formTransmissionBT(request *wp, char * path, char * query)
{
	char *downdir;
	char *updir;
	char *strptr;
	char *nextwebpage;
	char tmp[128];
	char cmd[128];
	int enabled;

	nextwebpage=req_get_cstream_var(wp, ("nextwebpage"),"");
	downdir=req_get_cstream_var(wp, ("btdownloaddir"),"");
//	updir=req_get_cstream_var(wp, ("btuploaddir"),"");
	strptr=req_get_cstream_var(wp, ("bt_enabled"),"");

	if(access(downdir, 0) != 0)
	{
		ERR_MSG("Directory Not Exists!!!");
		return;
	}

	if(strptr)
		enabled=atoi(strptr);

//	apmib_set(MIB_BT_UPLOAD_DIR,updir);
	apmib_set(MIB_BT_DOWNLOAD_DIR,downdir);
	apmib_set(MIB_BT_ENABLED,&enabled);
	apmib_update(CURRENT_SETTING);

	if(enabled)
	{
		if(access("/var/run/transmission.pid", 0) == 0)
		{
			ERR_MSG("There is transmission-daemon already running!");
			return;
		}
		sprintf(tmp, "%s/transmission-daemon", downdir);
		if(access(tmp, 0) != 0)
		{
			sprintf(cmd, "mkdir %s/transmission-daemon/", downdir);
			system(cmd);
		}
		sprintf(tmp, "%s/transmission-daemon/torrents", downdir);
		if(access(tmp, 0) != 0)
		{
			sprintf(cmd, "mkdir %s/transmission-daemon/torrents/", downdir);
			system(cmd);
		}
		sprintf(tmp, "%s/transmission-daemon/resume", downdir);
		if(access(tmp, 0) != 0)
		{
			sprintf(cmd, "mkdir %s/transmission-daemon/resume/", downdir);
			system(cmd);
		}
		sprintf(tmp, "%s/transmission-daemon/blocklists", downdir);
		if(access(tmp, 0) != 0)
		{
			sprintf(cmd, "mkdir %s/transmission-daemon/blocklists/", downdir);
			system(cmd);
		}
		sprintf(tmp, "/var/transmission");
		if(access(tmp, 0) != 0)
		{
			system("mkdir /var/transmission/");
		}

		sprintf(cmd, "ln -s %s/transmission-daemon/torrents/ /var/transmission/", downdir);
		system(cmd);
		sprintf(cmd, "ln -s %s/transmission-daemon/resume/ /var/transmission/", downdir);
		system(cmd);
		sprintf(cmd, "ln -s %s/transmission-daemon/blocklists/ /var/transmission/", downdir);
		system(cmd);
		sprintf(cmd, "transmission-daemon --log-error -w %s", downdir);
//		sprintf(cmd, "transmission-daemon --log-debug -w %s -e %s/log", downdir, downdir);
		system(cmd);
	}
	else
	{
		FILE *fp;
		char buf[16];
		int pid;

		fp=fopen("/var/run/transmission.pid","r");
		if(NULL == fp)
		{
			ERR_MSG("Can't open /var/run/transmission.pid!");
			return;
		}
		fgets(buf, sizeof(buf), fp);
		sscanf(buf, "%d", &pid);
		fclose(fp);

		sprintf(cmd,"kill -9 %d 2>/dev/null", pid);
		system(cmd);
		system("rm /var/transmission/torrents 2>/dev/null");
		system("rm /var/transmission/resume 2>/dev/null");
		system("rm /var/transmission/blocklists 2>/dev/null");
		system("rm /var/run/transmission.pid 2>/dev/null");
	}

	send_redirect_perm(wp,nextwebpage);
	return;
}
#endif

void formLdap(request *wp, char *path, char *query)
{
	char *strVal, *submitUrl;

	if (wp->superUser != 1)
		return;

	apmib_set_hist_clear();
	strVal = req_get_cstream_var(wp, ("UseAutoup"), "");
	if (strVal[0]) {
		ydespaces(strVal);
		apmib_nvram_set("x_ldap_autoup_enabled", strVal);
	} else {
		apmib_nvram_unset("x_ldap_autoup_enabled");
	}

	strVal = req_get_cstream_var(wp, ("server_url"), "");
	if (strVal[0]) {
		ydespaces(strVal);
		if (str_masking_check(strVal) == 1) {
			apmib_nvram_set("x_ldap_autoup_domain", strVal);
		}
	} else {
		apmib_nvram_unset("x_ldap_autoup_domain");
	}

	strVal = req_get_cstream_var(wp, ("server_file"), "");
	if (strVal[0]) {
		ydespaces(strVal);
		if (str_masking_check(strVal) == 1) {
			apmib_nvram_set("x_ldap_autoup_file", strVal);
		}
	} else {
		apmib_nvram_unset("x_ldap_autoup_file");
	}

	strVal = req_get_cstream_var(wp, ("preUse"), "");
	if (strVal[0]) {
		apmib_nvram_unset("x_autoup_prefix_use");
	} else {
		apmib_nvram_set("x_autoup_prefix_use", "0");
	}

	strVal = req_get_cstream_var(wp, ("pre"), "");
	if (strVal[0]) {
		ydespaces(strVal);
		if (str_masking_check(strVal) == 1) {
			apmib_nvram_set("x_ldap_autoup_prefix", strVal);
		}
	} else {
		apmib_nvram_unset("x_ldap_autoup_prefix");
	}

	strVal = req_get_cstream_var(wp, ("ldap_url"), "");
	if (strVal[0]) {
		ydespaces(strVal);
		if (str_masking_check(strVal) == 1) {
			apmib_nvram_set("x_autoup_auth_svr", strVal);
		}
	} else {
		apmib_nvram_unset("x_autoup_auth_svr");
	}

	web_config_trace(5, 10);	/* management/ldap */
	nvram_commit();

#ifdef __DAVO__
	need_reboot = 1;
	OK_MSG("/skb_ldap.htm");
#else
	send_redirect_perm(wp, "/skb_ldap.htm");
	//      OK_MSG(submitUrl);
#endif
	return;

 setErr:
	ERR_MSG("서버 Url 또는 데이터 파일명을 확인해주시기 바랍니다.");
}

void formAutoReboot(request * wp, char *path, char *query)
{
	char *strVal, *submitUrl, *uforce;
	int intVal;

	if (wp->superUser != 1)
		return;

	apmib_set_hist_clear();
	submitUrl = req_get_cstream_var(wp, "submit-url", "");	// hidden page

	strVal = req_get_cstream_var(wp, ("autoreboot_enabled"), "");
	if (strVal[0])
		apmib_nvram_set("x_auto_reboot_enable", "1");
	else
		apmib_nvram_set("x_auto_reboot_enable", "0");

	uforce = req_get_cstream_var(wp, ("autoreboot_userforce"), "");
	if (uforce[0])
		apmib_nvram_set("x_autoreboot_userforce", "1");
	else {
		apmib_nvram_set("x_autoreboot_userforce", "0");
		apmib_nvram_set("x_auto_reboot_on_idle", "1");
		apmib_nvram_set("x_auto_wan_port_idle", "1");
		apmib_nvram_set("x_auto_uptime", "7d");
		apmib_nvram_set("x_auto_bw_kbps", "1000");
		apmib_nvram_set("x_auto_hour_range", "03:00-04:00");
		apmib_nvram_set("x_autoreboot_week", "4-4");
		goto setok;
	}

	strVal = req_get_cstream_var(wp, ("autoreboot_on_idle"), "");
	if (strVal[0] && uforce[0]) {
		intVal = strtoul(strVal, NULL, 10);
		if (intVal == 0 || intVal == 1)
			apmib_nvram_set("x_auto_reboot_on_idle", strVal);
	}

	strVal = req_get_cstream_var(wp, ("autoreboot_wan_idle"), "");
	if (strVal[0] && uforce[0]) {
		intVal = strtoul(strVal, NULL, 10);
		if (intVal == 0 || intVal == 1)
			apmib_nvram_set("x_auto_wan_port_idle", strVal);
	}

	strVal = req_get_cstream_var(wp, ("autoreboot_uptime"), "");
	if (strVal[0] && uforce[0])
		apmib_nvram_set("x_auto_uptime", strVal);

	strVal = req_get_cstream_var(wp, ("autoreboot_kbps"), "");
	if (strVal[0] && uforce[0])
		apmib_nvram_set("x_auto_bw_kbps", strVal);

	strVal = req_get_cstream_var(wp, ("autoreboot_time"), "");
	if (strVal[0] && uforce[0])
		apmib_nvram_set("x_auto_hour_range", strVal);

	strVal = req_get_cstream_var(wp, ("autoreboot_week"), "");
	if (strVal[0] && uforce[0])
		apmib_nvram_set("x_autoreboot_week", strVal);

setok:
	web_config_trace(5, 11);	/* management/auto reboot */
	nvram_commit();
	need_reboot = 1;
	OK_MSG("/skb_auto_reboot.htm");
	return;

 setErr:
	ERR_MSG("설정을 확인해주시기 바랍니다.");
}

#define AUTOREBOOT_CFG	"/var/ldap_autoreboot"
int autoreboot_status(request *wp, int argc, char **argv)
{
	FILE *fp;
	int auto_reboot_on_idle;
	char auto_uptime[12];
	int auto_wan_port_idle;
	char auto_hour_range[20];
	char *n, *v;
	int nBytesSent = 0;
	int need_init = 1;
	int check_all = 0;
	int ldap_success = 1;
	char buf[80];

	fp = fopen(AUTOREBOOT_CFG, "r");
	if (fp) {
		while(fgets(buf, sizeof(buf), fp)) {
			ydespaces(buf);
			v = &buf[0];
			n = strsep(&v, "=");

			if (!n || !v)
				break;

			if ( !strcmp(n, "auto_reboot_on_idle") ) {
				auto_reboot_on_idle = strtoul(v, NULL, 10);
				check_all |= 1;
			}
			else if ( !strcmp(n, "auto_uptime") ) {
				snprintf(auto_uptime, sizeof(auto_uptime), "%s", v);
				check_all |= 2;
			}
			else if ( !strcmp(n, "auto_wan_port_idle") ) {
				auto_wan_port_idle = strtoul(v, NULL, 10);
				check_all |= 4;
			}
			else if ( !strcmp(n, "auto_hour_range") ) {
				snprintf(auto_hour_range, sizeof(auto_hour_range), "%s", v);
				check_all |= 8;
			}
		}
		if (check_all == 0xf)
			need_init = 0;
		fclose(fp);
	}

	if (need_init) {
		ldap_success = 0;

		auto_reboot_on_idle = 1;
		snprintf(auto_uptime, sizeof(auto_uptime), "%s", "7d");
		auto_wan_port_idle = 1;
		snprintf(auto_hour_range, sizeof(auto_hour_range), "%s", "03:00-04:00");
	}

	nBytesSent += req_format_write(wp, ("<tr>\n"));
	nBytesSent += req_format_write(wp, ("<td width=\"50%%\">\n"));
	nBytesSent += req_format_write(wp, ("GET FROM LDAP CFG SERVER:\n"));
	nBytesSent += req_format_write(wp, ("</td>\n"));
	nBytesSent += req_format_write(wp, ("<td>%s\n"), (ldap_success)?"Success":"Fail");
	nBytesSent += req_format_write(wp, ("</td>\n"));
	nBytesSent += req_format_write(wp, ("</tr>\n"));

	nBytesSent += req_format_write(wp, ("<tr>\n"));
	nBytesSent += req_format_write(wp, ("<td width=\"50%%\">\n"));
	nBytesSent += req_format_write(wp, ("Auto Reboot on idle:\n"));
	nBytesSent += req_format_write(wp, ("</td>\n"));
	nBytesSent += req_format_write(wp, ("<td>%s\n"), (auto_reboot_on_idle)?"Yes":"No");
	nBytesSent += req_format_write(wp, ("</td>\n"));
	nBytesSent += req_format_write(wp, ("</tr>\n"));

	nBytesSent += req_format_write(wp, ("<tr>\n"));
	nBytesSent += req_format_write(wp, ("<td width=\"50%%\">\n"));
	nBytesSent += req_format_write(wp, ("Auto Uptime:\n"));
	nBytesSent += req_format_write(wp, ("</td>\n"));
	nBytesSent += req_format_write(wp, ("<td width=\"50%%\">\n"));
	nBytesSent += req_format_write(wp, ("%s\n"), auto_uptime);
	nBytesSent += req_format_write(wp, ("</td>\n"));
	nBytesSent += req_format_write(wp, ("</tr>\n"));

	nBytesSent += req_format_write(wp, ("<tr>\n"));
	nBytesSent += req_format_write(wp, ("<td width=\"50%%\">\n"));
	nBytesSent += req_format_write(wp, ("Auto Wan Port Idle:\n"));
	nBytesSent += req_format_write(wp, ("</td>\n"));
	nBytesSent += req_format_write(wp, ("<td>\n"));
	nBytesSent += req_format_write(wp, ("%s\n"), (auto_wan_port_idle)?"Yes":"No");
	nBytesSent += req_format_write(wp, ("</td>\n"));
	nBytesSent += req_format_write(wp, ("</tr>\n"));
	nBytesSent += req_format_write(wp, ("<tr>\n"));
	nBytesSent += req_format_write(wp, ("<td width=\"50%%\">Auto Hour Range:(00~23):\n"));
	nBytesSent += req_format_write(wp, ("</td>\n"));
	nBytesSent += req_format_write(wp, ("<td width=\"50%%\">\n"));
	nBytesSent += req_format_write(wp, ("%s\n"), auto_hour_range);
	nBytesSent += req_format_write(wp, ("</td>\n"));
	nBytesSent += req_format_write(wp, ("</tr>\n"));

	return nBytesSent;
}

#ifdef __DAVO__
void formJumbo(request *wp, char *path, char *query)
{
	char *submitUrl;
	char *strVal;
	char tmpBuf[100];
	int ret = -1;

	apmib_set_hist_clear();
	strVal = req_get_cstream_var(wp, "jumbo_enable", "0");
	if (strVal[0]) {
		apmib_nvram_set("x_jumbo_enable", strVal);
	}

	strVal = req_get_cstream_var(wp, "jumbo_size", "1500");
	if (strVal[0]) {
		apmib_nvram_set("x_jumbo_size", strVal);
	}
	web_config_trace(5, 14);	/* management/jumbo frame */
	nvram_commit();

	ret = set_jumbo_frm();

	if (ret == -1) {
		strcpy(tmpBuf, "오류: 점보 프레임 설정에 실패하였습니다.!");
		goto setErr;
	}

	submitUrl = req_get_cstream_var(wp, ("submit-url"), "");	// hidden page
	send_redirect_perm(wp, "/skb_jumbo.htm");
	//OK_MSG(submitUrl);
	return;

 setErr:
	ERR_MSG(tmpBuf);
}

void formIgmpSet(request *wp, char *path, char *query)
{
	char *temp_str;
	char temp[128];
	int i, val, val_igmp_block_enable, val_igmp_thresh_hold, val_igmp_block_period;
	int port_status[4];
	int port_change_flag = 0;
	int intValue = 0;

	if (wp->superUser != 1)
		return;

	apmib_set_hist_clear();
#if defined(__IGMP_BLOCK_CONF__)
	temp_str = req_get_cstream_var(wp, "igmp_block_enable", "");
	if (strcmp(temp_str, "ON") == 0) {
		apmib_nvram_set("x_igmp_block_enable", "1");
		val_igmp_block_enable = 1;
	} else {
		apmib_nvram_set("x_igmp_block_enable", "0");
		val_igmp_block_enable = 0;
	}

	if (val_igmp_block_enable) {
		for (i = 0; i < 4; i++) {
			sprintf(temp, "lan%d_control", i + 1);
			temp_str = req_get_cstream_var(wp, temp, "");
			if (temp_str[0]) {
				port_change_flag = i + 1;
				break;
			}
		}

		if (port_change_flag) {
			for (i = 0; i < 4; i++) {
				sprintf(temp, "port%d_status", i + 1);
				temp_str = req_get_cstream_var(wp, temp, "0");
				port_status[i] = atoi(temp_str);
			}

			if (port_status[port_change_flag - 1] == 0)
				port_status[port_change_flag - 1] = 1;
			else
				port_status[port_change_flag - 1] = 0;

			sprintf(temp, "echo 2 %d %d %d %d > /proc/dv_igmp_block", port_status[0],
				port_status[1], port_status[2], port_status[3]);
			system(temp);
			send_redirect_perm(wp, "/skb_igmp.htm");
			return;
		}
	}

	temp_str = req_get_cstream_var(wp, "hidden_thresh_hold", "60");
	apmib_nvram_set("x_igmp_thresh_hold", temp_str);
	val_igmp_thresh_hold = atoi(temp_str);

	temp_str = req_get_cstream_var(wp, "hidden_block_period", "50");
	apmib_nvram_set("x_igmp_block_period", temp_str);
	val_igmp_block_period = atoi(temp_str);

	sprintf(temp, "echo 1 %d %d %d > /proc/dv_igmp_block", val_igmp_block_enable,
		val_igmp_thresh_hold, val_igmp_block_period);
	system(temp);
#endif
	/*
	temp_str = req_get_cstream_var(wp, "igmpv3", "");
	if (strcmp(temp_str,"ON")==0)
		dvnv_set("igmp_v3_enabled", "checked");
	else
		dvnv_unset("igmp_v3_enabled");
	*/
	temp_str = req_get_cstream_var(wp, "igmpfast", "");
	if (strcmp(temp_str, "ON") == 0)
		intValue = 0;
	else
		intValue = 1;

	apmib_set(MIB_IGMP_FAST_LEAVE_DISABLED, (void *)&intValue);

	temp_str = req_get_cstream_var(wp, "igmp_querier_enable", "");
	if (strcmp(temp_str, "ON") == 0) {
		apmib_nvram_set("x_igmp_querier", "1");
		system("echo 1 > /proc/dv_igmp_query_to_lan");
	} else {
		apmib_nvram_set("x_igmp_querier", "0");
		system("echo 0 > /proc/dv_igmp_query_to_lan");
	}

	temp_str = req_get_cstream_var(wp, "igmp_querier_interval", "");
	if (strcmp(temp_str, "") != 0)
		apmib_nvram_set("x_igmp_querier_interval", temp_str);

	temp_str = req_get_cstream_var(wp, "igmp_querier_mode", "");
	if (strcmp(temp_str, "") != 0)
		apmib_nvram_set("x_igmp_querier_auto", temp_str);

	temp_str = req_get_cstream_var(wp, "dv_igmp_joinlimit_enable", "");
	if (strcmp(temp_str, "ON") == 0) {
		apmib_nvram_set("x_igmp_joinlimit_enable", "1");
		val = 1;
	} else {
		apmib_nvram_set("x_igmp_joinlimit_enable", "0");
		val = 0;
	}
	if (val == 1) {
		temp_str = req_get_cstream_var(wp, "dv_igmp_limite_lan1", "32");
		apmib_nvram_set("x_igmp_limite_lan1", temp_str);
		temp_str = req_get_cstream_var(wp, "dv_igmp_limite_lan2", "32");
		apmib_nvram_set("x_igmp_limite_lan2", temp_str);
		temp_str = req_get_cstream_var(wp, "dv_igmp_limite_lan3", "32");
		apmib_nvram_set("x_igmp_limite_lan3", temp_str);
		temp_str = req_get_cstream_var(wp, "dv_igmp_limite_lan4", "32");
		apmib_nvram_set("x_igmp_limite_lan4", temp_str);
		temp_str = req_get_cstream_var(wp, "dv_igmp_limite_sys", "128");
		apmib_nvram_set("x_igmp_limite_sys", temp_str);
	}

	web_config_trace(5, 3);	/* management/igmp */

	need_reboot = 1;
	OK_MSG("/skb_igmp.htm");

	apmib_update_web(CURRENT_SETTING);

	return;
}

void formDiagnostic_ping(request *wp, char *path, char *query)
{
	char *temp_str;
	char temp[128];

	temp_str = req_get_cstream_var(wp, "input_ip", "");

	if (temp_str[0]) {
		if (send_ping_test(temp_str) == 1)
			snprintf(temp, sizeof(temp), "%s success ", temp_str);
		else
			snprintf(temp, sizeof(temp), "%s lose ", temp_str);
	} else
		strcpy(temp, "error");

	nvram_set("x_PING_TEST_RESULT", temp);

	nvram_commit();
	send_redirect_perm(wp, "/skb_diagnostic_ping.htm");
	return;
}

static int get_gateway_addr(unsigned char *return_buf)
{
	FILE *fp;
	unsigned char buf[64];
	int len = 0;

	if ( !return_buf )
		return 0;

	if ( (fp = fopen("/var/gateway", "r")) ) {
		buf[0] = 0;
		if ( fgets(buf, sizeof(buf), fp) )
			len = sprintf(&return_buf[0], "%s", buf);
		fclose(fp);
	}

	ydespaces(return_buf);
	return len;
}

int get_dns_addr(int pos, unsigned char *return_buf)
{
	int n, dns_mode;
	struct in_addr addr;
	struct nameserver_addr ns_addrs[8];

	if (!apmib_get(MIB_DNS_MODE, (void *)&dns_mode))
		return -1;

	addr.s_addr = 0;
	if (dns_mode == 1) {
		if (!apmib_get((pos == 1) ? MIB_DNS1 : MIB_DNS2, (void *)&addr.s_addr))
			return -1;
	} else if (pos > 0) {
		n = sort_nameserver("/etc/resolv.conf", ns_addrs,
				ARRAY_SIZE(ns_addrs), AF_INET);
		if (--pos < n)
			addr.s_addr = ns_addrs[pos].na_addr;
	}

	strcpy(return_buf, inet_ntoa(addr));
	return 1;
}

int get_ping_info(request *wp, int argc, char **argv)
{
	unsigned char test_Ip[64];
	int nBytesSent=0;
	char	*name;

	if (ejArgs(argc, argv, "%s", &name) < 1) {
		fprintf(stderr, "Insufficient args\n");
		return -1;
	}

	memset(test_Ip, 0, sizeof(test_Ip));
	if ( !strcmp(name, "gateway")) {
		if(get_gateway_addr(test_Ip)<1)
			goto err;
	}
	else if ( !strcmp(name, "wan_dns0")) {
		if(get_dns_addr(1, test_Ip)<1)
			goto err;
	}
	else if ( !strcmp(name, "wan_dns1")) {
		if(get_dns_addr(2, test_Ip)<1)
			goto err;
	}
	else {
		goto err;
	}

	if(strcmp(test_Ip, "0.0.0.0")==0 || test_Ip[0] == NULL)
		goto err;

	if(send_ping_test(test_Ip)==1)
		nBytesSent += req_format_write(wp, "<font size=2 color='green'>정상</font>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>%s</font>", test_Ip);
	else
		nBytesSent += req_format_write(wp, "<font size=2 color='red'>응답없음</font>&nbsp;&nbsp;<font size=2>%s</font>", test_Ip);

	return nBytesSent;

err:
	nBytesSent += req_format_write(wp, "<font size=2 color='#ff9900'>해당 정보없음</font>");
	return nBytesSent;
}

int igmp_stb_info(request *wp, int argc, char **argv)
{
	struct list_head *pos;
	struct list_head mc;
	int nbyte = 0;

	INIT_LIST_HEAD(&mc);
	read_mcast(&mc, "/proc/rtl865x/igmp");
	list_for_each(pos, &mc) {
		struct mcast_group *g =
			list_entry(pos, struct mcast_group, list);
		/* APNRTL-251: Compare 239.192.60.XX(stb only use) */
		if (!list_empty(&g->mbrlist) &&
		    (ntohl(g->group.s_addr) & 0xffffff00) == 0xefc03c00) {
			struct mcast_mbr *m =
				list_entry(g->mbrlist.next, struct mcast_mbr, list);
			nbyte = req_format_write(wp, "%u.%u.%u.%u|LAN %d",
					  NIPQUAD(m->address), m->port);
			break;
		}
	}
	mcast_group_free(&mc);
	if (nbyte == 0)
		nbyte = req_format_write(wp, "null");
	return nbyte;
}

void formAutoup(request *wp, char *path, char *query)
{
	char *strVal, tmpBuf[MAX_MSG_BUFFER_SIZE] = { 0 };
	char *strUrl, *submitUrl;
	char *strPrefix, *strFileName;

	if (wp->superUser != 1)
		return;

	apmib_set_hist_clear();
	submitUrl = req_get_cstream_var(wp, "submit-url", "");
	strVal = req_get_cstream_var(wp, "UseAutoup", "");

	if (strVal[0]) {
		if (!strcmp(strVal, "disable")) {
			apmib_nvram_set("x_autoup_enabled", "0");
			apmib_nvram_set("x_ldap_enabled", "0");
		} else if (!strcmp(strVal, "ldap")) {	//ldap
			apmib_nvram_set("x_autoup_enabled", "0");
			apmib_nvram_set("x_ldap_enabled", "1");
		} else if (!strcmp(strVal, "swms")) {	//swms
			apmib_nvram_set("x_autoup_enabled", "1");
			apmib_nvram_set("x_ldap_enabled", "0");

			strUrl = req_get_cstream_var(wp, "server_url", "");
			strFileName = req_get_cstream_var(wp, "datafile", "");
			strPrefix = req_get_cstream_var(wp, "pre", "");

			//printf("Server: %s, File:%s\n", strUrl, strFileName);
			if (!strUrl[0] || !strFileName[0]) {
				strcpy(tmpBuf, "Invail URL or file name");
				goto setErr;
			}
			apmib_nvram_set("x_autoup_enabled", "1");
			if (str_masking_check(strUrl) == 1) {
				apmib_nvram_set("x_autoup_domain", strUrl);
			}
			if (str_masking_check(strFileName) == 1) {
				apmib_nvram_set("x_autoup_file", strFileName);
			}
			if (str_masking_check(strPrefix) == 1) {
				apmib_nvram_set("x_autoup_prefix", strPrefix);
			}
		}
		web_config_trace(5, 13);	/* management/autoupgrade */
		nvram_commit();
	}
	need_reboot = 1;
	OK_MSG("/skb_auto_upgrade.htm");
	return;
 setErr:
	ERR_MSG(tmpBuf);
	return;
}

void formPortMirror(request *wp, char *path, char *query)
{
	char *submitUrl;
	char tmpBuf[100];
	int from, to;
	char *strVal;
	int is_on;

	if (wp->superUser != 1)
		return;

	strVal = req_get_cstream_var(wp, "save", (""));
	if (strVal[0]) {
		 strVal = req_get_cstream_var(wp, "portMirrorMode", ("OFF"));
		 is_on = (strcmp(strVal,"ON")==0) ? 1:0;

		 strVal = req_get_cstream_var(wp, "port_from", (""));
		 from = atoi(strVal);

		 strVal = req_get_cstream_var(wp, "port_to", (""));
		 to = atoi(strVal);

		 if (is_on)
			  sprintf(tmpBuf, "/bin/mirror set %d %d", from, to);
		 else
			  sprintf(tmpBuf, "/bin/mirror clear");
		 system(tmpBuf);
	}

	submitUrl = req_get_cstream_var(wp, ("submit-url"), (""));   // hidden page
	if (submitUrl[0])
		send_redirect_perm(wp, "/skb_port_mirror.htm");

	return;

setErr_end:
	ERR_MSG(tmpBuf);
}

int netconn_viewer(request *wp, int argc, char **argv)
{
	FILE *fp;
	char buf[128];
	int i, l, nbytes=0;
	char *argv_l[6];

	buf[0]=0;
	if ( (fp=popen("netstat -antu", "r")) ) {
		i = 0;
		nbytes += req_format_write(wp, "<tr>");
		nbytes += req_format_write(wp, "<td ><center>Proto</td>");
		nbytes += req_format_write(wp, "<td ><center>Recv-Q</td>");
		nbytes += req_format_write(wp, "<td ><center>Send-Q</td>");
		nbytes += req_format_write(wp, "<td ><center>Local Address</td>");
		nbytes += req_format_write(wp, "<td ><center>Foreign Address</td>");
		nbytes += req_format_write(wp, "<td ><center>State</td>");
		nbytes += req_format_write(wp, "</tr>");
		while( fgets(buf, sizeof(buf), fp) ) {
			ydespaces(buf);
			if ( i++ < 2)
				continue;
			nbytes += req_format_write(wp, "<tr>");
			parse_line(buf, argv_l, 6, " \r\n\t");
			for ( l=0; l < 6; l++) {
				nbytes += req_format_write(wp, "<td><center>%s</td>",
							(argv_l[l])?ydespaces(argv_l[l]):"");
			}
			nbytes += req_format_write(wp, "</tr>");
			buf[0]=0;
		}
		pclose(fp);
	}
	return nbytes;
}

unsigned char *gettoken(const unsigned char *str,unsigned int index,unsigned char symbol)
{
	static char tmp[50];
	unsigned char tk[50]; //save symbol index
	char *ptmp;
	int i,j,cnt=1,start,end;

	memset(tmp, 0x00, sizeof(tmp));

	for (i=0;i<strlen((char *)str);i++)
	{
		if (str[i]==symbol)
		{
			tk[cnt]=i;
			cnt++;
		}
	}

	if (index>cnt-1)
	{
		return NULL;
	}

	tk[0]=0;
	tk[cnt]=strlen((char *)str);

	if (index==0)
		start=0;
	else
		start=tk[index]+1;

	end=tk[index+1];

	j=0;
	for(i=start;i<end;i++)
	{
		tmp[j]=str[i];
		j++;
	}

	return (unsigned char *)tmp;
}

#endif
