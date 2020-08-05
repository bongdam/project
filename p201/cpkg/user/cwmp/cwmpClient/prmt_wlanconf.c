#ifndef __PRMT_WLANCONF_C__
#define __PRMT_WLANCONF_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_wlanconf.h"
#include "prmt_associateddevice.h"
#include "prmt_wps.h"
#include "bcm_param_api.h"
#include "bcm_cfg_api.h"
#include "prmt_stats.h"
#include <ifport_counter.h>

typedef enum {en_false = 0, en_true = 1} boolean;

struct sCWMP_ENTITY tWLANConf[] = {
	/*(name,								type,			flag,	 				accesslist,	etvalue,			setvalue,		next_table,	sibling)*/
	{"SSID",								eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
	{"BSSID",								eCWMP_tSTRING,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
	{"Enable",								eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
///	{"AssociatedDeviceNumberOfEntries",		eCWMP_tUINT,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
///TODO	{"AssociatedDevice",					eCWMP_tOBJECT,	CWMP_READ|CWMP_WRITE,	NULL,		NULL,			AssocObj,			NULL,		NULL},
	{"TotalBytesSent",						eCWMP_tUINT,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
	{"TotalBytesReceived",					eCWMP_tUINT,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
	{"KeyPassphrase",						eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,			NULL,		NULL},
#if 0
	{"BasicEncryptionModes",				eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
	{"WEPKeyIndex",							eCWMP_tUINT,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
	{"WPAEncryptionModes",					eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
	{"WPAAuthenticationMode",				eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
#endif
///	{"Status",								eCWMP_tSTRING,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
///	{"MaxBitRate",							eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
	{"Channel",								eCWMP_tUINT,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
	{"BeaconType",							eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
///	{"MACAddressControlEnabled",			eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
	{"Standard",							eCWMP_tSTRING,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
//	{"WEPEncryptionLevel",					eCWMP_tSTRING,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
//	{"BasicAuthenticationMode",				eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
//	{"IEEE11iEncryptionModes",				eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
//	{"IEEE11iAuthenticationMode",			eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
//	{"PossibleChannels",					eCWMP_tSTRING,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
//	{"BasicDataTransmitRates",				eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
//	{"OperationalDataTransmitRates",		eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
//	{"PossibleDataTransmitRates",			eCWMP_tSTRING,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
//	{"InsecureOOBAccessEnabled",			eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
//	{"BeaconAdvertisementEnabled",			eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
///	{"RadioEnabled",						eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
///	{"AutoRateFallBackEnabled",				eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
///	{"LocationDescription",					eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
//	{"RegulatoryDomain",					eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
//	{"TotalPSKFailures",					eCWMP_tUINT,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
//	{"TotalIntegrityFailures",				eCWMP_tUINT,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
//	{"ChannelsInUse",						eCWMP_tSTRING,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
//	{"DeviceOperationMode",					eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
//	{"DistanceFromRoot",					eCWMP_tUINT,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
//	{"PeerBSSID",							eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
//	{"AuthenticationServiceMode",			eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
	{"TotalPacketsSent",					eCWMP_tUINT,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
	{"TotalPacketsReceived",				eCWMP_tUINT,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
	{"TotalAssociations",					eCWMP_tUINT,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
///	{"Name",								eCWMP_tSTRING,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
	{"AutoChannelEnable",					eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
///	{"SSIDAdvertisementEnabled",			eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
///	{"TransmitPowerSupported",				eCWMP_tSTRING,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
///	{"TransmitPower",						eCWMP_tUINT,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
///	{"WMMSupported",						eCWMP_tBOOLEAN,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
///	{"UAPSDSupported",						eCWMP_tBOOLEAN,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
///	{"WMMEnable",							eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
///	{"UAPSDEnable",							eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
///	{"InterferenceMitigation",				eCWMP_tUINT,	CWMP_WRITE|CWMP_READ,	NULL,		get_WLANConf,		set_WLANConf,	NULL,		NULL},
///	{"APWMMParameterNumberOfEntries",		eCWMP_tUINT,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
///	{"STAWMMParameterNumberOfEntries",		eCWMP_tUINT,	CWMP_READ,				NULL,		get_WLANConf,		NULL,			NULL,		NULL},
///	{"WPS",									eCWMP_tOBJECT,	CWMP_READ,				NULL,		NULL,				NULL,			tWPS,		NULL},
///TODO	{"Stats",								eCWMP_tOBJECT,	CWMP_READ|CWMP_WRITE,	NULL,		NULL,							NULL,							tStats,		NULL},
	{"",									eCWMP_tNONE,	0,						NULL,		NULL,				NULL,			NULL,		NULL}
};

struct sCWMP_ENTITY	tWLANMAP[] = {
	{"0",						eCWMP_tOBJECT,	CWMP_READ|CWMP_WRITE|CWMP_LNKLIST,	NULL,		NULL,				NULL,			tWLANConf,	NULL},
	{"", eCWMP_tNONE, 0, NULL, NULL, NULL, NULL, NULL}
};

struct sCWMP_ENTITY tFWinodw[] = {
	{"first_window_url_acsconfig",			eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_fWindowConf,	set_fWindowConf,	NULL,		NULL},
	{"first_window_url",					eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_fWindowConf,	set_fWindowConf,	NULL,		NULL},
	{"first_window_function",				eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_fWindowConf,	set_fWindowConf,	NULL,		NULL},
	{"",									eCWMP_tNONE,	0,						NULL,		NULL,				NULL,			NULL,		NULL}
};

#if 0
void dv_wps_pbc_start(char *intf)
{
	#warning dv_wps_pbc_start should be implemented.
}
#endif

//APACRTL-602
static int rate_limit_set_count = 0;

void reset_rate_limit_set_count(void)
{
	rate_limit_set_count = 0;
}

int get_rate_limit_set_count(void)
{
	return rate_limit_set_count;
}

int WLANConfObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	unsigned int i;
	switch(type) {
	case eCWMP_tINITOBJ:
	{
		int max_wlan=MAXIDX*MAXSUBIDX;
		int ret;
		struct sCWMP_ENTITY **c = (struct sCWMP_ENTITY **)data;

		for(i=0; i < max_wlan; i++) {
			ret = create_Object(c, tWLANMAP, sizeof(tWLANMAP), 1, i+1);
			if (ret < 0)
				break;
		}
		add_objectNum(name, i);
		init_wl_ratelimit_t();
		return 0;
	}
	case eCWMP_tADDOBJ:
		return 0;
	case eCWMP_tDELOBJ:
		return 0;
	case eCWMP_tUPDATEOBJ:
		return 0;
	default:
		break;
	}

	return -1;
}

int get_WLANConf(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	char *ptr, *del="WLANConfiguration.";
	char buf[256] = {0, };
	int idx = 0, wl_idx = 0, wl_subidx = 0;
	int res = 0;

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	ptr = strstr(name, del);
	if (ptr && STRLEN(ptr)>STRLEN(del)) {
		ptr += STRLEN(del);
		idx = atoi(ptr);
	}

	if (idx <= 0 || idx > MAX_WLAN)
		return ERR_9005;

	get_wlan_idxes(idx, &wl_idx, &wl_subidx);

	if (!nv_strcmp(lastname, "Enable")) {
		res = get_ssid_enable(wl_idx, wl_subidx);
		*data = booldup( res );

	} else if (!nv_strcmp(lastname, "Status")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "BSSID")) {
		get_bssid(buf, sizeof(buf), wl_idx, wl_subidx);
		*data = strdup( (char*)buf );

	} else if (!nv_strcmp(lastname, "MaxBitRate")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "SSID")) {
		char enc_buf[1024] = {0, };
		get_ssid(enc_buf, sizeof(enc_buf), wl_idx, wl_subidx);
		*data = strdup(enc_buf);

	} else if (!nv_strcmp(lastname, "BeaconType")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_BEACONTYPE, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );

	} else if (!nv_strcmp(lastname, "MACAddressControlEnabled")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "Standard")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_STANDARD, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );

	} else if (!nv_strcmp(lastname, "WEPKeyIndex")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "WEPEncryptionLevel")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "KeyPassphrase")) {
		char enc_buf[1024] = {0, };
		get_ssid_encryptionkey(enc_buf, sizeof(enc_buf), wl_idx, wl_subidx);
		*data = strdup(enc_buf);

	}
#if 0
	else if (!nv_strcmp(lastname, "BasicEncryptionModes")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_BASIC_ENCRYPT_MODES, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	} else if (!nv_strcmp(lastname, "BasicAuthenticationMode")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_BASIC_AUTH_MODE, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	} else if (!nv_strcmp(lastname, "WPAEncryptionModes")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_WPA_ENCRYPT_MODES, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	} else if (!nv_strcmp(lastname, "WPAAuthenticationMode")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_WPA_AUTH_MODE, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	} else if (!nv_strcmp(lastname, "IEEE11iEncryptionModes")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_IEEE11I_ENCTYPT_MODES, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	} else if (!nv_strcmp(lastname, "IEEE11iAuthenticationMode")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_IEEE11I_AUTH_MODES, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}
#endif
/*
	else if (!nv_strcmp(lastname, "PossibleChannels")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_POSSIBLE_CHANNELS, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	} else if (!nv_strcmp(lastname, "BasicDataTransmitRates")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_BASIC_DATA_TRANSMIT_RATES, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	} else if (!nv_strcmp(lastname, "OperationalDataTransmitRates")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_OPERATION_DATA_TRANSMIT_RATES, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	} else if (!nv_strcmp(lastname, "PossibleDataTransmitRates")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_POSSIBLE_DATA_TRANSMIT_RATES, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	} else if (!nv_strcmp(lastname, "InsecureOOBAccessEnabled")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_INSECURE_OOB_ACCESS_ENABLED, (void*)buf, sizeof(buf));
		*data = booldup( (char*)buf );
	} else if (!nv_strcmp(lastname, "BeaconAdvertisementEnabled")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_BEACON_ADVERTISE_ENABLED, (void*)buf, sizeof(buf));
		*data = booldup( (char*)buf );
	}
*/
	else if (!nv_strcmp(lastname, "RadioEnabled")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "AutoRateFallBackEnabled")) {
		empty_data(*type, data);
	}
#if 0
	else if (!nv_strcmp(lastname, "LocationDescription")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "RegulatoryDomain")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "TotalPSKFailures")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "TotalIntegrityFailures")) {
		empty_data(*type, data);
	}
/*
	else if (!nv_strcmp(lastname, "ChannelsInUse")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_CHANNEL_IN_USE, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}
*/
	else if (!nv_strcmp(lastname, "DeviceOperationMode")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "DistanceFromRoot")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "PeerBSSID")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "AuthenticationServiceMode")) {
		empty_data(*type, data);
	}
#endif
	else if (!nv_strcmp(lastname, "TotalBytesSent")) {
		unsigned int val;

		val = get_wl_traffic(wl_idx, wl_subidx, 1);
		*data = uintdup(val);

	} else if (!nv_strcmp(lastname, "TotalBytesReceived")) {
		unsigned int val;

		val = get_wl_traffic(wl_idx, wl_subidx, 0);
		*data = uintdup(val);

	} else if (!nv_strcmp(lastname, "TotalPacketsSent")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_TOTAL_PACKETS_SENT, (void*)buf, sizeof(buf));
		*data = uintdup( (char*)buf );

	} else if (!nv_strcmp(lastname, "TotalPacketsReceived")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_TOTAL_PACKETS_RECEIVED, (void*)buf, sizeof(buf));
		*data = uintdup( (char*)buf );

	} else if (!nv_strcmp(lastname, "TotalAssociations")) {
		cwmp_cfg_get(CWMP_WLAN_CONF_TOTAL_ASSOCIATIONS, (void*)buf, sizeof(buf));
		*data = uintdup( (char*)buf );

	} else if (!nv_strcmp(lastname, "Name")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "AutoChannelEnable")) {
		*data = booldup(get_auto_chan_use(wl_idx));

	} else if (nv_strcmp(lastname, "Channel")) {
		*data = uintdup(get_current_channel(wl_idx));

	} else if (!nv_strcmp(lastname, "TransmitPowerSupported")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "TransmitPower")) {
		empty_data(*type, data);
	}
#if 0
	else if (!nv_strcmp(lastname, "SSIDAdvertisementEnabled")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "WMMSupported")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "UAPSDSupported")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "WMMEnable")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "UAPSDEnable")) {
		empty_data(*type, data);
	}
#endif
	else if (!nv_strcmp(name, "AssociatedDeviceNumberOfEntries"))
	{
		res = get_wl_client_info(wl_idx, wl_subidx);
		*data = uintdup(res);
	}
#if 0
	else if (!nv_strcmp(lastname, "APWMMParameterNumberOfEntries")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "STAWMMParameterNumberOfEntries")) {
		empty_data(*type, data);
	}
#endif
	else if (!nv_strcmp(lastname, "InterferenceMitigation")) {
		empty_data(*type, data);
	} else
		return ERR_9005;

	return 0;
}

int set_WLANConf(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char    *lastname = entity->name;
	char    *buf=data, *ptr, tmp[256];
	int     len=0;
	int idx=0, wl_idx, wl_subidx;
	int res;

	if( (name==NULL) || (data==NULL) || (entity==NULL)) return -1;
	if( entity->type!=type ) return ERR_9006;

	snprintf(tmp, sizeof(tmp), "%s", name);
	ptr = strrchr(tmp, '.');
	if (ptr)
		*ptr = 0;

	ptr = strrchr(tmp, '.');
	if (ptr && STRLEN(ptr) > 1)
		idx = atoi(ptr+1);

	if (idx <= 0 || idx > MAX_WLAN)
		return ERR_9005;

	get_wlan_idxes(idx, &wl_idx, &wl_subidx);

	if (!nv_strcmp(lastname, "Enable")) {
		if (IS_BRIDGE_MODE && wl_subidx > -1)
			return 0;
		return set_ssid_enable(*(int *)buf, wl_idx, wl_subidx);

	} else if (!nv_strcmp(lastname, "MaxBitRate")) {
	} else if (!nv_strcmp(lastname, "Channel")) {
		return set_wifi_chan(*(int *)buf, wl_idx);

	} else if (!nv_strcmp(lastname, "SSID")) {
		if( buf ) len = STRLEN( buf );
		if( len> 0 && len < 64 )
			return set_ssid(buf, wl_idx, wl_subidx);
		else
			return ERR_9007;
		return 0;

	} else if (!nv_strcmp(lastname, "BeaconType")) {
		return 0;

	} else if (!nv_strcmp(lastname, "MACAddressControlEnabled")) {
	} else if (!nv_strcmp(lastname, "KeyPassphrase")) {
		return set_ssid_encryptionkey(buf, wl_idx, wl_subidx);	//APACRTL-452

	}
#if 0
	else if (!nv_strcmp(lastname, "WEPKeyIndex")) {
	} else if (!nv_strcmp(lastname, "BasicEncryptionModes")) {
	} else if (!nv_strcmp(lastname, "BasicAuthenticationMode")) {
	} else if (!nv_strcmp(lastname, "WPAEncryptionModes")) {
	} else if (!nv_strcmp(lastname, "WPAAuthenticationMode")) {
	} else if (!nv_strcmp(lastname, "IEEE11iEncryptionModes")) {
	} else if (!nv_strcmp(lastname, "IEEE11iAuthenticationMode")) {
	} else if (!nv_strcmp(lastname, "BasicDataTransmitRates")) {
	} else if (!nv_strcmp(lastname, "OperationalDataTransmitRates")) {
	} else if (!nv_strcmp(lastname, "InsecureOOBAccessEnabled")) {
	} else if (!nv_strcmp(lastname, "BeaconAdvertisementEnabled")) {
	} else if (!nv_strcmp(lastname, "RadioEnabled")) {
	} else if (!nv_strcmp(lastname, "AutoRateFallBackEnabled")) {
	} else if (!nv_strcmp(lastname, "LocationDescription")) {
	} else if (!nv_strcmp(lastname, "RegulatoryDomain")) {
	} else if (!nv_strcmp(lastname, "DeviceOperationMode")) {
	} else if (!nv_strcmp(lastname, "DistanceFromRoot")) {
	} else if (!nv_strcmp(lastname, "PeerBSSID")) {
	}
#endif
	else if (!nv_strcmp(lastname, "AutoChannelEnable")) {
		res = set_auto_chan_use(*(int *)buf, wl_idx);
		return res;
	}
#if 0
	else if (!nv_strcmp(lastname, "AuthenticationServiceMode")) {
	} else if (!nv_strcmp(lastname, "SSIDAdvertisementEnabled")) {
	}
#endif
	else if (!nv_strcmp(lastname, "TransmitPower")) {
	} else if (!nv_strcmp(lastname, "TransmitPowerSupported")) {
	} else if (!nv_strcmp(lastname, "WMMEnable")) {
	} else if (!nv_strcmp(lastname, "UAPSDEnable")) {
	} else if (!nv_strcmp(lastname, "InterferenceMitigation")) {
	} else
		return ERR_9005;

	return 0;
}

int get_fWindowConf(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	char buf[128] = {0, }, *ptr, tmp[256] = {0, };
	char *del="WLANConfiguration.";
	int idx = 0, wl_idx = 0, wl_subidx = 0;

	if( (name==NULL) || (type==NULL)|| (data==NULL) || (entity==NULL)) return -1;

	snprintf(tmp, sizeof(tmp), "%s", name);
	ptr = strstr(tmp, del);
	if (ptr && STRLEN(ptr)> STRLEN(del)) {
		ptr += STRLEN(del);
		idx = atoi(ptr);
	}

	if (idx <= 0 || idx > MAX_WLAN)
		return ERR_9005;

	*type = entity->type;

	get_wlan_idxes(idx, &wl_idx, &wl_subidx);

	if (!nv_strcmp(lastname, "first_window_url_acsconfig")) {
		nvram_safe_get_r("acs_dv_fwindow_url", buf, sizeof(buf));
		*data = strdup(buf);
	} else if (!nv_strcmp(lastname, "first_window_url")) {
		get_first_window_url(buf, sizeof(buf), wl_idx, wl_subidx);
		*data = strdup(buf);
	} else if (!nv_strcmp(lastname, "first_window_function")) {
		get_first_window(buf, sizeof(buf), wl_idx, wl_subidx);
		*data = strdup(buf);
	} else {
		return ERR_9005;
	}

	return 0;
}

int set_fWindowConf(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char *lastname = entity->name;
	char *buf=data, *ptr, tmp[256] = {0, };
	char *del="WLANConfiguration.";
	int idx = 0, wl_idx = 0, wl_subidx = 0;

	if( (name==NULL) || (data==NULL) || (entity==NULL)) return -1;
	if( entity->type!=type ) return ERR_9006;

	snprintf(tmp, sizeof(tmp), "%s", name);
	ptr = strstr(tmp, del);
	if (ptr && STRLEN(ptr)> STRLEN(del)) {
		ptr += STRLEN(del);
		idx = atoi(ptr);
	}
	if (idx <= 0 || idx > MAX_WLAN)
		return ERR_9005;

	get_wlan_idxes(idx, &wl_idx, &wl_subidx);

	if (!nv_strcmp(lastname, "first_window_url")) {
		if (wl_subidx == -1)
			snprintf(tmp, sizeof(tmp), "WLAN%d_dv_fwindow_url", wl_idx);
		else
			snprintf(tmp, sizeof(tmp), "WLAN%d_VAP%d_dv_fwindow_url", wl_idx, wl_subidx);

		nvram_set(tmp, buf);
		return 1;
	} else if (!nv_strcmp(lastname, "first_window_function")) {
		if (nv_strcmp(buf, "0")&&nv_strcmp(buf, "1")&&nv_strcmp(buf, "2"))
			return ERR_9007;

		if (wl_subidx == -1)
			snprintf(tmp, sizeof(tmp), "WLAN%d_dv_fwindow", wl_idx);
		else
			snprintf(tmp, sizeof(tmp), "WLAN%d_VAP%d_dv_fwindow", wl_idx, wl_subidx);

		nvram_set(tmp, buf);
		return 1;
	} else {
		return ERR_9005;
	}

	return 0;
}
#endif /* __PRMT_WLANCONF_C__ */
