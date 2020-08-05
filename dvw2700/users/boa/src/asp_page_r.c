
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>		//davidhsu
#include <stdarg.h>
#include "boa.h"

#ifdef SUPPORT_ASP

#include "asp_page.h"
#include "apmib.h"
#include "apform.h"

#ifdef SUPER_NAME_SUPPORT
#include "auth.h"
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <alloca.h>
#include <libytool.h>

char *WAN_IF;
char *BRIDGE_IF;
char *ELAN_IF;
char *ELAN2_IF;
char *ELAN3_IF;
char *ELAN4_IF;
char *PPPOE_IF;
char WLAN_IF[20];
int wlan_num;
#ifdef MBSSID
int vwlan_num = 0;
int mssid_idx = 0;
#endif

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
static asp_name_t root_asp[] = {
	{"getInfo", getInfo},
	{"getIndex", getIndex},
#ifdef MULTI_WAN_SUPPORT
	{"getMultiWanIndex", getMultiWanIndex},
	{"getWanList", getWanList},
	{"getWanStatusList", getWanStatusList},
	{"getWanStatsList", getWanStatsList},
#endif
#ifdef GET_LAN_DEV_INFO_SUPPORT
	{"showClients", showClients},
#endif
#if defined(CONFIG_RTL_P2P_SUPPORT)
	{"getWifiP2PState", getWifiP2PState},
	{"wlP2PScanTbl", wlP2PScanTbl},
#endif
	{"wirelessClientList", wirelessClientList},
	{"wlSiteSurveyTbl", wlSiteSurveyTbl},
	{"wlWdsList", wlWdsList},
#if defined(WLAN_PROFILE)
	{"wlProfileList", wlProfileList},
	{"wlProfileTblList", wlProfileTblList},
#endif				//#if defined(WLAN_PROFILE)
	{"wdsList", wdsList},
#ifdef MBSSID
	{"getVirtualIndex", getVirtualIndex},
	{"getVirtualInfo", getVirtualInfo},
#endif
#if defined(NEW_SCHEDULE_SUPPORT)
	{"wlSchList", wlSchList},
#endif
	{"getScheduleInfo", getScheduleInfo},
	{"wlAcList", wlAcList},
	//modify by nctu
	{"getModeCombobox", getModeCombobox},
	{"getDHCPModeCombobox", getDHCPModeCombobox},
#ifdef CONFIG_RTL_AIRTIME
	{"airTimeList", airTimeList},
#endif
#ifdef CONFIG_RTK_MESH
#ifdef _MESH_ACL_ENABLE_
	{"wlMeshAcList", wlMeshAcList},
#endif
	{"wlMeshNeighborTable", wlMeshNeighborTable},
	{"wlMeshRoutingTable", wlMeshRoutingTable},
	{"wlMeshProxyTable", wlMeshProxyTable},
	{"wlMeshRootInfo", wlMeshRootInfo},
	{"wlMeshPortalTable", wlMeshPortalTable},
#endif
#ifdef TLS_CLIENT
	{"certRootList", certRootList},
	{"certUserList", certUserList},
#endif
	{"dhcpClientList", dhcpClientList},
	{"dhcpRsvdIp_List", dhcpRsvdIp_List},
#ifdef FAST_BSS_TRANSITION
	{"multilang", multilang},
	{"SSID_select", SSID_select},
	{"wlFtKhList", wlFtKhList},
#endif
#if defined(POWER_CONSUMPTION_SUPPORT)
	{"getPowerConsumption", getPowerConsumption},
#endif
#if defined(VLAN_CONFIG_SUPPORTED)
	{"getVlanList", getVlanList},
#endif
#if defined(CONFIG_8021Q_VLAN_SUPPORTED)
	{"getVlanInfo", getVlanInfo},
	{"getPortList", getPortList},
	{"getWlanValid", getWlanValid},
	{"getVlanTable", getVlanTable},
	{"getPVidArray", getPVidArray},
#endif
#ifdef HOME_GATEWAY
#if 0				//sc_yang
	{"showWanPage", showWanPage},
#endif
	{"portFwList", portFwList},
	{"ipFilterList", ipFilterList},
	{"portFilterList", portFilterList},
	{"macFilterList", macFilterList},
	{"urlFilterList", urlFilterList},
	//{"triggerPortList", triggerPortList},
#ifdef ROUTE_SUPPORT
	{"staticRouteList", staticRouteList},
	{"kernelRouteList", kernelRouteList},
#ifdef RIP6_SUPPORT
	{"kernelRoute6List", kernelRoute6List},
#endif
#endif
#if defined(GW_QOS_ENGINE)
	{"qosList", qosList},
#elif defined(QOS_BY_BANDWIDTH)
	{"ipQosList", ipQosList},
	{"l7QosList", l7QosList},
#endif
#ifdef CONFIG_IPV6
	{"getIPv6Info", getIPv6Info},
	{"getIPv6WanInfo", getIPv6WanInfo},
	{"getIPv6Status", getIPv6Status},
	{"getIPv6BasicInfo", getIPv6BasicInfo},
#endif
#if defined(WLAN_PROFILE)
	{"getWlProfileInfo", getWlProfileInfo},
#endif
#endif				//HOME_GATEWAY
	{"sysLogList", sysLogList},
	{"sysCmdLog", sysCmdLog},
#ifdef CONFIG_APP_TR069
	{"TR069ConPageShow", TR069ConPageShow},
#endif
#ifdef HTTP_FILE_SERVER_SUPPORTED
	{"dump_directory_index", dump_directory_index},
	{"Check_directory_status", Check_directory_status},
	{"Upload_st", Upload_st},
#ifdef HTTP_FILE_SERVER_HTM_UI
	{"dump_httpFileDir_init", dump_httpFileDir_init},
	{"dump_ListHead", dump_ListHead},
	{"dumpDirectList", dumpDirectList},
	{"dump_uploadDiv", dump_uploadDiv},
#endif
#endif
#ifdef VOIP_SUPPORT
	{"voip_general_get", asp_voip_GeneralGet},
	{"voip_dialplan_get", asp_voip_DialPlanGet},
	{"voip_tone_get", asp_voip_ToneGet},
	{"voip_ring_get", asp_voip_RingGet},
	{"voip_other_get", asp_voip_OtherGet},
	{"voip_config_get", asp_voip_ConfigGet},
	{"voip_fwupdate_get", asp_voip_FwupdateGet},
	{"voip_net_get", asp_voip_NetGet},
#ifdef CONFIG_RTK_VOIP_SIP_TLS
	{"voip_TLSGetCertInfo", asp_voip_TLSGetCertInfo},
#endif
#endif
#ifdef SAMBA_WEB_SUPPORT
	{"DiskList", DiskList},
	{"Storage_DispalyUser", Storage_DispalyUser},
	{"Storage_DispalyGroup", Storage_DispalyGroup},
	{"Storage_GetGroupMember", Storage_GetGroupMember},
	//{"Storage_CreateFolder",Storage_CreateFolder},
	{"FolderList", FolderList},
	{"ShareFolderList", ShareFolderList},
	{"Storage_GeDirRoot", Storage_GeDirRoot},
	{"UserEditName", UserEditName},
	{"GroupEditName", GroupEditName},
	{"StorageGetFolderPath", StorageGetFolderPath},
	{"StorageGetAccount", StorageGetAccount},
	{"PartitionsList", PartitionsList},
	{"getDiskInfo", getDiskInfo},
	{"PartitionList", PartitionList},
#endif
#if defined(CONFIG_RTL_ETH_802DOT1X_SUPPORT)
	{"getEthDot1xList", getEthDot1xList},
#endif
#if defined(CONFIG_APP_ZIGBEE)
	{"zigbee_dev_list", zigbee_dev_list},
#endif
#if defined(__DAVO__)
	{"showAutoUpState", showAutoUpState},
	{"captcha_img", captcha_img},
	{"showConnectVoIPtbl", showConnectVoIPtbl},
	{"show_acltbl", show_acltbl},
	{"print_wme_dscp", print_wme_dscp},
	{"show_ExceptionLog", show_ExceptionLog},
#endif
	{NULL, NULL}
};

static int asp_namcmp(asp_name_t *p1, asp_name_t *p2)
{
	return strcmp(p1->name, p2->name);
}

static void asp_namsort(void) __attribute__((unused));
static void __attribute__((constructor)) asp_namsort(void)
{
	qsort(root_asp, _countof(root_asp) - 1, sizeof(asp_name_t), (void *)asp_namcmp);
}

static asp_name_t *aspfunc(char *name, size_t length)
{
	char buf[length + 1];
	asp_name_t k;

	strncpy(buf, name, length);
	buf[length] = '\0';
	k.name = buf;
	return bsearch(&k, root_asp, _countof(root_asp) - 1,
	               sizeof(asp_name_t), (void *)asp_namcmp);
}

static form_name_t root_form[] = {
	{"formWlanSetup", formWlanSetup},
	{"formWlanRedirect", formWlanRedirect},
#if 0
	{"formWep64", formWep64},
	{"formWep128", formWep128},
#endif
	{"formWep", formWep},
#ifdef MBSSID
	{"formWlanMultipleAP", formWlanMultipleAP},
#endif
#ifdef CONFIG_RTL_AIRTIME
	{"formAirtime", formAirtime},
#endif
#ifdef CONFIG_RTK_MESH
	{"formMeshSetup", formMeshSetup},
	{"formMeshProxy", formMeshProxy},
	//{"formMeshProxyTbl", formMeshProxyTbl},
	{"formMeshStatus", formMeshStatus},
#ifdef _MESH_ACL_ENABLE_
	{"formMeshACLSetup", formMeshACLSetup},
#endif
#endif
	{"formTcpipSetup", formTcpipSetup},
	{"formPasswordSetup", formPasswordSetup},
	{"formLogout", formLogout},
	{"formUpload", formUpload},
#if defined(CONFIG_USBDISK_UPDATE_IMAGE)
	{"formUploadFromUsb", formUploadFromUsb},
#endif
#ifdef CONFIG_RTL_WAPI_SUPPORT
	{"formWapiReKey", formWapiReKey},
	{"formUploadWapiCert", formUploadWapiCert},
	{"formUploadWapiCertAS0", formUploadWapiCertAS0},
	{"formUploadWapiCertAS1", formUploadWapiCertAS1},
	{"formWapiCertManagement", formWapiCertManagement},
	{"formWapiCertDistribute", formWapiCertDistribute},
#endif
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
	{"formUpload8021xUserCert", formUpload8021xUserCert},
#endif
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
	{"formUploadEth8021xUserCert", formUploadEth8021xUserCert},
#endif
#if defined(CONFIG_RTL_ETH_802DOT1X_SUPPORT)
	{"formEthDot1x", formEthDot1x},
#endif
#ifdef TLS_CLIENT
	{"formCertUpload", formCertUpload},
#endif
	{"formWlAc", formWlAc},
	{"formAdvanceSetup", formAdvanceSetup},
	{"formReflashClientTbl", formReflashClientTbl},
	{"formWlEncrypt", formWlEncrypt},
	{"formStaticDHCP", formStaticDHCP},
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(CONFIG_RTL_8881A_SELECTIVE)
	{"formWlanBand2G5G", formWlanBand2G5G},
#endif
#ifdef FAST_BSS_TRANSITION
	{"formFt", formFt},
#endif
#if defined(VLAN_CONFIG_SUPPORTED)
	{"formVlan", formVlan},
#endif
#if defined(CONFIG_8021Q_VLAN_SUPPORTED)
	{"formVlan", formVlan},
#endif
#ifdef HOME_GATEWAY
#if defined(CONFIG_RTK_VLAN_WAN_TAG_SUPPORT)
	{"formVlanWAN", formVlanWAN},
#endif
#ifdef MULTI_WAN_SUPPORT
	{"formMultiWanListTcpip", formMultiWanListTcpip},
	{"formMultiWanTcpipSetup", formMultiWanTcpipSetup},
#else
	{"formWanTcpipSetup", formWanTcpipSetup},
#endif
#ifdef ROUTE_SUPPORT
	{"formRoute", formRoute},
#endif
	{"formPortFw", formPortFw},
	{"formFilter", formFilter},
	//{"formTriggerPort", formTriggerPort},
	{"formDMZ", formDMZ},
	{"formDdns", formDdns},
#ifdef CONFIG_APP_OPENVPN
	{"formOpenvpn", formOpenvpn},
	{"formSaveOpenvpnClientConfig", formSaveOpenvpnClientConfig},
#endif
	{"formOpMode", formOpMode},
#if defined(CONFIG_RTL_ULINKER)
	{"formUlkOpMode", formUlkOpMode},
#endif
#if defined(CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE)
	{"formDualFirmware", formDualFirmware},
#endif
#if defined(GW_QOS_ENGINE)
	{"formQoS", formQoS},
#elif defined(QOS_BY_BANDWIDTH)
	{"formIpQoS", formIpQoS},
#endif
#ifdef CONFIG_RTL_BT_CLIENT
	{"formBTBasicSetting", formBTBasicSetting},
	{"formBTClientSetting", formBTClientSetting},
	{"formBTFileSetting", formBTFileSetting},
	{"formBTNewTorrent", formBTNewTorrent},
#endif
#ifdef CONFIG_RTL_TRANSMISSION
	{"formTransmissionBT", formTransmissionBT},
#endif
#ifdef DOS_SUPPORT
	{"formDosCfg", formDosCfg},
#endif
#ifdef CONFIG_IPV6
	{"formRadvd", formRadvd},
#ifdef CONFIG_APP_RADVD_WAN
	{"formRadvd_wan", formRadvd_wan},
#endif
	{"formDnsv6", formDnsv6},
	{"formDhcpv6s", formDhcpv6s},
	{"formIPv6Addr", formIPv6Addr},
	{"formIpv6Setup", formIpv6Setup},
	{"formTunnel6", formTunnel6},
#ifdef CONFIG_MAP_E_SUPPORT
	{"formMapE", formMapE},
#endif
#endif
#else
	{"formSetTime", formSetTime},
#endif				//HOME_GATEWAY
	// by sc_yang
	{"formNtp", formNtp},
	{"formWizard", formWizard},
	{"formPocketWizard", formPocketWizard},
#ifdef REBOOT_CHECK
	{"formRebootCheck", formRebootCheck},
#if defined(WLAN_PROFILE)
	{"formSiteSurveyProfile", formSiteSurveyProfile},
#endif			//#if defined(WLAN_PROFILE)
#endif
	{"formSysCmd", formSysCmd},
	{"formSysLog", formSysLog},
#ifdef SYS_DIAGNOSTIC
	{"formDiagnostic", formDiagnostic},
#endif
#ifdef CONFIG_APP_SMTP_CLIENT
	{"formSmtpClient", formSmtpClient},
#endif
#if defined(CONFIG_SNMP)
	{"formSetSNMP", formSetSNMP},
#endif
	{"formSaveConfig", formSaveConfig},
	{"formUploadConfig", formUploadConfig},
	{"formSchedule", formSchedule},
#if defined(NEW_SCHEDULE_SUPPORT)
	{"formNewSchedule", formNewSchedule},
#endif
#if defined(CONFIG_RTL_P2P_SUPPORT)
	{"formWiFiDirect", formWiFiDirect},
	{"formWlP2PScan", formWlP2PScan},
#endif
	{"formWirelessTbl", formWirelessTbl},
	{"formStats", formStats},
	{"formWlSiteSurvey", formWlSiteSurvey},
	{"formWlWds", formWlWds},
	{"formWdsEncrypt", formWdsEncrypt},
#ifdef WLAN_EASY_CONFIG
	{"formAutoCfg", formAutoCfg},
#endif
#ifdef WIFI_SIMPLE_CONFIG
	{"formWsc", formWsc},
#endif
#ifdef CONFIG_APP_TR069
	{"formTR069Config", formTR069Config},
#ifdef _CWMP_WITH_SSL_

	{"formTR069CPECert", formTR069CPECert},
	{"formTR069CACert", formTR069CACert},
#endif
#endif
#ifdef HTTP_FILE_SERVER_SUPPORTED
	{"formusbdisk_uploadfile", formusbdisk_uploadfile},
#endif
#ifdef VOIP_SUPPORT
	{"voip_general_set", asp_voip_GeneralSet},
	{"voip_dialplan_set", asp_voip_DialPlanSet},
	{"voip_tone_set", asp_voip_ToneSet},
	{"voip_ring_set", asp_voip_RingSet},
	{"voip_other_set", asp_voip_OtherSet},
	{"voip_config_set", asp_voip_ConfigSet},
	{"voip_fw_set", asp_voip_FwSet},
	{"voip_net_set", asp_voip_NetSet},
#ifdef CONFIG_RTK_VOIP_IVR
	{"voip_ivrreq_set", asp_voip_IvrReqSet},
#endif
#ifdef CONFIG_RTK_VOIP_SIP_TLS
	{voip_TLSCertUpload, asp_voip_TLSCertUpload},
#endif
#endif

#ifdef SAMBA_WEB_SUPPORT
	{"formDiskCfg", formDiskCfg},

	{"formDiskManagementAnon", formDiskManagementAnon},
	{"formDiskManagementUser", formDiskManagementUser},
	{"formDiskManagementGroup", formDiskManagementGroup},

	{"formDiskCreateUser", formDiskCreateUser},
	{"formDiskCreateGroup", formDiskCreateGroup},
	{"formDiskEditUser", formDiskEditUser},
	{"formDiskEditGroup", formDiskEditGroup},

	{"formDiskCreateShare", formDiskCreateShare},
	{"formDiskCreateFolder", formDiskCreateFolder},
	{"formDiskFormat", formDiskFormat},
	{"formDiskPartition", formDiskPartition},
#endif

#ifdef CONFIG_CPU_UTILIZATION
	{"formCpuUtilization", formCpuUtilization},
#endif
#ifdef CONFIG_APP_WEAVE
	{"formWeave", formWeave},
#endif
#ifdef CONFIG_APP_ZIGBEE
	{"formZigBee", formZigBee},
#endif
#if defined(__DAVO__)
	{"formFtpUpload", formFtpUpload},
	{"formautoupgrade", formautoupgrade},
	{"formPortMirror", formPortMirror},
	{"formSNMP", formSNMP},
	{"formLogin", formLogin},
	{"formDiagnostic_ping", formDiagnostic_ping},
	{"formBroadcastStormCtrl", formBroadcastStormCtrl},
	{"formPortSetup", formPortSetup},
	{"formWebAcl", formWebAcl},
	{"formConnectVoIP", formConnectVoIP},
	{"formMacFilter", formMacFilter},
	{"formAclSetup", formAclSetup},
	{"formQosQue", formQosQue},
	{"formRemark", formRemark},
	{"formWanIpRenewal", formWanIpRenewal},
	{"formWlwmm", formWlwmm},
	{"formMfgTest", formMfgTest},
#endif
	{NULL, NULL}
};

static int form_namcmp(form_name_t *p1, form_name_t *p2)
{
	return strcmp(p1->name, p2->name);
}

static void form_namsort(void) __attribute__((unused));
static void __attribute__((constructor)) form_namsort(void)
{
	qsort(root_form, _countof(root_form) - 1, sizeof(form_name_t), (void *)form_namcmp);
}

static form_name_t *formfunc(char *name)
{
	form_name_t k = { .name = name };
	return bsearch(&k, root_form, _countof(root_form) - 1,
	               sizeof(form_name_t), (void *)form_namcmp);
}

#ifdef CSRF_SECURITY_PATCH
#include <time.h>

#define EXPIRE_TIME LOGIN_MAX_TIME
#define MAX_TBL_SIZE 10

struct goform_entry {
	int valid;
	unsigned int hash_id;
	char name[80];
	time_t time;
};

struct goform_entry security_tbl[MAX_TBL_SIZE] = { {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0} };

static inline unsigned int jshash(char *s)
{
	unsigned int hash = 1315423911;
	int c;
	while ((c = *s++))
		hash ^= ((hash << 5) + c + (hash >> 2));
	return hash;
}

static unsigned int rqst_hash(request *req)
{
	struct in_addr ip = { .s_addr = 0 };
	char buf[32], mac[20] = { [0] = '\0' };

	inet_aton(req->remote_ip_addr, &ip);
	if (get_clone_mac_by_ip(req->remote_ip_addr, mac) >= 0)
		sprintf(buf, "%s%08x", mac, ip.s_addr);
	else
		/* no arp. from ppp interface eg. assign a special mac */
		sprintf(buf, "%02x%02x%02x%02x%02x%02x%08x",
		        0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, ip.s_addr);
	return jshash(buf);
}

void log_boaform(char *form, request *req)
{
	int i, oldest = -1;
	time_t now = time(NULL);

	for (i = 0; i < MAX_TBL_SIZE; i++) {
		if (!security_tbl[i].valid ||
		    ((now - security_tbl[i].time) > EXPIRE_TIME) ||
		    !strcmp(form, security_tbl[i].name)) {
			break;
		} else if ((oldest == -1) ||
		           (security_tbl[i].time < security_tbl[oldest].time)) {
			oldest = i;
		}
	}

	if ((i < MAX_TBL_SIZE) || (i == MAX_TBL_SIZE && oldest != -1)) {
		if (i == MAX_TBL_SIZE)
			i = oldest;
		strlcpy(security_tbl[i].name, form, sizeof(security_tbl[0].name));
		security_tbl[i].hash_id = rqst_hash(req);
		security_tbl[i].time = now;
		security_tbl[i].valid = 1;
	}
}

static void delete_boaform(char *form)
{
	int i;
//for allow save config multi-times
	if (strcmp(form, "formSaveConfig") == 0)
		return;

#ifdef SYS_DIAGNOSTIC
	if (strcmp(form, "formDiagnostic") == 0)
		return;
#endif

	for (i = 0; i < MAX_TBL_SIZE; i++) {
		if (security_tbl[i].valid &&
		    !strcmp(form, security_tbl[i].name)) {
			security_tbl[i].valid = 0;
			break;
		}
	}
}

static int is_valid_boaform(char *form, request *req)
{
	int i, valid = 0;
	time_t t = time(NULL);

	/* iterate through all and age out */
	for (i = 0; i < MAX_TBL_SIZE; i++) {
		if (!security_tbl[i].valid)
			continue;
		else if ((t - security_tbl[i].time) > EXPIRE_TIME)
			security_tbl[i].valid = 0;
		else if (!valid && !strcmp(form, security_tbl[i].name) &&
		         security_tbl[i].hash_id == rqst_hash(req))
			valid = 1;
	}

	return valid ? : !!(!strcmp(form, "formSysLog") || !strcmp(form, "formLogin"));
}

static int is_any_log(void)
{
	int i;
	for (i = 0; i < MAX_TBL_SIZE; i++) {
		if (security_tbl[i].valid)
			return 1;
	}
	return 0;
}
#endif				// CSRF_SECURITY_PATCH

struct dstring {
	struct dstring *next;
	char value[0];
};

static struct dstring *dstring_top;

static int hhx(const char *p, unsigned int *dst)
{
	unsigned int val = 0;
	int c, i;

	for (i = 0; i < 2; i++) {
		c = *p++;
		if (isdigit(c))
			val = (val << 4) + (int)(c - '0');
		else if (isxdigit(c))
			val = (val << 4) | (int)(c + 10 - (islower(c) ? 'a' : 'A'));
		else
			return -1;
	}
	*dst = val;
	return 0;
}

static char *unescape(char *src)
{
	unsigned int c;
	char *p, *q, *s = src;

	while ((s = strpbrk(s, "%+"))) {
		/* Parse %xx */
		if (*s == '%') {
			hhx(s + 1, &c);
			*s++ = (char)c;
			for (p = s, q = s + 2; *q; *p++ = *q++);
			*p = '\0';
		}
		/* Space is special */
		else if (*s == '+')
			*s++ = ' ';
	}
	return src;
}

static void *memstr_cgi(const char *haystack, size_t haystacklen,
		const char *needle, int *len)
{
	register const char *ph, *p;
	const char *plast, *pend;
	unsigned int i, c;
	size_t needlelen = strlen(needle);

	if (haystacklen == 0) {
		if (needlelen)
			return NULL;
		else if (len)
			*len = 0;
		return (void *)haystack;
	}

	if (haystacklen >= needlelen) {
		ph = (const char *)haystack;
		plast = ph + (haystacklen - needlelen);
		pend = ph + haystacklen;
		do {
			for (i = 0, p = ph;; i++) {
				if (needle[i] == '\0') {
					if (len)
						*len = (int)(p - ph);
					return (char *)ph;
				}
				c = *p++;
				if (c == '%' && ((pend - p) > 1) && !hhx(p, &c))
					p += 2;
				else if (c == '+')
					c = ' ';
				if (needle[i] != (char)c)
					break;
			}
		} while (++ph <= plast);
	}
	return NULL;
}

/* unescape with allocated string */
static char *aunescape(const char *s, size_t len)
{
	struct dstring *p = malloc(sizeof(struct dstring) + len + 1);
	strlcpy(p->value, s, len + 1);
	p->next = dstring_top;
	dstring_top = p;
	return unescape(p->value);
}

void freeAllTempStr(void)
{
	while (dstring_top) {
		struct dstring *p = dstring_top;
		dstring_top = p->next;
		free(p);
	}
}

static char *asscan_cgi(char *query, size_t qlen, char *name)
{
	char *p, *q, *s;
	int len;

	if (!qlen || !query || !name || !name[0])
		return NULL;

	for (q = query; (p = memstr_cgi(q, qlen - (q - query), name, &len)); q += len) {
		if (p[len] == '=') {
			if ((p == query || p[-1] == '&')) {
				p += (len + 1);
				for (s = p; *s && *s != '&' && s < (query + qlen); s++) {}
				return aunescape(p, (size_t)(s - p));
			} else {
				for (q = p + len; *q != '&' && q < (query + qlen); q++) {}
				len = 0;
			}
		}
	}

	return NULL;
}

char *req_fget_cstream_var(request *req, const char *fmt, ...)
{
	va_list ap;
	char tmp[64];
	char *buf, *var, *p;
	int i;

	va_start(ap, fmt);
	var = yvasprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);

	if (req->method == M_POST) {
#ifndef NEW_POST
		struct stat statbuf;

		fstat(req->post_data_fd, &statbuf);
		buf = (char *)malloc(statbuf.st_size);
		if (buf == NULL)
			return (char *)defaultGetValue;
		lseek(req->post_data_fd, SEEK_SET, 0);
		read(req->post_data_fd, buf, statbuf.st_size);
		i = statbuf.st_size - 1;
#else
		buf = req->post_data;
		req->post_data_idx = 0;
		i = req->post_data_len - 1;
#endif
		/* strip trailing CRLF */
		while (i > 0 && ((buf[i] == 0x0a) || (buf[i] == 0x0d)))
			i--;
		i += 1;
	} else {
		buf = req->query_string;
		i = (buf) ? strlen(buf) : 0;
	}

	p = asscan_cgi(buf, i, var);

	if (var != tmp)
		free(var);

#ifndef NEW_POST
	if (req->method == M_POST)
		free(buf);
#endif
	return p;
}

char *req_get_cstream_var(request *req, char *var, char *dfl)
{
	return req_fget_cstream_var(req, "%s", var) ? : dfl;
}

void asp_init(int argc, char **argv)
{
	int i, num;
	char interface[16];
	extern int getWlStaNum(char *interface, int *num);

	// david ---- queury number of wlan interface ----------------
	wlan_num = 0;
	for (i = 0; i < NUM_WLAN_INTERFACE; i++) {
		sprintf(interface, "wlan%d", i);
		if (getWlStaNum(interface, &num) < 0)
			break;
		wlan_num++;
	}

#if defined(VOIP_SUPPORT) && defined(ATA867x)
	// no wlan interface in ATA867x
#else
	//      if (wlan_num==0)
	//      wlan_num = 1;   // set 1 as default
#endif

#ifdef MBSSID
	vwlan_num = NUM_VWLAN_INTERFACE;
#endif
	//---------------------------------------------------------

	if (apmib_init() == 0) {
		printf("Initialize AP MIB failed!%s:%d\n", __FUNCTION__, __LINE__);
		return;
	}
#ifndef SHRINK_INIT_TIME
	save_cs_to_file();
#endif
	/* determine interface name by mib value */
	WAN_IF = "eth1";
	BRIDGE_IF = "br0";
	ELAN_IF = "eth0";
	ELAN2_IF = "eth2";
	ELAN3_IF = "eth3";
	ELAN4_IF = "eth4";

#ifdef HOME_GATEWAY
	PPPOE_IF = "ppp0";
#elif defined(VOIP_SUPPORT) && defined(ATA867x)
	BRIDGE_IF = "eth0";
	ELAN_IF = "eth0";
#else
	BRIDGE_IF = "br0";
	ELAN_IF = "eth0";
#endif
	strcpy(WLAN_IF, "wlan0");
	//---------------------------
}

int update_content_length(request *req)
{
	char *e, *b, buf[32];
	int clen, n, hdrlen;
	char *s = memmem(req->buffer + req->buffer_start,
	                 req->buffer_end - req->buffer_start,
	                 "Content-Length:", sizeof("Content-Length:") - 1);
	if (s == NULL)
		return -1;
	e = memmem(s, req->buffer_end - (int)(s - req->buffer), "\r\n", 2);
	if (e == NULL)
		return -1;
	b = memmem(e, req->buffer_end - (int)(e - req->buffer), "\r\n\r\n", 4);
	if (b == NULL)
		return -1;

	clen = req->buffer_end - (int)(b - req->buffer) - 4;
	n = snprintf(buf, sizeof(buf), "Content-Length: %d", clen);
	hdrlen = (int)(e - s);
	if (n == hdrlen && !memcmp(s, buf, n))
		return 0;
	if ((hdrlen + req->buffer_start) >= n) {
		if (hdrlen != n)
			memmove(req->buffer + req->buffer_start + (hdrlen - n),
			        req->buffer + req->buffer_start,
			        (s - req->buffer) + req->buffer_start);
		req->buffer_start += (hdrlen - n);
		memcpy(s + (hdrlen - n), buf, n);
	} else {
		if ((req->buffer_end + (n - hdrlen)) > req->max_buffer_size)
			rqst_buffer_grow(req, (n - hdrlen));
		memmove(s + n, e, req->buffer_end - (e - req->buffer));
		memcpy(s, buf, n);
		req->buffer_end += (n - hdrlen);
	}

	return 0;
}

void handleForm(request *req)
{
	form_name_t *now_form;
	char *ptr;
#define SCRIPT_ALIAS "/boafrm/"

	ptr = strstr(req->request_uri, SCRIPT_ALIAS);
	if (ptr) {
		ptr += strlen(SCRIPT_ALIAS);
		now_form = formfunc(ptr);
		if (now_form) {
#ifdef CSRF_SECURITY_PATCH
#ifdef HTTP_FILE_SERVER_SUPPORTED
			if (strcmp(now_form->name, "formusbdisk_uploadfile") == 0)
				log_boaform(now_form->name, req);
#endif
			if (!is_any_log() || !is_valid_boaform(now_form->name, req)) {
#if defined(CONFIG_APP_FWD)
				{
					if (!strcmp(now_form->name, "formUpload"))
					{
						extern int get_shm_id();
						extern int clear_fwupload_shm();
						int shm_id = get_shm_id();
						clear_fwupload_shm(shm_id);
					}
				}
#endif
				send_redirect_perm(req, "/login.htm");
				//send_r_forbidden(req);
				return;
			}
			delete_boaform(now_form->name);
#endif
#ifdef SUPER_NAME_SUPPORT
			if (req->auth_flag != 0) {	//user has login
				if (!getFormAuth(ptr, req->auth_flag)) {	//postform auth to login user
					send_r_forbidden(req);
					return;
				}
			}
#endif
			send_r_request_ok2(req);	/* All's well */
			now_form->function(req, NULL, NULL);

#ifdef HTTP_FILE_SERVER_SUPPORTED
			if (req->FileUploadAct == 1) {
				if (strstr(req->UserBrowser, "MSIE"))
					update_content_length(req);
			} else
#endif
				update_content_length(req);
			freeAllTempStr();
			return;
		}
	}
	send_r_not_found(req);
}

void handleScript(request *req, char *left1, char *right1)
{
	char *left = left1, *right = right1;
	asp_name_t *now_asp;
	unsigned int funcNameLength;
	int i;

	left += 2;
	right -= 1;
	while (1) {
		while (*left == ' ') {
			if (left >= right)
				break;
			++left;
		}
		while (*left == ';') {
			if (left >= right)
				break;
			++left;
		}
		while (*left == '(') {
			if (left >= right)
				break;
			++left;
		}
		while (*left == ')') {
			if (left >= right)
				break;
			++left;
		}
		while (*left == ',') {
			if (left >= right)
				break;
			++left;
		}
		if (left >= right)
			break;

		/* count the function name length */
		do {
			char *ptr = left;

			funcNameLength = 0;
			while (*ptr != '(' && *ptr != ' ') {
				ptr++;
				funcNameLength++;
				if ((unsigned int)ptr >= (unsigned int)right)
					break;
			}
		} while (0);

		now_asp = aspfunc(left, funcNameLength);
		if (now_asp) {
			char *leftc, *rightc, *ps = NULL;
			size_t ps_buffer_len = 0;
			size_t argc = 0;

			left += strlen(now_asp->name);
			while (1) {
				int size, exit = 0;
				while (1) {
					if (*left == ')') {
						exit = 1;
						break;
					}
					if (*left == '\"')
						break;
					if ((unsigned int)left > (unsigned int)right) {
						exit = 1;
						break;
					}
					left++;
				}

				if (exit == 1)
					break;
				leftc = left;
				leftc++;
				rightc = strchr(leftc, '\"');
				if (rightc == NULL)
					break;
				size = (unsigned int)rightc - (unsigned int)leftc + 1;

				ps = realloc(ps, ps_buffer_len + size);
				strncpy(ps + ps_buffer_len, leftc, size - 1);
				ps_buffer_len += size;
				ps[ps_buffer_len - 1] = '\0';
				argc++;
				left = rightc + 1;
			}
			do {
				char *argv[argc + 1];

				argv[0] = ps;
				for (i = 1; i < argc; i++)
					argv[i] = argv[i - 1] + strlen(argv[i - 1]) + 1;
				argv[i] = NULL;
				now_asp->function(req, argc, argv);
				free(ps);
			} while (0);
		}
		++left;
	}
}
#endif

int rqst_buffer_grow(request *req, size_t count)
{
	char *p;
	size_t bsize;

	if (req->max_buffer_size)
		bsize = req->max_buffer_size << 1;
	else
		bsize = CLIENT_STREAM_SIZE;
	if (bsize < (req->buffer_end + count))
		bsize = req->buffer_end + count;
	p = realloc(req->buffer, bsize);
	if (p != NULL) {
		req->buffer = p;
		req->max_buffer_size = bsize;
	}
	return p ? 0 : -1;
}

int rqst_write(request *req, const void *buf, size_t count)
{
	if ((count > (req->max_buffer_size - req->buffer_end)) && rqst_buffer_grow(req, count))
		return -1;
	if (count) {
		memcpy(req->buffer + req->buffer_end, buf, count);
		req->buffer_end += count;
	}
	return (int)count;
}

int req_format_write(request *req, char *fmt, ...)
{
	va_list ap, aq;
	size_t len, spc;

	if (!req || !fmt)
		return 0;

	spc = req->max_buffer_size - req->buffer_end;
	va_start(ap, fmt);
	va_copy(aq, ap);
	len = (size_t)vsnprintf(req->buffer + req->buffer_end, spc, fmt, aq);
	va_end(aq);
	if (len >= spc) {
		if (!rqst_buffer_grow(req, len + 1))
			len = (size_t)vsnprintf(req->buffer + req->buffer_end,
			                        req->max_buffer_size - req->buffer_end, fmt, ap);
		else
			len = spc - 1;
	}
	va_end(ap);
	req->buffer_end += len;

	return (int)len;
}

int getIncludeCss(request *wp)
{
#ifdef CONFIG_APP_BOA_NEW_UI
	return req_format_write(wp, "<link href=\"/style.css\" rel=\"stylesheet\" type=\"text/css\">");
#else
	return req_format_write(wp,
	                        "<style>h2{font-weight:bold;color:rgb(0,0,255);}\
		tr.tbl_head {\
		background-color: #7f7f7f;\
		}\
		tr.tbl_body {\
		background-color: #b7b7b7;\
		}\
		td.tbl_title {\
		background-color: #008000;\
		color: #FFFFFF;\
		font-weight: bold;\
		}\
		</style>");
#endif
}
