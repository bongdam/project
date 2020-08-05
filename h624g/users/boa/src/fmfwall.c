/*
 *      Web server handler routines for firewall
 *
 *      Authors: David Hsu	<davidhsu@realtek.com.tw>
 *
 *      $Id: fmfwall.c,v 1.20 2009/07/09 03:21:23 keith_huang Exp $
 *
 */

/*-- System inlcude files --*/
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/wait.h>
#include <libytool.h>
#include <glob.h>

#include "boa.h"
#include "globals.h"
#include "apform.h"
#include "apmib.h"
#include "utility.h"
#include "asp_page.h"
#include <bcmnvram.h>
#include "captcha.h"
#ifdef CONFIG_NVRAM_APMIB
#include "nvram_mib/nvram_mib.h"
#endif

#ifdef __DAVO__
extern int need_reboot;
extern void translate_control_code(char *buffer);
#endif

#if defined(VLAN_CONFIG_SUPPORTED)
struct nameMapping
{
	char display[32];
	char ifname[16];
};
static struct nameMapping vlanNameMapping[15] =
{
	{"Ethernet Port1","eth0"},
	{"Ethernet Port2","eth2"},
	{"Ethernet Port3","eth3"},
	{"Ethernet Port4","eth4"},
	{"Ethernet Port5","eth1"},
	{"Wireless 1 Primary AP","wlan0"},
	{"Wireless 1 Virtual AP1","wlan0-va0"},
	{"Wireless 1 Virtual AP2","wlan0-va1"},
	{"Wireless 1 Virtual AP3","wlan0-va2"},
	{"Wireless 1 Virtual AP4","wlan0-va3"},
	{"Wireless 2 Primary AP","wlan1"},
	{"Wireless 2 Virtual AP1","wlan1-va0"},
	{"Wireless 2 Virtual AP2","wlan1-va1"},
	{"Wireless 2 Virtual AP3","wlan1-va2"},
	{"Wireless 2 Virtual AP4","wlan1-va3"},
};

static struct nameMapping* findNameMapping(const char *display)
{
	int i;
	for(i = 0; i < MAX_IFACE_VLAN_CONFIG;i++)
	{
		if(strcmp(display,vlanNameMapping[i].display) == 0)
			return &vlanNameMapping[i];
	}
	return NULL;
}

int vlanList(request *wp, int idx)
{
	VLAN_CONFIG_T entry;
	char *strToken;
	int cmpResult=0;
	//char *tmpStr0;
	int  index=0;
	char IfaceName[32];
	OPMODE_T opmode=-1;
	char wanLan[8];
	char bufStr[128];

#if defined(CONFIG_RTK_VLAN_NEW_FEATURE) ||defined(CONFIG_RTL_HW_VLAN_SUPPORT)
	unsigned char forwarding_rule;
#endif

	memset(IfaceName,0x00,sizeof(IfaceName));
	memset(wanLan,0x00,sizeof(wanLan));
	memset(bufStr,0x00,sizeof(bufStr));

	index = idx;

	if( index <= MAX_IFACE_VLAN_CONFIG && index != 0) /* ignore item 0 */
	{

    #ifdef RTK_USB3G_PORT5_LAN
        DHCP_T wan_dhcp = -1;
        apmib_get( MIB_DHCP, (void *)&wan_dhcp);
    #endif

		*((char *)&entry) = (char)index;

		if ( !apmib_get(MIB_VLANCONFIG_TBL, (void *)&entry))
		{
			fprintf(stderr,"Get vlan entry fail\n");
			return -1;
		}
#if defined(CONFIG_RTK_VLAN_NEW_FEATURE) ||defined(CONFIG_RTL_HW_VLAN_SUPPORT)
		forwarding_rule = entry.forwarding_rule;
#endif
		apmib_get( MIB_OP_MODE, (void *)&opmode);

		switch(index)
		{
			case 1:
			case 2:
			case 3:
			case 4:
				sprintf(IfaceName,"%s%d","Ethernet Port",index);
				sprintf(wanLan,"%s","LAN");
				break;
			case 5:
				sprintf(IfaceName,"%s","Wireless 1 Primary AP");
				if(opmode == WISP_MODE)
				{
					sprintf(wanLan,"%s","WAN");
#if defined(CONFIG_RTK_VLAN_NEW_FEATURE)
					forwarding_rule = VLAN_FORWARD_NAT;
#endif
				}
				else
				{
					sprintf(wanLan,"%s","LAN");
				}
				break;
			case 6:
			case 7:
			case 8:
			case 9:
				sprintf(IfaceName,"%s%d","Wireless 1 Virtual AP",index-5);
				sprintf(wanLan,"%s","LAN");
				break;
			case 10:
				sprintf(IfaceName,"%s","Wireless 2 Primary AP");
				sprintf(wanLan,"%s","LAN");
				break;
			case 11:
			case 12:
			case 13:
			case 14:
				sprintf(IfaceName,"%s%d","Wireless 2 Virtual AP",index-10);
				sprintf(wanLan,"%s","LAN");
				break;

			case 15:
				sprintf(IfaceName,"%s","Ethernet Port5");
#ifdef RTK_USB3G_PORT5_LAN
				if(opmode == WISP_MODE || opmode == BRIDGE_MODE || wan_dhcp == USB3G)
#else
				if(opmode == WISP_MODE || opmode == BRIDGE_MODE)
#endif
				{
					sprintf(wanLan,"%s","LAN");
				}
				else
				{
					sprintf(wanLan,"%s","WAN");

#if defined(CONFIG_RTK_VLAN_NEW_FEATURE) ||defined(CONFIG_RTL_HW_VLAN_SUPPORT)
					forwarding_rule = VLAN_FORWARD_NAT;
#endif
				}
				break;
			case 16:
			sprintf(IfaceName,"%s","Local Host/WAN");
				sprintf(wanLan,"%s","LAN");
				break;
		}

		/* enabled/netIface/tagged/untagged/priority/cfi/groupId/vlanId/LanWan */
		//req_format_write(wp, ("%d|%s|%d|%d|%d|%d|%d|%d|%s"), entry.enabled,IfaceName,entry.tagged,0,entry.priority,entry.cfi,0,entry.vlanId,wanLan);
#if defined(CONFIG_RTK_VLAN_NEW_FEATURE) ||defined(CONFIG_RTL_HW_VLAN_SUPPORT)
		sprintf(bufStr, "token[%d] =\'%d|%s|%d|%d|%d|%d|%d|%d|%s|%d\';\n",idx,entry.enabled,IfaceName,entry.tagged,0,entry.priority,entry.cfi,0,entry.vlanId,wanLan, forwarding_rule);
#else
		sprintf(bufStr, "token[%d] =\'%d|%s|%d|%d|%d|%d|%d|%d|%s\';\n",idx, entry.enabled,IfaceName,entry.tagged,0,entry.priority,entry.cfi,0,entry.vlanId,wanLan);
#endif
	}
	else
	{
#if defined(CONFIG_RTK_VLAN_NEW_FEATURE) ||defined(CONFIG_RTL_HW_VLAN_SUPPORT)
		sprintf(bufStr, "token[%d] =\'0|none|0|0|0|0|0|0|LAN|0\';\n", idx);
#else
		sprintf(bufStr, "token[%d] =\'0|none|0|0|0|0|0|0|LAN\';\n", idx);
#endif
	}
	req_format_write(wp, bufStr);
	return 0;
}

int getVlanList(request *wp, int argc, char **argv)
{
	int i, maxWebVlanNum;

#if defined(CONFIG_RTL_8198_AP_ROOT) && defined(GMII_ENABLED)
	maxWebVlanNum = MAX_IFACE_VLAN_CONFIG-2;
#else
	maxWebVlanNum = MAX_IFACE_VLAN_CONFIG-1;
#endif
	for (i=0; i<=maxWebVlanNum; i++) {
		vlanList(wp, i);
	}
	return 0;
}

/*void formVlan(request *wp, char *path, char *query)
{
	VLAN_CONFIG_T entry;
	char *submitUrl,*strTmp;
	int	i, vlan_onoff;
	struct nameMapping *mapping;
	char tmpBuf[100];

	//displayPostDate(wp->post_data);
	//printf("--%s(%d)--\n", __FUNCTION__, __LINE__);

	strTmp= req_get_cstream_var(wp, ("vlan_onoff"), "");
	if(strTmp[0])
	{
		vlan_onoff = atoi(strTmp);
	}

	if (!apmib_set(MIB_VLANCONFIG_ENABLED, (void *)&vlan_onoff))
	{
		strcpy(tmpBuf, ("set  MIB_VLANCONFIG_ENABLED error!"));
	//	printf("--%s(%d)--\n", __FUNCTION__, __LINE__);
		goto setErr;
	}
	if(vlan_onoff == 1)
	{
		if ( !apmib_set(MIB_VLANCONFIG_DELALL, (void *)&entry))
		{
			strcpy(tmpBuf, ("Delete all table error!"));
		//	printf("--%s(%d)--\n", __FUNCTION__, __LINE__);
			goto setErr;
		}

		for(i=1; i<=MAX_IFACE_VLAN_CONFIG ; i++)
		{
			memset(&entry, '\0', sizeof(entry));
		//	printf("--%s(%d)--i is %d\n", __FUNCTION__, __LINE__, i);

			*((char *)&entry) = (char)i;
			apmib_get(MIB_VLANCONFIG_TBL, (void *)&entry);

			memset(tmpBuf,0x00, sizeof(tmpBuf));
			sprintf(tmpBuf,"vlan_iface_%d",i);
			strTmp = req_get_cstream_var(wp, tmpBuf, "");

			if(strTmp[0])
			{
				//strcpy(entry.netIface,strTmp);

				mapping = findNameMapping(strTmp);

				if(mapping)
				{
					strcpy((char *)entry.netIface,mapping->ifname);
				}
			}
			else
			{
		//	printf("--%s(%d)--\n", __FUNCTION__, __LINE__);
				if ( apmib_set(MIB_VLANCONFIG_ADD, (void *)&entry) == 0)
				{
					strcpy(tmpBuf, ("Add table entry error!"));
	//				printf("--%s(%d)--\n", __FUNCTION__, __LINE__);
					goto setErr;
				}
	//			printf("--%s(%d)--\n", __FUNCTION__, __LINE__);
				continue;
			}

			memset(tmpBuf,0x00, sizeof(tmpBuf));
			sprintf(tmpBuf,"vlan_enable_%d",i);
			strTmp = req_get_cstream_var(wp, tmpBuf, "");
			if(strTmp[0])
			{
				entry.enabled = atoi(strTmp);
			}

			memset(tmpBuf,0x00, sizeof(tmpBuf));
			sprintf(tmpBuf,"vlan_tag_%d",i);
			strTmp = req_get_cstream_var(wp, tmpBuf, "");
			if(strTmp[0])
			{
				entry.tagged = atoi(strTmp);
			}

			memset(tmpBuf,0x00, sizeof(tmpBuf));
			sprintf(tmpBuf,"vlan_cfg_%d",i);
			strTmp = req_get_cstream_var(wp, tmpBuf, "");
			if(strTmp[0])
			{
				entry.cfi = atoi(strTmp);
			}

			memset(tmpBuf,0x00, sizeof(tmpBuf));
			sprintf(tmpBuf,"vlan_id_%d",i);
			strTmp = req_get_cstream_var(wp, tmpBuf, "");
			if(strTmp[0])
			{
				entry.vlanId = atoi(strTmp);
			}

			memset(tmpBuf,0x00, sizeof(tmpBuf));
			sprintf(tmpBuf,"vlan_priority_%d",i);
			strTmp = req_get_cstream_var(wp, tmpBuf, "");
			if(strTmp[0])
			{
				entry.priority = atoi(strTmp);
			}
#if defined(CONFIG_RTK_VLAN_NEW_FEATURE) || defined(CONFIG_RTL_HW_VLAN_SUPPORT)

			memset(tmpBuf,0x00, sizeof(tmpBuf));
			sprintf(tmpBuf,"vlan_forward_%d",i);
			strTmp = req_get_cstream_var(wp, tmpBuf, "");
			if(strTmp[0])
			{
				entry.forwarding_rule = atoi(strTmp);
			}
#endif

			if ( apmib_set(MIB_VLANCONFIG_ADD, (void *)&entry) == 0)
			{
				strcpy(tmpBuf, ("Add table entry error!"));
//				printf("--%s(%d)--\n", __FUNCTION__, __LINE__);
				goto setErr;
			}




		}

	}

	apmib_update_web(CURRENT_SETTING);

#ifndef NO_ACTION
	run_init_script("all");
#endif

	submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page
	if (submitUrl[0])
	{
		OK_MSG(submitUrl);
	}
  	return;

setErr:
	ERR_MSG(tmpBuf);
	return;

}*/
#endif

#ifdef HOME_GATEWAY
#ifdef __DAVO__
enum {
	EEXISTS = 1,
	EBADARG,
	ENOROOM,
	EFILEIO
};

struct staticfwd_s {
	unsigned int sip;
	unsigned int dip;	/* within lan's subnet */
	unsigned short sport;
	unsigned short dport;
	int proto;		/* 1:tcp 2:udp 3:tcp/udp */
} __attribute__ ((aligned(1), packed));

typedef struct staticfwd_s staticfwd_t;

typedef enum {
	MAPPING_TCP = 1,
	MAPPING_UDP,
	MAPPING_BOTH
} MAPPING_PPOTO;

#define STATICFWD_MAX_ENTRY     32

static staticfwd_t staticmap_tbl[STATICFWD_MAX_ENTRY];
static int staticmap_tbl_num;

static int validate_staticfwd(staticfwd_t *fwd)
{
	return (fwd->sip == 0 || fwd->sip == (unsigned long)-1 ||
		fwd->dip == 0 || fwd->dip == (unsigned long)-1 ||
		fwd->proto < 1 || fwd->proto > 3) ? -1 : 0;
}

int fget_staticfwd(staticfwd_t *fwd, int fwdsiz)
{
	static int is_first_call = 1;
	staticfwd_t tmp[STATICFWD_MAX_ENTRY];
	int i, nread = 0, nelem = 0;

	if (is_first_call) {
		char tmpBuf[52];
		char query[52];
		int dvargc;
		char *dvargs[5], *p;
		char *s_ip, *d_ip;
		staticfwd_t *entry;
		is_first_call = 0;

		if (!nvram_get_r("x_STATICMAP_TBL_NUM", tmpBuf, sizeof(tmpBuf))) {
			apmib_nvram_set("x_STATICMAP_TBL_NUM", "0");
			nread = 0;
		} else {
			nread = atoi(tmpBuf);
		}

		for (i = nelem = 0; i < nread; i++) {
			sprintf(query, "x_STATICMAP_TBL%d", i);
			if ((p = nvram_get_r(query, tmpBuf, sizeof(tmpBuf))) == NULL) {
				continue;
			}
			if ((dvargc = ystrargs(tmpBuf, dvargs, _countof(dvargs), ",", 1)) != 5) {
				continue;
			}

			entry = &tmp[nelem];

			s_ip = dvargs[0];
			inet_aton(s_ip, (struct in_addr *)&(entry->sip));

			//s_port = dvargs[1];
			entry->sport = (unsigned short)atoi(dvargs[1]);

			if (strcmp(dvargs[2], "1") == 0)
				entry->proto = MAPPING_TCP;
			else if (strcmp(dvargs[2], "2") == 0)
				entry->proto = MAPPING_UDP;
			else
				entry->proto = MAPPING_BOTH;

			d_ip = dvargs[3];
			inet_aton(d_ip, (struct in_addr *)&(entry->dip));

			//d_port = dvargs[4];
			entry->dport = (unsigned short)atoi(dvargs[4]);
			nelem++;
		}
		memcpy(staticmap_tbl, tmp, sizeof(staticmap_tbl));;
		staticmap_tbl_num = nelem;
	}

	if (fwdsiz < staticmap_tbl_num) {
		memcpy(fwd, staticmap_tbl, sizeof(staticfwd_t) * fwdsiz);;
		return fwdsiz;
	} else {
		memcpy(fwd, staticmap_tbl, sizeof(staticmap_tbl));;
		return staticmap_tbl_num;
	}
}

int fset_staticfwd(staticfwd_t *fwd, int op)
{				/* op: 0add 1: del */
	staticfwd_t tmp[STATICFWD_MAX_ENTRY];
	char *s_ip, *d_ip;
	char s_sip[30], d_sip[30];
	char query[32];
	char tmpBuf[64];
	int i, nelem;
	int found = -1;

	nelem = fget_staticfwd(tmp, STATICFWD_MAX_ENTRY);
	for (i = 0; i < nelem && found < 0; i++) {
		if (!memcmp(fwd, &tmp[i], sizeof(*fwd))) {
			found = i;
		}
	}

	if (op) {
		/* Deletion */
		if (found < 0)
			return -EBADARG;
		nelem--;
		for (i = found; i < nelem; i++) {
			memcpy(&tmp[i], &tmp[i + 1], sizeof(staticfwd_t));
		}
	} else {
		/* Addition */
		if (nelem >= STATICFWD_MAX_ENTRY)
			return -ENOROOM;
		if (found > -1)
			return -EEXISTS;
		if (validate_staticfwd(fwd))
			return -EBADARG;
		tmp[nelem++] = *fwd;
	}

	for (i = 0; i < nelem; i++) {
		sprintf(query, "x_STATICMAP_TBL%d", i);
		s_ip = inet_ntoa(*((struct in_addr *)&(tmp[i].sip)));
		sprintf(s_sip, "%s", s_ip);
		d_ip = inet_ntoa(*((struct in_addr *)&(tmp[i].dip)));
		sprintf(d_sip, "%s", d_ip);
		sprintf(tmpBuf, "%s,%d,%d,%s,%d", s_sip, tmp[i].sport, tmp[i].proto, d_sip,
			tmp[i].dport);
		apmib_nvram_set(query, tmpBuf);
	}
	for (; i < STATICFWD_MAX_ENTRY; i++) {
		sprintf(query, "x_STATICMAP_TBL%d", i);
		nvram_unset(query);
	}

	sprintf(tmpBuf, "%d", nelem);
	apmib_nvram_set("x_STATICMAP_TBL_NUM", tmpBuf);

	memcpy(staticmap_tbl, tmp, sizeof(staticfwd_t) * nelem);;
	staticmap_tbl_num = nelem;
	LOG(LOG_INFO, "출발주소가 %s:%u이고 착신주소가 외부IP:%u인 %s패킷을 내부 %s로 전달하는 Static Mapping 규칙이 %s됨",
	    apmib_btoa(IN_ADDR, &fwd->sip), fwd->sport, fwd->dport,
	    (fwd->proto == MAPPING_BOTH) ? "TCP/UDP" : (fwd->proto == MAPPING_TCP ? "TCP" : "UDP"),
	    apmib_btoa(IN_ADDR, &fwd->dip), op ? "삭제" : "추가");
	return 0;
}

#define ACLWRITE_PORT1 1
#define ACLWRITE_PORT2 2
#define ACLWRITE_PORT3 4
#define ACLWRITE_PORT4 8
static int get_aclport_to_port(int port)
{
	int change_port;

	if (port == ACLWRITE_PORT3)
		change_port = 3;
	else if (port == ACLWRITE_PORT4)
		change_port = 4;
	else
		change_port = port;

	return change_port;
}

static int get_port_to_aclport(int port)
{
	int change_port;

	if (port == 3)
		change_port = ACLWRITE_PORT3;
	else if (port == 4)
		change_port = ACLWRITE_PORT4;
	else
		change_port = port;

	return change_port;
}

static int DvAddMacFilterEntry(MACFILTER_T *macEntry, int port)
{
	char strPort[32], tmpbuf[128];
	int entryNum;
	char tmp[512];
	int i;

	if (!nvram_get_r("x_MACFILTER_TBL_NUM", tmpbuf, sizeof(tmpbuf))) {
		apmib_nvram_set("x_MACFILTER_TBL_NUM", "0");
		entryNum = 0;
	} else
		entryNum = safe_atoi(tmpbuf, 0);

	sprintf(tmp, "%02x:%02x:%02x:%02x:%02x:%02x,%02d,%s",
		macEntry->macAddr[0], macEntry->macAddr[1],
		macEntry->macAddr[2], macEntry->macAddr[3],
		macEntry->macAddr[4], macEntry->macAddr[5],
		port, macEntry->comment);

	// check duplicated entry
	for (i = 1; i <= entryNum; i++) {
		sprintf(strPort, "x_MACFILTER_TBL%d", i);
		if (nvram_get_r(strPort, tmpbuf, sizeof(tmpbuf)) &&
		    !strncmp(tmp, tmpbuf, 20))
			return -2;
	}

	sprintf(strPort, "x_MACFILTER_TBL%d", entryNum + 1);
	if (apmib_nvram_set(strPort, tmp) < 0)
		return -1;
	sprintf(tmp, "%d", entryNum + 1);
	if (apmib_nvram_set("x_MACFILTER_TBL_NUM", tmp) < 0)
		return -1;
	LOG(LOG_INFO, "MAC 필터링 LAN%d포트에 %s 주소를 규칙에 추가함",
	    get_aclport_to_port(port), apmib_btoa(ETH_ADDR, macEntry->macAddr));
	return 0;
}

static void DvDeleteMacFilterEntry(int entryNum, int index)
{
	char *mac, *port, opmode[16];
	char query[32];
	char tmpBuf[512];
	int portlist;
	int i;

	sprintf(query, "x_MACFILTER_TBL%d", index);
	if (nvram_get_r(query, tmpBuf, sizeof(tmpBuf)) == NULL)
		return;

	// delete entry from nvram
	nvram_unset(query);

	mac = strtok(tmpBuf, ",");
	port = strtok(NULL, ",");
	if (!mac || !port)
		return;

	portlist = atoi(port);
	i = get_aclport_to_port(portlist);

	sprintf(query, "x_MACFILTER_OPMODE%d", i);
	if (nvram_get_r(query, opmode, sizeof(opmode))) {
		yexecl(NULL, "aclwrite del br0 -a %s -r sfilter -o 7 -m %s -P %d -3 -4", opmode, mac, portlist);
		if (!strcmp(opmode, "permit")) {
			yexecl(NULL, "aclwrite del br0 -a drop -r sfilter -o 7 -3 -4 -P %d", portlist);
		}
	}

	LOG(LOG_INFO, "MAC 필터링 LAN%d포트에서 %s 주소를 제거함", i, mac);
	sprintf(tmpBuf, "%d", entryNum - 1);
	apmib_nvram_set("x_MACFILTER_TBL_NUM", tmpBuf);
}

static void DvAlignMacFilterEntry(int entryNum)
{
	int i, j;
	char tmpBuf[512], query[32];

	i = j = 1;
	while (i <= entryNum) {
		sprintf(query, "x_MACFILTER_TBL%d", i++);
		if (nvram_get_r(query, tmpBuf, sizeof(tmpBuf)) == NULL)
			continue;
		nvram_unset(query);

		sprintf(query, "x_MACFILTER_TBL%d", j++);
		apmib_nvram_set(query, tmpBuf);
	}
}

static void DvChangePortMode(int port, char *mode)
{
	char query[32];
	char old_mode[16];
	char tmpbuf[512];
	int i, entryNum;
	char *mac, *cur_port, *p;
	int portlist;

	sprintf(query, "x_MACFILTER_OPMODE%d", port);
	if ((p = nvram_get_r(query, old_mode, sizeof(old_mode))) == NULL) {
		apmib_nvram_set(query, mode);
		strcpy(old_mode, mode);
	}

	port = get_port_to_aclport(port);

	if (!strcasecmp(old_mode, "permit") && strcasecmp(old_mode, mode)) {
		yexecl(NULL, "aclwrite del br0 -a drop -r sfilter -o 7 -3 -4 -P %d", port);
	}
	if (!strcasecmp(old_mode, mode))
		return;

	apmib_nvram_set(query, mode);

	LOG(LOG_INFO, "MAC 필터링 LAN%d포트의 접근 규칙을 %s으로 변경함",
	    get_aclport_to_port(port), strcmp(mode, "permit") ? "차단" : "허용");

	if (!nvram_get_r("x_MACFILTER_TBL_NUM", tmpbuf, sizeof(tmpbuf))) {
		apmib_nvram_set("x_MACFILTER_TBL_NUM", "0");
		entryNum = 0;
	} else {
		entryNum = safe_atoi(tmpbuf, 0);
	}

	for (i = 1; i <= entryNum; i++) {
		sprintf(query, "x_MACFILTER_TBL%d", i);
		if (!nvram_get_r(query, tmpbuf, sizeof(tmpbuf))) {
			continue;
		}
		mac = strtok(tmpbuf, ",");
		cur_port = strtok(NULL, ",");
		if (!mac || !cur_port)
			continue;

		portlist = atoi(cur_port);
		yexecl(NULL, "aclwrite del br0 -a %s -r sfilter -o 7 -m %s -P %d -3 -4", old_mode, mac, portlist);
	}
}

static void DvEnableMacFilter(int enable)
{
	int entryNum, i, j;
	char tmpBuf[32];
	char query[512];
	char opmode[16];
	char *mac, *port;
	int portlist;

	if (enable) {
		apmib_nvram_set("x_MACFILTER_ENABLE", "1");
		return;
	}

	if (!nvram_get_r("x_MACFILTER_TBL_NUM", tmpBuf, sizeof(tmpBuf))) {
		entryNum = 0;
	} else {
		entryNum = atoi(tmpBuf);
	}

	for (i = 1; i <= entryNum; i++) {
		sprintf(query, "x_MACFILTER_TBL%d", i);
		if (nvram_get_r(query, tmpBuf, sizeof(tmpBuf)) == NULL)
			continue;
		mac = strtok(tmpBuf, ",");
		port = strtok(NULL, ",");
		if (!mac || !port)
			continue;

		portlist = atoi(port);
		j = get_port_to_aclport(portlist);

		sprintf(query, "x_MACFILTER_OPMODE%d", j);
		if (nvram_get_r(query, opmode, sizeof(opmode))) {
			// delete acl entry from acl list
			yexecl(NULL, "aclwrite del br0 -a %s -r sfilter -o 7 -m %s -P %d -3 -4", opmode, mac, portlist);
		}
	}

	for (i = 1; i <= 4; i++) {
		portlist = get_port_to_aclport(i);
		sprintf(query, "x_MACFILTER_OPMODE%d", i);
		nvram_get_r_def(query, opmode, sizeof(opmode), "drop");
		if (!strcasecmp(opmode, "permit")) {
			yexecl(NULL, "aclwrite del br0 -a drop -r sfilter -o 7 -3 -4 -P %d", portlist);
		}
	}

	apmib_nvram_set("x_MACFILTER_ENABLE", "0");
}

void formStMapping(request *wp, char *path, char *query)
{
	char *strAddPort, *strDelPort, *strVal, *strDelAllPort, *submitUrl;
	char *str_Sip, *str_Dip, *strFromSport, *strFromDport;
	char tmpBuf[100];
	int entryNum = 0, intVal, i;
	staticfwd_t entry, entry_t[STATICFWD_MAX_ENTRY];
	struct in_addr curIpAddr, curSubnet;
	int res;
	unsigned long v1, v2, v3;

	apmib_set_hist_clear();
	strAddPort = req_get_cstream_var(wp, "addStMapping", "");
	strDelPort = req_get_cstream_var(wp, "deleteMappingElement", "");
	strDelAllPort = req_get_cstream_var(wp, "deleteAllMapping", "");

	memset(&entry, 0, sizeof(entry));
	memset(entry_t, 0, sizeof(entry_t));

	submitUrl = req_get_cstream_var(wp, "submit-url", "/skb_static_mapping.htm");	// hidden page

	/* Add new static mappig table */
	if (strAddPort[0]) {
		str_Sip = req_get_cstream_var(wp, "s_ip", "");
		str_Dip = req_get_cstream_var(wp, "d_ip", "");

		strFromSport = req_get_cstream_var(wp, "fromSport", "");
		strFromDport = req_get_cstream_var(wp, "fromDport", "");

		if (!str_Sip[0] && !str_Dip[0] && !strFromSport[0] && !strFromDport[0])
			goto setOk_staticMapping;

		if (!str_Sip[0]) {
			strcpy(tmpBuf, "출발지 주소값이 설정되지 않았습니다.");
			goto setErr_staticMapping;
		}

		if (!str_Dip[0]) {
			strcpy(tmpBuf, "목적지 주소값이 설정되지 않았습니다.");
			goto setErr_staticMapping;
		}
		inet_aton(str_Sip, (struct in_addr *)&(entry.sip));
		getInAddr(BRIDGE_IF, IP_ADDR, (void *)&curIpAddr);
		getInAddr(BRIDGE_IF, SUBNET_MASK, (void *)&curSubnet);

		inet_aton(str_Dip, (struct in_addr *)&(entry.dip));

		if (!strFromSport[0]) {	// if static_mapping source port must exist
			strcpy(tmpBuf, "오류! 출발지 포트가 설정되지 않았습니다.");
			goto setErr_staticMapping;
		}
		if (!string_to_dec(strFromSport, &intVal) || intVal < 1 || intVal > 65535) {
			strcpy(tmpBuf, "오류! 포트 범위가 올바르지 않습니다.");
			goto setErr_staticMapping;
		}
		entry.sport = (unsigned short)intVal;

		if (!strFromDport[0]) {
			strcpy(tmpBuf, "오류! 목적지 포트가 설정되지 않았습니다.");
			goto setErr_staticMapping;
		} else {
			if (!string_to_dec(strFromDport, &intVal) || intVal < 1 || intVal > 65535) {
				strcpy(tmpBuf, "오류! 포트 범위가 올바르지 않습니다.");
				goto setErr_staticMapping;
			}
		}
		entry.dport = (unsigned short)intVal;

		strVal = req_get_cstream_var(wp, "protocol", "");
		if (strVal[0]) {
			if (strVal[0] == '1')
				entry.proto = MAPPING_TCP;
			else if (strVal[0] == '2')
				entry.proto = MAPPING_UDP;
			else if (strVal[0] == '3')
				entry.proto = MAPPING_BOTH;
			else {
				strcpy(tmpBuf, "오류! 프로토콜 종류가 올바르지 않습니다.");
				goto setErr_staticMapping;
			}

		} else {
			strcpy(tmpBuf, "오류! 프로토콜 종류가 없습니다.");
			goto setErr_staticMapping;
		}

		v2 = curIpAddr.s_addr;
		v3 = curSubnet.s_addr;
		v1 = (unsigned long)entry.sip;
		if ((v1 & v3) == (v2 & v3)) {
			strcpy(tmpBuf, "출발지 IP 주소가 올바르지 않습니다!");
			goto setErr_staticMapping;
		}

		v1 = (unsigned long)entry.dip;
		if ((v1 & v3) != (v2 & v3)) {
			strcpy(tmpBuf, "목적지 IP 주소가 올바르지 않습니다! <br>현재 서브넷 안에서 설정해야 합니다.");
			goto setErr_staticMapping;
		}

		switch ((res = fset_staticfwd(&entry, 0))) {
		case -EEXISTS:
			strcpy(tmpBuf, "설정 값이 겹칩니다. 이미 설정된 값입니다.");
			goto setErr_staticMapping;
		case -EBADARG:
			strcpy(tmpBuf, "입력한 설정 값이 올바르지 않습니다.");
			goto setErr_staticMapping;
		case -ENOROOM:
			strcpy(tmpBuf, "테이블이 모두 차서 더 이상 추가할 수 없습니다!");
			goto setErr_staticMapping;
		default:
			break;
		}
	}
	if (strDelPort[0] || strDelAllPort[0])
		entryNum = fget_staticfwd(entry_t, STATICFWD_MAX_ENTRY);

	/* Delete entry */
	if (strDelPort[0]) {
		for (i = 0; i < entryNum; i++) {
			snprintf(tmpBuf, sizeof(tmpBuf) - 1, "select%d", i);
			strVal = req_get_cstream_var(wp, tmpBuf, "");
			if (!strcmp(strVal, "ON")) {
				switch ((res = fset_staticfwd(&entry_t[i], 1))) {
				case -EEXISTS:
					strcpy(tmpBuf, "설정 값이 겹칩니다. 이미 설정된 값입니다.");
					goto setErr_staticMapping;
					break;
				case -EBADARG:
					strcpy(tmpBuf, "입력한 설정 값이 올바르지 않습니다.");
					goto setErr_staticMapping;
					break;
				case -ENOROOM:
					strcpy(tmpBuf, "테이블이 모두 차서 더 이상 추가할 수 없습니다!");
					goto setErr_staticMapping;
					break;
				default:
					break;
				}
			}
		}
	}

	/* Delete all entry */
	if (strDelAllPort[0]) {
		apmib_nvram_set("x_STATICMAP_TBL_NUM", "0");

		for (i = 0; i < entryNum; i++) {
			sprintf(tmpBuf, "x_STATICMAP_TBL%d", i);
			nvram_unset(tmpBuf);
		}

		memset(staticmap_tbl, 0, sizeof(staticmap_tbl));;
		staticmap_tbl_num = 0;
	}
#ifdef __DAVO__
	nvram_commit();
	need_reboot = 1;
	OK_MSG("/skb_static_mapping.htm");
	return;
#else
	if (sdmz_enable()) {
		OK_MSG(submitUrl);
		return;
	}
#ifndef NO_ACTION
	dv_run_init_firewall = 1;
#endif

#ifdef REBOOT_CHECK
	if (needReboot == 1) {
		OK_MSG(submitUrl);
		return;
	} else {
		DO_APPLY_WAIT(submitUrl);
		return;
	}
#endif

	if (submitUrl[0])
		websRedirect(wp, submitUrl);
	else
		websDone(wp, 200);
#endif

setOk_staticMapping:
	send_redirect_perm(wp, "/skb_static_mapping.htm");
	return;

setErr_staticMapping:
	ERR_MSG(tmpBuf);
}

void formVlan(request *wp, char *path, char *query)
{
	char var[20];
	char strBuf[64];
	int vlan_index;
	char *strVal, *strVid, *strUse;
	char *submitUrl;
	int i, j;
	int vid;
	unsigned int tagged_port = 0;
	unsigned int tagged_val = 0;
	char *p;
	struct abuffer mbr;

	if (wp->superUser != 1)
		return;

	apmib_set_hist_clear();		/* APACRTL-85 */

	submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page
	for (i = 0; i <= 4; i++) {
		if (i == 4)
			strcpy(var, "wan_pvid");
		else
			sprintf(var, "lan%d_pvid", i + 1);
		strVal = req_get_cstream_var(wp, var, "");
		if (!strVal || !strVal[0])
			continue;
		sprintf(var, "x_VLAN_PORT_%d", i);
		j = nvram_atoi(var, -1);
		vlan_index = atoi(strVal);
		if (vlan_index == 0) {
			nvram_unset(var);
			if (j > -1)
				LOG(LOG_INFO, "%s포트가 PVID 사용 안 함으로 설정됨", getportalias(i));
		}  else {
			sprintf(strBuf, "%d", vlan_index - 1);
			apmib_nvram_set(var, strBuf);
			if (apmib_set_hist_strstr(var) > -1)
				LOG(LOG_INFO, "%s포트의 PVID는 Vlan구성 %d번에 맵핑함",
				    getportalias(i), vlan_index);
		}
	}

	for (i = 0; i < 16; i++) {
		sprintf(var, "x_VLAN_%d", i);
		tagged_port = 0;
		tagged_val = 0;

		if ((p = nvram_get_r(var, strBuf, sizeof(strBuf))))
			sscanf(strBuf, "%d_%x_%x", &vid, &tagged_port, &tagged_val);

		sprintf(strBuf, "use%d", i);
		strUse = req_get_cstream_var(wp, strBuf, "");
		sprintf(strBuf, "vid%d", i);
		strVid = req_get_cstream_var(wp, strBuf, "");
		if (strUse && !strcmp(strUse, "1")) {
			init_abuffer(&mbr, 32);
			for (j = 0; j <= 4; j++) {
				sprintf(strBuf, "vlan%d_port%d", i, j);
				strVal = req_get_cstream_var(wp, strBuf, "");
				if (!strVal)
					continue;
				switch (strVal[0]) {
				case '0':
					tagged_port &= ~(1 << j);
					tagged_val &= ~(1 << j);
					break;
				case '1':
					tagged_port |= (1 << j);
					tagged_val &= ~(1 << j);
					aprintf(&mbr, "%s(U) ", getportalias(j));
					break;
				case '2':
					tagged_port |= (1 << j);
					tagged_val |= (1 << j);
					aprintf(&mbr, "%s(T) ", getportalias(j));
					break;
				}
			}
			sprintf(strBuf, "%s_%x_%x", strVid, tagged_port, tagged_val);
			apmib_nvram_set(var, strBuf);
			if (apmib_set_hist_strstr(var) > -1) {
				if (tagged_port)
					LOG(LOG_INFO, "Vlan ID %s가 %s구성으로 추가됨", strVid, mbr.buf);
				else
					LOG(LOG_INFO, "Vlan ID %s가 멤버포트 없는 구성으로 추가됨", strVid);
			}
			fini_abuffer(&mbr);
		} else {
			apmib_nvram_unset(var);
			if (p && vid)
				LOG(LOG_INFO, "Vlan ID %d가 삭제됨", vid);
		}
	}

	nvram_commit();

	need_reboot = 1;
	OK_MSG("/skb_vlan.htm");
	return;
}
#endif	//__DAVO__

/////////////////////////////////////////////////////////////////////////////
void formPortFw(request *wp, char *path, char *query)
{
	char *submitUrl, *strAddPort, *strDelPort, *strVal, *strDelAllPort;
	char *strIp, *strFrom, *strTo, *strT_from, *strComment;
	char tmpBuf[100];
	char tmpComment[100];
	int entryNum, intVal, i;
	PORTFW_T entry;
	struct in_addr curIpAddr, curSubnet;
	unsigned long v1, v2, v3;
	unsigned int *p;
#ifndef NO_ACTION
	int pid;
#endif
	apmib_set_hist_clear();	/* APACRTL-85 */

	strAddPort = req_get_cstream_var(wp, ("addPortFw"), "");
	strDelPort = req_get_cstream_var(wp, ("deleteSelPortFw"), "");
	strDelAllPort = req_get_cstream_var(wp, ("deleteAllPortFw"), "");

	memset(&entry, '\0', sizeof(entry));
	intVal = 1;
	if (apmib_set(MIB_PORTFW_ENABLED, (void *)&intVal) == 0) {
		strcpy(tmpBuf, "사용 설정 실패!");
		goto setErr_portfw;
	}

	/* Add new port-forwarding table */
	if (strAddPort[0]) {
		strIp = req_get_cstream_var(wp, ("ip"), "");
		strFrom = req_get_cstream_var(wp, ("fromPort"), "");
		strTo = req_get_cstream_var(wp, ("toPort"), "");
		strT_from = req_get_cstream_var(wp, ("t_fromPort"), "");
		strComment = req_get_cstream_var(wp, ("comment"), "");

		if (!strIp[0] && !strFrom[0] && !strTo[0] && !strT_from[0] && !strComment[0])
			goto setOk_portfw;

		if (!strIp[0]) {
			strcpy(tmpBuf, ("ip 주소값이 설정되지 않았습니다."));
			goto setErr_portfw;
		}

		inet_aton(strIp, (struct in_addr *)&entry.ipAddr);
		getInAddr(BRIDGE_IF, IP_ADDR, (void *)&curIpAddr);
		getInAddr(BRIDGE_IF, SUBNET_MASK, (void *)&curSubnet);

		p = (unsigned int *)entry.ipAddr;
		if (*p == curIpAddr.s_addr) {
			strcpy(tmpBuf, "게이트웨이 주소는 사용할 수 없습니다.");
			goto setErr_portfw;
		}

		v1 = *p;
		v2 = curIpAddr.s_addr;
		v3 = curSubnet.s_addr;

		if ((v1 & v3) != (v2 & v3)) {
			strcpy(tmpBuf, ("IP 주소가 올바르지 않습니다! 현재 서브넷 안에서 설정해야 합니다."));
			goto setErr_portfw;
		}

		if (!strFrom[0]) {	// if port-forwarding, from port must exist
			strcpy(tmpBuf, ("오류! 포트 범위가 설정되지 않았습니다."));
			goto setErr_portfw;
		}
		if (!string_to_dec(strFrom, &intVal) || intVal < 1 || intVal > 65535) {
			strcpy(tmpBuf, ("오류! 포트 범위가 올바르지 않습니다."));
			goto setErr_portfw;
		}
		entry.fromPort = (unsigned short)intVal;

		if (!strTo[0])
			entry.toPort = entry.fromPort;
		else {
			if (!string_to_dec(strTo, &intVal) || intVal < 1 || intVal > 65535) {
				strcpy(tmpBuf, ("오류! 포트 범위가 올바르지 않습니다."));
				goto setErr_portfw;
			}
		}
		entry.toPort = (unsigned short)intVal;

		if (entry.fromPort > entry.toPort) {
			strcpy(tmpBuf, ("오류! 포트 범위가 올바르지 않습니다."));
			goto setErr_portfw;
		}

		strVal = req_get_cstream_var(wp, ("protocol"), "");
		if (strVal[0]) {
			if (strVal[0] == '0')
				entry.protoType = PROTO_BOTH;
			else if (strVal[0] == '1')
				entry.protoType = PROTO_TCP;
			else if (strVal[0] == '2')
				entry.protoType = PROTO_UDP;
			else {
				strcpy(tmpBuf, ("오류! 프로토콜 종류가 올바르지 않습니다."));
				goto setErr_portfw;
			}
		} else {
			strcpy(tmpBuf, ("오류! 프로토콜 종류가 없습니다."));
			goto setErr_portfw;
		}

		sprintf(tmpComment, "%s|%s", strT_from, strComment[0] ? strComment : "");
		if (strlen(tmpComment) > COMMENT_LEN - 1) {
			strcpy(tmpBuf, ("오류! 설명이 너무 깁니다."));
			goto setErr_portfw;
		}

		strcpy((char *)entry.comment, tmpComment);

		if (!apmib_get(MIB_PORTFW_TBL_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, ("읽기 실패!"));
			goto setErr_portfw;
		}

		if ((entryNum + 1) > MAX_FILTER_NUM) {
			strcpy(tmpBuf, ("테이블이 모두 차서 더 이상 추가할 수 없습니다!"));
			goto setErr_portfw;
		}
		// Check if there is any port overlapped
		for (i = 1; i <= entryNum; i++) {
			PORTFW_T checkEntry;
			*((char *)&checkEntry) = (char)i;
			if (!apmib_get(MIB_PORTFW_TBL, (void *)&checkEntry)) {
				strcpy(tmpBuf, ("읽기 실패!"));
				goto setErr_portfw;
			}
			if (((entry.fromPort <= checkEntry.fromPort &&
			      entry.toPort >= checkEntry.fromPort) ||
			     (entry.fromPort >= checkEntry.fromPort && entry.fromPort <= checkEntry.toPort)
			    ) && (entry.protoType & checkEntry.protoType)) {
				strcpy(tmpBuf, ("포트 범위가 겹칩니다. 이미 사용중인 포트 입니다!"));
				goto setErr_portfw;
			}
		}

		// set to MIB. try to delete it first to avoid duplicate case
		apmib_set(MIB_PORTFW_DEL, (void *)&entry);
		if (apmib_set(MIB_PORTFW_ADD, (void *)&entry) == 0) {
			strcpy(tmpBuf, ("테이블에 추가할 수 없습니다!"));
			goto setErr_portfw;
		}
		LOG(LOG_INFO, "목적지 포트 %u-%u인 %s패킷을 내부주소 %s:%s로 전달하는 포트 포워딩 규칙이 추가됨",
		    entry.fromPort, entry.toPort,
		    (entry.protoType == PROTO_BOTH) ? "TCP/UDP" : (entry.protoType == PROTO_TCP ? "TCP" : "UDP"),
		    apmib_btoa(IN_ADDR, entry.ipAddr), strT_from);
	}

	/* Delete entry */
	if (strDelPort[0]) {
		if (!apmib_get(MIB_PORTFW_TBL_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, ("읽기 실패!"));
			goto setErr_portfw;
		}

		for (i = entryNum; i > 0; i--) {
			//snprintf(tmpBuf, 20, "select%d", i);
			snprintf(tmpBuf, sizeof(tmpBuf), "select%d", i);

			strVal = req_get_cstream_var(wp, tmpBuf, "");
			if (!strcmp(strVal, "ON")) {
				*((char *)&entry) = (char)i;
				if (!apmib_get(MIB_PORTFW_TBL, (void *)&entry)) {
					strcpy(tmpBuf, ("읽기 실패!"));
					goto setErr_portfw;
				}
				if (!apmib_set(MIB_PORTFW_DEL, (void *)&entry)) {
					strcpy(tmpBuf, ("삭제 실패!"));
					goto setErr_portfw;
				}
				sscanf(entry.comment, "%d", &v1);
				LOG(LOG_INFO, "목적지 포트 %u-%u인 %s패킷을 내부주소 %s:%u로 전달하는 포트 포워딩 규칙을 삭제함",
				    entry.fromPort, entry.toPort,
				    (entry.protoType == PROTO_BOTH) ? "TCP/UDP" : (entry.protoType == PROTO_TCP ? "TCP" : "UDP"),
				    apmib_btoa(IN_ADDR, entry.ipAddr), v1);
			}
		}
	}

	/* Delete all entry */
	if (strDelAllPort[0]) {
		if (!apmib_set(MIB_PORTFW_DELALL, (void *)&entry)) {
			strcpy(tmpBuf, ("전체삭제 실패!"));
			goto setErr_portfw;
		}
		LOG(LOG_INFO, "모든 포트 포워딩 규칙을 삭제함");
	}

 setOk_portfw:
	apmib_update_web(CURRENT_SETTING);
#ifdef __DAVO__
	submitUrl = req_get_cstream_var(wp, "submit-url", "");	// hidden page
	need_reboot = 1;
	OK_MSG("/skb_portfw.htm");
	return;
#endif
#ifndef NO_ACTION
	pid = fork();
	if (pid) {
		waitpid(pid, NULL, 0);
	} else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _FIREWALL_SCRIPT_PROG);
		execl(tmpBuf, _FIREWALL_SCRIPT_PROG, NULL);
		exit(1);
	}
#endif

	submitUrl = req_get_cstream_var(wp, "submit-url", "");	// hidden page

#ifdef REBOOT_CHECK
	if (needReboot == 1) {
		OK_MSG(submitUrl);
		return;
	}
#endif

	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);
	return;

 setErr_portfw:
	ERR_MSG(tmpBuf);
}

/////////////////////////////////////////////////////////////////////////////
void formFilter(request * wp, char *path, char *query)
{
	char *strAddIp, *strAddPort, *strAddMac, *strDelPort, *strDelIp, *strDelMac;
	char *strDelAllPort, *strDelAllIp, *strDelAllMac, *strVal, *submitUrl, *strComment;
	char *strModeMac;
	char *strFrom, *strTo;
#ifdef CONFIG_IPV6
	char *strIP6;
	char *ipVer;
#endif
	char tmpBuf[100];
	int entryNum, intVal, i, j;
	IPFILTER_T ipEntry, ipentrytmp;
	PORTFILTER_T portEntry, entrytmp;
	MACFILTER_T macEntry;
	struct in_addr curIpAddr, curSubnet;
	void *pEntry;
	unsigned long v1, v2, v3;
	int num_id, get_id, add_id, del_id, delall_id, enable_id;
	char *strAddUrl, *strDelUrl;
	char *strDelAllUrl, *strUrlMode;
	int mode;		/*url mode:white list or black list */
	URLFILTER_T urlEntry, urlEntrytmp;
	unsigned int *p, *q;
#ifndef NO_ACTION
	int pid;
#endif
	apmib_set_hist_clear();	/* APACRTL-85 */

	strAddIp = req_get_cstream_var(wp, ("addFilterIp"), "");
	strDelIp = req_get_cstream_var(wp, ("deleteSelFilterIp"), "");
	strDelAllIp = req_get_cstream_var(wp, ("deleteAllFilterIp"), "");

	strAddPort = req_get_cstream_var(wp, ("addFilterPort"), "");
	strDelPort = req_get_cstream_var(wp, ("deleteSelFilterPort"), "");
	strDelAllPort = req_get_cstream_var(wp, ("deleteAllFilterPort"), "");

	strAddMac = req_get_cstream_var(wp, ("addFilterMac"), "");
	strDelMac = req_get_cstream_var(wp, ("deleteSelFilterMac"), "");
	strModeMac = req_get_cstream_var(wp, ("changeModeFilterMac"), "");
	strDelAllMac = req_get_cstream_var(wp, ("deleteAllFilterMac"), "");

	strAddUrl = req_get_cstream_var(wp, ("addFilterUrl"), "");
	strDelUrl = req_get_cstream_var(wp, ("deleteSelFilterUrl"), "");
	strDelAllUrl = req_get_cstream_var(wp, ("deleteAllFilterUrl"), "");

	if (strAddIp[0] || strDelIp[0] || strDelAllIp[0]) {
		num_id = MIB_IPFILTER_TBL_NUM;
		get_id = MIB_IPFILTER_TBL;
		add_id = MIB_IPFILTER_ADD;
		del_id = MIB_IPFILTER_DEL;
		delall_id = MIB_IPFILTER_DELALL;
		enable_id = MIB_IPFILTER_ENABLED;
		memset(&ipEntry, '\0', sizeof(ipEntry));
		pEntry = (void *)&ipEntry;
	} else if (strAddPort[0] || strDelPort[0] || strDelAllPort[0]) {
		num_id = MIB_PORTFILTER_TBL_NUM;
		get_id = MIB_PORTFILTER_TBL;
		add_id = MIB_PORTFILTER_ADD;
		del_id = MIB_PORTFILTER_DEL;
		delall_id = MIB_PORTFILTER_DELALL;
		enable_id = MIB_PORTFILTER_ENABLED;
		memset(&portEntry, '\0', sizeof(portEntry));
		pEntry = (void *)&portEntry;
	} else if (strAddMac[0] || strDelMac[0] || strDelAllMac[0] || strModeMac[0]) {
		num_id = MIB_MACFILTER_TBL_NUM;
		get_id = MIB_MACFILTER_TBL;
		add_id = MIB_MACFILTER_ADD;
		del_id = MIB_MACFILTER_DEL;
		delall_id = MIB_MACFILTER_DELALL;
		enable_id = MIB_MACFILTER_ENABLED;
		memset(&macEntry, '\0', sizeof(macEntry));
		pEntry = (void *)&macEntry;
	} else {
		num_id = MIB_URLFILTER_TBL_NUM;
		get_id = MIB_URLFILTER_TBL;
		add_id = MIB_URLFILTER_ADD;
		del_id = MIB_URLFILTER_DEL;
		delall_id = MIB_URLFILTER_DELALL;
		enable_id = MIB_URLFILTER_ENABLED;
		memset(&urlEntry, '\0', sizeof(urlEntry));
		pEntry = (void *)&urlEntry;
	}
	// Set enable flag
	if (strAddIp[0] || strAddPort[0] || strAddMac[0] || strAddUrl[0]) {
		strVal = req_get_cstream_var(wp, ("enabled"), "");
		if (!strcmp(strVal, "ON"))
			intVal = 1;
		else
			intVal = 0;

		if (apmib_set(enable_id, (void *)&intVal) == 0) {
			strcpy(tmpBuf, ("Set enabled flag error!"));
			goto setErr_filter;
		}
	}

	strVal = req_get_cstream_var(wp, ("pageName"), "");
	if (strVal[0]) {
		if (!strcmp(strVal, ("PORTF"))) {
			enable_id = MIB_PORTFILTER_ENABLED;
			submitUrl = "/skb_portfilter.htm";
		} else if (!strcmp(strVal, ("IPF"))) {
			enable_id = MIB_IPFILTER_ENABLED;
			submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page
		} else if (!strcmp(strVal, ("MACF"))) {
			enable_id = MIB_MACFILTER_ENABLED;
			submitUrl = "/skb_macfilter.htm";
		}

		intVal = 1;
		if (apmib_set(enable_id, (void *)&intVal) == 0) {
			strcpy(tmpBuf, ("사용 설정 실패!"));
			goto setErr_filter;
		}

		if (enable_id == MIB_MACFILTER_ENABLED)
			DvEnableMacFilter(intVal);
	}

	strComment = req_get_cstream_var(wp, ("comment"), "");

	/* Add IP filter */
	if (strAddIp[0]) {
		strVal = req_get_cstream_var(wp, ("ip"), "");
#ifdef CONFIG_IPV6
		strIP6 = req_get_cstream_var(wp, ("ip6addr"), "");
#endif
		if (!strVal[0] && !strComment[0]
#ifdef CONFIG_IPV6
		    && !strIP6[0]
#endif
		    )
			goto setOk_filter;

		if (!strVal[0]
#ifdef CONFIG_IPV6
		    && !strIP6[0]
#endif
		    ) {
			strcpy(tmpBuf, ("Error! No ip address to set."));
			goto setErr_filter;
		}
#ifdef CONFIG_IPV6
		if (strIP6[0]) {
			ipEntry.ipVer = IPv6;
			strcpy(ipEntry.ip6Addr, strIP6);
		} else
			ipEntry.ipVer = IPv4;
#endif
		if (strVal[0]) {
			inet_aton(strVal, (struct in_addr *)&ipEntry.ipAddr);
			getInAddr(BRIDGE_IF, IP_ADDR, (void *)&curIpAddr);
			getInAddr(BRIDGE_IF, SUBNET_MASK, (void *)&curSubnet);

			p = (unsigned int *)ipEntry.ipAddr;

			v1 = *p;
			v2 = curIpAddr.s_addr;
			v3 = curSubnet.s_addr;

			if ((v1 & v3) != (v2 & v3)) {
				strcpy(tmpBuf, ("Invalid IP address! It should be set within the current subnet."));
				goto setErr_filter;
			}
		}

	}

	/* Add port filter */
	if (strAddPort[0]) {
		strFrom = req_get_cstream_var(wp, ("fromPort"), "");
		strTo = req_get_cstream_var(wp, ("toPort"), "");

		if (!strFrom[0] && !strTo[0] && !strComment[0])
			goto setOk_filter;

		if (!strFrom[0]) {	// if port-forwarding, from port must exist
			strcpy(tmpBuf, ("Error! No from-port value to be set."));
			goto setErr_filter;
		}
		if (!string_to_dec(strFrom, &intVal) || intVal < 1 || intVal > 65535) {
			strcpy(tmpBuf, ("Error! Invalid value of from-port."));
			goto setErr_filter;
		}
		portEntry.fromPort = (unsigned short)intVal;

		if (!strTo[0])
			portEntry.toPort = portEntry.fromPort;
		else {
			if (!string_to_dec(strTo, &intVal) || intVal < 1 || intVal > 65535) {
				strcpy(tmpBuf, ("Error! Invalid value of to-port."));
				goto setErr_filter;
			}
			portEntry.toPort = (unsigned short)intVal;
		}

		if (portEntry.fromPort > portEntry.toPort) {
			strcpy(tmpBuf, ("Error! Invalid port range."));
			goto setErr_filter;
		}
#ifdef CONFIG_IPV6
		ipVer = req_get_cstream_var(wp, ("ip6_enabled"), "");
		if (atoi(ipVer))
			portEntry.ipVer = IPv6;
		else
			portEntry.ipVer = IPv4;
#endif
	}

	if (strAddPort[0] || strAddIp[0]) {
		strVal = req_get_cstream_var(wp, ("protocol"), "");
		if (strVal[0]) {
			if (strVal[0] == '0') {
				if (strAddPort[0])
					portEntry.protoType = PROTO_BOTH;
				else
					ipEntry.protoType = PROTO_BOTH;
			} else if (strVal[0] == '1') {
				if (strAddPort[0])
					portEntry.protoType = PROTO_TCP;
				else
					ipEntry.protoType = PROTO_TCP;
			} else if (strVal[0] == '2') {
				if (strAddPort[0])
					portEntry.protoType = PROTO_UDP;
				else
					ipEntry.protoType = PROTO_UDP;
			} else {
				strcpy(tmpBuf, ("Error! Invalid protocol type."));
				goto setErr_filter;
			}
		} else {
			strcpy(tmpBuf, ("Error! Protocol type cannot be empty."));
			goto setErr_filter;
		}
	}

	if (strAddMac[0]) {
		strVal = req_get_cstream_var(wp, ("mac"), "");
		if (!strVal[0] && !strComment[0])
			goto setOk_filter;

		if (!strVal[0]) {
			strcpy(tmpBuf, ("Error! No mac address to set."));
			goto setErr_filter;
		}
		if (strlen(strVal) != 12 || !string_to_hex(strVal, macEntry.macAddr, 12)) {
			strcpy(tmpBuf, ("Error! Invalid MAC address."));
			goto setErr_filter;
		}
	}

	if (strAddUrl[0]) {
		strUrlMode = req_get_cstream_var(wp, "urlFilterMode", "");
		if (strUrlMode) {
			mode = atoi(strUrlMode);
			if (apmib_set(MIB_URLFILTER_MODE, (void *)&mode) == 0) {
				strcpy(tmpBuf, ("Set mode flag error!"));
				goto setErr_filter;
			}
		}
		strVal = req_get_cstream_var(wp, "url", "");
		if (!strVal[0])	// && !strComment[0])
			goto setOk_filter;

		if (!strVal[0]) {
			strcpy(tmpBuf, ("Error! No url keyword to set."));
			goto setErr_filter;
		} else {
			strcpy((char *)urlEntry.urlAddr, strVal);
			urlEntry.ruleMode = mode;
		}

		//add same url rule check
		apmib_get(MIB_URLFILTER_TBL_NUM, (void *)&entryNum);
		for (j = 1; j <= entryNum; j++) {
			memset(&urlEntrytmp, 0x00, sizeof(urlEntrytmp));
			*((char *)&urlEntrytmp) = (char)j;
			if (apmib_get(MIB_URLFILTER_TBL, (void *)&urlEntrytmp)) {
				if (strlen(urlEntry.urlAddr) == strlen(urlEntrytmp.urlAddr)) {
					if (!memcmp(urlEntrytmp.urlAddr, urlEntry.urlAddr, strlen(urlEntry.urlAddr))) {
						strcpy(tmpBuf, ("rule already exist!"));
						goto setErr_filter;
					}
				}
			}
		}
#ifdef URL_FILTER_USER_MODE_SUPPORT
		strUsrMode = req_get_cstream_var(wp, "urlFilterUserMode", "");
		if (strUsrMode) {
			usrMode = atoi(strUsrMode);
		}
		urlEntry.usrMode = (unsigned char)usrMode;
		if (usrMode == 1) {	//ip mode
			strVal = req_get_cstream_var(wp, "ip", "");
			if (strVal[0]) {
				inet_aton(strVal, (struct in_addr *)&urlEntry.ipAddr);
			}
		} else if (usrMode == 2)	//mac mode
		{
			strVal = req_get_cstream_var(wp, "mac", "");
			if (strVal[0]) {
				if (strlen(strVal) != 12 || !string_to_hex(strVal, urlEntry.macAddr, 12)) {
					strcpy(tmpBuf, ("Error! Invalid MAC address."));
					goto setErr_filter;
				}
			}
		}
#endif
	}
	if (strAddPort[0]) {
		apmib_get(MIB_PORTFILTER_TBL_NUM, (void *)&entryNum);
		for (j = 1; j <= entryNum; j++) {
			memset(&entrytmp, 0x00, sizeof(entrytmp));
			*((char *)&entrytmp) = (char)j;
			if (apmib_get(MIB_PORTFILTER_TBL, (void *)&entrytmp)) {
				if ((entrytmp.fromPort == portEntry.fromPort) &&
				    (entrytmp.toPort == portEntry.toPort) &&
				    ((entrytmp.protoType == portEntry.protoType) ||
				     ((entrytmp.protoType == PROTO_BOTH) && portEntry.protoType == PROTO_UDP) ||
				     ((entrytmp.protoType == PROTO_BOTH) && portEntry.protoType == PROTO_TCP) ||
				     ((entrytmp.protoType == PROTO_TCP) && portEntry.protoType == PROTO_BOTH) ||
				     ((entrytmp.protoType == PROTO_UDP) && portEntry.protoType == PROTO_BOTH))) {
					strcpy(tmpBuf, ("rule already exist!"));
					goto setErr_filter;
				}
				if ((((entrytmp.fromPort <= portEntry.fromPort) &&
				      (entrytmp.toPort >= portEntry.fromPort)) ||
				     ((entrytmp.fromPort <= portEntry.toPort) &&
				      (entrytmp.toPort >= portEntry.toPort))) &&
				    ((entrytmp.protoType == portEntry.protoType) ||
				     ((entrytmp.protoType == PROTO_BOTH) && portEntry.protoType == PROTO_UDP) ||
				     ((entrytmp.protoType == PROTO_BOTH) && portEntry.protoType == PROTO_TCP) ||
				     ((entrytmp.protoType == PROTO_TCP) && portEntry.protoType == PROTO_BOTH) ||
				     ((entrytmp.protoType == PROTO_UDP) && portEntry.protoType == PROTO_BOTH))) {
					strcpy(tmpBuf, ("port overlap!"));
					goto setErr_filter;
				}
				if ((((entrytmp.fromPort >= portEntry.fromPort) &&
				      (entrytmp.fromPort <= portEntry.toPort)) ||
				     ((entrytmp.toPort >= portEntry.fromPort) &&
				      (entrytmp.toPort <= portEntry.toPort))) &&
				    ((entrytmp.protoType == portEntry.protoType) ||
				     ((entrytmp.protoType == PROTO_BOTH) && portEntry.protoType == PROTO_UDP) ||
				     ((entrytmp.protoType == PROTO_BOTH) && portEntry.protoType == PROTO_TCP) ||
				     ((entrytmp.protoType == PROTO_TCP) && portEntry.protoType == PROTO_BOTH) ||
				     ((entrytmp.protoType == PROTO_UDP) && portEntry.protoType == PROTO_BOTH))) {
					strcpy(tmpBuf, ("port overlap!"));
					goto setErr_filter;
				}
			}
		}
	}

	if (strAddIp[0]) {
		apmib_get(MIB_IPFILTER_TBL_NUM, (void *)&entryNum);
		for (j = 1; j <= entryNum; j++) {
			memset(&ipentrytmp, 0x00, sizeof(ipentrytmp));
			*((char *)&ipentrytmp) = (char)j;
			if (apmib_get(MIB_IPFILTER_TBL, (void *)&ipentrytmp)) {
#ifdef RTL_IPFILTER_SUPPORT_IP_RANGE
				if (strEndIpAddr[0]) {
					if (((*((unsigned int *)ipentrytmp.ipAddr)) == (*((unsigned int *)ipEntry.ipAddr))) &&
					    ((*((unsigned int *)ipentrytmp.ipAddrEnd)) == (*((unsigned int *)ipEntry.ipAddrEnd))) &&
					    ((ipentrytmp.protoType == ipEntry.protoType) ||
					     (ipentrytmp.protoType == PROTO_BOTH && ipEntry.protoType == PROTO_TCP) ||
					     (ipentrytmp.protoType == PROTO_BOTH && ipEntry.protoType == PROTO_UDP) ||
					     (ipentrytmp.protoType == PROTO_TCP && ipEntry.protoType == PROTO_BOTH) ||
					     (ipentrytmp.protoType == PROTO_UDP && ipEntry.protoType == PROTO_BOTH))) {
						strcpy(tmpBuf, ("rule already exist!"));
						goto setErr_filter;
					}
					if (((((*((unsigned int *)ipentrytmp.ipAddrEnd)) >= (*((unsigned int *)ipEntry.ipAddrEnd))) &&
					      ((*((unsigned int *)ipentrytmp.ipAddr)) <= (*((unsigned int *)ipEntry.ipAddrEnd)))) ||
					     (((*((unsigned int *)ipentrytmp.ipAddrEnd)) >= (*((unsigned int *)ipEntry.ipAddr))) &&
					      ((*((unsigned int *)ipentrytmp.ipAddr)) <= (*((unsigned int *)ipEntry.ipAddr))))) &&
					    ((ipentrytmp.protoType == ipEntry.protoType) ||
					     (ipentrytmp.protoType == PROTO_BOTH && ipEntry.protoType == PROTO_TCP) ||
					     (ipentrytmp.protoType == PROTO_BOTH && ipEntry.protoType == PROTO_UDP) ||
					     (ipentrytmp.protoType == PROTO_TCP && ipEntry.protoType == PROTO_BOTH) ||
					     (ipentrytmp.protoType == PROTO_UDP && ipEntry.protoType == PROTO_BOTH))) {
						strcpy(tmpBuf, ("ip address overlap!"));
						goto setErr_filter;
					}
					if (((((*((unsigned int *)ipEntry.ipAddrEnd)) >= (*((unsigned int *)ipentrytmp.ipAddrEnd))) &&
					      ((*((unsigned int *)ipEntry.ipAddr)) <= (*((unsigned int *)ipentrytmp.ipAddrEnd)))) ||
					     (((*((unsigned int *)ipEntry.ipAddrEnd)) >= (*((unsigned int *)ipentrytmp.ipAddr))) &&
					      ((*((unsigned int *)ipEntry.ipAddr)) <= (*((unsigned int *)ipentrytmp.ipAddr))))) &&
					    ((ipentrytmp.protoType == ipEntry.protoType) ||
					     (ipentrytmp.protoType == PROTO_BOTH && ipEntry.protoType == PROTO_TCP) ||
					     (ipentrytmp.protoType == PROTO_BOTH && ipEntry.protoType == PROTO_UDP) ||
					     (ipentrytmp.protoType == PROTO_TCP && ipEntry.protoType == PROTO_BOTH) ||
					     (ipentrytmp.protoType == PROTO_UDP && ipEntry.protoType == PROTO_BOTH))) {
						strcpy(tmpBuf, ("ip address overlap!"));
						goto setErr_filter;
					}
				} else {
					if ((((*((unsigned int *)ipentrytmp.ipAddrEnd)) >= (*((unsigned int *)ipEntry.ipAddr))) &&
					     ((*((unsigned int *)ipentrytmp.ipAddr)) <= (*((unsigned int *)ipEntry.ipAddr)))) ||
					    (((*((unsigned int *)ipentrytmp.ipAddrEnd)) == (*((unsigned int *)ipEntry.ipAddr))) ||
					     ((*((unsigned int *)ipentrytmp.ipAddr)) == (*((unsigned int *)ipEntry.ipAddr)))) &&
					    ((ipentrytmp.protoType == ipEntry.protoType) ||
					     (ipentrytmp.protoType == PROTO_BOTH && ipEntry.protoType == PROTO_TCP) ||
					     (ipentrytmp.protoType == PROTO_BOTH && ipEntry.protoType == PROTO_UDP) ||
					     (ipentrytmp.protoType == PROTO_TCP && ipEntry.protoType == PROTO_BOTH) ||
					     (ipentrytmp.protoType == PROTO_UDP && ipEntry.protoType == PROTO_BOTH))) {
						strcpy(tmpBuf, ("ip address overlap!"));
						goto setErr_filter;
					}
				}
#else
				p = (unsigned int *)ipentrytmp.ipAddr;
				q = (unsigned int *)ipEntry.ipAddr;
				if ((*p == *q) &&
				    ((ipentrytmp.protoType == ipEntry.protoType) ||
				     (ipentrytmp.protoType == PROTO_BOTH && ipEntry.protoType == PROTO_TCP) ||
				     (ipentrytmp.protoType == PROTO_BOTH && ipEntry.protoType == PROTO_UDP) ||
				     (ipentrytmp.protoType == PROTO_TCP && ipEntry.protoType == PROTO_BOTH) ||
				     (ipentrytmp.protoType == PROTO_UDP && ipEntry.protoType == PROTO_BOTH))) {
					strcpy(tmpBuf, ("rule already exist!"));
					goto setErr_filter;
				}
#endif
			}
		}
	}

	if (strAddIp[0] || strAddPort[0] || strAddMac[0] || strAddUrl[0]) {
		if (strComment[0]) {
			if (strlen(strComment) > COMMENT_LEN - 1) {
				strcpy(tmpBuf, ("Error! Comment length too long."));
				goto setErr_filter;
			}
			if (strAddIp[0])
				strcpy((char *)ipEntry.comment, strComment);
			else if (strAddPort[0])
				strcpy((char *)portEntry.comment, strComment);
			else if (strAddMac[0])
				strcpy((char *)macEntry.comment, strComment);
		}

		if (!apmib_get(num_id, (void *)&entryNum)) {
			strcpy(tmpBuf, ("Get entry number error!"));
			goto setErr_filter;
		}
		if (strAddUrl[0]) {
			if ((entryNum + 1) > MAX_URLFILTER_NUM) {
				strcpy(tmpBuf, ("Cannot add new URL entry because table is full!"));
				goto setErr_filter;
			}
		} else {
			if ((entryNum + 1) > MAX_FILTER_NUM) {
				strcpy(tmpBuf, ("Cannot add new entry because table is full!"));
				goto setErr_filter;
			}
		}
#ifdef __DAVO__
		if (strAddMac[0]) {
			int ret;
			strVal = req_get_cstream_var(wp, ("port"), "");
			if (!strVal[0]) {
				strcpy(tmpBuf, ("오류! 포트를 설정해야 합니다."));
				goto setErr_filter;
			}
			if ((ret = DvAddMacFilterEntry(pEntry, atoi(strVal))) < 0) {
				if (ret == -2)
					strcpy(tmpBuf, ("오류! 중복되었습니다."));
				else
					strcpy(tmpBuf, ("오류! mac 필터 설정 실패."));
				goto setErr_filter;
			}
		}
#endif
		// set to MIB. try to delete it first to avoid duplicate case
		if (strAddIp[0] || strAddPort[0] || strAddUrl[0]) {
			apmib_set(del_id, pEntry);
			if (apmib_set(add_id, pEntry) == 0) {
				strcpy(tmpBuf, ("Add table entry error!"));
				goto setErr_filter;
			}
		}
	}

	/* Delete entry */
	if (strDelPort[0] || strDelIp[0] || strDelUrl[0]) {
		if (!apmib_get(num_id, (void *)&entryNum)) {
			strcpy(tmpBuf, ("Get entry number error!"));
			goto setErr_filter;
		}
		for (i = entryNum; i > 0; i--) {
			sprintf(tmpBuf, "select%d", i);

			strVal = req_get_cstream_var(wp, (tmpBuf), "");
			if (!strcmp(strVal, "ON")) {

				*((char *)pEntry) = (char)i;
				if (!apmib_get(get_id, pEntry)) {
					strcpy(tmpBuf, ("Get table entry error!"));
					goto setErr_filter;
				}
				if (!apmib_set(del_id, pEntry)) {
					strcpy(tmpBuf, ("Delete table entry error!"));
					goto setErr_filter;
				}
			}
		}
	}
#ifdef __DAVO__
	if (!strAddMac[0] && (strDelMac[0] || strModeMac[0])) {
		int cnt_del = 0;

		if (!nvram_get_r("x_MACFILTER_TBL_NUM", tmpBuf, sizeof(tmpBuf))) {
			apmib_nvram_set("x_MACFILTER_TBL_NUM", "0");
			entryNum = 0;
		} else {
			entryNum = safe_atoi(tmpBuf, 0);
		}

		for (i = entryNum; i > 0; i--) {
			sprintf(tmpBuf, "select%d", i);

			strVal = req_get_cstream_var(wp, (tmpBuf), "");
			if (!strcmp(strVal, ("ON"))) {
				DvDeleteMacFilterEntry(entryNum - cnt_del, i);
				cnt_del++;
			}
		}
		if (cnt_del > 0)
			DvAlignMacFilterEntry(entryNum);

		for (i = 1; i <= 4; i++) {
			sprintf(tmpBuf, "opmode%d", i);
			strVal = req_get_cstream_var(wp, (tmpBuf), "drop");
			if (strVal) {
				DvChangePortMode(i, strVal);
			}
		}
	}
#endif

	/* Delete all entry */
	if (strDelAllPort[0] || strDelAllIp[0] || strDelAllMac[0] || strDelAllUrl[0]) {
		if (!apmib_set(delall_id, pEntry)) {
			strcpy(tmpBuf, ("Delete all table error!"));
			goto setErr_filter;
		}
	}
 setOk_filter:
	apmib_update_web(CURRENT_SETTING);

#ifndef NO_ACTION
	pid = fork();
	if (pid) {
		waitpid(pid, NULL, 0);
	} else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _FIREWALL_SCRIPT_PROG);
		execl(tmpBuf, _FIREWALL_SCRIPT_PROG, NULL);
		exit(1);
	}
#endif

#ifdef __DAVO__
	nvram_commit();
	need_reboot = 1;
	OK_MSG(submitUrl);
#else
#ifdef REBOOT_CHECK
	if (needReboot == 1) {
		OK_MSG(submitUrl);
		return;
	}

	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);
#endif
#endif				// __DAVO__
	return;

 setErr_filter:
	ERR_MSG(tmpBuf);
}

#if 0
/////////////////////////////////////////////////////////////////////////////
void formTriggerPort(request *wp, char *path, char *query)
{
	char *strAddPort, *strDelAllPort, *strDelPort, *strVal, *submitUrl;
	char *strTriFrom, *strTriTo, *strIncFrom, *strIncTo, *strComment;
	char tmpBuf[100];
	int entryNum, intVal, i;
	TRIGGERPORT_T entry;

	memset(&entry, '\0', sizeof(entry));

	/* Add port filter */
	strAddPort = req_get_cstream_var(wp, ("addPort"), "");
	if (strAddPort[0]) {
		strVal = req_get_cstream_var(wp, ("enabled"), "");
		if ( !strcmp(strVal, "ON"))
			intVal = 1;
		else
			intVal = 0;

		if ( apmib_set(MIB_TRIGGERPORT_ENABLED, (void *)&intVal) == 0) {
			strcpy(tmpBuf, ("Set enabled flag error!"));
			goto setErr_triPort;
		}

		strTriFrom = req_get_cstream_var(wp, ("triFromPort"), "");
		strTriTo = req_get_cstream_var(wp, ("triToPort"), "");
		strIncFrom = req_get_cstream_var(wp, ("incFromPort"), "");
		strIncTo = req_get_cstream_var(wp, ("incToPort"), "");
		strComment = req_get_cstream_var(wp, ("comment"), "");

		if (!strTriFrom[0] && !strTriTo[0] && !strIncFrom[0] &&
					!strIncTo[0] && !strComment[0])
			goto setOk_triPort;

		// get trigger port range and protocol
		if (!strTriFrom[0]) { // from port must exist
			strcpy(tmpBuf, ("Error! No from-port value to be set."));
			goto setErr_triPort;
		}
		if ( !string_to_dec(strTriFrom, &intVal) || intVal<1 || intVal>65535) {
			strcpy(tmpBuf, ("Error! Invalid value of trigger from-port."));
			goto setErr_triPort;
		}
		entry.tri_fromPort = (unsigned short)intVal;

		if ( !strTriTo[0] )
			entry.tri_toPort = entry.tri_fromPort;
		else {
			if ( !string_to_dec(strTriTo, &intVal) || intVal<1 || intVal>65535) {
				strcpy(tmpBuf, ("Error! Invalid value of trigger to-port."));
				goto setErr_triPort;
			}
			entry.tri_toPort = (unsigned short)intVal;
		}

		if ( entry.tri_fromPort  > entry.tri_toPort ) {
			strcpy(tmpBuf, ("Error! Invalid trigger port range."));
			goto setErr_triPort;
		}

		strVal = req_get_cstream_var(wp, ("triProtocol"), "");
		if (strVal[0]) {
			if ( strVal[0] == '0' ) {
				if (strAddPort[0])
					entry.tri_protoType = PROTO_BOTH;
				else
					entry.tri_protoType = PROTO_BOTH;
			}
			else if ( strVal[0] == '1' ) {
				if (strAddPort[0])
					entry.tri_protoType = PROTO_TCP;
				else
					entry.tri_protoType = PROTO_TCP;
			}
			else if ( strVal[0] == '2' ) {
				if (strAddPort[0])
					entry.tri_protoType = PROTO_UDP;
				else
					entry.tri_protoType = PROTO_UDP;
			}
			else {
				strcpy(tmpBuf, ("Error! Invalid trigger-port protocol type."));
				goto setErr_triPort;
			}
		}
		else {
			strcpy(tmpBuf, ("Error! trigger-port protocol type cannot be empty."));
			goto setErr_triPort;
		}

		// get incoming port range and protocol
		if (!strIncFrom[0]) { // from port must exist
			strcpy(tmpBuf, ("Error! No from-port value to be set."));
			goto setErr_triPort;
		}
		if ( !string_to_dec(strIncFrom, &intVal) || intVal<1 || intVal>65535) {
			strcpy(tmpBuf, ("Error! Invalid value of incoming from-port."));
			goto setErr_triPort;
		}
		entry.inc_fromPort = (unsigned short)intVal;

		if ( !strIncTo[0] )
			entry.inc_toPort = entry.inc_fromPort;
		else {
			if ( !string_to_dec(strIncTo, &intVal) || intVal<1 || intVal>65535) {
				strcpy(tmpBuf, ("Error! Invalid value of incoming to-port."));
				goto setErr_triPort;
			}
			entry.inc_toPort = (unsigned short)intVal;
		}

		if ( entry.inc_fromPort  > entry.inc_toPort ) {
			strcpy(tmpBuf, ("Error! Invalid incoming port range."));
			goto setErr_triPort;
		}


		strVal = req_get_cstream_var(wp, ("incProtocol"), "");
		if (strVal[0]) {
			if ( strVal[0] == '0' ) {
				if (strAddPort[0])
					entry.inc_protoType = PROTO_BOTH;
				else
					entry.inc_protoType = PROTO_BOTH;
			}
			else if ( strVal[0] == '1' ) {
				if (strAddPort[0])
					entry.inc_protoType = PROTO_TCP;
				else
					entry.inc_protoType = PROTO_TCP;
			}
			else if ( strVal[0] == '2' ) {
				if (strAddPort[0])
					entry.inc_protoType = PROTO_UDP;
				else
					entry.inc_protoType = PROTO_UDP;
			}
			else {
				strcpy(tmpBuf, ("Error! Invalid incoming-port protocol type."));
				goto setErr_triPort;
			}
		}
		else {
			strcpy(tmpBuf, ("Error! incoming-port protocol type cannot be empty."));
			goto setErr_triPort;
		}

		// get comment
		if ( strComment[0] ) {
			if (strlen(strComment) > COMMENT_LEN-1) {
				strcpy(tmpBuf, ("Error! Comment length too long."));
				goto setErr_triPort;
			}
			strcpy(entry.comment, strComment);
		}

		// get entry number to see if it exceeds max
		if ( !apmib_get(MIB_TRIGGERPORT_TBL_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, ("Get entry number error!"));
			goto setErr_triPort;
		}
		if ( (entryNum + 1) > MAX_FILTER_NUM) {
			strcpy(tmpBuf, ("Cannot add new entry because table is full!"));
			goto setErr_triPort;
		}

		// Check if there is any port overlapped
		for (i=1; i<=entryNum; i++) {
			TRIGGERPORT_T checkEntry;
			*((char *)&checkEntry) = (char)i;
			if ( !apmib_get(MIB_TRIGGERPORT_TBL, (void *)&checkEntry)) {
				strcpy(tmpBuf, ("Get table entry error!"));
				goto setErr_triPort;
			}
			if ( ( (entry.tri_fromPort <= checkEntry.tri_fromPort &&
					entry.tri_toPort >= checkEntry.tri_fromPort) ||
			       (entry.tri_fromPort >= checkEntry.tri_fromPort &&
				entry.tri_fromPort <= checkEntry.tri_toPort)
			     )&&
			       (entry.tri_protoType & checkEntry.tri_protoType) ) {
				strcpy(tmpBuf, ("Trigger port range has overlapped with used port numbers!"));
				goto setErr_triPort;
			}
		}

		// set to MIB. try to delete it first to avoid duplicate case
		apmib_set(MIB_TRIGGERPORT_DEL, (void *)&entry);
		if ( apmib_set(MIB_TRIGGERPORT_ADD, (void *)&entry) == 0) {
			strcpy(tmpBuf, ("Add table entry error!"));
			goto setErr_triPort;
		}
	}

	/* Delete entry */
	strDelPort = req_get_cstream_var(wp, ("deleteSelPort"), "");
	if (strDelPort[0]) {
		if ( !apmib_get(MIB_TRIGGERPORT_TBL_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, ("Get entry number error!"));
			goto setErr_triPort;
		}
		for (i=entryNum; i>0; i--) {
			snprintf(tmpBuf, 20, "select%d", i);

			strVal = req_get_cstream_var(wp, tmpBuf, "");
			if ( !strcmp(strVal, "ON") ) {

				*((char *)&entry) = (char)i;
				if ( !apmib_get(MIB_TRIGGERPORT_TBL, (void *)&entry)) {
					strcpy(tmpBuf, ("Get table entry error!"));
					goto setErr_triPort;
				}
				if ( !apmib_set(MIB_TRIGGERPORT_DEL, (void *)&entry)) {
					strcpy(tmpBuf, ("Delete table entry error!"));
					goto setErr_triPort;
				}
			}
		}
	}

	/* Delete all entry */
	strDelAllPort = req_get_cstream_var(wp, ("deleteAllPort"), "");
	if ( strDelAllPort[0]) {
		if ( !apmib_set(MIB_TRIGGERPORT_DELALL, (void *)&entry)) {
			strcpy(tmpBuf, ("Delete all table error!"));
			goto setErr_triPort;
		}
	}

setOk_triPort:
	apmib_update_web(CURRENT_SETTING);

	submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page
	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);
  	return;

setErr_triPort:
	ERR_MSG(tmpBuf);
}
#endif

#if defined(CONFIG_RTK_VLAN_WAN_TAG_SUPPORT)
void formVlanWAN(request *wp, char *path, char *query)
{
	VLAN_CONFIG_T entry;
	char *submitUrl,*strTmp;
	int	value;
	struct nameMapping *mapping;
	char tmpBuf[100];

	value = !strcmp(req_get_cstream_var(wp, ("vlan_wan_enable"), ("")), "on");
	if (!apmib_set(MIB_VLAN_WAN_ENALE, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLANCONFIG_ENABLED error!"));
		goto setErr;
	}
	value =  atoi(req_get_cstream_var(wp, ("vlan_wan_tag"), ("0")));
	if(strcmp(req_get_cstream_var(wp, ("vlan_wan_enable"), ("")), "on"))
		value = 0;

	if (!apmib_set(MIB_VLAN_WAN_TAG, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_TAG error!"));
		goto setErr;
	}

	value = !strcmp(req_get_cstream_var(wp, ("vlan_wan_host_enable"), ("")), "on");
	if (!apmib_set(MIB_VLAN_WAN_HOST_ENABLE, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_HOST_ENALE error!"));
		goto setErr;
	}
	value =  atoi(req_get_cstream_var(wp, ("vlan_wan_host_tag"), ("0")));
	if (!apmib_set(MIB_VLAN_WAN_HOST_TAG, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_HOST_TAG error!"));
		goto setErr;
	}
	value =  atoi(req_get_cstream_var(wp, ("vlan_wan_host_pri"), ("0")));
	if(strcmp(req_get_cstream_var(wp, ("vlan_wan_enable"), ("")), "on"))
		value = 0;
	if (!apmib_set(MIB_VLAN_WAN_HOST_PRI, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_HOST_PRI error!"));
		goto setErr;
	}

	value = !strcmp(req_get_cstream_var(wp, ("vlan_wan_wifi_root_enable"), ("")), "on");
	if (!apmib_set(MIB_VLAN_WAN_WIFI_ROOT_ENABLE, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_WIFI_ROOT_ENALE error!"));
		goto setErr;
	}
	value =  atoi(req_get_cstream_var(wp, ("vlan_wan_wifi_root_tag"), ("0")));
	if (!apmib_set(MIB_VLAN_WAN_WIFI_ROOT_TAG, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_WIFI_ROOT_TAG error!"));
		goto setErr;
	}
	value =  atoi(req_get_cstream_var(wp, ("vlan_wan_wifi_root_pri"), ("0")));
	if (!apmib_set(MIB_VLAN_WAN_WIFI_ROOT_PRI, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_WIFI_ROOT_PRI error!"));
		goto setErr;
	}

	value = !strcmp(req_get_cstream_var(wp, ("vlan_wan_wifi_vap0_enable"), ("")), "on");
	if (!apmib_set(MIB_VLAN_WAN_WIFI_VAP0_ENABLE, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_WIFI_VAP0_ENALE error!"));
		goto setErr;
	}
	value =  atoi(req_get_cstream_var(wp, ("vlan_wan_wifi_vap0_tag"), ("0")));
	if (!apmib_set(MIB_VLAN_WAN_WIFI_VAP0_TAG, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_WIFI_VAP0_TAG error!"));
		goto setErr;
	}
	value =  atoi(req_get_cstream_var(wp, ("vlan_wan_wifi_vap0_pri"), ("0")));
	if (!apmib_set(MIB_VLAN_WAN_WIFI_VAP0_PRI, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_WIFI_VAP0_PRI error!"));
		goto setErr;
	}

	value = !strcmp(req_get_cstream_var(wp, ("vlan_wan_wifi_vap1_enable"), ("")), "on");
	if (!apmib_set(MIB_VLAN_WAN_WIFI_VAP1_ENABLE, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_WIFI_VAP1_ENALE error!"));
		goto setErr;
	}
	value =  atoi(req_get_cstream_var(wp, ("vlan_wan_wifi_vap1_tag"), ("0")));
	if (!apmib_set(MIB_VLAN_WAN_WIFI_VAP1_TAG, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_WIFI_VAP1_TAG error!"));
		goto setErr;
	}
	value =  atoi(req_get_cstream_var(wp, ("vlan_wan_wifi_vap1_pri"), ("0")));
	if (!apmib_set(MIB_VLAN_WAN_WIFI_VAP1_PRI, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_WIFI_VAP1_PRI error!"));
		goto setErr;
	}

	value = !strcmp(req_get_cstream_var(wp, ("vlan_wan_wifi_vap2_enable"), ("")), "on");
	if (!apmib_set(MIB_VLAN_WAN_WIFI_VAP2_ENABLE, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_WIFI_VAP2_ENALE error!"));
		goto setErr;
	}
	value =  atoi(req_get_cstream_var(wp, ("vlan_wan_wifi_vap2_tag"), ("0")));
	if (!apmib_set(MIB_VLAN_WAN_WIFI_VAP2_TAG, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_WIFI_VAP0_TAG error!"));
		goto setErr;
	}
	value =  atoi(req_get_cstream_var(wp, ("vlan_wan_wifi_vap2_pri"), ("0")));
	if (!apmib_set(MIB_VLAN_WAN_WIFI_VAP2_PRI, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_WIFI_VAP2_PRI error!"));
		goto setErr;
	}

	value = !strcmp(req_get_cstream_var(wp, ("vlan_wan_wifi_vap3_enable"), ("")), "on");
	if (!apmib_set(MIB_VLAN_WAN_WIFI_VAP3_ENABLE, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_WIFI_VAP3_ENALE error!"));
		goto setErr;
	}
	value =  atoi(req_get_cstream_var(wp, ("vlan_wan_wifi_vap3_tag"), ("0")));
	if (!apmib_set(MIB_VLAN_WAN_WIFI_VAP3_TAG, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_WIFI_VAP3_TAG error!"));
		goto setErr;
	}
	value =  atoi(req_get_cstream_var(wp, ("vlan_wan_wifi_vap3_pri"), ("0")));
	if (!apmib_set(MIB_VLAN_WAN_WIFI_VAP3_PRI, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_WIFI_VAP3_PRI error!"));
		goto setErr;
	}


	value = !strcmp(req_get_cstream_var(wp, ("vlan_wan_bridge_enable"), ("")), "on");
	if (!apmib_set(MIB_VLAN_WAN_BRIDGE_ENABLE, (void *)&value))
	{
		strcpy(tmpBuf, ("set  VLAN_WAN_BRIDGE_ENABLE error!"));
		goto setErr;
	}
	value =  atoi(req_get_cstream_var(wp, ("vlan_wan_bridge_tag"), ("0")));
	if(strcmp(req_get_cstream_var(wp, ("vlan_wan_bridge_enable"), ("")), "on"))
		value = 0;

	if (!apmib_set(MIB_VLAN_WAN_BRIDGE_TAG, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_BRIDGE_TAG error!"));
		goto setErr;
	}
	value = !strcmp(req_get_cstream_var(wp, ("vlan_wan_bridge_multicast_enable"), ("")), "on");

	if (!apmib_set(MIB_VLAN_WAN_BRIDGE_MULTICAST_ENABLE, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_BRIDGE_MULTICAST_ENABLE error!"));
		goto setErr;
	}
	value =  atoi(req_get_cstream_var(wp, ("vlan_wan_bridge_multicast_tag"), ("0")));
	if(strcmp(req_get_cstream_var(wp, ("vlan_wan_bridge_multicast_enable"), ("")), "on"))
		value = 0;

	if (!apmib_set(MIB_VLAN_WAN_BRIDGE_MULTICAST_TAG, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_BRIDGE_MULTICAST_TAG error!"));
		goto setErr;
	}
	value = 0;
	value |= (!strcmp(req_get_cstream_var(wp, ("vlan_wan_bridge_port_0"), ("")), "on"))<<3;
	value |= (!strcmp(req_get_cstream_var(wp, ("vlan_wan_bridge_port_1"), ("")), "on"))<<2;
	value |= (!strcmp(req_get_cstream_var(wp, ("vlan_wan_bridge_port_2"), ("")), "on"))<<1;
	value |= (!strcmp(req_get_cstream_var(wp, ("vlan_wan_bridge_port_3"), ("")), "on"))<<0;
	value |= (!strcmp(req_get_cstream_var(wp, ("vlan_wan_bridge_port_wifi_root"), ("")), "on"))<<6;
	value |= (!strcmp(req_get_cstream_var(wp, ("vlan_wan_bridge_port_wifi_vap0"), ("")), "on"))<<7;
	value |= (!strcmp(req_get_cstream_var(wp, ("vlan_wan_bridge_port_wifi_vap1"), ("")), "on"))<<8;
	value |= (!strcmp(req_get_cstream_var(wp, ("vlan_wan_bridge_port_wifi_vap2"), ("")), "on"))<<9;
	value |= (!strcmp(req_get_cstream_var(wp, ("vlan_wan_bridge_port_wifi_vap3"), ("")), "on"))<<10;
	if (!apmib_set(MIB_VLAN_WAN_BRIDGE_PORT, (void *)&value))
	{
		strcpy(tmpBuf, ("set  MIB_VLAN_WAN_BRIDGEPORT error!"));
		goto setErr;
	}


	apmib_update_web(CURRENT_SETTING);

	#ifndef NO_ACTION
		run_init_script("all");
	#endif

	OK_MSG("/skb_vlan_wan.htm");
	return;

	setErr:
	ERR_MSG(tmpBuf);

	return;

}
#endif

/////////////////////////////////////////////////////////////////////////////
void formDMZ(request *wp, char *path, char *query)
{
	char *submitUrl, *strSave, *strVal;
	char tmpBuf[100];
	int intVal;
	struct in_addr ipAddr, curIpAddr, curSubnet;
	unsigned long v1, v2, v3;
#ifndef NO_ACTION
	int pid;
#endif
	apmib_set_hist_clear();
#ifdef __DAVO__
	strSave = req_get_cstream_var(wp, ("save"), "");

	if (strSave[0]) {
		strVal = req_get_cstream_var(wp, ("dmzMode"), "");

		if (!strcmp(strVal, "dmz")) {
			intVal = 1;

			if (apmib_set(MIB_DMZ_ENABLED, (void *)&intVal) == 0) {
				strcpy(tmpBuf, ("Set dmz enabled flag error!"));
				goto setErr_dmz;
			}

			strVal = req_get_cstream_var(wp, ("ip"), "");
			if (!strVal[0]) {
				goto setOk_dmz;
			}
			inet_aton(strVal, &ipAddr);
			getInAddr(BRIDGE_IF, IP_ADDR, (void *)&curIpAddr);
			getInAddr(BRIDGE_IF, SUBNET_MASK, (void *)&curSubnet);

			v1 = ipAddr.s_addr;
			v2 = curIpAddr.s_addr;
			v3 = curSubnet.s_addr;
			if (v1) {
				if ((v1 & v3) != (v2 & v3)) {
					strcpy(tmpBuf, ("Invalid IP address! It should be set within the current subnet."));
					goto setErr_dmz;
				}
			}
			if (apmib_set(MIB_DMZ_HOST, (void *)&ipAddr) == 0) {
				strcpy(tmpBuf, ("Set DMZ MIB error!"));
				goto setErr_dmz;
			}

			if (nvram_get("x_SDMZ_ENABLED")) {
				apmib_nvram_set("x_SDMZ_ENABLED", "0");
			}
		} else if (!strcmp(strVal, "sdmz")) {
			char org[12];
			memset(org, 0, sizeof(org));

			if (apmib_nvram_set("x_SDMZ_ENABLED", "1") != 0) {
				strcpy(tmpBuf, ("Set sdmz enabled flag error!"));
				goto setErr_dmz;
			}

			strVal = req_get_cstream_var(wp, ("mac"), "");
			if (!strVal[0]) {
				goto setOk_dmz;
			}
			unsigned char mac[6];
			if (get_mac_addr(strVal, mac)) {
				sprintf(tmpBuf, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1],
					mac[2], mac[3], mac[4], mac[5]);
				apmib_nvram_set("x_SDMZ_HOST", tmpBuf);
			}

			apmib_get(MIB_DMZ_ENABLED, (void *)&intVal);
			if (intVal) {
				intVal = 0;
				apmib_set(MIB_DMZ_ENABLED, (void *)&intVal);
			}
		} else if (!strcmp(strVal, "disable")) {
			apmib_get(MIB_DMZ_ENABLED, (void *)&intVal);
			if (intVal) {
				intVal = 0;
				apmib_set(MIB_DMZ_ENABLED, (void *)&intVal);
			}
			strcpy(strVal, "0.0.0.0");
			inet_aton(strVal, &ipAddr);
			if (apmib_set(MIB_DMZ_HOST, (void *)&ipAddr) == 0) {
				strcpy(tmpBuf, ("Set DMZ MIB error!"));
				goto setErr_dmz;
			}

			if (nvram_get("x_SDMZ_ENABLED")) {
				apmib_nvram_set("x_SDMZ_ENABLED", "0");
			}
		}
	}
#endif
 setOk_dmz:
 	web_config_trace(3, 4);		/* firewall/dmz */
	apmib_update_web(CURRENT_SETTING);

#ifdef __DAVO__
	submitUrl = req_get_cstream_var(wp, "submit-url", "");	// hidden page
	nvram_commit();
	need_reboot = 1;
	OK_MSG("/skb_dmz.htm");
	return;
#endif
#ifndef NO_ACTION
	pid = fork();
	if (pid) {
		waitpid(pid, NULL, 0);
	} else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _FIREWALL_SCRIPT_PROG);
		execl(tmpBuf, _FIREWALL_SCRIPT_PROG, NULL);
		exit(1);
	}
#endif
	submitUrl = req_get_cstream_var(wp, "submit-url", "");	// hidden page
	nvram_commit();
	needReboot = 1;

#ifdef REBOOT_CHECK
	if (needReboot == 1) {
		OK_MSG(submitUrl);
		return;
	}
#endif
	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);
	return;

 setErr_dmz:
	ERR_MSG(tmpBuf);
}

/////////////////////////////////////////////////////////////////////////////
int staticMappingTbl(request *wp, int argc, char **argv)
{
	char *s_ip, *d_ip, *type;
	char s_sip[30], d_sip[30];
	int entry_num, nBytesSent=0, i;
	staticfwd_t entry[STATICFWD_MAX_ENTRY];

	nBytesSent += req_format_write(wp, "<tr class=\"tbl_head\">"
		"<td align=\"center\"><p><font size=2><b>출발지 주소</b></td>\n"
		"<td align=\"center\"><p><font size=2><b>출발지 포트</b></td>\n"
		"<td align=\"center\"><p><font size=2><b>&nbsp;프로토콜&nbsp;</b></td>\n"
		"<td align=\"center\"><p><font size=2><b>목적지 주소</b></td>\n"
		"<td align=\"center\"><p><font size=2><b>목적지 포트</b></td>\n"
		"<td align=center width=\"8%%\"><font size=\"2\"><b>선택</b></font></td></tr>\n");

	if ( (entry_num = fget_staticfwd(entry, STATICFWD_MAX_ENTRY)) > 0) {
		for (i=0; i < entry_num; i++) {
			s_ip = inet_ntoa(*((struct in_addr *)&(entry[i].sip)));
			if ( s_ip && !strcmp(s_ip, "0.0.0.0"))
				sprintf(s_sip, "----");
			else
				sprintf(s_sip, "%s", s_ip);

			d_ip = inet_ntoa(*((struct in_addr *)&(entry[i].dip)));
			if ( d_ip && !strcmp(d_ip, "0.0.0.0"))
				sprintf(d_sip, "----");
			else
				sprintf(d_sip, "%s", d_ip);

			if ( entry[i].proto == MAPPING_BOTH )
				type = "TCP+UDP";
			else if ( entry[i].proto == MAPPING_TCP )
				type = "TCP";
			else
				type = "UDP";

			nBytesSent += req_format_write(wp, "<tr class=\"tbl_body\">"
						"<td align=center><font size=\"2\">%s</td>\n"
						"<td align=center><font size=\"2\">%d</td>\n"
						"<td align=center><font size=\"2\">%s</td>\n"
						"<td align=center><font size=\"2\">%s</td>\n"
						"<td align=center><font size=\"2\">%d</td>\n"
						"<td align=center width=\"8%%\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td></tr>\n",
					s_sip, entry[i].sport, type, d_sip, entry[i].dport,  i);
		}
	}
	return nBytesSent;
}

int portFwList(request *wp, int argc, char **argv)
{
	int	nBytesSent=0, entryNum, i, j, comment_len;
	PORTFW_T entry;
	char	*type, portRange[20], *ip;
	char *args[2], *p, temp[256], t_portRange[20], comment[32];
    int t_fromPort=0, ac=0;

	if ( !apmib_get(MIB_PORTFW_TBL_NUM, (void *)&entryNum)) {
  		fprintf(stderr, "Get table entry error!\n");
		return -1;
	}

	nBytesSent += req_format_write(wp, ("<tr class=\"tbl_head\">"
      	"<td align=center width=\"20%%\" ><font size=\"2\"><b>서비스포트</b></font></td>\n"
      	"<td align=center width=\"20%%\" ><font size=\"2\"><b>프로토콜</b></font></td>\n"
      	"<td align=center width=\"20%%\" ><font size=\"2\"><b>내부IP주소</b></font></td>\n"
      	"<td align=center width=\"15%%\" ><font size=\"2\"><b>포트</b></font></td>\n"
		"<td align=center width=\"15%%\" ><font size=\"2\"><b>설명</b></font></td>\n"
      	"<td align=center width=\"10%%\" ><font size=\"2\"><b>삭제</b></font></td></tr>\n"));

	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_PORTFW_TBL, (void *)&entry))
			return -1;

		ip = inet_ntoa(*((struct in_addr *)entry.ipAddr));
		if ( !strcmp(ip, "0.0.0.0"))
			ip = "----";

		if ( entry.protoType == PROTO_BOTH )
			type = "TCP+UDP";
		else if ( entry.protoType == PROTO_TCP )
			type = "TCP";
		else
			type = "UDP";

		if ( entry.fromPort == 0)
			strcpy(portRange, "----");
		else if ( entry.fromPort == entry.toPort )
			snprintf(portRange, 20, "%d", entry.fromPort);
		else
			snprintf(portRange, 20, "%d-%d", entry.fromPort, entry.toPort);

#ifdef __DAVO__
        strcpy (temp, entry.comment);
        p = temp;
        ac = ystrargs(p, args, _countof(args), "|", 1);
        strcpy(t_portRange, portRange);
        strcpy(comment, entry.comment);
        if (ac>=1) {
            t_fromPort = safe_atoi(args[0], 0);
            if (t_fromPort!=0) {
                sprintf (t_portRange, "%d", t_fromPort);
                comment_len = strlen(entry.comment);
                ac = 0;
                for (j=0; j<comment_len; j++) {
                    if (entry.comment[j]=='|')
                        ac++;
                    if (ac==1) {
                        p = &(entry.comment[j+1]);
                        strcpy(comment, p);
                        break;
                    }
                }
            }
        }

		if (comment)
			translate_control_code(comment);
#endif
		nBytesSent += req_format_write(wp, ("<tr class=\"tbl_body\">"
			"<td align=center width=\"20%%\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"20%%\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"20%%\" ><font size=\"2\">%s</td>\n"
     			"<td align=center width=\"15%%\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"15%%\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"10%%\" >"
      			"<input type=\"submit\" value=\"삭제\" id=\"deleteSelPortFw%d\" name=\"deleteSelPortFw\" onClick=\"return deleteClick('%d')\"></td></tr>\n"),
				portRange, type, ip, t_portRange, comment, i, i);
	}
	return nBytesSent;
}


/////////////////////////////////////////////////////////////////////////////
int portFilterList(request *wp, int argc, char **argv)
{
	int	nBytesSent=0, entryNum, i;
	PORTFILTER_T entry;
	char	*type, portRange[20];

	if ( !apmib_get(MIB_PORTFILTER_TBL_NUM, (void *)&entryNum)) {
  		fprintf(stderr, "Get table entry error!\n");
		return -1;
	}

	nBytesSent += req_format_write(wp, ("<tr class=\"tbl_head\">"
      	"<td align=center width=\"30%%\"><font size=\"2\"><b>Port Range</b></font></td>\n"
      	"<td align=center width=\"25%%\"><font size=\"2\"><b>Protocol</b></font></td>\n"
#ifdef CONFIG_IPV6
      	"<td align=center ><font size=\"2\"><b>IP Version</b></font></td>\n"
#endif
	"<td align=center width=\"30%%\" ><font size=\"2\"><b>Comment</b></font></td>\n"
      	"<td align=center width=\"15%%\" ><font size=\"2\"><b>Select</b></font></td></tr>\n"));

	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_PORTFILTER_TBL, (void *)&entry))
			return -1;

		if ( entry.protoType == PROTO_BOTH )
			type = "TCP+UDP";
		else if ( entry.protoType == PROTO_TCP )
			type = "TCP";
		else
			type = "UDP";

		if ( entry.fromPort == 0)
			strcpy(portRange, "----");
		else if ( entry.fromPort == entry.toPort )
			snprintf(portRange, 20, "%d", entry.fromPort);
		else
			snprintf(portRange, 20, "%d-%d", entry.fromPort, entry.toPort);

		nBytesSent += req_format_write(wp, ("<tr class=\"tbl_body\">"
			"<td align=center width=\"30%%\" ><font size=\"2\">%s</td>\n"
   			"<td align=center width=\"25%%\" ><font size=\"2\">%s</td>\n"
 #ifdef	CONFIG_IPV6
 			"<td align=center ><font size=\"2\">IPv%d</td>\n"
 #endif
     			"<td align=center width=\"30%%\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"15%%\" ><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td></tr>\n"),
				portRange, type,
#ifdef	CONFIG_IPV6
				entry.ipVer,
#endif
				entry.comment, i);
	}
	return nBytesSent;
}


/////////////////////////////////////////////////////////////////////////////
int ipFilterList(request *wp, int argc, char **argv)
{
	int	nBytesSent=0, entryNum, i;
	IPFILTER_T entry;
	char	*type, *ip;

	if ( !apmib_get(MIB_IPFILTER_TBL_NUM, (void *)&entryNum)) {
  		fprintf(stderr, "Get table entry error!\n");
		return -1;
	}

	nBytesSent += req_format_write(wp, ("<tr class=\"tbl_head\">"
      	"<td align=center width=\"30%%\" ><font size=\"2\"><b>Local IP Address</b></font></td>\n"
      	"<td align=center width=\"25%%\" ><font size=\"2\"><b>Protocol</b></font></td>\n"
      	"<td align=center width=\"25%%\" ><font size=\"2\"><b>Comment</b></font></td>\n"
      	"<td align=center width=\"20%%\" ><font size=\"2\"><b>Select</b></font></td></tr>\n"));

	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_IPFILTER_TBL, (void *)&entry))
			return -1;

		ip = inet_ntoa(*((struct in_addr *)entry.ipAddr));
		if ( !strcmp(ip, "0.0.0.0"))
			ip = "----";

		if ( entry.protoType == PROTO_BOTH )
			type = "TCP+UDP";
		else if ( entry.protoType == PROTO_TCP )
			type = "TCP";
		else
			type = "UDP";
#ifdef CONFIG_IPV6
		if(entry.ipVer==IPv4)
			nBytesSent += req_format_write(wp, ("<tr class=\"tbl_body\">"
			"<td align=center width=\"30%%\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"25%%\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"25%%\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"20%%\" ><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td></tr>\n"),
				ip, type, entry.comment, i);
		else
			nBytesSent += req_format_write(wp, ("<tr class=\"tbl_body\">"
			"<td align=center width=\"30%%\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"25%%\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"25%%\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"20%%\" ><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td></tr>\n"),
				entry.ip6Addr, type, entry.comment, i);
#else
		nBytesSent += req_format_write(wp, ("<tr>"
			"<td align=center width=\"30%%\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"25%%\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"25%%\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"20%%\" ><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td></tr>\n"),
				ip, type, entry.comment, i);
#endif
	}
	return nBytesSent;
}


/////////////////////////////////////////////////////////////////////////////
int macFilterList(request *wp, int argc, char **argv)
{
	int nByteSent = 0, entryNum, i;
	char tmpbuf[512];
	char *mac, *port, *comment, *setColor;
	char *p;
	char query[32];
	int cnt_lan[4];
	int lan_port, pport;
	int mac_count;
	char opmode[16];

	if (!nvram_get_r("x_MACFILTER_TBL_NUM", tmpbuf, sizeof(tmpbuf))) {
		apmib_nvram_set("x_MACFILTER_TBL_NUM", "0");
		entryNum = 0;
	} else {
		entryNum = safe_atoi(tmpbuf, 0);
	}

	cnt_lan[0] = cnt_lan[1] = cnt_lan[2] = cnt_lan[3] = 0;
	for (i = 1; i <= entryNum; i++) {
		sprintf(query, "x_MACFILTER_TBL%d", i);
		if ((p = nvram_get_r(query, tmpbuf, sizeof(tmpbuf))) == NULL)
			continue;

		mac = strtok(tmpbuf, ",");
		port = strtok(NULL, ",");
		if (!mac || !port)
			continue;

		if (!strcasecmp(port, "01"))
			cnt_lan[0]++;
		if (!strcasecmp(port, "02"))
			cnt_lan[1]++;
		if (!strcasecmp(port, "04"))
			cnt_lan[2]++;
		if (!strcasecmp(port, "08"))
			cnt_lan[3]++;
	}

	nByteSent += req_format_write(wp, ("<tr class='tbl_head'>"
				"<td align=center width=\"20%%\" ><font size=\"2\"><b>포트</b></font></td>\n"
				"<td align=center width=\"30%%\" ><font size=\"2\"><b>MAC 주소</b></font></td>\n"
				"<td align=center width=\"30%%\" ><font size=\"2\"><b>설명</b></font></td>\n"
				"<td align=center width=\"20%%\" ><font size=\"2\"><b>삭제</b></font></td>\n"));

	for (lan_port = 1; lan_port <= 4; lan_port++) {
		mac_count = 0;

		if (lan_port % 2 == 0)
			setColor = "d5d5d5";
		else
			setColor = "f0f0f0";

		sprintf(query, "x_MACFILTER_OPMODE%d", lan_port);
		if ((p = nvram_get_r(query, opmode, sizeof(opmode))) == NULL) {
			apmib_nvram_set(query, "drop");
		}
		nByteSent += req_format_write(wp, ("<tr>\n"
					"<td rowspan='%d' align=center width=\"20%%\" bgcolor=\"#%s\"><font size=\"2\">LAN%d"
					"<br><select name='opmode%d' onChange=\"modeChange();\"><option value=\"drop\" %s>차단<option value=\"permit\" %s>허용</select></td>\n"),
				(cnt_lan[lan_port-1])? : 1, setColor, lan_port, lan_port, !strcasecmp(opmode, "drop") ? "selected" : "", !strcasecmp(opmode, "permit") ? "selected" : "");

		for (i = 1; i <= entryNum; i++) {
			sprintf(query, "x_MACFILTER_TBL%d", i);
			if ((p = nvram_get_r(query, tmpbuf, sizeof(tmpbuf))) == NULL) {
				continue;
			}
			mac = strtok(tmpbuf, ",");
			port = strtok(NULL, ",");
			comment = strtok(NULL, ",");

			if (!mac || !port)
				continue;

			pport = atoi(port);
			if (lan_port != get_aclport_to_port(pport))
				continue;

			snprintf(tmpbuf, sizeof(tmpbuf), ("%s"), mac);

			if (comment)
				translate_control_code(comment);

			nByteSent += req_format_write(wp,
					("<td align=center width=\"30%%\" bgcolor=\"#%s\"><font size=\"2\">%s</td>\n"
					 "<td align=center width=\"30%%\" bgcolor=\"#%s\"><font size=\"2\">%s</td>\n"
					 "<td align=center width=\"20%%\" bgcolor=\"#%s\">"
					 "<input type=\"submit\" value=\" 삭제 \" id=\"deleteSelFilterMac%d\" name=\"deleteSelFilterMac\" onClick=\"return deleteClick(%d)\">"
					 "</td></tr>\n"),
					setColor, tmpbuf, setColor, comment? comment : "", setColor, i, i);
			mac_count++;
		}
		if (mac_count == 0) {
			nByteSent += req_format_write(wp,
					("<td bgcolor=\"#%s\"></td><td bgcolor=\"#%s\"></td>"
					 "<td bgcolor=\"#%s\"></td></tr>\n"), setColor, setColor, setColor);
		}
	}

	return nByteSent;
}

/////////////////////////////////////////////////////////////////////////////
int urlFilterList(request *wp, int argc, char **argv)
{
	int nBytesSent=0, entryNum, i;
	URLFILTER_T entry;
	int mode;
#ifdef URL_FILTER_USER_MODE_SUPPORT
	char tmpBuf[20],tmpBuf2[20];
	int defaultRulefound=0;
#endif
	if ( !apmib_get(MIB_URLFILTER_TBL_NUM, (void *)&entryNum)) {
  		fprintf(stderr, "Get table entry error!\n");
		return -1;
	}

	if ( !apmib_get(MIB_URLFILTER_MODE, (void *)&mode)) {
  		fprintf(stderr, "Get URL Filter mode error!\n");
		return -1;
	}
#ifdef URL_FILTER_USER_MODE_SUPPORT
		nBytesSent += req_format_write(wp, ("<tr class=\"tbl_head\>"
			"<td align=center width=\"30%%\" ><font size=\"2\"><b>URL Address</b></font></td>\n"
			"<td align=center width=\"25%%\" ><font size=\"2\"><b>IP Address</b></font></td>\n"
			"<td align=center width=\"25%%\" ><font size=\"2\"><b>Mac Address</b></font></td>\n"
			"<td align=center width=\"20%%\" ><font size=\"2\"><b>Select</b></font></td></tr>\n"));
#else
	nBytesSent += req_format_write(wp, ("<tr class=\"tbl_head\">"
      	"<td align=center width=\"70%%\" ><font size=\"2\"><b>URL Address</b></font></td>\n"
      	"<td align=center width=\"30%%\" ><font size=\"2\"><b>Select</b></font></td></tr>\n"));
#endif
	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_URLFILTER_TBL, (void *)&entry))
			return -1;
		if(mode!=entry.ruleMode)
			continue;
#ifdef URL_FILTER_USER_MODE_SUPPORT
		usrMode=(int)entry.usrMode;
		if(usrMode==0)//default rule
		{
			defaultRulefound=1;
			continue;
		}
		switch(usrMode)
		{
			case 1://for specific ip
			{
				strcpy(tmpBuf,inet_ntoa(*((struct in_addr *)entry.ipAddr)));
				snprintf(tmpBuf2,20,"-");
				break;
			}
			case 2://for specific mac
			{
				snprintf(tmpBuf,20,"-");
				snprintf(tmpBuf2, 20, ("%02x:%02x:%02x:%02x:%02x:%02x"),
						 entry.macAddr[0], entry.macAddr[1], entry.macAddr[2],
					     entry.macAddr[3], entry.macAddr[4], entry.macAddr[5]);
				break;
			}
			default:
			{
				snprintf(tmpBuf,20,"-");
				snprintf(tmpBuf2,20,"-");
				break;
			}
		}
		nBytesSent += req_format_write(wp, ("<tr class=\"tbl_body\">"
			"<td align=center width=\"30%%\" ><font size=\"2\">%s</td>\n"
			"<td align=center width=\"25%%\" ><font size=\"2\">%s</td>\n"
			"<td align=center width=\"25%%\" ><font size=\"2\">%s</td>\n"
			"<td align=center width=\"20%%\" ><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td></tr>\n"),
			entry.urlAddr,tmpBuf, tmpBuf2, i);
#else
		nBytesSent += req_format_write(wp, ("<tr class=\"tbl_body\">"
			"<td align=center width=\"70%%\" ><font size=\"2\">%s</td>\n"
      			//"<td align=center width=\"30%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
       			"<td align=center width=\"30%%\" ><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td></tr>\n"),
			entry.urlAddr, i); //tmpBuf
			//entry.urlAddr, entry.comment, i); //tmpBuf
#endif
	}
#ifdef URL_FILTER_USER_MODE_SUPPORT //display default rules
	if(defaultRulefound==1)
	{
		for (i=1; i<=entryNum; i++) {
			*((char *)&entry) = (char)i;
			if ( !apmib_get(MIB_URLFILTER_TBL, (void *)&entry))
				return -1;
			if(mode!=entry.ruleMode)
				continue;
			if(0!=entry.usrMode)
				continue;
			snprintf(tmpBuf,20,"For all users");
			snprintf(tmpBuf2,20,"For all users");
			nBytesSent += req_format_write(wp, ("<tr>"
				"<td align=center width=\"30%%\" bgcolor=\"#FFBF00\"><font size=\"2\">%s</td>\n"
				"<td align=center width=\"25%%\" bgcolor=\"#FFBF00\"><font size=\"2\">%s</td>\n"
				"<td align=center width=\"25%%\" bgcolor=\"#FFBF00\"><font size=\"2\">%s</td>\n"
				"<td align=center width=\"20%%\" bgcolor=\"#FFBF00\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td></tr>\n"),
				entry.urlAddr,tmpBuf, tmpBuf2, i);
		}
	}
#endif
	return nBytesSent;

}

#if 0
/////////////////////////////////////////////////////////////////////////////
int triggerPortList(request *wp, int argc, char **argv)
{

	int	nBytesSent=0, entryNum, i;
	TRIGGERPORT_T entry;
	char	*triType, triPortRange[20], *incType, incPortRange[20];

	if ( !apmib_get(MIB_TRIGGERPORT_TBL_NUM, (void *)&entryNum)) {
  		fprintf(stderr, "Get table entry error!\n");
		return -1;
	}

	nBytesSent += req_format_write(wp, ("<tr>"
      	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Trigger-port Range</b></font></td>\n"
      	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Trigger-port Protocol</b></font></td>\n"
     	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Incoming-port Range</b></font></td>\n"
      	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Incoming-port Protocol</b></font></td>\n"
	"<td align=center width=\"14%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Comment</b></font></td>\n"
      	"<td align=center width=\"6%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Select</b></font></td></tr>\n"));


#if 0
	nBytesSent += req_format_write(wp, ("<tr>"
	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Trigger-port Range</b></font></td>\n"
      	"<td align=center width=\"15%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Trigger-port Protocol</b></font></td>\n")
	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Incoming-port Range</b></font></td>\n"
      	"<td align=center width=\"15%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Incoming-port Protocol</b></font></td>\n"
	"<td align=center width=\"14%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Comment</b></font></td>\n"
      	"<td align=center width=\"6%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Select</b></font></td></tr>\n"));

#endif
	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_TRIGGERPORT_TBL, (void *)&entry))
			return -1;

		if ( entry.tri_protoType == PROTO_BOTH )
			triType = "TCP+UDP";
		else if ( entry.tri_protoType == PROTO_TCP )
			triType = "TCP";
		else
			triType = "UDP";

		if ( entry.tri_fromPort == 0)
			strcpy(triPortRange, "----");
		else if ( entry.tri_fromPort == entry.tri_toPort )
			snprintf(triPortRange, 20, "%d", entry.tri_fromPort);
		else
			snprintf(triPortRange, 20, "%d-%d", entry.tri_fromPort, entry.tri_toPort);

		if ( entry.inc_protoType == PROTO_BOTH )
			incType = "TCP+UDP";
		else if ( entry.inc_protoType == PROTO_TCP )
			incType = "TCP";
		else
			incType = "UDP";

		if ( entry.inc_fromPort == 0)
			strcpy(incPortRange, "----");
		else if ( entry.inc_fromPort == entry.inc_toPort )
			snprintf(incPortRange, 20, "%d", entry.inc_fromPort);
		else
			snprintf(incPortRange, 20, "%d-%d", entry.inc_fromPort, entry.inc_toPort);


		nBytesSent += req_format_write(wp, ("<tr>"
			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
   			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
   			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
     			"<td align=center width=\"20%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"6%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td></tr>\n"),
				triPortRange, triType, incPortRange, incType, entry.comment, i);
	}
	return nBytesSent;
}
#endif

#ifdef __DAVO__
static char *hex2ip(char *h)
{
	struct in_addr ip;
	struct in6_addr addr;
	char str[INET6_ADDRSTRLEN];

	if(inet_pton(AF_INET6, h, &addr)<=0) {
		ip.s_addr = htonl(strtoul(h, NULL, 16));
		return inet_ntoa(ip);
	}

	return h;
}

#define EMIT_DELIM ((n>0)?",":"")
static inline int emit_str(char *buf, int n, char *name, char *p)
{
	return sprintf(&buf[n], "%s%s%s", EMIT_DELIM, name, p);
}


static char *ruleString(int ruleType, char *rule, char *buf)
{
	int n;
	char *p;
	char *s=rule;

	n = 0;
	switch(ruleType) {
		case 0:
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "P:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "Vi:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "Vp:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "SI:", hex2ip(p));
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "SIm:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "SPb:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "SPe:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "Act:", p);
			break;
		case 1:
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "Vi:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "Vp:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "DI:", hex2ip(p));
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "DIm:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "DPb:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "DPe:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "Act:", p);
			break;
		case 2:
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "SI:", hex2ip(p));
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "SIm:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "DI:", hex2ip(p));
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "DIm:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "T:0x", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "TM:0x", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "Pt:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "Act:", p);
			break;
		case 3:
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "SI:", hex2ip(p));
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "SIm:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "DI:", hex2ip(p));
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "DIm:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "T:0x", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "TM:0x", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "", toupper(p[0])=='T'?"TCP":"UDP");
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "SPb:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "SPe:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "DPb:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "DPe:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "Act:", p);
			break;
		case 4:
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "Vp:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "Act:", p);
			break;
		case 5:
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "SI6:", hex2ip(p));
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "SIm6:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "DI6:", hex2ip(p));
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "DIm6:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "T:0x", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "TM:0x", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "Pt:", p);
			p = strsep(&s, "_");
			if (p && p[0]) n+=emit_str(buf, n, "Act:", p);
			break;
		default:
			strcpy(buf, "알 수 없는 rule\n");
			break;
	}
	return buf;
}

int show_acltbl(request *wp, int argc, char **argv)
{
	int	entryNum, i, nCount;
	int nBytesSent=0;
	char tmpBuf[200];
	char *Inf="";
	int  ruleType;
	char *rule="";
	char *strTmp;
	char strParam[160];

	entryNum = 0;
	if (nvram_get_r("x_Q_R_NUM", tmpBuf, sizeof(tmpBuf)))
		entryNum = atoi(tmpBuf);

	for (i=0, nCount = 1; nCount <= entryNum; i++) {
		sprintf(strParam, "x_Q_R_%d", i);
		if (!nvram_get_r(strParam, tmpBuf, sizeof(tmpBuf)))
			continue;
		else
			nCount ++;
		ruleType = atoi(tmpBuf);
		strTmp = strchr(tmpBuf, '_');
		if (strTmp && strlen(strTmp) > 1)
			Inf = strTmp + 1;
		strTmp = strchr(Inf, '_');
		if (strTmp && strlen(strTmp) > 1) {
			Inf[strTmp-Inf] = 0;
			rule = strTmp+1;
		}else
			rule = "";

		nBytesSent += req_format_write(wp, "<tr bgcolor=#DDDDDD>\n"\
			"    <td align=center>%d</td>\n" \
			"    <td align=center>%d</td>\n", i+1, ruleType);
		if (ruleType == 4)
			nBytesSent += req_format_write(wp, "<td align=center>---</td>\n", "");
		else
			nBytesSent += req_format_write(wp, "<td align=center>%s</td>\n",
						strcasecmp(Inf, "br0") == 0?"LAN":"WAN");
		nBytesSent += req_format_write(wp, "<td>%s</td>\n", ruleString(ruleType, rule, strParam));
		nBytesSent += req_format_write(wp, "<td align=center>"\
			"<input type='checkbox' name='Q_R_%d' value='1'></td></tr>\n", i);
	}

	return nBytesSent;
}

void formDelete_acl(request *wp, char *path, char *query)
{
	int i, j, entryNum=0;
	char *str;
	char name[20];
	char name2[20];
	char value[80];

	if (nvram_get_r("x_Q_R_NUM", value, sizeof(value)))
		entryNum = atoi(value);
	if (entryNum<=0) {
		printf("error entryNum < 0\n");
		send_redirect_perm(wp, "/skb_qosacl.htm");
		return;
	}

	for (i=0;i<entryNum;i++) {
		sprintf(name, "Q_R_%d", i);
		str = req_get_cstream_var(wp, name, "");
		if (str[0]==0)
			continue;
		printf("formDelete_acl(): delete %s\n", name);
		sprintf(value, "x_%s", name);
		nvram_unset(value);
	}

	// compact Q_R_# list
	for (i=0, j=0; i<entryNum;i++) {
		sprintf(name, "x_Q_R_%d", i);

		if (nvram_get_r(name, value, sizeof(value))) {
			if (i!=j) {
				sprintf(name2, "x_Q_R_%d", j);
				apmib_nvram_set(name2, value);
				nvram_unset(name);
			}
			j++;
		}
	}
	if (j!=entryNum) {
		sprintf(value, "%d", j);
		apmib_nvram_set("x_Q_R_NUM", value);
	}
	send_redirect_perm(wp, "/skb_qosacl.htm");

	nvram_commit();

	yexecl(NULL, "dvqos --apply");
}

void formAclSetup(request *wp, char *path, char *query)
{
	char tmpBuf[100];
	char errMsg[128];
	char rule[128];
	int entryNum=0;
	char *strFrom, *strRuleType, *strUseVlan, *strUseSrcIp, *strUseSrcPort;
	char *SourceIPv6, *DestIPv6;
	char *strUsePhyPort, *strPhyPort;
	char *strVLANID=NULL;
	char *strSIP0, *strSIP1, *strSIP2, *strSIP3;
	char *strDIP0, *strDIP1, *strDIP2, *strDIP3;
	char *strSrcIpMask, *strDstIpMask, *strSrcIpv6Mask, *strDstIpv6Mask;
	char *strSrcPortFrom, *strSrcPortTo, *strDstPortFrom, *strDstPortTo;
	char *strUsePriority, *strLevel2Priority;
	char *strAction, *strIntPriority;
	char *strUseToS, *strToSValue, *strProtocol;
	int  ToSValue;
	int  ruleType;
	unsigned int SourceIP, DestIP;
	struct in6_addr addr;
	int proto;

	if (wp->superUser != 1)
		return;

	strFrom = req_get_cstream_var(wp, "delete", "");
	if (strFrom[0]!=0) {
		formDelete_acl(wp, path, query);
		return;
	}

	if (nvram_get_r("x_Q_R_NUM", tmpBuf, sizeof(tmpBuf)))
		entryNum = atoi(tmpBuf);

	if( entryNum >= 200 ) {
		sprintf(errMsg, "Rule이 너무 많습니다. 최대 200까지만 가능합니다.");
		goto setErr;
	}

	entryNum += 1;

	printf("ACL Tabled Add Query:%s\n", query);
	strRuleType = req_get_cstream_var(wp, "ruleType", "");
	if (strRuleType[0] == 0) {
		sprintf(errMsg, "Rule 형식을 얻을 수 없습니다.");
		goto setErr;
	}
	ruleType = atoi(strRuleType)-1;
	strFrom = req_get_cstream_var(wp, "side", "");
	printf("ACL Table From: %s, rule Type:%d\n", strFrom, ruleType);

	if (strFrom[0] == '0' || ruleType == 4)
		sprintf(rule, "%d_br0_", ruleType);
	else if (strFrom[0] == '1')
		sprintf(rule, "%d_eth1_", ruleType);
	else {
		sprintf(errMsg, "포트를 알 수 없습니다...\n");
//		goto setErr;
	}

	switch(ruleType) {
	case 0:

		strUsePhyPort = req_get_cstream_var(wp, "physical_use", "");
		if (!strUsePhyPort[0] || strUsePhyPort[0] == '0') {
			sprintf(errMsg, "Physical 포트 사용을 알 수 없습니다..");
			goto setErr;
		}
		strPhyPort = req_get_cstream_var(wp, "physical_port", "");
		if (strPhyPort[0])
			sprintf(rule, "%s%c_", rule, strPhyPort[0]);
		else
			sprintf(rule, "%s_", rule);

		strUseVlan = req_get_cstream_var(wp, "vlan_use", "");
		if (strUseVlan[0] == '1')
			strVLANID = req_get_cstream_var(wp, "vlan_value", "");
		if (strVLANID && strVLANID[0])
			strcat(rule, strVLANID);
		strcat(rule, "_");
		strcat(rule, "_");

		strUseSrcIp = req_get_cstream_var(wp, "srcip_use", "");
		strSIP0 = req_get_cstream_var(wp, "srcip0", "");
		strSIP1 = req_get_cstream_var(wp, "srcip1", "");
		strSIP2 = req_get_cstream_var(wp, "srcip2", "");
		strSIP3 = req_get_cstream_var(wp, "srcip3", "");

		SourceIPv6 = req_get_cstream_var(wp, "srcipv6", "");

		SourceIP = atoi(strSIP0)*0x1000000 + atoi(strSIP1)*0x10000
				  + atoi(strSIP2)*0x100+atoi(strSIP3);

		if (SourceIP) {
			sprintf(tmpBuf, "%08x_", SourceIP);
			strcat(rule, tmpBuf);
		} else if (SourceIPv6[0]) {
			if ((inet_pton(AF_INET6, SourceIPv6, &addr) <= 0)) {
				sprintf(errMsg, "입력하신 출발지 주소가 IPv6 형식이 아닙니다.");
				goto setErr;
			}
			sprintf(tmpBuf, "%s_", SourceIPv6);
			strcat(rule, tmpBuf);
		} else {
			strcat(rule, "_");
		}

		strSrcIpMask = req_get_cstream_var(wp, "srcip_mask", "");
		strSrcIpv6Mask = req_get_cstream_var(wp, "srcipv6_mask", "");

		if (*strSrcIpMask && atoi(strSrcIpMask) > 0) {
			sprintf(tmpBuf, "%d", atoi(strSrcIpMask));
			strcat(rule, tmpBuf);
		} else if (*strSrcIpv6Mask && atoi(strSrcIpv6Mask) > 0) {
			sprintf(tmpBuf, "%d", atoi(strSrcIpv6Mask));
			strcat(rule, tmpBuf);
		}
		strcat(rule, "_");

		strUseSrcPort = req_get_cstream_var(wp, "srcport_use", "");
		strSrcPortFrom = req_get_cstream_var(wp, "srcport0", "");
		if (*strSrcPortFrom)
			strcat(rule, strSrcPortFrom);
		strcat(rule, "_");

		strSrcPortTo = req_get_cstream_var(wp, "srcport1", "");

		if (strSrcPortTo[0])
			strcat(rule, strSrcPortTo);
		strcat(rule, "_");

		break;
	case 1:
		strVLANID = req_get_cstream_var(wp, "vlan_value", "");
		if (strVLANID)
			strcat(rule, strVLANID);
		strcat(rule, "_");
		strcat(rule, "_");

		strDIP0 = req_get_cstream_var(wp, "dstip0", "");
		strDIP1 = req_get_cstream_var(wp, "dstip1", "");
		strDIP2 = req_get_cstream_var(wp, "dstip2", "");
		strDIP3 = req_get_cstream_var(wp, "dstip3", "");

		DestIPv6 = req_get_cstream_var(wp, "dstipv6", "");

		DestIP = atoi(strDIP0)*0x1000000 + atoi(strDIP1)*0x10000
				  + atoi(strDIP2)*0x100+atoi(strDIP3);

		if (DestIP) {
			sprintf(tmpBuf, "%08x_", DestIP);
			strcat(rule, tmpBuf);
		} else if (DestIPv6[0]) {
			if ((inet_pton(AF_INET6, DestIPv6, &addr) <= 0)) {
				sprintf(errMsg, "입력하신 목적지 주소가 IPv6 형식이 아닙니다.");
				goto setErr;
			}
			sprintf(tmpBuf, "%s_", DestIPv6);
			strcat(rule, tmpBuf);
		} else {
			strcat(rule, "_");
		}

		strDstIpMask = req_get_cstream_var(wp, "dstip_mask", "");
		strDstIpv6Mask = req_get_cstream_var(wp, "dstipv6_mask", "");

		if (strDstIpMask[0] && atoi(strDstIpMask) > 0) {
			sprintf(tmpBuf, "%d", atoi(strDstIpMask));
			strcat(rule, tmpBuf);
		} else if (strDstIpv6Mask[0] && atoi(strDstIpv6Mask) > 0) {
			sprintf(tmpBuf, "%d", atoi(strDstIpv6Mask));
			strcat(rule, tmpBuf);
		}
		strcat(rule, "_");

		strDstPortFrom = req_get_cstream_var(wp, "dstport0", "");
		if (strDstPortFrom[0])
			strcat(rule, strDstPortFrom);
		strcat(rule, "_");

		strDstPortTo = req_get_cstream_var(wp, "dstport1", "");

		if (strDstPortTo[0])
			strcat(rule, strDstPortTo);
		strcat(rule, "_");
		break;
	case 2:
		strSIP0 = req_get_cstream_var(wp, "srcip0", "");
		strSIP1 = req_get_cstream_var(wp, "srcip1", "");
		strSIP2 = req_get_cstream_var(wp, "srcip2", "");
		strSIP3 = req_get_cstream_var(wp, "srcip3", "");

		SourceIPv6 = req_get_cstream_var(wp, "srcipv6", "");

		SourceIP = atoi(strSIP0)*0x1000000 + atoi(strSIP1)*0x10000
				  + atoi(strSIP2)*0x100+atoi(strSIP3);
		if (SourceIP) {
			sprintf(tmpBuf, "%08x_", SourceIP);
			strcat(rule, tmpBuf);
		} else if (SourceIPv6[0]) {
			if ((inet_pton(AF_INET6, SourceIPv6, &addr) <= 0)) {
				sprintf(errMsg, "입력하신 출발지 주소가 IPv6 형식이 아닙니다.");
				goto setErr;
			}
			sprintf(tmpBuf, "%s_", SourceIPv6);
			strcat(rule, tmpBuf);
		} else {
			strcat(rule, "_");
		}

		strSrcIpMask = req_get_cstream_var(wp, "srcip_mask", "");
		strSrcIpv6Mask = req_get_cstream_var(wp, "srcipv6_mask", "");

		if (strSrcIpMask[0] && atoi(strSrcIpMask) > 0) {
			sprintf(tmpBuf, "%d", atoi(strSrcIpMask));
			strcat(rule, tmpBuf);
		} else if (*strSrcIpv6Mask && atoi(strSrcIpv6Mask) > 0) {
			sprintf(tmpBuf, "%d", atoi(strSrcIpv6Mask));
			strcat(rule, tmpBuf);
		}
		strcat(rule, "_");

		strDIP0 = req_get_cstream_var(wp, "dstip0", "");
		strDIP1 = req_get_cstream_var(wp, "dstip1", "");
		strDIP2 = req_get_cstream_var(wp, "dstip2", "");
		strDIP3 = req_get_cstream_var(wp, "dstip3", "");

		DestIPv6 = req_get_cstream_var(wp, "dstipv6", "");

		DestIP = atoi(strDIP0)*0x1000000 + atoi(strDIP1)*0x10000
				  + atoi(strDIP2)*0x100+atoi(strDIP3);

		if (DestIP) {
			sprintf(tmpBuf, "%08x_", DestIP);
			strcat(rule, tmpBuf);
		} else if (DestIPv6[0]) {
			if ((inet_pton(AF_INET6, DestIPv6, &addr) <= 0)) {
				sprintf(errMsg, "입력하신 목적지 주소가 IPv6 형식이 아닙니다.");
				goto setErr;
			}
			sprintf(tmpBuf, "%s_", DestIPv6);
			strcat(rule, tmpBuf);
		} else {
			strcat(rule, "_");
		}
		strDstIpMask = req_get_cstream_var(wp, "dstip_mask", "");
		strDstIpv6Mask = req_get_cstream_var(wp, "dstipv6_mask", "");

		if (strDstIpMask[0] && atoi(strDstIpMask) > 0) {
			sprintf(tmpBuf, "%d", atoi(strDstIpMask));
			strcat(rule, tmpBuf);
		} else if (strDstIpv6Mask[0] && atoi(strDstIpv6Mask) > 0) {
			sprintf(tmpBuf, "%d", atoi(strDstIpv6Mask));
			strcat(rule, tmpBuf);
		}
		strcat(rule, "_");

		strUseToS = req_get_cstream_var(wp, "tos_use", "0");
		if (strUseToS[0] == '1') { // Check Using TOS
			strToSValue = req_get_cstream_var(wp, "tos_value", "0");
			ToSValue = strtol(strToSValue, NULL, 16);
			sprintf(tmpBuf, "%02x_ff_", ToSValue);
		} else {
			strUseToS = req_get_cstream_var(wp, "dscp_use", "0");
			if (strUseToS[0] == '1') {	// Checck Using DSCP
				strToSValue = req_get_cstream_var(wp, "dscp_value", "0");
				ToSValue = atoi(strToSValue) << 2;
				sprintf(tmpBuf, "%02x_fc_", ToSValue);
			} else {
				strcpy(tmpBuf, "__");
			}
		}
		strcat(rule, tmpBuf);

		strProtocol = req_get_cstream_var(wp, "protocol_val", "");
		if (strProtocol[0]) {
			if (atoi(strProtocol) == 99) {
				char *etc_proto;
				etc_proto = req_get_cstream_var(wp, "etc_proto_val", "");
				if (etc_proto[0])
					strcat(rule, etc_proto);
			} else {
				strcat(rule, strProtocol);
			}
		}
		strcat(rule, "_");
		break;
	case 3:
		strSIP0 = req_get_cstream_var(wp, "srcip0", "");
		strSIP1 = req_get_cstream_var(wp, "srcip1", "");
		strSIP2 = req_get_cstream_var(wp, "srcip2", "");
		strSIP3 = req_get_cstream_var(wp, "srcip3", "");

		SourceIPv6 = req_get_cstream_var(wp, "srcipv6", "");

		SourceIP = atoi(strSIP0)*0x1000000 + atoi(strSIP1)*0x10000
				  + atoi(strSIP2)*0x100+atoi(strSIP3);
		if (SourceIP) {
			sprintf(tmpBuf, "%08x_", SourceIP);
			strcat(rule, tmpBuf);
		} else if (SourceIPv6[0]) {
			if ((inet_pton(AF_INET6, SourceIPv6, &addr) <= 0)) {
				sprintf(errMsg, "입력하신 출발지 주소가 IPv6 형식이 아닙니다.");
				goto setErr;
			}
			sprintf(tmpBuf, "%s_", SourceIPv6);
			strcat(rule, tmpBuf);
		} else {
			strcat(rule, "_");
		}

		strSrcIpMask = req_get_cstream_var(wp, "srcip_mask", "");
		strSrcIpv6Mask = req_get_cstream_var(wp, "srcipv6_mask", "");

		if (strSrcIpMask[0] && atoi(strSrcIpMask) > 0) {
			sprintf(tmpBuf, "%d", atoi(strSrcIpMask));
			strcat(rule, tmpBuf);
		} else if (*strSrcIpv6Mask && atoi(strSrcIpv6Mask) > 0) {
			sprintf(tmpBuf, "%d", atoi(strSrcIpv6Mask));
			strcat(rule, tmpBuf);
		}
		strcat(rule, "_");

		strDIP0 = req_get_cstream_var(wp, "dstip0", "");
		strDIP1 = req_get_cstream_var(wp, "dstip1", "");
		strDIP2 = req_get_cstream_var(wp, "dstip2", "");
		strDIP3 = req_get_cstream_var(wp, "dstip3", "");

		DestIPv6 = req_get_cstream_var(wp, "dstipv6", "");

		DestIP = atoi(strDIP0)*0x1000000 + atoi(strDIP1)*0x10000
				  + atoi(strDIP2)*0x100+atoi(strDIP3);

		if (DestIP) {
			sprintf(tmpBuf, "%08x_", DestIP);
			strcat(rule, tmpBuf);
		} else if (DestIPv6[0]) {
			if ((inet_pton(AF_INET6, DestIPv6, &addr) <= 0)) {
				sprintf(errMsg, "입력하신 목적지 주소가 IPv6 형식이 아닙니다.");
				goto setErr;
			}
			sprintf(tmpBuf, "%s_", DestIPv6);
			strcat(rule, tmpBuf);
		} else {
			strcat(rule, "_");
		}
		strDstIpMask = req_get_cstream_var(wp, "dstip_mask", "");
		strDstIpv6Mask = req_get_cstream_var(wp, "dstipv6_mask", "");

		if (strDstIpMask[0] && atoi(strDstIpMask) > 0) {
			sprintf(tmpBuf, "%d", atoi(strDstIpMask));
			strcat(rule, tmpBuf);
		} else if (strDstIpv6Mask[0] && atoi(strDstIpv6Mask) > 0) {
			sprintf(tmpBuf, "%d", atoi(strDstIpv6Mask));
			strcat(rule, tmpBuf);
		}
		strcat(rule, "_");

		strUseToS = req_get_cstream_var(wp, "tos_use", "0");
		if (strUseToS[0] == '1') { // Check Using TOS
			strToSValue = req_get_cstream_var(wp, "tos_value", "0");
			ToSValue = strtol(strToSValue, NULL, 16);
			sprintf(tmpBuf, "%02x_ff_", ToSValue);
		} else {
			strUseToS = req_get_cstream_var(wp, "dscp_use", "0");
			if (strUseToS[0] == '1') {	// Checck Using DSCP
				strToSValue = req_get_cstream_var(wp, "dscp_value", "0");
				ToSValue = atoi(strToSValue) << 2;
				sprintf(tmpBuf, "%02x_fc_", ToSValue);
			} else {
				strcpy(tmpBuf, "__");
			}
		}
		strcat(rule, tmpBuf);

		strProtocol = req_get_cstream_var(wp, "protocol_val", "");
		if (strProtocol[0] && (atoi(strProtocol)== 6 || atoi(strProtocol) == 17)) {
			if (atoi(strProtocol) == 6)
				strcat(rule, "t_");
			else
				strcat(rule, "u_");
		} else {
			sprintf(errMsg, "프로토콜이 올바르지 않습니다(%s). TCP 또는 UDP를 선택해하여 주십시오.", strProtocol);
			goto setErr;
		}

		strSrcPortFrom = req_get_cstream_var(wp, "srcport0", "");
		if (strSrcPortFrom[0])
			strcat(rule, strSrcPortFrom);
		strcat(rule, "_");

		strSrcPortTo = req_get_cstream_var(wp, "srcport1", "");
		if (strSrcPortTo[0])
			strcat(rule, strSrcPortTo);
		strcat(rule, "_");


		strDstPortFrom = req_get_cstream_var(wp, "dstport0", "");
		if (strDstPortFrom[0])
			strcat(rule, strDstPortFrom);
		strcat(rule, "_");

		strDstPortTo = req_get_cstream_var(wp, "dstport1", "");
		if (strDstPortTo[0])
			strcat(rule, strDstPortTo);
		strcat(rule, "_");

		break;
	case 4:
		strUsePriority = req_get_cstream_var(wp, "l2priority", "");
		strLevel2Priority = req_get_cstream_var(wp, "l2priority_val", "");
		if (*strLevel2Priority)
			strcat(rule, strLevel2Priority);
		strcat(rule, "_");
		break;
	case 5:
		if ( (SourceIPv6 = req_get_cstream_var(wp, "srcipv6", ""))&&SourceIPv6[0] ) {
			if ((inet_pton(AF_INET6, SourceIPv6, &addr) <= 0)) {
				sprintf(errMsg, "입력하신 출발지 주소가 IPv6 형식이 아닙니다.");
				goto setErr;
			}
			sprintf(tmpBuf, "%s_", SourceIPv6);
			strcat(rule, tmpBuf);
		} else {
			strcat(rule, "_");
		}

		strSrcIpv6Mask = req_get_cstream_var(wp, "srcipv6_mask", "");
		if (*strSrcIpv6Mask && atoi(strSrcIpv6Mask) > 0) {
			sprintf(tmpBuf, "%d", atoi(strSrcIpv6Mask));
			strcat(rule, tmpBuf);
		}
		strcat(rule, "_");
		if ( (DestIPv6 = req_get_cstream_var(wp, "dstipv6", ""))&&DestIPv6[0]) {
			if ((inet_pton(AF_INET6, DestIPv6, &addr) <= 0)) {
				sprintf(errMsg, "입력하신 목적지 주소가 IPv6 형식이 아닙니다.");
				goto setErr;
			}
			sprintf(tmpBuf, "%s_", DestIPv6);
			strcat(rule, tmpBuf);
		} else {
			strcat(rule, "_");
		}
		strDstIpv6Mask = req_get_cstream_var(wp, "dstipv6_mask", "");

		if (strDstIpv6Mask[0] && atoi(strDstIpv6Mask) > 0) {
			sprintf(tmpBuf, "%d", atoi(strDstIpv6Mask));
			strcat(rule, tmpBuf);
		}
		strcat(rule, "_");

		strUseToS = req_get_cstream_var(wp, "tos_use", "0");
		if (strUseToS[0] == '1') { // Check Using TOS
			strToSValue = req_get_cstream_var(wp, "tos_value", "0");
			ToSValue = strtol(strToSValue, NULL, 16);
			sprintf(tmpBuf, "%02x_ff_", ToSValue);
		} else {
			strcpy(tmpBuf, "__");
		}
		strcat(rule, tmpBuf);

		strProtocol = req_get_cstream_var(wp, "protocol_val", "");
		if (strProtocol[0]) {
			if ( (proto=atoi(strProtocol)) == 99) {
				char *etc_proto;
				etc_proto = req_get_cstream_var(wp, "etc_proto_val", "");
				if (etc_proto[0])
					strcat(rule, etc_proto);
			} else {
				strcat(rule, strProtocol);
			}
		}
		strcat(rule, "_");
		break;
	default:
		strcpy(errMsg, "Rule 형식을 알 수 없습니다.");
		goto setErr;
		break;
	}
	strAction = req_get_cstream_var(wp, "qos_action", "");

	if (strAction[0]) {
		if (strAction[0] == '0') {
			strcat(rule, "d");
		} else {
			int IntPrior=-1;

			strIntPriority = req_get_cstream_var(wp, "int_pri", "");
			if (strIntPriority[0])
				IntPrior = atoi(strIntPriority);
			if (IntPrior >= 0 && IntPrior <= 7) {
				strcat(rule, strIntPriority);
			} else {
				strcpy(errMsg, "int.priority ACTION이 정의되지 않았습니다.");
				goto setErr;
			}
		}
	} else {
		strcpy(errMsg, "ACTION이 정의되지 않았습니다.");
		goto setErr;
	}
	{
		char Field[10];
		char *ipv6;
		sprintf(Field, "x_Q_R_%d", entryNum-1);
		ipv6 = req_get_cstream_var(wp, "ipmode", "");
		if(ipv6[0] == '1') // ipv6 mode
			strcat(rule, "_v6");
		printf("RULE: %s=%s\n", Field, rule);
		apmib_nvram_set(Field, rule);
	}
	sprintf(tmpBuf, "%d", entryNum);
	apmib_nvram_set("x_Q_R_NUM", tmpBuf);

	send_redirect_perm(wp, "/skb_qosacl.htm");

	nvram_commit();

	yexecl(NULL, "dvqos --apply");

	return;
setErr:
	ERR_MSG(errMsg);
	return;
}


void formQosQue(request *wp, char * path, char * query)
{
	char tmpBuf[80];
	char name[80];
	char tmp[12];
	int i, n=0;
	int  qos_enable = 0, qos_rate_enable;
	char *strPort, *str;
	int port = 0;

	if (wp->superUser != 1)
		return;

	if ( (strPort = req_get_cstream_var(wp, "port_num", "")) ) {
		port = strtoul(strPort, NULL, 10);
		sprintf(name, "x_QOS_ENABLE_%d", port);
	}
	if ( (str = req_get_cstream_var(wp, "que_enable", "off")) ) {
		if (strcmp(str, "on")==0) {
			qos_enable = 1;
			sprintf(tmpBuf, "1");
		}
		else {
			qos_enable = 0;
			sprintf(tmpBuf, "0");
		}
		apmib_nvram_set(name, tmpBuf);
	}
	if (qos_enable) {
		for (i=0;i<4;i++) {
			sprintf(name, "x_QOS_Q_%d_%d", port, i);

			sprintf(tmp, "qtype%d", i);
			if ( (str = req_get_cstream_var(wp, tmp, "SPQ")) ) {
				n = sprintf(tmpBuf, "%c",  str[0]);
				sprintf(tmp, "qrate%d", i);
				if ( (str = req_get_cstream_var(wp, tmp, "0")) ) {
					n += sprintf(&tmpBuf[n], "_%s", str);
				}
			}
			sprintf(tmp, "qweight%d", i);
			if ( (str = req_get_cstream_var(wp, tmp, "1")) )
				n+=sprintf(&tmpBuf[n], "_%s", str);
			apmib_nvram_set(name, tmpBuf);
		}
	}

	if ( (str= req_get_cstream_var(wp, "rate_enable", "off")) ) {
		if (strcmp(str, "on")==0)
			sprintf(tmpBuf, "1");
		else
			sprintf(tmpBuf, "0");

		sprintf(name, "x_QOS_RATE_ENABLE_%d", port);
		apmib_nvram_set(name, tmpBuf);
		qos_rate_enable = atoi(tmpBuf);
		if (qos_rate_enable) {
			if ( (str = req_get_cstream_var(wp, "in_rate", "0")) ) {
				sprintf(tmpBuf, "%s", str);
				sprintf(name, "x_QOS_RATE_I_%d", port);
				apmib_nvram_set(name, tmpBuf);
			}
			if ( (str = req_get_cstream_var(wp, "out_rate", "0")) ) {
				sprintf(tmpBuf, "%s", str);
				sprintf(name, "x_QOS_RATE_O_%d", port);
				apmib_nvram_set(name, tmpBuf);
			}
		}
	}
	nvram_commit();

	if ( (str = req_get_cstream_var(wp, "submit-url", "")) && str[0])
		send_redirect_perm(wp, "/skb_qosque.htm");

	yexecl(NULL, "dvqos --apply");
	return;
}

void formRemark(request *wp, char *path, char *query)
{
	char tmpBuf[40], tmp[20];
	int i,portbits;
	char *str[5];

	if (wp->superUser != 1)
		return;

	portbits=0;
	str[0] = req_get_cstream_var(wp, ("use_tag"), "off");
	if (strcmp(str[0], "on")==0) {
		str[4] = req_get_cstream_var(wp, ("tag_wan"), "off");
		str[0] = req_get_cstream_var(wp, ("tag_lan1"), "off");
		str[1] = req_get_cstream_var(wp, ("tag_lan2"), "off");
		str[2] = req_get_cstream_var(wp, ("tag_lan3"), "off");
		str[3] = req_get_cstream_var(wp, ("tag_lan4"), "off");

		for (i=0;i<5;i++) {
			if (strcmp(str[i], "on")==0) {
				portbits |= (0x01<<i);
			}
		}
	}
	if (portbits==0) {
		apmib_nvram_set("x_QOS_RM_1Q", "0_0_1_2_3_4_5_6_7");
	} else {
		int n=0;
		n = sprintf(tmpBuf, "%02X", portbits);
		for (i=0;i<8;i++) {
			sprintf(tmp, "tag_%d", i);
			str[0] = req_get_cstream_var(wp, tmp, "off");
			n+=sprintf(&tmpBuf[n], "_%s", str[0]);
		}
		apmib_nvram_set("x_QOS_RM_1Q", tmpBuf);
	}

	str[0] = req_get_cstream_var(wp, ("use_dscp"), "off");
	portbits=0;
	if (strcmp(str[0], "on")==0) {
		str[4] = req_get_cstream_var(wp, ("dscp_wan"), "off");
		str[0] = req_get_cstream_var(wp, ("dscp_lan1"), "off");
		str[1] = req_get_cstream_var(wp, ("dscp_lan2"), "off");
		str[2] = req_get_cstream_var(wp, ("dscp_lan3"), "off");
		str[3] = req_get_cstream_var(wp, ("dscp_lan4"), "off");

		for (i=0;i<5;i++) {
			if (strcmp(str[i], "on")==0) {
				portbits |= (0x01<<i);
			}
		}
	}
	if (portbits==0) {
		apmib_nvram_set("x_QOS_RM_DSCP", "0_0_0_0_0_46_46_46_46");
	} else {
		int n=0;
		n = sprintf(tmpBuf, "%02X", portbits);
		for (i=0;i<8;i++) {
			sprintf(tmp, "dscp_%d", i);
			str[0] = req_get_cstream_var(wp, tmp, "off");
			n+=sprintf(&tmpBuf[n], "_%s", str[0]);
		}
		apmib_nvram_set("x_QOS_RM_DSCP", tmpBuf);
	}
	str[0] = req_get_cstream_var(wp, ("submit-url"), (""));   // hidden page

	if (str[0][0])
		send_redirect_perm(wp, "/skb_qosremark.htm");

	nvram_commit();

	yexecl(NULL, "dvqos --apply");

	return;
}

#endif

#ifdef GW_QOS_ENGINE
/////////////////////////////////////////////////////////////////////////////
int qosList(request *wp, int argc, char **argv)
{
	int	entryNum;
	QOS_T entry;
	char buffer[120];
	char tmpBuf[80];
	int index;

	if ( !apmib_get(MIB_QOS_RULE_TBL_NUM, (void *)&entryNum)) {
		goto ret_empty;
	}
	index= atoi(argv[0]); // index shoud be 0 ~ 9
	index += 1;

	if( index <= entryNum)
	{
		*((char *)&entry) = (char)index;
		if ( !apmib_get(MIB_QOS_RULE_TBL, (void *)&entry))
		{
			goto ret_empty;
		}

              strcpy(tmpBuf, inet_ntoa(*((struct in_addr*)entry.local_ip_start)));
              strcpy(&tmpBuf[20], inet_ntoa(*((struct in_addr*)entry.local_ip_end)));
              strcpy(&tmpBuf[40], inet_ntoa(*((struct in_addr*)entry.remote_ip_start)));
              strcpy(&tmpBuf[60], inet_ntoa(*((struct in_addr*)entry.remote_ip_end)));
		 sprintf(buffer, "%d-%d-%d-%s-%s-%d-%d-%s-%s-%d-%d-%s", entry.enabled, entry.priority, entry.protocol,
                        tmpBuf, &tmpBuf[20],entry.local_port_start, entry.local_port_end,
                        &tmpBuf[40], &tmpBuf[60], entry.remote_port_start, entry.remote_port_end, entry.entry_name );

		req_format_write(wp, ("%s"), buffer);
	      return 0;
	}

ret_empty:
	req_format_write(wp, ("%s"), "");
	return 0;
}

/////////////////////////////////////////////////////////////////////////////
#define _PROTOCOL_TCP   6
#define _PROTOCOL_UDP   17
#define _PROTOCOL_BOTH   257
#define _PORT_MIN       0
#define _PORT_MAX       65535

static QOS_T entry_for_save[MAX_QOS_RULE_NUM];

void formQoS(request *wp, char *path, char *query)
{
#ifndef NO_ACTION
    int pid;
#endif

    char *submitUrl;
    char tmpBuf[100];

    char *strIp, *endIp, *tmpStr, *strEnabled;
    char varName[48];
    int index=1, protocol_others;
    int intVal, valid_num;
    QOS_T entry;
    struct in_addr curIpAddr, curSubnet;
    unsigned long v1, v2, v3, v4;

    strEnabled = req_get_cstream_var(wp, ("config.qos_enabled"), "");
    if( !strcmp(strEnabled, "true"))
    {
        intVal=1;
    }
    else
        intVal=0;
    if ( apmib_set( MIB_QOS_ENABLED, (void *)&intVal) == 0) {
        strcpy(tmpBuf, ("Set QoS enabled flag error!"));
        goto setErr_qos;
    }
    if (intVal==0)
         goto setOk_qos;
    strEnabled = req_get_cstream_var(wp, ("config.qos_auto_trans_rate"), "");
    if( !strcmp(strEnabled, "true"))
        intVal=1;
    else
        intVal=0;
    if ( apmib_set( MIB_QOS_AUTO_UPLINK_SPEED, (void *)&intVal) == 0) {
        strcpy(tmpBuf, ("Set QoS error!"));
        goto setErr_qos;
    }

    if( intVal == 0)
    {
        tmpStr = req_get_cstream_var(wp, ("config.qos_max_trans_rate"), "");
          string_to_dec(tmpStr, &intVal);
        if ( apmib_set(MIB_QOS_MANUAL_UPLINK_SPEED, (void *)&intVal) == 0) {
            strcpy(tmpBuf, ("Set QoS error!"));
            goto setErr_qos;
        }
    }


/*    if ( !apmib_set(MIB_QOS_DELALL, (void *)&entry)) {
        strcpy(tmpBuf, ("Delete all table error!"));
        goto setErr_qos;
    } */

    for(index=0, valid_num=0; index<MAX_QOS_RULE_NUM; index++)
    {
        sprintf(varName, "config.qos_rules[%d].enabled", index);
        tmpStr = req_get_cstream_var(wp, varName, "");
        if( !strcmp(tmpStr, "true"))
            intVal=1;
        else
            intVal=0;
        entry.enabled = (unsigned char)intVal;

        sprintf(varName, "config.qos_rules[%d].entry_name", index);
        tmpStr = req_get_cstream_var(wp, varName, "");
        strcpy(entry.entry_name, tmpStr);

        if (intVal == 0 && tmpStr[0] == 0)
             continue;

        sprintf(varName, "config.qos_rules[%d].priority", index);
        tmpStr = req_get_cstream_var(wp, varName, "");
        string_to_dec(tmpStr, &intVal);
        entry.priority = (unsigned char)intVal;

        sprintf(varName, "config.qos_rules[%d].protocol_menu", index);
        tmpStr = req_get_cstream_var(wp, varName, "");
        if (!strcmp(tmpStr, "-1"))
            protocol_others = 1;
        else
            protocol_others = 0;

        sprintf(varName, "config.qos_rules[%d].protocol", index);
        tmpStr = req_get_cstream_var(wp, varName, "");
        string_to_dec(tmpStr, &intVal);
        entry.protocol = (unsigned short)intVal;

        sprintf(varName, "config.qos_rules[%d].local_ip_start", index);
        strIp = req_get_cstream_var(wp, varName, "");
        inet_aton(strIp, (struct in_addr *)&entry.local_ip_start);
        sprintf(varName, "config.qos_rules[%d].local_ip_end", index);
        endIp = req_get_cstream_var(wp, varName, "");
        inet_aton(endIp, (struct in_addr *)&entry.local_ip_end);
        getInAddr(BRIDGE_IF, IP_ADDR, (void *)&curIpAddr);
        getInAddr(BRIDGE_IF, SUBNET_MASK, (void *)&curSubnet);

        v1 = *((unsigned long *)entry.local_ip_start);
        v2 = *((unsigned long *)&curIpAddr);
        v3 = *((unsigned long *)&curSubnet);
        if ( (v1 & v3) != (v2 & v3) ) {
            sprintf(tmpBuf, "\'%s\': Local IP start \'%s\' is not in the LAN subnet",
                        entry.entry_name, strIp);
            goto setErr_qos;
        }
        v4 = *((unsigned long *)entry.local_ip_end);
        if ( (v4 & v3) != (v2 & v3) ) {
            sprintf(tmpBuf, "\'%s\': Local IP end \'%s\' is not in the LAN subnet",
                        entry.entry_name, endIp);
            goto setErr_qos;
        }
        if ( v1 > v4 ) {
            sprintf(tmpBuf, "\'%s\': Local IP start, \'%s\', must be less than or equal to local IP end, \'%s\'",
                        entry.entry_name, strIp, endIp);
            goto setErr_qos;
        }


        sprintf(varName, "config.qos_rules[%d].remote_ip_start", index);
        strIp = req_get_cstream_var(wp, varName, "");
        inet_aton(strIp, (struct in_addr *)&entry.remote_ip_start);
        sprintf(varName, "config.qos_rules[%d].remote_ip_end", index);
        endIp = req_get_cstream_var(wp, varName, "");
        inet_aton(endIp, (struct in_addr *)&entry.remote_ip_end);
        v1 = *((unsigned long *)entry.remote_ip_start);
        v4 = *((unsigned long *)entry.remote_ip_end);
        if ( (v1 & v3) == (v2 & v3) ) {
            sprintf(tmpBuf, "\'%s\': Remote IP start \'%s\' is in the LAN subnet",
                        entry.entry_name, strIp);
            goto setErr_qos;
        }
        if ( (v4 & v3) == (v2 & v3) ) {
            sprintf(tmpBuf, "\'%s\': Remote IP end \'%s\' is in the LAN subnet",
                        entry.entry_name, endIp);
            goto setErr_qos;
        }
        if ( v1 > v4 ) {
            sprintf(tmpBuf, "\'%s\': Remote IP start, \'%s\', must be less than or equal to remote IP end, \'%s\'",
                        entry.entry_name, strIp, endIp);
            goto setErr_qos;
        }

/*        if ((!protocol_others) &&
            ( entry.protocol  == _PROTOCOL_TCP || entry.protocol  == _PROTOCOL_UDP ||entry.protocol  == _PROTOCOL_BOTH)) */
        {
            sprintf(varName, "config.qos_rules[%d].local_port_start", index);
            tmpStr = req_get_cstream_var(wp, varName, "");
            string_to_dec(tmpStr, &intVal);
            entry.local_port_start = (unsigned short)intVal;
            sprintf(varName, "config.qos_rules[%d].local_port_end", index);
            tmpStr = req_get_cstream_var(wp, varName, "");
            string_to_dec(tmpStr, &intVal);
            entry.local_port_end = (unsigned short)intVal;

            sprintf(varName, "config.qos_rules[%d].remote_port_start", index);
            tmpStr = req_get_cstream_var(wp, varName, "");
            string_to_dec(tmpStr, &intVal);
            entry.remote_port_start = (unsigned short)intVal;
            sprintf(varName, "config.qos_rules[%d].remote_port_end", index);
            tmpStr = req_get_cstream_var(wp, varName, "");
            string_to_dec(tmpStr, &intVal);
            entry.remote_port_end = (unsigned short)intVal;

        }

/*        *((char *)&entry_existed) = (char)index;
        if ( !apmib_get(MIB_QOS_RULE_TBL, (void *)&entry_existed)) {
		strcpy(tmpBuf, ("Get table entry error!"));
		goto setErr_qos;
        }
        if ( !apmib_set(MIB_QOS_DEL, (void *)&entry_existed)) {
		strcpy(tmpBuf, ("Delete table entry error!"));
		goto setErr_qos;
        } */

/*        if ( apmib_set(MIB_QOS_ADD, (void *)&entry) == 0) {
            strcpy(tmpBuf, ("Add table entry error!"));
            goto setErr_qos;
        } */
        memcpy(&entry_for_save[valid_num], &entry, sizeof(QOS_T));
        valid_num++;

    }


    if ( !apmib_set(MIB_QOS_DELALL, (void *)&entry)) {
        strcpy(tmpBuf, ("Delete all table error!"));
        goto setErr_qos;
    }

    for(index=0; index<valid_num; index++)
    {
        if ( apmib_set(MIB_QOS_ADD, (void *)&entry_for_save[index]) == 0) {
            strcpy(tmpBuf, ("Add table entry error!"));
            goto setErr_qos;
        }
    }

setOk_qos:
    apmib_update_web(CURRENT_SETTING);

#ifndef NO_ACTION
    pid = fork();
    if (pid) {
        waitpid(pid, NULL, 0);
    }
    else if (pid == 0) {
        snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _QOS_SCRIPT_PROG);
        execl( tmpBuf, _QOS_SCRIPT_PROG, NULL);
        exit(1);
    }
#endif

    submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page
    if (submitUrl[0])
        send_redirect_perm(wp, submitUrl);
    return;

setErr_qos:
    ERR_MSG(tmpBuf);
}
#endif

#ifdef QOS_BY_BANDWIDTH
static const char _md1[] = "Guaranteed minimum bandwidth", _md2[] = "Restricted maximum bandwidth";
static const char s4dashes[] = "----";

#define QOS_BW_CHECK_FAIL				-1
#define QOS_BW_NOT_OVERSIZE			0
#define QOS_UPLINK_BW_OVERSIZE		0x1
#define QOS_DOWNLINK_BW_OVERSIZE		0x2
#define QOS_BOTHLINK_BW_OVERSIZE		0x3

// Only for "Guaranteed minimum bandwidth",
// to check current uplink or downlink bandwidth added uplink & downlink bandwidth at previous rules
// whether larger than totoal uplink or downlink bandwidth
int checkQosRuleBw(unsigned long curUplinkBw, unsigned long curDownlinkBw, unsigned long totalUplinkBw, unsigned long totalDownlinkBw)
{
	int	entryNum, i, ret;
	IPQOS_T entry;
	unsigned long tmpTotolUplinkBw, tmpTotalDownlinkBw;

	if ( !apmib_get(MIB_QOS_RULE_TBL_NUM, (void *)&entryNum)) {
		return QOS_BW_CHECK_FAIL;
	}

	tmpTotolUplinkBw=curUplinkBw;
	tmpTotalDownlinkBw=curDownlinkBw;
	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_QOS_RULE_TBL, (void *)&entry))
			return QOS_BW_CHECK_FAIL;

		if ( (entry.mode & QOS_RESTRICT_MIN)  != 0){
			//Do check for "Guaranteed minimum bandwidth"
			tmpTotolUplinkBw += entry.bandwidth;
			tmpTotalDownlinkBw += entry.bandwidth_downlink;
		}
	}

	ret=QOS_BW_NOT_OVERSIZE;
	if(tmpTotolUplinkBw > totalUplinkBw)
		ret += QOS_UPLINK_BW_OVERSIZE;

	if(tmpTotalDownlinkBw > totalDownlinkBw)
		ret += QOS_DOWNLINK_BW_OVERSIZE;

	return ret;
}

/////////////////////////////////////////////////////////////////////////////
int ipQosList(request *wp, int argc, char **argv)
{
	int	nBytesSent=0, entryNum, i;
	IPQOS_T entry;
	char	*mode, bandwidth[10], bandwidth_downlink[10];
	char	mac[20], ip[40], *tmpStr;
#ifdef CONFIG_IPV6
	char	ip6[40];
#endif
	if ( !apmib_get(MIB_QOS_RULE_TBL_NUM, (void *)&entryNum)) {
  		fprintf(stderr, "Get table entry error!\n");
		return -1;
	}

	nBytesSent += req_format_write(wp, ("<tr class=\"tbl_head\">"
      	"<td align=center width=\"\" ><font size=\"2\"><b>Local IP Address</b></font></td>\n"
      	"<td align=center width=\"\" ><font size=\"2\"><b>MAC Address</b></font></td>\n"
#if defined(CONFIG_IPV6)
	"<td align=center width=\"20%%\" ><font size=\"2\"><b>Local IPv6 addr</b></font></td>\n"
#endif

#if defined(CONFIG_NETFILTER_XT_MATCH_LAYER7)
				"<td align=center width=\"20%%\" ><font size=\"2\"><b>Layer 7 Rule</b></font></td>\n"
#endif
      	"<td align=center width=\"\" ><font size=\"2\"><b>Mode</b></font></td>\n"
      	"<td align=center width=\"\" ><font size=\"2\"><b>Uplink Bandwidth</b></font></td>\n"
      	"<td align=center width=\"\" ><font size=\"2\"><b>Downlink Bandwidth</b></font></td>\n"
	"<td align=center width=\"\" ><font size=\"2\"><b>Comment</b></font></td>\n"
      	"<td align=center width=\"\" ><font size=\"2\"><b>Select</b></font></td></tr>\n"));

	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		if ( !apmib_get(MIB_QOS_RULE_TBL, (void *)&entry))
			return -1;

		if ( (entry.mode & QOS_RESTRICT_IP)  != 0) {
			tmpStr = inet_ntoa(*((struct in_addr *)entry.local_ip_start));
			strcpy(mac, tmpStr);
			tmpStr = inet_ntoa(*((struct in_addr *)entry.local_ip_end));
			sprintf(ip, "%s - %s", mac, tmpStr);
#ifdef CONFIG_IPV6
			strcpy(ip6, s4dashes);
#endif

			strcpy(mac, s4dashes);
		}
		else if ( (entry.mode & QOS_RESTRICT_MAC)  != 0) {
			sprintf(mac, "%02x%02x%02x%02x%02x%02x",
				entry.mac[0],entry.mac[1],entry.mac[2],entry.mac[3],entry.mac[4],entry.mac[5]);
			strcpy(ip, s4dashes);
#ifdef CONFIG_IPV6
			strcpy(ip6, s4dashes);
#endif

		}
#ifdef CONFIG_IPV6
		else if( (entry.mode & QOS_RESTRICT_IPV6)  != 0){
			strcpy(ip, s4dashes);
			strcpy(mac, s4dashes);
			strncpy(ip6,entry.ip6_src,40);
		}
#endif
		else //all
		{
			strcpy(ip, s4dashes);
			strcpy(mac, s4dashes);
#ifdef CONFIG_IPV6
			strcpy(ip6, s4dashes);
#endif
		}

		if ( (entry.mode & QOS_RESTRICT_MIN)  != 0)
			mode = (char *)_md1;
		else
			mode = (char *)_md2;

    if(entry.bandwidth == 0)
    	sprintf(bandwidth, "%s", "-");
		else
			snprintf(bandwidth, 10, "%ld", entry.bandwidth);

		if(entry.bandwidth_downlink == 0)
    	sprintf(bandwidth_downlink, "%s", "-");
		else
			snprintf(bandwidth_downlink, 10, "%ld", entry.bandwidth_downlink);

		nBytesSent += req_format_write(wp, ("<tr class=\"tbl_body\">"
			"<td align=center width=\"\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"\" ><font size=\"2\">%s</td>\n"
#ifdef CONFIG_IPV6
			"<td align=center width=\"\" ><font size=\"2\">%s</td>\n"
#endif
#if defined(CONFIG_NETFILTER_XT_MATCH_LAYER7)
      			"<td align=center width=\"\" ><font size=\"2\">%s</td>\n"
#endif
      			"<td align=center width=\"\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"\" ><font size=\"2\">%s</td>\n"
     			"<td align=center width=\"\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"\" ><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td></tr>\n"),
				ip, mac,
#ifdef CONFIG_IPV6
				ip6,
#endif
#if defined(CONFIG_NETFILTER_XT_MATCH_LAYER7)
				entry.l7_protocol,
#endif
				mode, bandwidth, bandwidth_downlink, entry.entry_name, i);
	}
	return nBytesSent;
}

int l7QosList(request *wp, int argc, char **argv)
{
	int	nBytesSent=0;

	nBytesSent += req_format_write(wp, ("<option value=\"Disable\">Disable</option>"));

#if defined(CONFIG_NETFILTER_XT_MATCH_LAYER7)
	if(0)
	{
		nBytesSent += req_format_write(wp, ("<option value=\"http\">http</option>"
		"<option value=\"bittorrent\">bittorrent</option>"
		"<option value=\"msnmessenger\">msnmessenger</option>"
		"<option value=\"doom3\">doom3</option>"
		));
	}
	else
	{

		#define READ_BUF_SIZE 512
		DIR *dir;
		struct dirent *next;

		pid_t   *pidList;
		int i=0,n=0,j=0;

		dir = opendir("/etc/l7-protocols/protocols");
		if (!dir)
		{
		        printf("find_pid_by_name: Cannot open /proc");
		        exit(1);
		}
		pidList = malloc(sizeof(*pidList)*5);
		while ((next = readdir(dir)) != NULL) {
			FILE *status;
		  char filename[READ_BUF_SIZE];
		  char buffer[READ_BUF_SIZE];
		  char name[READ_BUF_SIZE];

		  char *lineptr = NULL;
		  char *str;

		  /* Must skip ".." since that is outside /proc */
		  if (strcmp(next->d_name, "..") == 0)
		  	continue;

		  if (strstr(next->d_name, ".pat") == NULL)
		  	continue;

			lineptr = next->d_name;

			str = strsep(&lineptr,".");

			nBytesSent += req_format_write(wp, ("<option value=\"%s\">%s</option>"),str,str);

		}
		closedir(dir);
	}

#endif //#if defined(CONFIG_NETFILTER_XT_MATCH_LAYER7)

	return nBytesSent;
}

/////////////////////////////////////////////////////////////////////////////
void formIpQoS(request *wp, char *path, char *query)
{
	char *submitUrl, *strAdd, *strDel, *strVal, *strDelAll;
	char *strIpStart, *strIpEnd, *strMac, *strBandwidth, *strBandwidth_downlink, *strComment, *strL7Protocol;
#ifdef CONFIG_IPV6
	char *ip6_src;
#endif
	char tmpBuf[100];
	int entryNum, intVal, i;
	IPQOS_T entry;
	unsigned int *p;
	unsigned int *q;
#ifndef NO_ACTION
	int pid;
#endif
	unsigned long totalUplinkBw, totalDownlinkBw;
	int ret;
	int j=0;
	unsigned int ip1,ip2;
	unsigned char mac[6];
	struct in_addr ips,ipe;
//displayPostDate(wp->post_data);

	strAdd = req_get_cstream_var(wp, ("addQos"), "");
	strDel = req_get_cstream_var(wp, ("deleteSel"), "");
	strDelAll = req_get_cstream_var(wp, ("deleteAll"), "");

	memset(&entry, '\0', sizeof(entry));

	if (strAdd[0]) {
		strVal = req_get_cstream_var(wp, ("enabled"), "");
		if ( !strcmp(strVal, "ON"))
			intVal = 1;
		else
			intVal = 0;
		if ( apmib_set( MIB_QOS_ENABLED, (void *)&intVal) == 0) {
			strcpy(tmpBuf, ("Set enabled flag error!"));
			goto setErr;
		}

		if (intVal == 0)
			goto setOk;

		strVal = req_get_cstream_var(wp, ("automaticUplinkSpeed"), "");
		if ( !strcmp(strVal, "ON"))
			intVal = 1;
		else
			intVal = 0;
		if ( apmib_set( MIB_QOS_AUTO_UPLINK_SPEED, (void *)&intVal) == 0) {
			strcpy(tmpBuf, ("Set mib error!"));
			goto setErr;
		}

		if (intVal == 0) {
			strVal = req_get_cstream_var(wp, ("manualUplinkSpeed"), "");
			string_to_dec(strVal, &intVal);
			if ( apmib_set( MIB_QOS_MANUAL_UPLINK_SPEED, (void *)&intVal) == 0) {
				strcpy(tmpBuf, ("Set mib error!"));
				goto setErr;
			}
			totalUplinkBw=intVal;
		}
		else{
			// Auto uplink speed
#ifdef CONFIG_RTL_8198
			totalUplinkBw=1024000;		// 1000Mbps
#else
			totalUplinkBw=102400;		// 100Mbps
#endif
		}

		strVal = req_get_cstream_var(wp, ("automaticDownlinkSpeed"), "");
		if ( !strcmp(strVal, "ON"))
			intVal = 1;
		else
			intVal = 0;

		if ( apmib_set( MIB_QOS_AUTO_DOWNLINK_SPEED, (void *)&intVal) == 0) {
			strcpy(tmpBuf, ("Set mib error!"));
			goto setErr;
		}

		if (intVal == 0) {
			strVal = req_get_cstream_var(wp, ("manualDownlinkSpeed"), "");
			string_to_dec(strVal, &intVal);
			if ( apmib_set( MIB_QOS_MANUAL_DOWNLINK_SPEED, (void *)&intVal) == 0) {
				strcpy(tmpBuf, ("Set mib error!"));
				goto setErr;
			}
			totalDownlinkBw=intVal;
		}
		else{
			// Auto uplink speed
#ifdef CONFIG_RTL_8198
			totalDownlinkBw=1024000;		// 1000Mbps
#else
			totalDownlinkBw=102400;		// 100Mbps
#endif
		}

		strIpStart = req_get_cstream_var(wp, ("ipStart"), "");
		strIpEnd = req_get_cstream_var(wp, ("ipEnd"), "");
		strMac = req_get_cstream_var(wp, ("mac"), "");
#ifdef CONFIG_IPV6
		ip6_src = req_get_cstream_var(wp, ("ip6_src"), "");
#endif
		strBandwidth = req_get_cstream_var(wp, ("bandwidth"), "");
		strBandwidth_downlink = req_get_cstream_var(wp, ("bandwidth_downlink"), "");
		strComment = req_get_cstream_var(wp, ("comment"), "");
		strL7Protocol = req_get_cstream_var(wp, ("l7_protocol"), "");


		if (!strIpStart[0] && !strIpEnd[0] && !strMac[0] && !strBandwidth[0] && !strBandwidth_downlink[0] && !strComment[0]
#ifdef CONFIG_IPV6
		&&(!ip6_src[0])
#endif

		)
			goto setOk;


		if ( strL7Protocol[0] ) {
			strcpy((char *)entry.l7_protocol, strL7Protocol);
		}

		strVal = req_get_cstream_var(wp, ("addressType"), "");
		string_to_dec(strVal, &intVal);
		if (intVal == 0) { // IP
			inet_aton(strIpStart, &ips);
			inet_aton(strIpEnd, &ipe);
			//printf("ips:%x,ipe:%x,[%s]:[%d].\n",ips.s_addr,ipe.s_addr,__FUNCTION__,__LINE__);

			apmib_get(MIB_QOS_RULE_TBL_NUM, (void *)&entryNum);

			for(j=1;j<=entryNum;j++)
			{
				*((char *)&entry) = (char)j;
				if ( apmib_get(MIB_QOS_RULE_TBL, (void *)&entry))
				{
					if(entry.mode & QOS_RESTRICT_IP)
					{
						p = (unsigned int *)entry.local_ip_start;
						q = (unsigned int *)entry.local_ip_end;
						ip1=*p;
						ip2=*q;
						//printf("ip1:%x,ip2:%x,[%s]:[%d].\n",ip1,ip2,__FUNCTION__,__LINE__);
						if(((ips.s_addr >= ip1) && (ips.s_addr <= ip2))
							||((ipe.s_addr >= ip1) && (ipe.s_addr <=ip2))
							||((ips.s_addr < ip1) && (ipe.s_addr > ip2)))
						{
							strcpy(tmpBuf, (" ip address conflict!"));
							goto setErr;
						}

					}
				}
			}
			inet_aton(strIpStart, (struct in_addr *)&entry.local_ip_start);
			inet_aton(strIpEnd, (struct in_addr *)&entry.local_ip_end);
			entry.mode = QOS_RESTRICT_IP;
		}
		else if (intVal == 1) { //MAC
			string_to_hex(strMac, mac, 12);
			apmib_get(MIB_QOS_RULE_TBL_NUM, (void *)&entryNum);

			for(j=1;j<=entryNum;j++)
			{
				*((char *)&entry) = (char)j;
				if ( apmib_get(MIB_QOS_RULE_TBL, (void *)&entry))
				{
					if(entry.mode & QOS_RESTRICT_MAC)
					{
						/*printf("[%s]:[%d]%02x%02x%02x%02x%02x%02x\n",__FUNCTION__,__LINE__,
						entry.mac[0],entry.mac[1],entry.mac[2],entry.mac[3],entry.mac[4],entry.mac[5]);*/
						if((entry.mac[0]==mac[0])&&(entry.mac[1]==mac[1])
						&&(entry.mac[2]==mac[2])&&(entry.mac[3]==mac[3])
						&&(entry.mac[4]==mac[4])&&(entry.mac[5]==mac[5]))
						{
							strcpy(tmpBuf, (" mac address conflict!"));
							goto setErr;
						}

					}
				}
			}
			if (!string_to_hex(strMac, entry.mac, 12))
			{
				strcpy(tmpBuf, ("MAC input fail!"));
				goto setErr;
			}
			entry.mode = QOS_RESTRICT_MAC;
		}
#ifdef CONFIG_IPV6
		else if(intVal == 2){
			if(ip6_src!=NULL)
				strncpy(entry.ip6_src,ip6_src,40);
			entry.mode = QOS_RESTRICT_IPV6;
		}
#endif
		else
		{
			entry.mode = QOS_RESTRICT_ALL;
		}

		strVal = req_get_cstream_var(wp, ("mode"), "");
		if (strVal[0] == '1')
			entry.mode |= QOS_RESTRICT_MIN;
		else
			entry.mode |= QOS_RESTRICT_MAX;

		string_to_dec(strBandwidth, &intVal);
		entry.bandwidth = (unsigned long)intVal;

		string_to_dec(strBandwidth_downlink, &intVal);
		entry.bandwidth_downlink = (unsigned long)intVal;

		//To check uplink & downlink guaranteed minimum bandwidth
		if(entry.mode &  QOS_RESTRICT_MIN){
			ret=checkQosRuleBw(entry.bandwidth, entry.bandwidth_downlink, totalUplinkBw, totalDownlinkBw);
			if(ret==QOS_BW_CHECK_FAIL){
				strcpy(tmpBuf, ("checkQosRuleBw fail!"));
				goto setErr;
			}
			else if(ret==QOS_BOTHLINK_BW_OVERSIZE){
				strcpy(tmpBuf, ("Error: for guaranteed minimum bandwidth of both uplink and downlink, the sum bandwidth of all qos rules are larger than the total bandwidth!"));
				goto setErr;
			}
			else if(ret==QOS_DOWNLINK_BW_OVERSIZE){
				strcpy(tmpBuf, ("Error: for guaranteed minimum bandwidth of downlink, the sum bandwidth of all qos rules is larger than the total downlink bandwidth!"));
				goto setErr;
			}
			else if(ret==QOS_UPLINK_BW_OVERSIZE){
				strcpy(tmpBuf, ("Error: for guaranteed minimum bandwidth of uplink, the sum bandwidth of all qos rules is larger than the total uplink bandwidth!"));
				goto setErr;
			}
		}

		if ( strComment[0] ) {
			strcpy((char *)entry.entry_name, strComment);
		}
		entry.enabled = 1;
		if ( !apmib_get(MIB_QOS_RULE_TBL_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, ("Get entry number error!"));
			goto setErr;
		}

		if ( (entryNum + 1) > MAX_QOS_RULE_NUM) {
			strcpy(tmpBuf, ("Cannot add new entry because table is full!"));
			goto setErr;
		}

		// set to MIB. try to delete it first to avoid duplicate case
		apmib_set(MIB_QOS_DEL, (void *)&entry);
		if ( apmib_set(MIB_QOS_ADD, (void *)&entry) == 0) {
			strcpy(tmpBuf, ("Add table entry error!"));
			goto setErr;
		}
	}

	/* Delete entry */
	if (strDel[0]) {
		if ( !apmib_get(MIB_QOS_RULE_TBL_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, ("Get entry number error!"));
			goto setErr;
		}

		for (i=entryNum; i>0; i--) {
			snprintf(tmpBuf, 20, "select%d", i);

			strVal = req_get_cstream_var(wp, tmpBuf, "");
			if ( !strcmp(strVal, "ON") ) {
				*((char *)&entry) = (char)i;
				if ( !apmib_get(MIB_QOS_RULE_TBL, (void *)&entry)) {
					strcpy(tmpBuf, ("Get table entry error!"));
					goto setErr;
				}
				if ( !apmib_set(MIB_QOS_DEL, (void *)&entry)) {
					strcpy(tmpBuf, ("Delete table entry error!"));
					goto setErr;
				}
			}
		}
	}

	/* Delete all entry */
	if ( strDelAll[0]) {
		if ( !apmib_set(MIB_QOS_DELALL, (void *)&entry)) {
			strcpy(tmpBuf, ("Delete all table error!"));
			goto setErr;
		}
	}

setOk:
	apmib_update(CURRENT_SETTING);

#ifndef NO_ACTION
	pid = fork();
        if (pid) {
	      	waitpid(pid, NULL, 0);
	}
        else if (pid == 0) {
		snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _QOS_SCRIPT_PROG);
		execl( tmpBuf, _QOS_SCRIPT_PROG, NULL);
             exit(1);
        }
#endif

	submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page

#ifdef REBOOT_CHECK
	if(needReboot == 1)
	{
		OK_MSG(submitUrl);
		return;
	}
#endif

	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);
  	return;

setErr:
	ERR_MSG(tmpBuf);

}
#endif

#ifdef SAMBA_WEB_SUPPORT
int UserEditName(request *wp, int argc, char **argv)
{
	int 			nBytesSent = 0;
	int				index;
	STORAGE_USER_T	s_user;

	apmib_get(MIB_STORAGE_USER_EDIT_INDEX,(void*)&index);
	*((char*)&s_user) = (char)index;
	apmib_get(MIB_STORAGE_USER_TBL,(void*)&s_user);

	nBytesSent += req_format_write(wp, ("<tr>"
		"<td width=\"20%%\"><font size=2><b>Name:</b></td>\n"
		"<td width=\"50%%\"><font size=2>%s</td></tr>\n"),
		s_user.storage_user_name);

	return nBytesSent;
}

int GroupEditName(request *wp, int argc, char **argv)
{
	int 			nBytesSent = 0;
	int				index;
	STORAGE_GROUP_T	s_group;

	apmib_get(MIB_STORAGE_GROUP_EDIT_INDEX,(void*)&index);
	*((char*)&s_group) = (char)index;
	apmib_get(MIB_STORAGE_GROUP_TBL,(void*)&s_group);

	nBytesSent += req_format_write(wp, ("<tr>"
		"<td width=\"20%%\"><font size=2><b>Group Name</b></td>\n"
		"<td width=\"50%%\"><font size=2>%s</td></tr>\n"),
		s_group.storage_group_name);

	return nBytesSent;
}

int ShareFolderList(request *wp, int argc, char **argv)
{
	int 			nBytesSent = 0,len = 0;
	int				number,i;
	STORAGE_GROUP_T	s_group;

	nBytesSent += req_format_write(wp, ("<tr>"
      	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Diaplay Name</b></font></td>\n"
      	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Shared Folder</b></font></td>\n"
      	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Group</b></font></td>\n"
      	"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Access</b></font></td>\n"
      	"<td align=center width=\"10%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Delete</b></font></td></tr>\n"));

	apmib_get(MIB_STORAGE_GROUP_TBL_NUM,(void*)&number);
	for(i = 0;i < number;i++)
	{
		memset(&s_group,'\0',sizeof(STORAGE_GROUP_T));
		*((char*)&s_group) = (char)(i+1);
		apmib_get(MIB_STORAGE_GROUP_TBL,(void*)&s_group);

		if(s_group.storage_group_sharefolder_flag == 1){
			nBytesSent += req_format_write(wp, ("<tr>"
      			"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td>\n"
      			"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td>\n"
      			"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td>\n"
      			"<td align=center width=\"20%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td>\n"
      			"<td align=center width=\"10%%\" bgcolor=\"#808080\"><font size=\"2\"><b><input type=\"checkbox\" value=\"%s\" name=\"delete%d\"></b></font></td></tr>\n"),
      			s_group.storage_group_displayname,s_group.storage_group_sharefolder,s_group.storage_group_name,s_group.storage_group_access,
      			s_group.storage_group_name,i);
		}
	}

	return nBytesSent;
}

int Storage_GeDirRoot(request *wp, int argc, char **argv)
{
	int 			nBytesSent = 0;
	char*			dir_name;
	char			tmpBuff[30];
	char			tmpBuff2[30];

	memset(tmpBuff,'\0',30);
	memset(tmpBuff2,'\0',30);
	apmib_get(MIB_STORAGE_FOLDER_LOCAL,(void*)tmpBuff);

	dir_name = strstr(tmpBuff,"sd");
	strcpy(tmpBuff2,"/tmp/usb/");
	strcat(tmpBuff2,dir_name);

	nBytesSent += req_format_write(wp, ("<tr>"
		"<td width=\"20%%\"><font size=2><b>Location</b></td>\n"
		"<td width=\"50%%\"><font size=2>%s</td></tr>\n"
		"<input type=\"hidden\" name=\"Location\" value=\"%s\">\n"),
		tmpBuff2,tmpBuff2);

	return nBytesSent;
}

int FolderList(request *wp, int argc, char **argv)
{
	int 			nBytesSent = 0,len;
	FILE 			*fp,*fp2;
	char			tmpBuff[100],tmpBuff2[100];
	char			strLocal[30],Location[30];
	char*			strRootDir;
	int				i = 0,index = 0,flag = 0,number;
	char			*p,*p2;
	STORAGE_GROUP_T	s_group;


	memset(tmpBuff,'\0',100);
	memset(tmpBuff2,'\0',100);
	memset(strLocal,'\0',30);

	apmib_get(MIB_STORAGE_FOLDER_LOCAL,(void*)strLocal);
	strRootDir = strstr(strLocal,"sd");
	snprintf(tmpBuff2,100,"ls /tmp/usb/%s >/tmp/tmp.txt",strRootDir);
	system(tmpBuff2);

	nBytesSent += req_format_write(wp, ("<tr>"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Folder</b></font></td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Group</b></font></td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Select</b></font></td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Delete</b></font></td></tr>\n"));

	memset(tmpBuff,'\0',100);
	fp = fopen("/tmp/tmp.txt","r");
	if(fp == NULL)
	{
		return nBytesSent;
	}

	while(fgets(tmpBuff, 100, fp)){
		len = strlen(tmpBuff);
		tmpBuff[len-1] = '\0';
		snprintf(tmpBuff2,100,"ls -ld /tmp/usb/%s/%s >/tmp/tmp2.txt",strRootDir,tmpBuff);
		system(tmpBuff2);

		memset(tmpBuff2,'\0',100);
		fp2 = fopen("/tmp/tmp2.txt","r");
		if(fp2 == NULL){
			return nBytesSent;
		}

		if(fgets(tmpBuff2,100,fp2)){
			if(tmpBuff2[0] != 'd'){
				memset(tmpBuff,'\0',100);
				memset(tmpBuff2,'\0',100);
				fclose(fp2);
				continue;
			}
			p = tmpBuff2;

			while(i < 3){
				while(*p == ' '){
					p++;
				}
				p = strstr(p," ");
				i++;
			}

			while(*p == ' ')
				p++;

			p2 = strstr(p," ");
			*p2 = '\0';
			i  = 0;
		}

		apmib_get(MIB_STORAGE_GROUP_TBL_NUM,(void*)&number);
		for(i = 0;i < number;i++)
		{
			memset(&s_group,'\0',sizeof(STORAGE_GROUP_T));
			*((char*)&s_group) = (char)(i+1);
			apmib_get(MIB_STORAGE_GROUP_TBL,(void*)&s_group);

			if(s_group.storage_group_sharefolder_flag == 1){
				memset(Location,'\0',30);
				snprintf(Location,30,"/tmp/usb/%s/%s",strRootDir,tmpBuff);
				if(!strcmp(Location,s_group.storage_group_sharefolder)){
					flag = 1;
					break;
				}
			}
		}

		if(flag == 0){
			nBytesSent += req_format_write(wp, ("<tr>"
				"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">/tmp/usb/%s/%s</td>\n"
      			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">--</td>\n"
      			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><font size=\"2\"><input type=\"checkbox\" value=\"/tmp/usb/%s/%s\" name=\"select%d\" onClick=\"SelectClick(%d)\"></td>\n"
      			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" value=\"/tmp/usb/%s/%s\" name=\"delete%d\" onClick=\"DeleteClick(%d)\"></td></tr>\n"),
				strRootDir,tmpBuff,strRootDir,tmpBuff,index,index,strRootDir,tmpBuff,index,index);
			index++;
		}

		fclose(fp2);
		memset(tmpBuff,'\0',100);
		memset(tmpBuff2,'\0',100);
		flag = 0;
	}
	fclose(fp);

	nBytesSent += req_format_write(wp,(
		"<input type=\"hidden\"  name=\"DirNum\" value=\"%d\">\n"),
		index);
	return nBytesSent;

}

int DiskList(request *wp, int argc, char **argv)
{
	int 			nBytesSent = 0,len = 0;
	int				i,j = 0;
	char			capability[20],freeSize[20];
	int				num1,num2;
	char			*ptr;
	FILE 			*fp;
	int				total_size,free_size;
	char			tmpBuff[100];
	unsigned char	local[10];

	nBytesSent += req_format_write(wp, ("<tr>"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Partition</b></font></td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Capacity</b></font></td>\n"
		"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Free Space</b></font></td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Create Share</b></font></td></tr>\n"));

	memset(tmpBuff,0,100);
	system("df >/tmp/tmp.txt");
	fp = fopen("/tmp/tmp.txt","r");
	if(fp == NULL)
		return nBytesSent;

	while (fgets(tmpBuff, 100, fp)) {
		ptr = strstr(tmpBuff, "/dev/sd");
		if (ptr) {
			local[j] =  ptr - tmpBuff;
			while(j++ < 4)
			{
				ptr = strstr(ptr," ");
				while(*ptr == ' '){
					*ptr++ = '\0';
				}
				local[j] = ptr - tmpBuff;
			}
			local[j] = ptr - tmpBuff;

			memset(capability,'\0',20);
			memset(freeSize,'\0',20);
			num1 = atoi(tmpBuff+local[1])/(1000*1000);
			num2 = (atoi(tmpBuff+local[1])/1000)%1000;
			snprintf(capability,20,"%d.%d(G)",num1,num2);
			num1 = atoi(tmpBuff+local[3])/(1000*1000);
			num2 = (atoi(tmpBuff+local[3])/1000)%1000;
			snprintf(freeSize,20,"%d.%d(G)",num1,num2);

			nBytesSent += req_format_write(wp, ("<tr>"
				"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
     			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><input type=\"submit\" name=\"create_share\" value=\"Create Share\" onClick=\"CreateShare('%s')\"></td></tr>\n"),
				tmpBuff+local[0], capability, freeSize,tmpBuff+local[0]);

			memset(tmpBuff,0,100);
		}
		j = 0;
	}
	fclose(fp);

	return nBytesSent;
}

int Storage_DispalyUser(request *wp, int argc, char **argv)
{
	int nBytesSent = 0;
	STORAGE_USER_T s_user;
	int i;
	int number;

	nBytesSent += req_format_write(wp, ("<tr>"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>User Name</b></font></td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Group</b></font></td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Edit</b></font></td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Delete</b></font></td></tr>\n"));

	apmib_get(MIB_STORAGE_USER_TBL_NUM,(void*)&number);

	for(i = 0;i < number;i++)
	{
		*((char*)&s_user) = (char)(i+1);
		apmib_get(MIB_STORAGE_USER_TBL,(void*)&s_user);

		nBytesSent += req_format_write(wp, ("<tr>"
			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
      		"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
      		"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><input type=\"submit\" value=\"Edit\" onclick=\"UserEditClick('%d')\"></td>\n"
      		"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td></tr>\n"),
			s_user.storage_user_name, s_user.storage_user_group,(i+1),(i+1));
	}
	return nBytesSent;
}

int Storage_DispalyGroup(request *wp, int argc, char **argv)
{
	int nBytesSent = 0;
	STORAGE_GROUP_T s_group;
	int i;
	int number;

	nBytesSent += req_format_write(wp, ("<tr>"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Group Name</b></font></td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Access</b></font></td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Edit</b></font></td>\n"
      	"<td align=center width=\"25%%\" bgcolor=\"#808080\"><font size=\"2\"><b>Delete</b></font></td></tr>\n"));

	apmib_get(MIB_STORAGE_GROUP_TBL_NUM,(void*)&number);

	for(i = 0;i < number;i++)
	{
		*((char*)&s_group) = (char)(i+1);
		apmib_get(MIB_STORAGE_GROUP_TBL,(void*)&s_group);

		nBytesSent += req_format_write(wp, ("<tr>"
			"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
      		"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
      		"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><input type=\"submit\" value=\"Edit\" onClick=\"GroupEditClick('%d')\"></td>\n"
      		"<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"select%d\" value=\"ON\"></td>\n"),
			s_group.storage_group_name, s_group.storage_group_access,(i+1),(i+1));

	}
	return nBytesSent;
}

int Storage_GetGroupMember(request *wp, int argc, char **argv)
{
	int nBytesSent = 0;
	STORAGE_GROUP_T s_group;
	int i;
	int number;

	nBytesSent += req_format_write(wp,
		("<select name=\"Group\">\n"));

	apmib_get(MIB_STORAGE_GROUP_TBL_NUM,(void*)&number);

	for(i = 0;i < number;i++)
	{
		*((char*)&s_group) = (char)(i+1);
		apmib_get(MIB_STORAGE_GROUP_TBL,(void*)&s_group);

		nBytesSent += req_format_write(wp,
			("<option value=\"%d\">%s</option>\n"),
			(i+1),s_group.storage_group_name);

	}

	nBytesSent += req_format_write(wp,
		("</select>\n"));

	return nBytesSent;
}

#endif
#ifdef __DAVO__
int LanRestrictList(request *wp, int argc, char **argv)
{
	int nBytesSent=0;
	char query[32];
	char *tmpBuf;
	int enable;
	int i;
	int port;
	int maxnum;

	tmpBuf = nvram_get("x_LANRESTRICT_ENABLE");
	enable = atoi(tmpBuf);

	nBytesSent += req_format_write(wp, ("<tr><td><font size=2><b>\n"
		"<input type=\"checkbox\" name=\"lan_restrict_enable\" value=\"ON\" %s "
		"ONCLICK=updateState()>&nbsp;&nbsp;랜 제한 사용</b><br></td></tr>\n"),
			enable?"checked":"");

	for (i = 1; i <= 4; i++) {
		sprintf(query, "x_LANRESTRICT_ENABLE_PORT%d", i);

		tmpBuf = nvram_get(query);
		if (tmpBuf) {
			port = atoi(tmpBuf);
		}

		sprintf(query, "x_LANRESTRICT_MAXNUM%d", i);
		tmpBuf = nvram_get(query);
		if (tmpBuf) {
			maxnum = atoi(tmpBuf);
		}
		nBytesSent += req_format_write(wp, ("<tr><td>&nbsp;&nbsp;</td></tr>\n"));
		nBytesSent += req_format_write(wp, ("<tr><td><input type=\"checkbox\" name=\"lan_restrict_port_enable%d\" value=\"ON\" %s>LAN%d&nbsp;&nbsp;"
					"<select name=\"lan_restrict_num%d\"><option value=\"1\" %s>1<option value=\"2\" %s>2"
					"<option value=\"3\" %s>3<option value=\"4\" %s>4</select></td></tr>\n"),
				i, port?"checked":"", i, i, maxnum==1?"selected":"", maxnum==2?"selected":"",
				maxnum==3?"selected":"", maxnum==4?"selected":"");
	}
	return nBytesSent;
}

void formLanRestrict(request *wp, char *path, char *query)
{
	char *submitUrl, *strEnable, *strVal;
	char queury[32];
	int i;

	apmib_set_hist_clear();

	strEnable = req_get_cstream_var(wp, ("lan_restrict_enable"), (""));
	if ( !strcmp(strEnable, ("ON"))) {
		apmib_nvram_set("x_LANRESTRICT_ENABLE", "1");
		for (i = 1; i <= 4; i++) {
			sprintf(queury, "lan_restrict_port_enable%d", i);
			strEnable = req_get_cstream_var(wp, queury, (""));
			sprintf(queury, "x_LANRESTRICT_ENABLE_PORT%d", i);
			if ( !strcmp(strEnable, ("ON"))) {
				apmib_nvram_set(queury, "1");
				sprintf(queury, "lan_restrict_num%d", i);
				strVal = req_get_cstream_var(wp, queury, (""));
				sprintf(queury, "x_LANRESTRICT_MAXNUM%d", i);
				apmib_nvram_set(queury, strVal);
			} else {
				apmib_nvram_set(queury, "0");
			}
		}
	} else {
		apmib_nvram_set("x_LANRESTRICT_ENABLE", "0");
	}

	web_config_trace(3, 6);		/* firewall/LAN-restrict */
	system("sysconf lanrestrict");

	submitUrl = req_get_cstream_var(wp, ("submit-url"), (""));   // hidden page

	nvram_commit();
#ifdef __DAVO__
	need_reboot = 1;
	OK_MSG("/skb_lanrestrict.htm");
#else
	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);
#endif
	return;
}

void formBroadcastStormCtrl(request *wp, char *path, char *query)
{
	char *submitUrl, *strEnable, *strVal;
	char info[32];
	int rate;
	int i;
	char strBuf[64];

	apmib_set_hist_clear();

	strEnable = req_get_cstream_var(wp, ("broadcast_storm_ctrl_enable"), (""));
	if (!strcmp(strEnable, ("ON"))) {
		apmib_nvram_set("x_BCSTORM_CTRL_ENABLE", "1");
		strVal = req_get_cstream_var(wp, ("rate"), (""));
		rate = atoi(strVal);
		if (rate < 1 || rate > 500) {
			ERR_MSG("오류!!! BPS는 1 ~ 500 퍼센트 사이로 설정해야 합니다");
			return;
		}
		apmib_nvram_set("x_BCSTORM_CTRL_PERCENT", strVal);
		#if 1
		//cpercent -> permillage(by skb)
		sprintf(strBuf, "%d", (int)(float)(rate * 30.6));
		#else
		sprintf(strBuf, "%d", (int)(float)(rate * 303.6));
		#endif

		apmib_nvram_set("x_BCSTORM_CTRL_BPS", strBuf);

		for (i = 0; i < 5; i++) {
			sprintf(strBuf, "port%d_enable", i);
			strVal = req_get_cstream_var(wp, (strBuf), (""));
			if (!strcmp(strVal, ("ON"))) {
				sprintf(info, "1");
			} else {
				sprintf(info, "0");
			}
			sprintf(strBuf, "x_BCSTORM_PORT%d_ENABLE", i);
			apmib_nvram_set(strBuf, info);
		}
	} else {
		apmib_nvram_set("x_BCSTORM_CTRL_ENABLE", "0");
	}

	web_config_trace(3, 7);		/* firewall/broad caststorm control */
	nvram_commit();
	system("/bin/broadcast_storm.sh");

	submitUrl = req_get_cstream_var(wp, ("submit-url"), (""));	// hidden page
#ifdef __DAVO__
	need_reboot = 1;
	OK_MSG("/skb_bstorm.htm");
#else
	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);
#endif

	return;
}
#endif

static void gen_captcha_name(unsigned char *captcha)
{
	int i;
	char capt_str[6];
	static int rand_seed_gen=0;
	int len=CAPTCHA_STR_POOL_LEN;

	if (!rand_seed_gen) {
		int fd;
		fd = open("/dev/urandom", O_RDONLY);
		if (fd >= 0) {
			read(fd, (unsigned char *)&i, 4);
			close(fd);
		} else {
			i = (time_t)time(NULL);
		}
		srand((unsigned int)i);
		rand_seed_gen=1;
	}

	for (i = 0; i < 5; i ++) {
		capt_str[i]=CAPTCHA_STR_POOL[(rand()%len)];
	}
	capt_str[i]=0;

	strncpy(captcha, capt_str, CAPTCHA_STR_LEN-1);
	captcha[CAPTCHA_STR_LEN-1]=0;
}

static int unlink_slow(const char *pattern, int ceiling)
{
	glob_t gb;
	struct stat sb;
	time_t current;
	unsigned long elapsed;
	int i, left;

	if (glob(pattern, GLOB_NOSORT, NULL, &gb))
		return -1;
	time(&current);
	left = gb.gl_pathc;
	for (i = 0; i < gb.gl_pathc; i++) {
		if (!stat(gb.gl_pathv[i], &sb)) {
			elapsed = (unsigned long)(current - sb.st_atime);
			if (elapsed < 3UL)
				continue;
		}
		unlink(gb.gl_pathv[i]);
		/* hack for marking deletion */
		gb.gl_pathv[i][0] = '\0';
		left--;
	}

	for (i = 0; (left > ceiling) && (i < gb.gl_pathc); i++) {
		if (gb.gl_pathv[i][0]) {
			/* force deletion */
			unlink(gb.gl_pathv[i]);
			left--;
		}
	}
	globfree(&gb);
	return left;
}

int captcha_img(request *wp, int argc, char **argv)
{
	int	nBytesSent = 0;
	char hash_captcha[80];
	char captcha_str[6];
	char captcha_fname[128];
	int ret = 0;

	unlink_slow("/tmp/img/*", 3);

	gen_captcha_name(captcha_str);
	hash_sha256_captcha(captcha_str, hash_captcha);

	mkdir("/tmp/img", 0755);
	snprintf(captcha_fname, sizeof(captcha_fname), "/tmp/img/%s.gif", hash_captcha);

	ret = gencaptcha(captcha_str, captcha_fname);

	if (ret != 0)
		return -1;

	snprintf(captcha_fname, sizeof(captcha_fname), "img/%s.gif", hash_captcha);
	nBytesSent += req_format_write(wp, ("%s"), captcha_fname);

	return nBytesSent;
}
#endif // HOME_GATEWAY

