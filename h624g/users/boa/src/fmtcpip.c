/*
 *      Web server handler routines for TCP/IP stuffs
 *
 *      Authors: David Hsu	<davidhsu@realtek.com.tw>
 *
 *      $Id: fmtcpip.c,v 1.24 2009/08/24 10:31:08 bradhuang Exp $
 *
 */

/*-- System inlcude files --*/
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <time.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <syslog.h>
/*-- Local inlcude files --*/
#include "boa.h"
#include "globals.h"
#include "apmib.h"
#include "apform.h"
#include "utility.h"
#include "mibtbl.h"
#include "asp_page.h"
#ifdef __DAVO__
#include <bcmnvram.h>
#include <netinet/if_ether.h>
#include <sys/syscall.h>
#include <libytool.h>
#include "linux_list.h"
#endif
#ifdef CONFIG_NVRAM_APMIB
#include "nvram_mib/nvram_mib.h"
#endif

#ifdef __i386__
#define _LITTLE_ENDIAN_
#endif

#define _DHCPD_PROG_NAME	"udhcpd"
#define _DHCPD_PID_PATH		"/var/run"
#define _DHCPC_PROG_NAME	"udhcpc"
#define _DHCPC_PID_PATH		"/etc/udhcpc"
#define _PATH_DHCPS_LEASES	"/var/lib/misc/udhcpd.leases"


/*-- Macro declarations --*/
#ifdef _LITTLE_ENDIAN_
#define ntohdw(v) ( ((v&0xff)<<24) | (((v>>8)&0xff)<<16) | (((v>>16)&0xff)<<8) | ((v>>24)&0xff) )

#else
#define ntohdw(v) (v)
#endif

#define RECONNECT_MSG(url) { \
	req_format_write(wp, "<html><body><blockquote><h4>Change setting successfully!<BR><BR>If IP address was modified, you have to re-connect the WebServer" \
		"<BR>with the new address.<BR><BR>" \
                "<form><input type=button value=\"  OK  \" OnClick=window.location.replace(\"%s\")></form></blockquote></body></html>", url);\
}

extern void translate_control_code(char *buffer);

/*-- Forward declarations --*/
#if 0
static DHCP_T wanDhcpTmp=(DHCP_T)-1;
#endif

#ifdef __DAVO__
extern int dv_reboot_system;
extern int need_reboot;
#endif

//////////////////////////////////////////////////////////////////////////////
static int isValidName(char *str)
{
	int i, len=strlen(str);

	for (i=0; i<len; i++) {
		if (str[i] == ' ' || str[i] == '"' || str[i] == '\x27' || str[i] == '\x5c' || str[i] == '$')
			return 0;
	}
	return 1;
}

//////////////////////////////////////////////////////////////////////////////
int getOneDhcpClient(char **ppStart, unsigned long *size, char *ip, char *mac, char *liveTime, char *name)
{
	struct dhcpOfferedAddr entry;
	 u_int8_t empty_haddr[16];

     	memset(empty_haddr, 0, 16);
	if ( *size < sizeof(entry) )
		return -1;

	entry = *((struct dhcpOfferedAddr *)*ppStart);
	*ppStart = *ppStart + sizeof(entry);
	*size = *size - sizeof(entry);

	if (entry.expires == 0)
		return 0;

	if(!memcmp(entry.chaddr, empty_haddr, 16)){
		//fprintf(stderr, "got a unavailable entry for ip=%s\n",inet_ntoa(*((struct in_addr *)&entry.yiaddr)));
		return 0;
	}
	sprintf(ip, "%u.%u.%u.%u", NIPQUAD(entry.yiaddr));
	snprintf(mac, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
			entry.chaddr[0],entry.chaddr[1],entry.chaddr[2],entry.chaddr[3],
			entry.chaddr[4], entry.chaddr[5]);
	if(entry.expires == 0xffffffff)
        sprintf(liveTime,"%s", "Always");
	else
		snprintf(liveTime, 10, "%lu", (unsigned long)ntohl(entry.expires));
	snprintf(name, 64, "%s", entry.hostname);

	return 1;
}


///////////////////////////////////////////////////////////
int getPid(char *filename)
{
	struct stat status;
	char buff[100];
	FILE *fp;

	if ( stat(filename, &status) < 0)
		return -1;
	fp = fopen(filename, "r");
	if (!fp) {
        	fprintf(stderr, "Read pid file error!\n");
		return -1;
   	}
	fgets(buff, 100, fp);
	fclose(fp);

	return (atoi(buff));
}
int tcpipLanHandler(request *wp, char *tmpBuf)
{
	char *strIp, *strMask, *strGateway, *strDhcp, *strStp, *strMac, *strDNS, *strDomain, *strDhcpLeaseTime;
	char *strOption82;
	struct in_addr inIp, inMask, inGateway;
	DHCP_T dhcp, curDhcp;

	int stp;
	char *strdhcpRangeStart, *strdhcpRangeEnd;
	struct in_addr dhcpRangeStart, dhcpRangeEnd;
	struct in_addr dns1, dns2, dns3;
	int call_from_wizard = 0;
	int lan_dhcp_mode=0;
	int dhcp_lease_time=0;

	if (wp->superUser == 1) {
		strOption82 = req_get_cstream_var(wp, ("option82"), "");
		if (!strcmp(strOption82, "ON")) {
			apmib_nvram_set("OPTION82","checked");
		} else {
			apmib_nvram_set("OPTION82","unchecked");
		}
	}

	strDhcp = req_get_cstream_var(wp, ("dhcp"), "");
	if (!strDhcp[0])
		call_from_wizard = 1;

	// Set STP
	strStp = req_get_cstream_var(wp, ("stp"), "");
	if (strStp[0]) {
		if (strStp[0] == '0')
			stp = 0;
		else
			stp = 1;
		if ( !apmib_set(MIB_STP_ENABLED, (void *)&stp)) {
			strcpy(tmpBuf, ("Set STP mib error!"));
			goto setErr_tcpip;
		}
	}

#if 0 // Move to formStaticDHCP
	// Set static DHCP
	strStp = req_get_cstream_var(wp, ("static_dhcp"), "");
	if (strStp[0]) {
		if (strStp[0] == '0')
			stp = 0;
		else
			stp = 1;
		if ( !apmib_set(MIB_DHCPRSVDIP_ENABLED, (void *)&stp)) {
			strcpy(tmpBuf, ("Set static DHCP mib error!"));
			goto setErr_tcpip;
		}
	}
#endif

	// Set clone MAC address
	strMac = req_get_cstream_var(wp, ("lan_macAddr"), "");
	if (strMac[0]) {
		int orig_wlan_idx=0;
		int orig_vwlan_idx=0;
		int i;
		int j;
		if (strlen(strMac)!=12 || !string_to_hex(strMac, (unsigned char*)tmpBuf, 12)) {
			strcpy(tmpBuf, ("Error! Invalid MAC address."));
			goto setErr_tcpip;
		}
		if ( !apmib_set(MIB_ELAN_MAC_ADDR, (void *)tmpBuf)) {
			strcpy(tmpBuf, ("Set MIB_ELAN_MAC_ADDR mib error!"));
			goto setErr_tcpip;
		}

		orig_wlan_idx=wlan_idx;
		orig_vwlan_idx=vwlan_idx;
		if( !memcmp(strMac,"000000000000",12))
		{
			for(i=0;i<NUM_WLAN_INTERFACE;i++)
			{
				wlan_idx=i;
				for(j=0;j<NUM_VWLAN_INTERFACE;j++)
				{
					vwlan_idx=j;
					if ( !apmib_set(MIB_WLAN_WLAN_MAC_ADDR, (void *)tmpBuf)) {
						strcpy(tmpBuf, ("Set MIB_WLAN_WLAN_MAC_ADDR mib error!"));
						goto setErr_tcpip;
					}
				}
			}
		}
		else
		{
			for(i=0;i<NUM_WLAN_INTERFACE;i++)
			{
				wlan_idx=i;
				for(j=0;j<NUM_VWLAN_INTERFACE;j++)
				{
					vwlan_idx=j;
					if ( !apmib_set(MIB_WLAN_WLAN_MAC_ADDR, (void *)tmpBuf)) {
						strcpy(tmpBuf, ("Set MIB_WLAN_WLAN_MAC_ADDR mib error!"));
						goto setErr_tcpip;
					}
				tmpBuf[5]++;
			}
			tmpBuf[5]-=NUM_VWLAN_INTERFACE;
			tmpBuf[5]+=0x10;
			}
		}

		wlan_idx=orig_wlan_idx;
		vwlan_idx=orig_vwlan_idx;
	}

	// Read current DHCP setting for reference later
	if ( !apmib_get( MIB_DHCP, (void *)&curDhcp) ) {
		strcpy(tmpBuf, ("Get DHCP MIB error!"));
		goto setErr_tcpip;
	}

	strDhcp = req_get_cstream_var(wp, ("dhcp"), "");
	if ( strDhcp[0] ) {
		lan_dhcp_mode = atoi(strDhcp);

		if(lan_dhcp_mode != 0 && lan_dhcp_mode != 1 && lan_dhcp_mode != 2 && lan_dhcp_mode != 15  && lan_dhcp_mode != 19){
			strcpy(tmpBuf, ("Invalid DHCP value!"));
			goto setErr_tcpip;
		}

		if ( !apmib_set(MIB_DHCP, (void *)&lan_dhcp_mode)) {
	  		strcpy(tmpBuf, ("Set DHCP error!"));
			goto setErr_tcpip;
		}
		dhcp = lan_dhcp_mode;
	}
	else
		dhcp = curDhcp;

	if ( dhcp == DHCP_DISABLED || dhcp == DHCP_SERVER || dhcp == DHCP_AUTO || DHCP_AUTO_WAN) {
		strIp = req_get_cstream_var(wp, ("lan_ip"), "");
		if ( strIp[0] ) {
			char *def_ip;
			def_ip = nvram_get("IP_ADDR");
			if ( !inet_aton(strIp, &inIp) ) {
				strcpy(tmpBuf, ("Invalid IP-address value!"));
				goto setErr_tcpip;
			}
			if ( !apmib_set( MIB_IP_ADDR, (void *)&inIp)) {
				strcpy(tmpBuf, ("Set IP-address error!"));
				goto setErr_tcpip;
			}
			if (strcmp(strIp, def_ip)) // user change
				apmib_nvram_set("x_user_ip", strIp);
		}
		else { // get current used IP
			if ( !getInAddr(BRIDGE_IF, IP_ADDR, (void *)&inIp) ) {
				strcpy(tmpBuf, ("Get IP-address error!"));
				goto setErr_tcpip;
			}
		}

		strMask = req_get_cstream_var(wp, ("lan_mask"), "");
		if ( strMask[0] ) {
			if ( !inet_aton(strMask, &inMask) ) {
				strcpy(tmpBuf, ("Invalid subnet-mask value!"));
				goto setErr_tcpip;
			}
			if ( !apmib_set(MIB_SUBNET_MASK, (void *)&inMask)) {
				strcpy(tmpBuf, ("Set subnet-mask error!"));
				goto setErr_tcpip;
			}
		}
		else { // get current used netmask
			if ( !getInAddr(BRIDGE_IF, SUBNET_MASK, (void *)&inMask )) {
				strcpy(tmpBuf, ("Get subnet-mask error!"));
				goto setErr_tcpip;
			}
		}
		strGateway = req_get_cstream_var(wp, ("lan_gateway"), "");
		if ( (dhcp == DHCP_DISABLED && strGateway[0]) ||
			(dhcp == DHCP_SERVER && strGateway[0])	) {
			if ( !inet_aton(strGateway, &inGateway) ) {
				strcpy(tmpBuf, ("Invalid default-gateway value!"));
				goto setErr_tcpip;
			}
			if ( !apmib_set(MIB_DEFAULT_GATEWAY, (void *)&inGateway)) {
				strcpy(tmpBuf, ("Set default-gateway error!"));
				goto setErr_tcpip;
			}
		}

		if ( dhcp == DHCP_SERVER|| dhcp == DHCP_AUTO || DHCP_AUTO_WAN) {
			// Get/Set DHCP client range
			strdhcpRangeStart = req_get_cstream_var(wp, ("dhcpRangeStart"), "");
			if ( strdhcpRangeStart[0] ) {
				char *def_start;
				def_start = nvram_get("DHCP_CLIENT_START");
				if ( !inet_aton(strdhcpRangeStart, &dhcpRangeStart) ) {
					strcpy(tmpBuf, ("Invalid DHCP client start address!"));
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_DHCP_CLIENT_START, (void *)&dhcpRangeStart)) {
					strcpy(tmpBuf, ("Set DHCP client start address error!"));
					goto setErr_tcpip;
				}
				if (strcmp(strdhcpRangeStart, def_start)) // user change
					apmib_nvram_set("x_user_dhcp_start", strdhcpRangeStart);
			}
			strdhcpRangeEnd = req_get_cstream_var(wp, ("dhcpRangeEnd"), "");
			if ( strdhcpRangeEnd[0] ) {
				char *def_end;
				def_end = nvram_get("DHCP_CLIENT_END");
				if ( !inet_aton(strdhcpRangeEnd, &dhcpRangeEnd) ) {
					strcpy(tmpBuf, ("Invalid DHCP client end address!"));
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_DHCP_CLIENT_END, (void *)&dhcpRangeEnd)) {
					strcpy(tmpBuf, ("Set DHCP client end address error!"));
					goto setErr_tcpip;
				}
				if (strcmp(strdhcpRangeEnd, def_end)) // user change
					apmib_nvram_set("x_user_dhcp_end", strdhcpRangeEnd);
			}

			if ( strdhcpRangeStart[0] && strdhcpRangeEnd[0] ) {
				unsigned long start, end, mask, ip;
				int diff;

				start = dhcpRangeStart.s_addr;
				end = dhcpRangeEnd.s_addr;
				diff = (int) ( ntohdw(end) - ntohdw(start) );
				ip = inIp.s_addr;
				mask = inMask.s_addr;
				if (diff <= 0 ||
					diff > 256*3 ||
					(ip&mask) != (start&mask) ||
					(ip&mask) != (end& mask) ) {
					strcpy(tmpBuf, ("Invalid DHCP client range!"));
					goto setErr_tcpip;
				}
			}

			// If DHCP server is enabled in LAN, update dhcpd.conf
			strDNS = req_get_cstream_var(wp, ("dns1"), "");
			if ( strDNS[0] ) {
				if ( !inet_aton(strDNS, &dns1) ) {
					strcpy(tmpBuf, ("Invalid DNS address value!"));
					goto setErr_tcpip;
				}

				if ( !apmib_set(MIB_DNS1, (void *)&dns1)) {
	  				strcpy(tmpBuf, "Set DNS MIB error!");
					goto setErr_tcpip;
				}
			}

			strDNS = req_get_cstream_var(wp, ("dns2"), "");
			if ( strDNS[0] ) {
				if ( !inet_aton(strDNS, &dns2) ) {
					strcpy(tmpBuf, ("Invalid DNS address value!"));
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_DNS2, (void *)&dns2)) {
	  				strcpy(tmpBuf, "Set DNS MIB error!");
					goto setErr_tcpip;
				}
			}

			strDNS = req_get_cstream_var(wp, ("dns3"), "");
			if ( strDNS[0] ) {
				if ( !inet_aton(strDNS, &dns3) ) {
					strcpy(tmpBuf, ("Invalid DNS address value!"));
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_DNS3, (void *)&dns3)) {
	  				strcpy(tmpBuf, "Set DNS MIB error!");
					goto setErr_tcpip;
				}
			}

			if (!call_from_wizard) {
				strDhcpLeaseTime = req_get_cstream_var(wp, ("dhcpLeaseTime"), "");
				if ( strDhcpLeaseTime ) {
					dhcp_lease_time = atoi(strDhcpLeaseTime);
					if (dhcp_lease_time >= 60 && dhcp_lease_time <= 7200) {
						if ( !apmib_set(MIB_DHCP_LEASE_TIME, (void *)&dhcp_lease_time)) {
							strcpy(tmpBuf, ("Set MIB_DHCP_LEASE_TIME MIB error!"));
							goto setErr_tcpip;
						}
					}
				}
				strDomain = req_get_cstream_var(wp, ("domainName"), "");
				if ( strDomain ) {
					if (!isValidName(strDomain)) {
  						strcpy(tmpBuf, ("Invalid Domain Name! Please enter characters in A(a)~Z(z) or 0-9 without spacing."));
						goto setErr_tcpip;
					}
					if ( !apmib_set(MIB_DOMAIN_NAME, (void *)strDomain)) {
	  					strcpy(tmpBuf, ("Set MIB_DOMAIN_NAME MIB error!"));
						goto setErr_tcpip;
					}
				}else{
					 if ( !apmib_set(MIB_DOMAIN_NAME, (void *)"")){
	  					strcpy(tmpBuf, ("\"Set MIB_DOMAIN_NAME MIB error!\""));
						goto setErr_tcpip;
					}
				}
			}
		}
	}
	return 0 ;
setErr_tcpip:
	return -1 ;
}

///////////////////////////////////////////////////////////////////
#if defined(MIB_TLV)
extern int mib_search_by_id(const mib_table_entry_T *mib_tbl, unsigned short mib_id, unsigned char *pmib_num, const mib_table_entry_T **ppmib, unsigned int *offset);
extern mib_table_entry_T mib_root_table[];
#else
extern int update_linkchain(int fmt, void *Entry_old, void *Entry_new, int type_size);
#endif
int checkStaticIpIsValid(char *tmpBuf)
{
	int i, entryNum=0, enabled=0;
	DHCPRSVDIP_T entry;
	struct in_addr start_ip, end_ip, router_ip;
	unsigned int *ip;

	apmib_get(MIB_DHCPRSVDIP_ENABLED, (void *)&enabled);
	if(enabled==0)
		return 0;

	apmib_get(MIB_DHCPRSVDIP_TBL_NUM, (void *)&entryNum);
	apmib_get(MIB_DHCP_CLIENT_START,  (void *)&start_ip);
	apmib_get(MIB_DHCP_CLIENT_END,  (void *)&end_ip);
	apmib_get(MIB_IP_ADDR,  (void *)&router_ip);

	for (i=1; i<=entryNum; i++)
	{
		*((char *)&entry) = (char)i;
		if(!apmib_get(MIB_DHCPRSVDIP_TBL, (void *)&entry))
		{
			printf("get mib MIB_DHCPRSVDIP_TBL fail!\n");
			return 0;
		}
		ip = (unsigned int *)entry.ipAddr;
		if(*ip<start_ip.s_addr || *ip>end_ip.s_addr || *ip==router_ip.s_addr)
		{
			strcpy(tmpBuf, ("Please check your \"Static DHCP\" setting. The static IP address must be in the range of dhcpd ip pool, and is not same with router's ip!"));
			return 1;
		}
	}
	return 0;
}
void formTcpipSetup(request *wp, char *path, char *query)
{

	char tmpBuf[100];
	char buffer[200];
	char *submitUrl ;
#ifdef MIB_TLV
/* unuse value 150610*/
	/*char pmib_num[10]={0};
	mib_table_entry_T *pmib_tl = NULL;
	unsigned int offset;*/
#endif
	struct in_addr inLanaddr_orig, inLanaddr_new;
	struct in_addr inLanmask_orig, inLanmask_new;
/* unuse value 150610 */
	/*struct in_addr private_host, tmp_private_host, update;
	int	entryNum_resvdip, i;
	DHCPRSVDIP_T entry_resvdip, checkentry_resvdip;
	int link_type;*/
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
	int opmode=0, wlan0_mode=0, check_flag=0;
	int lan_dhcp_mode_orig=0;
	int lan_dhcp_mode=0;
	char lan_domain_name[	MAX_NAME_LEN]={0};
	char lan_domain_name_orig[	MAX_NAME_LEN]={0};
#endif
	apmib_get( MIB_IP_ADDR,  (void *)buffer); //save the orig lan subnet
	memcpy((void *)&inLanaddr_orig, buffer, 4);

	apmib_get( MIB_SUBNET_MASK,  (void *)buffer); //save the orig lan mask
	memcpy((void *)&inLanmask_orig, buffer, 4);

#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
	apmib_get( MIB_DHCP, (void *)&lan_dhcp_mode_orig);
	apmib_get( MIB_DOMAIN_NAME, (void *)lan_domain_name_orig);
#endif

	apmib_set_hist_clear();		/* APACRTL-85 */

	if(tcpipLanHandler(wp, tmpBuf) < 0){
		//back to the orig lan subnet and mask
		apmib_set(MIB_IP_ADDR, (void *)&inLanaddr_orig);
		apmib_set(MIB_SUBNET_MASK, (void *)&inLanmask_orig);
		goto setErr_end ;
	}

#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
	apmib_get(MIB_OP_MODE,(void *)&opmode);
	apmib_get( MIB_WLAN_MODE, (void *)&wlan0_mode);
	if(opmode ==1 && (wlan0_mode == 1 || wlan0_mode == 0)){ //when wlan is client mode or ap mode, user change lan setting
		check_flag=1;
	}
	apmib_set(MIB_AUTO_DISCOVERY_ENABLED,(void *)&check_flag); //lan ipaddress has been changed from web page
#endif

	web_config_trace(1, 3);	/* wired/local-lan */

	apmib_update_web(CURRENT_SETTING);	// update configuration to flash

	apmib_get( MIB_IP_ADDR,  (void *)buffer); //check the new lan subnet
	memcpy((void *)&inLanaddr_new, buffer, 4);

	apmib_get( MIB_SUBNET_MASK,  (void *)buffer); //check the new lan mask
	memcpy((void *)&inLanmask_new, buffer, 4);

/*	if(checkStaticIpIsValid(tmpBuf)>0)
		goto setErr_end ;*/
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
	apmib_get( MIB_DHCP, (void *)&lan_dhcp_mode);
	apmib_get( MIB_DOMAIN_NAME, (void *)lan_domain_name);
#endif
/* 2015-04-02 00:38 young */
#ifndef CONFIG_NVRAM_APMIB
	if((inLanaddr_orig.s_addr & inLanmask_orig.s_addr) != (inLanaddr_new.s_addr & inLanmask_new.s_addr)){
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
				mib_search_by_id(mib_root_table, MIB_DHCPRSVDIP_TBL, pmib_num, &pmib_tl, &offset);
				update_tblentry(pMib,offset,entryNum_resvdip,pmib_tl,&entry_resvdip, &checkentry_resvdip);
#else
				update_linkchain(link_type, &entry_resvdip, &checkentry_resvdip , sizeof(checkentry_resvdip));
#endif

			}
		}
		apmib_update_web(CURRENT_SETTING);	// update configuration to flash
	}
#endif

	submitUrl = req_get_cstream_var(wp, "submit-url", "");
	need_reboot = 1;
	OK_MSG("/skb_tcpiplan.htm");
	return;

#ifndef NO_ACTION
#if defined(VOIP_SUPPORT) && defined(ATA867x)
	run_init_script("all");
#else
	run_init_script("bridge");
#endif
#endif

#ifdef REBOOT_CHECK
#if !defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
	if(memcmp(&inLanaddr_orig,&inLanaddr_new,4) == 0)
#else
	if((memcmp(&inLanaddr_orig,&inLanaddr_new,4) == 0) && (lan_dhcp_mode_orig==lan_dhcp_mode) && (lan_domain_name[0] && !strcmp(lan_domain_name, lan_domain_name_orig)))
#endif
	{
		OK_MSG(submitUrl);
	}
	else
	{
		char tmpBuf[200];
		char lan_ip_buf[30], lan_ip[30];

		//apmib_reinit();

		//apmib_update_web(CURRENT_SETTING);	// update configuration to flash
		run_init_script_flag = 1;
#ifndef NO_ACTION
		run_init_script("all");
#endif
		apmib_get( MIB_IP_ADDR,  (void *)lan_ip_buf) ;
		inet_ntop(AF_INET, lan_ip_buf, lan_ip, sizeof(lan_ip));

	  	sprintf(tmpBuf,"%s","<h4>Change setting successfully!<BR><BR>Do not turn off or reboot the Device during this time.</h4>");
		OK_MSG_FW(tmpBuf, submitUrl, APPLY_COUNTDOWN_TIME+5, lan_ip);
	}
#else
	RECONNECT_MSG(submitUrl);	// display reconnect msg to remote
#endif


	return;

setErr_end:
	ERR_MSG(tmpBuf);
}

#ifdef RTK_USB3G
void kill_3G_ppp_inet(void)
{
    system("killall -15 ppp_inet 2> /dev/null");
    system("killall -15 pppd 2> /dev/null");
    system("rm /etc/ppp/connectfile >/dev/null 2>&1");
    system("rm /etc/ppp/link >/dev/null 2>&1");
}
#endif

#ifdef HOME_GATEWAY
#ifdef CONFIG_DSLITE_SUPPORT
#define NS_INT16SZ   2
#define NS_INADDRSZ  4
#define NS_IN6ADDRSZ    16

//add string to IPv4 address exchange
int
inet_pton4(src, dst)
	const char *src;
	unsigned char *dst;
{
	static const char digits[] = "0123456789";
	int saw_digit, octets, ch;
	unsigned char tmp[NS_INADDRSZ], *tp;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr(digits, ch)) != NULL) {
		unsigned int new = *tp * 10 + (pch - digits);

		if (new > 255)
			return (0);
		*tp = new;
		if (! saw_digit) {
			if (++octets > 4)
				return (0);
			saw_digit = 1;
			}
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return (0);
			*++tp = 0;
			saw_digit = 0;
		} else
			return (0);
	}
	if (octets < 4)
		return (0);
	memcpy(dst, tmp, NS_INADDRSZ);
	return (1);
}

//add string to IPv6 address exchange
int
inet_pton6(src, dst)
	const char *src;
	unsigned char *dst;
{
	static const char xdigits_l[] = "0123456789abcdef",
		xdigits_u[] = "0123456789ABCDEF";
	unsigned char tmp[NS_IN6ADDRSZ], *tp, *endp, *colonp;
	const char *xdigits, *curtok;
	int ch, saw_xdigit;
	unsigned int val;

	memset((tp = tmp), '\0', NS_IN6ADDRSZ);
	endp = tp + NS_IN6ADDRSZ;
	colonp = NULL;
	/** Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return (0);
	curtok = src;
	saw_xdigit = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return (0);
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':') {
			curtok = src;
		if (!saw_xdigit) {
			if (colonp)
				return (0);
			colonp = tp;
				continue;
		}
		if (tp + NS_INT16SZ > endp)
			return (0);
		*tp++ = (unsigned char) (val >> 8) & 0xff;
		*tp++ = (unsigned char) val & 0xff;
		saw_xdigit = 0;
		val = 0;
		continue;
		}
		if (ch == '.' && ((tp + NS_INADDRSZ) <= endp) &&
			inet_pton4(curtok, tp) > 0) {
			tp += NS_INADDRSZ;
			saw_xdigit = 0;
			break;  /** '\0' was seen by inet_pton4(). */
		}
		return (0);
	}
	if (saw_xdigit) {
		if (tp + NS_INT16SZ > endp)
			return (0);
		*tp++ = (unsigned char) (val >> 8) & 0xff;
		*tp++ = (unsigned char) val & 0xff;
	}
	if (colonp != NULL) {
	/**
	  * Since some memmove()'s erroneously fail to handle
	  * overlapping regions, we'll do the shift by hand.
	  */
		const int n = tp - colonp;
		int i;

		for (i = 1; i <= n; i++) {
			endp[- i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return (0);
	memcpy(dst, tmp, NS_IN6ADDRSZ);
	return (1);
}
#endif //end CONFIG_DSLITE_SUPPORT

#ifdef __DAVO__
#define MAC_BCAST_ADDR		(unsigned char *) "\xff\xff\xff\xff\xff\xff"
#define BST_IP				"255.255.255.255"
#define NOROUT_IP			"0.0.0.0"

struct arpMsg {
	struct ethhdr ethhdr;	    /* Ethernet header */
	u_short htype;				/* hardware type (must be ARPHRD_ETHER) */
	u_short ptype;				/* protocol type (must be ETH_P_IP) */
	u_char  hlen;				/* hardware address length (must be 6) */
	u_char  plen;				/* protocol address length (must be 4) */
	u_short operation;			/* ARP opcode */
	u_char  sHaddr[6];			/* sender's hardware address */
	u_char  sInaddr[4];			/* sender's IP address */
	u_char  tHaddr[6];			/* target's hardware address */
	u_char  tInaddr[4];			/* target's IP address */
	u_char  pad[18];			/* pad for min. Ethernet payload (60 bytes) */
};

static void get_mono(struct timespec *ts)
{
	if (syscall(__NR_clock_gettime, CLOCK_MONOTONIC, ts))
		perror("clock_gettime(MONOTONIC) failed");
}

unsigned monotonic_ms(void)
{
	struct timespec ts;
	get_mono(&ts);
	return (unsigned)(ts.tv_sec * 1000UL + ts.tv_nsec / 1000000);
}

static int webs_arpping(unsigned char *pSmac, unsigned int testIp, unsigned char *pSintf)
{
	int timeout = 2;
	int optval = 1;
	int n, s;                      /* socket */
	int rv = 0;                 /* return value */
	struct sockaddr addr;       /* for interface name */
	struct arpMsg arp;
	fd_set fdset;
	struct timeval tm;
	time_t diff, prev, now;

	if (!pSintf)
		return 0;

	if ((s = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ARP))) == -1)
		return 0;

	if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval))) {
		close(s);
		return 0;
	}

	/* send arp request */
	memset(&arp, 0, sizeof(arp));
	memcpy(arp.ethhdr.h_dest, MAC_BCAST_ADDR, 6);   /* MAC DA */
	memcpy(arp.ethhdr.h_source, pSmac, 6);          /* MAC SA */
	arp.ethhdr.h_proto = htons(ETH_P_ARP);          /* protocol type (Ethernet) */
	arp.htype = htons(ARPHRD_ETHER);                /* hardware type */
	arp.ptype = htons(ETH_P_IP);                    /* protocol type (ARP message) */
	arp.hlen = 6;                                   /* hardware address length */
	arp.plen = 4;                                   /* protocol address length */
	arp.operation = htons(ARPOP_REQUEST);           /* ARP op code */
	//memcpy(arp.sInaddr, &testIp, sizeof(testIp));   /* source IP address */
	memcpy(arp.sHaddr, pSmac, 6);                   /* source hardware address */
	memcpy(arp.tInaddr, &testIp, sizeof(testIp)); 	/* target IP address */
	memset(&addr, 0, sizeof(addr));
	strcpy(addr.sa_data, pSintf);
	if (sendto(s, &arp, sizeof(arp), 0, &addr, sizeof(addr)) < 0) {
		close(s);
		return 0;
	}

	/* wait arp reply, and check it */
	prev = monotonic_ms();
	tm.tv_sec =	1;
	tm.tv_usec = 0;
	while (1) {
		FD_ZERO(&fdset);
		FD_SET(s, &fdset);
		if ( (n=select(s + 1, &fdset, (fd_set *) NULL, (fd_set *) NULL, &tm)) > 0 ) {
			if (FD_ISSET(s, &fdset) && recv(s, &arp, sizeof(arp), 0) > 0) {
				if (arp.operation == htons(ARPOP_REPLY) && *((u_int *)arp.sInaddr) == testIp) {
					rv = 1;
					break;
				}
			}
		}
		memset(&tm, 0, sizeof(struct timeval));
		now = monotonic_ms();
		if ( (diff=(now-prev)) >= 1000)
			break;
		/* wait	arp	reply, and check it	*/
		if (diff == 0) tm.tv_sec = 1;
		else tm.tv_usec = diff%1000;
	}
	close(s);
	return rv;
}

static int is_dup_check(char *target)
{
	int n = 0;
	int bridge_mode = 0;
	char s_mac[6];
	char mode[8];
	char intf[80];
	struct in_addr tip;
	int retry = 2;

	yfcat("/var/sys_op", "%s", mode);
	bridge_mode = atoi(mode);
	if (bridge_mode)	{
		apmib_get(MIB_HW_NIC0_ADDR, (void *)s_mac);
		sprintf(intf, "%s", "br0");
	}
	else {
		apmib_get(MIB_HW_NIC1_ADDR, (void *)s_mac);
		sprintf(intf, "%s", "eth1");
	}

	if ( !strcmp(target, BST_IP) ||
		 !strcmp(target, NOROUT_IP) ||
		 !inet_aton(target, &tip) )
		return 2;

	while(retry--)
		if ( (n=webs_arpping(s_mac, tip.s_addr, intf)) )
			return 1;
	return 0;
}
#endif

int tcpipWanHandler(request *wp, char * tmpBuf, int *dns_changed)
{

	char	*strIp, *strMask, *strGateway, *strDNS, *strMode, *strConnect, *strMac;
	char  *strVal, *strType;
	int intVal;
	struct in_addr inIp, inMask,dns1, dns2, dns3, inGateway;
	DHCP_T dhcp, curDhcp;

	char tmpbuf[16];
#if defined(ROUTE_SUPPORT)
	int orig_nat=0;
	int curr_nat=0;
#endif
	DNS_TYPE_T dns, dns_old;

	char *submitUrl;
#ifndef NO_ACTION
	int pid;
#endif
#ifdef MULTI_PPPOE
	int flag = 0;
#endif
	int buttonState=0, call_from_wizard=0;

#if defined(CONFIG_DYNAMIC_WAN_IP)
	char *strPPPGateway, *strWanIpType;
	struct in_addr inPPPGateway;
	WAN_IP_TYPE_T wanIpType;
#if defined(CONFIG_GET_SERVER_IP_BY_DOMAIN)
	char *strGetServByDomain=NULL;
	char *strGatewayDomain;
#endif
#endif
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
	int intVal2,dot1x_mode,val,dot1x_enable;
#endif
#if defined(CONFIG_4G_LTE_SUPPORT)
	int lte = 0;
#endif
#ifdef __DAVO__
	int res;
#endif

	strVal = req_get_cstream_var(wp, ("lan_ip"), "");
	if (strVal[0])
		call_from_wizard = 1;

	strVal = req_get_cstream_var(wp, ("isPocketWizard"), "");
	if (strVal[0])
	{
		if ( atoi(strVal) == 1 )
		{
			call_from_wizard = 1;
		}
	}

	submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page

	strConnect = req_get_cstream_var(wp, ("pppConnect"), "");
	if (strConnect && strConnect[0]) {
		buttonState = 1;
#ifdef MULTI_PPPOE
		flag = 1;
#endif
		strMode = "ppp";
		goto set_ppp;
	}

        strConnect = req_get_cstream_var(wp, ("pppDisconnect"), "");
	if (strConnect && strConnect[0]) {
		buttonState = 2;
#ifdef MULTI_PPPOE
		flag = 1;
#endif
		strMode = "ppp";
		goto set_ppp;
	}
#ifdef  MULTI_PPPOE
	//second
	strConnect = req_get_cstream_var(wp, ("pppConnect2"), "");
	if (strConnect && strConnect[0]) {
		buttonState = 1;
#ifdef MULTI_PPPOE
		flag = 2;
#endif
		strMode = "ppp";
		goto set_ppp;
	}
		strConnect = req_get_cstream_var(wp, ("pppDisconnect2"), "");
	if (strConnect && strConnect[0]) {
		buttonState = 2;
#ifdef MULTI_PPPOE
		flag = 2;
#endif
		strMode = "ppp";
		goto set_ppp;
	}
	//thrid
		strConnect = req_get_cstream_var(wp, ("pppConnect3"), "");
	if (strConnect && strConnect[0]) {
		buttonState = 1;
#ifdef MULTI_PPPOE
		flag = 3;
#endif
		strMode = "ppp";
		goto set_ppp;
	}

		strConnect = req_get_cstream_var(wp, ("pppDisconnect3"), "");
	if (strConnect && strConnect[0]) {
		buttonState = 2;
#ifdef MULTI_PPPOE
		flag = 3;
#endif
		strMode = "ppp";
		goto set_ppp;
	}
	//forth
		strConnect = req_get_cstream_var(wp, ("pppConnect4"), "");
	if (strConnect && strConnect[0]) {
		buttonState = 1;
#ifdef MULTI_PPPOE
		flag = 4;
#endif
		strMode = "ppp";
		goto set_ppp;
	}

		strConnect = req_get_cstream_var(wp, ("pppDisconnect4"), "");
	if (strConnect && strConnect[0]) {
		buttonState = 2;
#ifdef MULTI_PPPOE
		flag = 4;
#endif
		strMode = "ppp";
		goto set_ppp;
	}
#endif

	strConnect = req_get_cstream_var(wp, ("pptpConnect"), "");
	if (strConnect && strConnect[0]) {
		buttonState = 1;
		strMode = "pptp";
		goto set_ppp;
	}

        strConnect = req_get_cstream_var(wp, ("pptpDisconnect"), "");
	if (strConnect && strConnect[0]) {
		buttonState = 2;
		strMode = "pptp";
		goto set_ppp;
	}
	strConnect = req_get_cstream_var(wp, ("l2tpConnect"), "");
	if (strConnect && strConnect[0]) {
		buttonState = 1;
		strMode = "l2tp";
		goto set_ppp;
	}

        strConnect = req_get_cstream_var(wp, ("l2tpDisconnect"), "");
	if (strConnect && strConnect[0]) {
		buttonState = 2;
		strMode = "l2tp";
		goto set_ppp;
	}

#ifdef RTK_USB3G
    strConnect = req_get_cstream_var(wp, ("USB3GConnect"), "");
    if (strConnect && strConnect[0]) {
        buttonState = 1;
        strMode = ("USB3G");
        goto set_ppp;
    }

    strConnect = req_get_cstream_var(wp, ("USB3GDisconnect"), "");
    if (strConnect && strConnect[0]) {
        buttonState = 2;
        strMode = ("USB3G");
        goto set_ppp;
    }
#endif /* #ifdef RTK_USB3G */

#if 0 //sc_yang
	strVal = req_get_cstream_var(wp, ("save"), "");
	if (!strVal || !strVal[0]) { // not save, wan type is changed
		strVal = req_get_cstream_var(wp, ("wanType"), "");
		wanDhcpTmp = (DHCP_T)(strVal[0] - '0');

		if (submitUrl && submitUrl[0])
			send_redirect_perm(wp, submitUrl);
		return;
	}
#endif
 	// Set clone MAC address
 	strVal = req_get_cstream_var(wp, ("macCloneEnable"), "");
 	if (strVal[0]) {
 		if (strcmp(strVal, ("ON")) == 0) {
 			apmib_nvram_set("x_mac_clone_enable", "1");
 			intVal = 1;
 		} else {
 			strcpy(tmpBuf, ("오류! MAC Clone 설정이 올바르지 않습니다."));
 			goto setErr_tcpip;
 		}
 	} else {
 		apmib_nvram_set("x_mac_clone_enable", "0");
 		intVal = 0;
 	}

 	{
 		strMac = req_get_cstream_var(wp, ("wan_macAddr"), "");
 		if (!strMac[0])
 			strMac = "000000000000";

 		if (strlen(strMac) != 12 || !string_to_hex(strMac, (unsigned char*)tmpBuf, 12)) {
 			strcpy(tmpBuf, ("오류! MAC 주소가 올바르지 않습니다."));
 			goto setErr_tcpip;
 		}

 		if ( !apmib_set(MIB_WAN_MAC_ADDR, (void *)tmpBuf)) {
 			strcpy(tmpBuf, ("WAN MAC 주소 mib 설정 오류!"));
 			goto setErr_tcpip;
 		}
 	}

	strMode = req_get_cstream_var(wp, ("dnsMode"), "");
	if ( strMode && strMode[0] ) {
		if (!strcmp(strMode, ("dnsAuto")))
			dns = DNS_AUTO;
		else if (!strcmp(strMode, ("dnsManual")))
			dns = DNS_MANUAL;
		else {
			strcpy(tmpBuf, ("DNS 모드가 올바르지 않습니다!"));
			goto setErr_tcpip;
		}

		if ( !apmib_get(MIB_DNS_MODE, (void *)&dns_old)) {
	  		strcpy(tmpBuf, ("DNS MIB 읽기 오류!"));
			goto setErr_tcpip;
		}
		if (dns != dns_old)
			*dns_changed = 1;

		// Set DNS to MIB
		if ( !apmib_set(MIB_DNS_MODE, (void *)&dns)) {
	  		strcpy(tmpBuf, "DNS MIB 설정 오류!");
			goto setErr_tcpip;
		}

		if ( dns == DNS_MANUAL ) {
			struct in_addr dns1_old, dns2_old, dns3_old;
			if ( !apmib_get(MIB_DNS1, (void *)&dns1_old)) {
	  			strcpy(tmpBuf, "DNS1 MIB 읽기 오류!");
				goto setErr_tcpip;
			}
			if ( !apmib_get(MIB_DNS2, (void *)&dns2_old)) {
	  			strcpy(tmpBuf, "DNS2 MIB 읽기 오류!");
				goto setErr_tcpip;
			}
			if ( !apmib_get(MIB_DNS3, (void *)&dns3_old)) {
	  			strcpy(tmpBuf, "DNS3 MIB 읽기 오류!");
				goto setErr_tcpip;
			}

			// If DHCP server is enabled in LAN, update dhcpd.conf
#if 0		//dns1 is can't be setup	//150614
			strDNS = req_get_cstream_var(wp, ("dns1"), "");
			if(strcmp(strDNS,"180.182.54.1") && strcmp(strDNS,"180.182.54.2") && strcmp(strDNS,"168.126.63.1") && strcmp(strDNS,"168.126.63.2") &&
				strcmp(strDNS,"164.124.107.9") && strcmp(strDNS,"203.248.252.2") && strcmp(strDNS,"164.124.101.2") && strcmp(strDNS,"203.248.240.31") &&
				strcmp(strDNS,"210.220.163.82") && strcmp(strDNS,"219.250.36.130") && strcmp(strDNS,"210.181.1.24") && strcmp(strDNS,"210.181.4.25") &&
				strcmp(strDNS,"202.30.143.11") && strcmp(strDNS,"203.240.193.11") && strcmp(strDNS,"211.238.160.21") && strcmp(strDNS,"208.67.222.222") &&
				strcmp(strDNS,"208.67.220.220") && strcmp(strDNS,"8.8.8.8") && strcmp(strDNS,"8.8.4.4")) {
					strcpy(tmpBuf, ("DNS1 주소가 올바르지 않습니다!"));
					goto setErr_tcpip;
			}
			if ( strDNS[0] ) {
				if ( !inet_aton(strDNS, &dns1) ) {
					strcpy(tmpBuf, ("DNS1 주소가 올바르지 않습니다!"));
					goto setErr_tcpip;
				}

				if ( !apmib_set(MIB_DNS1, (void *)&dns1)) {
	  				strcpy(tmpBuf, "DNS1 MIB 설정 오류!");
					goto setErr_tcpip;
				}
			}
			else {
				if ( !apmib_get(MIB_DNS1, (void *)&dns1) ) {
					strcpy(tmpBuf, "DNS1 MIB 읽기 오류!");
					goto setErr_tcpip;
				}
			}
#endif
			strDNS = req_get_cstream_var(wp, ("dns2"), "");
			if ( strDNS[0] ) {
				if ( !inet_aton(strDNS, &dns2) ) {
					strcpy(tmpBuf, ("DNS2 주소가 올바르지 않습니다!"));
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_DNS2, (void *)&dns2)) {
	  				strcpy(tmpBuf, "DNS2 MIB 설정 오류!");
					goto setErr_tcpip;
				}
			}
			else {
				if ( !apmib_get(MIB_DNS2, (void *)&dns2) ) {
					strcpy(tmpBuf, ("DNS2 MIB 읽기 오류!"));
					goto setErr_tcpip;
				}
			}
			strDNS = req_get_cstream_var(wp, ("dns3"), "");
			if ( strDNS[0] ) {
				if ( !inet_aton(strDNS, &dns3) ) {
					strcpy(tmpBuf, ("DNS3 주소가 올바르지 않습니다!"));
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_DNS3, (void *)&dns3)) {
	  				strcpy(tmpBuf, "DNS3 MIB 설정 오류!");
					goto setErr_tcpip;
				}
			}
			else {
				if ( !apmib_get(MIB_DNS3, (void *)&dns3) ) {
					strcpy(tmpBuf, "DNS3 MIB 읽기 오류!");
					goto setErr_tcpip;
				}
			}

			if ( dns1.s_addr != dns1_old.s_addr ||
				 dns2.s_addr != dns2_old.s_addr ||
				 dns3.s_addr != dns3_old.s_addr )
				*dns_changed = 1;
		}
	}

	// Read current ip mode setting for reference later
	if ( !apmib_get( MIB_WAN_DHCP, (void *)&curDhcp) ) {
		strcpy(tmpBuf, ("WAN DHCP MIB 읽기 오류!"));
		goto setErr_tcpip;
	}
#if defined(ROUTE_SUPPORT)
	if ( !apmib_get( MIB_NAT_ENABLED, (void *)&orig_nat) ) {
		strcpy(tmpBuf, ("Get NAT MIB error!"));
		goto setErr_tcpip;
	}

#endif
	//sc_yang
	//strMode = req_get_cstream_var(wp, ("ipMode"), "");
	strMode = req_get_cstream_var(wp, ("wanType"), "");

#if defined(CONFIG_RTL_ULINKER)
	if ( strMode && strMode[0] )
		;
	else
	{
		strMode = req_get_cstream_var(wp, ("otg_wan_type"), "");
	}
#endif

set_ppp:
	if ( strMode && strMode[0] ) {
		if ( !strcmp(strMode, ("autoIp")))
			dhcp = DHCP_CLIENT;
		else if ( !strcmp(strMode, ("fixedIp")))
			dhcp = DHCP_DISABLED;
		else if ( !strcmp(strMode, "ppp")) {
			char	*strName, *strPassword, *strService;
			char 	*strConnectNumber;
			char  *strsubnetNumber;
			char	*strIp;
			char  *strSubNet;
			struct in_addr  inIp;
			int count;
			dhcp = PPPOE;
			strConnectNumber = req_get_cstream_var(wp, "pppoeNumber", "");
			count = strtol(strConnectNumber, (char**)NULL, 10);

			if(strConnectNumber[0]){
				if ( apmib_set(MIB_PPP_CONNECT_COUNT, (void *)&count) == 0) {
					strcpy(tmpBuf, "Set PPPoE Number MIB error!");
					goto setErr_tcpip;
				}
			}
			strSubNet = req_get_cstream_var(wp, "pppSubNet_1", "");
			if(strSubNet[0]){
				if ( apmib_set(MIB_PPP_SUBNET1, (void *)strSubNet) == 0) {
					strcpy(tmpBuf, "Set PPPoE Number MIB error!");
					goto setErr_tcpip;
				}
			}
			strSubNet = req_get_cstream_var(wp, "pppSubNet_2", "");
			if(strSubNet[0]){
				if ( apmib_set(MIB_PPP_SUBNET2, (void *)strSubNet) == 0) {
					strcpy(tmpBuf, "Set PPPoE Number MIB error!");
					goto setErr_tcpip;
				}
			}
			strSubNet = req_get_cstream_var(wp, "pppSubNet_3", "");
			if(strSubNet[0]){
				if ( apmib_set(MIB_PPP_SUBNET3, (void *)strSubNet) == 0) {
					strcpy(tmpBuf, "Set PPPoE Number MIB error!");
					goto setErr_tcpip;
				}
			}
			strSubNet = req_get_cstream_var(wp, "pppSubNet_4","");
			if(strSubNet[0]){
				if ( apmib_set(MIB_PPP_SUBNET4, (void *)strSubNet) == 0) {
					strcpy(tmpBuf, "Set PPPoE Number MIB error!");
					goto setErr_tcpip;
				}
			}
			strsubnetNumber = req_get_cstream_var(wp, "pppSubNet1","");
			count = strtol(strsubnetNumber, (char**)NULL, 10);
			if(strsubnetNumber[0]){
				if ( apmib_set(MIB_SUBNET1_COUNT, (void *)&count) == 0) {
					strcpy(tmpBuf, "Set PPPoE Number MIB error!");
					goto setErr_tcpip;
				}
			}

			strsubnetNumber = req_get_cstream_var(wp, "pppSubNet2", "");
			count = strtol(strsubnetNumber, (char**)NULL, 10);
			if(strsubnetNumber[0]){
				if ( apmib_set(MIB_SUBNET2_COUNT, (void *)&count) == 0) {
					strcpy(tmpBuf, "Set PPPoE Number MIB error!");
					goto setErr_tcpip;
				}
			}

			strsubnetNumber = req_get_cstream_var(wp, "pppSubNet3", "");
			count = strtol(strsubnetNumber, (char**)NULL, 10);
			if(strsubnetNumber[0]){
				if ( apmib_set(MIB_SUBNET3_COUNT, (void *)&count) == 0) {
					strcpy(tmpBuf, "Set PPPoE Number MIB error!");
					goto setErr_tcpip;
				}
			}

			strsubnetNumber = req_get_cstream_var(wp, "pppSubNet4", "");
			count = strtol(strsubnetNumber, (char**)NULL, 10);
			if(strsubnetNumber[0]){
				if ( apmib_set(MIB_SUBNET4_COUNT, (void *)&count) == 0) {
					strcpy(tmpBuf, "Set PPPoE Number MIB error!");
					goto setErr_tcpip;
				}
			}
			// four ip seting,the first one
			strIp = req_get_cstream_var(wp, "S1_F1_start", "");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf, "Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET1_F1_START, (void *)&inIp)) {
					strcpy(tmpBuf, "Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp, "S1_F1_end", "");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf, "Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET1_F1_END, (void *)&inIp)) {
					strcpy(tmpBuf, "Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp, "S1_F2_start", "");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf, "Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET1_F2_START, (void *)&inIp)) {
					strcpy(tmpBuf, "Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp, "S1_F2_end", "");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf, "Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET1_F2_END, (void *)&inIp)) {
					strcpy(tmpBuf, "Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp, "S1_F3_start","");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf,"Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET1_F3_START, (void *)&inIp)) {
					strcpy(tmpBuf,"Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp,"S1_F3_end", "");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf,"Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET1_F3_END, (void *)&inIp)) {
					strcpy(tmpBuf,"Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}

			//the second
			strIp = req_get_cstream_var(wp,"S2_F1_start","");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf,"Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET2_F1_START, (void *)&inIp)) {
					strcpy(tmpBuf,"Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp,"S2_F1_end","");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf,"Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET2_F1_END, (void *)&inIp)) {
					strcpy(tmpBuf,"Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp,"S2_F2_start","");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf,"Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET2_F2_START, (void *)&inIp)) {
					strcpy(tmpBuf,"Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp,"S2_F2_end","");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf,"Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET2_F2_END, (void *)&inIp)) {
					strcpy(tmpBuf,"Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp,"S2_F3_start","");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf,"Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET2_F3_START, (void *)&inIp)) {
					strcpy(tmpBuf,"Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp,"S2_F3_end","");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf,"Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET2_F3_END, (void *)&inIp)) {
					strcpy(tmpBuf,"Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			//the third
			strIp = req_get_cstream_var(wp,"S3_F1_start","");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf,"Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET3_F1_START, (void *)&inIp)) {
					strcpy(tmpBuf,"Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp,"S3_F1_end","");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf,"Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET3_F1_END, (void *)&inIp)) {
					strcpy(tmpBuf,"Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp,"S3_F2_start","");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf,"Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET3_F2_START, (void *)&inIp)) {
					strcpy(tmpBuf, "Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp,"S3_F2_end","");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf,"Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET3_F2_END, (void *)&inIp)) {
					strcpy(tmpBuf,"Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp,"S3_F3_start","");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf,"Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET3_F3_START, (void *)&inIp)) {
					strcpy(tmpBuf,"Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp,"S3_F3_end","");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf, "Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET3_F3_END, (void *)&inIp)) {
					strcpy(tmpBuf, "Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			//the forth
			strIp = req_get_cstream_var(wp,"S4_F1_start", "");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf, "Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET4_F1_START, (void *)&inIp)) {
					strcpy(tmpBuf, "Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp, "S4_F1_end", "");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf,"Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET4_F1_END, (void *)&inIp)) {
					strcpy(tmpBuf,"Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp,"S4_F2_start", "");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf, "Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET4_F2_START, (void *)&inIp)) {
					strcpy(tmpBuf, "Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp, "S4_F2_end", "");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf,"Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET4_F2_END, (void *)&inIp)) {
					strcpy(tmpBuf,"Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp,"S4_F3_start", "");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf, "Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET4_F3_START, (void *)&inIp)) {
					strcpy(tmpBuf,"Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}
			strIp = req_get_cstream_var(wp,"S4_F3_end","");
			if ( strIp[0] ) {
				if ( !inet_aton(strIp, &inIp) ) {
					strcpy(tmpBuf,"Invalid subnet-mask value!");
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_SUBNET4_F3_END, (void *)&inIp)) {
					strcpy(tmpBuf,"Set subnet-mask error!");
					goto setErr_tcpip;
				}
			}

  			strName = req_get_cstream_var(wp, ("pppUserName"), "");
			if ( strName[0] ) {
				if ( apmib_set(MIB_PPP_USER_NAME, (void *)strName) == 0) {
					strcpy(tmpBuf, ("Set PPP user name MIB error!"));
					goto setErr_tcpip;
				}
			}

 			strPassword = req_get_cstream_var(wp, ("pppPassword"), "");
			if ( strPassword[0] ) {
				if ( apmib_set(MIB_PPP_PASSWORD, (void *)strPassword) == 0) {
					strcpy(tmpBuf, ("Set PPP user password MIB error!"));
					goto setErr_tcpip;
				}
			}
			strName = req_get_cstream_var(wp,"pppUserName2" ,"");
			if ( strName[0] ) {
				if ( apmib_set(MIB_PPP_USER_NAME2, (void *)strName) == 0) {
					strcpy(tmpBuf,"Set PPP user name MIB error!");
					goto setErr_tcpip;
				}
			}

			strPassword = req_get_cstream_var(wp,"pppPassword2" ,"");
			if ( strPassword[0] ) {
				if ( apmib_set(MIB_PPP_PASSWORD2, (void *)strPassword) == 0) {
					strcpy(tmpBuf,"Set PPP user password MIB error!");
					goto setErr_tcpip;
				}
			}
			strName = req_get_cstream_var(wp,"pppUserName3","");
			if ( strName[0] ) {
				if ( apmib_set(MIB_PPP_USER_NAME3, (void *)strName) == 0) {
					strcpy(tmpBuf, "Set PPP user name MIB error!");
					goto setErr_tcpip;
				}
			}

			strPassword = req_get_cstream_var(wp,"pppPassword3","");
			if ( strPassword[0] ) {
				if ( apmib_set(MIB_PPP_PASSWORD3, (void *)strPassword) == 0) {
					strcpy(tmpBuf, "Set PPP user password MIB error!");
					goto setErr_tcpip;
				}
			}
			strName = req_get_cstream_var(wp, "pppUserName4","");
			if ( strName[0] ) {
				if ( apmib_set(MIB_PPP_USER_NAME4, (void *)strName) == 0) {
					strcpy(tmpBuf, "Set PPP user name MIB error!");
					goto setErr_tcpip;
				}
			}

			strPassword = req_get_cstream_var(wp,"pppPassword4", "");
			if ( strPassword[0] ) {
				if ( apmib_set(MIB_PPP_PASSWORD4, (void *)strPassword) == 0) {
					strcpy(tmpBuf, "Set PPP user password MIB error!");
					goto setErr_tcpip;
				}
			}

			strService = req_get_cstream_var(wp, ("pppServiceName"), "");
			if ( strService[0] ) {
				if ( apmib_set(MIB_PPP_SERVICE_NAME, (void *)strService) == 0) {
					strcpy(tmpBuf, ("Set PPP serice name MIB error!"));
					goto setErr_tcpip;
				}
			}else{
				if ( apmib_set(MIB_PPP_SERVICE_NAME, (void *)"") == 0) {
					strcpy(tmpBuf, ("Set PPP serice name MIB error!"));
					goto setErr_tcpip;
				}
			}
			strService = req_get_cstream_var(wp, "pppServiceName2","");
			if ( strService[0] ) {
				if ( apmib_set(MIB_PPP_SERVICE_NAME2, (void *)strService) == 0) {
					strcpy(tmpBuf,"Set PPP serice name MIB error!");
					goto setErr_tcpip;
				}
			}else{
				if ( apmib_set(MIB_PPP_SERVICE_NAME2, (void *)"") == 0) {
					strcpy(tmpBuf,"Set PPP serice name MIB error!");
					goto setErr_tcpip;
				}
			}
			strService = req_get_cstream_var(wp,"pppServiceName3","");
			if ( strService[0] ) {
				if ( apmib_set(MIB_PPP_SERVICE_NAME3, (void *)strService) == 0) {
					strcpy(tmpBuf, "Set PPP serice name MIB error!");
					goto setErr_tcpip;
				}
			}else{
				if ( apmib_set(MIB_PPP_SERVICE_NAME3, (void *)"") == 0) {
					strcpy(tmpBuf, "Set PPP serice name MIB error!");
					goto setErr_tcpip;
				}
			}
			strService = req_get_cstream_var(wp,"pppServiceName4" ,"");
			if ( strService[0] ) {
				if ( apmib_set(MIB_PPP_SERVICE_NAME4, (void *)strService) == 0) {
					strcpy(tmpBuf, "Set PPP serice name MIB error!");
					goto setErr_tcpip;
				}
			}else{
				if ( apmib_set(MIB_PPP_SERVICE_NAME4, (void *)"") == 0) {
					strcpy(tmpBuf, "Set PPP serice name MIB error!");
					goto setErr_tcpip;
				}
			}

			strType = req_get_cstream_var(wp, ("pppConnectType"), "");
			if ( strType[0] ) {
				PPP_CONNECT_TYPE_T type;
				if ( strType[0] == '0' )
					type = CONTINUOUS;
				else if ( strType[0] == '1' )
					type = CONNECT_ON_DEMAND;
				else if ( strType[0] == '2' )
					type = MANUAL;
				else {
					strcpy(tmpBuf, ("Invalid PPP type value!"));
					goto setErr_tcpip;
				}
				if ( apmib_set(MIB_PPP_CONNECT_TYPE, (void *)&type) == 0) {
   					strcpy(tmpBuf, ("Set PPP type MIB error!"));
					goto setErr_tcpip;
				}
				if (type != CONTINUOUS) {
					char *strTime;
					strTime = req_get_cstream_var(wp, ("pppIdleTime"), "");
					if ( strTime[0] ) {
						int time;
 						time = strtol(strTime, (char**)NULL, 10) * 60;
						if ( apmib_set(MIB_PPP_IDLE_TIME, (void *)&time) == 0) {
   							strcpy(tmpBuf, ("Set PPP idle time MIB error!"));
							goto setErr_tcpip;
						}
					}
				}
			}
			strType = req_get_cstream_var(wp, "pppConnectType2","");
			if ( strType[0] ) {
				PPP_CONNECT_TYPE_T type;
				if ( strType[0] == '0' )
					type = CONTINUOUS;
				else if ( strType[0] == '1' )
					type = CONNECT_ON_DEMAND;
				else if ( strType[0] == '2' )
					type = MANUAL;
				else {
					strcpy(tmpBuf, "Invalid PPP type value!");
					goto setErr_tcpip;
				}
				if ( apmib_set(MIB_PPP_CONNECT_TYPE2, (void *)&type) == 0) {
   					strcpy(tmpBuf, "Set PPP type MIB error!");
					goto setErr_tcpip;
				}
				if (type != CONTINUOUS) {
					char *strTime;
					strTime = req_get_cstream_var(wp, "pppIdleTime2","");
					if ( strTime[0] ) {
						int time;
 						time = strtol(strTime, (char**)NULL, 10) * 60;
						if ( apmib_set(MIB_PPP_IDLE_TIME2, (void *)&time) == 0) {
   							strcpy(tmpBuf, "Set PPP idle time MIB error!");
							goto setErr_tcpip;
						}
					}
				}
			}

			strType = req_get_cstream_var(wp, "pppConnectType3", "");
			if ( strType[0] ) {
				PPP_CONNECT_TYPE_T type;
				if ( strType[0] == '0' )
					type = CONTINUOUS;
				else if ( strType[0] == '1' )
					type = CONNECT_ON_DEMAND;
				else if ( strType[0] == '2' )
					type = MANUAL;
				else {
					strcpy(tmpBuf, "Invalid PPP type value!");
					goto setErr_tcpip;
				}
				if ( apmib_set(MIB_PPP_CONNECT_TYPE3, (void *)&type) == 0) {
   					strcpy(tmpBuf, "Set PPP type MIB error!");
					goto setErr_tcpip;
				}
				if (type != CONTINUOUS) {
					char *strTime;
					strTime = req_get_cstream_var(wp, "pppIdleTime3", "");
					if ( strTime[0] ) {
						int time;
 						time = strtol(strTime, (char**)NULL, 10) * 60;
						if ( apmib_set(MIB_PPP_IDLE_TIME3, (void *)&time) == 0) {
   							strcpy(tmpBuf, "Set PPP idle time MIB error!");
							goto setErr_tcpip;
						}
					}
				}
			}
			strType = req_get_cstream_var(wp, "pppConnectType4" ,"");
			if ( strType[0] ) {
				PPP_CONNECT_TYPE_T type;
				if ( strType[0] == '0' )
					type = CONTINUOUS;
				else if ( strType[0] == '1' )
					type = CONNECT_ON_DEMAND;
				else if ( strType[0] == '2' )
					type = MANUAL;
				else {
					strcpy(tmpBuf, "Invalid PPP type value!");
					goto setErr_tcpip;
				}
				if ( apmib_set(MIB_PPP_CONNECT_TYPE4, (void *)&type) == 0) {
   					strcpy(tmpBuf, "Set PPP type MIB error!");
					goto setErr_tcpip;
				}
				if (type != CONTINUOUS) {
					char *strTime;
					strTime = req_get_cstream_var(wp, "pppIdleTime4", "");
					if ( strTime[0] ) {
						int time;
 						time = strtol(strTime, (char**)NULL, 10) * 60;
						if ( apmib_set(MIB_PPP_IDLE_TIME4, (void *)&time) == 0) {
   							strcpy(tmpBuf, "Set PPP idle time MIB error!");
							goto setErr_tcpip;
						}
					}
				}
			}
#ifdef _ALPHA_DUAL_WAN_SUPPORT_
			strVal = req_get_cstream_var(wp, ("pppVlanId"), "");
			if ( strVal[0] ) {
				int vlanId;
 				vlanId = strtol(strVal, (char**)NULL, 10);
				if ( apmib_set(MIB_CWMP_PPPOE_WAN_VLANID, (void *)&vlanId) == 0) {
					strcpy(tmpBuf, ("Set PPP vlan id MIB error!"));
					goto setErr_tcpip;
				}
			}
#endif
			strVal = req_get_cstream_var(wp, ("pppMtuSize"), "");
			if ( strVal[0] ) {
				int mtuSize;
 				mtuSize = strtol(strVal, (char**)NULL, 10);
				if ( apmib_set(MIB_PPP_MTU_SIZE, (void *)&mtuSize) == 0) {
					strcpy(tmpBuf, ("Set PPP mtu size MIB error!"));
					goto setErr_tcpip;
				}
			}
			strVal = req_get_cstream_var(wp,"pppMtuSize2","");
			if ( strVal[0] ) {
				int mtuSize;
				mtuSize = strtol(strVal, (char**)NULL, 10);
				if ( apmib_set(MIB_PPP_MTU_SIZE2, (void *)&mtuSize) == 0) {
					strcpy(tmpBuf, "Set PPP mtu size MIB error!");
					goto setErr_tcpip;
				}
			}

			strVal = req_get_cstream_var(wp, "pppMtuSize3","");
			if ( strVal[0] ) {
				int mtuSize;
				mtuSize = strtol(strVal, (char**)NULL, 10);
				if ( apmib_set(MIB_PPP_MTU_SIZE3, (void *)&mtuSize) == 0) {
					strcpy(tmpBuf, "Set PPP mtu size MIB error!");
					goto setErr_tcpip;
				}
			}
			strVal = req_get_cstream_var(wp, "pppMtuSize4", "");
			if ( strVal[0] ) {
				int mtuSize;
				mtuSize = strtol(strVal, (char**)NULL, 10);
				if ( apmib_set(MIB_PPP_MTU_SIZE4, (void *)&mtuSize) == 0) {
					strcpy(tmpBuf, "Set PPP mtu size MIB error!");
					goto setErr_tcpip;
				}
			}
		}
		else if ( !strcmp(strMode, "pptp")) {
			char	*strName, *strPassword;
			dhcp = PPTP;
  			strName = req_get_cstream_var(wp, ("pptpUserName"), "");
			if ( strName[0] ) {
				if ( apmib_set(MIB_PPTP_USER_NAME, (void *)strName) == 0) {
					strcpy(tmpBuf, ("Set PPTP user name MIB error!"));
					goto setErr_tcpip;
				}
			}
 			strPassword = req_get_cstream_var(wp, ("pptpPassword"), "");
			if ( strPassword[0] ) {
				if ( apmib_set(MIB_PPTP_PASSWORD, (void *)strPassword) == 0) {
					strcpy(tmpBuf, ("Set PPTP user password MIB error!"));
					goto setErr_tcpip;
				}
			}
#if defined(CONFIG_DYNAMIC_WAN_IP)
			strWanIpType = req_get_cstream_var(wp, ("wan_pptp_use_dynamic_carrier_radio"), (""));
			if ( strWanIpType[0] ) {
				if (!strcmp(strWanIpType, ("dynamicIP")))
				{
					wanIpType= DYNAMIC_IP;

				}
				else if (!strcmp(strWanIpType, ("staticIP")))
				{
					wanIpType = STATIC_IP;
				}
				else {
					strcpy(tmpBuf, ("Invalid PPTP wan IP type!"));
					goto setErr_tcpip;
				}

				if ( !apmib_set(MIB_PPTP_WAN_IP_DYNAMIC, (void *)&wanIpType)) {
			  		strcpy(tmpBuf, ("Set MIB_PPTP_WAN_IP_DYNAMIC error!"));
					goto setErr_tcpip;
				}
			}

			strPPPGateway = req_get_cstream_var(wp, ("pptpDefGw"), (""));
			if ( strPPPGateway[0] ) {
				if ( !inet_aton(strPPPGateway, &inPPPGateway) ) {
					strcpy(tmpBuf, ("Invalid pptp default gateway value!"));
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_PPTP_DEFAULT_GW, (void *)&inPPPGateway)) {
					strcpy(tmpBuf, ("Set pptp default gateway error!"));
					goto setErr_tcpip;
				}
			}
#endif

#if defined(CONFIG_DYNAMIC_WAN_IP)
			if(wanIpType==STATIC_IP){
#endif
				strIp = req_get_cstream_var(wp, ("pptpIpAddr"), "");
				if ( strIp[0] ) {
					if ( !inet_aton(strIp, &inIp) ) {
						strcpy(tmpBuf, ("Invalid IP-address value!"));
						goto setErr_tcpip;
					}
					if ( !apmib_set(MIB_PPTP_IP_ADDR, (void *)&inIp)) {
						strcpy(tmpBuf, ("Set IP-address error!"));
						goto setErr_tcpip;
					}
				}

				strMask = req_get_cstream_var(wp, ("pptpSubnetMask"), "");
				if ( strMask[0] ) {
					if ( !inet_aton(strMask, &inMask) ) {
						strcpy(tmpBuf, ("Invalid subnet-mask value!"));
						goto setErr_tcpip;
					}
					if ( !apmib_set(MIB_PPTP_SUBNET_MASK, (void *)&inMask)) {
						strcpy(tmpBuf, ("Set subnet-mask error!"));
						goto setErr_tcpip;
					}
				}
#if defined(CONFIG_DYNAMIC_WAN_IP)
			}
#endif

			strGateway = req_get_cstream_var(wp, ("pptpServerIpAddr"), "");
			if ( strGateway[0] ) {
				if ( !inet_aton(strGateway, &inGateway) ) {
					strcpy(tmpBuf, ("Invalid pptp server ip value!"));
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_PPTP_SERVER_IP_ADDR, (void *)&inGateway)) {
					strcpy(tmpBuf, ("Set pptp server ip error!"));
					goto setErr_tcpip;
				}
			}

#if defined(CONFIG_GET_SERVER_IP_BY_DOMAIN)
			strGetServByDomain = req_get_cstream_var(wp,"pptpGetServMode","");
			if(strGetServByDomain[0])
			{
				if(!strcmp(strGetServByDomain,"pptpGetServByDomainName"))
				{
					intVal=1;
					if(!apmib_set(MIB_PPTP_GET_SERV_BY_DOMAIN,(void*)&intVal))
					{
						strcpy(tmpBuf, ("Set pptp get server by domain error!"));
							goto setErr_tcpip;
					}
					strGatewayDomain = req_get_cstream_var(wp, ("pptpServerDomainName"), "");
					if(strGatewayDomain[0])
					{
						if ( !apmib_set(MIB_PPTP_SERVER_DOMAIN, (void *)strGatewayDomain)) {
							strcpy(tmpBuf, ("Set pptp server domain error!"));
							goto setErr_tcpip;
						}
					}
				}else
				{
					intVal=0;
					if(!apmib_set(MIB_PPTP_GET_SERV_BY_DOMAIN,(void*)&intVal))
					{
						strcpy(tmpBuf, ("Set pptp get server by domain error!"));
							goto setErr_tcpip;
					}
				}
			}

#endif

		strType = req_get_cstream_var(wp, ("pptpConnectType"), "");
			if ( strType[0] ) {
				PPP_CONNECT_TYPE_T type;
				if ( strType[0] == '0' )
					type = CONTINUOUS;
				else if ( strType[0] == '1' )
					type = CONNECT_ON_DEMAND;
				else if ( strType[0] == '2' )
					type = MANUAL;
				else {
					strcpy(tmpBuf, ("Invalid PPTP type value!"));
					goto setErr_tcpip;
				}
				if ( apmib_set(MIB_PPTP_CONNECTION_TYPE, (void *)&type) == 0) {
   					strcpy(tmpBuf, ("Set PPTP type MIB error!"));
					goto setErr_tcpip;
				}
				if (type != CONTINUOUS) {
					char *strTime;
					strTime = req_get_cstream_var(wp, ("pptpIdleTime"), "");
					if ( strTime[0] ) {
						int time;
 						time = strtol(strTime, (char**)NULL, 10) * 60;
						if ( apmib_set(MIB_PPTP_IDLE_TIME, (void *)&time) == 0) {
   							strcpy(tmpBuf, ("Set PPTP idle time MIB error!"));
							goto setErr_tcpip;
						}
					}
				}
			}
			strVal = req_get_cstream_var(wp, ("pptpMtuSize"), "");
			if ( strVal[0] ) {
				int mtuSize;
 				mtuSize = strtol(strVal, (char**)NULL, 10);
				if ( apmib_set(MIB_PPTP_MTU_SIZE, (void *)&mtuSize) == 0) {
					strcpy(tmpBuf, ("Set PPTP mtu size MIB error!"));
					goto setErr_tcpip;
				}
			}
			if (!call_from_wizard) { // not called from wizard
				strVal = req_get_cstream_var(wp, ("pptpSecurity"), "");
				if ( !strcmp(strVal, "ON"))
					intVal = 1;
				else
					intVal = 0;
				apmib_set(MIB_PPTP_SECURITY_ENABLED, (void *)&intVal);

				strVal = req_get_cstream_var(wp, ("pptpCompress"), "");
				if ( !strcmp(strVal, "ON"))
					intVal = 1;
				else
					intVal = 0;
				apmib_set(MIB_PPTP_MPPC_ENABLED, (void *)&intVal);
			}
		}
		/* # keith: add l2tp support. 20080515 */
		else if ( !strcmp(strMode, "l2tp")) {
			char	*strName, *strPassword;
			dhcp = L2TP;
  			strName = req_get_cstream_var(wp, ("l2tpUserName"), "");
			if ( strName[0] ) {
				if ( apmib_set(MIB_L2TP_USER_NAME, (void *)strName) == 0) {
					strcpy(tmpBuf, ("Set L2TP user name MIB error!"));
					goto setErr_tcpip;
				}
			}
 			strPassword = req_get_cstream_var(wp, ("l2tpPassword"), "");
			if ( strPassword[0] ) {
				if ( apmib_set(MIB_L2TP_PASSWORD, (void *)strPassword) == 0) {
					strcpy(tmpBuf, ("Set L2TP user password MIB error!"));
					goto setErr_tcpip;
				}
			}
#if defined(CONFIG_DYNAMIC_WAN_IP)
			strWanIpType = req_get_cstream_var(wp, ("wan_l2tp_use_dynamic_carrier_radio"), (""));
			if ( strWanIpType[0] ) {
				if (!strcmp(strWanIpType, ("dynamicIP")))
					wanIpType= DYNAMIC_IP;
				else if (!strcmp(strWanIpType, ("staticIP")))
					wanIpType = STATIC_IP;
				else {
					strcpy(tmpBuf, ("Invalid L2TP wan IP type!"));
					goto setErr_tcpip;
				}

				if ( !apmib_set(MIB_L2TP_WAN_IP_DYNAMIC, (void *)&wanIpType)) {
			  		strcpy(tmpBuf, ("Set MIB_L2TP_WAN_IP_DYNAMIC error!"));
					goto setErr_tcpip;
				}
			}

			strPPPGateway = req_get_cstream_var(wp, ("l2tpDefGw"), (""));
			if ( strPPPGateway[0] ) {
				if ( !inet_aton(strPPPGateway, &inPPPGateway) ) {
					strcpy(tmpBuf, ("Invalid l2tp default gateway value!"));
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_L2TP_DEFAULT_GW, (void *)&inPPPGateway)) {
					strcpy(tmpBuf, ("Set l2tp default gateway error!"));
					goto setErr_tcpip;
				}
			}
#endif

#if defined(CONFIG_DYNAMIC_WAN_IP)
			if(wanIpType==STATIC_IP){
#endif
				strIp = req_get_cstream_var(wp, ("l2tpIpAddr"), "");
				if ( strIp[0] ) {
					if ( !inet_aton(strIp, &inIp) ) {
						strcpy(tmpBuf, ("Invalid IP-address value!"));
						goto setErr_tcpip;
					}
					if ( !apmib_set(MIB_L2TP_IP_ADDR, (void *)&inIp)) {
						strcpy(tmpBuf, ("Set IP-address error!"));
						goto setErr_tcpip;
					}
				}

				strMask = req_get_cstream_var(wp, ("l2tpSubnetMask"), "");
				if ( strMask[0] ) {
					if ( !inet_aton(strMask, &inMask) ) {
						strcpy(tmpBuf, ("Invalid subnet-mask value!"));
						goto setErr_tcpip;
					}
					if ( !apmib_set(MIB_L2TP_SUBNET_MASK, (void *)&inMask)) {
						strcpy(tmpBuf, ("Set subnet-mask error!"));
						goto setErr_tcpip;
					}
				}
#if defined(CONFIG_DYNAMIC_WAN_IP)
			}
#endif
			strGateway = req_get_cstream_var(wp, ("l2tpServerIpAddr"), "");
			if ( strGateway[0] ) {
				if ( !inet_aton(strGateway, &inGateway) ) {
					strcpy(tmpBuf, ("Invalid l2tp server ip value!"));
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_L2TP_SERVER_IP_ADDR, (void *)&inGateway)) {
					strcpy(tmpBuf, ("Set pptp server ip error!"));
					goto setErr_tcpip;
				}
			}

#if defined(CONFIG_GET_SERVER_IP_BY_DOMAIN)
			strGetServByDomain = req_get_cstream_var(wp,"l2tpGetServMode","");
			if(strGetServByDomain[0])
			{
				if(!strcmp(strGetServByDomain,"l2tpGetServByDomainName"))
				{
					intVal=1;
					if(!apmib_set(MIB_L2TP_GET_SERV_BY_DOMAIN,(void*)&intVal))
					{
						strcpy(tmpBuf, ("Set l2tp get server by domain error!"));
							goto setErr_tcpip;
					}
					strGatewayDomain = req_get_cstream_var(wp, ("l2tpServerDomainName"), "");
					if(strGatewayDomain[0])
					{
						if ( !apmib_set(MIB_L2TP_SERVER_DOMAIN, (void *)strGatewayDomain)) {
							strcpy(tmpBuf, ("Set l2tp server domain error!"));
							goto setErr_tcpip;
						}
					}
				}else
				{
					intVal=0;
					if(!apmib_set(MIB_L2TP_GET_SERV_BY_DOMAIN,(void*)&intVal))
					{
						strcpy(tmpBuf, ("Set l2tp get server by domain error!"));
							goto setErr_tcpip;
					}
				}
			}

#endif

		strType = req_get_cstream_var(wp, ("l2tpConnectType"), "");
			if ( strType[0] ) {
				PPP_CONNECT_TYPE_T type;
				if ( strType[0] == '0' )
					type = CONTINUOUS;
				else if ( strType[0] == '1' )
					type = CONNECT_ON_DEMAND;
				else if ( strType[0] == '2' )
					type = MANUAL;
				else {
					strcpy(tmpBuf, ("Invalid L2TP type value!"));
					goto setErr_tcpip;
				}
				if ( apmib_set(MIB_L2TP_CONNECTION_TYPE, (void *)&type) == 0) {
   					strcpy(tmpBuf, ("Set L2TP type MIB error!"));
					goto setErr_tcpip;
				}
				if (type != CONTINUOUS) {
					char *strTime;
					strTime = req_get_cstream_var(wp, ("l2tpIdleTime"), "");
					if ( strTime[0] ) {
						int time;
 						time = strtol(strTime, (char**)NULL, 10) * 60;
						if ( apmib_set(MIB_L2TP_IDLE_TIME, (void *)&time) == 0) {
   							strcpy(tmpBuf, ("Set L2TP idle time MIB error!"));
							goto setErr_tcpip;
						}
					}
				}
			}
			strVal = req_get_cstream_var(wp, ("l2tpMtuSize"), "");
			if ( strVal[0] ) {
				int mtuSize;
 				mtuSize = strtol(strVal, (char**)NULL, 10);
				if ( apmib_set(MIB_L2TP_MTU_SIZE, (void *)&mtuSize) == 0) {
					strcpy(tmpBuf, ("Set L2TP mtu size MIB error!"));
					goto setErr_tcpip;
				}
			}

		}

#ifdef RTK_USB3G
        else if ( !strcmp(strMode, ("USB3G"))) {
            char  *strName, *strPassword, *strPIN, *strAPN, *strDialnum;
            dhcp = USB3G;
            strName = req_get_cstream_var(wp, ("USB3G_USER"), "");
            //if ( strName[0] ) {
                if ( apmib_set(MIB_USB3G_USER, (void *)strName) == 0) {
                    strcpy(tmpBuf, ("Set USB3G user name MIB error!"));
                    goto setErr_tcpip;
                }
            //}
            strPassword = req_get_cstream_var(wp, ("USB3G_PASS"), "");
            //if ( strPassword[0] ) {
                if ( apmib_set(MIB_USB3G_PASS, (void *)strPassword) == 0) {
                    strcpy(tmpBuf, ("Set USB3G user password MIB error!"));
                    goto setErr_tcpip;
                }
            //}
            strPIN = req_get_cstream_var(wp, ("USB3G_PIN"), "");
            //if ( strPIN[0] ) {
                if ( apmib_set(MIB_USB3G_PIN, (void *)strPIN) == 0) {
                    strcpy(tmpBuf, ("Set USB3G PIN MIB error!"));
                    goto setErr_tcpip;
                }
            //}
            strAPN = req_get_cstream_var(wp, ("USB3G_APN"), "");
            if ( strAPN[0] ) {
                if ( apmib_set(MIB_USB3G_APN, (void *)strAPN) == 0) {
                    strcpy(tmpBuf, ("Set USB3G APN MIB error!"));
                    goto setErr_tcpip;
                }
            }
            strDialnum = req_get_cstream_var(wp, ("USB3G_DIALNUM"), "");
            if ( strDialnum[0] ) {
                if ( apmib_set(MIB_USB3G_DIALNUM, (void *)strDialnum) == 0) {
                    strcpy(tmpBuf, ("Set USB3G Dial number MIB error!"));
                    goto setErr_tcpip;
                }
            }

            strDialnum = req_get_cstream_var(wp, ("USB3GMtuSize"), "");
            if ( strDialnum[0] ) {
                if ( apmib_set(MIB_USB3G_MTU_SIZE, (void *)strDialnum) == 0) {
                    strcpy(tmpBuf, ("Set USB3G mtu size MIB error!"));
                    goto setErr_tcpip;
                }
            }

            strType = req_get_cstream_var(wp, ("USB3GConnectType"), "");
            if ( strType[0] ) {
                PPP_CONNECT_TYPE_T type;
                if (!strcmp(strType, "0"))
                    type = CONTINUOUS;
                else if (!strcmp(strType, "1"))
                    type = CONNECT_ON_DEMAND;
                else if (!strcmp(strType, "2"))
                    type = MANUAL;
                else {
                    strcpy(tmpBuf, ("Invalid USB3G type value!"));
                    goto setErr_tcpip;
                }
                if ( apmib_set(MIB_USB3G_CONN_TYPE, (void *)strType) == 0) {
                    strcpy(tmpBuf, ("Set USB3G type MIB error!"));
                    goto setErr_tcpip;
                }
                if (type != CONTINUOUS) {
                    char *strTime;
                    strTime = req_get_cstream_var(wp, ("USB3GIdleTime"), "");
                    if ( strTime[0] ) {
                        int time;
                        char buffer[8];
                        time = atoi(strTime) * 60;
                        sprintf(buffer, "%d", time);
                        if ( apmib_set(MIB_USB3G_IDLE_TIME, (void *)buffer) == 0) {
                            strcpy(tmpBuf, ("Set USB3G idle time MIB error!"));
                            goto setErr_tcpip;
                        }
                    }
                }
            }
        }
#endif /* #ifdef RTK_USB3G */
#if defined(CONFIG_4G_LTE_SUPPORT)
		else if ( !strcmp(strMode, ("LTE4G"))) {
			dhcp = DHCP_CLIENT;
			lte = 1;
		}
#endif
#ifdef CONFIG_IPV6
#ifdef CONFIG_DSLITE_SUPPORT
	else if ( !strcmp(strMode, ("dslite")))
	{
		int dslite;
		addr6CfgParam_t ipaddr6;
		char *strAFTR;
		dhcp = AFTR;
		strMode = req_get_cstream_var(wp, ("dsliteMode"), "");

		if ( strMode && strMode[0] )
		{
			if (!strcmp(strMode, ("dsliteAuto")))
				dslite = 0;
			else if (!strcmp(strMode, ("dsliteManual")))
				dslite = 1;
			else {
				strcpy(tmpBuf, ("Invalid ds-lite mode value!"));
				goto setErr_tcpip;
			}

			if ( !apmib_set(MIB_DSLITE_MODE, (void *)&dslite)) {
	  			strcpy(tmpBuf, "Set DSLITE MODE MIB error!");
				goto setErr_tcpip;
			}

			if(dslite == 1)
			{
				strAFTR = req_get_cstream_var(wp, ("dsliteAftrIpAddr6"), "");
				if(strAFTR[0])
				{
					if(inet_pton6(strAFTR, ipaddr6.addrIPv6) == 0)
					{
						strcpy(tmpBuf, ("Invalid AFTR address value!"));
						goto setErr_tcpip;
					}

					if ( !apmib_set(MIB_IPV6_ADDR_AFTR_PARAM, (void *)&ipaddr6))
					{
	  					strcpy(tmpBuf, "Set AFTR MIB error!");
						goto setErr_tcpip;
					}
				}
				else
				{
					if ( !apmib_get(MIB_IPV6_ADDR_AFTR_PARAM, (void *)&ipaddr6) )
					{
						strcpy(tmpBuf, "Get AFTR MIB error!");
						goto setErr_tcpip;
					}
				}
			}
		}
	}
#endif
#endif

		else {
			strcpy(tmpBuf, ("Invalid IP mode value!"));
			goto setErr_tcpip;
		}

#if defined(CONFIG_4G_LTE_SUPPORT)
		if ( !apmib_set(MIB_LTE4G, (void *)&lte)) {
			strcpy(tmpBuf, ("Set MIB_LTE4G error!"));
			goto setErr_tcpip;
		}
#endif

#if defined(ROUTE_SUPPORT)
	if ( (dhcp == PPPOE) || (dhcp == PPTP) || (dhcp == L2TP) || (dhcp == USB3G) ) {
		curr_nat=1;

		if(curr_nat !=orig_nat){//force NAT is enabled when pppoe/pptp/l2tp
			if ( !apmib_set( MIB_NAT_ENABLED, (void *)&curr_nat) ) {
				strcpy(tmpBuf, ("Get NAT MIB error!"));
				goto setErr_tcpip;
			}
			intVal=0;
			if (apmib_set( MIB_RIP_LAN_TX, (void *)&intVal) == 0) {
					strcpy(tmpBuf, ("\"Set RIP LAN Tx error!\""));
					goto setErr_tcpip;
			}
			if (apmib_set( MIB_RIP_WAN_TX, (void *)&intVal) == 0) {
					strcpy(tmpBuf, ("\"Set RIP WAN Tx error!\""));
					goto setErr_tcpip;
			}
			if (!apmib_set(MIB_IGMP_PROXY_DISABLED, (void *)&intVal)) {
				strcpy(tmpBuf, ("Set MIB_IGMP_PROXY_DISABLED error!"));
				goto setErr_tcpip;
			}
		}
	}
#endif

        if ( buttonState == 1 && (dhcp == PPPOE || dhcp == PPTP || dhcp == L2TP || dhcp == USB3G) ) { // connect button is pressed
			int wait_time=45;  // FOR WISP MODE
			int opmode=0;
			apmib_update_web(CURRENT_SETTING);	// update to flash
			apmib_get(MIB_OP_MODE, (void *)&opmode);

#ifdef MULTI_PPPOE
			if(buttonState == 1 && dhcp == PPPOE)
			{
				extern int PPPoE_Number;
				int ppp_num;
				FILE *pF;
				system("ifconfig |grep 'ppp'| cut -d ' ' -f 1 |  wc -l > /etc/ppp/lineNumber");

				if(flag ==1){
					PPPoE_Number = 1;
					system("echo 1 > /etc/ppp/connfile1");
					system("rm /etc/ppp/disconnect_trigger1 >/dev/null 2>&1");
				}else if(flag ==2){
					PPPoE_Number = 2;
					system("echo 1 > /etc/ppp/connfile2");
					system("rm /etc/ppp/disconnect_trigger2 >/dev/null 2>&1");
				}else if(flag ==3){
					PPPoE_Number = 3;
					system("echo 1 > /etc/ppp/connfile3");
					system("rm /etc/ppp/disconnect_trigger3 >/dev/null 2>&1");
				}else if(flag ==4){
					PPPoE_Number = 4;
					system("echo 1 > /etc/ppp/connfile4");
					system("rm /etc/ppp/disconnect_trigger4 >/dev/null 2>&1");
				}
				system("rm /etc/ppp/connectfile >/dev/null 2>&1");
				if((pF = fopen("/etc/ppp/lineNumber","r+")) != NULL)
				{
					fscanf(pF,"%d",&ppp_num);
					if(ppp_num == 0)
					{
						system("killall -9 ppp_inet 2> /dev/null");
						goto End;
					}
				}
				while (wait_time-- >0) {
					if (isConnectPPP()){
						printf("PPP is connected\n");
						break;
					}
					sleep(1);
				}
				if (isConnectPPP())
					strcpy(tmpBuf, ("Connected to server successfully.\n"));
				else
					strcpy(tmpBuf, ("Connect to server failed!\n"));
				OK_MSG1(tmpBuf, submitUrl);
				return 1;
			}
End:
#endif
////			if(opmode==2)
////				WAN_IF = ("wlan0");
			if(opmode==2)
			{
				int wisp_wan_id, wlan_mode;
				char wlan_name[16];
				apmib_get(MIB_WISP_WAN_ID,(void *)&wisp_wan_id);

				sprintf(wlan_name,"wlan%d",wisp_wan_id);
				if(SetWlan_idx(wlan_name))
				{
					apmib_get(MIB_WLAN_MODE,(void *)&wlan_mode);
					if(wlan_mode == CLIENT_MODE)
						sprintf(tmpbuf, "wlan%d", wisp_wan_id);
					else
						sprintf(tmpbuf, "wlan%d-vxd", wisp_wan_id);
				}
				WAN_IF=tmpbuf;
//				printf("%s:%d wan_if=%s\n",__FUNCTION__,__LINE__,WAN_IF);
			}
			else if(opmode ==0)
				WAN_IF = ("eth1");

			system("killall -9 igmpproxy 2> /dev/null");
			system("echo 1,1 > /proc/br_mCastFastFwd");
			system("killall -9 dnrd 2> /dev/null");
			if(dhcp == PPPOE || dhcp == PPTP)
			{
				//system("killall -15 pppd 2> /dev/null");
			}
        #ifdef RTK_USB3G
            else if (dhcp == USB3G)
                kill_3G_ppp_inet();
        #endif
			else
			{
				//system("killall -9 pppd 2> /dev/null");
			}

				system("disconnect.sh option");
#ifndef NO_ACTION
        #ifdef RTK_USB3G
            if (dhcp == USB3G)
                system("ppp_inet -t 16 -c 0 -x");
            else {
        #endif
			pid = fork();
        		if (pid)
	        		waitpid(pid, NULL, 0);
			else if (pid == 0) {
				if(dhcp == PPPOE){
					snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _PPPOE_SCRIPT_PROG);
					execl( tmpBuf, _PPPOE_SCRIPT_PROG, "connect", WAN_IF, NULL);
				}else if(dhcp == PPTP){
					snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _PPTP_SCRIPT_PROG);
					execl( tmpBuf, _PPTP_SCRIPT_PROG, "connect", WAN_IF, NULL);
				}else if(dhcp == L2TP){
					system("killall -9 l2tpd 2> /dev/null");
					system("rm -f /var/run/l2tpd.pid 2> /dev/null");
					snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _L2TP_SCRIPT_PROG);
					execl( tmpBuf, _L2TP_SCRIPT_PROG, "connect", WAN_IF, NULL);
				}
       				exit(1);
			}
        #ifdef RTK_USB3G
            }
        #endif
			while (wait_time-- >0) {
				if (isConnectPPP()){
					printf("PPP is connected\n");
					break;
				}
				sleep(1);
			}
			if (isConnectPPP())
				strcpy(tmpBuf, ("Connected to server successfully.\n"));
			else
				strcpy(tmpBuf, ("Connect to server failed!\n"));

			OK_MSG1(tmpBuf, submitUrl);
#endif
			return 1;
		}

		if ( buttonState == 2 && (dhcp == PPPOE || dhcp == PPTP || dhcp == L2TP || dhcp == USB3G) ) { // disconnect button is pressed
			apmib_update_web(CURRENT_SETTING);	// update to flash


#ifdef MULTI_PPPOE
		if ( buttonState == 2 && dhcp == PPPOE)
		{
			char ppp_name[5];
			int orderNumber,pppNumbers,index;
			FILE *order,*number;
			int wait_time=30;
			if((order=fopen("/etc/ppp/ppp_order_info","r+"))==NULL)
			{
				printf("Cannot open this file\n");
				goto end;
			}
			if((number=fopen("/etc/ppp/lineNumber","r+"))==NULL)
			{
				printf("Cannot open this file\n");
				goto end;
			}
			fscanf(number,"%d",&pppNumbers);
			close(order);
			close(number);
			for( index = 0 ; index < pppNumbers ; ++index)
			{
				fscanf(order,"%d--%s",&orderNumber,ppp_name);
				if(flag == orderNumber)
				{
					int pid;
					char path[50],cmd[50];
					FILE *pidF;
					extern int PPPoE_Number;
					sprintf(path,"/var/run/%s.pid",ppp_name);
					if((pidF=fopen(path,"r+")) == NULL)
						goto end;
					fscanf(pidF,"%d",&pid);
					if(flag ==1){
						system("echo 1 > /etc/ppp/disconnect_trigger1");
						PPPoE_Number = 1;
					}
					else if(flag == 2){
						system("echo 1 > /etc/ppp/disconnect_trigger2");
						PPPoE_Number = 2;
					}
					else if(flag ==3){
						system("echo 1 > /etc/ppp/disconnect_trigger3");
						PPPoE_Number = 3;
					}
					else if(flag ==4){
						system("echo 1 > /etc/ppp/disconnect_trigger4");
						PPPoE_Number = 4;
					}
					sprintf(cmd,"kill %d  2> /dev/null",pid);
					system(cmd);
					system("rm /etc/ppp/connectfile >/dev/null 2>&1");
					while (wait_time-- >0) {
						if (!isConnectPPP()){
							printf("PPP is disconnected\n");
							break;
						}
						sleep(1);
					}
					if (!isConnectPPP())
						strcpy(tmpBuf, ("PPPoE disconnected.\n"));
					else
						strcpy(tmpBuf, ("Unknown\n"));

					OK_MSG1(tmpBuf, submitUrl);
					return 1;
				}
			}

		}
end:
#endif

#ifndef NO_ACTION
        #ifdef RTK_USB3G
            if (dhcp == USB3G)
                kill_3G_ppp_inet();
            else
        #endif
			//if(dhcp != PPTP)
			if(1)
			{
			pid = fork();
        		if (pid)
	             		waitpid(pid, NULL, 0);
        		else if (pid == 0) {
				snprintf(tmpBuf, 100, "%s/%s", _CONFIG_SCRIPT_PATH, _PPPOE_DC_SCRIPT_PROG);
				execl( tmpBuf, _PPPOE_DC_SCRIPT_PROG, "all", NULL);
                		exit(1);
        		}
        	}else{
        		system("killall -15 ppp_inet 2> /dev/null");
        		system("killall -15 pppd 2> /dev/null");
        	}

        		if(dhcp == PPPOE)
			strcpy(tmpBuf, ("PPPoE disconnected.\n"));
			if(dhcp == PPTP)
			strcpy(tmpBuf, ("PPTP disconnected.\n"));
			if(dhcp == L2TP)
			strcpy(tmpBuf, ("L2TP disconnected.\n"));
            if(dhcp == USB3G)
                strcpy(tmpBuf, ("USB3G disconnected.\n"));

			OK_MSG1(tmpBuf, submitUrl);
#endif
			return 1;
		}
	}
	else
		dhcp = curDhcp;

	if ( dhcp == DHCP_DISABLED ) {
		strIp = req_get_cstream_var(wp, ("wan_ip"), "");
		if ( strIp[0] ) {
			if ( !inet_aton(strIp, &inIp) ) {
				strcpy(tmpBuf, ("Invalid IP-address value!"));
				goto setErr_tcpip;
			}
#ifdef __DAVO__
			if ( (res=is_dup_check(strIp)>0) ) {
				sprintf(tmpBuf, "%s", (res==1)? ("IP 주소가 충돌했습니다."):("IP 주소가 올바르지 않습니다!"));
				goto setErr_tcpip;
			}
#endif
			if ( !apmib_set(MIB_WAN_IP_ADDR, (void *)&inIp)) {
				strcpy(tmpBuf, ("Set IP-address error!"));
				goto setErr_tcpip;
			}
		}

		strMask = req_get_cstream_var(wp, ("wan_mask"), "");
		if ( strMask[0] ) {
			if ( !inet_aton(strMask, &inMask) ) {
				strcpy(tmpBuf, ("Invalid subnet-mask value!"));
				goto setErr_tcpip;
			}
			if ( !apmib_set(MIB_WAN_SUBNET_MASK, (void *)&inMask)) {
				strcpy(tmpBuf, ("Set subnet-mask error!"));
				goto setErr_tcpip;
			}
		}

		strGateway = req_get_cstream_var(wp, ("wan_gateway"), "");
		if ( strGateway[0] ) {
			if ( !inet_aton(strGateway, &inGateway) ) {
				strcpy(tmpBuf, ("Invalid default-gateway value!"));
				goto setErr_tcpip;
			}
			if ( !apmib_set(MIB_WAN_DEFAULT_GATEWAY, (void *)&inGateway)) {
				strcpy(tmpBuf, ("Set default-gateway error!"));
				goto setErr_tcpip;
			}
		}

		strVal = req_get_cstream_var(wp, ("fixedIpMtuSize"), "");
		if ( strVal[0] ) {
			int mtuSize;
			mtuSize = strtol(strVal, (char**)NULL, 10);
			if ( apmib_set(MIB_FIXED_IP_MTU_SIZE, (void *)&mtuSize) == 0) {
				strcpy(tmpBuf, ("Set FIXED-IP mtu size MIB error!"));
				goto setErr_tcpip;
			}
		}
	}

	if ( !apmib_set(MIB_WAN_DHCP, (void *)&dhcp)) {
		strcpy(tmpBuf, ("Set DHCP error!"));
		goto setErr_tcpip;
	}

	if (!call_from_wizard) { // not called from wizard
		if (dhcp == DHCP_CLIENT) {
			strVal = req_get_cstream_var(wp, ("dhcpMtuSize"), "");
			if ( strVal ) {
				int mtuSize;
				mtuSize = strtol(strVal, (char**)NULL, 10);
				if ( apmib_set(MIB_DHCP_MTU_SIZE, (void *)&mtuSize) == 0) {
					strcpy(tmpBuf, ("Set DHCP mtu size MIB error!"));
					goto setErr_tcpip;
				}
			}

#if 0	/* Presume hostName read-only variable */
			strVal = req_get_cstream_var(wp, ("hostName"), "");
			if (strVal) {
				if (!isValidName(strVal)) {
  					strcpy(tmpBuf, ("Invalid Host Name! Please enter characters in A(a)~Z(z) or 0-9 without spacing."));
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_HOST_NAME, (void *)strVal)) {
  					strcpy(tmpBuf, ("Set MIB_HOST_NAME MIB error!"));
					goto setErr_tcpip;
				}
			}else{
				 if ( !apmib_set(MIB_HOST_NAME, (void *)"")){
	  					strcpy(tmpBuf, ("\"Set MIB_HOST_NAME MIB error!\""));
						goto setErr_tcpip;
				}
			}
#endif
		}
#ifdef _ALPHA_DUAL_WAN_SUPPORT_
		strVal = req_get_cstream_var(wp, ("pppoeWithDhcpEnabled"), "");
		if ( !strcmp(strVal, "ON"))
			intVal = 1;
		else
			intVal = 0;
		if ( !apmib_set(MIB_PPPOE_DHCP_ENABLED, (void *)&intVal)) {
			strcpy(tmpBuf, ("Set MIB_PPPOE_DHCP_ENABLED error!"));
			goto setErr_tcpip;
		}
#endif
#if 0
		/* APACRTL-539 369jb */
		strVal = req_get_cstream_var(wp, ("upnpEnabled"), "");
		if ( !strcmp(strVal, "ON"))
			intVal = 1;
		else
			intVal = 0;
		if ( !apmib_set(MIB_UPNP_ENABLED, (void *)&intVal)) {
			strcpy(tmpBuf, ("UPNP 사용 설정 오류!"));
			goto setErr_tcpip;
		}
#endif
//Brad add for igmpproxy
		strVal = req_get_cstream_var(wp, ("igmpproxyEnabled"), "");
		if ( !strcmp(strVal, "ON"))
			intVal = 0;
		else
			intVal = 1;
		if ( !apmib_set(MIB_IGMP_PROXY_DISABLED, (void *)&intVal)) {
			strcpy(tmpBuf, ("IGMP PROXY 사용 설정 오류!"));
			goto setErr_tcpip;
		}
//Brad add end
		strVal = req_get_cstream_var(wp, ("webWanAccess"), "");
		if ( !strcmp(strVal, "ON"))
			intVal = 1;
		else
			intVal = 0;
		if ( !apmib_set(MIB_WEB_WAN_ACCESS_ENABLED, (void *)&intVal)) {
			strcpy(tmpBuf, ("웹서버 접근 사용 설정 오류!"));
			goto setErr_tcpip;
		}

		strVal = req_get_cstream_var(wp, ("pingWanAccess"), "");
		if ( !strcmp(strVal, "ON"))
			intVal = 1;
		else
			intVal = 0;
		if ( !apmib_set(MIB_PING_WAN_ACCESS_ENABLED, (void *)&intVal)) {
			strcpy(tmpBuf, ("PING 응답 사용 설정 오류!"));
			goto setErr_tcpip;
		}

		strVal = req_get_cstream_var(wp, ("WANPassThru1"), "");
		if ( !strcmp(strVal, "ON"))
			intVal = 1;
		else
			intVal = 0;
		if ( !apmib_set(MIB_VPN_PASSTHRU_IPSEC_ENABLED, (void *)&intVal)) {
			strcpy(tmpBuf, ("VPN PASSTHRU IPSEC 사용 설정 오류!"));
			goto setErr_tcpip;
		}

		strVal = req_get_cstream_var(wp, ("WANPassThru2"), "");
		if ( !strcmp(strVal, "ON"))
			intVal = 1;
		else
			intVal = 0;
		if ( !apmib_set(MIB_VPN_PASSTHRU_PPTP_ENABLED, (void *)&intVal)) {
			strcpy(tmpBuf, ("VPN PASSTHRU PPTP 사용 설정 오류!"));
			goto setErr_tcpip;
		}

		strVal = req_get_cstream_var(wp, ("WANPassThru3"), "");
		if ( !strcmp(strVal, "ON"))
			intVal = 1;
		else
			intVal = 0;
		if ( !apmib_set(MIB_VPN_PASSTHRU_L2TP_ENABLED, (void *)&intVal)) {
			strcpy(tmpBuf, ("Set VPN_PASSTHRU_L2TP_ENABLED error!"));
			goto setErr_tcpip;
		}
		/*strVal = req_get_cstream_var(wp, ("ipv6_passthru_enabled"), "");
		if ( !strcmp(strVal, "ON"))
			intVal = 1;
		else
			intVal = 0;
		if (!apmib_set(MIB_CUSTOM_PASSTHRU_ENABLED, (void *)&intVal)) {
			strcpy(tmpBuf, ("Set custom passthru enabled error!"));
			goto setErr_tcpip;
		}*/

		if (wp->superUser == 1) {
			strVal = req_get_cstream_var(wp, ("telnet_enabled"), "");
			if (!strcmp(strVal, "ON")) {
				apmib_nvram_set("x_telnet_enable", "1");
				enable_telnet(); // Unnecessary reboot
				start_telnetd();
			} else {
				apmib_nvram_set("x_telnet_enable", "0");
			}
		}
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
		strVal = req_get_cstream_var(wp, ("WANDot1xEnabled"), "");
		apmib_get(MIB_ELAN_DOT1X_MODE,(void *)&dot1x_mode);
		apmib_get(MIB_ELAN_ENABLE_1X,(void *)&dot1x_enable);
		#if 0
		if(strcmp(strVal,"ON")){
			intVal = 1;
			dot1x_mode |= ETH_DOT1X_CLIENT_MODE;
		}
		else{
			dot1x_mode &= (~ETH_DOT1X_CLIENT_MODE);
			if(dot1x_mode)
				intVal = 1;
			else
				intVal = 0;
		}
		#else
		if(strcmp(strVal,"ON"))
		{
			dot1x_enable |= ETH_DOT1X_CLIENT_MODE_ENABLE_BIT;
			dot1x_mode |= ETH_DOT1X_CLIENT_MODE_BIT;
		}
		else
		{
			dot1x_enable &= ~ETH_DOT1X_CLIENT_MODE_ENABLE_BIT;
			dot1x_mode &= (~ETH_DOT1X_CLIENT_MODE_BIT);
		}
		#endif
		apmib_set(MIB_ELAN_DOT1X_MODE,(void *)&dot1x_mode);
		apmib_set(MIB_ELAN_ENABLE_1X,(void *)&dot1x_enable);

		strVal = req_get_cstream_var(wp, "eapType", "");
		if (strVal[0]) {
				if ( !string_to_dec(strVal, &intVal) ) {
					strcpy(tmpBuf, ("Invalid 802.1x EAP type value!"));
					goto setErr_tcpip;
				}
				if ( !apmib_set(MIB_ELAN_EAP_TYPE, (void *)&intVal)) {
					strcpy(tmpBuf, ("Set MIB_ELAN_EAP_TYPE error!"));
					goto setErr_tcpip;
				}
			}
			else{
				strcpy(tmpBuf, ("No 802.1x EAP type!"));
				goto setErr_tcpip;
			}

			if(intVal == EAP_MD5){
				strVal = req_get_cstream_var(wp, "eapUserId", "");
				if (strVal[0]) {
					if(strlen(strVal)>MAX_EAP_USER_ID_LEN){
						strcpy(tmpBuf, ("EAP user ID too long!"));
						goto setErr_tcpip;
					}
					if ( !apmib_set(MIB_ELAN_EAP_USER_ID, (void *)strVal)) {
						strcpy(tmpBuf, ("Set MIB_ELAN_EAP_USER_ID error!"));
						goto setErr_tcpip;
					}
				}
				else{
					strcpy(tmpBuf, ("No 802.1x EAP User ID!"));
					goto setErr_tcpip;
				}

				strVal = req_get_cstream_var(wp, "radiusUserName", "");
				if (strVal[0]) {
					if(strlen(strVal)>MAX_RS_USER_NAME_LEN){
						strcpy(tmpBuf, ("RADIUS user name too long!"));
						goto setErr_tcpip;
					}
					if ( !apmib_set(MIB_ELAN_RS_USER_NAME, (void *)strVal)) {
						strcpy(tmpBuf, ("Set MIB_ELAN_RS_USER_NAME error!"));
						goto setErr_tcpip;
					}
				}
				else{
					strcpy(tmpBuf, ("No 802.1x RADIUS User Name!"));
					goto setErr_tcpip;
				}


				strVal = req_get_cstream_var(wp, "radiusUserPass", "");
				if (strVal[0]) {
					if(strlen(strVal)>MAX_RS_USER_PASS_LEN){
						strcpy(tmpBuf, ("RADIUS user password too long!"));
						goto setErr_tcpip;
					}
					if ( !apmib_set(MIB_ELAN_RS_USER_PASSWD, (void *)strVal)) {
						strcpy(tmpBuf, ("Set MIB_ELAN_RS_USER_PASSWD error!"));
						goto setErr_tcpip;
					}
				}
				else{
					strcpy(tmpBuf, ("No 802.1x RADIUS User Password!"));
					goto setErr_tcpip;
				}
			}
			else if(intVal == EAP_TLS){

				strVal = req_get_cstream_var(wp, "eapUserId", "");
				if (strVal[0]) {
					if(strlen(strVal)>MAX_EAP_USER_ID_LEN){
						strcpy(tmpBuf, ("EAP user ID too long!"));
						goto setErr_tcpip;
					}
					if ( !apmib_set(MIB_ELAN_EAP_USER_ID, (void *)strVal)) {
						strcpy(tmpBuf, ("Set MIB_ELAN_EAP_USER_ID error!"));
						goto setErr_tcpip;
					}
				}
				else{
					strcpy(tmpBuf, ("No 802.1x EAP User ID!"));
					goto setErr_tcpip;
				}

				strVal = req_get_cstream_var(wp, "radiusUserCertPass", "");
				if (strVal[0]) {
					if(strlen(strVal)>MAX_RS_USER_CERT_PASS_LEN){
						strcpy(tmpBuf, ("RADIUS user cert password too long!"));
						goto setErr_tcpip;
					}
					if ( !apmib_set(MIB_ELAN_RS_USER_CERT_PASSWD, (void *)strVal)) {
						strcpy(tmpBuf, ("Set MIB_ELAN_RS_USER_CERT_PASSWD error!"));
						goto setErr_tcpip;
					}
				}
				else{
					if ( !apmib_set(MIB_ELAN_RS_USER_CERT_PASSWD, (void *)strVal)) {
						strcpy(tmpBuf, ("Clear MIB_ELAN_RS_USER_CERT_PASSWD error!"));
						goto setErr_tcpip;
					}
					//strcpy(tmpBuf, ("No 802.1x RADIUS user cert password!"));
					//goto setErr_encrypt;
				}


					if(isFileExist(RS_USER_CERT_ETH) != 1){
						strcpy(tmpBuf, ("No 802.1x RADIUS ethernet user cert!\nPlease upload it."));
						goto setErr_tcpip;
					}

					if(isFileExist(RS_ROOT_CERT_ETH) != 1){
						strcpy(tmpBuf, ("No 802.1x RADIUS ethernet root cert!\nPlease upload it."));
						goto setErr_tcpip;
					}


			}
			else if(intVal == EAP_PEAP){
				strVal = req_get_cstream_var(wp, "eapInsideType", "");
				if (strVal[0]) {
					if ( !string_to_dec(strVal, &intVal2) ) {
						strcpy(tmpBuf, ("Invalid 802.1x inside tunnel type value!"));
						goto setErr_tcpip;
					}
					if ( !apmib_set(MIB_ELAN_EAP_INSIDE_TYPE, (void *)&intVal2)) {
						strcpy(tmpBuf, ("Set MIB_ELAN_EAP_INSIDE_TYPE error!"));
						goto setErr_tcpip;
					}
				}
				else{
					strcpy(tmpBuf, ("No 802.1x inside tunnel type!"));
					goto setErr_tcpip;
				}

				if(intVal2 == INSIDE_MSCHAPV2){
					strVal = req_get_cstream_var(wp, "eapUserId", "");
					if (strVal[0]) {
						if(strlen(strVal)>MAX_EAP_USER_ID_LEN){
							strcpy(tmpBuf, ("EAP user ID too long!"));
							goto setErr_tcpip;
						}
						if ( !apmib_set(MIB_ELAN_EAP_USER_ID, (void *)strVal)) {
							strcpy(tmpBuf, ("Set MIB_ELAN_EAP_USER_ID error!"));
							goto setErr_tcpip;
						}
					}
					else{
						strcpy(tmpBuf, ("No 802.1x EAP User ID!"));
						goto setErr_tcpip;
					}

					strVal = req_get_cstream_var(wp, "radiusUserName", "");
					if (strVal[0]) {
						if(strlen(strVal)>MAX_RS_USER_NAME_LEN){
							strcpy(tmpBuf, ("RADIUS user name too long!"));
							goto setErr_tcpip;
						}
						if ( !apmib_set(MIB_ELAN_RS_USER_NAME, (void *)strVal)) {
							strcpy(tmpBuf, ("Set MIB_ELAN_RS_USER_NAME error!"));
							goto setErr_tcpip;
						}
					}
					else{
						strcpy(tmpBuf, ("No 802.1x RADIUS User Name!"));
						goto setErr_tcpip;
					}

					strVal = req_get_cstream_var(wp, "radiusUserPass", "");
					if (strVal[0]) {
						if(strlen(strVal)>MAX_RS_USER_PASS_LEN){
							strcpy(tmpBuf, ("RADIUS user password too long!"));
							goto setErr_tcpip;
						}
						if ( !apmib_set(MIB_ELAN_RS_USER_PASSWD, (void *)strVal)) {
							strcpy(tmpBuf, ("Set MIB_ELAN_RS_USER_PASSWD error!"));
							goto setErr_tcpip;
						}
					}
					else{
						strcpy(tmpBuf, ("No 802.1x RADIUS User Password!"));
						goto setErr_tcpip;
					}

//					if(isFileExist(RS_USER_CERT) == 1){
						strVal = req_get_cstream_var(wp, "radiusUserCertPass", "");
						if (strVal[0]) {
							if(strlen(strVal)>MAX_RS_USER_CERT_PASS_LEN){
								strcpy(tmpBuf, ("RADIUS user cert password too long!"));
								goto setErr_tcpip;
							}
							if ( !apmib_set(MIB_ELAN_RS_USER_CERT_PASSWD, (void *)strVal)) {
								strcpy(tmpBuf, ("Set MIB_ELAN_RS_USER_CERT_PASSWD error!"));
								goto setErr_tcpip;
							}
						}
						else{
							if ( !apmib_set(MIB_ELAN_RS_USER_CERT_PASSWD, (void *)strVal)) {
								strcpy(tmpBuf, ("[1] Clear MIB_ELAN_RS_USER_CERT_PASSWD error!"));
								goto setErr_tcpip;
							}
							//strcpy(tmpBuf, ("No 802.1x RADIUS user cert password!"));
							//goto setErr_encrypt;
						}
//					}
				}
				else{
					strcpy(tmpBuf, ("802.1x inside tunnel type not support!"));
					goto setErr_tcpip;
				}
			}
			else if (intVal == EAP_TTLS){
				strVal = req_get_cstream_var(wp, "eapPhase2Type", "");
				if (strVal[0]) {
					if ( !string_to_dec(strVal, &intVal2) ) {
						strcpy(tmpBuf, ("Invalid 802.1x phase2 type value!"));
						goto setErr_tcpip;
					}
					if ( !apmib_set(MIB_ELAN_EAP_PHASE2_TYPE, (void *)&intVal2)) {
						strcpy(tmpBuf, ("Set MIB_ELAN_EAP_INSIDE_TYPE error!"));
						goto setErr_tcpip;
					}
				}
				else{
					strcpy(tmpBuf, ("No 802.1x phase 2 type!"));
					goto setErr_tcpip;
				}

				if(intVal2 == TTLS_PHASE2_EAP){
					val = TTLS_PHASE2_EAP_MD5;
					apmib_set(MIB_ELAN_PHASE2_EAP_METHOD,(void *)&val);
					strVal = req_get_cstream_var(wp, "eapUserId", "");
					if (strVal[0]) {
						if(strlen(strVal)>MAX_EAP_USER_ID_LEN){
							strcpy(tmpBuf, ("EAP user ID too long!"));
							goto setErr_tcpip;
						}
						if ( !apmib_set(MIB_ELAN_EAP_USER_ID, (void *)strVal)) {
							strcpy(tmpBuf, ("Set MIB_ELAN_EAP_USER_ID error!"));
							goto setErr_tcpip;
						}
					}
					else{
						strcpy(tmpBuf, ("No 802.1x EAP User ID!"));
						goto setErr_tcpip;
					}

					strVal = req_get_cstream_var(wp, "radiusUserName", "");
					if (strVal[0]) {
						if(strlen(strVal)>MAX_RS_USER_NAME_LEN){
							strcpy(tmpBuf, ("RADIUS user name too long!"));
							goto setErr_tcpip;
						}
						if ( !apmib_set(MIB_ELAN_RS_USER_NAME, (void *)strVal)) {
							strcpy(tmpBuf, ("Set MIB_ELAN_RS_USER_NAME error!"));
							goto setErr_tcpip;
						}
					}
					else{
						strcpy(tmpBuf, ("No 802.1x RADIUS User Name!"));
						goto setErr_tcpip;
					}

					strVal = req_get_cstream_var(wp, "radiusUserPass", "");
					if (strVal[0]) {
						if(strlen(strVal)>MAX_RS_USER_PASS_LEN){
							strcpy(tmpBuf, ("RADIUS user password too long!"));
							goto setErr_tcpip;
						}
						if ( !apmib_set(MIB_ELAN_RS_USER_PASSWD, (void *)strVal)) {
							strcpy(tmpBuf, ("Set MIB_ELAN_RS_USER_PASSWD error!"));
							goto setErr_tcpip;
						}
					}
					else{
						strcpy(tmpBuf, ("No 802.1x RADIUS User Password!"));
						goto setErr_tcpip;
					}
					if(isFileExist(RS_ROOT_CERT_ETH) != 1){
						strcpy(tmpBuf, ("No 802.1x RADIUS ethernet root cert!\nPlease upload it."));
						goto setErr_tcpip;
					}
//
				}
				else{
					strcpy(tmpBuf, ("802.1x ttls phase2 type not support!"));
					goto setErr_tcpip;
				}
			}
			else{
				strcpy(tmpBuf, ("802.1x EAP type not support!"));
				goto setErr_tcpip;
			}
#endif

	}
	return 0 ;
setErr_tcpip:
	return -1 ;
}



////////////////////////////////////////////////////////////////////////////////
#ifdef __DAVO__
#define _DHCPC_PROG_NAME	"udhcpc"
#define _DHCPC_PID_PATH		"/etc/udhcpc"

#define PARSE_MAX			20
#define HANGUL_IP_INFORM	"IP 정보"
#define HANGUL_ROUTER		"Router 주소"

#define TD_COLOR(B)	(B%2)?"#DDDDDD":"#EEEEEE"

int show_ipv6_information(request *wp, int argc, char **argv)
{
	char *p, *s;
	int i;
	int nBytesSent = 0;

/*	nBytesSent += req_format_write(wp, "<tr bgcolor=\"%s\">\\n", TD_COLOR(0));
	nBytesSent += req_format_write(wp, "<td width=25%%><font size=2><b>&nbsp;%s</b></td>\\n", HANGUL_IP_INFORM);
	nBytesSent += req_format_write(wp, "<td width=75%%><font size=2>%s</td>", "TEST");
*/

	s = INET6_getaddrs("br0");
	for (i = 0, p = s; p && *p; p += (strlen(p) + 1), i++) {
		nBytesSent += req_format_write(wp, "<tr bgcolor=\"%s\">\\n"
							"<td width=30%%><font size=2><b>&nbsp;%s</b></td>\\n"
							"<td width=70%%><font size=2>%s</td>\\n"
							"</tr>\\n", TD_COLOR(0), (i == 0) ? HANGUL_IP_INFORM : "", p);
	}
	if (s)
		free(s);
	if (i == 0)
		nBytesSent += req_format_write(wp, "<tr bgcolor=\"%s\">\\n"
									"<td width=30%%><font size=2><b>&nbsp;%s</b></td>\\n"
									"<td width=70%%><font size=2></td>\\n"
									"</tr>\\n", TD_COLOR(0), HANGUL_IP_INFORM);

	s = INET6_getdroutes();
	for (i = 0, p = s; p && *p; p += (strlen(p) + 1), i++) {
		nBytesSent += req_format_write(wp, "<tr bgcolor=\"%s\">\\n"
							"<td width=30%%><font size=2><b>&nbsp;%s</b></td>\\n"
							"<td width=70%%><font size=2>%s</td>\\n"
							"</tr>\\n", TD_COLOR(1), (i==0)? HANGUL_ROUTER:"", p);
	}
	if (s)
		free(s);
	if (i == 0)
		nBytesSent += req_format_write(wp, "<tr bgcolor=\"%s\">\\n"
							"<td width=30%%><font size=2><b>&nbsp;%s</b></td>\\n"
							"<td width=70%%><font size=2></td>\\n"
							"</tr>\\n", TD_COLOR(1), (i==0)? HANGUL_ROUTER:"");

	s = INET6_getdns();
	for (i = 0, p = s; p && *p; p += (strlen(p) + 1), i++) {
		nBytesSent += req_format_write(wp, "<tr bgcolor=\"%s\">\\n"
							"<td width=30%%><font size=2><b>&nbsp;%s</b></td>\\n"
							"<td width=70%%><font size=2>%s</td>\\n"
							"</tr>\\n", TD_COLOR(0), (i==0)? "DNS":"", p);
	}
	if (s)
		free(s);
	if (i == 0)
		nBytesSent += req_format_write(wp, "<tr bgcolor=\"%s\">\\n"
							"<td width=30%%><font size=2><b>&nbsp;%s</b></td>\\n"
							"<td width=70%%><font size=2></td>\\n"
							"</tr>\\n", TD_COLOR(0), (i==0)? "DNS":"");
	return nBytesSent;
}

static void send_renewal_dhcpc(void)
{
	/*unuse value 150610*/
	/*char *tmpStr;
	char *submitUrl;*/
	char tmpBuf[128], ifmode[32];
	int pid, opmode = 0;

	if (!apmib_get(MIB_OP_MODE, (void *)&opmode))
		return;

	if (opmode == 1)
		snprintf(ifmode, sizeof(ifmode), "-br0");
	else
		snprintf(ifmode, sizeof(ifmode), "-eth1");

	snprintf(tmpBuf, sizeof(tmpBuf), "%s/%s%s.pid", _DHCPC_PID_PATH, _DHCPC_PROG_NAME, ifmode);

	pid = fget_and_test_pid(tmpBuf);
	if (pid > 0) {
		kill(pid, SIGUSR2);
		usleep(500000);
		kill(pid, SIGUSR1);
	}
}

void formWanIpRenewal(request *wp, char *path, char *query)
{
	char *submitUrl;

	submitUrl = req_get_cstream_var(wp, "submit-url", "");
	if (submitUrl[0]) {
		send_renewal_dhcpc();
		DO_APPLY_WAIT("/skb_status.htm");
		return;
	}

}

static const char *formPhyConfig(request *wp, int iname, int phyid, int *setconf, const char *alias)
{
	char cmd[128],tmp[128];
	char nbuf[32], vbuf[128];
	int i, argc;
	char *argv[12], *p = NULL;
	int n, up, nego, duplex, speed, rxpause, txpause, prev_up;

	apmib_set_hist_clear();		/* APACRTL-85 */

	sprintf(tmp, "power%d", iname);
	p =req_get_cstream_var(wp, tmp, "0");
	up = atoi(p);

	sprintf(tmp, "nego%d", iname);
	p =req_get_cstream_var(wp, tmp, "1");
	nego = atoi(p);

	up = !up;
	if (!nego) {
		sprintf(tmp, "speed%d", iname);
		p =req_get_cstream_var(wp, tmp, "1");
		speed = atoi(p);

		sprintf(tmp, "duplex%d", iname);
		p =req_get_cstream_var(wp, tmp, "0");
		duplex = atoi(p);
	} else
		duplex = 0, speed = 0;


	sprintf(tmp, "rx%d_pause", iname);
	p =req_get_cstream_var(wp, tmp, "1");
	rxpause = atoi(p);

	sprintf(tmp, "tx%d_pause", iname);
	p =req_get_cstream_var(wp, tmp, "1");
	txpause = atoi(p);

	if (rxpause && rxpause != 1)
		return "수신 흐름제어가 올바르지 않습니다";
	if (txpause && txpause != 1)
		return "송신 흐름제어가 올바르지 않습니다";

	n = sprintf(cmd, "phyconfig %d %s", phyid, up ? "up" : "down");
	if (nego)
		n += sprintf(&cmd[n], " auto");
	else {
		if(speed==0)
			sprintf(tmp, "10");
		else if(speed==1)
			sprintf(tmp, "100");
		else
			sprintf(tmp, "1000");
		n += sprintf(&cmd[n], " duplex %s speed %s", duplex ? "full" : "half", tmp);
	}
	sprintf(&cmd[n], " %srxpause %stxpause", rxpause ? "" : "-", txpause ? "" : "-");
	//system(cmd);

	argc = websStrArgs(cmd, argv, 12, " ");
	sprintf(nbuf, "x_port_%d_config", phyid);
	prev_up = (strstr(nvram_safe_get(nbuf), "down")) ? 0 : 1;
	n = 0;
	for (i = 2; i < argc; i++)
		n += sprintf(&vbuf[n], "%s_", argv[i]);
	if (n > 0) {
		vbuf[--n] = '\0';
		apmib_nvram_set(nbuf, vbuf);
		*setconf=1;
	}

	if (apmib_set_hist_strstr(nbuf) > -1) {	/* APACRTL-85 */
		if (!up) {
			if (prev_up)
				LOG(LOG_INFO, "%s포트를 전원 OFF 설정함", alias);
		} else if (nego)
			LOG(LOG_INFO, "%s포트가 자동협상과 흐름제어를 사용%s함으로 설정됨",
			    alias, rxpause ? "" : " 안 ");
		else
			LOG(LOG_INFO, "%s포트가 속도 %d, %s이중 전송방식, 흐름제어 사용%s함으로 설정됨",
			    alias, !speed ? 10 : ((speed == 1) ? 100 : 1000),
			    duplex ? "전" : "반", rxpause ? "" : " 안 ");
	}
	return NULL;
}

void formPortSetup(request *wp, char *path, char *query)
{
	char cmd[128], buf[128];
	char tmpBuf[128];
	int i, n;
	int opmode, mode_changed = 0;
	const char *w_error = NULL;
	char *p = NULL;
	int set_conf = 0;

	for (i = 0; i <= 4; i++) {
		sprintf(tmpBuf, "port_reset_%d", i);
		p = req_get_cstream_var(wp, tmpBuf, "");
		if (p[0]!=0) {
			LOG(LOG_INFO, "%s 포트 리셋함", getportalias(i));
			sprintf(cmd, "phyconfig %d up auto %s txpause", i, (i == 4)? "rxpause" : "-rxpause");
			system(cmd);
			sprintf(buf, "x_port_%d_config", i);
			apmib_nvram_set(buf, (i == 4)? "up_auto_rxpause_txpause" : "up_auto_-rxpause_txpause");
			nvram_commit();
			send_redirect_perm(wp, "skb_tcpipport.htm");
			return;
		}
	}
#if 0
	p = req_get_cstream_var(wp, "opMode", "");
	if (p[0]) {
		opmode=atoi(p);
		if (apmib_get(MIB_OP_MODE, (void *)&n) && n != opmode) {
			struct in_addr ip;
			DHCP_T dhcp;

			mode_changed = 1;
			switch (opmode) {
			case 0:
				LOG(LOG_INFO, "공유기 모드로 변경");
				dhcp = DHCP_SERVER;
				apmib_set(MIB_DHCP, (void *)&dhcp);

				apmib_get(MIB_IP_ADDR,	(void *)&ip);
				apmib_set(MIB_IP_ADDR, (void *)&ip);

				apmib_get(MIB_SUBNET_MASK,	(void *)&ip);
				apmib_set(MIB_SUBNET_MASK, (void *)&ip);

				inet_aton("0.0.0.0", &ip);
				apmib_set(MIB_DEFAULT_GATEWAY, (void *)&ip);

				apmib_get(MIB_DHCP_CLIENT_START,	(void *)&ip);
				apmib_set(MIB_DHCP_CLIENT_START, (void *)&ip);
				apmib_get(MIB_DHCP_CLIENT_END,	(void *)&ip);
				apmib_set(MIB_DHCP_CLIENT_END, (void *)&ip);
				break;

			case 1:
				LOG(LOG_INFO, "스위치 모드로 변경[LAN1~4]");
				dhcp = DHCP_DISABLED;
				apmib_set(MIB_DHCP, (void *)&dhcp);
				break;

			default:
				mode_changed = 0;
			}
		}

		if (apmib_set(MIB_OP_MODE, (void *)&opmode) == 0) {
			strcpy(tmpBuf, "Opmode 설정 오류!");
			goto setErr;
		}
	}
#endif
	for (i = 0; i <= 4; i++) {
		w_error = formPhyConfig(wp, i, i, &set_conf, getportalias(i));
		if (w_error) {
			strcpy(tmpBuf, w_error);
			goto setErr;
		}
	}

	apmib_update_web(CURRENT_SETTING);
	if (mode_changed) {
		need_reboot=1;
		REBOOT_WAIT("/skb_tcpipport.htm");
		sleep(1);
		dv_reboot_system=1;
		return;
	}
	if (set_conf) {
		need_reboot = 1;
		OK_MSG("/skb_tcpipport.htm");
	} else
		send_redirect_perm(wp, "/skb_tcpipport.htm");
	return;

 setErr:
	ERR_MSG(tmpBuf);
}
/* APACRTL-84  smlee 20151029 */
void formSetOperation(request *wp, char *path, char *query)
{
	char *strVal, *strMode, *strSsid, *submitUrl, *strEncrypt;
	int wlan_intf;
	char tmpBuf[100];
	char repeater_ssid[30];
	char vap4_ssid[30];
	int opmode, mode_changed = 0;
	char varName[40];
	int old_wlan_idx, old_vwlan_idx;
	int n;
	char wan_status[128];
	char buffer[6];
	int repeater1=0, repeater2=0;

	strMode = req_get_cstream_var(wp, "operation_mode", "");
	if (!strMode[0]) {
		strcpy(tmpBuf, "오류: 운용 모드가 선택되지 않았습니다.!");
		goto setErr;
	}
	opmode = atoi(strMode);

	if (opmode==0 || opmode==1) {
		apmib_nvram_set("REPEATER_ENABLED1", "0");
		apmib_nvram_set("WLAN0_VAP4_WLAN_DISABLED", "1");
		apmib_nvram_set("WLAN0_VAP4_MODE", "0");
		apmib_nvram_set("REPEATER_ENABLED2", "0");
		apmib_nvram_set("WLAN1_VAP4_WLAN_DISABLED", "1");
		apmib_nvram_set("WLAN1_VAP4_MODE", "0");

		if (apmib_get(MIB_OP_MODE, (void *)&n) && n != opmode) {
			struct in_addr ip;
			DHCP_T dhcp;

			mode_changed = 1;
			switch (opmode) {
			case 0:
				LOG(LOG_INFO, "공유기 모드로 변경");
				dhcp = DHCP_SERVER;
				apmib_set(MIB_DHCP, (void *)&dhcp);

				apmib_get(MIB_IP_ADDR,	(void *)&ip);
				apmib_set(MIB_IP_ADDR, (void *)&ip);

				apmib_get(MIB_SUBNET_MASK,	(void *)&ip);
				apmib_set(MIB_SUBNET_MASK, (void *)&ip);

				inet_aton("0.0.0.0", &ip);
				apmib_set(MIB_DEFAULT_GATEWAY, (void *)&ip);

				apmib_get(MIB_DHCP_CLIENT_START,	(void *)&ip);
				apmib_set(MIB_DHCP_CLIENT_START, (void *)&ip);
				apmib_get(MIB_DHCP_CLIENT_END,	(void *)&ip);
				apmib_set(MIB_DHCP_CLIENT_END, (void *)&ip);
				break;

			case 1:
				LOG(LOG_INFO, "스위치 모드로 변경[LAN1~4]");
				dhcp = DHCP_DISABLED;
				apmib_set(MIB_DHCP, (void *)&dhcp);
				break;

			default:
				mode_changed = 0;
			}
		}

		if (apmib_set(MIB_OP_MODE, (void *)&opmode) == 0) {
			strcpy(tmpBuf, "Opmode 설정 오류!");
			goto setErr;
		}

		/* unset repeater mode wan port recovery */
		nvram_get_r_def("x_port_4_config_back", wan_status, sizeof(wan_status),"up_auto_-rxpause_-txpause");
		apmib_nvram_set("x_port_4_config", wan_status);
		nvram_unset("x_port_4_config_back");
	} else if (opmode==2) {
		strVal = req_get_cstream_var(wp, "repeater_intf", "");
		if (strVal[0]) {
			wlan_intf = atoi(strVal);
		} else {
			strcpy(tmpBuf, "오류: 무선이 선택되지 않았습니다.!");
			goto setErr;

		}

		strSsid = req_get_cstream_var(wp, "repeater_ssid", "");
		if (!strcmp(strMode, "1") && !strSsid[0]) {
			strcpy(tmpBuf, "오류: Repeater SSID가 입력되지 않았습니다.!");
			goto setErr;
		}

		sprintf(repeater_ssid, "REPEATER_SSID%d", wlan_intf+1);
		sprintf(vap4_ssid, "WLAN%d_VAP4_SSID", wlan_intf);

		nvram_get_r_def("REPEATER_ENABLED1", buffer, sizeof(buffer), "0");
		repeater1=atoi(buffer);
		nvram_get_r_def("REPEATER_ENABLED2", buffer, sizeof(buffer), "0");
		repeater2=atoi(buffer);


		old_wlan_idx = wlan_idx;
		old_vwlan_idx = vwlan_idx;
		wlan_idx = wlan_intf;
		vwlan_idx = 5;

		sprintf(varName, "method%d", wlan_idx);
		strEncrypt = req_get_cstream_var(wp, varName, "");
		ENCRYPT_T encrypt = (ENCRYPT_T) strEncrypt[0] - '0';
		if (encrypt==ENCRYPT_WEP) {
			sprintf(varName, "authType%d", wlan_idx);
			char *strAuth = req_get_cstream_var(wp, varName, "");
			AUTH_TYPE_T authType;
			if (strAuth[0]) { // new UI
				if (!strcmp(strAuth, ("open")))
					authType = AUTH_OPEN;
				else if ( !strcmp(strAuth, ("shared")))
					authType = AUTH_SHARED;
				else
					authType = AUTH_BOTH;
				apmib_set(MIB_WLAN_AUTH_TYPE, (void *)&authType);

				formWep(wp, path, query);
				wlan_idx = old_wlan_idx;
				vwlan_idx = old_vwlan_idx;

				//need_reboot=1;
				//REBOOT_WAIT("/skb_opeate_mode.htm");
				//sleep(1);
				//dv_reboot_system=1;
				//return;
			}
		} else if (wpaHandler(wp, tmpBuf, wlan_idx) < 0) {
			wlan_idx = old_wlan_idx;
			vwlan_idx = old_vwlan_idx;
			goto setErr ;
		}

		if (wlan_intf == 1)	{	// 2.4G repeater mode setting
			apmib_nvram_set("REPEATER_ENABLED2", "1");
			apmib_nvram_set("WLAN1_VAP4_WLAN_DISABLED", "0");
			apmib_nvram_set("WLAN1_VAP4_MODE", "1");
			apmib_nvram_set("REPEATER_ENABLED1", "0");
			apmib_nvram_set("WLAN0_VAP4_WLAN_DISABLED", "1");
			apmib_nvram_set("WLAN0_VAP4_MODE", "0");
		} else {				// 5G repeater mode setting
			apmib_nvram_set("REPEATER_ENABLED1", "1");
			apmib_nvram_set("WLAN0_VAP4_WLAN_DISABLED", "0");
			apmib_nvram_set("WLAN0_VAP4_MODE", "1");
			apmib_nvram_set("REPEATER_ENABLED2", "0");
			apmib_nvram_set("WLAN1_VAP4_WLAN_DISABLED", "1");
			apmib_nvram_set("WLAN1_VAP4_MODE", "0");
		}
		apmib_nvram_set(repeater_ssid, strSsid);
		apmib_nvram_set(vap4_ssid, strSsid);

		/* set repeater mode down wan port */
		if (repeater1 == 0 && repeater2 == 0) {
			nvram_get_r_def("x_port_4_config", wan_status, sizeof(wan_status),"up_auto_-rxpause_-txpause");
			apmib_nvram_set("x_port_4_config_back", wan_status);
		}
		apmib_nvram_set("x_port_4_config", "down_auto_-rxpause_-txpause");
		apmib_nvram_set("OP_MODE", "1");
		apmib_nvram_set("DHCP", "0");
		LOG(LOG_INFO, "Repeater 모드[%s]로 변경", wlan_intf==1?"2.4GHz":"5GHz");
	}

	apmib_update_web(CURRENT_SETTING);

	submitUrl = req_get_cstream_var(wp, ("submit-url"), "");   // hidden page
	//OK_MSG(submitUrl);

	need_reboot=1;
	REBOOT_WAIT("/skb_opeate_mode.htm");
	sleep(1);
	dv_reboot_system=1;

	return;

setErr:
	ERR_MSG(tmpBuf);

}

#endif

void formWanTcpipSetup(request *wp, char *path, char *query)
{
	char tmpBuf[100];
	int dns_changed = 0;
	char *arg;
	char *submitUrl;
	int val;

	apmib_set_hist_clear();		/* APACRTL-85 */

	submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page

	if ((val = tcpipWanHandler(wp, tmpBuf, &dns_changed)) < 0)
		goto setErr_end ;
	else if (val == 1) // return ok
		return ;

	web_config_trace(1, 1);	/* wired/internet/ */

	apmib_update_web(CURRENT_SETTING);	// update to flash
	// run script
	if (dns_changed)
		arg = "all";
	else
		arg = "wan";

#ifdef UNIVERSAL_REPEATER
	apmib_get(MIB_REPEATER_ENABLED1, (void *)&val);
	if (val)
		arg = "all";
#endif

#ifdef __DAVO__
	need_reboot = 1;
	OK_MSG("/skb_tcpipwan.htm");
	return;
#endif
#ifndef NO_ACTION
	run_init_script(arg);
#endif
	return;

setErr_end:
	ERR_MSG(tmpBuf);
}
#endif
int checkSameIpOrMac(struct in_addr *IpAddr, unsigned char *macAddr, int entryNum)
{
	if(IpAddr==NULL || macAddr==NULL)
		return 4;
	int i;
	DHCPRSVDIP_T entry;
	struct in_addr start_ip, end_ip, router_ip;

	for (i=1; i<=entryNum; i++)
	{
		*((char *)&entry) = (char)i;
		if(!apmib_get(MIB_DHCPRSVDIP_TBL, (void *)&entry))
		{
			printf("get mib MIB_DHCPRSVDIP_TBL fail!\n");
			return -1;
		}
		if(memcmp(IpAddr, entry.ipAddr, 4)==0)
			return 1;
		if(memcmp(macAddr, entry.macAddr, 6)==0)
			return 2;
	}
	apmib_get(MIB_DHCP_CLIENT_START,  (void *)&start_ip);
	apmib_get(MIB_DHCP_CLIENT_END,  (void *)&end_ip);
	apmib_get(MIB_IP_ADDR,  (void *)&router_ip);

	if(IpAddr->s_addr<start_ip.s_addr || IpAddr->s_addr>end_ip.s_addr || IpAddr->s_addr==router_ip.s_addr)
		return 3;
	return 0;
}
//////////////////////////////////////////////////////////////////////////////
//Static DHCP
void formStaticDHCP(request *wp, char *path, char *query)
{
	char *strStp, *strIp, *strHostName, *strAddRsvIP, *strDelRsvIP, *strDelAllRsvIP, *strVal, *submitUrl;
	char tmpBuf[100];
	char buffer[100];
	int entryNum, i, stp;
	DHCPRSVDIP_T staticIPEntry, delEntry;
	struct in_addr inIp;
	struct in_addr inLanaddr_orig;
	struct in_addr inLanmask_orig;
	int retval;
	strAddRsvIP = req_get_cstream_var(wp, ("addRsvIP"), "");
	strDelRsvIP = req_get_cstream_var(wp, ("deleteSelRsvIP"), "");
	strDelAllRsvIP = req_get_cstream_var(wp, ("deleteAllRsvIP"), "");

//displayPostDate(wp->post_data);
	apmib_set_hist_clear();		/* APACRTL-85 */

	apmib_get( MIB_IP_ADDR,  (void *)buffer); //save the orig lan subnet
	memcpy((void *)&inLanaddr_orig, buffer, 4);

	apmib_get( MIB_SUBNET_MASK,  (void *)buffer); //save the orig lan mask
	memcpy((void *)&inLanmask_orig, buffer, 4);

	// Set static DHCP
	strStp = req_get_cstream_var(wp, ("static_dhcp"), "");
	if (strStp[0]) {
		if (strStp[0] == '0')
			stp = 0;
		else
			stp = 1;
		if ( !apmib_set(MIB_DHCPRSVDIP_ENABLED, (void *)&stp)) {
			strcpy(tmpBuf, ("고정 DHCP mib 설정 오류!"));
			goto setErr_rsv;
		}

		if (apmib_set_hist_search(MIB_DHCPRSVDIP_ENABLED) > -1 && !stp)
			LOG(LOG_INFO, "고정 IP할당 기능을 사용안함");
		if (!stp)
			goto setac_ret;
	}

	if (strAddRsvIP[0] && strDelRsvIP[0] == 0) {
		memset(&staticIPEntry, '\0', sizeof(staticIPEntry));
		strHostName = (char *)req_get_cstream_var(wp, ("hostname"), "");
		if (strHostName[0])
			strcpy((char *)staticIPEntry.hostName, strHostName);
		strIp = req_get_cstream_var(wp,( "ip_addr"), "");
		if (strIp[0]) {
			inet_aton(strIp, &inIp);
			memcpy(staticIPEntry.ipAddr, &inIp, 4);
		}
		strVal = req_get_cstream_var(wp, ("mac_addr"), "");
		if ( !strVal[0] ) {
			strcpy(tmpBuf, ("오류! MAC 주소가 비어 있습니다."));
			goto setac_ret;
		}
		if (strlen(strVal)!=12 || !string_to_hex(strVal, staticIPEntry.macAddr, 12)) {
			strcpy(tmpBuf, ("오류! MAC 주소가 올바르지 않습니다."));
			goto setErr_rsv;
		}
		if ( !apmib_get(MIB_DHCPRSVDIP_TBL_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, ("Get entry number error!"));
			goto setErr_rsv;
		}
		if ( (entryNum + 1) > MAX_DHCP_RSVD_IP_NUM) {
			strcpy(tmpBuf, ("테이블이 모두 차서 더이상 추가할 수 없습니다!"));
			goto setErr_rsv;
		}
		if((inLanaddr_orig.s_addr & inLanmask_orig.s_addr) != (inIp.s_addr & inLanmask_orig.s_addr)){
			strcpy(tmpBuf, ("추가할 수 없습니다. ip가 랜 네트워크 서브넷과 같지 않습니다!"));
			goto setErr_rsv;
		}

		retval=checkSameIpOrMac(&inIp, staticIPEntry.macAddr, entryNum);
		if(retval>0)
		{
			if(retval==1)
				strcpy(tmpBuf, ("오류! 중복 된 IP 주소는 설정 할 수 없습니다."));
			if(retval==2)
				strcpy(tmpBuf, ("오류! 중복 된 MAC은 설정 할 수 없습니다."));
			if(retval==3)
				strcpy(tmpBuf, ("DHCP IP 할당 내역에 맞게 설정 해 주세요."));
			if(retval==4)
				strcpy(tmpBuf, ("The IP and MAC address must be not null!"));

			goto setErr_rsv;
		}

		// set to MIB. try to delete it first to avoid duplicate case
		apmib_set(MIB_DHCPRSVDIP_DEL, (void *)&staticIPEntry);
		if ( apmib_set(MIB_DHCPRSVDIP_ADD, (void *)&staticIPEntry) == 0) {
			strcpy(tmpBuf, ("추가 오류!"));
			goto setErr_rsv;
		} else
			LOG(LOG_INFO, "고정 IP %s을 %s 맥주소 단말에 할당하는 규칙을 추가함",
			    apmib_btoa(IN_ADDR, staticIPEntry.ipAddr),
			    apmib_btoa(ETH_ADDR, staticIPEntry.macAddr));
	}

	/* Delete entry */
	if (strDelRsvIP[0]) {
		if ( !apmib_get(MIB_DHCPRSVDIP_TBL_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, ("읽기 오류!"));
			goto setErr_rsv;
		}
		for (i=entryNum; i>0; i--) {
			snprintf(tmpBuf, 20, "select%d", i);
			memset(&delEntry, '\0', sizeof(delEntry));
			strVal = req_get_cstream_var(wp, tmpBuf, "");
			if ( !strcmp(strVal, "ON") ) {

				*((char *)&delEntry) = (char)i;
				if ( !apmib_get(MIB_DHCPRSVDIP_TBL, (void *)&delEntry)) {
					strcpy(tmpBuf, ("읽기 오류!"));
					goto setErr_rsv;
				}
				if ( !apmib_set(MIB_DHCPRSVDIP_DEL, (void *)&delEntry)) {
					strcpy(tmpBuf, ("삭제 오류!"));
					goto setErr_rsv;
				} else
					LOG(LOG_INFO, "고정 IP %s을 %s 맥주소 단말에 할당하는 규칙을 삭제함",
					    apmib_btoa(IN_ADDR, delEntry.ipAddr),
					    apmib_btoa(ETH_ADDR, delEntry.macAddr));
			}
		}
	}

	/* Delete all entry */
	if ( strDelAllRsvIP[0]) {
		if ( !apmib_set(MIB_DHCPRSVDIP_DELALL, (void *)&staticIPEntry)) {
			strcpy(tmpBuf, ("전체 삭제 오류!"));
			goto setErr_rsv;
		} else
			LOG(LOG_INFO, "고정 IP할당 규칙을 모두 삭제함");
	}

setac_ret:
	apmib_update_web(CURRENT_SETTING);

#ifdef __DAVO__
	submitUrl = req_get_cstream_var(wp, "submit-url", "");   // hidden page
	need_reboot = 1;
	OK_MSG("/skb_tcpip_staticdhcp.htm");
#else
#ifndef NO_ACTION
	run_init_script("all");
#endif
 	return;
#endif
	return;
setErr_rsv:
	ERR_MSG(tmpBuf);
}


int dhcpRsvdIp_List(request *wp, int argc, char **argv)
{
	int	entryNum, i;
	int nBytesSent=0;
	DHCPRSVDIP_T entry;
	char macaddr[30], ipaddr[32];
	char hostName[60];

	apmib_get(MIB_DHCPRSVDIP_TBL_NUM, (void *)&entryNum);
	nBytesSent += req_format_write(wp, ("<tr class=\"tbl_head\">"
      	"<td align=center width=\"30%%\" ><font size=\"2\"><b>IP 주소</b></font></td>\n"
      	"<td align=center width=\"30%%\" ><font size=\"2\"><b>MAC 주소</b></font></td>\n"
      	"<td align=center width=\"30%%\" ><font size=\"2\"><b>설명</b></font></td>\n"
      	"<td align=center width=\"10%%\" ><font size=\"2\"><b>삭제</b></td></tr>\n"));
	for (i=1; i<=entryNum; i++) {
		*((char *)&entry) = (char)i;
		apmib_get(MIB_DHCPRSVDIP_TBL, (void *)&entry);
		if (!memcmp(entry.macAddr, "\x0\x0\x0\x0\x0\x0", 6))
			macaddr[0]='\0';
		else
			sprintf(macaddr," %02x-%02x-%02x-%02x-%02x-%02x", entry.macAddr[0], entry.macAddr[1], entry.macAddr[2], entry.macAddr[3], entry.macAddr[4], entry.macAddr[5]);

		memset(hostName, 0, sizeof(hostName));
		if (entry.hostName) {
			snprintf(hostName, sizeof(hostName), "%s", entry.hostName);
			translate_control_code(hostName);
		}

		nBytesSent += req_format_write(wp, ("<tr class=\"tbl_body\">"
				"<td align=center width=\"30%%\" ><font size=\"2\">%s</td>\n"
				"<td align=center width=\"30%%\" ><font size=\"2\">%s</td>\n"
      			"<td align=center width=\"30%%\" ><font size=\"2\">%s</td>\n"
       			"<td align=center width=\"10%%\" >"
       			"<input type=\"submit\" value=\"삭제\" id=\"deleteSelRsvIP%d\" name=\"deleteSelRsvIP\" onClick=\"return deleteClick('%d')\"></td></tr>\n"),
			inet_ntop(AF_INET, entry.ipAddr, ipaddr, sizeof(ipaddr)) ? : "0.0.0.0", macaddr, hostName, i, i);
	}
	return 0;
}

/////////////////////////////////////////////////////////////////////////////
#ifdef __DAVO__
#define HOST_LEN	64

struct fdb_l2 {
    u_int8_t haddr[6];
    short port;
};

struct leasee {
    struct list_head list;
    struct in_addr yiaddr;
    u_int32_t expires;
    u_int8_t chaddr[6];
    u_int16_t reachable;
    char hostname[HOST_LEN];
};

static int leasee_listup(const char *path, struct list_head *head, int probe)
{
    struct dhcpOfferedAddr lease;
    struct leasee *leasee;
    char *p, *q;
    in_addr_t ip;
    FILE *f;
    int fd, n, count = 0;
    char buf[64];

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;

    while (read(fd, &lease, sizeof(lease)) == sizeof(lease)) {
		if (!lease.expires || !memcmp(lease.chaddr, "\x00\x00\x00\x00\x00\x00", 6))
			continue;
		leasee = (struct leasee *)malloc(sizeof(struct leasee));
		if (leasee == NULL)
			continue;
		leasee->yiaddr.s_addr = lease.yiaddr;
		leasee->expires = lease.expires;
		memcpy(leasee->chaddr, lease.chaddr, 6);
		leasee->reachable = 0;
		snprintf(leasee->hostname, HOST_LEN, "%s", lease.hostname);
		list_add_tail(&leasee->list, head);
		count++;
    }
    close(fd);

	if (!probe || count <= 0)
		return count;

	p = (char *)malloc(count * sizeof(" XXX.XXX.XXX.XXX") + 32);
	n = sprintf(p, "mping -q -p -c 2 -w 1500");
	list_for_each_entry(leasee, head, list)
		n += sprintf(p + n, " %s", inet_ntoa(leasee->yiaddr));
	f = popen(p, "r");
	if (f) {
	    while (fgets(buf, sizeof(buf), f)) {
            q = strchr(buf, ' ');
            if (q == NULL)
                continue;
            *q = '\0';
            ip = inet_addr(buf);
            list_for_each_entry(leasee, head, list)
				if (leasee->yiaddr.s_addr == ip &&
				    ({ leasee->reachable = 1; 1; }))
					break;
	    }
	    pclose(f);
	}
	free(p);
	return count;
}

static struct fdb_l2 *contruct_fdb_l2(size_t *nmemb)
{
	struct fdb_l2 *p = NULL;
	FILE *f;
	int mbr;
	size_t i, size;
	unsigned char haddr[6];

	f = fopen("/proc/rtl865x/l2", "r");
	if (f == NULL)
		return NULL;
	i = size = 0;

    fscanf(f, "%*[^\n]\n");
	while (fscanf(f, "%*[^]]] %hhx:%hhx:%hhx:%hhx:%hhx:%hhx %*[^(](%d %*[^\n]\n",
	              &haddr[0], &haddr[1], &haddr[2],
	              &haddr[3], &haddr[4], &haddr[5], &mbr) >= 6) {
		if (i >= size) {
			struct fdb_l2 *q = realloc(p, sizeof(*p) * (size + 32));
			if (q == NULL)
				break;
			p = q;
			size += 32;
		}
		memcpy(p[i].haddr, haddr, 6);
		p[i].port = mbr;
		i++;
    }
	fclose(f);
	*nmemb = i;
	return p;
}

char *ether_etoa(const unsigned char *e, char *a)
{
	const char *__xascii = "0123456789abcdef";
	char *c = a;
	int i;

	for (i = 0; i < 6; i++) {
		if (i)
			*c++ = ':';
		*c++ = __xascii[(e[i] >> 4) & 0xf];
		*c++ = __xascii[e[i] & 0xf];
	}
	*c = '\0';
	return a;
}

int dhcpClientList(request *wp, int argc, char **argv)
{
    struct leasee *leasee, *t;
    int pid, nelem = 0, n = 0,  opmode, probing;
    char tmp[80], expire[16], port[16], hostname[64] = {0,};
    struct fdb_l2 *fdb = NULL;
    size_t i, ii, nmemb = 0;

    LIST_HEAD(head);

    snprintf(tmp, sizeof(tmp), "%s/%s.pid", _DHCPD_PID_PATH, _DHCPD_PROG_NAME);
	pid = getPid(tmp);
	if (pid > 0) {
		kill(pid, SIGUSR1);
		usleep(500000);
	}

    probing = (argc == 1 && !strcmp(argv[0], "local_ping_test")) ? 1 : 0;
    nelem = leasee_listup(_PATH_DHCPS_LEASES, &head, probing);

    ii = 0;
    list_for_each_entry(leasee, &head, list) {
    	hostname[0] = '\0';
        ether_etoa(leasee->chaddr, tmp);
        if (leasee->expires != -1U)
            snprintf(expire, sizeof(expire), "%u", leasee->expires);
		else
			strcpy(expire, "Always");
		if (probing)
		    n += req_format_write(wp,
					      "<tr bgcolor='%s'>"
					      "<td width=30%%><font size=2>%u.%u.%u.%u<br>[%s]</font></td>\n"
					      "<td width=70%%><font size=2 color='%s'>%s</font></td>"
					      "</tr>\n",
					      (ii & 1) ? "#EEEEEE" : "#DDDDDD",
					      NIPQUAD(leasee->yiaddr.s_addr), tmp,
					      leasee->reachable ? "green" : "red",
					      leasee->reachable ? "정상" : "응답없음");
		else if (argc == 1 && !strcmp(argv[0], "macSelect"))
			n += req_format_write(wp,
					      "<tr class=\"tbl_body\" align=center>"
					      "<td><font size=2>%u.%u.%u.%u</td>"
					      "<td><font size=2>%s</td>"
					      "<td><font size=2>%s</td>"
					      "<td><input type='radio' name='macChecked' value='%s' onClick=macInput('%s')></td>"
					      "</tr>\n",
					      NIPQUAD(leasee->yiaddr.s_addr), tmp, expire, tmp, tmp);
		else if (argc != 1 || strcmp(argv[0], "remnant_dhcpIp")) {
			if (fdb == NULL)
				fdb = contruct_fdb_l2(&nmemb);
			pid = -1;
			for (i = 0; fdb && i < nmemb; i++) {
				if (!memcmp(fdb[i].haddr, leasee->chaddr, 6)) {
					pid = fdb[i].port;
					break;
				}
			}

			if (pid < 0 || pid > 4) {
				if (check_wlan_exist(tmp))
					strcpy(port, "무선");
			} else
				snprintf(port, sizeof(port), "Lan%d", pid + 1);

			snprintf(hostname, sizeof(hostname), "%s", leasee->hostname);

			n += req_format_write(wp,
					      "<tr class=\"tbl_body\" align=center>"
					      "<td><font size=2>%s</td>"
					      "<td><font size=2>%u.%u.%u.%u</td>"
					      "<td><font size=2>%s</td>"
					      "<td><font size=2>%s</td>"
					      "<td><font size=2>%s</td>"
					      "</tr>", port, NIPQUAD(leasee->yiaddr.s_addr), tmp, hostname, expire);
		}
		ii++;
    }

	/* free leasee chains */
	list_for_each_entry_safe(leasee, t, &head, list) {
		list_del(&leasee->list);
		free(leasee);
	}

	// remant_dhcpIP
	if (nelem && argc == 1 && (strcmp(argv[0], "remnant_dhcpIp") == 0)) {
		struct in_addr sip = { .s_addr = 0 }, eip = { .s_addr = 0 };
		unsigned remnant;

		apmib_get(MIB_DHCP_CLIENT_START, (void *)&sip.s_addr);
		apmib_get(MIB_DHCP_CLIENT_END, (void *)&eip.s_addr);
		remnant = (ntohl(eip.s_addr) - ntohl(sip.s_addr) + 1) - nelem;

		if (remnant == 0)
			n += req_format_write(wp, "<font size=2 color='red'>없음</font>\n");
		else
			n += req_format_write(wp, "<font size=2>%lu</font>\n", remnant);
	} else if (argc == 1 && (strcmp(argv[0], "stbMac") == 0))
		n += req_format_write(wp, "_%d", nelem);

err:
	if (nelem == 0) {
		if (argc == 1 && strcmp(argv[0], "remnant_dhcpIp") == 0) {	//remant_dhcpIp
			n += req_format_write(wp, "<font size=2 color='#ff9900'>\n");
			apmib_get(MIB_OP_MODE, (void *)&opmode);
			if (opmode == BRIDGE_MODE)
				n += req_format_write(wp, "HUB 모드 사용중</font>\n");
			else
				n += req_format_write(wp, "DHCP 할당 내역 없음</font>\n");
		} else if (argc == 1 && (strcmp(argv[0], "local_ping_test") == 0)) {
			n += req_format_write(wp, "<tr bgcolor=#DDDDDD><td width=30%%>DHCP</td>\n"
					      "<td width=70%%><font size=2 color='#ff9900'>할당 내역 없음</font></td></tr>\n");
		} else if (argc == 1 && (strcmp(argv[0], "stbMac") == 0)) {
			n += req_format_write(wp, "null");
		} else if (argc == 1 && (strcmp(argv[0], "macSelect") == 0)) {
			n += req_format_write(wp,
					      "<tr class=\"tbl_body\" align=center>"
					      "<td><font size=2>None</td>"
					      "<td><font size=2>----</td>"
					      "<td><font size=2>----</td>"
					      "<td>&nbsp;</td></tr>\n");
		} else {
			n += req_format_write(wp,
					      "<tr class=\"tbl_body\" align=center>"
					      "<td><font size=2>None</td>"
					      "<td><font size=2>----</td>"
					      "<td><font size=2>----</td>"
					      "<td><font size=2>----</td>"
					      "<td><font size=2>----</td>"
					      "</tr>");
		}
	}

	if (fdb)
		free(fdb);

	return n;
}

#else   //#ifdef __DAVO__

int dhcpClientList(request *wp, int argc, char **argv)
{
	FILE *fp;
	int nBytesSent=0;
	int element=0, ret;
	char ipAddr[40], macAddr[40], liveTime[80], *buf=NULL, *ptr, tmpBuf[100], *td_color_flag;
	char hostName[64] = {0,};
	struct stat status;
	int pid, leases_status = 0;
	unsigned long fileSize=0;
	// siganl DHCP server to update lease file
	snprintf(tmpBuf, 100, "%s/%s.pid", _DHCPD_PID_PATH, _DHCPD_PROG_NAME);
	pid = getPid(tmpBuf);
	snprintf(tmpBuf, 100, "kill -SIGUSR1 %d\n", pid);

	if ( pid > 0)
		kill(pid, SIGUSR1);
	usleep(500000);

	if ( stat(_PATH_DHCPS_LEASES, &status) < 0 ) {
		leases_status = 1;
		goto err;
	}

	fileSize=status.st_size;
	buf = malloc(fileSize);
	if ( buf == NULL )
		goto err;
	fp = fopen(_PATH_DHCPS_LEASES, "r");
	if ( fp == NULL )
		goto err;

	fread(buf, 1, fileSize, fp);
	fclose(fp);

	ptr = buf;
	while (1) {
		ret = getOneDhcpClient(&ptr, &fileSize, ipAddr, macAddr, liveTime, hostName);

		if (ret < 0)
			break;
		if (ret == 0)
			continue;
		if (argc == 1 && (strcmp(argv[0], "remnant_dhcpIp") == 0)) {
			element++;
			continue;
		} else if (argc == 1 && (strcmp(argv[0], "local_ping_test") == 0)) {
			if ((element % 2) == 0)
				td_color_flag = "#DDDDDD";
			else
				td_color_flag = "#EEEEEE";

			if (send_ping_test(ipAddr) > 0)
				nBytesSent += req_format_write(wp,
							"<tr bgcolor='%s'><td width=30%%><font size=2>%s<br>[%s]</font></td>\n"
							  "<td width=70%%><font size=2 color='green'>정상</font></td></tr>\n",
							td_color_flag, ipAddr, macAddr);
			else
				nBytesSent += req_format_write(wp,
							"<tr bgcolor='%s'><td width=30%%><font size=2>%s<br>[%s]</td></td>\n"
							  "<td width=70%%><font size=2 color='red'>응답없음</font></td></tr>\n",
							td_color_flag, ipAddr, macAddr);
		} else if (argc == 1 && (strcmp(argv[0], "macSelect") == 0)) {
			nBytesSent += req_format_write(wp,
				("<tr class=\"tbl_body\" align=center><td><font size=2>%s</td><td><font size=2>%s</td><td><font size=2>%s</td><td><input type='radio' name='macChecked' value='%s' onClick=macInput('%s')></td></tr>\n"),
				ipAddr, macAddr, liveTime, macAddr, macAddr);
		} else {
			int lan_port_num = 0;
			char port_name[20];

			lan_port_num = check_lan(macAddr);
			if (0 <= lan_port_num && lan_port_num <= 3) {
				snprintf(port_name, sizeof(port_name), "Lan%d", lan_port_num + 1);
				nBytesSent += req_format_write(wp,
						("<tr class=\"tbl_body\" align=center><td><font size=2>%s</td><td><font size=2>%s</td><td><font size=2>%s</td><td><font size=2>%s</td></tr>"),
						port_name, ipAddr, macAddr, liveTime);
/* APACRTL-100 */
			} else if (check_wlan_exist(macAddr)) {
				snprintf(port_name, sizeof(port_name), "무선");
				nBytesSent += req_format_write(wp,
						("<tr class=\"tbl_body\" align=center><td><font size=2>%s</td><td><font size=2>%s</td><td><font size=2>%s</td><td><font size=2>%s</td></tr>"),
						port_name, ipAddr, macAddr, liveTime);
			}
		}
		element++;
	}
// remant_dhcpIP
	if (element && argc == 1 && (strcmp(argv[0], "remnant_dhcpIp") == 0)) {
		unsigned char temp_Ip[16];
		unsigned long start_ip = 0, end_ip = 0;
		unsigned long remnant_ip = 0;

		if (!apmib_get(MIB_DHCP_CLIENT_END, (void *)temp_Ip))
			goto err;

		end_ip = (temp_Ip[0] & 255) << 24;
		end_ip += (temp_Ip[1] & 255) << 16;
		end_ip += (temp_Ip[2] & 255) << 8;
		end_ip += temp_Ip[3] & 255;

		if (!apmib_get(MIB_DHCP_CLIENT_START, (void *)temp_Ip))
			goto err;

		start_ip = (temp_Ip[0] & 255) << 24;
		start_ip += (temp_Ip[1] & 255) << 16;
		start_ip += (temp_Ip[2] & 255) << 8;
		start_ip += temp_Ip[3] & 255;

		remnant_ip = ((end_ip - start_ip) + 1) - (unsigned long)element;

		if (remnant_ip == 0)
			nBytesSent += req_format_write(wp, "<font size=2 color='red'>없음</font>\n");
		else
			nBytesSent += req_format_write(wp, "<font size=2>%lu</font>\n", remnant_ip);
	} else if (argc == 1 && (strcmp(argv[0], "stbMac") == 0)) {
		nBytesSent += req_format_write(wp, "_%d", element);
	}
err:
	if (element == 0) {
		if (argc == 1 && strcmp(argv[0], "remnant_dhcpIp") == 0) {	//remant_dhcpIp
			nBytesSent += req_format_write(wp, "<font size=2 color='#ff9900'>\n");
			if (leases_status == 1)
				nBytesSent += req_format_write(wp, "HUB 모드 사용중</font>\n");
			else
				nBytesSent += req_format_write(wp, "DHCP 할당 내역 없음</font>\n");
		} else if (argc == 1 && (strcmp(argv[0], "local_ping_test") == 0)) {
				nBytesSent += req_format_write(wp,
							"<tr bgcolor=#DDDDDD><td width=30%%>DHCP</td>\n"
							  "<td width=70%%><font size=2 color='#ff9900'>할당 내역 없음</font></td></tr>\n");
		} else if (argc == 1 && (strcmp(argv[0], "stbMac") == 0)) {
				nBytesSent += req_format_write(wp, "null");
		} else if (argc == 1 && (strcmp(argv[0], "macSelect") == 0)) {
			nBytesSent += req_format_write(wp,
			("<tr  class=\"tbl_body\" align=center><td><font size=2>None</td><td><font size=2>----</td><td><font size=2>----</td><td>&nbsp;</td></tr>\n"));
		} else {
			nBytesSent += req_format_write(wp,
			("<tr class=\"tbl_body\" align=center><td><font size=2>None</td><td><font size=2>----</td><td><font size=2>----</td></tr>"));
		}
	}
	if (buf)
		free(buf);

	return nBytesSent;
}
#endif
/////////////////////////////////////////////////////////////////////////////
void formReflashClientTbl(request *wp, char *path, char *query)
{
	char *submitUrl;

	submitUrl = req_get_cstream_var(wp, "submit-url", "");
	if (submitUrl[0])
		send_redirect_perm(wp, "/skb_dhcptbl.htm");
}


//////////////////////////////////////////////////////////////////////////////
int isDhcpClientExist(char *name)
{
	char tmpBuf[100];
	struct in_addr intaddr;

	if ( getInAddr(name, IP_ADDR, (void *)&intaddr ) ) {
		snprintf(tmpBuf, 100, "%s/%s-%s.pid", _DHCPC_PID_PATH, _DHCPC_PROG_NAME, name);
		if ( getPid(tmpBuf) > 0)
			return 1;
	}
	return 0;
}

int show_ipv4_information(request *wp, int argc, char **argv)
{
	char *p, *s = NULL;
	int i;
	int nBytesSent = 0;

	s = INETx_getdns(AF_INET);
	for (i = 0, p = s; p && *p; p += (strlen(p) + 1), i++) {
		nBytesSent += req_format_write(wp, "<tr bgcolor=\"%s\">\\n"
							"<td width=30%%><font size=2><b>%s</b></td>\\n"
							"<td width=70%%><font size=2>%s</td>\\n"
							"</tr>\\n", TD_COLOR(0), (i==0)? "DNS 서버":"", p);
	}
	if (s)
		free(s);

	return nBytesSent;
}
