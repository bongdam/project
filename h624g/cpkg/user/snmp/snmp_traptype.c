#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/errno.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <netdb.h>
#include <wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
/*DAVO begin*/
#include <syslog.h>
/*DAVO end*/
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include "snmp_main.h"
#include "skbb_api.h"
#include "snmp_trap.h"
#include "skbb.h"
#include "snmp_response.h"
#include "./engine/asn1.h"
#include "./engine/snmp.h"
#include "./engine/agt_engine.h"
#include "./engine/snmp_community.h"
#include "defines.h"
#include <bcmnvram.h>
#include "misc.h"
#include "snmp_traptype.h"
#include <sys/sysinfo.h>
#include <libytool.h>

static char *getsvrip_dnsquery(char *ip_url, char *tell_ip, int len, const char *logstr);

extern int autochan_get_bandwidth(void);
extern int getWlBssInfo(char *interface, bss_info *pInfo);
/****************************************************************************
TRAP#1 BASIC TRAP
*Trigger
a. After systerm rebooting
b. Every 3 hours, send trap
c. When ip (re)assigned.
*****************************************************************************
*/
void *sendAutoTransmission(void)
{
	int out_length = SNMP_MAX_MSG_LENGTH;
	unsigned char string_return[80];
	long long_return = 0;
	unsigned char *out_data;
	char buf[12], trap_svr[80];
	int ipaddr;

	oid trap_oid[MAX_SNMP_OID];
	raw_snmp_info_t message;
	Oid oid_obj;
	oid oid_coldStart[] = { O_coldStart };
#if 0
	oid oid_snmpTrap[] = { O_snmpTrapOID};
	oid oid_autoTransmission[] = { O_autoTransmission };
#else
	oid oid_snmpTrapEnterprise[] = { O_snmpTrapEnterprise };
	oid oid_skbb[] = { O_skbb };
#endif
	//oid oid_sysObjectID[] = { O_sysObjectID };
	oid oid_modelName[] = { O_modelName };
	oid oid_version[] = { O_version };
	oid oid_wanIpAddress[] = { O_wanIpAddress };
	oid oid_mac[] = { O_wanMacAddress };
	oid oid_cpu[] = { O_CPU_Utilization };
	oid oid_ram[] = { O_RAM_Utilization };
	oid oid_flash[] = { O_Flash_Utilization };
	oid oid_uptime[] = { O_sysUptime };
	oid oid_wlan1mac[] = { O_WlanMacAddress_2g };
	oid oid_wlan0mac[] = { O_WlanMacAddress_5g };
	oid oid_lanmac[] = { O_lanMacAddress };
	oid oid_opmode[] = { O_DevicePortMode };
	oid oid_passThru[] = { O_Ipv6PassThru };

	memset((unsigned char *)&message, 0x00, sizeof(message));

	// build sendAutoTransmission header
	out_data =
		make_trap_v2c_headr(&message, &out_length, oid_coldStart,
							sizeof(oid_coldStart));
	RETURN_ON_BUILD_ERROR(out_data,
						  "make_trap_v2c_headr - send restart trap");
	// oid_snmpTrap
#if 0
	memset(&oid_obj, 0, sizeof(oid_obj));
	oid_obj.namelen = sizeof(oid_snmpTrap) / sizeof(oid);
	memcpy(oid_obj.name, oid_snmpTrap, sizeof(oid_snmpTrap));
	oid_obj.name[oid_obj.namelen] = 0;
	oid_obj.namelen += 1;

	long_return = 1;
	{
		int i;
		for (i = 0; i < sizeof(oid_autoTransmission); i++) {
			trap_oid[i] = oid_autoTransmission[i];
		}
		trap_oid[i] = 0;
	}
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OBJECT_ID,
								  sizeof(oid_autoTransmission) + 1,
								  (unsigned char *)trap_oid, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_manufacturer error");
#else
	// oid_snmpTrapEnterprise
	memset(&oid_obj, 0, sizeof(oid_obj));
	oid_obj.namelen = sizeof(oid_snmpTrapEnterprise) / sizeof(oid);
	memcpy(oid_obj.name, oid_snmpTrapEnterprise,
		   sizeof(oid_snmpTrapEnterprise));
	oid_obj.name[oid_obj.namelen] = 0;
	oid_obj.namelen += 1;
	long_return = 1;
	{
		int i;
		for (i = 0; i < sizeof(oid_skbb); i++) {
			trap_oid[i] = oid_skbb[i];
		}
		trap_oid[i] = 0;
	}
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OBJECT_ID,
								  sizeof(oid_skbb) + 1,
								  (unsigned char *)trap_oid, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_manufacturer error");

#endif
	// build sendAutoTransmission body
	//oid_wanIpAddress
	long_return = 0;
	get_wanIpAddress(&long_return, NON_STRING_TYPE);
	oid_obj.namelen = sizeof(oid_wanIpAddress) / sizeof(oid);
	memcpy(oid_obj.name, oid_wanIpAddress, sizeof(oid_wanIpAddress));

	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
								  sizeof(long),
								  (unsigned char *)&long_return,
								  &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_wanIpAddress error");

	//oid_wanMacAddress
	memset(string_return, 0, sizeof(string_return));
	get_mac(string_return, 6);
	oid_obj.namelen = sizeof(oid_mac) / sizeof(oid);
	memcpy(oid_obj.name, oid_mac, sizeof(oid_mac));
	long_return = 1;

	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
								  6, (unsigned char *)string_return,
								  &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_mac error");

	//oid_wlan1MacAddress
	memset(string_return, 0, sizeof(string_return));
	get_wlanMac(string_return, 1);
	oid_obj.namelen = sizeof(oid_wlan1mac) / sizeof(oid);
	memcpy(oid_obj.name, oid_wlan1mac, sizeof(oid_wlan1mac));
	long_return = 1;

	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
								  6, (unsigned char *)string_return,
								  &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_wlan1mac error");

	//oid_wlan0MacAddress
	memset(string_return, 0, sizeof(string_return));
	get_wlanMac(string_return, 0);
	oid_obj.namelen = sizeof(oid_wlan0mac) / sizeof(oid);
	memcpy(oid_obj.name, oid_wlan0mac, sizeof(oid_wlan0mac));
	long_return = 1;

	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
								  6, (unsigned char *)string_return,
								  &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_wlan0mac error");

	//oid_LanMacAddress
	memset(string_return, 0, sizeof(string_return));
	get_lanMac((char *)string_return, sizeof(string_return));
	oid_obj.namelen = sizeof(oid_lanmac) / sizeof(oid);
	memcpy(oid_obj.name, oid_lanmac, sizeof(oid_lanmac));
	long_return = 1;

	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
								  6, (unsigned char *)string_return,
								  &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_lanmac error");

	//oid_modelName
	memset(string_return, 0, sizeof(string_return));
	get_modelName(string_return, sizeof(string_return));
	oid_obj.namelen = sizeof(oid_modelName) / sizeof(oid);
	memcpy(oid_obj.name, oid_modelName, sizeof(oid_modelName));
	long_return = 1;
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
								  strlen(string_return),
								  (unsigned char *)string_return,
								  &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_modelName error");

	//oid_version
	memset(string_return, 0, sizeof(string_return));
	get_version(string_return, 80);
	oid_obj.namelen = sizeof(oid_version) / sizeof(oid);
	memcpy(oid_obj.name, oid_version, sizeof(oid_version));
	long_return = 1;
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
								  strlen(string_return),
								  (unsigned char *)string_return,
								  &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_version error");

	//long get_cpu_utiliz(void)
	long_return = get_cpu_utiliz();
	oid_obj.namelen = sizeof(oid_cpu) / sizeof(oid);
	memcpy(oid_obj.name, oid_cpu, sizeof(oid_cpu));

	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
								  sizeof(long),
								  (unsigned char *)&long_return,
								  &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_cpu error");

	//long get_ram_utiliz(void)
	long_return = get_ram_utiliz();
	oid_obj.namelen = sizeof(oid_ram) / sizeof(oid);
	memcpy(oid_obj.name, oid_ram, sizeof(oid_ram));

	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
								  sizeof(long),
								  (unsigned char *)&long_return,
								  &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_ram error");

	//long get_flash_utiliz(void)
	long_return = get_flash_utiliz();
	oid_obj.namelen = sizeof(oid_flash) / sizeof(oid);
	memcpy(oid_obj.name, oid_flash, sizeof(oid_flash));

	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
								  sizeof(long),
								  (unsigned char *)&long_return,
								  &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_flash error");

	//long get_devicePortMode(void)
	long_return = get_devicePortMode();
	oid_obj.namelen = sizeof(oid_opmode) / sizeof(oid);
	memcpy(oid_obj.name, oid_opmode, sizeof(oid_opmode));

	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long),
			(unsigned char *)&long_return,
			&out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_opmode error");

	//long get_Ipv6PassThruMode(void)
	long_return = get_Ipv6PassThruMode();
	oid_obj.namelen = sizeof(oid_passThru) / sizeof(oid);
	memcpy(oid_obj.name, oid_passThru, sizeof(oid_passThru));

	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long),
			(unsigned char *)&long_return,
			&out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_passThru error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	nvram_get_r_def("x_SNMP_TRAP_SERVER", trap_svr, sizeof(trap_svr), "iptvsh-trap.skbroadband.com");
	getsvrip_dnsquery(trap_svr, dvsnmp_cfg.trapserver[0], sizeof(dvsnmp_cfg.trapserver), BASIC_TRAP);

	if(!strcmp(dvsnmp_cfg.trapserver[0], "0.0.0.0"))
		syslog(LOG_NOTICE, "SNMP: Trap Server DNS Query Failed (%s)\n", BASIC_TRAP);
	else
		snmp_send_trap(&message, dvsnmp_cfg.trapserver[0], (unsigned short)strtoul(nvram_get_r_def("x_snmp_trap_port", buf, sizeof(buf), "162"), NULL, 10), BASIC_TRAP);

	return (out_data);
}


/****************************************************************************
TRAP#2 WIFI TRAP
*Trigger
When connecting or disconnecting STA to AP.
*****************************************************************************
*/
void *send_wlall_status_trap(char *msg, int msglen, char *trap_name)
{
	char buf[256];
	int out_length = SNMP_MAX_MSG_LENGTH;
	unsigned char *out_data = NULL;
	raw_snmp_info_t message;
	unsigned int ipaddr;
	static char wlsta_trap_server[80];
	static int port;
	in_addr_t addr;

	Oid oid_obj;
	oid oid_smartphone[] = { O_ConnectInfoEntry };
	oid oid_smartphone_leaf[] = { O_ConnectStauts };

	memset((unsigned char *)&message, 0x00, sizeof(message));
	// build sendAutoTransmission header
	out_data = make_trap_v2c_headr(&message, &out_length, oid_smartphone, sizeof(oid_smartphone));
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_v2c_headr - send Smart Phone Trap");

	// build sendAutoTransmission body
	//oid_wanIpAddress
	oid_obj.namelen = sizeof(oid_smartphone_leaf) / sizeof(oid);
	memcpy(oid_obj.name, oid_smartphone_leaf, sizeof(oid_smartphone_leaf));

	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR, msglen, (unsigned char *)msg, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_wanIpAddress error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	if (access("/var/tmp/trap2", F_OK) != 0) {
		nvram_get_r_def("x_WIFI_TRAP_PORT", buf, sizeof(buf), "162");
		port = atoi(buf);
		nvram_get_r_def("x_WIFI_TRAP_SERVER", buf, sizeof(buf), "iptvap-trap.skbroadband.com");
		getsvrip_dnsquery(buf, wlsta_trap_server, sizeof(wlsta_trap_server), WIFI_ON_TRAP);
		yecho("/var/tmp/trap2", "%s\n", wlsta_trap_server);
	} else {
		read_ip("/var/tmp/trap2", &addr, wlsta_trap_server);
	}
	if (!strcmp(wlsta_trap_server, "0.0.0.0"))
		syslog(LOG_NOTICE, "SNMP: Trap Server DNS Query Failed (%s)\n", trap_name);
	else
		snmp_send_trap(&message, wlsta_trap_server, port, trap_name);

	return (out_data);
}

/****************************************************************************
TRAP#3 CPE PING TRAP
*Trigger
Every 3hours, check cpe-device by ping under the AP(LAN PORT).
*****************************************************************************
*/

void *send_cpeping_status_trap(char *msg, int msglen)
{
	char buf[256];
	int out_length = SNMP_MAX_MSG_LENGTH;
	unsigned char *out_data;
	unsigned char string_return[6];
	raw_snmp_info_t message;
	static char cpe_trap_server[80];
	int port;
	int n, buffer_len;
	char buffer[1500];
	time_t _time;
	struct tm *ptm;

	Oid oid_obj;
	oid oid_cpeiping[] = { O_CpepingEntryTrap };
	oid oid_cpeiping_leaf[] = { O_CpepingEntryTrapLeaf };

	n = 0;
	buffer_len = sizeof(buffer);
	if ( !(ptm = get_trapevent_time(&_time, 0)) )
		return NULL;

	memset((unsigned char *)&message, 0x00, sizeof(message));
	// build cpepingtrap header
	out_data = make_trap_v2c_headr(&message, &out_length, oid_cpeiping,	sizeof(oid_cpeiping));
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_v2c_headr - send cpeping Trap");

	// build cpepingtrap body
	// oid_cpepingleaf
	n = snprintf(&buffer[n], buffer_len-n,  "evt-time=%04d-%02d-%02d %02d:%02d:%02d\r\n", (ptm->tm_year) + 1900, (ptm->tm_mon) + 1, ptm->tm_mday,
																  		ptm->tm_hour, ptm->tm_min, ptm->tm_sec);

	get_mac(string_return, 6);
	n += snprintf(&buffer[n], buffer_len-n, "ap-mac=%02x%02x%02x%02x%02x%02x\r\n", string_return[0], string_return[1], string_return[2],
																		string_return[3], string_return[4], string_return[5]);

	n += snprintf(&buffer[n], buffer_len-n, "%s", msg);

	oid_obj.namelen = sizeof(oid_cpeiping_leaf) / sizeof(oid);
	memcpy(oid_obj.name, oid_cpeiping_leaf, sizeof(oid_cpeiping_leaf));

	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR, n, (unsigned char *)buffer, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_cpepingleaf error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	nvram_get_r_def("x_cpeping_trap_server", buf, sizeof(buf), "iptvap-trap3.skbroadband.com");
	getsvrip_dnsquery(buf, cpe_trap_server, sizeof(cpe_trap_server), CPEPING_TRAP);

	buf[0] = 0;
	nvram_get_r_def("snmp_cpe_trap_port", buf, sizeof(buf), "162");
	port = atoi(buf);

	if(!strcmp(cpe_trap_server, "0.0.0.0"))
		syslog(LOG_NOTICE, "SNMP: Trap Server DNS Query Failed (%s)\n", CPEPING_TRAP);
	else
		snmp_send_trap(&message, cpe_trap_server, port, CPEPING_TRAP);

	return (out_data);
}

/****************************************************************************
TRAP#4 AUTO REBOOT TRAP
*Trigger
Send trap befor triggering auto-reboot.
*****************************************************************************
*/

void *sendAutoRebootTrap(unsigned long wan_crc, char *f_reason)
{
	int out_length = SNMP_MAX_MSG_LENGTH;
	unsigned char string_return[6];
	unsigned char *out_data;
	static char autoreboot_trap_server[64];
	char trap_svr[64], buf[12];
	raw_snmp_info_t message;
	unsigned int ipaddr;
	int port;
	int n, msglen;
	char msg[512];
	time_t _time;
	struct tm *ptm;

	Oid oid_obj;
	oid oid_autoreboot[] = { O_AutoReootTrap };
	oid oid_autoreboot_leaf[] = { O_AutoReootTrapLeaf };

	n=0;
	msglen = sizeof(msg);
	if ( !(ptm = get_trapevent_time(&_time, 0)) )
		return NULL;
	memset((unsigned char *)&message, 0x00, sizeof(message));

	// build sendAutoTransmission header
	out_data =
		make_trap_v2c_headr(&message, &out_length, oid_autoreboot,
							sizeof(oid_autoreboot));
	RETURN_ON_BUILD_ERROR(out_data,
						  "make_trap_v2c_headr - send auto_reboot trap");

	// build autoreboottrap body
	// oid_autoreboot_leaf
	n = snprintf(&msg[n], msglen-n,  "evt-time=%04d-%02d-%02d %02d:%02d:%02d\r\n", (ptm->tm_year)+1900, (ptm->tm_mon)+1, ptm->tm_mday,
																	  ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
	get_mac(string_return, 6);
	n += snprintf(&msg[n], msglen-n, "ap-mac=%02x%02x%02x%02x%02x%02x\r\n", string_return[0], string_return[1], string_return[2],
																		string_return[3], string_return[4], string_return[5]);

	n += snprintf(&msg[n], msglen-n, "wan_crc=%lu\r\n", wan_crc);

	if (f_reason[0])
		n += snprintf(&msg[n], msglen-n, "fail=%s\r\n", f_reason);


	oid_obj.namelen = sizeof(oid_autoreboot_leaf) / sizeof(oid);
	memcpy(oid_obj.name, oid_autoreboot_leaf, sizeof(oid_autoreboot_leaf));
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR, n, (unsigned char *)msg, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_autoreboot_leaf error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	nvram_get_r_def("x_autoreboot_trap_server", trap_svr, sizeof(trap_svr), "iptvap-trap4.skbroadband.com");
	getsvrip_dnsquery(trap_svr, autoreboot_trap_server, sizeof(autoreboot_trap_server), AUTOREBOOT_TRAP);
	nvram_get_r_def("x_WIFI_TRAP_PORT", buf, sizeof(buf), "162");
	port = atoi(buf);

	if(!strcmp(autoreboot_trap_server, "0.0.0.0"))
		syslog(LOG_NOTICE, "SNMP: Trap Server DNS Query Failed (%s)\n", AUTOREBOOT_TRAP);
	else
		snmp_send_trap(&message, autoreboot_trap_server, port, AUTOREBOOT_TRAP);
	return (out_data);
}

/****************************************************************************
TRAP#5 PORT LINK TRAP
*Trigger
When occuring port event(down/up), send trap.
ex)
evt-time=2012-02-08 11:00:23
ap-mac=001122334455
port=WAN (��Ʈ ���� : WAN, LAN1, LAN2, LAN3, LAN4)
evt-type=ON  (�̺�Ʈ ��� �� :  ON, OFF)
cpe-mac=001122334455
*****************************************************************************
portinfo =

xxxx  x  x  x  x
      ^  ^  ^  ^
     link port index
mask 0xf
*/
extern char *DevPortName[];
#define LINKPORTMASK	0x7
#define LINKEVTMASK		0x8
void *sendPortLinkTrap(unsigned char portinfo)
{
	int out_length = SNMP_MAX_MSG_LENGTH;
	unsigned char string_return[6];
	unsigned char *out_data;
	char portlink_trap_server[64];
	char trap_svr[64], buf[12];
	raw_snmp_info_t message;
	unsigned int ipaddr;
	int port;
	int i, n, msglen;
	char msg[512];
	time_t _time;
	struct tm *ptm;
	int portindex, event, found =0;
	unsigned char cpeMac[6], cpeMacstr[30];
	Oid oid_obj;
	oid oid_portlink_root[] = { O_PortLinkTrapRoot };
	oid oid_portlink_leaf[] = { O_PortLinkTrapLeaf };

	event = ((portinfo&LINKEVTMASK))?1:0;
	portindex = (portinfo&LINKPORTMASK)-1;

	if ( portindex >= MAX_PORT) {
		syslog(LOG_INFO, "PORTLINK_TRAP: port index(%d) error\n", portindex);
		return 0;
	}

	if ( portindex < 4 ){
		if ( !(n=initHostInfo()) )
			return 0;

		for ( i =0; i < n; i++) {
			if ( (portindex+1) == get_hostInfoPortNumber(i) ) {
				get_hostInfoMacAddr(i, cpeMac);
				if ( !is_valid_ether_addr(cpeMac) )
					continue;
				found = 1;
				break;
			}
		}
	}
	if (portindex != 4 && !found)
		return 0;
	n=0;
	msglen = sizeof(msg);
	if ( !(ptm = get_trapevent_time(&_time, 10)) )
		return NULL;
	memset((unsigned char *)&message, 0x00, sizeof(message));
	msg[0] = 0;
	// build header
	out_data = make_trap_v2c_headr(&message, &out_length, oid_portlink_root, sizeof(oid_portlink_root));
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_v2c_headr - send port link trap");

	// build body
	n = snprintf(&msg[n], msglen-n,  "evt-time=%04d-%02d-%02d %02d:%02d:%02d\r\n", (ptm->tm_year)+1900, (ptm->tm_mon)+1, ptm->tm_mday,
																	  ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
	get_mac(string_return, 6);
	n += snprintf(&msg[n], msglen-n, "ap-mac=%02x%02x%02x%02x%02x%02x\r\n", string_return[0], string_return[1], string_return[2],
																		string_return[3], string_return[4], string_return[5]);
	n += snprintf(&msg[n], msglen-n, "port=%s\r\n", DevPortName[portindex]);
	n += snprintf(&msg[n], msglen-n, "evt-type=%s\r\n", ((event)?"ON":"OFF"));

	cpeMacstr[0] = 0;
	if ( portindex != 4 )
		sprintf(&cpeMacstr[0], "%02x%02x%02x%02x%02x%02x",
					(unsigned int)cpeMac[0], (unsigned int)cpeMac[1], (unsigned int)cpeMac[2],
					(unsigned int)cpeMac[3], (unsigned int)cpeMac[4], (unsigned int)cpeMac[5]);

	n += snprintf(&msg[n], msglen-n, "cpe-mac=%s\r\n", &cpeMacstr[0]);

	oid_obj.namelen = sizeof(oid_portlink_leaf) / sizeof(oid);
	memcpy(oid_obj.name, oid_portlink_leaf, sizeof(oid_portlink_leaf));
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR, n, (unsigned char *)msg, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_portlink_leaf error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	nvram_get_r_def("x_portlink_trap_server", trap_svr, sizeof(trap_svr), "iptvap-trap5.skbroadband.com");
	getsvrip_dnsquery(trap_svr, portlink_trap_server, sizeof(portlink_trap_server), PORTLINK_TRAP);
	nvram_get_r_def("x_WIFI_TRAP_PORT", buf, sizeof(buf), "162");
	port = atoi(buf);

	if(!strcmp(portlink_trap_server, "0.0.0.0"))
		syslog(LOG_NOTICE, "SNMP: Trap Server DNS Query Failed (%s)\n", PORTLINK_TRAP);
	else
		snmp_send_trap(&message, portlink_trap_server, port, PORTLINK_TRAP);

	return (out_data);
}

/****************************************************************************
TRAP#6 Session TRAP (wired/wireless)
*Trigger
Over limited session(wired/wirelss) TRAP
ex)
evt-time=2012-02-08 11:00:23
ap-mac=001122334455
wifi-session-val=9
wifi-session-limit=10
wan-bitrate-val=12
wan-bitrate-limit=12.5
wan-pps-val=250
*****************************************************************************
*/
void *sendLimitedSessionTrap(int wifi_session, int wifi_session_total, char *wan_bitrate, char *wlan_bitrate)
{
	int out_length = SNMP_MAX_MSG_LENGTH;
	unsigned char string_return[6];
	unsigned char *out_data;
	char portlink_trap_server[64];
	char trap_svr[64], buf[12];
	raw_snmp_info_t message;
	unsigned int ipaddr;
	int port;
	int n, msglen;
	char msg[512];
	time_t _time;
	struct tm *ptm;
	double wan_kpps;

	Oid oid_obj;
	oid oid_limitsession_root[] = { O_LimitSessionTrapRoot };
	oid oid_limitsession_leaf[] = { O_LimitSessionTrapLeaf };

	n=0;
	msglen = sizeof(msg);
	if ( !(ptm = get_trapevent_time(&_time, 0)) )
		return NULL;
	memset((unsigned char *)&message, 0x00, sizeof(message));
	msg[0] = 0;
	// build header
	out_data = make_trap_v2c_headr(&message, &out_length, oid_limitsession_root, sizeof(oid_limitsession_root));
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_v2c_headr - send limited session trap");

	// build body
	n = snprintf(&msg[n], msglen-n,  "evt-time=%04d-%02d-%02d %02d:%02d:%02d\r\n",
				(ptm->tm_year)+1900, (ptm->tm_mon)+1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
	get_mac(string_return, 6);
	n += snprintf(&msg[n], msglen-n, "ap-mac=%02x%02x%02x%02x%02x%02x\r\n",
				string_return[0], string_return[1], string_return[2], string_return[3], string_return[4], string_return[5]);
	n += snprintf(&msg[n], msglen-n, "wifi-session-val=%d\r\n", wifi_session);

	n += snprintf(&msg[n], msglen-n, "wifi-session-limit=%d\r\n", wifi_session_total);

	n += snprintf(&msg[n], msglen-n, "wan-bitrate-val=%s\r\n", wan_bitrate);

	n += snprintf(&msg[n], msglen-n, "wan-bitrate-limit=%s.0\r\n",
				nvram_get_r_def("x_snmp_wireslimit", buf, sizeof(buf), "80"));

	// 1Mbps -> 1488pps -> 1.48Kpps
	wan_kpps = atoi(wan_bitrate) * 1.48;
	n += snprintf(&msg[n], msglen-n, "wan-pps-val=%.1f\r\n", wan_kpps);

	n += snprintf(&msg[n], msglen-n, "wifi-bitrate-val=%s\r\n", wlan_bitrate);

	oid_obj.namelen = sizeof(oid_limitsession_leaf) / sizeof(oid);
	memcpy(oid_obj.name, oid_limitsession_leaf, sizeof(oid_limitsession_leaf));
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR, n, (unsigned char *)msg, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_limitsession_leaf error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	nvram_get_r_def("x_limitedSession_trap_server", trap_svr, sizeof(trap_svr), "iptvap-trap6.skbroadband.com");
	getsvrip_dnsquery(trap_svr, portlink_trap_server, sizeof(portlink_trap_server), LIMITEDSEESION_TRAP);
	nvram_get_r_def("x_WIFI_TRAP_PORT", buf, sizeof(buf), "162");
	port = atoi(buf);

	if(!strcmp(portlink_trap_server, "0.0.0.0"))
		syslog(LOG_NOTICE, "SNMP: Trap Server DNS Query Failed (%s)\n", LIMITEDSEESION_TRAP);
	else
		snmp_send_trap(&message, portlink_trap_server, port, LIMITEDSEESION_TRAP);

	return (out_data);
}

/****************************************************************************
TRAP#7 Smart Reset TRAP (wireless)
*Trigger
When triggering smart reset.
ex)
evt-time=2012-02-08 11:00:23
ap-mac=001122334455
*****************************************************************************
*/
void *sendSmartResetTrap(char *f_reason)
{
	int out_length = SNMP_MAX_MSG_LENGTH;
	unsigned char string_return[6];
	unsigned char *out_data;
	char trap_server[64];
	char trap_svr[64], buf[12];
	raw_snmp_info_t message;
	unsigned int ipaddr;
	int port;
	int n, msglen;
	char msg[512];
	time_t _time;
	struct tm *ptm;

	Oid oid_obj;
	oid oid_smartReset_root[] = { O_SmartResetTrapRoot };
	oid oid_smartReset_leaf[] = { O_SmartResetTrapLeaf };

	n=0;
	msglen = sizeof(msg);
	if ( !(ptm = get_trapevent_time(&_time, 0)) )
		return NULL;
	memset((unsigned char *)&message, 0x00, sizeof(message));
	msg[0] = 0;
	// build header
	out_data = make_trap_v2c_headr(&message, &out_length, oid_smartReset_root, sizeof(oid_smartReset_root));
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_v2c_headr - send smartReset trap");

	// build body
	n = snprintf(&msg[n], msglen-n,  "evt-time=%04d-%02d-%02d %02d:%02d:%02d\r\n",
				(ptm->tm_year)+1900, (ptm->tm_mon)+1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
	get_mac(string_return, 6);
	n += snprintf(&msg[n], msglen-n, "ap-mac=%02x%02x%02x%02x%02x%02x\r\n",
				string_return[0], string_return[1], string_return[2], string_return[3], string_return[4], string_return[5]);

	if (f_reason[0])
		n += snprintf(&msg[n], msglen-n, "fail=%s\r\n", f_reason);

	oid_obj.namelen = sizeof(oid_smartReset_leaf) / sizeof(oid);
	memcpy(oid_obj.name, oid_smartReset_leaf, sizeof(oid_smartReset_leaf));
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR, n, (unsigned char *)msg, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_smartReset_leaf error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	nvram_get_r_def("x_smartReset_trap_server", trap_svr, sizeof(trap_svr), "iptvap-trap7.skbroadband.com");
	getsvrip_dnsquery(trap_svr, trap_server, sizeof(trap_server), SMARTRESET_TRAP);
	nvram_get_r_def("x_WIFI_TRAP_PORT", buf, sizeof(buf), "162");
	port = atoi(buf);

	if(!strcmp(trap_server, "0.0.0.0"))
		syslog(LOG_NOTICE, "SNMP: Trap Server DNS Query Failed (%s)\n", SMARTRESET_TRAP);
	else
		snmp_send_trap(&message, trap_server, port, SMARTRESET_TRAP);

	return (out_data);
}

/****************************************************************************
TRAP#8 AutoBandwidth TRAP (wireless)
*Trigger
when changed bandwidth(40Mhz -> 20Mhz)
ex)
evt-time=2012-02-08 11:00:23
ap-mac=001122334455
*****************************************************************************
*/

void *sendAutoBandwidthTrap(void)
{
	int out_length = SNMP_MAX_MSG_LENGTH;
	unsigned char string_return[6];
	unsigned char *out_data;
	char trap_server[64];
	char trap_svr[64], buf[12];
	raw_snmp_info_t message;

	int port;
	int n, msglen;
	char msg[512];
	time_t _time;
	struct tm *ptm;

	Oid oid_obj;
	oid oid_autobandwidth_root[] = { O_AutoBandwidthTrapRoot };
	oid oid_autobandwidth_leaf[] = { O_AutoBandwidthTrapLeaf };

	n=0;
	msglen = sizeof(msg);
	if ( !(ptm = get_trapevent_time(&_time, 10)) )
		return NULL;

	/* delay to wlan autochan algorithm */
	usleep(11000000);

	memset((unsigned char *)&message, 0x00, sizeof(message));
	msg[0] = 0;
	// build header
	out_data = make_trap_v2c_headr(&message, &out_length, oid_autobandwidth_root, sizeof(oid_autobandwidth_root));
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_v2c_headr - send autobandwidth trap");

	// build body
	n = snprintf(&msg[n], msglen-n,  "evt-time=%04d-%02d-%02d %02d:%02d:%02d\r\n",
				(ptm->tm_year)+1900, (ptm->tm_mon)+1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
	get_mac(string_return, 6);
	n += snprintf(&msg[n], msglen-n, "ap-mac=%02x%02x%02x%02x%02x%02x\r\n",
				string_return[0], string_return[1], string_return[2], string_return[3], string_return[4], string_return[5]);

	n += snprintf(&msg[n], msglen-n, "set-bandwidth=%s\r\n", (autochan_get_bandwidth()==0)?"20": "40");

	oid_obj.namelen = sizeof(oid_autobandwidth_leaf) / sizeof(oid);
	memcpy(oid_obj.name, oid_autobandwidth_leaf, sizeof(oid_autobandwidth_leaf));
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR, n, (unsigned char *)msg, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_autobandwidth_leaf error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	nvram_get_r_def("x_autobandwidth_trap_server", trap_svr, sizeof(trap_svr), "iptvap-trap9.skbroadband.com");
	getsvrip_dnsquery(trap_svr, trap_server, sizeof(trap_server), AUTOBANDWIDTH_TRAP);
	nvram_get_r_def("x_WIFI_TRAP_PORT", buf, sizeof(buf), "162");
	port = atoi(buf);

	if(!strcmp(trap_server, "0.0.0.0"))
		syslog(LOG_NOTICE, "SNMP: Trap Server DNS Query Failed (%s)\n", AUTOBANDWIDTH_TRAP);
	else
		snmp_send_trap(&message, trap_server, port, AUTOBANDWIDTH_TRAP);

	return (out_data);
}

void *sendHandOverSuccessTrap(void)
{
	int out_length = SNMP_MAX_MSG_LENGTH;
	unsigned char string_return[6];
	unsigned char *out_data;
	char trap_server[64];
	char trap_svr[64], buf[20];
	raw_snmp_info_t message;
	unsigned int ipaddr;
	int port;
	int n, msglen;
	char msg[512];
	time_t _time;
	struct tm *ptm;
// APACRTL-485
	FILE *fp = NULL;
	char cpemac[16];
	float delay = 0;

	Oid oid_obj;
	oid oid_handoverSuccess_root[] = { O_HandOverSuccessTrapRoot };
	oid oid_handoverSuccess_leaf[] = { O_HandOverSuccessTrapLeaf };

	n=0;
	msglen = sizeof(msg);
	if ( !(ptm = get_trapevent_time(&_time, 0)) )
		return NULL;
	memset((unsigned char *)&message, 0x00, sizeof(message));
	msg[0] = 0;
	// build header
	out_data = make_trap_v2c_headr(&message, &out_length, oid_handoverSuccess_root, sizeof(oid_handoverSuccess_root));
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_v2c_headr - send smartReset trap");

	// build body
	n = snprintf(&msg[n], msglen-n,  "evt-time=%04d-%02d-%02d %02d:%02d:%02d\r\n",
				(ptm->tm_year)+1900, (ptm->tm_mon)+1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
	get_mac(string_return, 6);
	n += snprintf(&msg[n], msglen-n, "ap-mac=%02x%02x%02x%02x%02x%02x\r\n",
				string_return[0], string_return[1], string_return[2], string_return[3], string_return[4], string_return[5]);

/* APACRTL-485 */
	fp = fopen("/tmp/.handover_info", "r");
	if (fp) {
		fgets(buf, sizeof(buf), fp);
		sscanf(buf, "%s %f", cpemac, &delay);
		n += snprintf(&msg[n], msglen-n, "cpe-mac=%s\r\n", cpemac);

		if (delay < 3)
			n += snprintf(&msg[n], msglen-n, "delay=3\r\n");
		else if (3 <= delay && delay < 5)
			n += snprintf(&msg[n], msglen-n, "delay=5\r\n");
		else if (5 <= delay && delay < 10)
			n += snprintf(&msg[n], msglen-n, "delay=10\r\n");
		fclose(fp);
		unlink("/tmp/.handover_info");
	}

	oid_obj.namelen = sizeof(oid_handoverSuccess_leaf) / sizeof(oid);
	memcpy(oid_obj.name, oid_handoverSuccess_leaf, sizeof(oid_handoverSuccess_leaf));
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR, n, (unsigned char *)msg, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_handoverSuccess_leaf error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	nvram_get_r_def("x_handover_trap_server", trap_svr, sizeof(trap_svr), "iptvap-trap9.skbroadband.com");
	getsvrip_dnsquery(trap_svr, trap_server, sizeof(trap_server), HANDOVER_TRAP);
	nvram_get_r_def("x_WIFI_TRAP_PORT", buf, sizeof(buf), "162");
	port = atoi(buf);

	if(!strcmp(trap_server, "0.0.0.0"))
		syslog(LOG_NOTICE, "SNMP: Trap Server DNS Query Failed (%s)\n", HANDOVER_TRAP);
	else
		snmp_send_trap(&message, trap_server, port, HANDOVER_TRAP);

	return (out_data);
}

void *sendNtpFailTrap(char *fail_server)
{
	int out_length = SNMP_MAX_MSG_LENGTH;
	unsigned char string_return[6];
	unsigned char *out_data;
	char trap_server[64];
	char trap_svr[64], buf[20];
	raw_snmp_info_t message;
	unsigned int ipaddr;
	int port;
	int n, msglen;
	char msg[512];
	time_t _time;
	struct tm *ptm;
	long wan_ip;

	Oid oid_obj;
	oid oid_NtpFail_root[] = { O_NtpFailTrapRoot };
	oid oid_NtpFail_leaf[] = { O_NtpFailTrapLeaf };

	if ( !(switch_port_status(4) & PHF_LINKUP ) ||
		 get_wan_ip(&wan_ip, NULL) == 0 || wan_ip == 0 )
		return;

	n=0;
	msglen = sizeof(msg);
	_time = time(NULL);
	ptm = localtime(&_time);
	memset((unsigned char *)&message, 0x00, sizeof(message));
	msg[0] = 0;
	// build header
	out_data = make_trap_v2c_headr(&message, &out_length, oid_NtpFail_root, sizeof(oid_NtpFail_root));
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_v2c_headr - send smartReset trap");

	// build body
	n = snprintf(&msg[n], msglen-n,  "evt-time=%04d-%02d-%02d %02d:%02d:%02d\r\n",
				(ptm->tm_year)+1900, (ptm->tm_mon)+1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
	get_mac(string_return, 6);
	n += snprintf(&msg[n], msglen-n, "ap-mac=%02x%02x%02x%02x%02x%02x\r\n",
				string_return[0], string_return[1], string_return[2], string_return[3], string_return[4], string_return[5]);
	n += snprintf(&msg[n], msglen-n, "ntp_server=%s\r\n", fail_server);

	oid_obj.namelen = sizeof(oid_NtpFail_leaf) / sizeof(oid);
	memcpy(oid_obj.name, oid_NtpFail_leaf, sizeof(oid_NtpFail_leaf));
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR, n, (unsigned char *)msg, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_NtpFail_leaf error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	nvram_get_r_def("x_ntp_trap_server", trap_svr, sizeof(trap_svr), "iptvap-trap10.skbroadband.com");
	getsvrip_dnsquery(trap_svr, trap_server, sizeof(trap_server), NTP_TRAP);
	nvram_get_r_def("x_WIFI_TRAP_PORT", buf, sizeof(buf), "162");
	port = atoi(buf);

	if(!strcmp(trap_server, "0.0.0.0"))
		syslog(LOG_NOTICE, "SNMP: Trap Server DNS Query Failed (%s)\n", NTP_TRAP);
	else
		snmp_send_trap(&message, trap_server, port, NTP_TRAP);

	return (out_data);
}

static int wlan_state_check(const char *wlan_if)
{
	int skfd = 0;
	struct ifreq ifr;

	if ( (skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return 0;

	strncpy(ifr.ifr_name, wlan_if, IFNAMSIZ);

	if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
		close(skfd);
		return -1;
	}

	close(skfd);

	return (ifr.ifr_flags & IFF_UP)? 1 : 0;
}

static char *__sendwlan1SitesurveyResultTrap(raw_snmp_info_t *message, int exceed_size)
{
	int out_length = exceed_size;
	unsigned char string_return[6];
	unsigned char *out_data;
	char trap_server[64];
	char trap_svr[64], buf[20];
	unsigned int ipaddr;
	int port;
	int n, msglen;
	char msg[10240];
	time_t _time;
	struct tm *ptm;
// APACRTL-485
	float delay = 0;
	wlan_scan_info wlInfo[65];
	int i, scan_num = 0;
	bss_info bss;

	Oid oid_obj;
	oid oid_SitesurveyResult_root[] = { O_SitesurveyResultTrapRoot };
	oid oid_SitesurveyResult_leaf[] = { O_SitesurveyResultTrapLeaf };

	n=0;
	msglen = sizeof(msg);
	out_length += msglen;
	if ( !(ptm = get_trapevent_time(&_time, 0)) )
		return NULL;
	msg[0] = 0;
	// build header
	out_data = make_trap_v2c_headr(message, &out_length, oid_SitesurveyResult_root, sizeof(oid_SitesurveyResult_root));
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_v2c_headr - send smartReset trap");

	// build body
	n = snprintf(&msg[n], msglen-n,  "evt-time=%04d-%02d-%02d %02d:%02d:%02d\r\n",
				(ptm->tm_year)+1900, (ptm->tm_mon)+1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
	//2.4G scan get
	if (wlan_state_check("wlan1")) {
		getWlBssInfo("wlan1", &bss);
		n += snprintf(&msg[n], msglen-n, "self_channel_2.4=%d\r\n", bss.channel);
	}
	get_mac(string_return, 6);
	n += snprintf(&msg[n], msglen-n, "ap-mac=%02x%02x%02x%02x%02x%02x\r\n",
				string_return[0], string_return[1], string_return[2], string_return[3], string_return[4], string_return[5]);

	memset(wlInfo, 0, sizeof(wlInfo));
	scan_num = getWlanScanInfo(1, &wlInfo[0]);
	for(i = 0; i < scan_num; i++) {
		n += snprintf(&msg[n], msglen-n, "|ani=%d\r\n", i+1);
		n += snprintf(&msg[n], msglen-n, "acs=%s\r\n", wlInfo[i].ssid);
		n += snprintf(&msg[n], msglen-n, "anb=%02x%02x%02x%02x%02x%02x\r\n",
				wlInfo[i].bssid[0], wlInfo[i].bssid[1], wlInfo[i].bssid[2],
				wlInfo[i].bssid[3], wlInfo[i].bssid[4], wlInfo[i].bssid[5]);
		n += snprintf(&msg[n], msglen-n, "channel=%d\r\n", atoi(wlInfo[i].channel));
		n += snprintf(&msg[n], msglen-n, "encrypt=%s\r\n", wlInfo[i].encrypt);
		n += snprintf(&msg[n], msglen-n, "rssi=%s\r\n", wlInfo[i].rssi);
	}
	oid_obj.namelen = sizeof(oid_SitesurveyResult_leaf) / sizeof(oid);
	memcpy(oid_obj.name, oid_SitesurveyResult_leaf, sizeof(oid_SitesurveyResult_leaf));
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR, n, (unsigned char *)msg, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_SitesurveyResult_leaf error");

	// build tail and message length
	out_data = make_resp_tail(message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	nvram_get_r_def("x_sitesurvey_trap_server", trap_svr, sizeof(trap_svr), "iptvap-trap11.skbroadband.com");
	getsvrip_dnsquery(trap_svr, trap_server, sizeof(trap_server), WL1_SITESURVEY_TRAP);
	nvram_get_r_def("x_WIFI_TRAP_PORT", buf, sizeof(buf), "162");
	port = atoi(buf);

	if(!strcmp(trap_server, "0.0.0.0"))
		syslog(LOG_NOTICE, "SNMP: Trap Server DNS Query Failed (%s)\n", WL1_SITESURVEY_TRAP);
	else
		snmp_send_trap(message, trap_server, port, WL1_SITESURVEY_TRAP);

	return (out_data);
}

void sendwlan1SitesurveyResultTrap(void)
{
	raw_snmp_info_t *p;
	int extra_size;
	unsigned char *out_data;

	p = (raw_snmp_info_t *)malloc(sizeof(raw_snmp_info_t) + (16 * 1024));
	if (p == NULL) {
		return;
	}
	extra_size = sizeof(raw_snmp_info_t) + (16 * 1024);
	memset(p, 0, extra_size);
	out_data = __sendwlan1SitesurveyResultTrap(p, extra_size);

	free(p);
}

static char *__sendwlan0SitesurveyResultTrap(raw_snmp_info_t *message, int exceed_size)
{
	int out_length = exceed_size;
	unsigned char string_return[6];
	unsigned char *out_data;
	char trap_server[64];
	char trap_svr[64], buf[20];
	unsigned int ipaddr;
	int port;
	int n, msglen;
	char msg[10240];
	time_t _time;
	struct tm *ptm;
// APACRTL-485
	float delay = 0;
	wlan_scan_info wlInfo[65];
	int i, scan_num = 0;
	bss_info bss;

	Oid oid_obj;
	oid oid_SitesurveyResult_root[] = { O_SitesurveyResultTrapRoot };
	oid oid_SitesurveyResult_leaf[] = { O_SitesurveyResultTrapLeaf };

	n=0;
	msglen = sizeof(msg);
	out_length += msglen;
	if ( !(ptm = get_trapevent_time(&_time, 0)) )
		return NULL;
	msg[0] = 0;
	// build header
	out_data = make_trap_v2c_headr(message, &out_length, oid_SitesurveyResult_root, sizeof(oid_SitesurveyResult_root));
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_v2c_headr - send smartReset trap");

	// build body
	n = snprintf(&msg[n], msglen-n,  "evt-time=%04d-%02d-%02d %02d:%02d:%02d\r\n",
				(ptm->tm_year)+1900, (ptm->tm_mon)+1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
	//5G scan get
	if (wlan_state_check("wlan0")) {
		getWlBssInfo("wlan0", &bss);
		n += snprintf(&msg[n], msglen-n, "self_channel_5=%d\r\n", bss.channel);
	}
	get_mac(string_return, 6);
	n += snprintf(&msg[n], msglen-n, "ap-mac=%02x%02x%02x%02x%02x%02x\r\n",
				string_return[0], string_return[1], string_return[2], string_return[3], string_return[4], string_return[5]);

	memset(wlInfo, 0, sizeof(wlInfo));
	scan_num = getWlanScanInfo(0, &wlInfo[0]);
	for(i= 0; i< scan_num; i++) {
		n += snprintf(&msg[n], msglen-n, "|ani=%d\r\n", i+1);
		n += snprintf(&msg[n], msglen-n, "acs=%s\r\n", wlInfo[i].ssid);
		n += snprintf(&msg[n], msglen-n, "anb=%02x%02x%02x%02x%02x%02x\r\n",
				wlInfo[i].bssid[0], wlInfo[i].bssid[1], wlInfo[i].bssid[2],
				wlInfo[i].bssid[3], wlInfo[i].bssid[4], wlInfo[i].bssid[5]);
		n += snprintf(&msg[n], msglen-n, "channel=%d\r\n", atoi(wlInfo[i].channel));
		n += snprintf(&msg[n], msglen-n, "encrypt=%s\r\n", wlInfo[i].encrypt);
		n += snprintf(&msg[n], msglen-n, "rssi=%s\r\n", wlInfo[i].rssi);
	}
	oid_obj.namelen = sizeof(oid_SitesurveyResult_leaf) / sizeof(oid);
	memcpy(oid_obj.name, oid_SitesurveyResult_leaf, sizeof(oid_SitesurveyResult_leaf));
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR, n, (unsigned char *)msg, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_SitesurveyResult_leaf error");

	// build tail and message length
	out_data = make_resp_tail(message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	nvram_get_r_def("x_sitesurvey_trap_server", trap_svr, sizeof(trap_svr), "iptvap-trap11.skbroadband.com");
	getsvrip_dnsquery(trap_svr, trap_server, sizeof(trap_server), WL0_SITESURVEY_TRAP);
	nvram_get_r_def("x_WIFI_TRAP_PORT", buf, sizeof(buf), "162");
	port = atoi(buf);

	if(!strcmp(trap_server, "0.0.0.0"))
		syslog(LOG_NOTICE, "SNMP: Trap Server DNS Query Failed (%s)\n", WL0_SITESURVEY_TRAP);
	else
		snmp_send_trap(message, trap_server, port, WL0_SITESURVEY_TRAP);

	return (out_data);
}

void sendwlan0SitesurveyResultTrap(void)
{
	raw_snmp_info_t *p;
	int extra_size;
	unsigned char *out_data;

	p = (raw_snmp_info_t *)malloc(sizeof(raw_snmp_info_t) + (16 * 1024));
	if (p == NULL) {
		return;
	}
	extra_size = sizeof(raw_snmp_info_t) + (16 * 1024);
	memset(p, 0, extra_size);
	out_data = __sendwlan0SitesurveyResultTrap(p, extra_size);

	free(p);
}

/****************************************************************************
TRAP#12 STA FAIL TRAP
*Trigger
When CONNECT FAIL STA to AP.
*****************************************************************************
*/
void *send_sta_fail_trap(char *msg, int msglen)
{
	char buf[256];
	int out_length = SNMP_MAX_MSG_LENGTH;
	unsigned char *out_data = NULL;
	raw_snmp_info_t message;
	unsigned int ipaddr;
	static char wlsta_trap_server[80];
	static int port;
	in_addr_t addr;

	Oid oid_obj;
	oid oid_staConnfail[] = { O_StaConnectFailTrapRoot };
	oid oid_staConnfail_leaf[] = { O_StaConnectFailTrapLeaf };

	memset((unsigned char *)&message, 0x00, sizeof(message));
	// build sendAutoTransmission header
	out_data = make_trap_v2c_headr(&message, &out_length, oid_staConnfail, sizeof(oid_staConnfail));
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_v2c_headr - send sta Conn fail Trap");

	// build body
	oid_obj.namelen = sizeof(oid_staConnfail_leaf) / sizeof(oid);
	memcpy(oid_obj.name, oid_staConnfail_leaf, sizeof(oid_staConnfail_leaf));

	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR, msglen, (unsigned char *)msg, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_staConnfail_leaf error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	nvram_get_r_def("x_WIFI_TRAP_PORT", buf, sizeof(buf), "162");
	port = atoi(buf);
	nvram_get_r_def("x_sta_fail_trap_server", buf, sizeof(buf), "iptvap-trap12.skbroadband.com");
	getsvrip_dnsquery(buf, wlsta_trap_server, sizeof(wlsta_trap_server), STA_FAIL_TRAP);

	if (!strcmp(wlsta_trap_server, "0.0.0.0"))
		syslog(LOG_NOTICE, "SNMP: Trap Server DNS Query Failed (%s)\n", STA_FAIL_TRAP);
	else
		snmp_send_trap(&message, wlsta_trap_server, port, STA_FAIL_TRAP);

	return (out_data);
}

static char *getsvrip_dnsquery(char *ip_url, char *tell_ip, int len, const char *logstr)
{
	struct addrinfo *_addrinfo, *_res;
	struct in_addr addr;
	int errcode = 0;
	char buf[128];
	unsigned int ipaddr = 0;

	if (!ip_url || !ip_url[0])
		return NULL;

	if ( (ipaddr=inet_addr(ip_url)) == INADDR_NONE) {
		errcode = getaddrinfo(ip_url, NULL, NULL, &_addrinfo);
		if(errcode != 0) {
			snprintf(tell_ip, len, "0.0.0.0");
			syslog(LOG_INFO, "%s: %s\n", (logstr)?logstr:"---", gai_strerror(errcode));
			return 0;
		}

		for(_res = _addrinfo; _res != NULL; _res = _res->ai_next) {
			addr.s_addr = ((struct sockaddr_in *)_res->ai_addr)->sin_addr.s_addr;
			snprintf(tell_ip, len, "%s", inet_ntoa(addr));
		}
		freeaddrinfo(_addrinfo);
	} else {
		snprintf(tell_ip, len, "%s", inet_ntoa(*(struct in_addr *)&ipaddr));
	}

	return tell_ip;
}
