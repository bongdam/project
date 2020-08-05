#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <netdb.h>
#include <limits.h>

#include <bcmnvram.h>
#include <shutils.h>

typedef u_int64_t __u64;
typedef u_int32_t __u32;
typedef u_int16_t __u16;
typedef u_int8_t __u8;
typedef u_int64_t u64;
typedef u_int32_t u32;
typedef u_int16_t u16;
typedef u_int8_t u8;

#include <linux/sockios.h>
#include <linux/if.h>
#include <linux/ethtool.h>
#include <linux/wireless.h>
#include <netinet/ip_icmp.h>
#include <wait.h>
#include "linux_list.h"
#include "furl.h"
#include "engine/snmp.h"
#include "snmp_main.h"
#include "skbb.h"
#include "engine/agt_mib.h"
#include "skbb_api.h"
#include "misc.h"
#include "defines.h"
#include "apmib_defs.h"
#include "apmib.h"
#include "1x_ioctl.h"
#include <libytool.h>
#include <nmpipe.h>
#include "custom.h"
#define __SNMP_BITMAP__

#define MAX_STATION_NUM         64  // max support sta number
#define STA_INFO_FLAG_ASOC	0x04
#define TEMP_MACAC_LIST_FILE        "/var/tmp_wlan_macac.list"

#define eval(cmd, args...) ({ \
		char *argv[] = { cmd , ## args, NULL }; \
		yexecv(argv, NULL,0, NULL); \
})

#define ENCRYPT_ADD_VAL 100
#define DECRYPT_ADD_VAL -100

extern int snmpAction;
extern int root_vwlan_disable[MAX_WLAN_INTF_NUM][2];
/* Global Variables */
struct phreq portReqs[PH_MAXPORT + 1];
static int g_SaveAndApply;
static int needReboot = 0;

static void ping_init_instance(int no);
static int LanAccessControlListDelALList(int select_port);
static struct nmpipe *named_pipe = NULL;

int portfw_tblnum = 0;

#define RTL819X_IOCTL_READ_PORT_STATS	              (SIOCDEVPRIVATE + 0x02)

#define WANIF "eth1"
#define LANIF "eth0"
struct port_statistics {
	unsigned int  rx_bytes;
	unsigned int  rx_unipkts;
	unsigned int  rx_mulpkts;
	unsigned int  rx_bropkts;
	unsigned int  rx_discard;
	unsigned int  rx_error;
	unsigned int  tx_bytes;
	unsigned int  tx_unipkts;
	unsigned int  tx_mulpkts;
	unsigned int  tx_bropkts;
	unsigned int  tx_discard;
	unsigned int  tx_error;
};

struct _port_status {
	unsigned int inputOCT;
	unsigned int outputOCT;
	unsigned int CRC;
};

void get_prePortfwConfig()
{
	int i;
	char buf[16], val[64], *args[8];
	struct in_addr in;

	portfw_tblnum = nvram_atoi("PORTFW_TBL_NUM", 0);
	for(i = 0; i < portfw_tblnum; i++) {
		snprintf(buf, sizeof(buf), "PORTFW_TBL%d", i+1);
		nvram_get_r(buf, val, sizeof(val));
		trim_spaces(val);
		if(ystrargs(val, args, _countof(args), ",|", 0) > 4) {
			if(inet_aton(args[0], &in))
				portfw_tbl[i].ipaddr = in.s_addr;
			portfw_tbl[i].startport = atoi(args[1]);
			portfw_tbl[i].endport = atoi(args[2]);
			portfw_tbl[i].protocol = atoi(args[3]);
			portfw_tbl[i].slanport = atoi(args[4]);
			if(!args[5])
				snprintf(portfw_tbl[i].name, sizeof(portfw_tbl[i].name), "%s", "");
			else
				snprintf(portfw_tbl[i].name, sizeof(portfw_tbl[i].name), "%s", args[5]);
		}
	}
}

void get_manufacturer(char *str, int len)
{
}

void get_modelName(char *str, int len)
{
	if (yfcat("/etc/version", "%s", str) <= 0)
		gethostname(str, len);
}

void get_version(char *str, int len)
{

	memset(str, 0, len);

	if(!yfcat("/etc/version", "%*s %s", str))
		sprintf(str, "%s", "1.00.00");
}

#define _PATH_PROCNET_ROUTE "/proc/net/route"
#define RTF_UP          0x0001
#define RTF_GATEWAY     0x0002

int getDefaultRoute(char *interface, unsigned int *route)
{
	char buff[1024], iface[16];
	char gate_addr[128], net_addr[128], mask_addr[128];
	int num, iflags, metric, refcnt, use, mss, window, irtt;
	FILE *fp = fopen(_PATH_PROCNET_ROUTE, "r");
	char *fmt;
	int found = 0;
	unsigned int addr;

	if (!fp) {
		printf("Open %s file error.\n", _PATH_PROCNET_ROUTE);
		return 0;
	}

	fmt = "%16s %128s %128s %X %d %d %d %128s %d %d %d";

	while (fgets(buff, 1023, fp)) {
		num = sscanf(buff, fmt, iface, net_addr, gate_addr, &iflags, &refcnt, &use, &metric, mask_addr, &mss, &window, &irtt);
		if (num < 10 || !(iflags & RTF_UP) || !(iflags & RTF_GATEWAY) || strcmp(iface, interface))
			continue;
		sscanf(gate_addr, "%x", &addr);
		*route = addr;

		found = 1;
		break;
	}

	fclose(fp);
	return found;
}

int getInAddr(char *interface, ADDR_T type, void *pAddr)
{
	struct ifreq ifr;
	int skfd = 0, found = 0;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd == -1)
		return 0;
	strcpy(ifr.ifr_name, interface);
	if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
		close(skfd);
		return (0);
	}
	if (type == HW_ADDR) {
		if (ioctl(skfd, SIOCGIFHWADDR, &ifr) >= 0) {
			memcpy(pAddr, &ifr.ifr_hwaddr, sizeof(struct sockaddr));
			found = 1;
		}
	} else if (type == IP_ADDR) {
		if (ioctl(skfd, SIOCGIFADDR, &ifr) >= 0) {
			*((struct in_addr *)pAddr) = *((struct in_addr *)&((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
			found = 1;
		}
	} else if (type == SUBNET_MASK) {
		if (ioctl(skfd, SIOCGIFNETMASK, &ifr) >= 0) {
			*((struct in_addr *)pAddr) = *((struct in_addr *)&((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
			found = 1;
		}
	}
	close(skfd);
	return (found);

}

void get_mac(char *str, int len)
{
	char *p = NULL;
	char buf[40];
	char temp[3];
	unsigned char hwAddr[6];
	int i, j;

	memset(str, 0, len);

	p = getValue("HW_NIC1_ADDR");

	if(!p) {
		strcpy(str, "000000000000");
		return;
	} else {
		strcpy(buf, p);
	}
	memset(temp, 0, sizeof(temp));
	for (i = 0, j = 0; i < 12; i += 2) {
		memcpy(temp, &buf[i], 2);
		hwAddr[j++] = (char)strtol(temp, NULL, 16);
	}
	memcpy(str, hwAddr, sizeof(hwAddr));
}

void get_lanMac(char *str, int len)
{
	char *p = NULL;
	char buf[40];
	char temp[3];
	unsigned char hwAddr[6];
	int i, j;

	memset(str, 0, len);
	p = getValue("HW_NIC0_ADDR");

	if(!p) {
		strcpy(str, "000000000000");
		return;
	} else {
		strcpy(buf, p);
	}
	memset(temp, 0, sizeof(temp));
	for (i = 0, j = 0; i < 12; i += 2) {
		memcpy(temp, &buf[i], 2);
		hwAddr[j++] = (char)strtol(temp, NULL, 16);

	}
	memcpy(str, hwAddr, sizeof(hwAddr));

}


void get_wanIpAddress(void *wanIp, int type)
{
	FILE *fp;
	struct in_addr in;
	unsigned int ipAddr = 0;
	char buf[80];

	buf[0] = 0;
	if (wanConfig.IpAddr == 0) {
		if ( (fp=fopen("/var/wan_ip", "r")) ) {
			if ( fgets(buf, sizeof(buf), fp) ) {
				if ( inet_aton(buf, &in) )
					ipAddr = in.s_addr;
			}
			fclose(fp);
		}
		//getInAddr("eth1", IP_ADDR, &ipAddr);
	}
	else {
		ipAddr = wanConfig.IpAddr;
	}

	if (wanConfig.IpAddr == 0)
		getInAddr("eth1", IP_ADDR, &ipAddr);
	else
		ipAddr = wanConfig.IpAddr;

	if (type == NON_STRING_TYPE) {
		*(unsigned int *)wanIp = ipAddr;
	} else {
		inet_ntop(AF_INET, &ipAddr, wanIp, MAX_SNMP_STR);
	}
}

int get_wanMethod()
{
	int mode = atoi(getValue("WAN_DHCP"));

	if (wanConfig.obtainedMethod == 0) {
		if (mode == 0)
			wanConfig.obtainedMethod = 2;
		else
			wanConfig.obtainedMethod = 1;
	}

	return wanConfig.obtainedMethod;
}

void set_wanMethod(int res)
{
	if (res != 1 && res != 2) {
		printf("Invalid Value....%d\n", res);
		return;
	}

	wanConfig.obtainedMethod = res;
	wanConfig.changed = 1;
}

int set_wanIpAddress(unsigned char *var_val, int var_val_len)
{
	wanConfig.IpAddr = *(unsigned int *)var_val;
	wanConfig.changed = 1;
	return 1;
}

void get_wanSubnetMask(void *wanMask, int type)
{
	FILE *fp;
	struct in_addr in;
	unsigned int Mask = 0;
	char buf[80];

	buf[0] = 0;
	if (wanConfig.subnetMask == 0) {
		if ( (fp=fopen("/var/netmask", "r")) ) {
			if ( fgets(buf, sizeof(buf), fp) ) {
				if ( inet_aton(buf, &in) )
					Mask = in.s_addr;
			}
			fclose(fp);
		}
		//getInAddr("eth1", IP_ADDR, &ipAddr);
	} else {
		Mask = wanConfig.subnetMask;
	}

	if (type == NON_STRING_TYPE)
		*(unsigned int *)wanMask = Mask;
	else
		inet_ntop(AF_INET, &Mask, wanMask, MAX_SNMP_STR);
}

int set_wanSubnetMask(unsigned char *var_val, int var_val_len)
{
	wanConfig.subnetMask = *(unsigned int *)var_val;
	wanConfig.changed = 1;
	return 1;
}

void get_lanSubnetMask(void *Mask, int type)
{
	char buf[20];
	struct in_addr ia;

	if(lanConfig.subnetMask == 0)
		snprintf(buf, sizeof(buf), "%s", getValue("SUBNET_MASK"));
	else {
		ia.s_addr = htonl(lanConfig.subnetMask);
		snprintf(buf, sizeof(buf), "%s", inet_ntoa(ia));
	}

	if (type == NON_STRING_TYPE)
		*(in_addr_t *)Mask = inet_addr(buf);
	else
		strcpy((char *)Mask, buf);

}

void set_lanSubnetMask(unsigned char *var_val, int var_val_len)
{
	lanConfig.subnetMask = *(unsigned int *)var_val;
	lanConfig.changed = 1;
}


void get_gwIpAddress(void *wanGw, int type)
{
	FILE *fp;
	unsigned int gwAddr;
	char buf[80];
	struct in_addr in;

	buf[0] = 0;
	if (wanConfig.defGateway == 0) {
		if ( (fp=fopen("/var/gateway", "r")) ) {
			if ( fgets(buf, sizeof(buf), fp) ) {
				if ( inet_aton(buf, &in) )
					gwAddr = in.s_addr;
			}
			fclose(fp);
		} else {
			wanConfig.defGateway = 0;
		}
	} else
		gwAddr = wanConfig.defGateway;

	if (type == NON_STRING_TYPE)
		*(unsigned int *)wanGw = gwAddr;
	else
		inet_ntop(AF_INET, &gwAddr, wanGw, MAX_SNMP_STR);
}

int set_wanDefaultGW(unsigned char *var_val, int var_val_len)
{
	wanConfig.defGateway = *(unsigned int *)var_val;
	wanConfig.changed = 1;
	return 1;
}

void get_dnsAddress(void *dns, int index, int type)
{
	char buf[80], *p;
	FILE *fp;
	int len, cnt = 0;
	char *option = "nameserver";

	if (wanConfig.DNS[index - 1] != 0) {
		*(unsigned int *)dns = wanConfig.DNS[index - 1];
		return;
	}

	fp = fopen("/etc/resolv.conf", "r");
	if (!fp) {
		*(unsigned int *)dns = 0;
		return;
	}

	len = strlen(option);
	while (fgets(buf, sizeof(buf), fp)) {
		if (strncmp(buf, option, len) || !isspace((unsigned char)buf[len]))
			continue;
		cnt++;
		if (cnt == index) {
			p = &buf[len];
			while (isspace((unsigned char)*p))
				p++;
			wanConfig.DNS[index - 1] = inet_addr(p);
		}
	}

	fclose(fp);
	*(unsigned int *)dns = wanConfig.DNS[index - 1];

	return;
}

int set_wanDNS2(unsigned char *var_val, int var_val_len)
{
	int mode = 1;
	int enable;

	enable = nvram_atoi("x_dns_enable", 0);

	if(enable == 0)
		return 0;

	setValue("x_dns_enable", "0");
	wanConfig.autoDNS = 1;
	wanConfig.DNS[1] = *(unsigned int *)var_val;
	wanConfig.changed = 1;

	return 1;
}

int get_DNSMode()
{
	int mode;

	mode = nvram_atoi("x_dns_enable", 0);

	if (mode == 1)
		return 1;
	else if (mode == 0)
		return 2;
}

int set_DNSMode(int res)
{
	char buf[2];

	if(res != 1 && res != 2)
		return 0;

	if (res == 1)
		strcpy(buf, "1");
	else if (res == 2)
		strcpy(buf, "0");

	setValue("x_dns_enable", buf);

	return 1;
}

int set_DNSMethod(int res)
{
	int method;

	if( res != 1 && res != 2 )
		return 0;

	if (res == 1)
		method = 0;
	else if (res == 2)
		method = 1;

	setValue_mib(MIB_DNS_MODE, (void*)&method);
	setValue("x_dns_enable", "0");
	wanConfig.changed = 1;

	return 1;
}

void get_lanIpAddress(void *lanIp, int type)
{
	char buf[80];
	unsigned long ipAddr;
	struct in_addr ia;

	if(lanConfig.IpAddr == 0)
		nvram_get_r_def("IP_ADDR", buf, sizeof(buf), "192.168.35.1");
	else {
		ia.s_addr = htonl(lanConfig.IpAddr);
		snprintf(buf, sizeof(buf), "%s", inet_ntoa(ia));
	}

	ipAddr = inet_addr(buf);

	*(long *)lanIp = ipAddr;
}

int get_radiusServerIP(int w_index, int index, void *ip_addr)
{
	char buf[64], param[20];
	unsigned int ipAddr;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			*(unsigned int *)ip_addr = 0;
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			*(unsigned int *)ip_addr = 0;
			return 1;
		}
	}

	if(securityConfig[w_index].secRadiusConfig[index].radiusIP == 0) {
		memset(param, 0, sizeof(param));
		if (index == 0)
			sprintf(param,"WLAN%d_RS_IP", w_index);
		else
			sprintf(param, "WLAN%d_VAP%d_RS_IP", w_index, index - 1);
		nvram_get_r_def(param, buf, sizeof(buf), "0.0.0.0");
		ipAddr = inet_addr(buf);
	} else
		ipAddr = securityConfig[w_index].secRadiusConfig[index].radiusIP;

	*(unsigned int *)ip_addr = ipAddr;

	if (ipAddr == INADDR_NONE)
		return 0;
	else
		return 1;
}

int set_radiusServerIP(int w_index, int index, unsigned char *var_val)
{
	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	securityConfig[w_index].secRadiusConfig[index].radiusIP = *(unsigned int*)var_val;
	securityConfig[w_index].changed[index] = 1;
	return 1;
}

int set_radiusPort(int w_index, int index, int rs_port)
{
	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	securityConfig[w_index].secRadiusConfig[index].radiusPort = rs_port;
	securityConfig[w_index].changed[index] = 1;

	return 1;
}

int get_radiusPort(int w_index, int index, long *Port)
{
	char buf[20], param[32];
	int rs_port;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 0;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 0;
		}
	}

	if(securityConfig[w_index].secRadiusConfig[index].radiusPort == 0) {
		memset(param, 0, sizeof(param));
		if (index == 0)
			sprintf(param, "WLAN%d_RS_PORT", w_index);
		else
			sprintf(param, "WLAN%d_VAP%d_RS_PORT", w_index, index - 1);

		snprintf(buf, sizeof(buf), "%s", getValue(param));
		rs_port = atoi(buf);
	} else
		rs_port = securityConfig[w_index].secRadiusConfig[index].radiusPort;

	*(int *)Port = rs_port;

	return rs_port;

}

int get_radiusPassword(int w_index, int index, char *Password)
{
	char param[32], buf[64] = {0,};

	memset(param, 0, sizeof(param));

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			snprintf(Password, MAX_SNMP_STR, "%s", buf);
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			snprintf(Password, MAX_SNMP_STR, "%s", buf);
			return 1;
		}
	}

	if(!strcmp(securityConfig[w_index].secRadiusConfig[index].radiusPasswd, "")) {
		if (index == 0) {
			sprintf(param, "WLAN%d_RS_PASSWORD", w_index);
		} else {
			sprintf(param, "WLAN%d_VAP%d_RS_PASSWORD", w_index, index - 1);
		}
		nvram_get_r_def(param, buf, sizeof(buf), "");
		snprintf(Password, MAX_SNMP_STR, "%s", buf);
	} else
		snprintf(Password, MAX_SNMP_STR, "%s", securityConfig[w_index].secRadiusConfig[index].radiusPasswd);

	return 1;
}

int set_radiusPassword(int w_index, int index, unsigned char *Password, int var_len)
{
	if(var_len < 1 || var_len > 64)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	snprintf(securityConfig[w_index].secRadiusConfig[index].radiusPasswd, sizeof(securityConfig[w_index].secRadiusConfig[index].radiusPasswd), "%s", Password);
	securityConfig[w_index].changed[index] = 1;
	return 1;
}

int get_radiusAccountMode(int w_index, int index)
{
	char param[32];
	int enabled, res = 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 2;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 2;
		}
	}

	if(securityConfig[w_index].secRadiusConfig[index].serverMode == 0) {
		if (index == 0)
			sprintf(param, "WLAN%d_ACCOUNT_RS_ENABLED", w_index);
		else
			sprintf(param, "WLAN%d_VAP%d_ACCOUNT_RS_ENABLED", w_index, index - 1);
		enabled = nvram_atoi(param, 0);

		if(enabled == 0)
			res = 2;
		else
			res = 1;

	} else
		res = securityConfig[w_index].secRadiusConfig[index].serverMode;

	return res;

}

int set_radiusAccountMode(int w_index, int index, int intVal)
{
	if(intVal != 1 && intVal != 2)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	securityConfig[w_index].secRadiusConfig[index].serverMode = intVal;
	securityConfig[w_index].changed[index] = 1;

	return 1;
}

int get_radiusAccountServerIp(int w_index, int index, void *ipAddr)
{
	char buf[20];
	char param[32];
	unsigned long serverIp;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			*(unsigned long *)ipAddr = 0;
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			*(unsigned long *)ipAddr = 0;
			return 1;
		}
	}

	if(securityConfig[w_index].secRadiusConfig[index].accountIP == 0) {
		memset(param, 0, sizeof(param));
		if (index == 0)
			sprintf(param, "WLAN%d_ACCOUNT_RS_IP", w_index);
		else
			sprintf(param, "WLAN%d_VAP%d_ACCOUNT_RS_IP", w_index, index - 1);

		snprintf(buf, sizeof(buf), "%s", getValue(param));
		serverIp = inet_addr(buf);
	} else
		serverIp = securityConfig[w_index].secRadiusConfig[index].accountIP;

	*(unsigned long *)ipAddr = serverIp;
	if (serverIp == INADDR_NONE)
		return 0;
	else
		return 1;

}

int set_radiusAccountServerIp(int w_index, int index, unsigned char *var_val)
{
	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	securityConfig[w_index].secRadiusConfig[index].accountIP = *(unsigned int*)var_val;
	securityConfig[w_index].changed[index] = 1;
	return 1;
}


int get_radiusAccountServerPort(int w_index, int index, void *AccountPort)
{
	char buf[8];
	char param[32];
	int port;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 0;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 0;
		}
	}

	if(securityConfig[w_index].secRadiusConfig[index].accountPort == 0) {
		memset(param, 0, sizeof(param));
		if (index == 0)
			sprintf(param, "WLAN%d_ACCOUNT_RS_PORT", w_index);
		else
			sprintf(param, "WLAN%d_VAP%d_ACCOUNT_RS_PORT", w_index, index - 1);

		snprintf(buf, sizeof(buf), "%s", getValue(param));

		port = atoi(buf);
	} else
		port = securityConfig[w_index].secRadiusConfig[index].accountPort;

	*(int *)AccountPort = port;

	return port;
}

int set_radiusAccountServerPort(int w_index, int index, int port)
{
	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	securityConfig[w_index].secRadiusConfig[index].accountPort = port;
	securityConfig[w_index].changed[index] = 1;

	return 1;
}

int get_radiusAccountServerPasswd(int w_index, int index, char *AccountPwd)
{
	char buf[64] = {0,};
	char param[32];

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			snprintf(AccountPwd, MAX_SNMP_STR, "%s", buf);
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			snprintf(AccountPwd, MAX_SNMP_STR, "%s", buf);
			return 1;
		}
	}

	if(!strcmp(securityConfig[w_index].secRadiusConfig[index].accountPasswd, "")) {
		if (index == 0)
			sprintf(param, "WLAN%d_ACCOUNT_RS_PASSWORD", w_index);
		else
			sprintf(param, "WLAN%d_VAP%d_ACCOUNT_RS_PASSWORD", w_index, index - 1);

		snprintf(buf, sizeof(buf), "%s", getValue(param));
		snprintf(AccountPwd, MAX_SNMP_STR, "%s", buf);
	} else
		snprintf(AccountPwd, MAX_SNMP_STR, securityConfig[w_index].secRadiusConfig[index].accountPasswd);

	return 1;
}

int set_radiusAccountServerPasswd(int w_index, int index, unsigned char *AccountPwd, int len)
{
	if(len < 1 || len > 64)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	snprintf(securityConfig[w_index].secRadiusConfig[index].accountPasswd, sizeof(securityConfig[w_index].secRadiusConfig[index].accountPasswd), "%s", AccountPwd);
	securityConfig[w_index].changed[index] = 1;
	return 1;
}

#define MAX_TRY     3
#define MAX_TIMEO   4000
#ifndef TRUE
#define TRUE    1
#define FALSE   0
#endif

static int (*pfw_parse_bootline)(struct bootline_mtd_info *);
static int (*pfw_validate)(struct fwstat *);
static int (*pfw_dualize)(struct fwstat *);
static int (*pfw_write)(struct fwstat *,
						 int (*)(struct fwblk *, void *, FW_WR *), void *);
static int (*pfurl)(char *, int , p_read_f , void *);
static int (*pfw_read_callback)(char *, int , struct fwstat *);
static const char *(*pfw_strerror)(int);


static int do_tftpget(struct fwstat *fbuf, int *exp, int timeo, char *filename, char *server)
{
	char cmd[256];
	int try;
	long ts, waiths;

	snprintf(cmd, sizeof(cmd) - 13, "tftp -g -r %s -l - %s", filename, server);
	fprintf(stderr, "SNMP: %s\n", cmd);
	for (try = 0; try < MAX_TRY; try++) {
		ts = times(NULL);
		/* put the 5 mins cap */
		if (*exp < 7)
			waiths = ((3 * (1 << *exp)) + (rand() % 3) + 1) * 100;
		else
			waiths = (300 + (rand() % 3) + 1) * 100;
		++*exp;

		if (!pfurl(cmd, timeo, (p_read_f) pfw_read_callback, (void *)fbuf))
			return (!fbuf->lasterror && fbuf->rcvlen > 0) ? 0 : -1;

		waiths -= (times(NULL) - ts);
		if (waiths <= 0)
			waiths = 1;
		usleep(waiths * 10000);
	}
	return -1;
}

int __executeManualUpgrade(char *server, char *path, char *filename)
{
	void *handle;
	char *error;
	char f_path[256];
	char *p, *saveptr;
	struct fwstat fbuf;
	char buffer[2048];
	int exp, status;
	time_t t;
	char *mm;

	if (!server || server[0]==0) {
		fprintf(stderr, "server address is empty\n");
		return -1;
	}
	if (!filename || filename[0]==0) {
		fprintf(stderr, "firmware name is empty\n");
		return -1;
	}
	handle = dlopen("libfurl.so", RTLD_LAZY);
	if (!handle) {
		fprintf(stderr, "%s\n", dlerror());
		return -1;
	}
	dlerror();                  /* Clear any existing error */
	*(void **)(&pfw_parse_bootline) = dlsym(handle, "fw_parse_bootline");
	*(void **)(&pfw_validate) = dlsym(handle, "fw_validate");
	*(void **)(&pfw_dualize) = dlsym(handle, "fw_dualize");
	*(void **)(&pfw_write) = dlsym(handle, "fw_write");
	*(void **)(&pfurl) = dlsym(handle, "furl");
	*(void **)(&pfw_read_callback) = dlsym(handle, "fw_read_callback");
	*(void **)(&pfw_strerror) = dlsym(handle, "fw_strerror");

	if ((error = dlerror()) != NULL) {
		dlclose(handle);
		fprintf(stderr, "%s\n", error);
		return -1;
	}
	mm = mmap(NULL, MAX_FWSIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (mm == MAP_FAILED) {
		perror("mmap");
		_exit(-1);
	}
	exp = 0;

	memset(&fbuf, 0, sizeof(fbuf));
	fbuf.fmem = mm;
	fbuf.caplen = MAX_FWSIZE;

	if ( (path && path[0]!=0) && (p = strtok_r(&path[0],"/ \t\r\n", &saveptr)) )
		sprintf(f_path, "/%s/%s", p, (!filename||filename[0]==0)? "fw.bin":filename);
	else
		sprintf(f_path, "%s", filename);

	if (!do_tftpget(&fbuf, &exp, MAX_TIMEO, f_path, server)) {
		fprintf(stderr, "SWMS: image length %d\n", fbuf.rcvlen);
		pfw_parse_bootline(&fbuf.blnfo);
		status = pfw_validate(&fbuf);
		if (!status && !(status = pfw_dualize(&fbuf))) {
			//vfecho("/proc/gpio", "4 %d", (fbuf.rcvlen / 43840) + 80 + 24);
			ifconfig("br0", 0, NULL, NULL);
			status = pfw_write(&fbuf, NULL, NULL);
			if (!status) {
				munmap(mm, MAX_FWSIZE);
				mm = MAP_FAILED;
				dlclose(handle);
				t = time(NULL);
				strftime(buffer, sizeof(buffer), "%F %H:%M:%S", localtime(&t));
				nvram_set("snmp_upgrade_time", buffer);
				nvram_commit();
				syslog(LOG_INFO, "manual upgrade, reboot in snmpd");
				yexecl(NULL, "reboot");
			} else
				ifconfig("br0", IFUP, NULL, NULL);
		}
		fprintf(stderr, "SWMS: %s\n", pfw_strerror(status));
	} else
		status = -EGETFW;

	if (mm != MAP_FAILED)
		munmap(mm, MAX_FWSIZE);
	dlclose(handle);

	return status;
}

int get_DevicePortNego(int portno)
{
	char buffer[64], var[64];
	char *p;

	if(!strcmp(portConfig[portno].port_config ,"")) {
		if(portno == 0) {
			sprintf(var, "x_port_4_config");
			nvram_get_r_def(var, buffer, sizeof(buffer), "up_auto_rxpause_txpause");
		} else {
			sprintf(var, "x_port_%d_config", portno-1);
			nvram_get_r_def(var, buffer, sizeof(buffer), "up_auto_-rxpause_txpause");
		}
	} else
		snprintf(buffer, sizeof(buffer), "%s", portConfig[portno].port_config);

	if((p = strstr(buffer, "auto")))
		return 2;
	else
		return 1;
}

int set_DevicePortNego(int nego, int index)
{
	char buffer[52], var[52], buf[52], temp[52];
	int parse=0, n=0;
	int len = sizeof(buf);
	char *p, *q;

	if(nego != 1 && nego != 2) //force, auto
		return 0;

	if (index == 0)
		sprintf(var, "x_port_4_config");
	else
		sprintf(var, "x_port_%d_config", index-1);
	snprintf(buffer, sizeof(buffer), "%s", getValue(var));
	snprintf(temp, sizeof(temp), "%s", buffer);

	p = strtok(buffer, "_");

	if(nego == 1){ //force
		while(p!=NULL){
			if(!parse)
				n+=snprintf(&buf[n], len, "%s", p);
			else if(parse==1)
				n+=snprintf(&buf[n], len-n, "_%s", FORCE);
			else{
				if((q=strstr(temp, "duplex")))    //previous setting is force
					n+=snprintf(&buf[n], len-n, "_%s", p);
				else{                                                   //previous setting is auto
					if(index == 0)
						n+=snprintf(&buf[n], len-n, "_full_speed_1000_rxpause_txpause");
					else
						n+=snprintf(&buf[n], len-n, "_full_speed_1000_-rxpause_txpause");
					break;
				}
			}
			parse++;
			p = strtok(NULL, "_");
		}
	} else { //auto
		while(p!=NULL){
			if(!parse)
				n+=snprintf(&buf[n], len, "%s", p);
			else if(parse==1)
				n+=snprintf(&buf[n], len-n, "_%s", x_AUTO);
			else{
				if(index == 0)
					n+=snprintf(&buf[n], len-n, "_rxpause_txpause");
				else
					n+=snprintf(&buf[n], len-n, "_-rxpause_txpause");
				break;
			}
			parse++;
			p = strtok(NULL, "_");
		}
	}

	memset(portConfig[index].port_config, 0, sizeof(portConfig[index].port_config));
	snprintf(portConfig[index].port_config, sizeof(portConfig[index].port_config), "%s", buf);
	portConfig[index].changed = 1;
	needReboot = 1;
	return 1;
}

int get_DevicePortSpeed(int portno)
{
	char buffer[52], var[52];
	char *p;
	char *argv[5];
	unsigned int phy_status = switch_port_status((portno==0)?4:portno-1);

	if(!strcmp(portConfig[portno].port_config, "")) {
		if(portno == 0) {
			sprintf(var, "x_port_4_config");
			nvram_get_r_def(var, buffer, sizeof(buffer), "up_auto_rxpause_txpause");
		} else {
			sprintf(var, "x_port_%d_config", portno-1);
			nvram_get_r_def(var, buffer, sizeof(buffer), "up_auto_-rxpause_txpause");
		}
	} else
		snprintf(buffer, sizeof(buffer), "%s", portConfig[portno].port_config);

	if ((phy_status & PHF_LINKUP)) {
		if(phy_status & PHF_100M)
			return 2;
		else if(phy_status & PHF_500M)
			return 5;
		else if((phy_status & PHF_1000M))
			return 6;
		else
			return 1;
	} else {

		if((p = strstr(buffer, "speed")))
		{
			parse_line(buffer, argv, 5, "_");

			if(!strcmp(argv[4], "10"))
				return 1;
			else if (!strcmp(argv[4], "100"))
				return 2;
			//else if (!strcmp(argv[4], "200"))
			//	return 3;
			//else if (!strcmp(argv[4], "300"))
			//	return 4;
			else if (!strcmp(argv[4], "1000"))
				return 6;
		} else
			return 6;
	}
}

int set_DevicePortSpeed(int Mbyte, int index)
{
	char buffer[52], var[52], buf[52];
	int parse=0, n=0;
	int len = sizeof(buf);
	char *p;

	// [Mbyte] : 1 = 10M, 2 = 100M, 6 = 1G
	if(Mbyte != 1 && Mbyte != 2 && Mbyte != 6)
		return 0;

	if(!strcmp(portConfig[index].port_config, "")) {
		if(index == 0) {
			sprintf(var, "x_port_4_config");
			nvram_get_r_def(var, buffer, sizeof(buffer), "up_auto_rxpause_txpause");
		} else {
			sprintf(var, "x_port_%d_config", index-1);
			nvram_get_r_def(var, buffer, sizeof(buffer), "up_auto_-rxpause_txpause");
		}
	} else
		snprintf(buffer, sizeof(buffer), "%s", portConfig[index].port_config);

	if((p=strstr(buffer, "duplex"))){ //privious setting is force
		p = strtok(buffer, "_");
		while(p!=NULL){
			if(!parse) {
				n+=snprintf(&buf[n], len, "%s", p);
			} else if(parse==4) {
				switch(Mbyte) {
				case 1:
					n+=snprintf(&buf[n], len-n, "_%s", M10);
					break;
				case 2:
					n+=snprintf(&buf[n], len-n, "_%s", M100);
					break;
#if 0
				case 3:
					n+=snprintf(&buf[n], len-n, "_200");
					break;
				case 4:
					n+=snprintf(&buf[n], len-n, "_300");
					break;
				case 5:
					n+=snprintf(&buf[n], len-n, "_500");
					break;
#endif
				case 6:
					n+=snprintf(&buf[n], len-n, "_%s", M1000);
					break;
				default:
					return 0;
				}
			} else {
				n+=snprintf(&buf[n], len-n, "_%s", p);
			}
			parse++;
			p = strtok(NULL, "_");
		}
		memset(portConfig[index].port_config, 0, sizeof(portConfig[index].port_config));
		snprintf(portConfig[index].port_config, sizeof(portConfig[index].port_config), "%s", buf);
		portConfig[index].changed = 1;
	}
	needReboot = 1;
	return 1;
}

int get_DevicePortDuplex(int portno)
{
	char buffer[52], var[52];
	char *p;

	if(!strcmp(portConfig[portno].port_config, "")) {
		if(portno == 0) {
			sprintf(var, "x_port_4_config");
			nvram_get_r_def(var, buffer, sizeof(buffer), "up_auto_rxpause_txpause");
		} else {
			sprintf(var, "x_port_%d_config", portno-1);
			nvram_get_r_def(var, buffer, sizeof(buffer), "up_auto_-rxpause_txpause");
		}
	} else
		snprintf(buffer, sizeof(buffer), "%s", portConfig[portno].port_config);

	if((p=strstr(buffer, "duplex"))){
		if(strstr(p, "full"))
			return 2;
		else
			return 1;
	} else
		return 2;

}

int set_DevicePortDuplex(int plex, int index)
{
	char buffer[52], var[52], buf[52];
	int parse=0, n=0;
	int len = sizeof(buf);
	char *p;

	if(plex != 1 && plex !=2) //half, full
		return 0;

	if(!strcmp(portConfig[index].port_config, "")) {
		if(index == 0) {
			sprintf(var, "x_port_4_config");
			nvram_get_r_def(var, buffer, sizeof(buffer), "up_auto_rxpause_txpause");
		} else {
			sprintf(var, "x_port_%d_config", index-1);
			nvram_get_r_def(var, buffer, sizeof(buffer), "up_auto_-rxpause_txpause");
		}
	} else
		snprintf(buffer, sizeof(buffer), "%s", portConfig[index].port_config);

	if((p=strstr(buffer, "auto"))) //previous setting is auto
		return 1;
	//previous setting is force
	p = strtok(buffer, "_");
	while(p!=NULL){
		if(!parse)
			n+=snprintf(&buf[n], len, "%s", p);
		else if(parse==2)
			n+=snprintf(&buf[n], len-n, "_%s", (plex==1)? HALF:FULL);
		else
			n+=snprintf(&buf[n], len-n, "_%s", p);
		parse++;
		p = strtok(NULL, "_");
	}

	memset(portConfig[index].port_config, 0, sizeof(portConfig[index].port_config));
	snprintf(portConfig[index].port_config, sizeof(portConfig[index].port_config), "%s", buf);
	portConfig[index].changed = 1;
	needReboot = 1;

	return 1;
}


int get_DevicePortOnOff(int portno)
{
	char var[52];
	char *p;

	if(!strcmp(portConfig[portno].port_config, "")) {
		if(portno == 0) {
			sprintf(var, "x_port_4_config");
			nvram_get_r_def(var, portConfig[portno].port_config, sizeof(portConfig[portno].port_config), "up_auto_rxpause_txpause");
		} else {
			sprintf(var, "x_port_%d_config", portno-1);
			nvram_get_r_def(var, portConfig[portno].port_config, sizeof(portConfig[portno].port_config), "up_auto_-rxpause_txpause");
		}
	}

	if((p=strstr(portConfig[portno].port_config, "down")))
		return 2;
	else
		return 1;

}

int set_DevicePortOnOff(int power, int index)
{
	char buffer[52], var[52], buf[52];
	int parse=0, n=0;
	int len = sizeof(buf);
	char *p;

	if(power != 1 && power != 2) //on, off
		return 0;

	if(!strcmp(portConfig[index].port_config, "")) {
		if(index == 0) {
			sprintf(var, "x_port_4_config");
			nvram_get_r_def(var, buffer, sizeof(buffer), "up_auto_rxpause_txpause");
		} else {
			sprintf(var, "x_port_%d_config", index-1);
			nvram_get_r_def(var, buffer, sizeof(buffer), "up_auto_-rxpause_txpause");
		}
	} else
		snprintf(buffer, sizeof(buffer), "%s", portConfig[index].port_config);

	p = strtok(buffer, "_");
	while(p!=NULL){
		if(!parse)
			n+=snprintf(&buf[n], len, "%s", (power==1)? UP:DOWN);
		else
			n+=snprintf(&buf[n], len-n, "_%s", p);
		parse++;
		p = strtok(NULL, "_");
	}
	memset(portConfig[index].port_config, 0, sizeof(portConfig[index].port_config));
	snprintf(portConfig[index].port_config, sizeof(portConfig[index].port_config), "%s", buf);
	portConfig[index].changed = 1;
	needReboot = 1;
	return 1;
}

int get_lanStatus(int portno)
{
	struct phreq phr;
	int fd;

	if (portno < PH_MINPORT || portno > PH_MAXPORT)
		return -1;

	memset(&phr, 0, sizeof(phr));
	fd = open("/proc/brdio", O_RDWR);
	if (fd < 0)
		return -1;
	phr.phr_port = (portno==0)?4:portno-1;
	if (ioctl(fd, PHGIO, &phr))
		perror("PHGIO");
	close(fd);
	return ! !(phr.phr_optmask & PHF_LINKUP);

}

long get_currentChannel(void)
{
	FILE *fp;
	char buf[64], c[10], m[10], ch[10], *tok1, *tok2;
	long nch;


	fp = popen("wl channel", "r");

	fread(buf, 64, 1, fp);

	tok2 = buf;
	tok1 = strsep(&tok2, "\n");
	tok1 = strsep(&tok2, "\n");

	sscanf(tok1, "%s %s %s %s", c, m, ch, ch);

	nch = strtol(ch, NULL, 10);

	pclose(fp);

	return nch;
}

long get_channel(void)
{
	char *p = NULL;
	long ch;

	if (p != NULL)
		ch = strtoul(p, NULL, 10);
	else
		ch = 0;

	return ch;
}

void set_lanIPAddress(unsigned char *var_val, int var_val_len, Oid * name)
{
	lanConfig.IpAddr = *(unsigned int *)var_val;
	lanConfig.changed = 1;
}

int get_dhcpServer(void)
{
	char buf[5];
	int dhcpEnable = 2;

	if(lanConfig.dhcpEnable == 0) {
		snprintf(buf, sizeof(buf), "%s", getValue("DHCP"));
		switch (buf[0]) {
			case '0':                  //disable
				dhcpEnable = 2;
				break;
			case '2':                  // dhcp Server Mode
				dhcpEnable = 1;
				break;
		}
	} else
		dhcpEnable = lanConfig.dhcpEnable;

	return dhcpEnable;
}

int set_dhcpServer(int res)
{
	if(res != 1 && res != 2)
		return 0;

	lanConfig.dhcpEnable = res;
	lanConfig.changed = 1;
	return 1;
}

void get_ipPoolStartAddress(long *addr)
{
	char buf[20];
	struct in_addr ia;

	memset(buf, 0, sizeof(buf));
	if(lanConfig.dhcpStartIp == 0)
		snprintf(buf, sizeof(buf), "%s", getValue("DHCP_CLIENT_START"));
	else {
		ia.s_addr = htonl(lanConfig.dhcpStartIp);
		snprintf(buf, sizeof(buf), "%s", inet_ntoa(ia));
	}
	*addr = inet_addr(buf);
}

int set_ipPoolStartAddress(long var)
{
	char buf[20];
	char *dot1, *dot2, *dot3, *tok;

	inet_ntop(AF_INET, &var, buf, sizeof(buf));

	tok = buf;
	dot1 = strsep(&tok, ".");   //rest of tok *.*.*
	if (tok == NULL) {
		return 0;
	}

	dot2 = strsep(&tok, ".");   //rest of tok *.*
	if (tok == NULL) {
		return 0;
	}

	dot3 = strsep(&tok, ".");   //rest of tok *
	if (tok == NULL) {
		return 0;
	}

	lanConfig.dhcpStartIp = var;
	lanConfig.changed = 1;
	return 1;
}

void get_ipPoolEndAddress(long *addr)
{
	char buf[20];
	struct in_addr ia;

	if(lanConfig.dhcpEndIp == 0)
		snprintf(buf, sizeof(buf), "%s", getValue("DHCP_CLIENT_END"));
	else {
		ia.s_addr = htonl(lanConfig.dhcpEndIp);
		snprintf(buf, sizeof(buf), "%s", inet_ntoa(ia));
	}

	*addr = inet_addr(buf);
}

int set_ipPoolEndAddress(long var)
{
	char *tok;
	char *dot1, *dot2, *dot3;
	char buf[16];

	inet_ntop(AF_INET, &var, buf, sizeof(buf));

	tok = buf;
	dot1 = strsep(&tok, ".");   //rest of tok *.*.*
	if (tok == NULL) {
		return 0;
	}

	dot2 = strsep(&tok, ".");   //rest of tok *.*
	if (tok == NULL) {
		return 0;
	}

	dot3 = strsep(&tok, ".");   //rest of tok *
	if (tok == NULL) {
		return 0;
	}

	//if(lanConfig.dhcpEndIp >= lanConfig.dhcpStartIp){
	if(var <= lanConfig.dhcpStartIp){
		printf("Invalid DHCP End IP\n");
		return 0;
	}

	lanConfig.dhcpEndIp = var;
	lanConfig.changed = 1;
	return 1;
}

int get_snmpEnable()
{
	int res;
	if(SNMPConfig.snmpEnable == 0) {
		res = nvram_atoi("x_SNMP_ENABLE", 1);
		if (res == 1)
			return 1;
		else if (res == 0)
			return 2;
	} else
		return SNMPConfig.snmpEnable;
}

int set_snmpEnable(int res)
{
	if (res != 1 && res != 2)
		return 0;

	SNMPConfig.snmpEnable = res;
	SNMPConfig.commchanged = 1;
	return 1;
}

extern void set_getcommunity(const char *);
extern void set_setcommunity(const char *);
long get_CommunityAdmin(int index, COM_T *com)
{
	int snmp_index = index+1;
	int res;
	char buf[8];

	if(snmp_index == 1) {
		if(SNMPConfig.getcommAdmin == 0) {
			nvram_get_r_def("x_SNMP_COM1", buf, sizeof(buf), "1_0");
			res = atoi(&buf[0]);
		} else {
			if(SNMPConfig.getcommAdmin == 1)
				res = 1;
			else
				res = 0;
		}
	} else {
		if(SNMPConfig.setcommAdmin == 0) {
			nvram_get_r_def("x_SNMP_COM2", buf, sizeof(buf), "1_1");
			res = atoi(&buf[0]);
		} else {
			if(SNMPConfig.setcommAdmin == 1)
				res = 1;
			else
				res = 0;
		}
	}
	return (long)res;
}

long get_CommunityType(int index, COM_T *com)
{
	int snmp_index = index+1;
	char buf[8];
	int res;

	if(snmp_index == 1) {
		if(SNMPConfig.getcommType == 0) {
			nvram_get_r_def("x_SNMP_COM1", buf, sizeof(buf), "1_0");
			res = atoi(&buf[2]);
		} else {
			if(SNMPConfig.getcommType == 1)
				res = 1;
			else
				res = 0;
		}
	} else {
		if(SNMPConfig.setcommType == 0) {
			nvram_get_r_def("x_SNMP_COM2", buf, sizeof(buf), "1_1");
			res = atoi(&buf[2]);
		} else {
			if(SNMPConfig.setcommType == 1)
				res = 1;
			else
				res = 0;
		}
	}

	return (long)res;
}

void get_CommunityName(char *str, int len, int index, COM_T *com)
{
	int snmp_index = index+1;

	if(snmp_index == 1) {
		if(!strcmp(SNMPConfig.getcommName, ""))
			nvram_get_r_def("x_SNMP_GET_COMMUNITY", str, len, "iptvshro^_");
		else
			snprintf(str, MAX_SNMP_STR, "%s", SNMPConfig.getcommName);
	} else {
		if(!strcmp(SNMPConfig.setcommName, ""))
			nvram_get_r_def("x_SNMP_SET_COMMUNITY", str, len, "iptvshrw^_");
		else
			snprintf(str, MAX_SNMP_STR, "%s", SNMPConfig.setcommName);
	}
}

int set_CommunityName(unsigned char *str, int len, int index)
{
	char *p = (char *)str;
	int snmp_index = index + 1;

	if(p == NULL || len == 0 || len < 8 || len > 22)
		return 0;

	if(snmp_index == 1)
		snprintf(SNMPConfig.getcommName, sizeof(SNMPConfig.getcommName), "%s", p);
	else
		snprintf(SNMPConfig.setcommName, sizeof(SNMPConfig.setcommName), "%s", p);

	SNMPConfig.commchanged = 1;

	return 1;
}

int set_CommunityType(int index, int type)
{
	int snmp_index = index+1;

	if ( type != 0 && type != 1 )
		return 0;

	if(type == 0)
		type = 2;

	if(snmp_index == 1)
		SNMPConfig.getcommType = type;
	else
		SNMPConfig.setcommType = type;

	SNMPConfig.commchanged = 1;
	return 1;
}

int set_CommunityAdmin(int index, int enable)
{
	int snmp_index = index + 1;

	if(enable != 0 && enable != 1)
		return 0;

	if(enable == 0)
		enable = 2;

	if(snmp_index == 1)
		SNMPConfig.getcommAdmin = enable;
	else
		SNMPConfig.setcommAdmin = enable;

	SNMPConfig.commchanged = 1;
	return 1;
}

void get_snmpTrapDestination(int index, unsigned char *trapServer, int len)
{
	if(!strcmp(SNMPConfig.trapDest[index], "")) {
		if (index == 0)
			nvram_get_r_def("x_SNMP_TRAP_SERVER", trapServer, len, "iptvsh-trap.skbroadband.com");
		else if (index == 1)
			nvram_get_r_def("x_WIFI_TRAP_SERVER", trapServer, len, "iptvap-trap.skbroadband.com");
		else if (index == 2)
			nvram_get_r_def("x_cpeping_trap_server", trapServer, len, "iptvap-trap3.skbroadband.com");
		else if (index == 3)
			nvram_get_r_def("x_autoreboot_trap_server", trapServer, len, "iptvap-trap4.skbroadband.com");
		else if (index == 4)
			nvram_get_r_def("x_portlink_trap_server", trapServer, len, "iptvap-trap5.skbroadband.com");
		else if (index == 5)
			nvram_get_r_def("x_limitedSession_trap_server", trapServer, len, "iptvap-trap6.skbroadband.com");
		else if (index == 6)
			nvram_get_r_def("x_smartReset_trap_server", trapServer, len, "iptvap-trap7.skbroadband.com");
		else if (index == 7)
			nvram_get_r_def("x_autobandwidth_trap_server", trapServer, len, "iptvap-trap9.skbroadband.com");
		else if (index == 8)
			nvram_get_r_def("x_handover_trap_server", trapServer, len, "iptvap-trap9.skbroadband.com");
		else if (index == 9)
			nvram_get_r_def("x_ntp_trap_server", trapServer, len, "iptvap-trap10.skbroadband.com");
		else
			nvram_get_r_def("x_sitesurvey_trap_server", trapServer, len, "iptvap-trap11.skbroadband.com");
	} else
		snprintf(trapServer, MAX_SNMP_STR, "%s", SNMPConfig.trapDest[index]);
}

int set_snmpTrapDestination(int index, unsigned char *trapServer, int var_len)
{
	if (var_len == 0)
		return 0;

	snprintf(SNMPConfig.trapDest[index], sizeof(SNMPConfig.trapDest[index]), "%s", trapServer);
	SNMPConfig.trapSrvchanged[index] = 1;
	return 1;
}

void get_snmpTrapCommunityName(unsigned char *strVal)
{
	char buf[128];

	if(!strcmp(SNMPConfig.trapName, "")) {
		nvram_get_r_def("x_SNMP_TRAP_COMMUNITY", buf, sizeof(buf), "iptvshrw^_");
		snprintf((char*)strVal, MAX_SNMP_STR, "%s", buf);
	} else
		snprintf((char*)strVal, MAX_SNMP_STR, "%s", SNMPConfig.trapName);
}

int set_snmpTrapCommunityName(unsigned char *strVal, int var_len)
{
	char *p = (char *)strVal;

	if (var_len == 0 || var_len < 8 || var_len > 22)
		return 0;

	snprintf(SNMPConfig.trapName, sizeof(SNMPConfig.trapName), "%s", p);
	SNMPConfig.trapchanged = 1;
	return 1;
}

int get_snmpTrapDestinationAdmin()
{
	int val;

	if(SNMPConfig.trapAdmin == 0)
		val = nvram_atoi("x_SNMP_TRAP_ENABLE", 1);
	else {
		if(SNMPConfig.trapAdmin == 1)
			val = 1;
		else
			val = 0;
	}

	return val;
}

int set_snmpTrapDestinationAdmin(int res)
{
	if (res != 0 && res != 1)
		return 0;

	if(res == 0)
		res = 2;

	SNMPConfig.trapAdmin = res;
	SNMPConfig.trapchanged = 1;
	return 1;
}

void set_autoTransmission(unsigned char *var_val, int var_val_len)
{
	struct in_addr ia;
	unsigned char *p = var_val;

	ia.s_addr = *(unsigned int *)p;

	sendAutoTransmission();
}

extern struct sockaddr_in snmp_src_ipaddr;      //neon20

int set_faultreset(int res)
{
	if (res == 1) {
		snmpAction = SNMP_REBOOT;
		return 1;
	} else {
		return 0;
	}
}

int set_HardWareReset(int res)
{
	if (res == 1) {
		yecho("/proc/gpio", "R\n");
		return 1;
	} else {
		return 0;
	}
}

void SaveWanConfig()
{
	char ipAddr[16];
	int old_wanMode;
	int wanChanged = 0;
	int enabled;
	unsigned char buf[40];

	if(wanConfig.changed == 0)
		return;
	wanConfig.changed = 0;

	old_wanMode = atoi(getValue("WAN_DHCP"));
	if (old_wanMode != 1)
		old_wanMode = 2;

	if (wanConfig.obtainedMethod != old_wanMode)
		wanChanged = 1;

	if (wanConfig.obtainedMethod == 1) {
		enabled = 1;
		setValue_mib(MIB_WAN_DHCP, (void*)&enabled);
	} else if (wanConfig.obtainedMethod == 2) {
		int old_ip;
		struct in_addr in;

		if (wanConfig.IpAddr == 0) {
			getInAddr("eth1", IP_ADDR, &wanConfig.IpAddr);
		}

		// Manual DNS Mode
		if (wanConfig.autoDNS == 1 && wanConfig.DNS[1] == 0) {
			yfcat("/etc/resolv.conf", "%*[^\n] %*s %s", buf);
			if (inet_aton(buf, &in))
				wanConfig.DNS[1]= in.s_addr;
		}

		if (wanConfig.subnetMask == 0) {
			yfcat("/var/netmask", "%s", buf);
			if (inet_aton(buf, &in))
				wanConfig.subnetMask = in.s_addr;
		}

		if (wanConfig.defGateway == 0) {
			yfcat("/var/gateway", "%s", buf);
			if (inet_aton(buf, &in))
				wanConfig.defGateway = in.s_addr;
		}

		enabled = 0;
		setValue_mib(MIB_WAN_DHCP, (void*)&enabled);
		snprintf(ipAddr, sizeof(ipAddr), "%s", getValue("WAN_IP_ADDR"));
		old_ip = inet_addr(ipAddr);
		if (wanConfig.IpAddr != old_ip)
			wanChanged = 1;
		setValue_mib(MIB_WAN_IP_ADDR, (void*)&wanConfig.IpAddr);
		setValue_mib(MIB_WAN_SUBNET_MASK, (void*)&wanConfig.subnetMask);
		setValue_mib(MIB_WAN_DEFAULT_GATEWAY, (void*)&wanConfig.defGateway);
	}

	if (wanConfig.autoDNS) {
		enabled = 1;
	} else {
		enabled = 0;
	}
	setValue_mib(MIB_DNS_MODE, (void*)&enabled);
#if 0
	if (wanConfig.DNS[0] != 0) {
		setValue_mib(MIB_DNS1, &wanConfig.DNS[0]);
	}
#endif
	if (wanConfig.DNS[1] != 0) {
		setValue_mib(MIB_DNS2, (void*)&wanConfig.DNS[1]);
	}

	yexecl("> /var/wanChanged", "echo %d", wanChanged);
	return;
}

void SaveLanConfig()
{
	unsigned char buf[40];
	struct in_addr in;
	int enabled;

	if(lanConfig.changed == 0)
		return;
	lanConfig.changed = 0;

	if (lanConfig.dhcpEnable == 1) {
		enabled = 2;
	} else if (lanConfig.dhcpEnable == 2) {
		enabled = 0;
	} else {
		enabled = nvram_atoi("DHCP", 2);
	}

	if (lanConfig.IpAddr == 0) {
		getInAddr("br0", IP_ADDR, &lanConfig.IpAddr);
	}

	if (lanConfig.subnetMask == 0) {
		nvram_get_r_def("SUBNET_MASK", buf, sizeof(buf), "255.255.255.0");
		if (inet_aton(buf, &in))
			lanConfig.subnetMask = in.s_addr;
	}

	if (lanConfig.dhcpStartIp== 0) {
		nvram_get_r_def("DHCP_CLIENT_START", buf, sizeof(buf), "192.168.35.2");
		if (inet_aton(buf, &in))
			lanConfig.dhcpStartIp = in.s_addr;
	}

	if (lanConfig.dhcpEndIp == 0) {
		nvram_get_r_def("DHCP_CLIENT_END", buf, sizeof(buf), "192.168.35.254");
		if (inet_aton(buf, &in))
			lanConfig.dhcpEndIp= in.s_addr;
	}

	setValue_mib(MIB_DHCP, (void*)&enabled);
	setValue_mib(MIB_IP_ADDR, (void*)&lanConfig.IpAddr);
	setValue_mib(MIB_SUBNET_MASK, (void*)&lanConfig.subnetMask);
	setValue_mib(MIB_DHCP_CLIENT_START, (void*)&lanConfig.dhcpStartIp);
	setValue_mib(MIB_DHCP_CLIENT_END, (void*)&lanConfig.dhcpEndIp);

	return;
}

void SaveWlanBasicConfig()
{
	int index, enabled = 1, disabled = 0;
	int bonding;
	char buf[40];
	char bonding_buf[32], session_buf[32];

	vwlan_idx = 0;

	for(index = 0; index < 2; index++) {
		wlan_idx = index;
		if(wlanBasicConfig[index].changed == 0)
			continue;
		wlanBasicConfig[index].changed = 0;

		if (wlanBasicConfig[index].wlanMode == 1) {
			wlanBasicConfig[index].wlanMode = 0;
		} else if (wlanBasicConfig[index].wlanMode == 2) {
			wlanBasicConfig[index].wlanMode = 1;
		} else {
			snprintf(buf, sizeof(buf), "WLAN%d_WLAN_DISABLED", index);
			wlanBasicConfig[index].wlanMode = nvram_atoi(buf, 0);
		}
		setValue_mib(MIB_WLAN_WLAN_DISABLED, (void*)&wlanBasicConfig[index].wlanMode);
		if(index == 1) {		// Sync handover SSID Enable/Disable
			snprintf(buf, sizeof(buf), "%d", wlanBasicConfig[index].wlanMode);
			setValue("WLAN0_VAP3_WLAN_DISABLED", buf);
		}

		if (wlanBasicConfig[index].wlanBand == 0) {
			snprintf(buf, sizeof(buf), "WLAN%d_BAND", index);
			if(index == 0)
				wlanBasicConfig[index].wlanBand = nvram_atoi(buf, 76);
			else
				wlanBasicConfig[index].wlanBand = nvram_atoi(buf, 11);
		}
		setValue_mib(MIB_WLAN_BAND, (void*)&wlanBasicConfig[index].wlanBand);

		snprintf(buf, sizeof(buf), "WLAN%d_CHANNEL_BONDING", index);
		bonding = nvram_atoi(buf, 0);
		if (wlanBasicConfig[index].wlanBonding == 0)
			wlanBasicConfig[index].wlanBonding = bonding;
		else
			wlanBasicConfig[index].wlanBonding -= 1;

		snprintf(bonding_buf, sizeof(bonding_buf), "x_wlan%d_auto_bonding", index);
		if (wlanBasicConfig[index].wlanAutoBonding == 1) {
			setValue(bonding_buf, "1");
			setValue_mib(MIB_WLAN_CHANNEL_BONDING, (void*)&bonding);
		} else if (wlanBasicConfig[index].wlanAutoBonding == 2) {
			setValue(bonding_buf, "0");
			setValue_mib(MIB_WLAN_CHANNEL_BONDING, (void*)&wlanBasicConfig[index].wlanBonding);
		} else {
			nvram_get_r_def(bonding_buf, buf, sizeof(buf), "1");
			setValue(bonding_buf, buf);
			if(!strcmp(buf, "0"))
				setValue_mib(MIB_WLAN_CHANNEL_BONDING, (void*)&wlanBasicConfig[index].wlanBonding);
		}

		if(index == 1) {
			if (wlanBasicConfig[index].CtrlSideBand == 1) {
				wlanBasicConfig[index].CtrlSideBand = 0;
			} else if (wlanBasicConfig[index].CtrlSideBand == 2) {
				wlanBasicConfig[index].CtrlSideBand = 1;
			} else {
				wlanBasicConfig[index].CtrlSideBand = nvram_atoi("WLAN1_CONTROL_SIDEBAND", 0);
			}
			setValue_mib(MIB_WLAN_CONTROL_SIDEBAND, (void*)&wlanBasicConfig[index].CtrlSideBand);
		}

		if (wlanBasicConfig[index].channelNumber == 0) {
			snprintf(buf, sizeof(buf), "WLAN%d_CHANNEL", index);
			wlanBasicConfig[index].channelNumber = nvram_atoi(buf, 0);
		} else if (wlanBasicConfig[index].channelNumber == -1) {		// auto channel
			wlanBasicConfig[index].channelNumber = 0;
		}
		setValue_mib(MIB_WLAN_CHANNEL, (void*)&wlanBasicConfig[index].channelNumber);

		if (wlanBasicConfig[index].DataRate == 0) {
			snprintf(buf, sizeof(buf), "WLAN%d_RATE_ADAPTIVE_ENABLED", index);
			if(nvram_atoi(buf, 1) == 0)	{
				snprintf(buf, sizeof(buf), "WLAN%d_FIX_RATE", index);
				wlanBasicConfig[index].DataRate = nvram_atoi(buf, 0);
			} else {										// auto data rate
				wlanBasicConfig[index].DataRate = 0;
			}
		} else if (wlanBasicConfig[index].DataRate == -1) {		// auto data rate
			wlanBasicConfig[index].DataRate = 0;
		}
		setValue_mib(MIB_WLAN_FIX_RATE, (void*)&wlanBasicConfig[index].DataRate);
		if (wlanBasicConfig[index].DataRate == 0)
			setValue_mib(MIB_WLAN_RATE_ADAPTIVE_ENABLED, (void*)&enabled);
		else
			setValue_mib(MIB_WLAN_RATE_ADAPTIVE_ENABLED, (void*)&disabled);

		snprintf(session_buf, sizeof(session_buf), "x_snmp_wl%dslimit", index);
		if (wlanBasicConfig[index].sessionLimit == 0) {
			nvram_get_r_def(session_buf, buf, sizeof(buf), "10");
		} else {
			snprintf(buf, sizeof(buf), "%d", wlanBasicConfig[index].sessionLimit);
		}
		setValue(session_buf, buf);
	}
}

void SaveMultiSSIDConfig()
{
	int root_idx, multi_idx;
	char buf[64], var[64];

	for(root_idx = 0; root_idx < 2; root_idx++) {
		for(multi_idx = 0; multi_idx < 5; multi_idx++) {
			wlan_idx = root_idx;
			vwlan_idx = multi_idx;
			if(wlanMultiConfig[multi_idx][root_idx].changed == 0)
				continue;
			wlanMultiConfig[multi_idx][root_idx].changed = 0;

			if(wlanMultiConfig[multi_idx][root_idx].ssidMode == 1)
				wlanMultiConfig[multi_idx][root_idx].ssidMode = 0;
			else if(wlanMultiConfig[multi_idx][root_idx].ssidMode == 2)
				wlanMultiConfig[multi_idx][root_idx].ssidMode = 1;
			else {
				if(multi_idx == 0)
					snprintf(buf, sizeof(buf), "WLAN%d_WLAN_DISABLED", root_idx);
				else
					snprintf(buf, sizeof(buf), "WLAN%d_VAP%d_WLAN_DISABLED", root_idx, multi_idx-1);
				wlanMultiConfig[multi_idx][root_idx].ssidMode = nvram_atoi(buf, "1");
			}
			setValue_mib(MIB_WLAN_WLAN_DISABLED, (void*)&wlanMultiConfig[multi_idx][root_idx].ssidMode);
			if(root_idx == 1 && multi_idx == 0) {		// Sync handover SSID
				snprintf(buf, sizeof(buf), "%d", wlanMultiConfig[multi_idx][root_idx].ssidMode);
				setValue("WLAN0_VAP3_WLAN_DISABLED", buf);
			}

			if(!strcmp(wlanMultiConfig[multi_idx][root_idx].ssid, "")) {
				if(multi_idx == 0)
					snprintf(buf, sizeof(buf), "WLAN%d_SSID", root_idx);
				else
					snprintf(buf, sizeof(buf), "WLAN%d_VAP%d_SSID", root_idx, multi_idx-1);
				nvram_get_r_def(buf, var, sizeof(var), "");
				snprintf(wlanMultiConfig[multi_idx][root_idx].ssid, sizeof(wlanMultiConfig[multi_idx][root_idx].ssid), "%s", var);
			}
			setValue_mib(MIB_WLAN_SSID, (void*)wlanMultiConfig[multi_idx][root_idx].ssid);

			if(wlanMultiConfig[multi_idx][root_idx].bssid == 1)
				wlanMultiConfig[multi_idx][root_idx].bssid = 0;
			else if(wlanMultiConfig[multi_idx][root_idx].bssid == 2)
				wlanMultiConfig[multi_idx][root_idx].bssid = 1;
			else {
				if(multi_idx == 0)
					snprintf(buf, sizeof(buf), "WLAN%d_HIDDEN_SSID", root_idx);
				else
					snprintf(buf, sizeof(buf), "WLAN%d_VAP%d_HIDDEN_SSID", root_idx, multi_idx-1);
				wlanMultiConfig[multi_idx][root_idx].bssid = nvram_atoi(buf, 0);
			}
			setValue_mib(MIB_WLAN_HIDDEN_SSID, (void*)&wlanMultiConfig[multi_idx][root_idx].bssid);

			if(wlanMultiConfig[multi_idx][root_idx].enc == 0) {
				if(multi_idx == 0)
					snprintf(buf, sizeof(buf), "WLAN%d_ENCRYPT", root_idx);
				else
					snprintf(buf, sizeof(buf), "WLAN%d_VAP%d_ENCRYPT", root_idx, multi_idx-1);
				wlanMultiConfig[multi_idx][root_idx].enc = nvram_atoi(buf, 6);
			} else {
				switch (wlanMultiConfig[multi_idx][root_idx].enc) {
					case 1:			// disable
						wlanMultiConfig[multi_idx][root_idx].enc = 0;
						break;
					case 2:			// wep
						wlanMultiConfig[multi_idx][root_idx].enc = 1;
						break;
					case 3:			// wpa
						wlanMultiConfig[multi_idx][root_idx].enc = 2;
						break;
					case 4:			// wpa2
						wlanMultiConfig[multi_idx][root_idx].enc = 4;
						break;
					case 5:			// wpa-mixed
						wlanMultiConfig[multi_idx][root_idx].enc = 6;
						break;
				}
			}
			setValue_mib(MIB_WLAN_ENCRYPT, (void*)&wlanMultiConfig[multi_idx][root_idx].enc);

			if(wlanMultiConfig[multi_idx][root_idx].ratelimit == 0) {
				if(multi_idx == 0)
					snprintf(buf, sizeof(buf), "WLAN%d_TX_RESTRICT", root_idx);
				else
					snprintf(buf, sizeof(buf), "WLAN%d_VAP%d_TX_RESTRICT", root_idx, multi_idx-1);
				wlanMultiConfig[multi_idx][root_idx].ratelimit = nvram_atoi(buf, 0);
			}
			setValue_mib(MIB_WLAN_TX_RESTRICT, (void*)&wlanMultiConfig[multi_idx][root_idx].ratelimit);
			setValue_mib(MIB_WLAN_RX_RESTRICT, (void*)&wlanMultiConfig[multi_idx][root_idx].ratelimit);
		}
	}
}

void SaveWlanAdvConfig()
{
	char buf[64];
	int i;

	vwlan_idx = 0;

	for(i = 0; i < 2; i++) {
		wlan_idx = i;
		if(wlanAdvConfig[i].changed == 0)
			continue;
		wlanAdvConfig[i].changed = 0;

		if(wlanAdvConfig[i].frag_threshold == 0) {
			snprintf(buf, sizeof(buf), "WLAN%d_FRAG_THRESHOLD", i);
			wlanAdvConfig[i].frag_threshold = nvram_atoi(buf, 2346);
		}
		setValue_mib(MIB_WLAN_FRAG_THRESHOLD, (void*)&wlanAdvConfig[i].frag_threshold);

		if(wlanAdvConfig[i].rts_threshold== 0) {
			snprintf(buf, sizeof(buf), "WLAN%d_RTS_THRESHOLD", i);
			wlanAdvConfig[i].rts_threshold = nvram_atoi(buf, 2347);
		}
		setValue_mib(MIB_WLAN_RTS_THRESHOLD, (void*)&wlanAdvConfig[i].rts_threshold);

		if(wlanAdvConfig[i].beacon_intv == 0) {
			snprintf(buf, sizeof(buf), "WLAN%d_BEACON_INTERVAL", i);
			wlanAdvConfig[i].beacon_intv = nvram_atoi(buf, 100);
		}
		setValue_mib(MIB_WLAN_BEACON_INTERVAL, (void*)&wlanAdvConfig[i].beacon_intv);

		if(wlanAdvConfig[i].preamble_type == 1)
			wlanAdvConfig[i].preamble_type = 0;
		else if(wlanAdvConfig[i].preamble_type == 2)
			wlanAdvConfig[i].preamble_type =1;
		else {
			snprintf(buf, sizeof(buf), "WLAN%d_PREAMBLE_TYPE", i);
			wlanAdvConfig[i].preamble_type = nvram_atoi(buf, 0);
		}
		setValue_mib(MIB_WLAN_PREAMBLE_TYPE, (void*)&wlanAdvConfig[i].preamble_type);

		if(wlanAdvConfig[i].iapp == 1)
			wlanAdvConfig[i].iapp = 0;
		else if(wlanAdvConfig[i].iapp == 2)
			wlanAdvConfig[i].iapp = 1;
		else {
			snprintf(buf, sizeof(buf), "WLAN%d_IAPP_DISABLED", i);
			wlanAdvConfig[i].iapp = nvram_atoi(buf, 1);
		}
		setValue_mib(MIB_WLAN_IAPP_DISABLED, (void*)&wlanAdvConfig[i].iapp);

		if(wlanAdvConfig[i].rfoutpwr == 0) {
			snprintf(buf, sizeof(buf), "WLAN%d_RFPOWER_SCALE", i);
			wlanAdvConfig[i].rfoutpwr = nvram_atoi(buf, 0);
		} else {
			switch (wlanAdvConfig[i].rfoutpwr) {
				case 100:
					wlanAdvConfig[i].rfoutpwr = 0;
					break;
				case 70:
					wlanAdvConfig[i].rfoutpwr = 1;
					break;
				case 50:
					wlanAdvConfig[i].rfoutpwr = 2;
					break;
				case 35:
					wlanAdvConfig[i].rfoutpwr = 3;
					break;
				case 15:
					wlanAdvConfig[i].rfoutpwr = 4;
					break;
			}
		}
		setValue_mib(MIB_WLAN_RFPOWER_SCALE, (void*)&wlanAdvConfig[i].rfoutpwr);
	}
}

long get_wlanMode(int index)
{
	char buf[5], param[32];
	int mode;

	if(wlanBasicConfig[index].wlanMode == 0) {
		memset(param, 0, sizeof(param));
		sprintf(param, "WLAN%d_WLAN_DISABLED", index);
		nvram_get_r_def(param, buf, sizeof(buf), "0");

		mode = atoi(buf);

		if (mode == 0)
			return 1;
		else if (mode == 1)
			return 2;
	} else
		return wlanBasicConfig[index].wlanMode;
}

void SaveRadiusConfig(int root_idx, int multi_idx)
{
	char buf[64], val[64];

	if(multi_idx == 0)
		snprintf(buf, sizeof(buf), "WLAN%d_RS_IP", root_idx);
	else
		snprintf(buf, sizeof(buf), "WLAN%d_VAP%d_RS_IP", root_idx, multi_idx-1);
	if(securityConfig[root_idx].secRadiusConfig[multi_idx].radiusIP == 0)
		nvram_get_r_def(buf, val, sizeof(val), "0.0.0.0");
	else
		inet_ntop(AF_INET, &securityConfig[root_idx].secRadiusConfig[multi_idx].radiusIP, val, sizeof(val));
	setValue(buf, val);

	if(securityConfig[root_idx].secRadiusConfig[multi_idx].radiusPort == 0) {
		if(multi_idx == 0)
			snprintf(buf, sizeof(buf), "WLAN%d_RS_PORT", root_idx);
		else
			snprintf(buf, sizeof(buf), "WLAN%d_VAP%d_RS_PORT", root_idx, multi_idx-1);
		securityConfig[root_idx].secRadiusConfig[multi_idx].radiusPort = nvram_atoi(buf, 1812);
	}
	setValue_mib(MIB_WLAN_RS_PORT, (void*)&securityConfig[root_idx].secRadiusConfig[multi_idx].radiusPort);

	if(multi_idx == 0)
		snprintf(buf, sizeof(buf), "WLAN%d_RS_PASSWORD", root_idx);
	else
		snprintf(buf, sizeof(buf), "WLAN%d_VAP%d_RS_PASSWORD", root_idx, multi_idx-1);
	if(!strcmp(securityConfig[root_idx].secRadiusConfig[multi_idx].radiusPasswd, ""))
		nvram_get_r_def(buf, val, sizeof(val), "");
	else
		snprintf(val, sizeof(val), "%s", securityConfig[root_idx].secRadiusConfig[multi_idx].radiusPasswd);
	setValue(buf, val);

	if(securityConfig[root_idx].secRadiusConfig[multi_idx].serverMode == 1)
		securityConfig[root_idx].secRadiusConfig[multi_idx].serverMode = 1;
	else if(securityConfig[root_idx].secRadiusConfig[multi_idx].serverMode == 2)
		securityConfig[root_idx].secRadiusConfig[multi_idx].serverMode = 0;
	else {
		if(multi_idx == 0)
			snprintf(buf, sizeof(buf), "WLAN%d_ACCOUNT_RS_ENABLED", root_idx);
		else
			snprintf(buf, sizeof(buf), "WLAN%d_VAP%d_ACCOUNT_RS_ENABLED", root_idx, multi_idx-1);
		securityConfig[root_idx].secRadiusConfig[multi_idx].serverMode = nvram_atoi(buf, 0);
	}
	setValue_mib(MIB_WLAN_ACCOUNT_RS_ENABLED, (void*)&securityConfig[root_idx].secRadiusConfig[multi_idx].serverMode);

	if(multi_idx == 0)
		snprintf(buf, sizeof(buf), "WLAN%d_ACCOUNT_RS_IP", root_idx);
	else
		snprintf(buf, sizeof(buf), "WLAN%d_VAP%d_ACCOUNT_RS_IP", root_idx, multi_idx-1);
	if(securityConfig[root_idx].secRadiusConfig[multi_idx].accountIP == 0)
		nvram_get_r_def(buf, val, sizeof(val), "0.0.0.0");
	else
		inet_ntop(AF_INET, &securityConfig[root_idx].secRadiusConfig[multi_idx].accountIP, val, sizeof(val));
	setValue(buf, val);

	if(securityConfig[root_idx].secRadiusConfig[multi_idx].accountPort == 0) {
		if(multi_idx == 0)
			snprintf(buf, sizeof(buf), "WLAN%d_ACCOUNT_RS_PORT", root_idx);
		else
			snprintf(buf, sizeof(buf), "WLAN%d_VAP%d_ACCOUNT_RS_PORT", root_idx, multi_idx-1);
		securityConfig[root_idx].secRadiusConfig[multi_idx].accountPort = nvram_atoi(buf, 1813);
	}
	setValue_mib(MIB_WLAN_ACCOUNT_RS_PORT, (void*)&securityConfig[root_idx].secRadiusConfig[multi_idx].accountPort);

	if(multi_idx == 0)
		snprintf(buf, sizeof(buf), "WLAN%d_ACCOUNT_RS_PASSWORD", root_idx);
	else
		snprintf(buf, sizeof(buf), "WLAN%d_VAP%d_ACCOUNT_RS_PASSWORD", root_idx, multi_idx-1);
	if(!strcmp(securityConfig[root_idx].secRadiusConfig[multi_idx].accountPasswd, "") )
		nvram_get_r_def(buf, val, sizeof(val), "");
	else
		snprintf(val, sizeof(val), "%s", securityConfig[root_idx].secRadiusConfig[multi_idx].accountPasswd);
	setValue(buf, val);
}

int SaveSecurityConfig()
{
	int i;
	char buf[32];
	char param[32];
	int keyLength;
	int j;
	int disabled=0, wep_index=1, wpa_index=2, wpa2_index=4, wpamix_index=6;
	int intVal;

	for (j = 2; j > 0; j--){
		for (i = 0; i < MAX_SSID; i++) {

			if (securityConfig[j - 1].changed[i] == 0)
				continue;
			securityConfig[j - 1].changed[i] = 0;  // reset flag changed.
			wlan_idx = j - 1;
			vwlan_idx = i;
			SaveRadiusConfig(j - 1, i);
			switch (securityConfig[j - 1].securityMode[i]) {
				case 0:
					setValue_mib(MIB_WLAN_ENCRYPT, (void*)&disabled);
					break;
				case 1:
					setValue_mib(MIB_WLAN_ENCRYPT, (void*)&wep_index);

					sprintf(buf, "%d", securityConfig[j - 1].secWEPConfig[i].WEP8021xAuthMode);
					intVal = atoi(buf);
					setValue_mib(MIB_WLAN_ENABLE_1X, (void*)&intVal);


					sprintf(buf, "%d", securityConfig[j - 1].secWEPConfig[i].WEPMacAuthMode);
					intVal = atoi(buf);
					setValue_mib(MIB_WLAN_MAC_AUTH_ENABLED, (void*)&intVal);

					sprintf(buf, "%d", securityConfig[j - 1].secWEPConfig[i].WEPAuthMethod);
					intVal = atoi(buf);
					setValue_mib(MIB_WLAN_AUTH_TYPE, (void*)&intVal);
					if (securityConfig[j - 1].secWEPConfig[i].WEPAuthEnable == 0) {
						setValue_mib(MIB_WLAN_WEP, (void*)&disabled);
						continue;
					} else {
						sprintf(buf, "%d", securityConfig[j - 1].secWEPConfig[i].WEPAuthKeySize);
						intVal = atoi(buf);
						setValue_mib(MIB_WLAN_WEP, (void*)&intVal);//(void*)buf);
					}

					sprintf(buf, "%d", securityConfig[j - 1].secWEPConfig[i].WEPKeyFormat);
					intVal = atoi(buf);
					setValue_mib(MIB_WLAN_WEP_KEY_TYPE, (void*)&intVal);

					sprintf(buf, "%d", securityConfig[j - 1].secWEPConfig[i].WEPKeyIndex - 1);
					intVal = atoi(buf);
					setValue_mib(MIB_WLAN_WEP_DEFAULT_KEY, (void*)&intVal);
					if (securityConfig[j - 1].secWEPConfig[i].WEPAuthKeySize == 2) {
						keyLength = 26;
						memset(buf, 0, keyLength + 1);
						if (securityConfig[j - 1].secWEPConfig[i].WEPKeyFormat == 0)
							string_to_hex(securityConfig[j - 1].secWEPConfig[i].EncryptionKey, buf, keyLength / 2);
						else {
							snprintf(buf, sizeof(buf), "%s", securityConfig[j - 1].secWEPConfig[i].EncryptionKey);
							intVal = atoi(buf);
						}

							if (securityConfig[j - 1].secWEPConfig[i].WEPKeyIndex == 0) {
								setValue_mib(MIB_WLAN_WEP128_KEY1, (void*)&intVal);
								setValue_mib(MIB_WLAN_WEP128_KEY2, (void*)&intVal);
								setValue_mib(MIB_WLAN_WEP128_KEY3, (void*)&intVal);
								setValue_mib(MIB_WLAN_WEP128_KEY4, (void*)&intVal);
							} else {
								if (i == 0) {
									sprintf(param, "WLAN%d_WEP128_KEY%d", j - 1, securityConfig[j - 1].secWEPConfig[i].WEPKeyIndex);
								} else {
						sprintf(param, "WLAN%d_VAP%d_WEP128_KEY%d", j - 1, i - 1, securityConfig[j - 1].secWEPConfig[i].WEPKeyIndex);
								}
								setValue(param, buf);
							}
					} else {
						keyLength = 10;
						memset(buf, 0, keyLength + 1);
						if (securityConfig[j - 1].secWEPConfig[i].WEPKeyFormat == 0)
							string_to_hex(securityConfig[j - 1].secWEPConfig[i].EncryptionKey, buf, keyLength / 2);
						else {
							snprintf(buf, sizeof(buf), "%s", securityConfig[j - 1].secWEPConfig[i].EncryptionKey);
							intVal = atoi(buf);
						}
							if (securityConfig[j - 1].secWEPConfig[i].WEPKeyIndex == 0) {
								setValue_mib(MIB_WLAN_WEP64_KEY1, (void*)&intVal);
								setValue_mib(MIB_WLAN_WEP64_KEY2, (void*)&intVal);
								setValue_mib(MIB_WLAN_WEP64_KEY3, (void*)&intVal);
								setValue_mib(MIB_WLAN_WEP64_KEY4, (void*)&intVal);
							} else {
								if (i == 0) {
									sprintf(param, "WLAN%d_WEP64_KEY%d", j - 1, securityConfig[j - 1].secWEPConfig[i].WEPKeyIndex);
								} else {
									sprintf(param, "WLAN%d_VAP%d_WEP64_KEY%d", j - 1, i - 1, securityConfig[j - 1].secWEPConfig[i].WEPKeyIndex);
								}
								setValue(param, buf);
							}
					}
					break;
				case 2:
					setValue_mib(MIB_WLAN_ENCRYPT, (void*)&wpa_index);
					sprintf(buf, "%d", securityConfig[j - 1].secWPAxConfig[i].WPAxAuthMode);
					intVal = atoi(buf);
					setValue_mib(MIB_WLAN_WPA_AUTH, (void*)&intVal);

					sprintf(buf, "%d", securityConfig[j - 1].secWPAxConfig[i].WPAxCipherSuite);
					intVal = atoi(buf);
					setValue_mib(MIB_WLAN_WPA_CIPHER_SUITE, (void*)&intVal);

					sprintf(buf, "%d", securityConfig[j - 1].secWPAxConfig[i].WPAxKeyFormat);
					intVal = atoi(buf);
					setValue_mib(MIB_WLAN_PSK_FORMAT, (void*)&intVal);

					setValue_mib(MIB_WLAN_WPA_PSK, (void*)securityConfig[j - 1].secWPAxConfig[i].PreSharedKey);
					break;
				case 3:
					setValue_mib(MIB_WLAN_ENCRYPT, (void*)&wpa2_index);
					sprintf(buf, "%d", securityConfig[j - 1].secWPAxConfig[i].WPAxAuthMode);
					intVal = atoi(buf);
					setValue_mib(MIB_WLAN_WPA_AUTH, (void*)&intVal);

					sprintf(buf, "%d", securityConfig[j - 1].secWPAxConfig[i].WPAxCipherSuite);
					intVal = atoi(buf);
					setValue_mib(MIB_WLAN_WPA2_CIPHER_SUITE, (void*)&intVal);

					sprintf(buf, "%d", securityConfig[j - 1].secWPAxConfig[i].WPAxKeyFormat);
					intVal = atoi(buf);
					setValue_mib(MIB_WLAN_PSK_FORMAT, (void*)&intVal);

					setValue_mib(MIB_WLAN_WPA_PSK, securityConfig[j - 1].secWPAxConfig[i].PreSharedKey);
					break;
				case 4:
					setValue_mib(MIB_WLAN_ENCRYPT, (void*)&wpamix_index);
					sprintf(buf, "%d", securityConfig[j - 1].secWPAmixConfig[i].WPAmixAuthMode);
					intVal = atoi(buf);
					setValue_mib(MIB_WLAN_WPA_AUTH, (void*)&intVal);

					sprintf(buf, "%d", securityConfig[j - 1].secWPAmixConfig[i].WPAmixCipherSuite);
					intVal = atoi(buf);
					setValue_mib(MIB_WLAN_WPA_CIPHER_SUITE, (void*)&intVal);
					sprintf(buf, "%d", securityConfig[j - 1].secWPAmixConfig[i].WPAmix2CipherSuite);
					intVal = atoi(buf);
					setValue_mib(MIB_WLAN_WPA2_CIPHER_SUITE, (void*)&intVal);

					sprintf(buf, "%d", securityConfig[j - 1].secWPAmixConfig[i].WPAmixKeyFormat);
					intVal = atoi(buf);
					setValue_mib(MIB_WLAN_PSK_FORMAT, (void*)&intVal);


					setValue_mib(MIB_WLAN_WPA_PSK, (void*)securityConfig[j - 1].secWPAmixConfig[i].PreSharedKey);
					break;
			}
		}
	}
	return 1;
}

int check_entry_portfw(int skip)
{
	int argc, i;
	char *argv[12];
	char buffer[64], value[128];

	for(i = 0; i < portfw_tblnum; i++) {
		if (skip == i)
			continue;

		snprintf(buffer, sizeof(buffer), "PORTFW_TBL%d", i);
		if ( nvram_get_r(buffer, value, sizeof(value)) ) {
			if ( !(argc = parse_line(value, argv, 12, ",\n")) )
				return 0;

			check_entry.startport = atoi(argv[1]);
			check_entry.endport = atoi(argv[2]);
			check_entry.protocol = atoi(argv[3]);
			if ( ( (portfw_entry.startport <= check_entry.startport && portfw_entry.endport >= check_entry.startport) ||
						(portfw_entry.startport >= check_entry.startport && portfw_entry.startport <= check_entry.endport) )&& (portfw_entry.protocol & check_entry.protocol) )
				return 0;
		}
	}

	return 1;
}

void SavePortConfig()
{
	char buf[64], val[64];
	int i;

	for(i = 0; i < 5; i++) {
		if(portConfig[i].changed == 0)
			continue;
		portConfig[i].changed = 0;

		if(i == 0)
			snprintf(buf, sizeof(buf), "x_port_4_config");
		else
			snprintf(buf, sizeof(buf), "x_port_%d_config", i-1);

		if(!strcmp(portConfig[i].port_config, "")) {
			if(i == 0)
				nvram_get_r_def(buf, val, sizeof(val), "up_auto_rxpause_txpause");
			else
				nvram_get_r_def(buf, val, sizeof(val), "up_auto_-rxpause_txpause");
			snprintf(portConfig[i].port_config, sizeof(portConfig[i].port_config), "%s", val);
		}
		setValue(buf, portConfig[i].port_config);
	}

	if(portLimit.changed == 0)
		return;

	if(portLimit.slimit == 0)
		nvram_get_r_def("x_snmp_wireslimit", val, sizeof(val), "80");
	else
		snprintf(val, sizeof(val), "%d", portLimit.slimit);

	nvram_set("x_snmp_wireslimit", val);
}

void SaveIGMPConfig()
{
	char val[16];

	if(IGMPConfig.changed == 0)
		return;
	IGMPConfig.changed = 0;

	if(IGMPConfig.igmpEnable == 1)
		snprintf(val, sizeof(val), "%s", "0");
	else if(IGMPConfig.igmpEnable == 2)
		snprintf(val, sizeof(val), "%s", "1");
	else
		nvram_get_r_def("IGMP_PROXY_DISABLED", val, sizeof(val), "0");
	setValue("IGMP_PROXY_DISABLED", val);

	if(IGMPConfig.fastleaveEnable == 1)
		snprintf(val, sizeof(val), "%s", "0");
	else if(IGMPConfig.fastleaveEnable == 2)
		snprintf(val, sizeof(val), "%s", "1");
	else
		nvram_get_r_def("IGMP_FAST_LEAVE_DISABLED", val, sizeof(val), "0");
	setValue("IGMP_FAST_LEAVE_DISABLED", val);

	if(IGMPConfig.MemExpTime == 0)
		nvram_get_r_def("x_igmp_expire_time", val, sizeof(val), "60");
	else
		snprintf(val, sizeof(val), "%d", IGMPConfig.MemExpTime);
	setValue("x_igmp_expire_time", val);

	if(IGMPConfig.QryIntv == 0)
		nvram_get_r_def("x_igmp_query_interval", val, sizeof(val), "125");
	else
		snprintf(val, sizeof(val), "%d", IGMPConfig.QryIntv);
	setValue("x_igmp_query_interval", val);

	if(IGMPConfig.GrpRespIntv == 0)
		nvram_get_r_def("x_igmp_query_res_interval", val, sizeof(val), "5");
	else
		snprintf(val, sizeof(val), "%d", IGMPConfig.GrpRespIntv);
	setValue("x_igmp_query_res_interval", val);

	if(IGMPConfig.GrpmemIntv == 0)
		nvram_get_r_def("x_igmp_grpmem_interval", val, sizeof(val), "60");
	else
		snprintf(val, sizeof(val), "%d", IGMPConfig.GrpmemIntv);
	setValue("x_igmp_grpmem_interval", val);

	if(IGMPConfig.GrpQryIntv == 0)
		nvram_get_r_def("x_igmp_querier_interval", val, sizeof(val), "125");
	else
		snprintf(val, sizeof(val), "%d", IGMPConfig.GrpQryIntv);
	setValue("x_igmp_querier_interval", val);
}

void SaveSnmpCofig()
{
	char buf[64], val[64];
	int i;

	if(SNMPConfig.commchanged == 0) {
		SNMPConfig.commchanged = 0;
		goto TRAP_SETTING;
	}

	if(SNMPConfig.snmpEnable == 1)
		snprintf(val, sizeof(val), "%s", "1");
	else if(SNMPConfig.snmpEnable == 2)
		snprintf(val, sizeof(val), "%s", "0");
	else
		nvram_get_r_def("x_SNMP_ENABLE", val, sizeof(val), "1");
	setValue("x_SNMP_ENABLE", val);

	if(!strcmp(SNMPConfig.getcommName, ""))
		nvram_get_r_def("x_SNMP_GET_COMMUNITY", SNMPConfig.getcommName, sizeof(SNMPConfig.getcommName), "iptvshro^_");
	setValue("x_SNMP_GET_COMMUNITY", SNMPConfig.getcommName);

	if(!strcmp(SNMPConfig.setcommName, ""))
		nvram_get_r_def("x_SNMP_SET_COMMUNITY", SNMPConfig.setcommName, sizeof(SNMPConfig.setcommName), "iptvshrw");
	setValue("x_SNMP_SET_COMMUNITY", SNMPConfig.setcommName);

	if(SNMPConfig.getcommType == 2)
		SNMPConfig.getcommType = 0;
	else if(SNMPConfig.getcommType == 0) {
		nvram_get_r_def("x_SNMP_COM1", val, sizeof(val), "1_0");
		SNMPConfig.getcommType = atoi(&val[2]);
	}

	if(SNMPConfig.setcommType == 2)
		SNMPConfig.setcommType = 0;
	else if(SNMPConfig.setcommType == 0) {
		nvram_get_r_def("x_SNMP_COM2", val, sizeof(val), "1_1");
		SNMPConfig.setcommType = atoi(&val[2]);
	}

	if(SNMPConfig.getcommAdmin == 2)
		SNMPConfig.getcommAdmin = 0;
	else if(SNMPConfig.getcommAdmin == 0) {
		nvram_get_r_def("x_SNMP_COM1", val, sizeof(val), "1_0");
		SNMPConfig.getcommAdmin = atoi(&val[0]);
	}

	if(SNMPConfig.setcommAdmin == 2)
		SNMPConfig.setcommAdmin = 0;
	else if(SNMPConfig.setcommAdmin == 0) {
		nvram_get_r_def("x_SNMP_COM2", val, sizeof(val), "1_1");
		SNMPConfig.setcommAdmin = atoi(&val[0]);
	}
	snprintf(val, sizeof(val), "%d_%d", SNMPConfig.getcommAdmin, SNMPConfig.getcommType);
	setValue("x_SNMP_COM1", val);

	snprintf(val, sizeof(val), "%d_%d", SNMPConfig.setcommAdmin, SNMPConfig.setcommType);
	setValue("x_SNMP_COM2", val);

TRAP_SETTING:
	for(i=0; i<11; i++) {
		if(SNMPConfig.trapSrvchanged[i] == 0)
			continue;
		if (i == 0) {
			snprintf(buf, sizeof(buf), "%s", "x_SNMP_TRAP_SERVER");
			if(!strcmp(SNMPConfig.trapDest[i], ""))
				nvram_get_r_def("x_SNMP_TRAP_SERVER", SNMPConfig.trapDest[i], sizeof(SNMPConfig.trapDest[i]), "iptvsh-trap.skbroadband.com");
		} else if (i == 1) {
			snprintf(buf, sizeof(buf), "%s", "x_WIFI_TRAP_SERVER");
			if(!strcmp(SNMPConfig.trapDest[i], ""))
				nvram_get_r_def("x_WIFI_TRAP_SERVER", SNMPConfig.trapDest[i], sizeof(SNMPConfig.trapDest[i]), "iptvap-trap.skbroadband.com");
		} else if (i == 2) {
			snprintf(buf, sizeof(buf), "%s", "x_cpeping_trap_server");
			if(!strcmp(SNMPConfig.trapDest[i], ""))
				nvram_get_r_def("x_cpeping_trap_server", SNMPConfig.trapDest[i], sizeof(SNMPConfig.trapDest[i]), "iptvap-trap3.skbroadband.com");
		} else if (i == 3) {
			snprintf(buf, sizeof(buf), "%s", "x_autoreboot_trap_server");
			if(!strcmp(SNMPConfig.trapDest[i], ""))
				nvram_get_r_def("x_autoreboot_trap_server", SNMPConfig.trapDest[i], sizeof(SNMPConfig.trapDest[i]), "iptvap-trap4.skbroadband.com");
		} else if (i == 4) {
			snprintf(buf, sizeof(buf), "%s", "x_portlink_trap_server");
			if(!strcmp(SNMPConfig.trapDest[i], ""))
				nvram_get_r_def("x_portlink_trap_server", SNMPConfig.trapDest[i], sizeof(SNMPConfig.trapDest[i]), "iptvap-trap5.skbroadband.com");
		} else if (i == 5) {
			snprintf(buf, sizeof(buf), "%s", "x_limitedSession_trap_server");
			if(!strcmp(SNMPConfig.trapDest[i], ""))
				nvram_get_r_def("x_limitedSession_trap_server", SNMPConfig.trapDest[i], sizeof(SNMPConfig.trapDest[i]), "iptvap-trap6.skbroadband.com");
		} else if (i == 6) {
			snprintf(buf, sizeof(buf), "%s", "x_smartReset_trap_server");
			if(!strcmp(SNMPConfig.trapDest[i], ""))
				nvram_get_r_def("x_smartReset_trap_server", SNMPConfig.trapDest[i], sizeof(SNMPConfig.trapDest[i]), "iptvap-trap7.skbroadband.com");
		} else if (i == 7) {
			snprintf(buf, sizeof(buf), "%s", "x_autobandwidth_trap_server");
			if(!strcmp(SNMPConfig.trapDest[i], ""))
				nvram_get_r_def("x_autobandwidth_trap_server", SNMPConfig.trapDest[i], sizeof(SNMPConfig.trapDest[i]), "iptvap-trap9.skbroadband.com");
		} else if (i == 8) {
			snprintf(buf, sizeof(buf), "%s", "x_handover_trap_server");
			if(!strcmp(SNMPConfig.trapDest[i], ""))
				nvram_get_r_def("x_handover_trap_server", SNMPConfig.trapDest[i], sizeof(SNMPConfig.trapDest[i]), "iptvap-trap9.skbroadband.com");
		} else if (i == 9) {
			snprintf(buf, sizeof(buf), "%s", "x_ntp_trap_server");
			if(!strcmp(SNMPConfig.trapDest[i], ""))
				nvram_get_r_def("x_ntp_trap_server", SNMPConfig.trapDest[i], sizeof(SNMPConfig.trapDest[i]), "iptvap-trap10.skbroadband.com");
		} else {
			snprintf(buf, sizeof(buf), "%s", "x_sitesurvey_trap_server");
			if(!strcmp(SNMPConfig.trapDest[i], ""))
				nvram_get_r_def("x_sitesurvey_trap_server", SNMPConfig.trapDest[i], sizeof(SNMPConfig.trapDest[i]), "iptvap-trap11.skbroadband.com");
		}
		setValue(buf, SNMPConfig.trapDest[i]);
	}

	if(SNMPConfig.trapchanged == 0)
		return;

	if(!strcmp(SNMPConfig.trapName, ""))
		nvram_get_r_def("x_SNMP_TRAP_COMMUNITY", SNMPConfig.trapName, sizeof(SNMPConfig.trapName), "iptvshrw^_");
	setValue("x_SNMP_TRAP_COMMUNITY", SNMPConfig.trapName);

	if(SNMPConfig.trapAdmin == 1)
		snprintf(val, sizeof(val), "%s", "1");
	else if(SNMPConfig.trapAdmin == 2)
		snprintf(val, sizeof(val), "%s", "0");
	else
		nvram_get_r_def("x_SNMP_TRAP_ENABLE", val, sizeof(val),  "1");
	setValue("x_SNMP_TRAP_ENABLE", val);
}

void SaveLogCofig()
{
	char val[8];
	int port = 0;
	char *args[2] = {NULL,};
	char value[128] = {0,};
	int n;

	if(syslogConfig.changed == 0)
		return;

	if(syslogConfig.logEnable == 1)
		snprintf(val, sizeof(val), "%s", "3");
	else if(syslogConfig.logEnable == 2)
		snprintf(val, sizeof(val), "%s", "0");
	else
		nvram_get_r_def("SCRLOG_ENABLED", val, sizeof(val), "3");
	setValue("SCRLOG_ENABLED", val);

	if(syslogConfig.rlogEnable == 1)
		snprintf(val, sizeof(val), "%s", "1");
	else if(syslogConfig.rlogEnable == 2)
		snprintf(val, sizeof(val), "%s", "0");
	else
		nvram_get_r_def("REMOTELOG_ENABLED", val, sizeof(val), "3");
	setValue("REMOTELOG_ENABLED", val);

	if(!strcmp(syslogConfig.rlogServer, ""))
		nvram_get_r_def("x_remote_logserver", syslogConfig.rlogServer, sizeof(syslogConfig.rlogServer), "syslogap.skbroadband.com:10614");

	n = ystrargs(syslogConfig.rlogServer, args, _countof(args), ":\n", 0);
	if (n == 2) {
		port = strtol(args[1], NULL, 10);
		if (port <= 0 || port > 65535) {
			port = 10614;
		}
		snprintf(value, sizeof(value), "%s:%d", args[0], port);
	} else {
		snprintf(value, sizeof(value), "%s:10614", args[0]);
	}
	setValue("x_remote_logserver", value);
}

void SaveNTPCofig()
{
	char buf[32];
	int i;

	if(ntpConfig.changed == 0)
		return;

	for(i = 0; i < 3; i++) {
		snprintf(buf, sizeof(buf), "x_ntp_server_ip%d", i + 1);
		if(!strcmp(ntpConfig.ntpServer[i], "")) {
			if (i == 0)
				nvram_get_r_def(buf, ntpConfig.ntpServer[i], sizeof(ntpConfig.ntpServer[i]), "time1.skbroadband.com");
			else if(i == 1)
				nvram_get_r_def(buf, ntpConfig.ntpServer[i], sizeof(ntpConfig.ntpServer[i]), "time2.skbroadband.com");
			else
				nvram_get_r_def(buf, ntpConfig.ntpServer[i], sizeof(ntpConfig.ntpServer[i]), "kr.pool.ntp.org");
		}
		setValue(buf, ntpConfig.ntpServer[i]);
	}
}

void SaveQosCofig()
{
	int i;
	char buf[32], val[32];

	for(i = 0; i < 5; i++) {
		if(QosConfig[i].changed == 0)
			continue;

		snprintf(buf, sizeof(buf), "x_QOS_ENABLE_%d", i==0 ? 4:i-1);
		if(QosConfig[i].limitMode == 1)
			snprintf(val, sizeof(val), "%s", "1");
		else if(QosConfig[i].limitMode == 2)
			snprintf(val, sizeof(val), "%s", "0");
		else
			nvram_get_r_def(buf, val, sizeof(val), "1");
		setValue(buf, val);

		snprintf(buf, sizeof(buf), "x_QOS_RATE_I_%d", i==0 ? 4:i-1);
		if(QosConfig[i].Rxlimit == 0)
			nvram_get_r_def(buf, val, sizeof(val), "0");
		else
			snprintf(val, sizeof(val), "%d", QosConfig[i].Rxlimit);
		setValue(buf, val);

		snprintf(buf, sizeof(buf), "x_QOS_RATE_O_%d", i==0 ? 4:i-1);
		if(QosConfig[i].Txlimit == 0)
			nvram_get_r_def(buf, val, sizeof(val), "0");
		else
			snprintf(val, sizeof(val), "%d", QosConfig[i].Txlimit);
		setValue(buf, val);

		snprintf(buf, sizeof(buf), "x_QOS_RATE_ENABLE_%d", i==0 ? 4:i-1);
		if(QosConfig[i].flowCtrl == 1)
			snprintf(val, sizeof(val), "%s", "0");
		else if(QosConfig[i].flowCtrl == 2)
			snprintf(val, sizeof(val), "%s", "1");
		else
			nvram_get_r_def(buf, val, sizeof(val), "0");
		setValue(buf, val);
	}
}

void SavePortFwConfig()
{
	char param[32], buf[64], val[128];
	int i;
	char *argv[12];
	int argc;
	PORTFW_T entry;

	if(portfw_entry.changed == 0)
		return;

	setValue_mib(MIB_PORTFW_DELALL, (void *)&entry);

	for (i = 0; i < portfw_tblnum; i++) {
		if(portfw_tbl[i].startport > portfw_tbl[i].endport)
			continue;
		snprintf(buf, sizeof(buf), "PORTFW_TBL%d", i+1);
		snprintf(val, sizeof(val), "%s,%d,%d,%d,%d|%s",
				inet_ntoa(*(struct in_addr *)&portfw_tbl[i].ipaddr),
				portfw_tbl[i].startport, portfw_tbl[i].endport,
				portfw_tbl[i].protocol, portfw_tbl[i].slanport, portfw_tbl[i].name);
		setValue(buf, val);
	}
	setValue_mib(MIB_PORTFW_TBL_NUM, (void *)&portfw_tblnum);
}

void SaveAndApply__(void)
{
	int res = g_SaveAndApply;

	g_SaveAndApply = 0;
	switch (res) {
		case 1:
			SaveWanConfig();
			SaveLanConfig();
			SaveWlanBasicConfig();
			SaveMultiSSIDConfig();
			SaveWlanAdvConfig();
			SaveSecurityConfig();
			SavePortConfig();
			SaveIGMPConfig();
			SaveSnmpCofig();
			SaveLogCofig();
			SaveNTPCofig();
			SaveQosCofig();
			SavePortFwConfig();
			break;
		case 2:
			yecho("/proc/load_default", "1\n");
			break;
		case 3:
			SaveWanConfig();
			break;
		case 4:
			SaveLanConfig();
			break;
		case 5:
			SaveWlanBasicConfig();
			SaveMultiSSIDConfig();
			break;
		case 6:
			SaveWlanAdvConfig();
			break;
		case 7:
			SaveSecurityConfig();
			break;
		case 8:
			SavePortConfig();
			break;
		case 9:
			SaveIGMPConfig();
			break;
		case 10:
			SaveSnmpCofig();
			break;
		case 11:
			SaveLogCofig();
			break;
		case 12:
			SaveNTPCofig();
			break;
		case 13:
			SaveQosCofig();
			break;
		case 14:
			break;
		case 15:
			break;
		case 16:
			SavePortFwConfig();
			break;
		default:
			return;
	}
	commitValue();
	snmpAction = SNMP_REBOOT;
	return;
}

int SaveAndApply(int res)
{
	if ( res < 1 || res > 16)
		return 0;

	g_SaveAndApply = res;
	snmpAction |= SNMP_SAVE_APPLY;

	return 1;
}

int get_systemInitMode()
{
	char buf[4];
	char *ptr;

	ptr = getValue("x_system_init_mode");

	if(ptr) {
		return (atoi(ptr));
	} else {
		int res[2], i;
		char param[32];

		for(i = 0; i < 2; i++)
		{
			sprintf(param, "WLAN%d_WLAN_DISABLED", i);
			snprintf(buf, sizeof(buf), "%s", getValue(param));
			res[i] = atoi(buf);
		}
		if (res[0] == 0 && res[1] == 0)
			return 2;
		else
			return 1;
	}

	return 2;
}

int set_systemInitMode(int res)
{
	int disabled;

	switch (res) {
		case 1:
			disabled = 1;
			setValue_mib(MIB_WLAN_WLAN_DISABLED, (void*)&disabled);
			setValue("x_system_init_mode", "1");
			break;
		case 2:
			disabled = 0;
			setValue_mib(MIB_WLAN_WLAN_DISABLED, (void*)&disabled);
			setValue("x_system_init_mode", "2");
			break;
		default:
			return 0;
	}

	needReboot = 0;
	snmpAction = SNMP_RESTART;
	return 1;
}

void get_systemConfigRootAccount(char *getbuf, int len)
{
	char buf[65];

	if ( !getbuf || len <= 0)
		return;

	snprintf(buf, sizeof(buf), "%s", getValue("x_SUPER_PASSWORD"));
	snprintf(getbuf, MAX_SNMP_STR, "%s", buf);
}

int set_systemConfigRootAccount(char *val, int len)
{
	char encode_userpass[65];
	char tok[] = "`~!@#$%^&*()-=_+[];',./{}:<>?\"\\|";
	int i, cnt=0;
	int mode;

	mode = atoi(getValue("x_root_account_mode"));

	if ( mode == 0 )
		return 0;

	if ( !val || len <= 0 || len < 10 || len > 32 )
		return 0;

	for (i=0; i < strlen(tok); i++)	{
		if( strchr(val, tok[i]) == NULL )
			cnt++;
	}

	if( cnt == strlen(tok) )
		return 0;

	memset(encode_userpass, 0, sizeof(encode_userpass));
	cal_sha256(val, encode_userpass);
	setValue("x_SUPER_PASSWORD", encode_userpass);
	setValue("x_root_account_mode", "0");

	needReboot = 0;
	snmpAction |= SNMP_WEB_RESTART;

	return 1;
}

int get_RootAccountMode()
{
	int mode;

	mode = atoi(getValue("x_root_account_mode"));

	if( mode == 0)
		return 2;
	else if ( mode == 1)
		return 1;
	else
		return NULL;
}

int set_RootAccountMode(int res)
{
	char buf[2];

	if ( res != 1 && res != 2)
		return 0;

	if (res == 1)
		snprintf(buf, sizeof(buf), "%s", "1");
	else if (res == 2)
		snprintf(buf, sizeof(buf), "%s", "0");

	setValue("x_root_account_mode", buf);
	return 1;
}

int set_wlanMode(int index, int intVal)
{
	if(intVal != 1 && intVal != 2)
		return 0;

	wlanBasicConfig[index].wlanMode = intVal;
	wlanBasicConfig[index].changed = 1;
	return 1;
}

long get_wlanBand(int index)
{
	char buf[5];
	char param[32];
	int band;
	long res;

	if(wlanBasicConfig[index].wlanBand == 0) {
		memset(param, 0, sizeof(param));
		sprintf(param, "WLAN%d_BAND", index);
		snprintf(buf, sizeof(buf), "%s", getValue(param));

		band = atoi(buf);

		if(index == 0) {
			switch (band) {
				case 4:                    // 5 Ghz(A)
					res = 1;
					break;
				case 8:                    // 5 Ghz(N)
					res = 2;
					break;
				case 12:                   // 5 Ghz(A+N)
					res = 3;
					break;
				case 64:                   // 5 Ghz(AC)
					res = 4;
					break;
				case 72:                   // 5 Ghz(N+AC)
					res = 5;
					break;
				case 76:                   // 5 Ghz(A+N+AC)
					res = 6;
					break;
				default:
					res = 6;
			}
		} else {
			switch (band) {
				case 1:                    // 2.4 Ghz(B)
				case 2:                    // 2.4 Ghz(G)
					res = band;
					break;
				case 3:                    // 2.4 Ghz(B+G)
					res = 4;
					break;
				case 8:                    // 2.4 Ghz(N)
					res = 3;
					break;
				case 10:                   // 2.4GHz (G+N)
					res = 5;
					break;
				case 11:                   // 2.4GHz(B+G+N);
					res = 6;
					break;
				default:
					res = 6;
			}
		}
	} else {
		if (index == 0) {
			switch (wlanBasicConfig[index].wlanBand) {
				case 4:
					res = 1;
					break;
				case 8:
					res = 2;
					break;
				case 12:
					res = 3;
					break;
				case 64:
					res = 4;
					break;
				case 72:
					res = 5;
					break;
				case 76:
					res = 6;
					break;
				default:
					res = 6;
			}
		} else {
			switch (wlanBasicConfig[index].wlanBand) {
				case 1:
					res = 1;
					break;
				case 2:
					res = 2;
					break;
				case 8:
					res = 3;
					break;
				case 3:
					res = 4;
					break;
				case 10:
					res = 5;
					break;
				case 11:
					res = 6;
					break;
				default:
					res = 6;
			}
		}
	}
	return res;
}


int set_wlanBand(int w_index, int p)
{
	int band;

	if (w_index == 0) {
		switch (p) {
			case 1:
				band = 4;
				break;
			case 2:
				band = 8;
				break;
			case 3:
				band = 12;
				break;
			case 4:
				band = 64;
				break;
			case 5:
				band = 72;
				break;
			case 6:
				band = 76;
				break;
			default:
				return 0;
		}
	} else {
		switch (p) {
			case 1:
				band = 1;
				break;
			case 2:
				band = 2;
				break;
			case 3:
				band = 8;
				break;
			case 4:
				band = 3;
				break;
			case 5:
				band = 10;
				break;
			case 6:
				band = 11;
				break;
			default:
				return 0;
		}
	}

	wlanBasicConfig[w_index].wlanBand = band;
	wlanBasicConfig[w_index].changed = 1;
	return 1;
}

long get_wlanChannelWidth(int index)
{
	char buf[32];
	char param[32];
	long channelBound;

	if(wlanBasicConfig[index].wlanAutoBonding == 0 && wlanBasicConfig[index].wlanBonding == 0) {
		param[0] = 0;
		sprintf(param, "x_wlan%d_auto_bonding", index);
		nvram_get_r_def(param, buf, sizeof(buf), "1");
		if ( buf[0] == '1' ) {
			channelBound = 0;
		} else {
			sprintf(param, "WLAN%d_CHANNEL_BONDING", index);
			snprintf(buf, sizeof(buf), "%s", getValue(param));
			channelBound = atoi(buf) + 1;
		}
	} else {
		if(wlanBasicConfig[index].wlanAutoBonding == 1)
			channelBound = 0;
		else
			channelBound = wlanBasicConfig[index].wlanBonding;
	}

    return channelBound;

}

int set_wlanChannelWidth(int w_index, int chBound)
{
	//wlan0 does not support auto bandwidth
	if (w_index == 0 && chBound == 0)
		return 0;

	if (chBound < 0 || chBound > 2 )
		return 0;


	if ( chBound == 0 )
		wlanBasicConfig[w_index].wlanAutoBonding = 1;
	else
		wlanBasicConfig[w_index].wlanAutoBonding = 2;

	if ( chBound > 0 ) {
		wlanBasicConfig[w_index].wlanBonding = chBound;
	}
	wlanBasicConfig[w_index].changed = 1;

	return 1;
}

long get_wlanCtrlSideBand_5g()
{
	int ch_num, i;
	int lower[9] = {36, 44, 52, 60, 100, 108, 116, 149, 157};
	int upper[9] = {40, 48, 56, 64, 104, 112, 120, 153, 161};

	if(wlanBasicConfig[0].channelNumber == 0)
		ch_num = nvram_atoi("WLAN0_CHANNEL", 0);
	else if(wlanBasicConfig[0].channelNumber == -1)		// auto channel
		ch_num = 0;
	else
		ch_num = wlanBasicConfig[0].channelNumber;

	for(i=0; i<18; i++) {
		if(ch_num == 0 || ch_num == 124)
			break;

		if(ch_num == lower[i]) {
			ch_num = upper[i];
			break;
		} else if(ch_num == upper[i]) {
			ch_num = lower[i];
			break;
		}
	}
	return ch_num;
}

long get_wlanCtrlSideBand()
{
	int controlSideBand;

	if(wlanBasicConfig[1].CtrlSideBand == 0) {
		controlSideBand = nvram_atoi("WLAN1_CONTROL_SIDEBAND", 0);

		if (controlSideBand == 0)
			return 1;
		else if (controlSideBand == 1)
			return 2;
	} else
		return wlanBasicConfig[1].CtrlSideBand;
}

int set_wlanCtrlSideBand(int w_index, int controlSideBand)
{
	if(controlSideBand != 1 && controlSideBand != 2)
		return 0;

	wlanBasicConfig[w_index].CtrlSideBand = controlSideBand;
	wlanBasicConfig[w_index].changed = 1;
	return 1;
}

int get_wlanChannelNumber(int index)
{
	char buf[20], param[32];
	int channel;

	if(wlanBasicConfig[index].channelNumber == 0) {
		memset(param, 0, sizeof(param));
		sprintf(param, "WLAN%d_CHANNEL", index);
		snprintf(buf, sizeof(buf), "%s", getValue(param));

		channel = atoi(buf);
	} else if(wlanBasicConfig[index].channelNumber == -1) 	// auto channel
		channel = 0;
	else
		channel = wlanBasicConfig[index].channelNumber;

	return channel;
}

int set_wlanChannelNumber(int w_index, int channelNum)
{
	char buf[20], var[20];
	int width, band;
	char buf2[20];
	if (w_index == 1 && (channelNum > 13))
		return 0;

	if (w_index == 0 && ((channelNum > 0 && channelNum < 36) || channelNum > 161))
		return 0;

	sprintf(var, "WLAN%d_CHANNEL_BONDING", w_index);
	snprintf(buf, sizeof(buf), "%s", getValue(var));
	sprintf(var, "WLAN%d_BAND", w_index);
	snprintf(buf2, sizeof(buf2), "%s", getValue(var));

	width = atoi(buf);
	band = atoi(buf2);

	if (w_index == 0) {
		if( width == 1 && ((band & 0x08) || (band & 0x40)) ) {
			switch (channelNum) {
				case 0:
				case 40:
				case 48:
				case 56:
				case 64:
				case 104:
				case 112:
				case 120:
				case 153:
				case 161:
					break;
				default:
					return 0;
			}
		}
	}

	if(channelNum == 0)
		wlanBasicConfig[w_index].channelNumber = -1;
	else
		wlanBasicConfig[w_index].channelNumber = channelNum;

	wlanBasicConfig[w_index].changed = 1;
	return 1;
}

extern int getMiscData(char *interface, struct _misc_data_ *pData);

long get_wlanDateRate(int index)
{
	char buf[50], param[20];
	int band;
	int autoRate = 0;
	int txRate;
	int rf_num;
	int rate_mask[] = { 15, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 4, 4, 4, 4, 4, 4, 4, 4, 8, 8, 8, 8, 8, 8, 8, 8 };
	int mask = 0;
	int i, found = -1;
	int rate;
	struct _misc_data_ miscData;

	if(wlanBasicConfig[index].wlanBand == 0) {
		memset(param, 0, sizeof(param));
		sprintf(param, "WLAN%d_BAND", index);
		snprintf(buf, sizeof(buf), "%s", getValue(param));
		band = atoi(buf);
	} else
		band = wlanBasicConfig[index].wlanBand;

	if(wlanBasicConfig[index].DataRate == 0) {
		memset(param, 0, sizeof(param));
		sprintf(param, "WLAN%d_FIX_RATE", index);
		snprintf(buf, sizeof(buf), "%s", getValue(param));

		txRate = atoi(buf);

		memset(param, 0, sizeof(param));
		sprintf(param, "WLAN%d_RATE_ADAPTIVE_ENABLED", index);
		snprintf(buf, sizeof(buf), "%s", getValue(param));
		autoRate = atoi(buf);

	} else if(wlanBasicConfig[index].DataRate == -1)	//auto data rate
		txRate = 0;
	else
		txRate = wlanBasicConfig[index].DataRate;

	memset(param, 0, sizeof(param));
	sprintf(param, "wlan%d", index);
	getMiscData(param, &miscData);

	rf_num = miscData.mimo_tr_used;
	if (autoRate)
		txRate = 0;
	if (band & 1)
		mask |= 1;
	if ((band & 2) || (band & 4))
		mask |= 2;
	if (band & 8) {
		if (rf_num == 2)
			mask |= 12;
		else
			mask |= 4;
	}
	for (i = 0; i <= 28; i++) {
		if (rate_mask[i] & mask) {
			if (i == 0)
				rate = 0;
			else
				rate = (1 << (i - 1));
			if (txRate == rate) {
				found = i;
				break;
			}
		}
	}
	if (found != -1)
		found += 1;

	return (found);
}

int set_wlanDateRate(int w_index, int val)
{
	int txRate;
	int band = get_wlanBand(w_index);

	if (val == 1) {
		wlanBasicConfig[w_index].DataRate = -1;
	} else if (val > 1 && val <= 37) {
		if(w_index == 0) {
			if ((val >= 2 && val <= 5) ||
					(band == 1 && !(val >= 6 && val <= 13)) || // BAND A
					(band == 2 && !(val >= 14 && val <= 29)) ||  // BAND N
					(band == 3 && (!(val >= 6  && val <= 29)))){ // &&
//								   !(val >= 30  && val <= 37)))) {// BAND A+N
				return 0;
			}
		} else if (w_index == 1){
			if (val > 29 ||
					(band == 1 && (val > 5)) || // BAND B
					(band == 2 && !(val >= 6 && val <= 13)) ||  // BAND G
					(band == 3 && !(val >= 14 && val <= 29)) || // BAND N
					(band == 4 && !(val >= 2 && val <= 13)) ||  // BAND B+G
					(band == 5 && !(val >= 6 && val <= 29)))    // BAND G+N
				return 0;
		}
		val -= 1;
		txRate = 1 << (val - 1);
		wlanBasicConfig[w_index].DataRate = txRate;
	} else {
		return 0;
	}
	wlanBasicConfig[w_index].changed = 1;
	return 1;
}

void get_wlanSSID(int w_index, int index, char *var_val)
{
	char vap[32];
	char buf[64] = {0,};

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			snprintf(var_val, MAX_SNMP_STR, "%s", buf);
			return;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			snprintf(var_val, MAX_SNMP_STR, "%s", buf);
			return;
		}
	}

	if(!strcmp(wlanMultiConfig[index][w_index].ssid, "")) {
		if (index == 0) {
			sprintf(vap, "WLAN%d_SSID", w_index);
		} else {
			sprintf(vap, "WLAN%d_VAP%d_SSID", w_index, index - 1);
		}
		nvram_get_r_def(vap, buf, sizeof(buf), "");
		snprintf(var_val, MAX_SNMP_STR, "%s", buf);
	} else
		snprintf(var_val, MAX_SNMP_STR, "%s", wlanMultiConfig[index][w_index].ssid);
}

int set_wlanSSID(int w_index, int index, unsigned char *var_val, int val_len)
{
	wlan_idx = w_index;
	vwlan_idx = index;

	if (val_len == 0 && val_len > 32)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	snprintf(wlanMultiConfig[index][w_index].ssid, sizeof(wlanMultiConfig[index][w_index].ssid), "%s", var_val);
	wlanMultiConfig[index][w_index].changed = 1;
	return 1;
}

int get_wlanSSIDMode(int w_index, int index)
{
	char param[20];
	int mode, enabled;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 2;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 2;
		}
	}

	if(wlanMultiConfig[index][w_index].ssidMode == 0) {
		if (index == 0) {
			sprintf(param, "WLAN%d_WLAN_DISABLED", w_index);
		} else if (index >= 1 && index <= 4) {
			sprintf(param, "WLAN%d_VAP%d_WLAN_DISABLED", w_index, index - 1);
		}
		enabled = nvram_atoi(param, 0);
		if(enabled == 0)
			mode = 1;
		else
			mode = 2;
	} else
		mode = wlanMultiConfig[index][w_index].ssidMode;

	return mode;
}

int set_wlanSSIDMode(int w_index, int index, int enabled)
{
	if (enabled != 1 && enabled != 2)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	wlanMultiConfig[index][w_index].ssidMode = enabled;
	wlanMultiConfig[index][w_index].changed = 1;
	return 1;
}

int get_wlanBSSID(int w_index, int index)
{
	char param[20];
	int enabled, mode;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if(wlanMultiConfig[index][w_index].bssid == 0) {
		if (index == 0) {
			sprintf(param, "WLAN%d_HIDDEN_SSID", w_index);
		} else if (index >= 1 && index <= 4) {
			sprintf(param, "WLAN%d_VAP%d_HIDDEN_SSID", w_index, index - 1);
		}
		enabled = nvram_atoi(param, 0);
		if(enabled == 0)
			mode = 1;
		else
			mode = 2;
	} else
		mode = wlanMultiConfig[index][w_index].bssid;

	return mode;
}

int set_wlanBSSID(int w_index, int index, int enabled)
{
	if (enabled != 1 && enabled != 2)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	wlanMultiConfig[index][w_index].bssid = enabled;
	wlanMultiConfig[index][w_index].changed = 1;
	return 1;
}

int get_wlanSecEncryption(int w_index, int index)
{
	char param[20];
	int mode;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if(wlanMultiConfig[index][w_index].enc == 0) {
		if (index == 0) {
			sprintf(param, "WLAN%d_ENCRYPT", w_index);
		} else {
			sprintf(param, "WLAN%d_VAP%d_ENCRYPT", w_index, index - 1);
		}
		mode = nvram_atoi(param, 6);

		switch (mode) {
			case 0:			// disable
				return 1;
			case 1:			// wep
				return 2;
			case 2:			// wpa
				return 3;
			case 4:			// wpa2
				return 4;
			case 6:			// wpa-mixed
				return 5;
		}
	} else
		return wlanMultiConfig[index][w_index].enc;
}

int set_wlanSecEncryption(int w_index, int index, int encrypt)
{
	if (encrypt < 1 || encrypt > 5)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	wlanMultiConfig[index][w_index].enc = encrypt;
	wlanMultiConfig[index][w_index].changed = 1;
	securityConfig[w_index].securityMode[index] = encrypt - 1;
	securityConfig[w_index].changed[index] = 1;

	return 1;
}

int get_wlanRateLimit(int w_index, int index)
{
	char keyStr[32];
	char *ptr;
	int res;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 0;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 0;
		}
	}

	if(wlanMultiConfig[index][w_index].ratelimit == 0) {
		if (index == 0) {
			sprintf(keyStr, "WLAN%d_TX_RESTRICT", w_index);
		} else {
			sprintf(keyStr, "WLAN%d_VAP%d_TX_RESTRICT", w_index, index - 1);
		}
		ptr = getValue(keyStr);

		if(!ptr)
			res = 0;
		else
			res = atoi(ptr);
	} else
		res = wlanMultiConfig[index][w_index].ratelimit;

	if(res <= 1000)
		return (res/10);
	else
		return 0;
}

int set_wlanRateLimit(int w_index, int index, int res)
{
	if (res > 100)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	res *= 10;
	wlanMultiConfig[index][w_index].ratelimit = res;
	wlanMultiConfig[index][w_index].changed = 1;
	return 1;
}

int get_data_size_converter(int data_h, int data_l)
{
	int upperQuotient = data_h;
	int upperRemainder;
	int bottomQuotient = data_l;
	int bottomRemainder = 0;

	if (upperQuotient != 0 || bottomQuotient >= 1024) {
		upperRemainder = upperQuotient & 1023;
		upperQuotient >>= 10;
		bottomRemainder = bottomQuotient & 1023;
		bottomQuotient >>= 10;
		bottomQuotient |= (upperRemainder << 22);
	}
	return bottomQuotient;
}


int get_wlanTrafficInfo(int w_index, int index, char *argv)
{
	FILE *f;
	char buf[80], *args[4];
	char *p = "0";

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 0;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 0;
		}
	}

	if ( index == 0 )
		snprintf(buf, sizeof(buf), "/proc/wlan%d/stats", w_index);
	else
		snprintf(buf, sizeof(buf), "/proc/wlan%d-va%d/stats", w_index, index - 1);

	f = fopen(buf, "r");
	if (f != NULL) {
		while (fgets(buf, sizeof(buf), f)) {
			if (ystrargs(buf, args, _countof(args), ":", 0) &&
					strcmp(args[0], argv) == 0) {
				p = args[1] ? : "0";
				break;
			}
		}
		fclose(f);
	}

	return atoi(p);
}

int set_wlanFragmentThreshold(int index, int res)
{
	if (res >= 256 && res <= 2346) {
		wlanAdvConfig[index].frag_threshold = res;
		wlanAdvConfig[index].changed = 1;
		return 1;
	} else {
		return 0;
	}
}

int get_wlanFragmentThreshold(int index)
{
	char buf[8], param[32];
	int ret;

	if(wlanAdvConfig[index].frag_threshold == 0) {
		sprintf(param, "WLAN%d_FRAG_THRESHOLD", index);
		snprintf(buf, sizeof(buf), "%s", getValue(param));
		ret = atoi(buf);
	} else
		ret = wlanAdvConfig[index].frag_threshold;

	return ret;

}

int get_wlanRTSThreshold(int index)
{
	int res;
	char buf[8], param[32];

	if(wlanAdvConfig[index].rts_threshold == 0) {
		sprintf(param, "WLAN%d_RTS_THRESHOLD", index);
		snprintf(buf, sizeof(buf), "%s", getValue(param));
		res = strtol(buf, NULL, 10);
	} else
		res = wlanAdvConfig[index].rts_threshold;

	return res;

}

int set_wlanRTSThreshold(int index, int res)
{
	if (res < 1 || res > 2347)
		return 0;

	wlanAdvConfig[index].rts_threshold = res;
	wlanAdvConfig[index].changed = 1;
	return 1;
}

int get_wlanBeaconInterval(int index)
{
	int res;
	char buf[8], param[32];

	if(wlanAdvConfig[index].beacon_intv == 0) {
		sprintf(param, "WLAN%d_BEACON_INTERVAL", index);
		snprintf(buf, sizeof(buf), "%s", getValue(param));
		res = strtol(buf, NULL, 10);
	} else
		res = wlanAdvConfig[index].beacon_intv;

	return res;
}

int set_wlanBeaconInterval(int index, int res)
{
	if (res < 50 || res > 1024)
		return 0;
	wlanAdvConfig[index].beacon_intv = res;
	wlanAdvConfig[index].changed = 1;
	return 1;
}

int get_wlanPreambleType(int index)
{
	int res, mode;
	char param[32];

	if(wlanAdvConfig[index].preamble_type == 0) {
		sprintf(param, "WLAN%d_PREAMBLE_TYPE", index);
		mode = nvram_atoi(param, 0);
		if (mode == 0 )
			res = 1;
		else if (mode == 1)
			res = 2;
	} else
		res = wlanAdvConfig[index].preamble_type;

	return res;
}

int set_wlanPreambleType(int index, int res)
{
	if(res != 1 && res != 2)
		return 0;

	wlanAdvConfig[index].preamble_type = res;
	wlanAdvConfig[index].changed = 1;
	return 1;
}

int get_wlanIAPPEnable(int index)
{
	char buf[4], param[32];
	int res, mode;

	if(wlanAdvConfig[index].iapp == 0) {
		sprintf(param, "WLAN%d_IAPP_DISABLED", index);
		snprintf(buf, sizeof(buf), "%s", getValue(param));
		mode = atoi(buf);

		if (mode == 0)
			res = 1;
		else if (mode == 1)
			res = 2;
	} else
		res = wlanAdvConfig[index].iapp;

	return res;
}

int set_wlanIAPPEnable(int index, int res)
{
	if(res != 1 && res != 2)
		return 0;

	wlanAdvConfig[index].iapp = res;
	wlanAdvConfig[index].changed = 1;
	return 1;
}

int get_wlanRFOutputPower(int index)
{
	int rfScale, res;
	char param[32];

	if(wlanAdvConfig[index].rfoutpwr == 0) {
		sprintf(param, "WLAN%d_RFPOWER_SCALE", index);
		rfScale = nvram_atoi(param, 0);

		switch (rfScale) {
			case 0:
				res = 100;
				break;
			case 1:
				res = 70;
				break;
			case 2:
				res = 50;
				break;
			case 3:
				res = 35;
				break;
			case 4:
				res = 15;
				break;
		}
	} else
		res = wlanAdvConfig[index].rfoutpwr;

	return res;
}

int set_wlanRFOutputPower(int index, int res)
{
	switch (res) {
		case 100: case 70: case 50: case 35: case 15:
			break;
		default :
			return 0;
	}

	wlanAdvConfig[index].rfoutpwr = res;
	wlanAdvConfig[index].changed = 1;
	return 1;
}

int get_secWEP8021xAuthMode(int w_index, int index)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 2;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 2;
		}
	}

	if (securityConfig[w_index].secWEPConfig[index].WEP8021xAuthMode == 0){
		return 2;
	} else {
		return 1;
	}
}

int set_secWEP8021xAuthMode(int w_index, int index, int mode)
{
	int newVal;

	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	switch (mode) {
		case 1:
			newVal = 1;
			break;
		case 2:
			newVal = 0;
			break;
		default:
			return 0;
	}
	if (securityConfig[w_index].secWEPConfig[index].WEP8021xAuthMode - '0'!= newVal) {
		securityConfig[w_index].changed[index] = 1;
		securityConfig[w_index].secWEPConfig[index].WEP8021xAuthMode = newVal;
	}

	return 1;
}

int get_secWEPMacAuthMode(int w_index, int index)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 2;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 2;
		}
	}

	if (securityConfig[w_index].secWEPConfig[index].WEPMacAuthMode == 0)
		return 2;
	else
		return 1;
}

int set_secWEPMacAuthMode(int w_index, int index, int res)
{
	int newVal;

	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if (res == 1)
		newVal = 1;
	else if (res == 2)
		newVal = 0;
	else
		return 0;

	if (securityConfig[w_index].secWEPConfig[index].WEPMacAuthMode - '0'!= newVal) {
		securityConfig[w_index].changed[index] = 1;
		securityConfig[w_index].secWEPConfig[index].WEPMacAuthMode = newVal;
	}

	return 1;
}


int get_secWEPAuthMethod(int w_index, int index)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 3;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 3;
		}
	}

	return ((int)securityConfig[w_index].secWEPConfig[index].WEPAuthMethod + 1);
}

int set_secWEPAuthMethod(int w_index, int index, int res)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if (res == 1)
		securityConfig[w_index].secWEPConfig[index].WEPAuthMethod = 0;
	else if (res == 2)
		securityConfig[w_index].secWEPConfig[index].WEPAuthMethod = 1;
	else if (res == 3)
		securityConfig[w_index].secWEPConfig[index].WEPAuthMethod = 2;
	else
		return 0;


	securityConfig[w_index].changed[index] = 1;
	return 1;
}

int get_secWEPKeySize(int w_index, int index)
{
	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	return (int)(securityConfig[w_index].secWEPConfig[index].WEPAuthKeySize);
}

int set_secWEPKeySize(int w_index, int index, int res)
{
	if (index > 4)
		return 0;

	if (res < 1 || res > 2)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if (securityConfig[w_index].secWEPConfig[index].WEPAuthKeySize - '0' == res) {
		securityConfig[w_index].changed[index] = 0;
	} else {
		securityConfig[w_index].changed[index] = 1;
		securityConfig[w_index].secWEPConfig[index].WEPAuthKeySize = res;
	}

	return 1;
}

int get_secWEPAuthEnable(int w_index, int index)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 2;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 2;
		}
	}

	if (securityConfig[w_index].secWEPConfig[index].WEPAuthEnable == 1)
		return 1;
	else if (securityConfig[w_index].secWEPConfig[index].WEPAuthEnable == 0)
		return 2;

	return 0;
}

int set_secWEPAuthEnable(int w_index, int index, int res)
{
	int newVal;

	if (index > 4)
		return 0;

	if (res == 1) {
		newVal = 1;
	} else if (res == 2) {
		newVal = 0;
	} else {
		return 0;
	}

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if (securityConfig[w_index].secWEPConfig[index].WEPAuthEnable - '0' == newVal) {
		securityConfig[w_index].changed[index] = 0;
	} else {
		securityConfig[w_index].changed[index] = 1;
		securityConfig[w_index].secWEPConfig[index].WEPAuthEnable = newVal;
	}

	return 1;
}

int get_secWEPKeyFormat(int w_index, int index)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 2;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 2;
		}
	}

	if (securityConfig[w_index].secWEPConfig[index].WEPKeyFormat == 0)
		return 1;
	else if (securityConfig[w_index].secWEPConfig[index].WEPKeyFormat == 1)
		return 2;

	return 0;
}

int set_secWEPKeyFormat(int w_index, int index, int res)
{
	int newVal;

	if (index > 4)
		return 0;

	if (res == 1)
		newVal = 0;
	else if (res == 2)
		newVal = 1;
	else
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if (securityConfig[w_index].secWEPConfig[index].WEPKeyFormat - '0' == newVal) {
		securityConfig[w_index].changed[index] = 0;
	} else {
		securityConfig[w_index].changed[index] = 1;
		securityConfig[w_index].secWEPConfig[index].WEPKeyFormat = newVal;
	}

	return 1;
}

int get_secWEPKeyIndex(int w_index, int index)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	return ((int)securityConfig[w_index].secWEPConfig[index].WEPKeyIndex);
}

int set_secWEPKeyIndex(int w_index, int index, int res)
{
	if (index > 4)
		return 0;

	if (res < 1 || res > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	securityConfig[w_index].secWEPConfig[index].WEPKeyIndex = res;
	securityConfig[w_index].changed[index] = 1;

	return 1;
}

int get_secWEPEncryptionKey(int w_index, int index, char *var_val)
{
	char buf[64] = {0,};

	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			snprintf(var_val, MAX_SNMP_STR, "%s", buf);
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			snprintf(var_val, MAX_SNMP_STR, "%s", buf);
			return 1;
		}
	}

	snprintf(var_val, MAX_SNMP_STR, "%s", securityConfig[w_index].secWEPConfig[index].EncryptionKey);
	return 1;
}

int set_secWEPEncryptionKey(int w_index, int index, unsigned char *var_val, int val_len)
{
	char tempBuf[28];

	if (index > 4 || val_len == 0)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	securityConfig[w_index].changed[index] = 1;
	memset(tempBuf, 0, sizeof(tempBuf));
	if (securityConfig[w_index].secWEPConfig[index].WEPAuthKeySize == 1) {
		if (securityConfig[w_index].secWEPConfig[index].WEPKeyFormat == 0) {
			if (val_len == 5) {
				snprintf(securityConfig[w_index].secWEPConfig[index].EncryptionKey, sizeof(securityConfig[w_index].secWEPConfig[index].EncryptionKey), "%s", (char*)var_val);
			} else if (val_len == 10 && hex_to_string(var_val, tempBuf, 10)) {
				snprintf(securityConfig[w_index].secWEPConfig[index].EncryptionKey, sizeof(securityConfig[w_index].secWEPConfig[index].EncryptionKey), "%s", tempBuf);
			} else {
				return 0;
			}
		} else {
			if (val_len == 5) {
				string_to_hex(var_val, securityConfig[w_index].secWEPConfig[index].EncryptionKey, 5);
			} else if (val_len == 10 && hex_to_string(var_val, tempBuf, 10)) {
				snprintf(securityConfig[w_index].secWEPConfig[index].EncryptionKey, sizeof(securityConfig[w_index].secWEPConfig[index].EncryptionKey), "%s", (char*)var_val);
			} else {
				return 0;
			}
		}
	} else {
		if (securityConfig[w_index].secWEPConfig[index].WEPKeyFormat == 0) {
			if (val_len == 13)
				snprintf(securityConfig[w_index].secWEPConfig[index].EncryptionKey, sizeof(securityConfig[w_index].secWEPConfig[index].EncryptionKey), "%s", (char*)var_val);
			else if (val_len == 26 && hex_to_string(var_val, tempBuf, 26))
				snprintf(securityConfig[w_index].secWEPConfig[index].EncryptionKey, sizeof(securityConfig[w_index].secWEPConfig[index].EncryptionKey), "%s", tempBuf);
			else
				return 0;
		} else {
			if (val_len == 13)
				string_to_hex(var_val, securityConfig[w_index].secWEPConfig[index].EncryptionKey, 13);
			else if (val_len == 26 && hex_to_string(var_val, tempBuf, 26))
				snprintf(securityConfig[w_index].secWEPConfig[index].EncryptionKey, sizeof(securityConfig[w_index].secWEPConfig[index].EncryptionKey), "%s", (char*)var_val);
			else
				return 0;
		}
	}
	return 1;
}

// WPAx Configuration Fucntion

int get_secWPAxAuthMode(int w_index, int index)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 2;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 2;
		}
	}

	return (int)securityConfig[w_index].secWPAxConfig[index].WPAxAuthMode;
}

int set_secWPAxAuthMode(int w_index, int index, int res)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if (((securityConfig[w_index].securityMode[index] != 2) && (securityConfig[w_index].securityMode[index] != 3)) || ((res != 1) && (res != 2)))
		return 0;

	if (securityConfig[w_index].secWPAxConfig[index].WPAxAuthMode != res) {
		securityConfig[w_index].secWPAxConfig[index].WPAxAuthMode = res;
		securityConfig[w_index].changed[index] = 1;
	}

	return 1;
}

int get_secWPAxCipherSuite(int w_index, int index)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 3;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 3;
		}
	}

	return (int)securityConfig[w_index].secWPAxConfig[index].WPAxCipherSuite;
}

int set_secWPAxCipherSuite(int w_index, int index, int res)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if (((securityConfig[w_index].securityMode[index] != 2) && (securityConfig[w_index].securityMode[index] != 3)) || (res < 1 || res > 3))
		return 0;

	if (securityConfig[w_index].secWPAxConfig[index].WPAxCipherSuite != res) {
		securityConfig[w_index].secWPAxConfig[index].WPAxCipherSuite = res;
		securityConfig[w_index].changed[index] = 1;
	}

	return 1;
}

int get_secWPAxKeyFormat(int w_index, int index)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if (securityConfig[w_index].secWPAxConfig[index].WPAxKeyFormat == 0)
		return 1;
	else if (securityConfig[w_index].secWPAxConfig[index].WPAxKeyFormat == 1)
		return 2;

	return 0;
}

int set_secWPAxKeyFormat(int w_index, int index, int res)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if ((securityConfig[w_index].securityMode[index] != 2) && (securityConfig[w_index].securityMode[index] != 3))
		return 0;

	if (res == 1)
		securityConfig[w_index].secWPAxConfig[index].WPAxKeyFormat = 0;
	else if (res == 2)
		securityConfig[w_index].secWPAxConfig[index].WPAxKeyFormat = 1;
	else
		return 0;

	securityConfig[w_index].changed[index] = 1;
	return 1;
}

int get_secWPAxPreSharedKey(int w_index, int index, char *var_val)
{
	char buf[64] = {0,};

	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			snprintf(var_val, MAX_SNMP_STR, "%s", buf);
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			snprintf(var_val, MAX_SNMP_STR, "%s", buf);
			return 1;
		}
	}

	snprintf(var_val, MAX_SNMP_STR, "%s", securityConfig[w_index].secWPAxConfig[index].PreSharedKey);
	return 1;
}

int set_secWPAxPreSharedKey(int w_index, int index, unsigned char *var_val, int val_len)
{
	char tempBuf[65];

	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if ((securityConfig[w_index].securityMode[index] != 2 && securityConfig[w_index].securityMode[index] != 3) || securityConfig[w_index].secWPAxConfig[index].WPAxAuthMode != 2 || val_len == 0)
		return 0;

	memset(tempBuf, 0, sizeof(tempBuf));
	securityConfig[w_index].changed[index] = 1;
	if (securityConfig[w_index].secWPAxConfig[index].WPAxKeyFormat == 0) {
		if (val_len < 8 || val_len > 64)
			return 0;
		free(securityConfig[w_index].secWPAxConfig[index].PreSharedKey);
		securityConfig[w_index].secWPAxConfig[index].PreSharedKey = malloc(val_len + 1);
		snprintf(securityConfig[w_index].secWPAxConfig[index].PreSharedKey, sizeof(securityConfig[w_index].secWPAxConfig[index].PreSharedKey), "%s", (char*)var_val);
		securityConfig[w_index].secWPAxConfig[index].PreSharedKey[val_len] = 0;
	} else {
		if (val_len < 64 || !hex_to_string(var_val, tempBuf, 64))
			return 0;
		free(securityConfig[w_index].secWPAxConfig[index].PreSharedKey);
		securityConfig[w_index].secWPAxConfig[index].PreSharedKey = malloc(65);
		snprintf(securityConfig[w_index].secWPAxConfig[index].PreSharedKey, sizeof(securityConfig[w_index].secWPAxConfig[index].PreSharedKey), "%s", (char*)var_val);
		securityConfig[w_index].secWPAxConfig[index].PreSharedKey[64] = 0;
	}

	return 1;
}

// WPA mixed Configuration Functions
int get_secWPAmixAuthMode(int w_index, int index)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 2;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 2;
		}
	}

	return (int)securityConfig[w_index].secWPAmixConfig[index].WPAmixAuthMode;
}

int set_secWPAmixAuthMode(int w_index, int index, int res)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if ((securityConfig[w_index].securityMode[index] != 4) || ((res != 1) && (res != 2)))
		return 0;

	if (securityConfig[w_index].secWPAmixConfig[index].WPAmixAuthMode != res) {
		securityConfig[w_index].secWPAmixConfig[index].WPAmixAuthMode = res;
		securityConfig[w_index].changed[index] = 1;
	}

	return 1;
}

int get_secWPAmixCipherSuite(int w_index, int index)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 3;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 3;
		}
	}

	return (int)securityConfig[w_index].secWPAmixConfig[index].WPAmixCipherSuite;
}

int set_secWPAmixCipherSuite(int w_index, int index, int res)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if ((securityConfig[w_index].securityMode[index] != 4) || (res < 1 || res > 3))
		return 0;

	securityConfig[w_index].secWPAmixConfig[index].WPAmixCipherSuite = res;
	securityConfig[w_index].changed[index] = 1;

	return 1;
}

int get_secWPAmix2CipherSuite(int w_index, int index)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 3;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 3;
		}
	}

	return (int)securityConfig[w_index].secWPAmixConfig[index].WPAmix2CipherSuite;
}

int set_secWPAmix2CipherSuite(int w_index, int index, int res)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if ((securityConfig[w_index].securityMode[index] != 4) || (res < 1 || res > 3))
		return 0;

	if (securityConfig[w_index].secWPAmixConfig[index].WPAmix2CipherSuite != res) {
		securityConfig[w_index].secWPAmixConfig[index].WPAmix2CipherSuite = res;
		securityConfig[w_index].changed[index] = 1;
	}

	return 1;
}

int get_secWPAmixKeyFormat(int w_index, int index)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if (securityConfig[w_index].secWPAmixConfig[index].WPAmixKeyFormat == 0)
		return 1;
	else if (securityConfig[w_index].secWPAmixConfig[index].WPAmixKeyFormat == 1)
		return 2;

	return 0;
}

int set_secWPAmixKeyFormat(int w_index, int index, int res)
{
	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if (securityConfig[w_index].securityMode[index] != 4)
		return 0;

	if (res == 1)
		securityConfig[w_index].secWPAmixConfig[index].WPAmixKeyFormat = 0;
	else if (res == 2)
		securityConfig[w_index].secWPAmixConfig[index].WPAmixKeyFormat = 1;
	else
		return 0;

	securityConfig[w_index].changed[index] = 1;
	return 1;
}

int get_secWPAmixPreSharedKey(int w_index, int index, char *var_val)
{
	char buf[64] = {0,};

	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			snprintf(var_val, MAX_SNMP_STR, "%s", buf);
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			snprintf(var_val, MAX_SNMP_STR, "%s", buf);
			return 1;
		}
	}

	snprintf(var_val, MAX_SNMP_STR, "%s", securityConfig[w_index].secWPAmixConfig[index].PreSharedKey);
	return 1;
}

int set_secWPAmixPreSharedKey(int w_index, int index, char *var_val, int val_len)
{
	char tempBuf[65];

	if (index > 4)
		return 0;

	if (w_index == 1) {	/* 2.4G */
		if (index == 3) {	// anyway
			return 1;
		}
	} else {			/* 5G */
		if (index == 1 || index == 2 || index == 3 || index == 4) {	// sk voip t wifi home anyway handover
			return 1;
		}
	}

	if ((securityConfig[w_index].securityMode[index] != 4) || securityConfig[w_index].secWPAmixConfig[index].WPAmixAuthMode != 2 || val_len == 0)
		return 0;

	memset(tempBuf, 0, sizeof(tempBuf));
	securityConfig[w_index].changed[index] = 1;
	if (securityConfig[w_index].secWPAmixConfig[index].WPAmixKeyFormat == 0) {
		if (val_len < 8 || val_len > 64)
			return 0;
		free(securityConfig[w_index].secWPAmixConfig[index].PreSharedKey);
		securityConfig[w_index].secWPAmixConfig[index].PreSharedKey = malloc(val_len + 1);
		snprintf(securityConfig[w_index].secWPAmixConfig[index].PreSharedKey, sizeof(securityConfig[w_index].secWPAmixConfig[index].PreSharedKey), "%s", var_val);
		securityConfig[w_index].secWPAmixConfig[index].PreSharedKey[val_len] = 0;
	} else {
		if (val_len < 64 || !hex_to_string(var_val, tempBuf, 64))
			return 0;
		free(securityConfig[w_index].secWPAmixConfig[index].PreSharedKey);
		securityConfig[w_index].secWPAmixConfig[index].PreSharedKey = malloc(65);
		snprintf(securityConfig[w_index].secWPAmixConfig[index].PreSharedKey, sizeof(securityConfig[w_index].secWPAmixConfig[index].PreSharedKey), "%s", var_val);
		securityConfig[w_index].secWPAmixConfig[index].PreSharedKey[64] = 0;
	}

	return 1;
}

#define RTL8651_IOCTL_GETWANSTATUS          2010
#define RTL8651_IOCTL_GETLANPORTSTATUS      2011
#define RTL8651_IOCTL_GETPORT_CRCERRCOUNT   2300
#define RTL8651_IOCTL_GETPORT_INCOUNT       2301
#define RTL8651_IOCTL_GETPORT_OUTCOUNT      2302

static int re865xIoctl(char *name, unsigned int arg0, unsigned int arg1, unsigned int arg2, unsigned int arg3)
{
	unsigned int args[4];
	struct ifreq ifr;
	int sockfd;

	args[0] = arg0;
	args[1] = arg1;
	args[2] = arg2;
	args[3] = arg3;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("fatal error socket\n");
		return -3;
	}
	strcpy((char *)&ifr.ifr_name, name);
	((unsigned int *)(&ifr.ifr_data))[0] = (unsigned int)args;

	if (ioctl(sockfd, SIOCDEVPRIVATE, &ifr) < 0) {
		perror("device ioctl:");
		close(sockfd);
		return -1;
	}
	close(sockfd);
	return 0;
}                               /* end re865xIoctl */

static int g_ap_opmode;

void init_port_status()
{
	char key[24];
	int i;

	for(i=0; i<=4; i++)
		memset(&portConfig[i], 0, sizeof(portConfig[0]));
	snprintf(key, sizeof(key), "%s", getValue("OP_MODE"));
	g_ap_opmode = strtoul(key, NULL, 10);

	for (i = 0; i <= PH_MAXPORT; i++) {
//		sprintf(key, "x_port_%d_config", i);
//		sprintf(cmd, "%s", getValue(key));
		portReqs[i].phr_port = i;
		memset(&portReqs[i], 0, sizeof(portReqs[0]));
	}
}


int init_securityConfig()
{
	int i, j;
	char buf[65];
	char param[32];
	int keyLength;
	int res;
	char *ptr;

	for (j = 2; j > 0; j--)
	{
		for (i = 0; i < MAX_SSID; i++) {
			securityConfig[j-1].changed[i] = 0;
			if (i == 0)
				sprintf(param, "WLAN%d_ENCRYPT", j - 1);
			else
				sprintf(param, "WLAN%d_VAP%d_ENCRYPT", j - 1, i - 1);
			snprintf(buf, sizeof(buf), "%s", getValue(param));
			res = atoi(buf);
			switch (res) {
				case 0:
				case 1:
				case 2:
					securityConfig[j-1].securityMode[i] = res;
					break;
				case 4:
					securityConfig[j-1].securityMode[i] = 3;
					break;
				case 6:
					securityConfig[j-1].securityMode[i] = 4;
					break;
				default:
					securityConfig[j-1].securityMode[i] = 0;
					break;
			}

			if (i == 0)
				sprintf(param, "WLAN%d_ENABLE_1X", j - 1);
			else
				sprintf(param, "WLAN%d_VAP%d_ENABLE_1X", j - 1, i - 1);
			snprintf(buf, sizeof(buf), "%s", getValue(param));
			securityConfig[j-1].secWEPConfig[i].WEP8021xAuthMode = atoi(buf);

			if (i == 0)
				sprintf(param, "WLAN%d_MAC_AUTH_ENABLED", j - 1);
			else
				sprintf(param, "WLAN%d_VAP%d_MAC_AUTH_ENABLED", j - 1, i - 1);

			snprintf(buf, sizeof(buf), "%s", getValue(param));
			securityConfig[j-1].secWEPConfig[i].WEPMacAuthMode = atoi(buf);

			if (i == 0)
				sprintf(param, "WLAN%d_AUTH_TYPE", j - 1);
			else
				sprintf(param, "WLAN%d_VAP%d_AUTH_TYPE", j - 1, i - 1);
			snprintf(buf, sizeof(buf), "%s", getValue(param));
			securityConfig[j-1].secWEPConfig[i].WEPAuthMethod = atoi(buf);

			if (i == 0)
				sprintf(param, "WLAN%d_WEP", j - 1);
			else
				sprintf(param, "WLAN%d_VAP%d_WEP", j - 1, i - 1);
			snprintf(buf, sizeof(buf), "%s", getValue(param));
			if (atoi(buf) == 0) {
				securityConfig[j-1].secWEPConfig[i].WEPAuthEnable = 0;
				securityConfig[j-1].secWEPConfig[i].WEPAuthKeySize = 1;
			} else {
				securityConfig[j-1].secWEPConfig[i].WEPAuthEnable = 1;
				securityConfig[j-1].secWEPConfig[i].WEPAuthKeySize = atoi(buf);
			}
			if (i == 0)
				sprintf(param, "WLAN%d_WEP_KEY_TYPE", j - 1);
			else
				sprintf(param, "WLAN%d_VAP%d_WEP_KEY_TYPE", j - 1, i - 1);
			snprintf(buf, sizeof(buf), "%s", getValue(param));
			securityConfig[j-1].secWEPConfig[i].WEPKeyFormat = atoi(buf);

			if (i == 0)
				sprintf(param, "WLAN%d_WEP_DEFAULT_KEY", j - 1);
			else
				sprintf(param, "WLAN%d_VAP%d_WEP_DEFAULT_KEY", j - 1, i - 1);
			snprintf(buf, sizeof(buf), "%s", getValue(param));
			securityConfig[j-1].secWEPConfig[i].WEPKeyIndex = atoi(buf) + 1;

			if (securityConfig[j-1].secWEPConfig[i].WEPAuthKeySize == 2) {
				keyLength = 26;
				if (i == 0) {
					if (securityConfig[j-1].secWEPConfig[i].WEPKeyIndex == 0)
						sprintf(param, "WLAN%d_WEP128_KEY1", j - 1);
					else
						sprintf(param, "WLAN%d_WEP128_KEY%d", j - 1, securityConfig[j-1].secWEPConfig[i].WEPKeyIndex);
				} else {
					if (securityConfig[j-1].secWEPConfig[i].WEPKeyIndex == 0)
						sprintf(param, "WLAN%d_VAP%d_WEP128_KEY1", j - 1, i - 1);
					else
						sprintf(param, "WLAN%d_VAP%d_WEP128_KEY%d", j - 1, i - 1, securityConfig[j-1].secWEPConfig[i].WEPKeyIndex);
				}
			} else {
				keyLength = 10;
				if (i == 0) {
					if (securityConfig[j-1].secWEPConfig[i].WEPKeyIndex == 0)
						sprintf(param, "WLAN%d_WEP64_KEY1", j - 1);
					else
						sprintf(param, "WLAN%d_WEP64_KEY%d", j - 1, securityConfig[j-1].secWEPConfig[i].WEPKeyIndex);
				} else {
					if (securityConfig[j-1].secWEPConfig[i].WEPKeyIndex == 0)
						sprintf(param, "WLAN%d_VAP%d_WEP64_KEY1", j - 1, i - 1);
					else
						sprintf(param, "WLAN%d_VAP%d_WEP64_KEY%d", j - 1, i - 1, securityConfig[j-1].secWEPConfig[i].WEPKeyIndex);
				}
			}
			snprintf(buf, sizeof(buf), "%s", getValue(param));
			if (securityConfig[j-1].secWEPConfig[i].WEPKeyFormat == 0)
				hex_to_string(buf, securityConfig[j-1].secWEPConfig[i].EncryptionKey, keyLength);
			else
				snprintf(securityConfig[j-1].secWEPConfig[i].EncryptionKey, sizeof(securityConfig[j-1].secWEPConfig[i].EncryptionKey), "%s", buf);
			// WPAx Setting Load...

			if (i == 0)
				sprintf(param, "WLAN%d_WPA_AUTH", j - 1);
			else
				sprintf(param, "WLAN%d_VAP%d_WPA_AUTH", j - 1, i - 1);
			snprintf(buf, sizeof(buf), "%s", getValue(param));
			securityConfig[j-1].secWPAxConfig[i].WPAxAuthMode = atoi(buf);

			if (securityConfig[j-1].securityMode[i] == 3) {
				if (i == 0)
					sprintf(param, "WLAN%d_WPA2_CIPHER_SUITE", j - 1);
				else
					sprintf(param, "WLAN%d_VAP%d_WPA2_CIPHER_SUITE", j - 1, i - 1);
			} else {
				if (i == 0)
					sprintf(param, "WLAN%d_WPA_CIPHER_SUITE", j - 1);
				else
					sprintf(param, "WLAN%d_VAP%d_WPA_CIPHER_SUITE", j - 1, i - 1);
			}
			snprintf(buf, sizeof(buf), "%s", getValue(param));
			securityConfig[j-1].secWPAxConfig[i].WPAxCipherSuite = atoi(buf);
			if (i == 0)
				sprintf(param, "WLAN%d_PSK_FORMAT", j - 1);
			else
				sprintf(param, "WLAN%d_VAP%d_PSK_FORMAT", j - 1, i - 1);
			snprintf(buf, sizeof(buf), "%s", getValue(param));
			securityConfig[j-1].secWPAxConfig[i].WPAxKeyFormat = atoi(buf);

			if (i == 0)
				sprintf(param, "WLAN%d_WPA_PSK", j - 1);
			else
				sprintf(param, "WLAN%d_VAP%d_WPA_PSK", j - 1, i - 1);
			ptr = getValue(param);

			if(!ptr)
				snprintf(buf, sizeof(buf), "%s", "");
			else
				snprintf(buf, sizeof(buf), "%s", ptr);
			securityConfig[j-1].secWPAxConfig[i].PreSharedKey = malloc(strlen(buf) + 1);
			snprintf(securityConfig[j-1].secWPAxConfig[i].PreSharedKey, sizeof(securityConfig[j-1].secWPAxConfig[i].PreSharedKey), "%s", buf);
			securityConfig[j-1].secWPAxConfig[i].PreSharedKey[strlen(buf)] = 0;

			// WPA mixed Setting Load
			if (i == 0)
				sprintf(param, "WLAN%d_WPA_AUTH", j - 1);
			else
				sprintf(param, "WLAN%d_VAP%d_WPA_AUTH", j - 1, i - 1);
			snprintf(buf, sizeof(buf), "%s", getValue(param));
			securityConfig[j-1].secWPAmixConfig[i].WPAmixAuthMode = atoi(buf);

			if (i == 0)
				sprintf(param, "WLAN%d_WPA_CIPHER_SUITE", j - 1);
			else
				sprintf(param, "WLAN%d_VAP%d_WPA_CIPHER_SUITE", j - 1, i - 1);
			snprintf(buf, sizeof(buf), "%s", getValue(param));
			securityConfig[j-1].secWPAmixConfig[i].WPAmixCipherSuite = atoi(buf);

			if (i == 0)
				sprintf(param, "WLAN%d_WPA2_CIPHER_SUITE", j - 1);
			else
				sprintf(param, "WLAN%d_VAP%d_WPA2_CIPHER_SUITE", j - 1, i - 1);
			snprintf(buf, sizeof(buf), "%s", getValue(param));
			securityConfig[j-1].secWPAmixConfig[i].WPAmix2CipherSuite = atoi(buf);

			if (i == 0)
				sprintf(param, "WLAN%d_PSK_FORMAT", j - 1);
			else
				sprintf(param, "WLAN%d_VAP%d_PSK_FORMAT", j - 1, i - 1);
			snprintf(buf, sizeof(buf), "%s", getValue(param));
			securityConfig[j-1].secWPAmixConfig[i].WPAmixKeyFormat = atoi(buf);

			if (i == 0)
				sprintf(param, "WLAN%d_WPA_PSK", j - 1);
			else
				sprintf(param, "WLAN%d_VAP%d_WPA_PSK", j - 1, i - 1);
			ptr = getValue(param);
			if(!ptr)
				snprintf(buf, sizeof(buf), "%s", "");
			else
				snprintf(buf, sizeof(buf), "%s", ptr);
			securityConfig[j-1].secWPAmixConfig[i].PreSharedKey = malloc(strlen(buf) + 1);
			snprintf(securityConfig[j-1].secWPAmixConfig[i].PreSharedKey, sizeof(securityConfig[j-1].secWPAmixConfig[i].PreSharedKey), "%s", buf);
			securityConfig[j-1].secWPAmixConfig[i].PreSharedKey[strlen(buf)] = 0;
		}
	}
	return 0;
}

int get_devicePortMode(void)
{
	char buf[8], param[32];
	int opMode;
	int repeater;
	int i;

	for (i = 1; i <= 2; i++) {
		snprintf(param, sizeof(param), "REPEATER_ENABLED%d", i);
		snprintf(buf, sizeof(buf), "%s", getValue(param));
		repeater = atoi(buf);
		if (repeater == 1)
			return 3;	//repeater mode
	}

	snprintf(buf, sizeof(buf), "%s", getValue("OP_MODE"));
	opMode = atoi(buf);
	if (opMode == 0) //dhcp
		return 2;
	else if (opMode == 1) //bridge
		return 1;
	else
		return 0;
}

int set_devicePortMode(int opMode)
{
	int old_opMode, new_opMode;
	char buf[8];
	int dhcp;

	snprintf(buf, sizeof(buf), "%s", getValue("OP_MODE"));

	old_opMode = atoi(buf);
	if (old_opMode != opMode)
		needReboot = 1;
	switch (opMode) {
		case 1: //bridge
			new_opMode = 1;
			setValue_mib(MIB_OP_MODE, (void*)&new_opMode);

			dhcp = 0;
			setValue_mib(MIB_DHCP, (void*)&dhcp);
			break;

		case 2: //dhcp
			new_opMode = 0;
			setValue_mib(MIB_OP_MODE, (void*)&new_opMode);

			dhcp = 2;
			setValue_mib(MIB_DHCP, (void*)&dhcp);
			break;
		default:
			return 0;
	}

	return 1;
}

long get_autoUpgradeEnable()
{
	int res;

	res = nvram_atoi("x_autoup_enabled", 1);

	if (res == 0)
		return 2;
	else
		return 1;
}

int set_autoUpgradeEnable(int intVal)
{
	char mode[4];

	if(intVal != 1 && intVal != 2)
		return 0;

	if(intVal == 1)
		snprintf(mode, sizeof(mode), "%s", "1");
	else
		snprintf(mode, sizeof(mode), "%s", "0");
	setValue("x_autoup_enabled", mode);
	return 1;
}

void set_autoUpgradeServer(unsigned char *var_val, int var_val_len)
{
	char *buf;

	buf = malloc(var_val_len + 1);
	memcpy(buf, var_val, var_val_len);
	buf[var_val_len] = 0;

	setValue("x_autoup_domain", buf);
	free(buf);
}

void get_autoUpgradeServer(char *var_val)
{
	char buf[256];

	nvram_get_r_def("x_autoup_domain", buf, sizeof(buf), "iptvsh-mgnt.skbroadband.com:12380");
	snprintf(var_val, MAX_SNMP_STR, "%s", buf);
}

void set_autoUpgradePrefix(unsigned char *var_val, int var_val_len)
{
	char *buf;

	buf = malloc(var_val_len + 1);
	memcpy(buf, var_val, var_val_len);
	buf[var_val_len] = 0;

	setValue("x_autoup_prefix", buf);
	free(buf);
}

void get_autoUpgradePrefix(char *var_val)
{
	char buf[256];

	nvram_get_r_def("x_autoup_prefix", buf, sizeof(buf), "");
	snprintf(var_val, MAX_SNMP_STR, "%s", buf);
}

void set_autoUpFWDataFile(unsigned char *var_val, int var_val_len)
{
	char buf[128] = {0,};

	snprintf(buf, sizeof(buf), "%s", var_val);
	setValue("x_autoup_file", buf);
}

void get_autoUpFWDataFile(char *var_val)
{
	char buf[64];

	nvram_get_r_def("x_autoup_file", buf, sizeof(buf), "H624G_config.txt");
	snprintf(var_val, MAX_SNMP_STR, "%s", buf);
}

int get_sysLogEnable()
{
	int mode, ret;

	if(syslogConfig.logEnable == 0) {
		mode = nvram_atoi("SCRLOG_ENABLED", 3);
		if (mode == 3)
			ret = 1;
		else if (mode == 0)
			ret = 2;
	} else
		ret = syslogConfig.logEnable;

	return ret;
}

int set_sysLogEnable(int res)
{
	if (res != 1 && res != 2)
		return 0;

	syslogConfig.logEnable = res;
	syslogConfig.changed = 1;
	return 1;
}

int get_sysLogRemoteLogEnable()
{
	int ret, mode;

	if(syslogConfig.rlogEnable == 0) {
		mode = nvram_atoi("REMOTELOG_ENABLED", 0);
		if (mode == 1)
			ret = 1;
		else if (mode == 0)
			ret = 2;
	} else
		ret = syslogConfig.rlogEnable;

	return ret;
}

int set_sysLogRemoteLogEnable(int res)
{
	if (res != 1 && res != 2)
		return 0;

	syslogConfig.rlogEnable = res;
	syslogConfig.changed = 1;
	return 1;
}

void get_sysLogRemoteLogServer(unsigned char *server)
{
	char buf[64];

	if(!strcmp(syslogConfig.rlogServer, ""))
		nvram_get_r_def("x_remote_logserver", buf, sizeof(buf), "syslogap.skbroadband.com:10614");
	else
		snprintf(buf, sizeof(buf), "%s", syslogConfig.rlogServer);
	snprintf(server, MAX_SNMP_STR, "%s", buf);
}

int set_sysLogRemoteLogServer(unsigned char *server, int len)
{
	if(!server || len == 0)
		return 0;

	snprintf(syslogConfig.rlogServer, sizeof(syslogConfig.rlogServer), "%s", server);
	syslogConfig.changed = 1;
	return 1;
}

void get_ntpServer(int index, char *server)
{
	char buf[32];
	char param[20];

	if(!strcmp(ntpConfig.ntpServer[index], "")) {
		snprintf(param, sizeof(param), "x_ntp_server_ip%d", index + 1);

		if (index == 0)
			nvram_get_r_def(param, buf, sizeof(buf), "time1.skbroadband.com");
		else if(index == 1)
			nvram_get_r_def(param, buf, sizeof(buf), "time2.skbroadband.com");
		else
			nvram_get_r_def(param, buf, sizeof(buf), "kr.pool.ntp.org");
		snprintf(server, MAX_SNMP_STR, "%s", buf);
	} else
		snprintf(server, MAX_SNMP_STR, "%s", ntpConfig.ntpServer[index]);

	return;
}

int set_ntpServer(int index, char *server)
{
	if(!server)
		return 0;

	snprintf(ntpConfig.ntpServer[index], sizeof(ntpConfig.ntpServer[index]), "%s", server);
	ntpConfig.changed = 1;
	return 1;
}


int get_IgmpMulticastEnable()
{
	int res;

	if(IGMPConfig.igmpEnable == 0) {
		res = nvram_atoi("IGMP_PROXY_DISABLED", 0);
		if (res == 0)
			return 1;
		else
			return 2;
	} else {
		return IGMPConfig.igmpEnable;
	}
}

int get_IgmpSelectMode()
{
	return (g_ap_opmode == 0)? 1 : 2;
}

int set_IgmpMulticastEnable(int res)
{
	if(res != 1 && res != 2)
		return 0;

	IGMPConfig.igmpEnable = res;
	IGMPConfig.changed = 1;
	return 1;
}

int get_IgmpFastLeaveEnable()
{
	int res = 0;

	if(IGMPConfig.fastleaveEnable == 0) {
		res = nvram_atoi("IGMP_FAST_LEAVE_DISABLED", 0);

		if (res == 0)
			return 1;
		else
			return 2;
	} else
		return IGMPConfig.fastleaveEnable;
}

int set_IgmpFastLeaveEnable(int res)
{
	if(res != 1 && res != 2)
		return 0;

	IGMPConfig.fastleaveEnable = res;
	IGMPConfig.changed = 1;
	return 1;
}

int get_IgmpProxyMemberExpireTime()
{
	int res;

	if(IGMPConfig.MemExpTime == 0)
		res = nvram_atoi("x_igmp_expire_time", 60);
	else
		res = IGMPConfig.MemExpTime;

	return res;
}

int set_IgmpProxyMemberExpireTime(int res)
{
	if (res == 0)
		return 0;

	IGMPConfig.MemExpTime = res;
	IGMPConfig.changed = 1;
	return 1;
}

int get_IgmpProxyQueryInterval()
{
	int res;

	if(IGMPConfig.QryIntv == 0)
		res = nvram_atoi("x_igmp_query_interval", 125);
	else
		res = IGMPConfig.QryIntv;

	return res;
}

int set_IgmpProxyQueryInterval(int res)
{
	if (res == 0)
		return 0;

	IGMPConfig.QryIntv = res;
	IGMPConfig.changed = 1;
	return 1;
}

int get_IgmpProxyQueryResInterval()
{
	int res;

	if(IGMPConfig.GrpRespIntv == 0)
		res = nvram_atoi("x_igmp_query_res_interval", 5);
	else
		res = IGMPConfig.GrpRespIntv;

	return res;
}

int set_IgmpProxyQueryResInterval(int res)
{
	if (res == 0)
		return 0;

	IGMPConfig.GrpRespIntv = res;
	IGMPConfig.changed = 1;
	return 1;
}

int get_IgmpProxyGroupMemberInterval()
{
	int res;

	if(IGMPConfig.GrpmemIntv == 0)
		res = nvram_atoi("x_igmp_grpmem_interval", 60);
	else
		res = IGMPConfig.GrpmemIntv;

	return res;
}

int set_IgmpProxyGroupMemberInterval(int res)
{
	if (res == 0)
		return 0;

	IGMPConfig.GrpmemIntv = res;
	IGMPConfig.changed = 1;
	return 1;
}

int get_IgmpProxyGroupQueryInterval()
{
	int res;

	if(IGMPConfig.GrpQryIntv == 0)
		res = nvram_atoi("x_igmp_querier_interval", 125);
	else
		res = IGMPConfig.GrpQryIntv;

	return res;
}

int set_IgmpProxyGroupQueryInterval(int res)
{
	if (res == 0)
		return 0;

	IGMPConfig.GrpQryIntv = res;
	IGMPConfig.changed = 1;
	return 1;
}

int get_LanAccessControlPortOpMode(int port_index)
{
	char param[32];
	char buf[8];

	if (port_index > 4 || nvram_atoi("MACFILTER_ENABLED", 1) == 0)
		return 1;
	else {
		sprintf(param, "x_MACFILTER_OPMODE%d", port_index);
		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "%s", getValue(param));
		if (!strcasecmp(buf, "drop"))
			return 3;
		else if (!strcasecmp(buf, "permit"))
			return 2;
	}
	return 1;
}

int set_LanAccessControlPortOpMode(int port_index, int res)
{
	char param[32];
	char *old_mode, opmode[16], oldmode[16];
	char tmpBuf[128];
	int Count, i, j;
	int portlist;
	char *mac, *cpu_port;

	if (port_index > 4)
		return 0;

	sprintf(param, "x_MACFILTER_OPMODE%d", port_index);
	switch (res) {
		case 1:
			LanAccessControlListDelALList(port_index);
			setValue("MACFILTER_ENABLED", "0");
			break;
		case 2:
			setValue("MACFILTER_ENABLED", "1");
			snprintf(opmode, sizeof(opmode), "%s", "permit");
			break;
		case 3:
			setValue("MACFILTER_ENABLED", "1");
			snprintf(opmode, sizeof(opmode), "%s", "drop");
			break;
		default:
			return 0;
	}

	old_mode = getValue(param);
	if (old_mode == NULL) {
		setValue(param, opmode);
		snprintf(oldmode, sizeof(oldmode), "%s", opmode);
	}

	if (!strcasecmp(oldmode, "permit") && strcasecmp(oldmode, opmode)) {
		yexecl(NULL, "aclwrite del br0 -a drop -r sfilter -o 7 -3 -4 -P %d", 1 << port_index);
	}

	if (!strcasecmp(oldmode, opmode))
		return 1;

	setValue(param, opmode);

	Count = atoi(getValue("x_MACFILTER_TBL_NUM"));
	for (i = 1; i <= Count; i++) {
		sprintf(param, "x_MACFILTER_TBL%d", i);
		snprintf(tmpBuf, sizeof(tmpBuf), "%s", getValue(param));
		mac = strtok(tmpBuf, ",");
		cpu_port = strtok(NULL, ",");
		if (!mac || !cpu_port)
			continue;
		portlist = atoi(cpu_port);
		for (j = 0; j <= 3; j++)
			if ((portlist >> j) & 0x1)
				break;
		if (j > 3 || port_index != j)
			continue;
		yexecl(NULL, "aclwrite del br0 -a drop -r sfilter -o 7 -m %s -P %d -3 -4", mac, 1 << port_index);
	}
	needReboot = 1;

	return 1;
}

int set_AccessControlListSetMacAddr(char *strVal, int val_len, unsigned char *hwaddr)
{
	unsigned char MacAddr[6];
	unsigned char ZeroMac[6];

	memset(ZeroMac, 0, sizeof(ZeroMac));
	if (val_len == 0 || strlen(strVal) == 0)
		return 0;

	if (simple_ether_atoe(strVal, MacAddr) == 0)
		return 0;

	if (!memcmp(MacAddr, ZeroMac, sizeof(MacAddr)))
		return 0;
	memcpy(hwaddr, MacAddr, sizeof(MacAddr));
	return 1;
}

int LanAccessControlListAdd(int port, unsigned char *hwaddr, char *comment)
{
	unsigned char ZeroMac[6];
	int bit_pn;
	char value[128];
	char param[32];
	char buf[128];
	int Count, i;
	memset(ZeroMac, 0, sizeof(ZeroMac));

	if (port == 1)
		bit_pn = 1;
	else if (port == 2)
		bit_pn = 2;
	else if (port == 3)
		bit_pn = 4;
	else if (port == 4)
		bit_pn = 8;
	else
		return 0;

	if (!memcmp(hwaddr, ZeroMac, sizeof(ZeroMac)))
		return 0;

	snprintf(buf, sizeof(buf), "%s", getValue("x_MACFILTER_TBL_NUM"));
	Count = atoi(buf);
	sprintf(value, "%02x:%02x:%02x:%02x:%02x:%02x,%02d,%s", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5],
			bit_pn, comment);
	for (i = 1; i <= Count; i++) {
		sprintf(param, "x_MACFILTER_TBL%d", i);
		snprintf(buf, sizeof(buf), "%s", getValue(param));
		if (!strncasecmp(buf, value, 20)) {
			return 0;
		}
	}
	for ( i = 1; i < 20; i++ ) {
		sprintf(param, "x_MACFILTER_TBL%d", i);
		if ( !getValue(param) ) {
			setValue(param, value);
			break;
		}
	}
	sprintf(buf, "%d", Count + 1);
	setValue("x_MACFILTER_TBL_NUM", buf);

	setValue("MACFILTER_ENABLED", "1");
	needReboot = 1;

	return 1;
}

static int get_aclport_to_port(int port)
{
	int change_port;

	if (port == 4)
		change_port = 3;
	else if (port == 8)
		change_port = 4;
	else
		change_port = port;

	return change_port;
}

static void DvAlignMacFilterEntry(int entryNum)
{
	int i, j;
	char tmpBuf[512], query[32];

	i = j = 1;
//	while (i <= entryNum) {
	for (i = 1; i < 20; i++) {
		sprintf(query, "x_MACFILTER_TBL%d", i);
		if (nvram_get_r(query, tmpBuf, sizeof(tmpBuf)) == NULL)
			continue;
		nvram_unset(query);

		sprintf(query, "x_MACFILTER_TBL%d", j++);
		nvram_set(query, tmpBuf);
	}
}

int LanAccessControlListDel(int port_index, int enable, unsigned char *hwaddr)
{
	int Count, num=0;
	char query[32];
	char tmpBuf[256], value[52];
	char *mac, *port, *ptr;
	int portlist, i, loop=0;
	unsigned char ZeroMac[6];
	int bit_pn;
	if(port_index < 1 || port_index >4)
		return 0;
	if(!enable)
		return 0;
	memset(ZeroMac, 0, sizeof(ZeroMac));

	if (!memcmp(hwaddr, ZeroMac, sizeof(ZeroMac))) //mac check
		return 0;

	snprintf(tmpBuf, sizeof(tmpBuf), "%s", getValue("x_MACFILTER_TBL_NUM"));
	Count = atoi(tmpBuf);

	sprintf(value, "%02x:%02x:%02x:%02x:%02x:%02x", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);

	if(port_index == 1)
		bit_pn = 1;
	else if(port_index == 2)
		bit_pn = 2;
	else if(port_index == 3)
		bit_pn = 4;
	else if(port_index == 4)
		bit_pn = 8;

	while(Count != num){
		loop++;
		sprintf(query, "x_MACFILTER_TBL%d", loop);
		ptr = getValue(query);

		if(!ptr)
			continue;
		else
			memcpy(tmpBuf, ptr, sizeof(tmpBuf));
		num ++;

		mac = strtok(tmpBuf, ",");
		port = strtok(NULL, ",");

		if (!mac || !port)
			return 0;

		portlist = atoi(port);
		if(!strncmp(mac, value, 17) && (portlist == bit_pn)){
			unsetValue(query);
			for (i = 0; i <= 3; i++){
				if ((portlist >> i) & 0x01)
					break;
			}
			if (i > 4)
				return 0;
			sprintf(tmpBuf, "%d", Count - 1);
			setValue("x_MACFILTER_TBL_NUM", tmpBuf);
			needReboot = 1;
			DvAlignMacFilterEntry(Count - 1);
			return 1;
		}
	}
	return 0;
}

static int LanAccessControlListDelALList(int select_port)
{
	int Count;
	char query[32];
	char tmpBuf[80];
	char *args[3];
	int portlist, i;
	int delete_num = 0;
	char *ptr;

	snprintf(tmpBuf, sizeof(tmpBuf), "%s", getValue("x_MACFILTER_TBL_NUM"));

	Count = atoi(tmpBuf);
	for (i = 0; i < Count; i++) {
		sprintf(query, "x_MACFILTER_TBL%d", i + 1);
		ptr = getValue(query);

		if(!ptr)
			continue;
		else
			snprintf(tmpBuf, sizeof(tmpBuf), "%s", ptr);

		ystrargs(tmpBuf, args, _countof(args), ",", 1);
		portlist = atoi(args[1]);

		if (get_aclport_to_port(portlist) == select_port) {
			unsetValue(query);
			delete_num++;
		}
	}

	sprintf(tmpBuf, "%d", Count - delete_num);
	setValue("x_MACFILTER_TBL_NUM", tmpBuf);
	DvAlignMacFilterEntry(Count - delete_num);
	return 1;
}

int LanAccessControlListDelAll(int port)
{
	if(port < 1 || port > 4)
		return 0;

	LanAccessControlListDelALList(port);
	needReboot = 1;

	return 1;
}

int set_LanAccessControlMode(int mode)
{
	if (mode != 1 && mode != 2)
		return 0;

	if (mode == 1) {
		setValue("MACFILTER_ENABLED", "1");
		return 1;
	}
	setValue("MACFILTER_ENABLED", "0");
	return 1;
}

int get_LanAccessControlMode()
{
	char tmpBuf[32];

	if (snprintf(tmpBuf, sizeof(tmpBuf), "%s", getValue("MACFILTER_ENABLED"))) {
		if (!strcmp(tmpBuf, "0"))
			return 2;
		else
			return 1;
	}

	return 2;

}

int get_LanAccessControlListPortNum(int entry)
{
	char tmpBuf[256];
	char query[32];
	char *strmac, *strport;
	int portlist, i, k;
	int tbl_max = atoi(getValue("x_MACFILTER_TBL_NUM"));

	for ( k = entry; k <= tbl_max; k++ ) {
		sprintf(query, "x_MACFILTER_TBL%d", k);
		snprintf(tmpBuf, sizeof(tmpBuf), "%s", getValue(query));

		strmac = strtok(tmpBuf, ",");
		strport = strtok(NULL, ",");
		portlist = atoi(strport);
		for (i = 0; i <= 3; i++) {
			if ( (portlist >> i) == 0x1 ) {
				return i;
			}
		}
	}
	return 0;
}

int get_LanAccessControlListMacAddr(int entry, unsigned char *dstStr)
{
	char tmpBuf[256];
	char query[32];
	char *strmac;
	unsigned char hwAddr[6];
	int i;
	int tbl_max = atoi(getValue("x_MACFILTER_TBL_NUM"));

	for ( i = entry; i <= tbl_max; i++ ) {
		sprintf(query, "x_MACFILTER_TBL%d", i);
		snprintf(tmpBuf, sizeof(tmpBuf), "%s", getValue(query));
		strmac = strtok(tmpBuf, ",");
		if (simple_ether_atoe(strmac, hwAddr)) {
			memcpy(dstStr, hwAddr, sizeof(hwAddr));
			return 1;
		}
	}
	memset(dstStr, 0, 6);
	return 0;
}

int get_LanAccessControlListComment(int entry, unsigned char *dstStr)
{
	char tmpBuf[256];
	char query[32];
	char *strmac, *strport, *strcomment;
	int i;
	int tbl_max = atoi(getValue("x_MACFILTER_TBL_NUM"));

	for ( i = entry; i <= tbl_max; i++ ) {
		sprintf(query, "x_MACFILTER_TBL%d", i);
		snprintf(tmpBuf, sizeof(tmpBuf), "%s", getValue(query));
		strmac = strtok(tmpBuf, ",");
		strport = strtok(NULL, ",");
		strcomment = strtok(NULL, ",");

		if (strcomment != NULL) {
			snprintf((char *)dstStr, MAX_SNMP_STR, "%s", strcomment);
			return 1;
		}
	}
	dstStr[0] = 0;
	return 0;
}

int get_WLanAccessControlOpMode(int index, int wl_index)
{
	char query[64];
	char buf[8];

	if (wl_index == 0)
		sprintf(query, "WLAN%d_MACAC_ENABLED", index);
	else
		sprintf(query, "WLAN%d_VAP%d_MACAC_ENABLED", index, wl_index - 1);

	snprintf(buf, sizeof(buf), "%s", getValue(query));

	return (atoi(buf) + 1);
}

int set_WLanAccessControlOpMode(int w_index, int index, int enabled)
{
	int mode;
	wlan_idx = w_index;
	vwlan_idx = index;

	if (enabled == 1) {
		mode = 0;
		setValue_mib(MIB_WLAN_MACAC_ENABLED, (void*)&mode);
	} else if (enabled == 2) {
		mode = 1;
		setValue_mib(MIB_WLAN_MACAC_ENABLED, (void*)&mode);
	} else if (enabled == 3) {
		mode = 2;
		setValue_mib(MIB_WLAN_MACAC_ENABLED, (void*)&mode);
	}

	return 1;
}

/*
	printf("flash set MACAC_ADDR cmd\n");
	printf("cmd:\n");
	printf("      add mac-addr comment -- append a filter mac address.\n");
	printf("      del entry-number -- delete a filter entry.\n");
	printf("      delall -- delete all filter mac address.\n");
	flash set MACAC_ADDR add 000852888888 hahaha
	flash set WLAN0_VAP0_MACAC_ADDR add 000852888888 hahaha
*/

int set_rearrange_ssid_idx(int index)
{
	if ( index == 1 )
		return 2;

	if ( index == 2 )
		return 3;

	if ( index == 3 )
		return 1;

	return index;

}

int get_rearrange_ssid_idx(int index)
{
	if ( index == 2 )
		return 1;
	if ( index == 3 )
		return 2;
	if ( index == 1 )
		return 3;

	return index;
}

int WLanAccessControlListAdd(int w_index, int wl_index, unsigned char *hwaddr, char *comment)
{
	char acl_cmt[128];
	MACFILTER_T entry;
	if ( !hwaddr )
		return 0;

	acl_cmt[0] = 0;

	snprintf(entry.comment, sizeof(entry.comment), "%s", comment);

	memcpy(entry.macAddr, hwaddr, 6);
	wlan_idx = w_index;
	vwlan_idx = wl_index + 1;

	setValue_mib(MIB_WLAN_AC_ADDR_ADD, (void*)&entry);
	return 1;
}

static void DvAlignWlanEntry(int w_index, int wl_index, int entryNum)
{
	int i, j;
	char tmpBuf[512], query[32];

	i = j = 1;

	for (i = 1; i < 20; i++) {
		if(wl_index == 0) {
			sprintf(query, "WLAN%d_MACAC_ADDR%d", w_index, i);
		} else {
			sprintf(query, "WLAN%d_VAP%d_MACAC_ADDR%d", w_index, wl_index - 1, i);
		}
		if (nvram_get_r(query, tmpBuf, sizeof(tmpBuf)) == NULL)
			continue;
		nvram_unset(query);

		if(wl_index == 0) {
			sprintf(query, "WLAN%d_MACAC_ADDR%d", w_index, j++);
		} else {
			sprintf(query, "WLAN%d_VAP%d_MACAC_ADDR%d", w_index, wl_index - 1, j++);
		}
		nvram_set(query, tmpBuf);
	}
}

int WLanAccessControlListDel(int w_index, int wl_index, int tblNo)
{
	int max;
	char buf[32];
	MACFILTER_T entry;
	wlan_idx = w_index;
	vwlan_idx = wl_index + 1;

	*((char *)&entry) = (char)tblNo;

	if(!apmib_get(MIB_WLAN_MACAC_ADDR, (void*)&entry)){
		printf("entry is empty!\n");
		return 0;
	}

	if(!setValue_mib(MIB_WLAN_AC_ADDR_DEL, (void*)&entry)){
		printf("delete error\n");
		return 0;
	}

	if(wl_index == 0){
		sprintf(buf, "WLAN%d_MACAC_NUM", w_index);
	}else{
		sprintf(buf, "WLAN%d_VAP%d_MACAC_NUM", w_index, wl_index - 1);
	}
	max = atoi(getValue(buf));

	DvAlignWlanEntry(w_index, wl_index, max - 1);
	return 1;
}

int WLanAccessControlListDelAll(int w_index, int wl_index)
{
	int del_num;
	MACFILTER_T entry;

	wlan_idx = w_index;
	vwlan_idx = wl_index;

	if(!setValue_mib(MIB_WLAN_AC_ADDR_DELALL, (void*)&entry)){
		printf("delete error\n");
		return 0;
	} else {
		del_num++;
	}

	return 1;
}

int get_WLanAccessControlListMacAddr(int wl_index, int tblNo, char *mac)
{
	char param[32];
	char buf[128];
	char cmd[256];
	char tmpBuf[256];
	int Count, i;
	char *strValue, *strKey;
	char *strmac;
	FILE *fp;

	for(i = 0; i < 2; i++)
	{
		if (wl_index == 0) {
			sprintf(param, "WLAN%d_MACAC_NUM", i);
			sprintf(cmd, "flash get wlan0 MACAC_ADDR >%s", TEMP_MACAC_LIST_FILE);
		} else {
			sprintf(param, "WLAN%d_VAP%d_MACAC_NUM", i, wl_index - 1);
			sprintf(cmd, "flash get wlan0-va%d MACAC_ADDR >%s", wl_index - 1, TEMP_MACAC_LIST_FILE);
		}
	}

//	flash_read(param, buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "%s", getValue(param));
	Count = atoi(buf);

	system(cmd);

	fp = fopen(TEMP_MACAC_LIST_FILE, "r");
	if (!fp)
		return 0;

	sprintf(param, "MACAC_ADDR%d", tblNo);
	for (i = 1; i <= Count && fgets(tmpBuf, sizeof(tmpBuf), fp); i++) {
		strValue = tmpBuf;
		strKey = strsep(&strValue, "=");
		if (strKey == NULL || strlen(strKey) == 0)
			continue;
		if (strcasecmp(strKey, param) == 0)
			break;
	}

	fclose(fp);
	unlink(TEMP_MACAC_LIST_FILE);
	if (i > Count)
		return 0;
	strmac = strtok(strValue, ",");

	if (strmac != NULL && simple_ether_atoe(strmac, mac))
		return 1;

	return 0;
}

int get_WLanAccessControlListComment(int wl_index, int tblNo, char *comment)
{
	char param[32];
	char buf[128];
	char cmd[256];
	char tmpBuf[256];
	int Count, i;
	char *strValue, *strKey;
	char *strmac, *strcomment;
	FILE *fp;

	for(i = 0; i < 2; i++)
	{
		if (wl_index == 0) {
			sprintf(param, "WLAN%d_MACAC_NUM", i);
			sprintf(cmd, "flash get wlan0 MACAC_ADDR >%s", TEMP_MACAC_LIST_FILE);
		} else {
			sprintf(param, "WLAN%d_VAP%d_MACAC_NUM", i, wl_index - 1);
			sprintf(cmd, "flash get wlan0-va%d MACAC_ADDR >%s", wl_index - 1, TEMP_MACAC_LIST_FILE);
		}
	}
//	flash_read(param, buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "%s", getValue(param));
	Count = atoi(buf);

	system(cmd);

	fp = fopen(TEMP_MACAC_LIST_FILE, "r");
	if (!fp)
		return 0;
	sprintf(param, "MACAC_ADDR%d", tblNo);
	for (i = 1; i <= Count && fgets(tmpBuf, sizeof(tmpBuf), fp); i++) {
		strValue = tmpBuf;
		strKey = strsep(&strValue, "=");
		if (strKey == NULL || strlen(strKey) == 0)
			continue;
		if (!strcasecmp(strKey, param))
			break;
	}

	fclose(fp);
	unlink(TEMP_MACAC_LIST_FILE);
	if (i > Count)
		return 0;
	strmac = strtok(strValue, ",");
	strcomment = strtok(NULL, ",");
	trim_spaces(strcomment);
	snprintf(comment, MAX_SNMP_STR, "%s", strcomment);
	return 0;
}

int get_vlanVid(int no)
{
	char param[16];
	char buf[32];
	char *vid;

	sprintf(param, "x_VLAN_%d", no);
	nvram_get_r_def(param, buf, sizeof(buf), "0_0_0");

	vid = strtok(buf, "_");
	return (atoi(vid));
}

int rearrange_index(int index)
{
	if(index == 4)
		return 0;
	else
		return (index + 1);
}

int get_vlanMemberPort(int no)
{
	char param[16];
	char buf[32];
	char *vid, *strset, *strtagged;
	int setVal, taggedVal;
	int rtnVal, i, j;
	int bit;

	sprintf(param, "x_VLAN_%d", no);
	nvram_get_r_def(param, buf, sizeof(buf), "0_0_0");

	vid = strtok(buf, "_");
	strset = strtok(NULL, "_");
	strtagged = strtok(NULL, "_");

	setVal = strtol(strset, NULL, 16);
	taggedVal = strtol(strtagged, NULL, 16);

	rtnVal = 0;
	for (i = 0; i <= 4; i++) {
		if (setVal & (1 << i)) {
			if (taggedVal & (1 << i))
				bit = 1; // 01 (tag)
			else
				bit = 2; // 10 (untag)
		} else {
			bit = 0;	// 00 (disable)
		}
		j = rearrange_index(i);
		rtnVal |= (bit << (j * 2));
	}

	return (rtnVal);
}

void get_portFwProtocol(unsigned char *protocol)
{
	if(!protocol)
		return;

	protocol[0] = 0;

	if (portfw_entry.protocol == 1)
		snprintf(protocol, MAX_SNMP_STR, "%s", "tcp:6");
	else if (portfw_entry.protocol == 2)
		snprintf(protocol, MAX_SNMP_STR, "%s", "udp:17");
	else if (portfw_entry.protocol == 3)
		snprintf(protocol, MAX_SNMP_STR, "%s", "all");
	else
		snprintf(protocol, MAX_SNMP_STR, "%s", "");
}

int set_portFwProtocol(unsigned char *protocol, int len)
{
	if(!protocol)
		return 0;

	if (strcmp(protocol, "all") == 0)
		portfw_entry.protocol = 3;
	else if (strcmp(protocol, "tcp:6") == 0)
		portfw_entry.protocol = 1;
	else if (strcmp(protocol, "udp:17") == 0)
		portfw_entry.protocol = 2;
	else
		return 0;

	return 1;
}

int get_PortFwExternalSport()
{
	return portfw_entry.startport;
}

int set_PortFwExternalSport(int portNum)
{
	if (!portNum || portNum > 65535)
		return 0;

	portfw_entry.startport = portNum;
	return 1;
}

int get_PortFwExternalEport()
{
	return portfw_entry.endport;
}

int set_PortFwExternalEport(int portNum)
{
	if (!portNum || portNum > 65535)
		return 0;

	portfw_entry.endport = portNum;
	return 1;
}

void get_PortFwIpAddress(void *ipAddr)
{
	*(unsigned int *)ipAddr = portfw_entry.ipaddr;
}

int set_PortFwIpAddress(unsigned char *ipAddr)
{
	unsigned long lan_ip, maskaddr;
	unsigned long *p = ipAddr;

	getInAddr("br0", IP_ADDR, (void *)&lan_ip);
	getInAddr("br0", SUBNET_MASK, (void *)&maskaddr );

	if(lan_ip == *(unsigned long *)p)
		return 0;

	if ( ((lan_ip&maskaddr) !=  (*(unsigned long *)p&maskaddr)) )
		return 0;

	portfw_entry.ipaddr = *(unsigned long *)p;
	return 1;
}

int get_PortFwInternalSport()
{
	return portfw_entry.slanport;
}

int set_PortFwInternalSport(int portNum)
{
	if(!portNum || portNum > 65535 )
		return 0;

	portfw_entry.slanport = portNum;

	return 1;
}

int get_PortFwInternalEport()
{
	return portfw_entry.elanport;
}

int set_PortFwInternalEport(int portNum)
{
	if(!portNum || portNum > 65535 )
		return 0;

	portfw_entry.elanport = portNum;

	return 1;
}

int set_PortFwEnable(int portfwAdd)
{
	if (!portfwAdd)
		return 0;

	if((portfw_tblnum + 1) > 20)
		return 0;

	if(portfw_entry.ipaddr && portfw_entry.startport && portfw_entry.endport && portfw_entry.slanport && portfw_entry.protocol) {
		if(portfw_entry.startport > portfw_entry.endport)
			return 0;

		if (check_entry_portfw(0) == 0)
			return 0;

		portfw_tbl[portfw_tblnum].protocol = portfw_entry.protocol;
		portfw_tbl[portfw_tblnum].startport = portfw_entry.startport;
		portfw_tbl[portfw_tblnum].endport = portfw_entry.endport;
		portfw_tbl[portfw_tblnum].ipaddr = portfw_entry.ipaddr;
		portfw_tbl[portfw_tblnum].slanport = portfw_entry.slanport;
		portfw_tbl[portfw_tblnum].elanport = portfw_entry.elanport;
		snprintf(portfw_tbl[portfw_tblnum].name, sizeof(portfw_tbl[portfw_tblnum].name), "%s", portfw_entry.name);
		portfw_entry.changed = 1;
		portfw_tblnum++;

		return 1;
	}
	return 0;
}

void dvnv_portfw_rerrange(int portfwDel)
{
	int i;

	for (i = portfwDel; i < portfw_tblnum; i++) {
		if(i == portfw_tblnum - 1)
			memset(&portfw_tbl[i], 0, sizeof(portfw_tbl[i]));
		else {
			memcpy(&portfw_tbl[i], &portfw_tbl[i+1], sizeof(portfw_tbl[i+1]));
			memset(&portfw_tbl[i+1], 0, sizeof(portfw_tbl[i+1]));
		}
	}
	portfw_tblnum--;
}

int set_PortFwDelete(int portfwDel)
{
	if (portfwDel < 1 || portfwDel > 20)
		return 0;

	if(!portfw_tblnum || (portfwDel > portfw_tblnum))
		return 0;

	memset(&portfw_tbl[portfw_tblnum], 0, sizeof(portfw_tbl[portfw_tblnum]));
	dvnv_portfw_rerrange(portfwDel - 1);
	portfw_entry.changed = 1;
	return 1;
}

int set_PortFwDeleteAll(int deleteAll)
{
	char cmd[256], param[32];
	int i;

	if (!deleteAll)
		return 0;

	for (i = 0; i < portfw_tblnum; i++)
		memset(&portfw_tbl[i], 0, sizeof(portfw_tbl[i]));

	portfw_tblnum = 0;
	portfw_entry.changed = 1;
	return 1;
}

int set_portFwStartPort(int index, int portNum)
{
	if (!portNum || portNum > 65535)
		return -1;

	portfw_tbl[index].startport = portNum;
	portfw_entry.changed = 1;
	return 0;
}

int get_portFwStartPort(int index)
{
	return portfw_tbl[index].startport;
}

int set_portFwEndPort(int index, int portNum)
{
	if (!portNum || portNum > 65535)
		return -1;

	if (portNum < portfw_tbl[index].startport)
		return -1;

	portfw_tbl[index].endport = portNum;
	portfw_entry.changed = 1;
	return 0;
}

int get_portFwEndPort(int index)
{
	return portfw_tbl[index].endport;
}

int set_PortfwLanAddr(int index, unsigned char *Ipaddress)
{
	unsigned long lan_ip, maskaddr;
	unsigned long *p = Ipaddress;

	getInAddr("br0", IP_ADDR, (void *)&lan_ip);
	getInAddr("br0", SUBNET_MASK, (void *)&maskaddr);

	if( lan_ip == *(unsigned long *)p )
		return -1;

	if ( ((lan_ip&maskaddr) !=  (*(unsigned long *)p&maskaddr)) )
		return -1;

	portfw_tbl[index].ipaddr = *(unsigned long *)p;
	portfw_entry.changed = 1;
	return 0;
}

void get_PortfwIpAddress(int index, void *Ip)
{
	*(unsigned long*)Ip = portfw_tbl[index].ipaddr;
}

int set_portFwLanPort(int index, int portNum)
{
	if (!portNum || portNum > 65535)
		return -1;

	portfw_tbl[index].slanport = portNum;
	portfw_entry.changed = 1;
	return 0;
}

int get_portFwLanPort(int index)
{
	return portfw_tbl[index].slanport;
}

int get_PortRateLimitMode(int port_index)
{
	char param[32];
	int mode, res;

	if(QosConfig[port_index].limitMode == 0) {
		snprintf(param, sizeof(param), "x_QOS_ENABLE_%d", port_index==0 ? 4:port_index - 1);
		mode = nvram_atoi(param, 1);

		if (mode == 0)
			res = 2;
		else
			res = 1;
	} else
		res = QosConfig[port_index].limitMode;

	return res;
}

int set_PortRateLimitMode(int port_index, int res)
{
	if(res != 1 && res != 2)
		return 0;

	QosConfig[port_index].limitMode = res;
	QosConfig[port_index].changed = 1;
	return 1;
}

int get_PortRateLimitIncomming(int port_index)
{
	char param[32];
	int rate = 0, val;

	if (port_index >= MAX_PORT)
		return 0;

	if(QosConfig[port_index].Rxlimit == 0) {
		snprintf(param, sizeof(param), "x_QOS_RATE_I_%d", port_index==0 ? 4:port_index - 1);
		val = nvram_atoi(param, 0);
		rate = 100 * val / 1000;
	} else
		rate = 100 *  QosConfig[port_index].Rxlimit / 1000;
	return rate;

}

int set_PortRateLimitIncomming(int port_index, int rate)
{
	if(rate < 1 || rate > 100)
		return 0;

	if (port_index >= MAX_PORT)
		return 0;

	QosConfig[port_index].Rxlimit = 1000 * rate / 100;
	QosConfig[port_index].changed = 1;
	return 1;
}

int get_PortRateLimitOutgoing(int port_index)
{
	char param[32];
	int rate = 0, val;

	if (port_index >= MAX_PORT)
		return 0;

	if(QosConfig[port_index].Txlimit == 0) {
		snprintf(param, sizeof(param), "x_QOS_RATE_O_%d", port_index==0 ? 4:port_index - 1);
		val = nvram_atoi(param, 0);
		rate = 100 * val / 1000;
	} else
		rate = 100 * QosConfig[port_index].Txlimit / 1000;

	return rate;
}

int set_PortRateLimitOutgoing(int port_index, int rate)
{
	if(rate < 1 || rate > 100)
		return 0;

	if (port_index >= MAX_PORT)
		return 0;

	QosConfig[port_index].Txlimit = 1000 * rate / 100;
	QosConfig[port_index].changed = 1;
	return 1;
}

int get_PortFlowControl(int port)
{
	char var[32];
	int mode, res;

	if (port > 4)
		return 0;

	if(QosConfig[port].flowCtrl == 0) {
		snprintf(var, sizeof(var), "x_QOS_RATE_ENABLE_%d", port==0 ? 4:port - 1);
		mode = nvram_atoi(var, 0);

		if(mode == 0) // off
			res = 1;
		else
			res = 2;
	} else
		res = QosConfig[port].flowCtrl;

	return res;
}

int set_PortFlowControl(int port, int res)
{
	if (port > 4)
		return 0;

	if(res != 1 && res != 2) // off:1   on:2
		return 0;

	QosConfig[port].flowCtrl = res;
	QosConfig[port].changed = 1;
	needReboot = 1;
	return 1;
}

void get_QosRuleDstIp(int index, char *val)
{
	int ruleType;
	char *tmp;
	char param[8];
	char *ruleStr, *ptr;
	struct in_addr ipaddr;

	snprintf(val, MAX_SNMP_STR, "%s", "none");

	sprintf(param, "x_Q_R_%d", index);
	tmp = getValue(param);
	if(!tmp) {
		return;
	} else {
		ruleType = atoi(tmp);
	}

	ptr = strchr(tmp, '_');
	if (ptr == NULL || strlen(ptr) <= 1)
		return;
	ptr = ptr + 1;
	ptr = strchr(ptr, '_');
	if (ptr == NULL || strlen(ptr) <= 1)
		return;
	ruleStr = ptr + 1;

	if (ruleType == 1 || ruleType == 2 || ruleType == 3) {
		ptr = strsep(&ruleStr, "_");
		ptr = strsep(&ruleStr, "_");
		ptr = strsep(&ruleStr, "_");
		if (ptr && ptr[0]) {
			ipaddr.s_addr = htonl(strtoul(ptr, NULL, 16));
			ptr = strsep(&ruleStr, "_");
			if (ptr && ptr[0])
				sprintf(val, "%s/%s", inet_ntoa(ipaddr), ptr);
			else
				sprintf(val, "%s", inet_ntoa(ipaddr));
		}
	}
}

void get_QosRuleSrcIp(int index, char *val)
{
	int ruleType;
	char *tmp;
	char param[8];
	char *ruleStr, *ptr;
	struct in_addr ipaddr;
	int mask;

	snprintf(val, MAX_SNMP_STR, "%s", "none");
	ipaddr.s_addr = 0;
	sprintf(param, "x_Q_R_%d", index);
	tmp = getValue(param);

	if(!tmp) {
		return;
	} else {
		ruleType = atoi(tmp);
	}

	ptr = strchr(tmp, '_');
	if (ptr == NULL || strlen(ptr) <= 1)
		return;
	ptr = ptr + 1;
	ptr = strchr(ptr, '_');
	if (ptr == NULL || strlen(ptr) <= 1)
		return;
	ruleStr = ptr + 1;

	switch (ruleType) {
		case 0:
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			if (ptr && ptr[0]) {
				ipaddr.s_addr = htonl(strtoul(ptr, NULL, 16));
				ptr = strsep(&ruleStr, "_");
				mask = atoi(ptr);
				sprintf(val, "%s/%d", inet_ntoa(ipaddr), mask);
			}
			break;
		case 1:
			break;
		case 2:
		case 3:
			ptr = strsep(&ruleStr, "_");
			if (ptr && ptr[0]) {
				ipaddr.s_addr = htonl(strtoul(ptr, NULL, 16));
				ptr = strsep(&ruleStr, "_");
				mask = atoi(ptr);
				sprintf(val, "%s/%d", inet_ntoa(ipaddr), mask);
			}
			break;
		case 4:
		default:
			break;;
	}
}

void get_QosRuleDstPortStart(int index, char *val)
{
	int ruleType;
	char *tmp;
	char param[8];
	char *ruleStr, *ptr;

	snprintf(val, MAX_SNMP_STR, "%s", "none");
	sprintf(param, "x_Q_R_%d", index);
	tmp = getValue(param);
	if (!tmp) {
		return;
	} else {
		ruleType = atoi(tmp);
		ptr = strchr(tmp, '_');
		if (ptr == NULL || strlen(ptr) <= 1)
			return;
		ptr += 1;
		ptr = strchr(ptr, '_');
		if (ptr == NULL || strlen(ptr) <= 1)
			return;
		ruleStr = ptr + 1;

		if (ruleType == 1) {
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			if (ptr && ptr[0])
				sprintf(val, "%d", atoi(ptr));
		} else if (ruleType == 3) {
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			if (ptr && ptr[0])
				sprintf(val, "%d", atoi(ptr));
		}
	}
}

void get_QosRuleDstPortEnd(int index, char *val)
{
	int ruleType;
	char *tmp;
	char param[8];
	char *ruleStr, *ptr;

	snprintf(val, MAX_SNMP_STR, "%s", "none");
	sprintf(param, "x_Q_R_%d", index);
	tmp = getValue(param);
	if (!tmp) {
		return;
	} else {
		ruleType = atoi(tmp);
		ptr = strchr(tmp, '_');
		if (ptr == NULL || strlen(ptr) <= 1)
			return;
		ptr += 1;
		ptr = strchr(ptr, '_');
		if (ptr == NULL || strlen(ptr) <= 1)
			return;
		ruleStr = ptr + 1;

		if (ruleType == 1) {
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			if (ptr && ptr[0])
				sprintf(val, "%d", atoi(ptr));
		} else if (ruleType == 3) {
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			if (ptr && ptr[0])
				sprintf(val, "%d", atoi(ptr));
		}
	}
}

void get_QosRuleSrcPortStart(int index, char *val)
{
	int ruleType;
	char *tmp;
	char param[8];
	char *ruleStr, *ptr;

	snprintf(val, MAX_SNMP_STR, "%s", "none");
	sprintf(param, "x_Q_R_%d", index);
	tmp = getValue(param);
	if (!tmp) {
		return;
	} else {
		ruleType = atoi(tmp);

		ptr = strchr(tmp, '_');
		if (ptr == NULL || strlen(ptr) <= 1)
			return;
		ptr += 1;
		ptr = strchr(ptr, '_');
		if (ptr == NULL || strlen(ptr) <= 1)
			return;
		ruleStr = ptr + 1;
		if (ruleType == 0) {
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			if (ptr && ptr[0])
				sprintf(val, "%d", atoi(ptr));
		} else if (ruleType == 3) {
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			if (ptr && ptr[0])
				sprintf(val, "%d", atoi(ptr));
		}
	}
}

void get_QosRuleSrcPortEnd(int index, char *val)
{
	int ruleType;
	char *tmp;
	char param[8];
	char *ruleStr, *ptr;

	snprintf(val, MAX_SNMP_STR, "%s", "none");
	sprintf(param, "x_Q_R_%d", index);
	tmp = getValue(param);

	if (!tmp) {
		return;
	} else {
		ruleType = atoi(tmp);

		ptr = strchr(tmp, '_');
		if (ptr == NULL || strlen(ptr) <= 1)
			return;
		ptr += 1;
		ptr = strchr(ptr, '_');
		if (ptr == NULL || strlen(ptr) <= 1)
			return;
		ruleStr = ptr + 1;
		if (ruleType == 0) {
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			if (ptr && ptr[0])
				sprintf(val, "%d", atoi(ptr));
		} else if (ruleType == 3) {
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			if (ptr && ptr[0])
				sprintf(val, "%d", atoi(ptr));
		}
	}
}

void get_QosRuleDstMacAddr(int index, char *val)
{
	sprintf(val, "none");
}

void get_QosRuleSrcMacAddr(int index, char *val)
{
	sprintf(val, "none");
}

int get_QosRuleProtocol(int index, char *val)
{
	char tmp[128];
	char param[8];

	snprintf(val, MAX_SNMP_STR, "%s", "none");
	sprintf(param, "x_Q_R_%d", index);
	snprintf(tmp, sizeof(tmp), "%s", getValue(param));

	if(strchr(tmp, 't'))
		snprintf(val, MAX_SNMP_STR, "%s", "tcp");

	if(strchr(tmp, 'u'))
		snprintf(val, MAX_SNMP_STR, "%s", "udp");
}

int get_PortQosPriority(int index)
{
	char *tmpBuf, temp[32];
	char *p, *q;
	int QosRuleCount = 0, i;
	int length, result=99;

	tmpBuf = getValue("x_Q_R_NUM");
	if(tmpBuf) {
		QosRuleCount = atoi(tmpBuf);
	}

	if(!QosRuleCount)
		return result; //not config

	for(i=0; i<QosRuleCount; i++){
		sprintf(temp, "x_Q_R_%d", i);
		tmpBuf = getValue(temp);

		length = strlen(tmpBuf);
		q = tmpBuf[(length -1)];

		if(!isdigit(q))
			continue;

		if ((p=strstr(tmpBuf, "br0"))) {
			if(tmpBuf[6]=='0' && index ==1) {
				result = (q-48);
			} else if(tmpBuf[6]=='1' && index ==2) {
				result = (q-48);
			} else if(tmpBuf[6]=='2' && index ==3) {
				result = (q-48);
			} else if(tmpBuf[6]=='3' && index ==4) {
				result = (q-48);
			} else if(tmpBuf[6]=='4' && index ==0) {
				result = (q-48);
			}

		}
	}
	return result;
}

int get_QosRuleCos(int index)
{
	int ruleType;
	char tmp[128];
	char param[8];
	char *ruleStr, *ptr;
	int res = 99;

	sprintf(param, "x_Q_R_%d", index);
	if (snprintf(tmp, sizeof(tmp), "%s", getValue(param)) == 0)
		return res;

	ruleType = atoi(tmp);
	ptr = strchr(tmp, '_');
	if (ptr == NULL || strlen(ptr) <= 1)
		return res;
	ptr += 1;
	ptr = strchr(ptr, '_');
	if (ptr == NULL || strlen(ptr) <= 1)
		return res;
	ruleStr = ptr + 1;

	if (ruleType == 0) {
		ptr = strsep(&ruleStr, "_");
		ptr = strsep(&ruleStr, "_");
		ptr = strsep(&ruleStr, "_");
		if (ptr && ptr[0]) {
			res = atoi(ptr);
		}
	} else if (ruleType == 1) {
		ptr = strsep(&ruleStr, "_");
		ptr = strsep(&ruleStr, "_");
		if (ptr && ptr[0]) {
			res = atoi(ptr);
		}
	} else if (ruleType == 4) {
		ptr = strsep(&ruleStr, "_");
		if (ptr && ptr[0]) {
			res = atoi(ptr);
		}
	}
	return res;
}

int get_QosRuleTosType(int index)
{
	int ruleType;
	char *tmp;
	char param[8];
	char *ruleStr, *ptr;
	int type = 0;
	int mask;

	sprintf(param, "x_Q_R_%d", index);
	tmp =  getValue(param);

	if(!tmp)
		return type;

	ruleType = atoi(tmp);
	ptr = strchr(tmp, '_');
	if (ptr == NULL || strlen(ptr) <= 1)
		return type;
	ptr += 1;
	ptr = strchr(ptr, '_');
	if (ptr == NULL || strlen(ptr) <= 1)
		return type;
	ruleStr = ptr + 1;

	if (ruleType == 2 || ruleType == 3) {
		ptr = strsep(&ruleStr, "_");
		ptr = strsep(&ruleStr, "_");
		ptr = strsep(&ruleStr, "_");
		ptr = strsep(&ruleStr, "_");
		ptr = strsep(&ruleStr, "_");
		if (ptr && ptr[0]) {
			ptr = strsep(&ruleStr, "_");
			mask = strtoul(ptr, NULL, 16);
			if (mask == 0xfc)
				type = 2;
			else if (mask == 0xff)
				type = 1;
		}
	}

	return type;

}

int get_QosRuleTos(int index)
{
	int ruleType;
	char tmp[128];
	char param[8];
	char *ruleStr, *ptr;
	int tos = 0;
	int mask;

	sprintf(param, "x_Q_R_%d", index);
	if (snprintf(tmp, sizeof(tmp), "%s", getValue(param)) == 0)
		return 0;

	ruleType = atoi(tmp);
	ptr = strchr(tmp, '_');
	if (ptr == NULL || strlen(ptr) <= 1)
		return 0;
	ptr += 1;
	ptr = strchr(ptr, '_');
	if (ptr == NULL || strlen(ptr) <= 1)
		return 0;
	ruleStr = ptr + 1;

	if (ruleType == 2 || ruleType == 3) {
		ptr = strsep(&ruleStr, "_");
		ptr = strsep(&ruleStr, "_");
		ptr = strsep(&ruleStr, "_");
		ptr = strsep(&ruleStr, "_");
		ptr = strsep(&ruleStr, "_");
		if (ptr && ptr[0]) {
			tos = strtoul(ptr, NULL, 16);
			ptr = strsep(&ruleStr, "_");
			mask = strtoul(ptr, NULL, 16);
			if (mask == 0xfc)
				tos = (tos >> 2) & 0xff;
		}
	}
	return tos;
}

void get_QosRuleEthType(int index, char *val)
{
	int ruleType;
	char tmp[128];
	char param[8];
	char *ruleStr, *ptr;

	snprintf(val, MAX_SNMP_STR, "%s", "none");
	sprintf(param, "x_Q_R_%d", index);
	if (snprintf(tmp, sizeof(tmp), "%s", getValue(param)) == 0)
		return;

	ruleType = atoi(tmp);
	ptr = strchr(tmp, '_');
	if (ptr == NULL || strlen(ptr) <= 1)
		return;
	ptr += 1;
	ptr = strchr(ptr, '_');
	if (ptr == NULL || strlen(ptr) <= 1)
		return;
	ruleStr = ptr + 1;

}

int get_QosRuleMarkIndex(int index)
{
	int ruleType;
	char tmp[128];
	char param[8];
	char *ruleStr, *ptr;
	int res = 99;

	sprintf(param, "x_Q_R_%d", index);
	if (snprintf(tmp, sizeof(tmp), "%s", getValue(param)) == 0)
		return 0;

	ruleType = atoi(tmp);
	ptr = strchr(tmp, '_');
	if (ptr == NULL || strlen(ptr) <= 1)
		return 0;
	ptr += 1;
	ptr = strchr(ptr, '_');
	if (ptr == NULL || strlen(ptr) <= 1)
		return 0;
	ruleStr = ptr + 1;
	ptr = NULL;

	switch (ruleType) {
		case 0:
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			break;
		case 1:
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			break;
		case 2:
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			break;
		case 3:
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			break;
		case 4:
			ptr = strsep(&ruleStr, "_");
			ptr = strsep(&ruleStr, "_");
			break;
	}

	if (ptr && ptr[0] && ptr[0] != 'd')
		res = atoi(ptr);

	return res;
}

int get_QosScheduleMode(int pn, int qn)
{
	char param[16];
	char buf[16];

	sprintf(param, "x_QOS_Q_%d_%d", pn==0?4:pn-1, qn);

	if (snprintf(buf, sizeof(buf), "%s", getValue(param))) {
		if (buf[0] == 'S' || buf[0] == 's')
			return 4;
		else if (buf[0] == 'W' || buf[0] == 'w')
			return 3;
	}

	return 0;
}

int get_QosScheduleWeight(int pn, int qn)
{
	char param[16];
	char buf[16];
	char *tmpVal;

	sprintf(param, "x_QOS_Q_%d_%d", pn==0?4:pn-1, qn);

	if (snprintf(buf, sizeof(buf), "%s", getValue(param))) {
		tmpVal = strtok(buf, "_");
		if(tmpVal[0] == 'S')
			return 255;
		tmpVal = strtok(NULL, "_");
		tmpVal = strtok(NULL, "_");
		if (tmpVal != NULL)
			return (atoi(tmpVal));
	}

	return 0;
}

struct _IgmpJoinTest_T_ {
	int GroupAddress;
	int GroupPort;
	int Version;
};

struct _IgmpJoinTest_T_ igmpJoinTest;


int get_IgmpJoinTestGroupAddr()
{
	return igmpJoinTest.GroupAddress;
}

int set_IgmpJoinTestGroupAddr(int addr)
{
	if (addr == 0 || addr == INADDR_NONE)
		return 0;
	igmpJoinTest.GroupAddress = addr;
	return 1;
}

int get_IgmpJoinTestGroupPort()
{
	return igmpJoinTest.GroupPort;
}

int set_IgmpJoinTestGroupPort(int res)
{
	if (res == 0)
		return 0;

	igmpJoinTest.GroupPort = res;
	return 1;
}

int get_IgmpJoinTestVersion()
{
	return igmpJoinTest.Version;
}

int set_IgmpJoinTestVersion(int res)
{
	igmpJoinTest.Version = res;
	return 1;
}

int set_IgmpJoinTest(int action)
{
	char buf[32];

	if (igmpJoinTest.GroupAddress == 0 || igmpJoinTest.GroupAddress == INADDR_NONE)
		return 0;
	// TODO
	switch (action) {
	case 1:
	case 2:
		printf("send %s Message to %s\n", (action == 1) ? "Join" : "Leave",
		       inet_ntop(AF_INET, &igmpJoinTest.GroupAddress, buf, sizeof(buf)));
		return 1;
	default:
		return 0;
	}
}

int get_QosMarkCosRemark(int tn)
{
	char *ptr;
	int memPort;
	int rCos[8];
	int cnt;
	int rtnVal = 99;

	if (tn >= 8)
		return 99;
	ptr = getValue("x_QOS_RM_1Q");
	if (ptr) {
		cnt = sscanf(ptr, "%x_%d_%d_%d_%d_%d_%d_%d_%d", &memPort,
				&rCos[0], &rCos[1], &rCos[2], &rCos[3], &rCos[4], &rCos[5], &rCos[6], &rCos[7]);
		if (cnt == 9)
			rtnVal = rCos[tn];
	}
	return rtnVal;

}

void get_QosMarkDscpRemark(int tn, unsigned char *strVal)
{
	char *ptr;
	int memPort;
	int rVal[8];
	int cnt;

	snprintf(strVal, MAX_SNMP_STR, "%s", "none");
	if (tn >= 8)
		return;
	ptr = getValue("x_QOS_RM_DSCP");
	if (ptr) {
		cnt = sscanf(ptr, "%x_%d_%d_%d_%d_%d_%d_%d_%d", &memPort,
				&rVal[0], &rVal[1], &rVal[2], &rVal[3], &rVal[4], &rVal[5], &rVal[6], &rVal[7]);
		if (cnt == 9)
			sprintf(strVal, "%d", rVal[tn]);
	}

}

int getWlStaInfo(char *interface, WLAN_STA_INFO_Tp pInfo)
{
	int skfd = 0;
	struct iwreq wrq;
	int ret;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd == -1) {
		return -1;
	}

#if 0
	strncpy(wrq.ifr_name, interface, IFNAMSIZ);
	if (ioctl(skfd, SIOCGIWNAME, &wrq) < 0) {
		close(skfd);
		return -1;
	}
#endif
	wrq.u.data.pointer = (caddr_t) pInfo;
	wrq.u.data.length = sizeof(WLAN_STA_INFO_T) * (MAX_STATION_NUM + 1);
	*((unsigned char *)wrq.u.data.pointer) = MAX_STATION_NUM;

	strncpy(wrq.ifr_name, interface, IFNAMSIZ);
	if ((ret = ioctl(skfd, SIOCGIWRTLSTAINFO, &wrq)) < 0) {
		close(skfd);
		return -1;
	}
	close(skfd);
	return ret;
}

ACTIVE_WLSTA_INFO_T ActiveWlList[2][MAX_STATION_NUM * 5];
int wirelessClientList(int index)
{
	int i, j, found = 0;
	WLAN_STA_INFO_Tp pInfo;
	char *buff;
	char WLAN_IF[20];
	char SSID[33];
	int ret;

	buff = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STATION_NUM + 1));
	if (buff == 0) {
		printf("Allocate buffer failed!\n");
		return 0;
	}

	memset(ActiveWlList, 0, sizeof(ActiveWlList));
	for (i = 0; i < MAX_SSID; i++) {
		if ( root_vwlan_disable[i][index] )
			continue;

		if (i == 0)
			sprintf(WLAN_IF, "wlan%d", index);
		else
			sprintf(WLAN_IF, "wlan%d-va%d", index, i - 1);

		memset(buff, 0, sizeof(WLAN_STA_INFO_T) * (MAX_STATION_NUM + 1));
		if ((ret = getWlStaInfo(WLAN_IF, (WLAN_STA_INFO_Tp) buff)) < 0)
			continue;

		get_wlanSSID(index, i, SSID);
		for (j = 1; j <= MAX_STATION_NUM; j++) {
			pInfo = (WLAN_STA_INFO_Tp)&buff[j * sizeof(WLAN_STA_INFO_T)];

			if (pInfo->aid && (pInfo->flags & STA_INFO_FLAG_ASOC)) {
				memcpy(ActiveWlList[index][found].mac, pInfo->addr, 6);
				snprintf(ActiveWlList[index][found].SSID, sizeof(ActiveWlList[index][found].SSID), "%s", SSID);
				ActiveWlList[index][found].rssi = pInfo->rssi;
				ActiveWlList[index][found].mode = pInfo->network;
				found++;
			}
		}
	}
	free(buff);

	return found;
}


void get_wlanActiveSSID(int w_index, int idx, unsigned char *destBuf)
{
	snprintf((char *)destBuf, MAX_SNMP_STR, "%s", ActiveWlList[w_index][idx].SSID);

	return;
}

void get_wlanActiveMac(int w_index, int idx, unsigned char *destBuf)
{
	memcpy(destBuf, ActiveWlList[w_index][idx].mac, 6);
	return;
}

int get_wlanActiveMode(int w_index, int idx)
{
	if(w_index == 0) {
		if (ActiveWlList[w_index][idx].mode & BAND_11N) {
			return 2;
		} else if (ActiveWlList[w_index][idx].mode & BAND_11A) {
			return 1;
		} else {
			return 2;
		}
	} else {
		if (ActiveWlList[w_index][idx].mode & BAND_11N) {
			return 3;
		} else if (ActiveWlList[w_index][idx].mode & BAND_11G) {
			return 2;
		} else if (ActiveWlList[w_index][idx].mode & BAND_11B) {
			return 1;
		} else {
			return 3;
		}
	}
}

int percentToDbm(int percent)
{
	if ( percent >= 90 )
		return -10;

	if ( percent <= 0 )
		return -100;

	return (percent - 100);
}

void get_wlanActiveRSSI(int w_index, int idx, unsigned char *destBuf)
{
	sprintf(destBuf, "%d", percentToDbm(ActiveWlList[w_index][idx].rssi));
}

void get_wlanActiveSNR(int w_index, int idx, unsigned char *destBuf)
{
	sprintf(destBuf, "%lu", ActiveWlList[w_index][idx].snr);
}

void get_wlanActiveBER(int w_index, int idx, unsigned char *destBuf)
{
	sprintf(destBuf, "%lu", ActiveWlList[w_index][idx].ber);
}

//#define DHCPS_LEASES    "/var/lib/misc/udhcpd.leases"
#define HOSTINFO_FILE   "/proc/rtl865x/l2"

struct HOST_INFO_T {
	int portNo;
	unsigned int ipAddr;
	unsigned char mac[6];
};

struct HOST_INFO_T hostInfo[64];

int is_local_port_fun(char *buf){
	char *ptr;
	int ptn;

	if( !(ptr = strstr(buf, "mbr(")) )
		return 0;
	if(ptr && strlen(ptr) > 4)
		ptr += 4;
	trim_spaces(ptr);
	ptn= atoi(ptr);
	if(( ptn >= 0 )&&( ptn < 4 )){
		return 1;
	}
	return 0;
}

int initHostInfo()
{
	FILE *fp;
	char tmpBuf[128];
	char *ptr1, *ptr2;
	int num = 0;
	int loc_port;
	int port;

	memset(hostInfo, 0, sizeof(hostInfo));
	fp = fopen(HOSTINFO_FILE, "r");
	if (!fp){
		return 0;
	}
	while (fgets(tmpBuf, sizeof(tmpBuf), fp)) {
		if( ( ptr1 = strstr(tmpBuf, "FWD DYN") ) && (loc_port = is_local_port_fun(tmpBuf)) ){
			if (ptr1) {
				char *strMac;
				ptr2 = strstr(tmpBuf, "mbr(");
				strMac = &tmpBuf[13];
				strMac[17] = 0;
				simple_ether_atoe(strMac, hostInfo[num].mac);
				if (ptr2 && strlen(ptr2) > 4)
					ptr2 += 4;
				trim_spaces(ptr2);
				port = atoi(ptr2);
				if ( port < 0 || port >= MAX_PORT - 1)
					continue;

				hostInfo[num].portNo = port+1;
				num++;
			}
		}
	}
	fclose(fp);
	return num;
}

int get_hostInfoPortNumber(int idx)
{
	return hostInfo[idx].portNo;
}

void get_hostInfoMacAddr(int idx, unsigned char *var_val)
{
	memcpy(var_val, hostInfo[idx].mac, 6);
}

unsigned int get_hostInfoIpAddr(int idx)
{
	char tmpBuf[256];
	FILE *fp;
	unsigned char i[10];
	char strmac[20];
	int argc;
	char *argv[15];
	unsigned long IpAddr=0;

	memcpy(i,hostInfo[idx].mac,6);
	sprintf(strmac,"%02x:%02x:%02x:%02x:%02x:%02x",i[0],i[1],i[2],i[3],i[4],i[5]);
	fp=fopen("/proc/net/arp","r");
	if(!fp)
		return 0;
	while(fgets(tmpBuf,sizeof(tmpBuf),fp)!=NULL){
		argc = parse_line(tmpBuf, argv, 15, " \t\r\n");
		if(strncmp(strmac,argv[3],strlen(strmac))==0){
			IpAddr=inet_addr(argv[0]);
			break;
		}
	}
	fclose(fp);
	return IpAddr;
}

unsigned int get_portStatusCrc(int idx)
{
	unsigned int crcErr;
	int rc;
	unsigned int args[2];

	args[0] = (unsigned int)&idx;
	rc = re865xIoctl("eth0", RTL8651_IOCTL_GETPORT_CRCERRCOUNT, (unsigned int)(args), 0, (unsigned int)&crcErr);
	return crcErr;
}


static int get_port_statistics(const char *interface, int port, struct port_statistics *stats)
{
	struct ifreq ifr;
	int s, rc;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	ifr.ifr_data = (void *)stats;
	*(int *)ifr.ifr_data = port;
	if ((rc = ioctl(s, RTL819X_IOCTL_READ_PORT_STATS, &ifr)))
		perror(__func__);
	close(s);
	return rc;
}

static void port_bps_check(struct _port_status *status)
{
	struct port_statistics stats;
	char *tmp_op;
	int opmode = -1;
	int i;

	tmp_op = getValue("OP_MODE");
	opmode = atoi(tmp_op);

	for(i=0; i<5; i++) {
		if(opmode == 0) { 	//NAT
			if(i==0) { 		//WAN
				if(!get_port_statistics(WANIF, 4, &stats)) {
					status[i].inputOCT = stats.rx_bytes;
					status[i].outputOCT = stats.tx_bytes;
					status[i].CRC = stats.rx_error;

				}
			} else {
				if(!get_port_statistics(LANIF, i-1, &stats)) {
					status[i].inputOCT = stats.rx_bytes;
					status[i].outputOCT = stats.tx_bytes;
					status[i].CRC = stats.rx_error;
				}
			}
		} else {	//Bridge
			if(!get_port_statistics(LANIF, i, &stats)) {
				status[i].inputOCT = stats.rx_bytes;
				status[i].outputOCT = stats.tx_bytes;
				status[i].CRC = stats.rx_error;
			}
		}
	}
}

unsigned long get_portStatus(int i, int flag)
{
	struct _port_status status[5];
	unsigned int phy_status[5];

	port_bps_check(status);
	phy_status[i] = switch_port_status((i==0)?4:i-1);

		if(flag == 1)
			return status[i].inputOCT;
		else if(flag == 2)
			return status[i].outputOCT;
		else if(flag == 3)
			return status[i].CRC;
		else
			return 0;
}

unsigned long get_portStatusOutBytes(int idx)
{
	unsigned long Bytes;
	int rc;
	unsigned int args[2];

	args[0] = (unsigned int)&idx;
	rc = re865xIoctl("eth0", RTL8651_IOCTL_GETPORT_OUTCOUNT, (unsigned int)(args), 0, (unsigned long)&Bytes);
	if(Bytes <= INT_MAX)
		return Bytes;
	else
		return INT_MAX;

}

/*
Gauge32
1G:  1000000000
500M:500000000
100M:100000000
10M: 10000000
*/
int get_portSpeed(int p_index)
{
	unsigned int phy_status=0;
	phy_status = switch_port_status((p_index==0)?4:p_index-1);
	if ((phy_status & PHF_10M))
		return 10000000;
	else if ((phy_status & PHF_100M))
		return 100000000;
	else if ((phy_status & PHF_500M))
		return 500000000;
	else
		return 1000000000;
}

void getPortMac(int index, char *buf)
{
	sprintf(buf, "0x%d", index);
}

int get_portPower(int p_index)
{
	char var[32];
	char *p;

	if(!strcmp(portConfig[p_index].port_config, "")){
		if(p_index == 0) {
			sprintf(var, "x_port_4_config");
			nvram_get_r_def(var, portConfig[p_index].port_config, sizeof(portConfig[p_index].port_config), "up_auto_rxpause_txpause");
		} else {
			sprintf(var, "x_port_%d_config", p_index-1);
			nvram_get_r_def(var, portConfig[p_index].port_config, sizeof(portConfig[p_index].port_config), "up_auto_-rxpause_txpause");
		}
	}

	if ((p = strstr(portConfig[p_index].port_config, "down")))
		return 2;
	else
		return 1;

}

int set_portPower(int p_index, int PowerOn)
{
	char buffer[52], var[32], buf[52];
	int parse = 0, n =0;
	int len = sizeof(buf);
	char *p;

	if(PowerOn == 3){	// 3 means "testing". Do nothing because it's not supported.
		return 1;
	}

	if(PowerOn != 1 && PowerOn != 2) {
		return 0;
	}

	if(!strcmp(portConfig[p_index].port_config, "")) {
		if(p_index == 0) {
			sprintf(var, "x_port_4_config");
			nvram_get_r_def(var, buffer, sizeof(buffer), "up_auto_rxpause_txpause");
		} else {
			sprintf(var, "x_port_%d_config", p_index-1);
			nvram_get_r_def(var, buffer, sizeof(buffer), "up_auto_-rxpause_txpause");
		}
	} else
		snprintf(buffer, sizeof(buffer), "%s", portConfig[p_index].port_config);

	p = strtok(buffer, "_");
	while(p!=NULL){
		if(!parse)
			n+=snprintf(&buf[n], len, "%s", (PowerOn==1)? UP:DOWN);
		else
			n+=snprintf(&buf[n], len-n, "_%s", p);
		parse++;
		p = strtok(NULL, "_");
	}
	memset(portConfig[p_index].port_config, 0, sizeof(portConfig[p_index].port_config));
	snprintf(portConfig[p_index].port_config, sizeof(portConfig[p_index].port_config), "%s", buf);
	portConfig[p_index].changed = 1;
	needReboot = 1;
	return 1;
}

#define safe_fclose(f) do { \
	if ((f)) { \
		fclose((f));\
		(f) = NULL; \
	} \
} while(0)
long get_lastChanged_time(int port)
{
	int index;
	long val_list[5]={0};

	yexecl("> /tmp/port_info", "preq link_watcher");
	yfcat("/tmp/port_info", "%ld %*[^\n] %ld %*[^\n] %ld %*[^\n] %ld %*[^\n] %ld", &val_list[0], &val_list[1], &val_list[2], &val_list[3], &val_list[4]);

	if(port == 4)
		index = 0;
	else
		index = port + 1;
	unlink("/tmp/port_info");
	return val_list[index];
}

#define LOCAL_MCAST(x)  (((x) &0xFFFFFF00) == 0xE0000000)

char *read_line_skip_mark(char *p, char *out, int maxlen)
{
	int c;
	char *e;

	/* skip leading white spaces or level mark <#> */
	for (; (c = *p); p++) {
		if (isspace(c))
			continue;
		else if (c == '<') {
			while (*p && *p != '>')
				p++;
			if (!*p)
				break;
		} else
			break;
	}

	if (*p == '\0')
		return NULL;

	for (e = (out + maxlen - 1); (c = *p++) && (out < e);) {
		switch (c) {
		case '\n':
			*out = 0;
			return p;
		case '\r':
			if (*p == '\n') {
				*out = 0;
				return ++p;
			}
			// fall thru
		default:
			*out++ = c;
			break;
		}
	}
	*out = 0;
	return p;
}

enum { GA_NONE, GA_MODULE, GA_GROUP, GA_BREAK };

static int igmpGroupAge(char *group, char *send_buf, int index)
{
	int argc, number=0, maxAge = -1;
	char *argv[12];
	char buf[128], tmp[12];
	int sts = GA_NONE;
	int n, tmpnumber = 0;
	FILE *fp;
	char *p, infobuf[128];

	if ( (fp = fopen("/proc/rtl865x/igmp", "r")) == NULL)
		return -1;

	while ( (p=fgets(infobuf, sizeof(infobuf), fp)) ) {
		if ( (p = read_line_skip_mark(infobuf, buf, sizeof(buf)))==NULL || sts == GA_BREAK)
			continue;

		argc = parse_line(buf, argv, 12, " ,:\\\r\n");
		if (argc <= 0)
			continue;

		switch (sts) {
		case GA_NONE:
			if (argc == 10 && !strcmp(argv[0], "module")) {
				if (!strcmp(argv[4], "eth*")) {
					sts = GA_MODULE;
					number = 1;
				} else
					sts = GA_BREAK;
			}
			break;
		case GA_MODULE:
			sprintf(tmp, "[%d]", number);
			if (argc == 4 && !strcmp("Group", argv[1])) {
				if(index) {
					if(strncmp(argv[3], group,10) == 0)
						sts = GA_GROUP;
					else
						++number;
				}
				else {
					if (strcmp(argv[3], group) == 0)
						sts = GA_GROUP;
					else
						++number;
				}
			} else if (argc == 7 && !strcmp(argv[0], "module"))
				sts = GA_BREAK;
			break;
		case GA_GROUP:
			if (argc == 6 && !strcmp(argv[4], "EXCLUDE")) {
				if(index){
					int port_num=0;

					if(strcmp(argv[2], "1")==0)
						port_num=1;
					else if(strcmp(argv[2], "2")==0)
						port_num=2;
					else if(strcmp(argv[2], "3")==0)
						port_num=3;
					else // 4
						port_num=4;

					sprintf(send_buf, "%s|LAN %d", argv[0], port_num);
					if (index == 1) {
						fclose(fp);
						return 1;
					}
					if ( (n=sscanf(argv[5], "%ds", &tmpnumber)) == 1)
						number = tmpnumber;

					if (number > maxAge)
						maxAge = number;
				}
				else {
					if ( (n=sscanf(argv[5], "%ds", &tmpnumber)) == 1)
						number = tmpnumber;

					if (number > maxAge)
						maxAge = number;
				}
			} else
				sts = GA_BREAK;
			break;
		default:
			break;
		}
	}
	fclose(fp);
	return maxAge;
}

int get_igmpJoinTable(int select, _igmpTbl_t *T)
{
	FILE *fp;
	char buf[128];
	int count = 0;
	int argc, j;
	char *argv[12];
	int mbr;
	int maxAge = 5;
	char tmp[12];
	struct in_addr m_grp;

	memset(T, 0, sizeof(_igmpTbl_t) * MAXTBLNUM);

	fp = fopen("/proc/n_multicast", "r");
	if (fp) {
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			argc = parse_line(buf, argv, 12, " \t\r\n");
			if (argc < 4 || strncmp(argv[0], "TotalOpCnt", 10) == 0)
				break;

			if (!inet_aton(argv[1], &m_grp))
				continue;

			if (LOCAL_MCAST(m_grp.s_addr) ||
					(m_grp.s_addr == htonl(0xeffffffa)) ||
					(m_grp.s_addr == htonl(0xefc0988f)))
				continue;

			if ((mbr = strtoul(argv[3], NULL, 16)) < 1)
				continue;

			if ((maxAge = strtoul(argv[7], NULL, 10)) < 1)
				continue;

			if ((maxAge = igmpGroupAge(argv[1], tmp, 0)) < 5)
				continue;

			if (select) {
				for (j = 0; j <= 4; j++) {
					if (mbr & (0x1 << j)) {
						strcpy(T[count].GroupAddr, argv[1]);
						T[count].mbr = (0x1 << j);
						T[count++].num = maxAge;
					}
				}
			} else {
				strcpy(T[count].GroupAddr, argv[1]);
				T[count].join_mbr = mbr;
				T[count++].num = maxAge;
			}
		}
		fclose(fp);
	}
	return count;
}

/*
void dump_igmpTbl(int sel, int index, int count, int column, _igmpTbl_t *T)
{
	int i;
	printf("\nsel %d idx %d count %d column %d\n", sel, index, count, column);
	for (i = 0; i < count; i++)
		printf("[%d] %s %d %d %d\n", i,
			T[i].GroupAddr, T[i].mbr,
			T[i].num, T[i].join_mbr);
}
*/

#define MAXMULTITBLNUM       5
#define RCV                  1
#define TRN                  2
static unsigned int rcv_multicast[MAXMULTITBLNUM];
static unsigned int trn_multicast[MAXMULTITBLNUM];

void get_multicastTable(void)
{
	FILE *fp;
	char buf[256];
	int i=0;
	int argc;
	char *argv[15];
	int tmp=RCV;

	fp=fopen("/proc/asicCounter","r");

	if (!fp)
		return;
	while(fgets(buf, sizeof(buf), fp) !=NULL){
		argc = parse_line(buf, argv, 15, " :\t\r\n");
		if(argc==0)
			continue;
		if(strncmp("Receive",argv[1],strlen("Receive"))==0){
			tmp =RCV;
		}
		else if(strncmp("Transmit",argv[1],strlen("Transmit"))==0){
			tmp =TRN;
		}
		if( (strncmp(argv[0],"0",1)>=0) && (strncmp(argv[0],"4",1)<=0) ){
			i=atoi(argv[0]);
			if(tmp ==RCV)
				rcv_multicast[i]=strtoul(argv[3],NULL,10);
			else if(tmp ==TRN)
				trn_multicast[i]=strtoul(argv[3],NULL,10);
		}
	}
	fclose(fp);
}

// added by kkm
unsigned int get_igmpJoinIpAddress(_igmpTbl_t *T)
{
	unsigned int IpAddress=inet_addr(T->GroupAddr);
	return IpAddress;
}

int get_igmpJoinMemberNumber(_igmpTbl_t *T)
{
	int i, cnt = 0;

	for (i = 0; i <= 4; i++) {
		if (T->join_mbr & (0x1 << i))
			cnt++;
	}
	return cnt;
}

int get_igmpJoinPort(_igmpTbl_t *T)
{

	int i;
	int joinport = 0;
#if !defined(__SNMP_BITMAP__)
	int PORT_MBR[4] = { 2, 4, 8, 16 };
#endif
	int result = 0;

/*
	bmt spec: bit map
	bit map : 1|1|0|0|(port1|port2|port3|port4, 0:X, 1:O)
	but, swms management page is simple
	LAN1: 1, LAN2: 2, LAN3: 3, LAN4: 4

	LAN4 | LAN3 | LAN2 | LAN1 | WAN
	  16	8		4	  2
*/
	for (i = 0; i < 4; i++) {
#if defined(__SNMP_BITMAP__)
		if (T->join_mbr & (0x2 << i))
			joinport |= (0x2 << i);
#else
		if (T->join_mbr & (0x2 << i))
			result += PORT_MBR[i];

#endif
	}
	if (result)
		return result + 1;	//wan port is 1

	return joinport;
}

unsigned int get_multicastJoinIpAddress(_igmpTbl_t *T)
{
	unsigned int IpAddress = inet_addr(T->GroupAddr);
	return IpAddress;

}

int get_multicastPortNumber(_igmpTbl_t *T)
{
	int i;

	for (i = 0; i < 4; i++) {
		if(T->mbr & (0x1 << i))
			return i;
	}
	return 0;
}

int get_multicastPortName(_igmpTbl_t *T)
{
	int PortNumber = ((T->mbr) >> 1);
	if (PortNumber >= 4)
		return 3;
	else if (PortNumber >= 2)
		return 2;
	else if (PortNumber >= 1)
		return 1;
	else
		return 0;

}

void get_multicastTable_Op(unsigned int * rcv_multicasttbl,unsigned int * trn_multicasttbl){
	FILE *fp;
	char buf[256];
	int i=0;
	int argc;
	char *argv[15];
	int tmp=RCV;

	fp=fopen("/proc/asicCounter","r");

	if (!fp)
		return;
	while(fgets(buf, sizeof(buf), fp) !=NULL){
		argc = parse_line(buf, argv, 15, " :\t\r\n");
		if(argc==0)
			continue;
		if(strncmp("Receive",argv[1],strlen("Receive"))==0){
			tmp = RCV;
		}
		else if(strncmp("Transmit",argv[1],strlen("Transmit"))==0){
			tmp = TRN;
		}
		if( (strncmp(argv[0],"0",1)>=0) && (strncmp(argv[0],"4",1)<=0) ){
			i=atoi(argv[0]);
			if(tmp ==RCV){
				rcv_multicasttbl[i]=strtoul(argv[3],NULL,10);
			}
			else if(tmp ==TRN){
				trn_multicasttbl[i]=strtoul(argv[3],NULL,10);
			}
		}
	}
	fclose(fp);
}

int get_multicastOperation(int no){
	static unsigned int rcv_tbl_1[MAXMULTITBLNUM]={0,};
	static unsigned int trn_tbl_1[MAXMULTITBLNUM]={0,};
	static unsigned int rcv_tbl_2[MAXMULTITBLNUM]={0,};
	static unsigned int trn_tbl_2[MAXMULTITBLNUM]={0,};

	if(no==0){
		get_multicastTable_Op(rcv_tbl_1,trn_tbl_1);
		sleep(1);
		get_multicastTable_Op(rcv_tbl_2,trn_tbl_2);
	}
	if(no ==0){     //case wan
		if(rcv_tbl_2[no]-rcv_tbl_1[no]==0)
			return 2;
		else
			return 1;
	}
	else{
		if(trn_tbl_2[no]-trn_tbl_1[no]==0)
			return 2;
		else
			return 1;
	}
}

unsigned int get_multicastInPackets(int no)
{
	if(no == 4)
		return trn_multicast[no];
	else
		return rcv_multicast[no];

}
unsigned int get_multicastOutPackets(int no)
{
	if(no == 4)
		return rcv_multicast[no];
	else
		return trn_multicast[no];

}

_PING_TEST_T ping_Test[4];

#define ICMP_MIN        8
#define MAX_DATA_LEN 	1024
typedef struct {
	struct icmphdr hdr;
	char msg[MAX_DATA_LEN];
} icmp_packet_t;

int checksum(unsigned short *buf, int sz)
{
	int nleft = sz;
	int sum = 0;
	unsigned short *w = buf;
	unsigned short ans = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *) (&ans) = *(unsigned char *) w;
		sum += ans;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	ans = ~sum;
	return ans;
}

#define PING_RESULT_PATH "/var/tmp/snmp_ping"

static void ping_result(int no)
{
	FILE *fp;
	char tmp[80];

	sprintf(tmp, "%s%d", PING_RESULT_PATH, no);
	if ((fp = fopen(tmp, "w"))) {
		fprintf(fp, "sentPktCount=%d\n", ping_Test[no].sentPktCount);
		fprintf(fp, "recvPktCount=%d\n", ping_Test[no].recvPktCount);
		fprintf(fp, "minPingTime=%d\n", ping_Test[no].minPingTime);
		fprintf(fp, "avgPingTime=%d\n", ping_Test[no].avgPingTime);
		fprintf(fp, "maxPingTime=%d\n", ping_Test[no].maxPingTime);
		fprintf(fp, "pingCompleted=%d\n", ping_Test[no].pingCompleted);
		fprintf(fp, "pid=%d\n", ping_Test[no].pid);

		fclose(fp);
	} else {
		printf("ping result file open error\n");
		return;
	}
}

void update_ping_result(int no)
{
	FILE *fp;
	char buf[80];
	char *argv[5];
	int argc;
	char tmp[80];

	sprintf(tmp, "%s%d", PING_RESULT_PATH, no);
	if ( (fp=fopen(tmp, "r")) ) {
		while( fgets(buf, sizeof(buf), fp) ) {
			if ( (argc = parse_line(buf, argv, 3, " =\r\n\t")) != 2)
				continue;

			if (!strcmp("sentPktCount", argv[0])) {
				ping_Test[no].sentPktCount = strtoul(argv[1], NULL, 10);
			}
			else if (!strcmp("recvPktCount", argv[0])) {
				ping_Test[no].recvPktCount = strtoul(argv[1], NULL, 10);
			}
			else if (!strcmp("minPingTime", argv[0])) {
				ping_Test[no].minPingTime = strtoul(argv[1], NULL, 10);
			}
			else if (!strcmp("avgPingTime", argv[0])) {
				ping_Test[no].avgPingTime = strtoul(argv[1], NULL, 10);
			}
			else if (!strcmp("maxPingTime", argv[0])) {
				ping_Test[no].maxPingTime = strtoul(argv[1], NULL, 10);
			}
			else if (!strcmp("pingCompleted", argv[0])) {
				ping_Test[no].pingCompleted = strtoul(argv[1], NULL, 10);
			}
			else if (!strcmp("pid", argv[0])) {
				ping_Test[no].pid = strtoul(argv[1], NULL, 10);
			}/* else
				break;*/
		}
		fclose(fp);
	}
}

static int ping(struct sockaddr_in *addr, int pid, int no)
{
	int i, sd;
	icmp_packet_t pkt;
	struct sockaddr_in from;
	struct timeval tv;
	char buf[512];
	int sum = 0;

	if ( (sd = socket(AF_INET, SOCK_RAW, 1 /*icmp*/)) < 0)
		goto out;

	setuid(getuid());

	tv.tv_sec = ping_Test[no].pktTimeout / 1000;
	tv.tv_usec = (ping_Test[no].pktTimeout % 1000) * 1000;
	if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) < 0) {
		perror("set socket option recv timeout: ");
		goto out;
	}
	if (setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv)) < 0) {
		perror("set socket option send timeout: ");
		goto out;
	}
	sum = 0;
	ping_Test[no].sentPktCount = 0;
	ping_Test[no].recvPktCount = 0;

	for (i = 0; i < ping_Test[no].pktCount; i++) {
		int len = sizeof(from);
		struct timeval tp;
		unsigned long triptime;

		bzero(&pkt, sizeof(pkt));
		pkt.hdr.type = ICMP_ECHO;
		pkt.hdr.un.echo.id = pid;
		pkt.hdr.un.echo.sequence = i;

		memset(&pkt.msg[0], 'e', ping_Test[no].pktSize);

		pkt.hdr.checksum = checksum((unsigned short *)&pkt, (ping_Test[no].pktSize+sizeof(struct icmphdr)) );

		gettimeofday(&tp, NULL);
		if (sendto(sd, &pkt, (ping_Test[no].pktSize+sizeof(struct icmphdr)), 0, (struct sockaddr *)addr, sizeof(*addr)) <= 0) {
			perror("send to error: ");
			goto out;
		}

		ping_Test[no].sentPktCount++;
		bzero(buf, sizeof(buf));
		if (recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &len) > 0) {
			struct iphdr *ip = (struct iphdr *)buf;
			struct icmphdr *icmp = (struct icmphdr *)(buf + ip->ihl * 4);

			if (len < ip->ihl + ICMP_MIN) {
				printf("Too few bytes form %s\n", inet_ntoa(from.sin_addr));
				goto out;
			}

			if (icmp->type != ICMP_ECHOREPLY) {
				printf("non-echo type %d received.\n", icmp->type);
				goto out;
			}

			if (icmp->un.echo.id != pid) {
				printf("someone else's packet\n");
				goto out;
			}
			gettimeofday(&tv, NULL);
			if ((tv.tv_usec -= tp.tv_usec) < 0) {
				--tv.tv_sec;
				tv.tv_usec += 1000000;
			}
			tv.tv_sec -= tp.tv_sec;
			triptime = tv.tv_sec * 1000 + (tv.tv_usec / 1000);
			printf("Ping Reply seq %d from %s : bytes=%d time=%ld.%ldms\n", i, inet_ntoa(from.sin_addr), len,
				   (tv.tv_sec * 1000 + tv.tv_usec / 1000), (tv.tv_usec % 1000));
			sum += triptime;
			ping_Test[no].recvPktCount++;

		} else {
			printf("Ping Reply seq %d from %s timeout\n", i, inet_ntoa(addr->sin_addr));
			triptime = ping_Test[no].pktTimeout;

			if (ping_Test[no].pktDelay != 0)
				usleep(ping_Test[no].pktDelay * 1000);
		}
		if (triptime < ping_Test[no].minPingTime)
			ping_Test[no].minPingTime = triptime;
		if (triptime > ping_Test[no].maxPingTime)
			ping_Test[no].maxPingTime = triptime;

		usleep(1000 * 1000);
	}
	close(sd);
	ping_Test[no].avgPingTime = sum / ping_Test[no].pktCount;
	ping_Test[no].pingCompleted = 1;
	printf("Ping Completed..(%d)\n", ping_Test[no].EntryStatus);
	ping_Test[no].pid = 0;

	ping_result(no);
	return 0;
  out:
	ping_Test[no].pingCompleted = 1;
	if (sd >= 0)
		close(sd);
	ping_Test[no].pid = 0;
	return -1;
}

extern int ping_pid;
static void write_pid(char *path, int pid)
{
	FILE *fp;

	if (!path)
		return;

	if ( !(fp=fopen(path, "w")) ) {
		printf("write pid file open error\n");
		return;
	}

	fprintf(fp, "%d", pid);

	fclose(fp);
}

static int read_pid(char *path)
{
	FILE *fp;
	char buf[80];

	if (!path)
		return -1;

	if ( !(fp=fopen(path, "r")) )
		return -1;

	fgets(buf, sizeof(buf), fp);

	fclose(fp);

	return (strtoul(buf, NULL, 10));
}

int snmp_ping_test(int No)
{
	struct hostent *hname;
	struct sockaddr_in addr;
	int pid = -1;
	char pid_path[80];

	if ( /*get_portPower(0) != 1 || */ ping_Test[No].pingAddress[0] == 0) {
		ping_Test[No].pingCompleted = 2;
		ping_Test[No].EntryStatus = Enum_RowStatusNotInSevice;
		return -1;
	}
	pid = getpid();
	hname = gethostbyname(ping_Test[No].pingAddress);
	if (hname == NULL) {
		ping_Test[No].pingCompleted = 2;
		ping_Test[No].EntryStatus = Enum_RowStatusNotInSevice;
		printf("ping Test: %s dns resolving failed.\n", ping_Test[No].pingAddress);
		return 0;
	}

	if ( (ping_pid = fork()) == 0) {
		bzero(&addr, sizeof(addr));
		addr.sin_family = hname->h_addrtype;
		addr.sin_port = 0;
		addr.sin_addr.s_addr = *(long*)hname->h_addr;
		ping_pid = getpid();

		sprintf(pid_path, "/var/run/snmp_ping%d.pid", No);
		write_pid(pid_path, ping_pid);
		ping_Test[No].pid = ping_pid;

		ping(&addr, ping_pid, No);

		exit(0);
	}
	return 0;
}

int get_pingProtocol(int no, int protocol)
{
	if (no <= 0 || no > 4)
		return -1;

	return 1;
}

int set_pingProtocol(int no, int protocol)
{
	if (no <= 0 || no > 4)
		return -1;

	if (protocol != 1)
		return -1;

	return 0;
}

char *get_pingAddress(int no)
{
	if (no <= 0 || no > 4)
		return NULL;

	no -= 1;

	return ping_Test[no].pingAddress;
}

int set_pingAddress(int no, char *val)
{
	if (no <= 0 || no > 4)
		return -1;

	no -= 1;

	snprintf(ping_Test[no].pingAddress, sizeof(ping_Test[no].pingAddress), "%s", val);

	return 0;
}

int get_pktCount(int no)
{
	if (no <= 0 || no > 4)
		return -1;

	no -= 1;

	return ping_Test[no].pktCount;
}

int set_pktCount(int no, int val)
{
	if (no <= 0 || no > 4)
		return -1;

	no -= 1;

	ping_Test[no].pktCount = val;

	return 0;
}

int get_pktSize(int no)
{
	if (no <= 0 || no > 4)
		return -1;

	no -= 1;

	return ping_Test[no].pktSize;
}

int set_pktSize(int no, int size)
{
	if (no <= 0 || no > 4)
		return -1;

	no -= 1;

	if (size > MAX_DATA_LEN)
		size = MAX_DATA_LEN;

	ping_Test[no].pktSize = size;

	return 0;
}

int get_pktDelay(int no)
{
	if (no <= 0 || no > 4)
		return -1;

	no -= 1;

	return ping_Test[no].pktDelay;
}

int set_pktDelay(int no, int val)
{
	if (no <= 0 || no > 4)
		return -1;

	no -= 1;

	if (val > 36000000)
		return -1;

	ping_Test[no].pktDelay = val;

	return 0;
}

int get_pktTimeout(int no)
{
	if (no <= 0 || no > 4)
		return -1;

	no -= 1;

	return ping_Test[no].pktTimeout;
}

int set_pktTimeout(int no, int val)
{
	if (no <= 0 || no > 4)
		return -1;

	no -= 1;

	if (val > 36000000)
		return -1;

	ping_Test[no].pktTimeout = val;
	return 0;
}

int get_TrapOnCompletion(int no)
{
	if (no <= 0 || no > 4)
		return -1;

	no -= 1;

	return ping_Test[no].TrapOnComplete;
}

int set_TrapOnCompletion(int no, int val)
{
	if (no <= 0 || no > 4)
		return -1;

	no -= 1;

	if (val != 1 && val != 2)
		return -1;

	ping_Test[no].TrapOnComplete = val;
	return 0;
}

int get_sentPktCount(int no)
{
	if (no <= 0 || no > 4)
		return -1;

	no -= 1;
	if (ping_Test[no].pingCompleted != 1)
		return 0;

	return ping_Test[no].sentPktCount;
}

int get_recvPktCount(int no)
{
	if (no <= 0 || no > 4)
		return -1;

	no -= 1;

	if (ping_Test[no].pingCompleted != 1)
		return 0;

	return ping_Test[no].recvPktCount;
}

int get_minPingTime(int no)
{
	if (no <= 0 || no > 4)
		return -1;

	no -= 1;

	if (ping_Test[no].pingCompleted != 1)
		return 0;

	return ping_Test[no].minPingTime;
}

int get_maxPingTime(int no)
{
	if (no <= 0 || no > 4)
		return -1;

	no -= 1;

	if (ping_Test[no].pingCompleted != 1)
		return 0;

	return ping_Test[no].maxPingTime;
}

int get_avgPingTime(int no)
{
	if (no <= 0 || no > 4)
		return -1;

	no -= 1;

	if (ping_Test[no].pingCompleted != 1)
		return 0;

	return ping_Test[no].avgPingTime;
}

int get_pingCompleted(int no)
{
	if (no <= 0 || no > 4)
		return -1;

	no -= 1;

	if (ping_Test[no].pingCompleted != 1)
		return 2;

	return 1;
}

char *get_EntryOwner(int no)
{
	if (no <= 0 || no > 4)
		return NULL;

	no -= 1;

	return ping_Test[no].pingOwner;
}

int set_EntryOwner(int no, char *val)
{

	if(no <= 0 || no > 4)
		return -1;

	no -= 1;

	snprintf(ping_Test[no].pingOwner, sizeof(ping_Test[no].pingOwner), "%s", val);
	return 0;
}

int get_pingEntryStatus(int no)
{
	if (no <= 0 || no > 4)
		return -1;
	no -= 1;

	return ping_Test[no].EntryStatus;
}


int set_pingEntryStatus(int no, int action)
{
	char tmp[80];
	char ping_path[80];

	if (no <= 0 || no > 4)
		return -1;

	if (action < 1 || action > 6)
		return -1;

	if (ping_Test[no].EntryStatus == action)
		return -1;

	no -= 1;

	ping_Test[no].EntryStatus = action;
	sprintf(tmp, "%s%d", PING_RESULT_PATH, no);
	switch(action) {
		case Enum_RowStatusActive:
			unlink(tmp);
			snmp_ping_test(no);
			break;
		case Enum_RowStatusDestory:
			sprintf(ping_path, "/var/run/snmp_ping%d.pid", no);
			ping_Test[no].pid = read_pid(ping_path);
			if (ping_Test[no].pid > 0)
				kill(ping_Test[no].pid, SIGTERM);
			ping_init_instance(no);
			unlink(ping_path);
			unlink(tmp);
			break;
		case Enum_RowStatusCreateAndWait:
			break;
		case Enum_RowStatusCreateAndGo:
		case Enum_RowStatusNotInSevice:
		case Enum_RowStatusNotReady:
			return -1;
		default:
			break;
	}
	return 0;
}


static void ping_init_instance(int no)
{
	memset(&ping_Test[no], 0, sizeof(ping_Test[0]));
	ping_Test[no].pktCount = 5;
	ping_Test[no].pktSize = 100;
	ping_Test[no].pktTimeout = 2000; //2000 milliseconds.
	ping_Test[no].TrapOnComplete = 2;
	ping_Test[no].minPingTime = UINT_MAX;
	ping_Test[no].pingCompleted = 2;
	ping_Test[no].EntryStatus = Enum_RowStatusNotReady;
}

int init_ping_test_t(void)
{
	int i;

	memset(ping_Test, 0, sizeof(ping_Test));
	for (i = 0; i < 4; i++)
		ping_init_instance(i);
	return 0;

}

extern unsigned int current_sysUpTime(void);

int random_utilization()
{
	unsigned int seed;

	seed = current_sysUpTime();
	srandom(seed);

	return random();
}

long get_cpu_utiliz(void)
{
	time_t t;
	char buf[512];
	double cpu_idle_load=0, cpu_usage=0;
	t=time(NULL);

	named_pipe = prequest("cpu_stat");
	if (named_pipe) {
		if (presponse(named_pipe, buf, sizeof(buf)) > 0)
			sscanf(buf, "%lf", &cpu_idle_load);
		prelease(named_pipe);
		cpu_usage = 100 - cpu_idle_load;
	}
	return cpu_usage;
}

long get_ram_utiliz(void)
{
	char buf[256], tmp[256];
	unsigned long total, mfree;
	FILE *fp;

	total = mfree = 0;
	if ( (fp = fopen("/proc/meminfo", "r")) ) {
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			if (strstr(buf, "MemTotal:")!=NULL) {
				sscanf(buf, "%s %lu kB", tmp, &total);
			} else if (strstr(buf, "MemFree:")!=NULL) {
				sscanf(buf, "%s %lu kB", tmp, &mfree);
			}
			if (total && mfree)
				break;
		}
		fclose(fp);

		if (total&& mfree) {
			return (100 - ((mfree*100) / total ));
		}
	}
	return 0;
}

long get_flash_utiliz(void)
{
	FILE *pp = NULL;
	char buf[256], *args[10];
	int n;
	long use = 0;

	pp = popen("df", "r");
	if (pp) {
		while (fgets(buf, sizeof(buf), pp)) {
			n = ystrargs(buf, args, _countof(args), " \n", 0);
			if (n > 5) {
				if (strcmp(args[0], "/dev/mtdblock2") == 0) {
					use = strtol(args[4], NULL, 10);
					break;
				}
			}
		}
		pclose(pp);
	}

	return use;
}

long set_delete_syslog(int res)
{
	if (res != 1)
		return SNMP_ERROR_WRONGVALUE;

	yexecl("2>/dev/null", "killall -USR1 syslogd");
	yexecl("> /var/tmp/messages", "cat /dev/null");

	return 0;
}

//////////////////////////////////////////////////////////////////
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif
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

#define LOCAL_MCAST(x)  (((x) &0xFFFFFF00) == 0xE0000000)
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

/*
	bmt spec: bit map
	bit map : 1|1|0|0|(port1|port2|port3|port4, 0:X, 1:O)
	but, swms management page is simple
	LAN1: 1, LAN2: 2, LAN3: 3, LAN4: 4

	LAN4 | LAN3 | LAN2 | LAN1 | WAN
	  16	8		4	  2
*/
int igmp_snoop_table_info(_igmpTbl_snoop_t *T)
{
	struct mcast_group *g;
	struct mcast_mbr *m;
	struct mcast_mbr *mbr[5];
	struct list_head *pos, *pos2;
	struct list_head mc;
	struct list_head upif_grp;
	uint32_t i = 0, ii, tmp;
	int count = 0;
	int opmode = -1;

	INIT_LIST_HEAD(&mc);
	INIT_LIST_HEAD(&upif_grp);
	memset(T, 0, sizeof(_igmpTbl_snoop_t) * MAXTBLNUM);

	opmode = atoi(getValue("OP_MODE"));

	if (opmode == 0)
		if_readgroup(&upif_grp, "eth1");
	read_mcast(&mc, "/proc/rtl865x/igmp");
	list_for_each(pos, &mc) {
		count = 0;
		g = list_entry(pos, struct mcast_group, list);
		tmp = ntohl(g->group.s_addr);
		// SSDP (Simple Service Discovery Protocol): 239.255.255.250
		// mDNS (Multicast DNS): 224.0.0.251
		// Local Peer Discovery: 239.192.152.143
		if ( i >= MAXTBLNUM )
			continue;
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

		if ( (T[i].join_port=(tmp & 0x1E)) ) {
			T[i].join_port = T[i].join_port >> 1;
			sprintf(T[i].GroupAddr,"%s", inet_ntoa(g->group));
			for (ii = 1; ii < ARRAY_SIZE(mbr); ii++) {
				if ((m = mbr[ii]) != NULL)
					count++;
			}
		}
		T[i].join_mbn = count;
		i++;
	}
	mcast_group_free(&mc);

	return i;
}

#define SIOCGIWRTLSTAINFO   0x8B30

static int getall_wlansta(RTL_STA_INFO *p, const char *ifname)
{
	int fd, rc;
	struct iwreq wrq;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	strncpy(wrq.ifr_name, ifname, IFNAMSIZ);
	memset(p, 0, sizeof(RTL_STA_INFO) * (MAX_SUPPLICANT_NUM + 1));
	wrq.u.data.pointer = (caddr_t)p;
	wrq.u.data.length = sizeof(RTL_STA_INFO) * (MAX_SUPPLICANT_NUM + 1);
	*((unsigned char *)wrq.u.data.pointer) = MAX_SUPPLICANT_NUM;

	rc = ioctl(fd, SIOCGIWRTLSTAINFO, &wrq);
	close(fd);
	return rc;
}

_CPEPING_TEST_T cpeping_Test[10];
extern int cpeping_trapmode_enable;

static void cpeping_init_instance(int no)
{
	memset(&cpeping_Test[no], 0, sizeof(cpeping_Test[0]));
	cpeping_Test[no].minPingTime = 0;
	cpeping_Test[no].EntryStatus = 0;
	cpeping_Test[no].pktTimeoutcnt = 0;
}

int init_cpeping_test_t(void)
{
	int i;

	for (i = 0; i <10 ; i++)
		cpeping_init_instance(i);
	return 0;
}

void update_cpeping_result(int no)
{
	FILE *fp;
	char buf[80];
	char *argv[2];
	int argc;
	char tmp[80];

	snprintf(tmp, sizeof(tmp), "%s%d", CPEPING_RESULT_PATH, no);
	if ( (fp = fopen(tmp, "r")) ) {
		while( fgets(buf, sizeof(buf), fp) ) {
			if ( (argc = parse_line(buf, argv, 2, " =\r\n\t")) != 2)
				break;
			else if (!strcmp("minPingTime", argv[0]))
				cpeping_Test[no].minPingTime = strtoul(argv[1], NULL, 10);
			else if (!strcmp("avgPingTime", argv[0]))
				cpeping_Test[no].avgPingTime = strtoul(argv[1], NULL, 10);
			else if (!strcmp("maxPingTime", argv[0]))
				cpeping_Test[no].maxPingTime = strtoul(argv[1], NULL, 10);
			else if (!strcmp("pktTimeoutcnt", argv[0]))
				cpeping_Test[no].pktTimeoutcnt = strtoul(argv[1], NULL, 10);
 			else
				break;
		}
		fclose(fp);
	}
	unlink(tmp);
	cpeping_Test[no].EntryStatus = 0;
}

int get_cpepingEntryStatus(int no)
{
	if (no <= 0 || no > 10)
		return -1;
	no -= 1;

	return cpeping_Test[no].EntryStatus;
}

int get_mincpePingTime(int no)
{
	if (no <= 0 || no > 10)
		return -1;

	no -= 1;

	return cpeping_Test[no].minPingTime;
}

int get_maxcpePingTime(int no)
{
	if (no <= 0 || no > 10)
		return -1;

	no -= 1;

	return cpeping_Test[no].maxPingTime;
}

int get_timeoutcpePingTime(int no)
{
	if (no <= 0 || no > 10)
		return -1;

	no -= 1;

	return cpeping_Test[no].pktTimeoutcnt;
}

int get_avgcpePingTime(int no)
{
	if (no <= 0 || no > 10)
		return -1;

	no -= 1;

	return cpeping_Test[no].avgPingTime;
}

int get_cpepingtrap_enable()
{
	char cpetrap_mode[4];

	sprintf(cpetrap_mode, "%s", getValue("x_cpeping_trap")? : "0");
	cpeping_trapmode_enable = atoi(cpetrap_mode);
	return cpeping_trapmode_enable;
}

int set_cpepingtrap_enable(int val)
{
	char buf[4];

	if(val!=0 && val!=1)
		return 0;

	sprintf(buf, "%d", val);
	cpeping_trapmode_enable = val;
	setValue("x_cpeping_trap", buf);
	nvram_commit();

	return 1;
}

int set_wlanReset(int res)
{
	if ( res == 1) {
		syslog(LOG_INFO, "<D>Do it, reset wlan in snmpd");
		system("smartreset --wl0 0x3 --wl1 0x3 &");
		return 1;
	}
	return 0;
}

int snmp_cpeping_test(int No)
{
    int client_socket;
    struct sockaddr_un server_addr;
    char buf[BUFF_SIZE], macaddr[32];
    struct sockaddr_in addr;

    if (No >= SUPPORT_HOST_NUM)
        return 0;

    client_socket = socket(PF_FILE, SOCK_STREAM, 0);
    if (client_socket == -1)
        return -1;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    snprintf(server_addr.sun_path, sizeof(server_addr.sun_path), "%s", FILE_SERVER);

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        close(client_socket);
        return -1;
    }

    addr.sin_addr.s_addr = htonl(get_hostInfoIpAddr(No));
    snprintf(macaddr, sizeof(macaddr), "%02X%02X%02X%02X%02X%02X",
        hostInfo[No].mac[0], hostInfo[No].mac[1], hostInfo[No].mac[2], hostInfo[No].mac[3], hostInfo[No].mac[4], hostInfo[No].mac[5]);

    snprintf(buf, sizeof(buf), "%d,%d,%s,%s", No, hostInfo[No].portNo, inet_ntoa(addr.sin_addr), macaddr);

    write(client_socket, buf, BUFF_SIZE);
    close(client_socket);

    return 0;
}

int set_cpepingEntryStatus(int no, int action)
{
	char tmp[80];
	char *cpetrap_mode;

	if (no <= 0 || no > 10)
		return -1;

	if (action!=1)
		return -1;

	cpetrap_mode = getValue("x_cpeping_trap")? : "0";
	if(!(atoi(cpetrap_mode)))
		return -1;

	no -= 1;

	cpeping_init_instance(no);
	cpeping_Test[no].EntryStatus = action;
	sprintf(tmp, "%s%d", CPEPING_RESULT_PATH, no);
	unlink(tmp);
	snmp_cpeping_test(no);

	return 0;
}

int get_wanport_phyconfig()
{
	struct phreq phr;
	int fd;

	memset(&phr, 0, sizeof(phr));
	fd = open("/proc/brdio", O_RDWR);
	if (fd < 0)
		return -1;
	phr.phr_port = PH_MAXPORT;
	if (ioctl(fd, PHGIO, &phr))
		perror("PHGIO");
	close(fd);
	return ! !(phr.phr_optmask & PHF_LINKUP);
}

int set_sysName(unsigned char *buf, int size)
{
	if (size > 0) {
		setValue_mib(MIB_HOST_NAME, (void*)buf);
		return 1;
	} else {
		return 0;
	}

}

int get_wlanResetMode()
{
	int mode;

	mode = atoi(getValue("x_wlan_reset_enable"));

	if(mode == 0)
		return 2;
	else if(mode == 1)
		return 1;
	else
		return 0;
}

int set_wlanResetMode(int mode)
{
	char buf[2];

	if(mode == 1)
		snprintf(buf, sizeof(buf), "%s", "1");
	else if (mode == 2)
		snprintf(buf, sizeof(buf), "%s", "0");
	else
		return 0;

	setValue("x_wlan_reset_enable", buf);
	return 1;
}

int get_Ipv6PassThruMode()
{
	int mode;

	mode = nvram_atoi("CUSTOM_PASSTHRU_ENABLED", 0);

	if(mode == 0)
		mode = 2;

	return mode;
}

int set_Ipv6PassThruMode(int mode)
{
	if(mode != 1 && mode != 2)
		return 0;

	if(mode == 2)
		mode = 0;

	setValue_mib(MIB_CUSTOM_PASSTHRU_ENABLED, (void*)&mode);
	return 1;
}

int get_autoResetMode()
{
	int mode;

	mode = atoi(getValue("x_auto_reboot_enable"));

	if(mode == 0) {
		return 2;
	} else {
		return 1;
	}
}

int set_autoResetMode(int res)
{
	int status;

	if(res != 1 && res != 2)
		return 0;

	status = access("/var/run/auto_reboot.pid", F_OK);

	if(res == 1) {
		setValue("x_auto_reboot_enable", "1");

		if(status) {
			start_autoreboot();
		}

	} else if (res == 2) {
		setValue("x_auto_reboot_enable", "0");

		if(!status) {
			yexecl(NULL, "killall auto_reboot");
			unlink("/var/run/auto_reboot.pid");
		}
	}
	commitValue();

	return 1;
}

int get_autoResetWanTraffic()
{
	int val;

	val = atoi(getValue("x_auto_bw_kbps"));

	if(val < 100 || val > 1000)
		return 0;

	val = val / 100;
	return val;
}

int set_autoResetWanTraffic(int res)
{
	char buf[2];

	if(res < 1 || res > 10)
		return 0;

	res = res * 100;
	sprintf(buf, "%d", res);

	setValue("x_auto_bw_kbps", buf);


	return 1;
}

int get_wirelessHandover()
{
	int val;

	val = atoi(getValue("WLAN0_VAP3_WLAN_DISABLED"));

	if(val != 1 && val != 0)
		return 0;

	if(val == 0)
		return 1;
	else
		return 2;
}

int set_wirelessHandover(int mode)
{
	int disabled;

	if (mode != 1 && mode != 2)
		return 0;

	if (mode == 1)
		disabled = 0;
	else
		disabled = 1;

	wlan_idx = 0;
	vwlan_idx = 4;
	setValue_mib(MIB_WLAN_WLAN_DISABLED, (void*)&disabled);
	return 1;
}

int set_wlanSessionLimit(int wl_band, int val)
{
	if ( val <= 0 || val > 30 )
		return 0;

	wlanBasicConfig[wl_band].sessionLimit = val;
	wlanBasicConfig[wl_band].changed = 1;
	return 1;
}

long get_wlanSessionLimit(int wl_band)
{
	char var[80];
	int setup_val = 0;

	if(wlanBasicConfig[wl_band].sessionLimit == 0) {
		sprintf(var, "x_snmp_wl%dslimit", wl_band);
		setup_val = nvram_atoi(var, 10);
	} else
		setup_val = wlanBasicConfig[wl_band].sessionLimit;

	return (setup_val);
}

static int getwlassoc_num( const char* wlintf, int *num )
{
	int skfd=0;
	unsigned short staNum;
	struct iwreq wrq;

	if ( (skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return 0;

	strncpy(&wrq.ifr_name, wlintf, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&staNum;
	wrq.u.data.length = sizeof(staNum);

	if ( ioctl(skfd, SIOCGIWRTLSTANUM, &wrq) < 0 ) {
		close( skfd );
		return -1;
	}
	*num  = (int)staNum;
	close( skfd );

	return *num;
}

static int get_wlsta_count(int wl_band)
{
	int i;
	char wl_intf[80];
	int total_sta_n = 0, val=0;

	if ( wl_band != 0 && wl_band != 1 )
		return 0;

	for ( i = 0; i < MAX_WLAN_INTF_NUM; i++ ) {
		if ( root_vwlan_disable[i][wl_band] ) {
			if ( i == 0) return 0;
			continue;
		}

		if (wl_band == 0 && i == 4) continue;		// handover SSID

		wl_intf[0]=0;
		if ( i == 0 ) sprintf(wl_intf, "wlan%d", wl_band);
		else sprintf(wl_intf, "wlan%d-va%d", wl_band, i-1);
		val=0;
		total_sta_n += getwlassoc_num(wl_intf, &val);
	}
	return total_sta_n;
}

long get_wlanSession(int wl_band)
{
	return (get_wlsta_count(wl_band));
}

int getWlBssInfo(char *interface, bss_info *pInfo)
{
	int skfd=0;
	struct iwreq wrq;

	if ( (skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;

	wrq.u.data.pointer = (caddr_t)pInfo;
	wrq.u.data.length = sizeof(bss_info);

	if (iw_get_ext(skfd, interface, SIOCGIWRTLGETBSSINFO, &wrq) < 0) {
		close( skfd );
		return -1;
	}
	close( skfd );

	return 0;
}

int set_wlanAutoband(int wl_band, int val)
{
	int channelNum = 0;
	bss_info bss;
	char wl_intf[80];

	if ( val != 1 && val != 2)
		return 0;

	wlan_idx = wl_band;
	vwlan_idx = 0;

	if ( val == 1 ) {
		//enable
		channelNum = 0;
	} else {
		//disable
		wl_intf[0]=0;
		sprintf(&wl_intf[0], "wlan%d", wl_band);
		getWlBssInfo( wl_intf, &bss);

		channelNum = bss.channel;
	}
	setValue_mib(MIB_WLAN_CHANNEL, (void*)&channelNum);

	return 1;
}

long get_wlanAutoband(int wl_band)
{
	FILE *fp;
	char buf[128], name[32], val[80], path[80];
	int use_40m =0;

	path[0] =0;
	sprintf(path, "/proc/wlan%d/mib_11n", wl_band);
	if ( !(fp = fopen(path, "r")) )
		return SNMP_ERROR_WRONGVALUE;

	while(fgets(buf, sizeof(buf), fp) != NULL) {
		name[0] = 0;
		val[0] = 0;
		ydespaces(&buf[0]);
		sscanf(buf, "%s %s", name, val);
		if(!strcmp(name, "currBW:")) {
			if (val[0] == '4')
				use_40m = 1;
			break;
		}
	}
	fclose(fp);
	return ((use_40m)? 2: 1);
}


int set_wanPortTraffic(int val)
{
	if ( val < 10 || val > 900 )//Mbps
		return 0;

	portLimit.slimit = val;
	portLimit.changed = 1;
	return 1;
}

long get_wanPortTraffic(void)
{
	int setup_val = 0;

	if(portLimit.slimit == 0) {
		setup_val = nvram_atoi("x_snmp_wireslimit", 80);//Mbps
	} else
		setup_val = portLimit.slimit;

	return (setup_val);
}

int set_autoResetWanCrc(int val)
{
	int status;
	char bufval[80];
	int wancrc = 0;

	if ( val < 0 )
		return 0;

	wancrc = nvram_atoi("x_autoreboot_wancrc", 20);
	if ( val == wancrc )
		return 1;

	sprintf(bufval, "%d", val);
	nvram_set("x_autoreboot_wancrc", bufval);

	if ( !(status = access("/var/run/auto_reboot.pid", F_OK)) ) {
		yexecl(NULL, "killall auto_reboot");
		unlink("/var/run/auto_reboot.pid");

		start_autoreboot();
	}
	commitValue();

	return 1;
}

long get_autoResetWanCrc(void)
{
	char buf[80];
	long val = 0;

	nvram_get_r_def("x_autoreboot_wancrc", buf, sizeof(buf), "20");
	val = strtoul(buf, NULL, 10);

	return (val);
}

int autochan_get_bandwidth(void)
{
	int skfd = 0;
	int bandwidth = 0;
	struct iwreq wrq;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (skfd < 0)
		return -1;

	wrq.u.data.pointer = (caddr_t)&bandwidth;
	wrq.u.data.length = sizeof(bandwidth);
	strncpy(wrq.ifr_name, "wlan1", IFNAMSIZ);
	wrq.u.data.flags = RTL8192CD_IOCTL_BANDWIDTH_GET;

	if (ioctl(skfd, SIOCIWCUSTOM, &wrq) < 0) {
		close(skfd);
		return -1;
	}
	close(skfd);

	return bandwidth;
}

int set_FactoryReset(int res)
{
	if (res != 1)
		return 0;

	g_SaveAndApply = 2;	//Factort Reset
	snmpAction |= SNMP_SAVE_APPLY;
	return 1;
}

int set_AdminReset(res)
{
	unsigned char mac[6] = {0,};
	char passwd[128] = {0,}, user_pw[128] = {0,};

	apmib_get(MIB_HW_NIC1_ADDR, mac);
	snprintf(passwd, sizeof(passwd), "%02X%02X%02X_admin", mac[3], mac[4], mac[5]);
	cal_sha256(passwd, user_pw);
	setValue("x_USER_PASSWORD", user_pw);
	commitValue();
	return 1;
}

int port_index_change(int index)
{
	if (index == 0)
		return 4;
	else
		return index - 1;
}

void get_wlanMac(char *mac, int index)
{
	char buf[20], strmac[16];

	snprintf(buf, sizeof(buf), "HW_WLAN%d_WLAN_ADDR", index);
	nvram_get_r_def(buf, strmac, sizeof(strmac), "000000000000");
	simple_ether_atoe(strmac, (unsigned char *)mac);
}
