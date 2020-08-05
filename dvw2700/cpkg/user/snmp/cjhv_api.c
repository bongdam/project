#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "cjhv_api.h"
#include "custom.h"

/* Global Variables */
_wanConfig_t_ wanConfig;
_portfwConfig_t_ setPortfw_entry;
_portfwConfig_t_ checkPortfw_entry;
_con_staInfo_t_ staInfo[MAX_STA_NUM * 2];
_con_hostInfo_t_ hostInfo[MAX_STA_NUM];
_ping_test_t pingTest;
extern unsigned int adjacent_channel[13];
extern unsigned int best_channel[13];
extern int snmpAction;
static int best_chan = 0;
int dmz_type = 0;

static struct nmpipe *named_pipe = NULL;
P_STATS portStats[5];

int banned_port[] = {8080, 8787, 2323, 67, 68, 53, 123, 20161, 80};

const int influence_table[CJHV_MAX_CHAN_NUM][CJHV_MAX_CHAN_NUM]= {
	{ 1, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, //channel 1 ~ 13
	{ 3, 1,	3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ 2, 3,	1, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0 },
	{ 1, 2,	3, 1, 3, 2, 1, 0, 0, 0, 0, 0, 0 },
	{ 0, 1,	2, 3, 1, 3, 2, 1, 0, 0, 0, 0, 0 },
	{ 0, 0,	1, 2, 3, 1, 3, 2, 1, 0, 0, 0, 0 },
	{ 0, 0,	0, 1, 2, 3, 1, 3, 2, 1, 0, 0, 0 },
	{ 0, 0,	0, 0, 1, 2, 3, 1, 3, 2, 1, 0, 0 },
	{ 0, 0,	0, 0, 0, 1, 2, 3, 1, 3, 2, 1, 0 },
	{ 0, 0,	0, 0, 0, 0, 1, 2, 3, 1, 3, 2, 1 },
	{ 0, 0,	0, 0, 0, 0, 0, 1, 2, 3, 1, 3, 2 },
	{ 0, 0,	0, 0, 0, 0, 0, 0, 1, 2, 3, 1, 3 },
	{ 0, 0,	0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 1 },
};

static int sep_token(char *p, char *argv[20], char *token)
{
	char *q;
	int i;

	q = NULL;
	for (i = 0; i < 20; ) {
		q = strsep(&p, token);
		if (!q)
			break;
		if (*q)
			argv[i++] = q;
	}
	return i;
}

unsigned long simple_strtoul(const char *cp,char **endp,unsigned int base)
{
    unsigned long result = 0,value;

    if (!base) {
        base = 10;
        if (*cp == '0') {
            base = 8;
            cp++;
            if ((*cp == 'x') && isxdigit(cp[1])) {
                cp++;
                base = 16;
            }
        }
    }
    while (isxdigit(*cp) && (value = isdigit(*cp) ? *cp-'0' : (islower(*cp)
        ? toupper(*cp) : *cp)-'A'+10) < base) {
        result = result*base + value;
        cp++;
    }
    if (endp)
        *endp = (char *)cp;

    return result;
}

int calculate_best_chan(int *sel_auto_ch, unsigned int *pD, int *pS, int end_chan)
{
	int i, ii;
	int min = -1;
	unsigned int tmp = 0xffffffff;

	if ( !pD || !pS )
		return -1;

	for ( i = 0; i < CJHV_MAX_CHAN_NUM; i++) {
		for ( ii = 0; ii < CJHV_MAX_CHAN_NUM; ii++) {
			pS[i] += (pD[ii] * influence_table[i][ii]);
		}

		printf("DVLOG_Channel %d[detect:%d], score %u\n", i+1, pD[i], pS[i]);
		if ( sel_auto_ch[0] == 1 ) {
			if ( (i < end_chan) && pS[i] < tmp ) {
				min = i;
				tmp = pS[i];
			}
		} else {
			if (sel_auto_ch[i+1] == 1) {
				if ( (i < end_chan) && pS[i] < tmp ) {
					min = i;
					tmp = pS[i];
				}
			}
		}
	}

	return (min + 1);
}

int calculate_around_score(int best_chan, unsigned int *pD)
{
	int i;
	int ch, tmp_chan;
	int around_score = 0;

	tmp_chan = best_chan -1;
	for ( i = 0; i < 4; i++ ) {
		ch = (tmp_chan + CHAN_OFFSET(i));
		if ( ch < 0 || ch > 12 )
			continue;
		around_score += pD[ch];
	}
	return around_score;
}

int write_pid(char *pid_file)
{
    FILE *f;
    int pid = 0;

    if (!pid_file || !pid_file[0])
        return 0;

    if ((f = fopen(pid_file, "w"))) {
        pid = getpid();
        fprintf(f, "%d\n", pid);
        fclose(f);
    }

    return pid;
}

int read_int(char *file, int def)
{
    FILE *f;
    int ret = def;

    if (!file || !file[0])
        return ret;

    f = fopen(file, "r");
    if (f) {
        if (fscanf(f, "%d", &ret) != 1) {
            ret = def;
        }
        fclose(f);
    }
    return ret;
}

int read_pid(char *path)
{
	FILE *fp;
	char buf[80];

	if (!path)
		return 0;

	if ( !(fp = fopen(path, "r")) )
		return 0;

	fgets(buf, sizeof(buf), fp);
	fclose(fp);
	return (strtoul(buf, NULL, 10));
}

int test_pid(char *pid_file)
{
    char path[64];
    int pid = read_pid(pid_file);

    if (pid <= 0)
        return 0;

    sprintf(path, "/proc/%d/cmdline", pid);
    return (access(path, F_OK) == 0) ? pid : 0;
}

int getPid(char *filename)
{
	struct stat status;
	char buff[64];
	FILE *fp;

	if (stat(filename, &status) < 0)
		return -1;
	fp = fopen(filename, "r");
	if (!fp) {
		fprintf(stderr, "Read pid file error!\n");
		return -1;
	}
	fgets(buff, 64, fp);
	fclose(fp);

	return (atoi(buff));
}

void string_to_hex(char *string, char *key, int len)
{
    int idx;
    int ii = 0;

    for (idx = 0; idx < len; idx++)
        ii += sprintf(&key[ii], "%02X", (int)string[idx]);
    key[ii] = 0;
}

int hex_to_string(char *string, unsigned char *key, int len)
{
    char tmpBuf[4];
    int idx, ii = 0;

    for (idx = 0; idx < len; idx += 2) {
        tmpBuf[0] = string[idx];
        tmpBuf[1] = string[idx + 1];
        tmpBuf[2] = 0;
        if (!isxdigit(tmpBuf[0]) || !isxdigit(tmpBuf[1]))
            return 0;
        key[ii++] = (unsigned char)strtol(tmpBuf, NULL, 16);
    }

    return 1;
}

int simple_ether_atoe(char *strVal, unsigned char *macAddr)
{
    int ii;
    int mac[6];

    if (strlen(strVal) == 12 && hex_to_string(strVal, macAddr, 12))
        return 1;

    ii = sscanf(strVal, "%02x:%02x:%02x:%02x:%02x:%02x",
    	&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    if (ii != 6)
        ii = sscanf(strVal, "%02x-%02x-%02x-%02x-%02x-%02x",
        	&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    if (ii != 6)
        return 0;
    for (ii = 0; ii < 6; ii++)
        macAddr[ii] = (unsigned char)(mac[ii] & 0xff);
    return 1;
}

static void ping_init_instance(void)
{
	memset(&pingTest, 0, sizeof(pingTest));
	pingTest.pktCount = 5;
	pingTest.pktSize = 100;
	pingTest.pktTimeout = 1000;
	pingTest.TrapOnComplete = 1;
	pingTest.pingCompleted = 2;
	pingTest.pingResultCode = Enum_RowStatusNotReady;
}

void global_variables_initial(void)
{
	memset(&wanConfig, 0, sizeof(wanConfig));
	memset(&staInfo[0], 0 , sizeof(staInfo));
	memset(&hostInfo[0], 0, sizeof(hostInfo));
	memset(&setPortfw_entry, 0, sizeof(setPortfw_entry));
	memset(&checkPortfw_entry, 0, sizeof(checkPortfw_entry));
	ping_init_instance();
}

static int _is_hex(char c)
{
    return (((c >= '0') && (c <= '9')) ||
            ((c >= 'A') && (c <= 'F')) ||
            ((c >= 'a') && (c <= 'f')));
}

static int value_to_hex(char *string, unsigned char *key, int len)
{
	char tmpBuf[4];
	int idx, ii = 0;
	for (idx = 0; idx < len; idx += 2) {
		tmpBuf[0] = string[idx];
		tmpBuf[1] = string[idx+1];
		tmpBuf[2] = 0;

		if ( !_is_hex(tmpBuf[0]) || !_is_hex(tmpBuf[1]))
			return 0;
		key[ii++] = (unsigned char) strtol(tmpBuf, (char**)NULL, 16);
	}

	return 1;
}

/* ======================= SYSTEM INFO ================================= */
void get_modelName(char *str, int len)
{
	char value[32] = {0,};

	nvram_get_r_def("DEVICE_NAME", value, sizeof(value), "DVW2700");
	snprintf(str, len, "%s", value);
}

void get_version(char *str, int len)
{
	memset(str, 0, len);

	if(!yfcat("/etc/version", "%s", str))
		sprintf(str, "%s", "1.00.00");
}

void get_uptime(char *str, int len, char *path)
{
	char uptime[40];
	FILE *fp;

	memset(str, 0, len);
	if(access(path, F_OK)) {
		return;
	}

	if ((fp = fopen(path, "r"))) {
		fgets(uptime, sizeof(uptime), fp);
		ydespaces(uptime);
		snprintf(str, len, "%s", uptime);
		fclose(fp);
	}
}

long get_cpu_utiliz(void)
{
	char buf[512];
	double cpu_idle_load = 0, cpu_usage = 0;

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
	FILE *fp = NULL;
	char buf[64];
	long i, kilos[4];

	fp = fopen("/proc/meminfo", "r");
	if (fp == NULL)
		return -1;
	for (i = 0; fgets(buf, sizeof(buf), fp) && i < 4;) {
		if (sscanf(buf, "MemTotal: %ld", kilos + 0) > 0 ||
		    sscanf(buf, "MemFree: %ld", kilos + 1) > 0 ||
		    sscanf(buf, "Buffers: %ld", kilos + 2) > 0 ||
		    sscanf(buf, "Cached: %ld", kilos + 3) > 0)
			i += 1;
	}
	fclose(fp);

	if (kilos[0] == 0)
		return 0;

	return 100L - (((kilos[1] + kilos[2] + kilos[3]) * 100) / kilos[0]);
}

long get_sys_status(void)
{
	int state = 0;
	long provisioning = 0;

	yfcat(AUTOUP_STATE, "%d", &state);

	if (state == 0) {
		provisioning = 6;
	} else {
		switch(state) {
			case 1:
				provisioning = 5;
				break;
			case 2:
				provisioning = 4;
				break;
			case 3:
				provisioning = 3;
				break;
			case 4:
				provisioning = 2;
				break;
			case 5:
				provisioning = 1;
				break;
			case 6:
				provisioning = 2;
				break;
			default:
				provisioning = 6;
				break;
		}
	}

	return provisioning;
}

void get_portStats(int p_idx)
{
	FILE *fp = NULL;
	char *args[16] = {NULL,};
	char portIdx[12] = {0,}, line[256] = {0,};
	int n, Rx = 1;

	memset(&portStats[0], 0, sizeof(portStats));

	snprintf(portIdx, sizeof(portIdx), "%d:", p_idx);

	fp = fopen("/proc/asicCounter", "r");
	if (fp) {
		while(fgets(line, sizeof(line), fp)) {
			n = ystrargs(line, args, _countof(args), " \n", 0);
			if (n > 8) {
				if (strcmp(args[0], portIdx) == 0) {
					if (Rx) {
						portStats[p_idx].rxbyte = strtoull(args[1], NULL, 10);
						portStats[p_idx].rx_multicast = strtol(args[3], NULL, 10);
						portStats[p_idx].crc = strtol(args[7], NULL, 10);
						Rx = 0;
					} else {
						portStats[p_idx].txbyte = strtoull(args[1], NULL, 10);
						portStats[p_idx].tx_multicast = strtol(args[3], NULL, 10);
					}
				}
			}
		}
		fclose(fp);
	}
}

unsigned long get_portStatusCrc(int portidx)
{
	get_portStats(portidx);
	return portStats[portidx].crc;
}
/* ======================= SYSTEM INFO ================================= */

/* ======================= WAN STATUS ================================= */
long get_wan_status(void)
{
	char value[4] = {0,};

	if (wanConfig.obtainedMethod == 0) {
		nvram_get_r_def("WAN_DHCP", value, sizeof(value), "1");
		if (value[0] == '0') {	// static
			wanConfig.obtainedMethod = 2;
		} else {
			wanConfig.obtainedMethod = 1;
		}
	}

	return wanConfig.obtainedMethod;
}

void get_mac(char *str, int len)
{
	char value[24];
	char temp[3] = {0,};
	unsigned char hwAddr[6];
	int i, j;

	memset(str, 0, len);
	nvram_get_r_def("HW_NIC1_ADDR", value, sizeof(value), "000000000000");

	for (i = 0, j = 0; i < 12; i += 2) {
		memcpy(temp, &value[i], 2);
		hwAddr[j++] = (char)strtol(temp, NULL, 16);
	}

	memcpy(str, hwAddr, sizeof(hwAddr));
}

void get_wanIpAddress(unsigned long *wanIp)
{
	FILE *fp = NULL;
	struct in_addr in;
	char value[32] = {0,};

	*wanIp = 0;
	if (wanConfig.IpAddr == 0) {
		fp = fopen("/var/wan_ip", "r");
		if (fp) {
			if (fgets(value, sizeof(value), fp)) {
				if ( inet_aton(value, &in) )
					wanConfig.IpAddr = in.s_addr;
			}
			fclose(fp);
		}
	}

	*wanIp = wanConfig.IpAddr;
}

void get_wanSubnetMask(unsigned long *wanMask)
{
	FILE *fp = NULL;
	struct in_addr in;
	char value[32] = {0,};

	*wanMask = 0;
	if (wanConfig.subnetMask == 0) {
		fp = fopen("/var/netmask", "r");
		if (fp) {
			if (fgets(value, sizeof(value), fp)) {
				if ( inet_aton(value, &in) )
					wanConfig.subnetMask = in.s_addr;
			}
			fclose(fp);
		}
	}

	*wanMask = wanConfig.subnetMask;
}

void get_gwIpAddress(unsigned long *wanGw)
{
	FILE *fp = NULL;
	struct in_addr in;
	char value[32] = {0,};

	*wanGw = 0;
	if (wanConfig.defGateway == 0) {
		fp = fopen("/var/gateway", "r");
		if (fp) {
			if (fgets(value, sizeof(value), fp)) {
				if ( inet_aton(value, &in) )
					wanConfig.defGateway = in.s_addr;
			}
			fclose(fp);
		}
	}

	*wanGw = wanConfig.defGateway;
}

void get_dnsAddress(unsigned long *dns, int index)
{
	char line[80] = {0,};
	char *args[2] = {NULL,};
	FILE *fp;
	int n, cnt = 0;

	*dns = 0;
	if (wanConfig.dns[index - 1] != 0) {
		*dns = wanConfig.dns[index - 1];
		return;
	}

	fp = fopen("/etc/resolv.conf", "r");
	if (!fp) {
		return;
	}

	while (fgets(line, sizeof(line), fp)) {
		n = ystrargs(line, args, _countof(args), " \n", 0);
		if (n == 2) {
			cnt++;
			if (cnt == index) {
				wanConfig.dns[index - 1] = inet_addr(args[1]);
			}
		}
	}
	fclose(fp);

	*dns = wanConfig.dns[index - 1];
}

int set_wanMethod(int mode)
{
	if (mode != 1 && mode != 2) { // 1: auto  2: static
		printf("Invalid Value....%d\n", mode);
		return 0;
	}

	wanConfig.obtainedMethod = mode;
	nvram_set("WAN_DHCP", (mode == 1) ? "1" : "0");
	nvram_set("DNS_MODE", (mode == 1) ? "0" : "1");

	return 1;
}

int set_wanIpAddress(unsigned char *var_val, int var_val_len)
{
	unsigned char *p = var_val;
	char wanIp[24] = {0,};

	wanConfig.IpAddr = *(unsigned long *)p;
	inet_ntop(AF_INET, &wanConfig.IpAddr, wanIp, sizeof(wanIp));
	nvram_set("WAN_IP_ADDR", wanIp);

	return 1;
}

int set_wanSubnetMask(unsigned char *var_val, int var_val_len)
{
	unsigned char *p = var_val;
	char wanMask[24] = {0,};

	wanConfig.subnetMask = *(unsigned long *)p;
	inet_ntop(AF_INET, &wanConfig.subnetMask, wanMask, sizeof(wanMask));
	nvram_set("WAN_SUBNET_MASK", wanMask);

	return 1;
}

int set_wanDefaultGW(unsigned char *var_val, int var_val_len)
{
	unsigned char *p = var_val;
	char wanGw[24] = {0,};

	wanConfig.defGateway = *(unsigned long *)p;
	inet_ntop(AF_INET, &wanConfig.defGateway, wanGw, sizeof(wanGw));
	nvram_set("WAN_DEFAULT_GATEWAY", wanGw);

	return 1;
}

int set_wanDNS2(unsigned char *var_val, int var_val_len)
{
	unsigned char *p = var_val;
	char dns[24];
	time_t t;
	struct tm *tmp;
	char buf[40] = {0,};
	char apms_ip[32] = {0,};

	wanConfig.dns[1] = *(unsigned long *)p;
	inet_ntop(AF_INET, &wanConfig.dns[1], dns, sizeof(dns));
	nvram_set("DNS2", dns);
	nvram_set("DNS_MODE", "1");

	t = time(NULL);
	tmp = localtime(&t);
	strftime(buf, sizeof(buf), "%F %T", tmp);
	nvram_get_r_def("apms_ip", apms_ip, sizeof(apms_ip), "0.0.0.0");
	yecho("/tmp/.attack_ip", "%s %s\n", apms_ip, buf);
	return 1;
}

void get_trap_wanIpAddress(unsigned long *wanIp)
{
	FILE *fp = NULL;
	struct in_addr in;
	char value[16] = {0,};

	*wanIp = 0;
	if (access("/var/wan_ip", F_OK) == 0) {
		yfcat("/var/wan_ip", "%s", value);
		if (inet_aton(value, &in))
			*wanIp = in.s_addr;
	}
}
/* ======================= WAN STATUS ================================= */

/* ======================= LAN STATUS ================================= */
void get_lanMac(char *str, int len)
{
	char value[24];
	char temp[3] = {0,};
	unsigned char hwAddr[6];
	int i, j;

	memset(str, 0, len);
	nvram_get_r_def("HW_NIC0_ADDR", value, sizeof(value), "000000000000");

	for (i = 0, j = 0; i < 12; i += 2) {
		memcpy(temp, &value[i], 2);
		hwAddr[j++] = (char)strtol(temp, NULL, 16);
	}

	memcpy(str, hwAddr, sizeof(hwAddr));
}

void get_lanIpAddress(unsigned long *lanIp)
{
	struct in_addr in;
	char value[32] = {0,};

	*lanIp = 0;
	nvram_get_r_def("IP_ADDR", value, sizeof(value), "192.168.200.254");
	if ( inet_aton(value, &in) )
		*lanIp = in.s_addr;
}

void get_lanSubnetMask(unsigned long *Mask)
{
	struct in_addr in;
	char value[32] = {0,};

	*Mask = 0;
	nvram_get_r_def("SUBNET_MASK", value, sizeof(value), "255.255.255.0");
	if ( inet_aton(value, &in) )
		*Mask = in.s_addr;
}

int set_lanIPAddress(unsigned char *var_val, int var_val_len)
{
	unsigned char *p = var_val;
	struct in_addr ipaddr;
	char lan_ip[24] = {0,};

	ipaddr.s_addr = *(unsigned long *)p;
	snprintf(lan_ip, sizeof(lan_ip), "%s", inet_ntoa(ipaddr));
	nvram_set("IP_ADDR", lan_ip);
	nvram_set("user_ip", lan_ip);

	return 1;
}

int set_lanSubnetMask(unsigned char *var_val, int var_val_len)
{
	unsigned char *p = var_val;
	struct in_addr ipaddr;
	char mask[24];

	ipaddr.s_addr = *(unsigned long *)p;
	snprintf(mask, sizeof(mask), "%s", inet_ntoa(ipaddr));
	nvram_set("SUBNET_MASK", mask);

	return 1;
}

long get_dhcpServer(void)
{
	char value[4] = {0,};
	long dhcpEnable = 1;

	nvram_get_r_def("DHCP", value, sizeof(value), "2");
	dhcpEnable = strtol(value, NULL, 10);

	return (dhcpEnable) ? 1 : 2;
}

int set_dhcpServer(int mode)
{
	char value[4];
	int dhcpEnable = 0;

	if (mode != 1 && mode != 2) { // 1: enable  2: disable
		printf("Invalid Value....%d\n", mode);
		return 0;
	}

	snprintf(value, sizeof(value), "%d", (dhcpEnable == 1) ? 2 : 0);
	nvram_set("DHCP", value);

	return 1;
}

void get_ipPoolStartAddress(unsigned long *start_ip)
{
	char value[24] = {0,};
	struct in_addr in;

	*start_ip = 0;
	nvram_get_r_def("DHCP_CLIENT_START", value, sizeof(value), "192.168.200.100");
	if ( inet_aton(value, &in) ) {
		*start_ip = in.s_addr;
	}
}

int set_ipPoolStartAddress(unsigned char *var_val, int var_val_len)
{
	unsigned char *p = var_val;
	char start_ip[24] = {0,};
	struct in_addr ipaddr;

	ipaddr.s_addr = *(unsigned long *)p;
	snprintf(start_ip, sizeof(start_ip), "%s", inet_ntoa(ipaddr));
	nvram_set("DHCP_CLIENT_START", start_ip);
	nvram_set("user_dhcp_start", start_ip);

	return 1;
}

void get_ipPoolEndAddress(unsigned long *end_ip)
{
	char value[24] = {0,};
	struct in_addr in;

	*end_ip = 0;
	nvram_get_r_def("DHCP_CLIENT_END", value, sizeof(value), "192.168.200.200");
	if ( inet_aton(value, &in) ) {
		*end_ip = in.s_addr;
	}
}

int set_ipPoolEndAddress(unsigned char *var_val, int var_val_len)
{
	unsigned char *p = var_val;
	char end_ip[24] = {0,};
	struct in_addr ipaddr;

	ipaddr.s_addr = *(unsigned long *)p;
	snprintf(end_ip, sizeof(end_ip), "%s", inet_ntoa(ipaddr));
	nvram_set("DHCP_CLIENT_END", end_ip);
	nvram_set("user_dhcp_end", end_ip);

	return 1;
}
/* ======================= LAN STATUS ================================= */

/* ======================= WLAN BASIC ================================= */
long get_wlanMode(int wlan_idx)
{
	char query[32] = {0,};
	char value[4] = {0,};

	snprintf(query, sizeof(query), "WLAN%d_WLAN_DISABLED", wlan_idx);
	nvram_get_r_def(query, value, sizeof(value), "0");

	return (value[0] == '0')? 1 : 2;
}

int set_wlanMode(int mode, int wlan_idx)
{
	char query[32] = {0,};

	if (mode != 1 && mode != 2) { // 1: enable  2: disable
		printf("Invalid Value....%d\n", mode);
		return 0;
	}

	snprintf(query, sizeof(query), "WLAN%d_WLAN_DISABLED", wlan_idx);
	if (mode == 1)
		nvram_set(query, "0");
	else
		nvram_set(query, "1");

	return 1;
}

long get_wlanBand(int wlan_idx)
{
	char query[24] = {0,};
	char value[12] = {0,};
	long ret = 0, band = 0;


	snprintf(query, sizeof(query), "WLAN%d_BAND", wlan_idx);
	nvram_get_r_def(query, value, sizeof(value), "11");
	ret = strtol(value, NULL, 10);

	if (wlan_idx == WLAN_2G) {
		switch(ret) {
			case 1:                    // 2.4 Ghz(B)
			case 2:                    // 2.4 Ghz(G)
				band = ret;
				break;
			case 3:                    // 2.4 Ghz(B+G)
				band = 4;
				break;
			case 8:                    // 2.4 Ghz(N)
				band = 3;
				break;
			case 10:                   // 2.4GHz (G+N)
				band = 5;
				break;
			case 11:                   // 2.4GHz(B+G+N);
				band = 6;
				break;
			default:
				band = 0;
				break;
		}
	} else {
		switch(ret) {
			case 4:                    // 5 Ghz(A)
				band = 1;
				break;
			case 8:                    // 5 Ghz(N)
				band = 2;
				break;
			case 12:                   // 5 GHz (A+N)
				band = 4;
				break;
			default:
				band = 0;
				break;
		}
	}

	return band;
}

int set_wlanBand(int band, int wlan_idx)
{
	char query[24] = {0,};
	char value[12] = {0,};
	int ret = 0;

	if (wlan_idx == WLAN_2G) {
		if (band < 1 || band > 6)
			return 0;

		switch (band) {
			case 1:
				ret = 1;
				break;
			case 2:
				ret = 2;
				break;
			case 3:
				ret = 8;
				break;
			case 4:
				ret = 3;
				break;
			case 5:
				ret = 10;
				break;
			case 6:
				ret = 11;
				break;
			default:
				return 0;
		}
	} else {
		if (band != 1 && band != 2 && band != 4)
			return 0;

		switch (band) {
			case 1:
				ret = 4;
				break;
			case 2:
				ret = 8;
				break;
			case 4:
				ret = 12;
				break;
			default:
				return 0;
		}
	}

	snprintf(value, sizeof(value), "%d", ret);
	snprintf(query, sizeof(query), "WLAN%d_BAND", wlan_idx);
	nvram_set(query, value);

	return 1;
}

static int autochan_get_bandwidth(void)
{
	FILE *fp = NULL;
	char line[80];
	char *args[2] = {NULL,};
	int n, bandwidth = 0;

	fp = fopen("/proc/wlan1/mib_11n", "r");
	if (fp) {
		while (fgets(line, sizeof(line), fp)) {
			n = ystrargs(line, args, _countof(args), " :\n", 0);
			if (n == 2) {
				if (strcmp(args[0], "currBW:") == 0) {
					if (strcmp(args[1], "40M") == 0) {
						bandwidth = 1;
					}
				}
			}
		}
		fclose(fp);
	}

	return bandwidth;
}

long get_wlanChannelWidth(int wlan_idx)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long channelWidth;
	long band = get_wlanBand(wlan_idx);

	if (wlan_idx == WLAN_2G) {
		if (band == 1 || band == 2 || band == 4) { 	/* B, G, B + G */
			return 1;								/* currBW is 20M */
		}
	} else {
		if (band == 1) {							/* A */
			return 1;								/* currBW is 20M */
		}
	}

	snprintf(query, sizeof(query), "WLAN%d_CHANNEL_BONDING", wlan_idx);
	nvram_get_r_def(query, value, sizeof(value), "0");

	if (value[0] == '7') {		// auto
		channelWidth = autochan_get_bandwidth();
		return channelWidth + 1;
	}

	channelWidth = strtol(value, NULL, 10) + 1;

	return channelWidth;
}

int set_wlanChannelWidth(int width, int wlan_idx)
{
	char query[32] = {0,};

	if (width != 1 && width != 2)
		return 0;

	snprintf(query, sizeof(query), "WLAN%d_CHANNEL_BONDING", wlan_idx);

	if (width == 1)
		nvram_set(query, "0");
	else
		nvram_set(query, "1");

	return 1;
}

long get_wlanCtrlSideBand(int wlan_idx)
{
	char query[32] = {0,};
	char value[12] = {0,};

	snprintf(query, sizeof(query), "WLAN%d_CONTROL_SIDEBAND", wlan_idx);
	nvram_get_r_def(query, value, sizeof(value), "0");

	if (value[0] == '0')
		return 1;				//upper
	else
		return 2;				//lower
}

int set_wlanCtrlSideBand(int controlSideBand, int wlan_idx)
{
	char query[32] = {0,};

	if (controlSideBand != 1 && controlSideBand !=  2)
		return 0;

	snprintf(query, sizeof(query), "WLAN%d_CONTROL_SIDEBAND", wlan_idx);

	if (controlSideBand == 1) {
		nvram_set(query, "0");
	} else {
		nvram_set(query, "1");
	}

	return 1;
}

long get_wlanChannelNumber(int wlan_idx)
{
	long channel;
	bss_info bss;
	char query[32] = {0,};
	char value[12] = {0,};
	char inf[12] = {0,};

	snprintf(query, sizeof(query), "WLAN%d_CHANNEL", wlan_idx);
	nvram_get_r_def(query, value, sizeof(value), "0");

	channel = strtol(value, NULL, 10);

	if (channel == 0) {
		snprintf(inf, sizeof(inf), "wlan%d", wlan_idx);
		getWlBssInfo(inf, &bss);
		channel = (long)bss.channel;
	}

	if (wlan_idx == WLAN_5G) {
		switch (channel)	 {
			case 36:
				channel = 1;
				break;
			case 40:
				channel = 2;
				break;
			case 44:
				channel = 3;
				break;
			case 48:
				channel = 4;
				break;
			case 52:
				channel = 5;
				break;
			case 56:
				channel = 6;
				break;
			case 60:
				channel = 7;
				break;
			case 64:
				channel = 8;
				break;
			case 100:
				channel = 9;
				break;
			case 104:
				channel = 10;
				break;
			case 108:
				channel = 11;
				break;
			case 112:
				channel = 12;
				break;
			case 116:
				channel = 13;
				break;
			case 120:
				channel = 14;
				break;
			case 124:
				channel = 15;
				break;
			case 149:
				channel = 16;
				break;
			case 153:
				channel = 17;
				break;
			case 157:
				channel = 18;
				break;
			case 161:
				channel = 19;
				break;
			default:
				break;
		}
	}

	return channel;
}

int set_wlanChannelNumber(int channelNum, int wlan_idx)
{
	char value[12] = {0,};
	char query[32] = {0,};
	int channel = 0;

	if (wlan_idx == WLAN_2G) {
		if (channelNum < 0 || channelNum > 13)
			return 0;
		channel = channelNum;
	} else {
		if (channelNum < 0 || channelNum > 19)
			return 0;
		switch (channelNum)	 {
			case 1:
				channel = 36;
				break;
			case 2:
				channel = 40;
				break;
			case 3:
				channel = 44;
				break;
			case 4:
				channel = 48;
				break;
			case 5:
				channel = 52;
				break;
			case 6:
				channel = 56;
				break;
			case 7:
				channel = 60;
				break;
			case 8:
				channel = 64;
				break;
			case 9:
				channel = 100;
				break;
			case 10:
				channel = 104;
				break;
			case 11:
				channel = 108;
				break;
			case 12:
				channel = 112;
				break;
			case 13:
				channel = 116;
				break;
			case 14:
				channel = 120;
				break;
			case 15:
				channel = 124;
				break;
			case 16:
				channel = 149;
				break;
			case 17:
				channel = 153;
				break;
			case 18:
				channel = 157;
				break;
			case 19:
				channel = 161;
				break;
			default:
				break;
		}
	}

	snprintf(value, sizeof(value), "%d", channel);
	snprintf(query, sizeof(query), "WLAN%d_CHANNEL", wlan_idx);
	nvram_set(query, value);

	return 1;
}

long get_wlanDateRate(int wlan_idx)
{
	int band, autoRate, txrate, rf_num;
	int mask = 0, i, found = -1, option_num = 0;
	int rate, idx, defidx = 0, vht_num;
	int rate_mask[] = {31,1,1,1,1,2,2,2,2,2,2,2,2,4,4,4,4,4,4,4,4,8,8,8,8,8,8,8,8,16,16,16,16,16,16,16,16};
	struct _misc_data_ miscData;
	char inf[12] = {0,}, query[32] = {0,}, value[12] = {0,};

	snprintf(query, sizeof(query), "WLAN%d_BAND", wlan_idx);
	nvram_get_r_def(query, value, sizeof(value), "11");
	band = strtol(value, NULL, 10);

	snprintf(query, sizeof(query), "WLAN%d_RATE_ADAPTIVE_ENABLED", wlan_idx);
	nvram_get_r_def(query, value, sizeof(value), "1");
	autoRate = strtol(value, NULL, 10);

	snprintf(query, sizeof(query), "WLAN%d_FIX_RATE", wlan_idx);
	nvram_get_r_def(query, value, sizeof(value), "0");
	txrate = strtol(value, NULL, 10);

	snprintf(inf, sizeof(inf), "wlan%d", wlan_idx);
	getMiscData(inf, &miscData);

	rf_num = miscData.mimo_tr_used;

	if (autoRate)
		txrate = 0;
	if (band & 1)
		mask |= 1;
	if ((band & 2) || (band & 4))
		mask |= 2;
	if (band & 8) {
		if (rf_num == 3)
			mask |= 20;
		else if (rf_num == 2)
			mask |= 12;
		else
			mask |= 4;
	}

	option_num++;
	for (idx = 1, i = 1; i <= 36; i++) {
		if (rate_mask[i] & mask) {
			rate = (1 << (i-1));
		 	if (txrate == 0)
            	defidx = 0;
			 else if (txrate == rate)
				defidx = idx;
			idx++;
			option_num++;
		}
	}

	if(band & 64) {
		if (rf_num == 3)
			vht_num = 29;
		else if (rf_num == 2)
			vht_num = 19;
		else
			vht_num = 9;
		for (idx = 30, i = 0; i <= vht_num; i++) {
			rate = ((1 << 31) + i);
			if (txrate == rate){
				defidx = option_num;
			}
			if((i == 9) || (i == 19) || (i == 29))
			{
				idx++;
				continue;
			}
			idx++;
			option_num++;
		}
	}

	found = defidx;
	if (found != -1) {
		found += 1;
	}
	return found;
}

int set_wlanDateRate(int val, int wlan_idx)
{
	char value[12] = {0,};
	int band = get_wlanBand(wlan_idx);
	char query[32] = {0,};

	if (val == 1) {
		snprintf(query, sizeof(query), "WLAN%d_RATE_ADAPTIVE_ENABLED", wlan_idx);
		nvram_set(query, "1");
	} else if (val > 1 && val <= 29) {
		if (wlan_idx == WLAN_2G) {
			if ((band == 1 && (val > 5)) || // BAND B
				(band == 2 && !(val >= 6 && val <= 13)) ||  // BAND G
				(band == 3 && !(val >= 14 && val <= 29)) || // BAND N
				(band == 4 && !(val >= 2 && val <= 13)) ||  // BAND B+G
				(band == 5 && !(val >= 6 && val <= 29)))    // BAND G+N
				return 0;
		} else {
			if ((band == 1 && !(val >= 6 && val <= 13)) || // BAND A
				(band == 2 && !(val >= 14 && val <= 29)) ||  // BAND N
				(band == 4 && !(val >= 6 && val <= 29))) // BAND A+N
				return 0;
		}
		snprintf(query, sizeof(query), "WLAN%d_RATE_ADAPTIVE_ENABLED", wlan_idx);
		nvram_set(query, "0");

		val -= 1;
		if (val < 29)
			val = 1 << (val - 1);
		else if (val >= 29 && val < 37)
			val = ((1 << 28) + val - 29);
		else
			val = ((1 << 31) + val - 37);

		snprintf(query, sizeof(query), "WLAN%d_FIX_RATE", wlan_idx);
		snprintf(value, sizeof(value), "%d", val);
		nvram_set(query, value);
	} else {
		return 0;
	}

	return 1;
}
/* ======================= WLAN BASIC ================================= */

/* ======================= WLAN SSID CONFIG ================================= */
void get_wlanSSID(int index, char *str, int len)
{
	char query[32] = {0,};
	char value[64] = {0,};

	memset(str, 0, len);
	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_SSID");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_SSID");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_SSID");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_SSID");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_SSID");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_SSID");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_SSID");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "");
	snprintf(str, len, "%s", value);
}

long get_wlanSSIDMode(int index)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long disable = 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WLAN_DISABLED");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WLAN_DISABLED");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WLAN_DISABLED");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WLAN_DISABLED");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WLAN_DISABLED");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WLAN_DISABLED");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WLAN_DISABLED");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "1");
	disable = strtol(value, NULL, 10);

	return (disable) ? 2 : 1;
}

long get_wlanBSSID(int index)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long hidden = 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_HIDDEN_SSID");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_HIDDEN_SSID");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_HIDDEN_SSID");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_HIDDEN_SSID");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_HIDDEN_SSID");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_HIDDEN_SSID");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_HIDDEN_SSID");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "1");
	hidden = strtol(value, NULL, 10);

	return (hidden) ? 2 : 1;
}

long get_wlanSecEncryption(int index)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long encrypt = 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_ENCRYPT");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_ENCRYPT");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_ENCRYPT");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_ENCRYPT");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_ENCRYPT");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_ENCRYPT");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_ENCRYPT");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "0");
	encrypt = strtol(value, NULL, 10);

	switch (encrypt) {
		case 0:						/* open */
			encrypt = 1;
			break;
		case 1:						/* wep */
			encrypt = 2;
			break;
		case 2:						/* wpa */
			encrypt = 3;
			break;
		case 4:						/* wpa2 */
			encrypt = 4;
			break;
		case 6:						/* wpa-mixed */
			encrypt = 5;
			break;
		default:
			break;
	}

	return encrypt;
}

long get_wlanRateLimit(int index)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long rateLimit = 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "x_wlan1_ratelimit");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "x_wlan1_vap0_ratelimit");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "x_wlan1_vap1_ratelimit");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "x_wlan1_vap2_ratelimit");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "x_wlan0_ratelimit");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "x_wlan0_vap0_ratelimit");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "x_wlan0_vap1_ratelimit");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "0");
	rateLimit = strtol(value, NULL, 10);

	return rateLimit / (10 * 1024);
}

int set_wlanSSID(int index, unsigned char *var_val, int val_len)
{
	char query[32] = {0,};
	int pass = 0;

	if (val_len == 0)
		return 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_SSID");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_SSID");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_SSID");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_SSID");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_SSID");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_SSID");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_SSID");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	nvram_set(query, (char *)var_val);
	return 1;
}

int set_wlanSSIDMode(int index, int mode)
{
	char query[32] = {0,};
	char value[4] = {0,};
	int pass = 0;

	if (mode != 1 && mode != 2)	/* enable : 1 disable : 2 */
		return 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WLAN_DISABLED");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WLAN_DISABLED");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WLAN_DISABLED");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WLAN_DISABLED");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WLAN_DISABLED");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WLAN_DISABLED");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WLAN_DISABLED");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%d", (mode == 1)? 0 : 1);
	nvram_set(query, value);

	return 1;
}

int set_wlanBSSID(int index, int bcast)
{
	char query[32] = {0,};
	char value[4] = {0,};
	int pass = 0;

	if (bcast != 1 && bcast != 2)
		return 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_HIDDEN_SSID");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_HIDDEN_SSID");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_HIDDEN_SSID");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_HIDDEN_SSID");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_HIDDEN_SSID");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_HIDDEN_SSID");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_HIDDEN_SSID");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%d", (bcast == 1)? 0 : 1);
	nvram_set(query, value);

	return 1;
}

int set_wlanSecEncryption(int index, int encrypt)
{
	char query[32] = {0,};
	char value[4] = {0,};
	int pass = 0;

	if (encrypt < 1 || encrypt > 5)
		return 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_ENCRYPT");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_ENCRYPT");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_ENCRYPT");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_ENCRYPT");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_ENCRYPT");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_ENCRYPT");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_ENCRYPT");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	switch (encrypt) {
		case 1:						/* open */
			encrypt = 0;
			break;
		case 2:						/* wep */
			encrypt = 1;
			break;
		case 3:						/* wpa */
			encrypt = 2;
			break;
		case 4:						/* wpa2 */
			encrypt = 4;
			break;
		case 5:						/* wpa-mixed */
			encrypt = 6;
			break;
		default:
			break;
	}

	snprintf(value, sizeof(value), "%d", encrypt);
	nvram_set(query, value);

	return 1;
}

int set_wlanRateLimit(int index, int rateLimit)
{
	char query[32] = {0,};
	char value[12] = {0,};
	int pass = 0;
	int mbps = 0;

	if (rateLimit < 0 || rateLimit > 10)
		return 0;

	mbps = 	rateLimit * 10 * 1024;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "x_wlan1_ratelimit");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "x_wlan1_vap0_ratelimit");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "x_wlan1_vap1_ratelimit");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "x_wlan1_vap2_ratelimit");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "x_wlan0_ratelimit");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "x_wlan0_vap0_ratelimit");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "x_wlan0_vap1_ratelimit");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%d", mbps);
	nvram_set(query, value);

	return 1;
}
/* ======================= WLAN SSID CONFIG ================================= */

/* ======================= SITE SURVEY INFO ================================= */
int surveyRequest(int wlan_idx)
{
	int wait_time = 0;
	int status;
	char intf[12] = {0,};
	unsigned char res;

	snprintf(intf, sizeof(intf), "wlan%d", wlan_idx);
	while (1) {
		// ==== modified by GANTOE for site survey 2008/12/26 ====
		switch(getWlSiteSurveyRequest(intf, &status)) {
			case -2:
				printf("survey progress...\n");
				break;
			case -1:
				printf("1.surbey fail\n");
				break;
			default:
				break;
		}

		if (status != 0) {	// not ready
			if (wait_time++ > 15) {
				printf("2.surbey fail\n");
				return -1;
			}
			sleep(1);
		} else
			break;
	}

	// wait until scan completely
	wait_time = 0;
	while (1) {
		res = 1;	// only request request status
		if ( getWlSiteSurveyResult(intf, (SS_STATUS_Tp)&res) < 0 ) {
				printf("3.surbey fail\n");
				return -1;
			}
			if (res == 0xff) {   // in progress
				if (wait_time++ > 20)
				{
					printf("4.surbey fail\n");
					return -1;
				}
				sleep(1);
			}
			else
				break;
		}

	return 0;
}

int getWlanScanInfo(int wlan_idx)
{
	SS_STATUS_T ssinfo;
	BssDscr *pBss;
	int i;
	char intf[12] = {0,};

    memset(&adjacent_channel[0], 0, sizeof(adjacent_channel));
    memset(&best_channel[0], 0, sizeof(best_channel));
    memset(&ssinfo, 0, sizeof(ssinfo));

    snprintf(intf, sizeof(intf), "wlan%d", wlan_idx);

	ssinfo.number = 0; // request BSS DB
	if ( getWlSiteSurveyResult(intf, &ssinfo) < 0 ) {
		return -1;
	}

	for (i = 0; i < ssinfo.number && ssinfo.number != 0xff; i++) {
		pBss = &ssinfo.bssdb[i];
		adjacent_channel[(pBss->ChannelNumber)-1]++;
		if (CONV_TO_RSSI(pBss->rssi) > -80)
			best_channel[(pBss->ChannelNumber)-1]++;
	}

    return (i == 0) ? -1 : 13;
}

long get_BestChannelAlgorithm(void)
{
	return best_chan;
}

int set_BestChannelAlgorithm(int wlan_idx, int set_type)
{
	int chan_score[CJHV_MAX_CHAN_NUM] = {0,};
	int sel_auto_ch[14] = {0,};
	int scan_num;
	int around_score = 0;
	char query[32] = {0,}, value[40] = {0,};
	unsigned int g_use_bonding = (get_wlanChannelWidth(wlan_idx) - 1);
	unsigned int g_L_admin = 6;
	char *argv[20] = {NULL,};
	int i, j, argc;
	FILE *fp = NULL;

	if (set_type != 1 && set_type != 2)
		return 0;

    if (get_wlanMode(WLAN_2G) == 1) {
		if (surveyRequest(WLAN_2G) < 0)
			return 0;
	}

	fp = fopen("/proc/dv_wlan1/auto_ch_info", "r");
	if (fp) {
		fgets(value, sizeof(value), fp);
		argc = sep_token(value, argv, " \n");
		for (i = 0; i < argc; i++) {
			if (argv[i][0] == '0') {
				sel_auto_ch[0] = 1;
			} else {
				j = simple_strtoul(argv[i], NULL, 10);
				if (j > 0 && j < 14) {
					sel_auto_ch[j] = 1;
				}
			}
		}
		fclose(fp);
	} else {
		return 0;
	}

	scan_num = getWlanScanInfo(WLAN_2G);
	if (scan_num == -1) {
		return 0;
	}

	best_chan = calculate_best_chan(&sel_auto_ch[0], &best_channel[0], &chan_score[0], CJHV_END_CHAN);
	printf("DVLOG_Select best channel %d \n", best_chan);

	snprintf(query, sizeof(query), "WLAN%d_CHANNEL_BONDING", wlan_idx);
	nvram_get_r_def(query, value, sizeof(value), "0");

	if (value[0] == '7') {		// auto
		g_use_bonding = HT_CHANNEL_WIDTH_20;
		around_score = calculate_around_score(best_chan, &best_channel[0]);
		if ( around_score < g_L_admin)
			g_use_bonding = HT_CHANNEL_WIDTH_20_40;

		printf("DVLOG_Running channel %d, bandwidth %dMhz(Ax(%d) < L_admin(%d))\n",
				best_chan, ((g_use_bonding)? 40: 20), around_score, g_L_admin);
	}

	if (set_type == 2) {	/* set bsetchan */
		if (value[0] == '7') {		// auto
			snprintf(value, sizeof(value), "%d", g_use_bonding);
			snprintf(query, sizeof(query), "WLAN%d_CHANNEL_BONDING", wlan_idx);
			nvram_set(query, value);
		}
		snprintf(value, sizeof(value), "%d", best_chan);
		snprintf(query, sizeof(query), "WLAN%d_CHANNEL", wlan_idx);
		nvram_set(query, value);
	}

	return 1;
}
/* ======================= SITE SURVEY INFO ================================= */

/* ======================= WLAN ADVANCE CONFIG ================================= */
long get_wlanFragmentThreshold(int wlan_idx)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long fragment = 0;

	snprintf(query, sizeof(query), "WLAN%d_FRAG_THRESHOLD", wlan_idx);
	nvram_get_r_def(query, value, sizeof(value), "2346");

	fragment = strtol(value, NULL, 10);

	return fragment;
}

int set_wlanFragmentThreshold(int wlan_idx, int fragment)
{
	char query[32] = {0,};
	char value[12] = {0,};

	if (fragment < 256 || fragment > 2346)
		return 0;

	snprintf(query, sizeof(query), "WLAN%d_FRAG_THRESHOLD", wlan_idx);
	snprintf(value, sizeof(value), "%d", fragment);

	nvram_set(query, value);

	return 1;
}

long get_wlanRTSThreshold(int wlan_idx)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long rts = 0;

	snprintf(query, sizeof(query), "WLAN%d_RTS_THRESHOLD", wlan_idx);
	nvram_get_r_def(query, value, sizeof(value), "2347");

	rts = strtol(value, NULL, 10);

	return rts;
}

int set_wlanRTSThreshold(int wlan_idx, int rts)
{
	char query[32] = {0,};
	char value[12] = {0,};

	if (rts < 0 || rts > 2347)
		return 0;

	snprintf(query, sizeof(query), "WLAN%d_RTS_THRESHOLD", wlan_idx);
	snprintf(value, sizeof(value), "%d", rts);

	nvram_set(query, value);

	return 1;
}

long get_wlanBeaconInterval(int wlan_idx)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long interval = 0;

	snprintf(query, sizeof(query), "WLAN%d_BEACON_INTERVAL", wlan_idx);
	nvram_get_r_def(query, value, sizeof(value), "100");

	interval = strtol(value, NULL, 10);

	return interval;
}

int set_wlanBeaconInterval(int wlan_idx, int interval)
{
	char query[32] = {0,};
	char value[12] = {0,};

	if (interval < 20 || interval > 1024)
		return 0;

	snprintf(query, sizeof(query), "WLAN%d_BEACON_INTERVAL", wlan_idx);
	snprintf(value, sizeof(value), "%d", interval);

	nvram_set(query, value);

	return 1;

}

long get_wlanPreambleType(int wlan_idx)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long preamble = 0;

	snprintf(query, sizeof(query), "WLAN%d_PREAMBLE_TYPE", wlan_idx);
	nvram_get_r_def(query, value, sizeof(value), "0");

	preamble = strtol(value, NULL, 10);

	return preamble + 1;
}

int set_wlanPreambleType(int wlan_idx, int preamble)
{
	char query[32] = {0,};
	char value[12] = {0,};

	snprintf(query, sizeof(query), "WLAN%d_PREAMBLE_TYPE", wlan_idx);

	switch (preamble) {
	case 1:
		snprintf(value, sizeof(value), "%d", preamble - 1);
		break;
	case 2:
		snprintf(value, sizeof(value), "%d", preamble - 1);
		break;
	default:
		return 0;
	}

	nvram_set(query, value);

	return 1;
}

int get_wlanRFOutputPower(int wlan_idx)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long power = 0;

	snprintf(query, sizeof(query), "WLAN%d_RFPOWER_SCALE", wlan_idx);
	nvram_get_r_def(query, value, sizeof(value), "0");

	power = strtol(value, NULL, 10);

	return power + 1;
}

int set_wlanRFOutputPower(int wlan_idx, int power)
{
	char query[32] = {0,};
	char value[12] = {0,};

	snprintf(query, sizeof(query), "WLAN%d_RFPOWER_SCALE", wlan_idx);
	switch (power) {
		case 1:
			snprintf(value, sizeof(value), "%d", power - 1);
			break;
		case 2:
			snprintf(value, sizeof(value), "%d", power - 1);
			break;
		case 3:
			snprintf(value, sizeof(value), "%d", power - 1);
			break;
		case 4:
			snprintf(value, sizeof(value), "%d", power - 1);
			break;
		case 5:
			snprintf(value, sizeof(value), "%d", power - 1);
			break;
		default:
			return 0;
	}

	nvram_set(query, value);
	return 1;
}
/* ======================= WLAN ADVANCE CONFIG ================================= */

/* ======================= CLIENT INFO ================================= */
void get_wlanCrcStats(char *interface, unsigned long *crc)
{
	char fileName[64], buf[64], tmp[32];
	FILE *fp;
	unsigned int find = 0, count = 0;

	snprintf(fileName, sizeof(fileName), "/proc/%s/stats", interface);

	fp = fopen(fileName, "r");
	if (fp == NULL) {
		*crc = 0;
		return;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		if (strstr(buf, "rx_crc_errors:")) {
			if (sscanf(buf, "%s %u", tmp, &count) == 2)
				find++;
		}
		if (find)
			break;
	}
	fclose(fp);

	*crc = count;
}

int getOneDhcpClient(char **ppStart, off_t *size, char *ip, int len, unsigned char *macaddr)
{
	struct dhcpOfferedAddr {
		u_int8_t chaddr[16];
		u_int32_t yiaddr;	/* network order */
		u_int32_t expires;	/* host order */
		char hostname[64];
		int VoIP_Device;	/* wifi phone check */
	};
	struct dhcpOfferedAddr entry;
	u_int8_t empty_haddr[16];

	memset(empty_haddr, 0, 16);
	if (*size < sizeof(entry))
		return -1;

	entry = *((struct dhcpOfferedAddr *)*ppStart);
	*ppStart = *ppStart + sizeof(entry);
	*size = *size - sizeof(entry);
	if (entry.expires == 0)
		return 0;

	if (!memcmp(entry.chaddr, empty_haddr, 16)) {
		return 0;
	}

	inet_ntop(AF_INET, &entry.yiaddr, ip, len);
	if (!memcmp(macaddr, entry.chaddr, 6))
		return 2;

	return 1;
}

void get_staIpaddr(unsigned char *macAddr, unsigned long *ipaddr)
{
	FILE *fp;
	int ret;
	char ip_addr[24], *buf = NULL, *ptr;
	struct stat status;
	int pid;
	char tmpBuf[24];

	*ipaddr = 0;

	snprintf(tmpBuf, sizeof(tmpBuf), "%s/%s.pid", _DHCPD_PID_PATH, _DHCPD_PROG_NAME);
	pid = getPid(tmpBuf);

	if (pid > 0)
		kill(pid, SIGUSR1);
	usleep(500000);

	if (stat(_PATH_DHCPS_LEASES, &status) < 0)
		return;

	buf = malloc(status.st_size);
	if (buf == NULL)
		return;

	fp = fopen(_PATH_DHCPS_LEASES, "r");
	if (fp == NULL)
		return;

	fread(buf, 1, status.st_size, fp);
	fclose(fp);

	ptr = buf;

	while (1) {
		ret = getOneDhcpClient(&ptr, &status.st_size, ip_addr, sizeof(ip_addr), macAddr);
		if (ret < 0)
			break;
		if (ret == 0)
			continue;
		if (ret == 2) {
			*ipaddr =  inet_addr(ip_addr);
			break;
		}
	}
}

void find_StaArptable(unsigned char *macAddr, unsigned long *ipaddr)
{
	FILE *fp = NULL;
	char line[128] = {0,};
	char *args[6] = {NULL,};
	int n = 0;
	char hostMac[24] = {0,};

	snprintf(hostMac, sizeof(hostMac), "%02x:%02x:%02x:%02x:%02x:%02x",
										macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);

	fp = fopen("/proc/net/arp", "r");
	if (fp) {
		while (fgets(line, sizeof(line), fp)) {
			n = ystrargs(line, args, _countof(args), " \n", 0);
			if (n > 5) {
				if (strcmp(args[3], hostMac) == 0) {
					*ipaddr = inet_addr(args[0]);
					break;
				}
			}
		}

	}
}

int wirelessClientList(int wlan_idx, int found)
{
	int i, j;
	WLAN_STA_INFO_Tp pInfo;
	char *buff;
	char intf[12] = {0,};
	int max_ssid = (wlan_idx == WLAN_2G)? 4 : 3;
	char query[32] = {0,};
	char value[12] = {0,};
	char ssid[64] = {0,};
	int disabled = 0;
	int num = 0;

	buff = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM + 1));
	if ( buff == 0 ) {
		printf("Allocate buffer failed!\n");
		return 0;
	}

	// 1.CJHV070 -> 2.KCT070 -> 3.CJWIFI -> 4.GUEST
	for (i = 0; i < max_ssid; i++) {
		if (wlan_idx == WLAN_2G) {	/* 2.4G */
			if (i == 0)				/* CJHV070 */
				snprintf(query, sizeof(query), "WLAN%d_VAP0_WLAN_DISABLED", wlan_idx);
			else if (i == 1)		/* KCT070 */
				snprintf(query, sizeof(query), "WLAN%d_VAP1_WLAN_DISABLED", wlan_idx);
			else if (i == 2)		/* CJWIFI */
				snprintf(query, sizeof(query), "WLAN%d_WLAN_DISABLED", wlan_idx);
			else					/* GUEST */
				snprintf(query, sizeof(query), "WLAN%d_VAP2_WLAN_DISABLED", wlan_idx);
		} else {					/* 5G */
			if (i == 0)				/* 5G_CJHV070 */
				snprintf(query, sizeof(query), "WLAN%d_VAP0_WLAN_DISABLED", wlan_idx);
			else if (i == 1)		/* 5G_CJWIFI */
				snprintf(query, sizeof(query), "WLAN%d_WLAN_DISABLED", wlan_idx);
			else					/* 5G_GUEST */
				snprintf(query, sizeof(query), "WLAN%d_VAP1_WLAN_DISABLED", wlan_idx);
		}

		nvram_get_r_def(query, value, sizeof(value), "0");
		disabled = strtol(value, NULL, 10);

		if (disabled)
			continue;

		if (wlan_idx == WLAN_2G) {	/* 2.4G */
			if (i == 0)	{			/* CJHV070 */
				snprintf(intf, sizeof(intf), "wlan%d-va0", wlan_idx);
				snprintf(query, sizeof(query), "WLAN%d_VAP0_SSID", wlan_idx);
			} else if (i == 1) {	/* KCT070 */
				snprintf(intf, sizeof(intf), "wlan%d-va1", wlan_idx);
				snprintf(query, sizeof(query), "WLAN%d_VAP1_SSID", wlan_idx);
			} else if (i == 2) {	/* CJWIFI */
				snprintf(intf, sizeof(intf), "wlan%d", wlan_idx);
				snprintf(query, sizeof(query), "WLAN%d_SSID", wlan_idx);
			} else {				/* GUEST */
				snprintf(intf, sizeof(intf), "wlan%d-va2", wlan_idx);
				snprintf(query, sizeof(query), "WLAN%d_VAP2_SSID", wlan_idx);
			}
		} else {					/* 5G */
			if (i == 0) {			/* 5G_CJHV070 */
				snprintf(intf, sizeof(intf), "wlan%d-va0", wlan_idx);
				snprintf(query, sizeof(query), "WLAN%d_VAP0_SSID", wlan_idx);
			} else if (i == 1) {	/* 5G_CJWIFI */
				snprintf(intf, sizeof(intf), "wlan%d", wlan_idx);
				snprintf(query, sizeof(query), "WLAN%d_SSID", wlan_idx);
			} else {				/* 5G_GUEST */
				snprintf(intf, sizeof(intf), "wlan%d-va1", wlan_idx);
				snprintf(query, sizeof(query), "WLAN%d_VAP1_SSID", wlan_idx);
			}
		}

		if ( getWlStaInfo(intf, (WLAN_STA_INFO_Tp)buff ) < 0 ) {
			printf("Read wlan sta info failed!\n");
			continue;
		}

		nvram_get_r_def(query, ssid, sizeof(ssid), "");

		for (j = 1; j <= MAX_STA_NUM; j++) {
			pInfo = (WLAN_STA_INFO_Tp)&buff[j * sizeof(WLAN_STA_INFO_T)];
			if (pInfo->aid && (pInfo->flags & STA_INFO_FLAG_ASOC)) {
				staInfo[found].mode = pInfo->network;
				memcpy(staInfo[found].mac, pInfo->addr, 6);
				strcpy(staInfo[found].ssid, ssid);
				staInfo[found].rssi = pInfo->rssi;
				staInfo[found].bandwidth = get_wlanChannelWidth(wlan_idx);
				get_wlanCrcStats(intf, &staInfo[found].rx_crc);
				get_staIpaddr(staInfo[found].mac, &staInfo[found].ipaddress);
				if (staInfo[found].ipaddress == 0)
					find_StaArptable(staInfo[found].mac, &staInfo[found].ipaddress);
				staInfo[found].band_info = wlan_idx;
				found++;
				num++;
			}
		}
	}

	if(buff)
		free(buff);

	return num;
}

int is_local_port_fun(char *buf)
{
	char *ptr;
	int ptn;
	if( !(ptr = strstr(buf, "mbr(")) )
		return 0;
	if(ptr && strlen(ptr) > 4)
		ptr += 4;
	ydespaces(ptr);
	ptn = atoi(ptr);
	if( ( ptn > 0 )&&( ptn <= 4 )) {
		return 1;
	}
	return 0;
}

int initHostInfo(void)
{
	FILE *fp = NULL;
	char line[128];
	char *ptr1, *ptr2;
	int num = 0;
	int loc_port;
	int port;
	char *macString;

	memset(&hostInfo[0], 0, sizeof(hostInfo));

	fp = fopen("/proc/rtl865x/l2", "r");
	if (!fp) {
		return 0;
	}

	while (fgets(line, sizeof(line), fp)) {
		if ( ( ptr1 = strstr(line, "FWD DYN") ) && (loc_port = is_local_port_fun(line)) ) {
			if (ptr1) {
				ptr2 = strstr(line, "mbr(");
				macString = &line[13];
				macString[17] = 0;
				simple_ether_atoe(macString, hostInfo[num].mac);
				if (ptr2 && strlen(ptr2) > 4)
					ptr2 += 4;
				ydespaces(ptr2);
				port = atoi(ptr2);
				if ( port < PRTNR_LAN1 || port > PRTNR_LAN4)
            		continue;
				hostInfo[num].portNo = port;
				get_staIpaddr(hostInfo[num].mac, &hostInfo[num].ipaddress);
				if (hostInfo[num].ipaddress == 0)
					find_StaArptable(hostInfo[num].mac, &hostInfo[num].ipaddress);
				num++;
			}
		}
	}
	fclose(fp);

	return num;
}

void get_wlanStaMac(int idx, char *macAddr, int len)
{
	memset(macAddr, 0, len);
	memcpy((unsigned char *)macAddr, staInfo[idx].mac, 6);
}

void get_hostInfoMac(int idx, char *macAddr, int len)
{
	memset(macAddr, 0, len);
	memcpy((unsigned char *)macAddr, hostInfo[idx].mac, 6);
}

void get_wlanStaipaddr(int idx, unsigned long *ipaddr)
{
	*ipaddr = staInfo[idx].ipaddress;
}

void get_hostInfoipAddr(int idx, unsigned long *ipaddr)
{
	*ipaddr = hostInfo[idx].ipaddress;
}

void get_wlanStaName(int idx, char *name, int len)
{
	memset(name, 0, len);
	snprintf(name, len,  "%s", staInfo[idx].ssid);
}

void get_hostInfoName(int idx, char *name, int len)
{
	char *portName[5] = { "WAN", "LAN1", "LAN2", "LAN3", "LAN4" };

	memset(name, 0, len);
	snprintf(name, len,  "%s", portName[hostInfo[idx].portNo]);
}

void get_wlanStaMode(int idx, long *band)
{
	if (staInfo[idx].mode & BAND_11N)
		*band = (staInfo[idx].band_info == WLAN_2G) ? 3 : 6;
	else if (staInfo[idx].mode & BAND_11G)
		*band = 2;
	else if (staInfo[idx].mode & BAND_11B)
		*band = 1;
	else if (staInfo[idx].mode & BAND_11A)
		*band = 4;
	else
		*band = 0;
}

void get_wlanStaBand(int idx, long *bandwidth)
{
	*bandwidth = staInfo[idx].bandwidth;
}

void get_wlanStaRssi(int idx , char *rssi, int len)
{
	memset(rssi, 0, len);
	snprintf(rssi, len, "%d", CONV_TO_RSSI(staInfo[idx].rssi));
}

void get_hostInfoCrc(int idx, unsigned long *crc)
{
	*crc = get_portStatusCrc(hostInfo[idx].portNo);
}
/* ======================= CLIENT INFO ================================= */

/* ======================= WEP SECURITY INFO ================================= */
long get_secWEP8021xAuthMode(int index)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long auth = 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_ENABLE_1X");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_ENABLE_1X");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_ENABLE_1X");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_ENABLE_1X");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_ENABLE_1X");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_ENABLE_1X");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_ENABLE_1X");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "0");
	auth = strtol(value, NULL, 10);

	return (auth) ? 1 : 2;
}

int set_secWEP8021xAuthMode(int index, int auth)
{
	char query[32] = {0,};
	char value[12] = {0,};
	int pass = 0;

	if (auth != 1 && auth != 2)
		return 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_ENABLE_1X");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_ENABLE_1X");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_ENABLE_1X");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_ENABLE_1X");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_ENABLE_1X");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_ENABLE_1X");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_ENABLE_1X");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%d", (auth == 2)? 0 : 1);
	nvram_set(query, value);

	return 1;
}

long get_secWEPMacAuthMode(int index)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long macAuth = 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_MAC_AUTH_ENABLED");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_MAC_AUTH_ENABLED");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_MAC_AUTH_ENABLED");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_MAC_AUTH_ENABLED");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_MAC_AUTH_ENABLED");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_MAC_AUTH_ENABLED");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_MAC_AUTH_ENABLED");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "0");
	macAuth = strtol(value, NULL, 10);

	return (macAuth) ? 1 : 2;
}

int set_secWEPMacAuthMode(int index, int macAuth)
{
	char query[32] = {0,};
	char value[12] = {0,};
	int pass = 0;

	if (macAuth != 1 && macAuth != 2)
		return 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_MAC_AUTH_ENABLED");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_MAC_AUTH_ENABLED");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_MAC_AUTH_ENABLED");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_MAC_AUTH_ENABLED");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_MAC_AUTH_ENABLED");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_MAC_AUTH_ENABLED");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_MAC_AUTH_ENABLED");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%d", (macAuth == 2)? 0 : 1);
	nvram_set(query, value);

	return 1;
}

long get_secWEPAuthMethod(int index)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long authType = 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_AUTH_TYPE");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_AUTH_TYPE");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_AUTH_TYPE");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_AUTH_TYPE");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_AUTH_TYPE");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_AUTH_TYPE");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_AUTH_TYPE");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "2");
	authType = strtol(value, NULL, 10);

	return authType + 1;
}

int set_secWEPAuthMethod(int index, int method)
{
	char query[32] = {0,};
	char value[12] = {0,};
	int pass = 0;

	if (method != 1 && method != 2 && method != 3)
		return 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_AUTH_TYPE");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_AUTH_TYPE");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_AUTH_TYPE");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_AUTH_TYPE");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_AUTH_TYPE");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_AUTH_TYPE");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_AUTH_TYPE");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%d", (method - 1));
	nvram_set(query, value);

	return 1;
}

long get_secWEPKeySize(int index)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long keySize = 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WEP");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WEP");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WEP");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WEP");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WEP");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WEP");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WEP");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "1");
	keySize = strtol(value, NULL, 10);

	return keySize;
}

int set_secWEPKeySize(int index, int keySize)
{
	char query[32] = {0,};
	char value[12] = {0,};
	int pass = 0;

	if (keySize != 1 && keySize != 2)
		return 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WEP");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WEP");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WEP");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WEP");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WEP");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WEP");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WEP");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%d", keySize);
	nvram_set(query, value);

	return keySize;
}

long get_secWEPKeyFormat(int index)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long format = 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WEP_KEY_TYPE");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WEP_KEY_TYPE");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WEP_KEY_TYPE");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WEP_KEY_TYPE");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WEP_KEY_TYPE");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WEP_KEY_TYPE");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WEP_KEY_TYPE");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "1");
	format = strtol(value, NULL, 10);

	return format + 1;
}

int set_secWEPKeyFormat(int index, int format)
{
	char query[32] = {0,};
	char value[12] = {0,};
	int pass = 0;

	if (format != 1 && format != 2)
		return 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WEP_KEY_TYPE");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WEP_KEY_TYPE");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WEP_KEY_TYPE");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WEP_KEY_TYPE");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WEP_KEY_TYPE");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WEP_KEY_TYPE");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WEP_KEY_TYPE");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%d", format - 1);
	nvram_set(query, value);

	return 1;
}

void get_secWEPEncryptionKey(int index, char *str, int len)
{
	char query[32] = {0,};
	char value[64] = {0,};
	char encryptionKey[64] = {0,};
	long keyIndex = 0, keySize = 0, keyformat = 0;
	int pass = 0, keyLength = 0;

	keyIndex = get_secWEPKeyIndex(index);
	keySize = get_secWEPKeySize(index);
	keyformat = get_secWEPKeyFormat(index);

	memset(str, 0, len);

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			if (keySize == 2)		/* 128 bit */
				snprintf(query, sizeof(query), "WLAN1_WEP128_KEY%ld", keyIndex);
			else					/* 64 bit */
				snprintf(query, sizeof(query), "WLAN1_WEP64_KEY%ld", keyIndex);
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			if (keySize == 2)		/* 128 bit */
				snprintf(query, sizeof(query), "WLAN1_VAP0_WEP128_KEY%ld", keyIndex);
			else					/* 64 bit */
				snprintf(query, sizeof(query), "WLAN1_VAP0_WEP64_KEY%ld", keyIndex);
			break;
		case 3:						/* KCT070VOIP */
			if (keySize == 2)		/* 128 bit */
				snprintf(query, sizeof(query), "WLAN1_VAP1_WEP128_KEY%ld", keyIndex);
			else					/* 64 bit */
				snprintf(query, sizeof(query), "WLAN1_VAP1_WEP64_KEY%ld", keyIndex);
			break;
		case 4:						/* Guest SSID */
			if (keySize == 2)		/* 128 bit */
				snprintf(query, sizeof(query), "WLAN1_VAP2_WEP128_KEY%ld", keyIndex);
			else					/* 64 bit */
				snprintf(query, sizeof(query), "WLAN1_VAP2_WEP64_KEY%ld", keyIndex);
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			if (keySize == 2)		/* 128 bit */
				snprintf(query, sizeof(query), "WLAN0_WEP128_KEY%ld", keyIndex);
			else					/* 64 bit */
				snprintf(query, sizeof(query), "WLAN0_WEP64_KEY%ld", keyIndex);
			break;
		case 6:						/* 5G_CJHV070VOIP */
			if (keySize == 2)		/* 128 bit */
				snprintf(query, sizeof(query), "WLAN0_VAP0_WEP128_KEY%ld", keyIndex);
			else					/* 64 bit */
				snprintf(query, sizeof(query), "WLAN0_VAP0_WEP64_KEY%ld", keyIndex);
			break;
		case 7:						/* 5G_Guest SSID */
			if (keySize == 2)		/* 128 bit */
				snprintf(query, sizeof(query), "WLAN0_VAP1_WEP128_KEY%ld", keyIndex);
			else					/* 64 bit */
				snprintf(query, sizeof(query), "WLAN0_VAP1_WEP64_KEY%ld", keyIndex);
			break;
		default:
			break;
	}

	if (pass)
		return;

	nvram_get_r_def(query, value, sizeof(value), "0");

	keyLength = (keySize == 2) ? 26 : 10;
	if (keyformat == 1) /* ascii */
		hex_to_string(value, (unsigned char *)encryptionKey, keyLength);
	else
		strncpy(encryptionKey, value, keyLength);

	snprintf(str, len, "%s", encryptionKey);
}

int set_secWEPEncryptionKey(int index, char *password, int len)
{
	char query[32] = {0,};
	char value[64] = {0,};
	char encryptionKey[64] = {0,};
	char key[32] = {0,};
	long keyIndex = 0, keySize = 0, keyformat = 0;
	int pass = 0, keyLength = 0;

	keyIndex = get_secWEPKeyIndex(index);
	keySize = get_secWEPKeySize(index);
	keyformat = get_secWEPKeyFormat(index);

	if (len == 0)
		return 0;

	if (keySize == 1) {
		if (keyformat == 1) {
			if (len == 5)
				strcpy(encryptionKey, password);
			else if (len == 10 && hex_to_string(password, (unsigned char *)value, 10))
				strcpy(encryptionKey, value);
			else
				return 0;
		} else {
			if (len == 5)
				string_to_hex(password, encryptionKey, 5);
			else if (len == 10 && hex_to_string(password, (unsigned char *)value, 10))
				strcpy(encryptionKey, password);
			else
				return 0;
		}
	} else {
		if (keyformat == 1) {
			if (len == 13)
				strcpy(encryptionKey, password);
			else if (len == 26 && hex_to_string(password, (unsigned char *)value, 26))
				strcpy(encryptionKey, value);
			else
				return 0;
		} else {
			if (len == 13)
				string_to_hex(password, encryptionKey, 13);
			else if (len == 26 && hex_to_string(password, (unsigned char *)value, 26))
				strcpy(encryptionKey, password);
			else
				return 0;
		}
	}

	if (keySize == 2) {
		keyLength = 26;
		if (keyformat == 1)
			string_to_hex(encryptionKey, key, keyLength / 2);
		else
			strncpy(key, encryptionKey, keyLength);
	} else {
		keyLength = 10;
		if (keyformat == 1)
			string_to_hex(encryptionKey, key, keyLength / 2);
		else
			strncpy(key, encryptionKey, keyLength);
	}

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			if (keySize == 2)		/* 128 bit */
				snprintf(query, sizeof(query), "WLAN1_WEP128_KEY%ld", keyIndex);
			else					/* 64 bit */
				snprintf(query, sizeof(query), "WLAN1_WEP64_KEY%ld", keyIndex);
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			if (keySize == 2)		/* 128 bit */
				snprintf(query, sizeof(query), "WLAN1_VAP0_WEP128_KEY%ld", keyIndex);
			else					/* 64 bit */
				snprintf(query, sizeof(query), "WLAN1_VAP0_WEP64_KEY%ld", keyIndex);
			break;
		case 3:						/* KCT070VOIP */
			if (keySize == 2)		/* 128 bit */
				snprintf(query, sizeof(query), "WLAN1_VAP1_WEP128_KEY%ld", keyIndex);
			else					/* 64 bit */
				snprintf(query, sizeof(query), "WLAN1_VAP1_WEP64_KEY%ld", keyIndex);
			break;
		case 4:						/* Guest SSID */
			if (keySize == 2)		/* 128 bit */
				snprintf(query, sizeof(query), "WLAN1_VAP2_WEP128_KEY%ld", keyIndex);
			else					/* 64 bit */
				snprintf(query, sizeof(query), "WLAN1_VAP2_WEP64_KEY%ld", keyIndex);
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			if (keySize == 2)		/* 128 bit */
				snprintf(query, sizeof(query), "WLAN0_WEP128_KEY%ld", keyIndex);
			else					/* 64 bit */
				snprintf(query, sizeof(query), "WLAN0_WEP64_KEY%ld", keyIndex);
			break;
		case 6:						/* 5G_CJHV070VOIP */
			if (keySize == 2)		/* 128 bit */
				snprintf(query, sizeof(query), "WLAN0_VAP0_WEP128_KEY%ld", keyIndex);
			else					/* 64 bit */
				snprintf(query, sizeof(query), "WLAN0_VAP0_WEP64_KEY%ld", keyIndex);
			break;
		case 7:						/* 5G_Guest SSID */
			if (keySize == 2)		/* 128 bit */
				snprintf(query, sizeof(query), "WLAN0_VAP1_WEP128_KEY%ld", keyIndex);
			else					/* 64 bit */
				snprintf(query, sizeof(query), "WLAN0_VAP1_WEP64_KEY%ld", keyIndex);
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	nvram_set(query, key);
	printf("%s %s\n", query, key);

	return 1;
}

long get_secWEPKeyIndex(int index)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long keyIndex = 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WEP_DEFAULT_KEY");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WEP_DEFAULT_KEY");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WEP_DEFAULT_KEY");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WEP_DEFAULT_KEY");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WEP_DEFAULT_KEY");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WEP_DEFAULT_KEY");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WEP_DEFAULT_KEY");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "0");
	keyIndex = strtol(value, NULL, 10);

	return keyIndex + 1;
}

int set_secWEPKeyIndex(int index, int keyIndex)
{
	char query[32] = {0,};
	char value[12] = {0,};
	int pass = 0;

	if (keyIndex < 1 ||  keyIndex > 4)
		return 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WEP_DEFAULT_KEY");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WEP_DEFAULT_KEY");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WEP_DEFAULT_KEY");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WEP_DEFAULT_KEY");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WEP_DEFAULT_KEY");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WEP_DEFAULT_KEY");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WEP_DEFAULT_KEY");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%d", keyIndex - 1);
	nvram_set(query, value);

	return 1;
}
/* ======================= WEP SECURITY INFO ================================= */

/* ======================= WPA SECURITY INFO ================================= */
long get_secWPAxAuthMode(int index)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long authMode = 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WPA_AUTH");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WPA_AUTH");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WPA_AUTH");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WPA_AUTH");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WPA_AUTH");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WPA_AUTH");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WPA_AUTH");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "2");
	authMode = strtol(value, NULL, 10);

	return (authMode == 1) ? 1 : 2;
}

int set_secWPAxAuthMode(int index, int authMode)
{
	char query[32] = {0,};
	char value[12] = {0,};
	int pass = 0;

	if (authMode != 1 && authMode != 2)
		return 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WPA_AUTH");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WPA_AUTH");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WPA_AUTH");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WPA_AUTH");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WPA_AUTH");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WPA_AUTH");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WPA_AUTH");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%d", authMode);
	nvram_set(query, value);

	return 1;
}

long get_secWPAxCipherSuite(int index)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long Encryption = 0, Suite = 0;

	Encryption = get_wlanSecEncryption(index);

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "%s", (Encryption == 3) ? "WLAN1_WPA_CIPHER_SUITE" : "WLAN1_WPA2_CIPHER_SUITE");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "%s", (Encryption == 3) ? "WLAN1_VAP0_WPA_CIPHER_SUITE" : "WLAN1_VAP0_WPA2_CIPHER_SUITE");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "%s", (Encryption == 3) ? "WLAN1_VAP1_WPA_CIPHER_SUITE" : "WLAN1_VAP1_WPA2_CIPHER_SUITE");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "%s", (Encryption == 3) ? "WLAN1_VAP2_WPA_CIPHER_SUITE" : "WLAN1_VAP2_WPA2_CIPHER_SUITE");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "%s", (Encryption == 3) ? "WLAN0_WPA_CIPHER_SUITE" : "WLAN0_WPA2_CIPHER_SUITE");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "%s", (Encryption == 3) ? "WLAN0_VAP0_WPA_CIPHER_SUITE" : "WLAN0_VAP0_WPA2_CIPHER_SUITE");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "%s", (Encryption == 3) ? "WLAN0_VAP1_WPA_CIPHER_SUITE" : "WLAN0_VAP1_WPA2_CIPHER_SUITE");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "3");
	Suite = strtol(value, NULL, 10);

	return Suite;
}

int set_secWPAxCipherSuite(int index, int Suite)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long Encryption = 0, pass = 0;

	Encryption = get_wlanSecEncryption(index);

	if (Suite < 0 || Suite > 3)
		return 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "%s", (Encryption == 3) ? "WLAN1_WPA_CIPHER_SUITE" : "WLAN1_WPA2_CIPHER_SUITE");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "%s", (Encryption == 3) ? "WLAN1_VAP0_WPA_CIPHER_SUITE" : "WLAN1_VAP0_WPA2_CIPHER_SUITE");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "%s", (Encryption == 3) ? "WLAN1_VAP1_WPA_CIPHER_SUITE" : "WLAN1_VAP1_WPA2_CIPHER_SUITE");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "%s", (Encryption == 3) ? "WLAN1_VAP2_WPA_CIPHER_SUITE" : "WLAN1_VAP2_WPA2_CIPHER_SUITE");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "%s", (Encryption == 3) ? "WLAN0_WPA_CIPHER_SUITE" : "WLAN0_WPA2_CIPHER_SUITE");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "%s", (Encryption == 3) ? "WLAN0_VAP0_WPA_CIPHER_SUITE" : "WLAN0_VAP0_WPA2_CIPHER_SUITE");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "%s", (Encryption == 3) ? "WLAN0_VAP1_WPA_CIPHER_SUITE" : "WLAN0_VAP1_WPA2_CIPHER_SUITE");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%d", Suite);
	nvram_set(query, value);

	return 1;
}

long get_secWPAxKeyFormat(int index)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long format = 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_PSK_FORMAT");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_PSK_FORMAT");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_PSK_FORMAT");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_PSK_FORMAT");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_PSK_FORMAT");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_PSK_FORMAT");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_PSK_FORMAT");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "0");
	format = strtol(value, NULL, 10);

	return format + 1;
}

int set_secWPAxKeyFormat(int index, int format)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long pass = 0;

	if (format != 1 && format != 2)
		return 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_PSK_FORMAT");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_PSK_FORMAT");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_PSK_FORMAT");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_PSK_FORMAT");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_PSK_FORMAT");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_PSK_FORMAT");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_PSK_FORMAT");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%d", format - 1);
	nvram_set(query, value);

	return 1;
}

void get_secWPAxPreSharedKey(int index, char *SharedKey, int len)
{
	char query[32] = {0,};
	char value[128] = {0,};

	memset(SharedKey, 0, len);

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WPA_PSK");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WPA_PSK");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WPA_PSK");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WPA_PSK");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WPA_PSK");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WPA_PSK");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WPA_PSK");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "");
	snprintf(SharedKey, len, "%s", value);
}

int set_secWPAxPreSharedKey(int index, char *SharedKey, int len)
{
	long format = 0;
	int pass = 0;
	char query[32] = {0,}, value[128] = {0,};
	unsigned char is_hexString[128] = {0,};

	format = get_secWPAxKeyFormat(index);

	if (format == 1) {
		if (len < 8 || len > 64)
			return 0;
	} else {
		if (len != 64 || !hex_to_string(SharedKey, is_hexString, 64))
			return 0;
	}

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WPA_PSK");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WPA_PSK");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WPA_PSK");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WPA_PSK");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WPA_PSK");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WPA_PSK");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WPA_PSK");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%s", SharedKey);
	nvram_set(query, value);

	return 1;
}
/* ======================= WPA SECURITY INFO ================================= */

/* ======================= WPA-Mixed SECURITY INFO ================================= */
long get_secWPAmixAuthMode(int index)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long authMode = 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WPA_AUTH");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WPA_AUTH");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WPA_AUTH");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WPA_AUTH");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WPA_AUTH");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WPA_AUTH");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WPA_AUTH");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "2");
	authMode = strtol(value, NULL, 10);

	return (authMode == 1) ? 1 : 2;
}

int set_secWPAmixAuthMode(int index, int authMode)
{
	char query[32] = {0,};
	char value[12] = {0,};
	int pass = 0;

	if (authMode != 1 && authMode != 2)
		return 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WPA_AUTH");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WPA_AUTH");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WPA_AUTH");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WPA_AUTH");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WPA_AUTH");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WPA_AUTH");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WPA_AUTH");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%d", authMode);
	nvram_set(query, value);

	return 1;
}

long get_secWPAmixCipherSuite(int index)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long Suite = 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WPA_CIPHER_SUITE");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WPA_CIPHER_SUITE");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WPA_CIPHER_SUITE");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WPA_CIPHER_SUITE");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WPA_CIPHER_SUITE");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WPA_CIPHER_SUITE");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WPA_CIPHER_SUITE");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "3");
	Suite = strtol(value, NULL, 10);

	return Suite;
}

int set_secWPAmixCipherSuite(int index, int Suite)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long pass = 0;

	if (Suite < 0 || Suite > 3)
		return 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WPA_CIPHER_SUITE");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WPA_CIPHER_SUITE");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WPA_CIPHER_SUITE");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WPA_CIPHER_SUITE");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WPA_CIPHER_SUITE");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WPA_CIPHER_SUITE");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WPA_CIPHER_SUITE");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%d", Suite);
	nvram_set(query, value);

	return 1;
}

long get_secWPAmix2CipherSuite(int index)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long Suite = 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WPA2_CIPHER_SUITE");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WPA2_CIPHER_SUITE");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WPA2_CIPHER_SUITE");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WPA2_CIPHER_SUITE");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WPA2_CIPHER_SUITE");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WPA2_CIPHER_SUITE");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WPA2_CIPHER_SUITE");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "3");
	Suite = strtol(value, NULL, 10);

	return Suite;
}

int set_secWPAmix2CipherSuite(int index, int Suite)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long pass = 0;

	if (Suite < 0 || Suite > 3)
		return 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WPA2_CIPHER_SUITE");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WPA2_CIPHER_SUITE");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WPA2_CIPHER_SUITE");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WPA2_CIPHER_SUITE");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WPA2_CIPHER_SUITE");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WPA2_CIPHER_SUITE");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WPA2_CIPHER_SUITE");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%d", Suite);
	nvram_set(query, value);

	return 1;
}

int get_secWPAmixKeyFormat(int index)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long format = 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_PSK_FORMAT");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_PSK_FORMAT");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_PSK_FORMAT");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_PSK_FORMAT");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_PSK_FORMAT");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_PSK_FORMAT");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_PSK_FORMAT");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "0");
	format = strtol(value, NULL, 10);

	return format + 1;;
}

int set_secWPAmixKeyFormat(int index, int format)
{
	char query[32] = {0,};
	char value[12] = {0,};
	long pass = 0;

	if (format != 1 && format != 2)
		return 0;

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_PSK_FORMAT");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_PSK_FORMAT");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_PSK_FORMAT");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_PSK_FORMAT");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_PSK_FORMAT");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_PSK_FORMAT");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_PSK_FORMAT");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%d", format - 1);
	nvram_set(query, value);

	return 1;
}

void get_secWPAmixPreSharedKey(int index, char *SharedKey, int len)
{
	char query[32] = {0,};
	char value[128] = {0,};

	memset(SharedKey, 0, len);

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WPA_PSK");
			break;
		case 1:						/* Hellowireless_ABCD */
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WPA_PSK");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WPA_PSK");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WPA_PSK");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WPA_PSK");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WPA_PSK");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WPA_PSK");
			break;
		default:
			break;
	}

	nvram_get_r_def(query, value, sizeof(value), "");
	snprintf(SharedKey, len, "%s", value);
}

int set_secWPAmixPreSharedKey(int index, char *SharedKey, int len)
{
	long format = 0;
	int pass = 0;
	char query[32] = {0,}, value[128] = {0,};
	unsigned char is_hexString[128] = {0,};

	format = get_secWPAxKeyFormat(index);

	if (format == 1) {
		if (len < 8 || len > 64)
			return 0;
	} else {
		if (len != 64 || !hex_to_string(SharedKey, is_hexString, 64))
			return 0;
	}

	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN1_WPA_PSK");
			break;
		case 1:						/* Hellowireless_ABCD */
			pass = 1;
			break;
		case 2:						/* CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP0_WPA_PSK");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(query, sizeof(query), "WLAN1_VAP1_WPA_PSK");
			break;
		case 4:						/* Guest SSID */
			snprintf(query, sizeof(query), "WLAN1_VAP2_WPA_PSK");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(query, sizeof(query), "WLAN0_WPA_PSK");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(query, sizeof(query), "WLAN0_VAP0_WPA_PSK");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(query, sizeof(query), "WLAN0_VAP1_WPA_PSK");
			break;
		default:
			break;
	}

	if (pass)
		return 1;

	snprintf(value, sizeof(value), "%s", SharedKey);
	nvram_set(query, value);

	return 1;
}
/* ======================= WPA-Mixed SECURITY INFO ================================= */

/* ======================= PORT CONFIG ================================= */
long get_devicePortMode(void)
{
	char query[32] = {0,};
	char value[12] = {0,};
	int opmode;

	snprintf(query, sizeof(query), "OP_MODE");
	nvram_get_r_def(query, value, sizeof(value), "0");

	opmode = strtol(value, NULL, 10);

	return (opmode)? 1 : 2;
}

int set_devicePortMode(int opMode)
{
	switch (opMode) {
		case 2:
			nvram_set("OP_MODE", "0");
			nvram_set("DHCP", "2");
			break;
		case 1:
			nvram_set("OP_MODE", "1");
			nvram_set("DHCP", "0");
			break;
		default:
			return 0;
	}

	return 1;
}

void get_DevportName(int portNum, char *port, int len)
{
	char *portName[5] = { "WAN", "LAN1", "LAN2", "LAN3", "LAN4" };

	if (portNum < PH_MINPORT || portNum > PH_MAXPORT)
		return;

	memset(port, 0, len);
	snprintf(port, len, "%s", portName[portNum]);
}

long get_DevicePortNego(int portNum)
{
	char query[32] = {0,};
	char value[64] = {0,};
	char *nego = NULL;

	snprintf(query, sizeof(query), "x_port_%d_config", portNum);
	nvram_get_r_def(query, value, sizeof(value), "up_auto_-rxpause_txpause");

	if ((nego = strstr(value, "auto")))
		return 2;
	else
		return 1;
}

int set_DevicePortNego(int portNum, int nego)
{
	char query[32] = {0,};
	char value[64] = {0,};
	char config[64] = {0,};
	int n = 0;
	char *args[7] = {NULL,};

	if(nego != 1 && nego != 2) //force, auto
		return 0;

	snprintf(query, sizeof(query), "x_port_%d_config", portNum);
	nvram_get_r_def(query, value, sizeof(value), "up_auto_-rxpause_-txpause");
	n = ystrargs(value, args, _countof(args), " _\n", 0);
	if (n < 4)
		return 0;

	if (nego == 1) { //force
		if (n == 7)
			snprintf(config, sizeof(config), "%s_duplex_%s_%s_%s_%s_%s",  args[0], args[2], args[3], args[4], args[5], args[6]);
		else
			snprintf(config, sizeof(config), "%s_duplex_full_speed_100_-rxpause_txpause",  args[0]);
	} else { //auto
		snprintf(config, sizeof(config), "%s_auto_-rxpause_txpause",  args[0]);
	}

	nvram_set(query, config);

	return 1;
}

unsigned int switch_port_status(int portno)
{
	struct phreq phr;
	int fd;

	if (portno < PH_MINPORT || portno > PH_MAXPORT)
		return 0;

	memset(&phr, 0, sizeof(phr));
	fd = open("/proc/brdio", O_RDWR);
	if (fd < 0)
		return 0;
	phr.phr_port = portno;
	if (ioctl(fd, PHGIO, &phr))
		perror("PHGIO");
	close(fd);
	return phr.phr_optmask;
}

long get_DevicePortSpeed(int portNum)
{
	char query[32] = {0,};
	char value[64] = {0,};
	char *speed;
	char *args[7] = {NULL,};
	int n = 0;
	unsigned int phy_status = switch_port_status(portNum);

	snprintf(query, sizeof(query), "x_port_%d_config", portNum);
	nvram_get_r_def(query, value, sizeof(value), "up_auto_-rxpause_txpause");

	if ((phy_status & PHF_LINKUP)) {
		if(phy_status & PHF_100M)
			return 2;
		else if(phy_status & PHF_500M)
			return 4;
		else if((phy_status & PHF_1000M))
			return 3;
		else
			return 1;
	} else {
		if ((speed = strstr(value, "speed"))) {
			n = ystrargs(value, args, _countof(args), " _\n", 0);
			if (n > 4) {
				if(!strcmp(args[4], "10"))
					return 1;
				else if (!strcmp(args[4], "100"))
					return 2;
				else if (!strcmp(args[4], "1000"))
					return 3;
			} else
				return 2;
		}
	}

	return 2;
}

int set_DevicePortSpeed(int portNum, int speed)
{
	char query[32] = {0,};
	char value[64] = {0,};
	char config[64] = {0,};
	long nego = 0;
	char *args[7] = {NULL,};
	int n = 0;

	if(speed != 1 && speed != 2) //10M, 100M
		return 0;

	nego = get_DevicePortNego(portNum);

	if (nego == 2)	// config value is auto
		return 0;

	snprintf(query, sizeof(query), "x_port_%d_config", portNum);
	nvram_get_r_def(query, value, sizeof(value), "up_auto_-rxpause_txpause");

	//up_duplex_full_speed_100_-rxpause_txpause
	n = ystrargs(value, args, _countof(args), " _\n", 0);
	if (n == 7) {
		snprintf(config, sizeof(config), "%s_duplex_%s_speed_%d_%s_%s", args[0], args[2], (speed == 1)? 10 : 100, args[5], args[6]);
		nvram_set(query, config);
		return 1;
	} else
		return 0;
}

long get_DevicePortDuplex(int portNum)
{
	char query[32] = {0,};
	char value[64] = {0,};
	char *duplex = NULL;

	snprintf(query, sizeof(query), "x_port_%d_config", portNum);
	nvram_get_r_def(query, value, sizeof(value), "up_auto_-rxpause_txpause");

	if ((duplex = strstr(value, "duplex"))) {
		if ( strstr(duplex, "full") )
			return 2;
		else
			return 1;
	} else
		return 2;
}

int set_DevicePortDuplex(int portNum, int duplex)
{
	char query[32] = {0,};
	char value[64] = {0,};
	char config[64] = {0,};
	long nego = 0;
	char *args[7] = {NULL,};
	int n = 0;

	if(duplex != 1 && duplex != 2) //half, full
		return 0;

	nego = get_DevicePortNego(portNum);

	if (nego == 2)	// config value is auto
		return 0;

	snprintf(query, sizeof(query), "x_port_%d_config", portNum);
	nvram_get_r_def(query, value, sizeof(value), "up_auto_-rxpause_txpause");

	//up_duplex_full_speed_100_-rxpause_txpause
	n = ystrargs(value, args, _countof(args), " _\n", 0);
	if (n == 7) {
		snprintf(config, sizeof(config), "%s_duplex_%s_speed_%s_%s_%s", args[0], (duplex == 1) ? "half" : "full", args[4], args[5], args[6]);
		nvram_set(query, config);
		return 1;
	} else
		return 0;
}

long get_DevicePortOnOff(int portNum)
{
	char query[32] = {0,};
	char value[64] = {0,};
	char *onoff = NULL;

	snprintf(query, sizeof(query), "x_port_%d_config", portNum);
	nvram_get_r_def(query, value, sizeof(value), "up_auto_-rxpause_txpause");

	if ((onoff = strstr(value, "down")) != NULL)
		return 2;
	else
		return 1;
}

int set_DevicePortOnOff(int portNum, int onoff)
{
	char query[32] = {0,};
	char value[64] = {0,};
	char config[64] = {0,};
	int n, i, k = 0, len = sizeof(config);
	char *args[7] = {NULL,};

	if (onoff != 1 && onoff != 2) //on, off
		return 0;

	snprintf(query, sizeof(query), "x_port_%d_config", portNum);
	nvram_get_r_def(query, value, sizeof(value), "up_auto_-rxpause_txpause");

	n = ystrargs(value, args, _countof(args), " _\n", 0);
	if (n) {
		for (i = 0; i < n; i++) {
			if (i == 0)
				k += snprintf(&config[k], len - k, "%s", (onoff == 1) ? "up" : "down");
			else
				k += snprintf(&config[k], len - k, "_%s", args[i]);
		}
	}

	nvram_set(query, config);

	return 1;
}

long get_DevicePortStatus(int portNum)
{
	unsigned int phy_status = switch_port_status(portNum);

	if ((phy_status & PHF_LINKUP))
		return 1;
	else
		return 2;
}
/* ======================= PORT CONFIG ================================= */

/* ======================= IGMP CONFIG ================================= */
long get_IgmpMulticastEnable(void)
{
	char value[12];
	long disable;

	nvram_get_r_def("IGMP_PROXY_DISABLED", value, sizeof(value), "1");
	disable = strtol(value, NULL, 10);

	return (disable == 0) ? 1 : 2;
}

int set_IgmpMulticastEnable(int mode)
{
	char value[4] = {0,};

	if (mode != 1 && mode != 2)
		return 0;

	snprintf(value, sizeof(value), "%d", (mode == 1) ? 0 : 1);
	nvram_set("IGMP_PROXY_DISABLED", value);

	return 1;
}

long get_IgmpSelectMode(void)
{
	long opmode;

	opmode = get_devicePortMode();
	if (opmode == 1) /* bridge */
		return 2;
	else			/* nat */
		return 1;
}

long get_IgmpFastLeaveEnable(void)
{
	char value[4] = {0,};
	long disable;

	nvram_get_r_def("IGMP_FAST_LEAVE_DISABLED", value, sizeof(value), "0");
	disable = strtol(value, NULL, 10);

	return (disable == 0) ? 1 : 2;
}

int set_IgmpFastLeaveEnable(int mode)
{
	char value[4] = {0,};

	if (mode != 1 && mode != 2)
		return 0;

	snprintf(value, sizeof(value), "%d", (mode == 1)? 0 : 1);
	nvram_set("IGMP_FAST_LEAVE_DISABLED", value);

	return 1;
}

long get_IgmpProxyMemberExpireTime(void)
{
	char value[12] = {0,};
	long expire = 0;

	nvram_get_r_def("x_igmp_expire_time", value, sizeof(value), "180");
	expire = strtol(value, NULL, 10);

	return expire;
}

int set_IgmpProxyMemberExpireTime(int expire)
{
	char value[12] = {0,};

	snprintf(value, sizeof(value), "%d", expire);
	nvram_set("x_igmp_expire_time", value);

	return 1;
}
/* ======================= IGMP CONFIG ================================= */

/* ======================= SNMP CONFIG ================================= */
long get_snmpEnable(void)
{
	long enable = 0;
	char value[4] = {0,};

	nvram_get_r_def("snmp_enable", value, sizeof(value), "1");
	enable = strtol(value, NULL, 10);

	return (enable) ? 1 : 2;
}

int set_snmpEnable(int enable)
{
	char value[4] = {0,};

	if (enable != 1 && enable != 2)
		return 0;

	snprintf(value, sizeof(value), "%d", (enable == 2)? 0 : 1);
	nvram_set("snmp_enable", value);

	return 1;
}

void get_getCommunityName(char *R_Community, int len)
{
	char value[64] = {0,};

	memset(R_Community, 0, len);
	nvram_get_r_def("snmp_get_community", value, sizeof(value), "CJHV-ap-Read");
	snprintf(R_Community, len, "%s", value);
}

int set_getCommunityName(unsigned char *R_Community, int len)
{
	if (len == 0)
		return 0;

	nvram_set("snmp_get_community", (char *)R_Community);
	return 1;
}

void get_setCommunityName(char *W_Community, int len)
{
	char value[64] = {0,};

	memset(W_Community, 0, len);
	nvram_get_r_def("snmp_set_community", value, sizeof(value), "CJHV-ap-Write");
	snprintf(W_Community, len, "%s", value);
}

int set_setCommunityName(unsigned char *W_Community, int len)
{
	if (len == 0)
		return 0;

	nvram_set("snmp_set_community", (char *)W_Community);
	return 1;
}

long get_snmpListenport(void)
{
	long port = 0;
	char value[12] = {0,};

	nvram_get_r_def("snmp_port", value, sizeof(value), "20161");
	port = strtol(value, NULL, 10);

	return port;
}

int set_snmpListenport(int s_port)
{
	char value[12] = {0,};

	if (s_port < 1 || s_port > 65535)
		return 0;

	snprintf(value, sizeof(value), "%d", s_port);
	nvram_set("snmp_port", value);

	return 1;
}

long get_TrapEnable(void)
{
	long enable = 0;
	char value[4] = {0,};

	nvram_get_r_def("snmp_trap_enable", value, sizeof(value), "1");
	enable = strtol(value, NULL, 10);

	return (enable) ? 1 : 2;
}

int set_TrapEnable(int enable)
{
	char value[4] = {0,};

	if (enable != 1 && enable != 2)
		return 0;

	snprintf(value, sizeof(value), "%d", (enable == 2)? 0 : 1);
	nvram_set("snmp_trap_enable", value);

	return 1;
}

void get_snmpTrapCommunityName(char *T_Community, int len)
{
	char value[64] = {0,};

	memset(T_Community, 0, len);

	nvram_get_r_def("snmp_trp_community", value, sizeof(value), "CJHV-ap-trap");
	snprintf(T_Community, len, "%s", value);
}

int set_snmpTrapCommunityName(unsigned char * T_Community, int len)
{
	if (len == 0)
		return 0;

	nvram_set("snmp_trp_community", (char *)T_Community);
	return 1;
}

void get_snmpTrapDestination(char *TrapServer, int len)
{
	char value[64] = {0,};

	memset(TrapServer, 0, len);
	nvram_get_r_def("apms_ip", value, sizeof(value), "0.0.0.0");
	snprintf(TrapServer, len, "%s", value);
}

int set_snmpTrapDestination(unsigned char *trapServer, int len)
{
	if (len == 0)
		return 0;

	nvram_set("apms_ip", (char *)trapServer);
	return 1;
}

long get_snmpTrapPort(void)
{
	char value[12] = {0,};
	long t_port = 0;

	nvram_get_r_def("snmp_trp_port", value, sizeof(value), "20161");
	t_port = strtol(value, NULL, 10);

	return t_port;
}

int set_snmpTrapPort(int t_port)
{
	char value[12] = {0,};

	if (t_port < 1 || t_port > 65535)
		return 0;

	snprintf(value, sizeof(value), "%d", t_port);
	nvram_set("snmp_trp_port", value);

	return 1;
}
/* ======================= SNMP CONFIG ================================= */

/* ======================= SYSLOG CONFIG ================================= */
long get_sysLogEnable(void)
{
	long syslog = 0;
	char value[4] = {0,};

	nvram_get_r_def("SCRLOG_ENABLED", value, sizeof(value), "3");
	syslog = strtol(value, NULL, 10);

	return (syslog == 3) ? 1 : 2;
}

int set_sysLogEnable(int enable)
{
	char value[4] = {0,};

	if (enable != 1 && enable != 2)
		return 0;

	snprintf(value, sizeof(value), "%d", (enable == 1)? 3 : 2);
	nvram_set("SCRLOG_ENABLED", value);

	return 1;
}

long get_sysLogRemoteLogEnable(void)
{
	char value[4] = {0,};
	long remote = 0;

	nvram_get_r_def("REMOTELOG_ENABLED", value, sizeof(value), "0");
	remote = strtol(value, NULL, 10);

	return (remote) ? 1 : 2;
}

int set_sysLogRemoteLogEnable(int remote)
{
	char value[4] = {0,};

	if (remote != 1 && remote != 2)
		return 0;

	snprintf(value, sizeof(value), "%d", (remote == 1)? 1 : 0)	;
	nvram_set("REMOTELOG_ENABLED", value);

	return 1;
}

void get_sysLogRemoteLogServer(char *logServer, int len)
{
	char value[64] = {0,};

	memset(logServer, 0, len);
	nvram_get_r_def("REMOTELOG_SERVER", value, sizeof(value), "0.0.0.0");
	snprintf(logServer, len, "%s", value);
}

int set_sysLogRemoteLogServer(unsigned char *server, int len)
{
	if (len == 0)
		return 0;

	nvram_set("REMOTELOG_SERVER", (char *)server);
	return 1;
}
/* ======================= SYSLOG CONFIG ================================= */

/* ======================= NTP CONFIG ================================= */
void get_ntpServer(int index, char *server, int len)
{
	char query[32] = {0,};
	char value[64] = {0,};

	memset(server, 0, len);

	snprintf(query, sizeof(query), "ntp_server_ip%d", index);
	nvram_get_r_def(query, value, sizeof(value), "180.182.38.254");

	snprintf(server, len, "%s", value);
}

int set_ntpServer(int index, unsigned char *server, int len)
{
	char query[32] = {0,};

	if (len == 0)
		return 0;

	snprintf(query, sizeof(query), "ntp_server_ip%d", index);
	nvram_set(query, (char *)server);

	return 1;
}
/* ======================= NTP CONFIG ================================= */

/* ======================= DMZ CONFIG ================================= */
long get_dmzEnable(void)
{
	char value[4] = {0,};

	if (!dmz_type) {
		nvram_get_r_def("x_sdmz_enable", value, sizeof(value), "0");
		if (value[0] == '1')
			return 1;
		nvram_get_r_def("DMZ_ENABLED", value, sizeof(value), "0");
		if (value[0] == '1')
			return 1;
	} else if (dmz_type == 1) {	/* superDmz */
		nvram_get_r_def("x_sdmz_enable", value, sizeof(value), "0");
		if (value[0] == '1')
			return 1;
	} else if (dmz_type == 2) {	/* Dmz */
		nvram_get_r_def("DMZ_ENABLED", value, sizeof(value), "0");
		if (value[0] == '1')
			return 1;
	} else
		return 2;

	return 2;
}

int set_dmzEnable(int enable)
{
	if (enable != 1 && enable != 2)
		return 0;

	if(!dmz_type)
		get_dmzType();

	if (dmz_type == 1) {	  				//superdmz
		if (enable == 1) {
			nvram_set("x_sdmz_enable", "1");
			nvram_set("DMZ_ENABLED", "0");
		} else {
			nvram_set("x_sdmz_enable", "0");
			nvram_unset("x_sdmz_host");
			dmz_type = 0;
		}
		return 1;
	} else if (dmz_type == 2) {  			//dmz
		if (enable == 1) {
			nvram_set("DMZ_ENABLED", "1");
			nvram_set("x_sdmz_enable", "0");
		} else {
			nvram_set("DMZ_ENABLED", "0");
			nvram_set("DMZ_HOST", "0.0.0.0");
			dmz_type = 0;
		}
		return 1;
	}

	return 0;
}

long get_dmzType(void)
{
	char value[4] = {0,};

	if (!dmz_type) {
		nvram_get_r_def("x_sdmz_enable", value, sizeof(value), "0");
		if (value[0] == '1') {
			dmz_type = 1;
			return 1;
		}
		nvram_get_r_def("DMZ_ENABLED", value, sizeof(value), "0");
		if (value[0] == '1') {
			dmz_type = 2;
			return 2;
		}
	}

	return dmz_type;
}

int set_dmzType(int type)
{
	if(type != 1 && type != 2)
		return 0;

	dmz_type = type;
	return 1;

}

void get_dmzMac(char *dmzMac, int len)
{
	char value[32] = {0,};
	char temp[3] = {0,};
	unsigned char hwAddr[6] = {0,};
	int i, j;

	memset(dmzMac, 0, len);
	memset(temp, 0, sizeof(temp));

	nvram_get_r_def("x_sdmz_host", value, sizeof(value), "");
	for (i = 0, j = 0; i < 17; i += 2) {
		memcpy(temp, &value[i], 2);
		hwAddr[j++] = (char)strtol(temp, NULL, 16);
		i++;
	}
	memcpy(dmzMac, hwAddr, sizeof(hwAddr));
}

int set_superdmzMac(unsigned char *macString, int len)
{
	unsigned char dmzMac[6] = {0,};
	char value[32] = {0,};

	if((strlen((char *)macString) != 12) || !value_to_hex((char *)macString, dmzMac, 12))
		return 0;

	snprintf(value, sizeof(value), "%02x:%02x:%02x:%02x:%02x:%02x", dmzMac[0], dmzMac[1], dmzMac[2], dmzMac[3], dmzMac[4], dmzMac[5]);
	nvram_set("x_sdmz_host", value);
	return 1;
}

void get_dmzIpAddress(unsigned long *ipaddress)
{
	struct in_addr in;
	char value[32] = {0,};
	unsigned long ipAddr = 0;

	nvram_get_r_def("DMZ_HOST", value, sizeof(value), "0.0.0.0");
	if ( inet_aton(value, &in) ) {
		ipAddr = in.s_addr;
		*ipaddress = ipAddr;
	} else
		*ipaddress = ipAddr;
}

int set_dmzIpAddress(unsigned char *ipaddress)
{
	unsigned long lan_ip, lanmask;
	struct in_addr ia;
	char dmzIp[32] = {0,};

	get_lanIpAddress(&lan_ip);
	get_lanSubnetMask(&lanmask);

	if(lan_ip == *(unsigned long *)ipaddress)
		return 0;

	if ( ((lan_ip & lanmask) != (*(unsigned long *)ipaddress & lanmask)) )
		return 0;


	ia.s_addr = *(unsigned long *)ipaddress;
	snprintf(dmzIp, sizeof(dmzIp), "%s", inet_ntoa(ia));
	nvram_set("DMZ_HOST", dmzIp);
	return 1;
}
/* ======================= DMZ CONFIG ================================= */

/* ======================= PORTFW CONFIG ================================= */
long get_PortFwEnable(void)
{
	long enable = 0;
	char value[4] = {0,};

	nvram_get_r_def("PORTFW_ENABLED", value, sizeof(value), "1");
	enable = strtol(value, NULL, 10);

	return (enable) ? 1 : 2;
}

void get_PortFwName(int index, char *comment, int len)
{
	char query[32] = {0,};
	char value[128] = {0,};
	int n;
	char *args[12] = {NULL,};

	memset(comment, 0, len);
	snprintf(query, sizeof(query), "PORTFW_TBL%d", index);
	nvram_get_r_def(query, value, sizeof(value), "");

	//192.168.200.101,7000,7000,3,5000,5001,0.0.0.0,1,test
	n = ystrargs(value, args, _countof(args), " ,\n", 0);
	if (n == 9) /* exist comment */
		snprintf(comment, len, "%s", args[8]);
}

void get_PortfwIpAddress(int index, unsigned long *Ipaddr)
{
	char query[32] = {0,};
	char value[128] = {0,};
	int n;
	char *args[12] = {NULL,};
	struct in_addr in;

	snprintf(query, sizeof(query), "PORTFW_TBL%d", index);
	nvram_get_r_def(query, value, sizeof(value), "");
	*Ipaddr = 0;

	//192.168.200.101,7000,7000,3,5000,5001,0.0.0.0,1,test
	n = ystrargs(value, args, _countof(args), " ,\n", 0);
	if (n > 5) {
		if ( inet_aton(args[0], &in) ) {
			*Ipaddr = in.s_addr;
		}
	}
}

void get_portFwStartPort(int index, long *s_port)
{
	char query[32] = {0,};
	char value[128] = {0,};
	int n;
	char *args[12] = {NULL,};

	snprintf(query, sizeof(query), "PORTFW_TBL%d", index);
	nvram_get_r_def(query, value, sizeof(value), "");
	*s_port = 0;

	//192.168.200.101,7000,7000,3,5000,5001,0.0.0.0,1,test
	n = ystrargs(value, args, _countof(args), " ,\n", 0);
	if (n > 5) {
		*s_port = strtol(args[4], NULL, 10);
	}
}

void get_portFwEndPort(int index, long *e_port)
{
	char query[32] = {0,};
	char value[128] = {0,};
	int n;
	char *args[12] = {NULL,};

	snprintf(query, sizeof(query), "PORTFW_TBL%d", index);
	nvram_get_r_def(query, value, sizeof(value), "");
	*e_port = 0;

	//192.168.200.101,7000,7000,3,5000,5001,0.0.0.0,1,test
	n = ystrargs(value, args, _countof(args), " ,\n", 0);
	if (n > 5) {
		*e_port = strtol(args[5], NULL, 10);
	}
}

void get_portFwLanPort(int index, long *lan_port)
{
	char query[32] = {0,};
	char value[128] = {0,};
	int n;
	char *args[12] = {NULL,};

	snprintf(query, sizeof(query), "PORTFW_TBL%d", index);
	nvram_get_r_def(query, value, sizeof(value), "");
	*lan_port = 0;

	//192.168.200.101,7000,7000,3,5000,5001,0.0.0.0,1,test
	n = ystrargs(value, args, _countof(args), " ,\n", 0);
	if (n > 5) {
		*lan_port = strtol(args[1], NULL, 10);
	}
}

void get_portFwProtocol(int index, long *protocol)
{
	char query[32] = {0,};
	char value[128] = {0,};
	int n;
	char *args[12] = {NULL,};

	snprintf(query, sizeof(query), "PORTFW_TBL%d", index);
	nvram_get_r_def(query, value, sizeof(value), "");
	*protocol = 0;

	//192.168.200.101,7000,7000,3,5000,5001,0.0.0.0,1,test
	n = ystrargs(value, args, _countof(args), " ,\n", 0);
	if (n > 5) {
		*protocol = strtol(args[3], NULL, 10);
	}
}

long get_setPortfwIndex(void)
{
	return setPortfw_entry.index;
}

int set_portfwIndex(int index)
{
	if(!index)
		return 0;

	setPortfw_entry.index = index;
	return 1;
}

long get_setPortfwEnable(void)
{
	return setPortfw_entry.enable;
}

int check_entry_portfw(void)
{
	char query[32] = {0,};
	char value[128] = {0,};
	int i, entryNum = 0, n;
	char *args[12] = {NULL,};

	nvram_get_r_def("PORTFW_TBL_NUM", value, sizeof(value), "0");
	entryNum = strtol(value, NULL, 10);

	for (i = 0; i < entryNum; i++) {
		snprintf(query, sizeof(query), "PORTFW_TBL%d", i + 1);
		nvram_get_r_def(query, value, sizeof(value), "");

		n = ystrargs(value, args, _countof(args), " ,\n", 0);
		if (n > 5) {
			checkPortfw_entry.startport = strtol(args[4], NULL, 10);
			checkPortfw_entry.endport = strtol(args[5], NULL, 10);
			checkPortfw_entry.protocol = strtol(args[3], NULL, 10);
			if (((setPortfw_entry.startport <= checkPortfw_entry.startport && setPortfw_entry.endport >= checkPortfw_entry.startport) ||
				(setPortfw_entry.startport >= checkPortfw_entry.startport && setPortfw_entry.startport <= checkPortfw_entry.endport)) &&
				(setPortfw_entry.protocol & checkPortfw_entry.protocol))
				return 0;
		}
	}

	return 1;
}

void rearrange_portfw(void)
{
	int i, j = 0;
	char query[32] = {0,}, rewrite[32] = {0,};
	char value[128] = {0,}, tableNum[12] = {0,};
	char *p = NULL;

	for (i = 0; i < MAX_FILTER_NUM; i++) {
		snprintf(query, sizeof(query), "PORTFW_TBL%d", (i + 1));
		p = nvram_get(query);
		if (p) {
			snprintf(value, sizeof(value), "%s", p);
			nvram_unset(query);
			snprintf(rewrite, sizeof(rewrite), "PORTFW_TBL%d", (j + 1));
			nvram_set(rewrite, value);
			j++;
		}
	}

	snprintf(tableNum, sizeof(tableNum), "%d", j);
	nvram_set("PORTFW_TBL_NUM", tableNum);
}

int set_portfwEnable(int enable)
{
	int i, entryNum;
	char query[32] = {0,};
	char value[128] = {0,};
	char ipaddr[32] = {0,};

	if (enable != 1 && enable != 2)
		return 0;

	nvram_get_r_def("PORTFW_TBL_NUM", value, sizeof(value), "0");
	entryNum = strtol(value, NULL, 10);

	if (enable == 1) {	/* add */
		if ( (entryNum + 1) > MAX_FILTER_NUM )
			return 0;

		if (setPortfw_entry.ipaddr && setPortfw_entry.startport && setPortfw_entry.endport && setPortfw_entry.lanport && setPortfw_entry.protocol) {
			if (setPortfw_entry.startport > setPortfw_entry.endport)
				return 0;

			if (!check_entry_portfw())
				return 0;

			for (i = 0; i < ARRAY_SIZE(banned_port); i++)
				if ((setPortfw_entry.startport <= banned_port[i]) && (setPortfw_entry.endport >= banned_port[i]))
					return 0;

			//192.168.200.101,7000,7000,3,5000,5001,0.0.0.0,1,test
			snprintf(query, sizeof(query), "PORTFW_TBL%d", entryNum + 1);
			inet_ntop(AF_INET, &setPortfw_entry.ipaddr, ipaddr, sizeof(ipaddr));
			snprintf(value, sizeof(value), "%s,%d,%d,%d,%d,%d,0.0.0.0,1,%s", ipaddr, setPortfw_entry.lanport, setPortfw_entry.lanport,
										setPortfw_entry.protocol, setPortfw_entry.startport, setPortfw_entry.endport, setPortfw_entry.name);
			nvram_set(query, value);

			snprintf(value, sizeof(value), "%d", entryNum + 1);
			nvram_set("PORTFW_TBL_NUM", value);
			return 1;
		} else
			return 0;
	} else {	/* delete */
		if (!entryNum || !(setPortfw_entry.index) || (setPortfw_entry.index > entryNum))
			return 0;

		snprintf(query, sizeof(query), "PORTFW_TBL%d", setPortfw_entry.index);
		nvram_unset(query);
		rearrange_portfw();
		return 1;
	}
}

void get_setPortFwName(char *portfw_comment, int len)
{
	memset(portfw_comment, 0, len);
	snprintf(portfw_comment, len, "%s", setPortfw_entry.name);
}

int set_portfwName(unsigned char *portfw_comment, int len)
{
	snprintf(setPortfw_entry.name, sizeof(setPortfw_entry.name), "%s", (char *)portfw_comment);
	return 1;
}

void get_portfwAddress(unsigned long *portfwIp)
{
	*portfwIp = setPortfw_entry.ipaddr;
}

int set_portfwAddress(unsigned char *ipaddr)
{
	unsigned long lan_ip, lanmask;

	get_lanIpAddress(&lan_ip);
	get_lanSubnetMask(&lanmask);

	if (lan_ip == *(unsigned long *)ipaddr)
		return 0;

	if ( ((lan_ip & lanmask) != (*(unsigned long *)ipaddr & lanmask)) )
		return 0;

	setPortfw_entry.ipaddr = *(unsigned long *)ipaddr;
	return 1;
}

long get_setPortfwSport(void)
{
	return setPortfw_entry.startport;
}

int set_portfwSport(int s_port)
{
	int i;

	if (s_port < 1 || s_port > 65535 )
		return 0;

	for (i = 0; i < ARRAY_SIZE(banned_port); i++) {
		if (s_port == banned_port[i])
			return 0;
	}

	setPortfw_entry.startport = s_port;
	return 1;
}

long get_setPortfwEport(void)
{
	return setPortfw_entry.endport;
}

int set_portfwEport(int e_port)
{
	int i;

	if (e_port < 1 || e_port > 65535 )
		return 0;

	for (i = 0; i < ARRAY_SIZE(banned_port); i++) {
		if (e_port == banned_port[i])
			return 0;
	}

	setPortfw_entry.endport = e_port;
	return 1;
}

long get_setPortfwLanport(void)
{
	return setPortfw_entry.lanport;
}

int set_portfwLanport(int laport)
{
	if (laport< 1 || laport > 65535 )
		return 0;

	setPortfw_entry.lanport = laport;

	return 1;
}

int set_portfwLanEport(int lanport)
{
	if (lanport < 1 || lanport > 65535 )
		return 0;

	return 1;
}

long get_setPortfwprotocol(void)
{
	return setPortfw_entry.protocol;
}

int set_portfwprotocol(int protocol)
{
	if (protocol < 1 || protocol > 3)
		return 0;

	setPortfw_entry.protocol = protocol;
	return 1;

}
/* ======================= PORTFW CONFIG ================================= */

/* ======================= TELNET CONFIG ================================= */
long get_telnetEnable(void)
{
	char value[4] = {0,};
	long enable = 0;

	nvram_get_r_def("telnet_enable", value, sizeof(value), "0");
	enable = strtol(value, NULL, 10);

	return (enable) ? 1 : 2;
}

int set_telnetEnable(int enable)
{
	char value[4] = {0,};

	if (enable != 1 && enable != 2)
		return 0;

	snprintf(value, sizeof(value), "%d", (enable == 1) ? 1 : 0);
	nvram_set("telnet_enable", value);
	start_telnetd();
	yexecl(NULL, "%s/%s &", _CONFIG_SCRIPT_PATH, _FIREWALL_SCRIPT_PROG);
	nvram_commit();

	return 1;
}
/* ======================= TELNET CONFIG ================================= */

/* ======================= ACL CONFIG ================================= */
long get_aclEnable(void)
{
	char value[4] = {0,};
	long aclEnable = 0;

	nvram_get_r_def("webacl_mode", value, sizeof(value), "0");
	aclEnable = strtol(value, NULL, 10);

	return (aclEnable) ? 1 : 2;
}

int set_aclEnable(int aclEnable)
{
	char num[12] = {0,}, query[32] = {0,};
	int acl_num = 0;

	if (aclEnable != 1 && aclEnable != 2)
		return 0;

	if (aclEnable == 1) {	/* enable */
		nvram_set("webacl_mode", "1");
		nvram_set("webman_enable", "1");
		nvram_get_r_def("webacl_num", num, sizeof(num), "0");
		acl_num = strtol(num, NULL, 10);
		if (acl_num == 0) {
			nvram_set("webacl_num", "1");
			snprintf(query, sizeof(query), "webacl_addr1");
       		nvram_set(query, "0.0.0.0");
		}
	} else {				/* disable */
		nvram_set("webacl_mode", "0");
	}

	yexecl(NULL, "%s/%s &", _CONFIG_SCRIPT_PATH, _FIREWALL_SCRIPT_PROG);
	nvram_commit();
	return 1;
}
/* ======================= ACL CONFIG ================================= */

/* ======================= WEBMAN CONFIG ================================= */
long get_WebEnable(void)
{
	char value[4] = {0,};
	long webman = 0;

	nvram_get_r_def("webman_enable", value, sizeof(value), "0");
	webman = strtol(value, NULL, 10);

	return (webman) ? 1 : 2;
}

int set_WebEnable(int webman)
{
	if (webman != 1 && webman != 2)
		return 0;

	if (webman == 1) {	/* enable */
		nvram_set("webman_enable", "1");
	} else {			/* disable */
		nvram_set("webman_enable", "0");
		nvram_set("webacl_mode", "0");
	}

	yexecl(NULL, "%s/%s &", _CONFIG_SCRIPT_PATH, _FIREWALL_SCRIPT_PROG);
	nvram_commit();
	return 1;
}
/* ======================= WEBMAN CONFIG ================================= */

/* ======================= DNS CHANGE INFO ================================= */
void get_attackIp(unsigned long *ipaddress)
{
	FILE *fp = NULL;
	struct in_addr in;
	char *args[3] = {NULL};
	char line[60] ={0,};
	int n;

	*ipaddress = 0;

	fp = fopen("/tmp/.attack_ip", "r");
	if (fp) {
		fgets(line, sizeof(line), fp);
		n = ystrargs(line, args, _countof(args), " \n", 0);
		if (n == 3) {
			if (inet_aton(args[0], &in)) {
				*ipaddress = in.s_addr;
			}
		}
		fclose(fp);
	}
}

void get_attackTime(char *eventTime, int len)
{
	FILE *fp = NULL;
	char *args[3] = {NULL};
	char line[60] ={0,};
	int n;

	memset(eventTime, 0, len);

	fp = fopen("/tmp/.attack_ip", "r");
	if (fp) {
		fgets(line, sizeof(line), fp);
		n = ystrargs(line, args, _countof(args), " \n", 0);
		if (n == 3) {
			snprintf(eventTime, len, "%s %s", args[1], args[2]);
		}
		fclose(fp);
	}
}
/* ======================= DNS CHANGE INFO ================================= */

/* ======================= IGMP JOIN INFO ================================= */
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

static int if_readgroup(struct list_head *h, char *ifname)
{
	FILE *fp = NULL;
	char *args[12] = {NULL,};
	char line[128] = {0,};
	uint32_t addr;
	int num_group, count = 0;
	int n;

	fp = fopen("/proc/net/igmp", "r");
	if (!fp)
		return 0;

	fgets(line, sizeof(line), fp);
	while (fgets(line, sizeof(line), fp)) {
		if ((n = ystrargs(line, args, _countof(args), " \t\r\n", 0)) < 4)
			continue;
		if (strcmp(args[1], ifname))
			continue;
		for (num_group = strtol(args[3], NULL, 10);
		     num_group > 0 && fgets(line, sizeof(line), fp) != NULL;
		     num_group--) {
			if ((n = ystrargs(line, args, _countof(args), " \t\r\n", 0)) < 4)
				continue;
			/* reporter > 0 */
			if (strtol(args[3], NULL, 10) > 0) {
				addr = strtoul(args[0], NULL, 16);
				if (IN_MULTICAST(addr) &&
				    mcast_group_add(h, htonl(addr)) == 1) {
					count++;
				}
			}
		}
		break;
	}

	fclose(fp);
	return count;
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

static int read_mbr(FILE *fp, uint32_t group, struct list_head *mc)
{
	int count = 0;
	char *p, *args[12] = {NULL,};
	char line[128] = {0,};
	struct mcast_mbr *mbr;
	int n;

	while (fgets(line, sizeof(line), fp)) {
		if ((n = ystrargs(line, args, _countof(args), " ,:\\\r\n", 0)) != 6 || !(p = strchr(args[0], '>')))
			break;
		mbr = mcast_mbr_add(mc, group, inet_addr(&p[1]));
		if (mbr != NULL) {
			mbr->port = atoi(args[2]);
			mbr->version = args[3][5] - '0';
			mbr->exclude = atoi(args[5]);
			count += 1;
		}
	}

	return count;
}

static int read_group(FILE *fp, struct list_head *mc)
{
	int count = 0;
	char *p, *args[12] = {NULL,};
	char line[128] = {0,};
	uint32_t addr;
	int n;

	for (p = NULL; fgets(line, sizeof(line), fp); )
		if (!strncmp(line, "igmp list:", strlen("igmp list:"))) {
			p = line;
			break;
		}

	if (p != NULL) {
		while (fgets(line, sizeof(line), fp)) {
			if ((n = ystrargs(line, args, _countof(args), " ,:\\\r\n", 0)) != 4 || strcmp("Group", args[1]))
				break;
			addr = inet_addr(args[3]);
			if (IN_MULTICAST(ntohl(addr)) &&
			    mcast_group_add(mc, addr) == 1) {
				read_mbr(fp, addr, mc);
				count++;
			}
		}
	}

	return count;
}

static int read_mcast(struct list_head *mc, const char *path)
{
	FILE *fp = NULL;
	char *args[12] = {NULL,};
	char line[128] = {0,};
	int n;

	fp = fopen(path, "r");
	if (!fp)
		return -1;

	while (fgets(line, sizeof(line), fp)) {
		if ((n = ystrargs(line, args, _countof(args), " ,:\\\r\n", 0)) > 7 &&
		    !strcmp(args[0], "module") && !strcmp(args[4], "eth*")) {
			read_group(fp, mc);
		}
	}

	fclose(fp);
	return 0;
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

static int shift_bitmask(uint8_t port)
{
	switch (port)
	{
		case 1:
			return 3;
		case 3:
			return 1;
		case 4:
			return 0;
		default:
			return 2;
	}
}

int igmp_snoop_table_info(_igmp_snoop_t *igmp)
{
	struct mcast_group *g;
	struct mcast_mbr *m = NULL;
	struct mcast_mbr *mbr[5];
	struct list_head *pos, *pos2;
	struct list_head mc;
	struct list_head upif_grp;
	uint32_t i = 0, ii, tmp;
	int count = 0;
	int opmode = -1;

	INIT_LIST_HEAD(&mc);
	INIT_LIST_HEAD(&upif_grp);

	opmode = get_devicePortMode();
	if (opmode == 2)
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
			/* bit map : -|-|-|-|-|-|-|-|¡¦(port1|port2|port3|¡¦, 0:X, 1:O) */
			tmp |= (1 << shift_bitmask(m->port));
			if (mbr[m->port] == NULL || mbr[m->port]->exclude < m->exclude)
				mbr[m->port] = m;
		}

		igmp[i].join_port = tmp;
		igmp[i].portNum = m->port;
		igmp[i].GAddr = g->group.s_addr;
		for (ii = 1; ii < ARRAY_SIZE(mbr); ii++) {
			if ((m = mbr[ii]) != NULL)
				count++;
		}
		igmp[i].join_mbn = count;
		i++;
	}
	mcast_group_free(&mc);
	return i;
}

void get_igmpJoinIpAddress(_igmp_snoop_t *igmp, unsigned long *ipaddr)
{
	*ipaddr = 0;
	*ipaddr = igmp->GAddr;
}
/* ======================= IGMP JOIN INFO ================================= */

/* ======================= MULTICAST INFO ================================= */
void get_multicastJoinIpAddress(_igmp_snoop_t *igmp, unsigned long *ipaddr)
{
	*ipaddr = 0;
	*ipaddr = igmp->GAddr;
}

long get_multicastPortNumber(_igmp_snoop_t *igmp)
{
	return igmp->portNum;
}

void get_multicastPortName(_igmp_snoop_t *igmp, char *port, int len)
{
	char *portName[5] = { "WAN", "LAN1", "LAN2", "LAN3", "LAN4" };

	memset(port, 0, len);
	snprintf(port, len, "%s", portName[igmp->portNum]);
}

void get_multicastInPackets(_igmp_snoop_t *igmp, unsigned long *rx_multicast)
{
	*rx_multicast = 0;
	get_portStats(igmp->portNum);
	*rx_multicast = portStats[igmp->portNum].rx_multicast;
}

void get_multicastOutPackets(_igmp_snoop_t *igmp, unsigned long *tx_multicast)
{
	*tx_multicast = 0;
	get_portStats(igmp->portNum);
	*tx_multicast = portStats[igmp->portNum].tx_multicast;
}
/* ======================= MULTICAST INFO ================================= */

/* ======================= TRAFFIC INFO ================================= */
void get_portStatusOutBytes(int port, unsigned long *txCount)
{
	int portIdx = 0;
	unsigned long bytes = 0;

	*txCount = 0;
	if (port == PRTNR_WAN0) {		/* WAN */
		get_portStats(PRTNR_WAN0);
		bytes = portStats[PRTNR_WAN0].txbyte;
	} else {						/* LAN 1-4 */
		for (portIdx = 1; portIdx < 5; portIdx++) {
			get_portStats(portIdx);
			bytes += portStats[portIdx].txbyte;
		}
	}

	*txCount = (bytes / 1024);	/* kbyte */
}

void get_wlanOutTrafficInfo(int index, unsigned long *txCount)
{
	char intf[12] = {0,};
	char f_name[32] = {0,};
	char line[80] = {0,};
	FILE *fp = NULL;
	char *args[4] = {NULL,};
	char *p = "0";

	*txCount = 0;
	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(intf, sizeof(intf), "wlan1");
			break;
		case 1:						/* Hellowireless_ABCD */
			return;
		case 2:						/* CJHV070VOIP */
			snprintf(intf, sizeof(intf), "wlan1-va0");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(intf, sizeof(intf), "wlan1-va1");
			break;
		case 4:						/* Guest SSID */
			snprintf(intf, sizeof(intf), "wlan1-va2");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(intf, sizeof(intf), "wlan0");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(intf, sizeof(intf), "wlan0-va0");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(intf, sizeof(intf), "wlan0-va1");
			break;
		default:
			return;
	}

	snprintf(f_name, sizeof(f_name), "/proc/%s/stats", intf);
	fp = fopen(f_name, "r");
	if (fp != NULL) {
		while (fgets(line, sizeof(line), fp)) {
			if (ystrargs(line, args, _countof(args), ":", 0) &&
			    strcmp(args[0], "tx_only_data_bytes") == 0) {
				p = args[1] ? : "0";
				*txCount = strtoul(p, NULL, 10) / 1024;	/* kbyte */
				break;
			}
		}
		fclose(fp);
	}
}

void get_portStatusInBytes(int port, unsigned long *rxCount)
{
	int portIdx = 0;
	unsigned long bytes = 0;

	*rxCount = 0;
	if (port == PRTNR_WAN0) {		/* WAN */
		get_portStats(PRTNR_WAN0);
		bytes = portStats[PRTNR_WAN0].rxbyte;
	} else {						/* LAN 1-4 */
		for (portIdx = 1; portIdx < 5; portIdx++) {
			get_portStats(portIdx);
			bytes += portStats[portIdx].rxbyte;
		}
	}

	*rxCount = (bytes / 1024);	/* kbyte */
}

void get_wlanInTrafficInfo(int index, unsigned long *rxCount)
{
	char intf[12] = {0,};
	char f_name[32] = {0,};
	char line[80] = {0,};
	FILE *fp = NULL;
	char *args[4] = {NULL,};
	char *p = "0";

	*rxCount = 0;
	switch(index) {
		case 0:						/* CJWIFI_ABCD */
			snprintf(intf, sizeof(intf), "wlan1");
			break;
		case 1:						/* Hellowireless_ABCD */
			return;
		case 2:						/* CJHV070VOIP */
			snprintf(intf, sizeof(intf), "wlan1-va0");
			break;
		case 3:						/* KCT070VOIP */
			snprintf(intf, sizeof(intf), "wlan1-va1");
			break;
		case 4:						/* Guest SSID */
			snprintf(intf, sizeof(intf), "wlan1-va2");
			break;
		case 5:						/* 5G_CJWIFI_ABCD */
			snprintf(intf, sizeof(intf), "wlan0");
			break;
		case 6:						/* 5G_CJHV070VOIP */
			snprintf(intf, sizeof(intf), "wlan0-va0");
			break;
		case 7:						/* 5G_Guest SSID */
			snprintf(intf, sizeof(intf), "wlan0-va1");
			break;
		default:
			return;
	}

	snprintf(f_name, sizeof(f_name), "/proc/%s/stats", intf);
	fp = fopen(f_name, "r");
	if (fp != NULL) {
		while (fgets(line, sizeof(line), fp)) {
			if (ystrargs(line, args, _countof(args), ":", 0) &&
			    strcmp(args[0], "rx_only_data_bytes") == 0) {
				p = args[1] ? : "0";
				*rxCount = strtoul(p, NULL, 10) / 1024;	/* kbyte */
				break;
			}
		}
		fclose(fp);
	}
}
/* ======================= TRAFFIC INFO ================================= */

/* ======================= RESET CONFIG ================================= */
int set_faultreset(int reboot)
{
	if (reboot == 1) {
		nvram_commit();
		snmpAction = SNMP_REBOOT;
		return 1;
	} else
		return 0;
}
/* ======================= RESET CONFIG ================================= */

/* ======================= PING TEST CONFIG ================================= */
void update_ping_result(void)
{
	FILE *fp = NULL;
	int n;
	char *args[2] = {NULL,};
	char line[128] = {0,};

	fp = fopen(PING_RST, "r");
	if (fp) {
		while (fgets(line, sizeof(line), fp)) {
			if ((n = ystrargs(line, args, _countof(args), "=\n", 0)) == 2) {
				if (!strcmp(args[0], "pingAddress"))
					snprintf(pingTest.pingAddress, sizeof(pingTest.pingAddress), "%s", args[1]);
				if (!strcmp(args[0], "pingPacketCount"))
					pingTest.pktCount = strtoul(args[1], NULL, 10);
				if (!strcmp(args[0], "pingPacketSize"))
					pingTest.pktSize = strtoul(args[1], NULL, 10);
				if (!strcmp(args[0], "pingPacketTimeout"))
					pingTest.pktTimeout = strtoul(args[1], NULL, 10);
				if (!strcmp(args[0], "pingDelay"))
					pingTest.pktDelay = strtoul(args[1], NULL, 10);
				if (!strcmp(args[0], "pingSentPackets"))
					pingTest.sentPktCount = strtoul(args[1], NULL, 10);
				if (!strcmp(args[0], "pingReceivedPackets"))
					pingTest.recvPktCount = strtoul(args[1], NULL, 10);
				if (!strcmp(args[0], "pingMinRtt"))
					pingTest.minPingTime = strtoul(args[1], NULL, 10);
				if (!strcmp(args[0], "pingAvgRtt"))
					pingTest.avgPingTime = strtoul(args[1], NULL, 10);
				if (!strcmp(args[0], "pingMaxRtt"))
					pingTest.maxPingTime = strtoul(args[1], NULL, 10);
				if (!strcmp(args[0], "pingCompleted"))
					pingTest.pingCompleted = strtol(args[1], NULL, 10);
				if (!strcmp(args[0], "pingResultCode"))
					pingTest.pingResultCode = strtol(args[1], NULL, 10);
				if (!strcmp(args[0], "pingTestStartTime"))
					snprintf(pingTest.pingStartTime, sizeof(pingTest.pingStartTime), "%s", args[1]);
				if (!strcmp(args[0], "pingTestEndTime"))
					snprintf(pingTest.pingEndTime, sizeof(pingTest.pingEndTime), "%s", args[1]);
			}
		}
		fclose(fp);
	}
}

void get_pingAddress(char *pingAddress, int len)
{
	memset(pingAddress, 0, len);
	snprintf(pingAddress, len, "%s", pingTest.pingAddress);
}

int set_pingAddress(unsigned char *pingAddress, int len)
{
	if (len == 0)
		return 0;

	snprintf(pingTest.pingAddress, sizeof(pingTest.pingAddress), "%s", (char *)pingAddress);
	return 1;
}

void get_pktCount(unsigned long *count)
{
	*count = 0;
	*count = pingTest.pktCount;
}

int set_pktCount(int count)
{
	pingTest.pktCount = (unsigned long)count;
	return 1;
}

void get_pktSize(unsigned long *size)
{
	*size = 0;
	*size = pingTest.pktSize;
}

int set_pktSize(int size)
{
	if (size > MAX_DATA_LEN)
		size = MAX_DATA_LEN;

	pingTest.pktSize = (unsigned long)size;
	return 1;
}

void get_pktTimeout(unsigned long *timeout)
{
	*timeout = 0;
	*timeout = pingTest.pktTimeout;
}

int set_pktTimeout(int timeout)
{
	pingTest.pktTimeout = (unsigned long)timeout;
	return 1;
}

void get_pktDelay(unsigned long *delay)
{
	*delay = 0;
	*delay = pingTest.pktDelay;
}

int set_pktDelay(int delay)
{
	pingTest.pktDelay = (unsigned long)delay;
	return 1;
}

void get_TrapOnCompletion(long *trapOn)
{
	*trapOn = 0;
	*trapOn = pingTest.TrapOnComplete;
}

int set_TrapOnCompletion(int trapOn)
{
	if (trapOn != 1 && trapOn != 2)
		return 0;

	pingTest.TrapOnComplete = trapOn;
	return 1;
}

void get_sentPktCount(unsigned long *send)
{
	*send = 0;
	*send = pingTest.sentPktCount;
}

void get_recvPktCount(unsigned long *receive)
{
	*receive = 0;
	*receive = pingTest.recvPktCount;
}

void get_minPingTime(unsigned long *min)
{
	*min = 0;
	*min = pingTest.minPingTime;
}

void get_avgPingTime(unsigned long *avg)
{
	*avg = 0;
	*avg = pingTest.avgPingTime;
}

void get_maxPingTime(unsigned long *max)
{
	*max = 0;
	*max = pingTest.maxPingTime;
}

void get_pingCompleted(long *complete)
{
	*complete = 0;
	*complete = (pingTest.pingCompleted == 1) ? 1 : 2;
}

void get_pingStarttime(char *start, int len)
{
	memset(start, 0, len);
	snprintf(start, len, "%s", pingTest.pingStartTime);
}

void get_pingEndtime(char *end, int len)
{
	memset(end, 0, len);
	snprintf(end, len, "%s", pingTest.pingEndTime);
}

void get_pingResultCode(long *status)
{
	*status = 0;
	*status = pingTest.pingResultCode;
}

void pingTest_Result(unsigned int send, unsigned int recv, float min, float avg, float max, char *start, char *end)
{
	FILE *fp = NULL;

	fp = fopen(PING_RST, "w");
	if (fp) {
		fprintf(fp, "pingAddress=%s\n", pingTest.pingAddress);
		fprintf(fp, "pingPacketCount=%u\n", pingTest.pktCount);
		fprintf(fp, "pingPacketSize=%u\n", pingTest.pktSize);
		fprintf(fp, "pingPacketTimeout=%u\n", pingTest.pktTimeout);
		fprintf(fp, "pingDelay=%u\n", pingTest.pktDelay);
		fprintf(fp, "pingSentPackets=%u\n", send);
		fprintf(fp, "pingReceivedPackets=%u\n", recv);
		fprintf(fp, "pingMinRtt=%u\n", (unsigned int)min);
		fprintf(fp, "pingAvgRtt=%u\n", (unsigned int)avg);
		fprintf(fp, "pingMaxRtt=%u\n", (unsigned int)max);
		fprintf(fp, "pingCompleted=1\n");
		fprintf(fp, "pingResultCode=%d\n", pingTest.pingResultCode);
		fprintf(fp, "pingTestStartTime=%s\n", start);
		fprintf(fp, "pingTestEndTime=%s\n", end);
		fclose(fp);
	}
}

int start_mping_report(void)
{
	char command[128] = {0,}, line[128] = {0,}, *q;
	FILE *pp = NULL;
	ssize_t i;
	int errnum, ipaddr;
	struct addrinfo host, *addr;
	struct sockaddr_in *sin;
	unsigned int send = 0, recv = 0;
	float min = 0, avg = 0, max = 0;

	if (!pingTest.pingAddress[0] || strlen(pingTest.pingAddress) == 0) {
		pingTest.pingCompleted = 2;
		pingTest.pingResultCode = Enum_RowStatusNotInSevice;
		return -1;
	}

	ipaddr = inet_addr(pingTest.pingAddress);
	if (ipaddr == INADDR_NONE) {
		memset(&host, 0, sizeof(host));
		host.ai_family = AF_UNSPEC;
		host.ai_socktype = 0;
		host.ai_flags = AI_PASSIVE;
		host.ai_protocol = 0;
		host.ai_canonname = NULL;
		host.ai_addr = NULL;
		host.ai_next = NULL;

		errnum = getaddrinfo(pingTest.pingAddress, NULL, &host, &addr);
		if (errnum != 0) {
			pingTest.pingCompleted = 2;
			fprintf(stderr, "[%s] getaddrinfo(): %s\n", __FUNCTION__, gai_strerror(errnum));
			return -1;
		}
		sin = (void*)addr->ai_addr;
		inet_ntop(AF_INET, &sin->sin_addr, pingTest.pingAddress, sizeof(pingTest.pingAddress));
	} else
		inet_ntop(AF_INET, &ipaddr, pingTest.pingAddress, sizeof(pingTest.pingAddress));

	snprintf(command, sizeof(command), "mping -c %u -s %u -w %u %s 2>&1", pingTest.pktCount, pingTest.pktSize, pingTest.pktTimeout, pingTest.pingAddress);

	if (fork() == 0) {
		time_t t;
		struct tm *tmp;
		char start[32] = {0,};
		char end[32] = {0,};
		char write_path[32] = {0,};
		int agent_pid = 0;

		snprintf(write_path, sizeof(write_path), "/var/run/snmp_ping");
		write_pid(write_path);
		t = time(NULL);
		tmp = localtime(&t);
		strftime(start, sizeof(start), "%F %T", tmp);

		pp = popen(command, "r");
		if (pp == NULL)
			return 0;

		for (i = 0; !feof(pp); i++) {
			while ((q = fgets(line, sizeof(line), pp))) {
				if (strstr(line, "statistics"))
					break;
				printf("%s", line);
			}
			if (q == NULL)
				break;
			if (fscanf(pp, "%u %*s %*s %u %*[^\n]\n", &send, &recv) != 2)
				break;
			if (fscanf(pp, "%*s %*s = %f/%f/%f %*[^\n]\n", &min, &avg, &max) != 3)
				break;
		}
		pclose(pp);
		t = time(NULL);
		tmp = localtime(&t);
		strftime(end, sizeof(end), "%F %T", tmp);
		pingTest_Result(send, recv, min, avg, max, start, end);
		if (access(PING_RST, F_OK) == 0)	/* ping trap message update */
			update_ping_result();
		if (pingTest.TrapOnComplete == 1)	/* ping result trap */
			sendAutoTransmission_ping();
		agent_pid = read_pid("/var/run/snmp_agentd.pid");
		kill(agent_pid, SIGUSR1);			/* snmp agent message update */
		unlink(write_path);
		exit(1);
	}

	return 0;
}

void stop_mping_report(void)
{
	int pid;
	char write_path[32] = {0,};

	snprintf(write_path, sizeof(write_path), "/var/run/snmp_ping");
	pid = read_pid(write_path);
	if (pid) {
		kill(pid, SIGTERM);
	}
	unlink(write_path);
	unlink(PING_RST);
}

int set_pingResultCode(int action)
{
	if (action < 1 || action > 6)
		return 0;

	pingTest.pingResultCode = action;
	switch(action) {
		case Enum_RowStatusActive:
		case Enum_RowStatusCreateAndGo:
			if (start_mping_report() < 0)
				return 0;
			break;
		case Enum_RowStatusDestory:
			stop_mping_report();
			ping_init_instance();
			break;
		case Enum_RowStatusNotInSevice:
		case Enum_RowStatusNotReady:
		case Enum_RowStatusCreateAndWait:
		default:
			break;
	}

	return 1;
}
/* ======================= PING TEST CONFIG ================================= */

/* ======================= FACTORY MODE CONFIG ================================= */
int set_factoryreset(int factory)
{
	if (factory == 1) {
		snmpAction = SNMP_FACTORY_RESET;
		return 1;
	} else
		return 0;
}
/* ======================= FACTORY MODE CONFIG ================================= */

/* ======================= SOFT RESET CONFIG ================================= */
void get_cjhvApSystemSoftReset(unsigned long *result)
{
	char value[4] = {0,};

	*result = 0;
	nvram_get_r_def("softreset_result", value, sizeof(value), "2");
	*result = strtoul(value, NULL, 10);
}

int set_softreset(int soft)
{
	unsigned long long tx_prev_bytes = 0, tx_cur_bytes = 0, tx_diff = 0;
	unsigned long long rx_prev_bytes = 0, rx_cur_bytes = 0, rx_diff = 0;

	get_portStats(PRTNR_WAN0);
	tx_prev_bytes = portStats[PRTNR_WAN0].txbyte;
	rx_prev_bytes = portStats[PRTNR_WAN0].rxbyte;
	sleep(1);
	get_portStats(PRTNR_WAN0);
	tx_cur_bytes = portStats[PRTNR_WAN0].txbyte;
	rx_cur_bytes = portStats[PRTNR_WAN0].rxbyte;

	tx_diff = (tx_cur_bytes - tx_prev_bytes);
	rx_diff = (rx_cur_bytes - rx_prev_bytes);

	if ((tx_diff <= DEFAULT_TRAFFIC_BYTE) && (rx_diff <= DEFAULT_TRAFFIC_BYTE)) {
		nvram_set("softreset_result", "1");	/* success */
	} else {
		nvram_set("softreset_result", "2");		/* fail */
	}
	snmpAction = SNMP_SOFTRESET_TRAP;
	printf("[softreset] Tx diff = %llu\n", tx_diff);
	printf("[softreset] Rx diff = %llu\n", rx_diff);
	nvram_commit();
	return 1;
}
/* ======================= SOFT RESET CONFIG ================================= */
