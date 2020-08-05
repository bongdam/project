#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "snmp_main.h"
#include "agt_engine.h"
#include "cjhv_api.h"
#include "cjhv_mib.h"
#include "snmp_trap.h"

extern _con_staInfo_t_ staInfo[MAX_STA_NUM];
extern _con_hostInfo_t_ hostInfo[MAX_STA_NUM];
extern unsigned int adjacent_channel[13];

extern unsigned char *build_snmp_response_without_list_of_varbind(raw_snmp_info_t *pi);

static void init_trapserver(char *serv_ip)
{
	memset(dvsnmp_cfg.trapserver[0], 0, DVSNMP_MAX_TRAP_SERVER_LEN);
	strncpy(dvsnmp_cfg.trapserver[0], serv_ip, DVSNMP_MAX_TRAP_SERVER_LEN);
}

static void static_get_dnsAddress(long *dns)
{
	char dnsIp1[32];

	nvram_get_r("DNS1", dnsIp1, sizeof(dnsIp1));
	*dns = inet_addr(dnsIp1);
	return;
}

static void static_get_dns2Address(long *dns2)
{
	char dnsIp2[32];

	nvram_get_r("DNS2", dnsIp2, sizeof(dnsIp2));
	*dns2 = inet_addr(dnsIp2);
	return;
}

static unsigned char *make_resp_tail(raw_snmp_info_t * pMsg, unsigned char *out_data, int *p_out_length)
{
	pMsg->response_packet_end = out_data;

	*p_out_length = correct_snmp_response_with_lengths(pMsg, 0, 0);
	out_data = asn_build_sequence(pMsg->response_pdu, p_out_length,
			pMsg->mesg.pdutype, pMsg->response_packet_end - pMsg->response_request_id);

	RETURN_ON_BUILD_ERROR(out_data, "build trap pdu type");
	return (out_data);
}

static void possible_snmp_trap(void)
{
	struct in_addr in;
	char ip[16];

	while (1) {
		nvram_get_r("apms_ip", ip, sizeof(ip));
		if (access(NTP_OK, F_OK) == 0 && (inet_aton(ip, &in) != 0)
				&& (in.s_addr > 0 && in.s_addr < 0xffffffff))
			break;
		sleep(1);
	}
}

static unsigned long get_random_time(unsigned long max)
{
	static char mac[20];
	int val;
	int t[6];

	if (mac[0] == 0)
		nvram_get_r("HW_NIC1_ADDR", mac, sizeof(mac));
	val = sscanf(mac, "%02x%02x%02x%02x%02x%02x", &t[0], &t[1], &t[2], &t[3], &t[4], &t[5]);
	if (val != 6 || max == 0)
		return 0;

	srand((unsigned int)t[5]);
	val = (rand() % max);
	if (val == 0)
		return max;

	return val;
}

static void init_snmp_trap_value(traplist_t *tlist)
{
	char val[16];

	nvram_get_r_def("normaltrap_per_min", val, sizeof(val), "30");
	tlist->normal.period = (strtoul(val, NULL, 10) * 60);
	nvram_get_r_def("wlantrap_per_min", val, sizeof(val), "1440");
	tlist->wlaninfo.period = (strtoul(val, NULL, 10) * 60);
	nvram_get_r_def("clienttrap_per_min", val, sizeof(val), "720");
	tlist->client.period = (strtoul(val, NULL, 10) * 60);
	nvram_get_r_def("dummy_per_min", val, sizeof(val), "1");
	tlist->dummy.period = (strtoul(val, NULL, 10) * 60);
	tlist->dummy.next = ygettime(NULL) + tlist->dummy.period;

	nvram_get_r_def("DNS_MODE", val, sizeof(val), "0");
	if (val[0] == '1') {
		tlist->dnsmode = 1;
		nvram_get_r("DNS2", tlist->dns2, sizeof(tlist->dns2));
	}
	nvram_get_r("apms_ip", val, sizeof(val));
	init_trapserver(val);
}

static int chk_trapserver(void)
{
	if (dvsnmp_cfg.trapserver[0] == 0) {
		printf("Trap server address error - [%s]\n", dvsnmp_cfg.trapserver[0]);
		return 0;
	}

	return 1;
}

static unsigned long get_request_id(void)
{
	static unsigned long rand_value = 0;

	if (rand_value == 0)
		rand_value = ((rand() << 16) + rand());

	return rand_value;
}

static unsigned int current_sysUpTime(void)
{
	int proc_time, proc_time2;

	if (yfcat("/proc/uptime", "%d.%d", &proc_time, &proc_time2) > 0)
		return (proc_time * 100) + proc_time2;

	return 0;
}

unsigned char *make_trap_v2c_headr(raw_snmp_info_t *pMsg,
		int *p_out_length, oid *pTrapOid, int oid_len)
{
	oid oid_sysUpTime[] = { O_sysUpTime };
	oid oid_trapOid[] = { O_snmpTrapOID, 0 };
	Oid oid_obj;
	unsigned char *out_data;

	pMsg->mesg.version = SNMP_VERSION_2C;
	pMsg->mesg.pdutype = SNMP_TRP2_REQ_PDU;
	strcpy(pMsg->mesg.community, dvsnmp_cfg.trpcommunity);
	pMsg->mesg.community_length = strlen(pMsg->mesg.community);
	pMsg->mesg.community_id = 0;

	pMsg->mesg.request_id = get_request_id();
	out_data = (unsigned char *)build_snmp_response_without_list_of_varbind(pMsg);
	RETURN_ON_BUILD_ERROR(out_data, "build request id");

	// build sysUpTIme
	oid_obj.namelen = sizeof(oid_sysUpTime) / sizeof(oid);
	memcpy(oid_obj.name, oid_sysUpTime, sizeof(oid_sysUpTime));
	long_return = (long)current_sysUpTime();
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_TIMETICKS, sizeof(int), (unsigned char *)&long_return, p_out_length);
	RETURN_ON_BUILD_ERROR(out_data, "build trap sysUpTime");

	// build Trap oid
	oid_obj.namelen = sizeof(oid_trapOid) / sizeof(oid);
	memcpy(oid_obj.name, oid_trapOid, sizeof(oid_trapOid));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_OBJID, oid_len, (unsigned char *)pTrapOid, p_out_length);
	RETURN_ON_BUILD_ERROR(out_data, "build trap trapOid");

	return (out_data);
}

static int getInAddr(char *interface, struct in_addr *pAddr)
{
    struct ifreq ifr;
    int skfd = 0, found = 0;
    struct sockaddr_in *addr;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd < 0)
		return 0;

	strcpy(ifr.ifr_name, interface);

	if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
		close(skfd);
		return 0;
	}

	if (ioctl(skfd, SIOCGIFADDR, &ifr) == 0) {
		addr = ((struct sockaddr_in *)&ifr.ifr_addr);
		*pAddr = *((struct in_addr *)&addr->sin_addr);
		found = 1;
	}

	close(skfd);
	return found;
}

static int snmp_send_trap(raw_snmp_info_t *pMsg, char *trap_ip, unsigned short trap_port, int hole_trap)
{
	int trap_sock, TTL;
	struct sockaddr_in server_addr;
	struct sockaddr_in my;
	int ret, log = 1, optval = 1, val = 0;
	struct in_addr intaddr;
	char buf[32];

	trap_sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (trap_sock < 0) {
		perror("socket");
		return (2);
	}

	if (trap_port == 0)
		trap_port = 20161;

	if (setsockopt(trap_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
		perror("setsockopt() error");
		return (2);
	}

	if (hole_trap) {
		nvram_get_r_def("dummy_ttl", buf, sizeof(buf), "3");
		TTL = atoi(buf);
		log = 0;

		if (setsockopt(trap_sock, IPPROTO_IP, IP_TTL, &TTL, sizeof(TTL)) < 0) {
			perror("setsockopt() error");
			return (2);
		}
	} else {
		nvram_get_r_def("normal_ttl", buf, sizeof(buf), "255");
		TTL = atoi(buf);
		if (setsockopt(trap_sock, IPPROTO_IP, IP_TTL, &TTL, sizeof(TTL)) < 0) {
			perror("setsockopt() error");
			return (2);
		}
	}

	memset(&my, 0, sizeof(my));
	my.sin_family = AF_INET;
	yfcat("/var/sys_op", "%d", &val);
	if (val == 0) {
		if (getInAddr("br0", &intaddr))
			my.sin_addr.s_addr = intaddr.s_addr;
	}

	my.sin_port = htons(trap_port);
	if ((ret = bind(trap_sock, (struct sockaddr *)&my, sizeof(my))) < 0) {
		perror("bind() error\n");
		return (2);
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(trap_ip);
	server_addr.sin_port = htons(trap_port);
	if ((ret = sendto(trap_sock, (char *)pMsg->response,
					pMsg->response_length, 0,
					(struct sockaddr *)&server_addr,
					sizeof(server_addr))) < 0) {
		perror("sendto trapSocket");
		syslog(LOG_NOTICE, "SNMP: fail sent trap to %s:%d\n", trap_ip, trap_port);
		close(trap_sock);
		return 1;
	}
	if (log)
		syslog(LOG_NOTICE, "SNMP: sent trap to %s:%d\n", trap_ip, trap_port);

	close(trap_sock);

	return 0;
}

int send_softReset_trap_message(void)
{
	int out_length = SNMP_MAX_MSG_LENGTH;
	char string_return[80];
	unsigned long counter = 0;
	unsigned char *out_data;
	char apms_ip[32] = {0,};
	raw_snmp_info_t message;
	Oid oid_obj;
	oid oid_cjhvApTrapSoftReset[] = { O_cjhvApTrapSoftReset };
	oid oid_wanMac[] = { O_cjhvApWanMacAddress };
	oid oid_softReset[] = { O_cjhvApSystemSoftResetResult };

	nvram_get_r_def("apms_ip", apms_ip, sizeof(apms_ip), "0.0.0.0");
	if (strcmp(apms_ip, "0.0.0.0") == 0)
		return 0;

	memset((unsigned char *)&message, 0x00, sizeof(message));

	// build sendAutoTransmission header
	out_data = make_trap_v2c_headr(&message, &out_length, oid_cjhvApTrapSoftReset, sizeof(oid_cjhvApTrapSoftReset));
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_v2c_headr - send oid_cjhvApTrapSoftReset");

	// build sendAutoTransmission body
	//oid_wanMacAddress
	get_mac(string_return, sizeof(string_return));
	oid_obj.namelen = sizeof(oid_wanMac) / sizeof(oid);
	memcpy(oid_obj.name, oid_wanMac, sizeof(oid_wanMac));
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR, 6, (unsigned char *)string_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_wanMac error");

	//softReset_result
	nvram_get_r_def("softreset_result", string_return, sizeof(string_return), "2");
	counter = strtoul(string_return, NULL, 10);
	oid_obj.namelen = sizeof(oid_softReset) / sizeof(oid);
	memcpy(oid_obj.name, oid_softReset, sizeof(oid_softReset));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_COUNTER, sizeof(counter), (unsigned char *)&counter, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_softReset error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	snmp_send_trap(&message, apms_ip, (unsigned short)strtoul(nvram_get("snmp_trp_port"), NULL, 10), 0);

	return 0;
}

int sendAutoTransmission_ping(void)
{
	int out_length = SNMP_MAX_MSG_LENGTH;
	char string_return[80];
	char apms_ip[32] = {0,};
	long long_return = 0;
	unsigned long counter = 0;
	unsigned char *out_data;
	raw_snmp_info_t message;
	Oid oid_obj;
	oid oid_cjhvApTrapPing[] = { O_cjhvApTrapPing };
	oid oid_wanMac[] = { O_cjhvApWanMacAddress };
	oid oid_pingAddress[] = { O_pingAddress };
	oid oid_pingPacketCount[] = { O_pingPacketCount };
	oid oid_pingPacketSize[] = { O_pingPacketSize };
	oid oid_pingPacketTimeout[] = { O_pingPacketTimeout };
	oid oid_pingDelay[] = { O_pingDelay };
	oid oid_pingSentPackets[] = { O_pingSentPackets };
	oid oid_pingReceivedPackets[] = { O_pingReceivedPackets };
	oid oid_pingMinRtt[] = { O_pingMinRtt };
	oid oid_pingAvgRtt[] = {O_pingAvgRtt };
	oid oid_pingMaxRtt[] = { O_pingMaxRtt };
	oid oid_pingCompleted[] = { O_pingCompleted };
	oid oid_pingResultCode[] = { O_pingResultCode };
	oid oid_pingTestStartTime[] = { O_pingTestStartTime };
	oid oid_pingTestEndTime[] = { O_pingTestEndTime };

	nvram_get_r_def("apms_ip", apms_ip, sizeof(apms_ip), "0.0.0.0");
	if (strcmp(apms_ip, "0.0.0.0") == 0)
		return 0;

	memset((unsigned char *)&message, 0x00, sizeof(message));

	// build sendAutoTransmission header
	out_data = make_trap_v2c_headr(&message, &out_length, oid_cjhvApTrapPing, sizeof(oid_cjhvApTrapPing));
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_v2c_headr - send oid_cjhvApTrapPing");

	// build sendAutoTransmission body
	//oid_wanMacAddress
	get_mac(string_return, sizeof(string_return));
	oid_obj.namelen = sizeof(oid_wanMac) / sizeof(oid);
	memcpy(oid_obj.name, oid_wanMac, sizeof(oid_wanMac));
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR, 6, (unsigned char *)string_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_wanMac error");

	//oid_pingAddress
	get_pingAddress(string_return, sizeof(string_return));
	oid_obj.namelen = sizeof(oid_pingAddress) / sizeof(oid);
	memcpy(oid_obj.name, oid_pingAddress, sizeof(oid_pingAddress));
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR, strlen(string_return), (unsigned char *)string_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_pingAddress error");

	//oid_pingPacketCount
	get_pktCount(&counter);
	oid_obj.namelen = sizeof(oid_pingPacketCount) / sizeof(oid);
	memcpy(oid_obj.name, oid_pingPacketCount, sizeof(oid_pingPacketCount));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_COUNTER, sizeof(long), (unsigned char *)&counter, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_pingPacketCount error");

	//oid_pingPacketSize
	get_pktSize(&counter);
	oid_obj.namelen = sizeof(oid_pingPacketSize) / sizeof(oid);
	memcpy(oid_obj.name, oid_pingPacketSize, sizeof(oid_pingPacketSize));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_COUNTER, sizeof(counter), (unsigned char *)&counter, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_pingPacketSize error");

	//oid_pingPacketTimeout
	get_pktTimeout(&counter);
	oid_obj.namelen = sizeof(oid_pingPacketTimeout) / sizeof(oid);
	memcpy(oid_obj.name, oid_pingPacketTimeout, sizeof(oid_pingPacketTimeout));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_COUNTER, sizeof(counter), (unsigned char *)&counter, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_pingPacketTimeout error");

	//oid_pingDelay
	get_pktDelay(&counter);
	oid_obj.namelen = sizeof(oid_pingDelay) / sizeof(oid);
	memcpy(oid_obj.name, oid_pingDelay, sizeof(oid_pingDelay));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_COUNTER, sizeof(counter), (unsigned char *)&counter, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_pingDelay error");

	//oid_pingSentPackets
	get_sentPktCount(&counter);
	oid_obj.namelen = sizeof(oid_pingSentPackets) / sizeof(oid);
	memcpy(oid_obj.name, oid_pingSentPackets, sizeof(oid_pingSentPackets));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_COUNTER, sizeof(counter), (unsigned char *)&counter, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_pingSentPackets error");

	//oid_pingReceivedPackets
	get_recvPktCount(&counter);
	oid_obj.namelen = sizeof(oid_pingReceivedPackets) / sizeof(oid);
	memcpy(oid_obj.name, oid_pingReceivedPackets, sizeof(oid_pingReceivedPackets));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_COUNTER, sizeof(counter), (unsigned char *)&counter, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_pingReceivedPackets error");

	//oid_pingMinRtt
	get_minPingTime(&counter);
	oid_obj.namelen = sizeof(oid_pingMinRtt) / sizeof(oid);
	memcpy(oid_obj.name, oid_pingMinRtt, sizeof(oid_pingMinRtt));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_COUNTER, sizeof(counter), (unsigned char *)&counter, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_pingMinRtt error");

	//oid_pingAvgRtt
	get_avgPingTime(&counter);
	oid_obj.namelen = sizeof(oid_pingAvgRtt) / sizeof(oid);
	memcpy(oid_obj.name, oid_pingAvgRtt, sizeof(oid_pingAvgRtt));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_COUNTER, sizeof(counter), (unsigned char *)&counter, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_pingAvgRtt error");

	//oid_pingMaxRtt
	get_maxPingTime(&counter);
	oid_obj.namelen = sizeof(oid_pingMaxRtt) / sizeof(oid);
	memcpy(oid_obj.name, oid_pingMaxRtt, sizeof(oid_pingMaxRtt));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_COUNTER, sizeof(counter), (unsigned char *)&counter, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_pingMaxRtt error");

	//oid_pingCompleted
	get_pingCompleted(&long_return);
	oid_obj.namelen = sizeof(oid_pingCompleted) / sizeof(oid);
	memcpy(oid_obj.name, oid_pingCompleted, sizeof(oid_pingCompleted));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER, sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_pingCompleted error");

	//oid_pingResultCode
	get_pingResultCode(&long_return);
	oid_obj.namelen = sizeof(oid_pingResultCode) / sizeof(oid);
	memcpy(oid_obj.name, oid_pingResultCode, sizeof(oid_pingResultCode));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER, sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_pingResultCode error");

	//oid_pingTestStartTime
	get_pingStarttime(string_return, sizeof(string_return));
	oid_obj.namelen = sizeof(oid_pingTestStartTime) / sizeof(oid);
	memcpy(oid_obj.name, oid_pingTestStartTime, sizeof(oid_pingTestStartTime));
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR, strlen(string_return), (unsigned char *)string_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_pingTestStartTime error");

	//oid_pingTestEndTime
	get_pingEndtime(string_return, sizeof(string_return));
	oid_obj.namelen = sizeof(oid_pingTestEndTime) / sizeof(oid);
	memcpy(oid_obj.name, oid_pingTestEndTime, sizeof(oid_pingTestEndTime));
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR, strlen(string_return), (unsigned char *)string_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_pingTestEndTime error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	snmp_send_trap(&message, apms_ip, (unsigned short)strtoul(nvram_get("snmp_trp_port"), NULL, 10), 0);

	return 0;
}

static int send_trap_normal(void)
{
	int out_length = SNMP_MAX_MSG_LENGTH;
	char string_return[80];
	long long_return = 0;
	unsigned char *out_data;
	raw_snmp_info_t message;
	Oid oid_obj;
	oid oid_cjhvApTrapNormal[] = { O_cjhvApTrapNormal };

	oid oid_modelName[] = { O_cjhvApSysModelName };
	oid oid_version[] = { O_cjhvApSysFirmwareVersion };
	oid oid_sysUptime[] = { O_cjhvApSysuptime };
	oid oid_wanStatus[] = {O_cjhvApWanStatus};
	oid oid_mac[] = { O_cjhvApWanMacAddress };
	oid oid_wanIpAddress[] = { O_cjhvApWanIpAddress };
	oid oid_wanDNS1[] = {O_cjhvApWanDNS1 };
	oid oid_wanDNS2[] = { O_cjhvApWanDNS2 };
	oid oid_wanUptime[] = { O_cjhvApWanUpTime };
	oid oid_dmzEnable[] = { O_cjhvApDmzEnable };
	oid oid_dmzIp[] = { O_cjhvApDmzIp };
	oid oid_telnetEnable[] = { O_cjhvApTelnetInfoEnable };
	oid oid_cpu[] = { O_cjhvApSysCpu };
	oid oid_ram[] = { O_cjhvApSysMemory };
	oid oid_aclModeEnable[] = { O_cjhvApACLInfoEnable };
	oid oid_WebModeEnable[] = { O_cjhvApWebinfoEnable };

	if (chk_trapserver() == 0)
		return 0;

	memset((unsigned char *)&message, 0x00, sizeof(message));

	// build sendAutoTransmission header
	out_data = make_trap_v2c_headr(&message, &out_length, oid_cjhvApTrapNormal,
			sizeof(oid_cjhvApTrapNormal));
	RETURN_ON_BUILD_ERROR(out_data,
			"make_trap_v2c_headr - send oid_cjhvApTrapNormal");

	// build sendAutoTransmission body
	//oid_modelName
	get_modelName(string_return, sizeof(string_return));
	oid_obj.namelen = sizeof(oid_modelName) / sizeof(oid);
	memcpy(oid_obj.name, oid_modelName, sizeof(oid_modelName));
	long_return = 1;
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
			strlen(string_return), (unsigned char *)string_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_modelName error");

	//oid_version
	get_version(string_return, sizeof(string_return));
	oid_obj.namelen = sizeof(oid_version) / sizeof(oid);
	memcpy(oid_obj.name, oid_version, sizeof(oid_version));
	long_return = 1;
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
			strlen(string_return), (unsigned char *)string_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_version error");

	//oid_Sysuptime
	get_uptime(string_return, sizeof(string_return), UPTIME);
	oid_obj.namelen = sizeof(oid_sysUptime) / sizeof(oid);
	memcpy(oid_obj.name, oid_sysUptime, sizeof(oid_sysUptime));
	long_return = 1;
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
			strlen(string_return), (unsigned char *)string_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_sysUptime error");

	//oid_wanStatus
	long_return = get_wan_status();
	oid_obj.namelen = sizeof(oid_wanStatus) / sizeof(oid);
	memcpy(oid_obj.name, oid_wanStatus, sizeof(oid_wanStatus));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_wanStatus error");

	//oid_wanMacAddress
	get_mac(string_return, 6);
	oid_obj.namelen = sizeof(oid_mac) / sizeof(oid);
	memcpy(oid_obj.name, oid_mac, sizeof(oid_mac));
	long_return = 1;
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
			6, (unsigned char *)string_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_mac error");

	//oid_wanIpAddress
	long_return = 0;
	get_trap_wanIpAddress((unsigned long *)&long_return);
	oid_obj.namelen = sizeof(oid_wanIpAddress) / sizeof(oid);
	memcpy(oid_obj.name, oid_wanIpAddress, sizeof(oid_wanIpAddress));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_wanIpAddress error");

	//oid_wanDNS1
	long_return = 0;
	get_dnsAddress((unsigned long *)&long_return, 1);
	oid_obj.namelen = sizeof(oid_wanDNS1) / sizeof(oid);
	memcpy(oid_obj.name, oid_wanDNS1, sizeof(oid_wanDNS1));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_wanDNS1 error");

	//oid_wanDNS2
	long_return = 0;
	get_dnsAddress((unsigned long *)&long_return, 2);
	oid_obj.namelen = sizeof(oid_wanDNS2) / sizeof(oid);
	memcpy(oid_obj.name, oid_wanDNS2, sizeof(oid_wanDNS2));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_wanDNS2 error");

	//oid_wanUptime
	get_uptime(string_return, sizeof(string_return), WANUPTIME);
	oid_obj.namelen = sizeof(oid_wanUptime) / sizeof(oid);
	memcpy(oid_obj.name, oid_wanUptime, sizeof(oid_wanUptime));
	long_return = 1;
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
			strlen(string_return), (unsigned char *)string_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_wanUptime error");

	//oid_dmzEnable
	long_return = get_dmzEnable();
	oid_obj.namelen = sizeof(oid_dmzEnable) / sizeof(oid);
	memcpy(oid_obj.name, oid_dmzEnable, sizeof(oid_dmzEnable));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_dmzEnable error");

	//oid_dmzIp
	long_return = 0;
	get_dmzIpAddress((unsigned long *)&long_return);
	oid_obj.namelen = sizeof(oid_dmzIp) / sizeof(oid);
	memcpy(oid_obj.name, oid_dmzIp, sizeof(oid_dmzIp));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_dmzIp error");

	//oid_telnetEnable
	long_return = 0;
	long_return = get_telnetEnable();
	oid_obj.namelen = sizeof(oid_telnetEnable) / sizeof(oid);
	memcpy(oid_obj.name, oid_telnetEnable, sizeof(oid_telnetEnable));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_telnetEnable error");

	//long get_cpu_utiliz(void)
	long_return = get_cpu_utiliz();
	oid_obj.namelen = sizeof(oid_cpu) / sizeof(oid);
	memcpy(oid_obj.name, oid_cpu, sizeof(oid_cpu));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_cpu error");

	//long get_ram_utiliz(void)
	long_return = get_ram_utiliz();
	oid_obj.namelen = sizeof(oid_ram) / sizeof(oid);
	memcpy(oid_obj.name, oid_ram, sizeof(oid_ram));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_ram error");

	//oid_aclModeEnable
	long_return = 0;
	long_return = get_aclEnable();
	oid_obj.namelen = sizeof(oid_aclModeEnable) / sizeof(oid);
	memcpy(oid_obj.name, oid_aclModeEnable, sizeof(oid_aclModeEnable));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_aclModeEnable error");

	//oid_WebModeEnable
	long_return = 0;
	long_return = get_WebEnable();
	oid_obj.namelen = sizeof(oid_WebModeEnable) / sizeof(oid);
	memcpy(oid_obj.name, oid_WebModeEnable, sizeof(oid_WebModeEnable));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_WebModeEnable error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	snmp_send_trap(&message, dvsnmp_cfg.trapserver[0],
			(unsigned short)strtoul(nvram_get("snmp_trp_port"), NULL, 10), 0);

	return 0;
}

static int send_trap_wlaninfo(void)
{
	int out_length = SNMP_MAX_MSG_LENGTH;
	char string_return[80];
	long long_return = 0;
	unsigned char *out_data;
	raw_snmp_info_t message;
	Oid oid_obj;
	oid oid_cjhvApTrapWlanAdjacentChannel[] = { O_cjhvApWlanInfoTrap };

	oid oid_mac[] = { O_cjhvApWanMacAddress };
	oid oid_apch[] = { O_cjhvApWlanChannelNumber };
	oid oid_apchwidth[] = { O_cjhvApWlanChannelWidth } ;
	oid oid_adjchannel_idx1[] = { O_cjhvApWlanAdjacentChannelTrapIndex1 };
	oid oid_adjchannel_num1[] = { O_cjhvApWlanAdjacentChannelTrapNumber1 };
	oid oid_adjchannel_count1[] = { O_cjhvApWlanAdjacentChannelTrapCount1 };
	oid oid_adjchannel_idx2[] = { O_cjhvApWlanAdjacentChannelTrapIndex2 };
	oid oid_adjchannel_num2[] = { O_cjhvApWlanAdjacentChannelTrapNumber2 };
	oid oid_adjchannel_count2[] = { O_cjhvApWlanAdjacentChannelTrapCount2 };
	oid oid_adjchannel_idx3[] = { O_cjhvApWlanAdjacentChannelTrapIndex3 };
	oid oid_adjchannel_num3[] = { O_cjhvApWlanAdjacentChannelTrapNumber3 };
	oid oid_adjchannel_count3[] = { O_cjhvApWlanAdjacentChannelTrapCount3 };
	oid oid_adjchannel_idx4[] = { O_cjhvApWlanAdjacentChannelTrapIndex4 };
	oid oid_adjchannel_num4[] = { O_cjhvApWlanAdjacentChannelTrapNumber4 };
	oid oid_adjchannel_count4[] = { O_cjhvApWlanAdjacentChannelTrapCount4 };
	oid oid_adjchannel_idx5[] = { O_cjhvApWlanAdjacentChannelTrapIndex5 };
	oid oid_adjchannel_num5[] = { O_cjhvApWlanAdjacentChannelTrapNumber5 };
	oid oid_adjchannel_count5[] = { O_cjhvApWlanAdjacentChannelTrapCount5 };
	oid oid_adjchannel_idx6[] = { O_cjhvApWlanAdjacentChannelTrapIndex6 };
	oid oid_adjchannel_num6[] = { O_cjhvApWlanAdjacentChannelTrapNumber6 };
	oid oid_adjchannel_count6[] = { O_cjhvApWlanAdjacentChannelTrapCount6 };
	oid oid_adjchannel_idx7[] = { O_cjhvApWlanAdjacentChannelTrapIndex7 };
	oid oid_adjchannel_num7[] = { O_cjhvApWlanAdjacentChannelTrapNumber7 };
	oid oid_adjchannel_count7[] = { O_cjhvApWlanAdjacentChannelTrapCount7 };
	oid oid_adjchannel_idx8[] = { O_cjhvApWlanAdjacentChannelTrapIndex8 };
	oid oid_adjchannel_num8[] = { O_cjhvApWlanAdjacentChannelTrapNumber8 };
	oid oid_adjchannel_count8[] = { O_cjhvApWlanAdjacentChannelTrapCount8 };
	oid oid_adjchannel_idx9[] = { O_cjhvApWlanAdjacentChannelTrapIndex9 };
	oid oid_adjchannel_num9[] = { O_cjhvApWlanAdjacentChannelTrapNumber9 };
	oid oid_adjchannel_count9[] = { O_cjhvApWlanAdjacentChannelTrapCount9 };
	oid oid_adjchannel_idx10[] = { O_cjhvApWlanAdjacentChannelTrapIndex10 };
	oid oid_adjchannel_num10[] = { O_cjhvApWlanAdjacentChannelTrapNumber10 };
	oid oid_adjchannel_count10[] = { O_cjhvApWlanAdjacentChannelTrapCount10 };
	oid oid_adjchannel_idx11[] = { O_cjhvApWlanAdjacentChannelTrapIndex11 };
	oid oid_adjchannel_num11[] = { O_cjhvApWlanAdjacentChannelTrapNumber11 };
	oid oid_adjchannel_count11[] = { O_cjhvApWlanAdjacentChannelTrapCount11 };
	oid oid_adjchannel_idx12[] = { O_cjhvApWlanAdjacentChannelTrapIndex12 };
	oid oid_adjchannel_num12[] = { O_cjhvApWlanAdjacentChannelTrapNumber12 };
	oid oid_adjchannel_count12[] = { O_cjhvApWlanAdjacentChannelTrapCount12 };
	oid oid_adjchannel_idx13[] = { O_cjhvApWlanAdjacentChannelTrapIndex13 };
	oid oid_adjchannel_num13[] = { O_cjhvApWlanAdjacentChannelTrapNumber13 };
	oid oid_adjchannel_count13[] = { O_cjhvApWlanAdjacentChannelTrapCount13 };
	/* 5G pass */

	if (chk_trapserver() == 0)
		return 0;

	if (get_wlanMode(WLAN_2G) == 1) {
		if (surveyRequest(WLAN_2G) < 0)
			return 0;
	}
	usleep(2000000);
	if (getWlanScanInfo(WLAN_2G) < 0)
		return 0;

	memset((unsigned char *)&message, 0x00, sizeof(message));

	// build sendAutoTransmission header
	out_data = make_trap_v2c_headr(&message, &out_length, oid_cjhvApTrapWlanAdjacentChannel,
			sizeof(oid_cjhvApTrapWlanAdjacentChannel));
	RETURN_ON_BUILD_ERROR(out_data,
			"make_trap_v2c_headr - sendoid_cjhvApTrapWlanAdjacentChannel");

	// build sendAutoTransmission body
	//oid_wanMacAddress
	get_mac(string_return, 6);
	oid_obj.namelen = sizeof(oid_mac) / sizeof(oid);
	memcpy(oid_obj.name, oid_mac, sizeof(oid_mac));
	long_return = 1;
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
			6, (unsigned char *)string_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_mac error");

	//oid_ApChannel
	long_return = get_wlanChannelNumber(WLAN_2G);
	oid_obj.namelen = sizeof(oid_apch) / sizeof(oid);
	memcpy(oid_obj.name, oid_apch, sizeof(oid_apch));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_apch error");

	//oid_ApChWidth
	long_return = get_wlanChannelWidth(WLAN_2G);
	oid_obj.namelen = sizeof(oid_apchwidth) / sizeof(oid);
	memcpy(oid_obj.name, oid_apchwidth, sizeof(oid_apchwidth));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_apchwidth error");

	//oid_adjchannel_idx1
	long_return = 1;
	oid_obj.namelen = sizeof(oid_adjchannel_idx1) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_idx1, sizeof(oid_adjchannel_idx1));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_idx1 error");

	//oid_adjchannel_num1
	long_return = 1;
	oid_obj.namelen = sizeof(oid_adjchannel_num1) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_num1, sizeof(oid_adjchannel_num1));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_num1 error");

	//oid_adjchannel_count1
	long_return = adjacent_channel[0];
	oid_obj.namelen = sizeof(oid_adjchannel_count1) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_count1, sizeof(oid_adjchannel_count1));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_count1 error");

	//oid_adjchannel_idx2
	long_return = 2;
	oid_obj.namelen = sizeof(oid_adjchannel_idx2) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_idx2, sizeof(oid_adjchannel_idx2));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_idx2 error");

	//oid_adjchannel_num2
	long_return = 2;
	oid_obj.namelen = sizeof(oid_adjchannel_num2) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_num2, sizeof(oid_adjchannel_num2));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_num2 error");

	//oid_adjchannel_count2
	long_return = adjacent_channel[1];
	oid_obj.namelen = sizeof(oid_adjchannel_count2) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_count2, sizeof(oid_adjchannel_count2));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_count2 error");

	//oid_adjchannel_idx3
	long_return = 3;
	oid_obj.namelen = sizeof(oid_adjchannel_idx3) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_idx3, sizeof(oid_adjchannel_idx3));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_idx3 error");

	//oid_adjchannel_num3
	long_return = 3;
	oid_obj.namelen = sizeof(oid_adjchannel_num3) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_num3, sizeof(oid_adjchannel_num3));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_num3 error");

	//oid_adjchannel_count3
	long_return = adjacent_channel[2];
	oid_obj.namelen = sizeof(oid_adjchannel_count3) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_count3, sizeof(oid_adjchannel_count3));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_count3 error");

	//oid_adjchannel_idx4
	long_return = 4;
	oid_obj.namelen = sizeof(oid_adjchannel_idx4) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_idx4, sizeof(oid_adjchannel_idx4));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_idx4 error");

	//oid_adjchannel_num4
	long_return = 4;
	oid_obj.namelen = sizeof(oid_adjchannel_num4) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_num4, sizeof(oid_adjchannel_num4));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_num4 error");

	//oid_adjchannel_count4
	long_return = adjacent_channel[3];
	oid_obj.namelen = sizeof(oid_adjchannel_count4) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_count4, sizeof(oid_adjchannel_count4));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_count4 error");

	//oid_adjchannel_idx5
	long_return = 5;
	oid_obj.namelen = sizeof(oid_adjchannel_idx5) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_idx5, sizeof(oid_adjchannel_idx5));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_idx5 error");

	//oid_adjchannel_num5
	long_return = 5;
	oid_obj.namelen = sizeof(oid_adjchannel_num5) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_num5, sizeof(oid_adjchannel_num5));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_num5 error");

	//oid_adjchannel_count5
	long_return = adjacent_channel[4];
	oid_obj.namelen = sizeof(oid_adjchannel_count5) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_count5, sizeof(oid_adjchannel_count5));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_count5 error");

	//oid_adjchannel_idx6
	long_return = 6;
	oid_obj.namelen = sizeof(oid_adjchannel_idx6) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_idx6, sizeof(oid_adjchannel_idx6));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_idx6 error");

	//oid_adjchannel_num6
	long_return = 6;
	oid_obj.namelen = sizeof(oid_adjchannel_num6) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_num6, sizeof(oid_adjchannel_num6));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_num6 error");

	//oid_adjchannel_count6
	long_return = adjacent_channel[5];
	oid_obj.namelen = sizeof(oid_adjchannel_count6) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_count6, sizeof(oid_adjchannel_count6));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_count6 error");

	//oid_adjchannel_idx7
	long_return = 7;
	oid_obj.namelen = sizeof(oid_adjchannel_idx7) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_idx7, sizeof(oid_adjchannel_idx7));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_idx7 error");

	//oid_adjchannel_num7
	long_return = 7;
	oid_obj.namelen = sizeof(oid_adjchannel_num7) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_num7, sizeof(oid_adjchannel_num7));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_num7 error");

	//oid_adjchannel_count7
	long_return = adjacent_channel[6];
	oid_obj.namelen = sizeof(oid_adjchannel_count7) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_count7, sizeof(oid_adjchannel_count7));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_count7 error");

	//oid_adjchannel_idx8
	long_return = 8;
	oid_obj.namelen = sizeof(oid_adjchannel_idx8) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_idx8, sizeof(oid_adjchannel_idx8));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_idx8 error");

	//oid_adjchannel_num8
	long_return = 8;
	oid_obj.namelen = sizeof(oid_adjchannel_num8) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_num8, sizeof(oid_adjchannel_num8));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_num8 error");

	//oid_adjchannel_count8
	long_return = adjacent_channel[7];
	oid_obj.namelen = sizeof(oid_adjchannel_count8) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_count8, sizeof(oid_adjchannel_count8));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_count8 error");

	//oid_adjchannel_idx9
	long_return = 9;
	oid_obj.namelen = sizeof(oid_adjchannel_idx9) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_idx9, sizeof(oid_adjchannel_idx9));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_idx9 error");

	//oid_adjchannel_num9
	long_return = 9;
	oid_obj.namelen = sizeof(oid_adjchannel_num9) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_num9, sizeof(oid_adjchannel_num9));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_num9 error");

	//oid_adjchannel_count9
	long_return = adjacent_channel[8];
	oid_obj.namelen = sizeof(oid_adjchannel_count9) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_count9, sizeof(oid_adjchannel_count9));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_count9 error");

	//oid_adjchannel_idx10
	long_return = 10;
	oid_obj.namelen = sizeof(oid_adjchannel_idx10) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_idx10, sizeof(oid_adjchannel_idx10));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_idx10 error");

	//oid_adjchannel_num10
	long_return = 10;
	oid_obj.namelen = sizeof(oid_adjchannel_num10) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_num10, sizeof(oid_adjchannel_num10));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_num10 error");

	//oid_adjchannel_count10
	long_return = adjacent_channel[9];
	oid_obj.namelen = sizeof(oid_adjchannel_count10) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_count10, sizeof(oid_adjchannel_count10));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_count10 error");

	//oid_adjchannel_idx11
	long_return = 11;
	oid_obj.namelen = sizeof(oid_adjchannel_idx11) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_idx11, sizeof(oid_adjchannel_idx11));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_idx11 error");

	//oid_adjchannel_num11
	long_return = 11;
	oid_obj.namelen = sizeof(oid_adjchannel_num11) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_num11, sizeof(oid_adjchannel_num11));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_num11 error");

	//oid_adjchannel_count11
	long_return = adjacent_channel[10];
	oid_obj.namelen = sizeof(oid_adjchannel_count11) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_count11, sizeof(oid_adjchannel_count11));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_count11 error");

	//oid_adjchannel_idx12
	long_return = 12;
	oid_obj.namelen = sizeof(oid_adjchannel_idx12) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_idx12, sizeof(oid_adjchannel_idx12));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_idx12 error");

	//oid_adjchannel_num12
	long_return = 12;
	oid_obj.namelen = sizeof(oid_adjchannel_num12) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_num12, sizeof(oid_adjchannel_num12));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_num12 error");

	//oid_adjchannel_count12
	long_return = adjacent_channel[11];
	oid_obj.namelen = sizeof(oid_adjchannel_count12) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_count12, sizeof(oid_adjchannel_count12));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_count12 error");

	//oid_adjchannel_idx13
	long_return = 13;
	oid_obj.namelen = sizeof(oid_adjchannel_idx13) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_idx13, sizeof(oid_adjchannel_idx13));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_idx13 error");

	//oid_adjchannel_num13
	long_return = 13;
	oid_obj.namelen = sizeof(oid_adjchannel_num13) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_num13, sizeof(oid_adjchannel_num13));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_num13 error");

	//oid_adjchannel_count13
	long_return = adjacent_channel[12];
	oid_obj.namelen = sizeof(oid_adjchannel_count13) / sizeof(oid);
	memcpy(oid_obj.name, oid_adjchannel_count13, sizeof(oid_adjchannel_count13));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_adjchannel_count13 error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	snmp_send_trap(&message, dvsnmp_cfg.trapserver[0],
			(unsigned short)strtoul(nvram_get("snmp_trp_port"), NULL, 10), 0);

	return 0;
}

static int send_trap_client(void)
{
	int out_length = SNMP_MAX_MSG_LENGTH;
	char string_return[80];
	char value[4];
	long long_return = 0;
	unsigned long crc_count = 0;
	unsigned char *out_data;
	int wlclient = 0;
	int client = 0;
	raw_snmp_info_t message;
	Oid oid_obj;
	oid oid_cjhvApClientTrap[] = { O_cjhvApClientInfoTrap };

	oid oid_mac[] = { O_cjhvApWanMacAddress };
	oid oid_client_idx1[] = { O_cjhvApWlanClientInfoTrapIndex1 };
	oid oid_client_mac1[] = { O_cjhvApWlanClientTrapMac1 };
	oid oid_client_ip1[] = { O_cjhvApWlanClientTrapIp1 };
	oid oid_client_name1[] = { O_cjhvApWlanClientTrapName1 };
	oid oid_client_mode1[] = { O_cjhvApWlanClientTrapMode1 };
	oid oid_client_band1[] = { O_cjhvApWlanClientTrapBand1 };
	oid oid_client_rssi1[] = { O_cjhvApWlanClientTrapRssi1 };

	oid oid_client_idx2[] = { O_cjhvApWlanClientInfoTrapIndex2 };
	oid oid_client_mac2[] = { O_cjhvApWlanClientTrapMac2 };
	oid oid_client_ip2[] = { O_cjhvApWlanClientTrapIp2 };
	oid oid_client_name2[] = { O_cjhvApWlanClientTrapName2 };
	oid oid_client_mode2[] = { O_cjhvApWlanClientTrapMode2 };
	oid oid_client_band2[] = { O_cjhvApWlanClientTrapBand2 };
	oid oid_client_rssi2[] = { O_cjhvApWlanClientTrapRssi2 };

	oid oid_client_idx3[] = { O_cjhvApWlanClientInfoTrapIndex3 };
	oid oid_client_mac3[] = { O_cjhvApWlanClientTrapMac3 };
	oid oid_client_ip3[] = { O_cjhvApWlanClientTrapIp3 };
	oid oid_client_name3[] = { O_cjhvApWlanClientTrapName3 };
	oid oid_client_mode3[] = { O_cjhvApWlanClientTrapMode3 };
	oid oid_client_band3[] = { O_cjhvApWlanClientTrapBand3 };
	oid oid_client_rssi3[] = { O_cjhvApWlanClientTrapRssi3 };

	oid oid_client_idx4[] = { O_cjhvApWlanClientInfoTrapIndex4 };
	oid oid_client_mac4[] = { O_cjhvApWlanClientTrapMac4 };
	oid oid_client_ip4[] = { O_cjhvApWlanClientTrapIp4 };
	oid oid_client_name4[] = { O_cjhvApWlanClientTrapName4 };
	oid oid_client_mode4[] = { O_cjhvApWlanClientTrapMode4 };
	oid oid_client_band4[] = { O_cjhvApWlanClientTrapBand4 };
	oid oid_client_rssi4[] = { O_cjhvApWlanClientTrapRssi4 };

	oid oid_client_idx5[] = { O_cjhvApWlanClientInfoTrapIndex5 };
	oid oid_client_mac5[] = { O_cjhvApWlanClientTrapMac5 };
	oid oid_client_ip5[] = { O_cjhvApWlanClientTrapIp5 };
	oid oid_client_name5[] = { O_cjhvApWlanClientTrapName5 };
	oid oid_client_mode5[] = { O_cjhvApWlanClientTrapMode5 };
	oid oid_client_band5[] = { O_cjhvApWlanClientTrapBand5 };
	oid oid_client_rssi5[] = { O_cjhvApWlanClientTrapRssi5 };

	oid oid_client_idx6[] = { O_cjhvApWlanClientInfoTrapIndex6 };
	oid oid_client_mac6[] = { O_cjhvApWlanClientTrapMac6 };
	oid oid_client_ip6[] = { O_cjhvApWlanClientTrapIp6 };
	oid oid_client_name6[] = { O_cjhvApWlanClientTrapName6 };
	oid oid_client_mode6[] = { O_cjhvApWlanClientTrapMode6 };
	oid oid_client_band6[] = { O_cjhvApWlanClientTrapBand6 };
	oid oid_client_rssi6[] = { O_cjhvApWlanClientTrapRssi6 };

	oid oid_client_idx7[] = { O_cjhvApWlanClientInfoTrapIndex7 };
	oid oid_client_mac7[] = { O_cjhvApWlanClientTrapMac7 };
	oid oid_client_ip7[] = { O_cjhvApWlanClientTrapIp7 };
	oid oid_client_name7[] = { O_cjhvApWlanClientTrapName7 };
	oid oid_client_crc7[] = { O_cjhvApWlanClientTrapCrc7 };

	oid oid_client_idx8[] = { O_cjhvApWlanClientInfoTrapIndex8 };
	oid oid_client_mac8[] = { O_cjhvApWlanClientTrapMac8 };
	oid oid_client_ip8[] = { O_cjhvApWlanClientTrapIp8 };
	oid oid_client_name8[] = { O_cjhvApWlanClientTrapName8 };
	oid oid_client_crc8[] = { O_cjhvApWlanClientTrapCrc8 };

	oid oid_client_idx9[] = { O_cjhvApWlanClientInfoTrapIndex9 };
	oid oid_client_mac9[] = { O_cjhvApWlanClientTrapMac9 };
	oid oid_client_ip9[] = { O_cjhvApWlanClientTrapIp9 };
	oid oid_client_name9[] = { O_cjhvApWlanClientTrapName9 };
	oid oid_client_crc9[] = { O_cjhvApWlanClientTrapCrc9 };

	oid oid_client_idx10[] = { O_cjhvApWlanClientInfoTrapIndex10 };
	oid oid_client_mac10[] = { O_cjhvApWlanClientTrapMac10 };
	oid oid_client_ip10[] = { O_cjhvApWlanClientTrapIp10 };
	oid oid_client_name10[] = { O_cjhvApWlanClientTrapName10 };
	oid oid_client_crc10[] = { O_cjhvApWlanClientTrapCrc10 };

	oid oid_wan_crc[] = { O_cjhvApSysWANCRC };

	if (chk_trapserver() == 0)
		return 0;

	if (get_wlanMode(WLAN_2G) == 1)
		wlclient = wirelessClientList(WLAN_2G, wlclient);
	if (wlclient < 6 && get_wlanMode(WLAN_5G) == 1)
		wlclient += wirelessClientList(WLAN_5G, wlclient);
	if (wlclient > 6)
		wlclient = 6;

	nvram_get_r_def("OP_MODE", value, sizeof(value), "0");
	if (value[0] == '0')
		client = initHostInfo();

	memset((unsigned char *)&message, 0x00, sizeof(message));

	// build sendAutoTransmission header
	out_data = make_trap_v2c_headr(&message, &out_length, oid_cjhvApClientTrap,
			sizeof(oid_cjhvApClientTrap));
	RETURN_ON_BUILD_ERROR(out_data,
			"make_trap_v2c_headr - send oid_cjhvApClientTrap");

	// build sendAutoTransmission body
	//oid_wanMacAddress
	get_mac(string_return, 6);
	oid_obj.namelen = sizeof(oid_mac) / sizeof(oid);
	memcpy(oid_obj.name, oid_mac, sizeof(oid_mac));

	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
			6, (unsigned char *)string_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_mac error");

	if ((wlclient + client) == 0) {
		//oid_wan_crc
		crc_count = get_portStatusCrc(PRTNR_WAN0);
		oid_obj.namelen = sizeof(oid_wan_crc) / sizeof(oid);
		memcpy(oid_obj.name, oid_wan_crc, sizeof(oid_wan_crc));
		out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_COUNTER,
				sizeof(long), (unsigned char *)&crc_count, &out_length);
		RETURN_ON_BUILD_ERROR(out_data, "oid_wan_crc error");

		// build tail and message length
		out_data = make_resp_tail(&message, out_data, &out_length);
		RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

		snmp_send_trap(&message, dvsnmp_cfg.trapserver[0],
				(unsigned short)strtoul(nvram_get("snmp_trp_port"), NULL, 10), 0);

		return 0;
	}

	if (wlclient >= 1) {
		//oid_client_idx1
		long_return = 1;
		oid_obj.namelen = sizeof(oid_client_idx1) / sizeof(oid);
		memcpy(oid_obj.name, oid_client_idx1, sizeof(oid_client_idx1));
		out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
				sizeof(long), (unsigned char *)&long_return, &out_length);
		RETURN_ON_BUILD_ERROR(out_data, "oid_client_idx1 error");

		//oid_client_mac1
		memset(string_return, 0, sizeof(string_return));
		memcpy(string_return, staInfo[0].mac, 6);
		oid_obj.namelen = sizeof(oid_client_mac1) / sizeof(oid);
		memcpy(oid_obj.name, oid_client_mac1, sizeof(oid_client_mac1));
		out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
				6, (unsigned char *)string_return, &out_length);
		RETURN_ON_BUILD_ERROR(out_data, "oid_client_mac1 error");

		//oid_client_ip1
		long_return = staInfo[0].ipaddress;
		oid_obj.namelen = sizeof(oid_client_ip1) / sizeof(oid);
		memcpy(oid_obj.name, oid_client_ip1, sizeof(oid_client_ip1));
		out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
				sizeof(long), (unsigned char *)&long_return, &out_length);
		RETURN_ON_BUILD_ERROR(out_data, "oid_client_ip1 error");

		//oid_client_name1
		memset(string_return, 0, sizeof(string_return));
		strcpy(string_return, staInfo[0].ssid);
		oid_obj.namelen = sizeof(oid_client_name1) / sizeof(oid);
		memcpy(oid_obj.name, oid_client_name1, sizeof(oid_client_name1));
		out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
				strlen(string_return), (unsigned char *)string_return, &out_length);
		RETURN_ON_BUILD_ERROR(out_data, "oid_client_name1 error");

		//oid_client_mode1
		get_wlanStaMode(0, &long_return);
		oid_obj.namelen = sizeof(oid_client_mode1) / sizeof(oid);
		memcpy(oid_obj.name, oid_client_mode1, sizeof(oid_client_mode1));
		out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
				sizeof(long), (unsigned char *)&long_return, &out_length);
		RETURN_ON_BUILD_ERROR(out_data, "oid_client_mode1 error");

		//oid_client_band1
		long_return = staInfo[0].bandwidth;
		oid_obj.namelen = sizeof(oid_client_band1) / sizeof(oid);
		memcpy(oid_obj.name, oid_client_band1, sizeof(oid_client_band1));
		out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
				sizeof(long), (unsigned char *)&long_return, &out_length);
		RETURN_ON_BUILD_ERROR(out_data, "oid_client_band1 error");

		//oid_client_rssi1
		get_wlanStaRssi(0, string_return, sizeof(string_return));
		oid_obj.namelen = sizeof(oid_client_rssi1) / sizeof(oid);
		memcpy(oid_obj.name, oid_client_rssi1, sizeof(oid_client_rssi1));
		out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
				strlen(string_return), (unsigned char *)string_return, &out_length);
		RETURN_ON_BUILD_ERROR(out_data, "oid_client_rssi1 error");

		//oid_client_idx2
		if (wlclient >= 2) {
			long_return = 2;
			oid_obj.namelen = sizeof(oid_client_idx2) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_idx2, sizeof(oid_client_idx2));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_idx2 error");

			//oid_client_mac2
			memset(string_return, 0, sizeof(string_return));
			memcpy(string_return, staInfo[1].mac, 6);
			oid_obj.namelen = sizeof(oid_client_mac2) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_mac2, sizeof(oid_client_mac2));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					6, (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_mac2 error");

			//oid_client_ip2
			long_return = staInfo[1].ipaddress;
			oid_obj.namelen = sizeof(oid_client_ip2) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_ip2, sizeof(oid_client_ip2));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_ip2 error");

			//oid_client_name2
			memset(string_return, 0, sizeof(string_return));
			strcpy(string_return, staInfo[1].ssid);
			oid_obj.namelen = sizeof(oid_client_name2) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_name2, sizeof(oid_client_name2));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					strlen(string_return), (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_name2 error");

			//oid_client_mode2
			get_wlanStaMode(1, &long_return);
			oid_obj.namelen = sizeof(oid_client_mode2) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_mode2, sizeof(oid_client_mode2));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_mode2 error");

			//oid_client_band2
			long_return = staInfo[1].bandwidth;
			oid_obj.namelen = sizeof(oid_client_band2) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_band2, sizeof(oid_client_band2));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_band2 error");

			//oid_client_rssi2
			get_wlanStaRssi(1, string_return, sizeof(string_return));
			oid_obj.namelen = sizeof(oid_client_rssi2) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_rssi2, sizeof(oid_client_rssi2));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					strlen(string_return), (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_rssi2 error");
		}

		//oid_client_idx3
		if (wlclient >= 3) {
			long_return = 3;
			oid_obj.namelen = sizeof(oid_client_idx3) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_idx3, sizeof(oid_client_idx3));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_idx3 error");

			//oid_client_mac3
			memset(string_return, 0, sizeof(string_return));
			memcpy(string_return, staInfo[2].mac, 6);
			oid_obj.namelen = sizeof(oid_client_mac3) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_mac3, sizeof(oid_client_mac3));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					6, (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_mac3 error");

			//oid_client_ip3
			long_return = staInfo[2].ipaddress;
			oid_obj.namelen = sizeof(oid_client_ip3) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_ip3, sizeof(oid_client_ip3));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_ip3 error");

			//oid_client_name3
			memset(string_return, 0, sizeof(string_return));
			strcpy(string_return, staInfo[2].ssid);
			oid_obj.namelen = sizeof(oid_client_name3) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_name3, sizeof(oid_client_name3));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					strlen(string_return), (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_name3 error");

			//oid_client_mode3
			get_wlanStaMode(2, &long_return);
			oid_obj.namelen = sizeof(oid_client_mode3) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_mode3, sizeof(oid_client_mode3));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_mode3 error");

			//oid_client_band3
			long_return = staInfo[2].bandwidth;
			oid_obj.namelen = sizeof(oid_client_band3) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_band3, sizeof(oid_client_band3));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_band3 error");

			//oid_client_rssi3
			get_wlanStaRssi(2, string_return, sizeof(string_return));
			oid_obj.namelen = sizeof(oid_client_rssi3) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_rssi3, sizeof(oid_client_rssi3));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					strlen(string_return), (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_rssi3 error");
		}

		//oid_client_idx4
		if (wlclient >= 4) {
			long_return = 4;
			oid_obj.namelen = sizeof(oid_client_idx4) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_idx4, sizeof(oid_client_idx4));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_idx4 error");

			//oid_client_mac4
			memset(string_return, 0, sizeof(string_return));
			memcpy(string_return, staInfo[3].mac, 6);
			oid_obj.namelen = sizeof(oid_client_mac4) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_mac4, sizeof(oid_client_mac4));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					6, (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_mac4 error");

			//oid_client_ip4
			long_return = staInfo[3].ipaddress;
			oid_obj.namelen = sizeof(oid_client_ip4) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_ip4, sizeof(oid_client_ip4));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_ip4 error");

			//oid_client_name4
			memset(string_return, 0, sizeof(string_return));
			strcpy(string_return, staInfo[3].ssid);
			oid_obj.namelen = sizeof(oid_client_name4) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_name4, sizeof(oid_client_name4));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					strlen(string_return), (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_name4 error");

			//oid_client_mode4
			get_wlanStaMode(3, &long_return);
			oid_obj.namelen = sizeof(oid_client_mode4) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_mode4, sizeof(oid_client_mode4));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_mode4 error");

			//oid_client_band4
			long_return = staInfo[3].bandwidth;
			oid_obj.namelen = sizeof(oid_client_band4) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_band4, sizeof(oid_client_band4));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_band4 error");

			//oid_client_rssi4
			get_wlanStaRssi(3, string_return, sizeof(string_return));
			oid_obj.namelen = sizeof(oid_client_rssi4) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_rssi4, sizeof(oid_client_rssi4));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					strlen(string_return), (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_rssi4 error");
		}

		//oid_client_idx5
		if (wlclient >= 5) {
			long_return = 5;
			oid_obj.namelen = sizeof(oid_client_idx5) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_idx5, sizeof(oid_client_idx5));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_idx5 error");

			//oid_client_mac5
			memset(string_return, 0, sizeof(string_return));
			memcpy(string_return, staInfo[4].mac, 6);
			oid_obj.namelen = sizeof(oid_client_mac5) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_mac5, sizeof(oid_client_mac5));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					6, (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_mac5 error");

			//oid_client_ip5
			long_return = staInfo[4].ipaddress;
			oid_obj.namelen = sizeof(oid_client_ip5) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_ip5, sizeof(oid_client_ip5));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_ip5 error");

			//oid_client_name5
			memset(string_return, 0, sizeof(string_return));
			strcpy(string_return, staInfo[4].ssid);
			oid_obj.namelen = sizeof(oid_client_name5) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_name5, sizeof(oid_client_name5));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					strlen(string_return), (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_name5 error");

			//oid_client_mode5
			get_wlanStaMode(4, &long_return);
			oid_obj.namelen = sizeof(oid_client_mode5) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_mode5, sizeof(oid_client_mode5));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_mode5 error");

			//oid_client_band5
			long_return = staInfo[4].bandwidth;
			oid_obj.namelen = sizeof(oid_client_band5) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_band5, sizeof(oid_client_band5));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_band5 error");

			//oid_client_rssi5
			get_wlanStaRssi(4, string_return, sizeof(string_return));
			oid_obj.namelen = sizeof(oid_client_rssi5) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_rssi5, sizeof(oid_client_rssi5));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					strlen(string_return), (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_rssi5 error");
		}

		//oid_client_idx6
		if (wlclient >= 6) {
			long_return = 6;
			oid_obj.namelen = sizeof(oid_client_idx6) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_idx6, sizeof(oid_client_idx6));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_idx6 error");

			//oid_client_mac6
			memset(string_return, 0, sizeof(string_return));
			memcpy(string_return, staInfo[5].mac, 6);
			oid_obj.namelen = sizeof(oid_client_mac6) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_mac6, sizeof(oid_client_mac6));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					6, (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_mac6 error");

			//oid_client_ip6
			long_return = staInfo[5].ipaddress;
			oid_obj.namelen = sizeof(oid_client_ip6) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_ip6, sizeof(oid_client_ip6));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_ip6 error");

			//oid_client_name6
			memset(string_return, 0, sizeof(string_return));
			strcpy(string_return, staInfo[5].ssid);
			oid_obj.namelen = sizeof(oid_client_name6) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_name6, sizeof(oid_client_name6));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					strlen(string_return), (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_name6 error");

			//oid_client_mode6
			get_wlanStaMode(5, &long_return);
			oid_obj.namelen = sizeof(oid_client_mode6) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_mode6, sizeof(oid_client_mode6));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_mode6 error");

			//oid_client_band6
			long_return = staInfo[5].bandwidth;
			oid_obj.namelen = sizeof(oid_client_band6) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_band6, sizeof(oid_client_band6));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_band6 error");

			//oid_client_rssi6
			get_wlanStaRssi(5, string_return, sizeof(string_return));
			oid_obj.namelen = sizeof(oid_client_rssi6) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_rssi6, sizeof(oid_client_rssi6));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					strlen(string_return), (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_rssi6 error");
		}
	}

	if (client >= 1) {
		//oid_client_idx7
		long_return = 7;
		oid_obj.namelen = sizeof(oid_client_idx7) / sizeof(oid);
		memcpy(oid_obj.name, oid_client_idx7, sizeof(oid_client_idx7));
		out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
				sizeof(long), (unsigned char *)&long_return, &out_length);
		RETURN_ON_BUILD_ERROR(out_data, "oid_client_idx7 error");

		//oid_client_mac7
		memset(string_return, 0, sizeof(string_return));
		memcpy(string_return, hostInfo[0].mac, 6);
		oid_obj.namelen = sizeof(oid_client_mac7) / sizeof(oid);
		memcpy(oid_obj.name, oid_client_mac7, sizeof(oid_client_mac7));
		out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
				6, (unsigned char *)string_return, &out_length);
		RETURN_ON_BUILD_ERROR(out_data, "oid_client_mac7 error");

		//oid_client_ip7
		long_return = hostInfo[0].ipaddress;
		oid_obj.namelen = sizeof(oid_client_ip7) / sizeof(oid);
		memcpy(oid_obj.name, oid_client_ip7, sizeof(oid_client_ip7));
		out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
				sizeof(long), (unsigned char *)&long_return, &out_length);
		RETURN_ON_BUILD_ERROR(out_data, "oid_client_ip7 error");

		//oid_client_name7
		get_DevportName(hostInfo[0].portNo, string_return, sizeof(string_return));
		oid_obj.namelen = sizeof(oid_client_name7) / sizeof(oid);
		memcpy(oid_obj.name, oid_client_name7, sizeof(oid_client_name7));
		out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
				strlen(string_return), (unsigned char *)string_return, &out_length);
		RETURN_ON_BUILD_ERROR(out_data, "oid_client_name7 error");

		//oid_client_crc7
		crc_count = get_portStatusCrc(hostInfo[0].portNo);
		oid_obj.namelen = sizeof(oid_client_crc7) / sizeof(oid);
		memcpy(oid_obj.name, oid_client_crc7, sizeof(oid_client_crc7));
		out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_COUNTER,
				sizeof(long), (unsigned char *)&crc_count, &out_length);
		RETURN_ON_BUILD_ERROR(out_data, "oid_client_crc7 error");

		if (client >= 2) {
			//oid_client_idx8
			long_return = 8;
			oid_obj.namelen = sizeof(oid_client_idx8) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_idx8, sizeof(oid_client_idx8));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_idx8 error");

			//oid_client_mac8
			memset(string_return, 0, sizeof(string_return));
			memcpy(string_return, hostInfo[1].mac, 6);
			oid_obj.namelen = sizeof(oid_client_mac8) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_mac8, sizeof(oid_client_mac8));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					6, (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_mac8 error");

			//oid_client_ip8
			long_return = hostInfo[1].ipaddress;
			oid_obj.namelen = sizeof(oid_client_ip8) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_ip8, sizeof(oid_client_ip8));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_ip8 error");

			//oid_client_name8
			get_DevportName(hostInfo[1].portNo, string_return, sizeof(string_return));
			oid_obj.namelen = sizeof(oid_client_name8) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_name8, sizeof(oid_client_name8));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					strlen(string_return), (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_name8 error");

			//oid_client_crc8
			crc_count = get_portStatusCrc(hostInfo[1].portNo);
			oid_obj.namelen = sizeof(oid_client_crc8) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_crc8, sizeof(oid_client_crc8));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_COUNTER,
					sizeof(long), (unsigned char *)&crc_count, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_crc8 error");
		}

		if (client >= 3) {
			//oid_client_idx9
			long_return = 9;
			oid_obj.namelen = sizeof(oid_client_idx9) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_idx9, sizeof(oid_client_idx9));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_idx9 error");

			//oid_client_mac9
			memset(string_return, 0, sizeof(string_return));
			memcpy(string_return, hostInfo[2].mac, 6);
			oid_obj.namelen = sizeof(oid_client_mac9) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_mac9, sizeof(oid_client_mac9));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					6, (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_mac9 error");

			//oid_client_ip9
			long_return = hostInfo[2].ipaddress;
			oid_obj.namelen = sizeof(oid_client_ip9) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_ip9, sizeof(oid_client_ip9));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_ip9 error");

			//oid_client_name9
			get_DevportName(hostInfo[2].portNo, string_return, sizeof(string_return));
			oid_obj.namelen = sizeof(oid_client_name9) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_name9, sizeof(oid_client_name9));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					strlen(string_return), (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_name9 error");

			//oid_client_crc9
			crc_count = get_portStatusCrc(hostInfo[2].portNo);
			oid_obj.namelen = sizeof(oid_client_crc9) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_crc9, sizeof(oid_client_crc9));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_COUNTER,
					sizeof(long), (unsigned char *)&crc_count, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_crc9 error");
		}

		if (client >= 4) {
			//oid_client_idx10
			long_return = 10;
			oid_obj.namelen = sizeof(oid_client_idx10) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_idx10, sizeof(oid_client_idx10));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_INTEGER,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_idx10 error");

			//oid_client_mac10
			memset(string_return, 0, sizeof(string_return));
			memcpy(string_return, hostInfo[3].mac, 6);
			oid_obj.namelen = sizeof(oid_client_mac10) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_mac10, sizeof(oid_client_mac10));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					6, (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_mac10 error");

			//oid_client_ip10
			long_return = hostInfo[3].ipaddress;
			oid_obj.namelen = sizeof(oid_client_ip10) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_ip10, sizeof(oid_client_ip10));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
					sizeof(long), (unsigned char *)&long_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_ip10 error");

			//oid_client_name10
			get_DevportName(hostInfo[3].portNo, string_return, sizeof(string_return));
			oid_obj.namelen = sizeof(oid_client_name10) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_name10, sizeof(oid_client_name10));
			out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
					strlen(string_return), (unsigned char *)string_return, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_name10 error");

			//oid_client_crc10
			crc_count = get_portStatusCrc(hostInfo[3].portNo);
			oid_obj.namelen = sizeof(oid_client_crc10) / sizeof(oid);
			memcpy(oid_obj.name, oid_client_crc10, sizeof(oid_client_crc10));
			out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_COUNTER,
					sizeof(long), (unsigned char *)&crc_count, &out_length);
			RETURN_ON_BUILD_ERROR(out_data, "oid_client_crc10 error");
		}
	}

	//oid_wan_crc
	crc_count = get_portStatusCrc(PRTNR_WAN0);
	oid_obj.namelen = sizeof(oid_wan_crc) / sizeof(oid);
	memcpy(oid_obj.name, oid_wan_crc, sizeof(oid_wan_crc));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_COUNTER,
			sizeof(long), (unsigned char *)&crc_count, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_wan_crc error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	snmp_send_trap(&message, dvsnmp_cfg.trapserver[0],
			(unsigned short)strtoul(nvram_get("snmp_trp_port"), NULL, 10), 0);

	return 0;
}

static int send_trap_dummy(void)
{
	int out_length = SNMP_MAX_MSG_LENGTH;
	char string_return[80];
	long long_return = 0;
	unsigned char *out_data;
	raw_snmp_info_t message;
	Oid oid_obj;
	oid oid_cjhvApTrapDummytrap[] = { O_cjhvApDummyTrap };

	oid oid_sysUptime[] = { O_cjhvApSysuptime };
	oid oid_mac[] = { O_cjhvApWanMacAddress };

	if (chk_trapserver() == 0)
		return 0;

	memset((unsigned char *)&message, 0x00, sizeof(message));

	// build sendAutoTransmission header
	out_data = make_trap_v2c_headr(&message, &out_length, oid_cjhvApTrapDummytrap,
			sizeof(oid_cjhvApTrapDummytrap));
	RETURN_ON_BUILD_ERROR(out_data,
			"make_trap_v2c_headr - send oid_cjhvApTrapDummytrap");

	// build sendAutoTransmission body
	//oid_Sysuptime
	get_uptime(string_return, sizeof(string_return), UPTIME);
	oid_obj.namelen = sizeof(oid_sysUptime) / sizeof(oid);
	memcpy(oid_obj.name, oid_sysUptime, sizeof(oid_sysUptime));
	long_return = 1;
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
			strlen(string_return), (unsigned char *)string_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_sysUptime error");

	//oid_wanMacAddress
	get_mac(string_return, 6);
	oid_obj.namelen = sizeof(oid_mac) / sizeof(oid);
	memcpy(oid_obj.name, oid_mac, sizeof(oid_mac));
	long_return = 1;
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
			6, (unsigned char *)string_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_mac error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	snmp_send_trap(&message, dvsnmp_cfg.trapserver[0],
			(unsigned short)strtoul(nvram_get("snmp_trp_port"), NULL, 10), 1);

	return 0;
}

static int send_trap_dns(void)
{
	int out_length = SNMP_MAX_MSG_LENGTH;
	char string_return[80];
	long long_return = 0;
	unsigned char *out_data;
	raw_snmp_info_t message;
	Oid oid_obj;
	oid oid_cjhvApTrapSecuritytrap[] = { O_cjhvApTrapSecurity };

	oid oid_mac[] = { O_cjhvApWanMacAddress };
	oid oid_attackIp[] = { O_cjhvApAttackSourceIP };
	oid oid_changeTime[] = { O_cjhvApChangeTime };
	oid oid_changeDns1[] = { O_cjhvApChangeDNS1 };
	oid oid_changeDns2[] = { O_cjhvApChangeDNS2 };

	if (chk_trapserver() == 0)
		return 0;

	memset((unsigned char *)&message, 0x00, sizeof(message));

	// build sendAutoTransmission header
	out_data = make_trap_v2c_headr(&message, &out_length, oid_cjhvApTrapSecuritytrap,
			sizeof(oid_cjhvApTrapSecuritytrap));
	RETURN_ON_BUILD_ERROR(out_data,
			"make_trap_v2c_headr - send oid_cjhvApTrapSecuritytrap");

	// build sendAutoTransmission body
	//oid_wanMacAddress
	get_mac(string_return, 6);
	oid_obj.namelen = sizeof(oid_mac) / sizeof(oid);
	memcpy(oid_obj.name, oid_mac, sizeof(oid_mac));
	long_return = 1;
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
			6, (unsigned char *)string_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_mac error");

	//oid_attackIp
	long_return = 0;
	get_attackIp((unsigned long *)&long_return);
	oid_obj.namelen = sizeof(oid_attackIp) / sizeof(oid);
	memcpy(oid_obj.name, oid_attackIp, sizeof(oid_attackIp));

	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_attackIp error");

	//oid_changeTime
	get_attackTime(string_return, sizeof(string_return));
	oid_obj.namelen = sizeof(oid_changeTime) / sizeof(oid);
	memcpy(oid_obj.name, oid_changeTime, sizeof(oid_changeTime));
	long_return = 1;
	out_data = snmp_build_varbind(out_data, &oid_obj, ASN_OCTET_STR,
			strlen(string_return), (unsigned char *)string_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_changeTime error");

	//oid_changeDns1
	long_return = 0;
	static_get_dnsAddress(&long_return);
	oid_obj.namelen = sizeof(oid_changeDns1) / sizeof(oid);
	memcpy(oid_obj.name, oid_changeDns1, sizeof(oid_changeDns1));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_changeDns1 error");

	//oid_changeDns2
	long_return = 0;
	static_get_dns2Address(&long_return);
	oid_obj.namelen = sizeof(oid_changeDns2) / sizeof(oid);
	memcpy(oid_obj.name, oid_changeDns2, sizeof(oid_changeDns2));

	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_IPADDRESS,
			sizeof(long), (unsigned char *)&long_return, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "oid_changeDns2 error");

	// build tail and message length
	out_data = make_resp_tail(&message, out_data, &out_length);
	RETURN_ON_BUILD_ERROR(out_data, "make_trap_tail");

	snmp_send_trap(&message, dvsnmp_cfg.trapserver[0],
			(unsigned short)strtoul(nvram_get("snmp_trp_port"), NULL, 10), 0);

	return 0;
}

static int check_daylight(unsigned long *next)
{
	time_t t;
	struct tm *tm;

	t = time(NULL);
	tm = localtime(&t);

	if (9 <= tm->tm_hour && tm->tm_hour < 21) // psh test
		return 1;

	*next += HALF_DAY;
	return 0;
}

static void polling_snmp_trap(traplist_t *tlist)
{
	int ret = 0;
	char new_dns[16];
	struct timeval tv;
	unsigned long ctime;

	send_trap_normal();
	send_trap_wlaninfo();
	send_trap_client();

	ctime = ygettime(NULL);

	tlist->normal.next = ctime + get_random_time(tlist->normal.period);
	tlist->wlaninfo.next = ctime + get_random_time(tlist->wlaninfo.period);
	tlist->client.next = ctime + get_random_time(tlist->client.period);;

	while (1) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		ret = select(0, NULL, NULL, NULL, &tv);
		ctime = ygettime(NULL);

		if (tlist->normal.next <= ctime) {
			tlist->normal.next += tlist->normal.period;
			send_trap_normal();
		}
		if (tlist->wlaninfo.next <= ctime) {
			tlist->wlaninfo.next += tlist->wlaninfo.period;
			send_trap_wlaninfo();
		}
		if (tlist->client.next <= ctime) {
			if (check_daylight(&tlist->client.next) > 0) {
				tlist->client.next += tlist->client.period;
				send_trap_client();
			}
		}
		if (tlist->dummy.next <= ctime) {
			tlist->dummy.next += tlist->dummy.period;
			send_trap_dummy();
		}
		if (tlist->dnsmode == 1) {
			nvram_get_r("DNS2", new_dns, sizeof(new_dns));
			if (strcmp(tlist->dns2, new_dns)) {
				send_trap_dns();
				snprintf(tlist->dns2, sizeof(tlist->dns2), "%s", new_dns);
			}
		}
		if (access("/tmp/wan_ip_change", F_OK) == 0) {
			unlink("/tmp/wan_ip_change");
			send_trap_normal();
		}
	}
}

int snmptrapmain(void)
{
	char val[4];
	pid_t pid;
	traplist_t tlist;

	nvram_get_r("snmp_trap_enable", val, sizeof(val));
	if (val[0] == '0') {
		printf("Snmp Trap disabled\n");
		return 0;
	}

	pid = fork();

	if (pid == 0) {
		yfecho(SNMP_TRAP_PID_FILE, O_WRONLY|O_CREAT|O_TRUNC, 0644, "%d\n", getpid());
		possible_snmp_trap();

		memset(&tlist, 0, sizeof(traplist_t));
		init_snmp_trap_value(&tlist);

		polling_snmp_trap(&tlist);
	}

	return 0;
}
