#ifndef __CJHV_API_H__
#define __CJHV_API_H__

#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <bcmnvram.h>
#include <libytool.h>
#include <nmpipe.h>
#include <8192cd.h>
#include <signal.h>
#include <time.h>
#include <brdio.h>

#include "linux_list.h"

#define SNMP_NO_ACTION			0
#define SNMP_REBOOT				1
#define SNMP_FACTORY_RESET		2
#define SNMP_SOFTRESET_TRAP		3

#define MAX_DATA_LEN	1024

#define DEFAULT_TRAFFIC_BYTE	40960	//40kbyte

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define LOCAL_MCAST(x)  (((x) & 0xFFFFFF00) == 0xE0000000)

#define MAX_FILTER_NUM 20
#define MAXTBLNUM	20
#define UPTIME		"/tmp/.uptime"
#define WANUPTIME	"/tmp/.wanup"
#define WLAN_2G		1
#define WLAN_5G		0

#define PING_RST	"/tmp/.ping_rst"

#define SIOCGIWRTLGETBSSINFO	0x8B37
#define SIOCGMISCDATA			0x8B48
#define SIOCGIWRTLSCANREQ		0x8B33
#define SIOCGIWRTLGETBSSDB		0x8B34
#define SIOCGIWRTLSTAINFO		0x8B30
#define STA_INFO_FLAG_ASOC		0x04

#define SSID_LEN	32
#define	MAX_BSS_DESC	64
#define MESHID_LEN 	32
#define MAX_STA_NUM		64

#define MAX_WALKING_CHANNUM		13
#define CJHV_END_CHAN		11
#define CJHV_MAX_CHAN_NUM	13
#define BASE_OFFSET		-2
#define CHAN_OFFSET(x) (((x) < 2)? (BASE_OFFSET + x) : (BASE_OFFSET + (x + 1)))

typedef enum { BAND_11B = 1, BAND_11G = 2, BAND_11BG = 3, BAND_11A = 4, BAND_11N = 8, BAND_5G_11AN = 12,
				BAND_5G_11AC = 64, BAND_5G_11AAC = 68, BAND_5G_11NAC = 72, BAND_5G_11ANAC = 76} BAND_TYPE_T;

#define _DHCPD_PROG_NAME	"udhcpd"
#define _DHCPD_PID_PATH		"/var/run"
#define _PATH_DHCPS_LEASES	"/var/lib/misc/udhcpd.leases"
#define _CONFIG_SCRIPT_PATH		"/bin"
#define _FIREWALL_SCRIPT_PROG	"firewall.sh"

typedef sta_info_2_web WLAN_STA_INFO_T;
typedef sta_info_2_web *WLAN_STA_INFO_Tp;

enum _HT_CHANNEL_WIDTH {
	HT_CHANNEL_WIDTH_20		= 0,
	HT_CHANNEL_WIDTH_20_40	= 1
};

typedef struct port_stats {
	unsigned long long rxbyte;
	unsigned long long txbyte;
	unsigned long rx_multicast;
	unsigned long tx_multicast;
	unsigned long crc;
} P_STATS;

typedef struct wanConfig {
	int obtainedMethod;
	unsigned long IpAddr;
	unsigned long subnetMask;
	unsigned long defGateway;
	unsigned long dns[2];
} _wanConfig_t_;

typedef struct portfwConfig {
	int index;
	int enable;
	char name[32];
	unsigned long ipaddr;
	int startport;
	int endport;
	int lanport;
	int protocol;
} _portfwConfig_t_;

typedef struct con_staInfo {
	unsigned char	mac[6];
	unsigned char	mode;
	char			ssid[64];
	unsigned char	rssi;
	unsigned long	ipaddress;
	unsigned long 	rx_crc;
	long		 	bandwidth;
	long		 	band_info;
} _con_staInfo_t_;

typedef struct con_hostInfo {
	unsigned char	mac[6];
	unsigned long	ipaddress;
	int	portNo;
} _con_hostInfo_t_;

typedef struct _bss_info {
	unsigned char state;
	unsigned char channel;
	unsigned char txRate;
	unsigned char bssid[6];
	unsigned char rssi, sq;	// RSSI  and signal strength
	unsigned char ssid[SSID_LEN + 1];
} bss_info;

struct _misc_data_ {
	unsigned char mimo_tr_hw_support;
	unsigned char mimo_tr_used;
	unsigned char resv[30];
};

typedef struct _OCTET_STRING {
    unsigned char *Octet;
    unsigned short Length;
} OCTET_STRING;

typedef enum _BssType {
    infrastructure = 1,
    independent = 2,
} BssType;

typedef	struct _IbssParms {
    unsigned short	atimWin;
} IbssParms;

typedef struct _BssDscr {
    unsigned char bdBssId[6];
    unsigned char bdSsIdBuf[SSID_LEN];
    OCTET_STRING  bdSsId;

	//by GANTOE for site survey 2008/12/26
	unsigned char bdMeshIdBuf[MESHID_LEN];
	OCTET_STRING bdMeshId;

    BssType bdType;
    unsigned short bdBcnPer;			// beacon period in Time Units
    unsigned char bdDtimPer;			// DTIM period in beacon periods
    unsigned long bdTstamp[2];			// 8 Octets from ProbeRsp/Beacon
    IbssParms bdIbssParms;			// empty if infrastructure BSS
    unsigned short bdCap;				// capability information
    unsigned char ChannelNumber;			// channel number
    unsigned long bdBrates;
    unsigned long bdSupportRates;
    unsigned char bdsa[6];			// SA address
    unsigned char rssi, sq;			// RSSI and signal strength
    unsigned char network;			// 1: 11B, 2: 11G, 4:11G
	// P2P_SUPPORT
	unsigned char	p2pdevname[33];
	unsigned char	p2prole;
	unsigned short	p2pwscconfig;
	unsigned char	p2paddress[6];
	unsigned char   stage;

	#if defined(CONFIG_RTL_COMAPI_WLTOOLS)
    unsigned char	    wpa_ie_len;
    unsigned char	    wpa_ie[256];
    unsigned char	    rsn_ie_len;
    unsigned char	    rsn_ie[256];
    #endif
} BssDscr, *pBssDscr;

typedef struct _sitesurvey_status {
    unsigned char number;
    unsigned char pad[3];
    BssDscr bssdb[MAX_BSS_DESC];
} SS_STATUS_T, *SS_STATUS_Tp;

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

typedef struct igmp_snoop {
	unsigned long GAddr;
	int join_mbn;
	int join_port;
	int portNum;
} _igmp_snoop_t;

typedef struct ping_test {
	char pingAddress[64];
	unsigned int pktCount;
	unsigned int pktSize;
	unsigned int pktTimeout;
	unsigned int pktDelay;
	int TrapOnComplete;
	unsigned int sentPktCount;
	unsigned int recvPktCount;
	unsigned int minPingTime;
	unsigned int avgPingTime;
	unsigned int maxPingTime;
	int pingCompleted;
	char pingStartTime[32];
	char pingEndTime[32];
	int pingResultCode;
} _ping_test_t;

typedef enum {
	Enum_RowStatusActive = 1,
	Enum_RowStatusNotInSevice,
	Enum_RowStatusNotReady,
	Enum_RowStatusCreateAndGo,
	Enum_RowStatusCreateAndWait,
	Enum_RowStatusDestory
} Enum_RowStatus;

int write_pid(char *pid_file);
int read_int(char *file, int def);
int read_pid(char *path);
int test_pid(char *pid_file);
void global_variables_initial(void);
int getWlBssInfo(char *interface, bss_info *pInfo);
int getMiscData(char *interface, struct _misc_data_ *pData);
int getWlSiteSurveyRequest(char *interface, int *pStatus);

/* ======================= SYSTEM INFO ================================= */
void get_modelName(char *str, int len);
void get_version(char *str, int len);
void get_uptime(char *str, int len, char *path);
long get_cpu_utiliz(void);
long get_ram_utiliz(void);
long get_sys_status(void);
void get_portStats(int p_idx);
unsigned long get_portStatusCrc(int idx);
/* ======================= SYSTEM INFO ================================= */

/* ======================= WAN STATUS ================================= */
long get_wan_status(void);
void get_mac(char *str, int len);
void get_wanIpAddress(unsigned long *wanIp);
void get_wanSubnetMask(unsigned long *wanMask);
void get_gwIpAddress(unsigned long *wanGw);
void get_dnsAddress(unsigned long *dns, int index);
int set_wanMethod(int mode);
int set_wanIpAddress(unsigned char *var_val, int var_val_len);
int set_wanSubnetMask(unsigned char *var_val, int var_val_len);
int set_wanDefaultGW(unsigned char *var_val, int var_val_len);
int set_wanDNS2(unsigned char *var_val, int var_val_len);
void get_trap_wanIpAddress(unsigned long *wanIp);
/* ======================= WAN STATUS ================================= */

/* ======================= LAN STATUS ================================= */
void get_lanMac(char *str, int len);
void get_lanIpAddress(unsigned long *lanIp);
void get_lanSubnetMask(unsigned long *Mask);
int set_lanIPAddress(unsigned char *var_val, int var_val_len);
int set_lanSubnetMask(unsigned char *var_val, int var_val_len);
long get_dhcpServer(void);
int set_dhcpServer(int mode);
void get_ipPoolStartAddress(unsigned long *start_ip);
int set_ipPoolStartAddress(unsigned char *var_val, int var_val_len);
void get_ipPoolEndAddress(unsigned long *end_ip);
int set_ipPoolEndAddress(unsigned char *var_val, int var_val_len);
/* ======================= LAN STATUS ================================= */

/* ======================= WLAN BASIC ================================= */
long get_wlanMode(int wlan_idx);
int set_wlanMode(int mode, int wlan_idx);
long get_wlanBand(int wlan_idx);
int set_wlanBand(int band, int wlan_idx);
long get_wlanChannelWidth(int wlan_idx);
int set_wlanChannelWidth(int width, int wlan_idx);
long get_wlanCtrlSideBand(int wlan_idx);
int set_wlanCtrlSideBand(int controlSideBand, int wlan_idx);
long get_wlanChannelNumber(int wlan_idx);
int set_wlanChannelNumber(int channelNum, int wlan_idx);
long get_wlanDateRate(int wlan_idx);
int set_wlanDateRate(int val, int wlan_idx);
/* ======================= WLAN BASIC ================================= */

/* ======================= WLAN SSID CONFIG ================================= */
void get_wlanSSID(int index, char *str, int len);
long get_wlanSSIDMode(int index);
long get_wlanBSSID(int index);
long get_wlanSecEncryption(int index);
long get_wlanRateLimit(int index);
int set_wlanSSID(int index, unsigned char *var_val, int val_len);
int set_wlanSSIDMode(int index, int mode);
int set_wlanBSSID(int index, int bcast);
int set_wlanSecEncryption(int index, int encrypt);
int set_wlanRateLimit(int index, int rateLimit);
/* ======================= WLAN SSID CONFIG ================================= */

/* ======================= SITE SURVEY INFO ================================= */
int surveyRequest(int wlan_idx);
int getWlanScanInfo(int wlan_idx);
int getWlSiteSurveyResult(char *interface, SS_STATUS_Tp pStatus);
long get_BestChannelAlgorithm(void);
int set_BestChannelAlgorithm(int wlan_idx, int set_type);
/* ======================= SITE SURVEY INFO ================================= */

/* ======================= WLAN ADVANCE CONFIG ================================= */
long get_wlanFragmentThreshold(int wlan_idx);
int set_wlanFragmentThreshold(int wlan_idx, int fragment);
long get_wlanRTSThreshold(int wlan_idx);
int set_wlanRTSThreshold(int wlan_idx, int rts);
long get_wlanBeaconInterval(int wlan_idx);
int set_wlanBeaconInterval(int wlan_idx, int interval);
long get_wlanPreambleType(int wlan_idx);
int set_wlanPreambleType(int wlan_idx, int preamble);
int get_wlanRFOutputPower(int wlan_idx);
int set_wlanRFOutputPower(int wlan_idx, int power);
/* ======================= WLAN ADVANCE CONFIG ================================= */

/* ======================= CLIENT INFO ================================= */
int wirelessClientList(int wlan_idx, int found);
int getWlStaInfo(char *interface, WLAN_STA_INFO_Tp pInfo);
int initHostInfo(void);
void get_wlanStaMac(int idx, char *macAddr, int len);
void get_hostInfoMac(int idx, char *macAddr, int len);
void get_wlanStaipaddr(int idx, unsigned long *ipaddr);
void get_hostInfoipAddr(int idx, unsigned long *ipaddr);
void get_wlanStaName(int idx, char *name, int len);
void get_hostInfoName(int idx, char *name, int len);
void get_wlanStaMode(int idx, long *band);
void get_wlanStaBand(int idx, long *bandwidth);
void get_wlanStaRssi(int idx , char *rssi, int len);
void get_hostInfoCrc(int idx, unsigned long *crc);
/* ======================= CLIENT INFO ================================= */

/* ======================= WEP SECURITY INFO ================================= */
long get_secWEP8021xAuthMode(int index);
int set_secWEP8021xAuthMode(int index, int auth);
long get_secWEPMacAuthMode(int index);
int set_secWEPMacAuthMode(int index, int macAuth);
long get_secWEPAuthMethod(int index);
int set_secWEPAuthMethod(int index, int method);
long get_secWEPKeySize(int index);
int set_secWEPKeySize(int index, int keySize);
long get_secWEPKeyFormat(int index);
int set_secWEPKeyFormat(int index, int format);
void get_secWEPEncryptionKey(int index, char *str, int len);
int set_secWEPEncryptionKey(int index, char *password, int len);
long get_secWEPKeyIndex(int index);
int set_secWEPKeyIndex(int index, int keyIndex);
/* ======================= WEP SECURITY INFO ================================= */

/* ======================= WPA SECURITY INFO ================================= */
long get_secWPAxAuthMode(int index);
int set_secWPAxAuthMode(int index, int authMode);
long get_secWPAxCipherSuite(int index);
int set_secWPAxCipherSuite(int index, int Suite);
long get_secWPAxKeyFormat(int index);
int set_secWPAxKeyFormat(int index, int format);
void get_secWPAxPreSharedKey(int index, char *SharedKey, int len);
int set_secWPAxPreSharedKey(int index, char *SharedKey, int len);
/* ======================= WPA SECURITY INFO ================================= */

/* ======================= WPA-Mixed SECURITY INFO ================================= */
long get_secWPAmixAuthMode(int index);
int set_secWPAmixAuthMode(int index, int authMode);
long get_secWPAmixCipherSuite(int index);
int set_secWPAmixCipherSuite(int index, int Suite);
long get_secWPAmix2CipherSuite(int index);
int set_secWPAmix2CipherSuite(int index, int Suite);
int get_secWPAmixKeyFormat(int index);
int set_secWPAmixKeyFormat(int index, int format);
void get_secWPAmixPreSharedKey(int index, char *SharedKey, int len);
int set_secWPAmixPreSharedKey(int index, char *SharedKey, int len);
/* ======================= WPA-Mixed SECURITY INFO ================================= */

/* ======================= PORT CONFIG ================================= */
long get_devicePortMode(void);
int set_devicePortMode(int opMode);
void get_DevportName(int portNum, char *port, int len);
long get_DevicePortNego(int portNum);
int set_DevicePortNego(int portNum, int nego);
unsigned int switch_port_status(int portno);
long get_DevicePortSpeed(int portNum);
int set_DevicePortSpeed(int portNum, int speed);
long get_DevicePortDuplex(int portNum);
int set_DevicePortDuplex(int portNum, int duplex);
long get_DevicePortOnOff(int portNum);
int set_DevicePortOnOff(int portNum, int onoff);
long get_DevicePortStatus(int portNum);
/* ======================= PORT CONFIG ================================= */

/* ======================= IGMP CONFIG ================================= */
long get_IgmpMulticastEnable(void);
int set_IgmpMulticastEnable(int mode);
long get_IgmpSelectMode(void);
long get_IgmpFastLeaveEnable(void);
int set_IgmpFastLeaveEnable(int mode);
long get_IgmpProxyMemberExpireTime(void);
int set_IgmpProxyMemberExpireTime(int expire);
/* ======================= IGMP CONFIG ================================= */

/* ======================= SNMP CONFIG ================================= */
long get_snmpEnable(void);
int set_snmpEnable(int enable);
void get_getCommunityName(char *R_Community, int len);
int set_getCommunityName(unsigned char *R_Community, int len);
void get_setCommunityName(char *W_Community, int len);
int set_setCommunityName(unsigned char *W_Community, int len);
long get_snmpListenport(void);
int set_snmpListenport(int s_port);
long get_TrapEnable(void);
int set_TrapEnable(int enable);
void get_snmpTrapCommunityName(char *T_Community, int len);
int set_snmpTrapCommunityName(unsigned char * T_Community, int len);
void get_snmpTrapDestination(char *TrapServer, int len);
int set_snmpTrapDestination(unsigned char *trapServer, int len);
long get_snmpTrapPort(void);
int set_snmpTrapPort(int t_port);
/* ======================= SNMP CONFIG ================================= */

/* ======================= SYSLOG CONFIG ================================= */
long get_sysLogEnable(void);
int set_sysLogEnable(int enable);
long get_sysLogRemoteLogEnable(void);
int set_sysLogRemoteLogEnable(int remote);
void get_sysLogRemoteLogServer(char *logServer, int len);
int set_sysLogRemoteLogServer(unsigned char *server, int len);
/* ======================= SYSLOG CONFIG ================================= */

/* ======================= NTP CONFIG ================================= */
void get_ntpServer(int index, char *server, int len);
int set_ntpServer(int index, unsigned char *server, int len);
/* ======================= NTP CONFIG ================================= */

/* ======================= DMZ CONFIG ================================= */
long get_dmzEnable(void);
int set_dmzEnable(int enable);
long get_dmzType(void);
int set_dmzType(int type);
void get_dmzMac(char *dmzMac, int len);
int set_superdmzMac(unsigned char *macString, int len);
void get_dmzIpAddress(unsigned long *ipaddress);
int set_dmzIpAddress(unsigned char *ipaddress);
/* ======================= DMZ CONFIG ================================= */

/* ======================= PORTFW CONFIG ================================= */
long get_PortFwEnable(void);
void get_PortFwName(int index, char *comment, int len);
void get_PortfwIpAddress(int index, unsigned long *Ipaddr);
void get_portFwStartPort(int index, long *s_port);
void get_portFwEndPort(int index, long *e_port);
void get_portFwLanPort(int index, long *lan_port);
void get_portFwProtocol(int index, long *protocol);
long get_setPortfwIndex(void);
int set_portfwIndex(int index);
long get_setPortfwEnable(void);
int set_portfwEnable(int enable);
void get_setPortFwName(char *portfw_comment, int len);
int set_portfwName(unsigned char *portfw_comment, int len);
void get_portfwAddress(unsigned long *portfwIp);
int set_portfwAddress(unsigned char *ipaddr);
long get_setPortfwSport(void);
int set_portfwSport(int s_port);
long get_setPortfwEport(void);
int set_portfwEport(int e_port);
long get_setPortfwLanport(void);
int set_portfwLanport(int laport);
int set_portfwLanEport(int lanport);
long get_setPortfwprotocol(void);
int set_portfwprotocol(int protocol);
/* ======================= PORTFW CONFIG ================================= */

/* ======================= TELNET CONFIG ================================= */
long get_telnetEnable(void);
int set_telnetEnable(int enable);
/* ======================= TELNET CONFIG ================================= */

/* ======================= ACL CONFIG ================================= */
long get_aclEnable(void);
int set_aclEnable(int aclEnable);
/* ======================= ACL CONFIG ================================= */

/* ======================= WEBMAN CONFIG ================================= */
long get_WebEnable(void);
int set_WebEnable(int webman);
/* ======================= WEBMAN CONFIG ================================= */

/* ======================= DNS CHANGE INFO ================================= */
void get_attackIp(unsigned long *ipaddress);
void get_attackTime(char *eventTime, int len);
/* ======================= DNS CHANGE INFO ================================= */

/* ======================= IGMP JOIN INFO ================================= */
int igmp_snoop_table_info(_igmp_snoop_t *igmp);
void get_igmpJoinIpAddress(_igmp_snoop_t *igmp, unsigned long *ipaddr);
/* ======================= IGMP JOIN INFO ================================= */

/* ======================= MULTICAST INFO ================================= */
void get_multicastJoinIpAddress(_igmp_snoop_t *igmp, unsigned long *ipaddr);
long get_multicastPortNumber(_igmp_snoop_t *igmp);
void get_multicastPortName(_igmp_snoop_t *igmp, char *port, int len);
void get_multicastInPackets(_igmp_snoop_t *igmp, unsigned long *rx_multicast);
void get_multicastOutPackets(_igmp_snoop_t *igmp, unsigned long *tx_multicast);
/* ======================= MULTICAST INFO ================================= */

/* ======================= TRAFFIC INFO ================================= */
void get_portStatusOutBytes(int port, unsigned long *txCount);
void get_wlanOutTrafficInfo(int index, unsigned long *txCount);
void get_portStatusInBytes(int port, unsigned long *rxCount);
void get_wlanInTrafficInfo(int index, unsigned long *rxCount);
/* ======================= TRAFFIC INFO ================================= */

/* ======================= RESET CONFIG ================================= */
int set_faultreset(int reboot);
/* ======================= RESET CONFIG ================================= */

/* ======================= PING TEST CONFIG ================================= */
void get_pingAddress(char *pingAddress, int len);
int set_pingAddress(unsigned char *pingAddress, int len);
void get_pktCount(unsigned long *count);
int set_pktCount(int count);
void get_pktSize(unsigned long *size);
int set_pktSize(int size);
void get_pktTimeout(unsigned long *timeout);
int set_pktTimeout(int timeout);
void get_pktDelay(unsigned long *delay);
int set_pktDelay(int delay);
void get_TrapOnCompletion(long *trapOn);
int set_TrapOnCompletion(int trapOn);
void get_sentPktCount(unsigned long *send);
void get_recvPktCount(unsigned long *receive);
void get_minPingTime(unsigned long *min);
void get_avgPingTime(unsigned long *avg);
void get_maxPingTime(unsigned long *max);
void get_pingCompleted(long *complete);
void get_pingStarttime(char *start, int len);
void get_pingEndtime(char *end, int len);
void get_pingResultCode(long *status);
int set_pingResultCode(int action);
int start_mping_report(void);
void stop_mping_report(void);
int sendAutoTransmission_ping(void);
/* ======================= PING TEST CONFIG ================================= */

/* ======================= FACTORY MODE CONFIG ================================= */
int set_factoryreset(int factory);
/* ======================= FACTORY MODE CONFIG ================================= */

/* ======================= SOFT RESET CONFIG ================================= */
void get_cjhvApSystemSoftReset(unsigned long *result);
int set_softreset(int soft);
int send_softReset_trap_message(void);
/* ======================= SOFT RESET CONFIG ================================= */
#endif
