#ifndef __SKBB_API_H__
#define __SKBB_API_H__

#include <sys/ioctl.h>
#include <linux/wireless.h>
#include <sys/un.h>
#include "engine/agt_mib.h"
#include "brdio.h"
#include "snmp_main.h"

#define STRING_TYPE		0
#define NON_STRING_TYPE 1

#define MAX_PORT		5
#define MAX_SSID		5
#define PortPowerOn		(1 << 8)
#define PortNegoAuto	(1 << 7)
#define PortDuplex		(1 << 3)
#define PortSpeed100M	(1 << 0)

#define MAX_PING_ENTRY	4

#define MAX_WLAN_INTF_NUM 5

#if defined(__STATRAP_EVENT__)
/* jihyun@davo160202 jcode#7 -*/
#define MAX_MONITOR_WLINTF 10
#endif

typedef struct {
	int enable;
	int type;
	char Community[30];
} COM_T;

typedef struct {
	char GroupAddr[16];
	int mbr;
	int num;
	int join_mbr;
} _igmpTbl_t;

typedef struct {
	char GroupAddr[16];
	int join_mbn;
	int join_port;
} _igmpTbl_snoop_t;

#if defined(__STATRAP_EVENT__)
/* jihyun@davo160202 jcode#7 -*/

struct sta_conhist_t {
	int state;
	unsigned char mac[6];
	struct timeval evtime;
	int handover;
};

struct wl_info_t {
	const int monitor;
	int ifindex;
	char *ifname;
	char ssid[32];
	struct sta_conhist_t conhist[MAX_SUPPLICANT_NUM];
};

struct nlkevent_t {
	int event;
	char event_msg[IW_CUSTOM_MAX];
	unsigned int event_msglen;
};
#endif

#define MAXTBLNUM       20

extern void get_manufacturer(char *str, int len);
extern void get_modelName(char *str, int len);
extern void get_version(char *str, int len);
extern void get_mac(char *str, int len);
extern void get_wanIpAddress(void *wanIp, int mode);
extern int set_wanIpAddress(unsigned char *var_val, int var_val_len);
extern int set_wanSubnetMask(unsigned char *var_val, int var_val_len);
extern void get_wanSubnetMask(void *wanMask, int type);
extern void get_lanIpAddress(void *lanIp, int type);
extern void set_wanMethod(int res);
extern int	get_wanMethod(void);
extern void get_gwIpAddress(void *wanGw, int mode);
extern int set_wanDefaultGW(unsigned char *var_val, int var_val_len);
extern void get_dnsAddress(void *dns, int index, int type);
extern void set_wanDNS1(unsigned char *var_val, int var_val_len);
extern int set_wanDNS2(unsigned char *var_val, int var_val_len);
int set_DNSMethod(int res);
int get_DNSMode();
int set_DNSMode(int res);
extern void get_lanMac(char *str, int len);
extern void get_lanSubnetMask(void *Mask, int type);
extern void set_lanSubnetMask(unsigned char *var_val, int var_val_len);
extern int set_wlanMode(int, int);
extern int set_faultreset(int res);
extern long get_wifiStatus(void);
extern int get_lanStatus(int index);
extern long get_currentChannel(void);
extern long get_channel(void);
extern int set_channel(int res);
extern long get_txPower(void);
extern int set_txPower(int res);
extern int  get_wanMethod(void);
extern void  set_wanMethod(int);
extern void get_lanIPAddress(long *addr);
extern void set_lanIPAddress(unsigned char* var_val, int var_val_len, Oid *name);
extern int get_dhcpServer(void);
extern int set_dhcpServer(int res);
extern void get_ipPoolStartAddress(long *addr);
extern int set_ipPoolStartAddress(long var);
extern void get_ipPoolEndAddress(long *addr);
extern int set_ipPoolEndAddress(long var);
extern int get_snmpEnable();
extern int set_snmpEnable(int res);
extern int set_CommunityName(unsigned char *str, int len, int index);
extern void get_snmpTrapDestination(int, unsigned char *, int);
extern int  set_snmpTrapDestination(int, unsigned char *, int);
extern void get_snmpTrapCommunityName(unsigned char *);
extern int  set_snmpTrapCommunityName(unsigned char *, int);
extern int  get_snmpTrapDestinationAdmin();
extern int  set_snmpTrapDestinationAdmin(int);
extern void set_autoTransmission(unsigned char *var_val, int var_val_len);
extern int get_bssid(char *str, int len);
extern int set_CommunityType(int index, int type);
extern int set_CommunityAdmin(int index, int enable);
extern void get_CommunityName(char *str, int len, int index, COM_T *com);
extern long get_CommunityType(int index, COM_T *com);
extern long get_CommunityAdmin(int index, COM_T *com);
extern int executeManualUpgrade(void);
extern int __executeManualUpgrade(char *serverIp, char *prefix, char *fwFile);
extern int	set_autoUpgradeEnable(int);
extern void set_autoUpgradeServer(unsigned char *var_val, int var_val_len);
extern void get_autoUpgradeServer(char *var_val);
extern void set_autoUpgradePrefix(unsigned char *var_val, int var_val_len);
extern void get_autoUpgradePrefix(char *var_val);
extern void set_autoUpFWDataFile(unsigned char *var_val, int var_val_len);
extern void get_autoUpFWDataFile(char *var_val);
extern void load_config(void);
extern void Community_parse(COM_T *);

extern void get_wlanMac(char *, int);
extern long get_wlanMode();
extern long get_wlanBand(int);
extern int set_wlanBand(int, int);
extern int get_wlanChannelNumber();
extern int set_wlanChannelNumber(int, int);
extern long get_wlanDateRate(int);
extern int set_wlanDateRate(int, int);
extern long get_wlanChannelWidth(int);
extern int set_wlanChannelWidth(int, int);
extern long get_wlanCtrlSideBand();
extern long get_wlanCtrlSideBand_5g();
extern int set_wlanCtrlSideBand(int, int);
extern long get_autoUpgradeEnable();
extern int get_radiusServerIP(int, int, void *ip_addr);
extern int set_radiusServerIP(int, int, unsigned char *var_val);
extern int set_radiusPort(int, int, int);
extern int get_radiusPort(int, int, long *Port);
extern int get_radiusPassword(int, int, char *Password);
extern int set_radiusPassword(int, int, unsigned char *Password, int var_len);
extern int get_radiusAccountMode(int, int);
extern int set_radiusAccountMode(int, int, int);
extern int get_radiusAccountServerIp(int, int, void *ipAddr);
extern int set_radiusAccountServerIp(int, int, unsigned char *var_val);
extern int get_radiusAccountServerPort(int, int, void *AccountPort);
extern int set_radiusAccountServerPort(int, int, int);
extern int get_radiusAccountServerPasswd(int, int, char *AccountPwd);
extern int set_radiusAccountServerPasswd(int, int, unsigned char *AccountPwd, int len);
extern void get_wlanSSID(int w_index, int index, char *var_val);
extern int set_wlanSSID(int w_index, int index, unsigned char *var_val, int val_len);
extern int get_wlanSSIDMode(int w_index, int index);
extern int set_wlanSSIDMode(int w_index, int index, int enabled);
extern int get_wlanBSSID(int w_index, int index);
extern int set_wlanBSSID(int w_index, int index, int enabled);
extern int get_wlanSecEncryption(int w_index, int index);
extern int set_wlanSecEncryption(int w_index, int index, int enc);
extern int set_wlanRateLimit(int w_index, int index, int res);
extern int get_wlanRateLimit(int w_index, int index);
extern int get_wlanTrafficInfo(int w_index, int index, char *argv);

extern int get_wlanFragmentThreshold(int index);
extern int set_wlanFragmentThreshold(int, int);
extern int get_wlanRTSThreshold(int index);
extern int set_wlanRTSThreshold(int, int);
extern int get_wlanBeaconInterval(int index);
extern int set_wlanBeaconInterval(int, int);
extern int get_wlanPreambleType(int index);
extern int set_wlanPreambleType(int, int);
extern int get_wlanIAPPEnable(int index);
extern int set_wlanIAPPEnable(int, int);
extern int get_wlanRFOutputPower(int index);
extern int set_wlanRFOutputPower(int index, int res);
extern int get_devicePortMode();
extern int set_devicePortMode(int opMode);
extern int SaveAndApply(int res);
extern int get_sysLogEnable();
extern int set_sysLogEnable(int);
extern int get_sysLogRemoteLogEnable();
extern int set_sysLogRemoteLogEnable(int);
extern void get_sysLogRemoteLogServer(unsigned char *);
extern int set_sysLogRemoteLogServer(unsigned char *, int);
extern void get_ntpServer(int index, char *server);
extern int set_ntpServer(int index, char *server);
extern int get_systemInitMode();
extern int set_systemInitMode(int);
extern int get_secWEP8021xAuthMode(int, int);
extern int set_secWEP8021xAuthMode(int, int, int);
extern int get_secWEPMacAuthMode(int, int);
extern int set_secWEPMacAuthMode(int, int, int);
extern int get_secWEPAuthMethod(int, int);
extern int set_secWEPAuthMethod(int, int, int);
extern int get_secWEPKeySize(int, int);
extern int set_secWEPKeySize(int, int, int);
extern int get_secWEPAuthEnable(int, int);
extern int set_secWEPAuthEnable(int, int, int);
extern int get_secWEPKeyFormat(int, int);
extern int set_secWEPKeyFormat(int, int, int);
extern int get_secWEPEncryptionKey(int, int, char *);
extern int set_secWEPEncryptionKey(int, int, unsigned char *, int);
extern int get_secWEPKeyIndex(int, int);
extern int set_secWEPKeyIndex(int, int, int);
extern int get_secWPAxAuthMode(int w_index, int index);
extern int set_secWPAxAuthMode(int w_index, int index, int res);
extern int get_secWPAxCipherSuite(int w_index, int index);
extern int set_secWPAxCipherSuite(int w_index, int index, int res);
extern int get_secWPAxKeyFormat(int w_index, int index);
extern int set_secWPAxKeyFormat(int w_index, int index, int res);
extern int get_secWPAxPreSharedKey(int w_index, int index, char *var_val);
extern int set_secWPAxPreSharedKey(int w_index, int index, unsigned char *var_val, int val_len);
extern int get_secWPAmixAuthMode(int w_index, int index);
extern int set_secWPAmixAuthMode(int w_index, int index, int res);
extern int get_secWPAmixCipherSuite(int w_index, int index);
extern int set_secWPAmixCipherSuite(int w_index, int index, int res);
extern int get_secWPAmix2CipherSuite(int w_index, int index);
extern int set_secWPAmix2CipherSuite(int w_index, int index, int res);
extern int get_secWPAmixKeyFormat(int w_index, int index);
extern int set_secWPAmixKeyFormat(int w_index, int index, int res);
extern int get_secWPAmixPreSharedKey(int w_index, int index, char *var_val);
extern int set_secWPAmixPreSharedKey(int w_index, int index, char *var_val, int val_len);
extern int get_IgmpMulticastEnable();
extern int get_IgmpSelectMode();
extern int set_IgmpMulticastEnable(int res);
extern int get_IgmpFastLeaveEnable();
extern int set_IgmpFastLeaveEnable(int res);
extern int get_IgmpProxyMemberExpireTime();
extern int set_IgmpProxyMemberExpireTime(int res);
extern int get_IgmpProxyQueryInterval();
extern int set_IgmpProxyQueryInterval(int res);
extern int get_IgmpProxyQueryResInterval();
extern int set_IgmpProxyQueryResInterval(int);
extern int get_IgmpProxyGroupMemberInterval();
extern int set_IgmpProxyGroupMemberInterval(int res);
extern int get_IgmpProxyGroupQueryInterval();
extern int set_IgmpProxyGroupQueryInterval(int res);
extern int get_LanAccessControlPortOpMode(int);
extern int set_LanAccessControlPortOpMode(int, int);
extern int set_AccessControlListSetMacAddr(char *strVal, int val_len, unsigned char *hwaddr);
extern int LanAccessControlListAdd(int port, unsigned char *hwaddr, char *comment);
extern int LanAccessControlListDel(int port, int enable, unsigned char *hwaddr);
extern int LanAccessControlListDelAll();
extern int set_LanAccessControlMode(int);
extern int get_LanAccessControlMode();
extern int get_LanAccessControlListPortNum(int entry);
extern int get_LanAccessControlListMacAddr(int entry, unsigned char *dstStr);
extern int get_LanAccessControlListComment(int entry, unsigned char *dstStr);
extern int get_WLanAccessControlOpMode(int index, int wl_index);
extern int set_WLanAccessControlOpMode(int, int, int);
extern int WLanAccessControlListAdd(int w_index, int wl_index, unsigned char *hwaddr, char *comment);
extern int WLanAccessControlListDel(int w_index, int wl_index, int tblNo);
extern int WLanAccessControlListDelAll(int w_index, int wl_index);
extern int get_WLanAccessControlListMacAddr(int wl_index, int tblNo, char *mac);
extern int get_WLanAccessControlListComment(int wl_index, int tblNo, char *comment);
extern int get_vlanVid(int no);
extern int get_vlanMemberPort(int no);
extern int get_PortRateLimitMode(int port_index);
extern int set_PortRateLimitMode(int port_index, int res);
extern int get_PortRateLimitIncomming(int port_index);
extern int set_PortRateLimitIncomming(int port_index,int rate);
extern int get_PortRateLimitOutgoing(int port_index);
extern int set_PortRateLimitOutgoing(int port_index,int rate);
extern int get_PortFlowControl(int port);
extern int set_PortFlowControl(int port, int res);
extern int get_QosScheduleMode(int pn, int qn);
extern int get_QosScheduleWeight(int pn, int qn);
extern int get_IgmpJoinTestGroupAddr();
extern int set_IgmpJoinTestGroupAddr(int addr);
extern int get_IgmpJoinTestGroupPort();
extern int set_IgmpJoinTestGroupPort(int res);
extern int get_IgmpJoinTestVersion();
extern int set_IgmpJoinTestVersion(int res);
extern int set_IgmpJoinTest(int action);
extern int get_QosMarkCosRemark(int);
extern void get_QosMarkDscpRemark(int, unsigned char *);
extern int wirelessClientList(int index);
extern void get_wlanActiveSSID(int w_index, int idx, unsigned char *destBuf);
extern void get_wlanActiveMac(int w_index, int idx, unsigned char *destBuf);
extern int get_wlanActiveMode(int w_index, int idx);
extern void get_wlanActiveRSSI(int w_index, int idx, unsigned char *destBuf);
extern void get_wlanActiveSNR(int w_index, int idx, unsigned char *destBuf);
extern void get_wlanActiveBER(int w_index, int idx, unsigned char *destBuf);
extern int get_hostInfoPortNumber(int idx);
extern void get_hostInfoMacAddr(int idx, unsigned char *var_val);
extern unsigned int get_hostInfoIpAddr(int idx);
extern unsigned int get_portStatusCrc(int idx);
extern unsigned long get_portStatusInBytes(int idx);
extern unsigned long get_portStatusOutBytes(int idx);
extern int get_portSpeed(int p_index);
extern int get_portPower(int p_index);
extern int set_portPower(int p_index, int PowerOn);
extern int get_DevicePortNego(int port);
extern int get_DevicePortSpeed(int port);
extern int get_DevicePortDuplex(int port);
extern int get_DevicePortOnOff(int port);
extern int set_DevicePortNego(int nego, int index);
extern int set_DevicePortSpeed(int Mbyte, int index);
extern int set_DevicePortDuplex(int plex, int index);
extern int set_DevicePortOnOff(int power, int index);
extern int get_PortQosPriority(int index);

extern void get_QosRuleDstIp(int, char *);
extern void get_QosRuleSrcIp(int index, char *val);
extern void get_QosRuleDstPortStart(int index, char *val);
extern void get_QosRuleDstPortEnd(int index, char *val);
extern void get_QosRuleSrcPortStart(int index, char *val);
extern void get_QosRuleSrcPortEnd(int index, char *val);
extern void get_QosRuleDstMacAddr(int index, char *val);
extern void get_QosRuleSrcMacAddr(int index, char *val);
extern int get_QosRuleProtocol(int index, char *val);
extern int get_QosRuleCos(int index);
extern int get_QosRuleTosType(int index);
extern int get_QosRuleTos(int index);
extern void get_QosRuleEthType(int index, char *val);
extern int get_QosRuleMarkIndex(int index);
extern int initHostInfo(void);

void get_systemConfigRootAccount(char *getbuf, int len);
int set_systemConfigRootAccount(char *val, int len);

int port_phreq_to_command(char *cmd, struct phreq *phr);
int port_cmd_to_phreq(char *cmd, struct phreq *phr);
void init_port_status();
int init_securityConfig();
int init_ping_test_t();
int set_pingProtocol(int no, int protocol);
char *get_pingAddress(int no);
int get_pktCount(int no);
int get_pktSize(int no);
int get_pktDelay(int no);
int get_pktTimeout(int no);
int get_TrapOnCompletion(int no);
int get_sentPktCount(int no);
int get_recvPktCount(int no);
int get_minPingTime(int no);
int get_maxPingTime(int no);
int get_avgPingTime(int no);
int get_pingCompleted(int no);
char *get_EntryOwner(int no);
int get_pingEntryStatus(int no);
int set_pingAddress(int no, char *val);
int set_pktCount(int no, int val);
int set_pktSize(int no, int size);
int set_pktDelay(int no, int val);
int set_pktTimeout(int no, int val);
int set_TrapOnCompletion(int no, int val);
int set_EntryOwner(int no, char *val);
int set_pingEntryStatus(int no, int action);
void update_ping_result(int no);
extern struct phreq portReqs[PH_MAXPORT + 1];
//added by kkm
extern int get_igmpJoinTable(int select, _igmpTbl_t *T);
extern int get_igmpJoinTable(int select, _igmpTbl_t *T);
extern int get_igmpJoinMemberNumber(_igmpTbl_t *T);
extern int get_igmpJoinPort(_igmpTbl_t *T);
extern unsigned int get_multicastJoinIpAddress(_igmpTbl_t *T);
extern int get_multicastPortNumber(_igmpTbl_t *T);
extern int get_multicastPortName(_igmpTbl_t *T);

extern int get_multicastOperation(int no);
extern unsigned int get_multicastInPackets(int no);
extern unsigned int get_multicastOutPackets(int no);
extern int random_utilization();
extern long get_cpu_utiliz(void);
extern long get_ram_utiliz(void);
extern long set_delete_syslog(int res);
extern int set_wlanReset(int res);
extern int set_sysName(unsigned char *, int);

int init_cpeping_test_t();
void update_cpeping_result(int no);
int get_cpepingEntryStatus(int no);
int get_mincpePingTime(int no);
int get_maxcpePingTime(int no);
int get_timeoutcpePingTime(int no);
int get_avgcpePingTime(int no);
int set_cpepingEntryStatus(int no, int action);
int checksum(unsigned short *buf, int sz);
int get_cpepingtrap_enable(void);
int set_cpepingtrap_enable(int val);
int get_wanport_phyconfig();
int get_wlanResetMode();
int set_wlanResetMode(int);
int snmp_cpeping_test(int No);
unsigned long get_portStatus(int i, int flag);
int get_Ipv6PassThruMode();
int set_Ipv6PassThruMode(int mode);
void getPortMac(int index, char *buf);
int set_HardWareReset(int res);
int get_autoResetWanTraffic();
int set_autoResetWanTraffic(int res);
int get_wirelessHandover();
int set_wirelessHandover(int mode);

int set_wlanAutoband(int wl_band, int val);
long get_wlanAutoband(int wl_band);
int set_wlanSessionLimit(int wl_band, int val);
long get_wlanSessionLimit(int wl_band);
long get_wlanSession(int wl_band);
int set_wanPortTraffic(int val);
long get_wanPortTraffic(void);

extern void get_portFwProtocol(unsigned char *protocol);
extern int set_portFwProtocol(unsigned char *protocol, int len);
extern int get_PortFwExternalSport(void);
extern int set_PortFwExternalSport(int portNum);
extern int get_PortFwExternalEport();
extern int set_PortFwExternalEport(int portNum);
extern void get_PortFwIpAddress(void *ipAddr);
extern int set_PortFwIpAddress(unsigned char *ipAddr);
extern int get_PortFwInternalSport();
extern int set_PortFwInternalSport(int portNum);
extern int get_PortFwInternalEport();
extern int set_PortFwInternalEport(int portNum);
extern int set_PortFwEnable(int portfwAdd);
extern int set_PortFwDelete(int portfwDel);
extern int set_PortFwDeleteAll(int deleteAll);
extern void portfw_list();
extern int get_portFwStartPort(int index);
extern int set_portFwStartPort(int index, int portNum);
extern int get_portFwEndPort(int index);
extern int set_portFwEndPort(int index, int portNum);
extern void get_PortfwIpAddress(int index, void *Ip);
extern int set_PortfwLanAddr(int index, unsigned char *Ipaddress);
extern int get_portFwLanPort(int index);
extern int set_portFwLanPort(int index, int portNum);

extern int set_FactoryReset(int res);
extern int set_AdminReset(int res);
extern int port_index_change(int index);

#define SSID_LEN        32
#define MAX_BSS_DESC    64
#define MESH_ID_LEN     32

#define x_AUTO	"auto"
#define FORCE	"duplex"
#define M10		"10"
#define M100	"100"
#define M1000	"1000"
#define FULL	"full"
#define HALF	"half"
#define UP		"up"
#define DOWN 	"down"

typedef struct _OCTET_STRING_SNMP {
    unsigned char *Octet;
    unsigned short Length;
} OCTET_STRING_SNMP;

typedef enum _BssType {
    infrastructure = 1,
    independent = 2,
} BssType;

typedef struct _IbssParms {
    unsigned short  atimWin;
} IbssParms;

typedef struct _acl_Var{
	int Index;
} acl_Var;

typedef struct _Device_port{
	char Port_power_var[52];
} Device_port;

typedef struct wlan_scan_info_t
{
    unsigned char ssid[32];
    unsigned char bssid[6];
    unsigned char channel[30];
    unsigned char encrypt[20];
    unsigned char rssi[5];
} wlan_scan_info;

typedef struct _bss_info {
    unsigned char state;
    unsigned char channel;
    unsigned char txRate;
    unsigned char bssid[6];
    unsigned char rssi, sq;	// RSSI  and signal strength
    unsigned char ssid[SSID_LEN+1];
} bss_info;

typedef struct _BssDscr {
    unsigned char bdBssId[6];
    unsigned char bdSsIdBuf[SSID_LEN];
    OCTET_STRING_SNMP  bdSsId;

//#if defined(CONFIG_RTK_MESH) || defined(CONFIG_RTL_819X)
	//by GANTOE for site survey 2008/12/26
	unsigned char bdMeshIdBuf[32];
	OCTET_STRING_SNMP bdMeshId;
//#endif
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
   unsigned char        stage;
} BssDscr, *pBssDscr;

typedef struct _sitesurvey_status {
    unsigned char number;
    unsigned char pad[3];
    BssDscr bssdb[MAX_BSS_DESC];
} SS_STATUS_T, *SS_STATUS_Tp;

#define CPEPING_RESULT_PATH "/var/tmp/cpe_ping"

static inline int
iw_get_ext(int skfd, char * ifname, int request, struct iwreq * pwrq)
{
  /* Set device name */
  strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);
  /* Do the request */
  return(ioctl(skfd, request, pwrq));
}

extern int getWlanScanInfo(int wl_idx, wlan_scan_info* wlInfo_);
#define FILE_SERVER "/var/tmp/cpesock"
#define SUPPORT_HOST_NUM 10
#define BUFF_SIZE   256
struct CPEList_t
{
	int No;
	int portno;
	char addr[32];
	char cpemac[32];
};

#endif //__SKBB_API_H__
