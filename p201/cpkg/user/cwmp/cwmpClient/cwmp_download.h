#ifndef _CWMP_DOWNLOAD_H_
#define _CWMP_DOWNLOAD_H_

#include "cwmpGlobal.h"
#include <shutils.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MACBIND			18
#define MAX_STB_CNT			9
#define MAX_VOIP_CNT		9
#define MAX_ATC_CNT			16
#define MAX_FWNO_CNT		64
#define MAX_NTP				8
//#define MAX_SNMP_ACCESS		8
#define MAX_TELNET_ACCESS	16
#define MAX_CR_ADDR			16 
#define MAX_TWAMP_LIST_CNT	24		//APACRTL-604
#define MAX_ACCESS_STR_LEN	32

#define UPLOAD_INFO_FILE_NAME           "/var/tmp/autoupgrade/upinfo"
#define DOWNLOAD_CONFIG_FILE_NAME       "/var/tmp/autoupgrade/dn_conf"
#define DOWNLOAD_PROV_FILE_NAME 	"/var/tmp/autoupgrade/dn_prov"
#define DOWNLOAD_HTTP_RESP_FILE_NAME 	"/var/tmp/autoupgrade/http_resp"
#define LOG_FILE_NAME                   "/var/tmp/autoupgrade/log"
#define POLLTIME_FILE_NAME              "/var/tmp/autoupgrade/nextpoll"
#define PID_FILE_NAME                   "/var/run/autoupgrade.id"
#define PVS_RESULT_FILE_NAME		"/var/tmp/autoupgrade/pvs.rep"
#define TMP_FIRMWARE_FILE_NAME		"/tmp/capd6000.bin"

enum {
	PROV_NONE = -1,
	PROV_DOWNLOAD_OK,
	PROV_URL_ERROR,
	PROV_SOCK_ERROR,
	PROV_TIMEOUT,
	PROV_CONFIG_ERROR,
	PROV_IMAGE_ERROR,
	PROV_IMAGE_SZ_ERROR,
	PROV_IMAGE_RESP_ERROR,
	PROV_SYSTEM_ERROR,
	PROV_RESPONSE_ERROR,
	PROV_UPLOAD_INFO_ERROR,
	PROV_DECOMP_ERROR,
};

typedef struct {
	char	name[16];
	char	protocol[8];
	unsigned short	wport;
	unsigned short	lport;
	char	dev_type[8];
	unsigned short	dev_no;
} port_forward_t;

typedef struct {
	port_forward_t	portfwd[32];
	unsigned short	tbl_count;
	short			use;
} _forward_tbl_t;

typedef struct {
	char ip[20];
	int port;
} _twamp_tbl_t;		//APACRTL-604

typedef enum {
	VAR_STB_MAC,
	VAR_VOIP_MAC,
	VAR_ACS_URL,
	VAR_IDS_URL,
	VAR_CONF_FILE,
	VAR_ERR_CODE,
	VAR_ERR_STR,
	VAR_ENCRYPT_KEY,       
	VAR_CONF_VERSION,       
	VAR_VERSION,            
	VAR_DIRECTORY,
	VAR_IMAGE,
	VAR_FILESIZE,           
	VAR_POLLING_PERIOD,
	VAR_POLLING_DAYS,
	VAR_POLLING_RANGE,
	VAR_POLLING_TIME,
#if 0
	VAR_NTP_SERVER,           
#else
	VAR_NTP_SERVER,           
	VAR_NTP_PROTO,           
	VAR_NTP_PORT,           
#endif
	VAR_TELNET_ACCESS,      
	VAR_FIREWALL_IN,        
	VAR_FIREWALL_OUT,       
	VAR_PORTFORWARD,
	VAR_PORTFORWARD_USE,
	VAR_MTU,
	VAR_MAX_ASSOC,
	VAR_IPTV_DSCP,          
	VAR_VOIP_DSCP,
	VAR_LAN_BLOCK,
	VAR_LAN_GATEWAY,
	VAR_IPTVPOOL_START,           
	VAR_IPTVPOOL_END,           
	VAR_VOIPPOOL_START,           
	VAR_VOIPPOOL_END,           
	VAR_PCPOOL_START,             
	VAR_PCPOOL_END,             
	VAR_CTRL_TRAFFIC,       
	VAR_DHCP_LEASE,         
	VAR_APS_RETRY,          
	VAR_APS_TIMEOUT,        
	VAR_ACS_RETRY,          
	VAR_ACS_TIMEOUT,        
	VAR_IDS_RETRY,          
	VAR_IDS_TIMEOUT,        
	VAR_NTP_RETRY,          
	VAR_NTP_TIMEOUT,        
	VAR_ATC_NUM,            
	VAR_ATCADDRESS,         
	VAR_APS_DOMAIN,         
	VAR_AUTH_DOMAIN1,		
	VAR_AUTH_DOMAIN2,       
	VAR_AUTH_IP1,           
	VAR_AUTH_IP2,           
	VAR_AUTH_PORT1,         
	VAR_AUTH_PORT2,         
	VAR_ACC_DOMAIN1, 
	VAR_ACC_DOMAIN2, 
	VAR_ACC_IP1,     
	VAR_ACC_IP2,     
	VAR_ACC_PORT1,   
	VAR_ACC_PORT2,   
	VAR_HPMS_DOMAIN,     
	VAR_HPMS_IP,         
	VAR_HPMS_PORT1,      
	VAR_HPMS_PORT2,      
	VAR_RMS_DOMAIN,         
	VAR_RMS_IP,             
	VAR_RMS_PORT1,          
	VAR_RMS_PORT2,          
	VAR_QMS_DOMAIN,         
	VAR_QMS_IP,             
	VAR_QMS_PORT1,          
	VAR_QMS_PORT2,
	VAR_FIRST_WINDOW_URL,
	VAR_DEV_MAC_LIST,
	VAR_FORCED_UPGRADE,
	VAR_SW_TAG_OK,
	VAR_IOT_VERSION,
	VAR_IOT_URL,
	VAR_IOT_FILESIZE,
	VAR_IOT_FILENAME,
	VAR_STB_ONLY,	 //APACRTL-495
	VAR_STUN_DOMAIN,	//APACRTL-505
	VAR_RCS_DOMAIN, 	//APACRTL-505        
	VAR_STUN_MAX_PERIOD,	//APACRTL-505         
	VAR_STUN_MIN_PERIOD,	//APACRTL-505         
	VAR_HP_PERIOD,	//APACRTL-505         
	VAR_HP_TTL,	//APACRTL-505
	VAR_CNSSEC_ENABLE,	//LG CNS security
	VAR_CNSSEC_POLLING_DAY,	//LG CNS security
	VAR_CNSSEC_SERVER,	//LG CNS security
	VAR_QLC_DIAGLOG_ENABLE,
	VAR_QLC_DIAGLOG_URL,
	VAR_QLC_DIAGLOG_PERIOD,
	VAR_QLC_STATLOG_ENABLE,	//APACRTL-622
	VAR_QLC_STATLOG_URL,	//APACRTL-622
	VAR_QLC_STATLOG_PERIOD,	//APACRTL-622
	VAR_QLC_STATLOG_SIZE,	//APACRTL-622
	VAR_QLC_STATLOG_INTERVAL,	//APACRTL-622
	VAR_QLC_STATLOG_STATION,	//APACRTL-622
	VAR_CR_ADDR,
	VAR_PERIODIC_RESET_ENABLE,
	VAR_PERIODIC_RESET_INTERVAL,
	VAR_PERIODIC_RESET_TIME,
	VAR_PERIODIC_RESET_RANGE,
	VAR_IOT_SERVICE_USE,
	//TWAMP
	VAR_TWAMP_ENABLE,
	VAR_TWAMP_SENDER_IP,
	VAR_TWAMP_SENDER_PORT
} var_kind_t;

typedef struct {
	char	conf_ver[16];   // integer
	char    sw_version[MAX_FWNO_CNT][8];     // x.x.x
	char    sw_dir[MAX_FWNO_CNT][128];         // sw directory
	char	sw_image[MAX_FWNO_CNT][128];
	int     sw_file_size[MAX_FWNO_CNT];       // xxx bytes

	char	iot_version[8];
	char	iot_url[128];
	char	iot_filename[32];
	int		iot_filesize;

	char 	is_sw_tag_ok;
	int		forcedUpgrade[MAX_FWNO_CNT];
#if 0	
	char	ntp_server[MAX_NTP][64];		// ntp_server: address,protocol(ntp or tp),port
#else
	char	ntp_server[MAX_NTP][64];		// ntp_server: address,protocol(ntp or tp),port
	char	ntp_proto[MAX_NTP][8];		// ntp_server: address,protocol(ntp or tp),port
	char	ntp_port[MAX_NTP][8];		// ntp_server: address,protocol(ntp or tp),port
#endif
	char	telnet_access[MAX_TELNET_ACCESS][MAX_ACCESS_STR_LEN];
	int     pvs_retry;        // xxx times
	int		acs_retry;
	int		ids_retry;
	int		ntp_retry;
	
	int     pvs_timeout;      // xxx times
	int		acs_timeout;
	int		ids_timeout;
	int		ntp_timeout;
	
	_forward_tbl_t	fwdtbl;
	char	firewall_in[8][64];
	char	firewall_out[8][64];
	unsigned short	mtu;
	unsigned short	max_assoc;
	unsigned short	iptv_dscp;
	unsigned short	voip_dscp;
	char	lan_block[16];
	char	lan_gateway[16];
	char	iptv_start[16];		// IPTV IP POOL
	char	iptv_end[16];
	char	voip_start[16];		// VOIP(WIFI PHONE +CPG) IP POOL
	char	voip_end[16];
	char	pcpool_start[16];	// Home Device IP POOL
	char	pcpool_end[16];
	char	polling_period[8];
	int		polling_days;
	int		polling_range;
	int		polling_time;
	unsigned int	control_traffic;
	unsigned int	dhcp_lease;
	char	pvs_server[64];
	unsigned short atc_num;
	char	atc_addr[MAX_ATC_CNT][16];
	char	rs_auth_server[2][64];	// TOBEAPPLIED begin
	char	rs_auth_ip[2][16];
	int		rs_auth_port[2];
	char	rs_account_server[2][64];
	char	rs_account_ip[2][16];
	int		rs_account_port[2];
	char	rms_server[64];
	char	rms_ip[16];
	int		rms_port[2];
	char	qms_server[64];
	char	qms_ip[16];
	int		qms_port[2];			// TOBEAPPLIED end
	char	devMac[MAX_MACBIND][64];
	char 	first_window_url[128];
	int		stb_only;	 //APACRTL-495
	char	stun_domain[64];	//APACRTL-505
	char	rcs_domain[64];		//APACRTL-505
	int 	stun_min_period;		//APACRTL-505
	int 	stun_max_period;		//APACRTL-505
	short 	hp_period;		//APACRTL-505
	short 	hp_ttl;		//APACRTL-505
	short	cnssec_enable;	//LG CNS security
	short	cnssec_polling_day;	//LG CNS security
	char	cnssec_server[128];	//LG CNS security
	short qlc_diaglog_enable;
	short qlc_diaglog_period;	
	char qlc_diaglog_url[128];
	int qlc_statlog_setflag;	//APACRTL-622
	int qlc_statlog_enable;	//APACRTL-622
	char qlc_statlog_url[128];	//APACRTL-622
	int qlc_statlog_period;	//APACRTL-622
	int qlc_statlog_size;	//APACRTL-622
	int qlc_statlog_interval;	//APACRTL-622
	int qlc_statlog_station;	//APACRTL-622
	char cr_addr[MAX_CR_ADDR][32];
	//APACQCA-59
	short periodic_reset_enable;
	short periodic_reset_interval_days;
	char periodic_reset_time[8];
	short periodic_reset_range;
	short iot_service_use;
	//TWAMP
	int twamp_enable;
	_twamp_tbl_t twamp_tbl[MAX_TWAMP_LIST_CNT];
} dn_conf_t;

extern int gStartDownload;

void cwmpStartDownload(struct soap *soap);

#ifdef __cplusplus
}
#endif

#endif /*_CWMP_DOWNLOAD_H_*/
