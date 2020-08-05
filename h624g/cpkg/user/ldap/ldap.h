#ifndef __LDAP_H__
#define __LDAP_H__

#define MAX_ID	100

#define STR(arg) { arg, #arg }

#define __WIFI_DUAL__	1

typedef struct CFG_ID_NAME {
   int  id;
   char *name;
}CFG_ID_NAME;

struct ldap_item {
	int  id;		/* name id: dvnv, mib, stdout use name */   	
	char value[128];  
	unsigned int flag;		/* dvnv | value type(string, int...) | reboot | ... */
};
struct ldap_cfg_t {
	int entry;
	int normal_down_cfg;
	struct ldap_item item[MAX_ID];
};

typedef union {
    unsigned int all;
    struct {
        unsigned int major:8;
        unsigned int minor:8;
        unsigned int conf:8;
        unsigned int :8;
    } i;
} version_t;


struct fwinfo {
    char confurl[128];      /* including file name (ex) http://config.skbroadband.com/config */
    char binpath[128];      /* image server */
    char binname[80];       /* image file name */
    version_t cur, new;
    int background, quiet;
    int upgrade_keep_going;
};

#define T_MASK   0x7

enum { T_STRING, T_INT, T_IPV4, T_PORT, T_ONOFF};

enum {
    FLG_REBOOT 		= (1 << 3),    /* Need reboot */
    FLG_NILNOK 		= (1 << 4),    /* Can not be null(nil) */
    FLG_INETATON	= (1 << 5),    /* Neither 0.0.0.0 nor 255.255.255.255 */
    FLG_INANY 		= (1 << 6),    /* if not specified, consider as "0.0.0.0" */
    FLG_DVNV		= (1 << 7),
	FLG_APMIB 		= (1 << 8),
	FLG_TOGGLE 		= (1 << 9),
	FLG_5G	 		= (1 << 10),
};

typedef struct variable_s {
	int id;
    const char *name;
    int (*setvar)(struct variable_s *, const char *);
    void *data;
    unsigned int val_type;
} variable;

struct wlan_ssid_t
{
	const char *mib_name;
	int enable;
};

struct wlan_ratelimit_t
{
	int setup;
	int ratelimit;
	int seq_f;
};

struct wlan_info_t
{	
	int seq_f;
	struct in_addr srv_addr;
	int port;
	char passwd[32];
};

struct wlan_ep_auth_info_t
{
	int setup_f;
	struct wlan_info_t radius;
	struct wlan_info_t account;	
};

struct wlan_auth_t {
	char *server;
	char *port;
	char *passwd;
};

struct lan_st_t {
	int set;
	int val;	
};

struct lan_port_t {
	struct lan_st_t auto_nego;
	struct lan_st_t speed;
	struct lan_st_t duplex;
	struct lan_st_t power_off;
	struct lan_st_t rate_limit;
};

#define FORMAT_VERSION					1 	/* not saved */	
#define cfg_filename					2 	/* dvnv: CFG_FILENAME */
#define dv_autoup_auth_svr				3 	/* dvnv:AUTH_SVR */
#define dv_ldap_autoup_domain			4 	/* not saved */
#define FW_VER							5 	/* not saved */
#define dv_ldap_autoup_file				6 	/* not saved */
#define syslog_server_url				7 	/* mib: SYSLOG_SVR */
#define DNS_MODE						8 	/* mib: AUTO_DNS */
#define OP_MODE							9 	/* mib: NAT_ENABLE */
#define DHCP_CLIENT_START				10	/* mib: NAT_STARTIP */
#define DHCP_CLIENT_END					11 	/* mib: NAT_ENDIP */
#define x_SNMP_ENABLE					12	/* dvnv: SNMP_ENABLE */
#define x_SNMP_GET_COMMUNITY			13 	/* dvnv: SNMP_GET_COMMUNITY */
#define x_SNMP_SET_COMMUNITY			14	/* dvnv: SNMP_SET_COMMUNITY */
#define x_SNMP_TRAP_COMMUNITY  			15	/* dvnv: SNMP_TRAP_COMMUNITY */
#define x_WIFI_TRAP_SERVER				16	/* dvnv: WIFI_TRAFFIC_TRAP_SVR */
#define x_holepunch_enabled				17	/* dvnv: HP_ENABLE */
#define PORT_NEGO	 					18	/* dvnv: PORT_NEGO LAN1(3) LAN2(2) LAN3(1) LAN4(0) */
#define PORT_SPEED 						19	/* dvnv: PORT_SPEED LAN1(3) LAN2(2) LAN3(1) LAN4(0) */
#define PORT_DUPLEX 					20	/* dvnv: PORT_DUPLEX LAN1(3) LAN2(2) LAN3(1) LAN4(0) */
#define PORT_ENABLE 					21	/* dvnv: PORT_ENABLE LAN1(3) LAN2(2) LAN3(1) LAN4(0) */
#define PORT_RATE_LIMIT					22	/* dvnv: PORT_RATE_LIMIT RX LAN1(3) LAN2(2) LAN3(1) LAN4(0)&& TX LAN1(3) LAN2(2) LAN3(1) LAN4(0) */
#define IGMP_DISABLED					23	/* mib: IGMP_PROXY_DISABLED */
#define IGMP_PROXY_DISABLED				24  
#define IGMP_FAST_LEAVE_DISABLED		25	/* dvnv: igmp_fast_leave_enable */
#define x_igmp_expire_time				26	/* dvnv: member_expire_time */
#define x_igmp_query_interval			27	/* dvnv: query_interval */
#define x_igmp_query_res_interval		28	/* dvnv: query_response_interval */
#define dv_ldap_autoup_enabled			29	/* not saved: AUTO_UPGRADE_ENABLE */
#define AUTO_UPGRADE_SVR 				30	/* dvnv: AUTO_UPGRADE_SVR */
#define FIRMWARE_FILE					31	/* not saved */
#define WLAN_DISABLED					32	/* mib: WIFI_2G_ENABLE */
#define SSID_ENABLE 					33	/* mib: SSID_ENABLE VAP0: anyway VAP1: sk_voip VAP2: t wifi home VAP3: sk_wlan_vap3 */
#define HIDDEN_SSID						34	/* mib: HIDDEN_SSID: SK_WiFixxxx VAP0: anyway VAP1: sk_voip VAP2: t wifi home VAP3: sk_wlan_vap3 */
#define DESIGNATED_RATE_LIMIT_SSID		35	/* dvnv: DESIGNATED_RATE_LIMIT_SSID: SK_WiFixxxx VAP0: anyway VAP1: sk_voip VAP2: t wifi home VAP3: sk_wlan_vap3 */
#define RADIUS_AUTH_SSID				36  /* mib */
#define MAC_AUTH_SSID					37  /* mib */
#define RADIUS_SVR_INFO					38  /* mib */
#define ACCOUNT_SVR_INFO				39  /* mib */
#if defined(__WIFI_DUAL__)	
//#define WIFI_5G_ENABLE					40
#define WIFI_5G_DISABLED				40
#define SSID_5G_ENABLE					41
#define HIDDEN_5G_SSID					42
#define DESIGNATED_5G_RATE_LIMIT_SSID	43
#define RADIUS_AUTH_5G_SSID				44
#define MAC_AUTH_5G_SSID				45
#define RADIUS_SVR_5G_INFO				46
#define ACCOUNT_SVR_5G_INFO				47
#endif
#define HP_SVR_IP_PORT					48 /* dvnv: HP_SVR_IP_PORT */
#define x_holepunch_control_interval	49 /* dvnv: HP_INTERVAL */
#define x_auto_reboot_on_idle			50 /* dvnv: AUTO_REBOOT_ON_IDLE: Y run / N not run */
#define x_auto_uptime					51 /* dvnv: UPTIME */
#define x_auto_wan_port_idle			52 /* dvnv: WAN_PORT_IDLE */
#define x_auto_hour_range 				53 /* dvnv: HOUR_RANGE */
#define model							54 /* not saved: model */
//===============================================================================================


#endif //__LDAP_H__
