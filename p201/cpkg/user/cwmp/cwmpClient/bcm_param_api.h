#include <typedefs.h>

#define MAXIDX		2

#ifdef __SERVICE_LGU_ENT__
#define MAXSUBIDX	7
#else
#define MAXSUBIDX	2
#endif

#define MAX_WLAN	(MAXIDX * MAXSUBIDX)

#define MAX_IPDM_SIZE 80
#define WL_DUMP_BUF_LEN 	(127 * 1024)
#define ETHER_ADDR_STR_LEN	18
#define MAX_STA_COUNT		128

#define IPDM_WL_ERR_SAV_FILE	"/var/tmp/cwmp/.wl_err_cnt.sav"
#define BRIDGE_MODE_FILE		"/tmp/.br_mode"
#define WLBRIDGE_MODE_FILE		"/tmp/.wlbr_mode"

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#define LOG_MAXSIZE 32768

#define IS_BRIDGE_MODE (access(BRIDGE_MODE_FILE, F_OK)==0)
#define IS_WLBRIDGE_MODE (access(WLBRIDGE_MODE_FILE, F_OK)==0)

#define NEIGH_CH_STR_LEN 16

#ifndef MAX_LAN_PORT
#define MAX_LAN_PORT 4
#endif

#define WAN_IP_FILE "/var/wan_ip"
#define WAN_NM_FILE "/var/netmask"
#define WAN_GW_FILE "/var/gateway"
#define IP_BUF_LEN 16

#ifndef LAN_IFNAME
#define LAN_IFNAME "br0"
#endif
#ifndef WAN_IFNAME
#define WAN_IFNAME "eth1"
#endif

#define WAN_MO_NOT_SET 9999

/*******************
GAPD-7100
 0 : LAN1
 1 : LAN2
 2 : LAN3
 3 : LAN4
 4 : WAN
********************/
enum {
	MIN_PORT = 0,
	LAN_PORT1 = 0,
	LAN_PORT2,
	LAN_PORT3,
	LAN_PORT4,
	WAN_PORT,
	MAX_PORT
};
#define WLAN_2G_DATA   11
#define WLAN_2G_MEMBER 12
#define WLAN_5G_DATA   21
#define WLAN_5G_MEMBER 22

enum {
	LOWER = 0,
	UPPER
};

enum {
	BAND_20MHZ = 0,
	BAND_40MHZ,
	BAND_80MHZ
};

enum {
	WAN_NOT_SET = 0,
	WAN_DHCP,
	WAN_STATIC
};

enum {
	TYPE_LINK = 1,	//Link Status
	TYPE_MAXBT,	//MaxBitrate
	TYPE_DUPLEX	//Duplex
};

enum {
	LINKUP = 1,
	NOLINK,
	DISABLE
};

enum {
	M_10 = 1,
	M_100,
	M_500,
	M_1000,
	M_AUTO
};

enum {
	D_HALF = 1,
	D_FULL,
	D_AUTO
};

typedef struct {
	char ipAddr[16];
	int  rssi;
	int  auth_info;
	uint assocTime;
	unsigned long tx_bytes;
	unsigned long rx_bytes;
	char macAddr[19];
	char auth_type;
} wl_client_info_t;

struct ip_tbl_t {
	char strip[20];
	char strmac[20];
	int	 expires;
};
struct _packet_filter_t {
	char	enable;
	char	direction[8];
	char	policy[8];
	char	protocol[8];
	char	srcip[36];
	char	srcport[32];
	char	srcmac[20];
	char	dstip[36];
	char	dstport[32];
};
struct _port_map_t {
	char	srcip[20];
	char	protocol[7];
	char 	enable;
	int		intPort;
	int		extPort;
	int		Range;
};

struct lease_t {
	unsigned char chaddr[16];
	unsigned int yiaddr;
	unsigned int expires;
	char hostname[64];
};

/*-----------------------------------------------------------------------------
 *  Neighbor AP
 *-----------------------------------------------------------------------------*/
#define STRNCMP nv_strcmp

typedef struct {
	int channel;
	int rssi;
	int scan;
	char ch_str[NEIGH_CH_STR_LEN];
} _neighap_info_t;

typedef struct _OCTET_STRING {
	unsigned char *Octet;
	unsigned short Length;
} OCTET_STRING;

typedef enum _BssType {
	infrastructure = 1,
	independent = 2,
} BssType;

typedef enum _Capability {
	cESS 		= 0x01,
	cIBSS		= 0x02,
	cPollable		= 0x04,
	cPollReq		= 0x01,
	cPrivacy		= 0x10,
	cShortPreamble	= 0x20,
} Capability;

#define BIT(x)  (1 << (x))

#ifndef BSS_BW_SHIFT
#define BSS_BW_SHIFT    5
#endif

#ifndef BSS_BW_MASK
#define BSS_BW_MASK     0x7
#endif

enum _HT_CHANNEL_WIDTH {
	HT_CHANNEL_WIDTH_20     = 0,
	HT_CHANNEL_WIDTH_20_40  = 1,
	HT_CHANNEL_WIDTH_80     = 2,
	HT_CHANNEL_WIDTH_160    = 3,
	HT_CHANNEL_WIDTH_10     = 4,
	HT_CHANNEL_WIDTH_5      = 5
};

extern unsigned int err_sav[MAXIDX][MAXSUBIDX];
extern int sys_reboot;

void add_colon_to_macaddr(char* dest, char *src, int bufsz, int _case);
void remove_colon_from_macaddr(char* dest, char *src, int bufsz, int _case);
int check_dotted_mac(char *src);
int check_colon_mac(char *src);
int check_number_mac(char *src);
void str_lower(char *p);
int u8_tr069_STRLEN(char *s);
unsigned int rand_seed(void);
void init_post_mo_setting(void);

void get_wlan_idxes(int objidx, int *wl_idx, int *wl_subidx);
char *get_wlan_ifname_from_idx(char *buf, int bufsz, int idx, int subidx);
char *get_lan_name(void);
uint64 get_dev_stat_info(char *inf, int isTx);
unsigned int get_traffic(char *, int);
void get_producer(char *val, int bufsz, int idx, int subidx);
void get_vendor(char *val, int bufsz, int idx, int subidx);
void get_model(char *val, int bufsz, int is_lower);
void get_version(char *val, int bufsz, int idx, int subidx);
int get_port_map_count(void);
char *conv_mac_format(char *mac);
int conv_mac_format_4_to_a(char *src, char *dst);
int conv_mac_format_4_to_e(char *src, unsigned char e[6]);
char *conv_mac_format_to_4(char *mac);
void get_wan_macaddr(char *val, int bufsz, int _case);
char *get_clone_macaddr(char *val, int bufsz, int _case);
void set_clone_macaddr(char *val, int bufsz, int _case);
void get_serial(char *val, int bufsz);
char *get_ap_name(char *buf, size_t bufsz);
int set_ap_name(char *val);

char *get_wanip(char *val, size_t valsz);
int set_wanip(char *val);
char *get_wanmask(char *val, size_t valsz);
int set_wanmask(char *val);
char *get_gateway(char *val, size_t valsz);
int set_gateway(char *val);

char *get_dns(char *val, int bufsz, int idx, int subidx);
int set_dns(char *val);

char *get_lanip(char *val, size_t valsz);
int set_lanip(char *val);
char *get_lanmask(char *val, size_t valsz);
int set_lanmask(char *val);
int set_lan(void);
int get_dhcp(void);
int set_dhcp(int res);

char *get_wan_proto(char *val, int bufsz, int idx, int subidx);
char *get_wan_proto_mo(char *val, size_t valsz);
int set_wan_proto(char *val);
int set_wan(void);

int set_ssh_passwd(char *val);

char *get_ntp_server(char *val, int valsz, int idx);
int set_ntp_server(char *val, int idx);
char *get_ntp_protocol(char *val, int bufsz, int idx, int subidx);
int set_ntp_protocol(char *val, int idx, int subidx);
void get_ntp_port(char *val, int bufsz, int idx, int subidx);
int set_ntp_port(char *val, int idx, int subidx);
char *get_time_svr(char *val, int bufsz, int idx, int subidx);
int set_time_svr(char *val, int idx, int subidx);
char *get_time_ip(char *val, int bufsz, int idx, int subidx);
int set_time_ip(char *val, int idx, int subidx);
char *get_ntp_tz(char *val, int valsz);
int set_ntp_tz(char *val);

int get_port_traffic(int pn, uint64 *tr, int is_tx);

int get_routerqos(void);
int set_routerqos(int val);
int get_qosuplimit(void);
int set_qosuplimit(int val);

unsigned int get_fwd_num(void);
void get_fwd_list(struct _port_map_t *List);
char *get_fwd_list_str(char *val, int bufsz);

char *get_dmz(char *val, int bufsz, int idx, int subidx);

int get_filtering_list(struct _packet_filter_t  *pf_list);
char *get_filtering_list_qms(char *buf, int bufsz);

int get_arp_spoofing(char *val);

int get_device_info(struct ip_tbl_t *list);
int get_connected_port_with_mac(char *mac);
char *get_lanport_device_mac(char *val, int bufsz, int idx);
char *get_lanport_device_ip(char *val, int bufsz, int idx);

char *get_ssid(char *buf, int bufsz, int idx, int subidx);
int set_ssid(char *val, int idx, int subidx);
char *get_bssid(char *buf, int bufsz, int idx, int subidx);
int get_ssid_enable(int idx, int subidx);
int set_ssid_enable(int val, int idx, int subidx);
void get_vssid_security(char *val, int bufsz, int idx, int subidx);
int set_vssid_security(char *val, int idx, int subidx);
int get_bss_max_assoc(int idx, int subidx);
int set_bss_max_assoc(int res, int idx, int subidx);
int set_encrypt_key();
int set_encrypt_mode();
int set_wlchannel();
void init_wl_ratelimit_t(void);
void set_wl_rate_limit(void);
int get_traffic_limit_on(int idx, int subidx);
int set_traffic_limit_on(int val, int idx,int subidx);
int get_traffic_limit_tx(int idx, int subidx);
int set_traffic_limit_tx(int val, int idx, int subidx);
int get_traffic_limit_rx(int idx, int subidx);
int set_traffic_limit_rx(int val, int idx, int subidx);
int get_rssi_limit(int subidx, int idx);
int set_rssi_limit(int val, int idx, int subidx);
int get_wl_client_info(int idx, int subidx);
int get_sta_dev_mon(FILE *fp, int numif, int numbss);
unsigned int get_wl_err_cnt(int idx, int subidx);
int set_wl_err_ini(int val, int idx, int subidx);
unsigned int get_dev_traffic(int pn, int isTx);
unsigned long long get_dev_traffic_64(int pn, int isTx);
unsigned int get_wl_traffic(int idx, int subidx, int isTx);
int get_ssid_hidden(int idx, int subidx);
int set_ssid_hidden(int val, int idx, int subidx);
int get_ssid_inner_con(int idx, int subidx);
int set_ssid_inner_con(int val, int idx, int subidx);
int get_ssid_web_access(int idx, int subidx);
int set_ssid_web_access(int val, int idx, int subidx);
int get_vlan_id(int idx, int subidx);
int set_vlan_id(int val, int idx, int subidx);
int get_ssid_lgauth(int idx, int subidx);
int set_ssid_lgauth(int res, int idx, int subidx);
int get_ssid_encryption(int idx, int subidx);
int set_ssid_encryption(int val, int idx, int subidx);
char *get_ssid_encryptionkey(char *val, int bufsz, int idx, int subidx);
int set_ssid_encryptionkey(char *val, int idx, int subidx);
void get_customer_web(char *val, int bufsz, int idx, int subidx);
int set_customer_web(char *val, int idx, int subidx);
void get_customer_web_url(char *val, int bufsz, int idx, int subidx);
int set_customer_web_url(char *val, int idx, int subidx);
int get_mac_auth_restrict_list(const char *prefix, char *val, int sz);
int add_mac_auth_restrict_list(const char *prefix, char *val);
int del_mac_auth_restrict_list(const char *prefix, char *val);
char *get_auth_limit_list(char *val, int bufsz, int idx, int subidx);
int add_1x_auth_list(char *val, int idx, int subidx);
int del_1x_auth_list(char *val, int idx, int subidx);
int get_lgauth_info_flag(int idx, int subidx);
int set_lgauth_info_flag(int var, int idx, int subidx);
void get_radius_domain(char *val, int bufsz, int idx, int subidx);
int set_radius_domain(char *val, int idx, int subidx);
void get_radius_ip(char *val, int bufsz, int idx, int subidx);
int set_radius_ip(char *val, int idx, int subidx);
void get_radius_port(char *val, int bufsz, int idx, int subidx);
int set_radius_port(char *val, int idx, int subidx);
void get_radius_shared_secret(char *val, int bufsz, int idx, int subidx);
int set_radius_shared_secret(char *val, int idx, int subidx);
void get_radius_domain2(char *val, int bufsz, int idx, int subidx);
int set_radius_domain2(char *val, int idx, int subidx);
void get_radius_ip2(char *val, int bufsz, int idx, int subidx);
int set_radius_ip2(char *val, int idx, int subidx);
void get_radius_port2(char *val, int bufsz, int idx, int subidx);
int set_radius_port2(char *val, int idx, int subidx);
void get_radius_shared_secret2(char *val, int bufsz, int idx, int subidx);
int set_radius_shared_secret2(char *val, int idx, int subidx);
void get_acct_domain(char *val, int bufsz, int idx, int subidx);
int set_acct_domain(char *val, int idx, int subidx);
void get_acct_ip(char *val, int bufsz, int idx, int subidx);
int set_acct_ip(char *val, int idx, int subidx);
void get_acct_port(char *val, int bufsz, int idx, int subidx);
int set_acct_port(char *val, int idx, int subidx);
void get_acct_shared_secret(char *val, int bufsz, int idx, int subidx);
int set_acct_shared_secret(char *val, int idx, int subidx);
void get_acct_domain2(char *val, int bufsz, int idx, int subidx);
int set_acct_domain2(char *val, int idx, int subidx);
void get_acct_ip2(char *val, int bufsz, int idx, int subidx);
int set_acct_ip2(char *val, int idx, int subidx);
void get_acct_port2(char *val, int bufsz, int idx, int subidx);
int set_acct_port2(char *val, int idx, int subidx);
void get_acct_shared_secret2(char *val, int bufsz, int idx, int subidx);
int set_acct_shared_secret2(char *val, int idx, int subidx);
void get_lgauth_web(char *val, int bufsz, int idx, int subidx);
int set_lgauth_web(char *val, int idx, int subidx);
void get_lgauth_web_redir_url(char *val, int bufsz, int idx, int subidx);
int set_lgauth_web_redir_url(char *val, int idx, int subidx);
void get_web_auth_info_flag(char *val, int bufsz, int idx, int subidx);
int set_web_auth_info_flag(char *val, int idx, int subidx);
void get_web_auth_port(char *val, int bufsz, int idx, int subidx);
int set_web_auth_port(char *val, int idx, int subidx);
int get_bonding_master_ch_idx(int idx);
int set_bonding_master_ch_idx(int val, int idx);
int get_ch_bonding_use(int idx);
int set_ch_bonding_use(int res, int idx);
int get_auto_chan_use(int idx);
int set_auto_chan_use(int res, int idx);
int get_current_channel(int);
int set_wifi_chan(int res, int idx);
int get_5g_chann_zone(char *val, int bufsz, int idx, int subidx);
int set_5g_chann_zone(char *val, int idx, int subidx);
int get_wifi_power(int idx);
int set_wifi_power(int val, int idx);
int get_wifi_radio_status(int idx);

int update_neigh_ap(int radio);
void reset_neigh_ap(int radio);
int scan_neigh_ap(int radio);
int get_neigh_ap_num(int radio);
int get_neigh_ap_channel(int radio, int idx);
int get_neigh_ap_rssi(int radio, int idx);
char *get_neigh_ap_qms(char *buf, int bufsz, int radio);

time_t get_upgrade_time();
char *get_upgrade_time_str(char *val, int bufsz);

void get_polling_list(char *val, int bufsz, int idx, int subidx);

char *get_lan_error(char *val, int bufsz, int idx, int subidx);
int set_lan_err_ini(char *val, int idx, int subidx);
int get_err_cnt(char *val, int bufsz, int portnum, int isTx);
int get_lan_err_cnt_tx(char *val, int bufsz, int portnum);
int get_lan_err_cnt_rx(char *val, int bufsz, int portnum);
int get_wan_err_cnt_tx(char *val, int bufsz);
int get_wan_err_cnt_rx(char *val, int bufsz);
int get_igmp_tables(char *val, int bufsz);
int get_igmp_test(char *val, int bufsz);
int set_igmp_test(char *val, int bufsz);
int get_igmp_test_result(char *val, int bufsz);

int set_reboot(char *val, int idx, int subidx);
int set_default(char *val, int idx, int subidx);
int set_lan_reset(int res, int idx, int subidx);
int set_wan_reset(int val);
int set_wifi_reset(int res, int idx, int subidx);

#ifdef __LGU_5000H__
void get_lanport_use(char *val, int bufsz, int idx, int subidx);
int set_lanport_use(char *val, int idx, int subidx);
void get_wifi_use(char *val, int bufsz, int idx, int subidx);
int set_wifi_use(char *val, int idx, int subidx);
#endif

int get_remote_http(char *val, int bufsz, int idx, int subidx);
int set_remote_http(char *val, int idx, int subidx);
char *get_remote_http_ip(char *val, int bufsz, int idx, int subidx);
int set_remote_http_ip(char *val, int idx, int subidx);
int get_remote_http_port(char *val, int bufsz, int idx, int subidx);
int set_remote_http_port(char *val, int idx, int subidx);
int get_dm_reg_use(char *val, int bufsz, int idx, int subidx);
int set_dm_reg_use(char *val, int idx, int subidx);
int get_dm_reg_period(char *val, int bufsz, int idx, int subidx);
int set_dm_reg_period(char *val, int idx, int subidx);
int get_dm_hp_period(char *val, int bufsz, int idx, int subidx);
int set_dm_hp_period(char *val, int idx, int subidx);
int get_dm_hp_ttl(char *val, int bufsz, int idx, int subidx);
int set_dm_hp_ttl(char *val, int idx, int subidx);
char *get_root_passwd(char *val, int bufsz, int idx, int subidx);
int set_root_passwd(char *val, int idx, int subidx);

char *get_conf_radius_domain(char *val, int bufsz, int idx, int subidx);
char *get_conf_radius_ip(char *val, int bufsz, int idx, int subidx);
char *get_conf_radius_port(char *val, int bufsz, int idx, int subidx);
char *get_conf_radius_domain2(char *val, int bufsz, int idx, int subidx);
char *get_conf_radius_ip2(char *val, int bufsz, int idx, int subidx);
char *get_conf_radius_port2(char *val, int bufsz, int idx, int subidx);

char *get_conf_acct_domain(char *val, int bufsz, int idx, int subidx);
char *get_conf_acct_ip(char *val, int bufsz, int idx, int subidx);
char *get_conf_acct_port(char *val, int bufsz, int idx, int subidx);
char *get_conf_acct_domain2(char *val, int bufsz, int idx, int subidx);
char *get_conf_acct_ip2(char *val, int bufsz, int idx, int subidx);
char *get_conf_acct_port2(char *val, int bufsz, int idx, int subidx);

char *get_qms_domain(char *val, int bufsz, int idx, int subidx);
char *get_qms_ip(char *val, int bufsz, int idx, int subidx);
char *get_qms_port1(char *val, int bufsz, int idx, int subidx);
char *get_qms_port2(char *val, int bufsz, int idx, int subidx);

char *get_shared_secret(char *val, int bufsz, int idx, int subidx);
int set_shared_secret(char *val, int idx, int subidx);
int get_shared_secret_flag();
int set_shared_secret_flag(int res, int idx, int subidx);

int get_conf_web_auth_port(int idx, int subidx);
char *get_auth_web_redir_url(char *val, int bufsz, int idx, int subidx);
int set_auth_web_redir_url(char *val, int idx, int subidx);

char *get_first_window(char *val, int bufsz, int idx, int subidx);
char *get_first_window_url(char *val, int bufsz, int idx, int subidx);

int get_phy_tx_over(int idx, int subidx);
int set_phy_tx_over(int res, int idx, int subidx);
int get_phy_rx_over(int idx, int subidx);
int set_phy_rx_over(int res, int idx, int subidx);
int get_phy_tx_th(int idx, int subidx);
int set_phy_tx_th(int res, int idx, int subidx);
int get_phy_rx_th(int idx, int subidx);
int set_phy_rx_th(int res, int idx, int subidx);
int get_ssid_tx_over(int idx, int subidx);
int set_ssid_tx_over(int res, int idx, int subidx);
int get_ssid_rx_over(int idx, int subidx);
int set_ssid_rx_over(int res, int idx, int subidx);
int get_ssid_tx_th(int idx, int subidx);
int set_ssid_tx_th(int res, int idx, int subidx);
int get_ssid_rx_th(int idx, int subidx);
int set_ssid_rx_th(int res, int idx, int subidx);
int get_ssid_conn_over(int idx, int subidx);
int set_ssid_conn_over(int res, int idx, int subidx);
int get_ssid_conn_th(int idx, int subidx);
int set_ssid_conn_th(int res, int idx, int subidx);
void get_white_list_version(char *val, int bufsz, int idx, int subidx);
void get_white_list_type(char *val, int bufsz, int idx, int subidx);
int update_white_list(int res);
char *get_mon_time(char *val, int bufsz);
int set_mon_time(char *val);
int get_mon_range(void);
int set_mon_range(int res);
int get_mon_days(void);
int set_mon_days(int res);
int get_mon_period(char *val, int bufsz);
int set_mon_period(char *val);
int get_mon_basic_info(void);
int set_mon_basic_info(int res);
int get_mon_config_info(void);
int set_mon_config_info(int res);
int get_mon_wifi_info(void);
int set_mon_wifi_info(int res);
int get_mon_wifi5_info(void);
int set_mon_wifi5_info(int res);
int get_mon_qos_info(void);
int set_mon_qos_info(int res);
int get_mon_ipdm_info(void);
int set_mon_ipdm_info(int res);
int get_mon_server_info(void);
int set_mon_server_info(int res);
int get_mon_service_info(void);
int set_mon_service_info(int res);
int get_mon_mon_info(void);
int set_mon_mon_info(int res);
int get_mon_acl_info(void);
int set_mon_acl_info(int res);
int get_traffic_mon(void);
int set_traffic_mon(int res);
char *get_traffic_time(char *val, int bufsz);
int set_traffic_time(char *val);
int get_traffic_range(void);
int set_traffic_range(int res);
int get_traffic_period(void);
int set_traffic_period(int res);
char *get_acl_list(char *strDest, int bufsz);
char *get_acl_info_use(char *val, int bufsz);
int set_acl_info_use(char *val, int idx, int subidx);
int add_acl_info(char *val, int idx, int subidx);
int del_acl_info(char *val, int idx, int subidx);
int reset_acl_info(char *val, int idx, int subidx);
unsigned int get_ssid_loop_cnt(int idx, int subidx, int isTx);
int get_phy_tx_loop_cnt(int idx, int subidx);
int get_phy_rx_loop_cnt(int idx, int subidx);

int get_acl_info_count(void);
char *get_wbr_ifname(void);
unsigned int get_interference(int idx);
int set_interference(int, int);
void start_wps(void);
void stop_wps(void);
int is_conn_iot_dongle();

char *get_wl_client_info_qms(char *val, int bufsz, int idx, int subidx);
void get_assocDevice_mac(char *buf, int size, int idx);
void get_assocDevice_ip(char *buf, int size, int idx);
int get_assocDevice_rssi(int idx);
int get_assocDevice_auth_info(int idx);
char get_assocDevice_auth_type(int idx);
unsigned int get_assocDevice_assocTime(int idx);

int get_device_log_from_file(const char *filename, char *log);

char *get_static_lease_qms(char *val, int bufsz, int idx, int subidx);

char *get_acs_domain(char *val, int bufsz, int idx, int subidx);
char *get_acs_ip(char *val, int bufsz, int idx, int subidx);
char *get_ids_domain(char *val, int bufsz, int idx, int subidx);
char *get_ids_ip(char *val, int bufsz, int idx, int subidx);

char *get_static_route(char *buf, int bufsz, int idx, int subidx);

int nvram_atoi(char *name, int dfl);
unsigned int get_uptime_mo();
char *get_gateway_mac(char *buf, int bufsz);
int get_lan_port_num_from_idx(int idx);
char *get_lan_link_conn_status(int idx);
char *get_wan_link_conn_status();
char *get_lan_maxbitrate(int idx);
char *get_wan_maxbitrate();
char *get_lan_duplex(int idx);
char *get_wan_duplex();

int get_twamp_status(char *buf, int bufsz);
unsigned int get_twamp_listen_port(void);
int get_twamp_sender_acl(char *buf, int bufsz);

unsigned int get_wan_pause_frame_status(void);
int set_wan_pause_frame_status(unsigned int val);
unsigned int get_port_pause_frame_status(int port);
int set_port_pause_frame_status(int port, unsigned int val);
