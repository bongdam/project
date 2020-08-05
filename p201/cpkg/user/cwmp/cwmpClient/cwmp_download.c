#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include "cwmpGlobal.h"
#include "cwmp_download.h"
#include <bcmnvram.h>
#include <libytool.h>
#include <bcmutils.h>
#include <syslog.h>
#include <furl.h>
#include <hanguel.h>
#include <shutils.h>
#include <strtok_s.h>

#ifndef DAVO_IMAGE_SIZE
#define DAVO_IMAGE_SIZE		0x7b0000
#endif

#include "bcm_param_api.h"

int gStartDownload = 0;

extern struct pollInfo pollInfo;
extern void cwmpSendEvent(unsigned int event);
extern void cwmpSetCpeHold(int holdit);

#define CONF_CHG(x) ((1)<<(x))
enum {
	CONF_TR069        = 0,
	CONF_PORT_FORWARD = 2,
	CONF_SNMP         = 3,
	CONF_SSH          = 4,
	CONF_DSCP         = 5,
	CONF_NTP          = 6,
	CONF_FIREWALL     = 7,
	CONF_RADIUS       = 8,
	CONF_MTU          = 9,
	CONF_CR           = 10,
	CONF_DHCP         = 11,
	CONF_SELF_REBOOT  = 16,
	CONF_DIAGLOG      = 24,
	CONF_SECD         = 25,
	CONF_STATLOG      = 26
};

typedef struct {
	char *name;
	int kind;
} var_tbl_t;

typedef struct {
	char *buf;
	char *trx_hd;
	char upload_fifo[40];
	int len;
	int trx_image_size;
	FILE *fifo;
	pid_t pid;
} image_t;

static dn_conf_t dn_conf;
const var_tbl_t conf_vars[] = { {"conf_version", VAR_CONF_VERSION },
	{ "version", VAR_VERSION },
	{ "directory", VAR_DIRECTORY },
	{ "sw_image", VAR_IMAGE },
	{ "sw_tag_ok", VAR_SW_TAG_OK },
	{ "filesize", VAR_FILESIZE },
	{ "iot_version", VAR_IOT_VERSION },
	{ "iot_dn_url", VAR_IOT_URL },
	{ "iot_dn_size", VAR_IOT_FILESIZE },
	{ "iot_filename", VAR_IOT_FILENAME },
	{ "polling_period", VAR_POLLING_PERIOD },
	{ "polling_days", VAR_POLLING_DAYS },
	{ "polling_range", VAR_POLLING_RANGE },
	{ "polling_time", VAR_POLLING_TIME },
	{ "ntp_server", VAR_NTP_SERVER },
	{ "ntp_proto", VAR_NTP_PROTO },
	{ "ntp_port", VAR_NTP_PORT },
	{ "telnms", VAR_TELNET_ACCESS },
	{ "fw_in", VAR_FIREWALL_IN },
	{ "fw_out", VAR_FIREWALL_OUT },
	{ "portforward", VAR_PORTFORWARD },
	{ "forward_use", VAR_PORTFORWARD_USE },
	{ "mtu", VAR_MTU },
	{ "max_assoc", VAR_MAX_ASSOC },
	{ "iptv_dscp", VAR_IPTV_DSCP },
	{ "voip_dscp", VAR_VOIP_DSCP },
	{ "lan_block", VAR_LAN_BLOCK },
	{ "lan_gateway", VAR_LAN_GATEWAY },
	{ "iptvpool_start", VAR_IPTVPOOL_START },
	{ "iptvpool_end", VAR_IPTVPOOL_END },
	{ "voippool_start", VAR_VOIPPOOL_START },
	{ "voippool_end", VAR_VOIPPOOL_END },
	{ "pcpool_start", VAR_PCPOOL_START },
	{ "pcpool_end", VAR_PCPOOL_END },
	{ "control_traffic", VAR_CTRL_TRAFFIC },
	{ "dhcp_lease", VAR_DHCP_LEASE },
	{ "aps_retry", VAR_APS_RETRY },
	{ "aps_timeout", VAR_APS_TIMEOUT },
	{ "acs_retry", VAR_ACS_RETRY },
	{ "acs_timeout", VAR_ACS_TIMEOUT },
	{ "ids_retry", VAR_IDS_RETRY },
	{ "ids_timeout", VAR_IDS_TIMEOUT },
	{ "ntp_retry", VAR_NTP_RETRY },
	{ "ntp_timeout", VAR_NTP_TIMEOUT },
	{ "atc_address", VAR_ATCADDRESS },
	{ "aps_domain", VAR_APS_DOMAIN },
	{ "auth_domain1", VAR_AUTH_DOMAIN1 },
	{ "auth_domain2", VAR_AUTH_DOMAIN2 },
	{ "auth_ip1", VAR_AUTH_IP1 },
	{ "auth_ip2", VAR_AUTH_IP2 },
	{ "auth_port1", VAR_AUTH_PORT1 },
	{ "auth_port2", VAR_AUTH_PORT2 },
	{ "acc_domain1", VAR_ACC_DOMAIN1 },
	{ "acc_domain2", VAR_ACC_DOMAIN2 },
	{ "acc_ip1", VAR_ACC_IP1 },
	{ "acc_ip2", VAR_ACC_IP2 },
	{ "acc_port1", VAR_ACC_PORT1 },
	{ "acc_port2", VAR_ACC_PORT2 },
	{ "qms_domain", VAR_QMS_DOMAIN },
	{ "qms_ip", VAR_QMS_IP },
	{ "qms_port1", VAR_QMS_PORT1 },
	{ "qms_port2", VAR_QMS_PORT2 },
	{ "first_window_url", VAR_FIRST_WINDOW_URL },
	{ "devList", VAR_DEV_MAC_LIST },
	{ "forcedUpgrade", VAR_FORCED_UPGRADE },
	{ "stun_domain", VAR_STUN_DOMAIN },	//APACRTL-505
	{ "rcs_domain", VAR_RCS_DOMAIN },	//APACRTL-505
	{ "stun_min_period", VAR_STUN_MIN_PERIOD },	//APACRTL-505
	{ "stun_max_period", VAR_STUN_MAX_PERIOD },	//APACRTL-505
	{ "hp_period", VAR_HP_PERIOD },	//APACRTL-505
	{ "hp_ttl", VAR_HP_TTL },	//APACRTL-505
	{ "cnssec_enable", VAR_CNSSEC_ENABLE },
	{ "cnssec_polling_day", VAR_CNSSEC_POLLING_DAY },
	{ "cnssec_server", VAR_CNSSEC_SERVER },
	{ "qlc_diaglog_enable", VAR_QLC_DIAGLOG_ENABLE },
	{ "qlc_diaglog_period", VAR_QLC_DIAGLOG_PERIOD },
	{ "qlc_diaglog_url", VAR_QLC_DIAGLOG_URL },
	{ "qlc_statlog_enable", VAR_QLC_STATLOG_ENABLE },	//APACRTL-622
	{ "qlc_statlog_url", VAR_QLC_STATLOG_URL },	//APACRTL-622
	{ "qlc_statlog_period", VAR_QLC_STATLOG_PERIOD },	//APACRTL-622
	{ "qlc_statlog_size", VAR_QLC_STATLOG_SIZE },	//APACRTL-622
	{ "qlc_statlog_interval", VAR_QLC_STATLOG_INTERVAL },	//APACRTL-622
	{ "qlc_statlog_station", VAR_QLC_STATLOG_STATION },	//APACRTL-622
	{ "cr_addr", VAR_CR_ADDR },
	{ "periodic_reset_enable", VAR_PERIODIC_RESET_ENABLE },
	{ "periodic_reset_interval_days", VAR_PERIODIC_RESET_INTERVAL },
	{ "periodic_reset_time", VAR_PERIODIC_RESET_TIME },
	{ "periodic_reset_range", VAR_PERIODIC_RESET_RANGE },
	{ "iot_service_use", VAR_IOT_SERVICE_USE },
	{ "twamp_enable", VAR_TWAMP_ENABLE },		//APACRTL-604
	{ "twamp_sender_ip", VAR_TWAMP_SENDER_IP },
	{ "twamp_sender_port", VAR_TWAMP_SENDER_PORT },
	{ NULL, -1}
};

/***********************************************************************/
/* porting functions */
/***********************************************************************/
static char *get_variable_from_line(char *line, const var_tbl_t *list, var_kind_t *kind)
{
	char *p;

	while (list && list->name && list->name[0] != 0) {
		if (strncasecmp(line, list->name, STRLEN(list->name)) == 0) {
			if ((p = strchr(line, '=')) != NULL) {
				while (*p == '=' || *p == ' ' || *p == '\t')
					p++;
			}
			if (kind)
				*kind = list->kind;
			return (p);
		}
		list++;
	}
	return (NULL);
}

static int parse_download_config_file(dn_conf_t *dn_conf)
{
	FILE *fp;
	char *value, line[120], *ptr;
	char *min;
	int found = 0;
	var_kind_t kind;
	int pfc = 0, tmp;
	int atc = 0, tac = 0, dmc = 0, cr = 0;
	int ntc_s = 0, ntc_pr = 0, ntc_pt = 0;
	int fic = 0, foc = 0;	// firewall in/out count
	unsigned int val_len = 0;
	int fw_no = 0;
	int twamp_sender_ip_no = 0;
	int twamp_sender_port_no = 0;

	//APACRTL-602 : PTV동작 조건 추가
	FILE *atc_fp = NULL;
	int len = 0;
	char t[128] = "";
	struct in_addr in;
	rename("/tmp/.atc_addr", "/tmp/.atc_addr.back");

	memset(dn_conf, 0, sizeof(dn_conf_t));

	if ((fp = fopen("/var/tmp/autoupgrade/dn_conf", "r")) != NULL) {
		while (fgets(line, sizeof(line), fp) > 0) {
			value = get_variable_from_line(line, conf_vars, &kind);
			if (value != NULL && STRLEN(value) > 0) {
				ydespaces(value);
				found += 1;
				switch (kind) {
				case VAR_CONF_VERSION:
					strncpy(dn_conf->conf_ver, value, sizeof(dn_conf->conf_ver) - 1);
					break;
				case VAR_VERSION:
					fw_no = atoi(line + STRLEN("version")) - 1;
					if (fw_no >= 0 && fw_no < MAX_FWNO_CNT)
						snprintf(dn_conf->sw_version[fw_no], sizeof(dn_conf->sw_version[fw_no]), "%s", value);
					break;
				case VAR_DIRECTORY:
					fw_no = atoi(line + STRLEN("directory")) - 1;
					if (fw_no >= 0 && fw_no < MAX_FWNO_CNT)
						snprintf(dn_conf->sw_dir[fw_no], sizeof(dn_conf->sw_dir[fw_no]), "%s", value);
					break;
				case VAR_IMAGE:
					fw_no = atoi(line + STRLEN("sw_image")) - 1;
					if (fw_no >= 0 && fw_no < MAX_FWNO_CNT)
						snprintf(dn_conf->sw_image[fw_no], sizeof(dn_conf->sw_image[fw_no]), "%s", value);
					break;
				case VAR_FILESIZE:
					fw_no = atoi(line + STRLEN("filesize")) - 1;
					if (fw_no >= 0 && fw_no < MAX_FWNO_CNT)
						dn_conf->sw_file_size[fw_no] = atoi(value);
					break;
				case VAR_SW_TAG_OK:
					dn_conf->is_sw_tag_ok = atoi(value);
					break;
				case VAR_IOT_VERSION:
					snprintf(dn_conf->iot_version, sizeof(dn_conf->iot_version), "%s", value);
					break;
				case VAR_IOT_URL:
					snprintf(dn_conf->iot_url, sizeof(dn_conf->iot_url), "%s", value);
					break;
				case VAR_IOT_FILESIZE:
					dn_conf->iot_filesize = atoi(value);
					break;
				case VAR_IOT_FILENAME:
					snprintf(dn_conf->iot_filename, sizeof(dn_conf->iot_filename), "%s", value);
					break;
				case VAR_POLLING_TIME:
					dn_conf->polling_time = atoi(value);
					min = strchr(value, ':');
					if (min != NULL) {
						min += 1;
					} else {
						*min = 0;
					}
					dn_conf->polling_time = dn_conf->polling_time * 3600 + atoi(min) * 60;
					break;
				case VAR_POLLING_RANGE:
					dn_conf->polling_range = atoi(value) * 60;
					break;
				case VAR_POLLING_PERIOD:
					strncpy(dn_conf->polling_period, value, sizeof(dn_conf->polling_period) - 1);
					break;
				case VAR_POLLING_DAYS:
					dn_conf->polling_days = atoi(value);
					break;
				case VAR_NTP_SERVER:

					snprintf(dn_conf->ntp_server[ntc_s], sizeof(dn_conf->ntp_server[ntc_s]), "%s", value);
					ntc_s++;
					break;
				case VAR_NTP_PROTO:

					snprintf(dn_conf->ntp_proto[ntc_pr], sizeof(dn_conf->ntp_proto[ntc_pr]), "%s", value);
					ntc_pr++;
					break;
				case VAR_NTP_PORT:

					snprintf(dn_conf->ntp_port[ntc_pt], sizeof(dn_conf->ntp_port[ntc_pt]), "%s", value);
					ntc_pt++;
					break;
				case VAR_TELNET_ACCESS:
					if (tac < 16)
						strncpy(dn_conf->telnet_access[tac++], value, MAX_ACCESS_STR_LEN);
					break;
				case VAR_FIREWALL_IN:
					if (fic < 8) {
						snprintf(dn_conf->firewall_in[fic], sizeof(dn_conf->firewall_in[fic]), "%s", value);
						fic++;
					}
					break;
				case VAR_FIREWALL_OUT:
					if (foc < 8) {
						snprintf(dn_conf->firewall_out[foc], sizeof(dn_conf->firewall_out[foc]), "%s", value);
						foc++;
					}
					break;
				case VAR_PORTFORWARD:
					if (pfc < 32) {
						ptr = strsep(&value, ",");
						snprintf(dn_conf->fwdtbl.portfwd[pfc].name, sizeof(dn_conf->fwdtbl.portfwd[pfc].name), "%s", ptr);
						ptr = strsep(&value, ",");
						snprintf(dn_conf->fwdtbl.portfwd[pfc].protocol, sizeof(dn_conf->fwdtbl.portfwd[pfc].protocol), "%s", ptr);
						ptr = strsep(&value, ",");
						dn_conf->fwdtbl.portfwd[pfc].wport = atoi(ptr);
						ptr = strsep(&value, ",");
						dn_conf->fwdtbl.portfwd[pfc].lport = atoi(ptr);
						ptr = strsep(&value, ",");
						snprintf(dn_conf->fwdtbl.portfwd[pfc].dev_type, sizeof(dn_conf->fwdtbl.portfwd[pfc].dev_type), "%s", ptr);
						ptr = strsep(&value, ",");
						dn_conf->fwdtbl.portfwd[pfc].dev_no = atoi(ptr);
						dn_conf->fwdtbl.tbl_count = (++pfc);
					}
					break;
				case VAR_PORTFORWARD_USE:
					dn_conf->fwdtbl.use = atoi(value);
					break;
				case VAR_MTU:
					dn_conf->mtu = atoi(value);
					break;
				case VAR_MAX_ASSOC:
					dn_conf->max_assoc = atoi(value);
					break;
				case VAR_IPTV_DSCP:
					tmp = atoi(value);
					dn_conf->iptv_dscp = (tmp << 2) & 0xff;
					break;
				case VAR_VOIP_DSCP:
					tmp = atoi(value);
					dn_conf->voip_dscp = (tmp << 2) & 0xff;
					break;
				case VAR_LAN_BLOCK:
					snprintf(dn_conf->lan_block, sizeof(dn_conf->lan_block), "%s", value);
					break;
				case VAR_LAN_GATEWAY:
					snprintf(dn_conf->lan_gateway, sizeof(dn_conf->lan_gateway), "%s", value);
					break;
				case VAR_IPTVPOOL_START:
					snprintf(dn_conf->iptv_start, sizeof(dn_conf->iptv_start), "%s", value);
					break;
				case VAR_IPTVPOOL_END:
					snprintf(dn_conf->iptv_end, sizeof(dn_conf->iptv_end), "%s", value);
					break;
				case VAR_VOIPPOOL_START:
					snprintf(dn_conf->voip_start, sizeof(dn_conf->voip_start), "%s", value);
					break;
				case VAR_VOIPPOOL_END:
					snprintf(dn_conf->voip_end, sizeof(dn_conf->voip_end), "%s", value);
					break;
				case VAR_PCPOOL_START:
					snprintf(dn_conf->pcpool_start, sizeof(dn_conf->pcpool_start), "%s", value);
					break;
				case VAR_PCPOOL_END:
					snprintf(dn_conf->pcpool_end, sizeof(dn_conf->pcpool_end), "%s", value);
					break;
				case VAR_CTRL_TRAFFIC:
					dn_conf->control_traffic = atoi(value);
					break;
				case VAR_DHCP_LEASE:
					dn_conf->dhcp_lease = atoi(value);
					break;
				case VAR_APS_RETRY:
					dn_conf->pvs_retry = atoi(value);
					break;
				case VAR_ACS_RETRY:
					dn_conf->acs_retry = atoi(value);
					break;
				case VAR_IDS_RETRY:
					dn_conf->ids_retry = atoi(value);
					break;
				case VAR_NTP_RETRY:
					dn_conf->ntp_retry = atoi(value);
					break;
				case VAR_APS_TIMEOUT:
					dn_conf->pvs_timeout = atoi(value);
					break;
				case VAR_ACS_TIMEOUT:
					dn_conf->acs_timeout = atoi(value);
					break;
				case VAR_IDS_TIMEOUT:
					dn_conf->ids_timeout = atoi(value);
					break;
				case VAR_NTP_TIMEOUT:
					dn_conf->ntp_timeout = atoi(value);
					break;
				case VAR_ATCADDRESS:
					if (atc < MAX_ATC_CNT) {
						snprintf(dn_conf->atc_addr[atc], sizeof(dn_conf->atc_addr[atc]), "%s", value);
						
						//APACRTL-602 : PTV동작 조건 추가
						if ((STRLEN(dn_conf->atc_addr[atc]) > 0) && 
								(inet_aton(dn_conf->atc_addr[atc], &in) != 0)) {
							if (!atc_fp && (access("/tmp/.atc_addr", F_OK) != 0))
								atc_fp = fopen("/tmp/.atc_addr", "a+");

							if (access("/tmp/.atc_addr", F_OK) == 0 && atc_fp)  {
								snprintf(t, sizeof(t), "%s\n", dn_conf->atc_addr[atc]);
								len = fwrite(t, 1, STRLEN(t), atc_fp);
								if (len != STRLEN(t)) {
									fclose(atc_fp);
									atc_fp = NULL;
								}
							}
						}
						
						atc++;
					}
					dn_conf->atc_num = atc;
					break;
				case VAR_APS_DOMAIN:
					snprintf(dn_conf->pvs_server, sizeof(dn_conf->pvs_server), "%s", value);
					break;
				case VAR_AUTH_DOMAIN1:	// TOBEAPPLIED begin
					snprintf(dn_conf->rs_auth_server[0], sizeof(dn_conf->rs_auth_server[0]), "%s", value);
					break;
				case VAR_AUTH_DOMAIN2:
					snprintf(dn_conf->rs_auth_server[1], sizeof(dn_conf->rs_auth_server[1]), "%s", value);
					break;
				case VAR_AUTH_IP1:
					snprintf(dn_conf->rs_auth_ip[0], sizeof(dn_conf->rs_auth_ip[0]), "%s", value);
					break;
				case VAR_AUTH_IP2:
					snprintf(dn_conf->rs_auth_ip[1], sizeof(dn_conf->rs_auth_ip[1]), "%s", value);
					break;
				case VAR_AUTH_PORT1:
					dn_conf->rs_auth_port[0] = atoi(value);
					break;
				case VAR_AUTH_PORT2:
					dn_conf->rs_auth_port[1] = atoi(value);
					break;
				case VAR_ACC_DOMAIN1:
					snprintf(dn_conf->rs_account_server[0], sizeof(dn_conf->rs_account_server[0]), "%s", value);
					break;
				case VAR_ACC_DOMAIN2:
					snprintf(dn_conf->rs_account_server[1], sizeof(dn_conf->rs_account_server[1]), "%s", value);
					break;
				case VAR_ACC_IP1:
					snprintf(dn_conf->rs_account_ip[0], sizeof(dn_conf->rs_account_ip[0]), "%s", value);
					break;
				case VAR_ACC_IP2:
					snprintf(dn_conf->rs_account_ip[1], sizeof(dn_conf->rs_account_ip[1]), "%s", value);
					break;
				case VAR_ACC_PORT1:
					dn_conf->rs_account_port[0] = atoi(value);
					break;
				case VAR_ACC_PORT2:
					dn_conf->rs_account_port[1] = atoi(value);
					break;
				case VAR_QMS_DOMAIN:
					snprintf(dn_conf->qms_server, sizeof(dn_conf->qms_server), "%s", value);
					break;
				case VAR_QMS_IP:
					snprintf(dn_conf->qms_ip, sizeof(dn_conf->qms_ip), "%s", value);
					break;
				case VAR_QMS_PORT1:
					dn_conf->qms_port[0] = atoi(value);
					break;
				case VAR_QMS_PORT2:	// TOBEAPPLIED end
					dn_conf->qms_port[1] = atoi(value);
					break;
				case VAR_FIRST_WINDOW_URL:
					snprintf(dn_conf->first_window_url, sizeof(dn_conf->first_window_url), "%s", value);
					break;
				case VAR_DEV_MAC_LIST:
					if (dmc < MAX_MACBIND) {
						snprintf(dn_conf->devMac[dmc], sizeof(dn_conf->devMac[dmc]), "%s", value);
						dmc++;
					}
					break;
				case VAR_FORCED_UPGRADE:
					fw_no = atoi(line + STRLEN("forcedUpgrade")) - 1;
					if (fw_no >= 0 && fw_no < MAX_FWNO_CNT)
						dn_conf->forcedUpgrade[fw_no] = atoi(value);
					break;
				case VAR_STUN_DOMAIN:
					val_len = STRLEN(value);
					strncpy(dn_conf->stun_domain, value, val_len);
					dn_conf->stun_domain[val_len] = '\0';
					break;
				case VAR_RCS_DOMAIN:
					val_len = STRLEN(value);
					strncpy(dn_conf->rcs_domain, value, val_len);
					dn_conf->rcs_domain[val_len] = '\0';
					break;
				case VAR_STUN_MIN_PERIOD:
					dn_conf->stun_min_period = atoi(value);
					break;
				case VAR_STUN_MAX_PERIOD:
					dn_conf->stun_max_period = atoi(value);
					break;
				case VAR_HP_PERIOD:
					dn_conf->hp_period = atoi(value);
					break;
				case VAR_HP_TTL:
					dn_conf->hp_ttl = atoi(value);
					break;
				case VAR_CNSSEC_ENABLE:
					dn_conf->cnssec_enable = atoi(value);
					break;
				case VAR_CNSSEC_POLLING_DAY:
					dn_conf->cnssec_polling_day = atoi(value);
					break;
				case VAR_CNSSEC_SERVER:
					val_len = STRLEN(value);
					strncpy(dn_conf->cnssec_server, value, val_len);
					dn_conf->cnssec_server[val_len] = '\0';
					break;	
				case VAR_QLC_DIAGLOG_ENABLE:
					dn_conf->qlc_diaglog_enable = atoi(value);
					break;
				case VAR_QLC_DIAGLOG_PERIOD:
					dn_conf->qlc_diaglog_period = atoi(value);
					break;
				case VAR_QLC_DIAGLOG_URL:
					val_len = STRLEN(value);
					strncpy(dn_conf->qlc_diaglog_url, value, val_len);
					dn_conf->qlc_diaglog_url[val_len] = '\0';
					break;
				case VAR_QLC_STATLOG_ENABLE:
					dn_conf->qlc_statlog_setflag = 1;
					dn_conf->qlc_statlog_enable = atoi(value);
					break;
				case VAR_QLC_STATLOG_URL:
					snprintf(dn_conf->qlc_statlog_url, sizeof(dn_conf->qlc_statlog_url), "%s", value);
					break;
				case VAR_QLC_STATLOG_PERIOD:
					dn_conf->qlc_statlog_period = atoi(value);
					break;
				case VAR_QLC_STATLOG_SIZE:
					dn_conf->qlc_statlog_size = atoi(value);
					break;
				case VAR_QLC_STATLOG_INTERVAL:
					dn_conf->qlc_statlog_interval = atoi(value);
					break;
				case VAR_QLC_STATLOG_STATION:
					dn_conf->qlc_statlog_station = atoi(value);
					break;
				case VAR_CR_ADDR:
					if (cr < MAX_CR_ADDR) {
						val_len = STRLEN(value);
						strncpy(dn_conf->cr_addr[cr], value, val_len);
						dn_conf->cr_addr[cr][val_len] = '\0';
						cr++;
					}
					break;
				//APACQCA-59
				case VAR_PERIODIC_RESET_ENABLE:
					dn_conf->periodic_reset_enable = atoi(value);
					break;
				case VAR_PERIODIC_RESET_INTERVAL:
					dn_conf->periodic_reset_interval_days = atoi(value);
					break;
				case VAR_PERIODIC_RESET_TIME:
					val_len = STRLEN(value);
					strncpy(dn_conf->periodic_reset_time, value, val_len);
					dn_conf->periodic_reset_time[val_len] = '\0';
					break;
				case VAR_PERIODIC_RESET_RANGE:
					dn_conf->periodic_reset_range = atoi(value);
					break;
				case VAR_IOT_SERVICE_USE:
					dn_conf->iot_service_use = atoi(value);
					break;
				case VAR_TWAMP_ENABLE:
					dn_conf->twamp_enable = atoi(value);
					break;
				case VAR_TWAMP_SENDER_IP:
					if (twamp_sender_ip_no < MAX_TWAMP_LIST_CNT) {
						char *dest = &(dn_conf->twamp_tbl[twamp_sender_ip_no].ip[0]);
						size_t dest_size = sizeof(dn_conf->twamp_tbl[twamp_sender_ip_no].ip);
						snprintf(dest, dest_size, "%s", value);
						twamp_sender_ip_no++;
					}
					break;
				case VAR_TWAMP_SENDER_PORT:
					if (twamp_sender_port_no < MAX_TWAMP_LIST_CNT) {
						dn_conf->twamp_tbl[twamp_sender_port_no].port = atoi(value);
						twamp_sender_port_no++;
					}
					break;
				default:
					break;
				}
			}
		}
		
		if (atc_fp) {
			fclose(atc_fp);
			atc_fp = NULL;
		}

		fclose(fp);
		return (found >= 10);
	}
	return (0);
}

/* copy from boa/src/LINUX/parser.c */
void save_update_way(void)
{
	time_t this_time;
	struct tm *now;
	char buf[20];

	if (pollInfo.fPeriodic)
		nvram_set("dv_acs_update_way", "auto");
	else
		nvram_set("dv_acs_update_way", "power");

	this_time = time(NULL);
	now = localtime(&this_time);
	snprintf(buf, 20, "%04d%02d%02d%02d%02d%02d", 
	        now->tm_year + 1900, now->tm_mon + 1, now->tm_mday, 
	        now->tm_hour, now->tm_min, now->tm_sec);

	nvram_set("dv_acs_update_time", buf);
}

extern int is_downgrade;

int isNeedUpdate()
{
	int old_ver = 0;
	int new_ver = 0;
	int count = 0;
	char line[16] = {0, };
	char version[16] = {0, };
	char *p;

	get_version(version, sizeof(version), 0, 0);

	old_ver = atoi(version);

	p = &version[0];

	while ((p = strchr(p, '.')) != NULL) {
		p += 1;
		old_ver = old_ver * 100 + atoi(p);
		count++;
		if (count >= 2)
			break;
	}

	p = nvram_safe_get_r("acs_sw_next_ver", line, sizeof(line));

	new_ver = atoi(line);
	count = 0;
	while ((p = strchr(p, '.')) != NULL) {
		p += 1;
		new_ver = new_ver * 100 + atoi(p);
		count++;
		if (count >= 2)
			break;
	}

	if (new_ver == old_ver)
		return 0;
	else if (new_ver > old_ver)
		return 1;
	else
		return (-1);
}

int get_current_fwno(void)
{
	int idx = 1;
	int old_ver = 0;
	int new_ver = 0;
	int count = 0;
	char line[16] = {0, };
	char version[16] = {0, };
	char *p;
	int i = 0;
	char key[64] = {0, };

	get_version(version, sizeof(version), 0, 0);
	old_ver = atoi(version);

	p = &version[0];

	while ((p = strchr(p, '.')) != NULL) {
		p += 1;
		old_ver = old_ver * 100 + atoi(p);
		count++;
		if (count >= 2)
			break;
	}

	for (i = 1; i <= MAX_FWNO_CNT; i++) {
		snprintf(key, sizeof(key), "acs_sw_next_ver%d", i);
		p = nvram_safe_get_r(key, line, sizeof(line));

		if (STRLEN(line) < 1)
			continue;

		new_ver = atoi(line);
		count = 0;
		while ((p = strchr(p, '.')) != NULL) {
			p += 1;
			new_ver = new_ver * 100 + atoi(p);
			count++;
			if (count >= 2)
				break;
		}

		if (new_ver == old_ver) {
			idx = i;
			continue;
		} else if (new_ver > old_ver)
			return i;
	}

	return idx;
}

#define MB * 1024 * 1024
#define safe_free(p)	do { \
				if ((p)) { \
					free((p)); \
					(p) = NULL; \
				} \
			} while (0)

static int isFileExist(char *file_name)
{
	struct stat status;

	if ( stat(file_name, &status) < 0)
		return 0;

	return 1;
}

int upgradeFirmware(char *fwFilename)
{
	int status = -1;
	int ret = 0;

	struct fwstat *fbuf;
	struct stat f_stat;
	char *unused;
	FILE *fp = NULL;
	unsigned char *FW_Data = NULL;
	int major, minor, conf;
	int numWrite = 0;

	if (access(TMP_FIRMWARE_FILE_NAME, F_OK) != 0 || stat(TMP_FIRMWARE_FILE_NAME, &f_stat) < 0) {
		CWMPDBG(2, (stderr, "Firmware file is not exist or invalid.\n"));
		TLOG_PRINT("Firmware file is not exist or invalid.\n");
		ret = -1;
		goto ERR;
	}

	if (FW_Data == NULL) {
		if ((FW_Data = (unsigned char *)malloc(f_stat.st_size + sizeof(struct fwstat) + 4)) == NULL) {
			CWMPDBG(2, (stderr, "Mem allocation is failed for writing Firmware.\n"));
			TLOG_PRINT("Mem allocation is failed for writing Firmware.\n");
			ret = -1;
			goto ERR;
		}
	}

	memset(FW_Data, 0, sizeof(f_stat.st_size + sizeof(struct fwstat) + 4));
	if ((fp = fopen(TMP_FIRMWARE_FILE_NAME, "rb")) == NULL) {
		CWMPDBG(2, (stderr, "Opening Firmware file is failed.\n"));
		TLOG_PRINT("Opening Firmware file is failed.\n");
		ret = -1;
		goto ERR;
	}

	if ( (numWrite = fread(FW_Data, 1, f_stat.st_size, fp)) < f_stat.st_size ) {
		CWMPDBG(2, (stderr, "Reading Firmware file is failed.\n"));
		TLOG_PRINT("Reading Firmware file is failed.\n");
		fclose(fp);
		ret = -1;
		goto ERR;
	}

	fclose(fp);
	//unlink(TMP_FIRMWARE_FILE_NAME);
	fp = NULL;

	//support multiple image
	fbuf = (struct fwstat *)&FW_Data[(numWrite + 3) & ~3];
	memset(fbuf, 0, sizeof(struct fwstat));
	fbuf->fmem = (char *)FW_Data;
	fbuf->caplen = 8 MB;
	fbuf->rcvlen = numWrite;

	status = fw_validate(fbuf);
	if (status) {
		CWMPDBG(2, (stderr, "Firmware file is invalid.(%s)\n", fw_strerror(status)));
		TLOG_PRINT("Firmware file is invalid.(%s)\n", fw_strerror(status));
		ret = -1;
		goto ERR;
	}

	//해당 버전은 fw_validate 정상 실행 이후 들어가있음.
	major = (fbuf->version >> 14) & 3;
	minor = (fbuf->version >> 7) & 0x7f;
	conf = fbuf->version & 0x7f;
	CWMPDBG(2, (stderr, "IDS = Firmware Version : %d.%02d.%02d\n", major, minor, conf));
	TLOG_PRINT("Downloaded Firmware Version : %d.%02d.%02d\n", major, minor, conf);
	
	(void)unused;
	fw_parse_bootline(&fbuf->blnfo);
	if (!(status = fw_dualize(fbuf))) {
		yecho(IMG_WRITE_LOCKFILE, "1"); //APACRTL-456
		status = fw_write(fbuf, NULL, NULL);
		sleep(1);
		//unlink(IMG_WRITE_LOCKFILE); //APACRTL-456
	}

	if (status) {
		TLOG_PRINT("Upgrade Firmware is failed.(%s)(%d.%02d.%02d)\n", fw_strerror(status), major, minor, conf);
		CWMPDBG(2, (stderr, "Upgrade Firmware is failed.(%s)\n", fw_strerror(status)));
		ret = -1;
		goto ERR;
	}

	TLOG_PRINT("Upgrade Firmware is success.(%s)(%d.%02d.%02d)\n", fw_strerror(status), major, minor, conf);
ERR:
	if (FW_Data)
		safe_free(FW_Data);
	
	if (isFileExist(TMP_FIRMWARE_FILE_NAME))
		unlink(TMP_FIRMWARE_FILE_NAME);
	
	return ret;
}

int cwmpdl_getfilename(int dlway, DownloadInfo_T *dlinfo, char *target, int target_sz, int *ftype)
{
	if (dlinfo == NULL || target == NULL)
		return -1;

	switch (dlway) {
		case DLWAY_DOWN:
			if (nv_strcmp(dlinfo->Download.CommandKey, "cmdk_dnld_cfg") == 0) {
				*ftype = DLTYPE_CONFIG;
				snprintf(target, target_sz, "%s", "/var/tmp/autoupgrade/dn_conf");
			} else {
				*ftype = DLTYPE_IMAGE;
				snprintf(target, target_sz, "%s", "/var/tmp/cwmp/dn_img");
			}
			break;
		case DLWAY_UP:
			if (strncmp(dlinfo->Upload.FileType, "1 ", 2) == 0) {
				*ftype = DLTYPE_CONFIG;
				//call the uploadcb_getfilename();
				snprintf(target, target_sz, "%s", "/tmp/config.xml");

				//fprintf(stderr, "[%s():%d] CONFIG TODO\n", __FUNCTION__, __LINE__));
			}
			break;
		default:
			target[0] = 0;
			break;
	}

	return 0;
}

static int apply_img_parameter(dn_conf_t *cfg)
{
	int f_apply = 0;
	char buf[128] = {0, };
	int i = 0;
	char key[64] = {0, };
	int fwno = 0;

	get_version(buf, sizeof(buf), 0, 0);
	TLOG_PRINT("Current Firmware Version : %s\n", buf);

	for (i = 0; i < MAX_FWNO_CNT; i++) {
		memset(buf, 0, sizeof(buf));
		snprintf(key, sizeof(key), "acs_sw_next_ver%d", i + 1);
		nvram_safe_get_r(key, buf, sizeof(buf));
		if (STRLEN(cfg->sw_version[i]) > 0 && nv_strcmp(cfg->sw_version[i], buf)) {
			TLOG_PRINT("Applied Config Firmware Version : %s\n", cfg->sw_version[i]);
			nvram_set(key, cfg->sw_version[i]);
			f_apply = 1;
		} else {
			if (STRLEN(cfg->sw_version[i]) == 0) {
				nvram_unset(key);
				f_apply = 1;
			}
		}

		memset(buf, 0, sizeof(buf));
		snprintf(key, sizeof(key), "acs_sw_dir%d", i + 1);
		nvram_safe_get_r(key, buf, sizeof(buf));
		if (STRLEN(cfg->sw_dir[i]) > 0 && nv_strcmp(cfg->sw_dir[i], buf)) {
			nvram_set(key, cfg->sw_dir[i]);
			f_apply = 1;
		} else {
			if (STRLEN(cfg->sw_dir[i]) == 0) {
				nvram_unset(key);
				f_apply = 1;
			}
		}

		memset(buf, 0, sizeof(buf));
		snprintf(key, sizeof(key), "acs_sw_size%d", i + 1);
		nvram_safe_get_r(key, buf, sizeof(buf));
		if (cfg->sw_file_size[i] > 0 && cfg->sw_file_size[i] != atoi(buf)) {
			snprintf(buf, sizeof(buf), "%d", cfg->sw_file_size[i]);
			nvram_set(key, buf);
			f_apply = 1;
		} else {
			if (STRLEN(buf) > 0 && cfg->sw_file_size[i] == 0) {
				nvram_unset(key);
				f_apply = 1;
			}
		}

		memset(buf, 0, sizeof(buf));
		snprintf(key, sizeof(key), "acs_sw_img_name%d", i + 1);
		nvram_safe_get_r(key, buf, sizeof(buf));
		if (STRLEN(cfg->sw_image[i]) > 0 && nv_strcmp(cfg->sw_image[i], buf)) {
			nvram_set(key, cfg->sw_image[i]);
			f_apply = 1;
		} else {
			if (STRLEN(cfg->sw_image[i]) == 0) {
				nvram_unset(key);
				f_apply = 1;
			}
		}
	}

	fwno = get_current_fwno();
	if (fwno > 0) {
		snprintf(key, sizeof(key), "acs_sw_next_ver%d", fwno);
		memset(buf, 0, sizeof(buf));
		nvram_safe_get_r(key, buf, sizeof(buf));
		nvram_set("acs_sw_next_ver", buf);

		snprintf(key, sizeof(key), "acs_sw_dir%d", fwno);
		memset(buf, 0, sizeof(buf));
		nvram_safe_get_r(key, buf, sizeof(buf));
		nvram_set("acs_sw_dir", buf);

		snprintf(key, sizeof(key), "acs_sw_size%d", fwno);
		memset(buf, 0, sizeof(buf));
		nvram_safe_get_r(key, buf, sizeof(buf));
		nvram_set("acs_sw_size", buf);

		snprintf(key, sizeof(key), "acs_sw_img_name%d", fwno);
		memset(buf, 0, sizeof(buf));
		nvram_safe_get_r(key, buf, sizeof(buf));
		nvram_set("acs_sw_img_name", buf);

		snprintf(key, sizeof(key), "dv_forced_upgrade%d", fwno);
		memset(buf, 0, sizeof(buf));
		nvram_safe_get_r(key, buf, sizeof(buf));
		nvram_set("dv_forced_upgrade", buf);
	}

	return f_apply;
}

static int apply_iot_parameter(dn_conf_t *cfg)
{
	char buf[128];
	int f_apply = 0;

	nvram_safe_get_r("iot_version", buf, sizeof(buf));
	if (nv_strcmp(cfg->iot_version, buf)) {
		nvram_set("iot_version", cfg->iot_version);
		f_apply = 1;
	}

	nvram_safe_get_r("iot_url", buf, sizeof(buf));
	if (nv_strcmp(cfg->iot_url, buf)) {
		nvram_set("iot_url", cfg->iot_url);
		f_apply = 1;
	}

	nvram_safe_get_r("iot_fileSize", buf, sizeof(buf));
	if (cfg->iot_filesize != atoi(buf)) {
		snprintf(buf, sizeof(buf), "%d", cfg->iot_filesize);
		nvram_set("iot_fileSize", buf);
		f_apply = 1;
	}

	nvram_safe_get_r("iot_filename", buf, sizeof(buf));
	if (nv_strcmp(cfg->iot_filename, buf)) {
		nvram_set("iot_filename", cfg->iot_filename);
		f_apply = 1;
	}

	return f_apply;
}

static int apply_polling_parameter(dn_conf_t *cfg, struct cwmp_userdata *ud)
{
	char buf[32];		// TOBEAPPLIED
	char *oldValue;		// TOBEAPPLIED
	char key[32];
	int f_apply = 0;
	char t[512];
	char t2[512];
	int i;
	int val = 0;

	struct in_addr ip_addr = {0, };
	char *slash_ptr = NULL;
	int nm_cidr;

// periodic inform
	nvram_safe_get_r("dv_acs_polling_time", t, sizeof(t));
	snprintf(buf, sizeof(buf), "%02d:%02d", cfg->polling_time / 3600, (cfg->polling_time % 3600) / 60);
	if (nv_strcmp(t, buf)) {
		syslog(LOG_WARNING, "Polling time is updated.");
		nvram_set("dv_acs_polling_time", buf);
		f_apply = 1;
	}
	nvram_safe_get_r("dv_acs_polling_range", t, sizeof(t));
	if (cfg->polling_range != atoi(t) * 60) {
		syslog(LOG_WARNING, "Polling range is updated.");
		snprintf(buf, sizeof(buf), "%d", cfg->polling_range / 60);
		nvram_set("dv_acs_polling_range", buf);
		f_apply = 1;
	}
	nvram_safe_get_r("dv_acs_polling_period", t, sizeof(t));
	if (STRLEN(cfg->polling_period) != 0 && STRNCASECMP(t, cfg->polling_period)) {
		syslog(LOG_WARNING, "Polling period is updated.");
		nvram_set("dv_acs_polling_period", cfg->polling_period);
		f_apply = 1;
	}
	nvram_safe_get_r("dv_acs_polling_days", t, sizeof(t));
	if (cfg->polling_days != -99 && cfg->polling_days != atoi(t)) {
		syslog(LOG_WARNING, "Polling days is updated.");
		snprintf(buf, sizeof(buf), "%d", cfg->polling_days);
		nvram_set("dv_acs_polling_days", buf);
		f_apply = 1;
	}
	if (f_apply) {
		//APACRTL-428
		syslog(LOG_INFO, DVLOG_MARK_ADMIN H_UP_POLLING_RANGE);
		unlink(POLLTIME_FILE_NAME);
		ud->InformIntervalCnt = 0;
	}

	for (i = 0; i < MAX_FWNO_CNT; i++) {
		memset(buf, 0, sizeof(buf));
		snprintf(key, sizeof(key), "dv_forced_upgrade%d", i + 1);
		oldValue = nvram_safe_get_r(key, buf, sizeof(buf));
		if (cfg->forcedUpgrade[i] > 0 && cfg->forcedUpgrade[i] != atoi(oldValue)) {
			snprintf(buf, sizeof(buf), "%d", cfg->forcedUpgrade[i]);
			nvram_set(key, buf);
			f_apply = 1;
		} else {
			if (STRLEN(buf) > 0 && cfg->forcedUpgrade[i] == 0) {
				nvram_unset(key);
				f_apply = 1;
			}
		}
	}

// control traffic
	oldValue = nvram_safe_get_r("dv_acs_control_traffic", t, sizeof(t));
	if (cfg->control_traffic != 0 && (cfg->control_traffic != atoi(t))) {
		snprintf(buf, sizeof(buf), "%u", cfg->control_traffic);
		nvram_set("dv_acs_control_traffic", buf);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("atc_num", t, sizeof(t));
	if (cfg->atc_num != atoi(oldValue)) {
		snprintf(t, sizeof(t), "%d", cfg->atc_num);
		nvram_set("atc_num", t);
		f_apply = 1;
	}

	for (i = 0; i < 16; i++) {
		snprintf(key, sizeof(key), "atc_addr%d", i + 1);
		oldValue = nvram_safe_get_r(key, t, sizeof(t));
		if (STRLEN(cfg->atc_addr[i]) > 0 && nv_strcmp(oldValue, cfg->atc_addr[i])) {
			nvram_set(key, cfg->atc_addr[i]);
			f_apply = 1;
		} else if (STRLEN(cfg->atc_addr[i]) == 0 && *oldValue) {
			nvram_unset(key);
			f_apply = 1;
		}
	}

	oldValue = nvram_safe_get_r("twamp_enable", t, sizeof(t));
	if (cfg->twamp_enable != atoi(oldValue)) {
		snprintf(t, sizeof(t), "%d", cfg->twamp_enable);
		nvram_set("twamp_enable", t);
		f_apply = 1;
	}
	
	val = 0;
	memset(t2, 0, sizeof(t2));
	for (i = 0; i < MAX_TWAMP_LIST_CNT; i++) {
		if ((STRLEN((cfg->twamp_tbl[i]).ip) < 1) || (!cfg->twamp_tbl[i].port))
			continue;

		slash_ptr = strrchr((cfg->twamp_tbl[i]).ip, '/');
		if (slash_ptr)
			*slash_ptr = '\0';

		if (!inet_aton((cfg->twamp_tbl[i]).ip, &ip_addr))
			continue;

		if (slash_ptr) {
			*slash_ptr = '/';
			nm_cidr = atoi(slash_ptr + 1);
			if (nm_cidr < 0 || nm_cidr > 32)
				continue;
		}

		if (cfg->twamp_tbl[i].port < 0 || cfg->twamp_tbl[i].port > 65535)
			continue;

		val += snprintf(&t2[val], sizeof(t2) - val, "%s|%d,", (cfg->twamp_tbl[i]).ip, cfg->twamp_tbl[i].port);
	}

	if (val > 0) {
		t2[val - 1] = '\0';
		oldValue = nvram_safe_get_r("twamp_sender", t, sizeof(t));
		if (STRNCMP(oldValue, t2)) {
			nvram_set("twamp_sender", t2);
			f_apply = 1;
		}
	}

	if (!cfg->twamp_enable) {
		yexecl(NULL, "killall twamp-reflector");
		hchk_pchk("twamp-reflector", "del");
		yexecl(NULL, "iptables -t nat -F PRE_TWAMP");
		yexecl(NULL, "iptables -F TWAMP_ACL");
	} else {
		yexecl(NULL, "TWAMP-RST");
	}

	unlink("/tmp/.atc_addr.back");	//APACRTL-602 : PTV동작 조건 추가

	return f_apply;
}

static int apply_port_forward(dn_conf_t *cfg)
{
	_forward_tbl_t *tbl = &cfg->fwdtbl;
	int i;
	int no, type;
	char key[32], val[128];
	char *ptr, t[128];
	int f_apply = 0;

	snprintf(val, sizeof(val), "%d", tbl->use);
	if (!nvram_match("acs_forward_port_use", val)) {
		nvram_set("acs_forward_port_use", val);
		f_apply = 1;
	}

	for (i = 0; i < 32; i++) {
		no = tbl->portfwd[i].dev_no - 1;

		if (!STRNCASECMP(tbl->portfwd[i].dev_type, "phone") || !STRNCASECMP(tbl->portfwd[i].dev_type, "1"))
			type = 1;
		else if (!STRNCASECMP(tbl->portfwd[i].dev_type, "pc") || !STRNCASECMP(tbl->portfwd[i].dev_type, "2"))
			type = 2;
		else if (!STRNCASECMP(tbl->portfwd[i].dev_type, "stb") || !STRNCASECMP(tbl->portfwd[i].dev_type, "3"))
			type = 3;
		else if (!STRNCASECMP(tbl->portfwd[i].dev_type, "ap") || !STRNCASECMP(tbl->portfwd[i].dev_type, "4"))
			type = 4;
		else 
			type = 5;

		snprintf(key, sizeof(key), "acs_forward_port%d", i);
		if (i < tbl->tbl_count)
			snprintf(val, sizeof(val), "%s:%d,%s,%d,%d,%d", tbl->portfwd[i].name, tbl->portfwd[i].wport,
				tbl->portfwd[i].protocol, tbl->portfwd[i].lport, type, tbl->portfwd[i].dev_no);
		else
			val[0] = 0;
		ptr = nvram_safe_get_r(key, t, sizeof(t));
		if (*ptr && i >= tbl->tbl_count) {
			nvram_unset(key);
			f_apply = 1;
		} else if (nv_strcmp(ptr, val)) {
			nvram_set(key, val);
			f_apply = 1;
		}
	}

	return f_apply;
}

/*-------------------------------------------------------------------------*/
unsigned int apply_config_parameter(int *val_apply)
{
	char *oldValue;		// TOBEAPPLIED
	char key[32] = "", buf[32] = "";
	char t[512] = "", t2[512] = "";
	char zero[32];
	int i = 0, f_apply = 0;
	dn_conf_t *cfg = &dn_conf;
	unsigned int config_changed = 0;
	struct in_addr lan_gw, cfg_gw;
	unsigned int old_end_addr = 0, new_end_addr = 0;

	memset(zero, 0, sizeof(zero));
	if (!memcmp(cfg, zero, sizeof(zero)))
		parse_download_config_file(cfg);

// update pvs_config_ver
	oldValue = nvram_safe_get_r("pvs_conf_ver", t, sizeof(t));
	if (STRLEN(cfg->conf_ver) > 0) {
		if (nv_strcmp(cfg->conf_ver, oldValue)) {
			nvram_set("pvs_conf_ver", cfg->conf_ver);
			f_apply = 1;
		} else {
			syslog(LOG_INFO, DVLOG_MARK_ADMIN "Config file version same");
		}
	}

	for (i = 0; i < MAX_TELNET_ACCESS; i++) {
		snprintf(key, sizeof(key), "acs_telnet_access_block%d", i);
		memset(t, 0, sizeof(t));
		oldValue = nvram_get_r(key, t, sizeof(t));
		if (STRLEN(cfg->telnet_access[i]) > 0 && (oldValue == NULL || nv_strcmp(cfg->telnet_access[i], oldValue))) {
			nvram_set(key, cfg->telnet_access[i]);
			config_changed |= CONF_CHG(CONF_SSH);
			f_apply = 1;
		} else if (STRLEN(cfg->telnet_access[i]) == 0 && oldValue != NULL) {
			nvram_unset(key);
			config_changed |= CONF_CHG(CONF_SSH);
			f_apply = 1;
		}
	}

	if (IS_BRIDGE_MODE)
		config_changed &= ~CONF_CHG(CONF_SSH);

// dscp value setting
	memset(t, 0, sizeof(t));
	oldValue = nvram_safe_get_r("dacom_qos_voip_dscp", t, sizeof(t));
	if (cfg->voip_dscp != 0 && cfg->voip_dscp != strtoul(t, NULL, 16)) {
		snprintf(t, sizeof(t), "0x%x", cfg->voip_dscp);
		nvram_set("dacom_qos_voip_dscp", t);
		config_changed |= CONF_CHG(CONF_DSCP);
		f_apply = 1;
	}
	memset(t, 0, sizeof(t));
	oldValue = nvram_safe_get_r("dacom_qos_iptv_dscp", t, sizeof(t));
	if (cfg->iptv_dscp != 0 && cfg->iptv_dscp != strtoul(t, NULL, 16)) {
		snprintf(t, sizeof(t), "0x%x", cfg->iptv_dscp);
		nvram_set("dacom_qos_iptv_dscp", t);
		config_changed |= CONF_CHG(CONF_DSCP);
		f_apply = 1;
	}

// ntp settings..
	memset(t, 0, sizeof(t));
	oldValue = nvram_safe_get_r("ntp_timeout", t, sizeof(t));
	if (cfg->ntp_timeout > 0 && cfg->ntp_timeout != atoi(oldValue)) {
		snprintf(t, sizeof(t), "%d", cfg->ntp_timeout);
		nvram_set("ntp_timeout", t);
		config_changed |= CONF_CHG(CONF_NTP);
		f_apply = 1;
	}
	memset(t, 0, sizeof(t));
	oldValue = nvram_safe_get_r("ntp_retry", t, sizeof(t));
	if (cfg->ntp_retry > 0 && cfg->ntp_retry != atoi(oldValue)) {
		snprintf(t, sizeof(t), "%d", cfg->ntp_retry);
		nvram_set("ntp_retry", t);
		config_changed |= CONF_CHG(CONF_NTP);
		f_apply = 1;
	}
	
	//ntp_server_address
	for (i = 0; i < MAX_NTP; i++) {
		snprintf(key, sizeof(key), "NTP_SERVER_IP%d", i + 1);
		memset(t, 0, sizeof(t));
		oldValue = nvram_safe_get_r(key, t, sizeof(t));
		if (STRLEN(cfg->ntp_server[i]) > 0 && nv_strcmp(oldValue, cfg->ntp_server[i])) {
			nvram_set(key, cfg->ntp_server[i]);
			config_changed |= CONF_CHG(CONF_NTP);
			f_apply = 1;
		} else if (STRLEN(cfg->ntp_server[i]) == 0 && *oldValue != 0) {
			nvram_unset(key);
			config_changed |= CONF_CHG(CONF_NTP);
			f_apply = 1;
		}
	}
	
	//ntp_protocol
	for (i = 0; i < MAX_NTP; i++) {
		snprintf(key, sizeof(key), "ntp_server_protocol%d", i + 1);
		memset(t, 0, sizeof(t));
		oldValue = nvram_safe_get_r(key, t, sizeof(t));
		if (STRLEN(cfg->ntp_proto[i]) > 0 && nv_strcmp(oldValue, cfg->ntp_proto[i])) {
			nvram_set(key, cfg->ntp_proto[i]);
			config_changed |= CONF_CHG(CONF_NTP);
			f_apply = 1;
		} else if (STRLEN(cfg->ntp_proto[i]) == 0 && *oldValue != 0) {
			nvram_unset(key);
			config_changed |= CONF_CHG(CONF_NTP);
			f_apply = 1;
		}
	}
	
	//port
	for (i = 0; i < MAX_NTP; i++) {
		snprintf(key, sizeof(key), "ntp_server_port%d", i + 1);
		memset(t, 0, sizeof(t));
		oldValue = nvram_safe_get_r(key, t, sizeof(t));
		if (STRLEN(cfg->ntp_port[i]) > 0 && nv_strcmp(oldValue, cfg->ntp_port[i])) {
			nvram_set(key, cfg->ntp_port[i]);
			config_changed |= CONF_CHG(CONF_NTP);
			f_apply = 1;
		} else if (STRLEN(cfg->ntp_port[i]) == 0 && *oldValue != 0) {
			nvram_unset(key);
			config_changed |= CONF_CHG(CONF_NTP);
			f_apply = 1;
		}
	}

	// port forward
	if (apply_port_forward(cfg)) {
		f_apply = 1;
		if (!IS_BRIDGE_MODE)
			config_changed |= CONF_CHG(CONF_PORT_FORWARD);
	}

// firewall
	for (i = 0; i < 8; i++) {
		snprintf(key, sizeof(key), "acs_fwin%d", i);
		memset(t, 0, sizeof(t));
		oldValue = nvram_safe_get_r(key, t, sizeof(t));
		if (STRLEN(cfg->firewall_in[i]) > 0 && nv_strcmp(oldValue, cfg->firewall_in[i])) {
			nvram_set(key, cfg->firewall_in[i]);
			config_changed |= CONF_CHG(CONF_FIREWALL);
			f_apply = 1;
		} else if (STRLEN(cfg->firewall_in[i]) == 0 && *oldValue) {
			nvram_unset(key);
			config_changed |= CONF_CHG(CONF_FIREWALL);
			f_apply = 1;
		}

	}
	for (i = 0; i < 8; i++) {
		snprintf(key, sizeof(key), "acs_fwout%d", i);
		memset(t, 0, sizeof(t));
		oldValue = nvram_safe_get_r(key, t, sizeof(t));
		if (STRLEN(cfg->firewall_out[i]) > 0 && nv_strcmp(oldValue, cfg->firewall_out[i])) {
			nvram_set(key, cfg->firewall_out[i]);
			config_changed |= CONF_CHG(CONF_FIREWALL);
			f_apply = 1;
		} else if (STRLEN(cfg->firewall_out[i]) == 0 && *oldValue) {
			nvram_unset(key);
			config_changed |= CONF_CHG(CONF_FIREWALL);
			f_apply = 1;
		}
	}

	// mtu, dhcp_lease, connection
	memset(t, 0, sizeof(t));
	oldValue = nvram_safe_get_r("DHCP_MTU_SIZE", t, sizeof(t));
	if (cfg->mtu != 0 && cfg->mtu != atoi(oldValue)) {
		snprintf(t, sizeof(t), "%d", cfg->mtu);
		nvram_set("DHCP_MTU_SIZE", t);
		if (!IS_BRIDGE_MODE)
			config_changed |= CONF_CHG(CONF_MTU);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("FIXED_MTU_SIZE", t, sizeof(t));
	if (cfg->mtu != 0 && cfg->mtu != atoi(oldValue)) {
		snprintf(t, sizeof(t), "%d", cfg->mtu);
		nvram_set("FIXED_MTU_SIZE", t);
		if (!IS_BRIDGE_MODE)
			config_changed |= CONF_CHG(CONF_MTU);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("DHCP_LEASE_TIME", t, sizeof(t));
	if (cfg->dhcp_lease > 0 && cfg->dhcp_lease != atoi(oldValue)) {
		snprintf(t, sizeof(t), "%d", cfg->dhcp_lease);
		nvram_set("DHCP_LEASE_TIME", t);
		config_changed |= CONF_CHG(CONF_DHCP);
		f_apply = 1;
	}

// ip pool
/* TODO: 상위AP와 IP충돌이 일어나는 상황에서 config의 lanblock이 192.168.219.0이면
   어떻게 해야하는가? */
	oldValue = nvram_safe_get_r("lan_block", t, sizeof(t));
	if (nvram_invmatch_r("lan_ip_changed", "1")
	    || (!nv_strcmp(cfg->lan_block, "192.168.219.0") && nv_strcmp(oldValue, "192.168.219.0"))) {
	    //|| (!nv_strcmp(cfg->lan_block, "192.168.123.0") && nv_strcmp(oldValue, "192.168.123.0"))) {

		if (STRLEN(cfg->lan_block) > 0 && nv_strcmp(oldValue, cfg->lan_block)) {
			nvram_set("lan_block", cfg->lan_block);
			config_changed |= CONF_CHG(CONF_DHCP);
			f_apply = 1;
		}

		oldValue = nvram_safe_get_r("IP_ADDR", t, sizeof(t));
		if (!(IS_BRIDGE_MODE) && STRLEN(cfg->lan_gateway) > 0 && nv_strcmp(oldValue, cfg->lan_gateway)) {
			nvram_set("IP_ADDR", cfg->lan_gateway);
			config_changed |= CONF_CHG(CONF_DHCP);
			f_apply = 1;
		}

		memset(t, 0, sizeof(t));
		oldValue = nvram_safe_get_r("stb_ip_start", t, sizeof(t));
		if (STRLEN(cfg->iptv_start) > 0 && nv_strcmp(oldValue, cfg->iptv_start)) {
			nvram_set("stb_ip_start", cfg->iptv_start);
			config_changed |= CONF_CHG(CONF_DHCP);
			f_apply = 1;
		}

		memset(t, 0, sizeof(t));
		oldValue = nvram_safe_get_r("stb_ip_end", t, sizeof(t));
		if (STRLEN(cfg->iptv_end) > 0 && nv_strcmp(oldValue, cfg->iptv_end)) {
			nvram_set("stb_ip_end", cfg->iptv_end);
			config_changed |= CONF_CHG(CONF_DHCP);
			f_apply = 1;
		}

		memset(t, 0, sizeof(t));
		oldValue = nvram_safe_get_r("voip_ip_start", t, sizeof(t));
		if (STRLEN(cfg->voip_start) > 0 && nv_strcmp(oldValue, cfg->voip_start)) {
			nvram_set("voip_ip_start", cfg->voip_start);
			config_changed |= CONF_CHG(CONF_DHCP);
			f_apply = 1;
		}

		memset(t, 0, sizeof(t));
		oldValue = nvram_safe_get_r("voip_ip_end", t, sizeof(t));
		if (STRLEN(cfg->voip_end) > 0 && nv_strcmp(oldValue, cfg->voip_end)) {
			nvram_set("voip_ip_end", cfg->voip_end);
			config_changed |= 1;
			f_apply = 1;
		}

		memset(t, 0, sizeof(t));
		oldValue = nvram_safe_get_r("DHCP_CLIENT_START", t, sizeof(t));
		if (STRLEN(cfg->pcpool_start) > 0 && nv_strcmp(oldValue, cfg->pcpool_start)) {
			nvram_set("DHCP_CLIENT_START", cfg->pcpool_start);
			config_changed |= CONF_CHG(CONF_DHCP);
			f_apply = 1;
		}
	
		//APACQCA-243
		memset(t, 0, sizeof(t));
		oldValue = nvram_safe_get_r("DHCP_CLIENT_END", t, sizeof(t));
		if (STRLEN(cfg->pcpool_end) > 0 && nv_strcmp(oldValue, cfg->pcpool_end)) {
			nvram_set("DHCP_CLIENT_END", cfg->pcpool_end);
			config_changed |= CONF_CHG(CONF_DHCP);
			f_apply = 1;
		}

		nvram_unset("lan_ip_changed");
	}

	if (!IS_BRIDGE_MODE) {
		nvram_safe_get_r("IP_ADDR", t, sizeof(t));
		if (inet_aton(t, &lan_gw) && inet_aton(cfg->lan_gateway, &cfg_gw)) {
			old_end_addr = ntohl(lan_gw.s_addr) & 0x000000ff;
			new_end_addr = ntohl(cfg_gw.s_addr) & 0x000000ff;
			if (new_end_addr != old_end_addr) {
				lan_gw.s_addr &= htonl(0xffffff00);
				lan_gw.s_addr |= htonl(new_end_addr);
				snprintf(t2, sizeof(t2), "%s", inet_ntoa(lan_gw));
				nvram_set("IP_ADDR", t2);
				memset(t2, 0, sizeof(t2));
				config_changed |= CONF_CHG(CONF_DHCP);
			}
		}
	}

// timeout and retry
	oldValue = nvram_safe_get_r("dv_pvs_retry", t, sizeof(t));
	if (cfg->pvs_retry != 0 && (cfg->pvs_retry != atoi(oldValue))) {
		snprintf(t, sizeof(t), "%d", cfg->pvs_retry);
		nvram_set("dv_pvs_retry", t);
		f_apply = 1;
	}
	oldValue = nvram_safe_get_r("dv_pvs_timeout", t, sizeof(t));
	if (cfg->pvs_timeout != 0 && (cfg->pvs_timeout != atoi(oldValue))) {
		snprintf(t, sizeof(t), "%d", cfg->pvs_timeout);
		nvram_set("dv_pvs_timeout", t);
		f_apply = 1;
	}
	oldValue = nvram_safe_get_r("dv_acs_retry", t, sizeof(t));
	if (cfg->acs_retry >= 0 && cfg->acs_retry != atoi(oldValue)) {
		snprintf(t, sizeof(t), "%d", cfg->acs_retry);
		nvram_set("dv_acs_retry", t);
		f_apply = 1;
	}
	oldValue = nvram_safe_get_r("dv_acs_timeout", t, sizeof(t));
	if (cfg->acs_timeout > 0 && (cfg->acs_timeout != atoi(oldValue))) {
		snprintf(t, sizeof(t), "%d", cfg->acs_timeout);
		nvram_set("dv_acs_timeout", t);
		f_apply = 1;
	}
	oldValue = nvram_safe_get_r("dv_ids_retry", t, sizeof(t));
	if (cfg->ids_retry >= 0 && cfg->ids_retry != atoi(oldValue)) {
		snprintf(t, sizeof(t), "%d", cfg->ids_retry);
		nvram_set("dv_ids_retry", t);
		f_apply = 1;
	}
	oldValue = nvram_safe_get_r("dv_ids_timeout", t, sizeof(t));
	if (cfg->ids_timeout > 0 && (cfg->ids_timeout != atoi(oldValue))) {
		snprintf(t, sizeof(t), "%d", cfg->ids_timeout);
		nvram_set("dv_ids_timeout", t);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("acs_mbr_RS_DOMAIN", t, sizeof(t));
	if (STRLEN(cfg->rs_auth_server[0]) > 0 && nv_strcmp(oldValue, cfg->rs_auth_server[0])) {
		nvram_set("acs_mbr_RS_DOMAIN", cfg->rs_auth_server[0]);
		config_changed |= CONF_CHG(CONF_RADIUS);
		f_apply = 1;
	}
	oldValue = nvram_safe_get_r("acs_mbr_RS2_DOMAIN", t, sizeof(t));
	if (STRLEN(cfg->rs_auth_server[1]) > 0 && nv_strcmp(oldValue, cfg->rs_auth_server[1])) {
		nvram_set("acs_mbr_RS2_DOMAIN", cfg->rs_auth_server[1]);
		config_changed |= CONF_CHG(CONF_RADIUS);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("acs_mbr_RS_IP", t, sizeof(t));
	if (STRLEN(cfg->rs_auth_ip[0]) > 0 && nv_strcmp(oldValue, cfg->rs_auth_ip[0])) {
		nvram_set("acs_mbr_RS_IP", cfg->rs_auth_ip[0]);
		config_changed |= CONF_CHG(CONF_RADIUS);
		f_apply = 1;
	}
	oldValue = nvram_safe_get_r("acs_mbr_RS2_IP", t, sizeof(t));
	if (STRLEN(cfg->rs_auth_ip[1]) > 0 && nv_strcmp(oldValue, cfg->rs_auth_ip[1])) {
		nvram_set("acs_mbr_RS2_IP", cfg->rs_auth_ip[1]);
		config_changed |= CONF_CHG(CONF_RADIUS);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("acs_mbr_RS_PORT", t, sizeof(t));
	if (cfg->rs_auth_port[0] != 0 && atoi(oldValue) != cfg->rs_auth_port[0]) {
		snprintf(buf, sizeof(buf), "%d", cfg->rs_auth_port[0]);
		nvram_set("acs_mbr_RS_PORT", buf);
		config_changed |= CONF_CHG(CONF_RADIUS);
		f_apply = 1;
	}
	oldValue = nvram_safe_get_r("acs_mbr_RS2_PORT", t, sizeof(t));
	if (cfg->rs_auth_port[1] != 0 && atoi(oldValue) != cfg->rs_auth_port[0]) {
		snprintf(buf, sizeof(buf), "%d", cfg->rs_auth_port[1]);
		nvram_set("acs_mbr_RS2_PORT", buf);
		config_changed |= CONF_CHG(CONF_RADIUS);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("acs_mbr_ACCOUNT_RS_DOMAIN", t, sizeof(t));
	if (STRLEN(cfg->rs_account_server[0]) > 0 && nv_strcmp(cfg->rs_account_server[0], oldValue)) {
		nvram_set("acs_mbr_ACCOUNT_RS_DOMAIN", cfg->rs_account_server[0]);
		config_changed |= CONF_CHG(CONF_RADIUS);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("acs_mbr_ACCOUNT_RS2_DOMAIN", t, sizeof(t));
	if (STRLEN(cfg->rs_account_server[1]) > 0 && nv_strcmp(cfg->rs_account_server[1], oldValue)) {
		nvram_set("acs_mbr_ACCOUNT_RS2_DOMAIN", cfg->rs_account_server[1]);
		config_changed |= CONF_CHG(CONF_RADIUS);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("acs_mbr_ACCOUNT_RS_IP", t, sizeof(t));
	if (STRLEN(cfg->rs_account_ip[0]) > 0 && nv_strcmp(cfg->rs_account_ip[0], oldValue)) {
		nvram_set("acs_mbr_ACCOUNT_RS_IP", cfg->rs_account_ip[0]);
		config_changed |= CONF_CHG(CONF_RADIUS);
		f_apply = 1;
	}
	
	oldValue = nvram_safe_get_r("acs_mbr_ACCOUNT_RS2_IP", t, sizeof(t));
	if (STRLEN(cfg->rs_account_ip[1]) > 0 && nv_strcmp(cfg->rs_account_ip[1], oldValue)) {
		nvram_set("acs_mbr_ACCOUNT_RS2_IP", cfg->rs_account_ip[1]);
		config_changed |= CONF_CHG(CONF_RADIUS);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("acs_mbr_ACCOUNT_RS_PORT", t, sizeof(t));
	if (cfg->rs_account_port[0] != 0 && cfg->rs_account_port[0] != atoi(oldValue)) {
		snprintf(buf, sizeof(buf), "%d", cfg->rs_account_port[0]);
		nvram_set("acs_mbr_ACCOUNT_RS_PORT", buf);
		config_changed |= CONF_CHG(CONF_RADIUS);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("acs_mbr_ACCOUNT_RS2_PORT", t, sizeof(t));
	if (cfg->rs_account_port[1] != 0 && cfg->rs_account_port[1] != atoi(oldValue)) {
		snprintf(buf, sizeof(buf), "%d", cfg->rs_account_port[1]);
		nvram_set("acs_mbr_ACCOUNT_RS2_PORT", buf);
		config_changed |= CONF_CHG(CONF_RADIUS);
		f_apply = 1;
	}

// QoS management server configuration
	oldValue = nvram_safe_get_r("dv_qms_server", t, sizeof(t));
	if (STRLEN(cfg->qms_server) > 0 && nv_strcmp(cfg->qms_server, oldValue)) {
		nvram_set("dv_qms_server", cfg->qms_server);
		f_apply = 1;
	}
	oldValue = nvram_safe_get_r("dv_qms_ip", t, sizeof(t));
	if (STRLEN(cfg->qms_ip) > 0 && nv_strcmp(cfg->qms_ip, oldValue)) {
		nvram_set("dv_qms_ip", cfg->qms_ip);
		f_apply = 1;
	}
	oldValue = nvram_safe_get_r("dv_qms_port1", t, sizeof(t));
	if (cfg->qms_port[0] != 0 && cfg->qms_port[0] != atoi(oldValue)) {
		snprintf(buf, sizeof(buf), "%d", cfg->qms_port[0]);
		nvram_set("dv_qms_port1", buf);
		f_apply = 1;
	}
	oldValue = nvram_safe_get_r("dv_qms_port2", t, sizeof(t));
	if (cfg->qms_port[1] != 0 && cfg->qms_port[1] != atoi(oldValue)) {
		snprintf(buf, sizeof(buf), "%d", cfg->qms_port[1]);
		nvram_set("dv_qms_port2", buf);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("acs_dv_fwindow_url", t, sizeof(t));
	if (STRLEN(cfg->first_window_url) > 0 && nv_strcmp(cfg->first_window_url, oldValue)) {
		nvram_set("acs_dv_fwindow_url", cfg->first_window_url);
		config_changed |= CONF_CHG(CONF_RADIUS);
		f_apply = 1;
	}

	if (IS_BRIDGE_MODE) 
		config_changed &= ~CONF_CHG(CONF_RADIUS);

	//Config for LG CNS security module
	oldValue = nvram_safe_get_r("secd_server_en", t, sizeof(t));
	if (cfg->cnssec_enable != atoi(oldValue)) {
		snprintf(t, sizeof(t), "%d", cfg->cnssec_enable);
		nvram_set("secd_server_en", t);
		config_changed |= CONF_CHG(CONF_SECD);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("secd_update_intv", t, sizeof(t));
	if ((cfg->cnssec_polling_day * 86400) != atoi(oldValue)) {
		snprintf(t, sizeof(t), "%d", (cfg->cnssec_polling_day * 86400));
		nvram_set("secd_update_intv", t);
		config_changed |= CONF_CHG(CONF_SECD);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("secd_server_name", t, sizeof(t));
	if (STRLEN(cfg->cnssec_server) > 0 && nv_strcmp(cfg->cnssec_server, oldValue)) {
		nvram_set("secd_server_name", cfg->cnssec_server);
		config_changed |= CONF_CHG(CONF_SECD);

		f_apply = 1;
	}

	//diaglog
	oldValue = nvram_safe_get_r("send_diaglog_enable", t, sizeof(t));
	if (cfg->qlc_diaglog_enable != atoi(oldValue)) {
		snprintf(t, sizeof(t), "%d", cfg->qlc_diaglog_enable);
		nvram_set("send_diaglog_enable", t);
		config_changed |= CONF_CHG(CONF_DIAGLOG);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("send_diaglog_period", t, sizeof(t));
	if (cfg->qlc_diaglog_period != atoi(oldValue)) {
		snprintf(t, sizeof(t), "%d", cfg->qlc_diaglog_period);
		nvram_set("send_diaglog_period", t);
		config_changed |= CONF_CHG(CONF_DIAGLOG);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("send_hgw_server", t, sizeof(t));
	if (STRLEN(cfg->qlc_diaglog_url) > 0 && STRNCMP(cfg->qlc_diaglog_url, oldValue)) {
		nvram_set("send_hgw_server", cfg->qlc_diaglog_url);
		config_changed |= CONF_CHG(CONF_DIAGLOG);
		f_apply = 1;
	}

	//statlog
	if (cfg->qlc_statlog_setflag) {	//APACRTL-622
		oldValue = nvram_get_r("qlc_statlog_enable", t, sizeof(t));
		if (!oldValue || (cfg->qlc_statlog_enable != atoi(oldValue))) {
			snprintf(t, sizeof(t), "%d", cfg->qlc_statlog_enable);
			nvram_set("qlc_statlog_enable", t);
			config_changed |= CONF_CHG(CONF_STATLOG);
			f_apply = 1;
		}

		oldValue = nvram_safe_get_r("qlc_statlog_url", t, sizeof(t));
		if (STRLEN(cfg->qlc_statlog_url) > 0 && STRNCMP(cfg->qlc_statlog_url, oldValue)) {
			nvram_set("qlc_statlog_url", cfg->qlc_statlog_url);
			config_changed |= CONF_CHG(CONF_STATLOG);
			f_apply = 1;
		}

		oldValue = nvram_get_r("qlc_statlog_period", t, sizeof(t));
		if (!oldValue || (cfg->qlc_statlog_period != atoi(oldValue))) {
			snprintf(t, sizeof(t), "%d", cfg->qlc_statlog_period);
			nvram_set("qlc_statlog_period", t);
			config_changed |= CONF_CHG(CONF_STATLOG);
			f_apply = 1;
		}

		oldValue = nvram_get_r("qlc_statlog_size", t, sizeof(t));
		if (!oldValue || (cfg->qlc_statlog_size != atoi(oldValue))) {
			snprintf(t, sizeof(t), "%d", cfg->qlc_statlog_size);
			nvram_set("qlc_statlog_size", t);
			config_changed |= CONF_CHG(CONF_STATLOG);
			f_apply = 1;
		}

		oldValue = nvram_get_r("qlc_statlog_interval", t, sizeof(t));
		if (!oldValue || (cfg->qlc_statlog_interval != atoi(oldValue))) {
			snprintf(t, sizeof(t), "%d", cfg->qlc_statlog_interval);
			nvram_set("qlc_statlog_interval", t);
			config_changed |= CONF_CHG(CONF_STATLOG);
			f_apply = 1;
		}

		oldValue = nvram_get_r("qlc_statlog_station", t, sizeof(t));
		if (!oldValue || (cfg->qlc_statlog_station != atoi(oldValue))) {
			snprintf(t, sizeof(t), "%d", cfg->qlc_statlog_station);
			nvram_set("qlc_statlog_station", t);
			config_changed |= CONF_CHG(CONF_STATLOG);
			f_apply = 1;
		}
	} else {
		oldValue = nvram_get_r("qlc_statlog_enable", t, sizeof(t));
		if (oldValue && atoi(oldValue)) {
			nvram_set("qlc_statlog_enable", "0");
			config_changed |= CONF_CHG(CONF_STATLOG);
			f_apply = 1;
		}
	}

	if (config_changed & (CONF_CHG(CONF_DIAGLOG) | CONF_CHG(CONF_STATLOG))) {
		if (config_changed & CONF_CHG(CONF_STATLOG))
			yexecl(NULL, "portmon cfg_update");

		yexecl(NULL, "killall -SIGUSR2 periodic_behavior");
		config_changed &= ~(CONF_CHG(CONF_DIAGLOG) | CONF_CHG(CONF_STATLOG));
		f_apply = 1;
	}

	//APACRTL-505
	oldValue = nvram_safe_get_r("cwmp_trcs_url", t, sizeof(t));
	if (STRLEN(cfg->rcs_domain) > 0) {
		if (STRLEN(oldValue) > 0 && strstr(oldValue, "https://"))
			snprintf(t2, sizeof(t2), "https://%s/cwmp_d", cfg->rcs_domain);
		else if (STRLEN(oldValue) > 0 && strstr(oldValue, "http://"))
			snprintf(t2, sizeof(t2), "http://%s/cwmp_d", cfg->rcs_domain);

		if (nv_strcmp(t2, oldValue)) {
			nvram_set("cwmp_trcs_url", t2);
			config_changed |= CONF_CHG(CONF_TR069);
			f_apply = 1;
		}
	}

	//APACRTL-505
	oldValue = nvram_safe_get_r("cwmp_acs_url", t, sizeof(t));
	if (STRLEN(cfg->pvs_server) > 0) {
		if (STRLEN(oldValue) > 0 && strstr(oldValue, "https://"))
			snprintf(t2, sizeof(t2), "https://%s/cwmp_d", cfg->pvs_server);
		else if (STRLEN(oldValue) > 0 && strstr(oldValue, "http://"))
			snprintf(t2, sizeof(t2), "http://%s/cwmp_d", cfg->pvs_server);

		if (nv_strcmp(t2, oldValue)) {
			nvram_set("cwmp_acs_url", t2);
			config_changed |= CONF_CHG(CONF_TR069);
			f_apply = 1;
		}
	}

	//APACRTL-505
	oldValue = nvram_safe_get_r("cwmp_hpms_server", t, sizeof(t));
	if (STRLEN(cfg->stun_domain) > 0 && nv_strcmp(oldValue, cfg->stun_domain)) {
		nvram_set("cwmp_hpms_server", cfg->stun_domain);
		config_changed |= CONF_CHG(CONF_TR069);
		f_apply = 1;
	}

	//APACRTL-505
	oldValue = nvram_safe_get_r("cwmp_stun_min_period", t, sizeof(t));
	if (cfg->stun_min_period != 0 && cfg->stun_min_period != atoi(oldValue)) {
		snprintf(buf, sizeof(buf), "%d", cfg->stun_min_period);
		nvram_set("cwmp_stun_min_period", buf);
		config_changed |= CONF_CHG(CONF_TR069);
		f_apply = 1;
	}

	//APACRTL-505
	oldValue = nvram_safe_get_r("cwmp_stun_max_period", t, sizeof(t));
	if (cfg->stun_max_period != 0 && cfg->stun_max_period != atoi(oldValue)) {
		snprintf(buf, sizeof(buf), "%d", cfg->stun_max_period);
		nvram_set("cwmp_stun_max_period", buf);
		config_changed |= CONF_CHG(CONF_TR069);
		f_apply = 1;
	}

	//APACRTL-505
	oldValue = nvram_safe_get_r("ipdm_hp_period", t, sizeof(t));
	if (cfg->hp_period != 0 && cfg->hp_period != atoi(oldValue)) {
		snprintf(buf, sizeof(buf), "%d", cfg->hp_period);
		nvram_set("ipdm_hp_period", buf);
		config_changed |= CONF_CHG(CONF_TR069);
		f_apply = 1;
	}

	//APACRTL-505
	oldValue = nvram_safe_get_r("ipdm_hp_ttl", t, sizeof(t));
	if (cfg->hp_ttl != 0 && cfg->hp_ttl != atoi(oldValue)) {
		snprintf(buf, sizeof(buf), "%d", cfg->hp_ttl);
		nvram_set("ipdm_hp_ttl", buf);
		config_changed |= CONF_CHG(CONF_TR069);
		f_apply = 1;
	}

	for (i = 0; i < MAX_CR_ADDR; i++) {
		snprintf(key, sizeof(key), "cr_address%d", i + 1);
		memset(t, 0, sizeof(t));
		oldValue = nvram_get_r(key, t, sizeof(t));
		if (STRLEN(cfg->cr_addr[i]) > 0 && (oldValue == NULL || (oldValue && STRNCMP(cfg->cr_addr[i], oldValue)))) {	//APACRTL-558
			nvram_set(key, cfg->cr_addr[i]);
			config_changed |= CONF_CHG(CONF_CR);
			f_apply = 1;
		} else if (STRLEN(cfg->cr_addr[i]) == 0 && 
				(oldValue && (STRLEN(oldValue) > 0))) {	//APACRTL-558
			nvram_set(key, "");
			config_changed |= CONF_CHG(CONF_CR);
			f_apply = 1;
		}
	}

	//Begin APACQCA-59
	oldValue = nvram_safe_get_r("self_reboot_enable", t, sizeof(t));
	if (cfg->periodic_reset_enable != atoi(oldValue)) {
		snprintf(buf, sizeof(buf), "%d", cfg->periodic_reset_enable);
		nvram_set("self_reboot_enable", buf);
		config_changed |= CONF_CHG(CONF_SELF_REBOOT);
		f_apply = 1;
	}
	
	oldValue = nvram_safe_get_r("self_day_period", t, sizeof(t));
	if (cfg->periodic_reset_interval_days != atoi(oldValue)) {
		snprintf(buf, sizeof(buf), "%d", cfg->periodic_reset_interval_days);
		nvram_set("self_day_period", buf);
		config_changed |= CONF_CHG(CONF_SELF_REBOOT);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("self_start_reboot_time", t, sizeof(t));
	if (STRLEN(cfg->periodic_reset_time) > 0 && STRNCMP(oldValue, cfg->periodic_reset_time)) {
		nvram_set("self_start_reboot_time", cfg->periodic_reset_time);
		config_changed |= CONF_CHG(CONF_SELF_REBOOT);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("self_reset_range", t, sizeof(t));
	if (cfg->periodic_reset_range != atoi(oldValue)) {
		snprintf(buf, sizeof(buf), "%d", cfg->periodic_reset_range);
		nvram_set("self_reset_range", buf);
		config_changed |= CONF_CHG(CONF_SELF_REBOOT);
		f_apply = 1;
	}

	oldValue = nvram_safe_get_r("self_iot_enable", t, sizeof(t));
	if (cfg->iot_service_use != atoi(oldValue)) {
		snprintf(buf, sizeof(buf), "%d", cfg->iot_service_use);
		nvram_set("self_iot_enable", buf);
		config_changed |= CONF_CHG(CONF_SELF_REBOOT);
		f_apply = 1;
	}

	if (config_changed & CONF_CHG(CONF_SELF_REBOOT)) {
		yexecl(NULL, "killall -SIGUSR1 periodic_behavior");
		config_changed &= ~CONF_CHG(CONF_SELF_REBOOT);
	}
	//End APACQCA-59

	{
		char tmp_mac[32] = "";	//APACRTL-599
		char stbmac[256], voipmac[256];	//APACRTL-599
		int cnt1 = 0, cnt2 = 0, len1 = 0, len2 = 0;
		char *ptr, *sav;
		char *tok_ptr = NULL;

		memset(stbmac, 0, sizeof(stbmac));
		memset(voipmac, 0, sizeof(voipmac));

		for (i = 0; i < MAX_MACBIND; i++) {
			memset(tmp_mac, 0, sizeof(tmp_mac));
			snprintf(key, sizeof(key), "cwmp_devList%d", i);
			memset(buf, 0, sizeof(buf));
			oldValue = nvram_safe_get_r(key, buf, sizeof(buf));
			if (STRLEN(cfg->devMac[i]) > 0 && STRNCASECMP(cfg->devMac[i], oldValue))
				nvram_set(key, cfg->devMac[i]);
			else if (STRLEN(cfg->devMac[i]) == 0) {
				if (*oldValue)
					nvram_unset(key);
				continue;
			}
			
			sav = cfg->devMac[i];
			ptr = STRTOK_R(sav, ",", &tok_ptr);
			if (ptr && !STRNCASECMP(ptr, "stb") && cnt1 < MAX_STB_CNT) {
				ptr = STRTOK_R(NULL, ",", &tok_ptr);
				if (ptr) {
					snprintf(tmp_mac, sizeof(tmp_mac), "%s", ptr);
					str_lower(tmp_mac);

					//APACRTL-599
					if (check_dotted_mac(tmp_mac)) {	//stb,9893.cc2f.6d4a,000852
						//Do nothing
					} else if (check_colon_mac(tmp_mac)) {	//stb,98:93:cc:2f:6d:4a,000852
						conv_mac_format_to_4(tmp_mac);
					} else {
						continue;
					}

					if (len1 > 0)
						len1 += snprintf(stbmac + len1, sizeof(stbmac) - len1, ";%s", tmp_mac);
					else
						len1 += snprintf(stbmac + len1, sizeof(stbmac) - len1, "%s", tmp_mac);
					cnt1++;
				}
			} else
				if (ptr && (!STRNCASECMP(ptr, "phone") || !STRNCASECMP(ptr, "cpg") || !STRNCASECMP(ptr, "ap"))
						&& cnt2 < MAX_VOIP_CNT) {
					ptr = STRTOK_R(NULL, ",", &tok_ptr);
					if (ptr) {
						snprintf(tmp_mac, sizeof(tmp_mac), "%s", ptr);
						str_lower(tmp_mac);

						//APACRTL-599
						if (check_dotted_mac(tmp_mac)) {	//stb,9893.cc2f.6d4a,000852
							//Do nothing
						} else if (check_colon_mac(tmp_mac)) {	//stb,98:93:cc:2f:6d:4a,000852
							conv_mac_format_to_4(tmp_mac);
						} else {
							continue;
						}

						if (len2 > 0)
							len2 += snprintf(voipmac + len2, sizeof(voipmac) - len2, ";%s", tmp_mac);
						else
							len2 += snprintf(voipmac + len2, sizeof(voipmac) - len2, "%s", tmp_mac);
						cnt2++;
					}
				}
		}

		memset(t, 0, sizeof(t));
		oldValue = nvram_safe_get_r("pvs_stb_mac", t, sizeof(t));
		if (STRNCASECMP(oldValue, stbmac)) {
			nvram_set("pvs_stb_mac", stbmac);
			config_changed |= CONF_CHG(CONF_DHCP);
			f_apply = 1;
		}

		memset(t, 0, sizeof(t));
		oldValue = nvram_safe_get_r("pvs_voip_mac", t, sizeof(t));
		if (STRNCASECMP(oldValue, voipmac)) {
			nvram_set("pvs_voip_mac", voipmac);
			config_changed |= CONF_CHG(CONF_DHCP);
			f_apply = 1;
		}
	}

	if (f_apply) {
		*val_apply += 1; //APACRTL-483
		//nvram_commit();
	}

	CWMPDBG(0, (stderr, "Config Changed --> 0x%08x\n", config_changed));
	TLOG_PRINT("Config Changed --> 0x%08x\n", config_changed);
	return config_changed;
}

static int build_report_config_info(DownloadInfo_T *dlInfo, const char *data)
{
	FILE *fp = NULL;
	char buf[500];
	char tmp[128], *ptr1, *ptr2;
	char model[16] = "";

	get_model(model, 16, LOWER);

	if ((fp = fopen(UPLOAD_INFO_FILE_NAME, "w")) == NULL)
		goto ERROR;

	soap_decode_key(buf, sizeof(buf), data);
	if (STRLEN(buf) > 0 && (ptr1 = strstr(buf, "conffile="))) {
		if ((ptr2 = strchr(ptr1, '&')))
			*ptr2 = 0;
		fprintf(fp, "%s\n", ptr1);
		if (ptr2)
			ptr1 = ptr2 + 1;
	} else
		fprintf(fp, "conffile=%s\n", dlInfo->Download.TargetFileName);
	get_wan_macaddr(tmp, sizeof(tmp), LOWER);
	fprintf(fp, "mac=%s\n", conv_mac_format_to_4(tmp));

	fprintf(fp, "vendor=%s\n", "davolink");
	fprintf(fp, "model=%s\n",  model);

// added for tr-069 cds
	if (ptr1)
		strncpy(tmp, ptr1, sizeof(tmp));
	else
		strncpy(tmp, buf, sizeof(tmp));

	ptr1 = strstr(tmp, "cpeId=");
	if (ptr1 && STRLEN(ptr1) > STRLEN("cpeId=")) {
		ptr1 += STRLEN("cpeId=");
		ptr2 = strchr(ptr1, '&');
		if (ptr2)
			*ptr2 = 0;
		fprintf(fp, "cpeId=%s\n", ptr1);
	} else {
		cwmp_cfg_get(CWMP_CONREQ_PASSWORD, tmp, 128);
		fprintf(fp, "cpeId=%s\n", tmp);
	}
	get_version(buf, 80, 0, 0);
	fprintf(fp, "version=%s\n", buf);

	fprintf(fp, "ip=%s\n", get_wanip(buf, 20));
	fprintf(fp, "ip_type=%s\n", get_wan_proto(buf, 20, 0, 0));

	get_dns(buf, 20, 0, 0);
	get_dns(&buf[20], 20, 1, 0);
	get_dns(&buf[40], 20, 2, 0);
	fprintf(fp, "dns1=%s\n", buf);
	fprintf(fp, "dns2=%s\n", &buf[20]);
	fprintf(fp, "dns3=%s\n", &buf[40]);

	fprintf(fp, "gateway=%s\n", get_gateway(buf, 20));
	fprintf(fp, "update=%s\n", nvram_safe_get_r("dv_acs_update_way", buf, sizeof(buf)));
	fprintf(fp, "update_time=%s\n", nvram_safe_get_r("dv_acs_update_time", buf, sizeof(buf)));
	if (pollInfo.fPeriodic)
		fprintf(fp, "request=%s\n", "auto");
	else
		fprintf(fp, "request=%s\n", "power");
	fprintf(fp, "stat_code=%s\n", "110000");

 ERROR:
	if (fp)
		fclose(fp);
	return (0);
}

static int build_report_software_info(DownloadInfo_T *dlInfo, const char *data)
{
	FILE *fp;
	char buf[80];
	char model[16] = "";

	get_model(model, 16, LOWER);

	if ((fp = fopen(UPLOAD_INFO_FILE_NAME, "w")) == NULL)
		goto ERROR;

	if (data && STRLEN(data) > 0 && strstr(data, "image="))
		fprintf(fp, "%s\n", data);
	else
		fprintf(fp, "image=%s\n", dlInfo->Download.TargetFileName);
	get_wan_macaddr(buf, sizeof(buf), LOWER);
	fprintf(fp, "mac=%s\n", conv_mac_format_to_4(buf));
	fprintf(fp, "vendor=%s\n", "davolink");
	fprintf(fp, "model=%s\n",  model);
	get_version(buf, 80, 0, 0);
	fprintf(fp, "version=%s\n", buf);
	fprintf(fp, "retry=%d\n", atoi(nvram_safe_get_r("dv_ids_retry", buf, sizeof(buf))));

 ERROR:
	if (fp)
		fclose(fp);
	return (0);
}

static int check_status_file(char *line, int line_size)
{
	FILE *fp;
	//char line[120];
	int ret = -1;

	if (line == NULL)
		return (ret);

	if ((fp = fopen(DOWNLOAD_HTTP_RESP_FILE_NAME, "r")) != NULL) {
		if (fgets(line, line_size, fp) > 0) {
			ret = strtoul(line, NULL, 10);
		}
		fclose(fp);
	} 

	CWMPDBG(0, (stderr, "Check Status file:%s return=%d\n", DOWNLOAD_HTTP_RESP_FILE_NAME, ret));
	return (ret);
}

int download_config(DownloadInfo_T *dlinfo)
{
	char cds_port[8] = "";
	char cds_url[128] = "";
	char hostname[256] = "";
	char *argv[] = { "provision", "conf", cds_url, hostname, cds_port, "0", NULL };
	char *ptr = NULL;
	char addParam[2048] = "";
	struct in_addr dns_rslt;
	struct url_info urlinfo;

	memset(&urlinfo, 0, sizeof(struct url_info));
	dns_rslt.s_addr = 0;

	ptr = strstr(dlinfo->Download.URL, "?");
	if (ptr != NULL && STRLEN(ptr) > 1) {
		*ptr = 0;
		snprintf(addParam, sizeof(addParam), "%s", ptr + 1);
	}
	CWMPDBG(0, (stderr, "<%s:%d>Start download Config!\n", __FUNCTION__, __LINE__));
	build_report_config_info(dlinfo, addParam);

#ifdef __DV_PROVISION_TEST__
	if (nvram_match_r("test_prov_cfg", "1")) {	//For test
		char cfg_ip[32] = "";
		char cfg_file[32] = "";

		nvram_safe_get_r("test_prov_cfg_ip", cfg_ip, sizeof(cfg_ip));
		nvram_safe_get_r("test_prov_cfg_port", cds_port, sizeof(cds_port));
		nvram_safe_get_r("test_prov_cfg_file", cfg_file, sizeof(cfg_file));
		if (STRLEN(cfg_file) == 0)
			snprintf(cfg_file, sizeof(cfg_file), "%s", "config.xml");

		snprintf(cds_url, sizeof(cds_url), "http://%s/%s", cfg_ip, cfg_file);
	} else {
#endif
		//APACRTL-564
		if (extract_info_from_url(dlinfo->Download.URL, &urlinfo, 443) == 0) {
			TLOG_PRINT("CDS DNS resolving is failed.\n");
			return ERR_9801;
		}

		if (dnsQuery(urlinfo.domain, &(dns_rslt.s_addr))) {
			char t[32] = "";
			
			nvram_safe_get_r("cwmp_cds_ipaddr", t, sizeof(t));
			if (t[0] == 0)
				snprintf(t, sizeof(t), "180.225.0.15");

			if (inet_aton(t, &dns_rslt) == 0) {
				TLOG_PRINT("CDS DNS resolving is failed.\n");
				return ERR_9801;
			}

			//APACRTL-564
			snprintf(hostname, sizeof(hostname), "tcds.lgqps.com");

		} else {
			//APACRTL-564
			snprintf(hostname, sizeof(hostname), "%s", urlinfo.domain);
		}

		if (STRLEN(urlinfo.suburl) > 0)
			snprintf(cds_url, sizeof(cds_url), "https://%s/%s", inet_ntoa(dns_rslt), urlinfo.suburl);
		else
			snprintf(cds_url, sizeof(cds_url), "https://%s/chgw_configure", inet_ntoa(dns_rslt));

		snprintf(cds_port, sizeof(cds_port), "%s", urlinfo.port);
#ifdef __DV_PROVISION_TEST__
	}
#endif

	TLOG_PRINT("Start downloading config.(URL : %s)\n", cds_url);
	TLOG_PRINT("Hostname(Config) : %s\n", hostname);	//APACRTL-564
	
	yexecv_safe(argv, NULL, 20, NULL);

	return 0;
}

int download_image(DownloadInfo_T *dlinfo)
{
	char port[8] = "", url[128] = "";
	char fileSize[16] = "", newVer[16] = "";
	char hostname[256] = "";
	char *argv[] = { "provision", "sw", url, hostname, port, fileSize, newVer, NULL };
	char *ptr = NULL; 
	char method[8] = "";
	char addParam[128] = "";
	struct in_addr dns_rslt;
	struct url_info urlinfo;

	memset(&urlinfo, 0, sizeof(struct url_info));
	dns_rslt.s_addr = 0;

	CWMPDBG(0, (stderr, "<%s:%d>Start download Image\n", __FUNCTION__, __LINE__));
	control_led_to_upgrade(UPGRADING_PHASE3);

	ptr = strstr(dlinfo->Download.URL, "?");
	if (ptr != NULL && STRLEN(ptr) > 1) {
		*ptr = 0;
		snprintf(addParam, sizeof(addParam), "%s", ptr + 1);
	}

	build_report_software_info(dlinfo, addParam);

	nvram_safe_get_r("acs_sw_size", fileSize, sizeof(fileSize));
	nvram_safe_get_r("acs_sw_next_ver", newVer, sizeof(newVer));

#ifdef __DV_PROVISION_TEST__
	if (nvram_match_r("test_prov_dwld", "1")) {	//For test
		nvram_safe_get_r("test_prov_dwld_port", port, sizeof(port));
		if (strstr(dlinfo->Download.URL, "https://"))
			snprintf(method, sizeof(method), "https");
		else
			snprintf(method, sizeof(method), "http");
	} else
		snprintf(method, sizeof(method), "https");
#else
	snprintf(method, sizeof(method), "https");
#endif
	
	if (extract_info_from_url(dlinfo->Download.URL, &urlinfo, 40443) == 0) {
		TLOG_PRINT("IDS DNS resolving is failed.\n");
		return ERR_9811;
	}
	
	if (dnsQuery(urlinfo.domain, &(dns_rslt.s_addr))) {
		TLOG_PRINT("IDS DNS resolving is failed.\n");
		return ERR_9811;
	} else {
		//APACRTL-564
		snprintf(hostname, sizeof(hostname), "%s", urlinfo.domain);
		snprintf(port, sizeof(port), "%s", urlinfo.port);
		if (STRLEN(urlinfo.suburl) > 0)
			snprintf(url, sizeof(url), "%s://%s/%s", method, inet_ntoa(dns_rslt), urlinfo.suburl);
		else
			snprintf(url, sizeof(url), "%s://%s/chgw_software", method, inet_ntoa(dns_rslt));
	}

	TLOG_PRINT("Start downloading firmware.(URL : %s)\n", url);
	TLOG_PRINT("Hostname(Image) : %s\n", hostname);

	yexecv_safe(argv, NULL, 20, NULL);

	return 0;
}

static void start_lan_reset(void)
{
	int i;
	char buf[64], config[50];

	for(i = 0; i < 4; i++) {
		snprintf(buf, sizeof(buf), "x_port_%d_config", i);
		nvram_get_r_def(buf, config, sizeof(config), "up_auto_-rxpause_txpause");
		port_reset(i, config);
	}

	return;
}

static int after_download(int file_type, char *target, struct cwmp_userdata *ud)
{
	int ret = 0;
	unsigned int change = 0;
	char line[128];
	int line_size = sizeof(line);

	memset(line, 0, line_size);

	switch (file_type) {
	case DLTYPE_IMAGE:
		//update firmware
		ret = check_status_file(line, line_size);
		
		if (ret != PROV_DOWNLOAD_OK) {
			TLOG_PRINT("Downloading Result(AP F/W) : %s", line);
			ud->prov_stat = FW_DOWN_FAIL;
		}

		if (ret == PROV_DOWNLOAD_OK) {
			TLOG_PRINT("Firmware download is OK.\n");
			ud->prov_stat = FW_DOWN_SUCCESS;
		} else if (ret == PROV_TIMEOUT || ret == PROV_SOCK_ERROR) {
			syslog(LOG_INFO, DVLOG_MARK_ADMIN "Firmware download is timeout.");
			return ERR_9812;
		} else if (ret == PROV_IMAGE_ERROR || ret == PROV_IMAGE_SZ_ERROR) {
			syslog(LOG_INFO, DVLOG_MARK_ADMIN "Downloaded firmware is invalid.");
			return ERR_9814;
		} else {
			syslog(LOG_INFO, DVLOG_MARK_ADMIN "Firmware download error");
			return ERR_9813;
		}

		break;
	case DLTYPE_CONFIG:
		{
			ret = check_status_file(line, line_size);
			
			if (ret != 0)
				TLOG_PRINT("Downloading Result(Config) : %s", line);

			if (ret == PROV_DOWNLOAD_OK) {
				TLOG_PRINT("Downloading Config is OK.\n");
				syslog(LOG_INFO, DVLOG_MARK_ADMIN "Config file is downloaded successfully");
				if (parse_download_config_file(&dn_conf)) {
					int f_apply = 0;
					f_apply = apply_img_parameter(&dn_conf);
					if (apply_polling_parameter(&dn_conf, ud)) {
						f_apply += 1;
						check_need_update_polltime(1); //APACRTL-543
					} else {
						check_need_update_polltime(0); //APACRTL-543
					}
					f_apply += apply_iot_parameter(&dn_conf);
					
					if (pollInfo.fPeriodic == 0)
						change = apply_config_parameter(&f_apply);	//APACRTL-483

					if (f_apply)
						nvram_commit();
					
					if (change & 1)
						start_lan_reset();

					ud->config_changed = change ? 1 : 0;
					return 0;
				} else
					return ERR_9804;	//Parsing error
			} else if (ret == PROV_TIMEOUT) {
				syslog(LOG_INFO, DVLOG_MARK_ADMIN "Config file download is timeout");
				return ERR_9802;
			} else if (ret == PROV_CONFIG_ERROR) {
				syslog(LOG_INFO, DVLOG_MARK_ADMIN "Config file MISMATCH error");
				parse_download_config_file(&dn_conf);

				//APACRTL-483 : when only need to apply, exec nvram_commit().
				if (apply_img_parameter(&dn_conf) == 1)
					nvram_commit();

				return ERR_9804;
			} else {
				syslog(LOG_INFO, DVLOG_MARK_ADMIN "Config file download error");
				return ERR_9803;
			}
		}
		break;
	}
	return 0;
}

int before_download(void)
{
	fprintf(stderr, "[%s():%d] TODO\n", __FUNCTION__, __LINE__);

	return 0;
}

void *cwmp_http_process(void *data)
{
	struct soap *soap = data;
	struct cwmp_userdata *ud = NULL;
	DownloadInfo_T *dlinfo = NULL;
	struct timeval to;
	char target[256] = "";
	int ret = 0;
	int file_type = DLTYPE_NONE;

	CWMPDBG(0, (stderr, "<%s:%d>cwmp_http_process starts!\n", __FUNCTION__, __LINE__));
	if (soap && soap->user) {
		unsigned int delay = 0;
		time_t st_time;
		ud = soap->user;
		dlinfo = &ud->DownloadInfo;

		//reset
		ud->DownloadState = DOWNLD_START;
		ud->DLStartTime = 0;
		ud->DLCompleteTime = 0;
		ud->DLFaultCode = 0;
		ud->config_changed = 0;
		st_time = time(NULL);

		//check if the delayseconds was set. If yes, wait....
		switch (ud->DownloadWay) {
			case DLWAY_DOWN:
				delay = dlinfo->Download.DelaySeconds;
				break;
			case DLWAY_UP:
				delay = dlinfo->Upload.DelaySeconds;
				break;
		}

		if (delay) {
			to.tv_sec = delay;
			to.tv_usec = 0;
			CWMPDBG(1,
				(stderr, "<%s:%d>sleep %d seconds(time=%d)\n", __FUNCTION__, __LINE__, delay, (int)time(NULL)));
			select(0, NULL, NULL, NULL, &to);
			CWMPDBG(2,
				(stderr, "<%s:%d>after sleep %d seconds(time=%d)\n", __FUNCTION__, __LINE__, delay,
				 (int)time(NULL)));
		}

		//get the file
		cwmpdl_getfilename(ud->DownloadWay, dlinfo, target, sizeof(target), &file_type);
		
		switch (ud->DownloadWay) {
			case DLWAY_DOWN:
				if (file_type == DLTYPE_CONFIG) {
					ud->prov_stat = CFG_DOWN_START;
					ret = download_config(dlinfo);
				} else {
					ret = download_image(dlinfo);
					if (ret != 0) {
						ud->prov_stat = FW_DOWN_FAIL;
					}
				}
				break;
			case DLWAY_UP:
				break;
		}

		if (ret == 0) {
			switch (ud->DownloadWay) {
				case DLWAY_DOWN:
					ret = after_download(file_type, target, ud);
					break;
				case DLWAY_UP:
					//nothing to do
					break;
			}

			ud->DLStartTime = st_time;
			ud->DLCompleteTime = time(NULL);
			ud->DLFaultCode = -ret;
		} else if (ret == -1) {
			switch (ud->DownloadWay) {
				case DLWAY_DOWN:
					ud->DLFaultCode = 9010;
					break;
				case DLWAY_UP:
					ud->DLFaultCode = 9011;
					break;
			}
		} else 
			ud->DLFaultCode = -ret;

		//save status and reboot
		if (ud->DLFaultCode)    //download error 
			ud->DownloadState = DOWNLD_ERROR;
		else
			ud->DownloadState = DOWNLD_FINISH;
		
		switch (ud->DownloadWay) {
			case DLWAY_DOWN:
				if (dlinfo->Download.CommandKey)
					ud->DLCommandKey = strdup(dlinfo->Download.CommandKey);
				else
					ud->DLCommandKey = NULL;

				//cwmp_reset_DownloadInfo( &ud->DownloadInfo, ud->DownloadWay );
				ud->DownloadWay = DLWAY_NONE;

				/*
				if (file_type == DLTYPE_IMAGE) {
					cwmpSendEvent( EC_TRANSFER);
					cwmp_SaveReboot( ud, 1 );//this will reboot the system.hence, don't need to call cwmpSetCpeHold(0);
				}
				*/
				cwmpSetCpeHold(0);
				break;
			case DLWAY_UP:
				if (dlinfo->Upload.CommandKey)
					ud->DLCommandKey = strdup(dlinfo->Upload.CommandKey);
				else
					ud->DLCommandKey = NULL;

				cwmp_reset_DownloadInfo(&ud->DownloadInfo, ud->DownloadWay);
				ud->DownloadWay = DLWAY_NONE;
				upgradeFirmware("");
				save_update_way();
				cwmpSendEvent(EC_AUTOTRANSFER | EC_M_UPLOAD);	//APACRTL-433
				cwmp_SaveReboot(ud, 0, 1);
				cwmpSetCpeHold(0);
				break;
		}
	}

	CWMPDBG(0, (stderr, "<%s:%d>cwmp_http_process is end!\n", __FUNCTION__, __LINE__));

	return NULL;
}

void cwmpStartDownload(struct soap *soap)
{
	if(soap==NULL) {
		cwmpSetCpeHold(0);//continue the cpe finite-state machine
		return;
	}

	cwmp_http_process((void *)soap);
	return ;
}
