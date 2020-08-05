#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <syslog.h>
#include <openssl/des.h>
#include <sys/syscall.h>
#include <dvflag.h>
#include <bcmnvram.h>
#include <libytool.h>
#include <furl.h>
#include "tms_client.h"
#include "tms_misc.h"
#include "tms_client_private.h"
#include <openssl/sha.h>

#define URL_REQ_VER             "F1.0"
#define URL_REQ_DOWNTYPE        "1" /* 0: plane text 1: encryptext */
#define URL_REQ_MODEL_DEFAULT   "DVW-2700"
#define URL_REQ_VENDOR_DEFAULT  "Davolink"

#define PROV_IP_DEFAULT         "180.182.38.50"
#define PROV_PORT_DEFAULT       "8080"

#define CFGAC_DEFAULT           "0"
#define CFVER_DEFAULT           ""
#define FWAC_DEFAULT            "0"
#define FWVER_DEFAULT           ""

#define PROV_INTERVAL_DEFAULT   1
#define PROV_STIME_DEFAULT      "01:00:00"
#define PROV_ETIME_DEFAULT      "06:00:00"
#define RETRY_COUNT_DEFAULT     3
#define RETYR_INTERVAL_DEFAULT  "1,10,60"

static int g_invalid_webconf;
extern int commit;

#define STR_TO_INT(x) ((x[0] == 'y'||x[0] == 'Y'||x[0] == 'e'||x[0] == 'E'||x[0] == 'o'||x[0] == 'O')?"1": "0")
#define TOGGLE_TO_INT(x) ((x[0]=='1'||x[0] == 'y'||x[0] == 'Y'||x[0] == 'e'||x[0] == 'E'||x[0] == 'o'||x[0] == 'O')?"0": "1")

static char *cfg_reparsing_data(char *cfgver, char *buf);
static unsigned monotonic_ms(void);
static int apply_sys_cfg(variable *v, char *name, char *value, int group_idx, int cfg_type);
static int set_time_range(int *target, const char *value);
static int set_retry_interval(int *pdata, char *value);

static int get_time_range(int *target, const char *value)
{
	int a[4];

	if (sscanf(value, "%d:%d-%d:%d", &a[0], &a[1], &a[2], &a[3]) == 4 &&
		a[0]>=0 && a[0]<=23 &&
		a[1]>=0 && a[1]<=59 &&
		a[2]>=0 && a[2]<=23 &&
		a[3]>=0 && a[3]<=59) {
	   target[0] = a[0];
	   target[1] = a[1];
	   target[2] = a[2];
	   target[3] = a[3];
	   return (0);
	}
	return (-1);
}

void initenv(struct tms_t *p)
{
	char tmp[40];

	//initialize variable
	memset(&p->apms.macaddr[0], 0, sizeof(p->apms.macaddr));
	memset(&p->apms.config_url, 0, sizeof(p->apms.config_url));
	memset(&p->apms.firmware_url, 0, sizeof(p->apms.firmware_url));
	///////////////////////////////////////////////////////////////
	memset(p, 0, sizeof(struct tms_t));
	snprintf(p->url_req.ver, sizeof(p->url_req.ver), "%s", URL_REQ_VER);
	nvram_get_r("HW_NIC1_ADDR", p->url_req.mac, sizeof(p->url_req.mac));

	nvram_get_r_def("url_req_downtype", tmp, sizeof(tmp), URL_REQ_DOWNTYPE);
	p->url_req.downtype = strtoul(tmp, NULL, 10);

	nvram_get_r_def("cfgac", p->cfgac, sizeof(p->cfgac), CFGAC_DEFAULT);
	nvram_get_r_def("fwac", p->fwac, sizeof(p->fwac), FWAC_DEFAULT);

	nvram_get_r_def("config_ver", p->cfver, sizeof(p->cfver), CFVER_DEFAULT);
	nvram_get_r_def("firmware_ver", p->fwver, sizeof(p->fwver), FWVER_DEFAULT);

	snprintf(p->url_req.model, sizeof(p->url_req.model), "%s", URL_REQ_MODEL_DEFAULT);
	snprintf(p->url_req.vendor, sizeof(p->url_req.vendor), "%s", URL_REQ_VENDOR_DEFAULT);

	nvram_get_r_def("cferr", tmp, sizeof(tmp), "0");
	p->cferr = strtoul(tmp, NULL, 10);
	nvram_get_r_def("fwerr", tmp, sizeof(tmp), "0");
	p->fwerr = strtoul(tmp, NULL, 10);

	nvram_get_r_def("prov_ip", (char *)p->apms.prov_ip, sizeof(p->apms.prov_ip), PROV_IP_DEFAULT);

	nvram_get_r_def("prov_port", tmp, sizeof(tmp), PROV_PORT_DEFAULT);
	p->apms.prov_port = strtoul(tmp, NULL, 10);

	p->apms.prov_interval = safe_atoi(nvram_get("prov_interval"), PROV_INTERVAL_DEFAULT);

	nvram_get_r_def("prov_stime", tmp, sizeof(tmp), PROV_STIME_DEFAULT);
	set_time_range(&p->apms.prov_stime[0], tmp);

	nvram_get_r_def("prov_etime", tmp, sizeof(tmp), PROV_ETIME_DEFAULT);
	set_time_range(&p->apms.prov_etime[0], tmp);

	p->apms.retry_count = safe_atoi(nvram_get("retry_count"), RETRY_COUNT_DEFAULT);

	nvram_get_r_def("retry_interval", tmp, sizeof(tmp), RETYR_INTERVAL_DEFAULT);
	set_retry_interval(&p->apms.retry_interval[0], tmp);

	nvram_get_r_def("wan_bw_kb", tmp, sizeof(tmp), "40");           /* default: change 10kbyte -> 40kbyte */
	p->chk.wan_bw_kb = strtoul(tmp, NULL, 10);

	nvram_get_r_def("dv_autoup_reboot_time", tmp, sizeof(tmp), "03:00-05:00");
	get_time_range(p->chk.reboot_time, tmp);

	nvram_get_r_def("dv_autoup_reboot_retry", tmp, sizeof(tmp), "1");    /* change default: 3 -> 1 time */
	p->chk.reboot_retry = atoi(tmp);

	nvram_get_r_def("dv_autoup_reboot_bw", tmp, sizeof(tmp), "40000");   /* default: 40kbps */
	p->chk.reboot_bw = atoi(tmp);

	nvram_get_r_def("dv_autoup_down_retry_delay", tmp, sizeof(tmp), "60");   /* default: 60 minute */
	p->chk.down_retry_delay = atoi(tmp);

	nvram_get_r_def("dv_autoup_reboot_check_svc", tmp, sizeof(tmp), "60");   /* default: 10 minute  -> default: 60 minute */
	p->chk.reboot_check_svc = atoi(tmp);

	/* reset to preconfig */
	if (nvram_get("tmp_cfgac") || nvram_get("tmp_fwac") || nvram_get("tmp_config_ver")) {
		nvram_unset("tmp_cfgac");
		nvram_unset("tmp_fwac");
		nvram_unset("tmp_config_ver");
		commit++;
	}
}

void dump_fwinfo(char *where, struct tms_t *p)
{
	int i;
	char tmp[24], cfver[40], fwver[40];

	fwver[0] = 0;
	memset(cfver, 0, sizeof(cfver));
	get_sys_ver(tmp, sizeof(tmp));
	cfg_reparsing_data(p->cfver, cfver);
	sprintf(fwver, "Davolink_DVW-2700_%s", tmp);

	DEBUG("\n==== TMS fwinfo dump at \"%s\" ====\n", where);
	DEBUG("url_req.ver %s\n", p->url_req.ver);
	DEBUG("sys mac %s\n", p->url_req.mac);
	DEBUG("url_req.downtype %d\n", p->url_req.downtype);
	DEBUG("cfgac %s\n", p->cfgac);
	if (!strcmp(where, "init"))
		DEBUG("cfver %s\n", cfver);
	else
		DEBUG("cfver %s\n", p->cfver);
	DEBUG("fwac %s\n", p->fwac);
	if (!strcmp(where, "init"))
		DEBUG("fwver %s\n", fwver);
	else
		DEBUG("fwver %s\n", p->fwver);
	DEBUG("url_req.model %s\n", p->url_req.model);
	DEBUG("url_req.vendor %s\n", p->url_req.vendor);
	DEBUG("url_req.cferr %d\n", p->cferr);
	DEBUG("url_req.fwerr %d\n", p->fwerr);
	DEBUG("apms_ip %s\n", p->apms.apms_ip);
	DEBUG("apms_port %d\n", p->apms.apms_port);
	DEBUG("prov_ip %s\n", p->apms.prov_ip);
	DEBUG("prov_port %d\n", p->apms.prov_port);
	DEBUG("prov_interval %d\n", p->apms.prov_interval);
	DEBUG("prov_time(H:M:S): %02d:%02d:%02d ~ %02d:%02d:%02d\n",
			p->apms.prov_stime[0],p->apms.prov_stime[1],p->apms.prov_stime[2],
			p->apms.prov_etime[0],p->apms.prov_etime[1],p->apms.prov_etime[2]);
	DEBUG("retry_count %d\n", p->apms.retry_count);
	for (i=0; i<p->apms.retry_count; i++)
		DEBUG("retry_interval(%d) %d\n", i+1, p->apms.retry_interval[i]);

	DEBUG( "wan_bw_kb %d\n", p->chk.wan_bw_kb);
	DEBUG( "reboot_time(H:M) [%02d:%02d]-[%02d:%02d] \n",
			p->chk.reboot_time[0], p->chk.reboot_time[1],
			p->chk.reboot_time[2], p->chk.reboot_time[3]);
	DEBUG( "reboot_retry %d \n", p->chk.reboot_retry);
	DEBUG( "reboot_bw %d \n", p->chk.reboot_bw);
	DEBUG( "down_retry_delay %d\n", p->chk.down_retry_delay);
	DEBUG( "reboot_check_svc %d\n", p->chk.reboot_check_svc);
	DEBUG( "================================\n\n");
}

/*
Davolink_DVW-2300N_1.11.50CJ.bin
Davolink_DVW-2300N_v1CJ.cfg
*/
#define PS_URL "http://%s:%d/tms/servlet/getApProvInfo?"\
				"macAddr=%s&"\
				"downType=%d&"\
				"ver=%s&"\
				"cfgac=%s&"\
				"cfver=%s&"\
				"fwac=%s&"\
				"fwver=%s&"\
				"model=%s&"\
				"vendor=%s&"\
				"cferr=%d&"\
				"fwerr=%d"

void make_build_msg(struct tms_t *p)
{
	char serv_addr[20];
	char tmp[24], cfver[40], fwver[40];

	confirm_server_ip((char *)p->apms.prov_ip, serv_addr, sizeof(serv_addr));
	cfg_reparsing_data(p->cfver, cfver);
	get_sys_ver(tmp, sizeof(tmp));
	sprintf(fwver, "Davolink_DVW-2700_%s", tmp);

	snprintf(&p->apms_req_url[0], sizeof(p->apms_req_url), PS_URL,
			serv_addr, p->apms.prov_port, p->url_req.mac, p->url_req.downtype,
			p->url_req.ver, p->cfgac, cfver, p->fwac, fwver,
			p->url_req.model, p->url_req.vendor, p->cferr, p->fwerr);
}

//HH24:MM:SS
static int set_time_range(int *target, const char *value)
{
	int a[3];

	if (sscanf(value, "%d:%d:%d", &a[0], &a[1], &a[2]) == 3 &&
		a[0]>=0 && a[0]<=23 &&
		a[1]>=0 && a[1]<=59 &&
		a[2]>=0 && a[2]<=59) {
		target[0] = a[0];
		target[1] = a[1];
		target[2] = a[2];
		return (0);
	}
	return (-1);
}

/*---------------------------------------------------------------------------*/
static int set_retry_interval(int *pdata, char *value)
{
	char *sp, *p;
	int i = 0;
	char tmp[20];

	if (!pdata || !value)
		return -1;

	sprintf(tmp, "%s", value);
	while ((p = strtok_r((i==0)? tmp: NULL, " ,\r\n\t", &sp))) {
		if (i == MAX_INTERVAL_CNT)
			break;
		pdata[i] = strtoul(p, NULL,  10);
		i++;
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
void init_random_number(void)
{
	char tmp[16];
	unsigned char a[6] = {0,};
	time_t t;

	t = time(NULL);
	nvram_get_r("HW_NIC1_ADDR", tmp, sizeof(tmp));
	if (tmp[0]) {
		ether_toa(tmp, a);
		srand(t ^ ((a[3]<<16) + (a[4]<<8) + a[5]));
	}
}

int check_ntp_client(void)
{
	char tmp[4];

	nvram_get_r("NTP_ENABLED", tmp, sizeof(tmp));

	if (tmp[0] == '0') {
		nvram_set("NTP_ENABLED", "1");
		nvram_commit();
		yexecl(NULL, "reboot");
		return 0;
	}

	return check_dvflag(DF_NTPSYNC);
}

#define DEFAULT_TRAFFIC_BYTE    40960 //40kbyte
#define DEFAULT_CHECK_SEC		60

static unsigned long long get_Outbyte_counts(int port, int direction)
{
    FILE *fp;
    char *tmp, *value;
    char buffer[512];
    unsigned long long cnt = 0;
    int i, line = 0;

	if (direction == TMS_TX)
		line = port + 11;
	else if (direction == TMS_RX)
		line = port + 2;

    if ((fp = fopen("/proc/asicCounter","r")) != NULL) {
        i = 0;
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (i == line) {	// Transmit
                value = buffer;
                tmp = strsep(&value, ":");
                ydespaces(value);
                tmp = strsep(&value, " ");
                cnt = strtoull(tmp, NULL, 10);	//Transmit octets
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
            }
            i++;
        }
        fclose(fp);
    }

	return (cnt);
}

static int running_yourTraffic(struct tms_t *p)
{
	unsigned long long tx_prev_bytes = 0, tx_cur_bytes = 0, tx_diff = 0;
	unsigned long long rx_prev_bytes = 0, rx_cur_bytes = 0, rx_diff = 0;
	int condition;

	if ((condition = (p->chk.wan_bw_kb * 1024)) <= 0)
		condition = DEFAULT_TRAFFIC_BYTE;

	tx_prev_bytes = get_Outbyte_counts(0, TMS_TX); //WAN TX
	rx_prev_bytes = get_Outbyte_counts(0, TMS_RX); //WAN RX

	DEBUG("(running_yourTraffic) check traffic during 1 (min)\n");
	syslog(LOG_INFO, "[TMS] Check Rraffic During 1 (min)");
	my_sleep(DEFAULT_CHECK_SEC);

	tx_cur_bytes = get_Outbyte_counts(0, TMS_TX); //WAN TX
	rx_cur_bytes = get_Outbyte_counts(0, TMS_RX); //WAN RX

	tx_diff = (tx_cur_bytes - tx_prev_bytes)/DEFAULT_CHECK_SEC;
	rx_diff = (rx_cur_bytes - rx_prev_bytes)/DEFAULT_CHECK_SEC;

	syslog(LOG_INFO, "[TMS] Tx traffic %llu(byte) Rx traffic %llu(byte) sec condition %d(byte)", tx_diff, rx_diff, condition);
	DEBUG("[TMS] Tx traffic %llu(byte) Rx traffic %llu(byte) sec condition %d(byte)", tx_diff, rx_diff, condition);
	if (tx_diff > condition || rx_diff > condition)
		return 1;

	return 0;
}


int check_service_idle(struct tms_t *p)
{
	if (!running_yourTraffic(p)) {
		/* to reboot now */
		DEBUG("service is idle (no client)\n");
		return (1);
	}

	while (1) {
		syslog(LOG_INFO, "[TMS] Next Time Traffic Check Polling Rebooting Time 1Hour...");
		my_sleep((p->chk.reboot_check_svc * 60));
		if (!running_yourTraffic(p)) {
			/* to reboot now */
			DEBUG("service is idle (no client)\n");
			return (1);
		}
	}

	return 1;
}

static void set_fwerrcode(int errst)
{
	char tmp[4];
	int fwerror = 1;

	if (errst < 0)
		errst = -errst;
	switch (errst) {
		case ESIGN:
		case EIDENTITY:
		case ELENGTH:
		case ECKSUM:
		case EPARTIAL:
			syslog(LOG_INFO, "[TMS] invalid firmware");
			break;
		case EGETCONF:
		case EINVALCONF:
		case EGETFW:
			if (errst == EGETFW)
				fwerror = 2;
			break;
		case EINBURNING:
			fwerror = 4;
			syslog(LOG_INFO, "[TMS] failed: upgrade");
			break;
		default:
			break;
	}
	sprintf(tmp, "%d", fwerror);
	nvram_set("fwerr", tmp);
	commit++;
}

int tms_cfg_setvar(struct variable_s *v, char *name, char *value, int group_idx)
{
	char value_v[256];
	char *nv_val;
	char getval[8];

	if (!value || value[0] == 0)
		return -1;

	snprintf(value_v, sizeof(value_v), "%s", value);
	switch (v->flgs & TYPE_MASK) {
		case STRING_T:
			if (v->data != NULL && v->size > 0)
				snprintf(v->data, v->size, "%s", value_v);
			break;
		default:
			break;
	}
	/* save configuration to nvram */
	if (v->flgs & FLG_DVNV) {
		nv_val = nvram_get_r_def((char *)v->name, getval, sizeof(getval), "");
		ydespaces(nv_val);
		if (strcmp(nv_val, value_v)) {
			nvram_set("tmp_cfgac", value_v);
			commit++;
		}
	}
	return 0;
}

static char *trim(char *s)
{
	int len = strlen(s);
	/* trim trailing whitespace */
	while (len > 0 && isspace(s[len - 1]))
		s[--len] = '\0';
	/* trim trailing whitespace and double quotation */
	memmove(s, &s[strspn(s, " \n\r\t\v")], len);
	return s;
}

static int parse_line(char *line, char *argv[], int argvLen, const char *delim)
{
	char *q, *p = line;
	int i, argc = 0;

	while ((q = strsep(&p, delim))) {
		trim(q);
		if (*q && (argc < argvLen))
			argv[argc++] = q;
	}
	for (i = argc; i < argvLen; i++)
		argv[i] = NULL;
	return argc;
}

#define MAX_ARGV_CFG	10
//config_url=http://180.182.38.50:8080/config_ap/6256/Davolink_DVW-2300N_1.27.50CJ_CFG.txt
static char *cfg_reparsing_data(char *cfgver, char *buf)
{
	int i, argc;
	char *argv[MAX_ARGV_CFG];
	char *p, *k;
	char tmp[128];
	int found = 0;

	if (!buf)
		return NULL;

	if (!cfgver || !cfgver[0])
		return NULL;

	buf[0] = 0;
	argc = parse_line(cfgver, argv, MAX_ARGV_CFG, " \r\n\t/");
	for (i = 0; i < argc; i++) {
		if (!strncmp(argv[i], "Davolink", strlen("Davolink"))) {
			found = 1;
			break;
		}
	}

	if (found == 1 && argv[i] != NULL) {
		k = argv[i];
		if ((p = strstr(argv[i], "CFG"))) {
			snprintf(tmp, (p-k), "%s", k);
			sprintf(&buf[0], "%s_CFG", tmp);
		}
	}
	return ((buf[0])?buf: NULL);
}

int tms_setvar(struct variable_s *v, char *name, char *value, int group_idx)
{
	int *target_int32;
	char value_v[256];
	char *nv_val;
	char *snmp_ip;
	int unchanged = 1, port;
	char getval[256];

	if (!value || value[0] == 0)
		return -1;

	snmp_ip = nvram_get("apms_ip");
	port = safe_atoi(nvram_get("snmp_port"), 20161);

	snprintf(value_v, sizeof(value_v), "%s", value);
	switch (v->flgs & TYPE_MASK) {
		case MAC_T:
		{
			if (v->data != NULL && v->size > 0)
				ether_toa(value_v, v->data);
		}
			break;
		case IPV4_T:
		{
			if (v->data != NULL && v->size > 0)
				inet_pton(AF_INET, value_v, (void *)(struct in_addr*)v->data);
		}
			break;
		case INT_T:
		{
			if (v->data != NULL && v->size > 0) {
				target_int32 = (int *)v->data;
				*target_int32 = atoi(value_v);
			}
		}
			break;
		case STRING_T:
		{
			if (v->data != NULL && v->size > 0)
				snprintf(v->data, v->size, "%s", value_v);
		}
			break;
		case SPECIAL_T:
		{
			if (v->data != NULL) {
				if (!strcasecmp(v->name, "retry_interval")) {
					if (set_retry_interval((int *)v->data, value_v) < 0)
						return 0;
				} else if (!strcasecmp(v->name, "prov_stime") ||
							!strcasecmp(v->name, "prov_etime")) {
					if (set_time_range((int *)v->data, value_v) < 0)
						return 0;
				}
			}
		}
			break;
		default:
			break;
	}
	/* save configuration to nvram */
	if (v->flgs & FLG_DVNV) {
		nv_val = nvram_get_r_def((char *)v->name, getval, sizeof(getval), "");
		ydespaces(nv_val);
		if (strcmp(nv_val, value_v)) {
			if (strcmp((char *)v->name, "prov_ip") && strcmp(value_v, "127.0.0.1")) {
				if (!strcmp((char *)v->name, "fwac"))
					nvram_set("tmp_fwac", value_v);
				else if (!strcmp((char *)v->name, "config_ver"))
					nvram_set("tmp_config_ver", value_v);
				else
					nvram_set((char *)v->name, value_v);
				commit++;
			}
			if (!strcmp((char *)v->name, "apms_ip")) { // snmp acl rule update..
				if (snmp_ip)
					yexecl(NULL, "iptables -D ACL --source %s -p udp --dport %d -j ACCEPT", snmp_ip, port);
				yexecl(NULL, "iptables -I ACL --source %s -p udp --dport %d -j ACCEPT", value_v, port);
			}
			unchanged = 0;
		}
	}

	return unchanged;
}

static void decryption_3deps(struct tms_t *p, struct fwstat *f)
{
	unsigned char tmpkey1[20], tmpkey2[20];
	char outbuf[MAX_DOWN_DATA];
	DES_cblock k1, k2, iv;
	DES_key_schedule ks1, ks2;

	memset(tmpkey1, 0, sizeof(tmpkey1));
	memset(tmpkey2, 0, sizeof(tmpkey2));
	memset(outbuf, 0, sizeof(outbuf));

	memcpy(&tmpkey1[0], &p->url_req.mac[0], 8);
	snprintf((char *)&tmpkey2[0], 5, "%s", &p->url_req.mac[8]);
	snprintf((char *)&tmpkey2[4], 5, "%s", &p->url_req.mac[0]);

	memcpy(&k1, &tmpkey1[0], 8);
	memcpy(&k2, &tmpkey2[0], 8);

	memcpy(&iv, &k1, 8);
	DES_set_key_unchecked(&k1,&ks1);
	DES_set_key_unchecked(&k2,&ks2);
	DES_ede2_cbc_encrypt((unsigned char*)f->fmem,(unsigned char*)f->fmem,f->rcvlen,&ks1,&ks2,&iv,DES_DECRYPT);

	//rawdump(f->fmem, f->rcvlen);
}

static int check_valid_config(int type, char *name, char *value)
{
	char sys_mac[80];

	if (type == WGET_APMS_REQ) {
		if (!strcmp(name, "macaddr")) {
			sys_mac[0] = 0;
			nvram_get_r("HW_NIC1_ADDR", sys_mac, sizeof(sys_mac));
			if (strcmp(sys_mac, value)) {
				syslog(LOG_INFO, "[TMS] wrong apms config(mac:%s): mac mismatch!", value);
				return 0;
			}
			return 1;
		}
	} else if (type == WGET_REQ_CONFIG) {
		if (!strcmp(name, "Manufacture")) {
			if (strcmp(MANUFACTURE_NAME, value)) {
				syslog(LOG_INFO, "[TMS] wrong davo config(%s): manufacturer mismatch!", value);
				nvram_set("cferr", "1");
				commit++;
				return 0;
			}
			nvram_unset("cferr");
			commit++;
			return 1;
		}
	}
	return 0;
}

static char *cal_sha256(char *src, char *dest)
{
	const char *__xascii = "0123456789abcdef";
	unsigned char md[32];
	char *p = dest;
	int i, c;

	SHA256(src, strlen(src), md);
	for (i = 0; i < (sizeof(md) / sizeof(md[0])); i++) {
		c = md[i];
		*p++ = __xascii[(c >> 4) & 0xf];
		*p++ = __xascii[c & 0xf];
	}
	*p = '\0';
	return dest;
}

static int set_account_cfg(struct variable_s *v, char *name, char *value)
{
	char *nv_name = (char *)v->data;
	char val[80], sha256_val[80];
	int unchanged = 1;

	nvram_get_r(nv_name, val, sizeof(val));

	if (value[0] == FORCE_SETUP_LETTER) {
		cal_sha256(&value[1], sha256_val);
		if (strcmp(val, sha256_val)) {
			nvram_set(nv_name, sha256_val);
			commit++;
			unchanged = 0;
		}
		if (!strcmp(name, "root_id") || !strcmp(name, "root_pw"))
			nvram_unset("web_rootaccount_touch");
		else
			nvram_unset("web_useraccount_touch");
		commit++;
		return unchanged;
	} else {
		cal_sha256(value, sha256_val);
		if (!strcmp(name, "root_id") || !strcmp(name, "root_pw")) {
			if (nvram_get("web_rootaccount_touch"))
				return unchanged;
		} else if (!strcmp(name, "user_id") || !strcmp(name, "user_pw")) {
			if (nvram_get("web_useraccount_touch"))
				return unchanged;
		}
		if (strcmp(val, sha256_val)) {
			nvram_set(nv_name, sha256_val);
			commit++;
			unchanged = 0;
		}
	}

	return unchanged;
}

static int set_nvram_cfg(struct variable_s *v, char *name, char *value)
{
	char *nv_name = (char *)v->data;
	char val[40];

	if (!strcmp(nv_name, "webacl_port")) {
		nvram_get_r(nv_name, val, sizeof(val));

		if (value[0] == FORCE_SETUP_LETTER) {
			nvram_unset("web_extenpage_touch");
			if (strcmp(val, (char *)&value[1])) {
				nvram_set(nv_name, (char *)&value[1]);
				commit++;
				return 0;
			}
		} else {
			if (nvram_get("web_extenpage_touch"))
				return 1;
			if (strcmp(val, value)) {
				nvram_set(nv_name, value);
				commit++;
				return 0;
			}
		}
	} else if (strcmp(nv_name, "x_port_1_config") == 0 || strcmp(nv_name, "x_port_2_config") == 0 ||
			strcmp(nv_name, "x_port_3_config") == 0 || strcmp(nv_name, "x_port_4_config") == 0) {
		nvram_get_r(nv_name, val, sizeof(val));
		if (value[0] == '1') { /* PORT ON */
			if (strstr(val, "up"))
				return 1;
			nvram_set(nv_name, "up_auto_-rxpause_-txpause");
			commit++;
			return 0;
		} else if (value[0] == '0') { /* PORT OFF */
			if (strstr(val, "down"))
				return 1;
			nvram_set(nv_name, "down_auto_-rxpause_-txpause");
			commit++;
			return 0;
		} else
			return 1;
	}

	return 1;
}

int tms_nvram_setvar(struct variable_s *v, char *name, char *value, int group_idx)
{
	if (value[0] == 0)
		return 1;

	if (!strcmp(name, "root_id") || !strcmp(name, "root_pw") ||
			!strcmp(name, "user_id") || !strcmp(name, "user_pw")) {
		if (!strcmp(name, "user_id") && !strcmp(value, "root")) {
			g_invalid_webconf = 1;
			return 1;
		} else if (!strcmp(name, "user_pw") && g_invalid_webconf)
			return 1;
		return set_account_cfg(v, name, value);
	} else
		return set_nvram_cfg(v, name, value);
}

static void tms_cfg_to_file(char *path, struct fwstat *f)
{
	FILE *fp;
	time_t tm_time;
	struct tm *st_time;
	char buff[80];

	if (!path || !f)
		return;

	if ((fp = fopen(path, "w"))) {
		time(&tm_time);
		st_time = localtime(&tm_time);
		strftime(buff, sizeof(buff), "[%Y/%m/%d %l:%M:%S]\n\n", st_time);

		fprintf(fp, "%s", buff);
		fwrite(f->fmem, f->rcvlen, 1, fp);
		fclose(fp);
	}
}

extern variable vartbl[];
static int parse_config(struct tms_t *p, int type, struct fwstat *f, int *psys_flag, int *status)
{
	variable *v = NULL;
	char buf[128], cfg_name[80];
	char *value, *name;
	unsigned int ip_acl = 0;
	int e;
	char *path;
	int valid_cfg = 0;

	if (type == WGET_APMS_REQ) {
		if (p->url_req.downtype)
			decryption_3deps(p, f);
	}
	path = ((type == WGET_APMS_REQ)? "/var/apms_cfg": "/var/davo_cfg");
	tms_cfg_to_file(path, f);

	while ((f->fmem = read_line(f->fmem, buf, sizeof(buf)))) {
		if (!buf[0])
			continue;
		value = buf;
		name = strsep(&value, "=");
		if (!name)
			continue;
		ydespaces(name);
		/* Comment */
		if (name[0] == '#')
			continue;
		if (value)
			ydespaces(value);
		else
			value = "";

		if (!valid_cfg && !(valid_cfg = check_valid_config(type, name, value))) {
			*status = -EINVALCONF;
			return 0;
		}

		for (v = &vartbl[0]; v->name; v++) {
			if (v->group_entry > 0) {
				for (e=1; e <= v->group_entry; e++) {
					sprintf(&cfg_name[0], "%s%d", v->name, e);
					if (!strcasecmp(cfg_name, name)) {
						ip_acl |= (1 << (e-1));
						sprintf(&cfg_name[0], "access_block%d", e);
						*psys_flag |= apply_sys_cfg(v, cfg_name, value, e, 0);
						break;
					}
				}
			} else {
				e = 0;
				if (!strcasecmp(v->name, name)) {
					*psys_flag |= apply_sys_cfg(v, name, value, e, type);
					break;
				}
			}
		}
	}

	g_invalid_webconf = 0;
	return 1;
}

static int check_validate_datainfo(struct tms_t *p_tmscfg, int req_type, struct fwstat *fbuf, int *psys_flag, int *status)
{
	if (req_type == WGET_APMS_REQ || req_type == WGET_REQ_CONFIG) {
		if (!parse_config(p_tmscfg, req_type, fbuf, psys_flag, status)) {
			syslog(LOG_INFO, "[TMS] failed to parsing %s config", ((req_type == WGET_APMS_REQ)?"apms":"davo"));
			return 0;
		}
		syslog(LOG_INFO, "[TMS] after apply cfg, %s sysflag(%#x)", ((req_type == WGET_APMS_REQ)?"apms":"davo"),*psys_flag);
	} else if (req_type == WGET_REQ_FIRM) {
		fw_parse_bootline(&fbuf->blnfo);
		if ((*status = fw_validate(fbuf)) != 0) {
			set_fwerrcode(fw_validate(fbuf));
			return 0;
		}
	}

	return 1;
}

int do_wget(struct fwstat *fbuf, char *fbuf_buf, int *exp, int timeo, struct tms_t *p, int req_type, int *psys_flag, int *status)
{
	char cmd[512];
	int try;
	int waiths;
	char *purl, *perr;
	unsigned long pre, end, diff = 0;

	if (req_type == WGET_APMS_REQ) {
		purl = p->apms_req_url;
		perr = "apms";
	} else if (req_type == WGET_REQ_CONFIG) {
		purl = p->apms.config_url;
		perr = "config";
	} else {
		purl = p->apms.firmware_url;
		perr = "firmware";
	}

	snprintf(cmd, sizeof(cmd) - 1,  "wget -q -O - \"%s\" 2>/dev/null", purl);
	for (try = 0; try <= p->apms.retry_count; try++) {
		*status = 0;
		pre = monotonic_ms();
		if (!furl(cmd, timeo, (p_read_f)fw_read_callback, (void *)fbuf)) {
			if (!fbuf->lasterror && fbuf->rcvlen > 0) {
				if (req_type != WGET_REQ_FIRM) {
					if (fbuf->fmem)
						fbuf->fmem[fbuf->rcvlen] = '\0';
				}
				if (check_validate_datainfo(p, req_type, fbuf, psys_flag, status)) {
					if (req_type == WGET_REQ_FIRM) {
						nvram_unset("fwerr");
						commit++;
					}
					return 1;
				}
			}
		}
		//skip last try
		if (try < p->apms.retry_count) {
			++*exp;
			waiths = p->apms.retry_interval[try]*60;

			DEBUG("furl: retry %d times after %d sec\n", try+1, waiths);
			syslog(LOG_INFO, "[TMS] failed: %s file download- retry after %d min",
									perr, p->apms.retry_interval[try]);
			end = monotonic_ms();
			if (end >= pre)
				diff = end - pre;
			else
				diff = pre - end;

			my_sleep_msec((waiths*1000)-(diff));

			memset(&fbuf[0], 0, sizeof(*fbuf));
			if (req_type == WGET_REQ_FIRM) {
				fbuf->fmem = fbuf_buf;
				fbuf->caplen = MAX_FWSIZE;

				DEBUG("result;%s\n", fw_strerror(*status));
				set_fwerrcode(*status);
			} else {
				fbuf->fmem = fbuf_buf;
				fbuf->caplen = MAX_DOWN_DATA;
			}
		}
	}
	if (*status == 0) {
		if ((req_type == WGET_APMS_REQ) || (req_type == WGET_REQ_CONFIG)) {
			*status = -EGETCONF;
			if (req_type == WGET_REQ_CONFIG) {
				nvram_set("cferr", "2");
				commit++;
			}
			syslog(LOG_INFO, "[TMS] failed: request %s config.", perr);
		} else {
			syslog(LOG_INFO, "[TMS] failed: firmware download");
			*status = EGETFW;
			set_fwerrcode(EGETFW);
		}
	}
	return 0;
}

static int apply_sys_cfg(variable *v, char *name, char *value, int group_idx, int cfg_type)
{
	struct in_addr ip;
	int sysflag = 0;
	unsigned int flg = 0;

	flg = v->flgs & FLG_MASK;
	/* do a set of sanity check */
	while (1) {
		if ((flg & FLG_NILNOK) && !value[0])
			break;

		if ((flg & FLG_INANY) && !value[0])
			value = "0.0.0.0";

		if ((flg & FLG_INETATON)) {
			inet_aton(value, &ip);
			if (ip.s_addr == 0 || ip.s_addr == (in_addr_t)-1)
				break;
		}
		DEBUG("%s=%s\n", name, value);
		if (!v->setvar(v, name, value, group_idx)) {
			syslog(LOG_INFO, "[TMS] changed config(%s=%s)", name, value);
			if (flg & FLG_REBOOT)
				sysflag |= TMS_NEED_REBOOT;

			if (flg & FLG_WEB)
				sysflag |= TMS_NEED_WEB;

			if (flg & FLG_FIREWALL)
				sysflag |= TMS_NEED_FIREWALL;
		}

		break;
	}
	return sysflag;
}

int letsgo_download_davo_config(struct tms_t *p)
{
	char tmp[8];

	if (!nvram_get_r("tmp_cfgac", tmp, sizeof(tmp)))
		nvram_get_r("cfgac", tmp, sizeof(tmp));

	syslog(LOG_INFO, "[TMS] decide davo cfg: cfgac system(%s)|apms(%s)\n", p->cfgac, tmp);
	if (!strcmp(p->cfgac, tmp)) {
		nvram_unset("cferr");
		commit++;
		return 0;
	}

	if (!p->apms.config_url[0]) {
		syslog(LOG_INFO, "[TMS] cant download davo config, empty cfg url\n");
		DEBUG("cant download davo config, empty cfg url...\n");
		nvram_set("cferr", "2");
		commit++;
		return 0;
	}

	return 1;
}

int letsgo_need_download_firmware(struct tms_t *p)
{
	char tmp[8];

	if (!nvram_get_r("tmp_fwac", tmp, sizeof(tmp)))
		nvram_get_r("fwac", tmp, sizeof(tmp));

	syslog(LOG_INFO, "[TMS] decide firmware: fwac system(%s)|apms(%s)\n", p->fwac, tmp);
	if (!strcmp(p->fwac, tmp)) {
		nvram_unset("fwerr");
		commit++;
		return 0;
	}

	if (!p->apms.firmware_url[0]) {
		syslog(LOG_INFO, "cant download firmware, empty firmware url\n");
		DEBUG("cant download firmware, empty firmware url...\n");
		nvram_set("fwerr", "2");
		commit++;
		return 0;
	}
	return 1;
}

int tms_check_cfg(struct variable_s *v, char *name, char *value, int group_idx)
{
	char value_v[256];

	if (!value || value[0] == 0)
		return -1;

	snprintf(value_v, sizeof(value_v), "%s", value);
	return 1;
}

void restart_web(void)
{
	int webPid;

	yfcat("/var/run/webs.pid", "%d", &webPid);
	if (webPid > 0) {
		kill(webPid, SIGTERM);
		system("boa &");
	}
}

static void get_mono(struct timespec *ts)
{
	if (syscall(__NR_clock_gettime, CLOCK_MONOTONIC, ts))
		perror("clock_gettime(MONOTONIC) failed");
}

static unsigned monotonic_ms(void)
{
	struct timespec ts;

	get_mono(&ts);
	return (unsigned)(ts.tv_sec * 1000UL + ts.tv_nsec / 1000000);
}

int check_dvflag(int flag)
{
	int fd;
	int get_flag;
	int ret = 0;

	if ((fd = open("/proc/dvflag", O_RDWR)) < 0)
		return 0;

	if (read(fd, (void *)&get_flag, sizeof(get_flag)) > 0) {
		if (get_flag & flag)
			ret = 1;
		else
			ret = 0;
	}
	close(fd);

	return ret;
}
