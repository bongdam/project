#ifndef __TMS_CLIENT_H__
#define __TMS_CLIENT_H__


#define MAC_T			(1 << 0)
#define STRING_T		(1 << 1)
#define INT_T			(1 << 2)
#define IPV4_T			(1 << 3)
#define SPECIAL_T		(1 << 4)
#define FLG_REBOOT		(1 << 5)		/* Need	reboot */
#define FLG_NILNOK		(1 << 6)		/* Can not be null(nil)	*/
#define FLG_INETATON	(1 << 7)		/* Neither 0.0.0.0 nor 255.255.255.255 */
#define FLG_INANY		(1 << 8)		/* if not specified, consider as "0.0.0.0" */
#define FLG_DVNV		(1 << 9)		/* it needs	to save	variable to	dvnv also */
#define FLG_WEB			(1 << 10)
#define FLG_FIREWALL	(1 << 11)

#define TYPE_MASK		0xff
#define FLG_MASK		0xffffffff

#define WRONG_DAVO_CFG	0x110000

#define WGET_APMS_REQ		1
#define WGET_REQ_CONFIG		2
#define WGET_REQ_FIRM		3

#define TMS_NEED_REBOOT		1
#define TMS_NEED_WEB		2
#define TMS_NEED_FIREWALL	4

#define MANUFACTURE_NAME	"Davolink"
#define AUTOUP_STATE "/tmp/autoup_state"
#define AUTOUP_UPGRADE "/tmp/autoup_upgrade"
#define	MAX_INTERVAL_CNT	10

struct apms_item_t {
	unsigned char macaddr[20];
	unsigned char apms_ip[64];
	int apms_port;
	unsigned char prov_ip[64];
	int prov_port;
	char config_url[256];
	char firmware_url[256];
	int prov_interval; // day
	int prov_stime[3]; // HH(24):MM:SS
	int prov_etime[3]; // HH(24):MM:SS
	int retry_count;
	int retry_interval[MAX_INTERVAL_CNT];
};

struct tms_url_t {
	char ver[128];
	char mac[20];
	int downtype;
	char model[30];
	char vendor[30];
};

struct chk_t {
	int wan_bw_kb;
	int reboot_time[4];     /* 재부팅 시간 */
	int reboot_retry;       /* 횟수 ==> unlimit */
	int reboot_bw;          /* default: 40kbps */
	int down_retry_delay;   /* 다운로드 대기시간(랜덤) */
	int reboot_check_svc;    /* 재부팅 확인주기 */
};

struct tms_t {
	char cfgac[128];
	char cfver[128];
	char fwac[128];
	char fwver[128];
	char apms_req_url[512];
	int	cferr;
	int fwerr;

	struct apms_item_t apms;
	struct tms_url_t url_req;
	struct chk_t chk;
};

typedef struct variable_s {
	const char *name;
	int (*setvar)(struct variable_s *, char *, char *, int);
	void *data;
	int  size;
	const unsigned int flgs;
	int group_entry;
} variable;

#endif
