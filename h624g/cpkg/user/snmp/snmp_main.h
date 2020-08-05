//------------------------------------------------------------------------------
//  davo snmp header file
//------------------------------------------------------------------------------
#ifndef     DAVO_SNMP_H__
#define     DAVO_SNMP_H__

#if defined(__cplusplus)
extern "C" {
#endif

/*
**  SNMP Configuration Structure
*/

#define		SNMP_NO_ACTION			0
#define		SNMP_RESTART			1
#define		SNMP_REBOOT				2
#define     SNMP_MANUAL_UPGRADE		4
#define     SNMP_FORCE_WLSCAN		8
#define     SNMP_WEB_RESTART		16
#define		SNMP_SAVE_APPLY			32

#define     DVSNMP_MAX_COMMUNITY_LEN    80
#define 	DVSNMP_MAX_TRAP_SERVER_LEN	80
#define     DVSNMP_MAX_TRAP_SERVER      1
#define     DVSNMP_MAX_ACL_SERVER      	8

#define		MAX_URL_LEN		80
#define		MAX_PARAM_LEN	30

#define DV_FOPEN		fopen
#define DV_FCLOSE		fclose
#define DV_OPEN			open
#define DV_CLOSE		close
#define DV_ACCESS		access
#define DV_STRSTR		strstr
#define DV_STRCMP		strcmp
#define DV_SPRINTF		sprintf
#define DV_FPRINTF		fprintf
#define DV_SNPRINTF		snprintf
#define DV_PRINTF		printf
#define DV_EXIT			exit
#define DV_UNLINK		unlink
#define DV_FSCANF		fscanf

#define STRONGCMP(x,x2)  optarg[0]==x || optarg[0]==x2
#define SNMP_AGENT_PID_FILE		"/var/run/snmp_agentd.pid"

#define INIT_TIL(target) \
do{\
	target.trap_srv[0] = target.trap_kind[0] = target.trap_file[0] = target.trap_tmp1[0] = '\0';\
}while(0)

#define BASIC_TRAP			"Basic Trap"
#define WIFI_ON_TRAP		"WiFi Connect Trap"
#define WIFI_OFF_TRAP		"WiFi Disconnect Trap"
#define CPEPING_TRAP		"CpePing Trap"
#define AUTOREBOOT_TRAP		"Autoreboot Trap"
#define PORTLINK_TRAP		"Portlink Trap"
#define LIMITEDSEESION_TRAP	"LimitedSession_Trap"
#define SMARTRESET_TRAP		"SmartReset_Trap"
#define HANDOVER_TRAP		"HandOver_Trap"
#define AUTOBANDWIDTH_TRAP 	"AutoBandwidth_Trap"
#define NTP_TRAP 			"NTP fail Trap"
#define WL1_SITESURVEY_TRAP "WLAN1 SiteSurvey Trap"
#define WL0_SITESURVEY_TRAP "WLAN0 SiteSurvey Trap"
#define STA_FAIL_TRAP 		"STA_Fail Trap"

#define MAX_SUPPLICANT_NUM 127

#if defined(__STATRAP_EVENT__)
/* jihyun@davo160202 jcode#7 -*/
#define MONITOR_ACTIVE		1
#define MONITOR_DEACTIVE	0
#endif

typedef struct DAVO_SNMP_CFG {
	char    			getcommunity[DVSNMP_MAX_COMMUNITY_LEN];
	char    			setcommunity[DVSNMP_MAX_COMMUNITY_LEN];
	char    			trpcommunity[DVSNMP_MAX_COMMUNITY_LEN];
	unsigned short  	snmpport;
	char 		 		trapserver[DVSNMP_MAX_TRAP_SERVER][DVSNMP_MAX_TRAP_SERVER_LEN];
	unsigned short  	trapport[DVSNMP_MAX_TRAP_SERVER];
	char 				snmp_authen_mode[MAX_PARAM_LEN];
} TDV_SNMP_CFG;

typedef enum {
	Enum_RowStatusActive = 1,
	Enum_RowStatusNotInSevice,
	Enum_RowStatusNotReady,
	Enum_RowStatusCreateAndGo,
	Enum_RowStatusCreateAndWait,
	Enum_RowStatusDestory
}Enum_RowStatus;

typedef struct {
	char	pingAddress[64];
	int		pktSize;
	int		pktTimeout;
	int		pktDelay;
	int 	pktTimeoutcnt;
// ping Test Result
	unsigned int minPingTime;
	unsigned int avgPingTime;
	unsigned int maxPingTime;
	short		EntryStatus;
} _CPEPING_TEST_T;

extern TDV_SNMP_CFG dvsnmp_cfg;

/*
**  Function Prototype
*/

/*!< Export Set/Get Function Prototype */
char* getSmashSnmpMode(char*);
char* getSmashSnmpGetCommunity(char*);
char* getSmashSnmpSetCommunity(char*);
char* getSmashSnmpTrapMode(char*);
char* getSmashSnmpTrapCommunity(char*);
char* getSmashSnmpTrapAddress(char*);

int setSmashSnmpMode(char*, int);
int setSmashSnmpGetCommunity(char*, int);
int setSmashSnmpSetCommunity(char*, int);
int setSmashSnmpTrapMode(char*, int);
int setSmashSnmpTrapCommunity(char*, int);
int setSmashSnmpTrapAddress(char*, int);

extern void setSmashSnmpInfo(char *name, char *value, int length);
extern char* getSmashSnmpInfo(char *target, char *name, int length);
extern void commitSmashSnmpInfo(void);

extern char *get_getcommunity();
extern char *get_setcommunity();
extern void set_trapserver(char *serv_ip);
extern char *get_trapserver(void);
extern void set_trapport(int port);
extern int get_trapport(void);

void setVarCMT(char *buf, char *target);
void getVarCMT(char *buf, char *target, int len);
extern int stricmp(char *s1, char *s2);
extern void init_DAVO_SIP_MIB();

extern void *sendGWMacAddr(void);
extern void *sendStMacAddr(void);
extern void *sendAutoTransmission(void);

extern char * getValue(char *name);
extern int setValue(char *name, char *value);
extern int unsetValue(char *name);
extern int setValue_mib(int id, void *value);
extern int getValue_mib(int id, void *value);
extern void commitValue();

#if !defined(__STATRAP_EVENT__)
void monitor_wlsta_attend(void);
void monitor_wlsta_print(void);
#endif

void cpe_ping_init();
void SaveAndApply__(void);

int get_data_size_converter(int data_h, int data_l);
long get_lastChanged_time(int port);
long get_flash_utiliz(void);
unsigned int current_sysUpTime(void);

#if defined(__cplusplus)
}
#endif

#endif  //#ifndef     DAVO_SNMP_H__

