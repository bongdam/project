#ifndef CWMPGLOBAL_H_
#define CWMPGLOBAL_H_

#include "tlog_printf.h"
#include "parameter_api.h"
#include "soapH.h"
#include "httpda.h"
#include "cwmp_notify.h"
#include "cwmp_download.h"

#if __STDC_VERSION__ >= 199901L
#include <stdint.h>
#include <inttypes.h>
#else
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long int uint64_t;
#define PRIu64 "llu"
#endif

//APACRTL-458
//#define TLOG_PRINT(...) syslog(LOG_INFO, DVLOG_MARK_TR069 "[TR] " __VA_ARGS__)
/*after setparametervalue/addobject/deleteobject & statu==1, reboot the system*/
//#define SELF_REBOOT

/*download way*/
#define DLWAY_NONE	0
#define DLWAY_DOWN	1
#define DLWAY_UP	2
/*download type*/
#define DLTYPE_NONE	0
#define DLTYPE_IMAGE	1
#define DLTYPE_WEB	2
#define DLTYPE_CONFIG	3
#define DLTYPE_LOG	4
/*download status*/
#define DOWNLD_NONE	0
#define DOWNLD_READY	1
#define DOWNLD_START	2
#define DOWNLD_FINISH	3
#define DOWNLD_ERROR	4
/*download image status*/
#define DOWN_IMG_NONE 0	//Before Downloading config
#define DOWN_IMG_VER_CHECK 0xff	//after receive "DOWNLOAD" message
#define DOWN_IMG_START 1
#define DOWN_IMG_FINISH 2
#define DOWN_IMG_OK 3
#define DOWN_IMG_ERROR 4

/*download config status*/
#define DOWN_CFG_NONE 0
#define DOWN_CFG_READY 1
#define DOWN_CFG_SUCCESS 2
#define DOWN_CFG_PARSE_ERR 3
#define DOWN_CFG_DOWN_ERR 4

//상위 8비트 : IoT 다운로드 필요 여부
//prov_stat
#define NEED_IOT_SW_POLL	0x01000000

enum {
	PROV_INIT = 0,
	READY_DOWN_CFG,
	CFG_DOWN_START,
	FW_DOWN_IN_PROGRESS,
	CFG_DOWN_IN_PROGRESS,
	IOT_DOWN_IN_PROGRESS,
	CFG_DOWN_OK,
	CFG_DOWN_ERR,
	CFG_DOWN_PARSE_ERR,
	FW_DOWN_SUCCESS,
	FW_DOWN_FAIL,
	MAX_PROV_STATUS
};

//main loop timer
enum {
	PROCESS_IN_IDLE,
	PROCESS_IN_BUSY
};

/*download union*/
typedef union
{
struct cwmp__Download	Download;
struct cwmp__Upload		Upload;
}DownloadInfo_T;

#define IMG_WRITE_LOCKFILE		"/tmp/.img_lock"
#define PROVISION_PERIOD "/tmp/.in_periodic_inform"	//APACQCA-59

#define CWMP_IP_FILE "/tmp/cwmp_wan_ip"
#define WAN_IP_CACHE "/var/wan_ip"	// XXX : no newline

#define EC_BOOTSTRAP	0x0001	/*0 BOOTSTRAP*/
#define EC_BOOT			0x0002	/*1 BOOT*/
#define EC_PERIODIC		0x0004	/*2 PERIODIC*/
#define EC_SCHEDULED	0x0008	/*3 SCHEDULED*/
#define EC_VALUECHANGE	0x0010	/*4 VALUE CHANGE*/
#define EC_KICKED		0x0020	/*5 KICKED*/
#define EC_CONNREQUEST	0x0040	/*6 CONNECTION REQUEST*/
#define EC_TRANSFER		0x0080	/*7 TRANSFER COMPLETE*/
#define EC_DIAGNOSTICS	0x0100	/*8 DIAGNOSTICS COMPLETE*/
#define EC_REQUESTDL	0x0200	/*9 REQUEST DOWNLOAD*/
#define EC_M_REBOOT		0x0400	/*M Reboot*/
#define EC_M_SCHEDULED	0x0800	/*M ScheduleInform*/
#define EC_M_DOWNLOAD	0x1000	/*M Download*/
#define EC_M_UPLOAD		0x2000	/*M Upload*/
#define EC_M_VENDOR		0x4000	/*M <vendor-specific method>*/
#define EC_X_VENDOR		0x8000	/*X <OUI> <event>*/
#define EC_AUTOTRANSFER	0x10000	/*10 AUTONOMOUS TRANSFER COMPLETE*/	//APACRTL-433
#define EC_X_PERIODIC_RST	0x20000	/*X <OUI> <event>*/	//APACQCA-59

// event we must store across reboot
#define EC_SAVE_MASK (EC_PERIODIC|EC_SCHEDULED|EC_TRANSFER|EC_M_REBOOT|EC_M_SCHEDULED|EC_M_DOWNLOAD|EC_M_UPLOAD)

#ifdef __REALTEK__
#define CWMP_HTTP_REALM		"realtek.com.tw"
#else /* __DAVO__ */
#define CWMP_HTTP_REALM		"davolink.co.kr"
#endif /* __REALTEK__ */
#define CWMP_IDLE_TIMEOUT	30
#define log			printf
#define HAS_EVENT(m, ev)	((m)->cpe_events & ev)
#define MSG_SIZE  		(sizeof(struct message) - sizeof(long))
#define any_response		(-1)

#define MAX_POLLING_RANGE 600   //APACRTL-617

#ifdef __DV_CWMP_SESSION_TEST__
enum {
	SESSION_FAIL__403 = 1,
	SESSION_FAIL__SEND_INFORM,
	SESSION_FAIL__SEND_DOWN_RESP,
	SESSION_FAIL__SEND_TRANS_COMP,
	SESSION_FAIL__SEND_AUTO_TRANS_COMP,
	SESSION_FAIL__SEND_EMPTY,
	SESSION_FAIL__SEND_GET_PARAM_VAL_RESP,
	SESSION_FAIL__SEND_SET_PARAM_VAL_RESP,
	SESSION_FAIL__SEND_ADD_OBJ_RESP,
	SESSION_FAIL__SEND_DEL_OBJ_RESP,
	SESSION_FAIL__ACS_FAULTCODE_INFORM,
	SESSION_FAIL__ACS_FAULTCODE_TRANS_COMP,
	SESSION_FAIL__ACS_FAULTCODE_AUTO_TRANS_COMP,
	SESSION_FAIL__ACS_FAULTCODE_GET_PARAM_VAL,
	SESSION_FAIL__ACS_FAULTCODE_8811,
	SESSION_FAIL__HOLD_REQ_TIMEOUT
};
#endif

enum {
	UPGRADING_COMPLETE = 0,
	UPGRADING_PHASE1,
	UPGRADING_PHASE2,
	UPGRADING_PHASE3
};

enum {
	MSG_SEND = 10,
	MSG_EVENT_CONNREQ,
	MSG_TIMER,
	MSG_RECV,
	MSG_CMD_IMPOLL = 100,
	MSG_CMD_IDLERESET,
	MSG_CMD_POLLTEST,
	MSG_CMD_IMBOOT,
	MSG_CMD_GETSTATUS
};

enum {
	REQ_COMPLETE,
	REQ_SENT
};

enum {
	CPE_ST_DISCONNECTED,
	CPE_ST_CONNECTED,
	CPE_ST_EMPTY_SENT,
	CPE_ST_AUTHENTICATING,
	CPE_ST_REQ_SENT,
	CPE_ST_RES_SENT
};

enum {
	CPE_AUTH_NONE,
	CPE_AUTH_BASIC,
	CPE_AUTH_DIGEST
};

enum {
	CPE_REQ_EMPTY,
	CPE_REQ_INFORM,
	CPE_REQ_TRANSFER_COMPLETE
};

enum {
	EVENT_NONE,
	EVENT_INFORM,
	EVENT_SEND_EMPTY,
	EVENT_SEND_REQ,
	EVENT_SEND_RSP,
	EVENT_RECV_EMPTY,
	EVENT_RECV_OTHER,
	EVENT_RECV_RSP,
	EVENT_RECV_REQ,
	EVENT_RECV_FAULT,
	EVENT_TIMEOUT,
	EVENT_PERIODIC_INFORM,
	EVENT_SCHEDULE_INFORM,
	EVENT_CLOSE,
	EVENT_CLOSE_FORCE,	//APACRTL-552
	//	EVENT_AUTHOK,
	EVENT_AUTHFAIL
};

enum {
	FROM_OLD_TIMER,
	FROM_NOW
};

struct message {
	long msg_type;
	long msg_datatype;
	void*	msg_data;
};

struct cpe_request {
	int rq_state;
	int rq_retry; // 1 if msg must be retry.
	int rq_retry_count; // number of retry to attempt.
	struct message rq_msg;
};

struct cpe_req {
	int		cpe_req_type; 
	void *	cpe_req_arg;	
	struct cpe_req *cpe_req_next;

	// for internal 
	void *	_next;
};

struct cpe_machine {
	int  		cpe_state;
	struct soap 	cpe_soap;
	void *		cpe_user;
	unsigned int	cpe_idle_time;
	unsigned int	cpe_idle_timeout;
	
	int		cpe_auth_count;
	int		cpe_auth_type; // 0 basic, 1 digest
	int		cpe_last_msgtype;
	int		cpe_recv_msgtype;
	int		cpe_isReqSent;
	int		cpe_hold; // 
	unsigned int	cpe_retry_count;
	int		cpe_retryCountdown;

	unsigned int 	cpe_events; // current working event.
	unsigned int 	cpe_event_queue; // event queue.

	unsigned int  cpe_conn_request;

	int		cpe_SendGetRPC;//jiunming
	struct http_da_info cpe_da_info;
	time_t session_init_time;
};

//user timer
enum {
	PASSED,
	NOT_PASSED,
	NOT_SET
};

enum {
	POLL_TIMER,
	STUN_TIMER,
	HOLEPUNCH_TIMER,
	IDLE_CHECK_TIMER,
	REBOOT_TIMER,
	IDLE_RESET_TIMER,
	NOT_FOUND
};

struct cwmp_timer {
	struct timespec poll_ts;
	struct timespec stun_ts;
	struct timespec hp_ts;
	struct timespec idle_check_ts;
	struct timespec reboot_ts;
	struct timespec idle_reset_ts;
};

struct cwmp_userdata
{
	// STUN 
	int 				MappedAddr;
	unsigned short			MappedPort;
	int					stunfd;
	unsigned short		STUNEnable;
	short				STUNMaxPeriod;
	short				STUNMinPeriod;
	//unsigned short 		STUNPeriod;
	//unsigned short		HPPeriod;
	//unsigned short 		HPRange;
	short 		STUNPeriod;
	short		HPPeriod;
	short 		HPRange;
	unsigned int		HP_TTL;
	
	//relative to SOAP header
	unsigned int		ID;
	unsigned int		HoldRequests;
	unsigned int		NoMoreRequests;
	unsigned int		CPE_MaxEnvelopes;
	unsigned int		ACS_MaxEnvelopes;
	
	//cwmp:fault
	int					FaultCode;
	
	//download/upload
	int					DownloadState;
	int					DownloadWay;
	char				*DLCommandKey;
	time_t				DLStartTime;
	time_t				DLCompleteTime;
	unsigned int		DLFaultCode;
	DownloadInfo_T		DownloadInfo;

	//inform
	unsigned int		InformInterval; //PeriodicInformInterval
	time_t				InformTime; //PeriodicInformTime
	int					PeriodicInform;
	unsigned int		EventCode;
	struct node			*NotifyParameter;
	int					InformIntervalCnt; 

	//ScheduleInform
	unsigned int		ScheduleInformCnt; //for scheduleInform RPC Method, save the DelaySeconds
	char				*SI_CommandKey;

	//Monotonic Timer
	struct cwmp_timer	cwmp_timer;

	//Reboot
	char				*RB_CommandKey;	//reboot's commandkey
	char				Reboot; // reboot flag
	char				Restart;
	unsigned char		fDownloadImage;
	char				fDownloadConfig;
	char				config_changed;
	char				RebootTimer;
	
	//FactoryReset
	int					FactoryReset;

	// andrew. 
	char 				*url1;	// ACS URL
	char 				*url2;	// TRCS URL
	char 				*username; // username used to auth us to ACS.
	char 				*password; // passwrd used to auth us to ACS.
	char 				*conreq_username;
	char 				*conreq_password;
	char 				*realm;
	int					server_port;
	void 				*machine;
	
	//certificate
	char				*cert_passwd;
	char				*cert_path;
	char				*ca_cert;

	char				*notify_filename;
	
	unsigned int		prov_stat;

	int					url_changed;
	clock_t				HoldRequestTime;
};

struct AutoTransferComplete {
	int  isDownload;
	char *TransferURL;
	char *TargetFileName;
	char *FileType;
	int	 FileSize;
	struct cwmp__FaultStruct FaultStruct;
	time_t	StartTime;
	time_t	CompleteTime;
};

struct pollInfo {
	unsigned int fPeriodic;
	unsigned int cumulative_pkt;
	unsigned int control_pkt;
	int interval;
	int			polling_period;
	int			polling_days;
	int			polling_range;
	char		polling_time[8];
	int			time_limit;
	int			errCount;
};


/*fault string*/
extern char *strERR_9000;
extern char *strERR_9001;
extern char *strERR_9002;
extern char *strERR_9003;
extern char *strERR_9004;
extern char *strERR_9005;
extern char *strERR_9006;
extern char *strERR_9007;
extern char *strERR_9008;
extern char *strERR_9009;
extern char *strERR_9010;
extern char *strERR_9011;
extern char *strERR_9012;
extern char *strERR_9013;
extern char *strERR_9014;
extern char *strERR_9015;
extern char *strERR_9016;
extern char *strERR_9017;
extern char *strERR_9018;
extern char *strERR_9019;
extern char *strERR_9801;
extern char *strERR_9802;
extern char *strERR_9803;
extern char *strERR_9804;
extern char *strERR_9811;
extern char *strERR_9812;
extern char *strERR_9813;
extern char *strERR_9814;
extern char *strERR_default;

extern struct soap clientSoap;
extern struct cpe_machine cpe_client;

extern int st_ACSSentEmpty;
extern int st_CPESentEmpty;
extern int gStartPing;
extern char gParameterKey[];
extern char gConnectionRequestURL[];
extern char *strCPEState[]; 

extern void cwmpStartPingDiag();
extern void MgmtSrvSetParamKey(const char *key);
extern int MgmtSrvGetConReqURL(char *url, unsigned int size);
extern int MsgSend(struct message *msg);
extern void handle_io(int sig);
extern void control_led_to_upgrade(int phase);
extern int dnsQuery(char *domain, unsigned int *ip);

extern void cwmpSendEvent(unsigned int event);
extern unsigned int apply_config_parameter(int *val_apply);
extern int upgradeFirmware(char *fwFilename);
extern void save_update_way();
extern unsigned int centisecond();

void cwmpEvent(struct cpe_machine *m, unsigned int event);
//#define cwmpEvent
void cwmpCpeSendEvent(struct cpe_machine *m, int type, void *data);
void cwmpCpeHold(struct cpe_machine *m, int holdit);
int CPEMachineNotify(struct cpe_machine *m, int event, void *arg);
void send_qms_msg(char *path);

extern struct cwmp_userdata *cwmp_init_userdata( void );
extern int cwmp_free_userdata( struct cwmp_userdata *user );
extern void cwmp_SaveReboot( struct cwmp_userdata *user, int reboot_flag, int apply);	//APACRTL-483

//main loop timer
void init_mainloop_status_lock(void);
void deinit_mainloop_status_lock(void);
void change_mainloop_status(int status);
int check_mainloop_status(void);

void check_need_update_polltime(int val);	//APACRTL-543

//provisioning status
void init_cpe_state_lock(void);
void deinit_cpe_state_lock(void);
void change_cpe_state(int status);
int check_cpe_state(void);

unsigned int get_prov_stat(struct cwmp_userdata *ud);
void set_prov_stat(struct cwmp_userdata *ud, unsigned int stat);

//user timer
void set_cwmp_timer(struct cwmp_userdata *ud, int type, time_t sec, int from);
int check_cwmp_timer(struct cwmp_userdata *ud, int type);
void reset_cwmp_timer(struct cwmp_userdata *ud, int type);
time_t ts_timediff(struct timespec *result, struct timespec *old, struct timespec *new);

#if 1
extern void cwmp_reset_DownloadInfo( DownloadInfo_T *dlinfo, int dlway );
#else
extern void *cwmp_download(void *data);
#endif
#endif /*#ifndef CWMPGLOBAL_H_*/
