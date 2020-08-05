#ifndef __CWMPCLIENTLIB_C__
#define __CWMPCLIENTLIB_C__

#include <signal.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <syslog.h>

#include "cwmpGlobal.h"
#include <libytool.h>
#include <shutils.h>
#include <bcmnvram.h>
#include <hanguel.h>
#include <publicfunc.h>
#include <strtok_s.h>

#include <ctype.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "cwmpClientLib.h"
#include "bcm_param_api.h"

#define TIME_2004_JAN_01			(1072882800)

/*fault string*/
char *strERR_9000 = "Method not supported";
char *strERR_9001 = "Request denied";
char *strERR_9002 = "Internal error";
char *strERR_9003 = "Invalid arguments";
char *strERR_9004 = "Resources exceeded";
char *strERR_9005 = "Invalid parameter name";
char *strERR_9006 = "Invalid parameter type";
char *strERR_9007 = "Invalid parameter value";
char *strERR_9008 = "Attempt to set a non-writable parameter";
char *strERR_9009 = "Notification request rejected";
char *strERR_9010 = "Download failure";
char *strERR_9011 = "Upload failure";
char *strERR_9012 = "File transfer server authentication failure";
char *strERR_9013 = "Unsupported protocol for file transfer";
char *strERR_9014 = "File transfer failure:unable to join multicast group";
char *strERR_9015 = "File transfer failure:unable to contact file server";
char *strERR_9016 = "File transfer failure:unable to access file";
char *strERR_9017 = "File transfer failure:unable to complete download";
char *strERR_9018 = "File transfer failure:file corrupted";
char *strERR_9019 = "Invalid Deployment Unit Update. Version already exists.";
char *strERR_9801 = "ERR_TIMEOUT_DNS_CDS";
char *strERR_9802 = "ERR_TIMEOUT_HTTP_CDS";
char *strERR_9803 = "ERR_DOWN_CONFIG";
char *strERR_9804 = "ERR_CONFIG_PARSING";
char *strERR_9811 = "ERR_TIMEOUT_DNS_IDS";
char *strERR_9812 = "ERR_TIMEOUT_HTTP_IDS";
char *strERR_9813 = "ERR_DOWN_IMAGE";
char *strERR_9814 = "ERR_IMAGE_UPDATE";
char *strERR_9821 = "ERR_APP_DECOMPRESS";
char *strERR_default = "fault";

char *strCPEState[] = {
	"Disconnected",
	"Connected",
	"Empty_Sent",
	"Authenticating",
	"Request_Sent"
};

// andrew
int msgid;
static struct cwmp_userdata *pUserData = NULL;
struct pollInfo pollInfo;

int is_downgrade;
int is_iboot;

extern int init_udp_process(int *, unsigned short *, int *);
extern int send_stun_msg(int *, unsigned short);
extern int isNeedUpdate(void);
extern unsigned int centisecond(void);
extern void CpeDisconnect(struct cpe_machine *m, int retry);
extern int need_reboot_apply;
extern long test_addr;

enum {
	BUSY = 0,
	IDLE
};

void init_check_idle_service(struct pollInfo *info);
int check_idle_service(struct pollInfo *info);

static void get_prov_status(struct soap *soap);
static int get_stun_min_period(struct cwmp_userdata *ud);	//APACRTL-414

#if defined(GSOAP_VERSION) && GSOAP_VERSION >= 20829
#define soap_default_time soap_default_dateTime
#define soap_out_time soap_out_dateTime
#endif

static int mainloop_status = PROCESS_IN_IDLE;
static pthread_mutex_t status_lock;
static pthread_mutex_t cpe_state_lock;

void init_mainloop_status_lock(void)
{
	pthread_mutex_init(&status_lock, NULL);
}

void deinit_mainloop_status_lock(void)
{
	pthread_mutex_destroy(&status_lock);
}

void change_mainloop_status(int status)
{
	pthread_mutex_lock(&status_lock);
	mainloop_status = status;
	pthread_mutex_unlock(&status_lock);
}

int check_mainloop_status(void)
{
	int res = 0;
	pthread_mutex_lock(&status_lock);
	res = mainloop_status;
	pthread_mutex_unlock(&status_lock);
	return res;
}

void init_cpe_state_lock(void)
{
	pthread_mutex_init(&cpe_state_lock, NULL);
}

void deinit_cpe_state_lock(void)
{
	pthread_mutex_destroy(&cpe_state_lock);
}

void change_cpe_state(int status)
{
	pthread_mutex_lock(&cpe_state_lock);
	cpe_client.cpe_state = status;
	pthread_mutex_unlock(&cpe_state_lock);
}

int check_cpe_state(void)
{
	int res = 0;
	
	pthread_mutex_lock(&cpe_state_lock);
	res = cpe_client.cpe_state;
	pthread_mutex_unlock(&cpe_state_lock);
	return res;
}

unsigned int get_prov_stat(struct cwmp_userdata *ud)
{
	return ud->prov_stat;
}

void set_prov_stat(struct cwmp_userdata *ud, unsigned int stat)
{
	ud->prov_stat = stat;
}

/***********************************************************************/
/* TEST_SESSION_FAIL */
/***********************************************************************/
#ifdef __DV_CWMP_SESSION_TEST__
static int get_session_fail_flag(void)
{
	char buf[128] = "";

	nvram_safe_get_r("test_prov_session_case", buf, sizeof(buf));

	return atoi(buf);
}

static void malform_utf8_to_euckr(char *data, size_t sz)
{
	int i = 0;
	unsigned char dummy[8] = {0xb1,0xe2,0xb4,0xc9,0xc0,0xa7,0xb1,0xe2};	//EUC-KR

	if (sz > sizeof(dummy))
		sz = sizeof(dummy);

	for (i = 0; i < sz; i++)
		memcpy(&data[i], &dummy[i], 1);
}

static void test_session_fail__403(char *val)
{
	if (!val)
		return;

	if (get_session_fail_flag() == SESSION_FAIL__403) {
		if (val[0] == 'a')
			val[0] = 'b';
		else
			val[0] = 'a';
	}
}

static void test_session_fail__acs_faultcode_inform(char *val)
{
	int flag = get_session_fail_flag();

	if (!val)
		return;

	if (flag == SESSION_FAIL__ACS_FAULTCODE_INFORM
			|| flag == SESSION_FAIL__ACS_FAULTCODE_8811)
		malform_utf8_to_euckr(val, STRLEN(val));	//do not use sizeof()
}

static void test_session_fail__acs_faultcode_trans_comp(char *val, size_t valsz)
{
	if (!val)
		return;

	if (get_session_fail_flag() == SESSION_FAIL__ACS_FAULTCODE_TRANS_COMP)
		malform_utf8_to_euckr(val, valsz);
}

static void test_session_fail__acs_faultcode_auto_trans_comp(char *val, size_t valsz)
{
	if (!val)
		return;

	if (get_session_fail_flag() == SESSION_FAIL__ACS_FAULTCODE_AUTO_TRANS_COMP)
		malform_utf8_to_euckr(val, valsz);
}

static void test_session_fail__acs_faultcode_get_param_val(char *val)
{
	if (!val)
		return;

	if (get_session_fail_flag() == SESSION_FAIL__ACS_FAULTCODE_GET_PARAM_VAL)
		malform_utf8_to_euckr(val, STRLEN(val));	//do not use sizeof()
}

static void test_session_fail__acs_faultcode_8811(int *faultcode)
{
	if (get_session_fail_flag() == SESSION_FAIL__ACS_FAULTCODE_8811)
		*faultcode = 8811;
}

static void test_session_fail__hold_req_timeout(int type)
{
	if (get_session_fail_flag() == SESSION_FAIL__HOLD_REQ_TIMEOUT
			&& type == SOAP_TYPE_cwmp__DownloadResponse)
		system("echo \"nameserver 127.0.0.1\" > /etc/resolv.conf");
}

static int test_session_fail__send(int type)
{
	int flag = get_session_fail_flag();

	switch (flag) {
		case SESSION_FAIL__SEND_INFORM:
			if (type == SOAP_TYPE_cwmp__Inform)
				return 1;
			break;
		case SESSION_FAIL__SEND_DOWN_RESP:
			if (type == SOAP_TYPE_cwmp__DownloadResponse)
				return 1;
			break;
		case SESSION_FAIL__SEND_TRANS_COMP:
			if (type == SOAP_TYPE_cwmp__TransferComplete)
				return 1;
			break;
		case SESSION_FAIL__SEND_AUTO_TRANS_COMP:
			if (type == 1011)
				return 1;
			break;
		case SESSION_FAIL__SEND_EMPTY:
			if (type == SOAP_TYPE_cwmp__Empty)
				return 1;
			break;
		case SESSION_FAIL__SEND_GET_PARAM_VAL_RESP:
			if (type == SOAP_TYPE_cwmp__GetParameterValuesResponse)
				return 1;
			break;
		case SESSION_FAIL__SEND_SET_PARAM_VAL_RESP:
			if (type == SOAP_TYPE_cwmp__SetParameterValuesResponse)
				return 1;
			break;
		case SESSION_FAIL__SEND_ADD_OBJ_RESP:
			if (type == SOAP_TYPE_cwmp__AddObjectResponse)
				return 1;
			break;
		case SESSION_FAIL__SEND_DEL_OBJ_RESP:
			if (type == SOAP_TYPE_cwmp__DeleteObjectResponse)
				return 1;
			break;
		default:
			break;
	}

	return 0;
}
#endif	//__DV_CWMP_SESSION_TEST__

/***********************************************************************/
/* Utility functions. */
/***********************************************************************/
struct cwmp_userdata *cwmp_init_userdata(void)
{
	char buf[256 + 1];
	unsigned int ch;
	unsigned int uVal;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	struct cwmp_userdata *data = malloc(sizeof(struct cwmp_userdata));
	if (data) {
		int srcPort = 0;
		memset(data, 0, sizeof(struct cwmp_userdata));
		
		//srcPort = init_udp_process(&data->MappedAddr, &data->MappedPort, &data->stunfd);
		//data->STUNEnable = srcPort == 0 ? 0 : 1;
		data->STUNEnable = 0;

		data->HPPeriod = ((uVal = atoi(nvram_safe_get_r("ipdm_hp_period", buf, 16))) > 0) ? uVal : 30;
		if (data->HPPeriod == 0)
			data->HPPeriod = 30;
		data->HPRange = data->HPPeriod;
		set_cwmp_timer(data, HOLEPUNCH_TIMER, data->HPRange, FROM_NOW);

		nvram_safe_get_r("cwmp_stun_max_period", buf, 16);
		data->STUNMaxPeriod = buf[0] == 0 ? 3600 : atoi(buf);
		nvram_safe_get_r("cwmp_stun_min_period", buf, 16);
		data->STUNMinPeriod = buf[0] == 0 ? 3600 : atoi(buf);
		data->HP_TTL = (uVal = atoi(nvram_safe_get_r("ipdm_hp_ttl", buf, 16))) > 0 ? uVal : 3;
		if (data->HP_TTL == 0)
			data->HP_TTL = 3;

		data->STUNPeriod = get_stun_min_period(data); //APACRTL-414
		set_cwmp_timer(data, STUN_TIMER, data->STUNPeriod, FROM_NOW);

		//relative to SOAP header
		data->ID = 1;
		data->HoldRequests = 0;
		data->NoMoreRequests = 0;
		data->CPE_MaxEnvelopes = 1;
		data->ACS_MaxEnvelopes = 1;

		//cwmp:fault
		data->FaultCode = 0;

		//others
		data->RB_CommandKey = cwmp_cfg_get(CWMP_RB_COMMANDKEY, buf, sizeof(buf)) ? strdup(buf) : NULL;
		data->Reboot = 0;
		data->FactoryReset = 0;

		//download
		data->DownloadState = DOWNLD_NONE;
		data->DownloadWay = DLWAY_NONE;
		data->DLCommandKey = cwmp_cfg_get(CWMP_DL_COMMANDKEY, buf, sizeof(buf)) ? strdup(buf) : NULL;
		data->DLStartTime = cwmp_cfg_get(CWMP_DL_STARTTIME, &uVal, sizeof(uVal)) ? uVal : 0;
		data->DLCompleteTime = cwmp_cfg_get(CWMP_DL_COMPLETETIME, &uVal, sizeof(uVal)) ? uVal : 0;
		data->DLFaultCode = 0;

		//inform
		data->EventCode = cwmp_cfg_get(CWMP_INFORM_EVENTCODE, &uVal, sizeof(uVal)) ? uVal : 0;
		data->NotifyParameter = NULL;
		notify_init(data->STUNEnable);

		/* ACS server info */
		data->url1 = cwmp_cfg_get(CWMP_ACS_URL, buf, sizeof(buf)) ? strdup(buf) : "";	/* "http://192.168.2.39:7547" */
		data->url2 = cwmp_cfg_get(CWMP_TRCS_URL, buf, sizeof(buf)) ? strdup(buf) : "";	/* "http://192.168.2.39:7547" */
		data->username = cwmp_cfg_get(CWMP_ACS_USERNAME, buf, sizeof(buf)) ? strdup(buf) : NULL;	/* "user" */
		data->password = cwmp_cfg_get(CWMP_ACS_PASSWORD, buf, sizeof(buf)) ? strdup(buf) : NULL;	/* "pw" */

#ifdef __DV_CWMP_SESSION_TEST__
		test_session_fail__403(data->password);
#endif

		/* CPE server info */
		if (data->STUNEnable)
			data->server_port = srcPort;
		else
			data->server_port = cwmp_cfg_get(CWMP_CPE_SERVER_PORT, &uVal, sizeof(uVal)) ? uVal : 7547;	/* "8547" */
		data->conreq_username = cwmp_cfg_get(CWMP_CONREQ_USERNAME, buf, sizeof(buf)) ? strdup(buf) : NULL;	/* "mv600" */
		data->conreq_password = cwmp_cfg_get(CWMP_CONREQ_PASSWORD, buf, sizeof(buf)) ? strdup(buf) : NULL;	/* "mv600" */
		data->realm = CWMP_HTTP_REALM;

		data->PeriodicInform = cwmp_cfg_get(CWMP_INFORM_ENABLE, &ch, sizeof(ch)) ? ch : 1;
		data->InformInterval = cwmp_cfg_get(CWMP_INFORM_INTERVAL, &uVal, sizeof(uVal)) ? uVal : 60;
		data->InformTime = cwmp_cfg_get(CWMP_INFORM_TIME, &uVal, sizeof(uVal)) ? uVal : 0;
	}
	pUserData = data;
	return data;
}

int cwmp_free_userdata(struct cwmp_userdata *user)
{
	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (user) {
		if (user->DLCommandKey)
			free(user->DLCommandKey);
		cwmp_reset_DownloadInfo(&user->DownloadInfo, user->DownloadWay);

		if (user->RB_CommandKey)
			free(user->RB_CommandKey);
		notify_uninit();
		if (user->NotifyParameter)
			while (pop_node_data(&user->NotifyParameter)) ;	//don't need to free the data returned

		// andrew
		if (user->url1)
			free(user->url1);
		if (user->url2)
			free(user->url2);
		if (user->username)
			free(user->username);
		if (user->password)
			free(user->password);
		if (user->conreq_username)
			free(user->conreq_username);
		if (user->conreq_password)
			free(user->conreq_password);

		free(user);
	}

	return 0;
}

void cwmp_SaveReboot(struct cwmp_userdata *user, int reboot_flag, int apply)
{
	int need_apply = 0;
	char buf[1024] = {0, };
	unsigned int uint_buf = 0;

	if (user) {
		//reboot commandkey
		memset(buf, 0, sizeof(buf));
		cwmp_cfg_get(CWMP_RB_COMMANDKEY, buf, sizeof(buf));
		if (user->RB_CommandKey) {
			if (nv_strcmp(user->RB_CommandKey, buf) != 0) {
				cwmp_cfg_set(CWMP_RB_COMMANDKEY, user->RB_CommandKey, sizeof(user->RB_CommandKey));
				need_apply = 1;
			}
		} else {
			if (STRLEN(buf) > 0) {
				cwmp_cfg_set(CWMP_RB_COMMANDKEY, "", 0);
				need_apply = 1;
			}
		}

		//related to download

		//user->DownloadWay??????
		memset(buf, 0, sizeof(buf));
		cwmp_cfg_get(CWMP_DL_COMMANDKEY, buf, sizeof(buf));
		if (user->DLCommandKey) {
			if (nv_strcmp(user->DLCommandKey, buf) != 0) {
				cwmp_cfg_set(CWMP_DL_COMMANDKEY, user->DLCommandKey, sizeof(user->DLCommandKey));
				need_apply = 1;
			}
		} else {
			if (STRLEN(buf) > 0) {
				cwmp_cfg_set(CWMP_DL_COMMANDKEY, "", 0);
				need_apply = 1;
			}
		}
			
		cwmp_cfg_get(CWMP_DL_STARTTIME, &uint_buf, sizeof(uint_buf));
		if (user->DLStartTime != uint_buf) {
			cwmp_cfg_set(CWMP_DL_STARTTIME, &user->DLStartTime, sizeof(user->DLStartTime));
			need_apply = 1;
		}

		cwmp_cfg_get(CWMP_DL_COMPLETETIME, &uint_buf, sizeof(uint_buf));
		if (user->DLCompleteTime != uint_buf) {
			cwmp_cfg_set(CWMP_DL_COMPLETETIME, &user->DLCompleteTime, sizeof(user->DLCompleteTime));
			need_apply = 1;
		}

		cwmp_cfg_get(CWMP_DL_FAULTCODE, &uint_buf, sizeof(uint_buf));
		if (user->DLFaultCode != uint_buf) {
			cwmp_cfg_set(CWMP_DL_FAULTCODE, &user->DLFaultCode, sizeof(user->DLFaultCode));
			need_apply = 1;
		}
		//inform
		// save unacked events
		user->EventCode |= ((cpe_client.cpe_events | cpe_client.cpe_event_queue) & EC_SAVE_MASK);
		//              cwmp_cfg_set( CWMP_INFORM_EVENTCODE, &user->EventCode, sizeof(&user->EventCode) );
	}

	need_apply += apply;
	
	save2flash_reboot(reboot_flag, need_apply);
	return;
}

void cwmp_reset_DownloadInfo(DownloadInfo_T *dlinfo, int dlway)
{
	CWMPDBG(2, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));

	if (dlinfo) {
		switch (dlway) {
			case DLWAY_UP:
				{
					struct cwmp__Upload *ul = &dlinfo->Upload;
					if (ul->CommandKey)
						free(ul->CommandKey);
					if (ul->FileType)
						free(ul->FileType);
					if (ul->URL)
						free(ul->URL);
					if (ul->Username)
						free(ul->Username);
					if (ul->Password)
						free(ul->Password);
				}
				break;
			case DLWAY_DOWN:
				{
					struct cwmp__Download *dw = &dlinfo->Download;
					if (dw->CommandKey)
						free(dw->CommandKey);
					if (dw->FileType)
						free(dw->FileType);
					if (dw->URL)
						free(dw->URL);
					if (dw->Username)
						free(dw->Username);
					if (dw->Password)
						free(dw->Password);
					if (dw->TargetFileName)
						free(dw->TargetFileName);
					if (dw->SuccessURL)
						free(dw->SuccessURL);
					if (dw->FailureURL)
						free(dw->FailureURL);
				}
				break;
			default:
				break;
		}

		memset(dlinfo, 0, sizeof(DownloadInfo_T));
	}

	return;
}

char *cwmp_ErrorString(int code)
{
	char *s = NULL;

	switch (code) {
		case 9000:
			s = strERR_9000;
			break;
		case 9001:
			s = strERR_9001;
			break;
		case 9002:
			s = strERR_9002;
			break;
		case 9003:
			s = strERR_9003;
			break;
		case 9004:
			s = strERR_9004;
			break;
		case 9005:
			s = strERR_9005;
			break;
		case 9006:
			s = strERR_9006;
			break;
		case 9007:
			s = strERR_9007;
			break;
		case 9008:
			s = strERR_9008;
			break;
		case 9009:
			s = strERR_9009;
			break;
		case 9010:
			s = strERR_9010;
			break;
		case 9011:
			s = strERR_9011;
			break;
		case 9012:
			s = strERR_9012;
			break;
		case 9013:
			s = strERR_9013;
			break;
		case 9014:
			s = strERR_9014;
			break;
		case 9015:
			s = strERR_9015;
			break;
		case 9016:
			s = strERR_9016;
			break;
		case 9017:
			s = strERR_9017;
			break;
		case 9018:
			s = strERR_9018;
			break;
		case 9019:
			s = strERR_9019;
			break;
		case 9801:
			s = strERR_9801;
			break;
		case 9802:
			s = strERR_9802;
			break;
		case 9803:
			s = strERR_9803;
			break;
		case 9804:
			s = strERR_9804;
			break;
		case 9811:
			s = strERR_9811;
			break;
		case 9812:
			s = strERR_9812;
			break;
		case 9813:
			s = strERR_9813;
			break;
		case 9814:
			s = strERR_9814;
			break;
		case 9821:
			s = strERR_9821;
			break;
		default:
			s = strERR_default;
			break;
	}

	return s;
}

void *cwmp_valuedup(struct soap *soap, int type, void *data)
{
	void *new_data = NULL;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (data) {
		switch (type) {
			case SOAP_TYPE_string:
				new_data = soap_strdup(soap, (char *)data);
				break;
			case SOAP_TYPE_int:
			case SOAP_TYPE_xsd__boolean:
				{
					int *num;
					num = soap_malloc(soap, sizeof(int));
					if (num)
						*num = *(int *)data;
					new_data = num;
				}
				break;
			case SOAP_TYPE_unsignedInt:
				{
					unsigned int *num;
					num = soap_malloc(soap, sizeof(unsigned int));
					if (num)
						*num = *(unsigned int *)data;
					new_data = num;
				}
				break;
			case SOAP_TYPE_time:
				{
					time_t *num;
					num = soap_malloc(soap, sizeof(time_t));
					if (num)
						*num = *(time_t *)data;
					new_data = num;
				}
				break;
			//case SOAP_TYPE_xsd__base64: //need data's size value
				//break;
			default:
				CWMPDBG(1, (stderr, "<%s:%d>Unknown type:%d\n", __FUNCTION__, __LINE__, type));
				break;
		}
	}
	return new_data;
}

int get_ParameterNameTotalCount(struct ArrayOfStrings *s)
{
	int err = -1;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (s) {
		int i, count = 0;
		err = 0;

		for (i = 0; i < s->__size; i++) {
			count = get_ParameterNameCount(s->__ptrstring[i], 0);
			if (count < 0) {
				CWMPDBG(4, (stderr, "<<%s %d\n", s->__ptrstring[i], count));
				//err = count;
				continue;
			} else
				err = err + count;
		}
	}
	CWMPDBG(2, (stderr, "<%s:%d>total count=%d,%d\n", __FUNCTION__, __LINE__, s->__size, err));
	return err;
}

int push_SetParameterVaulesFault(struct soap *soap, struct node **node, char *name, int code)
{
	struct cwmp__SetParameterValuesFault *d;
	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	d = soap_malloc(soap, sizeof(struct cwmp__SetParameterValuesFault));
	if (d) {
		soap_default_cwmp__SetParameterValuesFault(soap, d);
		d->ParameterName = soap_strdup(soap, name);
		d->FaultCode = code;

		d->FaultString = cwmp_ErrorString(code);
		if (d->FaultString == NULL) {
			d->FaultString = strERR_9002;
			d->FaultCode = 9002;
		}

		if (push_node_data(node, d) < 0) {
			soap_dealloc(soap, d->ParameterName);
			soap_dealloc(soap, d);
		}
	}
	return SOAP_OK;
}

struct cwmp__SetParameterValuesFault *pop_SetParameterVaulesFault(struct soap *soap, struct node **node)
{
	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	return pop_node_data(node);
}

/***********************************************************************/
/* create reqesut functions. */
/***********************************************************************/
int cwmp_CreateInform(struct soap *soap, int *type, void **data, unsigned int e, char *opt)
{
	struct cwmp_userdata *ud = soap->user;
	struct cwmp__Inform *req;

	CWMPDBG(2, (stderr, "<%s:%d>event:0x%x\n", __FUNCTION__, __LINE__, e));

	req = soap_malloc(soap, sizeof(struct cwmp__Inform));
	soap_default_cwmp__Inform(soap, req);
	*type = SOAP_TYPE_cwmp__Inform;
	*data = req;

	req->MaxEnvelopes = 1;
	req->CurrentTime = time(NULL);
	{
		struct cpe_machine *m = ud->machine;
		if (m)
			req->RetryCount = m->cpe_retry_count;
		else
			req->RetryCount = 0;
	}

	{
		/*set DeviceId */
		int vtype;
		void *vdata = NULL;

		get_ParameterValue("InternetGatewayDevice.DeviceInfo.Manufacturer", &vtype, &vdata);
#ifdef __DV_CWMP_SESSION_TEST__
		test_session_fail__acs_faultcode_inform(vdata);
#endif
		req->DeviceId.Manufacturer = cwmp_valuedup(soap, vtype, vdata);
		if (vdata)
			free(vdata);

		get_ParameterValue("InternetGatewayDevice.DeviceInfo.ManufacturerOUI", &vtype, &vdata);
		req->DeviceId.OUI = cwmp_valuedup(soap, vtype, vdata);
		if (vdata)
			free(vdata);

		/*Works system ACS needs this filed */
		get_ParameterValue("InternetGatewayDevice.DeviceInfo.ProductClass", &vtype, &vdata);
		req->DeviceId.ProductClass = cwmp_valuedup(soap, vtype, vdata);	//this is an optional parameter
		if (vdata)
			free(vdata);

		get_ParameterValue("InternetGatewayDevice.DeviceInfo.SerialNumber", &vtype, &vdata);
		req->DeviceId.SerialNumber = cwmp_valuedup(soap, vtype, vdata);
		if (vdata)
			free(vdata);
	}

	{
		/*set Event */
		int event_size = 0, i = 0;
		unsigned int tmp_e = e;

		while (tmp_e) {
			if (tmp_e & 0x1)
				event_size++;
			tmp_e = tmp_e >> 1;
		}

		if (((e & EC_BOOTSTRAP) == 0) && ((e & EC_BOOT) == 0) && (notify_check_all() > 0)) {
			if ((e & EC_X_PERIODIC_RST) == 0) {
				if ((e & EC_VALUECHANGE) == 0) {
					struct cpe_machine *m = ud->machine;
					m->cpe_events = m->cpe_events | EC_VALUECHANGE;
					e = e | EC_VALUECHANGE;
					event_size++;
				}
			}
		}

		if (event_size == 0) {	//special case if no event (as the previous session terminated unsuccessfully)
			req->Event.__size = 0;
			req->Event.__ptrEventStruct = soap_malloc(soap, sizeof(struct cwmp__EventStruct));
		} else {
			i = 0;
			req->Event.__size = event_size;
			req->Event.__ptrEventStruct = soap_malloc(soap, req->Event.__size * sizeof(struct cwmp__EventStruct));
			if (e & EC_BOOTSTRAP) {
				req->Event.__ptrEventStruct[i].EventCode = soap_strdup(soap, "0 BOOTSTRAP");
				req->Event.__ptrEventStruct[i].CommandKey = soap_strdup(soap, "");
				i++;
			}
			if (e & EC_BOOT) {
				req->Event.__ptrEventStruct[i].EventCode = soap_strdup(soap, "1 BOOT");
				req->Event.__ptrEventStruct[i].CommandKey = soap_strdup(soap, "");
				i++;
			}
			if (e & EC_PERIODIC) {
				req->Event.__ptrEventStruct[i].EventCode = soap_strdup(soap, "2 PERIODIC");
				req->Event.__ptrEventStruct[i].CommandKey = soap_strdup(soap, "");
				i++;
			}
			if (e & EC_SCHEDULED) {
				req->Event.__ptrEventStruct[i].EventCode = soap_strdup(soap, "3 SCHEDULED");
				req->Event.__ptrEventStruct[i].CommandKey = soap_strdup(soap, "");
				i++;
			}
			if (e & EC_VALUECHANGE) {
				req->Event.__ptrEventStruct[i].EventCode = soap_strdup(soap, "4 VALUE CHANGE");
				req->Event.__ptrEventStruct[i].CommandKey = soap_strdup(soap, "");
				i++;
			}
			if (e & EC_KICKED) {
				req->Event.__ptrEventStruct[i].EventCode = soap_strdup(soap, "5 KICKED");
				req->Event.__ptrEventStruct[i].CommandKey = soap_strdup(soap, "");
				i++;
			}
			if (e & EC_CONNREQUEST) {
				req->Event.__ptrEventStruct[i].EventCode = soap_strdup(soap, "6 CONNECTION REQUEST");
				req->Event.__ptrEventStruct[i].CommandKey = soap_strdup(soap, "");
				i++;
			}
			if (e & EC_TRANSFER) {
				req->Event.__ptrEventStruct[i].EventCode = soap_strdup(soap, "7 TRANSFER COMPLETE");
				req->Event.__ptrEventStruct[i].CommandKey = soap_strdup(soap, "");
				i++;
			}
			if (e & EC_AUTOTRANSFER) {	//APACRTL-433
				req->Event.__ptrEventStruct[i].EventCode = soap_strdup(soap, "10 AUTONOMOUS TRANSFER COMPLETE");
				req->Event.__ptrEventStruct[i].CommandKey = soap_strdup(soap, "");
				i++;
			}
			if (e & EC_DIAGNOSTICS) {
				req->Event.__ptrEventStruct[i].EventCode = soap_strdup(soap, "8 DIAGNOSTICS COMPLETE");
				req->Event.__ptrEventStruct[i].CommandKey = soap_strdup(soap, "");
				i++;
			}
			if (e & EC_REQUESTDL) {
				req->Event.__ptrEventStruct[i].EventCode = soap_strdup(soap, "9 REQUEST DOWNLOAD");
				req->Event.__ptrEventStruct[i].CommandKey = soap_strdup(soap, "");
				i++;
			}
			if (e & EC_M_REBOOT) {
				req->Event.__ptrEventStruct[i].EventCode = soap_strdup(soap, "M Reboot");
				req->Event.__ptrEventStruct[i].CommandKey =
					ud->RB_CommandKey ? soap_strdup(soap, ud->RB_CommandKey) : soap_strdup(soap, "");
				i++;
			}
			if (e & EC_M_SCHEDULED) {
				req->Event.__ptrEventStruct[i].EventCode = soap_strdup(soap, "M ScheduleInform");
				req->Event.__ptrEventStruct[i].CommandKey = soap_strdup(soap, "");
				i++;
			}

			req->Event.__size = i;
		}
	}

	{
		/*set ParameterList */
		int Ncount = 0, i = 0, j;
		struct CWMP_NOTIFY *c;
		void *vdata;
		int vtype;

		notify_create_update_info(&ud->NotifyParameter);
		Ncount = get_node_count(ud->NotifyParameter);
		if (ud->STUNEnable)
			Ncount -= 1;	//Do not inform UDPConnectionRequestAddress (Check notification inform list)

		req->ParameterList.__size = Ncount + 9;
		if (ud->STUNEnable)
			req->ParameterList.__size += 1;
		req->ParameterList.__ptrParameterValueStruct =
			soap_malloc(soap, req->ParameterList.__size * sizeof(struct cwmp__ParameterValueStruct));

		req->ParameterList.__ptrParameterValueStruct[i].Name = soap_strdup(soap, "InternetGatewayDevice.DeviceSummary");
		get_ParameterValue("InternetGatewayDevice.DeviceSummary", &vtype, &vdata);
		req->ParameterList.__ptrParameterValueStruct[i].__type = vtype;
		req->ParameterList.__ptrParameterValueStruct[i++].Value = cwmp_valuedup(soap, vtype, vdata);
		if (vdata)
			free(vdata);

		req->ParameterList.__ptrParameterValueStruct[i].Name =
			soap_strdup(soap, "InternetGatewayDevice.DeviceInfo.ModelName");
		get_ParameterValue("InternetGatewayDevice.DeviceInfo.ModelName", &vtype, &vdata);
		req->ParameterList.__ptrParameterValueStruct[i].__type = vtype;
		req->ParameterList.__ptrParameterValueStruct[i++].Value = cwmp_valuedup(soap, vtype, vdata);
		if (vdata)
			free(vdata);

		req->ParameterList.__ptrParameterValueStruct[i].Name =
			soap_strdup(soap, "InternetGatewayDevice.DeviceInfo.HardwareVersion");
		get_ParameterValue("InternetGatewayDevice.DeviceInfo.HardwareVersion", &vtype, &vdata);
		req->ParameterList.__ptrParameterValueStruct[i].__type = vtype;
		req->ParameterList.__ptrParameterValueStruct[i++].Value = cwmp_valuedup(soap, vtype, vdata);
		if (vdata)
			free(vdata);

		req->ParameterList.__ptrParameterValueStruct[i].Name =
			soap_strdup(soap, "InternetGatewayDevice.DeviceInfo.SoftwareVersion");
		get_ParameterValue("InternetGatewayDevice.DeviceInfo.SoftwareVersion", &vtype, &vdata);
		req->ParameterList.__ptrParameterValueStruct[i].__type = vtype;
		req->ParameterList.__ptrParameterValueStruct[i++].Value = cwmp_valuedup(soap, vtype, vdata);
		if (vdata)
			free(vdata);

		req->ParameterList.__ptrParameterValueStruct[i].Name =
			soap_strdup(soap, "InternetGatewayDevice.DeviceInfo.SpecVersion");
		get_ParameterValue("InternetGatewayDevice.DeviceInfo.SpecVersion", &vtype, &vdata);
		req->ParameterList.__ptrParameterValueStruct[i].__type = vtype;
		req->ParameterList.__ptrParameterValueStruct[i++].Value = cwmp_valuedup(soap, vtype, vdata);
		if (vdata)
			free(vdata);

		req->ParameterList.__ptrParameterValueStruct[i].Name =
			soap_strdup(soap, "InternetGatewayDevice.DeviceInfo.ProvisioningCode");
		get_ParameterValue("InternetGatewayDevice.DeviceInfo.ProvisioningCode", &vtype, &vdata);
		req->ParameterList.__ptrParameterValueStruct[i].__type = vtype;
		req->ParameterList.__ptrParameterValueStruct[i++].Value = cwmp_valuedup(soap, vtype, vdata);
		if (vdata)
			free(vdata);

		req->ParameterList.__ptrParameterValueStruct[i].Name =
			soap_strdup(soap, "InternetGatewayDevice.ManagementServer.ParameterKey");
		get_ParameterValue("InternetGatewayDevice.ManagementServer.ParameterKey", &vtype, &vdata);
		req->ParameterList.__ptrParameterValueStruct[i].__type = vtype;
		req->ParameterList.__ptrParameterValueStruct[i++].Value = cwmp_valuedup(soap, vtype, vdata);
		if (vdata)
			free(vdata);

		req->ParameterList.__ptrParameterValueStruct[i].Name =
			soap_strdup(soap, "InternetGatewayDevice.ManagementServer.ConnectionRequestURL");
		get_ParameterValue("InternetGatewayDevice.ManagementServer.ConnectionRequestURL", &vtype, &vdata);
		req->ParameterList.__ptrParameterValueStruct[i].__type = vtype;
		req->ParameterList.__ptrParameterValueStruct[i++].Value = cwmp_valuedup(soap, vtype, vdata);
		if (vdata)
			free(vdata);

		req->ParameterList.__ptrParameterValueStruct[i].Name =
			soap_strdup(soap, "InternetGatewayDevice.ManagementServer.STUNEnable");
		get_ParameterValue("InternetGatewayDevice.ManagementServer.STUNEnable", &vtype, &vdata);
		req->ParameterList.__ptrParameterValueStruct[i].__type = vtype;
		req->ParameterList.__ptrParameterValueStruct[i++].Value = cwmp_valuedup(soap, vtype, vdata);
		if (vdata)
			free(vdata);

		if (ud->STUNEnable) {
			req->ParameterList.__ptrParameterValueStruct[i].Name =
				soap_strdup(soap, "InternetGatewayDevice.ManagementServer.UDPConnectionRequestAddress");
			get_ParameterValue("InternetGatewayDevice.ManagementServer.UDPConnectionRequestAddress", &vtype,
					&vdata);
			req->ParameterList.__ptrParameterValueStruct[i].__type = vtype;
			req->ParameterList.__ptrParameterValueStruct[i++].Value = cwmp_valuedup(soap, vtype, vdata);
			if (vdata)
				free(vdata);
		}

		for (j = 1; j <= Ncount; j++) {	//Do not inform UDPConnectionRequestAddress
			if (ud->STUNEnable)
				c = get_node_data(ud->NotifyParameter, j);
			else
				c = get_node_data(ud->NotifyParameter, j - 1);

			if (c) {
				req->ParameterList.__ptrParameterValueStruct[i].Name = soap_strdup(soap, c->name);
				req->ParameterList.__ptrParameterValueStruct[i].__type = c->type;
				req->ParameterList.__ptrParameterValueStruct[i++].Value =
					cwmp_valuedup(soap, c->type, c->value);
			}
		}
	}

	cwmp_header_init(soap);

	return SOAP_OK;
}

int cwmp_CreateTransferComplete(struct soap *soap, int *type, void **data)
{
	struct cwmp_userdata *ud = soap->user;
	struct cwmp__TransferComplete *req;
	char *s = NULL;

	CWMPDBG(2, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));

	req = soap_malloc(soap, sizeof(struct cwmp__TransferComplete));
	soap_default_cwmp__TransferComplete(soap, req);
	*type = SOAP_TYPE_cwmp__TransferComplete;
	*data = req;

	if (ud->DLCommandKey)
		req->CommandKey = soap_strdup(soap, ud->DLCommandKey);
	else
		req->CommandKey = soap_strdup(soap, "");

	req->FaultStruct.FaultCode = ud->DLFaultCode;
	if (!nv_strcmp(req->CommandKey, "cmdk_dnld_cfg")) {
		if (ud->DLFaultCode == 0)
			set_prov_stat(ud, CFG_DOWN_IN_PROGRESS);
		else if (ud->DLFaultCode == -(ERR_9804))	//err config parsing
			set_prov_stat(ud, CFG_DOWN_PARSE_ERR);
		} else {
			set_prov_stat(ud, CFG_DOWN_ERR);
	}

	if (ud->DLFaultCode != 0)
		s = cwmp_ErrorString(ud->DLFaultCode);
	if (s == NULL)
		s = "";

#ifdef __DV_CWMP_SESSION_TEST__
	char test_buf[8] = "";
	test_session_fail__acs_faultcode_trans_comp(test_buf, sizeof(test_buf));
	s = test_buf;
#endif

	req->FaultStruct.FaultString = soap_strdup(soap, s);

	req->StartTime = ud->DLStartTime;
	req->CompleteTime = ud->DLCompleteTime;

	CWMPDBG(2, (stderr, "[%s] FaultCode=>%d Start Time=>%u EndTime=%u\n",
	        __FUNCTION__, req->FaultStruct.FaultCode,
	        (unsigned int)req->StartTime, (unsigned int)req->CompleteTime));

	cwmp_header_init(soap);

	return SOAP_OK;
}

int cwmp_CreateAutonomousTransferComplete(struct soap *soap, int *Type, void **data)
{
	struct cwmp_userdata *ud = soap->user;
	char *s = NULL;
	struct AutoTransferComplete *req;
	int is_AP_SW = 1;

	CWMPDBG(2, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));

	req = soap_malloc(soap, sizeof(struct AutoTransferComplete));
	soap_default_string(soap, &req->TransferURL);
	soap_default_string(soap, &req->TargetFileName);
	soap_default_cwmp__FaultStruct(soap, &req->FaultStruct);
	soap_default_time(soap, &req->StartTime);
	soap_default_time(soap, &req->CompleteTime);
	soap->omode &= ~SOAP_IO_CHUNK; //TR-069 ACS is not accept "HTTP chunk".
	*Type = 1011;
	*data = req;

	memset(req, 0, sizeof(struct AutoTransferComplete));
	is_AP_SW = access("/var/tmp/autoupgrade/dn_iot_resp", F_OK) == 0 ? 0 : 1;
	if (is_AP_SW) {
		TLOG_PRINT("Reporting result(Downloading AP Firmware)\n");
#if 0
		nvram_unset("cwmp_img_down_fail");
		nvram_commit();
#endif
		if (ud->DLFaultCode != 0)
			req->isDownload = 0;
		else
			req->isDownload = 1;
		req->TransferURL = soap_strdup(soap, ud->DownloadInfo.Download.URL);
		req->TargetFileName = soap_strdup(soap, ud->DownloadInfo.Download.TargetFileName);
		if (ud->DownloadInfo.Download.FileType)
			req->FileType = soap_strdup(soap, ud->DownloadInfo.Download.FileType);
		req->FileSize = ud->DownloadInfo.Download.FileSize;

		req->FaultStruct.FaultCode = ud->DLFaultCode;
		if (ud->DLFaultCode != 0)
			s = cwmp_ErrorString(ud->DLFaultCode);
		if (s == NULL)
			s = "";

#ifdef __DV_CWMP_SESSION_TEST__
		char test_buf[8] = "";
		test_session_fail__acs_faultcode_auto_trans_comp(test_buf, sizeof(test_buf));
		s = test_buf;
#endif

		req->FaultStruct.FaultString = soap_strdup(soap, s);

		req->StartTime = ud->DLStartTime;
		req->CompleteTime = ud->DLCompleteTime;
	}

	cwmp_header_init(soap);
	return SOAP_OK;
}

int cwmp_CreateGetRPCMethods(struct soap *soap, int *type, void **data)
{
	struct cwmp__GetRPCMethods *req;

	req = soap_malloc(soap, sizeof(struct cwmp__GetRPCMethods));
	*type = SOAP_TYPE_cwmp__GetRPCMethods;
	*data = req;
	soap_default_cwmp__GetRPCMethods(soap, req);

	cwmp_header_init(soap);

	return SOAP_OK;
}

/***********************************************************************/
/* cb fun. */
/***********************************************************************/
int cwmp_InformResponse(struct soap *soap, struct cwmp__InformResponse *Resp, int *type, void **data)
{
	struct cwmp_userdata *ud = soap->user;

	CWMPDBG(1, (stderr, "<%s:%d>Got Response\n", __FUNCTION__, __LINE__));

	//APACRTL-526
	if (ud)
		ud->FaultCode = 0;

	if (Resp) {
		struct cwmp_userdata *ud = soap->user;
		ud->ACS_MaxEnvelopes = Resp->MaxEnvelopes;
	}
	//reset eventcode
	if (ud->EventCode) {
		ud->EventCode = 0;
		if (ud->RB_CommandKey) {
			free(ud->RB_CommandKey);
			ud->RB_CommandKey = NULL;
		}
		cwmp_SaveReboot(ud, 0, 0);	//APACRTL-483 : Forbid unnecessary nvram_commit().
	}
	//clear the parameterlist
	if (ud->NotifyParameter)
		while (pop_node_data(&ud->NotifyParameter)) ;

	*type = SOAP_TYPE_cwmp__EmptyResponse;
	*data = NULL;

	return SOAP_OK;
}

int cwmp_TransferCompleteResponse(struct soap *soap, struct cwmp__TransferCompleteResponse *Resp, int *type, void **data)
{
	struct cwmp_userdata *ud = soap->user;

	CWMPDBG(1, (stderr, "<%s:%d>Got Response\n", __FUNCTION__, __LINE__));

	//reset download variables
#if 1
	cwmp_reset_DownloadInfo(&ud->DownloadInfo, ud->DownloadWay);
	ud->DownloadWay = DLWAY_NONE;
	if (ud->DLCommandKey) {
		free(ud->DLCommandKey);
		ud->DLCommandKey = NULL;
	}
#else
	cwmp_reset_download(&ud->Download);
#endif
	ud->DownloadState = DOWNLD_NONE;
	ud->DLStartTime = 0;
	ud->DLCompleteTime = 0;
	ud->DLFaultCode = 0;
	cwmp_SaveReboot(ud, 0, 0);	//APACRTL-483 : Forbid unnecessary nvram_commit().

	*type = SOAP_TYPE_cwmp__Empty;
	*data = NULL;
	return SOAP_OK;
}

int cwmp_GetRPCMethodsResponse(struct soap *soap, struct cwmp__GetRPCMethodsResponse *resp, int *type, void **data)
{
	int i;

	CWMPDBG(1, (stderr, "<%s:%d>Got Response\n", __FUNCTION__, __LINE__));

	for (i = 0; i < resp->MethodList.__size; i++) {
		CWMPDBG(0, (stderr, "\t %s\n", resp->MethodList.__ptrstring[i]));
	}

	*type = SOAP_TYPE_cwmp__Empty;
	*data = NULL;

	return SOAP_OK;
}

int cwmp_GetParameterValues(struct soap *soap, struct cwmp__GetParameterValues *req, int *type, void **data)
{
	struct cwmp__GetParameterValuesResponse *resp;
	int i, j;
	int count = 0;
	char *name;

	CWMPDBG(3, (stderr, "<%s:%d>Got Request\n", __FUNCTION__, __LINE__));

	//handle
	count = get_ParameterNameTotalCount(&req->ParameterNames);
	if (count < 0) {
		cwmp_set_fault(soap, 9005, NULL);
		*type = SOAP_TYPE_SOAP_ENV__Fault;
		*data = NULL;
		return SOAP_OK;
	}

	//response
	resp = soap_malloc(soap, sizeof(struct cwmp__GetParameterValuesResponse));
	soap_default_cwmp__GetParameterValuesResponse(soap, resp);

	*type = SOAP_TYPE_cwmp__GetParameterValuesResponse;
	*data = resp;

	if (count > 0) {
		resp->ParameterList.__size = count;
		resp->ParameterList.__ptrParameterValueStruct =
			soap_malloc(soap, resp->ParameterList.__size * sizeof(struct cwmp__ParameterValueStruct));

		CWMPDBG(3, (stderr, "\tafter soap_malloc:fail? %d\n", resp->ParameterList.__ptrParameterValueStruct == NULL));
		if (resp->ParameterList.__ptrParameterValueStruct == NULL) {
			soap_dealloc(soap, resp);
			cwmp_set_fault(soap, 9004, NULL);
			*type = SOAP_TYPE_SOAP_ENV__Fault;
			*data = NULL;
			return SOAP_OK;
		}

		j = 0;
		for (i = 0; i < req->ParameterNames.__size; i++) {
			int res;

			if (req->ParameterNames.__ptrstring[i] == NULL || STRLEN(req->ParameterNames.__ptrstring[i]) == 0)
				res = get_ParameterName("", 0, &name);
			else
				res = get_ParameterName(req->ParameterNames.__ptrstring[i], 0, &name);

			if (res < 0)
				continue;
			do {
				int t;
				void *d;

				res = get_ParameterValue(name, &t, &d);
				//fprintf(stderr, "%s:%d name=%s(%d)\n",__FUNCTION__, __LINE__, name, res);
				//if (get_ParameterValue( name, &t, &d )== 0)
				if (res == 0) {
					CWMPDBG(2, (stderr, "<%s> ", name));
					switch (t) {
						case eCWMP_tSTRING:
							CWMPDBG(2, (stderr, "<%s>\n", (char *)d));
#ifdef __DV_CWMP_SESSION_TEST__
							test_session_fail__acs_faultcode_get_param_val((char *)d);
#endif
							break;
						case eCWMP_tUINT:
							CWMPDBG(2, (stderr, "<%u>\n", *(unsigned int *)d));
							break;
						case eCWMP_tINT:
							CWMPDBG(2, (stderr, "<%d>\n", *(int *)d));
							break;
						case eCWMP_tDATETIME:
							{
								struct tm *now = localtime((time_t *)d);
								char buf[32];

								strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", now);
								CWMPDBG(2, (stderr, "<%s>\n", buf));
								break;
							}
						default:
							CWMPDBG(2, (stderr, "<%d>\n", *(int *)d));
							break;
					}


					soap_default_cwmp__ParameterValueStruct(soap,
					        &resp->ParameterList.
					        __ptrParameterValueStruct[j]);
					resp->ParameterList.__ptrParameterValueStruct[j].Name = soap_strdup(soap, name);
					resp->ParameterList.__ptrParameterValueStruct[j].__type = t;
					resp->ParameterList.__ptrParameterValueStruct[j].Value = cwmp_valuedup(soap, t, d);
					if (d) {
						if (d == test_addr) {
							fprintf(stderr, "____KANG:test_addr free(%p)!!!\n", test_addr);
							test_addr = 0;
						}
						free(d);
					}
					j++;
				}
				if (name)
					free(name);
			} while (get_ParameterName(NULL, 0, &name) == 0);
		}
		resp->ParameterList.__size = j;
	} else			//count==0
	{
		//show <ParameterList>.....</ParameterList>
		resp->ParameterList.__size = 0;
		resp->ParameterList.__ptrParameterValueStruct = soap_malloc(soap, sizeof(struct cwmp__ParameterValueStruct));
	}

	CWMPDBG(4, (stderr, "cwmp_GetParameterValues done\n"));
	return SOAP_OK;
}

int cwmp_GetRPCMethods(struct soap *soap, struct cwmp__GetRPCMethods *req, int *type, void **data)
{
	struct cwmp__GetRPCMethodsResponse *resp;
	int i;
	char *method_names[] = { "GetRPCMethods",
		"SetParameterValues",
		"GetParameterValues",
		"GetParameterNames",
		"SetParameterAttributes",
		"GetParameterAttributes",
		"AddObject",
		"DeleteObject",
		"Reboot",
		"Download",
		"Upload",
		"FactoryReset"
	};

	CWMPDBG(1, (stderr, "<%s:%d>Got Request\n", __FUNCTION__, __LINE__));

	resp = soap_malloc(soap, sizeof(struct cwmp__GetRPCMethodsResponse));
	soap_default_cwmp__GetRPCMethodsResponse(soap, resp);

	*type = SOAP_TYPE_cwmp__GetRPCMethodsResponse;
	*data = resp;

	resp->MethodList.__size = sizeof(method_names) / sizeof(char *);
	resp->MethodList.__ptrstring = soap_malloc(soap, resp->MethodList.__size * sizeof(char *));

	for (i = 0; i < resp->MethodList.__size; i++) {
		resp->MethodList.__ptrstring[i] = soap_strdup(soap, method_names[i]);
	}

	return SOAP_OK;
}

int cwmp_SetParameterValues(struct soap *soap, struct cwmp__SetParameterValues *req, int *type, void **data)
{
	struct cwmp__SetParameterValuesResponse *resp;
	struct node *pSPVF_root = NULL;
	int i;
	//char  *empty_string="";
	int err = 0;
	int applied = 0;
	struct cwmp_userdata *ud = soap->user;
	struct ParameterValueList *p = &req->ParameterList;

	CWMPDBG(1, (stderr, "<%s:%d>Got Request\n", __FUNCTION__, __LINE__));

	//handle
	for (i = 0; i < p->__size; i++) {
		int ret_err;
		struct cwmp__ParameterValueStruct *v = &p->__ptrParameterValueStruct[i];

		//handle error;
		ret_err = set_ParameterValue(v->Name, v->__type, v->Value);
		if (ret_err < 0) {
			err = 1;
			//add error code to fault list
			push_SetParameterVaulesFault(soap, &pSPVF_root, v->Name, -ret_err);
		} else {
			if (ret_err > 0)
				applied++;	//parameter changed, but had not applied
			//update the value in the notifylist
			notify_update_value(v->Name);
		}
	}

	//response
	if (err)		//error
	{
		cwmp_set_fault(soap, 9003, NULL);
		if (pSPVF_root != NULL)
			cwmp_set_SetParameterValuesFault(soap, &pSPVF_root);
		*type = SOAP_TYPE_SOAP_ENV__Fault;
		*data = NULL;
	} else {
		// set if and only if success
		MgmtSrvSetParamKey(req->ParameterKey);

		resp = soap_malloc(soap, sizeof(struct cwmp__SetParameterValuesResponse));
		soap_default_cwmp__SetParameterValuesResponse(soap, resp);
		*type = SOAP_TYPE_cwmp__SetParameterValuesResponse;
		*data = resp;
		resp->Status = 0;
		if (applied)
			ud->Restart = applied;
		else
			ud->Restart = 0;

		cwmp_SaveReboot(ud, 0, 0);	//APACRTL-483 : Forbid unnecessary nvram_commit().
	}
	return SOAP_OK;
}

int cwmp_GetParameterNames(struct soap *soap, struct cwmp__GetParameterNames *req, int *type, void **data)
{
	struct cwmp__GetParameterNamesResponse *resp;
	int i, count;
	char *name = NULL;

	CWMPDBG(1, (stderr, "<%s:%d>Got Request\n", __FUNCTION__, __LINE__));

	//try get the parameter entry and count all parameters
	count = get_ParameterNameCount(req->ParameterPath, req->NextLevel);
	//if count==0, return zero entity, not error 9005;
	if (count < 0)		//error
	{
		cwmp_set_fault(soap, 9005, NULL);
		*type = SOAP_TYPE_SOAP_ENV__Fault;
		*data = NULL;
		return SOAP_OK;
	}
	//response
	resp = soap_malloc(soap, sizeof(struct cwmp__GetParameterNamesResponse));
	soap_default_cwmp__GetParameterNamesResponse(soap, resp);
	*type = SOAP_TYPE_cwmp__GetParameterNamesResponse;
	*data = resp;

	if (count > 0) {
		resp->ParameterList.__size = count;
		resp->ParameterList.__ptrParameterInfoStruct =
			soap_malloc(soap, resp->ParameterList.__size * sizeof(struct cwmp__ParameterInfoStruct));
		if (resp->ParameterList.__ptrParameterInfoStruct == NULL) {
			soap_dealloc(soap, resp);
			cwmp_set_fault(soap, 9004, NULL);
			*type = SOAP_TYPE_SOAP_ENV__Fault;
			*data = NULL;
			return SOAP_OK;
		}

		if ((req->ParameterPath == NULL) || (STRLEN(req->ParameterPath) == 0))
			get_ParameterName("", req->NextLevel, &name);
		else
			get_ParameterName(req->ParameterPath, req->NextLevel, &name);

		i = 0;
		do {
			int iswritable;
			//fprintf( stderr, "Got %s:%d:name=%s \n", __FUNCTION__,__LINE__,name);
			resp->ParameterList.__ptrParameterInfoStruct[i].Name = soap_strdup(soap, name);
			get_ParameterIsWritable(name, &iswritable);
			resp->ParameterList.__ptrParameterInfoStruct[i].Writable = iswritable;
			free(name);	//name is allocated by "malloc", not "soap_malloc"
			i++;
			if (i == count)
				break;
		} while (get_ParameterName(NULL, req->NextLevel, &name) == 0);

		resp->ParameterList.__size = i;

	} else {		//( count ==0 )
		//show <ParameterList>.....</ParameterList>
		resp->ParameterList.__size = 0;
		resp->ParameterList.__ptrParameterInfoStruct = soap_malloc(soap, sizeof(struct cwmp__ParameterInfoStruct));
	}

	return SOAP_OK;
}

int cwmp_SetParameterAttributes(struct soap *soap, struct cwmp__SetParameterAttributes *req, int *type, void **data)
{
	struct cwmp__SetParameterAttributesResponse *resp;
	int i;
	int err = 0;
	struct cwmp_userdata *ud = soap->user;

	CWMPDBG(1, (stderr, "<%s:%d>Got Request\n", __FUNCTION__, __LINE__));

	//handle
	//check all arguments of SetParameterAttributes request
	for (i = 0; i < req->ParameterList.__size; i++) {
		char *name;
		int ret_err;
		struct cwmp__SetParameterAttributesStruct *s = &req->ParameterList.__ptrSetParameterAttributesStruct[i];
		if (s->Name == NULL || STRLEN(s->Name) == 0)
			ret_err = get_ParameterName("", 0, &name);
		else
			ret_err = get_ParameterName(s->Name, 0, &name);

		if (ret_err) {
			err = ERR_9005;
			break;
		}

		do {
			struct sCWMP_ENTITY *p = NULL;

			//not set object's attributes
			get_ParameterEntity(name, &p);
			if ((p != NULL) && (p->type != eCWMP_tOBJECT)) {
				if (s->NotificationChange) {
					if (s->Notification < 0 || s->Notification > 2)	//0:off, 1:passive, 2:active
						err = ERR_9003;

					//some parameters can't be set to active notification
					if ((p->flag & CWMP_DENY_ACT) && (s->Notification == 2))
						err = ERR_9009;
				}
			}
			free(name);
			if (err)
				break;	//error occurs
		} while (get_ParameterName(NULL, 0, &name) == 0);

		if (err)
			break;	//error occurs
	}
	if (err < 0) {
		cwmp_set_fault(soap, -err, NULL);
		*type = SOAP_TYPE_SOAP_ENV__Fault;
		*data = NULL;
		return SOAP_OK;
	}

	//really set the parameterAttributes
	for (i = 0; i < req->ParameterList.__size; i++) {
		char *name;
		int ret_err;
		struct cwmp__SetParameterAttributesStruct *s = &req->ParameterList.__ptrSetParameterAttributesStruct[i];
		if (s->Name == NULL || STRLEN(s->Name) == 0)
			ret_err = get_ParameterName("", 0, &name);
		else
			ret_err = get_ParameterName(s->Name, 0, &name);

		if (ret_err)	//this should not happen because we had checked arguments above
		{
			err = -1;	//ERR_9005
			continue;
		}

		do {
			struct sCWMP_ENTITY *p = NULL;
			unsigned int notify_mode = CWMP_NTF_MASK;
			unsigned int access_list = CWMP_ACS_MASK;

			//not set object's attributes
			get_ParameterEntity(name, &p);
			if ((p != NULL) && (p->type != eCWMP_tOBJECT)) {
				if (s->NotificationChange) {
					if (s->Notification >= 0 && s->Notification <= 2)	//0:off, 1:passive, 2:active
						notify_mode = s->Notification;
				}

				if (s->AccessListChange) {
					int i;
					int found = 0;
					//only one type supports, "Subscriber"
					for (i = 0; i < s->AccessList.__size; i++) {
						if (s->AccessList.__ptrstring &&
								s->AccessList.__ptrstring[i] &&
								nv_strcmp(s->AccessList.__ptrstring[i], "Subscriber") == 0) {
							found = 1;
							break;
						}
					}
					if (found)
						access_list = CWMP_ACS_SUB;
					else
						access_list = CWMP_ACS_OFF;
				}
				//update
				notify_update(name, notify_mode, access_list);
			}
			free(name);
		} while (get_ParameterName(NULL, 0, &name) == 0);
	}

	//response
	if (err) {
		cwmp_set_fault(soap, 9005, NULL);
		*type = SOAP_TYPE_SOAP_ENV__Fault;
		*data = NULL;
		return SOAP_OK;
	} else {
		resp = soap_malloc(soap, sizeof(struct cwmp__SetParameterAttributesResponse));
		soap_default_cwmp__SetParameterAttributesResponse(soap, resp);
		*type = SOAP_TYPE_cwmp__SetParameterAttributesResponse;
		*data = resp;

		//how to save a notification file
		notify_save(1);
		cwmp_SaveReboot(ud, 0, 0);	//APACRTL-483 : Forbid unnecessary nvram_commit().
	}

	return SOAP_OK;
}

int cwmp_GetParameterAttributes(struct soap *soap, struct cwmp__GetParameterAttributes *req, int *type, void **data)
{
	struct cwmp__GetParameterAttributesResponse *resp;
	char *name;
	int i, j;
	int count;

	CWMPDBG(1, (stderr, "<%s:%d>Got Request\n", __FUNCTION__, __LINE__));

	//handle
	count = get_ParameterNameTotalCount(&req->ParameterNames);
	CWMPDBG(7, (stderr, "<%s:%d>total count=%d\n", __FUNCTION__, __LINE__, count));
	if (count < 0) {
		cwmp_set_fault(soap, 9005, NULL);
		*type = SOAP_TYPE_SOAP_ENV__Fault;
		*data = NULL;
		return SOAP_OK;
	}
	//response
	resp = soap_malloc(soap, sizeof(struct cwmp__GetParameterAttributesResponse));
	soap_default_cwmp__GetParameterAttributesResponse(soap, resp);
	*type = SOAP_TYPE_cwmp__GetParameterAttributesResponse;
	*data = resp;

	if (count > 0) {
		resp->ParameterList.__size = count;
		resp->ParameterList.__ptrParameterAttributeStruct =
			soap_malloc(soap, resp->ParameterList.__size * sizeof(struct cwmp__ParameterAttributeStruct));
		if (resp->ParameterList.__ptrParameterAttributeStruct == NULL) {
			soap_dealloc(soap, resp);
			cwmp_set_fault(soap, 9004, NULL);
			*type = SOAP_TYPE_SOAP_ENV__Fault;
			*data = NULL;
			return SOAP_OK;
		}

		j = 0;
		for (i = 0; i < req->ParameterNames.__size; i++) {
			if (req->ParameterNames.__ptrstring[i] == NULL || STRLEN(req->ParameterNames.__ptrstring[i]) == 0)
				get_ParameterName("", 0, &name);
			else
				get_ParameterName(req->ParameterNames.__ptrstring[i], 0, &name);

			do {
				struct sCWMP_ENTITY *p = NULL;

				//wt-121v8 2.71, the response's name must be a full parameter name, not a partial path.
				get_ParameterEntity(name, &p);
				if ((p != NULL) && (p->type != eCWMP_tOBJECT)) {
					int notify = 0;
					unsigned int al = 0;

					get_ParameterNotification(name, &notify);
					get_ParameterAccessList(name, &al);
					soap_default_cwmp__ParameterAttributeStruct(soap,
							&resp->ParameterList.
							__ptrParameterAttributeStruct[j]);
					resp->ParameterList.__ptrParameterAttributeStruct[j].Name = soap_strdup(soap, name);
					resp->ParameterList.__ptrParameterAttributeStruct[j].Notification = notify;

					{
						struct ArrayOfStrings *s =
							&resp->ParameterList.__ptrParameterAttributeStruct[j].AccessList;

						//fprintf( stderr, "al: %s\n", al);
						if (al & CWMP_ACS_SUB) {
							s->__size = 1;
							s->__ptrstring = soap_malloc(soap, sizeof(char *) * s->__size);
							s->__ptrstring[0] = soap_strdup(soap, "Subscriber");
							//free(al);
						} else {
							s->__size = 0;
							s->__ptrstring = soap_malloc(soap, sizeof(char *));
							s->__ptrstring[0] = soap_strdup(soap, "");
						}
					}

					j++;
				}

				if (name)
					free(name);
				if (j >= count)
					break;
			} while (get_ParameterName(NULL, 0, &name) == 0);

			if (j >= count)
				break;
		}
		resp->ParameterList.__size = j;
	} else {		//( count ==0 )
		//show <ParameterList>.....</ParameterList>
		resp->ParameterList.__size = 0;
		resp->ParameterList.__ptrParameterAttributeStruct =
			soap_malloc(soap, sizeof(struct cwmp__ParameterAttributeStruct));
	}
	return SOAP_OK;
}

int cwmp_AddObject(struct soap *soap, struct cwmp__AddObject *req, int *type, void **data)
{
	struct cwmp__AddObjectResponse *resp;
	int err;
	int num;
	//char  *empty_string="";
	struct cwmp_userdata *ud = soap->user;

	CWMPDBG(1, (stderr, "<%s:%d>Got Request\n", __FUNCTION__, __LINE__));
	//handle
	err = add_ParameterObject(req->ObjectName, (unsigned int *)&num);
	if (err < 0) {
		if (err == -1)
			cwmp_set_fault(soap, 9002, NULL);
		else		//should be ERR_9XXX
			cwmp_set_fault(soap, -err, NULL);
		*type = SOAP_TYPE_SOAP_ENV__Fault;
		*data = NULL;
		return SOAP_OK;
	} else {
		// set if only if success
		MgmtSrvSetParamKey(req->ParameterKey);

		resp = soap_malloc(soap, sizeof(struct cwmp__AddObjectResponse));
		soap_default_cwmp__AddObjectResponse(soap, resp);
		*type = SOAP_TYPE_cwmp__AddObjectResponse;
		*data = resp;

		resp->InstanceNumber = num;
		if (err == 0)
			resp->Status = 0;
		else {
			resp->Status = 1;
#ifdef SELF_REBOOT
			ud->Reboot = 1;
#endif
		}

		cwmp_SaveReboot(ud, 0, 1);	//APACRTL-483
	}

	return SOAP_OK;
}

int cwmp_DeleteObject(struct soap *soap, struct cwmp__DeleteObject *req, int *type, void **data)
{
	struct cwmp__DeleteObjectResponse *resp;
	int err;
	//char  *empty_string="";
	struct cwmp_userdata *ud = soap->user;

	CWMPDBG(1, (stderr, "<%s:%d>Got Request\n", __FUNCTION__, __LINE__));

	//handle
	err = del_ParameterObject(req->ObjectName);
	if (err < 0) {
		if (err == -1)
			cwmp_set_fault(soap, 9002, NULL);
		else		//should be ERR_9XXX
			cwmp_set_fault(soap, -err, NULL);
		*type = SOAP_TYPE_SOAP_ENV__Fault;
		*data = NULL;
		return SOAP_OK;
	} else {
		//set if and only if success
		MgmtSrvSetParamKey(req->ParameterKey);

		resp = soap_malloc(soap, sizeof(struct cwmp__DeleteObjectResponse));
		soap_default_cwmp__DeleteObjectResponse(soap, resp);

		*type = SOAP_TYPE_cwmp__DeleteObjectResponse;
		*data = resp;

		resp->Status = 0;
		if (err == 0)
			ud->Restart = 0;
		else {
			ud->Restart = 1;
#ifdef SELF_REBOOT
			ud->Reboot = 1;
#endif
		}

		cwmp_SaveReboot(ud, 0, 1);	//APACRTL-483
	}
	return SOAP_OK;
}

int cwmp_Download(struct soap *soap, struct cwmp__Download *req, int *type, void **data)
{
	struct cwmp_userdata *ud = soap->user;
	DownloadInfo_T *dlinfo = &ud->DownloadInfo;
	struct cwmp__Download *dw = &dlinfo->Download;
	struct cwmp__DownloadResponse *resp;
	//int   i;
	//pthread_t pid;

	CWMPDBG(1, (stderr, "<%s:%d>Got Request\n", __FUNCTION__, __LINE__));

	if (ud->DownloadState != DOWNLD_NONE) {
		CWMPDBG(1, (stderr, "The download thread(%s) has been running!\n", __FUNCTION__));
		cwmp_set_fault(soap, 9001, NULL);
		*type = SOAP_TYPE_SOAP_ENV__Fault;
		*data = NULL;
		return SOAP_OK;
	}

	if (req->URL == NULL || (strncmp(req->URL, "http:", 5) && strncmp(req->URL, "https:", 6))) {
		cwmp_set_fault(soap, 9013, NULL);
		*type = SOAP_TYPE_SOAP_ENV__Fault;
		*data = NULL;
		return SOAP_OK;
	}
	//save cwmp_download structure for later processing dowload
	cwmp_reset_DownloadInfo(dlinfo, DLWAY_NONE);	//or user->DownloadWay
	if (req->CommandKey)
		dw->CommandKey = strdup(req->CommandKey);
	if (req->FileType)
		dw->FileType = strdup(req->FileType);
	if (req->URL)
		dw->URL = strdup(req->URL);
	if (req->Username)
		dw->Username = strdup(req->Username);
	if (req->Password)
		dw->Password = strdup(req->Password);
	dw->FileSize = req->FileSize;
	if (req->TargetFileName)
		dw->TargetFileName = strdup(req->TargetFileName);
	dw->DelaySeconds = req->DelaySeconds;
	if (req->SuccessURL)
		dw->SuccessURL = strdup(req->SuccessURL);
	if (req->FailureURL)
		dw->FailureURL = strdup(req->FailureURL);

	ud->DownloadWay = DLWAY_DOWN;
	ud->DownloadState = DOWNLD_READY;
	ud->fDownloadImage = DOWN_IMG_VER_CHECK;

	//response
	resp = soap_malloc(soap, sizeof(struct cwmp__DownloadResponse));
	soap_default_cwmp__DownloadResponse(soap, resp);
	resp->Status = 1;

	*type = SOAP_TYPE_cwmp__DownloadResponse;
	*data = resp;

	return SOAP_OK;
}

int cwmp_Reboot(struct soap *soap, struct cwmp__Reboot *req, int *type, void **data)
{
	struct cwmp_userdata *ud = soap->user;
	struct cwmp__RebootResponse *resp;
	//int   i;

	CWMPDBG(1, (stderr, "<%s:%d>Got Request\n", __FUNCTION__, __LINE__));

	//handle
	if (ud->RB_CommandKey)
		free(ud->RB_CommandKey);
	ud->RB_CommandKey = NULL;
	if (req->CommandKey)
		ud->RB_CommandKey = strdup(req->CommandKey);
	else
		ud->RB_CommandKey = strdup("");
	ud->EventCode |= EC_M_REBOOT;
	ud->Reboot = 1;
#ifdef TMP_WARM_CHANGE
	nvram_set("reset_log", "10");
	nvram_commit();
	syslog(LOG_INFO, DVLOG_MARK_ADMIN "Warm Start : " H_TR069_RESET);
#else
	nvram_set("reset_log", "2");	//APACRTL-464
	nvram_commit();
#endif

	//response
	resp = soap_malloc(soap, sizeof(struct cwmp__RebootResponse));
	soap_default_cwmp__RebootResponse(soap, resp);
	*type = SOAP_TYPE_cwmp__RebootResponse;
	*data = resp;

	return SOAP_OK;
}

int cwmp_ImageDownload(struct cpe_machine *m)
{
	struct cwmp_userdata *ud = m->cpe_user;
	DownloadInfo_T *dlinfo = &ud->DownloadInfo;
	struct cwmp__Download *dw = &dlinfo->Download;
	char buf[128];
	time_t old_img_dl_time = ygettime(NULL);

	if (ud->DownloadState != DOWNLD_NONE) {
		return SOAP_OK;
	}
	cwmp_reset_DownloadInfo(dlinfo, DLWAY_NONE);	//or user->DownloadWay

	nvram_safe_get_r("acs_sw_dir", buf, sizeof(buf));
	if (buf[0] == 0 || (strncmp(buf, "http:", 5) && strncmp(buf, "https:", 6))) {
		return SOAP_OK;
	}

	ud->fDownloadImage = DOWN_IMG_START;
	dw->URL = strdup(buf);

	dw->FileSize = atoi(nvram_safe_get_r("acs_sw_size", buf, sizeof(buf)));

	nvram_safe_get_r("acs_sw_img_name", buf, sizeof(buf));
	if (buf[0])
		dw->TargetFileName = strdup(buf);

	//save cwmp_download structure for later processing dowload
	dw->CommandKey = strdup("cmdk_dnld_img");
	dw->FileType = strdup("fwimage");
	dw->Username = NULL;
	dw->Password = NULL;

	dw->DelaySeconds = 0;
	dw->SuccessURL = NULL;
	dw->FailureURL = NULL;

	ud->DownloadWay = DLWAY_DOWN;
	ud->DownloadState = DOWNLD_READY;

	m->cpe_hold = 1;
#ifdef DV_HEALTH_CHECK 
	yexecl(NULL, "killall healthcheck");
#endif
#ifdef DV_PCHK_RESOURCE
	yexecl(NULL, "killall periodic_chk_resource");
#endif
	cwmpStartDownload(&m->cpe_soap);
	pollInfo.time_limit += ygettime(NULL) - old_img_dl_time + 1;
	//response
	return SOAP_OK;
}

int cwmp_Upload(struct soap *soap, struct cwmp__Upload *req, int *type, void **data)
{
	struct cwmp_userdata *ud = soap->user;
	DownloadInfo_T *dlinfo = &ud->DownloadInfo;
	struct cwmp__Upload *ul = &dlinfo->Upload;
	struct cwmp__UploadResponse *resp;
	//int   i;

	CWMPDBG(1, (stderr, "<%s:%d>Got Request\n", __FUNCTION__, __LINE__));

	//handle
	if (ud->DownloadState != DOWNLD_NONE) {
		CWMPDBG(1, (stderr, "The download thread(%s) has been running!\n", __FUNCTION__));
		cwmp_set_fault(soap, 9001, NULL);
		*type = SOAP_TYPE_SOAP_ENV__Fault;
		*data = NULL;
		return SOAP_OK;
	}

	if (req->FileType && strncmp(req->FileType, "1 ", 2)) {
		CWMPDBG(1, (stderr, "Only support '1 Vendor Configuration File!\n"));
		cwmp_set_fault(soap, 9001, NULL);
		*type = SOAP_TYPE_SOAP_ENV__Fault;
		*data = NULL;
		return SOAP_OK;
	}

	if (req->URL == NULL || (strncmp(req->URL, "http:", 5) && strncmp(req->URL, "https:", 6))) {
		cwmp_set_fault(soap, 9013, NULL);
		*type = SOAP_TYPE_SOAP_ENV__Fault;
		*data = NULL;
		return SOAP_OK;
	}
	//save cwmp_download structure for later processing dowload
	cwmp_reset_DownloadInfo(dlinfo, DLWAY_NONE);	//or user->DownloadWay
	if (req->CommandKey)
		ul->CommandKey = strdup(req->CommandKey);
	if (req->FileType)
		ul->FileType = strdup(req->FileType);
	if (req->URL)
		ul->URL = strdup(req->URL);
	if (req->Username)
		ul->Username = strdup(req->Username);
	if (req->Password)
		ul->Password = strdup(req->Password);
	ul->DelaySeconds = req->DelaySeconds;

	ud->DownloadWay = DLWAY_UP;
	ud->DownloadState = DOWNLD_READY;

	//response
	resp = soap_malloc(soap, sizeof(struct cwmp__UploadResponse));
	soap_default_cwmp__UploadResponse(soap, resp);
	resp->Status = 1;

	*type = SOAP_TYPE_cwmp__UploadResponse;
	*data = resp;
	return SOAP_OK;
}

int cwmp_FactoryReset(struct soap *soap, struct cwmp__FactoryReset *req, int *type, void **data)
{
	struct cwmp_userdata *ud = soap->user;
	struct cwmp__FactoryResetResponse *resp;
	//int   i;

	CWMPDBG(1, (stderr, "<%s:%d>Got Request\n", __FUNCTION__, __LINE__));

	//handle
	ud->FactoryReset = 1;

	//response
	resp = soap_malloc(soap, sizeof(struct cwmp__FactoryResetResponse));
	soap_default_cwmp__FactoryResetResponse(soap, resp);
	*type = SOAP_TYPE_cwmp__FactoryResetResponse;
	*data = resp;

	return SOAP_OK;
}

/***********************************************************************/
/* handle ther SOAP's header */
/***********************************************************************/
void cwmp_header_free(struct soap *soap)
{
	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (soap->header) {
		if (soap->header->cwmp__ID)
			soap_dealloc(soap, soap->header->cwmp__ID);

		if (soap->header->cwmp__HoldRequests)
			soap_dealloc(soap, soap->header->cwmp__HoldRequests);

		if (soap->header->cwmp__NoMoreRequests)
			soap_dealloc(soap, soap->header->cwmp__NoMoreRequests);

		soap_dealloc(soap, soap->header);
		soap->header = NULL;
	}
}

int cwmp_header_init(struct soap *soap)
{
	char buf[32];

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (soap->header)
		cwmp_header_free(soap);

	soap->header = soap_malloc(soap, sizeof(struct SOAP_ENV__Header));
	if (soap->header) {
		soap_default_SOAP_ENV__Header(soap, soap->header);
		snprintf(buf, sizeof(buf), "%u", ((struct cwmp_userdata *)soap->user)->ID++);
		soap->header->cwmp__ID = soap_strdup(soap, buf);
	}
	return SOAP_OK;
}

int cwmp_header_set_NoMoreRequests(struct soap *soap, int flag)
{
	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (soap->header) {
		if (soap->header->cwmp__NoMoreRequests == NULL)
			soap->header->cwmp__NoMoreRequests = soap_malloc(soap, sizeof(xsd__boolean));
		*(soap->header->cwmp__NoMoreRequests) = flag ? true : false;
	}
	return SOAP_OK;
}

int cwmp_header_set_HoldRequests(struct soap *soap, int flag)
{
	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (soap->header) {
		if (soap->header->cwmp__HoldRequests == NULL)
			soap->header->cwmp__HoldRequests = soap_malloc(soap, sizeof(xsd__boolean));
		*(soap->header->cwmp__HoldRequests) = flag ? true : false;
	}
	return SOAP_OK;
}

int cwmp_header_handle_request(struct soap *soap)
{
	struct cwmp_userdata *data = soap->user;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (soap->header && data) {
		CWMPDBG(1, (stderr, "<%s:%d>SOAP Request Header: ", __FUNCTION__, __LINE__));
		if (soap->header->cwmp__ID)	//keep it for response
		{
			CWMPDBG(1, (stderr, "<ID:%s> ", soap->header->cwmp__ID));
			//should keep the request's id???
		}

		if (soap->header->cwmp__HoldRequests) {
			CWMPDBG(1, (stderr, "<Hold:%d> ", *(soap->header->cwmp__HoldRequests)));
			data->HoldRequests = *(soap->header->cwmp__HoldRequests) ? true : false;
			soap_dealloc(soap, soap->header->cwmp__HoldRequests);
			soap->header->cwmp__HoldRequests = NULL;
		} else
			data->HoldRequests = false;	//if no present, default to false

		if (soap->header->cwmp__NoMoreRequests) {
			CWMPDBG(1, (stderr, "<NoMore:%d> ", *(soap->header->cwmp__NoMoreRequests)));
			if (*(soap->header->cwmp__NoMoreRequests))
				data->NoMoreRequests = true;
			else
				data->NoMoreRequests = false;
			soap_dealloc(soap, soap->header->cwmp__NoMoreRequests);
			soap->header->cwmp__NoMoreRequests = NULL;
		} else
			data->NoMoreRequests = false;	//if no present, default to false

		CWMPDBG(1, (stderr, "\n"));
	}

	return SOAP_OK;
}

int cwmp_header_handle_response(struct soap *soap)
{
	struct cwmp_userdata *data = soap->user;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (soap->header && data) {
		CWMPDBG(1, (stderr, "<%s:%d>SOAP Response Header: \n", __FUNCTION__, __LINE__));
		if (soap->header->cwmp__ID) {
			CWMPDBG(1, (stderr, "<ID:%s> ", soap->header->cwmp__ID));
			//check the last request's id with response's id???????????????
		}

		if (soap->header->cwmp__HoldRequests) {
			CWMPDBG(1, (stderr, "<Hold:%d> ", *(soap->header->cwmp__HoldRequests)));
			data->HoldRequests = *(soap->header->cwmp__HoldRequests) ? true : false;
		} else
			data->HoldRequests = false;	//if no present, default to false

		if (soap->header->cwmp__NoMoreRequests) {
			CWMPDBG(1, (stderr, "<NoMore:%d> ", *(soap->header->cwmp__NoMoreRequests)));
			if (*(soap->header->cwmp__NoMoreRequests))
				data->NoMoreRequests = true;
			else
				data->NoMoreRequests = false;
		} else
			data->NoMoreRequests = false;	//if no present, default to false

		CWMPDBG(1, (stderr, "\n"));

		cwmp_header_free(soap);
	} else if (data) {
		//recv an empty http response
		data->HoldRequests = false;	//if no present, default to false
	}
	return SOAP_OK;
}

/***********************************************************************/
/* set soap fault */
/***********************************************************************/
int cwmp_set_fault(struct soap *soap, int cwmp_faultcode, char *cwmp_faultstring)
{
	char *s = NULL;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	switch (cwmp_faultcode) {
		//the source of the fault : Server/Receiver
		case 9000:
		case 9001:
		case 9002:
		case 9004:
		case 9009:
		case 9010:
		case 9011:
		case 9012:
		case 9013:
			soap_set_receiver_error(soap, "CWMP fault", NULL, SOAP_OK);
			break;
			//the source of the fault : Client/Sender
		case 9003:
		case 9005:
		case 9006:
		case 9007:
		case 9008:
			soap_set_sender_error(soap, "CWMP fault", NULL, SOAP_OK);
			break;
		default:
			if (cwmp_faultcode >= 9800 && cwmp_faultcode <= 9899) {
				//default : receiver fault
				soap_set_receiver_error(soap, "CWMP fault", NULL, SOAP_OK);
			} else
				return -1;
			break;
	}

	soap->fault->detail = (struct SOAP_ENV__Detail *)soap_malloc(soap, sizeof(struct SOAP_ENV__Detail));
	if (soap->fault->detail == NULL)
		return SOAP_ERR;
	soap_default_SOAP_ENV__Detail(soap, soap->fault->detail);

	soap->fault->detail->cwmp__Fault = soap_malloc(soap, sizeof(struct cwmp__Fault));
	if (soap->fault->detail->cwmp__Fault == NULL)
		return SOAP_ERR;
	soap_default_cwmp__Fault(soap, soap->fault->detail->cwmp__Fault);

	soap->fault->detail->cwmp__Fault->FaultCode = cwmp_faultcode;
	if (cwmp_faultstring)
		s = cwmp_faultstring;
	else {
		s = cwmp_ErrorString(cwmp_faultcode);
		if (s == NULL)
			s = strERR_default;
	}
	if (s)
		soap->fault->detail->cwmp__Fault->FaultString = soap_strdup(soap, s);

	return SOAP_OK;
}

/*used after calling cwmp_set_fault()*/
int cwmp_set_SetParameterValuesFault(struct soap *soap, struct node **root)
{
	int count;

	CWMPDBG(3, (stderr, "<%s:%d>\n", __FUNCTION__, __LINE__));
	if (soap->fault == NULL)
		return SOAP_ERR;

	count = get_node_count(*root);
	if (count) {
		int i;
		struct cwmp__Fault *pfault = soap->fault->detail->cwmp__Fault;
		pfault->__sizeSPVF = count;
		pfault->SetParameterValuesFault =
			soap_malloc(soap, pfault->__sizeSPVF * sizeof(struct cwmp__SetParameterValuesFault));
		for (i = 0; i < count; i++) {
			struct cwmp__SetParameterValuesFault *p;
			soap_default_cwmp__SetParameterValuesFault(soap, &pfault->SetParameterValuesFault[i]);
			p = pop_SetParameterVaulesFault(soap, root);
			pfault->SetParameterValuesFault[i].ParameterName = p->ParameterName;
			pfault->SetParameterValuesFault[i].FaultCode = p->FaultCode;
			pfault->SetParameterValuesFault[i].FaultString = p->FaultString;
			soap_dealloc(soap, p);	//free the popping data (struct cwmp__SetParameterValuesFault)
		}
	}
	return SOAP_OK;
}

int cwmp_handle_fault(struct soap *soap, struct SOAP_ENV__Fault *fault, int *type, void **data)
{
	struct cwmp_userdata *ud = soap->user;

	CWMPDBG(0, (stderr, "<%s:%d>Got SOAP Fault\n", __FUNCTION__, __LINE__));

	*type = SOAP_TYPE_cwmp__Empty;
	*data = NULL;
	//reset
	if (ud)
		ud->FaultCode = 0;

	if (fault) {
		CWMPDBG(0, (stderr, "\t faultcode:%s\n", fault->faultcode));
		CWMPDBG(0, (stderr, "\t faultstring:%s\n", fault->faultstring));
		if (fault->detail) {
			if (fault->detail->__any)
				CWMPDBG(0, (stderr, "\t detail:%s\n", fault->detail->__any));
			if (fault->detail->cwmp__Fault) {
				//int i;
				//struct cwmp__SetParameterValuesFault  *pSPVF = fault->detail->cwmp__Fault->SetParameterValuesFault;

				CWMPDBG(0, (stderr, "\t CWMP:FaultCode:%d\n", fault->detail->cwmp__Fault->FaultCode));
				CWMPDBG(0, (stderr, "\t CWMP:FaultString:%s\n", fault->detail->cwmp__Fault->FaultString));

				//maybe call callback function to the connection management to report recv fault
				//or save the faultcode to soap->data for later processing
				//???????????????????????????
				if (ud) {
					ud->FaultCode = fault->detail->cwmp__Fault->FaultCode;
#ifdef __DV_CWMP_SESSION_TEST__
					test_session_fail__acs_faultcode_8811(&(ud->FaultCode));
#endif
				}
			}
		}

	}

	return SOAP_OK;
}

int cwmp_handle_unknown(struct soap *soap, void *req, int *type, void **data)
{
	CWMPDBG(1, (stderr, "<%s:%d>Got Request\n", __FUNCTION__, __LINE__));

	cwmp_set_fault(soap, 9000, NULL);
	*type = SOAP_TYPE_SOAP_ENV__Fault;
	*data = NULL;

	return SOAP_OK;
}

void cwmp_setup_credential(struct cpe_machine *m)
{
	struct cwmp_userdata *ud = m->cpe_user;
	struct soap *soap = &m->cpe_soap;

	switch (m->cpe_auth_type) {
		case CPE_AUTH_NONE:
			break;
		case CPE_AUTH_BASIC:
			soap->userid = ud->username;
			soap->passwd = ud->password;
			break;
#ifdef CWMP_ENABLE_DIGEST
		case CPE_AUTH_DIGEST:
			http_da_restore(soap, &m->cpe_da_info);
			break;
#endif
		default:
			CWMPDBG(3, (stderr, "Unknown Auth Type\n"));
			break;
	}
}

static void *sock_recv(void *data, int msg_recv)
{
	int sockfd = *(int *)data;
	fd_set rfds;
	struct timeval tv;
	int nfd, count = 0;

	if (sockfd < 0)
		return NULL;

	while (1) {
		tv.tv_sec = 0;
		tv.tv_usec = 500 * 1000;

retry:
		FD_ZERO(&rfds);
		FD_SET(sockfd, &rfds);

		nfd = select(sockfd + 1, &rfds, NULL, NULL, &tv);
		if (nfd > 0 && FD_ISSET(sockfd, &rfds)) {
			if (msg_recv) {
				struct message msg;

				msg.msg_type = MSG_RECV;
				msgsnd(msgid, (void *)&msg, MSG_SIZE, 0);
				usleep(25 * 1000);
			}
			break;
		} else if (nfd == 0 && count++ < 120 ) {
			//APACBR-210 : wait 1 minute
			continue;

		} else {
			if (nfd < 0 && errno == EINTR) {
				CWMPDBG( 3, ( stderr, "sock_recv() : select() error - EINTR\n") );
				goto retry;
			}
		}

		break;
	}

	return NULL;
}

/***********************************************************************/
/* process sending & receiving message */
/***********************************************************************/
int cwmp_process_send(struct soap *soap, const char *soap_endpoint, const char *soap_action, const int type, const void *data)
{
	struct cwmp_userdata *ud = soap->user;
	struct cpe_machine *m = ud->machine;
	int msg_recv;

	//check soap_endpoint(URL)
	if (!soap_endpoint || STRLEN(soap_endpoint) < 1)
		return soap->error = SOAP_ERR;

	CWMPDBG(2, (stderr, "<%s:%d> url=%s\n", __FUNCTION__, __LINE__, soap_endpoint));

	//only type==SOAP_TYPE_cwmp__Empty/SOAP_TYPE_SOAP_ENV__Fault, the data==NULL
	if ((type != SOAP_TYPE_cwmp__Empty)
			&& (type != SOAP_TYPE_SOAP_ENV__Fault)
			&& (data == NULL)) {
		return soap->error = SOAP_ERR;
	}

	cwmp_setup_credential(m);
	soap->encodingStyle = "";
	soap_begin(soap);
	soap_serializeheader(soap);

	//Step 1: serialize method's structure.
	switch (type) {
		case SOAP_TYPE_cwmp__Empty:
			TLOG_PRINT("Send Empty Msg\n");
			break;
		case SOAP_TYPE_SOAP_ENV__Fault:
			soap_serialize_SOAP_ENV__Fault(soap, soap->fault);
			break;
		case SOAP_TYPE_cwmp__Inform:
			TLOG_PRINT("Send Inform 0x%04x\n", m->cpe_events);
			soap_serialize_cwmp__Inform(soap, (struct cwmp__Inform *)data);
			break;
		case SOAP_TYPE_cwmp__TransferComplete:
			soap_serialize_cwmp__TransferComplete(soap, (struct cwmp__TransferComplete *)data);
			break;
		case SOAP_TYPE_cwmp__GetRPCMethods:
			TLOG_PRINT("Send GetRPCMethod.\n");
			soap_serialize_cwmp__GetRPCMethods(soap, (struct cwmp__GetRPCMethods *)data);
			break;
		case SOAP_TYPE_cwmp__GetParameterValuesResponse:
			TLOG_PRINT("Send GetParameterValuesResponse.\n");
			soap_serialize_cwmp__GetParameterValuesResponse(soap, (struct cwmp__GetParameterValuesResponse *)data);
			break;
		case SOAP_TYPE_cwmp__GetRPCMethodsResponse:
			TLOG_PRINT("Send GetRPCMethodsResponse.\n");
			soap_serialize_cwmp__GetRPCMethodsResponse(soap, (struct cwmp__GetRPCMethodsResponse *)data);
			break;
		case SOAP_TYPE_cwmp__SetParameterValuesResponse:
			TLOG_PRINT("Send SetParameterValuesResponse\n");
			soap_serialize_cwmp__SetParameterValuesResponse(soap, (struct cwmp__SetParameterValuesResponse *)data);
			break;
		case SOAP_TYPE_cwmp__GetParameterNamesResponse:
			soap_serialize_cwmp__GetParameterNamesResponse(soap, (struct cwmp__GetParameterNamesResponse *)data);
			break;
		case SOAP_TYPE_cwmp__SetParameterAttributesResponse:
			soap_serialize_cwmp__SetParameterAttributesResponse(soap, (struct cwmp__SetParameterAttributesResponse *)data);
			break;
		case SOAP_TYPE_cwmp__GetParameterAttributesResponse:
			soap_serialize_cwmp__GetParameterAttributesResponse(soap, (struct cwmp__GetParameterAttributesResponse *)data);
			break;
		case SOAP_TYPE_cwmp__AddObjectResponse:
			TLOG_PRINT("Send AddObjectResponse\n");
			soap_serialize_cwmp__AddObjectResponse(soap, (struct cwmp__AddObjectResponse *)data);
			break;
		case SOAP_TYPE_cwmp__DeleteObjectResponse:
			TLOG_PRINT("Send DeleteObjectResponse\n");
			soap_serialize_cwmp__DeleteObjectResponse(soap, (struct cwmp__DeleteObjectResponse *)data);
			break;
		case SOAP_TYPE_cwmp__DownloadResponse:
			TLOG_PRINT("Send DownloadResponse\n");
			soap_serialize_cwmp__DownloadResponse(soap, (struct cwmp__DownloadResponse *)data);
			break;
		case SOAP_TYPE_cwmp__RebootResponse:
			soap_serialize_cwmp__RebootResponse(soap, (struct cwmp__RebootResponse *)data);
			break;
		case SOAP_TYPE_cwmp__UploadResponse:
			soap_serialize_cwmp__UploadResponse(soap, (struct cwmp__UploadResponse *)data);
			break;
		case SOAP_TYPE_cwmp__FactoryResetResponse:
			soap_serialize_cwmp__FactoryResetResponse(soap, (struct cwmp__FactoryResetResponse *)data);
			break;
		case 1011:
			{
				struct AutoTransferComplete *a = (struct AutoTransferComplete *)data;
				char *tmp = "";
				soap_embedded(soap, &a->isDownload, SOAP_TYPE_int);
				soap_serialize_string(soap, &tmp);
				soap_serialize_string(soap, &a->TransferURL);
				soap_serialize_string(soap, &a->TargetFileName);
				soap_serialize_string(soap, &a->FileType);
				soap_serialize_string(soap, &tmp);
				soap_serialize_cwmp__FaultStruct(soap, &a->FaultStruct);
			}
			break;
		default:
			return soap->error = SOAP_ERR;
			break;
	}

	TLOG_PRINT("Message Build step 1\n");

	if (soap_begin_count(soap))
		return soap->error;

	TLOG_PRINT("Message Build step 2\n");

	//type==SOAP_TYPE_cwmp__Empty,skip this
	if ((soap->mode & SOAP_IO_LENGTH) && (type != SOAP_TYPE_cwmp__Empty)) {
		if (soap_envelope_begin_out(soap)
		        || soap_putheader(soap)
		        || soap_body_begin_out(soap))
			return soap->error;

		//Step 2: count method's length
		TLOG_PRINT("Message Build step 2 : count method length\n");

		switch (type) {
			case SOAP_TYPE_SOAP_ENV__Fault:
				soap_put_SOAP_ENV__Fault(soap, soap->fault, "SOAP-ENV:Fault", "");
				break;
			case SOAP_TYPE_cwmp__Inform:
				soap_put_cwmp__Inform(soap, (struct cwmp__Inform *)data, "cwmp:Inform", "");
				break;
			case SOAP_TYPE_cwmp__TransferComplete:
				soap_put_cwmp__TransferComplete(soap, (struct cwmp__TransferComplete *)data, "cwmp:TransferComplete",
				        "");
				break;
			case SOAP_TYPE_cwmp__GetRPCMethods:
				soap_put_cwmp__GetRPCMethods(soap, (struct cwmp__GetRPCMethods *)data, "cwmp:GetRPCMethods", "");
				break;
			case SOAP_TYPE_cwmp__GetParameterValuesResponse:
				soap_put_cwmp__GetParameterValuesResponse(soap, (struct cwmp__GetParameterValuesResponse *)data,
				        "cwmp:GetParameterValuesResponse", "");
				break;
			case SOAP_TYPE_cwmp__GetRPCMethodsResponse:
				soap_put_cwmp__GetRPCMethodsResponse(soap, (struct cwmp__GetRPCMethodsResponse *)data,
				        "cwmp:GetRPCMethodsResponse", "");
				break;
			case SOAP_TYPE_cwmp__SetParameterValuesResponse:
				soap_put_cwmp__SetParameterValuesResponse(soap, (struct cwmp__SetParameterValuesResponse *)data,
				        "cwmp:SetParameterValuesResponse", "");
				break;
			case SOAP_TYPE_cwmp__GetParameterNamesResponse:
				soap_put_cwmp__GetParameterNamesResponse(soap, (struct cwmp__GetParameterNamesResponse *)data,
				        "cwmp:GetParameterNamesResponse", "");
				break;
			case SOAP_TYPE_cwmp__SetParameterAttributesResponse:
				soap_put_cwmp__SetParameterAttributesResponse(soap, (struct cwmp__SetParameterAttributesResponse *)data,
				        "cwmp:SetParameterAttributesResponse", "");
				break;
			case SOAP_TYPE_cwmp__GetParameterAttributesResponse:
				soap_put_cwmp__GetParameterAttributesResponse(soap, (struct cwmp__GetParameterAttributesResponse *)data,
				        "cwmp:GetParameterAttributesResponse", "");
				break;
			case SOAP_TYPE_cwmp__AddObjectResponse:
				soap_put_cwmp__AddObjectResponse(soap, (struct cwmp__AddObjectResponse *)data, "cwmp:AddObjectResponse",
				        "");
				break;
			case SOAP_TYPE_cwmp__DeleteObjectResponse:
				soap_put_cwmp__DeleteObjectResponse(soap, (struct cwmp__DeleteObjectResponse *)data,
				        "cwmp:DeleteObjectResponse", "");
				break;
			case SOAP_TYPE_cwmp__DownloadResponse:
				soap_put_cwmp__DownloadResponse(soap, (struct cwmp__DownloadResponse *)data, "cwmp:DownloadResponse",
				        "");
				break;
			case SOAP_TYPE_cwmp__RebootResponse:
				soap_put_cwmp__RebootResponse(soap, (struct cwmp__RebootResponse *)data, "cwmp:RebootResponse", "");
				break;
			case SOAP_TYPE_cwmp__UploadResponse:
				soap_put_cwmp__UploadResponse(soap, (struct cwmp__UploadResponse *)data, "cwmp:UploadResponse", "");
				break;
			case SOAP_TYPE_cwmp__FactoryResetResponse:
				soap_put_cwmp__FactoryResetResponse(soap, (struct cwmp__FactoryResetResponse *)data,
				        "cwmp:FactoryResetResponse", "");
				break;
			case 1011:
				{
					register int id;
					struct AutoTransferComplete *a = (struct AutoTransferComplete *)data;
					char *tag = "cwmp:AutonomousTransferComplete", *tmp = "";
					char *type = "";
					id = soap_embed(soap, (void *)data, NULL, 0,
#if !defined(GSOAP_VERSION) || GSOAP_VERSION < 20829
							tag,
#endif
							108);
					soap_element_begin_out(soap, tag, soap_embedded_id(soap, id, NULL, 108), type);
					soap_out_int(soap, "IsDownload", -1, &a->isDownload, "");
					soap_out_string(soap, "AnnounceURL", -1, &tmp, "");
					soap_out_string(soap, "TransferURL", -1, &a->TransferURL, "");
					soap_out_string(soap, "TargetFileName", -1, &a->TargetFileName, "");
					soap_out_string(soap, "FileType", -1, &a->FileType, "");
					soap_out_int(soap, "FileSize", -1, &a->FileSize, "");
					soap_out_time(soap, "StartTime", -1, &a->StartTime, "");
					soap_out_time(soap, "CompleteTime", -1, &a->CompleteTime, "");
					soap_out_cwmp__FaultStruct(soap, "FaultStruct", -1, &a->FaultStruct, "");
					soap_element_end_out(soap, tag);
				}
				break;
			default:
				break;
		}

		TLOG_PRINT("Message Build step 2 : envelope end out\n");
		if (soap->error || soap_body_end_out(soap)
				|| soap_envelope_end_out(soap))
			return soap->error;
	}
	
	TLOG_PRINT("Message Build step 3\n");

	if (soap_end_count(soap))
		return soap->error;

	TLOG_PRINT("Ready connect to server\n");

#ifdef __DV_CWMP_SESSION_TEST__
	test_session_fail__hold_req_timeout(type);
#endif

	if (soap_connect(soap, soap_endpoint, soap_action)) {
		TLOG_PRINT("Fail Connect to server\n");
		return soap_closesock(soap);
	}

	//type==SOAP_TYPE_cwmp__Empty has no body, skip this
	if (type != SOAP_TYPE_cwmp__Empty) {
		if (soap_envelope_begin_out(soap)
		        || soap_putheader(soap)
		        || soap_body_begin_out(soap))
			return soap_closesock(soap);

		//Step 3: put method's structure
		switch (type) {
			case SOAP_TYPE_SOAP_ENV__Fault:
				soap_put_SOAP_ENV__Fault(soap, soap->fault, "SOAP-ENV:Fault", "");
				break;
			case SOAP_TYPE_cwmp__Inform:
				soap_put_cwmp__Inform(soap, (struct cwmp__Inform *)data, "cwmp:Inform", "");
				break;
			case SOAP_TYPE_cwmp__TransferComplete:
				soap_put_cwmp__TransferComplete(soap, (struct cwmp__TransferComplete *)data, "cwmp:TransferComplete",
				        "");
				struct cwmp__TransferComplete *tc = (struct cwmp__TransferComplete *)data;
				TLOG_PRINT("Send TransferComplete(FaultCode : %d)\n",(tc->FaultStruct).FaultCode);
				break;
			case SOAP_TYPE_cwmp__GetRPCMethods:
				soap_put_cwmp__GetRPCMethods(soap, (struct cwmp__GetRPCMethods *)data, "cwmp:GetRPCMethods", "");
				break;
			case SOAP_TYPE_cwmp__GetParameterValuesResponse:
				soap_put_cwmp__GetParameterValuesResponse(soap, (struct cwmp__GetParameterValuesResponse *)data,
				        "cwmp:GetParameterValuesResponse", "");
				break;
			case SOAP_TYPE_cwmp__GetRPCMethodsResponse:
				soap_put_cwmp__GetRPCMethodsResponse(soap, (struct cwmp__GetRPCMethodsResponse *)data,
				        "cwmp:GetRPCMethodsResponse", "");
				break;
			case SOAP_TYPE_cwmp__SetParameterValuesResponse:
				soap_put_cwmp__SetParameterValuesResponse(soap, (struct cwmp__SetParameterValuesResponse *)data,
				        "cwmp:SetParameterValuesResponse", "");
				break;
			case SOAP_TYPE_cwmp__GetParameterNamesResponse:
				soap_put_cwmp__GetParameterNamesResponse(soap, (struct cwmp__GetParameterNamesResponse *)data,
				        "cwmp:GetParameterNamesResponse", "");
				break;
			case SOAP_TYPE_cwmp__SetParameterAttributesResponse:
				soap_put_cwmp__SetParameterAttributesResponse(soap, (struct cwmp__SetParameterAttributesResponse *)data,
				        "cwmp:SetParameterAttributesResponse", "");
				break;
			case SOAP_TYPE_cwmp__GetParameterAttributesResponse:
				soap_put_cwmp__GetParameterAttributesResponse(soap, (struct cwmp__GetParameterAttributesResponse *)data,
				        "cwmp:GetParameterAttributesResponse", "");
				break;
			case SOAP_TYPE_cwmp__AddObjectResponse:
				soap_put_cwmp__AddObjectResponse(soap, (struct cwmp__AddObjectResponse *)data, "cwmp:AddObjectResponse",
				        "");
				break;
			case SOAP_TYPE_cwmp__DeleteObjectResponse:
				soap_put_cwmp__DeleteObjectResponse(soap, (struct cwmp__DeleteObjectResponse *)data,
				        "cwmp:DeleteObjectResponse", "");
				break;
			case SOAP_TYPE_cwmp__DownloadResponse:
				soap_put_cwmp__DownloadResponse(soap, (struct cwmp__DownloadResponse *)data, "cwmp:DownloadResponse",
				        "");
				break;
			case SOAP_TYPE_cwmp__RebootResponse:
				soap_put_cwmp__RebootResponse(soap, (struct cwmp__RebootResponse *)data, "cwmp:RebootResponse", "");
				break;
			case SOAP_TYPE_cwmp__UploadResponse:
				soap_put_cwmp__UploadResponse(soap, (struct cwmp__UploadResponse *)data, "cwmp:UploadResponse", "");
				break;
			case SOAP_TYPE_cwmp__FactoryResetResponse:
				soap_put_cwmp__FactoryResetResponse(soap, (struct cwmp__FactoryResetResponse *)data,
				        "cwmp:FactoryResetResponse", "");
				break;
			case 1011:
				{
					register int id;
					struct AutoTransferComplete *a = (struct AutoTransferComplete *)data;
					char *tag = "cwmp:AutonomousTransferComplete";
					char *type = "";
					char *tmp = "";
					id = soap_embed(soap, (void *)data, NULL, 0,
#if !defined(GSOAP_VERSION) || GSOAP_VERSION < 20829
					        tag,
#endif
					        108);
					soap_element_begin_out(soap, tag, soap_embedded_id(soap, id, NULL, 108), type);
					soap_out_int(soap, "IsDownload", -1, &a->isDownload, "");
					soap_out_string(soap, "AnnounceURL", -1, &tmp, "");
					soap_out_string(soap, "TransferURL", -1, &a->TransferURL, "");
					soap_out_string(soap, "TargetFileName", -1, &a->TargetFileName, "");
					soap_out_string(soap, "FileType", -1, &a->FileType, "");
					soap_out_int(soap, "FileSize", -1, &a->FileSize, "");
					soap_out_time(soap, "StartTime", -1, &a->StartTime, "");
					soap_out_time(soap, "CompleteTime", -1, &a->CompleteTime, "");
					soap_out_cwmp__FaultStruct(soap, "FaultStruct", -1, &a->FaultStruct, "");
					soap_element_end_out(soap, tag);
				
					TLOG_PRINT("Send AutonomousTransferComplete(FaultCode : %d)\n", (a->FaultStruct).FaultCode);
				}
				break;
			default:
				break;
		}

		if (soap->error || soap_body_end_out(soap)
				|| soap_envelope_end_out(soap))
			return soap_closesock(soap);
	}

#ifdef __DV_CWMP_SESSION_TEST__
	if (test_session_fail__send(type)) {
		soap_closesock(soap);
		return -1;
	}
#endif

	if (soap_end_send(soap))
		return soap_closesock(soap);

	if (m->cpe_isReqSent)
		msg_recv = 1;
	else
		msg_recv = 0;

	sock_recv((void *)&soap->socket, msg_recv);

	CWMPDBG(2, (stderr, "<%s:%d> done\n", __FUNCTION__, __LINE__));
	
	return soap->error;
}

static void printCookie(struct soap_cookie *c);

int cwmp_process_recv(struct soap *soap, int *type, void **data)
{
	struct cwmp_userdata *ud = soap->user;
	struct cpe_machine *m = ud->machine;
	int cpe_state = check_cpe_state();

	int recv_type = SOAP_TYPE_cwmp__None;
	void *recv_data = NULL;
	int err;
	int ret = 0;

	printCookie(soap->cookies);

	CWMPDBG(2, (stderr, "<%s:%d> State:%s(%d)\n", __FUNCTION__, __LINE__, strCPEState[cpe_state], cpe_state));
	m->cpe_recv_msgtype = recv_type;

	if ((soap == NULL) || (type == NULL) || (data == NULL))
		return soap->error = SOAP_ERR;

	*type = SOAP_TYPE_cwmp__Empty;
	*data = NULL;
	soap_begin(soap);

	ret = soap_begin_recv(soap);

	CWMPDBG(2, (stderr,"****************http status*******************\n"));
	CWMPDBG(2, (stderr,"%s(%d / %d)\n", soap->msgbuf, soap->status, ret));
	CWMPDBG(2, (stderr,"**********************************************\n"));

	if (soap->status != 200 && soap->status != 204) {
		//stop recv processing. (HTTP Error, etc...)
		CWMPDBG(2, (stderr, "<%s:%d> SOAP ErrorNo S:%d(R:%d)\n", __FUNCTION__, __LINE__, soap->status, ret));
		TLOG_PRINT("Recv HTTP Code : %d\n", soap->status);
		return soap_closesock(soap);
	}

#if 0
	//if http status-code=200~299, return SOAP_OK
	//otherwise, return error, ex: 301......
	if (soap_begin_recv(soap)) {
		return soap_closesock(soap);
	}
#endif

#if 1
	//only (http==200&&content-length!=0) to pass through
	//if(soap->status==204) /*only this is normal to close the session*/
	//support the chunked mode
	if (soap->status == 204 ||
	    ((soap->status == 200) && (soap->length == 0) && (!(soap->mode & SOAP_IO_CHUNK)))) {
		soap_end_recv(soap);
		recv_type = SOAP_TYPE_cwmp__EmptyResponse;
		m->cpe_recv_msgtype = recv_type;
		soap->keep_alive = 0;
		
		TLOG_PRINT("Recv Empty Msg\n");
		/* 
		   If cwmpClient can't report AutonomousTransferComplete messages,
		   DownloadState must be initialize for next polling.
		   (Download config / image.)
		   */
		if (cpe_state == CPE_ST_EMPTY_SENT && ud->DownloadState != DOWNLD_NONE) {
			//CWMPDBG(0, (stderr, "<%s:%d> ud->DownloadState: %d\n", __FUNCTION__, __LINE__, ud->DownloadState));
			ud->DownloadState = DOWNLD_NONE;
		}

		cwmp_header_handle_response(soap);
		return soap_closesock(soap);
	} else if (soap->status != 200) {
		TLOG_PRINT("Recv None Msg(code) : %d\n", soap->status);
		soap_end_recv(soap);
		recv_type = SOAP_TYPE_cwmp__None;
		m->cpe_recv_msgtype = recv_type;
		soap->keep_alive = 0;
		cwmp_header_handle_response(soap);
		return soap_closesock(soap);
	}
#else
	//empty response from acs:check if 204 status code?????
	if ((soap->length == 0) && (!(soap->mode & SOAP_IO_CHUNK))) {
		soap_end_recv(soap);
		cwmp_header_handle_response(soap);
		return soap_closesock(soap);
	}
#endif

	/*for zyxel */
	if (soap->mode & SOAP_IO_CHUNK) {
		soap_wchar chunked_end;
		chunked_end = soap_get0(soap);

		if ((soap->mode & SOAP_IO_CHUNK) && ((int)chunked_end == -1)) {	//or '0' 
			soap_end_recv(soap);
			recv_type = SOAP_TYPE_cwmp__EmptyResponse;
			m->cpe_recv_msgtype = recv_type;
			soap->keep_alive = 0;
			cwmp_header_handle_response(soap);
			return soap_closesock(soap);

		}
	}
	/*end for zyxel */

	if (soap_envelope_begin_in(soap)
	        || soap_recv_header(soap)
	        || soap_body_begin_in(soap))
		return soap_closesock(soap);

	//Step 4: get method's request/response
	soap_peek_element(soap);
	if (!soap_match_tag(soap, soap->tag, "cwmp:InformResponse")) {
		if (HAS_EVENT(m, EC_BOOT) && soap->status == 200)
			syslog(LOG_INFO, DVLOG_MARK_ADMIN "HGW is  authenticated successfully");

		//APACRTL-337
		if ((soap->status / 100) == 2)
			check_wan_ip_changed(1);

		TLOG_PRINT("Recv InformResponse\n");
		recv_type = SOAP_TYPE_cwmp__InformResponse;
		recv_data = soap_malloc(soap, sizeof(struct cwmp__InformResponse));
		soap_default_cwmp__InformResponse(soap, (struct cwmp__InformResponse *)recv_data);
		soap_get_cwmp__InformResponse(soap, (struct cwmp__InformResponse *)recv_data, "cwmp:InformResponse", "");
	} else if (!soap_match_tag(soap, soap->tag, "cwmp:TransferCompleteResponse")) {
		TLOG_PRINT("Recv TransferCompleteResponse\n");
		recv_type = SOAP_TYPE_cwmp__TransferCompleteResponse;
		recv_data = soap_malloc(soap, sizeof(struct cwmp__TransferCompleteResponse));
		soap_default_cwmp__TransferCompleteResponse(soap, (struct cwmp__TransferCompleteResponse *)recv_data);
		soap_get_cwmp__TransferCompleteResponse(soap, (struct cwmp__TransferCompleteResponse *)recv_data,
		        "cwmp:TransferCompleteResponse", "");
	} else if (!soap_match_tag(soap, soap->tag, "cwmp:GetRPCMethodsResponse")) {
		TLOG_PRINT("Recv GetRPCMethodsResponse\n");
		recv_type = SOAP_TYPE_cwmp__GetRPCMethodsResponse;
		recv_data = soap_malloc(soap, sizeof(struct cwmp__GetRPCMethodsResponse));
		soap_default_cwmp__GetRPCMethodsResponse(soap, (struct cwmp__GetRPCMethodsResponse *)recv_data);
		soap_get_cwmp__GetRPCMethodsResponse(soap, (struct cwmp__GetRPCMethodsResponse *)recv_data,
		        "cwmp:GetRPCMethodsResponse", "");
	} else if (!soap_match_tag(soap, soap->tag, "cwmp:GetParameterValues")) {
		TLOG_PRINT("Recv GetParameterValues\n");
		recv_type = SOAP_TYPE_cwmp__GetParameterValues;
		recv_data = soap_malloc(soap, sizeof(struct cwmp__GetParameterValues));
		soap_default_cwmp__GetParameterValues(soap, (struct cwmp__GetParameterValues *)recv_data);
		soap_get_cwmp__GetParameterValues(soap, (struct cwmp__GetParameterValues *)recv_data, "cwmp:GetParameterValues",
		        "");
	} else if (!soap_match_tag(soap, soap->tag, "cwmp:GetRPCMethods")) {
		TLOG_PRINT("Recv GetRPCMethods\n");
		recv_type = SOAP_TYPE_cwmp__GetRPCMethods;
		recv_data = soap_malloc(soap, sizeof(struct cwmp__GetRPCMethods));
		soap_default_cwmp__GetRPCMethods(soap, (struct cwmp__GetRPCMethods *)recv_data);
		soap_get_cwmp__GetRPCMethods(soap, (struct cwmp__GetRPCMethods *)recv_data, "cwmp:GetRPCMethods", "");
	} else if (!soap_match_tag(soap, soap->tag, "cwmp:SetParameterValues")) {
		TLOG_PRINT("Recv SetParameterValues\n");
		recv_type = SOAP_TYPE_cwmp__SetParameterValues;
		recv_data = soap_malloc(soap, sizeof(struct cwmp__SetParameterValues));
		soap_default_cwmp__SetParameterValues(soap, (struct cwmp__SetParameterValues *)recv_data);
		soap_get_cwmp__SetParameterValues(soap, (struct cwmp__SetParameterValues *)recv_data, "cwmp:SetParameterValues",
		        "");
	} else if (!soap_match_tag(soap, soap->tag, "cwmp:GetParameterNames")) {
		recv_type = SOAP_TYPE_cwmp__GetParameterNames;
		recv_data = soap_malloc(soap, sizeof(struct cwmp__GetParameterNames));
		soap_default_cwmp__GetParameterNames(soap, (struct cwmp__GetParameterNames *)recv_data);
		soap_get_cwmp__GetParameterNames(soap, (struct cwmp__GetParameterNames *)recv_data, "cwmp:GetParameterNames",
		        "");
	} else if (!soap_match_tag(soap, soap->tag, "cwmp:SetParameterAttributes")) {
		recv_type = SOAP_TYPE_cwmp__SetParameterAttributes;
		recv_data = soap_malloc(soap, sizeof(struct cwmp__SetParameterAttributes));
		soap_default_cwmp__SetParameterAttributes(soap, (struct cwmp__SetParameterAttributes *)recv_data);
		soap_get_cwmp__SetParameterAttributes(soap, (struct cwmp__SetParameterAttributes *)recv_data,
		        "cwmp:SetParameterAttributes", "");
	} else if (!soap_match_tag(soap, soap->tag, "cwmp:GetParameterAttributes")) {
		recv_type = SOAP_TYPE_cwmp__GetParameterAttributes;
		recv_data = soap_malloc(soap, sizeof(struct cwmp__GetParameterAttributes));
		soap_default_cwmp__GetParameterAttributes(soap, (struct cwmp__GetParameterAttributes *)recv_data);
		soap_get_cwmp__GetParameterAttributes(soap, (struct cwmp__GetParameterAttributes *)recv_data,
		        "cwmp:GetParameterAttributes", "");
	} else if (!soap_match_tag(soap, soap->tag, "cwmp:AddObject")) {
		TLOG_PRINT("Recv AddObject\n");
		recv_type = SOAP_TYPE_cwmp__AddObject;
		recv_data = soap_malloc(soap, sizeof(struct cwmp__AddObject));
		soap_default_cwmp__AddObject(soap, (struct cwmp__AddObject *)recv_data);
		soap_get_cwmp__AddObject(soap, (struct cwmp__AddObject *)recv_data, "cwmp:AddObject", "");
	} else if (!soap_match_tag(soap, soap->tag, "cwmp:DeleteObject")) {
		TLOG_PRINT("Recv DeleteObject\n");
		recv_type = SOAP_TYPE_cwmp__DeleteObject;
		recv_data = soap_malloc(soap, sizeof(struct cwmp__DeleteObject));
		soap_default_cwmp__DeleteObject(soap, (struct cwmp__DeleteObject *)recv_data);
		soap_get_cwmp__DeleteObject(soap, (struct cwmp__DeleteObject *)recv_data, "cwmp:DeleteObject", "");
	} else if (!soap_match_tag(soap, soap->tag, "cwmp:Download")) {
		TLOG_PRINT("Recv Download\n");
		recv_type = SOAP_TYPE_cwmp__Download;
		recv_data = soap_malloc(soap, sizeof(struct cwmp__Download));
		soap_default_cwmp__Download(soap, (struct cwmp__Download *)recv_data);
		soap_get_cwmp__Download(soap, (struct cwmp__Download *)recv_data, "cwmp:Download", "");
	} else if (!soap_match_tag(soap, soap->tag, "cwmp:Reboot")) {
		TLOG_PRINT("Recv Reboot\n");
		recv_type = SOAP_TYPE_cwmp__Reboot;
		recv_data = soap_malloc(soap, sizeof(struct cwmp__Reboot));
		soap_default_cwmp__Reboot(soap, (struct cwmp__Reboot *)recv_data);
		soap_get_cwmp__Reboot(soap, (struct cwmp__Reboot *)recv_data, "cwmp:Reboot", "");
	} else if (!soap_match_tag(soap, soap->tag, "cwmp:Upload")) {
		recv_type = SOAP_TYPE_cwmp__Upload;
		recv_data = soap_malloc(soap, sizeof(struct cwmp__Upload));
		soap_default_cwmp__Upload(soap, (struct cwmp__Upload *)recv_data);
		soap_get_cwmp__Upload(soap, (struct cwmp__Upload *)recv_data, "cwmp:Upload", "");
	} else if (!soap_match_tag(soap, soap->tag, "cwmp:FactoryReset")) {
		TLOG_PRINT("Recv FactoryReset\n");
		recv_type = SOAP_TYPE_cwmp__FactoryReset;
		recv_data = soap_malloc(soap, sizeof(struct cwmp__FactoryReset));
		soap_default_cwmp__FactoryReset(soap, (struct cwmp__FactoryReset *)recv_data);
		soap_get_cwmp__FactoryReset(soap, (struct cwmp__FactoryReset *)recv_data, "cwmp:FactoryReset", "");
	} else if (!soap_match_tag(soap, soap->tag, "SOAP-ENV:Fault")) {
		soap_recv_fault(soap
#if defined(GSOAP_VERSION) && GSOAP_VERSION >= 20829
		        , 1
#endif
		        );
		recv_type = SOAP_TYPE_SOAP_ENV__Fault;
		recv_data = NULL;	//soap->fault
		soap->error = SOAP_OK;	//to avoid to return
	} else if (!soap_match_tag(soap, soap->tag, "cwmp:AutonomousTransferCompleteResponse")) {
		TLOG_PRINT("Recv AutonomousTransferCompleteResponse\n");
		recv_type = SOAP_TYPE_cwmp__TransferCompleteResponse;
		recv_data = soap_malloc(soap, sizeof(struct cwmp__TransferCompleteResponse));
		soap_default_cwmp__TransferCompleteResponse(soap, (struct cwmp__TransferCompleteResponse *)recv_data);
		soap_get_cwmp__TransferCompleteResponse(soap, (struct cwmp__TransferCompleteResponse *)recv_data,
		        "cwmp:AutonomousTransferCompleteResponse", "");
	} else {		//maybe, there are 3 conditions
		// No body content, unknown request, and unknown response
		char *any;
		CWMPDBG(0, (stderr, "<%s:%d>UnKnown TAG: %s\n", __FUNCTION__, __LINE__, soap->tag));
		soap_in_string(soap, "-any", &any, "xsd:string");
		CWMPDBG(0, (stderr, "\tdump: %s\n", any));

		if (soap->tag == NULL || soap->tag[0] == '\0')	//no content
		{
			recv_type = SOAP_TYPE_cwmp__EmptyResponse;
			TLOG_PRINT("Recv Empty resp\n");
			recv_data = NULL;
		} else if (strstr(soap->tag, "Response"))	//unknown response
		{
			TLOG_PRINT("Recv Unknown resp : %s\n", soap->tag);
			recv_type = SOAP_TYPE_cwmp__UnKnownResponse;
			recv_data = NULL;
		} else		//unknown request
		{
			TLOG_PRINT("Recv Unknown MSG : %s\n", soap->tag);
			recv_type = SOAP_TYPE_cwmp__UnKnown;
			recv_data = NULL;
		}
	}
	m->cpe_recv_msgtype = recv_type;
	TLOG_PRINT("Recv TYPE : %d\n", recv_type);

	//soap_recv_fault() has already do these, skip this if recv_type==SOAP_TYPE_SOAP_ENV__Fault
	if (recv_type != SOAP_TYPE_SOAP_ENV__Fault) {
		if (soap_body_end_in(soap)
		        || soap_envelope_end_in(soap)
		        || soap_end_recv(soap)) {
			CWMPDBG(0, (stderr, "<%s:%d>Recv type:%d error , return\n", __FUNCTION__, __LINE__, recv_type));
			return soap_closesock(soap);
		}
	}
	//Step 5: handle receiving soap's header
	switch (recv_type) {
		//response
		case SOAP_TYPE_SOAP_ENV__Fault:
		case SOAP_TYPE_cwmp__EmptyResponse:	//????
		case SOAP_TYPE_cwmp__UnKnownResponse:
		case SOAP_TYPE_cwmp__InformResponse:
		case SOAP_TYPE_cwmp__TransferCompleteResponse:
		case SOAP_TYPE_cwmp__GetRPCMethodsResponse:
			cwmp_header_handle_response(soap);
			break;
			//request
		case SOAP_TYPE_cwmp__UnKnown:
		case SOAP_TYPE_cwmp__GetRPCMethods:
		case SOAP_TYPE_cwmp__GetParameterValues:
		case SOAP_TYPE_cwmp__SetParameterValues:
		case SOAP_TYPE_cwmp__GetParameterNames:
		case SOAP_TYPE_cwmp__SetParameterAttributes:
		case SOAP_TYPE_cwmp__GetParameterAttributes:
		case SOAP_TYPE_cwmp__AddObject:
		case SOAP_TYPE_cwmp__DeleteObject:
		case SOAP_TYPE_cwmp__Download:
		case SOAP_TYPE_cwmp__Reboot:
		case SOAP_TYPE_cwmp__Upload:
		case SOAP_TYPE_cwmp__FactoryReset:
			cwmp_header_handle_request(soap);
			break;
		default:
			break;
	}

	err = soap_closesock(soap);
	///Step 6: call cb fun.
	switch (recv_type) {
		case SOAP_TYPE_SOAP_ENV__Fault:
			cwmp_handle_fault(soap, soap->fault, type, data);
			break;
		case SOAP_TYPE_cwmp__EmptyResponse:
		case SOAP_TYPE_cwmp__UnKnownResponse:
			*type = SOAP_TYPE_cwmp__Empty;
			*data = NULL;
			break;
		case SOAP_TYPE_cwmp__UnKnown:
			cwmp_handle_unknown(soap, recv_data, type, data);
			break;
		case SOAP_TYPE_cwmp__InformResponse:
			cwmp_InformResponse(soap, (struct cwmp__InformResponse *)recv_data, type, data);
			break;
		case SOAP_TYPE_cwmp__TransferCompleteResponse:
			cwmp_TransferCompleteResponse(soap, (struct cwmp__TransferCompleteResponse *)recv_data, type, data);
			break;
		case SOAP_TYPE_cwmp__GetRPCMethodsResponse:
			cwmp_GetRPCMethodsResponse(soap, (struct cwmp__GetRPCMethodsResponse *)recv_data, type, data);
			break;
		case SOAP_TYPE_cwmp__GetParameterValues:
			cwmp_GetParameterValues(soap, (struct cwmp__GetParameterValues *)recv_data, type, data);
			m->cpe_last_msgtype = *type;
			break;
		case SOAP_TYPE_cwmp__GetRPCMethods:
			cwmp_GetRPCMethods(soap, (struct cwmp__GetRPCMethods *)recv_data, type, data);
			break;
		case SOAP_TYPE_cwmp__SetParameterValues:
			cwmp_SetParameterValues(soap, (struct cwmp__SetParameterValues *)recv_data, type, data);
			m->cpe_last_msgtype = *type;
			break;
		case SOAP_TYPE_cwmp__GetParameterNames:
			cwmp_GetParameterNames(soap, (struct cwmp__GetParameterNames *)recv_data, type, data);
			break;
		case SOAP_TYPE_cwmp__SetParameterAttributes:
			cwmp_SetParameterAttributes(soap, (struct cwmp__SetParameterAttributes *)recv_data, type, data);
			break;
		case SOAP_TYPE_cwmp__GetParameterAttributes:
			cwmp_GetParameterAttributes(soap, (struct cwmp__GetParameterAttributes *)recv_data, type, data);
			break;
		case SOAP_TYPE_cwmp__AddObject:
			cwmp_AddObject(soap, (struct cwmp__AddObject *)recv_data, type, data);
			break;
		case SOAP_TYPE_cwmp__DeleteObject:
			cwmp_DeleteObject(soap, (struct cwmp__DeleteObject *)recv_data, type, data);
			break;
		case SOAP_TYPE_cwmp__Download:
			cwmp_Download(soap, (struct cwmp__Download *)recv_data, type, data);
			break;
		case SOAP_TYPE_cwmp__Reboot:
			cwmp_Reboot(soap, (struct cwmp__Reboot *)recv_data, type, data);
			break;
		case SOAP_TYPE_cwmp__Upload:
			cwmp_Upload(soap, (struct cwmp__Upload *)recv_data, type, data);
			break;
		case SOAP_TYPE_cwmp__FactoryReset:
			cwmp_FactoryReset(soap, (struct cwmp__FactoryReset *)recv_data, type, data);
			break;
		default:
			break;
	}

	//don't free here, free at sending
	//soap_destroy(soap);
	//soap_end(soap);

	return err;
}

int dnsQuery(char *domain, unsigned int *ip)
{
#if 1
	struct addrinfo hints;
	struct addrinfo *res;
	struct in_addr addr;
	char addrstr[100] = "";
	int ret = -1;
	void *ptr = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(domain, NULL, &hints, &res)) {
		perror("getaddrinfo()");
		return ret;
	}

	while (res) {
		if (res->ai_family == AF_INET) {
			inet_ntop(res->ai_family, ptr, addrstr, sizeof(addrstr));
			if (!inet_aton(addrstr, &addr))
				continue;

			*ip = addr.s_addr;
			ret = 0;
			break;
		} else
			res = res->ai_next;
	}

	freeaddrinfo(res);

	return ret;
#else
	int ret = -1, server_id;
	long unsigned int iplist[4];
	int iplen = sizeof(iplist) / sizeof(unsigned long);

	if (inet_aton(domain, (struct in_addr *)ip))
		return 0;

	server_id = __lg_gethostbyname(domain, NULL, iplist, &iplen);
	if (server_id >= 0 && iplen) {
		memcpy(ip, (unsigned int *)&iplist[0], sizeof(unsigned int));
		ret = 0;
	}
	return (ret);
#endif
}

int MgmtSrvGetConReqURL(char *url, unsigned int size)
{
	struct soap *pSoap = &cpe_client.cpe_soap;
	struct cwmp_userdata *ud = cpe_client.cpe_user;
	char buf[32] = {0, };
	int rc;

	if ((NULL == ud) || (NULL == pSoap))
		return 0;

	rc = snprintf(url, size, "http://%s:%d/cr", get_wanip(buf, sizeof(buf)), ud->server_port);

	return rc;
}

int MgmtSrvGetUDPConReqURL(char *url, unsigned int size)
{
	struct cwmp_userdata *ud = cpe_client.cpe_user;
	int rc = 0;

	if (NULL == ud)
		return 0;

	rc = snprintf(url, size, "%s:%d", inet_ntoa(*(struct in_addr *)&ud->MappedAddr), (ud->MappedPort) ? ud->MappedPort : ud->server_port);

	return rc;
}

void cwmpMgmtConnReqPassword(const char *password)
{
	if (!pUserData)
		return;

	if (STRLEN(password) == 0)
		return;

	if (pUserData->conreq_password)
		free(pUserData->conreq_password);

	pUserData->conreq_password = strdup(password);
	if (pUserData->password)
		free(pUserData->password);

	pUserData->password = strdup(password);
	return;
}

void cwmpMgmtSetImmediatePolling(int res)
{
	if (!pUserData)
		return;

	if (res == 1) {
		time_t this_time;
		struct tm *now;

		this_time = time(NULL);
		now = localtime(&this_time);
		now->tm_sec = 0;

		cwmpMgmtSetPeriodicInformInterval(1);
		pollInfo.time_limit = mktime(now) + MAX_POLLING_RANGE;	//APACRTL-617
	}
	return;
}

int IdleResetCount;
int IdleResetFlag;
int cwmpMgmtSetIdleReset(int res)
{

	if (!pUserData)
		return -1;

	if (res == 1) {
		init_check_idle_service(&pollInfo);
		check_idle_service(&pollInfo);
		IdleResetCount = 60;
		set_cwmp_timer(pUserData, IDLE_RESET_TIMER, 60, FROM_NOW);
		yfecho(PROVISION_PERIOD, O_WRONLY|O_CREAT|O_TRUNC, 0644, "1"); //APACQCA-59
	}
	return 0;
}

int cwmpMgmtGetSTUNEnable(void)
{
	return pUserData->STUNEnable;
}

void cwmpMgmtSetSTUNEnable(int val)
{
	pUserData->STUNEnable = val;
}

int cwmpMgmtGetPeriodicInformInterval(void)
{
	return pUserData->InformIntervalCnt;
}

void cwmpMgmtSetPeriodicInformInterval(int val)
{
	pUserData->InformIntervalCnt = val;
	set_cwmp_timer(pUserData, POLL_TIMER, val, FROM_NOW);	//APACQCA-442 : Fix Bug
}

//APACRTL-543
static int need_update_polltime;
int is_need_update_polltime(void)
{
	if (need_update_polltime) {
		need_update_polltime = 0;
		return 1;
	}

	return 0;
}

//APACRTL-543
void check_need_update_polltime(int val)
{
	need_update_polltime = val;
}

static int next_poll_time;
static int next_poll_limit;

static void clear_cached_polling_time(void)
{
	next_poll_time = 0;
	next_poll_limit = 0;
}

static int get_cached_polling_time(unsigned int *poll_time, unsigned int *update_time_limit)
{
	if (access(POLLTIME_FILE_NAME, F_OK) != 0)
		return 0;

	if (!next_poll_time || !next_poll_limit) {
		FILE *fp;

		if ((fp = fopen(POLLTIME_FILE_NAME, "r")) != NULL) {
			fscanf(fp, "%u %u", &next_poll_time, &next_poll_limit);
			fclose(fp);
		} else
			return 0;
	}

	if (poll_time)
		*poll_time = next_poll_time;

	if (update_time_limit)
		*update_time_limit = next_poll_limit;

	return 1;
}

static int next_poll_invalid(void)
{
	unsigned int time_limit;
	unsigned int this_time;

	if (!get_cached_polling_time(NULL, &time_limit))
		return 0;

	this_time = time(NULL);

	if (time_limit + 3600 < this_time )
		return 1;

	return 0;
}

static int get_next_polling_time(void)
{
	FILE    *fp;
	unsigned int    poll_time=0, update_time_limit=0;
	unsigned int	this_time;

	if ((fp=fopen(POLLTIME_FILE_NAME, "r")) != NULL) {
		fscanf(fp, "%u %u", &poll_time, &update_time_limit);
		fclose(fp);
		this_time = time(NULL);
		if (poll_time <= this_time) {
			cwmpMgmtSetPeriodicInformInterval(0);	//APACQCA-442 : Fix Bug
		} else {
			cwmpMgmtSetPeriodicInformInterval(poll_time - this_time);	//APACQCA-442 : Fix Bug
			pollInfo.time_limit = update_time_limit;
		}

		next_poll_time = poll_time;
		next_poll_limit = update_time_limit;

		return (1);
	}
	return (0);
}

static void set_next_polling_time(unsigned int poll_time, unsigned int update_time_limit)
{
	FILE    *fp;

	if ((fp=fopen(POLLTIME_FILE_NAME, "w")) != NULL) {
		fprintf(fp, "%u %u\n", poll_time, update_time_limit);
		fclose(fp);

		next_poll_time = poll_time;
		next_poll_limit = update_time_limit;
	}
}

void cwmpMgmtSrvInformInterval()
{
	unsigned int byte;
	unsigned int delta = 0;
	time_t thisTime, nextTime;
	struct tm *now, next;
	int pollhour, pollmin;
	int polling_period = 0;
	char t[8], *endptr;
	char periodic_inform_time[32];
	
	if (!pUserData)
		return;

	pUserData->PeriodicInform = cwmp_cfg_get(CWMP_INFORM_ENABLE, &byte, sizeof(&byte)) ? byte : 1;

	if (!pUserData->PeriodicInform) {
		pUserData->InformIntervalCnt = 0;
		reset_cwmp_timer(pUserData, POLL_TIMER);
		return;
	}

	thisTime = time(NULL);
	if (thisTime < TIME_2004_JAN_01 && pollInfo.errCount < 10) {
		pollInfo.errCount++;
		cwmpMgmtSetPeriodicInformInterval(10);
		return;
	}

	get_next_polling_time();
	
	nvram_safe_get_r("dv_acs_polling_time", pollInfo.polling_time, sizeof(pollInfo.polling_time));
	nvram_safe_get_r("dv_acs_polling_range", t, sizeof(t));
	
	pollInfo.polling_range = strtol(t, NULL, 10) * 60;
	
	nvram_safe_get_r("dv_acs_polling_period", t, sizeof(t));
	if (!STRNCASECMP(t, "none"))
		pollInfo.polling_period = -99;
	else
		pollInfo.polling_period = strtol(t, NULL, 10);
	
	nvram_safe_get_r("dv_acs_polling_days", t, sizeof(t));
	pollInfo.polling_days = strtol(t, NULL, 10);


	if (pUserData->InformIntervalCnt <= 0 || (thisTime > TIME_2004_JAN_01 && pollInfo.errCount > 0)) {
		now = localtime(&thisTime);

		pollhour = strtoul(pollInfo.polling_time, &endptr, 10);
		endptr += 1;
		pollmin = strtoul(endptr, NULL, 10);
		next = *now;
		next.tm_hour = pollhour;
		next.tm_min = pollmin;
		next.tm_sec = 0;

		nextTime = mktime(&next);
		if (pollInfo.polling_period < 0) {
			if (pollInfo.polling_days != 0)
				polling_period = (unsigned int)soap_rand() % (pollInfo.polling_days + 1);
			else
				polling_period = 0;
		} else {
			polling_period = pollInfo.polling_period;
		}
		if (polling_period == 0 && thisTime >= nextTime)
			polling_period = 1;

		polling_period *= (24 * 3600);
		nextTime += polling_period;

		//PeriodicInformTime : TR-098
		snprintf(periodic_inform_time, 31, "%ld", nextTime);
		nvram_set("cwmp_periodic_time", periodic_inform_time);

		CWMPDBG(2, (stderr, "Next Polling Time = %d (%d)%s",
					polling_period, (int)nextTime, ctime((time_t *)&nextTime)));

		if (pollInfo.polling_range != 0)
			nextTime += ((unsigned int)soap_rand() % pollInfo.polling_range);
		
		CWMPDBG(2, (stderr, "Polling D-day     = (%d)%s", (int)nextTime, ctime((time_t *)&nextTime)));
		TLOG_PRINT("Polling D-day     = (%d)%s", (int)nextTime, ctime((time_t *)&nextTime));

		now = localtime((time_t *)&nextTime);
		syslog(LOG_INFO, DVLOG_MARK_ADMIN "Next periodic time : %04d-%02d-%02d-%02d:%02d:%02d", now->tm_year + 1900, now->tm_mon + 1,
		        now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);

		pollInfo.time_limit = nextTime + MAX_POLLING_RANGE;     //APACRTL-617

		CWMPDBG(2, (stderr, "Update Time Limt  = (%d)%s", (int)pollInfo.time_limit, ctime((time_t *)&pollInfo.time_limit)));

		set_next_polling_time(nextTime, pollInfo.time_limit);

		delta = (int)(nextTime - thisTime);
		pUserData->InformIntervalCnt = delta;
	}
	if (thisTime > TIME_2004_JAN_01)
		pollInfo.errCount = 0;

	cwmpMgmtSetPeriodicInformInterval(pUserData->InformIntervalCnt);
	CWMPDBG(1, (stderr, "next tick in %d sec\n", pUserData->InformIntervalCnt));
}

void cwmpMgmtSetSTUNPeriod(int period)
{
	if (pUserData == NULL)
		return;

	pUserData->STUNPeriod = period;
	set_cwmp_timer(pUserData, STUN_TIMER, pUserData->STUNPeriod, FROM_NOW);
}

void cwmpMgmtSetHPPeriod(int period)
{
	if (pUserData == NULL)
		return;

	//APACRTL-344
	pUserData->HPPeriod = period;
	pUserData->HPRange = period;
	set_cwmp_timer(pUserData, HOLEPUNCH_TIMER, pUserData->HPRange, FROM_NOW);
}

void cwmpMgmtSetHPttl(int ttl)
{
	if (pUserData == NULL)
		return;

	pUserData->HP_TTL = ttl;
}

void cwmpSetReboot(void)
{
	if (!pUserData)
		return;

	pUserData->Reboot = 1;
}

void cwmpMsgInit()
{
	// initialization message box.
	msgid = msgget((key_t) 1234, 0666);
	if (msgid != -1) {
		//              fprintf(stderr, "remove message queue %d\n", msgid);
		if (msgctl(msgid, IPC_RMID, NULL))
			CWMPDBG(3, (stderr, "failed to remove msgbox %d\n", errno));
	}

	usleep(500 * 1000);
	msgid = msgget((key_t) 1234, 0666 | IPC_CREAT);
	if (msgid == -1) {
		CWMPDBG(1, (stderr, "failed to create msgbox %d\n", errno));
	}

	return;
}

#if 1
static void printCookie(struct soap_cookie *c)
{
	while (c != NULL) {
		fprintf(stderr, "\n%s = %s\n", c->name, c->value);
		fprintf(stderr, "domain = %s\n", c->domain ? c->domain : "<empty>");
		fprintf(stderr, "path = %s\n", c->path ? c->path : "<empty>");
		fprintf(stderr, "expire = %d\n\n", (int)c->expire);

		c = c->next;
	}
}
#endif

static int get_stun_min_period(struct cwmp_userdata *ud)
{
	int rnd;
	char buf[20];

	int diff = 0;

	if (ud == NULL)
		return 3600;

	nvram_safe_get_r("cwmp_stun_max_period", buf, 16);
	ud->STUNMaxPeriod = buf[0] == 0 ? 3600 : atoi(buf);
	nvram_safe_get_r("cwmp_stun_min_period", buf, 16);
	ud->STUNMinPeriod = buf[0] == 0 ? 3600 : atoi(buf);

	if (ud->STUNMaxPeriod > ud->STUNMinPeriod && ud->STUNMaxPeriod > 0) {
		diff = (soap_rand() % (ud->STUNMaxPeriod - ud->STUNMinPeriod));
		//rnd = ud->STUNMinPeriod + (soap_rand() % (ud->STUNMaxPeriod - ud->STUNMinPeriod));
		if (diff > 0)
			rnd = ud->STUNMinPeriod + diff;
		else 
			rnd = ud->STUNMinPeriod - diff;
	} else
		rnd = ud->STUNMinPeriod;

	return rnd;
}

int ACSEventType(struct cpe_machine *m)
{
	//fprintf(stderr, "(ACS %d)",  m->cpe_recv_msgtype);
	switch (m->cpe_recv_msgtype) {
		case SOAP_TYPE_cwmp__Empty:
		case SOAP_TYPE_cwmp__EmptyResponse:
			return EVENT_RECV_EMPTY;

		case SOAP_TYPE_cwmp__InformResponse:
		case SOAP_TYPE_cwmp__TransferCompleteResponse:
		case SOAP_TYPE_cwmp__GetRPCMethodsResponse:
			/*jiunming,how to handle unknownresponse, just skip it????????? */
		case SOAP_TYPE_cwmp__UnKnownResponse:
			return EVENT_RECV_RSP;

		case SOAP_TYPE_cwmp__GetParameterValues:
		case SOAP_TYPE_cwmp__GetRPCMethods:
		case SOAP_TYPE_cwmp__SetParameterValues:
		case SOAP_TYPE_cwmp__GetParameterNames:
		case SOAP_TYPE_cwmp__SetParameterAttributes:
		case SOAP_TYPE_cwmp__GetParameterAttributes:
		case SOAP_TYPE_cwmp__AddObject:
		case SOAP_TYPE_cwmp__DeleteObject:
		case SOAP_TYPE_cwmp__Download:
		case SOAP_TYPE_cwmp__Reboot:
		case SOAP_TYPE_cwmp__Upload:
		case SOAP_TYPE_cwmp__FactoryReset:
			/*jiunming, handle unknow request-->send soap-fault message */
		case SOAP_TYPE_cwmp__UnKnown:
			return EVENT_RECV_REQ;

		case SOAP_TYPE_SOAP_ENV__Fault:
			return EVENT_RECV_FAULT;
		case SOAP_TYPE_cwmp__None:
			return EVENT_CLOSE;
	}

	return 0;
}

extern int running;

//APACRTL-453
extern int check_req_done;
extern int wait_req_cnt;

#define SEC_TO_NSEC (1000 * 1000 * 1000)

static time_t cal_timediff(struct timespec *ref)
{
	time_t sec = 0;
	struct timespec now;

	//Get heartbeat
	ygettime(&now);

	sec = now.tv_sec - ref->tv_sec;

	ref->tv_sec = now.tv_sec;
	ref->tv_nsec = now.tv_nsec;

	return sec;
}

static struct timespec *get_cwmp_timer(struct cwmp_userdata *ud, int type)
{
	struct timespec *timer = NULL;

	switch (type) {
		case POLL_TIMER:
			timer = &((ud->cwmp_timer).poll_ts);
			break;
		case STUN_TIMER:
			timer = &((ud->cwmp_timer).stun_ts);
			break;
		case HOLEPUNCH_TIMER:
			timer = &((ud->cwmp_timer).hp_ts);
			break;
		case IDLE_CHECK_TIMER:
			timer = &((ud->cwmp_timer).idle_check_ts);
			break;
		case REBOOT_TIMER:
			timer = &((ud->cwmp_timer).reboot_ts);
			break;
		case IDLE_RESET_TIMER:
			timer = &((ud->cwmp_timer).idle_reset_ts);
			break;
			break;

		default:
			break;
	}
	
	return timer;
}

void set_cwmp_timer(struct cwmp_userdata *ud, int type, time_t sec, int from)
{
	struct timespec *timer = get_cwmp_timer(ud, type);

	if (!timer)
		return;

	if (from == FROM_NOW) {
		ygettime(timer);
		timer->tv_sec += sec;
	} else
		timer->tv_sec += sec;
}

void set_cwmp_timer_from_ts(struct cwmp_userdata *ud, int type, time_t sec, struct timespec *ts)
{
	struct timespec *timer = get_cwmp_timer(ud, type);

	if (!timer || !ts)
		return;

	timer->tv_sec = ts->tv_sec + sec;
	timer->tv_nsec = ts->tv_nsec;
}

int check_cwmp_timer(struct cwmp_userdata *ud, int type)
{
	struct timespec *timer = get_cwmp_timer(ud, type);
	struct timespec now;

	if (!timer || timer->tv_sec <= 0)
		return NOT_SET;

	ygettime(&now);

	if ((now.tv_sec < timer->tv_sec) || 
			((now.tv_sec == timer->tv_sec) && (now.tv_nsec < timer->tv_nsec)))
		return NOT_PASSED;
	else
		return PASSED;
}

void reset_cwmp_timer(struct cwmp_userdata *ud, int type)
{
	struct timespec *timer = get_cwmp_timer(ud, type);
	
	if (!timer)
		return;
	
	timer->tv_sec = 0;
	timer->tv_nsec = 0;
}

static void check_notify_active(void)
{
	/*jiunming */
	int IsChange = 0;
	IsChange = notify_check_active();
	if (IsChange > 0) {
		CWMPDBG(1, (stderr, "notify_check_active return %d\n", IsChange));
		//set value_change flage to let the inform message include the "4 VALUE CHANGE" event code
		cwmpEvent(&cpe_client, EC_VALUECHANGE);
	}
}

static int process_msg_recv(struct soap *soap, struct message *msg, struct cwmp_userdata *ud, int *not_count)
{
	int cpe_state = check_cpe_state();
	char url[128] = "", method[8] = "";

	if (!cwmp_process_recv(soap, (int *)&msg->msg_datatype, &msg->msg_data)) {
		cpe_client.cpe_idle_time = 0;
		if (!strncmp(ud->url1, "http:", 5))
			snprintf(method, sizeof(method), "%s", "http");
		else
			snprintf(method, sizeof(method), "%s", "https");

		snprintf(url, sizeof(url), "%s://%s/%s", method, soap->cookies->domain,
				soap->cookies->path != NULL ? soap->cookies->path : "cwmp_d");

		printCookie(soap->cookies);
		soap_set_endpoint(soap, url);
		switch (ACSEventType(&cpe_client)) {
			case EVENT_RECV_EMPTY:
				CPEMachineNotify(&cpe_client, EVENT_RECV_EMPTY, 0);
				break;

			case EVENT_RECV_RSP:
				CPEMachineNotify(&cpe_client, EVENT_RECV_RSP, 0);
				break;

			case EVENT_RECV_REQ:
				CPEMachineNotify(&cpe_client, EVENT_RECV_REQ, 0);
				if (!cwmp_process_send(soap, url, "", msg->msg_datatype, msg->msg_data)) {
					soap_destroy(soap);
					soap_end(soap);	//free some dynamic memory allocation
				} else {
					soap_print_fault(soap, stderr);
					soap_destroy(soap);
					soap_end(soap);	//free some dynamic memory allocation
					CpeDisconnect(&cpe_client, 0);
				}
				break;

			case EVENT_RECV_FAULT:
				CPEMachineNotify(&cpe_client, EVENT_RECV_FAULT, 0);
				break;

			case EVENT_CLOSE:
				soap_connect(soap, url, "");
				CPEMachineNotify(&cpe_client, EVENT_SEND_REQ, 0);
				break;
		}
	} else {
		if (cpe_state != CPE_ST_DISCONNECTED) {
			if ((soap->status != 401) || (cpe_state != CPE_ST_AUTHENTICATING))
				soap_print_fault(soap, stderr);
		}

		// auth fail, may try another method.
		if ((soap->status == 401) && (cpe_state == CPE_ST_AUTHENTICATING)) {
			cpe_client.cpe_idle_time = 0;
			CPEMachineNotify(&cpe_client, EVENT_AUTHFAIL, 0);
		} else if ((soap->status == 403) && (cpe_state == CPE_ST_AUTHENTICATING)) {
			if (cpe_client.cpe_retry_count == 0) {
				unlink(PROVISION_PERIOD);
				const char *s = *soap_faultstring(soap);
				if (s && strstr(s, "bad nonce") == NULL)
					syslog(LOG_INFO, DVLOG_MARK_ADMIN "HGW MAC doesn't registered");
			}

			TLOG_PRINT("HGW authentication is failed.(Error Code: %d)", soap->status);	//for debug
			CpeDisconnect(&cpe_client, 0);
		} else {
			unlink(PROVISION_PERIOD);
			if (soap->status >= 400 && soap->status < 600) {
				soap->status = 0;
				soap->error = 0;
			}

			CPEMachineNotify(&cpe_client, EVENT_CLOSE, 0);
		}
	}

	return 0;
}

static int is_need_rc_restart(struct cwmp_userdata *ud, time_t sec)
{
	static int restart = 0;

	if (restart)
		return restart;

	//APACRTL-453 : Wait 3 sec before "rc restart"
	if (check_req_done == 1) {
		if (wait_req_cnt > 3) {
			if (!need_reboot_apply) {
				running = 0;
				nvram_commit();
				TLOG_PRINT("Apply Setting\n"); 
				unlink("/tmp/.wlcmd_scan_lock");
				yexecl(NULL, "/bin/rc restart");
				restart = 1;
			} else {
				TLOG_PRINT("Save and Reboot\n"); 
				cwmp_SaveReboot(ud, 1, 1);
			}
		}

		if (check_cpe_state() == CPE_ST_DISCONNECTED)
			wait_req_cnt += sec;
		else {
			if (!need_reboot_apply)
				check_req_done = 0;
			wait_req_cnt = 0;
		}
	}

	return restart;
}

int cwmp_process(struct soap *soap, const char *soap_endpoint, const char *soap_action)
{
	int run = 1;
	struct cwmp_userdata *ud = cpe_client.cpe_user;	//->user;
	struct message msg;

	int ret = 0;
	int not_count = 0;
	unsigned int prov_stat = 0;
	time_t sec = 0; 
	struct timespec ref;
	IdleResetCount = 0;
	
	memset(&pollInfo, 0, sizeof(pollInfo));
	cwmpMgmtSrvInformInterval();  // schedule the next inform.
	ygettime(&ref);

	IdleResetCount = 0;

	while (run) {
		ret = msgrcv(msgid, (void *)&msg, MSG_SIZE, 0, 0);
		if ((-1) == ret) {
			if (errno == EINTR) {	// timeout signal
				usleep(100 * 1000);
				continue;
			} else {
				CWMPDBG(1, (stderr, "msgrcv returns %d\n", ret));
				return -1;
			}
		}

		switch (msg.msg_type) {
			case MSG_TIMER:
				// must continue to read since signal is not queued.
				change_mainloop_status(PROCESS_IN_BUSY);

				if (not_count) {
					ygettime(&ref);
					not_count = 0;
				}

				sec = cal_timediff(&ref);

				if (is_need_rc_restart(ud, sec)) {
					change_mainloop_status(PROCESS_IN_IDLE);
					continue;
				}

				prov_stat = get_prov_stat(ud);

				// check if the machine is ready to run.
				if (check_cpe_state() == CPE_ST_DISCONNECTED) {
					if (cpe_client.cpe_retryCountdown) {
						if (cpe_client.cpe_events) {
							cpe_client.cpe_retryCountdown -= sec;
							if (cpe_client.cpe_retryCountdown <= 0) {
								cpe_client.cpe_retryCountdown = 0;
								CPEMachineNotify(&cpe_client, EVENT_SEND_REQ, (void *)0);
							}
						} else {
							cpe_client.cpe_retry_count = 0;
							cpe_client.cpe_retryCountdown = 0;
						}
					} else if (cpe_client.cpe_events) {
						TLOG_PRINT("Notify Event 0x%08x\n", cpe_client.cpe_events);
						CPEMachineNotify(&cpe_client, EVENT_SEND_REQ, (void *)0);
					}
				} else {
					if (prov_stat != CFG_DOWN_START)
						cpe_client.cpe_idle_time += sec;

					if (cpe_client.cpe_idle_time > cpe_client.cpe_idle_timeout) {
						//APACRTL-601, APACQCA-417
						TLOG_PRINT("cpe idle timeout!!!(%d)(%d).\n", cpe_client.cpe_idle_time, ud->HoldRequests);
						if (ud->HoldRequests || (cpe_client.cpe_events & EC_TRANSFER)) {
							ud->HoldRequests = 0;

							//APACRTL-601, APACQCA-442
							if (ud->PeriodicInform && (ud->InformIntervalCnt <= 0))
								cwmpMgmtSrvInformInterval();

							if (access("/tmp/prov_done", F_OK) != 0) {
								syslog(LOG_INFO, DVLOG_MARK_ADMIN "Config file download error");
								yecho("/tmp/prov_done", "1");
							}
							control_led_to_upgrade(UPGRADING_COMPLETE);
						}

						CPEMachineNotify(&cpe_client, EVENT_CLOSE, (void *)0);
					}

					if (check_cpe_state() == CPE_ST_CONNECTED
							&& (ud->DLCommandKey && !nv_strcmp(ud->DLCommandKey, "cmdk_dnld_cfg"))
							&& (ud->DownloadState == DOWNLD_FINISH || ud->DownloadState == DOWNLD_ERROR)) {
						ud->DownloadState = DOWNLD_NONE;
						cpe_client.cpe_events |= EC_TRANSFER;
						CPEMachineNotify(&cpe_client, EVENT_SEND_REQ, (void *)0);
						//cpe_client.cpe_events &= (~EC_TRANSFER);
					}
				}

				//APACQCA-442 : Fix Bug
				ud->STUNPeriod -= sec;
				if (check_cwmp_timer(ud, STUN_TIMER) == PASSED) {
					syslog(LOG_WARNING, "KeepAlive " H_SEND);
					ud->STUNPeriod = get_stun_min_period(ud);
					set_cwmp_timer(ud, STUN_TIMER, ud->STUNPeriod, FROM_OLD_TIMER);
					send_stun_msg(&ud->stunfd, 0);
				}

				if (ud->STUNEnable) {
					ud->HPPeriod -= sec;
					if (check_cwmp_timer(ud, HOLEPUNCH_TIMER) == PASSED) {
						ud->HPPeriod = ud->HPRange;
						set_cwmp_timer(ud, HOLEPUNCH_TIMER, ud->HPRange, FROM_OLD_TIMER);
						send_stun_msg(&ud->stunfd, ud->HP_TTL);
					}
				}

				if (access("/var/tmp/cwmp/conn", F_OK) == 0) {
					CWMPDBG(1, (stderr, "connection request .... state=%d\n", cpe_client.cpe_state));
					unlink("/var/tmp/cwmp/conn");
					cpe_client.cpe_conn_request = 1;
					cwmpEvent(&cpe_client, EC_CONNREQUEST);
				}

				check_notify_active();

				if (ud->PeriodicInform) {
					if (next_poll_invalid()) {
						// Set next polling time.
						cwmpMgmtSrvInformInterval();
					}

					if (ud->InformIntervalCnt > 0) {
						ud->InformIntervalCnt -= sec;

						//ud->InformIntervalCnt : Interval count must have at least 1sec.
						if (ud->InformIntervalCnt <= 0)
							ud->InformIntervalCnt = 0;
					}

					if (check_cwmp_timer(ud, POLL_TIMER) == PASSED) {
						reset_cwmp_timer(ud, POLL_TIMER);
						ud->InformIntervalCnt = 0;

						if (ud->InformIntervalCnt == 0 && pollInfo.errCount > 0)
							cwmpMgmtSrvInformInterval();

						if (ud->InformIntervalCnt == 0) {
							init_check_idle_service(&pollInfo);
							syslog(LOG_INFO, DVLOG_MARK_ADMIN "Periodic Provisioning process is Started");
							cwmpEvent(&cpe_client, EC_PERIODIC);
							set_cwmp_timer(ud, IDLE_CHECK_TIMER, 0, FROM_NOW);
							yfecho(PROVISION_PERIOD, O_WRONLY|O_CREAT|O_TRUNC, 0644, "1");
						}
					}
				}

				prov_stat = get_prov_stat(ud);

				if (check_cwmp_timer(ud, REBOOT_TIMER) == PASSED) {
					reset_cwmp_timer(ud, REBOOT_TIMER);
					syslog(LOG_WARNING, "TR069 Rebooting (RebootTimer == 0)");
					kill(1, SIGTERM);
				}

#define HOLDREQUEST_TIMEOUT			1600
				if (ud->HoldRequestTime > 0 && ud->HoldRequests) {
					clock_t now = centisecond();
					unsigned int gap = 0;

					if (now > ud->HoldRequestTime)
						gap = now - ud->HoldRequestTime;
					else
						gap = (LONG_MAX - ud->HoldRequestTime) + now +1;

					if (gap > HOLDREQUEST_TIMEOUT) {
						printf("*** BUG HoldRequests Now Close...\n");
						TLOG_PRINT("****** HoldRequests Now Close...\n");
						soap_closesock(soap);
						soap_destroy(soap);
						soap_end(soap);
						soap_done(soap);

						cpe_client.cpe_events = 0;
						cpe_client.cpe_event_queue = 0;
						ud->EventCode = 0;

						// reset machine
						cpe_client.cpe_idle_time = 0;
						cpe_client.cpe_auth_count = 0;
						cpe_client.cpe_auth_type = CPE_AUTH_NONE;
						change_cpe_state(CPE_ST_DISCONNECTED);
						ud->HoldRequests = 0;
						ud->HoldRequestTime = 0;

						//APACQCA-465
						if (access("/tmp/prov_done", F_OK) != 0) {
							syslog(LOG_INFO, DVLOG_MARK_ADMIN "Config file download error");
							yecho("/tmp/prov_done", "1");
						}

						control_led_to_upgrade(UPGRADING_COMPLETE);

						if (ud->PeriodicInform && (ud->InformIntervalCnt <= 0)) {
							fprintf(stderr, "****** HoldRequests Now Close... IN POLLING\n");
							TLOG_PRINT("****** HoldRequests Now Close... IN POLLING\n");
							cwmpMgmtSrvInformInterval();
						}
					}
				}

				change_mainloop_status(PROCESS_IN_IDLE);
				break;
			case MSG_RECV:
				change_mainloop_status(PROCESS_IN_BUSY);
				process_msg_recv(soap, &msg, ud, &not_count);
				change_mainloop_status(PROCESS_IN_IDLE);
				break;
			case MSG_EVENT_CONNREQ:
				change_mainloop_status(PROCESS_IN_BUSY);
				cpe_client.cpe_conn_request = 1;
				cwmpEvent(&cpe_client, EC_CONNREQUEST);
				change_mainloop_status(PROCESS_IN_IDLE);
				break;
			case MSG_CMD_IMPOLL:
				CWMPDBG(1,(stderr, "IPOLL recved\n"));
				syslog(LOG_WARNING, "Received Immediate Poll CMD.");
				//APACRTL-145
				is_iboot = 0;
				cwmpMgmtSetImmediatePolling(1);
				break;
			case MSG_CMD_IMBOOT:	//APACRTL-145
				CWMPDBG(1,(stderr, "IBOOT recved\n"));
				syslog(LOG_WARNING, "Received Immediate BOOT CMD.");
				is_iboot = 1;
				cwmpMgmtSetImmediatePolling(1);
				break;
			case MSG_CMD_IDLERESET:
				CWMPDBG(1,(stderr, "IRESET recved\n"));
				syslog(LOG_WARNING, "Received Idle Reset CMD.");
				if (cwmpMgmtSetIdleReset(1))
					cwmpSetReboot();    //dummy code??
				break;
			case MSG_CMD_POLLTEST:
				CWMPDBG(1,(stderr, "POLLTEST recved\n"));
				clear_cached_polling_time();
				break;
			case MSG_CMD_GETSTATUS:
				get_prov_status(soap);
				break;
			case MSG_SEND:
				CWMPDBG(1,(stderr, "not process type %ld\n", msg.msg_datatype));
				break;
			default:
				CWMPDBG(1, (stderr, "unknown event type %ld\n", msg.msg_type));
				break;		
		}

		//usleep(100 * 1000);
	}

	msgctl(msgid, IPC_RMID, 0);

	return 0;
}

void init_check_idle_service(struct pollInfo *info)
{
	char tmp[128] = {0, };
	
	info->cumulative_pkt = 0xffffffff;
	info->interval = 0;
	info->fPeriodic = 1;
	info->control_pkt = atoi(nvram_safe_get_r("dv_acs_control_traffic", tmp, sizeof(tmp)));
}

static inline uint64 get_delta(uint64 prev, uint64 now)
{
	if (prev > now) {
		// overflow
		return (0xffffffffffffffffULL - prev) + 1 + now;
	} else {
		return now - prev;
	}
}

uint64 wan_port_tx;

static uint64 get_forward_packet_count(int init)
{
	uint64 bytes=0, sum=0;
	int found=0;
	char *ifname=NULL;
	
	ifname = get_wbr_ifname();
	if (ifname) {
		fprintf(stderr, "ifname : %s\n", ifname);
		bytes = get_dev_stat_info(ifname, 1);
		found = 1;
	} else {
		// WBR not running, tx traffic from port mib
		// (Bridge, NAT)
		//APACRTL-331
		if (get_port_traffic(WAN_PORT, &bytes, 1)==0) {
			found = 1;
		}
	}

	if (found) {
		if (init)
			sum = 0;
		else
			sum = get_delta(wan_port_tx, bytes);
		printf("port:%d, tx traffic:%llu n %llu p %llu from:%s\n", WAN_PORT, sum, bytes, wan_port_tx, ifname?ifname:"WAN");
		wan_port_tx = bytes;
	} else {
		printf("get port traffic fail from:%s\n", ifname?ifname:"WAN");
	}

	return sum;
}

int check_idle_service(struct pollInfo *info)
{
	uint64 cur_fwd_pkt;
	int ret = 0, init;
	int join_cnt = 0;
	struct timespec now;

	if (info->fPeriodic == 0)
		return 1;

	//APACRTL-145 : Immediate boot -> Do not idle check!!
	if (is_iboot) {
		CWMPDBG(1, (stderr, "Immediately boot : Force upgrading firmware.\n"));
		syslog(LOG_INFO, DVLOG_MARK_ADMIN "Immediately boot : Force upgrading firmware.\n");
		is_iboot = 0;
		return 1;
	}

	if (info->cumulative_pkt != 0xffffffff)
		init = 0;
	else
		init = 1;

	cur_fwd_pkt = get_forward_packet_count(init);

	if (nvram_match_r("dv_forced_upgrade", "1"))
		join_cnt = 0;
	else
		join_cnt = get_mcast_join_count();

	if (info->cumulative_pkt != 0xffffffff && cur_fwd_pkt < info->control_pkt && join_cnt == 0)
		ret = 1;

	if (info->cumulative_pkt != 0xffffffff) {
		syslog(LOG_INFO, DVLOG_MARK_ADMIN "Checking traffic now, 1  minutes passed [ packet flow:%llu bytes, %d group is joined ]", cur_fwd_pkt, join_cnt);
	}

	ygettime(&now);
	CWMPDBG(1, (stderr, "[%ld.%09ld] Control :%d, transmitpkt:%llu atc join =%d, ret=%d\n", now.tv_sec, now.tv_nsec, info->control_pkt, cur_fwd_pkt, join_cnt, ret));

	info->cumulative_pkt = cur_fwd_pkt;

	return (ret);
}

//wan tx cnt debug
static char *get_time_str(void)
{
	static char str[80];
	time_t t;
	struct tm *tmp;

	t = time(NULL);
	tmp = localtime(&t);
	if (tmp == NULL)
		return "TM_ERR";
	strftime(str, sizeof(str), "%m/%d %H:%M:%S", tmp);
	return str;
}

void *cwmp_wan_tx_test(void *data)
{
	get_forward_packet_count(1);
	while (1) {
		sleep(30);
		fprintf(stderr, "%s: ", get_time_str());
		get_forward_packet_count(0);
	}
	return NULL;
}

void control_led_to_upgrade(int phase)
{
	switch (phase) {
		case UPGRADING_COMPLETE:
			if (IS_WLBRIDGE_MODE)
				yecho("/proc/gpio", "l_blink_3000");
			else
				yecho("/proc/gpio", "l_on");
			break;

		case UPGRADING_PHASE1:	
			yecho("/proc/gpio", "l_blink_1000");
			break;

		case UPGRADING_PHASE2:	
			yecho("/proc/gpio", "l_blink_200");
			break;

		case UPGRADING_PHASE3:	
			yecho("/proc/gpio", "l_blink_200");
			break;

		default:
			CWMPDBG(2, (stderr, "%s() : phase %d\n", __FUNCTION__, phase));
			break;
	}				/* -----  end switch  ----- */
}

static void get_prov_status(struct soap *soap)
{
	struct cwmp_userdata *ud = cpe_client.cpe_user;	//->user;
	const char *provstat_file = "/tmp/cwmp_provstat";
	FILE *dbg_fp;

	if (access(provstat_file, F_OK) == 0)
		unlink(provstat_file);

	dbg_fp = fopen(provstat_file, "w");
	
	if (dbg_fp) {
		fprintf(dbg_fp, "==========\n");
		fprintf(dbg_fp, "Polling IntervalCnt : %d\n", ud->InformIntervalCnt);
		fprintf(dbg_fp, "ud->DLFaultCode : %d\n", ud->DLFaultCode);
		fprintf(dbg_fp, "ud->FaultCode : %d\n", ud->FaultCode);
		fprintf(dbg_fp, "cpe_state : %s\n", strCPEState[check_cpe_state()]);
		fprintf(dbg_fp, "cpe_client.events : 0x%08x\n", cpe_client.cpe_events);
		fprintf(dbg_fp, "cpe_client.event_queue : 0x%08x\n", cpe_client.cpe_event_queue);
		fprintf(dbg_fp, "ud->DownloadState : %d\n", ud->DownloadState);
		fprintf(dbg_fp, "Download Image Flag : %d\n", ud->fDownloadImage);
		fprintf(dbg_fp, "Download Config Flag : %d\n", ud->fDownloadConfig);
		fprintf(dbg_fp, "isNeedUpdate() : %d\n", isNeedUpdate());
		fprintf(dbg_fp, "==========\n");
		fprintf(dbg_fp, "Force Upgrading(Immediate Boot) Flag : %d\n", is_iboot);
		fprintf(dbg_fp, "Join count : %d\n", get_mcast_join_count());
		fprintf(dbg_fp, "Current pkt count : %llu\n", get_forward_packet_count(0));
		fprintf(dbg_fp, "==========\n");
		fclose(dbg_fp);
	}
}

//APACRTL-337
int check_wan_ip_changed(int write_changed)
{
	char curr[32] = "", old[32] = "";
	int len = 0;
	int ret;
	FILE *f = NULL;

	curr[0] = 0;
	f = fopen(WAN_IP_CACHE, "r");
	if (f) {
		fgets(curr, sizeof(curr), f);
		ydespaces(curr);
		fclose(f);
	}

	f = fopen(CWMP_IP_FILE, "r");
	if (f) {
		fgets(old, sizeof(old), f);
		ydespaces(old);
		fclose(f);
		ret = (nv_strcmp(curr, old) == 0) ? 0 : 1;
	} else {
		len = STRLEN(curr);
		strncpy(old, curr, len);
		old[len] = '\0';
		ret = 1;
		write_changed = 1;
	}

	if (write_changed) {
		unlink(CWMP_IP_FILE);
		f = fopen(CWMP_IP_FILE, "w");
		if (f) {
			fprintf(f, "%s", curr);
			fclose(f);
		}
	}

	return ret;
}

#ifdef __cplusplus
}
#endif
#endif	/* __CWMPCLIENTLIB_C__ */
