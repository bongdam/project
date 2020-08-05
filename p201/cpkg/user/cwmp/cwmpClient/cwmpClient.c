#ifndef __CWMPCLIENT_C__
#define __CWMPCLIENT_C__

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>
#include "cwmpGlobal.h"
#include "cwmpClientLib.h"
#include "cwmp.nsmap"
#include <bcmnvram.h>
#include <libytool.h>
#include <shutils.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <syslog.h>
#include <hanguel.h>
#include <dvflag.h>

#include "bcm_param_api.h"
#include <cwmp_define.h>

#define CWMP_FLAG 0
#define CWMP_FLAG_DEBUG_MSG 1
#define CWMP_FLAG_CERT_AUTH 2
#define CWMP_FLAG_SENDGETRPC 3
#define CWMP_FLAG_SKIPMREBOOT 4
#define CWMP_FLAG_DELAY 5

#ifdef WITH_OPENSSL
#define CA_FNAME "/etc/cert/allcerts.pem"	//APACRTL-564
#endif

#ifdef CWMP_ENABLE_SSL
#ifdef WITH_POLARSSL
int certificate_verify_cb(int ok);
#else
int certificate_verify_cb(int ok, X509_STORE_CTX * store);
#endif
#endif				/*#ifdef CWMP_ENABLE_SSL */

int gNeedSendGetRPC = 0;
int gNeedSSLAuth = 0;
int gSkipMReboot = 0;
int gStartPing = 0;
int running = 1;
int check_req_done = 0;	//APACRTL-453
int wait_req_cnt = 0;	//APACRTL-453
int need_reboot_apply = 0;
struct soap serverSoap;
struct cpe_machine cpe_client;

extern int msgid;
extern struct pollInfo pollInfo;
extern void cwmpMgmtSetSTUNPeriod(int period);

int certificate_setup(struct soap *soap, int use_cert);

unsigned int centisecond(void)
{
	struct timespec ts;
	ygettime(&ts);
	return (unsigned int)((ts.tv_sec * 100) + (ts.tv_nsec / 10000000));
}

void wait_nat_done()
{
	int count = 0;

	do {
		if (access("/tmp/auto_nat_done", F_OK) == 0)
			break;
		count++;
		sleep(1);
	} while (count < 10);
}

static void cwmpSetRetryWait(struct cpe_machine *m);

/***********************************************************************/
/* handle connection request notification */
/***********************************************************************/

int cwmp_web_get(struct soap *soap)
{
	int result = 0;
	struct message msg;

#if 0
	struct cwmp_userdata *data = soap->user;
	int  req = 0;

	if (!soap->authrealm ||
			!soap->userid ||
			nv_strcmp(soap->userid, data->conreq_username) ||
			nv_strcmp(soap->authrealm, data->realm) ||
#ifdef CWMP_ENABLE_DIGEST
			(req = http_da_verify_get(soap, data->conreq_password))
#else
			(req = nv_strcmp(soap->passwd, data->conreq_password))
#endif
	) {
		soap->authrealm = data->realm;
#ifdef __DEBUG_PRINT__
		fprintf(stderr, "[%s():%d data->realm=[%s]\n", __FUNCTION__, __LINE__, data->realm);
#endif
		soap->error = 401;
		//soap->status = 401;
		soap_send_fault(soap);
		soap_end(soap);
		return 401;
	}
#endif

	soap_begin_count(soap);
	soap_end_count(soap);
	// wt-121v8-1.21
	if (check_cpe_state() != CPE_ST_DISCONNECTED) {
		result = 503;
	} else {
		msg.msg_type = MSG_EVENT_CONNREQ;
		msgsnd(msgid, (void *)&msg, MSG_SIZE, 0);
		result = 200;
	}

	soap_response(soap, result);	// HTTP response header with text/html
	soap_end_send(soap);
	soap_closesock(soap);

	CWMPDBG(2, (stderr, "ConnectRequest Response: %d\n", result));
	return SOAP_OK;
}

int cwmp_webserver_init(struct soap *web_soap, void *data)
{
	int m;			/* master and slave sockets */
	unsigned int uVal;
	unsigned short port;
	int cnt = 0;

	running = 1;
	soap_init(web_soap);
	web_soap->version = 1;
	//soap_set_version(web_soap, 1);
	web_soap->bind_flags = SO_REUSEADDR;
	web_soap->imode |= SOAP_IO_KEEPALIVE;
	web_soap->mode |= SOAP_IO_KEEPALIVE;
	//support UTF-8
	soap_set_imode(web_soap, SOAP_C_UTFSTRING);
	soap_set_omode(web_soap, SOAP_C_UTFSTRING);
	web_soap->fget = cwmp_web_get;
	web_soap->fpost = NULL;
	web_soap->user = data;

#ifdef CWMP_ENABLE_DIGEST
	//Algorithm -> MD5(Only Use)
	//if (soap_register_plugin_arg(web_soap, http_da, http_da_md5())) { 
	if (soap_register_plugin(web_soap, http_da)) { 
		soap_print_fault(web_soap, stderr);	// failed to register
		return -1;
	}
#endif

	port = cwmp_cfg_get(CWMP_CPE_SERVER_PORT, &uVal, sizeof(&uVal)) ? uVal : 7547;

	do {
		m = soap_bind(web_soap, NULL, port, 32);

		if (m < 0) {
			cnt++;
			sleep(6);
		}
	} while ((cnt < 20) && (m < 0));
	if (m < 0) {
		soap_print_fault(web_soap, stderr);
		return -1;
	}

	return 0;
}

extern int handle_message(int *, unsigned short *, char *, int);

enum {
	DO_WORK,
	TIMEOUT,
	ERROR
};

#define SEC_TO_NSEC (1000 * 1000 * 1000)

time_t ts_timediff(struct timespec *result, struct timespec *old, struct timespec *new)
{
	result->tv_sec = new->tv_sec - old->tv_sec;
	if (new->tv_nsec >= old->tv_nsec)
		result->tv_nsec = new->tv_nsec - old->tv_nsec;
	else {
		result->tv_nsec = (new->tv_nsec + SEC_TO_NSEC) - old->tv_nsec;
		result->tv_sec -= 1;
	}

	return result->tv_sec;
}

int cwmp_timer_loop(int sock)
{
	int ret = ERROR;
	int fdset = 0;
	fd_set rfds;
	time_t timeout_sec = 0;
	time_t timeout_nsec = 990 * 1000 * 1000;

	static struct timespec ts = {0, 0};
	struct timespec remain_ts = {0, 0};
	static struct timespec next_timeout_ts = {0, 0};

	if (next_timeout_ts.tv_sec == 0 || (ts.tv_sec < 0 || ts.tv_nsec < 0)) {
		ygettime(&next_timeout_ts);
		next_timeout_ts.tv_sec += timeout_sec;
		next_timeout_ts.tv_nsec += timeout_nsec;
		if (next_timeout_ts.tv_nsec >= SEC_TO_NSEC) {
			next_timeout_ts.tv_sec += 1;
			next_timeout_ts.tv_nsec -= SEC_TO_NSEC;
		}
		
		ts.tv_sec = timeout_sec;
		ts.tv_nsec = timeout_nsec;
	}

	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);

retry:
	ret = pselect(sock + 1, &rfds, NULL, NULL, &ts, NULL);
	if (ret > 0) {
		fdset = FD_ISSET(sock, &rfds);
		if (fdset) {
			ygettime(&remain_ts);
			ts_timediff(&ts, &remain_ts, &next_timeout_ts);
			ret = DO_WORK;
		}
	} else if ((ret < 0) && (errno != EINTR)) {
		fprintf(stderr, "%s() socket Error:%s\n", __FUNCTION__, strerror(errno));
	} else {
		if ((ret < 0) && (errno == EINTR)) {
			goto retry;
		} else {
			next_timeout_ts.tv_sec += timeout_sec;
			next_timeout_ts.tv_nsec += timeout_nsec;
			if (next_timeout_ts.tv_nsec >= SEC_TO_NSEC) {
				next_timeout_ts.tv_sec += 1;
				next_timeout_ts.tv_nsec -= SEC_TO_NSEC;
			}

			ts.tv_sec = timeout_sec;
			ts.tv_nsec = timeout_nsec;
		}

		ret = TIMEOUT;
	}

	return ret;
}

static void send_timer_msg(void)
{
	struct message msg;
	int ret = 0;

	if (check_mainloop_status() == PROCESS_IN_IDLE && !cpe_client.cpe_hold) {
		msg.msg_type = MSG_TIMER;
		ret = msgsnd(msgid, (void *)&msg, MSG_SIZE, 0);
		if (ret < 0) {
			CWMPDBG(1, (stdout, "msgsnd returns %d(msgid : %d type : %ld)\n", ret, msgid, msg.msg_type));
			perror("msgsnd ");
		}
	}
}

int cwmp_udp_loop(struct cwmp_userdata *ud)
{
	socklen_t fromLen;
	struct sockaddr_in from;
	struct message msg;

	char buf[1024];
	int recvLen, ret;
	int publicip;
	unsigned short mappedPort;

	while (1) {
		ret = cwmp_timer_loop(ud->stunfd);
		if (ret == DO_WORK) {
			fromLen = sizeof(from);
			memset(buf, 0, sizeof(buf));
			recvLen = recvfrom(ud->stunfd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromLen);
			if (recvLen > 0) {
				if (wait_req_cnt > 3)	//APACRTL-453 : Restart AP, so Do not accept connection from Server.
					break;

				ret = handle_message(&publicip, &mappedPort, buf, recvLen);
				if (ret == 0) {
					if (check_cpe_state() == CPE_ST_DISCONNECTED) {
						TLOG_PRINT("Recv UDP ConnectionReqeust(%d)\n", ntohs(ud->MappedPort));
						msg.msg_type = MSG_EVENT_CONNREQ;
						msgsnd(msgid, (void *)&msg, MSG_SIZE, 0);
					}
				} else {
					struct in_addr map_ip;
					map_ip.s_addr = publicip;
					TLOG_PRINT("STUN : KeepAlive - Binding Response(%s/%hu)\n", inet_ntoa(map_ip), ntohs(mappedPort));
					ud->MappedAddr = publicip;
					ud->MappedPort = mappedPort;
				}
			}
		} else if (ret == TIMEOUT) {
			send_timer_msg();
		} else {	//error
			break;
		}
	}

	if (ud->stunfd > 0)
		close(ud->stunfd);

	return 0;
}

int cwmp_webserver_loop(struct soap *web_soap)
{
	int s;
	int ret = 0;

	while (running) {
		ret = cwmp_timer_loop(web_soap->master);
		if (ret == DO_WORK) {
			s = soap_accept(web_soap);
			CWMPDBG(1, (stderr, "Socket connection successful: slave socket = %d\n", s));
			if (s < 0 || wait_req_cnt > 3) {
				soap_print_fault(web_soap, stderr);
				soap_end(web_soap);
				if (wait_req_cnt > 3)	//APACRTL-453 : Restart AP, so Do not accept connection from Server.
					break;
				else
					continue;
			}

			soap_begin(web_soap);
			soap_begin_recv(web_soap);
			soap_end_recv(web_soap);
			soap_end(web_soap);
		} else if (ret == TIMEOUT) {
			send_timer_msg();
		} else if (ret == ERROR) {
			soap_print_fault(web_soap, stderr);
			soap_end(web_soap);
			break;
		}
	}
	soap_done(web_soap);
	return 0;
}

/***********************************************************************/
/* web client */
/***********************************************************************/
void cwmpDiagnosticDone()
{
	cwmpEvent(&cpe_client, EC_DIAGNOSTICS);
}

void cwmpCpeHold(struct cpe_machine *m, int holdit)
{
	m->cpe_hold = holdit;
}

void cwmpSetCpeHold(int holdit)
{

	cwmpCpeHold(&cpe_client, holdit);
}

void cwmpEvent(struct cpe_machine *m, unsigned int event)
{
	int cpe_state = check_cpe_state();

	if (cpe_state == CPE_ST_DISCONNECTED) {
		m->cpe_events |= event;
	} else {
		m->cpe_event_queue |= event;
	}

	// WT121v8-1.45, New event triggers retry
	// if (m->cpe_retryCountdown > 2) {
	//         m->cpe_retryCountdown = 1;
	// }

	if (event & EC_BOOTSTRAP) {
		if (cpe_state == CPE_ST_DISCONNECTED) {	// discard all other event
			m->cpe_events = EC_BOOTSTRAP;
		} else {
			fprintf(stderr, "(TO-DO) Bootstrap while CPE running\n");
		}
	}
}

void cwmpSendEvent(unsigned int event)
{
	cwmpEvent(&cpe_client, event);
}

void cwmpClearEvent(struct cpe_machine *m, unsigned int event)
{
	m->cpe_events &= (~event);
}

static void CpeResetRetry(struct cpe_machine *m)
{
	CWMPDBG(3, (stderr, "Retry reseted\n"));
	m->cpe_retry_count = 0;
	m->cpe_retryCountdown = 0;
}

static void CpeStartRetry(struct cpe_machine *m)
{
	m->cpe_retry_count++;
	cwmpSetRetryWait(m);
}

extern int isNeedUpdate(void);
extern int exist_periodic_reset_flag(void);	//APACQCA-59
extern int exist_periodic_log_flag(void);
extern void reset_rate_limit_set_count(void);
extern int get_rate_limit_set_count(void);

void CpeDisconnect(struct cpe_machine *m, int retry)
{
	struct soap *pSoap = &m->cpe_soap;
	struct cwmp_userdata *data = m->cpe_user;

	//APACRTL-344
	int stun_min_period = 0;
	int stun_max_period = 0;

#ifdef CWMP_ENABLE_DIGEST
	if (m->cpe_auth_type == CPE_AUTH_DIGEST) {
		http_da_release(pSoap, &m->cpe_da_info);
	}
#endif

	// XXX : 추후에 서버로 부터 HTTP status code를 수신하면 다시 설정됨.
	pSoap->status = 0;
	pSoap->error = 0;

	soap_closesock(pSoap);
	soap_destroy(pSoap);
	soap_end(pSoap);
	soap_done(pSoap);

	m->cpe_events |= m->cpe_event_queue;
	m->cpe_event_queue = 0;
	
	//APACRTL-552, APACRTL-611
	if (m->cpe_events & (EC_AUTOTRANSFER | EC_TRANSFER | EC_CONNREQUEST))
		retry = 0;

	// reset machine
	m->cpe_idle_time = 0;
	m->cpe_auth_count = 0;
	m->cpe_auth_type = CPE_AUTH_NONE;
	change_cpe_state(CPE_ST_DISCONNECTED);
	m->cpe_SendGetRPC = gNeedSendGetRPC;
	data->HoldRequests = 0;
	data->HoldRequestTime = 0;

#if 1
	if (retry) {
#else
	if (retry && m->cpe_retry_count < 2) {
#endif
		CpeStartRetry(m);
	} else {
		CpeResetRetry(m);
		m->cpe_events = 0;
		m->cpe_event_queue = 0;
		data->EventCode = 0;
	}

	//Wait prov_done when ap process booting sequence.
	if (access("/tmp/prov_done", F_OK) != 0) {
		syslog(LOG_INFO, DVLOG_MARK_ADMIN "HGW is working properly");
		yecho("/tmp/prov_done", "1");
	}

	control_led_to_upgrade(UPGRADING_COMPLETE);

	//APACRTL-344
	stun_max_period = nvram_atoi("cwmp_stun_max_period", 3600);
	stun_min_period = nvram_atoi("cwmp_stun_min_period", 3600);
	if ((data->STUNMinPeriod != stun_min_period) || (data->STUNMaxPeriod != stun_max_period))
		cwmpMgmtSetSTUNPeriod(5);

	TLOG_PRINT("Disconnect Session(%d)\n", retry);

	if (data->Reboot) {
		fprintf(stderr, "<b>");
		fprintf(stderr, "system reboot\n");
		//close socket
		data->Reboot = 0;
		cwmp_SaveReboot(data, 1, 1);    //APACRTL-483
	}

	if (data->FactoryReset) {
		fprintf(stderr, "<f>");
		fprintf(stderr, "system FactoryReset\n");
		data->FactoryReset = 0;
		//close socket
		factoryreset_reboot();
	}

	if (data->Restart) {	//APACRTL-452
		int res = 0;
		int restart = data->Restart;
		int set_wan_cnt = 0;

		res = set_encrypt_mode();
		restart += res;

		res = set_wlchannel();
		restart += res;

		set_wan_cnt = set_wan();
		if (set_wan_cnt != WAN_MO_NOT_SET)
			restart += set_wan_cnt;

		res = set_lan();
		restart += res;

		//APACRTL-602
		set_wl_rate_limit();

		if (restart == get_rate_limit_set_count()) {
			reset_rate_limit_set_count();
			restart = 0;
			nvram_commit();
		}

		if (restart) {
			if (set_wan_cnt != WAN_MO_NOT_SET) {
				if (set_wan_cnt < 0)
					need_reboot_apply = 0;
				else
					need_reboot_apply = 1;
			} else
				set_wan_cnt = 0;

			check_req_done = 1;	//APACRTL-453
		} else
			check_req_done = 0;	//APACRTL-453

		data->Restart = 0;
	}

	init_post_mo_setting();
}

static int cwmpSendEmpty(struct cpe_machine *m)
{
	int type;
	void *data;
	char url[128];
	struct soap *soap = &m->cpe_soap;

	type = SOAP_TYPE_cwmp__Empty;
	data = 0;

	m->cpe_isReqSent = 1;
	m->cpe_idle_time = 0;
	m->cpe_last_msgtype = type;
	soap->version = 2;	//soap_set_version(&m->cpe_soap, 2);
	soap->omode &= ~SOAP_IO_CHUNK; //TR-069 ACS(LG BMT) is not accept "HTTP chunk".
	snprintf(url, sizeof(url), "%s", soap->endpoint);
	if (!cwmp_process_send(soap, url, NULL, type, data)) {
		soap_destroy(soap);
		soap_end(soap);	//free some dynamic memory allocation
	} else {
		soap_print_fault(soap, stderr);
		return -1;
	}

	return 0;
}

static void CpeHandleEmpty(struct cpe_machine *m)
{
	struct cwmp_userdata *ud = m->cpe_user;

	if (get_prov_stat(ud) == READY_DOWN_CFG ||
			m->cpe_last_msgtype == SOAP_TYPE_cwmp__GetParameterValuesResponse ||
			m->cpe_last_msgtype == SOAP_TYPE_cwmp__SetParameterValuesResponse) {
		cwmpSendEmpty(m);
		change_cpe_state(CPE_ST_EMPTY_SENT);
	} else {
		CpeDisconnect(m, 0);
	}
}

static void cwmpSendInform(struct cpe_machine *m, unsigned int e, void *option)
{
	struct soap *soap;
	struct cwmp_userdata *ud;

	void *data = NULL;
	int type;
	char url[128];
	soap = &m->cpe_soap;
	ud = soap->user;

	//APACRTL-526
	if (ud)
		ud->FaultCode = 0;

	if (ud->HoldRequests) {
		CWMPDBG(2, (stderr, "(BUG)HoldRequest= %d on sending Inform\n", ud->HoldRequests));
		TLOG_PRINT("HoldRequest= %d on sending Inform\n", ud->HoldRequests);
		return;
	}
	//CpeStartRetry(m); // start retry timer

	//update the parameter tree
	update_Parameter();

	m->cpe_isReqSent = 1;
	m->cpe_idle_time = 0;

	if (e & (EC_BOOTSTRAP | EC_BOOT | EC_PERIODIC | EC_AUTOTRANSFER | EC_TRANSFER | EC_X_VENDOR | EC_REQUESTDL)) {	//APACRTL-433
		snprintf(url, sizeof(url), "%s", ud->url1);	//TAPS
	} else {
		snprintf(url, sizeof(url), "%s", ud->url2);	//TRCS
	}

	cwmp_CreateInform(soap, &type, &data, e, option);
	m->cpe_last_msgtype = type;
	if (!cwmp_process_send(soap, url, NULL, type, data)) {
		soap_destroy(soap);
		soap_end(soap);
		soap_set_endpoint(soap, url);
	} else {
		soap_print_fault(soap, stderr);
		soap_destroy(soap);
		soap_end(soap);
		CpeDisconnect(m, 1);	// for reboot after firmware upgrade.
	}
}

static void cwmpSendTransferComplete(struct cpe_machine *m)
{
	struct soap *soap;
	struct cwmp_userdata *ud;

	void *data;
	int type;
	soap = &m->cpe_soap;
	ud = soap->user;

	if (ud->HoldRequests) {
		CWMPDBG(4, (stderr, "TransferComplete holded, sending empty\n"));
		cwmpSendEmpty(m);
		return;
	}

	m->cpe_isReqSent = 1;
	m->cpe_idle_time = 0;

	cwmp_CreateTransferComplete(soap, &type, &data);
	m->cpe_last_msgtype = type;
	if (!cwmp_process_send(soap, ud->url1, "", type, data)) {
		//fprintf(stderr, "process-send[%d] socket-%d, returns %d\n", __LINE__, soap->socket, soap->error);
		soap_destroy(soap);
		soap_end(soap);

	} else {
		soap_print_fault(soap, stderr);
		CpeDisconnect(m, 0);
	}
	soap_set_endpoint(soap, ud->url1);
}

static void cwmpSendAutonomousTransferComplete(struct cpe_machine *m)
{
	struct soap *soap;
	struct cwmp_userdata *ud;

	void *data;
	int type;
	soap = &m->cpe_soap;
	ud = soap->user;

	CWMPDBG(2, (stderr, "%s Start\n", __FUNCTION__));

	/*
	   if (ud->HoldRequests) {
	   fprintf(stderr, "AutonomousTransferComplete holded, sending empty\n");
	   cwmpSendEmpty(m);
	   return ;
	   }
	*/

	m->cpe_isReqSent = 1;
	m->cpe_idle_time = 0;

	cwmp_CreateAutonomousTransferComplete(soap, &type, &data);
	m->cpe_last_msgtype = type;
	if (!cwmp_process_send(soap, ud->url1, "", type, data)) {
		soap_destroy(soap);
		soap_end(soap);
		soap_set_endpoint(soap, ud->url1);
	} else {
		soap_print_fault(soap, stderr);
		CpeDisconnect(m, 0);	// for reboot after firmware upgrade
	}
}

static void cwmpSendGetRPCMethods(struct cpe_machine *m)
{
	struct soap *soap;
	struct cwmp_userdata *ud;

	void *data;
	int type;
	soap = &m->cpe_soap;
	ud = soap->user;

	if (ud->HoldRequests) {
		CWMPDBG(3, (stderr, "GetRPCMethods holded, sending empty\n"));
		cwmpSendEmpty(m);
		return;
	}
	//m->cpe_retry_count++;
	//cwmpSetRetryWait(m);

	m->cpe_isReqSent = 1;
	m->cpe_idle_time = 0;

	cwmp_CreateGetRPCMethods(soap, &type, &data);
	m->cpe_last_msgtype = type;
	if (!cwmp_process_send(soap, ud->url1, "", type, data)) {
		//soap_closesock(soap);
		soap_destroy(soap);
		soap_end(soap);

	} else {
		soap_print_fault(soap, stderr);
		soap_destroy(soap);
		soap_end(soap);
	}
}

static void cwmpSetRetryWait(struct cpe_machine *m)
{
	int ret = 0;

	switch (m->cpe_retry_count) {
		case 0:
			break;
		case 1:
			ret = 5;
			break;
		case 2:
			ret = 10;
			break;
		case 3:
			ret = 20;
			break;
		case 4:
			ret = 40;
			break;
		case 5:
			ret = 80;
			break;
		case 6:
			ret = 160;
			break;
		case 7:
			ret = 320;
			break;
		case 8:
			ret = 640;
			break;
		case 9:
			ret = 1280;
			break;
		default:
			ret = 2560;
			break;
	}

	if (ret)
		ret = ret + ((unsigned int)soap_rand() % ret);

	m->cpe_retryCountdown = ret + (ygettime(NULL) - m->session_init_time);
	CWMPDBG(2, (stderr, "set wait time to %d->%d (retry=%d)\n", ret, m->cpe_retryCountdown, m->cpe_retry_count));
}

void cwmpRetryRequest(struct cpe_machine *m)
{
	switch (m->cpe_last_msgtype) {
		case SOAP_TYPE_cwmp__Inform:
			cwmpSendInform(m, m->cpe_events, 0);
			break;
		case SOAP_TYPE_cwmp__GetRPCMethods:
			cwmpSendGetRPCMethods(m);
			break;
		case 1011:
			cwmpSendAutonomousTransferComplete(m);		//APACRTL-433
			break;
		case SOAP_TYPE_cwmp__TransferComplete:
			cwmpSendTransferComplete(m);
			break;
		case SOAP_TYPE_cwmp__Empty:
			cwmpSendEmpty(m);
			break;
		default:
			printf("%s(%d) BUG! What was the req?\n", __FILE__, __LINE__);
			break;
	}
}

#ifdef CWMP_ENABLE_SSL
#ifdef __DAVO__
static void set_cert_hostname(struct cpe_machine *m)
{
	struct cwmp_userdata *ud = m->cpe_user;
	char buf_url[256] = "";
	char *p = NULL;
	char *q = NULL;

	if (m->cpe_events & (EC_BOOTSTRAP | EC_BOOT | EC_PERIODIC | EC_AUTOTRANSFER | EC_TRANSFER | EC_X_VENDOR | EC_REQUESTDL))	//APACRTL-433
		snprintf(buf_url, sizeof(buf_url), "%s", ud->url1);
	else
		snprintf(buf_url, sizeof(buf_url), "%s", ud->url2);

	p = strstr(buf_url, "://");
	if (p)
		p += 3;
	else
		p = buf_url;

	q = strchr(p, '/');
	if (q)
		*q = 0;

	soap_davo_set_cert_url(&m->cpe_soap, p);
}
#endif	//__DAVO__
#endif	//CWMP_ENABLE_SSL

static int HandleSendReq(struct cpe_machine *m, void *arg)
{
	int ret = 0;
#ifdef CWMP_ENABLE_SSL
	struct cwmp_userdata *ud = m->cpe_user;
#endif

	switch (m->cpe_state) {
		case CPE_ST_CONNECTED:
			if (HAS_EVENT(m, EC_TRANSFER)) {
				m->cpe_soap.user = m->cpe_user;
				cwmpSendTransferComplete(m);
			} else if (m->cpe_SendGetRPC) {
				m->cpe_SendGetRPC = 0;
				cwmpSendGetRPCMethods(m);
			} else {
				change_cpe_state(CPE_ST_EMPTY_SENT);
				cwmpSendEmpty(m);
			}

			break;
		case CPE_ST_DISCONNECTED:
#ifdef CWMP_ENABLE_SSL
			soap_ssl_init();
#ifdef WITH_POLARSSL
			if ((gDebugFlag & 0xf00) != 0 && (m->cpe_soap.ssl != NULL)) {
				int debug_level = (gDebugFlag >> 8) & 0x0f;
				ssl_set_dbg(m->cpe_soap.ssl, 4, stderr);
			}
#endif

#endif /*#ifdef CWMP_ENABLE_SSL */
			soap_init2(&m->cpe_soap, SOAP_IO_KEEPALIVE, SOAP_IO_KEEPALIVE | SOAP_XML_TREE);
			//support UTF-8
			soap_set_imode(&m->cpe_soap, SOAP_C_UTFSTRING);
			soap_set_omode(&m->cpe_soap, SOAP_C_UTFSTRING);

			//APACBR-210 : Increase SSL handshake timeout.
			m->cpe_soap.connect_timeout = 6;
			m->cpe_soap.user = m->cpe_user;
			strncpy(&(m->cpe_soap.path[0]), "cwmp_d", 6);
			m->cpe_soap.path[6] = '\0';

			m->cpe_soap.version = 0;	//soap_set_version(&m->cpe_soap, 0);
#ifdef WITH_COOKIES
			m->cpe_soap.cookie_max = 10;
#endif

#ifdef CWMP_ENABLE_DIGEST
			//Algorithm -> MD5(Only Use)
			if (soap_register_plugin(&m->cpe_soap, http_da)) { 
			//if (soap_register_plugin_arg(&m->cpe_soap, http_da, http_da_md5()))                 
				soap_print_fault(&m->cpe_soap, stderr);	// failed to register
			}
#endif

#ifdef CWMP_ENABLE_SSL
#ifdef __DAVO__
			set_cert_hostname(m);
#endif
			if ((strncmp("https:", ud->url1, 6) == 0) && gNeedSSLAuth) {
				if (certificate_setup(&m->cpe_soap, 1) < 0)
					certificate_setup(&m->cpe_soap, 0);
			} else
				certificate_setup(&m->cpe_soap, 0);
#endif				/*#ifdef CWMP_ENABLE_SSL */
			change_cpe_state(CPE_ST_AUTHENTICATING);
			m->session_init_time = ygettime(NULL);

			TLOG_PRINT("Start cwmpSendInform 0x%08x\n", m->cpe_events);

			if (HAS_EVENT(m, EC_X_VENDOR))
				cwmpSendInform(m, m->cpe_events, "STUN_DISABLED");
			else
				cwmpSendInform(m, m->cpe_events, 0);

			break;
		case CPE_ST_EMPTY_SENT:
			if (0 == m->cpe_events) {
				cwmpSendEmpty(m);
			} else {
				log("REQ not allowed after EMPTY is sent, %x\n", m->cpe_events);
				ret = -1;
			}

			break;
		default:
			CWMPDBG(3, (stderr, "HandleSendReq: unhandle state %d\n", m->cpe_state));
			ret = -1;
	}

	return ret;
}

//static int HandleSendEmpty(struct cpe_machine *m, void *arg) {

//}

static int HandleRecvEmpty(struct cpe_machine *m, void *arg)
{
#if 1
	CpeDisconnect(m, 0);

	return 0;
#else
	switch (check_cpe_state()) {
		case CPE_ST_EMPTY_SENT:
			// send an initial inform.
			CpeDisconnect(m, 0);
			break;
		default:
			CpeHandleEmpty(m);
			//CpeDisconnect(m, 0);
	}
	return 0;
#endif
}

static int HandleRecvReq(struct cpe_machine *m, void *arg)
{
	int cpe_state = check_cpe_state();
	switch (cpe_state) {
		case CPE_ST_EMPTY_SENT:
			m->cpe_isReqSent = 0;
			break;
		case CPE_ST_CONNECTED:
			if (m->cpe_isReqSent) {
				CWMPDBG(2, (stderr, "(HandleRecvReq)Still have pending Request!!!\n"));
			}
			break;
		default:
			CWMPDBG(4, (stderr, "HandleRecvReq: unhandle state %d\n", cpe_state));
	}

	return 0;
}

static int HandleRecvRsp(struct cpe_machine *m, void *arg)
{
	//struct cpe_req *req;
	struct cwmp_userdata *ud = m->cpe_user;
	int ret = 0;

	switch (check_cpe_state()) {
		//case CPE_ST_REQ_SENT:
		case CPE_ST_AUTHENTICATING:
			change_cpe_state(CPE_ST_CONNECTED);
		case CPE_ST_CONNECTED:
			if (m->cpe_recv_msgtype == SOAP_TYPE_cwmp__InformResponse) {
				if (ud->FaultCode == 0 && !HAS_EVENT(m, (EC_TRANSFER | EC_AUTOTRANSFER)))	//APACRTL-433
					cwmpClearEvent(m, EC_BOOTSTRAP | EC_BOOT | EC_PERIODIC | EC_SCHEDULED |
					        EC_VALUECHANGE | EC_CONNREQUEST | EC_DIAGNOSTICS | EC_M_REBOOT |
					        EC_M_SCHEDULED | EC_X_VENDOR | EC_X_PERIODIC_RST);
				else if (!HAS_EVENT(m, (EC_TRANSFER | EC_AUTOTRANSFER)))	//APACRTL-433
					cwmpClearEvent(m, EC_BOOTSTRAP | EC_BOOT | EC_PERIODIC | EC_SCHEDULED |
					        EC_DIAGNOSTICS | EC_M_REBOOT | EC_M_SCHEDULED | EC_X_VENDOR);

			} else if (m->cpe_recv_msgtype == SOAP_TYPE_cwmp__TransferCompleteResponse) { 
				cwmp_reset_DownloadInfo(&ud->DownloadInfo, DLWAY_NONE);
				//APACRTL-433
				cwmpClearEvent(m, EC_TRANSFER | EC_AUTOTRANSFER | EC_M_DOWNLOAD | EC_M_UPLOAD);
			} else if (m->cpe_recv_msgtype == SOAP_TYPE_cwmp__GetRPCMethodsResponse) {
				//nothing to do for SOAP_TYPE_cwmp__GetRPCMethodsResponse
			} else {
				CWMPDBG(2, (stderr, "Unhandled RecvRsp %d\n", m->cpe_recv_msgtype));
			}
			m->cpe_isReqSent = 0;

			if (HAS_EVENT(m, EC_TRANSFER)) { //APACRTL-433
				cwmpSendTransferComplete(m);
			} else if (HAS_EVENT(m, EC_AUTOTRANSFER)) {	//APACRTL-433
				cwmpSendAutonomousTransferComplete(m);
			} else if (m->cpe_SendGetRPC) {
				m->cpe_SendGetRPC = 0;
				cwmpSendGetRPCMethods(m);
			} else {
				int res;

				res = cwmpSendEmpty(m);
#if 1
				if (res == 0)
					change_cpe_state(CPE_ST_CONNECTED);
				else
					change_cpe_state(CPE_ST_EMPTY_SENT);
#else
				if (res == 0 && ud->HoldRequests) {
					change_cpe_state(CPE_ST_CONNECTED);
					ud->HoldRequestTime = centisecond();
				} else
					change_cpe_state(CPE_ST_EMPTY_SENT);
#endif
			}

			break;

		case CPE_ST_EMPTY_SENT:
			//m->cpe_request = 0;
			break;
		default:
			ret = -1;
	}
	return ret;
}

static int HandleClose(struct cpe_machine *m, void *arg)
{
	int cpe_state = check_cpe_state();
	switch (cpe_state) {
		case CPE_ST_AUTHENTICATING:
			CpeDisconnect(m, m->cpe_soap.error != 0 ? 1 : 0);
			break;
		case CPE_ST_CONNECTED:
		case CPE_ST_EMPTY_SENT:
			//case CPE_ST_REQ_SENT:
			CpeDisconnect(m, 0);
			break;
		default:
			CWMPDBG(3, (stderr, "Close in unknown state %d\n", m->cpe_state));
	}
	return 0;
}

//APACTL-552
static int HandleClose_Force(struct cpe_machine *m, void *arg)
{
	int cpe_state = check_cpe_state();
	switch (cpe_state) {
		case CPE_ST_AUTHENTICATING:
		case CPE_ST_CONNECTED:
		case CPE_ST_EMPTY_SENT:
			//case CPE_ST_REQ_SENT:
			CpeDisconnect(m, 0);
			break;
		default:
			CWMPDBG(3, (stderr, "Close in unknown state %d\n", cpe_state));
	}
	return 0;
}

// TO-DO should determine if the fault is recoverable.. if NOT, then we should close unsuccesfully.
static int HandleRecvFault(struct cpe_machine *m, void *arg)
{
	//struct soap *pSoap = &m->cpe_soap;
	struct cwmp_userdata *ud = m->cpe_user;
	TLOG_PRINT("Recv FaultCode from server. (%d)(EC : 0x%08x)\n", ud->FaultCode, m->cpe_events);
	unlink(PROVISION_PERIOD);
	CpeDisconnect(m, 0);	//APACTL-552
	return 0;
}

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

static int HandleAuthFail(struct cpe_machine *m, void *arg)
{
	struct soap *pSoap = &m->cpe_soap;
	int cpe_state = check_cpe_state();

#ifdef CWMP_ENABLE_SSL
	/*clear the connection*/
	pSoap->keep_alive = 0;
	//soap_closesock( pSoap );
#endif				/*#ifdef CWMP_ENABLE_SSL */

	//CpeResetRetry(m);
	switch (cpe_state) {
		case CPE_ST_AUTHENTICATING:
			m->cpe_auth_count++;
			if (m->cpe_auth_count < 2) {
				//struct soap *pSoap = &m->cpe_soap;
				struct cwmp_userdata *ud = m->cpe_soap.user;

				if (m->cpe_auth_type == CPE_AUTH_NONE) {
					// we know the realm now, use it to retrieve password.
					//ud->username = ud->password = "acs";
#ifdef CWMP_ENABLE_DIGEST
					printCookie(pSoap->cookies);
					m->cpe_auth_type = CPE_AUTH_DIGEST;
					http_da_save(pSoap, &m->cpe_da_info, pSoap->authrealm, ud->username, ud->password);

					/* 
					   strncpy(&(m->cpe_soap.path[0]), "cwmp_d", 6);
					   m->cpe_soap.path[0] = '\0';
					*/

				} else if (m->cpe_auth_type == CPE_AUTH_DIGEST) {
					printCookie(pSoap->cookies);
#else
					m->cpe_auth_type = CPE_AUTH_BASIC;
				} else if (m->cpe_auth_type == CPE_AUTH_BASIC) {
#endif
					return HandleClose(m, arg);
				}

				cwmpSendInform(m, m->cpe_events, 0);

			} else {
				CWMPDBG(2, (stderr, "Auth Retry reaches %d, abort\n", m->cpe_auth_count));
				return HandleClose(m, arg);
			}
			break;
		default:
			CWMPDBG(1, (stderr, "HandleAuthFail: unhandled state %d\n", cpe_state));
	}
	return 0;
}

// used to notify CPE State Machine an event has occurred.
// return 0 if process OK, else return negative error code,
int CPEMachineNotify(struct cpe_machine *m, int event, void *arg)
{
	int ret = 0;
	int prev_state = check_cpe_state();
	int new_state = 0;

	CWMPDBG(2, (stderr, "Old[%s]-->", strCPEState[prev_state]));

	switch (event) {
		case EVENT_SEND_REQ:
			ret = HandleSendReq(m, arg);
			break;
#if 0
		case EVENT_SEND_EMPTY:
			ret = HandleSendEmpty(m,arg);
			break;
#endif
		case EVENT_RECV_EMPTY:
			ret = HandleRecvEmpty(m, arg);
			break;
		case EVENT_RECV_RSP:
			ret = HandleRecvRsp(m, arg);
			break;
#if 0
		case EVENT_TIMEOUT:
			fprintf(stderr,"(Timeout)");
			ret = HandleTimeout(m,arg);
			break;
#endif
		case EVENT_CLOSE:
			ret = HandleClose(m, arg);
			break;
		case EVENT_CLOSE_FORCE:	//APACTL-552
			ret = HandleClose_Force(m, arg);
			break;
		case EVENT_AUTHFAIL:
			ret = HandleAuthFail(m, arg);
			break;
		case EVENT_RECV_REQ:
			ret = HandleRecvReq(m, arg);
			break;
		case EVENT_RECV_FAULT:
			ret = HandleRecvFault(m, arg);
			break;
		default:
			CWMPDBG(3, (stderr, "Unknown Event %d\n", event));
	}

	TLOG_PRINT("StateMachine Event : [%d]\n", event);

	new_state = check_cpe_state();
	CWMPDBG(2, (stderr, "<--New[%s]\n", strCPEState[new_state]));
	if (prev_state != new_state)
		TLOG_PRINT("Changed State from [%s] to [%s]\n", strCPEState[prev_state], strCPEState[new_state]);

	return ret;
}

#if 0
static int init_dbgout(void)
{
	int fd;

	fd = open("/dev/console", O_WRONLY);
	if (fd >= 0) {
		dup2(fd, 1);
		dup2(fd, 2);
		close(fd);
	}
	return 0;
}
#endif

static int StartEventCode;
static int err_code = 0;
//extern int gDebugFlag;

void *cwmp_webclient(void *data)
{
	struct cwmp_userdata *ud = data;

	cwmpMsgInit();
	//CPEReqInit();

	//fprintf(stderr,"free req buffer = %d\n", CPEReqCount());
	syslog(LOG_WARNING, "Start cwmp_webclient function");
	TLOG_PRINT("Start cwmp_webclient function.\n");
	change_cpe_state(CPE_ST_DISCONNECTED);
	cpe_client.cpe_auth_type = CPE_AUTH_NONE;
	cpe_client.cpe_user = data;
	cpe_client.cpe_idle_timeout = CWMP_IDLE_TIMEOUT;
	cpe_client.cpe_SendGetRPC = gNeedSendGetRPC;
	ud->machine = (void *)&cpe_client;
	{
		unsigned int e = StartEventCode;
		if ((StartEventCode & EC_TRANSFER) || (StartEventCode & EC_AUTOTRANSFER))	//APACRTL-433
			ud->DLFaultCode = err_code;

		if (ud->EventCode & EC_BOOTSTRAP)
			e |= EC_BOOTSTRAP;
		if (ud->EventCode & EC_TRANSFER)
			e |= EC_TRANSFER;
		if (ud->EventCode & EC_AUTOTRANSFER)	//APACRTL-433
			e |= EC_AUTOTRANSFER;
		if (ud->EventCode & EC_M_DOWNLOAD)
			e |= EC_M_DOWNLOAD;
		if (ud->EventCode & EC_M_UPLOAD)
			e |= EC_M_UPLOAD;
		if (ud->EventCode & EC_VALUECHANGE)
			e |= EC_VALUECHANGE;
		if (ud->EventCode & EC_X_VENDOR)
			e |= EC_X_VENDOR;

		if (gSkipMReboot == 0)	/*for comtrend acs to test */
			if (ud->EventCode & EC_M_REBOOT)
				e |= EC_M_REBOOT;

		cwmpEvent(&cpe_client, e);
	}

	cwmp_process(&cpe_client.cpe_soap, ud->url1, "");

	return NULL;
}

/*******************************/
void cwmp_closeDebugMsg(void)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	if (fd > 2)
		close(fd);
}

static void sigusr_handler(int signo)
{
	extern void traverse_table(int);
	traverse_table(signo == SIGUSR1);
}

static int daemonize(void)
{
	int pid, i;

	switch(fork())
	{
		/* fork error */
		case -1:
			perror("fork()");
			exit(1);

			/* child process */
		case 0:
			/* obtain a new process group */
			if( (pid = setsid()) < 0)
			{
				perror("setsid()");
				exit(1);
			}

			/* close all descriptors except 0, 1, 2 */
			for (i=getdtablesize();i>=3;--i) close(i);

#if 0
			i = open("/dev/null", O_RDWR); /* open stdin */
			dup(i); /* stdout */
			dup(i); /* stderr */
#endif 

			umask(027);
			//chdir("/"); /* chdir to /tmp ? */

			return pid;

			/* parent process */
		default:
			exit(0);
	}
}

//  APACRTL-227
static int check_ntp_dvflag(void)
{
	int fd;
	unsigned int flgs;

	fd = open("/proc/dvflag", O_RDWR);
	if(fd > -1) {
		read(fd, &flgs, sizeof(flgs));
		close(fd);
		if((flgs & DF_NTPSYNC))
			return 1;
		else
			return 0;
	}

	return 0;
}

//APACRTL-227
static void wait_for_connect(int wait_cnt)
{
	int i = 0;
	char wan_ip[32];
	struct in_addr ip;

	for (i = 0; i < wait_cnt; i++) {
		sleep(1);

		memset(wan_ip, 0, sizeof(wan_ip)); 

		//check wan is up
		if (!yfcat(WAN_IP_CACHE, "%s", wan_ip)) 
			continue;

		ydespaces(wan_ip);

		if (!nv_strcmp(wan_ip, "0.0.0.0") || !inet_aton(wan_ip, &ip))
			continue;

		//check ntp sync
		if (check_ntp_dvflag() && (time(NULL) > 1072882800))
			break;
	}
}

int main(int argc, char **argv)
{
	//struct soap web_soap;
	struct cwmp_userdata *udata = NULL;
	pthread_t cwmp_webclient_pid;
	int delay = 0, fail_cnt = 0;
	char buf[32];
	FILE *fp;

	if (argc >= 2) {
		int i;
		for (i = 1; i < argc; i++) {
			if (nv_strcmp(argv[i], "-SendGetRPC") == 0) {
				gNeedSendGetRPC = 1;
			} else if (nv_strcmp(argv[i], "-SSLAuth") == 0) {
				gNeedSSLAuth = 1;
			} else if (nv_strcmp(argv[i], "-SkipMReboot") == 0) {
				gSkipMReboot = 1;
			} else if (nv_strcmp(argv[i], "-Delay") == 0) {
				delay = 1;
			} else if (nv_strcmp(argv[i], "-NoDebugMsg") == 0) {
				cwmp_closeDebugMsg();
			} else if (nv_strcmp(argv[i], "-fg") == 0) {
				//run foreground
			} else if (nv_strcmp(argv[i], "-test") == 0) {
#if 1 // wan tx cnt debug
				extern void *cwmp_wan_tx_test(void *data);
				cwmp_wan_tx_test(NULL);
				return 0;
#endif
			} else {
				fprintf(stderr, "<%s>Error argument: %s\n", __FILE__, argv[i]);
				return 0;
			}
		}
	} else if (argc == 1) {
		daemonize();
	}

	tlog_init("/var/log/tr069_log.log", 500 * 1024, 2);	//1MBytes
	wait_nat_done();

	signal(SIGCHLD, SIG_IGN);
	mkdir("/var/tmp/cwmp", 0777);
	StartEventCode = EC_BOOT;

	if (access("/var/run/cwmpClient.pid", F_OK) == 0) {
		if (access(IMG_WRITE_LOCKFILE, F_OK) == 0) {
			printf("Image writing process is working.\n");
			exit(0);
			return 1;
		}
		fp = fopen("/var/run/cwmpClient.pid", "r");
		if (fp) {
			fgets(buf, sizeof(buf), fp);
			fclose(fp);
			if (atoi(buf) > 0) {
				kill((pid_t) atoi(buf), SIGKILL);
				sleep(1);
			}
		}

		yexecl(NULL, "killall provision");

		if (access("/tmp/prov_done", F_OK) == 0)
			StartEventCode = 0;
	}

	//I think below block need not anymore.
	if (access("/var/tmp/cwmp/.fail_cnt", F_OK) == 0) {
		fp = fopen("/var/tmp/cwmp/.fail_cnt", "r");
		if (fp) {
			fgets(buf, sizeof(buf), fp);
			fclose(fp);
			fail_cnt = atoi(buf);
		}
	}

	if (nvram_invmatch_r("dv_aup_enabled", "1")) {
		//Do nothing!! : led is controlled by rcS script.
		//control_led_to_upgrade(UPGRADING_COMPLETE);
		yecho("/tmp/prov_done", "1");
		exit(0);
		return 1;
	}

	//APACRTL-227
	wait_for_connect(30);

	syslog(LOG_INFO, DVLOG_MARK_ADMIN "Provisioning process is Started");
	TLOG_PRINT("Start TR069 process.\n");

	if ((StartEventCode & EC_BOOT) == EC_BOOT)
		control_led_to_upgrade(UPGRADING_PHASE1);
	else
		control_led_to_upgrade(UPGRADING_COMPLETE);	//Not provisioning

	nvram_safe_get_r("pvs_conf_ver", buf, sizeof(buf));
	if (buf[0] == 0)
		StartEventCode |= EC_BOOTSTRAP;

	fp = fopen("/var/run/cwmpClient.pid", "w");
	if (fp) {
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	gNeedSSLAuth = 1;

	nvram_safe_get_r("dv_acs_debug_flag", buf, sizeof(buf));
	if ((gDebugFlag = strtoul(buf, NULL, 16)) == 0) {
		cwmp_closeDebugMsg();
		/* cpe_client.cpe_soap.debug = 0; */
	} else {
		// init_dbgout();
		/* cpe_client.cpe_soap.debug = 1; */
	}

	if (delay) {
		unsigned int delaytime = 5;

		while (delaytime != 0)
			delaytime = sleep(delaytime);
	}

	fprintf(stderr, "Start cwmpClient program!\n");

	/* callback func init */
	cwmp_cfg_init();

	if (init_Parameter() < 0) {
		CWMPDBG(1, (stderr, "init parameter tables error!\n"));
		return -1;
	}

	signal(SIGUSR1, sigusr_handler);
	signal(SIGUSR2, sigusr_handler);
	
	udata = cwmp_init_userdata();
	if (udata) {
		CWMPDBG(1, (stderr, "<<<<<<<Before StartEventCode : 0x%08x>>>>>>>>>>\n", StartEventCode));
		if ((StartEventCode & (EC_BOOT | EC_BOOTSTRAP)) == 0) {
			if (check_wan_ip_changed(0) || udata->STUNEnable) {
				StartEventCode |= EC_VALUECHANGE;
			}
		}

		if (udata->STUNEnable == 0 && cwmp_webserver_init(&serverSoap, udata) < 0) {
			CWMPDBG(1, (stderr, "init web server error!\n"));
			TLOG_PRINT("Init cwmp_webserver error\n");
			yecho("/var/tmp/cwmp/.fail_cnt", "%d", ++fail_cnt);
			return -1;
		}

		init_mainloop_status_lock();
		init_cpe_state_lock();

		CWMPDBG(1, (stderr, "<<<<<<<After StartEventCode : 0x%08x>>>>>>>>>>\n", StartEventCode));
		
		pthread_attr_t th_attr;
		pthread_attr_t* pth_attr = NULL;

		if (pthread_attr_init(&th_attr) != 0) {
			perror("socket recv error(pthread_attr_init): ");
			return -1;
		}

		if (pthread_attr_setdetachstate(&th_attr, PTHREAD_CREATE_DETACHED) != 0) {
			perror("socket recv error(pthread_attr_setdetachstate): ");
			return -1;
		}

		if (pthread_attr_setstacksize (&th_attr, 4 * 1024 * 1024) != 0) {
			perror("socket recv error(pthread_attr_setdetachstate): ");
			return -1;
		}

		pth_attr = &th_attr;

		if (pthread_create(&cwmp_webclient_pid, pth_attr, cwmp_webclient, udata) != 0) {
			CWMPDBG(1, (stderr, "init web client error!\n"));
			TLOG_PRINT("Init cwmp_webclient error\n");
			return -1;
		}

		if (udata->STUNEnable) {
			cwmp_udp_loop(udata);
		} else {
			cwmp_webserver_loop(&serverSoap);
		}
 
		//free userdata;
		cwmp_free_userdata(udata);
		udata = NULL;

		deinit_mainloop_status_lock();
		deinit_cpe_state_lock();
	}

	//free parameter;
	free_Parameter();

	//APACRTL-453 : Wait "rc restart"
	if (wait_req_cnt > 3) {
		while (1) {
			sleep(1);
		}
	}

	unlink("/var/tmp/cwmp/.fail_cnt");

	return 0;
}

#ifdef CWMP_ENABLE_SSL
/******************************************************************************\
 *
 *	OpenSSL
 *
 \******************************************************************************/
#ifdef WITH_POLARSSL
int certificate_verify_cb(int use_cert)
{
	return use_cert;	// always check certication.
}
#else
int certificate_verify_cb(int ok, X509_STORE_CTX * store)
{
	int ret = ok;

	if (!ok) {
		int err = 0;
		char data[256] = "";
		int depth = X509_STORE_CTX_get_error_depth(store);

		X509 *cert = X509_STORE_CTX_get_current_cert(store);
		X509_NAME_oneline(X509_get_issuer_name(cert), data, sizeof(data));
		fprintf(stderr, "certificate issuer %s\n", data);
		X509_NAME_oneline(X509_get_subject_name(cert), data, sizeof(data));
		fprintf(stderr, "certificate subject %s\n", data);

		fprintf(stderr, "SSL verify error or warning with certificate at depth %d: %s\n",
		        depth, X509_verify_cert_error_string(X509_STORE_CTX_get_error(store)));

		err = X509_STORE_CTX_get_error(store);
		X509_NAME_oneline(X509_get_subject_name(cert), data, sizeof(data));
		fprintf(stderr, "<%s:%d>Verifying certificate(%s) occurs error(%d)\n",
				__FUNCTION__, __LINE__, data, err);

		switch (err) {
			//APACRTL-564
			case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:	/*skip self_signed */
			case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:	/*skip self_signed */
			case X509_V_ERR_HOSTNAME_MISMATCH:
				X509_STORE_CTX_set_error(store, err);
				ret = 0;
				break;
			case X509_V_ERR_CERT_NOT_YET_VALID:	/*certificate is not yet valid */
			case X509_V_ERR_CERT_HAS_EXPIRED:	/*certificate has expired */
				if (!check_ntp_dvflag()) { 	//NTP_SYNC is off
					if ((depth == 0) && (check_cpe_state() == CPE_ST_AUTHENTICATING))
						syslog(LOG_INFO, DVLOG_MARK_ADMIN H_NTP_PASS_CERT);
					X509_STORE_CTX_set_error(store, X509_V_OK);
					ret = 1;
				} else {
					X509_STORE_CTX_set_error(store, err);
					ret = 0;
				}
				break;
			default:
				ret = 1;
				X509_STORE_CTX_set_error(store, X509_V_OK);
				fprintf(stderr, "<%s:%d>ignore this error(%d)\n", __FUNCTION__, __LINE__, err);
				break;
		}
		TLOG_PRINT("certificate_verify result(Depth : %d) : %d(%d)\n", depth, err, ret);
	}
	/* Note: return 1 to continue, but unsafe progress will be terminated by SSL */
	return ret;
}
#endif

/* APACRTL-496 */
int ssl_CTX_set_cipher_list(SSL_CTX *ctx)
{
	int res = 0;
#ifdef WITH_OPENSSL
	char buf[256] = {0, };
	char *ssl_options = NULL;
	if (nvram_get_r("DV_SSL_PREFERRED_CIPHERS", buf, sizeof(buf))) {
		ssl_options = buf;
	} else {
		ssl_options = DV_SSL_CIPHER_LIST_WITH_SHA_TR;	//APACRTL-564
	}

	res = SSL_CTX_set_cipher_list(ctx, ssl_options);
#endif
	return res;
}

int certificate_setup(struct soap *soap, int use_cert)
{
	int ret = -1;
	char *ca_filename = NULL;
	struct stat file_stat;
	int ssl_auth_mode = SOAP_SSL_NO_AUTHENTICATION;
	char buf[256] = {0, };
	int flags = 0;

	if (use_cert) {
#ifdef WITH_OPENSSL
		if (stat(CA_FNAME, &file_stat) < 0)
			ca_filename = NULL;
		else
			ca_filename = CA_FNAME;
#endif

		ssl_auth_mode = SOAP_SSL_REQUIRE_SERVER_AUTHENTICATION;
	}

	/*re-write the default callback function for verify certificate */
#ifdef WITH_OPENSSL
	soap->fsslverify = certificate_verify_cb;
#endif
	if (nvram_get_r("DV_SSL_PROTOCOL", buf, sizeof(buf))) {
		flags = strtol(buf, NULL, 0);
	} else {
		//ONLY TLS 1.2
		flags = (DV_SSL_CTX_TLSv1_2 | DV_SSL_CTX_NO_SSLv2 | DV_SSL_CTX_NO_SSLv3 | DV_SSL_CTX_NO_TLSv1 | DV_SSL_CTX_NO_TLSv1_1);
	}

	gsoap_ssl_set_protocol(flags);	//APACRTL-564

	if (soap_ssl_client_context(soap, ssl_auth_mode,	/* use SOAP_SSL_DEFAULT in production code */
	            NULL,	/* keyfile: required only when client must authenticate to server (see SSL docs on how to obtain this file) */
	            NULL,	/* password to read the keyfile */
	            ca_filename,	/* optional cacert file to store trusted certificates, use cacerts.pem for all public certificates issued by common CAs */
	            NULL,	/* optional capath to directory with trusted certificates */
	            NULL	/* if randfile!=NULL: use a file with random data to seed randomness */
	            )) {
		soap_print_fault(soap, stderr);
	} else {
		ret = 0;
		if (soap->ctx) {
			ssl_CTX_set_cipher_list(soap->ctx);
		}
	}
	return ret;
}
#endif				/*#ifdef CWMP_ENABLE_SSL */
#endif				/* __CWMPCLIENT_C__ */
