#ifndef _CWMP_CORE_H_
#define _CWMP_CORE_H_

#include "libcwmp.h"
#include "httpda.h"


#define CWMP_IDLE_TIMEOUT	30
#define log			printf
#define HAS_EVENT(m, ev)	((m)->cpe_events & ev)
#define MSG_SIZE  		(sizeof(struct message) - sizeof(int))
#define any_response		(-1)



enum {
	MSG_SEND = 10,
	MSG_EVENT_CONNREQ,
	MSG_TIMER,
	MSG_RECV
};

//enum {
//	REQ_COMPLETE,
//	REQ_SENT
//};

enum {
	CPE_ST_DISCONNECTED,
	CPE_ST_CONNECTED,
	CPE_ST_EMPTY_SENT,
	CPE_ST_AUTHENTICATING,
	//CPE_ST_REQ_SENT
};

enum {
	CPE_AUTH_NONE,
	CPE_AUTH_BASIC,
	CPE_AUTH_DIGEST
};

//enum {
//	CPE_REQ_EMPTY,
//	CPE_REQ_INFORM,
//	CPE_REQ_TRANSFER_COMPLETE
//};

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
//	EVENT_AUTHOK,
	EVENT_AUTHFAIL
};

struct message {
	int	msg_type;
	int	msg_datatype;
	void*	msg_data;
};

//struct cpe_request {
//	int rq_state;
//	int rq_retry; // 1 if msg must be retry.
//	int rq_retry_count; // number of retry to attempt.
//	struct message rq_msg;
//};

//struct cpe_req {
//	int		cpe_req_type; 
//	void 		*cpe_req_arg;	
//	struct cpe_req	*cpe_req_next;
//
//	// for internal 
//	void *	_next;
//};

struct cpe_machine
{
	int  			cpe_state;
	struct soap 		cpe_soap;
	void 			*cpe_user;
	unsigned int		cpe_idle_time;
	unsigned int		cpe_idle_timeout;
	
	int			cpe_auth_count;
	int			cpe_auth_type; // 0 basic, 1 digest
	int			cpe_last_msgtype;
	int			cpe_recv_msgtype;
	int			cpe_isReqSent;
	int			cpe_hold; // 
	unsigned int		cpe_retry_count;
	unsigned int 		cpe_retryCountdown;

	unsigned int 		cpe_events; // current working event.
	unsigned int 		cpe_event_queue; // event queue.

	unsigned int  		cpe_conn_request:1; // 

	int			cpe_SendGetRPC;//jiunming
	struct http_da_info 	cpe_da_info;
};


extern struct cpe_machine cpe_client;

//event api
void cwmpEvent(struct cpe_machine *m, unsigned int event);
void cwmpSendEvent(unsigned int event);
void cwmpDiagnosticDone();

//hold the state machine
void cwmpSetCpeHold(int holdit);

/*create the http client thread*/
int cwmp_webclient(struct cwmp_userdata *ud);

#endif /*_CWMP_CORE_H_*/
