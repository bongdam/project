#ifndef _PE_IPC_H_
#define _PE_IPC_H_

/*
*	Host send to target command
*/
typedef enum {
        WFO_IPC_H2T_INIT = 0,
        WFO_IPC_H2T_START_PROCESS = 1,
        WFO_IPC_H2T_STOP_PROCESS = 2,
        WFO_IPC_H2T_PKT_RECYCLE = 3,
        WFO_IPC_H2T_STA_ADD = 4,
        WFO_IPC_H2T_STA_DEL = 5,
        WFO_IPC_H2T_STA_UPDATE = 6,
        WFO_IPC_H2T_VAR_SET = 7,
        WFO_IPC_H2T_DEBUG = 8,
        WFO_IPC_H2T_MAX = 9,
} ca_wfo_ipc_h2t_t;

/*
*	Target send to host command
*/
typedef enum {
	WFO_IPC_T2H_PE_READY = 0,
        WFO_IPC_T2H_PKT_RECV = 1,
        WFO_IPC_T2H_PKT_SEND = 2,
        WFO_IPC_T2H_RXINFO_REPORT = 3,
        WFO_IPC_T2H_COUNTER_REPORT = 4,
        WFO_IPC_T2H_FUNC = 5,
        WFO_IPC_T2H_DEBUG = 6,
        WFO_IPC_T2H_MAX = 7,
} ca_wfo_ipc_t2h_t;

typedef enum {
	CMD_INIT_TX,
	CMD_START_PROCESS,
	CMD_STOP_PROCESS,
	CMD_ADD_STA,
	CMD_DEL_STA,
	CMD_UPDATE_STA,
	CMD_SET_VAR,
}IPC_TX_CMD_TYPE;

typedef enum {
	WFO_IPC_FUNC_ADDBAREQ = 0,
	WFO_IPC_FUNC_ISSUE_DEAUTH = 1,
	WFO_IPC_FUNC_ISSUE_PSPOLL = 2,
	WFO_IPC_FUNC_FREE_STAINFO = 3,
	WFO_IPC_FUNC_MAX = 4,
} ca_wfo_ipc_func_t;

struct ipc_tx_ctl_s{
	IPC_TX_CMD_TYPE name;
	void (* send_ipc)(unsigned char *,unsigned int);
};

struct ipc_rx_ctl_s{
	ca_wfo_ipc_t2h_t name;
	void (* rx_handler)(unsigned char *,unsigned int);
};

struct func_handler_s{
	ca_wfo_ipc_func_t name;
	bool (* do_func)(void*);
};

int register_wfo_ipc(void);
int tx_init_cmd(void);
int tx_start_process_cmd(void);
int tx_stop_process_cmd(void);
int tx_debug_cmd(unsigned char* buf, unsigned int len);
void rtl_ipc_tx_handler(IPC_TX_CMD_TYPE action,unsigned char *ipc_content,unsigned int buf_len);

#endif
