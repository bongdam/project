#include <linux/kernel.h>

#include <8192cd.h>
#include <8192cd_cfg.h>

#include <ca_types.h>
#include <ca_ipc_pe.h>

#include <pe_fw.h>
#include <pe_ipc.h>

#include <core/8192cd_core_rx.h>
#ifdef CONFIG_PE_ENABLE
struct list_head queued_ipc_cmd_list;

/*
*	RX CMD path
*/
extern ca_status_t ca_ipc_msg_handle_register(ca_ipc_session_id_t session_id,
	const ca_ipc_msg_handle_t * msg_handle_array,ca_uint32_t msg_handle_count);

/*
*	TX CMD path
*/
extern ca_status_t ca_ipc_msg_async_send(ca_ipc_pkt_t* p_ipc_pkt);
extern ca_status_t ca_ipc_msg_sync_send(ca_ipc_pkt_t* p_ipc_pkt,void * result_data,ca_uint16_t * result_size);

int tx_init_cmd(void);
int tx_start_process_cmd(void);
int tx_stop_process_cmd(void);
int tx_pkt_recycle_cmd(unsigned char *buf,unsigned int buf_len);
int tx_sta_add_cmd(unsigned char *buf,unsigned int buf_len);
int tx_sta_del_cmd(unsigned char *buf,unsigned int buf_len);
int tx_sta_update_cmd(unsigned char *buf,unsigned int buf_len);
int tx_var_set_cmd(void);
bool do_issue_add_ba_req(void* msg_data);
bool do_dummy(void* msg_data);


static struct ipc_tx_ctl_s ipc_tx_ctl[]={
	{CMD_INIT_TX,		tx_init_cmd},
	{CMD_START_PROCESS,	tx_start_process_cmd},
	{CMD_STOP_PROCESS,	tx_stop_process_cmd},
	{CMD_ADD_STA,		tx_sta_add_cmd},
	{CMD_DEL_STA,		tx_sta_del_cmd},
	{CMD_UPDATE_STA,	tx_sta_update_cmd},	
	{CMD_SET_VAR,		tx_var_set_cmd},
};

static struct func_handler_s func_handler[]={
	{WFO_IPC_FUNC_ADDBAREQ,		do_issue_add_ba_req},
	{WFO_IPC_FUNC_ISSUE_DEAUTH,	do_dummy},
	{WFO_IPC_FUNC_ISSUE_PSPOLL,	do_dummy},
	{WFO_IPC_FUNC_FREE_STAINFO,	do_dummy},
};

#if 0
void enqueue_ipc_cmd(ca_ipc_pkt_t* send_date)
{
	ca_ipc_pkt_t* queued_ipc_cmd = kmalloc(sizeof(ca_ipc_pkt_t) , GFP_ATOMIC);
	if(queued_ipc_cmd != NULL)
	{
		memcpy(queued_ipc_cmd, send_date, sizeof(ca_ipc_pkt_t));
		queued_ipc_cmd->msg_data = kmalloc(send_date->msg_size , GFP_ATOMIC);
		if(queued_ipc_cmd->msg_data == NULL)
		{
			memcpy(queued_ipc_cmd->msg_data, send_date->msg_data, send_date->msg_size);
			INIT_LIST_HEAD(&(queued_ipc_cmd->list));
			list_add_tail( &(queued_ipc_cmd->list), &queued_ipc_cmd_list);
		}
	}

}

void dequeue_ipc_cmd()
{
	struct list_head *phead, *plist;
	ca_ipc_pkt_t* send_date;
	ca_status_t ret;

	phead = &queued_ipc_cmd_list;
	plist = phead->next;

	while(plist != phead)
	{
		send_date = list_entry(plist, ca_ipc_pkt_t, list);
		plist = plist->next;	
		

		ret = ca_ipc_msg_async_send(send_date);
		if(ret == CA_E_FULL)
		{
			
			break;
		}
	}

}
#endif

void rtl_ipc_tx_handler(IPC_TX_CMD_TYPE action,unsigned char *msg_content,unsigned int msg_len)
{
	ipc_tx_ctl[action].send_ipc(msg_content,msg_len);
}

int tx_init_cmd(void)
{
    ca_ipc_pkt_t send_date;

    send_date.dst_cpu_id = CA_IPC_CPU_PE0;
    send_date.session_id = CA_IPC_SESSION_WFO;
    send_date.msg_no = WFO_IPC_H2T_INIT;
    send_date.msg_size = 0;
    send_date.msg_data = 0;
    send_date.priority = CA_IPC_PRIO_HIGH;

    ca_ipc_msg_async_send(&send_date);
	return 0;
}

int tx_start_process_cmd(void)
{
    ca_ipc_pkt_t send_date;

    send_date.dst_cpu_id = CA_IPC_CPU_PE0;
    send_date.session_id = CA_IPC_SESSION_WFO;
    send_date.msg_no = WFO_IPC_H2T_START_PROCESS;
    send_date.msg_size = 0;
    send_date.msg_data = 0;
    send_date.priority = CA_IPC_PRIO_HIGH;

    ca_ipc_msg_async_send(&send_date);
	return 0;
}

int tx_stop_process_cmd(void)
{
    ca_ipc_pkt_t send_date;

    send_date.dst_cpu_id = CA_IPC_CPU_PE0;
    send_date.session_id = CA_IPC_SESSION_WFO;
    send_date.msg_no = WFO_IPC_H2T_STOP_PROCESS;
    send_date.msg_size = 0;
    send_date.msg_data = 0;
    send_date.priority = CA_IPC_PRIO_HIGH;

    ca_ipc_msg_async_send(&send_date);
	return 0;
}

#define RECYCLE_SIZE	64
unsigned int recycle_skb[RECYCLE_SIZE];
unsigned char recycle_index = 0;

int tx_pkt_recycle_cmd(unsigned char *buf, unsigned int buf_len)
{
	ca_status_t ret;

	recycle_skb[recycle_index] = *((unsigned int*)buf);
	recycle_index++;
	if(recycle_index == RECYCLE_SIZE)
	{
	    ca_ipc_pkt_t send_date;

	    send_date.dst_cpu_id = CA_IPC_CPU_PE0;
	    send_date.session_id = CA_IPC_SESSION_WFO;
	    send_date.msg_no = WFO_IPC_H2T_PKT_RECYCLE;
	    send_date.msg_size = sizeof(recycle_skb);
	    send_date.msg_data = recycle_skb;
	    send_date.priority = CA_IPC_PRIO_HIGH;

	    ret = ca_ipc_msg_async_send(&send_date);

#if 0		
		//Queue IPC cmd when IPC list is full
		if(ret == CA_E_FULL)
		{
			ca_ipc_pkt_t* queued_ipc_cmd = kmalloc(sizeof(ca_ipc_pkt_t) , GFP_ATOMIC);
			if(queued_ipc_cmd != NULL)
			{
				memcpy(queued_ipc_cmd, &send_date, sizeof(ca_ipc_pkt_t));
				queued_ipc_cmd->msg_data = kmalloc(send_date.msg_size , GFP_ATOMIC);
				if(queued_ipc_cmd->msg_data == NULL)
				{
					memcpy(queued_ipc_cmd->msg_data, send_date.msg_data, send_date.msg_size);
					INIT_LIST_HEAD(&(queued_ipc_cmd->list));
					list_add_tail( &(queued_ipc_cmd->list), &queued_ipc_cmd_list);
				}
			}
		}
#endif

		recycle_index = 0;
	}
	return 0;
}

int tx_sta_add_cmd(unsigned char *buf,unsigned int buf_len)
{
    ca_ipc_pkt_t send_date;

    send_date.dst_cpu_id = CA_IPC_CPU_PE0;
    send_date.session_id = CA_IPC_SESSION_WFO;
    send_date.msg_no = WFO_IPC_H2T_STA_ADD;
    send_date.msg_size = buf_len;
    send_date.msg_data = buf;
    send_date.priority = CA_IPC_PRIO_HIGH;

    ca_ipc_msg_async_send(&send_date);
	return 0;
}

int tx_sta_del_cmd(unsigned char *buf,unsigned int buf_len)
{
    ca_ipc_pkt_t send_date;

    send_date.dst_cpu_id = CA_IPC_CPU_PE0;
    send_date.session_id = CA_IPC_SESSION_WFO;
    send_date.msg_no = WFO_IPC_H2T_STA_DEL;
    send_date.msg_size = buf_len;
    send_date.msg_data = buf;
    send_date.priority = CA_IPC_PRIO_HIGH;

    ca_ipc_msg_async_send(&send_date);
	return 0;
}

int tx_sta_update_cmd(unsigned char *buf,unsigned int buf_len)
{
    ca_ipc_pkt_t send_date;

    send_date.dst_cpu_id = CA_IPC_CPU_PE0;
    send_date.session_id = CA_IPC_SESSION_WFO;
    send_date.msg_no = WFO_IPC_H2T_STA_UPDATE;
    send_date.msg_size = buf_len;
    send_date.msg_data = buf;
    send_date.priority = CA_IPC_PRIO_HIGH;

    ca_ipc_msg_async_send(&send_date);
	return 0;
}

int tx_var_set_cmd(void)
{
    ca_ipc_pkt_t send_date;

    send_date.dst_cpu_id = CA_IPC_CPU_PE0;
    send_date.session_id = CA_IPC_SESSION_WFO;
    send_date.msg_no = WFO_IPC_H2T_VAR_SET;
    send_date.msg_size = 0;
    send_date.msg_data = 0;
    send_date.priority = CA_IPC_PRIO_HIGH;

    ca_ipc_msg_async_send(&send_date);
	return 0;
}


int tx_debug_cmd(unsigned char* buf, unsigned int len)
{
    ca_ipc_pkt_t send_date;

    send_date.dst_cpu_id = CA_IPC_CPU_PE0;
    send_date.session_id = CA_IPC_SESSION_WFO;
    send_date.msg_no = WFO_IPC_H2T_DEBUG;
    send_date.msg_size = len;
    send_date.msg_data = buf;
    send_date.priority = CA_IPC_PRIO_HIGH;

    ca_ipc_msg_async_send(&send_date);
	return 0;
}


int rx_pe_ready_cmd(ca_ipc_addr_t peer, ca_uint16_t msg_no, ca_uint16_t trans_id ,const void *msg_data,
				ca_uint16_t* msg_size)
{
	char byestr[]={"Bye from ARM , nice to meet you"};
	int size_str = sizeof(byestr);
	panic_printk( "async callback receives msg_no[%d] message[%s] size[%d]\n", msg_no,(const char *)msg_data,*msg_size);

	memcpy(msg_data,byestr,size_str);
	*msg_size = size_str;
	return 0;
}




int rx_pkt_send_cmd(ca_ipc_addr_t peer, ca_uint16_t msg_no, ca_uint16_t trans_id ,const void *msg_data,
				ca_uint16_t* msg_size)
{
	
	unsigned int skb[1];
	unsigned int pkt_size;
	unsigned int phys_mem_shift = 0;
//	if(flag){
//	panic_printk( "async callback receives msg_no[%d] message[%s] size[%d]\n", msg_no,(const char *)msg_data,*msg_size);

//	panic_printk("skb = %x, skb->data = %x, skb->len = %d\r\n", ((int*)msg_data)[0], ((int*)msg_data)[1], ((int*)msg_data)[2]);
//	}
	// < skb virt addr || skb->data phys addr || skb->len > 
	
//	panic_printk("mem virt addr = %x\r\n", get_pe_fw_virt_addr());
//	panic_printk("mem phys addr = %x\r\n", get_pe_fw_phys_addr());
	phys_mem_shift = ((int*)msg_data)[1] - (get_pe_fw_phys_addr()& 0x0FFFFFFF);
	pkt_size = *((unsigned int*)msg_data + 2);

	if(phys_mem_shift > 0x900000){
		panic_printk("mem virt addr = %x\r\n", get_pe_fw_virt_addr());
		panic_printk("mem phys addr = %x\r\n", get_pe_fw_phys_addr());
		panic_printk("phys shift = %x\r\n", phys_mem_shift);
	}
	
//	panic_printk("content of skb->data = %s\r\n", (char*)(get_pe_fw_virt_addr() + phys_mem_shift));

	//MEMORY COPY
	unsigned char *data  = (unsigned char*)(get_pe_fw_virt_addr() + phys_mem_shift);

	
	struct rtl8192cd_priv *priv = ipc_8814b_priv;	//hardcode for temporary
	struct sk_buff	*pskb = NULL;
		
	pskb = dev_alloc_skb(RX_BUF_LEN);

	if (pskb != NULL) {
		pskb->dev = priv->dev;
		skb_put(pskb, pkt_size);
		memcpy(pskb->data,data,pkt_size);

		if (rtl8192cd_start_xmit(pskb, priv->dev)){			
			rtl_kfree_skb(priv, pskb, _SKB_TX_);
		}
	}else{
		GDEBUG("!error pskb is null\n");
	}
			
	
	//rtl_ipc_rx_handler(msg_no,data,pkt_size);
	//RECYCLE
	skb[0] = ((int*)msg_data)[0];
	tx_pkt_recycle_cmd(skb, sizeof(skb));

	return 0;
}


int rx_pkt_recv_cmd(ca_ipc_addr_t peer, ca_uint16_t msg_no, ca_uint16_t trans_id ,const void *msg_data,
				ca_uint16_t* msg_size)
{
	unsigned int skb[1];
	unsigned int pkt_size;
	unsigned int phys_mem_shift = 0;
//	panic_printk( "async callback receives msg_no[%d] message[%s] size[%d]\n", msg_no,(const char *)msg_data,*msg_size);

//	panic_printk("skb = %x, skb->data = %x, skb->len = %d\r\n", ((int*)msg_data)[0], ((int*)msg_data)[1], ((int*)msg_data)[2]);

	// < skb virt addr || skb->data phys addr || skb->len > 
	
//	panic_printk("mem virt addr = %x\r\n", get_pe_fw_virt_addr());
//	panic_printk("mem phys addr = %x\r\n", get_pe_fw_phys_addr());
	phys_mem_shift = ((unsigned int*)msg_data)[1] - (get_pe_fw_phys_addr()& 0x0FFFFFFF);
	pkt_size = *((unsigned int*)msg_data + 2);

	//panic_printk("phys shift = %x, size = %d\r\n", phys_mem_shift , pkt_size);
	if(phys_mem_shift > 0x900000){
		panic_printk("1.mem virt addr = %x\r\n", get_pe_fw_virt_addr());
		panic_printk("mem phys addr = %x\r\n", get_pe_fw_phys_addr());
		panic_printk("phys shift = %x, data = %x\r\n", phys_mem_shift, phys_mem_shift + get_pe_fw_virt_addr());

	}


	//panic_printk("phys shift = %x\r\n", phys_mem_shift);
	
//	panic_printk("content of skb->data = %s\r\n", (char*)(get_pe_fw_virt_addr() + phys_mem_shift));
	
	//MEMORY COPY
	unsigned char *data  = (unsigned char*)(get_pe_fw_virt_addr() + phys_mem_shift);
	//panic_printk("data = %x, size %d\r\n", data, pkt_size);
	//dmac_flush_range((unsigned long)(data), (unsigned long)(data)+pkt_size);
	
	if(1)
	{
		struct rtl8192cd_priv *priv = ipc_8814b_priv;	//hardcode for temporary
		struct sk_buff	*pskb = NULL;
			
		struct rx_frinfo *pfrinfo;
		u4Byte offset;
		
		pskb = dev_alloc_skb(RX_BUF_LEN);
		//pskb = HAL_OS_malloc(priv, RX_BUF_LEN, _SKB_RX_, TRUE);

		if (pskb != NULL) {
			pskb->dev = priv->dev;

			offset = GetOffsetStartToRXDESC(priv, pskb);
			skb_reserve(pskb, sizeof(struct rx_frinfo) + offset);
			init_frinfo(pfrinfo);
			skb_put(pskb, pkt_size);
			memcpy(pskb->data,data,pkt_size);

			rtl88XX_ipc_rx_isr(priv, pskb);
#if 0	//tbd: check whether it need to be free
		//	if (rtl88XX_ipc_rx_isr(priv, pskb)){
				if(pskb!=NULL)
					rtl_kfree_skb(priv, pskb, _SKB_TX_);
		//	}
#endif		
		}else{
			GDEBUG("!error pskb is null\n");
		}
	}


	

	//RECYCLE
	skb[0] = ((int*)msg_data)[0];
	tx_pkt_recycle_cmd(skb, sizeof(skb));

	return 0;
}

int rx_rxinfo_report_cmd(ca_ipc_addr_t peer, ca_uint16_t msg_no, ca_uint16_t trans_id ,const void *msg_data,
				ca_uint16_t* msg_size)
{
	//panic_printk( "async callback receives msg_no[%d] message[%s] size[%d]\n", msg_no,(const char *)msg_data,*msg_size);

	/*
	*   30 RX_INFOs through one IPC MSG , total packet buffer is 1080 bytes
	*   Each Rx_INFO is pktinfo (4bytes) | driver_info (32bytes)
	*/

	return 0;
}

int rx_counter_report_cmd(ca_ipc_addr_t peer, ca_uint16_t msg_no, ca_uint16_t trans_id ,const void *msg_data,
				ca_uint16_t* msg_size)
{
	panic_printk( "async callback receives msg_no[%d] message[%s] size[%d]\n", msg_no,(const char *)msg_data,*msg_size);

	return 0;
}

bool do_issue_add_ba_req(void* msg_data)
{

	struct rtl8192cd_priv *priv = ipc_8814b_priv;	//hardcode for temporary
	struct stat_info *pstat ;
	unsigned char mac_addr[ETH_ALEN];
	unsigned char tid;
		
	memcpy(mac_addr,((unsigned char*)msg_data+1),ETH_ALEN);
	tid = *((unsigned char*)msg_data+7);

	pstat = get_stainfo(priv,mac_addr);

	if(pstat!=NULL){
		issue_ADDBAreq(priv, pstat, tid);
		return TRUE;
	}
	else{
		printk("error: pstat is null \n");
		return FALSE;
	}
}

bool do_dummy(void* msg_data)
{
}

int rx_func_cmd(ca_ipc_addr_t peer, ca_uint16_t msg_no, ca_uint16_t trans_id ,const void *msg_data,
				ca_uint16_t* msg_size)
{
//	panic_printk( "async callback receives msg_no[%d] message[%s] size[%d]\n", msg_no,(const char *)msg_data,*msg_size);

	//<< msg_data : [0] sub_type, [1-6] mac addr, [7] TID >>
	//unsigned int skb[1];
	unsigned char sub_type;

	sub_type = *((unsigned char*)msg_data+0);

	if((func_handler[sub_type].do_func(msg_data))!=TRUE)
		GDEBUG("run function fail (func id=%d) \n",sub_type);
		

	//RECYCLE
	//skb[0] = ((int*)msg_data)[0];
	//tx_pkt_recycle_cmd(skb, sizeof(skb));
	return 0;
}

int rx_debug_cmd(ca_ipc_addr_t peer, ca_uint16_t msg_no, ca_uint16_t trans_id ,const void *msg_data,
				ca_uint16_t* msg_size)
{
	//panic_printk( "async callback receives msg_no[%d] message[%s] size[%d]\n", msg_no,(const char *)msg_data,*msg_size);

	panic_printk("%s\r\n", (const char *)msg_data);
	return 0;
}


ca_ipc_msg_handle_t invoke_procs_wfo[]=
{
	{ .msg_no=WFO_IPC_T2H_PE_READY, 	.proc=rx_pe_ready_cmd },
	{ .msg_no=WFO_IPC_T2H_PKT_RECV, 	.proc=rx_pkt_recv_cmd },
	{ .msg_no=WFO_IPC_T2H_PKT_SEND, 	.proc=rx_pkt_send_cmd },	
	{ .msg_no=WFO_IPC_T2H_RXINFO_REPORT, 	.proc=rx_rxinfo_report_cmd },
	{ .msg_no=WFO_IPC_T2H_COUNTER_REPORT, 	.proc=rx_counter_report_cmd },
	{ .msg_no=WFO_IPC_T2H_FUNC, 		.proc=rx_func_cmd },
	{ .msg_no=WFO_IPC_T2H_DEBUG, 		.proc=rx_debug_cmd },
};

int register_wfo_ipc(void)
{
	int rc;
	//ca_uint16_t result_size = 0x10;
	panic_printk("Register IPC \r\n");

	INIT_LIST_HEAD(&queued_ipc_cmd_list);
	
	rc= ca_ipc_msg_handle_register(CA_IPC_SESSION_WFO, invoke_procs_wfo, WFO_IPC_T2H_MAX);
	if( CA_E_OK != rc )
	{
		printk("%s Register Failed :%d \n", __FILE__,__LINE__);
		return 1;
	}
	return 0;
}
#endif
