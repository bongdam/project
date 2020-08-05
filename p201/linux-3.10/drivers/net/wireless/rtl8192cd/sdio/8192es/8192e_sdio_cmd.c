/*
 *  SDIO cmd handle routines
 *
 *  Copyright (c) 2017 Realtek Semiconductor Corp.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#define _8192E_SDIO_CMD_C_

#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#endif

#include "8192cd.h"
#include "8192cd_headers.h"
#include "8192cd_debug.h"
#ifdef RTK_NL80211
#include "8192cd_cfg80211.h" 
#endif


enum rt_status SetMACIDSleep88XX(IN  HAL_PADAPTER Adapter, IN  BOOLEAN bSleep, IN  u4Byte aid);
void UpdateHalMSRRPT88XX(IN HAL_PADAPTER Adapter, HAL_PSTAINFO pEntry, u1Byte opmode);


struct cmd_header {
	_list list;
	struct rtl8192cd_priv *priv;
	struct stat_info *pstat;
	u16 cmd_code;
	u16 cmd_len;
};

struct slot_time_parm {
	struct cmd_header header;
	u16 use_short;
};

struct switch_edca_parm {
	struct cmd_header header;
	u32 be_edca;
	u32 vi_edca;
};

struct set_key_parm {
	struct cmd_header header;
	struct net_device *dev;
	unsigned long KeyIndex;
//	unsigned long KeyLen;
	unsigned char KeyType;
	unsigned char EncType;
        unsigned char MACAddr[MACADDRLEN];
	unsigned char Key[32];
};

struct disconnect_sta_parm {
	struct cmd_header header;
	struct net_device *dev;
	DOT11_DISCONNECT_REQ DisconnectReq;
};

struct indicate_mic_failure_parm {
	struct cmd_header header;
	struct net_device *dev;
	unsigned char MACAddr[MACADDRLEN];
	unsigned char indicate_upper_layer;
};

struct mac_clone_parm {
	struct cmd_header header;
	unsigned char MACAddr[MACADDRLEN];
};

struct recv_mgnt_frame_parm {
	struct cmd_header header;
	struct rx_frinfo *pfrinfo;
};

struct macid_pause_parm {
	struct cmd_header header;
        u16 macid;
	u16 pause;
};

struct macid_msr_parm {
	struct cmd_header header;
	u8 opmode;
};

#if defined(RTK_NL80211)
struct indicate_cfg_evt_parm {
	struct cmd_header header;
	int evt;
	unsigned char mac[6];
	unsigned char *extra;
};
#endif

#if (BEAMFORMING_SUPPORT == 1)
struct bfming_cfg_parm {
	struct cmd_header header;
	u8 opmode;
};
#endif

u8 callback_update_sta_RATid(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
u8 callback_del_sta(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);

u8 callback_40M_RRSR_SC_change(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
u8 callback_NAV_prot_len_change(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
u8 callback_slot_time_change(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
#ifdef TXREPORT
u8 callback_request_tx_report(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
#endif
#ifdef SW_ANT_SWITCH
u8 callback_antenna_switch(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
#endif
u8 callback_mp_ctx_background(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
u8 callback_IOT_EDCA_switch(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
u8 callback_set_key(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
u8 callback_disconnect_sta(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
u8 callback_indicate_MIC_failure(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
u8 callback_indicate_MIC_failure_clnt(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
#ifdef RTK_BR_EXT
u8 callback_mac_clone(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
#endif
u8 callback_recv_mgnt_frame(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
#ifdef CONFIG_RTL_WAPI_SUPPORT
u8 callback_recv_wai_frame(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
#endif
u8 callback_macid_pause_change(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
u8 callback_update_sta_msr(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);

#ifdef SDIO_AP_OFFLOAD
u8 callback_ap_offload(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
u8 callback_ap_unoffload(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
#endif
#if defined(WIFI_WPAS_CLI) || defined(RTK_NL80211)
u8 callback_wpas_join(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
#endif

#ifdef RTK_NL80211
u8 callback_notify_cfg_evt(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
#endif
#if (BEAMFORMING_SUPPORT == 1)
u8 callback_bfming_end(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);
#endif

typedef u8 (*cmd_callback)(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr);

struct _cmd_callback {
	u32 cmd_code;
	cmd_callback callback;
};

struct _cmd_callback rtw_cmd_callback[] = {
	{ _CMD_UPDATE_STA_RATID, callback_update_sta_RATid },
	{ _CMD_DEL_STA, callback_del_sta },
	
	{ _CMD_40M_RRSR_SC_CHANGE, callback_40M_RRSR_SC_change },
	{ _CMD_NAV_PROT_LEN_CHANGE, callback_NAV_prot_len_change },
	{ _CMD_SLOT_TIME_CHANGE, callback_slot_time_change },
#ifdef TXREPORT
	{ _CMD_REQUEST_TX_REPORT, callback_request_tx_report },
#endif
#ifdef SW_ANT_SWITCH
	{ _CMD_ANTENNA_SWITCH, callback_antenna_switch },
#endif
	{ _CMD_MP_CTX_BACKGROUND, callback_mp_ctx_background },
	{ _CMD_IOT_EDCA_SWITCH, callback_IOT_EDCA_switch },
	{ _CMD_SET_KEY, callback_set_key },
	{ _CMD_DISCONNECT_STA, callback_disconnect_sta },
	{ _CMD_INDICATE_MIC_FAILURE, callback_indicate_MIC_failure },
	{ _CMD_INDICATE_MIC_FAILURE_CLNT, callback_indicate_MIC_failure_clnt },
#ifdef RTK_BR_EXT
	{ _CMD_MAC_CLONE, callback_mac_clone },
#endif
	{ _CMD_RECV_MGNT_FRAME, callback_recv_mgnt_frame },
#ifdef CONFIG_RTL_WAPI_SUPPORT
	{ _CMD_RECV_WAI_FRAME, callback_recv_wai_frame },
#endif
	{ _CMD_MACID_PAUSE_CHANGE, callback_macid_pause_change },
	{ _CMD_UPDATE_STA_MSR, callback_update_sta_msr },
#ifdef SDIO_AP_OFFLOAD
	{ _CMD_AP_OFFLOAD, callback_ap_offload },
	{ _CMD_AP_UNOFFLOAD, callback_ap_unoffload },
#endif
#if defined(WIFI_WPAS_CLI) || defined(RTK_NL80211)
	{ _CMD_WPAS_JOIN, callback_wpas_join },
#endif
#ifdef RTK_NL80211
	{ _CMD_CFG_IND, callback_notify_cfg_evt },
#endif
#if (BEAMFORMING_SUPPORT == 1)
	{ _CMD_BFMING_END, callback_bfming_end },
#endif
};

int _rtw_init_cmd_priv(struct rtl8192cd_priv *priv)
{
	struct priv_shared_info *pshare;
	
	WARN_ON(ARRAY_SIZE(rtw_cmd_callback) != MAX_RTW_CMD_CODE);
	
	pshare = priv->pshare;
	
	init_waitqueue_head(&pshare->waitqueue);
	
	_rtw_init_queue(&pshare->cmd_queue);
	_rtw_init_queue(&pshare->rx_mgt_queue);
	_rtw_init_queue(&pshare->timer_evt_queue);
	
	return SUCCESS;
}

void _rtw_free_cmd_priv(struct rtl8192cd_priv *priv)
{
	_rtw_spinlock_free(&priv->pshare->timer_evt_queue.lock);
	_rtw_spinlock_free(&priv->pshare->rx_mgt_queue.lock);
	_rtw_spinlock_free(&priv->pshare->cmd_queue.lock);
}

static int rtw_enqueue_cmd(struct rtl8192cd_priv *priv, _queue *cmd_queue, struct cmd_header *pcmdhdr)
{
	_irqL irqL;
	
	_enter_critical_bh(&cmd_queue->lock, &irqL);
	
	rtw_list_insert_tail(&pcmdhdr->list, &cmd_queue->queue);
	
	++cmd_queue->qlen;
	
	_exit_critical_bh(&cmd_queue->lock, &irqL);
	
	if (test_and_set_bit(WAKE_EVENT_CMD, &priv->pshare->cmd_wake) == 0)
		wake_up_process(priv->pshare->cmd_thread);
	
	return TRUE;
}

static struct cmd_header* rtw_dequeue_cmd(struct rtl8192cd_priv *priv, _queue *cmd_queue)
{
	_list *phead, *plist;
	_irqL irqL;
	
	struct cmd_header *cmd_obj = NULL;
	
	plist = NULL;
	
	phead = get_list_head(cmd_queue);
	
	_enter_critical_bh(&cmd_queue->lock, &irqL);
	
	if (rtw_is_list_empty(phead) == FALSE) {
		plist = get_next(phead);
		rtw_list_delete(plist);
		--cmd_queue->qlen;
	}
	
	_exit_critical_bh(&cmd_queue->lock, &irqL);
	
	if (plist)
		cmd_obj = LIST_CONTAINOR(plist, struct cmd_header, list);
	
	return cmd_obj;
}

int rtw_enqueue_timer_event(struct rtl8192cd_priv *priv, struct timer_event_entry *entry, int insert_tail)
{
	_irqL irqL;
	_queue *pqueue = &priv->pshare->timer_evt_queue;
	int insert = 0;
	
	_enter_critical_bh(&pqueue->lock, &irqL);
	
	if (rtw_is_list_empty(&entry->list) == TRUE) {
		if (ENQUEUE_TO_TAIL == insert_tail)
			rtw_list_insert_tail(&entry->list, &pqueue->queue);
		else
			rtw_list_insert_head(&entry->list, &pqueue->queue);
		++pqueue->qlen;
		insert = 1;
	}
	
	_exit_critical_bh(&pqueue->lock, &irqL);
	
	if (insert) {
		if (test_and_set_bit(WAKE_EVENT_CMD, &priv->pshare->cmd_wake) == 0)
			wake_up_process(priv->pshare->cmd_thread);
	} else {
		++priv->pshare->nr_timer_evt_miss;
		printk("[%s] inertion fail!! (function=%p)\n", __FUNCTION__, entry->function);
	}
	
	return TRUE;
}

struct timer_event_entry* rtw_dequeue_timer_event(struct rtl8192cd_priv *priv)
{
	_list *phead, *plist;
	_irqL irqL;
	struct timer_event_entry *entry = NULL;
	_queue *pqueue = &priv->pshare->timer_evt_queue;
	
	plist = NULL;
	
	phead = get_list_head(pqueue);
	
	_enter_critical_bh(&pqueue->lock, &irqL);
	
	if (rtw_is_list_empty(phead) == FALSE) {
		plist = get_next(phead);
		rtw_list_delete(plist);
		--pqueue->qlen;
	}
	
	_exit_critical_bh(&pqueue->lock, &irqL);
	
	if (plist)
		entry = LIST_CONTAINOR(plist, struct timer_event_entry, list);
	
	return entry;
}

void timer_event_timer_fn(unsigned long __data)
{
	struct timer_event_entry *entry = (struct timer_event_entry *)__data;
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv *)entry->data;

	if (!(priv->drv_state & DRV_STATE_OPEN))
		return;

	rtw_enqueue_timer_event(priv, entry, ENQUEUE_TO_TAIL);
}

static void rtw_split_cmd_queue(struct rtl8192cd_priv *priv, struct stat_info *pstat,
	_queue *from_queue, _list *to_list)
{
	_list *phead, *plist;
	_irqL irqL;
	
	struct cmd_header *cmd_obj;
	
	phead = get_list_head(from_queue);
	
	_enter_critical_bh(&from_queue->lock, &irqL);
	
	plist = get_next(phead);
	
	while (rtw_end_of_queue_search(phead, plist) == FALSE) {
		cmd_obj = LIST_CONTAINOR(plist, struct cmd_header, list);
		plist = get_next(plist);
		
		if ((cmd_obj->priv == priv) && (cmd_obj->pstat == pstat)) {
			rtw_list_delete(&cmd_obj->list);
			rtw_list_insert_tail(&cmd_obj->list, to_list);
			--from_queue->qlen;
		}
	}
	
	_exit_critical_bh(&from_queue->lock, &irqL);
}

void rtw_flush_cmd_queue(struct rtl8192cd_priv *priv, struct stat_info *pstat)
{
	_list cmd_list;
	_list *phead, *plist;
	struct cmd_header *cmd_obj;
	
	if ((NULL != pstat) && (0 == pstat->pending_cmd))
		return;
	
	phead = &cmd_list;
	
	_rtw_init_listhead(phead);
	
	rtw_split_cmd_queue(priv, pstat, &priv->pshare->cmd_queue, phead);
	
	plist = get_next(phead);
	
	while (rtw_end_of_queue_search(phead, plist) == FALSE) {
		cmd_obj = LIST_CONTAINOR(plist, struct cmd_header, list);
		plist = get_next(plist);
		
		if (cmd_obj->pstat)
			clear_bit(cmd_obj->cmd_code, &cmd_obj->pstat->pending_cmd);
		rtw_mfree((u8*)cmd_obj, cmd_obj->cmd_len);
	}
}

void rtw_flush_rx_mgt_queue(struct rtl8192cd_priv *priv)
{
	_list cmd_list;
	_list *phead, *plist;
	struct cmd_header *cmd_obj;
	struct recv_mgnt_frame_parm *param;
	
	phead = &cmd_list;
	
	_rtw_init_listhead(phead);
	
	rtw_split_cmd_queue(priv, NULL, &priv->pshare->rx_mgt_queue, phead);
	
	plist = get_next(phead);
	
	while (rtw_end_of_queue_search(phead, plist) == FALSE) {
		cmd_obj = LIST_CONTAINOR(plist, struct cmd_header, list);
		plist = get_next(plist);
		
		param = (struct recv_mgnt_frame_parm *)cmd_obj;
		rtl_kfree_skb(priv, param->pfrinfo->pskb, _SKB_RX_);
		rtw_mfree((u8*)cmd_obj, cmd_obj->cmd_len);
	}
}

int rtw_cmd_thread(void *context)
{
	struct rtl8192cd_priv *priv;
	struct priv_shared_info *pshare;
	struct cmd_header* pcmd;
	cmd_callback cmd_handler;
	
	priv = (struct rtl8192cd_priv*) context;
	pshare = priv->pshare;
	
//	set_user_nice(current, -10);
	
	while (1)
	{
		wait_event(pshare->waitqueue, test_and_clear_bit(WAKE_EVENT_CMD, &pshare->cmd_wake));
		
		while (1)
		{
			if ((TRUE == pshare->bDriverStopped) ||(TRUE == pshare->bSurpriseRemoved)) {
				// avoid to continue calling wake_up_process() when cmd_thread is NULL
				set_bit(WAKE_EVENT_CMD, &pshare->cmd_wake);
				
				printk("[%s] bDriverStopped(%d) OR bSurpriseRemoved(%d)\n",
					__FUNCTION__, pshare->bDriverStopped, pshare->bSurpriseRemoved);
				goto out;
			}
			
			pcmd = NULL;
			
			if (_rtw_queue_empty(&pshare->timer_evt_queue) == FALSE) {
				struct timer_event_entry *timer_event;
				
				timer_event = rtw_dequeue_timer_event(priv);
				if (NULL != timer_event) {
					++pshare->nr_timer_evt;
#ifdef CMD_THREAD_FUNC_DEBUG
					pshare->cur_cmd_func = timer_event->function;
					timer_event->function(timer_event->data);
					pshare->cur_cmd_func = NULL;
#else
					timer_event->function(timer_event->data);
#endif
					continue;
				}
			}
			
			if (_rtw_queue_empty(&pshare->rx_mgt_queue) == FALSE) {
				pcmd = rtw_dequeue_cmd(priv, &pshare->rx_mgt_queue);
				if (NULL != pcmd) {
					++pshare->nr_rx_mgt_cmd;
					goto handle_cmd;
				}
			}
			
			pcmd = rtw_dequeue_cmd(priv, &pshare->cmd_queue);
			if (NULL != pcmd) {
				++pshare->nr_cmd;
				goto handle_cmd;
			}
			
			break;
			
handle_cmd:
			if (pcmd->cmd_code < ARRAY_SIZE(rtw_cmd_callback)) {
				cmd_handler = rtw_cmd_callback[pcmd->cmd_code].callback;
#ifdef CMD_THREAD_FUNC_DEBUG
				pshare->cur_cmd_func = cmd_handler;
				cmd_handler(pcmd->priv, pcmd);
				pshare->cur_cmd_func = NULL;
#else
				cmd_handler(pcmd->priv, pcmd);
#endif
			}
			
			rtw_mfree((u8*)pcmd, pcmd->cmd_len);
		}
	}
	
out:
	
	complete_and_exit(&pshare->cmd_thread_done, 0);
}

void notify_update_sta_RATid(struct rtl8192cd_priv *priv, struct stat_info *pstat)
{
	struct cmd_header *pcmdhdr;
	
	if (test_and_set_bit(_CMD_UPDATE_STA_RATID, &pstat->pending_cmd) != 0)
		return;
	
	pcmdhdr = (struct cmd_header *)rtw_zmalloc(sizeof(struct cmd_header));
	if (NULL == pcmdhdr) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		clear_bit(_CMD_UPDATE_STA_RATID, &pstat->pending_cmd);
		return;
	}
	
	pcmdhdr->cmd_code = _CMD_UPDATE_STA_RATID;
	pcmdhdr->cmd_len = sizeof(struct cmd_header);
	pcmdhdr->priv = priv;
	pcmdhdr->pstat = pstat;
	
	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

u8 callback_update_sta_RATid(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	struct stat_info *pstat = pcmdhdr->pstat;
	
	clear_bit(_CMD_UPDATE_STA_RATID, &pstat->pending_cmd);
	
	// do nothing to avoid to allocate remapped_aid if STA had disassociated
	if (pstat->state & WIFI_ASOC_STATE) {
		GET_HAL_INTERFACE(priv)->UpdateHalRAMaskHandler(priv, pstat, 3);
	}
	
	return TRUE;
}

void notify_del_sta(struct rtl8192cd_priv *priv, struct stat_info *pstat)
{
	struct cmd_header *pcmdhdr;
	
	if (test_and_set_bit(_CMD_DEL_STA, &pstat->pending_cmd) != 0)
		return;
	
	pcmdhdr = (struct cmd_header *)rtw_zmalloc(sizeof(struct cmd_header));
	if (NULL == pcmdhdr) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		clear_bit(_CMD_DEL_STA, &pstat->pending_cmd);
		return;
	}
	
	pcmdhdr->cmd_code = _CMD_DEL_STA;
	pcmdhdr->cmd_len = sizeof(struct cmd_header);
	pcmdhdr->priv = priv;
	pcmdhdr->pstat = pstat;
	
	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

u8 callback_del_sta(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	struct stat_info *pstat = pcmdhdr->pstat;
	
	if (test_and_clear_bit(_CMD_DEL_STA, &pstat->pending_cmd)) {
		unsigned char tmpbuf[16];
		
		sprintf((char *)tmpbuf, "%02x%02x%02x%02x%02x%02x",
			pstat->cmn_info.mac_addr[0], pstat->cmn_info.mac_addr[1], pstat->cmn_info.mac_addr[2],
			pstat->cmn_info.mac_addr[3], pstat->cmn_info.mac_addr[4], pstat->cmn_info.mac_addr[5]);
		del_sta(pcmdhdr->priv, tmpbuf);
	}
	
	return TRUE;
}

void notify_40M_RRSR_SC_change(struct rtl8192cd_priv *priv)
{
	struct cmd_header *pcmdhdr;
	
	if (test_and_set_bit(_CMD_40M_RRSR_SC_CHANGE, priv->pshare->pending_cmd) != 0)
		return;
	
	pcmdhdr = (struct cmd_header *)rtw_zmalloc(sizeof(struct cmd_header));
	if (NULL == pcmdhdr) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		return;
	}
	
	pcmdhdr->cmd_code = _CMD_40M_RRSR_SC_CHANGE;
	pcmdhdr->cmd_len = sizeof(struct cmd_header);
	pcmdhdr->priv = priv;
	
	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

u8 callback_40M_RRSR_SC_change(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	clear_bit(_CMD_40M_RRSR_SC_CHANGE, priv->pshare->pending_cmd);
	
	if (priv->pshare->is_40m_bw) {
		if (orSTABitMap(&priv->pshare->marvellMapBit) == 0) {
			if (0 != priv->pshare->Reg_RRSR_2) {
				RTL_W8(RRSR+2, priv->pshare->Reg_RRSR_2);
				RTL_W8(0x81b, priv->pshare->Reg_81b);
				priv->pshare->Reg_RRSR_2 = 0;
				priv->pshare->Reg_81b = 0;
			}
		} else {
			if (0 == priv->pshare->Reg_RRSR_2) {
				priv->pshare->Reg_RRSR_2 = RTL_R8(RRSR+2);
				priv->pshare->Reg_81b = RTL_R8(0x81b);
				RTL_W8(RRSR+2, priv->pshare->Reg_RRSR_2 | 0x60);
				RTL_W8(0x81b, priv->pshare->Reg_81b | 0x0E); 
			}
		}
	}
	
	return TRUE;
}

void notify_NAV_prot_len_change(struct rtl8192cd_priv *priv)
{
	struct cmd_header *pcmdhdr;
	
	if (test_and_set_bit(_CMD_NAV_PROT_LEN_CHANGE, priv->pshare->pending_cmd) != 0)
		return;
	
	pcmdhdr = (struct cmd_header *)rtw_zmalloc(sizeof(struct cmd_header));
	if (NULL == pcmdhdr) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		return;
	}
	
	pcmdhdr->cmd_code = _CMD_NAV_PROT_LEN_CHANGE;
	pcmdhdr->cmd_len = sizeof(struct cmd_header);
	pcmdhdr->priv = priv;
	
	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

u8 callback_NAV_prot_len_change(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	clear_bit(_CMD_NAV_PROT_LEN_CHANGE, priv->pshare->pending_cmd);
	
	if (orSTABitMap(&priv->pshare->mimo_ps_dynamic_sta)) {
		RTL_W8(NAV_PROT_LEN, 0x40);
	} else {
		RTL_W8(NAV_PROT_LEN, 0x20);
	}
	
	return TRUE;
}

void notify_slot_time_change(struct rtl8192cd_priv *priv, int use_short)
{
	struct slot_time_parm *param;
	struct cmd_header *pcmdhdr;
	
	param = (struct slot_time_parm *)rtw_zmalloc(sizeof(struct slot_time_parm));
	if (NULL == param) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		return;
	}
	
	// Initialize command header
	pcmdhdr = &param->header;
	pcmdhdr->cmd_code = _CMD_SLOT_TIME_CHANGE;
	pcmdhdr->cmd_len = sizeof(*param);
	pcmdhdr->priv = priv;
	
	// Initialize command-specific parameter
	param->use_short = use_short;
	
	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

u8 callback_slot_time_change(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	struct slot_time_parm *param = (struct slot_time_parm *)pcmdhdr;
	
	if (param->use_short)
		RTL_W8(SLOT_TIME, 0x09);
	else
		RTL_W8(SLOT_TIME, 0x14);
	
	return TRUE;
}

#ifdef TXREPORT
void notify_request_tx_report(struct rtl8192cd_priv *priv)
{
	struct cmd_header *pcmdhdr;
	
	if (test_and_set_bit(_CMD_REQUEST_TX_REPORT, priv->pshare->pending_cmd) != 0)
		return;
	
	pcmdhdr = (struct cmd_header *)rtw_zmalloc(sizeof(struct cmd_header));
	if (NULL == pcmdhdr) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		return;
	}
	
	pcmdhdr->cmd_code = _CMD_REQUEST_TX_REPORT;
	pcmdhdr->cmd_len = sizeof(struct cmd_header);
	pcmdhdr->priv = priv;
	
	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

u8 callback_request_tx_report(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	clear_bit(_CMD_REQUEST_TX_REPORT, priv->pshare->pending_cmd);
	
	requestTxReport88XX(priv);
	
	return TRUE;
}
#endif // TXREPORT

#ifdef SW_ANT_SWITCH
void notify_antenna_switch(struct rtl8192cd_priv *priv, u8 nextAntenna)
{
	struct cmd_header *pcmdhdr;
	
	priv->pshare->DM_SWAT_Table.NextAntenna = nextAntenna;
	
	if (test_and_set_bit(_CMD_ANTENNA_SWITCH, priv->pshare->pending_cmd) != 0)
		return;
	
	pcmdhdr = (struct cmd_header *)rtw_zmalloc(sizeof(struct cmd_header));
	if (NULL == pcmdhdr) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		return;
	}
	
	pcmdhdr->cmd_code = _CMD_ANTENNA_SWITCH;
	pcmdhdr->cmd_len = sizeof(struct cmd_header);
	pcmdhdr->priv = priv;
	
	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

u8 callback_antenna_switch(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	u8 nextAntenna;
	
	clear_bit(_CMD_ANTENNA_SWITCH, priv->pshare->pending_cmd);

	nextAntenna = priv->pshare->DM_SWAT_Table.NextAntenna;
	
#ifdef GPIO_ANT_SWITCH
	PHY_SetBBReg(priv, GPIO_PIN_CTRL, 0x3000, nextAntenna);	
#else		
	if (!priv->pshare->rf_ft_var.antSw_select)
		PHY_SetBBReg(priv, rFPGA0_XA_RFInterfaceOE, 0x300, nextAntenna);
	else
		PHY_SetBBReg(priv, rFPGA0_XB_RFInterfaceOE, 0x300, nextAntenna);
#endif
	
	priv->pshare->DM_SWAT_Table.CurAntenna = nextAntenna;
	
	return TRUE;
}
#endif // SW_ANT_SWITCH

void notify_mp_ctx_background(struct rtl8192cd_priv *priv)
{
	struct cmd_header *pcmdhdr;
	
	if (test_and_set_bit(_CMD_MP_CTX_BACKGROUND, priv->pshare->pending_cmd) != 0)
		return;
	
	pcmdhdr = (struct cmd_header *)rtw_zmalloc(sizeof(struct cmd_header));
	if (NULL == pcmdhdr) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		return;
	}
	
	pcmdhdr->cmd_code = _CMD_MP_CTX_BACKGROUND;
	pcmdhdr->cmd_len = sizeof(struct cmd_header);
	pcmdhdr->priv = priv;
	
	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

u8 callback_mp_ctx_background(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	clear_bit(_CMD_MP_CTX_BACKGROUND, priv->pshare->pending_cmd);
	
//	if ((OPMODE & (WIFI_MP_STATE | WIFI_MP_CTX_BACKGROUND | WIFI_MP_CTX_BACKGROUND_STOPPING)) ==
//		(WIFI_MP_STATE | WIFI_MP_CTX_BACKGROUND) )
	mp_ctx(priv, (unsigned char *)"tx-isr");
	
	return TRUE;
}

void notify_IOT_EDCA_switch(struct rtl8192cd_priv *priv, u32 be_edca, u32 vi_edca)
{
	struct switch_edca_parm *param;
	struct cmd_header *pcmdhdr;
	
	param = (struct switch_edca_parm *)rtw_zmalloc(sizeof(struct switch_edca_parm));
	if (NULL == param) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		return;
	}
	
	// Initialize command header
	pcmdhdr = &param->header;
	pcmdhdr->cmd_code = _CMD_IOT_EDCA_SWITCH;
	pcmdhdr->cmd_len = sizeof(*param);
	pcmdhdr->priv = priv;
	
	// Initialize command-specific parameter
	param->be_edca = be_edca;
	param->vi_edca = vi_edca;
	
	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

u8 callback_IOT_EDCA_switch(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	struct switch_edca_parm *param = (struct switch_edca_parm *)pcmdhdr;
	
	if ((u32)-1 != param->be_edca)
		RTL_W32(EDCA_BE_PARA, param->be_edca);
	
	if ((u32)-1 != param->vi_edca)
		RTL_W32(EDCA_VI_PARA, param->vi_edca);
	
	return TRUE;
}

void notify_set_key(struct net_device *dev, DOT11_SET_KEY *pSetKey, unsigned char *pKey)
{
	struct rtl8192cd_priv *priv = GET_DEV_PRIV(dev);
	struct set_key_parm *param;
	struct cmd_header *pcmdhdr;
	
	param = (struct set_key_parm *)rtw_zmalloc(sizeof(struct set_key_parm));
	if (NULL == param) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		return;
	}
	
	// Initialize command header
	pcmdhdr = &param->header;
	pcmdhdr->cmd_code = _CMD_SET_KEY;
	pcmdhdr->cmd_len = sizeof(*param);
	pcmdhdr->priv = priv;
	
	// Initialize command-specific parameter
	param->dev = dev;
	memcpy(param->MACAddr, pSetKey->MACAddr, MACADDRLEN);
	param->KeyType = pSetKey->KeyType;
	param->EncType = pSetKey->EncType;
	param->KeyIndex = pSetKey->KeyIndex;
	if (pKey)
		memcpy(param->Key, pKey, sizeof(param->Key));
	else
		memcpy(param->Key, pSetKey->KeyMaterial, sizeof(param->Key));
	
	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

u8 callback_set_key(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	struct set_key_parm *param = (struct set_key_parm *)pcmdhdr;
	DOT11_SET_KEY Set_Key;
	
	memset((char *)&Set_Key, 0, sizeof(Set_Key));
	memcpy(Set_Key.MACAddr, param->MACAddr, MACADDRLEN);
	Set_Key.KeyType = param->KeyType;
	Set_Key.EncType = param->EncType;
	Set_Key.KeyIndex = param->KeyIndex;
	
	DOT11_Process_Set_Key(param->dev, NULL, &Set_Key, param->Key);
	
	return TRUE;
}

void notify_disconnect_sta(struct net_device *dev, DOT11_DISCONNECT_REQ *pReq)
{
	struct rtl8192cd_priv *priv = GET_DEV_PRIV(dev);
	struct disconnect_sta_parm *param;
	struct cmd_header *pcmdhdr;
	
	param = (struct disconnect_sta_parm *)rtw_zmalloc(sizeof(struct disconnect_sta_parm));
	if (NULL == param) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		return;
	}
	
	// Initialize command header
	pcmdhdr = &param->header;
	pcmdhdr->cmd_code = _CMD_DISCONNECT_STA;
	pcmdhdr->cmd_len = sizeof(*param);
	pcmdhdr->priv = priv;
	
	// Initialize command-specific parameter
	param->dev = dev;
	memcpy(&param->DisconnectReq, pReq, sizeof(DOT11_DISCONNECT_REQ));
	
	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

u8 callback_disconnect_sta(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	struct disconnect_sta_parm *param = (struct disconnect_sta_parm *)pcmdhdr;
	struct iw_point wrq;
	
	wrq.pointer = (caddr_t)&param->DisconnectReq;
	wrq.length = sizeof(DOT11_DISCONNECT_REQ);
	
	__DOT11_Process_Disconnect_Req(param->dev, &wrq);
	
	return TRUE;
}

void notify_indicate_MIC_failure(struct net_device *dev, struct stat_info *pstat)
{
	struct rtl8192cd_priv *priv = GET_DEV_PRIV(dev);
	struct indicate_mic_failure_parm *param;
	struct cmd_header *pcmdhdr;
	
	param = (struct indicate_mic_failure_parm *)rtw_zmalloc(sizeof(struct indicate_mic_failure_parm));
	if (NULL == param) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		return;
	}
	
	// Initialize command header
	pcmdhdr = &param->header;
	pcmdhdr->cmd_code = _CMD_INDICATE_MIC_FAILURE;
	pcmdhdr->cmd_len = sizeof(*param);
	pcmdhdr->priv = priv;
	
	// Initialize command-specific parameter
	param->dev = dev;
	if (pstat) {
		param->indicate_upper_layer = 1;
		memcpy(param->MACAddr, pstat->cmn_info.mac_addr, MACADDRLEN);
	} else {
		param->indicate_upper_layer = 0;
	}
	
	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

u8 callback_indicate_MIC_failure(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	struct indicate_mic_failure_parm *param = (struct indicate_mic_failure_parm *)pcmdhdr;
	struct stat_info *pstat = NULL;
	
	if (param->indicate_upper_layer) {
		pstat = get_stainfo(priv, param->MACAddr); // indicate MIC failure whether STA exist.
	}
	
	__DOT11_Indicate_MIC_Failure(param->dev, pstat);
	
	return TRUE;
}

void notify_indicate_MIC_failure_clnt(struct rtl8192cd_priv *priv, unsigned char *sa)
{
	struct indicate_mic_failure_parm *param;
	struct cmd_header *pcmdhdr;
	
	param = (struct indicate_mic_failure_parm *)rtw_zmalloc(sizeof(struct indicate_mic_failure_parm));
	if (NULL == param) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		return;
	}
	
	// Initialize command header
	pcmdhdr = &param->header;
	pcmdhdr->cmd_code = _CMD_INDICATE_MIC_FAILURE_CLNT;
	pcmdhdr->cmd_len = sizeof(*param);
	pcmdhdr->priv = priv;
	
	// Initialize command-specific parameter
	memcpy(param->MACAddr, sa, MACADDRLEN);
	
	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

u8 callback_indicate_MIC_failure_clnt(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	struct indicate_mic_failure_parm *param = (struct indicate_mic_failure_parm *)pcmdhdr;
	
	__DOT11_Indicate_MIC_Failure_Clnt(priv, param->MACAddr);
	
	return TRUE;
}

#ifdef RTK_BR_EXT
void notify_mac_clone(struct rtl8192cd_priv *priv, unsigned char *addr)
{
	struct mac_clone_parm *param;
	struct cmd_header *pcmdhdr;
	
	param = (struct mac_clone_parm *)rtw_zmalloc(sizeof(struct mac_clone_parm));
	if (NULL == param) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		return;
	}
	
	// Initialize command header
	pcmdhdr = &param->header;
	pcmdhdr->cmd_code = _CMD_MAC_CLONE;
	pcmdhdr->cmd_len = sizeof(*param);
	pcmdhdr->priv = priv;
	
	// Initialize command-specific parameter
	memcpy(param->MACAddr, addr, MACADDRLEN);
	
	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

extern void mac_clone(struct rtl8192cd_priv *priv, unsigned char *addr);
u8 callback_mac_clone(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	struct mac_clone_parm *param = (struct mac_clone_parm *)pcmdhdr;
	
	mac_clone(priv, param->MACAddr);
	priv->macclone_completed = 1;
	
	return TRUE;
}
#endif // RTK_BR_EXT

void notify_recv_mgnt_frame(struct rtl8192cd_priv *priv, struct rx_frinfo *pfrinfo)
{
	struct recv_mgnt_frame_parm *param;
	struct cmd_header *pcmdhdr;
	
	param = (struct recv_mgnt_frame_parm *)rtw_zmalloc(sizeof(struct recv_mgnt_frame_parm));
	if (NULL == param) {
		++priv->pshare->nr_rx_mgt_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		rtl_kfree_skb(priv, pfrinfo->pskb, _SKB_RX_);
		return;
	}
	
	// Initialize command header
	pcmdhdr = &param->header;
	pcmdhdr->cmd_code = _CMD_RECV_MGNT_FRAME;
	pcmdhdr->cmd_len = sizeof(*param);
	pcmdhdr->priv = priv;
	
	// Initialize command-specific parameter
	param->pfrinfo = pfrinfo;
	
	rtw_enqueue_cmd(priv, &priv->pshare->rx_mgt_queue, pcmdhdr);
}

u8 callback_recv_mgnt_frame(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	struct recv_mgnt_frame_parm *param = (struct recv_mgnt_frame_parm *)pcmdhdr;
	
	rtl8192cd_rx_mgntframe(priv, NULL, param->pfrinfo);
	
	return TRUE;
}

#ifdef CONFIG_RTL_WAPI_SUPPORT
void notify_recv_wai_frame(struct rtl8192cd_priv *priv, struct rx_frinfo *pfrinfo)
{
	struct recv_mgnt_frame_parm *param;
	struct cmd_header *pcmdhdr;
	
	param = (struct recv_mgnt_frame_parm *)rtw_zmalloc(sizeof(struct recv_mgnt_frame_parm));
	if (NULL == param) {
		++priv->pshare->nr_rx_mgt_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		rtl_kfree_skb(priv, pfrinfo->pskb, _SKB_RX_);
		return;
	}
	
	// Initialize command header
	pcmdhdr = &param->header;
	pcmdhdr->cmd_code = _CMD_RECV_WAI_FRAME;
	pcmdhdr->cmd_len = sizeof(*param);
	pcmdhdr->priv = priv;
	
	// Initialize command-specific parameter
	param->pfrinfo = pfrinfo;
	
	rtw_enqueue_cmd(priv, &priv->pshare->rx_mgt_queue, pcmdhdr);
}

u8 callback_recv_wai_frame(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	struct recv_mgnt_frame_parm *param = (struct recv_mgnt_frame_parm *)pcmdhdr;
	struct rx_frinfo *pfrinfo = param->pfrinfo;
	unsigned char *pframe = get_pframe(pfrinfo);
	struct stat_info *pstat;

#ifdef WDS
	if (pfrinfo->to_fr_ds == 3) {
		pstat = get_stainfo(priv, GetAddr2Ptr(pframe));
	} else
#endif
	{
#ifdef A4_STA
		if (pfrinfo->to_fr_ds == 3 &&  priv->pmib->miscEntry.a4_enable)
			pstat = get_stainfo(priv, GetAddr2Ptr(pframe));
		else
#endif
	                pstat = get_stainfo(priv, pfrinfo->sa);
	}
	
	if (!pstat || wapiHandleRecvPacket(pfrinfo, pstat) == FAILED) {
		rtl_kfree_skb(priv, pfrinfo->pskb, _SKB_RX_);
	}
	
	return TRUE;
}
#endif // CONFIG_RTL_WAPI_SUPPORT

void notify_macid_pause_change(struct rtl8192cd_priv *priv, u16 macid, u16 pause)
{
	struct macid_pause_parm *param;
	struct cmd_header *pcmdhdr;
	
	param = (struct macid_pause_parm *)rtw_zmalloc(sizeof(struct macid_pause_parm));
	if (NULL == param) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		return;
	}
	
	// Initialize command header
	pcmdhdr = &param->header;
	pcmdhdr->cmd_code = _CMD_MACID_PAUSE_CHANGE;
	pcmdhdr->cmd_len = sizeof(*param);
	pcmdhdr->priv = priv;
	
	// Initialize command-specific parameter
	param->macid = macid;
	param->pause = pause;
	
	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

u8 callback_macid_pause_change(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	struct macid_pause_parm *param = (struct macid_pause_parm *)pcmdhdr;
	
	SetMACIDSleep88XX(priv, param->pause, param->macid);
	
	return TRUE;
}

void notify_update_sta_msr(struct rtl8192cd_priv *priv, struct stat_info *pstat, u8 opmode)
{
	struct macid_msr_parm *param;
	struct cmd_header *pcmdhdr;
	
	param = (struct macid_msr_parm *)rtw_zmalloc(sizeof(struct macid_msr_parm));
	if (NULL == param) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		return;
	}
	
	// Initialize command header
	pcmdhdr = &param->header;
	pcmdhdr->cmd_code = _CMD_UPDATE_STA_MSR;
	pcmdhdr->cmd_len = sizeof(*param);
	pcmdhdr->priv = priv;
	pcmdhdr->pstat = pstat;
	
	// Initialize command-specific parameter
	param->opmode = opmode;
	
	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

u8 callback_update_sta_msr(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	struct macid_msr_parm *param = (struct macid_msr_parm *)pcmdhdr;
	struct stat_info *pstat = pcmdhdr->pstat;

	// do nothing to avoid to allocate remapped_aid if STA had disassociated
	if ((pstat->state & WIFI_ASOC_STATE)
#ifdef WDS
		&& !(pstat->state & WIFI_WDS)
#endif
		) {
		UpdateHalMSRRPT88XX(priv, pstat, param->opmode);
		pcmdhdr->pstat->bDrop = ((DECREASE == param->opmode) ? 1:0);
	}
	
	return TRUE;
}

#ifdef SOFTAP_PS_DURATION
extern s32 sdio_local_read(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *pbuf);
extern s32 sdio_local_write(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *pbuf);
#endif

#ifdef SDIO_AP_OFFLOAD
void cmd_set_ap_offload(struct rtl8192cd_priv *priv, u8 en)
{
	struct cmd_header *pcmdhdr;

	pcmdhdr = (struct cmd_header *)rtw_zmalloc(sizeof(struct cmd_header));
	if (NULL == pcmdhdr) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		return;
	}

	if ( en )
		pcmdhdr->cmd_code = _CMD_AP_OFFLOAD;
	else
		pcmdhdr->cmd_code = _CMD_AP_UNOFFLOAD;

	pcmdhdr->cmd_len = sizeof(struct cmd_header);
	pcmdhdr->priv = GET_ROOT(priv);

	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

void rtw_offload_reinit_timer(struct rtl8192cd_priv *priv)
{
	mod_timer(&priv->pshare->beacon_timer, jiffies + 
		RTL_MILISECONDS_TO_JIFFIES(priv->pmib->dot11StationConfigEntry.dot11BeaconPeriod/2));
#ifndef CONFIG_POWER_SAVE
	mod_timer(&priv->pshare->ps_timer, jiffies + POWER_DOWN_T0);
#endif
	mod_timer(&priv->pshare->xmit_check_timer, jiffies + msecs_to_jiffies(10));
	if ((LED_TYPE >= LEDTYPE_SW_LINK_TXRX) && (LED_TYPE < LEDTYPE_SW_MAX))
		mod_timer(&priv->pshare->LED_Timer, jiffies + priv->pshare->LED_Interval);
#if (BEAMFORMING_SUPPORT == 1)
	PRT_BEAMFORMING_INFO pBeamformingInfo = &(priv->pshare->BeamformingInfo);
	mod_timer(&pBeamformingInfo->BeamformingTimer, jiffies + RTL_MILISECONDS_TO_JIFFIES(200));
#endif
}

#ifdef CONFIG_POWER_SAVE
u8 callback_ap_offload(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	struct priv_shared_info *pshare = priv->pshare;

	if (RTW_PM_AWAKE == pshare->offload_function_ctrl)
		return TRUE;

	if (pshare->ps_xfer_seq != pshare->xfer_seq) {
		pshare->offload_function_ctrl = RTW_PM_AWAKE;
		rtw_lock_suspend_timeout(priv, 2*priv->pmib->dot11OperationEntry.ps_timeout);
		return TRUE;
	}
	
	// if cmd_queue is not empty, then defer the suspend procedure to avoid illegal register access.
	if (!_rtw_queue_empty(&pshare->cmd_queue)) {
		cmd_set_ap_offload(priv, 1);
		return TRUE;
	}
	
	return rtw_sdio_suspend(&pshare->psdio_func->dev);
}

void ap_offload_exit(struct rtl8192cd_priv *priv)
{
	_irqL irqL;

	_enter_critical_mutex(&priv->pshare->apps_lock, &irqL);

	__rtw_sdio_resume(priv);
	
	_exit_critical_mutex(&priv->pshare->apps_lock, &irqL);

	printk("ap offload wakeup\n");
}
#else // !CONFIG_POWER_SAVE
u8 callback_ap_offload(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	struct priv_shared_info *pshare = priv->pshare;
	unsigned char loc_bcn[3] = {0};
	unsigned char loc_probe[3] = {0};
	u32 hidden = 0, i;
	int num_ap = 1;

	if (RTW_PM_AWAKE == pshare->offload_function_ctrl)
		return TRUE;

	if (pshare->offload_prohibited) {
		pshare->offload_function_ctrl = RTW_PM_AWAKE;
		return TRUE;
	}

	loc_bcn[0] = 0xf6;
	loc_probe[0] = loc_bcn[0] + pshare->ap_offload_res[0].probe_offset;

	if (pshare->bcn_priv[0]->pmib->dot11OperationEntry.hiddenAP)
		hidden |= BIT0;
	
#ifdef MBSSID
	for (i = 1; i < pshare->nr_bcn; i++) {
		loc_bcn[num_ap] = loc_bcn[0] + pshare->ap_offload_res[i].beacon_offset;
		loc_probe[num_ap] = loc_bcn[0] + pshare->ap_offload_res[i].probe_offset;
		++num_ap;
		
		if (pshare->bcn_priv[i]->pmib->dot11OperationEntry.hiddenAP)
			hidden |= BIT(i);
	}

	printk("clif loc: bcn[0]=%x probe[0]=%x bcn[1]=%x probe[1]=%x, hidden=%x\n",
		loc_bcn[0], loc_probe[0], loc_bcn[1], loc_probe[1], hidden);
#else
	printk("clif loc: bcn[0]=%x probe[0]=%x, hidden=%x\n",
		loc_bcn[0], loc_probe[0], hidden);
#endif

	/* en, nr_ap, hidden, deny */
	GET_HAL_INTERFACE(priv)->SetAPOffloadHandler(priv, 1, num_ap, hidden, 0, loc_bcn, loc_probe);

#ifdef SOFTAP_PS_DURATION
	GET_HAL_INTERFACE(priv)->SetSAPPsHandler(priv, 1, 70); //zyj test for two ssid problems
#endif

	pshare->pwr_state = RTW_STS_SUSPEND;
	pshare->offload_function_ctrl = RTW_PM_SUSPEND;

	if (timer_pending(&pshare->beacon_timer))
		del_timer_sync(&pshare->beacon_timer);

	if (timer_pending(&pshare->ps_timer))
		del_timer_sync(&pshare->ps_timer);

	if (timer_pending(&pshare->xmit_check_timer))
		del_timer_sync(&pshare->xmit_check_timer);
	
	return TRUE;
}

void ap_offload_exit(struct rtl8192cd_priv *priv)
{
#ifdef SOFTAP_PS_DURATION
	u8  b_val;
#endif

	// Don't do AP offload exit when not in AP offload state. otherwise it may cause TXDMA Error.
	if (RTW_PM_SUSPEND != priv->pshare->offload_function_ctrl)
		return;

#ifdef SOFTAP_PS_DURATION
	sdio_local_read(priv, SDIO_REG_HRPWM1, 1, &b_val);
	b_val ^= BIT7;
	sdio_local_write(priv, SDIO_REG_HRPWM1, 1, &b_val);

	GET_HAL_INTERFACE(priv)->SetSAPPsHandler(priv, 0, 0);
#endif
	GET_HAL_INTERFACE(priv)->SetAPOffloadHandler(priv, 0, 0, 0, 0, 0, 0);

	RTL_W8(RXPKT_NUM+2, RTL_R8(RXPKT_NUM+2) & ~BIT2);
	RTL_W8(TXPAUSE, 0x00);

	if (priv->pshare->pwr_state != RTW_STS_REP)
		priv->pshare->pwr_state = RTW_STS_NORMAL;

	// Update current Tx FIFO page & Tx OQT space
	WARN_ON(GET_HAL_INTF_DATA(priv)->SdioTxIntStatus);
	sdio_query_txbuf_status(priv);
	sdio_query_txoqt_status(priv);

	priv->pshare->offload_function_ctrl = RTW_PM_AWAKE;

	if (priv->drv_state & DRV_STATE_OPEN)
		rtw_offload_reinit_timer(priv);

	printk("ap offload wakeup\n");
}
#endif

void handle_ap_cmd(struct work_struct *work)
{
	struct rtl8192cd_priv *priv = container_of(work, struct rtl8192cd_priv, ap_cmd_queue);
	
	ap_offload_exit(priv);
}

u8 callback_ap_unoffload(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	ap_offload_exit(priv);

	return TRUE;
}
#endif // SDIO_AP_OFFLOAD

#if defined(WIFI_WPAS_CLI) || defined(RTK_NL80211)
void notify_wpas_join(struct rtl8192cd_priv *priv)
{
	struct cmd_header *pcmdhdr;
	
	pcmdhdr = (struct cmd_header *)rtw_zmalloc(sizeof(struct cmd_header));
	if (NULL == pcmdhdr) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		return;
	}
	
	pcmdhdr->cmd_code = _CMD_WPAS_JOIN;
	pcmdhdr->cmd_len = sizeof(struct cmd_header);
	pcmdhdr->priv = priv;
	
	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

u8 callback_wpas_join(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	start_clnt_join(priv);

	return TRUE;
}
#endif // WIFI_WPAS_CLI

#ifdef RTK_NL80211
void notify_cfg_evt(struct rtl8192cd_priv *priv, unsigned char *mac, int event, unsigned char *extra)
{
	struct indicate_cfg_evt_parm *param;
	struct cmd_header *pcmdhdr;

	if ( priv->dev->flags & IFF_UP ) {
		printk("notify_cfg_evt ++\n");

		param = (struct indicate_cfg_evt_parm *)rtw_zmalloc(sizeof(struct indicate_cfg_evt_parm));
		if (NULL == param) {
			++priv->pshare->nr_cmd_miss;
			DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
			return;
		}
		
		// Initialize command header
		pcmdhdr = &param->header;
		pcmdhdr->cmd_code = _CMD_CFG_IND;
		pcmdhdr->cmd_len = sizeof(*param);
		pcmdhdr->priv = priv;
		
		// Initialize command-specific parameter
		param->evt = event;
		param->extra = extra;
		if (mac != NULL)
			memcpy(param->mac, mac, 6);
		
		rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
		printk("notify_cfg_evt --\n");
	}
}

u8 callback_notify_cfg_evt(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	struct indicate_cfg_evt_parm *param = (struct indicate_cfg_evt_parm *)pcmdhdr;
	
	printk("callback_notify_cfg_evt ++\n");

	event_indicate_cfg80211(pcmdhdr->priv, param->mac, param->evt, param->extra);

	printk("callback_notify_cfg_evt --\n");

	return TRUE;
}
#endif // RTK_NL80211

#if (BEAMFORMING_SUPPORT == 1)
void notify_bfming_end(struct rtl8192cd_priv *priv, u8 opmode)
{
	struct bfming_cfg_parm *param;
	struct cmd_header *pcmdhdr;
	
	param = (struct bfming_cfg_parm *)rtw_zmalloc(sizeof(struct bfming_cfg_parm));
	if (NULL == param) {
		++priv->pshare->nr_cmd_miss;
		DEBUG_ERR("[%s] out of memory!!\n", __FUNCTION__);
		return;
	}

	// Initialize command header
	pcmdhdr = &param->header;
	pcmdhdr->cmd_code = _CMD_BFMING_END;
	pcmdhdr->cmd_len = sizeof(*param);
	pcmdhdr->priv = priv;

	// Initialize command-specific parameter
	param->opmode = opmode;

	rtw_enqueue_cmd(priv, &priv->pshare->cmd_queue, pcmdhdr);
}

u8 callback_bfming_end(struct rtl8192cd_priv *priv, struct cmd_header *pcmdhdr)
{
	struct bfming_cfg_parm *param = (struct bfming_cfg_parm *)pcmdhdr;

	Beamforming_End(priv, param->opmode);
	return TRUE;
}
#endif // BEAMFORMING_SUPPORT

