/*
 *  SDIO TX handle routines
 *
 *  Copyright (c) 2017 Realtek Semiconductor Corp.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#define _8192E_SDIO_XMIT_C_

#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/tcp.h>
#endif

#include "8192cd.h"
#include "8192cd_headers.h"
#include "8192cd_debug.h"
#include "WlanHAL/HalHeader/HalComTXDesc.h"
#include "WlanHAL/HalHeader/HalComReg.h"


#define TX_PAGE_SIZE		PBP_PSTX_SIZE

const int Queue2Oqt[MAX_HW_TX_QUEUE] = {
	TXOQT_TYPE_NOAC,	// MGNT_QUEUE
	TXOQT_TYPE_AC,		// BK_QUEUE
	TXOQT_TYPE_AC,		// BE_QUEUE
	TXOQT_TYPE_AC,		// VI_QUEUE
	TXOQT_TYPE_AC,		// VO_QUEUE
	TXOQT_TYPE_NOAC,	// HIGH_QUEUE
	// Don't care for BEACON_QUEUE / TXCMD_QUEUE
};

static void rtl8192cd_xmit_check_timer(unsigned long task_priv);
void rtl8192es_xmit_tasklet(unsigned long data);

int rtw_os_xmit_resource_alloc(struct rtl8192cd_priv *priv, struct xmit_buf *pxmitbuf, u32 alloc_sz)
{
#ifdef USE_PREALLOC_MODULE
	if (alloc_sz == (MAX_XMITBUF_SZ + XMITBUF_ALIGN_SZ)) {
		pxmitbuf->pallocated_buf = rtw_pre_malloc(PREALLOC_TYPE_XMITBUF, alloc_sz);
	} else
#endif
	pxmitbuf->pallocated_buf = rtw_zmalloc(alloc_sz);
	if (NULL == pxmitbuf->pallocated_buf)
	{
		return FAIL;
	}

	pxmitbuf->pkt_head = (u8 *)N_BYTE_ALIGMENT((SIZE_PTR)(pxmitbuf->pallocated_buf), XMITBUF_ALIGN_SZ);
	pxmitbuf->pkt_end = pxmitbuf->pallocated_buf + alloc_sz;

	return SUCCESS;	
}

void rtw_os_xmit_resource_free(struct rtl8192cd_priv *priv, struct xmit_buf *pxmitbuf, u32 free_sz)
{
	if (pxmitbuf->pallocated_buf)
	{
#ifdef USE_PREALLOC_MODULE
		if (free_sz == (MAX_XMITBUF_SZ + XMITBUF_ALIGN_SZ)) {
			rtw_pre_free(pxmitbuf->pallocated_buf);
		} else
#endif
		rtw_mfree(pxmitbuf->pallocated_buf, free_sz);
		pxmitbuf->pallocated_buf = NULL;
	}
}

int _rtw_init_xmit_priv(struct rtl8192cd_priv *priv)
{
	int i;
	struct priv_shared_info *pshare = priv->pshare;
	struct xmit_frame *pxframe;
	struct xmit_buf *pxmitbuf;
	
	for (i = 0; i < MAX_HW_TX_QUEUE; ++i) {
		_rtw_init_queue(&pshare->tx_pending_sta_queue[i]);
		_rtw_init_queue(&pshare->tx_xmitbuf_waiting_queue[i]);
	}
	_rtw_init_queue(&pshare->tx_urgent_queue);
	_init_txservq(&pshare->pspoll_sta_queue, BE_QUEUE);
	pshare->use_hw_queue_bitmap = 0;
	
	// init xmit_frame
	_rtw_init_queue(&pshare->free_xmit_queue);
	
	pshare->pallocated_frame_buf = rtw_zvmalloc(NR_XMITFRAME * sizeof(struct xmit_frame) + 4);
	if (NULL == pshare->pallocated_frame_buf) {
		printk("alloc pallocated_frame_buf fail!(size %d)\n", (NR_XMITFRAME * sizeof(struct xmit_frame) + 4));
		goto exit;
	}
	
	pshare->pxmit_frame_buf = (u8 *)N_BYTE_ALIGMENT((SIZE_PTR)(pshare->pallocated_frame_buf), 4);

	pxframe = (struct xmit_frame*) pshare->pxmit_frame_buf;

	for (i = 0; i < NR_XMITFRAME; i++)
	{
		_rtw_init_listhead(&(pxframe->list));
		
		pxframe->txinsn.fr_type = _RESERVED_FRAME_TYPE_;
		pxframe->txinsn.pframe = NULL;
		pxframe->txinsn.phdr = NULL;
 		
		rtw_list_insert_tail(&(pxframe->list), &(pshare->free_xmit_queue.queue));
		
		pxframe++;
	}

	pshare->free_xmit_queue.qlen = NR_XMITFRAME;
	
	// init xmit_buf
	_rtw_init_queue(&pshare->free_xmitbuf_queue);
	
	pshare->pallocated_xmitbuf = rtw_zvmalloc(NR_XMITBUFF * sizeof(struct xmit_buf) + 4);
	if (NULL == pshare->pallocated_xmitbuf) {
		printk("alloc pallocated_xmitbuf fail!(size %d)\n", (NR_XMITBUFF * sizeof(struct xmit_buf) + 4));
		goto exit;
	}
	
	pshare->pxmitbuf = (u8 *)N_BYTE_ALIGMENT((SIZE_PTR)(pshare->pallocated_xmitbuf), 4);
	
	pxmitbuf = (struct xmit_buf*)pshare->pxmitbuf;
	
	for (i = 0; i < NR_XMITBUFF; i++)
	{
		_rtw_init_listhead(&pxmitbuf->list);
		_rtw_init_listhead(&pxmitbuf->tx_xmitbuf_list);
		
		pxmitbuf->ext_tag = FALSE;
		
		if(rtw_os_xmit_resource_alloc(priv, pxmitbuf, (MAX_XMITBUF_SZ + XMITBUF_ALIGN_SZ)) == FAIL) {
			printk("alloc xmit_buf resource fail!(size %d)\n", (MAX_XMITBUF_SZ + XMITBUF_ALIGN_SZ));
			goto exit;
		}
		
		rtw_list_insert_tail(&pxmitbuf->list, &(pshare->free_xmitbuf_queue.queue));
		
		pxmitbuf++;
	}
	
	pshare->free_xmitbuf_queue.qlen = NR_XMITBUFF;
	
	// init xmit extension buff
	_rtw_init_queue(&pshare->free_xmit_extbuf_queue);

	pshare->pallocated_xmit_extbuf = rtw_zvmalloc(NR_XMIT_EXTBUFF * sizeof(struct xmit_buf) + 4);
	if (NULL == pshare->pallocated_xmit_extbuf) {
		printk("alloc pallocated_xmit_extbuf fail!(size %d)\n", (NR_XMIT_EXTBUFF * sizeof(struct xmit_buf) + 4));
		goto exit;
	}

	pshare->pxmit_extbuf = (u8 *)N_BYTE_ALIGMENT((SIZE_PTR)(pshare->pallocated_xmit_extbuf), 4);

	pxmitbuf = (struct xmit_buf*)pshare->pxmit_extbuf;

	for (i = 0; i < NR_XMIT_EXTBUFF; i++)
	{
		_rtw_init_listhead(&pxmitbuf->list);
		_rtw_init_listhead(&pxmitbuf->tx_xmitbuf_list);
		
		pxmitbuf->ext_tag = 1;
		
		if(rtw_os_xmit_resource_alloc(priv, pxmitbuf, MAX_XMIT_EXTBUF_SZ + XMITBUF_ALIGN_SZ) == FAIL) {
			printk("alloc xmit_extbuf resource fail!(size %d)\n", (MAX_XMIT_EXTBUF_SZ + XMITBUF_ALIGN_SZ));
			goto exit;
		}

		rtw_list_insert_tail(&pxmitbuf->list, &(pshare->free_xmit_extbuf_queue.queue));
		
		pxmitbuf++;
	}

	pshare->free_xmit_extbuf_queue.qlen = NR_XMIT_EXTBUFF;
	
	// init urgent xmit extension buff
	_rtw_init_queue(&pshare->free_urg_xmitbuf_queue);

	pshare->pallocated_urg_xmitbuf = rtw_zvmalloc(NR_URG_XMITBUFF * sizeof(struct xmit_buf) + 4);
	if (NULL == pshare->pallocated_urg_xmitbuf) {
		printk("alloc pallocated_urg_xmitbuf fail!(size %d)\n", (NR_URG_XMITBUFF * sizeof(struct xmit_buf) + 4));
		goto exit;
	}

	pshare->pxmitbuf_urg = (u8 *)N_BYTE_ALIGMENT((SIZE_PTR)(pshare->pallocated_urg_xmitbuf), 4);

	pxmitbuf = (struct xmit_buf*)pshare->pxmitbuf_urg;

	for (i = 0; i < NR_URG_XMITBUFF; i++)
	{
		_rtw_init_listhead(&pxmitbuf->list);
		_rtw_init_listhead(&pxmitbuf->tx_xmitbuf_list);
		
		pxmitbuf->ext_tag = 2;
		
		if(rtw_os_xmit_resource_alloc(priv, pxmitbuf, MAX_XMIT_EXTBUF_SZ + XMITBUF_ALIGN_SZ) == FAIL) {
			printk("alloc urg_xmitbuf resource fail!(size %d)\n", (MAX_XMIT_EXTBUF_SZ + XMITBUF_ALIGN_SZ));
			goto exit;
		}

		rtw_list_insert_tail(&pxmitbuf->list, &(pshare->free_urg_xmitbuf_queue.queue));
		
		pxmitbuf++;
	}

	pshare->free_urg_xmitbuf_queue.qlen = NR_URG_XMITBUFF;
	
	// init xmit_buf for beacon
	_rtw_init_queue(&pshare->free_bcn_xmitbuf_queue);

	pshare->pallocated_bcn_xmitbuf = rtw_zvmalloc(NR_BCN_XMITBUFF * sizeof(struct xmit_buf) + 4);
	if (NULL == pshare->pallocated_bcn_xmitbuf) {
		printk("alloc pallocated_bcn_xmitbuf fail!(size %d)\n", (NR_BCN_XMITBUFF * sizeof(struct xmit_buf) + 4));
		goto exit;
	}

	pshare->pbcn_xmitbuf = (u8 *)N_BYTE_ALIGMENT((SIZE_PTR)(pshare->pallocated_bcn_xmitbuf), 4);

	pxmitbuf = (struct xmit_buf*)pshare->pbcn_xmitbuf;

	for (i = 0; i < NR_BCN_XMITBUFF; ++i)
	{
		_rtw_init_listhead(&pxmitbuf->list);
		_rtw_init_listhead(&pxmitbuf->tx_xmitbuf_list);
		
		pxmitbuf->ext_tag = TRUE;
		
		if(rtw_os_xmit_resource_alloc(priv, pxmitbuf, MAX_BCN_XMITBUF_SZ + XMITBUF_ALIGN_SZ) == FAIL) {
			printk("alloc bcn_xmitbuf resource fail!(size %d)\n", (MAX_BCN_XMITBUF_SZ + XMITBUF_ALIGN_SZ));
			goto exit;
		}

		rtw_list_insert_tail(&pxmitbuf->list, &(pshare->free_bcn_xmitbuf_queue.queue));
		
		++pxmitbuf;
	}

	pshare->free_bcn_xmitbuf_queue.qlen = NR_BCN_XMITBUFF;
	
#ifdef CONFIG_TCP_ACK_TXAGG
	// init tcp ack related materials
	_rtw_init_queue(&pshare->tcpack_queue);
#endif
	pshare->need_sched_xmit = 0;

	init_timer(&pshare->xmit_check_timer);
	pshare->xmit_check_timer.data = (unsigned long)priv;
	pshare->xmit_check_timer.function = rtl8192cd_xmit_check_timer;
	
	// init xmit tasklet
	tasklet_init(&pshare->xmit_tasklet, rtl8192es_xmit_tasklet, (unsigned long)priv);

	for (i = 0; i < MAX_HW_TX_QUEUE; ++i)
		pshare->ts_used[i] = 0;

	// init xmit thread
	_rtw_init_queue(&pshare->pending_xmitbuf_queue);
	init_waitqueue_head(&pshare->xmit_waitqueue);

	return SUCCESS;
	
exit:
	_rtw_free_xmit_priv(priv);
	
	return FAIL;
}

void _rtw_free_xmit_priv(struct rtl8192cd_priv *priv)
{
	int i;
	struct priv_shared_info *pshare = priv->pshare;
	struct xmit_buf *pxmitbuf;

	for (i = 0; i < MAX_HW_TX_QUEUE; ++i) {
		_rtw_spinlock_free(&pshare->tx_pending_sta_queue[i].lock);
		_rtw_spinlock_free(&pshare->tx_xmitbuf_waiting_queue[i].lock);
	}

	_rtw_spinlock_free(&pshare->pending_xmitbuf_queue.lock);

	// free xmit_frame
	_rtw_spinlock_free(&pshare->free_xmit_queue.lock);

	if(pshare->pallocated_frame_buf)
	{
		rtw_vmfree(pshare->pallocated_frame_buf, NR_XMITFRAME * sizeof(struct xmit_frame) + 4);
		pshare->pallocated_frame_buf = NULL;
	}
	
	// free xmit_buf
	_rtw_spinlock_free(&pshare->free_xmitbuf_queue.lock);
	
	if(pshare->pallocated_xmitbuf)
	{
		pxmitbuf = (struct xmit_buf *)pshare->pxmitbuf;
		for (i=0; i<NR_XMITBUFF; ++i) {
			rtw_os_xmit_resource_free(priv, pxmitbuf,(MAX_XMITBUF_SZ + XMITBUF_ALIGN_SZ));
			++pxmitbuf;
		}

		rtw_vmfree(pshare->pallocated_xmitbuf, NR_XMITBUFF * sizeof(struct xmit_buf) + 4);
		pshare->pallocated_xmitbuf = NULL;
	}

	// free xmit extension buff
	_rtw_spinlock_free(&pshare->free_xmit_extbuf_queue.lock);

	if(pshare->pallocated_xmit_extbuf)
	{
		pxmitbuf = (struct xmit_buf *)pshare->pxmit_extbuf;
		for(i=0; i<NR_XMIT_EXTBUFF; ++i) {
			rtw_os_xmit_resource_free(priv, pxmitbuf,(MAX_XMIT_EXTBUF_SZ + XMITBUF_ALIGN_SZ));
			++pxmitbuf;
		}
		
		rtw_vmfree(pshare->pallocated_xmit_extbuf, NR_XMIT_EXTBUFF * sizeof(struct xmit_buf) + 4);
		pshare->pallocated_xmit_extbuf = NULL;
	}
	
	// free urgent xmit extension buff
	_rtw_spinlock_free(&pshare->free_urg_xmitbuf_queue.lock);

	if (pshare->pallocated_urg_xmitbuf)
	{
		pxmitbuf = (struct xmit_buf *)pshare->pxmitbuf_urg;
		for(i=0; i<NR_URG_XMITBUFF; ++i) {
			rtw_os_xmit_resource_free(priv, pxmitbuf,(MAX_XMIT_EXTBUF_SZ + XMITBUF_ALIGN_SZ));
			++pxmitbuf;
		}
		
		rtw_vmfree(pshare->pallocated_urg_xmitbuf, NR_URG_XMITBUFF * sizeof(struct xmit_buf) + 4);
		pshare->pallocated_urg_xmitbuf = NULL;
	}
	
	// free xmit_buf for beacon
	_rtw_spinlock_free(&pshare->free_bcn_xmitbuf_queue.lock);
	
	if(pshare->pallocated_bcn_xmitbuf)
	{
		pxmitbuf = (struct xmit_buf *)pshare->pbcn_xmitbuf;
		for(i=0; i<NR_BCN_XMITBUFF; ++i) {
			rtw_os_xmit_resource_free(priv, pxmitbuf,(MAX_BCN_XMITBUF_SZ + XMITBUF_ALIGN_SZ));
			++pxmitbuf;
		}

		rtw_vmfree(pshare->pallocated_bcn_xmitbuf, NR_BCN_XMITBUFF * sizeof(struct xmit_buf) + 4);
		pshare->pallocated_bcn_xmitbuf = NULL;
	}
}

static inline void rtw_init_xmitbuf(struct xmit_buf *pxmitbuf, u8 q_num)
{
	pxmitbuf->pkt_tail = pxmitbuf->pkt_data = pxmitbuf->pkt_head;
	pxmitbuf->pkt_offset = DEFAULT_TXPKT_OFFSET;
	
	pxmitbuf->q_num = q_num;
	pxmitbuf->agg_num = 0;
	pxmitbuf->use_hw_queue = 0;
	pxmitbuf->flags = 0;
}

struct xmit_buf *rtw_alloc_xmitbuf_ext(struct rtl8192cd_priv *priv, u8 q_num)
{
	_irqL irqL;
	struct xmit_buf *pxmitbuf = NULL;
	_list *plist, *phead;
	_queue *pfree_queue = &priv->pshare->free_xmit_extbuf_queue;
	
	plist =  NULL;
	
	phead = get_list_head(pfree_queue);
	
	_enter_critical(&pfree_queue->lock, &irqL);
	
	if(rtw_is_list_empty(phead) == FALSE) {
		
		plist = get_next(phead);
		
		rtw_list_delete(plist);
		
		--pfree_queue->qlen;
	}
	
	_exit_critical(&pfree_queue->lock, &irqL);
	
	if (NULL !=  plist) {
		pxmitbuf = LIST_CONTAINOR(plist, struct xmit_buf, list);
		rtw_init_xmitbuf(pxmitbuf, q_num);
	}
	
	return pxmitbuf;
}

s32 rtw_free_xmitbuf_ext(struct rtl8192cd_priv *priv, struct xmit_buf *pxmitbuf)
{
	_irqL irqL;
	_queue *pfree_queue;
	
	if (unlikely(NULL == pxmitbuf))
	{
		return FAIL;
	}
	
	pfree_queue = &priv->pshare->free_xmit_extbuf_queue;
	
	_enter_critical(&pfree_queue->lock, &irqL);
	
	rtw_list_insert_tail(&(pxmitbuf->list), get_list_head(pfree_queue));
	
	++pfree_queue->qlen;

	_exit_critical(&pfree_queue->lock, &irqL);
	
	return SUCCESS;
} 

struct xmit_buf *rtw_alloc_urg_xmitbuf(struct rtl8192cd_priv *priv, u8 q_num)
{
	_irqL irqL;
	struct xmit_buf *pxmitbuf = NULL;
	_list *plist, *phead;
	_queue *pfree_queue = &priv->pshare->free_urg_xmitbuf_queue;
	
	plist = NULL;
	
	phead = get_list_head(pfree_queue);
	
	_enter_critical(&pfree_queue->lock, &irqL);
	
	if (rtw_is_list_empty(phead) == FALSE) {
		
		plist = get_next(phead);
		
		rtw_list_delete(plist);
		
		--pfree_queue->qlen;
	}
	
	_exit_critical(&pfree_queue->lock, &irqL);
	
	if (NULL !=  plist) {
		pxmitbuf = LIST_CONTAINOR(plist, struct xmit_buf, list);
		rtw_init_xmitbuf(pxmitbuf, q_num);
	}
	
	return pxmitbuf;
}

s32 rtw_free_urg_xmitbuf(struct rtl8192cd_priv *priv, struct xmit_buf *pxmitbuf)
{
	_irqL irqL;
	_queue *pfree_queue;
	
	if (unlikely(NULL == pxmitbuf))
	{
		return FAIL;
	}
	
	pfree_queue = &priv->pshare->free_urg_xmitbuf_queue;
	
	_enter_critical(&pfree_queue->lock, &irqL);
	
	rtw_list_insert_tail(&(pxmitbuf->list), get_list_head(pfree_queue));
	
	++pfree_queue->qlen;

	_exit_critical(&pfree_queue->lock, &irqL);
	
	return SUCCESS;
} 

#define URGENT_QUEUE		31
int rtw_enqueue_urg_xmitframe(struct rtl8192cd_priv *priv, struct xmit_frame *pxmitframe, int insert_tail)
{
	_queue *xframe_queue;
	_irqL irqL;

	xframe_queue = &priv->pshare->tx_urgent_queue;
	
	xmit_lock(&xframe_queue->lock, &irqL);
	
	if (insert_tail)
		rtw_list_insert_tail(&pxmitframe->list, get_list_head(xframe_queue));
	else
		rtw_list_insert_head(&pxmitframe->list, get_list_head(xframe_queue));
	
	++xframe_queue->qlen;
	
	if (!test_and_set_bit(URGENT_QUEUE, &priv->pshare->need_sched_xmit))
		tasklet_hi_schedule(&priv->pshare->xmit_tasklet);
	
	xmit_unlock(&xframe_queue->lock, &irqL);
	
	return SUCCESS;
}

struct xmit_frame* rtw_dequeue_urg_xmitframe(struct rtl8192cd_priv *priv)
{
	_queue *xframe_queue;
	_list *phead, *plist;
	_irqL irqL;
	
	struct xmit_frame *pxmitframe = NULL;
	
	xframe_queue = &priv->pshare->tx_urgent_queue;
	
	phead = get_list_head(xframe_queue);
	plist = NULL;
	
	xmit_lock(&xframe_queue->lock, &irqL);
	
	if (rtw_is_list_empty(phead) == FALSE) {
		plist = get_next(phead);
		rtw_list_delete(plist);
		--xframe_queue->qlen;
		
		if (0 == xframe_queue->qlen)
			clear_bit(URGENT_QUEUE, &priv->pshare->need_sched_xmit);
	}
	
	xmit_unlock(&xframe_queue->lock, &irqL);
	
	if (plist) {
		pxmitframe = LIST_CONTAINOR(plist, struct xmit_frame, list);
	}
	
	return pxmitframe;
}

struct xmit_buf *rtw_alloc_xmitbuf(struct rtl8192cd_priv *priv, u8 q_num)
{
	_irqL irqL;
	struct xmit_buf *pxmitbuf = NULL;
	_list *plist, *phead;
	_queue *pfree_queue = &priv->pshare->free_xmitbuf_queue;
	
	plist = NULL;
	
	phead = get_list_head(pfree_queue);
	
	_enter_critical(&pfree_queue->lock, &irqL);
	
	if (rtw_is_list_empty(phead) == FALSE) {
		
		plist = get_next(phead);
		
		rtw_list_delete(plist);
		
		--pfree_queue->qlen;
	}
	
	_exit_critical(&pfree_queue->lock, &irqL);
	
	if (NULL !=  plist) {
		pxmitbuf = LIST_CONTAINOR(plist, struct xmit_buf, list);
		rtw_init_xmitbuf(pxmitbuf, q_num);
	}
	
	return pxmitbuf;
}

s32 rtw_free_xmitbuf(struct rtl8192cd_priv *priv, struct xmit_buf *pxmitbuf)
{
	_irqL irqL;
	_queue *pfree_queue;
	
	if (unlikely(NULL == pxmitbuf))
	{
		return FAIL;
	}
	
	BUG_ON(pxmitbuf->use_hw_queue);

	if (pxmitbuf->ext_tag)
	{
		if (2 == pxmitbuf->ext_tag)
			rtw_free_urg_xmitbuf(priv, pxmitbuf);
		else
		rtw_free_xmitbuf_ext(priv, pxmitbuf);
	}
	else
	{
		pfree_queue = &priv->pshare->free_xmitbuf_queue;
		
		_enter_critical(&pfree_queue->lock, &irqL);

		rtw_list_insert_tail(&(pxmitbuf->list), get_list_head(pfree_queue));

		++pfree_queue->qlen;
		
		_exit_critical(&pfree_queue->lock, &irqL);
	}

	return SUCCESS;	
} 

struct xmit_buf *rtw_alloc_beacon_xmitbuf(struct rtl8192cd_priv *priv)
{
	_irqL irqL;
	struct xmit_buf *pxmitbuf = NULL;
	_list *plist, *phead;
	_queue *pfree_queue = &priv->pshare->free_bcn_xmitbuf_queue;
	
	plist =  NULL;
	
	phead = get_list_head(pfree_queue);
	
	_enter_critical(&pfree_queue->lock, &irqL);
	
	if (rtw_is_list_empty(phead) == FALSE) {
		
		plist = get_next(phead);
		
		rtw_list_delete(plist);
		
		--pfree_queue->qlen;
	}
	
	_exit_critical(&pfree_queue->lock, &irqL);
	
	if (NULL !=  plist) {
		pxmitbuf = LIST_CONTAINOR(plist, struct xmit_buf, list);
		rtw_init_xmitbuf(pxmitbuf, BEACON_QUEUE);
	}
	
	return pxmitbuf;
}

s32 rtw_free_beacon_xmitbuf(struct rtl8192cd_priv *priv, struct xmit_buf *pxmitbuf)
{	
	_irqL irqL;
	_queue *pfree_queue;
	
	if (unlikely(NULL == pxmitbuf))
	{
		return FAIL;
	}
	
	pfree_queue = &priv->pshare->free_bcn_xmitbuf_queue;

	_enter_critical(&pfree_queue->lock, &irqL);
	
	rtw_list_insert_tail(&(pxmitbuf->list), get_list_head(pfree_queue));
	
	++pfree_queue->qlen;

	_exit_critical(&pfree_queue->lock, &irqL);
	
	return SUCCESS;
}

void rtw_free_txinsn_resource(struct rtl8192cd_priv *priv, struct tx_insn *txcfg)
{
	if ((NULL != txcfg->pframe) || (NULL != txcfg->phdr)) {
		if (_SKB_FRAME_TYPE_ == txcfg->fr_type) {
			rtl_kfree_skb(priv, (struct sk_buff *)txcfg->pframe, _SKB_TX_);
			if (NULL != txcfg->phdr)
				release_wlanllchdr_to_poll(priv, txcfg->phdr);
		}
		else if (_PRE_ALLOCMEM_ == txcfg->fr_type) {
			release_mgtbuf_to_poll(priv, txcfg->pframe);
			release_wlanhdr_to_poll(priv, txcfg->phdr);
		}
		else if (NULL != txcfg->phdr) {
			release_wlanhdr_to_poll(priv, txcfg->phdr);
		}
		
		txcfg->fr_type = _RESERVED_FRAME_TYPE_;
		txcfg->pframe = NULL;
		txcfg->phdr = NULL;
	}
}

struct xmit_frame *rtw_alloc_xmitframe(struct rtl8192cd_priv *priv)
{
	/*
		Please remember to use all the osdep_service api,
		and lock/unlock or _enter/_exit critical to protect 
		pfree_xmit_queue
	*/

	_irqL irqL;
	struct xmit_frame *pxframe = NULL;
	_list *plist, *phead;
	_queue *pfree_queue = &priv->pshare->free_xmit_queue;
	
	plist = NULL;
	
	phead = get_list_head(pfree_queue);
	
	xmit_lock(&pfree_queue->lock, &irqL);
	
	if (rtw_is_list_empty(phead) == FALSE) {
		plist = get_next(phead);
		rtw_list_delete(plist);
		
		--pfree_queue->qlen;
		if (STOP_NETIF_TX_QUEUE_THRESH == pfree_queue->qlen) {
#ifdef CONFIG_NETDEV_MULTI_TX_QUEUE
			if (BIT(_NETDEV_TX_QUEUE_ALL)-1 != priv->pshare->stop_netif_tx_queue) {
				priv->pshare->stop_netif_tx_queue = BIT(_NETDEV_TX_QUEUE_ALL)-1;
				rtl8192cd_tx_stopQueue(priv);
			}
#else
			if (0 == priv->pshare->stop_netif_tx_queue) {
				priv->pshare->stop_netif_tx_queue = 1;
				rtl8192cd_tx_stopQueue(priv);
			}
#endif // CONFIG_NETDEV_MULTI_TX_QUEUE
		}
	}
	
	xmit_unlock(&pfree_queue->lock, &irqL);
	
	if (likely(NULL != plist)) {
		pxframe = LIST_CONTAINOR(plist, struct xmit_frame, list);
		pxframe->priv = NULL;
		
		pxframe->txinsn.fr_type = _RESERVED_FRAME_TYPE_;
		pxframe->txinsn.pframe = NULL;
		pxframe->txinsn.phdr = NULL;
	} else {
		++priv->pshare->nr_out_of_xmitframe;
	}

	return pxframe;
}

s32 rtw_free_xmitframe(struct rtl8192cd_priv *priv, struct xmit_frame *pxmitframe)
{	
	_irqL irqL;
	_queue *pfree_queue;
#ifdef CONFIG_NETDEV_MULTI_TX_QUEUE
	int i;
#endif
	
	if (unlikely(NULL == pxmitframe)) {
		goto exit;
	}
	
	pfree_queue = &priv->pshare->free_xmit_queue;
	
	xmit_lock(&pfree_queue->lock, &irqL);
	
	rtw_list_insert_tail(&pxmitframe->list, get_list_head(pfree_queue));
	
	++pfree_queue->qlen;
#ifdef CONFIG_NETDEV_MULTI_TX_QUEUE
	if (priv->pshare->iot_mode_enable) {
		// If no consider this case, original flow will cause driver almost frequently restart and stop queue 0(VO),
		// and rarely restart other queue (especially for BE queue) during massive traffic loading.
		// Obviously, we will see serious ping timeout happen no matter ping packet size.
		// [Conclusion] If not in WMM process, we must restart all queues when reaching upper threshold.
		if ((WAKE_NETIF_TX_QUEUE_THRESH <= pfree_queue->qlen)
				&& (priv->pshare->stop_netif_tx_queue)) {
			priv->pshare->stop_netif_tx_queue = 0;
			rtl8192cd_tx_restartQueue(priv, _NETDEV_TX_QUEUE_ALL);
		}
	} else {
		for (i = 0; i < _NETDEV_TX_QUEUE_ALL; ++i) {
			if (WAKE_NETIF_TX_QUEUE_THRESH*(i+1) <= pfree_queue->qlen) {
				if (priv->pshare->stop_netif_tx_queue & BIT(i)) {
					priv->pshare->stop_netif_tx_queue &= ~ BIT(i);
					rtl8192cd_tx_restartQueue(priv, i);
				}
			} else
				break;
		}
	}
#else
	if ((WAKE_NETIF_TX_QUEUE_THRESH == pfree_queue->qlen)
			&& (priv->pshare->stop_netif_tx_queue)) {
		priv->pshare->stop_netif_tx_queue = 0;
		rtl8192cd_tx_restartQueue(priv);
	}
#endif // CONFIG_NETDEV_MULTI_TX_QUEUE
	
	xmit_unlock(&pfree_queue->lock, &irqL);
	
exit:
	
	return SUCCESS;
}

void rtw_free_xmitframe_queue(struct rtl8192cd_priv *priv, _queue *pframequeue)
{
	_irqL irqL;
	_list	*plist, *phead, xmit_list;
	struct xmit_frame *pxmitframe;
	
	phead = &xmit_list;
	
	do {
		_rtw_init_listhead(phead);
		
		xmit_lock(&(pframequeue->lock), &irqL);
		
		rtw_list_splice(get_list_head(pframequeue), phead);
		pframequeue->qlen = 0;
		
		xmit_unlock(&(pframequeue->lock), &irqL);
		
		plist = get_next(phead);
		
		while (plist != phead) {
			pxmitframe = LIST_CONTAINOR(plist, struct xmit_frame, list);
			plist = get_next(plist);
			
			rtw_free_txinsn_resource(pxmitframe->priv, &pxmitframe->txinsn);
			rtw_free_xmitframe(priv, pxmitframe);
		}
	} while (rtw_is_list_empty(&pframequeue->queue) == FALSE);
}

void rtw_txservq_flush(struct rtl8192cd_priv *priv, struct tx_servq *ptxservq)
{
	_queue *xframe_queue, *sta_queue;
	_list *phead, *plist;
	_irqL irqL;
	
	struct xmit_frame *pxmitframe = NULL;
	int deactive;
	
	xframe_queue = &ptxservq->xframe_queue;
	phead = get_list_head(xframe_queue);
	
	xmit_lock(&xframe_queue->lock, &irqL);
	
	plist = get_next(phead);
	while (plist != phead) {
		pxmitframe = LIST_CONTAINOR(plist, struct xmit_frame, list);
		plist = get_next(plist);
		
		rtw_free_txinsn_resource(pxmitframe->priv, &pxmitframe->txinsn);
		rtw_free_xmitframe(priv, pxmitframe);
	}
	_rtw_init_listhead(&(xframe_queue->queue));
	xframe_queue->qlen = 0;
	
	if (pxmitframe) {
	sta_queue = &priv->pshare->tx_pending_sta_queue[ptxservq->q_num];
	deactive = 0;
	
		_rtw_spinlock(&sta_queue->lock);
	
	if (rtw_is_list_empty(&ptxservq->tx_pending) == FALSE) {
		rtw_list_delete(&ptxservq->tx_pending);
		--sta_queue->qlen;
			ptxservq->ts_used = 0;
		deactive = 1;
	}
	
		_rtw_spinunlock(&sta_queue->lock);
	
	if (deactive)
		need_sched_xmit_for_dequeue(priv, ptxservq->q_num);
	}
	
	xmit_unlock(&xframe_queue->lock, &irqL);
}

struct xmit_frame* rtw_txservq_dequeue(struct rtl8192cd_priv *priv, struct tx_servq *ptxservq)
{
	_queue *xframe_queue, *sta_queue;
	_list *phead, *plist;
	_irqL irqL;
	
	struct xmit_frame *pxmitframe = NULL;
	const int q_num = ptxservq->q_num;
	
	xframe_queue = &ptxservq->xframe_queue;
	
	phead = get_list_head(xframe_queue);
	plist = NULL;
	
	xmit_lock(&xframe_queue->lock, &irqL);
	
	if (rtw_is_list_empty(phead) == FALSE) {
		plist = get_next(phead);
		rtw_list_delete(plist);
		--xframe_queue->qlen;
	}
	
	if (0 == xframe_queue->qlen) {
		sta_queue = &priv->pshare->tx_pending_sta_queue[q_num];
		
		_rtw_spinlock(&sta_queue->lock);
		
		if (rtw_is_list_empty(&ptxservq->tx_pending) == FALSE) {
			rtw_list_delete(&ptxservq->tx_pending);
			--sta_queue->qlen;
			ptxservq->ts_used = 0;
		}
		
		if (MCAST_QNUM == q_num)
			ptxservq->q_num = BE_QUEUE;
		
		_rtw_spinunlock(&sta_queue->lock);
	}
	
	xmit_unlock(&xframe_queue->lock, &irqL);
	
	if (plist) {
		if (unlikely(&priv->pshare->pspoll_sta_queue == ptxservq)) {
			struct stat_info *pstat;
			pstat = LIST_CONTAINOR(plist, struct stat_info, pspoll_list);
			pxmitframe = rtw_txservq_dequeue(priv, &pstat->tx_queue[BE_QUEUE]);

			if (NULL != pxmitframe)
				pxmitframe->txinsn.is_pspoll = 1;
		} else {
			pxmitframe = LIST_CONTAINOR(plist, struct xmit_frame, list);
		}
	}
	
	need_sched_xmit_for_dequeue(priv, q_num);
	
	return pxmitframe;
}

void rtw_pspoll_sta_enqueue(struct rtl8192cd_priv *priv, struct stat_info *pstat, int insert_tail)
{
	struct tx_servq *ptxservq;
	_queue *xframe_queue, *sta_queue;
	_irqL irqL;

	ptxservq = &priv->pshare->pspoll_sta_queue;

	xframe_queue = &ptxservq->xframe_queue;

	xmit_lock(&xframe_queue->lock, &irqL);

	if (!(pstat->state & WIFI_ASOC_STATE)) {
		xmit_unlock(&xframe_queue->lock, &irqL);
		return;
	}

	if (TRUE == rtw_is_list_empty(&pstat->pspoll_list)) {
		if (ENQUEUE_TO_TAIL == insert_tail)
			rtw_list_insert_tail(&pstat->pspoll_list, &xframe_queue->queue);
		else
			rtw_list_insert_head(&pstat->pspoll_list, &xframe_queue->queue);
		++xframe_queue->qlen;

		if (1 == xframe_queue->qlen)
		{
			sta_queue = &priv->pshare->tx_pending_sta_queue[ptxservq->q_num]; // polling packets use BE_QUEUE
				
			_rtw_spinlock(&sta_queue->lock);
				
			if (rtw_is_list_empty(&ptxservq->tx_pending) == TRUE) {
				rtw_list_insert_head(&ptxservq->tx_pending, &sta_queue->queue);
				++sta_queue->qlen;
			}
			
			set_bit(ptxservq->q_num, &priv->pshare->need_sched_xmit);
			
			_rtw_spinunlock(&sta_queue->lock);
		}
	}
		
	xmit_unlock(&xframe_queue->lock, &irqL);
}

void rtw_pspoll_sta_delete(struct rtl8192cd_priv *priv, struct stat_info *pstat)
{
	struct tx_servq *ptxservq;
	_queue *xframe_queue, *sta_queue;
	_irqL irqL;
	int deactive;

	ptxservq = &priv->pshare->pspoll_sta_queue;
	
	xframe_queue = &ptxservq->xframe_queue;
	
	xmit_lock(&xframe_queue->lock, &irqL);
	
	if (FALSE == rtw_is_list_empty(&pstat->pspoll_list)) {
		rtw_list_delete(&pstat->pspoll_list);
		--xframe_queue->qlen;
	}

	if (0 == xframe_queue->qlen) {
		sta_queue = &priv->pshare->tx_pending_sta_queue[ptxservq->q_num]; // polling packets use BE_QUEUE
		deactive = 0;

		_rtw_spinlock(&sta_queue->lock);
		
		if (rtw_is_list_empty(&ptxservq->tx_pending) == FALSE) {
			rtw_list_delete(&ptxservq->tx_pending);
			--sta_queue->qlen;
			deactive = 1;
		}

		_rtw_spinunlock(&sta_queue->lock);

		if (deactive)
			need_sched_xmit_for_dequeue(priv, ptxservq->q_num);
	}

	xmit_unlock(&xframe_queue->lock, &irqL);
}

// Before enqueue xmitframe, the fr_type, pframe, pstat and q_num field in txinsn must be initialized 
int rtw_enqueue_xmitframe(struct rtl8192cd_priv *priv, struct xmit_frame *pxmitframe, int insert_tail)
{
	struct tx_insn *txcfg;
	struct stat_info *pstat;
	struct tx_servq *ptxservq;
	_queue *xframe_queue, *sta_queue;
	_irqL irqL;
	
	txcfg = &pxmitframe->txinsn;
	pstat = txcfg->pstat;
	
	if (pstat)
	{
		ptxservq = &pstat->tx_queue[txcfg->q_num];
		
		xframe_queue = &ptxservq->xframe_queue;
		
		xmit_lock(&xframe_queue->lock, &irqL);
		
#ifdef WDS
		if (!(pstat->state & (WIFI_ASOC_STATE|WIFI_WDS)))
#else
		if (!(pstat->state & WIFI_ASOC_STATE))
#endif
		{
			xmit_unlock(&xframe_queue->lock, &irqL);
			return FALSE;
		}
		
		if (insert_tail)
			rtw_list_insert_tail(&pxmitframe->list, &xframe_queue->queue);
		else
			rtw_list_insert_head(&pxmitframe->list, &xframe_queue->queue);
		
		++xframe_queue->qlen;
		
		if (1 == xframe_queue->qlen)
		{
			sta_queue = &priv->pshare->tx_pending_sta_queue[txcfg->q_num];
			
			_rtw_spinlock(&sta_queue->lock);
			
			if ((rtw_is_list_empty(&ptxservq->tx_pending) == TRUE)
					&& (!(pstat->state & WIFI_SLEEP_STATE)
#ifdef WMM_APSD
					|| (pstat->apsd_trigger && (pstat->apsd_bitmap & wmm_apsd_bitmask[txcfg->q_num]))
#endif
					)) {
				rtw_list_insert_tail(&ptxservq->tx_pending, &sta_queue->queue);
				++sta_queue->qlen;
			}
			
			_rtw_spinunlock(&sta_queue->lock);
		}
		
		xmit_unlock(&xframe_queue->lock, &irqL);
	}
	else if (MGNT_QUEUE == txcfg->q_num)	// class 1 frame
	{
		ptxservq = &priv->tx_mgnt_queue;
		
		xframe_queue = &ptxservq->xframe_queue;
		
		xmit_lock(&xframe_queue->lock, &irqL);
		
		if (insert_tail)
			rtw_list_insert_tail(&pxmitframe->list, &xframe_queue->queue);
		else
			rtw_list_insert_head(&pxmitframe->list, &xframe_queue->queue);
		
		++xframe_queue->qlen;
		
		if (1 == xframe_queue->qlen)
		{
			sta_queue = &priv->pshare->tx_pending_sta_queue[MGNT_QUEUE];
			
			_rtw_spinlock(&sta_queue->lock);
			
			if (rtw_is_list_empty(&ptxservq->tx_pending) == TRUE) {
				rtw_list_insert_tail(&ptxservq->tx_pending, &sta_queue->queue);
				++sta_queue->qlen;
			}
			
			_rtw_spinunlock(&sta_queue->lock);
		}
		
		xmit_unlock(&xframe_queue->lock, &irqL);
	}
	else	// enqueue MC/BC
	{
		ptxservq = &priv->tx_mc_queue;
		
		xframe_queue = &ptxservq->xframe_queue;
		
		xmit_lock(&xframe_queue->lock, &irqL);
		
		if (insert_tail)
			rtw_list_insert_tail(&pxmitframe->list, &xframe_queue->queue);
		else
			rtw_list_insert_head(&pxmitframe->list, &xframe_queue->queue);
		
		++xframe_queue->qlen;
		
		if (1 == xframe_queue->qlen)
		{
			sta_queue = &priv->pshare->tx_pending_sta_queue[BE_QUEUE];
			
			_rtw_spinlock(&sta_queue->lock);
			
			if (rtw_is_list_empty(&ptxservq->tx_pending) == TRUE) {
				if (list_empty(&priv->sleep_list)) {
					ptxservq->q_num = BE_QUEUE;
					rtw_list_insert_head(&ptxservq->tx_pending, &sta_queue->queue);
					++sta_queue->qlen;
				} else {
					ptxservq->q_num = MCAST_QNUM;
				}
			}
			
			priv->release_mcast = 0;
			
			_rtw_spinunlock(&sta_queue->lock);
		}
		
		xmit_unlock(&xframe_queue->lock, &irqL);
	}
	
	need_sched_xmit_for_enqueue(priv, ptxservq->q_num);
	
	return TRUE;
}

struct xmit_frame* rtw_dequeue_xmitframe(struct rtl8192cd_priv *priv, int q_num)
{
	struct tx_servq *ptxservq;
	_queue *sta_queue;
	_list *phead, *plist;
	_irqL irqL;
	
	struct xmit_frame *pxmitframe;
	
	sta_queue = &priv->pshare->tx_pending_sta_queue[q_num];
	
	phead = get_list_head(sta_queue);
	
	do {
		ptxservq = NULL;
		
		xmit_lock(&sta_queue->lock, &irqL);
		
#ifdef CONFIG_SDIO_TX_AGGREGATION
		if (rtw_is_list_empty(phead) == FALSE) {
			plist = get_next(phead);
			ptxservq = LIST_CONTAINOR(plist, struct tx_servq, tx_pending);
		}
#else // !CONFIG_SDIO_TX_AGGREGATION
		while (rtw_is_list_empty(phead) == FALSE) {
			plist = get_next(phead);
			ptxservq = LIST_CONTAINOR(plist, struct tx_servq, tx_pending);
			
			if ((&priv->tx_mc_queue == ptxservq) || (&priv->pshare->pspoll_sta_queue == ptxservq))
				break;
			
			// check remaining timeslice
			if (ptxservq->ts_used < STA_TS_LIMIT)
				break;
			
			rtw_list_delete(plist);
			rtw_list_insert_tail(plist, phead);
			ptxservq->ts_used= 0;
			
			ptxservq = NULL;
		}
#endif // CONFIG_SDIO_TX_AGGREGATION
		
		xmit_unlock(&sta_queue->lock, &irqL);
		
		if (NULL == ptxservq) {
			need_sched_xmit_for_dequeue(priv, q_num);
			return NULL;
		}
		
		pxmitframe = rtw_txservq_dequeue(priv, ptxservq);
		
	} while (NULL == pxmitframe);
	
	return pxmitframe;
}

void need_sched_xmit_for_enqueue(struct rtl8192cd_priv *priv, int q_num)
{
	struct priv_shared_info *pshare = priv->pshare;
	struct tx_servq *ptxservq;
	_queue *sta_queue;
	_list *phead, *plist;
	_irqL irqL;
	
	sta_queue = &pshare->tx_pending_sta_queue[q_num];
	phead = get_list_head(sta_queue);
	
	xmit_lock(&sta_queue->lock, &irqL);
	
	if (pshare->need_sched_xmit & BIT(q_num))
		goto out;
	
	if (pshare->low_traffic_xmit & BIT(q_num)) {
		if (rtw_is_list_empty(phead) == FALSE) {
			set_bit(q_num, &pshare->need_sched_xmit);
			tasklet_hi_schedule(&pshare->xmit_tasklet);
		}
	} else {
		int max_agg = priv->pmib->miscEntry.max_xmitbuf_agg;
		int num = 0;
		
		plist = get_next(phead);
		
		while (plist != phead) {
			ptxservq = LIST_CONTAINOR(plist, struct tx_servq, tx_pending);
			plist = get_next(plist);
			
			num += tx_servq_len(ptxservq);
			if (num >= max_agg) {
				set_bit(q_num, &pshare->need_sched_xmit);
				tasklet_hi_schedule(&pshare->xmit_tasklet);
				break;
			}
		}
	}
	
out:
	xmit_unlock(&sta_queue->lock, &irqL);
}

void need_sched_xmit_for_dequeue(struct rtl8192cd_priv *priv, int q_num)
{
	struct priv_shared_info *pshare = priv->pshare;
	struct tx_servq *ptxservq;
	_queue *sta_queue;
	_list *phead, *plist;
	_irqL irqL;
	
	sta_queue = &pshare->tx_pending_sta_queue[q_num];
	phead = get_list_head(sta_queue);
	
	xmit_lock(&sta_queue->lock, &irqL);
	
	if (!(pshare->need_sched_xmit & BIT(q_num)))
		goto out;
	
	if (pshare->low_traffic_xmit & BIT(q_num)) {
		if (rtw_is_list_empty(phead) == TRUE)
			clear_bit(q_num, &pshare->need_sched_xmit);
	} else {
		int max_agg = priv->pmib->miscEntry.max_xmitbuf_agg;
		int num = 0;
		
		plist = get_next(phead);
		
		while (plist != phead) {
			ptxservq = LIST_CONTAINOR(plist, struct tx_servq, tx_pending);
			plist = get_next(plist);
			
			if (&pshare->pspoll_sta_queue == ptxservq)
				goto out;
			
			num += tx_servq_len(ptxservq);
			if (num >= max_agg)
				goto out;
		}
		
		clear_bit(q_num, &pshare->need_sched_xmit);
		if (rtw_is_list_empty(phead) == FALSE)
			pshare->txagg_timeout[q_num] = jiffies + msecs_to_jiffies(10);
	}
	
out:
	xmit_unlock(&sta_queue->lock, &irqL);
}

#ifdef CONFIG_TCP_ACK_TXAGG
#ifdef CONFIG_TCP_ACK_MERGE
int rtw_merge_tcpack(struct rtl8192cd_priv *priv, struct list_head *tcpack_list)
{
	_list *phead, *plist;
	
	struct xmit_frame *pxmitframe;
	struct xmit_frame *pxmitframe2;
	struct tx_insn *txcfg;
	struct sk_buff *skb1, *skb2;
	struct iphdr *iph1, *iph2;
	struct tcphdr *tcph1, *tcph2;
	int num;
	
	phead = tcpack_list;
	plist = phead->prev;
	
	if (plist == phead)
		return 0;
	
	num = 0;
	do {
		pxmitframe = LIST_CONTAINOR(plist, struct xmit_frame, list);
		skb1 = (struct sk_buff *) pxmitframe->txinsn.pframe;
		iph1 = (struct iphdr *)(skb1->data + ETH_HLEN);
		tcph1 = (struct tcphdr *)((u8*)iph1 + iph1->ihl*4);
		
		plist = plist->prev;
		
		while (plist != phead) {
			pxmitframe2 = LIST_CONTAINOR(plist, struct xmit_frame, list);
			plist = plist->prev;
			
			txcfg = &pxmitframe2->txinsn;
			skb2 = (struct sk_buff *) txcfg->pframe;
			iph2 = (struct iphdr *)(skb2->data + ETH_HLEN);
			tcph2 = (struct tcphdr *)((u8*)iph2 + iph2->ihl*4);
			
			if ((iph1->saddr == iph2->saddr) && (iph1->daddr == iph2->daddr) 
					&& (tcph1->source == tcph2->source) && (tcph1->dest == tcph2->dest)
					&& (tcph1->ack_seq != tcph2->ack_seq)) {
				rtw_list_delete(&pxmitframe2->list);
				rtw_free_txinsn_resource(pxmitframe2->priv, txcfg);
				rtw_free_xmitframe(priv, pxmitframe2);
			}
		}
		
		num++;
		plist = pxmitframe->list.prev;
	} while (plist != phead);
	
	return num;
}
#endif // CONFIG_TCP_ACK_MERGE

void rtw_migrate_tcpack(struct rtl8192cd_priv *priv, struct tcpack_servq *tcpackq)
{
	int q_num;
	int nr_tcpack;
	struct stat_info *pstat;
	struct tx_servq *ptxservq;
	_queue *xframe_queue, *sta_queue;
	_irqL irqL;
	
	struct list_head tcpack_list;
	
	q_num = tcpackq->q_num;
	pstat = (struct stat_info *)((char *)tcpackq - FIELD_OFFSET(struct stat_info, tcpack_queue)
		- q_num* sizeof(struct tcpack_servq));

	if (!(pstat->state & WIFI_ASOC_STATE)) {
#if defined(UNIVERSAL_REPEATER) || defined(MBSSID)
		struct aid_obj *aidarray = container_of(pstat, struct aid_obj, station);
		priv = aidarray->priv;
#endif
		priv->ext_stats.tx_drops += tcpackq->xframe_queue.qlen;
		DEBUG_ERR("TX DROP: class 3 error!\n");
		rtw_free_xmitframe_queue(priv, &tcpackq->xframe_queue);
		return;
	}
	
	INIT_LIST_HEAD(&tcpack_list);
	
	// move all xframes in tcpackq to temporary list "tcpack_list"
	xframe_queue = &tcpackq->xframe_queue;
	
	xmit_lock(&xframe_queue->lock, &irqL);
	
	list_splice_init(&xframe_queue->queue, &tcpack_list);
	nr_tcpack = xframe_queue->qlen;
	xframe_queue->qlen = 0;
	
	xmit_unlock(&xframe_queue->lock, &irqL);
	
#ifdef CONFIG_TCP_ACK_MERGE
	if (priv->pshare->rf_ft_var.tcpack_merge && (nr_tcpack > 1)) {
		nr_tcpack = rtw_merge_tcpack(priv, &tcpack_list);
	}
#endif
	
	// next, move all xframes in "tcpack_list" to pstat->tx_queue
	ptxservq = &pstat->tx_queue[q_num];
	
	xframe_queue = &ptxservq->xframe_queue;
	
	xmit_lock(&xframe_queue->lock, &irqL);
	
	list_splice_tail(&tcpack_list, &xframe_queue->queue);
	
	xframe_queue->qlen += nr_tcpack;
	
	if (xframe_queue->qlen == nr_tcpack)
	{
		sta_queue = &priv->pshare->tx_pending_sta_queue[q_num];
		
		_rtw_spinlock(&sta_queue->lock);
		
		if ((rtw_is_list_empty(&ptxservq->tx_pending) == TRUE)
				&& (!(pstat->state & WIFI_SLEEP_STATE)
#ifdef WMM_APSD
				|| (pstat->apsd_trigger && (pstat->apsd_bitmap & wmm_apsd_bitmask[q_num]))
#endif
				)) {
			rtw_list_insert_tail(&ptxservq->tx_pending, &sta_queue->queue);
			++sta_queue->qlen;
		}
		
		_rtw_spinunlock(&sta_queue->lock);
	}
	
	need_sched_xmit_for_enqueue(priv, q_num);
	
	xmit_unlock(&xframe_queue->lock, &irqL);
}

int rtw_enqueue_tcpack_xmitframe(struct rtl8192cd_priv *priv, struct xmit_frame *pxmitframe)
{
	struct tx_insn *txcfg;
	struct stat_info *pstat;
	struct tcpack_servq *tcpackq;
	_queue *xframe_queue, *tcpack_queue;
	_irqL irqL;
	int qlen;
	
	txcfg = &pxmitframe->txinsn;
	pstat = txcfg->pstat;
	
	tcpackq = &pstat->tcpack_queue[txcfg->q_num];
	xframe_queue = &tcpackq->xframe_queue;
	
	xmit_lock(&xframe_queue->lock, &irqL);
	
	if (!(pstat->state & WIFI_ASOC_STATE)) {
	xmit_unlock(&xframe_queue->lock, &irqL);
		return FALSE;
	}
	
	rtw_list_insert_tail(&pxmitframe->list, &xframe_queue->queue);
	qlen = ++xframe_queue->qlen;
	
	if (1 == qlen) {
		tcpackq->start_time = jiffies;
		tcpack_queue = &priv->pshare->tcpack_queue;
		
		_rtw_spinlock(&tcpack_queue->lock);
		
		if (rtw_is_list_empty(&tcpackq->tx_pending) == TRUE) {
			rtw_list_insert_tail(&tcpackq->tx_pending, &tcpack_queue->queue);
			++tcpack_queue->qlen;
		}
		
		_rtw_spinunlock(&tcpack_queue->lock);
	}
		
	xmit_unlock(&xframe_queue->lock, &irqL);
	
	if (MAX_TCP_ACK_AGG == qlen) {
		int deactive = 0;
		tcpack_queue = &priv->pshare->tcpack_queue;
		
		xmit_lock(&tcpack_queue->lock, &irqL);
		
		if (rtw_is_list_empty(&tcpackq->tx_pending) == FALSE) {
			rtw_list_delete(&tcpackq->tx_pending);
			--tcpack_queue->qlen;
			deactive = 1;
		}
		
		xmit_unlock(&tcpack_queue->lock, &irqL);
		
		if (deactive)
		rtw_migrate_tcpack(priv, tcpackq);
	}
	
	return TRUE;
}

int rtw_xmit_enqueue_tcpack(struct rtl8192cd_priv *priv, struct tx_insn *txcfg)
{
	struct xmit_frame *pxmitframe;

	if (NULL == (pxmitframe = rtw_alloc_xmitframe(priv))) {
		DEBUG_WARN("No more xmitframe\n");
		return FALSE;
	}
	
	memcpy(&pxmitframe->txinsn, txcfg, sizeof(struct tx_insn));
	pxmitframe->priv = priv;
	
	if (rtw_enqueue_tcpack_xmitframe(priv, pxmitframe) == FALSE) {
		priv->ext_stats.tx_drops++;
		DEBUG_ERR("TX DROP: %s failed!\n", __func__);
		rtw_free_xmitframe(priv, pxmitframe);
		return FALSE;
	}
	
	return TRUE;
}

void rtw_tcpack_servq_flush(struct rtl8192cd_priv *priv, struct tcpack_servq *tcpackq)
{
	_queue *xframe_queue, *tcpack_queue;
	_list *phead, *plist;
	_irqL irqL;
	
	struct xmit_frame *pxmitframe = NULL;
	
	xframe_queue = &tcpackq->xframe_queue;
	phead = get_list_head(xframe_queue);
	
	xmit_lock(&xframe_queue->lock, &irqL);
	
	plist = get_next(phead);
	while (plist != phead) {
		pxmitframe = LIST_CONTAINOR(plist, struct xmit_frame, list);
		plist = get_next(plist);
		
		rtw_free_txinsn_resource(pxmitframe->priv, &pxmitframe->txinsn);
		rtw_free_xmitframe(priv, pxmitframe);
	}
	_rtw_init_listhead(&(xframe_queue->queue));
	xframe_queue->qlen = 0;
	
	if (pxmitframe) {
	tcpack_queue = &priv->pshare->tcpack_queue;
	
		_rtw_spinlock(&tcpack_queue->lock);
	
	if (rtw_is_list_empty(&tcpackq->tx_pending) == FALSE) {
		rtw_list_delete(&tcpackq->tx_pending);
		--tcpack_queue->qlen;
	}
	
		_rtw_spinunlock(&tcpack_queue->lock);
	}
	
	xmit_unlock(&xframe_queue->lock, &irqL);
}
#endif // CONFIG_TCP_ACK_TXAGG

static void rtl8192cd_xmit_check_timer(unsigned long task_priv)
{
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv *)task_priv;
	struct priv_shared_info *pshare = priv->pshare;
	
#ifdef CONFIG_TCP_ACK_TXAGG
	struct tcpack_servq *tcpackq;
	_queue *tcpack_queue;
	_list *phead, *plist;
#endif
	_queue *sta_queue;
	int q_num;
	_irqL irqL;
	
	if ((pshare->bDriverStopped) || (pshare->bSurpriseRemoved))
		return;
	
#ifdef CONFIG_TCP_ACK_TXAGG
	tcpack_queue = &pshare->tcpack_queue;
	phead = get_list_head(tcpack_queue);
	
	if (rtw_is_list_empty(phead))
		goto tcpack_out;
	
	do {
		tcpackq = NULL;
		
		xmit_lock(&tcpack_queue->lock, &irqL);
		
		if (rtw_is_list_empty(phead) == FALSE) {
			plist = get_next(phead);
			tcpackq = LIST_CONTAINOR(plist, struct tcpack_servq, tx_pending);
			if (time_after_eq(jiffies, tcpackq->start_time+TCP_ACK_TIMEOUT)) {
				rtw_list_delete(&tcpackq->tx_pending);
				--tcpack_queue->qlen;
			} else {
				// don't process tcpackq before TCP_ACK_TIMEOUT
				tcpackq = NULL;
			}
		}
		
		xmit_unlock(&tcpack_queue->lock, &irqL);
		
		if (tcpackq) {
			rtw_migrate_tcpack(priv, tcpackq);
		}
	} while (tcpackq);
	
tcpack_out:
#endif // CONFIG_TCP_ACK_TXAGG
	
	for (q_num = BK_QUEUE; q_num <= VO_QUEUE; ++q_num) {
		sta_queue = &pshare->tx_pending_sta_queue[q_num];
		
		xmit_lock(&sta_queue->lock, &irqL);
		
		if (!(pshare->need_sched_xmit & BIT(q_num))
			&& sta_queue->qlen
			&& time_after_eq(jiffies, pshare->txagg_timeout[q_num]))
		{
			set_bit(q_num, &pshare->need_sched_xmit);
			tasklet_hi_schedule(&pshare->xmit_tasklet);
		}
		
		// Update low traffic state for each ACQ
		if (pshare->low_traffic_xmit_stats[q_num] < pshare->rf_ft_var.low_traffic_xmit_thd)
			pshare->low_traffic_xmit |= BIT(q_num);
		else
			pshare->low_traffic_xmit &= ~ BIT(q_num);
		pshare->low_traffic_xmit_stats[q_num] = 0;
		
		xmit_unlock(&sta_queue->lock, &irqL);
	}
	
	mod_timer(&pshare->xmit_check_timer, jiffies+msecs_to_jiffies(10));
}

int rtw_send_xmitframe(struct xmit_frame *pxmitframe)
{
	struct rtl8192cd_priv *priv;
	struct tx_insn* txcfg;
	
	priv = pxmitframe->priv;
	txcfg = &pxmitframe->txinsn;
	
	if (MCAST_QNUM == txcfg->q_num) {
		if (priv->release_mcast) {
			// Limit the number of TX BC/MC frame during ATIM window
			priv->tx_mc_pkt_num++;
			if (priv->tx_mc_pkt_num >= MAX_TX_MC_PKT) {
				struct tx_servq *ptxservq;
				_queue *sta_queue;
				_irqL irqL;
				int deactive = 0;
				
				ptxservq = &priv->tx_mc_queue;
				sta_queue = &priv->pshare->tx_pending_sta_queue[ptxservq->q_num];
				
				xmit_lock(&sta_queue->lock, &irqL);
				
				if (rtw_is_list_empty(&ptxservq->tx_pending) == FALSE) {
					rtw_list_delete(&ptxservq->tx_pending);
					--sta_queue->qlen;
					deactive = 1;
				}
				
				xmit_unlock(&sta_queue->lock, &irqL);
				
				if (deactive)
					need_sched_xmit_for_dequeue(priv, ptxservq->q_num);
				priv->release_mcast = 0;
			} else if (tx_servq_len(&priv->tx_mc_queue) == 0)
				priv->release_mcast = 0;
		}
	}
	
	switch (txcfg->next_txpath) {
	case TXPATH_HARD_START_XMIT:
		__rtl8192cd_usb_start_xmit(priv, txcfg);
		break;
		
	case TXPATH_SLOW_PATH:
		{
			struct net_device *wdsDev = NULL;
#ifdef WDS
			if (txcfg->wdsIdx >= 0) {
				wdsDev = priv->wds_dev[txcfg->wdsIdx];
			}
#endif
			
			rtl8192cd_tx_slowPath(priv, (struct sk_buff*)txcfg->pframe, txcfg->pstat,
					priv->dev, wdsDev, &pxmitframe->txinsn);
		}
		break;
		
	case TXPATH_FIRETX:
		if (__rtl8192cd_firetx(priv, txcfg) == CONGESTED) {
			rtw_free_txinsn_resource(priv, txcfg);
		}
		rtw_handle_xmit_fail(priv, txcfg);
		break;
	}
	
	rtw_free_xmitframe(priv, pxmitframe);

	return 0;
}

void rtl8192es_xmit_tasklet(unsigned long data)
{
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv*)data;
	struct priv_shared_info *pshare = priv->pshare;
	struct xmit_frame *pxmitframe;
	struct xmit_buf *pxmitbuf;
	struct tx_insn* txcfg;
	
	const u8 q_priority[] = {HIGH_QUEUE, MGNT_QUEUE, VO_QUEUE, VI_QUEUE, BE_QUEUE, BK_QUEUE};
	const int ts_limit[]  = {     65536,          0,    65536,    49152,    32768,    16384}; // unit: microsecond
	int i, q_num=-1;
	
	while(1)
	{
		if ((pshare->bDriverStopped == TRUE)||(pshare->bSurpriseRemoved== TRUE))
		{
			printk("[%s] bDriverStopped(%d) OR bSurpriseRemoved(%d)\n",
				__FUNCTION__, pshare->bDriverStopped, pshare->bSurpriseRemoved);
			return;
		}
		
		if (pshare->tx_urgent_queue.qlen && pshare->free_urg_xmitbuf_queue.qlen) {
			pxmitframe = rtw_dequeue_urg_xmitframe(priv);
			if (pxmitframe) {
				txcfg = &pxmitframe->txinsn;
				q_num = txcfg->q_num;
				pxmitbuf = rtw_alloc_urg_xmitbuf(priv, (u8)q_num);
				if (pxmitbuf) {
					if (test_and_set_bit(q_num, &pshare->use_hw_queue_bitmap) == 0)
						goto sendout;
					
					rtw_free_urg_xmitbuf(priv, pxmitbuf);
				}
				rtw_enqueue_urg_xmitframe(priv, pxmitframe, ENQUEUE_TO_HEAD);
			}
		}
		
		pxmitframe  = NULL;
		
		for (i = 0; i < ARRAY_SIZE(q_priority); ++i) {
			q_num = q_priority[i];
			
			if (MGNT_QUEUE == q_num) {
				if (0 == pshare->free_xmit_extbuf_queue.qlen)
					continue;
			} else {
				if (0 == pshare->free_xmitbuf_queue.qlen)
					continue;

				// check whether timeslice quota goes beyond the limit
				if (pshare->ts_used[q_num] > ts_limit[i])
					continue;
			}

			if (!(pshare->need_sched_xmit & BIT(q_num)))
				continue;

			if (test_and_set_bit(q_num, &pshare->use_hw_queue_bitmap) == 0) {
				if (NULL != (pxmitframe = rtw_dequeue_xmitframe(priv, q_num)))
					break;
				
				clear_bit(q_num, &pshare->use_hw_queue_bitmap);
			}
		}
		
		if (NULL == pxmitframe) {
			unsigned char reset_flag = 0;
			
			for (i = 0; i < MAX_HW_TX_QUEUE; ++i) {
				if (0 != pshare->ts_used[i]) {
					reset_flag = 1;
					pshare->ts_used[i] = 0;
				}
			}

			if (reset_flag)
				continue;
			else
				break;
		}
		
		txcfg = &pxmitframe->txinsn;
		
		// re-assign q_num to avoid txcfg->q_num is not equal tx_servq.q_num for tx_mc_queue.
		// Because q_num of tx_mc_queue will switch to MCAST_QNUM once any STA sleeps.
		// This action is redundent for other queues.
		txcfg->q_num = q_num;
		
		if (_SKB_FRAME_TYPE_ == txcfg->fr_type) {
#ifdef CONFIG_SDIO_TX_AGGREGATION
			pxmitbuf = get_usable_pending_xmitbuf(priv, txcfg);
			if (NULL == pxmitbuf)
#endif
				pxmitbuf = rtw_alloc_xmitbuf(priv, (u8)q_num);
		} else {
			pxmitbuf = rtw_alloc_xmitbuf_ext(priv, (u8)q_num);
		}
		
		if (NULL == pxmitbuf) {
			if (txcfg->is_pspoll) {
				txcfg->is_pspoll = 0;
				rtw_pspoll_sta_enqueue(priv, txcfg->pstat, ENQUEUE_TO_HEAD);
			}
			if (rtw_enqueue_xmitframe(pxmitframe->priv, pxmitframe, ENQUEUE_TO_HEAD) == FALSE) {
				pxmitframe->priv->ext_stats.tx_drops++;
				DEBUG_ERR("TX DROP: rtw_enqueue_xmitframe failed!\n");
				rtw_free_txinsn_resource(pxmitframe->priv, txcfg);
				rtw_free_xmitframe(priv, pxmitframe);
			}
			// Release the ownership of the HW TX queue
			clear_bit(q_num, &pshare->use_hw_queue_bitmap);
			continue;
		}
		
sendout:
		pxmitbuf->agg_start_with = txcfg;
		pxmitbuf->use_hw_queue = 1;
		txcfg->pxmitbuf = pxmitbuf;
		
		rtw_send_xmitframe(pxmitframe);
	}
}

int rtw_txinsn_require_bufsize(struct rtl8192cd_priv *priv, struct tx_insn *txcfg)
{
#ifdef CONFIG_IEEE80211W
	int sw_encrypt = UseSwCrypto(priv, txcfg->pstat, (txcfg->pstat ? FALSE : TRUE), txcfg->isPMF);
#else
	int sw_encrypt = UseSwCrypto(priv, txcfg->pstat, (txcfg->pstat ? FALSE : TRUE));
#endif
	
	return txcfg->llc + txcfg->fr_len + ((_TKIP_PRIVACY_== txcfg->privacy)? 8 : 0) +
		((txcfg->hdr_len + txcfg->iv + (sw_encrypt ? (txcfg->icv + txcfg->mic) : 0)
		+ TXDESC_SIZE + TXAGG_DESC_ALIGN_SZ)*txcfg->frg_num) - TXAGG_DESC_ALIGN_SZ;
}

void rtw_xmitbuf_aggregate(struct rtl8192cd_priv *priv, struct xmit_buf *pxmitbuf, struct stat_info *pstat, int q_num)
{
	struct tx_servq *ptxservq;
	struct xmit_frame *pxmitframe;
	struct tx_insn *txcfg;
	
	_queue *sta_queue;
	_list *phead, *plist;
	_irqL irqL;
	
	BUG_ON(0 == pxmitbuf->use_hw_queue);
	
	if (pstat) {
		ptxservq = &pstat->tx_queue[q_num];
	} else if (MGNT_QUEUE == q_num) {
		ptxservq = &priv->tx_mgnt_queue;
	} else {
		ptxservq = &priv->tx_mc_queue;
	}
	
	sta_queue = &priv->pshare->tx_pending_sta_queue[q_num];
	phead = get_list_head(sta_queue);
	
	while (1) {
		
		if (pxmitbuf->agg_num >= priv->pmib->miscEntry.max_xmitbuf_agg)
			break;
		
		if (rtw_is_list_empty(&ptxservq->tx_pending) == TRUE) {
			// re-select an another valid tx servq
			pxmitframe = NULL;
		} else {
			// check remaining timeslice
			if ((&priv->tx_mc_queue == ptxservq) || (&priv->pshare->pspoll_sta_queue == ptxservq)
					|| (ptxservq->ts_used < STA_TS_LIMIT)) {
				pxmitframe = rtw_txservq_dequeue(priv, ptxservq);
			} else {
				xmit_lock(&sta_queue->lock, &irqL);

				if (rtw_is_list_empty(&ptxservq->tx_pending) == FALSE) {
					rtw_list_delete(&ptxservq->tx_pending);
					rtw_list_insert_tail(&ptxservq->tx_pending, phead);
				}
				ptxservq->ts_used = 0;

				xmit_unlock(&sta_queue->lock, &irqL);
				
				pxmitframe = NULL;
			}
		}
		
		while (NULL == pxmitframe) {
			
			plist = NULL;
			
			xmit_lock(&sta_queue->lock, &irqL);
			
			if (rtw_is_list_empty(phead) == FALSE) {
				plist = get_next(phead);
			}
			
			xmit_unlock(&sta_queue->lock, &irqL);
			
			if (NULL == plist) return;
			
			ptxservq= LIST_CONTAINOR(plist, struct tx_servq, tx_pending);
			
			pxmitframe = rtw_txservq_dequeue(priv, ptxservq);
		}
		
		txcfg = &pxmitframe->txinsn;
		
		if (((pxmitbuf->agg_num + txcfg->frg_num) > MAX_TX_AGG_PKT_NUM)
				|| ((rtw_txinsn_require_bufsize(pxmitframe->priv, txcfg)+
				PTR_ALIGN(pxmitbuf->pkt_tail, TXAGG_DESC_ALIGN_SZ)) > pxmitbuf->pkt_end))
		{
			if (txcfg->is_pspoll) {
				rtw_pspoll_sta_enqueue(priv, txcfg->pstat, ENQUEUE_TO_HEAD);
				txcfg->is_pspoll = 0;
			}
			if (rtw_enqueue_xmitframe(priv, pxmitframe, ENQUEUE_TO_HEAD) == FALSE) {
				pxmitframe->priv->ext_stats.tx_drops++;
				DEBUG_ERR("TX DROP: rtw_enqueue_xmitframe failed!\n");
				rtw_free_txinsn_resource(pxmitframe->priv, txcfg);
				rtw_free_xmitframe(priv, pxmitframe);
			}
			break;
		}
		
		txcfg->pxmitbuf = pxmitbuf;
		
		// re-assign q_num to avoid txcfg->q_num is not equal tx_servq.q_num for tx_mc_queue.
		// Because q_num of tx_mc_queue will switch to MCAST_QNUM once any STA sleeps.
		// This action is redundent for other queues.
		txcfg->q_num = q_num;
		
		rtw_send_xmitframe(pxmitframe);
	}
}

int rtl8192cd_usb_tx_recycle(struct rtl8192cd_priv *priv, struct tx_desc_info* pdescinfo)
{
	int needRestartQueue = 0;

	if (pdescinfo->type == _SKB_FRAME_TYPE_)
	{
		struct sk_buff *skb = (struct sk_buff *)(pdescinfo->pframe);
#ifdef MP_TEST
		if (OPMODE & WIFI_MP_CTX_BACKGROUND) {
			skb->data = skb->head;
			skb->tail = skb->data;
			skb->len = 0;
			priv->pshare->skb_tail = (priv->pshare->skb_tail + 1) & (NUM_MP_SKB - 1);
		}
		else
#endif
		{
#ifdef __LINUX_2_6__
			rtl_kfree_skb(pdescinfo->priv, skb, _SKB_TX_IRQ_);
#endif
			needRestartQueue = 1;
		}
	}
	else if (pdescinfo->type == _PRE_ALLOCMEM_)
	{
		release_mgtbuf_to_poll(priv, (UINT8 *)(pdescinfo->pframe));
	}
	else if (pdescinfo->type == _RESERVED_FRAME_TYPE_)
	{
		// the chained skb, no need to release memory
	}
	else
	{
		DEBUG_ERR("Unknown tx frame type %d\n", pdescinfo->type);
	}

	pdescinfo->type = _RESERVED_FRAME_TYPE_;

	return needRestartQueue;
}

void sdio_recycle_xmitbuf(struct rtl8192cd_priv *priv, struct xmit_buf *pxmitbuf)
{
	struct priv_shared_info *pshare = priv->pshare;
	_queue *xmitbuf_queue;
	_irqL irqL;
#ifndef CONFIG_TX_RECYCLE_EARLY
	int i;
#endif

	if (rtw_is_list_empty(&pxmitbuf->tx_xmitbuf_list) == FALSE) {
		xmitbuf_queue = &pshare->tx_xmitbuf_waiting_queue[pxmitbuf->q_num];
		_enter_critical_bh(&xmitbuf_queue->lock, &irqL);

		rtw_list_delete(&pxmitbuf->tx_xmitbuf_list);
		--xmitbuf_queue->qlen;

		_exit_critical_bh(&xmitbuf_queue->lock, &irqL);
	}
	
#ifndef CONFIG_TX_RECYCLE_EARLY
	for (i = 0; i < pxmitbuf->agg_num; ++i) {
		rtl8192cd_usb_tx_recycle(priv, &pxmitbuf->txdesc_info[i]);
	}
#endif
	
	if (BEACON_QUEUE == pxmitbuf->q_num) {
		if (0 == pxmitbuf->status)
			++priv->ext_stats.beacon_ok;
		else
			++priv->ext_stats.beacon_er;
		
		rtw_free_beacon_xmitbuf(priv, pxmitbuf);
	} else {
		rtw_free_xmitbuf(priv, pxmitbuf);
	}

#ifdef MP_TEST
	if ((OPMODE & (WIFI_MP_STATE | WIFI_MP_CTX_BACKGROUND | WIFI_MP_CTX_BACKGROUND_STOPPING)) ==
		(WIFI_MP_STATE | WIFI_MP_CTX_BACKGROUND) )
	{
		notify_mp_ctx_background(priv);
	}
#endif
}

static inline u32 ffaddr2deviceId(struct rtl8192cd_priv *priv, u32 addr)
{
	HAL_INTF_DATA_TYPE *pHalData = GET_HAL_INTF_DATA(priv);

	return pHalData->Queue2Pipe[addr];
}

static inline u8 rtw_sdio_get_tx_pageidx(u32 addr)
{
	u8 idx;

	switch (addr)
	{
		case WLAN_TX_HIQ_DEVICE_ID:
			idx = HI_QUEUE_IDX;
			break;
		case WLAN_TX_MIQ_DEVICE_ID:
			idx = MID_QUEUE_IDX;
			break;
		case WLAN_TX_LOQ_DEVICE_ID:
			idx = LOW_QUEUE_IDX;
			break;
		case WLAN_TX_EXQ_DEVICE_ID:
			idx = EXTRA_QUEUE_IDX;
			break;
		default:
			printk("get_txfifo_pageidx(): wrong TX addr %x\n", addr);
			idx = 0;
			break;
	}

	return idx;
}

static int wait_for_txoqt(struct rtl8192cd_priv *priv, u8 q_num, u8 agg_num)
{
	struct priv_shared_info *pshare = priv->pshare;
	HAL_INTF_DATA_TYPE *pHalData = GET_HAL_INTF_DATA(priv);
	int oqt_idx = Queue2Oqt[q_num];
	int n = 0;

	while (pHalData->SdioTxOQTFreeSpace[oqt_idx] < agg_num) {
		if ((TRUE == pshare->bSurpriseRemoved) || (TRUE == pshare->bDriverStopped)) {
			printk("%s: bDriverStopped(%d) OR bSurpriseRemoved(%d) (wait TxOQT)\n",
				__func__, pshare->bDriverStopped, pshare->bSurpriseRemoved);
			return FALSE;
		}

		sdio_query_txoqt_status(priv);
		if ((++n % 20) == 0) {
			unsigned int pause, acq_info[8];
			int i;
			
			printk("%s(%d): OQT %d does not have enough space(%d), it needs: %d\n",
 				__func__, n, oqt_idx, pHalData->SdioTxOQTFreeSpace[oqt_idx], agg_num);
#if 0
			printk("QINFO=%08X %08X %08X %08X\n",
				RTL_R32(0x400), RTL_R32(0x404), RTL_R32(0x408), RTL_R32(0x40c));
			printk("      %08X %08X %08X %08X\n",
				RTL_R32(0x468), RTL_R32(0x46c), RTL_R32(0x470), RTL_R32(0x474));
			printk("TXPAUSE=%02X, SLEEP=%08X %08X\n",
				RTL_R8(TXPAUSE), RTL_R32(REG_MACID_SLEEP), 
				RTL_R32(REG_MACID_SLEEP1));
			printk("0x210=%08X\n", RTL_R32(TXDMA_STATUS));
#endif
			// If all ACQ are blocked, then leave the sleep state of STA occupied ACQ to avoid TX stop
			if (RTL_R8(0x45C) == 0xFF) {
				pause = RTL_R32(REG_MACID_SLEEP);
				for (i = 0; i < 4; i++) {
					acq_info[i] = RTL_R32(REG_Q0_INFO+4*i);
					pause &= ~ BIT(acq_info[i] >> 25);
					
					acq_info[i+4] = RTL_R32(REG_Q4_INFO+4*i);
					pause &= ~ BIT(acq_info[i+4] >> 25);
				}
				RTL_W32(REG_MACID_SLEEP, pause);
				
				printk("[%s] PAUSE=%08X\n", __func__, pause);
				printk("QINFO=%08X %08X %08X %08X\n",
					acq_info[0], acq_info[1], acq_info[2], acq_info[3]);
				printk("      %08X %08X %08X %08X\n",
					acq_info[4], acq_info[5], acq_info[6], acq_info[7]);
			}
			
			msleep(1);
			yield();
		}
	}

	pHalData->SdioTxOQTFreeSpace[oqt_idx] -= agg_num;
	
#ifdef CONFIG_SDIO_TX_IN_INTERRUPT
	if (pHalData->WaitSdioTxOQT) {
		pHalData->WaitSdioTxOQT = 0;
		++pshare->nr_out_of_txoqt_space;
	} else
#endif
	{
		if (n > 1)
			++pshare->nr_out_of_txoqt_space;
	}

	return TRUE;
}

#ifdef CONFIG_SDIO_TX_INTERRUPT
#ifdef CONFIG_SDIO_TX_IN_INTERRUPT
int rtw_check_txoqt(struct rtl8192cd_priv *priv, u8 q_num, u8 agg_num)
{
	HAL_INTF_DATA_TYPE *pHalData = GET_HAL_INTF_DATA(priv);
	int oqt_idx = Queue2Oqt[q_num];
	
	return (pHalData->SdioTxOQTFreeSpace[oqt_idx] < agg_num) ? FALSE : TRUE;
}

static int try_to_wait_for_txoqt(struct rtl8192cd_priv *priv, u8 q_num, u8 agg_num)
{
	HAL_INTF_DATA_TYPE *pHalData = GET_HAL_INTF_DATA(priv);
	int oqt_idx = Queue2Oqt[q_num];
	
	if (pHalData->SdioTxOQTFreeSpace[oqt_idx] < agg_num) {
		sdio_query_txoqt_status(priv);
		if (pHalData->SdioTxOQTFreeSpace[oqt_idx] < agg_num) {
			pHalData->WaitSdioTxOQT = 1;
			pHalData->WaitSdioTxOQTSpace = agg_num;
			pHalData->WaitSdioTxOQTQNum = q_num;
			return FALSE;
		}
	}

	pHalData->SdioTxOQTFreeSpace[oqt_idx] -= agg_num;
	return TRUE;
}
#endif // CONFIG_SDIO_TX_IN_INTERRUPT

static s32 rtw_sdio_check_tx_freepage(struct rtl8192cd_priv *priv, u8 page_idx, u8 page_num)
{
	HAL_INTF_DATA_TYPE *pHalData = GET_HAL_INTF_DATA(priv);
	u8 *free_tx_page = pHalData->SdioTxFIFOFreePage;

	if ((free_tx_page[page_idx] + free_tx_page[PUBLIC_QUEUE_IDX]) > (page_num + 1)) {
		return TRUE;
	} else {
		return FALSE;
	}
}

static void rtw_sdio_update_tx_freepage(struct rtl8192cd_priv *priv, u8 page_idx, u8 page_num)
{
	HAL_INTF_DATA_TYPE *pHalData = GET_HAL_INTF_DATA(priv);
	u8 *free_tx_page = pHalData->SdioTxFIFOFreePage;
	u8 requiredPublicPage = 0;

#ifdef TXDMA_ERROR_PAGE_DEBUG
	memcpy(pHalData->SdioTxFIFOFreePage_prev, free_tx_page, SDIO_TX_FREE_PG_QUEUE);
#endif

	if (page_num <= free_tx_page[page_idx]) {
		free_tx_page[page_idx] -= page_num;
	} else if ((free_tx_page[page_idx] + free_tx_page[PUBLIC_QUEUE_IDX]) > (page_num + 1)) {
		// The number of page which public page included is available.
		requiredPublicPage = page_num - free_tx_page[page_idx];
		free_tx_page[page_idx] = 0;
		free_tx_page[PUBLIC_QUEUE_IDX] -= requiredPublicPage;
	} else {
		printk("update_tx_freepage(): page error !!!!!!\n");
	}
}
#endif // CONFIG_SDIO_TX_INTERRUPT

#ifdef CONFIG_SDIO_TX_AGGREGATION
struct xmit_buf* get_usable_pending_xmitbuf(struct rtl8192cd_priv *priv, struct tx_insn* txcfg)
{
	_list *phead, *plist;
	_irqL irql;
	struct xmit_buf *pxmitbuf, *pxmitbuf_usable = NULL;
	_queue *pqueue;
	
	pqueue = &priv->pshare->pending_xmitbuf_queue;
	phead = get_list_head(pqueue);
	
	xmit_lock(&pqueue->lock, &irql);
	
	plist = phead->prev;
	while (plist != phead) {
		pxmitbuf = LIST_CONTAINOR(plist, struct xmit_buf, list);
		plist = plist->prev;
		
		if ((0 == pxmitbuf->ext_tag) && (pxmitbuf->q_num == txcfg->q_num)) {
			if (((pxmitbuf->agg_num + txcfg->frg_num) <= MAX_TX_AGG_PKT_NUM)
					&& ((pxmitbuf->agg_num + txcfg->frg_num) <= priv->pmib->miscEntry.max_xmitbuf_agg)
					&& ((rtw_txinsn_require_bufsize(priv, txcfg)+
					PTR_ALIGN(pxmitbuf->pkt_tail, TXAGG_DESC_ALIGN_SZ)) <= pxmitbuf->pkt_end)) {
				rtw_list_delete(&pxmitbuf->list);
				--pqueue->qlen;
				
				pxmitbuf_usable = pxmitbuf;
				pxmitbuf_usable->flags |= XMIT_BUF_FLAG_REUSE;
			}
			break;
		}
	}
	
	xmit_unlock(&pqueue->lock, &irql);
	
	return pxmitbuf_usable;
}
#endif // CONFIG_SDIO_TX_AGGREGATION

#ifdef TXDMA_ERROR_DEBUG
#ifdef TXDMA_ERROR_LLT_DEBUG
#define NUM_LLT_ENTRY	256

void dump_LLT_table(struct rtl8192cd_priv *priv)
{
	int i, count;
	unsigned int value;
	
	u8 mapping[NUM_LLT_ENTRY];
	u8 txpause;

	txpause = RTL_R8(TXPAUSE);
	RTL_W8(TXPAUSE, 0xFF);
	
	printk(KERN_ERR "[%s] Dump LLT [head=0x%02X, tail=0x%02X, BCNQ_BDNY=0x%02X]\n",
		__func__, RTL_R8(0x20b), RTL_R8(0x427), RTL_R8(0x424));
	
	for (i = 0; i < NUM_LLT_ENTRY; ++i) {
		RTL_W32(LLT_INI, (0x80000000|(i<<LLTINI_ADDR_SHIFT)));
		
		count = 0;
		while (1) {
			value = RTL_R32(LLT_INI);
			if (!(value & ((LLTE_RWM_RD & LLTE_RWM_Mask) << LLTE_RWM_SHIFT)))
				break;
			if (++count >= 100) {
				printk("[%s] LLT Polling failed !!!\n", __func__);
				goto out;
			}
		}

		mapping[i] = value & 0xff;
	}
	
out:
	RTL_W8(TXPAUSE, txpause);
	
	for (i = 0; i < 256; ++i) {
		printk(KERN_ERR "0x%02x \t0x%02x\n", i, mapping[i]);
	}
	printk(KERN_ERR "[%s] Dump LLT End\n", __func__);
}
#endif // TXDMA_ERROR_LLT_DEBUG

static inline void check_txdma_error(struct rtl8192cd_priv *priv, struct xmit_buf *pxmitbuf
#ifdef TXDMA_ERROR_PAGE_DEBUG
		, u32 reg204, u32 reg214
#endif
		)
{
	if ((0 == priv->pshare->tx_dma_err) && (priv->pshare->tx_dma_status = RTL_R32(TXDMA_STATUS)))
	{
#ifdef TXDMA_ERROR_PAGE_DEBUG
		HAL_INTF_DATA_TYPE *pHalData = GET_HAL_INTF_DATA(priv);
#endif
		struct tx_desc *pdesc;
		struct tx_desc_info *pdescinfo;
		int i, q_sel, q_num;
		int pg_num, total_pg_num;

		priv->pshare->tx_dma_err++;
		
		printk(KERN_ERR "[%s] TXDMA error 0x%lX\n", __FUNCTION__, priv->pshare->tx_dma_status);
#ifdef TXDMA_ERROR_PAGE_DEBUG
		printk(KERN_ERR "[REG][prev] 0x200=%08X, 0x204=%08X, 0x214=%08X [now] 0x204=%08X, 0x214=%08X\n",
			RTL_R32(RQPN), reg204, reg214, RTL_R32(FIFOPAGE), RTL_R32(RQPN_NPQ));
		printk(KERN_ERR "[TxFIFOFreePage][prev] HI %d MI %d LO %d PUB %d [now] HI %d MI %d LO %d PUB %d\n",
			pHalData->SdioTxFIFOFreePage_prev[HI_QUEUE_IDX],
			pHalData->SdioTxFIFOFreePage_prev[MID_QUEUE_IDX],
			pHalData->SdioTxFIFOFreePage_prev[LOW_QUEUE_IDX],
			pHalData->SdioTxFIFOFreePage_prev[PUBLIC_QUEUE_IDX],
			pHalData->SdioTxFIFOFreePage[HI_QUEUE_IDX],
			pHalData->SdioTxFIFOFreePage[MID_QUEUE_IDX],
			pHalData->SdioTxFIFOFreePage[LOW_QUEUE_IDX],
			pHalData->SdioTxFIFOFreePage[PUBLIC_QUEUE_IDX]);
#else
		printk(KERN_ERR "[REG] 0x200=%08X, 0x204=%08X, 0x214=%08X\n",
			RTL_R32(RQPN), RTL_R32(FIFOPAGE), RTL_R32(RQPN_NPQ));
#endif
		printk(KERN_ERR "[xmitbuf] pkt_data=%p, pkt_tail=%p, len=%d\n",
			pxmitbuf->pkt_data, pxmitbuf->pkt_tail, pxmitbuf->len);
		printk(KERN_ERR "[xmitbuf] q_num=%d, pkt_offset=%d, agg_num=%d, pg_num=%d\n",
			pxmitbuf->q_num, pxmitbuf->pkt_offset, pxmitbuf->agg_num, pxmitbuf->pg_num);
		
		q_num = pxmitbuf->q_num;
		total_pg_num = 0;
		for (i = 0; i < pxmitbuf->agg_num; ++i) {
			pdescinfo = &pxmitbuf->txdesc_info[i];
			pdesc = (struct tx_desc *)pdescinfo->buf_ptr;
			q_sel = (get_desc(pdesc->Dword1) >> TX_DW1_QSEL_SH) & TX_DW1_QSEL_MSK;
			
			pg_num = (pdescinfo->buf_len + TX_PAGE_SIZE-1) / TX_PAGE_SIZE;
			total_pg_num += pg_num;
			
			printk(KERN_ERR "[descinfo %d] buf_ptr=%p, buf_len=%d, pg_num=%d\n",
				i, pdescinfo->buf_ptr, pdescinfo->buf_len, pg_num);
			
			if (((HIGH_QUEUE == q_num) && (q_sel != 0x11))
				|| ((BEACON_QUEUE == q_num) && (q_sel != 0x10))
				|| ((MGNT_QUEUE == q_num) && (q_sel != 0x12))
				|| ((BK_QUEUE == q_num) && (q_sel != 0x01) && (q_sel != 0x02))
				|| ((BE_QUEUE == q_num) && (q_sel != 0x00) && (q_sel != 0x03))
				|| ((VI_QUEUE == q_num) && (q_sel != 0x04) && (q_sel != 0x05))
				|| ((VO_QUEUE == q_num) && (q_sel != 0x06) && (q_sel != 0x07))
				) {
				printk(KERN_ERR "==> TXDESC QSEL mismatch!!(q_num=%d, q_sel=%d)\n", q_num, q_sel);
			}
			mem_dump("TX DESC", (u8*)pdesc, TXDESC_SIZE);
			mem_dump("TX packet", (u8*)pdesc+TXDESC_SIZE, min(pdescinfo->buf_len-TXDESC_SIZE, 64u));
		}
		
		if (pxmitbuf->pg_num != total_pg_num) {
			printk(KERN_ERR "==> incorrect pg_num!!(pg_num=%d, recalc=%d)\n", pxmitbuf->pg_num, total_pg_num);
		}
		
#if 0
		dump_reg(priv);
#endif
			
#ifdef TXDMA_ERROR_LLT_DEBUG
		if (priv->pshare->tx_dma_status & BIT4)	// BIT_LLT_NULL_PG
			dump_LLT_table(priv);
#endif
	}
}
#endif // TXDMA_ERROR_DEBUG

void enqueue_pending_xmitbuf(struct rtl8192cd_priv *priv, struct xmit_buf *pxmitbuf)
{
	_queue *pqueue;
	_list *phead;
	_irqL irql;

	pqueue = &priv->pshare->pending_xmitbuf_queue;
	
	phead = get_list_head(pqueue);

	xmit_lock(&pqueue->lock, &irql);

	if (2 == pxmitbuf->ext_tag) {
		// Insert to the last urgent xmitbuf
		if (priv->pshare->last_urg_xmitbuf) {
			rtw_list_insert_head(&pxmitbuf->list, &priv->pshare->last_urg_xmitbuf->list);
		} else {
			rtw_list_insert_head(&pxmitbuf->list, phead);
		}
		priv->pshare->last_urg_xmitbuf = pxmitbuf;
	} else
		rtw_list_insert_tail(&pxmitbuf->list, phead);
	++pqueue->qlen;

	xmit_unlock(&pqueue->lock, &irql);

#ifdef CONFIG_SDIO_TX_INTERRUPT
	if (GET_HAL_INTF_DATA(priv)->SdioTxIntStatus)
		return;
#endif
	if (test_and_set_bit(WAKE_EVENT_XMIT, &priv->pshare->xmit_wake) == 0)
		wake_up_process(priv->pshare->xmit_thread);
}

struct xmit_buf* dequeue_pending_xmitbuf(struct rtl8192cd_priv *priv)
{
	_list *phead = NULL, *plist = NULL;
	_irqL irql;
	struct xmit_buf *pxmitbuf = NULL;
	_queue *pqueue = &priv->pshare->pending_xmitbuf_queue;
	
	phead = get_list_head(pqueue);

	xmit_lock(&pqueue->lock, &irql);
	
	if (rtw_is_list_empty(phead) == FALSE) {
		plist = get_next(phead);
		rtw_list_delete(plist);
		--pqueue->qlen;
		
		pxmitbuf = LIST_CONTAINOR(plist, struct xmit_buf, list);
		// Update the pointer of the last urgent xmitbuf in pending_xmitbuf_queue
		if (priv->pshare->last_urg_xmitbuf == pxmitbuf)
			priv->pshare->last_urg_xmitbuf = NULL;
	}

	xmit_unlock(&pqueue->lock, &irql);
	
	return pxmitbuf;
}

#ifdef CONFIG_SDIO_TX_INTERRUPT
struct xmit_buf* try_to_dequeue_pending_xmitbuf(struct rtl8192cd_priv *priv, int from)
{
	HAL_INTF_DATA_TYPE *pHalData = GET_HAL_INTF_DATA(priv);
	_list *phead, *plist = NULL;
	_irqL irql;
	struct xmit_buf *pxmitbuf;
	_queue *pqueue;
	u8 pg_num;
	
	pqueue = &priv->pshare->pending_xmitbuf_queue;
	phead = get_list_head(pqueue);
	
do_check:
	
#ifdef CONFIG_SDIO_TX_IN_INTERRUPT
	if ((SDIO_TX_THREAD == from) && pHalData->SdioTxIntStatus)
		return NULL;
#endif
	
	pxmitbuf = NULL;
	
	xmit_lock(&pqueue->lock, &irql);
	
	if (rtw_is_list_empty(phead) == FALSE) {
		plist = get_next(phead);
		pxmitbuf = LIST_CONTAINOR(plist, struct xmit_buf, list);
		// Sometimes pxmitbuf->pg_num is changed when non-full xmitbuf is reused, so backup first
		// Avoid free page threshold is less than updated pxmitbuf->pg_num to cause TX stop issue
		pg_num = pxmitbuf->pg_num;
		
		if (rtw_sdio_check_tx_freepage(priv, pxmitbuf->tx_page_idx, pg_num) == TRUE) {
			rtw_sdio_update_tx_freepage(priv, pxmitbuf->tx_page_idx, pg_num);
			rtw_list_delete(plist);
			--pqueue->qlen;
			
			// Update the pointer of the last urgent xmitbuf in pending_xmitbuf_queue
			if (priv->pshare->last_urg_xmitbuf == pxmitbuf)
				priv->pshare->last_urg_xmitbuf = NULL;
			
			set_bit(from, &priv->pshare->freepage_updated);
		}
	}

	xmit_unlock(&pqueue->lock, &irql);
	
	if (pxmitbuf) {
		if (!priv->pshare->freepage_updated) {
			// If free page is NOT enough, then update current FIFO status and check again
#ifdef CONFIG_SDIO_TX_IN_INTERRUPT
			sdio_query_txbuf_status_locksafe(priv);
#else
			sdio_query_txbuf_status(priv);
#endif
			if (rtw_sdio_check_tx_freepage(priv, pxmitbuf->tx_page_idx, pg_num) == TRUE) {
				if (test_and_clear_bit(SDIO_TX_INT_SETUP_TH, &pHalData->SdioTxIntStatus)) {
					// Invalidate TX Free Page Threshold
					RTL_W8(reg_freepage_thres[pHalData->SdioTxIntQIdx], 0xFF);
				}
				goto do_check;
			}
			
			if (test_and_set_bit(SDIO_TX_INT_SETUP_TH, &pHalData->SdioTxIntStatus))
				return NULL;
			pHalData->SdioTxIntQIdx = pxmitbuf->tx_page_idx;
			RTL_W8(reg_freepage_thres[pxmitbuf->tx_page_idx], pg_num+2);
			
#ifdef CONFIG_SDIO_TX_IN_INTERRUPT
			if ((SDIO_TX_THREAD == from) && (pHalData->SdioTxIntStatus & BIT(SDIO_TX_INT_WORKING)))
				return NULL;
			
			sdio_query_txbuf_status_locksafe(priv);
#else
			sdio_query_txbuf_status(priv);
#endif
			// check if free page is available to avoid race condition from SDIO ISR to cause NO interrupt issue
			if ((rtw_sdio_check_tx_freepage(priv, pxmitbuf->tx_page_idx, pg_num) == TRUE)
					|| (plist != get_next(phead))) {
				if (test_and_clear_bit(SDIO_TX_INT_SETUP_TH, &pHalData->SdioTxIntStatus)) {
					// Invalidate TX Free Page Threshold
					RTL_W8(reg_freepage_thres[pHalData->SdioTxIntQIdx], 0xFF);
					goto do_check;
				}
			}
#if 0
			printk("[%s %d] tx_page_idx=%d, pg_num=%d, TxIntStatus=%ld\n",
				__FUNCTION__, __LINE__, pxmitbuf->tx_page_idx, pg_num, pHalData->SdioTxIntStatus);
#endif
			
			pxmitbuf = NULL;
		}
	}
	
	return pxmitbuf;
}

s32 rtl8192es_dequeue_writeport(struct rtl8192cd_priv *priv, int from)
{
	struct priv_shared_info *pshare = priv->pshare;
	struct xmit_buf *pxmitbuf;
	u32 deviceId;
#ifdef TXDMA_ERROR_PAGE_DEBUG
	u32 reg204, reg214;
#endif

#ifdef SDIO_AP_OFFLOAD
	if (pshare->offload_function_ctrl)
		return FAIL;
#endif

	pxmitbuf = try_to_dequeue_pending_xmitbuf(priv, from);
	if (NULL == pxmitbuf)
		return FAIL;
	
#ifdef CONFIG_SDIO_TX_IN_INTERRUPT
	if (SDIO_TX_THREAD == from) {
		if (wait_for_txoqt(priv, pxmitbuf->q_num, pxmitbuf->agg_num) == FALSE)
			goto free_xmitbuf;
	} else {	// ISR
		if (try_to_wait_for_txoqt(priv, pxmitbuf->q_num, pxmitbuf->agg_num) == FALSE) {
			_irqL irql;
			_queue *pqueue = &pshare->pending_xmitbuf_queue;

			xmit_lock(&pqueue->lock, &irql);
			rtw_list_insert_head(&pxmitbuf->list, get_list_head(pqueue));
			++pqueue->qlen;
			if (2 == pxmitbuf->ext_tag) {
				// Update the pointer of the last urgent xmitbuf in pending_xmitbuf_queue
				if (NULL == pshare->last_urg_xmitbuf)
					pshare->last_urg_xmitbuf = pxmitbuf;
			}
			xmit_unlock(&pqueue->lock, &irql);
			
			clear_bit(from, &pshare->freepage_updated);
			sdio_query_txbuf_status_locksafe(priv);
			return FAIL;
		}
	}
#else
	if (wait_for_txoqt(priv, pxmitbuf->q_num, pxmitbuf->agg_num) == FALSE)
		goto free_xmitbuf;
#endif
	
	// statistics only for data frame
	if (MGNT_QUEUE != pxmitbuf->q_num) {
		pshare->xmitbuf_agg_num = pxmitbuf->agg_num;
	}

	// translate queue index to sdio fifo addr
	deviceId = ffaddr2deviceId(priv, pxmitbuf->q_num);
	
	if (TRUE == pshare->bSurpriseRemoved)
	{
		printk("%s: bSurpriseRemoved (write port)\n", __func__);
		goto free_xmitbuf;
	}

#ifdef TXDMA_ERROR_PAGE_DEBUG
	reg204 = RTL_R32(FIFOPAGE);
	reg214 = RTL_R32(RQPN_NPQ);
#endif

	sdio_write_port(priv, deviceId, pxmitbuf->len, (u8 *)pxmitbuf);
	
#ifdef TXDMA_ERROR_DEBUG
	check_txdma_error(priv, pxmitbuf
#ifdef TXDMA_ERROR_PAGE_DEBUG
		, reg204, reg214
#endif
		);
#endif

	clear_bit(from, &pshare->freepage_updated);

free_xmitbuf:

	sdio_recycle_xmitbuf(priv, pxmitbuf);
	if (pshare->need_sched_xmit)
		tasklet_hi_schedule(&pshare->xmit_tasklet);

	return SUCCESS;
}

s32 rtl8192es_xmit_buf_handler(struct rtl8192cd_priv *priv, int from)
{
	struct priv_shared_info *pshare = priv->pshare;
	u32 cnt = 0;
	
#ifdef CONFIG_SDIO_TX_IN_INTERRUPT
	pshare->xmit_thread_state |= XMIT_THREAD_STATE_RUNNING;
#endif
	
	while (rtl8192es_dequeue_writeport(priv, from) == SUCCESS) {
		if ((pshare->bSurpriseRemoved == TRUE) || (pshare->bDriverStopped == TRUE))
			break;
		++cnt;
	}
	
#ifdef CONFIG_SDIO_TX_IN_INTERRUPT
	pshare->xmit_thread_state &= ~XMIT_THREAD_STATE_RUNNING;
#endif
	pshare->nr_xmitbuf_handled_in_thread += cnt;

	return SUCCESS;
}

#else // !CONFIG_SDIO_TX_INTERRUPT
s32 rtl8192es_dequeue_writeport(struct rtl8192cd_priv *priv)
{
	HAL_INTF_DATA_TYPE *pHalData = GET_HAL_INTF_DATA(priv);
	u8 *freePage = pHalData->SdioTxFIFOFreePage;
	struct xmit_buf *pxmitbuf;
	u32 deviceId;
	u32 requiredPage;
	u8 PageIdx;
	u32 n = 0;
	
#ifdef SDIO_AP_OFFLOAD
	if (pshare->offload_function_ctrl)
		return FAIL;
#endif

	pxmitbuf = dequeue_pending_xmitbuf(priv);
	if (NULL == pxmitbuf)
		return FAIL;

	requiredPage = pxmitbuf->pg_num;

	// translate queue index to sdio fifo addr
	deviceId = ffaddr2deviceId(priv, pxmitbuf->q_num);

	// translate sdio fifo addr to tx fifo page index
	PageIdx = pxmitbuf->tx_page_idx;

	// check if hardware tx fifo page is enough
	do {
		if (requiredPage <= freePage[PageIdx]) {
			freePage[PageIdx] -= requiredPage;
			break;
		}
		// The number of page which public page included is available.
		if ((freePage[PageIdx] + freePage[PUBLIC_QUEUE_IDX]) > (requiredPage + 1))
		{
			u8 requiredPublicPage;

			requiredPublicPage = requiredPage - freePage[PageIdx];
			freePage[PageIdx] = 0;
			freePage[PUBLIC_QUEUE_IDX] -= requiredPublicPage;
			break;
		}

		if ((pshare->bSurpriseRemoved == TRUE) || (pshare->bDriverStopped == TRUE))
		{
			printk("%s: bSurpriseRemoved OR bDriverStopped (update TX FIFO page)\n", __func__);
			goto free_xmitbuf;
		}

		if ((++n % 60) == 0) {//or 80
			//printk("%s: FIFO starvation!(%d) len=%d agg=%d page=(R)%d(A)%d\n",
			//	__func__, n, pxmitbuf->len, pxmitbuf->agg_num, pxmitbuf->pg_num, freePage[PageIdx] + freePage[PUBLIC_QUEUE_IDX]);
			DEBUG_INFO("%s: FIFO starvation!\n", __func__);
			msleep(1);
			yield();
		}

		// Total number of page is NOT available, so update current FIFO status
		sdio_query_txbuf_status(priv);

	} while (1);

	if (pshare->bSurpriseRemoved == TRUE)
	{
		printk("%s: bSurpriseRemoved (write port)\n", __func__);
		goto free_xmitbuf;
	}


	if (wait_for_txoqt(priv, pxmitbuf->q_num, pxmitbuf->agg_num) == FALSE) {
		goto free_xmitbuf;
	}

	sdio_write_port(priv, deviceId, pxmitbuf->len, (u8 *)pxmitbuf);
	
#ifdef TXDMA_ERROR_DEBUG
	check_txdma_error(priv, pxmitbuf);
#endif

free_xmitbuf:

	sdio_recycle_xmitbuf(priv, pxmitbuf);
	if (pshare->need_sched_xmit)
		tasklet_hi_schedule(&pshare->xmit_tasklet);

	return SUCCESS;
}

s32 rtl8192es_xmit_buf_handler(struct rtl8192cd_priv *priv)
{
	while (rtl8192es_dequeue_writeport(priv) == SUCCESS) {
		if ((priv->pshare->bSurpriseRemoved == TRUE) || (priv->pshare->bDriverStopped == TRUE))
			break;
	}

	return SUCCESS;
}
#endif // CONFIG_SDIO_TX_INTERRUPT

void rtw_flush_xmit_pending_queue(struct rtl8192cd_priv *priv)
{
	struct xmit_buf *pxmitbuf = NULL;

	while (NULL != (pxmitbuf = dequeue_pending_xmitbuf(priv))) {
		sdio_recycle_xmitbuf(priv, pxmitbuf);
	}
}

int rtw_xmit_thread(void *context)
{
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv*) context;
	struct priv_shared_info *pshare = priv->pshare;
	
	while (1)
	{
		wait_event(pshare->xmit_waitqueue, test_and_clear_bit(WAKE_EVENT_XMIT, &pshare->xmit_wake));

		if ((pshare->bSurpriseRemoved == TRUE) || (pshare->bDriverStopped == TRUE)) {
			// avoid to continue calling wake_up_process() when xmit_thread is NULL
			set_bit(WAKE_EVENT_XMIT, &pshare->xmit_wake);
			
			printk("%s: bDriverStopped(%d) OR bSurpriseRemoved(%d)\n",
				__func__, pshare->bDriverStopped, pshare->bSurpriseRemoved);
			goto out;
		}
		
		pshare->nr_xmit_thread_run++;
		
#ifdef SDIO_AP_OFFLOAD
		if (pshare->offload_function_ctrl)
			continue;
#endif
		
#ifdef CONFIG_SDIO_TX_INTERRUPT
		if (GET_HAL_INTF_DATA(priv)->SdioTxIntStatus)
			continue;
		
		rtl8192es_xmit_buf_handler(priv, SDIO_TX_THREAD);
#else
		rtl8192es_xmit_buf_handler(priv);
#endif
	}
	
out:
	complete_and_exit(&pshare->xmit_thread_done, 0);
}

void rtl8192cd_usb_cal_txdesc_chksum(struct tx_desc *ptxdesc)
{
	u16 *usPtr = (u16*)ptxdesc;
	u32 count = 16;		// (32 bytes / 2 bytes per XOR) => 16 times
	u32 index;
	u16 checksum = 0;

	//Clear first
	ptxdesc->Dword7 &= cpu_to_le32(0xffff0000);
	
	for(index = 0 ; index < count ; index++){
		checksum = checksum ^ le16_to_cpu(*(usPtr + index));
	}
	
	ptxdesc->Dword7 |= cpu_to_le32(0x0000ffff&checksum);
}

#define MAX_UPDATE_BCN			40
#define UPDATE_BCN_TIMEOUT		20	// unit of ms

u32 sdio_submit_xmitbuf(struct rtl8192cd_priv *priv, struct xmit_buf *pxmitbuf)
{
	_queue *xmitbuf_queue;
	_irqL irqL;
	struct tx_desc *pdesc;
	int i;
	const int q_num = pxmitbuf->q_num;
	int err = 0;
	
	BUG_ON(pxmitbuf->pkt_tail > pxmitbuf->pkt_end);
	
	pdesc = (struct tx_desc*) pxmitbuf->pkt_data;
	pxmitbuf->len = (u32)(pxmitbuf->pkt_tail - pxmitbuf->pkt_data);
	
	pxmitbuf->pg_num = 0;
	for (i = 0; i < pxmitbuf->agg_num; ++i) {
		pxmitbuf->pg_num += (pxmitbuf->txdesc_info[i].buf_len + TX_PAGE_SIZE-1) / TX_PAGE_SIZE;
	}
	
	// translate sdio fifo addr to tx fifo page index
	pxmitbuf->tx_page_idx = rtw_sdio_get_tx_pageidx(ffaddr2deviceId(priv, q_num));

	if (pxmitbuf->pkt_offset) {
		pdesc->Dword1 |= set_desc(pxmitbuf->pkt_offset << TX_DW1_PKT_OFFSET_SH);
	}
	
	if (pxmitbuf->agg_num > 1) {
		// clear USB_TXAGG_NUM field to avoid erroneous settings from re-used pending xmitbuf
		pdesc->Dword7 &= ~ set_desc(TX_DW7_USB_TXAGG_NUM_MSK << TX_DW7_USB_TXAGG_NUM_SH);
		pdesc->Dword7 |= set_desc(pxmitbuf->agg_num << TX_DW7_USB_TXAGG_NUM_SH);
	}
	
	rtl8192cd_usb_cal_txdesc_chksum(pdesc);

	if (BEACON_QUEUE == q_num) {
#ifdef SDIO_AP_OFFLOAD
		if (priv->pshare->offload_function_ctrl
#ifdef MBSSID
			&& (0 == priv->vap_init_seq)
#endif
			)
		{
			unsigned long timeout = jiffies+msecs_to_jiffies(UPDATE_BCN_TIMEOUT);
			int cnt = 0;
			
			// when entering AP offload, make sure beacon download is successful
			// Note. [Beacon valid check] use 0x20a[0] for root & vap2, use 0x22a[0] for vap1 & vap3
			RTL_W8(0x20a, RTL_R8(0x20a));
			do {
				if ((TRUE == priv->pshare->bSurpriseRemoved) || (TRUE == priv->pshare->bDriverStopped))
					break;
				if ((cnt > MAX_UPDATE_BCN) || time_after(jiffies, timeout)) {
					priv->pshare->nr_update_bcn_fail++;
					err = -EBUSY;
					break;
				}
				sdio_write_port(priv, ffaddr2deviceId(priv, q_num), pxmitbuf->len, (u8 *)pxmitbuf);
				cnt++;
			} while (!(RTL_R8(0x20a) & BIT0));
		} else
#endif
		sdio_write_port(priv, ffaddr2deviceId(priv, q_num), pxmitbuf->len, (u8 *)pxmitbuf);

		pxmitbuf->use_hw_queue = 0;
		// Release the ownership of the HW TX queue
		clear_bit(q_num, &priv->pshare->use_hw_queue_bitmap);

		sdio_recycle_xmitbuf(priv, pxmitbuf);
	} else {
#ifdef CONFIG_SDIO_TX_AGGREGATION
		if (!(pxmitbuf->flags & XMIT_BUF_FLAG_REUSE))
#endif
		{
			xmitbuf_queue = &priv->pshare->tx_xmitbuf_waiting_queue[q_num];
			_enter_critical_bh(&xmitbuf_queue->lock, &irqL);

			rtw_list_insert_tail(&pxmitbuf->tx_xmitbuf_list, &xmitbuf_queue->queue);
			++xmitbuf_queue->qlen;

			_exit_critical_bh(&xmitbuf_queue->lock, &irqL);
		}

		pxmitbuf->use_hw_queue = 0;
		
		xmit_preempt_disable(irqL);
		
		// Release the ownership of the HW TX queue
		clear_bit(q_num, &priv->pshare->use_hw_queue_bitmap);
		/* Enqueue the pxmitbuf, and it will be dequeued by a xmit thread later */
		enqueue_pending_xmitbuf(priv, pxmitbuf);
		
		xmit_preempt_enable(irqL);
	}
	
	return err;
}

#ifdef CONFIG_SDIO_HCI
const int RATE_20M_2SS_LGI[] = {
	13, 26, 39, 52, 78, 104, 117, 130,	// 1SS
	26, 52, 78, 104, 156, 208, 234, 260	// 2SS
};
const int RATE_40M_2SS_LGI[] = {
	27, 54, 81, 108, 162, 216, 243, 270,	// 1SS
	54, 108, 162, 216, 324, 432, 486, 540	// 2SS
};

static inline void update_remaining_timeslot(struct rtl8192cd_priv *priv, struct tx_desc_info *pdescinfo, unsigned int q_num, unsigned char is_40m_bw)
{
	unsigned int txRate = 0;
	unsigned int ts_consumed = 0;
	struct tx_servq *ptxservq;
	struct stat_info *pstat = pdescinfo->pstat;

	if (pstat) {
		ptxservq = &pstat->tx_queue[q_num];
	} else if (MGNT_QUEUE == q_num) {
		ptxservq = &priv->tx_mgnt_queue;
	} else {
		return; // skip checking tx_mc_queue
	}

	if (rtw_is_list_empty(&ptxservq->tx_pending))
		return;

	if (is_MCS_rate(pdescinfo->rate)) {
		if (is_40m_bw)
			txRate = RATE_40M_2SS_LGI[pdescinfo->rate - HT_RATE_ID];
		else
			txRate = RATE_20M_2SS_LGI[pdescinfo->rate - HT_RATE_ID];
	} else {
		txRate = pdescinfo->rate;
	}

	ts_consumed = ((pdescinfo->buf_len)*16)/(txRate); // unit: microsecond (us)

	priv->pshare->ts_used[q_num] += ts_consumed;

	ptxservq->ts_used += ts_consumed;
}
#endif

#if (BEAMFORMING_SUPPORT == 1)
BOOLEAN IsMgntNDPA(	pu1Byte pdu);
#endif

void rtl8192cd_hal_fill_fwinfo(struct rtl8192cd_priv *priv, struct tx_insn* txcfg, struct tx_desc  *pdesc, unsigned int frag_idx)
{
	char n_txshort = 0, bg_txshort = 0;
	//int erp_protection = 0, n_protection = 0;
	//unsigned char rate;
	unsigned char txRate = 0;
#ifdef DRVMAC_LB
	static unsigned int rate_select = 0;
#endif
	BOOLEAN		bRtsEnable = FALSE;
	BOOLEAN		bErpProtect = FALSE;
	BOOLEAN		bNProtect = FALSE;
	BOOLEAN		bHwRts = FALSE;
	BOOLEAN		bCts2SelfEnable = FALSE;
	BOOLEAN		bRtsThreshold = FALSE;
	unsigned char RtsRate;
	unsigned int	value;
	unsigned int	reduction_level = 0;

#ifdef MP_TEST
	if (OPMODE & WIFI_MP_STATE) {
#ifdef RTK_AC_SUPPORT
		if (is_VHT_rate(txcfg->tx_rate)) {
			txRate = (txcfg->tx_rate - VHT_RATE_ID) + 44;
		} else
#endif
		if (is_MCS_rate(txcfg->tx_rate)) {	// HT rates
			txRate = (txcfg->tx_rate - HT_RATE_ID) + 12;
		}
		else{
			txRate = get_rate_index_from_ieee_value((UINT8)txcfg->tx_rate);
		}

		if (priv->pshare->CurrentChannelBW == CHANNEL_WIDTH_80) {
			pdesc->Dword5 |= set_desc((2 << TX_DW5_DATA_BW_SH)
				| (0 << TX_DW5_DATA_SC_SH) | (0 << TX_DW5_RTS_SC_SH));
			
			if (priv->pmib->dot11nConfigEntry.dot11nShortGIfor80M)
				n_txshort = 1;
		}
		else if (priv->pshare->CurrentChannelBW == CHANNEL_WIDTH_40) {
			pdesc->Dword5 |= set_desc((1 << TX_DW5_DATA_BW_SH)
				| (0 << TX_DW5_DATA_SC_SH) | (0 << TX_DW5_RTS_SC_SH));
			
			if (priv->pmib->dot11nConfigEntry.dot11nShortGIfor40M)
				n_txshort = 1;
		}
		else {
			if (priv->pmib->dot11nConfigEntry.dot11nShortGIfor20M)
				n_txshort = 1;
		}

		if (txcfg->retry)
			pdesc->Dword4 |= set_desc((1 << TX_DW4_RTY_LMT_EN_SH)
				| ((txcfg->retry & TX_DW4_DATA_RT_LMT_MSK) << TX_DW4_DATA_RT_LMT_SH));

		if (n_txshort == 1)
			pdesc->Dword5 |= set_desc(1 << TX_DW5_DATA_SHORT_SH);

		pdesc->Dword4 |= set_desc((txRate & TX_DW4_DATARATE_MSK) << TX_DW4_DATARATE_SH);
		
#ifdef RTK_5G_SUPPORT
		if (priv->pmib->dot11RFEntry.phyBandSelect == PHY_BAND_5G) {
			pdesc->Dword4 |= set_desc((4 & TX_DW4_RTSRATE_MSK) << TX_DW4_RTSRATE_SH);
		}
#endif

		return;
	}
#endif

	if (is_MCS_rate(txcfg->tx_rate))	// HT rates
	{
#ifdef RTK_AC_SUPPORT
		if (is_VHT_rate(txcfg->tx_rate))
			txRate = (txcfg->tx_rate - VHT_RATE_ID) + 44;
		else
#endif
			txRate = (txcfg->tx_rate - HT_RATE_ID) + 12;

#ifdef RTK_AC_SUPPORT
		if (priv->pshare->is_40m_bw==CHANNEL_WIDTH_80)
		{
			if(txcfg->pstat && (txcfg->pstat->tx_bw == CHANNEL_WIDTH_80
				&& (is_auto_rate(priv, txcfg->pstat) || is_fixedVHTTxRate(priv, txcfg->pstat))
				) )
			{
				pdesc->Dword5 |= set_desc((2 << TX_DW5_DATA_BW_SH)
					| (0 << TX_DW5_DATA_SC_SH) | (0 << TX_DW5_RTS_SC_SH));
				if (priv->pmib->dot11nConfigEntry.dot11nShortGIfor80M && //todo, add shortGI 80M option
						txcfg->pstat && (txcfg->pstat->vht_cap_buf.vht_cap_info & cpu_to_le32(BIT(5))))
					n_txshort = 1;
			} // TODO: Pedro, in 8812: is_MCS_rate(txcfg->tx_rate)
			else if(txcfg->pstat && (txcfg->pstat->tx_bw >= CHANNEL_WIDTH_40
				&& (is_auto_rate(priv, txcfg->pstat) || is_fixedMCSTxRate(priv, txcfg->pstat))        
				) )
			{
				pdesc->Dword5 |= set_desc((1 << TX_DW5_DATA_BW_SH)
					| ((priv->pshare->txsc_40 & TX_DW5_DATA_SC_MSK) << TX_DW5_DATA_SC_SH)
					| ((priv->pshare->txsc_40 & TX_DW5_RTS_SC_MSK) << TX_DW5_RTS_SC_SH));
				if (priv->pmib->dot11nConfigEntry.dot11nShortGIfor40M &&
						txcfg->pstat && (txcfg->pstat->ht_cap_buf.ht_cap_info & cpu_to_le16(_HTCAP_SHORTGI_40M_)))
					n_txshort = 1;
			}
			else
			{
				pdesc->Dword5 |= set_desc((0 << TX_DW5_DATA_BW_SH)
					| ((priv->pshare->txsc_20 & TX_DW5_DATA_SC_MSK) << TX_DW5_DATA_SC_SH)
					| ((priv->pshare->txsc_20 & TX_DW5_RTS_SC_MSK) << TX_DW5_RTS_SC_SH));
				if (priv->pmib->dot11nConfigEntry.dot11nShortGIfor20M &&
						txcfg->pstat && (txcfg->pstat->ht_cap_buf.ht_cap_info & cpu_to_le16(_HTCAP_SHORTGI_20M_)))
					n_txshort = 1;
			}
		}
		else
#endif
		if (priv->pshare->is_40m_bw) {
			if (txcfg->pstat && (txcfg->pstat->tx_bw == CHANNEL_WIDTH_40)
#ifdef WIFI_11N_2040_COEXIST
				&& !(priv->pmib->dot11nConfigEntry.dot11nCoexist && (((OPMODE & WIFI_AP_STATE) && 
				(priv->bg_ap_timeout ||orForce20_Switch20Map(priv)
				))
#ifdef CLIENT_MODE
				|| ((OPMODE & WIFI_STATION_STATE) && priv->coexist_connection && 
				(txcfg->pstat->ht_ie_len) && !(txcfg->pstat->ht_ie_buf.info0 & _HTIE_STA_CH_WDTH_))
#endif
				))
#endif

				) {
				pdesc->Dword5 |= set_desc((1 << TX_DW5_DATA_BW_SH) | (3 << TX_DW5_DATA_SC_SH));

				if (priv->pmib->dot11nConfigEntry.dot11nShortGIfor40M &&
						txcfg->pstat && (txcfg->pstat->ht_cap_buf.ht_cap_info & cpu_to_le16(_HTCAP_SHORTGI_40M_)))
					n_txshort = 1;
			}
			else {
				if (priv->pshare->offset_2nd_chan == HT_2NDCH_OFFSET_BELOW)
					pdesc->Dword5 |= set_desc((2 << TX_DW5_DATA_SC_SH) | (2 << TX_DW5_RTS_SC_SH));
				else
					pdesc->Dword5 |= set_desc((1 << TX_DW5_DATA_SC_SH) | (1 << TX_DW5_RTS_SC_SH));

				if (priv->pmib->dot11nConfigEntry.dot11nShortGIfor20M &&
					txcfg->pstat && (txcfg->pstat->ht_cap_buf.ht_cap_info & cpu_to_le16(_HTCAP_SHORTGI_20M_)))
					n_txshort = 1;
			}
		} else {
			if (priv->pmib->dot11nConfigEntry.dot11nShortGIfor20M &&
				txcfg->pstat && (txcfg->pstat->ht_cap_buf.ht_cap_info & cpu_to_le16(_HTCAP_SHORTGI_20M_)))
				n_txshort = 1;
		}

		if ((AMSDU_ENABLE && AMPDU_ENABLE && txcfg->aggre_en)
				|| ((txcfg->aggre_en >= FG_AGGRE_MPDU) && (txcfg->aggre_en <= FG_AGGRE_MPDU_BUFFER_LAST))) {
			int TID = ((struct sk_buff *)txcfg->pframe)->cb[1];
			if (txcfg->pstat->ADDBA_ready[TID] && !txcfg->pstat->low_tp_disable_ampdu) {
				pdesc->Dword2 |= set_desc(1 << TX_DW2_AGG_EN_SH);
				
				// assign aggr density
				if (txcfg->privacy) {
					pdesc->Dword2 |= set_desc(7 << TX_DW2_AMPDU_DENSITY_SH); 
				}
				else {
					value = (txcfg->pstat->ht_cap_buf.ampdu_para & _HTCAP_AMPDU_SPC_MASK_) >> _HTCAP_AMPDU_SPC_SHIFT_;
					pdesc->Dword2 |= set_desc((value & TX_DW2_AMPDU_DENSITY_MSK) << TX_DW2_AMPDU_DENSITY_SH);
				}
				value = ((1<<(txcfg->pstat->ht_cap_buf.ampdu_para & 0x03))*5) >>1;
				pdesc->Dword3 |= set_desc((value & TX_DW3_MAX_AGG_NUM_MSK) << TX_DW3_MAX_AGG_NUM_SH);
			}
		}

		// for STBC
		if (txcfg->pstat)
		{
			if ((txcfg->pstat->cmn_info.stbc_en & HT_STBC_EN)
#ifdef RTK_AC_SUPPORT
				|| (txcfg->pstat->cmn_info.stbc_en & VHT_STBC_EN)
#endif
			) {
#if (BEAMFORMING_SUPPORT == 1)
				u1Byte					Idx = 0;
				PRT_BEAMFORMING_ENTRY	pEntry;
				pEntry = Beamforming_GetEntryByMacId(priv, txcfg->pstat->cmn_info.aid, &Idx);
				if (pEntry == NULL || (!pEntry->Sounding_En))
#endif
				if ((get_rf_mimo_mode(priv) == RF_2T2R) || (get_rf_mimo_mode(priv) == RF_3T3R))
           			pdesc->Dword5 |= set_desc(1 << TX_DW5_DATA_STBC_SH);
	        }
		}
		// LDPC
#if (BEAMFORMING_SUPPORT == 1)
		if (!txcfg->ndpa) 
#endif
		if ((txcfg->pstat) &&
			((txcfg->pstat->cmn_info.ldpc_en & HT_LDPC_EN)
#ifdef RTK_AC_SUPPORT
			|| (txcfg->pstat->cmn_info.ldpc_en & VHT_LDPC_EN)
#endif
		)) {
			pdesc->Dword5 |= set_desc(1 << TX_DW5_DATA_LDPC_SH);
		}
	}
	else	// legacy rate
	{
		txRate = get_rate_index_from_ieee_value((UINT8)txcfg->tx_rate);
		if (is_CCK_rate(txcfg->tx_rate) && (txcfg->tx_rate != 2)) {
			if ((priv->pmib->dot11BssType.net_work_type & WIRELESS_11G) &&
					(priv->pmib->dot11ErpInfo.longPreambleStaNum > 0))
				; // txfw->txshort = 0
			else {
				if (txcfg->pstat)
					bg_txshort = (priv->pmib->dot11RFEntry.shortpreamble) &&
									(txcfg->pstat->useShortPreamble);
				else
					bg_txshort = priv->pmib->dot11RFEntry.shortpreamble;
			}
		}

#ifdef RTK_AC_SUPPORT
		if (priv->pshare->is_40m_bw==2) {
			pdesc->Dword5 |= set_desc(((priv->pshare->txsc_20 & TX_DW5_DATA_SC_MSK) << TX_DW5_DATA_SC_SH)
				| ((priv->pshare->txsc_20 & TX_DW5_RTS_SC_MSK) << TX_DW5_RTS_SC_SH));
		}
		else
#endif
		if (priv->pshare->is_40m_bw) {
			if (priv->pshare->offset_2nd_chan == HT_2NDCH_OFFSET_BELOW) {
				pdesc->Dword5 |= set_desc((2 << TX_DW5_DATA_SC_SH) | (2 << TX_DW5_RTS_SC_SH));
			} else {
				pdesc->Dword5 |= set_desc((1 << TX_DW5_DATA_SC_SH) | (1 << TX_DW5_RTS_SC_SH));
			}
		}

		if (bg_txshort)
			pdesc->Dword5 |= set_desc(1 << TX_DW5_DATA_SHORT_SH);
	}

	if (txcfg->need_ack) { // unicast
		if (frag_idx == 0) 
			RtsCheck(priv, txcfg, txcfg->fr_len, &bRtsEnable, &bCts2SelfEnable, &bHwRts, &bErpProtect, &bNProtect, &bRtsThreshold);
	}

	RtsRate = find_rts_rate(priv, txcfg->tx_rate, bErpProtect);
    // Use Cts2Self instead when RtsRate < 11M && MPDU <= rts_thrshld
	if (bRtsEnable && CheckCts2SelfEnable(RtsRate) && !bRtsThreshold)
	{
		bRtsEnable = FALSE;
		bCts2SelfEnable = TRUE;
	}

//	if(bErpProtect)
//		priv->pshare->phw->bErpProtection = TRUE;

	if (bRtsEnable)
		pdesc->Dword3 |= set_desc(1 << TX_DW3_RTSEN_SH);
	if (bCts2SelfEnable)
		pdesc->Dword3 |= set_desc(1 << TX_DW3_CTS2SELF_SH);
	if (bHwRts)
		pdesc->Dword3 |=set_desc(1 << TX_DW3_HW_RTS_EN_SH);

	if (bRtsEnable || bCts2SelfEnable) {
		unsigned int rtsTxRateIdx  = get_rate_index_from_ieee_value(RtsRate);
		if (bErpProtect) {
			unsigned char  rtsShort = 0;
			if (is_CCK_rate(RtsRate) && (RtsRate != 2)) {
				if ((priv->pmib->dot11BssType.net_work_type & WIRELESS_11G) &&
						(priv->pmib->dot11ErpInfo.longPreambleStaNum > 0))
					rtsShort = 0; // do nothing
				else {
					if (txcfg->pstat)
						rtsShort = (priv->pmib->dot11RFEntry.shortpreamble) &&
										(txcfg->pstat->useShortPreamble);
					else
						rtsShort = priv->pmib->dot11RFEntry.shortpreamble;
				}
			}
			pdesc->Dword5 |= (rtsShort == 1)? set_desc(1 << TX_DW5_RTS_SHORT_SH): 0;
		} 
		
		pdesc->Dword4 |= set_desc((rtsTxRateIdx & TX_DW4_RTSRATE_MSK) << TX_DW4_RTSRATE_SH);
		pdesc->Dword4 |= set_desc((0xf & TX_DW4_RTS_RATEFB_LMT_MSK) << TX_DW4_RTS_RATEFB_LMT_SH);
	}

	if (priv->pshare->rf_ft_var.txforce != 0xFF) {
		if(priv->pshare->rf_ft_var.sgiforce == 1)
			n_txshort = 1;
		else if(priv->pshare->rf_ft_var.sgiforce == 2)
			n_txshort = 0;
	}

	if (n_txshort == 1 && txcfg->pstat && (!txcfg->pstat->cmn_info.ra_info.disable_ra))
		pdesc->Dword5 |= set_desc(1 << TX_DW5_DATA_SHORT_SH);

#ifdef DRVMAC_LB
	if (priv->pmib->miscEntry.drvmac_lb && (priv->pmib->miscEntry.lb_mlmp == 4)) {
		txRate = rate_select;
		if (rate_select++ > 0x1b)
			rate_select = 0;

		pdesc->Dword3 |= set_desc(1 << TX_DW3_USERATE_SH);
		pdesc->Dword3 |= set_desc(1 << TX_DW3_DISDATAFB_SH);
		pdesc->Dword3 |= set_desc(1 << TX_DW3_DISRTSFB_SH);// disable RTS fall back
	}
#endif

	if ((priv->pshare->rf_ft_var.txforce != 0xff)
#if (BEAMFORMING_SUPPORT == 1)
			&& (!txcfg->ndpa) 
#endif
			) {
		pdesc->Dword3 |= set_desc(1 << TX_DW3_USERATE_SH);
		pdesc->Dword4 |= set_desc((priv->pshare->rf_ft_var.txforce & TX_DW4_DATARATE_MSK) << TX_DW4_DATARATE_SH);
	} else {
		pdesc->Dword4 |= set_desc((txRate & TX_DW4_DATARATE_MSK) << TX_DW4_DATARATE_SH);
	}
	
	if (priv->pshare->rf_ft_var.rts_init_rate) {
		pdesc->Dword4 |= set_desc((priv->pshare->rf_ft_var.rts_init_rate & TX_DW4_RTSRATE_MSK) << TX_DW4_RTSRATE_SH);
	}
	if ((priv->pmib->dot11RFEntry.phyBandSelect & PHY_BAND_5G) && 
			((get_desc(pdesc->Dword4) >> TX_DW4_RTSRATE_SH) & TX_DW4_RTSRATE_MSK)<4) {
		pdesc->Dword4 &= ~ set_desc(TX_DW4_RTSRATE_MSK << TX_DW4_RTSRATE_SH);
		pdesc->Dword4 |= set_desc(4 << TX_DW4_RTSRATE_SH);
	}

	if (txcfg->need_ack) {
		// give retry limit to management frame
		if (txcfg->q_num == MANAGE_QUE_NUM) {
			pdesc->Dword4 |= set_desc(1 << TX_DW4_RTY_LMT_EN_SH);
			if (GetFrameSubType(txcfg->phdr) == WIFI_PROBERSP) {
				;	// 0 no need to set
			}
#ifdef WDS
			else if ((GetFrameSubType(txcfg->phdr) == WIFI_PROBEREQ) && (txcfg->pstat->state & WIFI_WDS)) {
				pdesc->Dword4 |= set_desc(2 << TX_DW4_DATA_RT_LMT_SH);
			}
#endif
			else {
				pdesc->Dword4 |= set_desc(6 << TX_DW4_DATA_RT_LMT_SH);
			}
		}
#ifdef WDS
		else if (txcfg->wdsIdx >= 0) {
			if (txcfg->pstat->rx_avarage == 0) {
				pdesc->Dword4 |= set_desc(1 << TX_DW4_RTY_LMT_EN_SH);
				pdesc->Dword4 |= set_desc(3 << TX_DW4_DATA_RT_LMT_SH);
			}
		}
#endif
		else if (txcfg->pstat && !txcfg->fixed_rate) {
			if (priv->pshare->rf_ft_var.low_retry_rssi_thd && txcfg->pstat->rssi
					&& (txcfg->pstat->rssi < priv->pshare->rf_ft_var.low_retry_rssi_thd)) {
				if ((txcfg->tx_rate <= _9M_RATE_) ||
					((_MCS0_RATE_ == txcfg->tx_rate) || (_MCS1_RATE_ == txcfg->tx_rate))) {
					pdesc->Dword4 |= set_desc(1 << TX_DW4_RTY_LMT_EN_SH);
					pdesc->Dword4 |= set_desc((0x04 & TX_DW4_DATA_RT_LMT_MSK) << TX_DW4_DATA_RT_LMT_SH);
				} else {
					pdesc->Dword4 |= set_desc(1 << TX_DW4_RTY_LMT_EN_SH);
					pdesc->Dword4 |= set_desc((0x0c & TX_DW4_DATA_RT_LMT_MSK) << TX_DW4_DATA_RT_LMT_SH);
				}
			} else if (priv->pshare->rf_ft_var.low_rate_low_retry
					&& ((txcfg->tx_rate <= _9M_RATE_)
					|| (_MCS0_RATE_ == txcfg->tx_rate) || (_MCS1_RATE_ == txcfg->tx_rate))) {
				pdesc->Dword4 |= set_desc(1 << TX_DW4_RTY_LMT_EN_SH);
				pdesc->Dword4 |= set_desc((0x08 & TX_DW4_DATA_RT_LMT_MSK) << TX_DW4_DATA_RT_LMT_SH);
			} else
			if (is_MCS_rate(txcfg->tx_rate) && (txcfg->pstat->IOTPeer==HT_IOT_PEER_INTEL) && (txcfg->pstat->retry_inc)
					&& !(txcfg->pstat->leave) && priv->pshare->intel_rty_lmt) {
				pdesc->Dword4 |= set_desc(1 << TX_DW4_RTY_LMT_EN_SH);
				pdesc->Dword4 |= set_desc((priv->pshare->intel_rty_lmt & TX_DW4_DATA_RT_LMT_MSK) << TX_DW4_DATA_RT_LMT_SH);
			}
			else if ((txcfg->pstat->IOTPeer==HT_IOT_PEER_BROADCOM) && (txcfg->pstat->retry_inc) && !(txcfg->pstat->leave)) {
				pdesc->Dword4 |= set_desc(1 << TX_DW4_RTY_LMT_EN_SH);
				pdesc->Dword4 |= set_desc(0x20 << TX_DW4_DATA_RT_LMT_SH);
			}
		}

		// High power mechanism
		if (priv->pshare->rf_ft_var.tx_pwr_ctrl && txcfg->pstat && (txcfg->fr_type == _SKB_FRAME_TYPE_)) {
			if (txcfg->pstat->hp_level == 1)
				reduction_level = priv->pshare->phw->TXPowerOffset;
		}
		
#if (BEAMFORMING_SUPPORT == 1)
		if (txcfg->ndpa) {
			unsigned char *pwlhdr = (unsigned char*)txcfg->phdr;
			if (IsCtrlNDPA(pwlhdr) || IsMgntNDPA(pwlhdr)) {
				pdesc->Dword4 |= set_desc(5 << TX_DW4_DATA_RT_LMT_SH);
				pdesc->Dword4 |= set_desc(1 << TX_DW4_RTY_LMT_EN_SH);
				if(IsMgntNDPA(pwlhdr)) {		//0xe0
					pdesc->Dword3 |= set_desc(1 << TX_DW3_NDPA_SH);
				} else {		// 0x54
					if(!IS_TEST_CHIP(priv)) {
						if ((txcfg->pstat->WirelessMode & WIRELESS_MODE_AC_5G) && (txcfg->pstat->IOTPeer!=HT_IOT_PEER_BROADCOM))
							pdesc->Dword3 |= set_desc(2 << TX_DW3_NDPA_SH);
						else
							pdesc->Dword3 |= set_desc(1 << TX_DW3_NDPA_SH);
					} else {
						pdesc->Dword3 |= set_desc(1 << TX_DW3_NDPA_SH);
					}
				}
			}
		}
#endif
	}

	if (priv->pmib->dot11RFEntry.txpwr_reduction) {
		if (priv->pmib->dot11RFEntry.txpwr_reduction <= 3) {
			if (reduction_level < priv->pmib->dot11RFEntry.txpwr_reduction) {
				reduction_level = priv->pmib->dot11RFEntry.txpwr_reduction;
			}
		}
	}
	if (reduction_level)
		pdesc->Dword5 |= set_desc(reduction_level << TX_DW5_TXPWR_OFSET_SH);
}

// Now we didn't consider of FG_AGGRE_MSDU_FIRST case.
// If you want to support AMSDU method, you must modify this function.
int rtl8192cd_signin_txdesc(struct rtl8192cd_priv *priv, struct tx_insn* txcfg, struct wlan_ethhdr_t *pethhdr)
{
	struct tx_desc		*pdesc = NULL, desc_backup;
	struct tx_desc_info	*pdescinfo = NULL;
	unsigned int 		fr_len, tx_len, i, keyid;
	int				q_num;
	int				sw_encrypt;
	unsigned char		*da, *pbuf, *pwlhdr, *pmic, *picv;
	unsigned char		 q_select;
#ifdef TX_SHORTCUT
#ifdef CONFIG_RTL_WAPI_SUPPORT
	struct wlan_ethhdr_t ethhdr_data;
#endif
	int				idx=0;
	struct tx_sc_entry *ptxsc_entry;
	unsigned char		pktpri;
#endif
#ifdef CONFIG_IEEE80211W
	unsigned int	isBIP = 0;
#endif
#ifdef WMM_APSD
	unsigned char eosp = 0;
#endif
	
	struct wlan_hdr wlanhdr;
	u32 icv_data[2], mic_data[2];
	
	struct xmit_buf *pxmitbuf;
	u8 *mem_start, *pkt_start, *write_ptr;
	u32 pkt_len, hdr_len;

	keyid = 0;
	q_select = 0;
#ifdef CONFIG_IEEE80211W
	sw_encrypt = UseSwCrypto(priv, txcfg->pstat, (txcfg->pstat ? FALSE : TRUE), txcfg->isPMF);
#else
	sw_encrypt = UseSwCrypto(priv, txcfg->pstat, (txcfg->pstat ? FALSE : TRUE));
#endif
	
	pmic = (unsigned char *) mic_data;
	picv = (unsigned char *) icv_data;

	if (txcfg->tx_rate == 0) {
		DEBUG_ERR("tx_rate=0!\n");
		txcfg->tx_rate = find_rate(priv, NULL, 0, 1);
	}

	q_num = txcfg->q_num;
	tx_len = txcfg->fr_len;

	if (txcfg->fr_type == _SKB_FRAME_TYPE_) {
		pbuf = ((struct sk_buff *)txcfg->pframe)->data;
#ifdef TX_SHORTCUT
		if ((NULL == pethhdr) && (txcfg->aggre_en < FG_AGGRE_MSDU_FIRST)) {
			pethhdr = (struct wlan_ethhdr_t *)(pbuf - sizeof(struct wlan_ethhdr_t));
#ifdef CONFIG_RTL_WAPI_SUPPORT
			if ((_WAPI_SMS4_ == txcfg->privacy) && sw_encrypt) {
				// backup ethhdr because SecSWSMS4Encryption() will overwrite it via LLC header for SW WAPI
				memcpy(&ethhdr_data, pethhdr, sizeof(struct wlan_ethhdr_t));
				pethhdr = &ethhdr_data;
			}
#endif
		}
#endif
	} else {
		pbuf = (unsigned char*)txcfg->pframe;
	}
	
	da = get_da((unsigned char *)txcfg->phdr);

#ifdef CONFIG_IEEE80211W
	if(txcfg->isPMF && IS_MCAST(da)) 
	{
		isBIP = 1;
		txcfg->iv = 0;
		txcfg->fr_len += 10; // 10: MMIE length
	}
#endif

	// in case of default key, then find the key id
	if (GetPrivacy((txcfg->phdr)))
	{
#ifdef WDS
		if (txcfg->wdsIdx >= 0) {
			if (txcfg->pstat)
				keyid = txcfg->pstat->keyid;
			else
				keyid = 0;
		}
		else
#endif

#ifdef __DRAYTEK_OS__
		if (!IEEE8021X_FUN)
			keyid = priv->pmib->dot1180211AuthEntry.dot11PrivacyKeyIndex;
		else {
			if (IS_MCAST(GetAddr1Ptr ((unsigned char *)txcfg->phdr)) || !txcfg->pstat)
				keyid = priv->pmib->dot11GroupKeysTable.keyid;
			else
				keyid = txcfg->pstat->keyid;
		}
#else

		if (priv->pmib->dot1180211AuthEntry.dot11PrivacyAlgrthm==_WEP_40_PRIVACY_ ||
			priv->pmib->dot1180211AuthEntry.dot11PrivacyAlgrthm==_WEP_104_PRIVACY_) {
			if(IEEE8021X_FUN && txcfg->pstat) {
#ifdef A4_STA
				if (IS_MCAST(da) && !(txcfg->pstat->state & WIFI_A4_STA))
#else
				if(IS_MCAST(da))
#endif					
					keyid = 0;
				else
					keyid = txcfg->pstat->keyid;
			}
			else
				keyid = priv->pmib->dot1180211AuthEntry.dot11PrivacyKeyIndex;
		}
#endif
	}
	
	pxmitbuf = txcfg->pxmitbuf;
	
	mem_start = pxmitbuf->pkt_tail;
	
	for (i=0; i < txcfg->frg_num; i++)
	{
		mem_start = PTR_ALIGN(mem_start, TXAGG_DESC_ALIGN_SZ);
		pdesc = (struct tx_desc*) mem_start;
		pdescinfo = &pxmitbuf->txdesc_info[pxmitbuf->agg_num];
		
		pkt_start = mem_start + TXDESC_SIZE;
		if (0 == pxmitbuf->agg_num)
		{
			pkt_start += (pxmitbuf->pkt_offset * PACKET_OFFSET_SZ);
		}
		
		write_ptr = pkt_start;
		
		/*------------------------------------------------------------*/
		/*           fill descriptor of header + iv + llc             */
		/*------------------------------------------------------------*/

		if (i != 0)
		{
			// we have to allocate wlan_hdr
			pwlhdr = (UINT8 *)&wlanhdr;
			
			// other MPDU will share the same seq with the first MPDU
			memcpy((void *)pwlhdr, (void *)(txcfg->phdr), txcfg->hdr_len); // data pkt has 24 bytes wlan_hdr
//			pdesc->Dword3 |= set_desc((GetSequence(txcfg->phdr) & TX_SeqMask)  << TX_SeqSHIFT);
			memcpy(pdesc, &desc_backup, sizeof(*pdesc));
			goto init_desc;
		}
		else
		{
			//clear all bits
			memset(pdesc, 0, TXDESC_SIZE);
			
#ifdef WIFI_WMM
			if (txcfg->pstat /*&& (is_qos_data(txcfg->phdr))*/) {
				if ((GetFrameSubType(txcfg->phdr) & (WIFI_DATA_TYPE | BIT(6) | BIT(7))) == (WIFI_DATA_TYPE | BIT(7))) {
					unsigned char tempQosControl[2];
					memset(tempQosControl, 0, 2);
					tempQosControl[0] = ((struct sk_buff *)txcfg->pframe)->cb[1];
#ifdef WMM_APSD
					if (
#ifdef CLIENT_MODE
						(OPMODE & WIFI_AP_STATE) &&
#endif
						(APSD_ENABLE) && (txcfg->pstat->state & WIFI_SLEEP_STATE) &&
						(!GetMData(txcfg->phdr)) &&
						((((tempQosControl[0] == 7) || (tempQosControl[0] == 6)) && (txcfg->pstat->apsd_bitmap & 0x01)) ||
						 (((tempQosControl[0] == 5) || (tempQosControl[0] == 4)) && (txcfg->pstat->apsd_bitmap & 0x02)) ||
						 (((tempQosControl[0] == 3) || (tempQosControl[0] == 0)) && (txcfg->pstat->apsd_bitmap & 0x08)) ||
						 (((tempQosControl[0] == 2) || (tempQosControl[0] == 1)) && (txcfg->pstat->apsd_bitmap & 0x04))))
					{
						tempQosControl[0] |= BIT(4);
						eosp = 1;
					}
#endif
					if (txcfg->aggre_en == FG_AGGRE_MSDU_FIRST)
						tempQosControl[0] |= BIT(7);

					if (priv->pmib->dot11nConfigEntry.dot11nTxNoAck)
						tempQosControl[0] |= BIT(5);

					memcpy((void *)GetQosControl((txcfg->phdr)), tempQosControl, 2);
				}
			}
#endif

#if (BEAMFORMING_SUPPORT == 1)
			if(!txcfg->ndpa)
#endif	
			assign_wlanseq(GET_HW(priv), txcfg->phdr, txcfg->pstat, GET_MIB(priv)
#ifdef CONFIG_RTK_MESH	// For broadcast data frame via mesh (ex:ARP requst)
				, txcfg->is_11s
#endif
				);
			pdesc->Dword9 |= set_desc((GetSequence(txcfg->phdr) & TX_DW9_SEQ_MSK)  << TX_DW9_SEQ_SH);
			pwlhdr = txcfg->phdr;
		}
		
#if (BEAMFORMING_SUPPORT == 1)
		if(!txcfg->ndpa)
#endif	
		SetDuration(pwlhdr, 0);

		rtl8192cd_hal_fill_fwinfo(priv, txcfg, pdesc, i);
		
#ifdef CLIENT_MODE
		if (OPMODE & WIFI_STATION_STATE) {
			if (GetFrameSubType(txcfg->phdr) == WIFI_PSPOLL)
				pdesc->Dword3 |= set_desc(1 << TX_DW3_NAVUSEHDR_SH);

			if (priv->ps_state)
				SetPwrMgt(pwlhdr);
			else
				ClearPwrMgt(pwlhdr);
		}
#endif
#if (BEAMFORMING_SUPPORT == 1)
		if (txcfg->ndpa)
			pdesc->Dword3 |= set_desc(1 << TX_DW3_NAVUSEHDR_SH);
#endif

//		pdesc->Dword0 |= set_desc(TX_OWN | TX_FirstSeg | TX_LastSeg);
		pdesc->Dword0 |= set_desc(TXDESC_SIZE << TX_DW0_OFFSET_SH); // tx_desc size

		if (IS_MCAST(GetAddr1Ptr((unsigned char *)txcfg->phdr)))
			pdesc->Dword0 |= set_desc(1 << TX_DW0_BMC_SH);
		
		switch (q_num) {
		case HIGH_QUEUE:
#ifdef MBSSID
			if (IS_VAP_INTERFACE(priv)) {
				// set MBSSID index
				pdesc->Dword1 |= set_desc((priv->vap_init_seq & TX_DW1_MACID_MSK) << TX_DW1_MACID_SH);
				pdesc->Dword6 |= set_desc((priv->vap_init_seq & TX_DW6_MBSSID_MSK) << TX_DW6_MBSSID_SH);
			}
#endif
			pdesc->Dword1 |= set_desc(1 << TX_DW1_MOREDATA_SH);
			q_select = TXDESC_QSEL_HIGH;
			break;
		case MGNT_QUEUE:
			q_select = TXDESC_QSEL_MGT;
			break;
#if defined(DRVMAC_LB) && defined(WIFI_WMM)
		case BE_QUEUE:
			q_select = TXDESC_QSEL_TID0;
			break;
#endif
		default:
			// data packet
#ifdef RTL_MANUAL_EDCA
			if (priv->pmib->dot11QosEntry.ManualEDCA) {
				switch (q_num) {
				case VO_QUEUE:
					q_select = TXDESC_QSEL_TID6;
					break;
				case VI_QUEUE:
					q_select = TXDESC_QSEL_TID4;
					break;
				case BE_QUEUE:
					q_select = TXDESC_QSEL_TID0;
					break;
				default:
					q_select = TXDESC_QSEL_TID1;
					break;
				}
			}
			else
#endif
			q_select = ((struct sk_buff *)txcfg->pframe)->cb[1];
			break;
		}
		pdesc->Dword1 |= set_desc((q_select & TX_DW1_QSEL_MSK)<< TX_DW1_QSEL_SH);

		// Set RateID
		if (txcfg->pstat) {
			if (txcfg->pstat->cmn_info.aid != MANAGEMENT_AID)	{
				pdesc->Dword1 |= set_desc((txcfg->pstat->cmn_info.ra_info.rate_id & TX_DW1_RATE_ID_MSK) << TX_DW1_RATE_ID_SH);			
				// Set MacID
				if (q_select != TXDESC_QSEL_HIGH)
					pdesc->Dword1 |= set_desc(REMAP_AID(txcfg->pstat) << TX_DW1_MACID_SH);
				
#if (BEAMFORMING_SUPPORT == 1)
				if((priv->pmib->dot11RFEntry.txbf == 1)
						&& ((txcfg->pstat->ht_cap_len && (txcfg->pstat->ht_cap_buf.txbf_cap)) 
#ifdef RTK_AC_SUPPORT
						||(txcfg->pstat->vht_cap_len && (cpu_to_le32(txcfg->pstat->vht_cap_buf.vht_cap_info) & BIT(SU_BFEE_S)))
#endif
						)) {
					pdesc->Dword2 |= set_desc((txcfg->pstat->cmn_info.bf_info.p_aid & TX_DW2_P_AID_MSK)<<TX_DW2_P_AID_SH);
					pdesc->Dword2 |= set_desc((txcfg->pstat->cmn_info.bf_info.g_id & TX_DW2_G_ID_MSK)<<TX_DW2_G_ID_SH);
				}
#endif
			}
		} else {
 			pdesc->Dword1 |= set_desc(ARFR_BMC << TX_DW1_RATE_ID_SH);
#if (BEAMFORMING_SUPPORT == 1)
			if (priv->pmib->dot11RFEntry.txbf == 1)
				pdesc->Dword2 |= set_desc(1 << TX_DW2_G_ID_SH);
#endif
		}

		pdesc->Dword4 |= set_desc((0x1f & TX_DW4_DATA_RATEFB_LMT_MSK) << TX_DW4_DATA_RATEFB_LMT_SH);
		if (txcfg->fixed_rate)
			pdesc->Dword3 |= set_desc((1 << TX_DW3_DISDATAFB_SH) | (1 << TX_DW3_DISRTSFB_SH)
					| (1 << TX_DW3_USERATE_SH));

		if (txcfg->pstat && txcfg->pstat->cmn_info.ra_info.disable_ra)
			pdesc->Dword3 |= set_desc(1 << TX_DW3_USERATE_SH);

init_desc:

		if (i != (txcfg->frg_num - 1))
		{
			if (i == 0) {
				memcpy(&desc_backup, pdesc, sizeof(*pdesc));
				fr_len = (txcfg->frag_thrshld - txcfg->llc);
			} else {
				fr_len = txcfg->frag_thrshld;
			}
			tx_len -= fr_len;
			
			SetMFrag(pwlhdr);
			pdesc->Dword2 |= set_desc(1 << TX_DW2_MOREFRAG_SH);
		}
		else	// last seg, or the only seg (frg_num == 1)
		{
			fr_len = tx_len;
			ClearMFrag(pwlhdr);
		}
		SetFragNum((pwlhdr), i);
		
		// consider the diff between the first frag and the other frag in rtl8192cd_fill_fwinfo()
		if (((txcfg->need_ack) && (i != 0))
			|| priv->pshare->rf_ft_var.no_rtscts) {
			pdesc->Dword3 &= ~ set_desc((1 << TX_DW3_HW_RTS_EN_SH) | (1 << TX_DW3_RTSEN_SH) | (1 << TX_DW3_CTS2SELF_SH));
		}
		
		hdr_len = txcfg->hdr_len + txcfg->iv;
		if ((i == 0) && (txcfg->fr_type == _SKB_FRAME_TYPE_))
			hdr_len += txcfg->llc;
		
		pkt_len = hdr_len + fr_len;
		if ((txcfg->privacy) && sw_encrypt)
			pkt_len += (txcfg->icv + txcfg->mic);

		pdesc->Dword0 |= set_desc(pkt_len << TX_DW0_TXPKSIZE_SH);

//		if (!txcfg->need_ack && txcfg->privacy && sw_encrypt)
//			pdesc->Dword1 &= set_desc( ~(TX_SecTypeMask<< TX_SecTypeSHIFT));

		if ((txcfg->privacy) && !sw_encrypt) {
			// hw encrypt
			switch(txcfg->privacy) {
			case _WEP_104_PRIVACY_:
			case _WEP_40_PRIVACY_:
				wep_fill_iv(priv, pwlhdr, txcfg->hdr_len, keyid);
				pdesc->Dword1 |= set_desc(TXDESC_SECTYPE_WEP40_OR_TKIP << TX_DW1_SECTYPE_SH);
				break;

			case _TKIP_PRIVACY_:
				tkip_fill_encheader(priv, pwlhdr, txcfg->hdr_len, keyid);
				pdesc->Dword1 |= set_desc(TXDESC_SECTYPE_WEP40_OR_TKIP << TX_DW1_SECTYPE_SH);
				break;
#if defined(CONFIG_RTL_HW_WAPI_SUPPORT)
			case _WAPI_SMS4_:
				pdesc->Dword1 |= set_desc(TXDESC_SECTYPE_WAPI << TX_DW1_SECTYPE_SH);
				break;
#endif
			case _CCMP_PRIVACY_:
				//michal also hardware...
				aes_fill_encheader(priv, pwlhdr, txcfg->hdr_len, keyid);
				pdesc->Dword1 |= set_desc(TXDESC_SECTYPE_AES << TX_DW1_SECTYPE_SH);
				break;

			default:
				DEBUG_ERR("Unknow privacy\n");
				break;
			}
		}
		
		if (pxmitbuf->agg_num != 0)
			rtl8192cd_usb_cal_txdesc_chksum(pdesc);
		
		if (txcfg->fr_len == 0) {
			goto fill_frame_data;
		}

		/*------------------------------------------------------------*/
		/*              fill descriptor of frame body                 */
		/*------------------------------------------------------------*/
		
		// retrieve H/W MIC and put in payload
#ifdef CONFIG_RTL_WAPI_SUPPORT
		if (txcfg->privacy == _WAPI_SMS4_)
		{
			SecSWSMS4Encryption(priv, txcfg);
		}
#endif

		/*------------------------------------------------------------*/
		/*                insert sw encrypt here!                     */
		/*------------------------------------------------------------*/
		if (txcfg->privacy && sw_encrypt)
		{
			if (txcfg->privacy == _TKIP_PRIVACY_ ||
				txcfg->privacy == _WEP_40_PRIVACY_ ||
				txcfg->privacy == _WEP_104_PRIVACY_)
			{
				if (i == 0)
					tkip_icv(picv,
						pwlhdr + txcfg->hdr_len + txcfg->iv, txcfg->llc,
						pbuf, fr_len);
				else
					tkip_icv(picv,
						NULL, 0,
						pbuf, fr_len);

				if ((i == 0) && (txcfg->llc != 0)) {
					if (txcfg->privacy == _TKIP_PRIVACY_)
						tkip_encrypt(priv, pwlhdr, txcfg->hdr_len,
							pwlhdr + txcfg->hdr_len + 8, sizeof(struct llc_snap),
							pbuf, fr_len, picv, txcfg->icv);
					else
						wep_encrypt(priv, pwlhdr, txcfg->hdr_len,
							pwlhdr + txcfg->hdr_len + 4, sizeof(struct llc_snap),
							pbuf, fr_len, picv, txcfg->icv,
							txcfg->privacy);
				}
				else { // not first segment or no snap header
					if (txcfg->privacy == _TKIP_PRIVACY_)
						tkip_encrypt(priv, pwlhdr, txcfg->hdr_len, NULL, 0,
							pbuf, fr_len, picv, txcfg->icv);
					else
						wep_encrypt(priv, pwlhdr, txcfg->hdr_len, NULL, 0,
							pbuf, fr_len, picv, txcfg->icv,
							txcfg->privacy);
				}
			}
			else if (txcfg->privacy == _CCMP_PRIVACY_)
			{
				// then encrypt all (including ICV) by AES
				if ((i == 0) && (txcfg->llc != 0)) // encrypt 3 segments ==> llc, mpdu, and mic
				{
#ifdef CONFIG_IEEE80211W
					if (isBIP) {
						BIP_encrypt(priv, pwlhdr, pwlhdr + txcfg->hdr_len + 8,
							pbuf, fr_len, pmic, txcfg->isPMF);
					}
					else {
						aesccmp_encrypt(priv, pwlhdr, pwlhdr + txcfg->hdr_len + 8,
							pbuf, fr_len, pmic, txcfg->isPMF);
					}
#else
					aesccmp_encrypt(priv, pwlhdr, pwlhdr + txcfg->hdr_len + 8,
						pbuf, fr_len, pmic);
#endif
				}
				else {// encrypt 2 segments ==> mpdu and mic
#ifdef CONFIG_IEEE80211W
					if (isBIP) {
						BIP_encrypt(priv, pwlhdr, NULL,
							pbuf, fr_len, pmic, txcfg->isPMF);
					}
					else {
						aesccmp_encrypt(priv, pwlhdr, NULL,
							pbuf, fr_len, pmic, txcfg->isPMF);
					}
#else
					aesccmp_encrypt(priv, pwlhdr, NULL,
						pbuf, fr_len, pmic);
#endif
				}
			}
		}
		
fill_frame_data:
		
		// Fill data of header + iv + llc
		memcpy(write_ptr, pwlhdr, hdr_len);
		write_ptr += hdr_len;
		
		if (fr_len) {
			// Fill data of frame payload without llc
			memcpy(write_ptr, pbuf, fr_len);
			write_ptr += fr_len;
			
			// Fill data of icv/mic
			if (txcfg->privacy && sw_encrypt) {
				if (txcfg->privacy == _TKIP_PRIVACY_ ||
					txcfg->privacy == _WEP_40_PRIVACY_ ||
					txcfg->privacy == _WEP_104_PRIVACY_)
				{
					memcpy(write_ptr, picv, txcfg->icv);
					write_ptr += txcfg->icv;
				}
				else if (txcfg->privacy == _CCMP_PRIVACY_)
				{
					memcpy(write_ptr, pmic, txcfg->mic);
					write_ptr += txcfg->mic;
				}
#ifdef CONFIG_RTL_WAPI_SUPPORT
				else if (txcfg->privacy == _WAPI_SMS4_)
				{
					memcpy(write_ptr, pbuf + fr_len, txcfg->mic);
					write_ptr += txcfg->mic;
				}
#endif
			}
		}

		if ((i == (txcfg->frg_num - 1))
#if (BEAMFORMING_SUPPORT == 1)
				&& !txcfg->ndpa
#endif
				)
			pdescinfo->type = txcfg->fr_type;
		else
			pdescinfo->type = _RESERVED_FRAME_TYPE_;

#if defined(CONFIG_RTK_MESH) && defined(MESH_USE_METRICOP)
		if( (txcfg->fr_type == _PRE_ALLOCMEM_) && (txcfg->is_11s & 128)) // for 11s link measurement frame
			pdescinfo->type =_RESERVED_FRAME_TYPE_;
#endif
		pdescinfo->pframe = txcfg->pframe;
		pdescinfo->buf_ptr = mem_start;
		pdescinfo->buf_len = (u32)(write_ptr - mem_start);
		
		pdescinfo->pstat = txcfg->pstat;
		pdescinfo->rate = txcfg->tx_rate;
		pdescinfo->priv = priv;
#ifdef CONFIG_SDIO_HCI
		update_remaining_timeslot(priv, pdescinfo, q_num,
			(get_desc(pdesc->Dword5) >> TX_DW5_DATA_BW_SH) & TX_DW5_DATA_BW_MSK);
#endif
		mem_start = write_ptr;
		++pxmitbuf->agg_num;
		
		pbuf += fr_len;
	}
	
	pxmitbuf->pkt_tail = mem_start;
	
#ifdef TX_SHORTCUT
	if (!priv->pmib->dot11OperationEntry.disable_txsc && txcfg->pstat
			&& (txcfg->fr_type == _SKB_FRAME_TYPE_)
			&& (txcfg->frg_num == 1)
			&& ((txcfg->privacy == 0)
#ifdef CONFIG_RTL_WAPI_SUPPORT
			|| (txcfg->privacy == _WAPI_SMS4_)
#endif
			|| (!sw_encrypt))
//			&& !GetMData(txcfg->phdr)
			&& (txcfg->aggre_en < FG_AGGRE_MSDU_FIRST)
			/*&& (!IEEE8021X_FUN ||
				(IEEE8021X_FUN && (txcfg->pstat->ieee8021x_ctrlport == 1)
				&& (pethhdr->type != htons(0x888e)))) */
			&& (pethhdr->type != htons(0x888e))
#ifdef CONFIG_RTL_WAPI_SUPPORT
			&& (pethhdr->type != htons(ETH_P_WAPI))
#endif
			&& !txcfg->is_dhcp
#ifdef A4_STA
			&& ((txcfg->pstat && txcfg->pstat->state & WIFI_A4_STA) 
				||!IS_MCAST((unsigned char *)pethhdr))
#else
			&& !IS_MCAST((unsigned char *)pethhdr)
#endif
			) {
		pktpri = ((struct sk_buff *)txcfg->pframe)->cb[1];
		idx = get_tx_sc_free_entry(priv, txcfg->pstat, (u8*)pethhdr, pktpri);
		ptxsc_entry = &txcfg->pstat->tx_sc_ent[pktpri][idx];
		
		memcpy((void *)&ptxsc_entry->ethhdr, pethhdr, sizeof(struct wlan_ethhdr_t));
		desc_copy(&ptxsc_entry->hwdesc1, pdesc);
		
		// For convenient follow PCI rule to let Dword7[15:0] of Tx desc backup store TxBuffSize.
		// Do this, we can use the same condition to determine if go through TX shortcut path
		// (Note: for WAPI SW encryption, PCIE IF contain a extra SMS4_MIC_LEN)
		ptxsc_entry->hwdesc1.Dword7 &= set_desc(~TX_TxBufSizeMask);	// Remove checksum
		ptxsc_entry->hwdesc1.Dword7 |= set_desc(txcfg->fr_len & TX_TxBufSizeMask);
		
		descinfo_copy(&ptxsc_entry->swdesc1, pdescinfo);
		ptxsc_entry->sc_keyid = keyid;
		
		memcpy(&ptxsc_entry->txcfg, txcfg, FIELD_OFFSET(struct tx_insn, pxmitframe));
		memcpy((void *)&ptxsc_entry->wlanhdr, txcfg->phdr, sizeof(struct wlanllc_hdr));
		ClearMData(&ptxsc_entry->wlanhdr);	// MoreData bit of backup wlanhdr must be clear due to comment the condition "GetMData"
#ifdef WMM_APSD
		if (eosp) {
			// Let following packet can go through TX shortcut path when receiving trigger frame
			unsigned char *qosctrl = GetQosControl(&ptxsc_entry->wlanhdr);
			qosctrl[0] &= ~BIT4;
		}
#endif
		
		txcfg->pstat->protection = priv->pmib->dot11ErpInfo.protection;
		txcfg->pstat->ht_protection = priv->ht_protection;
	}
#endif // TX_SHORTCUT
	
	if ((_SKB_FRAME_TYPE_ == txcfg->fr_type)
#if (BEAMFORMING_SUPPORT == 1)
				|| txcfg->ndpa
#endif
			) {
		release_wlanllchdr_to_poll(priv, txcfg->phdr);
	} else {
		release_wlanhdr_to_poll(priv, txcfg->phdr);
	}
	txcfg->phdr = NULL;
	
#ifdef CONFIG_TX_RECYCLE_EARLY
	rtl8192cd_usb_tx_recycle(priv, pdescinfo);
#endif

#ifdef CONFIG_SDIO_TX_AGGREGATION
	if (pxmitbuf->ext_tag) {
		sdio_submit_xmitbuf(priv, pxmitbuf);
	} else {
		if (pxmitbuf->agg_start_with == txcfg) {
			rtw_xmitbuf_aggregate(priv, pxmitbuf, txcfg->pstat, q_num);
			sdio_submit_xmitbuf(priv, pxmitbuf);
		}
	}
#else
	sdio_submit_xmitbuf(priv, pxmitbuf);
#endif
	
	txcfg->pxmitbuf = NULL;

	return 0;
}

#ifdef TX_SHORTCUT
int rtl8192cd_signin_txdesc_shortcut(struct rtl8192cd_priv *priv, struct tx_insn *txcfg, struct tx_sc_entry *ptxsc_entry)
{
	struct tx_desc *pdesc;
	struct tx_desc_info *pdescinfo;
	int q_num;
	struct stat_info *pstat;
	struct sk_buff *pskb;
	
	struct xmit_buf *pxmitbuf;
	u8 *mem_start, *pkt_start, *write_ptr;
	u32 pkt_len, hdr_len, fr_len;
	
	pstat = txcfg->pstat;
	pskb = (struct sk_buff *)txcfg->pframe;

	q_num = txcfg->q_num;
	
	pxmitbuf = txcfg->pxmitbuf;
	
	mem_start = pxmitbuf->pkt_tail;
	mem_start = PTR_ALIGN(mem_start, TXAGG_DESC_ALIGN_SZ);
	
	pdesc = (struct tx_desc*) mem_start;
	pdescinfo = &pxmitbuf->txdesc_info[pxmitbuf->agg_num];
	
	pkt_start = mem_start + TXDESC_SIZE;
	if (0 == pxmitbuf->agg_num)
		pkt_start += (pxmitbuf->pkt_offset * PACKET_OFFSET_SZ);
		
	write_ptr = pkt_start;
	
	hdr_len = txcfg->hdr_len + txcfg->iv + txcfg->llc;
	fr_len = txcfg->fr_len;
#if defined(CONFIG_RTL_WAPI_SUPPORT)
	if (txcfg->privacy == _WAPI_SMS4_)
		fr_len += txcfg->mic;		// For WAPI software encryption, we must consider txcfg->mic
#endif
	pkt_len  = hdr_len + fr_len;
	
	/*------------------------------------------------------------*/
	/*           fill descriptor of header + iv + llc             */
	/*------------------------------------------------------------*/
	desc_copy(pdesc, &ptxsc_entry->hwdesc1);

	assign_wlanseq(GET_HW(priv), txcfg->phdr, pstat, GET_MIB(priv)
#ifdef CONFIG_RTK_MESH	// For broadcast data frame via mesh (ex:ARP requst)
		, txcfg->is_11s
#endif
		);

	pdesc->Dword9 &= ~ set_desc(TX_DW9_SEQ_MSK << TX_DW9_SEQ_SH);
	pdesc->Dword9 |= set_desc((GetSequence(txcfg->phdr) & TX_DW9_SEQ_MSK)  << TX_DW9_SEQ_SH);

	if ((pstat->IOTPeer == HT_IOT_PEER_INTEL) && (pstat->retry_inc)) {
		if (is_MCS_rate(pstat->current_tx_rate) && !(pstat->leave)
				&& priv->pshare->intel_rty_lmt) {
			pdesc->Dword4 |= set_desc(1 << TX_DW4_RTY_LMT_EN_SH);
			
			pdesc->Dword4 &= ~ set_desc(TX_DW4_DATA_RT_LMT_MSK << TX_DW4_DATA_RT_LMT_SH);
			pdesc->Dword4 |= set_desc((priv->pshare->intel_rty_lmt & TX_DW4_DATA_RT_LMT_MSK) << TX_DW4_DATA_RT_LMT_SH);
		} else {
			pdesc->Dword4 &= ~ set_desc(1 << TX_DW4_RTY_LMT_EN_SH);
			pdesc->Dword4 &= ~ set_desc(TX_DW4_DATA_RT_LMT_MSK << TX_DW4_DATA_RT_LMT_SH);
		}
	}

	if((priv->pshare->rf_ft_var.txforce != 0xff)
#if (BEAMFORMING_SUPPORT == 1)
		&& (!txcfg->ndpa) 
#endif
	){
		pdesc->Dword4 &= ~ set_desc(TX_DW4_DATARATE_MSK << TX_DW4_DATARATE_SH);
		pdesc->Dword4 |= set_desc((priv->pshare->rf_ft_var.txforce & TX_DW4_DATARATE_MSK) << TX_DW4_DATARATE_SH);
		
		pdesc->Dword3 |= set_desc(1 << TX_DW3_USERATE_SH);
		pdesc->Dword3 |= set_desc(1 << TX_DW3_DISDATAFB_SH);
		pdesc->Dword3 |= set_desc(1 << TX_DW3_DISRTSFB_SH);
	}

#if (BEAMFORMING_SUPPORT == 1)
	if (txcfg->pstat)
	{
		if ((txcfg->pstat->cmn_info.stbc_en & HT_STBC_EN)
#ifdef RTK_AC_SUPPORT
			|| (txcfg->pstat->cmn_info.stbc_en & VHT_STBC_EN)
#endif
		) {
			u1Byte					Idx = 0;
			PRT_BEAMFORMING_ENTRY	pEntry;
			pEntry = Beamforming_GetEntryByMacId(priv, txcfg->pstat->cmn_info.aid, &Idx);
			if (((get_rf_mimo_mode(priv) == RF_2T2R) || (get_rf_mimo_mode(priv) == RF_3T3R)) && (pEntry == NULL))
				pdesc->Dword5 |= set_desc(1 << TX_DW5_DATA_STBC_SH);
		}
	}
#endif
	
#ifdef CLIENT_MODE
	if (OPMODE & WIFI_STATION_STATE) {
		if (GetFrameSubType(txcfg->phdr) == WIFI_PSPOLL)
			pdesc->Dword3 |= set_desc(1 << TX_DW3_NAVUSEHDR_SH);

		if (priv->ps_state)
			SetPwrMgt(txcfg->phdr);
		else
			ClearPwrMgt(txcfg->phdr);
	}
#endif
	
	pdesc->Dword0 = set_desc((get_desc(pdesc->Dword0) & ~TX_DW0_TXPKSIZE_MSK) | pkt_len);
	
	if (pxmitbuf->agg_num != 0)
		rtl8192cd_usb_cal_txdesc_chksum(pdesc);

	descinfo_copy(pdescinfo, &ptxsc_entry->swdesc1);

	/*------------------------------------------------------------*/
	/*              fill descriptor of frame body                 */
	/*------------------------------------------------------------*/
	
#if defined(CONFIG_RTL_WAPI_SUPPORT)
	if (txcfg->privacy == _WAPI_SMS4_)
	{
		SecSWSMS4Encryption(priv, txcfg);
	}
#endif
	
	// Fill data of header + iv + llc
	memcpy(write_ptr, txcfg->phdr, hdr_len);
	write_ptr += hdr_len;
	
	// Fill data of frame payload without llc
	memcpy(write_ptr, pskb->data, fr_len);
	write_ptr += fr_len;
	
//	pdescinfo->type = _SKB_FRAME_TYPE_;
	pdescinfo->pframe = pskb;
	pdescinfo->buf_ptr = mem_start;
	pdescinfo->buf_len = (u32)(write_ptr - mem_start);
	
	pdescinfo->pstat = pstat;
	pdescinfo->priv = priv;
#ifdef CONFIG_SDIO_HCI
	update_remaining_timeslot(priv, pdescinfo, q_num,
		(get_desc(pdesc->Dword5) >> TX_DW5_DATA_BW_SH) & TX_DW5_DATA_BW_MSK);
#endif
	++pxmitbuf->agg_num;
	
	pxmitbuf->pkt_tail = write_ptr;
	
	release_wlanllchdr_to_poll(priv, txcfg->phdr);
	txcfg->phdr = NULL;
	
#ifdef CONFIG_TX_RECYCLE_EARLY
	rtl8192cd_usb_tx_recycle(priv, pdescinfo);
#endif

#ifdef CONFIG_SDIO_TX_AGGREGATION
	if (pxmitbuf->ext_tag) {
		sdio_submit_xmitbuf(priv, pxmitbuf);
	} else {
		if (pxmitbuf->agg_start_with == txcfg) {
			rtw_xmitbuf_aggregate(priv, pxmitbuf, pstat, q_num);
			sdio_submit_xmitbuf(priv, pxmitbuf);
		}
	}
#else
	sdio_submit_xmitbuf(priv, pxmitbuf);
#endif
	
	txcfg->pxmitbuf = NULL;

	return 0;
}
#endif // TX_SHORTCUT

void hal_fill_bcn_desc(struct rtl8192cd_priv *priv, struct tx_desc *pdesc, void *dat_content, unsigned short txLength, char forceUpdate)
{
	if (txLength != priv->tx_beacon_len || forceUpdate)
	{
		forceUpdate = 1;
		memset(pdesc, 0, TXDESC_SIZE);
		
		pdesc->Dword0 |= set_desc((1 << TX_DW0_BMC_SH) | (TXDESC_SIZE << TX_DW0_OFFSET_SH));
		pdesc->Dword0 |= set_desc((txLength & TX_DW0_TXPKSIZE_MSK) << TX_DW0_TXPKSIZE_SH);
		pdesc->Dword1 |= set_desc(TXDESC_QSEL_BCN << TX_DW1_QSEL_SH);

#ifdef MBSSID
		if (IS_VAP_INTERFACE(priv)) {
			// set MBSSID index
			pdesc->Dword1 |= set_desc((priv->vap_init_seq & TX_DW1_MACID_MSK) << TX_DW1_MACID_SH);
			pdesc->Dword6 |= set_desc((priv->vap_init_seq & TX_DW6_MBSSID_MSK) << TX_DW6_MBSSID_SH);
		}
#endif
		pdesc->Dword9 = set_desc((GetSequence(dat_content) & TX_DW9_SEQ_MSK) << TX_DW9_SEQ_SH);
		pdesc->Dword3 |= set_desc((1 << TX_DW3_DISDATAFB_SH) | (1 << TX_DW3_USERATE_SH));

		priv->tx_beacon_len = txLength;
	}
	else
	{
		pdesc->Dword9 = set_desc((GetSequence(dat_content) & TX_DW9_SEQ_MSK) << TX_DW9_SEQ_SH);
	}

	// Group Bit Control
	pdesc->Dword9 |= set_desc(((priv->timoffset-24) & TX_DW9_GROUPBIT_IE_OFFSET_MSK) << TX_DW9_GROUPBIT_IE_OFFSET_SH);
	// Auto set bitmap control by HW
	if (OPMODE & WIFI_ADHOC_STATE) {
		pdesc->Dword9 |= set_desc(0 << TX_DW9_GROUPBIT_IE_ENABLE_SH);
	} else {
		pdesc->Dword9 |= set_desc(1 << TX_DW9_GROUPBIT_IE_ENABLE_SH);
	}

#ifdef P2P_SUPPORT  // 2013
	if ((OPMODE & WIFI_P2P_SUPPORT) && (P2PMODE==P2P_TMP_GO || P2PMODE==P2P_PRE_GO)) {
		pdesc->Dword4 |= set_desc(4 << TX_DW4_RTSRATE_SH);    // RTS rate set to 6M
		pdesc->Dword4 |= set_desc(4 << TX_DW4_DATARATE_SH);  // use 6M to beacon rate
	}
#endif
	
	/*
	* Intel IOT, dynamic enhance beacon tx AGC
	*/
	if ((priv->bcnTxAGC_bak != priv->bcnTxAGC) || forceUpdate)
	{
		pdesc->Dword5 &= ~ set_desc(TX_DW5_TXPWR_OFSET_MSK << TX_DW5_TXPWR_OFSET_SH);
		if (priv->bcnTxAGC == 1) {
			pdesc->Dword5 |= set_desc(4 << TX_DW5_TXPWR_OFSET_SH);
		} else if (priv->bcnTxAGC == 2) {
			pdesc->Dword5 |= set_desc(5 << TX_DW5_TXPWR_OFSET_SH);
		}
		priv->bcnTxAGC_bak = priv->bcnTxAGC;
	}

	if ((priv->pshare->is_40m_bw != priv->pshare->is_40m_bw_bak) || forceUpdate) {
		pdesc->Dword5 &= ~ set_desc(TX_DW5_DATA_SC_MSK << TX_DW5_DATA_SC_SH);

		if (priv->pshare->is_40m_bw) {
			if (priv->pshare->offset_2nd_chan == HT_2NDCH_OFFSET_BELOW)
				pdesc->Dword5 |= set_desc(2 << TX_DW5_DATA_SC_SH);
			else
				pdesc->Dword5 |= set_desc(1 << TX_DW5_DATA_SC_SH);
		}
		priv->pshare->is_40m_bw_bak = priv->pshare->is_40m_bw;
	}
}


int signin_beacon_desc(struct rtl8192cd_priv *priv, unsigned int *beaconbuf, unsigned int frlen)
{
	struct tx_desc *pdesc;
	struct tx_desc_info	*pdescinfo;
	struct xmit_buf *pxmitbuf;
	u8 *mem_start, *pkt_start;
	u32 tx_len, pkt_offset;
	
	pdesc = &priv->tx_descB;
	
	// only one that hold the ownership of the HW TX queue can signin beacon
	// because there is only one reserved beacon block in HW to store beacon content
	if (test_and_set_bit(BEACON_QUEUE, &priv->pshare->use_hw_queue_bitmap) != 0)
		return -2;
	
	if (NULL == (pxmitbuf = rtw_alloc_beacon_xmitbuf(priv))) {
		// Release the ownership of the HW TX queue
		clear_bit(BEACON_QUEUE, &priv->pshare->use_hw_queue_bitmap);
		
		printk("[%s] alloc xmitbuf fail\n", __FUNCTION__);
		return -3;
	}
	pxmitbuf->use_hw_queue = 1;
	
	hal_fill_bcn_desc(priv, pdesc, (void*)beaconbuf, frlen, 0);
	
	mem_start = pxmitbuf->pkt_data;
	
	pkt_offset = pxmitbuf->pkt_offset * PACKET_OFFSET_SZ;
	pkt_start = mem_start + TXDESC_SIZE + pkt_offset;
	tx_len = frlen + TXDESC_SIZE + pkt_offset;
	
	memcpy(mem_start, pdesc, TXDESC_SIZE);
	memcpy(pkt_start, beaconbuf, frlen);

	pxmitbuf->pkt_tail = mem_start + tx_len;
	
	pdescinfo = &pxmitbuf->txdesc_info[0];
	pdescinfo->type = _RESERVED_FRAME_TYPE_;
	pdescinfo->pframe = NULL;
	pdescinfo->priv = priv;

	pdescinfo->buf_ptr = mem_start;
	pdescinfo->buf_len = tx_len;
	pxmitbuf->agg_num = 1;
	
	return sdio_submit_xmitbuf(priv, pxmitbuf);
}

#ifdef SDIO_AP_OFFLOAD
void ap_offload_process(struct rtl8192cd_priv *priv, unsigned int frlen)
{
	struct priv_shared_info *pshare = priv->pshare;
	struct rtl8192cd_hw *phw;
	struct wifi_mib *pmib;
	
	struct tx_desc *pdesc;
	u8 *pkt_start;
	int len, total_len, offset;
#ifdef MBSSID
	int i;
#endif

	pmib = GET_MIB(priv);
	phw = GET_HW(priv);

	/* beacon part */
	pshare->ap_offload_res[0].beacon_offset = 0;
	pkt_start = (u8*) pshare->offload_buf;
	
	memcpy(pkt_start, priv->beaconbuf, frlen);
	
	len = frlen + TXDESC_SIZE;
	offset = ALIGN(len, TX_PAGE_SIZE);
	if (offset - len < TXDESC_SIZE)
		offset += TX_PAGE_SIZE;
	
	/* probe rsp */
	pshare->ap_offload_res[0].probe_offset = (offset / TX_PAGE_SIZE);
	pkt_start = (u8*) pshare->offload_buf + offset;
	pdesc = (struct tx_desc *)(pkt_start - TXDESC_SIZE);
	
	memset(pkt_start, 0, WLAN_HDR_A3_LEN);
	len = WLAN_HDR_A3_LEN + fill_probe_rsp_content(priv, pkt_start, pkt_start+WLAN_HDR_A3_LEN,
		SSID, SSID_LEN, 1, 0, 0);

	assign_wlanseq(phw, pkt_start, NULL, pmib
#ifdef CONFIG_RTK_MESH	// For broadcast data frame via mesh (ex:ARP requst)
		, 0
#endif
		);
	memset(pdesc, 0, TXDESC_SIZE);
	hal_fill_bcn_desc(priv, pdesc, (void*)pkt_start, len, 1);
	pdesc->Dword8 |= set_desc(1 << TX_DW8_EN_HWSEQ_SH);//test by zyj
	pdesc->Dword3 |= set_desc((1 << TX_DW3_HW_SSN_SEL_SH));
	RTL_W16(0x4DA, (GetSequence(pkt_start) & TX_DW9_SEQ_MSK));
	RTL_W8(0x423, 0xff);  /* enable hw pkt seq */
	
	pdesc->Dword4 &= ~ set_desc(TX_DW4_DATA_RT_LMT_MSK << TX_DW4_DATA_RT_LMT_SH);
	pdesc->Dword4 |= set_desc(1 << TX_DW4_RTY_LMT_EN_SH);
	pdesc->Dword1 |= set_desc(0x12 << TX_DW1_QSEL_SH);
	rtl8192cd_usb_cal_txdesc_chksum(pdesc);
	
	total_len = offset + len;
	offset = ALIGN(total_len, TX_PAGE_SIZE);
	if (offset - total_len < TXDESC_SIZE)
		offset += TX_PAGE_SIZE;

#ifdef MBSSID
	for (i = 1; i < pshare->nr_bcn; i++) {
		struct rtl8192cd_priv *priv_vap;
		struct tx_desc *bcndesc;

		priv_vap = pshare->bcn_priv[i];
		
		/* beacon part */
		pshare->ap_offload_res[i].beacon_offset = (offset / TX_PAGE_SIZE);
		pkt_start = (u8*) pshare->offload_buf + offset;
		pdesc = (struct tx_desc *)(pkt_start - TXDESC_SIZE);
		
		bcndesc = &priv_vap->tx_descB;
		len = get_desc(bcndesc->Dword0) & TX_TxBufSizeMask;
		
		memcpy(pkt_start, (unsigned char *)priv_vap->beaconbuf, len);
		memcpy(pdesc, bcndesc, TXDESC_SIZE);
		hal_fill_bcn_desc(priv_vap, pdesc, (void*)pkt_start, len, 1);
		rtl8192cd_usb_cal_txdesc_chksum(pdesc);

		total_len = offset + len;
		offset = ALIGN(total_len, TX_PAGE_SIZE);
		if (offset - total_len < TXDESC_SIZE)
			offset += TX_PAGE_SIZE;

		/* probe rsp */
		pshare->ap_offload_res[i].probe_offset = (offset / TX_PAGE_SIZE);
		pkt_start = (u8*) pshare->offload_buf + offset;
		pdesc = (struct tx_desc *)(pkt_start - TXDESC_SIZE);
		
		memset(pkt_start, 0, WLAN_HDR_A3_LEN);
		len = WLAN_HDR_A3_LEN + fill_probe_rsp_content(priv_vap, pkt_start, pkt_start+WLAN_HDR_A3_LEN,
			((GET_MIB(priv_vap))->dot11StationConfigEntry.dot11DesiredSSID),
			((GET_MIB(priv_vap))->dot11StationConfigEntry.dot11DesiredSSIDLen), 1, 0, 0);

		assign_wlanseq(phw, pkt_start, NULL, priv_vap->pmib
#ifdef CONFIG_RTK_MESH
			,0 /* For broadcast data frame via mesh (ex:ARP requst) */
#endif
			);                     
		memset(pdesc, 0, TXDESC_SIZE);
		hal_fill_bcn_desc(priv_vap, pdesc, (void*)pkt_start, len, 1);
		pdesc->Dword4 &= ~ set_desc(TX_DW4_DATA_RT_LMT_MSK << TX_DW4_DATA_RT_LMT_SH);
		pdesc->Dword4 |= set_desc(1 << TX_DW4_RTY_LMT_EN_SH);
		pdesc->Dword1 |= set_desc(0x12 << TX_DW1_QSEL_SH);
		rtl8192cd_usb_cal_txdesc_chksum(pdesc);

		total_len = offset + len;
		offset = ALIGN(total_len, TX_PAGE_SIZE);
		if (offset - total_len < TXDESC_SIZE)
			offset += TX_PAGE_SIZE;
	} /* for */
#endif // MBSSID

	printk("offload total_len=%d\n", total_len);
	WARN_ON(total_len > sizeof(pshare->offload_buf));

	pshare->offload_function_ctrl = RTW_PM_START;
	if (signin_beacon_desc(priv, pshare->offload_buf, total_len))
		goto out_err;
	if (signin_beacon_desc(priv, priv->beaconbuf, frlen))
		goto out_err;
#ifdef USE_WAKELOCK_MECHANISM
	if (pshare->ps_ctrl != RTW_ACT_POWERDOWN)
#endif
	cmd_set_ap_offload(priv, 1);
	return;

out_err:
	pshare->offload_function_ctrl = RTW_PM_AWAKE;
	rtw_lock_suspend_timeout(priv, 2*priv->pmib->dot11OperationEntry.ps_timeout);
}
#endif // SDIO_AP_OFFLOAD

