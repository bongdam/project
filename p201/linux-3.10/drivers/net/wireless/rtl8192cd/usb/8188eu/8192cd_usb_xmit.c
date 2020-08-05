/*
 *  USB TX handle routines
 *
 *  Copyright (c) 2017 Realtek Semiconductor Corp.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#define _8192CD_USB_XMIT_C_

#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/tcp.h>
#endif

#include "8192cd.h"
#include "8192cd_headers.h"
#include "8192cd_debug.h"

#ifdef CONFIG_LOCKDEP
static struct lock_class_key tx_pending_sta_queue_lock_key[MAX_HW_TX_QUEUE];
static const char *tx_pending_sta_queue_key_strings[MAX_HW_TX_QUEUE] = {
	"MG_STAQ", "BK_STAQ", "BE_STAQ", "VI_STAQ", "VO_STAQ", "HI_STAQ", "BN_STAQ", "TXCMD_STAQ"
};
#endif

static void rtl8192cd_xmit_check_timer(unsigned long task_priv);
void rtl8192cu_xmit_tasklet(unsigned long data);
void usb_recycle_xmitbuf(struct rtl8192cd_priv *priv, struct xmit_buf *pxmitbuf);


int rtw_os_xmit_resource_alloc(struct rtl8192cd_priv *priv, struct xmit_buf *pxmitbuf, u32 alloc_sz)
{
#ifdef CONFIG_USE_USB_BUFFER_ALLOC_TX
	pxmitbuf->pallocated_buf = rtw_usb_buffer_alloc(priv->pshare->pusbdev, (size_t)alloc_sz, GFP_ATOMIC, &pxmitbuf->dma_transfer_addr);
	if (NULL == pxmitbuf->pallocated_buf)
		return FAIL;
	
	pxmitbuf->pkt_head = pxmitbuf->pallocated_buf;
#else // !CONFIG_USE_USB_BUFFER_ALLOC_TX
	
	pxmitbuf->pallocated_buf = rtw_zmalloc(alloc_sz);
	if (NULL == pxmitbuf->pallocated_buf)
	{
		return FAIL;
	}

	pxmitbuf->pkt_head = (u8 *)N_BYTE_ALIGMENT((SIZE_PTR)(pxmitbuf->pallocated_buf), XMITBUF_ALIGN_SZ);
	pxmitbuf->dma_transfer_addr = 0;
	
#endif // CONFIG_USE_USB_BUFFER_ALLOC_TX
	
	pxmitbuf->pxmit_urb = usb_alloc_urb(0, GFP_KERNEL);
     	if (NULL == pxmitbuf->pxmit_urb) 
     	{
    		return FAIL;
     	}
	
	pxmitbuf->pkt_end = pxmitbuf->pallocated_buf + alloc_sz;

	return SUCCESS;	
}

void rtw_os_xmit_resource_free(struct rtl8192cd_priv *priv, struct xmit_buf *pxmitbuf, u32 free_sz)
{
	if (pxmitbuf->pxmit_urb)
	{
		//usb_kill_urb(pxmitbuf->pxmit_urb);
		usb_free_urb(pxmitbuf->pxmit_urb);
	}
	
	if (pxmitbuf->pallocated_buf)
	{
#ifdef CONFIG_USE_USB_BUFFER_ALLOC_TX
		rtw_usb_buffer_free(priv->pshare->pusbdev, (size_t)free_sz, pxmitbuf->pallocated_buf, pxmitbuf->dma_transfer_addr);
		pxmitbuf->dma_transfer_addr = 0;
#else // !CONFIG_USE_USB_BUFFER_ALLOC_TX
		
		rtw_mfree(pxmitbuf->pallocated_buf, free_sz);
#endif // CONFIG_USE_USB_BUFFER_ALLOC_TX
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
		_rtw_init_queue(&pshare->tx_urb_waiting_queue[i]);
#ifdef CONFIG_LOCKDEP
		// avoid false positives, we need lockdep annotations to prevent them.
		lockdep_set_class_and_name(&pshare->tx_pending_sta_queue[i].lock,
			&tx_pending_sta_queue_lock_key[i],
			tx_pending_sta_queue_key_strings[i]);
#endif
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
		_rtw_init_listhead(&pxmitbuf->tx_urb_list);
		
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
		_rtw_init_listhead(&pxmitbuf->tx_urb_list);
		
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
		_rtw_init_listhead(&pxmitbuf->tx_urb_list);
		
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
		_rtw_init_listhead(&pxmitbuf->tx_urb_list);
		
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
	tasklet_init(&pshare->xmit_tasklet, rtl8192cu_xmit_tasklet, (unsigned long)priv);

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
		_rtw_spinlock_free(&pshare->tx_urb_waiting_queue[i].lock);
	}
	
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
		plist = NULL;
		
		xmit_lock(&sta_queue->lock, &irqL);
		
		if (rtw_is_list_empty(phead) == FALSE)
			plist = get_next(phead);
		
		xmit_unlock(&sta_queue->lock, &irqL);
		
		if (NULL == plist) {
			need_sched_xmit_for_dequeue(priv, q_num);
			return NULL;
		}
		
		ptxservq = LIST_CONTAINOR(plist, struct tx_servq, tx_pending);
		
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
		if (priv->release_mcast && (tx_servq_len(&priv->tx_mc_queue) == 0))
			priv->release_mcast = 0;
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

void rtl8192cu_xmit_tasklet(unsigned long data)
{
	struct rtl8192cd_priv *priv = (struct rtl8192cd_priv*)data;
	struct priv_shared_info *pshare = priv->pshare;
	struct xmit_frame *pxmitframe;
	struct xmit_buf *pxmitbuf;
	struct tx_insn* txcfg;
	
	const u8 q_priority[] = {HIGH_QUEUE, MGNT_QUEUE, VO_QUEUE, VI_QUEUE, BE_QUEUE, BK_QUEUE};
	int i, q_num=-1;
	
	while(1)
	{
		if ((pshare->bDriverStopped == TRUE)||(pshare->bSurpriseRemoved== TRUE) || (pshare->bWritePortCancel == TRUE))
		{
			printk("[%s] bDriverStopped(%d) OR bSurpriseRemoved(%d) OR bWritePortCancel(%d)\n",
				__FUNCTION__, pshare->bDriverStopped, pshare->bSurpriseRemoved, pshare->bWritePortCancel);
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
			}

			if (!(pshare->need_sched_xmit & BIT(q_num)))
				continue;

			if (test_and_set_bit(q_num, &pshare->use_hw_queue_bitmap) == 0) {
				if (NULL != (pxmitframe = rtw_dequeue_xmitframe(priv, q_num)))
					break;
				
				clear_bit(q_num, &pshare->use_hw_queue_bitmap);
			}
		}
		
		if (NULL == pxmitframe)
			break;
		
		txcfg = &pxmitframe->txinsn;
		
		// re-assign q_num to avoid txcfg->q_num is not equal tx_servq.q_num for tx_mc_queue.
		// Because q_num of tx_mc_queue will switch to MCAST_QNUM once any STA sleeps.
		// This action is redundent for other queues.
		txcfg->q_num = q_num;
		
		if (_SKB_FRAME_TYPE_ == txcfg->fr_type) {
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
			pxmitframe = rtw_txservq_dequeue(priv, ptxservq);
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

/*
	Procedure to re-cycle TXed packet

	=> Return value means if system need restart-TX-queue or not.

		1: Need Re-start Queue
		0: Don't Need Re-start Queue
*/

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

void usb_recycle_xmitbuf(struct rtl8192cd_priv *priv, struct xmit_buf *pxmitbuf)
{
	struct priv_shared_info *pshare = priv->pshare;
	_queue *urb_queue;
	_irqL irqL;
	int i;
	
	if (rtw_is_list_empty(&pxmitbuf->tx_urb_list) == FALSE) {
		urb_queue = &pshare->tx_urb_waiting_queue[pxmitbuf->q_num];
		
		_enter_critical(&urb_queue->lock, &irqL);
		
		rtw_list_delete(&pxmitbuf->tx_urb_list);
		
		--urb_queue->qlen;
		
		_exit_critical(&urb_queue->lock, &irqL);
	}
	
#ifndef CONFIG_TX_RECYCLE_EARLY
	for (i = 0; i < pxmitbuf->agg_num; ++i) {
		rtl8192cd_usb_tx_recycle(priv, &pxmitbuf->txdesc_info[i]);
	}
#endif
	
#ifdef CONFIG_RTL_92C_SUPPORT
	if (MCAST_QNUM == pxmitbuf->q_num) {
		if ((_rtw_queue_empty(&pshare->tx_pending_sta_queue[MCAST_QNUM]) == TRUE)
				&& (0 == pshare->tx_urb_waiting_queue[MCAST_QNUM].qlen)) {
			struct rtl8192cd_hw *phw = pshare->phw;
			
			if (phw->HIQ_nolimit_en) {
				phw->HIQ_nolimit_en = 0;
				notify_HIQ_NoLimit_change(priv);
			}
		}
	}
#endif
	
	if (BEACON_QUEUE == pxmitbuf->q_num) {
#if defined(CONFIG_RTL_92C_SUPPORT) || (!defined(CONFIG_SUPPORT_USB_INT) || !defined(CONFIG_INTERRUPT_BASED_TXBCN))
		if (0 == pxmitbuf->pxmit_urb->status)
			++priv->ext_stats.beacon_ok;
		else
			++priv->ext_stats.beacon_er;
#endif
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

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19))
static void usb_write_port_complete(struct urb *purb)
#else
static void usb_write_port_complete(struct urb *purb, struct pt_regs *regs)
#endif
{
	struct xmit_buf *pxmitbuf = (struct xmit_buf *)purb->context;
	struct rtl8192cd_priv *priv = pxmitbuf->priv;
	struct priv_shared_info *pshare = priv->pshare;
	
//	printk("+usb_write_port_complete\n");
	
	if(pshare->bSurpriseRemoved || pshare->bDriverStopped ||pshare->bWritePortCancel)
	{
		printk("[%s] bDriverStopped(%d) OR bSurpriseRemoved(%d) OR bWritePortCancel(%d)\n",
			__FUNCTION__, pshare->bDriverStopped, pshare->bSurpriseRemoved, pshare->bWritePortCancel);
		goto check_completion;
	}
	
	if(purb->status==0)
	{
	
	}
	else
	{
		printk("usb_write_port_complete : purb->status(%d) != 0 \n", purb->status);
		if((purb->status==-EPIPE) ||(purb->status==-EPROTO))
		{
		}
		else if(purb->status == -EINPROGRESS)
		{
			printk("usb_write_port_complete: EINPROGESS\n");
		}
		else if((purb->status == -ECONNRESET) || (purb->status == -ENOENT))
		{
			// Call usb_unlink_urb() or usb_kill_urb() to cancel urb
		}
		else if(purb->status == -ESHUTDOWN)
		{
			printk("usb_write_port_complete: ESHUTDOWN\n");
						
			pshare->bDriverStopped = TRUE;
			
			printk("usb_write_port_complete:bDriverStopped=TRUE\n");

			goto check_completion;
		}
		else
		{					
			pshare->bSurpriseRemoved = TRUE;
			printk("usb_write_port_complete:bSurpriseRemoved=TRUE\n");

			goto check_completion;
		}
	}

check_completion:
	
	if (pxmitbuf->isSync) {
		pxmitbuf->status = purb->status;
		complete(&pxmitbuf->done);
	} else {
		usb_recycle_xmitbuf(priv, pxmitbuf);
		if (pshare->need_sched_xmit)
			tasklet_hi_schedule(&pshare->xmit_tasklet);
	}
	
}

u32 usb_write_port(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *wmem, int timeout_ms)
{    
	unsigned int pipe;
	int status;
	u32 ret;
	struct urb *purb = NULL;
	struct priv_shared_info *pshare = priv->pshare;
	struct xmit_buf *pxmitbuf = (struct xmit_buf *)wmem;
	struct usb_device *pusbd = pshare->pusbdev;
	
	_queue *urb_queue;
	_irqL irqL;
	
	BUG_ON(0 == pxmitbuf->use_hw_queue);
	
	if((pshare->bDriverStopped) || (pshare->bSurpriseRemoved))
	{
		// Release the ownership of the HW TX queue
		clear_bit(pxmitbuf->q_num, &pshare->use_hw_queue_bitmap);
		pxmitbuf->use_hw_queue = 0;
		
		usb_recycle_xmitbuf(priv, pxmitbuf);
		
		printk("[%s] bDriverStopped(%d) OR bSurpriseRemoved(%d)\n",
			__FUNCTION__, pshare->bDriverStopped, pshare->bSurpriseRemoved);
		return FAIL;
	}
	
	pxmitbuf->priv = priv;
	
	//translate DMA FIFO addr to pipe handle
	pipe = ffaddr2pipehdl(priv, addr);
	
	purb = pxmitbuf->pxmit_urb;
	
#ifdef CONFIG_REDUCE_USB_TX_INT	
	if ( (pshare->free_xmitbuf_queue.qlen % NR_XMITBUFF == 0)
		|| (pxmitbuf->ext_tag == TRUE) )
	{
		purb->transfer_flags  &=  (~URB_NO_INTERRUPT);
	} else {
		purb->transfer_flags  |=  URB_NO_INTERRUPT;
	}
#endif
	
	usb_fill_bulk_urb(purb, pusbd, pipe, 
       				pxmitbuf->pkt_data,
              			cnt,
              			usb_write_port_complete,
              			pxmitbuf);//context is pxmitbuf
              			
#ifdef CONFIG_USE_USB_BUFFER_ALLOC_TX
	purb->transfer_dma = pxmitbuf->dma_transfer_addr;
	purb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
	purb->transfer_flags |= URB_ZERO_PACKET;
#endif // CONFIG_USE_USB_BUFFER_ALLOC_TX
              			
#if 0
	if (bwritezero)
        {
            purb->transfer_flags |= URB_ZERO_PACKET;           
        }			
#endif

	if (timeout_ms >= 0) {
		init_completion(&pxmitbuf->done);
		pxmitbuf->isSync = TRUE;
	} else {
		pxmitbuf->isSync = FALSE;
	}
	
	urb_queue = &pshare->tx_urb_waiting_queue[addr];
	
	_enter_critical(&urb_queue->lock, &irqL);
	
	rtw_list_insert_tail(&pxmitbuf->tx_urb_list, &urb_queue->queue);
	
	++urb_queue->qlen;
	
	_exit_critical(&urb_queue->lock, &irqL);
	
#ifdef CONFIG_RTL_92C_SUPPORT
	if (MCAST_QNUM == addr) {
		struct rtl8192cd_hw *phw = pshare->phw;
		
		if (!phw->HIQ_nolimit_en) {
			phw->HIQ_nolimit_en = 1;
			notify_HIQ_NoLimit_change(priv);
		}
	}
#endif
	
	pxmitbuf->use_hw_queue = 0;

	status = usb_submit_urb(purb, GFP_ATOMIC);
	
	// Release the ownership of the HW TX queue
	// place it in the back of usb_submit_urb() to avoid usb_submit_urb() contention
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
	smp_mb__before_atomic();
#else
	smp_mb__before_clear_bit();
#endif
	clear_bit(addr, &pshare->use_hw_queue_bitmap);
	
	if ((addr >= BK_QUEUE) && (addr <= VO_QUEUE)) {
		pshare->low_traffic_xmit_stats[addr] += pxmitbuf->agg_num;
	}

	if (!status)
	{
		ret = SUCCESS;
	}
	else
	{
		printk("usb_write_port, status=%d\n", status);
		ret = FAIL;
		usb_recycle_xmitbuf(priv, pxmitbuf);
	}
	
//   Commented by Albert 2009/10/13
//   We add the URB_ZERO_PACKET flag to urb so that the host will send the zero packet automatically.
/*	
	if(bwritezero == _TRUE)
	{
		usb_bulkout_zero(pintfhdl, addr);
	}
*/

	// synchronous write handling
	if ((timeout_ms >= 0) && (0 == status)) {
		unsigned long expire = timeout_ms ? msecs_to_jiffies(timeout_ms) : MAX_SCHEDULE_TIMEOUT;
		int status;
		pxmitbuf->status = 0;

		if (!wait_for_completion_timeout(&pxmitbuf->done, expire)) {
			usb_kill_urb(purb);
			status = ((pxmitbuf->status == -ENOENT) ? -ETIMEDOUT : pxmitbuf->status);
		} else
			status = pxmitbuf->status;

		if (!status) {
			ret = SUCCESS;
		} else {
			printk("usb_write_port sync, status=%d\n", status);
			ret = FAIL;
		}
		
		usb_recycle_xmitbuf(priv, pxmitbuf);
	}


//	printk("-usb_write_port\n");
	
	return ret;

}

void usb_write_port_cancel(struct rtl8192cd_priv *priv)
{
	int i;
	struct priv_shared_info *pshare = priv->pshare;
	struct xmit_buf *pxmitbuf;

	printk("usb_write_port_cancel \n");
	
	pshare->bWritePortCancel = TRUE;
	
	pxmitbuf = (struct xmit_buf *)pshare->pxmitbuf;
	
	for(i=0; i<NR_XMITBUFF; i++)
	{
	        if(pxmitbuf->pxmit_urb)
	        {
	                usb_kill_urb(pxmitbuf->pxmit_urb);
	        }
		
		pxmitbuf++;
	}
	
	pxmitbuf = (struct xmit_buf*)pshare->pxmit_extbuf;

	for (i = 0; i < NR_XMIT_EXTBUFF; i++)
	{	
	        if(pxmitbuf->pxmit_urb)
	        {
	                usb_kill_urb(pxmitbuf->pxmit_urb);
	        }
		
		pxmitbuf++;
	}
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

u32 usb_submit_xmitbuf(struct rtl8192cd_priv *priv, struct xmit_buf *pxmitbuf, int timeout_ms)
{
	struct tx_desc *pdesc;
	u32 tx_len, i;
	
	BUG_ON(pxmitbuf->pkt_tail > pxmitbuf->pkt_end);
	
	pdesc = (struct tx_desc*) pxmitbuf->pkt_data;
	tx_len = (u32)(pxmitbuf->pkt_tail - pxmitbuf->pkt_data);
	
#ifndef CONFIG_USE_USB_BUFFER_ALLOC_TX
	if ((tx_len % GET_HAL_INTF_DATA(priv)->UsbBulkOutSize) == 0) {
		// remove pkt_offset
		u32 pkt_offset = pxmitbuf->pkt_offset * PACKET_OFFSET_SZ;
		u32 *src = (u32*)((u8*)pdesc + TXDESC_SIZE -4);
		u32 *dst = (u32*)((u8*)src + pkt_offset);
		for (i = 0; i < TXDESC_SIZE/4; ++i) {
			*dst-- = *src--;
		}
		
		tx_len -= pkt_offset;
		pxmitbuf->pkt_data += pkt_offset;
		pxmitbuf->pkt_offset = 0;
		
		pxmitbuf->txdesc_info[0].buf_ptr += pkt_offset;
		pxmitbuf->txdesc_info[0].buf_len -= pkt_offset;
		
		pdesc = (struct tx_desc*) pxmitbuf->pkt_data;
	} else
#endif
	if (pxmitbuf->pkt_offset) {
		pdesc->Dword1 |= set_desc(pxmitbuf->pkt_offset << TX_PktOffsetSHIFT);
	}
	
	if (pxmitbuf->agg_num > 1) {
		pdesc->Dword5 |= set_desc(pxmitbuf->agg_num << TX_UsbAggNumSHIFT);
	}
	
	rtl8192cd_usb_cal_txdesc_chksum(pdesc);
	
	return usb_write_port(priv, pxmitbuf->q_num, tx_len, (u8*)pxmitbuf, timeout_ms);
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

			assign_wlanseq(GET_HW(priv), txcfg->phdr, txcfg->pstat, GET_MIB(priv)
#ifdef CONFIG_RTK_MESH	// For broadcast data frame via mesh (ex:ARP requst)
				, txcfg->is_11s
#endif
				);
			pdesc->Dword3 |= set_desc((GetSequence(txcfg->phdr) & TX_SeqMask)  << TX_SeqSHIFT);
			pwlhdr = txcfg->phdr;
		}
		SetDuration(pwlhdr, 0);

		rtl8192cd_fill_fwinfo(priv, txcfg, pdesc, i);

#ifdef HW_ANT_SWITCH
		pdesc->Dword2 &= set_desc(~ (BIT(24)|BIT(25)));
		if(!(priv->pshare->rf_ft_var.CurAntenna & 0x80) && (txcfg->pstat)) {
			if ((txcfg->pstat->CurAntenna^priv->pshare->rf_ft_var.CurAntenna) & 1)
				pdesc->Dword2 |= set_desc(BIT(24)|BIT(25));
		}
#endif

		pdesc->Dword0 |= set_desc(TX_OWN | TX_FirstSeg | TX_LastSeg);
		pdesc->Dword0 |= set_desc(TXDESC_SIZE << TX_OffsetSHIFT); // tx_desc size

		if (IS_MCAST(GetAddr1Ptr((unsigned char *)txcfg->phdr)))
			pdesc->Dword0 |= set_desc(TX_BMC);

#ifdef CLIENT_MODE
		if (OPMODE & WIFI_STATION_STATE) {
			if (GetFrameSubType(txcfg->phdr) == WIFI_PSPOLL)
				pdesc->Dword1 |= set_desc(TX_NAVUSEHDR);

			if (priv->ps_state)
				SetPwrMgt(pwlhdr);
			else
				ClearPwrMgt(pwlhdr);
		}
#endif
		
		switch (q_num) {
		case HIGH_QUEUE:
			q_select = 0x11;// High Queue
			break;
		case MGNT_QUEUE:
			q_select = 0x12;
			break;
#if defined(DRVMAC_LB) && defined(WIFI_WMM)
		case BE_QUEUE:
			q_select = 0;
			break;
#endif
		default:
			// data packet
#ifdef RTL_MANUAL_EDCA
			if (priv->pmib->dot11QosEntry.ManualEDCA) {
				switch (q_num) {
				case VO_QUEUE:
					q_select = 6;
					break;
				case VI_QUEUE:
					q_select = 4;
					break;
				case BE_QUEUE:
					q_select = 0;
					break;
				default:
					q_select = 1;
					break;
				}
			}
			else
#endif
			q_select = ((struct sk_buff *)txcfg->pframe)->cb[1];
			break;
		}
		pdesc->Dword1 |= set_desc((q_select & TX_QSelMask)<< TX_QSelSHIFT);

		// Set RateID
		if (txcfg->pstat) {
			if (txcfg->pstat->aid != MANAGEMENT_AID)	{
			u8 ratid;

#ifdef CONFIG_RTL_92D_SUPPORT
			if (priv->pmib->dot11RFEntry.phyBandSelect & PHY_BAND_5G){
				if (txcfg->pstat->tx_ra_bitmap & 0xffff000) {
					if (priv->pshare->is_40m_bw)
						ratid = ARFR_2T_Band_A_40M;
					else
						ratid = ARFR_2T_Band_A_20M;
				} else {
					ratid = ARFR_G_ONLY;
				}
			} else 
#endif
			{			
				if (txcfg->pstat->tx_ra_bitmap & 0xff00000) {
					if (priv->pshare->is_40m_bw)
						ratid = ARFR_2T_40M;
					else
						ratid = ARFR_2T_20M;
				} else if (txcfg->pstat->tx_ra_bitmap & 0xff000) {
					if (priv->pshare->is_40m_bw)
						ratid = ARFR_1T_40M;
					else
						ratid = ARFR_1T_20M;
				} else if (txcfg->pstat->tx_ra_bitmap & 0xff0) {
					ratid = ARFR_BG_MIX;
				} else {
					ratid = ARFR_B_ONLY;
				}
			}
			pdesc->Dword1 |= set_desc((ratid & TX_RateIDMask) << TX_RateIDSHIFT);			
// Set MacID
#ifdef CONFIG_RTL_88E_SUPPORT
			if (GET_CHIP_VER(priv)==VERSION_8188E)
				pdesc->Dword1 |= set_desc(REMAP_AID(txcfg->pstat) & TXdesc_88E_MacIdMask);
			else
#endif
				pdesc->Dword1 |= set_desc(REMAP_AID(txcfg->pstat) & TX_MacIdMask);;

			}
		} else {
		
#ifdef CONFIG_RTL_92D_SUPPORT
			if (priv->pmib->dot11RFEntry.phyBandSelect & PHY_BAND_5G)
				pdesc->Dword1 |= set_desc((ARFR_Band_A_BMC &TX_RateIDMask)<<TX_RateIDSHIFT);
			else
#endif
				pdesc->Dword1 |= set_desc((ARFR_BMC &TX_RateIDMask)<<TX_RateIDSHIFT);
		}

		pdesc->Dword5 |= set_desc((0x1f & TX_DataRateFBLmtMask) << TX_DataRateFBLmtSHIFT);
		if (txcfg->fixed_rate)
			pdesc->Dword4 |= set_desc(TX_DisDataFB|TX_DisRtsFB|TX_UseRate);
#ifdef CONFIG_RTL_88E_SUPPORT
		else if (GET_CHIP_VER(priv)==VERSION_8188E)
			pdesc->Dword4 |= set_desc(TX_UseRate);
#endif

		if (txcfg->pstat && txcfg->pstat->cmn_info.ra_info.disable_ra)
			pdesc->Dword4 |= set_desc(TX_UseRate);

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
			pdesc->Dword2 |= set_desc(TX_MoreFrag);
		}
		else	// last seg, or the only seg (frg_num == 1)
		{
			fr_len = tx_len;
			ClearMFrag(pwlhdr);
		}
		SetFragNum((pwlhdr), i);
		
		// consider the diff between the first frag and the other frag in rtl8192cd_fill_fwinfo()
		if ((txcfg->need_ack) && (i != 0)) {
			pdesc->Dword4 &= set_desc(~(TX_HwRtsEn | TX_RtsEn | TX_CTS2Self));
		}
		
		hdr_len = txcfg->hdr_len + txcfg->iv;
		if ((i == 0) && (txcfg->fr_type == _SKB_FRAME_TYPE_))
			hdr_len += txcfg->llc;
		
		pkt_len = hdr_len + fr_len;
		if ((txcfg->privacy) && sw_encrypt)
			pkt_len += (txcfg->icv + txcfg->mic);

		pdesc->Dword0 |= set_desc(pkt_len << TX_PktSizeSHIFT);

//		if (!txcfg->need_ack && txcfg->privacy && sw_encrypt)
//			pdesc->Dword1 &= set_desc( ~(TX_SecTypeMask<< TX_SecTypeSHIFT));

		if ((txcfg->privacy) && !sw_encrypt) {
			// hw encrypt
			switch(txcfg->privacy) {
			case _WEP_104_PRIVACY_:
			case _WEP_40_PRIVACY_:
				wep_fill_iv(priv, pwlhdr, txcfg->hdr_len, keyid);
				pdesc->Dword1 |= set_desc(0x1 << TX_SecTypeSHIFT);
				break;

			case _TKIP_PRIVACY_:
				tkip_fill_encheader(priv, pwlhdr, txcfg->hdr_len, keyid);
				pdesc->Dword1 |= set_desc(0x1 << TX_SecTypeSHIFT);
				break;
#if defined(CONFIG_RTL_HW_WAPI_SUPPORT)
			case _WAPI_SMS4_:
				pdesc->Dword1 |= set_desc(0x2 << TX_SecTypeSHIFT);
				break;
#endif
			case _CCMP_PRIVACY_:
				//michal also hardware...
				aes_fill_encheader(priv, pwlhdr, txcfg->hdr_len, keyid);
				pdesc->Dword1 |= set_desc(0x3 << TX_SecTypeSHIFT);
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
							pbuf, fr_len, pmic,txcfg->isPMF);
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

		if (i == (txcfg->frg_num - 1))
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
	
	if (_SKB_FRAME_TYPE_ == txcfg->fr_type) {
		release_wlanllchdr_to_poll(priv, txcfg->phdr);
	} else {
		release_wlanhdr_to_poll(priv, txcfg->phdr);
	}
	txcfg->phdr = NULL;
	
#ifdef CONFIG_TX_RECYCLE_EARLY
	rtl8192cd_usb_tx_recycle(priv, pdescinfo);
#endif
	
#ifdef CONFIG_USB_TX_AGGREGATION
	if (pxmitbuf->ext_tag) {
		usb_submit_xmitbuf_async(priv, pxmitbuf);
	} else {
		if (pxmitbuf->agg_start_with == txcfg) {
			rtw_xmitbuf_aggregate(priv, pxmitbuf, txcfg->pstat, q_num);
			usb_submit_xmitbuf_async(priv, pxmitbuf);
		}
	}
#else
	usb_submit_xmitbuf_async(priv, pxmitbuf);
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

	pdesc->Dword3 = set_desc((GetSequence(txcfg->phdr) & TX_SeqMask) << TX_SeqSHIFT);

	if (pstat) {
		pdesc->Dword1 &= set_desc(~TX_MacIdMask);
		pdesc->Dword1 |= set_desc(REMAP_AID(pstat) & TX_MacIdMask);
	}

	//set Break
#ifdef CONFIG_RTL_88E_SUPPORT
	if (GET_CHIP_VER(priv) != VERSION_8188E)
#endif
	{
		if ((q_num >= BK_QUEUE) && (q_num <= VO_QUEUE)) {
			if (pstat != priv->pshare->CurPstat[q_num-BK_QUEUE]) {
				pdesc->Dword1 |= set_desc(TX_BK);
			priv->pshare->CurPstat[q_num-BK_QUEUE] = pstat;
		} else {
				pdesc->Dword1 &= set_desc(~TX_BK); // clear it
		}
	} else {
			pdesc->Dword1 |= set_desc(TX_BK);
	}		
	}
	
	pdesc->Dword0 = set_desc((get_desc(pdesc->Dword0) & 0xffff0000) | pkt_len);
	
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
	++pxmitbuf->agg_num;
	
	pxmitbuf->pkt_tail = write_ptr;
	
	release_wlanllchdr_to_poll(priv, txcfg->phdr);
	txcfg->phdr = NULL;
	
#ifdef CONFIG_TX_RECYCLE_EARLY
	rtl8192cd_usb_tx_recycle(priv, pdescinfo);
#endif
	
#ifdef CONFIG_USB_TX_AGGREGATION
	if (pxmitbuf->ext_tag) {
		usb_submit_xmitbuf_async(priv, pxmitbuf);
	} else {
		if (pxmitbuf->agg_start_with == txcfg) {
			rtw_xmitbuf_aggregate(priv, pxmitbuf, pstat, q_num);
			usb_submit_xmitbuf_async(priv, pxmitbuf);
		}
	}
#else
	usb_submit_xmitbuf_async(priv, pxmitbuf);
#endif
	
	txcfg->pxmitbuf = NULL;

	return 0;
}
#endif // TX_SHORTCUT

int signin_beacon_desc(struct rtl8192cd_priv *priv, unsigned int *beaconbuf, unsigned int frlen)
{
	struct tx_desc *pdesc;
	struct tx_desc_info	*pdescinfo;
	struct xmit_buf *pxmitbuf;
	u8 *mem_start, *pkt_start;
	u32 tx_len, pkt_offset;
	
	pdesc = &priv->tx_descB;
	
#ifdef DFS
	if (!priv->pmib->dot11DFSEntry.disable_DFS &&
		(timer_pending(&GET_ROOT(priv)->ch_avail_chk_timer))) {
		RTL_W16(PCIE_CTRL_REG, RTL_R16(PCIE_CTRL_REG)| (BCNQSTOP));
		return -1;
	}
#endif
	
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
	
	fill_bcn_desc(priv, pdesc, (void*)beaconbuf, frlen, 0);
	
	mem_start = pxmitbuf->pkt_data;
	
#ifndef CONFIG_USE_USB_BUFFER_ALLOC_TX
	pkt_start = mem_start + TXDESC_SIZE;
	
	tx_len = frlen + TXDESC_SIZE;
	if ((tx_len % GET_HAL_INTF_DATA(priv)->UsbBulkOutSize) == 0) {
		pkt_offset = pxmitbuf->pkt_offset * PACKET_OFFSET_SZ;
		tx_len += pkt_offset;
		pkt_start += pkt_offset;
	} else {
		pxmitbuf->pkt_offset = 0;
	}
	
#else
	pkt_offset = pxmitbuf->pkt_offset * PACKET_OFFSET_SZ;
	pkt_start = mem_start + TXDESC_SIZE + pkt_offset;
	tx_len = frlen + TXDESC_SIZE + pkt_offset;
#endif // !CONFIG_USE_USB_BUFFER_ALLOC_TX
	
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
	
	return usb_submit_xmitbuf_async(priv, pxmitbuf);
}

