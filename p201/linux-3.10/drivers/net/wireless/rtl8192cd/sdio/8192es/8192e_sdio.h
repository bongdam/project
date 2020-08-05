/*
 *  Header files defines some SDIO inline routines
 *
 *  Copyright (c) 2017 Realtek Semiconductor Corp.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#ifndef _8192E_SDIO_H_
#define _8192E_SDIO_H_

#ifdef __KERNEL__
#include <asm/bitops.h>
#endif

#include "8192cd.h"
#include "sdio/sdio_io.h"
#include "8192e_sdio_hw.h"
#include "8192e_sdio_recv.h"
#include "8192e_sdio_cmd.h"
#include "hal_intf_xmit.h"

typedef __kernel_size_t		SIZE_T;	
typedef __kernel_ssize_t	SSIZE_T;

#define SIZE_PTR	SIZE_T
#define SSIZE_PTR	SSIZE_T

#define MAX_HW_TX_QUEUE			8
#define MAX_STA_TX_SERV_QUEUE		5	// must <= MAX_HW_TX_QUEUE

enum SDIO_TX_INT_STATUS {
	SDIO_TX_INT_SETUP_TH = 0,
	SDIO_TX_INT_WORKING,
};

enum {
	ENQUEUE_TO_HEAD = 0,
	ENQUEUE_TO_TAIL =1,
};

extern const u32 reg_freepage_thres[SDIO_TX_FREE_PG_QUEUE];

struct hal_data_8192e
{
	//In /Out Pipe information
	u8 Queue2Pipe[8];//for out pipe mapping
	// Add for dual MAC  0--Mac0 1--Mac1
	u32 interfaceIndex;

	u8 OutEpQueueSel;
	u8 OutEpNumber;
	
	// Auto FSM to Turn On, include clock, isolation, power control for MAC only
	u8 bMacPwrCtrlOn;
	
	//
	// SDIO ISR Related
	//
	u32 sdio_himr;
	u32 sdio_hisr;
	unsigned long SdioTxIntStatus;
	volatile u8 SdioTxIntQIdx;

	//
	// SDIO Tx FIFO related.
	//
	// HIQ, MID, LOW, PUB free pages; padapter->xmitpriv.free_txpg
	u8 SdioTxFIFOFreePage[SDIO_TX_FREE_PG_QUEUE];
	u8 SdioTxFIFOFreePage_prev[SDIO_TX_FREE_PG_QUEUE];
	u8 SdioTxOQTFreeSpace[2];	// MAX_TXOQT_TYPE
	
	int WaitSdioTxOQT;
	u8 WaitSdioTxOQTSpace;
	u8 WaitSdioTxOQTQNum;

	//
	// SDIO Rx FIFO related.
	//
	u8 SdioRxFIFOCnt;
	u16 SdioRxFIFOSize;
};

typedef struct hal_data_8192e HAL_INTF_DATA_TYPE, *PHAL_INTF_DATA_TYPE;

void InitSdioInterrupt(struct rtl8192cd_priv *priv);
void EnableSdioInterrupt(struct rtl8192cd_priv *priv);
void DisableSdioInterrupt(struct rtl8192cd_priv *priv);

int sdio_dvobj_init(struct rtl8192cd_priv *priv);
void sdio_dvobj_deinit(struct rtl8192cd_priv *priv);

int sdio_alloc_irq(struct rtl8192cd_priv *priv);
int sdio_free_irq(struct rtl8192cd_priv *priv);

void rtw_dev_unload(struct rtl8192cd_priv *priv);

u8 rtw_init_drv_sw(struct rtl8192cd_priv *priv);
u8 rtw_free_drv_sw(struct rtl8192cd_priv *priv);

void rtl8192es_interface_configure(struct rtl8192cd_priv *priv);
void _initSdioAggregationSetting(struct rtl8192cd_priv *priv);

s32 sdio_query_txbuf_status(struct rtl8192cd_priv *priv);
#ifdef CONFIG_SDIO_TX_IN_INTERRUPT
s32 sdio_query_txbuf_status_locksafe(struct rtl8192cd_priv *priv);
#endif
u8 sdio_query_txoqt_status(struct rtl8192cd_priv *priv);

#endif // _8192E_SDIO_H_

