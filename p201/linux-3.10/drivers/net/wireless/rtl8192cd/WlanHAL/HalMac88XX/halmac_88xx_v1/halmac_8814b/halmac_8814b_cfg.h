/******************************************************************************
 *
 * Copyright(c) 2016 - 2019 Realtek Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 ******************************************************************************/

#ifndef _HALMAC_8814B_CFG_H_
#define _HALMAC_8814B_CFG_H_

#include "../../halmac_hw_cfg.h"
#include "../halmac_88xx_v1_cfg.h"

#if HALMAC_8814B_SUPPORT

#define TX_FIFO_SIZE_8814B	393216
#define RX_FIFO_SIZE_8814B	32768
#define TRX_SHARE_SIZE_8814B	32768
#define RXDESC_FIFO_SIZE_8814B	4096

#define TX_FIFO_SIZE_LA_8814B	(TX_FIFO_SIZE_8814B >> 1)
#define TX_FIFO_SIZE_RX_EXPAND_1BLK_8814B	\
		(TX_FIFO_SIZE_8814B - TRX_SHARE_SIZE_8814B)
#define RX_FIFO_SIZE_RX_EXPAND_1BLK_8814B	\
		(RX_FIFO_SIZE_8814B + TRX_SHARE_SIZE_8814B)
#define TX_FIFO_SIZE_RX_EXPAND_2BLK_8814B	\
		(TX_FIFO_SIZE_8814B - (2 * TRX_SHARE_SIZE_8814B))
#define RX_FIFO_SIZE_RX_EXPAND_2BLK_8814B	\
		(RX_FIFO_SIZE_8814B + (2 * TRX_SHARE_SIZE_8814B))

#define EFUSE_SIZE_8814B		1024
#define EEPROM_SIZE_8814B		1024
#define BT_EFUSE_SIZE_8814B		0
#define PRTCT_EFUSE_SIZE_8814B	96

#define SEC_CAM_NUM_8814B		64

#endif /* HALMAC_8814B_SUPPORT */

#endif
