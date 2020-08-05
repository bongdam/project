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

#ifndef _HALMAC_88XX_V1_CFG_H_
#define _HALMAC_88XX_V1_CFG_H_

#include "../halmac_api.h"

#if HALMAC_88XX_V1_SUPPORT

#define TX_PAGE_SIZE_88XX_V1		128
#define TX_PAGE_SIZE_SHIFT_88XX_V1	7 /* 128 = 2^7 */
#define TX_ALIGN_SIZE_88XX_V1		8
#define RX_BUF_FW_88XX_V1		8192
#define RX_BUF_PHY_88XX_V1		16384

#define TX_DESC_IE_MAX_88XX_V1		5
#define TX_DESC_BODY_SIZE_88XX_V1	16

#if HALMAC_PLATFORM_TESTPROGRAM
#define TX_DESC_SIZE_88XX_V1		(TX_DESC_BODY_SIZE_88XX_V1 + \
					TX_DESC_IE_MAX_88XX_V1 * 8)
#else
#define TX_DESC_SIZE_88XX_V1		(TX_DESC_BODY_SIZE_88XX_V1 + \
					(TX_DESC_IE_MAX_88XX_V1 - 1) * 8)
#endif

#define TX_DESC_BUF_SIZE_88XX_V1	48
#define RX_DESC_SIZE_88XX_V1		24

#define H2C_PKT_SIZE_88XX_V1		32 /* Only support 32 byte packet now */
#define H2C_PKT_HDR_SIZE_88XX_V1	8
#define C2H_DATA_OFFSET_88XX_V1		10
#define C2H_PKT_BUF_88XX_V1		256

/* HW memory address */
#define OCPBASE_TXBUF_88XX_V1		0x18780000
#define OCPBASE_DMEM_88XX_V1		0x00200000

#define WLAN_FW_IRAM_MAX_SIZE_88XX_V1	262144
#define WLAN_FW_DRAM_MAX_SIZE_88XX_V1	65536
#define WLAN_FW_ERAM_MAX_SIZE_88XX_V1	65536
#define WLAN_FW_MAX_SIZE_88XX_V1	(WLAN_FW_IRAM_MAX_SIZE_88XX_V1 + \
	WLAN_FW_DRAM_MAX_SIZE_88XX_V1 + WLAN_FW_ERAM_MAX_SIZE_88XX_V1)

#endif /* HALMAC_88XX_V1_SUPPORT */

#endif
