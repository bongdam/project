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

#ifndef _HALMAC_SDIO_88XX_V1_H_
#define _HALMAC_SDIO_88XX_V1_H_

#include "../halmac_api.h"

#if (HALMAC_88XX_V1_SUPPORT && HALMAC_SDIO_SUPPORT)

enum halmac_ret_status
init_sdio_cfg_88xx_v1(struct halmac_adapter *adapter);

enum halmac_ret_status
deinit_sdio_cfg_88xx_v1(struct halmac_adapter *adapter);

enum halmac_ret_status
cfg_sdio_rx_agg_88xx_v1(struct halmac_adapter *adapter,
			struct halmac_rxagg_cfg *cfg);

u8
reg_r8_sdio_88xx_v1(struct halmac_adapter *adapter, u32 offset);

enum halmac_ret_status
reg_w8_sdio_88xx_v1(struct halmac_adapter *adapter, u32 offset, u8 value);

u16
reg_r16_sdio_88xx_v1(struct halmac_adapter *adapter, u32 offset);

enum halmac_ret_status
reg_w16_sdio_88xx_v1(struct halmac_adapter *adapter, u32 offset, u16 value);

u32
reg_r32_sdio_88xx_v1(struct halmac_adapter *adapter, u32 offset);

enum halmac_ret_status
reg_w32_sdio_88xx_v1(struct halmac_adapter *adapter, u32 offset, u32 value);

enum halmac_ret_status
get_sdio_tx_addr_88xx_v1(struct halmac_adapter *adapter, u8 *buf, u32 size,
			 u32 *cmd53_addr);

enum halmac_ret_status
cfg_txagg_sdio_align_88xx_v1(struct halmac_adapter *adapter, u8 enable,
			     u16 align_size);

enum halmac_ret_status
tx_allowed_sdio_88xx_v1(struct halmac_adapter *adapter, u8 *buf, u32 size);

u32
sdio_indirect_reg_r32_88xx_v1(struct halmac_adapter *adapter, u32 offset);

enum halmac_ret_status
sdio_reg_rn_88xx_v1(struct halmac_adapter *adapter, u32 offset, u32 size,
		    u8 *value);

enum halmac_ret_status
set_sdio_bulkout_num_88xx_v1(struct halmac_adapter *adapter, u8 num);

enum halmac_ret_status
get_sdio_bulkout_id_88xx_v1(struct halmac_adapter *adapter, u8 *buf, u32 size,
			    u8 *id);

enum halmac_ret_status
sdio_cmd53_4byte_88xx_v1(struct halmac_adapter *adapter,
			 enum halmac_sdio_cmd53_4byte_mode mode);

enum halmac_ret_status
sdio_hw_info_88xx_v1(struct halmac_adapter *adapter,
		     struct halmac_sdio_hw_info *info);

enum halmac_ret_status
en_ref_autok_sdio_88xx_v1(struct halmac_adapter *adapter, u8 en);

#endif /* HALMAC_88XX_V1_SUPPORT */

#endif/* _HALMAC_SDIO_88XX_V1_H_ */
