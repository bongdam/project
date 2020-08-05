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

#include "halmac_sdio_88xx_v1.h"
#include "halmac_88xx_v1_cfg.h"

#if (HALMAC_88XX_V1_SUPPORT && HALMAC_SDIO_SUPPORT)

/**
 * init_sdio_cfg_88xx_v1() - init SDIO
 * @adapter : the adapter of halmac
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
init_sdio_cfg_88xx_v1(struct halmac_adapter *adapter)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * deinit_sdio_cfg_88xx_v1() - deinit SDIO
 * @adapter : the adapter of halmac
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
deinit_sdio_cfg_88xx_v1(struct halmac_adapter *adapter)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * cfg_sdio_rx_agg_88xx_v1() - config rx aggregation
 * @adapter : the adapter of halmac
 * @halmac_rx_agg_mode
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
cfg_sdio_rx_agg_88xx_v1(struct halmac_adapter *adapter,
			struct halmac_rxagg_cfg *cfg)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * reg_r8_sdio_88xx_v1() - read 1byte register
 * @adapter : the adapter of halmac
 * @offset : register offset
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
u8
reg_r8_sdio_88xx_v1(struct halmac_adapter *adapter, u32 offset)
{
	return 0xFF;
}

/**
 * reg_w8_sdio_88xx_v1() - write 1byte register
 * @adapter : the adapter of halmac
 * @offset : register offset
 * @value : register value
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
reg_w8_sdio_88xx_v1(struct halmac_adapter *adapter, u32 offset, u8 value)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * reg_r16_sdio_88xx_v1() - read 2byte register
 * @adapter : the adapter of halmac
 * @offset : register offset
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
u16
reg_r16_sdio_88xx_v1(struct halmac_adapter *adapter, u32 offset)
{
	return 0xFFFF;
}

/**
 * reg_w16_sdio_88xx_v1() - write 2byte register
 * @adapter : the adapter of halmac
 * @offset : register offset
 * @value : register value
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
reg_w16_sdio_88xx_v1(struct halmac_adapter *adapter, u32 offset, u16 value)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * reg_r32_sdio_88xx_v1() - read 4byte register
 * @adapter : the adapter of halmac
 * @offset : register offset
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
u32
reg_r32_sdio_88xx_v1(struct halmac_adapter *adapter, u32 offset)
{
	return 0xFFFFFFFF;
}

/**
 * reg_r32_sdio_88xx_v1() - write 4byte register
 * @adapter : the adapter of halmac
 * @offset : register offset
 * @value : register value
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
reg_w32_sdio_88xx_v1(struct halmac_adapter *adapter, u32 offset, u32 value)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * sdio_reg_rn_88xx_v1() - read n byte register
 * @adapter : the adapter of halmac
 * @offset : register offset
 * @size : register value size
 * @value : register value
 * Author : Soar
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
sdio_reg_rn_88xx_v1(struct halmac_adapter *adapter, u32 offset, u32 size,
		    u8 *value)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * get_sdio_tx_addr_88xx_v1() - get CMD53 addr for the TX packet
 * @adapter : the adapter of halmac
 * @buf : tx packet, include txdesc
 * @size : tx packet size
 * @pcmd53_addr : cmd53 addr value
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
get_sdio_tx_addr_88xx_v1(struct halmac_adapter *adapter, u8 *buf, u32 size,
			 u32 *cmd53_addr)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * cfg_txagg_sdio_align_88xx_v1() -config sdio bus tx agg alignment
 * @adapter : the adapter of halmac
 * @enable : function enable(1)/disable(0)
 * @align_size : sdio bus tx agg alignment size (2^n, n = 3~11)
 * Author : Soar Tu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
cfg_txagg_sdio_align_88xx_v1(struct halmac_adapter *adapter, u8 enable,
			     u16 align_size)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * tx_allowed_sdio_88xx_v1() - check tx status
 * @adapter : the adapter of halmac
 * @pbuf : tx packet, include txdesc
 * @size : tx packet size, include txdesc
 * Author : Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
tx_allowed_sdio_88xx_v1(struct halmac_adapter *adapter, u8 *buf, u32 size)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * sdio_indirect_reg_r32_88xx_v1() - read MAC reg by SDIO reg
 * @adapter : the adapter of halmac
 * @offset : register offset
 * Author : Soar
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
u32
sdio_indirect_reg_r32_88xx_v1(struct halmac_adapter *adapter, u32 offset)
{
	return 0xFFFFFFFF;
}

/**
 * set_sdio_bulkout_num_88xx_v1() - inform bulk-out num
 * @adapter : the adapter of halmac
 * @bulkout_num : usb bulk-out number
 * Author : KaiYuan Chang
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
set_sdio_bulkout_num_88xx_v1(struct halmac_adapter *adapter, u8 num)
{
	return HALMAC_RET_NOT_SUPPORT;
}

/**
 * get_sdio_bulkout_id_88xx_v1() - get bulk out id for the TX packet
 * @adapter : the adapter of halmac
 * @buf : tx packet, include txdesc
 * @size : tx packet size
 * @bulkout_id : usb bulk-out id
 * Author : KaiYuan Chang
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
get_sdio_bulkout_id_88xx_v1(struct halmac_adapter *adapter, u8 *buf, u32 size,
			    u8 *id)
{
	return HALMAC_RET_NOT_SUPPORT;
}

/**
 * sdio_cmd53_4byte_88xx_v1() - cmd53 only for 4byte len register IO
 * @adapter : the adapter of halmac
 * @enable : 1->CMD53 only use in 4byte reg, 0 : No limitation
 * Author : Ivan Lin/KaiYuan Chang
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
sdio_cmd53_4byte_88xx_v1(struct halmac_adapter *adapter,
			 enum halmac_sdio_cmd53_4byte_mode mode)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * sdio_hw_info_88xx_v1() - info sdio hw info
 * @adapter : the adapter of halmac
 * @HALMAC_SDIO_CMD53_4BYTE_MODE :
 * clock_speed : sdio bus clock. Unit -> MHz
 * spec_ver : sdio spec version
 * Author : Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
sdio_hw_info_88xx_v1(struct halmac_adapter *adapter,
		     struct halmac_sdio_hw_info *info)
{
	return HALMAC_RET_SUCCESS;
}

enum halmac_ret_status
en_ref_autok_sdio_88xx_v1(struct halmac_adapter *adapter, u8 en)
{
	return HALMAC_RET_NOT_SUPPORT;
}
#endif /* HALMAC_88XX_V1_SUPPORT */
