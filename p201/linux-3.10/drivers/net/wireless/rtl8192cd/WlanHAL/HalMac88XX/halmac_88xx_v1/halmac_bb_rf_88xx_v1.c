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

#include "halmac_bb_rf_88xx_v1.h"
#include "halmac_88xx_v1_cfg.h"
#include "halmac_common_88xx_v1.h"
#include "halmac_init_88xx_v1.h"

#if HALMAC_88XX_V1_SUPPORT

/**
 * start_iqk_88xx_v1() -trigger FW IQK
 * @adapter : the adapter of halmac
 * @param : IQK parameter
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
start_iqk_88xx_v1(struct halmac_adapter *adapter,
		  struct halmac_iqk_para *param)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * start_dpk_88xx_v1() -trigger FW DPK
 * @adapter : the adapter of halmac
 * Author : Yong-Ching Lin/KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
start_dpk_88xx_v1(struct halmac_adapter *adapter)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * ctrl_pwr_tracking_88xx_v1() -trigger FW power tracking
 * @adapter : the adapter of halmac
 * @opt : power tracking option
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
ctrl_pwr_tracking_88xx_v1(struct halmac_adapter *adapter,
			  struct halmac_pwr_tracking_option *opt)
{
	return HALMAC_RET_SUCCESS;
}

enum halmac_ret_status
get_iqk_status_88xx_v1(struct halmac_adapter *adapter,
		       enum halmac_cmd_process_status *proc_status)
{
	return HALMAC_RET_SUCCESS;
}

enum halmac_ret_status
get_pwr_trk_status_88xx_v1(struct halmac_adapter *adapter,
			   enum halmac_cmd_process_status *proc_status)
{
	return HALMAC_RET_SUCCESS;
}

enum halmac_ret_status
get_psd_status_88xx_v1(struct halmac_adapter *adapter,
		       enum halmac_cmd_process_status *proc_status, u8 *data,
		       u32 *size)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * psd_88xx_v1() - trigger fw psd
 * @adapter : the adapter of halmac
 * @start_psd : start PSD
 * @end_psd : end PSD
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
psd_88xx_v1(struct halmac_adapter *adapter, u16 start_psd, u16 end_psd)
{
	return HALMAC_RET_SUCCESS;
}

enum halmac_ret_status
get_h2c_ack_iqk_88xx_v1(struct halmac_adapter *adapter, u8 *buf, u32 size)
{
	return HALMAC_RET_SUCCESS;
}

enum halmac_ret_status
get_h2c_ack_pwr_trk_88xx_v1(struct halmac_adapter *adapter, u8 *buf, u32 size)
{
	return HALMAC_RET_SUCCESS;
}

enum halmac_ret_status
get_psd_data_88xx_v1(struct halmac_adapter *adapter, u8 *buf, u32 size)
{
	u8 seg_id;
	u8 seg_size;
	u8 seq_num;
	u16 total_size;
	enum halmac_cmd_process_status proc_status;
	struct halmac_psd_state *state = &adapter->halmac_state.psd_state;

	seq_num = (u8)PSD_DATA_GET_H2C_SEQ(buf);
	PLTFM_MSG_TRACE("[TRACE]seq num : h2c->%d c2h->%d\n",
			state->seq_num, seq_num);
	if (seq_num != state->seq_num) {
		PLTFM_MSG_ERR("[ERR]seq num mismatch : h2c->%d c2h->%d\n",
			      state->seq_num, seq_num);
		return HALMAC_RET_SUCCESS;
	}

	if (state->proc_status != HALMAC_CMD_PROCESS_SENDING) {
		PLTFM_MSG_ERR("[ERR]not cmd sending\n");
		return HALMAC_RET_SUCCESS;
	}

	total_size = (u16)PSD_DATA_GET_TOTAL_SIZE(buf);
	seg_id = (u8)PSD_DATA_GET_SEGMENT_ID(buf);
	seg_size = (u8)PSD_DATA_GET_SEGMENT_SIZE(buf);
	state->data_size = total_size;

	if (!state->data)
		state->data = (u8 *)PLTFM_MALLOC(state->data_size);

	if (seg_id == 0)
		state->seg_size = seg_size;

	PLTFM_MEMCPY(state->data + seg_id * state->seg_size,
		     buf + C2H_DATA_OFFSET_88XX_V1, seg_size);

	if (PSD_DATA_GET_END_SEGMENT(buf) == 0)
		return HALMAC_RET_SUCCESS;

	proc_status = HALMAC_CMD_PROCESS_DONE;
	state->proc_status = proc_status;

	PLTFM_EVENT_SIG(HALMAC_FEATURE_PSD, proc_status, state->data,
			state->data_size);

	return HALMAC_RET_SUCCESS;
}
#endif /* HALMAC_88XX_V1_SUPPORT */
