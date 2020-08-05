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

#ifndef _HALMAC_INIT_88XX_V1_H_
#define _HALMAC_INIT_88XX_V1_H_

#include "../halmac_api.h"

#if HALMAC_88XX_V1_SUPPORT

enum halmac_ret_status
register_api_88xx_v1(struct halmac_adapter *adapter,
		     struct halmac_api_registry *registry);

void
init_adapter_param_88xx_v1(struct halmac_adapter *adapter);

void
init_adapter_dynamic_param_88xx_v1(struct halmac_adapter *adapter);

enum halmac_ret_status
mount_api_88xx_v1(struct halmac_adapter *adapter);

enum halmac_ret_status
pre_init_system_cfg_88xx_v1(struct halmac_adapter *adapter);

enum halmac_ret_status
init_system_cfg_88xx_v1(struct halmac_adapter *adapter);

enum halmac_ret_status
init_edca_cfg_88xx_v1(struct halmac_adapter *adapter);

enum halmac_ret_status
init_wmac_cfg_88xx_v1(struct halmac_adapter *adapter);

enum halmac_ret_status
init_mac_cfg_88xx_v1(struct halmac_adapter *adapter, enum halmac_trx_mode mode);

enum halmac_ret_status
init_protocol_cfg_88xx_v1(struct halmac_adapter *adapter);

enum halmac_ret_status
reset_ofld_feature_88xx_v1(struct halmac_adapter *adapter,
			   enum halmac_feature_id feature_id);

enum halmac_ret_status
verify_platform_api_88xx_v1(struct halmac_adapter *adapter);

void
tx_desc_chksum_88xx_v1(struct halmac_adapter *adapter, u8 enable);

enum halmac_ret_status
ch_map_parser_88xx_v1(struct halmac_adapter *adapter, enum halmac_trx_mode mode,
		      struct halmac_ch_mapping *map);

void
init_ofld_feature_state_machine_88xx_v1(struct halmac_adapter *adapter);

enum halmac_ret_status
set_pg_num_88xx_v1(struct halmac_adapter *adapter, enum halmac_trx_mode mode,
		   struct halmac_ch_pg_num *tbl);

void
halmac_init_bcnq_88xx_v1(struct halmac_adapter *adapter, u16 head_pg);

enum halmac_ret_status
fwff_is_empty_88xx_v1(struct halmac_adapter *adapter);

#endif /* HALMAC_88XX_V1_SUPPORT */

#endif/* _HALMAC_INIT_88XX_V1_H_ */
