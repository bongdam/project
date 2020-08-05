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

#include "halmac_sdio_8814b.h"
#include "halmac_pwr_seq_8814b.h"
#include "../halmac_init_88xx_v1.h"
#include "../halmac_common_88xx_v1.h"

#if (HALMAC_8814B_SUPPORT && HALMAC_SDIO_SUPPORT)

/**
 * mac_pwr_switch_sdio_8814b() - change mac power
 * @adapter
 * @pwr
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 */
enum halmac_ret_status
mac_pwr_switch_sdio_8814b(struct halmac_adapter *adapter,
			  enum halmac_mac_power pwr)
{
	return HALMAC_RET_NOT_SUPPORT;
}

/**
 * phy_cfg_sdio_8814b() - phy config
 * @adapter
 * Author : KaiYuan Chang
 * Return : enum halmac_ret_status
 */
enum halmac_ret_status
phy_cfg_sdio_8814b(struct halmac_adapter *adapter,
		   enum halmac_intf_phy_platform pltfm)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * halmac_pcie_switch_8814b() - change mac power
 * @adapter
 * @cfg
 * Author : KaiYuan Chang
 * Return : enum halmac_ret_status
 */
enum halmac_ret_status
pcie_switch_sdio_8814b(struct halmac_adapter *adapter,
		       enum halmac_pcie_cfg cfg)
{
	return HALMAC_RET_NOT_SUPPORT;
}

/**
 * intf_tun_sdio_8814b() - sdio interface fine tuning
 * @adapter
 * Author : Ivan
 * Return : enum halmac_ret_status
 */
enum halmac_ret_status
intf_tun_sdio_8814b(struct halmac_adapter *adapter)
{
	return HALMAC_RET_NOT_SUPPORT;
}
#endif /* HALMAC_8814B_SUPPORT */
