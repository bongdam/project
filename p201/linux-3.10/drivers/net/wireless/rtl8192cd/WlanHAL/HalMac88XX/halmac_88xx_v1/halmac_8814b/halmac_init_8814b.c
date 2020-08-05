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

#include "halmac_init_8814b.h"
#include "halmac_8814b_cfg.h"
#if HALMAC_PCIE_SUPPORT
#include "halmac_pcie_8814b.h"
#endif
#if HALMAC_SDIO_SUPPORT
#include "halmac_sdio_8814b.h"
#endif
#if HALMAC_USB_SUPPORT
#include "halmac_usb_8814b.h"
#endif
#include "halmac_gpio_8814b.h"
#include "../halmac_common_88xx_v1.h"
#include "../halmac_init_88xx_v1.h"

#if HALMAC_8814B_SUPPORT

#define RSVD_PG_DRV_NUM			16
#define RSVD_PG_H2C_EXTRAINFO_NUM	24
#define RSVD_PG_H2C_STATICINFO_NUM	8
#define RSVD_PG_H2CQ_NUM		8
#define RSVD_PG_CPU_INSTRUCTION_NUM	0
#define RSVD_PG_FW_TXBUF_NUM		4
#define RSVD_PG_CSIBUF_NUM		0
#define RSVD_PG_DLLB_NUM		(TX_FIFO_SIZE_8814B / 3 >> \
					TX_PAGE_SIZE_SHIFT_88XX_V1)

#define MAC_TRX_ENABLE	(BIT_HCI_TXDMA_EN | BIT_HCI_RXDMA_EN | BIT_TXDMA_EN | \
			BIT_RXDMA_EN | BIT_PROTOCOL_EN | BIT_SCHEDULE_EN | \
			BIT_MACTXEN | BIT_MACRXEN | BIT_SHCUT_EN)

#define BLK_DESC_NUM   0x3

/*PCIE Channel Mapping*/
static struct halmac_ch_mapping HALMAC_CH_MAP_PCIE_8814B[] = {
	/* { mode, vo_map, vi_map, be_map, bk_map, mg_map, hi_map } */
	{HALMAC_TRX_MODE_NORMAL,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_1, HALMAC_DMA_CH_2, HALMAC_DMA_CH_3,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_TRXSHARE,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_1, HALMAC_DMA_CH_2, HALMAC_DMA_CH_3,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_WMM,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_1, HALMAC_DMA_CH_2, HALMAC_DMA_CH_3,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_P2P,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_1, HALMAC_DMA_CH_2, HALMAC_DMA_CH_3,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_LOOPBACK,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_1, HALMAC_DMA_CH_2, HALMAC_DMA_CH_3,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_DELAY_LOOPBACK,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_1, HALMAC_DMA_CH_2, HALMAC_DMA_CH_3,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
};

/*USB 3 Bulkout Channel Mapping*/
static struct halmac_ch_mapping HALMAC_CH_MAP_3BULKOUT_8814B[] = {
	/* { mode, vo_map, vi_map, be_map, bk_map, mg_map, hi_map } */
	{HALMAC_TRX_MODE_NORMAL,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_0,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_TRXSHARE,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_0,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_WMM,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_0,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_P2P,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_0,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_LOOPBACK,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_0,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_DELAY_LOOPBACK,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_0,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
};

/*USB 4 Bulkout Channel Mapping*/
static struct halmac_ch_mapping HALMAC_CH_MAP_4BULKOUT_8814B[] = {
	/* { mode, vo_map, vi_map, be_map, bk_map, mg_map, hi_map } */
	{HALMAC_TRX_MODE_NORMAL,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_4, HALMAC_DMA_CH_4,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_TRXSHARE,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_4, HALMAC_DMA_CH_4,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_WMM,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_4, HALMAC_DMA_CH_4,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_P2P,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_4, HALMAC_DMA_CH_4,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_LOOPBACK,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_4, HALMAC_DMA_CH_4,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_DELAY_LOOPBACK,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_0, HALMAC_DMA_CH_4, HALMAC_DMA_CH_4,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
};

/*USB 5 Bulkout Channel Mapping*/
static struct halmac_ch_mapping HALMAC_CH_MAP_5BULKOUT_8814B[] = {
	/* { mode, vo_map, vi_map, be_map, bk_map, mg_map, hi_map } */
	{HALMAC_TRX_MODE_NORMAL,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_4, HALMAC_DMA_CH_8, HALMAC_DMA_CH_8,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_TRXSHARE,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_4, HALMAC_DMA_CH_8, HALMAC_DMA_CH_8,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_WMM,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_4, HALMAC_DMA_CH_8, HALMAC_DMA_CH_8,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_P2P,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_4, HALMAC_DMA_CH_8, HALMAC_DMA_CH_8,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_LOOPBACK,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_4, HALMAC_DMA_CH_8, HALMAC_DMA_CH_8,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
	{HALMAC_TRX_MODE_DELAY_LOOPBACK,
	 HALMAC_DMA_CH_0, HALMAC_DMA_CH_4, HALMAC_DMA_CH_8, HALMAC_DMA_CH_8,
	 HALMAC_DMA_CH_MGQ, HALMAC_DMA_CH_HIGH},
};

/*PCIE Channel Page Number*/
static struct halmac_ch_pg_num HALMAC_CH_PG_NUM_PCIE_8814B[] = {
	/* { mode, channel 0~16, gap_num} */
	{HALMAC_TRX_MODE_NORMAL,
	 {16, 16, 16, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_TRXSHARE,
	 {16, 16, 16, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_WMM,
	 {16, 16, 16, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_P2P,
	 {16, 16, 16, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_LOOPBACK,
	 {16, 16, 16, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_DELAY_LOOPBACK,
	 {16, 16, 16, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
};

/*USB 3 Bulkout Page Number*/
static struct halmac_ch_pg_num HALMAC_CH_PG_NUM_3BULKOUT_8814B[] = {
	/* { mode, channel 0~16, gap_num} */
	{HALMAC_TRX_MODE_NORMAL,
	 {16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_TRXSHARE,
	 {16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_WMM,
	 {16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_P2P,
	 {16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_LOOPBACK,
	 {16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_DELAY_LOOPBACK,
	 {16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
};

/*USB 4 Bulkout Page Number*/
static struct halmac_ch_pg_num HALMAC_CH_PG_NUM_4BULKOUT_8814B[] = {
	/* { mode, channel 0~16, gap_num} */
	{HALMAC_TRX_MODE_NORMAL,
	 {16, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_TRXSHARE,
	 {16, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_WMM,
	 {16, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_P2P,
	 {16, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_LOOPBACK,
	 {16, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_DELAY_LOOPBACK,
	 {16, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
};

/*USB 5 Bulkout Page Number*/
static struct halmac_ch_pg_num HALMAC_CH_PG_NUM_5BULKOUT_8814B[] = {
	/* { mode, channel 0~16, gap_num} */
	{HALMAC_TRX_MODE_NORMAL,
	 {16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_TRXSHARE,
	 {16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_WMM,
	 {16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_P2P,
	 {16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_LOOPBACK,
	 {16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
	{HALMAC_TRX_MODE_DELAY_LOOPBACK,
	 {16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 0, 0, 8, 8, 0}, 1},
};

static enum halmac_ret_status
txdma_ch_mapping_8814b(struct halmac_adapter *adapter,
		       enum halmac_trx_mode mode);

static enum halmac_ret_status
priority_queue_cfg_8814b(struct halmac_adapter *adapter,
			 enum halmac_trx_mode mode);

static enum halmac_ret_status
set_trx_fifo_info_8814b(struct halmac_adapter *adapter,
			enum halmac_trx_mode mode);

enum halmac_ret_status
mount_api_8814b(struct halmac_adapter *adapter)
{
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	adapter->chip_id = HALMAC_CHIP_ID_8814B;
	adapter->hw_cfg_info.efuse_size = EFUSE_SIZE_8814B;
	adapter->hw_cfg_info.eeprom_size = EEPROM_SIZE_8814B;
	adapter->hw_cfg_info.bt_efuse_size = BT_EFUSE_SIZE_8814B;
	adapter->hw_cfg_info.prtct_efuse_size = PRTCT_EFUSE_SIZE_8814B;
	adapter->hw_cfg_info.cam_entry_num = SEC_CAM_NUM_8814B;
	adapter->hw_cfg_info.tx_fifo_size = TX_FIFO_SIZE_8814B;
	adapter->hw_cfg_info.rx_fifo_size = RX_FIFO_SIZE_8814B;
	adapter->hw_cfg_info.rx_desc_fifo_size = RXDESC_FIFO_SIZE_8814B;
	adapter->hw_cfg_info.usb_txagg_num = BLK_DESC_NUM;

	adapter->txff_alloc.rsvd_drv_pg_num = RSVD_PG_DRV_NUM;

	api->halmac_init_trx_cfg = init_trx_cfg_8814b;
	api->halmac_init_h2c = init_h2c_8814b;
	api->halmac_pinmux_get_func = pinmux_get_func_8814b;
	api->halmac_pinmux_set_func = pinmux_set_func_8814b;
	api->halmac_pinmux_free_func = pinmux_free_func_8814b;

	if (adapter->intf == HALMAC_INTERFACE_SDIO) {
#if HALMAC_SDIO_SUPPORT
		api->halmac_mac_power_switch = mac_pwr_switch_sdio_8814b;
		api->halmac_phy_cfg = phy_cfg_sdio_8814b;
		api->halmac_pcie_switch = pcie_switch_sdio_8814b;
		api->halmac_interface_integration_tuning = intf_tun_sdio_8814b;
#endif
	} else if (adapter->intf == HALMAC_INTERFACE_USB) {
#if HALMAC_USB_SUPPORT
		api->halmac_mac_power_switch = mac_pwr_switch_usb_8814b;
		api->halmac_phy_cfg = phy_cfg_usb_8814b;
		api->halmac_pcie_switch = pcie_switch_usb_8814b;
		api->halmac_interface_integration_tuning = intf_tun_usb_8814b;
#endif
	} else if (adapter->intf == HALMAC_INTERFACE_PCIE) {
#if HALMAC_PCIE_SUPPORT
		api->halmac_mac_power_switch = mac_pwr_switch_pcie_8814b;
		api->halmac_phy_cfg = phy_cfg_pcie_8814b;
		api->halmac_pcie_switch = pcie_switch_8814b;
		api->halmac_interface_integration_tuning = intf_tun_pcie_8814b;
		api->halmac_cfgspc_set_pcie = cfgspc_set_pcie_8814b;
#endif
	} else {
		PLTFM_MSG_ERR("[ERR]Undefined IC\n");
		return HALMAC_RET_CHIP_NOT_SUPPORT;
	}

	return HALMAC_RET_SUCCESS;
}

/**
 * init_trx_cfg_8814b() - config trx dma register
 * @adapter : the adapter of halmac
 * @mode : trx mode selection
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
init_trx_cfg_8814b(struct halmac_adapter *adapter, enum halmac_trx_mode mode)
{
	u8 value8;
	u16 value16;
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;
	enum halmac_ret_status status = HALMAC_RET_SUCCESS;
	u8 en_fwff;

	adapter->trx_mode = mode;

	PLTFM_MSG_TRACE("[TRACE]%s ===>\n", __func__);

	status = txdma_ch_mapping_8814b(adapter, mode);
	if (status != HALMAC_RET_SUCCESS) {
		PLTFM_MSG_TRACE("[ERR]queue mapping\n");
		return status;
	}

	en_fwff = HALMAC_REG_R8(REG_WMAC_FWPKT_CR) & BIT_FWEN;
	if (en_fwff) {
		HALMAC_REG_W8_CLR(REG_WMAC_FWPKT_CR, BIT_FWEN);
		if (fwff_is_empty_88xx_v1(adapter) != HALMAC_RET_SUCCESS)
			PLTFM_MSG_ERR("[ERR]fwff is not empty\n");
	}
	value8 = 0;
	HALMAC_REG_W8(REG_CR, value8);
	value16 = HALMAC_REG_R16(REG_FWFF_PKT_INFO);
	HALMAC_REG_W16(REG_FWFF_CTRL, value16);
	value16 = MAC_TRX_ENABLE;
	HALMAC_REG_W16(REG_CR, HALMAC_REG_R16(REG_CR) | value16);
	if (en_fwff)
		HALMAC_REG_W8_SET(REG_WMAC_FWPKT_CR, BIT_FWEN);
	HALMAC_REG_W32(REG_H2CQ_CSR, BIT(31));

	status = priority_queue_cfg_8814b(adapter, mode);
	if (status != HALMAC_RET_SUCCESS) {
		PLTFM_MSG_ERR("[ERR]priority queue cfg\n");
		return status;
	}

	status = init_h2c_8814b(adapter);
	if (status != HALMAC_RET_SUCCESS) {
		PLTFM_MSG_ERR("[ERR]init h2cq!\n");
		return status;
	}

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

static enum halmac_ret_status
txdma_ch_mapping_8814b(struct halmac_adapter *adapter,
		       enum halmac_trx_mode mode)
{
	struct halmac_ch_mapping *cur_map_sel = NULL;
	enum halmac_ret_status status;

	if (adapter->intf == HALMAC_INTERFACE_PCIE) {
		cur_map_sel = HALMAC_CH_MAP_PCIE_8814B;
	} else if (adapter->intf == HALMAC_INTERFACE_USB) {
		if (adapter->bulkout_num == 3) {
			cur_map_sel = HALMAC_CH_MAP_3BULKOUT_8814B;
		} else if (adapter->bulkout_num == 4) {
			cur_map_sel = HALMAC_CH_MAP_4BULKOUT_8814B;
		} else if (adapter->bulkout_num == 5) {
			cur_map_sel = HALMAC_CH_MAP_5BULKOUT_8814B;
		} else {
			PLTFM_MSG_ERR("[ERR]invalid intf\n");
			return HALMAC_RET_NOT_SUPPORT;
		}
	} else {
		return HALMAC_RET_ITF_INCORRECT;
	}

	status = ch_map_parser_88xx_v1(adapter, mode, cur_map_sel);
	if (status != HALMAC_RET_SUCCESS)
		return status;

	return HALMAC_RET_SUCCESS;
}

static enum halmac_ret_status
priority_queue_cfg_8814b(struct halmac_adapter *adapter,
			 enum halmac_trx_mode mode)
{
	u8 transfer_mode = 0;
	u8 value8;
	u32 cnt;
	enum halmac_ret_status status;
	struct halmac_ch_pg_num *cur_pg_num = NULL;
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	status = set_trx_fifo_info_8814b(adapter, mode);
	if (status != HALMAC_RET_SUCCESS) {
		PLTFM_MSG_ERR("[ERR]set trx fifo!!\n");
		return status;
	}

	if (adapter->intf == HALMAC_INTERFACE_PCIE) {
		cur_pg_num = HALMAC_CH_PG_NUM_PCIE_8814B;
	} else if (adapter->intf == HALMAC_INTERFACE_USB) {
		if (adapter->bulkout_num == 3)
			cur_pg_num = HALMAC_CH_PG_NUM_3BULKOUT_8814B;
		else if (adapter->bulkout_num == 4)
			cur_pg_num = HALMAC_CH_PG_NUM_4BULKOUT_8814B;
		else
			cur_pg_num = HALMAC_CH_PG_NUM_5BULKOUT_8814B;
	} else {
		return HALMAC_RET_ITF_INCORRECT;
	}

	status = set_pg_num_88xx_v1(adapter, mode, cur_pg_num);
	if (status != HALMAC_RET_SUCCESS)
		return status;

	halmac_init_bcnq_88xx_v1(adapter, adapter->txff_alloc.rsvd_boundary);

	HALMAC_REG_W8_SET(REG_FWHW_TXQ_CTRL + 2, BIT(4));

	HALMAC_REG_W16(REG_TXBDNY, adapter->txff_alloc.rsvd_boundary);
	HALMAC_REG_W32(REG_RXFF_BNDY,
		       adapter->hw_cfg_info.rx_fifo_size -
		       C2H_PKT_BUF_88XX_V1 - 1);

	if (adapter->intf == HALMAC_INTERFACE_USB) {
		value8 = HALMAC_REG_R8(REG_AUTO_LLT_V1);
		value8 &= ~(BIT_MASK_BLK_DESC_NUM << BIT_SHIFT_BLK_DESC_NUM);
		value8 |= (BLK_DESC_NUM << BIT_SHIFT_BLK_DESC_NUM);
		HALMAC_REG_W8(REG_AUTO_LLT_V1, value8);

		HALMAC_REG_W8(REG_AUTO_LLT_V1 + 3, BLK_DESC_NUM);
		HALMAC_REG_W8_SET(REG_TXDMA_OFFSET_CHK + 1, BIT(1));
	}

	HALMAC_REG_W8_SET(REG_AUTO_LLT_V1, BIT_AUTO_INIT_LLT_V1);
	cnt = 1000;
	while (HALMAC_REG_R8(REG_AUTO_LLT_V1) & BIT_AUTO_INIT_LLT_V1) {
		PLTFM_DELAY_US(1);
		cnt--;
		if (cnt == 0)
			return HALMAC_RET_INIT_LLT_FAIL;
	}

	if (mode == HALMAC_TRX_MODE_DELAY_LOOPBACK) {
		transfer_mode = HALMAC_TRNSFER_LOOPBACK_DELAY;
		HALMAC_REG_W16(REG_WMAC_LBK_BUF_HD_V1,
			       adapter->txff_alloc.rsvd_boundary);
	} else if (mode == HALMAC_TRX_MODE_LOOPBACK) {
		transfer_mode = HALMAC_TRNSFER_LOOPBACK_DIRECT;
	} else {
		transfer_mode = HALMAC_TRNSFER_NORMAL;
	}

	adapter->hw_cfg_info.trx_mode = transfer_mode;
	HALMAC_REG_W8(REG_CR + 3, (u8)transfer_mode);

	return HALMAC_RET_SUCCESS;
}

static enum halmac_ret_status
set_trx_fifo_info_8814b(struct halmac_adapter *adapter,
			enum halmac_trx_mode mode)
{
	u16 cur_pg_addr;
	u32 txff_size = TX_FIFO_SIZE_8814B;
	u32 rxff_size = RX_FIFO_SIZE_8814B;
	struct halmac_txff_allocation *info = &adapter->txff_alloc;

	if (info->rx_fifo_exp_mode == HALMAC_RX_FIFO_EXPANDING_MODE_1_BLOCK) {
		txff_size = TX_FIFO_SIZE_RX_EXPAND_1BLK_8814B;
		rxff_size = RX_FIFO_SIZE_RX_EXPAND_1BLK_8814B;
	} else if (info->rx_fifo_exp_mode ==
		   HALMAC_RX_FIFO_EXPANDING_MODE_2_BLOCK) {
		txff_size = TX_FIFO_SIZE_RX_EXPAND_2BLK_8814B;
		rxff_size = RX_FIFO_SIZE_RX_EXPAND_2BLK_8814B;
	}

	if (info->la_mode != HALMAC_LA_MODE_DISABLE) {
		txff_size = TX_FIFO_SIZE_LA_8814B;
		rxff_size = RX_FIFO_SIZE_8814B;
	}

	adapter->hw_cfg_info.tx_fifo_size = txff_size;
	adapter->hw_cfg_info.rx_fifo_size = rxff_size;
	info->tx_fifo_pg_num = (u16)(txff_size >> TX_PAGE_SIZE_SHIFT_88XX_V1);

	info->rsvd_pg_num = info->rsvd_drv_pg_num +
					RSVD_PG_H2C_EXTRAINFO_NUM +
					RSVD_PG_H2C_STATICINFO_NUM +
					RSVD_PG_H2CQ_NUM +
					RSVD_PG_CPU_INSTRUCTION_NUM +
					RSVD_PG_FW_TXBUF_NUM +
					RSVD_PG_CSIBUF_NUM;

	if (mode == HALMAC_TRX_MODE_DELAY_LOOPBACK)
		info->rsvd_pg_num += RSVD_PG_DLLB_NUM;

	if (info->rsvd_pg_num > info->tx_fifo_pg_num)
		return HALMAC_RET_CFG_TXFIFO_PAGE_FAIL;

	info->acq_pg_num = info->tx_fifo_pg_num - info->rsvd_pg_num;
	info->rsvd_boundary = info->tx_fifo_pg_num - info->rsvd_pg_num;

	cur_pg_addr = info->tx_fifo_pg_num;
	cur_pg_addr -= RSVD_PG_CSIBUF_NUM;
	info->rsvd_csibuf_addr = cur_pg_addr;
	cur_pg_addr -= RSVD_PG_FW_TXBUF_NUM;
	info->rsvd_fw_txbuf_addr = cur_pg_addr;
	cur_pg_addr -= RSVD_PG_CPU_INSTRUCTION_NUM;
	info->rsvd_cpu_instr_addr = cur_pg_addr;
	cur_pg_addr -= RSVD_PG_H2CQ_NUM;
	info->rsvd_h2cq_addr = cur_pg_addr;
	cur_pg_addr -= RSVD_PG_H2C_STATICINFO_NUM;
	info->rsvd_h2c_sta_info_addr = cur_pg_addr;
	cur_pg_addr -= RSVD_PG_H2C_EXTRAINFO_NUM;
	info->rsvd_h2c_info_addr = cur_pg_addr;
	cur_pg_addr -= info->rsvd_drv_pg_num;
	info->rsvd_drv_addr = cur_pg_addr;

	if (mode == HALMAC_TRX_MODE_DELAY_LOOPBACK)
		info->rsvd_drv_addr -= RSVD_PG_DLLB_NUM;

	if (info->rsvd_boundary != info->rsvd_drv_addr)
		return HALMAC_RET_CFG_TXFIFO_PAGE_FAIL;

	return HALMAC_RET_SUCCESS;
}

/**
 * init_h2c_8814b() - config h2c packet buffer
 * @adapter : the adapter of halmac
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
init_h2c_8814b(struct halmac_adapter *adapter)
{
	u8 value8;
	u32 value32;
	u32 h2cq_addr;
	u32 h2cq_size;
	struct halmac_txff_allocation *txff_info = &adapter->txff_alloc;
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	h2cq_addr = txff_info->rsvd_h2cq_addr << TX_PAGE_SIZE_SHIFT_88XX_V1;
	h2cq_size = RSVD_PG_H2CQ_NUM << TX_PAGE_SIZE_SHIFT_88XX_V1;

	value32 = HALMAC_REG_R32(REG_H2C_HEAD);
	value32 = (value32 & 0xFFFC0000) | h2cq_addr;
	HALMAC_REG_W32(REG_H2C_HEAD, value32);

	value32 = HALMAC_REG_R32(REG_H2C_READ_ADDR);
	value32 = (value32 & 0xFFFC0000) | h2cq_addr;
	HALMAC_REG_W32(REG_H2C_READ_ADDR, value32);

	value32 = HALMAC_REG_R32(REG_H2C_TAIL);
	value32 &= 0xFFFC0000;
	value32 |= (h2cq_addr + h2cq_size);
	HALMAC_REG_W32(REG_H2C_TAIL, value32);

	value8 = HALMAC_REG_R8(REG_H2C_INFO);
	value8 = (u8)((value8 & 0xFC) | 0x01);
	HALMAC_REG_W8(REG_H2C_INFO, value8);

	value8 = HALMAC_REG_R8(REG_H2C_INFO);
	value8 = (u8)((value8 & 0xFB) | 0x04);
	HALMAC_REG_W8(REG_H2C_INFO, value8);

	value8 = HALMAC_REG_R8(REG_TXDMA_OFFSET_CHK + 1);
	value8 = (u8)((value8 & 0x7f) | 0x80);
	HALMAC_REG_W8(REG_TXDMA_OFFSET_CHK + 1, value8);

	adapter->h2c_info.buf_size = h2cq_size;
	get_h2c_buf_free_space_88xx_v1(adapter);

	if (adapter->h2c_info.buf_size != adapter->h2c_info.buf_fs) {
		PLTFM_MSG_ERR("[ERR]get h2c free space error!\n");
		return HALMAC_RET_GET_H2C_SPACE_ERR;
	}

	PLTFM_MSG_TRACE("[TRACE]h2c fs : %d\n", adapter->h2c_info.buf_fs);

	return HALMAC_RET_SUCCESS;
}

#endif /* HALMAC_8814B_SUPPORT */
