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

#include "halmac_init_88xx_v1.h"
#include "halmac_88xx_v1_cfg.h"
#include "halmac_fw_88xx_v1.h"
#include "halmac_common_88xx_v1.h"
#include "halmac_cfg_wmac_88xx_v1.h"
#include "halmac_efuse_88xx_v1.h"
#include "halmac_mimo_88xx_v1.h"
#include "halmac_bb_rf_88xx_v1.h"
#if HALMAC_SDIO_SUPPORT
#include "halmac_sdio_88xx_v1.h"
#endif
#if HALMAC_USB_SUPPORT
#include "halmac_usb_88xx_v1.h"
#endif
#if HALMAC_PCIE_SUPPORT
#include "halmac_pcie_88xx_v1.h"
#endif
#include "halmac_gpio_88xx_v1.h"
#include "halmac_flash_88xx_v1.h"

#if HALMAC_8814B_SUPPORT
#include "halmac_8814b/halmac_init_8814b.h"
#endif

#if HALMAC_PLATFORM_TESTPROGRAM
#include "halmisc_api_88xx_v1.h"
#endif

#if HALMAC_88XX_V1_SUPPORT

#define PLTFM_INFO_MALLOC_MAX_SIZE	16384
#define PLTFM_INFO_RSVD_PG_SIZE		16384
#define DLFW_PKT_MAX_SIZE	8192 /* need multiple of 2 */

#define SYS_FUNC_EN		0xD8
#define ANAPAR_PWR_LDO		0x3F
#define ANAPAR_PWR_XTAL		0x03
#define ANAPAR_XTAL0_BYTE1_CFG	0x03
#define ANAPAR_XTAL0_BYTE2_CFG	0x81
#define ANAPAR_XTAL0_BYTE3_CFG	0x88
#define ANAPAR_XTAL1_CFG	0x74
#define ANAPAR_MAC1_CFG_A_CUT	0x60041F04
#define ANAPAR_MAC1_CFG		0x60001C04
#define WLAN_SLOT_TIME		0x09
#define WLAN_PIFS_TIME		0x19
#define WLAN_SIFS_CCK_CONT_TX	0xA
#define WLAN_SIFS_OFDM_CONT_TX	0xE
#define WLAN_SIFS_CCK_TRX	0x10
#define WLAN_SIFS_OFDM_TRX	0x10
#define WLAN_VO_TXOP_LIMIT	0x186 /* unit : 32us */
#define WLAN_VI_TXOP_LIMIT	0x3BC /* unit : 32us */
#define WLAN_RDG_NAV		0x05
#define WLAN_TXOP_NAV		0x1B
#define WLAN_CCK_RX_TSF		0x30
#define WLAN_OFDM_RX_TSF	0x30
#define WLAN_TBTT_PROHIBIT	0x04 /* unit : 32us */
#define WLAN_TBTT_HOLD_TIME	0x064 /* unit : 32us */
#define WLAN_RESP_TXRATE	0x84
#define WLAN_ACK_TO_CCK		0x6A
#define WLAN_ACK_TO		0x21
#define WLAN_RX_FILTER0		0x0FFFFFFF
#define WLAN_RX_FILTER2		0xFFFF
#define WLAN_RCR_CFG		0xE418020E
#define WLAN_RXPKT_MAX_SZ	12288
#define WLAN_RXPKT_MAX_SZ_512	(WLAN_RXPKT_MAX_SZ >> 9)

#define WLAN_TX_FUNC_CFG1		0x30
#define WLAN_TX_FUNC_CFG2		0x30
#define WLAN_MAC_OPT_NORM_FUNC1		0x98
#define WLAN_MAC_OPT_LB_FUNC1		0x80
#define WLAN_MAC_OPT_FUNC2		0xB1810041
#define WLAN_TXQ_RPT_EN		0x3F

#define WLAN_SIFS_CCK_DUR_TUNE	0x0A
#define WLAN_SIFS_OFDM_DUR_TUNE	0x10
#define WLAN_SIFS_CCK_CTX	0x0A
#define WLAN_SIFS_CCK_IRX	0x0A
#define WLAN_SIFS_OFDM_CTX	0x0E
#define WLAN_SIFS_OFDM_IRX	0x0E

#define WLAN_AMPDU_MAX_TIME		0x70
#define WLAN_RTS_LEN_TH			0xFF
#define WLAN_RTS_TX_TIME_TH		0x08
#define WLAN_MAX_AGG_PKT_LIMIT		0x3F
#define WLAN_RTS_MAX_AGG_PKT_LIMIT	0x20
#define WLAN_PRE_TXCNT_TIME_TH		0x2D0
#define WALN_FAST_EDCA_VO_TH		0x06
#define WLAN_FAST_EDCA_VI_TH		0x06
#define WLAN_FAST_EDCA_BE_TH		0x06
#define WLAN_FAST_EDCA_BK_TH		0x06
#define WLAN_BAR_RETRY_LIMIT		0x01
#define WLAN_RA_TRY_RATE_AGG_LIMIT	0x08
#define WLAN_DATA_RATE_FB_CNT_1_4	0x01000000
#define WLAN_DATA_RATE_FB_CNT_5_8	0x08070504
#define WLAN_RTS_RATE_FB_CNT_5_8	0x08070504
#define WLAN_DATA_RATE_FB_RATE0		0xFE01F010
#define WLAN_DATA_RATE_FB_RATE0_H	0x40000000

#define WLAN_SIFS_CFG	(WLAN_SIFS_CCK_CONT_TX | \
			(WLAN_SIFS_OFDM_CONT_TX << BIT_SHIFT_SIFS_OFDM_CTX) | \
			(WLAN_SIFS_CCK_TRX << BIT_SHIFT_SIFS_CCK_TRX) | \
			(WLAN_SIFS_OFDM_TRX << BIT_SHIFT_SIFS_OFDM_TRX))

#define WLAN_TBTT_TIME	(WLAN_TBTT_PROHIBIT | \
			(WLAN_TBTT_HOLD_TIME << BIT_SHIFT_TBTT_HOLD_TIME))

#define WLAN_NAV_CFG		(WLAN_RDG_NAV | (WLAN_TXOP_NAV << 16))
#define WLAN_RX_TSF_CFG		(WLAN_CCK_RX_TSF | (WLAN_OFDM_RX_TSF) << 8)

#define WLAN_SIFS_DUR_TUNE	(WLAN_SIFS_CCK_DUR_TUNE | \
				(WLAN_SIFS_OFDM_DUR_TUNE << 8))

static void
init_state_machine_88xx_v1(struct halmac_adapter *adapter);

static enum halmac_ret_status
verify_io_88xx_v1(struct halmac_adapter *adapter);

static enum halmac_ret_status
verify_send_rsvd_page_88xx_v1(struct halmac_adapter *adapter);

static void
init_txq_ctrl_88xx_v1(struct halmac_adapter *adapter);

static void
init_sifs_ctrl_88xx_v1(struct halmac_adapter *adapter);

static void
init_rate_fallback_ctrl_88xx_v1(struct halmac_adapter *adapter);

static void
init_analog_ip_cfg_88xx_v1(struct halmac_adapter *adapter);

void
init_adapter_param_88xx_v1(struct halmac_adapter *adapter)
{
	adapter->api_registry.rx_exp_en = 1;
	adapter->api_registry.la_mode_en = 1;
	adapter->api_registry.cfg_drv_rsvd_pg_en = 1;
	adapter->api_registry.sdio_cmd53_4byte_en = 1;

	adapter->efuse_map = (u8 *)NULL;
	adapter->efuse_map_valid = 0;
	adapter->efuse_end = 0;

	adapter->dlfw_pkt_size = DLFW_PKT_MAX_SIZE;
	adapter->pltfm_info.malloc_size = PLTFM_INFO_MALLOC_MAX_SIZE;
	adapter->pltfm_info.rsvd_pg_size = PLTFM_INFO_RSVD_PG_SIZE;

	adapter->cfg_param_info.buf = NULL;
	adapter->cfg_param_info.buf_wptr = NULL;
	adapter->cfg_param_info.num = 0;
	adapter->cfg_param_info.full_fifo_mode = 0;
	adapter->cfg_param_info.buf_size = 0;
	adapter->cfg_param_info.avl_buf_size = 0;
	adapter->cfg_param_info.offset_accum = 0;
	adapter->cfg_param_info.value_accum = 0;

	adapter->ch_sw_info.buf = NULL;
	adapter->ch_sw_info.buf_wptr = NULL;
	adapter->ch_sw_info.extra_info_en = 0;
	adapter->ch_sw_info.buf_size = 0;
	adapter->ch_sw_info.avl_buf_size = 0;
	adapter->ch_sw_info.total_size = 0;
	adapter->ch_sw_info.ch_num = 0;

	adapter->drv_info_size = 0;
	adapter->tx_desc_transfer = 1;

	adapter->txff_alloc.tx_fifo_pg_num = 0;
	adapter->txff_alloc.acq_pg_num = 0;
	adapter->txff_alloc.rsvd_boundary = 0;
	adapter->txff_alloc.rsvd_drv_addr = 0;
	adapter->txff_alloc.rsvd_h2c_info_addr = 0;
	adapter->txff_alloc.rsvd_h2cq_addr = 0;
	adapter->txff_alloc.rsvd_cpu_instr_addr = 0;
	adapter->txff_alloc.rsvd_fw_txbuf_addr = 0;
	adapter->txff_alloc.pub_queue_pg_num = 0;
	adapter->txff_alloc.high_queue_pg_num = 0;
	adapter->txff_alloc.low_queue_pg_num = 0;
	adapter->txff_alloc.normal_queue_pg_num = 0;
	adapter->txff_alloc.extra_queue_pg_num = 0;

	adapter->txff_alloc.la_mode = HALMAC_LA_MODE_DISABLE;
	adapter->txff_alloc.rx_fifo_exp_mode =
					HALMAC_RX_FIFO_EXPANDING_MODE_DISABLE;

	adapter->hw_cfg_info.chk_security_keyid = 0;
	adapter->hw_cfg_info.page_size = TX_PAGE_SIZE_88XX_V1;
	adapter->hw_cfg_info.tx_align_size = TX_ALIGN_SIZE_88XX_V1;
	adapter->hw_cfg_info.txdesc_size = TX_DESC_SIZE_88XX_V1;
	adapter->hw_cfg_info.rxdesc_size = RX_DESC_SIZE_88XX_V1;
	adapter->hw_cfg_info.txdesc_ie_max_num = TX_DESC_IE_MAX_88XX_V1;
	adapter->hw_cfg_info.txdesc_body_size = TX_DESC_BODY_SIZE_88XX_V1;
	adapter->sdio_cmd53_4byte = HALMAC_SDIO_CMD53_4BYTE_MODE_DISABLE;

	adapter->watcher.get_watcher.sdio_rn_not_align = 0;

	adapter->pinmux_info.wl_led = 0;
	adapter->pinmux_info.sdio_int = 0;
	adapter->pinmux_info.sw_io_0 = 0;
	adapter->pinmux_info.sw_io_1 = 0;
	adapter->pinmux_info.sw_io_2 = 0;
	adapter->pinmux_info.sw_io_3 = 0;
	adapter->pinmux_info.sw_io_4 = 0;
	adapter->pinmux_info.sw_io_5 = 0;
	adapter->pinmux_info.sw_io_6 = 0;
	adapter->pinmux_info.sw_io_7 = 0;
	adapter->pinmux_info.sw_io_8 = 0;
	adapter->pinmux_info.sw_io_9 = 0;
	adapter->pinmux_info.sw_io_10 = 0;
	adapter->pinmux_info.sw_io_11 = 0;
	adapter->pinmux_info.sw_io_12 = 0;
	adapter->pinmux_info.sw_io_13 = 0;
	adapter->pinmux_info.sw_io_14 = 0;
	adapter->pinmux_info.sw_io_15 = 0;

	adapter->pcie_refautok_en = 1;
	adapter->pwr_off_flow_flag = 0;

	adapter->rx_ignore_info.hdr_chk_mask = 1;
	adapter->rx_ignore_info.fcs_chk_mask = 1;
	adapter->rx_ignore_info.hdr_chk_en = 0;
	adapter->rx_ignore_info.fcs_chk_en = 0;
	adapter->rx_ignore_info.cck_rst_en = 0;
	adapter->rx_ignore_info.fcs_chk_thr = HALMAC_PSF_FCS_CHK_THR_28;

	init_adapter_dynamic_param_88xx_v1(adapter);
	init_state_machine_88xx_v1(adapter);
}

void
init_adapter_dynamic_param_88xx_v1(struct halmac_adapter *adapter)
{
	adapter->h2c_info.seq_num = 0;
	adapter->h2c_info.buf_fs = 0;
}

enum halmac_ret_status
mount_api_88xx_v1(struct halmac_adapter *adapter)
{
	struct halmac_api *api = NULL;

	adapter->halmac_api =
		(struct halmac_api *)PLTFM_MALLOC(sizeof(struct halmac_api));
	if (!adapter->halmac_api)
		return HALMAC_RET_MALLOC_FAIL;

	api = (struct halmac_api *)adapter->halmac_api;

	api->halmac_read_efuse = NULL;
	api->halmac_write_efuse = NULL;

	/* Mount function pointer */
	api->halmac_register_api = register_api_88xx_v1;
	api->halmac_download_firmware = download_firmware_88xx_v1;
	api->halmac_free_download_firmware = free_download_firmware_88xx_v1;
	api->halmac_reset_wifi_fw = reset_wifi_fw_88xx_v1;
	api->halmac_get_fw_version = get_fw_version_88xx_v1;
	api->halmac_cfg_mac_addr = cfg_mac_addr_88xx_v1;
	api->halmac_cfg_bssid = cfg_bssid_88xx_v1;
	api->halmac_cfg_transmitter_addr = cfg_transmitter_addr_88xx_v1;
	api->halmac_cfg_net_type = cfg_net_type_88xx_v1;
	api->halmac_cfg_tsf_rst = cfg_tsf_rst_88xx_v1;
	api->halmac_cfg_bcn_space = cfg_bcn_space_88xx_v1;
	api->halmac_rw_bcn_ctrl = rw_bcn_ctrl_88xx_v1;
	api->halmac_cfg_multicast_addr = cfg_multicast_addr_88xx_v1;
	api->halmac_pre_init_system_cfg = pre_init_system_cfg_88xx_v1;
	api->halmac_init_system_cfg = init_system_cfg_88xx_v1;
	api->halmac_init_edca_cfg = init_edca_cfg_88xx_v1;
	api->halmac_init_protocol_cfg = init_protocol_cfg_88xx_v1;
	api->halmac_cfg_operation_mode = cfg_operation_mode_88xx_v1;
	api->halmac_cfg_ch_bw = cfg_ch_bw_88xx_v1;
	api->halmac_cfg_bw = cfg_bw_88xx_v1;
	api->halmac_init_wmac_cfg = init_wmac_cfg_88xx_v1;
	api->halmac_init_mac_cfg = init_mac_cfg_88xx_v1;
	api->halmac_dump_efuse_map = dump_efuse_map_88xx_v1;
	api->halmac_dump_efuse_map_bt = dump_efuse_map_bt_88xx_v1;
	api->halmac_write_efuse_bt = write_efuse_bt_88xx_v1;
	api->halmac_read_efuse_bt = read_efuse_bt_88xx_v1;
	api->halmac_cfg_efuse_auto_check = cfg_efuse_auto_check_88xx_v1;
	api->halmac_dump_logical_efuse_map = dump_log_efuse_map_88xx_v1;
	api->halmac_dump_logical_efuse_mask = dump_log_efuse_mask_88xx_v1;
	api->halmac_pg_efuse_by_map = pg_efuse_by_map_88xx_v1;
	api->halmac_mask_logical_efuse = mask_log_efuse_88xx_v1;
	api->halmac_get_efuse_size = get_efuse_size_88xx_v1;
	api->halmac_get_efuse_available_size = get_efuse_available_size_88xx_v1;
	api->halmac_get_c2h_info = get_c2h_info_88xx_v1;

	api->halmac_get_logical_efuse_size = get_log_efuse_size_88xx_v1;

	api->halmac_write_logical_efuse = write_log_efuse_88xx_v1;
	api->halmac_read_logical_efuse = read_logical_efuse_88xx_v1;

	api->halmac_write_wifi_phy_efuse = write_wifi_phy_efuse_88xx_v1;
	api->halmac_read_wifi_phy_efuse = read_wifi_phy_efuse_88xx_v1;

	api->halmac_ofld_func_cfg = ofld_func_cfg_88xx_v1;
	api->halmac_h2c_lb = h2c_lb_88xx_v1;
	api->halmac_debug = mac_debug_88xx_v1;
	api->halmac_cfg_parameter = cfg_parameter_88xx_v1;
	api->halmac_update_datapack = update_datapack_88xx_v1;
	api->halmac_run_datapack = run_datapack_88xx_v1;
	api->halmac_cfg_drv_info = cfg_drv_info_88xx_v1;
	api->halmac_send_bt_coex = send_bt_coex_88xx_v1;
	api->halmac_verify_platform_api = verify_platform_api_88xx_v1;
	api->halmac_update_packet = update_packet_88xx_v1;
	api->halmac_bcn_ie_filter = bcn_ie_filter_88xx_v1;
	api->halmac_cfg_txbf = cfg_txbf_88xx_v1;
	api->halmac_cfg_mumimo = cfg_mumimo_88xx_v1;
	api->halmac_cfg_sounding = cfg_sounding_88xx_v1;
	api->halmac_del_sounding = del_sounding_88xx_v1;
	api->halmac_su_bfer_entry_init = su_bfer_entry_init_88xx_v1;
	api->halmac_su_bfee_entry_init = su_bfee_entry_init_88xx_v1;
	api->halmac_mu_bfer_entry_init = mu_bfer_entry_init_88xx_v1;
	api->halmac_mu_bfee_entry_init = mu_bfee_entry_init_88xx_v1;
	api->halmac_su_bfer_entry_del = su_bfer_entry_del_88xx_v1;
	api->halmac_su_bfee_entry_del = su_bfee_entry_del_88xx_v1;
	api->halmac_mu_bfer_entry_del = mu_bfer_entry_del_88xx_v1;
	api->halmac_mu_bfee_entry_del = mu_bfee_entry_del_88xx_v1;

	api->halmac_add_ch_info = add_ch_info_88xx_v1;
	api->halmac_add_extra_ch_info = add_extra_ch_info_88xx_v1;
	api->halmac_ctrl_ch_switch = ctrl_ch_switch_88xx_v1;
	api->halmac_p2pps = p2pps_88xx_v1;
	api->halmac_clear_ch_info = clear_ch_info_88xx_v1;
	api->halmac_send_general_info = send_general_info_88xx_v1;
	api->halmac_send_scan_packet = send_scan_packet_88xx_v1;
	api->halmac_drop_scan_packet = drop_scan_packet_88xx_v1;

	api->halmac_start_iqk = start_iqk_88xx_v1;
	api->halmac_start_dpk = start_dpk_88xx_v1;
	api->halmac_ctrl_pwr_tracking = ctrl_pwr_tracking_88xx_v1;
	api->halmac_psd = psd_88xx_v1;
	api->halmac_cfg_la_mode = cfg_la_mode_88xx_v1;
	api->halmac_cfg_rxff_expand_mode = cfg_rxfifo_expand_mode_88xx_v1;

	api->halmac_config_security = config_security_88xx_v1;
	api->halmac_get_used_cam_entry_num = get_used_cam_entry_num_88xx_v1;
	api->halmac_read_cam_entry = read_cam_entry_88xx_v1;
	api->halmac_write_cam = write_cam_88xx_v1;
	api->halmac_clear_cam_entry = clear_cam_entry_88xx_v1;

	api->halmac_get_hw_value = get_hw_value_88xx_v1;
	api->halmac_set_hw_value = set_hw_value_88xx_v1;
	api->halmac_get_watcher = get_watcher_88xx_v1;

	api->halmac_cfg_drv_rsvd_pg_num = cfg_drv_rsvd_pg_num_88xx_v1;
	api->halmac_get_chip_version = get_version_88xx_v1;

	api->halmac_query_status = query_status_88xx_v1;
	api->halmac_reset_feature = reset_ofld_feature_88xx_v1;
	api->halmac_check_fw_status = check_fw_status_88xx_v1;
	api->halmac_dump_fw_dmem = dump_fw_dmem_88xx_v1;
	api->halmac_cfg_max_dl_size = cfg_max_dl_size_88xx_v1;

	api->halmac_dump_fifo = dump_fifo_88xx_v1;
	api->halmac_get_fifo_size = get_fifo_size_88xx_v1;

	api->halmac_chk_txdesc = chk_txdesc_88xx_v1;
	api->halmac_dl_drv_rsvd_page = dl_drv_rsvd_page_88xx_v1;
	api->halmac_cfg_csi_rate = cfg_csi_rate_88xx_v1;

	api->halmac_fill_txdesc_checksum = fill_txdesc_check_sum_88xx_v1;

	api->halmac_download_flash = download_flash_88xx_v1;
	api->halmac_txfifo_is_empty = txfifo_is_empty_88xx_v1;
	api->halmac_read_flash = read_flash_88xx_v1;
	api->halmac_erase_flash = erase_flash_88xx_v1;
	api->halmac_check_flash = check_flash_88xx_v1;
	api->halmac_cfg_edca_para = cfg_edca_para_88xx_v1;
	api->halmac_pinmux_wl_led_mode = pinmux_wl_led_mode_88xx_v1;
	api->halmac_pinmux_wl_led_sw_ctrl = pinmux_wl_led_sw_ctrl_88xx_v1;
	api->halmac_pinmux_sdio_int_polarity = pinmux_sdio_int_polarity_88xx_v1;
	api->halmac_pinmux_gpio_mode = pinmux_gpio_mode_88xx_v1;
	api->halmac_pinmux_gpio_output = pinmux_gpio_output_88xx_v1;
	api->halmac_pinmux_pin_status = pinmux_pin_status_88xx_v1;

	api->halmac_rx_cut_amsdu_cfg = rx_cut_amsdu_cfg_88xx_v1;
	api->halmac_fw_snding = fw_snding_88xx_v1;
	api->halmac_get_mac_addr = get_mac_addr_88xx_v1;
	api->halmac_init_low_pwr = init_low_pwr_88xx_v1;

	api->halmac_enter_cpu_sleep_mode = enter_cpu_sleep_mode_88xx_v1;
	api->halmac_get_cpu_mode = get_cpu_mode_88xx_v1;
	api->halmac_drv_fwctrl = drv_fwctrl_88xx_v1;

	if (adapter->intf == HALMAC_INTERFACE_SDIO) {
#if HALMAC_SDIO_SUPPORT
		api->halmac_init_sdio_cfg = init_sdio_cfg_88xx_v1;
		api->halmac_deinit_sdio_cfg = deinit_sdio_cfg_88xx_v1;
		api->halmac_cfg_rx_aggregation = cfg_sdio_rx_agg_88xx_v1;
		api->halmac_init_interface_cfg = init_sdio_cfg_88xx_v1;
		api->halmac_deinit_interface_cfg = deinit_sdio_cfg_88xx_v1;
		api->halmac_cfg_tx_agg_align = cfg_txagg_sdio_align_88xx_v1;
		api->halmac_tx_allowed_sdio = tx_allowed_sdio_88xx_v1;
		api->halmac_set_bulkout_num = set_sdio_bulkout_num_88xx_v1;
		api->halmac_get_sdio_tx_addr = get_sdio_tx_addr_88xx_v1;
		api->halmac_get_usb_bulkout_id = get_sdio_bulkout_id_88xx_v1;
		api->halmac_reg_read_8 = reg_r8_sdio_88xx_v1;
		api->halmac_reg_write_8 = reg_w8_sdio_88xx_v1;
		api->halmac_reg_read_16 = reg_r16_sdio_88xx_v1;
		api->halmac_reg_write_16 = reg_w16_sdio_88xx_v1;
		api->halmac_reg_read_32 = reg_r32_sdio_88xx_v1;
		api->halmac_reg_write_32 = reg_w32_sdio_88xx_v1;
		api->halmac_reg_read_indirect_32 =
						sdio_indirect_reg_r32_88xx_v1;
		api->halmac_reg_sdio_cmd53_read_n = sdio_reg_rn_88xx_v1;
		api->halmac_sdio_cmd53_4byte = sdio_cmd53_4byte_88xx_v1;
		api->halmac_sdio_hw_info = sdio_hw_info_88xx_v1;
		api->halmac_en_ref_autok_pcie = en_ref_autok_sdio_88xx_v1;

#endif
	} else if (adapter->intf == HALMAC_INTERFACE_USB) {
#if HALMAC_USB_SUPPORT
		api->halmac_init_usb_cfg = init_usb_cfg_88xx_v1;
		api->halmac_deinit_usb_cfg = deinit_usb_cfg_88xx_v1;
		api->halmac_cfg_rx_aggregation = cfg_usb_rx_agg_88xx_v1;
		api->halmac_init_interface_cfg = init_usb_cfg_88xx_v1;
		api->halmac_deinit_interface_cfg = deinit_usb_cfg_88xx_v1;
		api->halmac_cfg_tx_agg_align = cfg_txagg_usb_align_88xx_v1;
		api->halmac_tx_allowed_sdio = tx_allowed_usb_88xx_v1;
		api->halmac_set_bulkout_num = set_usb_bulkout_num_88xx_v1;
		api->halmac_get_sdio_tx_addr = get_usb_tx_addr_88xx_v1;
		api->halmac_get_usb_bulkout_id = get_usb_bulkout_id_88xx_v1;
		api->halmac_reg_read_8 = reg_r8_usb_88xx_v1;
		api->halmac_reg_write_8 = reg_w8_usb_88xx_v1;
		api->halmac_reg_read_16 = reg_r16_usb_88xx_v1;
		api->halmac_reg_write_16 = reg_w16_usb_88xx_v1;
		api->halmac_reg_read_32 = reg_r32_usb_88xx_v1;
		api->halmac_reg_write_32 = reg_w32_usb_88xx_v1;
		api->halmac_reg_read_indirect_32 = usb_indirect_reg_r32_88xx_v1;
		api->halmac_reg_sdio_cmd53_read_n = usb_reg_rn_88xx_v1;
		api->halmac_en_ref_autok_pcie = en_ref_autok_usb_88xx_v1;
#endif
	} else if (adapter->intf == HALMAC_INTERFACE_PCIE) {
#if HALMAC_PCIE_SUPPORT
		api->halmac_init_pcie_cfg = init_pcie_cfg_88xx_v1;
		api->halmac_deinit_pcie_cfg = deinit_pcie_cfg_88xx_v1;
		api->halmac_cfg_rx_aggregation = cfg_pcie_rx_agg_88xx_v1;
		api->halmac_init_interface_cfg = init_pcie_cfg_88xx_v1;
		api->halmac_deinit_interface_cfg = deinit_pcie_cfg_88xx_v1;
		api->halmac_cfg_tx_agg_align = cfg_txagg_pcie_align_88xx_v1;
		api->halmac_tx_allowed_sdio = tx_allowed_pcie_88xx_v1;
		api->halmac_set_bulkout_num = set_pcie_bulkout_num_88xx_v1;
		api->halmac_get_sdio_tx_addr = get_pcie_tx_addr_88xx_v1;
		api->halmac_get_usb_bulkout_id = get_pcie_bulkout_id_88xx_v1;
		api->halmac_reg_read_8 = reg_r8_pcie_88xx_v1;
		api->halmac_reg_write_8 = reg_w8_pcie_88xx_v1;
		api->halmac_reg_read_16 = reg_r16_pcie_88xx_v1;
		api->halmac_reg_write_16 = reg_w16_pcie_88xx_v1;
		api->halmac_reg_read_32 = reg_r32_pcie_88xx_v1;
		api->halmac_reg_write_32 = reg_w32_pcie_88xx_v1;
		api->halmac_reg_read_indirect_32 =
						pcie_indirect_reg_r32_88xx_v1;
		api->halmac_reg_sdio_cmd53_read_n = pcie_reg_rn_88xx_v1;
		api->halmac_en_ref_autok_pcie = en_ref_autok_pcie_88xx_v1;
#endif
	} else {
		PLTFM_MSG_ERR("[ERR]Set halmac io function Error!!\n");
	}

	if (adapter->chip_id == HALMAC_CHIP_ID_8814B) {
#if HALMAC_8814B_SUPPORT
		mount_api_8814b(adapter);
#endif
	} else {
		PLTFM_MSG_ERR("[ERR]Chip ID undefine!!\n");
		return HALMAC_RET_CHIP_NOT_SUPPORT;
	}

#if HALMAC_PLATFORM_TESTPROGRAM
	halmac_mount_misc_api_88xx_v1(adapter);
#endif

	return HALMAC_RET_SUCCESS;
}

static void
init_state_machine_88xx_v1(struct halmac_adapter *adapter)
{
	struct halmac_state *state = &adapter->halmac_state;

	init_ofld_feature_state_machine_88xx_v1(adapter);

	state->api_state = HALMAC_API_STATE_INIT;

	state->dlfw_state = HALMAC_DLFW_NONE;
	state->mac_pwr = HALMAC_MAC_POWER_OFF;
	state->gpio_cfg_state = HALMAC_GPIO_CFG_STATE_IDLE;
	state->rsvd_pg_state = HALMAC_RSVD_PG_STATE_IDLE;
}

void
init_ofld_feature_state_machine_88xx_v1(struct halmac_adapter *adapter)
{
	struct halmac_state *state = &adapter->halmac_state;

	state->efuse_state.cmd_cnstr_state = HALMAC_CMD_CNSTR_IDLE;
	state->efuse_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
	state->efuse_state.seq_num = adapter->h2c_info.seq_num;

	state->cfg_param_state.cmd_cnstr_state = HALMAC_CMD_CNSTR_IDLE;
	state->cfg_param_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
	state->cfg_param_state.seq_num = adapter->h2c_info.seq_num;

	state->scan_state.cmd_cnstr_state = HALMAC_CMD_CNSTR_IDLE;
	state->scan_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
	state->scan_state.seq_num = adapter->h2c_info.seq_num;

	state->update_pkt_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
	state->update_pkt_state.seq_num = adapter->h2c_info.seq_num;

	state->iqk_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
	state->iqk_state.seq_num = adapter->h2c_info.seq_num;

	state->pwr_trk_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
	state->pwr_trk_state.seq_num = adapter->h2c_info.seq_num;

	state->psd_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
	state->psd_state.seq_num = adapter->h2c_info.seq_num;
	state->psd_state.data_size = 0;
	state->psd_state.seg_size = 0;
	state->psd_state.data = NULL;

	state->fw_snding_state.cmd_cnstr_state = HALMAC_CMD_CNSTR_IDLE;
	state->fw_snding_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
	state->fw_snding_state.seq_num = adapter->h2c_info.seq_num;

	state->wlcpu_mode = HALMAC_WLCPU_ACTIVE;
}

/**
 * register_api_88xx_v1() - register feature list
 * @adapter
 * @registry : feature list, 1->enable 0->disable
 * Author : Ivan Lin
 *
 * Default is enable all api registry
 *
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
register_api_88xx_v1(struct halmac_adapter *adapter,
		     struct halmac_api_registry *registry)
{
	if (!registry)
		return HALMAC_RET_NULL_POINTER;

	PLTFM_MSG_TRACE("[TRACE]%s ===>\n", __func__);

	PLTFM_MEMCPY(&adapter->api_registry, registry, sizeof(*registry));

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

/**
 * pre_init_system_cfg_88xx_v1() - pre-init system config
 * @adapter : the adapter of halmac
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
pre_init_system_cfg_88xx_v1(struct halmac_adapter *adapter)
{
	u32 value32;
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;
	u8 enable_bb;

	PLTFM_MSG_TRACE("[TRACE]%s ===>\n", __func__);

	HALMAC_REG_W8(REG_RSV_CTRL, 0);

	/* Config PIN Mux */
	value32 = HALMAC_REG_R32(REG_PAD_CTRL1);
	value32 = value32 & (~(BIT(28) | BIT(29)));
	value32 = value32 | BIT(28) | BIT(29);
	HALMAC_REG_W32(REG_PAD_CTRL1, value32);

	value32 = HALMAC_REG_R32(REG_LED_CFG);
	value32 = value32 & (~(BIT(25) | BIT(26)));
	HALMAC_REG_W32(REG_LED_CFG, value32);

	value32 = HALMAC_REG_R32(REG_GPIO_MUXCFG);
	value32 = value32 & (~(BIT(2)));
	value32 = value32 | BIT(2);
	HALMAC_REG_W32(REG_GPIO_MUXCFG, value32);

	enable_bb = 0;
	set_hw_value_88xx_v1(adapter, HALMAC_HW_EN_BB_RF, &enable_bb);

	if (HALMAC_REG_R8(REG_SYS_CFG1 + 2) & BIT(4)) {
		PLTFM_MSG_ERR("[ERR]test mode!!\n");
		return HALMAC_RET_WLAN_MODE_FAIL;
	}

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

/**
 * init_system_cfg_88xx_v1() -  init system config
 * @adapter : the adapter of halmac
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
init_system_cfg_88xx_v1(struct halmac_adapter *adapter)
{
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;
	u32 tmp = 0;
	u8 value8;

	PLTFM_MSG_TRACE("[TRACE]%s ===>\n", __func__);

	/* disable data cpu & offload path */
	HALMAC_REG_W8(REG_DATA_CPU_CTL0, 0);
	HALMAC_REG_W8(REG_DATA_CPU_CTL1, 0);

	HALMAC_REG_W32_SET(REG_CPU_DMEM_CON, BIT_WL_PLATFORM_RST | BIT_DDMA_EN);
	value8 = HALMAC_REG_R8(REG_SYS_FUNC_EN + 1) | SYS_FUNC_EN;
	HALMAC_REG_W8(REG_SYS_FUNC_EN + 1, value8);

	init_analog_ip_cfg_88xx_v1(adapter);

	/*disable boot-from-flash for driver's DL FW*/
	tmp = HALMAC_REG_R32(REG_MCUFW_CTRL);
	if (tmp & BIT_BOOT_FSPI_EN) {
		HALMAC_REG_W32(REG_MCUFW_CTRL, tmp & (~BIT_BOOT_FSPI_EN));
		HALMAC_REG_W32_CLR(REG_GPIO_MUXCFG, BIT_FSPI_EN);
	}

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

/**
 * init_edca_cfg_88xx_v1() - config EDCA register
 * @adapter
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
init_edca_cfg_88xx_v1(struct halmac_adapter *adapter)
{
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;
	u32 value32;

	PLTFM_MSG_TRACE("[TRACE]%s ===>\n", __func__);

	cfg_mac_clk_88xx_v1(adapter);

	HALMAC_REG_W8_SET(REG_RD_CTRL + 1, BIT(1) | BIT(2));

	/* Clear TX pause */
	HALMAC_REG_W16(REG_TXPAUSE, 0x0000);

	HALMAC_REG_W8(REG_SLOT, WLAN_SLOT_TIME);
	HALMAC_REG_W8(REG_PIFS, WLAN_PIFS_TIME);
	HALMAC_REG_W32(REG_SIFS, WLAN_SIFS_CFG);

	HALMAC_REG_W16(REG_EDCA_VO_PARAM + 2, WLAN_VO_TXOP_LIMIT);
	HALMAC_REG_W16(REG_EDCA_VI_PARAM + 2, WLAN_VI_TXOP_LIMIT);

	HALMAC_REG_W32(REG_RD_NAV_NXT, WLAN_NAV_CFG);
	HALMAC_REG_W16(REG_RXTSF_OFFSET_CCK_V1, WLAN_RX_TSF_CFG);

	/* Select BCN control */
	HALMAC_REG_W8(REG_PORT_CTRL_SEL,
		      HALMAC_REG_R8(REG_PORT_CTRL_SEL) & 0xF8);

	/* Set beacon cotnrol - enable TSF and other related functions */
	HALMAC_REG_W8_SET(REG_PORT_CTRL_CFG, BIT_EN_PORT_FUNCTION);

	/* Set send beacon related registers */
	value32 = HALMAC_REG_R32(REG_TBTT_PROHIBIT_CFG);
	value32 &= 0xFFF00000;
	value32 |= WLAN_TBTT_TIME;
	HALMAC_REG_W32(REG_TBTT_PROHIBIT_CFG, value32);

	HALMAC_REG_W8_CLR(REG_TX_PTCL_CTRL + 1, BIT(4));

	/* MU primary packet fail, BAR packet will not issue */
	HALMAC_REG_W8_SET(REG_CROSS_TXOP_CTRL, BIT(5));

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

/**
 * init_wmac_cfg_88xx_v1() - config WMAC register
 * @adapter
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
init_wmac_cfg_88xx_v1(struct halmac_adapter *adapter)
{
	u8 value8;
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;
	enum halmac_ret_status status = HALMAC_RET_SUCCESS;

	PLTFM_MSG_TRACE("[TRACE]%s ===>\n", __func__);

	HALMAC_REG_W32(REG_MAR, 0xFFFFFFFF);
	HALMAC_REG_W32(REG_MAR + 4, 0xFFFFFFFF);

	HALMAC_REG_W8(REG_BBPSF_CTRL + 2, WLAN_RESP_TXRATE);

	HALMAC_REG_W32(REG_RXFLTMAP0, WLAN_RX_FILTER0);
	HALMAC_REG_W16(REG_RXFLTMAP2, WLAN_RX_FILTER2);

	HALMAC_REG_W32(REG_RCR, WLAN_RCR_CFG);

	HALMAC_REG_W8(REG_ACKTO, WLAN_ACK_TO);

	HALMAC_REG_W8(REG_RX_PKT_LIMIT, WLAN_RXPKT_MAX_SZ_512);

	HALMAC_REG_W8(REG_TCR + 2, WLAN_TX_FUNC_CFG2);
	HALMAC_REG_W8(REG_TCR + 1, WLAN_TX_FUNC_CFG1);

	HALMAC_REG_W8(REG_ACKTO_CCK, WLAN_ACK_TO_CCK);

	HALMAC_REG_W8_SET(REG_WMAC_TRXPTCL_CTL_H, BIT_EN_TXCTS_IN_RXNAV_V1);

	HALMAC_REG_W8_SET(REG_SND_PTCL_CTRL, BIT_R_DISABLE_CHECK_VHTSIGB_CRC);

	HALMAC_REG_W32(REG_WMAC_OPTION_FUNCTION_2, WLAN_MAC_OPT_FUNC2);

	if (adapter->hw_cfg_info.trx_mode == HALMAC_TRNSFER_NORMAL)
		value8 = WLAN_MAC_OPT_NORM_FUNC1;
	else
		value8 = WLAN_MAC_OPT_LB_FUNC1;

	HALMAC_REG_W8(REG_WMAC_OPTION_FUNCTION + 4, value8);

	status = api->halmac_init_low_pwr(adapter);
	if (status != HALMAC_RET_SUCCESS)
		return status;

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

/**
 * init_mac_cfg_88xx_v1() - config page1~page7 register
 * @adapter : the adapter of halmac
 * @mode : trx mode
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
init_mac_cfg_88xx_v1(struct halmac_adapter *adapter, enum halmac_trx_mode mode)
{
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;
	enum halmac_ret_status status = HALMAC_RET_SUCCESS;

	PLTFM_MSG_TRACE("[TRACE]%s ===>\n", __func__);

	status = api->halmac_init_trx_cfg(adapter, mode);
	if (status != HALMAC_RET_SUCCESS) {
		PLTFM_MSG_ERR("[ERR]init trx %x\n", status);
		return status;
	}

	status = api->halmac_init_protocol_cfg(adapter);
	if (status != HALMAC_RET_SUCCESS) {
		PLTFM_MSG_ERR("[ERR]init ptcl %x\n", status);
		return status;
	}

	status = init_edca_cfg_88xx_v1(adapter);
	if (status != HALMAC_RET_SUCCESS) {
		PLTFM_MSG_ERR("[ERR]init edca %x\n", status);
		return status;
	}

	status = init_wmac_cfg_88xx_v1(adapter);
	if (status != HALMAC_RET_SUCCESS) {
		PLTFM_MSG_ERR("[ERR]init wmac %x\n", status);
		return status;
	}

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return status;
}

/**
 * init_protocol_cfg_88xx_v1() - config protocol register
 * @adapter : the adapter of halmac
 * Author : KaiYuan Chang/Ivan Lin/Yong-Ching Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
init_protocol_cfg_88xx_v1(struct halmac_adapter *adapter)
{
	u32 max_agg_num;
	u32 max_rts_agg_num;
	u32 value32;
	u16 pre_txcnt;
	u8 value8;
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	PLTFM_MSG_TRACE("[TRACE]%s ===>\n", __func__);

	init_txq_ctrl_88xx_v1(adapter);
	init_sifs_ctrl_88xx_v1(adapter);
	init_rate_fallback_ctrl_88xx_v1(adapter);

	HALMAC_REG_W8(REG_AMPDU_MAX_TIME_V1, WLAN_AMPDU_MAX_TIME);
	HALMAC_REG_W8_SET(REG_TX_HANG_CTRL, BIT_EN_EOF_V1);

	pre_txcnt = WLAN_PRE_TXCNT_TIME_TH | BIT_EN_PRECNT;
	HALMAC_REG_W8(REG_PRECNT_CTRL, (u8)(pre_txcnt & 0xFF));
	HALMAC_REG_W8(REG_PRECNT_CTRL + 1, (u8)(pre_txcnt >> 8));

	max_agg_num = WLAN_MAX_AGG_PKT_LIMIT;
	max_rts_agg_num = WLAN_RTS_MAX_AGG_PKT_LIMIT;
	value32 = WLAN_RTS_LEN_TH | (WLAN_RTS_TX_TIME_TH << 8) |
				(max_agg_num << 16) | (max_rts_agg_num << 24);
	HALMAC_REG_W32(REG_PROT_MODE_CTRL, value32);

	HALMAC_REG_W16(REG_BAR_MODE_CTRL + 2,
		       WLAN_BAR_RETRY_LIMIT | WLAN_RA_TRY_RATE_AGG_LIMIT << 8);

	HALMAC_REG_W8(REG_FAST_EDCA_VOVI_SETTING, WALN_FAST_EDCA_VO_TH);
	HALMAC_REG_W8(REG_FAST_EDCA_VOVI_SETTING + 2, WLAN_FAST_EDCA_VI_TH);
	HALMAC_REG_W8(REG_FAST_EDCA_BEBK_SETTING, WLAN_FAST_EDCA_BE_TH);
	HALMAC_REG_W8(REG_FAST_EDCA_BEBK_SETTING + 2, WLAN_FAST_EDCA_BK_TH);

	/*close BA parser*/
	HALMAC_REG_W8_CLR(REG_LIFETIME_EN, BIT(5));

	value8 = HALMAC_REG_R8(REG_INIRTS_RATE_SEL);
	HALMAC_REG_W8(REG_INIRTS_RATE_SEL, value8 | BIT(5));

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

/**
 * reset_ofld_feature_88xx_v1() -reset async api cmd status
 * @adapter : the adapter of halmac
 * @feature_id : feature_id
 * Author : Ivan Lin/KaiYuan Chang
 * Return : enum halmac_ret_status.
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
reset_ofld_feature_88xx_v1(struct halmac_adapter *adapter,
			   enum halmac_feature_id feature_id)
{
	struct halmac_state *state = &adapter->halmac_state;

	PLTFM_MSG_TRACE("[TRACE]%s ===>\n", __func__);

	switch (feature_id) {
	case HALMAC_FEATURE_CFG_PARA:
		state->cfg_param_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		state->cfg_param_state.cmd_cnstr_state = HALMAC_CMD_CNSTR_IDLE;
		break;
	case HALMAC_FEATURE_DUMP_PHYSICAL_EFUSE:
	case HALMAC_FEATURE_DUMP_LOGICAL_EFUSE:
	case HALMAC_FEATURE_DUMP_LOGICAL_EFUSE_MASK:
		state->efuse_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		state->efuse_state.cmd_cnstr_state = HALMAC_CMD_CNSTR_IDLE;
		break;
	case HALMAC_FEATURE_CHANNEL_SWITCH:
		state->scan_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		state->scan_state.cmd_cnstr_state = HALMAC_CMD_CNSTR_IDLE;
		break;
	case HALMAC_FEATURE_UPDATE_PACKET:
		state->update_pkt_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		break;
	case HALMAC_FEATURE_SEND_SCAN_PACKET:
		state->scan_pkt_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		break;
	case HALMAC_FEATURE_DROP_SCAN_PACKET:
		state->drop_pkt_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		break;
	case HALMAC_FEATURE_IQK:
		state->iqk_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		break;
	case HALMAC_FEATURE_POWER_TRACKING:
		state->pwr_trk_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		break;
	case HALMAC_FEATURE_PSD:
		state->psd_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		break;
	case HALMAC_FEATURE_FW_SNDING:
		state->fw_snding_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		state->fw_snding_state.cmd_cnstr_state = HALMAC_CMD_CNSTR_IDLE;
		break;
	case HALMAC_FEATURE_ALL:
		state->cfg_param_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		state->cfg_param_state.cmd_cnstr_state = HALMAC_CMD_CNSTR_IDLE;
		state->efuse_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		state->efuse_state.cmd_cnstr_state = HALMAC_CMD_CNSTR_IDLE;
		state->scan_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		state->scan_state.cmd_cnstr_state = HALMAC_CMD_CNSTR_IDLE;
		state->update_pkt_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		state->scan_pkt_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		state->drop_pkt_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		state->iqk_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		state->pwr_trk_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		state->psd_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		state->fw_snding_state.proc_status = HALMAC_CMD_PROCESS_IDLE;
		state->fw_snding_state.cmd_cnstr_state = HALMAC_CMD_CNSTR_IDLE;
		break;
	default:
		PLTFM_MSG_ERR("[ERR]invalid feature id\n");
		return HALMAC_RET_INVALID_FEATURE_ID;
	}

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

/**
 * (debug API)verify_platform_api_88xx_v1() - verify platform api
 * @adapter : the adapter of halmac
 * Author : KaiYuan Chang/Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
verify_platform_api_88xx_v1(struct halmac_adapter *adapter)
{
	enum halmac_ret_status ret_status = HALMAC_RET_SUCCESS;

	PLTFM_MSG_TRACE("[TRACE]%s ===>\n", __func__);

	ret_status = verify_io_88xx_v1(adapter);

	if (ret_status != HALMAC_RET_SUCCESS)
		return ret_status;

	if (adapter->txff_alloc.la_mode != HALMAC_LA_MODE_FULL)
		ret_status = verify_send_rsvd_page_88xx_v1(adapter);

	if (ret_status != HALMAC_RET_SUCCESS)
		return ret_status;

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return ret_status;
}

void
tx_desc_chksum_88xx_v1(struct halmac_adapter *adapter, u8 enable)
{
	u16 value16;
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	PLTFM_MSG_TRACE("[TRACE]%s ===>\n", __func__, enable);

	adapter->tx_desc_checksum = enable;

	value16 = HALMAC_REG_R16(REG_TXDMA_OFFSET_CHK);
	if (enable == 1)
		HALMAC_REG_W16(REG_TXDMA_OFFSET_CHK, value16 | BIT(13));
	else
		HALMAC_REG_W16(REG_TXDMA_OFFSET_CHK, value16 & ~BIT(13));
}

static enum halmac_ret_status
verify_io_88xx_v1(struct halmac_adapter *adapter)
{
	return HALMAC_RET_SUCCESS;
}

static enum halmac_ret_status
verify_send_rsvd_page_88xx_v1(struct halmac_adapter *adapter)
{
	u8 txdesc_size = adapter->hw_cfg_info.txdesc_size;
	u8 *rsvd_buf = NULL;
	u8 *rsvd_page = NULL;
	u32 i;
	u32 pkt_size = 64;
	u32 payload = 0xab;
	enum halmac_ret_status ret_status = HALMAC_RET_SUCCESS;

	rsvd_buf = (u8 *)PLTFM_MALLOC(pkt_size);

	if (!rsvd_buf) {
		PLTFM_MSG_ERR("[ERR]rsvd buffer malloc fail!!\n");
		return HALMAC_RET_MALLOC_FAIL;
	}

	PLTFM_MEMSET(rsvd_buf, (u8)payload, pkt_size);

	ret_status = dl_rsvd_page_88xx_v1(adapter,
					  adapter->txff_alloc.rsvd_boundary,
					  rsvd_buf, pkt_size);
	if (ret_status != HALMAC_RET_SUCCESS) {
		PLTFM_FREE(rsvd_buf, pkt_size);
		return ret_status;
	}

	rsvd_page = (u8 *)PLTFM_MALLOC(pkt_size + txdesc_size);

	if (!rsvd_page) {
		PLTFM_MSG_ERR("[ERR]rsvd page malloc!!\n");
		PLTFM_FREE(rsvd_buf, pkt_size);
		return HALMAC_RET_MALLOC_FAIL;
	}

	PLTFM_MEMSET(rsvd_page, 0x00, pkt_size + txdesc_size);

	ret_status = dump_fifo_88xx_v1(adapter, HAL_FIFO_SEL_RSVD_PAGE, 0,
				       pkt_size + txdesc_size, rsvd_page);

	if (ret_status != HALMAC_RET_SUCCESS) {
		PLTFM_FREE(rsvd_buf, pkt_size);
		PLTFM_FREE(rsvd_page, pkt_size + txdesc_size);
		return ret_status;
	}

	for (i = 0; i < pkt_size; i++) {
		if (*(rsvd_buf + i) != *(rsvd_page + (i + txdesc_size))) {
			PLTFM_MSG_ERR("[ERR]Compare RSVD page Fail\n");
			ret_status = HALMAC_RET_PLATFORM_API_INCORRECT;
		}
	}

	PLTFM_FREE(rsvd_buf, pkt_size);
	PLTFM_FREE(rsvd_page, pkt_size + txdesc_size);

	return ret_status;
}

enum halmac_ret_status
set_pg_num_88xx_v1(struct halmac_adapter *adapter, enum halmac_trx_mode mode,
		   struct halmac_ch_pg_num *tbl)
{
	u8 flag;
	u16 pubq_num;
	u16 totalq_num = 0;
	u16 pg_num[HALMAC_TXDESC_DMA_CH16 + 1];
	u32 i;
	u32 j;
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	flag = 0;
	pubq_num = adapter->txff_alloc.acq_pg_num;
	for (i = 0; i < HALMAC_TRX_MODE_MAX; i++) {
		if (mode == tbl[i].mode) {
			for (j = 0; j < HALMAC_TXDESC_DMA_CH16 + 1; j++) {
				pg_num[j] = tbl[i].ch_num[j];
				totalq_num += pg_num[j];
				pubq_num -= pg_num[j];
			}
			flag = 1;
			break;
		}
	}
	pubq_num -= tbl[i].gap_num;
	totalq_num += (pubq_num + tbl[i].gap_num);

	if (flag == 0) {
		PLTFM_MSG_ERR("[ERR]trx mode!!\n");
		return HALMAC_RET_TRX_MODE_NOT_SUPPORT;
	}

	if (adapter->txff_alloc.acq_pg_num < totalq_num) {
		PLTFM_MSG_ERR("[ERR]acqnum = %d\n",
			      adapter->txff_alloc.acq_pg_num);
		for (i = 0; i < HALMAC_TXDESC_DMA_CH16 + 1; i++)
			PLTFM_MSG_ERR("[ERR]channel[%d] = %d\n", i, pg_num[i]);
		PLTFM_MSG_ERR("[ERR]gap num = %d\n", i, tbl[i].gap_num);
		return HALMAC_RET_CFG_TXFIFO_PAGE_FAIL;
	}

	HALMAC_REG_W16(REG_DMA_RQPN_INFO_0, pg_num[0]);
	HALMAC_REG_W16(REG_DMA_RQPN_INFO_1, pg_num[1]);
	HALMAC_REG_W16(REG_DMA_RQPN_INFO_2, pg_num[2]);
	HALMAC_REG_W16(REG_DMA_RQPN_INFO_3, pg_num[3]);
	HALMAC_REG_W16(REG_DMA_RQPN_INFO_4, pg_num[4]);
	HALMAC_REG_W16(REG_DMA_RQPN_INFO_5, pg_num[5]);
	HALMAC_REG_W16(REG_DMA_RQPN_INFO_6, pg_num[6]);
	HALMAC_REG_W16(REG_DMA_RQPN_INFO_7, pg_num[7]);
	HALMAC_REG_W16(REG_DMA_RQPN_INFO_8, pg_num[8]);
	HALMAC_REG_W16(REG_DMA_RQPN_INFO_9, pg_num[9]);
	HALMAC_REG_W16(REG_DMA_RQPN_INFO_10, pg_num[10]);
	HALMAC_REG_W16(REG_DMA_RQPN_INFO_11, pg_num[12]);
	HALMAC_REG_W16(REG_DMA_RQPN_INFO_12, pg_num[12]);
	HALMAC_REG_W16(REG_DMA_RQPN_INFO_13, pg_num[13]);
	HALMAC_REG_W16(REG_DMA_RQPN_INFO_14, pg_num[14]);
	HALMAC_REG_W16(REG_DMA_RQPN_INFO_15, pg_num[15]);
	HALMAC_REG_W16(REG_DMA_RQPN_INFO_16, pg_num[16]);
	HALMAC_REG_W16(REG_DMA_RQPN_INFO_PUB, pubq_num);
	HALMAC_REG_W32_SET(REG_RQPN_CTRL_2_V1, BIT(31));

	return HALMAC_RET_SUCCESS;
}

enum halmac_ret_status
ch_map_parser_88xx_v1(struct halmac_adapter *adapter, enum halmac_trx_mode mode,
		      struct halmac_ch_mapping *map)
{
	u8 flag;
	u32 i;

	flag = 0;
	for (i = 0; i < HALMAC_TRX_MODE_MAX; i++) {
		if (mode == map[i].mode) {
			adapter->ch_map[HALMAC_PQ_MAP_VO] = map[i].dma_map_vo;
			adapter->ch_map[HALMAC_PQ_MAP_VI] = map[i].dma_map_vi;
			adapter->ch_map[HALMAC_PQ_MAP_BE] = map[i].dma_map_be;
			adapter->ch_map[HALMAC_PQ_MAP_BK] = map[i].dma_map_bk;
			adapter->ch_map[HALMAC_PQ_MAP_MG] = map[i].dma_map_mg;
			adapter->ch_map[HALMAC_PQ_MAP_HI] = map[i].dma_map_hi;
			flag = 1;
			PLTFM_MSG_TRACE("[TRACE]%s done\n", __func__);
			break;
		}
	}

	if (flag == 0) {
		PLTFM_MSG_ERR("[ERR]trx mdoe!!\n");
		return HALMAC_RET_TRX_MODE_NOT_SUPPORT;
	}

	return HALMAC_RET_SUCCESS;
}

void
halmac_init_bcnq_88xx_v1(struct halmac_adapter *adapter, u16 head_pg)
{
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	head_pg &= 0xFFF;

	HALMAC_REG_W16(REG_BCN_CTRL_0, head_pg);
	HALMAC_REG_W16(REG_BCN_CTRL_0 + 2, head_pg);
	HALMAC_REG_W16(REG_BCN_CTRL_1, head_pg);
	HALMAC_REG_W16(REG_BCN_CTRL_1 + 2, head_pg);
	HALMAC_REG_W16(REG_BCN_CTRL_2, head_pg);
	//HALMAC_REG_W16(REG_BCN_CTRL_2 + 2, head_pg);
	HALMAC_REG_W16(REG_BCN_CTRL_2 + 2, head_pg+5);

	HALMAC_REG_W32(REG_BCNQ_BDNY_V2, (0 << 28) | head_pg);
	HALMAC_REG_W32(REG_BCNQ_BDNY_V2, (1 << 28) | head_pg);
	HALMAC_REG_W32(REG_BCNQ_BDNY_V2, (2 << 28) | head_pg);
	HALMAC_REG_W32(REG_BCNQ_BDNY_V2, (3 << 28) | head_pg);
	HALMAC_REG_W32(REG_BCNQ_BDNY_V2, (4 << 28) | head_pg);
	//HALMAC_REG_W32(REG_BCNQ_BDNY_V2, (5 << 28) | head_pg);
	HALMAC_REG_W32(REG_BCNQ_BDNY_V2, (5 << 28) | (head_pg+5));
}

static void
init_txq_ctrl_88xx_v1(struct halmac_adapter *adapter)
{
	u8 value8;
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	value8 = HALMAC_REG_R8(REG_FWHW_TXQ_CTRL);
	value8 |= (BIT(7) & ~BIT(1) & ~BIT(2));
	HALMAC_REG_W8(REG_FWHW_TXQ_CTRL, value8);

	HALMAC_REG_W8(REG_FWHW_TXQ_CTRL + 1, WLAN_TXQ_RPT_EN);
}

static void
init_sifs_ctrl_88xx_v1(struct halmac_adapter *adapter)
{
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	HALMAC_REG_W16(REG_SPEC_SIFS, WLAN_SIFS_DUR_TUNE);
	HALMAC_REG_W32(REG_SIFS, WLAN_SIFS_CFG);
	HALMAC_REG_W16(REG_RESP_SIFS_CCK,
		       WLAN_SIFS_CCK_CTX | WLAN_SIFS_CCK_IRX << 8);
	HALMAC_REG_W16(REG_RESP_SIFS_OFDM,
		       WLAN_SIFS_OFDM_CTX | WLAN_SIFS_OFDM_IRX << 8);
}

static void
init_rate_fallback_ctrl_88xx_v1(struct halmac_adapter *adapter)
{
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	HALMAC_REG_W32(REG_DARFRC, WLAN_DATA_RATE_FB_CNT_1_4);
	HALMAC_REG_W32(REG_DARFRCH, WLAN_DATA_RATE_FB_CNT_5_8);
	HALMAC_REG_W32(REG_RARFRCH, WLAN_RTS_RATE_FB_CNT_5_8);

	HALMAC_REG_W32(REG_ARFR0, WLAN_DATA_RATE_FB_RATE0);
	HALMAC_REG_W32(REG_ARFRH0, WLAN_DATA_RATE_FB_RATE0_H);
}

static void
init_analog_ip_cfg_88xx_v1(struct halmac_adapter *adapter)
{
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	HALMAC_REG_W8_SET(REG_SYS_SWR_CTRL1, BIT_WL_CTRL_XTAL_CADJ);
	HALMAC_REG_W8(REG_ANAPAR_POW_MAC, ANAPAR_PWR_LDO);
	HALMAC_REG_W8(REG_ANAPAR_POW_XTAL, ANAPAR_PWR_XTAL);
	HALMAC_REG_W8(REG_ANAPAR_XTAL_0 + 1, ANAPAR_XTAL0_BYTE1_CFG);
	HALMAC_REG_W8(REG_ANAPAR_XTAL_0 + 2, ANAPAR_XTAL0_BYTE2_CFG);
	HALMAC_REG_W8(REG_ANAPAR_XTAL_0 + 3, ANAPAR_XTAL0_BYTE3_CFG);
	HALMAC_REG_W8(REG_ANAPAR_XTAL_2, ANAPAR_XTAL1_CFG);
	if (adapter->chip_ver == HALMAC_CHIP_VER_A_CUT)
		HALMAC_REG_W32(REG_ANAPAR_MAC_1, ANAPAR_MAC1_CFG_A_CUT);
	else
		HALMAC_REG_W32(REG_ANAPAR_MAC_1, ANAPAR_MAC1_CFG);
}

enum halmac_ret_status
fwff_is_empty_88xx_v1(struct halmac_adapter *adapter)
{
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;
	u32 cnt;

	cnt = 5000;
	while (HALMAC_REG_R16(REG_FWFF_CTRL) !=
		HALMAC_REG_R16(REG_FWFF_PKT_INFO)) {
		if (cnt == 0) {
			PLTFM_MSG_ERR("[ERR]polling fwff empty fail\n");
			return HALMAC_RET_FWFF_NO_EMPTY;
		}
		cnt--;
		PLTFM_DELAY_US(50);
	}
	return HALMAC_RET_SUCCESS;
}

#endif /* HALMAC_88XX_V1_SUPPORT */
