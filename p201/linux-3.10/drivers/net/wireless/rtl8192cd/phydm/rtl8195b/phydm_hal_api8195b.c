/******************************************************************************
 *
 * Copyright(c) 2016 - 2017 Realtek Corporation.
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
 *****************************************************************************/

#include "mp_precomp.h"
#include "../phydm_precomp.h"

#if (RTL8195B_SUPPORT == 1)
#if (PHYDM_FW_API_ENABLE_8195B == 1)
/* ======================================================================== */
/* These following functions can be used for PHY DM only*/

u32 rega20_8195b;
u32 rega24_8195b;
u32 rega28_8195b;
u32 rega98_8195b;
u32 regaac_8195b;
u32 reg830_8195b;
u8 OFDMCCA_8195b;
u8 CCKCCA_8195b;
u8 BLOCK_8195b;

enum channel_width bw_8195b;
u8 central_ch_8195b;

__iram_odm_func__
void phydm_igi_toggle_8195b(struct dm_struct *dm)
{
	u32 igi = 0x20;

	igi = odm_get_bb_reg(dm, R_0xc50, 0x7f);
	odm_set_bb_reg(dm, R_0xc50, 0x7f, (igi - 2));
	odm_set_bb_reg(dm, R_0xc50, 0x7f, igi);
}

__iram_odm_func__
s8 phydm_cck_rssi_8195B(struct dm_struct *dm, u8 lna_idx, u8 vga_idx)
{
	s8 rx_pwr_all = 0;
	s8 lna_gain = 0;
	/*only use lna2/3/5/7*/
	s8 lna_gain_table_0[8] = {22, 8, -4, -12, -31, -32, -46, -52};

	lna_gain = lna_gain_table_0[lna_idx];
	rx_pwr_all = lna_gain - (2 * vga_idx);

	return rx_pwr_all;
}

__iram_odm_func__
boolean phydm_rfe_8195b(struct dm_struct *dm, u8 channel)
{
	/* Efuse is not wrote now */
	/* Need to check RFE type finally */
	switch (dm->rfe_type) {
	case 0:
		odm_set_bb_reg(dm, R_0xcb0, MASKLWORD, 0x0);
		break;
	case 1:
		if (channel <= 14)
			odm_set_bb_reg(dm, R_0xcb0, MASKLWORD, 0x5420);
		else if (channel > 35)
			odm_set_bb_reg(dm, R_0xcb0, MASKLWORD, 0x0);
		else
			return false;

		break;
	case 2:
		if (channel <= 14)
			odm_set_bb_reg(dm, R_0xcb0, MASKLWORD, 0x0);
		else if (channel > 35)
			odm_set_bb_reg(dm, R_0xcb0, MASKLWORD, 0x5431);
		else
			return false;
		break;
	default:
		odm_set_bb_reg(dm, R_0xcb0, MASKLWORD, 0x0);
		break;
	}
	/* chip top mux */
	odm_set_bb_reg(dm, R_0x74, BIT(2) | BIT(0), 0x3);

#if 0
	/* from s0 or s1 */
	odm_set_bb_reg(dm, R_0x1990, (BIT(5) | BIT(4) | BIT(3) | BIT(2) | BIT(1) | BIT(0)), 0x30);
	odm_set_bb_reg(dm, R_0x1990, (BIT(11) | BIT(10)), 0x3);

	/* input or output */
	odm_set_bb_reg(dm, R_0x974, (BIT(5) | BIT(4) | BIT(3) | BIT(2) | BIT(1) | BIT(0)), 0x3f);
	odm_set_bb_reg(dm, R_0x974, (BIT(11) | BIT(10)), 0x3);

	/* delay 400ns for PAPE */
	odm_set_bb_reg(dm, R_0x810, MASKBYTE3 | BIT(20) | BIT(21) | BIT(22) | BIT(23), 0x211);

	/* antenna switch table */
	odm_set_bb_reg(dm, R_0xca0, MASKLWORD, 0xa555);
	odm_set_bb_reg(dm, R_0xea0, MASKLWORD, 0xa555);

	/* inverse or not */
	odm_set_bb_reg(dm, R_0xcbc, (BIT(5) | BIT(4) | BIT(3) | BIT(2) | BIT(1) | BIT(0)), 0x0);
	odm_set_bb_reg(dm, R_0xcbc, (BIT(11) | BIT(10)), 0x0);
	odm_set_bb_reg(dm, R_0xebc, (BIT(5) | BIT(4) | BIT(3) | BIT(2) | BIT(1) | BIT(0)), 0x0);
	odm_set_bb_reg(dm, R_0xebc, (BIT(11) | BIT(10)), 0x0);
	/*}*/
#endif
	return true;
}

__iram_odm_func__
void phydm_ccapar_8195b(
	struct dm_struct *dm)
{
#if 0
	u32	cca_ifem[9][4] = {
		/*20M*/
		{0x75D97010, 0x75D97010, 0x75D97010, 0x75D97010}, /*Reg82C*/
		{0x00000000, 0x00000000, 0x00000000, 0x00000000}, /*Reg830*/
		{0x00000000, 0x00000000, 0x00000000, 0x00000000}, /*Reg838*/
		/*40M*/
		{0x75D97010, 0x75D97010, 0x75D97010, 0x75D97010}, /*Reg82C*/
		{0x00000000, 0x79a0ea28, 0x00000000, 0x79a0ea28}, /*Reg830*/
		{0x87765541, 0x87766341, 0x87765541, 0x87766341}, /*Reg838*/
		/*80M*/
		{0x75D97010, 0x75D97010, 0x75D97010, 0x75D97010}, /*Reg82C*/
		{0x00000000, 0x00000000, 0x00000000, 0x00000000}, /*Reg830*/
		{0x00000000, 0x87746641, 0x00000000, 0x87746641}
	}; /*Reg838*/

	u32	cca_efem[9][4] = {
		/*20M*/
		{0x75A76010, 0x75A76010, 0x75A76010, 0x75A75010}, /*Reg82C*/
		{0x00000000, 0x00000000, 0x00000000, 0x00000000}, /*Reg830*/
		{0x87766651, 0x87766431, 0x87766451, 0x87766431}, /*Reg838*/
		/*40M*/
		{0x75A75010, 0x75A75010, 0x75A75010, 0x75A75010}, /*Reg82C*/
		{0x00000000, 0x00000000, 0x00000000, 0x00000000}, /*Reg830*/
		{0x87766431, 0x87766431, 0x87766431, 0x87766431}, /*Reg838*/
		/*80M*/
		{0x75BA7010, 0x75BA7010, 0x75BA7010, 0x75BA7010}, /*Reg82C*/
		{0x00000000, 0x00000000, 0x00000000, 0x00000000}, /*Reg830*/
		{0x87766431, 0x87766431, 0x87766431, 0x87766431}
	}; /*Reg838*/

	u8	row, col;
	u32	reg82c, reg830, reg838;

	if (dm->cut_version != ODM_CUT_B)
		return;

	if (bw_8195b == CHANNEL_WIDTH_20)
		row = 0;
	else if (bw_8195b == CHANNEL_WIDTH_40)
		row = 3;
	else
		row = 6;

	if (central_ch_8195b <= 14) {
		if (dm->rx_ant_status == BB_PATH_A || dm->rx_ant_status == BB_PATH_B)
			col = 0;
		else
			col = 1;
	} else {
		if (dm->rx_ant_status == BB_PATH_A || dm->rx_ant_status == BB_PATH_B)
			col = 2;
		else
			col = 3;
	}

	if (dm->rfe_type == 0) {/*iFEM*/
		reg82c = (cca_ifem[row][col] != 0) ? cca_ifem[row][col] : reg82c_8195b;
		reg830 = (cca_ifem[row + 1][col] != 0) ? cca_ifem[row + 1][col] : reg830_8195b;
		reg838 = (cca_ifem[row + 2][col] != 0) ? cca_ifem[row + 2][col] : reg838_8195b;
	} else {/*eFEM*/
		reg82c = (cca_efem[row][col] != 0) ? cca_efem[row][col] : reg82c_8195b;
		reg830 = (cca_efem[row + 1][col] != 0) ? cca_efem[row + 1][col] : reg830_8195b;
		reg838 = (cca_efem[row + 2][col] != 0) ? cca_efem[row + 2][col] : reg838_8195b;
	}

	odm_set_bb_reg(dm, R_0x82c, MASKDWORD, reg82c);
	odm_set_bb_reg(dm, R_0x830, MASKDWORD, reg830);
	odm_set_bb_reg(dm, R_0x838, MASKDWORD, reg838);

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "[%s]: Update CCA parameters for Bcut (Pkt%d, Intf%d, RFE%d), row = %d, col = %d\n",
		  __func__, dm->package_type, dm->support_interface,
		  dm->rfe_type, row, col);
#endif
}

__iram_odm_func__
void phydm_ccapar_by_bw_8195b(
	struct dm_struct *dm,
	enum channel_width bandwidth)
{
#if 0
	u32		reg82c;


	if (dm->cut_version != ODM_CUT_A)
		return;

	/* A-cut */
	reg82c = odm_get_bb_reg(dm, R_0x82c, MASKDWORD);

	if (bandwidth == CHANNEL_WIDTH_20) {
		/* 82c[15:12] = 4 */
		/* 82c[27:24] = 6 */

		reg82c &= (~(0x0f00f000));
		reg82c |= ((0x4) << 12);
		reg82c |= ((0x6) << 24);
	} else if (bandwidth == CHANNEL_WIDTH_40) {
		/* 82c[19:16] = 9 */
		/* 82c[27:24] = 6 */

		reg82c &= (~(0x0f0f0000));
		reg82c |= ((0x9) << 16);
		reg82c |= ((0x6) << 24);
	} else if (bandwidth == CHANNEL_WIDTH_80) {
		/* 82c[15:12] 7 */
		/* 82c[19:16] b */
		/* 82c[23:20] d */
		/* 82c[27:24] 3 */

		reg82c &= (~(0x0ffff000));
		reg82c |= ((0xdb7) << 12);
		reg82c |= ((0x3) << 24);
	}

	odm_set_bb_reg(dm, R_0x82c, MASKDWORD, reg82c);
#endif
}

__iram_odm_func__
void phydm_ccapar_by_rxpath_8195b(
	struct dm_struct *dm)
{
#if 0
	if (dm->cut_version != ODM_CUT_A)
		return;

	if (dm->rx_ant_status == BB_PATH_A || dm->rx_ant_status == BB_PATH_B) {
		/* 838[7:4] = 8 */
		/* 838[11:8] = 7 */
		/* 838[15:12] = 6 */
		/* 838[19:16] = 7 */
		/* 838[23:20] = 7 */
		/* 838[27:24] = 7 */
		odm_set_bb_reg(dm, R_0x838, 0x0ffffff0, 0x777678);
	} else {
		/* 838[7:4] = 3 */
		/* 838[11:8] = 3 */
		/* 838[15:12] = 6 */
		/* 838[19:16] = 6 */
		/* 838[23:20] = 7 */
		/* 838[27:24] = 7 */
		odm_set_bb_reg(dm, R_0x838, 0x0ffffff0, 0x776633);
	}
#endif
}

__iram_odm_func__
void phydm_rxdfirpar_by_bw_8195b(
	struct dm_struct *dm,
	enum channel_width bandwidth)
{
	if (bandwidth == CHANNEL_WIDTH_40) {
		/* RX DFIR for BW40 */
		odm_set_bb_reg(dm, R_0x948, BIT(29) | BIT(28), 0x2);
		odm_set_bb_reg(dm, R_0x94c, BIT(29) | BIT(28), 0x2);
		odm_set_bb_reg(dm, R_0xc20, BIT(31), 0x0);
		odm_set_bb_reg(dm, R_0x8f0, BIT(31), 0x0);
	} else if (bandwidth == CHANNEL_WIDTH_80) {
		/* RX DFIR for BW80 */
		odm_set_bb_reg(dm, R_0x948, BIT(29) | BIT(28), 0x2);
		odm_set_bb_reg(dm, R_0x94c, BIT(29) | BIT(28), 0x1);
		odm_set_bb_reg(dm, R_0xc20, BIT(31), 0x0);
		odm_set_bb_reg(dm, R_0x8f0, BIT(31), 0x1);
	} else {
		/* RX DFIR for BW20, BW10 and BW5*/
		odm_set_bb_reg(dm, R_0x948, BIT(29) | BIT(28), 0x2);
		odm_set_bb_reg(dm, R_0x94c, BIT(29) | BIT(28), 0x2);
		odm_set_bb_reg(dm, R_0xc20, BIT(31), 0x1);
		odm_set_bb_reg(dm, R_0x8f0, BIT(31), 0x0);
	}
	/* PHYDM_DBG(dm, ODM_PHY_CONFIG, "phydm_rxdfirpar_by_bw_8195b\n");*/
}

__iram_odm_func__
boolean
phydm_write_txagc_1byte_8195b(
	struct dm_struct *dm,
	u32 power_index,
	enum rf_path path,
	u8 hw_rate)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
	u32 offset_txagc[2] = {0x1d00, 0x1d80};
	u8 rate_idx = (hw_rate & 0xfc), i;
	u8 rate_offset = (hw_rate & 0x3);
	u32 txagc_content = 0x0;

	/* For debug command only!!!! */

	/* Error handling */
	if (path > RF_PATH_A || hw_rate > 0x53) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: unsupported path (%d)\n",
			  __func__, path);
		return false;
	}

#if 1
	/* For HW limitation, We can't write TXAGC once a byte. */
	for (i = 0; i < 4; i++) {
		if (i != rate_offset)
			txagc_content = txagc_content | (config_phydm_read_txagc_8195b(dm, path, rate_idx + i) << (i << 3));
		else
			txagc_content = txagc_content | ((power_index & 0x3f) << (i << 3));
	}
	odm_set_bb_reg(dm, (offset_txagc[path] + rate_idx), MASKDWORD, txagc_content);
#else
	odm_write_1byte(dm, (offset_txagc[path] + hw_rate), (power_index & 0x3f));
#endif

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "[%s]: path-%d rate index 0x%x (0x%x) = 0x%x\n", __func__,
		  path, hw_rate, (offset_txagc[path] + hw_rate), power_index);
	return true;
#else
	return false;
#endif
}

__iram_odm_func__
void phydm_init_hw_info_by_rfe_type_8195b(
	struct dm_struct *dm)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
	dm->is_init_hw_info_by_rfe = false;
	/*
	Let original variable rfe_type to be rfe_type_8195b.
	Varible rfe_type as symbol is used to identify PHY parameter.
	*/
	dm->rfe_type = dm->rfe_type_expand >> 3;

	/*2.4G default rf set with wlg or btg*/
	if (dm->rfe_type_expand == 2 || dm->rfe_type_expand == 4 || dm->rfe_type_expand == 7)
		; //dm->default_rf_set_8195b = SWITCH_TO_BTG;
	else if (dm->rfe_type_expand == 0 || dm->rfe_type_expand == 1 ||
		 dm->rfe_type_expand == 3 || dm->rfe_type_expand == 5 ||
		 dm->rfe_type_expand == 6)
		; //dm->default_rf_set_8195b = SWITCH_TO_WLG;
	else if (dm->rfe_type_expand == 0x22 || dm->rfe_type_expand == 0x24 ||
		 dm->rfe_type_expand == 0x27 || dm->rfe_type_expand == 0x2a ||
		 dm->rfe_type_expand == 0x2c || dm->rfe_type_expand == 0x2f) {
		; //dm->default_rf_set_8195b = SWITCH_TO_BTG;
		odm_cmn_info_init(dm, ODM_CMNINFO_PACKAGE_TYPE, 1);
	} else if (dm->rfe_type_expand == 0x20 || dm->rfe_type_expand == 0x21 ||
		   dm->rfe_type_expand == 0x23 || dm->rfe_type_expand == 0x25 ||
		   dm->rfe_type_expand == 0x26 || dm->rfe_type_expand == 0x28 ||
		   dm->rfe_type_expand == 0x29 || dm->rfe_type_expand == 0x2b ||
		   dm->rfe_type_expand == 0x2d || dm->rfe_type_expand == 0x2e) {
		; //dm->default_rf_set_8195b = SWITCH_TO_WLG;
		odm_cmn_info_init(dm, ODM_CMNINFO_PACKAGE_TYPE, 1);
	}

	if (dm->rfe_type_expand == 3 || dm->rfe_type_expand == 4 ||
	    dm->rfe_type_expand == 0x23 || dm->rfe_type_expand == 0x24 ||
	    dm->rfe_type_expand == 0x2b || dm->rfe_type_expand == 0x2c)
		; //dm->default_ant_num_8195b = SWITCH_TO_ANT2;
	else
		; //dm->default_ant_num_8195b = SWITCH_TO_ANT1;

	dm->is_init_hw_info_by_rfe = true;
/*	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: RFE type (%d), rf set (%s)\n",
		__FUNCTION__, dm->rfe_type_expand,
		dm->default_rf_set_8195b == 0 ? "BTG" : "WLG"); */
#endif
}

#if 0
__iram_odm_func__
void
phydm_set_gnt_state_8195b(
	struct dm_struct			*dm,
	boolean				gnt_wl_state,
	boolean				gnt_bt_state
)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
	u32		gnt_val = 0;

	odm_set_bb_reg(dm, R_0x70, BIT(26), 0x1);

	if (gnt_wl_state)
		gnt_val = 0x3300;
	else
		gnt_val = 0x1100;

	if (gnt_bt_state)
		gnt_val = gnt_val | 0xcc00;
	else
		gnt_val = gnt_val | 0x4400;

	odm_set_bb_reg(dm, R_0x1704, MASKLWORD, gnt_val);
	ODM_delay_us(50); /*waiting before access 0x1700 */
	odm_set_bb_reg(dm, R_0x1700, MASKDWORD, 0xc00f0038);
#endif
}
/* ======================================================================== */
#endif
/* ======================================================================== */
/* These following functions can be used by driver*/

__iram_odm_func__
u32 config_phydm_read_rf_reg_8195b(
	struct dm_struct *dm,
	enum rf_path path,
	u32 reg_addr,
	u32 bit_mask)
{
	u32 readback_value, direct_addr;
	u32 offset_read_rf[2] = {0x2800, 0x2c00};

	/* Error handling.*/
	if (path > RF_PATH_A) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: unsupported path (%d)\n",
			  __func__, path);
		return INVALID_RF_DATA;
	}

	/* Calculate offset */
	reg_addr &= 0xff;
	direct_addr = offset_read_rf[path] + (reg_addr << 2);

	/* RF register only has 20bits */
	bit_mask &= RFREGOFFSETMASK;

	/* Read RF register directly */
	readback_value = odm_get_bb_reg(dm, direct_addr, bit_mask);
	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "[%s]: RF-%d 0x%x = 0x%x, bit mask = 0x%x\n", __func__, path,
		  reg_addr, readback_value, bit_mask);
	return readback_value;
}

__iram_odm_func__
boolean
config_phydm_write_rf_reg_8195b(
	struct dm_struct *dm,
	enum rf_path path,
	u32 reg_addr,
	u32 bit_mask,
	u32 data)
{
	u32 data_and_addr = 0, data_original = 0;
	u32 offset_write_rf[2] = {0xc90, 0xe90};
	u8 bit_shift;

	/* Error handling.*/
	if (path > RF_PATH_A) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: unsupported path (%d)\n",
			  __func__, path);
		return false;
	}

	/*for 95B C-Cut radio A modification*/
	if (data == 0xffffffff)
		return true;

	/* Read RF register content first */
	reg_addr &= 0xff;
	bit_mask = bit_mask & RFREGOFFSETMASK;

	if (bit_mask != RFREGOFFSETMASK) {
		data_original = config_phydm_read_rf_reg_8195b(dm, path, reg_addr, RFREGOFFSETMASK);

		/* Error handling. RF is disabled */
		if (config_phydm_read_rf_check_8195b(data_original) == false) {
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: Write fail, RF is disable\n",
				  __func__);
			return false;
		}

		/* check bit mask */
		if (bit_mask != 0xfffff) {
			for (bit_shift = 0; bit_shift <= 19; bit_shift++) {
				if (((bit_mask >> bit_shift) & 0x1) == 1)
					break;
			}
			data = ((data_original) & (~bit_mask)) | (data << bit_shift);
		}
	}

	/* Put write addr in [27:20]  and write data in [19:00] */
	data_and_addr = ((reg_addr << 20) | (data & 0x000fffff)) & 0x0fffffff;

	/* Write operation */
	odm_set_bb_reg(dm, offset_write_rf[path], MASKDWORD, data_and_addr);
	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "[%s]: RF-%d 0x%x = 0x%x (original: 0x%x), bit mask = 0x%x\n",
		  __func__, path, reg_addr, data, data_original, bit_mask);
	return true;
}

__iram_odm_func__
boolean
config_phydm_write_txagc_8195b(
	struct dm_struct *dm,
	u32 power_index,
	enum rf_path path,
	u8 hw_rate)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
	u32 offset_txagc[2] = {0x1d00, 0x1d80};
	u8 rate_idx = (hw_rate & 0xfc);

	/* Input need to be HW rate index, not driver rate index!!!! */

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: disable PHY API for debug!!\n", __func__);
		return true;
	}

	/* Error handling */
	if (path > RF_PATH_A || hw_rate > 0x53) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: unsupported path (%d)\n",
			  __func__, path);
		return false;
	}

	/* driver need to construct a 4-byte power index */
	odm_set_bb_reg(dm, (offset_txagc[path] + rate_idx), MASKDWORD, power_index);

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "[%s]: path-%d rate index 0x%x (0x%x) = 0x%x\n", __func__,
		  path, hw_rate, (offset_txagc[path] + hw_rate), power_index);
	return true;
#else
	return false;
#endif
}

__iram_odm_func__
u8 config_phydm_read_txagc_8195b(
	struct dm_struct *dm,
	enum rf_path path,
	u8 hw_rate)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
	u8 read_back_data;

	/* Input need to be HW rate index, not driver rate index!!!! */

	/* Error handling */
	if (path > RF_PATH_A || hw_rate > 0x53) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: unsupported path (%d)\n",
			  __func__, path);
		return INVALID_TXAGC_DATA;
	}

	/* Disable TX AGC report */
	odm_set_bb_reg(dm, R_0x1998, BIT(16), 0x0); /* need to check */

	/* Set data rate index (bit0~6) and path index (bit7) */
	odm_set_bb_reg(dm, R_0x1998, MASKBYTE0, (hw_rate | (path << 7)));

	/* Enable TXAGC report */
	odm_set_bb_reg(dm, R_0x1998, BIT(16), 0x1);

	/* Read TX AGC report */
	read_back_data = (u8)odm_get_bb_reg(dm, R_0xd30, 0x7f0000);

	/* Driver have to disable TXAGC report after reading TXAGC (ref. user guide v11) */
	odm_set_bb_reg(dm, R_0x1998, BIT(16), 0x0);

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: path-%d rate index 0x%x = 0x%x\n",
		  __func__, path, hw_rate, read_back_data);
	return read_back_data;
#else
	return 0;
#endif
}

__iram_odm_func__
boolean
config_phydm_switch_band_8195b(
	struct dm_struct *dm,
	u8 central_ch)
{
	u32 rf_reg18;
	boolean rf_reg_status = true;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]======================>\n",
		  __func__);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: disable PHY API for debug!!\n", __func__);
		return true;
	}

	rf_reg18 = config_phydm_read_rf_reg_8195b(dm, RF_PATH_A, 0x18, RFREGOFFSETMASK);
	rf_reg_status = rf_reg_status & config_phydm_read_rf_check_8195b(rf_reg18);

	if (central_ch <= 14) {
		/* 2.4G */

		/* Enable CCK block */
		odm_set_bb_reg(dm, R_0x808, BIT(28), 0x1);

		/* Enable OFDM block */
		odm_set_bb_reg(dm, R_0x808, BIT(29), 0x1);

		/* Disable MAC CCK check */
		odm_set_bb_reg(dm, R_0x454, BIT(7), 0x0);

		/* Disable BB CCK check */
		odm_set_bb_reg(dm, R_0xa80, BIT(18), 0x0);

		/*CCA Mask*/
		odm_set_bb_reg(dm, R_0x814, 0x0000FC00, 15); /*default value*/

		/* RF band */
		rf_reg18 = (rf_reg18 & (~(BIT(16) | BIT(9) | BIT(8))));
		rf_reg18 = (rf_reg18 & (~(MASKBYTE0)));
		rf_reg18 = (rf_reg18 | central_ch);
#if 0
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
		/* Switch WLG/BTG*/
		if (dm->default_rf_set_8195b == SWITCH_TO_BTG)
			config_phydm_switch_rf_set_8195b(dm, SWITCH_TO_BTG);
		else if (dm->default_rf_set_8195b == SWITCH_TO_WLG)
			config_phydm_switch_rf_set_8195b(dm, SWITCH_TO_WLG);
#endif

		/*RF TXA_TANK LUT mode*/
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xdf, BIT(6), 0x1);

		/*RF TXA_PA_TANK*/
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x64, 0x0000f, 0xf);
#endif
	} else if (central_ch > 35) {
		/* 5G */

		/* Disable CCK block */
		odm_set_bb_reg(dm, R_0x808, BIT(28), 0x0);

		/* Enable OFDM block */
		odm_set_bb_reg(dm, R_0x808, BIT(29), 0x1);

		/* Enable BB CCK check */
		odm_set_bb_reg(dm, R_0xa80, BIT(18), 0x1);

		/* Enable CCK check */
		odm_set_bb_reg(dm, R_0x454, BIT(7), 0x1);

		/*CCA Mask*/
		odm_set_bb_reg(dm, R_0x814, 0x0000FC00, 15); /*default value*/
		/*odm_set_bb_reg(dm, R_0x814, 0x0000FC00, 34); CCA mask = 13.6us*/

		/* RF band */
		rf_reg18 = (rf_reg18 & (~(BIT(16) | BIT(9) | BIT(8))));
		rf_reg18 = (rf_reg18 & (~(MASKBYTE0)));
		rf_reg18 = (rf_reg18 | BIT(8) | BIT(16));
		rf_reg18 = (rf_reg18 | central_ch);
#if 0
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
		/* Switch WLA */
		config_phydm_switch_rf_set_8195b(dm, SWITCH_TO_WLA);
#endif

		/*RF TXA_TANK LUT mode*/
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xdf, BIT(6), 0x0);
#endif
	} else {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Fail to switch band (ch: %d)\n", __func__,
			  central_ch);
		return false;
	}

	config_phydm_parameter_init_8195b(dm, ODM_PRE_RF_SET);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x18, RFREGOFFSETMASK, rf_reg18);
	config_phydm_parameter_init_8195b(dm, ODM_POST_RF_SET);

	if (phydm_rfe_8195b(dm, central_ch) == false)
		return false;

	if (rf_reg_status == false) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Fail to switch band (ch: %d), because writing RF register is fail\n",
			  __func__, central_ch);
		return false;
	}

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: Success to switch band (ch: %d)\n",
		  __func__, central_ch);
	return true;
}

__iram_odm_func__
boolean
config_phydm_switch_channel_8195b(
	struct dm_struct *dm,
	u8 central_ch)
{
	struct phydm_dig_struct *dig_t = &dm->dm_dig_table;
	u32 rf_reg18 = 0;
	boolean rf_reg_status = true;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]====================>\n", __func__);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: disable PHY API for debug!!\n", __func__);
		return true;
	}

	central_ch_8195b = central_ch;
	rf_reg18 = config_phydm_read_rf_reg_8195b(dm, RF_PATH_A, 0x18, RFREGOFFSETMASK);
	rf_reg_status = rf_reg_status & config_phydm_read_rf_check_8195b(rf_reg18);

	/* Switch band and channel */
	if (central_ch <= 14) {
		/* 2.4G */

		/* 1. RF band and channel*/
		rf_reg18 = (rf_reg18 & (~(BIT(17) | BIT(16) | MASKBYTE0)));
		rf_reg18 = (rf_reg18 & (~(BIT(19) | BIT(18) | MASKBYTE0)));
		rf_reg18 = (rf_reg18 | central_ch);

		/* 2. AGC table selection */
		odm_set_bb_reg(dm, R_0xc1c, 0x00000F00, 0x0);
		dig_t->agc_table_idx = 0x0;

		/* 3. Set central frequency for clock offset tracking */
		odm_set_bb_reg(dm, R_0x860, 0x1ffe0000, 0x96a);

		/* CCK TX filter parameters */
		if (central_ch == 14) {
			odm_set_bb_reg(dm, R_0xa20, MASKHWORD, 0xe82c);
			odm_set_bb_reg(dm, R_0xa24, MASKDWORD, 0x0000b81c);
			odm_set_bb_reg(dm, R_0xa28, MASKLWORD, 0x0000);
			odm_set_bb_reg(dm, R_0xa98, MASKHWORD, 0x0000);
			odm_set_bb_reg(dm, R_0xaac, MASKDWORD, 0x00003667);
		} else if (central_ch == 12){
			odm_set_bb_reg(dm, R_0xa20, MASKHWORD, 0x5998);
			odm_set_bb_reg(dm, R_0xa24, MASKDWORD, 0xf7ff8000);
			odm_set_bb_reg(dm, R_0xa28, MASKLWORD, 0x3205);
			odm_set_bb_reg(dm, R_0xa98, MASKHWORD, 0x27c0);
			odm_set_bb_reg(dm, R_0xaac, MASKDWORD, 0x12345677);
		} else if (central_ch == 13){
			odm_set_bb_reg(dm, R_0xa20, MASKHWORD, 0x099f);
			odm_set_bb_reg(dm, R_0xa24, MASKDWORD, 0x3a3090f0);
			odm_set_bb_reg(dm, R_0xa28, MASKLWORD, 0x3213);
			odm_set_bb_reg(dm, R_0xa98, MASKHWORD, 0x20b5);
			odm_set_bb_reg(dm, R_0xaac, MASKDWORD, 0x12345677);		
		} else {
			odm_set_bb_reg(dm, R_0xa20, MASKHWORD,
				       (rega20_8195b & MASKHWORD) >> 16);
			odm_set_bb_reg(dm, R_0xa24, MASKDWORD, rega24_8195b);
			odm_set_bb_reg(dm, R_0xa28, MASKLWORD,
				       (rega28_8195b & MASKLWORD));
			odm_set_bb_reg(dm, R_0xa98, MASKHWORD,
				       (rega98_8195b & MASKHWORD) >> 16);
			odm_set_bb_reg(dm, R_0xaac, MASKDWORD, regaac_8195b);
			//odm_set_bb_reg(dm, R_0xa20, MASKHWORD, 0x0000);
			//odm_set_bb_reg(dm, R_0xa24, MASKDWORD, 0x88f03454);
			//odm_set_bb_reg(dm, R_0xa28, MASKLWORD, 0x908c);
			//odm_set_bb_reg(dm, R_0xa98, MASKHWORD, 0x00ff);
			//odm_set_bb_reg(dm, R_0xaac, MASKDWORD, 0x01235677);
		}

	} else if (central_ch > 35) {
		/* 5G */

		/* 1. RF band and channel*/
		rf_reg18 = (rf_reg18 & (~(BIT(17) | BIT(16) | MASKBYTE0)));
		rf_reg18 = (rf_reg18 & (~(BIT(19) | BIT(18) | MASKBYTE0)));
		rf_reg18 = (rf_reg18 | BIT(16));

		rf_reg18 = (rf_reg18 | central_ch);

		if (central_ch >= 36 && central_ch <= 64)
			;
		else if ((central_ch >= 100) && (central_ch <= 140))
			rf_reg18 = (rf_reg18 | BIT(18));
		else if (central_ch > 140)
			rf_reg18 = (rf_reg18 | BIT(19));
		else {
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: Fail to switch channel (RF18) (ch: %d)\n",
				  __func__, central_ch);
			return false;
		}

		/* 2. AGC table selection */
		if (central_ch >= 36 && central_ch <= 64) {
			odm_set_bb_reg(dm, R_0xc1c, 0x00000F00, 0x1);
			dig_t->agc_table_idx = 0x1;
		} else if ((central_ch >= 100) && (central_ch <= 144)) {
			odm_set_bb_reg(dm, R_0xc1c, 0x00000F00, 0x2);
			dig_t->agc_table_idx = 0x2;
		} else if (central_ch >= 149) {
			odm_set_bb_reg(dm, R_0xc1c, 0x00000F00, 0x3);
			dig_t->agc_table_idx = 0x3;
		} else {
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: Fail to switch channel (AGC) (ch: %d)\n",
				  __func__, central_ch);
			return false;
		}

		/* 3. Set central frequency for clock offset tracking */
		if ((central_ch >= 36) && (central_ch <= 48))
			odm_set_bb_reg(dm, R_0x860, 0x1ffe0000, 0x494);
		else if ((central_ch >= 52) && (central_ch <= 64))
			odm_set_bb_reg(dm, R_0x860, 0x1ffe0000, 0x453);
		else if ((central_ch >= 100) && (central_ch <= 116))
			odm_set_bb_reg(dm, R_0x860, 0x1ffe0000, 0x452);
		else if ((central_ch >= 118) && (central_ch <= 177))
			odm_set_bb_reg(dm, R_0x860, 0x1ffe0000, 0x412);
		else {
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: Fail to switch channel (fc_area) (ch: %d)\n",
				  __func__, central_ch);
			return false;
		}

#if 0
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
		/*notch 5760 spur by CSI_MASK*/
		if (central_ch == 153)
			phydm_csi_mask_setting(dm, FUNC_ENABLE, (u32)central_ch, 20, 5760, PHYDM_DONT_CARE);
		else if (central_ch == 151)
			phydm_csi_mask_setting(dm, FUNC_ENABLE, (u32)central_ch, 40, 5760, PHYDM_DONT_CARE);
		else if (central_ch == 155)
			phydm_csi_mask_setting(dm, FUNC_ENABLE, (u32)central_ch, 80, 5760, PHYDM_DONT_CARE);
		else
			phydm_csi_mask_setting(dm, FUNC_DISABLE, (u32)central_ch, 80, 5760, PHYDM_DONT_CARE);
#endif
#endif
	} else {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Fail to switch band (ch: %d)\n", __func__,
			  central_ch);
		return false;
	}

	config_phydm_parameter_init_8195b(dm, ODM_PRE_RF_SET);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x18, RFREGOFFSETMASK, rf_reg18);
	config_phydm_parameter_init_8195b(dm, ODM_POST_RF_SET);

	if (rf_reg_status == false) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Fail to switch channel (ch: %d), because writing RF register is fail\n",
			  __func__, central_ch);
		return false;
	}

	if (phydm_rfe_8195b(dm, central_ch) == false)
		return false;

	phydm_ccapar_8195b(dm);

	phydm_igi_toggle_8195b(dm);

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "[%s]: Success to switch channel (ch: %d)\n", __func__,
		  central_ch);
	return true;
}

__iram_odm_func__
boolean
config_phydm_switch_bandwidth_8195b(
	struct dm_struct *dm,
	u8 primary_ch_idx,
	enum channel_width bandwidth)
{
	u32 rf_reg18;
	boolean rf_reg_status = true;
	u32 bb_reg8ac;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]===================>\n", __func__);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: disable PHY API for debug!!\n", __func__);
		return true;
	}

	/* Error handling */
	if (bandwidth >= CHANNEL_WIDTH_MAX || (bandwidth == CHANNEL_WIDTH_40 && primary_ch_idx > 2) || (bandwidth == CHANNEL_WIDTH_80 && primary_ch_idx > 4)) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Fail to switch bandwidth (bw: %d, primary ch: %d)\n",
			  __func__, bandwidth, primary_ch_idx);
		return false;
	}

	bw_8195b = bandwidth;
	rf_reg18 = config_phydm_read_rf_reg_8195b(dm, RF_PATH_A, 0x18, RFREGOFFSETMASK);
	rf_reg_status = rf_reg_status & config_phydm_read_rf_check_8195b(rf_reg18);

	/* Switch bandwidth */
	switch (bandwidth) {
	case CHANNEL_WIDTH_20: {
/* Small BW([7:6]) = 0, primary channel ([5:2]) = 0, rf mode([1:0]) = 20M */
#if 0
		odm_set_bb_reg(dm, R_0x8ac, MASKBYTE0, CHANNEL_WIDTH_20);

		/* ADC clock = 160M clock for BW20 */
		odm_set_bb_reg(dm, R_0x8ac, (BIT(9) | BIT(8)), 0x0);
		odm_set_bb_reg(dm, R_0x8ac, BIT(16), 0x1);

		/* DAC clock = 160M clock for BW20 */
		odm_set_bb_reg(dm, R_0x8ac, (BIT(21) | BIT(20)), 0x0);
		odm_set_bb_reg(dm, R_0x8ac, BIT(28), 0x1);
#endif
		bb_reg8ac = odm_get_bb_reg(dm, R_0x8ac, MASKDWORD);
		bb_reg8ac &= 0xffcffc00;
		bb_reg8ac |= 0x10010000;
		odm_set_bb_reg(dm, R_0x8ac, MASKDWORD, bb_reg8ac);

		/* ADC buffer clock */
		odm_set_bb_reg(dm, R_0x8c4, BIT(30), 0x1);

		/* RF bandwidth */
		rf_reg18 = (rf_reg18 | BIT(11) | BIT(10));

		/* Tx DFIR shaping */
		odm_set_bb_reg(dm, R_0xc10, (BIT(31) | BIT(30)), 0x0);

		break;
	}
	case CHANNEL_WIDTH_40: {
		/* Small BW([7:6]) = 0, primary channel ([5:2]) = sub-channel, rf mode([1:0]) = 40M */
		/*odm_set_bb_reg(dm, R_0x8ac, MASKBYTE0, (((primary_ch_idx & 0xf) << 2) | CHANNEL_WIDTH_40));*/

		/* CCK primary channel */
		if (primary_ch_idx == 1)
			odm_set_bb_reg(dm, R_0xa00, BIT(4), primary_ch_idx);
		else
			odm_set_bb_reg(dm, R_0xa00, BIT(4), 0);
#if 0
		/* ADC clock = 160M clock for BW40 */
		odm_set_bb_reg(dm, R_0x8ac, (BIT(11) | BIT(10)), 0x0);
		odm_set_bb_reg(dm, R_0x8ac, BIT(17), 0x1);

		/* DAC clock = 160M clock for BW20 */
		odm_set_bb_reg(dm, R_0x8ac, (BIT(23) | BIT(22)), 0x0);
		odm_set_bb_reg(dm, R_0x8ac, BIT(29), 0x1);
#endif
		bb_reg8ac = odm_get_bb_reg(dm, R_0x8ac, MASKDWORD);
		bb_reg8ac &= 0xff3ff300;
		bb_reg8ac |= 0x20020000 | ((primary_ch_idx & 0xf) << 2) | CHANNEL_WIDTH_40;
		odm_set_bb_reg(dm, R_0x8ac, MASKDWORD, bb_reg8ac);

		/* ADC buffer clock */
		odm_set_bb_reg(dm, R_0x8c4, BIT(30), 0x1);

		/* RF bandwidth */
		rf_reg18 = (rf_reg18 & (~(BIT(11) | BIT(10))));
		rf_reg18 = (rf_reg18 | BIT(11));

		/* Tx DFIR shaping */
		odm_set_bb_reg(dm, R_0xc10, (BIT(31) | BIT(30)), 0x0);

		break;
	}
	case CHANNEL_WIDTH_80: {
/* Small BW([7:6]) = 0, primary channel ([5:2]) = sub-channel, rf mode([1:0]) = 80M */
#if 0
		odm_set_bb_reg(dm, R_0x8ac, MASKBYTE0, (((primary_ch_idx & 0xf) << 2) | CHANNEL_WIDTH_80));

		/* ADC clock = 160M clock for BW80 */
		odm_set_bb_reg(dm, R_0x8ac, (BIT(13) | BIT(12)), 0x0);
		odm_set_bb_reg(dm, R_0x8ac, BIT(18), 0x1);

		/* DAC clock = 160M clock for BW20 */
		odm_set_bb_reg(dm, R_0x8ac, (BIT(25) | BIT(24)), 0x0);
		odm_set_bb_reg(dm, R_0x8ac, BIT(30), 0x1);
#endif
		bb_reg8ac = odm_get_bb_reg(dm, R_0x8ac, MASKDWORD);
		bb_reg8ac &= 0xfcffcf00;
		bb_reg8ac |= 0x40040000 | ((primary_ch_idx & 0xf) << 2) | CHANNEL_WIDTH_80;
		odm_set_bb_reg(dm, R_0x8ac, MASKDWORD, bb_reg8ac);

		/* ADC buffer clock */
		odm_set_bb_reg(dm, R_0x8c4, BIT(30), 0x1);

		/* RF bandwidth */
		rf_reg18 = (rf_reg18 & (~(BIT(11) | BIT(10))));
		rf_reg18 = (rf_reg18 | BIT(10));

		/* Tx DFIR shaping */
		odm_set_bb_reg(dm, R_0xc10, (BIT(31) | BIT(30)), 0x3);

		break;
	}
	case CHANNEL_WIDTH_5: {
/* Small BW([7:6]) = 1, primary channel ([5:2]) = 0, rf mode([1:0]) = 20M */
#if 0
		odm_set_bb_reg(dm, R_0x8ac, MASKBYTE0, (BIT(6) | CHANNEL_WIDTH_20));

		/* ADC clock = 40M clock */
		odm_set_bb_reg(dm, R_0x8ac, (BIT(9) | BIT(8)), 0x2);
		odm_set_bb_reg(dm, R_0x8ac, BIT(16), 0x0);

		/* DAC clock = 160M clock for BW20 */
		odm_set_bb_reg(dm, R_0x8ac, (BIT(21) | BIT(20)), 0x2);
		odm_set_bb_reg(dm, R_0x8ac, BIT(28), 0x0);
#endif
		bb_reg8ac = odm_get_bb_reg(dm, R_0x8ac, MASKDWORD);
		bb_reg8ac &= 0xefcefc00;
		bb_reg8ac |= (0x2 << 20) | (0x2 << 8) | BIT(6);
		odm_set_bb_reg(dm, R_0x8ac, MASKDWORD, bb_reg8ac);

		/* ADC buffer clock */
		odm_set_bb_reg(dm, R_0x8c4, BIT(30), 0x0);
		odm_set_bb_reg(dm, R_0x8c8, BIT(31), 0x1);

		/* RF bandwidth */
		rf_reg18 = (rf_reg18 | BIT(11) | BIT(10));

		/* Tx DFIR shaping */
		odm_set_bb_reg(dm, R_0xc10, (BIT(31) | BIT(30)), 0x0);

		break;
	}
	case CHANNEL_WIDTH_10: {
/* Small BW([7:6]) = 1, primary channel ([5:2]) = 0, rf mode([1:0]) = 20M */
#if 0
		odm_set_bb_reg(dm, R_0x8ac, MASKBYTE0, (BIT(7) | CHANNEL_WIDTH_20));

		/* ADC clock = 80M clock */
		odm_set_bb_reg(dm, R_0x8ac, (BIT(9) | BIT(8)), 0x3);
		odm_set_bb_reg(dm, R_0x8ac, BIT(16), 0x0);

		/* DAC clock = 160M clock for BW20 */
		odm_set_bb_reg(dm, R_0x8ac, (BIT(21) | BIT(20)), 0x3);
		odm_set_bb_reg(dm, R_0x8ac, BIT(28), 0x0);
#endif
		bb_reg8ac = odm_get_bb_reg(dm, R_0x8ac, MASKDWORD);
		bb_reg8ac &= 0xefcefc00;
		bb_reg8ac |= (0x3 << 20) | (0x3 << 8) | BIT(7);
		odm_set_bb_reg(dm, R_0x8ac, MASKDWORD, bb_reg8ac);

		/* ADC buffer clock */
		odm_set_bb_reg(dm, R_0x8c4, BIT(30), 0x0);
		odm_set_bb_reg(dm, R_0x8c8, BIT(31), 0x0);

		/* RF bandwidth */
		rf_reg18 = (rf_reg18 | BIT(11) | BIT(10));

		/* Tx DFIR shaping */
		odm_set_bb_reg(dm, R_0xc10, (BIT(31) | BIT(30)), 0x0);

		break;
	}
	default:
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Fail to switch bandwidth (bw: %d, primary ch: %d)\n",
			  __func__, bandwidth, primary_ch_idx);
	}

	/* Write RF18 register */
	config_phydm_parameter_init_8195b(dm, ODM_PRE_RF_SET);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x18, RFREGOFFSETMASK, rf_reg18);
	config_phydm_parameter_init_8195b(dm, ODM_POST_RF_SET);

	if (rf_reg_status == false) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Fail to switch bandwidth (bw: %d, primary ch: %d), because writing RF register is fail\n",
			  __func__, bandwidth, primary_ch_idx);
		return false;
	}

	/* Modify RX DFIR parameters */
	phydm_rxdfirpar_by_bw_8195b(dm, bandwidth);

	/* Modify CCA parameters */
	phydm_ccapar_by_bw_8195b(dm, bandwidth);
	phydm_ccapar_8195b(dm);

	phydm_igi_toggle_8195b(dm);

	/* Toggle RX path to avoid RX dead zone issue */
	/*odm_set_bb_reg(dm, R_0x808, MASKBYTE0, 0x0);*/
	/*odm_set_bb_reg(dm, R_0x808, MASKBYTE0, 0x11);*/

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "[%s]: Success to switch bandwidth (bw: %d, primary ch: %d)\n",
		  __func__, bandwidth, primary_ch_idx);
	return true;
}

__iram_odm_func__
boolean
config_phydm_csimask_BGA_8195b(struct dm_struct *dm,
			       u8 central_ch, enum channel_width bandwidth)
{
	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]===================>\n", __func__);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: disable PHY API for debug!!\n", __func__);
		return true;
	}

	/*Set CSI Mask RF Reg Begin*/
	config_phydm_parameter_init_8195b(dm, ODM_PRE_RF_SET);

	/* Reset CSI Mask */
	if (central_ch <= 14)
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
	else
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);

	odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x1);
	odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
	odm_set_bb_reg(dm, R_0x880, MASKDWORD, 0x0);
	odm_set_bb_reg(dm, R_0x884, MASKDWORD, 0x0);
	odm_set_bb_reg(dm, R_0x88c, MASKDWORD, 0x0);
	odm_set_bb_reg(dm, R_0x894, MASKDWORD, 0x0);
	odm_set_bb_reg(dm, R_0x898, MASKDWORD, 0x0);
	odm_set_bb_reg(dm, R_0x89c, MASKDWORD, 0x0);

	/* CSI Mask Setting */
	switch (bandwidth) {
	case CHANNEL_WIDTH_20: {
		switch (central_ch) {
		case 13:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(25) | BIT(26), 0x3);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 14:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(19), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 36:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 52:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(11), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 60:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(21), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 100:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(11), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 108:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(21), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 124:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(25), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 132:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(7), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 149:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(16), 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(16), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 153:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(5), 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(16), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 157:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(26), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 161:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		default:{
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: No CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
		}
		}
		break;
	}
	case CHANNEL_WIDTH_40: {
		switch (central_ch) {
		case 11:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x884, BIT(26), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 38:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x884, BIT(0), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 46:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x898, BIT(11), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 54:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(21), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 62:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x884, BIT(0), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 102:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(21), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 110:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x884, BIT(0), 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(0), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 118:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 126:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 134:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x884, BIT(0), 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(0), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 142:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x898, BIT(11), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 151:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(27), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 159:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x884, BIT(5), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		default:{
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: No CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
		}
		}

		break;
	}
	case CHANNEL_WIDTH_80: {
		switch (central_ch) {
		case 42:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x894, BIT(21), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 58:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(11), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 106:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(11), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 122:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x88c, BIT(0), 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(0), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 138:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x894, BIT(21), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 155:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(16), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}

		default:{
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: No CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
		}
		}
		break;
	}
	default:{
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: NO CSI Mask Required\n", __func__);
	}
	}
	/*Set CSI Mask RF Reg End*/
	config_phydm_parameter_init_8195b(dm, ODM_POST_RF_SET);

	return true;
}

__iram_odm_func__
boolean
config_phydm_csimask_QFN128_8195b(struct dm_struct *dm,
				  u8 central_ch, enum channel_width bandwidth)
{
	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]===================>\n", __func__);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: disable PHY API for debug!!\n", __func__);
		return true;
	}

	/*Set CSI Mask RF Reg Begin*/
	config_phydm_parameter_init_8195b(dm, ODM_PRE_RF_SET);

	/* Reset CSI Mask */
	if (central_ch <= 14)
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
	else
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);

	odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x1);
	odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
	odm_set_bb_reg(dm, R_0x880, MASKDWORD, 0x0);
	odm_set_bb_reg(dm, R_0x884, MASKDWORD, 0x0);
	odm_set_bb_reg(dm, R_0x88c, MASKDWORD, 0x0);
	odm_set_bb_reg(dm, R_0x894, MASKDWORD, 0x0);
	odm_set_bb_reg(dm, R_0x898, MASKDWORD, 0x0);
	odm_set_bb_reg(dm, R_0x89c, MASKDWORD, 0x0);

	/* CSI Mask Setting */
	switch (bandwidth) {
	case CHANNEL_WIDTH_20: {
		switch (central_ch) {
		case 13:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(26), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 14:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(19), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 36:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 52:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(11), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 60:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(21), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 100:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(11), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 108:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(21), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 112:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 124:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(25), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 132:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(7), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 144:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 149:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(16), 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(16), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 153:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(5), 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(16), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 157:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(26), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 161:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(16), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 165:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 169:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 173:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 177:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		default:{
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: No CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
		}
		}
		break;
	}
	case CHANNEL_WIDTH_40: {
		switch (central_ch) {
		case 11:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x884, BIT(26), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 38:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x884, BIT(0), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 46:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x898, BIT(11), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 54:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(21), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 62:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x884, BIT(0), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 102:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(21), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 110:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x884, BIT(0), 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(0), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 118:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 126:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 134:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x884, BIT(0), 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(0), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 142:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x898, BIT(11), 0x1);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 151:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(16), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 159:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 167:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 175:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x0);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		default:{
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: No CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
		}
		}

		break;
	}
	case CHANNEL_WIDTH_80: {
		switch (central_ch) {
		case 42:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x894, BIT(21), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 58:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(11), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 106:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(11), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 122:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x88c, BIT(0), 0x1);
			odm_set_bb_reg(dm, R_0x89c, BIT(0), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 138:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x894, BIT(21), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 155:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x880, BIT(16), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}
		case 171:{
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xa9, BIT4, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, RF_0xb4, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x874, BIT0, 0x1);
			odm_set_bb_reg(dm, R_0x88c, BIT(5), 0x1);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
			break;
		}

		default:{
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: No CSI Mask (bw: %d, ch: %d)\n",
				  __func__, bandwidth, central_ch);
		}
		}
		break;
	}
	default:{
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: NO CSI Mask Required\n", __func__);
	}
	}
	/*Set CSI Mask RF Reg End*/
	config_phydm_parameter_init_8195b(dm, ODM_POST_RF_SET);

	return true;
}

__iram_odm_func__
boolean
config_phydm_switch_csimask_8195b(struct dm_struct *dm,
				  u8 central_ch, enum channel_width bandwidth)
{
	boolean rf_reg_status = true;
	u32 ofst;
	u32 r830;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]===================>\n", __func__);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: disable PHY API for debug!!\n", __func__);
		return true;
	}

	/* CSI Mask Setting*/
	if (dm->package_type == 1 && dm->rfe_type == 0)
		config_phydm_csimask_QFN128_8195b(dm, central_ch, bandwidth);
	else
		config_phydm_csimask_BGA_8195b(dm, central_ch, bandwidth);

	/* FFT Sample Freq Setting */
	r830 = reg830_8195b;
	if (dm->package_type == 1 && dm->rfe_type == 0) {
		switch (bandwidth) {
		case CHANNEL_WIDTH_20: {
			odm_set_bb_reg(dm, R_0x8f0, BIT31, 0x0); //40MHz
			odm_set_bb_reg(dm, R_0x830, 0x3e000,
				       (r830 & 0x3e000) >> 13);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: Ch:%d FFT Freq: 40MHz)\n", __func__,
				  central_ch);
			break;
		}
		case CHANNEL_WIDTH_40: {
			odm_set_bb_reg(dm, R_0x8f0, BIT31, 0x0); //40MHz
			odm_set_bb_reg(dm, R_0x830, 0x7c0000,
				       (r830 & 0x7c0000) >> 18);
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: Ch:%d FFT Freq: 40MHz)\n", __func__,
				  central_ch);
			break;
		}
		default:{
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: NO FFT CLK Changed Required\n",
				  __func__);
			break;
		}
		}
	} else {
		ofst = 4;
		switch (bandwidth) {
		case CHANNEL_WIDTH_20: {
			switch (central_ch) {
			case 5:
			case 6:
			case 7:
			case 8:{
				odm_set_bb_reg(dm, R_0x8f0, BIT31, 0x1); //80MHz
				odm_set_bb_reg(dm, R_0x830, 0x3e000,
					       ((r830 & 0x3e000) >> 13)
					       + ofst);
				PHYDM_DBG(dm, ODM_PHY_CONFIG,
					  "[%s]: Ch:%d FFT Freq: 80MHz)\n",
					  __func__, central_ch);
				break;
			}
			default:{
				odm_set_bb_reg(dm, R_0x8f0, BIT31, 0x0); //40MHz
				odm_set_bb_reg(dm, R_0x830, 0x3e000,
					       (r830 & 0x3e000) >> 13);
				PHYDM_DBG(dm, ODM_PHY_CONFIG,
					  "[%s]: Ch:%d FFT Freq: 40MHz)\n",
					  __func__, central_ch);
				break;
			}
			}
			break;
		}
		case CHANNEL_WIDTH_40: {
			switch (central_ch) {
			case 3:
			case 4:
			case 5:
			case 6:
			case 7:
			case 8:
			case 9:
			case 10:{
				odm_set_bb_reg(dm, R_0x8f0, BIT31, 0x1); //80MHz
				odm_set_bb_reg(dm, R_0x830, 0x7c0000,
					       ((r830 & 0x7c0000) >> 18)
					       + ofst);
				PHYDM_DBG(dm, ODM_PHY_CONFIG,
					  "[%s]: Ch:%d FFT Freq: 80MHz)\n",
					  __func__, central_ch);
				break;
			}
			default:{
				odm_set_bb_reg(dm, R_0x8f0, BIT31, 0x0); //40MHz
				odm_set_bb_reg(dm, R_0x830, 0x7c0000,
					       (r830 & 0x7c0000) >> 18);
				PHYDM_DBG(dm, ODM_PHY_CONFIG,
					  "[%s]: Ch:%d FFT Freq: 40MHz)\n",
					  __func__, central_ch);
				break;
			}
			}
			break;
		}
		default:{
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: NO FFT CLK Changed Required\n",
				  __func__);
			break;
		}
		}
	}

	/* NBI Setting */
	switch (bandwidth) {
	case CHANNEL_WIDTH_20: {
		switch (central_ch) {
		case 14:{
			odm_set_bb_reg(dm, R_0xc20, BIT28, 0x1);
			odm_set_bb_reg(dm, R_0x878, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x87c, 0xfc000, 0x5);
			break;
		}
		default:{
			odm_set_bb_reg(dm, R_0xc20, BIT28, 0x0);
			odm_set_bb_reg(dm, R_0x878, BIT0, 0x0);
			odm_set_bb_reg(dm, R_0x87c, 0xfc000, 0x3F);
			break;
		}
		}
		break;
	}
	default:{
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: NO NBI Required\n", __func__);
		break;
	}
	}

	return true;
}

__iram_odm_func__
boolean
config_phydm_switch_bbpowercut_8195b(struct dm_struct *dm,
				     u8 central_ch,
				     enum channel_width bandwidth)
{
	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]===================>\n", __func__);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: disable PHY API for debug!!\n", __func__);
		return true;
	}

	/* Error handling */
	if (bandwidth >= CHANNEL_WIDTH_MAX) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Bandwidth Error (bw: %d)\n", __func__,
			  bandwidth);
		return false;
	}

	if (central_ch <= 14) { /* 2.4G */
		if (bandwidth == CHANNEL_WIDTH_20)
			odm_set_mac_reg(dm, R_0x24, (BIT2 | BIT1 | BIT0), 0x0);
		else
			odm_set_mac_reg(dm, R_0x24, (BIT2 | BIT1 | BIT0), 0x0);
	} else if (central_ch > 35) { /* 5G */
		odm_set_mac_reg(dm, R_0x24, (BIT2 | BIT1 | BIT0), 0x0);
	} else {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Fail Set BB Power Cut (ch: %d, BW: %d)\n",
			  __func__, central_ch, bandwidth);
		return false;
	}

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "[%s]: Success to Set BB Power Cut (ch: %d, BW: %d)\n",
		  __func__, central_ch, bandwidth);
	return true;
}

__iram_odm_func__
boolean
config_phydm_switch_channel_bw_8195b(
	struct dm_struct *dm,
	u8 central_ch,
	u8 primary_ch_idx,
	enum channel_width bandwidth)
{
	/* Switch band */
	if (config_phydm_switch_band_8195b(dm, central_ch) == false)
		return false;

	/* Switch channel */
	if (config_phydm_switch_channel_8195b(dm, central_ch) == false)
		return false;

	/* Switch bandwidth */
	if (config_phydm_switch_bandwidth_8195b(dm, primary_ch_idx, bandwidth) == false)
		return false;

	/* Switch CSI Mask*/
	if (!config_phydm_switch_csimask_8195b(dm, central_ch, bandwidth))
		return false;

	/* Switch bb powercut */
	if (!config_phydm_switch_bbpowercut_8195b(dm, central_ch, bandwidth))
		return false;

	return true;
}

__iram_odm_func__
boolean
config_phydm_trx_mode_8195b(
	struct dm_struct *dm,
	enum bb_path tx_path,
	enum bb_path rx_path,
	boolean is_tx2_path)
{
	return true;
}

__iram_odm_func__
boolean
config_phydm_parameter_init_8195b(
	struct dm_struct *dm,
	enum odm_parameter_init type)
{
	if (type == ODM_PRE_SETTING) {
		OFDMCCA_8195b = (u8)odm_get_bb_reg(dm, R_0x838, BIT(1));
		CCKCCA_8195b = (u8)odm_get_bb_reg(dm, R_0xa14,
						  (BIT(9) | BIT(8)));
		odm_set_bb_reg(dm, R_0x838, BIT(1), 0x1);
		odm_set_bb_reg(dm, R_0xa14, (BIT(9) | BIT(8)), 0x3);
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Pre setting: disable OFDM and CCK CCA Cap.\n",
			  __func__);
	} else if (type == ODM_POST_SETTING) {
		odm_set_bb_reg(dm, R_0x808, (BIT(28) | BIT(29)), 0x3);
		odm_set_bb_reg(dm, R_0x838, BIT(1), OFDMCCA_8195b);
		odm_set_bb_reg(dm, R_0xa14, (BIT(9) | BIT(8)), CCKCCA_8195b);
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Post setting: enable OFDM and CCK block\n",
			  __func__);
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Post setting: enable OFDM and CCK CCA Cap.\n",
			  __func__);
		rega20_8195b = odm_get_bb_reg(dm, R_0xa20, MASKDWORD);
		rega24_8195b = odm_get_bb_reg(dm, R_0xa24, MASKDWORD);
		rega28_8195b = odm_get_bb_reg(dm, R_0xa28, MASKDWORD);
		rega98_8195b = odm_get_bb_reg(dm, R_0xa98, MASKDWORD);
		regaac_8195b = odm_get_bb_reg(dm, R_0xaac, MASKDWORD);
		reg830_8195b = odm_get_bb_reg(dm, R_0x830, MASKDWORD); //MF TH
	} else if (type == ODM_PRE_RF_SET) {
		OFDMCCA_8195b = (u8)odm_get_bb_reg(dm, R_0x838, BIT(1));
		CCKCCA_8195b = (u8)odm_get_bb_reg(dm, R_0xa14,
						  (BIT(9) | BIT(8)));
		BLOCK_8195b = (u8)odm_get_bb_reg(dm, R_0x808,
						 (BIT(29) | BIT(28)));
		odm_set_bb_reg(dm, R_0x838, BIT(1), 0x1);
		odm_set_bb_reg(dm, R_0xa14, (BIT(9) | BIT(8)), 0x3);
		odm_set_bb_reg(dm, R_0x808, BIT(28), 0x0); //CCK Off
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Pre RF Set: disable CCK block and OFDM CCA Cap.\n",
			  __func__);
	} else if (type == ODM_POST_RF_SET) {
		odm_set_bb_reg(dm, R_0x838, BIT(1), OFDMCCA_8195b);
		odm_set_bb_reg(dm, R_0xa14, (BIT(9) | BIT(8)), CCKCCA_8195b);
		odm_set_bb_reg(dm, R_0x808, (BIT(29) | BIT(28)), BLOCK_8195b);
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Post RF Set: enable CCK block and OFDM CCA Cap.\n",
			  __func__);
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
	} else if (type == ODM_INIT_FW_SETTING) {
		u8 h2c_content[4] = {0};

		h2c_content[0] = dm->rfe_type_expand;
		h2c_content[1] = dm->rf_type;
		h2c_content[2] = dm->cut_version;
		h2c_content[3] = (dm->tx_ant_status << 4) | dm->rx_ant_status;

		odm_fill_h2c_cmd(dm, PHYDM_H2C_FW_GENERAL_INIT, 4, h2c_content);
#endif
	} else {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: Wrong type!!\n", __func__);
		return false;
	}

	return true;
}
#if 0
__iram_odm_func__
void
config_phydm_switch_rf_set_8195b(
	struct dm_struct			*dm,
	u8				rf_set
)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
#if (DM_ODM_SUPPORT_TYPE == ODM_WIN)
	void		*adapter	= dm->adapter;
	PMGNT_INFO			mgnt_info = &(((PADAPTER)(adapter))->MgntInfo);
#endif

	u32		bb_reg32;

	odm_set_bb_reg(dm, R_0x1080, BIT(16), 0x1);
	odm_set_bb_reg(dm, R_0x00, BIT(26), 0x1);
	/*odm_set_mac_reg(dm, R_0x70, BIT(26), 0x1);*/
	/*odm_set_mac_reg(dm, R_0x1704, MASKLWORD, 0x4000);*/
	/*odm_set_mac_reg(dm, R_0x1700, (BIT(31) | BIT(30)), 0x3); */

	bb_reg32 = odm_get_bb_reg(dm, R_0xcb8, MASKDWORD);
	switch (rf_set) {
	case SWITCH_TO_BTG:

		dm->current_rf_set_8195b = SWITCH_TO_BTG;

		bb_reg32 = (bb_reg32 | BIT(16));
		bb_reg32 &= (~(BIT(18) | BIT(20) | BIT(21) | BIT(22) | BIT(23)));
		odm_set_bb_reg(dm, R_0xa84, MASKBYTE2, 0xe);
		odm_set_bb_reg(dm, R_0xa80, MASKLWORD, 0xfc84);

#if (DM_ODM_SUPPORT_TYPE == ODM_WIN)
		if (*dm->mp_mode == true && mgnt_info->RegPHYParaFromFolder == 0)
#else
		if (*dm->mp_mode == true)
#endif
		{
			odm_set_bb_reg(dm, R_0xaa8, 0x1f0000, 0x14);
			odm_config_bb_with_header_file(dm, CONFIG_BB_AGC_TAB_DIFF);
			/*Toggle initial gain twice for valid gain table*/
			odm_set_bb_reg(dm, ODM_REG(IGI_A, dm), ODM_BIT(IGI, dm), 0x22);
			odm_set_bb_reg(dm, ODM_REG(IGI_A, dm), ODM_BIT(IGI, dm), 0x20);
		}
		break;
	case SWITCH_TO_WLG:

		dm->current_rf_set_8195b = SWITCH_TO_WLG;

		bb_reg32 = (bb_reg32 | BIT(20) | BIT(21) | BIT(22));
		bb_reg32 &= (~(BIT(16) | BIT(18) | BIT(23)));
		odm_set_bb_reg(dm, R_0xa84, MASKBYTE2, 0x12);
		odm_set_bb_reg(dm, R_0xa80, MASKLWORD, 0x7532);

#if (DM_ODM_SUPPORT_TYPE == ODM_WIN)
		if (*dm->mp_mode == true && mgnt_info->RegPHYParaFromFolder == 0)
#else
		if (*dm->mp_mode == true)
#endif
		{
			odm_set_bb_reg(dm, R_0xaa8, 0x1f0000, 0x13);
			odm_config_bb_with_header_file(dm, CONFIG_BB_AGC_TAB_DIFF);
			/*Toggle initial gain twice for valid gain table*/
			odm_set_bb_reg(dm, ODM_REG(IGI_A, dm), ODM_BIT(IGI, dm), 0x22);
			odm_set_bb_reg(dm, ODM_REG(IGI_A, dm), ODM_BIT(IGI, dm), 0x20);
		}
		break;
	case SWITCH_TO_WLA:

		dm->current_rf_set_8195b = SWITCH_TO_WLA;

		bb_reg32 = (bb_reg32 | BIT(20) | BIT(22) | BIT(23));
		bb_reg32 &= (~(BIT(16) | BIT(18) | BIT(21)));

		break;
	case SWITCH_TO_BT:

		dm->current_rf_set_8195b = SWITCH_TO_BT;

		break;
	default:
		break;
	}

	odm_set_bb_reg(dm, R_0xcb8, MASKDWORD, bb_reg32);
#endif
}

__iram_odm_func__
void
config_phydm_set_ant_path(struct dm_struct *dm, u8 rf_set, u8 ant_num)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
	boolean		switch_polarity_inverse = false;
	u8			regval_0xcb7 = 0;

	dm->current_ant_num_8195b = ant_num;
	config_phydm_switch_rf_set_8195b(dm, rf_set);

	if (rf_set == SWITCH_TO_BT)
		phydm_set_gnt_state_8195b(dm, false, true); /* GNT_WL=0, GNT_BT=1 for BT test */
	else
		phydm_set_gnt_state_8195b(dm, true, false); /* GNT_WL=1, GNT_BT=0 for WL test */

	/*switch does not exist*/
	if (dm->rfe_type_expand == 0x5 || dm->rfe_type_expand == 0x6 ||
		dm->rfe_type_expand == 0x25 || dm->rfe_type_expand == 0x26 ||
		dm->rfe_type_expand == 0x2a || dm->rfe_type_expand == 0x2d ||
		dm->rfe_type_expand == 0x2e)
		return;

	if (dm->current_ant_num_8195b) /*Ant1 = 0, Ant2 = 1*/
		switch_polarity_inverse = !switch_polarity_inverse;

	if (rf_set == SWITCH_TO_WLG)
		switch_polarity_inverse = !switch_polarity_inverse;

	/*set antenna control by WL 0xcb4[29:28]*/
	odm_set_bb_reg(dm, R_0x4c, BIT(24) | BIT(23), 0x2);

	/*set RFE_ctrl8 and RFE_ctrl9 as antenna control pins by software*/
	odm_set_bb_reg(dm, R_0xcb4, 0x000000ff, 0x77);

	/*0xcb4[29:28] = 2b'01 for no switch_polatiry_inverse, DPDT_SEL_N =1, DPDT_SEL_P =0*/
	regval_0xcb7 = (switch_polarity_inverse == false ? 0x1 : 0x2);

	odm_set_bb_reg(dm, R_0xcb4, 0x30000000, regval_0xcb7);
#endif
}
#endif
__iram_odm_func__
u32 query_phydm_trx_capability_8195b(
	struct dm_struct *dm)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
	u32 value32 = 0x00000000;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: trx_capability = 0x%x\n", __func__,
		  value32);
	return value32;
#else
	return 0;
#endif
}

__iram_odm_func__
u32 query_phydm_stbc_capability_8195b(
	struct dm_struct *dm)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
	u32 value32 = 0x00010001;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: stbc_capability = 0x%x\n",
		  __func__, value32);
	return value32;
#else
	return 0;
#endif
}

__iram_odm_func__
u32 query_phydm_ldpc_capability_8195b(
	struct dm_struct *dm)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
	u32 value32 = 0x01000100;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: ldpc_capability = 0x%x\n",
		  __func__, value32);
	return value32;
#else
	return 0;
#endif
}

__iram_odm_func__
u32 query_phydm_txbf_parameters_8195b(
	struct dm_struct *dm)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
	u32 value32 = 0x00030003;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: txbf_parameters = 0x%x\n",
		  __func__, value32);
	return value32;
#else
	return 0;
#endif
}

__iram_odm_func__
u32 query_phydm_txbf_capability_8195b(
	struct dm_struct *dm)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
	u32 value32 = 0x01010001;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: txbf_capability = 0x%x\n",
		  __func__, value32);
	return value32;
#else
	return 0;
#endif
}
#if 0
__iram_odm_func__
u8
query_phydm_default_rf_set_8195b(
	struct dm_struct				*dm
)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
	return dm->default_rf_set_8195b;
#else
	return 0;
#endif
}

__iram_odm_func__
u8
query_phydm_current_rf_set_8195b(
	struct dm_struct				*dm
)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
	return dm->current_rf_set_8195b;
#else
	return 0;
#endif
}

__iram_odm_func__
u8
query_phydm_rfetype_8195b(
	struct dm_struct				*dm
)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
	return dm->rfe_type_expand;
#else
	return 0;
#endif
}

__iram_odm_func__
u8
query_phydm_current_ant_num_8195b(
	struct dm_struct				*dm
)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
	u32				regval_0xcb4 = odm_get_bb_reg(dm, R_0xcb4, BIT(29) | BIT(28));

	if (dm->current_rf_set_8195b == SWITCH_TO_BTG || dm->current_rf_set_8195b == SWITCH_TO_WLA || dm->current_rf_set_8195b == SWITCH_TO_BT) {
		if (regval_0xcb4 == 1)
			dm->current_ant_num_8195b = SWITCH_TO_ANT1;
		else if (regval_0xcb4 == 2)
			dm->current_ant_num_8195b = SWITCH_TO_ANT2;
	else
		if (regval_0xcb4 == 1)
			dm->current_ant_num_8195b = SWITCH_TO_ANT2;
		else if (regval_0xcb4 == 2)
			dm->current_ant_num_8195b = SWITCH_TO_ANT1;
	}

	return dm->current_ant_num_8195b;
#else
	return 0;
#endif
}

__iram_odm_func__
u8
query_phydm_ant_num_map_8195b(
	struct dm_struct				*dm
)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8195B == 1)
	u8		mapping_table = 0;

	/* mapping table meaning
	1: choose ant1 or ant2
	2: only ant1
	3: only ant2
	4: cannot choose
	*/

	if (dm->rfe_type_expand == 0 || dm->rfe_type_expand == 7 || dm->rfe_type_expand == 0x20 ||
		dm->rfe_type_expand == 0x27 || dm->rfe_type_expand == 0x28 || dm->rfe_type_expand == 0x2f)
		mapping_table = 1;
	else if (dm->rfe_type_expand == 1 || dm->rfe_type_expand == 2 || dm->rfe_type_expand == 0x21 ||
		dm->rfe_type_expand == 0x22 || dm->rfe_type_expand == 0x29 || dm->rfe_type_expand == 0x2a)
		mapping_table = 2;
	else if (dm->rfe_type_expand == 3 || dm->rfe_type_expand == 4 || dm->rfe_type_expand == 0x23 ||
		dm->rfe_type_expand == 0x24 || dm->rfe_type_expand == 0x2b || dm->rfe_type_expand == 0x2c)
		mapping_table = 3;
	else if (dm->rfe_type_expand == 5 || dm->rfe_type_expand == 6 || dm->rfe_type_expand == 0x25 ||
		dm->rfe_type_expand == 0x26 || dm->rfe_type_expand == 0x2d || dm->rfe_type_expand == 0x2e)
		mapping_table = 4;

	return mapping_table;
#else
	return 0;
#endif
}
#endif
/* ======================================================================== */
#endif /*PHYDM_FW_API_ENABLE_8195B == 1*/
#endif /* RTL8195B_SUPPORT == 1 */
