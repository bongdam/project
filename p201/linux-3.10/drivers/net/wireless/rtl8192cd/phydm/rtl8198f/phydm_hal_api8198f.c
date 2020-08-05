/******************************************************************************
 *
 * Copyright(c) 2007 - 2017  Realtek Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in the
 * file called LICENSE.
 *
 * Contact Information:
 * wlanfae <wlanfae@realtek.com>
 * Realtek Corporation, No. 2, Innovation Road II, Hsinchu Science Park,
 * Hsinchu 300, Taiwan.
 *
 * Larry Finger <Larry.Finger@lwfinger.net>
 *
 *****************************************************************************/
#include "mp_precomp.h"
#include "../phydm_precomp.h"

#if (RTL8198F_SUPPORT == 1)
#if (PHYDM_FW_API_ENABLE_8198F == 1)
/* ======================================================================== */
/* These following functions can be used for PHY DM only*/

enum channel_width bw_8198f;
u8 central_ch_8198f;
u8 central_ch_8198f_drp;

#if !(DM_ODM_SUPPORT_TYPE == ODM_CE)
u32 cca_ifem_bcut_98f[3][4] = {
	{0x75D97010, 0x75D97010, 0x75D97010, 0x75D97010}, /*Reg82C*/
	{0x79a0ea2a, 0x79a0ea2a, 0x79a0ea2a, 0x79a0ea2a}, /*Reg830*/
	{0x87766441, 0x87746341, 0x87765541, 0x87746341} /*Reg838*/
};
u32 cca_efem_bcut_98f[3][4] = {
	{0x75B76010, 0x75B76010, 0x75B76010, 0x75B75010}, /*Reg82C*/
	{0x79a0ea2a, 0x79a0ea2a, 0x79a0ea2a, 0x79a0ea2a}, /*Reg830*/
	{0x87766451, 0x87766431, 0x87766451, 0x87766431} /*Reg838*/
};
#endif

u32 cca_ifem_ccut_98f[3][4] = {
	{0x75C97010, 0x75C97010, 0x75C97010, 0x75C97010}, /*Reg82C*/
	{0x79a0eaaa, 0x79A0EAAC, 0x79a0eaaa, 0x79a0eaaa}, /*Reg830*/
	{0x87765541, 0x87746341, 0x87765541, 0x87746341} /*Reg838*/
};
u32 cca_efem_ccut_98f[3][4] = {
	{0x75B86010, 0x75B76010, 0x75B86010, 0x75B76010}, /*Reg82C*/
	{0x79A0EAA8, 0x79A0EAAC, 0x79A0EAA8, 0x79a0eaaa}, /*Reg830*/
	{0x87766451, 0x87766431, 0x87766451, 0x87766431} /*Reg838*/
};
u32 cca_ifem_ccut_rfetype_98f[3][4] = {
	{0x75da8010, 0x75da8010, 0x75da8010, 0x75da8010}, /*Reg82C*/
	{0x79a0eaaa, 0x97A0EAAC, 0x79a0eaaa, 0x79a0eaaa}, /*Reg830*/
	{0x87765541, 0x86666341, 0x87765561, 0x86666361} /*Reg838*/
};

__iram_odm_func__
boolean phydm_chk_pkg_set_valid_8198f(struct dm_struct *dm,
				      u8 ver_bb, u8 ver_rf)
{
	boolean valid = true;

#if 0
	if (ver_bb >= ver_1 && ver_rf < ver_2)
		valid = false;

	if (!valid) {
		odm_set_bb_reg(dm, R_0x1c3c, (BIT(0) | BIT(1)), 0x0);
		pr_debug("[Warning][%s] Pkg_ver{bb, rf}={%d, %d} disable all BB block\n",
			 __func__, ver_bb, ver_rf);
	}
#endif

	return valid;
}

__iram_odm_func__
void phydm_igi_toggle_8198f(
	struct dm_struct *dm)
{
	u32 igi = 0x20;

	igi = odm_get_bb_reg(dm, R_0x1d70, 0x7f);
	odm_set_bb_reg(dm, R_0x1d70, 0x7f, (igi - 2)); /*path0*/
	odm_set_bb_reg(dm, R_0x1d70, 0x7f, igi);
	odm_set_bb_reg(dm, R_0x1d70, 0x7f00, (igi - 2)); /*path1*/
	odm_set_bb_reg(dm, R_0x1d70, 0x7f00, igi);
	odm_set_bb_reg(dm, R_0x1d70, 0x7f0000, (igi - 2)); /*path2*/
	odm_set_bb_reg(dm, R_0x1d70, 0x7f0000, igi);
	odm_set_bb_reg(dm, R_0x1d70, 0x7f000000, (igi - 2)); /*path3*/
	odm_set_bb_reg(dm, R_0x1d70, 0x7f000000, igi);
}

__iram_odm_func__
void phydm_8198f_type15_rfe(
	struct dm_struct *dm,
	u8 channel)
{
#if 0
	if (channel <= 14) {
		/* signal source */
		odm_set_bb_reg(dm, R_0xcb0, 0xffffff, 0x777777);
		odm_set_bb_reg(dm, R_0xeb0, 0xffffff, 0x777777);
		odm_set_bb_reg(dm, R_0xcb4, MASKBYTE1, 0x77);
		odm_set_bb_reg(dm, R_0xeb4, MASKBYTE1, 0x77);
	} else if ((channel > 35) && (channel <= 64)) {
		/* signal source */
		odm_set_bb_reg(dm, R_0xcb0, 0xffffff, 0x777747);
		odm_set_bb_reg(dm, R_0xeb0, 0xffffff, 0x777747);
		odm_set_bb_reg(dm, R_0xcb4, MASKBYTE0, 0x57);
		odm_set_bb_reg(dm, R_0xeb4, MASKBYTE0, 0x57);
	} else if (channel > 64) {
		/* signal source */
		odm_set_bb_reg(dm, R_0xcb0, 0xffffff, 0x777747);
		odm_set_bb_reg(dm, R_0xeb0, 0xffffff, 0x777747);
		odm_set_bb_reg(dm, R_0xcb4, MASKBYTE0, 0x75);
		odm_set_bb_reg(dm, R_0xeb4, MASKBYTE0, 0x75);
	} else
		return;

	/* inverse or not */
	odm_set_bb_reg(dm, R_0xcbc, 0x3f, 0x0);
	odm_set_bb_reg(dm, R_0xcbc, (BIT(11) | BIT(10) | BIT(9) | BIT(8)), 0x0);
	odm_set_bb_reg(dm, R_0xebc, 0x3f, 0x0);
	odm_set_bb_reg(dm, R_0xebc, (BIT(11) | BIT(10) | BIT(9) | BIT(8)), 0x0);

	/* antenna switch table */
	if (channel <= 14) {
		if (dm->rx_ant_status == BB_PATH_AB || dm->tx_ant_status == BB_PATH_AB) {
			/* 2TX or 2RX */
			odm_set_bb_reg(dm, R_0xca0, MASKLWORD, 0xa501);
			odm_set_bb_reg(dm, R_0xea0, MASKLWORD, 0xa501);
		} else if (dm->rx_ant_status == dm->tx_ant_status) {
			/* TXA+RXA or TXB+RXB */
			odm_set_bb_reg(dm, R_0xca0, MASKLWORD, 0xa500);
			odm_set_bb_reg(dm, R_0xea0, MASKLWORD, 0xa500);
		} else {
			/* TXB+RXA or TXA+RXB */
			odm_set_bb_reg(dm, R_0xca0, MASKLWORD, 0xa005);
			odm_set_bb_reg(dm, R_0xea0, MASKLWORD, 0xa005);
		}
	} else if (channel > 35) {
		odm_set_bb_reg(dm, R_0xca0, MASKLWORD, 0xa5a5);
		odm_set_bb_reg(dm, R_0xea0, MASKLWORD, 0xa5a5);
	}
#endif
}

__iram_odm_func__
u32 phydm_check_bit_mask_8198f(u32 bit_mask, u32 data_original, u32 data)
{
	u8 bit_shift;
	if (bit_mask != 0xfffff) {
		for (bit_shift = 0; bit_shift <= 19; bit_shift++) {
			if (((bit_mask >> bit_shift) & 0x1) == 1)
				break;
		}
		return ((data_original) & (~bit_mask)) | (data << bit_shift);
	}

	return data;
}

__iram_odm_func__
void phydm_rfe_8198f_efem(struct dm_struct *dm, u8 channel)
{
	boolean is_channel_2g = (channel <= 14) ? true : false;
	u8 rfe_type = dm->rfe_type;

	if (rfe_type == 1) {
		odm_set_mac_reg(dm, R_0x40, MASKDWORD, 0x5000000);
		odm_set_mac_reg(dm, R_0x64, MASKDWORD, 0x36270000);
		odm_set_bb_reg(dm, R_0x1c94, MASKDWORD, 0xffffffff);
		odm_set_bb_reg(dm, R_0x1c98, MASKDWORD, 0xfa50e4);
		/*A*/
		odm_set_bb_reg(dm, R_0x186c, MASKDWORD, 0x24000002);
		odm_set_bb_reg(dm, R_0x1838, MASKDWORD, 0x1004c00);
		odm_set_bb_reg(dm, R_0x1840, MASKDWORD, 0x77427770);
		odm_set_bb_reg(dm, R_0x1844, MASKDWORD, 0x77777777);
		/*B*/
		odm_set_bb_reg(dm, R_0x416c, MASKDWORD, 0x24000002);
		odm_set_bb_reg(dm, R_0x4138, MASKDWORD, 0x1004c00);
		odm_set_bb_reg(dm, R_0x4140, MASKDWORD, 0x42777707);
		odm_set_bb_reg(dm, R_0x4144, MASKDWORD, 0x77777777);
		/*C*/
		odm_set_bb_reg(dm, R_0x526c, MASKDWORD, 0x24000002);
		odm_set_bb_reg(dm, R_0x5238, MASKDWORD, 0x1004c00);
		odm_set_bb_reg(dm, R_0x5240, MASKDWORD, 0x77777077);
		odm_set_bb_reg(dm, R_0x5244, MASKDWORD, 0x77777742);
		/*D*/
		odm_set_bb_reg(dm, R_0x536c, MASKDWORD, 0x24000002);
		odm_set_bb_reg(dm, R_0x5338, MASKDWORD, 0x1004c00);
		odm_set_bb_reg(dm, R_0x5340, MASKDWORD, 0x77770777);
		odm_set_bb_reg(dm, R_0x5344, MASKDWORD, 0x77774277);
	} else if (rfe_type == 3) {
		odm_set_mac_reg(dm, R_0x1c94, MASKDWORD, 0xFFFFFFFF);
		odm_set_mac_reg(dm, R_0x1c98, MASKDWORD, 0x00FA50E4);
		/*TRSW LUT and rfm trsw for path A*/
		odm_set_mac_reg(dm, R_0x186c, MASKDWORD, 0x24000002);
		/*rfm PAPE and TRSW for path A*/
		odm_set_mac_reg(dm, R_0x1838, MASKDWORD, 0x01004E00);
		/*inv rfm trswfor path A*/
		odm_set_mac_reg(dm, R_0x183c, MASKDWORD, 0x00000010);
		/*TRSW LUT and rfm trsw for path B*/
		odm_set_mac_reg(dm, R_0x416c, MASKDWORD, 0x24000002);
		/*rfm PAPE and TRSW for path B*/
		odm_set_mac_reg(dm, R_0x4138, MASKDWORD, 0x01004E00);
		/*inv rfm trsw for path B*/
		odm_set_mac_reg(dm, R_0x413c, MASKDWORD, 0x00000040);
		/*TRSW LUT and rfm trsw for path C*/
		odm_set_mac_reg(dm, R_0x526c, MASKDWORD, 0x24000002);
		/*rfm PAPE and TRSW for path C*/
		odm_set_mac_reg(dm, R_0x5238, MASKDWORD, 0x01004E00);
		/*inv rfm trsw for path C */
		odm_set_mac_reg(dm, R_0x523c, MASKDWORD, 0x00000100);
		/*TRSW LUT and rfm trsw for path C*/
		odm_set_mac_reg(dm, R_0x536c, MASKDWORD, 0x24000002);
		/*rfm PAPE and TRSW for path C*/
		odm_set_mac_reg(dm, R_0x5338, MASKDWORD, 0x01004E00);
		/*inv rfm trsw for path C */
		odm_set_mac_reg(dm, R_0x533c, MASKDWORD, 0x00000400);
		/*A*/
		odm_set_mac_reg(dm, R_0x1840, MASKDWORD, 0x77247770);
		odm_set_mac_reg(dm, R_0x1844, MASKDWORD, 0x77777777);
		/*B*/
		odm_set_mac_reg(dm, R_0x4140, MASKDWORD, 0x24777707);
		odm_set_mac_reg(dm, R_0x4144, MASKDWORD, 0x77777777);
		/*C*/
		odm_set_mac_reg(dm, R_0x5240, MASKDWORD, 0x77777077);
		odm_set_mac_reg(dm, R_0x5244, MASKDWORD, 0x77777724);
		/*D*/
		odm_set_mac_reg(dm, R_0x5340, MASKDWORD, 0x77770777);
		odm_set_mac_reg(dm, R_0x5344, MASKDWORD, 0x77772477);
	} else {
		/*Default setting -> should be moved to PHY REG*/
		/*signal source*/
		odm_set_bb_reg(dm, R_0x1840, MASKDWORD, 0x77027770); /*path A*/
		odm_set_bb_reg(dm, R_0x4140, MASKDWORD, 0x02777707); /*path B*/
		odm_set_bb_reg(dm, R_0x5240, MASKDWORD, 0x77777702); /*path C*/
		odm_set_bb_reg(dm, R_0x5244, MASKDWORD, 0x02777707); /*path C*/
		odm_set_bb_reg(dm, R_0x5340, MASKDWORD, 0x77777702); /*path D*/
		odm_set_bb_reg(dm, R_0x5344, MASKDWORD, 0x02777707); /*path D*/

		/* path select setting*/
		/*all paths common setting*/
		odm_set_bb_reg(dm, R_0x1c98, MASKDWORD, 0x00fa50e4);
	}
}

__iram_odm_func__
void phydm_rfe_8198f_setting(
	void *dm_void,
	u8 rfe_num,
	u8 path_mux_sel,
	u8 inv_en,
	u8 source_sel)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "8198F RFE[%d]:{Path=0x%x}{inv_en=%d}{source=0x%x}\n",
		  rfe_num, path_mux_sel, inv_en, source_sel);

	if (rfe_num > 19 || rfe_num < 0) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "[Warning] Wrong RFE num=%d}\n",
			  rfe_num);
		return;
	}

	/*[Path_mux_sel] */ /*ref_num 0~15, 0x1990->0x1c98;ref_num 16~19, 0x1990 -> 0x1c9c*/
	if (rfe_num < 16) {
		if (path_mux_sel == BB_PATH_A)
			odm_set_bb_reg(dm, R_0x1c98, BIT(rfe_num * 2 + 1) | BIT(rfe_num * 2), 0x0);
		else if (path_mux_sel == BB_PATH_B)
			odm_set_bb_reg(dm, R_0x1c98, BIT(rfe_num * 2 + 1) | BIT(rfe_num * 2), 0x1);
		else if (path_mux_sel == BB_PATH_C)
			odm_set_bb_reg(dm, R_0x1c98, BIT(rfe_num * 2 + 1) | BIT(rfe_num * 2), 0x2);
		else /*path D*/
			odm_set_bb_reg(dm, R_0x1c98, BIT(rfe_num * 2 + 1) | BIT(rfe_num * 2), 0x3);
	} else {
		if (path_mux_sel == BB_PATH_A)
			odm_set_bb_reg(dm, R_0x1c9c, BIT((rfe_num - 16) * 2 + 1) | BIT((rfe_num - 16) * 2), 0x0);
		else if (path_mux_sel == BB_PATH_B)
			odm_set_bb_reg(dm, R_0x1c9c, BIT((rfe_num - 16) * 2 + 1) | BIT((rfe_num - 16) * 2), 0x1);
		else if (path_mux_sel == BB_PATH_C)
			odm_set_bb_reg(dm, R_0x1c9c, BIT((rfe_num - 16) * 2 + 1) | BIT((rfe_num - 16) * 2), 0x2);
		else /*path D*/
			odm_set_bb_reg(dm, R_0x1c9c, BIT((rfe_num - 16) * 2 + 1) | BIT((rfe_num - 16) * 2), 0x3);
	}
	/*[Inv_en]*/
	odm_set_bb_reg(dm, R_0x183c, BIT(rfe_num), (u32)inv_en); /*0xcbc -> 0x183c*/
	odm_set_bb_reg(dm, R_0x413c, BIT(rfe_num), (u32)inv_en);
	odm_set_bb_reg(dm, R_0x523c, BIT(rfe_num), (u32)inv_en);
	odm_set_bb_reg(dm, R_0x533c, BIT(rfe_num), (u32)inv_en);

	/*[Output Source Signal Selection]*/
	if (rfe_num <= 7) {
		odm_set_bb_reg(dm, R_0x1840, ((0xf) << (rfe_num * 4)), (u32)source_sel); /*0xcb0 -> 0x1840*/
		odm_set_bb_reg(dm, R_0x4140, ((0xf) << (rfe_num * 4)), (u32)source_sel);
		odm_set_bb_reg(dm, R_0x5240, ((0xf) << (rfe_num * 4)), (u32)source_sel);
		odm_set_bb_reg(dm, R_0x5340, ((0xf) << (rfe_num * 4)), (u32)source_sel);
	} else if (rfe_num > 7 && rfe_num <= 15) {
		odm_set_bb_reg(dm, R_0x1844, ((0xf) << ((rfe_num - 8) * 4)), (u32)source_sel); /*0xcb4 -> 0x1844*/
		odm_set_bb_reg(dm, R_0x4144, ((0xf) << ((rfe_num - 8) * 4)), (u32)source_sel);
		odm_set_bb_reg(dm, R_0x5244, ((0xf) << ((rfe_num - 8) * 4)), (u32)source_sel);
		odm_set_bb_reg(dm, R_0x5344, ((0xf) << ((rfe_num - 8) * 4)), (u32)source_sel);
	} else {
		odm_set_bb_reg(dm, R_0x1848, ((0xf) << ((rfe_num - 16) * 4)), (u32)source_sel); /*0xcb4 -> 0x1848*/
		odm_set_bb_reg(dm, R_0x4148, ((0xf) << ((rfe_num - 16) * 4)), (u32)source_sel);
		odm_set_bb_reg(dm, R_0x5248, ((0xf) << ((rfe_num - 16) * 4)), (u32)source_sel);
		odm_set_bb_reg(dm, R_0x5348, ((0xf) << ((rfe_num - 16) * 4)), (u32)source_sel);
	}
}

__iram_odm_func__
void phydm_rfe_8198f_init(
	struct dm_struct *dm)
{
	PHYDM_DBG(dm, ODM_PHY_CONFIG, "8198F RFE_Init, RFE_type=((%d))\n",
		  dm->rfe_type);

	/* chip top mux */
	/*odm_set_bb_reg(dm, R_0x64, BIT(29) | BIT(28), 0x3); BT control w/o in 98F */
	odm_set_bb_reg(dm, R_0x66, BIT(13) | BIT(12), 0x3);

	/* input or output */
	odm_set_bb_reg(dm, R_0x1c94, 0x3f, 0x32);

	/* from s0 ~ s3 */
	odm_set_bb_reg(dm, R_0x1ca0, MASKDWORD, 0x0);
}

__iram_odm_func__
boolean
phydm_rfe_8198f(
	struct dm_struct *dm,
	u8 channel)
{
	/* default rfe_type*/

	boolean is_channel_2g = (channel <= 14) ? true : false;
	u8 rfe_type = dm->rfe_type;

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "[8814B] Update RFE PINs: CH:%d, T/RX_path:{ 0x%x, 0x%x}, cut_ver:%d, rfe_type:%d\n",
		  channel, dm->tx_ant_status, dm->rx_ant_status,
		  dm->cut_version, rfe_type);

	if (channel > 14  || channel == 0)
		return false;

	/* @Distinguish the setting band */
	dm->rfe_hwsetting_band = (is_channel_2g) ? 1 : 2;

	/* @HW Setting for each RFE type */
	if (rfe_type == 1)
		phydm_rfe_8198f_efem(dm, channel);
	else if (rfe_type == 3)
		phydm_rfe_8198f_efem(dm, channel);

	return true;
}

__iram_odm_func__
void phydm_ccapar_by_rfe_8198f(
	struct dm_struct *dm)
{
	/*default*/
}

__iram_odm_func__
void phydm_init_hw_info_by_rfe_type_8198f(
	struct dm_struct *dm)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8198F == 1)
	u16 mask_path_a = 0x0303;
	u16 mask_path_b = 0x0c0c;
	u16 mask_path_c = 0x3030;
	u16 mask_path_d = 0xc0c0;

	dm->is_init_hw_info_by_rfe = false;
	/* Default setting */

	dm->is_init_hw_info_by_rfe = true;

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "%s: RFE type (%d), Board type (0x%x), Package type (%d)\n",
		  __func__, dm->rfe_type, dm->board_type, dm->package_type);
	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "%s: 5G ePA (%d), 5G eLNA (%d), 2G ePA (%d), 2G eLNA (%d)\n",
		  __func__, dm->ext_pa_5g, dm->ext_lna_5g, dm->ext_pa,
		  dm->ext_lna);
	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "%s: 5G PA type (%d), 5G LNA type (%d), 2G PA type (%d), 2G LNA type (%d)\n",
		  __func__, dm->type_apa, dm->type_alna, dm->type_gpa,
		  dm->type_glna);

#endif /*PHYDM_FW_API_FUNC_ENABLE_8198F == 1*/
}

__iram_odm_func__
s32 phydm_get_condition_number_8198f(
	struct dm_struct *dm)
{
	s32 ret_val;

	/*odm_set_bb_reg(dm, R_0x1988, BIT(22), 0x1);*/
	/*ret_val = (s32)odm_get_bb_reg(dm, R_0xf84, (BIT(17) | BIT(16) | MASKLWORD));*/

	/*return ret_val;*/
}

/* ======================================================================== */

/* ======================================================================== */
/* These following functions can be used by driver*/

__iram_odm_func__
u32 config_phydm_read_rf_reg_8198f(
	struct dm_struct *dm,
	enum rf_path path,
	u32 reg_addr,
	u32 bit_mask)
{
	u32 readback_value, direct_addr;
	u32 offset_read_rf[4] = {0x3c00, 0x4c00, 0x5800, 0x5c00};

	/* Error handling.*/
	if (path > RF_PATH_D) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: unsupported path (%d)\n",
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
		  "%s: RF-%d 0x%x = 0x%x, bit mask = 0x%x\n", __func__, path,
		  reg_addr, readback_value, bit_mask);
	return readback_value;
}

__iram_odm_func__
boolean
phydm_write_txagc_1byte_8198f(struct dm_struct *dm, u32 pw_idx, u8 hw_rate)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8198F == 1)

	u32 offset_txagc = 0x3a00;
	u8 rate_idx = (hw_rate & 0xfc), i;
	u8 rate_offset = (hw_rate & 0x3);
	u8 ret = 0;
	u32 txagc_idx = 0x0;

	/* @For debug command only!!!! */

	/* @Error handling */
	if (hw_rate > 0x53) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "unsupported rate\n");
		return false;
	}

	/* @For HW limitation, We can't write TXAGC once a byte. */
	for (i = 0; i < 4; i++) {
		if (i != rate_offset) {
			ret = config_phydm_read_txagc_diff_8198f(dm,
								 rate_idx + i);
			txagc_idx = txagc_idx | (ret << (i << 3));
		} else {
			txagc_idx = txagc_idx | ((pw_idx & 0x7f) << (i << 3));
		}
	}
	odm_set_bb_reg(dm, (offset_txagc + rate_idx), MASKDWORD, txagc_idx);

	PHYDM_DBG(dm, ODM_PHY_CONFIG, " %s(): rate_idx 0x%x (0x%x) = 0x%x\n",
		  __func__, hw_rate, (offset_txagc + hw_rate), pw_idx);
	return true;
#else
	return false;
#endif
}

__iram_odm_func__
boolean
config_phydm_write_rf_reg_8198f(
	struct dm_struct *dm,
	enum rf_path path,
	u32 reg_addr,
	u32 bit_mask,
	u32 data)
{
	u32 data_and_addr = 0, data_original = 0;
	u32 offset_write_rf[4] = {0x1808, 0x4108, 0x5208, 0x5308};

	/* Error handling.*/
	if (path > RF_PATH_D) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "config_phydm_write_rf_reg_8198f(): unsupported path (%d)\n",
			  path);
		return false;
	}

	/* Read RF register content first */
	reg_addr &= 0xff;
	bit_mask = bit_mask & RFREGOFFSETMASK;

	if (bit_mask != RFREGOFFSETMASK) {
		data_original = config_phydm_read_rf_reg_8198f(dm, path, reg_addr, RFREGOFFSETMASK);

		/* Error handling. RF is disabled */
		if (config_phydm_read_rf_check_8198f(data_original) == false) {
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "config_phydm_write_rf_reg_8198f(): Write fail, RF is disable\n");
			return false;
		}

		/* check bit mask */
		data = phydm_check_bit_mask_8198f(bit_mask, data_original, data);
	}

	/* Put write addr in [27:20]  and write data in [19:00] */
	data_and_addr = ((reg_addr << 20) | (data & 0x000fffff)) & 0x0fffffff;

	/* Write operation */
	odm_set_bb_reg(dm, offset_write_rf[path], MASKDWORD, data_and_addr);
	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "config_phydm_write_rf_reg_8198f(): RF-%d 0x%x = 0x%x (original: 0x%x), bit mask = 0x%x\n",
		  path, reg_addr, data, data_original, bit_mask);
	return true;
}

__iram_odm_func__
boolean
config_phydm_write_txagc_ref_8198f(
	struct dm_struct *dm,
	u32 power_index,
	enum rf_path path,
	enum PDM_RATE_TYPE rate_type)
{
	/* 4-path power reference */
	u32 txagc_ofdm_ref[4] = {0x18e8, 0x41e8, 0x52e8, 0x53e8};
	u32 txagc_cck_ref[4] = {0x18a0, 0x41a0, 0x52a0, 0x53a0};
	u8 pw_idx = power_index & 0x7f;

	/* bbrstb TX AGC report - default disable */
	/* Enable for writing the TX AGC table when bb_reset=0 */
	odm_set_bb_reg(dm, R_0x1c90, BIT(15), 0x0);

	/* Input need to be HW rate index, not driver rate index!!!! */
	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s(): disable PHY API for debug!!\n", __func__);
		return true;
	}
	/* Error handling */
	if (path > RF_PATH_D) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s(): unsupported path (%d)\n", __func__, path);
		return false;
	}
	if (power_index > 0x7f) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s(): unsupported power\n", __func__);
		return false;
	}

	/* According the rate to write in the ofdm or the cck */
	if (rate_type == PDM_CCK) /* CCK reference setting */
		odm_set_bb_reg(dm, txagc_cck_ref[path], 0x007F0000, pw_idx);
	else if (rate_type == PDM_OFDM) /* OFDM reference setting */
		odm_set_bb_reg(dm, txagc_ofdm_ref[path], 0x0001FC00, pw_idx);

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "config_phydm_write_txagc_8198f(): path-%d rate type %d (0x%x) = 0x%x\n",
		  path, rate_type, txagc_ofdm_ref[path], power_index);
	return true;
}

__iram_odm_func__
boolean
config_phydm_write_txagc_diff_8198f(
	struct dm_struct *dm,
	u32 power_index,
	u8 hw_rate)
{
	u32 offset_txagc = 0x3a00;
	u8 rate_idx = (hw_rate & 0xfc); /* Extract the 0xfc */
	u8 pw_idx = power_index & 0x7f;
	/* bbrstb TX AGC report - default disable */
	/* Enable for writing the TX AGC table when bb_reset=0 */
	odm_set_bb_reg(dm, R_0x1c90, BIT(15), 0x0);

	/* Input need to be HW rate index, not driver rate index!!!! */
	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s(): disable PHY API for debug!!\n", __func__);
		return true;
	}

	/* Error handling */
	if (hw_rate > 0x53) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s(): unsupported rate\n", __func__);
		return false;
	}
	if (power_index > 0x7f) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s(): unsupported power\n", __func__);
		return false;
	}

	/* According the rate to write in the ofdm or the cck */
	/* driver need to construct a 4-byte power index */
	odm_set_bb_reg(dm, (offset_txagc + rate_idx), MASKDWORD, pw_idx);

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "%s(): rate index 0x%x (0x%x) = 0x%x\n", __func__,
		  hw_rate, (offset_txagc + hw_rate), power_index);
	return true;
}

__iram_odm_func__
s8 config_phydm_read_txagc_diff_8198f(
	struct dm_struct *dm,
	u8 hw_rate)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8198F == 1)
	s8 read_back_data;

	/* Input need to be HW rate index, not driver rate index!!!! */

	/* Error handling */
	if (hw_rate > 0x53) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: unsupported\n", __func__);
		return INVALID_TXAGC_DATA;
	}

	/* Disable TX AGC report */
	odm_set_bb_reg(dm, R_0x1c7c, BIT(23), 0x0); /* need to check */

	/* Set data rate index (bit0~6) */
	odm_set_bb_reg(dm, R_0x1c7c, 0x7F000000, hw_rate);

	/* Enable TXAGC report */
	odm_set_bb_reg(dm, R_0x1c7c, BIT(23), 0x1);

	/* Read TX AGC report */
	read_back_data = (s8)odm_get_bb_reg(dm, R_0x2de8, 0xff);
	if (read_back_data & BIT(6))
		read_back_data |= BIT(7);

	/* Driver have to disable TXAGC report after reading TXAGC (ref. user guide v11) */
	odm_set_bb_reg(dm, R_0x1c7c, BIT(23), 0x0);

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: rate index 0x%x = 0x%x\n",
		  __func__, hw_rate, read_back_data);
	return read_back_data;
#else
	return 0;
#endif
}

__iram_odm_func__
u8 config_phydm_read_txagc_8198f(
	struct dm_struct *dm,
	enum rf_path path,
	u8 hw_rate,
	enum PDM_RATE_TYPE rate_type)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8198F == 1)
	s8 read_back_data;
	u8 read_ref_data;
	u8 result_data;
	/* 4-path power reference */
	u32 txagc_ofdm_ref[4] = {0x18e8, 0x41e8, 0x52e8, 0x53e8};
	u32 txagc_cck_ref[4] = {0x18a0, 0x41a0, 0x52a0, 0x53a0};

	/* Input need to be HW rate index, not driver rate index!!!! */

	/* Error handling */
	if (path > RF_PATH_D || hw_rate > 0x53) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: unsupported path (%d)\n",
			  __func__, path);
		return INVALID_TXAGC_DATA;
	}

	/* Disable TX AGC report */
	odm_set_bb_reg(dm, R_0x1c7c, BIT(23), 0x0); /* need to check */

	/* Set data rate index (bit0~6) and path index (bit7) */
	odm_set_bb_reg(dm, R_0x1c7c, 0x7F000000, hw_rate);

	/* Enable TXAGC report */
	odm_set_bb_reg(dm, R_0x1c7c, BIT(23), 0x1);

	/* Read power difference report */
	read_back_data = (s8)odm_get_bb_reg(dm, R_0x2de8, 0xff);
	if (read_back_data & BIT(6))
		read_back_data |= BIT(7);

	/* Read power reference value report */
	if (rate_type == PDM_CCK) /* Bit=22:16 */
		read_ref_data = (u8)odm_get_bb_reg(dm, txagc_cck_ref[path], 0x007F0000);
	else if (rate_type == PDM_OFDM) /* Bit=16:10 */
		read_ref_data = (u8)odm_get_bb_reg(dm, txagc_ofdm_ref[path], 0x0001FC00);

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: diff=0x%x ref=0x%x\n",
		  __func__, read_back_data, read_ref_data);

	if (read_back_data + read_ref_data < 0)
		result_data = 0;
	else
		result_data = read_back_data + read_ref_data;

	/* Driver have to disable TXAGC report after reading TXAGC (ref. user guide v11) */
	odm_set_bb_reg(dm, R_0x1c7c, BIT(23), 0x0);

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: path-%d rate index 0x%x = 0x%x\n",
		  __func__, path, hw_rate, result_data);
	return result_data;
#else
	return 0;
#endif
}

__iram_odm_func__
void phydm_set_csi_wgt_8198f(struct dm_struct *dm, u8 tone_idx, u8 wgt)
{
	/*Set Wgt*/
	/* enable CSI Table write clk*/
	odm_set_bb_reg(dm, R_0x1ee8, 0x3, 0x3);
	/* Setting CSI Table */
	odm_set_bb_reg(dm, R_0x1d94, 0xff000000, 0x40);
	odm_set_bb_reg(dm, R_0x1d94, 0xff0000, tone_idx); /*ton_idx*/
	odm_set_bb_reg(dm, R_0x1d94, 0xff, wgt); /*wgt = 4*/
	/* Disable CSI Table write clk*/
	odm_set_bb_reg(dm, R_0x1ee8, 0x3, 0x0);
	/* switch to CSI Table */
	odm_set_bb_reg(dm, R_0xc0c, BIT3, 0x1);
}

__iram_odm_func__
void phydm_reset_csi_wgt_8198f(struct dm_struct *dm)
{
	u8 i, tab_addr;
	/* enable CSI Table write clk*/
	odm_set_bb_reg(dm, R_0x1ee8, 0x3, 0x3);
	/* Setting CSI Table */
	odm_set_bb_reg(dm, R_0x1d94, 0xff000000, 0x40);
	for (i = 0; i < 127; i = i + 1) {
		tab_addr = i;
		odm_set_bb_reg(dm, R_0x1d94, 0xff0000, tab_addr); /*ton_idx*/
		odm_set_bb_reg(dm, R_0x1d94, 0xff, 0x0); /*wgt = 0*/
	}
	/* Disable CSI Table write clk*/
	odm_set_bb_reg(dm, R_0x1ee8, 0x3, 0x0);
	/* switch to Auto Detecte CSI Table */
	odm_set_bb_reg(dm, R_0xc0c, BIT3, 0x0);
}

__iram_odm_func__
void phydm_dynamic_spur_det_eliminate_8198f(
	struct dm_struct *dm)
{
	if (*dm->band_width == 1 && dm->rx_ant_status == BB_PATH_ABCD) {
		if (*dm->channel == 4) {
			/*Reset first*/
			phydm_reset_csi_wgt_8198f(dm);
			/*Set Wgt*/
			phydm_set_csi_wgt_8198f(dm, 0x14, 0xbb);
			phydm_set_csi_wgt_8198f(dm, 0x15, 0xbb);
		} else if (*dm->channel == 5) {
			/*Reset first*/
			phydm_reset_csi_wgt_8198f(dm);
			/*Set Wgt*/
			phydm_set_csi_wgt_8198f(dm, 0xd, 0x8);
		} else if (*dm->channel == 6) {
			/*Reset first*/
			phydm_reset_csi_wgt_8198f(dm);
			/*Set Wgt*/
			phydm_set_csi_wgt_8198f(dm, 0x4, 0x8b);
			phydm_set_csi_wgt_8198f(dm, 0x5, 0xb);
		} else if (*dm->channel == 7) {
			/*Reset first*/
			phydm_reset_csi_wgt_8198f(dm);
			/*Set Wgt*/
			phydm_set_csi_wgt_8198f(dm, 0x3d, 0xb);
			phydm_set_csi_wgt_8198f(dm, 0x3c, 0x8b);
		} else if (*dm->channel == 8) {
			/*Reset first*/
			phydm_reset_csi_wgt_8198f(dm);
			/*Set Wgt*/
			phydm_set_csi_wgt_8198f(dm, 0x34, 0x80);
			phydm_set_csi_wgt_8198f(dm, 0x35, 0xa);
		} else if (*dm->channel == 9) {
			/*Reset first*/
			phydm_reset_csi_wgt_8198f(dm);
			/*Set Wgt*/
			phydm_set_csi_wgt_8198f(dm, 0x2d, 0xb);
			phydm_set_csi_wgt_8198f(dm, 0x2c, 0xb0);
		} else if (*dm->channel == 10) {
			/*Reset first*/
			phydm_reset_csi_wgt_8198f(dm);
			/*Set Wgt*/
			phydm_set_csi_wgt_8198f(dm, 0x24, 0xb0);
			phydm_set_csi_wgt_8198f(dm, 0x25, 0xb);
		} else if (*dm->channel == 11) {
			/*Reset first*/
			phydm_reset_csi_wgt_8198f(dm);
			/*Set Wgt*/
			phydm_set_csi_wgt_8198f(dm, 0x1c, 0x80);
		} else {
			phydm_reset_csi_wgt_8198f(dm);
		}
	} else if (*dm->band_width == 0 && dm->rx_ant_status == BB_PATH_ABCD) {
		if (*dm->channel == 5) {
			/*Reset first*/
			phydm_reset_csi_wgt_8198f(dm);
			/*Set Wgt*/
			phydm_set_csi_wgt_8198f(dm, 0xd, 0x8);
		} else if (*dm->channel == 6) {
			/*Reset first*/
			phydm_reset_csi_wgt_8198f(dm);
			/*Set Wgt*/
			phydm_set_csi_wgt_8198f(dm, 0x4, 0xbb);
			phydm_set_csi_wgt_8198f(dm, 0x5, 0xb);
		} else if (*dm->channel == 7) {
			/*Reset first*/
			phydm_reset_csi_wgt_8198f(dm);
			/*Set Wgt*/
			phydm_set_csi_wgt_8198f(dm, 0x3d, 0xb);
			phydm_set_csi_wgt_8198f(dm, 0x3c, 0x8b);
		} else if (*dm->channel == 8) {
			/*Reset first*/
			phydm_reset_csi_wgt_8198f(dm);
			/*Set Wgt*/
			phydm_set_csi_wgt_8198f(dm, 0x34, 0x80);
			phydm_set_csi_wgt_8198f(dm, 0x35, 0xa);
		} else {
			phydm_reset_csi_wgt_8198f(dm);
		}
	} else {
		phydm_reset_csi_wgt_8198f(dm);
	}
}

__iram_odm_func__
boolean
config_phydm_switch_channel_8198f(
	struct dm_struct *dm,
	u8 central_ch)
{
	struct phydm_dig_struct *dig_tab = &dm->dm_dig_table;
	u32 rf_reg18 = 0, rf_reg_bc = 0xff;
	boolean rf_reg_status = true;
	u8 low_band[15] = {0x7, 0x6, 0x6, 0x5, 0x0, 0x0, 0x7, 0xff, 0x6, 0x5, 0x0, 0x0, 0x7, 0x6, 0x6};
	u8 middle_band[23] = {0x6, 0x5, 0x0, 0x0, 0x7, 0x6, 0x6, 0xff, 0x0, 0x0, 0x7, 0x6, 0x6, 0x5, 0x0, 0xff, 0x7, 0x6, 0x6, 0x5, 0x0, 0x0, 0x7};
	u8 high_band[15] = {0x5, 0x5, 0x0, 0x7, 0x7, 0x6, 0x5, 0xff, 0x0, 0x7, 0x7, 0x6, 0x5, 0x5, 0x0};
	u8 band_index = 0;

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "config_phydm_switch_channel_8198f()====================>\n");

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "config_phydm_switch_channel_8198f(): disable PHY API for debug!!\n");
		return true;
	}

	central_ch_8198f = central_ch;

	/* Errir handling for wrong HW setting due to wrong channel setting */
	if (central_ch_8198f <= 14)
		band_index = 1;
	else
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "config_phydm_switch_channel_8198f(): unsupported band (5G) (%d)\n",
			  central_ch_8198f);

	if (dm->rfe_hwsetting_band != band_index)
		phydm_rfe_8198f(dm, central_ch_8198f);

	/* RF register setting */
	rf_reg18 = config_phydm_read_rf_reg_8198f(dm, RF_PATH_A, 0x18, RFREGOFFSETMASK);
	rf_reg_status = rf_reg_status & config_phydm_read_rf_check_8198f(rf_reg18);
	rf_reg18 = (rf_reg18 & (~(0xf))); /* 98F only 2.4G -> ch-1~14, 3bit */

	/* Switch band and channel */
	if (central_ch <= 14) {
		/* 2.4G */

		/* 1. RF band and channel*/
		rf_reg18 = (rf_reg18 | central_ch);

		/* 2. AGC table selection */
		odm_set_bb_reg(dm, R_0x18ac, 0x1f0, 0x0); /*Path-A*/
		odm_set_bb_reg(dm, R_0x41ac, 0x1f0, 0x0); /*Path-B*/
		odm_set_bb_reg(dm, R_0x52ac, 0x1f0, 0x0); /*Path-C*/
		odm_set_bb_reg(dm, R_0x53ac, 0x1f0, 0x0); /*Path-D*/
		dig_tab->agc_table_idx = 0x0;

		/* 3. Set central frequency for clock offset tracking */
		if (central_ch == 13 || central_ch == 14) {
			/*n:41 s:37*/
			odm_set_bb_reg(dm, R_0xc30, MASK12BITS, 0x969);
		} else if (central_ch == 11 || central_ch == 12) {
			/* n:42, s:37 */
			odm_set_bb_reg(dm, R_0xc30, 0xfff, 0x96a);
		} else {
			/*n:42 s:38*/
			odm_set_bb_reg(dm, R_0xc30, MASK12BITS, 0x9aa);
		}

		/* CCK TX filter parameters */

		if (central_ch == 14) {
			odm_set_bb_reg(dm, R_0x1a24, MASKDWORD, 0x0000b81c);
			odm_set_bb_reg(dm, R_0x1a28, MASKLWORD, 0x0000);
			odm_set_bb_reg(dm, R_0x1aac, MASKDWORD, 0x00003667);
		} else {
			odm_set_bb_reg(dm, R_0x1a24, MASKDWORD, 0x64b80c1c);
			odm_set_bb_reg(dm, R_0x1a28, MASKLWORD, (0x00008810 & MASKLWORD));
			odm_set_bb_reg(dm, R_0x1aac, MASKDWORD, 0x01235667);
		}

	} else {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "config_phydm_switch_channel_8198f(): Fail to switch channel (ch: %d)\n",
			  central_ch);
		return false;
	}

	/* Modify IGI for MP driver to aviod PCIE interference */
	/*if (*dm->mp_mode && ((dm->rfe_type == 3) || (dm->rfe_type == 5))) {
		if (central_ch == 14)
			odm_write_dig(dm, 0x26);
		else if (central_ch < 14)
			odm_write_dig(dm, 0x20);
		else
			PHYDM_DBG(dm, ODM_PHY_CONFIG, "config_phydm_switch_channel_8198f(): Fail to switch channel (ch: %d)\n", central_ch);
	}*/

	/* Modify the setting of register 0xBC to reduce phase noise */
	if (central_ch <= 14)
		rf_reg_bc = 0x0;
	else
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "config_phydm_switch_channel_8198f(): Fail to switch channel (ch: %d)\n",
			  central_ch);

	if (rf_reg_bc != 0xff) {
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xbc,
			       (BIT(17) | BIT(16) | BIT(15)), rf_reg_bc);
	} else {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "config_phydm_switch_channel_8198f(): Fail to switch channel (ch: %d, Phase noise)\n",
			  central_ch);
		return false;
	}

	odm_set_rf_reg(dm, RF_PATH_A, RF_0x18, RFREGOFFSETMASK, rf_reg18);
	odm_set_rf_reg(dm, RF_PATH_B, RF_0x18, RFREGOFFSETMASK, rf_reg18);
	odm_set_rf_reg(dm, RF_PATH_C, RF_0x18, RFREGOFFSETMASK, rf_reg18);
	odm_set_rf_reg(dm, RF_PATH_D, RF_0x18, RFREGOFFSETMASK, rf_reg18);

	if (rf_reg_status == false) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "config_phydm_switch_channel_8198f(): Fail to switch channel (ch: %d), because writing RF register is fail\n",
			  central_ch);
		return false;
	}

	phydm_igi_toggle_8198f(dm);
	/* Dynamic spur detection by PSD and NBI/CSI mask */
	if (*dm->mp_mode)
		phydm_dynamic_spur_det_eliminate_8198f(dm);

	phydm_ccapar_by_rfe_8198f(dm);
	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "config_phydm_switch_channel_8198f(): Success to switch channel (ch: %d)\n",
		  central_ch);
	return true;
}

__iram_odm_func__
boolean
config_phydm_switch_bandwidth_8198f(
	struct dm_struct *dm,
	u8 primary_ch_idx,
	enum channel_width bandwidth)
{
	u32 rf_reg18, val32;
	boolean rf_reg_status = true;
	u8 rfe_type = dm->rfe_type;

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "config_phydm_switch_bandwidth_8198f()===================>\n");

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "config_phydm_switch_bandwidth_8198f(): disable PHY API for debug!!\n");
		return true;
	}

	/* Error handling */
	if (bandwidth >= CHANNEL_WIDTH_MAX || (bandwidth == CHANNEL_WIDTH_40 && primary_ch_idx > 2) ||
	    (bandwidth == CHANNEL_WIDTH_80 && primary_ch_idx > 4)) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "config_phydm_switch_bandwidth_8198f(): Fail to switch bandwidth (bw: %d, primary ch: %d)\n",
			  bandwidth, primary_ch_idx);
		return false;
	}

	bw_8198f = bandwidth;
	rf_reg18 = config_phydm_read_rf_reg_8198f(dm, RF_PATH_A, 0x18, RFREGOFFSETMASK);
	rf_reg_status = rf_reg_status & config_phydm_read_rf_check_8198f(rf_reg18);

	/* Switch bandwidth */
	switch (bandwidth) {
	case CHANNEL_WIDTH_20: {
		/*val32 = odm_get_bb_reg(dm, R_0x8ac, MASKDWORD);*/
		/*val32 &= 0xFFCFFC00;*/
		/*val32 |= (CHANNEL_WIDTH_20);*/
		/*odm_set_bb_reg(dm, R_0x8ac, MASKDWORD, val32);*/
		odm_set_bb_reg(dm, R_0x810, MASKDWORD, 0x10B019B0);
		odm_set_bb_reg(dm, R_0x9b0, 0x3, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0xc, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0xc0, 0x0); /*small BW*/
		odm_set_bb_reg(dm, R_0x9b0, 0xf00, primary_ch_idx); /*TX pri ch*/
		odm_set_bb_reg(dm, R_0x9b0, 0xf000, primary_ch_idx); /*RX pri ch*/
		/* DAC clock = 160M clock for BW20 */
		/* ADC clock = 160M clock for BW20 */
		odm_set_bb_reg(dm, R_0x9b4, MASKH3BYTES, 0x9246db);

		/* Gain setting */
		/* !!The value will depend on the contents of AGC table!! */
		/* AGC table change ==> parameter must be changed*/
		odm_set_bb_reg(dm, R_0x82c, 0x3f, 0x19);
		/* [19:14]=22, [25:20]=20, [31:26]=1d */
		odm_set_bb_reg(dm, R_0x86c, 0xffffc000, 0x1d822);
		odm_set_bb_reg(dm, R_0x86c, 0x1, 0x0);
		odm_set_bb_reg(dm, R_0x88c, 0xf000, 0x0);
		odm_set_bb_reg(dm, R_0x8a4, 0x3f, 0x18);
		/* SBD delay setting*/
		odm_set_bb_reg(dm, R_0x1d44, 0xff000000, 0x74);

		/* RF bandwidth */
		rf_reg18 = (rf_reg18 | BIT(11) | BIT(10));

		break;
	}
	case CHANNEL_WIDTH_40: {
		/* CCK primary channel */
		if (primary_ch_idx == 1)
			odm_set_bb_reg(dm, R_0x1a00, BIT(4), primary_ch_idx);
		else
			odm_set_bb_reg(dm, R_0x1a00, BIT(4), 0);
		/*val32 = odm_get_bb_reg(dm, R_0x8ac, MASKDWORD);*/
		/*val32 &= 0xFF3FF300;*/
		/*val32 |= (((primary_ch_idx & 0xf) << 2) | CHANNEL_WIDTH_40);*/
		/*odm_set_bb_reg(dm, R_0x8ac, MASKDWORD, val32);*/
		odm_set_bb_reg(dm, R_0x810, MASKDWORD, 0x10B019B0);
		odm_set_bb_reg(dm, R_0x9b0, 0x3, 0x1); /*TX_RF_BW*/
		odm_set_bb_reg(dm, R_0x9b0, 0xc, 0x1); /*RX_RF_BW*/
		odm_set_bb_reg(dm, R_0x9b0, 0xc0, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0xf00, primary_ch_idx);
		odm_set_bb_reg(dm, R_0x9b0, 0xf000, primary_ch_idx);
		/* DAC clock = 160M clock for BW40 */
		/* ADC clock = 160M clock for BW40 */
		odm_set_bb_reg(dm, R_0x9b4, MASKH3BYTES, 0x9246db);

		/* Gain setting */
		/* !!The value will depend on the contents of AGC table!! */
		/* AGC table change ==> parameter must be changed*/
		/* [17:12]=19, [11:6]=19 */
		odm_set_bb_reg(dm, R_0x82c, 0x3ffc0, 0x659);
		/* [19:14]=26, [25:20]=24, [31:26]=21 */
		odm_set_bb_reg(dm, R_0x86c, 0xffffc000, 0x21926);
		odm_set_bb_reg(dm, R_0x86c, 0x1, 0x0);
		odm_set_bb_reg(dm, R_0x88c, 0xf000, 0x0);
		odm_set_bb_reg(dm, R_0x8a4, MASK12BITS, 0x71c);
		odm_set_bb_reg(dm, R_0x870, 0x3ffff, 0x21926);
		/* SBD delay setting*/
		odm_set_bb_reg(dm, R_0x1d48, 0xff000000, 0x13);

		/* RF bandwidth */
		rf_reg18 = (rf_reg18 & (~(BIT(11) | BIT(10))));
		rf_reg18 = (rf_reg18 | BIT(11));

		break;
	}
	case CHANNEL_WIDTH_80: {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "switch_bandwidth_8198f(): Not sup BW80 (bw: %d, primary ch: %d)\n",
			  bandwidth, primary_ch_idx);
	}
	case CHANNEL_WIDTH_5: {
		/*val32 = odm_get_bb_reg(dm, R_0x8ac, MASKDWORD);*/
		/*val32 &= 0xEFEEFE00;*/
		/*val32 |= ((BIT(6) | CHANNEL_WIDTH_20));*/
		/*odm_set_bb_reg(dm, R_0x8ac, MASKDWORD, val32);*/
		odm_set_bb_reg(dm, R_0x810, MASKDWORD, 0x10b02ab0);
		odm_set_bb_reg(dm, R_0x9b0, 0x00000003, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0x0000000c, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0x000000c0, 0x1);
		odm_set_bb_reg(dm, R_0x9b0, 0x00000f00, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0x0000f000, 0x0);
		/* DAC clock = 40M clock for BW5 */
		/* ADC clock = 40M clock for BW5 */
		odm_set_bb_reg(dm, R_0x9b4, MASKH3BYTES, 0x9226d9);
		/* SBD delay setting as BW20 by Shawn */
		odm_set_bb_reg(dm, R_0x1d44, 0xff000000, 0x74);

		/* RF bandwidth */
		rf_reg18 = (rf_reg18 | BIT(11) | BIT(10));

		break;
	}
	case CHANNEL_WIDTH_10: {
		/*val32 = odm_get_bb_reg(dm, R_0x8ac, MASKDWORD);*/
		/*val32 &= 0xEFFEFF00;*/
		/*val32 |= ((BIT(7) | CHANNEL_WIDTH_20));*/
		/*odm_set_bb_reg(dm, R_0x8ac, MASKDWORD, val32);*/
		odm_set_bb_reg(dm, R_0x810, MASKDWORD, 0x10b02ab0);
		odm_set_bb_reg(dm, R_0x9b0, 0x00000003, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0x0000000c, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0x000000c0, 0x2);
		odm_set_bb_reg(dm, R_0x9b0, 0x00000f00, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0x0000f000, 0x0);
		/* DAC clock = 80M clock for BW10 */
		/* ADC clock = 80M clock for BW10 */
		odm_set_bb_reg(dm, R_0x9b4, MASKH3BYTES, 0x9236da);
		/* SBD delay setting as BW20 by Shawn */
		odm_set_bb_reg(dm, R_0x1d44, 0xff000000, 0x74);

		/* RF bandwidth */
		rf_reg18 = (rf_reg18 | BIT(11) | BIT(10));

		break;
	}
	default:
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "config_phydm_switch_bandwidth_8198f(): Fail to switch bandwidth (bw: %d, primary ch: %d)\n",
			  bandwidth, primary_ch_idx);
	}

	/* Write RF register */
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x18, RFREGOFFSETMASK, rf_reg18);
	odm_set_rf_reg(dm, RF_PATH_B, RF_0x18, RFREGOFFSETMASK, rf_reg18);
	odm_set_rf_reg(dm, RF_PATH_C, RF_0x18, RFREGOFFSETMASK, rf_reg18);
	odm_set_rf_reg(dm, RF_PATH_D, RF_0x18, RFREGOFFSETMASK, rf_reg18);

	if (rf_reg_status == false) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "config_phydm_switch_bandwidth_8198f(): Fail to switch bandwidth (bw: %d, primary ch: %d), because writing RF register is fail\n",
			  bandwidth, primary_ch_idx);
		return false;
	}

	/* Toggle IGI to let RF enter RX mode */
	phydm_igi_toggle_8198f(dm);

	/* Dynamic spur detection by PSD and NBI/CSI mask */
	/*if (*dm->mp_mode)
		phydm_dynamic_spur_det_eliminate_8198f(dm);*/

	/* Modify CCA parameters */
	phydm_ccapar_by_rfe_8198f(dm);

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "config_phydm_switch_bandwidth_8198f(): Success to switch bandwidth (bw: %d, primary ch: %d)\n",
		  bandwidth, primary_ch_idx);
	return true;
}

__iram_odm_func__
boolean
config_phydm_switch_channel_bw_8198f(
	struct dm_struct *dm,
	u8 central_ch,
	u8 primary_ch_idx,
	enum channel_width bandwidth)
{
	/* Switch channel */
	if (config_phydm_switch_channel_8198f(dm, central_ch) == false)
		return false;

	/* Switch bandwidth */
	if (config_phydm_switch_bandwidth_8198f(dm, primary_ch_idx, bandwidth) == false)
		return false;

	return true;
}

__iram_odm_func__
boolean
phydm_config_cck_tx_path_8198f(
	struct dm_struct *dm,
	enum bb_path tx_path)
{
	boolean set_result = PHYDM_SET_FAIL;

	/* Using antenna A for transmit all CCK packet */
	odm_set_bb_reg(dm, R_0x1a04, 0xf0000000, 0x8);
	odm_set_bb_reg(dm, R_0x1e5c, BIT(30), 0x1);

	/* Control CCK TX path by 0xa07[7] */
	odm_set_bb_reg(dm, R_0x1e5c, BIT(30), 0x1);

	/* TX logic map and TX path en for Nsts = 1 */
	if (tx_path == BB_PATH_A) /* 1T, 1ss */
		odm_set_bb_reg(dm, R_0x1a04, 0xf0000000, 0x8); /* CCK */
	else if (tx_path == BB_PATH_B)
		odm_set_bb_reg(dm, R_0x1a04, 0xf0000000, 0x4); /* CCK */
	else if (tx_path == BB_PATH_C)
		odm_set_bb_reg(dm, R_0x1a04, 0xf0000000, 0x2); /* CCK */
	else if (tx_path == BB_PATH_D)
		odm_set_bb_reg(dm, R_0x1a04, 0xf0000000, 0x1); /* CCK */

	/* TX logic map and TX path en for 2T */
	if (tx_path == BB_PATH_AB)
		odm_set_bb_reg(dm, R_0x1a04, 0xf0000000, 0xc); /* CCK */
	else if (tx_path == BB_PATH_AC)
		odm_set_bb_reg(dm, R_0x1a04, 0xf0000000, 0xa); /* CCK */
	else if (tx_path == BB_PATH_AD)
		odm_set_bb_reg(dm, R_0x1a04, 0xf0000000, 0x9); /* CCK */
	else if (tx_path == BB_PATH_BC)
		odm_set_bb_reg(dm, R_0x1a04, 0xf0000000, 0x6); /* CCK */
	else if (tx_path == BB_PATH_BD)
		odm_set_bb_reg(dm, R_0x1a04, 0xf0000000, 0x5); /* CCK */
	else if (tx_path == BB_PATH_CD)
		odm_set_bb_reg(dm, R_0x1a04, 0xf0000000, 0x3); /* CCK */

	/* TX logic map and TX path en for 3T */
	if (tx_path == BB_PATH_ABC)
		odm_set_bb_reg(dm, R_0x1a04, 0xf0000000, 0xe); /* CCK */
	else if (tx_path == BB_PATH_ABD)
		odm_set_bb_reg(dm, R_0x1a04, 0xf0000000, 0xd); /* CCK */
	else if (tx_path == BB_PATH_ACD)
		odm_set_bb_reg(dm, R_0x1a04, 0xf0000000, 0xb); /* CCK */
	else if (tx_path == BB_PATH_BCD)
		odm_set_bb_reg(dm, R_0x1a04, 0xf0000000, 0x7); /* CCK */

	/* TX logic map and TX path en for 4T */
	if (tx_path == BB_PATH_ABCD)
		odm_set_bb_reg(dm, R_0x1a04, 0xf0000000, 0xf); /* CCK */

	set_result = PHYDM_SET_SUCCESS;

	return set_result;
}

__iram_odm_func__
boolean
phydm_config_cck_rx_path_8198f(
	struct dm_struct *dm,
	enum bb_path rx_path)
{
	boolean set_result = PHYDM_SET_FAIL;
	u8 val = 0;

	val = dm->cck_sat_cnt_th_init;
	odm_set_bb_reg(dm, R_0x1ac0, 0x80000000, 0x0);
	if (dm->cut_version == ODM_CUT_A) {
		/* only enable 1 RX MRC enable */
		odm_set_bb_reg(dm, R_0x1a2c, 0x00000020, 0x1);
		/*r_dis_rx_path_clk_gat*/
		odm_set_bb_reg(dm, R_0x1a2c, 0x00600000, 0x0);
		odm_set_bb_reg(dm, R_0x1a2c, 0x00060000, 0x0);
	} else {
		if (rx_path == BB_PATH_A || rx_path == BB_PATH_B ||
		    rx_path == BB_PATH_C || rx_path == BB_PATH_D) {
			odm_set_bb_reg(dm, R_0x1a2c, 0x00000020, 0x1);
			/*r_dis_rx_path_clk_gat*/
			odm_set_bb_reg(dm, R_0x1a2c, 0x00600000, 0x0);
			odm_set_bb_reg(dm, R_0x1a2c, 0x00060000, 0x0);
			/*1Rx sat_ant_th*/
			odm_set_bb_reg(dm, R_0x1a10, 0x000000E0, 0x3);
		} else if (rx_path == BB_PATH_AB || rx_path == BB_PATH_AC ||
			rx_path == BB_PATH_AD || rx_path == BB_PATH_BC ||
			rx_path == BB_PATH_BD || rx_path == BB_PATH_CD) {
			odm_set_bb_reg(dm, R_0x1a2c, 0x00000020, 0x0);
			/*r_dis_rx_path_clk_gat*/
			odm_set_bb_reg(dm, R_0x1a2c, 0x00600000, 0x1);
			odm_set_bb_reg(dm, R_0x1a2c, 0x00060000, 0x1);
			/*2Rx sat_ant_th-check!!!*/
			odm_set_bb_reg(dm, R_0x1a10, 0x000000E0, val);
		} else if (rx_path == BB_PATH_ABC || rx_path == BB_PATH_ABD ||
			rx_path == BB_PATH_ACD || rx_path == BB_PATH_BCD) {
			odm_set_bb_reg(dm, R_0x1a2c, 0x00000020, 0x0);
			/*r_dis_rx_path_clk_gat*/
			odm_set_bb_reg(dm, R_0x1a2c, 0x00600000, 0x2);
			odm_set_bb_reg(dm, R_0x1a2c, 0x00060000, 0x2);
			/*3Rx sat_ant_th-check!!!*/
			odm_set_bb_reg(dm, R_0x1a10, 0x000000E0, val);
		} else if (rx_path == BB_PATH_ABCD) {
			odm_set_bb_reg(dm, R_0x1a2c, 0x00000020, 0x0);
			/*r_dis_rx_path_clk_gat*/
			odm_set_bb_reg(dm, R_0x1a2c, 0x00600000, 0x3);
			odm_set_bb_reg(dm, R_0x1a2c, 0x00060000, 0x3);
			/*4Rx sat_ant_th-check!!!*/
			odm_set_bb_reg(dm, R_0x1a10, 0x000000E0, val);
		}
	}
	/* Setting the 4-path RX MRC enable */

	/* Initailize the CCK path mapping */
	odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x0);
	odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0x0);

	/* CCK RX 1~4 path setting*/
	/* The path-X signal in the CCK is from the path-X (or Y) ADC */
	if (rx_path == BB_PATH_A) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x0); /*00*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0x0); /*00*/
	} else if (rx_path == BB_PATH_B) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x5); /*01*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0x5); /*01*/
	} else if (rx_path == BB_PATH_C) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0xa); /*10*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0xa); /*10*/
	} else if (rx_path == BB_PATH_D) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0xf); /*11*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0xf); /*11*/
	} else if (rx_path == BB_PATH_AB)
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x1); /*00,01*/
	else if (rx_path == BB_PATH_AC)
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x1); /*2 00,10*/
	else if (rx_path == BB_PATH_AD)
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x1); /*3 00,11*/
	else if (rx_path == BB_PATH_BC)
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x1); /*6 01,10*/
	else if (rx_path == BB_PATH_BD)
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x1); /*7 01,11*/
	else if (rx_path == BB_PATH_CD)
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x1); /*b 10,11*/
	else if (rx_path == BB_PATH_ABC) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x1); /*00,01*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0c000000, 0x2); /*10*/
	} else if (rx_path == BB_PATH_ABD) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x1); /*1 00,01*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0c000000, 0x2); /*3 11*/
	} else if (rx_path == BB_PATH_ACD) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x1); /*2 00,10*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0c000000, 0x2); /*1 11*/
	} else if (rx_path == BB_PATH_BCD) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x1); /*6 01,10*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0c000000, 0x2); /*1 11*/
	} else if (rx_path == BB_PATH_ABCD) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x1); /*00,01*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0xb); /*10,11*/
	}

	set_result = PHYDM_SET_SUCCESS;

	return set_result;
}

__iram_odm_func__
boolean
phydm_config_ofdm_tx_path_8198f(
	struct dm_struct *dm,
	enum bb_path tx_path)
{
	boolean set_result = PHYDM_SET_FAIL;

	/*[TX Antenna Setting] ==========================================*/
	/* TX path HW block enable */
	odm_set_bb_reg(dm, 0x1e28, 0xf, tx_path);

	/* TX logic map and TX path en for Nsts = 1, and OFDM TX path*/
	if (tx_path == BB_PATH_A) { /* 1T, 1ss */
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x1); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000003, 0x0); /* logic map */
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000000c, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000030, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000c0, 0x0);
	} else if (tx_path == BB_PATH_B) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x2); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000003, 0x0); /* logic map */
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000000c, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000030, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000c0, 0x0);
	} else if (tx_path == BB_PATH_C) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x4); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000003, 0x0); /* logic map */
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000000c, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000030, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000c0, 0x0);
	} else if (tx_path == BB_PATH_D) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x8); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000003, 0x0); /* logic map */
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000000c, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000030, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000c0, 0x0);
	} else if (tx_path == BB_PATH_AB) { /* --2TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x3); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000003, 0x0); /* logic map */
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000000c, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000030, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000c0, 0x0);
	} else if (tx_path == BB_PATH_AC) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x5); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000003, 0x0); /* logic map */
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000000c, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000030, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000c0, 0x0);
	} else if (tx_path == BB_PATH_AD) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x9); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000003, 0x0); /* logic map */
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000000c, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000030, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000c0, 0x1);
	} else if (tx_path == BB_PATH_BC) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x6); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000003, 0x0); /* logic map */
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000000c, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000030, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000c0, 0x0);
	} else if (tx_path == BB_PATH_BD) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xa); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000003, 0x0); /* logic map */
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000000c, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000030, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000c0, 0x1);
	} else if (tx_path == BB_PATH_CD) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xc); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000003, 0x0); /* logic map */
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000000c, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000030, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000c0, 0x1);
	} else if (tx_path == BB_PATH_ABC) { /* --3TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x7); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000003, 0x0); /* logic map */
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000000c, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000030, 0x2);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000c0, 0x0);
	} else if (tx_path == BB_PATH_ABD) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xb); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000003, 0x0); /* logic map */
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000000c, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000030, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000c0, 0x2);
	} else if (tx_path == BB_PATH_ACD) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xd); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000003, 0x0); /* logic map */
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000000c, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000030, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000c0, 0x2);
	} else if (tx_path == BB_PATH_BCD) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xe); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000003, 0x0); /* logic map */
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000000c, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000030, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000c0, 0x2);
	} else if (tx_path == BB_PATH_ABCD) { /* --4TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xf); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000003, 0x0); /* logic map */
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000000c, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000030, 0x2);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000c0, 0x3);
	}

	/* TX logic map and TX path en for Nsts = 2*/
	/* Due to LO is stand-by while 1T at path-b in normal driver, so 0x940 is the same setting btw path-A/B*/
	if (tx_path == BB_PATH_A || tx_path == BB_PATH_B ||
	    tx_path == BB_PATH_C || tx_path == BB_PATH_D) {
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000300, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000c00, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00003000, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000c000, 0x0);
	} else if (tx_path == BB_PATH_AB) { /* --2TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x3);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000300, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000c00, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00003000, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000c000, 0x0);
	} else if (tx_path == BB_PATH_AC) {
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x5);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000300, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000c00, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00003000, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000c000, 0x0);
	} else if (tx_path == BB_PATH_AD) {
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x9);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000300, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000c00, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00003000, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000c000, 0x1);
	} else if (tx_path == BB_PATH_BC) {
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x6);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000300, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000c00, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00003000, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000c000, 0x0);
	} else if (tx_path == BB_PATH_BD) {
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xa);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000300, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000c00, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00003000, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000c000, 0x1);
	} else if (tx_path == BB_PATH_CD) {
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xc);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000300, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000c00, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00003000, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000c000, 0x1);
	} else if (tx_path == BB_PATH_ABC) { /* --3TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x7);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000300, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000c00, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00003000, 0x2);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000c000, 0x0);
	} else if (tx_path == BB_PATH_ABD) {
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xb);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000300, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000c00, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00003000, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000c000, 0x2);
	} else if (tx_path == BB_PATH_ACD) {
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xd);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000300, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000c00, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00003000, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000c000, 0x2);
	} else if (tx_path == BB_PATH_BCD) {
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xe);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000300, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000c00, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00003000, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000c000, 0x2);
	} else if (tx_path == BB_PATH_ABCD) { /* --4TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xf);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000300, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00000c00, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00003000, 0x2);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000c000, 0x3);
	}

	/* TX logic map and TX path en for Nsts = 3*/
	if (tx_path == BB_PATH_ABC) { /* --3TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0x7);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00030000, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000c0000, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00300000, 0x2);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00c00000, 0x0);
	} else if (tx_path == BB_PATH_ABD) {
		odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0xb);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00030000, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000c0000, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00300000, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00c00000, 0x2);
	} else if (tx_path == BB_PATH_ACD) {
		odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0xd);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00030000, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000c0000, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00300000, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00c00000, 0x2);
	} else if (tx_path == BB_PATH_BCD) {
		odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0xe);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00030000, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000c0000, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00300000, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00c00000, 0x2);
	} else if (tx_path == BB_PATH_ABCD) { /* --4TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0xf);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00030000, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x000c0000, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00300000, 0x2);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00c00000, 0x3);
	}

	/* TX logic map and TX path en for Nsts = 4 */
	if (tx_path == BB_PATH_ABCD) { /* --4TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x0000f000, 0xf);
		odm_set_bb_reg(dm, R_0x1e2c, 0x03000000, 0x0);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0c000000, 0x1);
		odm_set_bb_reg(dm, R_0x1e2c, 0x30000000, 0x2);
		odm_set_bb_reg(dm, R_0x1e2c, 0xc0000000, 0x3);
	}
	return set_result;
}

__iram_odm_func__
boolean
phydm_config_ofdm_rx_path_8198f(
	struct dm_struct *dm,
	enum bb_path rx_path)
{
	boolean set_result = PHYDM_SET_SUCCESS;

	/* Setting the number of the antenna in the idle condition*/
	odm_set_bb_reg(dm, R_0x824, MASKBYTE3LOWNIBBLE, rx_path);

	/* Setting the number of the antenna */
	odm_set_bb_reg(dm, R_0x824, 0x000F0000, rx_path);

	/* Setting the RF mode */
	/* RF mode seeting in the RF-0 */
	if (!(rx_path & BB_PATH_A))
		config_phydm_write_rf_reg_8198f(dm, 0, 0, 0xf0000, 0x1);
	if (!(rx_path & BB_PATH_B))
		config_phydm_write_rf_reg_8198f(dm, 1, 0, 0xf0000, 0x1);
	if (!(rx_path & BB_PATH_C))
		config_phydm_write_rf_reg_8198f(dm, 2, 0, 0xf0000, 0x1);
	if (!(rx_path & BB_PATH_D))
		config_phydm_write_rf_reg_8198f(dm, 3, 0, 0xf0000, 0x1);

	if (rx_path == BB_PATH_A || rx_path == BB_PATH_B ||
	    rx_path == BB_PATH_C || rx_path == BB_PATH_D) {
		odm_set_bb_reg(dm, R_0x1d30, 0x300, 0x0);
		odm_set_bb_reg(dm, R_0x1d30, 0x600000, 0x0);
		/*1R modification by Shawn*/
		odm_set_bb_reg(dm, R_0x884, MASKDWORD, 0x1d67dcef);
	} else if (rx_path == BB_PATH_AB || rx_path == BB_PATH_AC || rx_path == BB_PATH_AD ||
		   rx_path == BB_PATH_BC || rx_path == BB_PATH_BD || rx_path == BB_PATH_CD) {
		odm_set_bb_reg(dm, R_0x1d30, 0x300, 0x1);
		odm_set_bb_reg(dm, R_0x1d30, 0x600000, 0x1);
		/*2R modification by Shawn*/
		odm_set_bb_reg(dm, R_0x884, MASKDWORD, 0x1d67575f);
	} else if (rx_path == BB_PATH_ABC || rx_path == BB_PATH_ABD ||
		   rx_path == BB_PATH_ACD || rx_path == BB_PATH_BCD) {
		odm_set_bb_reg(dm, R_0x1d30, 0x300, 0x2);
		odm_set_bb_reg(dm, R_0x1d30, 0x600000, 0x2);
		/*3R modification by Shawn*/
		odm_set_bb_reg(dm, R_0x884, MASKDWORD, 0x1d67575f);
	} else if (rx_path == BB_PATH_ABCD) {
		odm_set_bb_reg(dm, R_0x1d30, 0x300, 0x3);
		odm_set_bb_reg(dm, R_0x1d30, 0x600000, 0x3);
		/*4R modification by Shawn*/
		odm_set_bb_reg(dm, R_0x884, MASKDWORD, 0x1d67575f);
	}

	return set_result;
}

__iram_odm_func__
boolean
config_phydm_trx_mode_8198f(
	struct dm_struct *dm,
	enum bb_path tx_path,
	enum bb_path rx_path,
	boolean is_tx2_path)
{
	u32 rf_reg33 = 0;
	u16 counter = 0;
	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s ======>\n", __func__);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "disable PHY API\n");
		return true;
	}

	if (((tx_path & ~BB_PATH_ABCD) != 0) || ((rx_path & ~BB_PATH_ABCD) != 0)) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "Wrong setting: TX:0x%x, RX:0x%x\n", tx_path,
			  rx_path);
		return false;
	}

	/* [mode table] RF mode of path-A and path-B ===========================*/
	/* Cannot shut down path-A, beacause synthesizer will be shut down when path-A is in shut down mode */
	/* 3-wire setting */
	/*0: shutdown, 1: standby, 2: TX, 3: RX */
	/* RF mode setting*/
	if ((tx_path | rx_path) & BB_PATH_A)
		odm_set_bb_reg(dm, 0x1800, MASK20BITS, 0x33312);
	else
		odm_set_bb_reg(dm, 0x1800, MASK20BITS, 0x11111);
	if ((tx_path | rx_path) & BB_PATH_B)
		odm_set_bb_reg(dm, 0x4100, MASK20BITS, 0x33312);
	else
		odm_set_bb_reg(dm, 0x4100, MASK20BITS, 0x11111);
	if ((tx_path | rx_path) & BB_PATH_C)
		odm_set_bb_reg(dm, 0x5200, MASK20BITS, 0x33312);
	else
		odm_set_bb_reg(dm, 0x5200, MASK20BITS, 0x11111);
	if ((tx_path | rx_path) & BB_PATH_D)
		odm_set_bb_reg(dm, 0x5300, MASK20BITS, 0x33312);
	else
		odm_set_bb_reg(dm, 0x5300, MASK20BITS, 0x11111);

	/* CCK TX antenna mapping */
	phydm_config_cck_tx_path_8198f(dm, tx_path);

	/* OFDM TX antenna mapping*/
	phydm_config_ofdm_tx_path_8198f(dm, tx_path);
	odm_set_bb_reg(dm, R_0x1c28, 0xf, tx_path);

	/* CCK RX antenna mapping */
	phydm_config_cck_rx_path_8198f(dm, rx_path);

	/* OFDM RX antenna mapping*/
	phydm_config_ofdm_rx_path_8198f(dm, rx_path);

	if (rx_path == BB_PATH_A || rx_path == BB_PATH_B ||
	    rx_path == BB_PATH_C || rx_path == BB_PATH_D) {
		/* 1R */
		/* Disable Antenna weighting */
		odm_set_bb_reg(dm, R_0xc44, BIT(17), 0x0); /*AntWgt_en*/
		odm_set_bb_reg(dm, R_0xc54, BIT(20), 0x0); /*htstf ant-wgt enable = 0*/
		odm_set_bb_reg(dm, R_0xc38, BIT(24), 0x0); /*MRC_mode  =  'original ZF eqz'*/
	} else {
		/* 2R 3R 4R */
		/* Enable Antenna weighting */
		odm_set_bb_reg(dm, R_0xc44, BIT(17), 0x1); /*AntWgt_en*/
		odm_set_bb_reg(dm, R_0xc54, BIT(20), 0x1); /*htstf ant-wgt enable = 1*/
		odm_set_bb_reg(dm, R_0xc38, BIT(24), 0x1); /*MRC_mode =  'modified ZF eqz'*/
	}

	/* Update TXRX antenna status for PHYDM */
	dm->tx_ant_status = (tx_path & 0xf);
	dm->rx_ant_status = (rx_path & 0xf);
	/*
	if (*dm->mp_mode || (*dm->antenna_test) || (dm->normal_rx_path)) {
		0xef 0x80000  0x33 0x00001  0x3e 0x00034  0x3f 0x4080e  0xef 0x00000    suggested by Lucas
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xef, RFREGOFFSETMASK, 0x80000);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x33, RFREGOFFSETMASK, 0x00001);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x3e, RFREGOFFSETMASK, 0x00034);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x3f, RFREGOFFSETMASK, 0x4080e);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xef, RFREGOFFSETMASK, 0x00000);
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "MP mode or Antenna test mode!! support path-B TX and RX\n");
	} else {
		0xef 0x80000  0x33 0x00001  0x3e 0x00034  0x3f 0x4080c  0xef 0x00000
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xef, RFREGOFFSETMASK, 0x80000);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x33, RFREGOFFSETMASK, 0x00001);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x3e, RFREGOFFSETMASK, 0x00034);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x3f, RFREGOFFSETMASK, 0x4080c);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xef, RFREGOFFSETMASK, 0x00000);
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "Normal mode!! Do not support path-B TX and RX\n");
	}*/

	/*odm_set_rf_reg(dm, RF_PATH_A, RF_0xef, RFREGOFFSETMASK, 0x00000);*/

	/* Toggle igi to let RF enter RX mode, because BB doesn't send 3-wire command when RX path is enable */
	phydm_igi_toggle_8198f(dm);

	/* Modify CCA parameters */
	phydm_ccapar_by_rfe_8198f(dm);

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "Success to set TRx mode setting (TX: 0x%x, RX: 0x%x)\n",
		  tx_path, rx_path);
	return true;
}

__iram_odm_func__
boolean
config_phydm_parameter_init_8198f(
	struct dm_struct *dm,
	enum odm_parameter_init type)
{
	/* @Turn on 3-wire*/
	phydm_stop_3_wire(dm, PHYDM_REVERT);
	if (type == ODM_PRE_SETTING) {
		odm_set_bb_reg(dm, R_0x1c3c, (BIT(0) | BIT(1)), 0x0); /* 0x808 -> 0x1c3c, 0 ->29, 1->28 */
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: Pre setting: disable OFDM and CCK block\n",
			  __func__);
	} else if (type == ODM_POST_SETTING) {
		odm_set_bb_reg(dm, R_0x1c3c, (BIT(0) | BIT(1)), 0x3); /* 0x808 -> 0x1c3c, 0 ->29, 1->28 */
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: Post setting: enable OFDM and CCK block\n",
			  __func__);
		phydm_rfe_8198f(dm, central_ch_8198f);
#if (PHYDM_FW_API_FUNC_ENABLE_8198F == 1)
	} else if (type == ODM_INIT_FW_SETTING) {
		u8 h2c_content[4] = {0};

		h2c_content[0] = dm->rfe_type;
		h2c_content[1] = dm->rf_type;
		h2c_content[2] = dm->cut_version;
		h2c_content[3] = (dm->tx_ant_status << 4) | dm->rx_ant_status;

		odm_fill_h2c_cmd(dm, PHYDM_H2C_FW_GENERAL_INIT, 4, h2c_content);
#endif
	} else {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: Wrong type!!\n", __func__);
		return false;
	}
	/* @bmode sat_cnt setting*/
	dm->cck_sat_cnt_th_init = (u8)odm_get_bb_reg(dm, R_0x1a10, 0xE0);
	if (*dm->mp_mode) {
		odm_set_bb_reg(dm, R_0x1ad0, 0xff, 0x12);
		config_phydm_write_rf_reg_8198f(dm, RF_PATH_A, 0x35,
						0xFE000, 0x1);
		config_phydm_write_rf_reg_8198f(dm, RF_PATH_B, 0x35,
						0xFE000, 0x1);
		config_phydm_write_rf_reg_8198f(dm, RF_PATH_C, 0x35,
						0xFE000, 0x1);
		config_phydm_write_rf_reg_8198f(dm, RF_PATH_D, 0x35,
						0xFE000, 0x1);
	}
	return true;
}

/* ======================================================================== */
#endif /*PHYDM_FW_API_ENABLE_8198F == 1*/
#endif /* RTL8198F_SUPPORT == 1 */
