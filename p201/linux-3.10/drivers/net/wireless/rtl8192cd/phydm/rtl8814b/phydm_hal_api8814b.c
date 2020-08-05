/* ****************************************************************************
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
 * ****************************************************************************/
#include "mp_precomp.h"
#include "../phydm_precomp.h"

#if (RTL8814B_SUPPORT == 1)
#if (PHYDM_FW_API_ENABLE_8814B == 1)
/* ======================================================================== */
/* These following functions can be used for PHY DM only*/
enum channel_width bw_8814b;
static u8 central_ch_8814b;
/*static u8 central_ch_8814b_drp;*/
static u8 central_ch2_8814b;
/*static u8 central_ch2_8814b_drp;*/

#ifdef CONFIG_TXAGC_DEBUG_8814B
__odm_func__
boolean phydm_set_pw_by_rate_8814b(struct dm_struct *dm, s8 *pw_idx,
				   u8 rate_idx)
{
	u32 pw_all = 0;
	u8 j = 0;

	if (rate_idx % 4 != 0) {
		pr_debug("[Warning] %s\n", __func__);
		return false;
	}

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "pow = {%d, %d, %d, %d}\n",
		  *pw_idx, *(pw_idx - 1), *(pw_idx - 2), *(pw_idx - 3));

	/* @bbrstb TX AGC report - default disable */
	/* @Enable for writing the TX AGC table when bb_reset=0 */
	odm_set_bb_reg(dm, R_0x1c90, BIT(15), 0x0);

	/* @According the rate to write in the ofdm or the cck */
	/* @driver need to construct a 4-byte power index */
	odm_set_bb_reg(dm, 0x3a00 + rate_idx, MASKDWORD, pw_all);

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "rate_idx=0x%x (REG0x%x) = 0x%x\n",
		  rate_idx, 0x3a00 + rate_idx, pw_all);

	for (j = 0; j < 4; j++)
		config_phydm_read_txagc_diff_8814b(dm, rate_idx + j);

	return true;
}

__odm_func__
void phydm_txagc_tab_buff_init_8814b(struct dm_struct *dm)
{
	u8 i;

	for (i = 0; i < NUM_RATE_AC_4SS; i++) {
		dm->txagc_buff[RF_PATH_A][i] = i >> 2;
		dm->txagc_buff[RF_PATH_B][i] = i >> 2;
		dm->txagc_buff[RF_PATH_C][i] = i >> 2;
		dm->txagc_buff[RF_PATH_D][i] = i >> 2;
	}
}

__odm_func__
void phydm_txagc_tab_buff_show_8814b(struct dm_struct *dm)
{
	u8 i;

	pr_debug("path A\n");
	for (i = 0; i < NUM_RATE_AC_4SS; i++)
		pr_debug("[A][rate:%d] = %d\n", i,
			 dm->txagc_buff[RF_PATH_A][i]);
	pr_debug("path B\n");
	for (i = 0; i < NUM_RATE_AC_4SS; i++)
		pr_debug("[B][rate:%d] = %d\n", i,
			 dm->txagc_buff[RF_PATH_B][i]);
	pr_debug("path C\n");
	for (i = 0; i < NUM_RATE_AC_4SS; i++)
		pr_debug("[C][rate:%d] = %d\n", i,
			 dm->txagc_buff[RF_PATH_C][i]);
	pr_debug("path D\n");
	for (i = 0; i < NUM_RATE_AC_4SS; i++)
		pr_debug("[D][rate:%d] = %d\n", i,
			 dm->txagc_buff[RF_PATH_D][i]);
}
#endif

__odm_func__
void phydm_bb_reset_8814b(struct dm_struct *dm)
{
	odm_set_mac_reg(dm, R_0x0, BIT(16), 1);
	odm_set_mac_reg(dm, R_0x0, BIT(16), 0);
	odm_set_mac_reg(dm, R_0x0, BIT(16), 1);
}

__iram_odm_func__
boolean phydm_chk_pkg_set_valid_8814b(struct dm_struct *dm,
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

__odm_func__
void phydm_igi_toggle_8814b(struct dm_struct *dm)
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

__odm_func__
void phydm_rfe_8814b_ifem(struct dm_struct *dm, u8 channel)
{
	boolean is_channel_2g = (channel <= 14) ? true : false;
	u8 rfe_type = dm->rfe_type;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s()=======> RFE_type=((%d)), ch = %d\n",
		  __func__, dm->rfe_type, channel);

	if (rfe_type == 3) {
		if (is_channel_2g) {
			/*inv for path A~D*/
			odm_set_bb_reg(dm, R_0x183c, MASKDWORD, 0x40);
			odm_set_bb_reg(dm, R_0x413c, MASKDWORD, 0x1000);
			odm_set_bb_reg(dm, R_0x523c, MASKDWORD, 0x200);
			odm_set_bb_reg(dm, R_0x533c, MASKDWORD, 0x800);
			/*Path A*/
			odm_set_bb_reg(dm, R_0x1840, MASKDWORD, 0x77777777);
			odm_set_bb_reg(dm, R_0x1844, MASKDWORD, 0x77777777);
			/*Path B*/
			odm_set_bb_reg(dm, R_0x4140, MASKDWORD, 0x77777777);
			odm_set_bb_reg(dm, R_0x4144, MASKDWORD, 0x77777777);
			/*Path C*/
			odm_set_bb_reg(dm, R_0x5240, MASKDWORD, 0x77777777);
			odm_set_bb_reg(dm, R_0x5244, MASKDWORD, 0x77777777);
			/*Path D*/
			odm_set_bb_reg(dm, R_0x5340, MASKDWORD, 0x77777777);
			odm_set_bb_reg(dm, R_0x5344, MASKDWORD, 0x77777777);
		} else {
			/*no inv for path A~D*/
			odm_set_bb_reg(dm, R_0x183c, MASKDWORD, 0x10);
			odm_set_bb_reg(dm, R_0x413c, MASKDWORD, 0x2000);
			odm_set_bb_reg(dm, R_0x523c, MASKDWORD, 0x100);
			odm_set_bb_reg(dm, R_0x533c, MASKDWORD, 0x400);
			/*Path A*/
			odm_set_bb_reg(dm, R_0x1840, MASKDWORD, 0x77777777);
			odm_set_bb_reg(dm, R_0x1844, MASKDWORD, 0x77777777);
			/*Path B*/
			odm_set_bb_reg(dm, R_0x4140, MASKDWORD, 0x77777777);
			odm_set_bb_reg(dm, R_0x4144, MASKDWORD, 0x77777777);
			/*Path C*/
			odm_set_bb_reg(dm, R_0x5240, MASKDWORD, 0x77777777);
			odm_set_bb_reg(dm, R_0x5244, MASKDWORD, 0x77777777);
			/*Path D*/
			odm_set_bb_reg(dm, R_0x5340, MASKDWORD, 0x77777777);
			odm_set_bb_reg(dm, R_0x5344, MASKDWORD, 0x77777777);
		}
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

__odm_func__
void phydm_rfe_type_6(struct dm_struct *dm, u8 channel)
{
	boolean is_channel_2g = (channel <= 14) ? true : false;
	u8 rx_path;

	rx_path = dm->rx_ant_status;
	if (is_channel_2g) {
		/*inv for path A~D*/
		odm_set_bb_reg(dm, R_0x183c, MASKDWORD, 0x40);
		odm_set_bb_reg(dm, R_0x413c, MASKDWORD, 0x40);
		odm_set_bb_reg(dm, R_0x523c, MASKDWORD, 0x4000);
		odm_set_bb_reg(dm, R_0x533c, MASKDWORD, 0x4000);
		/*Path A*/
		odm_set_bb_reg(dm, R_0x1840, MASKDWORD, 0x74777720);
		odm_set_bb_reg(dm, R_0x1844, MASKDWORD, 0x77777777);
		/*Path B*/
		odm_set_bb_reg(dm, R_0x4140, MASKDWORD, 0x74207777);
		odm_set_bb_reg(dm, R_0x4144, MASKDWORD, 0x77777777);
		/*Path C*/
		odm_set_bb_reg(dm, R_0x5240, MASKDWORD, 0x77777777);
		odm_set_bb_reg(dm, R_0x5244, MASKDWORD, 0x74777720);
		/*Path D*/
		odm_set_bb_reg(dm, R_0x5340, MASKDWORD, 0x77777777);
		odm_set_bb_reg(dm, R_0x5344, MASKDWORD, 0x74207777);

	} else {
		/*all paths common setting*/
		odm_set_bb_reg(dm, R_0x1c94, MASKDWORD, 0xffffffff);
		/*no inv for path A~D*/
		odm_set_bb_reg(dm, R_0x183c, MASKDWORD, 0x4);
		odm_set_bb_reg(dm, R_0x413c, MASKDWORD, 0x4);
		odm_set_bb_reg(dm, R_0x523c, MASKDWORD, 0x400);
		odm_set_bb_reg(dm, R_0x533c, MASKDWORD, 0x400);
		/*Path A*/
		odm_set_bb_reg(dm, R_0x1840, MASKDWORD, 0x77777420);
		odm_set_bb_reg(dm, R_0x1844, MASKDWORD, 0x77777777);
		/*Path B*/
		odm_set_bb_reg(dm, R_0x4140, MASKDWORD, 0x77207477);
		odm_set_bb_reg(dm, R_0x4144, MASKDWORD, 0x77777777);
		/*Path C*/
		odm_set_bb_reg(dm, R_0x5240, MASKDWORD, 0x77777777);
		odm_set_bb_reg(dm, R_0x5244, MASKDWORD, 0x77777420);
		/*Path D*/
		odm_set_bb_reg(dm, R_0x5340, MASKDWORD, 0x77777777);
		odm_set_bb_reg(dm, R_0x5344, MASKDWORD, 0x77207477);
	}
}

__odm_func__
void phydm_rfe_8814b_efem(struct dm_struct *dm, u8 channel)
{
	/*boolean is_channel_2g = (channel <= 14) ? true : false;*/
	u8 rfe_type = dm->rfe_type;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s()=> RFE_type=((%d)), ch = %d\n",
		  __func__, dm->rfe_type, channel);

	if (rfe_type == 1) {

	} else if (rfe_type == 6) {
		phydm_rfe_type_6(dm, channel);
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

__odm_func__
u32 phydm_check_bit_mask_8814b(u32 bit_mask, u32 data_original, u32 data)
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

__odm_func__
void phydm_rfe_8814b_init(struct dm_struct *dm)
{
	PHYDM_DBG(dm, ODM_PHY_CONFIG, "8814b RFE_Init, RFE_type=((%d))\n",
		  dm->rfe_type);

	/* chip top mux */
	/*odm_set_bb_reg(dm, R_0x64, BIT(29) | BIT(28), 0x3);*/
	/*BT control w/o in 98F */
	odm_set_bb_reg(dm, R_0x66, BIT(13) | BIT(12), 0x3);

	/* input or output */
	odm_set_bb_reg(dm, R_0x1c94, 0x3f, 0x32);

	/* from s0 ~ s3 */
	odm_set_bb_reg(dm, R_0x1ca0, MASKDWORD, 0x0);
}

__odm_func__
boolean
phydm_rfe_8814b(struct dm_struct *dm, u8 channel)
{
	/* default rfe_type*/

	boolean is_channel_2g = (channel <= 14) ? true : false;
	u8 rfe_type = dm->rfe_type;

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "[8814B] Update RFE PINs: CH:%d, T/RX_path:{ 0x%x, 0x%x}, cut_ver:%d, rfe_type:%d\n",
		  channel, dm->tx_ant_status, dm->rx_ant_status,
		  dm->cut_version, rfe_type);

	if ((channel > 14 && channel < 36) || channel == 0)
		return false;

	/* @Distinguish the setting band */
	dm->rfe_hwsetting_band = (is_channel_2g) ? 1 : 2;

	/* @HW Setting for each RFE type */
	if (rfe_type == 1)
		phydm_rfe_8814b_efem(dm, channel);
	else if (rfe_type == 3)
		phydm_rfe_8814b_ifem(dm, channel);
	else if (rfe_type == 6)
		phydm_rfe_8814b_efem(dm, channel);

	return true;
}

__odm_func__
void phydm_ccapar_by_rfe_8814b(struct dm_struct *dm)
{

}

__odm_func__
void phydm_init_hw_info_by_rfe_type_8814b(struct dm_struct *dm)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8814B == 1)
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

#endif /*PHYDM_FW_API_FUNC_ENABLE_8814b == 1*/
}

__odm_func__
s32 phydm_get_condition_number_8814b(struct dm_struct *dm)
{
	s32 ret_val = 0;
#if 0
	odm_set_bb_reg(dm, R_0x1988, BIT(22), 0x1);
	ret_val = (s32)odm_get_bb_reg(dm, R_0xf84, (BIT(17) | BIT(16) |
				      MASKLWORD));
	return ret_val;
#endif
	return ret_val;
}

/* ======================================================================== */

/* ======================================================================== */
/* These following functions can be used by driver*/

__odm_func__
u32 config_phydm_read_syn_reg_8814b(struct dm_struct *dm, enum rf_syn syn_path,
				    u32 reg_addr, u32 bit_mask)
{
	u32 readback_value, direct_addr;
	u32 offset_read_rf[2] = {0x3b00, 0x4b00};

	/* Error handling.*/
	if (syn_path > RF_SYN1) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: unsupported syn (%d)\n",
			  __func__, syn_path);
		return INVALID_RF_DATA;
	}

	/* Calculate offset */
	reg_addr &= 0xff;
	direct_addr = offset_read_rf[syn_path] + (reg_addr << 2);

	/* RF register only has 20bits */
	bit_mask &= RFREGOFFSETMASK;

	/* Read RF register directly */
	readback_value = odm_get_bb_reg(dm, direct_addr, bit_mask);
	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "%s: RF-%d 0x%x = 0x%x, bit mask = 0x%x\n", __func__,
		  syn_path, reg_addr, readback_value, bit_mask);

	return readback_value;
}

__odm_func__
u32 config_phydm_read_rf_reg_8814b(struct dm_struct *dm, enum rf_path path,
				   u32 reg_addr, u32 bit_mask)
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

__odm_func__
u32 config_phydm_write_rf_syn_8814b(struct dm_struct *dm,
				    enum rf_syn syn_path, u32 reg_addr,
				    u32 bit_mask, u32 data)
{
	u32 direct_addr;
	u32 offset_read_rf[2] = {0x3b00, 0x4b00};

	/* Error handling.*/
	if (syn_path > RF_SYN1) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: unsupported syn (%d)\n",
			  __func__, syn_path);
		return false;
	}

	/* Calculate offset */
	reg_addr &= 0xff;
	direct_addr = offset_read_rf[syn_path] + (reg_addr << 2);

	/* RF register only has 20bits */
	bit_mask &= RFREGOFFSETMASK;

	/* write RF register directly*/
	odm_set_bb_reg(dm, direct_addr, bit_mask, data);

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "%s: SYN-%d 0x%x = 0x%x, bit mask = 0x%x\n", __func__,
		  syn_path, reg_addr, data, bit_mask);
#if (defined(CONFIG_RUN_IN_DRV))
	if (dm->support_interface == ODM_ITRF_PCIE)
		ODM_delay_us(13);
#elif (defined(CONFIG_RUN_IN_FW))
	ODM_delay_us(13);
#endif

	return true;
}

__odm_func__
boolean
config_phydm_write_rf_reg_8814b(struct dm_struct *dm, enum rf_path path,
				u32 reg_addr, u32 bit_mask, u32 data)
{
	u32 data_and_addr = 0, data_original = 0;
	u32 offset_write_rf[4] = {0x1808, 0x4108, 0x5208, 0x5308};

	/* Error handling.*/
	if (path > RF_PATH_D) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: unsupported path (%d)\n", __func__, path);
		return false;
	}

	/* Read RF register content first */
	reg_addr &= 0xff;
	bit_mask = bit_mask & RFREGOFFSETMASK;

	if (bit_mask != RFREGOFFSETMASK) {
		data_original = config_phydm_read_rf_reg_8814b(dm, path,
							       reg_addr,
							       RFREGOFFSETMASK);

		/* Error handling. RF is disabled */
		if (!(data_original != INVALID_RF_DATA)) {
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "%s: Write fail, RF is disable\n", __func__);
			return false;
		}

		/* check bit mask */
		data = phydm_check_bit_mask_8814b(bit_mask, data_original,
						  data);
	}

	/* Put write addr in [27:20]  and write data in [19:00] */
	data_and_addr = ((reg_addr << 20) | (data & 0x000fffff)) & 0x0fffffff;

	/* Write operation */
	odm_set_bb_reg(dm, offset_write_rf[path], MASKDWORD, data_and_addr);
	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "%s: RF-%d 0x%x = 0x%x (original: 0x%x), bit mask = 0x%x\n",
		  __func__, path, reg_addr, data, data_original, bit_mask);
#if (defined(CONFIG_RUN_IN_DRV))
	if (dm->support_interface == ODM_ITRF_PCIE)
		ODM_delay_us(13);
#elif (defined(CONFIG_RUN_IN_FW))
	ODM_delay_us(13);
#endif

	return true;
}

__odm_func__
boolean
phydm_write_txagc_1byte_8814b(struct dm_struct *dm,
			      s8 pw_idx, u8 hw_rate)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8814B == 1)

	u32 offset_txagc = 0x3a00;
	u8 rate_idx = (hw_rate & 0xfc), i;
	u8 rate_offset = (hw_rate & 0x3);
	u8 ret = 0;
	u32 txagc_idx = 0x0;
	u8 pw_idx_unsign = pw_idx;

	/* @For debug command only!!!! */

	/* @Error handling */
	if (hw_rate > 0x53) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "unsupported rate\n");
		return false;
	}

	/* @For HW limitation, We can't write TXAGC once a byte. */
	for (i = 0; i < 4; i++) {
		if (i != rate_offset) {
			ret = config_phydm_read_txagc_diff_8814b(dm,
								 rate_idx + i);
			txagc_idx = txagc_idx | (ret << (i << 3));
		} else {
			txagc_idx = txagc_idx | ((pw_idx_unsign & 0x7f)
						 << (i << 3));
		}
	}
	odm_set_bb_reg(dm, (offset_txagc + rate_idx), MASKDWORD, txagc_idx);

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "rate_idx 0x%x (0x%x) = 0x%x\n",
		  hw_rate, (offset_txagc + hw_rate), pw_idx_unsign);
	return true;
#else
	return false;
#endif
}

__odm_func__
boolean
config_phydm_write_txagc_ref_8814b(struct dm_struct *dm, u8 power_index,
				   enum rf_path path,
				   enum PDM_RATE_TYPE mod_type)
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
	if (mod_type == PDM_CCK) /* CCK reference setting */
		odm_set_bb_reg(dm, txagc_cck_ref[path], 0x7F0000, pw_idx);
	else if (mod_type == PDM_OFDM) /* OFDM reference setting */
		odm_set_bb_reg(dm, txagc_ofdm_ref[path], 0x1FC00, pw_idx);

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "%s(): path-%d rate type %d (0x%x) = 0x%x\n", __func__,
		  path, mod_type, txagc_ofdm_ref[path], power_index);
	return true;
}

__odm_func__
boolean
config_phydm_write_txagc_diff_8814b(struct dm_struct *dm, s8 power_index1,
				    s8 power_index2, s8 power_index3,
				    s8 power_index4, u8 hw_rate)
{
	u32 offset_txagc = 0x3a00;
	u8 rate_idx = (hw_rate & 0xfc); /* Extract the 0xfc */
	u8 power_idx1 = 0;
	u8 power_idx2 = 0;
	u8 power_idx3 = 0;
	u8 power_idx4 = 0;
	u32 pw_all = 0;

	power_idx1 = power_index1 & 0x7f;
	power_idx2 = power_index2 & 0x7f;
	power_idx3 = power_index3 & 0x7f;
	power_idx4 = power_index4 & 0x7f;
	pw_all = power_idx1 | (power_idx2 << 8) | (power_idx3 << 16) |
		     (power_idx4 << 24);
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
	if (power_idx1 > 0x7f ||  power_idx2 > 0x7f ||
	    power_idx3 > 0x7f || power_idx4 > 0x7f) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s(): unsupported power\n", __func__);
		return false;
	}
	/* According the rate to write in the ofdm or the cck */
	/* driver need to construct a 4-byte power index */
	odm_set_bb_reg(dm, (offset_txagc + rate_idx), MASKDWORD, pw_all);

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "%s(): rate index 0x%x (0x%x) = 0x%x\n", __func__,
		  hw_rate, (offset_txagc + hw_rate), pw_all);
	return true;
}

#if 1 /*Will remove when FW fill TXAGC funciton well verified*/
__odm_func__
void config_phydm_set_txagc_to_hw_8814b(struct dm_struct *dm)
{
#if (defined(CONFIG_RUN_IN_DRV))
	s8 diff_tab[4][NUM_RATE_AC_4SS]; /*power diff table of 4 paths*/
	s8 diff_tab_min[NUM_RATE_AC_4SS];
	u8 ref_pow_cck[4] = {dm->txagc_buff[RF_PATH_A][ODM_RATE11M],
			     dm->txagc_buff[RF_PATH_B][ODM_RATE11M],
			     dm->txagc_buff[RF_PATH_C][ODM_RATE11M],
			     dm->txagc_buff[RF_PATH_D][ODM_RATE11M]};
	u8 ref_pow_ofdm[4] = {dm->txagc_buff[RF_PATH_A][ODM_RATEMCS7],
			      dm->txagc_buff[RF_PATH_B][ODM_RATEMCS7],
			      dm->txagc_buff[RF_PATH_C][ODM_RATEMCS7],
			      dm->txagc_buff[RF_PATH_D][ODM_RATEMCS7]};
	u8 ref_pow_tmp = 0;
	enum rf_path path = 0;
	u8 i, j = 0;

	/* === [Reference base] =============================================*/
#ifdef CONFIG_TXAGC_DEBUG_8814B
	pr_debug("ref_pow_cck={%d, %d, %d, %d}\n",
		 ref_pow_cck[0], ref_pow_cck[1],
		 ref_pow_cck[2], ref_pow_cck[3]);
	pr_debug("ref_pow_ofdm={%d, %d, %d, %d}\n",
		 ref_pow_ofdm[0], ref_pow_ofdm[1],
		 ref_pow_ofdm[2], ref_pow_ofdm[3]);
#endif
	/*Set OFDM/CCK Ref. power index*/
	config_phydm_write_txagc_ref_8814b(dm, ref_pow_cck[0], RF_PATH_A,
					   PDM_CCK);
	config_phydm_write_txagc_ref_8814b(dm, ref_pow_cck[1], RF_PATH_B,
					   PDM_CCK);
	config_phydm_write_txagc_ref_8814b(dm, ref_pow_cck[2], RF_PATH_C,
					   PDM_CCK);
	config_phydm_write_txagc_ref_8814b(dm, ref_pow_cck[3], RF_PATH_D,
					   PDM_CCK);
	config_phydm_write_txagc_ref_8814b(dm, ref_pow_ofdm[0], RF_PATH_A,
					   PDM_OFDM);
	config_phydm_write_txagc_ref_8814b(dm, ref_pow_ofdm[1], RF_PATH_B,
					   PDM_OFDM);
	config_phydm_write_txagc_ref_8814b(dm, ref_pow_ofdm[2], RF_PATH_C,
					   PDM_OFDM);
	config_phydm_write_txagc_ref_8814b(dm, ref_pow_ofdm[3], RF_PATH_D,
					   PDM_OFDM);

	/* === [Power By Rate] ==============================================*/
	odm_move_memory(dm, diff_tab, dm->txagc_buff, NUM_RATE_AC_4SS * 4);
#ifdef CONFIG_TXAGC_DEBUG_8814B
	pr_debug("1. diff_tab path A\n");
	for (i = 0; i <= ODM_RATEVHTSS4MCS9; i++)
		pr_debug("[A][rate:%d] = %d\n", i, diff_tab[RF_PATH_A][i]);
	pr_debug("2. diff_tab path B\n");
	for (i = 0; i <= ODM_RATEVHTSS4MCS9; i++)
		pr_debug("[B][rate:%d] = %d\n", i, diff_tab[RF_PATH_B][i]);
	pr_debug("3. diff_tab path C\n");
	for (i = 0; i <= ODM_RATEVHTSS4MCS9; i++)
		pr_debug("[C][rate:%d] = %d\n", i, diff_tab[RF_PATH_C][i]);
	pr_debug("4. diff_tab path D\n");
	for (i = 0; i <= ODM_RATEVHTSS4MCS9; i++)
		pr_debug("[D][rate:%d] = %d\n", i, diff_tab[RF_PATH_D][i]);
#endif

	for (path = RF_PATH_A; path <= RF_PATH_D; path++) {
		/*CCK*/
		ref_pow_tmp = ref_pow_cck[path];
		for (j = ODM_RATE1M; j <= ODM_RATE11M; j++) {
			diff_tab[path][j] -= (s8)ref_pow_tmp;
			/**/
		}
		/*OFDM*/
		ref_pow_tmp = ref_pow_ofdm[path];
		for (j = ODM_RATE6M; j <= ODM_RATEMCS31; j++) {
			diff_tab[path][j] -= (s8)ref_pow_tmp;
			/**/
		}
		for (j = ODM_RATEVHTSS1MCS0; j <= ODM_RATEVHTSS4MCS9; j++) {
			diff_tab[path][j] -= (s8)ref_pow_tmp;
			/**/
		}
	}

#ifdef CONFIG_TXAGC_DEBUG_8814B
	pr_debug("5. diff_tab path A\n");
	for (i = 0; i <= ODM_RATEVHTSS4MCS9; i++)
		pr_debug("[A][rate:%d] = %d\n", i, diff_tab[RF_PATH_A][i]);
	pr_debug("6. diff_tab path B\n");
	for (i = 0; i <= ODM_RATEVHTSS4MCS9; i++)
		pr_debug("[B][rate:%d] = %d\n", i, diff_tab[RF_PATH_B][i]);
	pr_debug("7. diff_tab path C\n");
	for (i = 0; i <= ODM_RATEVHTSS4MCS9; i++)
		pr_debug("[C][rate:%d] = %d\n", i, diff_tab[RF_PATH_C][i]);
	pr_debug("8. diff_tab path D\n");
	for (i = 0; i <= ODM_RATEVHTSS4MCS9; i++)
		pr_debug("[D][rate:%d] = %d\n", i, diff_tab[RF_PATH_D][i]);
#endif

	for (i = ODM_RATE1M; i <= ODM_RATEMCS31; i++) {
		diff_tab_min[i] = MIN_2(MIN_2(diff_tab[RF_PATH_A][i],
					      diff_tab[RF_PATH_B][i]),
					MIN_2(diff_tab[RF_PATH_C][i],
					      diff_tab[RF_PATH_D][i]));
		#ifdef CONFIG_TXAGC_DEBUG_8814B
		pr_debug("diff_tab_min[rate:%d]= %d\n", i, diff_tab_min[i]);
		#endif
		if  (i % 4 == 3) {
			config_phydm_write_txagc_diff_8814b(dm,
							    diff_tab_min[i - 3],
							    diff_tab_min[i - 2],
							    diff_tab_min[i - 1],
							    diff_tab_min[i],
							    i - 3);
		}
	}

	for (i = ODM_RATEVHTSS1MCS0; i <= ODM_RATEVHTSS4MCS9; i++) {
		diff_tab_min[i] = MIN_2(MIN_2(diff_tab[RF_PATH_A][i],
					      diff_tab[RF_PATH_B][i]),
					MIN_2(diff_tab[RF_PATH_C][i],
					      diff_tab[RF_PATH_D][i]));
		#ifdef CONFIG_TXAGC_DEBUG_8814B
		pr_debug("diff_tab_min[rate:%d]= %d\n", i, diff_tab_min[i]);
		#endif
		if  (i % 4 == 3) {
			config_phydm_write_txagc_diff_8814b(dm,
							    diff_tab_min[i - 3],
							    diff_tab_min[i - 2],
							    diff_tab_min[i - 1],
							    diff_tab_min[i],
							    i - 3);
		}
	}
#endif
}

__odm_func__
boolean config_phydm_write_txagc_8814b(struct dm_struct *dm, u32 pw_idx,
				       enum rf_path path, u8 hw_rate)
{
#if (defined(CONFIG_RUN_IN_DRV))
	u8 ref_rate = ODM_RATEMCS31;
	u8 rate = 0;
	u8 fill_valid_cnt = 0;
	u8 i = 0;

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "Disable PHY API for debug\n");
		return true;
	}

	if (path > RF_PATH_D) {
		pr_debug("[Warning 1] %s\n", __func__);
		return false;
	}

	if (hw_rate <= ODM_RATEMCS31)
		ref_rate = ODM_RATEMCS31;
	else
		ref_rate = ODM_RATEVHTSS4MCS9;

	fill_valid_cnt = ref_rate - hw_rate + 1;
	if (fill_valid_cnt > 4)
		fill_valid_cnt = 4;

	for (i = 0; i < fill_valid_cnt; i++) {
		rate = hw_rate + i;
		if (rate >= NUM_RATE_AC_4SS) /*Just for protection*/
			break;

		dm->txagc_buff[path][rate] = (u8)(pw_idx >> (8 * i)) & 0xff;
	}
#endif
	return true;
}
#endif

#if 1 /*API for FW fill txagc*/
__odm_func__
void phydm_set_txagc_by_table_8814b(struct dm_struct *dm,
				    struct txagc_table_8814b *tab)
{
	u8 i = 0;

	/* === [Reference base] =============================================*/
	/*Set OFDM/CCK Ref. power index*/
	config_phydm_write_txagc_ref_8814b(dm, tab->ref_pow_cck[0], RF_PATH_A,
					   PDM_CCK);
	config_phydm_write_txagc_ref_8814b(dm, tab->ref_pow_cck[1], RF_PATH_B,
					   PDM_CCK);
	config_phydm_write_txagc_ref_8814b(dm, tab->ref_pow_cck[2], RF_PATH_C,
					   PDM_CCK);
	config_phydm_write_txagc_ref_8814b(dm, tab->ref_pow_cck[3], RF_PATH_D,
					   PDM_CCK);
	config_phydm_write_txagc_ref_8814b(dm, tab->ref_pow_ofdm[0], RF_PATH_A,
					   PDM_OFDM);
	config_phydm_write_txagc_ref_8814b(dm, tab->ref_pow_ofdm[1], RF_PATH_B,
					   PDM_OFDM);
	config_phydm_write_txagc_ref_8814b(dm, tab->ref_pow_ofdm[2], RF_PATH_C,
					   PDM_OFDM);
	config_phydm_write_txagc_ref_8814b(dm, tab->ref_pow_ofdm[3], RF_PATH_D,
					   PDM_OFDM);

	for (i = ODM_RATE1M; i <= ODM_RATEMCS31; i++) {
		if  (i % 4 == 3) {
			config_phydm_write_txagc_diff_8814b(dm,
							    tab->diff_t[i - 3],
							    tab->diff_t[i - 2],
							    tab->diff_t[i - 1],
							    tab->diff_t[i],
							    i - 3);
		}
	}

	for (i = ODM_RATEVHTSS1MCS0; i <= ODM_RATEVHTSS4MCS9; i++) {
		if  (i % 4 == 3) {
			config_phydm_write_txagc_diff_8814b(dm,
							    tab->diff_t[i - 3],
							    tab->diff_t[i - 2],
							    tab->diff_t[i - 1],
							    tab->diff_t[i],
							    i - 3);
		}
	}
}

__odm_func__
void phydm_get_txagc_ref_and_diff_8814b(struct dm_struct *dm,
					u8 txagc_buff[4][NUM_RATE_AC_4SS],
					u16 length,
					struct txagc_table_8814b *tab)
{
	s8 diff_tab[4][NUM_RATE_AC_4SS]; /*power diff table of 4 paths*/
	s8 diff_tab_min[NUM_RATE_AC_4SS];
	u8 ref_pow_cck[4];
	u8 ref_pow_ofdm[4];
	u8 ref_pow_tmp = 0;
	enum rf_path path = 0;
	u8 i, j = 0;

	if (length != NUM_RATE_AC_4SS) {
		pr_debug("[warning] %s\n", __func__);
		return;
	}

	/* === [Reference base] =============================================*/
#ifdef CONFIG_TXAGC_DEBUG_8814B
	pr_debug("ref_pow_cck={%d, %d, %d, %d}\n",
		 ref_pow_cck[0], ref_pow_cck[1],
		 ref_pow_cck[2], ref_pow_cck[3]);
	pr_debug("ref_pow_ofdm={%d, %d, %d, %d}\n",
		 ref_pow_ofdm[0], ref_pow_ofdm[1],
		 ref_pow_ofdm[2], ref_pow_ofdm[3]);
#endif

	/* === [Power By Rate] ==============================================*/
	odm_move_memory(dm, diff_tab, txagc_buff, NUM_RATE_AC_4SS * 4);

	ref_pow_cck[0] = diff_tab[RF_PATH_A][ODM_RATE11M];
	ref_pow_cck[1] = diff_tab[RF_PATH_B][ODM_RATE11M];
	ref_pow_cck[2] = diff_tab[RF_PATH_C][ODM_RATE11M];
	ref_pow_cck[3] = diff_tab[RF_PATH_D][ODM_RATE11M];

	ref_pow_ofdm[0] = diff_tab[RF_PATH_A][ODM_RATEMCS7];
	ref_pow_ofdm[1] = diff_tab[RF_PATH_B][ODM_RATEMCS7];
	ref_pow_ofdm[2] = diff_tab[RF_PATH_C][ODM_RATEMCS7];
	ref_pow_ofdm[3] = diff_tab[RF_PATH_D][ODM_RATEMCS7];

#ifdef CONFIG_TXAGC_DEBUG_8814B
	pr_debug("1. diff_tab path A\n");
	for (i = 0; i <= ODM_RATEVHTSS4MCS9; i++)
		pr_debug("[A][rate:%d] = %d\n", i, diff_tab[RF_PATH_A][i]);
	pr_debug("2. diff_tab path B\n");
	for (i = 0; i <= ODM_RATEVHTSS4MCS9; i++)
		pr_debug("[B][rate:%d] = %d\n", i, diff_tab[RF_PATH_B][i]);
	pr_debug("3. diff_tab path C\n");
	for (i = 0; i <= ODM_RATEVHTSS4MCS9; i++)
		pr_debug("[C][rate:%d] = %d\n", i, diff_tab[RF_PATH_C][i]);
	pr_debug("4. diff_tab path D\n");
	for (i = 0; i <= ODM_RATEVHTSS4MCS9; i++)
		pr_debug("[D][rate:%d] = %d\n", i, diff_tab[RF_PATH_D][i]);
#endif

	for (path = RF_PATH_A; path <= RF_PATH_D; path++) {
		/*CCK*/
		ref_pow_tmp = ref_pow_cck[path];
		for (j = ODM_RATE1M; j <= ODM_RATE11M; j++) {
			diff_tab[path][j] -= (s8)ref_pow_tmp;
			/**/
		}
		/*OFDM*/
		ref_pow_tmp = ref_pow_ofdm[path];
		for (j = ODM_RATE6M; j <= ODM_RATEMCS31; j++) {
			diff_tab[path][j] -= (s8)ref_pow_tmp;
			/**/
		}
		for (j = ODM_RATEVHTSS1MCS0; j <= ODM_RATEVHTSS4MCS9; j++) {
			diff_tab[path][j] -= (s8)ref_pow_tmp;
			/**/
		}
	}

#ifdef CONFIG_TXAGC_DEBUG_8814B
	pr_debug("3. diff_tab path A\n");
	for (i = 0; i <= ODM_RATEVHTSS4MCS9; i++)
		pr_debug("[A][rate:%d] = %d\n", i, diff_tab[RF_PATH_A][i]);
	pr_debug("4. diff_tab path B\n");
	for (i = 0; i <= ODM_RATEVHTSS4MCS9; i++)
		pr_debug("[B][rate:%d] = %d\n", i, diff_tab[RF_PATH_B][i]);
	pr_debug("4. diff_tab path C\n");
	for (i = 0; i <= ODM_RATEVHTSS4MCS9; i++)
		pr_debug("[C][rate:%d] = %d\n", i, diff_tab[RF_PATH_C][i]);
	pr_debug("4. diff_tab path D\n");
	for (i = 0; i <= ODM_RATEVHTSS4MCS9; i++)
		pr_debug("[D][rate:%d] = %d\n", i, diff_tab[RF_PATH_D][i]);
#endif

	for (i = ODM_RATE1M; i <= ODM_RATEMCS31; i++) {
		diff_tab_min[i] = MIN_2(MIN_2(diff_tab[RF_PATH_A][i],
					      diff_tab[RF_PATH_B][i]),
					MIN_2(diff_tab[RF_PATH_C][i],
					      diff_tab[RF_PATH_D][i]));
		#ifdef CONFIG_TXAGC_DEBUG_8814B
		pr_debug("diff_tab_min[rate:%d]= %d\n", i, diff_tab_min[i]);
		#endif
	}

	for (i = ODM_RATEVHTSS1MCS0; i <= ODM_RATEVHTSS4MCS9; i++) {
		diff_tab_min[i] = MIN_2(MIN_2(diff_tab[RF_PATH_A][i],
					      diff_tab[RF_PATH_B][i]),
					MIN_2(diff_tab[RF_PATH_C][i],
					      diff_tab[RF_PATH_D][i]));
		#ifdef CONFIG_TXAGC_DEBUG_8814B
		pr_debug("diff_tab_min[rate:%d]= %d\n", i, diff_tab_min[i]);
		#endif
	}

	odm_move_memory(dm, tab->ref_pow_cck, ref_pow_cck, 4);
	odm_move_memory(dm, tab->ref_pow_ofdm, ref_pow_ofdm, 4);
	odm_move_memory(dm, tab->diff_t, diff_tab_min, NUM_RATE_AC_4SS);
}
#endif

__odm_func__
s8 config_phydm_read_txagc_diff_8814b(struct dm_struct *dm, u8 hw_rate)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8814B == 1)
	s8 read_back_data;

	/* Input need to be HW rate index, not driver rate index!!!! */

	/* Error handling */
	if (hw_rate > 0x53) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s(): unsupported rate\n",
			  __func__);
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

	/* Driver have to disable TXAGC report after reading TXAGC */
	odm_set_bb_reg(dm, R_0x1c7c, BIT(23), 0x0);

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s(): rate index 0x%x = 0x%x\n",
		  __func__, hw_rate, read_back_data);
	return read_back_data;
#else
	return 0;
#endif
}

__odm_func__
u8 config_phydm_read_txagc_8814b(struct dm_struct *dm, enum rf_path path,
				 u8 hw_rate, enum PDM_RATE_TYPE rate_type)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8814B == 1)
	s8 read_back_data;
	u8 ref_data = 0;
	u8 result_data;
	/* 4-path power reference */
	u32 ofdm_ref[4] = {0x18e8, 0x41e8, 0x52e8, 0x53e8};
	u32 cck_ref[4] = {0x18a0, 0x41a0, 0x52a0, 0x53a0};

	/* Input need to be HW rate index, not driver rate index!!!! */

	/* Error handling */
	if (path > RF_PATH_D || hw_rate > 0x53) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s(): unsupported path (%d)\n",
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
		ref_data = (u8)odm_get_bb_reg(dm, cck_ref[path], 0x7F0000);
	else if (rate_type == PDM_OFDM) /* Bit=16:10 */
		ref_data = (u8)odm_get_bb_reg(dm, ofdm_ref[path], 0x1FC00);

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s(): diff=0x%x ref=0x%x\n",
		  __func__, read_back_data, ref_data);

	if (read_back_data + ref_data < 0)
		result_data = 0;
	else
		result_data = read_back_data + ref_data;

	/* Driver have to disable TXAGC report after reading TXAGC */
	odm_set_bb_reg(dm, R_0x1c7c, BIT(23), 0x0);

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s(): path-%d rate index 0x%x = 0x%x\n",
		  __func__, path, hw_rate, result_data);
	return result_data;
#else
	return 0;
#endif
}

#ifdef CONFIG_RCK_OFFSET_ADJUST_8814B
void phydm_set_rck_offset_8814b(struct dm_struct *dm, enum rck_adjust_level lv)
{
	u8 i = RF_PATH_A;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s ======>\n", __func__);
	switch (lv) {
	case RCK_OFFSET_NORMAL:
		for (i = RF_PATH_A; i <= RF_PATH_D; i++) {
			config_phydm_write_rf_reg_8814b(dm, i, RF_0xee,
							BIT(1), 0x1);
			config_phydm_write_rf_reg_8814b(dm, i, RF_0x33,
							0x1f, 0x1);
			config_phydm_write_rf_reg_8814b(dm, i, RF_0x3f,
							MASK12BITS, 0x0);
			config_phydm_write_rf_reg_8814b(dm, i, RF_0xee,
							BIT(1), 0x0);
		}
		break;
	case RCK_OFFSET_MINUS_LV1:
		for (i = RF_PATH_A; i <= RF_PATH_D; i++) {
			config_phydm_write_rf_reg_8814b(dm, i, RF_0xee,
							BIT(1), 0x1);
			config_phydm_write_rf_reg_8814b(dm, i, RF_0x33,
							0x1f, 0x1);
			config_phydm_write_rf_reg_8814b(dm, i, RF_0x3f,
							MASK12BITS, 0xaaa);
			config_phydm_write_rf_reg_8814b(dm, i, RF_0xee,
							BIT(1), 0x0);
			}
		break;
	default:
		break;
	}
}
#endif

void phydm_dyn_dpd_8814b(struct dm_struct *dm, u8 central_ch)
{
	u8 rfe_type = dm->rfe_type;
	u8 disable_6m = 0;

	/* disable DPD in low rate for specific channel */
	/* iFEM only */
	if (central_ch == 140)
		if (rfe_type == 0 || rfe_type == 2 || rfe_type == 3 ||
		    rfe_type == 7 || rfe_type == 8 || rfe_type == 9)
			disable_6m = 1;

	odm_set_bb_reg(dm, R_0xa70, BIT(0), disable_6m);
}

boolean phydm_tone_intf_bw_mapping(struct dm_struct *dm, u8 ch, u8 *bw,
				   u32 *tone_idx, u32 *intf, u8 *efem_only)
{
	/*spur on DC needs to move central freq, then do psd*/
	/*20M flow needs to refine coz spur on DC tone*/
	/*80/320 = (f_spur(MHz)-fc(MHz))/tone_idx, tone_idx ~ S(12,0)*/
	boolean mapping_result = true;
	if (ch < 15) {
		if (ch == 5 && *bw == CHANNEL_WIDTH_20) {/*spur freq 5280M*/
			*tone_idx = 0x20;
			*intf = 2440;
			*bw = 20;
		} else if (ch == 6 && *bw == CHANNEL_WIDTH_20) {
			*tone_idx = 0xc;
			*intf = 2440;
			*bw = 20;
		} else if (ch == 7 && *bw == CHANNEL_WIDTH_20) {
			*tone_idx = 0xff8;
			*intf = 2440;
			*bw = 20;
		} else if (ch == 8 && *bw == CHANNEL_WIDTH_20) {
			*tone_idx = 0xfe4;
			*intf = 2440;
			*bw = 20;
		} else if (ch == 13 && *bw == CHANNEL_WIDTH_20) {
			*tone_idx = 0x20;
			*intf = 2480;
			*bw = 20;
		} else if (ch == 3 && *bw == CHANNEL_WIDTH_40) {
			*tone_idx = 0x48;
			*intf = 2440;
			*bw = 40;
		} else if (ch == 4 && *bw == CHANNEL_WIDTH_40) {
			*tone_idx = 0x34;
			*intf = 2440;
			*bw = 40;
		} else if (ch == 5 && *bw == CHANNEL_WIDTH_40) {
			*tone_idx = 0x20;
			*intf = 2440;
			*bw = 40;
		} else if (ch == 6 && *bw == CHANNEL_WIDTH_40) {
			*tone_idx = 0xc;
			*intf = 2440;
			*bw = 40;
		} else if (ch == 7 && *bw == CHANNEL_WIDTH_40) {
			*tone_idx = 0xff8;
			*intf = 2440;
			*bw = 40;
		} else if (ch == 8 && *bw == CHANNEL_WIDTH_40) {
			*tone_idx = 0xfe4;
			*intf = 2440;
			*bw = 40;
		} else if (ch == 9 && *bw == CHANNEL_WIDTH_40) {
			*tone_idx = 0xfd0;
			*intf = 2440;
			*bw = 40;
		} else if (ch == 10 && *bw == CHANNEL_WIDTH_40) {
			*tone_idx = 0xfbc;
			*intf = 2440;
			*bw = 40;
		}  else {
			mapping_result = false;
		}
	} else if (ch >= 36) {
		if (ch == 56 && *bw == CHANNEL_WIDTH_20) {/*spur freq 5280M*/
			*tone_idx = 0;
			*intf = 5280;
			*bw = 20;
			mapping_result = false;
		} else if (ch == 54 && *bw == CHANNEL_WIDTH_40) {
			*tone_idx = 0x28; /* idx = 40 */
			*intf = 5280;
			*bw = 40;
		} else if (ch == 58 && *bw == CHANNEL_WIDTH_80) {
			*tone_idx = 0xfd8; /* idx = -40 */
			*intf = 5280;
			*bw = 80;
		} else if (ch == 120 && *bw == CHANNEL_WIDTH_20) {
			*tone_idx = 0;
			*intf = 5600;
			*bw = 20;
			mapping_result = false;
		} else if (ch == 118 && *bw == CHANNEL_WIDTH_40) {
			*tone_idx = 0x28; /* idx = 40 */
			*intf = 5600;
			*bw = 40;
		} else if (ch == 122 && *bw == CHANNEL_WIDTH_80) {
			*tone_idx = 0xfd8; /* idx = -40 */
			*intf = 5600;
			*bw = 80;
		} else if (ch == 153 && *bw == CHANNEL_WIDTH_20) {
			*tone_idx = 0xfec; /* idx = -20 */
			*intf = 5760;
			*bw = 20;
			if (dm->rfe_type == 1 || dm->rfe_type == 4 ||
			    dm->rfe_type == 5 || dm->rfe_type == 6)
				*efem_only = true;
		} else if (ch == 151 && *bw == CHANNEL_WIDTH_40) {
			*tone_idx = 0x14; /* idx = 20 */
			*intf = 5760;
			*bw = 40;
			if (dm->rfe_type == 1 || dm->rfe_type == 4 ||
			    dm->rfe_type == 5 || dm->rfe_type == 6)
				*efem_only = true;
		} else if (ch == 155 && *bw == CHANNEL_WIDTH_80) {
			*tone_idx = 0xfc4;/* idx = -60 */
			*intf = 5760;
			*bw = 80;
		} else if (ch == 159 && *bw == CHANNEL_WIDTH_40) {
			*tone_idx = 0x14;/* idx = 20 */
			*intf = 5800;
			*bw = 40;
		} else if (ch == 169 && *bw == CHANNEL_WIDTH_20) {
			*tone_idx = 0xfec;/* idx = -20 */
			*intf = 5840;
			*bw = 20;
		} else if (ch == 167 && *bw == CHANNEL_WIDTH_40) {
			*tone_idx = 0x14;/* idx = 20 */
			*intf = 5840;
			*bw = 40;
		}  else if (ch == 171 && *bw == CHANNEL_WIDTH_80) {
			*tone_idx = 0xfc4;/* idx = -60 */
			*intf = 5840;
			*bw = 80;	
		} else {
			mapping_result = false;
		}
	} else {
		mapping_result = false;
	}
	return mapping_result;
}

boolean phydm_csi_wgt_mapping(struct dm_struct *dm, u32 psd_db,
			      u32 threshold_csi_db)
{
	boolean mapping_result = true;

	if (psd_db >= threshold_csi_db && psd_db < 44)
		dm->csi_wgt = 4;
	else if (psd_db >= 44 && psd_db < 50)
		dm->csi_wgt = 3;
	else if (psd_db >= 50 && psd_db < 56)
		dm->csi_wgt = 2;
	else if (psd_db >= 56 && psd_db < 62)
		dm->csi_wgt = 1;
	else if (psd_db >= 62)
		dm->csi_wgt = 0;
	else
		mapping_result = false;
	return mapping_result;
}

u32 phydm_rf_psd(struct dm_struct *dm, u8 path, u32 tone_idx)
{
	u32 reg_1b04 = 0, reg_1b08 = 0, reg_1b0c_11_10 = 0;
	u32 reg_1b14 = 0, reg_1b18 = 0, reg_1b1c = 0;
	u32 reg_1b28 = 0;
	u32 reg_1bcc_5_0 = 0;
	u32 reg_1b2c_27_16 = 0, reg_1b34 = 0, reg_1bd4 = 0;
	u32 reg_180c = 0, reg_410c = 0, reg_520c = 0, reg_530c = 0;
	u32 igi = 0;
	u32 i = 0;
	u32 psd_val = 0, psd_val_42_32 = 0, psd_val_31_0 = 0, psd_max = 0;
	u32 psd_status_temp = 0;
	u16 poll_cnt = 0;
	
	/*read and record the ori. value*/
	reg_1b04 = odm_get_bb_reg(dm, R_0x1b04, MASKDWORD);
	reg_1b08 = odm_get_bb_reg(dm, R_0x1b08, MASKDWORD);
	reg_1b0c_11_10 = odm_get_bb_reg(dm, R_0x1b0c, 0xc00);
	reg_1b14 = odm_get_bb_reg(dm, R_0x1b14, MASKDWORD);
	reg_1b18 = odm_get_bb_reg(dm, R_0x1b18, MASKDWORD);
	reg_1b1c = odm_get_bb_reg(dm, R_0x1b1c, MASKDWORD);
	reg_1b28 = odm_get_bb_reg(dm, R_0x1b28, MASKDWORD);
	reg_1bcc_5_0 = odm_get_bb_reg(dm, R_0x1bcc, 0x3f);
	reg_1b2c_27_16 = odm_get_bb_reg(dm, R_0x1b2c, 0xfff0000);
	reg_1b34 = odm_get_bb_reg(dm, R_0x1b34, MASKDWORD);
	reg_1bd4 = odm_get_bb_reg(dm, R_0x1bd4, MASKDWORD);
	igi = odm_get_bb_reg(dm, R_0x1d70, MASKDWORD);
	reg_180c = odm_get_bb_reg(dm, R_0x180c, 0x3);
	reg_410c = odm_get_bb_reg(dm, R_0x410c, 0x3);
	reg_520c = odm_get_bb_reg(dm, R_0x520c, 0x3);
	reg_530c = odm_get_bb_reg(dm, R_0x530c, 0x3);

	/*rf psd reg setting*/
	odm_set_bb_reg(dm, R_0x1b00, 0x6, path); /*path is RF_path*/
	odm_set_bb_reg(dm, R_0x1b04, MASKDWORD, 0x0);
	odm_set_bb_reg(dm, R_0x1b08, MASKDWORD, 0x80);
	odm_set_bb_reg(dm, R_0x1b0c, 0xc00, 0x3);
	odm_set_bb_reg(dm, R_0x1b14, MASKDWORD, 0x0);
	odm_set_bb_reg(dm, R_0x1b18, MASKDWORD, 0x1);
/*#if (DM_ODM_SUPPORT_TYPE == ODM_AP)*/
	odm_set_bb_reg(dm, R_0x1b1c, MASKDWORD, 0x82103D21);
/*#else*/
	/*odm_set_bb_reg(dm, R_0x1b1c, MASKDWORD, 0x821A3D21);*/
/*#endif*/
	odm_set_bb_reg(dm, R_0x1b28, MASKDWORD, 0x0);
	odm_set_bb_reg(dm, R_0x1bcc, 0x3f, 0x3f);
	odm_set_bb_reg(dm, R_0x8a0, 0xf, 0x0); /* AGC off */
	odm_set_bb_reg(dm, R_0x1d70, MASKDWORD, 0x20202020);

	for (i = tone_idx - 1; i <= tone_idx + 1; i++) {
		/*set psd tone_idx for detection*/
		odm_set_bb_reg(dm, R_0x1b2c, 0xfff0000, i);
		/*one shot for RXIQK psd*/
		odm_set_bb_reg(dm, R_0x1b34, MASKDWORD, 0x1);
		odm_set_bb_reg(dm, R_0x1b34, MASKDWORD, 0x0);

		for (poll_cnt = 0; poll_cnt < 20; poll_cnt++) {
			odm_set_bb_reg(dm, R_0x1bd4, 0x3f0000, 0x2b);
			psd_status_temp = odm_get_bb_reg(dm, R_0x1bfc, BIT(1));
			if (!psd_status_temp)
				ODM_delay_us(10);
			else
				break;
		}

		/*read RxIQK power*/
		odm_set_bb_reg(dm, R_0x1bd4, MASKDWORD, 0x00250001);
		psd_val_42_32 = odm_get_bb_reg(dm, R_0x1bfc, 0x7ff0000);
		odm_set_bb_reg(dm, R_0x1bd4, MASKDWORD, 0x002e0001);
		psd_val_31_0 = odm_get_bb_reg(dm, R_0x1bfc, MASKDWORD);
		psd_val = (psd_val_42_32 << 21) + (psd_val_31_0 >> 11);
		if (psd_val > psd_max)
			psd_max = psd_val;
	}

	/*refill the ori. value*/
	odm_set_bb_reg(dm, R_0x1b00, 0x6, path);
	odm_set_bb_reg(dm, R_0x1b04, MASKDWORD, reg_1b04);
	odm_set_bb_reg(dm, R_0x1b08, MASKDWORD, reg_1b08);
	odm_set_bb_reg(dm, R_0x1b0c, 0xc00, reg_1b0c_11_10);
	odm_set_bb_reg(dm, R_0x1b14, MASKDWORD, reg_1b14);
	odm_set_bb_reg(dm, R_0x1b18, MASKDWORD, reg_1b18);
	odm_set_bb_reg(dm, R_0x1b1c, MASKDWORD, reg_1b1c);
	odm_set_bb_reg(dm, R_0x1b28, MASKDWORD, reg_1b28);
	odm_set_bb_reg(dm, R_0x1bcc, 0x3f, reg_1bcc_5_0);
	odm_set_bb_reg(dm, R_0x1b2c, 0xfff0000, reg_1b2c_27_16);
	odm_set_bb_reg(dm, R_0x1b34, MASKDWORD, reg_1b34);
	odm_set_bb_reg(dm, R_0x1bd4, MASKDWORD, reg_1bd4);
	odm_set_bb_reg(dm, R_0x8a0, 0xf, 0xf); /* AGC on */
	odm_set_bb_reg(dm, R_0x1d70, MASKDWORD, igi);
	PHYDM_DBG(dm, ODM_COMP_API, "psd_max %d\n", psd_max);

	return psd_max;
}

__odm_func__
void phydm_dynamic_spur_det_eliminate_8814b(struct dm_struct *dm)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8814B == 1)
	u32 threshold_nbi_db = 38, threshold_csi_db = 38;
	u32 tone_idx = 0, f_intf = 0;
	u32 psd_db[NUM_PATH] = {0};
	u32 psd_tmp = 0, tmp_val = 0;
	u8 path[NUM_PATH] = {RF_PATH_A, RF_PATH_B, RF_PATH_C, RF_PATH_D};
	u8 path_en[NUM_PATH] = {0};
	boolean nbi_enable[NUM_PATH] = {false, false, false, false};
	boolean csi_enable = false, mapping_result = false, set_csi_wgt = false;
	boolean nbi_2g_dis = false;
	boolean csi_psd_no_need = false, nbi_psd_no_need = false;
	u8 set_nbi[NUM_PATH] = {PHYDM_SET_NO_NEED, PHYDM_SET_NO_NEED,
				PHYDM_SET_NO_NEED, PHYDM_SET_NO_NEED};
	u8 set_csi = PHYDM_SET_NO_NEED;
	u8 init_nbi, init_csi;
	u8 channel = *dm->channel, bw = *dm->band_width;
	u8 dsde_sel = dm->dsde_sel, nbi_path = dm->nbi_path_sel;
	u8 csi_wgt = dm->csi_wgt;
	u8 csi_wgt_max = 4;
	u8 i = 0, j = 0, efem_only = false;

	if (channel < 15) {
		threshold_nbi_db = 34;
		threshold_csi_db = 10;
		nbi_2g_dis = true;
	}

	/*Init NBI/CSI*/
	init_csi = phydm_csi_mask_setting_jgr3(dm, FUNC_DISABLE, 0, 0, 0, 0, 0);
	init_nbi = phydm_nbi_setting_jgr3(dm, FUNC_DISABLE, 0, 0, 0, 0, 0);
	PHYDM_DBG(dm, ODM_COMP_API, "init_nbi %d, init_csi %d, ext_pa %d\n",
		  init_csi, init_nbi, dm->ext_pa);
	/*tone idx & interference mapping*/
	mapping_result = phydm_tone_intf_bw_mapping(dm, channel, &bw, &tone_idx,
						    &f_intf, &efem_only);
	if (dsde_sel == DET_DISABLE) {
		PHYDM_DBG(dm, ODM_COMP_API, "Spur Detect Disable\n");
		return;
	} else if (dsde_sel == DET_CSI && mapping_result) {
		PHYDM_DBG(dm, ODM_COMP_API, "CSI always ON; NBI Auto\n");
	} else if (dsde_sel == DET_NBI && mapping_result) {
		for (i = 0 ; i < NUM_PATH ; i++) {
			set_nbi[i] = phydm_nbi_setting_jgr3(dm, FUNC_ENABLE,
							    channel, bw,
							    f_intf * 1000,
							    0, path[i]);
		}
		odm_set_bb_reg(dm, R_0x818, 0xff, 0xf9);
		odm_set_bb_reg(dm, R_0x1944, 0x300, 0x1);
		odm_set_bb_reg(dm, R_0x4044, 0x300, 0x0);
		odm_set_bb_reg(dm, R_0x5044, 0x300, 0x0);
		odm_set_bb_reg(dm, R_0x5144, 0x300, 0x1);
		odm_set_bb_reg(dm, R_0x810, 0xf, 0x7);
		odm_set_bb_reg(dm, R_0x810, 0xf0000, 0x7);
		PHYDM_DBG(dm, ODM_COMP_API,
			  "NBI always ON, set [%d %d %d %d]; CSI Auto\n",
			  set_nbi[0], set_nbi[1], set_nbi[2], set_nbi[3]);
		nbi_psd_no_need = true;
	} else if (dsde_sel == DET_CSI_NBI_EN && mapping_result) {
		for (i = 0 ; i < NUM_PATH ; i++) {
			set_nbi[i] = phydm_nbi_setting_jgr3(dm, FUNC_ENABLE,
							    channel, bw,
							    f_intf * 1000,
							    0, path[i]);
		}
		odm_set_bb_reg(dm, R_0x818, 0xff, 0xf9);
		odm_set_bb_reg(dm, R_0x1944, 0x300, 0x1);
		odm_set_bb_reg(dm, R_0x4044, 0x300, 0x0);
		odm_set_bb_reg(dm, R_0x5044, 0x300, 0x0);
		odm_set_bb_reg(dm, R_0x5144, 0x300, 0x1);
		odm_set_bb_reg(dm, R_0x810, 0xf, 0x7);
		odm_set_bb_reg(dm, R_0x810, 0xf0000, 0x7);

		set_csi = phydm_csi_mask_setting_jgr3(dm, FUNC_ENABLE,
						      channel, bw,
						      f_intf * 1000, 0,
						      csi_wgt);
		PHYDM_DBG(dm, ODM_COMP_API,
			  "NBI & CSI alway ON, set NBI=[%d %d %d %d], CSI=%d ; csi_wgt = %d\n",
			  set_nbi[0], set_nbi[1], set_nbi[2], set_nbi[3],
			  set_csi, csi_wgt);
		return;
	} else if (dsde_sel == DET_AUTO && mapping_result) {
		PHYDM_DBG(dm, ODM_COMP_API, "Spur Detect auto\n");
	} else {
		PHYDM_DBG(dm, ODM_COMP_API, "Not spur channel\n");
		return;
	}

	/*check rx path on*/
	path_en[0] = (dm->rx_ant_status & BB_PATH_A) ? true : false; /*Path A*/
	path_en[1] = (dm->rx_ant_status & BB_PATH_B) ? true : false; /*Path B*/
	path_en[2] = (dm->rx_ant_status & BB_PATH_C) ? true : false; /*Path C*/
	path_en[3] = (dm->rx_ant_status & BB_PATH_D) ? true : false; /*Path D*/

	PHYDM_DBG(dm, ODM_COMP_API, "path en (%d,%d,%d,%d)\n",
		  path_en[0], path_en[1], path_en[2], path_en[3]);


	if (mapping_result) {
		PHYDM_DBG(dm, ODM_COMP_API,
			  "nbi_TH (%d)dB, csi_TH (%d)dB, map_r %d\n",
			  threshold_nbi_db, threshold_csi_db, mapping_result);
		PHYDM_DBG(dm, ODM_COMP_API,
			  "Tone Idx %x, interf (%d)M, ch %d, bw %d, efem %d\n",
			  tone_idx, f_intf, channel, bw, efem_only);
	} else {
		PHYDM_DBG(dm, ODM_COMP_API,
			  "Idx Not Found, Not Support Dyn_Elmntr\n");
		return;
	}

	/*RFIQK psd detection, average 32 times psd*/
	for (i = 0; i < NUM_PATH; i++) {
		if (path_en[i] == 0)
			continue;
		for (j = 0; j < NUM_TRY; j++) {
			tmp_val = phydm_rf_psd(dm, path[i], tone_idx);
			psd_tmp += (tmp_val >> 5);
			tmp_val = 0;
		}
		psd_db[i] = odm_convert_to_db(psd_tmp);
		psd_tmp = 0;
	}
	PHYDM_DBG(dm, ODM_COMP_API, "psd in dB (%d,%d,%d,%d)\n",
		  psd_db[0], psd_db[1], psd_db[2], psd_db[3]);

	/*NBI/CSI psd TH check*/
	for (i = 0; i < NUM_PATH; i++) {
		PHYDM_DBG(dm, ODM_COMP_API,
			  "psd_db = %d, threshold_nbi_db = %d\n",
			  psd_db[i], threshold_nbi_db);
		/*AP eFEM NBI always on*/
		if (((psd_db[i] >= threshold_nbi_db && !dm->ext_pa) ||
		     efem_only) && !nbi_psd_no_need)
			nbi_enable[i] = true;
		/*AP eFEM CSI always off*/
		if (psd_db[i] >= threshold_csi_db && path_en[i] &&
		    !dm->ext_pa) {
			set_csi_wgt = phydm_csi_wgt_mapping(dm, psd_db[i],
							    threshold_csi_db);
			if (csi_wgt_max > dm->csi_wgt)
				csi_wgt_max = dm->csi_wgt;
			PHYDM_DBG(dm, ODM_COMP_API, "Path[%d] csi_wgt = %d\n",
				  i, dm->csi_wgt);
			csi_enable = true;
		}
		if (nbi_2g_dis)
			nbi_enable[i] = false;
	}
	PHYDM_DBG(dm, ODM_COMP_API, "nbi_en (%d,%d,%d,%d), csi_en %d\n",
		  nbi_enable[0], nbi_enable[1], nbi_enable[2],
		  nbi_enable[3], csi_enable);
	for (i = 0; i < NUM_PATH; i++) {
		if (nbi_enable[i] && path_en[i]) {
			set_nbi[i] = phydm_nbi_setting_jgr3(dm, FUNC_ENABLE,
							    channel, bw,
							    f_intf * 1000, 0,
							    path[i]);
			PHYDM_DBG(dm, ODM_COMP_API,
				  "rfe_type = %d, bw = %d, channel = %d\n",
				  dm->rfe_type, bw, channel);
			odm_set_bb_reg(dm, R_0x818, 0xff, 0xf9);
			odm_set_bb_reg(dm, R_0x1944, 0x300, 0x1);
			odm_set_bb_reg(dm, R_0x4044, 0x300, 0x0);
			odm_set_bb_reg(dm, R_0x5044, 0x300, 0x0);
			odm_set_bb_reg(dm, R_0x5144, 0x300, 0x1);
			odm_set_bb_reg(dm, R_0x810, 0xf, 0x7);
			odm_set_bb_reg(dm, R_0x810, 0xf0000, 0x7);
		}
	}
	dm->csi_wgt = csi_wgt_max;
	set_csi = phydm_csi_mask_setting_jgr3(dm, FUNC_ENABLE, channel, bw,
					      f_intf * 1000, 0, dm->csi_wgt);
	PHYDM_DBG(dm, ODM_COMP_API, "Max csi_wgt = %d\n", dm->csi_wgt);
	if (dsde_sel == DET_CSI_NBI_EN)
		PHYDM_DBG(dm, ODM_COMP_API, "csi_wgt = %d\n", csi_wgt);
	else
		PHYDM_DBG(dm, ODM_COMP_API, "csi_wgt = %d\n", dm->csi_wgt);
	PHYDM_DBG(dm, ODM_COMP_API, "set_nbi (%d,%d,%d,%d), set_csi %d\n",
		  set_nbi[0], set_nbi[1], set_nbi[2], set_nbi[3], set_csi);
#endif
}

__odm_func__
boolean
phydm_config_set_rfc_8814b(struct dm_struct *dm, enum rfc_mode mode)
{
	boolean set_result = PHYDM_SET_FAIL;
	u8 i;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s()===> mode=%d\n", __func__, mode);
	if (mode == rfc_4x4) {
		for (i = RF_PATH_A; i <= RF_PATH_D; i++) {
			/*RF mode table write enable*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0xef, BIT19,
				       0x1);
			/*Select RX mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xf, 1);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e, 0xfffff,
				       0x364);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f, 0xfffff,
				       0x280f7);
			/*Select RX mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xf, 2);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e, 0xfffff,
				       0x3fc);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f, 0xfffff,
				       0x280f7);
			/*Select RX mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xf, 3);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e, 0xfffff,
				       0x265);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f, 0xfffff,
				       0xafcf7);
			/*Select 4 mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xF, 4);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e,
				       0xfffff, 0x003F6);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f,
				       0xfffff, 0x0F9F7);
			/*Select 5 mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xF, 5);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e,
				       0xfffff, 0x003FC);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f,
				       0xfffff, 0xBF8FF);
			/*Select 7 mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xF, 7);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e,
				       0xfffff, 0x003FD);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f,
				       0xfffff, 0xEFCF7);
			/*RF mode table write disable*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0xef, BIT(19),
				       0x0);
		}
		set_result = PHYDM_SET_SUCCESS;
	} else if (mode == rfc_2x2) {
		 /* A & D setting */
		for (i = RF_PATH_A; i <= RF_PATH_D; i += 3) {
			/*RF mode table write enable*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0xef,
				       BIT19, 0x1);
			/*Select RX mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xF, 1);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e,
				       0xfffff, 0x00364);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f,
				       0xfffff, 0x280f7);
			/*Select RX mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xF, 2);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e,
				       0xfffff, 0x003fc);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f,
				       0xfffff, 0x280f7);
			/*Select RX mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xF, 3);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e,
				       0xfffff, 0x00265);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f,
				       0xfffff, 0xafcf7);
			/*Select 4 mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xF, 4);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e,
				       0xfffff, 0x003F6);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f,
				       0xfffff, 0x0F9F7);
			/*Select 5 mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xF, 5);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e,
				       0xfffff, 0x003FC);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f,
				       0xfffff, 0xBF8FF);
			/*Select 7 mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xF, 7);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e,
				       0xfffff, 0x003FD);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f,
				       0xfffff, 0xEFCF7);
			/*RF mode table write disable*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0xef,
				       BIT(19), 0x0);
			}
		/* B & C setting */
		for (i = RF_PATH_B; i <= RF_PATH_C; i++) {
			PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s => Path = %d\n",
				  __func__, i);
			/*RF mode table write enable*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0xef,
				       BIT19, 0x1);
			/*Select RX mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xF, 1);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e,
				       0xfffff, 0x00364);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f,
				       0xfffff, 0x280c7);
			/*Select RX mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xF, 2);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e,
				       0xfffff, 0x003fc);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f,
				       0xfffff, 0x280c7);
			/*Select RX mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xF, 3);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e,
				       0xfffff, 0x00365);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f,
				       0xfffff, 0xafcc7);
			/*Select 4 mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xF, 4);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e,
				       0xfffff, 0x003F6);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f,
				       0xfffff, 0x0F9C7);
			/*Select 5 mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xF, 5);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e,
				       0xfffff, 0x003FC);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f,
				       0xfffff, 0xBF8CF);
			/*Select 7 mode*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x33, 0xF, 7);
			/*Set Table data*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3e,
				       0xfffff, 0x003FD);
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0x3f,
				       0xfffff, 0xEFCC7);
			/*RF mode table write disable*/
			odm_set_rf_reg(dm, (enum rf_path)i, RF_0xef,
				       BIT(19), 0x0);
		}
		set_result = PHYDM_SET_SUCCESS;
	} else {
		set_result = PHYDM_SET_FAIL;
	}
	return set_result;
}

__odm_func__
void config_phydm_cca_dyn_pw_th(struct dm_struct *dm, enum channel_width bw)
{
	/* Gain setting */
	/* !!The value will depend on the contents of AGC table!! */
	/* AGC table change ==> parameter must be changed*/

	/* Switch bandwidth */
	switch (bw) {
	case CHANNEL_WIDTH_20: {
		/* pri20 Falling, Rising, Max */
		/* [31:26]=1a [25:20]=1d [19:14]=1e */
		odm_set_bb_reg(dm, R_0x86c, 0xffffc000, 0x1a75e);
		/* pri20 Min */
		/* [5:0]=15 */
		odm_set_bb_reg(dm, R_0x8a4, 0x3f, 0x15);
		break;
	}
	case CHANNEL_WIDTH_40: {
		/* pri20 Falling, Rising, Max */
		/* [31:26]=17 [25:20]=1a [19:14]=1b */
		odm_set_bb_reg(dm, R_0x86c, 0xffffc000, 0x1769b);
		/* s20 Falling, Rising, Max */
		/* [17:12]=17, [11:6]=1a, [5:0]=1b */
		odm_set_bb_reg(dm, R_0x870, 0x3ffff, 0x1769b);
		/* pri20 s20 Min */
		/* [5:0]=12 [11:6]=12 */
		odm_set_bb_reg(dm, R_0x8a4, MASK12BITS, 0x492);
		break;
	}
	case CHANNEL_WIDTH_80: {
		/* [5:0]=14*/
		odm_set_bb_reg(dm, R_0x830, 0x3f, 0x14);
		/* pri20 Falling, Rising, Max */
		/* [31:26]=17 [25:20]=17 [19:14]=18 */
		odm_set_bb_reg(dm, R_0x86c, 0xffffc000, 0x145d8);
		/* s20 Falling, Rising, Max, s40 Rising, Max */
		/* [17:12]=14 [11:6]=17 [5:0]=18 [29:24]=1a [23:18]=1b */
		odm_set_bb_reg(dm, R_0x870, 0x3fffffff, 0x1a6d45d8);
		/* s40 Falling */
		/* [5:0]=17 */
		odm_set_bb_reg(dm, R_0x874, 0x3f, 0x17);
		/* pri20 s20 s40 Min */
		/* [5:0]=9 [11:6]=9 [17:12]=12 */
		odm_set_bb_reg(dm, R_0x8a4, 0x3ffff, 0x12249);
		break;
	}
	case CHANNEL_WIDTH_5: {
		/* pri20 Falling, Rising, Max */
		/* [31:26]=1a [25:20]=1d [19:14]=1e */
		odm_set_bb_reg(dm, R_0x86c, 0xffffc000, 0x1a75e);
		/* pri20 Min */
		/* [5:0]=15 */
		odm_set_bb_reg(dm, R_0x8a4, 0x3f, 0x15);
		break;
	}
	case CHANNEL_WIDTH_10: {
		/* pri20 Falling, Rising, Max */
		/* [31:26]=1a [25:20]=1d [19:14]=1e */
		odm_set_bb_reg(dm, R_0x86c, 0xffffc000, 0x1a75e);
		/* pri20 Min */
		/* [5:0]=15 */
		odm_set_bb_reg(dm, R_0x8a4, 0x3f, 0x15);
		break;
	}
	case CHANNEL_WIDTH_80_80: {
		odm_set_bb_reg(dm, R_0x830, 0x3f, 0x1a); /* PW th 2nd40 */
		/* [31:26]=0x1b, [25:20]=0x1e, [19:14]=0x1f */
		odm_set_bb_reg(dm, R_0x86c, 0xffffc000, 0x1B79F);
		/* th_min */
		/* [17:12]=0x18 [11:6]=0x16, [5:0]=0x16 */
		odm_set_bb_reg(dm, R_0x8a4, 0x3ffff, 0x18596);
		/*
		 * 2nd20 dynamic th
		 * [17:12]=0x1a, [11:6]=0x1d, [5:0]=0x1e
		 * 2nd40 dynamic th
		 * [29:24]=0x20, [23:18]=0x21
		 */
		odm_set_bb_reg(dm, R_0x870, 0x3FFFFFFF, 0x2085D75E);
		odm_set_bb_reg(dm, R_0x874, 0x3f, 0x1d);
		break;
	}
	default:
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "set fail, unknown bandwidth: %d\n", bw);
	}
}

__odm_func__
void
config_phydm_path_adda_setting_8814b(struct dm_struct *dm)
{
	u8 available_path = dm->rx_ant_status | dm->tx_ant_status;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s ======> Path = %d\n", __func__,
		  dm->rx_ant_status);
	odm_set_bb_reg(dm, R_0x1830, BIT(30), 0x1);
	odm_set_bb_reg(dm, R_0x4130, BIT(30), 0x1);
	odm_set_bb_reg(dm, R_0x5230, BIT(30), 0x1);
	odm_set_bb_reg(dm, R_0x5330, BIT(30), 0x1);
	/*1: enable ANAPAR value, 0: disable*/
	if (!(available_path & BB_PATH_A))
		odm_set_bb_reg(dm, R_0x1830, BIT(30), 0x0);
	if (!(available_path & BB_PATH_B))
		odm_set_bb_reg(dm, R_0x4130, BIT(30), 0x0);
	if (!(available_path & BB_PATH_C))
		odm_set_bb_reg(dm, R_0x5230, BIT(30), 0x0);
	if (!(available_path & BB_PATH_D))
		odm_set_bb_reg(dm, R_0x5330, BIT(30), 0x0);
}

__odm_func__
boolean
phydm_config_cck_tx_path_8814b(struct dm_struct *dm, enum bb_path tx_path)
{
	boolean set_result = PHYDM_SET_FAIL;

	/* Control CCK TX path by R_0x1e5c */
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

__odm_func__
boolean
phydm_config_cck_rx_path_8814b(struct dm_struct *dm, enum bb_path rx_path)
{
	boolean set_result = PHYDM_SET_FAIL;
	/* ---------always 1R CCK ---------- */
	/*[RX Antenna Setting] ==========================================*/
	/*Disable MRC for CCK CCA */
	/*odm_set_bb_reg(dm, R_0x1a2c, 0x00600000, 0x0);*/
	/*Disable MRC for CCK barker */
	/*odm_set_bb_reg(dm, R_0x1a2c, 0x00060000, 0x0);*/
	odm_set_bb_reg(dm, R_0x1ac0, 0x80000000, 0x0);
#if 0
	/* CCK antenna diversity */
	if (dm->rf_type > RF_1T1R)
		odm_set_bb_reg(dm, R_0x1a00, BIT(15), 0x0);
	else
		odm_set_bb_reg(dm, R_0x1a00, BIT(15), 0x1);
#endif
	/* Setting the 4-path RX MRC enable */
	if (rx_path == BB_PATH_A || rx_path == BB_PATH_B ||
	    rx_path == BB_PATH_C || rx_path == BB_PATH_D) {
		odm_set_bb_reg(dm, R_0x1a2c, 0x00000020, 0x1);
		/*r_dis_rx_path_clk_gat*/
		odm_set_bb_reg(dm, R_0x1a2c, 0x00600000, 0x0);
		odm_set_bb_reg(dm, R_0x1a2c, 0x00060000, 0x0);
	} else if (rx_path == BB_PATH_AB) {
		odm_set_bb_reg(dm, R_0x1a2c, 0x00000020, 0x0);
		/*r_dis_rx_path_clk_gat*/
		odm_set_bb_reg(dm, R_0x1a2c, 0x00600000, 0x1);
		odm_set_bb_reg(dm, R_0x1a2c, 0x00060000, 0x1);
	} else if (rx_path == BB_PATH_ABC) {
		odm_set_bb_reg(dm, R_0x1a2c, 0x00000020, 0x0);
		/*r_dis_rx_path_clk_gat*/
		odm_set_bb_reg(dm, R_0x1a2c, 0x00600000, 0x2);
		odm_set_bb_reg(dm, R_0x1a2c, 0x00060000, 0x2);
	} else if (rx_path == BB_PATH_ABCD || rx_path == BB_PATH_AC ||
		   rx_path == BB_PATH_AD || rx_path == BB_PATH_BC ||
		   rx_path == BB_PATH_BD || rx_path == BB_PATH_CD ||
		   rx_path == BB_PATH_ABD || rx_path == BB_PATH_ACD ||
		   rx_path == BB_PATH_BCD) {
		odm_set_bb_reg(dm, R_0x1a2c, 0x00000020, 0x0);
		/*r_dis_rx_path_clk_gat*/
		odm_set_bb_reg(dm, R_0x1a2c, 0x00600000, 0x3);
		odm_set_bb_reg(dm, R_0x1a2c, 0x00060000, 0x3);
	}

	/* Initailize the CCK path mapping */
	odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x0);
	odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0x0);

	/* CCK RX 1~4 path setting*/
	/* The path-X signal in the CCK is from the path-X (or Y) ADC */
	if (rx_path == BB_PATH_A) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x0); /*00,00*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0x0); /*00,00*/
	} else if (rx_path == BB_PATH_B) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x5); /*01,01*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0x5); /*01,01*/
	} else if (rx_path == BB_PATH_C) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0xa); /*10,10*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0xa); /*10,10*/
	} else if (rx_path == BB_PATH_D) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0xf); /*11,11*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0xf); /*11,11*/
	} else if (rx_path == BB_PATH_AB) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x1); /*00,01*/
		/*odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0x1); 00,01*/
	} else if (rx_path == BB_PATH_AC) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x0); /*00,00*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0xa); /*10,10*/
	} else if (rx_path == BB_PATH_AD) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x0); /*00,00*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0xf); /*ff,11*/
	} else if (rx_path == BB_PATH_BC) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x5); /*01,01*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0xa); /*10,10*/
	} else if (rx_path == BB_PATH_BD) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x5); /*01,01*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0xf); /*11,11*/
	} else if (rx_path == BB_PATH_CD) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0xb); /*10,11*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0xb); /*10,11*/
	} else if (rx_path == BB_PATH_ABC) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x1); /*00,01*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0x8); /*10,00*/
	} else if (rx_path == BB_PATH_ABD) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x1); /*00,01*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0xf); /*11,11*/
	} else if (rx_path == BB_PATH_ACD) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x0); /*00,00*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0xb); /*10,11*/
	} else if (rx_path == BB_PATH_BCD) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x5); /*01,01*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0xb); /*10,11*/
	} else if (rx_path == BB_PATH_ABCD) {
		odm_set_bb_reg(dm, R_0x1a04, 0x0f000000, 0x1); /*00,01*/
		odm_set_bb_reg(dm, R_0x1a84, 0x0f000000, 0xb); /*10,11*/
	}

	set_result = PHYDM_SET_SUCCESS;

	return set_result;
}

__odm_func__
boolean
phydm_config_ofdm_tx_path_8814b(struct dm_struct *dm,
				enum bb_path tx_path)
{
	boolean set_result = PHYDM_SET_SUCCESS;

	/*[TX Antenna Setting] ==========================================*/
	/* TX path HW block enable */
	odm_set_bb_reg(dm, R_0x1e28, 0xf, tx_path);
	dm->tx_ant_status = tx_path;
	/*1: Enable ANAPAR value, 0: disable*/
	config_phydm_path_adda_setting_8814b(dm);
	/* TX logic map and TX path en for Nsts = 1, and OFDM TX path*/
	if (tx_path == BB_PATH_A) { /* 1T, 1ss */
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x1); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x0); /* logic map */
	} else if (tx_path == BB_PATH_B) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x2); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x0); /* logic map */
	} else if (tx_path == BB_PATH_C) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x4); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x0); /* logic map */
	} else if (tx_path == BB_PATH_D) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x8); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x0); /* logic map */
	} else if (tx_path == BB_PATH_AB) { /* --2TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x3); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x4); /* logic map */
	} else if (tx_path == BB_PATH_AC) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x5); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x10); /* logic map */
	} else if (tx_path == BB_PATH_AD) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x9); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x40); /* logic map */
	} else if (tx_path == BB_PATH_BC) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x6); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x10); /* logic map */
	} else if (tx_path == BB_PATH_BD) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xa); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x40); /* logic map */
	} else if (tx_path == BB_PATH_CD) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xc); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x40); /* logic map */
	} else if (tx_path == BB_PATH_ABC) { /* --3TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x7); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x24); /* logic map */
	} else if (tx_path == BB_PATH_ABD) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xb); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x84); /* logic map */
	} else if (tx_path == BB_PATH_ACD) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xd); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x90); /* logic map */
	} else if (tx_path == BB_PATH_BCD) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xe); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x90); /* logic map */
	} else if (tx_path == BB_PATH_ABCD) { /* --4TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xf); /* path_en */
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0xe4); /* logic map */
	}

	/* TX logic map and TX path en for Nsts = 2*/
	if (tx_path == BB_PATH_AB) { /* --2TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x3);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x4);
	} else if (tx_path == BB_PATH_AC) {
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x5);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x10);
	} else if (tx_path == BB_PATH_AD) {
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x9);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x40);
	} else if (tx_path == BB_PATH_BC) {
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x6);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x10);
	} else if (tx_path == BB_PATH_BD) {
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xa);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x40);
	} else if (tx_path == BB_PATH_CD) {
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xc);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x40);
	} else if (tx_path == BB_PATH_ABC) { /* --3TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x7);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x24);
	} else if (tx_path == BB_PATH_ABD) {
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xb);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x84);
	} else if (tx_path == BB_PATH_ACD) {
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xd);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x90);
	} else if (tx_path == BB_PATH_BCD) {
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xe);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x90);
	} else if (tx_path == BB_PATH_ABCD) { /* --4TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xf);
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0xe4);
	}

	/* TX logic map and TX path en for Nsts = 3*/
	if (tx_path == BB_PATH_ABC) { /* --3TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0x7);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00ff0000, 0x24);
	} else if (tx_path == BB_PATH_ABD) {
		odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0xb);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00ff0000, 0x84);
	} else if (tx_path == BB_PATH_ACD) {
		odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0xd);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00ff0000, 0x90);
	} else if (tx_path == BB_PATH_BCD) {
		odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0xe);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00ff0000, 0x90);
	} else if (tx_path == BB_PATH_ABCD) { /* --4TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0xf);
		odm_set_bb_reg(dm, R_0x1e2c, 0x00ff0000, 0xe4);
	}

	/* TX logic map and TX path en for Nsts = 4 */
	if (tx_path == BB_PATH_ABCD) { /* --4TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x0000f000, 0xf);
		odm_set_bb_reg(dm, R_0x1e2c, 0xff000000, 0xe4);
	}
	return set_result;
}

__odm_func__
boolean
phydm_config_ofdm_tx_path_ext_8814b(struct dm_struct *dm,
				    enum bb_path tx_path,
				    enum bb_path tx_path_sel_1ss,
				    enum bb_path tx_path_sel_2ss,
				    enum bb_path tx_path_sel_3ss)
{
	boolean set_result = PHYDM_SET_SUCCESS;

	/*[TX Antenna Setting] ==========================================*/
	/* TX path HW block enable */
	//odm_set_bb_reg(dm, R_0x1e28, 0xf, tx_path);
	dm->tx_ant_status = tx_path;
	/* TX logic map and TX path en for Nsts = 1, and OFDM TX path*/
	if (tx_path_sel_1ss == BB_PATH_NON) {
		if (tx_path == BB_PATH_A) { /* 1T, 1ss */
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x1);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x0);
		} else if (tx_path == BB_PATH_B) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x2);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x0);
		} else if (tx_path == BB_PATH_C) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x4);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x0);
		} else if (tx_path == BB_PATH_D) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x8);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x0);
		} else if (tx_path == BB_PATH_AB) { /* --2TX-- */
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x3);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x4);
		} else if (tx_path == BB_PATH_AC) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x5);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x10);
		} else if (tx_path == BB_PATH_AD) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x9);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x40);
		} else if (tx_path == BB_PATH_BC) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x6);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x10);
		} else if (tx_path == BB_PATH_BD) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xa);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x40);
		} else if (tx_path == BB_PATH_CD) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xc);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x40);
		} else if (tx_path == BB_PATH_ABC) { /* --3TX-- */
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x7);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x24);
		} else if (tx_path == BB_PATH_ABD) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xb);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x84);
		} else if (tx_path == BB_PATH_ACD) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xd);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x90);
		} else if (tx_path == BB_PATH_BCD) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xe);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x90);
		} else if (tx_path == BB_PATH_ABCD) { /* --4TX-- */
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xf);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0xe4);
		}
	} else {
		if (tx_path_sel_1ss == BB_PATH_A) { /* 1T, 1ss */
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x1);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x0);
		} else if (tx_path_sel_1ss == BB_PATH_B) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x2);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x0);
		} else if (tx_path_sel_1ss == BB_PATH_C) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x4);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x0);
		} else if (tx_path_sel_1ss == BB_PATH_D) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x8);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x0);
		} else if (tx_path_sel_1ss == BB_PATH_AB) { /* --2TX-- */
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x3);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x4);
		} else if (tx_path_sel_1ss == BB_PATH_AC) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x5);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x10);
		} else if (tx_path_sel_1ss == BB_PATH_AD) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x9);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x40);
		} else if (tx_path_sel_1ss == BB_PATH_BC) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x6);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x10);
		} else if (tx_path_sel_1ss == BB_PATH_BD) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xa);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x40);
		} else if (tx_path_sel_1ss == BB_PATH_CD) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xc);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x40);
		} else if (tx_path_sel_1ss == BB_PATH_ABC) { /* --3TX-- */
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x7);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x24);
		} else if (tx_path_sel_1ss == BB_PATH_ABD) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xb);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x84);
		} else if (tx_path_sel_1ss == BB_PATH_ACD) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xd);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x90);
		} else if (tx_path_sel_1ss == BB_PATH_BCD) {
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xe);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0x90);
		} else if (tx_path_sel_1ss == BB_PATH_ABCD) { /* --4TX-- */
			odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0xf);
			odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0xe4);
		}
	}

	/* TX logic map and TX path en for Nsts = 2*/
	if (tx_path_sel_2ss == BB_PATH_NON) {
		if (tx_path == BB_PATH_AB) { /* --2TX-- */
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x3);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x4);
		} else if (tx_path == BB_PATH_AC) {
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x5);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x10);
		} else if (tx_path == BB_PATH_AD) {
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x9);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x40);
		} else if (tx_path == BB_PATH_BC) {
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x6);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x10);
		} else if (tx_path == BB_PATH_BD) {
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xa);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x40);
		} else if (tx_path == BB_PATH_CD) {
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xc);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x40);
		} else if (tx_path == BB_PATH_ABC) { /* --3TX-- */
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x7);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x24);
		} else if (tx_path == BB_PATH_ABD) {
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xb);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x84);
		} else if (tx_path == BB_PATH_ACD) {
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xd);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x90);
		} else if (tx_path == BB_PATH_BCD) {
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xe);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x90);
		} else if (tx_path == BB_PATH_ABCD) { /* --4TX-- */
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xf);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0xe4);
		}
	} else {
		if (tx_path_sel_2ss == BB_PATH_AB) { /* --2TX-- */
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x3);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x4);
		} else if (tx_path_sel_2ss == BB_PATH_AC) {
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x5);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x10);
		} else if (tx_path_sel_2ss == BB_PATH_AD) {
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x9);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x40);
		} else if (tx_path_sel_2ss == BB_PATH_BC) {
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x6);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x10);
		} else if (tx_path_sel_2ss == BB_PATH_BD) {
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xa);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x40);
		} else if (tx_path_sel_2ss == BB_PATH_CD) {
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xc);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x40);
		} else if (tx_path_sel_2ss == BB_PATH_ABC) { /* --3TX-- */
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x7);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x24);
		} else if (tx_path_sel_2ss == BB_PATH_ABD) {
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xb);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x84);
		} else if (tx_path_sel_2ss == BB_PATH_ACD) {
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xd);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x90);
		} else if (tx_path_sel_2ss == BB_PATH_BCD) {
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xe);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0x90);
		} else if (tx_path_sel_2ss == BB_PATH_ABCD) { /* --4TX-- */
			odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0xf);
			odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0xe4);
		}
	}

	/* TX logic map and TX path en for Nsts = 3*/
	if (tx_path_sel_3ss == BB_PATH_NON) {
		if (tx_path == BB_PATH_ABC) { /* --3TX-- */
			odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0x7);
			odm_set_bb_reg(dm, R_0x1e2c, 0x00ff0000, 0x24);
		} else if (tx_path == BB_PATH_ABD) {
			odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0xb);
			odm_set_bb_reg(dm, R_0x1e2c, 0x00ff0000, 0x84);
		} else if (tx_path == BB_PATH_ACD) {
			odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0xd);
			odm_set_bb_reg(dm, R_0x1e2c, 0x00ff0000, 0x90);
		} else if (tx_path == BB_PATH_BCD) {
			odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0xe);
			odm_set_bb_reg(dm, R_0x1e2c, 0x00ff0000, 0x90);
		} else if (tx_path == BB_PATH_ABCD) { /* --4TX-- */
			odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0xf);
			odm_set_bb_reg(dm, R_0x1e2c, 0x00ff0000, 0xe4);
		}
	} else {
		if (tx_path_sel_3ss == BB_PATH_ABC) { /* --3TX-- */
			odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0x7);
			odm_set_bb_reg(dm, R_0x1e2c, 0x00ff0000, 0x24);
		} else if (tx_path_sel_3ss == BB_PATH_ABD) {
			odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0xb);
			odm_set_bb_reg(dm, R_0x1e2c, 0x00ff0000, 0x84);
		} else if (tx_path_sel_3ss == BB_PATH_ACD) {
			odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0xd);
			odm_set_bb_reg(dm, R_0x1e2c, 0x00ff0000, 0x90);
		} else if (tx_path_sel_3ss == BB_PATH_BCD) {
			odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0xe);
			odm_set_bb_reg(dm, R_0x1e2c, 0x00ff0000, 0x90);
		} else if (tx_path_sel_3ss == BB_PATH_ABCD) { /* --4TX-- */
			odm_set_bb_reg(dm, R_0x820, 0x00000f00, 0xf);
			odm_set_bb_reg(dm, R_0x1e2c, 0x00ff0000, 0xe4);
		}
	}

	/* TX logic map and TX path en for Nsts = 4 */
	if (tx_path == BB_PATH_ABCD) { /* --4TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x0000f000, 0xf);
		odm_set_bb_reg(dm, R_0x1e2c, 0xff000000, 0xe4);
	}
	return set_result;
}

__odm_func__
boolean
phydm_config_ofdm_rx_path_8814b(struct dm_struct *dm,
				enum bb_path rx_path)
{
	u8 rfe_type = dm->rfe_type;
	boolean is_channel_2g = (*dm->channel <= 14) ? true : false;
	boolean set_result = PHYDM_SET_SUCCESS;

	/* Setting the number of the antenna in the idle condition*/
	odm_set_bb_reg(dm, R_0x824, MASKBYTE3LOWNIBBLE, rx_path);

	/* Setting the number of the antenna */
	odm_set_bb_reg(dm, R_0x824, 0xF0000, rx_path);  /* rx seg0 */

	dm->rx_ant_status = rx_path;

	/*1: enable ANAPAR value, 0: disable*/
	config_phydm_path_adda_setting_8814b(dm);

	/* Setting the RF mode */
	/* RF mode seeting in the RF-0 */
	if (!(rx_path & BB_PATH_A))
		config_phydm_write_rf_reg_8814b(dm, 0, RF_0x0, 0xf0000, 0x1);
	if (!(rx_path & BB_PATH_B))
		config_phydm_write_rf_reg_8814b(dm, 1, RF_0x0, 0xf0000, 0x1);
	if (!(rx_path & BB_PATH_C))
		config_phydm_write_rf_reg_8814b(dm, 2, RF_0x0, 0xf0000, 0x1);
	if (!(rx_path & BB_PATH_D))
		config_phydm_write_rf_reg_8814b(dm, 3, RF_0x0, 0xf0000, 0x1);

	if (rx_path == BB_PATH_A || rx_path == BB_PATH_B ||
	    rx_path == BB_PATH_C || rx_path == BB_PATH_D) {
		odm_set_bb_reg(dm, R_0x1d30, 0x300, 0x0);
		odm_set_bb_reg(dm, R_0x1d30, 0x600000, 0x0);
		odm_set_bb_reg(dm, R_0x884, 0x1c000, 0x5);
	} else if (rx_path == BB_PATH_AB || rx_path == BB_PATH_AC ||
		   rx_path == BB_PATH_AD || rx_path == BB_PATH_BC ||
		   rx_path == BB_PATH_BD || rx_path == BB_PATH_CD) {
		odm_set_bb_reg(dm, R_0x1d30, 0x300, 0x1);
		odm_set_bb_reg(dm, R_0x1d30, 0x600000, 0x1);
		odm_set_bb_reg(dm, R_0x884, 0x1c000, 0x5);
	} else if (rx_path == BB_PATH_ABC || rx_path == BB_PATH_ABD ||
		   rx_path == BB_PATH_ACD || rx_path == BB_PATH_BCD) {
		odm_set_bb_reg(dm, R_0x1d30, 0x300, 0x2);
		odm_set_bb_reg(dm, R_0x1d30, 0x600000, 0x2);
		odm_set_bb_reg(dm, R_0x884, 0x1c000, 0x4);
	} else if (rx_path == BB_PATH_ABCD) {
		odm_set_bb_reg(dm, R_0x1d30, 0x300, 0x3);
		odm_set_bb_reg(dm, R_0x1d30, 0x600000, 0x3);
		odm_set_bb_reg(dm, R_0x884, 0x1c000, 0x4);
	}
	if (*dm->mp_mode)
		phydm_dynamic_spur_det_eliminate_8814b(dm);
	/* by path settings for RFE6 */
	if (rfe_type == 6) {
		if (is_channel_2g) {
			PHYDM_DBG(dm, DBG_TMP, "RX_ant RFE6 2.4G\n");
			if (rx_path == BB_PATH_A || rx_path == BB_PATH_AD)
				odm_set_bb_reg(dm, R_0x1c98, MASKDWORD,
					       0x3f2a0500);
			else if (rx_path == BB_PATH_B || rx_path == BB_PATH_D ||
				 rx_path == BB_PATH_AB ||
				 rx_path == BB_PATH_BD ||
				 rx_path == BB_PATH_CD ||
				 rx_path == BB_PATH_BCD ||
				 rx_path == BB_PATH_ACD ||
				 rx_path == BB_PATH_ABD ||
				 rx_path == BB_PATH_ABCD)
				odm_set_bb_reg(dm, R_0x1c98, MASKDWORD,
					       0x3f2a1500);
			else if (rx_path == BB_PATH_C ||
				 rx_path == BB_PATH_BC ||
				 rx_path == BB_PATH_ABC)
				odm_set_bb_reg(dm, R_0x1c98, MASKDWORD,
					       0x2f2a1500);
			else if (rx_path == BB_PATH_AC)
				odm_set_bb_reg(dm, R_0x1c98, MASKDWORD,
					       0x2f2a1100);
		} else {
			PHYDM_DBG(dm, DBG_TMP, "RX_ant RFE6 5G\n");
			if (rx_path == BB_PATH_A || rx_path == BB_PATH_AB ||
			    rx_path == BB_PATH_AC || rx_path == BB_PATH_ABC ||
			    rx_path == BB_PATH_ABD || rx_path == BB_PATH_ACD)
				odm_set_bb_reg(dm, R_0x1c98, MASKDWORD,
					       0x3f2a1500);
			else if (rx_path == BB_PATH_B ||
				 rx_path == BB_PATH_BC ||
				 rx_path == BB_PATH_BCD)
				odm_set_bb_reg(dm, R_0x1c98, MASKDWORD,
					       0x3f2a1510);
			else if (rx_path == BB_PATH_C || rx_path == BB_PATH_CD)
				odm_set_bb_reg(dm, R_0x1c98, MASKDWORD,
					       0x3f2a1500);
			else if (rx_path == BB_PATH_D || rx_path == BB_PATH_BD)
				odm_set_bb_reg(dm, R_0x1c98, MASKDWORD,
					       0x3f3a1510);
			else if (rx_path == BB_PATH_AD)
				odm_set_bb_reg(dm, R_0x1c98, MASKDWORD,
					       0x3f3a1500);
		}
	}
	return set_result;
}

__odm_func__
boolean
config_phydm_trx_mode_ext_8814b(struct dm_struct *dm, enum bb_path tx_path,
				enum bb_path rx_path,
				enum bb_path tx_path_sel_1ss,
				enum bb_path tx_path_sel_2ss,
				enum bb_path tx_path_sel_3ss)
{
	u32 test = 0;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s ======>\n", __func__);
	PHYDM_DBG(dm, ODM_PHY_CONFIG, "1tx = %d , rx = %d\n", tx_path, rx_path);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "disable PHY API\n");
		return true;
	}

	if (((tx_path & ~BB_PATH_ABCD) != 0) ||
	    ((rx_path & ~BB_PATH_ABCD) != 0)) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "Wrong set: TX:0x%x, RX:0x%x\n", tx_path, rx_path);
		return false;
	}
	/* [mode table] RF mode of path-A and path-B ===================*/
	/* Cannot shut down path-A, beacause synthesizer will
	 *be shut down when path-A is in shut down mode
	 */
	/* Update TXRX antenna status for PHYDM */
	dm->tx_ant_status = (tx_path & 0xf);
	dm->rx_ant_status = (rx_path & 0xf);
	/* 3-wire setting */
	/* 0: shutdown, 1: standby, 2: TX, 3: RX */
	/* RF mode setting */
	odm_set_bb_reg(dm, 0x1800, 0xf0, 0x1);
	odm_set_bb_reg(dm, 0x4100, 0xf0, 0x1);
	odm_set_bb_reg(dm, 0x5200, 0xf0, 0x1);
	odm_set_bb_reg(dm, 0x5300, 0xf0, 0x1);
	if ((tx_path_sel_1ss | tx_path_sel_2ss | tx_path_sel_3ss) & BB_PATH_A)
		odm_set_bb_reg(dm, 0x1800, 0xf, 0x2);
	else
		odm_set_bb_reg(dm, 0x1800, 0xf, 0x1);
	if ((tx_path_sel_1ss | tx_path_sel_2ss | tx_path_sel_3ss) & BB_PATH_B)
		odm_set_bb_reg(dm, 0x4100, 0xf, 0x2);
	else
		odm_set_bb_reg(dm, 0x4100, 0xf, 0x1);
	if ((tx_path_sel_1ss | tx_path_sel_2ss | tx_path_sel_3ss) & BB_PATH_C)
		odm_set_bb_reg(dm, 0x5200, 0xf, 0x2);
	else
		odm_set_bb_reg(dm, 0x5200, 0xf, 0x1);
	if ((tx_path_sel_1ss | tx_path_sel_2ss | tx_path_sel_3ss) & BB_PATH_D)
		odm_set_bb_reg(dm, 0x5300, 0xf, 0x2);
	else
		odm_set_bb_reg(dm, 0x5300, 0xf, 0x1);
	if (rx_path & BB_PATH_A)
		odm_set_bb_reg(dm, 0x1800, 0xfff00, 0x333);
	else
		odm_set_bb_reg(dm, 0x1800, 0xfff00, 0x111);
	if (rx_path & BB_PATH_B)
		odm_set_bb_reg(dm, 0x4100, 0xfff00, 0x333);
	else
		odm_set_bb_reg(dm, 0x4100, 0xfff00, 0x111);
	if (rx_path & BB_PATH_C)
		odm_set_bb_reg(dm, 0x5200, 0xfff00, 0x333);
	else
		odm_set_bb_reg(dm, 0x5200, 0xfff00, 0x111);
	if (rx_path & BB_PATH_D)
		odm_set_bb_reg(dm, 0x5300, 0xfff00, 0x333);
	else
		odm_set_bb_reg(dm, 0x5300, 0xfff00, 0x111);
	/* Disable the SYN1 */
	if (*dm->mp_mode) /*for verification*/
		test = 0;
	else
		config_phydm_write_rf_syn_8814b(dm, RF_SYN1, RF_0x0, 0xf0000,
						0x0);
	/* Disable the 80+80 TRX  */
	odm_set_bb_reg(dm, R_0x9b0, BIT4 | BIT5, 0x0);
	/* CCK TX antenna mapping */
	phydm_config_cck_tx_path_8814b(dm, tx_path);

	/* OFDM TX antenna mapping*/
	phydm_config_ofdm_tx_path_ext_8814b(dm, tx_path, tx_path_sel_1ss,
					    tx_path_sel_2ss, tx_path_sel_3ss);
	odm_set_bb_reg(dm, R_0x1c28, 0xf, tx_path);

	/* CCK RX antenna mapping */
	phydm_config_cck_rx_path_8814b(dm, rx_path);

	/* OFDM RX antenna mapping*/
	phydm_config_ofdm_rx_path_8814b(dm, rx_path);

	if (rx_path == BB_PATH_A || rx_path == BB_PATH_B ||
	    rx_path == BB_PATH_C || rx_path == BB_PATH_D) {
		/* 1R */
		/* Disable Antenna weighting */
		odm_set_bb_reg(dm, R_0xc44, BIT(17), 0x0); /*AntWgt_en*/
		/*htstf ant-wgt enable = 0*/
		odm_set_bb_reg(dm, R_0xc54, BIT(20), 0x0);
		/*MRC_mode  =  'original ZF eqz'*/
		odm_set_bb_reg(dm, R_0xc38, BIT(24), 0x0);
	} else {
		/* 2R 3R 4R */
		/* Enable Antenna weighting */
		odm_set_bb_reg(dm, R_0xc44, BIT(17), 0x1); /*AntWgt_en*/
		/*htstf ant-wgt enable = 1*/
		odm_set_bb_reg(dm, R_0xc54, BIT(20), 0x1);
		/*MRC_mode =  'modified ZF eqz'*/
		odm_set_bb_reg(dm, R_0xc38, BIT(24), 0x1);
	}

	/* Toggle igi to let RF enter RX mode,
	 * because BB doesn't send 3-wire command when RX path is enable
	 */
	phydm_igi_toggle_8814b(dm);

	/* Modify CCA parameters */
	phydm_ccapar_by_rfe_8814b(dm);

	/* HW Setting depending on RFE type & band */
	/*phydm_rfe_8814b(dm, central_ch_8814b);*/

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "Success to set TRx mode setting (TX: 0x%x, RX: 0x%x)\n",
		  tx_path, rx_path);
	return true;
}

__odm_func__
boolean
config_phydm_trx_mode_8814b(struct dm_struct *dm, enum bb_path tx_path,
			    enum bb_path rx_path)
{
	u32 test = 0;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s ======>\n", __func__);
	PHYDM_DBG(dm, ODM_PHY_CONFIG, "1tx = %d , rx = %d\n", tx_path, rx_path);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "disable PHY API\n");
		return true;
	}

	if (((tx_path & ~BB_PATH_ABCD) != 0) ||
	    ((rx_path & ~BB_PATH_ABCD) != 0)) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "Wrong set: TX:0x%x, RX:0x%x\n", tx_path, rx_path);
		return false;
	}
	/* [mode table] RF mode of path-A and path-B ===================*/
	/* Cannot shut down path-A, beacause synthesizer will
	 *be shut down when path-A is in shut down mode
	 */
	/* Update TXRX antenna status for PHYDM */
	dm->tx_ant_status = (tx_path & 0xf);
	dm->rx_ant_status = (rx_path & 0xf);
	/* 3-wire setting */
	/* 0: shutdown, 1: standby, 2: TX, 3: RX */
	/* RF mode setting */
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
	/* Disable the SYN1 */
	if (*dm->mp_mode) /*for verification*/
		test = 0;
	else
		config_phydm_write_rf_syn_8814b(dm, RF_SYN1, RF_0x0, 0xf0000,
						0x0);
	/* Disable the 80+80 TRX  */
	odm_set_bb_reg(dm, R_0x9b0, BIT4 | BIT5, 0x0);
	/* CCK TX antenna mapping */
	phydm_config_cck_tx_path_8814b(dm, tx_path);

	/* OFDM TX antenna mapping*/
	phydm_config_ofdm_tx_path_8814b(dm, tx_path);
	odm_set_bb_reg(dm, R_0x1c28, 0xf, tx_path);

	/* CCK RX antenna mapping */
	phydm_config_cck_rx_path_8814b(dm, rx_path);

	/* OFDM RX antenna mapping*/
	phydm_config_ofdm_rx_path_8814b(dm, rx_path);

	if (rx_path == BB_PATH_A || rx_path == BB_PATH_B ||
	    rx_path == BB_PATH_C || rx_path == BB_PATH_D) {
		/* 1R */
		/* Disable Antenna weighting */
		odm_set_bb_reg(dm, R_0xc44, BIT(17), 0x0); /*AntWgt_en*/
		/*htstf ant-wgt enable = 0*/
		odm_set_bb_reg(dm, R_0xc54, BIT(20), 0x0);
		/*MRC_mode  =  'original ZF eqz'*/
		odm_set_bb_reg(dm, R_0xc38, BIT(24), 0x0);
	} else {
		/* 2R 3R 4R */
		/* Enable Antenna weighting */
		odm_set_bb_reg(dm, R_0xc44, BIT(17), 0x1); /*AntWgt_en*/
		/*htstf ant-wgt enable = 1*/
		odm_set_bb_reg(dm, R_0xc54, BIT(20), 0x1);
		/*MRC_mode =  'modified ZF eqz'*/
		odm_set_bb_reg(dm, R_0xc38, BIT(24), 0x1);
	}

	/* Toggle igi to let RF enter RX mode,
	 * because BB doesn't send 3-wire command when RX path is enable
	 */
	phydm_igi_toggle_8814b(dm);

	/* Modify CCA parameters */
	phydm_ccapar_by_rfe_8814b(dm);

	/* HW Setting depending on RFE type & band */
	/*phydm_rfe_8814b(dm, central_ch_8814b);*/

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "Success to set TRx mode setting (TX: 0x%x, RX: 0x%x)\n",
		  tx_path, rx_path);
	return true;
}

__odm_func__
boolean
config_phydm_trx_80p80_8814b(struct dm_struct *dm, enum bb_path tx_path,
			     enum bb_path rx_path, u8 pri_ch)
{
	/*u32 syn_buf_addr = 0x21, syn_ldo_addr = 0x20;
	 *u32 rf_bg = 0x7e, rf_ldo = 0xd3, rf_buf = 0xb0;
	 */
	u8 rx_path_seg0 = 0, rx_path_seg1 = 0;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s ======>\n", __func__);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "disable PHY API\n");
		return true;
	}

	if (((tx_path & ~BB_PATH_ABCD) != 0) ||
	    ((rx_path & ~BB_PATH_ABCD) != 0)) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "Wrong set: TX:0x%x, RX:0x%x\n", tx_path, rx_path);
		return false;
	}

	if (tx_path == BB_PATH_A || tx_path == BB_PATH_B ||
	    tx_path == BB_PATH_C || tx_path == BB_PATH_D ||
	    tx_path == BB_PATH_AB || tx_path == BB_PATH_CD ||
	    tx_path == BB_PATH_ABC || tx_path == BB_PATH_ABD ||
	    tx_path == BB_PATH_ACD || tx_path == BB_PATH_BCD)
		return false;
	if (pri_ch % 2 == 0) {
		/*pri_ch even -> seg0 low fc (RF_AB) */
		rx_path_seg0 = rx_path & BB_PATH_AB;
		rx_path_seg1 = rx_path & BB_PATH_CD;
	} else {
		return false;
	}
	/* Update TXRX antenna status for PHYDM */
	dm->tx_ant_status = (tx_path & 0xf);
	dm->rx_ant_status = (rx_path & 0xf);
	/* Enable the SYN1 */
	config_phydm_write_rf_syn_8814b(dm, RF_SYN1, RF_0x0, 0xf0000, 0x2);
	/* SYN0 and SYN1 RFC setting */
#if 0
	config_phydm_write_rf_syn_8814b(dm, RF_SYN0, syn_ldo_addr, BIT(13), 1);
	config_phydm_write_rf_syn_8814b(dm, RF_SYN0, syn_buf_addr, BIT(11), 1);
	config_phydm_write_rf_syn_8814b(dm, RF_SYN1, syn_ldo_addr, BIT(13), 1);
	config_phydm_write_rf_syn_8814b(dm, RF_SYN1, syn_buf_addr, BIT(11), 1);
	/* Path-A~D RFC setting */
	odm_set_rf_reg(dm, RF_PATH_A, rf_bg, BIT0, 1);
	odm_set_rf_reg(dm, RF_PATH_A, rf_ldo, BIT10, 1);
	odm_set_rf_reg(dm, RF_PATH_A, rf_buf, BIT17, 1);
	odm_set_rf_reg(dm, RF_PATH_B, rf_bg, BIT0, 1);
	odm_set_rf_reg(dm, RF_PATH_B, rf_ldo, BIT10, 0);
	odm_set_rf_reg(dm, RF_PATH_B, rf_buf, BIT17, 0);
	odm_set_rf_reg(dm, RF_PATH_C, rf_bg, BIT0, 1);
	odm_set_rf_reg(dm, RF_PATH_C, rf_ldo, BIT10, 0);
	odm_set_rf_reg(dm, RF_PATH_C, rf_buf, BIT17, 0);
	odm_set_rf_reg(dm, RF_PATH_D, rf_bg, BIT0, 1);
	odm_set_rf_reg(dm, RF_PATH_D, rf_ldo, BIT10, 1);
	odm_set_rf_reg(dm, RF_PATH_D, rf_buf, BIT17, 1);
#endif
	/* [mode table] RF mode of path-A~D =====================*/
	/* 3-wire setting */
	/* 0: shutdown, 1: standby, 2: TX, 3: RX */
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

	/* Enable the 80+80 TRX  */
	odm_set_bb_reg(dm, R_0x9b0, BIT4 | BIT5, 0x3);

	/* OFDM TX antenna mapping*/
	odm_set_bb_reg(dm, R_0x1e28, 0xf, tx_path & 0x3);
	odm_set_bb_reg(dm, R_0x1e28, 0xf0, tx_path & 0xc);
	/* TX logic map and TX path en for Nsts = 1, and OFDM TX path*/
	if (tx_path == BB_PATH_AC) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x1); /*seg0 path_en*/
		odm_set_bb_reg(dm, R_0x824, 0x0000000f, 0x4); /*seg1 path_en*/
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0xa0);/*TX logicmap*/
	} else if (tx_path == BB_PATH_AD) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x1); /*seg0 path_en*/
		odm_set_bb_reg(dm, R_0x824, 0x0000000f, 0x8); /*seg1 path_en*/
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0xa0);/*TX logicmap*/
	} else if (tx_path == BB_PATH_BC) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x2); /*seg0 path_en*/
		odm_set_bb_reg(dm, R_0x824, 0x0000000f, 0x4); /*seg1 path_en*/
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0xa0);/*TX logicmap*/
	} else if (tx_path == BB_PATH_BD) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x2); /*seg0 path_en*/
		odm_set_bb_reg(dm, R_0x824, 0x0000000f, 0x8); /*seg1 path_en*/
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0xa0);/*TX logicmap*/
	} else if (tx_path == BB_PATH_ABCD) {
		odm_set_bb_reg(dm, R_0x820, 0x0000000f, 0x3); /*seg0 path_en*/
		odm_set_bb_reg(dm, R_0x824, 0x0000000f, 0xc); /*seg1 path_en*/
		odm_set_bb_reg(dm, R_0x1e2c, 0x000000ff, 0xe4);/*TX logicmap*/
	}
	/* TX path en for Nsts = 2*/
	if (tx_path == BB_PATH_ABCD) { /* --4TX-- */
		odm_set_bb_reg(dm, R_0x820, 0x000000f0, 0x3); /*seg0 path_en*/
		odm_set_bb_reg(dm, R_0x824, 0x000000f0, 0xc); /*seg1 path_en*/
		odm_set_bb_reg(dm, R_0x1e2c, 0x0000ff00, 0xe4);/*TX logicmap*/
	}

	odm_set_bb_reg(dm, R_0x1c28, 0xf, tx_path);

	/* OFDM RX antenna mapping*/
	/* Setting the number of the antenna in the idle condition*/
	odm_set_bb_reg(dm, R_0x824, 0xF000000, rx_path_seg0);/* rxCCAseg0*/
	odm_set_bb_reg(dm, R_0x824, 0xF0000000, rx_path_seg1); /*rxCCAseg1*/
	/* Setting the number of the antenna */
	odm_set_bb_reg(dm, R_0x824, 0xF0000, rx_path_seg0);  /* rxseg0*/
	odm_set_bb_reg(dm, R_0x824, 0xF00000, rx_path_seg1); /* rxseg1*/

	config_phydm_path_adda_setting_8814b(dm);
	/* Setting the RF mode */
	/* RF mode setting in the RF-0 */
	if (!(rx_path & BB_PATH_A))
		odm_set_rf_reg(dm, 0, RF_0x0, 0xf0000, 0x1);
	if (!(rx_path & BB_PATH_B))
		odm_set_rf_reg(dm, 1, RF_0x0, 0xf0000, 0x1);
	if (!(rx_path & BB_PATH_C))
		odm_set_rf_reg(dm, 2, RF_0x0, 0xf0000, 0x1);
	if (!(rx_path & BB_PATH_D))
		odm_set_rf_reg(dm, 3, RF_0x0, 0xf0000, 0x1);

	if (rx_path == BB_PATH_AC || rx_path == BB_PATH_AD ||
	    rx_path == BB_PATH_BC || rx_path == BB_PATH_BD) {
		odm_set_bb_reg(dm, R_0x1d30, 0x300, 0x0);
		odm_set_bb_reg(dm, R_0x1d30, 0x600000, 0x0);
	} else if (rx_path == BB_PATH_ABCD) {
		odm_set_bb_reg(dm, R_0x1d30, 0x300, 0x1);
		odm_set_bb_reg(dm, R_0x1d30, 0x600000, 0x1);
	} else {
		return false;
	}
	odm_set_bb_reg(dm, R_0x884, 0x1c000, 0x5); /*Shawn 1R/2R setting*/
	if (rx_path == BB_PATH_A || rx_path == BB_PATH_B ||
	    rx_path == BB_PATH_C || rx_path == BB_PATH_D) {
		/* 1R */
		/* Disable Antenna weighting */
		odm_set_bb_reg(dm, R_0xc44, BIT(17), 0x0); /*AntWgt_en*/
		/*htstf ant-wgt enable = 0*/
		odm_set_bb_reg(dm, R_0xc54, BIT(20), 0x0);
		/*MRC_mode = 'original ZF eqz'*/
		odm_set_bb_reg(dm, R_0xc38, BIT(24), 0x0);
	} else {
		/* 2R */
		/* Enable Antenna weighting */
		odm_set_bb_reg(dm, R_0xc44, BIT(17), 0x1); /*AntWgt_en*/
		/*htstf ant-wgt enable = 1*/
		odm_set_bb_reg(dm, R_0xc54, BIT(20), 0x1);
		/*MRC_mode = 'modified ZF eqz'*/
		odm_set_bb_reg(dm, R_0xc38, BIT(24), 0x1);
	}

	/* Toggle igi to let RF enter RX mode,
	 *because BB doesn't send 3-wire command when RX path is enable
	 */
	phydm_igi_toggle_8814b(dm);

	/* Modify CCA parameters */
	phydm_ccapar_by_rfe_8814b(dm);

	/* HW Setting depending on RFE type & band */
	/*phydm_rfe_8814b(dm, central_ch_8814b);*/

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "Success to set 80+80 TRx mode (TX: 0x%x, RX: 0x%x)\n",
		  tx_path, rx_path);
	return true;
}

void phydm_dis_cck_trx_8814b(void *dm_void, u8 set_type)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	if (set_type == PHYDM_SET) {
		/* @CCK RxIQ weighting = [0,0] */
		odm_set_bb_reg(dm, R_0x1a14, 0x300, 0x3);
		/* @disable CCK Tx */
		odm_set_bb_reg(dm, R_0x1a04, 0xf0000000, 0x0);
	} else if (set_type == PHYDM_REVERT) {
		/* @CCK RxIQ weighting = [1,1] */
		odm_set_bb_reg(dm, R_0x1a14, 0x300, 0x0);
		/* @enable CCK Tx */
		phydm_config_cck_tx_path_8814b(dm,
					       (enum bb_path)dm->tx_ant_status);
	}
}

__odm_func__
boolean
config_phydm_switch_band_8814b(struct dm_struct *dm,
			       u8 central_ch)
{
	/*u32 rf_reg18 = 0;*/
	boolean rf_reg_status = true;
#if 0
	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s ======>\n", __func__);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "Disable PHY API for dbg\n");
		return true;
	}

	rf_reg18 = config_phydm_read_syn_reg_8814b(dm, RF_SYN0, RF_0x18,
						   RFREG_MASK);
	if (rf_reg18 != INVALID_RF_DATA)
		rf_reg_status = true;
	else
		rf_reg_status = false;

	if (central_ch <= 14) {
		/* 2.4G */

		/* @Enable CCK TRx */
		phydm_dis_cck_trx_8814b(dm, PHYDM_REVERT);

		/* Disable MAC CCK check */
		odm_set_bb_reg(dm, R_0x454, BIT(7), 0x0);

		/* Disable BB CCK check */
		odm_set_bb_reg(dm, R_0x1a80, BIT(18), 0x0);

		/* @CCA Mask, default = 0xf */
		odm_set_bb_reg(dm, R_0x1c80, 0x3F000000, 0xF);

		/* RF band, set as Ch1*/
		rf_reg18 &= ~(BIT(16) | BIT(9) | BIT(8) | MASKBYTE0);
		rf_reg18 = rf_reg18 | 0x1;
	} else if (central_ch > 35) {
		/* 5G */

		/* Enable BB CCK check */
		odm_set_bb_reg(dm, R_0x1a80, BIT(18), 0x1);

		/* Enable MAC CCK check */
		odm_set_bb_reg(dm, R_0x454, BIT(7), 0x1);

		/* @Disable CCK TRx */
		phydm_dis_cck_trx_8814b(dm, PHYDM_SET);

		/* @CCA Mask */
		odm_set_bb_reg(dm, R_0x1c80, 0x3F000000, 0x22);

		/* RF band -> 5G , set as Ch36*/
		rf_reg18 &= ~(BIT(16) | BIT(9) | BIT(8) | MASKBYTE0);
		rf_reg18 |= (BIT(8) | BIT(16) | 0x24);
	} else {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "Fail to switch band (ch: %d)\n",
			  central_ch);
		return false;
	}

	config_phydm_write_rf_syn_8814b(dm, RF_SYN0, RF_0x18,
					RFREG_MASK, rf_reg18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_A, RF_0x18,
					RFREG_MASK, rf_reg18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_B, RF_0x18,
					RFREG_MASK, rf_reg18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_C, RF_0x18,
					RFREG_MASK, rf_reg18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_D, RF_0x18,
					RFREG_MASK, rf_reg18);
	if (!phydm_rfe_8814b(dm, central_ch))
		return false;

	if (!rf_reg_status) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "Fail to switch band (ch: %d), write RF_reg fail\n",
			  central_ch);
		return false;
	}
	/*BB rst*/
	phydm_bb_reset_8814b(dm);

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "Success to switch band (ch: %d)\n",
		  central_ch);
#endif
	return rf_reg_status;
}

__odm_func__
void
phydm_agc_tab_sel_8814b(struct dm_struct *dm, u8 central_ch)
{
	struct phydm_dig_struct *dig_tab = &dm->dm_dig_table;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "====AGC Tab Sel====\n");
	/* 2. AGC table selection */
	if (central_ch <= 14) {
		odm_set_bb_reg(dm, R_0x18ac, 0x1f0, 0x0); /*Path-A*/
		odm_set_bb_reg(dm, R_0x41ac, 0x1f0, 0x0); /*Path-B*/
		odm_set_bb_reg(dm, R_0x52ac, 0x1f0, 0x0); /*Path-C*/
		odm_set_bb_reg(dm, R_0x53ac, 0x1f0, 0x0); /*Path-D*/
		dig_tab->agc_table_idx = 0x0;
	} else if (central_ch >= 36 && central_ch <= 64) {
		odm_set_bb_reg(dm, R_0x18ac, 0x1f0, 0x1);
		odm_set_bb_reg(dm, R_0x41ac, 0x1f0, 0x1);
		odm_set_bb_reg(dm, R_0x52ac, 0x1f0, 0x1);
		odm_set_bb_reg(dm, R_0x53ac, 0x1f0, 0x1);
		dig_tab->agc_table_idx = 0x1;
	} else if ((central_ch >= 100) && (central_ch <= 144)) {
		odm_set_bb_reg(dm, R_0x18ac, 0x1f0, 0x2);
		odm_set_bb_reg(dm, R_0x41ac, 0x1f0, 0x2);
		odm_set_bb_reg(dm, R_0x52ac, 0x1f0, 0x2);
		odm_set_bb_reg(dm, R_0x53ac, 0x1f0, 0x2);
		dig_tab->agc_table_idx = 0x2;
	} else if (central_ch >= 149) {
		odm_set_bb_reg(dm, R_0x18ac, 0x1f0, 0x3);
		odm_set_bb_reg(dm, R_0x41ac, 0x1f0, 0x3);
		odm_set_bb_reg(dm, R_0x52ac, 0x1f0, 0x3);
		odm_set_bb_reg(dm, R_0x53ac, 0x1f0, 0x3);
		dig_tab->agc_table_idx = 0x3;
	} else {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "(AGC) Fail\n");
	}
}

__odm_func__
void
phydm_cck_tx_shaping_filter_8814b(struct dm_struct *dm, u8 central_ch)
{
	/* @CCK TX filter parameters */
	if (central_ch == 14) {
		odm_set_bb_reg(dm, R_0x1a24, MASKDWORD, 0xb81c);
		odm_set_bb_reg(dm, R_0x1a28, MASKLWORD, 0x0);
		odm_set_bb_reg(dm, R_0x1aac, MASKDWORD, 0x3667);
	} else {
		odm_set_bb_reg(dm, R_0x1a24, MASKDWORD, 0x64b80c1c);
		odm_set_bb_reg(dm, R_0x1a28, MASKLWORD,
			       (0x8810 & MASKLWORD));
		odm_set_bb_reg(dm, R_0x1aac, MASKDWORD, 0x1235667);
	}
}

__odm_func__
void
phydm_sco_trk_fc_setting_8814b(struct dm_struct *dm, u8 central_ch)
{
	PHYDM_DBG(dm, ODM_PHY_CONFIG, "====Set fc for clk offset====\n");
	if (central_ch == 13 || central_ch == 14) {
		/*n:41 s:37*/
		odm_set_bb_reg(dm, R_0xc30, MASK12BITS, 0x969);
	} else if (central_ch == 11 || central_ch == 12) {
		/* n:42, s:37 */
		odm_set_bb_reg(dm, R_0xc30, 0xfff, 0x96a);
	} else if (central_ch >= 1 && central_ch <= 10) {
		/*n:42 s:38*/
		odm_set_bb_reg(dm, R_0xc30, MASK12BITS, 0x9aa);
	} else if (central_ch >= 36 && central_ch <= 51) {
		/* n:20, s:18 */
		odm_set_bb_reg(dm, R_0xc30, 0xfff, 0x494);
	} else if (central_ch >= 52 && central_ch <= 55) {
		/* n:19, s:18 */
		odm_set_bb_reg(dm, R_0xc30, 0xfff, 0x493);
	} else if ((central_ch >= 56) && (central_ch <= 111)) {
		/* n:19, s:17 */
		odm_set_bb_reg(dm, R_0xc30, 0xfff, 0x453);
	} else if ((central_ch >= 112) && (central_ch <= 119)) {
		/* n:18, s:17 */
		odm_set_bb_reg(dm, R_0xc30, 0xfff, 0x452);
	} else if ((central_ch >= 120) && (central_ch <= 172)) {
		/* n:18, s:16 */
		odm_set_bb_reg(dm, R_0xc30, 0xfff, 0x412);
	} else if ((central_ch >= 173) && (central_ch <= 177)) {
		/* n:17, s:16 */
		odm_set_bb_reg(dm, R_0xc30, 0xfff, 0x411);
	} else {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "(fc_area)Fail\n");
	}
}

__odm_func__
boolean
config_phydm_switch_channel_8814b(struct dm_struct *dm, u8 central_ch)
{
	u32 rf_18 = 0;
	u8 band_index = 0, i = 0;
	boolean is_2g_ch = true;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s()====================>\n", __func__);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: disable PHY API for debug!!\n", __func__);
		return true;
	}

	if ((central_ch > 14 && central_ch < 36) ||
	    (central_ch > 64 && central_ch < 100) ||
	    (central_ch > 144 && central_ch < 149) ||
	    central_ch > 177) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "Error CH:%d\n", central_ch);
		return false;
	}

	central_ch_8814b = central_ch;

	/* Error handling for wrong HW setting due to wrong channel setting */
	if (central_ch_8814b <= 14)
		band_index = 1;
	else
		band_index = 2;

	if (dm->rfe_hwsetting_band != band_index)
		phydm_rfe_8814b(dm, central_ch_8814b);

	/* RF register setting */
	rf_18 = config_phydm_read_syn_reg_8814b(dm, RF_SYN0, RF_0x18,
						RFREGOFFSETMASK);
	if (rf_18 == INVALID_RF_DATA) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "Invalid RF_0x18\n");
		return false;
	}

	is_2g_ch = (central_ch <= 14) ? true : false;

	/* ==== [Set BB Reg] =================================================*/

	/* @1. AGC table selection */
	phydm_agc_tab_sel_8814b(dm, central_ch);
	/* @2. Set fc for clock offset tracking */
	phydm_sco_trk_fc_setting_8814b(dm, central_ch);
	/* @3. Other BB Settings*/
	if (is_2g_ch) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "set cahnnel 2.4G\n");
		phydm_cck_tx_shaping_filter_8814b(dm, central_ch);
		/* @Enable CCK TRx */
		phydm_dis_cck_trx_8814b(dm, PHYDM_REVERT);

		/* Disable MAC CCK check */
		odm_set_mac_reg(dm, R_0x454, BIT(7), 0x0);

		/* Disable BB CCK check */
		odm_set_bb_reg(dm, R_0x1a80, BIT(18), 0x0);

		/* @CCA Mask, default = 0xf */
		odm_set_bb_reg(dm, R_0x1c80, 0x3F000000, 0xF);

		/*RF band edge setting*/
		for (i = RF_PATH_A; i <= RF_PATH_D; i++) {
			if (*dm->band_width == CHANNEL_WIDTH_20)
				odm_set_rf_reg(dm, i, RF_0x5d, 0xf0000, 0x8);
			else if (*dm->band_width == CHANNEL_WIDTH_40)
				odm_set_rf_reg(dm, i, RF_0x5d, 0xf0000, 0xa);
		}
	} else {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "set cahnnel 5G\n");
		/* Enable BB CCK check */
		odm_set_bb_reg(dm, R_0x1a80, BIT(18), 0x1);
		/* Enable MAC CCK check */
		odm_set_mac_reg(dm, R_0x454, BIT(7), 0x1);
		/* @Disable CCK TRx */
		phydm_dis_cck_trx_8814b(dm, PHYDM_SET);
		/* @CCA Mask */
		odm_set_bb_reg(dm, R_0x1c80, 0x3F000000, 0x22);
	}

	/* ==== [Set RF Reg 0x18] ===========================================*/
	rf_18 &= ~0x703ff; /*[18:17],[16],[9:8],[7:0]*/
	rf_18 |= central_ch; /* @Channel*/

	if (!is_2g_ch) { /*5G*/
		rf_18 |= (BIT(16) | BIT(8));

		/* @5G Sub-Band, 01: 5400<f<=5720, 10: f>5720*/
		if (central_ch > 144)
			rf_18 |= BIT(18);
		else if (central_ch >= 80)
			rf_18 |= BIT(17);
	} else { /*2.4G*/
		/*For B-cut bandedge setting*/
		if (bw_8814b == CHANNEL_WIDTH_40) {
			rf_18 = rf_18 & (~(BIT(14) | BIT(13) | BIT(12)));
			if (central_ch > 3 && central_ch < 9)
				rf_18 = rf_18 | BIT(12);
		}
	}

	/* Set the RF-A~D and SYN0 */
	config_phydm_write_rf_syn_8814b(dm, RF_SYN0, RF_0x18,
					RFREGOFFSETMASK, rf_18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_A, RF_0x18,
					RFREGOFFSETMASK, rf_18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_B, RF_0x18,
					RFREGOFFSETMASK, rf_18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_C, RF_0x18,
					RFREGOFFSETMASK, rf_18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_D, RF_0x18,
					RFREGOFFSETMASK, rf_18);
	/*Setting subband*/
	rf_18 = 0;
	rf_18 = config_phydm_read_syn_reg_8814b(dm, RF_SYN0, RF_0x18,
						RFREGOFFSETMASK);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_A, RF_0x18,
					RFREGOFFSETMASK, rf_18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_B, RF_0x18,
					RFREGOFFSETMASK, rf_18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_C, RF_0x18,
					RFREGOFFSETMASK, rf_18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_D, RF_0x18,
					RFREGOFFSETMASK, rf_18);
	/*====================================================================*/

	phydm_igi_toggle_8814b(dm);
	/* Dynamic spur detection by PSD and NBI/CSI mask */

	if (!phydm_rfe_8814b(dm, central_ch))
		return false;

	if (*dm->mp_mode) {
		dm->is_psd_in_process = 1;
		phydm_dynamic_spur_det_eliminate_8814b(dm);
		dm->is_psd_in_process = 0;
	}

#ifdef CONFIG_RCK_OFFSET_ADJUST_8814B
	phydm_set_rck_offset_8814b(dm, RCK_OFFSET_NORMAL);
#endif

	/* disable DPD by rate */
	phydm_dyn_dpd_8814b(dm, central_ch);


	/*BB rst*/
	phydm_bb_reset_8814b(dm);

	phydm_ccapar_by_rfe_8814b(dm);
	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "%s(): Success to switch channel (ch: %d)\n", __func__,
		  central_ch);
	return true;
}

__odm_func__
boolean
config_phydm_switch_bw_8814b(struct dm_struct *dm, u8 pri_ch,
			     enum channel_width bandwidth)
{
	u32 rf_18, rf_syn1_18 = 0;
	boolean rf_reg_status = true;
	boolean en_cca_dyn_pw_th = false;
	/*u8 rfe_type = dm->rfe_type;*/

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s()=============>BW=%d, prich = %d\n",
		  __func__, bandwidth, pri_ch);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: disable PHY API for debug!!\n", __func__);
		return true;
	}

	/* Error handling */
	if (bandwidth >= CHANNEL_WIDTH_MAX ||
	    (bandwidth == CHANNEL_WIDTH_40 && pri_ch > 2) ||
	    (bandwidth == CHANNEL_WIDTH_80 && pri_ch > 4)) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: switch bandwidth fail(bw: %d, primary ch: %d)\n",
			  __func__, bandwidth, pri_ch);
		return false;
	}

	bw_8814b = bandwidth;
	if (bandwidth == CHANNEL_WIDTH_80_80) {
		/* Enable the SYN1 */
		config_phydm_write_rf_syn_8814b(dm, RF_SYN1, RF_0x0,
						0xf0000, 0x2);
		/*Set RFC mode*/
		phydm_config_set_rfc_8814b(dm, rfc_2x2);
		rf_18 = config_phydm_read_syn_reg_8814b(dm, RF_SYN0, RF_0x18,
							RFREGOFFSETMASK);
		rf_syn1_18 = config_phydm_read_syn_reg_8814b(dm, RF_SYN1,
							     RF_0x18,
							     RFREGOFFSETMASK);
		if (rf_18 != INVALID_RF_DATA && rf_syn1_18 != INVALID_RF_DATA)
			rf_reg_status = true;
		else
			rf_reg_status = false;
	} else {
		/*Set RFC mode*/
		phydm_config_set_rfc_8814b(dm, rfc_4x4);
		/* Disable the SYN1 */
		config_phydm_write_rf_syn_8814b(dm, RF_SYN1, RF_0x0,
						0xf0000, 0x0);
		rf_18 = config_phydm_read_syn_reg_8814b(dm, RF_SYN0, RF_0x18,
							RFREGOFFSETMASK);
		if (rf_18 != INVALID_RF_DATA)
			rf_reg_status = true;
		else
			rf_reg_status = false;
#ifdef CONFIG_RCK_OFFSET_ADJUST_8814B
	phydm_set_rck_offset_8814b(dm, RCK_OFFSET_NORMAL);
#endif		
	}

	/* Switch bandwidth */
	switch (bandwidth) {
	case CHANNEL_WIDTH_20: {
		odm_set_bb_reg(dm, R_0x9b0, 0x3, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0xc, 0x0);
		/* Disable the 80+80 TRX  */
		odm_set_bb_reg(dm, R_0x9b0, BIT4 | BIT5, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0xc0, 0x0); /*small BW*/
		odm_set_bb_reg(dm, R_0x9b0, 0xf00, pri_ch); /*TX pri ch*/
		odm_set_bb_reg(dm, R_0x9b0, 0xf000, pri_ch); /*RX pri ch*/
		/* DAC clock = 480M clock for BW20 */
		/* ADC clock = 160M clock for BW20 */
		odm_set_bb_reg(dm, R_0x9b4, MASKH3BYTES, 0xdb6db6);

		/* Gain setting */
		/* !!The value will depend on the contents of AGC table!! */
		/* AGC table change ==> parameter must be changed*/
		/* [19:14]=22, [25:20]=20, [31:26]=1d */
		odm_set_bb_reg(dm, R_0x86c, 0xffffc000, 0x1d822);
		odm_set_bb_reg(dm, R_0x88c, 0xf000, 0x0);
		odm_set_bb_reg(dm, R_0x8a4, 0x3f, 0x18);
		/* RF bandwidth - RX 2bit */
		rf_18 = (rf_18 | BIT(11) | BIT(10));
		/* RF bandwidth - TX 3bit */
		rf_18 = (rf_18 & (~(BIT(14) | BIT(13) | BIT(12))));
		break;
	}
	case CHANNEL_WIDTH_40: {
		/* CCK primary channel */
		if (pri_ch == 1)
			odm_set_bb_reg(dm, R_0x1a00, BIT(4), pri_ch);
		else
			odm_set_bb_reg(dm, R_0x1a00, BIT(4), 0);

		odm_set_bb_reg(dm, R_0x9b0, 0x3, 0x1); /*TX_RF_BW*/
		odm_set_bb_reg(dm, R_0x9b0, 0xc, 0x1); /*RX_RF_BW*/
		/* Disable the 80+80 TRX  */
		odm_set_bb_reg(dm, R_0x9b0, BIT4 | BIT5, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0xc0, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0xf00, pri_ch);
		odm_set_bb_reg(dm, R_0x9b0, 0xf000, pri_ch);

		/* Gain setting */
		/* !!The value will depend on the contents of AGC table!! */
		/* AGC table change ==> parameter must be changed*/
		/* [19:14]=26, [25:20]=24, [31:26]=21 */
		odm_set_bb_reg(dm, R_0x86c, 0xffffc000, 0x21926);
		odm_set_bb_reg(dm, R_0x88c, 0xf000, 0x0);
		odm_set_bb_reg(dm, R_0x8a4, MASK12BITS, 0x71c);

		/* RF bandwidth - RX 2bit */
		rf_18 = (rf_18 & (~(BIT(11) | BIT(10))));
		rf_18 = (rf_18 | BIT(11));
		/* RF bandwidth - TX 3bit */
		rf_18 = (rf_18 & (~(BIT(14) | BIT(13) | BIT(12))));
		rf_18 = (rf_18 | BIT(12)); /*New setting BW40=0 by morgan*/
		if (central_ch_8814b <= 3 || (central_ch_8814b >= 9 &&
					      central_ch_8814b < 14)) {
			rf_18 = (rf_18 & (~(BIT(14) | BIT(13) | BIT(12))));
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "ininininin40 ==> ch=%d, rf_18 = 0x%x\n",
				  central_ch_8814b, rf_18);
		}
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "BWWWWWW40 ==> ch=%d, rf_18 = 0x%x\n",
			  central_ch_8814b, rf_18);
		break;
	}
	case CHANNEL_WIDTH_80: {
		/* TX_RF_BW:[1:0]=0x2, RX_RF_BW:[3:2]=0x2 */
		odm_set_bb_reg(dm, R_0x9b0, 0xf, 0xa);
		/* Disable the 80+80 TRX  */
		odm_set_bb_reg(dm, R_0x9b0, BIT4 | BIT5, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0xc0, 0x0); /* small BW */
		/* TX pri ch:[11:8], RX pri ch:[15:12] */
		odm_set_bb_reg(dm, R_0x9b0, 0xff00, (pri_ch | (pri_ch << 4)));

		/* Gain setting */
		/* !!The value will depend on the contents of AGC table!! */
		/* AGC table change ==> parameter must be changed*/
		odm_set_bb_reg(dm, R_0x830, 0x3f, 0x1a); /* PW th 2nd40 */
		/* [31:26]=0x1b, [25:20]=0x1e, [19:14]=0x1f */
		odm_set_bb_reg(dm, R_0x86c, 0xffffc000, 0x1B79F);
		odm_set_bb_reg(dm, R_0x88c, 0xf000, 0x6);
		/* th_min */
		/* [17:12]=0x18 [11:6]=0x16, [5:0]=0x16 */
		odm_set_bb_reg(dm, R_0x8a4, 0x3ffff, 0x18596);

		/* RF bandwidth - RX 2bit */
		rf_18 &= ~(BIT(11) | BIT(10));
		rf_18 |= BIT(10);
		/* RF bandwidth - TX 3bit */
		rf_18 = (rf_18 & (~(BIT(14) | BIT(13) | BIT(12))));
		rf_18 = (rf_18 | BIT(13)); /*New setting BW80=1 by Morgan*/
		if (central_ch_8814b <= 3 || (central_ch_8814b >= 9 &&
					      central_ch_8814b < 14)) {
			rf_18 = (rf_18 & (~(BIT(14) | BIT(13) | BIT(12))));
			rf_18 = (rf_18 | BIT(12));
		}
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "BWWWWWW80 ==> ch=%d, rf_18 = 0x%x\n",
			  central_ch_8814b, rf_18);
		break;
	}
	case CHANNEL_WIDTH_5: {
		odm_set_bb_reg(dm, R_0x810, MASKDWORD, 0x10b02ab0);
		odm_set_bb_reg(dm, R_0x9b0, 0x3, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0xc, 0x0);
		/* Disable the 80+80 TRX  */
		odm_set_bb_reg(dm, R_0x9b0, BIT4 | BIT5, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0xc0, 0x1);
		odm_set_bb_reg(dm, R_0x9b0, 0xff00, 0x0);
		/* DAC clock = 120M clock for BW5 */
		/* ADC clock = 40M clock for BW5 */
		odm_set_bb_reg(dm, R_0x9b4, MASKH3BYTES, 0xdb4db2);
		/* RF bandwidth */
		rf_18 = (rf_18 | BIT(11) | BIT(10));
		/* RF bandwidth - TX 3bit */
		rf_18 = (rf_18 & (~(BIT(14) | BIT(13) | BIT(12))));

		break;
	}
	case CHANNEL_WIDTH_10: {
		odm_set_bb_reg(dm, R_0x810, MASKDWORD, 0x10b02ab0);
		odm_set_bb_reg(dm, R_0x9b0, 0x3, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0xc, 0x0);
		/* Disable the 80+80 TRX  */
		odm_set_bb_reg(dm, R_0x9b0, BIT4 | BIT5, 0x0);
		odm_set_bb_reg(dm, R_0x9b0, 0xc0, 0x2);
		odm_set_bb_reg(dm, R_0x9b0, 0xff00, 0x0);
		/* DAC clock = 240M clock for BW10 */
		/* ADC clock = 80M clock for BW10 */
		odm_set_bb_reg(dm, R_0x9b4, MASKH3BYTES, 0xdb4db4);

		/* RF bandwidth */
		rf_18 = (rf_18 | BIT(11) | BIT(10));
		/* RF bandwidth - TX 3bit */
		rf_18 = (rf_18 & (~(BIT(14) | BIT(13) | BIT(12))));

		break;
	}
	case CHANNEL_WIDTH_80_80: {
		/****setting the BW related****/
		/* TX_RF_BW:[1:0]=0x3, RX_RF_BW:[3:2]=0x3 */
		rf_18 = config_phydm_read_syn_reg_8814b(dm, RF_SYN0, RF_0x18,
							RFREGOFFSETMASK);
		rf_syn1_18 = config_phydm_read_syn_reg_8814b(dm, RF_SYN1,
							     RF_0x18,
							     RFREGOFFSETMASK);
		odm_set_bb_reg(dm, R_0x9b0, 0xf, 0xa);
		/* Enable the 80+80 TRX  */
		odm_set_bb_reg(dm, R_0x9b0, BIT4 | BIT5, 0x3);
		odm_set_bb_reg(dm, R_0x9b0, 0xc0, 0x0); /* small BW */
		odm_set_bb_reg(dm, R_0x9b0, 0xff00, (pri_ch | (pri_ch << 4)));
		/* Gain setting */
		/* !!The value will depend on the contents of AGC table!! */
		/* AGC table change ==> parameter must be changed*/
		odm_set_bb_reg(dm, R_0x830, 0x3f, 0x1a); /* PW th 2nd40 */
		/* [31:26]=0x1b, [25:20]=0x1e, [19:14]=0x1f */
		odm_set_bb_reg(dm, R_0x86c, 0xffffc000, 0x1B79F);
		odm_set_bb_reg(dm, R_0x88c, 0xf000, 0x6);
		/* th_min */
		/* [17:12]=0x18 [11:6]=0x16, [5:0]=0x16 */
		odm_set_bb_reg(dm, R_0x8a4, 0x3ffff, 0x18596);
		/*
		 * 2nd20 dynamic th
		 * [17:12]=0x1a, [11:6]=0x1d, [5:0]=0x1e
		 * 2nd40 dynamic th
		 * [29:24]=0x20, [23:18]=0x21
		 */
		odm_set_bb_reg(dm, R_0x870, 0x3FFFFFFF, 0x2085D75E);
		odm_set_bb_reg(dm, R_0x874, 0x3f, 0x1d);

		/* RF bandwidth - RX 2bit */
		rf_18 &= ~(BIT(11) | BIT(10));
		rf_18 |= BIT(10);
		rf_syn1_18 &= ~(BIT(11) | BIT(10));
		rf_syn1_18 |= BIT(10);
		/* RF bandwidth - TX 3bit */
		rf_18 = (rf_18 & (~(BIT(14) | BIT(13) | BIT(12))));
		rf_18 = (rf_18 | BIT(13));
		rf_syn1_18 = (rf_syn1_18 & (~(BIT(14) | BIT(13) | BIT(12))));
		rf_syn1_18 = (rf_syn1_18 | BIT(13));

		break;
	}
	default:
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s(): switch bandwidth fail(bw: %d, pri-ch: %d)\n",
			  __func__, bandwidth, pri_ch);
	}

	/* Write RF register */
	if (bandwidth == CHANNEL_WIDTH_80_80) {
		config_phydm_write_rf_syn_8814b(dm, RF_SYN0, RF_0x18,
						RFREGOFFSETMASK, rf_18);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x18, 0xfffff, rf_18);
		odm_set_rf_reg(dm, RF_PATH_B, RF_0x18, 0xfffff, rf_18);
		config_phydm_write_rf_syn_8814b(dm, RF_SYN1, RF_0x18,
						RFREGOFFSETMASK, rf_syn1_18);
		odm_set_rf_reg(dm, RF_PATH_C, RF_0x18, 0xfffff, rf_syn1_18);
		odm_set_rf_reg(dm, RF_PATH_D, RF_0x18, 0xfffff, rf_syn1_18);
	} else {
		config_phydm_write_rf_syn_8814b(dm, RF_SYN0, RF_0x18,
						RFREGOFFSETMASK, rf_18);
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x18, RFREGOFFSETMASK, rf_18);
		odm_set_rf_reg(dm, RF_PATH_B, RF_0x18, RFREGOFFSETMASK, rf_18);
		odm_set_rf_reg(dm, RF_PATH_C, RF_0x18, RFREGOFFSETMASK, rf_18);
		odm_set_rf_reg(dm, RF_PATH_D, RF_0x18, RFREGOFFSETMASK, rf_18);
	}
	if (!rf_reg_status) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: switch bandwidth fail(bw: %d, pri-ch: %d),",
			  __func__, bandwidth, pri_ch);
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  " because writing RF register is fail\n");
		return false;
	}

	/* Toggle IGI to let RF enter RX mode */
	phydm_igi_toggle_8814b(dm);

	/* Modify CCA parameters */
	phydm_ccapar_by_rfe_8814b(dm);

	/* Dynamic power threshold */
	if (dm->rfe_type == 0) {
		en_cca_dyn_pw_th = (boolean)odm_get_bb_reg(dm, R_0x86c, BIT(0));
		if (en_cca_dyn_pw_th) {
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "Enable dynamic power threshold\n");
			config_phydm_cca_dyn_pw_th(dm, bandwidth);
		}
	} else {
		/*Disable dynamic power thr*/
		odm_set_bb_reg(dm, R_0x86c, 0x1, 0x0);
	}

	/*BB rst*/
	phydm_bb_reset_8814b(dm);

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "%s: Success to switch bandwidth (bw: %d, primary ch: %d)\n",
		  __func__, bandwidth, pri_ch);
	return true;
}

__odm_func__
boolean
config_phydm_ch_80p80_8814b(struct dm_struct *dm, u8 central_ch1,
			    u8 central_ch2, u8 pri_ch)
{
	u32 rf_syn0_18 = 0, rf_syn1_18 = 0;
	boolean rf_reg_sta = true;
	/*u8 rfe_type = dm->rfe_type;*/
	struct phydm_dig_struct *dig_tab = &dm->dm_dig_table;
	u8 band_index = 0;
	u8 seg0_ch = 0, seg1_ch = 0;
#ifdef CONFIG_RCK_OFFSET_ADJUST_8814B
	u8 ch1_ch2_diff = 0;
#endif

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: disable PHY API for debug!!\n", __func__);
		return true;
	}

	/****setting the Band related****/
	/****setting the CH related****/
	if (pri_ch % 2) {
		seg0_ch = central_ch2; /*pri_ch odd -> seg0 high fc*/
		seg1_ch = central_ch1;
	} else {
		seg0_ch = central_ch1; /*pri_ch even -> seg0 low fc*/
		seg1_ch = central_ch2;
	}

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s()-->pri_ch = %d\n", __func__, pri_ch);
	central_ch_8814b = central_ch1;
	central_ch2_8814b = central_ch2;
	/* Error handling for wrong HW setting due to wrong channel setting */
	/*band index: 1=2.4Ghz, 2=5Ghz*/
	/*remove from here*/
	if (central_ch_8814b <= 14)
		band_index = 1;
	else
		band_index = 2;

	if (dm->rfe_hwsetting_band != band_index)
		phydm_rfe_8814b(dm, central_ch_8814b);

	/* RF register setting */
	rf_syn0_18 = config_phydm_read_syn_reg_8814b(dm, RF_SYN0, RF_0x18,
						     RFREGOFFSETMASK);
	rf_syn1_18 = config_phydm_read_syn_reg_8814b(dm, RF_SYN1, RF_0x18,
						     RFREGOFFSETMASK);
	if (rf_syn0_18 != INVALID_RF_DATA && rf_syn1_18 != INVALID_RF_DATA)
		rf_reg_sta = true;
	else
		rf_reg_sta = false;

	rf_syn0_18 = (rf_syn0_18 & (~(BIT(18) | BIT(17) | MASKBYTE0)));
	rf_syn1_18 = (rf_syn1_18 & (~(BIT(18) | BIT(17) | MASKBYTE0)));

	/* Switch band and channel */
	if (central_ch1 > 35 && central_ch2 > 35) {
		/* 5G */
		/* @Disable CCK block */
		phydm_dis_cck_trx_8814b(dm, PHYDM_SET);
		/* @Enable BB CCK check */
		odm_set_bb_reg(dm, R_0x1a80, BIT(18), 0x1);
		/* @Enable MAC CCK check */
		odm_set_bb_reg(dm, R_0x454, BIT(7), 0x1);
		/* OFDM CCA Mask, 0x22 */
		odm_set_bb_reg(dm, R_0x1c80, 0x3f000, 0x22);
		/* CCK CCA Mask, 0x22 */
		odm_set_bb_reg(dm, R_0x1c80, 0xfc0000, 0x22);

		/* 1. RF band and channel*/
		rf_syn0_18 |= seg0_ch;
		rf_syn1_18 |= seg1_ch;

		/* 2. primary 80 AGC table selection */
		if (central_ch1 >= 36 && central_ch1 <= 64) {
			odm_set_bb_reg(dm, R_0x18ac, 0x1f0, 0x1);
			odm_set_bb_reg(dm, R_0x41ac, 0x1f0, 0x1);
			dig_tab->agc_table_idx = 0x1;
		} else if ((central_ch1 >= 100) && (central_ch1 <= 144)) {
			odm_set_bb_reg(dm, R_0x18ac, 0x1f0, 0x2);
			odm_set_bb_reg(dm, R_0x41ac, 0x1f0, 0x2);
			dig_tab->agc_table_idx = 0x2;
		} else if (central_ch1 >= 149) {
			odm_set_bb_reg(dm, R_0x18ac, 0x1f0, 0x3);
			odm_set_bb_reg(dm, R_0x41ac, 0x1f0, 0x3);
			dig_tab->agc_table_idx = 0x3;
		} else {
			PHYDM_DBG(dm, ODM_PHY_CONFIG, "(pri-80 AGC) Fail\n");
			return false;
		}
		/* 3. 2nd80 AGC table selection */
		if (central_ch2 >= 36 && central_ch2 <= 64) {
			odm_set_bb_reg(dm, R_0x52ac, 0x1f0, 0x1);
			odm_set_bb_reg(dm, R_0x53ac, 0x1f0, 0x1);
			dig_tab->agc_table_idx = 0x1;
		} else if ((central_ch2 >= 100) && (central_ch2 <= 144)) {
			odm_set_bb_reg(dm, R_0x52ac, 0x1f0, 0x2);
			odm_set_bb_reg(dm, R_0x53ac, 0x1f0, 0x2);
			dig_tab->agc_table_idx = 0x2;
		} else if (central_ch2 >= 149) {
			odm_set_bb_reg(dm, R_0x52ac, 0x1f0, 0x3);
			odm_set_bb_reg(dm, R_0x53ac, 0x1f0, 0x3);
			dig_tab->agc_table_idx = 0x3;
		} else {
			PHYDM_DBG(dm, ODM_PHY_CONFIG, "(2nd-80 AGC) Fail\n");
			return false;
		}

		/* 4. Set central frequency for clock offset tracking */
		if (seg0_ch >= 36 && seg0_ch <= 48) {
			/* n:20, s:18 */
			odm_set_bb_reg(dm, R_0xc30, 0xfff, 0x494);
		} else if (seg0_ch == 52) {
			/* n:19, s:18 */
			odm_set_bb_reg(dm, R_0xc30, 0xfff, 0x493);
		} else if ((seg0_ch >= 56) && (seg0_ch <= 108)) {
			/* n:19, s:17 */
			odm_set_bb_reg(dm, R_0xc30, 0xfff, 0x453);
		} else if ((seg0_ch >= 112) && (seg0_ch <= 116)) {
			/* n:18, s:17 */
			odm_set_bb_reg(dm, R_0xc30, 0xfff, 0x452);
		} else if ((seg0_ch >= 120) && (seg0_ch <= 169)) {
			/* n:18, s:16 */
			odm_set_bb_reg(dm, R_0xc30, 0xfff, 0x412);
		} else if ((seg0_ch >= 173) && (seg0_ch <= 177)) {
			/* n:17, s:16 */
			odm_set_bb_reg(dm, R_0xc30, 0xfff, 0x411);
		} else {
			PHYDM_DBG(dm, ODM_PHY_CONFIG, "(pri-80 fc_area)Fail\n");
			return false;
		}
		/* 5. Set 2nd central frequency for clock offset tracking */
		if (seg1_ch >= 36 && seg1_ch <= 48) {
			/* n:20, s:18 */
			odm_set_bb_reg(dm, R_0x1c2c, 0xfff00000, 0x494);
		} else if (seg1_ch == 52) {
			/* n:19, s:18 */
			odm_set_bb_reg(dm, R_0x1c2c, 0xfff00000, 0x493);
		} else if ((seg1_ch >= 56) && (seg1_ch <= 108)) {
			/* n:19, s:17 */
			odm_set_bb_reg(dm, R_0x1c2c, 0xfff00000, 0x453);
		} else if ((seg1_ch >= 112) && (seg1_ch <= 116)) {
			/* n:18, s:17 */
			odm_set_bb_reg(dm, R_0x1c2c, 0xfff00000, 0x452);
		} else if ((seg1_ch >= 120) && (seg1_ch <= 169)) {
			/* n:18, s:16 */
			odm_set_bb_reg(dm, R_0x1c2c, 0xfff00000, 0x412);
		} else if ((seg1_ch >= 173) && (seg1_ch <= 177)) {
			/* n:17, s:16 */
			odm_set_bb_reg(dm, R_0x1c2c, 0xfff00000, 0x411);
		} else {
			PHYDM_DBG(dm, ODM_PHY_CONFIG, "(2nd-80 fc_area)Fail\n");
			return false;
		}

		/* RF band -> 5G */
		rf_syn0_18 &= ~(BIT(16) | BIT(9) | BIT(8));
		rf_syn0_18 |= (BIT(8) | BIT(16));
		rf_syn1_18 &= ~(BIT(16) | BIT(9) | BIT(8));
		rf_syn1_18 |= (BIT(8) | BIT(16));
	} else {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: Fail to switch channel (ch1: %d, ch2: %d)\n",
			  __func__, central_ch1, central_ch2);
		return false;
	}

	if (central_ch1 > 144)
		rf_syn0_18 = (rf_syn0_18 | BIT(18));
	else if (central_ch1 >= 80)
		rf_syn0_18 = (rf_syn0_18 | BIT(17));
	if (central_ch2 > 144)
		rf_syn1_18 = (rf_syn1_18 | BIT(18));
	else if (central_ch2 >= 80)
		rf_syn1_18 = (rf_syn1_18 | BIT(17));

	config_phydm_write_rf_syn_8814b(dm, RF_SYN0, RF_0x18,
					RFREGOFFSETMASK, rf_syn0_18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_A, RF_0x18,
					RFREGOFFSETMASK, rf_syn0_18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_B, RF_0x18,
					RFREGOFFSETMASK, rf_syn0_18);
	config_phydm_write_rf_syn_8814b(dm, RF_SYN1, RF_0x18,
					RFREGOFFSETMASK, rf_syn1_18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_C, RF_0x18,
					RFREGOFFSETMASK, rf_syn1_18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_D, RF_0x18,
					RFREGOFFSETMASK, rf_syn1_18);
	/*Subband setting*/
	rf_syn0_18 = 0;
	rf_syn1_18 = 0;
	rf_syn0_18 = config_phydm_read_syn_reg_8814b(dm, RF_SYN0, RF_0x18,
						     RFREGOFFSETMASK);
	rf_syn1_18 = config_phydm_read_syn_reg_8814b(dm, RF_SYN1, RF_0x18,
						     RFREGOFFSETMASK);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_A, RF_0x18,
					RFREGOFFSETMASK, rf_syn0_18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_B, RF_0x18,
					RFREGOFFSETMASK, rf_syn0_18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_C, RF_0x18,
					RFREGOFFSETMASK, rf_syn1_18);
	config_phydm_write_rf_reg_8814b(dm, RF_PATH_D, RF_0x18,
					RFREGOFFSETMASK, rf_syn1_18);

#ifdef CONFIG_RCK_OFFSET_ADJUST_8814B
	if (central_ch1 > central_ch2)
		ch1_ch2_diff = central_ch1 - central_ch2;
	else
		ch1_ch2_diff = central_ch2 - central_ch1;
	if (ch1_ch2_diff == 16)
		phydm_set_rck_offset_8814b(dm, RCK_OFFSET_MINUS_LV1);
	else
		phydm_set_rck_offset_8814b(dm, RCK_OFFSET_NORMAL);
#endif

	/* disable DPD by rate */
	phydm_dyn_dpd_8814b(dm, seg0_ch);

	/*BB rst*/
	phydm_bb_reset_8814b(dm);

	return rf_reg_sta;
}

__odm_func__
boolean
config_phydm_switch_channel_bw_8814b(struct dm_struct *dm, u8 central_ch,
				     u8 primary_ch_idx, enum channel_width bw)
{
	/* Switch band */
	if (!config_phydm_switch_band_8814b(dm, central_ch))
		return false;
	/* Switch channel */
	if (!config_phydm_switch_channel_8814b(dm, central_ch))
		return false;
	/* Switch bandwidth */
	if (!config_phydm_switch_bw_8814b(dm, primary_ch_idx, bw))
		return false;
	return true;
}

__odm_func__
boolean
config_phydm_parameter_init_8814b(struct dm_struct *dm,
				  enum odm_parameter_init type)
{
	/* @Turn on 3-wire*/
	/* FW can not access PHYDM API to read/write 3 wire*/
	odm_set_bb_reg(dm, R_0x180c, 0x3, 0x3);
	odm_set_bb_reg(dm, R_0x180c, BIT(28), 0x1);
	odm_set_bb_reg(dm, R_0x410c, 0x3, 0x3);
	odm_set_bb_reg(dm, R_0x410c, BIT(28), 0x1);
	odm_set_bb_reg(dm, R_0x520c, 0x3, 0x3);
	odm_set_bb_reg(dm, R_0x520c, BIT(28), 0x1);
	odm_set_bb_reg(dm, R_0x530c, 0x3, 0x3);
	odm_set_bb_reg(dm, R_0x530c, BIT(28), 0x1);

	/* Enable the SYN0 */
	config_phydm_write_rf_syn_8814b(dm, RF_SYN0, RF_0x0, 0xf0000, 0x2);
	/* Disable the SYN1 */
	config_phydm_write_rf_syn_8814b(dm, RF_SYN1, RF_0x0, 0xf0000, 0x0);
	if (type == ODM_PRE_SETTING) {
		/* 0x808 -> 0x1c3c, 0 ->29, 1->28 */
		odm_set_bb_reg(dm, R_0x1c3c, (BIT(0) | BIT(1)), 0x0);
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: Pre setting: disable OFDM and CCK block\n",
			  __func__);
	} else if (type == ODM_POST_SETTING) {
		/* 0x808 -> 0x1c3c, 0 ->29, 1->28 */
		odm_set_bb_reg(dm, R_0x1c3c, (BIT(0) | BIT(1)), 0x3);
		phydm_config_set_rfc_8814b(dm, rfc_4x4);
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: Post setting: enable OFDM and CCK block\n",
			  __func__);
#if (PHYDM_FW_API_FUNC_ENABLE_8814B == 1)
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

	#ifdef CONFIG_TXAGC_DEBUG_8814B
	/*phydm_txagc_tab_buff_init_8814b(dm);*/
	#endif

	return true;
}

__odm_func__
boolean
config_phydm_syn_ch_8814b(struct dm_struct *dm, u8 central_ch,
			  enum rf_syn syn_path)
{
	u32 rf_18;
	/*u32 syn_buf_addr = 0x21, syn_ldo_addr = 0x20;
	 *u32 rf_bg = 0x7e, rf_ldo = 0xd3, rf_buf = 0xb0;
	 */

	/*Set RFC mode*/
	phydm_config_set_rfc_8814b(dm, rfc_2x2);

	rf_18 = config_phydm_read_rf_reg_8814b(dm, RF_PATH_A, RF_0x18,
					       RFREGOFFSETMASK);
	/* Enable the SYN */
	if (syn_path == RF_SYN1)
		config_phydm_write_rf_syn_8814b(dm, syn_path, RF_0x0,
						0xf0000, 0x2);
	/*channel*/
	rf_18 = (rf_18 & (~(BIT(18) | BIT(17) | MASKBYTE0)));
	rf_18 |= central_ch;
	if (central_ch <= 14) {
		/* 2.4G */
		/* 1. RF channel*/
		rf_18 = (rf_18 | central_ch);
		/* RF band */
		rf_18 &= ~(BIT(16) | BIT(9) | BIT(8));
	} else if (central_ch > 35) {
		/* 1. RF channel*/
		rf_18 |= central_ch;
		/* RF band -> 5G */
		rf_18 &= ~(BIT(16) | BIT(9) | BIT(8));
		rf_18 |= (BIT(8) | BIT(16));
	}
	if (central_ch > 144)
		rf_18 = (rf_18 | BIT(18));
	else if (central_ch >= 80)
		rf_18 = (rf_18 | BIT(17));
	config_phydm_write_rf_syn_8814b(dm, syn_path, RF_0x18,
					RFREG_MASK, rf_18);
	return true;
}

__odm_func__
boolean
config_phydm_zero_wait_dfs_8814b(struct dm_struct *dm, enum rf_syn syn_path,
				 u8 central_ch)
{
	u32 rf_18 = 0;
	u8 rf_path1 = 0, rf_path2 = 0;

	switch (syn_path) {
	case RF_SYN0: {
		rf_path1 = RF_PATH_A;
		rf_path2 = RF_PATH_B;
		config_phydm_syn_ch_8814b(dm, central_ch, RF_SYN0);
		break;
	}
	case RF_SYN1: {
		rf_path1 = RF_PATH_C;
		rf_path2 = RF_PATH_D;
		config_phydm_syn_ch_8814b(dm, central_ch, RF_SYN1);
		break;
	}
	default:
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s(): SYN path error\n", __func__);
	}
	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: disable PHY API for debug!!\n", __func__);
		return true;
	}

	/*Switch A&B or C&D channel*/
	rf_18 = config_phydm_read_syn_reg_8814b(dm, syn_path, RF_0x18,
						RFREGOFFSETMASK);
	odm_set_rf_reg(dm, rf_path1, RF_0x18, RFREG_MASK, rf_18);
	odm_set_rf_reg(dm, rf_path2, RF_0x18, RFREG_MASK, rf_18);
	return true;
}

#if CONFIG_POWERSAVING
__odm_func_aon__
boolean
phydm_rfe_8814b_lps(struct dm_struct *dm, boolean enable_sw_rfe)
{
	/* u8 rfe_type = dm->rfe_type; */
	u32 rf_reg18_ch = 0;
	boolean rfe_cfg_status = false;

	rf_reg18_ch = config_phydm_read_rf_reg_8814b(dm, RF_PATH_A, RF_0x18,
						     0xff);

	/* HW Setting for each RFE type */
	if (!enable_sw_rfe) {
		rfe_cfg_status = phydm_rfe_8814b(dm, (u8)rf_reg18_ch);
	}

	return true;
}

__odm_func_aon__
boolean
phydm_8814b_lps(struct dm_struct *dm, boolean enable_lps)
{
	u16 poll_cnt = 0;
	u32 bbtemp = 0;

	if (enable_lps == _TRUE) {
		/* backup RF reg0x0 */
		SysMib.Wlan.PS.PSParm.RxGainPathA = (u16)(config_phydm_read_rf_reg_8814b(dm, RF_PATH_A, RF_0x00, RFREG_MASK));
		SysMib.Wlan.PS.PSParm.RxGainPathB = (u16)(config_phydm_read_rf_reg_8814b(dm, RF_PATH_B, RF_0x00, RFREG_MASK));
		SysMib.Wlan.PS.PSParm.RxGainPathC = (u16)(config_phydm_read_rf_reg_8814b(dm, RF_PATH_C, RF_0x00, RFREG_MASK));
		SysMib.Wlan.PS.PSParm.RxGainPathD = (u16)(config_phydm_read_rf_reg_8814b(dm, RF_PATH_D, RF_0x00, RFREG_MASK));

		/* turn off TRx HSSI: 0x180c[1:0]=2'b00, path:18/41/52/53 */
		bbtemp = odm_get_bb_reg(dm, R_0x180c, MASKDWORD) & 0xfffffffc;
		odm_set_bb_reg(dm, R_0x180c, MASKDWORD, bbtemp);
		bbtemp = odm_get_bb_reg(dm, R_0x410c, MASKDWORD) & 0xfffffffc;
		odm_set_bb_reg(dm, R_0x410c, MASKDWORD, bbtemp);
		bbtemp = odm_get_bb_reg(dm, R_0x520c, MASKDWORD) & 0xfffffffc;
		odm_set_bb_reg(dm, R_0x520c, MASKDWORD, bbtemp);
		bbtemp = odm_get_bb_reg(dm, R_0x530c, MASKDWORD) & 0xfffffffc;
		odm_set_bb_reg(dm, R_0x530c, MASKDWORD, bbtemp);

		/* Set RF enter shutdown mode */
		config_phydm_write_rf_reg_8814b(dm, RF_PATH_A, RF_0x0,
						RFREG_MASK, 0);
		config_phydm_write_rf_reg_8814b(dm, RF_PATH_B, RF_0x0,
						RFREG_MASK, 0);
		config_phydm_write_rf_reg_8814b(dm, RF_PATH_C, RF_0x0,
						RFREG_MASK, 0);
		config_phydm_write_rf_reg_8814b(dm, RF_PATH_D, RF_0x0,
						RFREG_MASK, 0);

		/* if eFEM, RFE control for signal source = 0 */
		phydm_rfe_8814b_lps(dm, _TRUE);

		/* Check BB state is idle, do not check GNT_WL only for LPS */
		while (1) {
			odm_set_bb_reg(dm, R_0x1c3c, 0x00f00000, 0x0);
			bbtemp = odm_get_bb_reg(dm, R_0x2db4, MASKDWORD);
			if ((bbtemp & 0x1FFEFF3F) == 0 &&
			    (bbtemp & 0xC0000000) == 0xC0000000)
				break;

			if (poll_cnt > WAIT_TXSM_STABLE_CNT) {
				WriteMACRegDWord(REG_DBG_DW_FW_ERR, ReadMACRegDWord(REG_DBG_DW_FW_ERR) | FES_BBSTATE_IDLE);
			/* SysMib.Wlan.DbgPort.DbgInfoParm.u4ErrFlag[0] |= FES_BBSTATE_IDLE; */
				return _FALSE;
			}

			DelayUS(WAIT_TXSM_STABLE_ONCE_TIME);
			poll_cnt++;
		}

		/* disable CCK and OFDM module */
		WriteMACRegByte(REG_SYS_FUNC_EN, ReadMACRegByte(REG_SYS_FUNC_EN)
				& ~BIT_FEN_BBRSTB);

		if (poll_cnt < WAIT_TXSM_STABLE_CNT) {
			/* Gated BBclk 0x1c24[0] = 1 */
			bbtemp = odm_get_bb_reg(dm, R_0x1c24, MASKDWORD) |
				 0x00000001;
			odm_set_bb_reg(dm, R_0x1c24, MASKDWORD, bbtemp);
		}

		return _TRUE;
	} else {
		/* release BB clk 0x1c24[0] = 0 */
		bbtemp = odm_get_bb_reg(dm, R_0x1c24, MASKDWORD) &
			 (~0x00000001);
		odm_set_bb_reg(dm, R_0x1c24, MASKDWORD, bbtemp);

		/* Enable CCK and OFDM module, */
		/* should be a delay large than 200ns before RF access */
		WriteMACRegByte(REG_SYS_FUNC_EN, ReadMACRegByte(REG_SYS_FUNC_EN)
				| BIT_FEN_BBRSTB);
		DelayUS(1);

		/* if eFEM, restore RFE control signal */
		phydm_rfe_8814b_lps(dm, _FALSE);

		/* Set RF enter active mode */
		config_phydm_write_rf_reg_8814b(dm, RF_PATH_A, R_0x00, RFREG_MASK, (0x30000 | SysMib.Wlan.PS.PSParm.RxGainPathA));
		config_phydm_write_rf_reg_8814b(dm, RF_PATH_B, R_0x00, RFREG_MASK, (0x30000 | SysMib.Wlan.PS.PSParm.RxGainPathB));
		config_phydm_write_rf_reg_8814b(dm, RF_PATH_C, R_0x00, RFREG_MASK, (0x30000 | SysMib.Wlan.PS.PSParm.RxGainPathC));
		config_phydm_write_rf_reg_8814b(dm, RF_PATH_D, R_0x00, RFREG_MASK, (0x30000 | SysMib.Wlan.PS.PSParm.RxGainPathD));

		/* turn on TRx HSSI: 0x180c[1:0]=2'b11, path: 18/41/52/53 */
		bbtemp = odm_get_bb_reg(dm, R_0x180c, MASKDWORD) | 0x00000003;
		odm_set_bb_reg(dm, R_0x180c, MASKDWORD, bbtemp);
		bbtemp = odm_get_bb_reg(dm, R_0x410c, MASKDWORD) | 0x00000003;
		odm_set_bb_reg(dm, R_0x410c, MASKDWORD, bbtemp);
		bbtemp = odm_get_bb_reg(dm, R_0x520c, MASKDWORD) | 0x00000003;
		odm_set_bb_reg(dm, R_0x520c, MASKDWORD, bbtemp);
		bbtemp = odm_get_bb_reg(dm, R_0x530c, MASKDWORD) | 0x00000003;
		odm_set_bb_reg(dm, R_0x530c, MASKDWORD, bbtemp);

		return _TRUE;
	}
}
#endif /* #if CONFIG_POWERSAVING */

/* ======================================================================== */
#endif /* PHYDM_FW_API_ENABLE_8814b == 1 */
#endif /* RTL8814b_SUPPORT == 1 */
