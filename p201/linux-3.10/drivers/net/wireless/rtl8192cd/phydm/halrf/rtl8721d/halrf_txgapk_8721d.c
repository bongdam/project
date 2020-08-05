// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2018  Realtek Corporation.
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
#if (DM_ODM_SUPPORT_TYPE == ODM_WIN)
#if RT_PLATFORM == PLATFORM_MACOSX
#include "phydm_precomp.h"
#else
#include "../phydm_precomp.h"
#endif
#else
#include "../../phydm_precomp.h"
#endif

#include "halrf_txgapk_8721d.h"

#if (RTL8721D_SUPPORT == 1)
/*---------------------------Define Local Constant---------------------------*/
void do_txgapk_8721d(void *dm_void,
		     u8 delta_thermal_index,
		     u8 thermal_value,
		     u8 threshold)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;

	phy_txgap_calibrate_8721d(dm, true);
}

void _txgapk_Phy_8721d(struct dm_struct *dm)
{
	RF_DBG(dm, DBG_RF_TXGAPK, "[DPK]=======_txgapk_Phy_8195b !!!!!=====\n");

	/*TGGC INIT*/
	odm_set_bb_reg(dm, 0xb00, MASKDWORD, 0x0005e018);
	odm_set_bb_reg(dm, 0xb04, MASKDWORD, 0xf76d9f84);
	odm_set_bb_reg(dm, 0xb28, MASKDWORD, 0x000844aa);
	odm_set_bb_reg(dm, 0xb68, MASKDWORD, 0x11160200);
	/*pwsf boundary*/
	odm_set_bb_reg(dm, 0xb30, MASKDWORD, 0x0007bdef);
	/*change to page B1*/
	odm_set_bb_reg(dm, 0xe28, MASKDWORD, 0x40000000);
	/*LUT SRAM block selection*/
	odm_set_bb_reg(dm, 0xbc0, MASKDWORD, 0x0000a9bf);/*01;0A;0D;1F*/
	/*change to page B*/
	odm_set_bb_reg(dm, 0xe28, MASKDWORD, 0x0);
	/*tx_amp*/
	odm_set_bb_reg(dm, 0xb08, MASKDWORD, 0x41382e21);
	odm_set_bb_reg(dm, 0xb0c, MASKDWORD, 0x5b554f48);
	odm_set_bb_reg(dm, 0xb10, MASKDWORD, 0x6f6b6661);
	odm_set_bb_reg(dm, 0xb14, MASKDWORD, 0x817d7874);
	odm_set_bb_reg(dm, 0xb18, MASKDWORD, 0x908c8884);
	odm_set_bb_reg(dm, 0xb1c, MASKDWORD, 0x9d9a9793);
	odm_set_bb_reg(dm, 0xb20, MASKDWORD, 0xaaa7a4a1);
	odm_set_bb_reg(dm, 0xb24, MASKDWORD, 0xb6b3b0ad);
	/*change to page B1*/
	odm_set_bb_reg(dm, 0xe28, MASKDWORD, 0x40000000);
	/*tx_inverse Page_B1*/
	odm_set_bb_reg(dm, 0xb00, MASKDWORD, 0x02ce03e8);
	odm_set_bb_reg(dm, 0xb04, MASKDWORD, 0x01fd024c);
	odm_set_bb_reg(dm, 0xb08, MASKDWORD, 0x01a101c9);
	odm_set_bb_reg(dm, 0xb0c, MASKDWORD, 0x016a0183);
	odm_set_bb_reg(dm, 0xb10, MASKDWORD, 0x01430153);
	odm_set_bb_reg(dm, 0xb14, MASKDWORD, 0x01280134);
	odm_set_bb_reg(dm, 0xb18, MASKDWORD, 0x0112011c);
	odm_set_bb_reg(dm, 0xb1c, MASKDWORD, 0x01000107);
	odm_set_bb_reg(dm, 0xb20, MASKDWORD, 0x00f200f9);
	odm_set_bb_reg(dm, 0xb24, MASKDWORD, 0x00e500eb);
	odm_set_bb_reg(dm, 0xb28, MASKDWORD, 0x00da00e0);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x00d200d6);
	odm_set_bb_reg(dm, 0xb30, MASKDWORD, 0x00c900cd);
	odm_set_bb_reg(dm, 0xb34, MASKDWORD, 0x00c200c5);
	odm_set_bb_reg(dm, 0xb38, MASKDWORD, 0x00bb00be);
	odm_set_bb_reg(dm, 0xb3c, MASKDWORD, 0x00b500b8);
	/*change to page B*/
	odm_set_bb_reg(dm, 0xe28, MASKDWORD, 0x0);
	/*[10] force enable ram64x22 cs, [11] force enable ram64x16 cs*/
	odm_set_bb_reg(dm, 0xb38, 0x0c000000, 0x3);

	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x40000304);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x41000203);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x42000102);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x43000101);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x44000101);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x45000101);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x46000101);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x47000101);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x4800caff);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x490080a1);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x4a005165);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x4b003340);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x4c002028);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x4d001419);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x4e000810);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x4f000506);

	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x00000000);

	/*change to page B*/
	odm_set_bb_reg(dm, 0xe28, MASKDWORD, 0x0);
	/*[10] force enable ram64x22 cs, [11] force enable ram64x16 cs*/
	odm_set_bb_reg(dm, 0xb38, 0x0c000000, 0x3);
	/*write even*/
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x00500000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x01500000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x02500000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x03500000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x04500000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x05500000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x06500000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x07500000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x08500000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x09500000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x0a500000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x0b500000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x0c500000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x0d500000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x0e500000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x0f500000);
	/*write odd*/
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x00900000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x01900000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x02900000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x03900000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x04900000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x05900000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x06900000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x07900000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x08900000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x09900000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x0a900000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x0b900000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x0c900000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x0d900000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x0e900000);
	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x0f900000);

	odm_set_bb_reg(dm, 0xb2c, MASKDWORD, 0x00000000);

	/*IQK Setting*/
	odm_set_bb_reg(dm, 0xe20, MASKDWORD, 0x0);
	odm_set_bb_reg(dm, 0xe28, MASKDWORD, 0x40000000);
	odm_set_bb_reg(dm, 0xb40, MASKDWORD, 0x00040100);
	odm_set_bb_reg(dm, 0xe28, MASKDWORD, 0x0);

	odm_set_bb_reg(dm, 0xe30, MASKDWORD, 0x1000cc1b);
	odm_set_bb_reg(dm, 0xe34, MASKDWORD, 0x1000cc1b);
	odm_set_bb_reg(dm, 0xe38, MASKDWORD, 0x821403ff);
	odm_set_bb_reg(dm, 0xe3c, MASKDWORD, 0x00160000);
	odm_set_bb_reg(dm, 0xe40, MASKDWORD, 0x01007c00);
	odm_set_bb_reg(dm, 0xe44, MASKDWORD, 0x01004800);
	odm_set_bb_reg(dm, 0xe48, MASKDWORD, 0xf8000800);
	odm_set_bb_reg(dm, 0xe4c, MASKDWORD, 0x00002911);
}

void _txgapk_afe_setting_8721d(struct dm_struct *dm,
			       boolean do_txgapk)
{
	if (do_txgapk) {
	/*BB setting*/
		odm_set_bb_reg(dm, 0xc04, MASKDWORD, 0x03a05601);
		odm_set_bb_reg(dm, 0xc08, MASKDWORD, 0x000800e4);
		odm_set_bb_reg(dm, 0x874, MASKDWORD, 0x25205000);
		odm_set_bb_reg(dm, 0x88c, MASKDWORD, 0xccf000c0);
	/*AFE setting*/
		odm_set_bb_reg(dm, 0xe70, MASKDWORD, 0x03c00016);
	} else {
		RF_DBG(dm, DBG_RF_TXGAPK,
		       "[TGGC]AFE setting for Normal mode!!!!\n");
	/*Restore BB setting*/
		odm_set_bb_reg(dm, 0xc04, MASKDWORD, 0x03a05611);
		odm_set_bb_reg(dm, 0xc08, MASKDWORD, 0x000000e4);
		odm_set_bb_reg(dm, 0x874, MASKDWORD, 0x25005000);
		odm_set_bb_reg(dm, 0x88c, MASKDWORD, 0xcc4000c0);
	/*Restore AFE setting*/
		odm_set_bb_reg(dm, 0xe70, MASKDWORD, 0x03c00050);
	/*Restore IQK setting*/
		odm_set_bb_reg(dm, 0xe20, MASKDWORD, 0x0);
		odm_set_bb_reg(dm, 0xe3c, 0x3c000000, 0x0);
		odm_set_bb_reg(dm, 0xe40, BIT(31), 0x0);
		odm_set_bb_reg(dm, 0xe44, BIT(31), 0x0);
	/*Restore RF setting*/
		odm_set_rf_reg(dm, RF_PATH_A, 0xde, BIT(16), 0x0);
		odm_set_rf_reg(dm, RF_PATH_A, 0xee, BIT(18), 0x0);
		odm_set_rf_reg(dm, RF_PATH_A, 0xdd, BIT(0), 0x0);
		odm_set_rf_reg(dm, RF_PATH_A, 0x8f, 0x6000, 0x0);
		/*odm_set_rf_reg(dm, RF_PATH_A, 0x1a, 0xfffff, 0x0);*/
	}
}

void _txgapk_rf_setting_8721d(struct dm_struct *dm,
			      u8 path)
{
	struct dm_iqk_info *iqk_info = &dm->IQK_info;

	switch (*dm->band_type) {
	case ODM_BAND_2_4G:
		RF_DBG(dm, DBG_RF_TXGAPK,
		       "[TGCC] 2G txgapk rf setting!!!\n");
		odm_set_bb_reg(dm, 0xe28, MASKDWORD, 0x0);
		//odm_set_rf_reg(dm, RF_PATH_A, 0xde, BIT(18), 0x0);

		odm_set_rf_reg(dm, RF_PATH_A, 0x00, 0xfffff, 0x5001a);
		/*switch*/
		odm_set_rf_reg(dm, RF_PATH_A, 0x57, 0x6, 0x1);
		/*LB Attenuation*/
		odm_set_rf_reg(dm, RF_PATH_A, 0x57, 0xf0, 0xf);

		odm_set_rf_reg(dm, RF_PATH_A, 0x7c, BIT(0), 0x1);
		/*mixer gain*/
		odm_set_rf_reg(dm, RF_PATH_A, 0x8c, BIT(8), 0x1);
		/*debug PGA gain*/
		odm_set_rf_reg(dm, RF_PATH_A, 0xdd, BIT(0), 0x1);
		odm_set_rf_reg(dm, RF_PATH_A, 0x8f, 0x06000, 0x3);

		break;
	case ODM_BAND_5G:
		RF_DBG(dm, DBG_RF_TXGAPK,
		       "[TGCC] 5G txgapk rf setting!!!\n");
		odm_set_bb_reg(dm, 0xe28, MASKDWORD, 0x0);
		odm_set_rf_reg(dm, RF_PATH_A, 0xde, BIT(18), 0x0);

		odm_set_rf_reg(dm, RF_PATH_A, 0x00, 0xfffff, 0x5001f);
		/*switch*/
		odm_set_rf_reg(dm, RF_PATH_A, 0x63, 0x30000, 0x0);
		/*LB Attenuation*/
		odm_set_rf_reg(dm, RF_PATH_A, 0x63, 0xf000, 0xf);
		/*mixer gain*/
		odm_set_rf_reg(dm, RF_PATH_A, 0x8c, BIT(8), 0x0);
		/*debug PGA gain*/
		odm_set_rf_reg(dm, RF_PATH_A, 0xdd, BIT(0), 0x1);
		odm_set_rf_reg(dm, RF_PATH_A, 0x8f, BIT(14) | BIT(13), 0x1);

		break;
	}
	/*IQK setting*/
	odm_set_bb_reg(dm, 0xb00, BIT(7), 0x0);
	odm_set_bb_reg(dm, 0xe28, MASKDWORD, 0x80800000);
	odm_set_bb_reg(dm, 0xe30, MASKDWORD, 0x3800cc1c);
	odm_set_bb_reg(dm, 0xe34, MASKDWORD, 0x1800cc1c);
	odm_set_bb_reg(dm, 0xe3c, 0x000fffff, 0x50013);
	odm_set_bb_reg(dm, 0xe3c, 0x3c000000, 0xa);
	odm_set_bb_reg(dm, 0xe40, MASKDWORD, 0x81007c00);
	odm_set_bb_reg(dm, 0xe44, MASKDWORD, 0x81004800);
	odm_set_bb_reg(dm, 0xe4c, MASKDWORD, 0x0000a910);
	/*open DPK*/
	odm_set_bb_reg(dm, 0xb00, BIT(7), 0x1);
	/*bypass DPK*/
	odm_set_bb_reg(dm, 0xb68, BIT(29), 0x1);
}

#if 0
u8 _txgapk_clear_extra0p5dB_8721d(struct dm_struct *dm,
				  u8 rf_path, boolean is_cck)
{
	u8 end;
	u32 rf0_idx_current, tmp, rf0x0_curr;
	u8 idx;
	u32 rf3f[11];

	RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC]===_clear 0.5dB setting!!!!!===\n");
	return end;
}
#endif

u64 _txgapk_one_shot_8721d(struct dm_struct *dm, u8 path)
{
	long txgap_k1 = 1, txgap_k2 = 2;
	long rx_dsp_power = 0;
	u32 regea4, regea0;
	/*u32 txgap_k1 = 0x1, txgap_k2 = 0x2;*/
	/*u64 rx_dsp_power = 0x0;*/

	odm_set_bb_reg(dm, 0xe28, BIT(31), 0x1);/*Enable SingleTone*/
	odm_set_bb_reg(dm, 0xe3c, BIT(20), 0x0);/*Rx_img_sig*/
	/*one shot*/
	odm_set_bb_reg(dm, 0xe48, MASKDWORD, 0xfa000800);
	odm_set_bb_reg(dm, 0xe48, MASKDWORD, 0xf8000800);
	ODM_delay_ms(5);

	txgap_k1 = odm_get_bb_reg(dm, 0xea4, 0x1f);
	txgap_k2 = odm_get_bb_reg(dm, 0xea0, MASKDWORD);
	regea4 = odm_get_bb_reg(dm, 0xea4, 0x1f);
	regea0 = odm_get_bb_reg(dm, 0xea0, MASKDWORD);
	//rx_dsp_power = (u64)((txgap_k1 << 32) + txgap_k2);
	//rx_dsp_power = txgap_k2;
	rx_dsp_power = txgap_k1 * 4294967296 + txgap_k2; // 4294967296 = 2^32
	RF_DBG(dm, DBG_RF_TXGAPK, "regea4 = 0x%x\n", regea4);
	RF_DBG(dm, DBG_RF_TXGAPK, "regea0 = 0x%x\n", regea0);
	RF_DBG(dm, DBG_RF_TXGAPK, "rx_dsp_power =%d\n", rx_dsp_power);

	odm_set_bb_reg(dm, 0xe28, BIT(31), 0x0);

	return rx_dsp_power;
}

void _phy_txgapk_calibrate_8721d(void *dm_void, u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	struct _hal_rf_ *rf = &dm->rf_table;

	u8 rf_path, rf0_idx, idx, rf0_idx_current, rf0_idx_next, i;
	u32 RFreg0;
	u8 delta_gain_retry = 3;
	int delta_gain_gap_pre, delta_gain_gap[11];
	u8 extr_0p5db[11];
	int gain_case[11];
	u32 rf56_current, rf56_next;
	long psd_value_current, psd_value_next;
	int rf56_current_temp[11], rf56_next_temp[11], psd_gap[11], psd_diff;
	s32 rf3f[11], tmp2;
	u32 rf0x0_curr, rf0x0_next, tmp;
	u8 end = 0xa;
	u8 rate = 24;
	boolean is_cck;

	RFreg0 = odm_get_rf_reg(dm, RF_PATH_A, RF_0x0, 0xfffff);

	if (*dm->mp_mode)
		rate = phydm_get_hwrate_to_mrate(dm, *rf->mp_rate_index);

	if (rate == 2 || rate == 4 || rate == 11 || rate == 22)
		is_cck = true;
	else
		is_cck = false;

	RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC]CH = %d, BW = %x, tx_rate = %x\n",
	       *dm->channel, *dm->band_width, rate);

	memset(rf3f, 0x0, sizeof(rf3f));
	memset(delta_gain_gap, 0x0, sizeof(delta_gain_gap));
	memset(rf56_current_temp, 0x0, sizeof(rf56_current_temp));
	memset(rf56_next_temp, 0x0, sizeof(rf56_next_temp));
	memset(extr_0p5db, 0x0, sizeof(extr_0p5db));
	memset(gain_case, 0x0, sizeof(gain_case));

	/*_txgapk_Phy_8721d(dm);*/
	_txgapk_afe_setting_8721d(dm, true);
	_txgapk_rf_setting_8721d(dm, RF_PATH_A);

	/*get 0x56 gain table*/
	odm_set_bb_reg(dm, 0xe28, BIT(31), 0x0);
	odm_set_rf_reg(dm, RF_PATH_A, 0xde, BIT(16), 0x0);
	ODM_delay_ms(1);
	for (idx = 1; idx <= 11; idx++) {
		/*current_fr0x_56*/
		rf0_idx_current = 3 * (idx - 1) + 1;
		odm_set_rf_reg(dm, rf_path, 0x0, 0x1f, rf0_idx_current);
		ODM_delay_ms(1);
		rf3f[idx] = odm_get_rf_reg(dm, rf_path, 0x56, 0x1fff);
		RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC]read idx=0x%x, rf3f =0x%x\n",
		       rf0_idx_current, rf3f[idx]);
		if ((((rf3f[idx] & 0xe0) >> 5) == 0x7) &&
		    (((rf3f[idx] & 0xe00) >> 9) == 0x7)) {
			end = idx;
			break;
		}
	}
	RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC]end = 0x%x\n", end);

	for (rf0_idx = end; rf0_idx >= 1; rf0_idx--) {
		/*current_fr0x_56*/
		rf0_idx_current = 3 * (rf0_idx - 1) + 1;
		rf56_current_temp[rf0_idx] = rf3f[rf0_idx] & 0xfff;

		rf0_idx_next = rf0_idx_current + 1;
		odm_set_rf_reg(dm, RF_PATH_A, 0xde, BIT(16), 0x0);
		odm_set_rf_reg(dm, rf_path, 0x0, 0x1f, rf0_idx_next);
		rf56_next_temp[rf0_idx] = odm_get_rf_reg(dm, rf_path,
							 0x56, 0xfff);

		if (((rf56_current_temp[rf0_idx] & 0xe0) !=
		    (rf56_next_temp[rf0_idx] & 0xe0)) |
		    ((rf56_current_temp[rf0_idx] & 0xe00) !=
		    (rf56_next_temp[rf0_idx] & 0xe00))) {
			odm_set_rf_reg(dm, RF_PATH_A, 0xde, BIT(16), 0x1);
			odm_set_rf_reg(dm, rf_path, 0x56, 0x1fff,
				       rf56_current_temp[rf0_idx]);
			/*do one-shot*/
			psd_value_current = _txgapk_one_shot_8721d(dm, rf_path);

			odm_set_rf_reg(dm, RF_PATH_A, 0xde, BIT(16), 0x1);
			odm_set_rf_reg(dm, rf_path, 0x56, 0x1fff,
				       rf56_next_temp[rf0_idx]);
			/*do one-shot*/
			psd_value_next = _txgapk_one_shot_8721d(dm, rf_path);

			RF_DBG(dm, DBG_RF_TXGAPK,
			       "[TGGC]rf0idx= 0x%x, rf56_current_temp[%x]=0x%x, psd_current =%d\n",
			       rf0_idx_current, rf0_idx,
			       rf56_current_temp[rf0_idx], psd_value_current);
			RF_DBG(dm, DBG_RF_TXGAPK,
			       "[TGGC]rf0idx= 0x%x, rf56_next_temp[%x]=0x%x, psd_value_next =%d\n",
			       rf0_idx_next, rf0_idx,
			       rf56_next_temp[rf0_idx], psd_value_next);

			psd_diff = psd_value_next / (psd_value_current / 1000);
			RF_DBG(dm, DBG_RF_TXGAPK, "psd_diff =%d\n", psd_diff);
			if (psd_diff > 1679)
				psd_gap[rf0_idx] = 3; //1.5dB
			else if (psd_diff > 1496)
				psd_gap[rf0_idx] = 2; //1dB
			else if (psd_diff > 1333)
				psd_gap[rf0_idx] = 1; //0.5dB
			else if (psd_diff > 1188)
				psd_gap[rf0_idx] = 0; //0dB
			else if (psd_diff > 1059)
				psd_gap[rf0_idx] = -1; //-0.5dB
			else if (psd_diff > 944)
				psd_gap[rf0_idx] = -2; //1dB
			else if (psd_diff > 841)
				psd_gap[rf0_idx] = -3; //-1.5dB
			else
				psd_gap[rf0_idx] = -4; //-2dB
		} else {
			psd_gap[rf0_idx] = 0;
		}
		RF_DBG(dm, DBG_RF_TXGAPK, "psd_gap[%x] =%d\n",
		       rf0_idx, psd_gap[rf0_idx]);
	}

	gain_case[end] = psd_gap[end];
	if ((gain_case[end] % 2) != 0)
		extr_0p5db[end] = 0x1;
	else
		extr_0p5db[end] = 0x0;
	delta_gain_gap[end] = (gain_case[end] -
				   extr_0p5db[end]) / 2;
	RF_DBG(dm, DBG_RF_TXGAPK,
	       "[TGGC] gain_case[%x] = %d,psd_gap[%x] = %d\n",
	       end, gain_case[end], end, psd_gap[end]);

	for (rf0_idx = end - 1; rf0_idx >= 0x1; rf0_idx--) {
		gain_case[rf0_idx] = gain_case[rf0_idx + 1] + psd_gap[rf0_idx];
		if ((gain_case[rf0_idx] % 2) != 0)
			extr_0p5db[rf0_idx] = 0x1;
		else
			extr_0p5db[rf0_idx] = 0x0;
		delta_gain_gap[rf0_idx] = (gain_case[rf0_idx] -
					   extr_0p5db[rf0_idx]) / 2;
		RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] extr_0p5db[%x] = %d\n",
		       rf0_idx, extr_0p5db[rf0_idx]);
		RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] gain_case[%x] = %d\n",
		       rf0_idx, gain_case[rf0_idx]);
		RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] delta_gain_gap[%x] = %d\n",
		       rf0_idx, delta_gain_gap[rf0_idx]);
	}
	odm_set_rf_reg(dm, RF_PATH_A, 0xde, BIT(16), 0x0);
	odm_write_4byte(dm, 0xe28, 0x00000000);

	/*store to RF TXAGC table*/
	for (rf0_idx = 1; rf0_idx <= end; rf0_idx++) {
		rf3f[rf0_idx] = (rf56_current_temp[rf0_idx] +
				 delta_gain_gap[rf0_idx]) & 0xfff;

		RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] new rf3f[%x] = %x\n",
		       rf0_idx, rf3f[rf0_idx]);
	}

	odm_set_rf_reg(dm, rf_path, 0xee, BIT(16), 0x1);
	for (idx = 0x1; idx <= end; idx++) {
		switch (*dm->band_type) {
		case ODM_BAND_2_4G:
			if (!is_cck)
				tmp = (idx - 1);
			else
				tmp = 0x20 | (idx - 1);
			break;
		case ODM_BAND_5G:
			if (*dm->channel > 140)
				tmp = 0x300 | (idx - 1);
			else if (*dm->channel > 64)
				tmp = 0x280 | (idx - 1);
			else
				tmp = 0x200 | (idx - 1);
			break;
		}
		if (odm_get_rf_reg(dm, rf_path, 0x19, BIT(0)))
			tmp = tmp | 0x40;

		odm_set_rf_reg(dm, rf_path, 0x33, 0xfffff, tmp);
		if (extr_0p5db[idx] == 0x1)
			tmp2 = BIT(12) | rf3f[idx];
		else
			tmp2 = rf3f[idx] & 0x0fff;
		odm_set_rf_reg(dm, rf_path, 0x3f, 0x01fff, tmp2);
		RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC]idx= %x, 33= 0x%x, 3f= 0x%x\n",
		       idx, tmp, tmp2);
	}
	odm_set_rf_reg(dm, rf_path, 0xee, BIT(16), 0x0);

	_txgapk_afe_setting_8721d(dm, false);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x0, 0xfffff, RFreg0);
	/*disable DPK*/
	/*odm_set_bb_reg(dm, 0xb00, BIT(7), 0x0);*/
}

void phy_txgap_calibrate_8721d(void *dm_void,
			       boolean clear)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	struct _ADAPTER *p_adapter = dm->adapter;

#if (MP_DRIVER == 1)
#ifdef CONFIG_MP_INCLUDED
	PMPT_CONTEXT p_mpt_ctx = &p_adapter->mppriv.MptCtx;
#endif
#endif

	struct _hal_rf_ *p_rf = &dm->rf_table;

#if (DM_ODM_SUPPORT_TYPE == ODM_IOT)
	/*if (!(p_rf->rf_supportability & HAL_RF_TXGAPK))*/
		/*return;*/
	_phy_txgapk_calibrate_8721d(dm, RF_PATH_A);

#endif
	RF_DBG(dm, DBG_RF_IQK, "[DPK]====_txgapk_8721d End!!!!!========\n");
}

#endif
