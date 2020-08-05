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
/*#if (DM_ODM_SUPPORT_TYPE == ODM_WIN)*/
#if (DM_ODM_SUPPORT_TYPE == 0x08)
/*[PHYDM-262] workaround for SD4 compile warning*/
#if RT_PLATFORM == PLATFORM_MACOSX
#include "phydm_precomp.h"
#else
#include "../phydm_precomp.h"
#endif
#else
#include "../../phydm_precomp.h"
#endif

#if (RTL8721D_SUPPORT == 1)

void
_btiqk_backup_bb_registers_8721d(struct dm_struct *dm,
				 u32 *adda_reg,
				 u32 *adda_backup,
				 u32 register_num)
{
	u32 i;

	for (i = 0; i < register_num; i++)
		adda_backup[i] = odm_get_bb_reg(dm, adda_reg[i], MASKDWORD);
}

void
_btiqk_backup_mac_registers_8721d(struct dm_struct *dm,
				  u32 *mac_reg,
				  u32 *mac_backup,
				  u32 register_num)
{
	u32 i;

	for (i = 0; i < register_num; i++)
		mac_backup[i] = odm_read_4byte(dm, mac_reg[i]);
}

void
_btiqk_backup_rf_registers_8721d(struct dm_struct *dm,
				 u32 *rf_reg,
				 u32 rf_reg_backup[][1],
				 u32 rf_reg_num)
{
	u32 i;

	for (i = 0; i < rf_reg_num; i++)
		rf_reg_backup[i][RF_PATH_A] = odm_get_rf_reg(dm, RF_PATH_A,
							     rf_reg[i],
							     RFREG_MASK);
}

void
_btiqk_reload_bb_registers_8721d(struct dm_struct *dm,
				 u32 *adda_reg,
				 u32 *adda_backup,
				 u32 regiester_num)
{
	u32 i;

	for (i = 0; i < regiester_num; i++)
		odm_set_bb_reg(dm, adda_reg[i], MASKDWORD, adda_backup[i]);
}

void
_btiqk_reload_mac_registers_8721d(struct dm_struct *dm,
				  u32 *mac_reg,
				  u32 *mac_backup,
				  u32 register_num)
{
	u32 i;

	RF_DBG(dm, DBG_RF_IQK, "[BTIQK] Reload MAC parameters !\n");
	for (i = 0; i < register_num; i++)
		odm_write_4byte(dm, mac_reg[i], mac_backup[i]);
}

void _btiqk_reload_rf_registers_8721d(struct dm_struct *dm,
				      u32 *rf_reg,
				      u32 rf_reg_backup[][1],
				      u32 rf_reg_num)
{
	u32 i;

	for (i = 0; i < rf_reg_num; i++) {
		odm_set_rf_reg(dm, RF_PATH_A, rf_reg[i], RFREG_MASK,
			       rf_reg_backup[i][RF_PATH_A]);
		RF_DBG(dm, DBG_RF_IQK, "[BTIQK] Reload RF_A 0x%x = 0x%x\n",
		       rf_reg[i], rf_reg_backup[i][RF_PATH_A]);
	}
}

boolean
_btiqk_simularity_compare_8721d(struct dm_struct *dm,
				s32 result[][2],
				u8 c1,
				u8 c2)
{
	u32 i, j, diff, simularity_bit_map, bound = 2;
	boolean is_result = true;
	s32 tmp1 = 0, tmp2 = 0;

	RF_DBG(dm, DBG_RF_IQK,
	       "===> BTIQK:phy simularity compare 8721d c1 %d c2 %d!!!\n",
	       c1, c2);
	simularity_bit_map = 0;
	for (i = 0; i < bound; i++) {
		if (i == 1 || i == 3 || i == 5 || i == 7) {
			if ((result[c1][i] & 0x00000200) != 0)
				tmp1 = result[c1][i] | 0xFFFFFC00;
			else
				tmp1 = result[c1][i];

			if ((result[c2][i] & 0x00000200) != 0)
				tmp2 = result[c2][i] | 0xFFFFFC00;
			else
				tmp2 = result[c2][i];
		} else {
			tmp1 = result[c1][i];
			tmp2 = result[c2][i];
		}

		diff = (tmp1 > tmp2) ? (tmp1 - tmp2) : (tmp2 - tmp1);

		if (diff > MAX_TOLERANCE) {
			RF_DBG(dm, DBG_RF_IQK,
			       "BTIQK:differnece overflow %d index %d compare1 0x%x compare2 0x%x!!!\n",
			       diff, i, result[c1][i], result[c2][i]);
			simularity_bit_map = simularity_bit_map | (1 << i);
		}
	}

	RF_DBG(dm, DBG_RF_IQK,
	       "BTIQK:phy simularity compare 8721d simularity bit_map %x !!!\n",
	       simularity_bit_map);

	if (simularity_bit_map == 0)
		return is_result;

	if (!(simularity_bit_map & 0x03)) { /*path A TX OK*/
		for (i = 0; i < 2; i++)
			result[3][i] = result[c1][i];
	}

	return false;
}

boolean _btiqk_lok_8721d(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	u32 btiqk_x, btiqk_y, r_tx_x, r_tx_y;
	u32 lok_result, btiqk_success = 0;
	u32 reg_eac, iqk_fail_bit, mac_reg4;
	u8 t = 0;

	RF_DBG(dm, DBG_RF_IQK, "[BTIQK] BTIQK:Start!!!");

	/*11_AD_TXIQK_LOK_20181024_SingleTone_polling*/
	odm_set_bb_reg(dm, R_0x88c, MASKDWORD, 0xCCF400C0);
	odm_set_bb_reg(dm, R_0xc80, MASKDWORD, 0x40000100);
	odm_set_bb_reg(dm, R_0xe6c, MASKDWORD, 0x03c00016);
	odm_set_bb_reg(dm, R_0xe70, MASKDWORD, 0x03c00016);
	odm_set_bb_reg(dm, R_0xc04, MASKDWORD, 0x03a05601);
	odm_set_bb_reg(dm, R_0xc08, MASKDWORD, 0x000800e4);
	odm_set_bb_reg(dm, R_0x874, MASKDWORD, 0x25204000);
	odm_set_bb_reg(dm, R_0x888, MASKDWORD, 0x000000cb);/*AFE = BT*/
	odm_set_bb_reg(dm, R_0xe28, MASKDWORD, 0x00800000);

	odm_set_rf_reg(dm, RF_PATH_A, RF_0xdf, 0x00040, 0x0);

	odm_set_bb_reg(dm, R_0xe30, MASKDWORD, 0x1400cc08);
	odm_set_bb_reg(dm, R_0xe34, MASKDWORD, 0x3800cc1b);
	odm_set_bb_reg(dm, R_0xe38, MASKDWORD, 0x821403ff);
	odm_set_bb_reg(dm, R_0xe3c, MASKDWORD, 0x28160000);
	odm_set_bb_reg(dm, R_0xe40, MASKDWORD, 0x01007c00);
	odm_set_bb_reg(dm, R_0xe44, MASKDWORD, 0x01004800);
	odm_set_bb_reg(dm, R_0xe48, MASKDWORD, 0xf8000800);
	odm_set_bb_reg(dm, R_0xe4c, MASKDWORD, 0x00402911);
	odm_set_bb_reg(dm, R_0xe4c, 0x00180000, 0x0);
	odm_set_bb_reg(dm, R_0xe50, MASKDWORD, 0x1000dc10);
	odm_set_bb_reg(dm, R_0xe54, MASKDWORD, 0x1000dc10);

	odm_set_rf_reg(dm, RF_PATH_A, RF_0xee, 0x40000, 0x1);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0xdd, 0x00004, 0x1);
	odm_set_rf_reg(dm, RF_PATH_A, 0x06, 0x03000, 0x3);/*DAC Gain*/
	odm_set_rf_reg(dm, RF_PATH_A, 0x06, 0x00e00, 0x2);/*IPA Gain*/
	odm_set_rf_reg(dm, RF_PATH_A, 0x06, 0x001e0, 0x3);/*PAD Gain*/
	odm_set_rf_reg(dm, RF_PATH_A, 0x06, 0x0001f, 0x3);/*TXBB Gain*/
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x18, 0x30000, 0x0);
	odm_set_rf_reg(dm, RF_PATH_A, 0x01, 0x00004, 0x1);/*RF GNT_BT = 1*/

	odm_set_bb_reg(dm, R_0xe28, MASKDWORD, 0x80800000);

	mac_reg4 = odm_read_4byte(dm, 0x4);/*Shut down DAI*/
	odm_write_4byte(dm, 0x4, mac_reg4 & ~(BIT(31)));
	odm_set_bb_reg(dm, R_0xe48, MASKDWORD, 0xfa000800);
	odm_set_bb_reg(dm, R_0xe48, MASKDWORD, 0xf8000800);
	while ((odm_get_bb_reg(dm, R_0xeac, BIT(26)) != 1) && (t < 20)) {
		ODM_delay_ms(1);
		t++;
	}
	odm_write_4byte(dm, 0x4, mac_reg4);/*Enable DAI*/
	/*12_Read_Tx_X_Tx_Y*/
	btiqk_x = odm_get_bb_reg(dm, R_0xe94, 0x03ff0000);
	btiqk_y = odm_get_bb_reg(dm, R_0xe9c, 0x03ff0000);
	RF_DBG(dm, DBG_RF_IQK,
	       "[BTIQK] btiqk_x = 0x%x, btiqk_y = 0x%x, iqkend = 0x%x/n",
	       btiqk_x, btiqk_y, odm_get_bb_reg(dm, R_0xeac, BIT(26)));

	/* Check failed */
	reg_eac = odm_get_bb_reg(dm, R_0xeac, MASKDWORD);
	iqk_fail_bit = odm_get_bb_reg(dm, R_0xeac, 0x10000000);
	RF_DBG(dm, DBG_RF_IQK, "[BTIQK] 0xeac = 0x%x,eacBIT28=0x%x\n", reg_eac,
	       iqk_fail_bit);
	/*monitor image power before & after IQK*/
	RF_DBG(dm, DBG_RF_IQK,
	       "[BTIQK] 0xe90(before IQK)= 0x%x, 0xe98(afer IQK) = 0x%x\n",
	       odm_get_bb_reg(dm, R_0xe90, MASKDWORD),
	       odm_get_bb_reg(dm, R_0xe98, MASKDWORD));
#if 0
	/*13_Read_IQDAC, re read/write rf08 means enable writing_table*/
	r_tx_x = odm_get_rf_reg(dm, RF_PATH_A, RF_0x08, 0xfc000);
	r_tx_y = odm_get_rf_reg(dm, RF_PATH_A, RF_0x08, 0x003f0);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x08, 0xfc000, r_tx_x);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x08, 0x003f0, r_tx_y);
	lok_result = (r_tx_x << 6) | (r_tx_y);
#endif
	/*14_restore_BTRF_setting_20181024*/
	odm_set_bb_reg(dm, R_0xe28, MASKDWORD, 0x00000000);

	odm_set_rf_reg(dm, RF_PATH_A, RF_0xdd, 0x00004, 0x0);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0xee, 0x40000, 0x0);
	odm_set_rf_reg(dm, RF_PATH_A, 0x01, 0x00004, 0x0);

	odm_set_bb_reg(dm, R_0x888, MASKDWORD, 0x00000003);

	if (!(reg_eac & BIT(28)) &&
	    (((btiqk_x & 0x03FF0000) >> 16) != 0x142) &&
	    (((btiqk_y & 0x03FF0000) >> 16) != 0x42))
		btiqk_success |= 0x01;
	else
		RF_DBG(dm, DBG_RF_IQK, "[BTIQK] pathA TX IQK is fail!\n");

	return btiqk_success;
}

void
_btiqk_retry_8721d(struct dm_struct *dm,
		   s32 result[][2],
		   u8 t)
{
	u32 i;
	u8 path_aok = 0;

#if MP_DRIVER
	const u32 retry_count = 9;
#else
	const u32 retry_count = 2;
#endif

	RF_DBG(dm, DBG_RF_IQK, "IQ Calibration for 1T1R for %d times\n", t);

	/* path A TXIQK */
	for (i = 0; i < retry_count; i++) {
		path_aok = _btiqk_lok_8721d(dm);
		if (path_aok == 0x01) {
			RF_DBG(dm, DBG_RF_IQK, "path A Tx IQK Success!!\n");
			result[t][0] = (odm_get_bb_reg(dm, R_0xe94, MASKDWORD) &
					0x3FF0000) >> 16;
			result[t][1] = (odm_get_bb_reg(dm, R_0xe9c, MASKDWORD) &
					0x3FF0000) >> 16;
			break;
		}

		RF_DBG(dm, DBG_RF_IQK, "[BTIQK] path A TXIQK Fail!!\n");
		result[t][0] = 0x100;
		result[t][1] = 0x0;
	}

	RF_DBG(dm, DBG_RF_IQK, "%s <==\n", __func__);
}

u32
_btiqk_return_result_8721d(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	s32 result[4][2];
	u8 i, final_candidate;
	boolean is_patha_ok;
	u32 btiqk_x, btiqk_y, r_tx_x, r_tx_y;
	u32 btiqk_result, lok_result;
	boolean is12simular, is13simular, is23simular;

	for (i = 0; i < 2; i++) {
		result[0][i] = 0;
		result[1][i] = 0;
		result[2][i] = 0;

		if (i == 0 || i == 2 || i == 4 || i == 6)
			result[3][i] = 0x100;
		else
			result[3][i] = 0;
	}

	final_candidate = 0xff;
	is_patha_ok = false;
	is12simular = false;
	is23simular = false;
	is13simular = false;

	for (i = 0; i < 3; i++) {
		_btiqk_retry_8721d(dm, result, i);
		if (i == 1) {
			is12simular = _btiqk_simularity_compare_8721d(dm,
								      result,
								      0, 1);
			if (is12simular) {
				final_candidate = 0;
				break;
			}
		}
		if (i == 2) {
			is13simular = _btiqk_simularity_compare_8721d(dm,
								      result,
								      0, 2);
			if (is13simular) {
				final_candidate = 0;
				break;
			}
			is23simular = _btiqk_simularity_compare_8721d(dm,
								      result,
								      1, 2);
			if (is23simular)
				final_candidate = 1;
			else
				final_candidate = 3;
		}
	}
	RF_DBG(dm, DBG_RF_IQK, "IQK: is23simular final_candidate is %x\n",
	       final_candidate);

	if (final_candidate != 0xff) {
		btiqk_x = result[final_candidate][0];
		btiqk_y = result[final_candidate][1];

		RF_DBG(dm, DBG_RF_IQK, "IQK: final_candidate is %x\n",
		       final_candidate);
		is_patha_ok = true;
	} else {
		RF_DBG(dm, DBG_RF_IQK, "IQK: FAIL use default value\n");
		/* default value */
		btiqk_x = 0x100;
		btiqk_y = 0x0;
	}

	if (btiqk_x != 0)
		btiqk_result = (btiqk_x << 22) | (btiqk_y << 12);

	odm_set_rf_reg(dm, RF_PATH_A, 0x01, 0x00004, 0x1);/*RF GNT_BT = 1*/
	r_tx_x = odm_get_rf_reg(dm, RF_PATH_A, RF_0x08, 0xfc000);
	r_tx_y = odm_get_rf_reg(dm, RF_PATH_A, RF_0x08, 0x003f0);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x08, 0xfc000, r_tx_x);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x08, 0x003f0, r_tx_y);
	lok_result = (r_tx_x << 6) | (r_tx_y);
	odm_set_rf_reg(dm, RF_PATH_A, 0x01, 0x00004, 0x0);/*RF GNT_BT = 0*/
	return btiqk_result | lok_result;
}

void phy_bt_lok_write_8721d(struct dm_struct *dm,
			    u32 lok_xx,
			    u32 lok_yy)
{
	odm_set_rf_reg(dm, RF_PATH_A, RF_0xee, BIT18, 0x1);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x1, BIT2, 0x1);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x08, 0xfc000, lok_xx);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x08, 0x003f0, lok_yy);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x1, BIT2, 0x0);
	odm_set_rf_reg(dm, RF_PATH_A, RF_0xee, BIT18, 0x0);
}

#if 1
void phy_bt_adda_dck_8721d(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	RF_DBG(dm, DBG_RF_IQK, "[BT DCK]ADC offset mark off!!");

	/*01_DAC_DCK_ADC_offset_mark_off_20181024*/
	odm_set_bb_reg(dm, R_0x88c, MASKDWORD, 0xccf000c0);
	/*odm_set_bb_reg(dm, R_0xc80, MASKDWORD, 0x40000100);*/
	odm_set_bb_reg(dm, R_0xe6c, MASKDWORD, 0x03c00016);
	odm_set_bb_reg(dm, R_0xe70, MASKDWORD, 0x03c00016);
	odm_set_bb_reg(dm, R_0xc04, MASKDWORD, 0x03a05601);
	odm_set_bb_reg(dm, R_0xc08, MASKDWORD, 0x000800e4);
	odm_set_bb_reg(dm, R_0x874, MASKDWORD, 0x25204000);

	odm_set_bb_reg(dm, R_0x888, MASKDWORD, 0x0000008b);

	odm_set_bb_reg(dm, R_0x950, 0x01ff01ff, 0x00);
	odm_set_bb_reg(dm, R_0x818, 0x00400000, 0x0);
	odm_set_bb_reg(dm, R_0x990, 0x40000000, 0x1);

	odm_set_bb_reg(dm, R_0x880, 0x00000002, 0x0);
	odm_set_bb_reg(dm, R_0x880, 0x00000010, 0x1);
	odm_set_bb_reg(dm, R_0x880, 0x00008000, 0x1);
	odm_set_bb_reg(dm, R_0x880, 0x00010000, 0x0);
	odm_set_bb_reg(dm, R_0x880, 0x00020000, 0x1);
	odm_set_bb_reg(dm, R_0x888, 0x00000020, 0x0);

	odm_set_bb_reg(dm, R_0xe28, 0x00000008, 0x1);
	odm_set_bb_reg(dm, R_0xe48, 0x00f00000, 0x1);
	odm_set_bb_reg(dm, R_0xe48, 0x00000002, 0x0);
	odm_set_bb_reg(dm, R_0x908, 0x00000fff, 0x300);

	odm_set_bb_reg(dm, R_0x990, 0x80000000, 0x0);
	ODM_delay_us(1);
	odm_set_bb_reg(dm, R_0x990, 0x80000000, 0x1);

	RF_DBG(dm, DBG_RF_IQK, "[BT DCK]BT DAC mark off!!");

	/*04_DAC_DCK_mark_off_20181024*/
	odm_set_bb_reg(dm, R_0x888, MASKDWORD, 0x0000008b);
	odm_set_bb_reg(dm, R_0x818, 0x00400000, 0x0);
	odm_set_bb_reg(dm, R_0x990, 0x40000000, 0x1);

	odm_set_bb_reg(dm, R_0x880, 0x00000002, 0x0);
	odm_set_bb_reg(dm, R_0x880, 0x00000010, 0x0);
	odm_set_bb_reg(dm, R_0x880, 0x00008000, 0x0);
	odm_set_bb_reg(dm, R_0x880, 0x00010000, 0x1);
	odm_set_bb_reg(dm, R_0x880, 0x00020000, 0x1);
	odm_set_bb_reg(dm, R_0x888, 0x00000020, 0x1);

	odm_set_bb_reg(dm, R_0x988, MASKDWORD, 0x0003FFF0);
	odm_set_bb_reg(dm, R_0x98c, MASKDWORD, 0x00000000);
	odm_set_bb_reg(dm, R_0x994, MASKDWORD, 0x0003FFF0);
	odm_set_bb_reg(dm, R_0x998, MASKDWORD, 0x00000000);

	odm_set_bb_reg(dm, R_0x988, 0x80000000, 0x1);
	odm_set_bb_reg(dm, R_0x994, 0x80000000, 0x1);
	odm_set_bb_reg(dm, R_0x988, 0x40000000, 0x0);
	odm_set_bb_reg(dm, R_0x994, 0x40000000, 0x0);

	ODM_delay_us(1);
	odm_set_bb_reg(dm, R_0x988, 0x00000001, 0x1);	//pow_da_I_CR
	odm_set_bb_reg(dm, R_0x994, 0x00000001, 0x1);	//pow_da_Q_CR
	ODM_delay_us(1);
	odm_set_bb_reg(dm, R_0x988, 0x00000002, 0x1);	//cal_os_I_CR
	odm_set_bb_reg(dm, R_0x994, 0x00000002, 0x1);	//cal_os_Q_CR

	odm_set_bb_reg(dm, R_0x988, 0x00000001, 0x0);	//pow_da_I_CR
	odm_set_bb_reg(dm, R_0x994, 0x00000001, 0x0);	//pow_da_Q_CR
	/*return to normal setting*/
	odm_set_bb_reg(dm, R_0x880, 0x00000002, 0x1);
	odm_set_bb_reg(dm, R_0x880, 0x00000010, 0x1);
	odm_set_bb_reg(dm, R_0x880, 0x00010000, 0x0);
	odm_set_bb_reg(dm, R_0x880, 0x00020000, 0x0);
	odm_set_bb_reg(dm, R_0x888, 0x00000020, 0x0);

	odm_set_bb_reg(dm, R_0x888, MASKDWORD, 0x00000003);
}
#else
void phy_bt_adc_dck_8721d(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &dm->rf_calibrate_info;

	RF_DBG(dm, DBG_RF_IQK, "[BT DCK]ADC offset mark off!!");

	/*01_DAC_DCK_ADC_offset_mark_off_20181024*/
	odm_set_bb_reg(dm, R_0x88c, MASKDWORD, 0xccf000c0);
	odm_set_bb_reg(dm, R_0xc80, MASKDWORD, 0x40000100);
	odm_set_bb_reg(dm, R_0xe6c, MASKDWORD, 0x03c00016);
	odm_set_bb_reg(dm, R_0xe70, MASKDWORD, 0x03c00016);
	odm_set_bb_reg(dm, R_0xc04, MASKDWORD, 0x03a05601);
	odm_set_bb_reg(dm, R_0xc08, MASKDWORD, 0x000800e4);
	odm_set_bb_reg(dm, R_0x874, MASKDWORD, 0x25204000);
	odm_set_bb_reg(dm, R_0x888, MASKDWORD, 0x0000008b);

	odm_set_bb_reg(dm, R_0x950, 0x01ff01ff, 0x00);
	odm_set_bb_reg(dm, R_0x818, 0x00400000, 0x0);
	odm_set_bb_reg(dm, R_0x990, 0x40000000, 0x1);

	odm_set_bb_reg(dm, R_0x880, 0x00000002, 0x0);
	odm_set_bb_reg(dm, R_0x880, 0x00000010, 0x1);
	odm_set_bb_reg(dm, R_0x880, 0x00008000, 0x1);
	odm_set_bb_reg(dm, R_0x880, 0x00010000, 0x0);
	odm_set_bb_reg(dm, R_0x880, 0x00020000, 0x1);
	odm_set_bb_reg(dm, R_0x888, 0x00000020, 0x0);

	odm_set_bb_reg(dm, R_0xe28, 0x00000008, 0x1);
	odm_set_bb_reg(dm, R_0xe48, 0x00f00000, 0x1);
	odm_set_bb_reg(dm, R_0xe48, 0x00000002, 0x0);
	odm_set_bb_reg(dm, R_0x908, 0x00000fff, 0x300);

	odm_set_bb_reg(dm, R_0x990, 0x80000000, 0x0);
	ODM_delay_us(1);
	odm_set_bb_reg(dm, R_0x990, 0x80000000, 0x1);
}

void phy_bt_dac_dck_8721d(void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_rf_calibration_struct *cali_info = &dm->rf_calibrate_info;

	RF_DBG(dm, DBG_RF_IQK, "[BT DCK]BT DAC mark off!!");

	/*04_DAC_DCK_mark_off_20181024*/
	odm_set_bb_reg(dm, R_0x88c, MASKDWORD, 0xccf000c0);
	odm_set_bb_reg(dm, R_0xc80, MASKDWORD, 0x40000100);
	odm_set_bb_reg(dm, R_0xe6c, MASKDWORD, 0x03c00016);
	odm_set_bb_reg(dm, R_0xe70, MASKDWORD, 0x03c00016);
	odm_set_bb_reg(dm, R_0xc04, MASKDWORD, 0x03a05601);
	odm_set_bb_reg(dm, R_0xc08, MASKDWORD, 0x000800e4);
	odm_set_bb_reg(dm, R_0x874, MASKDWORD, 0x25204000);
	odm_set_bb_reg(dm, R_0x888, MASKDWORD, 0x0000008b);

	odm_set_bb_reg(dm, R_0x818, 0x00400000, 0x0);
	odm_set_bb_reg(dm, R_0x990, 0x40000000, 0x1);

	odm_set_bb_reg(dm, R_0x880, 0x00000002, 0x0);
	odm_set_bb_reg(dm, R_0x880, 0x00000010, 0x0);
	odm_set_bb_reg(dm, R_0x880, 0x00008000, 0x0);
	odm_set_bb_reg(dm, R_0x880, 0x00010000, 0x1);
	odm_set_bb_reg(dm, R_0x880, 0x00020000, 0x1);
	odm_set_bb_reg(dm, R_0x888, 0x00000020, 0x1);

	odm_set_bb_reg(dm, R_0x988, MASKDWORD, 0x0003FFF0);
	odm_set_bb_reg(dm, R_0x98c, MASKDWORD, 0x00000000);
	odm_set_bb_reg(dm, R_0x994, MASKDWORD, 0x0003FFF0);
	odm_set_bb_reg(dm, R_0x998, MASKDWORD, 0x00000000);

	odm_set_bb_reg(dm, R_0x988, 0x80000000, 0x1);
	odm_set_bb_reg(dm, R_0x994, 0x80000000, 0x1);
	odm_set_bb_reg(dm, R_0x988, 0x40000000, 0x0);
	odm_set_bb_reg(dm, R_0x994, 0x40000000, 0x0);

	ODM_delay_us(1);
	odm_set_bb_reg(dm, R_0x988, 0x00000001, 0x1);	//pow_da_I_CR
	odm_set_bb_reg(dm, R_0x994, 0x00000001, 0x1);	//pow_da_Q_CR
	ODM_delay_us(1);
	odm_set_bb_reg(dm, R_0x988, 0x00000002, 0x1);	//cal_os_I_CR
	odm_set_bb_reg(dm, R_0x994, 0x00000002, 0x1);	//cal_os_Q_CR

	odm_set_bb_reg(dm, R_0x988, 0x00000001, 0x0);	//pow_da_I_CR
	odm_set_bb_reg(dm, R_0x994, 0x00000001, 0x0);	//pow_da_Q_CR
	/*return to normal setting*/
	odm_set_bb_reg(dm, R_0x880, 0x00000002, 0x1);
	odm_set_bb_reg(dm, R_0x880, 0x00000010, 0x1);
	odm_set_bb_reg(dm, R_0x880, 0x00010000, 0x0);
	odm_set_bb_reg(dm, R_0x880, 0x00020000, 0x0);
	odm_set_bb_reg(dm, R_0x888, 0x00000020, 0x0);

	odm_set_bb_reg(dm, R_0x888, MASKDWORD, 0x00000003);
}

#endif

void phy_bt_dck_write_8721d(struct dm_struct *dm,
			    u8 q_dck,
			    u8 i_dck)
{
	odm_set_bb_reg(dm, R_0x998, 0x00000001, 0x1);
	odm_set_bb_reg(dm, R_0x994, 0x00000001, 0x1);

	odm_set_bb_reg(dm, R_0x98c, 0x01000000, 1);
	odm_set_bb_reg(dm, R_0x998, 0x01000000, 1);
	odm_set_bb_reg(dm, R_0x98c, 0x00200000, 1);
	odm_set_bb_reg(dm, R_0x998, 0x00200000, 1);
	odm_set_bb_reg(dm, R_0x98c, 0x02000000, 1);
	odm_set_bb_reg(dm, R_0x998, 0x02000000, 1);

	odm_set_bb_reg(dm, R_0x98c, 0x00007c00, 0x1f);
	odm_set_bb_reg(dm, R_0x98c, 0x00000200, 0x1);

	odm_set_bb_reg(dm, R_0x98c, 0x001F8000, i_dck);

	odm_set_bb_reg(dm, R_0x998, 0x00007c00, 0x1f);
	odm_set_bb_reg(dm, R_0x998, 0x00000200, 0x1);

	odm_set_bb_reg(dm, R_0x998, 0x001F8000, q_dck);

	odm_set_bb_reg(dm, R_0x998, 0x00000001, 0x0);
	odm_set_bb_reg(dm, R_0x994, 0x00000001, 0x0);
}

u32 phy_btiq_calibrate_8721d(struct dm_struct *dm)
{
	u32 result;
	u32 bt_rf_backup[BTIQK_RF_REG_NUM_8721D][1];
	u32 bt_bb_backup[BTIQK_BB_REG_NUM_8721D];
	u32 bt_mac_backup[BTIQK_MAC_REG_NUM_8721D];

	u32 BTIQK_MAC_REG_8721D[] = { 0x074, 0x764 };
	u32 BTIQK_BB_REG_8721D[] = { R_0xc80, R_0x88c, R_0xe6c, R_0xe70,
		R_0xc04, R_0xc08, R_0x874, R_0x888, R_0xe28, R_0xe30, R_0xe34,
		R_0xe38, R_0xe3c, R_0xe40, R_0xe44 };
	u32 BTIQK_RF_REG_8721D[][1] = { RF_0x0, RF_0x1, RF_0x18, RF_0xdf,
		RF_0xdd, RF_0xee };
	u8 i = 0;

	RF_DBG(dm, DBG_RF_IQK, "[BTIQK]==========IQK strat!!!!!==========\n");

	_btiqk_backup_bb_registers_8721d(dm, BTIQK_BB_REG_8721D, bt_bb_backup,
					 BTIQK_BB_REG_NUM_8721D);
	_btiqk_backup_rf_registers_8721d(dm, (uint32_t *)BTIQK_RF_REG_8721D,
					 bt_rf_backup, BTIQK_RF_REG_NUM_8721D);
	_btiqk_backup_mac_registers_8721d(dm, BTIQK_MAC_REG_8721D,
					  bt_mac_backup,
					  BTIQK_MAC_REG_NUM_8721D);

	/*Switch to wifi temporary, will move to wifi driver later*/
	//bt_change_gnt_wifi_only();
	odm_write_4byte(dm, 0x74, 0xA);
	odm_write_4byte(dm, 0x764, 0x1a00);

	phy_bt_adda_dck_8721d(dm);
	ODM_delay_ms(BTIQK_DELAY_TIME_8721D);
	result = _btiqk_return_result_8721d(dm);

	_btiqk_reload_rf_registers_8721d(dm, (uint32_t *)BTIQK_RF_REG_8721D,
					 bt_rf_backup, BTIQK_RF_REG_NUM_8721D);
	_btiqk_reload_bb_registers_8721d(dm, BTIQK_BB_REG_8721D, bt_bb_backup,
					 BTIQK_BB_REG_NUM_8721D);
	_btiqk_reload_mac_registers_8721d(dm, BTIQK_MAC_REG_8721D,
					  bt_mac_backup,
					  BTIQK_MAC_REG_NUM_8721D);

	RF_DBG(dm, DBG_RF_IQK, "[BTIQK]delay 50ms!!!\n");
	ODM_delay_ms(BTIQK_DELAY_TIME_8721D);

	odm_write_4byte(dm, 0x74, 0x7000A);
	odm_write_4byte(dm, 0x764, 0x1800);
	RF_DBG(dm, DBG_RF_IQK, "[BTIQK]==========IQK end!!!!!==========\n");
	return result;
}

#endif
