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
#if (DM_ODM_SUPPORT_TYPE == ODM_WIN)
#if RT_PLATFORM == PLATFORM_MACOSX
#include "phydm_precomp.h"
#else
#include "../phydm_precomp.h"
#endif
#else
#include "../../phydm_precomp.h"
#endif

#if (RTL8198F_SUPPORT == 1)



/*---------------------------Define Local Constant---------------------------*/
void phydm_get_read_counter_8198f(struct dm_struct *dm)
{
	u32 counter = 0x0;

	while (1) {
		if ((odm_get_rf_reg(dm, RF_PATH_A, RF_0x8, RFREGOFFSETMASK) == 0xabcde) || counter > 300)
			break;
		counter++;
		ODM_delay_ms(1);
	};
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x8, RFREGOFFSETMASK, 0x0);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]counter = %d\n", counter);
}

#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)
void do_iqk_8198f(
	void *dm_void,
	u8 delta_thermal_index,
	u8 thermal_value,
	u8 threshold)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;

	dm->rf_calibrate_info.thermal_value_iqk = thermal_value;
	halrf_segment_iqk_trigger(dm, true, iqk_info->segment_iqk);
}
#else
/*Originally config->do_iqk is hooked phy_iq_calibrate_8198f, but do_iqk_8198f and phy_iq_calibrate_8198f have different arguments*/
void do_iqk_8198f(
	void *dm_void,
	u8 delta_thermal_index,
	u8 thermal_value,
	u8 threshold)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	boolean is_recovery = (boolean)delta_thermal_index;

	halrf_segment_iqk_trigger(dm, true, iqk_info->segment_iqk);
}
#endif

void _iqk_clean_cfir_8198f(struct dm_struct *dm, u8 mode, u8 path)
{
	odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | path << 1);
	if (mode == TXIQK) {
		odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x3);
		odm_write_4byte(dm, 0x1bd8, 0xc0000003);
		odm_write_4byte(dm, 0x1bd8, 0xe0000001);
	}
	else {
		odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x1);
		odm_write_4byte(dm, 0x1bd8, 0x60000003);
		odm_write_4byte(dm, 0x1bd8, 0xe0000001);
	}		

	odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x0);
	odm_write_4byte(dm, 0x1bd8, 0x0);
}

void _iqk_cal_path_off_8198f(struct dm_struct *dm)
{
	u8 path;

	for(path = 0; path < SS_8198F; path++) {
		odm_set_rf_reg(dm, (enum rf_path)path, 0x0, 0xfffff, 0x10000);
		odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | path << 1);
		odm_write_1byte(dm, 0x1bcc, 0x3f);
	}
}

void _iqk_con_tx_8198f(
	struct dm_struct *dm,
	boolean is_contx)
{
	if (is_contx) {
		odm_set_bb_reg(dm, 0x180c, 0x3, 0x0);
		odm_set_bb_reg(dm, 0x410c, 0x3, 0x0);
		odm_set_bb_reg(dm, 0x520c, 0x3, 0x0);
		odm_set_bb_reg(dm, 0x530c, 0x3, 0x0);
		odm_set_bb_reg(dm, 0x1d08, BIT(0), 0x1);
		odm_set_bb_reg(dm, 0x1ca4, BIT(0), 0x1);
		odm_set_bb_reg(dm, 0x1e70, BIT(1), 0x1);
		odm_set_bb_reg(dm, 0x1e70, BIT(1), 0x0);
		odm_set_bb_reg(dm, 0x1e70, BIT(2), 0x0);
		odm_set_bb_reg(dm, 0x1e70, BIT(2), 0x1);
	} else {
		odm_set_bb_reg(dm, 0x1d08, BIT(0), 0x0);
		odm_set_bb_reg(dm, 0x1ca4, BIT(0), 0x0);
	}
}

void _iqk_rf_set_check_8198f(
	struct dm_struct *dm,
	u8 path,
	u16 add,
	u32 data)
{
	u32 i;

	odm_set_rf_reg(dm, (enum rf_path)path, add, RFREGOFFSETMASK, data);

	for (i = 0; i < 100; i++) {
		if (odm_get_rf_reg(dm, (enum rf_path)path, add, RFREGOFFSETMASK) == data)
			break;
		else {
			ODM_delay_us(10);
			odm_set_rf_reg(dm, (enum rf_path)path, add, RFREGOFFSETMASK, data);
		}
	}
}

void _iqk_rf0xb0_workaround_8198f(
	struct dm_struct *dm)
{
	/*add 0xb8 control for the bad phase noise after switching channel*/
	odm_set_rf_reg(dm, (enum rf_path)0x0, RF_0xb8, RFREGOFFSETMASK, 0x00a00);
	odm_set_rf_reg(dm, (enum rf_path)0x0, RF_0xb8, RFREGOFFSETMASK, 0x80a00);
}

void _iqk_fill_iqk_report_8198f(
	void *dm_void,
	u8 channel)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	u32 tmp1 = 0x0, tmp2 = 0x0, tmp3 = 0x0;
	u8 i;

	for (i = 0; i < SS_8198F; i++) {
		tmp1 = tmp1 + ((iqk_info->iqk_fail_report[channel][i][TX_IQK] & 0x1) << i);
		tmp2 = tmp2 + ((iqk_info->iqk_fail_report[channel][i][RX_IQK] & 0x1) << (i + 4));
		tmp3 = tmp3 + ((iqk_info->rxiqk_fail_code[channel][i] & 0x3) << (i * 2 + 8));
	}
	odm_write_4byte(dm, 0x1b00, 0x8);
	odm_set_bb_reg(dm, R_0x1bf0, 0x0000ffff, tmp1 | tmp2 | tmp3);

	tmp1 = 0x0;
	for (i = 0; i < SS_8198F; i++)
		tmp1 = tmp1 | (iqk_info->rxiqk_agc[channel][i] << (i*8));
	odm_write_4byte(dm, 0x1be8, tmp1);
}

void _iqk_fail_count_8198f(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	u8 i;

	dm->n_iqk_cnt++;
	if (odm_get_rf_reg(dm, RF_PATH_A, RF_0x1bf0, BIT(16)) == 1)
		iqk_info->is_reload = true;
	else
		iqk_info->is_reload = false;

	if (!iqk_info->is_reload) {
		for (i = 0; i < 8; i++) {
			if (odm_get_bb_reg(dm, R_0x1bf0, BIT(i)) == 1)
				dm->n_iqk_fail_cnt++;
		}
	}
	RF_DBG(dm, DBG_RF_IQK, "[IQK]All/Fail = %d %d\n", dm->n_iqk_cnt, dm->n_iqk_fail_cnt);
}

void _iqk_iqk_fail_report_8198f(
	struct dm_struct *dm)
{
	u32 tmp1bf0 = 0x0;
	u8 i;

	tmp1bf0 = odm_read_4byte(dm, 0x1bf0);

	for (i = 0; i < 4; i++) {
		if (tmp1bf0 & (0x1 << i))
#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)
			RF_DBG(dm, DBG_RF_IQK, "[IQK] please check S%d TXIQK\n", i);
#else
			panic_printk("[IQK] please check S%d TXIQK\n", i);
#endif
		if (tmp1bf0 & (0x1 << (i + 12)))
#if !(DM_ODM_SUPPORT_TYPE & ODM_AP)
			RF_DBG(dm, DBG_RF_IQK, "[IQK] please check S%d RXIQK\n", i);
#else
			panic_printk("[IQK] please check S%d RXIQK\n", i);
#endif
	}
}

void _iqk_backup_mac_bb_8198f(
	struct dm_struct *dm,
	u32 *MAC_backup,
	u32 *BB_backup,
	u32 *backup_mac_reg,
	u32 *backup_bb_reg)
{
	u32 i;
	for (i = 0; i < MAC_REG_NUM_8198F; i++)
		MAC_backup[i] = odm_read_4byte(dm, backup_mac_reg[i]);

	for (i = 0; i < BB_REG_NUM_8198F; i++)
		BB_backup[i] = odm_read_4byte(dm, backup_bb_reg[i]);

	/*	RF_DBG(dm, DBG_RF_IQK, "[IQK]BackupMacBB Success!!!!\n"); */
}

void _iqk_backup_rf_8198f(
	struct dm_struct *dm,
	u32 RF_backup[][4],
	u32 *backup_rf_reg)
{
	u32 i;

	for (i = 0; i < RF_REG_NUM_8198F; i++) {
		RF_backup[i][RF_PATH_A] = odm_get_rf_reg(dm, RF_PATH_A, backup_rf_reg[i], RFREGOFFSETMASK);
		RF_backup[i][RF_PATH_B] = odm_get_rf_reg(dm, RF_PATH_B, backup_rf_reg[i], RFREGOFFSETMASK);
		RF_backup[i][RF_PATH_C] = odm_get_rf_reg(dm, RF_PATH_C, backup_rf_reg[i], RFREGOFFSETMASK);
		RF_backup[i][RF_PATH_D] = odm_get_rf_reg(dm, RF_PATH_D, backup_rf_reg[i], RFREGOFFSETMASK);
	}
	/*	RF_DBG(dm, DBG_RF_IQK, "[IQK]BackupRF Success!!!!\n"); */
}

void _iqk_agc_bnd_int_8198f(
	struct dm_struct *dm)
{
	return;
	/*initialize RX AGC bnd, it must do after bbreset*/
	odm_write_4byte(dm, 0x1b00, 0x8);
	odm_write_4byte(dm, 0x1b00, 0xf80a7008);
	odm_write_4byte(dm, 0x1b00, 0xf8015008);
	odm_write_4byte(dm, 0x1b00, 0xf8000008);
	/*RF_DBG(dm, DBG_RF_IQK, "[IQK]init. rx agc bnd\n");*/
}

void _iqk_bb_reset_8198f(
	struct dm_struct *dm)
{
	boolean cca_ing = false;
	u32 count = 0;

	odm_set_rf_reg(dm, RF_PATH_A, RF_0x0, RFREGOFFSETMASK, 0x10000);
	odm_set_rf_reg(dm, RF_PATH_B, RF_0x0, RFREGOFFSETMASK, 0x10000);
	/*reset BB report*/
	odm_set_bb_reg(dm, R_0x8f8, 0x0ff00000, 0x0);

	while (1) {
		odm_write_4byte(dm, 0x8fc, 0x0);
		odm_set_bb_reg(dm, R_0x198c, 0x7, 0x7);
		cca_ing = (boolean)odm_get_bb_reg(dm, R_0xfa0, BIT(3));

		if (count > 30)
			cca_ing = false;

		if (cca_ing) {
			ODM_delay_ms(1);
			count++;
		} else {
			odm_write_1byte(dm, 0x808, 0x0); /*RX ant off*/
			odm_set_bb_reg(dm, R_0xa04, BIT(27) | BIT(26) | BIT(25) | BIT(24), 0x0); /*CCK RX path off*/

			/*BBreset*/
			odm_set_bb_reg(dm, R_0x0, BIT(16), 0x0);
			odm_set_bb_reg(dm, R_0x0, BIT(16), 0x1);

			if (odm_get_bb_reg(dm, R_0x660, BIT(16)))
				odm_write_4byte(dm, 0x6b4, 0x89000006);
			/*RF_DBG(dm, DBG_RF_IQK, "[IQK]BBreset!!!!\n");*/
			break;
		}
	}
}

void _iqk_afe_setting_8198f(
	struct dm_struct *dm,
	boolean do_iqk)
{
	u8 i;

	if (do_iqk) {
		odm_write_4byte(dm, 0x1830, 0x700f0041);
		for(i=0; i<0x10; i++)
			odm_write_4byte(dm, 0x1830, 0x700f0041 + (i << 20));
		odm_write_4byte(dm, 0x1830, 0x70ff0041);

		odm_write_4byte(dm, 0x4130, 0x700f0041);
		for(i=0; i<0x10; i++)
			odm_write_4byte(dm, 0x4130, 0x700f0041 + (i << 20));
		odm_write_4byte(dm, 0x4130, 0x70ff0041);


		odm_write_4byte(dm, 0x5230, 0x700f0041);
		for(i=0; i<0x10; i++)
			odm_write_4byte(dm, 0x5230, 0x700f0041 + (i << 20));
		odm_write_4byte(dm, 0x5230, 0x70ff0041);

		odm_write_4byte(dm, 0x5330, 0x700f0041);
		for(i=0; i<0x10; i++)
			odm_write_4byte(dm, 0x5330, 0x700f0041 + (i << 20));
		odm_write_4byte(dm, 0x5330, 0x70ff0041);

		
//		odm_write_4byte(dm, 0x4130, 0x700f0041);
//		odm_write_4byte(dm, 0x4130, 0x700f0041);
//		odm_write_4byte(dm, 0x5230, 0x700f0041);
//		odm_write_4byte(dm, 0x5230, 0x700f0041);
//		odm_write_4byte(dm, 0x5330, 0x700f0041);
//		odm_write_4byte(dm, 0x5330, 0x700f0041);
		/*		RF_DBG(dm, DBG_RF_IQK, "[IQK]AFE setting for IQK mode!!!!\n"); */
	} else {
		odm_write_4byte(dm, 0x1830, 0x700b8041);
		odm_write_4byte(dm, 0x1830, 0x700b8041);
		odm_write_4byte(dm, 0x1830, 0x70144041);
		odm_write_4byte(dm, 0x1830, 0x70244041);
		odm_write_4byte(dm, 0x1830, 0x70344041);
		odm_write_4byte(dm, 0x1830, 0x70444041);
		odm_write_4byte(dm, 0x1830, 0x705b8041);
		odm_write_4byte(dm, 0x1830, 0x70644041);
		odm_write_4byte(dm, 0x1830, 0x707b8041);
		odm_write_4byte(dm, 0x1830, 0x708b8041);
		odm_write_4byte(dm, 0x1830, 0x709b8041);
		odm_write_4byte(dm, 0x1830, 0x70ab8041);
		odm_write_4byte(dm, 0x1830, 0x70bb8041);
		odm_write_4byte(dm, 0x1830, 0x70cb8041);
		odm_write_4byte(dm, 0x1830, 0x70db8041);
		odm_write_4byte(dm, 0x1830, 0x70eb8041);
		odm_write_4byte(dm, 0x1830, 0x70fb8041);
		odm_write_4byte(dm, 0x1830, 0x70fb8041);
		odm_write_4byte(dm, 0x4130, 0x700b8041);
		odm_write_4byte(dm, 0x4130, 0x700b8041);
		odm_write_4byte(dm, 0x4130, 0x70144041);
		odm_write_4byte(dm, 0x4130, 0x70244041);
		odm_write_4byte(dm, 0x4130, 0x70344041);
		odm_write_4byte(dm, 0x4130, 0x70444041);
		odm_write_4byte(dm, 0x4130, 0x705b8041);
		odm_write_4byte(dm, 0x4130, 0x70644041);
		odm_write_4byte(dm, 0x4130, 0x707b8041);
		odm_write_4byte(dm, 0x4130, 0x708b8041);
		odm_write_4byte(dm, 0x4130, 0x709b8041);
		odm_write_4byte(dm, 0x4130, 0x70ab8041);
		odm_write_4byte(dm, 0x4130, 0x70bb8041);
		odm_write_4byte(dm, 0x4130, 0x70cb8041);
		odm_write_4byte(dm, 0x4130, 0x70db8041);
		odm_write_4byte(dm, 0x4130, 0x70eb8041);
		odm_write_4byte(dm, 0x4130, 0x70fb8041);
		odm_write_4byte(dm, 0x4130, 0x70fb8041);
		odm_write_4byte(dm, 0x5230, 0x700b8041);
		odm_write_4byte(dm, 0x5230, 0x700b8041);
		odm_write_4byte(dm, 0x5230, 0x70144041);
		odm_write_4byte(dm, 0x5230, 0x70244041);
		odm_write_4byte(dm, 0x5230, 0x70344041);
		odm_write_4byte(dm, 0x5230, 0x70444041);
		odm_write_4byte(dm, 0x5230, 0x705b8041);
		odm_write_4byte(dm, 0x5230, 0x70644041);
		odm_write_4byte(dm, 0x5230, 0x707b8041);
		odm_write_4byte(dm, 0x5230, 0x708b8041);
		odm_write_4byte(dm, 0x5230, 0x709b8041);
		odm_write_4byte(dm, 0x5230, 0x70ab8041);
		odm_write_4byte(dm, 0x5230, 0x70bb8041);
		odm_write_4byte(dm, 0x5230, 0x70cb8041);
		odm_write_4byte(dm, 0x5230, 0x70db8041);
		odm_write_4byte(dm, 0x5230, 0x70eb8041);
		odm_write_4byte(dm, 0x5230, 0x70fb8041);
		odm_write_4byte(dm, 0x5230, 0x70fb8041);
		odm_write_4byte(dm, 0x5330, 0x700b8041);
		odm_write_4byte(dm, 0x5330, 0x700b8041);
		odm_write_4byte(dm, 0x5330, 0x70144041);
		odm_write_4byte(dm, 0x5330, 0x70244041);
		odm_write_4byte(dm, 0x5330, 0x70344041);
		odm_write_4byte(dm, 0x5330, 0x70444041);
		odm_write_4byte(dm, 0x5330, 0x705b8041);
		odm_write_4byte(dm, 0x5330, 0x70644041);
		odm_write_4byte(dm, 0x5330, 0x707b8041);
		odm_write_4byte(dm, 0x5330, 0x708b8041);
		odm_write_4byte(dm, 0x5330, 0x709b8041);
		odm_write_4byte(dm, 0x5330, 0x70ab8041);
		odm_write_4byte(dm, 0x5330, 0x70bb8041);
		odm_write_4byte(dm, 0x5330, 0x70cb8041);
		odm_write_4byte(dm, 0x5330, 0x70db8041);
		odm_write_4byte(dm, 0x5330, 0x70eb8041);
		odm_write_4byte(dm, 0x5330, 0x70fb8041);
		odm_write_4byte(dm, 0x5330, 0x70fb8041);


		/*		RF_DBG(dm, DBG_RF_IQK, "[IQK]AFE setting for Normal mode!!!!\n"); */
	}
}

void _iqk_restore_mac_bb_8198f(
	struct dm_struct *dm,
	u32 *MAC_backup,
	u32 *BB_backup,
	u32 *backup_mac_reg,
	u32 *backup_bb_reg)
{
	u32 i;

	for (i = 0; i < MAC_REG_NUM_8198F; i++)
		odm_write_4byte(dm, backup_mac_reg[i], MAC_backup[i]);
	for (i = 0; i < BB_REG_NUM_8198F; i++)
		odm_write_4byte(dm, backup_bb_reg[i], BB_backup[i]);

	odm_set_bb_reg(dm, 0x1e70, BIT(2), 0x0);
	/*rx go throughput IQK*/
	odm_set_bb_reg(dm, 0x180c, BIT(31), 0x1);
	odm_set_bb_reg(dm, 0x410c, BIT(31), 0x1);
	odm_set_bb_reg(dm, 0x520c, BIT(31), 0x1);
	odm_set_bb_reg(dm, 0x530c, BIT(31), 0x1);
	/*	RF_DBG(dm, DBG_RF_IQK, "[IQK]RestoreMacBB Success!!!!\n"); */
}

void _iqk_restore_rf_8198f(
	struct dm_struct *dm,
	u32 *rf_reg,
	u32 temp[][4])
{
	u32 i;
	
	odm_set_rf_reg(dm, RF_PATH_A, RF_0xef, 0xfffff, 0x0);
	odm_set_rf_reg(dm, RF_PATH_B, RF_0xef, 0xfffff, 0x0);
	odm_set_rf_reg(dm, RF_PATH_C, RF_0xef, 0xfffff, 0x0);
	odm_set_rf_reg(dm, RF_PATH_D, RF_0xef, 0xfffff, 0x0);
	/*0xdf[4]=0*/
	_iqk_rf_set_check_8198f(dm, RF_PATH_A, 0xdf, temp[0][RF_PATH_A] & (~BIT(4)));
	_iqk_rf_set_check_8198f(dm, RF_PATH_B, 0xdf, temp[0][RF_PATH_B] & (~BIT(4)));
	_iqk_rf_set_check_8198f(dm, RF_PATH_C, 0xdf, temp[0][RF_PATH_C] & (~BIT(4)));
	_iqk_rf_set_check_8198f(dm, RF_PATH_D, 0xdf, temp[0][RF_PATH_D] & (~BIT(4)));

	for (i = 1; i < RF_REG_NUM_8198F; i++) {
		odm_set_rf_reg(dm, RF_PATH_A, rf_reg[i], 0xfffff, temp[i][RF_PATH_A]);
		odm_set_rf_reg(dm, RF_PATH_B, rf_reg[i], 0xfffff, temp[i][RF_PATH_B]);
		odm_set_rf_reg(dm, RF_PATH_C, rf_reg[i], 0xfffff, temp[i][RF_PATH_C]);
		odm_set_rf_reg(dm, RF_PATH_D, rf_reg[i], 0xfffff, temp[i][RF_PATH_D]);
	}
	/*	RF_DBG(dm, DBG_RF_IQK, "[IQK]RestoreRF Success!!!!\n"); */
}

void _iqk_backup_iqk_8198f(
	struct dm_struct *dm,
	u8 step,
	u8 path)
{
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	u8 i, j, k;

	switch (step) {
	case 0:
		iqk_info->iqk_channel[1] = iqk_info->iqk_channel[0];
		for (i = 0; i < SS_8198F; i++) {
			iqk_info->lok_idac[1][i] = iqk_info->lok_idac[0][i];
			iqk_info->rxiqk_agc[1][i] = iqk_info->rxiqk_agc[0][i];
			iqk_info->bypass_iqk[1][i] = iqk_info->bypass_iqk[0][i];
			iqk_info->rxiqk_fail_code[1][i] = iqk_info->rxiqk_fail_code[0][i];
			for (j = 0; j < 2; j++) {
				iqk_info->iqk_fail_report[1][i][j] = iqk_info->iqk_fail_report[0][i][j];
				for (k = 0; k < 8; k++) {
					iqk_info->iqk_cfir_real[1][i][j][k] = iqk_info->iqk_cfir_real[0][i][j][k];
					iqk_info->iqk_cfir_imag[1][i][j][k] = iqk_info->iqk_cfir_imag[0][i][j][k];
				}
			}
		}

		for (i = 0; i < SS_8198F; i++) {
			iqk_info->rxiqk_fail_code[0][i] = 0x0;
			iqk_info->rxiqk_agc[0][i] = 0x0;
			for (j = 0; j < 2; j++) {
				iqk_info->iqk_fail_report[0][i][j] = true;
				iqk_info->gs_retry_count[0][i][j] = 0x0;
			}
			for (j = 0; j < 3; j++)
				iqk_info->retry_count[0][i][j] = 0x0;
		}
		/*backup channel*/
		iqk_info->iqk_channel[0] = iqk_info->rf_reg18;
		break;
	case 1: /*LOK backup*/
		iqk_info->lok_idac[0][path] = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x58, RFREGOFFSETMASK);
		break;
	case 2: /*TXIQK backup*/
	case 3: /*RXIQK backup*/
		phydm_get_iqk_cfir(dm, (step - 2), path, false);
		break;
	}
}

void _iqk_reload_iqk_setting_8198f(
	struct dm_struct *dm,
	u8 channel,
	u8 reload_idx /*1: reload TX, 2: reload LO, TX, RX*/
	)
{
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
#if 0
	u8 i, path, idx;
	u16 iqk_apply[2] = {0xc94, 0xe94};
	u32 tmp;

	for (path = 0; path < 2; path++) {
		if (reload_idx == 2) {
			/*odm_set_rf_reg(dm, (enum rf_path)path, RF_0xdf, BIT(4), 0x1);*/
			tmp = odm_get_rf_reg(dm, (enum rf_path)path, RF_0xdf, RFREGOFFSETMASK) | BIT(4);
			_iqk_rf_set_check_8198f(dm, (enum rf_path)path, 0xdf, tmp);
			odm_set_rf_reg(dm, (enum rf_path)path, RF_0x58, RFREGOFFSETMASK, iqk_info->lok_idac[channel][path]);
		}

		for (idx = 0; idx < reload_idx; idx++) {
			odm_set_bb_reg(dm, R_0x1b00, MASKDWORD, 0x8 | path << 1);
			odm_set_bb_reg(dm, R_0x1b2c, MASKDWORD, 0x7);
			odm_set_bb_reg(dm, R_0x1b38, MASKDWORD, 0x20000000);
			odm_set_bb_reg(dm, R_0x1b3c, MASKDWORD, 0x20000000);
			odm_write_1byte(dm, 0x1bcc, 0x0);

			if (idx == 0)
				odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x3);
			else
				odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x1);
			odm_set_bb_reg(dm, R_0x1bd4, BIT(20) | BIT(19) | BIT(18) | BIT(17) | BIT(16), 0x10);
			for (i = 0; i < 8; i++) {
				odm_write_4byte(dm, 0x1bd8, ((0xc0000000 >> idx) + 0x3) + (i * 4) + (iqk_info->iqk_cfir_real[channel][path][idx][i] << 9));
				odm_write_4byte(dm, 0x1bd8, ((0xc0000000 >> idx) + 0x1) + (i * 4) + (iqk_info->iqk_cfir_imag[channel][path][idx][i] << 9));
			}
			if (idx == 0)
				odm_set_bb_reg(dm, iqk_apply[path], BIT(0), ~(iqk_info->iqk_fail_report[channel][path][idx]));
			else
				odm_set_bb_reg(dm, iqk_apply[path], BIT(10), ~(iqk_info->iqk_fail_report[channel][path][idx]));
		}
		odm_set_bb_reg(dm, R_0x1bd8, MASKDWORD, 0x0);
		odm_set_bb_reg(dm, R_0x1b0c, BIT(13) | BIT(12), 0x0);
	}
#endif
}

boolean
_iqk_reload_iqk_8198f(
	struct dm_struct *dm,
	boolean reset)
{
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	u8 i;
	iqk_info->is_reload = false;

	if (reset) {
		for (i = 0; i < 2; i++)
			iqk_info->iqk_channel[i] = 0x0;
	} else {
		iqk_info->rf_reg18 = odm_get_rf_reg(dm, RF_PATH_A, RF_0x18, RFREGOFFSETMASK);

		for (i = 0; i < 2; i++) {
			if (iqk_info->rf_reg18 == iqk_info->iqk_channel[i]) {
				_iqk_reload_iqk_setting_8198f(dm, i, 2);
				_iqk_fill_iqk_report_8198f(dm, i);
				RF_DBG(dm, DBG_RF_IQK, "[IQK]reload IQK result before!!!!\n");
				iqk_info->is_reload = true;
			}
		}
	}
	/*report*/
	odm_set_bb_reg(dm, R_0x1bf0, BIT(16), (u8)iqk_info->is_reload);
	return iqk_info->is_reload;
}

void _iqk_rfe_setting_8198f(
	struct dm_struct *dm)
{
	odm_write_4byte(dm, 0x183c, 0x0);
	odm_write_4byte(dm, 0x413c, 0x0);
	odm_write_4byte(dm, 0x523c, 0x0);
	odm_write_4byte(dm, 0x533c, 0x0);
	odm_write_4byte(dm, 0x1840, 0x77777777);
	odm_write_4byte(dm, 0x1844, 0x77777777);
	odm_write_4byte(dm, 0x4140, 0x77777777);
	odm_write_4byte(dm, 0x4144, 0x77777777);
	odm_write_4byte(dm, 0x5240, 0x77777777);
	odm_write_4byte(dm, 0x5244, 0x77777777);
	odm_write_4byte(dm, 0x5340, 0x77777777);
	odm_write_4byte(dm, 0x5344, 0x77777777);
}

void _iqk_setrf_bypath_8198f(
	struct dm_struct *dm)
{
	u8 path;
	u32 tmp;

	/*TBD*/
}

void _iqk_bbtx_path_8198f(
	struct dm_struct *dm,
	u8 path)
{
	u32 temp1, temp2;

	switch (path) {
	case RF_PATH_A:
		temp1 = 0x11111111;
		temp2 = 0x1;
		break;
	case RF_PATH_B:
		temp1 = 0x22222222;
		temp2 = 0x2;
		break;
	case RF_PATH_C:
		temp1 = 0x44444444;
		temp2 = 0x4;
		break;
	case RF_PATH_D:
		temp1 = 0x88888888;
		temp2 = 0x8;
		break;
	}
	odm_write_4byte(dm, 0x820, temp1);
	odm_set_bb_reg(dm, 0x824, 0xf0000, temp2);
}

void _iqk_iqk_mode_8198f(
	struct dm_struct *dm,
	boolean is_iqkmode)
{
	u32 temp1, temp2;
	/*RF can't be write in iqk mode*/
	/*page 1b can't */
	if (is_iqkmode)
		odm_set_bb_reg(dm, 0x1cd0, BIT(31), 0x1);
	else
		odm_set_bb_reg(dm, 0x1cd0, BIT(31), 0x0);	
}

void _iqk_macbb_8198f(
	struct dm_struct *dm)
{
	/*MACBB register setting*/
	odm_write_1byte(dm, 0x522, 0xff);
	odm_set_bb_reg(dm, R_0x550, BIT(11) | BIT(3), 0x0);
	/*BB CCA off*/
	odm_set_bb_reg(dm, 0x1c68, BIT(27) | BIT(26) | BIT(25) | BIT(24), 0xf);
	/*tx go throughput IQK*/
	odm_set_bb_reg(dm, 0x1e24, BIT(17), 0x1);
	/*enable IQK block*/
	odm_set_bb_reg(dm, 0x1cd0, BIT(30) | BIT(29) | BIT(28), 0x7);	
	/*enable IQK loop back in BB*/
	odm_set_bb_reg(dm, 0x1d60, BIT(31), 0x1);	
	/*ADDA FIFO reset*/
	odm_write_4byte(dm, 0x1c38, 0xffffffff);
	/*CCK off*/
	odm_set_bb_reg(dm, 0x1c3c, BIT(1), 0x0);	
}

void _iqk_lok_setting_8198f(
	struct dm_struct *dm,
	u8 path)
{
	_iqk_cal_path_off_8198f(dm);
	_iqk_bbtx_path_8198f(dm, path);
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
	odm_write_1byte(dm, 0x1b20, 0x00040008);
	odm_write_1byte(dm, 0x1bcc, 0x9);
	odm_set_bb_reg(dm, 0x1b2c, 0xfff, 0x18);

	/*loop gain*/
	_iqk_rf_set_check_8198f(dm, (enum rf_path)path, RF_0xdf, 0x810);
	_iqk_rf_set_check_8198f(dm, (enum rf_path)path, RF_0xef, 0x0);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56, 0xfff, 0x0c8);
//	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56, 0xfff, 0xee4);
	/*	RF_DBG(dm, DBG_RF_IQK, "[IQK]Set LOK setting!!!!\n");*/
}

void _iqk_txk_setting_8198f(
	struct dm_struct *dm,
	u8 path)
{
	_iqk_bbtx_path_8198f(dm, path);
	_iqk_cal_path_off_8198f(dm);
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
	odm_write_1byte(dm, 0x1b20, 0x00040008);
	odm_write_1byte(dm, 0x1bcc, 0x9);
	/*loop gain*/
	_iqk_rf_set_check_8198f(dm, (enum rf_path)path, RF_0xdf, 0x810);
	_iqk_rf_set_check_8198f(dm, (enum rf_path)path, RF_0xef, 0x0);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56, 0xfff, 0x0c8);
//	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56, 0xfff, 0xee4);
	/*	RF_DBG(dm, DBG_RF_IQK, "[IQK]Set TXK setting!!!!\n");*/
}

void _iqk_lok_for_rxk_setting_8198f(
	struct dm_struct *dm,
	u8 path)
{
	_iqk_bbtx_path_8198f(dm, path);
	_iqk_cal_path_off_8198f(dm);
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
	odm_write_4byte(dm, 0x1b20, 0x00060008);
	odm_write_1byte(dm, 0x1bcc, 0x9);
	odm_set_bb_reg(dm, 0x1b2c, 0xfff, 0x38);
	/*loop gain*/
	_iqk_rf_set_check_8198f(dm, (enum rf_path)path, RF_0xdf, 0x810);
	_iqk_rf_set_check_8198f(dm, (enum rf_path)path, RF_0xef, 0x0);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56, 0xfff, 0x0c8);
	/*	RF_DBG(dm, DBG_RF_IQK, "[IQK]Set LOK setting!!!!\n");*/
}

void _iqk_rxk1_setting_8198f(
	struct dm_struct *dm,
	u8 path)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;

	_iqk_bbtx_path_8198f(dm, path);
	_iqk_cal_path_off_8198f(dm);
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
	odm_write_1byte(dm, 0x1bcc, 0x9);
	odm_write_4byte(dm, 0x1b20, 0x00060008);
	/*loop gain*/
	_iqk_rf_set_check_8198f(dm, (enum rf_path)path, RF_0xdf, 0x810);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56, 0xfff, 0x0c8);
//	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56, 0xfff, 0x0c0);
	/*RF_DBG(dm, DBG_RF_IQK, "[IQK]Set RXK setting!!!!\n");*/
}

void _iqk_rxk2_setting_8198f(
	struct dm_struct *dm,
	u8 path,
	boolean is_gs)
{
	struct dm_iqk_info *iqk = &dm->IQK_info;

	if (is_gs) {
		iqk->tmp1bcc = 0x09;
		iqk->txgain = 0x064;
		iqk->lna_idx = 1;
	}
	_iqk_bbtx_path_8198f(dm, path);
	_iqk_cal_path_off_8198f(dm);
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
	odm_write_1byte(dm, 0x1bcc, iqk->tmp1bcc);
	odm_write_4byte(dm, 0x1b24, 0x00070048 | iqk->lna_idx << 10);
	/*loop gain*/
	_iqk_rf_set_check_8198f(dm, (enum rf_path)path, RF_0xdf, 0x80810);
	_iqk_rf_set_check_8198f(dm, (enum rf_path)path, 0x7e, 0x82200);
	_iqk_rf_set_check_8198f(dm, (enum rf_path)path, 0x7f, 0x000fa);
	_iqk_rf_set_check_8198f(dm, (enum rf_path)path, 0x80, 0x2001e);
	_iqk_rf_set_check_8198f(dm, (enum rf_path)path, 0x81, 0x0fc00);
	_iqk_rf_set_check_8198f(dm, (enum rf_path)path, 0xb0, 0xffbc7);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56, 0xfff, iqk->txgain);
	/*	RF_DBG(dm, DBG_RF_IQK, "[IQK]Set RXK setting!!!!\n");*/
}

boolean
_iqk_check_cal_8198f(
	struct dm_struct *dm,
	u8 path,
	u8 cmd)
{
	boolean notready = true, fail = true;
	u32 delay_count = 0x0;

	while (notready) {
		if (odm_read_1byte(dm, 0x2d9c) == 0x55) {
			if (cmd == 0x0) /*LOK*/
				fail = false;
			else
				fail = (boolean)odm_get_bb_reg(dm, R_0x1b08, BIT(26));
			notready = false;
		} else {
			ODM_delay_ms(1);
			delay_count++;
		}

		if (delay_count >= 50) {
			fail = true;
			RF_DBG(dm, DBG_RF_IQK, "[IQK]IQK timeout!!!\n");
			break;
		}
	}
	odm_write_1byte(dm, 0x1b10, 0x0);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]delay count = 0x%x!!!\n", delay_count);
	return fail;
}

void
_iqk_set_lok_lut_8198f(
	struct dm_struct *dm,
	u8 path)
{
	u32 temp;
	u8 idac_i, idac_q;
	u8 i;
	temp = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x58, 0xfffff);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]setlut_0x58 = 0x%x\n", temp);
	idac_i = (temp & 0xfc000) >> 14;
	idac_q = (temp & 0x3f0) >> 4;
	temp =  (idac_i << 6) | idac_q;
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xdf, BIT(4), 0x0);
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x1);
	for (i = 0; i < 8; i++) {
		temp = (i << 14) | (temp & 0xfff);
		odm_set_rf_reg(dm, (enum rf_path)path, 0x33, 0xfffff, temp);
		/*RF_DBG(dm, DBG_RF_IQK, "[IQK]path =%d,0x33  = 0x%x!!!\n", path, temp);*/
	}
	odm_set_rf_reg(dm, (enum rf_path)path, RF_0xef, BIT(4), 0x0);
}

boolean
_iqk_rx_iqk_gain_search_fail_8198f(
	struct dm_struct *dm,
	u8 path,
	u8 step)
{
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	boolean fail = true;
	u32 IQK_CMD = 0x0, rf_reg0, tmp, bb_idx;
	u8 IQMUX[2] = {0x9, 0x12};
//	u8 tx_chain[2] = {0xc0, 0x60, 0x20, 0x0};
	u8 tx_chain[2] = {0xc0, 0x60};
	u8 idx1, idx2;

	if (step == RXIQK1) {
		RF_DBG(dm, DBG_RF_IQK, "[IQK]============ S%d RXIQK GainSearch ============\n", path);
		IQK_CMD = 0x208 | (1 << (path + 4));
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S%d GS%d_Trigger=0x%x\n", path, step, IQK_CMD);
		odm_write_4byte(dm, 0x1b00, IQK_CMD);
		odm_write_4byte(dm, 0x1b00, IQK_CMD + 0x1);
		ODM_delay_ms(IQK_DELAY_8198F);
		fail = _iqk_check_cal_8198f(dm, path, 0x1);
	} else if (step == RXIQK2) {
		for (idx1 = 0; idx1 < 2; idx1++) {
			if (iqk_info->tmp1bcc == IQMUX[idx1])
				break;
		}

		for (idx2 = 0; idx2 < 2; idx2++) {
			if (iqk_info->txgain == tx_chain[idx2])
				break;
		}

		odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
		odm_write_1byte(dm, 0x1bcc, iqk_info->tmp1bcc);
		odm_set_rf_reg(dm, (enum rf_path)path, RF_0x56, 0xfff, iqk_info->txgain);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]0x56=0x%x, tmp1bcc=0x%x\n", iqk_info->txgain, iqk_info->tmp1bcc);
		IQK_CMD = 0x308 | (1 << (path + 4));
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S%d GS%d_Trigger=0x%x\n", path, step, IQK_CMD);
		odm_write_4byte(dm, 0x1b00, IQK_CMD);
		odm_write_4byte(dm, 0x1b00, IQK_CMD + 0x1);
		ODM_delay_ms(IQK_DELAY_8198F);
		fail = _iqk_check_cal_8198f(dm, path, 0x1);

		rf_reg0 = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x0, RFREGOFFSETMASK);

		odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]RF0x0 = 0x%x, 0x1b3c = 0x%x\n", rf_reg0, odm_read_4byte(dm, 0x1b3c));
		tmp = (rf_reg0 & 0x1fe0) >> 5;
		iqk_info->lna_idx = tmp >> 5;
		bb_idx = tmp & 0x1f;

#if 0
		if (bb_idx == 0x1) {
			if (idx2 != 3)
				idx2++;
			else if (idx1 != 3)
				idx1++;
			else
				iqk_info->isbnd = true;
			fail = true;
		} else if (bb_idx > 0x5) {
			if (idx1 != 0)
				idx1--;
			else if (idx2 !=0 )
				idx2--;
			else
				iqk_info->isbnd = true;
			fail = true;
		} else
			fail = false;
#endif

#if 1
		if (bb_idx == 0x1) {
			if (iqk_info->lna_idx != 0)
				iqk_info->lna_idx--;
			else if (idx2 != 1)
				idx2++;
			else if (idx1 != 1)
				idx1++;
			else
				iqk_info->isbnd = true;
			fail = true;
		} else if (bb_idx > 0x5) {
			if (iqk_info->lna_idx != 2)
				iqk_info->lna_idx++;
			else if (idx2 !=0 )
				idx2--;
			else
				iqk_info->isbnd = true;
			fail = true;
		} else
			fail = false;
#endif
		if (iqk_info->isbnd == true) {
			fail = false;
			RF_DBG(dm, DBG_RF_IQK, "[IQK]gain is at boundary\n");
		}
		iqk_info->tmp1bcc = IQMUX[idx1];
		iqk_info->txgain = tx_chain[idx2];
		iqk_info->rxiqk_agc[0][path]= (idx2 <<6) | (idx1 << 4);
		if (fail) {
			odm_write_4byte(dm, 0x1b00, 0xf8000008 | path << 1);
			tmp = (odm_read_4byte(dm, 0x1b24) & 0xffffe3ff) |
				(iqk_info->lna_idx << 10);
			odm_write_4byte(dm, 0x1b24, tmp);
		}
	}
	return fail;
}

boolean
_lok_one_shot_8198f(
	void *dm_void,
	u8 path,
	boolean for_rxk)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	struct _hal_rf_ *rf = &dm->rf_table;

	u8 delay_count = 0;
	boolean LOK_notready = false;
	u32 temp = 0;
	u32 IQK_CMD = 0x0;
	u8 idac_i, idac_q;
	if (for_rxk) {
		RF_DBG(dm, DBG_RF_IQK,
			"[IQK]======S%d LOK for RXK======\n", path);
		IQK_CMD = 0x1008 | (1 << (4 + path)) | (path << 1);
	} else { 
		RF_DBG(dm, DBG_RF_IQK,
			"[IQK]======S%d LOK======\n", path);
		IQK_CMD = 0x8 | (1 << (4 + path)) | (path << 1);
	}
	RF_DBG(dm, DBG_RF_IQK, "[IQK]LOK_Trigger = 0x%x\n", IQK_CMD);
	odm_write_4byte(dm, 0x1b00, IQK_CMD);
	odm_write_4byte(dm, 0x1b00, IQK_CMD + 1);
	/*LOK: CMD ID = 0	{0xf8000018, 0xf8000028}*/
	/*LOK: CMD ID = 0	{0xf8000019, 0xf8000029}*/
	ODM_delay_ms(IQK_DELAY_8198F);
	LOK_notready = _iqk_check_cal_8198f(dm, path, 0x0);
	if (!for_rxk)
	_iqk_set_lok_lut_8198f(dm, path);
//	if (!LOK_notready)
//		_iqk_backup_iqk_8198f(dm, 0x1, path);
	if (rf->rf_dbg_comp & DBG_RF_IQK) {
		temp = odm_get_rf_reg(dm, (enum rf_path)path, RF_0x58, 0xfffff);
		if (!LOK_notready)
			RF_DBG(dm, DBG_RF_IQK, "[IQK]0x58 = 0x%x\n", temp);
		else
			RF_DBG(dm, DBG_RF_IQK, "[IQK]==>S%d LOK Fail!!!\n", path);
	}
	iqk_info->lok_fail[path] = LOK_notready;
	return LOK_notready;
}

boolean
_iqk_one_shot_8198f(
	void *dm_void,
	u8 path,
	u8 idx)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	struct _hal_rf_ *rf = &dm->rf_table;
	boolean notready = true, fail = true;
	u32 iqk_cmd = 0x0 , temp = 0x0;

	if (idx == TXIQK)
		RF_DBG(dm, DBG_RF_IQK, "[IQK]============ S%d WBTXIQK ============\n", path);
	else if (idx == RXIQK1)
		RF_DBG(dm, DBG_RF_IQK, "[IQK]============ S%d WBRXIQK STEP1============\n", path);
	else
		RF_DBG(dm, DBG_RF_IQK, "[IQK]============ S%d WBRXIQK STEP2============\n", path);

	if (idx == TXIQK) {
		temp = ((*dm->band_width + 4) << 8) | (1 << (path + 4)) | (path << 1);
		iqk_cmd = 0x8 | temp;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]TXK_Trigger = 0x%x\n", iqk_cmd);
		/*{0xf8000418, 0xf800042a} ==> 20 WBTXK (CMD = 4)*/
		/*{0xf8000518, 0xf800052a} ==> 40 WBTXK (CMD = 5)*/
		/*{0xf8000618, 0xf800062a} ==> 80 WBTXK (CMD = 6)*/
	} else if (idx == RXIQK1) {
		if (*dm->band_width == 2)
			iqk_cmd = 0x808 | (1 << (path + 4)) | (path << 1);
		else
			iqk_cmd = 0x708 | (1 << (path + 4)) | (path << 1);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]RXK1_Trigger = 0x%x\n", iqk_cmd);
		/*{0xf8000718, 0xf800072a} ==> 20 WBTXK (CMD = 7)*/
		/*{0xf8000718, 0xf800072a} ==> 40 WBTXK (CMD = 7)*/
		/*{0xf8000818, 0xf800082a} ==> 80 WBTXK (CMD = 8)*/
	} else if (idx == RXIQK2) {
		temp = ((*dm->band_width + 9) << 8) | (1 << (path + 4)) | (path << 1);
		iqk_cmd = 0x8 | temp;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]RXK2_Trigger = 0x%x\n", iqk_cmd);
		/*{0xf8000918, 0xf800092a} ==> 20 WBRXK (CMD = 9)*/
		/*{0xf8000a18, 0xf8000a2a} ==> 40 WBRXK (CMD = 10)*/
		/*{0xf8000b18, 0xf8000b2a} ==> 80 WBRXK (CMD = 11)*/
//		odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
//		odm_write_4byte(dm, 0x1b24, (odm_read_4byte(dm, 0x1b24) & 0xffffe3ff) | ((iqk_info->lna_idx & 0x7) << 10));
	}
	if (rf->rf_dbg_comp & DBG_RF_IQK) {
		if (idx != TXIQK) {
			odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
			RF_DBG(dm, DBG_RF_IQK, "[IQK]0x1bcc =0x%x\n", odm_read_1byte(dm, 0x1bcc));
		}
	}

	odm_write_4byte(dm, 0x1b00, iqk_cmd);
	odm_write_4byte(dm, 0x1b00, iqk_cmd + 0x1);
	ODM_delay_ms(IQK_DELAY_8198F);
	fail = _iqk_check_cal_8198f(dm, path, 0x1);

	if (rf->rf_dbg_comp & DBG_RF_IQK) {
//		odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]0x1b00 = 0x%x, 0x1b08 = 0x%x\n", odm_read_4byte(dm, 0x1b00), odm_read_4byte(dm, 0x1b08));
		if (idx != TXIQK) {
			RF_DBG(dm, DBG_RF_IQK, "[IQK]RF0x0 = 0x%x, RF0x56 = 0x%x\n",
				odm_get_rf_reg(dm, (enum rf_path)path, RF_0x0, RFREGOFFSETMASK),
				odm_get_rf_reg(dm, (enum rf_path)path, RF_0x56, RFREGOFFSETMASK));
		}
	}

	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
#if 0
	if (idx == TXIQK) {
		if (!fail)
			_iqk_backup_iqk_8198f(dm, 0x2, path);
	}
#endif
	if (idx == RXIQK2) {
		iqk_info->rxiqk_agc[0][path] = iqk_info->rxiqk_agc[0][path] |
			((odm_get_rf_reg(dm, (enum rf_path)path, RF_0x0, RFREGOFFSETMASK) >> 5) & 0x3f);

		odm_write_4byte(dm, 0x1b38, 0x20000000);
#if 0
		if (!fail)
			_iqk_backup_iqk_8198f(dm, 0x3, path);
#endif
	}

	if (fail) {
		if (idx == TXIQK)
			_iqk_clean_cfir_8198f(dm, TXIQK, path);
		else if (idx == RXIQK2)
			_iqk_clean_cfir_8198f(dm, RXIQK, path);
	}


	if (idx == TXIQK)
		iqk_info->iqk_fail_report[0][path][TXIQK] = fail;
	else
		iqk_info->iqk_fail_report[0][path][RXIQK] = fail;

	return fail;
}

boolean
_iqk_rx_iqk_by_path_8198f(
	void *dm_void,
	u8 path)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	boolean KFAIL = false, gonext;

#if 1
	switch (iqk_info->rxiqk_step) {
	case 1:
#if 1
		_iqk_lok_for_rxk_setting_8198f(dm, path);
		_lok_one_shot_8198f(dm, path, true);
#endif
		iqk_info->rxiqk_step++;
		break;
	case 2: /*gain search_RXK1*/
#if 1
		_iqk_rxk1_setting_8198f(dm, path);
		gonext = false;
		while (1) {
			KFAIL = _iqk_rx_iqk_gain_search_fail_8198f(dm, path, RXIQK1);
			if (KFAIL && iqk_info->gs_retry_count[0][path][0] < 2)
				iqk_info->gs_retry_count[0][path][0]++;
			else if (KFAIL) {
				iqk_info->rxiqk_fail_code[0][path] = 0;
				iqk_info->rxiqk_step = RXK_STEP_8198F;
				gonext = true;
			} else {
				iqk_info->rxiqk_step++;
				gonext = true;
			}
			if (gonext)
				break;
		}
//		halrf_iqk_xym_read(dm, path, 0x2);
#else
		iqk_info->rxiqk_step++;
#endif
		break;
	case 3: /*gain search_RXK2*/
#if 1
		_iqk_rxk2_setting_8198f(dm, path, true);
		iqk_info->isbnd = false;
		while (1) {
			RF_DBG(dm, DBG_RF_IQK, "[IQK]gs2_retry = %d\n", iqk_info->gs_retry_count[0][path][1]);
			KFAIL = _iqk_rx_iqk_gain_search_fail_8198f(dm, path, RXIQK2);
			if (KFAIL && iqk_info->gs_retry_count[0][path][1] < rxiqk_gs_limit)
				iqk_info->gs_retry_count[0][path][1]++;
			else {
				iqk_info->rxiqk_step++;
				break;
			}
		}
//		halrf_iqk_xym_read(dm, path, 0x3);
#else
		iqk_info->rxiqk_step++;
#endif
		break;
	case 4: /*RXK1*/
#if 1
		_iqk_rxk1_setting_8198f(dm, path);
		gonext = false;
		while (1) {
			KFAIL = _iqk_one_shot_8198f(dm, path, RXIQK1);
			if (KFAIL && iqk_info->retry_count[0][path][RXIQK1] < 2)
				iqk_info->retry_count[0][path][RXIQK1]++;
			else if (KFAIL) {
				iqk_info->rxiqk_fail_code[0][path] = 1;
				iqk_info->rxiqk_step = RXK_STEP_8198F;
				gonext = true;
			} else {
				iqk_info->rxiqk_step++;
				gonext = true;
			}
			if (gonext)
				break;
		}
//		halrf_iqk_xym_read(dm, path, 0x4);
#else
	iqk_info->rxiqk_step++;
#endif
		break;
	case 5: /*RXK2*/
#if 1
		_iqk_rxk2_setting_8198f(dm, path, false);
		gonext = false;
#if 1
		while (1) {
			KFAIL = _iqk_one_shot_8198f(dm, path, RXIQK2);
			if (KFAIL && iqk_info->retry_count[0][path][RXIQK2] < 2)
				iqk_info->retry_count[0][path][RXIQK2]++;
			else if (KFAIL) {
				iqk_info->rxiqk_fail_code[0][path] = 2;
				iqk_info->rxiqk_step = RXK_STEP_8198F;
				gonext = true;
			} else {
				iqk_info->rxiqk_step++;
				gonext = true;
			}
			if (gonext)
				break;
		}
#endif
//		halrf_iqk_xym_read(dm, path, 0x0);
#else
	iqk_info->rxiqk_step++;
#endif
		break;
	}
	return KFAIL;
#endif
}

void _iqk_iqk_by_path_8198f(
	void *dm_void,
	boolean segment_iqk)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	boolean KFAIL = true;
	u8 i, kcount_limit;

	/*	RF_DBG(dm, DBG_RF_IQK, "[IQK]iqk_step = 0x%x\n", dm->rf_calibrate_info.iqk_step); */
#if 1
	switch (iqk_info->iqk_step) {
	case 0: /*S0 LOK*/
#if 1
		_iqk_lok_setting_8198f(dm, RF_PATH_A);
		_lok_one_shot_8198f(dm, RF_PATH_A, false);
#endif
		iqk_info->iqk_step++;
		break;
	case 1: /*S1 LOK*/
#if 1
		_iqk_lok_setting_8198f(dm, RF_PATH_B);
		_lok_one_shot_8198f(dm, RF_PATH_B, false);
#endif
		iqk_info->iqk_step++;
		break;
	case 2: /*S2 LOK*/
#if 1
		_iqk_lok_setting_8198f(dm, RF_PATH_C);
		_lok_one_shot_8198f(dm, RF_PATH_C, false);
#endif
		iqk_info->iqk_step++;
		break;
	case 3: /*S3 LOK*/
#if 1
		_iqk_lok_setting_8198f(dm, RF_PATH_D);
		_lok_one_shot_8198f(dm, RF_PATH_D, false);
#endif
		iqk_info->iqk_step++;
		break;
	case 4: /*S0 TXIQK*/
#if 1
		_iqk_txk_setting_8198f(dm, RF_PATH_A);
		KFAIL = _iqk_one_shot_8198f(dm, RF_PATH_A, TXIQK);
		iqk_info->kcount++;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0TXK KFail = 0x%x\n", KFAIL);
		if (KFAIL && iqk_info->retry_count[0][RF_PATH_A][TXIQK] < 3)
			iqk_info->retry_count[0][RF_PATH_A][TXIQK]++;
		else
#endif
			iqk_info->iqk_step++;
//		halrf_iqk_xym_read(dm, RF_PATH_A, 0x1);
		break;
	case 5: /*S1 TXIQK*/
#if 1
		_iqk_txk_setting_8198f(dm, RF_PATH_B);
		KFAIL = _iqk_one_shot_8198f(dm, RF_PATH_B, TXIQK);
		iqk_info->kcount++;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S1TXK KFail = 0x%x\n", KFAIL);
		if (KFAIL && iqk_info->retry_count[0][RF_PATH_B][TXIQK] < 3)
			iqk_info->retry_count[0][RF_PATH_B][TXIQK]++;
		else
#endif
			iqk_info->iqk_step++;
//		halrf_iqk_xym_read(dm, RF_PATH_B, 0x1);
		break;
	case 6: /*S2 TXIQK*/
#if 1
		_iqk_txk_setting_8198f(dm, RF_PATH_C);
		KFAIL = _iqk_one_shot_8198f(dm, RF_PATH_C, TXIQK);
		iqk_info->kcount++;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S2TXK KFail = 0x%x\n", KFAIL);
		if (KFAIL && iqk_info->retry_count[0][RF_PATH_C][TXIQK] < 3)
			iqk_info->retry_count[0][RF_PATH_C][TXIQK]++;
		else
#endif
			iqk_info->iqk_step++;
//		halrf_iqk_xym_read(dm, RF_PATH_C, 0x1);
		break;
	case 7: /*S3 TXIQK*/
#if 1
		_iqk_txk_setting_8198f(dm, RF_PATH_D);
		KFAIL = _iqk_one_shot_8198f(dm, RF_PATH_D, TXIQK);
		iqk_info->kcount++;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S3TXK KFail = 0x%x\n", KFAIL);
		if (KFAIL && iqk_info->retry_count[0][RF_PATH_D][TXIQK] < 3)
			iqk_info->retry_count[0][RF_PATH_D][TXIQK]++;
		else
#endif
			iqk_info->iqk_step++;
//		halrf_iqk_xym_read(dm, RF_PATH_D, 0x1);
		break;
	case 8: /*S0 RXIQK*/
#if 1
		while (1) {
			KFAIL = _iqk_rx_iqk_by_path_8198f(dm, RF_PATH_A);
			RF_DBG(dm, DBG_RF_IQK, "[IQK]S0RXK KFail = 0x%x\n", KFAIL);
			if (iqk_info->rxiqk_step == RXK_STEP_8198F) {
				iqk_info->iqk_step++;
				iqk_info->rxiqk_step = 1;
				if (KFAIL)
					RF_DBG(dm, DBG_RF_IQK, "[IQK]S0RXK fail code: %d!!!\n", iqk_info->rxiqk_fail_code[0][RF_PATH_A]);
				break;
			}
		}
		iqk_info->kcount++;
#else
	iqk_info->iqk_step++;
#endif
		break;
	case 9: /*S1 RXIQK*/
#if 1
		while (1) {
			KFAIL = _iqk_rx_iqk_by_path_8198f(dm, RF_PATH_B);
			RF_DBG(dm, DBG_RF_IQK, "[IQK]S1RXK KFail = 0x%x\n", KFAIL);
			if (iqk_info->rxiqk_step == RXK_STEP_8198F) {
				iqk_info->iqk_step++;
				iqk_info->rxiqk_step = 1;
				if (KFAIL)
					RF_DBG(dm, DBG_RF_IQK, "[IQK]S1RXK fail code: %d!!!\n", iqk_info->rxiqk_fail_code[0][RF_PATH_B]);
				break;
			}
		}
		iqk_info->kcount++;
#else
	iqk_info->iqk_step++;
#endif
		break;
	case 10: /*S2 RXIQK*/
#if 1
		while (1) {
			KFAIL = _iqk_rx_iqk_by_path_8198f(dm, RF_PATH_C);
			RF_DBG(dm, DBG_RF_IQK, "[IQK]S2RXK KFail = 0x%x\n", KFAIL);
			if (iqk_info->rxiqk_step == RXK_STEP_8198F) {
				iqk_info->iqk_step++;
				iqk_info->rxiqk_step = 1;
				if (KFAIL)
					RF_DBG(dm, DBG_RF_IQK, "[IQK]S2RXK fail code: %d!!!\n", iqk_info->rxiqk_fail_code[0][RF_PATH_A]);
				break;
			}
		}
		iqk_info->kcount++;
#else
	iqk_info->iqk_step++;
#endif
		break;
	case 11: /*S3 RXIQK*/
#if 1
		while (1) {
			KFAIL = _iqk_rx_iqk_by_path_8198f(dm, RF_PATH_D);
			RF_DBG(dm, DBG_RF_IQK, "[IQK]S3RXK KFail = 0x%x\n", KFAIL);
			if (iqk_info->rxiqk_step == RXK_STEP_8198F) {
				iqk_info->iqk_step++;
				iqk_info->rxiqk_step = 1;
				if (KFAIL)
					RF_DBG(dm, DBG_RF_IQK, "[IQK]S3RXK fail code: %d!!!\n", iqk_info->rxiqk_fail_code[0][RF_PATH_B]);
				break;
			}
		}
		iqk_info->kcount++;
#else
	iqk_info->iqk_step++;
#endif
		break;
	}

	if (iqk_info->iqk_step == IQK_STEP_8198F) {
		RF_DBG(dm, DBG_RF_IQK, "[IQK]==========LOK summary ==========\n");
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_LOK_fail = %d, S1_LOK_fail = %d, S2_LOK_fail = %d,, S3_LOK_fail = %d\n",
		       iqk_info->lok_fail[RF_PATH_A], iqk_info->lok_fail[RF_PATH_B],
		       iqk_info->lok_fail[RF_PATH_C], iqk_info->lok_fail[RF_PATH_D]);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]==========IQK summary ==========\n");
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_TXIQK_fail = %d, S1_TXIQK_fail = %d, S2_TXIQK_fail = %d, S3_TXIQK_fail = %d\n",
		       iqk_info->iqk_fail_report[0][RF_PATH_A][TXIQK], iqk_info->iqk_fail_report[0][RF_PATH_B][TXIQK],
		       iqk_info->iqk_fail_report[0][RF_PATH_C][TXIQK], iqk_info->iqk_fail_report[0][RF_PATH_D][TXIQK]);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_RXIQK_fail = %d, S1_RXIQK_fail = %d, S2_RXIQK_fail = %d, S3_RXIQK_fail = %d\n",
		       iqk_info->iqk_fail_report[0][RF_PATH_A][RXIQK], iqk_info->iqk_fail_report[0][RF_PATH_B][RXIQK],
		       iqk_info->iqk_fail_report[0][RF_PATH_C][RXIQK], iqk_info->iqk_fail_report[0][RF_PATH_D][RXIQK]);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_TXIQK_retry = %d, S1_TXIQK_retry = %d, S2_TXIQK_retry = %d, S3_TXIQK_retry = %d\n",
		       iqk_info->retry_count[0][RF_PATH_A][TXIQK], iqk_info->retry_count[0][RF_PATH_B][TXIQK],
		       iqk_info->retry_count[0][RF_PATH_C][TXIQK], iqk_info->retry_count[0][RF_PATH_D][TXIQK]);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_RXK1_retry = %d, S0_RXK2_retry = %d,S1_RXK1_retry = %d, S1_RXK2_retry = %d\n",
		       iqk_info->retry_count[0][RF_PATH_A][RXIQK1], iqk_info->retry_count[0][RF_PATH_A][RXIQK2],
		       iqk_info->retry_count[0][RF_PATH_B][RXIQK1], iqk_info->retry_count[0][RF_PATH_B][RXIQK2]);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S2_RXK1_retry = %d, S2_RXK2_retry = %d,S3_RXK1_retry = %d, S3_RXK2_retry = %d\n",
		       iqk_info->retry_count[0][RF_PATH_C][RXIQK1], iqk_info->retry_count[0][RF_PATH_C][RXIQK2],
		       iqk_info->retry_count[0][RF_PATH_D][RXIQK1], iqk_info->retry_count[0][RF_PATH_D][RXIQK2]);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S0_GS1_retry = %d, S0_GS2_retry = %d, S1_GS1_retry = %d, S1_GS2_retry = %d\n",
		       iqk_info->gs_retry_count[0][RF_PATH_A][0], iqk_info->gs_retry_count[0][RF_PATH_A][1],
		       iqk_info->gs_retry_count[0][RF_PATH_B][0], iqk_info->gs_retry_count[0][RF_PATH_B][1]);
		RF_DBG(dm, DBG_RF_IQK, "[IQK]S2_GS1_retry = %d, S2_GS2_retry = %d, S3_GS1_retry = %d, S3_GS2_retry = %d\n",
		       iqk_info->gs_retry_count[0][RF_PATH_C][0], iqk_info->gs_retry_count[0][RF_PATH_C][1],
		       iqk_info->gs_retry_count[0][RF_PATH_D][0], iqk_info->gs_retry_count[0][RF_PATH_D][1]);
		for (i = 0; i < SS_8198F; i++) {
			odm_write_4byte(dm, 0x1b00, 0x8 | i << 1);
			odm_set_bb_reg(dm, R_0x1b20, BIT(26), 0x1);
//			odm_write_4byte(dm, 0x1b2c, 0x7);
			odm_write_1byte(dm, 0x1bcc, 0x0);
			odm_write_4byte(dm, 0x1b38, 0x20000000);
		}
	}
#endif

}

void _iqk_start_iqk_8198f(
	struct dm_struct *dm,
	boolean segment_iqk)
{
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	u8 i=0;
	u8 kcount_limit;
	
	if (*dm->band_width == 2)
		kcount_limit = kcount_limit_80m;
	else
		kcount_limit = kcount_limit_others;

	while (i <  100) {
		_iqk_iqk_by_path_8198f(dm, segment_iqk);
		if (iqk_info->iqk_step == IQK_STEP_8198F)
			break;
		if (segment_iqk && (iqk_info->kcount == kcount_limit))
			break;
	}
}

void _iq_calibrate_8198f_init(
	struct dm_struct *dm)
{
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	u8 i, j, k, m;
	static boolean firstrun = true;

	if (firstrun) {
		firstrun = false;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]=====>PHY_IQCalibrate_8198F_Init\n");

		for (i = 0; i < SS_8198F; i++) {
			for (j = 0; j < 2; j++) {
				iqk_info->lok_fail[i] = true;
				iqk_info->iqk_fail[j][i] = true;
				iqk_info->iqc_matrix[j][i] = 0x20000000;
			}
		}

		for (i = 0; i < 2; i++) {
			iqk_info->iqk_channel[i] = 0x0;

			for (j = 0; j < SS_8198F; j++) {
				iqk_info->lok_idac[i][j] = 0x0;
				iqk_info->rxiqk_agc[i][j] = 0x0;
				iqk_info->bypass_iqk[i][j] = 0x0;

				for (k = 0; k < 2; k++) {
					iqk_info->iqk_fail_report[i][j][k] = true;
					for (m = 0; m < 8; m++) {
						iqk_info->iqk_cfir_real[i][j][k][m] = 0x0;
						iqk_info->iqk_cfir_imag[i][j][k][m] = 0x0;
					}
				}

				for (k = 0; k < 3; k++)
					iqk_info->retry_count[i][j][k] = 0x0;
			}
		}
	}
}

boolean
_iqk_rximr_rxk1_test_8198f(
	struct dm_struct *dm,
	u8 path,
	u32 tone_index)
{
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	boolean fail = true;
	u32 IQK_CMD;

	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
	odm_write_4byte(dm, 0x1b20, (odm_read_4byte(dm, 0x1b20) & 0x000fffff) | ((tone_index & 0xfff) << 20));
	odm_write_4byte(dm, 0x1b24, (odm_read_4byte(dm, 0x1b24) & 0x000fffff) | ((tone_index & 0xfff) << 20));

	IQK_CMD = 0xf8000208 | (1 << (path + 4));
	odm_write_4byte(dm, 0x1b00, IQK_CMD);
	odm_write_4byte(dm, 0x1b00, IQK_CMD + 0x1);

	ODM_delay_ms(IQK_DELAY_8198F);
	fail = _iqk_check_cal_8198f(dm, path, 0x1);
	return fail;
}

u32 _iqk_tximr_selfcheck_8198f(
	void *dm_void,
	u8 tone_index,
	u8 path)
{
	u32 tx_ini_power_H[2], tx_ini_power_L[2];
	u32 tmp1, tmp2, tmp3, tmp4, tmp5;
	u32 IQK_CMD;
	u32 tximr = 0x0;
	u8 i;

	struct dm_struct *dm = (struct dm_struct *)dm_void;
	/*backup*/
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
	odm_write_4byte(dm, 0x1bc8, 0x80000000);
	odm_write_4byte(dm, 0x8f8, 0x41400080);
	tmp1 = odm_read_4byte(dm, 0x1b0c);
	tmp2 = odm_read_4byte(dm, 0x1b14);
	tmp3 = odm_read_4byte(dm, 0x1b1c);
	tmp4 = odm_read_4byte(dm, 0x1b20);
	tmp5 = odm_read_4byte(dm, 0x1b24);
	/*setup*/
	odm_write_4byte(dm, 0x1b0c, 0x00003000);
	odm_write_4byte(dm, 0x1b1c, 0xA2193C32);
	odm_write_1byte(dm, 0x1b15, 0x00);
	odm_write_4byte(dm, 0x1b20, (u32)(tone_index << 20 | 0x00040008));
	odm_write_4byte(dm, 0x1b24, (u32)(tone_index << 20 | 0x00060008));
	odm_write_4byte(dm, 0x1b2c, 0x07);
	odm_write_4byte(dm, 0x1b38, 0x20000000);
	odm_write_4byte(dm, 0x1b3c, 0x20000000);
	/* ======derive pwr1========*/
	for (i = 0; i < SS_8198F; i++) {
		odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
		if (i == 0)
			odm_write_1byte(dm, 0x1bcc, 0x0f);
		else
			odm_write_1byte(dm, 0x1bcc, 0x09);
		/* One Shot*/
		IQK_CMD = 0x00000800;
		odm_write_4byte(dm, 0x1b34, IQK_CMD + 1);
		odm_write_4byte(dm, 0x1b34, IQK_CMD);
		ODM_delay_ms(1);
		odm_write_4byte(dm, 0x1bd4, 0x00040001);
		tx_ini_power_H[i] = odm_read_4byte(dm, 0x1bfc);
		odm_write_4byte(dm, 0x1bd4, 0x000C0001);
		tx_ini_power_L[i] = odm_read_4byte(dm, 0x1bfc);
	}
	/*restore*/
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
	odm_write_4byte(dm, 0x1b0c, tmp1);
	odm_write_4byte(dm, 0x1b14, tmp2);
	odm_write_4byte(dm, 0x1b1c, tmp3);
	odm_write_4byte(dm, 0x1b20, tmp4);
	odm_write_4byte(dm, 0x1b24, tmp5);

	if (tx_ini_power_H[1] == tx_ini_power_H[0])
		tximr = (3 * (halrf_psd_log2base(tx_ini_power_L[0] << 2) - halrf_psd_log2base(tx_ini_power_L[1]))) / 100;
	else
		tximr = 0;
	return tximr;
}

void _iqk_start_tximr_test_8198f(
	struct dm_struct *dm,
	u8 imr_limit)
{
	boolean KFAIL;
	u8 path, i, tone_index;
	u32 imr_result;

	for (path = 0; path < SS_8198F; path++) {
		_iqk_txk_setting_8198f(dm, path);
		KFAIL = _iqk_one_shot_8198f(dm, path, TXIQK);
		for (i = 0x0; i < imr_limit; i++) {
			tone_index = (u8)(0x08 | i << 4);
			imr_result = _iqk_tximr_selfcheck_8198f(dm, tone_index, path);
			RF_DBG(dm, DBG_RF_IQK, "[IQK]path=%x, toneindex = %x, TXIMR = %d\n", path, tone_index, imr_result);
		}
		RF_DBG(dm, DBG_RF_IQK, "\n");
	}
}

u32 _iqk_rximr_selfcheck_8198f(
	void *dm_void,
	u32 tone_index,
	u8 path,
	u32 tmp1b38)
{
	u32 rx_ini_power_H[2], rx_ini_power_L[2]; /*[0]: psd tone; [1]: image tone*/
	u32 tmp1, tmp2, tmp3, tmp4, tmp5;
	u32 IQK_CMD, tmp1bcc;
	u8 i, num_k1, rximr_step, count = 0x0;
	u32 rximr = 0x0;
	boolean KFAIL = true;

	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;

	/*backup*/
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
	tmp1 = odm_read_4byte(dm, 0x1b0c);
	tmp2 = odm_read_4byte(dm, 0x1b14);
	tmp3 = odm_read_4byte(dm, 0x1b1c);
	tmp4 = odm_read_4byte(dm, 0x1b20);
	tmp5 = odm_read_4byte(dm, 0x1b24);

	odm_write_4byte(dm, 0x1b0c, 0x00001000);
	odm_write_1byte(dm, 0x1b15, 0x00);
	odm_write_4byte(dm, 0x1b1c, 0x82193d31);
	odm_write_4byte(dm, 0x1b20, (u32)(tone_index << 20 | 0x00040008));
	odm_write_4byte(dm, 0x1b24, (u32)(tone_index << 20 | 0x00060048));
	odm_write_4byte(dm, 0x1b2c, 0x07);
	odm_write_4byte(dm, 0x1b38, tmp1b38);
	odm_write_4byte(dm, 0x1b3c, 0x20000000);

	for (i = 0; i < 2; i++) {
		if (i == 0)
			odm_write_4byte(dm, 0x1b1c, 0x82193d31);
		else
			odm_write_4byte(dm, 0x1b1c, 0xa2193d31);
		IQK_CMD = 0x00000800;
		odm_write_4byte(dm, 0x1b34, IQK_CMD + 1);
		odm_write_4byte(dm, 0x1b34, IQK_CMD);
		ODM_delay_ms(2);
		odm_write_1byte(dm, 0x1bd6, 0xb);
		while (count < 100) {
			count++;
			if (odm_get_bb_reg(dm, R_0x1bfc, BIT(1)) == 1)
				break;
			else
				ODM_delay_ms(1);
		}
		if (1) {
			odm_write_1byte(dm, 0x1bd6, 0x5);
			rx_ini_power_H[i] = odm_read_4byte(dm, 0x1bfc);
			odm_write_1byte(dm, 0x1bd6, 0xe);
			rx_ini_power_L[i] = odm_read_4byte(dm, 0x1bfc);
		} else {
			rx_ini_power_H[i] = 0x0;
			rx_ini_power_L[i] = 0x0;
		}
	}
	/*restore*/
	odm_write_4byte(dm, 0x1b0c, tmp1);
	odm_write_4byte(dm, 0x1b14, tmp2);
	odm_write_4byte(dm, 0x1b1c, tmp3);
	odm_write_4byte(dm, 0x1b20, tmp4);
	odm_write_4byte(dm, 0x1b24, tmp5);
	for (i = 0; i < 2; i++)
		rx_ini_power_H[i] = (rx_ini_power_H[i] & 0xf8000000) >> 27;

	if (rx_ini_power_H[0] != rx_ini_power_H[1])
		switch (rx_ini_power_H[0]) {
		case 1:
			rx_ini_power_L[0] = (u32)((rx_ini_power_L[0] >> 1) | 0x80000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 1;
			break;
		case 2:
			rx_ini_power_L[0] = (u32)((rx_ini_power_L[0] >> 2) | 0x80000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 2;
			break;
		case 3:
			rx_ini_power_L[0] = (u32)((rx_ini_power_L[0] >> 2) | 0xc0000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 2;
			break;
		case 4:
			rx_ini_power_L[0] = (u32)((rx_ini_power_L[0] >> 3) | 0x80000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 3;
			break;
		case 5:
			rx_ini_power_L[0] = (u32)((rx_ini_power_L[0] >> 3) | 0xa0000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 3;
			break;
		case 6:
			rx_ini_power_L[0] = (u32)((rx_ini_power_L[0] >> 3) | 0xc0000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 3;
			break;
		case 7:
			rx_ini_power_L[0] = (u32)((rx_ini_power_L[0] >> 3) | 0xe0000000);
			rx_ini_power_L[1] = (u32)rx_ini_power_L[1] >> 3;
			break;
		default:
			break;
		}
	rximr = (u32)(3 * ((halrf_psd_log2base(rx_ini_power_L[0] / 100) - halrf_psd_log2base(rx_ini_power_L[1] / 100))) / 100);
	/*
		RF_DBG(dm, DBG_RF_IQK, "%-20s: 0x%x, 0x%x, 0x%x, 0x%x,0x%x, tone_index=%x, rximr= %d\n",
		(path == 0) ? "PATH A RXIMR ": "PATH B RXIMR",
		rx_ini_power_H[0], rx_ini_power_L[0], rx_ini_power_H[1], rx_ini_power_L[1], tmp1bcc, tone_index, rximr);
*/
	return rximr;
}

void _iqk_rximr_test_8198f(
	struct dm_struct *dm,
	u8 path,
	u8 imr_limit)
{
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	boolean kfail;
	u8 i, step, count, side;
	u32 imr_result = 0, tone_index;
	u32 temp = 0, temp1b38[2][15];
	char *freq[15] = {"1.25MHz", "3.75MHz", "6.25MHz", "8.75MHz", "11.25MHz",
			  "13.75MHz", "16.25MHz", "18.75MHz", "21.25MHz", "23.75MHz",
			  "26.25MHz", "28.75MHz", "31.25MHz", "33.75MHz", "36.25MHz"};

	for (step = 1; step < 5; step++) {
		count = 0;
		switch (step) {
		case 1: /*gain search_RXK1*/
			_iqk_rxk1_setting_8198f(dm, path);
			while (count < 3) {
				kfail = _iqk_rx_iqk_gain_search_fail_8198f(dm, path, RXIQK1);
				RF_DBG(dm, DBG_RF_IQK, "[IQK]path = %x, kfail = %x\n", path, kfail);
				if (kfail) {
					count++;
					if (count == 3)
						step = 5;
				} else {
					break;
				}
			}
			break;
		case 2: /*gain search_RXK2*/
			_iqk_rxk2_setting_8198f(dm, path, true);
			iqk_info->isbnd = false;
			while (count < 8) {
				kfail = _iqk_rx_iqk_gain_search_fail_8198f(dm, path, RXIQK2);
				RF_DBG(dm, DBG_RF_IQK, "[IQK]path = %x, kfail = %x\n", path, kfail);
				if (kfail) {
					count++;
					if (count == 8)
						step = 5;
				} else {
					break;
				}
			}
			break;
		case 3: /*get RXK1 IQC*/
			odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
			temp = odm_read_4byte(dm, 0x1b1c);
			for (side = 0; side < 2; side++) {
				for (i = 0; i < imr_limit; i++) {
					if (side == 0)
						tone_index = 0xff8 - (i << 4);
					else
						tone_index = 0x08 | (i << 4);
					while (count < 3) {
						_iqk_rxk1_setting_8198f(dm, path);
						kfail = _iqk_rximr_rxk1_test_8198f(dm, path, tone_index);
						RF_DBG(dm, DBG_RF_IQK, "[IQK]path = %x, kfail = %x\n", path, kfail);
						if (kfail) {
							count++;
							if (count == 3) {
								step = 5;
								temp1b38[side][i] = 0x20000000;
								RF_DBG(dm, DBG_RF_IQK, "[IQK]path = %x, toneindex = %x rxk1 fail\n", path, tone_index);
							}
						} else {
							odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
							odm_write_4byte(dm, 0x1b1c, 0xa2193c32);
							odm_write_4byte(dm, 0x1b14, 0xe5);
							odm_write_4byte(dm, 0x1b14, 0x0);
							temp1b38[side][i] = odm_read_4byte(dm, 0x1b38);
							RF_DBG(dm, DBG_RF_IQK, "[IQK]path = 0x%x, tone_idx = 0x%x, tmp1b38 = 0x%x\n", path, tone_index, temp1b38[side][i]);
							break;
						}
					}
				}
			}
			break;
		case 4: /*get RX IMR*/
			for (side = 0; side < 2; side++) {
				for (i = 0x0; i < imr_limit; i++) {
					if (side == 0)
						tone_index = 0xff8 - (i << 4);
					else
						tone_index = 0x08 | (i << 4);
					_iqk_rxk2_setting_8198f(dm, path, false);
					imr_result = _iqk_rximr_selfcheck_8198f(dm, tone_index, path, temp1b38[side][i]);
					RF_DBG(dm, DBG_RF_IQK, "[IQK]tone_idx = 0x%5x, freq = %s%10s, RXIMR = %5d dB\n", tone_index, (side == 0) ? "-" : " ", freq[i], imr_result);
				}
				odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
				odm_write_4byte(dm, 0x1b1c, temp);
				odm_write_4byte(dm, 0x1b38, 0x20000000);
			}
			break;
		}
	}
}

void _iqk_start_rximr_test_8198f(
	struct dm_struct *dm,
	u8 imr_limit)
{
	u8 path;

	for (path = 0; path < SS_8198F; path++)
		_iqk_rximr_test_8198f(dm, path, imr_limit);
}

void _iqk_start_imr_test_8198f(
	void *dm_void)
{
	u8 imr_limit;

	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;

	if (*dm->band_width == 2)
		imr_limit = 0xf;
	else if (*dm->band_width == 1)
		imr_limit = 0x8;
	else
		imr_limit = 0x4;
	//	_iqk_start_tximr_test_8198f(dm, imr_limit);
	_iqk_start_rximr_test_8198f(dm, imr_limit);
}

void _phy_iq_calibrate_8198f(
	struct dm_struct *dm,
	boolean reset,
	boolean segment_iqk)
{
	u32 MAC_backup[MAC_REG_NUM_8198F], BB_backup[BB_REG_NUM_8198F], RF_backup[RF_REG_NUM_8198F][SS_8198F];
	u32 backup_mac_reg[MAC_REG_NUM_8198F] = {0x520, 0x550};
	u32 backup_bb_reg[BB_REG_NUM_8198F] = {0x820, 0x824, 0x1c38, 0x1c68, 0x1d60, 0x180c, 0x410c, 0x520c, 0x530c, 0x1c3c,
						0x183c, 0x1840, 0x1844, 0x413c, 0x4140, 0x4144, 0x523c, 0x5240, 0x5244,
						0x533c, 0x5340, 0x5344};
	u32 backup_rf_reg[RF_REG_NUM_8198F] = {0xdf, 0x0};
	boolean is_mp = false;
	u8 i = 0;

	struct dm_iqk_info *iqk_info = &dm->IQK_info;

	if (*dm->mp_mode)
		is_mp = true;

//	if (!is_mp)
//		if (_iqk_reload_iqk_8198f(dm, reset))
//			return;

	RF_DBG(dm, DBG_RF_IQK, "[IQK]==========IQK strat!!!!!==========\n");

	RF_DBG(dm, DBG_RF_IQK, "[IQK]band_type = %s, band_width = %d, ExtPA2G = %d, ext_pa_5g = %d\n", (*dm->band_type == ODM_BAND_5G) ? "5G" : "2G", *dm->band_width, dm->ext_pa, dm->ext_pa_5g);

	iqk_info->kcount = 0;
	iqk_info->iqk_step = 0;
	iqk_info->rxiqk_step = 1;

	_iqk_backup_iqk_8198f(dm, 0x0, 0x0);
	_iqk_backup_mac_bb_8198f(dm, MAC_backup, BB_backup, backup_mac_reg, backup_bb_reg);
	_iqk_backup_rf_8198f(dm, RF_backup, backup_rf_reg);
#if 0
	_iqk_configure_macbb_8198f(dm);
	_iqk_afe_setting_8198f(dm, true);
	_iqk_rfe_setting_8198f(dm, false);
	_iqk_agc_bnd_int_8198f(dm);
	_iqk_rf_setting_8198f(dm);
#endif

	while (i < 20) {
		i++;
		_iqk_macbb_8198f(dm);
		_iqk_afe_setting_8198f(dm, true);
		_iqk_rfe_setting_8198f(dm);
//		_iqk_agc_bnd_int_8198f(dm);
		_iqk_con_tx_8198f(dm, true);
		_iqk_start_iqk_8198f(dm, segment_iqk);
		_iqk_con_tx_8198f(dm,false);
		_iqk_afe_setting_8198f(dm, false);
		_iqk_restore_mac_bb_8198f(dm, MAC_backup, BB_backup, backup_mac_reg, backup_bb_reg);
		_iqk_restore_rf_8198f(dm, backup_rf_reg, RF_backup);
		if (iqk_info->iqk_step == IQK_STEP_8198F)
			break;
		iqk_info->kcount = 0;
		RF_DBG(dm, DBG_RF_IQK, "[IQK]delay 50ms!!!\n");
		ODM_delay_ms(50);
	};
//	if (segment_iqk)
//		_iqk_reload_iqk_setting_8198f(dm, 0x0, 0x1);

	_iqk_fill_iqk_report_8198f(dm, 0);
//	_iqk_rf0xb0_workaround_8198f(dm);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]==========IQK end!!!!!==========\n");
}

void _phy_iq_calibrate_by_fw_8198f(
	void *dm_void,
	u8 clear,
	u8 segment_iqk)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	enum hal_status status = HAL_STATUS_FAILURE;

	if (*dm->mp_mode)
		clear = 0x1;
	//	else if (dm->is_linked)
	//		segment_iqk = 0x1;

	iqk_info->iqk_times++;
	status = odm_iq_calibrate_by_fw(dm, clear, segment_iqk);

	if (status == HAL_STATUS_SUCCESS)
		RF_DBG(dm, DBG_RF_IQK, "[IQK]FWIQK OK!!!\n");
	else
		RF_DBG(dm, DBG_RF_IQK, "[IQK]FWIQK fail!!!\n");
}

/*IQK_version:0x9, NCTL:0x5*/
/*1.HW conTX issue: 0x1e70[2]=0 after IQK*/
void phy_iq_calibrate_8198f(
	void *dm_void,
	boolean clear,
	boolean segment_iqk)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct _hal_rf_ *rf = &dm->rf_table;

	if (*dm->mp_mode)
		halrf_iqk_hwtx_check(dm, true);
	/*FW IQK*/
	if (dm->fw_offload_ability & PHYDM_RF_IQK_OFFLOAD) {
		_phy_iq_calibrate_by_fw_8198f(dm, clear, (u8)(segment_iqk));
		phydm_get_read_counter_8198f(dm);
		_iqk_check_if_reload(dm);
	} else {
		_iq_calibrate_8198f_init(dm);
		_phy_iq_calibrate_8198f(dm, clear, segment_iqk);
	}
	_iqk_fail_count_8198f(dm);
	if (*dm->mp_mode)
		halrf_iqk_hwtx_check(dm, false);
#if (DM_ODM_SUPPORT_TYPE & ODM_AP)
	_iqk_iqk_fail_report_8198f(dm);
#endif
	halrf_iqk_dbg(dm);
}

void _phy_imr_measure_8198f(
	struct dm_struct *dm)
{
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	u32 MAC_backup[MAC_REG_NUM_8198F], BB_backup[BB_REG_NUM_8198F], RF_backup[RF_REG_NUM_8198F][SS_8198F];
	u32 backup_mac_reg[MAC_REG_NUM_8198F] = {0x520, 0x550};
	u32 backup_bb_reg[BB_REG_NUM_8198F] = {0x808, 0x90c, 0xc00, 0xcb0, 0xcb4, 0xcbc, 0xe00, 0xeb0, 0xeb4, 0xebc, 0x1990, 0x9a4, 0xa04, 0xb00};
	u32 backup_rf_reg[RF_REG_NUM_8198F] = {0xdf, 0x0};

	_iqk_backup_iqk_8198f(dm, 0x0, 0x0);
	_iqk_backup_mac_bb_8198f(dm, MAC_backup, BB_backup, backup_mac_reg, backup_bb_reg);
	_iqk_backup_rf_8198f(dm, RF_backup, backup_rf_reg);
	_iqk_macbb_8198f(dm);
	_iqk_afe_setting_8198f(dm, true);
	_iqk_rfe_setting_8198f(dm);
//	_iqk_agc_bnd_int_8198f(dm);
//	_iqk_rf_setting_8198f(dm);

	_iqk_start_imr_test_8198f(dm);

	_iqk_afe_setting_8198f(dm, false);
	_iqk_restore_mac_bb_8198f(dm, MAC_backup, BB_backup, backup_mac_reg, backup_bb_reg);
	_iqk_restore_rf_8198f(dm, backup_rf_reg, RF_backup);
}

void do_imr_test_8198f(
	void *dm_void)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;

	RF_DBG(dm, DBG_RF_IQK, "[IQK]  ************IMR Test *****************\n");
	_phy_imr_measure_8198f(dm);
	RF_DBG(dm, DBG_RF_IQK, "[IQK]  **********End IMR Test *******************\n");
}
#endif
