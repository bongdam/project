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
#if (DM_ODM_SUPPORT_TYPE == ODM_WIN)
#if RT_PLATFORM == PLATFORM_MACOSX
#include "phydm_precomp.h"
#else
#include "../phydm_precomp.h"
#endif
#else
#include "../../phydm_precomp.h"
#endif

#if (RTL8195B_SUPPORT == 1)
/*---------------------------Define Local Constant---------------------------*/


/*---------------------------Define Local Constant---------------------------*/
void do_txgapk_8195b(
	void *dm_void,
	u8 delta_thermal_index,
	u8 thermal_value,
	u8 threshold)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	/*boolean		is_recovery = (boolean) delta_thermal_index;*/
	phy_txgap_calibrate_8195b(dm, true);
}

void _txgapk_bp_rf_gain_table_8195b(struct dm_struct *dm)
{
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_txgapk_info *txgapk_info = &(rf->halrf_txgapk_info);
	u8 idx = 0x0, rf_path = 0x0, band = 0x0;
	u8 rf0_idx_current = 0x0;
	u8 ch_num[5] = {0x0, 0x0, 0x1, 0x3, 0x5};
	u32 rf18 = 0x0;
	u8 end = 0x8;
	
	RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] backup rf gain table\n");
	odm_write_4byte(dm, 0x1b00, 0x8 | rf_path << 1);
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
	rf18 = odm_get_rf_reg(dm, RF_PATH_A, 0x18, 0xfffff);
	for(band = 0; band < 5; band++) {
		odm_set_rf_reg(dm, rf_path, 0x18, 0x70000, ch_num[band]);
		if (band == 0) {
			odm_set_rf_reg(dm, RF_PATH_A, 0x1a, 0x00001, 0x1);// is cck
			odm_set_rf_reg(dm, RF_PATH_A, 0x1a, 0x10000, 0x1);// is cck
		} else {
			odm_set_rf_reg(dm, RF_PATH_A, 0x1a, 0x00001, 0x0);
			odm_set_rf_reg(dm, RF_PATH_A, 0x1a, 0x10000, 0x0);
		}
		RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] RF 0x18 = %x\n",odm_get_rf_reg(dm, rf_path, 0x18, 0xfffff));
		RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] RF 0x1a = %x\n",odm_get_rf_reg(dm, rf_path, 0x1a, 0xfffff));
		/*get 0x56 gain table*/
		odm_set_rf_reg(dm, rf_path, 0xde, BIT(16), 0x0);
		for (idx = 1; idx <= end; idx++) {
			/*current_fr0x_56*/
			rf0_idx_current = 3 * (idx - 1) + 1;
			odm_set_rf_reg(dm, rf_path, 0x0, 0x1f, rf0_idx_current);
			ODM_delay_us(10);
			txgapk_info->txgapk_rf3f_bp[band][idx][rf_path] = odm_get_rf_reg(dm, rf_path, 0x56, 0x1fff);
			RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] backup rf%x, band=%x, idx=0x%x, rf3f =0x%x\n",
			       rf_path, band, rf0_idx_current, txgapk_info->txgapk_rf3f_bp[band][idx][rf_path]);
		}
		RF_DBG(dm, DBG_RF_TXGAPK, "\n");
		odm_set_rf_reg(dm, RF_PATH_A, 0xde, BIT(16), 0x1);
	}
	odm_set_rf_reg(dm, RF_PATH_A, 0x18, 0xfffff, rf18);
	txgapk_info->txgapk_bp_done = true;
	return;
}

void _txgapk_reload_rf_gain_table_8195b(struct dm_struct *dm, boolean is_cck, u8 rf_path)
{

	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_txgapk_info *txgapk_info = &(rf->halrf_txgapk_info);
	u8 idx = 0x0, band = 0x0;
	u32 tmp, tmp2;
	u8 end = 0x8;

	odm_write_4byte(dm, 0x1b00, 0x8 | rf_path << 1);
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
	odm_set_rf_reg(dm, rf_path, 0xee, BIT(16), 0x1);

	RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] reload rf gain table\n");
	RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] RF 0x18 = %x\n", odm_get_rf_reg(dm, rf_path, 0x18, 0xfffff));
	for (idx = 0x1; idx <= end; idx++) {
		switch (*dm->band_type) {
		case ODM_BAND_2_4G:
			if (is_cck) {
				tmp = 0x20 | (idx - 1);
				band = 0;
			} else {
				tmp = (idx - 1);
				band = 1;
			}
			break;
		case ODM_BAND_5G:
			if (*dm->channel > 144) {
				tmp = 0x300 | (idx - 1);
				band = 4;
			} else if (*dm->channel > 64) {
				tmp = 0x280 | (idx - 1);
				band = 3;
			} else {
				tmp = 0x200 | (idx - 1);
				band = 2;
			}
			break;
		}
		tmp2 = txgapk_info->txgapk_rf3f_bp[band][idx][rf_path];
		odm_set_rf_reg(dm, rf_path, 0x33, 0xfffff, tmp);
		odm_set_rf_reg(dm, rf_path, 0x3f, 0x01fff, tmp2);
#if 1
		RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] idx= %x, 33= 0x%x, 3f= 0x%x\n",
		       idx, tmp, tmp2);
#endif
	}
	RF_DBG(dm, DBG_RF_TXGAPK, "\n");
	odm_set_rf_reg(dm, rf_path, 0xee, BIT(16), 0x0);
}

void _txgapk_backup_mac_bb_8195b(
	struct dm_struct *dm,
	u32 *MAC_backup,
	u32 *BB_backup,
	u32 *backup_mac_reg,
	u32 *backup_bb_reg)
{
	u32 i;

	for (i = 0; i < GAPK_MAC_REG_NUM_8195B; i++)
		MAC_backup[i] = odm_read_4byte(dm, backup_mac_reg[i]);

	for (i = 0; i < GAPK_BB_REG_NUM_8195B; i++)
		BB_backup[i] = odm_read_4byte(dm, backup_bb_reg[i]);
}

void _txgapk_backup_rf_8195b(
	struct dm_struct *dm,
	u32 RF_backup[][SS_8195B],
	u32 *backup_rf_reg)
{
	u32 i;
	u8 j;

	for (i = 0; i < GAPK_RF_REG_NUM_8195B; i++)
		for (j = 0; j < SS_8195B; j++) {
			RF_backup[i][j] = odm_get_rf_reg(dm, j,
							 backup_rf_reg[i],
							 RFREGOFFSETMASK);
		}
}
void _txgapk_restore_mac_bb_8195b(
	struct dm_struct *dm,
	u32 *MAC_backup,
	u32 *BB_backup,
	u32 *backup_mac_reg,
	u32 *backup_bb_reg)
{
	u32 i;

	for (i = 0; i < GAPK_MAC_REG_NUM_8195B; i++)
		odm_write_4byte(dm, backup_mac_reg[i], MAC_backup[i]);
	for (i = 0; i < GAPK_BB_REG_NUM_8195B; i++)
		odm_write_4byte(dm, backup_bb_reg[i], BB_backup[i]);
}

void _txgapk_restore_rf_8195b(
	struct dm_struct *dm,
	u32 *backup_rf_reg,
	u32 RF_backup[][SS_8195B])
{
	u32 i;

	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
	//odm_set_rf_reg(dm, RF_PATH_A, 0xef, RFREGOFFSETMASK, 0x0);
	//odm_set_rf_reg(dm, RF_PATH_A, 0xee, RFREGOFFSETMASK, 0x0);
	//odm_set_rf_reg(dm, RF_PATH_A, 0xde, RFREGOFFSETMASK, 0x0);
	for (i = 0; i < GAPK_RF_REG_NUM_8195B ; i++) {
		odm_set_rf_reg(dm, RF_PATH_A, backup_rf_reg[i], RFREGOFFSETMASK,
			       RF_backup[i][RF_PATH_A]);
	}
}

void _txgapk_backup_8195b(
	struct dm_struct *dm,
	u32 *backup_txgap,
	u32 *backup_txgap_reg,
	u8 txgapk_reg_num)
{
	u32 i;

	for (i = 0; i < txgapk_reg_num; i++)
		backup_txgap[i] = odm_read_4byte(dm, backup_txgap_reg[i]);
}

void _txgapk_restore_8195b(
	struct dm_struct *dm,
	u32 *backup_txgap,
	u32 *backup_txgap_reg,
	u8 txgapk_reg_num)
{
	u32 i;

	for (i = 0; i < txgapk_reg_num; i++)
		odm_write_4byte(dm, backup_txgap_reg[i], backup_txgap[i]);
}

void _txgapk_afe_setting_8195b(
	struct dm_struct *dm,
	boolean do_txgapk)
{
	if (do_txgapk) {
	/*AFE setting*/
		odm_write_4byte(dm, 0x34,  0xC10AA254);
		odm_write_4byte(dm, 0xc58, 0xE4012C92);
		odm_write_4byte(dm, 0xc5c, 0xF05E0002);
		odm_write_4byte(dm, 0xc6c, 0x00000003);
		//odm_write_4byte(dm, 0xc6c, 0x0000122b);
		//odm_write_4byte(dm, 0xc60, 0x70000000);
		//odm_write_4byte(dm, 0xc60, 0x700F005A);
#if 0
		odm_write_4byte(dm, 0xc60, 0x70000000);
		odm_write_4byte(dm, 0xc60, 0x700F0040);
		odm_write_4byte(dm, 0xc60, 0x70180040);
		odm_write_4byte(dm, 0xc60, 0x70280040);
		odm_write_4byte(dm, 0xc60, 0x70380040);
		odm_write_4byte(dm, 0xc60, 0x70480040);
		odm_write_4byte(dm, 0xc60, 0x70580040);
		odm_write_4byte(dm, 0xc60, 0x70680040);
		odm_write_4byte(dm, 0xc60, 0x70780040);
		odm_write_4byte(dm, 0xc60, 0x70880040);
		odm_write_4byte(dm, 0xc60, 0x70980040);
		odm_write_4byte(dm, 0xc60, 0x70a80040);
		odm_write_4byte(dm, 0xc60, 0x70b80040);
		odm_write_4byte(dm, 0xc60, 0x70c80040);
		odm_write_4byte(dm, 0xc60, 0x70d80040);
		odm_write_4byte(dm, 0xc60, 0x70e80040);
		odm_write_4byte(dm, 0xc60, 0x70f80040);
#else
		odm_write_4byte(dm, 0xC60, 0x70000000);
		odm_write_4byte(dm, 0xC60, 0x700F0040);
		odm_write_4byte(dm, 0xC60, 0x70180040);
		odm_write_4byte(dm, 0xC60, 0x70280040);
		odm_write_4byte(dm, 0xC60, 0x70380040);
		odm_write_4byte(dm, 0xC60, 0x70480040);
		odm_write_4byte(dm, 0xC60, 0x70570040);
		odm_write_4byte(dm, 0xC60, 0x70680040);
		odm_write_4byte(dm, 0xC60, 0x70770040);
		odm_write_4byte(dm, 0xC60, 0x70870040);
		odm_write_4byte(dm, 0xC60, 0x70970040);
		odm_write_4byte(dm, 0xC60, 0x70A70040);
		odm_write_4byte(dm, 0xC60, 0x70B70040);
		odm_write_4byte(dm, 0xC60, 0x70C00040);
		odm_write_4byte(dm, 0xC60, 0x70D00040);
		odm_write_4byte(dm, 0xC60, 0x70EF0040);
		odm_write_4byte(dm, 0xC60, 0x70F00040);
#endif
		odm_write_4byte(dm, 0x808, 0x2D028200);
		odm_write_4byte(dm, 0x810, 0x20101063);
		odm_write_4byte(dm, 0x90c, 0x0B00C000);
		odm_write_4byte(dm, 0x9a4, 0x00000080);
		odm_write_4byte(dm, 0xc94, 0x0100010D);
		odm_write_4byte(dm, 0xe94, 0x0100015D);
		odm_write_4byte(dm, 0x1904, 0x00020000);
		odm_set_bb_reg(dm, 0xc00, BIT(1) | BIT(0), 0x0);
	} else {
		RF_DBG(dm, DBG_RF_TXGAPK,
		       "[TGGC]AFE setting for Normal mode!!!!\n");
		odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
		odm_set_rf_reg(dm, RF_PATH_A, 0xde, BIT(16), 0x0);
		odm_set_rf_reg(dm, RF_PATH_A, 0xee, BIT(18), 0x0);
		odm_set_rf_reg(dm, RF_PATH_A, 0x8f, BIT(14) | BIT(13), 0x0);
		odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x1);
		odm_set_bb_reg(dm, 0x1b0c, BIT(13) | BIT(12), 0x0);
		odm_set_bb_reg(dm, 0x1bcc, 0x3f, 0x0);
		odm_write_4byte(dm, 0xc58, 0xE4012E92);
		odm_write_4byte(dm, 0xc5c, 0xF05E0002);
		odm_write_4byte(dm, 0xc6c, 0x0000122B);
		odm_write_4byte(dm, 0x034, 0xC10AA254);
		odm_write_4byte(dm, 0x808, 0x34028211);
		odm_write_4byte(dm, 0x810, 0x21104285);
		odm_write_4byte(dm, 0x90c, 0x13000400);
		odm_write_4byte(dm, 0x9a4, 0x80000088);
		odm_write_4byte(dm, 0xc94, 0x01000501);
		odm_write_4byte(dm, 0xe94, 0x00000000);
		odm_write_4byte(dm, 0x1904, 0x00238000);
		odm_set_bb_reg(dm, 0xc00, BIT(1) | BIT(0), 0x3);

	}
}

u8 _txgapk_clear_extra0p5dB_8195b(struct dm_struct *dm,
				  u8 rf_path, boolean is_cck)
{
	u8 end;
	u32 rf0_idx_current, tmp, rf0x0_curr;
	u8 idx;
	u32 rf3f[11];

	RF_DBG(dm, DBG_RF_TXGAPK, "\n");
	RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC]===_clear 0.5dB setting!!!!!===\n");
	RF_DBG(dm, DBG_RF_TXGAPK, "\n");
	odm_set_bb_reg(dm, 0xc00, 0xff, 0x4); /*disable 3-wire*/
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);

	if(is_cck) {
		odm_set_rf_reg(dm, rf_path, 0x1a, BIT(0), 0x1);	
		odm_set_rf_reg(dm, rf_path, 0x1a, BIT(16), 0x1);
	} else {
		odm_set_rf_reg(dm, rf_path, 0x1a, BIT(0), 0x0);
		odm_set_rf_reg(dm, rf_path, 0x1a, BIT(16), 0x0);
	}
	// get 0x56 gain table
	for (idx = 1; idx <= 8; idx++) {
		odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
		odm_set_rf_reg(dm, RF_PATH_A, 0xde, BIT(16), 0x0);
		ODM_delay_ms(1);
		/*current_fr0x_56*/
		rf0_idx_current = 3 * (idx - 1) + 1;
		odm_set_rf_reg(dm, rf_path, 0x0, 0x1f, rf0_idx_current);
		//rf0x0_curr = odm_get_rf_reg(dm, rf_path, 0x0, 0xfffff);
		ODM_delay_ms(1);
		rf3f[idx] = odm_get_rf_reg(dm, rf_path, 0x5f, 0xfff);
		RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC](1) idx=%x, rf3f =%x\n",
		       idx, rf3f[idx]);
		if ((((rf3f[idx] & 0xe0) >> 5) == 0x7) &&
		    (((rf3f[idx] & 0xe00) >> 9) == 0x7)) {
			end = idx;
			break;
		}
	}

	RF_DBG(dm, DBG_RF_TXGAPK, "\n");
#if 0
	//restore gain table
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
	odm_set_rf_reg(dm, rf_path, 0xee, BIT(16), 0x1);

	for (idx = 1; idx <= 8; idx++) {
		switch (*dm->band_type) {
		case ODM_BAND_2_4G:
			if (!is_cck)
				tmp = idx - 1;
			else
				tmp = 0x20 | idx - 1;
			break;
		case ODM_BAND_5G:
			if (*dm->channel > 140)
				tmp = 0x180 | idx - 1;
			else if (*dm->channel > 64)
				tmp = 0x140 | idx - 1;
			else
				tmp = 0x100 | idx - 1;
		break;
		}
		odm_set_rf_reg(dm, rf_path, 0x33, 0xfffff, tmp);
		odm_set_rf_reg(dm, rf_path, 0x3f, 0x01fff,
			       rf3f[idx] & 0xfff);
		ODM_delay_ms(1);
		RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC](2) idx=%x, rf3f =%x\n",
		       idx, rf3f[idx]);
		if (((rf3f[idx] & 0xe0) >> 5) == 0x7) {
			end = idx;
			break;
		}
	}
#endif
	if (end > 8)
		end = 8;
	odm_set_rf_reg(dm, rf_path, 0xee, BIT(16), 0x0);
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x1);

	RF_DBG(dm, DBG_RF_TXGAPK, "\n");
	RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC](3) end = %x\n", end);

	return end;
}

u8 _txgapk_search_range_8195b(struct dm_struct *dm, u8 rf_path)
{
	u8 rf0_idx, end, start = 0x3;
	u32 rf0_idx_current, rf0x0_curr, tmp, tmp2;

	RF_DBG(dm, DBG_RF_TXGAPK, "\n");
	//find the start/end table
	for (rf0_idx = 1; rf0_idx <= 10; rf0_idx++) {
		odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
		odm_set_rf_reg(dm, RF_PATH_A, 0xde, BIT(16), 0x0);
		ODM_delay_ms(1);
		/*current_fr0x_56*/
		rf0_idx_current = 3 * (rf0_idx - 1) + 1;
		odm_set_rf_reg(dm, rf_path, 0x0, 0x1f, rf0_idx_current);
		ODM_delay_ms(1);
		rf0x0_curr = odm_get_rf_reg(dm, rf_path, 0x0, 0xfffff);
		ODM_delay_ms(1);
		tmp = odm_get_rf_reg(dm, rf_path, 0x56, 0xfff);
		tmp2  = odm_get_rf_reg(dm, rf_path, 0x5f, 0xfff);
		if (((tmp & 0xe0) >> 5) == 0x7) {
			end = rf0_idx;
			break;
		}
	RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC](3) idx=%x, 56 =%x\n", rf0_idx, tmp);
	}
	return end;
}

void _txgapk_init_8195b(
	struct dm_struct *dm)
{
RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC]=======_txgapk_init_8195b !!!!!=====\n");

/*TGGC INIT*/
	//odm_write_4byte(dm, 0xc94, 0x01000101);
	odm_write_4byte(dm, 0x1c44, 0xA34300F3);
	odm_write_4byte(dm, 0x1b00, 0x00000008);
	odm_write_4byte(dm, 0x1b00, 0x00A70008);
	odm_write_4byte(dm, 0x1b00, 0x00150008);
	odm_write_4byte(dm, 0x1b00, 0x00000008);
	odm_write_4byte(dm, 0x1b04, 0xE24629D2);
	odm_write_4byte(dm, 0x1b08, 0x00000080);
	odm_write_4byte(dm, 0x1b0c, 0x00000000);
	odm_write_4byte(dm, 0x1b10, 0x00010C00);
	odm_write_4byte(dm, 0x1b14, 0x00000000);
	odm_write_4byte(dm, 0x1b18, 0x00292903);
	odm_write_4byte(dm, 0x1b1c, 0xA2193C32);
	odm_write_4byte(dm, 0x1b20, 0x03040008);
	odm_write_4byte(dm, 0x1b24, 0x00060008);
	odm_write_4byte(dm, 0x1b28, 0x80060300);
	odm_write_4byte(dm, 0x1b2c, 0x00180018);
	odm_write_4byte(dm, 0x1b30, 0x20000000);
	odm_write_4byte(dm, 0x1b34, 0x00000800);
	odm_write_4byte(dm, 0x1b38, 0x20000000);
	odm_write_4byte(dm, 0x1b3c, 0x20000000);
	odm_write_4byte(dm, 0x1bc0, 0x01000000);
	//odm_write_4byte(dm, 0x1bcc, 0x00000000);
	/*DPK INIT*/
	//DPK phy setting
	odm_write_4byte(dm, 0x1b90, 0x0105f038);
	odm_write_4byte(dm, 0x1b94, 0xf76d9f84);
	odm_write_4byte(dm, 0x1bc8, 0x000c44aa);
	odm_write_4byte(dm, 0x1bcc, 0x11160200);
	// pwsf boundary
	odm_write_4byte(dm, 0x1bb8, 0x000fffff);
	// LUT SRAM block selection
	odm_write_4byte(dm, 0x1bbc, 0x00009DBF);
	// tx_amp
	odm_write_4byte(dm, 0x1b98, 0x41414141);
	odm_write_4byte(dm, 0x1b9c, 0x5b554f48);
	odm_write_4byte(dm, 0x1ba0, 0x6f6b6661);
	odm_write_4byte(dm, 0x1ba4, 0x817d7874);
	odm_write_4byte(dm, 0x1ba8, 0x908c8884);
	odm_write_4byte(dm, 0x1bac, 0x9d9a9793);
	odm_write_4byte(dm, 0x1bb0, 0xaaa7a4a1);
	odm_write_4byte(dm, 0x1bb4, 0xb6b3b0ad);
	// tx_inverse
	odm_write_4byte(dm, 0x1b40, 0x01fd01fd);
	odm_write_4byte(dm, 0x1b44, 0x01fd01fd);
	odm_write_4byte(dm, 0x1b48, 0x01a101c9);
	odm_write_4byte(dm, 0x1b4c, 0x016a0181);
	odm_write_4byte(dm, 0x1b50, 0x01430155);
	odm_write_4byte(dm, 0x1b54, 0x01270135);
	odm_write_4byte(dm, 0x1b58, 0x0112011c);
	odm_write_4byte(dm, 0x1b5c, 0x01000108);
	odm_write_4byte(dm, 0x1b60, 0x00f100f8);
	odm_write_4byte(dm, 0x1b64, 0x00e500eb);
	odm_write_4byte(dm, 0x1b68, 0x00db00e0);
	odm_write_4byte(dm, 0x1b6c, 0x00d100d5);
	odm_write_4byte(dm, 0x1b70, 0x00c900cd);
	odm_write_4byte(dm, 0x1b74, 0x00c200c5);
	odm_write_4byte(dm, 0x1b78, 0x00bb00be);
	odm_write_4byte(dm, 0x1b7c, 0x00b500b8);
	// write pwsf
	//S3
	odm_write_4byte(dm, 0x1bdc, 0x40caffe1);
	odm_write_4byte(dm, 0x1bdc, 0x4080a1e3);
	odm_write_4byte(dm, 0x1bdc, 0x405165e5);
	odm_write_4byte(dm, 0x1bdc, 0x403340e7);
	odm_write_4byte(dm, 0x1bdc, 0x402028e9);
	odm_write_4byte(dm, 0x1bdc, 0x401419eb);
	odm_write_4byte(dm, 0x1bdc, 0x400d10ed);
	odm_write_4byte(dm, 0x1bdc, 0x40080aef);

	odm_write_4byte(dm, 0x1bdc, 0x400506f1);
	odm_write_4byte(dm, 0x1bdc, 0x400304f3);
	odm_write_4byte(dm, 0x1bdc, 0x400203f5);
	odm_write_4byte(dm, 0x1bdc, 0x400102f7);
	odm_write_4byte(dm, 0x1bdc, 0x400101f9);
	odm_write_4byte(dm, 0x1bdc, 0x400101fb);
	odm_write_4byte(dm, 0x1bdc, 0x400101fd);
	odm_write_4byte(dm, 0x1bdc, 0x400101ff);
	//S0
	odm_write_4byte(dm, 0x1bdc, 0x40caff81);
	odm_write_4byte(dm, 0x1bdc, 0x4080a183);
	odm_write_4byte(dm, 0x1bdc, 0x40516585);
	odm_write_4byte(dm, 0x1bdc, 0x40334087);
	odm_write_4byte(dm, 0x1bdc, 0x40202889);
	odm_write_4byte(dm, 0x1bdc, 0x4014198b);
	odm_write_4byte(dm, 0x1bdc, 0x400d108d);
	odm_write_4byte(dm, 0x1bdc, 0x40080a8f);

	odm_write_4byte(dm, 0x1bdc, 0x40050691);
	odm_write_4byte(dm, 0x1bdc, 0x40030493);
	odm_write_4byte(dm, 0x1bdc, 0x40020395);
	odm_write_4byte(dm, 0x1bdc, 0x40010297);
	odm_write_4byte(dm, 0x1bdc, 0x40010199);
	odm_write_4byte(dm, 0x1bdc, 0x4001019b);
	odm_write_4byte(dm, 0x1bdc, 0x4001019d);
	odm_write_4byte(dm, 0x1bdc, 0x4001019f);
	odm_write_4byte(dm, 0x1bdc, 0x00000000);

	// clear even
	odm_write_4byte(dm, 0x1bdc, 0xd0000001);
	odm_write_4byte(dm, 0x1bdc, 0xd0000003);
	odm_write_4byte(dm, 0x1bdc, 0xd0000005);
	odm_write_4byte(dm, 0x1bdc, 0xd0000007);
	odm_write_4byte(dm, 0x1bdc, 0xd0000009);
	odm_write_4byte(dm, 0x1bdc, 0xd000000b);
	odm_write_4byte(dm, 0x1bdc, 0xd000000d);
	odm_write_4byte(dm, 0x1bdc, 0xd000000f);
	odm_write_4byte(dm, 0x1bdc, 0xd0000011);
	odm_write_4byte(dm, 0x1bdc, 0xd0000013);
	odm_write_4byte(dm, 0x1bdc, 0xd0000015);
	odm_write_4byte(dm, 0x1bdc, 0xd0000017);
	odm_write_4byte(dm, 0x1bdc, 0xd0000019);
	odm_write_4byte(dm, 0x1bdc, 0xd000001b);
	odm_write_4byte(dm, 0x1bdc, 0xd000001d);
	odm_write_4byte(dm, 0x1bdc, 0xd000001f);
	odm_write_4byte(dm, 0x1bdc, 0xd0000021);
	odm_write_4byte(dm, 0x1bdc, 0xd0000023);
	odm_write_4byte(dm, 0x1bdc, 0xd0000025);
	odm_write_4byte(dm, 0x1bdc, 0xd0000027);
	odm_write_4byte(dm, 0x1bdc, 0xd0000029);
	odm_write_4byte(dm, 0x1bdc, 0xd000002b);
	odm_write_4byte(dm, 0x1bdc, 0xd000002d);
	odm_write_4byte(dm, 0x1bdc, 0xd000002f);
	odm_write_4byte(dm, 0x1bdc, 0xd0000031);
	odm_write_4byte(dm, 0x1bdc, 0xd0000033);
	odm_write_4byte(dm, 0x1bdc, 0xd0000035);
	odm_write_4byte(dm, 0x1bdc, 0xd0000037);
	odm_write_4byte(dm, 0x1bdc, 0xd0000039);
	odm_write_4byte(dm, 0x1bdc, 0xd000003b);
	odm_write_4byte(dm, 0x1bdc, 0xd000003d);
	odm_write_4byte(dm, 0x1bdc, 0xd000003f);
	odm_write_4byte(dm, 0x1bdc, 0xd0000041);
	odm_write_4byte(dm, 0x1bdc, 0xd0000043);
	odm_write_4byte(dm, 0x1bdc, 0xd0000045);
	odm_write_4byte(dm, 0x1bdc, 0xd0000047);
	odm_write_4byte(dm, 0x1bdc, 0xd0000049);
	odm_write_4byte(dm, 0x1bdc, 0xd000004b);
	odm_write_4byte(dm, 0x1bdc, 0xd000004d);
	odm_write_4byte(dm, 0x1bdc, 0xd000004f);
	odm_write_4byte(dm, 0x1bdc, 0xd0000051);
	odm_write_4byte(dm, 0x1bdc, 0xd0000053);
	odm_write_4byte(dm, 0x1bdc, 0xd0000055);
	odm_write_4byte(dm, 0x1bdc, 0xd0000057);
	odm_write_4byte(dm, 0x1bdc, 0xd0000059);
	odm_write_4byte(dm, 0x1bdc, 0xd000005b);
	odm_write_4byte(dm, 0x1bdc, 0xd000005d);
	odm_write_4byte(dm, 0x1bdc, 0xd000005f);
	odm_write_4byte(dm, 0x1bdc, 0xd0000061);
	odm_write_4byte(dm, 0x1bdc, 0xd0000063);
	odm_write_4byte(dm, 0x1bdc, 0xd0000065);
	odm_write_4byte(dm, 0x1bdc, 0xd0000067);
	odm_write_4byte(dm, 0x1bdc, 0xd0000069);
	odm_write_4byte(dm, 0x1bdc, 0xd000006b);
	odm_write_4byte(dm, 0x1bdc, 0xd000006d);
	odm_write_4byte(dm, 0x1bdc, 0xd000006f);
	odm_write_4byte(dm, 0x1bdc, 0xd0000071);
	odm_write_4byte(dm, 0x1bdc, 0xd0000073);
	odm_write_4byte(dm, 0x1bdc, 0xd0000075);
	odm_write_4byte(dm, 0x1bdc, 0xd0000077);
	odm_write_4byte(dm, 0x1bdc, 0xd0000079);
	odm_write_4byte(dm, 0x1bdc, 0xd000007b);
	odm_write_4byte(dm, 0x1bdc, 0xd000007d);
	odm_write_4byte(dm, 0x1bdc, 0xd000007f);
	// clear odd
	odm_write_4byte(dm, 0x1bdc, 0x90000081);
	odm_write_4byte(dm, 0x1bdc, 0x90000083);
	odm_write_4byte(dm, 0x1bdc, 0x90000085);
	odm_write_4byte(dm, 0x1bdc, 0x90000087);
	odm_write_4byte(dm, 0x1bdc, 0x90000089);
	odm_write_4byte(dm, 0x1bdc, 0x9000008b);
	odm_write_4byte(dm, 0x1bdc, 0x9000008d);
	odm_write_4byte(dm, 0x1bdc, 0x9000008f);
	odm_write_4byte(dm, 0x1bdc, 0x90000091);
	odm_write_4byte(dm, 0x1bdc, 0x90000093);
	odm_write_4byte(dm, 0x1bdc, 0x90000095);
	odm_write_4byte(dm, 0x1bdc, 0x90000097);
	odm_write_4byte(dm, 0x1bdc, 0x90000099);
	odm_write_4byte(dm, 0x1bdc, 0x9000009b);
	odm_write_4byte(dm, 0x1bdc, 0x9000009d);
	odm_write_4byte(dm, 0x1bdc, 0x9000009f);
	odm_write_4byte(dm, 0x1bdc, 0x900000a1);
	odm_write_4byte(dm, 0x1bdc, 0x900000a3);
	odm_write_4byte(dm, 0x1bdc, 0x900000a5);
	odm_write_4byte(dm, 0x1bdc, 0x900000a7);
	odm_write_4byte(dm, 0x1bdc, 0x900000a9);
	odm_write_4byte(dm, 0x1bdc, 0x900000ab);
	odm_write_4byte(dm, 0x1bdc, 0x900000ad);
	odm_write_4byte(dm, 0x1bdc, 0x900000af);
	odm_write_4byte(dm, 0x1bdc, 0x900000b1);
	odm_write_4byte(dm, 0x1bdc, 0x900000b3);
	odm_write_4byte(dm, 0x1bdc, 0x900000b5);
	odm_write_4byte(dm, 0x1bdc, 0x900000b7);
	odm_write_4byte(dm, 0x1bdc, 0x900000b9);
	odm_write_4byte(dm, 0x1bdc, 0x900000bb);
	odm_write_4byte(dm, 0x1bdc, 0x900000bd);
	odm_write_4byte(dm, 0x1bdc, 0x900000bf);
	odm_write_4byte(dm, 0x1bdc, 0x900000c1);
	odm_write_4byte(dm, 0x1bdc, 0x900000c3);
	odm_write_4byte(dm, 0x1bdc, 0x900000c5);
	odm_write_4byte(dm, 0x1bdc, 0x900000c7);
	odm_write_4byte(dm, 0x1bdc, 0x900000c9);
	odm_write_4byte(dm, 0x1bdc, 0x900000cb);
	odm_write_4byte(dm, 0x1bdc, 0x900000cd);
	odm_write_4byte(dm, 0x1bdc, 0x900000cf);
	odm_write_4byte(dm, 0x1bdc, 0x900000d1);
	odm_write_4byte(dm, 0x1bdc, 0x900000d3);
	odm_write_4byte(dm, 0x1bdc, 0x900000d5);
	odm_write_4byte(dm, 0x1bdc, 0x900000d7);
	odm_write_4byte(dm, 0x1bdc, 0x900000d9);
	odm_write_4byte(dm, 0x1bdc, 0x900000db);
	odm_write_4byte(dm, 0x1bdc, 0x900000dd);
	odm_write_4byte(dm, 0x1bdc, 0x900000df);
	odm_write_4byte(dm, 0x1bdc, 0x900000e1);
	odm_write_4byte(dm, 0x1bdc, 0x900000e3);
	odm_write_4byte(dm, 0x1bdc, 0x900000e5);
	odm_write_4byte(dm, 0x1bdc, 0x900000e7);
	odm_write_4byte(dm, 0x1bdc, 0x900000e9);
	odm_write_4byte(dm, 0x1bdc, 0x900000eb);
	odm_write_4byte(dm, 0x1bdc, 0x900000ed);
	odm_write_4byte(dm, 0x1bdc, 0x900000ef);
	odm_write_4byte(dm, 0x1bdc, 0x900000f1);
	odm_write_4byte(dm, 0x1bdc, 0x900000f3);
	odm_write_4byte(dm, 0x1bdc, 0x900000f5);
	odm_write_4byte(dm, 0x1bdc, 0x900000f7);
	odm_write_4byte(dm, 0x1bdc, 0x900000f9);
	odm_write_4byte(dm, 0x1bdc, 0x900000fb);
	odm_write_4byte(dm, 0x1bdc, 0x900000fd);
	odm_write_4byte(dm, 0x1bdc, 0x900000ff);
	odm_write_4byte(dm, 0x1bdc, 0x00000000);

	odm_set_rf_reg(dm, RF_PATH_A, 0x56, BIT(19), 0x1);
	odm_set_bb_reg(dm, 0xc00, 0xff, 0x4); /*disable 3-wire*/
}

void _txgapk_rf_setting_8195b(
	struct dm_struct *dm,
	u8 path)
{
	struct dm_iqk_info *iqk_info = &dm->IQK_info;

	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
	//odm_set_rf_reg(dm, RF_PATH_A, 0xde, BIT(16), 0x1);
	//odm_set_rf_reg(dm, RF_PATH_A, 0x56, 0xfffff, 0x50ee3);
	switch (*dm->band_type) {
	case ODM_BAND_2_4G:
		odm_set_rf_reg(dm, RF_PATH_A, 0x57, BIT(2) | BIT(1), 0x1);
		odm_set_rf_reg(dm, RF_PATH_A, 0x57, 0x70, 0x0);
		odm_set_rf_reg(dm, RF_PATH_A, 0x8c, 0x1c0, 0x6);
		odm_set_rf_reg(dm, RF_PATH_A, 0x8f, 0x6000, 0x3);
		//odm_set_rf_reg(dm, RF_PATH_A, 0x00, 0xfffff, 0x2000f);
		//odm_set_rf_reg(dm, RF_PATH_A, 0x00, 0xfffff, 0x35da0);

		RF_DBG(dm, DBG_RF_TXGAPK,
		       "[TGCC] 2G txgapk rf setting!!!\n");
	break;
	case ODM_BAND_5G:
		odm_set_rf_reg(dm, RF_PATH_A, 0x8f, 0x6000, 0x03);
		odm_set_rf_reg(dm, RF_PATH_A, 0x63, 0xf000, 0x1);
		odm_set_rf_reg(dm, RF_PATH_A, 0x8c, 0x1c0, 0x4);
		//odm_set_rf_reg(dm, RF_PATH_A, 0x00, 0xfffff, 0x2000f);
		//odm_set_rf_reg(dm, RF_PATH_A, 0x00, 0xfffff, 0x35da0);
		RF_DBG(dm, DBG_RF_TXGAPK,
		       "[TGCC] 5G txgapk rf setting!!!\n");
	break;
	}

	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x1);
}

u64 _txgapk_one_shot_8195b(struct dm_struct *dm, u8 path)
{
	u32 txgap_k1 = 0x1, txgap_k2 = 0x2;
	u64 rx_dsp_power = 0x0;
	u32 tmp = 0x0;
	u32 bitmask2616 = 0x07ff0000;

	/*clear the flag*/
	//odm_write_1byte(dm, 0x1bd6, 0x0b);
	//odm_set_bb_reg(dm, 0x1bfc, BIT(1), 0x0);
	/* get tx gain*/
	//odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);	
	RF_DBG(dm, DBG_RF_TXGAPK, "(1) RF0x56 =%x\n", odm_get_rf_reg(dm, path, 0x56, 0xfffff));	
	//RF_DBG(dm, DBG_RF_TXGAPK, "(1) RFx0de =%x\n", odm_get_rf_reg(dm, path, 0xde, 0xfffff));	
	odm_write_4byte(dm, 0x1b00, 0x8 | path << 1);
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x1);
	ODM_delay_us(200);
	/* one-shot-1*/
	odm_write_4byte(dm, 0x1b34, 0x1);
	odm_write_4byte(dm, 0x1b34, 0x0);
	ODM_delay_ms(5); //don't remove !!!!	
	//RF_DBG(dm, DBG_RF_TXGAPK, "\n");
	//odm_write_4byte(dm, 0x1b34, 0x1);
	//odm_write_4byte(dm, 0x1b34, 0x0);
	//ODM_delay_ms(2);

	odm_write_4byte(dm, 0x1bd4, 0x00250001);
	ODM_delay_us(200);
	txgap_k1 = odm_read_4byte(dm, 0x1bfc) >> 27;
	odm_write_4byte(dm, 0x1bd4, 0x002e0001);
	ODM_delay_us(200);
	txgap_k2 = odm_read_4byte(dm, 0x1bfc);
	//rx_dsp_power = (u64)((txgap_k1 << 32) + txgap_k2);
	//rx_dsp_power = txgap_k2;
	rx_dsp_power = (u64)((u64)txgap_k1 * 4294967296 + (u64)txgap_k2); // 4294967296 = 2^32;	
	//RF_DBG(dm, DBG_RF_TXGAPK, "0x1bb8 =%x\n", odm_read_4byte(dm, 0x1bb8));
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);	
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
	//RF_DBG(dm, DBG_RF_TXGAPK, "(2) RF0x56 =%x\n", odm_get_rf_reg(dm, path, 0x56, 0xfffff));	
	//RF_DBG(dm, DBG_RF_TXGAPK, "(2) 0x1bb8 =%x\n", odm_read_4byte(dm, 0x1bb8));
	//RF_DBG(dm, DBG_RF_TXGAPK, "\n");
	//RF_DBG(dm, DBG_RF_TXGAPK, "rx_dsp_power =%d\n", rx_dsp_power);

	return rx_dsp_power;

}

void _txgapk_configure_macbb_8195b(struct dm_struct *dm)
{
	/*MACBB register setting*/
	odm_write_1byte(dm, 0x522, 0x7f);
	odm_set_bb_reg(dm, 0x1518, BIT(16), 0x1);
	odm_set_bb_reg(dm, 0x550, BIT(11) | BIT(3), 0x0);
	odm_set_bb_reg(dm, 0x90c, BIT(15), 0x1);
	/*0x90c[15]=1: dac_buf reset selection*/
	odm_set_bb_reg(dm, 0xc94, BIT(0), 0x1);
	odm_set_bb_reg(dm, 0xc94, (BIT(11) | BIT(10)), 0x1);
	/* 3-wire off*/
	odm_write_4byte(dm, 0xc00, 0x00000004);
	/*disable PMAC*/
	odm_set_bb_reg(dm, 0xb00, BIT(8), 0x0);
	/*RF_DBG(dm, DBG_RF_TXGAPK, ("[TGGC]Set MACBB setting!!!!\n"));*/
	/*disable CCK block*/
	odm_set_bb_reg(dm, R_0x808, BIT(28), 0x0);
	/*disable OFDM CCA*/
	odm_set_bb_reg(dm, R_0x838, BIT(3) | BIT(2) | BIT(1), 0x7);
}

void _txgapk_write_rfgain(struct dm_struct *dm, u8 rf_path)
{
	u8 idx = 0x0;

	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
	odm_set_rf_reg(dm, rf_path, 0xee, BIT(16), 0x0);

	odm_set_rf_reg(dm, rf_path, 0x33, 0xfffff, 0x0);
	odm_set_rf_reg(dm, rf_path, 0x3f, 0x00fff, 0x1260c);
	odm_set_rf_reg(dm, rf_path, 0x33, 0xfffff, 0x1);
	odm_set_rf_reg(dm, rf_path, 0x3f, 0x00fff, 0x12e0a);
	odm_set_rf_reg(dm, rf_path, 0x33, 0xfffff, 0x2);
	odm_set_rf_reg(dm, rf_path, 0x3f, 0x00fff, 0x12e27);
	odm_set_rf_reg(dm, rf_path, 0x33, 0xfffff, 0x3);
	odm_set_rf_reg(dm, rf_path, 0x3f, 0x00fff, 0x12e2a);
	odm_set_rf_reg(dm, rf_path, 0x33, 0xfffff, 0x4);
	odm_set_rf_reg(dm, rf_path, 0x3f, 0x00fff, 0x12e67);
	odm_set_rf_reg(dm, rf_path, 0x33, 0xfffff, 0x5);
	//odm_set_rf_reg(dm, rf_path, 0x3f, 0x00fff, 0x12e6a);
	odm_set_rf_reg(dm, rf_path, 0x3f, 0x00fff, 0x12e6b);
	odm_set_rf_reg(dm, rf_path, 0x33, 0xfffff, 0x6);
	odm_set_rf_reg(dm, rf_path, 0x3f, 0x00fff, 0x126a9);
	odm_set_rf_reg(dm, rf_path, 0x33, 0xfffff, 0x7);
	odm_set_rf_reg(dm, rf_path, 0x3f, 0x00fff, 0x12ee9);
	odm_set_rf_reg(dm, rf_path, 0x33, 0xfffff, 0x8);
	odm_set_rf_reg(dm, rf_path, 0x3f, 0x00fff, 0x12eec);
	odm_set_rf_reg(dm, rf_path, 0x33, 0xfffff, 0x9);
	odm_set_rf_reg(dm, rf_path, 0x3f, 0x00fff, 0x12eef);
	odm_set_rf_reg(dm, rf_path, 0x33, 0xfffff, 0xa);
	odm_set_rf_reg(dm, rf_path, 0x3f, 0x00fff, 0x12ef2);

	odm_set_rf_reg(dm, rf_path, 0xee, BIT(16), 0x0);
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x1);
}

void _phy_txgapk_calibrate_8195b(void *dm_void, u8 path, boolean is_cck)
{
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	struct _hal_rf_ *rf = &dm->rf_table;
	struct _halrf_txgapk_info *txgapk_info = &(rf->halrf_txgapk_info);

	u8 rf_path = 0x0, rf0_idx, idx, rf0_idx_current, rf0_idx_next, i;
	u8 delta_gain_retry = 3;
	u8 extr_0p5db[11];
	u8 start = 0x1, end = 0x7;
	u8 rate = 24, band = 0;
	u32 rf56_current = 0x0, rf56_next = 0x0, tmp = 0x0;;
	
	int delta_gain_gap_pre, delta_gain_gap[11];
	int gain_case[11];	
	int psd_gap[11];
	int rf56_current_temp[11], rf56_next_temp[11];
	int psd_diff = 0x0;
	s32 rf3f[11], tmp2;
	u64 psd_value_current, psd_value_next;

	RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC]CH = %d, BW = %x, is_cck = %x\n",
	       *dm->channel, *dm->band_width, is_cck);

	memset(rf3f, 0x0, sizeof(rf3f));
	memset(delta_gain_gap, 0x0, sizeof(delta_gain_gap));
	memset(rf56_current_temp, 0x0, sizeof(rf56_current_temp));
	memset(rf56_next_temp, 0x0, sizeof(rf56_next_temp));
	memset(extr_0p5db, 0x0, sizeof(extr_0p5db));
	memset(gain_case, 0x0, sizeof(gain_case));

	//_txgapk_write_rfgain(dm, path); //for test only
	//_txgapk_configure_macbb_8195b(dm);
	rf_path = RF_PATH_A;
	_txgapk_init_8195b(dm);
	_txgapk_afe_setting_8195b(dm, true);
	odm_set_bb_reg(dm, 0xc00, 0xff, 0x4); /*disable 3-wire*/
	ODM_delay_ms(1);
	//backup rf gain table
	if (!txgapk_info->txgapk_bp_done) {
		_txgapk_bp_rf_gain_table_8195b(dm);
		_txgapk_afe_setting_8195b(dm, false);	
		return;
	}
	
	if (txgapk_info->txgapk_bp_done)
		_txgapk_reload_rf_gain_table_8195b(dm, is_cck, 0x0);

	odm_set_bb_reg(dm, 0x1b14, BIT(8), 0x0); //disable fiqk
#if 1
	odm_set_bb_reg(dm, 0x1b1c, BIT(29), 0x0); //sig_pwr
	odm_set_bb_reg(dm, 0x1b1c, BIT(1), 0x0); //Rx_cal_M
	odm_set_bb_reg(dm, 0x1b1c, BIT(0), 0x1); //Tx_cal_M
	odm_set_bb_reg(dm, 0x1b1c, BIT(8), 0x1); //RX_XY_M_Enable
	odm_write_4byte(dm, 0x1b3c, 0x20000000); // RX_XY
#else
	odm_write_4byte(dm, 0x1b1c, 0x821B7C31);
#endif
	//odm_set_bb_reg(dm, 0x1b18, BIT(1), 0x0);
	//odm_write_4byte(dm, 0x1b20, 0x03050030);
	odm_set_bb_reg(dm, 0x1b24, 0xfffff, 0x50008);
	//Reg2c[11:0]:TX_tone_idx, Reg2c[27:16]:RX_tone_idx, 160M/1024
	//odm_set_bb_reg(dm, 0x1bcc, 0x0000003f, 0x24);
	odm_set_bb_reg(dm, 0x1bcc, 0xffffffff, 0x11160224);
	odm_write_4byte(dm, 0x1b2c, 0x00100010);
	odm_write_4byte(dm, 0x1b30, 0x20000000);
	//odm_set_bb_reg(dm, 0x1b18, BIT(0), 0x1);
	odm_write_4byte(dm, 0x1b18, 0x292901);
	_txgapk_rf_setting_8195b(dm, RF_PATH_A);
	//end = _txgapk_clear_extra0p5dB_8195b(dm, RF_PATH_A, is_cck);
	//_txgapk_search_range_8195b(dm, RF_PATH_A);
	
	/*get 0x56 gain table*/	
	odm_write_4byte(dm, 0x1b00, 0x8 | rf_path << 1);
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
	odm_set_rf_reg(dm, rf_path, 0xde, BIT(16), 0x0);
	ODM_delay_us(10);

	//select band
	switch (*dm->band_type) {
	case ODM_BAND_2_4G:
		if (is_cck)
			band = 0;
		else
			band = 1;
		break;
	case ODM_BAND_5G:
		if (*dm->channel > 144)
			band = 4;
		else if (*dm->channel > 64)
			band = 3;
		else 
			band = 2;
		break;
	}

	if(is_cck) {
		odm_set_rf_reg(dm, rf_path, 0x1a, BIT(0), 0x1);	
		odm_set_rf_reg(dm, rf_path, 0x1a, BIT(16), 0x1);
	} else {
		odm_set_rf_reg(dm, rf_path, 0x1a, BIT(0), 0x0);
		odm_set_rf_reg(dm, rf_path, 0x1a, BIT(16), 0x0);
	}
	for (idx = 1; idx <= 8; idx++) {
		/*current_fr0x_56*/
#if 0
		rf0_idx_current = 3 * (idx - 1) + 1;
		odm_set_rf_reg(dm, rf_path, 0x0, 0x1f, rf0_idx_current);
		ODM_delay_us(100);
		rf3f[idx] = odm_get_rf_reg(dm, rf_path, 0x56, 0x1fff);
#else
		rf3f[idx] = txgapk_info->txgapk_rf3f_bp[band][idx][rf_path];
#endif
		RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] read idx=0x%x, rf3f =0x%x\n",
		       idx, rf3f[idx]);
		if ((((rf3f[idx] & 0xe0) >> 5) == 0x7) &&
		    (((rf3f[idx] & 0xe00) >> 9) == 0x7)) {
			end = idx;
			break;
		}
	}
	if ( end > 8)
		end = 0x8;
	RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] end = 0x%x\n", end);
#if 1
	for (rf0_idx = end; rf0_idx >= 0x1; rf0_idx--) {		
		odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
		ODM_delay_ms(1);

		/*current_fr0x_56*/
		rf0_idx_current = 3 * (rf0_idx - 1) + 1;
		rf56_current_temp[rf0_idx] = rf3f[rf0_idx] & 0xfff;
		rf0_idx_next = rf0_idx_current + 1;
		if(rf0_idx == end)
			rf56_next_temp[rf0_idx] = rf56_current_temp[rf0_idx];
		else
			rf56_next_temp[rf0_idx] = rf3f[rf0_idx + 1] - 2;
		//odm_set_rf_reg(dm, rf_path, 0xde, BIT(16), 0x0);
		//odm_set_rf_reg(dm, rf_path, 0x0, 0x1f, rf0_idx_next);
		
		//rf56_next_temp[rf0_idx] = odm_get_rf_reg(dm, rf_path, 0x56, 0xfff);
		//config_phydm_write_txagc_8195b(dm, rf0_idx_current, path, 0x7);
		ODM_delay_ms(1);


		if (((rf56_current_temp[rf0_idx] & 0xe0) !=
		    (rf56_next_temp[rf0_idx] & 0xe0)) |
		    ((rf56_current_temp[rf0_idx] & 0xe00) !=
		    (rf56_next_temp[rf0_idx] & 0xe00)) |
		    (rf0_idx >= end)) {
			odm_set_rf_reg(dm, rf_path, 0x56, 0xfff, rf56_current_temp[rf0_idx]);
			odm_set_rf_reg(dm, rf_path, 0xde, BIT(16), 0x1);			
			odm_set_rf_reg(dm, rf_path, 0x56, 0xfff, rf56_current_temp[rf0_idx]);
			//config_phydm_write_txagc_8195b(dm, rf0_idx_current, path, 0x7);
			/*do one-shot*/
			psd_value_current = (long)_txgapk_one_shot_8195b(dm, rf_path);
			ODM_delay_ms(2);
			
			odm_set_rf_reg(dm, rf_path, 0x56, 0xfff, rf56_next_temp[rf0_idx]);
			odm_set_rf_reg(dm, rf_path, 0xde, BIT(16), 0x1);
			odm_set_rf_reg(dm, rf_path, 0x56, 0xfff, rf56_next_temp[rf0_idx]);
			//config_phydm_write_txagc_8195b(dm, rf0_idx_next, path, 0x7);
			/*do one-shot*/
			psd_value_next = (long)_txgapk_one_shot_8195b(dm, rf_path);
			RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] idx_current= 0x%x, rf56_current_temp[%d]=0x%x, psd_current    =%d\n",
						   rf0_idx_current, rf0_idx,
						   rf56_current_temp[rf0_idx], psd_value_current);
			RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] idx_next   = 0x%x, rf56_next_temp[%d]   =0x%x, psd_value_next =%d\n",
						   rf0_idx_next, rf0_idx,
						   rf56_next_temp[rf0_idx], psd_value_next);
			if ( psd_value_current > 0x1000)
				psd_diff = psd_value_next  / (psd_value_current / 1000);
			else
				psd_diff = 1200;

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
		if(rf0_idx >= end)
			psd_gap[rf0_idx] = 0;		
		RF_DBG(dm, DBG_RF_TXGAPK,
		       "[TGGC] psd_diff =%d, psd_gap[%x] = %d\n", psd_diff, rf0_idx, psd_gap[rf0_idx]);
	}
#endif
	odm_set_bb_reg(dm, 0xc00, 0xff, 0x7); /*enable 3-wire*/
	ODM_delay_ms(1);
	RF_DBG(dm, DBG_RF_TXGAPK, "\n");

	/*store to RF TXAGC table*/
	gain_case[end] = psd_gap[end];
	if ((gain_case[end] % 2) != 0)
		extr_0p5db[end] = 0x1;
	else
		extr_0p5db[end] = 0x0;

	delta_gain_gap[end] = (gain_case[end] - extr_0p5db[end]) / 2;

	RF_DBG(dm, DBG_RF_TXGAPK,
	       "[TGGC] gain_case[%x] = %d,psd_gap[%x] = %d\n",
	       end, gain_case[end], end, psd_gap[end]);

	for (rf0_idx = end - 1; rf0_idx >= 0x1; rf0_idx--) {
		gain_case[rf0_idx] = gain_case[rf0_idx + 1] + psd_gap[rf0_idx];
		if ((gain_case[rf0_idx] % 2) != 0)
			extr_0p5db[rf0_idx] = 0x1;
		else
			extr_0p5db[rf0_idx] = 0x0;

		delta_gain_gap[rf0_idx] = (gain_case[rf0_idx] - extr_0p5db[rf0_idx]) / 2;

		RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] extr_0p5db[%x] = %d\n",
		       rf0_idx, extr_0p5db[rf0_idx]);
		RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] gain_case[%x] = %d\n",
		       rf0_idx, gain_case[rf0_idx]);
		RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC] delta_gain_gap[%x] = %d\n",
		       rf0_idx, delta_gain_gap[rf0_idx]);
	}
	odm_set_rf_reg(dm, rf_path, 0xde, BIT(16), 0x0);

	/*store to RF TXAGC table*/
	for (rf0_idx = 1; rf0_idx <= end; rf0_idx++) {
		rf3f[rf0_idx] = (rf56_current_temp[rf0_idx] +
				 delta_gain_gap[rf0_idx]) & 0xfff;
	}
	odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x0);
	odm_set_rf_reg(dm, rf_path, 0xee, BIT(16), 0x1);
	for (idx = 0x1; idx < end; idx++) {
		switch (*dm->band_type) {
		case ODM_BAND_2_4G:
			if (!is_cck)
				tmp = (idx - 1);
			else
				tmp = 0x20 | (idx - 1);
				break;
		case ODM_BAND_5G:
			if (*dm->channel > 140)
				tmp = 0x180 | (idx - 1);
			else if (*dm->channel > 64)
				tmp = 0x140 | (idx - 1);
			else
				tmp = 0x100 | (idx - 1);
			break;
		}
		odm_set_rf_reg(dm, rf_path, 0x33, 0xfffff, tmp);
		if (extr_0p5db[idx] == 0x1)
			tmp2 = BIT(12) | rf3f[idx];
		else
			tmp2 = rf3f[idx];
		odm_set_rf_reg(dm, rf_path, 0x3f, 0x01fff, tmp2);
		RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC]idx= %x, 33= 0x%x, 3f= 0x%x\n"
					, idx, tmp, tmp2);
	}
	odm_set_rf_reg(dm, rf_path, 0xee, BIT(16), 0x0);
	//odm_set_bb_reg(dm, 0x1bb8, BIT(20), 0x1);
	odm_set_bb_reg(dm, 0x1b14, BIT(8), 0x1);
	odm_set_bb_reg(dm, 0x1b1c, BIT(29), 0x1);
	odm_set_bb_reg(dm, 0x1b1c, BIT(1), 0x1);
	odm_set_bb_reg(dm, 0x1b1c, BIT(0), 0x0);
	odm_set_bb_reg(dm, 0x1b1c, BIT(8), 0x0);
	odm_set_bb_reg(dm, 0x1b18, BIT(1), 0x1);
	_txgapk_afe_setting_8195b(dm, false);

}

void phy_txgap_calibrate_8195b(
	void *dm_void,
	boolean clear)
{
	u32 MAC_backup[GAPK_MAC_REG_NUM_8195B];
	u32 BB_backup[GAPK_BB_REG_NUM_8195B];
	u32 RF_backup[GAPK_RF_REG_NUM_8195B][1];
	u32 backup_mac_reg[GAPK_MAC_REG_NUM_8195B] = {0x520, 0x550, 0x1518};
	u32 backup_bb_reg[GAPK_BB_REG_NUM_8195B] = {0x808, 0x810, 0x90c, 0xc00,
						0xcb0, 0xcb4, 0xcbc,
						0x1990, 0x9a4, 0xa04};
	u32 backup_rf_reg[GAPK_RF_REG_NUM_8195B] = {0xdf, 0xde, 0x8f, 0x0, 0x1};
	struct dm_struct *dm = (struct dm_struct *)dm_void;
	struct dm_iqk_info *iqk_info = &dm->IQK_info;
	struct _ADAPTER *p_adapter = dm->adapter;

#if (MP_DRIVER == 1)
#ifdef CONFIG_MP_INCLUDED
	PMPT_CONTEXT p_mpt_ctx = &(p_adapter->mppriv.MptCtx);
#endif
#endif

	struct _hal_rf_ *p_rf = &(dm->rf_table);

#if (DM_ODM_SUPPORT_TYPE == ODM_IOT)
	if (!(p_rf->rf_supportability & HAL_RF_TXGAPK))
		return;
#if (RTL8195B_SUPPORT == 1)
	_txgapk_backup_mac_bb_8195b(dm, MAC_backup, BB_backup,
				 backup_mac_reg, backup_bb_reg);
	_txgapk_backup_rf_8195b(dm, RF_backup, backup_rf_reg);

	if (*dm->band_type == ODM_BAND_2_4G) {
		_phy_txgapk_calibrate_8195b(dm, RF_PATH_A, true);
		RF_DBG(dm, DBG_RF_TXGAPK, "\n");
		_phy_txgapk_calibrate_8195b(dm, RF_PATH_A, false);
	} else
		_phy_txgapk_calibrate_8195b(dm, RF_PATH_A, false);

	_txgapk_restore_rf_8195b(dm, backup_rf_reg, RF_backup);
	_txgapk_restore_mac_bb_8195b(dm, MAC_backup, BB_backup,
				  backup_mac_reg, backup_bb_reg);
#endif
#endif
	RF_DBG(dm, DBG_RF_TXGAPK, "[TGGC]====_txgapk_8195b End!!!!!========\n");

	return;
}

#endif
